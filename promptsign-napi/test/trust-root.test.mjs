// node --test
//
// The trust root is what every keyless signature is ultimately checked against,
// so three things are asserted here: that a plain `npm install` can verify with
// no PROMPTSIGN_* configuration at all, that the pinned root is still the root
// we think it is, and that this package's copy of it still matches the canonical
// one at the repo root.
//
// Each case runs in a child process. Selecting the bundled root sets
// PROMPTSIGN_TRUST_DIR once per process (the core reads it from the environment),
// so sharing one process between cases would make them order-dependent.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, test } from 'node:test';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.resolve(here, '..');
const TRUST_DIR = path.join(pkg, 'trust');
// The canonical root, one level up. This package's trust/ is a committed copy of
// it, kept in step by scripts/sync-trust.mjs; see trust/README.md for why the
// copy exists at all.
const CANONICAL_TRUST_DIR = path.resolve(pkg, '..', 'trust');
const built = fs.existsSync(path.join(pkg, 'promptsign-napi.node'));

// The Rekor log this package trusts. rekor.pub holds one PEM block per trusted
// log and is append-only: a rotation adds the new key and keeps the old one, so
// entries witnessed before the rotation stay verifiable. Appending is therefore
// allowed here; dropping this log is not, and fails until the constant changes
// in the same commit.
const REKOR_LOG_ID = 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d';

/** Every log id in a rekor.pub, computed the way the core does: sha256 of each
 *  block's SPKI DER. */
function logIds(pem) {
  return [...pem.matchAll(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/g)].map(
    (m) =>
      createHash('sha256')
        .update(Buffer.from(m[1].replace(/\s+/g, ''), 'base64'))
        .digest('hex'),
  );
}

// Structurally a keyless bundle, with a certificate chain that is not a
// certificate. Loading the trust root happens *before* the chain is parsed, so
// which of the two errors comes back says whether the root was found.
const BOGUS_BUNDLE = JSON.stringify({
  schema: 'promptsign/bundle/v1',
  signer: { certChain: ['AAAA'] },
  signature: 'AAAA',
});

/** Run a snippet with `napi` bound to the package, under a chosen environment.
 *  `null` in `env` removes a variable that the ambient environment may have. */
function inChild(snippet, env = {}) {
  const childEnv = { ...process.env };
  for (const [k, v] of Object.entries(env)) {
    if (v === null) delete childEnv[k];
    else childEnv[k] = v;
  }
  const out = execFileSync(
    process.execPath,
    ['-e', `const napi = require(${JSON.stringify(path.join(pkg, 'index.cjs'))});\n${snippet}`],
    { encoding: 'utf8', env: childEnv },
  );
  return out.trim();
}

const CLEAN = { PROMPTSIGN_TRUST_DIR: null, PROMPTSIGN_HOME: null };

describe('the pinned trust root', () => {
  test('ships in the package', () => {
    assert.ok(fs.existsSync(path.join(TRUST_DIR, 'fulcio.pem')), 'trust/fulcio.pem is missing');
    assert.ok(fs.existsSync(path.join(TRUST_DIR, 'rekor.pub')), 'trust/rekor.pub is missing');
  });

  test('is published — trust/ is in package.json files', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8'));
    assert.ok(
      manifest.files.some((f) => f.replace(/\/$/, '') === 'trust'),
      'trust/ must be in "files", or npm ships a package that cannot verify',
    );
  });

  test('still trusts the Rekor log we pin', () => {
    const ids = logIds(fs.readFileSync(path.join(TRUST_DIR, 'rekor.pub'), 'utf8'));
    assert.ok(ids.length > 0, 'rekor.pub has no PUBLIC KEY block');
    assert.ok(
      ids.includes(REKOR_LOG_ID),
      `rekor.pub no longer trusts ${REKOR_LOG_ID}. Rotation appends a key, it does not ` +
        `replace one — dropping a log breaks every signature it witnessed. Found: ${ids.join(', ')}`,
    );
  });

  test('fulcio.pem is a certificate chain, not an empty or stray file', () => {
    const pem = fs.readFileSync(path.join(TRUST_DIR, 'fulcio.pem'), 'utf8');
    assert.match(pem, /-----BEGIN CERTIFICATE-----/);
    assert.ok(pem.length > 500, 'suspiciously small for a CA chain');
  });

  // Drift is the failure this catches. The copy shipped to npm is what a JS
  // consumer verifies against, so a copy that no longer matches the canonical
  // root means npm users are anchored to a root nobody is maintaining. Skipped
  // outside the repo, because the canonical directory is not published: this
  // test file is not in package.json "files", but an installed tree is not the
  // only place `node --test` can be pointed at.
  test(
    'matches the canonical root in trust/',
    { skip: fs.existsSync(CANONICAL_TRUST_DIR) ? false : 'not a source checkout' },
    () => {
      for (const name of ['fulcio.pem', 'rekor.pub']) {
        const canonical = fs.readFileSync(path.join(CANONICAL_TRUST_DIR, name));
        const copy = fs.readFileSync(path.join(TRUST_DIR, name));
        assert.ok(
          canonical.equals(copy),
          `promptsign-napi/trust/${name} has drifted from the canonical trust/${name}. ` +
            'Append rotated material to trust/, never to this copy, then run ' +
            '`node scripts/sync-trust.mjs` from the repo root.',
        );
      }
    },
  );
});

describe('trust root resolution', { skip: built ? false : 'native addon not built' }, () => {
  test('an unconfigured install uses the bundled root', () => {
    const info = JSON.parse(inChild('console.log(JSON.stringify(napi.trustRoot()))', CLEAN));
    assert.equal(info.source, 'bundled');
    assert.equal(path.resolve(info.dir), TRUST_DIR);
  });

  // The regression this whole change exists for: before it, a plain install
  // failed here with "no Sigstore trust root … run promptsign trust fetch
  // first", which told a JS consumer to install a CLI they had chosen not to.
  test('an unconfigured install can verify — it gets past loading the root', () => {
    const message = inChild(
      `try { napi.verifyKeyless(${JSON.stringify(BOGUS_BUNDLE)}); console.log('NO THROW'); }
       catch (e) { console.log(e.message.split('\\n')[0]); }`,
      CLEAN,
    );
    assert.doesNotMatch(message, /no Sigstore trust root/);
    // Reached certificate parsing, which is after the trust root is loaded.
    assert.match(message, /certificate/i);
  });

  test('importing the package sets nothing on its own', () => {
    const value = inChild(
      'console.log(JSON.stringify(process.env.PROMPTSIGN_TRUST_DIR ?? null))',
      CLEAN,
    );
    assert.equal(value, 'null', 'import must have no side effect on the host environment');
  });

  test('an explicit PROMPTSIGN_TRUST_DIR is never overridden', () => {
    const info = JSON.parse(
      inChild('console.log(JSON.stringify(napi.trustRoot()))', {
        ...CLEAN,
        PROMPTSIGN_TRUST_DIR: '/somewhere/else',
      }),
    );
    assert.equal(info.source, 'PROMPTSIGN_TRUST_DIR');
    assert.equal(info.dir, '/somewhere/else');
  });

  test('PROMPTSIGN_HOME takes precedence, and the error says so', () => {
    const env = { ...CLEAN, PROMPTSIGN_HOME: path.join(pkg, 'test', 'no-such-home') };
    const info = JSON.parse(inChild('console.log(JSON.stringify(napi.trustRoot()))', env));
    assert.equal(info.source, 'PROMPTSIGN_HOME');

    const message = inChild(
      `try { napi.verifyKeyless(${JSON.stringify(BOGUS_BUNDLE)}); console.log('NO THROW'); }
       catch (e) { console.log(e.message.replace(/\\n/g, ' | ')); }`,
      env,
    );
    assert.match(message, /no Sigstore trust root/);
    assert.match(
      message,
      /PROMPTSIGN_HOME is set, so the root pinned in this package was not used/,
    );
  });
});
