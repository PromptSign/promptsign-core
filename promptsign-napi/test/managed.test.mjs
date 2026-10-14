// The managed layer through the binding: policyLayers(), strictMode() and the
// managed flag on trustRoots(). PROMPTSIGN_MANAGED_DIR stands in for the
// platform directory, which only works on a machine that has none.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const napi = require('../index.cjs');
const here = path.dirname(fileURLToPath(import.meta.url));
const platformDir =
  {
    win32: 'C:\\ProgramData\\PromptSign',
    darwin: '/Library/Application Support/PromptSign',
  }[process.platform] ?? '/etc/promptsign';
const skip = existsSync(platformDir)
  ? `${platformDir} exists, so PROMPTSIGN_MANAGED_DIR does not apply`
  : false;

function withEnv(vars, fn) {
  const prev = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('policyLayers, strictMode and trustRoots report the managed layer', { skip }, () => {
  const work = mkdtempSync(path.join(tmpdir(), 'psnapi-managed-'));
  const managed = path.join(work, 'managed');
  const home = path.join(work, 'home');
  const policy = (extra) =>
    JSON.stringify({ schema: 'promptsign/policy/v1', default: 'warn', rules: [], ...extra });

  mkdirSync(path.join(managed, 'trust'), { recursive: true });
  mkdirSync(home, { recursive: true });
  writeFileSync(path.join(home, 'policy.json'), policy({ default: 'enforce' }));
  for (const f of ['fulcio.pem', 'rekor.pub']) {
    writeFileSync(path.join(managed, 'trust', f), readFileSync(path.join(here, '..', 'trust', f)));
  }

  withEnv({ PROMPTSIGN_MANAGED_DIR: managed, PROMPTSIGN_HOME: home, PROMPTSIGN_STRICT: '' }, () => {
    // No managed policy yet: the user's policy is the only layer.
    assert.deepEqual(
      napi.policyLayers(work).map((l) => l.layer),
      ['user'],
    );
    assert.equal(napi.strictMode(), false);

    writeFileSync(path.join(managed, 'managed-policy.json'), policy({ strict: true }));

    const layers = napi.policyLayers(work);
    assert.deepEqual(
      layers.map((l) => l.layer),
      ['managed', 'user'],
    );
    assert.equal(layers[0].source, path.join(managed, 'managed-policy.json'));
    assert.equal(layers[0].policy.strict, true);
    assert.equal(napi.strictMode(), true);

    // The built-in root comes from the managed trust directory.
    assert.deepEqual(napi.trustRoot(), {
      dir: path.join(managed, 'trust'),
      source: 'managed',
    });
    const [builtin] = napi.trustRoots();
    assert.equal(builtin.name, 'sigstore-public');
    assert.equal(builtin.managed, true);
  });
});
