// Thin JS wrapper over the native addon: every native function returns a JSON
// string (the same wire shape as `promptsign … --json`); here we parse it so
// callers get plain objects. The FFI surface stays tiny and auditable.
'use strict';

const { existsSync } = require('node:fs');
const { homedir } = require('node:os');
const { join } = require('node:path');

// glibc vs musl on Linux. Node's report exposes the runtime glibc version only
// on a glibc host; its absence means musl (Alpine, distroless-static, etc.).
function linuxLibc() {
  const report =
    typeof process.report?.getReport === 'function' ? process.report.getReport() : null;
  return report?.header?.glibcVersionRuntime ? 'gnu' : 'musl';
}

// Which prebuilt platform package serves this host. Kept deliberately explicit
// (no generated loader) so the resolution is auditable.
function platformPackage() {
  const { platform, arch } = process;
  if (platform === 'linux') {
    if (arch === 'x64') return `linux-x64-${linuxLibc()}`;
    if (arch === 'arm64') return `linux-arm64-${linuxLibc()}`;
    return undefined;
  }
  return {
    'win32 x64': 'win32-x64-msvc',
    'darwin x64': 'darwin-x64',
    'darwin arm64': 'darwin-arm64',
  }[`${platform} ${arch}`];
}

// Resolution order:
//   1. a local dev build (plain `cargo build` + copy-artifact.mjs), so this repo
//      and the parity test work with no published binary;
//   2. the prebuilt platform package installed as an optionalDependency.
function loadNative() {
  const local = join(__dirname, 'promptsign-napi.node');
  if (existsSync(local)) return require(local);

  const suffix = platformPackage();
  if (suffix) {
    try {
      return require(`@promptsign/verify-${suffix}`);
    } catch (e) {
      throw new Error(
        `@promptsign/verify: the prebuilt binary '@promptsign/verify-${suffix}' is not installed.\n` +
          'If you installed with --no-optional or --omit=optional, re-install without it.\n' +
          `Original error: ${e.message}`,
      );
    }
  }
  throw new Error(
    `@promptsign/verify: no prebuilt binary for ${process.platform}-${process.arch}.\n` +
      'Build from source:\n' +
      '  cargo build --release -p promptsign-napi --manifest-path <repo>/rust/Cargo.toml\n' +
      '  node <repo>/rust/promptsign-napi/scripts/copy-artifact.mjs',
  );
}

const native = loadNative();

// --- trust root -------------------------------------------------------------
// Keyless verification is offline, but it is offline *against a trust root*, and
// the core resolves that root from the filesystem: PROMPTSIGN_TRUST_DIR, else
// $PROMPTSIGN_HOME/trust. On a machine that has never run `promptsign trust
// fetch` there is nothing there, so a plain `npm install` + verify() used to
// fail with "run promptsign trust fetch first" — telling a JS consumer to go
// install a CLI they deliberately did not install.
//
// So the package pins its own copy of the Sigstore roots in trust/ and points
// the core at them. Pinning at build time is stronger than fetching over TLS on
// first use, which would be trust-on-first-use on the trust root itself.

const BUNDLED_TRUST_DIR = join(__dirname, 'trust');

const hasBundledTrustRoot = () =>
  existsSync(join(BUNDLED_TRUST_DIR, 'fulcio.pem')) &&
  existsSync(join(BUNDLED_TRUST_DIR, 'rekor.pub'));

/** Which root is in effect, and why. Mirrors the core's resolution order. */
function trustRoot() {
  if (process.env.PROMPTSIGN_TRUST_DIR) {
    return { dir: process.env.PROMPTSIGN_TRUST_DIR, source: 'PROMPTSIGN_TRUST_DIR' };
  }
  if (process.env.PROMPTSIGN_HOME) {
    return { dir: join(process.env.PROMPTSIGN_HOME, 'trust'), source: 'PROMPTSIGN_HOME' };
  }
  if (hasBundledTrustRoot()) return { dir: BUNDLED_TRUST_DIR, source: 'bundled' };
  return { dir: join(homedir(), '.promptsign', 'trust'), source: 'promptsign-home-default' };
}

// The core reads the directory from the environment at call time, so this is how
// a caller-supplied root is expressed. Deliberately never overrides a value the
// host already set — an operator with their own or a private root keeps it — and
// it runs once, lazily, so importing this package changes nothing on its own.
let trustApplied = false;
function applyBundledTrustRoot() {
  if (trustApplied) return;
  trustApplied = true;
  if (trustRoot().source !== 'bundled') return;
  process.env.PROMPTSIGN_TRUST_DIR = BUNDLED_TRUST_DIR;
}

/** The one foot-gun this design introduces: setting PROMPTSIGN_HOME (for pins or
 *  policy) also opts out of the bundled root, and the core's error cannot know
 *  that. Explain it rather than leaving a puzzle. */
function explainTrustRootError(message) {
  const { source, dir } = trustRoot();
  const why = {
    PROMPTSIGN_TRUST_DIR: `PROMPTSIGN_TRUST_DIR points at ${dir}, which takes precedence over the root pinned in this package.`,
    PROMPTSIGN_HOME: `PROMPTSIGN_HOME is set, so the root pinned in this package was not used. Run \`promptsign trust fetch\`, unset PROMPTSIGN_HOME, or set PROMPTSIGN_TRUST_DIR=${BUNDLED_TRUST_DIR}.`,
    bundled: `the pinned root in ${BUNDLED_TRUST_DIR} could not be read — this install may be incomplete.`,
    'promptsign-home-default': `this install is missing trust/fulcio.pem and trust/rekor.pub, so there is no pinned root to fall back on.`,
  }[source];
  return new Error(`${message}\n@promptsign/verify: ${why}`);
}

function withTrustRoot(fn) {
  applyBundledTrustRoot();
  try {
    return fn();
  } catch (e) {
    const message = e && e.message ? e.message : String(e);
    if (message.includes('no Sigstore trust root')) throw explainTrustRootError(message);
    throw e;
  }
}

/** Verify one target (directory or file). Returns a VerifyResult object,
 * identical to `promptsign verify --json`. */
function verify(target, opts) {
  return withTrustRoot(() => JSON.parse(native.verify(target, opts)));
}

/** Verify a tree of roots. Returns an array of VerifyResult. */
function verifyTree(roots, opts) {
  return withTrustRoot(() => JSON.parse(native.verifyTreeJson(roots, opts)));
}

/** Offline keyless verification of a bundle. Accepts the bundle as an object or
 * a JSON string. Returns { identity, issuer, keyid }, or throws on failure. */
function verifyKeyless(bundle) {
  return withTrustRoot(() =>
    JSON.parse(native.verifyKeyless(typeof bundle === 'string' ? bundle : JSON.stringify(bundle))),
  );
}

/** The effective policy for a directory (like `promptsign policy show`). */
function policyShow(dir) {
  return JSON.parse(native.policyShow(dir));
}

/** The wrapped promptsign-core version. */
function coreVersion() {
  return native.coreVersion();
}

module.exports = { verify, verifyTree, verifyKeyless, policyShow, coreVersion, trustRoot };
