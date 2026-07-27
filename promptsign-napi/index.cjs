// Thin JS wrapper over the native addon: every native function returns a JSON
// string (the same wire shape as `promptsign … --json`); here we parse it so
// callers get plain objects. The FFI surface stays tiny and auditable.
'use strict';

const { existsSync } = require('node:fs');
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

/** Verify one target (directory or file). Returns a VerifyResult object,
 * identical to `promptsign verify --json`. */
function verify(target, opts) {
  return JSON.parse(native.verify(target, opts));
}

/** Verify a tree of roots. Returns an array of VerifyResult. */
function verifyTree(roots, opts) {
  return JSON.parse(native.verifyTreeJson(roots, opts));
}

/** Offline keyless verification of a bundle. Accepts the bundle as an object or
 * a JSON string. Returns { identity, issuer, keyid }, or throws on failure. */
function verifyKeyless(bundle) {
  return JSON.parse(
    native.verifyKeyless(typeof bundle === 'string' ? bundle : JSON.stringify(bundle)),
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

module.exports = { verify, verifyTree, verifyKeyless, policyShow, coreVersion };
