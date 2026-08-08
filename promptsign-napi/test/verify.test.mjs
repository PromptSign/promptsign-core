// Parity test: the napi binding must produce the SAME VerifyResult as the CLI's
// `verify --json`, because both wrap the identical promptsign-core. Uses local-key
// (Ed25519) signing so the whole test is offline and deterministic — no trust root
// or network. Requires a CLI binary built with the `local-key` feature (set
// PROMPTSIGN_RUST_BIN, or `cargo build --features local-key -p promptsign-cli`).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const napi = require('../index.cjs');
const here = path.dirname(fileURLToPath(import.meta.url));
// The CLI is a sibling repo, so its target dir is the likelier location — but a
// workspace that has both checked out one level up also works. Absent entirely,
// the parity tests skip: they compare against the CLI, and a missing CLI is a
// missing comparison, not a failure of the binding.
const exe = process.platform === 'win32' ? 'promptsign.exe' : 'promptsign';
const RUST_BIN = [
  process.env.PROMPTSIGN_RUST_BIN,
  path.resolve(here, '..', '..', '..', 'promptsign-cli', 'target', 'debug', exe),
  path.resolve(here, '..', '..', 'target', 'debug', exe),
].find((p) => p && existsSync(p));

const parity = RUST_BIN
  ? false
  : 'no promptsign CLI with the local-key feature — build one with ' +
    '`cargo build --features local-key -p promptsign-cli` in the promptsign-cli repo, ' +
    'or set PROMPTSIGN_RUST_BIN';

// The CLI exits 2 when verification fails; its JSON still goes to stdout. Read it
// regardless of exit code so we can compare a failing verdict too.
function cliJson(args, opts) {
  try {
    return JSON.parse(execFileSync(RUST_BIN, args, { ...opts, encoding: 'utf8' }));
  } catch (e) {
    if (e.stdout) return JSON.parse(e.stdout);
    throw e;
  }
}

function signedSkill(tag) {
  const work = mkdtempSync(path.join(tmpdir(), `psnapi-${tag}-`));
  const home = path.join(work, 'home');
  const skill = path.join(work, 'skill');
  mkdirSync(home, { recursive: true });
  mkdirSync(path.join(skill, 'scripts'), { recursive: true });
  writeFileSync(path.join(skill, 'SKILL.md'), '# demo\nDoes things.\n');
  writeFileSync(path.join(skill, 'scripts', 'run.py'), 'print(1)\n');
  const env = { ...process.env, PROMPTSIGN_HOME: home };
  execFileSync(RUST_BIN, ['keygen', '--identity', 'github:napi'], { env });
  execFileSync(
    RUST_BIN,
    ['sign', skill, '--local-key', '--name', 'demo/napi', '--version', '1.0.0'],
    { env },
  );
  return { work, home, skill, env };
}

// Run the napi binding with the same PROMPTSIGN_HOME + cwd the CLI subprocess uses,
// so policy/pins resolution is identical.
function napiVerify(fn, home, cwd) {
  const prevHome = process.env.PROMPTSIGN_HOME;
  const prevCwd = process.cwd();
  process.env.PROMPTSIGN_HOME = home;
  process.chdir(cwd);
  try {
    return fn();
  } finally {
    process.chdir(prevCwd);
    if (prevHome === undefined) delete process.env.PROMPTSIGN_HOME;
    else process.env.PROMPTSIGN_HOME = prevHome;
  }
}

test('verify() equals `promptsign verify --json` byte-for-byte', { skip: parity }, () => {
  const { work, home, skill, env } = signedSkill('ok');
  const cli = cliJson(['verify', skill, '--json', '--no-pin-updates'], { env, cwd: work });
  const got = napiVerify(() => napi.verify(skill, { noPinUpdates: true }), home, work);
  assert.deepEqual(got, cli);
  assert.equal(got.action, 'pass');
  assert.equal(got.identity, 'github:napi');
  assert.equal(got.name, 'demo/napi');
});

test('verify() reports a tampered file as failed, same as the CLI', { skip: parity }, () => {
  const { work, home, skill, env } = signedSkill('tamper');
  writeFileSync(path.join(skill, 'scripts', 'run.py'), 'print(2)\n'); // change after signing
  const cli = cliJson(['verify', skill, '--json', '--no-pin-updates'], { env, cwd: work });
  const got = napiVerify(() => napi.verify(skill, { noPinUpdates: true }), home, work);
  assert.deepEqual(got, cli);
  assert.equal(got.action, 'fail');
  assert.ok(got.findings.some((f) => /modified/.test(f.message)));
});

test('verifyTree() returns an array matching verify-tree --json', { skip: parity }, () => {
  const { work, home, skill, env } = signedSkill('tree');
  const cli = cliJson(['verify-tree', skill, '--json', '--no-pin-updates'], { env, cwd: work });
  const got = napiVerify(() => napi.verifyTree([skill], { noPinUpdates: true }), home, work);
  assert.deepEqual(got, cli);
  assert.equal(got.length, cli.length);
});

test(
  'policyShow() returns the built-in default when no policy is configured',
  { skip: parity },
  () => {
    const { work, home } = signedSkill('policy');
    const got = napiVerify(() => napi.policyShow(work), home, work);
    assert.equal(got.schema, 'promptsign/policy/v1');
    assert.ok(Array.isArray(got.rules));
  },
);

test('coreVersion() reports the wrapped core version', () => {
  assert.match(napi.coreVersion(), /^\d+\.\d+\.\d+/);
});
