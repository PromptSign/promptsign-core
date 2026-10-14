// logDecisions(): a harness built on the binding logs what it did with each
// verification (spec/08), in the same records the CLI writes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const napi = require('../index.cjs');

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

test('logDecisions writes a result, an unresolved skill and an error', () => {
  const work = mkdtempSync(path.join(tmpdir(), 'psnapi-dlog-'));
  const home = path.join(work, 'home');
  const file = path.join(work, 'CLAUDE.md');
  const log = path.join(work, 'decisions.jsonl');

  mkdirSync(home);
  writeFileSync(file, '# rules\n');
  writeFileSync(
    path.join(home, 'policy.json'),
    JSON.stringify({ schema: 'promptsign/policy/v1', default: 'enforce', rules: [] }),
  );

  withEnv({ PROMPTSIGN_HOME: home, USER: 'tester', USERNAME: 'tester' }, () => {
    const r = napi.verify(file, { noPinUpdates: true });
    assert.equal(r.action, 'fail');
    assert.deepEqual(r.evidence, { rule: { layer: 'user', pattern: '*', action: 'enforce' } });

    const failed = napi.logDecisions({
      harness: 'claude',
      event: 'PreToolUse',
      decisionLog: log,
      entries: [
        { result: r, decision: 'block' },
        { unresolved: { name: 'nobody:missing', message: 'not found' }, decision: 'allow' },
        { error: { name: 'x', message: 'boom' } },
      ],
    });
    assert.deepEqual(failed, []);
  });

  const records = readFileSync(log, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  assert.equal(records.length, 3);
  assert.match(records[0].verifier, /^promptsign-verify\//);
  assert.equal(records[0].user, 'tester');
  assert.equal(records[0].target, file);
  assert.equal(records[0].result, 'fail');
  assert.equal(records[0].decision, 'block');
  assert.deepEqual(records[0].rule, { layer: 'user', pattern: '*', action: 'enforce' });
  assert.equal(records[0].revocation, 'unchecked');
  assert.equal(records[1].result, 'unresolved');
  assert.equal(records[1].findings[0].level, 'warn');
  assert.equal(records[2].result, 'error');
  assert.equal(records[2].decision, undefined);
});

test('logDecisions refuses a decision it does not know', () => {
  assert.throws(
    () =>
      napi.logDecisions({
        event: 'PreToolUse',
        entries: [{ error: { message: 'x' }, decision: 'maybe' }],
      }),
    /decision must be "allow" or "block"/,
  );
});
