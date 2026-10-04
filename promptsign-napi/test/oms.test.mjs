// OMS verification and the root registry through the npm binding. Runs in its
// own process (node --test isolates files), so PROMPTSIGN_HOME set here does
// not leak into the other tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, '..', '..', 'promptsign-core', 'tests', 'fixtures', 'foreign', 'oms');
const NVIDIA_FP = '6f1bb875b77aea3fc878a7a3237497235c53657601375c0ef4bdcde69e843782';

// A certificate-mode root in trusted_root.json shape, as `promptsign trust add
// --ca` writes it.
function caRootDoc(pemPath) {
  const der = readFileSync(pemPath, 'utf8')
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return {
    mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
    tlogs: [],
    certificateAuthorities: [{ certChain: { certificates: [{ rawBytes: der }] } }],
  };
}

const base = mkdtempSync(path.join(tmpdir(), 'ps-napi-oms-'));
const home = path.join(base, 'home');
const trust = path.join(home, 'trust');
mkdirSync(path.join(trust, 'roots'), { recursive: true });
cpSync(path.join(here, '..', 'trust'), trust, { recursive: true });
writeFileSync(path.join(trust, 'roots', 'nvidia.json'), JSON.stringify(caRootDoc(path.join(fixtures, 'nvidia-agent-root-cert.pem'))));
process.env.PROMPTSIGN_HOME = home;

const { verify, trustRoots } = createRequire(import.meta.url)('../index.cjs');

test('trustRoots lists the pinned public root and the user\'s named roots', () => {
  const roots = trustRoots();
  assert.deepEqual(
    roots.map((r) => [r.name, r.kind]),
    [
      ['sigstore-public', 'keyless'],
      ['nvidia', 'certificate'],
    ],
  );
  assert.equal(roots[1].fingerprint, NVIDIA_FP);
});

test('an OMS-signed skill verifies with format and root', () => {
  const skill = path.join(base, 'skills', 'earth2studio-discover');
  cpSync(path.join(fixtures, 'nvidia-earth2studio-discover'), skill, { recursive: true });
  const policy = path.join(base, 'policy.json');
  writeFileSync(policy, JSON.stringify({ schema: 'promptsign/policy/v1', default: 'enforce', rules: [] }));

  const r = verify(skill, { policyPath: policy, noPinUpdates: true });
  assert.equal(r.action, 'pass', JSON.stringify(r.findings));
  assert.equal(r.format, 'oms');
  assert.equal(r.root, 'nvidia');
  assert.equal(r.kind, 'skill');

  writeFileSync(path.join(skill, 'SKILL.md'), '# replaced\n');
  const tampered = verify(skill, { policyPath: policy, noPinUpdates: true });
  assert.equal(tampered.action, 'fail');
  assert.ok(tampered.findings.some((f) => f.message === 'modified: SKILL.md'));
});
