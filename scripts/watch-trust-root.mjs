// Watch Sigstore's live trust root and report when it carries material the
// canonical root in trust/ does not pin yet.
//
//   node scripts/watch-trust-root.mjs           append new material, write a PR body
//   node scripts/watch-trust-root.mjs --check   report only, write nothing
//
// Exit codes: 0 ran successfully, 1 upstream was unreachable, 2 drift found in
// --check mode. Whether drift was found in the default mode is reported through
// GITHUB_OUTPUT and stdout rather than through the exit code, because the
// workflow has to branch on it and a non-zero exit would abort the job.
//
// This is a comparison of sets, not of bytes, and that difference is the whole
// design. The two endpoints below serve only what is current. The pinned root
// accumulates, because rotation here is append and never replace. After the
// first rotation the two files are permanently unequal byte for byte, and that
// is correct rather than broken. The question worth asking is narrower: does
// upstream serve anything we do not already pin?
//
// So this script only ever appends. It has no code path that writes upstream
// content over a pinned file, which makes the append-only rule structural
// instead of a warning somebody has to read. Dropping a retired CA or log key
// would invalidate every signature made under it.
//
// These endpoints cannot distinguish a genuine rotation from a replayed
// downgrade, so nothing here is trusted enough to commit on its own. The job
// opens a pull request and a human decides. When trusted_root.json support
// lands, fetchUpstream is the one function that has to change, because TUF
// carries the same material with the metadata to tell those two cases apart.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.dirname(HERE);
const TRUST_DIR = path.join(REPO_ROOT, 'trust');

const SOURCES = {
  'fulcio.pem': {
    url: 'https://fulcio.sigstore.dev/api/v1/rootCert',
    label: 'CERTIFICATE',
    what: 'Fulcio CA',
  },
  'rekor.pub': {
    url: 'https://rekor.sigstore.dev/api/v1/log/publicKey',
    label: 'PUBLIC KEY',
    what: 'Rekor log',
  },
};

const ATTEMPTS = 3;
const TIMEOUT_MS = 15_000;
const BACKOFF_MS = [2_000, 5_000];

// Written next to the appended files for the workflow to hand to `gh pr create`.
// Untracked, so .gitignore keeps it out of the very commit this script prepares.
const PR_BODY_FILE = 'trust-root-pr-body.md';

const checkOnly = process.argv.includes('--check');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Every PEM block of one label, kept as both its identifier and its original
 *  text. The identifier is the sha256 of the decoded body, which is exactly what
 *  the core compares on. For a Rekor key that value is the log id, and for a CA
 *  it is the fingerprint of the certificate DER. */
function blocks(text, label) {
  const re = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`, 'g');
  return [...text.matchAll(re)].map((m) => {
    const der = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
    return { id: createHash('sha256').update(der).digest('hex'), pem: m[0].trim() };
  });
}

// The timeout is an explicit controller rather than AbortSignal.timeout so that
// it can be cleared. A timer left armed keeps a libuv handle open, and on
// Windows exiting over one of those trips an assertion inside libuv itself
// instead of returning the exit code.
async function fetchUpstream(url) {
  let last;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        signal: ac.signal,
        headers: { accept: 'application/x-pem-file, text/plain' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      return await res.text();
    } catch (e) {
      last = e;
      if (attempt < ATTEMPTS) await sleep(BACKOFF_MS[attempt - 1]);
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(`${url}: ${last?.message ?? last}`);
}

const unreachable = (detail) => {
  process.stderr.write(
    `PromptSign: could not reach Sigstore.\n  ${detail}\n\n` +
      `Nothing was compared, so this is not a drift finding. Re-run the job.\n`,
  );
  return 1;
};

async function collect() {
  const findings = [];
  for (const [name, src] of Object.entries(SOURCES)) {
    let upstreamText;
    try {
      upstreamText = await fetchUpstream(src.url);
    } catch (e) {
      return { code: unreachable(e.message) };
    }

    const pinnedText = fs.readFileSync(path.join(TRUST_DIR, name), 'utf8');
    const pinned = blocks(pinnedText, src.label);
    const upstream = blocks(upstreamText, src.label);

    if (upstream.length === 0) {
      return {
        code: unreachable(
          `${src.url} returned no ${src.label} block. An empty answer is treated as ` +
            `unreachable rather than as a rotation, because it must never be read as ` +
            `"upstream dropped everything".`,
        ),
      };
    }

    const pinnedIds = new Set(pinned.map((b) => b.id));
    const upstreamIds = new Set(upstream.map((b) => b.id));

    findings.push({
      name,
      ...src,
      pinnedText,
      pinned,
      // Material upstream serves that we have never pinned. This is what a
      // rotation looks like, and it is the only thing that opens a pull request.
      added: upstream.filter((b) => !pinnedIds.has(b.id)),
      // Material we pin that upstream has stopped serving. Expected after any
      // rotation, and deliberately kept. It is surfaced so that a reviewer can
      // see what a careless copy would have destroyed.
      retired: pinned.filter((b) => !upstreamIds.has(b.id)),
    });
  }
  return { findings };
}

async function main() {
  const { code, findings } = await collect();
  if (code !== undefined) return code;

  for (const f of findings) {
    for (const b of f.added) process.stdout.write(`  NEW      ${f.name}  ${b.id}\n`);
    for (const b of f.retired) process.stdout.write(`  retired  ${f.name}  ${b.id}\n`);
    if (f.added.length === 0 && f.retired.length === 0) {
      process.stdout.write(`  ok       ${f.name}  ${f.pinned.map((b) => b.id).join(', ')}\n`);
    }
  }

  const drifted = findings.filter((f) => f.added.length > 0);

  if (drifted.length === 0) {
    process.stdout.write('\nthe pinned trust root already covers everything Sigstore serves\n');
    if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'drift=false\n');
    return 0;
  }

  if (checkOnly) {
    process.stderr.write('\nSigstore serves material the pinned root does not cover.\n');
    return 2;
  }

  // Append, never replace. The existing text is copied through byte for byte
  // rather than normalised, so the pull request shows added lines and nothing
  // else. A rotation is reviewed on the identifiers it introduces, and
  // reflowing untouched material buries that in whitespace noise.
  //
  // Whether the file ends in a newline is treated as its own convention and
  // preserved. Sigstore's files do not end in one, which is why appending with
  // a plain `cat` runs the END and BEGIN markers together on one line. That
  // still parses, and it is unpleasant to read, so the separator is written
  // here. Matching the trailing convention is what keeps the diff to added
  // lines only, including on the first rotation, so a reviewer can see that
  // nothing was removed or rewritten without reading a byte of base64.
  for (const f of drifted) {
    const trailingNewline = f.pinnedText.endsWith('\n');
    const separator = trailingNewline ? '' : '\n';
    const trailer = trailingNewline ? '\n' : '';
    const appended = f.added.map((b) => b.pem).join('\n');
    const body = `${f.pinnedText}${separator}${appended}${trailer}`;
    fs.writeFileSync(path.join(TRUST_DIR, f.name), body);
  }

  // The in-repo copies have to move with the canonical root, or the pull
  // request fails the drift check that guards them.
  execFileSync(process.execPath, [path.join(HERE, 'sync-trust.mjs')], { stdio: 'inherit' });

  writePrBody(drifted);
  return 0;
}

/** The pull request body. Identifiers rather than base64, so that review is a
 *  comparison of short hex strings and not of PEM. */
function writePrBody(drifted) {
  const lines = [
    'Sigstore is serving trust material that the pinned root in `trust/` did not',
    'cover. The new blocks have been **appended**. Nothing was replaced or removed.',
    '',
    'Review this as a diff of identifiers rather than of base64. Each value below is',
    'the sha256 of the decoded DER, which is what `promptsign-core` compares on.',
    '',
  ];

  for (const f of drifted) {
    lines.push(`## ${f.what} (\`trust/${f.name}\`)`, '');
    lines.push('| | identifier |', '| --- | --- |');
    for (const b of f.added) lines.push(`| **added** | \`${b.id}\` |`);
    for (const b of f.pinned.filter((p) => !f.retired.some((r) => r.id === p.id))) {
      lines.push(`| kept | \`${b.id}\` |`);
    }
    for (const b of f.retired) lines.push(`| kept, retired upstream | \`${b.id}\` |`);
    lines.push('');
    if (f.retired.length > 0) {
      const n = f.retired.length;
      lines.push(
        `> Sigstore no longer serves ${n} ${f.what} entr${n === 1 ? 'y' : 'ies'} that this root`,
        '> still pins. That is expected, and the entries must stay. Everything signed',
        '> under them verifies only while they remain. Do not tidy them out of this',
        '> pull request.',
        '',
      );
    }
  }

  lines.push(
    '## Before merging',
    '',
    "- [ ] Confirm each added identifier against Sigstore's own rotation announcement.",
    '      These two endpoints serve whatever is current. They cannot tell a genuine',
    '      rotation from a replayed downgrade, which is the reason this is a pull',
    '      request and not an automatic commit.',
    '- [ ] Check that no previously pinned identifier has disappeared from the table.',
    '- [ ] Update the Rekor log id quoted in `trust/README.md`, `promptsign-napi/README.md`,',
    '      and `promptsign-plugin/trust/README.md` if the current log changed.',
    '- [ ] Sync `promptsign-plugin/trust/` from this branch once it lands, or its own',
    '      drift check will go red.',
    '',
    'CI does not start on its own here, because a pull request opened with',
    '`GITHUB_TOKEN` does not trigger workflows. Close and reopen it to run the checks.',
  );

  const bodyPath = path.join(REPO_ROOT, PR_BODY_FILE);
  fs.writeFileSync(bodyPath, lines.join('\n') + '\n');

  process.stdout.write(`\nappended new material and wrote ${PR_BODY_FILE}\n`);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'drift=true\n');
}

// Assigned rather than passed to process.exit. Calling process.exit while
// undici still holds a socket from fetch aborts the process inside libuv on
// Windows, which surfaces as an assertion failure and exit code 127 instead of
// the code this script meant to return.
process.exitCode = await main();
