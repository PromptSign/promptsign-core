// Copy the canonical pinned trust root in trust/ over every in-repo copy of it.
//
// The canonical root lives at the repo root because it is owned by the project,
// not by any one thing that publishes it. promptsign-napi/trust/ exists only
// because npm publishes what is inside the package directory and nothing else,
// so @promptsign/verify cannot reference a file above itself.
//
// The copy is committed rather than produced at build time, which means it can
// drift. test/trust-root.test.mjs fails when it has; this script is the fix it
// points at. Run it after appending rotated material to the canonical files.
//
// Usage:
//   node scripts/sync-trust.mjs          # write the copies
//   node scripts/sync-trust.mjs --check  # report drift, write nothing (exit 1)
import { copyFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');

// The canonical directory also holds a README explaining what it is, which the
// copies deliberately do not get: promptsign-napi/trust/ ships to npm, and a
// file telling the reader to edit a directory that is not in the tarball would
// be worse than no file at all. Only these two are the trust root.
const FILES = ['fulcio.pem', 'rekor.pub'];
const CANONICAL = path.join(repoRoot, 'trust');
const COPIES = [path.join(repoRoot, 'promptsign-napi', 'trust')];

const check = process.argv.includes('--check');
const rel = (p) => path.relative(repoRoot, p).replaceAll(path.sep, '/');

let drifted = 0;
for (const dir of COPIES) {
  for (const name of FILES) {
    const src = path.join(CANONICAL, name);
    const dest = path.join(dir, name);

    // Compared as bytes, not as parsed PEM: .gitattributes normalises the repo
    // to LF, so an equal-bytes check is portable, and a copy that differs only
    // in whitespace is still a copy someone edited in place.
    let same = false;
    try {
      same = readFileSync(src).equals(readFileSync(dest));
    } catch {
      same = false; // missing copy counts as drift
    }
    if (same) continue;

    drifted++;
    if (check) {
      console.error(`drift: ${rel(dest)} differs from ${rel(src)}`);
      continue;
    }
    copyFileSync(src, dest);
    console.log(`synced ${rel(src)} -> ${rel(dest)}`);
  }
}

if (check && drifted) {
  console.error(
    `\n${drifted} file(s) out of step with the canonical root in trust/.\n` +
      'Append rotated material to trust/, never to a copy, then run:\n' +
      '  node scripts/sync-trust.mjs',
  );
  process.exit(1);
}
if (!drifted) console.log('trust root copies are in step with trust/');
