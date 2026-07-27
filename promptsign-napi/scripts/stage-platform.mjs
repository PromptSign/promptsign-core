// CI helper: copy a freshly cross-built cdylib into its npm/<platform>/ package
// directory as `promptsign-napi.node`, ready to publish. Mirrors what
// copy-artifact.mjs does for a local dev build, but for an explicit target.
//
// Usage:
//   node scripts/stage-platform.mjs <rust-target-triple> <npm-platform>
//   node scripts/stage-platform.mjs x86_64-unknown-linux-gnu linux-x64-gnu
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const [triple, platform] = process.argv.slice(2);
if (!triple || !platform) {
  console.error('usage: stage-platform.mjs <rust-target-triple> <npm-platform>');
  process.exit(1);
}

const here = path.dirname(fileURLToPath(import.meta.url));
// cargo puts cross-built artifacts under target/<triple>/release.
const releaseDir = path.resolve(here, '..', '..', 'target', triple, 'release');
const candidates = ['promptsign_napi.dll', 'libpromptsign_napi.so', 'libpromptsign_napi.dylib'];

const src = candidates.map((c) => path.join(releaseDir, c)).find((p) => existsSync(p));
if (!src) {
  console.error(`no built cdylib in ${releaseDir} — did the target build for ${triple}?`);
  process.exit(1);
}

const destDir = path.resolve(here, '..', 'npm', platform);
mkdirSync(destDir, { recursive: true });
const dest = path.join(destDir, 'promptsign-napi.node');
copyFileSync(src, dest);
console.log(`staged ${path.basename(src)} -> ${path.relative(process.cwd(), dest)}`);
