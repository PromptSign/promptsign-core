// Copy the freshly built cdylib to `promptsign-napi.node` so `require()` finds it.
// The @napi-rs/cli would do this (plus generate index.d.ts) if installed; this
// keeps the build working with a plain `cargo build` and no npm toolchain.
import { copyFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const releaseDir = path.resolve(here, '..', '..', 'target', 'release');
const candidates = ['promptsign_napi.dll', 'libpromptsign_napi.so', 'libpromptsign_napi.dylib'];

const src = candidates.map((c) => path.join(releaseDir, c)).find((p) => existsSync(p));
if (!src) {
  console.error(
    `no built cdylib in ${releaseDir} — run: cargo build --release -p promptsign-napi --manifest-path ../Cargo.toml`,
  );
  process.exit(1);
}
const dest = path.resolve(here, '..', 'promptsign-napi.node');
copyFileSync(src, dest);
console.log(`copied ${path.basename(src)} -> ${path.relative(process.cwd(), dest)}`);
