# @promptsign/verify

Embed the PromptSign **verifier** in Node — the same audited `promptsign-core`
(Rust) the CLI uses, wrapped with [napi-rs](https://napi.rs). For marketplaces,
registries, and CI that want to check a signature in-process instead of shelling
out to the CLI or re-implementing verification.

**Verify-only.** Signing needs the network (Sigstore) and stays in the CLI. This
package exposes verification, which is fully offline.

## API

```js
const { verify, verifyTree, verifyKeyless, policyShow, coreVersion } = require('@promptsign/verify');

// Verify a signed directory or file. Same result as `promptsign verify --json`.
const result = verify('./skills/pdf', { noPinUpdates: true });
if (result.action === 'fail') {
  console.error('do not run:', result.findings);
}

// Verify several roots at once (like `promptsign verify-tree`).
const results = verifyTree(['./skills/pdf', './agents/reviewer.md']);

// Offline keyless verification of a bundle object/JSON — throws on failure.
const who = verifyKeyless(bundleJson); // { identity, issuer, keyid }

// The effective policy for a directory (like `promptsign policy show`).
const policy = policyShow('.');

coreVersion(); // the wrapped promptsign-core version
```

`verify` / `verifyTree` return the same `VerifyResult` shape the CLI emits with
`--json` (`action` is `"pass" | "warn" | "fail"`; see `index.d.ts`). Policy and
TOFU-pin resolution follow the CLI's rules and honour `PROMPTSIGN_HOME`.

## Building the native addon

Prebuilt binaries ship as platform packages (see below). To build from source in
this repo for local dev:

```sh
# 1. compile the cdylib (from the promptsign-core repo root)
cargo build --release -p promptsign-napi --manifest-path Cargo.toml
# 2. copy it next to index.cjs as promptsign-napi.node
node promptsign-napi/scripts/copy-artifact.mjs
```

(With `@napi-rs/cli` installed, `napi build --release` does both and regenerates
`index.d.ts`.)

## Distribution & publishing

`@promptsign/verify` ships **no binary itself**. Each platform's addon is a
separate package under `npm/` — `@promptsign/verify-linux-x64-gnu`,
`-linux-arm64-gnu`, `-linux-x64-musl`, `-linux-arm64-musl`, `-darwin-x64`,
`-darwin-arm64`, `-win32-x64-msvc` — listed as `optionalDependencies`. npm
installs only the one matching the host's `os`/`cpu`/`libc`; `index.cjs` then
loads it (a local dev build, if present, wins) and detects glibc vs musl via the
Node report. This is the standard napi-rs prebuild layout done by hand, so the
loader stays auditable.

Releases are automated by `.github/workflows/publish-verify.yml`:

1. bump the version and sync every platform package + pin:
   ```sh
   cd promptsign-napi && npm version <x.y.z> && npm run sync-versions
   ```
2. tag `verify-v<x.y.z>` and push. The workflow builds all seven targets (musl
   via `cross`, the rest via plain cargo), stages each into its `npm/<platform>/`
   dir (`scripts/stage-platform.mjs`), and publishes the platform packages + the
   main package with `--provenance`.

Needs an `NPM_TOKEN` secret with publish rights to the `@promptsign` scope.

## Tests

```sh
# needs a CLI built with the local-key feature for the parity comparison
# (promptsign-cli is a separate sibling repo, cloned next to this one)
cargo build --features local-key -p promptsign-cli --manifest-path ../promptsign-cli/Cargo.toml
cd promptsign-napi && node --test
```

The tests assert the binding's `VerifyResult` is byte-for-byte identical to the
CLI's `verify --json` on the same fixture — the parity guarantee that comes free
from wrapping the same core.
