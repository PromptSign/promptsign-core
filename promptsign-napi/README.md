# @promptsign/verify

Embed the PromptSign **verifier** in Node using the same audited `promptsign-core`
(Rust) the CLI uses, wrapped with [napi-rs](https://napi.rs). This is intended for marketplaces,
registries, and CI that want to check a signature in-process instead of shelling
out to the CLI or re-implementing verification.

**Verify-only.** Signing needs the network (Sigstore) and stays in the CLI. This
package exposes verification, which runs fully offline against the Sigstore trust
root pinned in `trust/` — no network call, and nothing to fetch first.

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
Trust-On-First-Use (TOFU) pin resolution follow the same rules as the CLI and 
honour `PROMPTSIGN_HOME`.

## Trust root

Every keyless signature is checked against a Sigstore trust root: Fulcio's CA
chain (`fulcio.pem`) and the Rekor log's public key (`rekor.pub`). This package
pins its own copy in `trust/`, so `npm install` is all that is needed. 
Verification does not require `promptsign trust fetch`, or the CLI at all.

Pinning at build time is deliberately stronger than fetching the root over TLS on
first use, which would amount to trust-on-first-use on the trust root itself.

Resolution order, highest first:

| | Where the root comes from |
|---|---|
| `PROMPTSIGN_TRUST_DIR` | An explicit directory. Use this for a private trust root. |
| `PROMPTSIGN_HOME` | `$PROMPTSIGN_HOME/trust`, i.e. whatever `promptsign trust fetch` cached. |
| bundled | The copy in this package. |
| default | `~/.promptsign/trust`, when the package has no bundled copy. |

Nothing the host already set is ever overridden. `trustRoot()` reports which of
the four is in effect and why:

```js
const { trustRoot } = require('@promptsign/verify');
trustRoot(); // { dir: '…/node_modules/@promptsign/verify/trust', source: 'bundled' }
```

One consequence worth knowing: setting `PROMPTSIGN_HOME` for pins or policy also opts out of 
the bundled root, because `PROMPTSIGN_HOME` takes precedence. If that home has no cached root,
verification fails; the error says exactly this rather than leaving you to work it out.

Mechanically, the bundled root is selected by setting `PROMPTSIGN_TRUST_DIR` on
the first `verify` / `verifyTree` / `verifyKeyless` call, since the core reads the
directory from the environment. Importing the package changes nothing.

**Rotating it.** Sigstore rotates these rarely, but it does. Refresh with:

```sh
promptsign trust fetch
cp ~/.promptsign/trust/fulcio.pem ~/.promptsign/trust/rekor.pub promptsign-napi/trust/
cd promptsign-napi && node --test test/trust-root.test.mjs   # asserts the log id
```

That test pins the expected Rekor log id, so a changed root fails until the
constant is updated in the same commit. Treat it as a security-relevant change:
its own commit, the new log id in the message, and a version bump.

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
separate package under `npm/`. The packages are `@promptsign/verify-linux-x64-gnu`,
`-linux-arm64-gnu`, `-linux-x64-musl`, `-linux-arm64-musl`, `-darwin-x64`,
`-darwin-arm64`, `-win32-x64-msvc`, and they are listed as `optionalDependencies`. 
npm installs only the one matching the host's `os`/`cpu`/`libc`; `index.cjs` then
loads it, with a local development build taking precedence if present, and detects 
glibc vs musl via the Node report. This is the standard napi-rs prebuild layout 
implemented by hand, so the loader stays auditable.

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
CLI's `verify --json` on the same fixture. This provides parity guarantee that
comes free from wrapping the same core.
