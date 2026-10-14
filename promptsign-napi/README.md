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
const {
  verify, verifyTree, verifyKeyless, policyShow, policyLayers, strictMode, trustRoots, coreVersion,
  logDecisions,
} = require('@promptsign/verify');

// Verify a signed directory or file. Same result as `promptsign verify --json`.
const result = verify('./skills/pdf', { noPinUpdates: true });
if (result.action === 'fail') {
  console.error('do not run:', result.findings);
}

// Verify several roots at once (like `promptsign verify-tree`).
const results = verifyTree(['./skills/pdf', './agents/reviewer.md']);

// Offline keyless verification of a bundle object/JSON — throws on failure.
const who = verifyKeyless(bundleJson); // { identity, issuer, keyid, root }

// The user's policy. A project's own .promptsign/policy.json can only
// tighten it.
const policy = policyShow('.');

// Every policy layer in evaluation order: the machine's managed policy, the
// user's, the project's. Each later one can only tighten the first.
const layers = policyLayers('.'); // [{ layer, source, policy }]

// Whether a hook should fail closed: PROMPTSIGN_STRICT=1, or `strict: true`
// in the managed or the user policy.
const strict = strictMode();

// Every trust root a signature may chain to: the pinned public Sigstore root,
// managed roots and bundles, roots added with `promptsign trust add`
// (~/.promptsign/trust/roots), then the roots of installed trust bundles,
// named <bundle>/<root>.
const roots = trustRoots(); // [{ name, kind, fingerprint, subject, managed, expires? }]

coreVersion(); // the wrapped promptsign-core version

// Record what a hook did with each verification in the decision log
// (spec/08): the logs the managed and the user policy turn on, plus
// decisionLog. Returns the logs it could not write.
logDecisions({
  harness: 'claude',
  event: 'PreToolUse',
  entries: [
    { result, decision: result.action === 'fail' ? 'block' : 'allow' },
    { unresolved: { name: 'demo:missing', message: 'not found on disk' }, decision: 'allow' },
  ],
});
```

`verify` also reads OpenSSF Model Signing (OMS) bundles: a directory with
`skill.oms.sig` or `model.sig` and no PromptSign bundle is verified against the
user's trust roots, and the result carries `format: "oms"` and the `root` it
chained to. A PromptSign bundle in the same directory takes precedence.

`verify` / `verifyTree` return the same `VerifyResult` shape the CLI emits with
`--json` (`action` is `"pass" | "warn" | "fail"`; see `index.d.ts`). Each result
also carries a non-enumerable `evidence` (payload digest, deciding rule,
revocation state) that `logDecisions` reads, so pass the result object itself. Policy and 
Trust-On-First-Use (TOFU) pin resolution follow the same rules as the CLI and 
honour `PROMPTSIGN_HOME`, unless the machine's managed policy sets `lock_env`.

## Trust root

The verifier checks every keyless signature against a Sigstore trust root:
Fulcio's CA chain (`fulcio.pem`), the Rekor log's public key (`rekor.pub`), and
Sigstore's `trusted_root.json`, which adds the Rekor v2 log and the timestamp
authority. This package
ships a copy in `trust/`, so `npm install` is all that is needed. 
Verification does not require `promptsign trust fetch`, or the CLI at all.

That copy is not where the root is maintained. The canonical one lives at the
repository root, in [`trust/`](../trust/); this package carries a copy because
npm publishes what is inside the package directory and nothing above it. The two
are kept identical by `scripts/sync-trust.mjs`, and `test/trust-root.test.mjs`
fails if they drift.

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

**Rotating it.** Sigstore rotates these rarely, but it does. Rotation is
**append, never replace**. Both files hold a list: `fulcio.pem` contains a chain of CA
certificates, while `rekor.pub` contains one PEM block per trusted log. A signature is
checked against the CA that issued its certificate and the log that witnessed its entry.
Each is selected by name, so keeping the retired material is what lets everything
signed before the rotation continue to verify. Dropping it silently invalidates the
entire back catalogue.

Append to the canonical root, never to this package's copy, then sync. Editing
the copy in place is the one thing the drift test exists to catch.

```sh
promptsign trust fetch                              # writes the current root
cat ~/.promptsign/trust/rekor.pub  >> trust/rekor.pub
cat ~/.promptsign/trust/fulcio.pem >> trust/fulcio.pem
node scripts/sync-trust.mjs                         # update this package's copy
cd promptsign-napi && node --test test/trust-root.test.mjs
```

New material goes first if you want it listed as current; otherwise, order is 
cosmetic, because selection is by log id and by issuer. The test asserts the
already-pinned log is still present, so appending passes and replacing fails.
Treat it as a security-relevant change: give it its own commit, include the
new log ID in the commit message, and bump the version.

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
