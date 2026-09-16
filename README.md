# promptsign-core

The Rust implementation of [PromptSign](https://github.com/PromptSign/spec) —
signing and verification of AI instruction files (`SKILL.md`, `CLAUDE.md`,
`AGENTS.md`, agent definitions) and the script payloads that ship with them.

Agentic coding tools load these files straight into a model's context, where
they act as executable code, and skills bundle scripts the host actually runs.
This crate is what decides whether a given one came from who it claims and has
not been altered since.

The wire formats are specified independently, in
[PromptSign/spec](https://github.com/PromptSign/spec). This is *an*
implementation of them, not the definition — a second, independent
implementation in Node is held to byte-for-byte agreement with it.

## Workspace

| Crate | What it is |
|---|---|
| [`promptsign-core`](promptsign-core/) | The library: canonicalization, manifests, DSSE envelopes, keyless verification, trust policy, revocation. |
| [`promptsign-napi`](promptsign-napi/) | A [napi-rs](https://napi.rs) binding publishing the verifier to Node as [`@promptsign/verify`](promptsign-napi/README.md). |

Marketplaces, registries, harnesses, and CI embed one of these in-process
rather than shelling out to a binary or reimplementing verification. One
audited core behind every surface is deliberate: a verifier *monoculture* is
the good kind — one thing to audit, one place to fix.

## Where the pinned trust root lives

[`trust/`](trust/) at the repository root is the canonical, single source of
truth for the pinned Sigstore trust root — `fulcio.pem` and `rekor.pub`. This
repository owns it, and everything else that carries those bytes carries a copy:
`promptsign-napi/trust/`, because npm publishes only what is inside the package
directory, and `promptsign-plugin/trust/`, because the plugin's binary tier has
no `node_modules` to read the npm package's copy from.

Rotate the root in `trust/` and nowhere else. Rotation is **append, never
replace** — dropping retired material invalidates every signature made under it.
`node scripts/sync-trust.mjs` pushes a change out to the in-repo copies, and
`promptsign-napi/test/trust-root.test.mjs` fails when a copy has drifted. See
[`trust/README.md`](trust/README.md) for the full procedure.

## Scope

**Verification — all of it, fully offline.**

This project handles the complete verification lifecycle entirely locally:

* **Signature & Integrity Checking** – Validates cryptographic signatures and payloads.
* **Trust-Policy Evaluation** – Enforces user-defined trust boundaries locally.
* **Trust-On-First-Use (TOFU) Pins** – Manages local state for initial trust anchors.
* **Offline Keyless Verification** – Validates certificate chains, transparency-log inclusion
proofs, and signed entry timestamps without network calls.
* **Revocation-Feed Evaluation** – Inspects certificate validity against a locally cached feed.

**Signing — local keys only.**

The `keys::keygen` and `bundle::sign_manifest` functions produce Ed25519 signatures with zero network involvement.

**Keyless signing is deliberately *out of scope*.**

Obtaining an OpenID Connect token, exchanging it for a short-lived Fulcio certificate,
and writing to the Rekor transparency log all require network access. Including them in
this crate would drag an HTTP stack into the dependency tree of every verifier that embeds it. 

That flow lives in the `promptsign` CLI instead. This crate strictly *verifies* the resulting
bundle—offline, forever after.

## Using it

```rust
use promptsign_core::policy::Action;
use promptsign_core::verify::{verify_target, VerifyOptions};

let result = verify_target("./skills/pdf", &VerifyOptions::default())?;

match result.action {
    Action::Pass => println!("signed by {:?}", result.identity),
    Action::Warn => eprintln!("warnings: {:?}", result.findings),
    Action::Fail => eprintln!("do not load: {:?}", result.findings),
}
```

`VerifyResult` carries the signer `identity`, `issuer`, and `keyid`, plus
`integrated_time` — the authenticated moment the transparency log witnessed a
keyless signature. It serializes to exactly the JSON the CLI emits under
`--json`.

Other entry points, by module:

- `verifytree::{discover_targets, verify_tree}` — walk a repo or config
  directory and verify every instruction file found. The workhorse of
  session-start enforcement.
- `manifest::{build_manifest, check_integrity, walk_files}` — build and check
  the digest manifest for a bundle.
- `canonicalize` — the canonical form digests are taken over, and the
  invisible-Unicode rejection rules.
- `bundle::{sign_manifest, verify_envelope, locate_bundle}` — DSSE envelopes
  and the three carriage forms (directory bundle, sidecar, embedded).
- `keyless::{verify_keyless, load_trust_root}` — offline keyless verification.
- `policy::{load_policy, evaluate, load_pins}` — who may sign what.
- `revocation` — feed parsing, entry matching, and staleness.

Errors are plain `String`s (`Error = String`): every failure ends up as a
one-line message in a CLI or hook, and the Node implementation's error model is
the same.

## Design constraints

These are requirements, not aspirations, because a verifier that is slow,
flaky, or fat does not get embedded:

- **No network on the verify path.** Not a policy — a structural property. The
  dependency tree contains no HTTP client and no TLS stack: no `reqwest`,
  `hyper`, `ureq`, `curl`, `tokio`, `openssl`, or `rustls`. Verification cannot
  phone home because there is nothing here that could. Everything a check needs
  is stapled into the bundle or cached on disk, so verification works on a
  plane and in a sealed CI sandbox, and can never be *down*.
- **Small enough to audit.** 11 direct dependencies; 55 crates in the full
  transitive tree. The verifier becomes the new root of trust the moment anyone
  relies on it, and a verifier with a supply-chain problem is a punchline.
- **Fast enough to run constantly.** Verification happens on every session
  start and every skill invocation, so it competes with startup time, not with
  build time.

## Spec Conformance

Implements [Specifications 01–06](https://github.com/PromptSign/spec):
* Bundle manifest
* Canonicalization
* Signature bundle
* Trust policy
* Keyless verification
* Revocation feed

### Cross-Implementation Compatibility
Wire compatibility with the Node reference implementation is enforced by a cross-implementation test suite:
* A bundle signed by either implementation verifies in the other.
* Canonical digests agree byte for byte.

When this crate and the spec disagree, the spec is right.

## Releasing

This repo cuts two independent releases. Neither version number derives from
the other, so each gets its own bump and its own tag.

| Release | Version lives in | Tag | Publishes to |
|---|---|---|---|
| `promptsign-core` crate | `Cargo.toml` `[workspace.package].version` | `core-vX.Y.Z` | crates.io, via `.github/workflows/publish-crate.yml` (trusted publishing, no token) |
| `@promptsign/verify` (napi) | `promptsign-napi/package.json` `.version` | `verify-vX.Y.Z` | npm, 8 packages, via `.github/workflows/publish-verify.yml` (trusted publishing, no token) |

### 1. Release the `promptsign-core` crate

1. In `Cargo.toml`, set `[workspace.package].version` to `X.Y.Z`. This also
   moves `promptsign-napi`'s *crate* version, since it inherits the workspace
   version. That is expected, and unrelated to the napi *npm* version in
   step 2 below.
2. `cargo test -p promptsign-core --locked`
3. `git commit -am "Release promptsign-core X.Y.Z"`
4. `git tag core-vX.Y.Z`
5. `git push origin main && git push origin core-vX.Y.Z`
6. Watch `publish-crate.yml` finish and confirm `X.Y.Z` is live on crates.io
   before moving on to a `promptsign-cli` release (see below).

### 2. Release `@promptsign/verify` (napi)

`promptsign-napi/package.json`'s `version` is a separate field from the crate
version above, and `npm publish` reads it, not `Cargo.toml`.

1. From `promptsign-napi/`: `npm version X.Y.Z --no-git-tag-version`
2. `npm run sync-versions`, which copies the new version into the 7
   `npm/*/package.json` platform packages and into the main package's
   `optionalDependencies` pins.
3. `git add promptsign-napi/package.json promptsign-napi/npm/*/package.json`
4. `git commit -m "Release @promptsign/verify X.Y.Z"`
5. `git tag verify-vX.Y.Z`
6. `git push origin main && git push origin verify-vX.Y.Z`
7. Watch `publish-verify.yml` finish.

Skip steps 1-2 and tag directly, and `npm publish` rejects the release with
"cannot publish over the previously published version": every platform
package still carries the old version number.

### 3. Downstream: `promptsign-cli`

`promptsign-cli` lives in its own repo and depends on the published
`promptsign-core` crate, not this checkout. Once step 1 above is live on
crates.io: in the `promptsign-cli` repo, bump its `Cargo.toml` version and its
`promptsign-core = "X.Y.Z"` dependency line, run
`cargo update -p promptsign-core --precise X.Y.Z` to refresh `Cargo.lock`
against the now-published crate, commit both files together, then tag and
push that repo's own `vX.Y.Z`.

## Security

> [!IMPORTANT]
> This crate is a verifier, which makes it a trust root for anything that embeds it. **Please report vulnerabilities privately** through this repository's GitHub Security Advisories rather than via public issues.

### Operational Security Considerations

A valid signature establishes origin and integrity—**not safety**. 

* **Malicious Payloads** – A signed prompt-injection payload is still a prompt-injection payload.
* **Identity Attribution** – Any UI surfacing a verification result to a human should display the signing identity rather than showing a bare checkmark.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
