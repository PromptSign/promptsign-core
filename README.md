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

## Security

> [!IMPORTANT]
> This crate is a verifier, which makes it a trust root for anything that embeds it. **Please report vulnerabilities privately** through this repository's GitHub Security Advisories rather than via public issues.

### Operational Security Considerations

A valid signature establishes origin and integrity—**not safety**. 

* **Malicious Payloads** – A signed prompt-injection payload is still a prompt-injection payload.
* **Identity Attribution** – Any UI surfacing a verification result to a human should display the signing identity rather than showing a bare checkmark.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
