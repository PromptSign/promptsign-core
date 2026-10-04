# Foreign signature fixtures

Real bundles in formats PromptSign verifies but does not produce. The repo
`.gitattributes` marks them `-text`: these formats hash raw bytes, and a
line-ending conversion would break them. Tests that need a tampered or CRLF
copy build it in a temp directory at run time.

The OMS fixtures below verify as stored with `model_signing` 1.1.1 (sigstore
4.5.0). Each one is a Sigstore bundle v0.3 (`application/vnd.dev.sigstore.bundle.v0.3+json`)
around a DSSE envelope (`application/vnd.in-toto+json`) around an in-toto
Statement v1.

## oms/

| Fixture | Source | Predicate | Signer material | Transparency |
|---|---|---|---|---|
| `nvidia-earth2studio-discover/` | `NVIDIA/skills` @ `0e0d506`, `skills/earth2studio-discover` (Apache-2.0) | `model_signing/signature/v1.0` | `x509CertificateChain`, 3 certs, P-384: leaf `CN=NVIDIA Agent Skills Signing 001` (no SAN), `CN=NVIDIA Agent Capabilities ICA 01`, root `CN=NVIDIA Agent Capabilities CA` | none |
| `nvidia-agent-root-cert.pem` | `NVIDIA/skills` @ `0e0d506`, `nv-agent-root-cert.pem` | | trust anchor for the row above, SHA-256 fingerprint `6F:1B:B8:75:...:37:82` | |
| `upstream-v1.1.0-sigstore/` | `sigstore/model-transparency` @ `38aa519`, `scripts/tests/v1.1.0-sigstore` (Apache-2.0) | `model_signing/signature/v1.0`, `ignore_paths` includes `ignore-me` | `certificate` (leaf only), Fulcio, `email:stefanb@us.ibm.com`, issuer `https://sigstore.verify.ibm.com/oauth2` | Rekor v1 `dsse` 0.0.1, SET + inclusion proof + checkpoint, plus one RFC3161 timestamp; integratedTime 1760062340 |
| `upstream-v1.0.0-sigstore/` | same repo, `scripts/tests/v1.0.0-sigstore` | `model_signing/signature/v1.0`, no `ignore_paths` field | same identity | Rekor v1 `dsse` 0.0.1, SET; integratedTime 1746236086 |
| `upstream-v1.1.0-certificate/` | same repo, `scripts/tests/v1.1.0-certificate` | `model_signing/signature/v1.0` | `x509CertificateChain`, 2 certs: P-384 leaf, RSA-signed intermediate | none |
| `upstream-v0.2.0-certificate/` | same repo, `scripts/tests/v0.2.0-certificate` | `model_signing/Digests/v0.1` (one subject per file, predicate unused) | `x509CertificateChain`, 2 certs | none |
| `upstream-certificate-ca.pem` | same repo, `scripts/tests/keys/certificate/ca-cert.pem` | | trust anchor for the two rows above (`CN=root-ca`) | |
| `key-skill/` | generated here | `model_signing/signature/v1.0` | `publicKey` hint, ECDSA P-256 (`key-skill.ec.pub`) | none |
| `key-skill-ignore-scripts/` | generated here, signed with `--ignore-paths <dir>/scripts` | as above; `scripts` in `ignore_paths` | as above | none |
| `key-skill-bidi/` | generated here, `SKILL.md` heading contains U+202E | as above | as above | none |

PromptSign verifies bundles from `model_signing` 1.0 and later. The tests use
`upstream-v0.2.0-certificate/` as the earlier-version case it rejects.

We signed the `key-skill*` fixtures with
`model_signing sign key --private_key ec.key --signature <dir>/skill.oms.sig <dir>`
and did not keep the private key.

## Format facts the parser relies on

- **Root digest.** `subject[0].digest.sha256` = SHA-256 over the concatenated raw
  digests of `predicate.resources`, in predicate order. The subject name is the
  signed directory's basename.
- **Signature file.** `resources` never lists the signature file; exclude it
  from the directory walk.
- **Default ignores.** From v1.1.0 on, `ignore_paths` includes `.git`,
  `.github`, `.gitattributes` and `.gitignore`.
- **Chain order.** `certificates[0]` is the leaf. Build the chain by position and
  signature, not by subject name.
- **Key hint.** `publicKey.hint` is not the SHA-256 of the SPKI DER; match keys
  by PromptSign's own keyid.
