# The canonical pinned Sigstore trust root

`fulcio.pem` (the Fulcio CA certificate chain) and `rekor.pub` (the Rekor
transparency log's public key) are what every keyless signature PromptSign
checks is ultimately anchored to. **This directory is the single source of
truth for both.** Everywhere else they appear, they appear as a copy.

They are pinned and committed rather than fetched, so a fresh install can verify
offline with no network call on the first use. Fetching the root over TLS on
first use would be trust-on-first-use on the trust root itself, which is the one
place that defeats the point.

Rekor log id (hex SHA-256 of the log key's SPKI DER), for cross-checking:

```
c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
```

## Who copies from here

| Copy | Why it exists | How it is kept in step |
| --- | --- | --- |
| [`promptsign-napi/trust/`](../promptsign-napi/trust/) | npm ships only what is inside the package directory, so `@promptsign/verify` needs its own copy to be published. | `node scripts/sync-trust.mjs`, enforced by a test (see below). |
| `promptsign-plugin/trust/` (separate repo) | The plugin's binary tier has no `node_modules` to read the npm package's copy from. | A CI check in that repo, comparing against this directory. |

The copies are committed rather than generated at build time on purpose. A build
step that materialises the root can be misconfigured, and when it is, the result
is a package that installs cleanly and then fails at verification time on
someone else's machine. A committed copy that drifts fails in CI instead, on the
pull request that caused it.

## Rotating the root

Sigstore rotates these rarely, but it does. Rotation is **append, never
replace**. Both files hold a list: `fulcio.pem` is a chain of CA certificates,
`rekor.pub` holds one PEM block per trusted log. A signature is checked against
the CA that issued its certificate and the log that witnessed its entry, and
each is selected by identity rather than by position. Keeping the retired
material is what lets everything signed before the rotation carry on verifying.
Dropping it silently invalidates the entire back catalogue.

```sh
promptsign trust fetch                              # writes the current root
cat ~/.promptsign/trust/rekor.pub  >> trust/rekor.pub
cat ~/.promptsign/trust/fulcio.pem >> trust/fulcio.pem
node scripts/sync-trust.mjs                         # push the change to the copies
cd promptsign-napi && node --test test/trust-root.test.mjs
```

New material goes first if you want it listed as current; otherwise the order is
cosmetic. `test/trust-root.test.mjs` asserts the already-pinned log is still
present, so appending passes and replacing fails until the pinned id changes in
the same commit.

Treat a change to either file as security-relevant: give it its own commit, state
the new log id in the commit message, and bump the version.
