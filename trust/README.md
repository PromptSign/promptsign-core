# The canonical pinned Sigstore trust root

`fulcio.pem` holds the Fulcio CA certificate chain and `rekor.pub` holds the
Rekor transparency log's public key. PromptSign anchors every keyless signature
it checks to these two files. **This directory holds the originals.** Every
other place that has them holds a copy.

The repository pins and commits both files, so a fresh install verifies offline
on first use. Fetching the root over TLS on first use would make the trust root
itself trust-on-first-use, and pinning exists to prevent exactly that.

Rekor log id (hex SHA-256 of the log key's SPKI DER), for cross-checking:

```
c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
```

## Who copies from here

| Copy | Why it exists | How it stays in step |
| --- | --- | --- |
| [`promptsign-napi/trust/`](../promptsign-napi/trust/) | npm publishes only what sits inside the package directory, so `@promptsign/verify` carries its own copy. | `node scripts/sync-trust.mjs`, enforced by a test (see below). |
| `promptsign-plugin/trust/` (separate repo) | The plugin's binary tier has no `node_modules` to read the npm package's copy from. | A CI check in that repo compares it with this directory. |
| `spec/test/fixtures/trust-roots/public/` (separate repo) | The conformance checks verify one real public-good signature against it. | It needs no syncing: the fixture signature needs only the material it was made under, and a rotation only appends. |

We commit the copies instead of generating them at build time. If someone
misconfigured a build step that wrote the root, the package would install
cleanly and then fail verification on a user's machine. A committed copy that
drifts fails CI on the pull request that caused the drift.

## Noticing a rotation

`scripts/watch-trust-root.mjs` compares what this directory pins with what
Sigstore serves. `.github/workflows/watch-trust-root.yml` runs it weekly and on
demand.

The watcher compares sets of certificates and keys, not bytes. Sigstore's two
endpoints serve the current material alone, while this root keeps the retired
material too, so after the first rotation the files differ byte for byte by
design. The watcher checks one thing: whether Sigstore serves anything this root
does not already cover.

If it does, the watcher appends the new blocks, syncs the copies, and opens a
pull request that lists the identifiers instead of the base64.

The watcher does not commit to `main`. A pin has value because it stays put when
a server changes its answer, and a job that committed what it fetched would turn
these files into "the last thing the endpoint returned". Reaching that endpoint
means trusting DNS, the public CA system, and Sigstore's infrastructure. Anyone
who subverted one of those would get their CA appended on a schedule with nobody
reviewing it, and every signature they issued afterwards would verify. The
endpoints also return bare PEM with no version, no expiry, and no signature over
the response, so the watcher cannot tell a real rotation from a replayed or
injected one. A person reviews the pull request instead.

To run it yourself, `node scripts/watch-trust-root.mjs --check` reports without
writing anything. Exit codes: `0` covered, `1` Sigstore unreachable, `2` Sigstore
serves material this root does not pin.

## Rotating the root

Sigstore rotates these from time to time. A rotation appends and never replaces.
Both files hold lists: `fulcio.pem` is a chain of CA certificates, and
`rekor.pub` holds one PEM block per trusted log. The verifier checks a signature
against the CA that issued its certificate and the log that witnessed its entry,
and it picks each by identity, not position. Keeping the retired material keeps
everything signed before the rotation verifying. Dropping it breaks the whole
back catalogue, with no error at the moment of the rotation.

```sh
promptsign trust fetch                              # writes the current root
cat ~/.promptsign/trust/rekor.pub  >> trust/rekor.pub
cat ~/.promptsign/trust/fulcio.pem >> trust/fulcio.pem
node scripts/sync-trust.mjs                         # push the change to the copies
cd promptsign-napi && node --test test/trust-root.test.mjs
```

Put new material first if you want it listed as current; otherwise the order
does not matter. `test/trust-root.test.mjs` asserts that the already-pinned log
is still present, so an append passes and a replacement fails until the same
commit changes the pinned id.

Treat a change to either file as a security change: give it its own commit, put
the new log id in the commit message, and bump the version.
