# Sigstore trust root fixture

`trusted_root.json` is the public-good Sigstore trusted root as published in
the Sigstore TUF repository (`tuf-repo-cdn.sigstore.dev`, targets metadata
version 14, SHA-256 `6494e21e...0b66`), fetched 2026-10-04. Tests parse it as a
registry root to check that PromptSign reads Sigstore's own `trusted_root.json`
shape.
