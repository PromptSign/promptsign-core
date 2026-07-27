// promptsign-core — wire-compatible Rust port of the Phase 1 Node reference
// implementation (cli/src/*.mjs). Same JSON formats (manifest, DSSE bundle,
// policy, pins), same canonicalization, same digests: a bundle signed by one
// implementation verifies in the other.
//
// Errors are plain strings: every failure ultimately surfaces as a one-line
// CLI/hook message, matching the Node implementation's Error.message model.

pub mod bundle;
pub mod canonicalize;
pub mod keyless;
pub mod keys;
pub mod manifest;
pub mod policy;
pub mod revocation;
pub mod util;
pub mod verify;
pub mod verifytree;

pub type Error = String;
pub type Result<T> = std::result::Result<T, Error>;
