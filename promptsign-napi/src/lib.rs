// Node (napi-rs) binding for the PromptSign verifier. This wraps the SAME
// promptsign-core the CLI uses, so a marketplace or harness embeds the audited
// verifier in-process instead of shelling out or reimplementing it. Verify-only:
// signing needs the network and stays in the CLI.
//
// The FFI surface is deliberately tiny — every function returns the VerifyResult
// (or policy/keyless summary) as a JSON string, which the JS wrapper parses. That
// keeps the boundary auditable and the wire shape identical to `promptsign
// verify --json`.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use promptsign_core::verify::{verify_target, VerifyOptions};
use promptsign_core::verifytree::verify_tree;
use std::path::PathBuf;

#[napi(object)]
pub struct VerifyOpts {
    pub policy_path: Option<String>,
    pub no_pin_updates: Option<bool>,
}

fn to_options(opts: Option<VerifyOpts>) -> VerifyOptions {
    let opts = opts.unwrap_or(VerifyOpts {
        policy_path: None,
        no_pin_updates: None,
    });

    VerifyOptions {
        policy_path: opts.policy_path.map(PathBuf::from),
        no_pin_updates: opts.no_pin_updates.unwrap_or(false),
        skip_policy: false,
    }
}

fn err(e: String) -> Error {
    Error::from_reason(e)
}

/// Verify one target (directory or file). Returns the VerifyResult as JSON —
/// identical to `promptsign verify --json`.
#[napi]
pub fn verify(target: String, opts: Option<VerifyOpts>) -> Result<String> {
    let r = verify_target(&target, &to_options(opts)).map_err(err)?;

    serde_json::to_string(&r).map_err(|e| err(e.to_string()))
}

/// Verify a tree of roots. Returns a JSON array of VerifyResult — identical to
/// `promptsign verify-tree --json`.
#[napi]
pub fn verify_tree_json(roots: Vec<String>, opts: Option<VerifyOpts>) -> Result<String> {
    let results = verify_tree(&roots, &to_options(opts)).map_err(err)?;

    serde_json::to_string(&results).map_err(|e| err(e.to_string()))
}

/// Offline keyless verification of a bundle (spec/05). Returns
/// `{ identity, issuer, keyid }` as JSON, or throws on any verification failure.
#[napi]
pub fn verify_keyless(bundle_json: String) -> Result<String> {
    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| err(format!("invalid bundle JSON: {e}")))?;
    let kv = promptsign_core::keyless::verify_keyless(&bundle).map_err(err)?;

    serde_json::to_string(&serde_json::json!({
        "identity": kv.identity,
        "issuer": kv.issuer,
        "keyid": kv.leaf_keyid,
    }))
    .map_err(|e| err(e.to_string()))
}

/// The effective policy for a directory, as JSON (like `promptsign policy show`).
#[napi]
pub fn policy_show(dir: String) -> Result<String> {
    let (_policy, raw, _src) =
        promptsign_core::policy::load_policy(None, &PathBuf::from(dir)).map_err(err)?;

    serde_json::to_string(&raw).map_err(|e| err(e.to_string()))
}

/// The wrapped promptsign-core version, so consumers can assert the verifier build.
#[napi]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
