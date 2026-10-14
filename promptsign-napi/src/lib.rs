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
/// `{ identity, issuer, keyid, root }` as JSON, or throws on any verification
/// failure.
#[napi]
pub fn verify_keyless(bundle_json: String) -> Result<String> {
    let bundle: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| err(format!("invalid bundle JSON: {e}")))?;
    let kv = promptsign_core::keyless::verify_keyless(&bundle).map_err(err)?;

    serde_json::to_string(&serde_json::json!({
        "identity": kv.identity,
        "issuer": kv.issuer,
        "keyid": kv.leaf_keyid,
        "root": kv.root,
    }))
    .map_err(|e| err(e.to_string()))
}

/// The user's policy as JSON (like `promptsign policy show`). `dir` is the
/// project directory; its own `.promptsign/policy.json` can only tighten the
/// user's policy, so it is checked for validity here but not returned.
#[napi]
pub fn policy_show(dir: String) -> Result<String> {
    let (_policy, raw, _src) = promptsign_core::policy::load_policy(None).map_err(err)?;

    promptsign_core::policy::load_project_policy(&PathBuf::from(dir)).map_err(err)?;
    serde_json::to_string(&raw).map_err(|e| err(e.to_string()))
}

/// Every policy layer in evaluation order: the machine's managed policy, the
/// user's, and the project's in `dir`. JSON array of
/// `{ layer, source, policy }`, `layer` being "managed", "user" or
/// "project". Without a managed policy the array holds a user layer, the
/// built-in default when the user has no policy file.
#[napi]
pub fn policy_layers(dir: String) -> Result<String> {
    let layers = promptsign_core::policy::policy_layers(None, &PathBuf::from(dir)).map_err(err)?;

    serde_json::to_string(&layers).map_err(|e| err(e.to_string()))
}

/// True when hooks should fail closed: PROMPTSIGN_STRICT=1, or `strict: true`
/// in the managed or the user policy (spec/04).
#[napi]
pub fn strict_mode() -> bool {
    promptsign_core::policy::strict_mode()
}

/// Every trust root the verifier accepts: the built-in root, the managed
/// roots and bundles, then the user's named roots (`promptsign trust add`)
/// and installed trust bundles, bundle roots named `<bundle>/<root>`. JSON
/// array of `{ name, kind, fingerprint, subject, managed, expires? }`, kind
/// "keyless" or "certificate"; `managed` is true for a root from the managed
/// trust directory; `expires` is a bundle root's bundle expiry (RFC 3339).
#[napi]
pub fn trust_roots() -> Result<String> {
    let roots = promptsign_core::trustroot::load_registry().map_err(err)?;
    let out: Vec<serde_json::Value> = roots
        .iter()
        .map(|r| {
            let mut root = serde_json::json!({
                "name": r.name,
                "kind": if r.is_ca_only() { "certificate" } else { "keyless" },
                "fingerprint": r.fingerprint,
                "subject": r.subject,
                "managed": r.managed,
            });

            if let Some(t) = r.expires {
                root["expires"] = promptsign_core::util::format_iso8601(t).into();
            }
            root
        })
        .collect();

    serde_json::to_string(&out).map_err(|e| err(e.to_string()))
}

/// The managed layer's part in choosing the built-in root, for the JS
/// wrapper's report of the root in effect: `{ builtinDir, envLocked }`.
/// `builtinDir` is the managed trust directory when it holds the built-in
/// root, else null. `envLocked` is true when the managed policy sets
/// `lock_env`, which makes the core ignore PROMPTSIGN_TRUST_DIR and
/// PROMPTSIGN_HOME.
#[napi]
pub fn managed_trust() -> Result<String> {
    let builtin = promptsign_core::trustroot::builtin_root_dir();
    let managed = promptsign_core::managed::managed_trust_dir();

    serde_json::to_string(&serde_json::json!({
        "builtinDir": (builtin == managed).then(|| managed.display().to_string()),
        "envLocked": promptsign_core::managed::env_locked(),
    }))
    .map_err(|e| err(e.to_string()))
}

/// The wrapped promptsign-core version, so consumers can assert the verifier build.
#[napi]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
