// The managed layer (spec/04 "Managed policy", spec/07 §2.4): a directory
// that an administrator owns and users cannot write. Verifiers evaluate its
// policy first, and the user's and the project's policies can only add to it.
// Every user on the machine trusts the roots and trust bundles in its trust
// directory.
//
// Each platform has one fixed location. A project can set environment
// variables for the hooks it runs (Claude Code's project settings, for one),
// so the location cannot come from the environment.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

pub const MANAGED_POLICY_FILE: &str = "managed-policy.json";
pub const MANAGED_REVOCATION_FILE: &str = "revocation.json";

/// The variables `lock_env` turns off. Each moves a file the verifier reads
/// from, and a project can set any of them for a hook.
pub const LOCKED_VARS: [&str; 4] = [
    "PROMPTSIGN_POLICY",
    "PROMPTSIGN_HOME",
    "PROMPTSIGN_TRUST_DIR",
    "PROMPTSIGN_REVOCATION_FILE",
];

/// The managed directory this platform defines.
pub fn platform_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\PromptSign")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/PromptSign")
    } else {
        PathBuf::from("/etc/promptsign")
    }
}

/// The managed directory: the platform's, or `$PROMPTSIGN_MANAGED_DIR` on a
/// machine that has no platform directory. The variable stands in for an
/// absent managed layer in tests and trials. It cannot hide one that exists.
pub fn managed_dir() -> PathBuf {
    let platform = platform_dir();

    if !platform.exists() {
        if let Some(p) = std::env::var_os("PROMPTSIGN_MANAGED_DIR").filter(|p| !p.is_empty()) {
            return PathBuf::from(p);
        }
    }
    platform
}

pub fn managed_policy_path() -> PathBuf {
    managed_dir().join(MANAGED_POLICY_FILE)
}

/// Managed roots and trust bundles, laid out like the user's trust directory.
pub fn managed_trust_dir() -> PathBuf {
    managed_dir().join("trust")
}

pub fn managed_revocation_path() -> PathBuf {
    managed_dir().join(MANAGED_REVOCATION_FILE)
}

/// True when the managed policy sets `lock_env`. A managed policy that does
/// not parse counts as locked: verification fails on it anyway, and the
/// verifier should not read from a location the environment chose meanwhile.
pub fn env_locked() -> bool {
    match fs::read(managed_policy_path()) {
        Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map(|v| v["lock_env"] == true)
            .unwrap_or(true),
        Err(_) => false,
    }
}

/// A non-empty environment variable, unless the managed policy locks the
/// environment.
pub fn env_override(name: &str) -> Option<OsString> {
    let value = std::env::var_os(name).filter(|v| !v.is_empty())?;

    if env_locked() {
        return None;
    }
    Some(value)
}
