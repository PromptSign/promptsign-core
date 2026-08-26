// Local Ed25519 key management (v1 parity). Keyless OIDC-bound short-lived
// certificates replace long-lived local keys later in Phase 2; the bundle
// format already carries the signer block needed for that transition.

use crate::util::{promptsign_home, sha256_hex, short16, write_private};
use crate::Result;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};

pub fn default_key_path() -> PathBuf {
    promptsign_home().join("key.pem")
}

pub struct KeygenResult {
    pub key_path: PathBuf,
    pub pub_path: PathBuf,
    pub keyid: String,
}

pub fn keygen(dir: Option<&Path>, force: bool, identity: Option<&str>) -> Result<KeygenResult> {
    let dir = dir.map(Path::to_path_buf).unwrap_or_else(promptsign_home);
    let key_path = dir.join("key.pem");
    let pub_path = dir.join("key.pub.pem");

    if key_path.exists() && !force {
        return Err(format!(
            "key already exists at {} (use --force to overwrite)",
            key_path.display()
        ));
    }

    let mut secret = [0u8; 32];

    getrandom::getrandom(&mut secret).map_err(|e| format!("rng failure: {e}"))?;

    let key = SigningKey::from_bytes(&secret);

    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("key encoding failed: {e}"))?;

    write_private(&key_path, pem.as_bytes()).map_err(|e| format!("{}: {e}", key_path.display()))?;

    let pub_pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("public key encoding failed: {e}"))?;

    fs::write(&pub_path, pub_pem).map_err(|e| format!("{}: {e}", pub_path.display()))?;

    let config = serde_json::json!({ "identity": identity });
    let config_path = dir.join("config.json");

    fs::write(
        &config_path,
        serde_json::to_string_pretty(&config).unwrap() + "\n",
    )
    .map_err(|e| format!("{}: {e}", config_path.display()))?;
    Ok(KeygenResult {
        key_path,
        pub_path,
        keyid: fingerprint(&key.verifying_key())?,
    })
}

pub fn load_private_key(key_path: &Path) -> Result<SigningKey> {
    if !key_path.exists() {
        return Err(format!(
            "no signing key at {} — run \"promptsign keygen\" first",
            key_path.display()
        ));
    }

    let pem = fs::read_to_string(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;

    SigningKey::from_pkcs8_pem(&pem).map_err(|e| format!("{}: {e}", key_path.display()))
}

pub fn fingerprint(public_key: &VerifyingKey) -> Result<String> {
    let der = public_key
        .to_public_key_der()
        .map_err(|e| format!("public key encoding failed: {e}"))?;

    Ok(sha256_hex(der.as_bytes()))
}

pub fn default_identity(public_key: &VerifyingKey) -> Result<String> {
    if let Ok(id) = std::env::var("PROMPTSIGN_IDENTITY") {
        if !id.is_empty() {
            return Ok(id);
        }
    }

    let cfg_path = promptsign_home().join("config.json");

    if cfg_path.exists() {
        if let Ok(text) = fs::read_to_string(&cfg_path) {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(id) = cfg.get("identity").and_then(|v| v.as_str()) {
                    return Ok(id.to_string());
                }
            }
        }
    }
    Ok(format!("key:{}", short16(&fingerprint(public_key)?)))
}
