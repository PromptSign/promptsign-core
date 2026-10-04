// Multi-root trust: a registry of named roots a verifier accepts.
//
// The built-in root "sigstore-public" is the pinned pair in the trust
// directory (fulcio.pem + rekor.pub). Every other root is a document in
// Sigstore's trusted_root.json shape under <trust dir>/roots/<name>.json. A
// root with transparency logs verifies keyless signatures; a root with
// certificate authorities only verifies certificate-mode signatures, checked
// at the current time. Roots come only from the user's trust directory.

use crate::chain::{is_self_signed, subject_of};
use crate::keyless::{parse_rekor_logs, trust_dir, RekorLog};
use crate::util::{hex, sha256_hex};
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use der::{Decode, Encode};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;

pub const DEFAULT_ROOT: &str = "sigstore-public";
pub const TRUSTED_ROOT_MEDIA_TYPE: &str =
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1";

#[derive(Clone)]
pub struct Root {
    pub name: String,
    /// Pinned CA certificates: intermediates and the anchor. Any of them may
    /// terminate a chain.
    pub ca_certs: Vec<Certificate>,
    /// Transparency logs whose entries this root accepts. Empty for a
    /// certificate-mode root.
    pub rekor_logs: Vec<RekorLog>,
    /// Hex SHA-256 of the anchor certificate's DER.
    pub fingerprint: String,
    /// Subject DN of the anchor certificate.
    pub subject: String,
}

impl Root {
    fn new(name: &str, ca_certs: Vec<Certificate>, rekor_logs: Vec<RekorLog>) -> Result<Root> {
        if ca_certs.is_empty() {
            return Err(format!("trust root \"{name}\": no CA certificates"));
        }

        // The anchor is the self-signed certificate when the root carries one,
        // otherwise the last certificate given.
        let anchor = ca_certs
            .iter()
            .find(|c| is_self_signed(c))
            .unwrap_or(&ca_certs[ca_certs.len() - 1]);
        let der = anchor.to_der().map_err(|e| e.to_string())?;

        Ok(Root {
            name: name.to_string(),
            fingerprint: sha256_hex(&der),
            subject: subject_of(anchor),
            ca_certs,
            rekor_logs,
        })
    }

    /// A keyless root from the pinned PEM pair (`fulcio.pem`, `rekor.pub`).
    pub fn from_pem(name: &str, fulcio_pem: &[u8], rekor_pem: &str) -> Result<Root> {
        let ca_certs =
            Certificate::load_pem_chain(fulcio_pem).map_err(|e| format!("CA certificates: {e}"))?;

        Root::new(name, ca_certs, parse_rekor_logs(rekor_pem)?)
    }

    /// A certificate-mode root from one or more PEM CA certificates.
    pub fn ca_only(name: &str, ca_pem: &[u8]) -> Result<Root> {
        let ca_certs =
            Certificate::load_pem_chain(ca_pem).map_err(|e| format!("CA certificate: {e}"))?;

        Root::new(name, ca_certs, Vec::new())
    }

    /// A root from a Sigstore `trusted_root.json` document. Logs whose key is
    /// not ECDSA P-256 (Rekor v2's Ed25519 logs) are skipped: their entries
    /// carry no signed entry timestamp this verifier can check. CA validity
    /// windows (`validFor`) are not enforced yet.
    pub fn from_trusted_root(name: &str, doc: &Value) -> Result<Root> {
        let mut ca_certs = Vec::new();

        for ca in doc["certificateAuthorities"]
            .as_array()
            .into_iter()
            .flatten()
        {
            for c in ca["certChain"]["certificates"]
                .as_array()
                .into_iter()
                .flatten()
            {
                let der = BASE64_STANDARD
                    .decode(
                        c["rawBytes"]
                            .as_str()
                            .ok_or("certificate without rawBytes")?,
                    )
                    .map_err(|_| "invalid base64 in certificate rawBytes")?;

                ca_certs.push(
                    Certificate::from_der(&der).map_err(|e| format!("certificate parse: {e}"))?,
                );
            }
        }

        let mut rekor_logs = Vec::new();

        for log in doc["tlogs"].as_array().into_iter().flatten() {
            let details = log["publicKey"]["keyDetails"].as_str().unwrap_or("");

            if !details.starts_with("PKIX_ECDSA_P256") {
                continue;
            }

            let der = BASE64_STANDARD
                .decode(
                    log["publicKey"]["rawBytes"]
                        .as_str()
                        .ok_or("log key without rawBytes")?,
                )
                .map_err(|_| "invalid base64 in log key rawBytes")?;

            rekor_logs.push(RekorLog::from_spki_der(&der)?);
        }

        Root::new(name, ca_certs, rekor_logs)
    }

    /// This root as a `trusted_root.json` document.
    pub fn to_trusted_root(&self) -> Value {
        let tlogs: Vec<Value> = self
            .rekor_logs
            .iter()
            .map(|l| {
                json!({
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": {
                        "rawBytes": BASE64_STANDARD.encode(&l.spki_der),
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                    },
                    "logId": { "keyId": BASE64_STANDARD.encode(hex_decode(&l.log_id)) }
                })
            })
            .collect();
        let certificates: Vec<Value> = self
            .ca_certs
            .iter()
            .map(|c| json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap_or_default()) }))
            .collect();

        json!({
            "mediaType": TRUSTED_ROOT_MEDIA_TYPE,
            "tlogs": tlogs,
            "certificateAuthorities": [{
                "subject": { "commonName": self.subject },
                "certChain": { "certificates": certificates }
            }],
            "ctlogs": [],
            "timestampAuthorities": []
        })
    }

    pub fn is_ca_only(&self) -> bool {
        self.rekor_logs.is_empty()
    }

    pub fn log_ids(&self) -> Vec<String> {
        self.rekor_logs.iter().map(|l| l.log_id.clone()).collect()
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Lower-case hex of base64 bytes (Sigstore bundles carry log ids as base64).
pub(crate) fn b64_to_hex(s: &str) -> Result<String> {
    BASE64_STANDARD
        .decode(s)
        .map(|b| hex(&b))
        .map_err(|_| "invalid base64".to_string())
}

fn roots_dir(dir: &Path) -> PathBuf {
    dir.join("roots")
}

fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));

    if !ok {
        return Err(format!(
            "invalid trust root name \"{name}\": use lower-case letters, digits, '-', '_' or '.'"
        ));
    }
    if name == DEFAULT_ROOT {
        return Err(format!("\"{DEFAULT_ROOT}\" is the built-in root"));
    }
    Ok(())
}

/// Every root in the user's trust directory.
pub fn load_registry() -> Result<Vec<Root>> {
    load_registry_from(&trust_dir())
}

/// Every root in `dir`: the built-in pinned pair first (when present), then
/// `roots/*.json` by name. A root file that does not parse is an error, not
/// a silent skip.
pub fn load_registry_from(dir: &Path) -> Result<Vec<Root>> {
    let mut roots = Vec::new();
    let fulcio = dir.join("fulcio.pem");
    let rekor = dir.join("rekor.pub");

    if fulcio.exists() && rekor.exists() {
        let pem = fs::read(&fulcio).map_err(|e| format!("{}: {e}", fulcio.display()))?;
        let rekor_pem =
            fs::read_to_string(&rekor).map_err(|e| format!("{}: {e}", rekor.display()))?;

        roots.push(
            Root::from_pem(DEFAULT_ROOT, &pem, &rekor_pem)
                .map_err(|e| format!("{}: {e}", dir.display()))?,
        );
    }

    let rdir = roots_dir(dir);

    if rdir.is_dir() {
        let mut files: Vec<PathBuf> = fs::read_dir(&rdir)
            .map_err(|e| format!("{}: {e}", rdir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();

        files.sort();
        for p in files {
            let name = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();

            check_name(name).map_err(|e| format!("{}: {e}", p.display()))?;

            let doc: Value =
                serde_json::from_slice(&fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?)
                    .map_err(|e| format!("{}: {e}", p.display()))?;

            roots.push(
                Root::from_trusted_root(name, &doc).map_err(|e| format!("{}: {e}", p.display()))?,
            );
        }
    }
    Ok(roots)
}

/// Add a certificate-mode root from PEM CA certificates. Refuses a name in
/// use and a root already trusted under another name.
pub fn add_ca_root(dir: &Path, name: &str, ca_pem: &[u8]) -> Result<Root> {
    check_name(name)?;

    let root = Root::ca_only(name, ca_pem)?;
    let path = roots_dir(dir).join(format!("{name}.json"));

    if path.exists() {
        return Err(format!("trust root \"{name}\" already exists"));
    }
    if let Some(same) = load_registry_from(dir)?
        .into_iter()
        .find(|r| r.fingerprint == root.fingerprint)
    {
        return Err(format!("this root is already trusted as \"{}\"", same.name));
    }

    fs::create_dir_all(roots_dir(dir)).map_err(|e| format!("{}: {e}", dir.display()))?;
    fs::write(
        &path,
        serde_json::to_string_pretty(&root.to_trusted_root()).unwrap() + "\n",
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(root)
}

pub fn remove_root(dir: &Path, name: &str) -> Result<()> {
    check_name(name)?;

    let path = roots_dir(dir).join(format!("{name}.json"));

    if !path.exists() {
        return Err(format!("no trust root named \"{name}\""));
    }
    fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))
}
