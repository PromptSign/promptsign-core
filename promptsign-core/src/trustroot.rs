// Multi-root trust: a registry of named roots a verifier accepts.
//
// The built-in root "sigstore-public" is the pinned pair in the trust
// directory (fulcio.pem + rekor.pub), joined by the public trusted_root.json
// when the directory has one. Every other root is a document in
// Sigstore's trusted_root.json shape under <trust dir>/roots/<name>.json. A
// root with transparency logs verifies keyless signatures; a root with
// certificate authorities only verifies certificate-mode signatures, checked
// at the current time. Roots come only from the user's trust directory.

use crate::chain::{is_self_signed, subject_of};
use crate::keyless::{parse_rekor_logs, trust_dir, RekorLog};
use crate::timestamp::TimestampAuthority;
use crate::trustbundle::installed_in;
use crate::util::{format_iso8601, hex, parse_iso8601, promptsign_home, sha256_hex};
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

/// A `validFor` window, `[start, end]` in Unix seconds (spec/07 §4): closed
/// at both ends, like Sigstore's TimeRange. A missing side is open, and a
/// missing window is always valid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub start: Option<i64>,
    pub end: Option<i64>,
}

impl Window {
    pub fn contains(&self, t: i64) -> bool {
        !matches!(self.start, Some(s) if t < s) && !matches!(self.end, Some(e) if t > e)
    }

    fn from_json(v: &Value) -> Result<Window> {
        let side = |key: &str| -> Result<Option<i64>> {
            match v.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(t) => t
                    .as_str()
                    .and_then(parse_iso8601)
                    .map(Some)
                    .ok_or_else(|| format!("validFor.{key} is not an RFC 3339 time: {t}")),
            }
        };

        if v.is_null() {
            return Ok(Window::default());
        }
        Ok(Window {
            start: side("start")?,
            end: side("end")?,
        })
    }

    fn to_json(self) -> Option<Value> {
        if self == Window::default() {
            return None;
        }

        let mut out = serde_json::Map::new();

        if let Some(s) = self.start {
            out.insert("start".into(), json!(format_iso8601(s)));
        }
        if let Some(e) = self.end {
            out.insert("end".into(), json!(format_iso8601(e)));
        }
        Some(Value::Object(out))
    }
}

#[derive(Clone)]
pub struct Root {
    pub name: String,
    /// Pinned CA certificates: intermediates and the anchor. Any of them may
    /// terminate a chain.
    pub ca_certs: Vec<Certificate>,
    /// The validity window of each entry in `ca_certs`, index for index. A
    /// certificate listed under several CA entries appears once per entry.
    pub ca_valid: Vec<Window>,
    /// Transparency logs whose entries this root accepts. Empty for a
    /// certificate-mode root.
    pub rekor_logs: Vec<RekorLog>,
    /// RFC 3161 timestamp authorities whose timestamps date signatures under
    /// this root (spec/07 §1).
    pub tsas: Vec<TimestampAuthority>,
    /// Hex SHA-256 of the anchor certificate's DER.
    pub fingerprint: String,
    /// Subject DN of the anchor certificate.
    pub subject: String,
    /// For a root from a trust bundle, that bundle's expiry (spec/07 §5.6).
    pub expires: Option<i64>,
}

impl Root {
    fn new(
        name: &str,
        ca_certs: Vec<Certificate>,
        ca_valid: Vec<Window>,
        rekor_logs: Vec<RekorLog>,
    ) -> Result<Root> {
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
            ca_valid,
            rekor_logs,
            tsas: Vec::new(),
            expires: None,
        })
    }

    /// A keyless root from the pinned PEM pair (`fulcio.pem`, `rekor.pub`).
    pub fn from_pem(name: &str, fulcio_pem: &[u8], rekor_pem: &str) -> Result<Root> {
        let ca_certs =
            Certificate::load_pem_chain(fulcio_pem).map_err(|e| format!("CA certificates: {e}"))?;
        let ca_valid = vec![Window::default(); ca_certs.len()];

        Root::new(name, ca_certs, ca_valid, parse_rekor_logs(rekor_pem)?)
    }

    /// A certificate-mode root from one or more PEM CA certificates.
    pub fn ca_only(name: &str, ca_pem: &[u8]) -> Result<Root> {
        let ca_certs =
            Certificate::load_pem_chain(ca_pem).map_err(|e| format!("CA certificate: {e}"))?;
        let ca_valid = vec![Window::default(); ca_certs.len()];

        Root::new(name, ca_certs, ca_valid, Vec::new())
    }

    /// A root from a Sigstore `trusted_root.json` document (spec/07 §1).
    /// Logs with a key other than ECDSA P-256 or Ed25519 are skipped, as is
    /// an Ed25519 log without a `baseUrl` (its id hashes the origin) and a
    /// log whose stated id is not the one its key and origin give.
    pub fn from_trusted_root(name: &str, doc: &Value) -> Result<Root> {
        let mut ca_certs = Vec::new();
        let mut ca_valid = Vec::new();

        for ca in doc["certificateAuthorities"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let window = Window::from_json(&ca["validFor"])?;

            for cert in certs_of(&ca["certChain"])? {
                ca_certs.push(cert);
                ca_valid.push(window);
            }
        }

        let mut rekor_logs = Vec::new();

        for log in doc["tlogs"].as_array().into_iter().flatten() {
            let details = log["publicKey"]["keyDetails"].as_str().unwrap_or("");
            let base_url = log["baseUrl"].as_str().filter(|u| !u.is_empty());
            let der = || -> Result<Vec<u8>> {
                BASE64_STANDARD
                    .decode(
                        log["publicKey"]["rawBytes"]
                            .as_str()
                            .ok_or("log key without rawBytes")?,
                    )
                    .map_err(|_| "invalid base64 in log key rawBytes".to_string())
            };
            let mut rekor = if details.starts_with("PKIX_ECDSA_P256") {
                RekorLog::from_spki_der(&der()?)?
            } else if details == "PKIX_ED25519" {
                match base_url {
                    Some(url) => RekorLog::ed25519(&der()?, url)?,
                    None => continue,
                }
            } else {
                continue;
            };

            if let Some(stated) = log["logId"]["keyId"].as_str() {
                if b64_to_hex(stated)? != rekor.log_id {
                    continue;
                }
            }
            rekor.valid = Window::from_json(&log["publicKey"]["validFor"])?;
            rekor.base_url = base_url.map(str::to_string);
            rekor_logs.push(rekor);
        }

        let mut tsas = Vec::new();

        for tsa in doc["timestampAuthorities"].as_array().into_iter().flatten() {
            let certs = certs_of(&tsa["certChain"])?;

            if certs.is_empty() {
                continue;
            }
            tsas.push(TimestampAuthority {
                certs,
                valid: Window::from_json(&tsa["validFor"])?,
                uri: tsa["uri"].as_str().unwrap_or_default().to_string(),
            });
        }

        let mut root = Root::new(name, ca_certs, ca_valid, rekor_logs)?;

        root.tsas = tsas;
        Ok(root)
    }

    /// The built-in root: the pinned pair joined with the public
    /// `trusted_root.json`. The document's CAs and logs come first, so its
    /// windows and base URLs apply; the pair adds what the document lacks.
    fn joined(name: &str, doc: Root, pinned: Root) -> Result<Root> {
        let mut ca_certs = doc.ca_certs;
        let mut ca_valid = doc.ca_valid;
        let mut rekor_logs = doc.rekor_logs;

        ca_certs.extend(pinned.ca_certs);
        ca_valid.extend(pinned.ca_valid);
        for log in pinned.rekor_logs {
            if !rekor_logs.iter().any(|l| l.log_id == log.log_id) {
                rekor_logs.push(log);
            }
        }

        let mut root = Root::new(name, ca_certs, ca_valid, rekor_logs)?;

        root.tsas = doc.tsas;
        Ok(root)
    }

    /// This root as a `trusted_root.json` document. Consecutive certificates
    /// with the same window share one CA entry.
    pub fn to_trusted_root(&self) -> Value {
        let tlogs: Vec<Value> = self
            .rekor_logs
            .iter()
            .map(|l| {
                let mut public_key = json!({
                    "rawBytes": BASE64_STANDARD.encode(&l.spki_der),
                    "keyDetails": l.key_details()
                });

                if let Some(w) = l.valid.to_json() {
                    public_key["validFor"] = w;
                }

                let mut log = json!({
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": public_key,
                    "logId": { "keyId": BASE64_STANDARD.encode(hex_decode(&l.log_id)) }
                });

                if let Some(url) = &l.base_url {
                    log["baseUrl"] = json!(url);
                }
                log
            })
            .collect();
        let tsas: Vec<Value> = self
            .tsas
            .iter()
            .map(|t| {
                let certificates: Vec<Value> = t
                    .certs
                    .iter()
                    .map(|c| json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap_or_default()) }))
                    .collect();
                let anchor = t.certs.last().map(subject_of).unwrap_or_default();
                let mut out = json!({
                    "subject": { "commonName": anchor },
                    "certChain": { "certificates": certificates }
                });

                if !t.uri.is_empty() {
                    out["uri"] = json!(t.uri);
                }
                if let Some(w) = t.valid.to_json() {
                    out["validFor"] = w;
                }
                out
            })
            .collect();
        let mut groups: Vec<(Window, Vec<Value>)> = Vec::new();

        for (c, w) in self.ca_certs.iter().zip(&self.ca_valid) {
            let raw = json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap_or_default()) });

            match groups.last_mut() {
                Some((last, certs)) if last == w => certs.push(raw),
                _ => groups.push((*w, vec![raw])),
            }
        }

        let authorities: Vec<Value> = groups
            .into_iter()
            .map(|(w, certificates)| {
                let mut ca = json!({
                    "subject": { "commonName": self.subject },
                    "certChain": { "certificates": certificates }
                });

                if let Some(w) = w.to_json() {
                    ca["validFor"] = w;
                }
                ca
            })
            .collect();

        json!({
            "mediaType": TRUSTED_ROOT_MEDIA_TYPE,
            "tlogs": tlogs,
            "certificateAuthorities": authorities,
            "ctlogs": [],
            "timestampAuthorities": tsas
        })
    }

    /// Whether `cert`, a CA of this root, was valid at `t` under any of the
    /// CA entries that list it.
    pub(crate) fn ca_valid_at(&self, cert: &Certificate, t: i64) -> bool {
        let der = cert.to_der().ok();

        self.ca_certs
            .iter()
            .zip(&self.ca_valid)
            .any(|(c, w)| c.to_der().ok() == der && w.contains(t))
    }

    pub fn is_ca_only(&self) -> bool {
        self.rekor_logs.is_empty()
    }

    pub fn log_ids(&self) -> Vec<String> {
        self.rekor_logs.iter().map(|l| l.log_id.clone()).collect()
    }
}

/// The certificates of a `certChain` object, in order.
fn certs_of(chain: &Value) -> Result<Vec<Certificate>> {
    chain["certificates"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let der = BASE64_STANDARD
                .decode(
                    c["rawBytes"]
                        .as_str()
                        .ok_or("certificate without rawBytes")?,
                )
                .map_err(|_| "invalid base64 in certificate rawBytes")?;

            Certificate::from_der(&der).map_err(|e| format!("certificate parse: {e}"))
        })
        .collect()
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

pub(crate) fn roots_dir(dir: &Path) -> PathBuf {
    dir.join("roots")
}

pub(crate) fn check_name(name: &str) -> Result<()> {
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

/// Where the user's named roots live: `$PROMPTSIGN_HOME/trust/roots`. Unlike
/// the pinned public root, this never follows PROMPTSIGN_TRUST_DIR, which a
/// host (the npm package) may point at a bundled, read-only copy.
pub fn user_trust_dir() -> PathBuf {
    promptsign_home().join("trust")
}

/// Every root the user trusts (spec/07 §2): the pinned public root from the
/// trust directory, the user's named roots, then the roots of each installed
/// trust bundle.
pub fn load_registry() -> Result<Vec<Root>> {
    let pinned: Vec<Root> = load_pinned(&trust_dir())?.into_iter().collect();

    registry(&user_trust_dir(), pinned)
}

/// Every root in `dir`: the built-in pinned pair first (when present), then
/// `roots/*.json` by name, then bundle roots. A root file that does not
/// parse, or a stored bundle that does not verify, is an error, not a silent
/// skip.
pub fn load_registry_from(dir: &Path) -> Result<Vec<Root>> {
    let pinned: Vec<Root> = load_pinned(dir)?.into_iter().collect();

    registry(dir, pinned)
}

fn registry(dir: &Path, pinned: Vec<Root>) -> Result<Vec<Root>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let bundles = installed_in(dir, &pinned, now)?;
    let mut roots = pinned;

    roots.extend(load_named_in(&roots_dir(dir))?);
    for installed in bundles {
        roots.extend(installed.bundle.roots);
    }
    Ok(roots)
}

/// The built-in root from the trust directory: the pinned pair
/// (`fulcio.pem` + `rekor.pub`), the public `trusted_root.json`, or both
/// joined. The document is what carries Rekor v2 logs and timestamp
/// authorities.
pub(crate) fn load_pinned(dir: &Path) -> Result<Option<Root>> {
    let fulcio = dir.join("fulcio.pem");
    let rekor = dir.join("rekor.pub");
    let doc_path = dir.join("trusted_root.json");
    let pinned = if fulcio.exists() && rekor.exists() {
        let pem = fs::read(&fulcio).map_err(|e| format!("{}: {e}", fulcio.display()))?;
        let rekor_pem =
            fs::read_to_string(&rekor).map_err(|e| format!("{}: {e}", rekor.display()))?;

        Some(
            Root::from_pem(DEFAULT_ROOT, &pem, &rekor_pem)
                .map_err(|e| format!("{}: {e}", dir.display()))?,
        )
    } else {
        None
    };
    let doc = if doc_path.exists() {
        let v: Value = serde_json::from_slice(
            &fs::read(&doc_path).map_err(|e| format!("{}: {e}", doc_path.display()))?,
        )
        .map_err(|e| format!("{}: {e}", doc_path.display()))?;

        Some(
            Root::from_trusted_root(DEFAULT_ROOT, &v)
                .map_err(|e| format!("{}: {e}", doc_path.display()))?,
        )
    } else {
        None
    };

    match (doc, pinned) {
        (Some(d), Some(p)) => Root::joined(DEFAULT_ROOT, d, p).map(Some),
        (d, p) => Ok(d.or(p)),
    }
}

pub(crate) fn load_named_in(rdir: &Path) -> Result<Vec<Root>> {
    let mut roots = Vec::new();

    if !rdir.is_dir() {
        return Ok(roots);
    }

    let mut files: Vec<PathBuf> = fs::read_dir(rdir)
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
    Ok(roots)
}

/// Add a certificate-mode root to the user's registry.
pub fn add_user_ca_root(name: &str, ca_pem: &[u8]) -> Result<Root> {
    add_ca_root(&user_trust_dir(), name, ca_pem)
}

/// Add a `trusted_root.json` document to the user's registry.
pub fn add_user_trusted_root(name: &str, doc: &Value) -> Result<Root> {
    add_trusted_root(&user_trust_dir(), name, doc)
}

/// Remove a named root from the user's registry.
pub fn remove_user_root(name: &str) -> Result<()> {
    remove_root(&user_trust_dir(), name)
}

/// Add a certificate-mode root from PEM CA certificates. Refuses a name in
/// use and a root already trusted under another name.
pub fn add_ca_root(dir: &Path, name: &str, ca_pem: &[u8]) -> Result<Root> {
    check_name(name)?;
    store_root(dir, Root::ca_only(name, ca_pem)?)
}

/// Add a root from a Sigstore `trusted_root.json` document (a private
/// Sigstore deployment, or a CA published in that shape).
pub fn add_trusted_root(dir: &Path, name: &str, doc: &Value) -> Result<Root> {
    check_name(name)?;
    store_root(dir, Root::from_trusted_root(name, doc)?)
}

fn store_root(dir: &Path, root: Root) -> Result<Root> {
    let path = roots_dir(dir).join(format!("{}.json", root.name));

    if path.exists() {
        return Err(format!("trust root \"{}\" already exists", root.name));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_closed_at_both_ends() {
        let w = Window {
            start: Some(100),
            end: Some(200),
        };

        assert!(!w.contains(99));
        assert!(w.contains(100));
        assert!(w.contains(200));
        assert!(!w.contains(201));
        assert!(Window::default().contains(i64::MIN));
    }
}
