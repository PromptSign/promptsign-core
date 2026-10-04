// Offline verification of keyless (Sigstore-style) bundles per spec/05-keyless.md:
// stapled certificate chain to a pinned trust root, SAN identity + Fulcio issuer
// extraction, Rekor signed-entry-timestamp check. No network anywhere.

use crate::bundle::pae;
use crate::chain::{anchor_chain, spki_der_of, verify_leaf_signature, Anchored};
use crate::trustroot::{load_registry, Root};
use crate::util::{promptsign_home, sha256_hex};
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use der::asn1::Utf8StringRef;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

const OID_SAN: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_FULCIO_ISSUER_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
const OID_FULCIO_ISSUER_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.1");

/// One transparency log: its public key, and the log id (hex SHA-256 of the
/// key's SPKI DER) that every entry it witnesses carries.
#[derive(Clone)]
pub struct RekorLog {
    pub key: p256::ecdsa::VerifyingKey,
    pub log_id: String,
    pub spki_der: Vec<u8>,
}

impl RekorLog {
    pub fn from_spki_der(der: &[u8]) -> Result<RekorLog> {
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|e| format!("invalid P-256 public key: {e}"))?;

        Ok(RekorLog {
            key,
            log_id: sha256_hex(der),
            spki_der: der.to_vec(),
        })
    }
}

pub struct TrustRoot {
    pub ca_certs: Vec<Certificate>,
    /// Every log whose entries are accepted, in file order — first is current.
    ///
    /// Plural for the same reason `ca_certs` is: rotation must not invalidate
    /// what was already witnessed. An entry names the log that recorded it, so
    /// verification selects by that name; a signature made before a key rotation
    /// keeps verifying against the retired key. A single-key `rekor.pub` is just
    /// the one-element case, so nothing has to change until Sigstore rotates.
    pub rekor_logs: Vec<RekorLog>,
}

pub fn trust_dir() -> PathBuf {
    match std::env::var_os("PROMPTSIGN_TRUST_DIR") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => promptsign_home().join("trust"),
    }
}

pub fn load_trust_root() -> Result<TrustRoot> {
    let dir = trust_dir();
    let fulcio = dir.join("fulcio.pem");
    let rekor = dir.join("rekor.pub");

    if !fulcio.exists() || !rekor.exists() {
        return Err(format!(
            "no Sigstore trust root in {} — run \"promptsign trust fetch\" first",
            dir.display()
        ));
    }

    let pem = fs::read(&fulcio).map_err(|e| format!("{}: {e}", fulcio.display()))?;
    let ca_certs =
        Certificate::load_pem_chain(&pem).map_err(|e| format!("{}: {e}", fulcio.display()))?;

    if ca_certs.is_empty() {
        return Err(format!("{}: no certificates", fulcio.display()));
    }

    let rekor_pem = fs::read_to_string(&rekor).map_err(|e| format!("{}: {e}", rekor.display()))?;
    let rekor_logs =
        parse_rekor_logs(&rekor_pem).map_err(|e| format!("{}: {e}", rekor.display()))?;

    Ok(TrustRoot {
        ca_certs,
        rekor_logs,
    })
}

/// Every trusted log in a `rekor.pub`, one PEM PUBLIC KEY block each. The file
/// is append-only by convention: adding a rotated key must not remove the key
/// that witnessed everything signed before it.
pub(crate) fn parse_rekor_logs(pem: &str) -> Result<Vec<RekorLog>> {
    let ders = pem_bodies(pem, "PUBLIC KEY")?;

    if ders.is_empty() {
        return Err("no PUBLIC KEY block".to_string());
    }

    ders.iter()
        .map(|der| RekorLog::from_spki_der(der))
        .collect()
}

fn pem_bodies(pem: &str, label: &str) -> Result<Vec<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;

    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let stop = after.find(&end).ok_or(format!("missing {end}"))?;
        let b64: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        out.push(
            BASE64_STANDARD
                .decode(&b64)
                .map_err(|e| format!("invalid PEM base64: {e}"))?,
        );
        rest = &after[stop + end.len()..];
    }
    Ok(out)
}

/// Extract (identity, issuer) from a Fulcio-style leaf certificate.
pub fn leaf_identity(leaf: &Certificate) -> Result<(String, String)> {
    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or("leaf certificate has no extensions")?;
    let mut identity: Option<String> = None;
    let mut issuer: Option<String> = None;

    for ext in exts {
        if ext.extn_id == OID_SAN {
            let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                .map_err(|e| format!("SAN parse: {e}"))?;

            for name in san.0 {
                match name {
                    GeneralName::Rfc822Name(s) => identity = Some(s.to_string()),
                    GeneralName::UniformResourceIdentifier(s) => identity = Some(s.to_string()),
                    _ => {}
                }
                if identity.is_some() {
                    break;
                }
            }
        } else if ext.extn_id == OID_FULCIO_ISSUER_V2 {
            let s = Utf8StringRef::from_der(ext.extn_value.as_bytes())
                .map_err(|e| format!("issuer ext parse: {e}"))?;

            issuer = Some(s.as_str().to_string());
        } else if ext.extn_id == OID_FULCIO_ISSUER_V1 && issuer.is_none() {
            issuer = Some(String::from_utf8_lossy(ext.extn_value.as_bytes()).to_string());
        }
    }
    Ok((
        identity.ok_or("leaf certificate has no SAN identity")?,
        issuer.ok_or("leaf certificate has no Fulcio issuer extension")?,
    ))
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;

    for p in path {
        cur = cur.get(p)?;
    }
    cur.as_str()
}

pub struct KeylessVerification {
    pub identity: String,
    pub issuer: String,
    pub leaf_keyid: String,
    pub payload: Vec<u8>,
    /// Name of the registry root the certificate chained to.
    pub root: String,
}

/// One transparency-log entry, in whatever carriage the bundle used.
pub(crate) struct TlogEntry<'a> {
    /// Base64 canonicalized entry body.
    pub body_b64: &'a str,
    /// Hex SHA-256 of the witnessing log's key.
    pub log_id: String,
    pub log_index: i64,
    pub integrated_time: i64,
    pub set_b64: &'a str,
}

/// What a keyless signature proves once the chain, the envelope signature and
/// the log entry all check out.
pub(crate) struct KeylessParts {
    pub identity: String,
    pub issuer: String,
    pub leaf_keyid: String,
    pub root: String,
    pub integrated_time: i64,
}

/// The registry's keyless roots (those with logs). Errors when there are none,
/// since keyless verification is then impossible.
pub(crate) fn keyless_roots() -> Result<Vec<Root>> {
    let roots: Vec<Root> = load_registry()?
        .into_iter()
        .filter(|r| !r.is_ca_only())
        .collect();

    if roots.is_empty() {
        return Err(format!(
            "no Sigstore trust root in {}: run \"promptsign trust fetch\" first",
            trust_dir().display()
        ));
    }
    Ok(roots)
}

/// Offline keyless verification per spec/05-keyless.md §4, independent of
/// how the bundle carries its parts: the chain must end at a keyless root,
/// the leaf must have signed the DSSE envelope, and one of that root's logs
/// must have witnessed the entry while the leaf was valid.
pub(crate) fn verify_keyless_parts(
    chain: &[Certificate],
    payload_type: &str,
    payload: &[u8],
    sig_b64: &str,
    tlog: &TlogEntry,
    roots: &[Root],
) -> Result<KeylessParts> {
    let keyless: Vec<Root> = roots.iter().filter(|r| !r.is_ca_only()).cloned().collect();
    let anchored = anchor_chain(chain, &keyless)?;
    let leaf = &chain[0];

    // envelope signature (step 1)
    let sig = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|_| "invalid base64 in signature")?;

    verify_leaf_signature(leaf, &pae(payload_type, payload), &sig)?;

    // SET over the canonical entry (step 3). The entry names the log that
    // witnessed it; pick that log's key from a root the chain ends at. After a
    // key rotation both keys are pinned, so old entries keep verifying.
    let mut found: Option<(&Anchored, &RekorLog)> = None;

    for a in &anchored {
        if let Some(log) = a.root.rekor_logs.iter().find(|l| l.log_id == tlog.log_id) {
            found = Some((a, log));
            break;
        }
    }

    let (anchor, log) = found.ok_or_else(|| {
        let trusted: Vec<&str> = anchored
            .iter()
            .flat_map(|a| a.root.rekor_logs.iter())
            .map(|l| &l.log_id[..16.min(l.log_id.len())])
            .collect();

        format!(
            "transparency logId {} does not match any trusted log (trusted: {}…)",
            tlog.log_id,
            trusted.join("…, ")
        )
    })?;
    let canonical = format!(
        "{{\"body\":{},\"integratedTime\":{},\"logID\":{},\"logIndex\":{}}}",
        serde_json::to_string(tlog.body_b64).unwrap(),
        tlog.integrated_time,
        serde_json::to_string(&tlog.log_id).unwrap(),
        tlog.log_index
    );
    let set = BASE64_STANDARD
        .decode(tlog.set_b64)
        .map_err(|_| "invalid base64 in signedEntryTimestamp")?;
    let set_sig = p256::ecdsa::Signature::from_der(&set).map_err(|_| "malformed SET")?;

    log.key
        .verify_prehash(&Sha256::digest(canonical.as_bytes()), &set_sig)
        .map_err(|_| "signed entry timestamp verification failed".to_string())?;

    // entry binding (step 4)
    let body_raw = BASE64_STANDARD
        .decode(tlog.body_b64)
        .map_err(|_| "invalid base64 in body")?;
    let body: Value = serde_json::from_slice(&body_raw).map_err(|e| format!("entry body: {e}"))?;

    if str_at(&body, &["kind"]) != Some("dsse") {
        return Err(format!(
            "unexpected transparency entry kind: {}",
            show_str(&body, "kind")
        ));
    }

    let payload_hash = str_at(&body, &["spec", "payloadHash", "value"]).unwrap_or("");

    if payload_hash != sha256_hex(payload) {
        return Err("transparency entry payloadHash does not match envelope payload".to_string());
    }

    let entry_sigs = body
        .get("spec")
        .and_then(|s| s.get("signatures"))
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    if !entry_sigs
        .iter()
        .any(|s| str_at(s, &["signature"]) == Some(sig_b64))
    {
        return Err("transparency entry does not contain the envelope signature".to_string());
    }

    // cert validity at integration time (step 5)
    let validity = &leaf.tbs_certificate.validity;
    let nb = validity.not_before.to_unix_duration().as_secs() as i64;
    let na = validity.not_after.to_unix_duration().as_secs() as i64;

    if tlog.integrated_time < nb || tlog.integrated_time > na {
        return Err(format!(
            "log integration time {} outside certificate validity [{nb}, {na}]",
            tlog.integrated_time
        ));
    }

    // identity extraction (step 6)
    let (identity, issuer) = leaf_identity(leaf)?;

    Ok(KeylessParts {
        identity,
        issuer,
        leaf_keyid: sha256_hex(&spki_der_of(leaf)?),
        root: anchor.root.name.clone(),
        integrated_time: tlog.integrated_time,
    })
}

/// Full offline keyless verification of a PromptSign bundle per
/// spec/05-keyless.md §4 (steps 1–6), against every keyless root in the
/// registry. Returns the authenticated payload; manifest parsing, integrity
/// and policy are the caller's next steps.
pub fn verify_keyless(bundle: &Value) -> Result<KeylessVerification> {
    let roots = keyless_roots()?;
    let chain_b64 = bundle
        .get("signer")
        .and_then(|s| s.get("certChain"))
        .and_then(|c| c.as_array())
        .ok_or("keyless bundle missing signer.certChain")?;
    let mut chain: Vec<Certificate> = Vec::with_capacity(chain_b64.len());

    for c in chain_b64 {
        let der = BASE64_STANDARD
            .decode(c.as_str().ok_or("certChain entry is not a string")?)
            .map_err(|_| "invalid base64 in certChain")?;

        chain.push(Certificate::from_der(&der).map_err(|e| format!("certificate parse: {e}"))?);
    }

    let payload_type =
        str_at(bundle, &["envelope", "payloadType"]).ok_or("missing envelope.payloadType")?;
    let payload = BASE64_STANDARD
        .decode(str_at(bundle, &["envelope", "payload"]).unwrap_or(""))
        .map_err(|_| "invalid base64 in payload")?;
    let sig_b64 = bundle
        .get("envelope")
        .and_then(|e| e.get("signatures"))
        .and_then(|s| s.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.get("sig"))
        .and_then(|s| s.as_str())
        .ok_or("missing envelope signature")?;
    let t = bundle
        .get("transparency")
        .ok_or("keyless bundle missing transparency block")?;
    let tlog = TlogEntry {
        body_b64: str_at(t, &["body"]).ok_or("transparency.body missing")?,
        log_id: str_at(t, &["logId"])
            .ok_or("transparency.logId missing")?
            .to_string(),
        log_index: t
            .get("logIndex")
            .and_then(|v| v.as_i64())
            .ok_or("transparency.logIndex missing")?,
        integrated_time: t
            .get("integratedTime")
            .and_then(|v| v.as_i64())
            .ok_or("transparency.integratedTime missing")?,
        set_b64: str_at(t, &["signedEntryTimestamp"])
            .ok_or("transparency.signedEntryTimestamp missing")?,
    };
    let parts = verify_keyless_parts(&chain, payload_type, &payload, sig_b64, &tlog, &roots)?;

    // display-hint check (step 6)
    if let Some(hint) = str_at(bundle, &["signer", "identity"]) {
        if hint != parts.identity {
            return Err(format!(
                "signer.identity \"{hint}\" does not match certificate identity \"{}\"",
                parts.identity
            ));
        }
    }
    if let Some(hint) = str_at(bundle, &["signer", "issuer"]) {
        if hint != parts.issuer {
            return Err(format!(
                "signer.issuer \"{hint}\" does not match certificate issuer \"{}\"",
                parts.issuer
            ));
        }
    }

    Ok(KeylessVerification {
        identity: parts.identity,
        issuer: parts.issuer,
        leaf_keyid: parts.leaf_keyid,
        payload,
        root: parts.root,
    })
}

/// Parse a PEM certificate chain into leaf-first base64 DER (bundle carriage form).
pub fn pem_chain_to_b64_der(pem: &[u8]) -> Result<Vec<String>> {
    let certs = Certificate::load_pem_chain(pem).map_err(|e| format!("certificate chain: {e}"))?;

    if certs.is_empty() {
        return Err("empty certificate chain".to_string());
    }
    certs
        .iter()
        .map(|c| {
            c.to_der()
                .map(|d| BASE64_STANDARD.encode(d))
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// (identity, issuer, leaf keyid) from a base64-DER chain, leaf first.
pub fn chain_leaf_info(chain_b64: &[String]) -> Result<(String, String, String)> {
    let der = BASE64_STANDARD
        .decode(chain_b64.first().ok_or("empty certificate chain")?)
        .map_err(|_| "invalid base64 in certChain")?;
    let leaf = Certificate::from_der(&der).map_err(|e| format!("certificate parse: {e}"))?;
    let (identity, issuer) = leaf_identity(&leaf)?;

    Ok((identity, issuer, sha256_hex(&spki_der_of(&leaf)?)))
}

/// Every trusted log's id (hex SHA-256 of its public key SPKI DER), for display.
/// First is the current log; any others are retired keys still being honoured.
pub fn trusted_log_ids() -> Result<Vec<String>> {
    Ok(load_trust_root()?
        .rekor_logs
        .into_iter()
        .map(|l| l.log_id)
        .collect())
}

/// The current log's id. Callers that show every pinned log want
/// [`trusted_log_ids`].
pub fn trusted_log_id() -> Result<String> {
    trusted_log_ids()?
        .into_iter()
        .next()
        .ok_or_else(|| "no trusted Rekor log".to_string())
}

fn show_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "undefined".to_string(),
    }
}
