// Offline verification of keyless (Sigstore-style) bundles per spec/05-keyless.md:
// stapled certificate chain to a pinned trust root, SAN identity + Fulcio issuer
// extraction, Rekor signed-entry-timestamp check. No network anywhere.

use crate::bundle::pae;
use crate::util::{promptsign_home, sha256_hex};
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use der::asn1::Utf8StringRef;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey as _;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};
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
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

pub struct TrustRoot {
    pub ca_certs: Vec<Certificate>,
    pub rekor_key: p256::ecdsa::VerifyingKey,
    pub rekor_log_id: String,
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
    let (rekor_key, spki_der) =
        parse_p256_spki_pem(&rekor_pem).map_err(|e| format!("{}: {e}", rekor.display()))?;

    Ok(TrustRoot {
        ca_certs,
        rekor_key,
        rekor_log_id: sha256_hex(&spki_der),
    })
}

fn parse_p256_spki_pem(pem: &str) -> Result<(p256::ecdsa::VerifyingKey, Vec<u8>)> {
    let der = pem_body(pem, "PUBLIC KEY")?;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(&der)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;

    Ok((key, der))
}

fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or(format!("missing {begin}"))? + begin.len();
    let stop = pem.find(&end).ok_or(format!("missing {end}"))?;
    let b64: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    BASE64_STANDARD
        .decode(&b64)
        .map_err(|e| format!("invalid PEM base64: {e}"))
}

fn spki_der_of(cert: &Certificate) -> Result<Vec<u8>> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("SPKI encode: {e}"))
}

/// Verify that `child`'s signature was produced by the holder of `parent`'s key.
fn verify_signed_by(child: &Certificate, parent: &Certificate) -> Result<()> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("TBS encode: {e}"))?;
    let sig = child
        .signature
        .as_bytes()
        .ok_or("certificate signature has unused bits")?;
    let parent_spki = &parent.tbs_certificate.subject_public_key_info;
    let parent_spki_der = spki_der_of(parent)?;
    let sig_alg = child.signature_algorithm.oid;

    if sig_alg == OID_ED25519 {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&parent_spki_der)
            .map_err(|e| format!("parent key: {e}"))?;
        let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| "malformed ed25519 sig")?;

        use ed25519_dalek::Verifier;
        return vk
            .verify(&tbs, &s)
            .map_err(|_| "certificate signature invalid".to_string());
    }
    if sig_alg != OID_ECDSA_SHA256 && sig_alg != OID_ECDSA_SHA384 {
        return Err(format!(
            "unsupported certificate signature algorithm: {sig_alg}"
        ));
    }
    if parent_spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err("parent key is not an EC key".to_string());
    }

    let curve: ObjectIdentifier = parent_spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or("parent EC key has no curve parameter")?
        .decode_as()
        .map_err(|e| format!("parent curve: {e}"))?;
    let digest: Vec<u8> = if sig_alg == OID_ECDSA_SHA256 {
        Sha256::digest(&tbs).to_vec()
    } else {
        Sha384::digest(&tbs).to_vec()
    };

    if curve == OID_P256 {
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&parent_spki_der)
            .map_err(|e| format!("parent key: {e}"))?;
        let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| "malformed ECDSA sig")?;

        vk.verify_prehash(&digest, &s)
            .map_err(|_| "certificate signature invalid".to_string())
    } else if curve == OID_P384 {
        let vk = p384::ecdsa::VerifyingKey::from_public_key_der(&parent_spki_der)
            .map_err(|e| format!("parent key: {e}"))?;
        let s = p384::ecdsa::Signature::from_der(sig).map_err(|_| "malformed ECDSA sig")?;

        vk.verify_prehash(&digest, &s)
            .map_err(|_| "certificate signature invalid".to_string())
    } else {
        Err(format!("unsupported parent curve: {curve}"))
    }
}

/// Verify the leaf-first chain up to (and including) a trust-store CA.
fn verify_chain(chain: &[Certificate], trust: &TrustRoot) -> Result<()> {
    if chain.is_empty() {
        return Err("empty certificate chain".to_string());
    }
    for i in 0..chain.len() - 1 {
        verify_signed_by(&chain[i], &chain[i + 1]).map_err(|e| format!("chain link {i}: {e}"))?;
    }

    let last = &chain[chain.len() - 1];
    let last_der = last.to_der().map_err(|e| e.to_string())?;

    for ca in &trust.ca_certs {
        if ca.to_der().ok().as_deref() == Some(&last_der) {
            return Ok(()); // chain terminates at a pinned CA
        }
        if verify_signed_by(last, ca).is_ok() {
            return Ok(());
        }
    }
    Err("certificate chain does not terminate at a trusted root".to_string())
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

/// Verify a DSSE signature with the leaf certificate's key (Ed25519 or P-256).
fn verify_envelope_sig(leaf: &Certificate, message: &[u8], sig: &[u8]) -> Result<()> {
    let spki = &leaf.tbs_certificate.subject_public_key_info;
    let spki_der = spki_der_of(leaf)?;

    if spki.algorithm.oid == OID_ED25519 {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::Verifier;

        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("leaf key: {e}"))?;
        let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| "malformed signature")?;

        vk.verify(message, &s)
            .map_err(|_| "signature verification failed".to_string())
    } else if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("leaf key: {e}"))?;
        let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| "malformed signature")?;

        vk.verify_prehash(&Sha256::digest(message), &s)
            .map_err(|_| "signature verification failed".to_string())
    } else {
        Err(format!(
            "unsupported leaf key algorithm: {}",
            spki.algorithm.oid
        ))
    }
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
}

/// Full offline keyless verification per spec/05-keyless.md §4 (steps 1–6).
/// Returns the authenticated payload; manifest parsing/integrity/policy are
/// the caller's next steps.
pub fn verify_keyless(bundle: &Value) -> Result<KeylessVerification> {
    let trust = load_trust_root()?;

    // certificate chain
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
    verify_chain(&chain, &trust)?;

    let leaf = &chain[0];

    // envelope signature (step 1)
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
    let sig = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|_| "invalid base64 in signature")?;

    verify_envelope_sig(leaf, &pae(payload_type, &payload), &sig)?;

    // SET over the canonical entry (step 3)
    let t = bundle
        .get("transparency")
        .ok_or("keyless bundle missing transparency block")?;
    let body_b64 = str_at(t, &["body"]).ok_or("transparency.body missing")?;
    let log_id = str_at(t, &["logId"]).ok_or("transparency.logId missing")?;
    let log_index = t
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .ok_or("transparency.logIndex missing")?;
    let integrated_time = t
        .get("integratedTime")
        .and_then(|v| v.as_i64())
        .ok_or("transparency.integratedTime missing")?;
    let set_b64 =
        str_at(t, &["signedEntryTimestamp"]).ok_or("transparency.signedEntryTimestamp missing")?;

    if log_id != trust.rekor_log_id {
        return Err(format!(
            "transparency logId {log_id} does not match trusted log"
        ));
    }

    let canonical = format!(
        "{{\"body\":{},\"integratedTime\":{integrated_time},\"logID\":{},\"logIndex\":{log_index}}}",
        serde_json::to_string(body_b64).unwrap(),
        serde_json::to_string(log_id).unwrap()
    );
    let set = BASE64_STANDARD
        .decode(set_b64)
        .map_err(|_| "invalid base64 in signedEntryTimestamp")?;
    let set_sig = p256::ecdsa::Signature::from_der(&set).map_err(|_| "malformed SET")?;

    trust
        .rekor_key
        .verify_prehash(&Sha256::digest(canonical.as_bytes()), &set_sig)
        .map_err(|_| "signed entry timestamp verification failed".to_string())?;

    // entry binding (step 4)
    let body_raw = BASE64_STANDARD
        .decode(body_b64)
        .map_err(|_| "invalid base64 in body")?;
    let body: Value = serde_json::from_slice(&body_raw).map_err(|e| format!("entry body: {e}"))?;

    if str_at(&body, &["kind"]) != Some("dsse") {
        return Err(format!(
            "unexpected transparency entry kind: {}",
            show_str(&body, "kind")
        ));
    }

    let payload_hash = str_at(&body, &["spec", "payloadHash", "value"]).unwrap_or("");

    if payload_hash != sha256_hex(&payload) {
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

    if integrated_time < nb || integrated_time > na {
        return Err(format!(
            "log integration time {integrated_time} outside certificate validity [{nb}, {na}]"
        ));
    }

    // identity extraction + display-hint check (step 6)
    let (identity, issuer) = leaf_identity(leaf)?;

    if let Some(hint) = str_at(bundle, &["signer", "identity"]) {
        if hint != identity {
            return Err(format!(
                "signer.identity \"{hint}\" does not match certificate identity \"{identity}\""
            ));
        }
    }
    if let Some(hint) = str_at(bundle, &["signer", "issuer"]) {
        if hint != issuer {
            return Err(format!(
                "signer.issuer \"{hint}\" does not match certificate issuer \"{issuer}\""
            ));
        }
    }

    Ok(KeylessVerification {
        identity,
        issuer,
        leaf_keyid: sha256_hex(&spki_der_of(leaf)?),
        payload,
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

/// The trusted log's id (hex SHA-256 of its public key SPKI DER), for display.
pub fn trusted_log_id() -> Result<String> {
    Ok(load_trust_root()?.rekor_log_id)
}

fn show_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "undefined".to_string(),
    }
}
