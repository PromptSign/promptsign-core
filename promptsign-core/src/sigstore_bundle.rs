// Verification of standard Sigstore bundles (v0.1 to v0.3) carrying a DSSE
// envelope, as OMS and other in-toto producers write them. Two signer modes:
//
// - keyless: a Fulcio-style leaf plus a transparency-log entry, checked by the
//   same code as PromptSign's own keyless bundles (spec/05-keyless.md);
// - certificate: an X.509 chain to a certificate-mode root in the registry,
//   no log, every certificate checked at the current time.
//
// This module authenticates the payload and names the signer. Mapping the
// in-toto Statement to files is the caller's job.

use crate::bundle::pae;
use crate::chain::{
    anchor_chain, check_signing_leaf, check_valid_at, spki_der_of, subject_of,
    verify_leaf_signature,
};
use crate::keyless::{verify_keyless_parts, TlogEntry};
use crate::trustroot::{b64_to_hex, load_registry, Root};
use crate::util::sha256_hex;
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use der::Decode;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_cert::Certificate;

pub const MEDIA_TYPE_PREFIX: &str = "application/vnd.dev.sigstore.bundle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerMode {
    Keyless,
    Certificate,
}

#[derive(Debug, Clone)]
pub struct VerifiedStatement {
    pub mode: SignerMode,
    /// Keyless: the certificate's SAN identity. Certificate mode: the leaf's
    /// subject DN.
    pub identity: String,
    /// Keyless: the OIDC issuer. Certificate mode: `x509:sha256:<root fp>`.
    pub issuer: String,
    /// Registry name of the root the chain ended at.
    pub root: String,
    pub root_fingerprint: String,
    pub leaf_keyid: String,
    pub payload_type: String,
    pub payload: Vec<u8>,
    /// Log integration time; keyless only.
    pub integrated_time: Option<i64>,
    /// Log index of the entry; keyless only.
    pub log_index: Option<i64>,
}

pub fn is_sigstore_bundle(v: &Value) -> bool {
    v.get("mediaType")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m.starts_with(MEDIA_TYPE_PREFIX))
}

fn b64(v: &Value, what: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(v.as_str().ok_or_else(|| format!("{what} missing"))?)
        .map_err(|_| format!("invalid base64 in {what}"))
}

/// Protobuf JSON writes int64 as a string; accept either form.
fn int64(v: &Value, what: &str) -> Result<i64> {
    match v {
        Value::String(s) => s.parse().map_err(|_| format!("{what} is not an integer")),
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| format!("{what} is not an integer")),
        _ => Err(format!("{what} missing")),
    }
}

fn parse_chain(material: &Value) -> Result<Vec<Certificate>> {
    let raw: Vec<&Value> = if let Some(c) = material.get("certificate") {
        vec![&c["rawBytes"]]
    } else if let Some(chain) = material.get("x509CertificateChain") {
        chain["certificates"]
            .as_array()
            .ok_or("x509CertificateChain without certificates")?
            .iter()
            .map(|c| &c["rawBytes"])
            .collect()
    } else if material.get("publicKey").is_some() {
        return Err("public-key bundles (no certificate) are not supported".to_string());
    } else {
        return Err("bundle has no verification material".to_string());
    };

    raw.into_iter()
        .map(|r| {
            Certificate::from_der(&b64(r, "certificate rawBytes")?)
                .map_err(|e| format!("certificate parse: {e}"))
        })
        .collect()
}

/// Verify against every root in the user's registry, at the current time.
pub fn verify_sigstore_bundle_with_registry(bundle: &Value) -> Result<VerifiedStatement> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();

    verify_sigstore_bundle(bundle, &load_registry()?, now)
}

/// Verify a Sigstore bundle against `roots`. A chain ending at a root with
/// logs is keyless and needs a log entry; a chain ending at a certificate-mode
/// root is checked at `now`. When the chain ends at several roots, the first
/// that verifies wins.
pub fn verify_sigstore_bundle(
    bundle: &Value,
    roots: &[Root],
    now: i64,
) -> Result<VerifiedStatement> {
    if !is_sigstore_bundle(bundle) {
        return Err("not a Sigstore bundle".to_string());
    }

    let env = bundle
        .get("dsseEnvelope")
        .ok_or("only DSSE Sigstore bundles are supported")?;
    let chain = parse_chain(&bundle["verificationMaterial"])?;
    let payload_type = env["payloadType"]
        .as_str()
        .ok_or("dsseEnvelope.payloadType missing")?
        .to_string();
    let payload = b64(&env["payload"], "dsseEnvelope.payload")?;
    let sig_b64 = env["signatures"][0]["sig"]
        .as_str()
        .ok_or("dsseEnvelope has no signature")?;
    let anchored = anchor_chain(&chain, roots)?;
    let mut first_error = None;

    for a in &anchored {
        let attempt = if a.root.is_ca_only() {
            verify_certificate_mode(&chain, &a.path, &payload_type, &payload, sig_b64, now)
        } else {
            verify_keyless_mode(bundle, &chain, &payload_type, &payload, sig_b64, a.root)
        };

        match attempt {
            Ok((mode, identity, issuer, integrated_time, log_index)) => {
                return Ok(VerifiedStatement {
                    mode,
                    identity,
                    issuer: if mode == SignerMode::Certificate {
                        format!("x509:sha256:{}", a.root.fingerprint)
                    } else {
                        issuer
                    },
                    root: a.root.name.clone(),
                    root_fingerprint: a.root.fingerprint.clone(),
                    leaf_keyid: sha256_hex(&spki_der_of(&chain[0])?),
                    payload_type,
                    payload,
                    integrated_time,
                    log_index,
                })
            }
            Err(e) => first_error = first_error.or(Some(e)),
        }
    }
    Err(first_error.unwrap_or_else(|| "no trust root verified this bundle".to_string()))
}

type ModeResult = Result<(SignerMode, String, String, Option<i64>, Option<i64>)>;

fn verify_certificate_mode(
    chain: &[Certificate],
    path: &[Certificate],
    payload_type: &str,
    payload: &[u8],
    sig_b64: &str,
    now: i64,
) -> ModeResult {
    let leaf = &chain[0];

    check_valid_at(path, now)?;
    check_signing_leaf(leaf)?;

    let sig = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|_| "invalid base64 in signature")?;

    verify_leaf_signature(leaf, &pae(payload_type, payload), &sig)?;
    Ok((
        SignerMode::Certificate,
        subject_of(leaf),
        String::new(),
        None,
        None,
    ))
}

fn verify_keyless_mode(
    bundle: &Value,
    chain: &[Certificate],
    payload_type: &str,
    payload: &[u8],
    sig_b64: &str,
    root: &Root,
) -> ModeResult {
    let entry = &bundle["verificationMaterial"]["tlogEntries"][0];

    if entry.is_null() {
        return Err("keyless bundle has no transparency log entry".to_string());
    }

    let tlog = TlogEntry {
        body_b64: entry["canonicalizedBody"]
            .as_str()
            .ok_or("tlog entry has no canonicalizedBody")?,
        log_id: b64_to_hex(
            entry["logId"]["keyId"]
                .as_str()
                .ok_or("tlog entry has no logId")?,
        )?,
        log_index: int64(&entry["logIndex"], "tlog logIndex")?,
        integrated_time: int64(&entry["integratedTime"], "tlog integratedTime")?,
        set_b64: entry["inclusionPromise"]["signedEntryTimestamp"]
            .as_str()
            .ok_or("tlog entry has no signed entry timestamp")?,
    };
    let parts = verify_keyless_parts(
        chain,
        payload_type,
        payload,
        sig_b64,
        &tlog,
        std::slice::from_ref(root),
    )?;

    Ok((
        SignerMode::Keyless,
        parts.identity,
        parts.issuer,
        Some(parts.integrated_time),
        Some(tlog.log_index),
    ))
}
