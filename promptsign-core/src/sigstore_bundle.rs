// Verification of standard Sigstore bundles (v0.1 to v0.3) carrying a DSSE
// envelope, as OMS and other in-toto producers write them. Two signer modes:
//
// - keyless: a Fulcio-style leaf plus a transparency-log entry, checked by the
//   same code as PromptSign's own keyless bundles (spec/05-keyless.md);
// - certificate: an X.509 chain to a certificate-mode root in the registry,
//   no log, every certificate checked when an RFC 3161 timestamp from the
//   root's timestamp authorities says the signature was made, else now.
//
// This module authenticates the payload and names the signer. Mapping the
// in-toto Statement to files is the caller's job.

use crate::chain::{
    anchor_chain, check_signing_leaf, check_valid_at, spki_der_of, subject_of, Anchored,
};
use crate::keyless::{
    b64_list, verified_times, verify_keyless_parts, EnvelopeSig, LogProof, TlogEntry,
};
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
    /// When the signature was made: the log's integratedTime, else the
    /// earliest verified RFC 3161 timestamp. Absent for a certificate-mode
    /// signature with no timestamp.
    pub integrated_time: Option<i64>,
    /// Log index of the entry; keyless only.
    pub log_index: Option<i64>,
}

pub fn is_sigstore_bundle(v: &Value) -> bool {
    v.get("mediaType")
        .and_then(|m| m.as_str())
        .is_some_and(|m| m.starts_with(MEDIA_TYPE_PREFIX))
}

/// Protobuf JSON bytes. Go's decoder skips line breaks, so bundles from Go
/// tools may wrap long values; so does this.
fn b64(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s: String = v
        .as_str()
        .ok_or_else(|| format!("{what} missing"))?
        .chars()
        .filter(|c| !matches!(c, '\n' | '\r'))
        .collect();

    BASE64_STANDARD
        .decode(s)
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
    let timestamps: Vec<Vec<u8>> = bundle["verificationMaterial"]["timestampVerificationData"]
        ["rfc3161Timestamps"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| b64(&t["signedTimestamp"], "signedTimestamp"))
        .collect::<Result<_>>()?;
    let env = EnvelopeSig::dsse(&payload_type, &payload, sig_b64)?;
    let anchored = anchor_chain(&chain, roots)?;
    let mut first_error = None;

    for a in &anchored {
        let attempt = if a.root.is_ca_only() {
            verify_certificate_mode(&chain, a, &env, &timestamps, now)
        } else {
            verify_keyless_mode(bundle, &chain, &env, &timestamps, a.root)
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
    anchored: &Anchored,
    env: &EnvelopeSig,
    timestamps: &[Vec<u8>],
    now: i64,
) -> ModeResult {
    let leaf = &chain[0];
    let ca = anchored.path.last().ok_or("empty certificate path")?;
    let (times, _) = verified_times(timestamps, &env.sig, anchored.root)?;

    // No log witnessed a certificate-mode signature. A timestamp from the
    // root's own authority says when it was made; without one, the
    // certificates and the CA's window are checked now (spec/07 §3.2).
    let at = if times.is_empty() {
        vec![now]
    } else {
        times.clone()
    };

    for &t in &at {
        check_valid_at(&anchored.path, t)?;
        if !anchored.root.ca_valid_at(ca, t) {
            return Err(format!(
                "certificate authority \"{}\" of trust root \"{}\" is outside its validity window at {t}",
                subject_of(ca),
                anchored.root.name
            ));
        }
    }
    check_signing_leaf(leaf)?;
    env.verify_by(leaf)?;
    Ok((
        SignerMode::Certificate,
        subject_of(leaf),
        String::new(),
        times.iter().copied().min(),
        None,
    ))
}

/// A Sigstore tlog entry's proof: the inclusion promise (Rekor v1) when it
/// has one, else the inclusion proof and its checkpoint (Rekor v2).
fn entry_proof(entry: &Value) -> Result<LogProof<'_>> {
    if let Some(set_b64) = entry["inclusionPromise"]["signedEntryTimestamp"].as_str() {
        return Ok(LogProof::Promise {
            integrated_time: int64(&entry["integratedTime"], "tlog integratedTime")?,
            set_b64,
        });
    }

    let p = &entry["inclusionProof"];

    if !p.is_object() {
        return Err(
            "tlog entry has neither an inclusion promise nor an inclusion proof".to_string(),
        );
    }
    if !p["logIndex"].is_null()
        && int64(&p["logIndex"], "inclusionProof logIndex")?
            != int64(&entry["logIndex"], "tlog logIndex")?
    {
        return Err("inclusion proof is for a different log index".to_string());
    }
    Ok(LogProof::Inclusion {
        tree_size: u64::try_from(int64(&p["treeSize"], "inclusionProof treeSize")?)
            .map_err(|_| "negative treeSize")?,
        root_hash: b64(&p["rootHash"], "inclusionProof rootHash")?,
        hashes: b64_list(&p["hashes"], "inclusionProof hashes")?,
        checkpoint: p["checkpoint"]["envelope"]
            .as_str()
            .ok_or("inclusion proof has no checkpoint")?,
    })
}

fn verify_keyless_mode(
    bundle: &Value,
    chain: &[Certificate],
    env: &EnvelopeSig,
    timestamps: &[Vec<u8>],
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
        proof: entry_proof(entry)?,
    };
    let parts = verify_keyless_parts(chain, env, &tlog, timestamps, std::slice::from_ref(root))?;

    Ok((
        SignerMode::Keyless,
        parts.identity,
        parts.issuer,
        Some(parts.integrated_time),
        Some(tlog.log_index),
    ))
}

#[cfg(test)]
mod conformance {
    // Sigstore's own conformance vectors (github.com/sigstore/sigstore-conformance,
    // test/assets/bundle-verify) for Rekor v2 entries, checkpoints and RFC 3161
    // timestamps. They are not vendored here; point
    // PROMPTSIGN_SIGSTORE_CONFORMANCE at a checkout's bundle-verify directory
    // to run them. A directory ending in `_fail` must not verify.

    use super::*;
    use std::path::Path;

    /// A message-signature bundle through the keyless checks, with the
    /// artifact digest standing in for the DSSE envelope.
    fn verify_message_signature(bundle: &Value, roots: &[Root]) -> Result<()> {
        let chain = parse_chain(&bundle["verificationMaterial"])?;
        let ms = &bundle["messageSignature"];
        let sig_b64 = ms["signature"].as_str().ok_or("no signature")?;
        let mut env = EnvelopeSig::dsse("", &[], sig_b64)?;

        env.digest = Some(b64(&ms["messageDigest"]["digest"], "messageDigest")?);

        let timestamps: Vec<Vec<u8>> = bundle["verificationMaterial"]["timestampVerificationData"]
            ["rfc3161Timestamps"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|t| b64(&t["signedTimestamp"], "signedTimestamp"))
            .collect::<Result<_>>()?;
        let anchored = anchor_chain(&chain, roots)?;
        let mut first_error = None;

        for a in &anchored {
            match verify_keyless_mode(bundle, &chain, &env, &timestamps, a.root) {
                Ok(_) => return Ok(()),
                Err(e) => first_error = first_error.or(Some(e)),
            }
        }
        Err(first_error.unwrap_or_else(|| "no root".to_string()))
    }

    fn read(p: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    #[test]
    fn sigstore_conformance_vectors() {
        let Some(dir) = std::env::var_os("PROMPTSIGN_SIGSTORE_CONFORMANCE") else {
            return;
        };
        let dir = Path::new(&dir);
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("rekor2-") || n.contains("tsa"))
            .collect();
        let mut wrong = Vec::new();

        names.sort();
        for name in &names {
            let case = dir.join(name);
            let bundle = read(&case.join("bundle.sigstore.json"));
            let mut root_doc = if case.join("trusted_root.json").exists() {
                read(&case.join("trusted_root.json"))
            } else {
                read(&dir.join("rekor2-happy-path/trusted_root.json"))
            };

            if name == "trust-root-tsa-validity-end-inclusive" {
                root_doc["timestampAuthorities"][0]["validFor"]["end"] =
                    serde_json::json!("2025-06-12T12:02:20Z");
            }

            let roots = vec![Root::from_trusted_root("conformance", &root_doc).unwrap()];
            let result = if bundle.get("dsseEnvelope").is_some() {
                verify_sigstore_bundle(&bundle, &roots, 0).map(|_| ())
            } else {
                verify_message_signature(&bundle, &roots)
            };
            let expect_ok = !name.ends_with("_fail");

            eprintln!("{name}: {result:?}");
            if result.is_ok() != expect_ok {
                wrong.push(format!("{name}: {result:?}"));
            }
        }
        assert!(!names.is_empty(), "no vectors in {}", dir.display());
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
