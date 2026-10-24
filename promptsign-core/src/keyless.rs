// Offline verification of keyless (Sigstore-style) bundles per spec/05-keyless.md:
// stapled certificate chain to a pinned trust root, SAN identity + Fulcio issuer
// extraction, and the log's proof: a Rekor v1 signed entry timestamp, or a
// Rekor v2 inclusion proof with RFC 3161 timestamps. No network anywhere.

use crate::bundle::pae;
use crate::chain::{
    anchor_chain, spki_der_of, subject_of, validity, verify_leaf_signature, Anchored,
};
use crate::logproof::{leaf_hash, verify_checkpoint, verify_inclusion};
use crate::timestamp::{verify_timestamp, MAX_TIMESTAMPS};
use crate::trustroot::{load_registry, Root, Window};
use crate::util::{hex, promptsign_home, sha256_hex};
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

/// A transparency log's signing key. Rekor v1 logs use ECDSA P-256; Rekor v2
/// logs use Ed25519 or ECDSA P-256.
#[derive(Clone)]
pub enum LogKey {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// One transparency log: its public key, and the log id that every entry it
/// witnesses carries. For a P-256 key the id is the hex SHA-256 of the SPKI
/// DER; for an Ed25519 key it is the C2SP signed-note key hash, which covers
/// the log's origin (spec/07 §1).
#[derive(Clone)]
pub struct RekorLog {
    pub key: LogKey,
    pub log_id: String,
    pub spki_der: Vec<u8>,
    /// When the key may have witnessed entries (spec/07 §4). Open for the
    /// pinned `rekor.pub`, which carries no windows.
    pub valid: Window,
    /// The log's base URL. Its host is the origin a Rekor v2 checkpoint names;
    /// the pinned `rekor.pub` has none.
    pub base_url: Option<String>,
}

impl RekorLog {
    pub fn from_spki_der(der: &[u8]) -> Result<RekorLog> {
        let key = p256::ecdsa::VerifyingKey::from_public_key_der(der)
            .map_err(|e| format!("invalid P-256 public key: {e}"))?;

        Ok(RekorLog {
            key: LogKey::P256(key),
            log_id: sha256_hex(der),
            spki_der: der.to_vec(),
            valid: Window::default(),
            base_url: None,
        })
    }

    /// An Ed25519 log, which needs its base URL: the log id hashes the origin.
    pub fn ed25519(der: &[u8], base_url: &str) -> Result<RekorLog> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let key = ed25519_dalek::VerifyingKey::from_public_key_der(der)
            .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
        let origin =
            host_of(base_url).ok_or_else(|| format!("log baseUrl \"{base_url}\" has no host"))?;
        let mut id = Sha256::new();

        id.update(origin.as_bytes());
        id.update(b"\n\x01");
        id.update(key.as_bytes());
        Ok(RekorLog {
            key: LogKey::Ed25519(key),
            log_id: hex(&id.finalize()),
            spki_der: der.to_vec(),
            valid: Window::default(),
            base_url: Some(base_url.to_string()),
        })
    }

    /// The checkpoint origin: the host of the log's base URL.
    pub fn origin(&self) -> Option<String> {
        self.base_url.as_deref().and_then(host_of)
    }

    /// The four bytes a checkpoint signature line names its key by.
    pub(crate) fn key_hint(&self) -> Vec<u8> {
        (0..4)
            .filter_map(|i| u8::from_str_radix(self.log_id.get(2 * i..2 * i + 2)?, 16).ok())
            .collect()
    }

    pub fn key_details(&self) -> &'static str {
        match self.key {
            LogKey::P256(_) => "PKIX_ECDSA_P256_SHA_256",
            LogKey::Ed25519(_) => "PKIX_ED25519",
        }
    }
}

/// The host of an http(s) URL, without user info or port.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    };

    (!host.is_empty()).then(|| host.to_string())
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
    match crate::managed::env_override("PROMPTSIGN_TRUST_DIR") {
        Some(p) => PathBuf::from(p),
        None => promptsign_home().join("trust"),
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
        .tbs_certificate()
        .extensions()
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
    /// When the signature was witnessed (spec/05 §4 step 5).
    pub signed_at: i64,
}

/// One transparency-log entry, in whatever carriage the bundle used.
pub(crate) struct TlogEntry<'a> {
    /// Base64 canonicalized entry body.
    pub body_b64: &'a str,
    /// Hex id of the witnessing log (spec/07 §1).
    pub log_id: String,
    pub log_index: i64,
    pub proof: LogProof<'a>,
}

/// How the log vouches for the entry.
pub(crate) enum LogProof<'a> {
    /// Rekor v1: a signed entry timestamp over the canonical entry, which also
    /// signs the time the log integrated it.
    Promise {
        integrated_time: i64,
        set_b64: &'a str,
    },
    /// Rekor v2: an inclusion proof against a checkpoint the log signed. It
    /// carries no time; RFC 3161 timestamps supply it.
    Inclusion {
        tree_size: u64,
        root_hash: Vec<u8>,
        hashes: Vec<Vec<u8>>,
        checkpoint: &'a str,
    },
}

/// What a keyless signature proves once the chain, the envelope signature and
/// the log entry all check out.
pub(crate) struct KeylessParts {
    pub identity: String,
    pub issuer: String,
    pub leaf_keyid: String,
    pub root: String,
    /// The log's integratedTime when it signed one, else the earliest
    /// verified timestamp.
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

/// The validity windows of spec/07 §4 at signing time `t`: every CA on the
/// path that the root lists, under any of its entries, and the log key that
/// witnessed it.
fn check_windows(a: &Anchored, log: &RekorLog, t: i64) -> Result<()> {
    if let Some(ca) = a.root.ca_outside_window(&a.path, t) {
        return Err(format!(
            "certificate authority \"{}\" of trust root \"{}\" was outside its validity window when the signature was made ({t})",
            subject_of(ca),
            a.root.name
        ));
    }
    if !log.valid.contains(t) {
        return Err(format!(
            "transparency log {}… of trust root \"{}\" was outside its validity window when the signature was made ({t})",
            &log.log_id[..16.min(log.log_id.len())],
            a.root.name
        ));
    }
    Ok(())
}

/// Every RFC 3161 timestamp in the bundle that verifies against `root`'s
/// timestamp authorities, over the envelope signature `sig`. One that does
/// not verify is no time evidence; the first such error explains a bundle
/// left with none.
pub(crate) fn verified_times(
    timestamps: &[Vec<u8>],
    sig: &[u8],
    root: &Root,
) -> Result<(Vec<i64>, Option<String>)> {
    if timestamps.len() > MAX_TIMESTAMPS {
        return Err(format!(
            "bundle carries {} timestamps, more than {MAX_TIMESTAMPS}",
            timestamps.len()
        ));
    }

    let mut times = Vec::new();
    let mut first_error = None;

    for ts in timestamps {
        match verify_timestamp(ts, sig, &root.tsas) {
            Ok(v) => times.push(v.time),
            Err(e) => first_error = first_error.or(Some(e)),
        }
    }
    Ok((times, first_error))
}

/// The DSSE signature a keyless bundle carries, in both forms the log
/// entries compare against.
pub(crate) struct EnvelopeSig<'a> {
    pub payload_type: &'a str,
    pub payload: &'a [u8],
    pub sig: Vec<u8>,
    pub sig_b64: &'a str,
    /// Tests only: a Sigstore message signature over this SHA-256 artifact
    /// digest, so the conformance vectors run through the same checks.
    #[cfg(test)]
    pub digest: Option<Vec<u8>>,
}

impl<'a> EnvelopeSig<'a> {
    pub(crate) fn dsse(payload_type: &'a str, payload: &'a [u8], sig_b64: &'a str) -> Result<Self> {
        Ok(EnvelopeSig {
            payload_type,
            payload,
            sig: BASE64_STANDARD
                .decode(sig_b64)
                .map_err(|_| "invalid base64 in signature")?,
            sig_b64,
            #[cfg(test)]
            digest: None,
        })
    }

    /// Step 1: the leaf's key signed the envelope.
    pub(crate) fn verify_by(&self, leaf: &Certificate) -> Result<()> {
        #[cfg(test)]
        if let Some(d) = &self.digest {
            return crate::chain::verify_leaf_prehash(leaf, d, &self.sig);
        }
        verify_leaf_signature(leaf, &pae(self.payload_type, self.payload), &self.sig)
    }

    /// The digest a `hashedrekord` entry records for this signature under
    /// `alg`: the hash of PAE(payloadType, payload).
    fn entry_digest(&self, alg: &str) -> Option<Vec<u8>> {
        #[cfg(test)]
        if let Some(d) = &self.digest {
            return (alg == "SHA2_256").then(|| d.clone());
        }

        let pae = pae(self.payload_type, self.payload);

        match alg {
            "SHA2_256" => Some(Sha256::digest(&pae).to_vec()),
            "SHA2_384" => Some(sha2::Sha384::digest(&pae).to_vec()),
            "SHA2_512" => Some(sha2::Sha512::digest(&pae).to_vec()),
            _ => None,
        }
    }
}

/// Offline keyless verification per spec/05-keyless.md §4, independent of
/// how the bundle carries its parts: the chain must end at a keyless root,
/// the leaf must have signed the DSSE envelope, one of that root's logs must
/// hold the entry, and the leaf must have been valid at every verified
/// signing time.
pub(crate) fn verify_keyless_parts(
    chain: &[Certificate],
    env: &EnvelopeSig,
    tlog: &TlogEntry,
    timestamps: &[Vec<u8>],
    roots: &[Root],
) -> Result<KeylessParts> {
    let keyless: Vec<Root> = roots.iter().filter(|r| !r.is_ca_only()).cloned().collect();
    let anchored = anchor_chain(chain, &keyless)?;
    let leaf = &chain[0];

    // envelope signature (step 1)
    env.verify_by(leaf)?;

    // The entry names the log that witnessed it; only the logs of a root the
    // chain ends at count. After a key rotation both keys are pinned, so old
    // entries keep verifying.
    let mut first_error = None;

    for a in &anchored {
        for log in a.root.rekor_logs.iter().filter(|l| l.log_id == tlog.log_id) {
            match verify_with_log(a, log, leaf, env, tlog, timestamps) {
                Ok(time) => {
                    let (identity, issuer) = leaf_identity(leaf)?;

                    return Ok(KeylessParts {
                        identity,
                        issuer,
                        leaf_keyid: sha256_hex(&spki_der_of(leaf)?),
                        root: a.root.name.clone(),
                        integrated_time: time,
                    });
                }
                Err(e) => first_error = first_error.or(Some(e)),
            }
        }
    }
    if let Some(e) = first_error {
        return Err(e);
    }

    let trusted: Vec<&str> = anchored
        .iter()
        .flat_map(|a| a.root.rekor_logs.iter())
        .map(|l| &l.log_id[..16.min(l.log_id.len())])
        .collect();

    Err(format!(
        "transparency logId {} does not match any trusted log (trusted: {}…)",
        tlog.log_id,
        trusted.join("…, ")
    ))
}

/// Steps 3 to 5 for one candidate log: the log's proof, the entry binding,
/// and the certificate's validity at each signing time. Returns the time the
/// signature was witnessed.
fn verify_with_log(
    a: &Anchored,
    log: &RekorLog,
    leaf: &Certificate,
    env: &EnvelopeSig,
    tlog: &TlogEntry,
    timestamps: &[Vec<u8>],
) -> Result<i64> {
    let body_raw = BASE64_STANDARD
        .decode(tlog.body_b64)
        .map_err(|_| "invalid base64 in body")?;
    let body: Value = serde_json::from_slice(&body_raw).map_err(|e| format!("entry body: {e}"))?;

    // log proof (step 3) and entry binding (step 4)
    let witnessed = match &tlog.proof {
        LogProof::Promise {
            integrated_time,
            set_b64,
        } => {
            verify_set(log, tlog, *integrated_time, set_b64)?;
            bind_dsse_v001(&body, env)?;
            Some(*integrated_time)
        }
        LogProof::Inclusion {
            tree_size,
            root_hash,
            hashes,
            checkpoint,
        } => {
            let cp = verify_checkpoint(checkpoint, log)?;

            if cp.size != *tree_size || cp.root_hash != *root_hash {
                return Err("inclusion proof does not match its checkpoint".to_string());
            }

            let index = u64::try_from(tlog.log_index).map_err(|_| "negative logIndex")?;

            verify_inclusion(index, cp.size, &leaf_hash(&body_raw), hashes, &cp.root_hash)?;
            bind_hashedrekord_v002(&body, leaf, env)?;
            None
        }
    };

    // time validity (step 5)
    let (mut times, ts_error) = verified_times(timestamps, &env.sig, a.root)?;

    times.extend(witnessed);
    if times.is_empty() {
        return Err(match ts_error {
            Some(e) => format!("no verified signing time: {e}"),
            None => "no verified signing time: the log entry carries none and the bundle has no timestamp".to_string(),
        });
    }

    let (nb, na) = validity(leaf);

    for &t in &times {
        if t < nb || t > na {
            return Err(format!(
                "signing time {t} outside certificate validity [{nb}, {na}]"
            ));
        }
        check_windows(a, log, t)?;
    }
    Ok(witnessed.unwrap_or_else(|| times.iter().copied().min().unwrap_or_default()))
}

/// Rekor v1: the SET is the log's ECDSA signature over the canonical entry.
fn verify_set(log: &RekorLog, tlog: &TlogEntry, integrated_time: i64, set_b64: &str) -> Result<()> {
    let LogKey::P256(key) = &log.key else {
        return Err("signed entry timestamp from a log without a P-256 key".to_string());
    };
    let canonical = format!(
        "{{\"body\":{},\"integratedTime\":{},\"logID\":{},\"logIndex\":{}}}",
        serde_json::to_string(tlog.body_b64).unwrap(),
        integrated_time,
        serde_json::to_string(&tlog.log_id).unwrap(),
        tlog.log_index
    );
    let set = BASE64_STANDARD
        .decode(set_b64)
        .map_err(|_| "invalid base64 in signedEntryTimestamp")?;
    let set_sig = p256::ecdsa::Signature::from_der(&set).map_err(|_| "malformed SET")?;

    key.verify_prehash(&Sha256::digest(canonical.as_bytes()), &set_sig)
        .map_err(|_| "signed entry timestamp verification failed".to_string())
}

/// A Rekor v1 `dsse` 0.0.1 entry must hash the payload and hold the signature.
fn bind_dsse_v001(body: &Value, env: &EnvelopeSig) -> Result<()> {
    if str_at(body, &["kind"]) != Some("dsse") {
        return Err(format!(
            "unexpected transparency entry kind: {}",
            show_str(body, "kind")
        ));
    }

    let payload_hash = str_at(body, &["spec", "payloadHash", "value"]).unwrap_or("");

    if payload_hash != sha256_hex(env.payload) {
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
        .any(|s| str_at(s, &["signature"]) == Some(env.sig_b64))
    {
        return Err("transparency entry does not contain the envelope signature".to_string());
    }
    Ok(())
}

/// A Rekor v2 `hashedrekord` 0.0.2 entry must hash PAE(payloadType, payload)
/// and hold the signature and the leaf certificate (spec/05 §3.2).
fn bind_hashedrekord_v002(body: &Value, leaf: &Certificate, env: &EnvelopeSig) -> Result<()> {
    if str_at(body, &["kind"]) != Some("hashedrekord")
        || str_at(body, &["apiVersion"]) != Some("0.0.2")
    {
        return Err(format!(
            "unexpected transparency entry kind for an inclusion proof: {} {}",
            show_str(body, "kind"),
            show_str(body, "apiVersion")
        ));
    }

    let spec = &body["spec"]["hashedRekordV002"];
    let b64 = |v: &Value, what: &str| -> Result<Vec<u8>> {
        BASE64_STANDARD
            .decode(
                v.as_str()
                    .ok_or_else(|| format!("transparency entry has no {what}"))?,
            )
            .map_err(|_| format!("invalid base64 in transparency entry {what}"))
    };
    let alg = spec["data"]["algorithm"].as_str().unwrap_or("none");
    let digest = env
        .entry_digest(alg)
        .ok_or_else(|| format!("unsupported transparency entry digest algorithm: {alg}"))?;

    if b64(&spec["data"]["digest"], "digest")? != digest {
        return Err("transparency entry digest does not match the signed content".to_string());
    }
    if b64(&spec["signature"]["content"], "signature")? != env.sig {
        return Err("transparency entry does not contain the envelope signature".to_string());
    }
    if b64(
        &spec["signature"]["verifier"]["x509Certificate"]["rawBytes"],
        "certificate",
    )? != leaf.to_der().map_err(|e| e.to_string())?
    {
        return Err("transparency entry names a different certificate".to_string());
    }
    Ok(())
}

/// Full offline keyless verification of a PromptSign bundle per
/// spec/05-keyless.md §4 (steps 1–6), against every keyless root in the
/// registry. Returns the authenticated payload; manifest parsing, integrity
/// and policy are the caller's next steps.
pub fn verify_keyless(bundle: &Value) -> Result<KeylessVerification> {
    verify_keyless_with(bundle, &keyless_roots()?)
}

/// Base64 strings in a JSON array, decoded. Absent means none.
pub(crate) fn b64_list(v: &Value, what: &str) -> Result<Vec<Vec<u8>>> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            BASE64_STANDARD
                .decode(
                    s.as_str()
                        .ok_or_else(|| format!("{what} entry is not a string"))?,
                )
                .map_err(|_| format!("invalid base64 in {what}"))
        })
        .collect()
}

/// The log proof of a PromptSign `transparency` block (spec/05 §1).
fn native_proof(t: &Value) -> Result<LogProof<'_>> {
    if let Some(set_b64) = str_at(t, &["signedEntryTimestamp"]) {
        return Ok(LogProof::Promise {
            integrated_time: t
                .get("integratedTime")
                .and_then(|v| v.as_i64())
                .ok_or("transparency.integratedTime missing")?,
            set_b64,
        });
    }

    let p = t
        .get("inclusionProof")
        .ok_or("transparency block has neither signedEntryTimestamp nor inclusionProof")?;

    Ok(LogProof::Inclusion {
        tree_size: p
            .get("treeSize")
            .and_then(|v| v.as_u64())
            .ok_or("inclusionProof.treeSize missing")?,
        root_hash: BASE64_STANDARD
            .decode(str_at(p, &["rootHash"]).ok_or("inclusionProof.rootHash missing")?)
            .map_err(|_| "invalid base64 in inclusionProof.rootHash")?,
        hashes: b64_list(&p["hashes"], "inclusionProof.hashes")?,
        checkpoint: str_at(p, &["checkpoint"]).ok_or("inclusionProof.checkpoint missing")?,
    })
}

/// `verify_keyless` against the given roots instead of the registry.
pub fn verify_keyless_with(bundle: &Value, roots: &[Root]) -> Result<KeylessVerification> {
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
    let env = EnvelopeSig::dsse(payload_type, &payload, sig_b64)?;
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
        proof: native_proof(t)?,
    };
    let timestamps = b64_list(&bundle["timestamps"], "timestamps")?;
    let parts = verify_keyless_parts(&chain, &env, &tlog, &timestamps, roots)?;

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
        signed_at: parts.integrated_time,
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
