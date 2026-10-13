// Test-only Sigstore stand-in: a Fulcio-style CA and a Rekor-style log key that
// issue real keyless PromptSign signatures, fully offline. Each instance is one
// "deployment": the public good instance in one test, an organization's private
// one in another. Nothing here ships; signed trust bundles for tests are made
// with it rather than with any CLI command.

#![allow(dead_code)]

pub mod v2;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use promptsign_core::bundle::{pae, PAYLOAD_TYPE};
use promptsign_core::util::sha256_hex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, Utf8StringRef};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, EncodePem, Length, Writer};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

pub(crate) struct IssuerExt(pub String);

impl AssociatedOid for IssuerExt {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
}
impl Encode for IssuerExt {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        Utf8StringRef::new(&self.0)?.encoded_len()
    }
    fn encode(&self, w: &mut impl Writer) -> x509_cert::der::Result<()> {
        Utf8StringRef::new(&self.0)?.encode(w)
    }
}
impl AsExtension for IssuerExt {
    fn critical(&self, _: &Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub struct MockSigstore {
    ca_key: p256::ecdsa::SigningKey,
    ca_name: Name,
    pub ca_cert: Certificate,
    log_key: p256::ecdsa::SigningKey,
    serial: std::cell::Cell<u32>,
    /// Rekor v2: an Ed25519 log that signs checkpoints.
    log2_key: ed25519_dalek::SigningKey,
    /// An RFC 3161 timestamp authority: its own root, and the
    /// timestamping certificate that root issued.
    tsa_root_cert: Certificate,
    tsa_key: p256::ecdsa::SigningKey,
    pub tsa_cert: Certificate,
}

impl MockSigstore {
    /// A deployment whose keys derive from `seed`, so two seeds are two
    /// unrelated deployments. Its CA is valid 2025 to 2125: a fixed window, so
    /// two calls with one seed build the same certificate even when a second
    /// ticks between them.
    pub fn new(seed: u8, cn: &str) -> MockSigstore {
        MockSigstore::new_valid(seed, cn, 1_735_689_600, 4_891_363_200)
    }

    /// As `new`, with the CA certificate valid over `[not_before, not_after]`
    /// (Unix seconds), so fixtures written today still verify years later.
    pub fn new_valid(seed: u8, cn: &str, not_before: i64, not_after: i64) -> MockSigstore {
        let ca_key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let ca_name = Name::from_str(&format!("CN={cn},O=promptsign tests")).unwrap();
        let ca_spki = SubjectPublicKeyInfoOwned::from_der(
            ca_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let ca_cert = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity(not_before, not_after),
            ca_name.clone(),
            ca_spki,
            &ca_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let log_key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap();
        let (tsa_root_cert, tsa_key, tsa_cert) =
            v2::timestamp_authority(seed, cn, not_before, not_after);

        MockSigstore {
            ca_key,
            ca_name,
            ca_cert,
            log_key,
            serial: std::cell::Cell::new(2),
            log2_key: ed25519_dalek::SigningKey::from_bytes(&[seed.wrapping_add(2); 32]),
            tsa_root_cert,
            tsa_key,
            tsa_cert,
        }
    }

    pub fn fulcio_pem(&self) -> String {
        self.ca_cert
            .to_pem(x509_cert::der::pem::LineEnding::LF)
            .unwrap()
    }

    pub fn rekor_pem(&self) -> String {
        self.log_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap()
    }

    pub fn log_id(&self) -> String {
        sha256_hex(
            self.log_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
    }

    /// This deployment as a trusted_root.json document.
    pub fn trusted_root(&self) -> Value {
        let spki = self.log_key.verifying_key().to_public_key_der().unwrap();

        json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [{
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": BASE64_STANDARD.encode(spki.as_bytes()),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": { "keyId": BASE64_STANDARD.encode(Sha256::digest(spki.as_bytes())) }
            }],
            "certificateAuthorities": [{
                "subject": { "commonName": "test" },
                "certChain": { "certificates": [
                    { "rawBytes": BASE64_STANDARD.encode(self.ca_cert.to_der().unwrap()) }
                ] }
            }],
            "ctlogs": [],
            "timestampAuthorities": []
        })
    }

    /// A keyless PromptSign bundle over `payload`, witnessed now.
    pub fn sign_payload(&self, payload: &[u8], identity: &str, issuer: &str) -> Value {
        self.sign_payload_at(payload, identity, issuer, now())
    }

    /// As `sign_payload`, witnessed at `integrated_time`. The leaf is valid
    /// for ten minutes from a minute before it, as Fulcio issues them.
    pub fn sign_payload_at(
        &self,
        payload: &[u8],
        identity: &str,
        issuer: &str,
        integrated_time: i64,
    ) -> Value {
        let serial = self.serial.get();

        self.serial.set(serial + 1);

        let leaf_key = ed25519_dalek::SigningKey::from_bytes(&[serial as u8; 32]);
        let leaf_spki = SubjectPublicKeyInfoOwned::from_der(
            leaf_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let mut leaf = CertificateBuilder::new(
            Profile::Leaf {
                issuer: self.ca_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(serial),
            validity(integrated_time - 60, integrated_time + 600),
            Name::from_str("CN=sigstore-intermediate").unwrap(),
            leaf_spki,
            &self.ca_key,
        )
        .unwrap();
        let san = if identity.contains("://") {
            GeneralName::UniformResourceIdentifier(Ia5String::new(identity).unwrap())
        } else {
            GeneralName::Rfc822Name(Ia5String::new(identity).unwrap())
        };

        leaf.add_extension(&SubjectAltName(vec![san])).unwrap();
        leaf.add_extension(&IssuerExt(issuer.to_string())).unwrap();

        let leaf_cert: Certificate = leaf.build::<p256::ecdsa::DerSignature>().unwrap();
        let sig_b64 = BASE64_STANDARD.encode(leaf_key.sign(&pae(PAYLOAD_TYPE, payload)).to_bytes());
        let body = json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            "spec": {
                "payloadHash": { "algorithm": "sha256", "value": sha256_hex(payload) },
                "signatures": [{
                    "signature": sig_b64,
                    "verifier": leaf_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap()
                }]
            }
        });
        let body_b64 = BASE64_STANDARD.encode(serde_json::to_vec(&body).unwrap());
        let log_id = self.log_id();
        let canonical = format!(
            "{{\"body\":{},\"integratedTime\":{integrated_time},\"logID\":{},\"logIndex\":{serial}}}",
            serde_json::to_string(&body_b64).unwrap(),
            serde_json::to_string(&log_id).unwrap()
        );
        let set: p256::ecdsa::Signature = self
            .log_key
            .sign_prehash(&Sha256::digest(canonical.as_bytes()))
            .unwrap();

        json!({
            "schema": "promptsign/bundle/v1",
            "envelope": {
                "payloadType": PAYLOAD_TYPE,
                "payload": BASE64_STANDARD.encode(payload),
                "signatures": [{ "keyid": "", "sig": sig_b64 }]
            },
            "signer": {
                "scheme": "keyless",
                "identity": identity,
                "issuer": issuer,
                "certChain": [BASE64_STANDARD.encode(leaf_cert.to_der().unwrap())]
            },
            "transparency": {
                "logId": log_id,
                "logIndex": serial,
                "integratedTime": integrated_time,
                "signedEntryTimestamp": BASE64_STANDARD.encode(set.to_der()),
                "body": body_b64
            }
        })
    }

    /// A sidecar (`<file>.psig.json`) for a single file's bytes, as
    /// `promptsign sign <file>` writes it.
    pub fn sign_file(&self, file_name: &str, bytes: &[u8], identity: &str, issuer: &str) -> Value {
        self.sign_file_at(file_name, bytes, identity, issuer, now())
    }

    /// As `sign_file`, witnessed at `integrated_time`.
    pub fn sign_file_at(
        &self,
        file_name: &str,
        bytes: &[u8],
        identity: &str,
        issuer: &str,
        integrated_time: i64,
    ) -> Value {
        let manifest = json!({
            "schema": "promptsign/manifest/v1",
            "name": file_name,
            "scope": "file",
            "files": [{ "path": file_name, "sha256": sha256_hex(bytes) }]
        });

        self.sign_payload_at(
            &serde_json::to_vec(&manifest).unwrap(),
            identity,
            issuer,
            integrated_time,
        )
    }
}

pub(crate) fn validity(not_before: i64, not_after: i64) -> Validity {
    let at = |t: i64| {
        x509_cert::time::Time::try_from(UNIX_EPOCH + Duration::from_secs(t as u64)).unwrap()
    };

    Validity {
        not_before: at(not_before),
        not_after: at(not_after),
    }
}

/// A fresh directory under the system temp dir. The counter keeps names
/// apart when parallel tests read the same clock tick.
pub fn temp_dir(tag: &str) -> std::path::PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let dir = std::env::temp_dir().join(format!(
        "ps-{tag}-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    std::fs::create_dir_all(&dir).unwrap();
    dir
}
