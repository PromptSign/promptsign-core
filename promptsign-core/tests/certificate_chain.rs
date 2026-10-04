// Certificate-mode path rules with a synthetic PKI: only CA certificates may
// issue, and path length limits hold. An enterprise CA issues many ordinary
// certificates; none of them may mint a signing certificate of its own.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePublicKey as _;
use promptsign_core::bundle::pae;
use promptsign_core::sigstore_bundle::{verify_sigstore_bundle, SignerMode};
use promptsign_core::trustroot::Root;
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, Encode, EncodePem};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn spki(k: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(k.verifying_key().to_public_key_der().unwrap().as_bytes())
        .unwrap()
}

fn cert(
    profile: Profile,
    serial: u32,
    subject: &str,
    subject_key: &SigningKey,
    issuer_key: &SigningKey,
) -> Certificate {
    CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        Name::from_str(subject).unwrap(),
        spki(subject_key),
        issuer_key,
    )
    .unwrap()
    .build::<DerSignature>()
    .unwrap()
}

fn leaf_profile(issuer: &str) -> Profile {
    Profile::Leaf {
        issuer: Name::from_str(issuer).unwrap(),
        enable_key_agreement: false,
        enable_key_encipherment: false,
    }
}

fn bundle(chain: &[&Certificate], signer: &SigningKey) -> Value {
    let payload = br#"{"_type":"https://in-toto.io/Statement/v1"}"#;
    let sig: DerSignature = signer.sign(&pae(PAYLOAD_TYPE, payload));
    let certificates: Vec<Value> = chain
        .iter()
        .map(|c| json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap()) }))
        .collect();

    json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": { "x509CertificateChain": { "certificates": certificates } },
        "dsseEnvelope": {
            "payload": BASE64_STANDARD.encode(payload),
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{ "sig": BASE64_STANDARD.encode(sig.as_bytes()) }]
        }
    })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct Pki {
    root_key: SigningKey,
    root: Root,
}

fn pki() -> Pki {
    let root_key = key(1);
    let root_cert = cert(
        Profile::Root,
        1,
        "CN=Corp Root,O=Corp",
        &root_key,
        &root_key,
    );
    let pem = root_cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .unwrap();

    Pki {
        root: Root::ca_only("corp", pem.as_bytes()).unwrap(),
        root_key,
    }
}

#[test]
fn a_signing_certificate_from_a_real_intermediate_verifies() {
    let p = pki();
    let ica_key = key(2);
    let ica = cert(
        Profile::SubCA {
            issuer: Name::from_str("CN=Corp Root,O=Corp").unwrap(),
            path_len_constraint: Some(0),
        },
        2,
        "CN=Corp Signing CA,O=Corp",
        &ica_key,
        &p.root_key,
    );
    let leaf_key = key(3);
    let leaf = cert(
        leaf_profile("CN=Corp Signing CA,O=Corp"),
        3,
        "CN=Release Signing,O=Corp",
        &leaf_key,
        &ica_key,
    );
    let v = verify_sigstore_bundle(&bundle(&[&leaf, &ica], &leaf_key), &[p.root], now()).unwrap();

    assert_eq!(v.mode, SignerMode::Certificate);
    assert_eq!(v.root, "corp");
    assert!(v.identity.contains("CN=Release Signing"), "{}", v.identity);
}

#[test]
fn an_ordinary_certificate_cannot_issue_a_signing_certificate() {
    let p = pki();
    let employee_key = key(4);
    let employee = cert(
        leaf_profile("CN=Corp Root,O=Corp"),
        4,
        "CN=Alice,O=Corp",
        &employee_key,
        &p.root_key,
    );
    let forged_key = key(5);
    let forged = cert(
        leaf_profile("CN=Alice,O=Corp"),
        5,
        "CN=Release Signing,O=Corp",
        &forged_key,
        &employee_key,
    );
    let err = verify_sigstore_bundle(
        &bundle(&[&forged, &employee], &forged_key),
        &[p.root],
        now(),
    )
    .unwrap_err();

    assert!(err.contains("not a CA"), "{err}");
}

#[test]
fn path_length_limits_hold() {
    let p = pki();
    let ica_key = key(6);
    let ica = cert(
        Profile::SubCA {
            issuer: Name::from_str("CN=Corp Root,O=Corp").unwrap(),
            path_len_constraint: Some(0),
        },
        6,
        "CN=Corp ICA,O=Corp",
        &ica_key,
        &p.root_key,
    );
    let sub_key = key(7);
    let sub = cert(
        Profile::SubCA {
            issuer: Name::from_str("CN=Corp ICA,O=Corp").unwrap(),
            path_len_constraint: None,
        },
        7,
        "CN=Team CA,O=Corp",
        &sub_key,
        &ica_key,
    );
    let leaf_key = key(8);
    let leaf = cert(
        leaf_profile("CN=Team CA,O=Corp"),
        8,
        "CN=Team Signing,O=Corp",
        &leaf_key,
        &sub_key,
    );
    let err = verify_sigstore_bundle(&bundle(&[&leaf, &sub, &ica], &leaf_key), &[p.root], now())
        .unwrap_err();

    assert!(err.contains("allows 0"), "{err}");
}
