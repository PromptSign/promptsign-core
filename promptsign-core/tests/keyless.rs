// End-to-end keyless verification against a synthetic Fulcio-style CA and
// Rekor-style log, fully offline. Uses one #[test] because trust-dir/home env
// vars are process-global.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use ed25519_dalek::pkcs8::EncodePublicKey as _;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use promptsign_core::bundle::{pae, verify_envelope, PAYLOAD_TYPE};
use promptsign_core::util::sha256_hex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, Utf8StringRef};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Encode, EncodePem, Length, Writer};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

struct IssuerExt(String);

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

fn spki_of_ed25519(vk: &ed25519_dalek::VerifyingKey) -> SubjectPublicKeyInfoOwned {
    use x509_cert::der::Decode;
    SubjectPublicKeyInfoOwned::from_der(vk.to_public_key_der().unwrap().as_bytes()).unwrap()
}

#[test]
fn keyless_verify_end_to_end() {
    // --- synthetic CA + leaf ---
    let ca_key = p256::ecdsa::SigningKey::from_slice(&[41u8; 32]).unwrap();
    let ca_name = Name::from_str("CN=promptsign test root,O=test").unwrap();
    let ca_spki = {
        use x509_cert::der::Decode;
        SubjectPublicKeyInfoOwned::from_der(
            ca_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
    };
    let ca_cert: Certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(3600 * 24 * 365)).unwrap(),
        ca_name.clone(),
        ca_spki,
        &ca_key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();

    let leaf_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut leaf_builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: ca_name.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        Validity::from_now(Duration::from_secs(600)).unwrap(),
        Name::from_str("CN=sigstore-intermediate").unwrap(),
        spki_of_ed25519(&leaf_key.verifying_key()),
        &ca_key,
    )
    .unwrap();

    leaf_builder
        .add_extension(&SubjectAltName(vec![GeneralName::Rfc822Name(
            Ia5String::new("alice@example.com").unwrap(),
        )]))
        .unwrap();
    leaf_builder
        .add_extension(&IssuerExt("https://accounts.example.com".to_string()))
        .unwrap();

    let leaf_cert: Certificate = leaf_builder.build::<p256::ecdsa::DerSignature>().unwrap();

    // --- envelope over a minimal manifest ---
    let manifest = json!({
        "schema": "promptsign/manifest/v1",
        "name": "acme/demo",
        "version": "1.0.0",
        "kind": "skill",
        "scope": "dir",
        "created": "2026-07-07T00:00:00.000Z",
        "files": []
    });
    let payload = serde_json::to_vec(&manifest).unwrap();
    let sig = leaf_key.sign(&pae(PAYLOAD_TYPE, &payload));
    let sig_b64 = BASE64_STANDARD.encode(sig.to_bytes());

    // --- synthetic Rekor log entry + SET ---
    let rekor_key = p256::ecdsa::SigningKey::from_slice(&[43u8; 32]).unwrap();
    let rekor_spki_der = rekor_key.verifying_key().to_public_key_der().unwrap();
    let log_id = sha256_hex(rekor_spki_der.as_bytes());
    let leaf_pem = leaf_cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .unwrap();
    let body = json!({
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": { "algorithm": "sha256", "value": sha256_hex(&payload) },
            "signatures": [ { "signature": sig_b64, "verifier": leaf_pem } ]
        }
    });
    let body_b64 = BASE64_STANDARD.encode(serde_json::to_vec(&body).unwrap());
    let integrated_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let canonical = format!(
        "{{\"body\":{},\"integratedTime\":{integrated_time},\"logID\":{},\"logIndex\":42}}",
        serde_json::to_string(&body_b64).unwrap(),
        serde_json::to_string(&log_id).unwrap()
    );
    let set: p256::ecdsa::Signature = rekor_key
        .sign_prehash(&Sha256::digest(canonical.as_bytes()))
        .unwrap();
    let set_b64 = BASE64_STANDARD.encode(set.to_der());

    // --- trust dir ---
    let trust = std::env::temp_dir().join(format!("pstrust-{}", std::process::id()));

    std::fs::create_dir_all(&trust).unwrap();
    std::fs::write(
        trust.join("fulcio.pem"),
        ca_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap(),
    )
    .unwrap();
    std::fs::write(
        trust.join("rekor.pub"),
        rekor_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap(),
    )
    .unwrap();
    std::env::set_var("PROMPTSIGN_TRUST_DIR", &trust);

    // --- bundle ---
    let bundle = json!({
        "schema": "promptsign/bundle/v1",
        "envelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": BASE64_STANDARD.encode(&payload),
            "signatures": [ { "keyid": "", "sig": sig_b64 } ]
        },
        "signer": {
            "scheme": "keyless",
            "identity": "alice@example.com",
            "issuer": "https://accounts.example.com",
            "certChain": [ BASE64_STANDARD.encode(leaf_cert.to_der().unwrap()) ]
        },
        "transparency": {
            "logId": log_id,
            "logIndex": 42,
            "integratedTime": integrated_time,
            "signedEntryTimestamp": set_b64,
            "body": body_b64
        }
    });

    // happy path
    let ok = verify_envelope(&bundle).expect("keyless bundle should verify");

    assert_eq!(ok.identity, "alice@example.com");
    assert_eq!(ok.issuer.as_deref(), Some("https://accounts.example.com"));
    assert_eq!(ok.manifest.name, "acme/demo");

    // tampered payload -> envelope signature failure
    let mut tampered = bundle.clone();
    let mut evil = manifest.clone();

    evil["name"] = json!("acme/evil");
    tampered["envelope"]["payload"] =
        json!(BASE64_STANDARD.encode(serde_json::to_vec(&evil).unwrap()));
    assert!(verify_envelope(&tampered)
        .unwrap_err()
        .contains("signature"));

    // identity display hint must match the certificate
    let mut spoofed = bundle.clone();

    spoofed["signer"]["identity"] = json!("anthropic-official@example.com");
    assert!(verify_envelope(&spoofed)
        .unwrap_err()
        .contains("does not match certificate identity"));

    // SET forged with a different log key -> fail
    let mut wrong_set = bundle.clone();
    let other_key = p256::ecdsa::SigningKey::from_slice(&[44u8; 32]).unwrap();
    let forged: p256::ecdsa::Signature = other_key
        .sign_prehash(&Sha256::digest(canonical.as_bytes()))
        .unwrap();

    wrong_set["transparency"]["signedEntryTimestamp"] =
        json!(BASE64_STANDARD.encode(forged.to_der()));
    assert!(verify_envelope(&wrong_set)
        .unwrap_err()
        .contains("signed entry timestamp"));

    // integration time outside cert validity -> fail
    let mut stale = bundle.clone();
    let old_time = integrated_time - 3600 * 24 * 30;
    let stale_canonical = format!(
        "{{\"body\":{},\"integratedTime\":{old_time},\"logID\":{},\"logIndex\":42}}",
        serde_json::to_string(&body_b64).unwrap(),
        serde_json::to_string(&log_id).unwrap()
    );
    let stale_set: p256::ecdsa::Signature = rekor_key
        .sign_prehash(&Sha256::digest(stale_canonical.as_bytes()))
        .unwrap();

    stale["transparency"]["integratedTime"] = json!(old_time);
    stale["transparency"]["signedEntryTimestamp"] =
        json!(BASE64_STANDARD.encode(stale_set.to_der()));
    assert!(verify_envelope(&stale)
        .unwrap_err()
        .contains("outside certificate validity"));

    // chain not anchored in the trust store -> fail
    let rogue_ca = p256::ecdsa::SigningKey::from_slice(&[45u8; 32]).unwrap();
    let rogue_name = Name::from_str("CN=rogue root").unwrap();
    let rogue_spki = {
        use x509_cert::der::Decode;
        SubjectPublicKeyInfoOwned::from_der(
            rogue_ca
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap()
    };
    let _rogue_cert: Certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(9u32),
        Validity::from_now(Duration::from_secs(3600)).unwrap(),
        rogue_name.clone(),
        rogue_spki,
        &rogue_ca,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    let mut rogue_leaf_builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: rogue_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(10u32),
        Validity::from_now(Duration::from_secs(600)).unwrap(),
        Name::from_str("CN=rogue-leaf").unwrap(),
        spki_of_ed25519(&leaf_key.verifying_key()),
        &rogue_ca,
    )
    .unwrap();

    rogue_leaf_builder
        .add_extension(&SubjectAltName(vec![GeneralName::Rfc822Name(
            Ia5String::new("alice@example.com").unwrap(),
        )]))
        .unwrap();
    rogue_leaf_builder
        .add_extension(&IssuerExt("https://accounts.example.com".to_string()))
        .unwrap();

    let rogue_leaf: Certificate = rogue_leaf_builder
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
    let mut rogue_bundle = bundle.clone();

    rogue_bundle["signer"]["certChain"] = Value::Array(vec![json!(
        BASE64_STANDARD.encode(rogue_leaf.to_der().unwrap())
    )]);
    assert!(verify_envelope(&rogue_bundle)
        .unwrap_err()
        .contains("does not terminate at a trusted root"));

    std::env::remove_var("PROMPTSIGN_TRUST_DIR");

    let _ = std::fs::remove_dir_all(&trust);
}
