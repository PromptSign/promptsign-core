// Sigstore bundle verification against the root registry, using real bundles
// from tests/fixtures/foreign (provenance in its README). Every root is passed
// in explicitly, so these tests touch no process-global environment.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use promptsign_core::sigstore_bundle::{is_sigstore_bundle, verify_sigstore_bundle, SignerMode};
use promptsign_core::trustroot::{self, Root, DEFAULT_ROOT};
use promptsign_core::util::parse_iso8601;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const NVIDIA_ROOT_FP: &str = "6f1bb875b77aea3fc878a7a3237497235c53657601375c0ef4bdcde69e843782";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn oms(rel: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures/foreign/oms").join(rel)
}

fn read_json(p: PathBuf) -> Value {
    serde_json::from_slice(&fs::read(&p).unwrap()).unwrap()
}

fn now() -> i64 {
    parse_iso8601("2026-10-04T00:00:00Z").unwrap()
}

fn sigstore_public() -> Root {
    let trust = manifest_dir().join("../trust");

    Root::from_pem(
        DEFAULT_ROOT,
        &fs::read(trust.join("fulcio.pem")).unwrap(),
        &fs::read_to_string(trust.join("rekor.pub")).unwrap(),
    )
    .unwrap()
}

fn nvidia_root() -> Root {
    Root::ca_only(
        "nvidia",
        &fs::read(oms("nvidia-agent-root-cert.pem")).unwrap(),
    )
    .unwrap()
}

fn upstream_ca_root() -> Root {
    Root::ca_only(
        "upstream-test",
        &fs::read(oms("upstream-certificate-ca.pem")).unwrap(),
    )
    .unwrap()
}

fn statement(payload: &[u8]) -> Value {
    serde_json::from_slice(payload).unwrap()
}

#[test]
fn detects_sigstore_bundles_by_media_type() {
    assert!(is_sigstore_bundle(&read_json(oms(
        "upstream-v1.1.0-sigstore/model.sig"
    ))));
    assert!(is_sigstore_bundle(&read_json(oms(
        "nvidia-earth2studio-discover/skill.oms.sig"
    ))));
    assert!(!is_sigstore_bundle(
        &serde_json::json!({ "schema": "promptsign/bundle/v1" })
    ));
}

#[test]
fn keyless_bundles_verify_against_the_public_root() {
    for (fixture, time) in [
        ("upstream-v1.1.0-sigstore/model.sig", 1760062340),
        ("upstream-v1.0.0-sigstore/model.sig", 1746236086),
    ] {
        let v = verify_sigstore_bundle(&read_json(oms(fixture)), &[sigstore_public()], now())
            .unwrap_or_else(|e| panic!("{fixture}: {e}"));

        assert_eq!(v.mode, SignerMode::Keyless, "{fixture}");
        assert_eq!(v.identity, "stefanb@us.ibm.com");
        assert_eq!(v.issuer, "https://sigstore.verify.ibm.com/oauth2");
        assert_eq!(v.root, DEFAULT_ROOT);
        assert_eq!(v.integrated_time, Some(time));
        assert_eq!(v.payload_type, "application/vnd.in-toto+json");
        assert_eq!(
            statement(&v.payload)["predicateType"],
            "https://model_signing/signature/v1.0"
        );
    }
}

#[test]
fn certificate_mode_verifies_against_a_ca_root() {
    let bundle = read_json(oms("nvidia-earth2studio-discover/skill.oms.sig"));
    let v = verify_sigstore_bundle(&bundle, &[sigstore_public(), nvidia_root()], now()).unwrap();

    assert_eq!(v.mode, SignerMode::Certificate);
    assert_eq!(v.root, "nvidia");
    assert_eq!(v.root_fingerprint, NVIDIA_ROOT_FP);
    assert_eq!(v.issuer, format!("x509:sha256:{NVIDIA_ROOT_FP}"));
    // RFC 4514 string order: most specific first. Policy rules glob on this.
    assert_eq!(
        v.identity,
        "CN=NVIDIA Agent Skills Signing 001,O=NVIDIA Corporation,C=US"
    );
    assert_eq!(v.integrated_time, None);
    assert_eq!(
        statement(&v.payload)["subject"][0]["name"],
        "earth2studio-discover"
    );

    let up = verify_sigstore_bundle(
        &read_json(oms("upstream-v1.1.0-certificate/model.sig")),
        &[upstream_ca_root()],
        now(),
    )
    .unwrap();

    assert_eq!(up.mode, SignerMode::Certificate);
    assert_eq!(up.root, "upstream-test");
}

#[test]
fn certificate_mode_names_the_root_it_does_not_trust() {
    let bundle = read_json(oms("nvidia-earth2studio-discover/skill.oms.sig"));
    let err = verify_sigstore_bundle(&bundle, &[sigstore_public()], now()).unwrap_err();

    assert!(err.contains("NVIDIA Agent Capabilities CA"), "{err}");
    assert!(err.contains("trust"), "{err}");

    let err = verify_sigstore_bundle(&bundle, &[upstream_ca_root()], now()).unwrap_err();

    assert!(err.contains("NVIDIA Agent Capabilities CA"), "{err}");
}

#[test]
fn certificate_mode_checks_validity_at_the_current_time() {
    let bundle = read_json(oms("nvidia-earth2studio-discover/skill.oms.sig"));
    let later = parse_iso8601("2029-01-01T00:00:00Z").unwrap();
    let err = verify_sigstore_bundle(&bundle, &[nvidia_root()], later).unwrap_err();

    assert!(err.contains("not valid"), "{err}");
}

#[test]
fn tampered_payload_fails_in_both_modes() {
    for (fixture, roots) in [
        (
            "upstream-v1.1.0-sigstore/model.sig",
            vec![sigstore_public()],
        ),
        (
            "nvidia-earth2studio-discover/skill.oms.sig",
            vec![nvidia_root()],
        ),
    ] {
        let mut bundle = read_json(oms(fixture));
        let payload = BASE64_STANDARD
            .decode(bundle["dsseEnvelope"]["payload"].as_str().unwrap())
            .unwrap();
        let tampered = String::from_utf8(payload)
            .unwrap()
            .replacen("\"sha256\"", "\"sha256\" ", 1);

        bundle["dsseEnvelope"]["payload"] = Value::String(BASE64_STANDARD.encode(tampered));
        assert!(
            verify_sigstore_bundle(&bundle, &roots, now()).is_err(),
            "{fixture} verified after tampering"
        );
    }
}

#[test]
fn a_swapped_leaf_fails() {
    let mut bundle = read_json(oms("nvidia-earth2studio-discover/skill.oms.sig"));
    let other = read_json(oms("upstream-v1.1.0-certificate/model.sig"));

    bundle["verificationMaterial"]["x509CertificateChain"]["certificates"][0] =
        other["verificationMaterial"]["x509CertificateChain"]["certificates"][0].clone();
    assert!(verify_sigstore_bundle(&bundle, &[nvidia_root(), upstream_ca_root()], now()).is_err());
}

#[test]
fn keyless_needs_the_log_that_witnessed_the_entry() {
    let trust = manifest_dir().join("../trust");
    let wrong_log = Root::from_pem(
        "other-log",
        &fs::read(trust.join("fulcio.pem")).unwrap(),
        &fs::read_to_string(oms("key-skill.ec.pub")).unwrap(),
    )
    .unwrap();
    let bundle = read_json(oms("upstream-v1.1.0-sigstore/model.sig"));
    let err = verify_sigstore_bundle(&bundle, &[wrong_log], now()).unwrap_err();

    assert!(err.contains("log"), "{err}");
}

#[test]
fn a_ca_only_root_never_accepts_a_keyless_certificate() {
    // The Fulcio CA added as a certificate-mode root: the short-lived leaf
    // must not verify without the log that dates it.
    let trust = manifest_dir().join("../trust");
    let fulcio_as_ca =
        Root::ca_only("fulcio-ca", &fs::read(trust.join("fulcio.pem")).unwrap()).unwrap();
    let bundle = read_json(oms("upstream-v1.1.0-sigstore/model.sig"));

    assert!(verify_sigstore_bundle(&bundle, &[fulcio_as_ca], now()).is_err());
}

#[test]
fn unsupported_bundles_fail_with_a_reason() {
    let key_mode = read_json(oms("key-skill/skill.oms.sig"));
    let err = verify_sigstore_bundle(&key_mode, &[sigstore_public()], now()).unwrap_err();

    assert!(err.contains("public-key"), "{err}");

    // PromptSign verifies bundles from model_signing 1.0 and later; an earlier
    // bundle is rejected.
    let legacy = read_json(oms("upstream-v0.2.0-certificate/model.sig"));

    assert!(verify_sigstore_bundle(&legacy, &[upstream_ca_root()], now()).is_err());
}

#[test]
fn the_public_sigstore_trusted_root_parses() {
    let doc = read_json(manifest_dir().join("tests/fixtures/sigstore/trusted_root.json"));
    let root = Root::from_trusted_root("from-tuf", &doc).unwrap();
    let pinned = sigstore_public();

    // Rekor v1 (P-256) is usable; the Ed25519 Rekor v2 log is skipped.
    assert_eq!(root.log_ids(), pinned.log_ids());
    assert!(!root.is_ca_only());

    let bundle = read_json(oms("upstream-v1.1.0-sigstore/model.sig"));
    let v = verify_sigstore_bundle(&bundle, &[root], now()).unwrap();

    assert_eq!(v.root, "from-tuf");
}

#[test]
fn trusted_root_documents_round_trip() {
    for root in [sigstore_public(), nvidia_root()] {
        let back = Root::from_trusted_root(&root.name, &root.to_trusted_root()).unwrap();

        assert_eq!(back.fingerprint, root.fingerprint);
        assert_eq!(back.log_ids(), root.log_ids());
        assert_eq!(back.is_ca_only(), root.is_ca_only());
    }
}

#[test]
fn registry_add_list_remove() {
    let dir = std::env::temp_dir().join(format!("ps-registry-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let trust = manifest_dir().join("../trust");

    fs::copy(trust.join("fulcio.pem"), dir.join("fulcio.pem")).unwrap();
    fs::copy(trust.join("rekor.pub"), dir.join("rekor.pub")).unwrap();

    let names = |dir: &PathBuf| -> Vec<String> {
        trustroot::load_registry_from(dir)
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect()
    };

    assert_eq!(names(&dir), vec![DEFAULT_ROOT.to_string()]);

    let pem = fs::read(oms("nvidia-agent-root-cert.pem")).unwrap();
    let added = trustroot::add_ca_root(&dir, "nvidia", &pem).unwrap();

    assert_eq!(added.fingerprint, NVIDIA_ROOT_FP);
    assert!(dir.join("roots/nvidia.json").exists());
    assert_eq!(
        names(&dir),
        vec![DEFAULT_ROOT.to_string(), "nvidia".to_string()]
    );

    let reloaded = trustroot::load_registry_from(&dir).unwrap();

    assert!(reloaded[1].is_ca_only());
    assert_eq!(reloaded[1].fingerprint, NVIDIA_ROOT_FP);

    assert!(
        trustroot::add_ca_root(&dir, "nvidia", &pem).is_err(),
        "duplicate name"
    );
    assert!(
        trustroot::add_ca_root(&dir, DEFAULT_ROOT, &pem).is_err(),
        "reserved name"
    );
    assert!(
        trustroot::add_ca_root(&dir, "../evil", &pem).is_err(),
        "path in name"
    );
    assert!(
        trustroot::add_ca_root(&dir, "empty", b"not a pem").is_err(),
        "no certificate"
    );
    assert!(
        trustroot::remove_root(&dir, DEFAULT_ROOT).is_err(),
        "built-in root"
    );

    trustroot::remove_root(&dir, "nvidia").unwrap();
    assert_eq!(names(&dir), vec![DEFAULT_ROOT.to_string()]);
    assert!(
        trustroot::remove_root(&dir, "nvidia").is_err(),
        "already removed"
    );

    let _ = fs::remove_dir_all(&dir);
}
