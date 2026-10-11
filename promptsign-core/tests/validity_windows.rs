// Validity windows (spec/07 §4): a CA or log entry's `validFor` bounds the time
// a signature was made. Keyless signatures are timed by the log's
// integratedTime, certificate-mode ones by the current time.

use promptsign_core::sigstore_bundle::verify_sigstore_bundle;
use promptsign_core::trustroot::Root;
use promptsign_core::util::parse_iso8601;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

// integratedTime of the two upstream keyless fixtures.
const V1_1_0: &str = "upstream-v1.1.0-sigstore/model.sig"; // 2025-10-10
const V1_0_0: &str = "upstream-v1.0.0-sigstore/model.sig"; // 2025-05-03

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_json(p: PathBuf) -> Value {
    serde_json::from_slice(&fs::read(&p).unwrap()).unwrap()
}

fn oms(rel: &str) -> Value {
    read_json(manifest_dir().join("tests/fixtures/foreign/oms").join(rel))
}

fn now() -> i64 {
    parse_iso8601("2026-10-04T00:00:00Z").unwrap()
}

/// The public trusted_root.json fixture: CA[0] is the retired 2021 CA,
/// CA[1] the current one, tlogs[0] the Rekor v1 key.
fn public_doc() -> Value {
    read_json(manifest_dir().join("tests/fixtures/sigstore/trusted_root.json"))
}

fn verifies(doc: &Value, fixture: &str) -> Result<(), String> {
    let root = Root::from_trusted_root("org", doc)?;

    verify_sigstore_bundle(&oms(fixture), &[root], now()).map(|_| ())
}

#[test]
fn the_fixture_windows_hold_for_both_signatures() {
    let doc = public_doc();

    verifies(&doc, V1_1_0).unwrap();
    verifies(&doc, V1_0_0).unwrap();
}

#[test]
fn a_ca_window_that_ended_before_the_entry_fails() {
    let mut doc = public_doc();

    doc["certificateAuthorities"][1]["validFor"]["end"] = json!("2025-06-01T00:00:00Z");

    let err = verifies(&doc, V1_1_0).unwrap_err();

    assert!(err.contains("validity window"), "{err}");
    verifies(&doc, V1_0_0).expect("signed before the CA's window ended");
}

#[test]
fn a_ca_window_that_starts_after_the_entry_fails() {
    let mut doc = public_doc();

    doc["certificateAuthorities"][1]["validFor"]["start"] = json!("2025-06-01T00:00:00Z");

    let err = verifies(&doc, V1_0_0).unwrap_err();

    assert!(err.contains("validity window"), "{err}");
    verifies(&doc, V1_1_0).expect("signed after the CA's window started");
}

#[test]
fn a_log_window_that_ended_before_the_entry_fails() {
    let mut doc = public_doc();

    doc["tlogs"][0]["publicKey"]["validFor"]["end"] = json!("2025-06-01T00:00:00Z");

    let err = verifies(&doc, V1_1_0).unwrap_err();

    assert!(err.contains("validity window"), "{err}");
    verifies(&doc, V1_0_0).expect("witnessed before the log key was retired");
}

#[test]
fn the_same_ca_in_two_entries_holds_if_either_window_does() {
    let mut doc = public_doc();
    let mut retired = doc["certificateAuthorities"][1].clone();

    retired["validFor"] = json!({ "start": "2022-04-13T20:06:15Z", "end": "2025-06-01T00:00:00Z" });
    doc["certificateAuthorities"][1]["validFor"] = json!({ "start": "2025-06-01T00:00:00Z" });
    doc["certificateAuthorities"]
        .as_array_mut()
        .unwrap()
        .push(retired);

    verifies(&doc, V1_0_0).unwrap();
    verifies(&doc, V1_1_0).unwrap();
}

fn nvidia_doc(valid_for: Value) -> Value {
    let pem =
        fs::read(manifest_dir().join("tests/fixtures/foreign/oms/nvidia-agent-root-cert.pem"))
            .unwrap();
    let mut doc = Root::ca_only("nvidia", &pem).unwrap().to_trusted_root();

    doc["certificateAuthorities"][0]["validFor"] = valid_for;
    doc
}

#[test]
fn certificate_mode_checks_the_ca_window_at_the_current_time() {
    let bundle = oms("nvidia-earth2studio-discover/skill.oms.sig");
    let check = |valid_for: Value| {
        let root = Root::from_trusted_root("nvidia", &nvidia_doc(valid_for)).unwrap();

        verify_sigstore_bundle(&bundle, &[root], now()).map(|_| ())
    };

    check(json!({ "start": "2026-01-01T00:00:00Z" })).unwrap();

    let ended = check(json!({ "start": "2026-01-01T00:00:00Z", "end": "2026-09-01T00:00:00Z" }))
        .unwrap_err();

    assert!(ended.contains("validity window"), "{ended}");

    let not_yet = check(json!({ "start": "2027-01-01T00:00:00Z" })).unwrap_err();

    assert!(not_yet.contains("validity window"), "{not_yet}");
}

#[test]
fn windows_survive_a_round_trip() {
    let mut doc = public_doc();

    doc["certificateAuthorities"][1]["validFor"]["end"] = json!("2025-06-01T00:00:00Z");
    doc["tlogs"][0]["publicKey"]["validFor"]["end"] = json!("2026-01-01T00:00:00Z");

    let back = Root::from_trusted_root("org", &doc)
        .unwrap()
        .to_trusted_root();

    assert!(
        verifies(&back, V1_1_0).is_err(),
        "the CA window was dropped"
    );
    verifies(&back, V1_0_0).unwrap();
    assert_eq!(
        back["tlogs"][0]["publicKey"]["validFor"]["end"],
        "2026-01-01T00:00:00Z"
    );
}
