// Writes the shared trust-root fixtures (spec/07 §6) that every implementation
// runs its conformance checks on. Ignored by default; regenerate with
//
//   PROMPTSIGN_FIXTURES_OUT=../../spec/test/fixtures/trust-roots \
//     cargo test --test conformance_fixtures -- --ignored
//
// Every certificate, log entry and bundle carries a fixed time, and the mock's
// signatures are deterministic, so a rerun writes identical bytes. Before
// writing, the generator checks each bundle does what the fixture README says.

mod common;

use common::{temp_dir, MockSigstore};
use promptsign_core::trustbundle::{check_trust_bundle, store_trust_bundle};
use promptsign_core::util::parse_iso8601;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const GH: &str = "https://token.actions.githubusercontent.com";
const PUBLISH: &str = "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main";
const MALLORY: &str =
    "https://github.com/mallory/trust/.github/workflows/publish.yml@refs/heads/main";
const ALICE: &str = "alice@acme.test";
const ACME_SSO: &str = "https://sso.acme.test";

fn at(rfc3339: &str) -> i64 {
    parse_iso8601(rfc3339).unwrap()
}

/// The organization's current deployment, which also signs its trust bundle.
fn prod() -> MockSigstore {
    MockSigstore::new_valid(
        30,
        "acme prod fulcio",
        at("2026-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
}

/// A deployment the organization retired on 2026-07-01 by ending its CA's
/// validFor window.
fn old() -> MockSigstore {
    MockSigstore::new_valid(
        40,
        "acme old fulcio",
        at("2025-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
}

fn roots() -> Value {
    let mut old_root = old().trusted_root();

    old_root["certificateAuthorities"][0]["validFor"] =
        json!({ "start": "2025-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z" });
    json!({ "prod": prod().trusted_root(), "old": old_root })
}

fn bundle(version: u64, issued: &str, expires: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": version,
        "issued": issued,
        "expires": expires,
        "roots": roots(),
        "signers": [{ "identity": PUBLISH, "issuer": GH, "root": "prod" }],
    }))
    .unwrap();

    bytes.push(b'\n');
    bytes
}

/// A bundle and its sidecar, signed through acme's prod deployment as
/// `identity` at `signed`.
struct Signed {
    bytes: Vec<u8>,
    sidecar: Value,
}

fn signed_bundle(bytes: Vec<u8>, identity: &str, signed: &str) -> Signed {
    let sidecar = prod().sign_file_at("trust-bundle.json", &bytes, identity, GH, at(signed));

    Signed { bytes, sidecar }
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();

    bytes.push(b'\n');
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn write_bundle(out: &Path, dir: &str, b: &Signed) {
    let dir = out.join("bundles").join(dir);

    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("trust-bundle.json"), &b.bytes).unwrap();
    write_json(&dir.join("trust-bundle.json.psig.json"), &b.sidecar);
}

fn write_artifact(out: &Path, file: &str, bytes: &[u8], deployment: &MockSigstore, signed: &str) {
    let dir = out.join("artifacts");
    let sidecar = deployment.sign_file_at(file, bytes, ALICE, ACME_SSO, at(signed));

    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(file), bytes).unwrap();
    write_json(&dir.join(format!("{file}.psig.json")), &sidecar);
}

#[test]
#[ignore = "writes fixtures; run with PROMPTSIGN_FIXTURES_OUT set"]
fn write_trust_root_fixtures() {
    let out = std::env::var_os("PROMPTSIGN_FIXTURES_OUT")
        .map(std::path::PathBuf::from)
        .expect("set PROMPTSIGN_FIXTURES_OUT to the fixture directory");
    let now = common::now();
    let v1 = signed_bundle(
        bundle(1, "2026-10-01T00:00:00Z", "2126-01-01T00:00:00Z"),
        PUBLISH,
        "2026-10-01T00:00:00Z",
    );
    let v2 = signed_bundle(
        bundle(2, "2026-10-02T00:00:00Z", "2126-01-01T00:00:00Z"),
        PUBLISH,
        "2026-10-02T00:00:00Z",
    );
    let unlisted = signed_bundle(
        bundle(2, "2026-10-02T00:00:00Z", "2126-01-01T00:00:00Z"),
        MALLORY,
        "2026-10-02T00:00:00Z",
    );
    let stale = signed_bundle(
        bundle(1, "2026-09-01T00:00:00Z", "2026-09-30T00:00:00Z"),
        PUBLISH,
        "2026-09-01T00:00:00Z",
    );

    // The README's claims, checked against the core before anything is written.
    let trust = temp_dir("fixtures-check");
    let check = |b: &Signed| check_trust_bundle(&trust, "acme", &b.bytes, &b.sidecar, now);
    let store = |b: &Signed| {
        let sidecar = serde_json::to_vec(&b.sidecar).unwrap();

        store_trust_bundle(&trust, "acme", &b.bytes, &sidecar, None).unwrap();
    };

    assert!(
        check(&unlisted).is_err(),
        "an unlisted signer must not install"
    );
    assert!(check(&stale).is_err(), "an expired bundle must not install");
    check(&v1).unwrap();
    store(&v1);
    check(&v2).unwrap();
    assert!(
        check(&unlisted).is_err(),
        "an unlisted signer must not update"
    );
    store(&v2);
    assert!(check(&v1).is_err(), "a lower version must not update");
    let _ = fs::remove_dir_all(&trust);

    let _ = fs::remove_dir_all(out.join("bundles"));
    let _ = fs::remove_dir_all(out.join("artifacts"));
    write_bundle(&out, "acme-v1", &v1);
    write_bundle(&out, "acme-v2", &v2);
    write_bundle(&out, "acme-v2-unlisted-signer", &unlisted);
    write_bundle(&out, "acme-stale", &stale);
    write_artifact(
        &out,
        "prod-signed.txt",
        b"signed through acme's prod Fulcio and log\n",
        &prod(),
        "2026-10-01T06:00:00Z",
    );
    write_artifact(
        &out,
        "before-retirement.txt",
        b"signed through acme's old Fulcio before its CA was retired\n",
        &old(),
        "2026-06-01T00:00:00Z",
    );
    write_artifact(
        &out,
        "after-retirement.txt",
        b"signed through acme's old Fulcio after its CA was retired\n",
        &old(),
        "2026-08-01T00:00:00Z",
    );
}
