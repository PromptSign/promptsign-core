// Trust bundles (spec/07 §5): an organization's roots in one signed,
// versioned document, installed once with the user's confirmation and kept
// current only by signers the installed version names.

mod common;

use common::{now, temp_dir, MockSigstore};
use promptsign_core::keyless::verify_keyless_with;
use promptsign_core::trustbundle::{
    check_trust_bundle, installed_bundles, remove_trust_bundle, store_trust_bundle, Check,
};
use promptsign_core::trustroot::{self, DEFAULT_ROOT};
use promptsign_core::util::format_iso8601;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const GH: &str = "https://token.actions.githubusercontent.com";
const PUBLISH: &str = "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main";
const ROTATED: &str =
    "https://github.com/acme/trust/.github/workflows/publish-v2.yml@refs/heads/main";

fn public() -> MockSigstore {
    MockSigstore::new(10, "public good")
}

fn org() -> MockSigstore {
    MockSigstore::new(20, "acme fulcio")
}

/// A trust directory whose built-in root is the `public()` deployment.
fn trust_dir() -> PathBuf {
    let dir = temp_dir("trust-bundle");
    let p = public();

    fs::write(dir.join("fulcio.pem"), p.fulcio_pem()).unwrap();
    fs::write(dir.join("rekor.pub"), p.rekor_pem()).unwrap();
    dir
}

fn signer(identity: &str, root: &str) -> Value {
    json!({ "identity": identity, "issuer": GH, "root": root })
}

fn doc(version: u64, expires_in: i64, roots: Value, signers: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": version,
        "issued": format_iso8601(now() - 3600),
        "expires": format_iso8601(now() + expires_in),
        "roots": roots,
        "signers": signers,
    }))
    .unwrap()
}

fn org_roots() -> Value {
    json!({ "prod": org().trusted_root() })
}

fn signed_by(by: &MockSigstore, identity: &str, bytes: &[u8]) -> Value {
    by.sign_file("trust-bundle.json", bytes, identity, GH)
}

fn install(dir: &Path, bytes: &[u8], sidecar: &Value) -> Result<Check, String> {
    let check = check_trust_bundle(dir, "acme", bytes, sidecar, now())?;

    if !check.unchanged {
        store_trust_bundle(
            dir,
            "acme",
            bytes,
            &serde_json::to_vec(sidecar).unwrap(),
            Some("https://trust.acme.test/trust-bundle.json"),
        )?;
    }
    Ok(check)
}

fn root_names(dir: &Path) -> Vec<String> {
    trustroot::load_registry_from(dir)
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect()
}

fn v1(dir: &Path) {
    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);

    install(dir, &bytes, &signed_by(&public(), PUBLISH, &bytes)).unwrap();
}

#[test]
fn a_bundle_signed_under_the_public_root_installs_and_its_roots_verify() {
    let dir = trust_dir();
    let artifact = org().sign_payload(b"{}", "alice@acme.test", "https://sso.acme.test");
    let before = trustroot::load_registry_from(&dir).unwrap();

    assert!(
        verify_keyless_with(&artifact, &before).is_err(),
        "not trusted yet"
    );

    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let check = install(&dir, &bytes, &signed_by(&public(), PUBLISH, &bytes)).unwrap();

    assert!(!check.update);
    assert_eq!(check.signer.identity, PUBLISH);
    assert_eq!(check.signer.root, DEFAULT_ROOT);
    assert_eq!(check.bundle.version, 1);
    assert_eq!(root_names(&dir), vec![DEFAULT_ROOT, "acme/prod"]);

    let after = trustroot::load_registry_from(&dir).unwrap();
    let v = verify_keyless_with(&artifact, &after).unwrap();

    assert_eq!(v.root, "acme/prod");
    assert_eq!(v.identity, "alice@acme.test");
}

#[test]
fn installing_needs_a_signer_the_bundle_lists() {
    let dir = trust_dir();
    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &bytes, &signed_by(&public(), ROTATED, &bytes)).unwrap_err();

    assert!(err.contains("not a signer"), "{err}");
}

#[test]
fn the_signature_must_cover_these_bytes() {
    let dir = trust_dir();
    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let other = doc(1, 3600, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &bytes, &signed_by(&public(), PUBLISH, &other)).unwrap_err();

    assert!(err.contains("modified"), "{err}");
}

#[test]
fn updates_need_a_higher_version() {
    let dir = trust_dir();

    v1(&dir);

    let v2 = doc(2, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let v2_sig = signed_by(&public(), PUBLISH, &v2);
    let check = install(&dir, &v2, &v2_sig).unwrap();

    assert!(check.update);
    assert_eq!(check.bundle.version, 2);
    assert!(install(&dir, &v2, &v2_sig).unwrap().unchanged);

    let again = doc(2, 7200, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &again, &signed_by(&public(), PUBLISH, &again)).unwrap_err();

    assert!(err.contains("rollback"), "{err}");

    let old = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &old, &signed_by(&public(), PUBLISH, &old)).unwrap_err();

    assert!(err.contains("rollback"), "{err}");
}

#[test]
fn signers_rotate_only_through_the_installed_version() {
    let dir = trust_dir();

    v1(&dir);

    // A version listing a new signer, signed by that new signer, is not
    // accepted: v1 does not name it.
    let hijack = doc(2, 86400, org_roots(), vec![signer(ROTATED, DEFAULT_ROOT)]);
    let err = install(&dir, &hijack, &signed_by(&public(), ROTATED, &hijack)).unwrap_err();

    assert!(err.contains("not a signer"), "{err}");

    // The current signer introduces it, then it takes over.
    let v2 = doc(
        2,
        86400,
        org_roots(),
        vec![signer(PUBLISH, DEFAULT_ROOT), signer(ROTATED, DEFAULT_ROOT)],
    );

    install(&dir, &v2, &signed_by(&public(), PUBLISH, &v2)).unwrap();

    let v3 = doc(3, 86400, org_roots(), vec![signer(ROTATED, DEFAULT_ROOT)]);

    install(&dir, &v3, &signed_by(&public(), ROTATED, &v3)).unwrap();

    let v4 = doc(4, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &v4, &signed_by(&public(), PUBLISH, &v4)).unwrap_err();

    assert!(
        err.contains("not a signer"),
        "the retired signer was dropped in v3: {err}"
    );
}

#[test]
fn a_signer_may_chain_to_a_root_the_bundle_carries() {
    let dir = trust_dir();
    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, "prod")]);
    let check = install(&dir, &bytes, &signed_by(&org(), PUBLISH, &bytes)).unwrap();

    assert_eq!(check.signer.root, "acme/prod");

    let v2 = doc(2, 86400, org_roots(), vec![signer(PUBLISH, "prod")]);

    install(&dir, &v2, &signed_by(&org(), PUBLISH, &v2)).unwrap();

    // The same identity under the public root is not that signer.
    let v3 = doc(3, 86400, org_roots(), vec![signer(PUBLISH, "prod")]);
    let err = install(&dir, &v3, &signed_by(&public(), PUBLISH, &v3)).unwrap_err();

    assert!(err.contains("not a signer"), "{err}");
}

#[test]
fn an_expired_bundle_is_refused_and_an_installed_one_goes_stale() {
    let dir = trust_dir();
    let expired = doc(1, -60, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &expired, &signed_by(&public(), PUBLISH, &expired)).unwrap_err();

    assert!(err.contains("expired"), "{err}");

    v1(&dir);

    let fresh = installed_bundles(&dir, now()).unwrap();

    assert_eq!(fresh.len(), 1);
    assert!(!fresh[0].stale);
    assert_eq!(
        fresh[0].source.as_deref(),
        Some("https://trust.acme.test/trust-bundle.json")
    );

    let later = installed_bundles(&dir, now() + 2 * 86400).unwrap();

    assert!(later[0].stale, "past its expiry");

    let roots = trustroot::load_registry_from(&dir).unwrap();

    assert!(roots[1].expires.is_some());
}

#[test]
fn a_stored_bundle_is_reverified_on_every_load() {
    let dir = trust_dir();

    v1(&dir);

    let stored = dir.join("bundles/acme/trust-bundle.json");
    let mut bytes = fs::read(&stored).unwrap();

    bytes.extend_from_slice(b" ");
    fs::write(&stored, bytes).unwrap();

    assert!(installed_bundles(&dir, now()).is_err());
    assert!(trustroot::load_registry_from(&dir).is_err());
}

#[test]
fn a_root_already_trusted_under_another_name_is_refused() {
    let dir = trust_dir();

    trustroot::add_trusted_root(&dir, "acme-by-hand", &org().trusted_root()).unwrap();

    let bytes = doc(1, 86400, org_roots(), vec![signer(PUBLISH, DEFAULT_ROOT)]);
    let err = install(&dir, &bytes, &signed_by(&public(), PUBLISH, &bytes)).unwrap_err();

    assert!(err.contains("already trusted"), "{err}");
}

#[test]
fn removing_a_bundle_removes_its_roots() {
    let dir = trust_dir();

    v1(&dir);
    remove_trust_bundle(&dir, "acme").unwrap();

    assert_eq!(root_names(&dir), vec![DEFAULT_ROOT]);
    assert!(remove_trust_bundle(&dir, "acme").is_err());
}

#[test]
fn malformed_documents_are_rejected() {
    let dir = trust_dir();
    let base = || -> Value {
        serde_json::from_slice(&doc(
            1,
            86400,
            org_roots(),
            vec![signer(PUBLISH, DEFAULT_ROOT)],
        ))
        .unwrap()
    };
    let cases: Vec<(&str, Value)> = vec![
        ("schema", {
            let mut d = base();
            d["schema"] = json!("promptsign/trust-bundle/v0");
            d
        }),
        ("version", {
            let mut d = base();
            d["version"] = json!(0);
            d
        }),
        ("roots", {
            let mut d = base();
            d["roots"] = json!({});
            d
        }),
        ("root name", {
            let mut d = base();
            d["roots"] = json!({ "Prod/1": org().trusted_root() });
            d
        }),
        ("signers", {
            let mut d = base();
            d["signers"] = json!([]);
            d
        }),
        ("signer root", {
            let mut d = base();
            d["signers"] = json!([signer(PUBLISH, "staging")]);
            d
        }),
        ("expires", {
            let mut d = base();
            d["expires"] = d["issued"].clone();
            d
        }),
    ];

    for (what, d) in cases {
        let bytes = serde_json::to_vec(&d).unwrap();

        assert!(
            install(&dir, &bytes, &signed_by(&public(), PUBLISH, &bytes)).is_err(),
            "{what} should be rejected"
        );
    }
}
