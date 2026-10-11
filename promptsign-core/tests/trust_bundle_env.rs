// A signature from an installed trust bundle's root, verified the way the CLI
// does it: through verify_target, the user's registry and policy. Covers the
// stale-bundle finding (spec/07 §5.6). One #[test] because PROMPTSIGN_HOME is
// process-global.

mod common;

use common::{now, temp_dir, MockSigstore};
use promptsign_core::trustbundle::{check_user_trust_bundle, store_trust_bundle};
use promptsign_core::trustroot::{user_trust_dir, DEFAULT_ROOT};
use promptsign_core::util::format_iso8601;
use promptsign_core::verify::{verify_target, VerifyOptions, VerifyResult};
use serde_json::json;
use std::fs;

const GH: &str = "https://token.actions.githubusercontent.com";
const PUBLISH: &str = "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main";

fn verify(path: &std::path::Path) -> VerifyResult {
    verify_target(path.to_str().unwrap(), &VerifyOptions::default()).unwrap()
}

fn stale_finding(r: &VerifyResult) -> Option<String> {
    r.findings
        .iter()
        .find(|f| f.message.contains("trust bundle") && f.message.contains("expired"))
        .map(|f| f.level.clone())
}

#[test]
fn a_stale_bundle_warns_by_default_and_fails_when_policy_says_so() {
    let home = temp_dir("trust-bundle-env");
    let public = MockSigstore::new(10, "public good");
    let org = MockSigstore::new(20, "acme fulcio");

    std::env::set_var("PROMPTSIGN_HOME", &home);
    std::env::remove_var("PROMPTSIGN_TRUST_DIR");
    std::env::remove_var("PROMPTSIGN_POLICY");
    fs::create_dir_all(user_trust_dir()).unwrap();
    fs::write(user_trust_dir().join("fulcio.pem"), public.fulcio_pem()).unwrap();
    fs::write(user_trust_dir().join("rekor.pub"), public.rekor_pem()).unwrap();

    let bundle = serde_json::to_vec_pretty(&json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": 1,
        "issued": format_iso8601(now() - 3600),
        "expires": format_iso8601(now() + 3),
        "roots": { "prod": org.trusted_root() },
        "signers": [{ "identity": PUBLISH, "issuer": GH, "root": DEFAULT_ROOT }],
    }))
    .unwrap();
    let sidecar = public.sign_file("trust-bundle.json", &bundle, PUBLISH, GH);

    check_user_trust_bundle("acme", &bundle, &sidecar, now()).unwrap();
    store_trust_bundle(
        &user_trust_dir(),
        "acme",
        &bundle,
        &serde_json::to_vec(&sidecar).unwrap(),
        None,
    )
    .unwrap();

    // An artifact signed through the organization's own Fulcio and log.
    let work = home.join("work");
    let notes = work.join("notes.txt");
    let bytes = b"org-signed notes\n";

    fs::create_dir_all(&work).unwrap();
    fs::write(&notes, bytes).unwrap();
    fs::write(
        work.join("notes.txt.psig.json"),
        serde_json::to_vec(&org.sign_file(
            "notes.txt",
            bytes,
            "alice@acme.test",
            "https://sso.acme.test",
        ))
        .unwrap(),
    )
    .unwrap();

    let fresh = verify(&notes);

    assert_eq!(
        fresh.root.as_deref(),
        Some("acme/prod"),
        "{:?}",
        fresh.findings
    );
    assert_ne!(
        format!("{:?}", fresh.action),
        "Fail",
        "{:?}",
        fresh.findings
    );
    assert_eq!(stale_finding(&fresh), None);

    std::thread::sleep(std::time::Duration::from_secs(4));

    let stale = verify(&notes);

    assert_eq!(
        stale_finding(&stale).as_deref(),
        Some("warn"),
        "{:?}",
        stale.findings
    );
    assert_ne!(
        format!("{:?}", stale.action),
        "Fail",
        "{:?}",
        stale.findings
    );

    fs::write(
        home.join("policy.json"),
        serde_json::to_vec(&json!({
            "schema": "promptsign/policy/v1",
            "default": "warn",
            "rules": [{ "pattern": "*", "action": "warn", "tofu": true }],
            "on_trust_bundle_stale": "fail",
        }))
        .unwrap(),
    )
    .unwrap();

    let strict = verify(&notes);

    assert_eq!(
        stale_finding(&strict).as_deref(),
        Some("error"),
        "{:?}",
        strict.findings
    );
    assert_eq!(format!("{:?}", strict.action), "Fail");

    let _ = fs::remove_dir_all(&home);
}
