// Approvals (spec/09): an in-toto statement over an artifact's content
// digest, verified offline under any registry root, withdrawn by the
// revocation feed, and counted by a policy rule that requires them.

mod common;

use common::MockSigstore;
use promptsign_core::approval::{
    collect, listing_for, statement, user_store, verify_approval, Rejected, IN_TOTO_PAYLOAD_TYPE,
};
use promptsign_core::managed::platform_dir;
use promptsign_core::policy::Action;
use promptsign_core::revocation::{RevocationEntry, RevocationFeed, REVOCATION_SCHEMA};
use promptsign_core::trustroot::{add_trusted_root, user_trust_dir, Root};
use promptsign_core::util::parse_iso8601;
use promptsign_core::verify::{verify_target, VerifyOptions, VerifyResult};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const ALICE: &str = "alice@acme.test";
const BOB: &str = "bob@acme.test";
const SSO: &str = "https://sso.acme.test";
const CA_LEAF: &str = "CN=sigstore-intermediate";
const DIGEST: &str = "4f3c2a8d1e9b7c6a5f4e3d2c1b0a99887766554433221100ffeeddccbbaa9988";

fn t0() -> i64 {
    parse_iso8601("2026-10-01T12:00:00Z").unwrap()
}

fn deployment() -> MockSigstore {
    MockSigstore::new_valid(
        44,
        "acme approvals",
        parse_iso8601("2026-01-01T00:00:00Z").unwrap(),
        parse_iso8601("2036-01-01T00:00:00Z").unwrap(),
    )
}

fn approve(d: &MockSigstore, digest: &str, identity: &str) -> Value {
    // Each approver's statement differs in approvedAt, as with `promptsign
    // approve`, so each has its own payload digest.
    let at = format!("2026-10-01T12:{:02}:00Z", identity.len());
    let doc = serde_json::to_vec(&statement("skill", digest, &at, None)).unwrap();

    d.sign_typed_payload_at(IN_TOTO_PAYLOAD_TYPE, &doc, identity, SSO, t0())
}

fn keyless_root(d: &MockSigstore) -> Root {
    Root::from_trusted_root("acme/prod", &d.trusted_root()).unwrap()
}

#[test]
fn an_approval_covers_its_content_only() {
    let d = deployment();
    let roots = [keyless_root(&d)];
    let a = verify_approval(&approve(&d, DIGEST, ALICE), DIGEST, &roots, t0()).unwrap();

    assert_eq!((a.identity.as_str(), a.issuer.as_str()), (ALICE, SSO));
    assert_eq!(a.root, "acme/prod");
    assert!(a.payload_digest.starts_with("sha256:"));

    let other = "0".repeat(64);

    assert_eq!(
        verify_approval(&approve(&d, &other, ALICE), DIGEST, &roots, t0()),
        Err(Rejected::OtherContent)
    );
}

#[test]
fn only_an_in_toto_approval_statement_is_an_approval() {
    let d = deployment();
    let roots = [keyless_root(&d)];
    let doc =
        serde_json::to_vec(&statement("skill", DIGEST, "2026-10-01T12:00:00Z", None)).unwrap();
    let wrong_type = d.sign_typed_payload_at("application/json", &doc, ALICE, SSO, t0());

    assert!(matches!(
        verify_approval(&wrong_type, DIGEST, &roots, t0()),
        Err(Rejected::Invalid(e)) if e.contains("in-toto")
    ));

    let mut scan = statement("skill", DIGEST, "2026-10-01T12:00:00Z", None);

    scan["predicateType"] = json!("https://example.test/scan/v1");

    let scan = d.sign_typed_payload_at(
        IN_TOTO_PAYLOAD_TYPE,
        &serde_json::to_vec(&scan).unwrap(),
        ALICE,
        SSO,
        t0(),
    );

    assert!(matches!(
        verify_approval(&scan, DIGEST, &roots, t0()),
        Err(Rejected::Invalid(e)) if e.contains("not an approval")
    ));

    // A root the approval does not chain to rejects it.
    let elsewhere =
        [
            Root::from_trusted_root("other", &MockSigstore::new(45, "other").trusted_root())
                .unwrap(),
        ];

    assert!(matches!(
        verify_approval(&approve(&d, DIGEST, ALICE), DIGEST, &elsewhere, t0()),
        Err(Rejected::Invalid(_))
    ));
}

#[test]
fn a_certificate_mode_approval_verifies_under_a_ca_root() {
    let d = deployment();
    let mut doc = d.trusted_root_v2();

    doc["tlogs"] = json!([]);

    let roots = [Root::from_trusted_root("acme/ca", &doc).unwrap()];
    let payload = serde_json::to_vec(&statement(
        "skill",
        DIGEST,
        "2026-10-01T12:00:00Z",
        Some("PR 412"),
    ))
    .unwrap();
    let bundle = d.sign_sigstore_certificate_mode_typed(IN_TOTO_PAYLOAD_TYPE, &payload, t0(), true);
    let a = verify_approval(&bundle, DIGEST, &roots, common::now()).unwrap();

    assert_eq!(a.identity, CA_LEAF);
    assert_eq!(a.root, "acme/ca");
    assert!(a.issuer.starts_with("x509:sha256:"));
}

#[test]
fn the_revocation_feed_withdraws_approvals() {
    let d = deployment();
    let roots = [keyless_root(&d)];
    let dir = common::temp_dir("approvals-revoked");
    let alice = approve(&d, DIGEST, ALICE);
    let bob = approve(&d, DIGEST, BOB);
    let bob_digest = verify_approval(&bob, DIGEST, &roots, t0())
        .unwrap()
        .payload_digest;

    fs::write(dir.join("alice.json"), alice.to_string()).unwrap();
    fs::write(dir.join("bob.json"), bob.to_string()).unwrap();
    fs::write(dir.join("broken.json"), "{").unwrap();

    let files = [
        dir.join("alice.json"),
        dir.join("bob.json"),
        dir.join("broken.json"),
    ];
    let entry = |kind: &str| RevocationEntry {
        kind: kind.to_string(),
        identity: None,
        issuer: None,
        from: None,
        payload_digest: None,
        log_index: None,
        reason: Some("test".into()),
    };
    let feed = RevocationFeed {
        schema: REVOCATION_SCHEMA.to_string(),
        generated_at: "2026-10-02T00:00:00Z".to_string(),
        entries: vec![
            // Alice's approvals from before her compromise still count.
            RevocationEntry {
                identity: Some(ALICE.into()),
                from: Some("2026-10-02T00:00:00Z".into()),
                ..entry("identity")
            },
            RevocationEntry {
                payload_digest: Some(bob_digest),
                ..entry("digest")
            },
        ],
    };
    let got = collect(&files, DIGEST, &roots, Some(&feed), t0());

    assert_eq!(got.approvals.len(), 1, "{:?}", got.findings);
    assert_eq!(got.approvals[0].identity, ALICE);
    assert!(got
        .findings
        .iter()
        .any(|f| f.level == "warn" && f.message.contains("approval by bob@acme.test revoked")));
    assert!(got
        .findings
        .iter()
        .any(|f| f.level == "info" && f.message.contains("broken.json")));

    let all = collect(&files, DIGEST, &roots, None, t0());

    assert_eq!(all.approvals.len(), 2);
    let _ = fs::remove_dir_all(&dir);
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn policy(home: &Path, rule: Value) {
    write(
        &home.join("policy.json"),
        &json!({ "schema": "promptsign/policy/v1", "default": "warn", "rules": [rule] })
            .to_string(),
    );
}

fn errors(r: &VerifyResult) -> Vec<&str> {
    r.findings
        .iter()
        .filter(|f| f.level == "error")
        .map(|f| f.message.as_str())
        .collect()
}

/// One test: the policy, home and working directory are process-global.
#[test]
fn a_policy_counts_approvals_of_the_exact_bytes() {
    if platform_dir().exists() {
        eprintln!(
            "skipped: {} exists, so its managed policy would apply",
            platform_dir().display()
        );
        return;
    }

    let d = deployment();
    let home = common::temp_dir("approvals-home");
    let work = common::temp_dir("approvals-work");
    let skill = work.join("skill");
    let opts = VerifyOptions {
        no_pin_updates: true,
        ..Default::default()
    };

    std::env::set_var("PROMPTSIGN_HOME", &home);
    std::env::remove_var("PROMPTSIGN_MANAGED_DIR");
    std::env::remove_var("PROMPTSIGN_TRUST_DIR");
    std::env::remove_var("PROMPTSIGN_POLICY");
    std::env::remove_var("PROMPTSIGN_REVOCATION_FILE");
    std::env::set_current_dir(&work).unwrap();
    add_trusted_root(&user_trust_dir(), "acme", &d.trusted_root()).unwrap();
    write(
        &skill.join("SKILL.md"),
        "---\nname: triage\ndescription: x\n---\nTriage.\n",
    );
    write(&skill.join("scripts/run.py"), "print('hi')\n");

    let target = skill.to_str().unwrap();
    let approver = json!({ "identity": "*@acme.test", "issuer": SSO, "trust_root": "acme" });

    policy(
        &home,
        json!({ "pattern": "*", "action": "enforce",
                "approval": { "approvers": [approver] } }),
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Fail);
    assert_eq!(
        errors(&r),
        ["\"skill\" has 0 of 1 required approval (rule: *)"]
    );

    // An approval committed beside the skill stands in for a signature.
    let listing = listing_for(&skill).unwrap();

    assert_eq!(listing.files, 2);
    write(
        &skill.join(".promptsign/approvals/alice.json"),
        &approve(&d, &listing.digest, ALICE).to_string(),
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert_eq!(r.approvals.len(), 1);
    assert_eq!(r.approvals[0].identity, ALICE);

    // Changing one byte un-approves it.
    write(&skill.join("scripts/run.py"), "print('pwned')\n");
    assert_eq!(verify_target(target, &opts).unwrap().action, Action::Fail);
    write(&skill.join("scripts/run.py"), "print('hi')\n");

    // Two distinct approvers: one more from the user's store, while an
    // approver the rule does not name, or Alice twice, adds nothing.
    policy(
        &home,
        json!({ "pattern": "*", "action": "enforce",
                "approval": { "approvers": [approver], "threshold": 2 } }),
    );

    let store = user_store(&listing.digest);

    write(
        &store.join("alice-again.json"),
        &approve(&d, &listing.digest, ALICE).to_string(),
    );
    write(
        &store.join("mallory.json"),
        &approve(&d, &listing.digest, "mallory@evil.test").to_string(),
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(
        errors(&r),
        ["\"skill\" has 1 of 2 required approvals (rule: *)"]
    );
    write(
        &store.join("bob.json"),
        &approve(&d, &listing.digest, BOB).to_string(),
    );
    assert_eq!(verify_target(target, &opts).unwrap().action, Action::Pass);

    // A rule that also names an author still needs the author's signature.
    policy(
        &home,
        json!({ "pattern": "*", "action": "enforce", "identity": "*@acme.test",
                "approval": { "approvers": [approver] } }),
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(errors(&r), ["unsigned artifact \"skill\" (rule: *)"]);

    // Without an approval rule, no approvals are read or reported.
    policy(&home, json!({ "pattern": "*", "action": "warn" }));

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Warn);
    assert!(r.approvals.is_empty());

    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_dir_all(&work);
}
