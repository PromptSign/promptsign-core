// verify_oms end to end: registry roots from the trust directory, the user's
// policy, TOFU pins. One #[test] because PROMPTSIGN_HOME and
// PROMPTSIGN_TRUST_DIR are process-global.

use promptsign_core::policy::Action;
use promptsign_core::trustroot;
use promptsign_core::verify::{verify_oms, VerifyOptions};
use std::fs;
use std::path::{Path, PathBuf};

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for ent in fs::read_dir(from).unwrap() {
        let ent = ent.unwrap();
        let dest = to.join(ent.file_name());

        if ent.file_type().unwrap().is_dir() {
            copy_dir(&ent.path(), &dest);
        } else {
            fs::copy(ent.path(), dest).unwrap();
        }
    }
}

fn opts(policy: &Path) -> VerifyOptions {
    VerifyOptions {
        policy_path: Some(policy.to_path_buf()),
        ..Default::default()
    }
}

fn write_policy(path: &Path, rule: serde_json::Value) {
    let doc = serde_json::json!({
        "schema": "promptsign/policy/v1",
        "default": "warn",
        "rules": [rule]
    });

    fs::write(path, serde_json::to_string(&doc).unwrap()).unwrap();
}

#[test]
fn oms_skill_under_policy_roots_and_pins() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures/foreign/oms");
    let base = std::env::temp_dir().join(format!("ps-oms-policy-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let home = base.join("home");
    let trust = home.join("trust");
    let skill = base.join("skills/earth2studio-discover");

    fs::create_dir_all(&trust).unwrap();
    fs::copy(
        manifest_dir.join("../trust/fulcio.pem"),
        trust.join("fulcio.pem"),
    )
    .unwrap();
    fs::copy(
        manifest_dir.join("../trust/rekor.pub"),
        trust.join("rekor.pub"),
    )
    .unwrap();
    copy_dir(&fixtures.join("nvidia-earth2studio-discover"), &skill);
    std::env::set_var("PROMPTSIGN_HOME", &home);
    std::env::set_var("PROMPTSIGN_TRUST_DIR", &trust);

    let target = skill.to_str().unwrap();
    let policy = base.join("policy.json");

    write_policy(
        &policy,
        serde_json::json!({ "pattern": "*", "action": "enforce", "tofu": true, "trust_root": "nvidia" }),
    );

    // Root not trusted yet: an invalid signature, naming the root.
    let r = verify_oms(target, &opts(&policy)).unwrap();

    assert_eq!(r.action, Action::Fail);
    assert_eq!(r.format.as_deref(), Some("oms"));
    assert!(
        r.findings[0]
            .message
            .contains("NVIDIA Agent Capabilities CA"),
        "{:?}",
        r.findings
    );

    // Trust it: passes, pins the root.
    trustroot::add_ca_root(
        &trust,
        "nvidia",
        &fs::read(fixtures.join("nvidia-agent-root-cert.pem")).unwrap(),
    )
    .unwrap();

    let r = verify_oms(target, &opts(&policy)).unwrap();

    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert_eq!(r.root.as_deref(), Some("nvidia"));
    assert_eq!(r.name, "earth2studio-discover");
    assert_eq!(r.kind.as_deref(), Some("skill"));
    assert!(r
        .issuer
        .as_deref()
        .unwrap()
        .starts_with("x509:sha256:6f1bb875"));
    assert!(r
        .findings
        .iter()
        .any(|f| f.message.contains("trust on first use")));

    let pins = fs::read_to_string(home.join("pins.json")).unwrap();

    assert!(pins.contains("x509:sha256:6f1bb875"), "{pins}");

    // Second run: pin holds, nothing new.
    let r = verify_oms(target, &opts(&policy)).unwrap();

    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert!(r.findings.is_empty(), "{:?}", r.findings);

    // A rule that requires another root fails the same signature.
    write_policy(
        &policy,
        serde_json::json!({ "pattern": "*", "action": "enforce", "trust_root": "sigstore-public" }),
    );

    let r = verify_oms(target, &opts(&policy)).unwrap();

    assert_eq!(r.action, Action::Fail);
    assert!(
        r.findings.iter().any(|f| f.message.contains("trust root")),
        "{:?}",
        r.findings
    );

    // Integrity failures fail whatever the policy says.
    write_policy(
        &policy,
        serde_json::json!({ "pattern": "*", "action": "off" }),
    );
    fs::write(skill.join("SKILL.md"), "# replaced\n").unwrap();

    let r = verify_oms(target, &opts(&policy)).unwrap();

    assert_eq!(r.action, Action::Fail);
    assert!(
        r.findings.iter().any(|f| f.message == "modified: SKILL.md"),
        "{:?}",
        r.findings
    );

    let _ = fs::remove_dir_all(&base);
}
