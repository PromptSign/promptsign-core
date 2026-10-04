// verify_target and verify_tree find OMS signatures on their own, and a
// PromptSign bundle takes precedence over an OMS signature in the same
// directory. One #[test] because PROMPTSIGN_HOME and PROMPTSIGN_TRUST_DIR are
// process-global.

use ed25519_dalek::SigningKey;
use promptsign_core::bundle::{sign_manifest, write_bundle};
use promptsign_core::manifest::{build_manifest, BuildOptions};
use promptsign_core::policy::Action;
use promptsign_core::trustroot;
use promptsign_core::verify::{verify_target, VerifyOptions};
use promptsign_core::verifytree::{discover_targets, verify_tree};
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

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn oms_signatures_are_found_and_promptsign_bundles_take_precedence() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixtures = manifest_dir.join("tests/fixtures/foreign/oms");
    let base = std::env::temp_dir().join(format!("ps-oms-discovery-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let home = base.join("home");
    let trust = home.join("trust");
    let skills = base.join("skills");
    let oms_skill = skills.join("earth2studio-discover");
    let both = skills.join("both/earth2studio-discover");
    let broken = skills.join("broken");

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
    trustroot::add_ca_root(
        &trust,
        "nvidia",
        &fs::read(fixtures.join("nvidia-agent-root-cert.pem")).unwrap(),
    )
    .unwrap();
    std::env::set_var("PROMPTSIGN_HOME", &home);
    std::env::set_var("PROMPTSIGN_TRUST_DIR", &trust);

    let policy = base.join("policy.json");

    fs::write(
        &policy,
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[{"pattern":"*","action":"enforce"}]}"#,
    )
    .unwrap();

    let opts = VerifyOptions {
        policy_path: Some(policy),
        no_pin_updates: true,
        ..Default::default()
    };

    // 1. An OMS-signed directory verifies through verify_target.
    copy_dir(&fixtures.join("nvidia-earth2studio-discover"), &oms_skill);

    let r = verify_target(&s(&oms_skill), &opts).unwrap();

    assert_eq!(r.format.as_deref(), Some("oms"));
    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert_eq!(r.root.as_deref(), Some("nvidia"));

    // 2. Both signatures present: the PromptSign bundle decides, and the
    //    result says the OMS signature was not the one checked.
    copy_dir(&fixtures.join("nvidia-earth2studio-discover"), &both);

    let key = SigningKey::from_bytes(&[9u8; 32]);
    let manifest = build_manifest(
        &both,
        None,
        &BuildOptions {
            name: Some("acme/both"),
            version: None,
            kind: None,
        },
    )
    .unwrap();

    write_bundle(
        &both,
        &sign_manifest(&manifest, &key, "dev@acme.example").unwrap(),
    )
    .unwrap();

    let r = verify_target(&s(&both), &opts).unwrap();

    assert_eq!(r.format.as_deref(), Some("promptsign"));
    assert_eq!(r.name, "acme/both");
    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert!(
        r.findings
            .iter()
            .any(|f| f.level == "info" && f.message.contains("skill.oms.sig")),
        "{:?}",
        r.findings
    );

    // 3. A broken OMS signature with no PromptSign bundle is an invalid
    //    signature, never "unsigned".
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("SKILL.md"), "# s\n").unwrap();
    fs::write(broken.join("skill.oms.sig"), "{}").unwrap();

    let r = verify_target(&s(&broken), &opts).unwrap();

    assert!(r.signed);
    assert_eq!(r.format.as_deref(), Some("oms"));
    assert_eq!(r.action, Action::Fail);
    assert!(
        r.findings[0].message.contains("invalid signature"),
        "{:?}",
        r.findings
    );

    // 4. verify_tree treats each signed directory as one target, so the
    //    SKILL.md files inside are not reported on their own.
    fs::write(skills.join("CLAUDE.md"), "# loose\n").unwrap();

    let mut targets: Vec<PathBuf> = discover_targets(&[s(&skills)]);

    targets.sort();
    assert_eq!(
        targets,
        vec![
            skills.join("CLAUDE.md"),
            both.clone(),
            broken.clone(),
            oms_skill.clone()
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
    );

    let results = verify_tree(&[s(&skills)], &opts).unwrap();
    let by_format = |f: &str| {
        results
            .iter()
            .filter(|r| r.format.as_deref() == Some(f))
            .count()
    };

    assert_eq!(results.len(), 4);
    assert_eq!(by_format("oms"), 2);
    assert_eq!(by_format("promptsign"), 1);

    let _ = fs::remove_dir_all(&base);
}
