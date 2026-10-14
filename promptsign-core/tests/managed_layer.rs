// The managed layer (spec/04 "Managed policy", spec/07 §2.4): a policy and
// trust directory an administrator owns, which the user's policy, the
// project's and the environment cannot loosen. Uses $PROMPTSIGN_MANAGED_DIR,
// which only applies on a machine without the platform directory. One #[test]
// because every variable involved is process-global.

use promptsign_core::managed::{env_locked, managed_dir, platform_dir};
use promptsign_core::policy::{strict_mode, Action};
use promptsign_core::trustroot::{self, load_full_registry, DEFAULT_ROOT};
use promptsign_core::util::promptsign_home;
use promptsign_core::verify::{verify_target, VerifyOptions};
use std::fs;
use std::path::{Path, PathBuf};

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn names() -> Vec<(String, bool)> {
    load_full_registry(0)
        .unwrap()
        .roots
        .into_iter()
        .map(|r| (r.name, r.managed))
        .collect()
}

#[test]
fn the_managed_layer_cannot_be_loosened() {
    if platform_dir().exists() {
        eprintln!(
            "skipped: {} exists, so PROMPTSIGN_MANAGED_DIR does not apply",
            platform_dir().display()
        );
        return;
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("ps-managed-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let managed = base.join("managed");
    let real_home = base.join("real-home");
    let env_home = base.join("env-home");
    let repo = base.join("repo");
    let ca = fs::read(manifest_dir.join("tests/fixtures/foreign/oms/nvidia-agent-root-cert.pem"))
        .unwrap();
    let opts = VerifyOptions {
        no_pin_updates: true,
        ..Default::default()
    };

    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&real_home).unwrap();
    fs::write(repo.join("CLAUDE.md"), "# rules\n").unwrap();
    std::env::set_var("HOME", &real_home);
    std::env::set_var("USERPROFILE", &real_home);
    std::env::set_var("PROMPTSIGN_HOME", &env_home);
    std::env::set_var("PROMPTSIGN_MANAGED_DIR", &managed);
    std::env::remove_var("PROMPTSIGN_POLICY");
    std::env::remove_var("PROMPTSIGN_TRUST_DIR");
    std::env::remove_var("PROMPTSIGN_STRICT");
    std::env::set_current_dir(&repo).unwrap();

    // No managed policy: the user's policy is the base, as before.
    write(
        &env_home.join("policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"off","rules":[{"pattern":"*","action":"off"}]}"#,
    );

    let target = repo.join("CLAUDE.md");
    let target = target.to_str().unwrap();
    let r = verify_target(target, &opts).unwrap();

    assert_eq!(managed_dir(), managed);
    assert_eq!(r.action, Action::Pass, "{:?}", r.findings);
    assert!(!r.policy_source.contains("(managed)"));

    // 1. A managed policy that enforces signatures wins over the user's "off".
    write(
        &managed.join("managed-policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[]}"#,
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Fail, "{:?}", r.findings);
    assert!(r.findings[0].message.starts_with("unsigned artifact"));
    assert_eq!(
        r.policy_source,
        format!(
            "{} (managed) + {} (tighten only)",
            managed.join("managed-policy.json").display(),
            env_home.join("policy.json").display()
        )
    );

    // 2. The project's "off" cannot loosen it either.
    write(
        &repo.join(".promptsign/policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"off","rules":[]}"#,
    );
    assert_eq!(verify_target(target, &opts).unwrap().action, Action::Fail);
    fs::remove_dir_all(repo.join(".promptsign")).unwrap();

    // 3. Under a managed "warn", a user policy file tightens it, and the
    //    built-in default no longer applies when the user has none.
    write(
        &managed.join("managed-policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[]}"#,
    );
    write(
        &env_home.join("policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[]}"#,
    );

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Fail);
    assert!(
        r.findings
            .iter()
            .any(|f| f.message.starts_with("user policy: unsigned artifact")),
        "{:?}",
        r.findings
    );
    fs::remove_file(env_home.join("policy.json")).unwrap();

    let r = verify_target(target, &opts).unwrap();

    assert_eq!(r.action, Action::Warn);
    assert_eq!(r.findings.len(), 1);
    assert!(!r.policy_source.contains("built-in default"));

    // 4. Trust: managed roots load first and are marked; a user root that
    //    takes a managed name is ignored; user_roots: false drops the rest.
    trustroot::add_ca_root(&managed.join("trust"), "corp", &ca).unwrap();
    write(
        &env_home.join("trust/roots/corp.json"),
        &fs::read_to_string(managed.join("trust/roots/corp.json")).unwrap(),
    );
    write(
        &env_home.join("trust/roots/mine.json"),
        &fs::read_to_string(managed.join("trust/roots/corp.json")).unwrap(),
    );

    let reg = load_full_registry(0).unwrap();

    assert_eq!(
        names(),
        vec![("corp".to_string(), true), ("mine".to_string(), false)]
    );
    assert!(
        reg.ignored[0].contains("trust root \"corp\""),
        "{:?}",
        reg.ignored
    );

    write(
        &managed.join("managed-policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[],"user_roots":false}"#,
    );
    assert_eq!(names(), vec![("corp".to_string(), true)]);
    assert!(load_full_registry(0).unwrap().ignored[0].contains("user_roots"));

    // 5. A built-in root in the managed trust directory wins over
    //    PROMPTSIGN_TRUST_DIR.
    let bundled = base.join("bundled-trust");

    write(&bundled.join("fulcio.pem"), "not a certificate");
    write(&bundled.join("rekor.pub"), "not a key");
    std::env::set_var("PROMPTSIGN_TRUST_DIR", &bundled);
    assert!(trustroot::load_registry().is_err());
    for f in ["fulcio.pem", "rekor.pub"] {
        fs::copy(
            manifest_dir.join("../trust").join(f),
            managed.join("trust").join(f),
        )
        .unwrap();
    }
    assert_eq!(
        names(),
        vec![(DEFAULT_ROOT.to_string(), true), ("corp".to_string(), true)]
    );
    assert_eq!(trustroot::builtin_root_dir(), managed.join("trust"));

    // 6. lock_env: PROMPTSIGN_HOME, PROMPTSIGN_POLICY and PROMPTSIGN_TRUST_DIR
    //    stop applying.
    let loose = base.join("loose.json");

    write(
        &loose,
        r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[]}"#,
    );
    std::env::set_var("PROMPTSIGN_POLICY", &loose);
    assert_eq!(verify_target(target, &opts).unwrap().action, Action::Fail);
    assert!(!env_locked());
    assert_eq!(promptsign_home(), env_home);

    write(
        &managed.join("managed-policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[],"lock_env":true}"#,
    );
    assert!(env_locked());
    assert_eq!(promptsign_home(), real_home.join(".promptsign"));
    assert_eq!(
        promptsign_core::keyless::trust_dir(),
        real_home.join(".promptsign/trust")
    );
    assert_eq!(verify_target(target, &opts).unwrap().action, Action::Warn);

    // 7. strict: from the managed policy, or PROMPTSIGN_STRICT=1.
    assert!(!strict_mode());
    write(
        &managed.join("managed-policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[],"strict":true}"#,
    );
    assert!(strict_mode());

    // A managed policy that does not parse fails verification and counts as
    // strict and locked.
    write(&managed.join("managed-policy.json"), "{");
    assert!(verify_target(target, &opts).is_err());
    assert!(strict_mode());
    assert!(env_locked());

    for v in [
        "PROMPTSIGN_HOME",
        "PROMPTSIGN_MANAGED_DIR",
        "PROMPTSIGN_POLICY",
        "PROMPTSIGN_TRUST_DIR",
    ] {
        std::env::remove_var(v);
    }
    std::env::set_current_dir(&manifest_dir).unwrap();
    let _ = fs::remove_dir_all(&base);
}
