// The user's named roots live under $PROMPTSIGN_HOME/trust/roots whatever
// PROMPTSIGN_TRUST_DIR says: that variable only picks the pinned public root
// (the npm package points it at its bundled copy). One #[test] because both
// variables are process-global.

use promptsign_core::trustroot::{self, DEFAULT_ROOT};
use std::fs;
use std::path::PathBuf;

#[test]
fn named_roots_come_from_the_users_home_not_the_trust_dir() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("ps-registry-env-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let bundled = base.join("node_modules/@promptsign/verify/trust");
    let home = base.join("home");

    fs::create_dir_all(&bundled).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::copy(
        manifest_dir.join("../trust/fulcio.pem"),
        bundled.join("fulcio.pem"),
    )
    .unwrap();
    fs::copy(
        manifest_dir.join("../trust/rekor.pub"),
        bundled.join("rekor.pub"),
    )
    .unwrap();
    std::env::set_var("PROMPTSIGN_HOME", &home);
    std::env::set_var("PROMPTSIGN_TRUST_DIR", &bundled);

    let pem = fs::read(manifest_dir.join("tests/fixtures/foreign/oms/nvidia-agent-root-cert.pem"))
        .unwrap();
    let added = trustroot::add_user_ca_root("nvidia", &pem).unwrap();

    assert!(home.join("trust/roots/nvidia.json").exists());
    assert!(!bundled.join("roots").exists());

    let names: Vec<String> = trustroot::load_registry()
        .unwrap()
        .into_iter()
        .map(|r| r.name)
        .collect();

    assert_eq!(names, vec![DEFAULT_ROOT.to_string(), "nvidia".to_string()]);
    assert_eq!(added.name, "nvidia");

    trustroot::remove_user_root("nvidia").unwrap();
    assert_eq!(trustroot::load_registry().unwrap().len(), 1);

    let _ = fs::remove_dir_all(&base);
}
