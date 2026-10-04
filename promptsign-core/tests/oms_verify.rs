// OMS directory verification: statement parsing, integrity, coverage, line
// endings and the invisible-character check, on real fixtures copied to temp
// directories. Roots are passed explicitly; no process-global environment.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use promptsign_core::oms::{check_dir, parse_statement, verify_oms_dir, OmsStatement};
use promptsign_core::policy::Action;
use promptsign_core::trustroot::{Root, DEFAULT_ROOT};
use promptsign_core::util::{parse_iso8601, sha256_hex};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn oms(rel: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures/foreign/oms").join(rel)
}

fn now() -> i64 {
    parse_iso8601("2026-10-04T00:00:00Z").unwrap()
}

fn nvidia_root() -> Root {
    Root::ca_only(
        "nvidia",
        &fs::read(oms("nvidia-agent-root-cert.pem")).unwrap(),
    )
    .unwrap()
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

/// A fresh copy of a fixture directory, named like the original so the
/// signed subject name still matches.
fn copy_of(fixture: &str, tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("ps-oms-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let dir = base.join(Path::new(fixture).file_name().unwrap());

    copy_dir(&oms(fixture), &dir);
    dir
}

fn nvidia_copy(tag: &str) -> PathBuf {
    copy_of("nvidia-earth2studio-discover", tag)
}

fn messages(findings: &[promptsign_core::policy::Finding]) -> String {
    findings
        .iter()
        .map(|f| format!("[{}] {}", f.level, f.message))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_signed_skill_verifies_clean() {
    let dir = nvidia_copy("clean");
    let out = verify_oms_dir(&dir, &[sigstore_public(), nvidia_root()], now()).unwrap();

    assert_eq!(out.action, Action::Pass, "{}", messages(&out.findings));
    assert!(out.findings.is_empty(), "{}", messages(&out.findings));
    assert_eq!(out.name, "earth2studio-discover");
    assert_eq!(out.kind, "skill");
    assert_eq!(out.signer.root, "nvidia");
}

#[test]
fn a_modified_or_missing_file_fails() {
    let dir = nvidia_copy("modified");

    fs::write(dir.join("SKILL.md"), "# replaced\n").unwrap();
    fs::remove_file(dir.join("BENCHMARK.md")).unwrap();

    let out = verify_oms_dir(&dir, &[nvidia_root()], now()).unwrap();
    let text = messages(&out.findings);

    assert_eq!(out.action, Action::Fail);
    assert!(text.contains("modified: SKILL.md"), "{text}");
    assert!(text.contains("missing file: BENCHMARK.md"), "{text}");
}

#[test]
fn uncovered_files_fail_when_an_agent_reads_or_runs_them() {
    for (path, expect) in [
        ("agents/openai.yaml", Action::Warn),
        ("references/extra.md", Action::Fail),
        ("scripts/run.sh", Action::Fail),
        ("helper.py", Action::Fail),
        ("CLAUDE.md", Action::Fail),
        ("assets/logo.png", Action::Warn),
    ] {
        let dir = nvidia_copy("uncovered");
        let abs = dir.join(path);

        fs::create_dir_all(abs.parent().unwrap()).unwrap();
        fs::write(&abs, "x\n").unwrap();

        let out = verify_oms_dir(&dir, &[nvidia_root()], now()).unwrap();
        let text = messages(&out.findings);

        assert_eq!(out.action, expect, "{path}: {text}");
        assert!(
            text.contains(&format!("uncovered: {path}")),
            "{path}: {text}"
        );
    }
}

#[test]
fn crlf_markdown_matches_its_signed_lf_copy() {
    let dir = nvidia_copy("crlf");
    let text = fs::read_to_string(dir.join("SKILL.md")).unwrap();

    fs::write(dir.join("SKILL.md"), text.replace('\n', "\r\n")).unwrap();

    let out = verify_oms_dir(&dir, &[nvidia_root()], now()).unwrap();
    let msgs = messages(&out.findings);

    assert_eq!(out.action, Action::Pass, "{msgs}");
    assert!(
        msgs.contains("[info]") && msgs.contains("SKILL.md"),
        "{msgs}"
    );

    // Line-ending tolerance is for Markdown only: a script must match exactly.
    let raw_dir = std::env::temp_dir().join(format!("ps-oms-crlf-raw-{}", std::process::id()));
    let _ = fs::remove_dir_all(&raw_dir);
    fs::create_dir_all(&raw_dir).unwrap();
    fs::write(raw_dir.join("run.sh"), "echo a\r\necho b\r\n").unwrap();

    let signed_lf = statement(&[("run.sh", &sha256_hex(b"echo a\necho b\n"))]);
    let (findings, action) = check_dir(&raw_dir, &signed_lf, "skill.oms.sig").unwrap();

    assert_eq!(action, Action::Fail, "{}", messages(&findings));
}

#[test]
fn files_the_signer_left_out_are_reported() {
    // ignore-me was excluded through ignore_paths at signing time.
    let dir = copy_of("upstream-v1.1.0-sigstore", "ignored");
    let out = verify_oms_dir(&dir, &[sigstore_public()], now()).unwrap();
    let text = messages(&out.findings);

    assert_eq!(out.signer.root, DEFAULT_ROOT);
    assert_eq!(out.action, Action::Warn, "{text}");
    assert!(text.contains("uncovered: ignore-me"), "{text}");
}

#[test]
fn a_bundle_from_an_untrusted_root_is_an_error() {
    let dir = nvidia_copy("untrusted");
    let err = verify_oms_dir(&dir, &[sigstore_public()], now())
        .err()
        .unwrap();

    assert!(err.contains("NVIDIA Agent Capabilities CA"), "{err}");
}

fn statement(resources: &[(&str, &str)]) -> OmsStatement {
    OmsStatement {
        name: "s".into(),
        resources: resources
            .iter()
            .map(|(n, d)| (n.to_string(), d.to_string()))
            .collect(),
        ignore_paths: vec![],
    }
}

#[test]
fn signed_markdown_with_hidden_characters_fails() {
    let dir = std::env::temp_dir().join(format!("ps-oms-bidi-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let body = "# Hel\u{202E}lo\n";

    fs::write(dir.join("SKILL.md"), body).unwrap();

    let (findings, action) = check_dir(
        &dir,
        &statement(&[("SKILL.md", &sha256_hex(body.as_bytes()))]),
        "skill.oms.sig",
    )
    .unwrap();

    assert_eq!(action, Action::Fail);
    assert!(
        messages(&findings).contains("U+202E"),
        "{}",
        messages(&findings)
    );
}

#[test]
fn signed_files_inside_skipped_directories_are_still_checked() {
    let dir = std::env::temp_dir().join(format!("ps-oms-skip-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("node_modules")).unwrap();
    fs::write(dir.join("node_modules/a.js"), "a\n").unwrap();

    let ok = statement(&[("node_modules/a.js", &sha256_hex(b"a\n"))]);
    let (findings, action) = check_dir(&dir, &ok, "skill.oms.sig").unwrap();

    assert_eq!(action, Action::Pass, "{}", messages(&findings));

    let changed = statement(&[("node_modules/a.js", &sha256_hex(b"b\n"))]);

    assert_eq!(
        check_dir(&dir, &changed, "skill.oms.sig").unwrap().1,
        Action::Fail
    );
}

fn payload_of(fixture: &str) -> Value {
    let b: Value = serde_json::from_slice(&fs::read(oms(fixture)).unwrap()).unwrap();

    serde_json::from_slice(
        &BASE64_STANDARD
            .decode(b["dsseEnvelope"]["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn parse(v: &Value) -> Result<OmsStatement, String> {
    parse_statement(
        "application/vnd.in-toto+json",
        &serde_json::to_vec(v).unwrap(),
    )
}

#[test]
fn statements_are_checked_before_any_file_is_read() {
    let good = payload_of("nvidia-earth2studio-discover/skill.oms.sig");
    let st = parse(&good).unwrap();

    assert_eq!(st.name, "earth2studio-discover");
    assert_eq!(st.resources.len(), 4);
    assert!(parse_statement("text/plain", b"{}").is_err());

    let legacy = payload_of("upstream-v0.2.0-certificate/model.sig");

    assert!(parse(&legacy).unwrap_err().contains("before 1.0"));

    let mut shards = good.clone();

    shards["predicate"]["serialization"]["method"] = json!("shards");
    assert!(parse(&shards).unwrap_err().contains("shards"));

    let mut wrong_root = good.clone();

    wrong_root["subject"][0]["digest"]["sha256"] = json!("00".repeat(32));
    assert!(parse(&wrong_root).unwrap_err().contains("root digest"));

    for bad_name in [
        "../escape.md",
        "/abs.md",
        "a/../../b",
        "C:/x.md",
        "a\\b.md",
        "",
    ] {
        let mut v = good.clone();

        v["predicate"]["resources"][0]["name"] = json!(bad_name);
        assert!(parse(&v).is_err(), "{bad_name:?} accepted");
    }

    let mut dup = good.clone();
    let first = dup["predicate"]["resources"][0].clone();

    dup["predicate"]["resources"][1] = first;
    assert!(parse(&dup).is_err(), "duplicate resource accepted");
}
