// OpenSSF Model Signing (OMS) bundles: a detached Sigstore bundle
// (`skill.oms.sig`, `model.sig`) whose in-toto Statement lists every file of a
// directory with its raw SHA-256. PromptSign verifies these, never writes them.
//
// The signature and signer come from sigstore_bundle. This module checks the
// Statement, then the directory under PromptSign's rules: every listed file
// must match, and a file the Statement does not cover is reported. Uncovered
// files an agent reads or runs fail; others warn.

use crate::canonicalize::{check_markdown_text, is_markdown};
use crate::manifest::{infer_kind, role_for, walk_tree, CONTEXT_INJECTED};
use crate::policy::{Action, Finding};
use crate::sigstore_bundle::{verify_sigstore_bundle, VerifiedStatement};
use crate::trustroot::Root;
use crate::util::sha256_hex;
use crate::Result;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
pub const STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_V1: &str = "https://model_signing/signature/v1.0";
const PREDICATE_PRE_1_0: &str = "https://model_signing/Digests/v0.1";

/// Signature file names, in lookup order.
pub const SIGNATURE_FILES: [&str; 2] = ["skill.oms.sig", "model.sig"];

#[derive(Debug, Clone)]
pub struct OmsStatement {
    /// Subject name: the signed directory's name.
    pub name: String,
    /// (relative path, hex SHA-256 of the raw bytes), in signed order.
    pub resources: Vec<(String, String)>,
    /// Paths the signer excluded, as recorded in the Statement.
    pub ignore_paths: Vec<String>,
}

pub struct OmsOutcome {
    pub signer: VerifiedStatement,
    pub name: String,
    pub kind: &'static str,
    pub findings: Vec<Finding>,
    /// Integrity and coverage only; policy comes later.
    pub action: Action,
}

/// The signature file in `dir`, if any.
pub fn signature_file(dir: &Path) -> Option<PathBuf> {
    SIGNATURE_FILES
        .iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file())
}

/// A resource path must stay inside the signed directory.
fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.contains('\\')
        && !p.contains(':')
        && p.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Parse and check an OMS Statement: version, serialization, resource paths,
/// and the root digest that binds the resource list to the signed subject.
pub fn parse_statement(payload_type: &str, payload: &[u8]) -> Result<OmsStatement> {
    if payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(format!("unsupported payload type for OMS: {payload_type}"));
    }

    let v: Value =
        serde_json::from_slice(payload).map_err(|e| format!("invalid in-toto Statement: {e}"))?;

    if v["_type"] != STATEMENT_V1 {
        return Err(format!(
            "unsupported in-toto Statement type: {}",
            v["_type"]
        ));
    }

    let predicate_type = v["predicateType"].as_str().unwrap_or("");

    if predicate_type == PREDICATE_PRE_1_0 {
        return Err("unsupported: OMS bundles from model_signing before 1.0".to_string());
    }
    if predicate_type != PREDICATE_V1 {
        return Err(format!("unsupported predicate type: {predicate_type}"));
    }

    let ser = &v["predicate"]["serialization"];
    let method = ser["method"].as_str().unwrap_or("");

    if method != "files" {
        return Err(format!("unsupported OMS serialization method: {method}"));
    }
    if ser["hash_type"].as_str() != Some("sha256") {
        return Err(format!("unsupported OMS hash type: {}", ser["hash_type"]));
    }

    let subjects = v["subject"].as_array().ok_or("Statement has no subject")?;

    if subjects.len() != 1 {
        return Err(format!(
            "OMS Statement has {} subjects, expected 1",
            subjects.len()
        ));
    }

    let name = subjects[0]["name"].as_str().unwrap_or("").to_string();
    let root_digest = subjects[0]["digest"]["sha256"]
        .as_str()
        .ok_or("subject has no sha256 digest")?;
    let mut resources = Vec::new();
    let mut seen = BTreeSet::new();
    let mut concatenated = Vec::new();

    for r in v["predicate"]["resources"]
        .as_array()
        .ok_or("OMS predicate has no resources")?
    {
        let path = r["name"].as_str().unwrap_or("");
        let digest = r["digest"].as_str().unwrap_or("").to_lowercase();

        if !safe_path(path) {
            return Err(format!("OMS resource has an unsafe path: {path:?}"));
        }
        if r["algorithm"].as_str() != Some("sha256") {
            return Err(format!("OMS resource {path} is not hashed with sha256"));
        }
        if !seen.insert(path.to_string()) {
            return Err(format!("OMS resource listed twice: {path}"));
        }

        let raw = unhex(&digest)
            .filter(|b| b.len() == 32)
            .ok_or_else(|| format!("OMS resource {path} has an invalid digest"))?;

        concatenated.extend_from_slice(&raw);
        resources.push((path.to_string(), digest));
    }
    if resources.is_empty() {
        return Err("OMS Statement lists no files".to_string());
    }
    if sha256_hex(&concatenated) != root_digest.to_lowercase() {
        return Err("OMS root digest does not match the listed files".to_string());
    }

    let ignore_paths = ser["ignore_paths"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(OmsStatement {
        name,
        resources,
        ignore_paths,
    })
}

fn crlf_to_lf(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;

    while i < buf.len() {
        if buf[i] == b'\r' && buf.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(buf[i]);
        i += 1;
    }
    out
}

/// An uncovered file fails when an agent would read or run it: entrypoints,
/// executables, context-injected files and Markdown. Anything else warns.
fn uncovered_fails(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);

    matches!(role_for(rel), "entrypoint" | "executable")
        || CONTEXT_INJECTED.contains(&base)
        || is_markdown(rel)
}

/// Check `dir` against a verified Statement. `signature_name` is the bundle's
/// own file at the top of `dir`, which the Statement never lists.
pub fn check_dir(
    dir: &Path,
    statement: &OmsStatement,
    signature_name: &str,
) -> Result<(Vec<Finding>, Action)> {
    let mut findings = Vec::new();
    let mut action = Action::Pass;
    let mut note = |level: &str, message: String, findings: &mut Vec<Finding>| {
        let to = match level {
            "error" => Action::Fail,
            "warn" => Action::Warn,
            _ => Action::Pass,
        };

        if to > action {
            action = to;
        }
        findings.push(Finding {
            level: level.to_string(),
            message,
        });
    };

    // Listed files are read by path, so a file the signer covered inside a
    // directory the walk skips (node_modules, .venv) is still checked.
    for (rel, expected) in &statement.resources {
        let abs = dir.join(rel);

        match fs::symlink_metadata(&abs) {
            Err(_) => {
                note("error", format!("missing file: {rel}"), &mut findings);
                continue;
            }
            Ok(md) if !md.is_file() => {
                note("error", format!("not a regular file: {rel}"), &mut findings);
                continue;
            }
            Ok(_) => {}
        }

        let buf = fs::read(&abs).map_err(|e| format!("{rel}: {e}"))?;

        if sha256_hex(&buf) != *expected {
            if is_markdown(rel) && sha256_hex(&crlf_to_lf(&buf)) == *expected {
                note(
                    "info",
                    format!(
                        "{rel}: line endings differ from the signed copy (CRLF); content matches"
                    ),
                    &mut findings,
                );
            } else {
                note("error", format!("modified: {rel}"), &mut findings);
                continue;
            }
        }
        if is_markdown(rel) {
            if let Err(e) = check_markdown_text(&buf) {
                note("error", format!("{rel}: {e}"), &mut findings);
            }
        }
    }

    let listed: BTreeSet<&str> = statement
        .resources
        .iter()
        .map(|(p, _)| p.as_str())
        .collect();
    let tree = walk_tree(dir)?;

    for rel in &tree.files {
        if rel == signature_name || listed.contains(rel.as_str()) {
            continue;
        }

        let level = if uncovered_fails(rel) {
            "error"
        } else {
            "warn"
        };

        note(
            level,
            format!("uncovered: {rel} is not covered by the signature"),
            &mut findings,
        );
    }
    for link in &tree.links {
        note("error", format!("symlink present: {link}"), &mut findings);
    }
    Ok((findings, action))
}

/// Verify the OMS bundle in `dir` against `roots`: signature, Statement, then
/// the directory itself.
pub fn verify_oms_dir(dir: &Path, roots: &[Root], now: i64) -> Result<OmsOutcome> {
    let sig_path =
        signature_file(dir).ok_or_else(|| format!("no OMS signature file in {}", dir.display()))?;
    let bundle: Value = serde_json::from_slice(
        &fs::read(&sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?,
    )
    .map_err(|e| format!("{}: {e}", sig_path.display()))?;

    verify_oms_bundle(
        dir,
        &bundle,
        sig_path.file_name().and_then(|n| n.to_str()).unwrap_or(""),
        roots,
        now,
    )
}

pub fn verify_oms_bundle(
    dir: &Path,
    bundle: &Value,
    signature_name: &str,
    roots: &[Root],
    now: i64,
) -> Result<OmsOutcome> {
    let signer = verify_sigstore_bundle(bundle, roots, now)?;
    let statement = parse_statement(&signer.payload_type, &signer.payload)?;
    let (findings, action) = check_dir(dir, &statement, signature_name)?;
    let paths: Vec<String> = statement.resources.iter().map(|(p, _)| p.clone()).collect();

    Ok(OmsOutcome {
        name: statement.name.clone(),
        kind: infer_kind(&paths),
        signer,
        findings,
        action,
    })
}
