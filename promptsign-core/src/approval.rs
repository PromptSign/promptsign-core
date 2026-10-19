// Approvals (spec/09): in-toto Statements whose subject is an artifact's
// content digest, signed by a reviewer. A policy rule can require a number of
// them from approvers it names. Verification stays offline: approvals are
// files next to the artifact or in the managed and user stores, and the
// verifier checks them against the trust-root registry like any signature.

use crate::keyless::verify_keyless_with;
use crate::managed::managed_dir;
use crate::manifest::{build_manifest, BuildOptions, FileEntry, Manifest};
use crate::policy::Finding;
use crate::revocation::{check_revocation, payload_digest_of, RevocationFeed, Subject};
use crate::sigstore_bundle::{is_sigstore_bundle, verify_sigstore_bundle};
use crate::trustroot::Root;
use crate::util::{promptsign_home, sha256_hex};
use crate::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const APPROVAL_PREDICATE: &str = "https://promptsign.dev/approval/v1";
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// The directory approvals live in: under `.promptsign/` beside the
/// artifact, and in the managed and user stores.
pub const APPROVALS_DIR: &str = "approvals";

/// An artifact's content listing and its digest (spec/09 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub text: String,
    /// Lower-case hex SHA-256 of `text`.
    pub digest: String,
    pub files: usize,
}

/// The listing of a manifest's files: `<sha256>  <path>` lines sorted by
/// path bytes.
pub fn listing_of(files: &[FileEntry]) -> Listing {
    let mut entries: Vec<&FileEntry> = files.iter().collect();

    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    let text: String = entries
        .iter()
        .map(|f| format!("{}  {}\n", f.sha256, f.path))
        .collect();

    Listing {
        digest: sha256_hex(text.as_bytes()),
        files: entries.len(),
        text,
    }
}

/// The manifest a signer would build for the artifact at `path`.
pub fn manifest_for(path: &Path) -> Result<Manifest> {
    let abs = std::path::absolute(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let opts = BuildOptions {
        name: None,
        version: None,
        kind: None,
    };

    if abs.is_dir() {
        return build_manifest(&abs, None, &opts);
    }

    let parent = abs
        .parent()
        .ok_or_else(|| format!("{}: no parent directory", abs.display()))?;

    build_manifest(parent, Some(&abs), &opts)
}

/// The listing of the artifact at `path`.
pub fn listing_for(path: &Path) -> Result<Listing> {
    Ok(listing_of(&manifest_for(path)?.files))
}

/// The approval statement for `digest`, as `promptsign approve` signs it.
/// `approved_at` keeps two approvers' statements, and so their payload
/// digests, apart (spec/09 §5).
pub fn statement(name: &str, digest: &str, approved_at: &str, note: Option<&str>) -> Value {
    let mut predicate = json!({ "approvedAt": approved_at });

    if let Some(n) = note {
        predicate["note"] = json!(n);
    }
    json!({
        "_type": STATEMENT_TYPE,
        "subject": [{ "name": name, "digest": { "sha256": digest } }],
        "predicateType": APPROVAL_PREDICATE,
        "predicate": predicate,
    })
}

/// A verified approval of the artifact under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    /// The approver: a certificate's SAN identity. In certificate mode, its
    /// SAN email, else its user principal name, else its subject DN.
    pub identity: String,
    /// OIDC issuer, or `x509:sha256:<root fingerprint>` in certificate mode.
    pub issuer: String,
    /// Registry name of the root the approval chained to.
    pub root: String,
    /// When the approver signed, if the signature proves it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<i64>,
    #[serde(skip)]
    pub payload_digest: String,
    #[serde(skip)]
    pub log_index: Option<i64>,
}

/// Why an approval file does not count.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    /// It verifies but approves other content, as an approval of an earlier
    /// version does. Verifiers skip it without a finding.
    OtherContent,
    Invalid(String),
}

/// Verify one approval bundle offline against `roots` (spec/09 §2, §3) and
/// check that it covers `digest`.
pub fn verify_approval(
    bundle: &Value,
    digest: &str,
    roots: &[Root],
    now: i64,
) -> std::result::Result<Approval, Rejected> {
    let invalid = Rejected::Invalid;
    let (identity, issuer, root, payload, signed_at, log_index) = if is_sigstore_bundle(bundle) {
        let vs = verify_sigstore_bundle(bundle, roots, now).map_err(invalid)?;

        if vs.payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(Rejected::Invalid(format!(
                "payloadType {} is not an in-toto statement",
                vs.payload_type
            )));
        }
        (
            vs.identity,
            vs.issuer,
            vs.root,
            vs.payload,
            vs.integrated_time,
            vs.log_index,
        )
    } else {
        let payload_type = bundle
            .pointer("/envelope/payloadType")
            .and_then(Value::as_str)
            .unwrap_or_default();

        if payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(Rejected::Invalid(format!(
                "payloadType \"{payload_type}\" is not an in-toto statement"
            )));
        }

        let keyless: Vec<Root> = roots.iter().filter(|r| !r.is_ca_only()).cloned().collect();
        let kv = verify_keyless_with(bundle, &keyless).map_err(invalid)?;

        (
            kv.identity,
            kv.issuer,
            kv.root,
            kv.payload,
            Some(kv.signed_at),
            bundle
                .pointer("/transparency/logIndex")
                .and_then(Value::as_i64),
        )
    };
    let doc: Value = serde_json::from_slice(&payload)
        .map_err(|e| Rejected::Invalid(format!("statement: {e}")))?;

    if doc["_type"] != STATEMENT_TYPE {
        return Err(Rejected::Invalid("not an in-toto Statement v1".into()));
    }
    if doc["predicateType"] != APPROVAL_PREDICATE {
        return Err(Rejected::Invalid(format!(
            "predicateType {} is not an approval",
            doc["predicateType"]
        )));
    }
    if !doc["predicate"].is_object() {
        return Err(Rejected::Invalid("predicate is not an object".into()));
    }

    let covers = doc["subject"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|s| s.pointer("/digest/sha256").and_then(Value::as_str) == Some(digest));

    if !covers {
        return Err(Rejected::OtherContent);
    }
    Ok(Approval {
        identity,
        issuer,
        root,
        signed_at,
        payload_digest: payload_digest_of(&payload),
        log_index,
    })
}

/// The `.promptsign/approvals/` directory that travels with the artifact.
pub fn local_dir(target: &Path, is_dir: bool) -> Option<PathBuf> {
    let base = if is_dir {
        Some(target)
    } else {
        target.parent()
    }?;

    Some(base.join(".promptsign").join(APPROVALS_DIR))
}

/// The user's store directory for `digest`.
pub fn user_store(digest: &str) -> PathBuf {
    promptsign_home().join(APPROVALS_DIR).join(digest)
}

/// Every approval file a verifier reads for an artifact (spec/09 §3).
pub fn approval_files(target: &Path, is_dir: bool, digest: &str) -> Vec<PathBuf> {
    let dirs = [
        local_dir(target, is_dir),
        Some(managed_dir().join(APPROVALS_DIR).join(digest)),
        Some(user_store(digest)),
    ];
    let mut files = Vec::new();

    for dir in dirs.into_iter().flatten() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut found: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json") && p.is_file())
            .collect();

        found.sort();
        files.extend(found);
    }
    files
}

/// The approvals that count for an artifact, minus revoked ones, and a
/// finding for each file that does not verify or that the feed revokes.
#[derive(Debug, Default)]
pub struct Collected {
    pub approvals: Vec<Approval>,
    pub findings: Vec<Finding>,
}

pub fn collect(
    files: &[PathBuf],
    digest: &str,
    roots: &[Root],
    feed: Option<&RevocationFeed>,
    now: i64,
) -> Collected {
    let mut out = Collected::default();
    let note = |file: &Path, why: String| Finding {
        level: "info".to_string(),
        message: format!("approval {} not counted: {why}", file.display()),
    };

    for file in files {
        let bundle = std::fs::read(file)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()));
        let approval = match bundle {
            Ok(b) => verify_approval(&b, digest, roots, now),
            Err(e) => Err(Rejected::Invalid(e)),
        };

        match approval {
            Ok(a) => {
                let revoked = feed.and_then(|f| {
                    check_revocation(
                        f,
                        &Subject {
                            identity: &a.identity,
                            issuer: Some(&a.issuer),
                            payload_digest: a.payload_digest.clone(),
                            log_index: a.log_index,
                            integrated_time: a.signed_at,
                        },
                    )
                });

                match revoked {
                    Some(reason) => out.findings.push(Finding {
                        level: "warn".to_string(),
                        message: format!("approval by {} revoked: {reason}", a.identity),
                    }),
                    None if out.approvals.contains(&a) => {}
                    None => out.approvals.push(a),
                }
            }
            Err(Rejected::OtherContent) => {}
            Err(Rejected::Invalid(why)) => out.findings.push(note(file, why)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, sha256: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            sha256: sha256.to_string(),
            role: None,
        }
    }

    #[test]
    fn the_listing_sorts_paths_by_bytes() {
        let l = listing_of(&[
            entry("scripts/run.py", "bb"),
            entry("SKILL.md", "aa"),
            entry("references/x.md", "cc"),
        ]);

        assert_eq!(
            l.text,
            "aa  SKILL.md\ncc  references/x.md\nbb  scripts/run.py\n"
        );
        assert_eq!(l.digest, sha256_hex(l.text.as_bytes()));
        assert_eq!(l.files, 3);
    }

    #[test]
    fn the_statement_names_the_digest_and_predicate() {
        let s = statement("acme/x", "ab12", "2026-10-16T00:00:00Z", Some("PR 412"));

        assert_eq!(s["subject"][0]["digest"]["sha256"], "ab12");
        assert_eq!(s["predicateType"], APPROVAL_PREDICATE);
        assert_eq!(s["predicate"]["note"], "PR 412");
        assert_eq!(
            statement("x", "ab", "2026-10-16T00:00:00Z", None)["predicate"],
            json!({ "approvedAt": "2026-10-16T00:00:00Z" })
        );
    }

    #[test]
    fn local_approvals_sit_beside_a_file_and_inside_a_directory() {
        let d = Path::new("/w/skill");

        assert_eq!(
            local_dir(d, true).unwrap(),
            d.join(".promptsign").join("approvals")
        );
        assert_eq!(
            local_dir(&d.join("CLAUDE.md"), false).unwrap(),
            d.join(".promptsign").join("approvals")
        );
    }
}
