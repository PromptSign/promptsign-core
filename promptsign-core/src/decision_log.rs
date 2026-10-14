// Local decision log (spec/08): one JSON line per verification, so a
// security team has evidence of what ran and why without a server. The
// verifier only writes the file; a SIEM agent or log shipper tails it.
//
// The managed policy or the user's policy turns it on with
// `decision_log: true`, and a command can name a file of its own. A failed
// write never changes a verdict.

use crate::managed;
use crate::policy::{find_user_policy, load_managed_policy, Action, DecidingRule, Finding, Policy};
use crate::revocation::RevocationState;
use crate::util::{iso8601_now, promptsign_home};
use crate::verify::VerifyResult;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DECISION_LOG_SCHEMA: &str = "promptsign/decision-log/v1";
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated copies kept beside the live file, `<file>.1` (newest) to `<file>.4`.
pub const ROTATED_COPIES: u32 = 4;

/// A file the verifier appends records to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sink {
    pub path: PathBuf,
    pub max_bytes: u64,
}

/// The OS user the verifier runs as, from the environment.
pub fn user() -> String {
    ["USER", "USERNAME"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The log's file name inside a log directory. Each user gets a file of their
/// own, so users of one machine never write to each other's.
pub fn file_name() -> String {
    let user: String = user()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();

    format!("decisions-{user}.jsonl")
}

/// The sink a policy layer asks for, if it turns the log on. A relative
/// `decision_log_dir` resolves against the directory of the policy file.
fn layer_sink(policy: &Policy, source: &str, default_dir: PathBuf) -> Option<Sink> {
    if policy.decision_log != Some(true) {
        return None;
    }

    let dir = match &policy.decision_log_dir {
        Some(d) => Path::new(source)
            .parent()
            .map(|p| p.join(d))
            .unwrap_or_else(|| PathBuf::from(d)),
        None => default_dir,
    };

    Some(Sink {
        path: dir.join(file_name()),
        max_bytes: policy.decision_log_max_bytes.unwrap_or(DEFAULT_MAX_BYTES),
    })
}

/// Every file this process logs to: the managed policy's, the user policy's,
/// then `explicit_file` (a command's own flag). A managed policy that does not
/// load still logs to the managed default, so its failures show up there.
pub fn sinks(explicit_policy: Option<&Path>, explicit_file: Option<&Path>) -> Vec<Sink> {
    let managed_default = managed::managed_dir().join("log");
    let mut out: Vec<Sink> = Vec::new();

    match load_managed_policy() {
        Ok(Some((policy, _, source))) => out.extend(layer_sink(&policy, &source, managed_default)),
        Ok(None) => {}
        Err(_) => out.push(Sink {
            path: managed_default.join(file_name()),
            max_bytes: DEFAULT_MAX_BYTES,
        }),
    }
    if let Ok(Some((policy, _, source))) = find_user_policy(explicit_policy) {
        out.extend(layer_sink(&policy, &source, promptsign_home().join("log")));
    }
    if let Some(file) = explicit_file {
        out.push(Sink {
            path: file.to_path_buf(),
            max_bytes: DEFAULT_MAX_BYTES,
        });
    }

    let mut unique: Vec<Sink> = Vec::new();

    for sink in out {
        if !unique.iter().any(|s| s.path == sink.path) {
            unique.push(sink);
        }
    }
    unique
}

/// Where a record comes from: which verifier, which harness, which event.
#[derive(Debug, Clone)]
pub struct Context {
    /// `<implementation>/<version>`, e.g. `promptsign-cli/0.7.0`.
    pub verifier: String,
    /// `claude`, `codex` or `openclaw` for a hook; absent for a command.
    pub harness: Option<String>,
    /// The hook event (`SessionStart`, `PreToolUse`, ...) or the command
    /// (`verify`, `verify-tree`).
    pub event: String,
}

/// What an enforcement point did with the event a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block,
}

/// One line of the log. Field order is the wire order.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub time: String,
    pub verifier: String,
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrated_time: Option<i64>,
    /// `pass`, `warn` or `fail`; `unresolved` when the target was not found,
    /// `error` when the verifier could not run.
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<DecidingRule>,
    /// `clear`, `revoked`, `stale`, `unavailable`, or `unchecked` when no
    /// revocation feed applies.
    pub revocation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_source: Option<String>,
    pub findings: Vec<Finding>,
}

fn absolute(target: &str) -> String {
    std::path::absolute(target)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| target.to_string())
}

impl Record {
    fn base(ctx: &Context, name: String, result: &str, decision: Option<Decision>) -> Record {
        Record {
            schema: DECISION_LOG_SCHEMA,
            time: iso8601_now(),
            verifier: ctx.verifier.clone(),
            user: user(),
            harness: ctx.harness.clone(),
            event: ctx.event.clone(),
            target: None,
            name,
            format: None,
            signed: false,
            payload_digest: None,
            identity: None,
            issuer: None,
            root: None,
            integrated_time: None,
            result: result.to_string(),
            decision,
            rule: None,
            revocation: "unchecked".to_string(),
            policy_source: None,
            findings: Vec::new(),
        }
    }

    /// The record of one verification.
    pub fn verified(ctx: &Context, r: &VerifyResult, decision: Option<Decision>) -> Record {
        Record {
            target: Some(absolute(&r.target)),
            format: r.format.clone(),
            signed: r.signed,
            payload_digest: r.evidence.payload_digest.clone(),
            identity: r.identity.clone(),
            issuer: r.issuer.clone(),
            root: r.root.clone(),
            integrated_time: r.integrated_time,
            rule: r.evidence.rule.clone(),
            revocation: match r.evidence.revocation {
                None => "unchecked",
                Some(RevocationState::Clear) => "clear",
                Some(RevocationState::Revoked) => "revoked",
                Some(RevocationState::Stale) => "stale",
                Some(RevocationState::Unavailable) => "unavailable",
            }
            .to_string(),
            policy_source: Some(r.policy_source.clone()),
            findings: r.findings.clone(),
            ..Record::base(ctx, r.name.clone(), r.action.as_str(), decision)
        }
    }

    /// The record of one verification, from a `VerifyResult` in its JSON
    /// form plus its `evidence`, as the Node binding returns them. A caller
    /// may have changed the action or added findings before logging it.
    pub fn from_json(ctx: &Context, r: &Value, decision: Option<Decision>) -> Record {
        let text = |key: &str| r[key].as_str().map(str::to_string);
        let evidence = &r["evidence"];
        let rule = evidence["rule"].as_object().map(|o| DecidingRule {
            layer: o
                .get("layer")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            pattern: o
                .get("pattern")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            action: o
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
        let findings = r["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|f| Finding {
                level: f["level"].as_str().unwrap_or_default().to_string(),
                message: f["message"].as_str().unwrap_or_default().to_string(),
            })
            .collect();

        Record {
            target: text("target").map(|t| absolute(&t)),
            format: text("format"),
            signed: r["signed"].as_bool().unwrap_or(false),
            payload_digest: evidence["payloadDigest"].as_str().map(str::to_string),
            identity: text("identity"),
            issuer: text("issuer"),
            root: text("root"),
            integrated_time: r["integratedTime"].as_i64(),
            rule,
            revocation: evidence["revocation"]
                .as_str()
                .unwrap_or("unchecked")
                .to_string(),
            policy_source: text("policySource"),
            findings,
            ..Record::base(
                ctx,
                text("name").unwrap_or_default(),
                r["action"].as_str().unwrap_or("error"),
                decision,
            )
        }
    }

    /// A target the hook could not find on disk, so nothing was verified.
    pub fn unresolved(ctx: &Context, name: &str, message: String, decision: Decision) -> Record {
        Record {
            findings: vec![Finding {
                level: if decision == Decision::Block {
                    "error"
                } else {
                    "warn"
                }
                .to_string(),
                message,
            }],
            ..Record::base(ctx, name.to_string(), "unresolved", Some(decision))
        }
    }

    /// A verification that could not run.
    pub fn error(
        ctx: &Context,
        name: &str,
        target: Option<&str>,
        message: String,
        decision: Option<Decision>,
    ) -> Record {
        Record {
            target: target.map(absolute),
            findings: vec![Finding {
                level: "error".to_string(),
                message,
            }],
            ..Record::base(ctx, name.to_string(), "error", decision)
        }
    }
}

/// `allow`, or `block` when the action fails.
pub fn decision_for(action: Action) -> Decision {
    if action == Action::Fail {
        Decision::Block
    } else {
        Decision::Allow
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();

    s.push(suffix);
    PathBuf::from(s)
}

/// `<file>` becomes `<file>.1`, `<file>.1` becomes `<file>.2`, and so on; the
/// oldest copy is dropped.
fn rotate(path: &Path) -> std::io::Result<()> {
    for i in (1..ROTATED_COPIES).rev() {
        let from = suffixed(path, &format!(".{i}"));

        if from.exists() {
            fs::rename(&from, suffixed(path, &format!(".{}", i + 1)))?;
        }
    }
    fs::rename(path, suffixed(path, ".1"))
}

/// Append `text` to one sink, rotating first when it would pass the limit.
/// A lock file beside the log serializes writers of the same file.
fn append_to(sink: &Sink, text: &str) -> std::io::Result<()> {
    if let Some(dir) = sink.path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }

    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(suffixed(&sink.path, ".lock"))?;

    lock.lock()?;

    let len = fs::metadata(&sink.path).map(|m| m.len()).unwrap_or(0);

    if len > 0 && len + text.len() as u64 > sink.max_bytes {
        rotate(&sink.path)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&sink.path)?
        .write_all(text.as_bytes())
}

/// Append records to every sink. Returns one message per sink that could not
/// be written, for the caller to report.
pub fn append(sinks: &[Sink], records: &[Record]) -> Vec<String> {
    if sinks.is_empty() || records.is_empty() {
        return Vec::new();
    }

    let text: String = records
        .iter()
        .map(|r| serde_json::to_string(r).unwrap_or_default() + "\n")
        .collect();

    sinks
        .iter()
        .filter_map(|s| {
            append_to(s, &text)
                .err()
                .map(|e| format!("decision log {}: {e}", s.path.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ps-dlog-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        fs::create_dir_all(&d).unwrap();
        d
    }

    fn ctx() -> Context {
        Context {
            verifier: "test/0".to_string(),
            harness: Some("claude".to_string()),
            event: "PreToolUse".to_string(),
        }
    }

    #[test]
    fn records_are_one_json_line_each_in_wire_order() {
        let dir = tmp_dir("lines");
        let sink = Sink {
            path: dir.join("log.jsonl"),
            max_bytes: DEFAULT_MAX_BYTES,
        };
        let record = Record::unresolved(&ctx(), "demo", "not found".into(), Decision::Allow);

        assert!(append(std::slice::from_ref(&sink), &[record.clone(), record]).is_empty());

        let text = fs::read_to_string(&sink.path).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(r#"{"schema":"promptsign/decision-log/v1","time":"#));
        assert!(lines[0].contains(
            r#""harness":"claude","event":"PreToolUse","name":"demo","signed":false,"result":"unresolved","decision":"allow","revocation":"unchecked","findings":[{"level":"warn","message":"not found"}]}"#
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_result_round_trips_through_its_json_form() {
        let r = VerifyResult {
            target: "/x/skill".into(),
            policy_source: "/p.json".into(),
            name: "acme/skill".into(),
            version: None,
            kind: None,
            identity: Some("alice@acme.test".into()),
            issuer: Some("https://sso.acme.test".into()),
            keyid: Some(String::new()),
            integrated_time: Some(1_790_000_000),
            format: Some("promptsign".into()),
            root: Some("acme/prod".into()),
            signed: true,
            action: Action::Warn,
            findings: vec![Finding {
                level: "warn".into(),
                message: "m".into(),
            }],
            evidence: crate::verify::Evidence {
                payload_digest: Some("sha256:ab".into()),
                rule: Some(DecidingRule {
                    layer: "managed".into(),
                    pattern: "acme/*".into(),
                    action: "warn".into(),
                }),
                revocation: Some(RevocationState::Stale),
            },
        };
        let mut json = serde_json::to_value(&r).unwrap();

        json["evidence"] = serde_json::to_value(&r.evidence).unwrap();

        let mut direct = Record::verified(&ctx(), &r, Some(Decision::Block));
        let mut back = Record::from_json(&ctx(), &json, Some(Decision::Block));

        direct.time.clear();
        back.time.clear();
        assert_eq!(
            serde_json::to_string(&direct).unwrap(),
            serde_json::to_string(&back).unwrap()
        );
    }

    #[test]
    fn the_log_rotates_at_its_limit_and_keeps_four_copies() {
        let dir = tmp_dir("rotate");
        let sink = Sink {
            path: dir.join("log.jsonl"),
            max_bytes: 1,
        };
        let record = Record::unresolved(&ctx(), "demo", "x".into(), Decision::Block);

        for _ in 0..7 {
            assert!(append(std::slice::from_ref(&sink), std::slice::from_ref(&record)).is_empty());
        }
        for i in 1..=4 {
            assert!(suffixed(&sink.path, &format!(".{i}")).is_file(), "copy {i}");
        }
        assert!(!suffixed(&sink.path, ".5").exists());
        assert_eq!(fs::read_to_string(&sink.path).unwrap().lines().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_log_dir_resolves_against_the_policy_file() {
        let policy = Policy {
            decision_log: Some(true),
            decision_log_dir: Some("logs".into()),
            decision_log_max_bytes: Some(5),
            ..crate::policy::default_policy()
        };
        let sink = layer_sink(&policy, "/etc/promptsign/managed-policy.json", "/x".into()).unwrap();

        assert_eq!(
            sink.path,
            Path::new("/etc/promptsign/logs").join(file_name())
        );
        assert_eq!(sink.max_bytes, 5);
        assert!(layer_sink(&crate::policy::default_policy(), "/p.json", "/x".into()).is_none());
    }

    #[test]
    fn file_names_keep_only_safe_characters() {
        assert!(file_name().starts_with("decisions-"));
        assert!(file_name()
            .trim_start_matches("decisions-")
            .trim_end_matches(".jsonl")
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')));
    }
}
