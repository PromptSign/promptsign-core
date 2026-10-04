// Full verification pipeline for one target:
//   1. locate bundle   2. verify envelope (crypto)   3. re-verify integrity
//   against disk   4. evaluate trust policy + TOFU pins.

use crate::bundle::{has_signature_marker, locate_bundle, verify_envelope, BundleSource};
use crate::manifest::{
    check_file_integrity, check_integrity, strip_md_ext, walk_files, CONTEXT_INJECTED,
};
use crate::oms;
use crate::policy::{
    evaluate, load_pins, load_policy, match_rule, save_pins, Action, EvalInput, Finding, Pins,
    Policy,
};
use crate::revocation::{self, Subject};
use crate::trustroot::load_registry;
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub policy_path: Option<PathBuf>,
    pub no_pin_updates: bool,
    pub skip_policy: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub target: String,
    #[serde(rename = "policySource")]
    pub policy_source: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub keyid: Option<String>,
    /// Rekor log integration time (Unix seconds) for keyless signatures — the
    /// authenticated moment the signature was witnessed. Absent for local-key
    /// signatures and on any unverified/failed path.
    #[serde(rename = "integratedTime", skip_serializing_if = "Option::is_none")]
    pub integrated_time: Option<i64>,
    /// Signature format: "promptsign" or "oms". Absent when unsigned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Trust root the signer chained to (keyless and certificate mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    pub signed: bool,
    pub action: Action,
    pub findings: Vec<Finding>,
}

/// The Rekor integration time stapled in an authenticated bundle, if present.
/// Only meaningful after `verify_envelope` succeeds (transparency was checked).
fn integrated_time_of(bundle_value: &Value) -> Option<i64> {
    bundle_value
        .pointer("/transparency/integratedTime")
        .and_then(|v| v.as_i64())
}

fn basename(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Build the revocation match-subject from an authenticated bundle. The payload
/// and transparency fields were already validated by `verify_envelope`, so reading
/// them back from the raw value here is safe.
fn revocation_subject<'a>(
    bundle_value: &Value,
    identity: &'a str,
    issuer: Option<&'a str>,
) -> Subject<'a> {
    let payload = BASE64_STANDARD
        .decode(
            bundle_value
                .pointer("/envelope/payload")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .unwrap_or_default();

    Subject {
        identity,
        issuer,
        payload_digest: revocation::payload_digest_of(&payload),
        log_index: bundle_value
            .pointer("/transparency/logIndex")
            .and_then(|v| v.as_i64()),
        integrated_time: bundle_value
            .pointer("/transparency/integratedTime")
            .and_then(|v| v.as_i64()),
    }
}

fn policy_off(policy: &Policy, name: &str) -> bool {
    let rule = match_rule(policy, name);
    let level = rule
        .action
        .or_else(|| policy.default_action.clone())
        .unwrap_or_else(|| "warn".to_string());

    level == "off"
}

/// An `x-promptsign:` marker inside a context-injected file (CLAUDE.md/AGENTS.md)
/// is never a signature — its presence is a failure. Returns the warning message
/// for such a file, if it applies.
fn marker_message(path: &Path, display: &str) -> Option<String> {
    if !CONTEXT_INJECTED.contains(&basename(path).as_str()) {
        return None;
    }

    let data = std::fs::read(path).ok()?;

    if has_signature_marker(&String::from_utf8_lossy(&data)) {
        Some(format!(
            "{display} carries an embedded x-promptsign marker, which is not a valid signature \
             for context-injected files — treat as untrusted; sign it with a sidecar instead"
        ))
    } else {
        None
    }
}

fn context_marker_messages(abs: &Path, is_dir: bool) -> Vec<String> {
    let mut msgs = Vec::new();

    if is_dir {
        if let Ok(rels) = walk_files(abs) {
            for rel in rels {
                if let Some(m) = marker_message(&abs.join(&rel), &rel) {
                    msgs.push(m);
                }
            }
        }
    } else if let Some(m) = marker_message(abs, &basename(abs)) {
        msgs.push(m);
    }
    msgs
}

/// Fold context-injected marker warnings into a result: they add findings and
/// force at least `Fail` (downgraded to `Warn` only under a policy `off`, so the
/// warning is surfaced either way).
fn apply_markers(
    msgs: &[String],
    policy: &Policy,
    name: &str,
    findings: &mut Vec<Finding>,
    action: &mut Action,
) {
    if msgs.is_empty() {
        return;
    }

    let off = policy_off(policy, name);
    let level = if off { "warn" } else { "error" };

    for m in msgs {
        findings.push(Finding {
            level: level.to_string(),
            message: m.clone(),
        });
    }

    let bump = if off { Action::Warn } else { Action::Fail };

    if bump > *action {
        *action = bump;
    }
}

pub fn verify_target(target: &str, opts: &VerifyOptions) -> Result<VerifyResult> {
    let project_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let (policy, _raw, policy_source) = load_policy(opts.policy_path.as_deref(), &project_dir)?;
    let abs = std::path::absolute(target).map_err(|e| format!("{target}: {e}"))?;
    let md = std::fs::metadata(&abs).map_err(|e| format!("{}: {e}", abs.display()))?;
    let is_dir = md.is_dir();
    let fallback_name = strip_md_ext(&basename(&abs));
    let marker_msgs = context_marker_messages(&abs, is_dir);

    let (bundle_value, _bundle_path) = match locate_bundle(&abs)? {
        // No PromptSign bundle: an OMS signature in the directory is the
        // signature to check, and a broken one is invalid, never unsigned.
        BundleSource::None if is_dir && oms::signature_file(&abs).is_some() => {
            return verify_oms(target, opts);
        }
        BundleSource::None => {
            let out = evaluate(
                &policy,
                &EvalInput {
                    name: &fallback_name,
                    identity: None,
                    keyid: None,
                    issuer: None,
                    root: None,
                    signed: false,
                },
                &Pins::new(),
            );
            let mut findings = out.findings;
            let mut action = out.action;

            apply_markers(
                &marker_msgs,
                &policy,
                &fallback_name,
                &mut findings,
                &mut action,
            );
            return Ok(VerifyResult {
                target: target.to_string(),
                policy_source,
                name: fallback_name,
                version: None,
                kind: None,
                identity: None,
                issuer: None,
                keyid: None,
                integrated_time: None,
                format: None,
                root: None,
                signed: false,
                action,
                findings,
            });
        }
        BundleSource::CarriageError(msg) => {
            let off = policy_off(&policy, &fallback_name);
            let mut action = if off { Action::Warn } else { Action::Fail };
            let mut findings = vec![Finding {
                level: if off { "warn" } else { "error" }.to_string(),
                message: format!("invalid embedded signature: {msg}"),
            }];

            apply_markers(
                &marker_msgs,
                &policy,
                &fallback_name,
                &mut findings,
                &mut action,
            );
            return Ok(VerifyResult {
                target: target.to_string(),
                policy_source,
                name: fallback_name,
                version: None,
                kind: None,
                identity: None,
                issuer: None,
                keyid: None,
                integrated_time: None,
                format: Some(FORMAT_PROMPTSIGN.to_string()),
                root: None,
                signed: true,
                action,
                findings,
            });
        }
        BundleSource::Found { value, path } => (value, path),
    };

    let envelope = match verify_envelope(&bundle_value) {
        Ok(env) => env,
        Err(e) => {
            return Ok(signature_failure(
                target,
                &policy,
                policy_source,
                &marker_msgs,
                fallback_name,
                FORMAT_PROMPTSIGN,
                format!("invalid signature: {e}"),
            ))
        }
    };

    let manifest = envelope.manifest;
    let mut findings: Vec<Finding> = Vec::new();
    let mut action = Action::Pass;

    // Integrity failures are unconditional: a valid signature over content that
    // no longer matches the disk is a tampered artifact, whatever policy says.
    // File scope checks the target file itself; directory scope walks the tree.
    let problems = if manifest.scope.as_deref() == Some("file") {
        check_file_integrity(&abs, &manifest)?
    } else {
        check_integrity(&abs, &manifest)?
    };

    for problem in problems {
        findings.push(Finding {
            level: "error".to_string(),
            message: problem,
        });
        action = Action::Fail;
    }

    let subject = revocation_subject(&bundle_value, "", None);
    let signed = Signed {
        name: manifest.name,
        version: manifest.version,
        kind: manifest.kind,
        identity: envelope.identity,
        issuer: envelope.issuer,
        keyid: envelope.keyid,
        root: envelope.root,
        integrated_time: integrated_time_of(&bundle_value),
        format: FORMAT_PROMPTSIGN,
        payload_digest: subject.payload_digest,
        log_index: subject.log_index,
    };
    let mut result = finish(
        target,
        &policy,
        policy_source,
        &marker_msgs,
        opts,
        signed,
        findings,
        action,
    )?;

    // A PromptSign bundle takes precedence over an OMS signature beside it.
    if let Some(oms_sig) = is_dir.then(|| oms::signature_file(&abs)).flatten() {
        result.findings.push(Finding {
            level: "info".to_string(),
            message: format!(
                "{} not checked: the PromptSign signature takes precedence",
                basename(&oms_sig)
            ),
        });
    }
    Ok(result)
}

const FORMAT_PROMPTSIGN: &str = "promptsign";
const FORMAT_OMS: &str = "oms";

/// What the signature step established, whatever format the bundle used.
struct Signed {
    name: String,
    version: Option<String>,
    kind: Option<String>,
    identity: String,
    /// OIDC issuer (keyless) or `x509:sha256:<root>` (certificate mode).
    issuer: Option<String>,
    keyid: String,
    root: Option<String>,
    integrated_time: Option<i64>,
    format: &'static str,
    payload_digest: String,
    log_index: Option<i64>,
}

/// Policy, markers, revocation and TOFU pins over an authenticated signer.
/// `findings`/`action` carry the integrity results so far.
#[allow(clippy::too_many_arguments)]
fn finish(
    target: &str,
    policy: &Policy,
    policy_source: String,
    marker_msgs: &[String],
    opts: &VerifyOptions,
    signed: Signed,
    mut findings: Vec<Finding>,
    mut action: Action,
) -> Result<VerifyResult> {
    if opts.skip_policy {
        // No policy to consult, but a marker on a context-injected file must
        // still fail (self-check safety) — mirror integrity's unconditional Fail.
        for m in marker_msgs {
            findings.push(Finding {
                level: "error".to_string(),
                message: m.clone(),
            });
            action = Action::Fail;
        }
        return Ok(VerifyResult {
            target: target.to_string(),
            policy_source: "(skipped)".to_string(),
            name: signed.name,
            version: signed.version,
            kind: signed.kind,
            identity: Some(signed.identity),
            issuer: signed.issuer,
            keyid: Some(signed.keyid),
            integrated_time: signed.integrated_time,
            format: Some(signed.format.to_string()),
            root: signed.root,
            signed: true,
            action,
            findings,
        });
    }

    let mut pins = load_pins()?;
    // Keyless and certificate-mode signers pin identity+issuer, never the key
    // (spec/05 §5): the ephemeral key changes every signing, a leaf rotates.
    let pin_keyid: &str = if signed.issuer.is_some() {
        ""
    } else {
        &signed.keyid
    };
    let out = evaluate(
        policy,
        &EvalInput {
            name: &signed.name,
            identity: Some(&signed.identity),
            keyid: Some(pin_keyid),
            issuer: signed.issuer.as_deref(),
            root: signed.root.as_deref(),
            signed: true,
        },
        &pins,
    );

    findings.extend(out.findings);
    if out.action > action {
        action = out.action;
    }

    apply_markers(
        marker_msgs,
        policy,
        &signed.name,
        &mut findings,
        &mut action,
    );

    // Revocation feed (spec/06): "valid yesterday, killed today". Consulted only
    // when a feed is configured; every subject field comes from the
    // authenticated bundle.
    if policy.revocation_feed.is_some() {
        let subject = Subject {
            identity: &signed.identity,
            issuer: signed.issuer.as_deref(),
            payload_digest: signed.payload_digest.clone(),
            log_index: signed.log_index,
            integrated_time: signed.integrated_time,
        };
        let rev = revocation::evaluate(policy, &subject);

        findings.extend(rev.findings);
        if rev.action > action {
            action = rev.action;
        }
    }

    if action != Action::Fail && !opts.no_pin_updates {
        if let Some(pin) = out.pin_update {
            findings.push(Finding {
                level: "info".to_string(),
                message: format!(
                    "pinned \"{}\" to identity \"{}\" (trust on first use)",
                    signed.name, signed.identity
                ),
            });
            pins.insert(pin.name.clone(), pin);
            save_pins(&pins)?;
        }
    }

    Ok(VerifyResult {
        target: target.to_string(),
        policy_source,
        name: signed.name,
        version: signed.version,
        kind: signed.kind,
        identity: Some(signed.identity),
        issuer: signed.issuer,
        keyid: Some(signed.keyid),
        integrated_time: signed.integrated_time,
        format: Some(signed.format.to_string()),
        root: signed.root,
        signed: true,
        action,
        findings,
    })
}

/// A signature that does not verify is never silently ignored: at least a
/// warning even under action "off", a failure under "warn"/"enforce".
fn signature_failure(
    target: &str,
    policy: &Policy,
    policy_source: String,
    marker_msgs: &[String],
    name: String,
    format: &'static str,
    message: String,
) -> VerifyResult {
    let off = policy_off(policy, &name);
    let mut action = if off { Action::Warn } else { Action::Fail };
    let mut findings = vec![Finding {
        level: if action == Action::Fail {
            "error"
        } else {
            "warn"
        }
        .to_string(),
        message,
    }];

    apply_markers(marker_msgs, policy, &name, &mut findings, &mut action);
    VerifyResult {
        target: target.to_string(),
        policy_source,
        name,
        version: None,
        kind: None,
        identity: None,
        issuer: None,
        keyid: None,
        integrated_time: None,
        format: Some(format.to_string()),
        root: None,
        signed: true,
        action,
        findings,
    }
}

/// Verify a directory signed with OpenSSF Model Signing (`skill.oms.sig` or
/// `model.sig`) against the user's trust roots, then apply the same policy,
/// markers, revocation and pins as a PromptSign bundle.
pub fn verify_oms(target: &str, opts: &VerifyOptions) -> Result<VerifyResult> {
    let project_dir = std::env::current_dir().map_err(|e| e.to_string())?;
    let (policy, _raw, policy_source) = load_policy(opts.policy_path.as_deref(), &project_dir)?;
    let abs = std::path::absolute(target).map_err(|e| format!("{target}: {e}"))?;

    if !abs.is_dir() {
        return Err(format!(
            "{}: OMS signatures cover directories",
            abs.display()
        ));
    }

    let sig_path = oms::signature_file(&abs)
        .ok_or_else(|| format!("no OMS signature file in {}", abs.display()))?;
    let sig_name = basename(&sig_path);
    let fallback_name = basename(&abs);
    let marker_msgs = context_marker_messages(&abs, true);
    let outcome = std::fs::read(&sig_path)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()))
        .and_then(|bundle| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or_default();

            oms::verify_oms_bundle(&abs, &bundle, &sig_name, &load_registry()?, now)
        });
    let out = match outcome {
        Ok(out) => out,
        Err(e) => {
            return Ok(signature_failure(
                target,
                &policy,
                policy_source,
                &marker_msgs,
                fallback_name,
                FORMAT_OMS,
                format!("invalid signature: {e}"),
            ))
        }
    };
    let signed = Signed {
        name: out.name,
        version: None,
        kind: Some(out.kind.to_string()),
        identity: out.signer.identity,
        issuer: Some(out.signer.issuer),
        keyid: out.signer.leaf_keyid,
        root: Some(out.signer.root),
        integrated_time: out.signer.integrated_time,
        format: FORMAT_OMS,
        payload_digest: revocation::payload_digest_of(&out.signer.payload),
        log_index: out.signer.log_index,
    };

    finish(
        target,
        &policy,
        policy_source,
        &marker_msgs,
        opts,
        signed,
        out.findings,
        out.action,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("psgate-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);

        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn context_injected_markers_are_gated() {
        let d = tmpdir("marker");

        fs::write(
            d.join("CLAUDE.md"),
            "---\nx-promptsign: abc\n---\n# Project\n",
        )
        .unwrap();
        // OpenClaw workspace bootstrap files are context-injected too.
        fs::write(d.join("SOUL.md"), "---\nx-promptsign: abc\n---\n# Soul\n").unwrap();
        // reviewer.md is structured-frontmatter — a marker there is NOT gated.
        fs::write(
            d.join("reviewer.md"),
            "---\nx-promptsign: abc\n---\n# Reviewer\n",
        )
        .unwrap();

        // Dir scope: only the context-injected CLAUDE.md and SOUL.md are flagged.
        let msgs = context_marker_messages(&d, true);

        assert_eq!(msgs.len(), 2, "{msgs:?}");
        assert!(msgs.iter().any(|m| m.contains("CLAUDE.md")));
        assert!(msgs.iter().any(|m| m.contains("SOUL.md")));

        // File scope: the CLAUDE.md / SOUL.md targets themselves are flagged.
        assert_eq!(
            context_marker_messages(&d.join("CLAUDE.md"), false).len(),
            1
        );
        assert_eq!(context_marker_messages(&d.join("SOUL.md"), false).len(), 1);
        // reviewer.md target is not gated.
        assert!(context_marker_messages(&d.join("reviewer.md"), false).is_empty());

        // A gated file WITHOUT a marker is clean.
        fs::write(d.join("AGENTS.md"), "---\nname: a\n---\n# A\n").unwrap();
        assert!(context_marker_messages(&d.join("AGENTS.md"), false).is_empty());

        let _ = fs::remove_dir_all(&d);
    }
}
