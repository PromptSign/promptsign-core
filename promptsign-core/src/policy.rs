// Trust policy evaluation and TOFU pin store (spec/04-policy.md).
// A signature without policy is meaningless: anyone can validly sign as
// themselves. Policy decides which identities may sign which names.

use crate::util::{glob_match, iso8601_now, promptsign_home, short16, write_private};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const POLICY_SCHEMA: &str = "promptsign/policy/v1";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Rule {
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    /// Registry root (spec/04) the signature must chain to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tofu: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub schema: String,
    #[serde(rename = "default", skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    // Revocation feed (spec/06). Absent `revocation_feed` = not consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_feed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_feed_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_feed_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_feed_staleness: Option<String>,
    /// "warn" (default) or "fail": how verify degrades when the feed is stale or
    /// missing. A revoked artifact always fails regardless of this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_feed_stale: Option<String>,
}

pub fn default_policy() -> Policy {
    Policy {
        schema: POLICY_SCHEMA.to_string(),
        default_action: Some("warn".to_string()),
        rules: vec![Rule {
            pattern: "*".to_string(),
            action: Some("warn".to_string()),
            tofu: Some(true),
            ..Default::default()
        }],
        revocation_feed: None,
        revocation_feed_identity: None,
        revocation_feed_issuer: None,
        max_feed_staleness: None,
        on_feed_stale: None,
    }
}

fn read_policy_file(p: &Path) -> Result<(Policy, Value)> {
    let text = fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let raw: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;

    if raw.get("schema").and_then(|s| s.as_str()) != Some(POLICY_SCHEMA) {
        return Err(format!("{}: unsupported policy schema", p.display()));
    }

    let policy: Policy =
        serde_json::from_value(raw.clone()).map_err(|e| format!("{}: {e}", p.display()))?;

    Ok((policy, raw))
}

/// The user's policy (spec/04). Resolution order: explicit path,
/// $PROMPTSIGN_POLICY, ~/.promptsign/policy.json, built-in default. A project
/// directory never supplies it: see [`load_project_policy`].
/// The raw Value is kept alongside the typed policy so `policy show` can
/// print unknown fields (revocation_feed, require_attestations, ...) verbatim.
pub fn load_policy(explicit: Option<&Path>) -> Result<(Policy, Value, String)> {
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();

    if let Some(p) = explicit {
        candidates.push((p.to_path_buf(), true));
    }
    if let Ok(env_p) = std::env::var("PROMPTSIGN_POLICY") {
        if !env_p.is_empty() {
            candidates.push((PathBuf::from(env_p), false));
        }
    }
    candidates.push((promptsign_home().join("policy.json"), false));

    for (p, is_explicit) in candidates {
        if p.exists() {
            let (policy, raw) = read_policy_file(&p)?;

            return Ok((policy, raw, p.display().to_string()));
        }
        if is_explicit {
            return Err(format!("policy not found: {}", p.display()));
        }
    }

    let policy = default_policy();
    let raw = serde_json::to_value(&policy).unwrap();

    Ok((policy, raw, "(built-in default)".to_string()))
}

pub fn project_policy_path(project_dir: &Path) -> PathBuf {
    project_dir.join(".promptsign").join("policy.json")
}

/// A project's own policy, `<project>/.promptsign/policy.json`, if it has
/// one. The project is untrusted input: this policy can only add
/// requirements on top of the user's, never relax them or add trust.
pub fn load_project_policy(project_dir: &Path) -> Result<Option<(Policy, Value, String)>> {
    let p = project_policy_path(project_dir);

    if !p.exists() {
        return Ok(None);
    }

    let (policy, raw) = read_policy_file(&p)?;

    Ok(Some((policy, raw, p.display().to_string())))
}

/// The user's policy plus, when present, the project's tighten-only policy.
pub struct EffectivePolicy {
    pub user: Policy,
    pub project: Option<Policy>,
    /// Display form: the user's source, then the project's when present.
    pub source: String,
}

pub fn load_effective_policy(
    explicit: Option<&Path>,
    project_dir: &Path,
) -> Result<EffectivePolicy> {
    let (user, _raw, user_source) = load_policy(explicit)?;
    let project = load_project_policy(project_dir)?;
    let source = match &project {
        Some((_, _, p)) => format!("{user_source} + {p} (tighten only)"),
        None => user_source,
    };

    Ok(EffectivePolicy {
        user,
        project: project.map(|(p, _, _)| p),
        source,
    })
}

/// First matching rule wins; fall back to the policy default action.
pub fn match_rule(policy: &Policy, name: &str) -> Rule {
    policy
        .rules
        .iter()
        .find(|r| glob_match(&r.pattern, name))
        .cloned()
        .unwrap_or_else(|| Rule {
            pattern: "*".to_string(),
            action: Some(
                policy
                    .default_action
                    .clone()
                    .unwrap_or_else(|| "warn".to_string()),
            ),
            ..Default::default()
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    pub name: String,
    pub identity: String,
    pub keyid: String,
    /// Present only for keyless pins: the ephemeral key changes every signing,
    /// so keyless pins bind identity+issuer with an empty keyid (spec/05 §5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub first_seen: String,
}

pub type Pins = BTreeMap<String, Pin>;

fn pins_path() -> PathBuf {
    promptsign_home().join("pins.json")
}

pub fn load_pins() -> Result<Pins> {
    let p = pins_path();

    if !p.exists() {
        return Ok(Pins::new());
    }

    let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;

    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn save_pins(pins: &Pins) -> Result<()> {
    let home = promptsign_home();

    fs::create_dir_all(&home).map_err(|e| format!("{}: {e}", home.display()))?;

    let p = pins_path();

    write_private(&p, serde_json::to_string_pretty(pins).unwrap() + "\n")
        .map_err(|e| format!("{}: {e}", p.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Warn,
    Fail,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Warn => "warn",
            Action::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: String,
    pub message: String,
}

pub struct EvalInput<'a> {
    pub name: &'a str,
    pub identity: Option<&'a str>,
    /// Empty string for keyless bundles: pins must not bind ephemeral keys.
    pub keyid: Option<&'a str>,
    /// OIDC issuer — present iff the bundle is keyless.
    pub issuer: Option<&'a str>,
    /// Registry root the signature chained to; absent for keyful bundles.
    pub root: Option<&'a str>,
    pub signed: bool,
}

pub struct EvalOutcome {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub rule: Rule,
    pub pin_update: Option<Pin>,
}

/// Evaluate a verified signer against policy. `signed: false` means no bundle
/// was found at all. Action is the worst outcome across all checks.
/// The part of an identity a TOFU pin binds (spec/05 §5). A keyless CI
/// identity is a workflow URI ending in `@refs/...`; every release tag changes
/// that suffix, so the pin binds the workflow and ignores the ref. Keyful
/// identities are free-form and compared whole.
fn pin_identity<'a>(identity: &'a str, issuer: Option<&str>) -> &'a str {
    // A certificate-mode signer is pinned by its root (the issuer carries the
    // root fingerprint), so a rotated leaf under the same root keeps passing.
    if issuer.is_some_and(|i| i.starts_with("x509:")) {
        return "";
    }
    if issuer.is_none() || !identity.starts_with("https://") {
        return identity;
    }
    match identity.find("@refs/") {
        Some(at) => &identity[..at],
        None => identity,
    }
}

pub fn evaluate(policy: &Policy, input: &EvalInput, pins: &Pins) -> EvalOutcome {
    let rule = match_rule(policy, input.name);
    let level = rule
        .action
        .clone()
        .or_else(|| policy.default_action.clone())
        .unwrap_or_else(|| "warn".to_string());
    let mut findings: Vec<Finding> = Vec::new();
    let mut action = Action::Pass;
    let violate = |message: String, findings: &mut Vec<Finding>, action: &mut Action| {
        if level == "off" {
            return;
        }

        let enforce = level == "enforce";

        findings.push(Finding {
            level: if enforce { "error" } else { "warn" }.to_string(),
            message,
        });

        let to = if enforce { Action::Fail } else { Action::Warn };

        if to > *action {
            *action = to;
        }
    };

    if !input.signed {
        violate(
            format!(
                "unsigned artifact \"{}\" (rule: {})",
                input.name, rule.pattern
            ),
            &mut findings,
            &mut action,
        );
        return EvalOutcome {
            action,
            findings,
            rule,
            pin_update: None,
        };
    }

    let identity = input.identity.unwrap_or("");
    let keyid = input.keyid.unwrap_or("");

    if let Some(rule_identity) = &rule.identity {
        if !glob_match(rule_identity, identity) {
            violate(
                format!(
                    "identity \"{identity}\" not allowed for \"{}\" (expected {rule_identity})",
                    input.name
                ),
                &mut findings,
                &mut action,
            );
        }
    }
    if let Some(rule_issuer) = &rule.issuer {
        // Keyful bundles have no issuer, so an issuer rule fails them: "must be
        // signed keyless via this IdP" is exactly what the rule expresses.
        let issuer = input.issuer.unwrap_or("");

        if !glob_match(rule_issuer, issuer) {
            violate(
                format!(
                    "issuer \"{issuer}\" not allowed for \"{}\" (expected {rule_issuer})",
                    input.name
                ),
                &mut findings,
                &mut action,
            );
        }
    }
    if let Some(rule_root) = &rule.trust_root {
        let root = input.root.unwrap_or("");

        if rule_root != root {
            violate(
                format!(
                    "trust root \"{root}\" not allowed for \"{}\" (expected {rule_root})",
                    input.name
                ),
                &mut findings,
                &mut action,
            );
        }
    }
    if let Some(rule_keyid) = &rule.keyid {
        if rule_keyid != keyid {
            violate(
                format!("keyid {}… does not match pinned rule keyid", short16(keyid)),
                &mut findings,
                &mut action,
            );
        }
    }

    let mut pin_update = None;

    if rule.tofu == Some(true) {
        if let Some(pin) = pins.get(input.name) {
            let issuer_changed = pin.issuer.as_deref().unwrap_or("") != input.issuer.unwrap_or("");
            let identity_changed = pin_identity(&pin.identity, pin.issuer.as_deref())
                != pin_identity(identity, input.issuer);

            if identity_changed || pin.keyid != keyid || issuer_changed {
                // Pin mismatch is always a hard failure: this is the signal for
                // account compromise or repo-transfer attacks (T3).
                let issuer_note = if issuer_changed {
                    format!(
                        " (issuer \"{}\" → \"{}\")",
                        pin.issuer.as_deref().unwrap_or("-"),
                        input.issuer.unwrap_or("-")
                    )
                } else {
                    String::new()
                };

                findings.push(Finding {
                    level: "error".to_string(),
                    message: format!(
                        "TOFU pin mismatch for \"{}\": previously signed by \"{}\" (key {}…), now \"{}\" (key {}…){issuer_note}",
                        input.name,
                        pin.identity,
                        short16(&pin.keyid),
                        identity,
                        short16(keyid)
                    ),
                });
                action = Action::Fail;
            }
        } else if action != Action::Fail {
            pin_update = Some(Pin {
                name: input.name.to_string(),
                identity: identity.to_string(),
                keyid: keyid.to_string(),
                issuer: input.issuer.map(str::to_string),
                first_seen: iso8601_now(),
            });
        }
    }
    EvalOutcome {
        action,
        findings,
        rule,
        pin_update,
    }
}

/// Evaluate the user's policy, then the project's on top of it. The project
/// can only make the outcome stricter: its findings are added and the worse
/// action wins. It never checks or writes TOFU pins (those are the user's).
pub fn evaluate_with_project(
    user: &Policy,
    project: Option<&Policy>,
    input: &EvalInput,
    pins: &Pins,
) -> EvalOutcome {
    let mut out = evaluate(user, input, pins);

    if let Some(project) = project {
        let mut no_tofu = project.clone();

        for r in &mut no_tofu.rules {
            r.tofu = None;
        }

        let extra = evaluate(&no_tofu, input, &Pins::new());

        out.findings
            .extend(extra.findings.into_iter().map(|f| Finding {
                level: f.level,
                message: format!("project policy: {}", f.message),
            }));
        if extra.action > out.action {
            out.action = extra.action;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(rules: Vec<Rule>) -> Policy {
        Policy {
            schema: POLICY_SCHEMA.into(),
            default_action: Some("warn".into()),
            rules,
            revocation_feed: None,
            revocation_feed_identity: None,
            revocation_feed_issuer: None,
            max_feed_staleness: None,
            on_feed_stale: None,
        }
    }

    #[test]
    fn unsigned_warns_by_default_and_fails_under_enforce() {
        let p = default_policy();
        let out = evaluate(
            &p,
            &EvalInput {
                name: "x",
                identity: None,
                keyid: None,
                issuer: None,
                root: None,
                signed: false,
            },
            &Pins::new(),
        );

        assert_eq!(out.action, Action::Warn);

        let p = policy_with(vec![Rule {
            pattern: "*".into(),
            action: Some("enforce".into()),
            ..Default::default()
        }]);
        let out = evaluate(
            &p,
            &EvalInput {
                name: "x",
                identity: None,
                keyid: None,
                issuer: None,
                root: None,
                signed: false,
            },
            &Pins::new(),
        );

        assert_eq!(out.action, Action::Fail);
        assert!(out.findings[0].message.contains("unsigned artifact"));
    }

    #[test]
    fn identity_rule_enforced() {
        let p = policy_with(vec![Rule {
            pattern: "anthropic/*".into(),
            identity: Some("github:anthropic*".into()),
            action: Some("enforce".into()),
            ..Default::default()
        }]);
        let ok = evaluate(
            &p,
            &EvalInput {
                name: "anthropic/pdf",
                identity: Some("github:anthropic"),
                keyid: Some("k"),
                issuer: None,
                root: None,
                signed: true,
            },
            &Pins::new(),
        );

        assert_eq!(ok.action, Action::Pass);

        let bad = evaluate(
            &p,
            &EvalInput {
                name: "anthropic/pdf",
                identity: Some("github:evil"),
                keyid: Some("k"),
                issuer: None,
                root: None,
                signed: true,
            },
            &Pins::new(),
        );

        assert_eq!(bad.action, Action::Fail);
    }

    #[test]
    fn tofu_pins_then_hard_fails_on_identity_change() {
        let p = default_policy();
        let mut pins = Pins::new();
        let first = evaluate(
            &p,
            &EvalInput {
                name: "s",
                identity: Some("github:a"),
                keyid: Some("k1"),
                issuer: None,
                root: None,
                signed: true,
            },
            &pins,
        );

        assert_eq!(first.action, Action::Pass);

        let pin = first.pin_update.unwrap();

        pins.insert(pin.name.clone(), pin);

        let same = evaluate(
            &p,
            &EvalInput {
                name: "s",
                identity: Some("github:a"),
                keyid: Some("k1"),
                issuer: None,
                root: None,
                signed: true,
            },
            &pins,
        );

        assert_eq!(same.action, Action::Pass);
        assert!(same.pin_update.is_none());

        let changed = evaluate(
            &p,
            &EvalInput {
                name: "s",
                identity: Some("github:b"),
                keyid: Some("k2"),
                issuer: None,
                root: None,
                signed: true,
            },
            &pins,
        );

        assert_eq!(changed.action, Action::Fail);
        assert!(changed.findings[0].message.contains("TOFU pin mismatch"));
    }

    const GHA: &str = "https://token.actions.githubusercontent.com";
    const SIGN_YML: &str = "https://github.com/acme/skills/.github/workflows/sign.yml";

    fn keyless_input<'a>(identity: &'a str, issuer: &'a str) -> EvalInput<'a> {
        EvalInput {
            name: "s",
            identity: Some(identity),
            keyid: Some(""),
            issuer: Some(issuer),
            root: None,
            signed: true,
        }
    }

    fn keyless_pin(identity: &str, issuer: &str) -> Pins {
        let mut pins = Pins::new();

        pins.insert(
            "s".into(),
            Pin {
                name: "s".into(),
                identity: identity.into(),
                keyid: String::new(),
                issuer: Some(issuer.into()),
                first_seen: "2026-01-01T00:00:00Z".into(),
            },
        );
        pins
    }

    #[test]
    fn keyless_pin_survives_a_new_release_tag_from_the_same_workflow() {
        let p = default_policy();
        let pins = keyless_pin(&format!("{SIGN_YML}@refs/tags/v1.0.0"), GHA);

        for next in ["@refs/tags/v1.0.1", "@refs/heads/main"] {
            let out = evaluate(&p, &keyless_input(&format!("{SIGN_YML}{next}"), GHA), &pins);

            assert_eq!(out.action, Action::Pass, "{next}: {:?}", out.findings);
            assert!(out.findings.is_empty());
            assert!(out.pin_update.is_none());
        }
    }

    #[test]
    fn keyless_pin_still_fails_on_another_workflow_repo_or_issuer() {
        let p = default_policy();
        let pins = keyless_pin(&format!("{SIGN_YML}@refs/tags/v1.0.0"), GHA);
        let other_workflow =
            "https://github.com/acme/skills/.github/workflows/evil.yml@refs/tags/v1.0.1";
        let other_repo =
            "https://github.com/evil/skills/.github/workflows/sign.yml@refs/tags/v1.0.1";
        let same_tag = format!("{SIGN_YML}@refs/tags/v1.0.0");

        for (identity, issuer) in [
            (other_workflow, GHA),
            (other_repo, GHA),
            (same_tag.as_str(), "https://gitlab.com"),
        ] {
            let out = evaluate(&p, &keyless_input(identity, issuer), &pins);

            assert_eq!(out.action, Action::Fail, "{identity} via {issuer}");
            assert!(out.findings[0].message.contains("TOFU pin mismatch"));
        }
    }

    #[test]
    fn ref_suffix_is_ignored_only_for_keyless_workflow_uris() {
        assert_eq!(
            pin_identity(&format!("{SIGN_YML}@refs/tags/v1"), Some(GHA)),
            SIGN_YML
        );
        // Email identities keep their '@'.
        assert_eq!(
            pin_identity("dev@example.com", Some("https://github.com/login/oauth")),
            "dev@example.com"
        );
        // Keyful identities are free-form and always compared exactly.
        assert_eq!(
            pin_identity("https://x@refs/tags/v1", None),
            "https://x@refs/tags/v1"
        );
    }

    const NV_ROOT: &str =
        "x509:sha256:6f1bb875b77aea3fc878a7a3237497235c53657601375c0ef4bdcde69e843782";

    #[test]
    fn trust_root_rule_requires_that_root() {
        let p = policy_with(vec![Rule {
            pattern: "*".into(),
            trust_root: Some("nvidia".into()),
            action: Some("enforce".into()),
            ..Default::default()
        }]);
        let input = |root| EvalInput {
            root,
            ..keyless_input("CN=Signing 001", NV_ROOT)
        };
        let wrong = evaluate(&p, &input(Some("sigstore-public")), &Pins::new());

        assert_eq!(wrong.action, Action::Fail);
        assert!(
            wrong.findings[0].message.contains("trust root"),
            "{:?}",
            wrong.findings
        );

        let missing = evaluate(&p, &input(None), &Pins::new());

        assert_eq!(missing.action, Action::Fail);
        assert_eq!(
            evaluate(&p, &input(Some("nvidia")), &Pins::new()).action,
            Action::Pass
        );
    }

    #[test]
    fn x509_pin_binds_the_root_not_the_leaf() {
        let p = default_policy();
        let pins = keyless_pin(
            "CN=NVIDIA Agent Skills Signing 001,O=NVIDIA Corporation,C=US",
            NV_ROOT,
        );
        let rotated = evaluate(
            &p,
            &keyless_input(
                "CN=NVIDIA Agent Skills Signing 002,O=NVIDIA Corporation,C=US",
                NV_ROOT,
            ),
            &pins,
        );

        assert_eq!(rotated.action, Action::Pass, "{:?}", rotated.findings);
        assert!(rotated.pin_update.is_none());

        let other_root = evaluate(
            &p,
            &keyless_input(
                "CN=NVIDIA Agent Skills Signing 001,O=NVIDIA Corporation,C=US",
                "x509:sha256:00",
            ),
            &pins,
        );

        assert_eq!(other_root.action, Action::Fail);
        assert!(other_root.findings[0].message.contains("TOFU pin mismatch"));
    }

    fn unsigned(name: &str) -> EvalInput<'_> {
        EvalInput {
            name,
            identity: None,
            keyid: None,
            issuer: None,
            root: None,
            signed: false,
        }
    }

    fn rule(pattern: &str, action: &str) -> Rule {
        Rule {
            pattern: pattern.into(),
            action: Some(action.into()),
            ..Default::default()
        }
    }

    #[test]
    fn a_project_policy_cannot_relax_the_users() {
        let user = policy_with(vec![rule("*", "enforce")]);
        let project = policy_with(vec![rule("*", "off")]);
        let out = evaluate_with_project(&user, Some(&project), &unsigned("x"), &Pins::new());

        assert_eq!(out.action, Action::Fail);
    }

    #[test]
    fn a_project_policy_cannot_add_trust() {
        let user = policy_with(vec![Rule {
            identity: Some("https://github.com/acme/*".into()),
            ..rule("*", "enforce")
        }]);
        let project = policy_with(vec![Rule {
            identity: Some("https://github.com/evil/*".into()),
            ..rule("*", "enforce")
        }]);
        let evil = keyless_input(
            "https://github.com/evil/x/.github/workflows/s.yml@refs/tags/v1",
            GHA,
        );
        let out = evaluate_with_project(&user, Some(&project), &evil, &Pins::new());

        assert_eq!(out.action, Action::Fail);
    }

    #[test]
    fn a_project_policy_can_tighten() {
        let user = default_policy();
        let project = policy_with(vec![rule("*", "enforce")]);
        let out = evaluate_with_project(&user, Some(&project), &unsigned("x"), &Pins::new());

        assert_eq!(out.action, Action::Fail);
        assert!(
            out.findings
                .iter()
                .any(|f| f.message.starts_with("project policy: ")),
            "{:?}",
            out.findings
        );

        // With no project policy the user's warn stands.
        assert_eq!(
            evaluate_with_project(&user, None, &unsigned("x"), &Pins::new()).action,
            Action::Warn
        );
    }

    #[test]
    fn a_project_policy_never_writes_or_checks_pins() {
        let user = policy_with(vec![rule("*", "warn")]);
        let project = policy_with(vec![Rule {
            tofu: Some(true),
            ..rule("*", "warn")
        }]);
        let pins = keyless_pin("someone-else@example.com", GHA);
        let out = evaluate_with_project(
            &user,
            Some(&project),
            &keyless_input("dev@example.com", GHA),
            &pins,
        );

        assert_eq!(out.action, Action::Pass, "{:?}", out.findings);
        assert!(out.pin_update.is_none());
    }

    #[test]
    fn the_project_policy_is_loaded_beside_the_users_not_instead() {
        let base = std::env::temp_dir().join(format!("ps-policy-load-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("repo/.promptsign")).unwrap();

        let user_path = base.join("user.json");

        fs::write(
            &user_path,
            r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[]}"#,
        )
        .unwrap();
        fs::write(
            base.join("repo/.promptsign/policy.json"),
            r#"{"schema":"promptsign/policy/v1","default":"off","rules":[]}"#,
        )
        .unwrap();

        let eff = load_effective_policy(Some(&user_path), &base.join("repo")).unwrap();

        assert_eq!(eff.user.default_action.as_deref(), Some("enforce"));
        assert_eq!(
            eff.project.as_ref().unwrap().default_action.as_deref(),
            Some("off")
        );
        assert!(eff.source.contains("tighten only"), "{}", eff.source);

        let none = load_effective_policy(Some(&user_path), &base).unwrap();

        assert!(none.project.is_none());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn off_action_suppresses_policy_findings() {
        let p = policy_with(vec![Rule {
            pattern: "*".into(),
            action: Some("off".into()),
            ..Default::default()
        }]);
        let out = evaluate(
            &p,
            &EvalInput {
                name: "x",
                identity: None,
                keyid: None,
                issuer: None,
                root: None,
                signed: false,
            },
            &Pins::new(),
        );

        assert_eq!(out.action, Action::Pass);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn first_match_wins() {
        let p = policy_with(vec![
            Rule {
                pattern: "a/*".into(),
                action: Some("enforce".into()),
                ..Default::default()
            },
            Rule {
                pattern: "*".into(),
                action: Some("off".into()),
                ..Default::default()
            },
        ]);

        assert_eq!(match_rule(&p, "a/x").action.as_deref(), Some("enforce"));
        assert_eq!(match_rule(&p, "b/x").action.as_deref(), Some("off"));
    }
}
