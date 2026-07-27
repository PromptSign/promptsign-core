// Trust policy evaluation and TOFU pin store (spec/04-policy.md).
// A signature without policy is meaningless: anyone can validly sign as
// themselves. Policy decides which identities may sign which names.

use crate::util::{glob_match, iso8601_now, promptsign_home, short16};
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

/// Resolution order: explicit path, $PROMPTSIGN_POLICY, project
/// .promptsign/policy.json, ~/.promptsign/policy.json, built-in default.
/// The raw Value is kept alongside the typed policy so `policy show` can
/// print unknown fields (revocation_feed, require_attestations, ...) verbatim.
pub fn load_policy(explicit: Option<&Path>, project_dir: &Path) -> Result<(Policy, Value, String)> {
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();

    if let Some(p) = explicit {
        candidates.push((p.to_path_buf(), true));
    }
    if let Ok(env_p) = std::env::var("PROMPTSIGN_POLICY") {
        if !env_p.is_empty() {
            candidates.push((PathBuf::from(env_p), false));
        }
    }
    candidates.push((project_dir.join(".promptsign").join("policy.json"), false));
    candidates.push((promptsign_home().join("policy.json"), false));

    for (p, is_explicit) in candidates {
        if p.exists() {
            let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let raw: Value =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?;

            if raw.get("schema").and_then(|s| s.as_str()) != Some(POLICY_SCHEMA) {
                return Err(format!("{}: unsupported policy schema", p.display()));
            }

            let policy: Policy =
                serde_json::from_value(raw.clone()).map_err(|e| format!("{}: {e}", p.display()))?;

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

    fs::write(&p, serde_json::to_string_pretty(pins).unwrap() + "\n")
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

            if pin.identity != identity || pin.keyid != keyid || issuer_changed {
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
                signed: true,
            },
            &pins,
        );

        assert_eq!(changed.action, Action::Fail);
        assert!(changed.findings[0].message.contains("TOFU pin mismatch"));
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
