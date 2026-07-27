// Revocation feed consumption (spec/06-revocation.md). Fully offline: the cached
// feed is a keyless-signed bundle, re-verified against the policy-pinned feed
// identity on every use (the cache is never trusted on its own). A signature that
// was valid yesterday can be killed today without any online CA in the hot path.

use crate::keyless::verify_keyless;
use crate::policy::{Action, Finding, Policy};
use crate::util::{glob_match, parse_duration, parse_iso8601, promptsign_home, sha256_hex};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const REVOCATION_SCHEMA: &str = "promptsign/revocation/v1";
pub const REVOCATION_PAYLOAD_TYPE: &str = "application/vnd.promptsign.revocation+json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Identity entries only: revoke signatures whose Rekor integratedTime >= from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(
        rename = "payloadDigest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payload_digest: Option<String>,
    #[serde(rename = "logIndex", default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationFeed {
    pub schema: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(default)]
    pub entries: Vec<RevocationEntry>,
}

/// The bundle under test, reduced to the fields revocation matches on. Built by
/// the verifier from the already-authenticated envelope + transparency block.
pub struct Subject<'a> {
    pub identity: &'a str,
    /// None for keyful bundles (identity entries never match them).
    pub issuer: Option<&'a str>,
    /// "sha256:<hex>" of the DSSE payload.
    pub payload_digest: String,
    /// Rekor log index + integration time (keyless bundles only).
    pub log_index: Option<i64>,
    pub integrated_time: Option<i64>,
}

pub fn feed_path() -> PathBuf {
    match std::env::var_os("PROMPTSIGN_REVOCATION_FILE") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => promptsign_home().join("revocation.json"),
    }
}

/// The DSSE payload digest a `digest` entry matches, from the raw envelope payload.
pub fn payload_digest_of(payload: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(payload))
}

/// Load the cached feed bundle JSON (the signed bundle, not the doc — it is
/// re-verified on every use). `None` if no feed has been fetched.
pub fn load_cached_feed() -> Result<Option<Value>> {
    let p = feed_path();

    if !p.exists() {
        return Ok(None);
    }

    let data = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let v: Value = serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", p.display()))?;

    Ok(Some(v))
}

/// Verify a feed bundle offline (spec/06 §2): keyless signature valid, revocation
/// payloadType/schema, and signer identity/issuer match the policy-pinned feed
/// identity. Returns the authenticated feed document.
pub fn verify_feed(bundle: &Value, policy: &Policy) -> Result<RevocationFeed> {
    if bundle
        .pointer("/envelope/payloadType")
        .and_then(|v| v.as_str())
        != Some(REVOCATION_PAYLOAD_TYPE)
    {
        return Err("feed bundle is not a revocation feed (wrong payloadType)".to_string());
    }

    let kv = verify_keyless(bundle)?;

    if let Some(want) = &policy.revocation_feed_identity {
        if !glob_match(want, &kv.identity) {
            return Err(format!(
                "revocation feed signed by \"{}\", not the pinned feed identity \"{want}\"",
                kv.identity
            ));
        }
    }
    if let Some(want) = &policy.revocation_feed_issuer {
        if !glob_match(want, &kv.issuer) {
            return Err(format!(
                "revocation feed issuer \"{}\" does not match pinned \"{want}\"",
                kv.issuer
            ));
        }
    }

    let feed: RevocationFeed =
        serde_json::from_slice(&kv.payload).map_err(|e| format!("revocation feed: {e}"))?;

    if feed.schema != REVOCATION_SCHEMA {
        return Err(format!(
            "unsupported revocation feed schema: {}",
            feed.schema
        ));
    }
    Ok(feed)
}

/// Match the subject against every feed entry. Returns the first matching entry's
/// reason string (spec/06 §1.1, §4.3). `None` = not revoked.
pub fn check_revocation(feed: &RevocationFeed, subject: &Subject) -> Option<String> {
    for entry in &feed.entries {
        let hit = match entry.kind.as_str() {
            "digest" => entry
                .payload_digest
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(&subject.payload_digest)),
            "logIndex" => {
                matches!((entry.log_index, subject.log_index), (Some(a), Some(b)) if a == b)
            }
            "identity" => identity_entry_matches(entry, subject),
            _ => false, // forward-compatible: unknown entry kinds are ignored
        };

        if hit {
            let reason = entry
                .reason
                .clone()
                .unwrap_or_else(|| "no reason given".to_string());
            let what = match entry.kind.as_str() {
                "digest" => "artifact digest".to_string(),
                "logIndex" => format!("log index {}", entry.log_index.unwrap_or(-1)),
                _ => format!(
                    "identity \"{}\"",
                    entry.identity.clone().unwrap_or_default()
                ),
            };

            return Some(format!("{what}: {reason}"));
        }
    }
    None
}

fn identity_entry_matches(entry: &RevocationEntry, subject: &Subject) -> bool {
    // Identity entries only apply to keyless bundles (a keyful bundle has no issuer).
    let issuer = match subject.issuer {
        Some(i) => i,
        None => return false,
    };
    let pat = match &entry.identity {
        Some(p) => p,
        None => return false,
    };

    if !glob_match(pat, subject.identity) {
        return false;
    }
    if let Some(iss_pat) = &entry.issuer {
        if !glob_match(iss_pat, issuer) {
            return false;
        }
    }
    // Timestamping: with `from`, revoke only signatures at/after that instant.
    match &entry.from {
        None => true,
        Some(from) => match (parse_iso8601(from), subject.integrated_time) {
            (Some(from_secs), Some(t)) => t >= from_secs,
            // Unparseable `from`, or no integration time to compare: fail safe by
            // treating the entry as applying (a revocation should not be skipped
            // because its window is malformed).
            _ => true,
        },
    }
}

/// True if the cached feed is older than `max_feed_staleness` (spec/06 §4.4).
pub fn is_stale(feed: &RevocationFeed, policy: &Policy) -> bool {
    let max = match policy
        .max_feed_staleness
        .as_deref()
        .and_then(parse_duration)
    {
        Some(s) => s,
        None => return false, // no staleness bound configured
    };
    let generated = match parse_iso8601(&feed.generated_at) {
        Some(t) => t,
        None => return true, // an unparseable timestamp is treated as stale
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    now - generated > max
}

/// Outcome of consulting the revocation feed for one artifact.
pub struct RevocationOutcome {
    pub findings: Vec<Finding>,
    pub action: Action,
}

/// Full offline revocation evaluation (spec/06 §4). Caller invokes this only when
/// `policy.revocation_feed` is set and this is not a signer self-check.
pub fn evaluate(policy: &Policy, subject: &Subject) -> RevocationOutcome {
    let degrade = || {
        // "unavailable" degrades per on_feed_stale (default warn).
        if policy.on_feed_stale.as_deref() == Some("fail") {
            ("error", Action::Fail)
        } else {
            ("warn", Action::Warn)
        }
    };
    let unavailable = |msg: String| {
        let (level, action) = degrade();

        RevocationOutcome {
            findings: vec![Finding {
                level: level.to_string(),
                message: msg,
            }],
            action,
        }
    };

    let bundle = match load_cached_feed() {
        Ok(Some(b)) => b,
        Ok(None) => {
            return unavailable(
                "revocation feed not cached — run `promptsign revoke fetch`".to_string(),
            )
        }
        Err(e) => return unavailable(format!("revocation feed unreadable: {e}")),
    };
    let feed = match verify_feed(&bundle, policy) {
        Ok(f) => f,
        Err(e) => return unavailable(format!("revocation feed not trusted: {e}")),
    };

    // A revoked artifact fails regardless of feed freshness.
    if let Some(reason) = check_revocation(&feed, subject) {
        return RevocationOutcome {
            findings: vec![Finding {
                level: "error".to_string(),
                message: format!("revoked — {reason}"),
            }],
            action: Action::Fail,
        };
    }
    if is_stale(&feed, policy) {
        return unavailable(format!(
            "revocation feed is stale (generated {}) — run `promptsign revoke fetch`",
            feed.generated_at
        ));
    }
    RevocationOutcome {
        findings: Vec::new(),
        action: Action::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(entries: Vec<RevocationEntry>, generated_at: &str) -> RevocationFeed {
        RevocationFeed {
            schema: REVOCATION_SCHEMA.into(),
            generated_at: generated_at.into(),
            entries,
        }
    }

    fn entry(kind: &str) -> RevocationEntry {
        RevocationEntry {
            kind: kind.into(),
            identity: None,
            issuer: None,
            from: None,
            payload_digest: None,
            log_index: None,
            reason: None,
        }
    }

    fn subject<'a>(
        identity: &'a str,
        issuer: Option<&'a str>,
        digest: &str,
        log_index: Option<i64>,
        t: Option<i64>,
    ) -> Subject<'a> {
        Subject {
            identity,
            issuer,
            payload_digest: digest.to_string(),
            log_index,
            integrated_time: t,
        }
    }

    #[test]
    fn digest_entry_revokes_unconditionally() {
        let f = feed(
            vec![RevocationEntry {
                payload_digest: Some("sha256:abc".into()),
                reason: Some("malware".into()),
                ..entry("digest")
            }],
            "2026-07-13T00:00:00.000Z",
        );
        let s = subject("anyone", None, "sha256:abc", None, None);

        assert!(check_revocation(&f, &s).unwrap().contains("malware"));

        let s2 = subject("anyone", None, "sha256:def", None, None);

        assert!(check_revocation(&f, &s2).is_none());
    }

    #[test]
    fn log_index_entry_matches_exact() {
        let f = feed(
            vec![RevocationEntry {
                log_index: Some(42),
                ..entry("logIndex")
            }],
            "2026-07-13T00:00:00.000Z",
        );

        assert!(
            check_revocation(&f, &subject("x", Some("i"), "sha256:z", Some(42), Some(1))).is_some()
        );
        assert!(
            check_revocation(&f, &subject("x", Some("i"), "sha256:z", Some(43), Some(1))).is_none()
        );
        // keyful bundle without a log index is untouched by logIndex entries
        assert!(check_revocation(&f, &subject("x", None, "sha256:z", None, None)).is_none());
    }

    #[test]
    fn identity_entry_respects_issuer_and_from() {
        let f = feed(
            vec![RevocationEntry {
                identity: Some("repo:github.com/acme/*".into()),
                issuer: Some("https://token.actions.githubusercontent.com".into()),
                from: Some("2026-07-01T00:00:00.000Z".into()),
                reason: Some("session-compromise".into()),
                ..entry("identity")
            }],
            "2026-07-13T00:00:00.000Z",
        );
        let from = parse_iso8601("2026-07-01T00:00:00.000Z").unwrap();
        let iss = "https://token.actions.githubusercontent.com";

        // signed after `from` -> revoked
        assert!(check_revocation(
            &f,
            &subject(
                "repo:github.com/acme/skills",
                Some(iss),
                "sha256:z",
                Some(1),
                Some(from + 10)
            )
        )
        .is_some());
        // signed before `from` -> still valid (timestamping)
        assert!(check_revocation(
            &f,
            &subject(
                "repo:github.com/acme/skills",
                Some(iss),
                "sha256:z",
                Some(1),
                Some(from - 10)
            )
        )
        .is_none());
        // wrong issuer -> no match
        assert!(check_revocation(
            &f,
            &subject(
                "repo:github.com/acme/skills",
                Some("https://accounts.google.com"),
                "sha256:z",
                Some(1),
                Some(from + 10)
            )
        )
        .is_none());
        // keyful bundle (no issuer) is never matched by identity entries
        assert!(check_revocation(
            &f,
            &subject("repo:github.com/acme/skills", None, "sha256:z", None, None)
        )
        .is_none());
    }

    #[test]
    fn unknown_entry_kinds_are_ignored() {
        let f = feed(vec![entry("future-kind")], "2026-07-13T00:00:00.000Z");

        assert!(
            check_revocation(&f, &subject("x", Some("i"), "sha256:z", Some(1), Some(1))).is_none()
        );
    }

    #[test]
    fn staleness_by_max_feed_staleness() {
        let mut policy = crate::policy::default_policy();

        policy.max_feed_staleness = Some("72h".into());

        // generated far in the past -> stale
        let old = feed(vec![], "2000-01-01T00:00:00.000Z");

        assert!(is_stale(&old, &policy));
        // no bound configured -> never stale
        policy.max_feed_staleness = None;
        assert!(!is_stale(&old, &policy));
    }
}
