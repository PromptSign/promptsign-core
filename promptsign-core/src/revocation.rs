// Revocation feed consumption (spec/06-revocation.md). Fully offline: the cached
// feed is a signed bundle, re-verified against the policy-pinned feed signer and
// root on every use (the cache is never trusted on its own). A signature that
// was valid yesterday can be killed today without any online CA in the hot path.
//
// A feed may chain to any root in the registry: the public Sigstore root, a
// tenant's own keyless deployment, or a certificate-mode CA with no log.

use crate::keyless::verify_keyless_with;
use crate::managed::{env_override, managed_revocation_path};
use crate::policy::{Action, Finding, Policy};
use crate::sigstore_bundle::{is_sigstore_bundle, verify_sigstore_bundle};
use crate::trustroot::{load_full_registry, Registry, Root};
use crate::util::{glob_match, parse_duration, parse_iso8601, promptsign_home, sha256_hex};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const REVOCATION_SCHEMA: &str = "promptsign/revocation/v1";
pub const REVOCATION_PAYLOAD_TYPE: &str = "application/vnd.promptsign.revocation+json";
/// A `revocation_feed` with this prefix names an installed trust bundle whose
/// `revocationFeed` supplies the feed (spec/06 §3).
pub const TRUST_BUNDLE_FEED: &str = "trust-bundle:";

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

/// The file `revoke fetch` caches the feed in: `$PROMPTSIGN_REVOCATION_FILE`
/// (unless the managed policy locks the environment), else
/// `~/.promptsign/revocation.json`.
pub fn feed_path() -> PathBuf {
    match env_override("PROMPTSIGN_REVOCATION_FILE") {
        Some(p) => PathBuf::from(p),
        None => promptsign_home().join("revocation.json"),
    }
}

/// The freshest cached feed that verifies under `policy` (spec/06 §4 step
/// 1): the managed copy an administrator keeps current, or the user's. An
/// older copy never hides a newer revocation. `Ok(None)` when neither
/// exists; the first problem when none verifies.
fn freshest_feed(policy: &Policy) -> std::result::Result<Option<RevocationFeed>, String> {
    let mut best: Option<RevocationFeed> = None;
    let mut problem: Option<String> = None;

    for p in [managed_revocation_path(), feed_path()] {
        if !p.exists() {
            continue;
        }

        let loaded = std::fs::read(&p)
            .map_err(|e| format!("{}: {e}", p.display()))
            .and_then(|d| {
                serde_json::from_slice::<Value>(&d).map_err(|e| format!("{}: {e}", p.display()))
            })
            .map_err(|e| format!("revocation feed unreadable: {e}"))
            .and_then(|b| {
                verify_feed(&b, policy).map_err(|e| format!("revocation feed not trusted: {e}"))
            });

        match loaded {
            Ok(feed) => {
                let at = |f: &RevocationFeed| parse_iso8601(&f.generated_at).unwrap_or(i64::MIN);

                if best.as_ref().is_none_or(|b| at(&feed) > at(b)) {
                    best = Some(feed);
                }
            }
            Err(e) => {
                problem.get_or_insert(e);
            }
        }
    }
    match (best, problem) {
        (Some(feed), _) => Ok(Some(feed)),
        (None, Some(e)) => Err(e),
        (None, None) => Ok(None),
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

/// Where a feed comes from and who may sign it (spec/06 §2, §3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedPin {
    pub url: Option<String>,
    /// Glob over the feed signer's identity.
    pub identity: Option<String>,
    /// Glob over the feed signer's issuer.
    pub issuer: Option<String>,
    /// Glob over the registry root the feed's signature must chain to.
    pub trust_root: Option<String>,
}

/// The feed pin `policy` sets. With `revocation_feed: "trust-bundle:<name>"`
/// the URL, signer and root come from that installed bundle's
/// `revocationFeed`, and each `revocation_feed_*` key the policy sets
/// replaces the bundle's value.
pub fn feed_pin(policy: &Policy, registry: &Registry) -> Result<FeedPin> {
    let from_policy = FeedPin {
        url: policy.revocation_feed.clone(),
        identity: policy.revocation_feed_identity.clone(),
        issuer: policy.revocation_feed_issuer.clone(),
        trust_root: policy.revocation_feed_trust_root.clone(),
    };
    let Some(name) = policy
        .revocation_feed
        .as_deref()
        .and_then(|f| f.strip_prefix(TRUST_BUNDLE_FEED))
    else {
        return Ok(from_policy);
    };
    let installed = registry
        .bundles
        .iter()
        .find(|b| b.bundle.name == name)
        .ok_or_else(|| {
            format!("revocation_feed names trust bundle \"{name}\", which is not installed")
        })?;
    let feed = installed
        .bundle
        .revocation_feed
        .as_ref()
        .ok_or_else(|| format!("trust bundle \"{name}\" names no revocation feed"))?;

    Ok(FeedPin {
        url: Some(feed.url.clone()),
        identity: from_policy.identity.or(Some(feed.identity.clone())),
        issuer: from_policy.issuer.or(feed.issuer.clone()),
        trust_root: from_policy.trust_root.or(Some(feed.root.clone())),
    })
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Verify a feed bundle offline (spec/06 §2) against the registry, under the
/// feed pin `policy` sets. Returns the authenticated feed document.
pub fn verify_feed(bundle: &Value, policy: &Policy) -> Result<RevocationFeed> {
    let now = now_secs();
    let registry = load_full_registry(now)?;

    verify_feed_with(bundle, &feed_pin(policy, &registry)?, &registry.roots, now)
}

/// Verify a feed bundle against `roots` at `now`: a PromptSign keyless bundle
/// or a Sigstore bundle (keyless or certificate mode) with the revocation
/// payloadType, chained to a root the pin allows, by the pinned signer.
pub fn verify_feed_with(
    bundle: &Value,
    pin: &FeedPin,
    roots: &[Root],
    now: i64,
) -> Result<RevocationFeed> {
    let roots: Vec<Root> = roots
        .iter()
        .filter(|r| {
            pin.trust_root
                .as_deref()
                .is_none_or(|g| glob_match(g, &r.name))
        })
        .cloned()
        .collect();

    if roots.is_empty() {
        return Err(format!(
            "no trust root matches the pinned feed root \"{}\"",
            pin.trust_root.as_deref().unwrap_or_default()
        ));
    }

    let (identity, issuer, payload) = if is_sigstore_bundle(bundle) {
        let vs = verify_sigstore_bundle(bundle, &roots, now)?;

        if vs.payload_type != REVOCATION_PAYLOAD_TYPE {
            return Err("feed bundle is not a revocation feed (wrong payloadType)".to_string());
        }
        (vs.identity, vs.issuer, vs.payload)
    } else {
        if bundle
            .pointer("/envelope/payloadType")
            .and_then(|v| v.as_str())
            != Some(REVOCATION_PAYLOAD_TYPE)
        {
            return Err("feed bundle is not a revocation feed (wrong payloadType)".to_string());
        }

        let keyless: Vec<Root> = roots.into_iter().filter(|r| !r.is_ca_only()).collect();
        let kv = verify_keyless_with(bundle, &keyless)?;

        (kv.identity, kv.issuer, kv.payload)
    };

    if let Some(want) = &pin.identity {
        if !glob_match(want, &identity) {
            return Err(format!(
                "revocation feed signed by \"{identity}\", not the pinned feed identity \"{want}\""
            ));
        }
    }
    if let Some(want) = &pin.issuer {
        if !glob_match(want, &issuer) {
            return Err(format!(
                "revocation feed issuer \"{issuer}\" does not match pinned \"{want}\""
            ));
        }
    }

    let feed: RevocationFeed =
        serde_json::from_slice(&payload).map_err(|e| format!("revocation feed: {e}"))?;

    if feed.schema != REVOCATION_SCHEMA {
        return Err(format!(
            "unsupported revocation feed schema: {}",
            feed.schema
        ));
    }
    Ok(feed)
}

/// The freshest cached feed that verifies under `policy`, for subjects
/// beyond the artifact's own signature, such as its approvals (spec/09 §5).
/// `None` when no copy verifies; the artifact's own check reports why.
pub fn trusted_feed(policy: &Policy) -> Option<RevocationFeed> {
    freshest_feed(policy).ok().flatten()
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
    pub state: RevocationState,
}

/// What the feed said about one artifact, for the decision log (spec/08).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RevocationState {
    /// A fresh feed does not list it.
    Clear,
    Revoked,
    /// The newest feed that verifies is past `max_feed_staleness`.
    Stale,
    /// No feed is cached, or none verifies.
    Unavailable,
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
    let degraded = |msg: String, state: RevocationState| {
        let (level, action) = degrade();

        RevocationOutcome {
            findings: vec![Finding {
                level: level.to_string(),
                message: msg,
            }],
            action,
            state,
        }
    };
    let unavailable = |msg: String| degraded(msg, RevocationState::Unavailable);

    let feed = match freshest_feed(policy) {
        Ok(Some(f)) => f,
        Ok(None) => {
            return unavailable(
                "revocation feed not cached — run `promptsign revoke fetch`".to_string(),
            )
        }
        Err(e) => return unavailable(e),
    };

    // A revoked artifact fails regardless of feed freshness.
    if let Some(reason) = check_revocation(&feed, subject) {
        return RevocationOutcome {
            findings: vec![Finding {
                level: "error".to_string(),
                message: format!("revoked — {reason}"),
            }],
            action: Action::Fail,
            state: RevocationState::Revoked,
        };
    }
    if is_stale(&feed, policy) {
        return degraded(
            format!(
                "revocation feed is stale (generated {}) — run `promptsign revoke fetch`",
                feed.generated_at
            ),
            RevocationState::Stale,
        );
    }
    RevocationOutcome {
        findings: Vec::new(),
        action: Action::Pass,
        state: RevocationState::Clear,
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
