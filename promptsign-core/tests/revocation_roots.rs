// A revocation feed under any registry root (spec/06 §2, §3): a PromptSign
// keyless bundle through a tenant's own deployment, a certificate-mode
// Sigstore bundle under a CA with no log, the root pin, and a feed named by
// an installed trust bundle.

mod common;

use common::MockSigstore;
use promptsign_core::policy::default_policy;
use promptsign_core::revocation::{feed_pin, verify_feed_with, FeedPin, REVOCATION_PAYLOAD_TYPE};
use promptsign_core::trustbundle::{parse_trust_bundle, BundleFeed, Installed};
use promptsign_core::trustroot::{Registry, Root};
use promptsign_core::util::parse_iso8601;
use serde_json::{json, Value};

const ALICE: &str = "alice@acme.test";
const SSO: &str = "https://sso.acme.test";
/// The subject DN of the mock's certificate-mode leaf.
const CA_LEAF: &str = "CN=sigstore-intermediate";

fn t0() -> i64 {
    parse_iso8601("2026-10-01T12:00:00Z").unwrap()
}

fn deployment() -> MockSigstore {
    MockSigstore::new_valid(
        43,
        "acme feed",
        parse_iso8601("2026-01-01T00:00:00Z").unwrap(),
        parse_iso8601("2036-01-01T00:00:00Z").unwrap(),
    )
}

fn feed_doc() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "promptsign/revocation/v1",
        "generatedAt": "2026-10-01T12:00:00Z",
        "entries": [{ "type": "identity", "identity": "mallory@acme.test", "reason": "left" }]
    }))
    .unwrap()
}

fn keyless_root(d: &MockSigstore) -> Root {
    Root::from_trusted_root("acme/prod", &d.trusted_root()).unwrap()
}

fn ca_root(d: &MockSigstore) -> Root {
    let mut doc = d.trusted_root_v2();

    doc["tlogs"] = json!([]);
    Root::from_trusted_root("acme/ca", &doc).unwrap()
}

fn pin(identity: &str, trust_root: &str) -> FeedPin {
    FeedPin {
        identity: Some(identity.to_string()),
        trust_root: Some(trust_root.to_string()),
        ..Default::default()
    }
}

#[test]
fn a_keyless_feed_verifies_through_a_tenant_root() {
    let d = deployment();
    let bundle = d.sign_typed_payload_at(REVOCATION_PAYLOAD_TYPE, &feed_doc(), ALICE, SSO, t0());
    let roots = [keyless_root(&d)];
    let feed = verify_feed_with(&bundle, &pin(ALICE, "acme/*"), &roots, t0()).unwrap();

    assert_eq!(feed.entries.len(), 1);

    let e = verify_feed_with(&bundle, &pin(ALICE, "sigstore-public"), &roots, t0()).unwrap_err();

    assert!(
        e.contains("no trust root matches the pinned feed root"),
        "{e}"
    );

    let e = verify_feed_with(&bundle, &pin("bob@*", "acme/*"), &roots, t0()).unwrap_err();

    assert!(e.contains("not the pinned feed identity"), "{e}");
}

#[test]
fn a_certificate_mode_feed_verifies_under_a_ca_root() {
    let d = deployment();
    let bundle =
        d.sign_sigstore_certificate_mode_typed(REVOCATION_PAYLOAD_TYPE, &feed_doc(), t0(), true);
    let roots = [keyless_root(&d), ca_root(&d)];
    let feed = verify_feed_with(&bundle, &pin(CA_LEAF, "acme/ca"), &roots, common::now()).unwrap();

    assert_eq!(feed.generated_at, "2026-10-01T12:00:00Z");

    // The issuer of a certificate-mode signer is the root's fingerprint.
    let by_issuer = FeedPin {
        issuer: Some(format!("x509:sha256:{}", ca_root(&d).fingerprint)),
        ..pin(CA_LEAF, "acme/ca")
    };

    assert!(verify_feed_with(&bundle, &by_issuer, &roots, common::now()).is_ok());

    // A keyless root never accepts a certificate-mode feed.
    let e =
        verify_feed_with(&bundle, &pin(CA_LEAF, "acme/prod"), &roots, common::now()).unwrap_err();

    assert!(!e.is_empty());
}

#[test]
fn a_sigstore_bundle_of_another_payload_type_is_not_a_feed() {
    let d = deployment();
    let bundle = d.sign_sigstore_certificate_mode(&feed_doc(), t0(), true);
    let e = verify_feed_with(
        &bundle,
        &pin(CA_LEAF, "acme/ca"),
        &[ca_root(&d)],
        common::now(),
    )
    .unwrap_err();

    assert!(e.contains("wrong payloadType"), "{e}");
}

fn bundle_doc(d: &MockSigstore, feed: Option<Value>) -> Vec<u8> {
    let mut ca = d.trusted_root_v2();

    ca["tlogs"] = json!([]);

    let mut doc = json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": 1,
        "issued": "2026-10-01T00:00:00Z",
        "expires": "2126-01-01T00:00:00Z",
        "roots": { "ca": ca },
        "signers": [{ "identity": "x", "issuer": "y", "root": "sigstore-public" }]
    });

    if let Some(f) = feed {
        doc["revocationFeed"] = f;
    }
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn a_trust_bundle_names_its_feed() {
    let d = deployment();
    let feed = json!({ "url": "https://trust.acme.test/revocation.json", "identity": CA_LEAF, "root": "ca" });
    let b = parse_trust_bundle("acme", &bundle_doc(&d, Some(feed))).unwrap();

    assert_eq!(
        b.revocation_feed,
        Some(BundleFeed {
            url: "https://trust.acme.test/revocation.json".into(),
            identity: CA_LEAF.into(),
            issuer: None,
            root: "acme/ca".into(),
        })
    );
    assert!(parse_trust_bundle("acme", &bundle_doc(&d, None))
        .unwrap()
        .revocation_feed
        .is_none());

    let e = parse_trust_bundle(
        "acme",
        &bundle_doc(&d, Some(json!({ "url": "https://x", "root": "ca" }))),
    )
    .err()
    .unwrap();

    assert_eq!(e, "trust bundle revocationFeed has no identity");

    let e = parse_trust_bundle(
        "acme",
        &bundle_doc(
            &d,
            Some(json!({ "url": "https://x", "identity": "i", "root": "prod" })),
        ),
    )
    .err()
    .unwrap();

    assert_eq!(
        e,
        "trust bundle revocationFeed root \"prod\" is neither sigstore-public nor one of the bundle's roots"
    );
}

#[test]
fn a_policy_takes_its_feed_from_an_installed_bundle() {
    let d = deployment();
    let feed = json!({ "url": "https://trust.acme.test/revocation.json", "identity": CA_LEAF, "root": "ca" });
    let bundle = parse_trust_bundle("acme", &bundle_doc(&d, Some(feed))).unwrap();
    let registry = Registry {
        roots: bundle.roots.clone(),
        bundles: vec![Installed {
            bundle,
            source: None,
            stale: false,
            managed: true,
        }],
        ignored: Vec::new(),
    };
    let policy = |extra: Value| {
        let mut p = serde_json::to_value(default_policy()).unwrap();

        p["revocation_feed"] = json!("trust-bundle:acme");
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        serde_json::from_value(p).unwrap()
    };

    assert_eq!(
        feed_pin(&policy(json!({})), &registry).unwrap(),
        FeedPin {
            url: Some("https://trust.acme.test/revocation.json".into()),
            identity: Some(CA_LEAF.into()),
            issuer: None,
            trust_root: Some("acme/ca".into()),
        }
    );

    // The policy's own keys replace the bundle's.
    let narrowed = feed_pin(
        &policy(json!({ "revocation_feed_identity": "CN=revoker" })),
        &registry,
    )
    .unwrap();

    assert_eq!(narrowed.identity.as_deref(), Some("CN=revoker"));
    assert_eq!(narrowed.trust_root.as_deref(), Some("acme/ca"));

    let mut other = policy(json!({}));

    other.revocation_feed = Some("trust-bundle:globex".into());
    assert_eq!(
        feed_pin(&other, &registry).unwrap_err(),
        "revocation_feed names trust bundle \"globex\", which is not installed"
    );
}
