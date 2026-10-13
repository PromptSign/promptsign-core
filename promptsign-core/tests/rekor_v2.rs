// Rekor v2 entries and RFC 3161 timestamps (spec/05 §3.2 and §4, spec/07 §1):
// a mock deployment logs a signature as a hashedrekord 0.0.2 entry, proves
// it with a signed checkpoint, and dates it with a timestamp authority.

mod common;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use common::v2::checkpoint;
use common::{temp_dir, MockSigstore};
use promptsign_core::keyless::verify_keyless_with;
use promptsign_core::sigstore_bundle::verify_sigstore_bundle;
use promptsign_core::trustroot::{load_registry_from, Root, DEFAULT_ROOT};
use promptsign_core::util::{format_iso8601, parse_iso8601};
use serde_json::{json, Value};

const ALICE: &str = "alice@acme.test";
const SSO: &str = "https://sso.acme.test";

fn t0() -> i64 {
    parse_iso8601("2026-10-01T12:00:00Z").unwrap()
}

fn deployment() -> MockSigstore {
    MockSigstore::new_valid(
        41,
        "acme v2",
        parse_iso8601("2026-01-01T00:00:00Z").unwrap(),
        parse_iso8601("2036-01-01T00:00:00Z").unwrap(),
    )
}

fn root_of(doc: &Value) -> Root {
    Root::from_trusted_root("acme", doc).unwrap()
}

fn sig_of(bundle: &Value) -> Vec<u8> {
    BASE64_STANDARD
        .decode(bundle["envelope"]["signatures"][0]["sig"].as_str().unwrap())
        .unwrap()
}

fn err(bundle: &Value, root: &Root) -> String {
    verify_keyless_with(bundle, std::slice::from_ref(root))
        .err()
        .expect("bundle must not verify")
}

#[test]
fn a_rekor_v2_entry_with_a_timestamp_verifies() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let bundle = d.sign_payload_v2_at(b"{\"m\":1}", ALICE, SSO, t0());
    let v = verify_keyless_with(&bundle, std::slice::from_ref(&root)).unwrap();

    assert_eq!(v.identity, ALICE);
    assert_eq!(v.issuer, SSO);
    assert_eq!(v.root, "acme");
    assert_eq!(v.signed_at, t0());
}

#[test]
fn a_rekor_v2_entry_needs_a_verified_timestamp() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let good = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());
    let sig = sig_of(&good);
    let with = |ts: Vec<u8>| {
        let mut b = good.clone();

        b["timestamps"] = json!([BASE64_STANDARD.encode(ts)]);
        b
    };
    let mut none = good.clone();

    none.as_object_mut().unwrap().remove("timestamps");
    assert!(err(&none, &root).contains("no verified signing time"));

    let other = with(d.timestamp(b"another signature", t0(), false));

    assert!(err(&other, &root).contains("does not cover this signature"));

    let late = with(d.timestamp(&sig, t0() + 3600, false));

    assert!(err(&late, &root).contains("outside certificate validity"));

    let stranger = MockSigstore::new_valid(90, "stranger", 0, i64::from(u32::MAX));
    let foreign = with(stranger.timestamp(&sig, t0(), true));

    let e = err(&foreign, &root);

    assert!(e.contains("does not chain"), "{e}");

    // An embedded certificate from the trusted authority is fine.
    verify_keyless_with(&with(d.timestamp(&sig, t0(), true)), &[root]).unwrap();
}

#[test]
fn a_timestamp_authority_window_is_closed_at_both_ends() {
    let d = deployment();
    let bundle = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());
    let mut doc = d.trusted_root_v2();

    doc["timestampAuthorities"][0]["validFor"] =
        json!({ "start": format_iso8601(t0() - 10), "end": format_iso8601(t0()) });
    verify_keyless_with(&bundle, &[root_of(&doc)]).unwrap();

    doc["timestampAuthorities"][0]["validFor"]["end"] = json!(format_iso8601(t0() - 1));
    assert!(err(&bundle, &root_of(&doc)).contains("validity window"));
}

#[test]
fn the_checkpoint_must_carry_the_log_signature() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let good = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());
    let proof = &good["transparency"]["inclusionProof"];
    let size = proof["treeSize"].as_u64().unwrap();
    let hash = BASE64_STANDARD
        .decode(proof["rootHash"].as_str().unwrap())
        .unwrap();
    let with = |cp: String| {
        let mut b = good.clone();

        b["transparency"]["inclusionProof"]["checkpoint"] = json!(cp);
        b
    };
    let impostor = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);

    assert!(err(
        &with(checkpoint(&d.log2_origin(), &impostor, size, &hash)),
        &root
    )
    .contains("no signature from log"));
    assert!(err(
        &with(checkpoint(
            "rekor.elsewhere.test",
            d.log2_key(),
            size,
            &hash
        )),
        &root
    )
    .contains("is not the log's origin"));

    // A forged signature under the log's own key hint is an error, not
    // something to skip.
    let real = checkpoint(&d.log2_origin(), d.log2_key(), size, &hash);
    let (text, line) = real.split_once("\n\n").unwrap();
    let (prefix, b64) = line.trim_end().rsplit_once(' ').unwrap();
    let mut raw = BASE64_STANDARD.decode(b64).unwrap();

    *raw.last_mut().unwrap() ^= 1;
    assert!(err(
        &with(format!(
            "{text}\n\n{prefix} {}\n",
            BASE64_STANDARD.encode(raw)
        )),
        &root
    )
    .contains("does not verify"));

    // Witness cosignatures from unknown keys are ignored, in any position.
    let cosigned = format!("{text}\n\n\u{2014} witness.test AAAAAAAAAAAAAAAAAAAAAAAA\n{line}");

    verify_keyless_with(&with(cosigned), &[root]).unwrap();
}

#[test]
fn the_inclusion_proof_must_lead_to_the_checkpoint() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let good = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());
    let mut tampered = good.clone();

    tampered["transparency"]["inclusionProof"]["hashes"][0] =
        json!(BASE64_STANDARD.encode([7u8; 32]));
    assert!(err(&tampered, &root).contains("inclusion proof"));

    let mut resized = good.clone();

    resized["transparency"]["inclusionProof"]["treeSize"] = json!(1000);
    assert!(err(&resized, &root).contains("does not match its checkpoint"));
}

#[test]
fn a_rekor_v1_entry_may_carry_timestamps_too() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let mut bundle = d.sign_payload_at(b"{}", ALICE, SSO, t0());

    d.add_timestamp(&mut bundle, t0() + 5);

    let v = verify_keyless_with(&bundle, std::slice::from_ref(&root)).unwrap();

    // The log's own time is the signing time when it signed one.
    assert_eq!(v.signed_at, t0());

    // Every verified time must fall inside the certificate's validity.
    d.add_timestamp(&mut bundle, t0() + 3600);
    assert!(err(&bundle, &root).contains("outside certificate validity"));
}

#[test]
fn a_root_document_keeps_v2_logs_and_timestamp_authorities() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let again = Root::from_trusted_root("acme", &root.to_trusted_root()).unwrap();

    assert_eq!(root.log_ids(), vec![d.log_id(), d.log2_id()]);
    assert_eq!(again.log_ids(), root.log_ids());
    assert_eq!(again.rekor_logs[1].origin(), Some(d.log2_origin()));
    assert_eq!(again.tsas.len(), 1);
    assert_eq!(again.tsas[0].certs.len(), 2);

    // An Ed25519 log without a base URL has no origin, so no usable id.
    let mut doc = d.trusted_root_v2();

    doc["tlogs"][1].as_object_mut().unwrap().remove("baseUrl");
    assert_eq!(root_of(&doc).log_ids(), vec![d.log_id()]);
}

#[test]
fn the_built_in_root_joins_the_public_trusted_root_document() {
    let d = deployment();
    let dir = temp_dir("joined-root");

    std::fs::write(dir.join("fulcio.pem"), d.fulcio_pem()).unwrap();
    std::fs::write(dir.join("rekor.pub"), d.rekor_pem()).unwrap();

    let pair_only = load_registry_from(&dir).unwrap();

    assert_eq!(pair_only[0].log_ids(), vec![d.log_id()]);

    std::fs::write(
        dir.join("trusted_root.json"),
        serde_json::to_vec(&d.trusted_root_v2()).unwrap(),
    )
    .unwrap();

    let roots = load_registry_from(&dir).unwrap();
    let builtin = &roots[0];

    assert_eq!(builtin.name, DEFAULT_ROOT);
    assert_eq!(builtin.log_ids(), vec![d.log_id(), d.log2_id()]);
    assert_eq!(builtin.tsas.len(), 1);

    let bundle = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());

    assert_eq!(
        verify_keyless_with(&bundle, &roots).unwrap().root,
        DEFAULT_ROOT
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A native v2 bundle in Sigstore's bundle v0.3 carriage.
fn to_sigstore(native: &Value) -> Value {
    let t = &native["transparency"];
    let p = &t["inclusionProof"];
    let log_id: Vec<u8> = (0..32)
        .map(|i| u8::from_str_radix(&t["logId"].as_str().unwrap()[2 * i..2 * i + 2], 16).unwrap())
        .collect();

    json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": { "rawBytes": native["signer"]["certChain"][0] },
            "tlogEntries": [{
                "logIndex": t["logIndex"].to_string(),
                "logId": { "keyId": BASE64_STANDARD.encode(log_id) },
                "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
                "inclusionProof": {
                    "logIndex": t["logIndex"].to_string(),
                    "rootHash": p["rootHash"],
                    "treeSize": p["treeSize"].to_string(),
                    "hashes": p["hashes"],
                    "checkpoint": { "envelope": p["checkpoint"] }
                },
                "canonicalizedBody": t["body"]
            }],
            "timestampVerificationData": { "rfc3161Timestamps": [
                { "signedTimestamp": native["timestamps"][0] }
            ] }
        },
        "dsseEnvelope": {
            "payload": native["envelope"]["payload"],
            "payloadType": native["envelope"]["payloadType"],
            "signatures": [{ "sig": native["envelope"]["signatures"][0]["sig"], "keyid": "" }]
        }
    })
}

#[test]
fn a_sigstore_bundle_with_a_rekor_v2_entry_verifies() {
    let d = deployment();
    let root = root_of(&d.trusted_root_v2());
    let native = d.sign_payload_v2_at(b"{}", ALICE, SSO, t0());
    let v = verify_sigstore_bundle(&to_sigstore(&native), &[root], common::now()).unwrap();

    assert_eq!(v.identity, ALICE);
    assert_eq!(v.integrated_time, Some(t0()));
    assert_eq!(v.log_index, native["transparency"]["logIndex"].as_i64());
}

#[test]
fn a_timestamp_dates_a_certificate_mode_signature() {
    let d = deployment();
    let mut doc = d.trusted_root_v2();

    doc["tlogs"] = json!([]);

    let root = root_of(&doc);

    assert!(root.is_ca_only());

    // The leaf lived for ten minutes in 2026-10. With a timestamp from the
    // root's authority it is checked then; without one, now, when it has
    // long expired.
    let stamped = d.sign_sigstore_certificate_mode(b"{}", t0(), true);
    let v = verify_sigstore_bundle(&stamped, std::slice::from_ref(&root), common::now()).unwrap();

    assert_eq!(v.integrated_time, Some(t0()));

    let bare = d.sign_sigstore_certificate_mode(b"{}", t0(), false);
    let e = verify_sigstore_bundle(&bare, &[root], common::now()).unwrap_err();

    assert!(e.contains("is not valid at"), "{e}");
}
