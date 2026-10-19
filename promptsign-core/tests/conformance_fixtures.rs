// Writes the shared trust-root, Rekor v2 and approval fixtures (spec/07 §6,
// spec/09) that every implementation runs its conformance checks on. Ignored
// by default; regenerate with
//
//   PROMPTSIGN_FIXTURES_OUT=../../spec/test/fixtures/trust-roots \
//   PROMPTSIGN_REKOR_V2_FIXTURES_OUT=../../spec/test/fixtures/rekor-v2 \
//   PROMPTSIGN_APPROVAL_FIXTURES_OUT=../../spec/test/fixtures/approvals \
//     cargo test --test conformance_fixtures -- --ignored
//
// Every certificate, log entry and bundle carries a fixed time, and the mock's
// signatures are deterministic, so a rerun writes identical bytes. Before
// writing, the generator checks each bundle does what the fixture README says.

mod common;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use common::v2::checkpoint;
use common::{temp_dir, MockSigstore};
use promptsign_core::keyless::verify_keyless_with;
use promptsign_core::trustbundle::{check_trust_bundle, store_trust_bundle};
use promptsign_core::trustroot::Root;
use promptsign_core::util::parse_iso8601;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const GH: &str = "https://token.actions.githubusercontent.com";
const PUBLISH: &str = "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main";
const MALLORY: &str =
    "https://github.com/mallory/trust/.github/workflows/publish.yml@refs/heads/main";
const ALICE: &str = "alice@acme.test";
const ACME_SSO: &str = "https://sso.acme.test";

fn at(rfc3339: &str) -> i64 {
    parse_iso8601(rfc3339).unwrap()
}

/// The organization's current deployment, which also signs its trust bundle.
fn prod() -> MockSigstore {
    MockSigstore::new_valid(
        30,
        "acme prod fulcio",
        at("2026-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
}

/// A deployment the organization retired on 2026-07-01 by ending its CA's
/// validFor window.
fn old() -> MockSigstore {
    MockSigstore::new_valid(
        40,
        "acme old fulcio",
        at("2025-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
}

fn roots() -> Value {
    let mut old_root = old().trusted_root();

    old_root["certificateAuthorities"][0]["validFor"] =
        json!({ "start": "2025-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z" });
    json!({ "prod": prod().trusted_root(), "old": old_root })
}

fn bundle(version: u64, issued: &str, expires: &str) -> Vec<u8> {
    bundle_with_feed(version, issued, expires, None)
}

/// A bundle that also names a revocation feed (spec/07 §5.1).
fn bundle_with_feed(version: u64, issued: &str, expires: &str, feed: Option<Value>) -> Vec<u8> {
    let mut doc = json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": version,
        "issued": issued,
        "expires": expires,
        "roots": roots(),
        "signers": [{ "identity": PUBLISH, "issuer": GH, "root": "prod" }],
    });

    if let Some(f) = feed {
        doc["revocationFeed"] = f;
    }

    let mut bytes = serde_json::to_vec_pretty(&doc).unwrap();

    bytes.push(b'\n');
    bytes
}

/// A bundle and its sidecar, signed through acme's prod deployment as
/// `identity` at `signed`.
struct Signed {
    bytes: Vec<u8>,
    sidecar: Value,
}

fn signed_bundle(bytes: Vec<u8>, identity: &str, signed: &str) -> Signed {
    let sidecar = prod().sign_file_at("trust-bundle.json", &bytes, identity, GH, at(signed));

    Signed { bytes, sidecar }
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();

    bytes.push(b'\n');
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn write_bundle(out: &Path, dir: &str, b: &Signed) {
    let dir = out.join("bundles").join(dir);

    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("trust-bundle.json"), &b.bytes).unwrap();
    write_json(&dir.join("trust-bundle.json.psig.json"), &b.sidecar);
}

fn write_artifact(out: &Path, file: &str, bytes: &[u8], deployment: &MockSigstore, signed: &str) {
    let dir = out.join("artifacts");
    let sidecar = deployment.sign_file_at(file, bytes, ALICE, ACME_SSO, at(signed));

    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(file), bytes).unwrap();
    write_json(&dir.join(format!("{file}.psig.json")), &sidecar);
}

#[test]
#[ignore = "writes fixtures; run with PROMPTSIGN_FIXTURES_OUT set"]
fn write_trust_root_fixtures() {
    let out = std::env::var_os("PROMPTSIGN_FIXTURES_OUT")
        .map(std::path::PathBuf::from)
        .expect("set PROMPTSIGN_FIXTURES_OUT to the fixture directory");
    let now = common::now();
    let v1 = signed_bundle(
        bundle(1, "2026-10-01T00:00:00Z", "2126-01-01T00:00:00Z"),
        PUBLISH,
        "2026-10-01T00:00:00Z",
    );
    let v2 = signed_bundle(
        bundle(2, "2026-10-02T00:00:00Z", "2126-01-01T00:00:00Z"),
        PUBLISH,
        "2026-10-02T00:00:00Z",
    );
    let unlisted = signed_bundle(
        bundle(2, "2026-10-02T00:00:00Z", "2126-01-01T00:00:00Z"),
        MALLORY,
        "2026-10-02T00:00:00Z",
    );
    let stale = signed_bundle(
        bundle(1, "2026-09-01T00:00:00Z", "2026-09-30T00:00:00Z"),
        PUBLISH,
        "2026-09-01T00:00:00Z",
    );
    let feed = |root: &str| {
        Some(json!({
            "url": "https://trust.acme.test/revocation.json",
            "identity": "https://github.com/acme/trust/.github/workflows/revoke.yml@refs/heads/main",
            "issuer": GH,
            "root": root,
        }))
    };
    let with_feed = signed_bundle(
        bundle_with_feed(
            1,
            "2026-10-01T00:00:00Z",
            "2126-01-01T00:00:00Z",
            feed("prod"),
        ),
        PUBLISH,
        "2026-10-01T00:00:00Z",
    );
    let bad_feed = signed_bundle(
        bundle_with_feed(
            1,
            "2026-10-01T00:00:00Z",
            "2126-01-01T00:00:00Z",
            feed("staging"),
        ),
        PUBLISH,
        "2026-10-01T00:00:00Z",
    );

    // The README's claims, checked against the core before anything is written.
    let trust = temp_dir("fixtures-check");
    let check = |b: &Signed| check_trust_bundle(&trust, "acme", &b.bytes, &b.sidecar, now);
    let store = |b: &Signed| {
        let sidecar = serde_json::to_vec(&b.sidecar).unwrap();

        store_trust_bundle(&trust, "acme", &b.bytes, &sidecar, None).unwrap();
    };

    assert!(
        check(&unlisted).is_err(),
        "an unlisted signer must not install"
    );
    assert!(check(&stale).is_err(), "an expired bundle must not install");
    assert!(
        check(&bad_feed).is_err(),
        "a feed root the bundle does not hold must not install"
    );
    assert_eq!(
        check(&with_feed)
            .unwrap()
            .bundle
            .revocation_feed
            .unwrap()
            .root,
        "acme/prod"
    );
    check(&v1).unwrap();
    store(&v1);
    check(&v2).unwrap();
    assert!(
        check(&unlisted).is_err(),
        "an unlisted signer must not update"
    );
    store(&v2);
    assert!(check(&v1).is_err(), "a lower version must not update");
    let _ = fs::remove_dir_all(&trust);

    let _ = fs::remove_dir_all(out.join("bundles"));
    let _ = fs::remove_dir_all(out.join("artifacts"));
    write_bundle(&out, "acme-v1", &v1);
    write_bundle(&out, "acme-v2", &v2);
    write_bundle(&out, "acme-v2-unlisted-signer", &unlisted);
    write_bundle(&out, "acme-stale", &stale);
    write_bundle(&out, "acme-feed", &with_feed);
    write_bundle(&out, "acme-feed-bad-root", &bad_feed);
    write_artifact(
        &out,
        "prod-signed.txt",
        b"signed through acme's prod Fulcio and log\n",
        &prod(),
        "2026-10-01T06:00:00Z",
    );
    write_artifact(
        &out,
        "before-retirement.txt",
        b"signed through acme's old Fulcio before its CA was retired\n",
        &old(),
        "2026-06-01T00:00:00Z",
    );
    write_artifact(
        &out,
        "after-retirement.txt",
        b"signed through acme's old Fulcio after its CA was retired\n",
        &old(),
        "2026-08-01T00:00:00Z",
    );
}

/// acme's deployment that rotates its Fulcio intermediate under one offline
/// root: generation 1's entry lists the intermediate and the root and ends on
/// 2026-07-01; generation 2's entry lists the same root, open-ended.
fn rotated() -> MockSigstore {
    MockSigstore::new_valid(
        60,
        "acme rotated root",
        at("2026-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
    .with_intermediate("acme rotated intermediate 1")
}

fn rotated_root(deployment: &MockSigstore) -> Value {
    let mut doc = deployment.trusted_root();
    let root = doc["certificateAuthorities"][0]["certChain"]["certificates"][1].clone();

    doc["certificateAuthorities"][0]["validFor"] =
        json!({ "start": "2026-01-01T00:00:00Z", "end": "2026-07-01T00:00:00Z" });
    doc["certificateAuthorities"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "subject": { "commonName": "acme rotated root" },
            "certChain": { "certificates": [root] },
            "validFor": { "start": "2026-07-01T00:00:00Z" }
        }));
    doc
}

#[test]
#[ignore = "writes fixtures; run with PROMPTSIGN_FIXTURES_OUT set"]
fn write_rotated_intermediate_fixtures() {
    let out = std::env::var_os("PROMPTSIGN_FIXTURES_OUT")
        .map(std::path::PathBuf::from)
        .expect("set PROMPTSIGN_FIXTURES_OUT to the fixture directory")
        .join("rotated");
    let deployment = rotated();
    let doc = rotated_root(&deployment);
    let files: [(&str, &[u8], &str); 2] = [
        (
            "before-rotation.txt",
            b"signed through acme's intermediate 1 while it was current
",
            "2026-06-01T00:00:00Z",
        ),
        (
            "retired-intermediate.txt",
            b"signed through acme's intermediate 1 after generation 2 replaced it
",
            "2026-08-01T00:00:00Z",
        ),
    ];
    let signed: Vec<Value> = files
        .iter()
        .map(|(file, bytes, when)| deployment.sign_file_at(file, bytes, ALICE, ACME_SSO, at(when)))
        .collect();

    // The README's claims, checked against the core before anything is written.
    let root = Root::from_trusted_root("acme-rotated", &doc).unwrap();

    assert!(verify_keyless_with(&signed[0], std::slice::from_ref(&root)).is_ok());

    let err = verify_keyless_with(&signed[1], std::slice::from_ref(&root))
        .err()
        .expect("a signature from the retired intermediate must fail");

    assert!(err.contains("validity window"), "{err}");

    let _ = fs::remove_dir_all(&out);
    write_json(&out.join("trusted_root.json"), &doc);
    for ((file, bytes, _), sidecar) in files.iter().zip(&signed) {
        fs::write(out.join(file), bytes).unwrap();
        write_json(&out.join(format!("{file}.psig.json")), sidecar);
    }
}

/// acme's Rekor v2 deployment: a CA, a Rekor v1 log, an Ed25519 Rekor v2 log
/// and a timestamp authority.
fn v2() -> MockSigstore {
    MockSigstore::new_valid(
        50,
        "acme v2",
        at("2026-01-01T00:00:00Z"),
        at("2126-01-01T00:00:00Z"),
    )
}

/// One Rekor v2 fixture: a file, its sidecar, and whether it verifies.
struct Case {
    file: &'static str,
    sidecar: Value,
    verifies: bool,
}

#[test]
#[ignore = "writes fixtures; run with PROMPTSIGN_REKOR_V2_FIXTURES_OUT set"]
fn write_rekor_v2_fixtures() {
    let out = std::env::var_os("PROMPTSIGN_REKOR_V2_FIXTURES_OUT")
        .map(std::path::PathBuf::from)
        .expect("set PROMPTSIGN_REKOR_V2_FIXTURES_OUT to the fixture directory");
    let d = v2();
    let signed = at("2026-10-01T12:00:00Z");
    let doc = d.trusted_root_v2();
    let root = Root::from_trusted_root("acme-v2", &doc).unwrap();
    let body = |file: &str| format!("{file}: signed through acme's Rekor v2 log\n");
    let v2_signed =
        |file: &str| d.sign_file_v2_at(file, body(file).as_bytes(), ALICE, ACME_SSO, signed);
    let sig_of = |s: &Value| {
        BASE64_STANDARD
            .decode(s["envelope"]["signatures"][0]["sig"].as_str().unwrap())
            .unwrap()
    };
    let mut cases = Vec::new();

    cases.push(Case {
        file: "signed.txt",
        sidecar: v2_signed("signed.txt"),
        verifies: true,
    });

    let mut none = v2_signed("no-timestamp.txt");

    none.as_object_mut().unwrap().remove("timestamps");
    cases.push(Case {
        file: "no-timestamp.txt",
        sidecar: none,
        verifies: false,
    });

    let mut other = v2_signed("timestamp-other-signature.txt");

    other["timestamps"] =
        json!([BASE64_STANDARD.encode(d.timestamp(b"another signature", signed, false))]);
    cases.push(Case {
        file: "timestamp-other-signature.txt",
        sidecar: other,
        verifies: false,
    });

    let mut late = v2_signed("timestamp-after-certificate.txt");
    let late_sig = sig_of(&late);

    late["timestamps"] =
        json!([BASE64_STANDARD.encode(d.timestamp(&late_sig, signed + 3600, false))]);
    cases.push(Case {
        file: "timestamp-after-certificate.txt",
        sidecar: late,
        verifies: false,
    });

    let mut forged = v2_signed("checkpoint-other-key.txt");
    let proof = forged["transparency"]["inclusionProof"].clone();
    let root_hash = BASE64_STANDARD
        .decode(proof["rootHash"].as_str().unwrap())
        .unwrap();

    forged["transparency"]["inclusionProof"]["checkpoint"] = json!(checkpoint(
        &d.log2_origin(),
        &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
        proof["treeSize"].as_u64().unwrap(),
        &root_hash
    ));
    cases.push(Case {
        file: "checkpoint-other-key.txt",
        sidecar: forged,
        verifies: false,
    });

    let mut witnessed = v2_signed("checkpoint-witness-first.txt");
    let note = witnessed["transparency"]["inclusionProof"]["checkpoint"]
        .as_str()
        .unwrap()
        .to_string();
    let (text, sigs) = note.split_once("\n\n").unwrap();

    witnessed["transparency"]["inclusionProof"]["checkpoint"] = json!(format!(
        "{text}\n\n\u{2014} witness.test AAAAAAAAAAAAAAAAAAAAAAAA\n{sigs}"
    ));
    cases.push(Case {
        file: "checkpoint-witness-first.txt",
        sidecar: witnessed,
        verifies: true,
    });

    let mut tampered = v2_signed("proof-tampered.txt");

    tampered["transparency"]["inclusionProof"]["hashes"][0] =
        json!(BASE64_STANDARD.encode([7u8; 32]));
    cases.push(Case {
        file: "proof-tampered.txt",
        sidecar: tampered,
        verifies: false,
    });

    let v1_body = body("v1-with-timestamp.txt");
    let mut v1 = d.sign_file_at(
        "v1-with-timestamp.txt",
        v1_body.as_bytes(),
        ALICE,
        ACME_SSO,
        signed,
    );

    d.add_timestamp(&mut v1, signed + 5);
    cases.push(Case {
        file: "v1-with-timestamp.txt",
        sidecar: v1,
        verifies: true,
    });

    // The README's claims, checked against the core before anything is written.
    for c in &cases {
        let result = verify_keyless_with(&c.sidecar, std::slice::from_ref(&root));

        assert_eq!(result.is_ok(), c.verifies, "{}: {:?}", c.file, result.err());
        if let Ok(v) = result {
            assert_eq!(v.signed_at, signed, "{}", c.file);
        }
    }

    let _ = fs::remove_dir_all(out.join("artifacts"));
    fs::create_dir_all(out.join("artifacts")).unwrap();
    write_json(&out.join("trusted_root.json"), &doc);
    for c in &cases {
        let file = if c.file == "v1-with-timestamp.txt" {
            v1_body.clone()
        } else {
            body(c.file)
        };

        fs::write(out.join("artifacts").join(c.file), file).unwrap();
        write_json(
            &out.join("artifacts").join(format!("{}.psig.json", c.file)),
            &c.sidecar,
        );
    }
}

/// A native keyless bundle in Sigstore's bundle v0.3 carriage, as cosign
/// writes it: the leaf certificate, the Rekor v2 entry with its checkpoint,
/// and the timestamps.
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
#[ignore = "writes fixtures; run with PROMPTSIGN_APPROVAL_FIXTURES_OUT set"]
fn write_approval_fixtures() {
    use promptsign_core::approval::{statement, verify_approval, Rejected, IN_TOTO_PAYLOAD_TYPE};
    use sha2::{Digest, Sha256};

    let out = std::env::var_os("PROMPTSIGN_APPROVAL_FIXTURES_OUT")
        .map(std::path::PathBuf::from)
        .expect("set PROMPTSIGN_APPROVAL_FIXTURES_OUT to the fixture directory");
    // The conformance skill's content listing, which listing.txt holds.
    let listing = fs::read(out.join("listing.txt")).unwrap();
    let digest: String = Sha256::digest(&listing)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let d = v2();
    let signed = at("2026-10-01T12:00:00Z");
    let root = Root::from_trusted_root("acme-v2", &d.trusted_root_v2()).unwrap();
    let approval = |covers: &str, note: &str| {
        serde_json::to_vec(&statement(
            "demo-skill",
            covers,
            "2026-10-01T12:00:00Z",
            Some(note),
        ))
        .unwrap()
    };
    let bob = d.sign_typed_payload_at(
        IN_TOTO_PAYLOAD_TYPE,
        &approval(&digest, "reviewed by bob"),
        "bob@acme.test",
        ACME_SSO,
        signed,
    );
    let carol = to_sigstore(&d.sign_typed_payload_v2_at(
        IN_TOTO_PAYLOAD_TYPE,
        &approval(&digest, "reviewed by carol"),
        "carol@acme.test",
        ACME_SSO,
        signed,
    ));
    let other = d.sign_typed_payload_at(
        IN_TOTO_PAYLOAD_TYPE,
        &approval(&"0".repeat(64), "an earlier version"),
        "dave@acme.test",
        ACME_SSO,
        signed,
    );

    // The README's claims, checked against the core before anything is written.
    for (bundle, who) in [(&bob, "bob@acme.test"), (&carol, "carol@acme.test")] {
        let a = verify_approval(bundle, &digest, std::slice::from_ref(&root), signed).unwrap();

        assert_eq!((a.identity.as_str(), a.root.as_str()), (who, "acme-v2"));
    }
    assert_eq!(
        verify_approval(&other, &digest, std::slice::from_ref(&root), signed),
        Err(Rejected::OtherContent)
    );

    write_json(&out.join("bob.json"), &bob);
    write_json(&out.join("carol.sigstore.json"), &carol);
    write_json(&out.join("other-content.json"), &other);
}
