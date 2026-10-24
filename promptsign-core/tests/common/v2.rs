// Rekor v2 and RFC 3161 for the mock deployment: an Ed25519 log that proves
// inclusion against checkpoints it signs, and a timestamp authority with its
// own root. Ed25519 and RFC 6979 ECDSA are deterministic, so fixtures built
// from these come out byte-identical on every run.

use super::profile::{self, Profile};
use super::{validity, IssuerExt, MockSigstore};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::Signer as _;
use promptsign_core::bundle::{pae, PAYLOAD_TYPE};
use promptsign_core::util::{format_iso8601, hex, sha256_hex};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use x509_cert::builder::Builder;
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const TSA_POLICY: &str = "1.3.6.1.4.1.57264.2";

fn spki_of(der: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(der).unwrap()
}

fn p256_spki(key: &p256::ecdsa::SigningKey) -> SubjectPublicKeyInfoOwned {
    use p256::pkcs8::EncodePublicKey;

    spki_of(key.verifying_key().to_public_key_der().unwrap().as_bytes())
}

/// The deployment's timestamp authority: a root, a signing key, and the
/// timestamping certificate the root issued for it.
pub(super) fn timestamp_authority(
    seed: u8,
    cn: &str,
    not_before: i64,
    not_after: i64,
) -> (Certificate, p256::ecdsa::SigningKey, Certificate) {
    let root_key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(3); 32]).unwrap();
    let root_name = Name::from_str(&format!("CN={cn} TSA root,O=promptsign tests")).unwrap();
    let root = profile::builder(
        Profile::Root,
        SerialNumber::from(1u32),
        validity(not_before, not_after),
        root_name.clone(),
        p256_spki(&root_key),
    )
    .unwrap()
    .build::<_, p256::ecdsa::DerSignature>(&root_key)
    .unwrap();
    let key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(4); 32]).unwrap();
    let mut leaf = profile::builder(
        Profile::Leaf {
            issuer: root_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        validity(not_before, not_after),
        Name::from_str(&format!("CN={cn} TSA,O=promptsign tests")).unwrap(),
        p256_spki(&key),
    )
    .unwrap();

    leaf.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
        TIME_STAMPING,
    )]))
    .unwrap();

    (
        root,
        key,
        leaf.build::<_, p256::ecdsa::DerSignature>(&root_key)
            .unwrap(),
    )
}

/// One DER TLV.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];

    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();

        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn oid(s: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(s).to_der().unwrap()
}

fn int(v: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = v
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();

    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn generalized_time(t: i64) -> Vec<u8> {
    let s: String = format_iso8601(t)
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'Z')
        .collect();

    tlv(0x18, s.as_bytes())
}

/// RFC 6962 hashes, and a whole tree's root and audit paths.
pub fn leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([0u8]);
    h.update(data);
    h.finalize().to_vec()
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().to_vec()
}

fn mth(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let k = leaves.len().next_power_of_two() / 2;

    node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

fn audit_path(m: usize, leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if leaves.len() == 1 {
        return Vec::new();
    }

    let k = leaves.len().next_power_of_two() / 2;

    if m < k {
        let mut p = audit_path(m, &leaves[..k]);

        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &leaves[k..]);

        p.push(mth(&leaves[..k]));
        p
    }
}

/// The signed-note key hash of an Ed25519 log key under `origin`.
pub fn note_key_hash(origin: &str, key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update(origin.as_bytes());
    h.update(b"\n\x01");
    h.update(key.as_bytes());
    h.finalize().to_vec()
}

/// A C2SP checkpoint for `origin`, signed by `key`.
pub fn checkpoint(origin: &str, key: &ed25519_dalek::SigningKey, size: u64, root: &[u8]) -> String {
    let text = format!("{origin}\n{size}\n{}\n", BASE64_STANDARD.encode(root));
    let mut sig = note_key_hash(origin, &key.verifying_key())[..4].to_vec();

    sig.extend(key.sign(text.as_bytes()).to_bytes());
    format!(
        "{text}\n\u{2014} {origin} {}\n",
        BASE64_STANDARD.encode(sig)
    )
}

impl MockSigstore {
    /// The Rekor v2 log's origin, the host of its base URL.
    pub fn log2_origin(&self) -> String {
        format!(
            "rekor-{}.test",
            hex(&self.log2_key.verifying_key().as_bytes()[..4])
        )
    }

    pub fn log2_id(&self) -> String {
        hex(&note_key_hash(
            &self.log2_origin(),
            &self.log2_key.verifying_key(),
        ))
    }

    pub fn log2_key(&self) -> &ed25519_dalek::SigningKey {
        &self.log2_key
    }

    /// This deployment as a trusted_root.json document with all of it: the
    /// CA, the Rekor v1 log, the Rekor v2 log and the timestamp authority.
    pub fn trusted_root_v2(&self) -> Value {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let mut doc = self.trusted_root();
        let log2 = self.log2_key.verifying_key().to_public_key_der().unwrap();
        let raw =
            |c: &Certificate| json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap()) });

        doc["tlogs"].as_array_mut().unwrap().push(json!({
            "baseUrl": format!("https://{}", self.log2_origin()),
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": BASE64_STANDARD.encode(log2.as_bytes()),
                "keyDetails": "PKIX_ED25519"
            },
            "logId": { "keyId": BASE64_STANDARD.encode(note_key_hash(&self.log2_origin(), &self.log2_key.verifying_key())) }
        }));
        doc["timestampAuthorities"] = json!([{
            "subject": { "commonName": "test TSA" },
            "uri": "https://tsa.test/api/v1/timestamp",
            "certChain": { "certificates": [raw(&self.tsa_cert), raw(&self.tsa_root_cert)] }
        }]);
        doc
    }

    /// An RFC 3161 TimeStampResp over `sig`, dated `at`. `embed` puts the
    /// timestamping certificate in the token.
    pub fn timestamp(&self, sig: &[u8], at: i64, embed: bool) -> Vec<u8> {
        let imprint = seq(&[
            seq(&[oid(SHA256_OID), tlv(0x05, &[])]),
            tlv(0x04, &Sha256::digest(sig)),
        ]);
        let tst_info = seq(&[
            int(1),
            oid(TSA_POLICY),
            imprint,
            int(at as u64),
            generalized_time(at),
        ]);
        let attrs = [
            seq(&[oid(CONTENT_TYPE), set(&[oid(TST_INFO)])]),
            seq(&[
                oid(MESSAGE_DIGEST),
                set(&[tlv(0x04, &Sha256::digest(&tst_info))]),
            ]),
        ]
        .concat();
        let signature: p256::ecdsa::DerSignature = self.tsa_key.sign(&tlv(0x31, &attrs));
        let signer_info = seq(&[
            int(1),
            seq(&[
                self.tsa_cert.tbs_certificate().issuer().to_der().unwrap(),
                self.tsa_cert
                    .tbs_certificate()
                    .serial_number()
                    .to_der()
                    .unwrap(),
            ]),
            seq(&[oid(SHA256_OID)]),
            tlv(0xa0, &attrs),
            seq(&[oid(ECDSA_SHA256)]),
            tlv(0x04, signature.as_bytes()),
        ]);
        let mut signed_data = vec![
            int(3),
            set(&[seq(&[oid(SHA256_OID)])]),
            seq(&[oid(TST_INFO), tlv(0xa0, &tlv(0x04, &tst_info))]),
        ];

        if embed {
            signed_data.push(tlv(0xa0, &self.tsa_cert.to_der().unwrap()));
        }
        signed_data.push(set(&[signer_info]));
        seq(&[
            seq(&[int(0)]),
            seq(&[oid(SIGNED_DATA), tlv(0xa0, &seq(&signed_data))]),
        ])
    }

    /// Adds a timestamp over the bundle's envelope signature, dated `at`.
    pub fn add_timestamp(&self, bundle: &mut Value, at: i64) {
        let sig = BASE64_STANDARD
            .decode(bundle["envelope"]["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        let ts = BASE64_STANDARD.encode(self.timestamp(&sig, at, false));

        match bundle["timestamps"].as_array_mut() {
            Some(list) => list.push(json!(ts)),
            None => bundle["timestamps"] = json!([ts]),
        }
    }

    /// A Fulcio-style leaf for a P-256 key, valid for ten minutes from a
    /// minute before `at`.
    fn leaf_p256(
        &self,
        serial: u32,
        key: &p256::ecdsa::SigningKey,
        identity: &str,
        issuer: &str,
        at: i64,
    ) -> Certificate {
        let mut leaf = profile::builder(
            Profile::Leaf {
                issuer: self.ca_name.clone(),
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(serial),
            validity(at - 60, at + 600),
            Name::from_str("CN=sigstore-intermediate").unwrap(),
            p256_spki(key),
        )
        .unwrap();
        let san = if identity.contains("://") {
            GeneralName::UniformResourceIdentifier(Ia5String::new(identity).unwrap())
        } else {
            GeneralName::Rfc822Name(Ia5String::new(identity).unwrap())
        };

        leaf.add_extension(&SubjectAltName(vec![san])).unwrap();
        leaf.add_extension(&IssuerExt(issuer.to_string())).unwrap();
        leaf.build::<_, p256::ecdsa::DerSignature>(&self.ca_key)
            .unwrap()
    }

    /// A keyless PromptSign bundle logged in the Rekor v2 log as a
    /// `hashedrekord` 0.0.2 entry, with a timestamp dated `at`. Rekor v2
    /// needs a prehashed signature, so the leaf key is P-256.
    pub fn sign_payload_v2_at(
        &self,
        payload: &[u8],
        identity: &str,
        issuer: &str,
        at: i64,
    ) -> Value {
        self.sign_typed_payload_v2_at(PAYLOAD_TYPE, payload, identity, issuer, at)
    }

    /// As `sign_payload_v2_at`, with another DSSE payloadType.
    pub fn sign_typed_payload_v2_at(
        &self,
        payload_type: &str,
        payload: &[u8],
        identity: &str,
        issuer: &str,
        at: i64,
    ) -> Value {
        let serial = self.serial.get();

        self.serial.set(serial + 1);

        let leaf_key =
            p256::ecdsa::SigningKey::from_slice(&[(serial % 100) as u8 + 1; 32]).unwrap();
        let leaf = self.leaf_p256(serial, &leaf_key, identity, issuer, at);
        let leaf_der = leaf.to_der().unwrap();
        let sig: p256::ecdsa::DerSignature = leaf_key.sign(&pae(payload_type, payload));
        let body = json!({
            "apiVersion": "0.0.2",
            "kind": "hashedrekord",
            "spec": { "hashedRekordV002": {
                "data": {
                    "algorithm": "SHA2_256",
                    "digest": BASE64_STANDARD.encode(Sha256::digest(pae(payload_type, payload)))
                },
                "signature": {
                    "content": BASE64_STANDARD.encode(sig.as_bytes()),
                    "verifier": {
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                        "x509Certificate": { "rawBytes": BASE64_STANDARD.encode(&leaf_der) }
                    }
                }
            } }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let index = serial as usize;
        let size = index + 3;
        let leaves: Vec<Vec<u8>> = (0..size)
            .map(|i| {
                if i == index {
                    leaf_hash(&body_bytes)
                } else {
                    leaf_hash(format!("entry {i}").as_bytes())
                }
            })
            .collect();
        let root = mth(&leaves);

        json!({
            "schema": "promptsign/bundle/v1",
            "envelope": {
                "payloadType": payload_type,
                "payload": BASE64_STANDARD.encode(payload),
                "signatures": [{ "keyid": sha256_hex(leaf.tbs_certificate().subject_public_key_info().to_der().unwrap().as_slice()), "sig": BASE64_STANDARD.encode(sig.as_bytes()) }]
            },
            "signer": {
                "scheme": "keyless",
                "identity": identity,
                "issuer": issuer,
                "certChain": [BASE64_STANDARD.encode(&leaf_der)]
            },
            "transparency": {
                "logId": self.log2_id(),
                "logIndex": index,
                "body": BASE64_STANDARD.encode(&body_bytes),
                "inclusionProof": {
                    "treeSize": size,
                    "rootHash": BASE64_STANDARD.encode(&root),
                    "hashes": audit_path(index, &leaves).iter().map(|h| BASE64_STANDARD.encode(h)).collect::<Vec<_>>(),
                    "checkpoint": checkpoint(&self.log2_origin(), &self.log2_key, size as u64, &root)
                }
            },
            "timestamps": [BASE64_STANDARD.encode(self.timestamp(sig.as_bytes(), at, false))]
        })
    }

    /// A Sigstore bundle signed in certificate mode (no log) by a leaf of
    /// this deployment's CA valid around `at`, optionally with a timestamp
    /// dated `at`.
    pub fn sign_sigstore_certificate_mode(
        &self,
        payload: &[u8],
        at: i64,
        timestamped: bool,
    ) -> Value {
        self.sign_sigstore_certificate_mode_typed(
            "application/vnd.in-toto+json",
            payload,
            at,
            timestamped,
        )
    }

    /// As `sign_sigstore_certificate_mode`, with another DSSE payloadType.
    pub fn sign_sigstore_certificate_mode_typed(
        &self,
        payload_type: &str,
        payload: &[u8],
        at: i64,
        timestamped: bool,
    ) -> Value {
        let leaf_key = p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).unwrap();
        let leaf = self.leaf_p256(
            7,
            &leaf_key,
            "builder@acme.test",
            "https://sso.acme.test",
            at,
        );
        let sig: p256::ecdsa::DerSignature = leaf_key.sign(&pae(payload_type, payload));
        let mut material = json!({
            "x509CertificateChain": { "certificates": [
                { "rawBytes": BASE64_STANDARD.encode(leaf.to_der().unwrap()) }
            ] }
        });

        if timestamped {
            material["timestampVerificationData"] = json!({ "rfc3161Timestamps": [
                { "signedTimestamp": BASE64_STANDARD.encode(self.timestamp(sig.as_bytes(), at, true)) }
            ] });
        }
        json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": material,
            "dsseEnvelope": {
                "payload": BASE64_STANDARD.encode(payload),
                "payloadType": payload_type,
                "signatures": [{ "sig": BASE64_STANDARD.encode(sig.as_bytes()), "keyid": "" }]
            }
        })
    }

    /// As `sign_file_at`, logged in the Rekor v2 log.
    pub fn sign_file_v2_at(
        &self,
        file_name: &str,
        bytes: &[u8],
        identity: &str,
        issuer: &str,
        at: i64,
    ) -> Value {
        let manifest = json!({
            "schema": "promptsign/manifest/v1",
            "name": file_name,
            "scope": "file",
            "files": [{ "path": file_name, "sha256": sha256_hex(bytes) }]
        });

        self.sign_payload_v2_at(
            &serde_json::to_vec(&manifest).unwrap(),
            identity,
            issuer,
            at,
        )
    }
}
