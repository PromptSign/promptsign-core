// X.509 path checks shared by keyless (Fulcio) and certificate-mode
// verification: link signatures, CA constraints on every issuing certificate,
// validity windows, and the DSSE signature made by the leaf key.

use crate::trustroot::Root;
use crate::Result;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use x509_cert::Certificate;

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_EKU_CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
const OID_EKU_ANY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37.0");

pub(crate) fn spki_der_of(cert: &Certificate) -> Result<Vec<u8>> {
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("SPKI encode: {e}"))
}

pub(crate) fn subject_of(cert: &Certificate) -> String {
    cert.tbs_certificate.subject.to_string()
}

fn ec_curve(cert: &Certificate) -> Result<ObjectIdentifier> {
    cert.tbs_certificate
        .subject_public_key_info
        .algorithm
        .parameters
        .as_ref()
        .ok_or("EC key has no curve parameter")?
        .decode_as()
        .map_err(|e| format!("EC curve: {e}"))
}

/// Verify that `child`'s signature was produced by the holder of `parent`'s key.
pub(crate) fn verify_signed_by(child: &Certificate, parent: &Certificate) -> Result<()> {
    let tbs = child
        .tbs_certificate
        .to_der()
        .map_err(|e| format!("TBS encode: {e}"))?;
    let sig = child
        .signature
        .as_bytes()
        .ok_or("certificate signature has unused bits")?;
    let parent_spki_der = spki_der_of(parent)?;
    let sig_alg = child.signature_algorithm.oid;

    if sig_alg == OID_ED25519 {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::Verifier;

        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&parent_spki_der)
            .map_err(|e| format!("parent key: {e}"))?;
        let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| "malformed ed25519 sig")?;

        return vk
            .verify(&tbs, &s)
            .map_err(|_| "certificate signature invalid".to_string());
    }
    if sig_alg == OID_RSA_SHA256 || sig_alg == OID_RSA_SHA384 || sig_alg == OID_RSA_SHA512 {
        return verify_rsa_pkcs1(&parent_spki_der, sig_alg, &tbs, sig)
            .map_err(|_| "certificate signature invalid".to_string());
    }
    if sig_alg != OID_ECDSA_SHA256 && sig_alg != OID_ECDSA_SHA384 {
        return Err(format!(
            "unsupported certificate signature algorithm: {sig_alg}"
        ));
    }
    if parent.tbs_certificate.subject_public_key_info.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err("parent key is not an EC key".to_string());
    }

    let digest: Vec<u8> = if sig_alg == OID_ECDSA_SHA256 {
        Sha256::digest(&tbs).to_vec()
    } else {
        Sha384::digest(&tbs).to_vec()
    };

    verify_ecdsa_prehash(&parent_spki_der, ec_curve(parent)?, &digest, sig)
        .map_err(|_| "certificate signature invalid".to_string())
}

/// RSA PKCS#1 v1.5 over SHA-2, the signature most enterprise CAs put on the
/// certificates they issue.
fn verify_rsa_pkcs1(
    spki_der: &[u8],
    sig_alg: ObjectIdentifier,
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};

    let key = RsaPublicKey::from_public_key_der(spki_der).map_err(|e| format!("RSA key: {e}"))?;
    let (scheme, digest) = if sig_alg == OID_RSA_SHA256 {
        (
            Pkcs1v15Sign::new::<Sha256>(),
            Sha256::digest(message).to_vec(),
        )
    } else if sig_alg == OID_RSA_SHA384 {
        (
            Pkcs1v15Sign::new::<Sha384>(),
            Sha384::digest(message).to_vec(),
        )
    } else {
        (
            Pkcs1v15Sign::new::<Sha512>(),
            Sha512::digest(message).to_vec(),
        )
    };

    key.verify(scheme, &digest, sig)
        .map_err(|_| "RSA signature invalid".to_string())
}

fn verify_ecdsa_prehash(
    spki_der: &[u8],
    curve: ObjectIdentifier,
    digest: &[u8],
    sig_der: &[u8],
) -> Result<()> {
    if curve == OID_P256 {
        let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| format!("P-256 key: {e}"))?;
        let s = p256::ecdsa::Signature::from_der(sig_der).map_err(|_| "malformed ECDSA sig")?;

        vk.verify_prehash(digest, &s)
            .map_err(|_| "ECDSA signature invalid".to_string())
    } else if curve == OID_P384 {
        let vk = p384::ecdsa::VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| format!("P-384 key: {e}"))?;
        let s = p384::ecdsa::Signature::from_der(sig_der).map_err(|_| "malformed ECDSA sig")?;

        vk.verify_prehash(digest, &s)
            .map_err(|_| "ECDSA signature invalid".to_string())
    } else {
        Err(format!("unsupported EC curve: {curve}"))
    }
}

/// Verify a DSSE signature with the leaf certificate's key: Ed25519, P-256
/// with SHA-256, or P-384 with SHA-384 (the hash follows the curve).
pub(crate) fn verify_leaf_signature(leaf: &Certificate, message: &[u8], sig: &[u8]) -> Result<()> {
    let spki = &leaf.tbs_certificate.subject_public_key_info;
    let spki_der = spki_der_of(leaf)?;

    if spki.algorithm.oid == OID_ED25519 {
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::Verifier;

        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&spki_der)
            .map_err(|e| format!("leaf key: {e}"))?;
        let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| "malformed signature")?;

        return vk
            .verify(message, &s)
            .map_err(|_| "signature verification failed".to_string());
    }
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(format!(
            "unsupported leaf key algorithm: {}",
            spki.algorithm.oid
        ));
    }

    let curve = ec_curve(leaf)?;
    let digest: Vec<u8> = if curve == OID_P384 {
        Sha384::digest(message).to_vec()
    } else {
        Sha256::digest(message).to_vec()
    };

    verify_ecdsa_prehash(&spki_der, curve, &digest, sig)
        .map_err(|_| "signature verification failed".to_string())
}

fn extension(cert: &Certificate, oid: ObjectIdentifier) -> Option<&x509_cert::ext::Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
}

/// A certificate that issues another one must say it is a CA, and its path
/// length limit must allow the CA certificates beneath it.
fn check_issuer(cert: &Certificate, cas_below: usize) -> Result<()> {
    let ext = extension(cert, OID_BASIC_CONSTRAINTS).ok_or_else(|| {
        format!(
            "\"{}\" issues certificates but has no basic constraints",
            subject_of(cert)
        )
    })?;
    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| format!("basic constraints: {e}"))?;

    if !bc.ca {
        return Err(format!(
            "\"{}\" issues certificates but is not a CA",
            subject_of(cert)
        ));
    }
    if let Some(limit) = bc.path_len_constraint {
        if cas_below > limit as usize {
            return Err(format!(
                "\"{}\" allows {limit} CA certificates beneath it, the chain has {cas_below}",
                subject_of(cert)
            ));
        }
    }
    if let Some(ext) = extension(cert, OID_KEY_USAGE) {
        let ku =
            KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| format!("key usage: {e}"))?;

        if !ku.key_cert_sign() {
            return Err(format!(
                "\"{}\" issues certificates without the keyCertSign usage",
                subject_of(cert)
            ));
        }
    }
    Ok(())
}

/// A certificate-mode leaf must be allowed to sign: digitalSignature when it
/// states key usages, code signing when it states extended ones.
pub(crate) fn check_signing_leaf(leaf: &Certificate) -> Result<()> {
    if let Some(ext) = extension(leaf, OID_KEY_USAGE) {
        let ku =
            KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| format!("key usage: {e}"))?;

        if !ku.digital_signature() {
            return Err("signing certificate lacks the digitalSignature usage".to_string());
        }
    }
    if let Some(ext) = extension(leaf, OID_EXT_KEY_USAGE) {
        let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
            .map_err(|e| format!("extended key usage: {e}"))?;

        if !eku
            .0
            .iter()
            .any(|o| *o == OID_EKU_CODE_SIGNING || *o == OID_EKU_ANY)
        {
            return Err("signing certificate is not issued for code signing".to_string());
        }
    }
    Ok(())
}

pub(crate) fn validity(cert: &Certificate) -> (i64, i64) {
    let v = &cert.tbs_certificate.validity;

    (
        v.not_before.to_unix_duration().as_secs() as i64,
        v.not_after.to_unix_duration().as_secs() as i64,
    )
}

/// Every certificate on the path must be valid at `at`.
pub(crate) fn check_valid_at(path: &[Certificate], at: i64) -> Result<()> {
    for cert in path {
        let (nb, na) = validity(cert);

        if at < nb || at > na {
            return Err(format!(
                "certificate \"{}\" is not valid at {at} (valid {nb} to {na})",
                subject_of(cert)
            ));
        }
    }
    Ok(())
}

pub(crate) fn is_self_signed(cert: &Certificate) -> bool {
    cert.tbs_certificate.subject == cert.tbs_certificate.issuer
        && verify_signed_by(cert, cert).is_ok()
}

/// A verified path from the leaf up to a certificate the root pins.
pub(crate) struct Anchored<'r> {
    pub root: &'r Root,
    /// Leaf first, ending at the pinned certificate.
    pub path: Vec<Certificate>,
}

/// Every root a leaf-first chain terminates at, in registry order. The chain
/// is checked link by link by position and signature, never by subject name;
/// the top certificate must be pinned by the root or signed by a certificate
/// the root pins. Each issuing certificate on the path must be a CA.
pub(crate) fn anchor_chain<'r>(
    chain: &[Certificate],
    roots: &'r [Root],
) -> Result<Vec<Anchored<'r>>> {
    if chain.is_empty() {
        return Err("empty certificate chain".to_string());
    }
    for i in 0..chain.len() - 1 {
        verify_signed_by(&chain[i], &chain[i + 1]).map_err(|e| format!("chain link {i}: {e}"))?;
    }

    let last = &chain[chain.len() - 1];
    let last_der = last.to_der().map_err(|e| e.to_string())?;
    let mut anchored = Vec::new();
    let mut constraint_error = None;

    for root in roots {
        let mut path = chain.to_vec();
        let pinned = root
            .ca_certs
            .iter()
            .any(|ca| ca.to_der().ok().as_deref() == Some(&last_der));

        if !pinned {
            match root
                .ca_certs
                .iter()
                .find(|ca| verify_signed_by(last, ca).is_ok())
            {
                Some(ca) => path.push(ca.clone()),
                None => continue,
            }
        }
        match (1..path.len()).try_for_each(|i| check_issuer(&path[i], i - 1)) {
            Ok(()) => anchored.push(Anchored { root, path }),
            Err(e) => constraint_error = constraint_error.or(Some(e)),
        }
    }
    if let (true, Some(e)) = (anchored.is_empty(), constraint_error) {
        return Err(e);
    }
    if anchored.is_empty() {
        return Err(format!(
            "certificate chain does not terminate at a trusted root: it ends at \"{}\", which is not in your trust roots (add it with \"promptsign trust add\" if you trust it)",
            last.tbs_certificate.issuer
        ));
    }
    Ok(anchored)
}
