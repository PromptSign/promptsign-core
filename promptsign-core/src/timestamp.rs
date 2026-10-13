// RFC 3161 signed timestamps (spec/05 §4, spec/07 §1). A timestamp authority
// (TSA) signs the hash of a signature together with the time it saw it. That
// time replaces a transparency log's integratedTime: Rekor v2 entries carry
// none, and a certificate-mode signature with a timestamp is checked at the
// time it was made instead of now. Offline: the authority's certificates come
// from the trust root, the timestamp is stapled in the bundle.

use crate::chain::{
    check_issuer, check_valid_at, digest_with, extension, subject_of, verify_cms_signature,
    verify_signed_by,
};
use crate::tlv::{self, Tlv};
use crate::trustroot::Window;
use crate::util::days_from_civil;
use crate::Result;
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OID_SUBJECT_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const OID_EKU_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// A bundle may carry at most this many timestamps.
pub(crate) const MAX_TIMESTAMPS: usize = 32;

/// One timestamp authority of a trust root (`timestampAuthorities[]`).
#[derive(Clone)]
pub struct TimestampAuthority {
    /// The chain as the root lists it: the timestamping certificate first,
    /// intermediates next, the anchor last.
    pub certs: Vec<Certificate>,
    pub valid: Window,
    pub uri: String,
}

impl TimestampAuthority {
    fn anchor(&self) -> Result<&Certificate> {
        self.certs
            .last()
            .ok_or_else(|| "timestamp authority has no certificates".to_string())
    }
}

/// A verified timestamp: when the authority saw the signature, and the
/// authority's anchor subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedTimestamp {
    pub time: i64,
    pub authority: String,
}

/// The parts of a timestamp response that do not depend on which authority
/// signed it.
struct Token<'a> {
    gen_time: i64,
    signer: SignerId<'a>,
    signed_attrs: Vec<u8>,
    digest_alg: ObjectIdentifier,
    sig_alg: ObjectIdentifier,
    signature: &'a [u8],
    embedded: Vec<Certificate>,
}

enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyId(&'a [u8]),
}

/// Verify one DER TimeStampResp over `signature` (the signature bytes the
/// timestamp covers) against `authorities`. The first authority whose chain
/// holds wins.
pub fn verify_timestamp(
    resp: &[u8],
    signature: &[u8],
    authorities: &[TimestampAuthority],
) -> Result<VerifiedTimestamp> {
    let token = parse(resp, signature)?;
    let mut first_error = None;

    for authority in authorities {
        match verify_with(&token, authority) {
            Ok(()) => {
                return Ok(VerifiedTimestamp {
                    time: token.gen_time,
                    authority: subject_of(authority.anchor()?),
                })
            }
            Err(e) => first_error = first_error.or(Some(e)),
        }
    }
    Err(first_error.unwrap_or_else(|| "no trusted timestamp authority".to_string()))
}

fn parse<'a>(resp: &'a [u8], signature: &[u8]) -> Result<Token<'a>> {
    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo }
    let top = tlv::decode_one(resp, tlv::SEQUENCE).map_err(|e| format!("timestamp: {e}"))?;
    let parts = tlv::children(top.content)?;

    if parts.len() < 2 {
        return Err("timestamp response carries no token".to_string());
    }

    let status = tlv::children(parts[0].content)?;
    let code = status.first().ok_or("timestamp: empty status")?;

    tlv::expect(code, tlv::INTEGER)?;
    if code.content != [0] && code.content != [1] {
        return Err("timestamp response status is not granted".to_string());
    }

    // ContentInfo ::= SEQUENCE { contentType, [0] EXPLICIT SignedData }
    let content_info = tlv::children(parts[1].content)?;

    if content_info.len() != 2 || tlv::oid(&content_info[0])? != OID_SIGNED_DATA {
        return Err("timestamp token is not CMS SignedData".to_string());
    }

    let signed_data = tlv::decode_one(content_info[1].content, tlv::SEQUENCE)?;
    let fields = tlv::children(signed_data.content)?;

    if fields.len() < 4 {
        return Err("timestamp: truncated SignedData".to_string());
    }

    // encapContentInfo ::= SEQUENCE { eContentType, [0] EXPLICIT OCTET STRING }
    let encap = tlv::children(fields[2].content)?;

    if encap.len() != 2 || tlv::oid(&encap[0])? != OID_TST_INFO {
        return Err("timestamp token does not hold a TSTInfo".to_string());
    }

    let e_content = tlv::decode_one(encap[1].content, tlv::OCTET_STRING)?.content;
    let mut embedded = Vec::new();
    let mut signer_infos = None;

    for f in &fields[3..] {
        match f.tag {
            0xa0 => {
                for c in tlv::children(f.content)? {
                    // CertificateChoices: only plain certificates are used.
                    if c.tag == tlv::SEQUENCE {
                        embedded.push(
                            Certificate::from_der(c.raw)
                                .map_err(|e| format!("timestamp certificate: {e}"))?,
                        );
                    }
                }
            }
            0xa1 => {}
            tlv::SET => signer_infos = Some(*f),
            _ => return Err("timestamp: unexpected SignedData field".to_string()),
        }
    }

    let infos = tlv::children(signer_infos.ok_or("timestamp has no signer")?.content)?;

    if infos.len() != 1 {
        return Err("timestamp must have exactly one signer".to_string());
    }

    let (signer, signed_attrs, digest_alg, sig_alg, sig) = parse_signer_info(&infos[0])?;

    check_signed_attrs(signed_attrs, digest_alg, e_content)?;

    let gen_time = check_tst_info(e_content, signature)?;
    let mut signed = signed_attrs.raw.to_vec();

    // The signature covers the attributes as an explicit SET OF (RFC 5652 §5.4).
    signed[0] = tlv::SET;
    Ok(Token {
        gen_time,
        signer,
        signed_attrs: signed,
        digest_alg,
        sig_alg,
        signature: sig,
        embedded,
    })
}

type SignerParts<'a> = (
    SignerId<'a>,
    Tlv<'a>,
    ObjectIdentifier,
    ObjectIdentifier,
    &'a [u8],
);

fn parse_signer_info<'a>(info: &Tlv<'a>) -> Result<SignerParts<'a>> {
    let f = tlv::children(info.content)?;

    if f.len() < 5 {
        return Err("timestamp: truncated SignerInfo".to_string());
    }

    let signer = match f[1].tag {
        tlv::SEQUENCE => {
            let ias = tlv::children(f[1].content)?;

            if ias.len() != 2 {
                return Err("timestamp: bad issuerAndSerialNumber".to_string());
            }
            tlv::expect(&ias[1], tlv::INTEGER)?;
            SignerId::IssuerSerial {
                issuer: ias[0].raw,
                serial: ias[1].content,
            }
        }
        0x80 => SignerId::KeyId(f[1].content),
        _ => return Err("timestamp: unsupported signer identifier".to_string()),
    };
    let digest_alg = tlv::algorithm_oid(&f[2])?;

    if f[3].tag != 0xa0 {
        return Err("timestamp signer has no signed attributes".to_string());
    }

    let sig_alg = tlv::algorithm_oid(&f[4])?;
    let sig = f.get(5).ok_or("timestamp: SignerInfo has no signature")?;

    tlv::expect(sig, tlv::OCTET_STRING)?;
    Ok((signer, f[3], digest_alg, sig_alg, sig.content))
}

/// The signed attributes must name TSTInfo as the content type and carry the
/// digest of the encapsulated TSTInfo, so the signature covers the time.
fn check_signed_attrs(attrs: Tlv, digest_alg: ObjectIdentifier, e_content: &[u8]) -> Result<()> {
    let mut content_type_ok = false;
    let mut digest_ok = false;

    for attr in tlv::children(attrs.content)? {
        let parts = tlv::children(attr.content)?;

        if parts.len() != 2 {
            return Err("timestamp: malformed signed attribute".to_string());
        }

        let kind = tlv::oid(&parts[0])?;
        let values = tlv::children(parts[1].content)?;

        if kind == OID_CONTENT_TYPE {
            content_type_ok = values.len() == 1 && tlv::oid(&values[0])? == OID_TST_INFO;
        } else if kind == OID_MESSAGE_DIGEST {
            let expected = digest_with(digest_alg, e_content)?;

            digest_ok = values.len() == 1
                && values[0].tag == tlv::OCTET_STRING
                && values[0].content == expected.as_slice();
        }
    }
    if !content_type_ok {
        return Err("timestamp signed attributes do not name TSTInfo".to_string());
    }
    if !digest_ok {
        return Err("timestamp message digest does not match its TSTInfo".to_string());
    }
    Ok(())
}

/// TSTInfo: the message imprint must be the hash of `signature`. Returns
/// genTime in Unix seconds.
fn check_tst_info(der: &[u8], signature: &[u8]) -> Result<i64> {
    let info = tlv::decode_one(der, tlv::SEQUENCE)?;
    let f = tlv::children(info.content)?;

    if f.len() < 5 {
        return Err("timestamp: truncated TSTInfo".to_string());
    }

    let imprint = tlv::children(f[2].content)?;

    if imprint.len() != 2 {
        return Err("timestamp: malformed message imprint".to_string());
    }

    let expected = digest_with(tlv::algorithm_oid(&imprint[0])?, signature)?;

    tlv::expect(&imprint[1], tlv::OCTET_STRING)?;
    if imprint[1].content != expected.as_slice() {
        return Err("timestamp does not cover this signature".to_string());
    }
    tlv::expect(&f[4], tlv::GENERALIZED_TIME)?;
    parse_generalized_time(f[4].content)
}

/// `YYYYMMDDHHMMSS[.fff]Z` to Unix seconds, fractions dropped.
pub(crate) fn parse_generalized_time(raw: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(raw).map_err(|_| "timestamp: genTime is not ASCII")?;
    let bad = || format!("timestamp: unsupported genTime \"{s}\"");
    let body = s.strip_suffix('Z').ok_or_else(bad)?;
    let whole = body.split('.').next().ok_or_else(bad)?;

    if whole.len() != 14 || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }

    let n = |a: usize, b: usize| whole[a..b].parse::<i64>().map_err(|_| bad());
    let (y, mo, d) = (n(0, 4)?, n(4, 6)?, n(6, 8)?);
    let (h, mi, se) = (n(8, 10)?, n(10, 12)?, n(12, 14)?);

    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo as u32, d as u32) * 86400 + h * 3600 + mi * 60 + se)
}

fn matches_signer(cert: &Certificate, id: &SignerId) -> bool {
    match id {
        SignerId::IssuerSerial { issuer, serial } => {
            let trim = |b: &[u8]| -> Vec<u8> {
                let start = b.iter().position(|x| *x != 0).unwrap_or(b.len());

                b[start..].to_vec()
            };

            cert.tbs_certificate.issuer.to_der().ok().as_deref() == Some(*issuer)
                && trim(cert.tbs_certificate.serial_number.as_bytes()) == trim(serial)
        }
        SignerId::KeyId(key_id) => extension(cert, OID_SUBJECT_KEY_ID)
            .and_then(|e| tlv::decode_one(e.extn_value.as_bytes(), tlv::OCTET_STRING).ok())
            .is_some_and(|ski| ski.content == *key_id),
    }
}

/// The signer certificate (embedded in the token or listed by the authority)
/// must chain to the authority's anchor through the authority's own
/// certificates, be valid at genTime, and be issued for timestamping.
fn verify_with(token: &Token, authority: &TimestampAuthority) -> Result<()> {
    let anchor = authority.anchor()?;
    let anchor_der = anchor.to_der().map_err(|e| e.to_string())?;
    let signer = token
        .embedded
        .iter()
        .chain(authority.certs.iter())
        .find(|c| matches_signer(c, &token.signer))
        .ok_or("timestamp signer certificate not found")?;
    let mut path = vec![signer.clone()];

    while path.last().and_then(|c| c.to_der().ok()) != Some(anchor_der.clone()) {
        if path.len() > authority.certs.len() {
            return Err(format!(
                "timestamp signer does not chain to the authority \"{}\"",
                subject_of(anchor)
            ));
        }

        let cur = path.last().ok_or("empty path")?;
        let issuer = authority
            .certs
            .iter()
            .find(|ca| verify_signed_by(cur, ca).is_ok())
            .ok_or_else(|| {
                format!(
                    "timestamp signer does not chain to the authority \"{}\"",
                    subject_of(anchor)
                )
            })?;

        path.push(issuer.clone());
    }
    (1..path.len()).try_for_each(|i| check_issuer(&path[i], i - 1))?;
    check_valid_at(&path, token.gen_time).map_err(|e| format!("timestamp: {e}"))?;
    check_timestamping_leaf(signer)?;
    if !authority.valid.contains(token.gen_time) {
        return Err(format!(
            "timestamp authority \"{}\" was outside its validity window at {}",
            subject_of(anchor),
            token.gen_time
        ));
    }
    verify_cms_signature(
        signer,
        token.sig_alg,
        token.digest_alg,
        &token.signed_attrs,
        token.signature,
    )
    .map_err(|e| format!("timestamp: {e}"))
}

fn check_timestamping_leaf(cert: &Certificate) -> Result<()> {
    let eku = extension(cert, OID_EXT_KEY_USAGE)
        .ok_or("timestamp signer certificate has no extended key usage")?;
    let eku = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
        .map_err(|e| format!("extended key usage: {e}"))?;

    if !eku.0.contains(&OID_EKU_TIME_STAMPING) {
        return Err("timestamp signer certificate is not issued for timestamping".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_drops_fractions() {
        assert_eq!(parse_generalized_time(b"19700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_generalized_time(b"20250612120220.123Z").unwrap(),
            parse_generalized_time(b"20250612120220Z").unwrap()
        );
        assert!(parse_generalized_time(b"20250612120220+0100").is_err());
        assert!(parse_generalized_time(b"2025061212022Z").is_err());
    }
}
