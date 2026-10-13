// A small DER reader for structures x509-cert does not model: the RFC 3161
// timestamp response and the CMS SignedData inside it. Signed attributes are
// verified over their exact encoded bytes, so this keeps every value's raw
// slice instead of re-encoding anything. Same rules as the Node reader
// (der.mjs): low tag numbers and definite lengths only.

use crate::Result;
use der::oid::ObjectIdentifier;

pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;

#[derive(Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    /// The value, without tag and length.
    pub content: &'a [u8],
    /// Tag, length and value, as encoded.
    pub raw: &'a [u8],
}

/// One TLV at the start of `buf`, and the bytes after it.
pub(crate) fn read(buf: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if buf.len() < 2 {
        return Err("DER: truncated".to_string());
    }

    let tag = buf[0];

    if tag & 0x1f == 0x1f {
        return Err("DER: unsupported tag".to_string());
    }

    let mut len = buf[1] as usize;
    let mut start = 2;

    if len & 0x80 != 0 {
        let n = len & 0x7f;

        if n == 0 || n > 4 || start + n > buf.len() {
            return Err("DER: bad length".to_string());
        }
        len = buf[start..start + n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | *b as usize);
        start += n;
    }

    let end = start
        .checked_add(len)
        .filter(|e| *e <= buf.len())
        .ok_or("DER: truncated")?;

    Ok((
        Tlv {
            tag,
            content: &buf[start..end],
            raw: &buf[..end],
        },
        &buf[end..],
    ))
}

/// Exactly one TLV filling `buf`, of the expected tag.
pub(crate) fn decode_one(buf: &[u8], tag: u8) -> Result<Tlv<'_>> {
    let (tlv, rest) = read(buf)?;

    if !rest.is_empty() {
        return Err("DER: trailing data".to_string());
    }
    expect(&tlv, tag)?;
    Ok(tlv)
}

/// The TLVs inside a constructed value.
pub(crate) fn children(content: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;

    while !rest.is_empty() {
        let (tlv, next) = read(rest)?;

        out.push(tlv);
        rest = next;
    }
    Ok(out)
}

pub(crate) fn expect(tlv: &Tlv, tag: u8) -> Result<()> {
    if tlv.tag != tag {
        return Err(format!(
            "DER: expected tag 0x{tag:02x}, found 0x{:02x}",
            tlv.tag
        ));
    }
    Ok(())
}

/// An OBJECT IDENTIFIER's content as an OID.
pub(crate) fn oid(tlv: &Tlv) -> Result<ObjectIdentifier> {
    expect(tlv, OID)?;
    ObjectIdentifier::from_bytes(tlv.content).map_err(|e| format!("DER: OID: {e}"))
}

/// The OID of an AlgorithmIdentifier SEQUENCE.
pub(crate) fn algorithm_oid(tlv: &Tlv) -> Result<ObjectIdentifier> {
    expect(tlv, SEQUENCE)?;
    oid(children(tlv.content)?
        .first()
        .ok_or("DER: empty AlgorithmIdentifier")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nested_values_and_oids() {
        // SEQUENCE { OID 1.2.840.113549.1.7.2, INTEGER 5 }
        let der = [
            0x30, 0x0e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02, 0x02,
            0x01, 0x05,
        ];
        let seq = decode_one(&der, SEQUENCE).unwrap();
        let parts = children(seq.content).unwrap();

        assert_eq!(oid(&parts[0]).unwrap().to_string(), "1.2.840.113549.1.7.2");
        assert_eq!(parts[1].content, &[0x05]);
        assert_eq!(
            algorithm_oid(&seq).unwrap().to_string(),
            "1.2.840.113549.1.7.2"
        );
    }

    #[test]
    fn rejects_truncation_and_trailing_bytes() {
        assert!(read(&[0x30, 0x05, 0x01]).is_err());
        assert!(decode_one(&[0x02, 0x01, 0x05, 0x00], INTEGER).is_err());
        assert!(read(&[0x30, 0x85, 0, 0, 0, 0, 0]).is_err());
    }
}
