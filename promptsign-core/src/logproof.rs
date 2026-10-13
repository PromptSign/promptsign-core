// Rekor v2 log evidence (spec/05 §3.2): an RFC 6962 inclusion proof of the
// entry against a checkpoint the log signed. Rekor v2 issues no signed entry
// timestamp; the checkpoint signature plus the proof is what shows the log
// holds the entry, and time comes from RFC 3161 timestamps (timestamp.rs).
//
// A checkpoint is a C2SP signed note: the body is the log origin, the tree
// size and the base64 root hash, one per line, then a blank line, then one
// "— <name> <base64(key hint || signature)>" line per signer. Witness
// cosignatures may follow; a verifier ignores signers it does not know.

use crate::keyless::{LogKey, RekorLog};
use crate::Result;
use base64::prelude::{Engine as _, BASE64_STANDARD};
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest, Sha256};

/// A checkpoint whose log signature verified.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    pub size: u64,
    pub root_hash: Vec<u8>,
}

/// Verify a signed-note checkpoint with `log`'s key. The origin line must be
/// the log's origin, and at least one signature line must come from the log;
/// a log signature that does not verify fails the checkpoint.
pub(crate) fn verify_checkpoint(note: &str, log: &RekorLog) -> Result<Checkpoint> {
    let origin = log
        .origin()
        .ok_or("transparency log has no baseUrl, so its checkpoint origin is unknown")?;
    let split = note.find("\n\n").ok_or("checkpoint: no signature block")?;
    let text = &note[..split + 1];
    let sigs = &note[split + 2..];
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();

    if lines.len() < 3 {
        return Err("checkpoint: needs origin, size and root hash lines".to_string());
    }
    if lines[0] != origin {
        return Err(format!(
            "checkpoint origin \"{}\" is not the log's origin \"{origin}\"",
            lines[0]
        ));
    }

    let size = parse_size(lines[1])?;
    let root_hash = BASE64_STANDARD
        .decode(lines[2])
        .ok()
        .filter(|h| h.len() == 32)
        .ok_or("checkpoint: root hash is not 32 bytes of base64")?;

    if sigs.is_empty() || !sigs.ends_with('\n') {
        return Err("checkpoint: malformed signature block".to_string());
    }

    let hint = log.key_hint();
    let mut verified = false;

    for line in sigs[..sigs.len() - 1].split('\n') {
        let rest = line
            .strip_prefix("\u{2014} ")
            .ok_or("checkpoint: malformed signature line")?;
        let (name, b64) = rest
            .split_once(' ')
            .ok_or("checkpoint: malformed signature line")?;
        let raw = BASE64_STANDARD
            .decode(b64)
            .map_err(|_| "checkpoint: signature is not base64")?;

        if raw.len() < 5 {
            return Err("checkpoint: signature too short".to_string());
        }
        if name != origin || raw[..4] != hint {
            continue;
        }
        verify_note_signature(&log.key, text.as_bytes(), &raw[4..])?;
        verified = true;
    }
    if !verified {
        return Err(format!(
            "checkpoint carries no signature from log \"{origin}\""
        ));
    }
    Ok(Checkpoint { size, root_hash })
}

fn parse_size(s: &str) -> Result<u64> {
    let ok =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));

    ok.then(|| s.parse::<u64>().ok())
        .flatten()
        .ok_or_else(|| format!("checkpoint: tree size \"{s}\" is not a number"))
}

/// Ed25519 signs the note text directly; ECDSA signs its SHA-256, DER encoded.
fn verify_note_signature(key: &LogKey, text: &[u8], sig: &[u8]) -> Result<()> {
    let bad = || "checkpoint signature by the log does not verify".to_string();

    match key {
        LogKey::Ed25519(vk) => {
            use ed25519_dalek::Verifier;

            let s = ed25519_dalek::Signature::from_slice(sig).map_err(|_| bad())?;

            vk.verify(text, &s).map_err(|_| bad())
        }
        LogKey::P256(vk) => {
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| bad())?;

            vk.verify(text, &s).map_err(|_| bad())
        }
    }
}

/// RFC 6962 leaf hash of a canonicalized entry body.
pub(crate) fn leaf_hash(body: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([0u8]);
    h.update(body);
    h.finalize().to_vec()
}

fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}

/// RFC 9162 §2.1.3.2: does `proof` take the leaf at `index` to `root` in a
/// tree of `size` leaves?
pub(crate) fn verify_inclusion(
    index: u64,
    size: u64,
    leaf: &[u8],
    proof: &[Vec<u8>],
    root: &[u8],
) -> Result<()> {
    if index >= size {
        return Err(format!(
            "inclusion proof: index {index} is outside a tree of size {size}"
        ));
    }

    let (mut f_n, mut s_n) = (index, size - 1);
    let mut r = leaf.to_vec();

    for p in proof {
        if p.len() != 32 {
            return Err("inclusion proof: hash is not 32 bytes".to_string());
        }
        if s_n == 0 {
            return Err("inclusion proof: too many hashes".to_string());
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            while f_n & 1 == 0 && f_n != 0 {
                f_n >>= 1;
                s_n >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n != 0 {
        return Err("inclusion proof: too few hashes".to_string());
    }
    if r != root {
        return Err("inclusion proof does not lead to the checkpoint's root hash".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root of the leaves `leaves[lo..hi]` (RFC 6962 MTH).
    fn mth(leaves: &[Vec<u8>]) -> Vec<u8> {
        match leaves.len() {
            1 => leaves[0].clone(),
            n => {
                let k = n.next_power_of_two() / 2;

                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    /// Audit path for leaf `m` (RFC 6962 PATH).
    fn path(m: usize, leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let n = leaves.len();

        if n == 1 {
            return Vec::new();
        }

        let k = n.next_power_of_two() / 2;

        if m < k {
            let mut p = path(m, &leaves[..k]);

            p.push(mth(&leaves[k..]));
            p
        } else {
            let mut p = path(m - k, &leaves[k..]);

            p.push(mth(&leaves[..k]));
            p
        }
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_and_size() {
        for size in 1..=17usize {
            let leaves: Vec<Vec<u8>> = (0..size).map(|i| leaf_hash(&[i as u8])).collect();
            let root = mth(&leaves);

            for m in 0..size {
                let proof = path(m, &leaves);

                verify_inclusion(m as u64, size as u64, &leaves[m], &proof, &root).unwrap();
                assert!(
                    verify_inclusion(m as u64, size as u64, &leaf_hash(b"x"), &proof, &root)
                        .is_err()
                );
                if !proof.is_empty() {
                    assert!(verify_inclusion(
                        m as u64,
                        size as u64,
                        &leaves[m],
                        &proof[1..],
                        &root
                    )
                    .is_err());
                }
            }
            assert!(verify_inclusion(size as u64, size as u64, &leaves[0], &[], &root).is_err());
        }
    }

    #[test]
    fn tree_size_is_strict_decimal() {
        assert_eq!(parse_size("0").unwrap(), 0);
        assert_eq!(parse_size("736").unwrap(), 736);
        assert!(parse_size("0736").is_err());
        assert!(parse_size("+736").is_err());
        assert!(parse_size("").is_err());
    }
}
