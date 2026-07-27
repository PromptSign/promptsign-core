// Canonicalization of instruction files per spec/02-canonicalization.md.
// Only .md/.markdown files are canonicalized; everything else is hashed as raw bytes.

use crate::util::sha256_hex;
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug)]
pub struct CanonError {
    pub message: String,
    pub line: Option<usize>,
}

impl CanonError {
    fn new(message: impl Into<String>, line: Option<usize>) -> Self {
        CanonError {
            message: message.into(),
            line,
        }
    }
}

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(n) => write!(f, "{} (line {})", self.message, n),
            None => write!(f, "{}", self.message),
        }
    }
}

pub fn is_markdown(rel_path: &str) -> bool {
    let lower = rel_path.to_lowercase();

    lower.ends_with(".md") || lower.ends_with(".markdown")
}

// Always rejected, even inside code fences: Unicode Tags block (invisible
// instruction smuggling), bidi controls (Trojan Source), directional marks.
fn always_bad(c: char) -> bool {
    matches!(c as u32,
        0xE0000..=0xE007F | 0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C)
}

// Rejected outside code fences: zero-width space, word joiner, interior BOM.
fn zero_width(c: char) -> bool {
    matches!(c as u32, 0x200B | 0x2060 | 0xFEFF)
}

fn check_invisible(lines: &[String]) -> Result<(), CanonError> {
    let mut in_fence = false;

    for (i, line) in lines.iter().enumerate() {
        if let Some(c) = line.chars().find(|c| always_bad(*c)) {
            return Err(CanonError::new(
                format!("disallowed invisible/bidi character U+{:04X}", c as u32),
                Some(i + 1),
            ));
        }

        let trimmed = line.trim_start();

        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if let Some(c) = line.chars().find(|c| zero_width(*c)) {
            return Err(CanonError::new(
                format!(
                    "disallowed zero-width character U+{:04X} outside code fence",
                    c as u32
                ),
                Some(i + 1),
            ));
        }

        // ZWNJ/ZWJ are legitimate in Persian/Arabic text and emoji sequences;
        // rejected only when surrounded by ASCII, where their only purpose is smuggling.
        let chars: Vec<char> = line.chars().collect();

        for (j, &c) in chars.iter().enumerate() {
            if c == '\u{200C}' || c == '\u{200D}' {
                let ascii_prev = j == 0 || (chars[j - 1] as u32) <= 0x7f;
                let ascii_next = j + 1 >= chars.len() || (chars[j + 1] as u32) <= 0x7f;

                if ascii_prev && ascii_next {
                    return Err(CanonError::new(
                        format!("zero-width joiner U+{:X} in ASCII context", c as u32),
                        Some(i + 1),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Remove an `x-promptsign:` mapping from YAML frontmatter (embedded-signature
/// fallback carriage) so the signature is not part of the signed content.
pub fn strip_signature_block(text: &str) -> String {
    if !text.starts_with("---\n") {
        return text.to_string();
    }

    let end = match text[3..].find("\n---") {
        Some(i) => i + 3,
        None => return text.to_string(),
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut skipping = false;

    for line in text[4..end].split('\n') {
        if line.starts_with("x-promptsign:") {
            skipping = true;
            continue;
        }
        if skipping && (line.starts_with(' ') || line.starts_with('\t')) {
            continue;
        }
        skipping = false;
        kept.push(line);
    }
    format!("---\n{}{}", kept.join("\n"), &text[end..])
}

/// Canonical form: strict UTF-8, no BOM, LF endings, NFC, no trailing
/// whitespace, exactly one trailing newline, signature block excised.
pub fn canonicalize_markdown(buf: &[u8]) -> Result<String, CanonError> {
    let text = std::str::from_utf8(buf).map_err(|_| CanonError::new("invalid UTF-8", None))?;
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text: String = text.nfc().collect();
    let text = strip_signature_block(&text);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|l| l.trim_end_matches([' ', '\t']).to_string())
        .collect();

    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    check_invisible(&lines)?;
    Ok(lines.join("\n") + "\n")
}

/// Digest used in manifests: canonical form for Markdown, raw bytes otherwise.
/// Executables are ALWAYS raw bytes — never normalize code you will run.
pub fn digest_file(buf: &[u8], rel_path: &str, role: &str) -> Result<String, CanonError> {
    if role != "executable" && is_markdown(rel_path) {
        Ok(sha256_hex(canonicalize_markdown(buf)?.as_bytes()))
    } else {
        Ok(sha256_hex(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_bom_trailing_ws_normalize_to_same_digest() {
        let a = canonicalize_markdown(b"# Title\r\nbody  \r\n\r\n").unwrap();
        let b = canonicalize_markdown("\u{FEFF}# Title\nbody\n".as_bytes()).unwrap();

        assert_eq!(a, b);
        assert_eq!(a, "# Title\nbody\n");
    }

    #[test]
    fn nfc_normalizes() {
        // e + combining acute vs precomposed é
        let a = canonicalize_markdown("caf\u{0065}\u{0301}\n".as_bytes()).unwrap();
        let b = canonicalize_markdown("caf\u{00E9}\n".as_bytes()).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn rejects_tags_block_even_in_fence() {
        let bad = format!("```\nhi{}there\n```\n", '\u{E0041}');
        let err = canonicalize_markdown(bad.as_bytes()).unwrap_err();

        assert!(err.to_string().contains("U+E0041"), "{err}");
    }

    #[test]
    fn rejects_bidi_override() {
        let err = canonicalize_markdown("safe \u{202E}evil\n".as_bytes()).unwrap_err();

        assert!(err.to_string().contains("U+202E"));
    }

    #[test]
    fn zero_width_ok_in_fence_rejected_outside() {
        assert!(canonicalize_markdown("```\na\u{200B}b\n```\n".as_bytes()).is_ok());

        let err = canonicalize_markdown("a\u{200B}b\n".as_bytes()).unwrap_err();

        assert!(err.to_string().contains("outside code fence"));
    }

    #[test]
    fn joiner_allowed_in_persian_rejected_in_ascii() {
        assert!(canonicalize_markdown("می\u{200C}خواهم\n".as_bytes()).is_ok());

        let err = canonicalize_markdown("ig\u{200C}nore\n".as_bytes()).unwrap_err();

        assert!(err.to_string().contains("ASCII context"));
    }

    #[test]
    fn invalid_utf8_rejected() {
        let err = canonicalize_markdown(&[0xff, 0xfe, 0x00]).unwrap_err();

        assert_eq!(err.to_string(), "invalid UTF-8");
    }

    #[test]
    fn signature_block_stripped() {
        let with = "---\nname: x\nx-promptsign:\n  v: 1\n  sig: abc\ndescription: d\n---\nbody\n";
        let without = "---\nname: x\ndescription: d\n---\nbody\n";

        assert_eq!(
            canonicalize_markdown(with.as_bytes()).unwrap(),
            canonicalize_markdown(without.as_bytes()).unwrap()
        );
    }

    #[test]
    fn executables_hashed_raw() {
        // CRLF must NOT be normalized for executables
        let d1 = digest_file(b"print(1)\r\n", "scripts/x.py", "executable").unwrap();
        let d2 = digest_file(b"print(1)\n", "scripts/x.py", "executable").unwrap();

        assert_ne!(d1, d2);
    }
}
