use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);

    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn sha256_hex(buf: &[u8]) -> String {
    hex(&Sha256::digest(buf))
}

/// First 16 hex chars of a digest/keyid, like JS `keyid.slice(0, 16)`.
/// Safe on arbitrary (possibly short or non-ASCII) input.
pub fn short16(s: &str) -> String {
    s.chars().take(16).collect()
}

pub fn home_dir() -> PathBuf {
    // Match Node os.homedir(): USERPROFILE on Windows, HOME elsewhere.
    let vars: [&str; 2] = if cfg!(windows) {
        ["USERPROFILE", "HOME"]
    } else {
        ["HOME", "USERPROFILE"]
    };

    for v in vars {
        if let Some(p) = std::env::var_os(v) {
            if !p.is_empty() {
                return PathBuf::from(p);
            }
        }
    }
    PathBuf::from(".")
}

pub fn promptsign_home() -> PathBuf {
    match std::env::var_os("PROMPTSIGN_HOME") {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => home_dir().join(".promptsign"),
    }
}

/// Write a file owned by one user and restrict it to `0600` on Unix.
///
/// Files under `promptsign_home` include the private key, pin store, and
/// global policy. The latter two are not secrets, but they record the
/// identities a user trusts and the policies they enforce, so they should
/// not be writable or readable by other users on a shared machine.
///
/// This does not protect against an attacker who can already write the home
/// directory. Such an attacker can replace the policy, cached trust roots,
/// or binary on `PATH` regardless. This follows the `known_hosts` model and
/// is deliberate.
///
/// Permissions are applied after writing rather than at creation time. This
/// avoids platform-specific open flags for files whose contents are already
/// available to anyone who can run the CLI, at the cost of briefly retaining
/// an existing file's previous mode.
///
/// Permission-setting failures are ignored deliberately: a filesystem that
/// cannot represent the mode should not turn a successful write into an
/// error. Windows has no equivalent, and its profile directory is already
/// per-user.
pub fn write_private(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    fs::write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Same semantics as the Node implementation's globMatch: '*' matches any
/// run of characters (including none); everything else is literal.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        return pattern == value;
    }

    let first = parts[0];
    let last = parts[parts.len() - 1];

    if !value.starts_with(first) {
        return false;
    }

    let mut pos = first.len();

    for part in &parts[1..parts.len() - 1] {
        if part.is_empty() {
            continue;
        }
        match value[pos..].find(part) {
            Some(i) => pos += i + part.len(),
            None => return false,
        }
    }
    value.len() >= pos + last.len() && value[pos..].ends_with(last)
}

/// ISO-8601 UTC with milliseconds, identical shape to JS Date.toISOString().
pub fn iso8601_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs() as i64;
    let ms = dur.subsec_millis();
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);

    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Parse an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS[.mmm]Z`, the shape
/// `iso8601_now` and JS `Date.toISOString()` produce) to epoch seconds. Lenient
/// on the fractional-seconds and trailing `Z`; strict on the date/time layout.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;

    if dp.next().is_some() {
        return None;
    }

    // Drop the trailing 'Z' and any fractional part; ignore other offsets (feed
    // timestamps are always UTC 'Z' by spec).
    let time = rest.trim_end_matches('Z');
    let time = time.split('.').next()?;
    let mut tp = time.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let se: i64 = tp.next().unwrap_or("0").parse().ok()?;

    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }

    let days = days_from_civil(y, mo as u32, d as u32);

    Some(days * 86400 + h * 3600 + mi * 60 + se)
}

/// Parse a duration like "72h", "7d", "30m", "3600s" to seconds. Bare integers
/// are seconds. Used for `max_feed_staleness` (spec/06).
pub fn parse_duration(s: &str) -> Option<i64> {
    let s = s.trim();

    if s.is_empty() {
        return None;
    }

    let (num, unit): (&str, i64) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86400),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    let n: i64 = num.trim().parse().ok()?;

    if n < 0 {
        return None;
    }
    Some(n * unit)
}

/// Inverse of civil_from_days: (y, m, d) -> days since 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146097 + doe - 719468
}

// Howard Hinnant's civil_from_days: days since 1970-01-01 -> (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;

    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("anthropic/*", "anthropic/pdf"));
        assert!(!glob_match("anthropic/*", "anthroplc/pdf"));
        assert!(glob_match("github:trailofbits*", "github:trailofbits"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*a", "a"));
        assert!(!glob_match("exact", "exact-not"));
        assert!(glob_match("exact", "exact"));
    }

    #[test]
    fn civil_epoch_and_leap() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19723), (2024, 1, 1));
        // 2024-02-29 = 19782 days after epoch
        assert_eq!(civil_from_days(19782), (2024, 2, 29));
    }

    #[test]
    fn days_from_civil_is_inverse() {
        for z in [0i64, 19723, 19782, -1, 20000, 12345] {
            let (y, m, d) = civil_from_days(z);

            assert_eq!(days_from_civil(y, m, d), z, "roundtrip for {z}");
        }
    }

    #[test]
    fn parse_iso8601_matches_now_roundtrip() {
        assert_eq!(parse_iso8601("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601("2024-02-29T12:00:00Z"),
            Some(19782 * 86400 + 43200)
        );
        // fractional seconds and a missing seconds field are tolerated
        assert_eq!(
            parse_iso8601("2024-01-01T00:00:00.500Z"),
            Some(19723 * 86400)
        );
        assert!(parse_iso8601("not-a-date").is_none());
        assert!(parse_iso8601("2024-13-01T00:00:00Z").is_none());
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("72h"), Some(72 * 3600));
        assert_eq!(parse_duration("7d"), Some(7 * 86400));
        assert_eq!(parse_duration("30m"), Some(1800));
        assert_eq!(parse_duration("3600s"), Some(3600));
        assert_eq!(parse_duration("90"), Some(90));
        assert!(parse_duration("").is_none());
        assert!(parse_duration("-5h").is_none());
        assert!(parse_duration("abc").is_none());
    }
}
