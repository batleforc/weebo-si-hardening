//! The three parsers of untrusted input (RFC 0019, D1 and D-15). None of them can fail: every
//! malformed input is a value the caller turns into a verdict, never an error.

use serde_json::Value;

/// How much of `che.eclipse.org/devfile` is ever read.
pub const SCHEMA_SCAN_BYTES: usize = 4096;

/// The longest user-derived text echoed into a warning or the log line.
pub const MAX_EXCERPT_CHARS: usize = 32;

/// The longest contract written as a string: `u32::MAX` has 10 digits.
const MAX_CONTRACT_DIGITS: usize = 10;

/// The `weebo.io/platform-contract` attribute, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Contract {
    /// No attribute.
    Absent,
    /// Present but not a non-negative integer that fits a `u32`.
    Invalid,
    /// A contract number.
    Number(u32),
}

/// Read the contract attribute: a JSON integer, or a string of at most 10 ASCII digits (YAML
/// authors quote numbers). Anything else — 0 (numbers start at 1), float, sign, overflow,
/// object — is [`Contract::Invalid`], which counts as 1 like an absent one.
pub fn parse_contract(value: Option<&Value>) -> Contract {
    let number = match value {
        None => return Contract::Absent,
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s))
            if !s.is_empty()
                && s.len() <= MAX_CONTRACT_DIGITS
                && s.bytes().all(|b| b.is_ascii_digit()) =>
        {
            s.parse::<u64>().ok()
        }
        Some(_) => None,
    };
    number
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n != 0)
        .map_or(Contract::Invalid, Contract::Number)
}

/// A `MAJOR.MINOR.PATCH` version, compared numerically.
pub type SchemaVersion = (u32, u32, u32);

/// Parse `MAJOR.MINOR.PATCH`, digits only.
pub fn parse_schema_version(text: &str) -> Option<SchemaVersion> {
    let mut parts = text.split('.').map(|part| {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            None
        } else {
            part.parse::<u32>().ok()
        }
    });
    let version = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

/// Find the top-level `schemaVersion:` line in the first [`SCHEMA_SCAN_BYTES`] of the Che
/// dashboard's annotation. A line scan, not a YAML parser (D1): the first such line decides, and
/// an unreadable value is `None`, as an absent one.
pub fn scan_schema_version(annotation: &str) -> Option<SchemaVersion> {
    let head = annotation
        .get(..annotation.floor_char_boundary(SCHEMA_SCAN_BYTES))
        .unwrap_or_default();
    let value = head
        .lines()
        .find_map(|line| line.strip_prefix("schemaVersion:"))?;
    let token = value.split_whitespace().next()?;
    let token = token
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .or_else(|| token.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
        .unwrap_or(token);
    parse_schema_version(token)
}

/// What a `parent.uri` says about pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriPin {
    /// A commit, a tag or a version segment.
    Pinned,
    /// A branch, named through [`excerpt`].
    Branch(String),
    /// Nothing recognised: treated as unpinned (a false warning is one line, a false "pinned" is
    /// the trap of Motivation 3).
    Unpinned,
}

/// A URI with its scheme and host lowercased, its userinfo, default port, query and fragment
/// removed, unreserved escapes decoded, and `.`, `..` and repeated `/` resolved (T3). A string without `://` is kept whole, minus query
/// and fragment.
pub fn normalise_uri(uri: &str) -> String {
    let without_query = uri.split(['?', '#']).next().unwrap_or_default();
    let Some((scheme, rest)) = without_query.split_once("://") else {
        return without_query.to_string();
    };
    let scheme = scheme.to_lowercase();
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .to_lowercase();
    let default_port = match scheme.as_str() {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let host = match host.strip_suffix(default_port) {
        Some(bare) if !default_port.is_empty() => bare.to_string(),
        _ => host,
    };
    let decoded = decode_unreserved(path);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/').filter(|s| !s.is_empty()) {
        match segment {
            "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    let mut out = format!("{scheme}://{host}");
    for segment in &segments {
        out.push('/');
        out.push_str(segment);
    }
    let last = decoded.rsplit('/').next().unwrap_or_default();
    if !segments.is_empty() && (decoded.ends_with('/') || matches!(last, "." | "..")) {
        out.push('/');
    }
    out
}

/// Decodes the percent-encoded unreserved characters (RFC 3986 §2.3) that a server reads as the
/// literal character, so `%6Fld` and `old` normalise alike; any other escape stays as written.
fn decode_unreserved(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(i) = rest.find('%') {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let byte = tail
            .get(1..3)
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        match byte {
            Some(b) => {
                out.push(char::from(b));
                rest = tail.get(3..).unwrap_or_default();
            }
            None => {
                out.push('%');
                rest = tail.get(1..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    out
}

/// The path segments of a normalised URI.
fn path_segments(normalised: &str) -> impl Iterator<Item = &str> {
    let path = normalised
        .split_once("://")
        .map_or(normalised, |(_, rest)| {
            rest.find('/')
                .map_or("", |i| rest.get(i..).unwrap_or_default())
        });
    path.split('/').filter(|s| !s.is_empty())
}

fn is_commit(segment: &str) -> bool {
    segment.len() == 40 && segment.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `v1.4.0`, `2.1.0`, `1.4.0-rc.1`: an optional `v`, three numbers, an optional `-`/`+` suffix.
fn is_semver(segment: &str) -> bool {
    let bare = segment.strip_prefix('v').unwrap_or(segment);
    let core = bare.split(['-', '+']).next().unwrap_or_default();
    parse_schema_version(core).is_some()
}

/// What the segment at the head of `segments` says, if it is a marker: `refs/heads/<b>`,
/// `raw/branch/<b>`, `main` or `master` are a branch; `refs/tags/…`, `raw/tag/…`,
/// `raw/commit/…`, a 40-hex commit or a version segment are pinned.
fn marker(segments: &[&str]) -> Option<UriPin> {
    match segments {
        ["refs", "heads", branch, ..] | ["raw", "branch", branch, ..] => {
            Some(UriPin::Branch(excerpt(branch)))
        }
        ["refs", "tags", _, ..] | ["raw", "tag" | "commit", _, ..] => Some(UriPin::Pinned),
        [s, ..] if is_commit(s) || is_semver(s) => Some(UriPin::Pinned),
        [s @ ("main" | "master"), ..] => Some(UriPin::Branch(excerpt(s))),
        _ => None,
    }
}

/// Classify a `parent.uri` from its reference string alone (never fetched). Where the layout
/// says which segment is the ref — GitHub raw `/<owner>/<repo>/<ref>/…`, GitLab `/-/raw/<ref>/…`
/// — only that segment decides, so a version-shaped directory under a branch never pins.
/// Elsewhere segments are read left to right and the first [`marker`] decides.
pub fn classify_parent_uri(uri: &str) -> UriPin {
    let normalised = normalise_uri(uri);
    let segments: Vec<&str> = path_segments(&normalised).collect();
    let at_ref = |from: usize| {
        segments
            .get(from..)
            .and_then(marker)
            .unwrap_or(UriPin::Unpinned)
    };
    if normalised.starts_with("https://raw.githubusercontent.com/")
        || normalised.starts_with("http://raw.githubusercontent.com/")
    {
        return at_ref(2);
    }
    for (index, window) in segments.windows(2).enumerate() {
        if window == ["-", "raw"] {
            return at_ref(index.saturating_add(2));
        }
    }
    let mut rest = segments.as_slice();
    while let [_, tail @ ..] = rest {
        if let Some(pin) = marker(rest) {
            return pin;
        }
        rest = tail;
    }
    UriPin::Unpinned
}

/// User text made safe for a warning or a log field: `[A-Za-z0-9.+-]` only, at most
/// [`MAX_EXCERPT_CHARS`] characters (I1, I2).
pub fn excerpt(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        .take(MAX_EXCERPT_CHARS)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "a failed assertion is the test failing")]
mod tests {
    use std::time::{Duration, Instant};

    use serde_json::json;

    use super::*;

    #[test]
    fn contract_table() {
        let rows: &[(Option<Value>, Contract)] = &[
            (None, Contract::Absent),
            (Some(json!(3)), Contract::Number(3)),
            (Some(json!(0)), Contract::Invalid),
            (Some(json!("0")), Contract::Invalid),
            (Some(json!("2")), Contract::Number(2)),
            (Some(json!("0042")), Contract::Number(42)),
            (Some(json!(u32::MAX)), Contract::Number(u32::MAX)),
            (Some(json!("4294967295")), Contract::Number(u32::MAX)),
            (Some(json!(u64::from(u32::MAX) + 1)), Contract::Invalid),
            (Some(json!("4294967296")), Contract::Invalid),
            (Some(json!("12345678901")), Contract::Invalid),
            (Some(json!(-1)), Contract::Invalid),
            (Some(json!("-1")), Contract::Invalid),
            (Some(json!("+1")), Contract::Invalid),
            (Some(json!(" 1")), Contract::Invalid),
            (Some(json!(1.5)), Contract::Invalid),
            (Some(json!(2.0)), Contract::Invalid),
            (Some(json!("three")), Contract::Invalid),
            (Some(json!("")), Contract::Invalid),
            (Some(json!("٣")), Contract::Invalid),
            (Some(json!(null)), Contract::Invalid),
            (Some(json!(true)), Contract::Invalid),
            (Some(json!([1])), Contract::Invalid),
            (Some(json!({"n": 1})), Contract::Invalid),
        ];
        for (value, expected) in rows {
            assert_eq!(parse_contract(value.as_ref()), *expected, "{value:?}");
        }
    }

    #[test]
    fn schema_version_table() {
        let rows: &[(&str, Option<SchemaVersion>)] = &[
            ("", None),
            ("schemaVersion: 2.3.0", Some((2, 3, 0))),
            ("schemaVersion: 2.3.0\n", Some((2, 3, 0))),
            ("schemaVersion: 2.1.0\r\nmetadata:\r\n", Some((2, 1, 0))),
            (
                "metadata:\n  name: x\nschemaVersion: \"2.2.1\"",
                Some((2, 2, 1)),
            ),
            ("schemaVersion: '2.2.0' # pinned", Some((2, 2, 0))),
            ("schemaVersion:2.2.0", Some((2, 2, 0))),
            ("  schemaVersion: 2.2.0", None),
            ("metadata:\n  schemaVersion: 2.2.0", None),
            ("schemaVersion: 2.2", None),
            ("schemaVersion: 2.2.0-alpha", None),
            ("schemaVersion: v2.2.0", None),
            ("schemaVersion: 99999999999.0.0", None),
            ("schemaVersion:", None),
            ("schemaVersion: x\nschemaVersion: 2.2.0", None),
            ("schemaversion: 2.2.0", None),
        ];
        for (body, expected) in rows {
            assert_eq!(scan_schema_version(body), *expected, "{body:?}");
        }
    }

    #[test]
    fn only_the_first_4kib_is_scanned() {
        let padding = "#".repeat(SCHEMA_SCAN_BYTES);
        assert_eq!(
            scan_schema_version(&format!("{padding}\nschemaVersion: 2.2.0")),
            None
        );
        // A multi-byte character across the boundary is not a panic.
        let body = format!(
            "{}é\nschemaVersion: 2.2.0",
            "a".repeat(SCHEMA_SCAN_BYTES - 1)
        );
        assert_eq!(scan_schema_version(&body), None);
    }

    #[test]
    fn a_4mib_annotation_is_scanned_in_bounded_time() {
        let no_newline = "x".repeat(4 << 20);
        let lines = "a: b\r\n".repeat((4 << 20) / 6);
        let start = Instant::now();
        assert_eq!(scan_schema_version(&no_newline), None);
        assert_eq!(scan_schema_version(&lines), None);
        // Generous: the 4 KiB cut bounds the work, the limit only catches a full scan.
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn parent_uri_table() {
        let branch = |b: &str| UriPin::Branch(b.to_string());
        let commit = "0123456789abcdef0123456789ABCDEF01234567";
        let rows: Vec<(String, UriPin)> = vec![
            // GitHub raw.
            ("https://raw.githubusercontent.com/batleforc/WeeboDevImage/refs/heads/main/che-min-mise/devfile.yaml".into(), branch("main")),
            ("https://raw.githubusercontent.com/batleforc/WeeboDevImage/refs/heads/feat-x/devfile.yaml".into(), branch("feat-x")),
            ("https://raw.githubusercontent.com/o/r/refs/tags/v1.4.0/devfile.yaml".into(), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o/r/refs/tags/stable/devfile.yaml".into(), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o/r/main/devfile.yaml".into(), branch("main")),
            ("https://raw.githubusercontent.com/o/r/master/devfile.yaml".into(), branch("master")),
            ("https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.4.0/che-min-mise/devfile.yaml".into(), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o/r/2.1.0/devfile.yaml".into(), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o/r/v1.4.0-rc.1/devfile.yaml".into(), UriPin::Pinned),
            (format!("https://raw.githubusercontent.com/o/r/{commit}/devfile.yaml"), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o/r/develop/devfile.yaml".into(), UriPin::Unpinned),
            // The first marker decides: a version directory under a branch is still the branch.
            ("https://raw.githubusercontent.com/o/r/main/v1.4.0/devfile.yaml".into(), branch("main")),
            ("https://raw.githubusercontent.com/o/r/refs/heads/v1.4.0/devfile.yaml".into(), branch("v1.4.0")),
            // On GitHub raw only the ref segment decides.
            ("https://raw.githubusercontent.com/o/r/develop/stacks/2.1.0/devfile.yaml".into(), UriPin::Unpinned),
            ("https://raw.githubusercontent.com/o/2.0.0/main/devfile.yaml".into(), branch("main")),
            (format!("https://raw.githubusercontent.com:443/o/r/{commit}/d.yaml"), UriPin::Pinned),
            ("https://raw.githubusercontent.com/o".into(), UriPin::Unpinned),
            // GitLab.
            ("https://gitlab.com/g/p/-/raw/v1.0.0/devfile.yaml".into(), UriPin::Pinned),
            ("https://gitlab.com/g/p/-/raw/develop/2.1.0/devfile.yaml".into(), UriPin::Unpinned),
            ("https://gitlab.com/g/p/-/raw/main/devfile.yaml".into(), branch("main")),
            // Forgejo / Gitea.
            ("https://git.example.org/o/r/raw/branch/main/devfile.yaml".into(), branch("main")),
            ("https://git.example.org/o/r/raw/tag/v1.0.0/devfile.yaml".into(), UriPin::Pinned),
            (format!("https://git.example.org/o/r/raw/commit/{commit}/devfile.yaml"), UriPin::Pinned),
            // Registry-shaped and others.
            ("https://registry.devfile.io/devfiles/go".into(), UriPin::Unpinned),
            ("https://registry.devfile.io/devfiles/go/2.1.0".into(), UriPin::Pinned),
            ("devfile.yaml".into(), UriPin::Unpinned),
            ("".into(), UriPin::Unpinned),
            // The host is never a marker, a query never pins.
            ("https://v1.2.3/o/r/devfile.yaml".into(), UriPin::Unpinned),
            ("https://host/o/r/devfile.yaml?ref=v1.4.0".into(), UriPin::Unpinned),
            ("https://host/o/r/devfile.yaml#v1.4.0".into(), UriPin::Unpinned),
            // Userinfo is dropped before the path is read.
            ("https://main:token@host/o/r/refs/heads/dev/devfile.yaml".into(), branch("dev")),
            // Unicode and control characters in a branch never reach the excerpt.
            ("https://host/o/r/refs/heads/br\u{1b}[31mänch/x".into(), branch("br31mnch")),
            (format!("https://host/o/r/refs/heads/{}/x", "b".repeat(8192)), branch(&"b".repeat(32))),
            (format!("https://host/{}", "a/".repeat(4096)), UriPin::Unpinned),
        ];
        for (uri, expected) in rows {
            assert_eq!(classify_parent_uri(&uri), expected, "{uri}");
        }
    }

    #[test]
    fn normalisation_table() {
        let rows = [
            (
                "HTTPS://User:Tok@Raw.GitHub.com/A/B?x=1#f",
                "https://raw.github.com/A/B",
            ),
            ("https://raw.github.com", "https://raw.github.com"),
            ("https://a@b@Host/p", "https://host/p"),
            ("relative/Path?q", "relative/Path"),
            ("https://Host:443//a///b/", "https://host/a/b/"),
            ("http://host:80/a", "http://host/a"),
            ("https://host:8443/a", "https://host:8443/a"),
            (
                "https://host/org/%6Fld-stack/%2F",
                "https://host/org/old-stack/%2F",
            ),
            ("https://host/org/x/../old/./a", "https://host/org/old/a"),
            ("https://host/a/b/..", "https://host/a/"),
            ("https://host/../..", "https://host"),
            ("https://host/a%zz%4", "https://host/a%zz%4"),
        ];
        for (uri, expected) in rows {
            assert_eq!(normalise_uri(uri), expected, "{uri}");
        }
    }

    #[test]
    fn excerpt_allow_lists_and_bounds() {
        assert_eq!(
            excerpt("weebo-gen 1.2.0+b\r\n\u{1b}[0m"),
            "weebo-gen1.2.0+b0m"
        );
        assert_eq!(excerpt(&"x".repeat(10_000)).len(), MAX_EXCERPT_CHARS);
    }
}
