//! Path normalisation, because that is where forward-auth gates are bypassed.
//!
//! The gate and the application must agree on what path a request has. If they do not, the gate
//! answers about `/public/..%2factuator/env` and the application serves `/actuator/env`, and
//! every path rule in RFC 0009 is decoration. So the path is normalised before any rule sees it,
//! and the cases where normalisation itself is the attack — a second layer of encoding, an
//! encoded separator, a `..` that climbs out of the root — are refusals rather than best-effort
//! interpretations.
//!
//! The rule this module implements, from RFC 0009's *Path normalisation*: percent-decode once,
//! resolve `.` and `..`, collapse repeated slashes, strip a `;`-parameter segment. Refuse when
//! decoding yields a second `%`, when an encoded separator appears, or when `..` escapes the
//! root. A caller with a legitimate need for `/a%2Fb` is a bug report, not a security exception.

use std::fmt;

/// A path that survived normalisation, and the only kind a rule is ever matched against.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalisedPath(String);

impl NormalisedPath {
    /// The normalised path, always starting with `/`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NormalisedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a path was refused rather than normalised.
///
/// Every variant is a denial. None of them is configurable, for the reason RFC 0005 gives about
/// an unparseable image reference and this RFC repeats: a control whose bypass is "send something
/// malformed" is not a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// Did not start with `/`. An absolute-form request target (`http://host/x`) or a bare
    /// `*` — neither is something a rule can be matched against.
    NotAbsolute,
    /// A `%` that is not followed by two hexadecimal digits.
    BadEncoding,
    /// Decoding once produced another `%XX`. Double encoding has exactly one purpose against a
    /// gate that decodes once, and this is it.
    DoubleEncoded,
    /// An encoded `/` or `\`. Decoding it would change how the path splits into segments, which
    /// is the difference between the gate's view and the application's.
    EncodedSeparator,
    /// `..` climbed above the root.
    EscapesRoot,
    /// A decoded control character, including the NUL byte some frameworks truncate a path on.
    ControlCharacter,
}

/// The longest path this gate will consider. A longer one is refused as
/// [`PathError::NotAbsolute`]'s neighbour rather than normalised: nothing a workspace endpoint
/// serves needs it, and unbounded work per request is its own denial of service.
pub const MAX_PATH_LEN: usize = 8192;

/// Normalise a raw request path, or refuse it.
///
/// The query string is cut first and never looked at again: no rule in RFC 0009 matches on a
/// query, and a gate that decided on one would answer differently for two requests an
/// application treats identically.
pub fn normalise(raw: &str) -> Result<NormalisedPath, PathError> {
    if !raw.starts_with('/') || raw.len() > MAX_PATH_LEN {
        return Err(PathError::NotAbsolute);
    }
    let path = raw.split_once(['?', '#']).map_or(raw, |(before, _)| before);

    let mut out: Vec<String> = Vec::new();
    // A trailing slash is preserved, and a path whose last segment was `.` or `..` grows one:
    // `/a/b/..` is the directory `/a/`, the way every other resolver reads it. Tracked rather
    // than assumed, because getting it wrong changes which rule matches for every path ending in
    // a dot segment.
    let mut ended_on_dot_segment = false;
    for raw_segment in path.split('/') {
        // A `;`-parameter segment: `/a;jsessionid=1/b`. Stripped rather than kept, because a
        // servlet container routes on the part before the `;` and a gate that kept it would
        // match a different rule than the application.
        let segment = raw_segment
            .split_once(';')
            .map_or(raw_segment, |(before, _)| before);
        let decoded = decode_once(segment)?;
        match decoded.as_str() {
            "" => {}
            "." => ended_on_dot_segment = true,
            ".." => {
                if out.pop().is_none() {
                    return Err(PathError::EscapesRoot);
                }
                ended_on_dot_segment = true;
            }
            _ => {
                out.push(decoded);
                ended_on_dot_segment = false;
            }
        }
    }
    let trailing_slash = path.ends_with('/') || ended_on_dot_segment;

    let mut normalised = String::with_capacity(path.len() + 1);
    for segment in &out {
        normalised.push('/');
        normalised.push_str(segment);
    }
    // The root and a directory both end in a slash; an empty `out` means every segment resolved
    // away, which is the root.
    if normalised.is_empty() || trailing_slash {
        normalised.push('/');
    }
    Ok(NormalisedPath(normalised))
}

/// Percent-decode one segment exactly once, refusing everything that would make a second pass
/// meaningful.
fn decode_once(segment: &str) -> Result<String, PathError> {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte != b'%' {
            out.push(byte as char);
            i += 1;
            continue;
        }
        let (Some(high), Some(low)) = (
            bytes.get(i + 1).copied().and_then(hex_value),
            bytes.get(i + 2).copied().and_then(hex_value),
        ) else {
            return Err(PathError::BadEncoding);
        };
        let decoded = high * 16 + low;
        match decoded {
            b'/' | b'\\' => return Err(PathError::EncodedSeparator),
            b'%' => return Err(PathError::DoubleEncoded),
            0..=0x1f | 0x7f => return Err(PathError::ControlCharacter),
            // Byte-wise on purpose: a decoded non-ASCII byte becomes one `char` in `0x80..=0xff`
            // rather than half of a re-assembled code point. Rules match ASCII prefixes on
            // segment boundaries, so the only property that matters is that one raw path always
            // produces one normal form — and re-decoding UTF-8 here would add a second way to
            // spell a segment, which is the class of bug this whole module is about.
            _ => out.push(decoded as char),
        }
        i += 3;
    }
    // Decoding once must not have produced something that decodes again: `%252e` arrives as
    // `%2e`, which a second decoder — the application's — reads as `.`.
    if out.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && hex_value(window[1]).is_some() && hex_value(window[2]).is_some()
    }) {
        return Err(PathError::DoubleEncoded);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn norm(raw: &str) -> String {
        normalise(raw).unwrap().as_str().to_owned()
    }

    #[test]
    fn the_ordinary_paths_a_page_load_is_made_of_survive_unchanged() {
        for raw in [
            "/",
            "/index.html",
            "/static/app.js",
            "/api/items/",
            "/a-b_c",
        ] {
            assert_eq!(norm(raw), raw, "{raw:?}");
        }
    }

    #[test]
    fn a_query_string_is_cut_and_never_decided_on() {
        assert_eq!(norm("/api/items?filter=%2e%2e"), "/api/items");
        assert_eq!(norm("/api/items#fragment"), "/api/items");
    }

    #[test]
    fn dot_segments_resolve_and_repeated_slashes_collapse() {
        assert_eq!(norm("/a/./b"), "/a/b");
        assert_eq!(norm("/a/b/../c"), "/a/c");
        assert_eq!(norm("/a//b"), "/a/b");
        assert_eq!(norm("/a/b/.."), "/a/");
        // `/..` is not "the root": it is a climb out of it, and it is refused below with the
        // rest of the corpus rather than clamped to `/`.
        assert_eq!(normalise("/.."), Err(PathError::EscapesRoot));
    }

    #[test]
    fn a_matrix_parameter_is_stripped_the_way_a_servlet_container_strips_it() {
        assert_eq!(norm("/actuator;jsessionid=1/env"), "/actuator/env");
    }

    #[test]
    fn the_bypass_corpus_is_refused_rather_than_interpreted() {
        // Every row is a real technique against a forward-auth gate: get the gate to see a public
        // path and the application to serve a private one.
        let corpus = [
            ("/public/..%2factuator/env", PathError::EncodedSeparator),
            ("/public/..%5cactuator", PathError::EncodedSeparator),
            ("/%252e%252e/actuator", PathError::DoubleEncoded),
            ("/actuator%00.png", PathError::ControlCharacter),
            ("/actuator%2", PathError::BadEncoding),
            ("/actuator%zz", PathError::BadEncoding),
            ("/../../etc/passwd", PathError::EscapesRoot),
            ("actuator/env", PathError::NotAbsolute),
        ];
        for (raw, expected) in corpus {
            assert_eq!(normalise(raw), Err(expected), "{raw:?}");
        }
    }

    #[test]
    fn an_encoded_dot_still_decodes_because_only_the_separator_is_dangerous() {
        // `%2e` is not an attack on its own — it becomes a `.` and then resolves like any other.
        // Refusing it would break URLs that legitimately encode one.
        assert_eq!(norm("/a/%2e%2e/b"), "/b");
        assert_eq!(norm("/caf%C3%A9"), "/caf\u{c3}\u{a9}");
    }

    #[test]
    fn a_path_longer_than_the_bound_is_refused_rather_than_walked() {
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert_eq!(normalise(&long), Err(PathError::NotAbsolute));
    }
}
