//! What this feature decided about one image reference, and the vocabulary the metric, the log
//! line and the API error all render from.

use std::fmt;

use weebo_si_crd::EntryKey;

use crate::reference::ParseError;

/// Which pattern set permitted an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermittedBy {
    /// A catalogue entry the subject's selection reached.
    Entry(EntryKey),
    /// The platform set — allowed in every namespace regardless of team, withheld by no grant.
    Platform,
}

impl fmt::Display for PermittedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry(key) => write!(f, "entry {key}"),
            Self::Platform => f.write_str("platform"),
        }
    }
}

/// The verdict for one image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Permitted, by the named pattern set.
    Permitted(PermittedBy),
    /// Parsed, and matched no pattern in the effective union.
    NoMatchingPattern,
    /// Did not parse. **Always a denial, never a pass-through** — the one place in RFC 0005 with
    /// no configurable knob, because the alternative is a control whose bypass is "send
    /// something malformed."
    Unparseable(ParseError),
}

impl Verdict {
    /// Whether this verdict permits the image.
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permitted(_))
    }

    /// The `result` label of `weebo_si_image_policy_total`.
    ///
    /// `not_granted` is deliberately **not** produced here: it is a property of the *resolution*
    /// (a workspace naming a key its team lacks), not of an image, and it is reported by
    /// [`crate::resolve`] before any image is judged.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Permitted(_) => "allowed",
            Self::NoMatchingPattern => "denied",
            Self::Unparseable(_) => "unparseable",
        }
    }
}

/// One container's image, and what was decided about it. The container name travels with the
/// verdict because it is what the error message needs — "component `tools`" is actionable where
/// "one of this workspace's images" is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageVerdict {
    /// The container or component name the reference was read from.
    pub container: String,
    /// The reference, **as the user wrote it**, not normalized. Attacker-controlled text: every
    /// consumer escapes and length-bounds it, per [`escape_reference`].
    pub reference: String,
    /// What was decided.
    pub verdict: Verdict,
}

/// The longest reference any message or log line will echo back.
pub const MAX_ECHOED_REFERENCE: usize = 200;

/// Render an attacker-controlled reference for a log line or an API error: quoted, escaped, and
/// length-bounded.
///
/// RFC 0005's *Security considerations* makes this a rule rather than a nicety — "a control that
/// can be made to write arbitrary bytes into an operator's log stream has traded one problem for
/// another." The reference reaches two places (the API error and the log line) and both go
/// through here, so there is one implementation to review rather than two to keep in step.
pub fn escape_reference(reference: &str) -> String {
    let truncated: String = reference.chars().take(MAX_ECHOED_REFERENCE).collect();
    let mut out = String::with_capacity(truncated.len() + 2);
    out.push('"');
    for c in truncated.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Anything non-printable — control characters, and the terminal escape sequences a
            // log reader would otherwise execute.
            c if c.is_control() => out.push_str(&format!("\\u{{{:04x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    if reference.chars().count() > MAX_ECHOED_REFERENCE {
        out.push_str("…(truncated)");
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn the_result_labels_are_the_metrics_contract() {
        assert_eq!(Verdict::Permitted(PermittedBy::Platform).label(), "allowed");
        assert_eq!(
            Verdict::Permitted(PermittedBy::Entry(EntryKey::new("internal"))).label(),
            "allowed"
        );
        assert_eq!(Verdict::NoMatchingPattern.label(), "denied");
        assert_eq!(
            Verdict::Unparseable(ParseError::Empty).label(),
            "unparseable"
        );
    }

    #[test]
    fn only_a_permitted_verdict_permits() {
        assert!(Verdict::Permitted(PermittedBy::Platform).is_permitted());
        assert!(!Verdict::NoMatchingPattern.is_permitted());
        assert!(!Verdict::Unparseable(ParseError::Malformed).is_permitted());
    }

    #[test]
    fn a_reference_is_quoted_and_escaped_before_it_reaches_a_log() {
        assert_eq!(escape_reference("nginx"), "\"nginx\"");
        assert_eq!(escape_reference("evil\"name"), "\"evil\\\"name\"");
        assert_eq!(escape_reference("line\nbreak"), "\"line\\nbreak\"");
    }

    #[test]
    fn a_terminal_escape_sequence_cannot_reach_a_log_reader_unescaped() {
        let hostile = "\u{1b}[31mred";
        let escaped = escape_reference(hostile);
        assert!(!escaped.contains('\u{1b}'), "{escaped}");
        assert!(escaped.contains("\\u{001b}"), "{escaped}");
    }

    #[test]
    fn an_over_long_reference_is_bounded_and_says_so() {
        let long = "a".repeat(MAX_ECHOED_REFERENCE * 2);
        let escaped = escape_reference(&long);
        assert!(escaped.ends_with("…(truncated)"));
        assert!(escaped.len() < long.len());
    }

    #[test]
    fn a_reference_at_the_bound_is_not_marked_truncated() {
        let exact = "a".repeat(MAX_ECHOED_REFERENCE);
        assert!(!escape_reference(&exact).ends_with("…(truncated)"));
    }
}
