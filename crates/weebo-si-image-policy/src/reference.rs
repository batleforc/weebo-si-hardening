//! Image reference parsing and normalization — **the security-critical part of RFC 0005, and
//! everything else in this crate is bookkeeping.**
//!
//! The string a user types and the image a kubelet pulls are related by a normalization nobody
//! has in their head: `nginx` is `docker.io/library/nginx:latest`, `REGISTRY.INTERNAL/x` is
//! `registry.internal/x:latest`, `internal/weebo/dev` is *not* a host because it has no dot and
//! no port. A pattern matched against the raw string is therefore a bypass generator, so a
//! reference is parsed into `{host, path, tag, digest}` and normalized before anything looks at
//! it, and [`crate::pattern`] parses a pattern by the same rules into the same shape.
//!
//! Three properties this module is written to hold, per RFC 0005's *Security considerations*:
//!
//! - **Parse failure denies.** Every function here returns `Result`; there is no lenient path,
//!   no fallback to string comparison, and no configurable knob. The one caller that turns a
//!   [`ParseError`] into a verdict turns it into a denial.
//! - **No unbounded work.** The input is length-capped before parsing and every scan below is a
//!   single forward pass over the bytes. Nothing backtracks, so a long image name cannot be a
//!   denial of service against a `failurePolicy: Fail` admission path.
//! - **No `k8s-openapi` type.** A reference is a `&str` here and a `&str` in the adapter, which
//!   is what keeps the test suite for the part that can be catastrophically wrong a table of
//!   triples with no fixtures.

use std::fmt;

/// The longest reference this parser will look at. Well above anything a registry accepts (the
/// distribution spec bounds a path at 255 characters and a tag at 128) and far below anything
/// that costs measurable time, which is the point: the cap exists so an attacker cannot choose
/// the parser's input size, not to enforce a registry's own limit.
pub const MAX_REFERENCE_LEN: usize = 512;

/// The host every reference with no explicit registry normalizes to.
pub const DEFAULT_HOST: &str = "docker.io";
/// The path prefix a single-component `docker.io` path normalizes to — `nginx` is
/// `docker.io/library/nginx`, and this is the only place in the design where a path grows a
/// segment it was not written with.
pub const DEFAULT_NAMESPACE: &str = "library";
/// The tag a reference with neither a tag nor a digest normalizes to.
pub const DEFAULT_TAG: &str = "latest";

/// Why a reference (or a pattern, which is parsed by the same rules) did not parse.
///
/// Deliberately carries no copy of the offending input: the caller already has it, and a parse
/// error that embeds attacker-controlled bytes is one `format!` away from being the thing that
/// writes them somewhere they are not escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input is empty.
    Empty,
    /// The input is longer than [`MAX_REFERENCE_LEN`].
    TooLong,
    /// The input carries a byte no part of the distribution grammar admits.
    IllegalCharacter(char),
    /// The host, or one of its labels, is not a legal registry host.
    IllegalHost,
    /// A path component is not `[a-z0-9]` groups separated by `.`, `_`, `__` or `-`.
    IllegalPathComponent,
    /// The tag is not `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
    IllegalTag,
    /// The digest is not `algorithm:encoded`.
    IllegalDigest,
    /// More than one `@`, an empty side of a separator, or another shape the grammar has no
    /// reading for.
    Malformed,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty reference"),
            Self::TooLong => write!(f, "longer than {MAX_REFERENCE_LEN} characters"),
            Self::IllegalCharacter(c) => write!(f, "illegal character {c:?}"),
            Self::IllegalHost => f.write_str("illegal registry host"),
            Self::IllegalPathComponent => f.write_str("illegal repository path component"),
            Self::IllegalTag => f.write_str("illegal tag"),
            Self::IllegalDigest => f.write_str("illegal digest"),
            Self::Malformed => f.write_str("malformed reference"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed, normalized image reference — the only shape anything in this crate matches
/// against.
///
/// Fields are private with accessors rather than `pub`, for the same reason
/// `network-profiles`' `PolicyBody` is opaque: the normalization is the security property, and a
/// `pub` field is an invitation for a later change to construct one of these by hand and skip
/// it. The only constructor is [`ImageReference::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    host: String,
    path: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl ImageReference {
    /// The normalized registry host, lowercased, trailing dot stripped, port included when the
    /// reference carried one. Never empty.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The normalized repository path — `library/nginx` for `nginx`. Never empty, never leading
    /// or trailing `/`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The tag, or `None`.
    ///
    /// **`None` whenever the reference carries a digest**, tag written or not: a digested
    /// reference runs those bytes whatever its tag says, so the tag is not evidence and a
    /// pattern carrying a tag constraint must not match on it. That is the fail-closed reading
    /// of RFC 0005's "the tag is decoration, the digest is what runs," and it makes
    /// `dev:v1@sha256:…` and `dev@sha256:…` behave identically, which is what an admin reading
    /// the table in that RFC would predict.
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The digest, or `None`.
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// The path split into its `/`-separated components. Never empty.
    pub fn path_components(&self) -> std::str::Split<'_, char> {
        self.path.split('/')
    }

    /// Parse and normalize one reference. The only way to build an [`ImageReference`].
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::Empty);
        }
        if raw.len() > MAX_REFERENCE_LEN {
            return Err(ParseError::TooLong);
        }
        // One forward pass rejecting anything outside the union of every sub-grammar below, so
        // no later scan has to consider a byte the distribution spec has no reading for. Braces
        // land here: `{`/`}` are legal in a *pattern* and never in a reference, which is what
        // makes "a brace in a reference is always a parse failure" a property of the grammar
        // rather than a convention (RFC 0005's *Contract*).
        if let Some(c) = raw.chars().find(|c| !is_legal_reference_char(*c)) {
            return Err(ParseError::IllegalCharacter(c));
        }

        let (name_and_tag, digest) = split_digest(raw)?;
        let (name, tag) = split_tag(name_and_tag)?;
        let (host, path) = split_host(name)?;

        let host = normalize_host(host)?;
        let path = normalize_path(&host, path)?;

        if let Some(tag) = tag.as_deref() {
            validate_tag(tag)?;
        }

        // A digest wins outright: the tag is dropped rather than carried, so nothing downstream
        // can accidentally treat it as evidence. See `tag()`.
        let tag = match digest {
            Some(_) => None,
            None => Some(tag.unwrap_or_else(|| DEFAULT_TAG.to_string())),
        };

        Ok(Self {
            host,
            path,
            tag,
            digest,
        })
    }
}

impl fmt::Display for ImageReference {
    /// The normalized form, as `images check` prints it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.host, self.path)?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// The union of every character any part of the reference grammar admits. Everything else is
/// rejected before any structural scan runs.
fn is_legal_reference_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '/' | ':' | '@' | '+' | '=')
}

/// Split `name[:tag]@digest` into its two halves. At most one `@`.
fn split_digest(raw: &str) -> Result<(&str, Option<String>), ParseError> {
    let mut parts = raw.splitn(2, '@');
    // `splitn` always yields at least one item for a non-empty input.
    let name = parts.next().unwrap_or(raw);
    let Some(digest) = parts.next() else {
        return Ok((raw, None));
    };
    if raw.matches('@').count() > 1 {
        return Err(ParseError::Malformed);
    }
    if name.is_empty() {
        return Err(ParseError::Malformed);
    }
    validate_digest(digest)?;
    Ok((name, Some(digest.to_string())))
}

/// `algorithm:encoded`, where `algorithm` is `[a-z0-9]+([+._-][a-z0-9]+)*` and `encoded` is at
/// least 32 characters of `[a-zA-Z0-9=_-]`.
fn validate_digest(digest: &str) -> Result<(), ParseError> {
    let mut halves = digest.splitn(2, ':');
    let algorithm = halves.next().unwrap_or_default();
    let Some(encoded) = halves.next() else {
        return Err(ParseError::IllegalDigest);
    };
    if algorithm.is_empty() || encoded.len() < 32 {
        return Err(ParseError::IllegalDigest);
    }
    // Separator-delimited groups, exactly as the path grammar is shaped — no empty group.
    let mut previous_was_separator = true;
    for c in algorithm.chars() {
        if matches!(c, '+' | '.' | '_' | '-') {
            if previous_was_separator {
                return Err(ParseError::IllegalDigest);
            }
            previous_was_separator = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            previous_was_separator = false;
        } else {
            return Err(ParseError::IllegalDigest);
        }
    }
    if previous_was_separator {
        return Err(ParseError::IllegalDigest);
    }
    if !encoded
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '=' | '_' | '-'))
    {
        return Err(ParseError::IllegalDigest);
    }
    Ok(())
}

/// Split `name[:tag]`. The tag is the part after the **last `:` that follows the last `/`** —
/// which is what disambiguates `registry:5000/repo` (a port) from `repo:tag` (a tag) without
/// guessing. `registry:5000/repo:tag` has both, and each lands where it belongs.
fn split_tag(name_and_tag: &str) -> Result<(&str, Option<String>), ParseError> {
    let last_slash = name_and_tag.rfind('/');
    let final_segment_start = last_slash.map_or(0, |i| i + 1);
    let Some(colon) = name_and_tag[final_segment_start..]
        .rfind(':')
        .map(|i| i + final_segment_start)
    else {
        return Ok((name_and_tag, None));
    };
    let (name, tag) = name_and_tag.split_at(colon);
    // Strip the ':'; `split_at` on a byte index found by `rfind` is on a char boundary.
    let tag = &tag[1..];
    if name.is_empty() || tag.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok((name, Some(tag.to_string())))
}

/// Split `[host/]path`. The first component is a host **only** if it carries a `.` or a `:`, or
/// is exactly `localhost` — the rule that makes `internal/weebo/dev` a Docker Hub path and
/// `localhost:5000/dev` a local registry. Getting this wrong in either direction is a bypass,
/// which is why it is one function with its own tests rather than an inline condition.
fn split_host(name: &str) -> Result<(Option<&str>, &str), ParseError> {
    let Some(slash) = name.find('/') else {
        return Ok((None, name));
    };
    let (first, rest) = name.split_at(slash);
    let rest = &rest[1..];
    if first.is_empty() || rest.is_empty() {
        return Err(ParseError::Malformed);
    }
    if first.contains('.') || first.contains(':') || first == "localhost" {
        Ok((Some(first), rest))
    } else {
        Ok((None, name))
    }
}

/// Lowercase, strip one trailing dot, validate the labels and the optional port. Hosts are
/// case-insensitive and a trailing dot is a valid FQDN, so both normalize away before any
/// comparison — the two rows of RFC 0005's own table that a flat string glob gets wrong.
fn normalize_host(host: Option<&str>) -> Result<String, ParseError> {
    let Some(host) = host else {
        return Ok(DEFAULT_HOST.to_string());
    };
    let lowered = host.to_ascii_lowercase();

    let (name, port) = match lowered.rfind(':') {
        Some(colon) => {
            let (name, port) = lowered.split_at(colon);
            (name.to_string(), Some(port[1..].to_string()))
        }
        None => (lowered, None),
    };

    let name = name.strip_suffix('.').unwrap_or(&name).to_string();
    if name.is_empty() {
        return Err(ParseError::IllegalHost);
    }
    for label in name.split('.') {
        validate_host_label(label)?;
    }
    match port {
        Some(port) => {
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return Err(ParseError::IllegalHost);
            }
            Ok(format!("{name}:{port}"))
        }
        None => Ok(name),
    }
}

/// One host label: `[a-z0-9]([a-z0-9-]*[a-z0-9])?`. Already lowercased by the caller.
fn validate_host_label(label: &str) -> Result<(), ParseError> {
    if label.is_empty() {
        return Err(ParseError::IllegalHost);
    }
    let bytes = label.as_bytes();
    let first = *bytes.first().unwrap_or(&b'-');
    let last = *bytes.last().unwrap_or(&b'-');
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(ParseError::IllegalHost);
    }
    if !label
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ParseError::IllegalHost);
    }
    Ok(())
}

/// Validate every component, and add the `library/` prefix a single-component Docker Hub path
/// gets. Repository paths are lowercase by the distribution grammar, so an uppercase one is a
/// parse failure rather than something to fold — folding it would make two distinct references
/// compare equal to one pattern.
fn normalize_path(host: &str, path: &str) -> Result<String, ParseError> {
    if path.is_empty() {
        return Err(ParseError::Malformed);
    }
    for component in path.split('/') {
        validate_path_component(component)?;
    }
    if host == DEFAULT_HOST && !path.contains('/') {
        return Ok(format!("{DEFAULT_NAMESPACE}/{path}"));
    }
    Ok(path.to_string())
}

/// One path component: `[a-z0-9]+` groups separated by `.`, `_`, `__` or `-+`. Shared with
/// [`crate::variable`]'s `PathComponent`, which is the same grammar applied to a variable's
/// *value* — the reason a team named `a/**` cannot widen a pattern.
pub(crate) fn validate_path_component(component: &str) -> Result<(), ParseError> {
    let bytes = component.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return Err(ParseError::IllegalPathComponent);
    };
    // Separator *runs* are legal in the middle (`__`, `--` — `che--traefik` is a real platform
    // image); a leading or trailing one is not, which is the whole of the boundary rule.
    let alphanumeric = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alphanumeric(first) || !alphanumeric(last) {
        return Err(ParseError::IllegalPathComponent);
    }
    if component
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        Ok(())
    } else {
        Err(ParseError::IllegalPathComponent)
    }
}

/// One tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`. Unlike a path, a tag is case-sensitive —
/// `:UBI9` and `:ubi9` are different tags at every registry, so folding them would make a
/// pattern match a tag the admin did not write.
fn validate_tag(tag: &str) -> Result<(), ParseError> {
    if tag.is_empty() || tag.len() > 128 {
        return Err(ParseError::IllegalTag);
    }
    let mut chars = tag.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() || first == '_' => {}
        _ => return Err(ParseError::IllegalTag),
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
        Ok(())
    } else {
        Err(ParseError::IllegalTag)
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

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parsed(raw: &str) -> ImageReference {
        ImageReference::parse(raw).unwrap_or_else(|err| panic!("{raw:?} should parse: {err}"))
    }

    /// RFC 0005's *Contract* table, verbatim, as a table.
    #[test]
    fn the_rfcs_normalization_table_is_executable() {
        let cases: &[(&str, &str)] = &[
            ("nginx", "docker.io/library/nginx:latest"),
            ("weebo/dev", "docker.io/weebo/dev:latest"),
            (
                "REGISTRY.INTERNAL/weebo/dev",
                "registry.internal/weebo/dev:latest",
            ),
            (
                "registry.internal./weebo/dev",
                "registry.internal/weebo/dev:latest",
            ),
            ("localhost:5000/dev", "localhost:5000/dev:latest"),
            ("internal/weebo/dev", "docker.io/internal/weebo/dev:latest"),
        ];
        for (written, pulled) in cases {
            assert_eq!(
                parsed(written).to_string(),
                *pulled,
                "{written:?} should normalize to {pulled:?}"
            );
        }
    }

    #[test]
    fn a_digest_drops_the_tag_because_the_tag_is_not_evidence() {
        let with_both = parsed(&format!("registry.internal/dev:v1@{DIGEST}"));
        let digest_only = parsed(&format!("registry.internal/dev@{DIGEST}"));
        assert_eq!(with_both.tag(), None);
        assert_eq!(digest_only.tag(), None);
        assert_eq!(with_both.digest(), Some(DIGEST));
        assert_eq!(with_both.path(), digest_only.path());
    }

    #[test]
    fn fields_are_split_not_globbed() {
        let reference = parsed("registry.internal/teams/team-1/dev-java:21");
        assert_eq!(reference.host(), "registry.internal");
        assert_eq!(reference.path(), "teams/team-1/dev-java");
        assert_eq!(reference.tag(), Some("21"));
        assert_eq!(reference.digest(), None);
    }

    #[test]
    fn a_port_is_a_host_and_a_tag_is_a_tag_even_together() {
        let reference = parsed("registry.internal:5000/dev:v2");
        assert_eq!(reference.host(), "registry.internal:5000");
        assert_eq!(reference.path(), "dev");
        assert_eq!(reference.tag(), Some("v2"));
    }

    #[test]
    fn the_port_is_part_of_the_host_and_therefore_significant() {
        assert_ne!(
            parsed("registry.internal:5000/dev").host(),
            parsed("registry.internal/dev").host()
        );
    }

    #[test]
    fn a_first_component_with_no_dot_and_no_port_is_a_path_not_a_host() {
        // The row of the RFC's table most likely to be implemented backwards.
        assert_eq!(parsed("internal/weebo/dev").host(), DEFAULT_HOST);
        assert_eq!(parsed("internal/weebo/dev").path(), "internal/weebo/dev");
    }

    #[test]
    fn localhost_is_a_host_without_a_port_by_special_case() {
        assert_eq!(parsed("localhost/dev").host(), "localhost");
        assert_eq!(parsed("localhost/dev").path(), "dev");
    }

    #[test]
    fn tags_are_case_sensitive_and_hosts_are_not() {
        assert_eq!(
            parsed("REGISTRY.INTERNAL/dev:UBI9").host(),
            "registry.internal"
        );
        assert_eq!(parsed("REGISTRY.INTERNAL/dev:UBI9").tag(), Some("UBI9"));
    }

    #[test]
    fn separator_runs_inside_a_path_component_are_legal() {
        // `quay.io/eclipse/che--traefik` is a real platform image, and `__` is in the grammar.
        assert_eq!(
            parsed("quay.io/eclipse/che--traefik").path(),
            "eclipse/che--traefik"
        );
        assert_eq!(parsed("quay.io/a/b__c").path(), "a/b__c");
        assert_eq!(parsed("quay.io/a/b.c").path(), "a/b.c");
    }

    #[test]
    fn an_uppercase_path_is_a_parse_failure_not_something_to_fold() {
        // Folding would make two distinct references compare equal to one pattern.
        assert_eq!(
            ImageReference::parse("registry.internal/Weebo/dev"),
            Err(ParseError::IllegalPathComponent)
        );
    }

    #[test]
    fn a_brace_is_always_a_parse_failure_in_a_reference() {
        // The property RFC 0005 leans on so a pattern needs no brace escaping.
        assert_eq!(
            ImageReference::parse("registry.internal/teams/{TEAM_NAME}/dev"),
            Err(ParseError::IllegalCharacter('{'))
        );
    }

    #[test]
    fn a_star_is_always_a_parse_failure_in_a_reference() {
        assert_eq!(
            ImageReference::parse("registry.internal/**"),
            Err(ParseError::IllegalCharacter('*'))
        );
    }

    #[test]
    fn malformed_references_are_rejected_never_passed_through() {
        let rejected: &[&str] = &[
            "",
            "registry.internal/",
            "/dev",
            "registry.internal/dev:",
            "registry.internal/dev@",
            "registry.internal/dev@sha256:short",
            "registry.internal/dev@notadigest",
            &format!("registry.internal/dev@{DIGEST}@{DIGEST}"),
            "registry.internal//dev",
            "registry.internal/-dev",
            "registry.internal/dev-",
            "registry.internal:/dev",
            "registry.internal:notaport/dev",
            "-registry.internal/dev",
            "registry..internal/dev",
            "registry.internal/dev:-bad",
            "registry.internal/dev:a b",
        ];
        for raw in rejected {
            assert!(
                ImageReference::parse(raw).is_err(),
                "{raw:?} must not parse — parse failure denies, and a lenient parser is a bypass"
            );
        }
    }

    #[test]
    fn an_over_long_reference_is_capped_before_any_structural_scan() {
        let long = format!("registry.internal/{}", "a".repeat(MAX_REFERENCE_LEN));
        assert_eq!(ImageReference::parse(&long), Err(ParseError::TooLong));
    }

    #[test]
    fn a_reference_at_the_cap_still_parses() {
        let filler = MAX_REFERENCE_LEN - "registry.internal/".len();
        let at_cap = format!("registry.internal/{}", "a".repeat(filler));
        assert_eq!(at_cap.len(), MAX_REFERENCE_LEN);
        assert!(ImageReference::parse(&at_cap).is_ok());
    }

    #[test]
    fn parsing_is_idempotent_over_its_own_output() {
        // A normalization that is not a fixed point is one where "normalized twice" and
        // "normalized once" can disagree, which is exactly the gap a bypass lives in.
        for raw in [
            "nginx",
            "REGISTRY.INTERNAL/weebo/dev",
            "registry.internal./weebo/dev",
            "localhost:5000/dev:v1",
        ] {
            let once = parsed(raw);
            let twice = parsed(&once.to_string());
            assert_eq!(
                once, twice,
                "{raw:?} should be a fixed point after one pass"
            );
        }
    }

    #[test]
    fn path_components_are_split_not_re_parsed() {
        let reference = parsed("registry.internal/teams/team-1/dev");
        let components: Vec<&str> = reference.path_components().collect();
        assert_eq!(components, vec!["teams", "team-1", "dev"]);
    }
}
