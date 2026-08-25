//! Pattern parsing, typed substitution and per-field matching — RFC 0005's *Pattern grammar*.
//!
//! A pattern is parsed by the same rules as a reference ([`crate::reference`]) into the same
//! `{host, path, tag}` shape, and each field is matched independently. That is the whole reason
//! the separator ambiguity that makes flat-string globbing unsafe — is the `:` in
//! `registry:5000/foo` a port or a tag, does `**` cross it — does not exist here: the split
//! happened in the parser, and the matcher never sees a `:` it has to guess about.
//!
//! A pattern may not carry a digest. `@` is a parse error, per the *Contract* table's "digest:
//! not writable in a pattern": a digest is an exact value, an allow-list of exact digests is a
//! different feature (`requireDigest`, in *Future work*), and a pattern that could carry one
//! would read as pinning while doing nothing of the sort on a tagged reference.

use std::fmt;

use crate::reference::{
    DEFAULT_HOST, DEFAULT_NAMESPACE, ImageReference, MAX_REFERENCE_LEN, ParseError,
    validate_path_component,
};
use crate::variable::{VariableName, VariableValues};

/// One piece of a glob run — inside a path segment, or inside a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobPiece {
    /// A literal run.
    Literal(String),
    /// `*` — any run of characters, never crossing a `/` (a segment's matcher is only ever
    /// handed one segment).
    Star,
    /// A variable, resolved to a whole [`crate::variable::PathComponent`] before comparison.
    Var(VariableName),
}

/// One `/`-separated segment of a pattern's path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    /// A glob over exactly one segment — `dev-*`, `nginx`, `{PROJECT}`.
    Glob(Vec<GlobPiece>),
    /// `**` — one or more whole segments. Never zero: `a/**` does not match `a`, because an
    /// admin writing `registry.internal/shared/**` means "something under shared", and matching
    /// the bare repository `shared` as well would be a wider allow-list than the text reads as.
    DoubleStar,
}

/// A pattern's host — the trust anchor of the whole allow-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// `*.suffix` — any host with at least one label before `suffix`. **Not** `suffix` itself:
    /// `*.internal` permitting `internal` would be a registry the admin did not name.
    Suffix(String),
    /// A sequence of whole labels, each literal or a `{TEAM_NAME}` slot, plus an optional port.
    Labels {
        /// The labels, in order.
        labels: Vec<GlobPiece>,
        /// The port, if the pattern named one. Significant: a pattern with no port matches only
        /// a reference with no port.
        port: Option<String>,
    },
}

/// A parsed image pattern. Built only by [`Pattern::parse`], and matched only against a parsed
/// [`ImageReference`] — there is no `matches(&str)`, which is the compile-time half of "a
/// pattern never sees a string the parser did not already split."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    host: HostPattern,
    path: Vec<PathSegment>,
    tag: Option<Vec<GlobPiece>>,
}

impl Pattern {
    /// The pattern as the admin wrote it — for an error message and for `images check`'s output,
    /// never for matching.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Every variable this pattern names, in first-seen order. Used by the catalogue validator
    /// to report an undeclared name, and by `images check` to say what a pattern became.
    pub fn variables(&self) -> Vec<&VariableName> {
        let host_pieces: &[GlobPiece] = match &self.host {
            HostPattern::Labels { labels, .. } => labels,
            HostPattern::Suffix(_) => &[],
        };
        let path_pieces = self.path.iter().filter_map(|segment| match segment {
            PathSegment::Glob(pieces) => Some(pieces.as_slice()),
            PathSegment::DoubleStar => None,
        });
        let tag_pieces = self.tag.as_deref().into_iter();

        let mut out: Vec<&VariableName> = Vec::new();
        for pieces in std::iter::once(host_pieces)
            .chain(path_pieces)
            .chain(tag_pieces)
        {
            for piece in pieces {
                if let GlobPiece::Var(name) = piece
                    && !out.contains(&name)
                {
                    out.push(name);
                }
            }
        }
        out
    }

    /// Whether this pattern names `{TEAM_NAME}` anywhere.
    pub fn interpolates_team_name(&self) -> bool {
        self.variables()
            .iter()
            .any(|name| name.as_str() == crate::variable::TEAM_NAME)
    }

    /// Parse one pattern. The same length cap, the same host/path/tag split and the same
    /// component grammar as [`ImageReference::parse`], plus the glob and variable syntax and
    /// minus the digest.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        if raw.is_empty() {
            return Err(ParseError::Empty);
        }
        if raw.len() > MAX_REFERENCE_LEN {
            return Err(ParseError::TooLong);
        }
        if raw.contains('@') {
            // "digest: not writable in a pattern" — Contract's grammar table.
            return Err(ParseError::IllegalDigest);
        }
        if let Some(c) = raw.chars().find(|c| !is_legal_pattern_char(*c)) {
            return Err(ParseError::IllegalCharacter(c));
        }
        // A pattern that is *only* a wildcard is the "any registry" form the Contract rejects.
        // Caught here rather than in `parse_host`, because with no `/` there is no host half for
        // that function to be handed — `*` would otherwise fall through to the default host and
        // silently become `docker.io/library/*`, which is a large allow-list wearing the text of
        // an unbounded one.
        if raw == "*" || raw == "**" {
            return Err(ParseError::IllegalHost);
        }

        let (name, tag) = split_pattern_tag(raw)?;
        let (host_text, path_text) = split_pattern_host(name)?;

        let host = parse_host(host_text)?;
        let path = parse_path(&host, path_text)?;
        let tag = match tag {
            Some(text) => Some(parse_glob(&text, GlobField::Tag)?),
            None => None,
        };

        Ok(Self {
            raw: raw.to_string(),
            host,
            path,
            tag,
        })
    }

    /// Whether `reference` is permitted by this pattern, given the variables bound for this
    /// subject.
    ///
    /// **An undefined variable makes the whole pattern match nothing**, checked first and
    /// before any field comparison, per RFC 0005's *Contract*. Not "an empty segment", which
    /// would collapse `registry.internal/teams/{TEAM_NAME}/**` into
    /// `registry.internal/teams/**` and hand every namespace with no team every team's images.
    pub fn matches(&self, reference: &ImageReference, variables: &VariableValues) -> bool {
        for name in self.variables() {
            if variables.get(name).is_none() {
                return false;
            }
        }
        self.matches_host(reference.host(), variables)
            && matches_path(&self.path, reference, variables)
            && self.matches_tag(reference.tag(), variables)
    }

    /// This pattern with every variable substituted, as text — what `images check` prints so an
    /// admin can see what an interpolating pattern became rather than infer it. Returns `None`
    /// when a variable is undefined, which is the same answer [`Self::matches`] gives.
    pub fn interpolated(&self, variables: &VariableValues) -> Option<String> {
        let host = match &self.host {
            HostPattern::Suffix(suffix) => format!("*.{suffix}"),
            HostPattern::Labels { labels, port } => {
                let rendered = render_pieces(labels, variables, ".")?;
                match port {
                    Some(port) => format!("{rendered}:{port}"),
                    None => rendered,
                }
            }
        };
        let mut path = Vec::new();
        for segment in &self.path {
            path.push(match segment {
                PathSegment::DoubleStar => "**".to_string(),
                PathSegment::Glob(pieces) => render_pieces(pieces, variables, "")?,
            });
        }
        let mut out = format!("{host}/{}", path.join("/"));
        if let Some(pieces) = &self.tag {
            out.push(':');
            out.push_str(&render_pieces(pieces, variables, "")?);
        }
        Some(out)
    }

    fn matches_host(&self, host: &str, variables: &VariableValues) -> bool {
        match &self.host {
            // Compared against the whole host *including any port*, so `*.internal` does not
            // match `x.internal:5000`. Ports are significant, and a suffix rule that ignored
            // them would silently permit a second registry on the same name.
            HostPattern::Suffix(suffix) => host.ends_with(&format!(".{suffix}")),
            HostPattern::Labels { labels, port } => {
                let (name, actual_port) = match host.rfind(':') {
                    Some(colon) => (&host[..colon], Some(&host[colon + 1..])),
                    None => (host, None),
                };
                if port.as_deref() != actual_port {
                    return false;
                }
                let expected: Vec<&str> = name.split('.').collect();
                if expected.len() != labels.len() {
                    return false;
                }
                labels
                    .iter()
                    .zip(expected)
                    .all(|(piece, label)| match piece {
                        GlobPiece::Literal(literal) => literal == label,
                        // Rejected at parse time — a bare `*` host is not an allow-list.
                        GlobPiece::Star => false,
                        GlobPiece::Var(name) => variables
                            .get(name)
                            .is_some_and(|value| value.as_str() == label),
                    })
            }
        }
    }

    fn matches_tag(&self, tag: Option<&str>, variables: &VariableValues) -> bool {
        let Some(pieces) = &self.tag else {
            // "A pattern with no tag constraint matches any reference in its host and path,
            // tagged, digested, or both."
            return true;
        };
        // "A digest-only reference has no tag and therefore matches only tag-agnostic patterns."
        let Some(tag) = tag else {
            return false;
        };
        matches_glob(pieces, tag, variables)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Which field a glob run belongs to — the two have different legal characters, and a tag is
/// case-sensitive where a path is not (a path is lowercase-only, so the distinction never
/// arises there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobField {
    PathSegment,
    Tag,
}

/// The union of every character any part of the pattern grammar admits — the reference set,
/// plus the two glob and variable metacharacters.
fn is_legal_pattern_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '.' | '-' | '_' | '/' | ':' | '+' | '=' | '*' | '{' | '}')
}

/// Same rule as a reference's: the tag is what follows the last `:` after the last `/`.
fn split_pattern_tag(raw: &str) -> Result<(&str, Option<String>), ParseError> {
    let last_slash = raw.rfind('/');
    let final_segment_start = last_slash.map_or(0, |i| i + 1);
    let Some(colon) = raw[final_segment_start..]
        .rfind(':')
        .map(|i| i + final_segment_start)
    else {
        return Ok((raw, None));
    };
    let (name, tag) = raw.split_at(colon);
    let tag = &tag[1..];
    if name.is_empty() || tag.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok((name, Some(tag.to_string())))
}

/// Same rule as a reference's, with one addition: a first component that *is* a host wildcard
/// (`*.suffix`) or carries a `{TEAM_NAME}` label is a host too, since neither can be a Docker
/// Hub path component.
fn split_pattern_host(name: &str) -> Result<(Option<&str>, &str), ParseError> {
    let Some(slash) = name.find('/') else {
        return Ok((None, name));
    };
    let (first, rest) = name.split_at(slash);
    let rest = &rest[1..];
    if first.is_empty() || rest.is_empty() {
        return Err(ParseError::Malformed);
    }
    let is_host = first.contains('.')
        || first.contains(':')
        || first == "localhost"
        || first.starts_with("*.")
        // A bare `*` in the first position is a *host* attempt, routed to `parse_host` so it is
        // refused there. Reading it as a Docker Hub path component instead would turn `*/**` —
        // an admin writing "any registry" — into `docker.io/*/**`, which is not what they wrote
        // and is not a refusal either.
        || first == "*";
    if is_host {
        Ok((Some(first), rest))
    } else {
        Ok((None, name))
    }
}

fn parse_host(host: Option<&str>) -> Result<HostPattern, ParseError> {
    let Some(host) = host else {
        return Ok(HostPattern::Labels {
            labels: vec![GlobPiece::Literal(DEFAULT_HOST.to_string())],
            port: None,
        });
    };

    // "A bare `*` is rejected at validation — 'any registry' is not an allow-list."
    if host == "*" {
        return Err(ParseError::IllegalHost);
    }
    if let Some(suffix) = host.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') || suffix.contains('{') {
            return Err(ParseError::IllegalHost);
        }
        let lowered = suffix.to_ascii_lowercase();
        let lowered = lowered.strip_suffix('.').unwrap_or(&lowered).to_string();
        for label in lowered.split('.') {
            validate_host_literal_label(label)?;
        }
        return Ok(HostPattern::Suffix(lowered));
    }

    let lowered = host.to_ascii_lowercase();
    let (name, port) = match lowered.rfind(':') {
        Some(colon) => {
            let port = lowered[colon + 1..].to_string();
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return Err(ParseError::IllegalHost);
            }
            (lowered[..colon].to_string(), Some(port))
        }
        None => (lowered, None),
    };
    let name = name.strip_suffix('.').unwrap_or(&name).to_string();
    if name.is_empty() {
        return Err(ParseError::IllegalHost);
    }

    let mut labels = Vec::new();
    for label in name.split('.') {
        // "a host whose whole label is a variable" — a *whole* label, never a run inside one:
        // `{TEAM_NAME}x.internal` would make the trust anchor depend on string concatenation,
        // which is the thing the typed substitution exists to prevent.
        if let Some(inner) = label.strip_prefix('{').and_then(|l| l.strip_suffix('}')) {
            // The host is lowercased above, and variable names are uppercase — so the name is
            // recovered rather than read, which is why this compares case-insensitively.
            let name = VariableName::new(inner.to_ascii_uppercase())
                .map_err(|_| ParseError::IllegalHost)?;
            if !name.allowed_in_host() {
                return Err(ParseError::IllegalHost);
            }
            labels.push(GlobPiece::Var(name));
        } else {
            validate_host_literal_label(label)?;
            labels.push(GlobPiece::Literal(label.to_string()));
        }
    }
    Ok(HostPattern::Labels { labels, port })
}

fn validate_host_literal_label(label: &str) -> Result<(), ParseError> {
    if label.is_empty() {
        return Err(ParseError::IllegalHost);
    }
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return Err(ParseError::IllegalHost);
    };
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return Err(ParseError::IllegalHost);
    }
    if label
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Ok(())
    } else {
        Err(ParseError::IllegalHost)
    }
}

fn parse_path(host: &HostPattern, path: &str) -> Result<Vec<PathSegment>, ParseError> {
    if path.is_empty() {
        return Err(ParseError::Malformed);
    }
    // The same `library/` prefix a reference gets, applied to a pattern so `nginx*` and
    // `docker.io/library/nginx*` are the same allow-list rather than two that differ by which
    // one the admin happened to type.
    let is_default_host = matches!(
        host,
        HostPattern::Labels { labels, port: None }
            if labels.as_slice() == [GlobPiece::Literal(DEFAULT_HOST.to_string())]
    );
    let owned;
    let path = if is_default_host && !path.contains('/') {
        owned = format!("{DEFAULT_NAMESPACE}/{path}");
        owned.as_str()
    } else {
        path
    };

    let mut segments = Vec::new();
    for segment in path.split('/') {
        if segment == "**" {
            segments.push(PathSegment::DoubleStar);
        } else {
            segments.push(PathSegment::Glob(parse_glob(
                segment,
                GlobField::PathSegment,
            )?));
        }
    }
    Ok(segments)
}

/// Parse one segment (or one tag) into literal / `*` / `{VAR}` pieces.
fn parse_glob(text: &str, field: GlobField) -> Result<Vec<GlobPiece>, ParseError> {
    if text.is_empty() {
        return Err(match field {
            GlobField::PathSegment => ParseError::IllegalPathComponent,
            GlobField::Tag => ParseError::IllegalTag,
        });
    }
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = text;

    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix('*') {
            // `**` is only meaningful as a whole segment, handled by the caller; inside a
            // segment it would be indistinguishable from `*`, and an admin writing it almost
            // certainly meant the whole-segment form.
            if after.starts_with('*') {
                return Err(ParseError::Malformed);
            }
            flush(&mut literal, &mut pieces, field)?;
            pieces.push(GlobPiece::Star);
            rest = after;
            continue;
        }
        if let Some(after) = rest.strip_prefix('{') {
            let Some(end) = after.find('}') else {
                return Err(ParseError::Malformed);
            };
            let name = &after[..end];
            if name.is_empty() {
                return Err(ParseError::Malformed);
            }
            let name = VariableName::new(name).map_err(|_| ParseError::Malformed)?;
            flush(&mut literal, &mut pieces, field)?;
            pieces.push(GlobPiece::Var(name));
            rest = &after[end + 1..];
            continue;
        }
        let Some(c) = rest.chars().next() else { break };
        if c == '}' {
            return Err(ParseError::Malformed);
        }
        literal.push(c);
        rest = &rest[c.len_utf8()..];
    }
    flush(&mut literal, &mut pieces, field)?;

    if pieces.is_empty() {
        return Err(ParseError::Malformed);
    }
    validate_boundaries(&pieces, field)?;
    Ok(pieces)
}

/// A parsed run must be able to match *something*, and the boundary rules are where that is
/// decided: no reference component may start or end with a separator, so neither may a pattern's
/// literal edge.
///
/// Without this, `registry.internal/-dev` parses, never matches, and is therefore invisible —
/// and "never matches" is indistinguishable from "correctly restrictive" from the outside, which
/// is the same argument RFC 0005 makes for reporting an undeclared variable rather than treating
/// it as a literal. A pattern that cannot work has to be a `Degraded` condition an admin can
/// see, not a quiet no-op.
///
/// A `*` or a `{VAR}` at an edge is fine: whatever it resolves to supplies the boundary
/// character, and a [`crate::variable::PathComponent`] is validated to have legal edges of its
/// own.
fn validate_boundaries(pieces: &[GlobPiece], field: GlobField) -> Result<(), ParseError> {
    let illegal = || match field {
        GlobField::PathSegment => ParseError::IllegalPathComponent,
        GlobField::Tag => ParseError::IllegalTag,
    };

    // A wholly-literal run is just a component (or a tag), and gets the full grammar.
    if let [GlobPiece::Literal(only)] = pieces {
        return match field {
            GlobField::PathSegment => validate_path_component(only),
            GlobField::Tag => validate_tag_literal(only).map_err(|()| illegal()),
        };
    }

    let edge_is_legal = |literal: &str, leading: bool| {
        let edge = if leading {
            literal.chars().next()
        } else {
            literal.chars().next_back()
        };
        match (field, leading) {
            (GlobField::PathSegment, _) => {
                edge.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            }
            (GlobField::Tag, true) => edge.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'),
            // A tag may end in `.` or `-` when something follows the run — `:v1.*` is a real
            // pattern, and the `.` is not a trailing character of the tag itself.
            (GlobField::Tag, false) => true,
        }
    };

    if let Some(GlobPiece::Literal(first)) = pieces.first()
        && !edge_is_legal(first, true)
    {
        return Err(illegal());
    }
    if let Some(GlobPiece::Literal(last)) = pieces.last()
        && !edge_is_legal(last, false)
    {
        return Err(illegal());
    }
    Ok(())
}

/// A wholly-literal tag: the same grammar [`crate::reference`] validates a reference's tag with,
/// restated here because that function is private to its own module and this one needs the
/// answer rather than the error type.
fn validate_tag_literal(tag: &str) -> Result<(), ()> {
    if tag.is_empty() || tag.len() > 128 {
        return Err(());
    }
    let mut chars = tag.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() || first == '_' => {}
        _ => return Err(()),
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) {
        Ok(())
    } else {
        Err(())
    }
}

/// Validate an accumulated literal run against its field's grammar and push it.
///
/// **A literal run is validated by the same function a whole component is**, so a pattern
/// cannot smuggle a character past the grammar by putting a `*` next to it — `dev-*` validates
/// `dev-`… which a whole-component check would reject for its trailing separator. Hence the
/// relaxed boundary rule here: a *run* may end in a separator (something follows it), while a
/// segment with no glob at all is still checked whole by the reference validator below.
fn flush(
    literal: &mut String,
    pieces: &mut Vec<GlobPiece>,
    field: GlobField,
) -> Result<(), ParseError> {
    if literal.is_empty() {
        return Ok(());
    }
    match field {
        GlobField::PathSegment => {
            if !literal.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
            }) {
                return Err(ParseError::IllegalPathComponent);
            }
        }
        GlobField::Tag => {
            if !literal
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                return Err(ParseError::IllegalTag);
            }
        }
    }
    pieces.push(GlobPiece::Literal(std::mem::take(literal)));
    Ok(())
}

/// Match a path pattern against a reference's segments, with `**` consuming one or more.
///
/// Iterative with a single backtrack point per `**`, which is the standard two-pointer wildcard
/// algorithm: worst case is O(segments × pattern), never exponential. RFC 0005's *Security
/// considerations* makes that a requirement rather than a preference — a backtracking glob
/// engine in a `failurePolicy: Fail` admission path is a denial of service against the whole
/// cluster's pod creation, delivered as a long image name.
fn matches_path(
    pattern: &[PathSegment],
    reference: &ImageReference,
    variables: &VariableValues,
) -> bool {
    let input: Vec<&str> = reference.path_components().collect();
    let (mut p, mut i) = (0usize, 0usize);
    // Where to resume if the current `**` turns out to have consumed too few segments.
    let mut star_pattern: Option<usize> = None;
    let mut star_input = 0usize;

    while i < input.len() {
        match pattern.get(p) {
            Some(PathSegment::DoubleStar) => {
                // `**` is one-or-more, so it commits to the current segment immediately and
                // records where to extend from.
                star_pattern = Some(p);
                p += 1;
                i += 1;
                star_input = i;
            }
            Some(PathSegment::Glob(pieces)) if matches_segment(pieces, input[i], variables) => {
                p += 1;
                i += 1;
            }
            _ => match star_pattern {
                Some(star) => {
                    // Extend the last `**` by one segment and retry everything after it.
                    p = star + 1;
                    star_input += 1;
                    i = star_input;
                }
                None => return false,
            },
        }
    }
    // Trailing `**` needs at least one segment, which the loop above already consumed — so any
    // pattern segment left over is a segment the reference does not have.
    p == pattern.len()
}

/// One segment. No special case for a wholly-literal run: [`validate_boundaries`] already
/// refused a segment that could never match, so the general matcher is correct for both — and
/// one code path is one thing to get right rather than two that can disagree.
fn matches_segment(pieces: &[GlobPiece], segment: &str, variables: &VariableValues) -> bool {
    matches_glob(pieces, segment, variables)
}

/// Two-pointer glob match over one segment or one tag. Same complexity argument as
/// [`matches_path`]: one backtrack point, no recursion.
fn matches_glob(pieces: &[GlobPiece], input: &str, variables: &VariableValues) -> bool {
    // Resolve variables to their literal values first, so the matcher below sees only literals
    // and stars. This is the *typed* substitution: a `PathComponent` cannot carry a `*`, a `/`
    // or a brace, so the resolved literal can never introduce a metacharacter.
    let mut resolved: Vec<GlobPiece> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        match piece {
            GlobPiece::Var(name) => match variables.get(name) {
                Some(value) => resolved.push(GlobPiece::Literal(value.as_str().to_string())),
                None => return false,
            },
            other => resolved.push(other.clone()),
        }
    }

    let bytes = input.as_bytes();
    let (mut p, mut i) = (0usize, 0usize);
    let mut star_pattern: Option<usize> = None;
    let mut star_input = 0usize;

    while i < bytes.len() {
        match resolved.get(p) {
            Some(GlobPiece::Literal(literal)) if input[i..].starts_with(literal.as_str()) => {
                p += 1;
                i += literal.len();
            }
            Some(GlobPiece::Star) => {
                star_pattern = Some(p);
                star_input = i;
                p += 1;
            }
            _ => match star_pattern {
                Some(star) => {
                    p = star + 1;
                    star_input += 1;
                    i = star_input;
                }
                None => return false,
            },
        }
    }
    // A trailing `*` matches the empty remainder.
    while matches!(resolved.get(p), Some(GlobPiece::Star)) {
        p += 1;
    }
    p == resolved.len()
}

fn render_pieces(pieces: &[GlobPiece], variables: &VariableValues, join: &str) -> Option<String> {
    let mut out = Vec::with_capacity(pieces.len());
    for piece in pieces {
        out.push(match piece {
            GlobPiece::Literal(literal) => literal.clone(),
            GlobPiece::Star => "*".to_string(),
            GlobPiece::Var(name) => variables.get(name)?.as_str().to_string(),
        });
    }
    Some(out.join(join))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::variable::{NAMESPACE, PathComponent, TEAM_NAME};

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pattern(raw: &str) -> Pattern {
        Pattern::parse(raw).unwrap_or_else(|err| panic!("{raw:?} should parse: {err}"))
    }

    fn reference(raw: &str) -> ImageReference {
        ImageReference::parse(raw).unwrap_or_else(|err| panic!("{raw:?} should parse: {err}"))
    }

    fn no_vars() -> VariableValues {
        VariableValues::new()
    }

    fn vars(pairs: &[(&str, &str)]) -> VariableValues {
        VariableValues::from_pairs(pairs.iter().map(|(name, value)| {
            (
                VariableName::new(*name).unwrap_or_else(|err| panic!("{err}")),
                PathComponent::new(value).unwrap_or_else(|err| panic!("{value:?}: {err}")),
            )
        }))
    }

    fn matches(raw_pattern: &str, raw_reference: &str, variables: &VariableValues) -> bool {
        pattern(raw_pattern).matches(&reference(raw_reference), variables)
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        assert!(matches(
            "registry.internal/shared/base",
            "registry.internal/shared/base",
            &no_vars()
        ));
        assert!(!matches(
            "registry.internal/shared/base",
            "registry.internal/shared/other",
            &no_vars()
        ));
    }

    #[test]
    fn a_star_matches_within_one_segment_and_a_double_star_matches_whole_segments() {
        // The RFC's own example: `library/*` matches `library/nginx`, not `library/a/b`; `**`
        // matches both.
        assert!(matches("docker.io/library/*", "nginx", &no_vars()));
        assert!(!matches(
            "docker.io/library/*",
            "docker.io/library/a/b",
            &no_vars()
        ));
        assert!(matches("docker.io/library/**", "nginx", &no_vars()));
        assert!(matches(
            "docker.io/library/**",
            "docker.io/library/a/b",
            &no_vars()
        ));
    }

    #[test]
    fn a_double_star_matches_one_or_more_segments_never_zero() {
        assert!(matches(
            "registry.internal/shared/**",
            "registry.internal/shared/base",
            &no_vars()
        ));
        assert!(matches(
            "registry.internal/shared/**",
            "registry.internal/shared/a/b/c",
            &no_vars()
        ));
        // `shared` itself is a repository the admin did not name.
        assert!(!matches(
            "registry.internal/shared/**",
            "registry.internal/shared",
            &no_vars()
        ));
    }

    #[test]
    fn a_star_inside_a_segment_matches_a_prefix_run() {
        assert!(matches(
            "registry.internal/teams/team-1/dev-*",
            "registry.internal/teams/team-1/dev-java",
            &no_vars()
        ));
        assert!(!matches(
            "registry.internal/teams/team-1/dev-*",
            "registry.internal/teams/team-1/prod-java",
            &no_vars()
        ));
    }

    #[test]
    fn the_host_is_matched_as_a_host_not_as_a_string_prefix() {
        // The flat-glob failure RFC 0005's *Alternatives* names: `registry.internal.evil.com`
        // must not match a pattern anchored at `registry.internal`.
        assert!(!matches(
            "registry.internal/**",
            "registry.internal.evil.com/x/y",
            &no_vars()
        ));
        // ...and a case-different host must, because hosts are case-insensitive.
        assert!(matches(
            "registry.internal/**",
            "REGISTRY.INTERNAL/x",
            &no_vars()
        ));
    }

    #[test]
    fn a_bare_star_host_is_rejected_because_any_registry_is_not_an_allow_list() {
        assert_eq!(Pattern::parse("*/**"), Err(ParseError::IllegalHost));
        assert_eq!(Pattern::parse("*"), Err(ParseError::IllegalHost));
    }

    #[test]
    fn a_suffix_host_needs_at_least_one_label_before_the_suffix() {
        assert!(matches("*.internal/**", "registry.internal/x", &no_vars()));
        assert!(matches("*.internal/**", "a.b.internal/x", &no_vars()));
        assert!(!matches("*.internal/**", "internal/x", &no_vars()));
        assert!(!matches("*.internal/**", "registry.external/x", &no_vars()));
    }

    #[test]
    fn a_suffix_host_does_not_ignore_a_port() {
        assert!(!matches(
            "*.internal/**",
            "registry.internal:5000/x",
            &no_vars()
        ));
    }

    #[test]
    fn a_port_in_the_pattern_must_match_the_port_in_the_reference() {
        assert!(matches(
            "localhost:5000/**",
            "localhost:5000/dev",
            &no_vars()
        ));
        assert!(!matches(
            "localhost:5000/**",
            "localhost:5001/dev",
            &no_vars()
        ));
        assert!(!matches("localhost:5000/**", "localhost/dev", &no_vars()));
        assert!(!matches("localhost/**", "localhost:5000/dev", &no_vars()));
    }

    #[test]
    fn a_pattern_with_no_tag_constraint_matches_any_tag_or_a_digest() {
        assert!(matches(
            "registry.internal/**",
            "registry.internal/x:v1",
            &no_vars()
        ));
        assert!(matches(
            "registry.internal/**",
            &format!("registry.internal/x@{DIGEST}"),
            &no_vars()
        ));
    }

    #[test]
    fn a_pattern_with_a_tag_constraint_matches_only_a_matching_tag() {
        let p = "quay.io/devfile/universal-developer-image:ubi9-*";
        assert!(matches(
            p,
            "quay.io/devfile/universal-developer-image:ubi9-latest",
            &no_vars()
        ));
        assert!(!matches(
            p,
            "quay.io/devfile/universal-developer-image:ubi8-latest",
            &no_vars()
        ));
    }

    #[test]
    fn a_digested_reference_matches_only_tag_agnostic_patterns() {
        // "A reference carrying a digest runs that digest whatever its tag says" — so a tag
        // constraint must not be satisfied by the decoration next to the digest.
        let digested = format!("registry.internal/x:v1@{DIGEST}");
        assert!(!matches("registry.internal/x:v1", &digested, &no_vars()));
        assert!(matches("registry.internal/x", &digested, &no_vars()));
    }

    #[test]
    fn a_pattern_may_not_carry_a_digest() {
        assert_eq!(
            Pattern::parse(&format!("registry.internal/x@{DIGEST}")),
            Err(ParseError::IllegalDigest)
        );
    }

    #[test]
    fn team_name_interpolates_per_namespace_and_denies_across_teams() {
        // The RFC's own `images audit` row: a team-1 namespace running team-3's image.
        let p = "registry.internal/teams/{TEAM_NAME}/**";
        let team1 = vars(&[(TEAM_NAME, "team-1")]);
        assert!(matches(
            p,
            "registry.internal/teams/team-1/dev-java:21",
            &team1
        ));
        assert!(!matches(
            p,
            "registry.internal/teams/team-3/dev-go:1.24",
            &team1
        ));
    }

    #[test]
    fn an_undefined_variable_matches_nothing_rather_than_collapsing_the_segment() {
        // The single most damaging way this could be implemented: treating `{TEAM_NAME}` as an
        // empty segment would turn this pattern into `registry.internal/teams/**` and hand
        // every namespace with no team every team's images.
        let p = "registry.internal/teams/{TEAM_NAME}/**";
        assert!(!matches(
            p,
            "registry.internal/teams/team-1/dev",
            &no_vars()
        ));
        assert!(!matches(p, "registry.internal/teams/dev", &no_vars()));
        assert!(!matches(
            p,
            "registry.internal/teams/anything/at/all",
            &no_vars()
        ));
    }

    #[test]
    fn a_declared_variable_interpolates_in_a_path_segment() {
        let p = "registry.internal/projects/{PROJECT}/**";
        assert!(matches(
            p,
            "registry.internal/projects/apollo/api:v1",
            &vars(&[("PROJECT", "apollo")])
        ));
        assert!(!matches(
            p,
            "registry.internal/projects/other/api:v1",
            &vars(&[("PROJECT", "apollo")])
        ));
    }

    #[test]
    fn a_variable_value_can_never_introduce_a_metacharacter() {
        // `PathComponent` refuses `a/**` at construction, so this is the *matcher's* half of the
        // same guarantee: even a value that somehow reached here is compared as one literal
        // label, never re-parsed as pattern syntax.
        let p = "registry.internal/teams/{TEAM_NAME}/**";
        let team = vars(&[(TEAM_NAME, "team-1")]);
        assert!(!matches(p, "registry.internal/teams/team-1x/dev", &team));
        assert!(!matches(p, "registry.internal/teams/xteam-1/dev", &team));
    }

    #[test]
    fn namespace_interpolates_in_a_path_but_is_rejected_in_a_host() {
        assert!(matches(
            "registry.internal/{NAMESPACE}/**",
            "registry.internal/user-alice/dev",
            &vars(&[(NAMESPACE, "user-alice")])
        ));
        assert_eq!(
            Pattern::parse("{NAMESPACE}.registry.internal/**"),
            Err(ParseError::IllegalHost)
        );
    }

    #[test]
    fn team_name_is_the_only_variable_permitted_in_a_host() {
        assert!(Pattern::parse("{TEAM_NAME}.registry.internal/**").is_ok());
        assert_eq!(
            Pattern::parse("{PROJECT}.registry.internal/**"),
            Err(ParseError::IllegalHost)
        );
    }

    #[test]
    fn a_team_name_host_label_matches_the_whole_label_only() {
        let p = "{TEAM_NAME}.registry.internal/**";
        let team = vars(&[(TEAM_NAME, "team-1")]);
        assert!(matches(p, "team-1.registry.internal/x", &team));
        assert!(!matches(p, "team-1x.registry.internal/x", &team));
        assert!(!matches(p, "registry.internal/x", &team));
    }

    #[test]
    fn a_variable_interpolates_in_a_tag() {
        assert!(matches(
            "registry.internal/base:{TEAM_NAME}-*",
            "registry.internal/base:team-1-2026",
            &vars(&[(TEAM_NAME, "team-1")])
        ));
    }

    #[test]
    fn variables_lists_every_name_once_in_first_seen_order() {
        let p = pattern("{TEAM_NAME}.registry.internal/{PROJECT}/{TEAM_NAME}/**:{PROJECT}-*");
        let names: Vec<&str> = p.variables().iter().map(|n| n.as_str()).collect();
        assert_eq!(names, vec![TEAM_NAME, "PROJECT"]);
    }

    #[test]
    fn interpolates_team_name_reports_the_host_and_the_path_alike() {
        assert!(pattern("registry.internal/teams/{TEAM_NAME}/**").interpolates_team_name());
        assert!(pattern("{TEAM_NAME}.registry.internal/**").interpolates_team_name());
        assert!(!pattern("registry.internal/shared/**").interpolates_team_name());
        assert!(!pattern("registry.internal/{NAMESPACE}/**").interpolates_team_name());
    }

    #[test]
    fn interpolated_prints_what_a_pattern_became_or_nothing_when_undefined() {
        let p = pattern("registry.internal/teams/{TEAM_NAME}/**");
        assert_eq!(
            p.interpolated(&vars(&[(TEAM_NAME, "team-1")])).as_deref(),
            Some("registry.internal/teams/team-1/**")
        );
        assert_eq!(p.interpolated(&no_vars()), None);
    }

    #[test]
    fn malformed_patterns_are_rejected() {
        let rejected: &[&str] = &[
            "",
            "registry.internal/",
            "/x",
            "registry.internal/x:",
            "registry.internal/{}/x",
            "registry.internal/{lowercase}/x",
            "registry.internal/{UNCLOSED/x",
            "registry.internal/CLOSED}/x",
            // `**` inside a segment is indistinguishable from `*`; the whole-segment form is
            // almost certainly what was meant, so this is a typo worth reporting.
            "registry.internal/a**b/x",
            "registry.internal/-dev",
            "registry.internal/DEV",
            "registry..internal/x",
            "-registry.internal/x",
            "registry.internal:notaport/x",
        ];
        for raw in rejected {
            assert!(
                Pattern::parse(raw).is_err(),
                "{raw:?} must not parse — an unparseable pattern grants nothing, and a lenient \
                 parser matches more than the admin meant"
            );
        }
    }

    #[test]
    fn an_over_long_pattern_is_capped() {
        let long = format!("registry.internal/{}", "a".repeat(MAX_REFERENCE_LEN));
        assert_eq!(Pattern::parse(&long), Err(ParseError::TooLong));
    }

    #[test]
    fn a_pattern_never_matches_a_reference_whose_normalized_host_differs() {
        // The property test RFC 0005's *Implementation plan* asks for, run over the cross
        // product of the catalogue-shaped patterns and references this suite already uses.
        let patterns = [
            "registry.internal/**",
            "docker.io/library/**",
            "quay.io/devfile/**",
            "*.internal/**",
            "localhost:5000/**",
            "{TEAM_NAME}.registry.internal/**",
        ];
        let references = [
            "registry.internal/shared/base:1",
            "nginx",
            "quay.io/devfile/udi:ubi9-latest",
            "ghcr.io/someone/scratch:main",
            "localhost:5000/dev",
            "team-1.registry.internal/x",
            "registry.internal.evil.com/x/y",
        ];
        let team = vars(&[(TEAM_NAME, "team-1")]);
        for raw_pattern in patterns {
            let p = pattern(raw_pattern);
            for raw_reference in references {
                let r = reference(raw_reference);
                if !p.matches(&r, &team) {
                    continue;
                }
                let host_matches = p.matches_host(r.host(), &team);
                assert!(
                    host_matches,
                    "{raw_pattern:?} matched {raw_reference:?} without its host matching"
                );
            }
        }
    }

    #[test]
    fn matching_is_linear_enough_that_a_pathological_input_returns_promptly() {
        // Not a timing assertion — a structural one: the two-pointer matchers below have a
        // single backtrack point, so the classic `a*a*a*...` blowup has no exponential path to
        // take. If this ever hangs, the matcher grew recursion.
        let p = pattern("registry.internal/**/**/**/**/**/*a*a*a*a*a*");
        let long = format!("registry.internal/{}", "a/".repeat(40) + &"a".repeat(80));
        let r = reference(&long);
        let _ = p.matches(&r, &no_vars());
    }
}
