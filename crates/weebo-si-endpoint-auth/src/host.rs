//! Hosts, and the suffix this feature governs.
//!
//! A host is the primary key of every decision — RFC 0009's *Which `Ingress` answers for a host*
//! calls resolving one to a policy a security boundary rather than a lookup — so it is a type
//! with one constructor that normalises, rather than a `String` every call site lowercases and
//! trims in its own way.

use std::collections::BTreeSet;
use std::fmt;

/// A request's `Host`, normalised: lowercase, no port, no trailing dot.
///
/// The normalisation is the point. `ALICE-WS-API.weebo.si:443`, `alice-ws-api.weebo.si.` and
/// `alice-ws-api.weebo.si` are one host to a browser and to an ingress controller; a gate that
/// treated them as three would answer for one and be bypassed through the other two.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Host(String);

/// Why a `Host` could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// Empty, or empty once the port and trailing dot were removed.
    Empty,
    /// Contains a character no hostname may carry — everything outside `[a-z0-9.-]` after
    /// lowercasing, which includes the `/`, `@` and whitespace a header-smuggling attempt uses.
    NotAHostname,
    /// Longer than the 253 characters DNS allows, so no real name and not worth indexing.
    TooLong,
}

/// The longest a DNS name may be, and therefore the longest a `Host` may be.
pub const MAX_HOST_LEN: usize = 253;

impl Host {
    /// Parse and normalise a `Host` header value.
    ///
    /// An IPv6 literal (`[::1]:8080`) is rejected rather than normalised: a workspace endpoint is
    /// always reached by name — the suffix is what this feature governs — and accepting an
    /// address here would only ever produce a host that matches no policy and denies. Failing to
    /// parse says the same thing, one step earlier and with a reason.
    pub fn parse(raw: &str) -> Result<Self, HostError> {
        let trimmed = raw.trim();
        let without_port = match trimmed.rsplit_once(':') {
            Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
                head
            }
            _ => trimmed,
        };
        let without_dot = without_port.strip_suffix('.').unwrap_or(without_port);
        if without_dot.is_empty() {
            return Err(HostError::Empty);
        }
        if without_dot.len() > MAX_HOST_LEN {
            return Err(HostError::TooLong);
        }
        let lowered = without_dot.to_ascii_lowercase();
        let usable = lowered
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !usable {
            return Err(HostError::NotAHostname);
        }
        Ok(Self(lowered))
    }

    /// The normalised host, for indexing and for a log line.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which hosts this feature governs: one suffix, minus the names an admin excluded.
///
/// Both halves are load-bearing. The suffix is what keeps the gate from answering for a host it
/// knows nothing about — a decision on an unknown host is a denial, and a denial on
/// `github.com` would mean the gate had been pointed at traffic that is none of its business.
/// The exclusions are where the Che gateway's own ingress and the gateway's own host are named,
/// rather than matched by a constant compiled into the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostScope {
    suffix: String,
    exclude: BTreeSet<Host>,
}

/// Why a [`HostScope`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// The suffix does not start with a dot, so `.weebo.si` was written `weebo.si` and
    /// `notweebo.si` would match it.
    SuffixNotDotted,
    /// The suffix is a single label (`.si`), which is a whole public suffix rather than a
    /// cluster's domain. Refused at configuration load, where it is one message, rather than
    /// discovered as a gate that answers for the internet.
    SuffixTooBroad,
    /// An excluded host did not parse.
    Exclusion(HostError),
}

impl HostScope {
    /// Build a scope from the configuration file's `hosts.suffix` and `hosts.exclude`.
    pub fn new<'a>(
        suffix: &str,
        exclude: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ScopeError> {
        let suffix = suffix.trim().to_ascii_lowercase();
        if !suffix.starts_with('.') {
            return Err(ScopeError::SuffixNotDotted);
        }
        if suffix.trim_start_matches('.').split('.').count() < 2 {
            return Err(ScopeError::SuffixTooBroad);
        }
        let exclude = exclude
            .into_iter()
            .map(|raw| Host::parse(raw).map_err(ScopeError::Exclusion))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self { suffix, exclude })
    }

    /// Whether this feature answers for `host` at all.
    pub fn governs(&self, host: &Host) -> bool {
        host.as_str().ends_with(&self.suffix) && !self.exclude.contains(host)
    }

    /// The governed suffix, for a message that has to name it.
    pub fn suffix(&self) -> &str {
        &self.suffix
    }
}

/// The client address an ingress controller reported, as a string.
///
/// Opaque on purpose: this crate never parses it, compares it numerically or reasons about
/// subnets. It hands it to [`crate::port::WorkloadIdentity`], whose implementation answers "which
/// namespace's pod is this" from a watch of pods, and whose conformance — per RFC 0009's
/// *Checking that assumption rather than configuring it* — is probed rather than assumed. A
/// domain that could compare addresses would eventually be asked to trust a CIDR.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientAddress(String);

impl ClientAddress {
    /// Wrap what the controller reported.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The address as the controller wrote it.
    pub fn as_str(&self) -> &str {
        &self.0
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

    #[test]
    fn one_host_has_one_normal_form() {
        let expected = Host::parse("alice-ws-api.weebo.si").unwrap();
        for raw in [
            "ALICE-WS-API.weebo.si",
            "alice-ws-api.weebo.si:443",
            "alice-ws-api.weebo.si.",
            "  alice-ws-api.WEEBO.si  ",
        ] {
            assert_eq!(Host::parse(raw).unwrap(), expected, "{raw:?}");
        }
    }

    #[test]
    fn a_host_header_carrying_a_path_or_a_space_does_not_parse() {
        // The shapes a request-smuggling attempt puts in a Host header. A gate that indexed them
        // would be indexing an attacker's string.
        for raw in [
            "alice-ws-api.weebo.si/../bob",
            "alice@weebo.si",
            "alice ws.weebo.si",
            "alice_ws.weebo.si",
        ] {
            assert_eq!(Host::parse(raw), Err(HostError::NotAHostname), "{raw:?}");
        }
    }

    #[test]
    fn a_bare_port_or_an_empty_name_does_not_parse() {
        assert_eq!(Host::parse(""), Err(HostError::Empty));
        assert_eq!(Host::parse(":443"), Err(HostError::Empty));
        assert_eq!(Host::parse("."), Err(HostError::Empty));
    }

    #[test]
    fn the_scope_is_a_suffix_and_not_a_substring() {
        let scope = HostScope::new(".weebo.si", ["che.weebo.si"]).unwrap();
        assert!(scope.governs(&Host::parse("alice-ws-api.weebo.si").unwrap()));
        // The whole reason the suffix must start with a dot.
        assert!(!scope.governs(&Host::parse("notweebo.si").unwrap()));
        assert!(!scope.governs(&Host::parse("weebo.si.evil.example").unwrap()));
    }

    #[test]
    fn an_excluded_host_is_not_governed_even_though_it_is_under_the_suffix() {
        let scope = HostScope::new(".weebo.si", ["che.weebo.si", "AUTH.weebo.si"]).unwrap();
        assert!(!scope.governs(&Host::parse("che.weebo.si").unwrap()));
        // Exclusions are normalised like any other host, or an admin's capital letter becomes a
        // gate in front of the login page it was written to keep out of the way.
        assert!(!scope.governs(&Host::parse("auth.weebo.si").unwrap()));
    }

    #[test]
    fn a_suffix_that_would_govern_a_public_suffix_is_refused_at_load() {
        assert_eq!(
            HostScope::new("weebo.si", []),
            Err(ScopeError::SuffixNotDotted)
        );
        assert_eq!(HostScope::new(".si", []), Err(ScopeError::SuffixTooBroad));
    }
}
