//! What an endpoint's access rules *are*, already compiled.
//!
//! An [`EndpointPolicy`] is the whole input to a decision: the owner, the team, the profile the
//! catalogue and the team's grant resolved to, the names the developer delegated to, and the
//! ordered path rules. It is built once on an informer event by [`crate::compile`] and read by
//! every request that follows, which is the difference RFC 0009's *Request cost* is about —
//! sixteen rules of YAML parsed once per annotation change rather than once per asset.
//!
//! Everything here is immutable and cheap to share. Nothing here reads a clock, a header or a
//! cluster.

use std::collections::BTreeSet;
use std::fmt;

use crate::identity::{GroupName, NamespaceName, TeamName, Username};

/// A catalogue key — `private`, `team`, `shared`, `open`. Admin vocabulary: a developer names one
/// and may never define one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogueKey(String);

impl CatalogueKey {
    /// Wrap a key read from the configuration or from an annotation.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The key as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CatalogueKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who, besides the owner, a profile may let in.
///
/// A list rather than a mode, per RFC 0009: `[]` says "the owner and nobody else" where a `false`
/// would have been YAML 1.1's problem and a reader's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Delegation {
    /// Everyone in the owner's team — derived from namespace ownership, never from a list
    /// somebody maintains.
    Team,
    /// Whoever the owner named in `allow-users` / `allow-groups`.
    UsersAndGroups,
}

/// What happens to an `Authorization` header this cluster did not mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerMode {
    /// Refused. The default, and the reason `curl -H 'Authorization: Bearer x'` is not a
    /// one-header bypass of the whole feature.
    Reject,
    /// Handed to the application untouched, on the paths where the application genuinely
    /// authenticates its own tokens.
    Passthrough,
}

/// A catalogue entry, resolved: what one key means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessProfile {
    /// The key this profile came from — the `access` annotation's value, and the thing a log
    /// line names.
    pub key: CatalogueKey,
    /// No authentication at all. `open` is the only profile where a request with no credential
    /// is allowed, and a catalogue entry may not combine it with `delegation`.
    pub anonymous: bool,
    /// Who else, besides the owner, may reach the endpoint.
    pub delegation: BTreeSet<Delegation>,
}

impl AccessProfile {
    /// The closed profile: the owner, and nobody else.
    pub fn private() -> Self {
        Self {
            key: CatalogueKey::new("private"),
            anonymous: false,
            delegation: BTreeSet::new(),
        }
    }

    /// Whether this profile lets the named kind of caller in at all.
    pub fn delegates(&self, kind: Delegation) -> bool {
        self.delegation.contains(&kind)
    }
}

/// An HTTP method, as a closed set.
///
/// Closed because it is a metric's neighbour and a rule's matcher: formatting whatever arrived
/// would let a caller invent methods, and matching on an unknown one must be a decision rather
/// than a string comparison that happens to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `OPTIONS`.
    Options,
    /// `CONNECT`.
    Connect,
    /// `TRACE`.
    Trace,
    /// Anything else, including an extension method an application defines. One variant rather
    /// than a string: a rule may not name it, so it can only ever fall to the endpoint default.
    Other,
}

impl Method {
    /// Parse the method the controller stated in `X-Forwarded-Method`.
    ///
    /// Case-sensitive, because HTTP methods are: a gate that accepted `get` would accept a method
    /// no origin server routes, and answer for a request that will be handled differently.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            _ => Self::Other,
        }
    }

    fn bit(self) -> u16 {
        1 << (self as u16)
    }
}

/// The methods a rule applies to.
///
/// A bitset rather than a `Vec<Method>` for the reason the whole module exists: this is read on
/// every request, and a set membership test should not be a linear walk over a heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MethodSet(u16);

impl MethodSet {
    /// Every method — what a rule with no `methods` list means.
    pub const ANY: Self = Self(u16::MAX);

    /// A set holding exactly the listed methods.
    pub fn of(methods: impl IntoIterator<Item = Method>) -> Self {
        Self(methods.into_iter().fold(0, |acc, m| acc | m.bit()))
    }

    /// Whether `method` is in this set.
    pub fn contains(self, method: Method) -> bool {
        self.0 & method.bit() != 0
    }

    /// Whether this set is empty — a rule that could never match, which [`crate::compile`]
    /// refuses rather than indexes.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// How a rule's `path` is compared to a request's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// The whole path, trailing slash ignored.
    Exact,
    /// A prefix, matched on segment boundaries: `/actuator/` matches `/actuator/env` and
    /// `/actuator`, and never `/actuatorial`.
    Prefix,
}

/// One entry of the developer's ordered rule list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRule {
    /// The path, normalised at compile time so that a rule and a request are compared in the
    /// same alphabet.
    pub path: String,
    /// Exact or prefix.
    pub kind: MatchKind,
    /// Which methods this rule answers for.
    pub methods: MethodSet,
    /// The profile this path resolves to — a catalogue key the team was granted.
    pub profile: AccessProfile,
    /// A per-rule override of the endpoint's bearer mode. `None` means "whatever the endpoint
    /// says", which is how `bearer: Passthrough` stays scoped to the paths that asked for it.
    pub bearer: Option<BearerMode>,
}

impl PathRule {
    /// Whether this rule answers for `path` and `method`.
    pub fn matches(&self, path: &str, method: Method) -> bool {
        self.methods.contains(method) && self.matches_path(path)
    }

    fn matches_path(&self, path: &str) -> bool {
        let rule = self.path.strip_suffix('/').unwrap_or(&self.path);
        let candidate = path.strip_suffix('/').unwrap_or(path);
        match self.kind {
            MatchKind::Exact => rule == candidate,
            MatchKind::Prefix => {
                if rule.is_empty() {
                    return true;
                }
                candidate == rule
                    || candidate
                        .strip_prefix(rule)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
        }
    }
}

/// Where a `ReverseProxy` dialect's traffic actually goes, recorded by the operator in
/// `hardening.weebo.io/upstream` when it repointed the route at the gateway.
///
/// `None` on every forward-auth dialect, and that asymmetry is the whole difference between the
/// two modes: with no upstream there is nothing to carry, and the gate answers a question
/// instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    /// The `Service` in the endpoint's own namespace.
    pub service: String,
    /// The port on it.
    pub port: u16,
}

impl Upstream {
    /// Parse the `<service>:<port>` the operator recorded.
    pub fn parse(raw: &str) -> Option<Self> {
        let (service, port) = raw.trim().rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        if service.is_empty() || port == 0 {
            return None;
        }
        Some(Self {
            service: service.to_owned(),
            port,
        })
    }

    /// The in-cluster URL of this backend, in `namespace`.
    pub fn url(&self, namespace: &str) -> String {
        format!("http://{}.{}.svc:{}", self.service, namespace, self.port)
    }
}

/// Where an indexed routing object came from, which decides how much of it is frozen and which
/// of the two write paths a verdict came from — the log line RFC 0009 promises a developer who
/// shared an endpoint on Friday and restarted on Monday.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Generated by DevWorkspace Operator from a devfile.
    Devfile,
    /// Written by the developer themselves.
    Author,
}

/// One endpoint's access rules, compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPolicy {
    /// The namespace the routing object lives in. The owner check compares against *this*, not
    /// against anything in the host: a host names a user by convention, a namespace names one by
    /// annotation, and only one of those is written by the platform.
    pub namespace: NamespaceName,
    /// The namespace's owner.
    pub owner: Username,
    /// The owner's team, or `None` for a namespace in no team.
    pub team: Option<TeamName>,
    /// The profile every request falls to when no rule matches.
    pub profile: AccessProfile,
    /// Names the owner delegated to.
    pub allow_users: BTreeSet<Username>,
    /// Groups the owner delegated to.
    pub allow_groups: BTreeSet<GroupName>,
    /// What happens to a foreign `Authorization` header, unless a rule overrides it.
    pub bearer: BearerMode,
    /// The ordered rule list. First match wins.
    pub rules: Vec<PathRule>,
    /// Devfile projection, or the developer's own object.
    pub provenance: Provenance,
    /// Where the traffic goes on a `ReverseProxy` dialect. `None` everywhere else.
    pub upstream: Option<Upstream>,
    /// The index generation this policy was compiled into — carried so a cached anything can be
    /// checked against the policy it was computed under, and so a log line can say which
    /// revision answered.
    pub generation: u64,
}

/// The profile one request resolved to, and which rule produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected<'a> {
    /// The index of the matching rule, or `None` for the endpoint default.
    pub rule: Option<usize>,
    /// The profile that applies.
    pub profile: &'a AccessProfile,
    /// The bearer mode that applies.
    pub bearer: BearerMode,
}

impl EndpointPolicy {
    /// The profile that applies to `path` and `method`.
    ///
    /// First match wins, in the order written. A request matching no rule falls to the endpoint's
    /// own profile, which is why a missing final catch-all is not a hole.
    pub fn select(&self, path: &str, method: Method) -> Selected<'_> {
        for (index, rule) in self.rules.iter().enumerate() {
            if rule.matches(path, method) {
                return Selected {
                    rule: Some(index),
                    profile: &rule.profile,
                    bearer: rule.bearer.unwrap_or(self.bearer),
                };
            }
        }
        Selected {
            rule: None,
            profile: &self.profile,
            bearer: self.bearer,
        }
    }

    /// Whether `username` is the owner of the namespace this endpoint lives in.
    pub fn is_owner(&self, username: &Username) -> bool {
        &self.owner == username
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

    fn rule(path: &str, kind: MatchKind, key: &str) -> PathRule {
        PathRule {
            path: path.to_owned(),
            kind,
            methods: MethodSet::ANY,
            profile: AccessProfile {
                key: CatalogueKey::new(key),
                anonymous: key == "open",
                delegation: BTreeSet::new(),
            },
            bearer: None,
        }
    }

    fn policy(rules: Vec<PathRule>) -> EndpointPolicy {
        EndpointPolicy {
            namespace: NamespaceName::new("user-alice"),
            owner: Username::new("alice"),
            team: None,
            profile: AccessProfile::private(),
            allow_users: BTreeSet::new(),
            allow_groups: BTreeSet::new(),
            bearer: BearerMode::Reject,
            rules,
            provenance: Provenance::Devfile,
            upstream: None,
            generation: 1,
        }
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn an_upstream_is_parsed_from_what_the_operator_recorded_and_refuses_nonsense() {
        let upstream = Upstream::parse("my-app:8080").unwrap();
        assert_eq!(
            upstream.url("user-alice"),
            "http://my-app.user-alice.svc:8080"
        );
        for raw in [
            "my-app",
            "my-app:0",
            ":8080",
            "my-app:not-a-port",
            "my-app:70000",
        ] {
            assert_eq!(Upstream::parse(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn a_prefix_rule_matches_on_segment_boundaries_only() {
        let p = policy(vec![rule("/actuator/", MatchKind::Prefix, "private")]);
        for path in ["/actuator", "/actuator/", "/actuator/env"] {
            assert_eq!(p.select(path, Method::Get).rule, Some(0), "{path:?}");
        }
        // The bug this project would otherwise ship: `/actuatorial` is a different resource.
        assert_eq!(p.select("/actuatorial", Method::Get).rule, None);
    }

    #[test]
    fn a_trailing_slash_never_changes_the_verdict() {
        let p = policy(vec![rule("/healthz", MatchKind::Exact, "open")]);
        assert_eq!(p.select("/healthz", Method::Get).rule, Some(0));
        assert_eq!(p.select("/healthz/", Method::Get).rule, Some(0));
    }

    #[test]
    fn first_match_wins_in_the_order_written() {
        let p = policy(vec![
            rule("/actuator/", MatchKind::Prefix, "private"),
            rule("/", MatchKind::Prefix, "shared"),
        ]);
        assert_eq!(
            p.select("/actuator/env", Method::Get).profile.key,
            CatalogueKey::new("private")
        );
        assert_eq!(
            p.select("/api/items", Method::Get).profile.key,
            CatalogueKey::new("shared")
        );
    }

    #[test]
    fn a_request_matching_no_rule_falls_to_the_endpoint_profile() {
        let p = policy(vec![rule("/healthz", MatchKind::Exact, "open")]);
        let selected = p.select("/api/items", Method::Get);
        assert_eq!(selected.rule, None);
        assert_eq!(selected.profile.key, CatalogueKey::new("private"));
    }

    #[test]
    fn methods_narrow_a_rule_without_narrowing_the_endpoint() {
        let mut webhook = rule("/api/webhooks/", MatchKind::Prefix, "open");
        webhook.methods = MethodSet::of([Method::Post]);
        let p = policy(vec![webhook]);
        assert_eq!(p.select("/api/webhooks/stripe", Method::Post).rule, Some(0));
        // A GET on the webhook path is not the webhook: it falls through to the endpoint's own
        // profile, which is closed.
        assert_eq!(p.select("/api/webhooks/stripe", Method::Get).rule, None);
    }

    #[test]
    fn a_rule_may_widen_the_bearer_mode_only_where_it_matches() {
        let mut api = rule("/api/", MatchKind::Prefix, "private");
        api.bearer = Some(BearerMode::Passthrough);
        let p = policy(vec![api]);
        assert_eq!(
            p.select("/api/items", Method::Get).bearer,
            BearerMode::Passthrough
        );
        assert_eq!(p.select("/", Method::Get).bearer, BearerMode::Reject);
    }

    #[test]
    fn the_method_set_is_a_set_and_unknown_methods_are_one_value() {
        let set = MethodSet::of([Method::Get, Method::Post]);
        assert!(set.contains(Method::Get));
        assert!(!set.contains(Method::Delete));
        assert!(MethodSet::ANY.contains(Method::Other));
        assert_eq!(Method::parse("PROPFIND"), Method::Other);
        assert_eq!(Method::parse("get"), Method::Other);
    }
}
