//! Compile at write time, not at read time.
//!
//! An endpoint's policy arrives as text — a catalogue key in one annotation, two comma-separated
//! name lists, and a small YAML document of ordered rules. Parsing that per request is the cost a
//! naive gate actually pays: sixteen rules of YAML per asset, times two hundred assets, times
//! every developer in the cluster, and invisible in a unit test. So it happens here, once, on the
//! informer event that changed the object, and what a request reads is the [`EndpointPolicy`]
//! this module produced.
//!
//! Compiling is also where the team's grant and the admin's override are intersected, which is
//! the one place in RFC 0009 where "an override may only narrow" is either true or a bug. It is a
//! set intersection with a test that says so, rather than an ordering of `if` statements.
//!
//! **A compile failure is a closed endpoint, not an open one.** The caller indexes
//! [`EndpointPolicy::closed`] and records the reason on the object; it never indexes nothing,
//! because "nothing" and "private" already deny identically and only one of them can explain
//! itself to the developer who wrote the annotation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;

use crate::identity::{GroupName, NamespaceName, TeamName, Username};
use crate::path::normalise;
use crate::policy::{
    AccessProfile, BearerMode, CatalogueKey, Delegation, EndpointPolicy, MatchKind, Method,
    MethodSet, PathRule, Provenance, Upstream,
};

/// The admin's catalogue: what each key means. Admin vocabulary, cluster-wide, and the only place
/// a profile is ever defined.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalogue {
    entries: BTreeMap<CatalogueKey, AccessProfile>,
}

impl Catalogue {
    /// Build a catalogue from `(key, anonymous, delegation)` triples.
    ///
    /// A key that is both `anonymous` and delegating is refused here rather than resolved later:
    /// "no authentication at all" and "these named people" are two different answers to the same
    /// question, and a profile that claims both has no meaning a developer could reason about.
    pub fn new(
        entries: impl IntoIterator<Item = (CatalogueKey, bool, BTreeSet<Delegation>)>,
    ) -> Result<Self, CompileError> {
        let mut map = BTreeMap::new();
        for (key, anonymous, delegation) in entries {
            if anonymous && !delegation.is_empty() {
                return Err(CompileError::AnonymousWithDelegation(key));
            }
            map.insert(
                key.clone(),
                AccessProfile {
                    key,
                    anonymous,
                    delegation,
                },
            );
        }
        Ok(Self { entries: map })
    }

    /// The profile a key names, if the catalogue defines one.
    pub fn profile(&self, key: &CatalogueKey) -> Option<&AccessProfile> {
        self.entries.get(key)
    }
}

/// What a team was granted: which keys its namespaces may reach, and which one they get by
/// default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The keys this team may name.
    pub allowed: BTreeSet<CatalogueKey>,
    /// The key an endpoint resolves to when it names none. Singular: an endpoint resolves to
    /// exactly one profile.
    pub default: CatalogueKey,
}

/// Which users an override applies to.
///
/// A `namespaceSelector` is resolved by the informer adapter into the set of namespaces it
/// currently matches, and arrives here as [`OverrideMatch::Namespaces`]. Label matching is an
/// adapter's job: doing it in the domain would mean evaluating a selector per request, which is
/// exactly the per-request work this module exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideMatch {
    /// Usernames, each either exact or a trailing-`*` prefix (`contractor-*`).
    Users(Vec<String>),
    /// Namespaces the selector matched.
    Namespaces(BTreeSet<NamespaceName>),
}

impl OverrideMatch {
    fn matches(&self, owner: &Username, namespace: &NamespaceName) -> bool {
        match self {
            Self::Users(patterns) => {
                patterns
                    .iter()
                    .any(|pattern| match pattern.strip_suffix('*') {
                        Some(prefix) => owner.as_str().starts_with(prefix),
                        None => pattern == owner.as_str(),
                    })
            }
            Self::Namespaces(namespaces) => namespaces.contains(namespace),
        }
    }
}

/// An admin's per-user narrowing — per-user what a grant is per-team.
///
/// Every field is an intersection, never a replacement. That is the whole contract: an override
/// can only ever be the reason somebody gets *less* than their team was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    /// Who it applies to.
    pub matcher: OverrideMatch,
    /// Keys this user may reach, intersected with the team's.
    pub allowed: Option<BTreeSet<CatalogueKey>>,
    /// A default of its own, which must survive the intersection like any other key.
    pub default: Option<CatalogueKey>,
    /// A delegation ceiling. `Some(empty)` is the hard form — this user may not share an endpoint
    /// at all, whichever catalogue key they reach.
    pub delegation: Option<BTreeSet<Delegation>>,
}

/// What the informer read off one routing object, before any of it means anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEndpoint {
    /// The namespace the object lives in.
    pub namespace: NamespaceName,
    /// The namespace's owner, from the annotation Che writes.
    pub owner: Username,
    /// The owner's team, resolved from `spec.teams` on the namespace event — never per request.
    pub team: Option<TeamName>,
    /// `hardening.weebo.io/access`.
    pub access: Option<String>,
    /// `hardening.weebo.io/allow-users`, comma-separated.
    pub allow_users: Option<String>,
    /// `hardening.weebo.io/allow-groups`, comma-separated.
    pub allow_groups: Option<String>,
    /// `hardening.weebo.io/rules`, YAML.
    pub rules: Option<String>,
    /// `hardening.weebo.io/upstream` — where a `ReverseProxy` dialect's traffic was going before
    /// the operator repointed the route at the gateway. Read, never written, here: the operator
    /// records it and the gateway carries the bytes to it.
    pub upstream: Option<String>,
    /// Devfile projection, or the developer's own object.
    pub provenance: Provenance,
}

/// What a cluster decides once, and every endpoint in it inherits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileSettings {
    /// What happens to an `Authorization` header this cluster did not mint, unless a rule says
    /// otherwise.
    pub foreign_bearer: BearerMode,
    /// `rules.max_per_endpoint`.
    pub max_rules: usize,
    /// What an `access` annotation naming a key the catalogue does not define resolves to.
    pub on_unknown_key: UnknownKey,
}

impl Default for CompileSettings {
    fn default() -> Self {
        Self {
            foreign_bearer: BearerMode::Reject,
            max_rules: 16,
            on_unknown_key: UnknownKey::Default,
        }
    }
}

/// RFC 0002's selection semantics for a key nobody defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownKey {
    /// Fall to the grant's default — a typo costs a developer their sharing, not their endpoint.
    Default,
    /// Refuse to compile, so the endpoint is closed and the reason is recorded.
    Deny,
}

/// Why an endpoint did not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// A catalogue entry claims both "no authentication" and a delegation list.
    AnonymousWithDelegation(CatalogueKey),
    /// The annotation names a key the catalogue does not define, under `onUnknownKey: Deny`.
    UnknownKey(CatalogueKey),
    /// The annotation names a key the team's grant — or the admin's override — does not allow.
    NotGranted(CatalogueKey),
    /// The grant's own default is not in its allowed set, or an override narrowed the allowed set
    /// to something the default is no longer in. A configuration bug, and a closed endpoint until
    /// it is fixed.
    DefaultNotAllowed(CatalogueKey),
    /// The rules annotation is not a YAML list of rules.
    UnparseableRules(String),
    /// More rules than `rules.max_per_endpoint`.
    TooManyRules {
        /// How many the annotation carried.
        found: usize,
        /// How many are allowed.
        max: usize,
    },
    /// A rule's path is not one the gate could ever match — it does not normalise to itself, so
    /// the rule would answer for a path no request has.
    RulePath(String),
    /// A rule listed a method this gate does not name. Refused rather than ignored: a rule that
    /// silently matches nothing is a rule a developer believes is protecting something.
    UnknownMethod(String),
    /// A rule listed an empty `methods`, which could never match.
    EmptyMethods(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnonymousWithDelegation(key) => {
                write!(f, "catalogue key {key} is anonymous and delegates")
            }
            Self::UnknownKey(key) => write!(f, "no catalogue entry named {key}"),
            Self::NotGranted(key) => write!(f, "{key} is not granted here"),
            Self::DefaultNotAllowed(key) => write!(f, "default {key} is not in the allowed set"),
            Self::UnparseableRules(why) => write!(f, "rules did not parse: {why}"),
            Self::TooManyRules { found, max } => write!(f, "{found} rules, at most {max} allowed"),
            Self::RulePath(path) => write!(f, "rule path {path:?} is not a normalised path"),
            Self::UnknownMethod(method) => write!(f, "unknown method {method:?}"),
            Self::EmptyMethods(path) => write!(f, "rule {path:?} lists no method"),
        }
    }
}

/// The wire shape of one entry of the `hardening.weebo.io/rules` annotation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRule {
    path: String,
    #[serde(default)]
    r#match: WireMatch,
    access: String,
    #[serde(default)]
    methods: Option<Vec<String>>,
    #[serde(default)]
    bearer: Option<WireBearer>,
}

#[derive(Debug, Default, Deserialize)]
enum WireMatch {
    #[serde(rename = "exact")]
    Exact,
    #[default]
    #[serde(rename = "prefix")]
    Prefix,
}

#[derive(Debug, Deserialize)]
enum WireBearer {
    Reject,
    Passthrough,
}

/// Compile one routing object into the policy a request will read.
pub fn compile(
    raw: &RawEndpoint,
    catalogue: &Catalogue,
    grant: &Grant,
    overrides: &[Override],
    settings: &CompileSettings,
    generation: u64,
) -> Result<EndpointPolicy, CompileError> {
    let applicable = overrides
        .iter()
        .find(|o| o.matcher.matches(&raw.owner, &raw.namespace));

    // An override may only narrow. Both halves of that are this intersection, and the test below
    // is the one that would catch a future refactor turning it into a replacement.
    let allowed: BTreeSet<CatalogueKey> = match applicable.and_then(|o| o.allowed.as_ref()) {
        Some(narrower) => grant.allowed.intersection(narrower).cloned().collect(),
        None => grant.allowed.clone(),
    };
    let default = applicable
        .and_then(|o| o.default.clone())
        .unwrap_or_else(|| grant.default.clone());
    if !allowed.contains(&default) {
        return Err(CompileError::DefaultNotAllowed(default));
    }
    let ceiling = applicable.and_then(|o| o.delegation.as_ref());

    let requested = raw
        .access
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(CatalogueKey::new);
    let key = match requested {
        Some(key) if catalogue.profile(&key).is_none() => match settings.on_unknown_key {
            UnknownKey::Default => default.clone(),
            UnknownKey::Deny => return Err(CompileError::UnknownKey(key)),
        },
        Some(key) => key,
        None => default.clone(),
    };
    let profile = resolve_profile(&key, catalogue, &allowed, ceiling)?;

    let rules = compile_rules(raw, catalogue, &allowed, ceiling, settings)?;

    Ok(EndpointPolicy {
        namespace: raw.namespace.clone(),
        owner: raw.owner.clone(),
        team: raw.team.clone(),
        profile,
        allow_users: split_names(raw.allow_users.as_deref())
            .map(Username::new)
            .collect(),
        allow_groups: split_names(raw.allow_groups.as_deref())
            .map(GroupName::new)
            .collect(),
        bearer: settings.foreign_bearer,
        rules,
        provenance: raw.provenance,
        upstream: raw.upstream.as_deref().and_then(Upstream::parse),
        generation,
    })
}

/// The profile a key resolves to here, with the admin's delegation ceiling already applied.
fn resolve_profile(
    key: &CatalogueKey,
    catalogue: &Catalogue,
    allowed: &BTreeSet<CatalogueKey>,
    ceiling: Option<&BTreeSet<Delegation>>,
) -> Result<AccessProfile, CompileError> {
    let profile = catalogue
        .profile(key)
        .ok_or_else(|| CompileError::UnknownKey(key.clone()))?;
    if !allowed.contains(key) {
        return Err(CompileError::NotGranted(key.clone()));
    }
    let delegation = match ceiling {
        Some(ceiling) => profile.delegation.intersection(ceiling).copied().collect(),
        None => profile.delegation.clone(),
    };
    Ok(AccessProfile {
        key: profile.key.clone(),
        anonymous: profile.anonymous,
        delegation,
    })
}

fn compile_rules(
    raw: &RawEndpoint,
    catalogue: &Catalogue,
    allowed: &BTreeSet<CatalogueKey>,
    ceiling: Option<&BTreeSet<Delegation>>,
    settings: &CompileSettings,
) -> Result<Vec<PathRule>, CompileError> {
    let Some(document) = raw
        .rules
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    else {
        return Ok(Vec::new());
    };
    let wire: Vec<WireRule> = serde_yaml_bw::from_str(document)
        .map_err(|error| CompileError::UnparseableRules(error.to_string()))?;
    if wire.len() > settings.max_rules {
        return Err(CompileError::TooManyRules {
            found: wire.len(),
            max: settings.max_rules,
        });
    }
    wire.into_iter()
        .map(|rule| compile_rule(rule, catalogue, allowed, ceiling))
        .collect()
}

fn compile_rule(
    wire: WireRule,
    catalogue: &Catalogue,
    allowed: &BTreeSet<CatalogueKey>,
    ceiling: Option<&BTreeSet<Delegation>>,
) -> Result<PathRule, CompileError> {
    // A rule's path is normalised here, against the same function a request's path goes through,
    // so that the two are compared in one alphabet. A path that does not survive — or that
    // normalises to something else — is refused rather than silently rewritten: `/actuator/../`
    // as a rule is a developer's mistake, and honouring it would protect a different path than
    // the one they read.
    let normalised =
        normalise(&wire.path).map_err(|_| CompileError::RulePath(wire.path.clone()))?;
    if normalised.as_str() != wire.path {
        return Err(CompileError::RulePath(wire.path));
    }
    let methods = match wire.methods {
        None => MethodSet::ANY,
        Some(listed) => {
            if listed.is_empty() {
                return Err(CompileError::EmptyMethods(wire.path.clone()));
            }
            let mut parsed = Vec::with_capacity(listed.len());
            for method in listed {
                match Method::parse(&method) {
                    Method::Other => return Err(CompileError::UnknownMethod(method)),
                    known => parsed.push(known),
                }
            }
            MethodSet::of(parsed)
        }
    };
    let key = CatalogueKey::new(wire.access);
    let profile = resolve_profile(&key, catalogue, allowed, ceiling)?;
    Ok(PathRule {
        path: normalised.as_str().to_owned(),
        kind: match wire.r#match {
            WireMatch::Exact => MatchKind::Exact,
            WireMatch::Prefix => MatchKind::Prefix,
        },
        methods,
        profile,
        bearer: wire.bearer.map(|mode| match mode {
            WireBearer::Reject => BearerMode::Reject,
            WireBearer::Passthrough => BearerMode::Passthrough,
        }),
    })
}

fn split_names(raw: Option<&str>) -> impl Iterator<Item = &str> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

impl EndpointPolicy {
    /// The policy an endpoint gets when compiling it failed: closed, owned by whoever owns the
    /// namespace, with no rules and no delegation.
    ///
    /// Failing closed is not the interesting part — an object left out of the index would deny
    /// too. Failing closed *with an owner and a generation* is: the endpoint still answers for its
    /// owner, so a developer who mistyped a rule can still reach their own application and read
    /// the Event explaining why their colleague cannot.
    pub fn closed(raw: &RawEndpoint, generation: u64) -> Self {
        Self {
            namespace: raw.namespace.clone(),
            owner: raw.owner.clone(),
            team: raw.team.clone(),
            profile: AccessProfile::private(),
            allow_users: BTreeSet::new(),
            allow_groups: BTreeSet::new(),
            bearer: BearerMode::Reject,
            rules: Vec::new(),
            provenance: raw.provenance,
            // Kept even on a policy that refused to compile: on a `ReverseProxy` dialect the
            // upstream is how the owner still reaches their own application, and dropping it
            // would turn a mistyped rule into an endpoint nobody can reach at all.
            upstream: raw.upstream.as_deref().and_then(Upstream::parse),
            generation,
        }
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
    use crate::policy::Method;
    use crate::testing::{catalogue, full_grant, raw_endpoint};

    fn keys(names: &[&str]) -> BTreeSet<CatalogueKey> {
        names.iter().map(|name| CatalogueKey::new(*name)).collect()
    }

    fn compile_with(
        raw: &RawEndpoint,
        grant: &Grant,
        overrides: &[Override],
    ) -> Result<EndpointPolicy, CompileError> {
        compile(
            raw,
            &catalogue(),
            grant,
            overrides,
            &CompileSettings::default(),
            3,
        )
    }

    #[test]
    fn an_endpoint_with_no_annotations_gets_its_teams_default() {
        let raw = raw_endpoint("user-alice", "alice");
        let policy = compile_with(&raw, &full_grant(), &[]).unwrap();
        assert_eq!(policy.profile.key, CatalogueKey::new("private"));
        assert!(policy.profile.delegation.is_empty());
        assert_eq!(policy.generation, 3);
    }

    #[test]
    fn the_team_default_is_what_makes_a_colleague_work_with_no_annotation_at_all() {
        let grant = Grant {
            allowed: keys(&["private", "team", "shared"]),
            default: CatalogueKey::new("team"),
        };
        let policy = compile_with(&raw_endpoint("user-alice", "alice"), &grant, &[]).unwrap();
        assert!(policy.profile.delegates(Delegation::Team));
    }

    #[test]
    fn names_are_split_and_trimmed_the_way_a_person_types_them() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared".into());
        raw.allow_users = Some(" bob , carol ,,".into());
        raw.allow_groups = Some("team-payments".into());
        let policy = compile_with(&raw, &full_grant(), &[]).unwrap();
        assert_eq!(
            policy.allow_users,
            BTreeSet::from([Username::new("bob"), Username::new("carol")])
        );
        assert_eq!(
            policy.allow_groups,
            BTreeSet::from([GroupName::new("team-payments")])
        );
    }

    #[test]
    fn a_key_the_team_was_not_granted_does_not_compile() {
        let grant = Grant {
            allowed: keys(&["private"]),
            default: CatalogueKey::new("private"),
        };
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("open".into());
        assert_eq!(
            compile_with(&raw, &grant, &[]),
            Err(CompileError::NotGranted(CatalogueKey::new("open")))
        );
    }

    #[test]
    fn an_unknown_key_falls_to_the_default_or_refuses_depending_on_the_setting() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared-with-everyone".into());
        let lenient = compile_with(&raw, &full_grant(), &[]).unwrap();
        assert_eq!(lenient.profile.key, CatalogueKey::new("private"));

        let strict = compile(
            &raw,
            &catalogue(),
            &full_grant(),
            &[],
            &CompileSettings {
                on_unknown_key: UnknownKey::Deny,
                ..CompileSettings::default()
            },
            1,
        );
        assert_eq!(
            strict,
            Err(CompileError::UnknownKey(CatalogueKey::new(
                "shared-with-everyone"
            )))
        );
    }

    #[test]
    fn an_override_narrows_and_can_never_widen() {
        // The team holds `private` only. An override generously offering `shared` must not be a
        // way to get more than the team was granted — the intersection is the whole contract.
        let grant = Grant {
            allowed: keys(&["private"]),
            default: CatalogueKey::new("private"),
        };
        let widening = Override {
            matcher: OverrideMatch::Users(vec!["alice".into()]),
            allowed: Some(keys(&["private", "shared", "open"])),
            default: None,
            delegation: None,
        };
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared".into());
        assert_eq!(
            compile_with(&raw, &grant, &[widening]),
            Err(CompileError::NotGranted(CatalogueKey::new("shared")))
        );
    }

    #[test]
    fn an_overrides_empty_delegation_is_the_hard_form() {
        // "This user may not share an endpoint at all, whichever catalogue key they reach."
        let narrowing = Override {
            matcher: OverrideMatch::Users(vec!["contractor-*".into()]),
            allowed: None,
            default: None,
            delegation: Some(BTreeSet::new()),
        };
        let mut raw = raw_endpoint("user-contractor-dan", "contractor-dan");
        raw.access = Some("shared".into());
        let policy = compile_with(&raw, &full_grant(), &[narrowing]).unwrap();
        assert_eq!(policy.profile.key, CatalogueKey::new("shared"));
        assert!(
            policy.profile.delegation.is_empty(),
            "the profile is still `shared`, and it delegates to nobody"
        );
    }

    #[test]
    fn an_override_matches_a_prefix_and_a_namespace_but_not_a_neighbour() {
        let by_prefix = Override {
            matcher: OverrideMatch::Users(vec!["contractor-*".into()]),
            allowed: Some(keys(&["private"])),
            default: Some(CatalogueKey::new("private")),
            delegation: None,
        };
        let mut raw = raw_endpoint("user-contractor-dan", "contractor-dan");
        raw.access = Some("shared".into());
        assert!(compile_with(&raw, &full_grant(), std::slice::from_ref(&by_prefix)).is_err());

        // A user whose name merely contains the prefix elsewhere is not matched.
        let mut other = raw_endpoint("user-erin", "erin-contractor-x");
        other.access = Some("shared".into());
        assert!(compile_with(&other, &full_grant(), &[by_prefix]).is_ok());

        let by_namespace = Override {
            matcher: OverrideMatch::Namespaces(BTreeSet::from([NamespaceName::new("user-erin")])),
            allowed: Some(keys(&["private"])),
            default: Some(CatalogueKey::new("private")),
            delegation: None,
        };
        let mut erin = raw_endpoint("user-erin", "erin");
        erin.access = Some("shared".into());
        assert!(compile_with(&erin, &full_grant(), &[by_namespace]).is_err());
    }

    #[test]
    fn a_default_the_allowed_set_no_longer_holds_is_a_configuration_bug_and_closes_the_endpoint() {
        let grant = Grant {
            allowed: keys(&["team"]),
            default: CatalogueKey::new("shared"),
        };
        assert_eq!(
            compile_with(&raw_endpoint("user-alice", "alice"), &grant, &[]),
            Err(CompileError::DefaultNotAllowed(CatalogueKey::new("shared")))
        );
    }

    #[test]
    fn the_rules_annotation_from_the_rfc_compiles_to_what_it_reads_like() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared".into());
        // Byte for byte the list in RFC 0009's *What the developer writes*.
        raw.rules = Some(
            [
                "- { path: /healthz,       match: exact,  access: open }",
                "- { path: /api/webhooks/, match: prefix, access: open, methods: [POST] }",
                "- { path: /actuator/,     match: prefix, access: private }",
                "- { path: /,              match: prefix, access: shared }",
            ]
            .join("\n"),
        );
        let policy = compile_with(&raw, &full_grant(), &[]).unwrap();
        assert_eq!(policy.rules.len(), 4);
        assert!(policy.select("/healthz", Method::Get).profile.anonymous);
        assert!(
            policy
                .select("/api/webhooks/stripe", Method::Post)
                .profile
                .anonymous
        );
        // A GET on the webhook path is not the webhook, and falls through to the catch-all.
        assert_eq!(
            policy
                .select("/api/webhooks/stripe", Method::Get)
                .profile
                .key,
            CatalogueKey::new("shared")
        );
        assert_eq!(
            policy.select("/actuator/env", Method::Get).profile.key,
            CatalogueKey::new("private")
        );
    }

    #[test]
    fn a_rule_naming_an_ungranted_key_refuses_the_whole_list() {
        // Not "drop that rule": a list that silently loses its `open` entry is a probe that
        // breaks, and a list that silently loses its `private` entry is a back door left open.
        let grant = Grant {
            allowed: keys(&["private", "team"]),
            default: CatalogueKey::new("private"),
        };
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules = Some("- { path: /healthz, match: exact, access: open }".into());
        assert_eq!(
            compile_with(&raw, &grant, &[]),
            Err(CompileError::NotGranted(CatalogueKey::new("open")))
        );
    }

    #[test]
    fn an_unparseable_or_oversized_rule_list_refuses() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules = Some("this is not a list".into());
        assert!(matches!(
            compile_with(&raw, &full_grant(), &[]),
            Err(CompileError::UnparseableRules(_))
        ));

        let many = (0..17)
            .map(|i| format!("- {{ path: /p{i}, match: prefix, access: private }}"))
            .collect::<Vec<_>>()
            .join("\n");
        raw.rules = Some(many);
        assert_eq!(
            compile_with(&raw, &full_grant(), &[]),
            Err(CompileError::TooManyRules { found: 17, max: 16 })
        );
    }

    #[test]
    fn a_rule_path_that_is_not_already_normalised_refuses() {
        // Honouring `/public/../actuator/` would protect a different path than the one the
        // developer read in their own devfile.
        let mut raw = raw_endpoint("user-alice", "alice");
        for path in ["/public/../actuator/", "actuator", "/a//b"] {
            raw.rules = Some(format!(
                "- {{ path: {path}, match: prefix, access: private }}"
            ));
            assert_eq!(
                compile_with(&raw, &full_grant(), &[]),
                Err(CompileError::RulePath(path.to_owned())),
                "{path:?}"
            );
        }
    }

    #[test]
    fn a_rule_listing_a_method_this_gate_cannot_name_refuses() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules =
            Some("- { path: /dav/, match: prefix, access: private, methods: [PROPFIND] }".into());
        assert_eq!(
            compile_with(&raw, &full_grant(), &[]),
            Err(CompileError::UnknownMethod("PROPFIND".into()))
        );

        raw.rules = Some("- { path: /x, match: exact, access: private, methods: [] }".into());
        assert_eq!(
            compile_with(&raw, &full_grant(), &[]),
            Err(CompileError::EmptyMethods("/x".into()))
        );
    }

    #[test]
    fn a_rule_may_pass_a_foreign_bearer_through_on_its_own_path_only() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules =
            Some("- { path: /api/, match: prefix, access: private, bearer: Passthrough }".into());
        let policy = compile_with(&raw, &full_grant(), &[]).unwrap();
        assert_eq!(
            policy.select("/api/items", Method::Get).bearer,
            BearerMode::Passthrough
        );
        assert_eq!(policy.select("/", Method::Get).bearer, BearerMode::Reject);
    }

    #[test]
    fn a_catalogue_key_cannot_be_anonymous_and_delegate() {
        assert_eq!(
            Catalogue::new([(
                CatalogueKey::new("open"),
                true,
                BTreeSet::from([Delegation::Team])
            )]),
            Err(CompileError::AnonymousWithDelegation(CatalogueKey::new(
                "open"
            )))
        );
    }

    #[test]
    fn a_compile_failure_still_leaves_the_owner_able_to_reach_their_own_endpoint() {
        let raw = raw_endpoint("user-alice", "alice");
        let closed = EndpointPolicy::closed(&raw, 9);
        assert_eq!(closed.owner, Username::new("alice"));
        assert!(closed.profile.delegation.is_empty());
        assert!(closed.rules.is_empty());
        assert_eq!(closed.generation, 9);
    }
}
