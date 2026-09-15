//! The decision — RFC 0009's flowchart, as one pure function.
//!
//! Everything else in this crate exists to hand [`decide`] its three arguments already resolved:
//! a request, the policy for its host, and whatever credential the ports could prove. It reads no
//! headers, opens no cookie, verifies no signature and touches no clock, which is what lets the
//! whole of RFC 0009's *Developer continuity* be a table of cases rather than an integration
//! suite.

use crate::host::{Host, HostScope};
use crate::identity::{Claims, Credential};
use crate::index::CatalogLookup;
use crate::path::{PathError, normalise};
use crate::policy::{AccessProfile, BearerMode, Delegation, EndpointPolicy, Method};

/// The scheme the controller stated in `X-Forwarded-Proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// TLS. The only scheme that can carry a `__Host-` cookie, and therefore the only one on
    /// which a session exists at all.
    Https,
    /// Plain HTTP. Refused with a reason rather than failing in a way that looks like a bug —
    /// RFC 0009's *Plain HTTP is not supported, and says so*.
    Http,
}

/// What kind of request this is, which decides how an unauthenticated caller is challenged.
///
/// Read from `Sec-Fetch-Mode` / `Sec-Fetch-Dest` / `Accept` by the inbound adapter, and modelled
/// here because the choice between the three is a decision, not a formatting detail: a `302`
/// answered to an XHR becomes an opaque CORS failure the developer will attribute to their own
/// code, and a `302` answered into an iframe becomes a blank panel with no message at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestShape {
    /// A top-level browser navigation.
    Navigation,
    /// A framed request — the Che dashboard and the IDE's endpoints view open a workspace
    /// endpoint in an iframe, and an identity provider will refuse to be framed.
    Framed,
    /// `fetch`, XHR, a WebSocket upgrade, `curl`, CI.
    Other,
}

/// One request, as the gate sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    /// The host under decision.
    pub host: Host,
    /// The raw path, exactly as the controller reported it — *not* normalised. Normalising before
    /// this point would throw away the comparison in [`decide`] that catches a path the gate and
    /// the application would read differently.
    pub raw_path: String,
    /// The method the controller stated, never the one the auth request itself was made with:
    /// Traefik replays the original method while nginx's `auth_request` always sends `GET`, so a
    /// gate that read its own transport would decide differently on two dialects.
    pub method: Method,
    /// The scheme the controller stated.
    pub scheme: Scheme,
    /// How to challenge this caller, if it comes to that.
    pub shape: RequestShape,
    /// Whether this is a genuine CORS preflight — an `OPTIONS` *with* the preflight headers, not
    /// merely an `OPTIONS`.
    pub preflight: bool,
}

/// What the gate decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Proceed to the application.
    Allow,
    /// Refuse.
    Deny,
    /// Nobody is signed in yet; say so in the shape this caller can act on.
    Challenge(Challenge),
}

/// How an unauthenticated caller is told to authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// `302` to sign in — the flow a person at a browser expects.
    Redirect,
    /// A small HTML page with a link, for a request inside an iframe.
    FramedPage,
    /// `401` with `WWW-Authenticate`, for everything else.
    Unauthorized,
}

/// Why the gate decided what it did — the `reason` label of
/// `weebo_si_endpoint_auth_decisions_total`, and the word in the log line.
///
/// A closed enum rendered by a `&'static str`, never formatting whatever arrived: RFC 0004's
/// project-wide rule, which two RFCs in a row had to be corrected on after the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The caller is the owner, by session.
    Owner,
    /// The caller is the owner, by a bearer token this issuer minted.
    BearerVerified,
    /// The caller was let in by the endpoint's delegation.
    Delegated,
    /// The path resolved to an anonymous profile.
    Anonymous,
    /// The caller is the workspace itself — a pod of the namespace, or its service-account token.
    SelfOrigin,
    /// A foreign `Authorization` header on a path that opted into passing them through.
    BearerPassthrough,
    /// A genuine CORS preflight, allowed on its own and never on behalf of the request that
    /// follows it.
    Preflight,
    /// Someone who is neither the owner nor delegated to.
    NotOwner,
    /// Nobody proved anything.
    NoIdentity,
    /// The session ended at the identity provider.
    Revoked,
    /// Two routing objects claim this host, so the question "whose policy is this" has no answer.
    HostConflict,
    /// The path did not survive normalisation, or survived it differently enough to change which
    /// rule matched.
    UnnormalisedPath,
    /// No indexed object answers for this host, or the host is outside the governed suffix.
    NoPolicy,
    /// Plain HTTP, which cannot carry a `__Host-` cookie and therefore cannot hold a session.
    InsecureScheme,
}

impl Reason {
    /// The metric label and the log word.
    pub fn label(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::BearerVerified => "bearer_verified",
            Self::Delegated => "delegated",
            Self::Anonymous => "anonymous",
            Self::SelfOrigin => "self_origin",
            Self::BearerPassthrough => "bearer_passthrough",
            Self::Preflight => "preflight",
            Self::NotOwner => "not_owner",
            Self::NoIdentity => "no_identity",
            Self::Revoked => "revoked",
            Self::HostConflict => "host_conflict",
            Self::UnnormalisedPath => "unnormalised_path",
            Self::NoPolicy => "no_policy",
            Self::InsecureScheme => "insecure_scheme",
        }
    }
}

/// One decision: what, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Allow, deny, or challenge.
    pub verdict: Verdict,
    /// Why.
    pub reason: Reason,
}

impl Decision {
    /// The `verdict` metric label.
    pub fn verdict_label(self) -> &'static str {
        match self.verdict {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Challenge(_) => "challenge",
        }
    }

    /// Whether this decision lets the request through.
    pub fn is_allow(self) -> bool {
        matches!(self.verdict, Verdict::Allow)
    }

    const fn allow(reason: Reason) -> Self {
        Self {
            verdict: Verdict::Allow,
            reason,
        }
    }

    const fn deny(reason: Reason) -> Self {
        Self {
            verdict: Verdict::Deny,
            reason,
        }
    }
}

/// Decide one request.
///
/// The order of the checks is the flowchart's, and two of them are load-bearing enough to be
/// worth finding here rather than in the RFC:
///
/// * **The preflight allow is for the preflight alone.** The real request that follows is decided
///   on its own merits, as it must be — a preflight carries no credentials by construction and
///   could never be authorised anyway.
/// * **A verified bearer is an identity, not an exemption.** It takes the same road as a cookie:
///   owner check, delegation, path rules. That is what makes `curl`, CI and a test suite work
///   against a closed endpoint without weakening it.
pub fn decide(
    request: &AuthRequest,
    scope: &HostScope,
    lookup: &CatalogLookup,
    credential: &Credential,
) -> Decision {
    if request.scheme == Scheme::Http {
        return Decision::deny(Reason::InsecureScheme);
    }
    if !scope.governs(&request.host) {
        return Decision::deny(Reason::NoPolicy);
    }
    if request.preflight {
        return Decision::allow(Reason::Preflight);
    }
    let policy = match lookup {
        CatalogLookup::Policy(policy) => policy.as_ref(),
        CatalogLookup::Conflict => return Decision::deny(Reason::HostConflict),
        CatalogLookup::Unknown => return Decision::deny(Reason::NoPolicy),
    };
    let Ok(path) = normalise(&request.raw_path) else {
        return Decision::deny(Reason::UnnormalisedPath);
    };
    let selected = policy.select(path.as_str(), request.method);
    // The classic forward-auth bypass, refused rather than out-run: if the gate's view of the
    // path and the controller's raw one resolve to different rules, the gate would be answering
    // about a path the application will not serve.
    if raw_selects_differently(policy, request, &selected.rule) {
        return Decision::deny(Reason::UnnormalisedPath);
    }
    if selected.profile.anonymous {
        return Decision::allow(Reason::Anonymous);
    }

    match credential {
        Credential::Session(claims) => authorise(policy, selected.profile, claims, Reason::Owner),
        Credential::Bearer(claims) => {
            authorise(policy, selected.profile, claims, Reason::BearerVerified)
        }
        Credential::ServiceAccount(namespace) | Credential::PodOrigin(namespace) => {
            if namespace == &policy.namespace {
                Decision::allow(Reason::SelfOrigin)
            } else {
                // A pod of *another* namespace is not this endpoint's workspace, and it is not a
                // person either: there is no name to check against `allow-users`, so delegation
                // cannot apply and the answer is the closed one.
                Decision::deny(Reason::NotOwner)
            }
        }
        Credential::ForeignBearer => {
            if selected.bearer == BearerMode::Passthrough {
                Decision::allow(Reason::BearerPassthrough)
            } else {
                // Never a redirect: whatever sent an `Authorization` header is not a browser
                // waiting to be sent to a login page.
                challenge(Challenge::Unauthorized, Reason::NoIdentity)
            }
        }
        Credential::RevokedSession => challenge(challenge_shape(request), Reason::Revoked),
        Credential::None => challenge(challenge_shape(request), Reason::NoIdentity),
    }
}

/// Whether the raw path and the normalised one resolve to different rules.
fn raw_selects_differently(
    policy: &EndpointPolicy,
    request: &AuthRequest,
    normalised_rule: &Option<usize>,
) -> bool {
    let raw = request
        .raw_path
        .split_once(['?', '#'])
        .map_or(request.raw_path.as_str(), |(before, _)| before);
    &policy.select(raw, request.method).rule != normalised_rule
}

/// The owner check, then delegation. Reached identically by a session and by a verified bearer,
/// which is the property the conformance suite asserts rather than assumes.
///
/// **`profile` is the one the *path* resolved to, not the endpoint's own.** That is what makes
/// narrowing work: an endpoint shared with a colleague, with `/actuator/` resolved to `private`,
/// delegates on `/` and to nobody under `/actuator/`. Reading `policy.profile` here instead
/// would make every path rule that narrows a decoration — the bug this crate shipped for exactly
/// one test run.
///
/// `allow_users` and `allow_groups` stay endpoint-level on purpose: a rule names a catalogue key,
/// which says *what kinds* of delegation apply, and the names the owner delegated to are written
/// once for the endpoint rather than repeated per path.
fn authorise(
    policy: &EndpointPolicy,
    profile: &AccessProfile,
    claims: &Claims,
    owner_reason: Reason,
) -> Decision {
    if policy.is_owner(&claims.username) {
        return Decision::allow(owner_reason);
    }
    if profile.delegation.is_empty() {
        return Decision::deny(Reason::NotOwner);
    }
    if profile.delegates(Delegation::Team) && in_owners_team(policy, claims) {
        return Decision::allow(Reason::Delegated);
    }
    if profile.delegates(Delegation::UsersAndGroups) && named_by_owner(policy, claims) {
        return Decision::allow(Reason::Delegated);
    }
    Decision::deny(Reason::NotOwner)
}

/// A team's members are the owners of its namespaces. A caller who owns no namespace is in no
/// team, and `None == None` must never be a match: two teamless people are not colleagues.
fn in_owners_team(policy: &EndpointPolicy, claims: &Claims) -> bool {
    match (&policy.team, &claims.team) {
        (Some(endpoint_team), Some(caller_team)) => endpoint_team == caller_team,
        _ => false,
    }
}

fn named_by_owner(policy: &EndpointPolicy, claims: &Claims) -> bool {
    policy.allow_users.contains(&claims.username)
        || policy
            .allow_groups
            .iter()
            .any(|group| claims.groups.contains(group))
}

const fn challenge_shape(request: &AuthRequest) -> Challenge {
    match request.shape {
        RequestShape::Navigation => Challenge::Redirect,
        RequestShape::Framed => Challenge::FramedPage,
        RequestShape::Other => Challenge::Unauthorized,
    }
}

const fn challenge(challenge: Challenge, reason: Reason) -> Decision {
    Decision {
        verdict: Verdict::Challenge(challenge),
        reason,
    }
}

/// `decide`'s one dependency that is not a value: the path this crate refuses to normalise twice.
/// Exposed so an adapter can log the path a decision was made about without redoing the work.
pub fn normalised_path_of(request: &AuthRequest) -> Result<String, PathError> {
    normalise(&request.raw_path).map(|path| path.as_str().to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use crate::identity::{Claims, GroupName, NamespaceName, TeamName, Username};
    use crate::policy::{
        AccessProfile, BearerMode, CatalogueKey, MatchKind, MethodSet, PathRule, Provenance,
    };
    use crate::testing::{compile_fixture, raw_endpoint};

    const HOST: &str = "alice-ws-api.weebo.si";

    fn scope() -> HostScope {
        HostScope::new(".weebo.si", ["che.weebo.si", "auth.weebo.si"]).unwrap()
    }

    fn request(path: &str) -> AuthRequest {
        AuthRequest {
            host: Host::parse(HOST).unwrap(),
            raw_path: path.to_owned(),
            method: Method::Get,
            scheme: Scheme::Https,
            shape: RequestShape::Other,
            preflight: false,
        }
    }

    /// An endpoint owned by alice, resolved to `key`, with whatever the test names delegated.
    fn policy(key: &str) -> EndpointPolicy {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some(key.to_owned());
        let mut compiled = compile_fixture(&raw).unwrap();
        compiled.team = Some(TeamName::new("team-1"));
        compiled
    }

    fn lookup(policy: EndpointPolicy) -> CatalogLookup {
        CatalogLookup::Policy(Arc::new(policy))
    }

    fn verdict(request: &AuthRequest, lookup: &CatalogLookup, credential: &Credential) -> Decision {
        decide(request, &scope(), lookup, credential)
    }

    fn alice() -> Credential {
        Credential::Session(Claims::in_team("alice", "team-1"))
    }

    fn colleague() -> Credential {
        Credential::Session(Claims::in_team("bob", "team-1"))
    }

    fn stranger() -> Credential {
        Credential::Session(Claims::user("mallory"))
    }

    #[test]
    fn the_owner_is_allowed_and_everybody_else_is_not() {
        let closed = lookup(policy("private"));
        assert_eq!(
            verdict(&request("/"), &closed, &alice()),
            Decision::allow(Reason::Owner)
        );
        assert_eq!(
            verdict(&request("/"), &closed, &colleague()),
            Decision::deny(Reason::NotOwner)
        );
        assert_eq!(
            verdict(&request("/"), &closed, &stranger()),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn a_teammate_is_allowed_by_team_delegation_and_a_stranger_is_not() {
        let shared = lookup(policy("team"));
        assert_eq!(
            verdict(&request("/"), &shared, &colleague()),
            Decision::allow(Reason::Delegated)
        );
        assert_eq!(
            verdict(&request("/"), &shared, &stranger()),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn two_people_in_no_team_are_not_colleagues() {
        // `None == None` must never be a match: a person who has never opened a workspace is not
        // somebody's teammate, and a gate that read it that way would let every such account into
        // every `team` endpoint in the cluster.
        let mut teamless = policy("team");
        teamless.team = None;
        assert_eq!(
            verdict(&request("/"), &lookup(teamless), &stranger()),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn a_named_user_or_group_is_allowed_only_where_the_profile_delegates_that_way() {
        let mut shared = policy("shared");
        shared.allow_users = BTreeSet::from([Username::new("carol")]);
        shared.allow_groups = BTreeSet::from([GroupName::new("design")]);
        let shared = lookup(shared);
        assert_eq!(
            verdict(
                &request("/"),
                &shared,
                &Credential::Session(Claims::user("carol"))
            ),
            Decision::allow(Reason::Delegated)
        );
        assert_eq!(
            verdict(
                &request("/"),
                &shared,
                &Credential::Session(Claims::user("dave").with_groups(["design"]))
            ),
            Decision::allow(Reason::Delegated)
        );

        // The same names on a `team` endpoint delegate to nobody: the profile does not carry
        // `UsersAndGroups`, and the annotation alone is not a grant.
        let mut team_only = policy("team");
        team_only.allow_users = BTreeSet::from([Username::new("carol")]);
        assert_eq!(
            verdict(
                &request("/"),
                &lookup(team_only),
                &Credential::Session(Claims::user("carol"))
            ),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn a_verified_bearer_takes_the_same_road_as_a_cookie() {
        // The property the conformance suite asserts rather than assumes: a token and a session
        // produce the same verdict for the same person. Only the reason differs, so the metric
        // can still tell CI traffic from a browser.
        let shared = lookup(policy("team"));
        assert_eq!(
            verdict(
                &request("/"),
                &shared,
                &Credential::Bearer(Claims::in_team("alice", "team-1"))
            ),
            Decision::allow(Reason::BearerVerified)
        );
        assert_eq!(
            verdict(
                &request("/"),
                &shared,
                &Credential::Bearer(Claims::in_team("bob", "team-1"))
            ),
            Decision::allow(Reason::Delegated)
        );
        assert_eq!(
            verdict(
                &request("/"),
                &shared,
                &Credential::Bearer(Claims::user("mallory"))
            ),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn a_foreign_bearer_is_refused_unless_the_path_asked_for_it() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules =
            Some("- { path: /api/, match: prefix, access: private, bearer: Passthrough }".into());
        let compiled = lookup(compile_fixture(&raw).unwrap());
        assert_eq!(
            verdict(
                &request("/api/items"),
                &compiled,
                &Credential::ForeignBearer
            ),
            Decision::allow(Reason::BearerPassthrough)
        );
        // Everywhere else it is a 401, never a redirect: whatever sent an Authorization header is
        // not a browser waiting for a login page.
        assert_eq!(
            verdict(&request("/"), &compiled, &Credential::ForeignBearer),
            Decision {
                verdict: Verdict::Challenge(Challenge::Unauthorized),
                reason: Reason::NoIdentity,
            }
        );
    }

    #[test]
    fn the_workspace_reaching_its_own_endpoint_needs_no_credential_and_nobody_elses_pod_does() {
        let closed = lookup(policy("private"));
        for credential in [
            Credential::PodOrigin(NamespaceName::new("user-alice")),
            Credential::ServiceAccount(NamespaceName::new("user-alice")),
        ] {
            assert_eq!(
                verdict(&request("/"), &closed, &credential),
                Decision::allow(Reason::SelfOrigin)
            );
        }
        // RFC 0004's east-west isolation at the front door: one address resolves to one
        // namespace, and another namespace's pod is not this workspace.
        assert_eq!(
            verdict(
                &request("/"),
                &closed,
                &Credential::PodOrigin(NamespaceName::new("user-bob"))
            ),
            Decision::deny(Reason::NotOwner)
        );
    }

    #[test]
    fn an_anonymous_rule_is_the_only_thing_a_credentialless_caller_reaches() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.rules = Some(
            [
                "- { path: /healthz, match: exact, access: open }",
                "- { path: /api/webhooks/, match: prefix, access: open, methods: [POST] }",
            ]
            .join("\n"),
        );
        let compiled = lookup(compile_fixture(&raw).unwrap());
        assert_eq!(
            verdict(&request("/healthz"), &compiled, &Credential::None),
            Decision::allow(Reason::Anonymous)
        );
        let mut post = request("/api/webhooks/stripe");
        post.method = Method::Post;
        assert_eq!(
            verdict(&post, &compiled, &Credential::None),
            Decision::allow(Reason::Anonymous)
        );
        // The same path with the wrong method is not the webhook.
        assert_eq!(
            verdict(
                &request("/api/webhooks/stripe"),
                &compiled,
                &Credential::None
            )
            .verdict,
            Verdict::Challenge(Challenge::Unauthorized)
        );
    }

    #[test]
    fn how_a_caller_is_challenged_is_decided_by_the_request_and_not_by_configuration() {
        let closed = lookup(policy("private"));
        for (shape, expected) in [
            (RequestShape::Navigation, Challenge::Redirect),
            (RequestShape::Framed, Challenge::FramedPage),
            (RequestShape::Other, Challenge::Unauthorized),
        ] {
            let mut request = request("/");
            request.shape = shape;
            assert_eq!(
                verdict(&request, &closed, &Credential::None),
                Decision {
                    verdict: Verdict::Challenge(expected),
                    reason: Reason::NoIdentity,
                },
                "{shape:?}"
            );
        }
    }

    #[test]
    fn a_revoked_session_says_revoked_rather_than_no_identity() {
        let closed = lookup(policy("private"));
        let decision = verdict(&request("/"), &closed, &Credential::RevokedSession);
        assert_eq!(decision.reason, Reason::Revoked);
        assert!(matches!(decision.verdict, Verdict::Challenge(_)));
    }

    #[test]
    fn a_genuine_preflight_is_allowed_and_the_request_after_it_is_not() {
        let closed = lookup(policy("private"));
        let mut preflight = request("/api/items");
        preflight.method = Method::Options;
        preflight.preflight = true;
        assert_eq!(
            verdict(&preflight, &closed, &Credential::None),
            Decision::allow(Reason::Preflight)
        );

        // An OPTIONS *without* the preflight headers is an ordinary request some frameworks route
        // to ordinary handlers. Allowing every OPTIONS would hand those handlers away.
        let mut plain_options = preflight.clone();
        plain_options.preflight = false;
        assert!(!verdict(&plain_options, &closed, &Credential::None).is_allow());

        // And the real request that follows a preflight is decided on its own merits.
        assert!(!verdict(&request("/api/items"), &closed, &Credential::None).is_allow());
    }

    #[test]
    fn a_path_the_gate_and_the_application_would_read_differently_is_denied() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("open".into());
        raw.rules = Some("- { path: /actuator/, match: prefix, access: private }".into());
        let compiled = lookup(compile_fixture(&raw).unwrap());

        // The endpoint is open; `/actuator/` is not. Every row below is an attempt to reach it
        // through a path the gate would normalise differently than the application resolves it.
        for raw_path in [
            "/public/..%2factuator/env",
            "/%252e%252e/actuator/env",
            "/actuator%00/env",
        ] {
            assert_eq!(
                verdict(&request(raw_path), &compiled, &Credential::None),
                Decision::deny(Reason::UnnormalisedPath),
                "{raw_path:?}"
            );
        }

        // And the one that survives normalisation cleanly still resolves to the private rule
        // rather than to the open endpoint.
        assert_eq!(
            verdict(
                &request("/public/../actuator/env"),
                &compiled,
                &Credential::None
            ),
            Decision::deny(Reason::UnnormalisedPath),
        );
        assert_eq!(
            verdict(&request("/actuator/env"), &compiled, &alice()),
            Decision::allow(Reason::Owner)
        );
    }

    #[test]
    fn a_contested_host_denies_rather_than_picking_a_winner() {
        assert_eq!(
            verdict(&request("/"), &CatalogLookup::Conflict, &alice()),
            Decision::deny(Reason::HostConflict)
        );
    }

    #[test]
    fn a_host_nothing_answers_for_denies_even_for_the_owner() {
        assert_eq!(
            verdict(&request("/"), &CatalogLookup::Unknown, &alice()),
            Decision::deny(Reason::NoPolicy)
        );
    }

    #[test]
    fn a_host_outside_the_governed_suffix_is_never_this_gates_business() {
        let mut elsewhere = request("/");
        elsewhere.host = Host::parse("example.com").unwrap();
        assert_eq!(
            verdict(&elsewhere, &lookup(policy("open")), &alice()),
            Decision::deny(Reason::NoPolicy)
        );

        // Including the hosts an admin excluded — the Che gateway authenticates its own.
        let mut che = request("/");
        che.host = Host::parse("che.weebo.si").unwrap();
        assert_eq!(
            verdict(&che, &lookup(policy("open")), &alice()),
            Decision::deny(Reason::NoPolicy)
        );
    }

    #[test]
    fn plain_http_is_refused_before_anything_else_is_even_looked_at() {
        // A `__Host-` cookie requires `Secure`, so an http:// endpoint cannot hold a session at
        // all. Refused with its own reason rather than failing later in a way that looks like a
        // bug — and before the host lookup, so the answer does not depend on the index.
        let mut insecure = request("/");
        insecure.scheme = Scheme::Http;
        assert_eq!(
            verdict(&insecure, &lookup(policy("open")), &alice()),
            Decision::deny(Reason::InsecureScheme)
        );
    }

    #[test]
    fn narrowing_is_invisible_to_the_owner_and_the_whole_point_for_the_delegate() {
        let mut raw = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared".into());
        raw.allow_users = Some("bob".into());
        raw.rules = Some(
            [
                "- { path: /actuator/, match: prefix, access: private }",
                "- { path: /, match: prefix, access: shared }",
            ]
            .join("\n"),
        );
        let compiled = lookup(compile_fixture(&raw).unwrap());
        let bob = Credential::Session(Claims::user("bob"));

        assert_eq!(
            verdict(&request("/"), &compiled, &bob),
            Decision::allow(Reason::Delegated)
        );
        assert_eq!(
            verdict(&request("/actuator/env"), &compiled, &bob),
            Decision::deny(Reason::NotOwner)
        );
        // The owner sees no difference at all, which is why they will not notice the narrowing
        // and will not be tempted to remove it.
        assert_eq!(
            verdict(&request("/actuator/env"), &compiled, &alice()),
            Decision::allow(Reason::Owner)
        );
    }

    #[test]
    fn every_reason_renders_a_label_and_no_two_share_one() {
        let reasons = [
            Reason::Owner,
            Reason::BearerVerified,
            Reason::Delegated,
            Reason::Anonymous,
            Reason::SelfOrigin,
            Reason::BearerPassthrough,
            Reason::Preflight,
            Reason::NotOwner,
            Reason::NoIdentity,
            Reason::Revoked,
            Reason::HostConflict,
            Reason::UnnormalisedPath,
            Reason::NoPolicy,
            Reason::InsecureScheme,
        ];
        let labels: BTreeSet<&str> = reasons.iter().map(|reason| reason.label()).collect();
        assert_eq!(labels.len(), reasons.len(), "every label must be distinct");
        assert!(labels.iter().all(|label| !label.is_empty()));
    }

    #[test]
    fn the_verdict_label_is_the_metrics_contract() {
        let allow = Decision::allow(Reason::Owner);
        let deny = Decision::deny(Reason::NotOwner);
        let challenge = Decision {
            verdict: Verdict::Challenge(Challenge::Redirect),
            reason: Reason::NoIdentity,
        };
        assert_eq!(allow.verdict_label(), "allow");
        assert_eq!(deny.verdict_label(), "deny");
        assert_eq!(challenge.verdict_label(), "challenge");
    }

    #[test]
    fn a_rule_is_matched_on_the_method_the_controller_stated() {
        // nginx's auth_request always arrives as GET while Traefik replays the original method;
        // the gate reads `X-Forwarded-Method` either way, which is what `AuthRequest::method`
        // holds. This test exists so a future refactor cannot quietly start reading the
        // transport's own method instead.
        let mut policy = policy("private");
        policy.rules = vec![PathRule {
            path: "/api/".into(),
            kind: MatchKind::Prefix,
            methods: MethodSet::of([Method::Post]),
            profile: AccessProfile {
                key: CatalogueKey::new("open"),
                anonymous: true,
                delegation: BTreeSet::new(),
            },
            bearer: None,
        }];
        policy.provenance = Provenance::Author;
        policy.bearer = BearerMode::Reject;
        let compiled = lookup(policy);

        let mut post = request("/api/items");
        post.method = Method::Post;
        assert!(verdict(&post, &compiled, &Credential::None).is_allow());
        assert!(!verdict(&request("/api/items"), &compiled, &Credential::None).is_allow());
    }
}
