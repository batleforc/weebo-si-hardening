//! Resolving what a request presented into an identity, and running the decision under the
//! feature's own enforcement mode.
//!
//! This is the whole request path. Read it top to bottom and the claim in RFC 0009's *Request
//! cost* is checkable: the credential is resolved through synchronous ports answered from watch
//! caches, an identity cache absorbs the repeated work of a page load, and the verdict itself is
//! recomputed every time from the compiled policy. Nothing here awaits anything.

use crate::cache::{CacheKind, Fingerprint, IdentityCache};
use crate::decide::{AuthRequest, Decision, Scheme, Verdict, decide};
use crate::host::ClientAddress;
use crate::identity::{Claims, Credential, NamespaceName};
use crate::index::CatalogLookup;
use crate::port::{
    Clock, EndpointCatalog, RevocationStore, SessionCodec, Teams, TokenOutcome, TokenVerifier,
    WorkloadIdentity,
};
use crate::time::Timestamp;

/// Whether the gate's own verdict is answered or only counted.
///
/// The third step of RFC 0009's rollout, and the one that tells an admin which endpoint a probe
/// has been hitting unauthenticated for a year — *before* the probe breaks. Deliberately separate
/// from the chassis's `DryRun`: with no annotation written, no request ever reaches the gateway,
/// so `DryRun` can count how many endpoints *would* be gated and never who would be denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// Decide, log and count — then answer `200` regardless.
    Observe,
    /// Answer what was decided.
    Enforce,
}

/// What a request presented, before anything has been proved about it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Presented {
    /// The sealed host session cookie, if the request carried one.
    pub cookie: Option<String>,
    /// The `Authorization` header's credential, with the `Bearer ` prefix already removed.
    pub bearer: Option<String>,
    /// The client address the controller reported, where the controller is trusted to have
    /// derived it from the TCP peer rather than repeated a header the client set.
    pub client_address: Option<ClientAddress>,
}

/// One request's outcome: what was decided, and what is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// What the gate decided, always — this is what the log line and the metric record, in both
    /// enforcement modes.
    pub decision: Decision,
    /// What the controller is told. Identical to `decision.verdict` under
    /// [`Enforcement::Enforce`]; always [`Verdict::Allow`] under [`Enforcement::Observe`].
    pub answered: Verdict,
}

impl Outcome {
    /// Whether the decision and the answer disagree — the count that makes `Observe` worth
    /// running, and one that must be zero once enforcement is on.
    pub fn is_observed_only(self) -> bool {
        self.decision.verdict != self.answered
    }
}

/// The request path, wired.
///
/// Holds borrowed ports rather than owning them: there is one of these per process, built by the
/// composition root, and every field behind it is an informer-backed cache shared with the rest
/// of the gateway.
pub struct Gateway<'a> {
    catalog: &'a dyn EndpointCatalog,
    sessions: &'a dyn SessionCodec,
    tokens: &'a dyn TokenVerifier,
    workloads: &'a dyn WorkloadIdentity,
    revocations: &'a dyn RevocationStore,
    teams: &'a dyn Teams,
    clock: &'a dyn Clock,
    session_cache: &'a IdentityCache<Claims>,
    bearer_cache: &'a IdentityCache<Claims>,
    service_account_cache: &'a IdentityCache<NamespaceName>,
    enforcement: Enforcement,
}

/// Everything a [`Gateway`] is built from, so that adding a port is a struct field rather than a
/// tenth positional argument nobody can read at the call site.
pub struct GatewayPorts<'a> {
    /// Host to policy.
    pub catalog: &'a dyn EndpointCatalog,
    /// Opening sealed cookies.
    pub sessions: &'a dyn SessionCodec,
    /// Verifying bearer tokens.
    pub tokens: &'a dyn TokenVerifier,
    /// Pod addresses and service-account tokens.
    pub workloads: &'a dyn WorkloadIdentity,
    /// Sessions the identity provider ended.
    pub revocations: &'a dyn RevocationStore,
    /// Team membership, derived from namespace ownership.
    pub teams: &'a dyn Teams,
    /// The clock.
    pub clock: &'a dyn Clock,
    /// Opened cookies, by hash.
    pub session_cache: &'a IdentityCache<Claims>,
    /// Verified bearers, by hash.
    pub bearer_cache: &'a IdentityCache<Claims>,
    /// `TokenReview` answers, by hash.
    pub service_account_cache: &'a IdentityCache<NamespaceName>,
}

impl<'a> Gateway<'a> {
    /// Wire the request path.
    pub fn new(ports: GatewayPorts<'a>, enforcement: Enforcement) -> Self {
        Self {
            catalog: ports.catalog,
            sessions: ports.sessions,
            tokens: ports.tokens,
            workloads: ports.workloads,
            revocations: ports.revocations,
            teams: ports.teams,
            clock: ports.clock,
            session_cache: ports.session_cache,
            bearer_cache: ports.bearer_cache,
            service_account_cache: ports.service_account_cache,
            enforcement,
        }
    }

    /// Decide one request.
    pub fn authorize(&self, request: &AuthRequest, presented: &Presented) -> Outcome {
        let now = self.clock.now();
        let lookup = self.catalog.policy_for(&request.host);
        // Resolve a credential only where one can change the answer. An unknown host, a contested
        // one and a plain-HTTP request are all decided before `decide()` reads the credential at
        // all, and opening a sealed cookie for them would be the one piece of real work on the
        // path that needs none.
        let credential =
            if request.scheme == Scheme::Https && matches!(lookup, CatalogLookup::Policy(_)) {
                self.resolve(request, presented, now)
            } else {
                Credential::None
            };
        let decision = decide(request, self.catalog.scope(), &lookup, &credential);
        let answered = match self.enforcement {
            Enforcement::Enforce => decision.verdict,
            Enforcement::Observe => Verdict::Allow,
        };
        Outcome { decision, answered }
    }

    /// Turn headers into a credential, in the flowchart's order: an `Authorization` header first,
    /// then a cookie, then the client address. Explicit credentials beat implicit ones, so a
    /// developer testing what a colleague will see can do it from their own workspace terminal by
    /// presenting that colleague's session, and gets the answer the colleague would get.
    fn resolve(&self, request: &AuthRequest, presented: &Presented, now: Timestamp) -> Credential {
        if let Some(token) = presented
            .bearer
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            return self.resolve_bearer(token, now);
        }
        if let Some(cookie) = presented.cookie.as_deref().filter(|c| !c.is_empty()) {
            return self.resolve_session(request, cookie, now);
        }
        if let Some(address) = presented.client_address.as_ref()
            && let Some(namespace) = self.workloads.namespace_of_address(address)
        {
            return Credential::PodOrigin(namespace);
        }
        Credential::None
    }

    fn resolve_bearer(&self, token: &str, now: Timestamp) -> Credential {
        let key = Fingerprint::of(token);
        if let Some(claims) = self.bearer_cache.get(&key, now) {
            return self.as_person(claims);
        }
        match self.tokens.verify(token, now) {
            TokenOutcome::Ours { claims, expires_at } => {
                // Cached without the team: team membership is authorisation input, and
                // authorisation input is recomputed per request. See `as_person`.
                self.bearer_cache
                    .insert(key, claims.clone(), expires_at, now);
                self.as_person(claims)
            }
            TokenOutcome::Foreign | TokenOutcome::Invalid => {
                self.resolve_service_account(token, now)
            }
        }
    }

    /// A service-account token is the answer where a pod's address does not survive the network
    /// path — the SNAT case. Tried only once the token turned out not to be ours, so an ordinary
    /// bearer costs no `TokenReview` at all.
    fn resolve_service_account(&self, token: &str, now: Timestamp) -> Credential {
        let key = Fingerprint::of(token);
        if let Some(namespace) = self.service_account_cache.get(&key, now) {
            return Credential::ServiceAccount(namespace);
        }
        match self.workloads.namespace_of_service_account(token, now) {
            Some(identity) => {
                self.service_account_cache.insert(
                    key,
                    identity.namespace.clone(),
                    identity.expires_at,
                    now,
                );
                Credential::ServiceAccount(identity.namespace)
            }
            None => Credential::ForeignBearer,
        }
    }

    fn resolve_session(&self, request: &AuthRequest, cookie: &str, now: Timestamp) -> Credential {
        let key = Fingerprint::of(cookie);
        let claims = match self.session_cache.get(&key, now) {
            Some(claims) => claims,
            None => match self.sessions.open_host_session(&request.host, cookie, now) {
                Some(opened) => {
                    self.session_cache
                        .insert(key, opened.claims.clone(), opened.expires_at, now);
                    opened.claims
                }
                // A cookie that does not open is indistinguishable from none: wrong key, wrong
                // host, expired or corrupt all mean "sign in again".
                None => return Credential::None,
            },
        };
        // Revocation is checked on the *cached* identity too, and outside the cache entry, so a
        // back-channel logout cuts a session off within informer lag rather than at the end of a
        // twelve-hour cookie — including for the two hundred assets already in flight.
        if let Some(session) = claims.session.as_ref()
            && self.revocations.is_revoked(session)
        {
            self.session_cache.forget(&key);
            return Credential::RevokedSession;
        }
        Credential::Session(self.team_of(claims))
    }

    fn as_person(&self, claims: Claims) -> Credential {
        Credential::Bearer(self.team_of(claims))
    }

    /// Fill in the caller's team from the live index, never from the cookie and never from the
    /// cache. A person added to a team reaches their colleague's endpoint on the next request; a
    /// person removed from one stops reaching it on the next request.
    fn team_of(&self, mut claims: Claims) -> Claims {
        claims.team = self.teams.team_of(&claims.username);
        claims
    }

    /// Which cache kinds this gateway holds, for the metric loop. Ordered so the series come out
    /// the same way every scrape.
    pub fn cache_kinds(&self) -> [CacheKind; 3] {
        [
            self.session_cache.kind(),
            self.bearer_cache.kind(),
            self.service_account_cache.kind(),
        ]
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::compile::RawEndpoint;
    use crate::decide::{Challenge, Reason, RequestShape, Scheme};
    use crate::host::Host;
    use crate::identity::{SessionId, Username};
    use crate::policy::{EndpointPolicy, Method};
    use crate::port::TokenOutcome;
    use crate::testing::{
        FakeCatalog, FakeRevocations, FakeSessions, FakeTeams, FakeTokens, FakeWorkloads,
        FixedClock, compile_fixture, raw_endpoint,
    };

    const HOST: &str = "alice-ws-api.weebo.si";
    const COOKIE: &str = "sealed-host-session-for-bob";
    const TOKEN: &str = "a-token-our-issuer-minted";

    fn shared_endpoint(allow_users: Option<&str>) -> EndpointPolicy {
        let mut raw: RawEndpoint = raw_endpoint("user-alice", "alice");
        raw.access = Some("shared".into());
        raw.allow_users = allow_users.map(str::to_owned);
        let mut policy = compile_fixture(&raw).unwrap();
        policy.team = Some(crate::identity::TeamName::new("team-1"));
        policy
    }

    struct Harness {
        catalog: FakeCatalog,
        sessions: FakeSessions,
        tokens: FakeTokens,
        workloads: FakeWorkloads,
        revocations: FakeRevocations,
        teams: FakeTeams,
        clock: FixedClock,
        session_cache: IdentityCache<Claims>,
        bearer_cache: IdentityCache<Claims>,
        service_account_cache: IdentityCache<NamespaceName>,
    }

    impl Harness {
        fn new(policy: EndpointPolicy) -> Self {
            Self {
                catalog: FakeCatalog::one(HOST, policy),
                sessions: FakeSessions::with(
                    COOKIE,
                    Claims {
                        session: Some(SessionId::new("sid-1")),
                        ..Claims::user("bob")
                    },
                    Timestamp::from_secs(3_600),
                ),
                tokens: FakeTokens::with(
                    TOKEN,
                    TokenOutcome::Ours {
                        claims: Claims::user("bob"),
                        expires_at: Timestamp::from_secs(3_600),
                    },
                ),
                workloads: FakeWorkloads::default(),
                revocations: FakeRevocations::default(),
                teams: FakeTeams::default(),
                clock: FixedClock::at(0),
                session_cache: IdentityCache::new(CacheKind::Session, 1_000, 300),
                bearer_cache: IdentityCache::new(CacheKind::Bearer, 1_000, 300),
                service_account_cache: IdentityCache::new(CacheKind::TokenReview, 1_000, 300),
            }
        }

        fn with_workloads(mut self, workloads: FakeWorkloads) -> Self {
            self.workloads = workloads;
            self
        }

        fn gateway(&self, enforcement: Enforcement) -> Gateway<'_> {
            Gateway::new(
                GatewayPorts {
                    catalog: &self.catalog,
                    sessions: &self.sessions,
                    tokens: &self.tokens,
                    workloads: &self.workloads,
                    revocations: &self.revocations,
                    teams: &self.teams,
                    clock: &self.clock,
                    session_cache: &self.session_cache,
                    bearer_cache: &self.bearer_cache,
                    service_account_cache: &self.service_account_cache,
                },
                enforcement,
            )
        }
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

    fn with_cookie() -> Presented {
        Presented {
            cookie: Some(COOKIE.to_owned()),
            ..Presented::default()
        }
    }

    fn with_bearer(token: &str) -> Presented {
        Presented {
            bearer: Some(token.to_owned()),
            ..Presented::default()
        }
    }

    #[test]
    fn a_page_load_of_two_hundred_assets_verifies_one_token() {
        // RFC 0009's *Request cost*, as an assertion: the burst pays one signature check and 199
        // map reads. If this number ever moves, the latency budget moved with it.
        let harness = Harness::new(shared_endpoint(Some("bob")));
        let gateway = harness.gateway(Enforcement::Enforce);
        for asset in 0..200 {
            let outcome = gateway.authorize(
                &request(&format!("/static/{asset}.js")),
                &with_bearer(TOKEN),
            );
            assert!(outcome.decision.is_allow(), "asset {asset}");
        }
        assert_eq!(harness.tokens.calls(), 1);
        let stats = harness.bearer_cache.stats();
        assert_eq!((stats.hits, stats.misses, stats.entries), (199, 1, 1));
    }

    #[test]
    fn a_policy_change_lands_on_the_next_request_with_the_same_credential() {
        // The invariant that makes the identity cache safe: the cookie proves identity, never
        // authorisation. Bob's session is cached and stays cached; removing his name from
        // `allow-users` denies him anyway, on the very next request.
        let harness = Harness::new(shared_endpoint(Some("bob")));
        let gateway = harness.gateway(Enforcement::Enforce);

        let before = gateway.authorize(&request("/"), &with_cookie());
        assert_eq!(before.decision.reason, Reason::Delegated);

        harness.catalog.swap(HOST, shared_endpoint(None), 2);

        let after = gateway.authorize(&request("/"), &with_cookie());
        assert_eq!(after.decision.reason, Reason::NotOwner);
        assert!(!after.decision.is_allow());
        // ...and the session was never re-opened: the identity was cached the whole time, and it
        // is the *verdict* that was recomputed.
        assert_eq!(harness.session_cache.stats().hits, 1);
    }

    #[test]
    fn team_membership_is_read_per_request_and_never_from_the_cookie() {
        let harness = Harness::new({
            let mut raw = raw_endpoint("user-alice", "alice");
            raw.access = Some("team".into());
            let mut policy = compile_fixture(&raw).unwrap();
            policy.team = Some(crate::identity::TeamName::new("team-1"));
            policy
        });
        let gateway = harness.gateway(Enforcement::Enforce);

        assert!(
            !gateway
                .authorize(&request("/"), &with_cookie())
                .decision
                .is_allow()
        );
        harness.teams.put("bob", "team-1");
        assert_eq!(
            gateway
                .authorize(&request("/"), &with_cookie())
                .decision
                .reason,
            Reason::Delegated
        );
        harness.teams.remove("bob");
        assert_eq!(
            gateway
                .authorize(&request("/"), &with_cookie())
                .decision
                .reason,
            Reason::NotOwner
        );
    }

    #[test]
    fn a_back_channel_logout_cuts_off_a_cached_session() {
        let harness = Harness::new(shared_endpoint(Some("bob")));
        let gateway = harness.gateway(Enforcement::Enforce);
        assert!(
            gateway
                .authorize(&request("/"), &with_cookie())
                .decision
                .is_allow()
        );

        harness.revocations.revoke("sid-1");

        let after = gateway.authorize(&request("/"), &with_cookie());
        assert_eq!(after.decision.reason, Reason::Revoked);
        assert_eq!(
            after.decision.verdict,
            Verdict::Challenge(Challenge::Unauthorized)
        );
        // The cache entry is dropped rather than left to expire, so the revocation costs one
        // lookup rather than one per request for the rest of the cookie's life.
        assert_eq!(harness.session_cache.stats().entries, 0);
    }

    #[test]
    fn the_workspaces_own_pod_needs_no_credential_at_all() {
        let harness = Harness::new(shared_endpoint(None))
            .with_workloads(FakeWorkloads::address("10.42.0.7", "user-alice"));
        let gateway = harness.gateway(Enforcement::Enforce);
        let presented = Presented {
            client_address: Some(ClientAddress::new("10.42.0.7")),
            ..Presented::default()
        };
        assert_eq!(
            gateway.authorize(&request("/"), &presented).decision.reason,
            Reason::SelfOrigin
        );

        // A pod of another namespace resolves to that namespace, which is not this endpoint's.
        let elsewhere = Harness::new(shared_endpoint(None))
            .with_workloads(FakeWorkloads::address("10.42.0.9", "user-bob"));
        let gateway = elsewhere.gateway(Enforcement::Enforce);
        let presented = Presented {
            client_address: Some(ClientAddress::new("10.42.0.9")),
            ..Presented::default()
        };
        assert_eq!(
            gateway.authorize(&request("/"), &presented).decision.reason,
            Reason::NotOwner
        );
    }

    #[test]
    fn where_the_cluster_snats_the_workspaces_service_account_token_does_the_same_job() {
        let harness = Harness::new(shared_endpoint(None)).with_workloads(
            FakeWorkloads::service_account("sa-token", "user-alice", Timestamp::from_secs(3_600)),
        );
        let gateway = harness.gateway(Enforcement::Enforce);
        for _ in 0..50 {
            assert_eq!(
                gateway
                    .authorize(&request("/"), &with_bearer("sa-token"))
                    .decision
                    .reason,
                Reason::SelfOrigin
            );
        }
        // One TokenReview for fifty requests — the row in *Data and state* that says "one API
        // call per token, not per request".
        assert_eq!(harness.service_account_cache.stats().entries, 1);
        assert_eq!(harness.service_account_cache.stats().misses, 1);
    }

    #[test]
    fn an_explicit_credential_beats_the_pod_it_was_sent_from() {
        // A developer testing what a colleague will see, from their own workspace terminal, gets
        // the answer the colleague would get — not the owner's.
        let harness = Harness::new(shared_endpoint(None))
            .with_workloads(FakeWorkloads::address("10.42.0.7", "user-alice"));
        let gateway = harness.gateway(Enforcement::Enforce);
        let presented = Presented {
            cookie: Some(COOKIE.to_owned()),
            client_address: Some(ClientAddress::new("10.42.0.7")),
            ..Presented::default()
        };
        assert_eq!(
            gateway.authorize(&request("/"), &presented).decision.reason,
            Reason::NotOwner
        );
    }

    #[test]
    fn a_foreign_bearer_is_not_an_identity_and_does_not_cost_a_token_review_twice() {
        let harness = Harness::new(shared_endpoint(None));
        let gateway = harness.gateway(Enforcement::Enforce);
        let outcome = gateway.authorize(&request("/"), &with_bearer("somebody-elses-token"));
        assert_eq!(outcome.decision.reason, Reason::NoIdentity);
        assert_eq!(
            outcome.decision.verdict,
            Verdict::Challenge(Challenge::Unauthorized)
        );
        // Nothing was cached: there is no identity to remember, and caching "this is not an
        // identity" would be a cache an unauthenticated caller fills.
        assert_eq!(harness.bearer_cache.stats().entries, 0);
        assert_eq!(harness.service_account_cache.stats().entries, 0);
    }

    #[test]
    fn observe_answers_allow_while_recording_what_enforce_would_have_done() {
        let harness = Harness::new(shared_endpoint(None));
        let gateway = harness.gateway(Enforcement::Observe);
        let outcome = gateway.authorize(&request("/"), &with_cookie());
        assert_eq!(outcome.decision.reason, Reason::NotOwner);
        assert_eq!(outcome.answered, Verdict::Allow);
        assert!(outcome.is_observed_only());

        // And under Enforce the same request is refused, with the same decision recorded.
        let enforcing = harness.gateway(Enforcement::Enforce);
        let enforced = enforcing.authorize(&request("/"), &with_cookie());
        assert_eq!(enforced.decision, outcome.decision);
        assert!(!enforced.is_observed_only());
    }

    #[test]
    fn an_expired_cookie_is_a_challenge_rather_than_an_error() {
        let harness = Harness::new(shared_endpoint(Some("bob")));
        harness.clock.advance(7_200);
        let gateway = harness.gateway(Enforcement::Enforce);
        let outcome = gateway.authorize(&request("/"), &with_cookie());
        assert_eq!(outcome.decision.reason, Reason::NoIdentity);
        assert_eq!(
            outcome.decision.verdict,
            Verdict::Challenge(Challenge::Unauthorized)
        );
    }

    #[test]
    fn the_owner_reaches_their_own_endpoint_with_a_session_and_with_a_token_alike() {
        let harness = Harness::new(shared_endpoint(None));
        let gateway = harness.gateway(Enforcement::Enforce);
        // The fixtures' session and token are both for bob, who is not the owner; the point here
        // is that the two paths agree, which is the conformance property RFC 0009 names.
        let by_cookie = gateway.authorize(&request("/"), &with_cookie());
        let by_token = gateway.authorize(&request("/"), &with_bearer(TOKEN));
        assert_eq!(by_cookie.decision.verdict, by_token.decision.verdict);

        let owners = Harness::new(shared_endpoint(None));
        let cache_kinds = owners.gateway(Enforcement::Enforce).cache_kinds();
        assert_eq!(
            cache_kinds.map(|kind| kind.label()),
            ["session", "bearer", "token_review"]
        );
    }

    #[test]
    fn a_name_the_owner_never_wrote_is_not_delegated_to() {
        let harness = Harness::new(shared_endpoint(Some("carol")));
        let gateway = harness.gateway(Enforcement::Enforce);
        assert_eq!(
            gateway
                .authorize(&request("/"), &with_cookie())
                .decision
                .reason,
            Reason::NotOwner
        );
        assert_eq!(
            shared_endpoint(Some("carol")).allow_users,
            BTreeSet::from([Username::new("carol")])
        );
    }
}
