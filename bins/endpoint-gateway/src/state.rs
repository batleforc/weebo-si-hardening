//! Everything the handlers share, built once by the composition root.
//!
//! One struct rather than a dozen `Arc`s threaded through every handler, and it holds *ports*
//! rather than concrete types wherever the decision reaches for them — the concrete adapters are
//! named in `main.rs` and nowhere else, per `docs/architecture/hexagonal.md`.

use std::sync::Arc;

use prometheus::Registry;
use weebo_si_endpoint_auth::cache::{CacheKind, Fingerprint, IdentityCache};
use weebo_si_endpoint_auth::decide::{AuthRequest, Verdict};
use weebo_si_endpoint_auth::host::{Host, HostScope};
use weebo_si_endpoint_auth::identity::{Claims, SessionId};
use weebo_si_endpoint_auth::index::CatalogLookup;
use weebo_si_endpoint_auth::port::{Clock, EndpointCatalog, RevocationStore};
use weebo_si_endpoint_auth::time::Timestamp;
use weebo_si_endpoint_auth::{Enforcement, Outcome, Presented};

use crate::adapters::introspection::Introspector;
use crate::adapters::kube_catalog::KubeCatalog;
use crate::adapters::kube_revocations::KubeRevocations;
use crate::adapters::kube_workload::KubeWorkloadIdentity;
use crate::adapters::metrics::GatewayMetrics;
use crate::adapters::oidc::{JwksVerifier, OidcClient};
use crate::adapters::session::{Binding, SealedCodec};
use crate::config::GatewayConfig;
use crate::ratelimit::Rate;

/// Bearer signature verifications per client key — what one caller may make the gateway check.
///
/// A person's token is verified once and then served from the cache until it expires, and a
/// script reuses its token, so a legitimate client needs a handful a minute; this is far above
/// that. What it stops is one caller minting a fresh token per request: past the burst, a fresh
/// bearer from that client is not an identity until the bucket refills.
pub const BEARER_VERIFY_PER_CLIENT: Rate = Rate {
    burst: 20,
    per_minute: 120,
};

/// Bearer signature verifications for every caller together — the ceiling on the CPU unique
/// signed tokens can spend: at ~45 µs each (ES256 with `ring`), the refill rate is well under a
/// percent of one core, and the burst a few milliseconds of work.
pub const BEARER_VERIFY_GLOBAL: Rate = Rate {
    burst: 500,
    per_minute: 6_000,
};

/// Every bounded map this process keeps, built together so their sizes come from one place.
pub struct Caches {
    /// Opened cookies, by hash.
    pub sessions: IdentityCache<Claims>,
    /// Verified bearers, by hash.
    pub bearers: IdentityCache<Claims>,
    /// `TokenReview` answers, by hash.
    pub service_accounts: IdentityCache<weebo_si_endpoint_auth::identity::NamespaceName>,
    /// One-time grants already redeemed on this replica.
    pub redeemed: IdentityCache<()>,
    /// Sessions already logged as reaching a host.
    pub logged: IdentityCache<()>,
    /// Opaque tokens the issuer has already called `inactive`, so a flood of invented ones costs
    /// one introspection per token rather than one per request.
    pub introspection_negative: IdentityCache<()>,
}

/// The system clock, as a port, so that nothing below it can read one by accident.
pub struct SystemClock;

impl SystemClock {
    /// Now, without going through the port — the sweep loop's one caller.
    pub fn now_timestamp(&self) -> Timestamp {
        self.now()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or_default(),
        )
    }
}

/// Shared state.
pub struct GatewayState {
    /// The configuration file, validated at load.
    pub config: GatewayConfig,
    /// The governed suffix.
    pub scope: HostScope,
    /// Host to policy, and username to team.
    pub catalog: Arc<KubeCatalog>,
    /// Pod addresses and service-account tokens.
    pub workloads: Arc<KubeWorkloadIdentity>,
    /// Revoked sessions.
    pub revocations: Arc<KubeRevocations>,
    /// Sealed cookies.
    pub codec: SealedCodec,
    /// Bearer verification against cached keys.
    pub verifier: JwksVerifier,
    /// Asking the issuer about an opaque bearer. `None` unless `bearer.introspection.enabled`,
    /// which is the default: an opaque token has nothing to check offline, so this path trades
    /// the JWKS cache's outage tolerance for the ability to serve a platform whose access tokens
    /// carry no claims.
    pub introspector: Option<Introspector>,
    /// The login path. Empty while discovery has not succeeded yet — at boot it is tried once,
    /// and on failure retried in the background with backoff until it does (`main.rs`), so an
    /// identity provider that was down when this replica started costs sign-ins until it is back
    /// rather than for the life of the pod. Every existing session works throughout.
    pub oidc: std::sync::OnceLock<OidcClient>,
    /// Set on SIGTERM: `/readyz` answers `503` from then on, so the replica leaves the rotation
    /// before its listener closes.
    pub shutting_down: std::sync::atomic::AtomicBool,
    /// The clock.
    pub clock: SystemClock,
    /// Opened cookies, by hash.
    pub session_cache: IdentityCache<Claims>,
    /// Verified bearers, by hash.
    pub bearer_cache: IdentityCache<Claims>,
    /// `TokenReview` answers, by hash.
    pub service_account_cache: IdentityCache<weebo_si_endpoint_auth::identity::NamespaceName>,
    /// One-time grants already redeemed on this replica.
    pub redeemed: IdentityCache<()>,
    /// Opaque tokens already known to be inactive.
    pub introspection_negative: IdentityCache<()>,
    /// The per-address limiter in front of the login surface — RFC 0009's *The login surface is
    /// a surface*. `/auth` is exempt: it is the hot path, the ingress controller is its only
    /// caller, and the peer check of *Checking that assumption* is what protects it instead.
    pub login_limiter: crate::ratelimit::RateLimiter,
    /// Deny and challenge lines per host and reason — `logging.deny_per_minute`.
    pub deny_log_limiter: crate::ratelimit::RateLimiter,
    /// Deny and challenge lines suppressed since the last one written, reported on that line.
    pub suppressed_lines: std::sync::atomic::AtomicU64,
    /// The limits in front of bearer signature verification — see [`BEARER_VERIFY_PER_CLIENT`].
    pub verify_per_client: crate::ratelimit::RateLimiter,
    /// See [`BEARER_VERIFY_GLOBAL`].
    pub verify_global: crate::ratelimit::RateLimiter,
    /// `/oidc/backchannel-logout`'s own limiter — every call comes from the identity provider's
    /// egress address, so it cannot share the sign-in bucket.
    pub logout_limiter: crate::ratelimit::RateLimiter,
    /// Sessions that have already been logged as reaching a host — the bounded set behind
    /// "one line per user per host per session" rather than one per asset.
    pub logged: IdentityCache<()>,
    /// How many allows have been decided, for the 1-in-N debugging sample.
    pub allows: std::sync::atomic::AtomicU64,
    /// Metrics.
    pub metrics: GatewayMetrics,
    /// The Prometheus registry `/metrics` renders.
    pub registry: Registry,
    /// Whether the gate answers its verdict or only records it.
    pub enforcement: Enforcement,
    /// What `/selftest` requires a caller to present, one per session key, newest first —
    /// derived from the keys every replica shares, so the probe is answered by whichever replica
    /// the `Service` picks. `/selftest` reports observations, never secrets, and this is what
    /// keeps even those from being a public endpoint.
    pub selftest_tokens: Vec<String>,
    /// The JWKS generation the identity caches were last valid for.
    pub keys_generation: std::sync::atomic::AtomicU64,
    /// The forwarding client the `ReverseProxy` shell uses. Built even in forward-auth mode,
    /// where it is never called: one connection pool costs a few kilobytes, and a `None` here
    /// would mean an `unwrap` on the one path that carries a developer's traffic.
    pub proxy: crate::proxy::ProxyClient,
    /// The last cache counters published, so the counters can be advanced by their delta rather
    /// than reset — a `_total` that goes down is a `_total` nobody can rate().
    pub published: std::sync::Mutex<[weebo_si_endpoint_auth::cache::CacheStats; 3]>,
}

impl GatewayState {
    /// The login path, once discovery has succeeded.
    pub fn oidc(&self) -> Option<&OidcClient> {
        self.oidc.get()
    }

    /// Whether this replica has been asked to stop.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Mark this replica as draining — `/readyz` fails from now on.
    pub fn begin_shutdown(&self) {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// What the catalogue says about a host.
    pub fn catalog_lookup(
        &self,
        host: &weebo_si_endpoint_auth::host::Host,
    ) -> weebo_si_endpoint_auth::index::CatalogLookup {
        self.catalog.policy_for(host)
    }

    /// Resolve a service-account token through the apiserver if it is one and is not cached yet.
    ///
    /// Called by both shells *before* the decision. This is the only I/O either of them does on
    /// a request, it happens once per token rather than once per request, and it is here — in
    /// the handler, where a reader trips over it — rather than inside `decide()`, which may not
    /// do any.
    /// Whether a bearer that would cost a signature verification on this request may have one.
    ///
    /// Only a token that names this gateway's issuer and is not already cached is a
    /// verification — every other bearer is resolved for free or by the service-account branch,
    /// which has limits of its own. Those are the requests a caller can multiply by sending a
    /// fresh token each time, and each costs tens of microseconds of signature arithmetic
    /// whether the signature turns out good or not: the limit is in front of the cryptography
    /// for the same reason the login surface's is.
    fn may_verify_signature(&self, token: &str, client: &str, now: Timestamp) -> bool {
        if self.verifier.rules().is_none()
            || self
                .bearer_cache
                .get(&Fingerprint::of(token), now)
                .is_some()
            || crate::adapters::oidc::unverified_issuer(token).as_deref()
                != Some(self.verifier.issuer())
        {
            return true;
        }
        let allowed = (client.is_empty() || self.verify_per_client.allow(client, now))
            && self.verify_global.allow("*", now);
        if !allowed {
            self.metrics.bearer_verification_throttled();
        }
        allowed
    }

    /// Everything a bearer may cost before the decision, done here where a reader can see it.
    ///
    /// Returns whether the bearer may be used on this request at all: `false` when it would need a
    /// signature verification and a verification limit refused one — the caller then decides as
    /// if no bearer had been sent, which is failing closed for that credential and nothing else.
    pub async fn prewarm_bearer(&self, token: Option<&str>, address: Option<&str>) -> bool {
        let Some(token) = token.map(str::trim).filter(|token| !token.is_empty()) else {
            return true;
        };
        let now = self.now();
        if !self.may_verify_signature(token, address.unwrap_or_default(), now) {
            return false;
        }
        // A token the reviewer already answered for is done: looked up first, because the shape
        // check below decodes the payload twice and parses it, and a workspace calling another
        // repeats the same token on every request.
        if weebo_si_endpoint_auth::port::WorkloadIdentity::namespace_of_service_account(
            self.workloads.as_ref(),
            token,
            now,
        )
        .is_some()
        {
            return true;
        }
        // Shape, claimed issuer and claimed expiry — all unverified, all free — decide whether a
        // `TokenReview` is worth asking for; the reviewer's own limits bound how many are.
        if self.workloads.worth_reviewing(token, now) {
            let reviewed = self
                .workloads
                .review(token, address.unwrap_or_default(), now)
                .await;
            self.metrics.bearer(
                weebo_si_endpoint_auth::bearer::TokenShape::ServiceAccount,
                if reviewed.is_some() {
                    weebo_si_endpoint_auth::bearer::BearerResult::Accepted
                } else {
                    weebo_si_endpoint_auth::bearer::BearerResult::Unverifiable
                },
            );
            return true;
        }
        // The second thing that genuinely needs an API call on this path, and it goes where the
        // first one does: above `decide()`, once per token, visible to a reader. A JWT never
        // reaches it — `is_opaque` is a header decode, not a round trip.
        let Some(introspector) = self.introspector.as_ref() else {
            return true;
        };
        if !Introspector::is_opaque(token) {
            return true;
        }
        if let Some(introspected) = introspector
            .prewarm(
                token,
                address.unwrap_or_default(),
                now,
                &self.bearer_cache,
                &self.introspection_negative,
            )
            .await
        {
            self.metrics
                .bearer(Introspector::shape(), introspected.result);
        }
        true
    }

    /// What the per-address limiter keys on — see [`limit_key`].
    pub fn limit_key(
        &self,
        headers: &axum::http::HeaderMap,
        peer: Option<std::net::SocketAddr>,
    ) -> String {
        limit_key(
            &self.config.self_origin.trusted_proxy,
            &self.config.self_origin.client_ip_header,
            headers,
            peer,
        )
    }

    /// Whether the client-address header may be believed for this connection.
    ///
    /// RFC 0009's *Self-origin*: a header the controller derived and one it repeated are
    /// identical on the wire, so the question is never "what does the header say" but "did this
    /// connection come from something allowed to set it". `peer` is `None` on the forward-auth
    /// path, where the connection is the controller's by construction — the controller is the
    /// only thing that calls `/auth`.
    pub fn trusts_client_address(&self, peer: Option<std::net::SocketAddr>) -> bool {
        self.workloads.addresses_trusted()
            && peer_may_state_address(&self.config.self_origin.trusted_proxy, peer)
    }

    /// Drop every cached identity when the issuer's keys have rotated.
    ///
    /// Cheap enough to do per request — an atomic load — and it has to be per request rather
    /// than on a timer: the window between a rotation and the next sweep is exactly the window
    /// in which a cache would be the reason a token verified against a retired key still passes.
    pub fn drop_identities_on_key_rotation(&self) {
        let current = self.verifier.generation();
        let last = self
            .keys_generation
            .swap(current, std::sync::atomic::Ordering::Relaxed);
        if last != current && last != 0 {
            self.bearer_cache.clear();
            println!("endpoint-gateway: signing keys rotated; verified-bearer cache dropped");
        }
    }

    /// Advance the identity-cache counters by what the caches have done since the last scrape.
    pub fn publish_cache_stats(&self) {
        let current = [
            self.session_cache.stats(),
            self.bearer_cache.stats(),
            self.service_account_cache.stats(),
        ];
        let kinds = [
            CacheKind::Session,
            CacheKind::Bearer,
            CacheKind::TokenReview,
        ];
        let Ok(mut published) = self.published.lock() else {
            return;
        };
        for ((kind, now), before) in kinds.iter().zip(current.iter()).zip(published.iter()) {
            self.metrics.cache_delta(
                *kind,
                now.hits.saturating_sub(before.hits),
                now.misses.saturating_sub(before.misses),
                now.evictions.saturating_sub(before.evictions),
            );
        }
        *published = current;
    }

    /// Now.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Whether this session was revoked.
    pub fn is_revoked(&self, session: &str) -> bool {
        self.revocations.is_revoked(&SessionId::new(session))
    }

    /// The owner of the endpoint on `host`, for the `403` that names whom to ask.
    pub fn owner_of(&self, host: &Host) -> Option<String> {
        match self.catalog.policy_for(host) {
            CatalogLookup::Policy(policy) => Some(policy.owner.as_str().to_owned()),
            _ => None,
        }
    }

    /// The claims an ID token carries, verified against the issuer's keys.
    ///
    /// Its own entry point rather than the bearer branch, because the two want opposite things
    /// from the same token: the bearer branch refuses an ID token structurally, and the login path
    /// is the one place an ID token is exactly what should have arrived.
    pub fn claims_of_id_token(&self, id_token: &str) -> Option<Claims> {
        self.verifier.claims_of_id_token(id_token, self.now())
    }

    /// Verify a logout token and record the revocation it names.
    ///
    /// Verified, not trusted: `/oidc/backchannel-logout` is an unauthenticated endpoint by
    /// design, so the token's signature is the only thing that makes it the identity provider's
    /// word rather than an attacker's denial-of-service against a session.
    pub async fn revoke_from_logout_token(
        &self,
        logout_token: &str,
    ) -> Result<Option<String>, crate::adapters::kube_revocations::RevokeError> {
        let now = self.now();
        let Some(session) = self
            .verifier
            .session_of_logout_token(logout_token, now)
            .map(|session| session.as_str().to_owned())
        else {
            return Ok(None);
        };
        self.revocations
            .revoke(
                &session,
                now.plus_secs(self.config.session.sso_ttl_secs),
                now,
            )
            .await?;
        // Drop it here too rather than waiting for the informer: the replica that received the
        // logout is the one most likely to be asked about that session next.
        self.session_cache.clear();
        Ok(Some(session))
    }

    /// Re-prove a session at the token endpoint if it is due, and renew its claims.
    ///
    /// Returns the session to carry on with, and — when it was refreshed — the re-sealed SSO
    /// cookie to set. `Err(())` means the identity provider refused the refresh, which is the
    /// answer to "how long does a disabled account keep working": until its next use, not until
    /// its cookie expires.
    ///
    /// `WhenNoBackchannel` is the default because doing both is paying twice for one property:
    /// where the identity provider tells us a session ended, informer lag already beats any
    /// interval this could use.
    pub async fn revalidate(
        &self,
        sso: crate::adapters::session::SealedPayload,
    ) -> Result<(crate::adapters::session::SealedPayload, Option<String>), ()> {
        use crate::config::RevalidationMode;

        let backchannel = self
            .oidc()
            .is_some_and(|oidc| oidc.discovery().backchannel_logout_supported);
        let due_by_mode = match self.config.revalidation.mode {
            RevalidationMode::Never => false,
            RevalidationMode::Always => true,
            RevalidationMode::WhenNoBackchannel => !backchannel,
        };
        let now = self.now();
        let overdue = due_by_mode
            && now.is_at_or_after(
                Timestamp::from_secs(sso.proved_at)
                    .plus_secs(self.config.revalidation.interval_secs),
            );
        // The other reason to re-prove a session: somebody has delegated to a group since it was
        // sealed, so the list it carries is no longer the list that decides. Silent — this is
        // the `prompt=none` re-auth of RFC 0009's *Group claims*, reached through the refresh
        // token rather than through a redirect nobody would notice either way.
        let stale_groups = sso.generation != self.catalog.groups_generation();
        if !overdue && !stale_groups {
            return Ok((sso, None));
        }
        let (Some(oidc), Some(refresh)) = (self.oidc(), sso.refresh.clone()) else {
            // Nothing to re-prove with. Not an error: a session minted before refresh tokens
            // were configured keeps working until it expires, and the startup warning an admin
            // sees is the one that says so. A stale group generation with no way to refresh is
            // the same story — the session is judged on the groups it has, which can only ever
            // be *fewer* than it would gain, so it fails closed.
            return Ok((sso, None));
        };
        let Ok(tokens) = oidc.refresh(&refresh).await else {
            return Err(());
        };
        let Some(claims) = self.claims_of_id_token(&tokens.id_token) else {
            return Err(());
        };
        let renewed = crate::adapters::session::SealedPayload {
            username: claims.username.as_str().to_owned(),
            groups: self.catalog.filter_groups(
                claims.groups.iter().map(|group| group.as_str().to_owned()),
                self.config.session.max_groups,
            ),
            session: claims
                .session
                .as_ref()
                .map(|session| session.as_str().to_owned())
                .or(sso.session.clone()),
            expires_at: now.plus_secs(self.config.session.sso_ttl_secs).as_secs(),
            generation: self.catalog.groups_generation(),
            grant_id: None,
            proved_at: now.as_secs(),
            refresh: tokens.refresh_token.clone().or(Some(refresh)),
            session_expires_at: None,
        };
        let sealed = self.codec.seal(&renewed, Binding::Sso).ok_or(())?;
        Ok((renewed, Some(sealed)))
    }

    /// Re-mint a host cookie that is past half-life, or `None`.
    ///
    /// **Only past half-life**, so a page load of two hundred assets mints one cookie rather than
    /// two hundred; and only when the configuration asks for it, because the mechanism depends on
    /// the dialect forwarding `Set-Cookie` from a `200` (Traefik's
    /// `addAuthCookiesToResponse`, which the controller sets on the shared middleware).
    pub fn slide(&self, request: &AuthRequest, presented: &Presented) -> Option<String> {
        if !self.config.session.host_sliding {
            return None;
        }
        let sealed = presented.cookie.as_deref()?;
        let now = self.now();
        let payload = self
            .codec
            .open(sealed, Binding::HostBound(request.host.as_str()), now)?;
        // A grant is not a session, and is never slid into one.
        if payload.grant_id.is_some() {
            return None;
        }
        let renewed = slid(payload, now.as_secs(), self.config.session.host_ttl_secs)?;
        let value = self
            .codec
            .seal(&renewed, Binding::HostBound(request.host.as_str()))?;
        Some(format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            crate::http::HOST_COOKIE,
            renewed.expires_at.saturating_sub(now.as_secs())
        ))
    }

    /// One log line per decision, following RFC 0009's *What gets logged*: every denial and
    /// every challenge, the **first** allow of a session on a host, and a counter for the rest.
    ///
    /// That gives roughly one allow line per user per host per session instead of one per asset,
    /// keeps the refusal stream — the part a security review reads — complete and cheap, and
    /// leaves the rest to `weebo_si_endpoint_auth_decisions_total`. Denials are naturally rare
    /// when the feature works, which is what makes "always" affordable; if they are not rare,
    /// the volume is itself the signal.
    ///
    /// **No line ever carries a cookie, a token, an `Authorization` header or a grant.** The
    /// signature is the enforcement: there is no parameter here one could be passed through.
    pub fn log_decision(&self, request: &AuthRequest, outcome: &Outcome, presented: &Presented) {
        let observed = if outcome.is_observed_only() {
            " observed-only"
        } else {
            ""
        };
        let path = request.raw_path.split('?').next().unwrap_or("/");
        match outcome.decision.verdict {
            Verdict::Deny | Verdict::Challenge(_) => {
                use std::sync::atomic::Ordering;

                let reason = outcome.decision.reason.label();
                // One bucket per host and reason: a loop of refused requests is one burst of
                // lines and then silence, while a *different* refusal — another host, another
                // reason — still gets its line straight away.
                if self.config.logging.deny_per_minute != 0
                    && !self
                        .deny_log_limiter
                        .allow(&format!("{}|{reason}", request.host), self.now())
                {
                    self.suppressed_lines.fetch_add(1, Ordering::Relaxed);
                    self.metrics.log_line_suppressed();
                    return;
                }
                // The next line written says how many were not, so the gap in the log is
                // visible in the log.
                let suppressed = self.suppressed_lines.swap(0, Ordering::Relaxed);
                let suppressed = if suppressed == 0 {
                    String::new()
                } else {
                    format!(" suppressed_since_last={suppressed}")
                };
                println!(
                    "endpoint-gateway: {} host={} path={} reason={reason}{observed}{suppressed}",
                    outcome.decision.verdict_label(),
                    request.host,
                    path,
                );
            }
            Verdict::Allow => self.log_allow(request, outcome, presented, path, observed),
        }
    }

    fn log_allow(
        &self,
        request: &AuthRequest,
        outcome: &Outcome,
        presented: &Presented,
        path: &str,
        observed: &str,
    ) {
        let now = self.now();
        // Keyed by the credential's hash *and* the host, so the same session reaching a second
        // endpoint is a second line — which is the interesting event — while two hundred assets
        // on one host are one.
        let first = self.config.logging.first_allow_per_host
            && match presented.cookie.as_deref().or(presented.bearer.as_deref()) {
                Some(credential) => {
                    // The same scoped hash the session cache keys on — no string built per
                    // request, and length-prefixed, so no credential and host can collide with
                    // another pair by moving bytes across the boundary.
                    let key = Fingerprint::scoped(request.host.as_str(), credential);
                    let unseen = self.logged.get(&key, now).is_none();
                    if unseen {
                        self.logged.insert(
                            key,
                            (),
                            now.plus_secs(self.config.session.host_ttl_secs.max(3_600)),
                            now,
                        );
                    }
                    unseen
                }
                // No credential to key on — a self-origin or anonymous allow. Those are already
                // one-per-request events rather than a burst, and sampling them is what
                // `allow_sample` is for.
                None => false,
            };
        let sampled = match self.config.logging.allow_sample {
            0 => false,
            n => {
                let count = self
                    .allows
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                count.is_multiple_of(u64::from(n))
            }
        };
        if first || sampled {
            println!(
                "endpoint-gateway: allow host={} path={} reason={}{observed}",
                request.host,
                path,
                outcome.decision.reason.label(),
            );
        }
    }

    /// Build the caches this state holds, sized from the configuration.
    pub fn caches(config: &GatewayConfig) -> Caches {
        Caches {
            sessions: IdentityCache::new(
                CacheKind::Session,
                config.cache.identity_max_entries,
                config.cache.identity_ttl_secs,
            ),
            bearers: IdentityCache::new(
                CacheKind::Bearer,
                config.cache.identity_max_entries,
                config.cache.identity_ttl_secs,
            ),
            service_accounts: IdentityCache::new(
                CacheKind::TokenReview,
                config.cache.token_review_max_entries,
                3_600,
            ),
            redeemed: IdentityCache::new(CacheKind::Session, 100_000, 300),
            // The logged-once set. Bounded like every other cache here: losing an entry costs one
            // extra log line, which is the cheapest failure in this file.
            logged: IdentityCache::new(CacheKind::Session, 100_000, 43_200),
            introspection_negative: IdentityCache::new(
                CacheKind::Bearer,
                config.cache.identity_max_entries,
                config.bearer.introspection.negative_ttl_secs.max(1),
            ),
        }
    }
}

/// Whether a connection from `peer` is one allowed to state a caller's address in a header.
///
/// `peer` is `None` on the forward-auth path, where the only caller is the ingress controller.
pub fn peer_may_state_address(
    trusted: &crate::config::TrustedProxy,
    peer: Option<std::net::SocketAddr>,
) -> bool {
    use crate::config::TrustedProxy;

    match (trusted, peer) {
        (TrustedProxy::Off, _) => false,
        (TrustedProxy::Any, _) | (_, None) => true,
        (TrustedProxy::Cidrs(cidrs), Some(peer)) => {
            cidrs.iter().any(|cidr| cidr.contains(peer.ip()))
        }
    }
}

/// What the per-address limiter keys on.
///
/// A hint, never an identity: it bounds the cost of a flood and decides nothing about who anybody
/// is. **The client-address header is read only from a peer `trusted_proxy` admits** (second-pass
/// finding 6): it used to be read from any connection, so a caller that could reach the Service
/// directly chose its own bucket per request and was never limited at all. Otherwise the key is
/// the connection's own address.
pub fn limit_key(
    trusted: &crate::config::TrustedProxy,
    header: &str,
    headers: &axum::http::HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> String {
    peer_may_state_address(trusted, peer)
        .then(|| stated_address(headers, header).map(str::to_owned))
        .flatten()
        .or_else(|| peer.map(|peer| peer.ip().to_string()))
        .unwrap_or_default()
}

/// The address a client-address header states: its **rightmost** entry.
///
/// `X-Forwarded-For` is a list each proxy appends to, so only its last entry was written by the
/// proxy that called this gateway; every entry before it is whatever the client sent. Traefik's
/// `forwardAuth` with `trustForwardHeader: false` sends exactly one, the connection's own
/// address. A single-valued header such as `X-Real-Ip` is its own last entry.
pub fn stated_address<'a>(headers: &'a axum::http::HeaderMap, header: &str) -> Option<&'a str> {
    headers
        .get_all(header.to_ascii_lowercase())
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The host cookie `payload` slides into at `now`, or `None` when it should not be re-minted.
///
/// Only past half-life, and **never past the SSO session it came from** (M1): the re-mint used to
/// be `now + host_ttl` unconditionally, so a host cookie in continuous use outlived the session
/// that proved it — indefinitely, one half-life at a time. It is capped at
/// `session_expires_at`, and a cookie that does not carry one (minted before the field existed)
/// is not slid at all: it lives out its own expiry and the next one is minted through the SSO
/// cookie, which is where the bound lives.
pub fn slid(
    payload: crate::adapters::session::SealedPayload,
    now: u64,
    ttl: u64,
) -> Option<crate::adapters::session::SealedPayload> {
    let cap = payload.session_expires_at?;
    let half_life = payload.expires_at.saturating_sub(ttl / 2);
    if now < half_life {
        return None;
    }
    let expires_at = crate::http::capped_expiry(now, ttl, Some(cap));
    if expires_at <= payload.expires_at {
        // Already as far as the session allows: re-minting would set a cookie for nothing.
        return None;
    }
    Some(crate::adapters::session::SealedPayload {
        expires_at,
        ..payload
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::adapters::session::SealedPayload;

    fn host_cookie(expires_at: u64, session_expires_at: Option<u64>) -> SealedPayload {
        SealedPayload {
            username: "alice".into(),
            groups: Vec::new(),
            session: Some("sid-1".into()),
            expires_at,
            generation: 1,
            grant_id: None,
            proved_at: 0,
            refresh: None,
            session_expires_at,
        }
    }

    #[test]
    fn sliding_never_outlives_the_sso_session_it_came_from() {
        let ttl = 3_600;
        // Past half-life, session ends in 10 minutes: the re-mint stops at the session's end.
        let renewed = slid(host_cookie(10_000, Some(10_600)), 9_000, ttl).unwrap();
        assert_eq!(renewed.expires_at, 10_600);
        // Past half-life, session far away: a full ttl, as before.
        let renewed = slid(host_cookie(10_000, Some(100_000)), 9_000, ttl).unwrap();
        assert_eq!(renewed.expires_at, 12_600);
        // Continuous use cannot walk past the cap one half-life at a time.
        let mut cookie = host_cookie(10_000, Some(20_000));
        let mut now = 9_000;
        while let Some(next) = slid(cookie.clone(), now, ttl) {
            cookie = next;
            now = cookie.expires_at - ttl / 2 + 1;
        }
        assert_eq!(cookie.expires_at, 20_000);
        // Before half-life, nothing.
        assert!(slid(host_cookie(10_000, Some(100_000)), 7_000, ttl).is_none());
    }

    /// Second-pass finding 6: the limiter's key came from the client-address header whatever
    /// connection carried it, so any caller could pick a fresh bucket per request.
    #[test]
    fn the_limit_key_believes_the_address_header_only_from_a_trusted_peer() {
        use crate::config::{Cidr, TrustedProxy};

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-real-ip", "198.51.100.7".parse().unwrap());
        let controller: std::net::SocketAddr = "10.128.0.5:4000".parse().unwrap();
        let stranger: std::net::SocketAddr = "10.42.0.9:4000".parse().unwrap();
        let cidrs = TrustedProxy::Cidrs(vec![Cidr::parse("10.128.0.0/16").unwrap()]);

        assert_eq!(
            limit_key(&cidrs, "X-Real-Ip", &headers, Some(controller)),
            "198.51.100.7"
        );
        // Not a trusted peer: its own address, whatever header it sent.
        assert_eq!(
            limit_key(&cidrs, "X-Real-Ip", &headers, Some(stranger)),
            "10.42.0.9"
        );
        assert_eq!(
            limit_key(&TrustedProxy::Off, "X-Real-Ip", &headers, Some(controller)),
            "10.128.0.5"
        );
        // `any` is the admin saying every peer may state it.
        assert_eq!(
            limit_key(&TrustedProxy::Any, "X-Real-Ip", &headers, Some(stranger)),
            "198.51.100.7"
        );
        // A trusted peer that states nothing is keyed on itself.
        assert_eq!(
            limit_key(
                &cidrs,
                "X-Real-Ip",
                &axum::http::HeaderMap::new(),
                Some(controller)
            ),
            "10.128.0.5"
        );
    }

    #[test]
    fn the_stated_address_is_the_rightmost_entry_the_nearest_proxy_wrote() {
        let mut headers = axum::http::HeaderMap::new();
        // Traefik's forwardAuth with trustForwardHeader: false: one entry, the connection's.
        headers.insert("x-forwarded-for", "fd00:10:245::7b20".parse().unwrap());
        assert_eq!(
            stated_address(&headers, "X-Forwarded-For"),
            Some("fd00:10:245::7b20")
        );
        // A proxy that appends: whatever the client put first is not the address.
        headers.insert(
            "x-forwarded-for",
            "10.42.0.7, 198.51.100.7".parse().unwrap(),
        );
        assert_eq!(
            stated_address(&headers, "X-Forwarded-For"),
            Some("198.51.100.7")
        );
        // Repeated header lines: the last one is the nearest proxy's.
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        assert_eq!(
            stated_address(&headers, "X-Forwarded-For"),
            Some("203.0.113.9")
        );
        // Absent, or empty after the last comma: nothing is stated.
        assert_eq!(stated_address(&headers, "X-Real-Ip"), None);
        headers.insert("x-real-ip", "10.42.0.7, ".parse().unwrap());
        assert_eq!(stated_address(&headers, "X-Real-Ip"), None);
    }

    #[test]
    fn a_host_cookie_without_its_session_bound_is_not_slid() {
        assert!(slid(host_cookie(10_000, None), 9_900, 3_600).is_none());
    }
}
