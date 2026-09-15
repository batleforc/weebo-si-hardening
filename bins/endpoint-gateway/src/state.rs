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

use crate::adapters::kube_catalog::KubeCatalog;
use crate::adapters::kube_revocations::KubeRevocations;
use crate::adapters::kube_workload::KubeWorkloadIdentity;
use crate::adapters::metrics::GatewayMetrics;
use crate::adapters::oidc::{JwksVerifier, OidcClient};
use crate::adapters::session::{Binding, SealedCodec};
use crate::config::GatewayConfig;

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
    /// The login path. `None` where discovery failed at boot and the gateway is serving cookies
    /// it already minted — a sign-in is then unavailable, and every existing session still works.
    pub oidc: Option<OidcClient>,
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
    /// What `/selftest` requires a caller to present — minted at boot, known only to this
    /// process and the probe it runs. `/selftest` reports observations, never secrets, and this
    /// is what keeps even those from being a public endpoint.
    pub selftest_token: String,
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
    pub async fn prewarm_service_account(&self, token: Option<&str>) {
        let Some(token) = token else {
            return;
        };
        if !crate::adapters::kube_workload::KubeWorkloadIdentity::looks_like_service_account_token(
            token,
        ) {
            return;
        }
        let now = self.now();
        if weebo_si_endpoint_auth::port::WorkloadIdentity::namespace_of_service_account(
            self.workloads.as_ref(),
            token,
            now,
        )
        .is_none()
        {
            let _ = self.workloads.review(token, now).await;
        }
    }

    /// Whether the client-address header may be believed for this connection.
    ///
    /// RFC 0009's *Self-origin*: a header the controller derived and one it repeated are
    /// identical on the wire, so the question is never "what does the header say" but "did this
    /// connection come from something allowed to set it". `peer` is `None` on the forward-auth
    /// path, where the connection is the controller's by construction — the controller is the
    /// only thing that calls `/auth`.
    pub fn trusts_client_address(&self, peer: Option<std::net::SocketAddr>) -> bool {
        use crate::config::TrustedProxy;

        if !self.workloads.addresses_trusted() {
            return false;
        }
        match (&self.config.self_origin.trusted_proxy, peer) {
            (TrustedProxy::Off, _) => false,
            (TrustedProxy::Any, _) | (_, None) => true,
            (TrustedProxy::Cidrs(prefixes), Some(peer)) => {
                let address = peer.ip().to_string();
                prefixes
                    .iter()
                    .any(|prefix| address.starts_with(prefix.as_str()))
            }
        }
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

    /// The identity a request proved, for the outbound headers. Re-derived rather than carried
    /// out of the decision, because the decision's answer is a verdict and a reason — not a
    /// caller — and widening it to return one would put the identity on the path of every denial
    /// too.
    pub fn identity_of(&self, request: &AuthRequest, presented: &Presented) -> Option<Claims> {
        let now = self.now();
        if let Some(sealed) = presented.cookie.as_deref()
            && let Some(payload) =
                self.codec
                    .open(sealed, Binding::HostBound(request.host.as_str()), now)
        {
            return Some(payload.claims());
        }
        let token = presented.bearer.as_deref()?;
        match weebo_si_endpoint_auth::port::TokenVerifier::verify(&self.verifier, token, now) {
            weebo_si_endpoint_auth::port::TokenOutcome::Ours { claims, .. } => Some(claims),
            _ => None,
        }
    }

    /// The claims an ID token carries, verified against the issuer's keys like any other token.
    pub fn claims_of_id_token(&self, id_token: &str) -> Option<Claims> {
        match weebo_si_endpoint_auth::port::TokenVerifier::verify(
            &self.verifier,
            id_token,
            self.now(),
        ) {
            weebo_si_endpoint_auth::port::TokenOutcome::Ours { claims, .. } => Some(claims),
            _ => None,
        }
    }

    /// Verify a logout token and record the revocation it names.
    ///
    /// Verified, not trusted: `/oidc/backchannel-logout` is an unauthenticated endpoint by
    /// design, so the token's signature is the only thing that makes it the identity provider's
    /// word rather than an attacker's denial-of-service against a session.
    pub async fn revoke_from_logout_token(
        &self,
        logout_token: &str,
    ) -> Result<Option<String>, kube::Error> {
        let now = self.now();
        let session = match weebo_si_endpoint_auth::port::TokenVerifier::verify(
            &self.verifier,
            logout_token,
            now,
        ) {
            weebo_si_endpoint_auth::port::TokenOutcome::Ours { claims, .. } => claims
                .session
                .as_ref()
                .map(|session| session.as_str().to_owned()),
            _ => None,
        };
        let Some(session) = session else {
            return Ok(None);
        };
        self.revocations
            .revoke(&session, now.plus_secs(self.config.session.sso_ttl_secs))
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
            .oidc
            .as_ref()
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
        let (Some(oidc), Some(refresh)) = (self.oidc.as_ref(), sso.refresh.clone()) else {
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
        let ttl = self.config.session.host_ttl_secs;
        let half_life = Timestamp::from_secs(payload.expires_at)
            .as_secs()
            .saturating_sub(ttl / 2);
        if now.as_secs() < half_life {
            return None;
        }
        let renewed = crate::adapters::session::SealedPayload {
            expires_at: now.plus_secs(ttl).as_secs(),
            ..payload
        };
        let value = self
            .codec
            .seal(&renewed, Binding::HostBound(request.host.as_str()))?;
        Some(format!(
            "{}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={ttl}",
            crate::http::HOST_COOKIE
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
                println!(
                    "endpoint-gateway: {} host={} path={} reason={}{observed}",
                    outcome.decision.verdict_label(),
                    request.host,
                    path,
                    outcome.decision.reason.label(),
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
                    let key = Fingerprint::of(&format!("{credential}@{}", request.host));
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
        }
    }
}
