//! Asking the issuer about a token that carries no claims — RFC 7662, for the deployments whose
//! access tokens are opaque.
//!
//! Not every access token is a JWT. Che on OpenShift authenticates against the OpenShift OAuth
//! server, whose tokens are opaque strings (`sha256~…`): there is no signature, no JWKS and no
//! claim, and the only way to learn who holds one is to ask. A JWKS-only verifier does not merely
//! fail there — it fails *for every non-browser caller on that platform*, which is the same set
//! the bearer branch exists to serve.
//!
//! **Three properties this must not break, and one it genuinely costs.**
//!
//! * *The synchronous port survives.* The call happens here, in the inbound adapter, **before**
//!   `decide()` — the same place and for the same reason as the `TokenReview` of *Self-origin* —
//!   and it fills the same bearer cache the JWT path fills. [`TokenVerifier`] stays cache-only and
//!   unable to `await`, so "no I/O on the request path" keeps being a compile-time property
//!   rather than a promise renewed per feature.
//! * *The burst survives.* Two hundred assets present one token. The call is coalesced on the
//!   token's hash and its answer cached until the token's own `exp`, so a page load costs one
//!   introspection rather than two hundred — exactly as it costs one AEAD open.
//! * *A flood of invented tokens is bounded.* An `inactive` answer is remembered for
//!   `negative_ttl_secs`, and the call sits behind a per-forwarded-address limiter.
//! * *What it costs is offline verification.* An opaque token carries no assertion, so there is
//!   nothing to check while the identity provider is down — and pretending otherwise with a long
//!   cache would mean honouring a token the issuer has already revoked. Hence off by default, and
//!   where the issuer can be asked for JWT access tokens (RFC 9068), that is the shape to ask for.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use weebo_si_endpoint_auth::bearer::{BearerResult, BearerRules, TokenShape};
use weebo_si_endpoint_auth::cache::{Fingerprint, IdentityCache};
use weebo_si_endpoint_auth::identity::Claims;
use weebo_si_endpoint_auth::port::RevocationStore;
use weebo_si_endpoint_auth::time::Timestamp;

use crate::adapters::oidc::{claims_from_values, presented_from_claims};
use crate::ratelimit::RateLimiter;

/// How many introspections may be in flight before the map sweeps the ones nobody is waiting on.
/// Far above any real concurrency — this is a leak ceiling, not a throughput limit.
const MAX_INFLIGHT: usize = 4_096;

/// One introspection verifier, with its caches and its limiter.
pub struct Introspector {
    endpoint: String,
    client_id: String,
    client_secret: String,
    username_claim: String,
    groups_claim: String,
    negative_ttl_secs: u64,
    identity_ttl_secs: u64,
    http: reqwest::Client,
    rules: BearerRules,
    revocations: Arc<dyn RevocationStore>,
    limiter: RateLimiter,
    /// One lock per token in flight, so two hundred assets presenting the same token make one
    /// call: the first holder asks, the rest wait and then find the cache filled.
    inflight: Mutex<HashMap<Fingerprint, Arc<tokio::sync::Mutex<()>>>>,
}

/// Everything an [`Introspector`] is built from.
pub struct IntrospectorPorts {
    /// Where to ask — the configured endpoint, or the discovery document's.
    pub endpoint: String,
    /// This gateway's client id, used to authenticate the introspection call itself.
    pub client_id: String,
    /// Its secret.
    pub client_secret: String,
    /// Which claim carries the username.
    pub username_claim: String,
    /// Which claim carries the groups.
    pub groups_claim: String,
    /// How long `inactive` is remembered.
    pub negative_ttl_secs: u64,
    /// The ceiling a positive answer's lifetime is capped by — `cache.identity_ttl_secs`.
    pub identity_ttl_secs: u64,
    /// What makes a token ours. The same rules the JWT path uses, so the two cannot disagree
    /// about which audience this gateway accepts.
    pub rules: BearerRules,
    /// Sessions the identity provider has ended.
    pub revocations: Arc<dyn RevocationStore>,
    /// The per-forwarded-address limiter, in front of the round trip.
    pub limiter: RateLimiter,
}

/// What one introspection concluded.
pub struct Introspected {
    /// Which check answered.
    pub result: BearerResult,
    /// The caller and the token's deadline, where the token is an identity.
    pub identity: Option<(Claims, Timestamp)>,
}

impl Introspector {
    /// Build it.
    pub fn new(ports: IntrospectorPorts) -> Self {
        Self {
            endpoint: ports.endpoint,
            client_id: ports.client_id,
            client_secret: ports.client_secret,
            username_claim: ports.username_claim,
            groups_claim: ports.groups_claim,
            negative_ttl_secs: ports.negative_ttl_secs,
            identity_ttl_secs: ports.identity_ttl_secs,
            http: reqwest::Client::new(),
            rules: ports.rules,
            revocations: ports.revocations,
            limiter: ports.limiter,
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Whether this token is one only introspection could resolve.
    ///
    /// A JWT decodes; an opaque token does not. Asking that question before asking the issuer is
    /// what keeps a round trip off the path of every ordinary bearer — and off the path of a
    /// service-account token, which is a JWT too.
    pub fn is_opaque(token: &str) -> bool {
        jsonwebtoken::decode_header(token).is_err()
    }

    /// Resolve an opaque bearer into the bearer cache, if it is not there already.
    ///
    /// Called from the inbound adapter, before `decide()`. Returns what happened so the caller can
    /// record the metric; `None` means nothing was asked — already cached, already known to be
    /// inactive, or over the limit.
    pub async fn prewarm(
        &self,
        token: &str,
        address: &str,
        now: Timestamp,
        bearers: &IdentityCache<Claims>,
        negatives: &IdentityCache<()>,
    ) -> Option<Introspected> {
        let key = Fingerprint::of(token);
        if bearers.get(&key, now).is_some() || negatives.get(&key, now).is_some() {
            return None;
        }
        // In front of the round trip, never behind it: a limiter that runs after the call has
        // already paid for the flood it was meant to stop. Over the limit answers nothing, which
        // leaves the token unresolved and the request a `401` — the same answer a foreign token
        // gets, which is what RFC 0009 asks for.
        if !self.limiter.allow(address, now) {
            return None;
        }

        let lock = self.lock_for(key);
        let _held = lock.lock().await;
        // Re-checked under the lock: the holder before us may have filled it, which is the whole
        // reason the lock exists.
        if bearers.get(&key, now).is_some() || negatives.get(&key, now).is_some() {
            self.release(key);
            return None;
        }

        let introspected = self.ask(token, now).await;
        match &introspected {
            Introspected {
                result,
                identity: Some((claims, expires_at)),
            } if result.is_identity() => {
                // Until the token's own `exp`, capped by the identity cache's ceiling: honouring
                // an opaque token for longer than the issuer would is the one thing this path
                // must not do.
                let ceiling = now.plus_secs(self.identity_ttl_secs);
                bearers.insert(key, claims.clone(), (*expires_at).min(ceiling), now);
            }
            // Everything else is remembered as a refusal for `negative_ttl_secs`, so a flood of
            // invented tokens costs one call per token rather than one per request.
            _ => {
                negatives.insert(key, (), now.plus_secs(self.negative_ttl_secs), now);
            }
        }
        self.release(key);
        Some(introspected)
    }

    async fn ask(&self, token: &str, now: Timestamp) -> Introspected {
        let response = self
            .http
            .post(&self.endpoint)
            .timeout(Duration::from_secs(5))
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .send()
            .await;
        let body = match response {
            Ok(response) if response.status().is_success() => {
                response.json::<serde_json::Value>().await
            }
            Ok(response) => {
                eprintln!(
                    "WARN endpoint-gateway: introspection answered {}",
                    response.status()
                );
                return Introspected {
                    result: BearerResult::Unverifiable,
                    identity: None,
                };
            }
            Err(err) => {
                // The honest half of this path: an identity-provider outage stops a caller
                // holding a valid opaque token, because there is nothing to check offline.
                eprintln!("WARN endpoint-gateway: introspection unreachable: {err}");
                return Introspected {
                    result: BearerResult::Unverifiable,
                    identity: None,
                };
            }
        };
        let Ok(body) = body else {
            return Introspected {
                result: BearerResult::Unverifiable,
                identity: None,
            };
        };
        if body.get("active").and_then(serde_json::Value::as_bool) != Some(true) {
            return Introspected {
                result: BearerResult::Inactive,
                identity: None,
            };
        }
        // RFC 7662 gives an introspection response the same claim names a JWT payload uses, with
        // one exception: the party that asked is `client_id` here and `azp` there. So the same
        // reader and the same five checks answer for both shapes.
        let presented = presented_from_claims(&body, body.get("client_id"));
        let result = self.rules.check(&presented, now, self.revocations.as_ref());
        let identity = result
            .is_identity()
            .then(|| claims_from_values(&body, &self.username_claim, &self.groups_claim))
            .flatten();
        Introspected {
            result: if result.is_identity() && identity.is_none() {
                BearerResult::Unverifiable
            } else {
                result
            },
            identity,
        }
    }

    fn lock_for(&self, key: Fingerprint) -> Arc<tokio::sync::Mutex<()>> {
        match self.inflight.lock() {
            Ok(mut inflight) => {
                // Bounded, because the key is a token hash and the set of token hashes is
                // whatever a caller decides it is. `release` clears the normal path, but a client
                // that disconnects mid-introspection has its handler future dropped and never
                // reaches it — so without this, opening connections and abandoning them would
                // grow this map for as long as the process lives. An entry nobody holds any more
                // is one whose `Arc` is down to the map's own reference.
                if inflight.len() >= MAX_INFLIGHT {
                    inflight.retain(|_, lock| Arc::strong_count(lock) > 1);
                }
                Arc::clone(
                    inflight
                        .entry(key)
                        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
                )
            }
            // A poisoned map costs coalescing, never correctness: the call happens, it is simply
            // not shared with whoever else is asking about the same token right now.
            Err(_) => Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn release(&self, key: Fingerprint) {
        if let Ok(mut inflight) = self.inflight.lock() {
            // Only when nobody else is queued behind it, so the map does not grow with every
            // token the cluster has ever seen.
            if inflight
                .get(&key)
                .is_some_and(|lock| Arc::strong_count(lock) <= 2)
            {
                inflight.remove(&key);
            }
        }
    }

    /// The shape this verifier answers for, for the metric.
    pub const fn shape() -> TokenShape {
        TokenShape::Opaque
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
    fn a_jwt_is_never_sent_to_introspection() {
        // The header of a minimal `{"alg":"RS256"}` JWT — enough for `decode_header`.
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln";
        assert!(!Introspector::is_opaque(jwt));
        // What OpenShift actually hands out.
        assert!(Introspector::is_opaque(
            "sha256~aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_-abc"
        ));
        assert!(Introspector::is_opaque(""));
    }

    #[test]
    fn an_introspection_response_is_read_with_the_same_claim_names_as_a_jwt() {
        // The one name the two shapes disagree on: `client_id` here, `azp` in a JWT.
        let body = serde_json::json!({
            "active": true,
            "iss": "https://sso.weebo.si/realms/weebo",
            "aud": "endpoint-gateway",
            "client_id": "che-client",
            "exp": 2_000,
            "sid": "sid-1",
        });
        let presented = presented_from_claims(&body, body.get("client_id"));
        assert_eq!(
            presented.issuer.as_deref(),
            Some("https://sso.weebo.si/realms/weebo")
        );
        assert!(presented.audiences.contains("endpoint-gateway"));
        assert_eq!(presented.authorized_party.as_deref(), Some("che-client"));
        assert_eq!(presented.expires_at, Some(Timestamp::from_secs(2_000)));
        assert_eq!(
            presented.session.map(|sid| sid.as_str().to_owned()),
            Some("sid-1".to_owned())
        );
    }
}
