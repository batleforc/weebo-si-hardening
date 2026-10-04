//! The identity provider: discovery, a background JWKS refresh, bearer verification, and the
//! authorization-code exchange.
//!
//! **The split down the middle of this file is the one RFC 0009's *Request cost* rests on.**
//! [`JwksVerifier`] implements [`TokenVerifier`] and is *synchronous*: it verifies a signature
//! against keys already in memory and cannot reach the network, so an identity provider that is
//! down cannot stop a `curl` that already holds a valid token — and a page load of two hundred
//! assets cannot become two hundred round trips. [`OidcClient`] is the login path, where a
//! network call is exactly right and happens once per sign-in.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use weebo_si_endpoint_auth::bearer::{BearerResult, BearerRules, PresentedToken, TokenShape};
use weebo_si_endpoint_auth::identity::{Claims, GroupName, SessionId, Username};
use weebo_si_endpoint_auth::port::{RevocationStore, TokenOutcome, TokenVerifier};
use weebo_si_endpoint_auth::time::Timestamp;

use crate::adapters::metrics::GatewayMetrics;

/// The subset of the discovery document this gateway reads.
#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    /// Where a browser is sent to sign in.
    pub authorization_endpoint: String,
    /// Where a code is exchanged.
    pub token_endpoint: String,
    /// Where the signing keys are published.
    pub jwks_uri: String,
    /// Whether the identity provider will tell us a session ended.
    ///
    /// Read at startup and reported, per RFC 0009: back-channel logout absent is a `Degraded`
    /// condition and a fallback to periodic revalidation, never a silent twelve-hour window.
    #[serde(default)]
    pub backchannel_logout_supported: bool,
    /// Whether the logout token carries a `sid`.
    #[serde(default)]
    pub backchannel_logout_session_supported: bool,
    /// Where an opaque token can be asked about (RFC 7662). Absent on issuers that publish none,
    /// which is a refusal to start when `bearer.introspection.enabled` is on: the feature would
    /// otherwise look configured and deny every non-browser caller on the platform it exists for.
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
    /// Which claims this issuer says it can put in a token. Read for one purpose: to check that
    /// `claims.username` is one of them *before* the first request, because a claim mapping that
    /// is wrong locks every developer out of their own endpoint and looks, from the outside, like
    /// the feature working.
    #[serde(default)]
    pub claims_supported: Vec<String>,
}

impl Discovery {
    /// Whether this issuer advertises the claim every owner check compares.
    ///
    /// `None` when the issuer publishes no `claims_supported` at all, which is common and not an
    /// error — the check is then deferred to the first sign-in, where a missing username claim
    /// is an `unusable_id_token` rather than a silent allow.
    pub fn advertises_claim(&self, claim: &str) -> Option<bool> {
        if self.claims_supported.is_empty() {
            return None;
        }
        Some(self.claims_supported.iter().any(|known| known == claim))
    }
}

/// Fetch the issuer's discovery document.
pub async fn discover(issuer: &str) -> Result<Discovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    crate::outbound::client()
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|err| format!("discovery at {url}: {err}"))?
        .json::<Discovery>()
        .await
        .map_err(|err| format!("discovery at {url} is not a discovery document: {err}"))
}

/// The issuer's signing keys, refreshed in the background.
///
/// A generation counter beside the keys, because RFC 0009's identity cache is keyed by token hash
/// and a rotation has to be able to invalidate it: bumping the generation is how "these claims
/// were verified against keys we no longer publish" becomes a cache miss rather than a stale
/// allow.
#[derive(Clone, Default)]
pub struct JwksCache {
    inner: Arc<RwLock<JwksState>>,
    /// Wakes [`refresh_jwks`] early — on a token naming a `kid` this cache does not hold, which
    /// is what a rotation looks like from the verifier's side before the next scheduled fetch.
    wake: Arc<tokio::sync::Notify>,
    /// When the last on-demand refresh was asked for, seconds since the epoch — the rate limit
    /// that keeps a flood of tokens with invented `kid`s from becoming a flood of JWKS fetches.
    last_demand: Arc<std::sync::atomic::AtomicU64>,
    /// How many on-demand refreshes have been asked for, for tests and the curious.
    demands: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Default)]
struct JwksState {
    keys: Option<JwkSet>,
    /// Every key of `keys` with a `kid`, already turned into the form a verification takes —
    /// built once per key-set change rather than on every first-seen bearer, which used to clone
    /// the whole set and rebuild the key each time. `None` for a key `DecodingKey::from_jwk`
    /// refuses, so the refusal is remembered rather than recomputed.
    decoding: HashMap<String, Option<Arc<DecodingKey>>>,
    generation: u64,
}

/// What [`JwksCache::key`] found under a `kid`.
pub enum KeyLookup {
    /// No key set has been fetched yet.
    NoKeys,
    /// The set holds no key under that `kid`.
    Unknown,
    /// The set holds one, and it is not a key this gateway can verify with.
    Unusable,
    /// The key, ready to verify with.
    Found(Arc<DecodingKey>),
}

/// At most one on-demand JWKS refresh per this many seconds, however many unknown `kid`s arrive.
pub const ON_DEMAND_REFRESH_MIN_INTERVAL_SECS: u64 = 30;

impl JwksCache {
    /// Replace the key set. The generation is bumped **only when the set changed**: every
    /// bump drops the verified-bearer cache, and a scheduled refresh that fetched the same keys
    /// again used to do that every ten minutes for nothing.
    pub fn store(&self, keys: JwkSet) {
        if let Ok(mut state) = self.inner.write() {
            if state.keys.as_ref() == Some(&keys) {
                return;
            }
            state.decoding = keys
                .keys
                .iter()
                .filter_map(|jwk| {
                    let kid = jwk.common.key_id.clone()?;
                    Some((kid, DecodingKey::from_jwk(jwk).ok().map(Arc::new)))
                })
                .collect();
            state.keys = Some(keys);
            state.generation += 1;
        }
    }

    /// Ask for an early refresh because a token named a key this cache does not hold. Returns
    /// whether the request was passed on — `false` inside the rate-limit window.
    pub fn request_refresh(&self, now: Timestamp) -> bool {
        use std::sync::atomic::Ordering;

        let now = now.as_secs();
        let last = self.last_demand.load(Ordering::Relaxed);
        if last != 0 && now < last.saturating_add(ON_DEMAND_REFRESH_MIN_INTERVAL_SECS) {
            return false;
        }
        if self
            .last_demand
            .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Another request won the race and has already asked.
            return false;
        }
        self.demands.fetch_add(1, Ordering::Relaxed);
        self.wake.notify_one();
        true
    }

    /// Wait until [`Self::request_refresh`] asks for an early fetch — what a refresh loop
    /// selects on beside its schedule.
    pub async fn woken(&self) {
        self.wake.notified().await;
    }

    /// How many on-demand refreshes have been passed on.
    #[cfg(test)]
    pub fn on_demand_refreshes(&self) -> u64 {
        self.demands.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The verification key under `kid`, without copying the key set.
    pub fn key(&self, kid: &str) -> KeyLookup {
        let Ok(state) = self.inner.read() else {
            return KeyLookup::NoKeys;
        };
        if state.keys.is_none() {
            return KeyLookup::NoKeys;
        }
        match state.decoding.get(kid) {
            None => KeyLookup::Unknown,
            Some(None) => KeyLookup::Unusable,
            Some(Some(key)) => KeyLookup::Found(Arc::clone(key)),
        }
    }

    /// The generation alone — read on every request, so it must not copy the key set the way
    /// [`Self::snapshot`] does.
    pub fn generation(&self) -> u64 {
        self.inner.read().map(|state| state.generation).unwrap_or(0)
    }

    /// The current key set and its generation — a copy, so tests only; the request path reads
    /// [`Self::key`] and [`Self::generation`].
    #[cfg(test)]
    pub fn snapshot(&self) -> (Option<JwkSet>, u64) {
        match self.inner.read() {
            Ok(state) => (state.keys.clone(), state.generation),
            Err(_) => (None, 0),
        }
    }

    /// Whether any key is loaded — what `/readyz` asks before answering, since a gateway with no
    /// keys denies every bearer in the cluster.
    pub fn is_loaded(&self) -> bool {
        self.inner
            .read()
            .map(|state| state.keys.is_some())
            .unwrap_or(false)
    }
}

/// How soon a failed JWKS fetch is retried while no key has ever been loaded, and the most that
/// retry ever waits.
pub const JWKS_RETRY_INITIAL: Duration = Duration::from_secs(1);
/// See [`JWKS_RETRY_INITIAL`].
pub const JWKS_RETRY_MAX: Duration = Duration::from_secs(60);

/// Keep [`JwksCache`] current, forever. One fetch now, then every `interval`.
///
/// **While no key is loaded, a failure is retried with backoff rather than on the schedule**
/// (second-pass finding 4): a replica with no keys fails `/readyz`, and the loop used to sleep the
/// full ten-minute interval after a failed first fetch, so one blip at boot kept the replica out
/// of the rotation for ten minutes with nothing retrying.
pub async fn refresh_jwks(jwks_uri: String, cache: JwksCache, interval: Duration) {
    refresh_jwks_with(
        jwks_uri,
        cache,
        interval,
        JWKS_RETRY_INITIAL,
        JWKS_RETRY_MAX,
    )
    .await;
}

/// [`refresh_jwks`] with the retry timings as parameters, so a test does not wait a second.
pub async fn refresh_jwks_with(
    jwks_uri: String,
    cache: JwksCache,
    interval: Duration,
    retry_initial: Duration,
    retry_max: Duration,
) {
    let client = crate::outbound::client();
    let mut retry = retry_initial;
    loop {
        let fetched = match client
            .get(&jwks_uri)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(response) => match response.json::<JwkSet>().await {
                Ok(keys) => {
                    cache.store(keys);
                    true
                }
                Err(err) => {
                    eprintln!("WARN endpoint-gateway: JWKS at {jwks_uri} unreadable: {err}");
                    false
                }
            },
            Err(err) => {
                eprintln!("WARN endpoint-gateway: JWKS fetch failed: {err}");
                false
            }
        };
        let wait = if !fetched && !cache.is_loaded() {
            let wait = retry.min(interval);
            retry = retry.saturating_mul(2).min(retry_max);
            wait
        } else {
            retry = retry_initial;
            interval
        };
        // The schedule, or earlier when a token named a key we do not hold (rate-limited at the
        // asking end, in `JwksCache::request_refresh`).
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = cache.woken() => {}
        }
    }
}

/// What one verification concluded, in full: the shape, which check answered, and the identity
/// where there is one.
///
/// Richer than [`TokenOutcome`] on purpose. The decision only needs "ours, foreign or invalid";
/// the metric needs to know *which* of the checks refused, and `--explain-token` needs to print
/// it back to the developer whose `fetch` wrapper is not the problem.
pub struct Examination {
    /// JWT or opaque.
    pub shape: TokenShape,
    /// Which check answered.
    pub result: BearerResult,
    /// The caller and the token's own deadline, where the token is an identity.
    pub identity: Option<(Claims, Timestamp)>,
    /// What was read off the token, where enough of it was readable to say.
    pub presented: Option<PresentedToken>,
}

/// Which shape arrived and which check refused it, before there is an [`Examination`] to put it
/// in — kept small on purpose, since it is the `Err` half of the hot path's own decoder.
type Refusal = (TokenShape, BearerResult);

impl Examination {
    fn refused(shape: TokenShape, result: BearerResult) -> Self {
        Self {
            shape,
            result,
            identity: None,
            presented: None,
        }
    }

    /// What `--check --explain-token` prints: one line per check, the failing one named, and the
    /// change that would make the token work.
    ///
    /// A function returning lines rather than a run of `println!`, so the output a developer is
    /// going to paste into an issue has a test — this command exists to end an afternoon of
    /// guessing, and an unreadable answer is the same afternoon.
    pub fn report(&self, issuer: &str, now: Timestamp) -> Vec<String> {
        let mut lines = Vec::new();
        match self.presented.as_ref() {
            None => lines.push(format!(
                "issuer    FAIL  nothing verifiable here — {}",
                match self.shape {
                    TokenShape::Opaque =>
                        "this is not a JWT, so only introspection could resolve it",
                    _ => "no published key matches this token, or its signature does not check out",
                }
            )),
            Some(presented) => {
                lines.push(format!(
                    "issuer    {}  {}",
                    tick(presented.issuer.as_deref() == Some(issuer)),
                    presented.issuer.as_deref().unwrap_or("(no iss claim)")
                ));
                lines.push(format!(
                    "shape     JWT, typ={}, {}",
                    presented.token_type.as_deref().unwrap_or("(none)"),
                    match presented.expires_at {
                        Some(exp) if !now.is_at_or_after(exp) =>
                            format!("exp in {}", human(exp.as_secs() - now.as_secs())),
                        Some(exp) =>
                            format!("expired {} ago", human(now.as_secs() - exp.as_secs())),
                        None => "no exp".to_owned(),
                    }
                ));
                lines.push(format!(
                    "audience  {}  aud=[{}] azp={}",
                    tick(self.result != BearerResult::WrongAudience),
                    presented
                        .audiences
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", "),
                    presented.authorized_party.as_deref().unwrap_or("(none)")
                ));
            }
        }
        lines.push(format!(
            "verdict   {}  {}",
            tick(self.result.is_identity()),
            self.result
        ));
        lines.push(format!("          {}", self.result.advice()));
        if let Some((claims, _)) = self.identity.as_ref() {
            lines.push(format!(
                "          this gateway would call you {}",
                claims.username
            ));
            if claims.session.is_some() {
                // Said out loud rather than implied: `--check` has no cluster, so the one check
                // it cannot make is the one against the live revocation set.
                lines.push(
                    "          the token names a session; a running gateway also checks it \
                     against the revocation set, which this command has no cluster to read"
                        .to_owned(),
                );
            }
        }
        lines
    }
}

fn tick(ok: bool) -> &'static str {
    if ok { "ok  " } else { "FAIL" }
}

/// Seconds as something a person reads at a glance.
fn human(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs}s"),
        60..3_600 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3_600, (secs % 3_600) / 60),
    }
}

/// Verifies a bearer against the cached keys. Synchronous, by construction.
///
/// **What this adapter owns is the cryptography; what makes a token *ours* is the domain's.** The
/// signature, the key and the algorithm are checked here, and everything after that — audience,
/// the ID-token refusal, expiry, revocation — is [`BearerRules::check`], so the table that
/// specifies it runs with no keys and no identity provider and there is exactly one
/// implementation of it. `jsonwebtoken`'s own `aud`, `exp` and `nbf` validation is therefore
/// turned *off*: a second implementation of a check would answer "invalid" where this one has to
/// answer *which* check refused.
pub struct JwksVerifier {
    cache: JwksCache,
    issuer: String,
    client_id: String,
    rules: Option<BearerRules>,
    revocations: Arc<dyn RevocationStore>,
    metrics: Option<GatewayMetrics>,
    username_claim: String,
    groups_claim: String,
}

/// Everything a [`JwksVerifier`] is built from — a struct rather than eight positional arguments,
/// two of which are claim names and three of which are strings.
pub struct VerifierPorts {
    /// The background-refreshed key set.
    pub cache: JwksCache,
    /// The issuer whose tokens are ours.
    pub issuer: String,
    /// This gateway's OIDC client id — the audience an ID token and a logout token carry.
    pub client_id: String,
    /// What makes a bearer ours. `None` where `verify_own_issuer` is off, which turns the whole
    /// branch into "every bearer is foreign".
    pub rules: Option<BearerRules>,
    /// Sessions the identity provider has ended, so a back-channel logout kills the access tokens
    /// minted from that session and not only its cookies.
    pub revocations: Arc<dyn RevocationStore>,
    /// Where `weebo_si_endpoint_auth_bearer_total` is recorded. `None` in a unit test.
    pub metrics: Option<GatewayMetrics>,
    /// Which claim carries the username.
    pub username_claim: String,
    /// Which claim carries the groups.
    pub groups_claim: String,
}

impl JwksVerifier {
    /// Build a verifier.
    pub fn new(ports: VerifierPorts) -> Self {
        // Every path that verifies a bearer goes through a verifier, so constructing one is the
        // last moment `ring` can still become the provider — see `jwt_crypto::install`.
        crate::adapters::jwt_crypto::install();
        Self {
            cache: ports.cache,
            issuer: ports.issuer,
            client_id: ports.client_id,
            rules: ports.rules,
            revocations: ports.revocations,
            metrics: ports.metrics,
            username_claim: ports.username_claim,
            groups_claim: ports.groups_claim,
        }
    }

    /// The issuer a bearer must name to be ours — and so to cost a signature verification.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The generation the keys are at — the value the identity cache is invalidated on.
    pub fn generation(&self) -> u64 {
        self.cache.generation()
    }

    /// Whether any key has been fetched yet. `/readyz` reads this: a replica with no keys
    /// refuses every bearer in the cluster, and refusing traffic is better done by staying out
    /// of the rotation than by answering `401`.
    pub fn keys_loaded(&self) -> bool {
        self.cache.is_loaded()
    }

    /// What makes a bearer ours, for `--check` and for the startup lines.
    pub fn rules(&self) -> Option<&BearerRules> {
        self.rules.as_ref()
    }

    /// Verify one token and say which check answered — without recording anything.
    ///
    /// The non-recording twin of [`TokenVerifier::verify`]. Used by the outbound-header path,
    /// which re-derives the caller on an allow, and by `--explain-token`; counting those would
    /// make the metric a request counter rather than a verification counter.
    pub fn examine(&self, token: &str, now: Timestamp) -> Examination {
        let Some(rules) = self.rules.as_ref() else {
            // `verify_own_issuer: false`. The branch does not exist, so every bearer is somebody
            // else's and only a `bearer: Passthrough` rule reaches the application with it.
            return Examination::refused(TokenShape::Jwt, BearerResult::Foreign);
        };
        // A Kubernetes service-account token is a JWT too, and it is *not* ours: telling the two
        // apart by the issuer claim before doing any cryptography is what keeps a `TokenReview`
        // off the path of every ordinary bearer. An opaque token does not decode at all, and is
        // the introspection verifier's business rather than this one's.
        let claims = match self.decode_verified(token, now) {
            Ok(claims) => claims,
            Err((shape, result)) => return Examination::refused(shape, result),
        };
        let presented = self.presented_from(&claims);
        let result = rules.check(&presented, now, self.revocations.as_ref());
        let identity = result
            .is_identity()
            .then(|| self.claims_from(&claims))
            .flatten();
        Examination {
            shape: TokenShape::Jwt,
            // Verified, and missing the one claim every owner check compares. Not an identity:
            // treating it as one with an empty username would make the owner check compare
            // against nothing.
            result: if result.is_identity() && identity.is_none() {
                BearerResult::Unverifiable
            } else {
                result
            },
            identity,
            presented: Some(presented),
        }
    }

    /// The ID token from a code exchange or a refresh, whose claims become the session.
    ///
    /// A separate entry point rather than a flag on [`Self::examine`], because the two want
    /// opposite things from the same token: the bearer branch refuses an ID token structurally,
    /// and the login path is the one place an ID token is exactly what should have arrived. Its
    /// audience is this gateway's own client id, which is what an ID token's audience *is*.
    pub fn claims_of_id_token(&self, token: &str, now: Timestamp) -> Option<Claims> {
        let claims = self.decode_verified(token, now).ok()?;
        let presented = self.presented_from(&claims);
        if !presented.audiences.contains(&self.client_id) {
            return None;
        }
        match presented.expires_at {
            Some(exp) if !now.is_at_or_after(exp) => {}
            _ => return None,
        }
        self.claims_from(&claims).map(|(claims, _)| claims)
    }

    /// The session a back-channel logout token names, or `None`.
    ///
    /// `/oidc/backchannel-logout` is unauthenticated by design, so the signature is the only thing
    /// that makes this the identity provider's word rather than an attacker's denial of service
    /// against a session. Two structural checks beyond it, both from the specification: the token
    /// must carry the back-channel-logout event, and it must **not** carry a `nonce` — which is
    /// what stops an ID token being replayed here as a logout instruction.
    pub fn session_of_logout_token(&self, token: &str, now: Timestamp) -> Option<SessionId> {
        const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

        let claims = self.decode_verified(token, now).ok()?;
        let presented = self.presented_from(&claims);
        if !presented.audiences.contains(&self.client_id) || presented.nonce {
            return None;
        }
        if !claims
            .get("events")
            .and_then(|events| events.as_object())
            .is_some_and(|events| events.contains_key(EVENT))
        {
            return None;
        }
        // `exp` is optional on a logout token; one that carries a past `exp` is not.
        if presented
            .expires_at
            .is_some_and(|exp| now.is_at_or_after(exp))
        {
            return None;
        }
        presented.session
    }

    /// Signature, key, algorithm and issuer — the half of "is this ours" that needs cryptography.
    ///
    /// `aud`, `exp` and `nbf` are deliberately left to the caller: which of them refused is the
    /// thing the metric and `--explain-token` exist to report, and `jsonwebtoken` would flatten
    /// all three into one error kind.
    fn decode_verified(&self, token: &str, now: Timestamp) -> Result<serde_json::Value, Refusal> {
        let Ok(header) = jsonwebtoken::decode_header(token) else {
            // Not a JWT at all: an opaque access token, which only introspection can resolve.
            return Err((TokenShape::Opaque, BearerResult::Unverifiable));
        };
        let lookup = header
            .kid
            .as_deref()
            .map_or(KeyLookup::Unknown, |kid| self.cache.key(kid));
        if matches!(lookup, KeyLookup::NoKeys) {
            // No keys yet: refusing is the only safe answer, and `/readyz` is already failing
            // for the same reason, so this is a window a cold replica is kept out of the
            // rotation for rather than one it answers wrongly in.
            return Err((TokenShape::Jwt, BearerResult::Unverifiable));
        }
        if matches!(lookup, KeyLookup::Unknown) {
            // A `kid` we do not hold is a forgery, a rotation we have not fetched yet — or, far
            // more often, simply somebody else's token: every service-account token and every
            // foreign issuer's JWT lands here. The *unverified* `iss` tells those apart for free,
            // and only a token claiming to be ours is worth a fetch (second-pass finding 7:
            // every service-account call used to ask for one). Claiming to be ours and naming a
            // key we do not hold is `unverifiable`, not `foreign`: whose it says it is, we know.
            if unverified_issuer(token).as_deref() != Some(self.issuer.as_str()) {
                return Err((TokenShape::Jwt, BearerResult::Foreign));
            }
            if header.kid.is_some() {
                self.cache.request_refresh(now);
            }
            return Err((TokenShape::Jwt, BearerResult::Unverifiable));
        }
        // Alg confusion, closed here rather than trusted from the header: a token naming an
        // algorithm this gateway does not verify with is refused before a key is chosen, so
        // `none` and a symmetric algorithm whose key an attacker supplies are both unreachable.
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err((TokenShape::Jwt, BearerResult::Unverifiable));
        }
        let KeyLookup::Found(key) = lookup else {
            return Err((TokenShape::Jwt, BearerResult::Unverifiable));
        };
        let mut validation = Validation::new(header.alg);
        // Exactly the one algorithm the header names — **after** the allow-list above has already
        // refused anything else, which is where alg confusion is actually closed. Handing
        // `jsonwebtoken` the whole allow-list instead looks stricter and is not: it requires every
        // entry to be the same family as the key, so a list mixing RSA and EC refuses *every*
        // token, on every issuer, with the same `InvalidAlgorithm` a forged one would get.
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.validate_aud = false;
        validation.validate_exp = false;
        validation.validate_nbf = false;
        jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                    (TokenShape::Jwt, BearerResult::Foreign)
                }
                _ => (TokenShape::Jwt, BearerResult::Unverifiable),
            })
    }

    /// The five facts the domain checks, read off a verified token's claims.
    fn presented_from(&self, value: &serde_json::Value) -> PresentedToken {
        presented_from_claims(value, value.get("azp"))
    }

    fn claims_from(&self, value: &serde_json::Value) -> Option<(Claims, Timestamp)> {
        claims_from_values(value, &self.username_claim, &self.groups_claim)
    }
}

/// The `exp` a JWT *claims*, read without verifying anything — good for capping how long a
/// cached answer may live, never for trusting the token. `None` for anything not a JWT payload
/// with a non-negative integer `exp`.
pub fn unverified_exp(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let bytes = B64.decode(payload.trim_end_matches('=')).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("exp")?.as_u64()
}

/// The `iss` a JWT *claims*, read without verifying anything — good for deciding whether a token
/// is worth any further work, and for nothing else.
pub fn unverified_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = B64.decode(payload.trim_end_matches('=')).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value.get("iss")?.as_str().map(str::to_owned)
}

/// Read the five facts off a claim set — a JWT's payload, or an introspection response, which
/// RFC 7662 gives the same names to.
///
/// `party` is where the "who asked for this token" fact lives, and it is the one name the two
/// shapes disagree on: `azp` in a JWT, `client_id` in an introspection response.
pub fn presented_from_claims(
    value: &serde_json::Value,
    party: Option<&serde_json::Value>,
) -> PresentedToken {
    let issuer = value
        .get("iss")
        .and_then(|iss| iss.as_str())
        .unwrap_or_default();
    let mut token = PresentedToken::proved(issuer);
    // `aud` is a string or an array of them, and a gate that read only one shape would accept a
    // token for the wrong audience on every issuer that writes the other.
    token.audiences = match value.get("aud") {
        Some(serde_json::Value::String(one)) => [one.clone()].into_iter().collect(),
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(|audience| audience.as_str())
            .map(str::to_owned)
            .collect(),
        _ => Default::default(),
    };
    token.authorized_party = party.and_then(|party| party.as_str()).map(str::to_owned);
    token.token_type = value
        .get("typ")
        .and_then(|typ| typ.as_str())
        .map(str::to_owned);
    token.at_hash = value.get("at_hash").is_some();
    token.nonce = value.get("nonce").is_some();
    token.expires_at = value
        .get("exp")
        .and_then(|exp| exp.as_u64())
        .map(Timestamp::from_secs);
    token.not_before = value
        .get("nbf")
        .and_then(|nbf| nbf.as_u64())
        .map(Timestamp::from_secs);
    token.session = value
        .get("sid")
        .and_then(|sid| sid.as_str())
        .map(SessionId::new);
    token
}

/// The caller, read off a claim set with the configured claim names.
pub fn claims_from_values(
    value: &serde_json::Value,
    username_claim: &str,
    groups_claim: &str,
) -> Option<(Claims, Timestamp)> {
    let username = value.get(username_claim)?.as_str()?.to_owned();
    let groups = value
        .get(groups_claim)
        .and_then(|groups| groups.as_array())
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| group.as_str())
                .map(GroupName::new)
                .collect()
        })
        .unwrap_or_default();
    let expires_at = Timestamp::from_secs(value.get("exp")?.as_u64()?);
    let session = value
        .get("sid")
        .and_then(|sid| sid.as_str())
        .map(SessionId::new);
    Some((
        Claims {
            username: Username::new(username),
            groups,
            team: None,
            session,
        },
        expires_at,
    ))
}

impl TokenVerifier for JwksVerifier {
    fn verify(&self, token: &str, now: Timestamp) -> TokenOutcome {
        let examination = self.examine(token, now);
        // Counted here rather than in `examine`, so the series counts *verifications* — a page
        // load of two hundred assets pays one, which is the number the identity cache exists to
        // produce and therefore the number worth graphing.
        if let Some(metrics) = self.metrics.as_ref() {
            metrics.bearer(examination.shape, examination.result);
        }
        match (examination.result, examination.identity) {
            (result, Some((claims, expires_at))) if result.is_identity() => {
                TokenOutcome::Ours { claims, expires_at }
            }
            // Somebody else's issuer, or nothing we could read: the service-account branch is
            // tried next, and a `bearer: Passthrough` rule is what reaches the application.
            (BearerResult::Foreign, _) => TokenOutcome::Foreign,
            // Our issuer, refused by one of the checks. Not foreign — we know whose it is — and
            // not an identity either.
            _ => TokenOutcome::Invalid,
        }
    }
}

/// Algorithms this gateway will verify with. Named rather than inherited from the token's own
/// header alone: `none` is an algorithm, and so is a symmetric one an attacker can supply the key
/// for.
pub const ALLOWED_ALGORITHMS: [Algorithm; 4] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
];

/// The login path: an authorization-code exchange with PKCE.
pub struct OidcClient {
    discovery: Discovery,
    client_id: String,
    client_secret: String,
    redirect_url: String,
    http: reqwest::Client,
}

/// What the token endpoint answered.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    /// The ID token, whose claims become the session.
    pub id_token: String,
    /// The refresh token, sealed into the SSO cookie **only** — never into a host cookie and
    /// never into a grant, because those travel to an endpoint host and a refresh token there
    /// would be a credential the application's own origin could read.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

impl OidcClient {
    /// Build the client.
    pub fn new(
        discovery: Discovery,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Self {
        Self {
            discovery,
            client_id,
            client_secret,
            redirect_url,
            http: crate::outbound::client(),
        }
    }

    /// Where to send a browser, and the verifier to keep for the exchange.
    pub fn authorization_url(&self, state: &str, verifier: &str) -> String {
        let challenge = pkce_challenge(verifier);
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid+profile+email+groups\
             &state={}&code_challenge={}&code_challenge_method=S256",
            self.discovery.authorization_endpoint,
            urlencode(&self.client_id),
            urlencode(&self.redirect_url),
            urlencode(state),
            challenge,
        )
    }

    /// Exchange a code for tokens.
    pub async fn exchange(&self, code: &str, verifier: &str) -> Result<TokenResponse, String> {
        let response = self
            .http
            .post(&self.discovery.token_endpoint)
            .timeout(Duration::from_secs(10))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_url.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|err| format!("token endpoint: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("token endpoint answered {}", response.status()));
        }
        response
            .json::<TokenResponse>()
            .await
            .map_err(|err| format!("token endpoint response: {err}"))
    }

    /// Re-prove a session at the token endpoint, which also renews its claims — RFC 0009's
    /// periodic revalidation, lazily and only on use.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, String> {
        let response = self
            .http
            .post(&self.discovery.token_endpoint)
            .timeout(Duration::from_secs(10))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|err| format!("token endpoint: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("refresh answered {}", response.status()));
        }
        response
            .json::<TokenResponse>()
            .await
            .map_err(|err| format!("refresh response: {err}"))
    }

    /// The discovery document this client was built from.
    pub fn discovery(&self) -> &Discovery {
        &self.discovery
    }
}

/// The S256 PKCE challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    B64.encode(Sha256::digest(verifier.as_bytes()))
}

/// Percent-encode everything that is not unreserved — enough for the query parameters this file
/// builds, and deliberately not a general-purpose URL library.
pub fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing, and a fixture that does not build names \
              itself in the message"
)]
mod tests {
    use super::*;

    /// A verifier with no revocation store behind it — the shape a unit test wants, where the
    /// interesting property is the cryptography rather than the session set.
    struct NoRevocations;
    impl RevocationStore for NoRevocations {
        fn is_revoked(&self, _session: &SessionId) -> bool {
            false
        }
    }

    fn verifier(cache: JwksCache, rules: Option<BearerRules>) -> JwksVerifier {
        JwksVerifier::new(VerifierPorts {
            cache,
            issuer: ISSUER.into(),
            client_id: "che-client".into(),
            rules,
            revocations: Arc::new(NoRevocations),
            metrics: None,
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
        })
    }

    const ISSUER: &str = "https://sso.weebo.si/realms/weebo";

    fn rules() -> BearerRules {
        #[allow(
            clippy::expect_used,
            reason = "a fixture rule set that does not build is the test suite failing to start"
        )]
        BearerRules::new(ISSUER, ["endpoint-gateway"], Vec::<String>::new())
            .expect("fixture rules must build")
    }

    /// A throwaway ES256 keypair and the JWKS that publishes it.
    ///
    /// Generated per test run rather than checked in: a private key in a repository is a finding
    /// whatever the comment above it says, and generating one costs a millisecond.
    struct Realm {
        key: jsonwebtoken::EncodingKey,
        keys: JwkSet,
    }

    impl Realm {
        fn new() -> Self {
            use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

            // Before the first token is minted: signing fixes the provider too.
            crate::adapters::jwt_crypto::install();

            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .expect("a keypair must be generatable");
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("the generated keypair must load");
            // SEC1 uncompressed point: 0x04 ‖ x ‖ y, 32 bytes each for P-256.
            let point = pair.public_key().as_ref().to_vec();
            let keys = serde_json::from_value::<JwkSet>(serde_json::json!({
                "keys": [{
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "kid": KID,
                    "x": B64.encode(&point[1..33]),
                    "y": B64.encode(&point[33..65]),
                }]
            }))
            .expect("the JWKS must build");
            Self {
                key: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()),
                keys,
            }
        }

        /// Mint a token this realm's key signed, whatever is in it.
        fn mint(&self, claims: serde_json::Value) -> String {
            self.mint_with_kid(KID, claims)
        }

        fn mint_with_kid(&self, kid: &str, claims: serde_json::Value) -> String {
            let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
            header.kid = Some(kid.to_owned());
            jsonwebtoken::encode(&header, &claims, &self.key).expect("the token must sign")
        }

        fn cache(&self) -> JwksCache {
            let cache = JwksCache::default();
            cache.store(self.keys.clone());
            cache
        }
    }

    const KID: &str = "test-key";

    /// The bearer branch against real cryptography, one row per outcome.
    ///
    /// The domain's own table already covers the checks; this is the wire-level half — a token
    /// **signed by the realm's own key**, which is exactly the token `verify_own_issuer: true`
    /// used to accept unconditionally. The third row is the one this section exists for.
    #[test]
    fn a_signed_token_is_only_an_identity_when_it_is_also_for_us() {
        let realm = Realm::new();
        let verifier = verifier(realm.cache(), Some(rules()));
        let now = Timestamp::from_secs(1_000);
        let base = serde_json::json!({
            "iss": ISSUER,
            "aud": "endpoint-gateway",
            "exp": 2_000,
            "preferred_username": "alice",
            "typ": "Bearer",
        });
        let with = |patch: serde_json::Value| {
            let mut claims = base.clone();
            for (key, value) in patch.as_object().into_iter().flatten() {
                claims[key.as_str()] = value.clone();
            }
            claims
        };

        let cases: &[(&str, serde_json::Value, BearerResult)] = &[
            ("ours, for us, live", base.clone(), BearerResult::Accepted),
            (
                "our realm's key, another client's audience — the confused deputy",
                with(serde_json::json!({"aud": "their-app", "azp": "their-app"})),
                BearerResult::WrongAudience,
            ),
            (
                "the ID token from the same exchange",
                with(serde_json::json!({"at_hash": "ZmFrZQ", "typ": "ID"})),
                BearerResult::IdToken,
            ),
            (
                "expired",
                with(serde_json::json!({"exp": 999})),
                BearerResult::Expired,
            ),
            (
                "another issuer's claim, this realm's signature",
                with(serde_json::json!({"iss": "https://sso.example.test/realms/other"})),
                BearerResult::Foreign,
            ),
            (
                "verified, and missing the claim every owner check compares",
                serde_json::json!({"iss": ISSUER, "aud": "endpoint-gateway", "exp": 2_000}),
                BearerResult::Unverifiable,
            ),
        ];
        for (why, claims, expected) in cases {
            let examined = verifier.examine(&realm.mint(claims.clone()), now);
            assert_eq!(examined.result, *expected, "{why}");
            assert_eq!(examined.shape, TokenShape::Jwt, "{why}");
            assert_eq!(examined.identity.is_some(), expected.is_identity(), "{why}");
        }

        // A token whose claims are all correct and whose *signature* is somebody else's is
        // `unverifiable` rather than `foreign`: the issuer claim is ours, so "this is not our
        // issuer's" would be the wrong thing to tell anybody. Forged with the same `kid` on
        // purpose — a forger picks the key id the real one publishes.
        let elsewhere = Realm::new();
        assert_eq!(
            verifier.examine(&elsewhere.mint(base), now).result,
            BearerResult::Unverifiable
        );
    }

    /// The login path wants the opposite thing from the same token, and gets it through its own
    /// entry point — otherwise the structural ID-token refusal would break every sign-in.
    #[test]
    fn the_id_token_the_bearer_branch_refuses_is_the_one_the_login_path_needs() {
        let realm = Realm::new();
        let verifier = verifier(realm.cache(), Some(rules()));
        let now = Timestamp::from_secs(1_000);
        let id_token = realm.mint(serde_json::json!({
            "iss": ISSUER,
            "aud": "che-client",
            "exp": 2_000,
            "at_hash": "ZmFrZQ",
            "typ": "ID",
            "sid": "sid-1",
            "preferred_username": "alice",
        }));
        assert_eq!(
            verifier.examine(&id_token, now).result,
            BearerResult::IdToken
        );
        let claims = verifier
            .claims_of_id_token(&id_token, now)
            .expect("the login path must accept its own ID token");
        assert_eq!(claims.username.as_str(), "alice");

        // And the login path is not a way back in for an ID token minted for somebody else.
        let theirs = realm.mint(serde_json::json!({
            "iss": ISSUER, "aud": "their-app", "exp": 2_000, "preferred_username": "alice",
        }));
        assert!(verifier.claims_of_id_token(&theirs, now).is_none());
    }

    /// `/oidc/backchannel-logout` is unauthenticated by design, so the signature is the only thing
    /// that makes a logout token the identity provider's word — and the two structural checks are
    /// what stop an ID token being replayed there as an instruction to end somebody's session.
    #[test]
    fn a_logout_token_is_a_logout_token_and_not_any_signed_token_with_a_sid() {
        let realm = Realm::new();
        let verifier = verifier(realm.cache(), Some(rules()));
        let now = Timestamp::from_secs(1_000);
        let logout = serde_json::json!({
            "iss": ISSUER,
            "aud": "che-client",
            "exp": 2_000,
            "sid": "sid-1",
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        });
        assert_eq!(
            verifier
                .session_of_logout_token(&realm.mint(logout.clone()), now)
                .map(|sid| sid.as_str().to_owned()),
            Some("sid-1".to_owned())
        );

        let mut without_event = logout.clone();
        without_event["events"] = serde_json::json!({});
        assert!(
            verifier
                .session_of_logout_token(&realm.mint(without_event), now)
                .is_none()
        );

        // An ID token carries a `sid` and a `nonce`, and is not an instruction.
        let mut id_token = logout;
        id_token["nonce"] = serde_json::json!("n-0S6_WzA2Mj");
        assert!(
            verifier
                .session_of_logout_token(&realm.mint(id_token), now)
                .is_none()
        );
    }

    /// What `--check --explain-token` prints. The command exists to end an afternoon of a
    /// developer reading their own `fetch` wrapper, so the answer it gives is worth a test:
    /// which line failed, and what to change.
    #[test]
    fn explaining_a_refused_token_names_the_check_and_the_fix() {
        let realm = Realm::new();
        let verifier = verifier(realm.cache(), Some(rules()));
        let now = Timestamp::from_secs(1_000);
        let token = realm.mint(serde_json::json!({
            "iss": ISSUER,
            "aud": "account",
            "azp": "che-client",
            "exp": 1_252,
            "typ": "Bearer",
            "preferred_username": "alice",
        }));
        let report = verifier.examine(&token, now).report(ISSUER, now).join("\n");

        assert!(
            report.contains("issuer    ok    https://sso.weebo.si/realms/weebo"),
            "{report}"
        );
        assert!(
            report.contains("shape     JWT, typ=Bearer, exp in 4m12s"),
            "{report}"
        );
        assert!(
            report.contains("audience  FAIL  aud=[account] azp=che-client"),
            "{report}"
        );
        assert!(report.contains("wrong_audience"), "{report}");
        // The fix, not just the diagnosis.
        assert!(report.contains("audience mapper"), "{report}");
        assert!(report.contains("bearer.authorized_parties"), "{report}");
        // Nothing here leaks the token itself.
        assert!(!report.contains(&token), "{report}");

        // And an accepted one says who this gateway would call you, which is the other half of
        // "confirm it is accepted before anyone depends on it".
        let good = realm.mint(serde_json::json!({
            "iss": ISSUER, "aud": "endpoint-gateway", "exp": 2_000, "preferred_username": "alice",
        }));
        let report = verifier.examine(&good, now).report(ISSUER, now).join("\n");
        assert!(report.contains("verdict   ok    accepted"), "{report}");
        assert!(report.contains("would call you alice"), "{report}");

        // An opaque token has no claims to report, and the line says which of the two reasons.
        let opaque = verifier.examine("sha256~not-a-jwt-at-all", now);
        let report = opaque.report(ISSUER, now).join("\n");
        assert!(report.contains("not a JWT"), "{report}");
    }

    #[test]
    fn a_verifier_with_no_keys_refuses_rather_than_trusting_the_header() {
        let verifier = verifier(JwksCache::default(), Some(rules()));
        // A token whose header says `alg: none` is the oldest JWT attack there is; with no keys
        // loaded the answer is the same as for any other token — nothing is verified.
        let outcome = verifier.verify("not.a.token", Timestamp::from_secs(0));
        assert!(matches!(
            outcome,
            TokenOutcome::Foreign | TokenOutcome::Invalid
        ));
        assert_eq!(verifier.generation(), 0);
    }

    /// `verify_own_issuer: false` turns the whole branch off rather than leaving it open: with no
    /// rules there is no way for a token to be ours, and only a `bearer: Passthrough` path rule
    /// reaches the application with one.
    #[test]
    fn no_rules_means_every_bearer_is_somebody_elses() {
        let verifier = verifier(JwksCache::default(), None);
        let examined = verifier.examine("anything.at.all", Timestamp::from_secs(0));
        assert_eq!(examined.result, BearerResult::Foreign);
        assert!(examined.identity.is_none());
    }

    /// An opaque token is not refused for being unsigned — it is refused for being unreadable
    /// *here*, which is the introspection verifier's business and the reason the two shapes get
    /// different labels in the metric.
    #[test]
    fn an_opaque_token_is_labelled_opaque_rather_than_invalid() {
        let verifier = verifier(JwksCache::default(), Some(rules()));
        let examined = verifier.examine("sha256~not-a-jwt-at-all", Timestamp::from_secs(0));
        assert_eq!(examined.shape, TokenShape::Opaque);
        assert_eq!(examined.result, BearerResult::Unverifiable);
    }

    /// The reader both verifiers share, over the shapes an issuer actually writes: `aud` as a
    /// string on one realm and as an array on the next, which is where a gate that read only one
    /// of them would accept a token minted for the wrong audience.
    #[test]
    fn audiences_are_read_whether_the_issuer_writes_one_or_many() {
        let one = presented_from_claims(
            &serde_json::json!({"iss": ISSUER, "aud": "endpoint-gateway", "exp": 9}),
            None,
        );
        assert!(one.audiences.contains("endpoint-gateway"));
        let many = presented_from_claims(
            &serde_json::json!({"iss": ISSUER, "aud": ["account", "endpoint-gateway"]}),
            Some(&serde_json::json!("che-client")),
        );
        assert!(many.audiences.contains("endpoint-gateway"));
        assert_eq!(many.authorized_party.as_deref(), Some("che-client"));
        // And an ID token is recognisable from the claim set alone, with no key in sight.
        let id_token = presented_from_claims(
            &serde_json::json!({"iss": ISSUER, "aud": "che-client", "at_hash": "x"}),
            None,
        );
        assert!(id_token.is_id_token());
    }

    #[test]
    fn the_pkce_challenge_is_the_s256_of_the_verifier() {
        // The one test vector from RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn urlencoding_covers_what_a_redirect_uri_actually_contains() {
        // Built rather than written out: the expected string is a run of percent escapes, and a
        // literal one in a test is a thing reviewers skim and spellcheckers trip over.
        let encoded = urlencode("https://auth.weebo.si/oidc/callback");
        assert_eq!(encoded.matches("%3A").count(), 1);
        assert_eq!(encoded.matches("%2F").count(), 4);
        assert!(!encoded.contains('/'), "{encoded}");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn an_issuer_that_does_not_advertise_the_username_claim_is_reported_before_the_first_request() {
        let mut discovery = Discovery {
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            backchannel_logout_supported: false,
            backchannel_logout_session_supported: false,
            introspection_endpoint: None,
            claims_supported: vec!["sub".into(), "email".into()],
        };
        assert_eq!(
            discovery.advertises_claim("preferred_username"),
            Some(false)
        );
        discovery.claims_supported.push("preferred_username".into());
        assert_eq!(discovery.advertises_claim("preferred_username"), Some(true));
        // An issuer that publishes no list at all is not evidence of absence.
        discovery.claims_supported.clear();
        assert_eq!(discovery.advertises_claim("preferred_username"), None);
    }

    #[test]
    fn a_jwks_generation_bump_is_what_invalidates_a_cached_identity() {
        let cache = JwksCache::default();
        assert!(!cache.is_loaded());
        cache.store(JwkSet { keys: Vec::new() });
        assert!(cache.is_loaded());
        assert_eq!(cache.snapshot().1, 1);
        let rotated = Realm::new().cache().snapshot().0.unwrap();
        cache.store(rotated.clone());
        assert_eq!(cache.snapshot().1, 2);
    }

    /// M3: a refresh that fetched the same keys again bumped the generation, which drops every
    /// verified bearer the gateway had cached — every ten minutes, for nothing.
    #[test]
    fn storing_the_same_key_set_again_is_not_a_rotation() {
        let keys = Realm::new().cache().snapshot().0.unwrap();
        let cache = JwksCache::default();
        cache.store(keys.clone());
        cache.store(keys.clone());
        cache.store(keys);
        assert_eq!(cache.snapshot().1, 1);
    }

    /// M3: a token naming a `kid` the cache does not hold asks for an early refresh — once per
    /// window, however many such tokens arrive.
    #[test]
    fn an_unknown_kid_asks_for_a_refresh_and_a_flood_of_them_asks_once() {
        let known = Realm::new();
        let stranger = Realm::new();
        let cache = known.cache();
        let verifier = verifier(cache.clone(), Some(rules()));
        let token = stranger.mint_with_kid(
            "rotated-key",
            serde_json::json!({
                "iss": "https://sso.weebo.si/realms/weebo",
                "aud": "endpoint-gateway",
                "preferred_username": "alice",
                "exp": 4_000_000_000_u64,
            }),
        );
        for _ in 0..100 {
            let _ = verifier.examine(&token, Timestamp::from_secs(1_000));
        }
        assert_eq!(cache.on_demand_refreshes(), 1);
        // The next window asks again.
        let _ = verifier.examine(
            &token,
            Timestamp::from_secs(1_000 + ON_DEMAND_REFRESH_MIN_INTERVAL_SECS),
        );
        assert_eq!(cache.on_demand_refreshes(), 2);
        // A key we do hold asks for nothing.
        let ours = known.mint(serde_json::json!({
            "iss": "https://sso.weebo.si/realms/weebo",
            "aud": "endpoint-gateway",
            "preferred_username": "alice",
            "exp": 4_000_000_000_u64,
        }));
        let _ = verifier.examine(&ours, Timestamp::from_secs(10_000));
        assert_eq!(cache.on_demand_refreshes(), 2);
    }

    /// Second-pass finding 4: a JWKS fetch that failed at boot was retried only after the full
    /// ten-minute interval, keeping the replica unready (no keys) for all of it.
    #[tokio::test]
    async fn a_failed_first_jwks_fetch_is_retried_with_backoff_not_on_the_schedule() {
        use axum::routing::get;

        let keys = Realm::new().keys;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/certs",
            get(move || {
                let counted = Arc::clone(&counted);
                let keys = keys.clone();
                async move {
                    let call = counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if call < 2 {
                        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down").into_response()
                    } else {
                        axum::Json(keys).into_response()
                    }
                }
            }),
        );
        use axum::response::IntoResponse;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let cache = JwksCache::default();
        tokio::spawn(refresh_jwks_with(
            format!("http://{address}/certs"),
            cache.clone(),
            Duration::from_secs(600),
            Duration::from_millis(10),
            Duration::from_millis(40),
        ));
        let started = std::time::Instant::now();
        while !cache.is_loaded() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "the keys never loaded: the failure waited for the schedule"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    /// Second-pass finding 7: an unknown `kid` asked for a refresh on *every* JWT, and every
    /// service-account token or foreign issuer's token carries a `kid` this cache will never hold.
    /// Only a token whose (unverified) `iss` is ours is worth a fetch — and only such a token is
    /// `unverifiable` rather than `foreign`.
    #[test]
    fn only_a_token_claiming_our_issuer_asks_for_a_refresh_on_an_unknown_kid() {
        let known = Realm::new();
        let stranger = Realm::new();
        let cache = known.cache();
        let verifier = verifier(cache.clone(), Some(rules()));
        let now = Timestamp::from_secs(1_000);
        for iss in [
            "https://kubernetes.default.svc.cluster.local",
            "https://sso.example.test/realms/other",
        ] {
            let theirs = stranger.mint_with_kid(
                "their-key",
                serde_json::json!({"iss": iss, "aud": "x", "exp": 4_000_000_000_u64}),
            );
            let examined = verifier.examine(&theirs, now);
            assert_eq!(examined.result, BearerResult::Foreign, "{iss}");
        }
        assert_eq!(cache.on_demand_refreshes(), 0);

        let claims_ours = stranger.mint_with_kid(
            "rotated-key",
            serde_json::json!({"iss": ISSUER, "aud": "endpoint-gateway", "exp": 4_000_000_000_u64}),
        );
        assert_eq!(
            verifier.examine(&claims_ours, now).result,
            BearerResult::Unverifiable
        );
        assert_eq!(cache.on_demand_refreshes(), 1);
    }
}
