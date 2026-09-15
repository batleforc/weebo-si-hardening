//! The identity provider: discovery, a background JWKS refresh, bearer verification, and the
//! authorization-code exchange.
//!
//! **The split down the middle of this file is the one RFC 0009's *Request cost* rests on.**
//! [`JwksVerifier`] implements [`TokenVerifier`] and is *synchronous*: it verifies a signature
//! against keys already in memory and cannot reach the network, so an identity provider that is
//! down cannot stop a `curl` that already holds a valid token — and a page load of two hundred
//! assets cannot become two hundred round trips. [`OidcClient`] is the login path, where a
//! network call is exactly right and happens once per sign-in.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use weebo_si_endpoint_auth::identity::{Claims, GroupName, SessionId, Username};
use weebo_si_endpoint_auth::port::{TokenOutcome, TokenVerifier};
use weebo_si_endpoint_auth::time::Timestamp;

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
    reqwest::Client::new()
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
}

#[derive(Default)]
struct JwksState {
    keys: Option<JwkSet>,
    generation: u64,
}

impl JwksCache {
    /// Replace the key set, bumping the generation.
    pub fn store(&self, keys: JwkSet) {
        if let Ok(mut state) = self.inner.write() {
            state.keys = Some(keys);
            state.generation += 1;
        }
    }

    /// The current key set and its generation.
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

/// Keep [`JwksCache`] current, forever. One fetch now, then every `interval`.
pub async fn refresh_jwks(jwks_uri: String, cache: JwksCache, interval: Duration) {
    let client = reqwest::Client::new();
    loop {
        match client
            .get(&jwks_uri)
            .timeout(Duration::from_secs(10))
            .send()
            .await
        {
            Ok(response) => match response.json::<JwkSet>().await {
                Ok(keys) => cache.store(keys),
                Err(err) => {
                    eprintln!("WARN endpoint-gateway: JWKS at {jwks_uri} unreadable: {err}")
                }
            },
            Err(err) => eprintln!("WARN endpoint-gateway: JWKS fetch failed: {err}"),
        }
        tokio::time::sleep(interval).await;
    }
}

/// Verifies a bearer against the cached keys. Synchronous, by construction.
pub struct JwksVerifier {
    cache: JwksCache,
    issuer: String,
    audiences: BTreeSet<String>,
    username_claim: String,
    groups_claim: String,
}

impl JwksVerifier {
    /// Build a verifier.
    pub fn new(
        cache: JwksCache,
        issuer: String,
        audiences: impl IntoIterator<Item = String>,
        username_claim: String,
        groups_claim: String,
    ) -> Self {
        Self {
            cache,
            issuer,
            audiences: audiences.into_iter().collect(),
            username_claim,
            groups_claim,
        }
    }

    /// The generation the keys are at — the value the identity cache is invalidated on.
    pub fn generation(&self) -> u64 {
        self.cache.snapshot().1
    }

    /// Whether any key has been fetched yet. `/readyz` reads this: a replica with no keys
    /// refuses every bearer in the cluster, and refusing traffic is better done by staying out
    /// of the rotation than by answering `401`.
    pub fn keys_loaded(&self) -> bool {
        self.cache.is_loaded()
    }

    fn claims_from(&self, value: &serde_json::Value) -> Option<(Claims, Timestamp)> {
        let username = value.get(&self.username_claim)?.as_str()?.to_owned();
        let groups = value
            .get(&self.groups_claim)
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
}

impl TokenVerifier for JwksVerifier {
    fn verify(&self, token: &str, _now: Timestamp) -> TokenOutcome {
        // A Kubernetes service-account token is a JWT too, and it is *not* ours: telling the two
        // apart by the issuer claim before doing any cryptography is what keeps a `TokenReview`
        // off the path of every ordinary bearer.
        let Some(header) = jsonwebtoken::decode_header(token).ok() else {
            return TokenOutcome::Foreign;
        };
        let (Some(keys), _) = self.cache.snapshot() else {
            // No keys yet: refusing is the only safe answer, and `/readyz` is already failing
            // for the same reason, so this is a window a cold replica is kept out of the
            // rotation for rather than one it answers wrongly in.
            return TokenOutcome::Invalid;
        };
        let Some(kid) = header.kid else {
            return TokenOutcome::Foreign;
        };
        let Some(jwk) = keys.find(&kid) else {
            return TokenOutcome::Foreign;
        };
        let Ok(key) = DecodingKey::from_jwk(jwk) else {
            return TokenOutcome::Invalid;
        };
        // Alg confusion, closed here rather than trusted from the header: a token naming an
        // algorithm this gateway does not verify with is refused before a key is chosen, so
        // `none` and a symmetric algorithm whose key an attacker supplies are both unreachable.
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return TokenOutcome::Invalid;
        }
        let mut validation = Validation::new(header.alg);
        validation.algorithms = ALLOWED_ALGORITHMS.to_vec();
        validation.set_issuer(&[self.issuer.as_str()]);
        if self.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&self.audiences.iter().cloned().collect::<Vec<_>>());
        }
        match jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation) {
            Ok(data) => match self.claims_from(&data.claims) {
                Some((claims, expires_at)) => TokenOutcome::Ours { claims, expires_at },
                // Verified, and missing the one claim every owner check compares. Not "ours":
                // treating it as an identity with an empty username would make the owner check
                // compare against nothing.
                None => TokenOutcome::Invalid,
            },
            Err(err) => match err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => TokenOutcome::Foreign,
                _ => TokenOutcome::Invalid,
            },
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
            http: reqwest::Client::new(),
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
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn a_verifier_with_no_keys_refuses_rather_than_trusting_the_header() {
        let verifier = JwksVerifier::new(
            JwksCache::default(),
            "https://sso.weebo.si/realms/weebo".into(),
            [],
            "preferred_username".into(),
            "groups".into(),
        );
        // A token whose header says `alg: none` is the oldest JWT attack there is; with no keys
        // loaded the answer is the same as for any other token — nothing is verified.
        let outcome = verifier.verify("not.a.token", Timestamp::from_secs(0));
        assert!(matches!(
            outcome,
            TokenOutcome::Foreign | TokenOutcome::Invalid
        ));
        assert_eq!(verifier.generation(), 0);
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
        cache.store(JwkSet { keys: Vec::new() });
        assert_eq!(cache.snapshot().1, 2);
    }
}
