//! Sealed cookies — RFC 0009's *Two cookies, on purpose*, and the key rotation under *Data and
//! state*.
//!
//! Three sealed payloads, one codec:
//!
//! * the **SSO cookie**, host-only on the gateway's own host, which is the thing a browser
//!   presents once per day;
//! * the **host cookie**, bound to one endpoint host, which is what `/auth` actually reads;
//! * the **one-time grant**, bound to one host and valid for one redirect, which is how the
//!   first is exchanged for the second without ever putting a shared-domain cookie on the
//!   suffix.
//!
//! AEAD rather than a signature, because these carry claims — a username and a group list — that
//! are the identity provider's business and not the browser's. AES-256-GCM with a random 96-bit
//! nonce per seal, and **the host is the associated data**: a cookie sealed for
//! `alice-ws-api.weebo.si` fails to open on any other host even with the right key, which is the
//! cross-host replay RFC 0009's *Security considerations* is built around preventing.
//!
//! Rotation accepts the previous key for the length of `sso_ttl`, so rotating costs no logins:
//! sealing always uses the first key, opening tries each in turn.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use weebo_si_endpoint_auth::host::Host;
use weebo_si_endpoint_auth::identity::{Claims, GroupName, SessionId, Username};
use weebo_si_endpoint_auth::port::{OpenedSession, SessionCodec};
use weebo_si_endpoint_auth::time::Timestamp;

/// The wire form of a sealed session, in whichever cookie carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPayload {
    /// The username claim.
    #[serde(rename = "u")]
    pub username: String,
    /// The groups sealed into this session — *some* of the caller's groups, per RFC 0009's
    /// *Group claims*: only those an endpoint somewhere names.
    #[serde(rename = "g", default)]
    pub groups: Vec<String>,
    /// The identity provider's session id, which back-channel logout revokes by.
    #[serde(rename = "s", default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// Expiry, seconds since the epoch.
    #[serde(rename = "e")]
    pub expires_at: u64,
    /// The generation of the interesting-group set this session was sealed under. A session that
    /// predates the current generation is re-authenticated silently rather than judged on a stale
    /// group list.
    #[serde(rename = "gen", default)]
    pub generation: u64,
    /// A one-time grant's id — present only on a grant, and what makes it one-time.
    #[serde(rename = "j", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    /// When this session was last proved at the identity provider. Periodic revalidation is
    /// measured from here, lazily and only on use, so an idle session costs nothing.
    #[serde(rename = "i", default)]
    pub proved_at: u64,
    /// The refresh token, present on the SSO cookie alone — see [`Binding`].
    #[serde(rename = "r", default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
    /// When the SSO session this value was derived from expires — carried on a grant and on a
    /// host cookie so that re-minting one (sliding) can never outlive the session that proved
    /// it. `None` on the SSO cookie itself, whose own `expires_at` is that bound, and on a host
    /// cookie minted before the field existed, which is then not slid at all (fail closed).
    #[serde(rename = "se", default, skip_serializing_if = "Option::is_none")]
    pub session_expires_at: Option<u64>,
}

/// The sign-in in flight between `/oidc/start` and `/oidc/callback`: where to go afterwards, the
/// PKCE verifier and the `state` value the identity provider must echo.
///
/// **Its own type and its own [`Binding`]**, never a [`SealedPayload`] with fields repurposed.
/// It used to be exactly that — the return URL in `username`, the verifier in `groups`, sealed
/// against the SSO binding — which made the state cookie a valid SSO cookie for a "user" named
/// after whatever `rd` the caller chose: replay `__Host-weebo-state` as `__Host-weebo-sso` and
/// `/host-session` minted a grant for that name. A separate associated data makes the two values
/// mutually unopenable, and a separate type means no field can be read as the other's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginState {
    /// Where to send the browser once signed in — already checked to be an endpoint of this
    /// cluster, or empty.
    #[serde(rename = "rd")]
    pub return_to: String,
    /// The PKCE verifier.
    #[serde(rename = "v")]
    pub verifier: String,
    /// The `state` parameter the identity provider must echo back.
    #[serde(rename = "st")]
    pub state: String,
    /// Expiry, seconds since the epoch.
    #[serde(rename = "e")]
    pub expires_at: u64,
}

impl SealedPayload {
    /// The claims this payload carries. The team is **not** here and never will be: team
    /// membership is authorisation input, and RFC 0009's *Request cost* keeps authorisation
    /// input out of anything cached or sealed.
    pub fn claims(&self) -> Claims {
        Claims {
            username: Username::new(self.username.clone()),
            groups: self.groups.iter().map(GroupName::new).collect(),
            team: None,
            session: self.session.as_ref().map(SessionId::new),
        }
    }
}

/// The associated data a payload is sealed against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding<'a> {
    /// The SSO cookie, on the gateway's own host.
    Sso,
    /// The sign-in state cookie, on the gateway's own host — never openable as [`Self::Sso`].
    LoginState,
    /// A host cookie or a grant, bound to one endpoint host.
    HostBound(&'a str),
}

impl Binding<'_> {
    fn aad(&self) -> &[u8] {
        match self {
            Self::Sso => b"weebo-si/sso",
            Self::LoginState => b"weebo-si/login-state",
            // A hostname is `[a-z0-9.-]` only (`Host::parse`), so it can never equal either
            // constant above, which both contain a `/`.
            Self::HostBound(host) => host.as_bytes(),
        }
    }
}

/// Seals and opens every cookie this gateway mints.
pub struct SealedCodec {
    /// The first is what seals; every one of them may open. Rotation is therefore "prepend the
    /// new key, drop the old one an `sso_ttl` later", and costs nobody a login.
    ciphers: Vec<Aes256Gcm>,
}

/// Why a key set could not be built.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// No key at all — the gateway would mint cookies nothing could open, including itself after
    /// a restart.
    Empty,
    /// A key that is not 32 bytes of base64.
    NotThirtyTwoBytes(usize),
    /// A key that is not base64 at all.
    NotBase64,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("no session key: set ENDPOINT_GATEWAY_SESSION_KEYS"),
            Self::NotThirtyTwoBytes(len) => {
                write!(f, "a session key is {len} bytes; AES-256-GCM needs 32")
            }
            Self::NotBase64 => f.write_str(
                "a session key is not base64 (standard or url-safe, padded or not) — 32 random \
                 bytes, e.g. `openssl rand -base64 32`",
            ),
        }
    }
}

/// Decode one key, in whichever base64 the admin's `openssl`/`head -c32 | base64` happened to
/// produce.
///
/// **Four alphabets, not one.** The cookie payload is url-safe and unpadded because it travels in
/// a header; a *key* travels in a `Secret` and never appears on the wire, so insisting it share
/// that encoding buys nothing and costs a refusal to start. `openssl rand -base64 32` — the
/// command the documentation all but names — emits standard, padded base64, and a gateway that
/// answers "a session key is not base64" to its own documented recipe is a bug in the gateway
/// rather than in the recipe.
fn decode_key(raw: &str) -> Result<Vec<u8>, KeyError> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};

    let raw = raw.trim();
    B64.decode(raw)
        .or_else(|_| URL_SAFE.decode(raw))
        .or_else(|_| STANDARD.decode(raw))
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .map_err(|_| KeyError::NotBase64)
}

impl SealedCodec {
    /// Build a codec from base64 keys, newest first.
    pub fn new(keys: &[String]) -> Result<Self, KeyError> {
        if keys.is_empty() {
            return Err(KeyError::Empty);
        }
        let ciphers = keys
            .iter()
            .map(|raw| {
                let bytes = decode_key(raw)?;
                if bytes.len() != 32 {
                    return Err(KeyError::NotThirtyTwoBytes(bytes.len()));
                }
                let key = Key::<Aes256Gcm>::from_slice(&bytes);
                Ok(Aes256Gcm::new(key))
            })
            .collect::<Result<Vec<_>, KeyError>>()?;
        Ok(Self { ciphers })
    }

    /// Seal `payload` against `binding`.
    ///
    /// `None` only if the platform's random source fails, which is the one failure here that is
    /// not a bug: minting no cookie is correct, and minting one with a predictable nonce is not.
    pub fn seal(&self, payload: &SealedPayload, binding: Binding<'_>) -> Option<String> {
        // The login state has its own type and its own entry point; a `SealedPayload` sealed
        // against its binding is exactly the confusion that binding exists to rule out.
        if binding == Binding::LoginState {
            return None;
        }
        self.seal_json(&serde_json::to_vec(payload).ok()?, binding)
    }

    /// Open a sealed value against `binding`, or `None`.
    ///
    /// Every way of failing returns `None` on purpose: wrong key, wrong host, corrupt, expired.
    /// A caller can act on none of them differently — the answer is always "sign in again" — and
    /// distinguishing them in a response is how an attacker learns which half of a forged cookie
    /// was wrong.
    pub fn open(
        &self,
        sealed: &str,
        binding: Binding<'_>,
        now: Timestamp,
    ) -> Option<SealedPayload> {
        if binding == Binding::LoginState {
            return None;
        }
        let payload: SealedPayload =
            serde_json::from_slice(&self.open_json(sealed, binding)?).ok()?;
        if now.is_at_or_after(Timestamp::from_secs(payload.expires_at)) {
            return None;
        }
        Some(payload)
    }

    /// Whether `value` has the shape of something [`Self::seal`] produced — `v1.`, a 12-byte
    /// nonce and a ciphertext, both base64url — without opening it. What tells a grant this
    /// gateway minted apart from an application's own query parameter that happens to share its
    /// name: only the first is worth redeeming, and refusing the second would make that page
    /// unreachable for everybody.
    pub fn looks_sealed(value: &str) -> bool {
        let mut parts = value.splitn(3, '.');
        parts.next() == Some("v1")
            && parts
                .next()
                .and_then(|nonce| B64.decode(nonce).ok())
                .is_some_and(|nonce| nonce.len() == 12)
            && parts
                .next()
                .is_some_and(|sealed| sealed.len() >= 22 && B64.decode(sealed).is_ok())
    }

    /// Seal the sign-in state, against [`Binding::LoginState`] and nothing else.
    pub fn seal_login_state(&self, state: &LoginState) -> Option<String> {
        self.seal_json(&serde_json::to_vec(state).ok()?, Binding::LoginState)
    }

    /// Open the sign-in state, or `None` — including for any SSO cookie, host cookie or grant.
    pub fn open_login_state(&self, sealed: &str, now: Timestamp) -> Option<LoginState> {
        let state: LoginState =
            serde_json::from_slice(&self.open_json(sealed, Binding::LoginState)?).ok()?;
        if now.is_at_or_after(Timestamp::from_secs(state.expires_at)) {
            return None;
        }
        Some(state)
    }

    fn seal_json(&self, plaintext: &[u8], binding: Binding<'_>) -> Option<String> {
        let cipher = self.ciphers.first()?;
        let mut nonce_bytes = [0_u8; 12];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: binding.aad(),
                },
            )
            .ok()?;
        Some(format!(
            "v1.{}.{}",
            B64.encode(nonce_bytes),
            B64.encode(sealed)
        ))
    }

    fn open_json(&self, sealed: &str, binding: Binding<'_>) -> Option<Vec<u8>> {
        let mut parts = sealed.splitn(3, '.');
        if parts.next()? != "v1" {
            return None;
        }
        let nonce_bytes = B64.decode(parts.next()?).ok()?;
        let ciphertext = B64.decode(parts.next()?).ok()?;
        if nonce_bytes.len() != 12 {
            return None;
        }
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.ciphers.iter().find_map(|cipher| {
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: binding.aad(),
                    },
                )
                .ok()
        })
    }
}

impl SessionCodec for SealedCodec {
    fn open_host_session(
        &self,
        host: &Host,
        sealed: &str,
        now: Timestamp,
    ) -> Option<OpenedSession> {
        let payload = self.open(sealed, Binding::HostBound(host.as_str()), now)?;
        // A grant is not a session: it is a one-time value redeemed at `/host-session`, and
        // accepting one here would turn a value that travels in a URL — logged by proxies,
        // kept in browser history — into a session cookie's equal.
        if payload.grant_id.is_some() {
            return None;
        }
        Some(OpenedSession {
            claims: payload.claims(),
            expires_at: Timestamp::from_secs(payload.expires_at),
        })
    }
}

/// What derives the self-origin probe's token from a session key — a label, so the same key
/// never yields the same bytes for two purposes.
const SELFTEST_LABEL: &[u8] = b"weebo selftest";

/// HMAC-SHA256 (RFC 2104), over `sha2` alone: the one MAC this binary needs is not worth a
/// second crate whose `digest` generation differs from the workspace's `sha2`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    const BLOCK: usize = 64;
    let mut block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |byte: u8| block.map(|k| k ^ byte);
    let mut inner = Sha256::new();
    inner.update(pad(0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(pad(0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// The `/selftest` tokens, one per session key, newest first.
///
/// **Derived, not random** (second-pass finding 2). A per-process random token meant the probe —
/// which goes out through the public `Ingress` and back in through the `Service` — landed on a
/// *different* replica most of the time, was answered `404`, and was inconclusive. Every replica
/// holds the same session keys, so every replica derives the same token and any of them can
/// answer the probe; a caller without the keys still cannot.
pub fn selftest_tokens(keys: &[String]) -> Result<Vec<String>, KeyError> {
    if keys.is_empty() {
        return Err(KeyError::Empty);
    }
    keys.iter()
        .map(|raw| decode_key(raw).map(|key| B64.encode(hmac_sha256(&key, SELFTEST_LABEL))))
        .collect()
}

/// A random URL-safe id, for a grant, a state or a PKCE verifier.
pub fn random_id() -> Option<String> {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(B64.encode(bytes))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn keys(count: usize) -> Vec<String> {
        (0..count).map(|i| B64.encode([i as u8 + 1; 32])).collect()
    }

    fn payload() -> SealedPayload {
        SealedPayload {
            username: "alice".into(),
            groups: vec!["payments".into()],
            session: Some("sid-1".into()),
            expires_at: 3_600,
            generation: 1,
            grant_id: None,
            proved_at: 0,
            refresh: None,
            session_expires_at: None,
        }
    }

    /// What `/auth` redeems as a grant: only a value of the shape this codec produces, so an
    /// application's own `__weebo_grant=...` is left to the application.
    #[test]
    fn only_a_value_this_codec_could_have_sealed_looks_sealed() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let grant = codec
            .seal(&payload(), Binding::HostBound("alice-ws-api.weebo.si"))
            .unwrap();
        assert!(SealedCodec::looks_sealed(&grant));
        for application_value in [
            "",
            "1",
            "promo-2026",
            "v1",
            "v1.abc.def",
            "v2.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA",
            "v1.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
            "v1.AAAAAAAAAAAAAAAA.short",
            "v1.AAAAAAAAAAAAAAAA.not base64 at all!!!!!",
        ] {
            assert!(
                !SealedCodec::looks_sealed(application_value),
                "{application_value:?}"
            );
        }
    }

    /// B1: the sign-in state cookie used to be sealed against the SSO binding with the return
    /// URL in `username`, so replaying `__Host-weebo-state` as `__Host-weebo-sso` was a session
    /// for any name the caller put in `rd`. Neither value may now open as the other.
    #[test]
    fn a_login_state_cookie_is_not_an_sso_cookie_and_an_sso_cookie_is_not_a_login_state() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let state = LoginState {
            return_to: "https://alice-ws-api.weebo.si/".into(),
            verifier: "verifier".into(),
            state: "state".into(),
            expires_at: 600,
        };
        let sealed_state = codec.seal_login_state(&state).unwrap();
        let now = Timestamp::from_secs(0);
        assert_eq!(codec.open_login_state(&sealed_state, now), Some(state));
        // The attack: the state cookie presented where the SSO cookie is read.
        assert_eq!(codec.open(&sealed_state, Binding::Sso, now), None);
        for host in ["alice-ws-api.weebo.si", "weebo-si/sso"] {
            assert_eq!(
                codec.open(&sealed_state, Binding::HostBound(host), now),
                None
            );
        }
        assert_eq!(codec.open(&sealed_state, Binding::LoginState, now), None);
        // ...and the other way round: an SSO cookie is no sign-in in flight.
        let sso = codec.seal(&payload(), Binding::Sso).unwrap();
        assert_eq!(codec.open_login_state(&sso, now), None);
        // Expiry holds for the state too.
        assert_eq!(
            codec.open_login_state(&sealed_state, Timestamp::from_secs(600)),
            None
        );
    }

    #[test]
    fn a_sealed_cookie_opens_on_the_host_it_was_sealed_for_and_on_no_other() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let sealed = codec
            .seal(&payload(), Binding::HostBound("alice-ws-api.weebo.si"))
            .unwrap();
        assert_eq!(
            codec
                .open(
                    &sealed,
                    Binding::HostBound("alice-ws-api.weebo.si"),
                    Timestamp::from_secs(0)
                )
                .unwrap()
                .username,
            "alice"
        );
        // The cross-host replay the two-cookie design exists to prevent: the same cookie, the
        // same key, a different host.
        assert_eq!(
            codec.open(
                &sealed,
                Binding::HostBound("bob-ws-api.weebo.si"),
                Timestamp::from_secs(0)
            ),
            None
        );
        assert_eq!(
            codec.open(&sealed, Binding::Sso, Timestamp::from_secs(0)),
            None
        );
    }

    #[test]
    fn an_expired_cookie_does_not_open() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let sealed = codec.seal(&payload(), Binding::Sso).unwrap();
        assert!(
            codec
                .open(&sealed, Binding::Sso, Timestamp::from_secs(3_599))
                .is_some()
        );
        assert!(
            codec
                .open(&sealed, Binding::Sso, Timestamp::from_secs(3_600))
                .is_none()
        );
    }

    #[test]
    fn rotation_costs_no_logins() {
        let old = keys(1);
        let new = vec![B64.encode([9_u8; 32]), old[0].clone()];
        let before = SealedCodec::new(&old).unwrap();
        let sealed = before.seal(&payload(), Binding::Sso).unwrap();

        let after = SealedCodec::new(&new).unwrap();
        assert!(
            after
                .open(&sealed, Binding::Sso, Timestamp::from_secs(0))
                .is_some(),
            "a session sealed with the previous key must still open"
        );
        // ...and what it seals now is not openable by the old key set alone.
        let resealed = after.seal(&payload(), Binding::Sso).unwrap();
        assert!(
            before
                .open(&resealed, Binding::Sso, Timestamp::from_secs(0))
                .is_none()
        );
    }

    #[test]
    fn a_tampered_cookie_does_not_open() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let sealed = codec.seal(&payload(), Binding::Sso).unwrap();
        let mut bytes: Vec<char> = sealed.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'A' { 'B' } else { 'A' };
        let tampered: String = bytes.into_iter().collect();
        assert_eq!(
            codec.open(&tampered, Binding::Sso, Timestamp::from_secs(0)),
            None
        );
    }

    #[test]
    fn a_grant_is_not_a_session() {
        // A grant travels in a URL — proxy logs, browser history — so accepting one as a host
        // cookie would make every one of those places a credential store.
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let grant = SealedPayload {
            grant_id: Some("one-time".into()),
            ..payload()
        };
        let sealed = codec
            .seal(&grant, Binding::HostBound("alice-ws-api.weebo.si"))
            .unwrap();
        let host = Host::parse("alice-ws-api.weebo.si").unwrap();
        assert!(
            codec
                .open_host_session(&host, &sealed, Timestamp::from_secs(0))
                .is_none()
        );
    }

    #[test]
    fn a_key_that_is_not_thirty_two_bytes_refuses_to_build() {
        assert_eq!(SealedCodec::new(&[]).err(), Some(KeyError::Empty));
        assert_eq!(
            SealedCodec::new(&[B64.encode([1_u8; 16])]).err(),
            Some(KeyError::NotThirtyTwoBytes(16))
        );
        assert_eq!(
            SealedCodec::new(&["not base64 at all!!".to_owned()]).err(),
            Some(KeyError::NotBase64)
        );
    }

    /// The gateway used to refuse the key its own documentation tells an admin to generate.
    ///
    /// `openssl rand -base64 32` emits *standard, padded* base64; the decoder accepted only the
    /// url-safe unpadded alphabet the cookie payload uses, and answered "a session key is not
    /// base64" to the recipe. A key never travels on the wire, so there is nothing for the strict
    /// alphabet to buy — and RFC 0009's *Failure mode* is about a gateway that will not come up.
    #[test]
    fn a_key_is_accepted_in_whichever_base64_the_admin_generated_it() {
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};

        let raw = [7_u8; 32];
        for encoded in [
            B64.encode(raw),
            URL_SAFE.encode(raw),
            STANDARD.encode(raw),
            STANDARD_NO_PAD.encode(raw),
            format!("  {}  ", STANDARD.encode(raw)),
        ] {
            let codec = SealedCodec::new(std::slice::from_ref(&encoded))
                .unwrap_or_else(|err| panic!("{encoded:?} should be a usable key: {err}"));
            // The same 32 bytes whichever way they were spelled, so a rotation that switches
            // alphabet does not silently become a rotation that invalidates every session.
            let sealed = codec.seal(&payload(), Binding::Sso).unwrap();
            assert!(
                SealedCodec::new(&[B64.encode(raw)])
                    .unwrap()
                    .open(&sealed, Binding::Sso, Timestamp::from_secs(0))
                    .is_some(),
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn two_seals_of_one_payload_differ_because_the_nonce_does() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let first = codec.seal(&payload(), Binding::Sso).unwrap();
        let second = codec.seal(&payload(), Binding::Sso).unwrap();
        assert_ne!(first, second);
    }

    /// RFC 4231 test case 2 — the MAC the self-test token is derived with is the standard one.
    #[test]
    fn hmac_sha256_matches_the_rfc_4231_vector() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Second-pass finding 2: two replicas with the same keys answer each other's probe, and a
    /// different key set does not.
    #[test]
    fn every_replica_derives_the_same_selftest_token_from_the_same_keys() {
        let one = selftest_tokens(&keys(2)).unwrap();
        let other = selftest_tokens(&keys(2)).unwrap();
        assert_eq!(one, other);
        assert_eq!(one.len(), 2);
        assert_ne!(one[0], one[1]);
        let elsewhere = selftest_tokens(&[B64.encode([42_u8; 32])]).unwrap();
        assert!(!one.contains(&elsewhere[0]));
        // Not the key itself, nor anything a cookie is sealed with.
        assert!(!keys(2).contains(&one[0]));
        assert!(selftest_tokens(&[]).is_err());
    }
}
