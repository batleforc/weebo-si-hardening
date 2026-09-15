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
    /// A host cookie or a grant, bound to one endpoint host.
    HostBound(&'a str),
}

impl Binding<'_> {
    fn aad(&self) -> &[u8] {
        match self {
            Self::Sso => b"weebo-si/sso",
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
            Self::NotBase64 => f.write_str("a session key is not base64"),
        }
    }
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
                let bytes = B64.decode(raw.trim()).map_err(|_| KeyError::NotBase64)?;
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
        let cipher = self.ciphers.first()?;
        let mut nonce_bytes = [0_u8; 12];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = serde_json::to_vec(payload).ok()?;
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &plaintext,
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
        let plaintext = self.ciphers.iter().find_map(|cipher| {
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: binding.aad(),
                    },
                )
                .ok()
        })?;
        let payload: SealedPayload = serde_json::from_slice(&plaintext).ok()?;
        if now.is_at_or_after(Timestamp::from_secs(payload.expires_at)) {
            return None;
        }
        Some(payload)
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
        }
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

    #[test]
    fn two_seals_of_one_payload_differ_because_the_nonce_does() {
        let codec = SealedCodec::new(&keys(1)).unwrap();
        let first = codec.seal(&payload(), Binding::Sso).unwrap();
        let second = codec.seal(&payload(), Binding::Sso).unwrap();
        assert_ne!(first, second);
    }
}
