//! The identity caches — bounded, keyed by hash, and never holding a verdict.
//!
//! RFC 0009's *Request cost* states the rule this module implements: **what may be cached is who
//! the caller is; what may never be cached is whether they are allowed.** Opening a sealed cookie
//! and verifying a signature are pure functions of a credential and a key, so their results can
//! be reused for as long as the credential itself is valid. Delegation, the owner check and the
//! path rules are recomputed from the compiled policy on every request, which is what makes a
//! name removed from `allow-users` take effect on the next request — for the assets still in
//! flight, not at the next session expiry.
//!
//! The asset burst is the case this exists for: two hundred requests, one cookie, one host. The
//! first pays an AEAD open, the other hundred and ninety-nine pay a hash and a map read, and all
//! two hundred re-derive the verdict.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::time::Timestamp;

/// The hash of a credential, and the only form of one this crate will hold.
///
/// A newtype rather than a `String` because the property is "the cache cannot contain a token
/// even by accident", and a property is worth a type. [`fmt::Debug`] prints a short prefix of the
/// hash so a log line can correlate two requests from one session without carrying anything
/// replayable — and there is deliberately no accessor returning the credential, because there is
/// no credential here to return.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Hash a credential.
    pub fn of(credential: &str) -> Self {
        let digest = Sha256::digest(credential.as_bytes());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// The first four bytes, hex — enough to correlate, useless to replay.
    pub fn short(&self) -> String {
        self.0[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({}…)", self.short())
    }
}

/// Which cache an observation is about — the `kind` label of
/// `weebo_si_endpoint_auth_identity_cache_total`, closed like every other label in this project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    /// Opened host session cookies.
    Session,
    /// Bearer tokens this issuer minted, already verified.
    Bearer,
    /// `TokenReview` answers for workspace service-account tokens.
    TokenReview,
}

impl CacheKind {
    /// The metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Bearer => "bearer",
            Self::TokenReview => "token_review",
        }
    }
}

/// What one lookup did — the `result` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    /// Answered from memory.
    Hit,
    /// Not there, or there and expired.
    Miss,
    /// An insert pushed the oldest entry out.
    Evicted,
}

impl CacheOutcome {
    /// The metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Evicted => "evicted",
        }
    }
}

/// Hits, misses and evictions since the process started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheStats {
    /// Lookups answered from memory.
    pub hits: u64,
    /// Lookups that had to do the work.
    pub misses: u64,
    /// Entries pushed out by an insert.
    pub evictions: u64,
    /// Entries currently held.
    pub entries: usize,
}

struct Entry<V> {
    value: V,
    expires_at: Timestamp,
    seq: u64,
}

struct Inner<V> {
    entries: HashMap<Fingerprint, Entry<V>>,
    order: BTreeMap<u64, Fingerprint>,
    next_seq: u64,
    hits: u64,
    misses: u64,
    evictions: u64,
}

/// A bounded, expiring map from a credential's hash to what that credential proved.
///
/// Bounded so that a flood of distinct tokens evicts rather than grows — an unbounded identity
/// cache is a memory exhaustion an unauthenticated caller can drive. Expiring on the credential's
/// *own* deadline rather than on a fixed TTL, so a cache can never make a token outlive its `exp`
/// — and capped by a TTL of the cache's own so that an identity provider's twelve-hour token does
/// not mean twelve hours of stale claims.
pub struct IdentityCache<V> {
    kind: CacheKind,
    capacity: usize,
    ttl_secs: u64,
    inner: Mutex<Inner<V>>,
}

impl<V: Clone> IdentityCache<V> {
    /// A cache holding at most `capacity` entries, none for longer than `ttl_secs`.
    pub fn new(kind: CacheKind, capacity: usize, ttl_secs: u64) -> Self {
        Self {
            kind,
            capacity: capacity.max(1),
            ttl_secs,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                order: BTreeMap::new(),
                next_seq: 0,
                hits: 0,
                misses: 0,
                evictions: 0,
            }),
        }
    }

    /// Which cache this is.
    pub fn kind(&self) -> CacheKind {
        self.kind
    }

    /// What `key` proved, if it is still valid at `now`.
    ///
    /// A poisoned lock answers `None`: a cache miss costs a signature check, where returning an
    /// error would cost a developer their request. This is the one place in this crate where
    /// "degrade to doing the work again" is the right answer to an internal failure.
    pub fn get(&self, key: &Fingerprint, now: Timestamp) -> Option<V> {
        let mut inner = self.inner.lock().ok()?;
        let entry = inner.entries.get(key);
        match entry {
            Some(entry) if !now.is_at_or_after(entry.expires_at) => {
                let value = entry.value.clone();
                inner.hits += 1;
                Some(value)
            }
            Some(entry) => {
                let seq = entry.seq;
                inner.entries.remove(key);
                inner.order.remove(&seq);
                inner.misses += 1;
                None
            }
            None => {
                inner.misses += 1;
                None
            }
        }
    }

    /// Remember that `key` proved `value`, until `expires_at` or the cache's own TTL, whichever
    /// comes first.
    ///
    /// Returns the observation to record for this insert: [`CacheOutcome::Evicted`] when it
    /// pushed an older entry out, [`CacheOutcome::Miss`] otherwise. An insert is always the tail
    /// of a miss — nothing inserts on a hit — so recording it as anything else would count the
    /// same request twice in `weebo_si_endpoint_auth_identity_cache_total`.
    pub fn insert(
        &self,
        key: Fingerprint,
        value: V,
        expires_at: Timestamp,
        now: Timestamp,
    ) -> CacheOutcome {
        let deadline = expires_at.min(now.plus_secs(self.ttl_secs));
        if now.is_at_or_after(deadline) {
            // Already expired: caching it would only ever produce a hit that has to be thrown
            // away, and an entry that pushes a live one out.
            return CacheOutcome::Miss;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return CacheOutcome::Miss;
        };
        let seq = inner.next_seq;
        inner.next_seq += 1;
        if let Some(previous) = inner.entries.insert(
            key,
            Entry {
                value,
                expires_at: deadline,
                seq,
            },
        ) {
            inner.order.remove(&previous.seq);
        }
        inner.order.insert(seq, key);
        if inner.entries.len() > self.capacity
            && let Some((oldest_seq, oldest_key)) = inner.order.iter().next().map(|(s, k)| (*s, *k))
        {
            inner.order.remove(&oldest_seq);
            inner.entries.remove(&oldest_key);
            inner.evictions += 1;
            return CacheOutcome::Evicted;
        }
        CacheOutcome::Miss
    }

    /// Forget one entry — what a revocation does, and what a key rotation does in bulk.
    pub fn forget(&self, key: &Fingerprint) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(entry) = inner.entries.remove(key)
        {
            inner.order.remove(&entry.seq);
        }
    }

    /// Drop everything. The JWKS generation bump, and the session key rotation.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.entries.clear();
            inner.order.clear();
        }
    }

    /// Hits, misses, evictions, size.
    pub fn stats(&self) -> CacheStats {
        match self.inner.lock() {
            Ok(inner) => CacheStats {
                hits: inner.hits,
                misses: inner.misses,
                evictions: inner.evictions,
                entries: inner.entries.len(),
            },
            Err(_) => CacheStats::default(),
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

    fn at(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    #[test]
    fn a_fingerprint_never_renders_the_credential() {
        let print = Fingerprint::of("eyJhbGciOi.secret.token");
        let rendered = format!("{print:?}");
        assert!(!rendered.contains("secret"), "{rendered}");
        assert_eq!(print.short().len(), 8);
        assert_eq!(print, Fingerprint::of("eyJhbGciOi.secret.token"));
        assert_ne!(print, Fingerprint::of("eyJhbGciOi.secret.tokeo"));
    }

    #[test]
    fn a_hit_is_the_second_request_of_a_page_load() {
        let cache: IdentityCache<&str> = IdentityCache::new(CacheKind::Session, 10, 300);
        let key = Fingerprint::of("cookie");
        assert_eq!(cache.get(&key, at(0)), None);
        cache.insert(key, "alice", at(3600), at(0));
        assert_eq!(cache.get(&key, at(1)), Some("alice"));
        let stats = cache.stats();
        assert_eq!((stats.hits, stats.misses), (1, 1));
    }

    #[test]
    fn an_entry_never_outlives_the_credential_it_answers_for() {
        let cache: IdentityCache<&str> = IdentityCache::new(CacheKind::Bearer, 10, 3600);
        let key = Fingerprint::of("token");
        // The token expires in 60s; the cache's own TTL is an hour and must not win.
        cache.insert(key, "alice", at(60), at(0));
        assert_eq!(cache.get(&key, at(59)), Some("alice"));
        assert_eq!(cache.get(&key, at(60)), None);
    }

    #[test]
    fn the_cache_ttl_caps_a_long_lived_credential() {
        let cache: IdentityCache<&str> = IdentityCache::new(CacheKind::Bearer, 10, 30);
        let key = Fingerprint::of("token");
        cache.insert(key, "alice", at(43_200), at(0));
        assert_eq!(cache.get(&key, at(29)), Some("alice"));
        assert_eq!(cache.get(&key, at(31)), None);
    }

    #[test]
    fn a_flood_of_distinct_credentials_evicts_rather_than_grows() {
        let cache: IdentityCache<u32> = IdentityCache::new(CacheKind::Bearer, 4, 300);
        for i in 0..64_u32 {
            cache.insert(Fingerprint::of(&format!("token-{i}")), i, at(300), at(0));
        }
        let stats = cache.stats();
        assert_eq!(stats.entries, 4);
        assert_eq!(stats.evictions, 60);
        // The oldest are the ones gone.
        assert_eq!(cache.get(&Fingerprint::of("token-0"), at(1)), None);
        assert_eq!(cache.get(&Fingerprint::of("token-63"), at(1)), Some(63));
    }

    #[test]
    fn forgetting_one_entry_is_what_a_revocation_does() {
        let cache: IdentityCache<&str> = IdentityCache::new(CacheKind::Session, 10, 300);
        let key = Fingerprint::of("cookie");
        cache.insert(key, "alice", at(300), at(0));
        cache.forget(&key);
        assert_eq!(cache.get(&key, at(1)), None);
        cache.insert(key, "alice", at(300), at(0));
        cache.clear();
        assert_eq!(cache.get(&key, at(1)), None);
    }

    #[test]
    fn an_already_expired_credential_is_not_cached_at_all() {
        let cache: IdentityCache<&str> = IdentityCache::new(CacheKind::Bearer, 10, 300);
        let key = Fingerprint::of("token");
        assert_eq!(
            cache.insert(key, "alice", at(10), at(20)),
            CacheOutcome::Miss
        );
        assert_eq!(cache.stats().entries, 0);
    }
}
