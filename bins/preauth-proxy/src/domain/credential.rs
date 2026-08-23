//! The credential cache, and the single-flight rule around it.
//!
//! There is deliberately **no TTL and no proactive refresh**. The upstream is the authority on
//! whether a credential is still good and it says so with a status code; storing an expiry the
//! proxy guessed at would be a second source of truth that could disagree with it. The credential
//! the upstream just rejected is the credential we discard, and nothing else can be stale.

use std::sync::Arc;

use tokio::sync::{Mutex, RwLock};

use super::port::{AcquireError, Credential, CredentialSource};

/// A single held credential, shared by every request this replica serves.
///
/// Each replica holds its own; replicas are independent and need no shared store.
#[derive(Debug, Default)]
pub struct Cache {
    /// The credential itself. `RwLock` because the steady state is "many readers, no writer".
    held: RwLock<Option<Arc<Credential>>>,
    /// Held across an acquisition so that N concurrent misses produce one login, not N.
    acquiring: Mutex<()>,
}

impl Cache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a credential is currently held, for [`super::policy::CacheState`].
    pub async fn holds_credential(&self) -> bool {
        self.held.read().await.is_some()
    }

    /// The held credential, or `None`.
    pub async fn peek(&self) -> Option<Arc<Credential>> {
        self.held.read().await.clone()
    }

    /// Return the held credential, acquiring one first if the cache is empty.
    ///
    /// **Single-flight.** The first caller to find the cache empty takes the acquisition lock and
    /// performs the exchange; the rest wait on the lock and reuse its result. The re-check
    /// *inside* the lock is the load-bearing part — this is the same check-then-act-under-a-lock
    /// discipline [RFC 0001](../../../../docs/rfc/0001-passwd-append.md) applies to its file
    /// append, and skipping the second check would reintroduce exactly the window the lock exists
    /// to close.
    ///
    /// # Errors
    ///
    /// Propagates the source's failure. Nothing is cached on failure, so the next request retries.
    pub async fn get_or_acquire(
        &self,
        source: &impl CredentialSource,
    ) -> Result<Arc<Credential>, AcquireError> {
        if let Some(held) = self.peek().await {
            return Ok(held);
        }

        let _flight = self.acquiring.lock().await;

        // Re-check under the lock: another caller may have populated the cache while we waited.
        if let Some(held) = self.peek().await {
            return Ok(held);
        }

        let fresh = Arc::new(source.acquire().await?);
        *self.held.write().await = Some(Arc::clone(&fresh));
        Ok(fresh)
    }

    /// Discard `stale` — but only if it is still the credential being held.
    ///
    /// Compare-and-clear rather than a bare clear: two requests that both get a `401` on the same
    /// stale credential would otherwise have the second one throw away the fresh credential the
    /// first just acquired, and the pair would renew forever.
    pub async fn invalidate(&self, stale: &Credential) {
        let mut held = self.held.write().await;
        if held.as_deref() == Some(stale) {
            *held = None;
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Counts logins, and takes long enough that concurrent callers genuinely overlap.
    struct CountingSource {
        calls: AtomicUsize,
        delay: Duration,
    }

    impl CountingSource {
        fn new(delay_ms: u64) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                delay: Duration::from_millis(delay_ms),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl CredentialSource for CountingSource {
        async fn acquire(&self) -> Result<Credential, AcquireError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(Credential::new(format!("sid=token{n}")))
        }
    }

    struct AlwaysFails;

    impl CredentialSource for AlwaysFails {
        async fn acquire(&self) -> Result<Credential, AcquireError> {
            Err(AcquireError::Rejected(403))
        }
    }

    #[tokio::test]
    async fn the_first_call_acquires_and_the_second_reuses() {
        let cache = Cache::new();
        let source = CountingSource::new(0);

        let first = cache.get_or_acquire(&source).await.unwrap();
        let second = cache.get_or_acquire(&source).await.unwrap();

        assert_eq!(first.expose(), "sid=token0");
        assert_eq!(second.expose(), "sid=token0");
        assert_eq!(source.calls(), 1);
    }

    /// The test that fails without the lock.
    #[tokio::test]
    async fn concurrent_misses_produce_exactly_one_login() {
        const CALLERS: usize = 32;

        let cache = Arc::new(Cache::new());
        // A real delay is what makes this a race rather than a formality: without the lock, all
        // 32 callers read the empty cache before any of them finishes acquiring.
        let source = Arc::new(CountingSource::new(20));

        let mut handles = Vec::with_capacity(CALLERS);
        for _ in 0..CALLERS {
            let cache = Arc::clone(&cache);
            let source = Arc::clone(&source);
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_acquire(&*source)
                    .await
                    .map(|c| c.expose().to_owned())
            }));
        }

        let mut seen = Vec::with_capacity(CALLERS);
        for handle in handles {
            seen.push(handle.await.unwrap().unwrap());
        }

        assert_eq!(
            source.calls(),
            1,
            "{CALLERS} concurrent misses hit the origin more than once"
        );
        assert!(
            seen.iter().all(|c| c == "sid=token0"),
            "callers disagreed about the credential: {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_acquisition_caches_nothing() {
        let cache = Cache::new();
        assert!(cache.get_or_acquire(&AlwaysFails).await.is_err());
        assert!(!cache.holds_credential().await);

        // The next request is free to retry, and succeeds.
        let source = CountingSource::new(0);
        assert!(cache.get_or_acquire(&source).await.is_ok());
    }

    #[tokio::test]
    async fn invalidating_the_held_credential_empties_the_cache() {
        let cache = Cache::new();
        let source = CountingSource::new(0);
        let held = cache.get_or_acquire(&source).await.unwrap();

        cache.invalidate(&held).await;
        assert!(!cache.holds_credential().await);

        // A fresh acquisition follows, and it is a different token.
        let next = cache.get_or_acquire(&source).await.unwrap();
        assert_eq!(next.expose(), "sid=token1");
        assert_eq!(source.calls(), 2);
    }

    #[tokio::test]
    async fn invalidating_a_credential_that_is_no_longer_held_is_a_no_op() {
        let cache = Cache::new();
        let source = CountingSource::new(0);
        let stale = cache.get_or_acquire(&source).await.unwrap();

        cache.invalidate(&stale).await;
        let fresh = cache.get_or_acquire(&source).await.unwrap();

        // The second holder of the stale credential now tries to invalidate it too. Without the
        // compare-and-clear, this would discard `fresh` and the pair would renew forever.
        cache.invalidate(&stale).await;

        assert_eq!(
            cache.peek().await.unwrap().expose(),
            fresh.expose(),
            "a stale invalidation discarded a fresh credential"
        );
        assert_eq!(source.calls(), 2);
    }

    #[test]
    fn a_credential_never_prints_itself() {
        let rendered = format!("{:?}", Credential::new("sid=supersecret"));
        assert!(!rendered.contains("supersecret"), "{rendered}");
        assert!(rendered.contains("15 bytes"), "{rendered}");
    }
}
