//! A token bucket per client address — RFC 0009's *The login surface is a surface*.
//!
//! `/oidc/start`, `/oidc/callback`, `/host-session` and `/oidc/backchannel-logout` are reachable
//! by anyone who can resolve the gateway's own host, and three of them do public-key or symmetric
//! cryptography per call. **The limiter is in front of the cryptography rather than behind it**,
//! which is the whole point: a limiter that runs after the signature check has already paid for
//! the attack it was meant to stop.
//!
//! `/auth` is exempt and stays exempt. It is the hot path, it is called by the ingress controller
//! alone, and it is protected instead by the peer check of *Checking that assumption* — putting a
//! per-address limit on it would rate-limit the controller.
//!
//! The one call this also guards is introspection: an opaque bearer costs a round trip to the
//! identity provider, so a flood of invented tokens is a flood of calls somebody else's server
//! has to answer.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use weebo_si_endpoint_auth::time::Timestamp;

/// How many buckets one call may examine when the map is full — the bound that keeps a flood of
/// new keys from costing a full scan each under the one lock every caller shares.
pub const EVICTION_SWEEP: usize = 16;

/// How many calls, and how fast the allowance comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// The burst: how many calls may happen back to back.
    pub burst: u32,
    /// How many are restored per minute.
    pub per_minute: u32,
}

/// Per-key token buckets, bounded.
///
/// Bounded because the key is a client address and the set of client addresses is whatever an
/// attacker decides it is: an unbounded map here would turn a rate limiter into the memory
/// exhaustion it exists to prevent.
///
/// **At the ceiling, only buckets that have fully refilled are dropped** — a full bucket and no
/// bucket are the same answer, so that forgets nothing. If the map is still full after that, a
/// *new* key is refused (fail closed for newcomers) rather than making room: the limiter used to
/// clear every bucket at that point, so an attacker cycling ten thousand addresses reset
/// everybody's limit, their own included.
///
/// **And finding a refilled bucket is amortised** (second-pass finding 6): every new key at the
/// ceiling used to `retain` over the whole map under the global lock, so a flood of new keys was
/// a flood of full scans. Keys are kept in insertion order and each call examines at most
/// [`EVICTION_SWEEP`] of the oldest — dropping the refilled ones, sending the rest to the back —
/// so the work per call is constant and successive calls walk the whole map between them.
pub struct RateLimiter {
    rate: Rate,
    capacity: usize,
    buckets: Mutex<Buckets>,
}

#[derive(Default)]
struct Buckets {
    by_key: HashMap<String, Bucket>,
    /// Every key in `by_key`, exactly once, oldest first.
    order: VecDeque<String>,
}

#[derive(Clone, Copy)]
struct Bucket {
    /// Allowance left, in thousandths of a call, so a per-minute refill is integer arithmetic.
    milli_tokens: u64,
    touched: u64,
}

impl RateLimiter {
    /// A limiter at `rate`, holding at most `capacity` addresses.
    pub fn new(rate: Rate, capacity: usize) -> Self {
        Self {
            rate,
            capacity: capacity.max(1),
            buckets: Mutex::new(Buckets::default()),
        }
    }

    /// Whether this caller may proceed, spending one unit of their allowance if so.
    ///
    /// A poisoned lock answers `true`: this is a rate limiter, not an authorisation decision, and
    /// failing closed here would turn one panicking request into a gateway that refuses every
    /// sign-in in the cluster.
    pub fn allow(&self, key: &str, now: Timestamp) -> bool {
        let ceiling = u64::from(self.rate.burst) * 1_000;
        let per_second = u64::from(self.rate.per_minute) * 1_000 / 60;
        let Ok(mut guard) = self.buckets.lock() else {
            return true;
        };
        let buckets = &mut *guard;
        let now_secs = now.as_secs();
        if !buckets.by_key.contains_key(key) {
            if buckets.by_key.len() >= self.capacity {
                for _ in 0..EVICTION_SWEEP.min(buckets.order.len()) {
                    let Some(oldest) = buckets.order.pop_front() else {
                        break;
                    };
                    let refilled = buckets.by_key.get(&oldest).is_none_or(|bucket| {
                        bucket.milli_tokens.saturating_add(
                            now_secs
                                .saturating_sub(bucket.touched)
                                .saturating_mul(per_second),
                        ) >= ceiling
                    });
                    if refilled {
                        buckets.by_key.remove(&oldest);
                    } else {
                        buckets.order.push_back(oldest);
                    }
                }
                if buckets.by_key.len() >= self.capacity {
                    return false;
                }
            }
            buckets.by_key.insert(
                key.to_owned(),
                Bucket {
                    milli_tokens: ceiling,
                    touched: now_secs,
                },
            );
            buckets.order.push_back(key.to_owned());
        }
        let Some(bucket) = buckets.by_key.get_mut(key) else {
            return true;
        };
        let elapsed = now_secs.saturating_sub(bucket.touched);
        bucket.milli_tokens = bucket
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(per_second))
            .min(ceiling);
        bucket.touched = now_secs;
        if bucket.milli_tokens < 1_000 {
            return false;
        }
        bucket.milli_tokens -= 1_000;
        true
    }

    /// How many keys are held, for tests.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().map(|b| b.by_key.len()).unwrap_or(0)
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
    fn a_burst_is_allowed_and_the_next_call_is_not() {
        let limiter = RateLimiter::new(
            Rate {
                burst: 3,
                per_minute: 60,
            },
            100,
        );
        let now = Timestamp::from_secs(1_000);
        for call in 0..3 {
            assert!(limiter.allow("10.42.0.7", now), "call {call}");
        }
        assert!(!limiter.allow("10.42.0.7", now));
        // Another caller is untouched: the limit is per address, not per gateway.
        assert!(limiter.allow("10.42.0.8", now));
    }

    #[test]
    fn the_allowance_comes_back_over_time() {
        let limiter = RateLimiter::new(
            Rate {
                burst: 2,
                per_minute: 60,
            },
            100,
        );
        let start = Timestamp::from_secs(1_000);
        assert!(limiter.allow("a", start));
        assert!(limiter.allow("a", start));
        assert!(!limiter.allow("a", start));
        // One per second at 60/minute.
        assert!(limiter.allow("a", start.plus_secs(1)));
        assert!(!limiter.allow("a", start.plus_secs(1)));
    }

    #[test]
    fn the_map_is_bounded_because_the_key_is_whatever_a_caller_says() {
        let limiter = RateLimiter::new(
            Rate {
                burst: 1,
                per_minute: 60,
            },
            8,
        );
        let now = Timestamp::from_secs(1_000);
        for address in 0..1_000 {
            let _ = limiter.allow(&format!("10.0.0.{address}"), now);
        }
        assert!(limiter.len() <= 8);
    }

    /// M2: at the ceiling the limiter used to clear *every* bucket, so a flood of fresh
    /// addresses reset the limit of the caller it was meant to be holding back.
    #[test]
    fn a_flood_of_new_addresses_does_not_reset_anybody_elses_limit() {
        let limiter = RateLimiter::new(
            Rate {
                burst: 2,
                per_minute: 2,
            },
            8,
        );
        let now = Timestamp::from_secs(1_000);
        assert!(limiter.allow("attacker", now));
        assert!(limiter.allow("attacker", now));
        assert!(!limiter.allow("attacker", now));
        for address in 0..1_000 {
            let _ = limiter.allow(&format!("10.0.0.{address}"), now);
        }
        assert!(
            !limiter.allow("attacker", now),
            "the flood must not have bought a fresh allowance"
        );
        assert!(limiter.len() <= 8);
        // A newcomer while the map is full of drained buckets waits (fail closed)...
        assert!(!limiter.allow("newcomer", now));
        // ...until they have refilled, at which point they are forgotten and room is made.
        assert!(limiter.allow("newcomer", now.plus_secs(120)));
    }

    /// Second-pass finding 6: at the ceiling each new key did a full scan of the map. The work
    /// per call is now bounded, and a refilled bucket beyond the first sweep is still found by
    /// the calls that follow.
    #[test]
    fn eviction_at_the_ceiling_is_amortised_and_still_finds_room() {
        let limiter = RateLimiter::new(
            Rate {
                burst: 1,
                per_minute: 1,
            },
            EVICTION_SWEEP * 4,
        );
        let start = Timestamp::from_secs(1_000);
        // Fill the map with drained buckets.
        for address in 0..EVICTION_SWEEP * 4 {
            assert!(limiter.allow(&format!("drained-{address}"), start));
        }
        assert_eq!(limiter.len(), EVICTION_SWEEP * 4);
        // Nothing has refilled: newcomers wait, and nobody's bucket was dropped to make room.
        for newcomer in 0..10 {
            assert!(!limiter.allow(&format!("new-{newcomer}"), start));
        }
        assert_eq!(limiter.len(), EVICTION_SWEEP * 4);
        // Once they have refilled, one call makes room by sweeping at most EVICTION_SWEEP.
        let later = start.plus_secs(120);
        assert!(limiter.allow("new-a", later));
        assert!(limiter.len() <= EVICTION_SWEEP * 4);
        assert!(
            limiter.len() >= EVICTION_SWEEP * 3,
            "swept more than one batch"
        );
    }
}
