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

use std::collections::HashMap;
use std::sync::Mutex;

use weebo_si_endpoint_auth::time::Timestamp;

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
/// exhaustion it exists to prevent. Past the ceiling the oldest-touched half is dropped, which
/// costs an attacker nothing and costs a legitimate caller one refilled bucket.
pub struct RateLimiter {
    rate: Rate,
    capacity: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
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
            buckets: Mutex::new(HashMap::new()),
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
        let Ok(mut buckets) = self.buckets.lock() else {
            return true;
        };
        if buckets.len() >= self.capacity && !buckets.contains_key(key) {
            let cutoff = now.as_secs().saturating_sub(60);
            buckets.retain(|_, bucket| bucket.touched >= cutoff);
            if buckets.len() >= self.capacity {
                buckets.clear();
            }
        }
        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            milli_tokens: ceiling,
            touched: now.as_secs(),
        });
        let elapsed = now.as_secs().saturating_sub(bucket.touched);
        bucket.milli_tokens = bucket
            .milli_tokens
            .saturating_add(elapsed.saturating_mul(per_second))
            .min(ceiling);
        bucket.touched = now.as_secs();
        if bucket.milli_tokens < 1_000 {
            return false;
        }
        bucket.milli_tokens -= 1_000;
        true
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
        assert!(limiter.buckets.lock().unwrap().len() <= 8);
    }
}
