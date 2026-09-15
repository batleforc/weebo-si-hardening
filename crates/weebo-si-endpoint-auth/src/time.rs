//! One time type, in seconds, because every deadline this crate reasons about — a token's `exp`,
//! a cookie's expiry, a cache entry's TTL — arrives in seconds and is compared to another.
//!
//! Deliberately not `std::time::Instant` or `SystemTime`: the domain must not be able to read a
//! clock. A decision that could call `now()` is a decision a test cannot pin, and the request
//! path's "no I/O" invariant has a sibling here — "no ambient state" — that is just as easy to
//! break by accident and just as annoying to debug afterwards.

/// A point in time, in seconds since the Unix epoch.
///
/// The adapter that reads the system clock is the only place a `Timestamp` is created from
/// nothing; everything else receives one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// A timestamp from seconds since the Unix epoch.
    pub const fn from_secs(secs: u64) -> Self {
        Self(secs)
    }

    /// Seconds since the Unix epoch.
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// `self` moved forward by `secs`, saturating rather than wrapping.
    ///
    /// Saturating on purpose: an overflow here would turn a deadline into a point in the past,
    /// which is the direction that expires a live session or accepts an expired token. Clamping
    /// at `u64::MAX` fails towards "this deadline is far away", which for every caller in this
    /// crate is the same as "no deadline" and is never a security decision on its own.
    pub const fn plus_secs(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// Whether `self` is at or after `deadline` — the one comparison every expiry check makes,
    /// written once so that no call site gets the boundary backwards.
    pub const fn is_at_or_after(self, deadline: Self) -> bool {
        self.0 >= deadline.0
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
    fn expiry_is_inclusive_at_the_deadline() {
        let exp = Timestamp::from_secs(100);
        assert!(Timestamp::from_secs(100).is_at_or_after(exp));
        assert!(Timestamp::from_secs(101).is_at_or_after(exp));
        assert!(!Timestamp::from_secs(99).is_at_or_after(exp));
    }

    #[test]
    fn plus_secs_saturates_rather_than_wrapping_into_the_past() {
        let far = Timestamp::from_secs(u64::MAX - 1);
        assert_eq!(far.plus_secs(10), Timestamp::from_secs(u64::MAX));
    }
}
