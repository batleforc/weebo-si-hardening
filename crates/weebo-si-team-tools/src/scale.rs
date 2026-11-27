//! The scale state machine — RFC 0020, *Architecture* (the state diagram) and D2.
//!
//! ```text
//! Idle --requesters > 0--> Up --requesters = 0--> Grace --elapsed--> Idle
//!                           ^------- a requester returns ----'
//! Up / Idle --no DevWorkspace requests the key--> Removed
//! ```
//!
//! Pure: the grace timer lives in the adapter's memory, keyed by `(team, key)`; it is passed in
//! as `grace_since` and handed back. A timer that was lost (a controller restart) re-arms from
//! `now` while the workload is still up, so a tool stays up at most one extra grace.

use std::time::{Duration, SystemTime};

/// Where a tool stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// At least one requester is started, `Starting` or `Running`: 1 replica.
    Up,
    /// No active requester; still 1 replica until the grace elapses.
    Grace,
    /// Rendered, 0 replicas.
    Idle,
    /// No DevWorkspace requests the key: the rendered objects go, the PVCs stay.
    Removed,
}

/// What [`decide`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleDecision {
    /// The phase.
    pub phase: Phase,
    /// The replicas to hold through `/scale`; `None` when [`Phase::Removed`].
    pub replicas: Option<i32>,
    /// The grace timer to keep for the next pass (`None` clears it).
    pub grace_since: Option<SystemTime>,
}

impl ScaleDecision {
    /// The `/scale` write this decision needs against the live `current` replicas, if any. The
    /// workload is created at 0 by the adapter, so a missing workload counts as 0.
    pub fn write(&self, current: Option<i32>) -> Option<i32> {
        self.replicas
            .filter(|wanted| *wanted != current.unwrap_or(0))
    }
}

/// Decide the replicas of one tool.
///
/// - `requesters`: DevWorkspaces of the team requesting the key, in any phase; 0 is
///   [`Phase::Removed`].
/// - `active`: those with `spec.started: true` or `status.phase` `Starting`/`Running`.
/// - `replicas`: the workload's live `spec.replicas`, `None` before it exists.
pub fn decide(
    requesters: usize,
    active: usize,
    replicas: Option<i32>,
    grace_since: Option<SystemTime>,
    now: SystemTime,
    grace: Duration,
) -> ScaleDecision {
    let decision = |phase, replicas, grace_since| ScaleDecision {
        phase,
        replicas,
        grace_since,
    };
    if requesters == 0 {
        return decision(Phase::Removed, None, None);
    }
    if active > 0 {
        return decision(Phase::Up, Some(1), None);
    }
    if replicas.unwrap_or(0) <= 0 {
        return decision(Phase::Idle, Some(0), None);
    }
    let since = grace_since.unwrap_or(now);
    // A clock that went backwards reads as "no time elapsed": the tool stays up, never down
    // early.
    let elapsed = now.duration_since(since).unwrap_or(Duration::ZERO);
    if elapsed >= grace {
        decision(Phase::Idle, Some(0), None)
    } else {
        decision(Phase::Grace, Some(1), Some(since))
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
    use crate::port::Clock;
    use crate::port::testing::FakeClock;

    const GRACE: Duration = Duration::from_secs(600);

    #[test]
    fn a_requester_scales_up() {
        let clock = FakeClock::at(1_000);
        let up = decide(1, 1, Some(0), None, clock.now(), GRACE);
        assert_eq!(up.phase, Phase::Up);
        assert_eq!(up.write(Some(0)), Some(1));
        assert_eq!(up.write(Some(1)), None);
        assert_eq!(
            decide(1, 1, None, None, clock.now(), GRACE).write(None),
            Some(1)
        );
    }

    #[test]
    fn a_stopped_requester_keeps_it_rendered_at_zero() {
        let clock = FakeClock::at(1_000);
        let idle = decide(1, 0, Some(0), None, clock.now(), GRACE);
        assert_eq!(idle.phase, Phase::Idle);
        assert_eq!(idle.write(Some(0)), None);
        assert_eq!(idle.write(None), None);
    }

    #[test]
    fn zero_requesters_reach_idle_after_grace() {
        let clock = FakeClock::at(1_000);
        let grace = decide(1, 0, Some(1), None, clock.now(), GRACE);
        assert_eq!(grace.phase, Phase::Grace);
        assert_eq!(grace.replicas, Some(1));
        assert_eq!(grace.grace_since, Some(clock.now()));

        clock.advance(Duration::from_secs(599));
        let still = decide(1, 0, Some(1), grace.grace_since, clock.now(), GRACE);
        assert_eq!(still.phase, Phase::Grace);
        assert_eq!(still.grace_since, grace.grace_since);

        clock.advance(Duration::from_secs(1));
        let idle = decide(1, 0, Some(1), still.grace_since, clock.now(), GRACE);
        assert_eq!(idle.phase, Phase::Idle);
        assert_eq!(idle.write(Some(1)), Some(0));
        assert_eq!(idle.grace_since, None);
    }

    #[test]
    fn a_returning_requester_cancels_the_grace() {
        let clock = FakeClock::at(1_000);
        let grace = decide(1, 0, Some(1), None, clock.now(), GRACE);
        clock.advance(Duration::from_secs(300));
        let back = decide(2, 1, Some(1), grace.grace_since, clock.now(), GRACE);
        assert_eq!(back.phase, Phase::Up);
        assert_eq!(back.grace_since, None);
        // The next stop starts a fresh grace.
        clock.advance(Duration::from_secs(400));
        let again = decide(2, 0, Some(1), back.grace_since, clock.now(), GRACE);
        assert_eq!(again.phase, Phase::Grace);
        assert_eq!(again.grace_since, Some(clock.now()));
    }

    #[test]
    fn no_requester_at_all_is_removed() {
        let clock = FakeClock::at(1_000);
        let removed = decide(0, 0, Some(1), Some(clock.now()), clock.now(), GRACE);
        assert_eq!(removed.phase, Phase::Removed);
        assert_eq!(removed.write(Some(1)), None);
        assert_eq!(removed.grace_since, None);
    }

    #[test]
    fn a_lost_timer_rearms_and_a_backwards_clock_never_scales_down_early() {
        let clock = FakeClock::at(1_000);
        // Restart: up, no timer: the grace starts now, not in the past.
        let rearmed = decide(1, 0, Some(1), None, clock.now(), GRACE);
        assert_eq!(rearmed.phase, Phase::Grace);
        let future = clock.now() + Duration::from_secs(10_000);
        let backwards = decide(1, 0, Some(1), Some(future), clock.now(), GRACE);
        assert_eq!(backwards.phase, Phase::Grace);
    }

    #[test]
    fn a_zero_grace_scales_down_at_once() {
        let clock = FakeClock::at(1_000);
        let idle = decide(1, 0, Some(1), None, clock.now(), Duration::ZERO);
        assert_eq!(idle.phase, Phase::Idle);
    }
}
