//! Counters and decision events — implemented by `weebo-si-runtime`'s Prometheus adapter.

use weebo_si_crd::FeatureMode;

use crate::feature::{FeatureId, FeatureOutcome};

/// Counters and decision events.
pub trait Observer {
    /// Record one feature's decision. Called for every enabled feature, in every mode — `mode`
    /// is part of the record (RFC 0002's `weebo_si_admission_requests_total{...,mode,...}`)
    /// even though the *feature* itself is never told it, per `Context`'s own invariant.
    fn decided(&self, feature: FeatureId, mode: FeatureMode, outcome: &FeatureOutcome);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::cell::RefCell;

    use super::*;

    /// `&self`, not `&mut self` — matches the port's signature — so the fake needs interior
    /// mutability to record calls.
    #[derive(Default)]
    pub struct RecordingObserver(RefCell<Vec<(FeatureId, FeatureMode, FeatureOutcome)>>);

    impl RecordingObserver {
        pub fn events(&self) -> Vec<(FeatureId, FeatureMode, FeatureOutcome)> {
            self.0.borrow().clone()
        }
    }

    impl Observer for RecordingObserver {
        fn decided(&self, feature: FeatureId, mode: FeatureMode, outcome: &FeatureOutcome) {
            self.0.borrow_mut().push((feature, mode, outcome.clone()));
        }
    }
}
