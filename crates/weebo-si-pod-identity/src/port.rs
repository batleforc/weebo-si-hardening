//! This crate's one outbound port: what a decision would have changed or refused.
//!
//! The chassis's own `Observer` only receives `{result, mutated, denied}`, and the per-field
//! rewrite counter, the per-reason refusal counter with `fixable_by_mutation` and the `DryRun`
//! lines need more (RFC 0018, *Architecture*), as `ImagePolicyObserver` does for image-policy.
//! No method answers "what mode am I in": the adapter adds the `mode` label from the gate, and
//! `DryRun` reports exactly what `Enforce` would do.

use crate::rewrite::Rewrite;
use crate::subject::PodSubject;
use crate::violation::Violation;

/// One violation of the pod as admitted, and whether the mutation would have fixed it (L23).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The reason.
    pub violation: Violation,
    /// `true` when the pod as `identity_rewrite` would leave it no longer has this violation.
    pub fixable_by_mutation: bool,
}

/// Where a pod-identity decision goes — the Prometheus adapter, and an in-memory fake here.
pub trait PodIdentityObserver: Send + Sync {
    /// The mutation judged `pod`: `rewrites` is what it changes, empty for `unchanged`.
    fn rewrites(&self, pod: &PodSubject, rewrites: &[Rewrite]);

    /// Validation judged `pod`: `violations` is empty when it is allowed.
    fn violations(&self, pod: &PodSubject, violations: &[Judged]);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::sync::Mutex;

    use super::*;

    /// Records every observation, by pod name, for a test to assert over.
    #[derive(Default)]
    pub struct RecordingObserver {
        rewrites: Mutex<Vec<(String, Vec<Rewrite>)>>,
        violations: Mutex<Vec<(String, Vec<Judged>)>>,
    }

    impl RecordingObserver {
        pub fn rewrites(&self) -> Vec<(String, Vec<Rewrite>)> {
            self.rewrites
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        pub fn violations(&self) -> Vec<(String, Vec<Judged>)> {
            self.violations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl PodIdentityObserver for RecordingObserver {
        fn rewrites(&self, pod: &PodSubject, rewrites: &[Rewrite]) {
            self.rewrites
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((pod.name.clone(), rewrites.to_vec()));
        }

        fn violations(&self, pod: &PodSubject, violations: &[Judged]) {
            self.violations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((pod.name.clone(), violations.to_vec()));
        }
    }
}
