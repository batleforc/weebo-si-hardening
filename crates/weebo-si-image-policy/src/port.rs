//! This crate's one outbound port: where a verdict goes once it has been reached.
//!
//! **Why a port at all, when `weebo-si-dwoc-pin` and `policy-guard` need none.** The chassis's
//! own [`Observer`](weebo_si_chassis::port::observer::Observer) records
//! `weebo_si_admission_requests_total` from a [`Decision`](weebo_si_chassis::Decision), and a
//! `Decision` carries a `result` and a `team` — which is most of what
//! `weebo_si_image_policy_total` needs and not all of it. Two labels have nowhere to live in
//! that shape: `resource` (a `DevWorkspace` and a `Pod` are the same `FeatureId` in the same
//! registry-shaped decision), and the platform/variable counters, which are per *image* and per
//! *variable* rather than per decision. A feature emitting several observations for one
//! `evaluate()` is not something `Decision` models, and widening `Decision` to model it would
//! put this feature's vocabulary in the chassis — the coupling `Decision`'s own doc comment
//! refuses.
//!
//! So this crate gets a port of its own, in the same place `weebo-si-network-profiles` puts
//! `ReconcileObserver` and for the same reason. The invariant that matters is untouched: the
//! port has no method that answers "what mode am I in", so a feature still cannot learn its own
//! mode, and `DryRun` still records exactly what `Enforce` would have done.

use weebo_si_crd::TeamName;

use crate::variable::{VariableName, VariableResult};
use crate::verdict::ImageVerdict;

/// Which of the two enforcement points a verdict came from — the `resource` metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// The `DevWorkspace` webhook: the selection-precise half.
    DevWorkspace,
    /// The `Pod` webhook: the team-boundary floor.
    Pod,
}

impl Resource {
    /// The `resource` metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::DevWorkspace => "devworkspace",
            Self::Pod => "pod",
        }
    }

    /// The `resource` label of the chassis' own `weebo_si_admission_duration_seconds`, which
    /// spells Kubernetes kinds rather than lowercase plurals.
    pub fn kind(self) -> &'static str {
        match self {
            Self::DevWorkspace => "DevWorkspace",
            Self::Pod => "Pod",
        }
    }
}

/// Where a verdict goes once it has been reached — implemented by `weebo-si-runtime`'s
/// Prometheus adapter, and by an in-memory fake here.
pub trait ImagePolicyObserver: Send + Sync {
    /// One image's verdict.
    ///
    /// `permitted_by_platform_only` is passed rather than derived so the counter's meaning stays
    /// the one RFC 0005 documents — "permitted only by the platform set" — rather than drifting
    /// to "matched the platform set among others" if the union's ordering ever changes.
    fn image_judged(
        &self,
        resource: Resource,
        team: Option<&TeamName>,
        verdict: &ImageVerdict,
        permitted_by_platform_only: bool,
    );

    /// A workspace named an entry key its team's grant does not allow.
    fn not_granted(&self, resource: Resource, team: Option<&TeamName>, count: usize);

    /// One variable's resolution outcome for one subject.
    ///
    /// **The name, never the value.** A name is written by an admin in one file and is bounded
    /// by that file's length; a value is a namespace annotation and is therefore unbounded — the
    /// same rule that keeps an image reference out of a metric label, applied to the other
    /// user-influenced string in this feature.
    fn variable_resolved(&self, variable: &VariableName, result: VariableResult);

    /// The raw value a bound annotation currently holds for one namespace.
    ///
    /// **The value crosses the port and stops there.** The adapter compares it against the last
    /// one it saw and counts a *change*; it never becomes a label. That split is the whole
    /// design of `weebo_si_image_policy_variable_changed_total`, which RFC 0005 calls "a
    /// detection control, not a diagnostic": where `variables` is declared, a bound annotation
    /// changing is either an admin doing something deliberate — rare — or a workspace user doing
    /// exactly the thing the design assumes they cannot.
    ///
    /// Called with the value **as read**, before validation, so a hostile one is counted rather
    /// than silently dropped along with the variable it failed to become.
    fn variable_value_seen(
        &self,
        namespace: &weebo_si_crd::NamespaceName,
        variable: &VariableName,
        value: &str,
    );
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::sync::Mutex;

    use super::*;

    /// One recorded image observation: resource, team, verdict, platform-only.
    pub type ImageRecord = (Resource, Option<TeamName>, ImageVerdict, bool);
    /// One recorded not-granted observation: resource, team, how many keys were dropped.
    pub type NotGrantedRecord = (Resource, Option<TeamName>, usize);

    /// Records every observation, for a test to assert over.
    #[derive(Default)]
    pub struct RecordingObserver {
        images: Mutex<Vec<ImageRecord>>,
        not_granted: Mutex<Vec<NotGrantedRecord>>,
        variables: Mutex<Vec<(VariableName, VariableResult)>>,
        values: Mutex<Vec<(String, VariableName, String)>>,
    }

    impl RecordingObserver {
        pub fn images(&self) -> Vec<ImageRecord> {
            self.images
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        pub fn not_granted(&self) -> Vec<NotGrantedRecord> {
            self.not_granted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        pub fn variables(&self) -> Vec<(VariableName, VariableResult)> {
            self.variables
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        pub fn values(&self) -> Vec<(String, VariableName, String)> {
            self.values
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl ImagePolicyObserver for RecordingObserver {
        fn image_judged(
            &self,
            resource: Resource,
            team: Option<&TeamName>,
            verdict: &ImageVerdict,
            permitted_by_platform_only: bool,
        ) {
            self.images
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    resource,
                    team.cloned(),
                    verdict.clone(),
                    permitted_by_platform_only,
                ));
        }

        fn not_granted(&self, resource: Resource, team: Option<&TeamName>, count: usize) {
            self.not_granted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((resource, team.cloned(), count));
        }

        fn variable_resolved(&self, variable: &VariableName, result: VariableResult) {
            self.variables
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((variable.clone(), result));
        }

        fn variable_value_seen(
            &self,
            namespace: &weebo_si_crd::NamespaceName,
            variable: &VariableName,
            value: &str,
        ) {
            self.values
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    namespace.as_str().to_string(),
                    variable.clone(),
                    value.to_string(),
                ));
        }
    }

    /// Discards everything — for the many tests that assert a verdict rather than a counter.
    pub struct NullObserver;

    impl ImagePolicyObserver for NullObserver {
        fn image_judged(
            &self,
            _resource: Resource,
            _team: Option<&TeamName>,
            _verdict: &ImageVerdict,
            _permitted_by_platform_only: bool,
        ) {
        }
        fn not_granted(&self, _resource: Resource, _team: Option<&TeamName>, _count: usize) {}
        fn variable_resolved(&self, _variable: &VariableName, _result: VariableResult) {}
        fn variable_value_seen(
            &self,
            _namespace: &weebo_si_crd::NamespaceName,
            _variable: &VariableName,
            _value: &str,
        ) {
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

    #[test]
    fn the_resource_labels_are_the_metrics_contract() {
        assert_eq!(Resource::DevWorkspace.label(), "devworkspace");
        assert_eq!(Resource::Pod.label(), "pod");
    }

    #[test]
    fn the_kind_spelling_is_the_chassis_histograms_not_the_counters() {
        assert_eq!(Resource::DevWorkspace.kind(), "DevWorkspace");
        assert_eq!(Resource::Pod.kind(), "Pod");
    }
}
