//! Which features are active, in which mode, for which namespace.

use weebo_si_crd::{FeatureMode, NamespaceName, Team};

use crate::feature::FeatureId;

/// Which features are active, in which mode, for which namespace.
pub trait FeatureGate {
    /// The mode `feature` runs in for `namespace`. Absent from `spec.features` means `Off`.
    fn mode(&self, feature: FeatureId, namespace: &NamespaceName) -> FeatureMode;
    /// Ordered, chassis-level, shared by every feature. Owned, not borrowed: a live
    /// implementation reads this from behind a lock (`WeeboSiConfig` is hot-reloadable), and a
    /// handful of entries written by one admin in one file is cheap to clone per admission.
    fn teams(&self) -> Vec<Team>;
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use super::*;

    pub struct FakeFeatureGate {
        default_mode: FeatureMode,
        teams: Vec<Team>,
    }

    impl FakeFeatureGate {
        pub fn new(default_mode: FeatureMode, teams: Vec<Team>) -> Self {
            Self {
                default_mode,
                teams,
            }
        }
    }

    impl FeatureGate for FakeFeatureGate {
        fn mode(&self, _feature: FeatureId, _namespace: &NamespaceName) -> FeatureMode {
            self.default_mode
        }

        fn teams(&self) -> Vec<Team> {
            self.teams.clone()
        }
    }
}
