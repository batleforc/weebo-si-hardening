//! What this feature needs from the cluster, without knowing how to ask for it.
//!
//! **One store port, write-only.** Everything this feature reads about a namespace — its labels,
//! the `-previous` annotation, who owns which key — comes from the namespace watch the controller
//! already runs, through the subject. RFC 0013's *Data and state*: no new watch.

use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::DomainError;
use weebo_si_crd::NamespaceName;

use crate::model::labels::PodSecurityLabels;
use crate::model::restore::Restore;

/// One write to a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelWrite {
    /// Server-side apply, field manager [`crate::FIELD_MANAGER`], forced: the six labels and the
    /// `-previous` annotation, and nothing else.
    Apply {
        /// The six labels.
        labels: PodSecurityLabels,
        /// The `-previous` annotation's value.
        previous: String,
    },
    /// Put the six keys back and remove the `-previous` annotation.
    ///
    /// **Not** under [`crate::FIELD_MANAGER`]: once restored, the keys are no longer this
    /// feature's, and a later pass must not read them as its own and conclude the annotation was
    /// lost.
    Restore(Restore),
}

/// Writes to namespaces.
pub trait NamespaceLabelStore: Send + Sync {
    /// Write `write` to `namespace`. Returns the warnings the apiserver sent back — on an
    /// `enforce` change, one per existing pod the new level would refuse.
    ///
    /// A manually boxed future rather than `async fn` in the trait: this port is called through
    /// `&dyn NamespaceLabelStore`, and native `async fn` in a trait is not object-safe.
    fn write<'a>(
        &'a self,
        namespace: &'a NamespaceName,
        write: &'a LabelWrite,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DomainError>> + Send + 'a>>;
}

/// Where a pass's outcome is reported: metrics and the log line.
pub trait ReconcileObserver: Send + Sync {
    /// One reconcile pass completed.
    fn reconciled(&self, outcome: &crate::application::ReconcileOutcome);
    /// One teardown completed.
    fn torn_down(&self, outcome: &crate::application::TeardownOutcome);
    /// One pass did not complete.
    fn failed(&self);
    /// Stop reporting on `namespace`: it left scope or was deleted. Without this, the
    /// per-level gauge counts a namespace nobody reconciles forever.
    fn forget(&self, namespace: &NamespaceName);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    use super::*;
    use crate::model::labels::PREVIOUS_ANNOTATION;

    /// A namespace as the fake store holds it: all its labels, all its annotations.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct FakeNamespace {
        pub labels: BTreeMap<String, String>,
        pub annotations: BTreeMap<String, String>,
    }

    /// An in-memory `NamespaceLabelStore`, recording every write and applying it to a map of
    /// namespaces, with scripted warnings.
    #[derive(Default)]
    pub struct FakeNamespaceLabelStore {
        pub namespaces: RwLock<BTreeMap<NamespaceName, FakeNamespace>>,
        pub writes: RwLock<Vec<(NamespaceName, LabelWrite)>>,
        pub warnings: Vec<String>,
    }

    impl FakeNamespaceLabelStore {
        pub fn namespace(&self, name: &NamespaceName) -> FakeNamespace {
            self.namespaces
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(name)
                .cloned()
                .unwrap_or_default()
        }

        pub fn writes(&self) -> Vec<(NamespaceName, LabelWrite)> {
            self.writes
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl NamespaceLabelStore for FakeNamespaceLabelStore {
        fn write<'a>(
            &'a self,
            namespace: &'a NamespaceName,
            write: &'a LabelWrite,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DomainError>> + Send + 'a>> {
            Box::pin(async move {
                self.writes
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((namespace.clone(), write.clone()));
                let mut namespaces = self
                    .namespaces
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let entry = namespaces.entry(namespace.clone()).or_default();
                match write {
                    LabelWrite::Apply { labels, previous } => {
                        entry.labels.extend(labels.as_map().clone());
                        entry
                            .annotations
                            .insert(PREVIOUS_ANNOTATION.to_string(), previous.clone());
                    }
                    LabelWrite::Restore(restore) => {
                        for key in &restore.remove {
                            entry.labels.remove(key);
                        }
                        entry.labels.extend(restore.set.clone());
                        entry.annotations.remove(PREVIOUS_ANNOTATION);
                    }
                }
                Ok(self.warnings.clone())
            })
        }
    }

    #[derive(Default)]
    pub struct RecordingReconcileObserver {
        pub reconciled: RwLock<Vec<crate::application::ReconcileOutcome>>,
        pub torn_down: RwLock<Vec<crate::application::TeardownOutcome>>,
        pub failures: RwLock<usize>,
        pub forgotten: RwLock<Vec<NamespaceName>>,
    }

    impl ReconcileObserver for RecordingReconcileObserver {
        fn reconciled(&self, outcome: &crate::application::ReconcileOutcome) {
            self.reconciled
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(outcome.clone());
        }

        fn torn_down(&self, outcome: &crate::application::TeardownOutcome) {
            self.torn_down
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(outcome.clone());
        }

        fn failed(&self) {
            *self
                .failures
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
        }

        fn forget(&self, namespace: &NamespaceName) {
            self.forgotten
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(namespace.clone());
        }
    }
}
