//! What this feature needs from the cluster, without knowing how to ask for it.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::DomainError;
use weebo_si_chassis::managed::{Applied, Diff};
use weebo_si_crd::{NamespaceName, TemplateRef};

use crate::model::object::ManagedQuotaObject;
use crate::model::template::{LimitRangeTemplate, QuotaTemplate};

/// The templates, by reference. `None` covers "does not exist" and "not in the watch cache yet";
/// both make the profile invalid, and an invalid profile keeps what namespaces have.
pub trait QuotaTemplateStore: Send + Sync {
    /// The `ResourceQuota` at `template`.
    fn quota(&self, template: &TemplateRef) -> Option<QuotaTemplate>;
    /// The `LimitRange` at `template`.
    fn limit_range(&self, template: &TemplateRef) -> Option<LimitRangeTemplate>;
}

/// How many `ResourceQuota`s and `LimitRange`s in a namespace this feature did not write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForeignObjects {
    /// Foreign quotas: they still apply, and can only make the namespace stricter.
    pub quotas: usize,
    /// Foreign `LimitRange`s: two sets of defaults apply, with no defined winner.
    pub limit_ranges: usize,
}

/// `status.hard` and `status.used` of the managed quota.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuotaUsage {
    /// `status.hard`.
    pub hard: BTreeMap<String, String>,
    /// `status.used`.
    pub used: BTreeMap<String, String>,
}

/// The managed objects, and writing them. An implementation is trusted to return only objects
/// carrying `hardening.weebo.io/managed-by: weebo-si-operator` from [`Self::managed_in`]: the
/// diff can only delete what it is shown.
pub trait ManagedQuotaStore: Send + Sync {
    /// The managed objects in `namespace`, from a watch cache.
    fn managed_in(&self, namespace: &NamespaceName) -> Vec<ManagedQuotaObject>;
    /// The managed quota's usage, if it exists and the quota controller has filled its status.
    fn usage_in(&self, namespace: &NamespaceName) -> Option<QuotaUsage>;
    /// The objects in `namespace` this feature did not write. Counted, never touched.
    fn foreign_in(&self, namespace: &NamespaceName) -> ForeignObjects;
    /// Apply every line of `diffs`. Boxed rather than `async fn`: called through `&dyn`.
    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff<ManagedQuotaObject>],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>>;
}

/// Where outcomes are reported.
pub trait ReconcileObserver: Send + Sync {
    /// One reconcile pass completed.
    fn reconciled(&self, outcome: &crate::application::ReconcileOutcome);
    /// One namespace was torn down (`mode: Off`).
    fn torn_down(&self, namespace: &NamespaceName, applied: &Applied);
    /// One pass did not complete.
    fn failed(&self);
    /// Stop reporting on `namespace`.
    fn forget(&self, namespace: &NamespaceName);
    /// The catalogue was checked: how many profiles are valid and invalid.
    fn profiles(&self, valid: usize, invalid: usize);
    /// The value of `namespace`'s selection annotation this pass. A change from the last value
    /// seen counts in `weebo_si_resource_quotas_selection_changed_total`: the annotation is not
    /// narrowing-only, so who changes it is worth seeing.
    fn selection(&self, namespace: &NamespaceName, annotation: Option<&str>);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::HashMap;
    use std::sync::RwLock;

    use weebo_si_chassis::managed::tally;

    use super::*;

    /// Templates by `(name, namespace)`.
    #[derive(Default)]
    pub struct FakeTemplateStore {
        pub quotas: HashMap<TemplateRef, QuotaTemplate>,
        pub limit_ranges: HashMap<TemplateRef, LimitRangeTemplate>,
    }

    impl QuotaTemplateStore for FakeTemplateStore {
        fn quota(&self, template: &TemplateRef) -> Option<QuotaTemplate> {
            self.quotas.get(template).cloned()
        }

        fn limit_range(&self, template: &TemplateRef) -> Option<LimitRangeTemplate> {
            self.limit_ranges.get(template).cloned()
        }
    }

    /// Managed objects in memory, with scripted usage and foreign counts.
    #[derive(Default)]
    pub struct FakeQuotaStore {
        pub objects: RwLock<Vec<ManagedQuotaObject>>,
        pub usage: HashMap<NamespaceName, QuotaUsage>,
        pub foreign: HashMap<NamespaceName, ForeignObjects>,
        pub applies: RwLock<usize>,
    }

    impl FakeQuotaStore {
        pub fn all(&self) -> Vec<ManagedQuotaObject> {
            self.objects
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl ManagedQuotaStore for FakeQuotaStore {
        fn managed_in(&self, namespace: &NamespaceName) -> Vec<ManagedQuotaObject> {
            self.all()
                .into_iter()
                .filter(|object| &object.key.namespace == namespace)
                .collect()
        }

        fn usage_in(&self, namespace: &NamespaceName) -> Option<QuotaUsage> {
            self.usage.get(namespace).cloned()
        }

        fn foreign_in(&self, namespace: &NamespaceName) -> ForeignObjects {
            self.foreign.get(namespace).copied().unwrap_or_default()
        }

        fn apply<'a>(
            &'a self,
            diffs: &'a [Diff<ManagedQuotaObject>],
        ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
            Box::pin(async move {
                *self
                    .applies
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
                let mut objects = self
                    .objects
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for diff in diffs {
                    match diff {
                        Diff::Create(object) | Diff::Update(object) => {
                            objects.retain(|existing| existing.key != object.key);
                            objects.push(object.clone());
                        }
                        Diff::Delete { key, .. } => objects.retain(|existing| &existing.key != key),
                        Diff::Unchanged(_) => {}
                    }
                }
                Ok(tally(diffs))
            })
        }
    }
}
