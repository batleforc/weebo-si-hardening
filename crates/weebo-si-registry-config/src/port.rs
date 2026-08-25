//! What this feature needs from the cluster, without knowing how to ask for it — the watch and
//! the apiserver round-trip are an adapter's problem.
//!
//! **Two ports, where `network-profiles` has four**, and the absences are the design:
//!
//! * **No `Capabilities`.** There is no second backend, no cluster capability to probe, and
//!   nothing to resolve — `ConfigMap` and `Secret` are core resources every apiserver serves.
//!   RFC 0007's *Architecture* is explicit that inventing one to match the shape of the sibling
//!   bricks "would be the wrong kind of symmetry."
//! * **No `BaselineView`.** That port exists so `network-profiles`' *webhook* half can ask
//!   whether a namespace is protected yet before letting a workspace start. This brick has no
//!   webhook half that gates anything, because it is not a control: a workspace whose registry
//!   configuration has not landed starts unconfigured and says so through
//!   `weebo_si_registry_ready`, which is a metric, not a denial.

use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::DomainError;
use weebo_si_crd::{NamespaceName, RegistryCatalog, SourceKind, TemplateRef};

use crate::model::diff::{Applied, Diff};
use crate::model::object::{ManagedObject, Template};

/// Fetch a template by reference. The domain copies whatever comes back verbatim and never
/// inspects its payload — see [`crate::model::object::ObjectBody`]'s doc for why the type, not a
/// convention, is what guarantees that.
///
/// **This is the first port in this project that reads `Secret` objects.** An implementation is
/// therefore expected to hold decoded bytes for exactly as long as it takes to answer, and never
/// to memoise them: RFC 0007's *Data and state* — "A `Secret` held in a long-lived in-memory
/// cache is a credential kept warm for the lifetime of the process."
pub trait TemplateStore {
    /// The template at `template_ref`, if it resolves. `kind` is a parameter rather than
    /// something read off the object because a `ConfigMap` and a `Secret` may legitimately share
    /// a `{name, namespace}`, and a catalogue entry naming one must never be handed the other.
    ///
    /// `None` covers both "the object does not exist" and "it exists but is not yet in this
    /// adapter's watch cache" — indistinguishable to a caller and treated identically (write
    /// nothing for this source, and report it as `not_found`).
    fn template(&self, kind: SourceKind, template_ref: &TemplateRef) -> Option<Template>;
}

/// What exists now, and applying a diff against it.
///
/// An adapter implementing this over a real cluster is trusted to have already filtered
/// [`Self::managed_in`]'s result to objects carrying `hardening.weebo.io/managed-by:
/// weebo-si-operator`. That filter belongs here and not in the diff computation, per RFC 0004's
/// *Security considerations*, which this brick inherits unchanged and needs more than either
/// sibling: a workspace namespace is full of `ConfigMap`s that are none of this operator's
/// business, and an unfiltered `managed_in` would compute a `Delete` for every one of them.
pub trait ObjectStore: Send + Sync {
    /// Every managed object currently in `ns`. Synchronous — a real adapter answers this from an
    /// in-memory watch cache, never a live apiserver round-trip.
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject>;
    /// Every managed object anywhere in the cluster — the population
    /// `weebo_si_registry_managed_objects` reports.
    fn managed_everywhere(&self) -> Vec<ManagedObject>;
    /// Apply every line of `diffs` — create, update, delete; `Unchanged` is a no-op line kept for
    /// the tally. Returns counts, not the objects: the caller already has those in `diffs`.
    ///
    /// A manually boxed future rather than `async fn` in the trait: this port is called through
    /// `&dyn ObjectStore`, and native `async fn` in a trait is not object-safe.
    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>>;
}

/// Where a reconcile pass's outcome is reported. The reconcile-side counterpart to
/// `weebo_si_chassis::port::observer::Observer`, and separate from it for the same reason
/// `ReconcileFeature` is separate from `Feature`.
pub trait ReconcileObserver: Send + Sync {
    /// One pass completed. `outcome.applied` being `None` is how the implementor knows it was a
    /// `DryRun` — the mode is deliberately not a second parameter that could disagree with it.
    fn reconciled(&self, outcome: &crate::application::ReconcileOutcome);
    /// One pass did not complete.
    fn failed(&self);
    /// A fresh snapshot of everything this operator currently owns, plus the catalogue that
    /// resolves each object's key to its ecosystem.
    ///
    /// **The catalogue is a parameter rather than something the implementor holds**, because it
    /// is hot-reloaded: an implementor that captured one at construction would label every object
    /// with whichever ecosystem the configuration named at boot. It is passed as a snapshot per
    /// call for the same reason `objects` is — RFC 0007's gauge is recomputed from a full picture
    /// rather than maintained by increments.
    fn managed_objects(&self, objects: &[ManagedObject], catalog: &RegistryCatalog);
    /// Stop reporting on `namespace` — this feature no longer reconciles it, because it went
    /// `Off`, left `namespaceSelector`, or was deleted.
    ///
    /// Part of the port rather than an implementor's own bookkeeping because *the domain is what
    /// knows*: only a reconcile pass can tell that a namespace has left scope, and without this
    /// the readiness gauge counts a namespace nobody is configuring as degraded forever — which
    /// is the one way the brick's single alertable signal becomes an ignored one.
    fn forget(&self, namespace: &NamespaceName);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::RwLock;

    use crate::model::mount::MOUNT_TO_DEVWORKSPACE_LABEL;
    use crate::model::object::ObjectBody;

    use super::*;

    /// A `TemplateStore` over a scripted `{(kind, ref) -> Template}` map.
    #[derive(Default)]
    pub struct FakeTemplateStore(HashMap<(SourceKind, TemplateRef), Template>);

    impl FakeTemplateStore {
        pub fn new(
            entries: impl IntoIterator<Item = ((SourceKind, TemplateRef), Template)>,
        ) -> Self {
            Self(entries.into_iter().collect())
        }

        /// The common case: an automountable `ConfigMap` mounted `subpath` at `/home/user`,
        /// which is the shape RFC 0007's own example uses.
        pub fn automountable(
            entries: impl IntoIterator<Item = ((SourceKind, TemplateRef), Vec<u8>)>,
        ) -> Self {
            Self(
                entries
                    .into_iter()
                    .map(|(id, bytes)| {
                        (
                            id,
                            Template {
                                labels: BTreeMap::from([(
                                    MOUNT_TO_DEVWORKSPACE_LABEL.to_string(),
                                    "true".to_string(),
                                )]),
                                annotations: BTreeMap::from([
                                    (
                                        "controller.devfile.io/mount-as".to_string(),
                                        "subpath".to_string(),
                                    ),
                                    (
                                        "controller.devfile.io/mount-path".to_string(),
                                        "/home/user".to_string(),
                                    ),
                                ]),
                                body: ObjectBody::opaque(bytes),
                            },
                        )
                    })
                    .collect(),
            )
        }
    }

    impl TemplateStore for FakeTemplateStore {
        fn template(&self, kind: SourceKind, template_ref: &TemplateRef) -> Option<Template> {
            self.0.get(&(kind, template_ref.clone())).cloned()
        }
    }

    /// An in-memory `ObjectStore` — a flat `Vec<ManagedObject>`, since a `ManagedObject`'s own
    /// `ObjectKey` already carries its namespace.
    #[derive(Default)]
    pub struct FakeObjectStore(RwLock<Vec<ManagedObject>>);

    impl FakeObjectStore {
        pub fn new(existing: impl IntoIterator<Item = ManagedObject>) -> Self {
            Self(RwLock::new(existing.into_iter().collect()))
        }

        /// Everything currently held, across every namespace — for a test to assert against
        /// after an `apply` call.
        pub fn all(&self) -> Vec<ManagedObject> {
            self.0
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl ObjectStore for FakeObjectStore {
        fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject> {
            self.0
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter(|obj| &obj.key.namespace == ns)
                .cloned()
                .collect()
        }

        fn managed_everywhere(&self) -> Vec<ManagedObject> {
            self.all()
        }

        fn apply<'a>(
            &'a self,
            diffs: &'a [Diff],
        ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
            Box::pin(async move {
                let mut guard = self
                    .0
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                for diff in diffs {
                    match diff {
                        Diff::Create(obj) | Diff::Update(obj) => {
                            guard.retain(|existing| existing.key != obj.key);
                            guard.push(obj.clone());
                        }
                        Diff::Delete { key, .. } => guard.retain(|existing| &existing.key != key),
                        Diff::Unchanged(_) => {}
                    }
                }
                Ok(crate::model::diff::tally(diffs))
            })
        }
    }

    #[derive(Default)]
    pub struct RecordingReconcileObserver {
        pub reconciled: RwLock<Vec<crate::application::ReconcileOutcome>>,
        pub failures: RwLock<usize>,
    }

    impl ReconcileObserver for RecordingReconcileObserver {
        fn reconciled(&self, outcome: &crate::application::ReconcileOutcome) {
            self.reconciled
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

        fn managed_objects(&self, _objects: &[ManagedObject], _catalog: &RegistryCatalog) {}

        fn forget(&self, _namespace: &NamespaceName) {}
    }
}
