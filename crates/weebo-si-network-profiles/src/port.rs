//! What this feature needs from the cluster, without knowing how to ask for it — the watch, the
//! discovery call and the apiserver round-trip are an adapter's problem (a later phase's).

use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::DomainError;
use weebo_si_crd::{Backend, NamespaceName, TemplateRef};

use crate::canary::Reachability;
use crate::model::diff::{Applied, Diff};
use crate::model::policy::{ManagedObject, PolicyBody};

/// Which backends this cluster actually offers, per RFC 0004's *Design*: "`weebo-si-operator
/// backends` prints which are compiled in and which the cluster actually offers."
pub trait Capabilities {
    /// Whether the apiserver advertises `backend`.
    fn offers(&self, backend: Backend) -> bool;
}

/// Fetch a template's rule content by reference. The domain copies whatever comes back
/// verbatim and never inspects it — see [`crate::model::policy::PolicyBody`]'s doc.
pub trait TemplateStore {
    /// The body a template object carries, if it resolves. `backend` is needed alongside
    /// `template_ref` because the two policy dialects are different API resources at the same
    /// `{name, namespace}` — a `NetworkPolicy` variant and a `Cilium` variant can legitimately
    /// name the same template ref pointing at two different objects. `None` covers both "the
    /// object does not exist" and "it exists but is not yet in this adapter's watch cache" — the
    /// two are indistinguishable to a caller and treated identically (write nothing for this
    /// object).
    fn body(&self, backend: Backend, template_ref: &TemplateRef) -> Option<PolicyBody>;
}

/// What exists now, and applying a diff against it. An adapter implementing this over a real
/// cluster is trusted to have already filtered `managed_in`'s result to objects carrying
/// `hardening.weebo.io/managed-by: weebo-si-operator` — see [`crate::model::diff::compute_diff`]'s
/// doc for why that filter belongs here and not in the diff computation.
///
/// `Send + Sync` as a supertrait — `application::reconcile` (an `async fn`) holds `&dyn
/// PolicyStore` across its own `.await`, matching `weebo_si_chassis::port::dwoc_catalog::DwocCatalog`'s
/// same reasoning.
pub trait PolicyStore: Send + Sync {
    /// Every managed object currently in `ns`. Synchronous, like `DwocCatalog::resolves` and
    /// `NamespaceView::facts` — a real adapter answers this from an in-memory watch cache, never
    /// a live apiserver round-trip, the same reason those two ports stayed synchronous.
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject>;
    /// Every managed object anywhere in the cluster — the population
    /// `weebo_si_network_managed_objects` reports. Same watch cache as [`Self::managed_in`],
    /// unfiltered; a port method rather than an adapter-only one because a controller has to be
    /// able to ask it without naming a concrete adapter.
    fn managed_everywhere(&self) -> Vec<ManagedObject>;
    /// Apply every line of `diffs` — create, update, delete; `Unchanged` is a no-op line kept for
    /// the tally. Returns counts, not the objects: the caller already has those in `diffs`.
    ///
    /// **Async, unlike every other port in this crate** — a real adapter's implementation
    /// genuinely writes to the apiserver here, which `managed_in`'s watch-cache read never does.
    /// A manually boxed future rather than `async fn` in the trait: this port is called through
    /// `&dyn PolicyStore` (mirroring `weebo_si_chassis::admit`'s `&dyn FeatureGate` and friends),
    /// and native `async fn` in a trait is not object-safe.
    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>>;
}

/// Whether a namespace already carries its baseline object.
///
/// A port of its own rather than a second method on [`PolicyStore`] because its one consumer —
/// [`crate::feature::baseline_gate::BaselineGate`], which runs in the **webhook** role — has no
/// business being handed `apply`. The webhook role writes nothing, and RFC 0002's argument for
/// splitting the two roles ("the webhook role, the one an untrusted `AdmissionReview` body
/// reaches, never holds the write permission only the controller needs") applies just as much to
/// the port a handler is given as to the `ClusterRole` its pod runs under.
pub trait BaselineView: Send + Sync {
    /// Whether `ns` currently carries a managed baseline object. Synchronous, like
    /// [`PolicyStore::managed_in`], and for the same reason: a real adapter answers it from an
    /// in-memory watch cache, never a live apiserver round-trip on the admission path.
    fn has_baseline(&self, ns: &NamespaceName) -> bool;
}

/// One leg of the enforcement canary — see [`crate::canary`] for what the pair of legs means.
///
/// `restricted` is the whole parameter: `false` asks "can the client reach the target with
/// nothing in the way", `true` asks "can it still, with a deny policy applied". An adapter owns
/// the pods, the policy and the waiting; this trait owns neither, which is what keeps the
/// verdict testable without a cluster.
pub trait CanaryProbe: Send + Sync {
    /// Run one leg and report what it observed. An `Err` is the probe failing to *run* (an
    /// apiserver rejection, a missing permission) — a probe that ran and could not decide
    /// reports [`Reachability::Inconclusive`] instead.
    fn reachability(
        &self,
        restricted: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Reachability, DomainError>> + Send + '_>>;

    /// Remove everything the probe created. Part of the port rather than an adapter detail
    /// because the probe is the only thing in this brick that creates a workload, and "who is
    /// responsible for taking it away again" should be answerable from the trait.
    fn cleanup(&self) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + '_>>;
}

/// Where a reconcile pass's outcome is reported. The reconcile-side counterpart to
/// `weebo_si_chassis::port::observer::Observer`, and separate from it for the same reason
/// `ReconcileFeature` is separate from `Feature`: what a reconcile decision *is* has no overlap
/// with what an admission decision is, and one trait covering both would carry a field neither
/// caller can fill.
pub trait ReconcileObserver: Send + Sync {
    /// One pass completed. `outcome.applied` being `None` is how the implementor knows it was a
    /// `DryRun` — the mode is deliberately not a second parameter that could disagree with it.
    fn reconciled(&self, outcome: &crate::application::ReconcileOutcome);
    /// One pass did not complete.
    fn failed(&self);
    /// A fresh snapshot of everything this operator currently owns.
    fn managed_objects(&self, objects: &[ManagedObject]);
    /// The enforcement probe's latest verdict.
    fn canary(&self, verdict: crate::canary::CanaryVerdict);
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::{HashMap, HashSet};
    use std::sync::RwLock;

    use super::*;

    pub struct FakeCapabilities(HashSet<Backend>);

    impl FakeCapabilities {
        pub fn new(offered: impl IntoIterator<Item = Backend>) -> Self {
            Self(offered.into_iter().collect())
        }
    }

    impl Capabilities for FakeCapabilities {
        fn offers(&self, backend: Backend) -> bool {
            self.0.contains(&backend)
        }
    }

    pub struct FakeTemplateStore(HashMap<(Backend, TemplateRef), PolicyBody>);

    impl FakeTemplateStore {
        pub fn new(entries: impl IntoIterator<Item = (TemplateRef, Vec<u8>)>) -> Self {
            Self::with_backend(Backend::NetworkPolicy, entries)
        }

        pub fn with_backend(
            backend: Backend,
            entries: impl IntoIterator<Item = (TemplateRef, Vec<u8>)>,
        ) -> Self {
            Self(
                entries
                    .into_iter()
                    .map(|(reference, bytes)| ((backend, reference), PolicyBody::opaque(bytes)))
                    .collect(),
            )
        }
    }

    impl TemplateStore for FakeTemplateStore {
        fn body(&self, backend: Backend, template_ref: &TemplateRef) -> Option<PolicyBody> {
            self.0.get(&(backend, template_ref.clone())).cloned()
        }
    }

    /// A `BaselineView` over a fixed set of namespaces that have one.
    pub struct FakeBaselineView(HashSet<NamespaceName>);

    impl FakeBaselineView {
        pub fn new(with_baseline: impl IntoIterator<Item = NamespaceName>) -> Self {
            Self(with_baseline.into_iter().collect())
        }
    }

    impl BaselineView for FakeBaselineView {
        fn has_baseline(&self, ns: &NamespaceName) -> bool {
            self.0.contains(ns)
        }
    }

    /// A `CanaryProbe` that replays a scripted `(unrestricted, restricted)` pair, and records
    /// which legs were actually run — so a test can assert the second leg is *skipped* when the
    /// first one already failed, not merely that the verdict came out `Unknown`.
    pub struct FakeCanaryProbe {
        unrestricted: Reachability,
        restricted: Reachability,
        legs: RwLock<Vec<bool>>,
    }

    impl FakeCanaryProbe {
        pub fn new(unrestricted: Reachability, restricted: Reachability) -> Self {
            Self {
                unrestricted,
                restricted,
                legs: RwLock::new(Vec::new()),
            }
        }

        /// The `restricted` argument of every leg that ran, in order.
        pub fn legs_run(&self) -> Vec<bool> {
            self.legs
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl CanaryProbe for FakeCanaryProbe {
        fn reachability(
            &self,
            restricted: bool,
        ) -> Pin<Box<dyn Future<Output = Result<Reachability, DomainError>> + Send + '_>> {
            self.legs
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(restricted);
            let observed = if restricted {
                self.restricted
            } else {
                self.unrestricted
            };
            Box::pin(async move { Ok(observed) })
        }

        fn cleanup(&self) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// A `ReconcileObserver` that records what it was told, for a test to assert against.
    #[derive(Default)]
    pub struct RecordingReconcileObserver {
        pub reconciled: RwLock<Vec<crate::application::ReconcileOutcome>>,
        pub failures: RwLock<usize>,
        pub canary: RwLock<Option<crate::canary::CanaryVerdict>>,
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

        fn managed_objects(&self, _objects: &[ManagedObject]) {}

        fn canary(&self, verdict: crate::canary::CanaryVerdict) {
            *self
                .canary
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(verdict);
        }
    }

    /// An in-memory `PolicyStore` — a flat `Vec<ManagedObject>`, since a `ManagedObject`'s own
    /// `ObjectKey` already carries its namespace.
    #[derive(Default)]
    pub struct FakePolicyStore(RwLock<Vec<ManagedObject>>);

    impl FakePolicyStore {
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

    impl PolicyStore for FakePolicyStore {
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
}
