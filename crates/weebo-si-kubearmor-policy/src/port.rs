//! What this feature needs from the cluster, without knowing how to ask for it — the watch, the
//! discovery call and the apiserver round-trip are an adapter's problem.
//!
//! Four of the five mirror `network-profiles`' own ports method for method. The fifth,
//! [`NodeEnforcerView`], is new to this brick and is the asymmetry RFC 0006's *Architecture*
//! spends a paragraph on: `Capabilities` there answers a cluster-wide question that is knowable
//! *before* writing anything, while "is this policy actually enforced where this pod landed" is
//! a per-node question knowable only afterwards.

use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::DomainError;
use weebo_si_crd::{NamespaceName, RuntimeBackend, TemplateRef};

use crate::model::diff::{Applied, Diff};
use crate::model::policy::{ManagedObject, RuleBody};

/// Which runtime-enforcement engines this cluster actually offers — in practice, whether the
/// apiserver serves the `KubeArmorPolicy` CRD at all.
///
/// A cluster-wide question with a cluster-wide answer, and deliberately **not** the same question
/// as "will this policy be enforced on the node this pod lands on": see [`NodeEnforcerView`].
/// `weebo-si-operator backends kubearmor` prints both, because collapsing them into one answer is
/// how an operator ends up believing a policy is enforced when it is merely present.
pub trait Capabilities {
    /// Whether the apiserver advertises `backend`.
    fn offers(&self, backend: RuntimeBackend) -> bool;
}

/// Fetch a template's rule content by reference. The domain copies whatever comes back verbatim
/// and never inspects it — see [`crate::model::policy::RuleBody`]'s doc.
pub trait TemplateStore {
    /// The body a template object carries, if it resolves. `backend` is a parameter even though
    /// only one member exists today, for the reason [`RuntimeBackend`] itself has one member: a
    /// second engine reads its templates from a different API resource at the same `{name,
    /// namespace}`, and that must be an added variant rather than a changed signature.
    ///
    /// `None` covers both "the object does not exist" and "it exists but is not yet in this
    /// adapter's watch cache" — indistinguishable to a caller and treated identically (write
    /// nothing for this object).
    fn body(&self, backend: RuntimeBackend, template_ref: &TemplateRef) -> Option<RuleBody>;
}

/// What exists now, and applying a diff against it. An adapter implementing this over a real
/// cluster is trusted to have already filtered [`Self::managed_in`]'s result to objects carrying
/// `hardening.weebo.io/managed-by: weebo-si-operator` — that filter belongs here and not in the
/// diff computation, per RFC 0004's *Security considerations*, which this brick inherits
/// unchanged.
pub trait PolicyStore: Send + Sync {
    /// Every managed object currently in `ns`. Synchronous — a real adapter answers this from an
    /// in-memory watch cache, never a live apiserver round-trip.
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject>;
    /// Every managed object anywhere in the cluster — the population
    /// `weebo_si_kubearmor_managed_objects` reports.
    fn managed_everywhere(&self) -> Vec<ManagedObject>;
    /// Apply every line of `diffs` — create, update, delete; `Unchanged` is a no-op line kept for
    /// the tally. Returns counts, not the objects: the caller already has those in `diffs`.
    ///
    /// **Async, unlike every other port in this crate** — a real adapter genuinely writes to the
    /// apiserver here. A manually boxed future rather than `async fn` in the trait: this port is
    /// called through `&dyn PolicyStore`, and native `async fn` in a trait is not object-safe.
    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>>;
}

/// Whether a namespace already carries its baseline object.
///
/// A port of its own rather than a second method on [`PolicyStore`], for the reason
/// `network-profiles`' `BaselineView` is one: its consumers run in the **webhook** role, which
/// writes nothing and has no business being handed `apply`.
pub trait BaselineView: Send + Sync {
    /// Whether `ns` currently carries a managed baseline object. Synchronous, from a watch cache.
    fn has_baseline(&self, ns: &NamespaceName) -> bool;
}

/// Whether the node a given workspace's pods landed on can enforce at all — the join RFC 0006
/// puts behind one port rather than two.
///
/// **This port reads two resources and reports one fact**, and that shape is deliberate. The
/// underlying signals are a `Pod`'s `spec.nodeName` and that node's `kubearmor.io/enforcer`
/// label; joining them in the adapter keeps the two cluster-scoped reads (a `Node` watch is this
/// project's first outside its own CRD) behind a single, narrowly-typed answer, so nothing in the
/// domain can start reading a node for some other reason. The bounded projection is the adapter's
/// contract, restated in RFC 0006's *Security considerations → Privileges*: label out, nothing
/// else.
///
/// It answers about a *workspace*, not a pod, because that is the granularity the gauge reports
/// and because a workspace with no running pod is a legitimate, distinct answer
/// ([`Enforcement::Unknown`]) rather than a missing sample.
pub trait NodeEnforcerView: Send + Sync {
    /// What the node hosting `workspace_id`'s pods reports. Synchronous, from watch caches.
    fn enforcement(&self, ns: &NamespaceName, workspace_id: &str) -> Enforcement;
}

/// Who to ask [`NodeEnforcerView`] about, and when to forget what it answered.
///
/// A separate port rather than two more methods on [`NodeEnforcerView`], because the two answer
/// different questions for different callers: the domain asks "is *this* workspace enforced" and
/// must not be able to enumerate the fleet, while the controller's gauge tick needs the roster
/// and never makes a decision from it. Splitting them keeps the enumeration out of reach of
/// anything holding a `NodeEnforcerView` — nothing in this crate's decision path takes an
/// `EnforcementSubjects`, and nothing can start to without that showing up in a signature.
///
/// Declared here rather than next to the controller loop that consumes it so the adapter
/// implementing it (`weebo-si-runtime`) can name it at all: the adapter crate depends on this
/// one and not on the controller.
pub trait EnforcementSubjects {
    /// Every `{namespace, workspace_id}` currently running a pod.
    fn workspaces(&self) -> Vec<(NamespaceName, String)>;
    /// Drop any memoised node lookups before the next sweep, so a node relabelled by KubeArmor's
    /// operator is picked up rather than never.
    fn invalidate(&self);
}

/// What [`NodeEnforcerView`] found — the value behind `weebo_si_kubearmor_enforced`.
///
/// Three states rather than a `bool`, because "no pod is running for this workspace" and "a pod
/// is running on a node with no usable LSM" are different facts and RFC 0006's whole *Bypass*
/// argument depends on not conflating them. What the RFC's own metric definition does conflate —
/// a node with no enforcer against a pod opted out through KubeArmor's per-pod annotation — is
/// its stated open question, and it stays open here: both arrive as [`Enforcement::NotEnforced`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enforcement {
    /// The node carries a `kubearmor.io/enforcer` label naming a real enforcer — the value is
    /// carried so a log line can say *which* (`bpf`, `apparmor`, `selinux`) rather than only
    /// "yes".
    Enforced(String),
    /// A pod is scheduled, and its node's `kubearmor.io/enforcer` label is absent or empty.
    /// Policy objects exist and are not enforced there; the gauge reads `0`.
    NotEnforced,
    /// No pod of this workspace is scheduled anywhere yet, or its node is not in the watch cache.
    /// Not a failure — the gauge reports no sample at all rather than a misleading `0`.
    Unknown,
}

impl Enforcement {
    /// The gauge value, when there is one. `None` for [`Enforcement::Unknown`] — the caller
    /// removes the sample rather than publishing a zero it cannot stand behind.
    pub fn gauge(&self) -> Option<f64> {
        match self {
            Self::Enforced(_) => Some(1.0),
            Self::NotEnforced => Some(0.0),
            Self::Unknown => None,
        }
    }
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
    /// A fresh snapshot of everything this operator currently owns.
    fn managed_objects(&self, objects: &[ManagedObject]);
    /// A fresh snapshot of every workspace's enforcement state.
    ///
    /// **The whole fleet at once, not one workspace at a time**, and the shape is the contract
    /// rather than a convenience. RFC 0004's *Observability contract* rules that "no metric
    /// carries a namespace or a workspace id as a label... a per-workspace time series is how a
    /// metrics backend is taken down by a hardening component", and that rule binds this brick
    /// too. An implementor is therefore expected to publish *counts per state*, which it can only
    /// do from the full population — the same argument [`Self::managed_objects`] makes for taking
    /// a snapshot rather than a delta. Which particular workspace is unenforced is a log line and
    /// a `kubectl` query, not a time series.
    fn enforcement_snapshot(&self, states: &[Enforcement]);
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

    pub struct FakeCapabilities(HashSet<RuntimeBackend>);

    impl FakeCapabilities {
        pub fn new(offered: impl IntoIterator<Item = RuntimeBackend>) -> Self {
            Self(offered.into_iter().collect())
        }
    }

    impl Capabilities for FakeCapabilities {
        fn offers(&self, backend: RuntimeBackend) -> bool {
            self.0.contains(&backend)
        }
    }

    pub struct FakeTemplateStore(HashMap<(RuntimeBackend, TemplateRef), RuleBody>);

    impl FakeTemplateStore {
        pub fn new(entries: impl IntoIterator<Item = (TemplateRef, Vec<u8>)>) -> Self {
            Self::with_backend(RuntimeBackend::KubeArmor, entries)
        }

        pub fn with_backend(
            backend: RuntimeBackend,
            entries: impl IntoIterator<Item = (TemplateRef, Vec<u8>)>,
        ) -> Self {
            Self(
                entries
                    .into_iter()
                    .map(|(reference, bytes)| ((backend, reference), RuleBody::opaque(bytes)))
                    .collect(),
            )
        }
    }

    impl TemplateStore for FakeTemplateStore {
        fn body(&self, backend: RuntimeBackend, template_ref: &TemplateRef) -> Option<RuleBody> {
            self.0.get(&(backend, template_ref.clone())).cloned()
        }
    }

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

    /// A `NodeEnforcerView` over a scripted `{(namespace, workspace_id) -> Enforcement}` map;
    /// anything not in it is `Unknown`, which is what a real adapter reports for a workspace
    /// with no scheduled pod.
    #[derive(Default)]
    pub struct FakeNodeEnforcerView(HashMap<(String, String), Enforcement>);

    impl FakeNodeEnforcerView {
        pub fn new(entries: impl IntoIterator<Item = ((String, String), Enforcement)>) -> Self {
            Self(entries.into_iter().collect())
        }
    }

    impl NodeEnforcerView for FakeNodeEnforcerView {
        fn enforcement(&self, ns: &NamespaceName, workspace_id: &str) -> Enforcement {
            self.0
                .get(&(ns.as_str().to_string(), workspace_id.to_string()))
                .cloned()
                .unwrap_or(Enforcement::Unknown)
        }
    }

    #[derive(Default)]
    pub struct RecordingReconcileObserver {
        pub reconciled: RwLock<Vec<crate::application::ReconcileOutcome>>,
        pub failures: RwLock<usize>,
        pub enforced: RwLock<Vec<Enforcement>>,
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

        fn enforcement_snapshot(&self, states: &[Enforcement]) {
            *self
                .enforced
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = states.to_vec();
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn an_enforced_node_gauges_one_and_names_its_enforcer() {
        let enforcement = Enforcement::Enforced("bpf".to_string());
        assert_eq!(enforcement.gauge(), Some(1.0));
    }

    #[test]
    fn a_node_with_no_enforcer_gauges_zero_rather_than_going_quiet() {
        // RFC 0006's *Bypass*: "making the gap visible: `weebo_si_kubearmor_enforced` at `0`,
        // not a metric that goes quiet."
        assert_eq!(Enforcement::NotEnforced.gauge(), Some(0.0));
    }

    #[test]
    fn an_unscheduled_workspace_publishes_no_sample_rather_than_a_zero_it_cannot_stand_behind() {
        assert_eq!(Enforcement::Unknown.gauge(), None);
    }
}
