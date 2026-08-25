//! `DesiredState` — what a `desired()` call computed for one subject — over the diff machinery
//! the chassis owns.
//!
//! [`Diff`], `compute_diff`, `Applied` and `tally` are [`weebo_si_chassis::managed`]'s, per RFC
//! 0006's *Architecture*: "reused diff machinery — a `KubeArmorPolicy` and a `NetworkPolicy`
//! diff the same way: compare spec bodies under a managed-by label filter." What this module
//! owns is what is genuinely this feature's: [`DesiredState`] and its provenance, and the
//! [`Managed`] impl saying what "same content" means for a `KubeArmorPolicy`.

use weebo_si_chassis::managed::{Managed, ObjectKey};
use weebo_si_crd::{DefaultPosture, RuntimeBackend, RuntimeProfileKey, TeamName};

use super::policy::ManagedObject;

pub use weebo_si_chassis::managed::{Applied, compute_diff, tally};

/// One line of the diff between `desired` and what a [`crate::port::PolicyStore`] reports exists
/// now — the chassis' generic [`weebo_si_chassis::managed::Diff`] at this feature's object type.
pub type Diff = weebo_si_chassis::managed::Diff<ManagedObject>;

impl Managed for ManagedObject {
    type Backend = RuntimeBackend;

    fn key(&self) -> &ObjectKey {
        &self.key
    }

    fn backend(&self) -> RuntimeBackend {
        self.backend
    }

    /// Engine, selector and rule body. `profile` is deliberately not compared — it is provenance
    /// carried into a label, and a catalogue key renamed over identical rules is not a reason to
    /// rewrite every policy in the fleet, which for this feature means a KubeArmor reload on
    /// every node hosting one of those workspaces.
    fn content_eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.pod_selector == other.pod_selector
            && self.body == other.body
    }
}

/// What a `ReconcileFeature::desired` call computed: the objects that should exist for one
/// subject (a namespace's baseline, or one workspace's profile objects), the posture that
/// namespace should carry, and the two facts about *how* that answer was reached that RFC 0006's
/// observability needs as metric labels.
///
/// The provenance fields are carried here rather than recomputed by the caller, for the reason
/// `network-profiles`' own `DesiredState` gives: `team` and `not_granted` fall out of
/// [`crate::resolve::resolve`], which already ran inside `desired()`, and a controller calling
/// `resolve` a second time to label a counter would be two copies of the resolution chain free
/// to drift apart.
///
/// **No `unsupported` field**, unlike `network-profiles`'. There, a profile can resolve and still
/// have no variant for the running backend, which is a per-profile degradation the metric has to
/// name. Here a catalogue entry carries exactly one `templateRef` and there is exactly one
/// engine, so that state cannot exist: either the cluster serves `KubeArmorPolicy` — a
/// cluster-wide answer [`crate::port::Capabilities`] gives once — or nothing is written at all.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredState {
    /// The objects that should exist for this subject.
    pub objects: Vec<ManagedObject>,
    /// The default posture this subject's namespace should carry, as KubeArmor's own three
    /// annotations. `Some` only for a namespace subject: posture is a property of the namespace,
    /// and a workspace pass must never race another workspace's pass to rewrite it.
    pub posture: Option<DefaultPosture>,
    /// The team that matched this subject's namespace, if any — the `team` label on
    /// `weebo_si_kubearmor_reconcile_total` and `weebo_si_kubearmor_not_granted_total`.
    pub team: Option<TeamName>,
    /// Keys the subject asked for that its team's grant does not allow. Always empty for a
    /// namespace baseline, which no grant can withhold.
    pub not_granted: Vec<RuntimeProfileKey>,
}

impl DesiredState {
    /// The common case: some objects, no posture, no team, nothing dropped.
    pub fn objects(objects: Vec<ManagedObject>) -> Self {
        Self {
            objects,
            ..Self::default()
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
    use weebo_si_crd::NamespaceName;

    use super::super::policy::{PodSelector, RuleBody};
    use super::*;

    fn object(name: &str, body: &[u8]) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            backend: RuntimeBackend::KubeArmor,
            profile: RuntimeProfileKey::new("git-write"),
            pod_selector: PodSelector::Empty,
            body: RuleBody::opaque(body.to_vec()),
        }
    }

    // The algorithm is tested exhaustively in `weebo_si_chassis::managed::diff`. What is this
    // feature's own — and therefore tested here — is the `Managed` impl above.

    #[test]
    fn same_key_different_rule_body_is_an_update() {
        let desired = [object("weebo-base", b"new")];
        let existing = [object("weebo-base", b"old")];
        assert_eq!(
            compute_diff(&desired, &existing),
            vec![Diff::Update(desired[0].clone())]
        );
    }

    #[test]
    fn same_key_different_pod_selector_is_an_update() {
        let mut desired = object("weebo-base", b"a");
        desired.pod_selector = PodSelector::DevWorkspaceId("ws1".to_string());
        let existing = object("weebo-base", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_renamed_profile_key_alone_does_not_rewrite_the_policy() {
        // Rewriting a KubeArmorPolicy is not free: KubeArmor reprograms the LSM on every node
        // running a pod the policy selects. A catalogue rename must not cost that.
        let mut desired = object("weebo-base", b"a");
        desired.profile = RuntimeProfileKey::new("base-v2");
        let existing = object("weebo-base", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Unchanged(desired.key.clone())]
        );
    }

    #[test]
    fn the_delete_line_carries_the_backend_an_adapter_needs() {
        let existing = [object("weebo-base", b"a")];
        assert_eq!(
            compute_diff(&[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: RuntimeBackend::KubeArmor,
            }]
        );
    }

    #[test]
    fn desired_state_objects_carries_no_posture() {
        // `DesiredState::objects` is the workspace-subject constructor; posture belongs to the
        // namespace pass alone.
        let state = DesiredState::objects(vec![object("weebo-base", b"a")]);
        assert_eq!(state.posture, None);
        assert_eq!(state.team, None);
        assert!(state.not_granted.is_empty());
    }
}
