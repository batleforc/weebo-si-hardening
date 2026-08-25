//! `DesiredState` — what a `desired()` call computed for one subject — over the diff machinery
//! the chassis owns.
//!
//! [`Diff`], [`compute_diff`], [`Applied`] and [`tally`] are no longer defined here: RFC 0006's
//! *Architecture* describes `kubearmor-policy`'s diff as **reused**, not reimplemented ("a
//! `KubeArmorPolicy` and a `NetworkPolicy` diff the same way"), so they moved to
//! [`weebo_si_chassis::managed`] alongside `ObjectKey`/`PodSelector` and are re-exported here
//! under their original paths. What stayed is what is genuinely this feature's:
//! [`DesiredState`], whose three provenance fields are `network-profiles`' own observability
//! contract, and the [`Managed`] impl that tells the chassis what "same content" means for a
//! policy object.

use weebo_si_chassis::managed::{Managed, ObjectKey};
use weebo_si_crd::{Backend, ProfileKey, TeamName};

use super::policy::ManagedObject;

pub use weebo_si_chassis::managed::{Applied, compute_diff, tally};

/// One line of the diff between `desired` and what a `PolicyStore` reports exists now — the
/// chassis' generic [`weebo_si_chassis::managed::Diff`] at this feature's own object type.
pub type Diff = weebo_si_chassis::managed::Diff<ManagedObject>;

impl Managed for ManagedObject {
    type Backend = Backend;

    fn key(&self) -> &ObjectKey {
        &self.key
    }

    fn backend(&self) -> Backend {
        self.backend
    }

    /// Dialect, selector and body — the three fields that make the object what it is. `profile`
    /// is deliberately *not* compared: it is provenance carried into a label, and a catalogue
    /// key renamed with identical rules underneath is not a reason to rewrite every object in
    /// the fleet.
    fn content_eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.pod_selector == other.pod_selector
            && self.body == other.body
    }
}

/// What a `ReconcileFeature::desired` call computed: the objects that should exist for one
/// subject (a namespace's baseline, or one workspace's profile objects), plus the three facts
/// about *how* that answer was reached that RFC 0004's *Observability contract* needs as metric
/// labels.
///
/// The provenance fields are deliberately carried here rather than recomputed by the caller.
/// `team` and `not_granted` are outputs of [`crate::resolve::resolve`], which already runs inside
/// `desired()`; having a controller call `resolve` a second time just to label a counter would be
/// two copies of the resolution chain free to drift apart — the failure this crate's
/// "the decision is computed once, in one place" rule exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredState {
    /// The objects that should exist for this subject.
    pub objects: Vec<ManagedObject>,
    /// The team that matched this subject's namespace, if any —
    /// `weebo_si_network_reconcile_total`'s and `weebo_si_network_not_granted_total`'s `team`
    /// label.
    pub team: Option<TeamName>,
    /// Profile keys the subject asked for that its team's grant does not allow —
    /// `weebo_si_network_not_granted_total`'s `profile` label. Always empty for a namespace
    /// baseline, which no grant can withhold.
    pub not_granted: Vec<ProfileKey>,
    /// Profile keys that resolved but carry no variant for the currently resolved backend, and
    /// were therefore **not applied** rather than approximated —
    /// `weebo_si_network_profile_unsupported`. Per the RFC's *Backends and degradation*:
    /// degradation is per profile and never silent.
    pub unsupported: Vec<ProfileKey>,
}

impl DesiredState {
    /// The common case: some objects, no team, nothing dropped, nothing unsupported.
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
    use weebo_si_crd::{Backend, NamespaceName, ProfileKey};

    use super::super::policy::{PodSelector, PolicyBody};
    use super::*;

    fn object(name: &str, body: &[u8]) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            backend: Backend::NetworkPolicy,
            profile: ProfileKey::new("git"),
            pod_selector: PodSelector::Empty,
            body: PolicyBody::opaque(body.to_vec()),
        }
    }

    // The algorithm itself is tested exhaustively in `weebo_si_chassis::managed::diff`. What is
    // this feature's own — and therefore tested here — is the `Managed` impl above: which fields
    // of a policy object make it "the same object" and which do not.

    #[test]
    fn same_key_different_body_is_an_update() {
        let desired = [object("weebo-git", b"new")];
        let existing = [object("weebo-git", b"old")];
        assert_eq!(
            compute_diff(&desired, &existing),
            vec![Diff::Update(desired[0].clone())]
        );
    }

    #[test]
    fn same_key_different_pod_selector_is_an_update() {
        let mut desired = object("weebo-git", b"a");
        desired.pod_selector = PodSelector::DevWorkspaceId("ws1".to_string());
        let existing = object("weebo-git", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn same_key_different_backend_is_an_update() {
        let mut desired = object("weebo-git", b"a");
        desired.backend = Backend::Cilium;
        let existing = object("weebo-git", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_renamed_profile_key_alone_does_not_rewrite_the_object() {
        // `profile` is provenance in a label, not content. Comparing it would mean every
        // catalogue rename rewrites every object in the fleet for no change in behaviour.
        let mut desired = object("weebo-git", b"a");
        desired.profile = ProfileKey::new("git-v2");
        let existing = object("weebo-git", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Unchanged(desired.key.clone())]
        );
    }

    #[test]
    fn the_delete_line_carries_the_backend_an_adapter_needs() {
        let existing = [object("weebo-git", b"a")];
        assert_eq!(
            compute_diff(&[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: Backend::NetworkPolicy,
            }]
        );
    }

    #[test]
    fn desired_state_objects_leaves_every_provenance_field_empty() {
        let state = DesiredState::objects(vec![object("weebo-git", b"a")]);
        assert_eq!(state.objects.len(), 1);
        assert_eq!(state.team, None);
        assert!(state.not_granted.is_empty());
        assert!(state.unsupported.is_empty());
    }
}
