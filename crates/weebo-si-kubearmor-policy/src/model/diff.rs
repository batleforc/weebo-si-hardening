//! `DesiredState` — what a `desired()` call computed for one subject — over the diff machinery
//! the chassis owns.
//!
//! [`Diff`], `compute_diff`, `Applied` and `tally` are [`weebo_si_chassis::managed`]'s, per RFC
//! 0006's *Architecture*: "reused diff machinery — a `KubeArmorPolicy` and a `NetworkPolicy`
//! diff the same way: compare spec bodies under a managed-by label filter." What this module
//! owns is what is genuinely this feature's: [`DesiredState`] and its provenance, and the
//! [`Managed`] impl saying what "same content" means for a `KubeArmorPolicy`.

use weebo_si_chassis::managed::{Managed, ObjectKey, PodSelector, Selected};
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
    ///
    /// `owner` **is** compared, and deliberately so. It is not rule content, but a live object
    /// whose `ownerReference` is missing (written before the operator set one) or points at a
    /// different DevWorkspace uid is an object the apiserver will never garbage-collect with its
    /// workspace. Treating that as an `Update` is what adopts every such object on the next pass
    /// — one write per object, once — instead of leaving it orphaned forever once its workspace
    /// is gone (a workspace pass only ever sees its own objects, so nothing else would delete
    /// it). The store adapter reads back exactly the entry it writes, so an object already
    /// carrying the right owner never churns.
    fn content_eq(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.pod_selector == other.pod_selector
            && self.body == other.body
            && self.owner == other.owner
    }

    fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }
}

/// The selector is what ties an object to the subject that wrote it — see
/// [`weebo_si_chassis::managed::scope`].
impl Selected for ManagedObject {
    fn pod_selector(&self) -> &PodSelector {
        &self.pod_selector
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
    /// Objects this subject owns but could not build this pass because their template did not
    /// resolve — deleted, or not yet in the adapter's watch cache. Their live copy is **held**:
    /// never deleted, never updated, until the template resolves again. Dropping them from
    /// `objects` alone would turn a momentarily unreadable template into a `Delete` of the policy
    /// currently enforced (fail-open); holding them fails closed.
    pub held: Vec<ObjectKey>,
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

    use super::super::policy::{Owner, PodSelector, RuleBody};
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
            owner: None,
            uid: None,
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
    fn the_delete_line_carries_the_backend_and_listed_uid_an_adapter_needs() {
        let mut live = object("weebo-base", b"a");
        live.uid = Some("uid-listed".to_string());
        let existing = [live];
        assert_eq!(
            compute_diff(&[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: RuntimeBackend::KubeArmor,
                uid: Some("uid-listed".to_string()),
            }]
        );
    }

    #[test]
    fn a_listed_uid_alone_does_not_rewrite_the_object() {
        // A desired object never carries a uid; a live one always does — comparing it would
        // mean a KubeArmor reload for every policy on every pass.
        let desired = object("weebo-base", b"a");
        let mut existing = object("weebo-base", b"a");
        existing.uid = Some("uid-listed".to_string());
        assert_eq!(
            compute_diff(std::slice::from_ref(&desired), &[existing]),
            vec![Diff::Unchanged(desired.key.clone())]
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

    fn owner(uid: &str) -> Owner {
        Owner {
            api_version: "workspace.devfile.io/v1alpha2".to_string(),
            kind: "DevWorkspace".to_string(),
            name: "data-pipeline".to_string(),
            uid: uid.to_string(),
        }
    }

    #[test]
    fn a_live_object_lacking_its_owner_is_updated_so_it_is_adopted() {
        // An object written before the operator set `ownerReferences` would otherwise never be
        // garbage-collected with its workspace — nothing else ever deletes it.
        let mut desired = object("weebo-git-ws1", b"a");
        desired.owner = Some(owner("uid-1"));
        let existing = object("weebo-git-ws1", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_live_object_owned_by_a_different_uid_is_updated() {
        let mut desired = object("weebo-git-ws1", b"a");
        desired.owner = Some(owner("uid-2"));
        let mut existing = object("weebo-git-ws1", b"a");
        existing.owner = Some(owner("uid-1"));
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_live_object_already_carrying_its_owner_is_unchanged() {
        let mut desired = object("weebo-git-ws1", b"a");
        desired.owner = Some(owner("uid-1"));
        let existing = desired.clone();
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Unchanged(desired.key.clone())]
        );
    }
}
