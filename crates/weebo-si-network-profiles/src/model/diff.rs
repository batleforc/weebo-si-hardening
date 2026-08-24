//! `DesiredState` and the diff against what a `PolicyStore` port reports exists now. Pure — no
//! I/O, no `kube` — so it is exhaustively tested without a cluster, per RFC 0004's *Architecture*.

use weebo_si_crd::{Backend, ProfileKey, TeamName};

use super::policy::{ManagedObject, ObjectKey};

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

/// One line of the diff between `desired` and what a `PolicyStore` reports exists now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diff {
    /// Present in `desired`, absent from `existing`.
    Create(ManagedObject),
    /// Present in both, but `backend`/`pod_selector`/`body` differ.
    Update(ManagedObject),
    /// Present in `existing`, absent from `desired`. Carries `backend` — unlike `Create`/`Update`
    /// there is no `ManagedObject` to read it from, and a `PolicyStore` adapter needs it to know
    /// which API (`NetworkPolicy` or `CiliumNetworkPolicy`) to issue the delete against.
    Delete {
        /// The object's identity.
        key: ObjectKey,
        /// Which dialect it was written in.
        backend: Backend,
    },
    /// Present in both, identical.
    Unchanged(ObjectKey),
}

/// Compute the diff between what should exist (`desired`) and what a `PolicyStore` reports
/// exists now (`existing`).
///
/// `existing` is trusted to already be filtered to this feature's own managed objects — the
/// `hardening.weebo.io/managed-by` label check is a `PolicyStore` port responsibility (a later
/// phase's), not this function's, per RFC 0004's *Security considerations*: "the operator reads,
/// updates and deletes only objects carrying the label." A caller that never puts an unmanaged
/// object into `existing` gets the RFC's invariant for free — this function cannot produce a
/// `Delete` for an object it was never told about.
pub fn compute_diff(desired: &[ManagedObject], existing: &[ManagedObject]) -> Vec<Diff> {
    let mut diffs = Vec::new();

    for wanted in desired {
        match existing.iter().find(|obj| obj.key == wanted.key) {
            None => diffs.push(Diff::Create(wanted.clone())),
            Some(current) => {
                if current.backend == wanted.backend
                    && current.pod_selector == wanted.pod_selector
                    && current.body == wanted.body
                {
                    diffs.push(Diff::Unchanged(wanted.key.clone()));
                } else {
                    diffs.push(Diff::Update(wanted.clone()));
                }
            }
        }
    }

    for present in existing {
        if !desired.iter().any(|obj| obj.key == present.key) {
            diffs.push(Diff::Delete {
                key: present.key.clone(),
                backend: present.backend,
            });
        }
    }

    diffs
}

/// Counts of what a `PolicyStore::apply` call did, one per `Diff` variant — never the objects
/// themselves, since a caller already has those in the `Diff`s it passed in. Feeds
/// `weebo_si_network_reconcile_total` in a later phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// How many `Diff::Create` lines were applied.
    pub created: u32,
    /// How many `Diff::Update` lines were applied.
    pub updated: u32,
    /// How many `Diff::Delete` lines were applied.
    pub deleted: u32,
    /// How many `Diff::Unchanged` lines needed no write.
    pub unchanged: u32,
}

/// Tally `diffs` by variant. Pure — a `PolicyStore` adapter calls this over whatever it actually
/// wrote, but the counting itself needs no I/O to test.
pub fn tally(diffs: &[Diff]) -> Applied {
    let mut applied = Applied::default();
    for diff in diffs {
        match diff {
            Diff::Create(_) => applied.created += 1,
            Diff::Update(_) => applied.updated += 1,
            Diff::Delete { .. } => applied.deleted += 1,
            Diff::Unchanged(_) => applied.unchanged += 1,
        }
    }
    applied
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

    #[test]
    fn present_only_in_desired_is_a_create() {
        let desired = [object("weebo-git", b"a")];
        let diffs = compute_diff(&desired, &[]);
        assert_eq!(diffs, vec![Diff::Create(desired[0].clone())]);
    }

    #[test]
    fn present_only_in_existing_is_a_delete() {
        let existing = [object("weebo-git", b"a")];
        let diffs = compute_diff(&[], &existing);
        assert_eq!(
            diffs,
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: existing[0].backend,
            }]
        );
    }

    #[test]
    fn identical_in_both_is_unchanged() {
        let desired = [object("weebo-git", b"a")];
        let existing = [object("weebo-git", b"a")];
        let diffs = compute_diff(&desired, &existing);
        assert_eq!(diffs, vec![Diff::Unchanged(desired[0].key.clone())]);
    }

    #[test]
    fn same_key_different_body_is_an_update() {
        let desired = [object("weebo-git", b"new")];
        let existing = [object("weebo-git", b"old")];
        let diffs = compute_diff(&desired, &existing);
        assert_eq!(diffs, vec![Diff::Update(desired[0].clone())]);
    }

    #[test]
    fn same_key_different_pod_selector_is_an_update() {
        let mut desired = object("weebo-git", b"a");
        desired.pod_selector = PodSelector::DevWorkspaceId("ws1".to_string());
        let existing = object("weebo-git", b"a");
        let diffs = compute_diff(&[desired.clone()], &[existing]);
        assert_eq!(diffs, vec![Diff::Update(desired)]);
    }

    #[test]
    fn an_empty_desired_and_an_empty_existing_produce_no_diff() {
        assert!(compute_diff(&[], &[]).is_empty());
    }

    #[test]
    fn a_namespace_out_of_scope_never_produces_a_delete_because_nothing_is_passed_as_existing() {
        // The scope check happens before this function is ever called (a namespace outside
        // `namespaceSelector` produces an empty `existing` slice at the call site, per the
        // RFC's "scope is a selector, applied before anything is computed"). This test
        // documents that this function has no way to reintroduce that bug: with an empty
        // `existing`, the only diffs it can produce are creates.
        let desired = [object("weebo-git", b"a")];
        let diffs = compute_diff(&desired, &[]);
        assert!(diffs.iter().all(|d| matches!(d, Diff::Create(_))));
    }

    #[test]
    fn tally_of_no_diffs_is_all_zero() {
        assert_eq!(tally(&[]), Applied::default());
    }

    #[test]
    fn tally_counts_one_of_each_kind() {
        let obj = object("weebo-git", b"a");
        let diffs = vec![
            Diff::Create(obj.clone()),
            Diff::Update(obj.clone()),
            Diff::Delete {
                key: obj.key.clone(),
                backend: obj.backend,
            },
            Diff::Unchanged(obj.key.clone()),
        ];
        assert_eq!(
            tally(&diffs),
            Applied {
                created: 1,
                updated: 1,
                deleted: 1,
                unchanged: 1,
            }
        );
    }

    #[test]
    fn tally_counts_multiple_of_the_same_kind() {
        let a = object("weebo-git", b"a");
        let b = object("weebo-vault", b"b");
        let diffs = vec![Diff::Create(a), Diff::Create(b)];
        assert_eq!(
            tally(&diffs),
            Applied {
                created: 2,
                ..Applied::default()
            }
        );
    }
}
