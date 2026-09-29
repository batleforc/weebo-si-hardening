//! Which of a namespace's managed objects one reconcile subject *owns* — and the diff restricted
//! to exactly those.
//!
//! A namespace holds objects written by more than one reconcile subject: the namespace pass
//! writes the baseline (`PodSelector::Empty`), and every DevWorkspace pass writes its own profile
//! objects (`PodSelector::DevWorkspaceId(id)`). Each pass's `desired()` only ever describes its
//! own share, so diffing it against *every* managed object in the namespace turns every other
//! subject's objects into `Delete` lines — the namespace pass deleting every workspace's
//! profiles, each workspace pass deleting the baseline and every sibling workspace's objects.
//!
//! [`compute_owned_diff`] is the only diff a subject-driven reconcile should call, and it takes
//! the owner's selector as a required argument; [`OwnedScope`] is the bound
//! `application::reconcile` puts on its subject, so a new subject type cannot reach a reconcile
//! without answering "which objects are mine".

use super::diff::{Diff, Managed, compute_diff};
use super::object::{ObjectKey, PodSelector};
use crate::error::DomainError;
use crate::feature::Subject;

/// A managed object that governs a set of pods through a [`PodSelector`] — the selector being
/// what ties it to the subject that wrote it.
pub trait Selected: Managed {
    /// Which pods this object governs.
    fn pod_selector(&self) -> &PodSelector;
}

/// A reconcile subject that owns exactly the managed objects carrying one pod selector.
///
/// **Required, with no default**, for the reason [`Subject::resource`] is: a default would let
/// the next subject type silently inherit someone else's scope.
pub trait OwnedScope: Subject {
    /// The selector every object this subject writes carries — and therefore the only objects a
    /// reconcile of this subject may update or delete.
    fn owned_selector(&self) -> PodSelector;
}

/// [`compute_diff`], restricted to the objects `owner` owns.
///
/// - `existing` is filtered to objects whose selector is `owner` before diffing, so another
///   subject's objects can never become a `Delete`.
/// - `held` names objects the caller could not build this pass (a template that is deleted or
///   not yet in the watch cache) and whose live copy must therefore be left exactly as it is:
///   no `Delete`, no `Update`. Failing closed means keeping the policy that is enforced now, not
///   removing it because its replacement is momentarily unreadable.
/// - Every `desired` object must carry `owner` (a feature bug otherwise), and none may share a
///   key with a live object another subject owns — writing it would silently take that object
///   over. Both are refused as [`DomainError::InvalidConfiguration`].
pub fn compute_owned_diff<M: Selected>(
    owner: &PodSelector,
    desired: &[M],
    held: &[ObjectKey],
    existing: &[M],
) -> Result<Vec<Diff<M>>, DomainError> {
    if let Some(stray) = desired.iter().find(|obj| obj.pod_selector() != owner) {
        return Err(DomainError::InvalidConfiguration(format!(
            "desired object {}/{} carries selector {:?}, not its subject's {owner:?}",
            stray.key().namespace,
            stray.key().name,
            stray.pod_selector()
        )));
    }
    if let Some(foreign) = existing
        .iter()
        .filter(|obj| obj.pod_selector() != owner)
        .find(|obj| desired.iter().any(|wanted| wanted.key() == obj.key()))
    {
        return Err(DomainError::InvalidConfiguration(format!(
            "desired object {}/{} collides with a live object owned by selector {:?}",
            foreign.key().namespace,
            foreign.key().name,
            foreign.pod_selector()
        )));
    }

    let owned: Vec<M> = existing
        .iter()
        .filter(|obj| obj.pod_selector() == owner && !held.contains(obj.key()))
        .cloned()
        .collect();
    Ok(compute_diff(desired, &owned))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::NamespaceName;

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Fake {
        key: ObjectKey,
        selector: PodSelector,
        body: Vec<u8>,
    }

    impl Managed for Fake {
        type Backend = ();

        fn key(&self) -> &ObjectKey {
            &self.key
        }

        fn backend(&self) {}

        fn content_eq(&self, other: &Self) -> bool {
            self.selector == other.selector && self.body == other.body
        }
    }

    impl Selected for Fake {
        fn pod_selector(&self) -> &PodSelector {
            &self.selector
        }
    }

    fn key(name: &str) -> ObjectKey {
        ObjectKey {
            namespace: NamespaceName::new("user-alice"),
            name: name.to_string(),
        }
    }

    fn object(name: &str, selector: PodSelector, body: &[u8]) -> Fake {
        Fake {
            key: key(name),
            selector,
            body: body.to_vec(),
        }
    }

    fn ws(id: &str) -> PodSelector {
        PodSelector::DevWorkspaceId(id.to_string())
    }

    fn live() -> Vec<Fake> {
        vec![
            object("weebo-base", PodSelector::Empty, b"base"),
            object("weebo-git-ws1", ws("ws1"), b"git"),
            object("weebo-vault-ws1", ws("ws1"), b"vault"),
            object("weebo-git-ws2", ws("ws2"), b"git"),
        ]
    }

    fn deleted(diffs: &[Diff<Fake>]) -> Vec<String> {
        diffs
            .iter()
            .filter_map(|d| match d {
                Diff::Delete { key, .. } => Some(key.name.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_namespace_scope_never_deletes_a_workspace_object() {
        let desired = [object("weebo-base", PodSelector::Empty, b"base")];
        let diffs = compute_owned_diff(&PodSelector::Empty, &desired, &[], &live()).unwrap();
        assert_eq!(diffs, vec![Diff::Unchanged(key("weebo-base"))]);
    }

    #[test]
    fn a_workspace_scope_never_deletes_the_baseline_or_a_sibling_workspace_object() {
        let desired = [
            object("weebo-git-ws1", ws("ws1"), b"git"),
            object("weebo-vault-ws1", ws("ws1"), b"vault"),
        ];
        let diffs = compute_owned_diff(&ws("ws1"), &desired, &[], &live()).unwrap();
        assert!(deleted(&diffs).is_empty(), "{diffs:?}");
    }

    #[test]
    fn a_stale_object_of_the_same_scope_is_still_deleted() {
        let desired = [object("weebo-git-ws1", ws("ws1"), b"git")];
        let diffs = compute_owned_diff(&ws("ws1"), &desired, &[], &live()).unwrap();
        assert_eq!(deleted(&diffs), vec!["weebo-vault-ws1".to_string()]);
    }

    #[test]
    fn a_held_object_is_neither_deleted_nor_updated() {
        let diffs =
            compute_owned_diff::<Fake>(&PodSelector::Empty, &[], &[key("weebo-base")], &live())
                .unwrap();
        assert!(diffs.is_empty(), "{diffs:?}");
    }

    #[test]
    fn a_desired_object_with_a_foreign_selector_is_refused() {
        let desired = [object("weebo-git-ws2", ws("ws2"), b"git")];
        assert!(compute_owned_diff(&ws("ws1"), &desired, &[], &live()).is_err());
    }

    #[test]
    fn a_desired_object_colliding_with_another_scopes_live_object_is_refused() {
        let desired = [object("weebo-base", ws("ws1"), b"x")];
        assert!(compute_owned_diff(&ws("ws1"), &desired, &[], &live()).is_err());
    }
}
