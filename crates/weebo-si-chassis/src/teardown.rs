//! The control-plane identities that tear a namespace down — shared by every guard that refuses
//! writes to operator-managed objects.

/// The namespace controller (which deletes every object in a terminating namespace) and the
/// garbage collector (which deletes dependents whose owner is gone), each under its own service
/// account when kube-controller-manager runs with `--use-service-account-credentials`, and under
/// the shared `system:kube-controller-manager` user when it does not.
///
/// A guard exempts these on `DELETE`. Without that, a namespace holding a managed object stays
/// `Terminating` forever while the guard enforces: the namespace controller's delete is refused
/// like any other actor's. None of these identities can be obtained by a workspace user.
pub const TEARDOWN_IDENTITIES: [&str; 3] = [
    "system:serviceaccount:kube-system:namespace-controller",
    GARBAGE_COLLECTOR,
    CONTROLLER_MANAGER,
];

const GARBAGE_COLLECTOR: &str = "system:serviceaccount:kube-system:generic-garbage-collector";
const CONTROLLER_MANAGER: &str = "system:kube-controller-manager";

/// Whether `actor` is one of [`TEARDOWN_IDENTITIES`].
pub fn is_teardown_identity(actor: &str) -> bool {
    TEARDOWN_IDENTITIES.contains(&actor)
}

/// Whether a guard lets `actor` through for this write: any teardown identity on a `DELETE`, and
/// the garbage collector alone on an `UPDATE`.
///
/// The `UPDATE` is the orphaning delete: `kubectl delete devworkspace x --cascade=orphan` makes
/// the garbage collector *patch* every dependent to drop its `ownerReference` before the owner
/// goes, and a refused patch leaves the owner stuck behind its `orphan` finalizer forever.
/// Profile objects carry an `ownerReference` to their DevWorkspace, so this is reachable. The
/// garbage collector only ever edits `metadata.ownerReferences`/`finalizers`, and the identity is
/// not one a workspace user can hold.
pub fn teardown_may(actor: &str, deleting: bool) -> bool {
    if deleting {
        is_teardown_identity(actor)
    } else {
        actor == GARBAGE_COLLECTOR || actor == CONTROLLER_MANAGER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_namespace_controller_may_delete_but_never_update() {
        let namespace_controller = TEARDOWN_IDENTITIES[0];
        assert!(teardown_may(namespace_controller, true));
        assert!(!teardown_may(namespace_controller, false));
    }

    #[test]
    fn the_garbage_collector_may_orphan_as_well_as_delete() {
        for actor in [GARBAGE_COLLECTOR, CONTROLLER_MANAGER] {
            assert!(teardown_may(actor, true));
            assert!(teardown_may(actor, false));
        }
    }

    #[test]
    fn nobody_else_is_let_through() {
        assert!(!teardown_may("user-alice", true));
        assert!(!teardown_may(
            "system:serviceaccount:user-alice:default",
            false
        ));
    }
}
