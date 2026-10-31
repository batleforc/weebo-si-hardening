//! Deleting a managed object the way every reconcile store does: pinned to the uid the diff saw,
//! with the outcomes that are not reconcile errors (already gone, recreated since) told apart.

use kube::api::{DeleteParams, Preconditions};
use weebo_si_chassis::DomainError;
use weebo_si_chassis::managed::ObjectKey;

/// `DeleteParams` pinned to the uid the object was listed with, when the diff carried one.
///
/// The watch cache a diff is computed from can be stale, and nothing stops a same-named object
/// being deleted and recreated between that list and this delete — by a user, or by another
/// subject's pass. A delete by name alone would remove the new object; a delete preconditioned
/// on the old uid is refused by the apiserver instead. Shared by every
/// store that deletes what a diff told it to (`network-profiles`, `kubearmor-policy`).
pub fn pinned_delete_params(uid: Option<&str>) -> DeleteParams {
    DeleteParams {
        preconditions: uid.map(|uid| Preconditions {
            uid: Some(uid.to_string()),
            resource_version: None,
        }),
        ..DeleteParams::default()
    }
}

/// What a [`pinned_delete_params`] delete's result means for the reconcile pass.
pub fn pinned_delete_outcome<T>(
    feature: &str,
    key: &ObjectKey,
    result: Result<T, kube::Error>,
) -> Result<(), DomainError> {
    match result {
        Ok(_) => Ok(()),
        // Deleting an object that is already gone is the outcome we wanted, not a failure —
        // this is what keeps a repeated Enforce pass over a namespace idempotent.
        Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
        // The uid precondition failed: the object under this name is not the one the diff saw,
        // so it is not this delete's to remove. Not a reconcile error — the object it was meant
        // for is gone either way, and the newcomer is diffed on its own merits on the next pass.
        Err(kube::Error::Api(err)) if err.code == 409 => {
            tracing::warn!(
                "{feature} not deleting {}/{}: it was recreated since \
                 it was listed ({})",
                key.namespace,
                key.name,
                err.message
            );
            Ok(())
        }
        Err(err) => Err(DomainError::PortFailed(err.to_string())),
    }
}
