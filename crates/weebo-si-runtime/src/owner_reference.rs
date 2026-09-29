//! The one `metadata.ownerReferences` entry a workspace-scoped policy object carries, written and
//! read back by both policy stores ([`crate::kube_policy_store`], [`crate::kubearmor_policy_store`])
//! — see RFC 0004's *The objects written*: "Profile objects carry an `ownerReference` to their
//! DevWorkspace, so the apiserver garbage collects them when the workspace is deleted."
//!
//! Two choices, both deliberate:
//!
//! - **`controller: false`.** The DevWorkspace is not the controller of these objects —
//!   `weebo-si-operator` is. A controller reference is also a claim only one owner may make, and
//!   DevWorkspace Operator's own controller-runtime `Owns()` watches key off exactly that claim;
//!   a plain (non-controller) owner reference is all garbage collection needs.
//! - **`blockOwnerDeletion: false`.** Setting it `true` requires `update` on
//!   `devworkspaces/finalizers` wherever the `OwnerReferencesPermissionEnforcement` admission
//!   plugin runs, which the controller's `ClusterRole` does not grant and has no other reason to.
//!   Blocking would only make foreground deletion of a workspace wait for its policies; the
//!   default background deletion removes them either way.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use serde_json::{Value, json};
use weebo_si_chassis::managed::Owner;

/// The only owner `kind` either store ever writes, and therefore the only one it reads back.
const OWNER_KIND: &str = "DevWorkspace";

/// The `metadata.ownerReferences` value for `owner`, or `None` for an unowned object (the
/// baseline) — in which case the caller leaves the field out of its apply entirely.
pub(crate) fn owner_references_json(owner: Option<&Owner>) -> Option<Value> {
    owner.map(|owner| {
        json!([{
            "apiVersion": owner.api_version,
            "kind": owner.kind,
            "name": owner.name,
            "uid": owner.uid,
            "controller": false,
            "blockOwnerDeletion": false,
        }])
    })
}

/// The owner a live object carries, read back from its `metadata.ownerReferences` — the first
/// `DevWorkspace` entry, ignoring any other owner something else may have added. Reading back
/// exactly the shape [`owner_references_json`] writes is what keeps an adopted object from being
/// rewritten on every pass.
pub(crate) fn owner_from_references(references: Option<&[OwnerReference]>) -> Option<Owner> {
    references?
        .iter()
        .find(|reference| reference.kind == OWNER_KIND)
        .map(|reference| Owner {
            api_version: reference.api_version.clone(),
            kind: reference.kind.clone(),
            name: reference.name.clone(),
            uid: reference.uid.clone(),
        })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn owner() -> Owner {
        Owner {
            api_version: "workspace.devfile.io/v1alpha2".to_string(),
            kind: "DevWorkspace".to_string(),
            name: "data-pipeline".to_string(),
            uid: "8f0c2a4e-uid".to_string(),
        }
    }

    #[test]
    fn an_unowned_object_writes_no_owner_references_at_all() {
        assert_eq!(owner_references_json(None), None);
    }

    #[test]
    fn the_written_reference_neither_claims_control_nor_blocks_owner_deletion() {
        let written = owner_references_json(Some(&owner())).unwrap();
        assert_eq!(written[0]["controller"], json!(false));
        assert_eq!(written[0]["blockOwnerDeletion"], json!(false));
    }

    #[test]
    fn an_owner_round_trips_through_the_shape_this_adapter_writes_and_reads_back() {
        // The property the diff depends on: `Managed::content_eq` compares owners, so an owner
        // read back from the watch cache that differed from the one written would rewrite every
        // profile object in the fleet on every pass.
        let written = owner_references_json(Some(&owner())).unwrap();
        let references: Vec<OwnerReference> = serde_json::from_value(written).unwrap();
        assert_eq!(owner_from_references(Some(&references)), Some(owner()));
    }

    #[test]
    fn an_object_with_no_owner_references_reads_back_unowned() {
        assert_eq!(owner_from_references(None), None);
        assert_eq!(owner_from_references(Some(&[])), None);
    }

    #[test]
    fn a_foreign_owner_is_ignored_in_favour_of_the_devworkspace() {
        let references = vec![
            OwnerReference {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "other".to_string(),
                uid: "other-uid".to_string(),
                ..OwnerReference::default()
            },
            serde_json::from_value(owner_references_json(Some(&owner())).unwrap()[0].clone())
                .unwrap(),
        ];
        assert_eq!(owner_from_references(Some(&references)), Some(owner()));
    }
}
