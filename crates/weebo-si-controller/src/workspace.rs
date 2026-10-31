//! What the reconcile loops over workspaces share: reading a `DevWorkspace`'s id and owner
//! reference, and the `held` warning every template-driven feature logs.

use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use weebo_si_chassis::managed::{ObjectKey, Owner};
use weebo_si_crd::DEVWORKSPACE_ID_LABEL;

/// The DevWorkspace's id — the value its pods carry as `controller.devfile.io/devworkspace_id`,
/// which every profile object selects on.
///
/// DevWorkspace Operator records it on the `DevWorkspace` itself as `status.devworkspaceId`, and
/// puts the label on the objects it *creates* (pods, Deployments, Services), not on the
/// `DevWorkspace`. Status first; the label is still honoured for an object that carries one.
/// `None` until DWO has assigned it.
pub fn devworkspace_id(obj: &DynamicObject) -> Option<String> {
    obj.data
        .pointer("/status/devworkspaceId")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .or_else(|| {
            obj.metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
                .filter(|id| !id.is_empty())
                .cloned()
        })
}

/// The `DevWorkspace` GVK, matching this repo's own convention (see
/// `charts/weebo-si-operator/templates/mutatingwebhookconfiguration.yaml`) rather than upstream
/// DevWorkspace Operator's actual group — consistent with every other reference to this resource
/// in this codebase.
pub fn devworkspace_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk("workspace.devfile.io", "v1alpha2", "DevWorkspace");
    ApiResource::from_gvk_with_plural(&gvk, "devworkspaces")
}

/// The DevWorkspace `obj` as the [`Owner`] every profile object written for it is
/// garbage-collected with — RFC 0004's "Profile objects carry an `ownerReference` to their
/// DevWorkspace."
///
/// `apiVersion` and `kind` come from [`devworkspace_resource`] — the resource this controller
/// actually watches and read `obj`'s `uid` from — rather than from a second hard-coded string:
/// the garbage collector resolves an owner through exactly the `apiVersion` written, and one that
/// named a different resource than the one the `uid` belongs to would read as "owner gone" and
/// delete the workspace's policies out from under it. `None` when the object carries no name or
/// uid, which no object read from the apiserver ever lacks.
pub fn devworkspace_owner(obj: &DynamicObject) -> Option<Owner> {
    let resource = devworkspace_resource();
    Some(Owner {
        api_version: resource.api_version,
        kind: resource.kind,
        name: obj.metadata.name.clone()?,
        uid: obj.metadata.uid.clone()?,
    })
}

/// One line per object a pass *held* — its template did not resolve (deleted, or not yet in the
/// watch cache), so the live copy was neither updated nor deleted. Without this line a template
/// deleted by mistake is invisible: every metric reads healthy while the enforced policy quietly
/// stops tracking its template.
///
/// Shared by `network-profiles`, `kubearmor-policy` and `registry-config`, whose
/// `ReconcileOutcome::held` means the same thing.
pub fn held_warnings(feature: &str, held: &[ObjectKey]) -> Vec<String> {
    held.iter()
        .map(|key| {
            format!(
                "feature={feature} object={}/{} result=held — \
                 template unresolved, live object left untouched",
                key.namespace, key.name
            )
        })
        .collect()
}

/// Log [`held_warnings`] at `WARN`.
pub fn warn_held(feature: &str, held: &[ObjectKey]) {
    for line in held_warnings(feature, held) {
        tracing::warn!("{line}");
    }
}
