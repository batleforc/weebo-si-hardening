//! Turns the raw `AdmissionReview` object into `weebo-si-dwoc-pin`'s `Workspace` — the one place
//! this crate reads the DevWorkspace's own JSON, and it reads nothing beyond the one attribute
//! dwoc-pin cares about, per RFC 0002's *Security considerations*.

use kube::core::DynamicObject;
use weebo_si_crd::{DwocRef, NamespaceName};
use weebo_si_dwoc_pin::Workspace;

/// The attribute this feature reads and writes.
pub const CONFIG_REF_ATTRIBUTE: &str = "controller.devfile.io/devworkspace-config";

/// Build a [`Workspace`] from the admitted object and the namespace the request names.
pub fn workspace_from_object(namespace: &NamespaceName, obj: &DynamicObject) -> Workspace {
    let name = obj.metadata.name.clone().unwrap_or_default();
    let config_ref = obj
        .data
        .pointer("/spec/template/attributes")
        .and_then(|attributes| attributes.get(CONFIG_REF_ATTRIBUTE))
        .and_then(|value| serde_json::from_value::<DwocRef>(value.clone()).ok());
    Workspace {
        name,
        namespace: namespace.clone(),
        config_ref,
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

    fn object(spec: serde_json::Value) -> DynamicObject {
        let mut obj = DynamicObject::new(
            "python-web",
            &kube::core::ApiResource {
                group: "controller.devfile.io".to_string(),
                version: "v1alpha1".to_string(),
                api_version: "controller.devfile.io/v1alpha1".to_string(),
                kind: "DevWorkspace".to_string(),
                plural: "devworkspaces".to_string(),
            },
        );
        obj.data = serde_json::json!({"spec": spec});
        obj
    }

    #[test]
    fn absent_attribute_is_none() {
        let obj = object(serde_json::json!({"template": {}}));
        let workspace = workspace_from_object(&NamespaceName::new("user-alice"), &obj);
        assert_eq!(workspace.config_ref, None);
    }

    #[test]
    fn present_attribute_is_extracted() {
        let obj = object(serde_json::json!({
            "template": {"attributes": {(CONFIG_REF_ATTRIBUTE): {"name": "gpu-config", "namespace": "eclipse-che"}}}
        }));
        let workspace = workspace_from_object(&NamespaceName::new("user-alice"), &obj);
        assert_eq!(
            workspace.config_ref,
            Some(DwocRef {
                name: "gpu-config".to_string(),
                namespace: NamespaceName::new("eclipse-che"),
            })
        );
    }
}
