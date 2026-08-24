//! Turns the raw `AdmissionReview` object into the domain subjects the two DevWorkspace-shaped
//! features take — the one place this crate reads the DevWorkspace's own JSON, and it reads
//! nothing beyond the two attributes those features name, per RFC 0002's *Security
//! considerations*.

use kube::core::DynamicObject;
use kube::core::admission::Operation;
use weebo_si_crd::{DwocRef, NamespaceName};
use weebo_si_dwoc_pin::Workspace;
use weebo_si_network_profiles::{WorkspaceAdmission, WorkspaceOperation};

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

/// Build a [`WorkspaceAdmission`] — `network-profiles`' own admission subject — from the same
/// request.
///
/// `attribute_key` and `namespace_annotation` are passed in rather than read here: both are
/// configurable (`workspaceSelection.attribute`, `namespaceSelection.annotation`), and the empty
/// string disables its channel, which is the caller's live configuration to know, not this
/// function's.
pub fn workspace_admission_from_object(
    namespace: &NamespaceName,
    obj: &DynamicObject,
    operation: Operation,
    attribute_key: &str,
    namespace_annotation: Option<String>,
) -> WorkspaceAdmission {
    let attribute = if attribute_key.is_empty() {
        None
    } else {
        obj.data
            .pointer("/spec/template/attributes")
            .and_then(|attributes| attributes.get(attribute_key))
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    WorkspaceAdmission {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        // Everything that is not a `CREATE` is treated as an `Update`: the gate refuses nothing
        // on an update, so mapping `DELETE`/`CONNECT` here to the permissive side is the
        // fail-open direction for operations the webhook's own rule does not even register for.
        operation: match operation {
            Operation::Create => WorkspaceOperation::Create,
            _ => WorkspaceOperation::Update,
        },
        attribute,
        namespace_annotation,
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

    const PROFILES_ATTRIBUTE: &str = "hardening.weebo.io/network-profiles";

    #[test]
    fn the_network_profiles_attribute_is_extracted_verbatim() {
        let obj = object(serde_json::json!({
            "template": {"attributes": {(PROFILES_ATTRIBUTE): "git,vault"}}
        }));
        let subject = workspace_admission_from_object(
            &NamespaceName::new("user-alice"),
            &obj,
            Operation::Create,
            PROFILES_ATTRIBUTE,
            None,
        );
        assert_eq!(subject.attribute.as_deref(), Some("git,vault"));
        assert_eq!(subject.operation, WorkspaceOperation::Create);
    }

    #[test]
    fn an_empty_attribute_key_disables_the_channel_entirely() {
        // `workspaceSelection.attribute: ""` is the RFC's documented off switch — the attribute
        // must then be invisible even when the devfile carries one.
        let obj = object(serde_json::json!({
            "template": {"attributes": {(PROFILES_ATTRIBUTE): "vault"}}
        }));
        let subject = workspace_admission_from_object(
            &NamespaceName::new("user-alice"),
            &obj,
            Operation::Create,
            "",
            None,
        );
        assert_eq!(subject.attribute, None);
    }

    #[test]
    fn every_operation_other_than_create_maps_to_update() {
        let obj = object(serde_json::json!({"template": {}}));
        for operation in [Operation::Update, Operation::Delete, Operation::Connect] {
            let subject = workspace_admission_from_object(
                &NamespaceName::new("user-alice"),
                &obj,
                operation,
                PROFILES_ATTRIBUTE,
                None,
            );
            assert_eq!(subject.operation, WorkspaceOperation::Update);
        }
    }
}
