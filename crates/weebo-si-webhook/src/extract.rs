//! Turns the raw `AdmissionReview` object into the domain subjects the DevWorkspace-shaped
//! features take — the one place this crate reads the DevWorkspace's own JSON, and it reads
//! nothing beyond the fields those features name, per RFC 0002's *Security considerations*
//! (RFC 0019's *Attributes and annotations read* for `devfile-contract`).

use kube::core::DynamicObject;
use kube::core::admission::Operation;
use serde_json::Value;
use weebo_si_crd::{
    DEVFILE_CONTRACT_ANNOTATION, DEVFILE_CONTRACT_REASON_ANNOTATION, DwocRef, GENERATOR_ATTRIBUTE,
    NamespaceName, PLATFORM_CONTRACT_ATTRIBUTE,
};
use weebo_si_devfile_contract::parse::SCHEMA_SCAN_BYTES;
use weebo_si_devfile_contract::{DevfileWorkspace, Parent, is_start};
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
    namespace_grant: Option<String>,
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
        namespace_grant,
    }
}

/// The Che dashboard's copy of the devfile head, where it keeps `schemaVersion` (RFC 0019, R15).
pub const CHE_DEVFILE_ANNOTATION: &str = "che.eclipse.org/devfile";

/// The first [`SCHEMA_SCAN_BYTES`] of `text`, cut on a character boundary: no user string is
/// copied whole, whatever the apiserver let through.
fn head(text: &str) -> String {
    text.get(..text.floor_char_boundary(SCHEMA_SCAN_BYTES))
        .unwrap_or_default()
        .to_string()
}

/// `spec.template.parent` as the developer wrote it: `uri`, then `id` (an empty `version` counts
/// as none), then `kubernetes`. A parent naming none of them is no parent.
fn parent(template: Option<&Value>) -> Option<Parent> {
    let parent = template?.get("parent")?;
    let text = |key: &str| parent.get(key).and_then(Value::as_str).map(str::to_string);
    if let Some(uri) = text("uri") {
        return Some(Parent::Uri(uri));
    }
    if let Some(id) = text("id") {
        let version = text("version").filter(|version| !version.is_empty());
        return Some(Parent::Id { id, version });
    }
    parent.get("kubernetes").map(|_| Parent::Kubernetes)
}

/// Build a [`DevfileWorkspace`] — `devfile-contract`'s subject — from the admitted object and, on
/// an `UPDATE`, the stored one, which only feeds the start test (D-13). An `UPDATE` without an
/// `oldObject` (the apiserver always sends one) of a started workspace reads as a start: the side
/// the denied list applies to.
pub fn devfile_workspace_from_object(
    namespace: &NamespaceName,
    obj: &DynamicObject,
    old_obj: Option<&DynamicObject>,
    operation: &Operation,
) -> DevfileWorkspace {
    let template = obj.data.pointer("/spec/template");
    let attribute = |key: &str| {
        template
            .and_then(|t| t.get("attributes"))
            .and_then(|a| a.get(key))
    };
    let annotation = |key: &str| {
        obj.metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(key))
    };
    let started = |data: &Value| data.pointer("/spec/started") == Some(&Value::Bool(true));
    let old_data = old_obj.map(|old| &old.data);
    DevfileWorkspace {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        platform_contract: attribute(PLATFORM_CONTRACT_ATTRIBUTE).cloned(),
        generator: attribute(GENERATOR_ATTRIBUTE)
            .and_then(Value::as_str)
            .map(head),
        parent: parent(template),
        che_devfile: annotation(CHE_DEVFILE_ANNOTATION).map(|value| head(value)),
        stored_verdict: annotation(DEVFILE_CONTRACT_ANNOTATION).cloned(),
        stored_reasons: annotation(DEVFILE_CONTRACT_REASON_ANNOTATION).cloned(),
        starting: is_start(
            matches!(operation, Operation::Create),
            old_data.is_some_and(started),
            started(&obj.data),
            old_data.is_none_or(|old| old.pointer("/spec/template") != template),
        ),
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
                group: "workspace.devfile.io".to_string(),
                version: "v1alpha2".to_string(),
                api_version: "workspace.devfile.io/v1alpha2".to_string(),
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
                None,
            );
            assert_eq!(subject.operation, WorkspaceOperation::Update);
        }
    }

    fn devworkspace(started: bool, template: serde_json::Value) -> DynamicObject {
        let mut obj = object(serde_json::json!({"started": started, "template": template}));
        obj.metadata.annotations = Some(
            [
                (
                    CHE_DEVFILE_ANNOTATION.to_string(),
                    format!("schemaVersion: 2.3.0\n{}", "x".repeat(10_000)),
                ),
                (
                    DEVFILE_CONTRACT_ANNOTATION.to_string(),
                    "current".to_string(),
                ),
            ]
            .into(),
        );
        obj
    }

    fn extract(
        obj: &DynamicObject,
        old: Option<&DynamicObject>,
        operation: Operation,
    ) -> DevfileWorkspace {
        devfile_workspace_from_object(&NamespaceName::new("user-alice"), obj, old, &operation)
    }

    #[test]
    fn the_devfile_fields_are_extracted_and_bounded() {
        let obj = devworkspace(
            true,
            serde_json::json!({
                "attributes": {
                    (PLATFORM_CONTRACT_ATTRIBUTE): "2",
                    (GENERATOR_ATTRIBUTE): "é".repeat(5_000),
                },
                "parent": {"uri": "https://example.com/devfile.yaml"},
            }),
        );
        let subject = extract(&obj, None, Operation::Create);
        assert_eq!(subject.platform_contract, Some(serde_json::json!("2")));
        assert_eq!(
            subject.parent,
            Some(Parent::Uri("https://example.com/devfile.yaml".to_string()))
        );
        assert!(subject.generator.unwrap().len() <= SCHEMA_SCAN_BYTES);
        let che = subject.che_devfile.unwrap();
        assert!(che.starts_with("schemaVersion: 2.3.0") && che.len() == SCHEMA_SCAN_BYTES);
        assert_eq!(subject.stored_verdict.as_deref(), Some("current"));
        assert_eq!(subject.stored_reasons, None);
        assert!(subject.starting);
    }

    #[test]
    fn every_parent_shape_is_read() {
        let parent_of = |parent: serde_json::Value| {
            extract(
                &devworkspace(false, serde_json::json!({"parent": parent})),
                None,
                Operation::Create,
            )
            .parent
        };
        assert_eq!(
            parent_of(serde_json::json!({"id": "che-min-mise", "version": ""})),
            Some(Parent::Id {
                id: "che-min-mise".to_string(),
                version: None
            })
        );
        assert_eq!(
            parent_of(serde_json::json!({"id": "che-min-mise", "version": "1.2.0"})),
            Some(Parent::Id {
                id: "che-min-mise".to_string(),
                version: Some("1.2.0".to_string())
            })
        );
        assert_eq!(
            parent_of(serde_json::json!({"kubernetes": {"name": "base"}})),
            Some(Parent::Kubernetes)
        );
        assert_eq!(parent_of(serde_json::json!({})), None);
        assert_eq!(
            extract(&object(serde_json::json!({})), None, Operation::Create).parent,
            None
        );
    }

    /// D-13: only a start transition or a template change while running is a start.
    #[test]
    fn the_start_transition_is_computed_from_both_objects() {
        let template = serde_json::json!({"parent": {"uri": "https://a/v1.0.0/"}});
        let other = serde_json::json!({"parent": {"uri": "https://a/main/"}});
        let update = |old: &DynamicObject, new: &DynamicObject| {
            extract(new, Some(old), Operation::Update).starting
        };
        let stopped = devworkspace(false, template.clone());
        let running = devworkspace(true, template.clone());
        assert!(update(&stopped, &running), "spec.started turned true");
        assert!(!update(&running, &running), "a finalizer or label update");
        assert!(!update(&running, &stopped), "a stop");
        assert!(
            update(&running, &devworkspace(true, other.clone())),
            "parent changed while running"
        );
        assert!(
            !update(&stopped, &devworkspace(false, other)),
            "editing a stopped workspace"
        );
        assert!(
            extract(&running, None, Operation::Update).starting,
            "an UPDATE without oldObject reads as a start"
        );
    }
}
