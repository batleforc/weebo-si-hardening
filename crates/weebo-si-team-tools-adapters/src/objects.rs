//! The Kubernetes shape of a [`ToolObject`]: which API each kind goes to, the apply document,
//! and how a live object is read back for the diff.
//!
//! A rendered workload, `Service` or `Certificate` comes back from the apiserver with defaults
//! the render never wrote, so comparing bodies would turn every pass into an update. The render
//! is fingerprinted instead: [`fingerprint`] hashes what this controller writes, the apply stores
//! it in [`FINGERPRINT_ANNOTATION`], and both sides of the diff compare fingerprints
//! ([`comparable`] for the desired side, [`from_live`] for the live side).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use weebo_si_chassis::managed::Owner;
use weebo_si_chassis::{ObjectKey, PodSelector};
use weebo_si_crd::{
    DEVWORKSPACE_ID_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, TEAM_TOOL_LABEL,
    ToolKey,
};
use weebo_si_runtime::owner_reference::{owner_from_references, owner_references_json};
use weebo_si_team_tools::render::{ingress_policy_name, server_certificate_name};
use weebo_si_team_tools::{ToolObject, ToolObjectKind};

/// Where the apply records the fingerprint of what it wrote.
pub const FINGERPRINT_ANNOTATION: &str = "hardening.weebo.io/team-tools-fingerprint";

/// The kinds a tools namespace holds; the requester side writes only `ConfigMap`,
/// `Certificate` and `CiliumNetworkPolicy`.
pub const ALL_KINDS: [ToolObjectKind; 6] = [
    ToolObjectKind::Deployment,
    ToolObjectKind::StatefulSet,
    ToolObjectKind::Service,
    ToolObjectKind::ConfigMap,
    ToolObjectKind::CiliumNetworkPolicy,
    ToolObjectKind::Certificate,
];

/// The API `kind` is served by.
pub fn resource(kind: ToolObjectKind) -> ApiResource {
    let (group, version, plural) = match kind {
        ToolObjectKind::Deployment => ("apps", "v1", "deployments"),
        ToolObjectKind::StatefulSet => ("apps", "v1", "statefulsets"),
        ToolObjectKind::Service => ("", "v1", "services"),
        ToolObjectKind::ConfigMap => ("", "v1", "configmaps"),
        ToolObjectKind::CiliumNetworkPolicy => ("cilium.io", "v2", "ciliumnetworkpolicies"),
        ToolObjectKind::Certificate => ("cert-manager.io", "v1", "certificates"),
    };
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(group, version, kind.as_str()),
        plural,
    )
}

/// Whether `kind` is scaled through `/scale`.
pub fn is_workload(kind: ToolObjectKind) -> bool {
    matches!(
        kind,
        ToolObjectKind::Deployment | ToolObjectKind::StatefulSet
    )
}

/// The fingerprint of what the apply writes for `object`: labels, annotations, body and owner.
pub fn fingerprint(object: &ToolObject) -> String {
    let canonical = json!({
        "kind": object.kind.as_str(),
        "labels": object.labels,
        "annotations": object.annotations,
        "body": object.body,
        "owner": object.owner.as_ref().map(|owner| [&owner.api_version, &owner.kind, &owner.name, &owner.uid]),
    });
    // serde_json's map is ordered (no `preserve_order`), so the same object always serialises
    // to the same bytes.
    let digest = Sha256::digest(canonical.to_string().as_bytes());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            // Writing to a String cannot fail.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// `object` reduced to what the diff compares: its fingerprint stands for its content.
pub fn comparable(object: &ToolObject) -> ToolObject {
    ToolObject {
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        body: Value::String(fingerprint(object)),
        owner: None,
        ..object.clone()
    }
}

/// A tool's ingress policy or server certificate: only a tools namespace holds one, and the
/// cluster-wide caches see it there even once the namespace is not watched.
pub fn is_tools_side(object: &ToolObject) -> bool {
    match object.kind {
        ToolObjectKind::CiliumNetworkPolicy => object.key.name == ingress_policy_name(&object.tool),
        ToolObjectKind::Certificate => object.key.name == server_certificate_name(&object.tool),
        _ => false,
    }
}

/// A live object as the diff sees it, `None` when it is not one of this feature's (no
/// `managed-by` or no `team-tool` label). The body is the fingerprint it was applied with, so it
/// equals [`comparable`] of the desired object exactly when nothing changed.
pub fn from_live(kind: ToolObjectKind, object: &DynamicObject) -> Option<ToolObject> {
    let labels = object.metadata.labels.as_ref()?;
    if labels.get(MANAGED_BY_LABEL).map(String::as_str) != Some(MANAGED_BY_VALUE) {
        return None;
    }
    let tool = ToolKey::new(labels.get(TEAM_TOOL_LABEL)?.clone());
    // Only an egress policy selects one workspace; every other object is its subject's `Empty`.
    let selector = object
        .data
        .pointer("/spec/endpointSelector/matchLabels")
        .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
        .and_then(Value::as_str)
        .filter(|_| kind == ToolObjectKind::CiliumNetworkPolicy)
        .map_or(PodSelector::Empty, |id| {
            PodSelector::DevWorkspaceId(id.to_string())
        });
    let stored = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(FINGERPRINT_ANNOTATION))
        .cloned()
        .unwrap_or_default();
    Some(ToolObject {
        key: ObjectKey {
            namespace: NamespaceName::new(object.metadata.namespace.clone()?),
            name: object.metadata.name.clone()?,
        },
        kind,
        tool,
        selector,
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        body: Value::String(stored),
        owner: None,
        uid: object.metadata.uid.clone(),
    })
}

/// Whether a live object carries `managed-by`.
pub fn is_managed(object: &DynamicObject) -> bool {
    object
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE)
}

/// The server-side apply document of `object`. A workload's body never carries `spec.replicas`
/// (the render strips it); `replicas` puts one back, for the create only.
pub fn apply_document(object: &ToolObject, replicas: Option<i32>) -> Value {
    let mut annotations = object.annotations.clone();
    annotations.insert(FINGERPRINT_ANNOTATION.to_string(), fingerprint(object));
    let mut metadata = json!({
        "name": object.key.name,
        "namespace": object.key.namespace.as_str(),
        "labels": object.labels,
        "annotations": annotations,
    });
    if let Some(references) = owner_references_json(object.owner.as_ref()) {
        metadata["ownerReferences"] = references;
    }
    let mut document = match &object.body {
        Value::Object(body) => Value::Object(body.clone()),
        _ => json!({}),
    };
    document["apiVersion"] = Value::String(object.kind.api_version().to_string());
    document["kind"] = Value::String(object.kind.as_str().to_string());
    document["metadata"] = metadata;
    if let Some(replicas) = replicas
        && let Some(spec) = document.get_mut("spec").and_then(Value::as_object_mut)
    {
        spec.insert("replicas".to_string(), json!(replicas));
    }
    document
}

/// The live `spec.replicas` of a workload; `None` when the field is absent.
pub fn replicas_of(object: &DynamicObject) -> Option<i32> {
    object
        .data
        .pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .and_then(|replicas| i32::try_from(replicas).ok())
}

/// The owner a live object was written with (for logs and tests).
pub fn live_owner(object: &DynamicObject) -> Option<Owner> {
    owner_from_references(object.metadata.owner_references.as_deref())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn statefulset() -> ToolObject {
        ToolObject {
            key: ObjectKey {
                namespace: NamespaceName::new("team-weebo-tools"),
                name: "buildkitd".to_string(),
            },
            kind: ToolObjectKind::StatefulSet,
            tool: ToolKey::new("buildkit"),
            selector: PodSelector::Empty,
            labels: BTreeMap::from([
                (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
                (TEAM_TOOL_LABEL.to_string(), "buildkit".to_string()),
            ]),
            annotations: BTreeMap::new(),
            body: json!({"spec": {"serviceName": "buildkitd"}}),
            owner: None,
            uid: None,
        }
    }

    fn live(document: Value) -> DynamicObject {
        serde_json::from_value(document).unwrap()
    }

    #[test]
    fn an_applied_object_reads_back_equal_and_a_changed_render_does_not() {
        let desired = statefulset();
        let mut document = apply_document(&desired, None);
        // What the apiserver adds must not matter.
        document["spec"]["podManagementPolicy"] = json!("OrderedReady");
        document["metadata"]["uid"] = json!("u-1");
        let read = from_live(ToolObjectKind::StatefulSet, &live(document)).unwrap();
        let wanted = comparable(&desired);
        assert_eq!(read.key, wanted.key);
        assert_eq!(read.body, wanted.body);
        assert_eq!(read.uid.as_deref(), Some("u-1"));

        let mut changed = desired.clone();
        changed.body = json!({"spec": {"serviceName": "other"}});
        assert_ne!(read.body, comparable(&changed).body);
    }

    #[test]
    fn only_the_create_writes_replicas() {
        let desired = statefulset();
        assert!(
            apply_document(&desired, None)
                .pointer("/spec/replicas")
                .is_none()
        );
        assert_eq!(
            apply_document(&desired, Some(0)).pointer("/spec/replicas"),
            Some(&json!(0))
        );
    }

    #[test]
    fn an_object_without_managed_by_or_team_tool_is_not_ours() {
        let mut document = apply_document(&statefulset(), None);
        document["metadata"]["labels"] = json!({TEAM_TOOL_LABEL: "buildkit"});
        assert!(from_live(ToolObjectKind::StatefulSet, &live(document.clone())).is_none());
        document["metadata"]["labels"] = json!({MANAGED_BY_LABEL: MANAGED_BY_VALUE});
        assert!(from_live(ToolObjectKind::StatefulSet, &live(document)).is_none());
    }

    #[test]
    fn only_the_ingress_policy_and_the_server_certificate_mark_a_tools_namespace() {
        let mut object = statefulset();
        assert!(!is_tools_side(&object));
        object.kind = ToolObjectKind::CiliumNetworkPolicy;
        object.key.name = "weebo-team-tool-buildkit-ingress".to_string();
        assert!(is_tools_side(&object));
        object.key.name = "weebo-team-tool-buildkit-workspace1".to_string();
        assert!(!is_tools_side(&object));
        object.kind = ToolObjectKind::Certificate;
        object.key.name = "weebo-team-tool-buildkit-server".to_string();
        assert!(is_tools_side(&object));
        object.key.name = "weebo-team-tool-buildkit-client".to_string();
        assert!(!is_tools_side(&object));
    }

    #[test]
    fn an_egress_policy_reads_back_its_workspace_selector_and_owner() {
        let mut policy = statefulset();
        policy.kind = ToolObjectKind::CiliumNetworkPolicy;
        policy.selector = PodSelector::DevWorkspaceId("workspace1".to_string());
        policy.owner = Some(Owner {
            api_version: "workspace.devfile.io/v1alpha2".to_string(),
            kind: "DevWorkspace".to_string(),
            name: "python-web".to_string(),
            uid: "dw-uid".to_string(),
        });
        policy.body = json!({"spec": {"endpointSelector": {"matchLabels": {DEVWORKSPACE_ID_LABEL: "workspace1"}}}});
        let document = apply_document(&policy, None);
        let object = live(document);
        let read = from_live(ToolObjectKind::CiliumNetworkPolicy, &object).unwrap();
        assert_eq!(read.selector, policy.selector);
        assert_eq!(live_owner(&object), policy.owner);
    }
}
