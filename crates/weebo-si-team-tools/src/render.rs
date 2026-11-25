//! The objects this feature writes — RFC 0020, *Labels, annotations, names* and Resolved 10
//! (the `Certificate`s and the ingress policy are generated, not templated).
//!
//! **The invariant.** No object built here carries `hardening.weebo.io/profile`: network-profiles
//! would delete the egress policy as a stale profile object of the workspace it selects. A
//! template's own metadata is never copied whole for the same reason (and so an Argo tracking
//! label or annotation on a template cannot make Argo prune the copy): only the
//! `controller.devfile.io/*` keys, which tell DWO what to mount, survive.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use weebo_si_chassis::managed::{Managed, Owner, Selected};
use weebo_si_chassis::{ObjectKey, PodSelector};
use weebo_si_crd::{
    DEVWORKSPACE_ID_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, Selector,
    TEAM_TOOL_LABEL, TeamName, ToolIssuerRef, ToolKey,
};

use crate::bind::WORKSPACE_NAMESPACE_LABEL;
use crate::port::ToolTemplate;
use crate::validate::ValidEntry;

/// The server-side apply field manager of every object.
pub const FIELD_MANAGER: &str = "weebo-si-team-tools";
/// The field manager of the `/scale` writes, the only writer of `spec.replicas`.
pub const SCALE_FIELD_MANAGER: &str = "weebo-si-team-tools-scale";
/// DWO mounts an object carrying it into every workspace of the namespace.
pub const MOUNT_LABEL: &str = "controller.devfile.io/mount-to-devworkspace";
/// DWO watches only the ConfigMaps carrying it.
pub const WATCH_CONFIGMAP_LABEL: &str = "controller.devfile.io/watch-configmap";
/// DWO watches only the Secrets carrying it.
pub const WATCH_SECRET_LABEL: &str = "controller.devfile.io/watch-secret";
/// `env` or `file`: how DWO mounts the object.
pub const MOUNT_AS_ANNOTATION: &str = "controller.devfile.io/mount-as";
/// Where DWO mounts a `file` object.
pub const MOUNT_PATH_ANNOTATION: &str = "controller.devfile.io/mount-path";
/// The prefix of the template metadata keys copied onto a rendered object.
const DWO_PREFIX: &str = "controller.devfile.io/";
/// Cilium's label for a namespace label of the peer.
const CILIUM_NAMESPACE_LABEL: &str = "k8s:io.cilium.k8s.namespace.labels.";
/// Cilium's label for the peer's namespace.
const CILIUM_POD_NAMESPACE: &str = "k8s:io.kubernetes.pod.namespace";

/// The kinds this feature writes. Plays the chassis diff's `Backend` role: the store needs it to
/// know which API a delete goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ToolObjectKind {
    /// `apps/v1`.
    Deployment,
    /// `apps/v1`.
    StatefulSet,
    /// `v1`.
    Service,
    /// `v1`.
    ConfigMap,
    /// `cilium.io/v2`.
    CiliumNetworkPolicy,
    /// `cert-manager.io/v1`.
    Certificate,
}

impl ToolObjectKind {
    /// The kind of a template, if it is one this feature writes.
    pub fn from_kind(kind: &str) -> Option<Self> {
        Some(match kind {
            "Deployment" => Self::Deployment,
            "StatefulSet" => Self::StatefulSet,
            "Service" => Self::Service,
            "ConfigMap" => Self::ConfigMap,
            "CiliumNetworkPolicy" => Self::CiliumNetworkPolicy,
            "Certificate" => Self::Certificate,
            _ => return None,
        })
    }

    /// The Kubernetes kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "Deployment",
            Self::StatefulSet => "StatefulSet",
            Self::Service => "Service",
            Self::ConfigMap => "ConfigMap",
            Self::CiliumNetworkPolicy => "CiliumNetworkPolicy",
            Self::Certificate => "Certificate",
        }
    }

    /// The `apiVersion`.
    pub fn api_version(self) -> &'static str {
        match self {
            Self::Deployment | Self::StatefulSet => "apps/v1",
            Self::Service | Self::ConfigMap => "v1",
            Self::CiliumNetworkPolicy => "cilium.io/v2",
            Self::Certificate => "cert-manager.io/v1",
        }
    }
}

/// One object this feature writes.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolObject {
    /// `{namespace, name}`.
    pub key: ObjectKey,
    /// Its kind.
    pub kind: ToolObjectKind,
    /// The catalogue key, written as `hardening.weebo.io/team-tool`.
    pub tool: ToolKey,
    /// The subject that owns it: `DevWorkspaceId` for an egress policy, `Empty` otherwise.
    pub selector: PodSelector,
    /// `metadata.labels`, `managed-by` and `team-tool` included.
    pub labels: BTreeMap<String, String>,
    /// `metadata.annotations`.
    pub annotations: BTreeMap<String, String>,
    /// Every top-level field but `apiVersion`, `kind` and `metadata`. A workload's never carries
    /// `spec.replicas`: `/scale` is its only writer, and the create sets 0.
    pub body: Value,
    /// The DevWorkspace an egress policy goes with.
    pub owner: Option<Owner>,
    /// The uid the store listed it with; `None` for a desired object.
    pub uid: Option<String>,
}

impl Managed for ToolObject {
    type Backend = ToolObjectKind;

    fn key(&self) -> &ObjectKey {
        &self.key
    }

    fn backend(&self) -> ToolObjectKind {
        self.kind
    }

    fn content_eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.labels == other.labels
            && self.annotations == other.annotations
            && self.body == other.body
            && self.owner == other.owner
    }

    fn uid(&self) -> Option<&str> {
        self.uid.as_deref()
    }
}

impl Selected for ToolObject {
    fn pod_selector(&self) -> &PodSelector {
        &self.selector
    }
}

/// `weebo-team-tool-<key>-ingress`, in the tools namespace.
pub fn ingress_policy_name(key: &ToolKey) -> String {
    format!("weebo-team-tool-{key}-ingress")
}

/// `weebo-team-tool-<key>-server`, in the tools namespace.
pub fn server_certificate_name(key: &ToolKey) -> String {
    format!("weebo-team-tool-{key}-server")
}

/// `weebo-team-tool-<key>`, the endpoint `ConfigMap` in a workspace namespace.
pub fn endpoint_config_map_name(key: &ToolKey) -> String {
    format!("weebo-team-tool-{key}")
}

/// `weebo-team-tool-<key>-client`, the client `Certificate` and its `Secret`.
pub fn client_certificate_name(key: &ToolKey) -> String {
    format!("weebo-team-tool-{key}-client")
}

/// `weebo-team-tool-<key>-<devworkspaceId>`, one egress policy per workspace.
pub fn egress_policy_name(key: &ToolKey, devworkspace_id: &str) -> String {
    format!("weebo-team-tool-{key}-{devworkspace_id}")
}

/// The tool's service FQDN, the server certificate's DNS name and the endpoint's host.
pub fn service_host(entry: &ValidEntry, tools_namespace: &NamespaceName) -> String {
    format!("{}.{tools_namespace}.svc", entry.entry.service.name)
}

fn managed_labels(key: &ToolKey) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
        (TEAM_TOOL_LABEL.to_string(), key.to_string()),
    ])
}

fn dwo_keys(map: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    map.iter()
        .filter(|(key, _)| key.starts_with(DWO_PREFIX))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn object(
    namespace: &NamespaceName,
    name: String,
    kind: ToolObjectKind,
    key: &ToolKey,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
    body: Value,
) -> ToolObject {
    let mut all = labels;
    all.extend(managed_labels(key));
    ToolObject {
        key: ObjectKey {
            namespace: namespace.clone(),
            name,
        },
        kind,
        tool: key.clone(),
        selector: PodSelector::Empty,
        labels: all,
        annotations,
        body,
        owner: None,
        uid: None,
    }
}

/// A template rendered into `namespace` under its own name. `None` for a kind this feature does
/// not write (validation refuses it first).
pub fn from_template(
    template: &ToolTemplate,
    namespace: &NamespaceName,
    key: &ToolKey,
) -> Option<ToolObject> {
    let kind = ToolObjectKind::from_kind(&template.kind)?;
    let mut body = template.body.clone();
    if matches!(
        kind,
        ToolObjectKind::Deployment | ToolObjectKind::StatefulSet
    ) && let Some(spec) = body.get_mut("spec").and_then(Value::as_object_mut)
    {
        spec.remove("replicas");
    }
    // The apiserver allocated these to the template; copied, they collide (422 "already allocated").
    if kind == ToolObjectKind::Service
        && let Some(spec) = body.get_mut("spec").and_then(Value::as_object_mut)
    {
        for field in ["clusterIP", "clusterIPs", "healthCheckNodePort"] {
            spec.remove(field);
        }
        if let Some(ports) = spec.get_mut("ports").and_then(Value::as_array_mut) {
            for port in ports.iter_mut().filter_map(Value::as_object_mut) {
                port.remove("nodePort");
            }
        }
    }
    Some(object(
        namespace,
        template.name.clone(),
        kind,
        key,
        dwo_keys(&template.labels),
        dwo_keys(&template.annotations),
        body,
    ))
}

fn to_ports(entry: &ValidEntry) -> Value {
    json!([{"ports": [{"port": entry.port.port, "protocol": entry.port.protocol}]}])
}

/// A Cilium peer selecting the pods of every namespace `selector` matches **and** labelled
/// `workspace-namespace=true` (RFC 0020, S1).
pub fn namespace_peer(selector: &Selector) -> Value {
    let mut labels: BTreeMap<String, String> = selector
        .match_labels
        .iter()
        .map(|(key, value)| (format!("{CILIUM_NAMESPACE_LABEL}{key}"), value.clone()))
        .collect();
    labels.insert(
        format!("{CILIUM_NAMESPACE_LABEL}{WORKSPACE_NAMESPACE_LABEL}"),
        "true".to_string(),
    );
    let expressions: Vec<Value> = selector
        .match_expressions
        .iter()
        .map(|expression| {
            json!({
                "key": format!("{CILIUM_NAMESPACE_LABEL}{}", expression.key),
                "operator": expression.operator,
                "values": expression.values,
            })
        })
        .collect();
    let mut peer = json!({"matchLabels": labels});
    if !expressions.is_empty() {
        peer["matchExpressions"] = Value::Array(expressions);
    }
    peer
}

/// The tools namespace's ingress policy: the tool's pods, from the team's workspace namespaces,
/// on the tool port only.
pub fn ingress_policy(
    tools_namespace: &NamespaceName,
    entry: &ValidEntry,
    team_selector: &Selector,
) -> ToolObject {
    let key = &entry.entry.key;
    object(
        tools_namespace,
        ingress_policy_name(key),
        ToolObjectKind::CiliumNetworkPolicy,
        key,
        BTreeMap::new(),
        BTreeMap::new(),
        json!({"spec": {
            "endpointSelector": {"matchLabels": entry.pod_labels},
            "ingress": [{"fromEndpoints": [namespace_peer(team_selector)], "toPorts": to_ports(entry)}],
        }}),
    )
}

fn issuer(issuer: &ToolIssuerRef) -> Value {
    json!({"group": "cert-manager.io", "kind": issuer.kind, "name": issuer.name})
}

/// The server `Certificate`, when the entry has `tls`.
pub fn server_certificate(
    tools_namespace: &NamespaceName,
    entry: &ValidEntry,
    issuer_ref: &ToolIssuerRef,
) -> Option<ToolObject> {
    let tls = entry.entry.tls.as_ref()?;
    let key = &entry.entry.key;
    Some(object(
        tools_namespace,
        server_certificate_name(key),
        ToolObjectKind::Certificate,
        key,
        BTreeMap::new(),
        BTreeMap::new(),
        json!({"spec": {
            "secretName": tls.server_secret_name,
            "issuerRef": issuer(issuer_ref),
            "dnsNames": [service_host(entry, tools_namespace)],
            "usages": ["digital signature", "key encipherment", "server auth"],
        }}),
    ))
}

/// The endpoint `ConfigMap`, mounted as env, when the entry names a `clientEnv`.
pub fn endpoint_config_map(
    namespace: &NamespaceName,
    entry: &ValidEntry,
    tools_namespace: &NamespaceName,
) -> Option<ToolObject> {
    let env = entry.entry.client_env.as_ref()?;
    let key = &entry.entry.key;
    let url = format!(
        "tcp://{}:{}",
        service_host(entry, tools_namespace),
        entry.entry.service.port
    );
    Some(object(
        namespace,
        endpoint_config_map_name(key),
        ToolObjectKind::ConfigMap,
        key,
        BTreeMap::from([
            (MOUNT_LABEL.to_string(), "true".to_string()),
            (WATCH_CONFIGMAP_LABEL.to_string(), "true".to_string()),
        ]),
        BTreeMap::from([(MOUNT_AS_ANNOTATION.to_string(), "env".to_string())]),
        json!({"data": {env: url}}),
    ))
}

/// The client `Certificate`: CN the namespace owner (never the DevWorkspace), organisation the
/// team, the entry's `clientDuration`, its `Secret` mounted as files by DWO.
pub fn client_certificate(
    namespace: &NamespaceName,
    entry: &ValidEntry,
    issuer_ref: &ToolIssuerRef,
    team: &TeamName,
    common_name: &str,
) -> Option<ToolObject> {
    let tls = entry.entry.tls.as_ref()?;
    let key = &entry.entry.key;
    let mut secret_labels = managed_labels(key);
    secret_labels.insert(MOUNT_LABEL.to_string(), "true".to_string());
    secret_labels.insert(WATCH_SECRET_LABEL.to_string(), "true".to_string());
    Some(object(
        namespace,
        client_certificate_name(key),
        ToolObjectKind::Certificate,
        key,
        BTreeMap::new(),
        BTreeMap::new(),
        json!({"spec": {
            "secretName": client_certificate_name(key),
            "commonName": common_name,
            "subject": {"organizations": [team.as_str()]},
            "duration": tls.client_duration,
            "issuerRef": issuer(issuer_ref),
            "usages": ["digital signature", "key encipherment", "client auth"],
            "secretTemplate": {
                "labels": secret_labels,
                "annotations": {
                    MOUNT_AS_ANNOTATION: "file",
                    MOUNT_PATH_ANNOTATION: tls.client_mount_path,
                },
            },
        }}),
    ))
}

/// One workspace's egress policy: its pods, to the tool's pods in the tools namespace, on the
/// tool port. Goes with its DevWorkspace (`ownerReferences`).
pub fn egress_policy(
    namespace: &NamespaceName,
    devworkspace_id: &str,
    owner: &Owner,
    entry: &ValidEntry,
    tools_namespace: &NamespaceName,
) -> ToolObject {
    let key = &entry.entry.key;
    let mut peer = entry.pod_labels.clone();
    peer.insert(
        CILIUM_POD_NAMESPACE.to_string(),
        tools_namespace.to_string(),
    );
    let mut policy = object(
        namespace,
        egress_policy_name(key, devworkspace_id),
        ToolObjectKind::CiliumNetworkPolicy,
        key,
        BTreeMap::new(),
        BTreeMap::new(),
        json!({"spec": {
            "endpointSelector": {"matchLabels": {DEVWORKSPACE_ID_LABEL: devworkspace_id}},
            "egress": [{"toEndpoints": [{"matchLabels": peer}], "toPorts": to_ports(entry)}],
        }}),
    );
    policy.selector = PodSelector::DevWorkspaceId(devworkspace_id.to_string());
    policy.owner = Some(owner.clone());
    policy
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::selector::{Expression, Operator};
    use weebo_si_crd::{PROFILE_LABEL, ToolIssuerRef};

    use super::*;
    use crate::fixtures::{TOOLS_NS, owner, team, valid_entry};

    fn ca() -> ToolIssuerRef {
        ToolIssuerRef {
            kind: "ClusterIssuer".to_string(),
            name: "team-weebo-tools-ca".to_string(),
        }
    }

    #[test]
    fn ingress_admits_only_the_team_selector() {
        let policy = ingress_policy(
            &NamespaceName::new(TOOLS_NS),
            &valid_entry(),
            &team().namespace_selector,
        );
        assert_eq!(policy.key.name, "weebo-team-tool-buildkit-ingress");
        let rule = &policy.body["spec"]["ingress"][0];
        assert_eq!(
            rule["fromEndpoints"],
            json!([{"matchLabels": {
                "k8s:io.cilium.k8s.namespace.labels.hardening.weebo.io/workspace-namespace": "true",
                "k8s:io.cilium.k8s.namespace.labels.weebo.io/team": "weebo",
            }}])
        );
        assert_eq!(
            rule["toPorts"],
            json!([{"ports": [{"port": "1234", "protocol": "TCP"}]}])
        );
        assert_eq!(
            policy.body["spec"]["endpointSelector"],
            json!({"matchLabels": {"app": "buildkitd"}})
        );
    }

    #[test]
    fn ingress_peers_carry_match_expressions() {
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![Expression {
                key: "weebo.io/team".to_string(),
                operator: Operator::In,
                values: vec!["weebo".to_string(), "data".to_string()],
            }],
        };
        assert_eq!(
            namespace_peer(&selector),
            json!({
                "matchLabels": {
                    "k8s:io.cilium.k8s.namespace.labels.hardening.weebo.io/workspace-namespace": "true",
                },
                "matchExpressions": [{
                    "key": "k8s:io.cilium.k8s.namespace.labels.weebo.io/team",
                    "operator": "In",
                    "values": ["weebo", "data"],
                }],
            })
        );
    }

    #[test]
    fn a_rendered_workload_never_carries_replicas_nor_template_metadata() {
        let entry = valid_entry();
        let mut template = entry.tools[0].clone();
        template
            .labels
            .insert(PROFILE_LABEL.to_string(), "git".to_string());
        template.labels.insert(
            "app.kubernetes.io/instance".to_string(),
            "argo-app".to_string(),
        );
        template.annotations.insert(
            "argocd.argoproj.io/tracking-id".to_string(),
            "x".to_string(),
        );
        let rendered =
            from_template(&template, &NamespaceName::new(TOOLS_NS), &entry.entry.key).unwrap();
        assert_eq!(rendered.kind, ToolObjectKind::StatefulSet);
        assert!(rendered.body["spec"].get("replicas").is_none());
        assert!(rendered.body["spec"].get("template").is_some());
        assert_eq!(rendered.labels, managed_labels(&entry.entry.key));
        assert!(rendered.annotations.is_empty());
    }

    #[test]
    fn a_rendered_service_drops_the_template_allocations() {
        let entry = valid_entry();
        let mut template = entry.tools[1].clone();
        assert_eq!(template.kind, "Service");
        template.body["spec"]["clusterIP"] = json!("10.96.0.42");
        template.body["spec"]["clusterIPs"] = json!(["10.96.0.42"]);
        template.body["spec"]["healthCheckNodePort"] = json!(31000);
        template.body["spec"]["ports"][0]["nodePort"] = json!(30123);
        let rendered =
            from_template(&template, &NamespaceName::new(TOOLS_NS), &entry.entry.key).unwrap();
        let spec = &rendered.body["spec"];
        for field in ["clusterIP", "clusterIPs", "healthCheckNodePort"] {
            assert!(spec.get(field).is_none(), "{field}");
        }
        assert_eq!(
            spec["ports"],
            json!([{"name": "grpc", "port": 1234, "targetPort": 1234, "protocol": "TCP"}])
        );
    }

    #[test]
    fn a_requester_template_keeps_its_dwo_mount_keys() {
        let entry = valid_entry();
        let mut template = entry.requesters[0].clone();
        template
            .labels
            .insert(MOUNT_LABEL.to_string(), "true".to_string());
        template
            .annotations
            .insert(MOUNT_AS_ANNOTATION.to_string(), "subpath".to_string());
        let rendered = from_template(
            &template,
            &NamespaceName::new("dev-ws-bob"),
            &entry.entry.key,
        )
        .unwrap();
        assert_eq!(rendered.labels[MOUNT_LABEL], "true");
        assert_eq!(rendered.annotations[MOUNT_AS_ANNOTATION], "subpath");
        assert_eq!(rendered.body["data"]["config.toml"], "debug = false");
    }

    #[test]
    fn the_cn_comes_from_the_namespace_annotation_not_the_attribute() {
        let cert = client_certificate(
            &NamespaceName::new("dev-ws-batleforc-test"),
            &valid_entry(),
            &ca(),
            &TeamName::new("weebo"),
            "batleforc-test",
        )
        .unwrap();
        assert_eq!(cert.body["spec"]["commonName"], "batleforc-test");
        assert_eq!(
            cert.body["spec"]["subject"]["organizations"],
            json!(["weebo"])
        );
        assert_eq!(cert.key.name, "weebo-team-tool-buildkit-client");
        let template = &cert.body["spec"]["secretTemplate"];
        assert_eq!(template["labels"][MOUNT_LABEL], "true");
        assert_eq!(template["labels"][WATCH_SECRET_LABEL], "true");
        assert_eq!(template["annotations"][MOUNT_AS_ANNOTATION], "file");
        assert_eq!(
            template["annotations"][MOUNT_PATH_ANNOTATION],
            "/home/user/.config/weebo/buildkit"
        );
    }

    #[test]
    fn the_client_certificate_lasts_24h() {
        let cert = client_certificate(
            &NamespaceName::new("dev-ws-bob"),
            &valid_entry(),
            &ca(),
            &TeamName::new("weebo"),
            "bob",
        )
        .unwrap();
        assert_eq!(cert.body["spec"]["duration"], "24h");
        assert_eq!(cert.body["spec"]["issuerRef"]["kind"], "ClusterIssuer");
    }

    #[test]
    fn no_tls_means_no_certificate() {
        let mut entry = valid_entry();
        entry.entry.tls = None;
        let ns = NamespaceName::new(TOOLS_NS);
        assert!(server_certificate(&ns, &entry, &ca()).is_none());
        assert!(client_certificate(&ns, &entry, &ca(), &TeamName::new("weebo"), "bob").is_none());
    }

    #[test]
    fn the_server_certificate_names_the_service_fqdn() {
        let cert =
            server_certificate(&NamespaceName::new(TOOLS_NS), &valid_entry(), &ca()).unwrap();
        assert_eq!(
            cert.body["spec"]["dnsNames"],
            json!(["buildkitd.team-weebo-tools.svc"])
        );
        assert_eq!(cert.body["spec"]["secretName"], "buildkitd-tls");
    }

    #[test]
    fn the_endpoint_is_the_service_fqdn_mounted_as_env() {
        let cm = endpoint_config_map(
            &NamespaceName::new("dev-ws-bob"),
            &valid_entry(),
            &NamespaceName::new(TOOLS_NS),
        )
        .unwrap();
        assert_eq!(cm.key.name, "weebo-team-tool-buildkit");
        assert_eq!(
            cm.body["data"]["BUILDKIT_HOST"],
            "tcp://buildkitd.team-weebo-tools.svc:1234"
        );
        assert_eq!(cm.annotations[MOUNT_AS_ANNOTATION], "env");
        assert_eq!(cm.labels[WATCH_CONFIGMAP_LABEL], "true");
    }

    #[test]
    fn the_egress_policy_selects_one_workspace_and_reaches_only_the_tool() {
        let policy = egress_policy(
            &NamespaceName::new("dev-ws-bob"),
            "workspace1234",
            &owner(),
            &valid_entry(),
            &NamespaceName::new(TOOLS_NS),
        );
        assert_eq!(policy.key.name, "weebo-team-tool-buildkit-workspace1234");
        assert_eq!(
            policy.selector,
            PodSelector::DevWorkspaceId("workspace1234".to_string())
        );
        assert_eq!(policy.owner, Some(owner()));
        assert_eq!(
            policy.body["spec"]["egress"][0]["toEndpoints"],
            json!([{"matchLabels": {"app": "buildkitd", "k8s:io.kubernetes.pod.namespace": TOOLS_NS}}])
        );
        assert!(!policy.labels.contains_key(PROFILE_LABEL));
    }
}
