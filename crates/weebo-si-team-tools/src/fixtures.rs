//! Test fixtures shared by every module: RFC 0020's reference BuildKit entry and the `weebo`
//! team.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures; a failed assertion is the test failing"
)]

use std::collections::BTreeMap;

use serde_json::{Value, json};
use weebo_si_chassis::managed::Owner;
use weebo_si_crd::{
    FeatureMode, NamespaceName, OnNotGranted, Resolved, ResolvedTeamToolsConfig, Selector,
    TEAM_TOOLS_NAMESPACE_LABEL, Team, TeamName, TeamTeamTools, TeamToolsConfig, ToolEntry,
    ToolIssuerRef, ToolKey, ToolService, ToolTemplateRef, ToolTls, ToolWorkload,
    ToolWorkspaceSelection, WorkloadKind,
};

use crate::bind::{ToolsNamespace, WORKSPACE_NAMESPACE_LABEL};
use crate::port::ToolTemplate;
use crate::port::testing::FakeTemplateStore;
use crate::validate::{ValidEntry, validate_entry};

pub const TEMPLATE_NS: &str = "weebo-si-hardening-templates";
pub const OPERATOR_NS: &str = "weebo-si-hardening";
pub const TOOLS_NS: &str = "team-weebo-tools";

pub fn keys(names: &[&str]) -> Vec<ToolKey> {
    names.iter().copied().map(ToolKey::new).collect()
}

fn template_ref(kind: &str, name: &str) -> ToolTemplateRef {
    ToolTemplateRef {
        kind: kind.to_string(),
        name: name.to_string(),
        namespace: NamespaceName::new(TEMPLATE_NS),
    }
}

pub fn buildkit_entry() -> ToolEntry {
    ToolEntry {
        key: ToolKey::new("buildkit"),
        workload: ToolWorkload {
            kind: WorkloadKind::StatefulSet,
            name: "buildkitd".to_string(),
        },
        service: ToolService {
            name: "buildkitd".to_string(),
            port: 1234,
        },
        client_env: Some("BUILDKIT_HOST".to_string()),
        tls: Some(ToolTls {
            server_secret_name: "buildkitd-tls".to_string(),
            client_duration: "24h".to_string(),
            client_mount_path: "/home/user/.config/weebo/buildkit".to_string(),
        }),
        tool_templates: vec![
            template_ref("StatefulSet", "buildkitd"),
            template_ref("Service", "buildkitd"),
            template_ref("ConfigMap", "buildkitd-toml"),
            template_ref("CiliumNetworkPolicy", "buildkitd-egress"),
        ],
        requester_templates: vec![template_ref("ConfigMap", "buildx-client")],
        idle_grace_seconds: None,
    }
}

fn template(kind: &str, name: &str, body: Value) -> ToolTemplate {
    ToolTemplate {
        kind: kind.to_string(),
        name: name.to_string(),
        namespace: NamespaceName::new(TEMPLATE_NS),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        body,
    }
}

/// The reference templates, each body passed through `edit(kind, body)` first.
pub fn store_with(mut edit: impl FnMut(&str, &mut Value)) -> FakeTemplateStore {
    let mut templates = vec![
        template(
            "StatefulSet",
            "buildkitd",
            json!({"spec": {
                "replicas": 0,
                "serviceName": "buildkitd",
                "selector": {"matchLabels": {"app": "buildkitd"}},
                "template": {
                    "metadata": {"labels": {"app": "buildkitd"}},
                    "spec": {
                        "hostUsers": false,
                        "automountServiceAccountToken": false,
                        "containers": [{
                            "name": "buildkitd",
                            "image": "registry.pkg.weebo.poc/moby/buildkit:v0.35.1-rootless",
                            "securityContext": {
                                "runAsUser": 1000,
                                "procMount": "Unmasked",
                                "seccompProfile": {"type": "Unconfined"},
                                "appArmorProfile": {"type": "Unconfined"},
                            },
                        }],
                    },
                },
            }}),
        ),
        template(
            "Service",
            "buildkitd",
            json!({"spec": {
                "selector": {"app": "buildkitd"},
                "ports": [{"name": "grpc", "port": 1234, "targetPort": 1234, "protocol": "TCP"}],
            }}),
        ),
        template(
            "ConfigMap",
            "buildkitd-toml",
            json!({"data": {"buildkitd.toml": "[registry.\"docker.io\"]"}}),
        ),
        template(
            "CiliumNetworkPolicy",
            "buildkitd-egress",
            json!({"spec": {"endpointSelector": {"matchLabels": {"app": "buildkitd"}}, "egress": []}}),
        ),
        template(
            "ConfigMap",
            "buildx-client",
            json!({"data": {"config.toml": "debug = false"}}),
        ),
    ];
    for t in &mut templates {
        edit(&t.kind, &mut t.body);
    }
    FakeTemplateStore { templates }
}

pub fn store() -> FakeTemplateStore {
    store_with(|_, _| {})
}

pub fn valid_entry() -> ValidEntry {
    validate_entry(
        &buildkit_entry(),
        &[],
        &store(),
        &NamespaceName::new(TEMPLATE_NS),
        &[],
    )
    .unwrap()
}

pub fn team() -> Team {
    Team {
        name: TeamName::new("weebo"),
        namespace_selector: Selector {
            match_labels: BTreeMap::from([("weebo.io/team".to_string(), "weebo".to_string())]),
            match_expressions: Vec::new(),
        },
    }
}

/// A workspace namespace of team `weebo`.
pub fn weebo_labels() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("weebo.io/team".to_string(), "weebo".to_string()),
        (WORKSPACE_NAMESPACE_LABEL.to_string(), "true".to_string()),
    ])
}

pub fn bound_tools_namespace() -> ToolsNamespace {
    ToolsNamespace {
        labels: BTreeMap::from([(TEAM_TOOLS_NAMESPACE_LABEL.to_string(), "weebo".to_string())]),
        quotas: vec![BTreeMap::from([(
            "limits.memory".to_string(),
            "12Gi".to_string(),
        )])],
    }
}

pub fn grant(allowed: &[&str], default: &[&str]) -> TeamTeamTools {
    TeamTeamTools {
        namespace: NamespaceName::new(TOOLS_NS),
        issuer_ref: Some(ToolIssuerRef {
            kind: "ClusterIssuer".to_string(),
            name: "team-weebo-tools-ca".to_string(),
        }),
        allowed: keys(allowed),
        default: keys(default),
    }
}

pub fn config(on_not_granted: OnNotGranted, grant: TeamTeamTools) -> ResolvedTeamToolsConfig {
    Resolved::without_teams(TeamToolsConfig {
        mode: FeatureMode::Enforce,
        namespace_selector: None,
        catalog: vec![buildkit_entry()],
        workspace_selection: ToolWorkspaceSelection::default(),
        on_not_granted,
        idle_grace_seconds: 600,
    })
    .with_grants(BTreeMap::from([("weebo".to_string(), grant)]))
}

pub fn config_with(allowed: &[&str], default: &[&str]) -> ResolvedTeamToolsConfig {
    config(OnNotGranted::Default, grant(allowed, default))
}

pub fn owner() -> Owner {
    Owner {
        api_version: "workspace.devfile.io/v1alpha2".to_string(),
        kind: "DevWorkspace".to_string(),
        name: "python-web".to_string(),
        uid: "uid-1".to_string(),
    }
}
