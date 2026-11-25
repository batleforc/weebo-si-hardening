//! `spec.features.teamTools` — see RFC 0020's *Design → Contract*.
//!
//! The cluster block is the catalogue of tools; a team's block is its grant (`allowed`,
//! `default`) plus the tools namespace and the CA it is served from. A team declares no catalogue
//! entry of its own, so there is nothing to merge: resolution only collects the team blocks.
//!
//! The structural bounds are CRD rules (RFC 0020, *Validation*, first row, and Resolved 18); every
//! check that needs the templates or the catalogue is the feature's `validate()`, reported as
//! `Degraded`.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::namespace::NamespaceName;
use crate::network_profiles::OnNotGranted;
use crate::resolved::Resolved;
use crate::selector::Selector;
use crate::team::{WeeboSiTeam, resolution_order};

/// The DevWorkspace attribute naming the requested keys, and the verdict annotation the
/// admission gate writes on the DevWorkspace (`granted=<keys>;dropped=<keys>`).
pub const TEAM_TOOLS_ATTRIBUTE: &str = "hardening.weebo.io/team-tools";

/// The most entries `catalog` may carry.
pub const MAX_TOOL_ENTRIES: usize = 32;

/// The most templates one entry may name, tool and requester lists each.
pub const MAX_TOOL_TEMPLATES: usize = 16;

/// The most keys one request names; a team `default` is a request, so it is bounded the same.
pub const MAX_REQUESTED_TOOLS: usize = 8;

/// The time a tool stays up after its last requester stops, unless the entry overrides it.
pub const DEFAULT_IDLE_GRACE_SECONDS: u32 = 600;

/// A catalogue key: the attribute's vocabulary. A DNS label of at most 40 characters, so
/// `weebo-team-tool-<key>-client` and the other generated names stay valid object names.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ToolKey(
    #[schemars(
        length(min = 1, max = 40),
        regex(pattern = "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    )]
    String,
);

impl ToolKey {
    /// Wrap a key. Does not validate: the CRD schema does.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of the workload scaled on demand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum WorkloadKind {
    /// An `apps/v1` `Deployment`.
    Deployment,
    /// An `apps/v1` `StatefulSet`, whose `volumeClaimTemplates` survive scale to zero.
    StatefulSet,
}

/// `catalog[].workload` — the tool template scaled through `/scale`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolWorkload {
    /// `Deployment` or `StatefulSet`.
    pub kind: WorkloadKind,
    /// Its name among the tool templates.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

/// `catalog[].service` — the port the ingress and egress policies open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolService {
    /// The `Service` template's name.
    #[schemars(length(min = 1, max = 63))]
    pub name: String,
    /// One of its ports.
    #[schemars(range(min = 1))]
    pub port: u16,
}

/// `catalog[].tls` — server and per-user client certificates, issued by the team's `issuerRef`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolTls {
    /// The `Secret` the server `Certificate` writes, mounted by the tool template.
    #[schemars(length(min = 1, max = 253))]
    pub server_secret_name: String,
    /// The client certificate's lifetime, a Go duration (`24h`).
    #[schemars(length(min = 1, max = 32))]
    pub client_duration: String,
    /// Where DWO mounts the client certificate in the workspace.
    #[schemars(length(min = 2, max = 1024), regex(pattern = "^/"))]
    pub client_mount_path: String,
}

/// A template object, in the template namespace (checked by `validate()`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolTemplateRef {
    /// The object's kind; the allowed kinds are checked by `validate()`.
    #[schemars(length(min = 1, max = 63))]
    pub kind: String,
    /// The object's name.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    /// The namespace it lives in.
    #[schemars(length(min = 1, max = 63))]
    pub namespace: NamespaceName,
}

/// One entry of `spec.features.teamTools.catalog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolEntry {
    /// The key a devfile attribute or a team grant names.
    pub key: ToolKey,
    /// The tool template scaled on demand.
    pub workload: ToolWorkload,
    /// The port the network policies open.
    pub service: ToolService,
    /// The key of the generated endpoint `ConfigMap`, an environment variable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = "^[A-Za-z_][A-Za-z0-9_]*$")
    )]
    pub client_env: Option<String>,
    /// Absent means no mTLS: allowed, and logged (RFC 0020, Resolved 14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ToolTls>,
    /// Rendered into the team's tools namespace.
    #[schemars(length(max = MAX_TOOL_TEMPLATES))]
    pub tool_templates: Vec<ToolTemplateRef>,
    /// `ConfigMap`s rendered into each requesting namespace.
    #[serde(default)]
    #[schemars(length(max = MAX_TOOL_TEMPLATES))]
    pub requester_templates: Vec<ToolTemplateRef>,
    /// Overrides the block's `idleGraceSeconds` for this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = u32::MAX))]
    pub idle_grace_seconds: Option<u32>,
}

/// `spec.features.teamTools.workspaceSelection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolWorkspaceSelection {
    /// DevWorkspace attribute naming a comma-separated key list. `""` disables requests.
    #[serde(default = "default_attribute")]
    #[schemars(length(max = 317))]
    pub attribute: String,
}

fn default_attribute() -> String {
    TEAM_TOOLS_ATTRIBUTE.to_string()
}

impl Default for ToolWorkspaceSelection {
    fn default() -> Self {
        Self {
            attribute: default_attribute(),
        }
    }
}

fn default_idle_grace_seconds() -> u32 {
    DEFAULT_IDLE_GRACE_SECONDS
}

/// `spec.features.teamTools` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamToolsConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows which requesting namespaces are read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every tool a team may be granted. Required, may be empty.
    #[schemars(
        length(max = MAX_TOOL_ENTRIES),
        extend("x-kubernetes-validations" = [{
            "rule": "self.all(e, self.exists_one(f, f.key == e.key))",
            "message": "two catalog entries share the same key"
        }])
    )]
    pub catalog: Vec<ToolEntry>,
    /// The DevWorkspace attribute naming the requested keys.
    #[serde(default)]
    pub workspace_selection: ToolWorkspaceSelection,
    /// What a requested key the team is not granted gets: dropped, or the request refused.
    #[serde(default)]
    pub on_not_granted: OnNotGranted,
    /// Time a tool stays up after its last requester stops.
    // The apiserver ignores `format: uint32`: without the maximum a value the operator cannot
    // deserialise would be admitted and break the whole singleton.
    #[serde(default = "default_idle_grace_seconds")]
    #[schemars(range(max = u32::MAX))]
    pub idle_grace_seconds: u32,
}

/// `spec.features.teamTools.issuerRef` on a `WeeboSiTeam` — this team's CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolIssuerRef {
    /// `ClusterIssuer` only: a namespaced `Issuer` cannot serve workspace namespaces (RFC 0020,
    /// Resolved 18).
    #[schemars(
        length(max = 32),
        extend("x-kubernetes-validations" = [{
            "rule": "self == 'ClusterIssuer'",
            "message": "issuerRef.kind must be ClusterIssuer: a namespaced Issuer cannot serve workspace namespaces"
        }])
    )]
    pub kind: String,
    /// The `ClusterIssuer`'s name.
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

/// `spec.features.teamTools` on a `WeeboSiTeam` — the tools namespace and the team's grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamTeamTools {
    /// The tools namespace; it must carry `hardening.weebo.io/team-tools=<team name>`.
    #[schemars(length(min = 1, max = 63))]
    pub namespace: NamespaceName,
    /// This team's CA; required by `validate()` when an allowed entry has `tls`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<ToolIssuerRef>,
    /// The keys this team may request.
    #[serde(default)]
    #[schemars(length(max = MAX_TOOL_ENTRIES))]
    pub allowed: Vec<ToolKey>,
    /// The keys a workspace with no attribute gets; within `allowed` (checked by `validate()`).
    #[serde(default)]
    #[schemars(length(max = MAX_REQUESTED_TOOLS))]
    pub default: Vec<ToolKey>,
}

/// What one team reaches: its block, as written. A team declares no catalogue entry, so the grant
/// needs no derivation.
pub type ToolGrant = TeamTeamTools;

/// [`TeamToolsConfig`] resolved against the `WeeboSiTeam` objects.
pub type ResolvedTeamToolsConfig = Resolved<TeamToolsConfig, ToolGrant>;

impl TeamToolsConfig {
    /// Collect every team's block as its grant, per RFC 0011. Nothing merges, so nothing
    /// conflicts; a team with no block has no grant and gets no tool (RFC 0020, *Behaviour*).
    pub fn resolve(&self, teams: &[WeeboSiTeam]) -> ResolvedTeamToolsConfig {
        let grants = resolution_order(teams)
            .into_iter()
            .filter_map(|team| {
                let block = team.spec.features.team_tools.clone()?;
                Some((team.team_name().to_string(), block))
            })
            .collect();
        Resolved {
            config: self.clone(),
            grants,
        }
    }
}

/// The state of one tool of a team, as `status.teamTools[].state` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TeamToolState {
    /// Rendered, scaled to 1.
    Running,
    /// Requesters reached 0; still up until the idle grace elapses.
    Grace,
    /// Rendered, scaled to 0.
    Idle,
    /// The tools namespace cache is not synced: no scale, no delete.
    Held,
    /// The tools namespace is not bound: nothing is written there.
    Unbound,
    /// The catalogue entry is invalid: what is rendered is kept, nothing new is applied.
    Invalid,
}

/// One entry of `WeeboSiTeam.status.teamTools`: counts only, never who requests (privacy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TeamToolStatus {
    /// The catalogue key.
    pub key: ToolKey,
    /// The tools namespace.
    pub namespace: NamespaceName,
    /// The workload's current replicas.
    pub replicas: i32,
    /// How many DevWorkspaces of the team request the key.
    pub requesters: i64,
    /// Where the tool stands.
    pub state: TeamToolState,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_carries_the_bounds_and_the_cel_rules() {
        let schema = serde_json::to_value(schemars::schema_for!(TeamToolsConfig)).unwrap();
        let catalog = &schema["properties"]["catalog"];
        assert_eq!(catalog["maxItems"], MAX_TOOL_ENTRIES);
        assert_eq!(
            catalog["x-kubernetes-validations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let entry = &schema["$defs"]["ToolEntry"]["properties"];
        assert_eq!(entry["toolTemplates"]["maxItems"], MAX_TOOL_TEMPLATES);
        assert_eq!(entry["requesterTemplates"]["maxItems"], MAX_TOOL_TEMPLATES);
        assert_eq!(schema["$defs"]["ToolKey"]["maxLength"], 40);

        let team = serde_json::to_value(schemars::schema_for!(TeamTeamTools)).unwrap();
        assert_eq!(team["properties"]["allowed"]["maxItems"], MAX_TOOL_ENTRIES);
        assert_eq!(
            team["properties"]["default"]["maxItems"],
            MAX_REQUESTED_TOOLS
        );
        assert_eq!(
            team["$defs"]["ToolIssuerRef"]["properties"]["kind"]["x-kubernetes-validations"][0]["rule"],
            "self == 'ClusterIssuer'"
        );
    }

    #[test]
    fn mode_and_catalog_are_required_and_the_rest_defaults() {
        assert!(
            serde_json::from_value::<TeamToolsConfig>(serde_json::json!({"mode": "DryRun"}))
                .is_err()
        );
        let config: TeamToolsConfig =
            serde_json::from_value(serde_json::json!({"mode": "DryRun", "catalog": []})).unwrap();
        assert_eq!(config.workspace_selection.attribute, TEAM_TOOLS_ATTRIBUTE);
        assert_eq!(config.on_not_granted, OnNotGranted::Default);
        assert_eq!(config.idle_grace_seconds, DEFAULT_IDLE_GRACE_SECONDS);

        let team: TeamTeamTools =
            serde_json::from_value(serde_json::json!({"namespace": "team-weebo-tools"})).unwrap();
        assert!(team.allowed.is_empty() && team.default.is_empty());
        assert_eq!(team.issuer_ref, None);
    }

    #[test]
    fn the_rfc_example_deserialises_and_resolves_to_the_team_grant() {
        let config: TeamToolsConfig = serde_json::from_value(serde_json::json!({
            "mode": "DryRun",
            "idleGraceSeconds": 600,
            "onNotGranted": "Default",
            "catalog": [{
                "key": "buildkit",
                "workload": {"kind": "StatefulSet", "name": "buildkitd"},
                "service": {"name": "buildkitd", "port": 1234},
                "clientEnv": "BUILDKIT_HOST",
                "tls": {
                    "serverSecretName": "buildkitd-tls",
                    "clientDuration": "24h",
                    "clientMountPath": "/home/user/.config/weebo/buildkit",
                },
                "toolTemplates": [
                    {"kind": "StatefulSet", "name": "buildkitd", "namespace": "weebo-si-hardening-templates"},
                    {"kind": "Service", "name": "buildkitd", "namespace": "weebo-si-hardening-templates"},
                ],
                "requesterTemplates": [
                    {"kind": "ConfigMap", "name": "buildx-client", "namespace": "weebo-si-hardening-templates"},
                ],
            }],
        }))
        .unwrap();
        assert_eq!(config.catalog[0].workload.kind, WorkloadKind::StatefulSet);

        let team: WeeboSiTeam = serde_json::from_value(serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": {"name": "weebo"},
            "spec": {
                "namespaceSelector": {"matchLabels": {"weebo.io/team": "weebo"}},
                "features": {"teamTools": {
                    "namespace": "team-weebo-tools",
                    "issuerRef": {"kind": "ClusterIssuer", "name": "team-weebo-tools-ca"},
                    "allowed": ["buildkit"],
                    "default": [],
                }},
            },
        }))
        .unwrap();
        let resolved = config.resolve(&[team]);
        let grant = resolved.grants.get("weebo").unwrap();
        assert_eq!(grant.allowed, vec![ToolKey::new("buildkit")]);
        assert_eq!(grant.namespace.as_str(), "team-weebo-tools");
        assert!(config.resolve(&[]).grants.is_empty());
    }
}
