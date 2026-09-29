//! `WeeboSiTeam` — one team, one object, carrying its own catalogue for every feature.
//!
//! RFC 0002 made a team `{name, namespaceSelector}` inside the singleton and put every
//! entitlement in a per-feature `grants` map keyed by the team's name. RFC 0011 amends that:
//! identity and entitlement live together on an object with the team's own lifetime, and the
//! `grants` maps leave the wire. What is *not* amended is the reason grants were per feature in
//! the first place — a team still declares a different shape for each feature, in that feature's
//! own vocabulary, which is why [`TeamFeatures`] is six optional blocks and not one.
//!
//! The ordering rule changes with the split and is the one thing to read twice. RFC 0002 made
//! `spec.teams` ordered and first-match-wins, justified by "this list is written by one admin in
//! one file, where reading order is an intuition already available". Separate objects have no
//! file and no order, so the intuition is gone and something explicit has to replace it:
//! [`WeeboSiTeamSpec::priority`], lowest first, ties broken by name. Inferring precedence from selector
//! specificity was rejected for the reason RFC 0002 rejected it.

use std::fmt;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::argo::ApplicationTemplate;
use crate::dwoc_pin::TeamDwocPin;
use crate::endpoint_auth::TeamEndpointAuth;
use crate::image_policy::TeamImagePolicy;
use crate::kubearmor_policy::TeamKubeArmorPolicy;
use crate::network_profiles::TeamNetworkProfiles;
use crate::registry_config::TeamRegistryConfig;
use crate::selector::Selector;

/// The priority a team gets when it does not say. High on purpose: a team that has an opinion
/// about precedence states it, and lands ahead of every team that does not.
pub const DEFAULT_PRIORITY: i32 = 1000;

/// A team name. A newtype so a team can never be passed where a catalogue key or a namespace
/// name is expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct TeamName(String);

impl TeamName {
    /// Wrap a team name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TeamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A team as the features see it: a name and the namespaces it owns.
///
/// **Derived, never written.** Until RFC 0011 this was an entry of `spec.teams` and a wire type;
/// it is now the in-memory view [`team_views`] projects out of the objects, in resolution order.
/// Every feature's namespace-to-team matching keeps taking a `&[Team]` and keeps meaning
/// "first match wins", so the split cost the features nothing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// This team's identity, referenced by a `WeeboSiUser` and by every resolved grant.
    pub name: TeamName,
    /// The namespaces that belong to this team.
    pub namespace_selector: Selector,
}

/// What one team is entitled to, one optional block per feature.
///
/// A block absent means "whatever a namespace with no team gets" — the cluster default, applied
/// unchanged. That is the one rule making a partially configured team safe: a feature a team has
/// not thought about cannot be widened by the split.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamFeatures {
    /// This team's `dwoc-pin` catalogue and default, per RFC 0002.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dwoc_pin: Option<TeamDwocPin>,
    /// This team's `network-profiles` catalogue and defaults, per RFC 0004.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_profiles: Option<TeamNetworkProfiles>,
    /// This team's `image-policy` catalogue and defaults, per RFC 0005.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_policy: Option<TeamImagePolicy>,
    /// This team's `kubearmor-policy` catalogue and defaults, per RFC 0006.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubearmor_policy: Option<TeamKubeArmorPolicy>,
    /// This team's `registry-config` catalogue and defaults, per RFC 0007.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_config: Option<TeamRegistryConfig>,
    /// This team's `endpoint-auth` catalogue and default, per RFC 0009.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_auth: Option<TeamEndpointAuth>,
}

/// `spec.identity` — what this team's members are, outside Kubernetes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamIdentity {
    /// The identity provider half.
    #[serde(default, skip_serializing_if = "is_default")]
    pub authentik: TeamAuthentik,
}

/// `spec.identity.authentik` — the groups every member of this team receives.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamAuthentik {
    /// Authentik group **names** — `AuthentikGroup.spec.name`, resolved by the upstream operator
    /// against its own API, never against Kubernetes. Each is checked against
    /// `spec.features.identity.authentik.allowedGroupRefs` before anything is created.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_refs: Vec<String>,
}

/// `spec.workspace` — what each member of this team gets deployed for them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamWorkspace {
    /// The Eclipse Che workspace application, as an Argo CD template rendered per person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub che: Option<ApplicationTemplate>,
}

/// `spec` of the `WeeboSiTeam` CRD.
#[derive(CustomResource, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "hardening.weebo.io",
    version = "v1alpha1",
    kind = "WeeboSiTeam",
    singular = "weebositeam",
    plural = "weebositeams",
    shortname = "wsteam",
    status = "WeeboSiTeamStatus"
)]
#[kube(printcolumn = r#"{"name":"Priority","type":"integer","jsonPath":".spec.priority"}"#)]
#[kube(printcolumn = r#"{"name":"Namespaces","type":"integer","jsonPath":".status.namespaces"}"#)]
#[kube(printcolumn = r#"{"name":"Members","type":"integer","jsonPath":".status.members"}"#)]
#[kube(
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#
)]
#[kube(printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiTeamSpec {
    /// A human label. Nothing branches on it — the team's identity is `metadata.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Precedence when a namespace matches more than one team: lowest wins, ties break on name.
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// The namespaces that belong to this team.
    pub namespace_selector: Selector,
    /// What this team is entitled to, per feature.
    #[serde(default)]
    pub features: TeamFeatures,
    /// What this team's members are outside Kubernetes.
    #[serde(default, skip_serializing_if = "is_default")]
    pub identity: TeamIdentity,
    /// What each member gets deployed for them.
    #[serde(default, skip_serializing_if = "is_default")]
    pub workspace: TeamWorkspace,
}

/// Whether a value is its own default, for the `skip_serializing_if` above.
///
/// Empty blocks are omitted rather than printed as `{}`: these objects are written by hand and
/// printed by `weebo-si-operator teams export`, and a team that configures nothing outside
/// Kubernetes should not have to read two lines saying so.
fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

fn default_priority() -> i32 {
    DEFAULT_PRIORITY
}

/// `status` of the `WeeboSiTeam` CRD. Entirely derived: deleting it costs one reconcile.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiTeamStatus {
    /// The `metadata.generation` this status reflects.
    #[serde(default)]
    pub observed_generation: i64,
    /// How many namespaces this team's selector currently claims.
    #[serde(default)]
    pub namespaces: i64,
    /// How many `WeeboSiUser` objects name this team.
    #[serde(default)]
    pub members: i64,
    /// Standard `metav1.Condition` list: `Ready`, `Degraded`.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

impl WeeboSiTeam {
    /// This team's name — its `metadata.name`, which is the identity every reference uses.
    ///
    /// An object with no name cannot exist in the API server; the empty string here is the value
    /// a hand-built object in a test gets, and it matches nothing rather than matching everything.
    pub fn team_name(&self) -> TeamName {
        TeamName::new(self.metadata.name.clone().unwrap_or_default())
    }

    /// The view the features resolve against.
    pub fn as_team(&self) -> Team {
        Team {
            name: self.team_name(),
            namespace_selector: self.spec.namespace_selector.clone(),
        }
    }

    /// The sort key: priority first, then name. Total and deterministic, so two replicas
    /// resolving the same objects cannot disagree about which team owns a namespace.
    pub fn resolution_key(&self) -> (i32, String) {
        (
            self.spec.priority,
            self.metadata.name.clone().unwrap_or_default(),
        )
    }
}

/// Every team, in resolution order.
///
/// The replacement for `spec.teams`' document order. Every caller that used to pass
/// `&config.spec.teams` passes this instead, and first-match-wins keeps meaning what it meant.
pub fn resolution_order(teams: &[WeeboSiTeam]) -> Vec<&WeeboSiTeam> {
    let mut ordered: Vec<&WeeboSiTeam> = teams.iter().collect();
    ordered.sort_by_key(|team| team.resolution_key());
    ordered
}

/// Every team as a [`Team`] view, in resolution order.
pub fn team_views(teams: &[WeeboSiTeam]) -> Vec<Team> {
    resolution_order(teams)
        .into_iter()
        .map(WeeboSiTeam::as_team)
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn team(name: &str, priority: i32) -> WeeboSiTeam {
        let mut team = WeeboSiTeam::new(
            name,
            WeeboSiTeamSpec {
                display_name: None,
                priority,
                namespace_selector: Selector::default(),
                features: TeamFeatures::default(),
                identity: TeamIdentity::default(),
                workspace: TeamWorkspace::default(),
            },
        );
        team.status = None;
        team
    }

    #[test]
    fn resolution_order_is_priority_then_name() {
        let teams = vec![
            team("zulu", 100),
            team("alpha", 200),
            team("mike", 100),
            team("bravo", 50),
        ];
        let ordered: Vec<String> = team_views(&teams)
            .into_iter()
            .map(|team| team.name.to_string())
            .collect();
        assert_eq!(
            ordered,
            vec![
                "bravo".to_string(),
                "mike".to_string(),
                "zulu".to_string(),
                "alpha".to_string(),
            ]
        );
    }

    #[test]
    fn a_team_with_no_priority_lands_behind_one_with_a_priority() {
        let teams = vec![team("stated", 10), team("unstated", DEFAULT_PRIORITY)];
        let ordered = team_views(&teams);
        assert_eq!(ordered[0].name.as_str(), "stated");
    }

    #[test]
    fn the_team_name_is_the_object_name() {
        assert_eq!(team("platform", 1).team_name(), TeamName::new("platform"));
    }
}
