//! `WeeboSiUser` — one person, one object: the Kubernetes identity, the team, and the two
//! optional provisioning switches. See RFC 0011.
//!
//! Membership becomes something an admin writes down. `endpoint-auth` derives it today — a team's
//! members are the owners of its namespaces (`weebo-si-endpoint-auth`'s `TeamMembership` port) —
//! and that derivation stays, as the answer for somebody with no object here. The two can
//! disagree, and RFC 0011 says the declared answer wins: somebody in team A owning a namespace of
//! team B is a real situation, and the object is the one a human reviewed.
//!
//! What this object deliberately does **not** carry is a credential. `AuthentikUser` has no
//! password field by design and neither does this; the identity provider owns its own invite and
//! reset flows, and no secret this operator could leak is ever in hand.

use std::fmt;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::identity::ProvisioningMode;
use crate::team::TeamName;
use crate::template::{Bindings, DISPLAY_NAME, EMAIL, OBJECT_NAME, TEAM_NAME, USERNAME};

/// A person's Kubernetes identity, as the API server presents it after authentication.
///
/// A newtype for the same reason [`TeamName`] is one: the value travels through team lookups,
/// templates and Authentik payloads, and none of those should accept a namespace or a catalogue
/// key by accident.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct Username(String);

impl Username {
    /// Wrap a username.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `spec.authentik` — whether this person exists in the identity provider, and as what.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserAuthentik {
    /// Required when the block is present, per the chassis rule: a behaviour nobody wrote down
    /// does not run.
    pub mode: ProvisioningMode,
    /// The `AuthentikUser`'s own name. Defaults to this object's `metadata.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Groups this person gets **in addition** to their team's. Every entry is checked against
    /// `spec.features.identity.authentik.allowedGroupRefs`.
    #[serde(default)]
    pub group_refs: Vec<String>,
}

/// `spec.che` — whether this person gets the workspace application their team describes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserChe {
    /// Required when the block is present.
    pub mode: ProvisioningMode,
    /// Overrides the namespace the team's `destination.namespace` template renders to. The
    /// override is what `{USER_NAMESPACE}` binds to everywhere else, so one field moves the whole
    /// application.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Helm values deep-merged **over** the team's. A person narrows or tunes; the team's block
    /// is what they start from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::free_form::object_schema")]
    pub values: Option<Value>,
}

/// `spec` of the `WeeboSiUser` CRD.
#[derive(CustomResource, Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "hardening.weebo.io",
    version = "v1alpha1",
    kind = "WeeboSiUser",
    singular = "weebosiuser",
    plural = "weebosiusers",
    shortname = "wsuser",
    status = "WeeboSiUserStatus"
)]
#[kube(printcolumn = r#"{"name":"Username","type":"string","jsonPath":".spec.username"}"#)]
#[kube(printcolumn = r#"{"name":"Team","type":"string","jsonPath":".spec.team"}"#)]
#[kube(
    printcolumn = r#"{"name":"Authentik","type":"string","jsonPath":".status.authentik.state"}"#
)]
#[kube(printcolumn = r#"{"name":"Che","type":"string","jsonPath":".status.che.state"}"#)]
#[kube(
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#
)]
#[kube(printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiUserSpec {
    /// The Kubernetes identity. Two objects claiming one username is a violation on both — an
    /// identity resolving to two sets of entitlements has no correct reading.
    pub username: Username,
    /// Passed to Authentik as `name`. Defaults to the username.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Required when `authentik.mode` is not `Off`, because `AuthentikUser` requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The `WeeboSiTeam` this person belongs to. Empty is legal and reported: a person with no
    /// team has no entitlement and no workspace, which is a person who is not finished rather
    /// than an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<TeamName>,
    /// `false` suspends provisioning without deleting anything: the `AuthentikUser` is written
    /// with `isActive: false` and the application is left alone.
    #[serde(default = "default_true")]
    pub active: bool,
    /// The identity provider half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentik: Option<UserAuthentik>,
    /// The workspace half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub che: Option<UserChe>,
}

fn default_true() -> bool {
    true
}

/// What happened to one provisioned object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum TargetState {
    /// The block is absent or `Off`. Nothing was looked for.
    Off,
    /// This operator created it, and owns it: deleting the person deletes it.
    Created,
    /// It already existed and is owned by somebody else. Referenced, **never written** — the
    /// operator reports what it found rather than taking over an object an admin made.
    Adopted,
    /// The target CRD is not installed, or the reference names nothing.
    Absent,
    /// Another `WeeboSiUser` claims the same target.
    Conflict,
}

impl fmt::Display for TargetState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Off => "Off",
            Self::Created => "Created",
            Self::Adopted => "Adopted",
            Self::Absent => "Absent",
            Self::Conflict => "Conflict",
        };
        f.write_str(label)
    }
}

/// One provisioned object's reported state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TargetStatus {
    /// The object's name.
    pub name: String,
    /// Its namespace, for a namespaced kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// What happened.
    pub state: TargetState,
    /// Human-readable detail, carrying the violation text when there is one.
    #[serde(default)]
    pub message: String,
}

/// `status` of the `WeeboSiUser` CRD.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiUserStatus {
    /// The `metadata.generation` this status reflects.
    #[serde(default)]
    pub observed_generation: i64,
    /// The team this person resolved to, absent when they have none or it does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    /// The identity provider half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentik: Option<TargetStatus>,
    /// The workspace half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub che: Option<TargetStatus>,
    /// Standard `metav1.Condition` list: `Ready`, `Degraded`.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

impl WeeboSiUser {
    /// This object's own name.
    pub fn object_name(&self) -> String {
        self.metadata.name.clone().unwrap_or_default()
    }

    /// The name to show, defaulted to the username.
    pub fn display_name(&self) -> String {
        self.spec
            .display_name
            .clone()
            .unwrap_or_else(|| self.spec.username.to_string())
    }

    /// The `AuthentikUser` this person maps to, named or defaulted.
    pub fn authentik_name(&self) -> String {
        self.spec
            .authentik
            .as_ref()
            .and_then(|block| block.name.clone())
            .unwrap_or_else(|| self.object_name())
    }

    /// The five variables a template's first pass resolves. `{USER_NAMESPACE}` is bound later,
    /// by [`crate::argo::ApplicationTemplate::render`], because it is itself rendered.
    pub fn bindings(&self) -> Bindings {
        Bindings::new()
            .bind(USERNAME, self.spec.username.to_string())
            .bind(OBJECT_NAME, self.object_name())
            .bind(
                TEAM_NAME,
                self.spec
                    .team
                    .as_ref()
                    .map(TeamName::to_string)
                    .unwrap_or_default(),
            )
            .bind(EMAIL, self.spec.email.clone().unwrap_or_default())
            .bind(DISPLAY_NAME, self.display_name())
    }

    /// Whether this person asked for an identity-provider account.
    pub fn wants_authentik(&self) -> bool {
        matches!(
            self.spec.authentik.as_ref().map(|block| block.mode),
            Some(ProvisioningMode::Ensure)
        )
    }

    /// Whether this person asked for their team's workspace application.
    pub fn wants_che(&self) -> bool {
        matches!(
            self.spec.che.as_ref().map(|block| block.mode),
            Some(ProvisioningMode::Ensure)
        )
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

    fn user() -> WeeboSiUser {
        let mut user = WeeboSiUser::new(
            "max",
            WeeboSiUserSpec {
                username: Username::new("max"),
                display_name: None,
                email: Some("max@weebo.io".to_string()),
                team: Some(TeamName::new("platform")),
                active: true,
                authentik: None,
                che: None,
            },
        );
        user.status = None;
        user
    }

    #[test]
    fn the_display_name_falls_back_to_the_username() {
        assert_eq!(user().display_name(), "max".to_string());
        let mut named = user();
        named.spec.display_name = Some("Max Leriche".to_string());
        assert_eq!(named.display_name(), "Max Leriche".to_string());
    }

    #[test]
    fn the_authentik_name_falls_back_to_the_object_name() {
        assert_eq!(user().authentik_name(), "max".to_string());
        let mut named = user();
        named.spec.authentik = Some(UserAuthentik {
            mode: ProvisioningMode::Ensure,
            name: Some("max-leriche".to_string()),
            group_refs: Vec::new(),
        });
        assert_eq!(named.authentik_name(), "max-leriche".to_string());
    }

    #[test]
    fn an_absent_block_wants_nothing() {
        assert!(!user().wants_authentik());
        assert!(!user().wants_che());
    }

    #[test]
    fn mode_off_wants_nothing_either() {
        let mut off = user();
        off.spec.authentik = Some(UserAuthentik {
            mode: ProvisioningMode::Off,
            name: None,
            group_refs: Vec::new(),
        });
        assert!(!off.wants_authentik());
    }

    #[test]
    fn a_person_with_no_team_binds_an_empty_team_name() {
        let mut teamless = user();
        teamless.spec.team = None;
        assert_eq!(teamless.bindings().get(TEAM_NAME), Some(""));
    }
}
