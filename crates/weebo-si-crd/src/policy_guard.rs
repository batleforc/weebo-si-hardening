//! `spec.features.policyGuard` — see RFC 0004's *Design → Contract*, "`policyGuard`."

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::selector::Selector;

/// `spec.features.policyGuard` in full. Nothing here can be internally inconsistent the way a
/// catalogue/grant pair can, so unlike `NetworkProfilesConfig` this type has no `validate()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyGuardConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Identities exempt from the guard's rules, in addition to the operator's own.
    #[serde(default)]
    pub allowed_identities: Vec<String>,
}
