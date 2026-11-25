//! `spec.features.devfileContract` — see RFC 0019's *Design → Contract*.
//!
//! Like `imageRewrite`, this block carries no team contribution (RFC 0019, *Teams*): the contract
//! numbers and the denied list are cluster facts, so it passes through `resolve_teams` unchanged.
//!
//! Every check is structural, so all of them are CEL rules on the CRD (RFC 0019, *Validation*):
//! a config the apiserver accepts is meaningful, and nothing is reported as `Degraded`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::selector::Selector;

/// The highest contract number a config may name (RFC 0019, *Validation*).
pub const MAX_CONTRACT: u32 = 1000;

/// The most entries `deniedContracts` and `deniedParents` may each carry.
pub const MAX_DENIED_ENTRIES: usize = 64;

/// The most `versions` one `deniedParents` entry may carry.
pub const MAX_DENIED_VERSIONS: usize = 32;

/// The verdict annotation the feature writes on the `DevWorkspace`: `current|outdated|unknown`.
pub const DEVFILE_CONTRACT_ANNOTATION: &str = "hardening.weebo.io/devfile-contract";

/// The reason-code annotation written next to [`DEVFILE_CONTRACT_ANNOTATION`].
pub const DEVFILE_CONTRACT_REASON_ANNOTATION: &str = "hardening.weebo.io/devfile-contract-reason";

/// The devfile attribute declaring the platform contract the devfile was written for.
pub const PLATFORM_CONTRACT_ATTRIBUTE: &str = "weebo.io/platform-contract";

/// The generator's record of the parent it chose — logged only, never evaluated.
pub const DEVFILE_PARENT_ATTRIBUTE: &str = "weebo.io/devfile-parent";

/// The generator's name and version — logged only, never evaluated.
pub const GENERATOR_ATTRIBUTE: &str = "weebo.io/generator";

/// What a matched denied list does on a start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OnDenied {
    /// Refuse the start (under `Enforce`).
    #[default]
    Deny,
    /// Admit it with a warning instead.
    Warn,
}

/// One `deniedParents` entry: a URI prefix, or a registry stack id and its denied versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {
        "rule": "has(self.uriPrefix) != has(self.id)",
        "message": "a denied parent names a uriPrefix or an id, not both"
    },
    {
        "rule": "!has(self.uriPrefix) || self.uriPrefix.startsWith('https://') || self.uriPrefix.startsWith('http://')",
        "message": "uriPrefix must be an http(s) URL prefix"
    },
    {
        "rule": "!has(self.versions) || size(self.versions) == 0 || has(self.id)",
        "message": "versions apply to a registry id only"
    }
]))]
pub struct DeniedParent {
    /// A `parent.uri` prefix, matched after normalisation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 8, max = 2048))]
    pub uri_prefix: Option<String>,
    /// A registry stack id (`parent.id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 253))]
    pub id: Option<String>,
    /// The denied versions of `id`; empty denies every version, an absent one included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = MAX_DENIED_VERSIONS), inner(length(min = 1, max = 64)))]
    pub versions: Vec<String>,
}

/// `spec.features.devfileContract` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {
        "rule": "1 <= self.minimumContract && self.minimumContract <= self.currentContract && self.currentContract <= 1000",
        "message": "contracts start at 1 and minimumContract cannot exceed currentContract"
    },
    {
        "rule": "!has(self.deniedContracts) || self.deniedContracts.all(c, 1 <= c && c <= self.currentContract)",
        "message": "a denied contract must be a published one"
    },
    {
        "rule": "!has(self.minimumSchemaVersion) || self.minimumSchemaVersion.matches('^[0-9]+\\\\.[0-9]+\\\\.[0-9]+$')",
        "message": "minimumSchemaVersion is MAJOR.MINOR.PATCH"
    }
]))]
pub struct DevfileContractConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// The newest contract the User Guide publishes.
    pub current_contract: u32,
    /// Below this a devfile is `outdated` (a warning, never a refusal).
    pub minimum_contract: u32,
    /// The lowest `schemaVersion` accepted without a warning, checked only when the Che
    /// dashboard kept it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 32))]
    pub minimum_schema_version: Option<String>,
    /// Contracts refused at a start; empty refuses nothing.
    #[serde(default)]
    #[schemars(length(max = MAX_DENIED_ENTRIES))]
    pub denied_contracts: Vec<u32>,
    /// Parents refused at a start; empty refuses nothing.
    #[serde(default)]
    #[schemars(length(max = MAX_DENIED_ENTRIES))]
    pub denied_parents: Vec<DeniedParent>,
    /// What a denied-list match does on a start.
    #[serde(default)]
    pub on_denied: OnDenied,
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
    fn the_schema_carries_the_cel_rules_and_the_bounds() {
        let schema = serde_json::to_value(schemars::schema_for!(DevfileContractConfig)).unwrap();
        let rules = schema["x-kubernetes-validations"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        // The CEL literal and the Rust constant must not drift apart.
        assert!(
            rules[0]["rule"]
                .as_str()
                .unwrap()
                .ends_with(&format!("<= {MAX_CONTRACT}"))
        );
        let properties = &schema["properties"];
        assert_eq!(
            properties["deniedContracts"]["maxItems"],
            MAX_DENIED_ENTRIES
        );
        assert_eq!(properties["deniedParents"]["maxItems"], MAX_DENIED_ENTRIES);
        assert_eq!(properties["minimumSchemaVersion"]["maxLength"], 32);

        let parent = &schema["$defs"]["DeniedParent"];
        assert_eq!(
            parent["x-kubernetes-validations"].as_array().unwrap().len(),
            3
        );
        assert_eq!(parent["properties"]["uriPrefix"]["maxLength"], 2048);
        assert_eq!(
            parent["properties"]["versions"]["maxItems"],
            MAX_DENIED_VERSIONS
        );
        assert_eq!(parent["properties"]["versions"]["items"]["maxLength"], 64);
    }

    #[test]
    fn mode_and_contracts_are_required_and_the_rest_defaults() {
        assert!(
            serde_json::from_value::<DevfileContractConfig>(serde_json::json!({"mode": "DryRun"}))
                .is_err()
        );
        let config: DevfileContractConfig = serde_json::from_value(serde_json::json!({
            "mode": "DryRun", "currentContract": 1, "minimumContract": 1
        }))
        .unwrap();
        assert!(config.denied_contracts.is_empty());
        assert!(config.denied_parents.is_empty());
        assert_eq!(config.minimum_schema_version, None);
        assert_eq!(config.on_denied, OnDenied::Deny);
    }

    #[test]
    fn the_rfc_example_deserialises() {
        let config: DevfileContractConfig = serde_json::from_value(serde_json::json!({
            "mode": "Enforce",
            "currentContract": 3,
            "minimumContract": 2,
            "minimumSchemaVersion": "2.2.0",
            "deniedContracts": [1],
            "deniedParents": [
                {"uriPrefix": "https://raw.githubusercontent.com/batleforc/WeeboDevImage/v1.2.0/"},
                {"id": "che-min-mise", "versions": ["1.2.0"]},
            ],
            "onDenied": "Warn",
        }))
        .unwrap();
        assert_eq!(config.denied_parents.len(), 2);
        assert_eq!(config.on_denied, OnDenied::Warn);
    }
}
