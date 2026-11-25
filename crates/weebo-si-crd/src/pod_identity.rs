//! `spec.features.podIdentity` — see RFC 0018's *Design → Contract*.
//!
//! Like `imageRewrite`, this block carries no team contribution (RFC 0018: a team does not change
//! the identity a pod gets), so it passes through `resolve_teams` unchanged.
//!
//! Both ids are bounded by CEL on the CRD, so a config the apiserver accepts is meaningful and
//! nothing is reported as `Degraded` (RFC 0018, L4).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::selector::Selector;

/// The uid and gid the WeeboDevImages declare (`useradd -u 1234`), the default of both ids.
pub const DEFAULT_POD_ID: i64 = 1234;

/// The most keys `exemptDwocKeys` may carry.
pub const MAX_EXEMPT_DWOC_KEYS: usize = 64;

fn default_pod_id() -> i64 {
    DEFAULT_POD_ID
}

/// `spec.features.podIdentity` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodIdentityConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// The pod-level uid set when a pod gives none; a pod's own non-zero uid is kept. Never 0.
    #[serde(default = "default_pod_id")]
    #[schemars(extend("x-kubernetes-validations" = [{
        "rule": "1 <= self && self <= 65535",
        "message": "runAsUser must be between 1 and 65535 (uid 0 is root in the image)"
    }]))]
    pub run_as_user: i64,
    /// The pod-level gid and `fsGroup` set when a pod gives none or gives 0; a pod's own non-zero
    /// gid is kept. Never 0.
    #[serde(default = "default_pod_id")]
    #[schemars(extend("x-kubernetes-validations" = [{
        "rule": "1 <= self && self <= 65535",
        "message": "runAsGroup must be between 1 and 65535 (group 0 writes the image's system files)"
    }]))]
    pub run_as_group: i64,
    /// `dwoc-pin` keys whose namespaces (by their `hardening.weebo.io/dwoc` annotation) are left
    /// untouched, e.g. `[build]` (RFC 0018, L27).
    #[serde(default)]
    #[schemars(length(max = MAX_EXEMPT_DWOC_KEYS), inner(length(min = 1, max = 253)))]
    pub exempt_dwoc_keys: Vec<String>,
    /// Last resort, off by default. `true` adds group 0 to every pod in scope, which grants write
    /// on every group-0-writable (`g=u`) file of the image; the feature's status says so for as
    /// long as it is on.
    #[serde(default)]
    pub grant_group_zero: bool,
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
    fn the_schema_bounds_both_ids_with_the_rfc_message() {
        let schema = serde_json::to_value(schemars::schema_for!(PodIdentityConfig)).unwrap();
        for (field, message) in [
            (
                "runAsUser",
                "runAsUser must be between 1 and 65535 (uid 0 is root in the image)",
            ),
            (
                "runAsGroup",
                "runAsGroup must be between 1 and 65535 (group 0 writes the image's system files)",
            ),
        ] {
            let rule = &schema["properties"][field]["x-kubernetes-validations"][0];
            assert_eq!(rule["rule"], "1 <= self && self <= 65535");
            assert_eq!(rule["message"], message);
        }
        let keys = &schema["properties"]["exemptDwocKeys"];
        assert_eq!(keys["maxItems"], MAX_EXEMPT_DWOC_KEYS);
        assert_eq!(keys["items"]["maxLength"], 253);
    }

    #[test]
    fn mode_is_required_and_the_rest_defaults() {
        assert!(serde_json::from_value::<PodIdentityConfig>(serde_json::json!({})).is_err());
        let config: PodIdentityConfig =
            serde_json::from_value(serde_json::json!({"mode": "DryRun"})).unwrap();
        assert_eq!(config.run_as_user, DEFAULT_POD_ID);
        assert_eq!(config.run_as_group, DEFAULT_POD_ID);
        assert!(config.exempt_dwoc_keys.is_empty());
        assert!(!config.grant_group_zero);
    }

    #[test]
    fn the_rfc_example_deserialises() {
        let config: PodIdentityConfig = serde_json::from_value(serde_json::json!({
            "mode": "DryRun",
            "namespaceSelector": {"matchLabels": {
                "kubernetes.io/metadata.name": "dev-ws-batleforc-test"
            }},
            "runAsUser": 1234,
            "runAsGroup": 1234,
            "exemptDwocKeys": ["build"],
            "grantGroupZero": false,
        }))
        .unwrap();
        assert_eq!(config.exempt_dwoc_keys, vec!["build".to_string()]);
    }
}
