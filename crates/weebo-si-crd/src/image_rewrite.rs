//! `spec.features.imageRewrite` — see RFC 0017's *Design → Contract*.
//!
//! Like `policyGuard`, this block carries no team contribution (RFC 0017, resolved 7: a rule
//! picks the server that receives every pull of a namespace, which is the cluster admin's call
//! only), so it passes through `resolve_teams` unchanged.
//!
//! The structural checks are CEL rules on the CRD, so a typo is refused at `kubectl apply`
//! rather than silently disabling every rule. The exact, normalisation-dependent check — is
//! `from` a host, is `to` a host and a path — needs the reference parser, which lives in
//! `weebo-si-image-policy` (`rewrite::Rules::new`); this crate is its dependency and cannot call
//! it, the same split `imagePolicy` already has.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::selector::Selector;

/// The most rules one configuration may carry — bounds the per-image work (RFC 0017, T7).
pub const MAX_REWRITE_RULES: usize = 64;

/// The annotation recording each rewritten image's original name, on the `DevWorkspace` (one
/// entry per component) and on the `Pod` (one per container), per RFC 0017's resolved 5.
pub const IMAGE_REWRITE_ANNOTATION: &str = "hardening.weebo.io/image-rewrite";

/// One rule: every image whose normalised host is `from` is pulled from `to` instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteRule {
    /// A registry host — `docker.io`, `quay.io`, `registry.example:5000`.
    #[schemars(length(min = 1, max = 253))]
    pub from: String,
    /// A host followed by at least one `/`-separated path component —
    /// `registry.pkg.weebo.poc/quay`.
    #[schemars(length(min = 1, max = 512))]
    pub to: String,
}

/// `spec.features.imageRewrite` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageRewriteConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// The rules, at most 64. Empty is legal and rewrites nothing.
    #[serde(default)]
    #[schemars(
        length(max = MAX_REWRITE_RULES),
        extend("x-kubernetes-validations" = [
            {
                "rule": "self.all(r, self.exists_one(s, s.from.lowerAscii() == r.from.lowerAscii()))",
                "message": "two rules share the same `from`: which one wins would be declaration order"
            },
            {
                "rule": "self.all(r, !self.exists(s, r.to.lowerAscii().startsWith(s.from.lowerAscii() + '/')))",
                "message": "a rule's `to` host must not be another rule's `from` (chain or loop)"
            },
            {
                "rule": "self.all(r, r.to.contains('/'))",
                "message": "a rule's `to` must be a host followed by at least one path component"
            },
            {
                "rule": "self.all(r, (r.from.matches('[.:]') || r.from.lowerAscii() == 'localhost') && (r.to.matches('^[^/]*[.:][^/]*/') || r.to.lowerAscii().startsWith('localhost/')))",
                "message": "a rule's `from` and the host of its `to` must contain a `.` or a `:`, or be `localhost`: an image reads any other first component as a Docker Hub namespace"
            }
        ])
    )]
    pub rules: Vec<RewriteRule>,
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
    fn the_schema_carries_the_cel_rules_and_the_bound() {
        let schema = serde_json::to_value(schemars::schema_for!(ImageRewriteConfig)).unwrap();
        let rules = &schema["properties"]["rules"];
        assert_eq!(rules["maxItems"], MAX_REWRITE_RULES);
        assert_eq!(
            rules["x-kubernetes-validations"].as_array().unwrap().len(),
            4
        );
    }

    #[test]
    fn mode_is_required_and_rules_default_to_empty() {
        assert!(serde_json::from_value::<ImageRewriteConfig>(serde_json::json!({})).is_err());
        let config: ImageRewriteConfig =
            serde_json::from_value(serde_json::json!({"mode": "DryRun"})).unwrap();
        assert!(config.rules.is_empty());
    }
}
