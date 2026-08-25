//! `WeeboSiConfig` — cluster-scoped, singleton named `cluster`. See RFC 0002's *Contract*,
//! "The `WeeboSiConfig` CRD."

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc_pin::DwocPinConfig;
use crate::image_policy::ImagePolicyConfig;
use crate::network_profiles::NetworkProfilesConfig;
use crate::policy_guard::PolicyGuardConfig;
use crate::team::Team;

/// One optional field per registered feature, typed — a feature the binary does not know about
/// cannot be written into the resource at all, per RFC 0002's *Contract*.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Features {
    /// `spec.features.dwocPin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dwoc_pin: Option<DwocPinConfig>,
    /// `spec.features.networkProfiles`, per RFC 0004.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_profiles: Option<NetworkProfilesConfig>,
    /// `spec.features.policyGuard`, per RFC 0004.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_guard: Option<PolicyGuardConfig>,
    /// `spec.features.imagePolicy`, per RFC 0005.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_policy: Option<ImagePolicyConfig>,
}

/// The one name a `WeeboSiConfig` is honored under. Any other name is ignored and reported as a
/// `Degraded` condition on the object, per RFC 0002's *Contract*.
pub const SINGLETON_NAME: &str = "cluster";

/// `spec` of the `WeeboSiConfig` CRD.
#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "hardening.weebo.io",
    version = "v1alpha1",
    kind = "WeeboSiConfig",
    singular = "weebosiconfig",
    plural = "weebosiconfigs",
    status = "WeeboSiConfigStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiConfigSpec {
    /// Chassis-level, ordered, first match wins.
    #[serde(default)]
    pub teams: Vec<Team>,
    /// One optional field per registered feature.
    #[serde(default)]
    pub features: Features,
}

/// The reported state of one feature, mirroring its [`crate::feature_mode::FeatureMode`] plus
/// `Degraded` for a configuration reconcile rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum FeatureState {
    /// The feature's mode is `Off`.
    Disabled,
    /// The feature's mode is `DryRun`.
    DryRun,
    /// The feature's mode is `Enforce`.
    Active,
    /// The feature's configuration was rejected at reconcile.
    Degraded,
}

/// One entry of `status.features`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FeatureStatus {
    /// The feature's kebab-case identifier.
    pub name: String,
    /// The feature's reported state.
    pub state: FeatureState,
    /// Human-readable detail — e.g. "evaluated 214 workspaces: 6 would be replaced."
    pub message: String,
    /// The `spec.metadata.generation` this status was computed from.
    pub observed_generation: i64,
}

/// `status` of the `WeeboSiConfig` CRD. Entirely derived from `spec` and the feature registry —
/// deleting it costs one reconcile, per RFC 0002's *Data and state*.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WeeboSiConfigStatus {
    /// The `spec.metadata.generation` this status reflects.
    #[serde(default)]
    pub observed_generation: i64,
    /// One entry per registered feature.
    #[serde(default)]
    pub features: Vec<FeatureStatus>,
    /// Standard `metav1.Condition` list: `Ready`, `Degraded`.
    #[serde(default)]
    pub conditions: Vec<Condition>,
}
