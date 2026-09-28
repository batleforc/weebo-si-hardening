//! `WeeboSiConfig` — cluster-scoped, singleton named `cluster`. See RFC 0002's *Contract*,
//! "The `WeeboSiConfig` CRD."

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc_pin::DwocPinConfig;
use crate::endpoint_auth::EndpointAuthConfig;
use crate::identity::IdentityConfig;
use crate::image_policy::ImagePolicyConfig;
use crate::kubearmor_policy::KubeArmorPolicyConfig;
use crate::network_profiles::NetworkProfilesConfig;
use crate::policy_guard::PolicyGuardConfig;
use crate::registry_config::RegistryConfig;
use crate::team::{TeamName, WeeboSiTeam};

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
    /// `spec.features.kubearmorPolicy`, per RFC 0006.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubearmor_policy: Option<KubeArmorPolicyConfig>,
    /// `spec.features.registryConfig`, per RFC 0007.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_config: Option<RegistryConfig>,
    /// `spec.features.endpointAuth`, per RFC 0009.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_auth: Option<EndpointAuthConfig>,
    /// `spec.features.identity`, per RFC 0011 — the only feature that creates objects in systems
    /// other than this cluster's own, and the only one with allow-lists of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityConfig>,
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
    /// One optional field per registered feature.
    ///
    /// `spec.teams` used to sit beside this and does not any more: RFC 0011 moved teams to their
    /// own `WeeboSiTeam` objects, and removed the field rather than deprecating it. A manifest
    /// still carrying it is pruned by the API server, which reads as "my teams vanished" — the
    /// loud failure a hard cut should have.
    #[serde(default)]
    pub features: Features,
}

/// One conflict the resolution found, and whose fault it is.
///
/// The `team` is what lets a `WeeboSiTeam`'s own `status` carry its own mistakes and nobody
/// else's — the singleton reports every conflict, each team reports the ones it caused. It is an
/// `Option` because the type has to outlive today's single source of conflicts: every one of them
/// is a team redefining a catalogue key, and a future conflict between two cluster-level entries
/// would belong to nobody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveConflict {
    /// The team responsible, if one is.
    pub team: Option<TeamName>,
    /// The violation, rendered.
    pub message: String,
}

impl WeeboSiConfigSpec {
    /// Merge the `WeeboSiTeam` objects into every feature's catalogue and grants, per RFC 0011.
    ///
    /// Returns one entry per conflict found, for the reconcile loops' `Degraded` conditions.
    /// **Every loader has to call this**: a configuration nobody resolved grants nothing, so the
    /// cost of forgetting is every namespace falling to the cluster default — safe, visible in
    /// the feature metrics, and never the opposite.
    pub fn resolve_teams(&mut self, teams: &[WeeboSiTeam]) -> Vec<ResolveConflict> {
        let mut conflicts = Vec::new();

        if let Some(feature) = self.features.dwoc_pin.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::dwoc_pin::ConfigViolation::CatalogKeyConflict { team, .. } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }
        if let Some(feature) = self.features.network_profiles.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::network_profiles::NetworkProfilesConfigViolation::CatalogKeyConflict {
                        team,
                        ..
                    } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }
        if let Some(feature) = self.features.image_policy.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::image_policy::ImagePolicyConfigViolation::CatalogKeyConflict {
                        team,
                        ..
                    } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }
        if let Some(feature) = self.features.kubearmor_policy.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::kubearmor_policy::KubeArmorPolicyConfigViolation::CatalogKeyConflict {
                        team,
                        ..
                    } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }
        if let Some(feature) = self.features.registry_config.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::registry_config::RegistryConfigViolation::CatalogKeyConflict {
                        team,
                        ..
                    } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }
        if let Some(feature) = self.features.endpoint_auth.as_mut() {
            for violation in feature.resolve(teams) {
                let message = violation.to_string();
                let team = match violation {
                    crate::endpoint_auth::EndpointAuthConfigViolation::CatalogKeyConflict {
                        team,
                        ..
                    } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
        }

        conflicts
    }
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
///
/// `camelCase` on the wire like every other type in this schema — it was missing the attribute
/// until 2026-08-25, which serialised `observedGeneration` as `observed_generation` and made
/// this one field disagree with both its parent and RFC 0002's own examples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
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
