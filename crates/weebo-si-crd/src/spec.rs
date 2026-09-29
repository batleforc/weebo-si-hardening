//! `WeeboSiConfig` — cluster-scoped, singleton named `cluster`. See RFC 0002's *Contract*,
//! "The `WeeboSiConfig` CRD."

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc_pin::{DwocPinConfig, ResolvedDwocPinConfig};
use crate::endpoint_auth::{EndpointAuthConfig, ResolvedEndpointAuthConfig};
use crate::identity::IdentityConfig;
use crate::image_policy::{ImagePolicyConfig, ResolvedImagePolicyConfig};
use crate::kubearmor_policy::{KubeArmorPolicyConfig, ResolvedKubeArmorPolicyConfig};
use crate::network_profiles::{NetworkProfilesConfig, ResolvedNetworkProfilesConfig};
use crate::policy_guard::PolicyGuardConfig;
use crate::registry_config::{RegistryConfig, ResolvedRegistryConfig};
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

/// Every feature block of a `WeeboSiConfig`, resolved against the `WeeboSiTeam` objects — what
/// the features evaluate, as opposed to [`Features`], which is what an admin wrote.
///
/// Only [`WeeboSiConfigSpec::resolve_teams`] builds one from a spec, so a reader holding this
/// type cannot have skipped the merge. `policyGuard` and `identity` carry no team contribution
/// and pass through unchanged; they are here so a reader needs one value, not two.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedFeatures {
    /// `spec.features.dwocPin`, resolved.
    pub dwoc_pin: Option<ResolvedDwocPinConfig>,
    /// `spec.features.networkProfiles`, resolved.
    pub network_profiles: Option<ResolvedNetworkProfilesConfig>,
    /// `spec.features.policyGuard`, unchanged.
    pub policy_guard: Option<PolicyGuardConfig>,
    /// `spec.features.imagePolicy`, resolved.
    pub image_policy: Option<ResolvedImagePolicyConfig>,
    /// `spec.features.kubearmorPolicy`, resolved.
    pub kubearmor_policy: Option<ResolvedKubeArmorPolicyConfig>,
    /// `spec.features.registryConfig`, resolved.
    pub registry_config: Option<ResolvedRegistryConfig>,
    /// `spec.features.endpointAuth`, resolved.
    pub endpoint_auth: Option<ResolvedEndpointAuthConfig>,
    /// `spec.features.identity`, unchanged.
    pub identity: Option<IdentityConfig>,
}

impl WeeboSiConfigSpec {
    /// Merge the `WeeboSiTeam` objects into every feature's catalogue and derive every team's
    /// grants, per RFC 0011.
    ///
    /// Returns the resolved features, and one entry per conflict found for the reconcile loops'
    /// `Degraded` conditions. Resolving against no teams is legal and yields the cluster
    /// catalogues with no grants — every namespace on the cluster default, the fail-closed
    /// direction.
    pub fn resolve_teams(&self, teams: &[WeeboSiTeam]) -> (ResolvedFeatures, Vec<ResolveConflict>) {
        let mut conflicts = Vec::new();

        let dwoc_pin = self.features.dwoc_pin.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
                let message = violation.to_string();
                let team = match violation {
                    crate::dwoc_pin::ConfigViolation::CatalogKeyConflict { team, .. } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
            resolved
        });

        let network_profiles = self.features.network_profiles.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
                let message = violation.to_string();
                let team = match violation {
                    crate::network_profiles::NetworkProfilesConfigViolation::CatalogKeyConflict { team, .. } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
            resolved
        });

        let image_policy = self.features.image_policy.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
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
            resolved
        });

        let kubearmor_policy = self.features.kubearmor_policy.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
                let message = violation.to_string();
                let team = match violation {
                    crate::kubearmor_policy::KubeArmorPolicyConfigViolation::CatalogKeyConflict { team, .. } => Some(team),
                    _ => None,
                };
                conflicts.push(ResolveConflict { team, message });
            }
            resolved
        });

        let registry_config = self.features.registry_config.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
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
            resolved
        });

        let endpoint_auth = self.features.endpoint_auth.as_ref().map(|feature| {
            let (resolved, violations) = feature.resolve(teams);
            for violation in violations {
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
            resolved
        });

        let resolved = ResolvedFeatures {
            dwoc_pin,
            network_profiles,
            policy_guard: self.features.policy_guard.clone(),
            image_policy,
            kubearmor_policy,
            registry_config,
            endpoint_auth,
            identity: self.features.identity.clone(),
        };
        (resolved, conflicts)
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::dwoc::DwocRef;
    use crate::dwoc_pin::{
        Catalog, CatalogEntry, CatalogKey, Grant, NamespaceSelection, OnMissingTarget, TeamDwocPin,
    };
    use crate::feature_mode::FeatureMode;
    use crate::namespace::NamespaceName;
    use crate::resolved::Resolved;
    use crate::selector::Selector;
    use crate::team::{
        TeamFeatures, TeamIdentity, TeamName, TeamWorkspace, WeeboSiTeamSpec, team_views,
    };

    fn entry(key: &str, dwoc: &str) -> CatalogEntry {
        CatalogEntry {
            key: CatalogKey::new(key),
            target: DwocRef {
                name: dwoc.to_string(),
                namespace: NamespaceName::new("eclipse-che"),
            },
        }
    }

    fn spec() -> WeeboSiConfigSpec {
        WeeboSiConfigSpec {
            features: Features {
                dwoc_pin: Some(DwocPinConfig {
                    mode: FeatureMode::Enforce,
                    namespace_selector: None,
                    catalog: Catalog::new(vec![entry("baseline", "weebo-hardened-config")]),
                    default: CatalogKey::new("baseline"),
                    namespace_selection: NamespaceSelection::default(),
                    on_missing_target: OnMissingTarget::default(),
                }),
                ..Features::default()
            },
        }
    }

    fn team(name: &str, priority: i32, dwoc_pin: Option<TeamDwocPin>) -> WeeboSiTeam {
        WeeboSiTeam::new(
            name,
            WeeboSiTeamSpec {
                display_name: None,
                priority,
                namespace_selector: Selector::default(),
                features: TeamFeatures {
                    dwoc_pin,
                    ..TeamFeatures::default()
                },
                identity: TeamIdentity::default(),
                workspace: TeamWorkspace::default(),
            },
        )
    }

    fn gpu_block(dwoc: &str) -> Option<TeamDwocPin> {
        Some(TeamDwocPin {
            catalog: Catalog::new(vec![entry("gpu", dwoc)]),
            default: CatalogKey::new("gpu"),
        })
    }

    #[test]
    fn resolving_against_no_teams_is_the_cluster_configuration_with_no_grants() {
        let spec = spec();
        let (resolved, conflicts) = spec.resolve_teams(&[]);
        assert!(conflicts.is_empty());
        assert_eq!(
            resolved.dwoc_pin,
            spec.features.dwoc_pin.clone().map(Resolved::without_teams)
        );
    }

    #[test]
    fn a_team_block_adds_its_entries_and_a_grant_that_also_reaches_the_cluster_default() {
        let teams = [
            team("platform", 100, gpu_block("gpu-config")),
            team("research", 200, None),
        ];
        let (resolved, conflicts) = spec().resolve_teams(&teams);
        assert!(conflicts.is_empty());

        let dwoc_pin = resolved.dwoc_pin.unwrap();
        assert!(dwoc_pin.catalog.contains(&CatalogKey::new("baseline")));
        assert!(dwoc_pin.catalog.contains(&CatalogKey::new("gpu")));
        assert_eq!(
            dwoc_pin.grant_for(&TeamName::new("platform")),
            Some(&Grant {
                allowed: vec![CatalogKey::new("gpu"), CatalogKey::new("baseline")],
                default: CatalogKey::new("gpu"),
            })
        );
        // No block for the feature: no grant, so the cluster default applies unchanged.
        assert_eq!(dwoc_pin.grant_for(&TeamName::new("research")), None);
        assert!(dwoc_pin.validate(&team_views(&teams)).is_empty());
    }

    #[test]
    fn a_conflicting_redefinition_is_blamed_on_the_later_team_and_the_first_definition_wins() {
        let teams = [
            team("platform", 100, gpu_block("gpu-config")),
            team("research", 200, gpu_block("other-gpu-config")),
        ];
        let (resolved, conflicts) = spec().resolve_teams(&teams);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].team, Some(TeamName::new("research")));

        let dwoc_pin = resolved.dwoc_pin.unwrap();
        let gpu = dwoc_pin
            .catalog
            .entries()
            .iter()
            .find(|entry| entry.key == CatalogKey::new("gpu"))
            .unwrap();
        assert_eq!(gpu.target.name, "gpu-config");
        // The losing team still reaches the key — the reviewed definition, not nothing.
        assert!(
            dwoc_pin
                .grant_for(&TeamName::new("research"))
                .unwrap()
                .allowed
                .contains(&CatalogKey::new("gpu"))
        );
    }

    #[test]
    fn features_without_a_team_contribution_pass_through_unchanged() {
        let mut spec = spec();
        spec.features.identity =
            Some(serde_json::from_value(serde_json::json!({"mode": "DryRun"})).unwrap());
        let (resolved, _) = spec.resolve_teams(&[]);
        assert_eq!(resolved.identity, spec.features.identity);
        assert_eq!(resolved.policy_guard, None);
    }
}
