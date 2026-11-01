//! `spec.features.podSecurity` — which Pod Security Admission level each workspace namespace
//! gets, per team. See RFC 0013's *Design → Contract*.
//!
//! **No catalogue.** Every other feature in this CRD routes catalogue entries; this one routes one
//! of three upstream values, and a catalogue on top of three fixed values would be a layer of
//! indirection with nothing in it. A team therefore contributes a level, not entries, and
//! resolving teams can never conflict.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::resolved::Resolved;
use crate::selector::Selector;
use crate::team::{Team, TeamName, WeeboSiTeam, resolution_order};

/// A Pod Security Standards level.
///
/// **Lowercase on the wire, unlike every other enum in this CRD**, because these are upstream's
/// values: the same spelling goes into the `pod-security.kubernetes.io/enforce` label, and an
/// admin who writes `restricted` in a namespace label should not have to write `Restricted` here.
///
/// The variant order is the strictness order, `Privileged < Baseline < Restricted`, so `Ord`
/// answers "which is stricter" and [`Ord::max`] is "the stricter of the two".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum PodSecurityLevel {
    /// No restriction.
    Privileged,
    /// Refuses the known privilege escalations: host namespaces, `hostPath`, privileged
    /// containers, added capabilities beyond the default set, `Unconfined` seccomp.
    Baseline,
    /// `baseline`, plus non-root, no privilege escalation, every capability dropped, and an
    /// explicit seccomp profile.
    Restricted,
}

impl PodSecurityLevel {
    /// Every level, loosest first — for a metric that publishes one series per level.
    pub const ALL: [PodSecurityLevel; 3] = [Self::Privileged, Self::Baseline, Self::Restricted];

    /// The value as upstream spells it, in a label and in a metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Privileged => "privileged",
            Self::Baseline => "baseline",
            Self::Restricted => "restricted",
        }
    }

    /// Parse upstream's spelling. Exact and lowercase, as the apiserver reads it: a label
    /// `Restricted` is not a level the admission plugin recognises, so it is not one here either.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "privileged" => Some(Self::Privileged),
            "baseline" => Some(Self::Baseline),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }
}

impl fmt::Display for PodSecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The revision of the Pod Security Standards every `*-version` label pins: `latest` or `v1.N`.
///
/// Required with no default, per RFC 0013's *Pinning the version*: both answers are defensible
/// and the choice is the admin's. Kept as a string on the wire, checked by
/// [`ResolvedPodSecurityConfig::validate`], because the apiserver accepts exactly these two
/// shapes and anything else in the label makes it fall back to `latest` silently.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct PodSecurityVersion(String);

impl PodSecurityVersion {
    /// Wrap a version.
    pub fn new(version: impl Into<String>) -> Self {
        Self(version.into())
    }

    /// The wrapped value, as it goes into the label.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the apiserver reads this as a version rather than falling back to `latest`.
    pub fn is_well_formed(&self) -> bool {
        if self.0 == "latest" {
            return true;
        }
        let Some(minor) = self.0.strip_prefix("v1.") else {
            return false;
        };
        !minor.is_empty()
            && minor.bytes().all(|byte| byte.is_ascii_digit())
            && (minor == "0" || !minor.starts_with('0'))
    }
}

impl fmt::Display for PodSecurityVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `backend`'s configuration value: write the labels, or only compare them with OpenShift's
/// synced ones. `Auto` is resolved at startup by API discovery — an adapter's job.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PodSecurityBackend {
    /// `ObserveSynced` when the cluster serves `security.openshift.io/v1`, otherwise `Labels`.
    #[default]
    Auto,
    /// Write the six labels and the `-previous` annotation.
    Labels,
    /// Write nothing; compare the level OpenShift's label syncer set with the resolved one.
    ObserveSynced,
}

/// `spec.features.podSecurity.namespaceSelection` — the namespace annotation naming a level.
///
/// **It can only tighten.** A level in the annotation looser than the namespace's resolved one is
/// ignored, which is what makes it safe to leave writable by the namespace's own user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityNamespaceSelection {
    /// Namespace annotation naming a level. The empty string disables this step.
    #[serde(default = "default_pod_security_annotation")]
    pub annotation: String,
}

fn default_pod_security_annotation() -> String {
    "hardening.weebo.io/pod-security".to_string()
}

impl Default for PodSecurityNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_pod_security_annotation(),
        }
    }
}

fn default_ceiling() -> PodSecurityLevel {
    PodSecurityLevel::Baseline
}

/// `spec.features.podSecurity` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodSecurityConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the controller's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// The level of a namespace belonging to no team, or to a team that sets none. Required.
    pub default: PodSecurityLevel,
    /// The loosest level this feature will ever write. A team or default looser than this is
    /// clamped to it, and the clamp is reported.
    #[serde(default = "default_ceiling")]
    pub ceiling: PodSecurityLevel,
    /// Written to every `*-version` label. Required.
    pub version: PodSecurityVersion,
    /// Write the labels, or observe OpenShift's.
    #[serde(default)]
    pub backend: PodSecurityBackend,
    /// The tighten-only namespace annotation.
    #[serde(default)]
    pub namespace_selection: PodSecurityNamespaceSelection,
}

/// `spec.features.podSecurity` on a `WeeboSiTeam` — this team's levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamPodSecurity {
    /// This team's enforce level. Absent: the cluster `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<PodSecurityLevel>,
    /// The level written to `warn` and `audit`. Absent: this team's `level`. May only be stricter
    /// than or equal to `level`; a looser one is raised to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_level: Option<PodSecurityLevel>,
}

/// [`PodSecurityConfig`] resolved against the `WeeboSiTeam` objects. The grant of a team is its
/// own block, unchanged: there is no catalogue to merge.
pub type ResolvedPodSecurityConfig = Resolved<PodSecurityConfig, TeamPodSecurity>;

impl PodSecurityConfig {
    /// Collect every team's block, per RFC 0011.
    ///
    /// A team contributes a level, not catalogue keys, so two teams cannot conflict. What it can
    /// do is ask for more than the configuration allows, and those violations are returned here,
    /// each naming its team, so the team's own `status` carries them — the way every other
    /// feature's `resolve` returns the catalogue conflicts a team caused. The configuration-wide
    /// ones stay in [`ResolvedPodSecurityConfig::validate`].
    pub fn resolve(
        &self,
        teams: &[WeeboSiTeam],
    ) -> (ResolvedPodSecurityConfig, Vec<PodSecurityConfigViolation>) {
        let mut violations = Vec::new();
        let grants = resolution_order(teams)
            .into_iter()
            .filter_map(|team| {
                let block = team.spec.features.pod_security?;
                let name = team.team_name();
                if let Some(level) = block.level
                    && level < self.ceiling
                {
                    violations.push(PodSecurityConfigViolation::TeamLevelLooserThanCeiling {
                        team: name.clone(),
                        level,
                        ceiling: self.ceiling,
                    });
                }
                let level = block.level.unwrap_or(self.default);
                if let Some(warn_level) = block.warn_level
                    && warn_level < level
                {
                    violations.push(PodSecurityConfigViolation::TeamWarnLooserThanLevel {
                        team: name.clone(),
                        warn_level,
                        level,
                    });
                }
                Some((name.to_string(), block))
            })
            .collect();
        let resolved = Resolved {
            config: self.clone(),
            grants,
        };
        (resolved, violations)
    }
}

/// One way `spec.features.podSecurity` can violate its own invariants. Reported on the object as
/// `Degraded`; the feature keeps running, with every looser level clamped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodSecurityConfigViolation {
    /// `version` is neither `latest` nor `v1.N`.
    MalformedVersion(PodSecurityVersion),
    /// The cluster `default` is looser than `ceiling`, so every namespace with no team level is
    /// clamped.
    DefaultLooserThanCeiling {
        /// The configured default.
        default: PodSecurityLevel,
        /// The ceiling it is clamped to.
        ceiling: PodSecurityLevel,
    },
    /// A team asks for a level looser than `ceiling`. An admin wrote a level they cannot have.
    TeamLevelLooserThanCeiling {
        /// The team.
        team: TeamName,
        /// The level it asks for.
        level: PodSecurityLevel,
        /// The ceiling it is clamped to.
        ceiling: PodSecurityLevel,
    },
    /// A team's `warnLevel` is looser than the level it enforces, which would warn about less
    /// than is refused. It is raised to the enforce level.
    TeamWarnLooserThanLevel {
        /// The team.
        team: TeamName,
        /// The configured `warnLevel`.
        warn_level: PodSecurityLevel,
        /// The level it is raised to.
        level: PodSecurityLevel,
    },
    /// A grant names a team no `WeeboSiTeam` declares. Unreachable through the wire, kept so a
    /// resolution bug producing one is reported rather than silently dropped.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for PodSecurityConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedVersion(version) => write!(
                f,
                "version {version} is neither `latest` nor `v1.N`; the apiserver would read it as \
                 latest"
            ),
            Self::DefaultLooserThanCeiling { default, ceiling } => write!(
                f,
                "default level {default} is looser than the ceiling {ceiling}, and is clamped to it"
            ),
            Self::TeamLevelLooserThanCeiling {
                team,
                level,
                ceiling,
            } => write!(
                f,
                "team {team} asks for level {level}, looser than the ceiling {ceiling}, and is \
                 clamped to it"
            ),
            Self::TeamWarnLooserThanLevel {
                team,
                warn_level,
                level,
            } => write!(
                f,
                "team {team}'s warnLevel {warn_level} is looser than its level {level}, and is \
                 raised to it"
            ),
            Self::GrantNamesUndeclaredTeam(team) => {
                write!(f, "grant names team {team}, which no WeeboSiTeam declares")
            }
        }
    }
}

impl ResolvedPodSecurityConfig {
    /// This team's block, if it has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&TeamPodSecurity> {
        self.grants.get(team.as_str())
    }

    /// Every configuration-wide violation, not just the first. A team's own violations come out
    /// of [`PodSecurityConfig::resolve`].
    pub fn validate(&self, teams: &[Team]) -> Vec<PodSecurityConfigViolation> {
        let mut violations = Vec::new();

        if !self.version.is_well_formed() {
            violations.push(PodSecurityConfigViolation::MalformedVersion(
                self.version.clone(),
            ));
        }
        if self.default < self.ceiling {
            violations.push(PodSecurityConfigViolation::DefaultLooserThanCeiling {
                default: self.default,
                ceiling: self.ceiling,
            });
        }

        for team in self.grants.keys() {
            let team = TeamName::new(team.clone());
            if !teams.iter().any(|declared| declared.name == team) {
                violations.push(PodSecurityConfigViolation::GrantNamesUndeclaredTeam(team));
            }
        }

        violations
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
    use crate::team::{TeamFeatures, TeamIdentity, TeamWorkspace, WeeboSiTeamSpec, team_views};

    fn config() -> PodSecurityConfig {
        serde_json::from_value(serde_json::json!({
            "mode": "DryRun",
            "default": "restricted",
            "version": "v1.34",
        }))
        .unwrap()
    }

    fn team(name: &str, block: Option<TeamPodSecurity>) -> WeeboSiTeam {
        WeeboSiTeam::new(
            name,
            WeeboSiTeamSpec {
                display_name: None,
                priority: 100,
                namespace_selector: Selector::default(),
                features: TeamFeatures {
                    pod_security: block,
                    ..TeamFeatures::default()
                },
                identity: TeamIdentity::default(),
                workspace: TeamWorkspace::default(),
            },
        )
    }

    #[test]
    fn levels_are_ordered_by_strictness() {
        assert!(PodSecurityLevel::Privileged < PodSecurityLevel::Baseline);
        assert!(PodSecurityLevel::Baseline < PodSecurityLevel::Restricted);
        assert_eq!(
            PodSecurityLevel::Baseline.max(PodSecurityLevel::Restricted),
            PodSecurityLevel::Restricted
        );
    }

    #[test]
    fn levels_use_upstreams_spelling_on_the_wire_and_in_parse() {
        for level in PodSecurityLevel::ALL {
            assert_eq!(
                serde_json::to_value(level).unwrap(),
                serde_json::json!(level.as_str())
            );
            assert_eq!(PodSecurityLevel::parse(level.as_str()), Some(level));
        }
        assert_eq!(PodSecurityLevel::parse("Restricted"), None);
        assert_eq!(PodSecurityLevel::parse(""), None);
    }

    #[test]
    fn the_defaults_are_a_baseline_ceiling_auto_backend_and_the_documented_annotation() {
        let config = config();
        assert_eq!(config.ceiling, PodSecurityLevel::Baseline);
        assert_eq!(config.backend, PodSecurityBackend::Auto);
        assert_eq!(
            config.namespace_selection.annotation,
            "hardening.weebo.io/pod-security"
        );
    }

    #[test]
    fn default_and_version_are_required() {
        for missing in ["default", "version"] {
            let mut value = serde_json::json!({
                "mode": "DryRun", "default": "restricted", "version": "latest"
            });
            value.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<PodSecurityConfig>(value).is_err(),
                "{missing} must have no default"
            );
        }
    }

    #[test]
    fn only_latest_and_v1_n_are_well_formed_versions() {
        for good in ["latest", "v1.0", "v1.34", "v1.100"] {
            assert!(PodSecurityVersion::new(good).is_well_formed(), "{good}");
        }
        for bad in ["", "v1.34.0", "1.34", "v2.0", "v1.034", "Latest", "v1."] {
            assert!(!PodSecurityVersion::new(bad).is_well_formed(), "{bad}");
        }
    }

    #[test]
    fn resolve_collects_each_teams_block_and_nothing_for_a_team_without_one() {
        let teams = [
            team(
                "team-build",
                Some(TeamPodSecurity {
                    level: Some(PodSecurityLevel::Baseline),
                    warn_level: Some(PodSecurityLevel::Restricted),
                }),
            ),
            team("team-1", None),
        ];
        let (resolved, violations) = config().resolve(&teams);
        assert!(violations.is_empty());
        assert_eq!(
            resolved.grant_for(&TeamName::new("team-build")),
            Some(&TeamPodSecurity {
                level: Some(PodSecurityLevel::Baseline),
                warn_level: Some(PodSecurityLevel::Restricted),
            })
        );
        assert_eq!(resolved.grant_for(&TeamName::new("team-1")), None);
        assert!(resolved.validate(&team_views(&teams)).is_empty());
    }

    #[test]
    fn a_team_violation_is_reported_once_and_names_its_team() {
        let teams = [team(
            "loose",
            Some(TeamPodSecurity {
                level: Some(PodSecurityLevel::Privileged),
                warn_level: None,
            }),
        )];
        let spec = crate::spec::WeeboSiConfigSpec {
            features: crate::spec::Features {
                pod_security: Some(config()),
                ..crate::spec::Features::default()
            },
        };
        let (resolved, conflicts) = spec.resolve_teams(&teams);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].team, Some(TeamName::new("loose")));
        assert!(
            resolved
                .pod_security
                .unwrap()
                .validate(&team_views(&teams))
                .is_empty(),
            "validate must not report the team's violation a second time"
        );
    }

    #[test]
    fn validate_reports_every_looser_than_allowed_level() {
        let teams = [
            team(
                "loose",
                Some(TeamPodSecurity {
                    level: Some(PodSecurityLevel::Privileged),
                    warn_level: None,
                }),
            ),
            team(
                "backwards",
                Some(TeamPodSecurity {
                    level: Some(PodSecurityLevel::Restricted),
                    warn_level: Some(PodSecurityLevel::Baseline),
                }),
            ),
        ];
        let mut config = config();
        config.default = PodSecurityLevel::Privileged;
        config.version = PodSecurityVersion::new("1.34");
        let (resolved, team_violations) = config.resolve(&teams);
        let violations = resolved.validate(&team_views(&teams));

        assert!(
            violations.contains(&PodSecurityConfigViolation::MalformedVersion(
                PodSecurityVersion::new("1.34")
            ))
        );
        assert!(
            violations.contains(&PodSecurityConfigViolation::DefaultLooserThanCeiling {
                default: PodSecurityLevel::Privileged,
                ceiling: PodSecurityLevel::Baseline,
            })
        );
        assert_eq!(violations.len(), 2);
        assert!(team_violations.contains(
            &PodSecurityConfigViolation::TeamLevelLooserThanCeiling {
                team: TeamName::new("loose"),
                level: PodSecurityLevel::Privileged,
                ceiling: PodSecurityLevel::Baseline,
            }
        ));
        assert!(
            team_violations.contains(&PodSecurityConfigViolation::TeamWarnLooserThanLevel {
                team: TeamName::new("backwards"),
                warn_level: PodSecurityLevel::Baseline,
                level: PodSecurityLevel::Restricted,
            })
        );
        assert_eq!(team_violations.len(), 2);
    }

    #[test]
    fn a_ceiling_of_privileged_makes_every_level_legal() {
        let teams = [team(
            "loose",
            Some(TeamPodSecurity {
                level: Some(PodSecurityLevel::Privileged),
                warn_level: None,
            }),
        )];
        let mut config = config();
        config.ceiling = PodSecurityLevel::Privileged;
        let (resolved, team_violations) = config.resolve(&teams);
        assert!(team_violations.is_empty());
        assert!(resolved.validate(&team_views(&teams)).is_empty());
    }
}
