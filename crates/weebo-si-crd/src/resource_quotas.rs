//! `spec.features.resourceQuotas` — the catalogue of quota profiles, the grants over it, and the
//! configuration-level validation. See RFC 0014's *Design → Contract*.
//!
//! Shaped after [`crate::dwoc_pin`], not after `network_profiles`: a namespace resolves to
//! **exactly one** profile, because two `ResourceQuota`s in a namespace are both enforced and two
//! `LimitRange`s apply with no defined winner (RFC 0014's *One profile per namespace, not a set*).
//! So a grant is `{allowed, default}` with one default key, and a team's block is
//! `{catalog, default}`, as in `dwocPin`.
//!
//! What a profile's templates *say* — whether a compute quota has the defaults it needs — is
//! checked by the feature against the live templates, not here: this crate never reads a cluster.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::merge::merge_catalogs;
use crate::network_profiles::{OnNotGranted, TemplateRef};
use crate::resolved::Resolved;
use crate::selector::Selector;
use crate::team::{Team, TeamName, WeeboSiTeam, resolution_order};

/// A quota profile's key: what a grant, the namespace annotation and the
/// `hardening.weebo.io/profile` label on the written objects name. A newtype so a quota profile
/// key cannot be passed where a network profile key is expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct QuotaProfileKey(String);

impl QuotaProfileKey {
    /// Wrap a profile key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the key can be a label value: 1–63 characters, alphanumerics, `-`, `_` and `.`,
    /// starting and ending with an alphanumeric. It is written as `hardening.weebo.io/profile`.
    pub fn is_label_value(&self) -> bool {
        let bytes = self.0.as_bytes();
        let edge = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_alphanumeric);
        !bytes.is_empty()
            && bytes.len() <= 63
            && edge(bytes.first())
            && edge(bytes.last())
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    }
}

impl fmt::Display for QuotaProfileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One profile: at most one `ResourceQuota` template and at most one `LimitRange` template, at
/// least one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QuotaProfile {
    /// The key a grant or the namespace annotation names.
    pub key: QuotaProfileKey,
    /// The `ResourceQuota` whose `spec` is copied as `weebo-quota`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_ref: Option<TemplateRef>,
    /// The `LimitRange` whose `spec` is copied as `weebo-limits`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_range_ref: Option<TemplateRef>,
}

/// Every profile a namespace may be granted. Serializes as a plain array.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct QuotaCatalog {
    entries: Vec<QuotaProfile>,
}

impl QuotaCatalog {
    /// Build a catalogue from its profiles.
    pub fn new(entries: Vec<QuotaProfile>) -> Self {
        Self { entries }
    }

    /// Every profile, in configuration order.
    pub fn entries(&self) -> &[QuotaProfile] {
        &self.entries
    }

    /// The profile a key names.
    pub fn profile(&self, key: &QuotaProfileKey) -> Option<&QuotaProfile> {
        self.entries.iter().find(|entry| &entry.key == key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &QuotaProfileKey) -> bool {
        self.profile(key).is_some()
    }
}

/// What one team may reach: its own profiles plus the cluster `default`, and the one a namespace
/// naming nothing gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuotaGrant {
    /// The profiles this team may reach.
    pub allowed: Vec<QuotaProfileKey>,
    /// The one among `allowed` a namespace naming nothing gets.
    pub default: QuotaProfileKey,
}

/// `spec.features.resourceQuotas` on a `WeeboSiTeam` — this team's profiles and its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TeamResourceQuotas {
    /// This team's profiles, merged into the cluster catalogue at resolution.
    #[serde(default)]
    pub catalog: QuotaCatalog,
    /// The profile a namespace of this team gets when it names none.
    pub default: QuotaProfileKey,
}

/// `spec.features.resourceQuotas.namespaceSelection` — the namespace annotation naming one
/// profile key among those the namespace's team is granted.
///
/// **Not narrowing-only**, unlike RFC 0013's: a quota profile is not ordered ("large" has more
/// CPU and maybe fewer pods). What bounds it is the grant, and every change of its value is
/// counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QuotaNamespaceSelection {
    /// Namespace annotation naming a profile key. The empty string disables this step.
    #[serde(default = "default_quota_annotation")]
    pub annotation: String,
}

fn default_quota_annotation() -> String {
    "hardening.weebo.io/resource-quota".to_string()
}

impl Default for QuotaNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_quota_annotation(),
        }
    }
}

/// `spec.features.resourceQuotas` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceQuotasConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the controller's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every profile a namespace may be granted.
    pub catalog: QuotaCatalog,
    /// The profile of a namespace belonging to no team.
    pub default: QuotaProfileKey,
    /// The namespace annotation naming a profile key.
    #[serde(default)]
    pub namespace_selection: QuotaNamespaceSelection,
    /// What a namespace naming a key its team lacks gets: the team default, or no change.
    #[serde(default)]
    pub on_not_granted: OnNotGranted,
}

/// [`ResourceQuotasConfig`] resolved against the `WeeboSiTeam` objects.
pub type ResolvedResourceQuotasConfig = Resolved<ResourceQuotasConfig, QuotaGrant>;

impl ResourceQuotasConfig {
    /// Merge every team's catalogue into this configuration and derive each team's grant, per
    /// RFC 0011. A team reaches its own profiles plus the cluster `default`, as in `dwocPin`.
    pub fn resolve(
        &self,
        teams: &[WeeboSiTeam],
    ) -> (
        ResolvedResourceQuotasConfig,
        Vec<ResourceQuotasConfigViolation>,
    ) {
        let blocks: Vec<(TeamName, Vec<QuotaProfile>)> = resolution_order(teams)
            .into_iter()
            .filter_map(|team| {
                team.spec
                    .features
                    .resource_quotas
                    .as_ref()
                    .map(|block| (team.team_name(), block.catalog.entries().to_vec()))
            })
            .collect();
        let (entries, conflicts) =
            merge_catalogs(self.catalog.entries(), &blocks, |entry| entry.key.clone());
        let mut config = self.clone();
        config.catalog = QuotaCatalog::new(entries);

        let grants = resolution_order(teams)
            .into_iter()
            .filter_map(|team| {
                let block = team.spec.features.resource_quotas.as_ref()?;
                let mut allowed: Vec<QuotaProfileKey> = block
                    .catalog
                    .entries()
                    .iter()
                    .map(|entry| entry.key.clone())
                    .collect();
                if !allowed.contains(&self.default) {
                    allowed.push(self.default.clone());
                }
                Some((
                    team.team_name().to_string(),
                    QuotaGrant {
                        allowed,
                        default: block.default.clone(),
                    },
                ))
            })
            .collect();

        let violations = conflicts
            .into_iter()
            .map(
                |conflict| ResourceQuotasConfigViolation::CatalogKeyConflict {
                    team: conflict.team,
                    key: conflict.key,
                },
            )
            .collect();
        (Resolved { config, grants }, violations)
    }
}

/// One way `spec.features.resourceQuotas` can violate its own invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceQuotasConfigViolation {
    /// The catalogue is empty: there is nothing to apply, not even the `default`.
    EmptyCatalog,
    /// The same key appears twice in `catalog`.
    DuplicateProfileKey(QuotaProfileKey),
    /// A key cannot be the `hardening.weebo.io/profile` label value it is written as.
    InvalidProfileKey(QuotaProfileKey),
    /// A profile names neither a `ResourceQuota` nor a `LimitRange`.
    ProfileHasNoTemplate(QuotaProfileKey),
    /// `default` names a key absent from `catalog`.
    DefaultNotInCatalog(QuotaProfileKey),
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team.
        team: TeamName,
        /// The uncatalogued key.
        key: QuotaProfileKey,
    },
    /// A team's `default` is not one it may reach.
    GrantDefaultOutsideAllowed {
        /// The team.
        team: TeamName,
        /// Its default.
        default: QuotaProfileKey,
    },
    /// A grant names a team no `WeeboSiTeam` declares. Unreachable through the wire, kept so a
    /// resolution bug producing one is reported.
    GrantNamesUndeclaredTeam(TeamName),
    /// A team redefined a profile key somebody already defined, differently. The first definition
    /// stands; this team reaches it instead of its own.
    CatalogKeyConflict {
        /// The team whose profile lost.
        team: TeamName,
        /// The contested key.
        key: QuotaProfileKey,
    },
}

impl fmt::Display for ResourceQuotasConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCatalog => f.write_str("the quota profile catalogue is empty"),
            Self::DuplicateProfileKey(key) => write!(f, "quota profile {key} is declared twice"),
            Self::InvalidProfileKey(key) => write!(
                f,
                "quota profile key {key:?} cannot be a label value (1-63 alphanumerics, '-', '_' \
                 or '.')"
            ),
            Self::ProfileHasNoTemplate(key) => write!(
                f,
                "quota profile {key} names neither a quotaRef nor a limitRangeRef"
            ),
            Self::DefaultNotInCatalog(key) => {
                write!(f, "default quota profile {key} is not in the catalog")
            }
            Self::GrantAllowedUnknownKey { team, key } => {
                write!(
                    f,
                    "grant for team {team} allows uncatalogued quota profile {key}"
                )
            }
            Self::GrantDefaultOutsideAllowed { team, default } => write!(
                f,
                "team {team} defaults to quota profile {default}, which it does not reach"
            ),
            Self::GrantNamesUndeclaredTeam(team) => {
                write!(f, "grant names team {team}, which no WeeboSiTeam declares")
            }
            Self::CatalogKeyConflict { team, key } => write!(
                f,
                "team {team} redefines quota profile {key}, which is already defined differently"
            ),
        }
    }
}

impl ResolvedResourceQuotasConfig {
    /// This team's grant, if it has a block.
    pub fn grant_for(&self, team: &TeamName) -> Option<&QuotaGrant> {
        self.grants.get(team.as_str())
    }

    /// Every violation, not just the first.
    pub fn validate(&self, teams: &[Team]) -> Vec<ResourceQuotasConfigViolation> {
        let mut violations = Vec::new();
        if self.catalog.entries().is_empty() {
            violations.push(ResourceQuotasConfigViolation::EmptyCatalog);
        }

        let mut seen = std::collections::HashSet::new();
        for profile in self.catalog.entries() {
            if !seen.insert(&profile.key) {
                violations.push(ResourceQuotasConfigViolation::DuplicateProfileKey(
                    profile.key.clone(),
                ));
            }
            if !profile.key.is_label_value() {
                violations.push(ResourceQuotasConfigViolation::InvalidProfileKey(
                    profile.key.clone(),
                ));
            }
            if profile.quota_ref.is_none() && profile.limit_range_ref.is_none() {
                violations.push(ResourceQuotasConfigViolation::ProfileHasNoTemplate(
                    profile.key.clone(),
                ));
            }
        }
        if !self.catalog.contains(&self.default) {
            violations.push(ResourceQuotasConfigViolation::DefaultNotInCatalog(
                self.default.clone(),
            ));
        }

        for (team, grant) in &self.grants {
            let team = TeamName::new(team.clone());
            if !teams.iter().any(|declared| declared.name == team) {
                violations.push(ResourceQuotasConfigViolation::GrantNamesUndeclaredTeam(
                    team.clone(),
                ));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(ResourceQuotasConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            if !grant.allowed.contains(&grant.default) {
                violations.push(ResourceQuotasConfigViolation::GrantDefaultOutsideAllowed {
                    team,
                    default: grant.default.clone(),
                });
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
    use crate::namespace::NamespaceName;
    use crate::team::{TeamFeatures, TeamIdentity, TeamWorkspace, WeeboSiTeamSpec, team_views};

    fn template(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening-templates"),
        }
    }

    fn profile(key: &str) -> QuotaProfile {
        QuotaProfile {
            key: QuotaProfileKey::new(key),
            quota_ref: Some(template(&format!("quota-{key}"))),
            limit_range_ref: Some(template("limits-standard")),
        }
    }

    fn config() -> ResourceQuotasConfig {
        ResourceQuotasConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: QuotaCatalog::new(vec![profile("standard")]),
            default: QuotaProfileKey::new("standard"),
            namespace_selection: QuotaNamespaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
        }
    }

    fn team(name: &str, block: Option<TeamResourceQuotas>) -> WeeboSiTeam {
        WeeboSiTeam::new(
            name,
            WeeboSiTeamSpec {
                display_name: None,
                priority: 100,
                namespace_selector: Selector::default(),
                features: TeamFeatures {
                    resource_quotas: block,
                    ..TeamFeatures::default()
                },
                identity: TeamIdentity::default(),
                workspace: TeamWorkspace::default(),
            },
        )
    }

    #[test]
    fn the_wire_shape_is_the_rfcs() {
        let config: ResourceQuotasConfig = serde_json::from_value(serde_json::json!({
            "mode": "DryRun",
            "catalog": [{
                "key": "standard",
                "quotaRef": {"name": "quota-standard", "namespace": "weebo-si-hardening-templates"},
                "limitRangeRef": {"name": "limits-standard", "namespace": "weebo-si-hardening-templates"},
            }],
            "default": "standard",
        }))
        .unwrap();
        assert_eq!(config, self::config());
        assert_eq!(
            config.namespace_selection.annotation,
            "hardening.weebo.io/resource-quota"
        );
    }

    #[test]
    fn a_team_reaches_its_own_profiles_and_the_cluster_default() {
        let teams = [team(
            "team-data",
            Some(TeamResourceQuotas {
                catalog: QuotaCatalog::new(vec![profile("large")]),
                default: QuotaProfileKey::new("large"),
            }),
        )];
        let (resolved, conflicts) = config().resolve(&teams);
        assert!(conflicts.is_empty());
        assert_eq!(
            resolved.grant_for(&TeamName::new("team-data")),
            Some(&QuotaGrant {
                allowed: vec![
                    QuotaProfileKey::new("large"),
                    QuotaProfileKey::new("standard")
                ],
                default: QuotaProfileKey::new("large"),
            })
        );
        assert!(resolved.catalog.contains(&QuotaProfileKey::new("large")));
        assert!(resolved.validate(&team_views(&teams)).is_empty());
    }

    #[test]
    fn a_redefined_key_is_a_conflict_and_the_first_definition_stands() {
        let mut other = profile("standard");
        other.quota_ref = Some(template("quota-huge"));
        let teams = [team(
            "greedy",
            Some(TeamResourceQuotas {
                catalog: QuotaCatalog::new(vec![other]),
                default: QuotaProfileKey::new("standard"),
            }),
        )];
        let (resolved, conflicts) = config().resolve(&teams);
        assert_eq!(
            conflicts,
            vec![ResourceQuotasConfigViolation::CatalogKeyConflict {
                team: TeamName::new("greedy"),
                key: QuotaProfileKey::new("standard"),
            }]
        );
        assert_eq!(
            resolved
                .catalog
                .profile(&QuotaProfileKey::new("standard"))
                .unwrap()
                .quota_ref,
            Some(template("quota-standard"))
        );
    }

    #[test]
    fn validate_reports_every_malformed_profile() {
        let mut config = config();
        config.catalog = QuotaCatalog::new(vec![
            profile("standard"),
            profile("standard"),
            QuotaProfile {
                key: QuotaProfileKey::new("empty"),
                quota_ref: None,
                limit_range_ref: None,
            },
            profile("-bad key"),
        ]);
        config.default = QuotaProfileKey::new("missing");
        let violations = Resolved::without_teams(config).validate(&[]);
        for expected in [
            ResourceQuotasConfigViolation::DuplicateProfileKey(QuotaProfileKey::new("standard")),
            ResourceQuotasConfigViolation::ProfileHasNoTemplate(QuotaProfileKey::new("empty")),
            ResourceQuotasConfigViolation::InvalidProfileKey(QuotaProfileKey::new("-bad key")),
            ResourceQuotasConfigViolation::DefaultNotInCatalog(QuotaProfileKey::new("missing")),
        ] {
            assert!(
                violations.contains(&expected),
                "{expected:?} in {violations:?}"
            );
        }
    }

    #[test]
    fn an_empty_catalogue_is_reported() {
        let mut config = config();
        config.catalog = QuotaCatalog::default();
        let violations = Resolved::without_teams(config).validate(&[]);
        assert!(violations.contains(&ResourceQuotasConfigViolation::EmptyCatalog));
    }

    #[test]
    fn a_team_default_it_cannot_reach_is_reported() {
        let teams = [team(
            "lost",
            Some(TeamResourceQuotas {
                catalog: QuotaCatalog::default(),
                default: QuotaProfileKey::new("large"),
            }),
        )];
        let (resolved, _) = config().resolve(&teams);
        assert!(resolved.validate(&team_views(&teams)).contains(
            &ResourceQuotasConfigViolation::GrantDefaultOutsideAllowed {
                team: TeamName::new("lost"),
                default: QuotaProfileKey::new("large"),
            }
        ));
    }

    #[test]
    fn profile_keys_must_be_label_values() {
        for good in ["standard", "large-2", "a", "x.y_z"] {
            assert!(QuotaProfileKey::new(good).is_label_value(), "{good}");
        }
        for bad in ["", "-a", "a-", "a b", "a/b", &"a".repeat(64)] {
            assert!(!QuotaProfileKey::new(bad).is_label_value(), "{bad}");
        }
    }
}
