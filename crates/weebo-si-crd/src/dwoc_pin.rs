//! `spec.features.dwocPin` — the catalogue, the grants, and the reconcile-time validation rules
//! over them. See RFC 0002's *Feature: `dwoc-pin`*.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc::DwocRef;
use crate::feature_mode::FeatureMode;
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// A short identifier for a catalogue entry, unique within the catalogue. Never a
/// `{name, namespace}` pair — see RFC 0002's *Why keys rather than references*.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct CatalogKey(String);

impl CatalogKey {
    /// Wrap a catalogue key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CatalogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One entry of `spec.features.dwocPin.catalog`. Serializes flat, as `{key, name, namespace}`
/// per the RFC's own examples — not `{key, target: {name, namespace}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CatalogEntry {
    /// The short identifier a grant, an annotation, or a resolved decision names.
    pub key: CatalogKey,
    /// The DWOC this key points at.
    #[serde(flatten)]
    pub target: DwocRef,
}

/// Every DWOC a workspace is permitted to run with, keyed by [`CatalogKey`]. Serializes as a
/// plain array — the wrapper exists for the accessor methods below, per Rust's orphan rule
/// (only the crate defining `Catalog` may write an inherent `impl` for it).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Catalog {
    entries: Vec<CatalogEntry>,
}

impl Catalog {
    /// Build a catalogue from its entries.
    pub fn new(entries: Vec<CatalogEntry>) -> Self {
        Self { entries }
    }

    /// Every entry, in configuration order.
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// The target a key names, if the key is in the catalogue.
    pub fn target(&self, key: &CatalogKey) -> Option<&DwocRef> {
        self.entries
            .iter()
            .find(|entry| &entry.key == key)
            .map(|entry| &entry.target)
    }

    /// The key naming a target, if that target is in the catalogue.
    pub fn resolve_ref(&self, target: &DwocRef) -> Option<&CatalogKey> {
        self.entries
            .iter()
            .find(|entry| &entry.target == target)
            .map(|entry| &entry.key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &CatalogKey) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }
}

/// What one team may reach: a non-empty set of catalogue keys, and the one among them a
/// namespace with no more specific answer gets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Grant {
    /// The catalogue keys this team may reach.
    pub allowed: Vec<CatalogKey>,
    /// The one among `allowed` a namespace with no more specific answer gets.
    pub default: CatalogKey,
}

/// What to do when the namespace annotation names a key outside the reachable grant — a key
/// nobody catalogued, or a key the team is not granted; the two are indistinguishable to
/// whoever wrote the annotation and are therefore treated identically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OnUnknownKey {
    /// Fall through to the grant's default, and flag the offending value.
    #[default]
    Default,
    /// Refuse the admission.
    Deny,
}

/// What to do when the resolved catalogue entry does not point at a live DWOC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OnMissingTarget {
    /// Make no patch; the workspace proceeds with whatever it asked for.
    #[default]
    Skip,
    /// Deny the admission.
    Deny,
}

/// `spec.features.dwocPin.namespaceSelection` — the namespace annotation naming a catalogue key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceSelection {
    /// Namespace annotation naming a catalogue key. The empty string disables namespace
    /// selection entirely.
    #[serde(default = "default_annotation")]
    pub annotation: String,
    /// What to do when that annotation names a key the namespace cannot reach.
    #[serde(default)]
    pub on_unknown_key: OnUnknownKey,
}

fn default_annotation() -> String {
    "hardening.weebo.io/dwoc".to_string()
}

impl Default for NamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_annotation(),
            on_unknown_key: OnUnknownKey::default(),
        }
    }
}

/// `spec.features.dwocPin` in full.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DwocPinConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhook's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every DWOC a workspace is permitted to run with.
    pub catalog: Catalog,
    /// The entry for a namespace belonging to no team.
    pub default: CatalogKey,
    /// What each team may reach, keyed by team name.
    #[serde(default)]
    pub grants: BTreeMap<String, Grant>,
    /// The namespace annotation naming a catalogue key.
    #[serde(default)]
    pub namespace_selection: NamespaceSelection,
    /// What to do when the resolved entry does not point at a live DWOC.
    #[serde(default)]
    pub on_missing_target: OnMissingTarget,
}

impl DwocPinConfig {
    /// This team's grant, if `grants` has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&Grant> {
        self.grants.get(team.as_str())
    }
}

/// One way `spec.features.dwocPin` can violate its own invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigViolation {
    /// The same key appears twice in `catalog`.
    DuplicateCatalogKey(CatalogKey),
    /// `default` names a key absent from `catalog`.
    DefaultNotInCatalog(CatalogKey),
    /// A team's `allowed` is empty.
    GrantAllowedEmpty(TeamName),
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team whose grant names the key.
        team: TeamName,
        /// The uncatalogued key.
        key: CatalogKey,
    },
    /// A team's `default` is not inside its own `allowed`.
    GrantDefaultOutsideAllowed {
        /// The team whose grant is malformed.
        team: TeamName,
        /// The default that is outside `allowed`.
        default: CatalogKey,
    },
    /// `grants` names a team `spec.teams` never declared.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for ConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCatalogKey(key) => write!(f, "catalogue key {key} is declared twice"),
            Self::DefaultNotInCatalog(key) => {
                write!(f, "default catalogue key {key} is not in the catalog")
            }
            Self::GrantAllowedEmpty(team) => {
                write!(f, "grant for team {team} has an empty allowed set")
            }
            Self::GrantAllowedUnknownKey { team, key } => {
                write!(f, "grant for team {team} allows uncatalogued key {key}")
            }
            Self::GrantDefaultOutsideAllowed { team, default } => write!(
                f,
                "grant for team {team} defaults to {default}, which is outside its own allowed set"
            ),
            Self::GrantNamesUndeclaredTeam(team) => {
                write!(
                    f,
                    "grant names team {team}, which spec.teams never declared"
                )
            }
        }
    }
}

impl DwocPinConfig {
    /// Every violation this configuration has, if any, per RFC 0002's *Validating the
    /// configuration itself belongs to the controller*. Returns all of them, not just the
    /// first — the reconcile loop reports one `Degraded` condition per violation.
    pub fn validate(&self, teams: &[Team]) -> Vec<ConfigViolation> {
        let mut violations = Vec::new();

        let mut seen_keys = std::collections::HashSet::new();
        for entry in self.catalog.entries() {
            if !seen_keys.insert(&entry.key) {
                violations.push(ConfigViolation::DuplicateCatalogKey(entry.key.clone()));
            }
        }

        if !self.catalog.contains(&self.default) {
            violations.push(ConfigViolation::DefaultNotInCatalog(self.default.clone()));
        }

        let declared_teams: std::collections::HashSet<&str> =
            teams.iter().map(|t| t.name.as_str()).collect();

        for (team_name, grant) in &self.grants {
            let team = TeamName::new(team_name.clone());
            if !declared_teams.contains(team_name.as_str()) {
                violations.push(ConfigViolation::GrantNamesUndeclaredTeam(team.clone()));
            }
            if grant.allowed.is_empty() {
                violations.push(ConfigViolation::GrantAllowedEmpty(team.clone()));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(ConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            if !grant.allowed.contains(&grant.default) {
                violations.push(ConfigViolation::GrantDefaultOutsideAllowed {
                    team: team.clone(),
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

    fn dwoc(name: &str) -> DwocRef {
        DwocRef {
            name: name.to_string(),
            namespace: NamespaceName::new("eclipse-che"),
        }
    }

    fn clean_catalog() -> Catalog {
        Catalog::new(vec![
            CatalogEntry {
                key: CatalogKey::new("baseline"),
                target: dwoc("weebo-hardened-config"),
            },
            CatalogEntry {
                key: CatalogKey::new("gpu"),
                target: dwoc("gpu-config"),
            },
        ])
    }

    fn config(catalog: Catalog, default: &str, grants: BTreeMap<String, Grant>) -> DwocPinConfig {
        DwocPinConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog,
            default: CatalogKey::new(default),
            grants,
            namespace_selection: NamespaceSelection::default(),
            on_missing_target: OnMissingTarget::default(),
        }
    }

    fn team(name: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector::default(),
        }
    }

    #[test]
    fn a_well_formed_configuration_produces_no_violations() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu")],
                default: CatalogKey::new("gpu"),
            },
        );
        let cfg = config(clean_catalog(), "baseline", grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn duplicate_catalog_keys_are_reported() {
        let catalog = Catalog::new(vec![
            CatalogEntry {
                key: CatalogKey::new("baseline"),
                target: dwoc("weebo-hardened-config"),
            },
            CatalogEntry {
                key: CatalogKey::new("baseline"),
                target: dwoc("other-config"),
            },
        ]);
        let cfg = config(catalog, "baseline", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ConfigViolation::DuplicateCatalogKey(CatalogKey::new(
                    "baseline"
                )))
        );
    }

    #[test]
    fn a_default_absent_from_the_catalog_is_reported() {
        let cfg = config(clean_catalog(), "missing", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ConfigViolation::DefaultNotInCatalog(CatalogKey::new(
                    "missing"
                )))
        );
    }

    #[test]
    fn a_grant_with_an_empty_allowed_set_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: Vec::new(),
                default: CatalogKey::new("gpu"),
            },
        );
        let cfg = config(clean_catalog(), "baseline", grants);
        assert!(
            cfg.validate(&teams)
                .contains(&ConfigViolation::GrantAllowedEmpty(TeamName::new("team-1")))
        );
    }

    #[test]
    fn a_grant_allowed_naming_an_uncatalogued_key_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("amd")],
                default: CatalogKey::new("amd"),
            },
        );
        let cfg = config(clean_catalog(), "baseline", grants);
        assert!(
            cfg.validate(&teams)
                .contains(&ConfigViolation::GrantAllowedUnknownKey {
                    team: TeamName::new("team-1"),
                    key: CatalogKey::new("amd"),
                })
        );
    }

    #[test]
    fn a_grant_default_outside_its_own_allowed_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config(clean_catalog(), "baseline", grants);
        assert!(
            cfg.validate(&teams)
                .contains(&ConfigViolation::GrantDefaultOutsideAllowed {
                    team: TeamName::new("team-1"),
                    default: CatalogKey::new("baseline"),
                })
        );
    }

    #[test]
    fn a_grant_naming_a_team_nobody_declared_is_reported() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu")],
                default: CatalogKey::new("gpu"),
            },
        );
        let cfg = config(clean_catalog(), "baseline", grants);
        assert!(
            cfg.validate(&[])
                .contains(&ConfigViolation::GrantNamesUndeclaredTeam(TeamName::new(
                    "ghost-team"
                )))
        );
    }

    #[test]
    fn multiple_violations_are_all_reported_not_just_the_first() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            Grant {
                allowed: Vec::new(),
                default: CatalogKey::new("nowhere"),
            },
        );
        let cfg = config(clean_catalog(), "missing", grants);
        assert!(cfg.validate(&[]).len() >= 4);
    }

    #[test]
    fn catalog_entry_wire_shape_is_flat() {
        let entry = CatalogEntry {
            key: CatalogKey::new("baseline"),
            target: dwoc("weebo-hardened-config"),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"})
        );
    }
}
