//! `spec.features.networkProfiles` — the profile catalogue, the baseline, the grants, and the
//! reconcile-time validation rules over them. See RFC 0004's *Design → Contract*.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::namespace::NamespaceName;
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// A short identifier for a catalogue entry, unique within the catalogue. Never a
/// `{name, namespace}` pair — same rationale as `CatalogKey` in `dwoc_pin`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ProfileKey(String);

impl ProfileKey {
    /// Wrap a profile key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The policy dialect a variant, and the `ManagedObject` built from it, is written in. Concrete
/// and resolved — never `Auto`, which is [`EnforcementBackend`]'s job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Backend {
    /// `networking.k8s.io/v1`, `NetworkPolicy`.
    NetworkPolicy,
    /// `cilium.io/v2`, `CiliumNetworkPolicy`.
    Cilium,
}

/// `enforcement.backend`'s configuration value. `Auto` resolves to the most capable backend the
/// apiserver advertises — that resolution is an adapter's job, not this crate's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EnforcementBackend {
    /// Resolve to the most capable backend the cluster offers.
    #[default]
    Auto,
    /// Always write `NetworkPolicy`.
    NetworkPolicy,
    /// Always write `CiliumNetworkPolicy`.
    Cilium,
}

/// A `{name, namespace}` pair naming a real policy object an admin authored — a template, never
/// dereferenced into its rules by this crate. Deliberately not a reuse of `DwocRef`: same shape,
/// a different referent, same rationale RFC 0002 gives for `CatalogKey` being its own newtype
/// rather than a raw `String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct TemplateRef {
    /// The template object's name.
    pub name: String,
    /// The namespace it lives in.
    pub namespace: NamespaceName,
}

/// One backend's rendering of a profile. A profile carries at most one variant per backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Variant {
    /// Which dialect this variant is written in.
    pub backend: Backend,
    /// The template object this variant copies `policyTypes`/`ingress`/`egress` from.
    pub template_ref: TemplateRef,
}

/// One entry of `spec.features.networkProfiles.catalog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Profile {
    /// The short identifier a grant, an attribute, or a resolved decision names.
    pub key: ProfileKey,
    /// This profile's variants, at most one per [`Backend`].
    pub variants: Vec<Variant>,
}

impl Profile {
    /// This profile's variant for `backend`, if it has one.
    pub fn variant(&self, backend: Backend) -> Option<&Variant> {
        self.variants.iter().find(|v| v.backend == backend)
    }
}

/// Every profile a workspace may be granted, keyed by [`ProfileKey`]. Serializes as a plain
/// array — the wrapper exists for the accessor methods below, per Rust's orphan rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ProfileCatalog {
    entries: Vec<Profile>,
}

impl ProfileCatalog {
    /// Build a catalogue from its entries.
    pub fn new(entries: Vec<Profile>) -> Self {
        Self { entries }
    }

    /// Every entry, in configuration order.
    pub fn entries(&self) -> &[Profile] {
        &self.entries
    }

    /// The profile a key names, if the key is in the catalogue.
    pub fn profile(&self, key: &ProfileKey) -> Option<&Profile> {
        self.entries.iter().find(|entry| &entry.key == key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &ProfileKey) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }
}

/// What one team may reach: the set of profile keys it may reach, and the subset of them applied
/// when a workspace asks for nothing. Either may legitimately be empty — an ungranted team
/// reaches only the baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileGrant {
    /// The profile keys this team may reach.
    #[serde(default)]
    pub allowed: Vec<ProfileKey>,
    /// The subset of `allowed` applied when a workspace names nothing more specific.
    #[serde(default)]
    pub default: Vec<ProfileKey>,
}

/// What to do when a workspace names a profile key its team's grant does not allow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OnNotGranted {
    /// Drop the ungranted keys and apply the grant's default instead.
    #[default]
    Default,
    /// Refuse the request naming the ungranted key.
    Deny,
}

/// `spec.features.networkProfiles.namespaceSelection` — the namespace annotation naming a
/// comma-separated profile key list, read when the workspace attribute is not set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProfileNamespaceSelection {
    /// Namespace annotation naming a comma-separated profile key list. The empty string disables
    /// this selection step entirely.
    #[serde(default = "default_profile_annotation")]
    pub annotation: String,
}

fn default_profile_annotation() -> String {
    "hardening.weebo.io/network-profiles".to_string()
}

impl Default for ProfileNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_profile_annotation(),
        }
    }
}

/// `spec.features.networkProfiles.workspaceSelection` — the devfile attribute naming a
/// comma-separated profile key list, taking precedence over the namespace annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSelection {
    /// DevWorkspace attribute naming a comma-separated profile key list. The empty string
    /// disables this selection step entirely.
    #[serde(default = "default_workspace_attribute")]
    pub attribute: String,
}

fn default_workspace_attribute() -> String {
    "hardening.weebo.io/network-profiles".to_string()
}

impl Default for WorkspaceSelection {
    fn default() -> Self {
        Self {
            attribute: default_workspace_attribute(),
        }
    }
}

/// `enforcement.canary` — periodic proof the CNI enforces policy at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Canary {
    /// Whether the canary probe runs.
    pub enabled: bool,
    /// How often the probe runs.
    pub interval_seconds: u32,
}

impl Default for Canary {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 300,
        }
    }
}

/// `spec.features.networkProfiles.enforcement`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Enforcement {
    /// Which policy dialect to write.
    #[serde(default)]
    pub backend: EnforcementBackend,
    /// The periodic enforcement probe.
    #[serde(default)]
    pub canary: Canary,
}

/// `spec.features.networkProfiles` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProfilesConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the controller's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every profile a workspace may be granted.
    pub catalog: ProfileCatalog,
    /// The profile applied to every namespace in scope, never negotiable.
    pub baseline: ProfileKey,
    /// What each team may reach, keyed by team name.
    #[serde(default)]
    pub grants: BTreeMap<String, ProfileGrant>,
    /// The namespace annotation naming a profile key list.
    #[serde(default)]
    pub namespace_selection: ProfileNamespaceSelection,
    /// The devfile attribute naming a profile key list.
    #[serde(default)]
    pub workspace_selection: WorkspaceSelection,
    /// What to do when a workspace names a profile key its team's grant does not allow.
    #[serde(default)]
    pub on_not_granted: OnNotGranted,
    /// The enforcement backend and its canary.
    #[serde(default)]
    pub enforcement: Enforcement,
}

impl NetworkProfilesConfig {
    /// This team's grant, if `grants` has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&ProfileGrant> {
        self.grants.get(team.as_str())
    }
}

/// One way `spec.features.networkProfiles` can violate its own invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkProfilesConfigViolation {
    /// The same key appears twice in `catalog`.
    DuplicateProfileKey(ProfileKey),
    /// `baseline` names a key absent from `catalog`.
    BaselineNotInCatalog(ProfileKey),
    /// A catalogue entry carries no variant at all.
    ProfileHasNoVariants(ProfileKey),
    /// A catalogue entry carries two variants for the same backend.
    ProfileHasDuplicateBackend {
        /// The profile carrying the duplicate.
        profile: ProfileKey,
        /// The backend declared twice.
        backend: Backend,
    },
    /// A team's `default` names a key outside its own `allowed`.
    GrantDefaultOutsideAllowed {
        /// The team whose grant is malformed.
        team: TeamName,
        /// The default key that is outside `allowed`.
        key: ProfileKey,
    },
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team whose grant names the key.
        team: TeamName,
        /// The uncatalogued key.
        key: ProfileKey,
    },
    /// `grants` names a team `spec.teams` never declared.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for NetworkProfilesConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProfileKey(key) => write!(f, "profile key {key} is declared twice"),
            Self::BaselineNotInCatalog(key) => {
                write!(f, "baseline profile key {key} is not in the catalog")
            }
            Self::ProfileHasNoVariants(key) => {
                write!(f, "profile {key} has no variants")
            }
            Self::ProfileHasDuplicateBackend { profile, backend } => write!(
                f,
                "profile {profile} declares more than one variant for backend {backend:?}"
            ),
            Self::GrantDefaultOutsideAllowed { team, key } => write!(
                f,
                "grant for team {team} defaults to {key}, which is outside its own allowed set"
            ),
            Self::GrantAllowedUnknownKey { team, key } => {
                write!(f, "grant for team {team} allows uncatalogued key {key}")
            }
            Self::GrantNamesUndeclaredTeam(team) => {
                write!(
                    f,
                    "grant names team {team}, which spec.teams never declared"
                )
            }
        }
    }
}

impl NetworkProfilesConfig {
    /// Every violation this configuration has, if any. Returns all of them, not just the first —
    /// the reconcile loop reports one `Degraded` condition per violation.
    pub fn validate(&self, teams: &[Team]) -> Vec<NetworkProfilesConfigViolation> {
        let mut violations = Vec::new();

        let mut seen_keys = std::collections::HashSet::new();
        for entry in self.catalog.entries() {
            if !seen_keys.insert(&entry.key) {
                violations.push(NetworkProfilesConfigViolation::DuplicateProfileKey(
                    entry.key.clone(),
                ));
            }

            if entry.variants.is_empty() {
                violations.push(NetworkProfilesConfigViolation::ProfileHasNoVariants(
                    entry.key.clone(),
                ));
            }

            let mut seen_backends = std::collections::HashSet::new();
            for variant in &entry.variants {
                if !seen_backends.insert(variant.backend) {
                    violations.push(NetworkProfilesConfigViolation::ProfileHasDuplicateBackend {
                        profile: entry.key.clone(),
                        backend: variant.backend,
                    });
                }
            }
        }

        if !self.catalog.contains(&self.baseline) {
            violations.push(NetworkProfilesConfigViolation::BaselineNotInCatalog(
                self.baseline.clone(),
            ));
        }

        let declared_teams: std::collections::HashSet<&str> =
            teams.iter().map(|t| t.name.as_str()).collect();

        for (team_name, grant) in &self.grants {
            let team = TeamName::new(team_name.clone());
            if !declared_teams.contains(team_name.as_str()) {
                violations.push(NetworkProfilesConfigViolation::GrantNamesUndeclaredTeam(
                    team.clone(),
                ));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(NetworkProfilesConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            for key in &grant.default {
                if !grant.allowed.contains(key) {
                    violations.push(NetworkProfilesConfigViolation::GrantDefaultOutsideAllowed {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
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

    fn template(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn np_variant(name: &str) -> Variant {
        Variant {
            backend: Backend::NetworkPolicy,
            template_ref: template(name),
        }
    }

    fn clean_catalog() -> ProfileCatalog {
        ProfileCatalog::new(vec![
            Profile {
                key: ProfileKey::new("base"),
                variants: vec![np_variant("weebo-base")],
            },
            Profile {
                key: ProfileKey::new("git"),
                variants: vec![np_variant("weebo-git")],
            },
            Profile {
                key: ProfileKey::new("vault"),
                variants: vec![np_variant("weebo-vault")],
            },
        ])
    }

    fn config(
        catalog: ProfileCatalog,
        baseline: &str,
        grants: BTreeMap<String, ProfileGrant>,
    ) -> NetworkProfilesConfig {
        NetworkProfilesConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog,
            baseline: ProfileKey::new(baseline),
            grants,
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: Enforcement::default(),
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
            ProfileGrant {
                allowed: vec![ProfileKey::new("git"), ProfileKey::new("vault")],
                default: vec![ProfileKey::new("git")],
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn an_empty_grant_is_not_a_violation() {
        let teams = [team("team-2")];
        let mut grants = BTreeMap::new();
        grants.insert("team-2".to_string(), ProfileGrant::default());
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn duplicate_profile_keys_are_reported() {
        let catalog = ProfileCatalog::new(vec![
            Profile {
                key: ProfileKey::new("base"),
                variants: vec![np_variant("weebo-base")],
            },
            Profile {
                key: ProfileKey::new("base"),
                variants: vec![np_variant("other-base")],
            },
        ]);
        let cfg = config(catalog, "base", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&NetworkProfilesConfigViolation::DuplicateProfileKey(
                    ProfileKey::new("base")
                ))
        );
    }

    #[test]
    fn a_baseline_absent_from_the_catalog_is_reported() {
        let cfg = config(clean_catalog(), "missing", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&NetworkProfilesConfigViolation::BaselineNotInCatalog(
                    ProfileKey::new("missing")
                ))
        );
    }

    #[test]
    fn a_profile_with_no_variants_is_reported() {
        let catalog = ProfileCatalog::new(vec![Profile {
            key: ProfileKey::new("base"),
            variants: Vec::new(),
        }]);
        let cfg = config(catalog, "base", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&NetworkProfilesConfigViolation::ProfileHasNoVariants(
                    ProfileKey::new("base")
                ))
        );
    }

    #[test]
    fn a_profile_with_two_variants_for_the_same_backend_is_reported() {
        let catalog = ProfileCatalog::new(vec![Profile {
            key: ProfileKey::new("base"),
            variants: vec![np_variant("weebo-base"), np_variant("weebo-base-2")],
        }]);
        let cfg = config(catalog, "base", BTreeMap::new());
        assert!(cfg.validate(&[]).contains(
            &NetworkProfilesConfigViolation::ProfileHasDuplicateBackend {
                profile: ProfileKey::new("base"),
                backend: Backend::NetworkPolicy,
            }
        ));
    }

    #[test]
    fn a_grant_allowed_naming_an_uncatalogued_key_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("nope")],
                default: Vec::new(),
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).contains(
            &NetworkProfilesConfigViolation::GrantAllowedUnknownKey {
                team: TeamName::new("team-1"),
                key: ProfileKey::new("nope"),
            }
        ));
    }

    #[test]
    fn a_grant_default_outside_its_own_allowed_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git")],
                default: vec![ProfileKey::new("vault")],
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).contains(
            &NetworkProfilesConfigViolation::GrantDefaultOutsideAllowed {
                team: TeamName::new("team-1"),
                key: ProfileKey::new("vault"),
            }
        ));
    }

    #[test]
    fn a_grant_naming_a_team_nobody_declared_is_reported() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git")],
                default: vec![ProfileKey::new("git")],
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&[]).contains(
            &NetworkProfilesConfigViolation::GrantNamesUndeclaredTeam(TeamName::new("ghost-team"))
        ));
    }

    #[test]
    fn multiple_violations_are_all_reported_not_just_the_first() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("nowhere")],
                default: vec![ProfileKey::new("also-nowhere")],
            },
        );
        let cfg = config(clean_catalog(), "missing", grants);
        assert!(cfg.validate(&[]).len() >= 4);
    }

    #[test]
    fn variant_wire_shape_is_nested_not_flat() {
        let variant = np_variant("weebo-base");
        let json = serde_json::to_value(&variant).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "backend": "NetworkPolicy",
                "templateRef": {"name": "weebo-base", "namespace": "weebo-si-hardening"},
            })
        );
    }

    #[test]
    fn grant_wire_shape_matches_the_rfcs_example() {
        let grant = ProfileGrant {
            allowed: vec![ProfileKey::new("git"), ProfileKey::new("vault")],
            default: vec![ProfileKey::new("git")],
        };
        let json = serde_json::to_value(&grant).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"allowed": ["git", "vault"], "default": ["git"]})
        );
    }
}
