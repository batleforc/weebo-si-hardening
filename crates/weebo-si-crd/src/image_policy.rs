//! `spec.features.imagePolicy` — the entry catalogue, the declared variables, the grants, and
//! the reconcile-time validation rules over them. See RFC 0005's *Design → Contract*.
//!
//! **This module deliberately holds no pattern parser.** RFC 0005's *Architecture* puts
//! `pattern.rs` in `weebo-si-image-policy` and calls it "the whole security surface"; this crate
//! is `weebo-si-image-policy`'s *dependency*, so it cannot call into it. The split that falls
//! out is the one the dependency direction forces and it is worth naming rather than
//! discovering: [`ImagePolicyConfig::validate`] reports every violation that is *structural* —
//! duplicate keys, unknown keys, a grant defaulting outside its own `allowed`, a variable name
//! outside its charset — and `weebo_si_image_policy::validate` calls it and appends the ones
//! that need a parsed pattern (unparseable, undeclared variable, illegal team name, a top-level
//! `default` entry that can only ever interpolate to nothing). Both produce the same
//! [`ImagePolicyConfigViolation`], which lives here so neither half owns a private vocabulary.
//! Callers want the second function; the first exists because this crate can prove half the
//! contract on its own.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::dwoc_pin::OnUnknownKey;
use crate::feature_mode::FeatureMode;
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// A short identifier for a catalogue entry, unique within the catalogue. Same rationale as
/// `CatalogKey` in `dwoc_pin` and `ProfileKey` in `network_profiles`: a key is never a
/// `{name, namespace}` pair, and never a bare `String` a team name could be passed as.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct EntryKey(String);

impl EntryKey {
    /// Wrap an entry key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One entry of `spec.features.imagePolicy.catalog`: a key, and the image patterns it permits.
///
/// **Carries no scope, no exception and no negation**, per RFC 0005's *A pattern set is a
/// union*: selecting more entries can only ever permit more, so an `except` field would be a
/// rule whose meaning depends on which other entries happen to be selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Entry {
    /// The short identifier a grant, an attribute, or the top-level `default` names.
    pub key: EntryKey,
    /// The image patterns this entry permits. Non-empty; parsed by `weebo-si-image-policy`, and
    /// held here as the text an admin wrote so the CRD stays readable by `kubectl` and GitOps.
    pub patterns: Vec<String>,
}

/// Every entry a workspace may be granted, keyed by [`EntryKey`]. Serializes as a plain array —
/// the wrapper exists for the accessor methods below, per Rust's orphan rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ImageCatalog {
    entries: Vec<Entry>,
}

impl ImageCatalog {
    /// Build a catalogue from its entries.
    pub fn new(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// Every entry, in configuration order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry a key names, if the key is in the catalogue.
    pub fn entry(&self, key: &EntryKey) -> Option<&Entry> {
        self.entries.iter().find(|entry| &entry.key == key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &EntryKey) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }
}

/// What one team may reach: the set of entry keys it may reach, and the subset applied when a
/// workspace asks for nothing. Either may legitimately be empty — an ungranted team reaches
/// only the platform set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImageGrant {
    /// The entry keys this team may reach.
    #[serde(default)]
    pub allowed: Vec<EntryKey>,
    /// The subset of `allowed` applied when a workspace names nothing more specific.
    #[serde(default)]
    pub default: Vec<EntryKey>,
}

/// One declared pattern variable's binding. Exactly one binding form ships —
/// `fromNamespaceAnnotation` — per RFC 0005's *Future work*: "so the surface stays one thing
/// rather than a small language."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VariableBinding {
    /// The namespace annotation key this variable's value is read from.
    pub from_namespace_annotation: String,
}

/// `spec.features.imagePolicy.platform` — the pattern set allowed in every namespace regardless
/// of team, and the only one no grant can withhold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlatformConfig {
    /// Whether the compiled-in platform patterns apply. The compiled-in list is explicitly
    /// **not** contract (RFC 0005's *Stability*) — it tracks Che and DevWorkspace Operator.
    #[serde(default = "default_true")]
    pub builtin: bool,
    /// Additional always-allowed patterns, for an admin who mirrors the platform images into
    /// their own registry.
    #[serde(default)]
    pub extra: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            builtin: true,
            extra: Vec::new(),
        }
    }
}

/// `spec.features.imagePolicy.namespaceSelection` — the namespace annotation naming a
/// comma-separated entry key list, read when the workspace attribute is not set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageNamespaceSelection {
    /// Namespace annotation naming a comma-separated entry key list. The empty string disables
    /// this selection step entirely.
    #[serde(default = "default_image_annotation")]
    pub annotation: String,
}

fn default_image_annotation() -> String {
    "hardening.weebo.io/image-policy".to_string()
}

impl Default for ImageNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_image_annotation(),
        }
    }
}

/// `spec.features.imagePolicy.workspaceSelection` — the devfile attribute naming a
/// comma-separated entry key list, taking precedence over the namespace annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageWorkspaceSelection {
    /// DevWorkspace attribute naming a comma-separated entry key list. The empty string disables
    /// this selection step entirely.
    #[serde(default = "default_image_attribute")]
    pub attribute: String,
}

fn default_image_attribute() -> String {
    "hardening.weebo.io/image-policy".to_string()
}

impl Default for ImageWorkspaceSelection {
    fn default() -> Self {
        Self {
            attribute: default_image_attribute(),
        }
    }
}

/// `spec.features.imagePolicy` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImagePolicyConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the webhooks' own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every entry a workspace may be granted. Required, non-empty.
    pub catalog: ImageCatalog,
    /// Additional pattern variables beyond the two built in, name → binding. Declaring one is
    /// the opt-in to an annotation-sourced value, and to the RBAC dependency RFC 0005's
    /// *Security considerations* spends a section on.
    #[serde(default)]
    pub variables: BTreeMap<String, VariableBinding>,
    /// Applied to a namespace belonging to no team, and to a team with no grant. Required; may
    /// be empty, which means the platform set and nothing else.
    pub default: Vec<EntryKey>,
    /// What each team may reach, keyed by team name.
    #[serde(default)]
    pub grants: BTreeMap<String, ImageGrant>,
    /// The namespace annotation naming an entry key list.
    #[serde(default)]
    pub namespace_selection: ImageNamespaceSelection,
    /// The devfile attribute naming an entry key list.
    #[serde(default)]
    pub workspace_selection: ImageWorkspaceSelection,
    /// What to do when a workspace names an entry key its team's grant does not allow.
    ///
    /// Reuses `dwoc-pin`'s [`OnUnknownKey`] rather than `network-profiles`' `OnNotGranted`: the
    /// two enums are the same `Default`/`Deny` pair, and a third copy of it would be a third
    /// place to keep in step. The field name is this RFC's own (`onNotGranted`), because that
    /// is the vocabulary its *Contract* table uses.
    #[serde(default)]
    pub on_not_granted: OnUnknownKey,
    /// The always-allowed platform pattern set.
    #[serde(default)]
    pub platform: PlatformConfig,
}

impl ImagePolicyConfig {
    /// This team's grant, if `grants` has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&ImageGrant> {
        self.grants.get(team.as_str())
    }
}

/// The two variable names the operator resolves itself. Reserved: a `spec.variables` entry
/// rebinding either is a violation, because a pattern's reader would have no way to tell which
/// meaning was in play.
pub const RESERVED_VARIABLES: [&str; 2] = ["TEAM_NAME", "NAMESPACE"];

/// Whether `name` is a legal variable name — `[A-Z][A-Z0-9_]*`, per RFC 0005's *Variables in a
/// pattern*. Lives here rather than in the domain crate because
/// [`ImagePolicyConfig::validate`] is the first thing that needs it, and the domain crate's
/// `VariableName` newtype validates through this same function.
pub fn is_legal_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// One way `spec.features.imagePolicy` can violate its own invariants.
///
/// Produced by two functions in two crates — see this module's own header for why — so it is
/// deliberately a flat enum with no "which half found it" discriminator: an admin reading a
/// `Degraded` condition does not care which crate noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePolicyConfigViolation {
    /// `catalog` is empty. Required non-empty: a feature with nothing in its catalogue permits
    /// only the platform set, which is a configuration with no correct reading.
    EmptyCatalog,
    /// The same key appears twice in `catalog`.
    DuplicateEntryKey(EntryKey),
    /// A catalogue entry carries no pattern at all.
    EntryHasNoPatterns(EntryKey),
    /// A pattern does not parse. The entry carrying it grants nothing, per RFC 0005's
    /// *Contract*: "A misconfigured entry must fail toward denying, not toward matching more
    /// than the admin meant."
    UnparseablePattern {
        /// The entry carrying the pattern.
        entry: EntryKey,
        /// The pattern text, as written.
        pattern: String,
        /// Why it did not parse.
        reason: String,
    },
    /// A pattern names a variable `spec.variables` never declared and that is not built in.
    /// Never treated as a literal: `{TEMA_NAME}` has to be a reported typo rather than a path
    /// segment that silently never matches.
    UndeclaredVariable {
        /// The entry carrying the pattern.
        entry: EntryKey,
        /// The pattern text, as written.
        pattern: String,
        /// The undeclared name.
        variable: String,
    },
    /// A declared variable rebinds `TEAM_NAME` or `NAMESPACE`.
    ReservedVariableName(String),
    /// A declared variable's name is outside `[A-Z][A-Z0-9_]*`.
    IllegalVariableName(String),
    /// A declared variable binds to the empty annotation key, which can never resolve.
    EmptyVariableBinding(String),
    /// A declared variable no pattern uses. Not harmful, and reported anyway: it is either a
    /// typo in the pattern or a leftover, and both are worth a look.
    UnusedVariable(String),
    /// A pattern uses `{TEAM_NAME}` while some `spec.teams[].name` is not a legal path
    /// component, so that team's patterns could never be substituted into safely.
    TeamNameNotAPathComponent(TeamName),
    /// The top-level `default` names an entry whose every pattern interpolates `{TEAM_NAME}`.
    /// `default` applies exactly where there is no team, so the entry can only ever grant
    /// nothing — a mistake with no correct reading.
    DefaultEntryInterpolatesTeamName(EntryKey),
    /// The top-level `default` names a key absent from `catalog`.
    DefaultUnknownKey(EntryKey),
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team whose grant names the key.
        team: TeamName,
        /// The uncatalogued key.
        key: EntryKey,
    },
    /// A team's `default` names a key outside its own `allowed`.
    GrantDefaultOutsideAllowed {
        /// The team whose grant is malformed.
        team: TeamName,
        /// The default key that is outside `allowed`.
        key: EntryKey,
    },
    /// `grants` names a team `spec.teams` never declared.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for ImagePolicyConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCatalog => write!(f, "catalog is empty"),
            Self::DuplicateEntryKey(key) => write!(f, "entry key {key} is declared twice"),
            Self::EntryHasNoPatterns(key) => write!(f, "entry {key} has no patterns"),
            Self::UnparseablePattern {
                entry,
                pattern,
                reason,
            } => write!(
                f,
                "entry {entry} carries an unparseable pattern {pattern:?}: {reason}"
            ),
            Self::UndeclaredVariable {
                entry,
                pattern,
                variable,
            } => write!(
                f,
                "entry {entry}'s pattern {pattern:?} names variable {{{variable}}}, which is \
                 neither built in nor declared in spec.variables"
            ),
            Self::ReservedVariableName(name) => {
                write!(f, "variable {name} is reserved and may not be rebound")
            }
            Self::IllegalVariableName(name) => {
                write!(f, "variable name {name:?} is outside [A-Z][A-Z0-9_]*")
            }
            Self::EmptyVariableBinding(name) => write!(
                f,
                "variable {name} binds to an empty annotation key, which can never resolve"
            ),
            Self::UnusedVariable(name) => {
                write!(f, "variable {name} is declared but no pattern uses it")
            }
            Self::TeamNameNotAPathComponent(team) => write!(
                f,
                "team name {team:?} is not a legal image path component, and a pattern \
                 interpolates {{TEAM_NAME}}"
            ),
            Self::DefaultEntryInterpolatesTeamName(key) => write!(
                f,
                "the top-level default names entry {key}, whose patterns all interpolate \
                 {{TEAM_NAME}} — default applies exactly where there is no team, so it can only \
                 ever grant nothing"
            ),
            Self::DefaultUnknownKey(key) => {
                write!(f, "the top-level default names uncatalogued key {key}")
            }
            Self::GrantAllowedUnknownKey { team, key } => {
                write!(f, "grant for team {team} allows uncatalogued key {key}")
            }
            Self::GrantDefaultOutsideAllowed { team, key } => write!(
                f,
                "grant for team {team} defaults to {key}, which is outside its own allowed set"
            ),
            Self::GrantNamesUndeclaredTeam(team) => write!(
                f,
                "grant names team {team}, which spec.teams never declared"
            ),
        }
    }
}

impl ImagePolicyConfig {
    /// Every *structural* violation this configuration has — everything provable without
    /// parsing a pattern. Returns all of them, not just the first, mirroring
    /// `NetworkProfilesConfig::validate`: the reconcile loop reports one `Degraded` condition
    /// per violation.
    ///
    /// Callers should prefer `weebo_si_image_policy::validate`, which calls this and appends the
    /// parse-dependent half. See this module's header.
    pub fn validate(&self, teams: &[Team]) -> Vec<ImagePolicyConfigViolation> {
        let mut violations = Vec::new();

        if self.catalog.entries().is_empty() {
            violations.push(ImagePolicyConfigViolation::EmptyCatalog);
        }

        let mut seen_keys = std::collections::HashSet::new();
        for entry in self.catalog.entries() {
            if !seen_keys.insert(&entry.key) {
                violations.push(ImagePolicyConfigViolation::DuplicateEntryKey(
                    entry.key.clone(),
                ));
            }
            if entry.patterns.is_empty() {
                violations.push(ImagePolicyConfigViolation::EntryHasNoPatterns(
                    entry.key.clone(),
                ));
            }
        }

        for (name, binding) in &self.variables {
            if RESERVED_VARIABLES.contains(&name.as_str()) {
                violations.push(ImagePolicyConfigViolation::ReservedVariableName(
                    name.clone(),
                ));
            } else if !is_legal_variable_name(name) {
                violations.push(ImagePolicyConfigViolation::IllegalVariableName(
                    name.clone(),
                ));
            }
            if binding.from_namespace_annotation.is_empty() {
                violations.push(ImagePolicyConfigViolation::EmptyVariableBinding(
                    name.clone(),
                ));
            }
        }

        for key in &self.default {
            if !self.catalog.contains(key) {
                violations.push(ImagePolicyConfigViolation::DefaultUnknownKey(key.clone()));
            }
        }

        let declared_teams: std::collections::HashSet<&str> =
            teams.iter().map(|t| t.name.as_str()).collect();

        for (team_name, grant) in &self.grants {
            let team = TeamName::new(team_name.clone());
            if !declared_teams.contains(team_name.as_str()) {
                violations.push(ImagePolicyConfigViolation::GrantNamesUndeclaredTeam(
                    team.clone(),
                ));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(ImagePolicyConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            for key in &grant.default {
                if !grant.allowed.contains(key) {
                    violations.push(ImagePolicyConfigViolation::GrantDefaultOutsideAllowed {
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

    fn entry(key: &str, patterns: &[&str]) -> Entry {
        Entry {
            key: EntryKey::new(key),
            patterns: patterns.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn clean_catalog() -> ImageCatalog {
        ImageCatalog::new(vec![
            entry("internal", &["registry.internal/shared/**"]),
            entry("team-registry", &["registry.internal/teams/{TEAM_NAME}/**"]),
            entry(
                "devfile-udi",
                &["quay.io/devfile/universal-developer-image:ubi9-*"],
            ),
        ])
    }

    fn config(
        catalog: ImageCatalog,
        default: &[&str],
        grants: BTreeMap<String, ImageGrant>,
    ) -> ImagePolicyConfig {
        ImagePolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog,
            variables: BTreeMap::new(),
            default: default.iter().map(|k| EntryKey::new(*k)).collect(),
            grants,
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
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
            ImageGrant {
                allowed: vec![
                    EntryKey::new("internal"),
                    EntryKey::new("team-registry"),
                    EntryKey::new("devfile-udi"),
                ],
                default: vec![EntryKey::new("internal"), EntryKey::new("team-registry")],
            },
        );
        let cfg = config(clean_catalog(), &["internal"], grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn an_empty_catalog_is_reported() {
        let cfg = config(ImageCatalog::default(), &[], BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::EmptyCatalog)
        );
    }

    #[test]
    fn an_empty_top_level_default_is_not_a_violation() {
        // "May be empty, which means the platform set and nothing else" — RFC 0005's Contract.
        let cfg = config(clean_catalog(), &[], BTreeMap::new());
        assert!(cfg.validate(&[]).is_empty());
    }

    #[test]
    fn duplicate_entry_keys_are_reported() {
        let catalog = ImageCatalog::new(vec![
            entry("internal", &["registry.internal/**"]),
            entry("internal", &["registry.other/**"]),
        ]);
        let cfg = config(catalog, &[], BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::DuplicateEntryKey(
                    EntryKey::new("internal")
                ))
        );
    }

    #[test]
    fn an_entry_with_no_patterns_is_reported() {
        let catalog = ImageCatalog::new(vec![entry("internal", &[])]);
        let cfg = config(catalog, &[], BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::EntryHasNoPatterns(
                    EntryKey::new("internal")
                ))
        );
    }

    #[test]
    fn a_declared_variable_rebinding_a_reserved_name_is_reported() {
        let mut cfg = config(clean_catalog(), &[], BTreeMap::new());
        cfg.variables.insert(
            "TEAM_NAME".to_string(),
            VariableBinding {
                from_namespace_annotation: "weebo.io/team".to_string(),
            },
        );
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::ReservedVariableName(
                    "TEAM_NAME".to_string()
                ))
        );
    }

    #[test]
    fn a_declared_variable_outside_the_name_charset_is_reported() {
        let mut cfg = config(clean_catalog(), &[], BTreeMap::new());
        cfg.variables.insert(
            "project".to_string(),
            VariableBinding {
                from_namespace_annotation: "weebo.io/project".to_string(),
            },
        );
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::IllegalVariableName(
                    "project".to_string()
                ))
        );
    }

    #[test]
    fn a_declared_variable_with_an_empty_binding_is_reported() {
        let mut cfg = config(clean_catalog(), &[], BTreeMap::new());
        cfg.variables.insert(
            "PROJECT".to_string(),
            VariableBinding {
                from_namespace_annotation: String::new(),
            },
        );
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::EmptyVariableBinding(
                    "PROJECT".to_string()
                ))
        );
    }

    #[test]
    fn legal_variable_names_are_exactly_the_documented_charset() {
        assert!(is_legal_variable_name("PROJECT"));
        assert!(is_legal_variable_name("A"));
        assert!(is_legal_variable_name("TEAM_NAME_2"));
        assert!(!is_legal_variable_name(""));
        assert!(!is_legal_variable_name("project"));
        assert!(!is_legal_variable_name("_PROJECT"));
        assert!(!is_legal_variable_name("2PROJECT"));
        assert!(!is_legal_variable_name("PRO-JECT"));
    }

    #[test]
    fn a_top_level_default_naming_an_uncatalogued_key_is_reported() {
        let cfg = config(clean_catalog(), &["nope"], BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::DefaultUnknownKey(
                    EntryKey::new("nope")
                ))
        );
    }

    #[test]
    fn a_grant_allowed_naming_an_uncatalogued_key_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ImageGrant {
                allowed: vec![EntryKey::new("nope")],
                default: Vec::new(),
            },
        );
        let cfg = config(clean_catalog(), &[], grants);
        assert!(cfg.validate(&teams).contains(
            &ImagePolicyConfigViolation::GrantAllowedUnknownKey {
                team: TeamName::new("team-1"),
                key: EntryKey::new("nope"),
            }
        ));
    }

    #[test]
    fn a_grant_default_outside_its_own_allowed_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ImageGrant {
                allowed: vec![EntryKey::new("internal")],
                default: vec![EntryKey::new("devfile-udi")],
            },
        );
        let cfg = config(clean_catalog(), &[], grants);
        assert!(cfg.validate(&teams).contains(
            &ImagePolicyConfigViolation::GrantDefaultOutsideAllowed {
                team: TeamName::new("team-1"),
                key: EntryKey::new("devfile-udi"),
            }
        ));
    }

    #[test]
    fn a_grant_naming_a_team_nobody_declared_is_reported() {
        let mut grants = BTreeMap::new();
        grants.insert("ghost-team".to_string(), ImageGrant::default());
        let cfg = config(clean_catalog(), &[], grants);
        assert!(
            cfg.validate(&[])
                .contains(&ImagePolicyConfigViolation::GrantNamesUndeclaredTeam(
                    TeamName::new("ghost-team")
                ))
        );
    }

    #[test]
    fn multiple_violations_are_all_reported_not_just_the_first() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            ImageGrant {
                allowed: vec![EntryKey::new("nowhere")],
                default: vec![EntryKey::new("also-nowhere")],
            },
        );
        let cfg = config(clean_catalog(), &["missing"], grants);
        assert!(cfg.validate(&[]).len() >= 4);
    }

    #[test]
    fn the_wire_shape_matches_the_rfcs_example() {
        let entry = entry("team-registry", &["registry.internal/teams/{TEAM_NAME}/**"]);
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "key": "team-registry",
                "patterns": ["registry.internal/teams/{TEAM_NAME}/**"],
            })
        );
    }

    #[test]
    fn platform_builtin_defaults_to_true() {
        let platform: PlatformConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(platform.builtin);
        assert!(platform.extra.is_empty());
    }

    #[test]
    fn the_two_selection_keys_default_to_the_documented_strings() {
        assert_eq!(
            ImageNamespaceSelection::default().annotation,
            "hardening.weebo.io/image-policy"
        );
        assert_eq!(
            ImageWorkspaceSelection::default().attribute,
            "hardening.weebo.io/image-policy"
        );
    }
}
