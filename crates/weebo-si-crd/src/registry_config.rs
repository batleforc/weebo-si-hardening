//! `spec.features.registryConfig` — the catalogue of package-manager configuration objects, the
//! grants over it, and the reconcile-time validation rules. See RFC 0007's *Design → Contract*.
//!
//! Shaped after [`crate::network_profiles`]' own types, with this brick's vocabulary and **two
//! fields deliberately absent**:
//!
//! - **No `baseline`.** RFC 0007's *Guide-level explanation*: "there is no universally correct
//!   `.npmrc`. A cluster with one mirror for everyone expresses that as a grant every team has,
//!   not as a mandatory entry, because 'mandatory' here would mean writing a file into a
//!   container whose image may not even have the tool it configures."
//! - **No `workspaceSelection`.** Not a preference — DevWorkspace Operator's automount is a
//!   property of the *namespace*, so there is no per-workspace mechanism to route to. See RFC
//!   0007's *The unit is the namespace, not the workspace*.
//!
//! [`OnNotGranted`] and [`TemplateRef`] are reused from `network_profiles` rather than
//! redeclared: unlike a profile key (whose whole point is that a `NetworkPolicy` grant must not
//! typecheck against a `KubeArmorPolicy` catalogue), those two carry no dialect at all.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::network_profiles::{OnNotGranted, TemplateRef};
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// A short identifier for a catalogue entry, unique within the catalogue — the name a grant or a
/// namespace annotation uses. A newtype for the same reason [`crate::ProfileKey`] is one: a
/// registry key must never typecheck where a network profile key is expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct RegistryKey(String);

impl RegistryKey {
    /// Wrap a registry key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegistryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which package ecosystem a catalogue entry configures.
///
/// **Used only as a metric label and for CLI grouping, never for behaviour** — nothing in this
/// project branches on it, and a `match` on it inside a decision would be the first step toward
/// a brick that knows what an `.npmrc` is. It is a closed enum rather than a free string for
/// exactly one reason: it becomes a metric label, and a free string there is unbounded
/// cardinality handed to whoever edits the config.
///
/// The members are the ecosystems [Batlehub](https://github.com/batleforc/batlehub) proxies
/// *and* that have a configuration file worth distributing. The ones it serves without one to
/// inject (GitHub Releases, the JetBrains marketplace) fall under [`Ecosystem::Other`], as does
/// anything behind a mirror this fleet does not run.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
)]
pub enum Ecosystem {
    /// npm / pnpm / yarn — `.npmrc`.
    Npm,
    /// Python — `pip.conf`, `uv.toml`.
    Pypi,
    /// Rust — Cargo's `config.toml`.
    Cargo,
    /// Go — `GOPROXY`, `GONOSUMDB`.
    Go,
    /// Java — Maven's `settings.xml`.
    Maven,
    /// Ruby — `.gemrc`, `bundle config`.
    RubyGems,
    /// PHP — Composer's `auth.json`/`config.json`.
    Composer,
    /// Conda — `.condarc`.
    Conda,
    /// Terraform — the CLI configuration file's `provider_installation` block.
    Terraform,
    /// The IDE extension marketplace DevWorkspace's editors resolve against.
    OpenVsx,
    /// Anything else: an ecosystem Batlehub fronts with nothing to inject, or a mirror this
    /// fleet does not run. An entirely respectable answer — see RFC 0007's *Unresolved
    /// questions*.
    #[default]
    Other,
}

impl Ecosystem {
    /// The lowercase spelling used as a metric label and in CLI output. Derived rather than
    /// stored so a new member cannot be added without one.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Maven => "maven",
            Self::RubyGems => "rubygems",
            Self::Composer => "composer",
            Self::Conda => "conda",
            Self::Terraform => "terraform",
            Self::OpenVsx => "openvsx",
            Self::Other => "other",
        }
    }

    /// Every member, so a metric that publishes one series per ecosystem can publish the zeroes
    /// too — a gauge that is absent until something exists is one nobody has a panel for.
    pub const ALL: [Ecosystem; 11] = [
        Ecosystem::Npm,
        Ecosystem::Pypi,
        Ecosystem::Cargo,
        Ecosystem::Go,
        Ecosystem::Maven,
        Ecosystem::RubyGems,
        Ecosystem::Composer,
        Ecosystem::Conda,
        Ecosystem::Terraform,
        Ecosystem::OpenVsx,
        Ecosystem::Other,
    ];
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Which kind of object a source names. The two differ in confidentiality, not in mechanism:
/// DevWorkspace Operator automounts both the same way, and this brick copies both the same way.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum SourceKind {
    /// A `ConfigMap` — the registry URL, the mirror's certificate bundle, a `settings.xml`.
    ConfigMap,
    /// A `Secret` — the token the URL above authenticates with. See RFC 0007's *Security
    /// considerations → A copied credential is a disclosed credential* before adding one.
    Secret,
}

impl SourceKind {
    /// The Kubernetes kind, as it appears in a manifest and as a metric label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfigMap => "ConfigMap",
            Self::Secret => "Secret",
        }
    }

    /// Every member, for a metric that publishes one series per kind.
    pub const ALL: [SourceKind; 2] = [SourceKind::ConfigMap, SourceKind::Secret];
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One object a catalogue entry expands into.
///
/// A catalogue entry holds a *list* of these rather than a single reference because one ecosystem
/// routinely needs two objects with different confidentiality: the `ConfigMap` holding the
/// registry URL, and the `Secret` holding the token it authenticates with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySource {
    /// Which kind of object `template_ref` names.
    pub kind: SourceKind,
    /// The object an admin authored, copied verbatim into each granted namespace.
    pub template_ref: TemplateRef,
}

/// One entry of `spec.features.registryConfig.catalog`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryEntry {
    /// The short identifier a grant or a namespace annotation names.
    pub key: RegistryKey,
    /// Metric label and CLI grouping only — never a branch.
    #[serde(default)]
    pub ecosystem: Ecosystem,
    /// The objects this entry expands into: at least one, at most one per
    /// `{kind, name, namespace}` triple.
    pub sources: Vec<RegistrySource>,
}

/// Every entry a namespace may be granted, keyed by [`RegistryKey`]. Serializes as a plain array
/// — the wrapper exists for the accessor methods below, per Rust's orphan rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RegistryCatalog {
    entries: Vec<RegistryEntry>,
}

impl RegistryCatalog {
    /// Build a catalogue from its entries.
    pub fn new(entries: Vec<RegistryEntry>) -> Self {
        Self { entries }
    }

    /// Every entry, in configuration order.
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// The entry a key names, if the key is in the catalogue.
    pub fn entry(&self, key: &RegistryKey) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| &entry.key == key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &RegistryKey) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }
}

/// What one team may reach: the keys it may be granted, and the subset applied when a namespace
/// asks for nothing. Either may legitimately be empty — an ungranted team gets no registry
/// configuration at all, which is this brick's whole "no baseline" position.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryGrant {
    /// The registry keys this team may reach.
    #[serde(default)]
    pub allowed: Vec<RegistryKey>,
    /// The subset of `allowed` applied when a namespace names nothing more specific.
    #[serde(default)]
    pub default: Vec<RegistryKey>,
}

/// `spec.features.registryConfig.namespaceSelection` — the namespace annotation naming a
/// comma-separated key list.
///
/// **The only selection tier this brick has.** `network-profiles` reads a devfile attribute
/// first; there is no equivalent here, because DevWorkspace Operator's automount has no
/// per-workspace selector to route to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryNamespaceSelection {
    /// Namespace annotation naming a comma-separated registry key list. The empty string
    /// disables this selection step entirely, leaving the grant's `default` as the only source.
    #[serde(default = "default_registry_annotation")]
    pub annotation: String,
}

fn default_registry_annotation() -> String {
    "hardening.weebo.io/registry-config".to_string()
}

impl Default for RegistryNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_registry_annotation(),
        }
    }
}

/// `spec.features.registryConfig` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistryConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the controller's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every entry a namespace may be granted.
    pub catalog: RegistryCatalog,
    /// What each team may reach, keyed by team name.
    #[serde(default)]
    pub grants: BTreeMap<String, RegistryGrant>,
    /// The namespace annotation naming a registry key list.
    #[serde(default)]
    pub namespace_selection: RegistryNamespaceSelection,
    /// What to do when a namespace names a key its team's grant does not allow.
    #[serde(default)]
    pub on_not_granted: OnNotGranted,
}

impl RegistryConfig {
    /// This team's grant, if `grants` has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&RegistryGrant> {
        self.grants.get(team.as_str())
    }
}

/// One way `spec.features.registryConfig` can violate its own invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryConfigViolation {
    /// The same key appears twice in `catalog`.
    DuplicateRegistryKey(RegistryKey),
    /// A catalogue entry names no source at all — an entry that expands into nothing is a grant
    /// that silently does nothing.
    EntryHasNoSources(RegistryKey),
    /// A catalogue entry names the same `{kind, name, namespace}` twice. Not merely redundant:
    /// two sources with the same template name collide on the copy's own name, so the second
    /// would overwrite the first on every pass.
    EntryHasDuplicateSource {
        /// The entry carrying the duplicate.
        entry: RegistryKey,
        /// Which kind was named twice.
        kind: SourceKind,
        /// The template object's name.
        name: String,
    },
    /// Two catalogue entries whose sources produce the same copy name in a target namespace.
    /// The copy is named `weebo-si-<key>-<source-name>`, so this can only happen when the keys
    /// and source names differ but their concatenation does not.
    DuplicateCopyName {
        /// The name both entries would write.
        name: String,
        /// The second entry to claim it.
        entry: RegistryKey,
    },
    /// A team's `default` names a key outside its own `allowed`.
    GrantDefaultOutsideAllowed {
        /// The team whose grant is malformed.
        team: TeamName,
        /// The default key that is outside `allowed`.
        key: RegistryKey,
    },
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team whose grant names the key.
        team: TeamName,
        /// The uncatalogued key.
        key: RegistryKey,
    },
    /// `grants` names a team `spec.teams` never declared.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for RegistryConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRegistryKey(key) => write!(f, "registry key {key} is declared twice"),
            Self::EntryHasNoSources(key) => write!(f, "registry entry {key} has no sources"),
            Self::EntryHasDuplicateSource { entry, kind, name } => write!(
                f,
                "registry entry {entry} names the same {kind} source {name} more than once"
            ),
            Self::DuplicateCopyName { name, entry } => write!(
                f,
                "registry entry {entry} would write a copy named {name}, which another entry \
                 already claims"
            ),
            Self::GrantDefaultOutsideAllowed { team, key } => write!(
                f,
                "grant for team {team} defaults to {key}, which is outside its own allowed set"
            ),
            Self::GrantAllowedUnknownKey { team, key } => {
                write!(f, "grant for team {team} allows uncatalogued key {key}")
            }
            Self::GrantNamesUndeclaredTeam(team) => write!(
                f,
                "grant names team {team}, which spec.teams never declared"
            ),
        }
    }
}

/// The name a copy of `source` under `key` is written under in a target namespace.
///
/// Lives here rather than in the brick crate so that [`RegistryConfig::validate`] can refuse a
/// catalogue whose entries collide *before* the controller discovers it by overwriting one copy
/// with another every pass. The scheme is RFC 0007's: "Named `weebo-si-<key>-<source-name>` in
/// the target namespace, so two entries whose templates share a name do not collide."
pub fn copy_name(key: &RegistryKey, source_name: &str) -> String {
    format!("weebo-si-{key}-{source_name}")
}

impl RegistryConfig {
    /// Every violation this configuration has, if any. Returns all of them, not just the first —
    /// the reconcile loop reports one `Degraded` condition per violation.
    pub fn validate(&self, teams: &[Team]) -> Vec<RegistryConfigViolation> {
        let mut violations = Vec::new();

        let mut seen_keys = std::collections::HashSet::new();
        let mut seen_copy_names: std::collections::HashMap<String, RegistryKey> =
            std::collections::HashMap::new();
        for entry in self.catalog.entries() {
            if !seen_keys.insert(&entry.key) {
                violations.push(RegistryConfigViolation::DuplicateRegistryKey(
                    entry.key.clone(),
                ));
            }

            if entry.sources.is_empty() {
                violations.push(RegistryConfigViolation::EntryHasNoSources(
                    entry.key.clone(),
                ));
            }

            let mut seen_sources = std::collections::HashSet::new();
            for source in &entry.sources {
                let triple = (
                    source.kind,
                    source.template_ref.name.clone(),
                    source.template_ref.namespace.clone(),
                );
                if !seen_sources.insert(triple) {
                    violations.push(RegistryConfigViolation::EntryHasDuplicateSource {
                        entry: entry.key.clone(),
                        kind: source.kind,
                        name: source.template_ref.name.clone(),
                    });
                }

                let name = copy_name(&entry.key, &source.template_ref.name);
                match seen_copy_names.get(&name) {
                    Some(claimed) if claimed != &entry.key => {
                        violations.push(RegistryConfigViolation::DuplicateCopyName {
                            name,
                            entry: entry.key.clone(),
                        });
                    }
                    _ => {
                        seen_copy_names.insert(name, entry.key.clone());
                    }
                }
            }
        }

        let declared_teams: std::collections::HashSet<&str> =
            teams.iter().map(|t| t.name.as_str()).collect();

        for (team_name, grant) in &self.grants {
            let team = TeamName::new(team_name.clone());
            if !declared_teams.contains(team_name.as_str()) {
                violations.push(RegistryConfigViolation::GrantNamesUndeclaredTeam(
                    team.clone(),
                ));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(RegistryConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            for key in &grant.default {
                if !grant.allowed.contains(key) {
                    violations.push(RegistryConfigViolation::GrantDefaultOutsideAllowed {
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
    use crate::namespace::NamespaceName;
    use crate::selector::Selector;

    use super::*;

    fn template(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn entry(key: &str, ecosystem: Ecosystem, sources: Vec<RegistrySource>) -> RegistryEntry {
        RegistryEntry {
            key: RegistryKey::new(key),
            ecosystem,
            sources,
        }
    }

    fn config_map(name: &str) -> RegistrySource {
        RegistrySource {
            kind: SourceKind::ConfigMap,
            template_ref: template(name),
        }
    }

    fn secret(name: &str) -> RegistrySource {
        RegistrySource {
            kind: SourceKind::Secret,
            template_ref: template(name),
        }
    }

    fn clean_catalog() -> RegistryCatalog {
        RegistryCatalog::new(vec![
            entry(
                "internal-npm",
                Ecosystem::Npm,
                vec![config_map("weebo-npmrc"), secret("weebo-npm-token")],
            ),
            entry(
                "internal-pypi",
                Ecosystem::Pypi,
                vec![config_map("weebo-pip-conf")],
            ),
        ])
    }

    fn config(catalog: RegistryCatalog, grants: BTreeMap<String, RegistryGrant>) -> RegistryConfig {
        RegistryConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog,
            grants,
            namespace_selection: RegistryNamespaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
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
            RegistryGrant {
                allowed: vec![
                    RegistryKey::new("internal-npm"),
                    RegistryKey::new("internal-pypi"),
                ],
                default: vec![RegistryKey::new("internal-npm")],
            },
        );
        assert!(config(clean_catalog(), grants).validate(&teams).is_empty());
    }

    #[test]
    fn an_empty_grant_is_not_a_violation() {
        // The "no baseline" position, as an executable assertion: a team granted nothing is a
        // team whose workspaces get no registry configuration, which is a legitimate answer and
        // not a misconfiguration.
        let teams = [team("team-2")];
        let mut grants = BTreeMap::new();
        grants.insert("team-2".to_string(), RegistryGrant::default());
        assert!(config(clean_catalog(), grants).validate(&teams).is_empty());
    }

    #[test]
    fn duplicate_registry_keys_are_reported() {
        let catalog = RegistryCatalog::new(vec![
            entry("internal-npm", Ecosystem::Npm, vec![config_map("a")]),
            entry("internal-npm", Ecosystem::Npm, vec![config_map("b")]),
        ]);
        assert!(config(catalog, BTreeMap::new()).validate(&[]).contains(
            &RegistryConfigViolation::DuplicateRegistryKey(RegistryKey::new("internal-npm"))
        ));
    }

    #[test]
    fn an_entry_with_no_sources_is_reported() {
        let catalog = RegistryCatalog::new(vec![entry("internal-npm", Ecosystem::Npm, Vec::new())]);
        assert!(config(catalog, BTreeMap::new()).validate(&[]).contains(
            &RegistryConfigViolation::EntryHasNoSources(RegistryKey::new("internal-npm"))
        ));
    }

    #[test]
    fn the_same_source_twice_in_one_entry_is_reported() {
        let catalog = RegistryCatalog::new(vec![entry(
            "internal-npm",
            Ecosystem::Npm,
            vec![config_map("weebo-npmrc"), config_map("weebo-npmrc")],
        )]);
        assert!(config(catalog, BTreeMap::new()).validate(&[]).contains(
            &RegistryConfigViolation::EntryHasDuplicateSource {
                entry: RegistryKey::new("internal-npm"),
                kind: SourceKind::ConfigMap,
                name: "weebo-npmrc".to_string(),
            }
        ));
    }

    #[test]
    fn a_configmap_and_a_secret_of_the_same_name_are_two_different_sources() {
        // The triple is `{kind, name, namespace}`, not `{name, namespace}` — an admin who names
        // both halves of an entry after the ecosystem is doing something ordinary.
        let catalog = RegistryCatalog::new(vec![entry(
            "internal-npm",
            Ecosystem::Npm,
            vec![config_map("weebo-npm"), secret("weebo-npm")],
        )]);
        assert!(config(catalog, BTreeMap::new()).validate(&[]).is_empty());
    }

    #[test]
    fn two_entries_colliding_on_one_copy_name_are_reported() {
        // `weebo-si-<key>-<source-name>` is not injective on its own: `a` + `b-c` and `a-b` + `c`
        // both render `weebo-si-a-b-c`, and the second would overwrite the first every pass.
        let catalog = RegistryCatalog::new(vec![
            entry("a", Ecosystem::Other, vec![config_map("b-c")]),
            entry("a-b", Ecosystem::Other, vec![config_map("c")]),
        ]);
        assert!(config(catalog, BTreeMap::new()).validate(&[]).contains(
            &RegistryConfigViolation::DuplicateCopyName {
                name: "weebo-si-a-b-c".to_string(),
                entry: RegistryKey::new("a-b"),
            }
        ));
    }

    #[test]
    fn a_grant_allowing_an_uncatalogued_key_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RegistryGrant {
                allowed: vec![RegistryKey::new("nope")],
                default: Vec::new(),
            },
        );
        assert!(config(clean_catalog(), grants).validate(&teams).contains(
            &RegistryConfigViolation::GrantAllowedUnknownKey {
                team: TeamName::new("team-1"),
                key: RegistryKey::new("nope"),
            }
        ));
    }

    #[test]
    fn a_grant_default_outside_its_own_allowed_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RegistryGrant {
                allowed: vec![RegistryKey::new("internal-npm")],
                default: vec![RegistryKey::new("internal-pypi")],
            },
        );
        assert!(config(clean_catalog(), grants).validate(&teams).contains(
            &RegistryConfigViolation::GrantDefaultOutsideAllowed {
                team: TeamName::new("team-1"),
                key: RegistryKey::new("internal-pypi"),
            }
        ));
    }

    #[test]
    fn a_grant_naming_a_team_nobody_declared_is_reported() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            RegistryGrant {
                allowed: vec![RegistryKey::new("internal-npm")],
                default: vec![RegistryKey::new("internal-npm")],
            },
        );
        assert!(config(clean_catalog(), grants).validate(&[]).contains(
            &RegistryConfigViolation::GrantNamesUndeclaredTeam(TeamName::new("ghost-team"))
        ));
    }

    #[test]
    fn multiple_violations_are_all_reported_not_just_the_first() {
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost-team".to_string(),
            RegistryGrant {
                allowed: vec![RegistryKey::new("nowhere")],
                default: vec![RegistryKey::new("also-nowhere")],
            },
        );
        let catalog = RegistryCatalog::new(vec![entry("empty", Ecosystem::Npm, Vec::new())]);
        assert!(config(catalog, grants).validate(&[]).len() >= 4);
    }

    #[test]
    fn the_catalog_wire_shape_matches_the_rfcs_example() {
        let json = serde_json::to_value(entry(
            "internal-npm",
            Ecosystem::Npm,
            vec![config_map("weebo-npmrc"), secret("weebo-npm-token")],
        ))
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "key": "internal-npm",
                "ecosystem": "Npm",
                "sources": [
                    {
                        "kind": "ConfigMap",
                        "templateRef": {"name": "weebo-npmrc", "namespace": "weebo-si-hardening"},
                    },
                    {
                        "kind": "Secret",
                        "templateRef": {
                            "name": "weebo-npm-token", "namespace": "weebo-si-hardening",
                        },
                    },
                ],
            })
        );
    }

    #[test]
    fn an_omitted_ecosystem_reads_as_other_rather_than_rejecting_the_entry() {
        // The field is metric-label-only, so an entry that leaves it out is under-labelled, not
        // wrong — refusing the whole catalogue over a dashboard dimension would be the wrong
        // trade.
        let parsed: RegistryEntry = serde_json::from_value(serde_json::json!({
            "key": "internal-npm",
            "sources": [{
                "kind": "ConfigMap",
                "templateRef": {"name": "weebo-npmrc", "namespace": "weebo-si-hardening"},
            }],
        }))
        .unwrap();
        assert_eq!(parsed.ecosystem, Ecosystem::Other);
    }

    #[test]
    fn the_default_selection_annotation_is_this_features_own_not_network_profiles() {
        assert_eq!(
            RegistryNamespaceSelection::default().annotation,
            "hardening.weebo.io/registry-config"
        );
    }

    #[test]
    fn the_copy_name_carries_both_the_key_and_the_template_name() {
        assert_eq!(
            copy_name(&RegistryKey::new("internal-npm"), "weebo-npmrc"),
            "weebo-si-internal-npm-weebo-npmrc"
        );
    }

    #[test]
    fn every_ecosystem_has_a_distinct_label() {
        let mut labels: Vec<&str> = Ecosystem::ALL.iter().map(Ecosystem::label).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "two ecosystems share a metric label");
    }
}
