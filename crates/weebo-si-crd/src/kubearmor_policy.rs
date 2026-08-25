//! `spec.features.kubearmorPolicy` — the runtime profile catalogue, the baseline, the grants,
//! the default posture, and the reconcile-time validation rules over them. See RFC 0006's
//! *Design → Contract*.
//!
//! Deliberately a sibling of [`crate::network_profiles`] rather than a generic over it. The two
//! features share a *shape* (catalogue, baseline, grants, `onNotGranted`, two-tier selection)
//! and share the two types where sharing is genuinely free — [`OnNotGranted`] and
//! [`TemplateRef`], both imported from there rather than redeclared — but their keys select
//! different things and their catalogue entries carry different payloads. A `ProfileKey` naming
//! a `NetworkPolicy` template and a [`RuntimeProfileKey`] naming a `KubeArmorPolicy` template
//! are not interchangeable, and a shared newtype would let a grant for one silently typecheck
//! against the other's catalogue.

use std::collections::BTreeMap;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::feature_mode::FeatureMode;
use crate::network_profiles::{OnNotGranted, TemplateRef};
use crate::selector::Selector;
use crate::team::{Team, TeamName};

/// A short identifier for a runtime profile catalogue entry, unique within the catalogue. Never
/// a `{name, namespace}` pair — same rationale as `CatalogKey` in `dwoc_pin` and `ProfileKey` in
/// `network_profiles`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct RuntimeProfileKey(String);

impl RuntimeProfileKey {
    /// Wrap a runtime profile key.
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuntimeProfileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The engine a managed object is written for. Concrete and resolved — never `Auto`, which is
/// [`RuntimeEnforcementBackend`]'s job.
///
/// One member today, and that is the point: RFC 0006's *Alternatives considered* commits to
/// KubeArmor as the first engine while keeping a second (Tetragon, or another eBPF-based one) an
/// additive variant rather than a schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RuntimeBackend {
    /// `security.kubearmor.com/v1`, `KubeArmorPolicy`.
    KubeArmor,
}

impl fmt::Display for RuntimeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KubeArmor => f.write_str("KubeArmor"),
        }
    }
}

/// `enforcement.backend`'s configuration value. `Auto` resolves to the most capable engine the
/// apiserver advertises — that resolution is an adapter's job, not this crate's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RuntimeEnforcementBackend {
    /// Resolve to the most capable engine the cluster offers.
    #[default]
    Auto,
    /// Always write `KubeArmorPolicy`.
    KubeArmor,
}

/// What KubeArmor does with an operation no rule in any applied policy matched.
///
/// The values are KubeArmor's own, lower-cased on the wire it reads (`audit` / `block`); this
/// enum is capitalised to match every other enum in this CRD, and [`Posture::as_str`] is the one
/// place the two spellings meet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Posture {
    /// Log the unmatched operation and allow it. **The default**, and the only defensible one:
    /// a `Block` default posture on a namespace whose baseline was authored for `Audit` denies
    /// every operation the template did not think to allow, which for a workspace container is
    /// most of them.
    #[default]
    Audit,
    /// Deny the unmatched operation.
    Block,
}

impl Posture {
    /// The value KubeArmor reads from the namespace annotation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// KubeArmor's namespace annotation for the file rule domain — which, per RFC 0006's *Contract*,
/// also governs process rules.
pub const KUBEARMOR_FILE_POSTURE_ANNOTATION: &str = "kubearmor-file-posture";
/// KubeArmor's namespace annotation for the network rule domain.
pub const KUBEARMOR_NETWORK_POSTURE_ANNOTATION: &str = "kubearmor-network-posture";
/// KubeArmor's namespace annotation for the capabilities rule domain.
pub const KUBEARMOR_CAPABILITIES_POSTURE_ANNOTATION: &str = "kubearmor-capabilities-posture";

/// `enforcement.defaultPosture` — what happens in each rule domain when nothing matches.
///
/// **Three fields, not four.** KubeArmor has no separate process posture: process rules are
/// evaluated under the file posture, so a fourth field would be dead contract surface asking to
/// be misconfigured. See RFC 0006's *Design → Contract*.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DefaultPosture {
    /// Unmatched file *and process* operations.
    #[serde(default)]
    pub file: Posture,
    /// Unmatched network operations.
    #[serde(default)]
    pub network: Posture,
    /// Unmatched capability use.
    #[serde(default)]
    pub capabilities: Posture,
}

impl DefaultPosture {
    /// This posture as the three `{annotation, value}` pairs KubeArmor reads off a namespace.
    ///
    /// A method here rather than a loop in the adapter that writes them: which annotation
    /// carries which field is part of this feature's contract with KubeArmor, and the mapping
    /// should be tested where the contract lives, not where the `kube::Api` call happens.
    pub fn annotations(&self) -> [(&'static str, &'static str); 3] {
        [
            (KUBEARMOR_FILE_POSTURE_ANNOTATION, self.file.as_str()),
            (KUBEARMOR_NETWORK_POSTURE_ANNOTATION, self.network.as_str()),
            (
                KUBEARMOR_CAPABILITIES_POSTURE_ANNOTATION,
                self.capabilities.as_str(),
            ),
        ]
    }
}

/// `spec.features.kubearmorPolicy.enforcement`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEnforcement {
    /// Which engine to write policy for.
    #[serde(default)]
    pub backend: RuntimeEnforcementBackend,
    /// What happens in each rule domain when nothing matches.
    #[serde(default)]
    pub default_posture: DefaultPosture,
}

/// One entry of `spec.features.kubearmorPolicy.catalog`.
///
/// Carries one [`TemplateRef`] directly rather than a `variants` list, unlike
/// [`crate::network_profiles::Profile`]: there is exactly one backend today, and the
/// variant-per-backend shape is deferred until a second one actually exists rather than
/// speculatively built now — RFC 0006's *Alternatives considered*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeProfile {
    /// The short identifier a grant, an attribute, or a resolved decision names.
    pub key: RuntimeProfileKey,
    /// The `KubeArmorPolicy` object this entry copies its rule content from.
    pub template_ref: TemplateRef,
}

/// Every runtime profile a workspace may be granted, keyed by [`RuntimeProfileKey`]. Serializes
/// as a plain array — the wrapper exists for the accessor methods below, per Rust's orphan rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RuntimeProfileCatalog {
    entries: Vec<RuntimeProfile>,
}

impl RuntimeProfileCatalog {
    /// Build a catalogue from its entries.
    pub fn new(entries: Vec<RuntimeProfile>) -> Self {
        Self { entries }
    }

    /// Every entry, in configuration order.
    pub fn entries(&self) -> &[RuntimeProfile] {
        &self.entries
    }

    /// The entry a key names, if the key is in the catalogue.
    pub fn profile(&self, key: &RuntimeProfileKey) -> Option<&RuntimeProfile> {
        self.entries.iter().find(|entry| &entry.key == key)
    }

    /// Whether `key` is in the catalogue.
    pub fn contains(&self, key: &RuntimeProfileKey) -> bool {
        self.entries.iter().any(|entry| &entry.key == key)
    }
}

/// What one team may reach: the set of runtime profile keys it may reach, and the subset of them
/// applied when a workspace asks for nothing. Either may legitimately be empty — an ungranted
/// team reaches only the baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeProfileGrant {
    /// The runtime profile keys this team may reach.
    #[serde(default)]
    pub allowed: Vec<RuntimeProfileKey>,
    /// The subset of `allowed` applied when a workspace names nothing more specific.
    #[serde(default)]
    pub default: Vec<RuntimeProfileKey>,
}

/// `spec.features.kubearmorPolicy.namespaceSelection` — the namespace annotation naming a
/// comma-separated runtime profile key list, read when the workspace attribute is not set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeNamespaceSelection {
    /// Namespace annotation naming a comma-separated key list. The empty string disables this
    /// selection step entirely.
    #[serde(default = "default_runtime_annotation")]
    pub annotation: String,
}

fn default_runtime_annotation() -> String {
    "hardening.weebo.io/kubearmor-policy".to_string()
}

impl Default for RuntimeNamespaceSelection {
    fn default() -> Self {
        Self {
            annotation: default_runtime_annotation(),
        }
    }
}

/// `spec.features.kubearmorPolicy.workspaceSelection` — the devfile attribute naming a
/// comma-separated runtime profile key list, taking precedence over the namespace annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeWorkspaceSelection {
    /// DevWorkspace attribute naming a comma-separated key list. The empty string disables this
    /// selection step entirely.
    #[serde(default = "default_runtime_attribute")]
    pub attribute: String,
}

fn default_runtime_attribute() -> String {
    "hardening.weebo.io/kubearmor-policy".to_string()
}

impl Default for RuntimeWorkspaceSelection {
    fn default() -> Self {
        Self {
            attribute: default_runtime_attribute(),
        }
    }
}

/// `spec.features.kubearmorPolicy` in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubeArmorPolicyConfig {
    /// Required, per the chassis: `Off` | `DryRun` | `Enforce`.
    pub mode: FeatureMode,
    /// Optional, per the chassis: narrows within the controller's own scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_selector: Option<Selector>,
    /// Every runtime profile a workspace may be granted.
    pub catalog: RuntimeProfileCatalog,
    /// The profile applied to every workspace pod in scope, never negotiable.
    pub baseline: RuntimeProfileKey,
    /// What each team may reach, keyed by team name.
    #[serde(default)]
    pub grants: BTreeMap<String, RuntimeProfileGrant>,
    /// The namespace annotation naming a runtime profile key list.
    #[serde(default)]
    pub namespace_selection: RuntimeNamespaceSelection,
    /// The devfile attribute naming a runtime profile key list.
    #[serde(default)]
    pub workspace_selection: RuntimeWorkspaceSelection,
    /// What to do when a workspace names a key its team's grant does not allow.
    #[serde(default)]
    pub on_not_granted: OnNotGranted,
    /// The enforcement engine and the default posture written onto namespaces in scope.
    #[serde(default)]
    pub enforcement: RuntimeEnforcement,
}

impl KubeArmorPolicyConfig {
    /// This team's grant, if `grants` has one.
    pub fn grant_for(&self, team: &TeamName) -> Option<&RuntimeProfileGrant> {
        self.grants.get(team.as_str())
    }
}

/// One way `spec.features.kubearmorPolicy` can violate its own invariants.
///
/// Two of `network-profiles`' violations have no counterpart here — `ProfileHasNoVariants` and
/// `ProfileHasDuplicateBackend` — because a catalogue entry carries exactly one `templateRef`
/// and the type system already rules both out. The remaining five are the same failures, over
/// this feature's own key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeArmorPolicyConfigViolation {
    /// The same key appears twice in `catalog`.
    DuplicateProfileKey(RuntimeProfileKey),
    /// `baseline` names a key absent from `catalog`.
    BaselineNotInCatalog(RuntimeProfileKey),
    /// A team's `default` names a key outside its own `allowed`.
    GrantDefaultOutsideAllowed {
        /// The team whose grant is malformed.
        team: TeamName,
        /// The default key that is outside `allowed`.
        key: RuntimeProfileKey,
    },
    /// A team's `allowed` names a key absent from `catalog`.
    GrantAllowedUnknownKey {
        /// The team whose grant names the key.
        team: TeamName,
        /// The uncatalogued key.
        key: RuntimeProfileKey,
    },
    /// `grants` names a team `spec.teams` never declared.
    GrantNamesUndeclaredTeam(TeamName),
}

impl fmt::Display for KubeArmorPolicyConfigViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateProfileKey(key) => {
                write!(f, "runtime profile key {key} is declared twice")
            }
            Self::BaselineNotInCatalog(key) => {
                write!(
                    f,
                    "baseline runtime profile key {key} is not in the catalog"
                )
            }
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

impl KubeArmorPolicyConfig {
    /// Every violation this configuration has, if any. Returns all of them, not just the first —
    /// the reconcile loop reports one `Degraded` condition per violation, same as
    /// [`crate::network_profiles::NetworkProfilesConfig::validate`].
    pub fn validate(&self, teams: &[Team]) -> Vec<KubeArmorPolicyConfigViolation> {
        let mut violations = Vec::new();

        let mut seen_keys = std::collections::HashSet::new();
        for entry in self.catalog.entries() {
            if !seen_keys.insert(&entry.key) {
                violations.push(KubeArmorPolicyConfigViolation::DuplicateProfileKey(
                    entry.key.clone(),
                ));
            }
        }

        if !self.catalog.contains(&self.baseline) {
            violations.push(KubeArmorPolicyConfigViolation::BaselineNotInCatalog(
                self.baseline.clone(),
            ));
        }

        let declared_teams: std::collections::HashSet<&str> =
            teams.iter().map(|t| t.name.as_str()).collect();

        for (team_name, grant) in &self.grants {
            let team = TeamName::new(team_name.clone());
            if !declared_teams.contains(team_name.as_str()) {
                violations.push(KubeArmorPolicyConfigViolation::GrantNamesUndeclaredTeam(
                    team.clone(),
                ));
            }
            for key in &grant.allowed {
                if !self.catalog.contains(key) {
                    violations.push(KubeArmorPolicyConfigViolation::GrantAllowedUnknownKey {
                        team: team.clone(),
                        key: key.clone(),
                    });
                }
            }
            for key in &grant.default {
                if !grant.allowed.contains(key) {
                    violations.push(KubeArmorPolicyConfigViolation::GrantDefaultOutsideAllowed {
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
    use crate::namespace::NamespaceName;

    fn template(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn entry(key: &str) -> RuntimeProfile {
        RuntimeProfile {
            key: RuntimeProfileKey::new(key),
            template_ref: template(&format!("weebo-{key}-runtime")),
        }
    }

    fn clean_catalog() -> RuntimeProfileCatalog {
        RuntimeProfileCatalog::new(vec![entry("base"), entry("git-write"), entry("net-raw")])
    }

    fn config(
        catalog: RuntimeProfileCatalog,
        baseline: &str,
        grants: BTreeMap<String, RuntimeProfileGrant>,
    ) -> KubeArmorPolicyConfig {
        KubeArmorPolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog,
            baseline: RuntimeProfileKey::new(baseline),
            grants,
            namespace_selection: RuntimeNamespaceSelection::default(),
            workspace_selection: RuntimeWorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: RuntimeEnforcement::default(),
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
            RuntimeProfileGrant {
                allowed: vec![
                    RuntimeProfileKey::new("git-write"),
                    RuntimeProfileKey::new("net-raw"),
                ],
                default: vec![RuntimeProfileKey::new("git-write")],
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn an_empty_grant_is_not_a_violation() {
        let teams = [team("team-2")];
        let mut grants = BTreeMap::new();
        grants.insert("team-2".to_string(), RuntimeProfileGrant::default());
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).is_empty());
    }

    #[test]
    fn duplicate_profile_keys_are_reported() {
        let catalog = RuntimeProfileCatalog::new(vec![entry("base"), entry("base")]);
        let cfg = config(catalog, "base", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&KubeArmorPolicyConfigViolation::DuplicateProfileKey(
                    RuntimeProfileKey::new("base")
                ))
        );
    }

    #[test]
    fn a_baseline_absent_from_the_catalog_is_reported() {
        let cfg = config(clean_catalog(), "missing", BTreeMap::new());
        assert!(
            cfg.validate(&[])
                .contains(&KubeArmorPolicyConfigViolation::BaselineNotInCatalog(
                    RuntimeProfileKey::new("missing")
                ))
        );
    }

    #[test]
    fn a_grant_allowing_an_uncatalogued_key_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("nope")],
                default: Vec::new(),
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).contains(
            &KubeArmorPolicyConfigViolation::GrantAllowedUnknownKey {
                team: TeamName::new("team-1"),
                key: RuntimeProfileKey::new("nope"),
            }
        ));
    }

    #[test]
    fn a_default_outside_its_own_allowed_set_is_reported() {
        let teams = [team("team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("git-write")],
                default: vec![RuntimeProfileKey::new("net-raw")],
            },
        );
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&teams).contains(
            &KubeArmorPolicyConfigViolation::GrantDefaultOutsideAllowed {
                team: TeamName::new("team-1"),
                key: RuntimeProfileKey::new("net-raw"),
            }
        ));
    }

    #[test]
    fn a_grant_naming_an_undeclared_team_is_reported() {
        let mut grants = BTreeMap::new();
        grants.insert("ghost".to_string(), RuntimeProfileGrant::default());
        let cfg = config(clean_catalog(), "base", grants);
        assert!(cfg.validate(&[]).contains(
            &KubeArmorPolicyConfigViolation::GrantNamesUndeclaredTeam(TeamName::new("ghost"))
        ));
    }

    #[test]
    fn every_violation_of_a_thoroughly_broken_config_is_reported_not_just_the_first() {
        let catalog = RuntimeProfileCatalog::new(vec![entry("base"), entry("base")]);
        let mut grants = BTreeMap::new();
        grants.insert(
            "ghost".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("nope")],
                default: vec![RuntimeProfileKey::new("other")],
            },
        );
        let cfg = config(catalog, "missing", grants);
        let violations = cfg.validate(&[]);
        assert_eq!(
            violations.len(),
            5,
            "duplicate key, missing baseline, undeclared team, uncatalogued allowed, \
             default outside allowed — all five, one Degraded condition each: {violations:?}"
        );
    }

    #[test]
    fn the_default_posture_is_audit_in_every_domain() {
        // A `Block` default on a namespace whose baseline was authored for `Audit` denies
        // everything the template did not think to allow. The safe default is the rollout
        // shape RFC 0006 asks for, not the strict one.
        let posture = DefaultPosture::default();
        assert_eq!(posture.file, Posture::Audit);
        assert_eq!(posture.network, Posture::Audit);
        assert_eq!(posture.capabilities, Posture::Audit);
    }

    #[test]
    fn the_posture_annotations_map_each_domain_to_kubearmors_own_key() {
        let posture = DefaultPosture {
            file: Posture::Block,
            network: Posture::Audit,
            capabilities: Posture::Block,
        };
        assert_eq!(
            posture.annotations(),
            [
                ("kubearmor-file-posture", "block"),
                ("kubearmor-network-posture", "audit"),
                ("kubearmor-capabilities-posture", "block"),
            ]
        );
    }

    #[test]
    fn there_is_no_process_posture_because_kubearmor_has_none() {
        // Stated as a test rather than only in a doc comment: process rules are evaluated under
        // the file posture, so a fourth annotation would be one KubeArmor never reads.
        let keys: Vec<&str> = DefaultPosture::default()
            .annotations()
            .iter()
            .map(|(key, _)| *key)
            .collect();
        assert_eq!(keys.len(), 3);
        assert!(!keys.iter().any(|key| key.contains("process")));
    }

    #[test]
    fn selection_defaults_to_the_features_own_annotation_and_attribute() {
        assert_eq!(
            RuntimeNamespaceSelection::default().annotation,
            "hardening.weebo.io/kubearmor-policy"
        );
        assert_eq!(
            RuntimeWorkspaceSelection::default().attribute,
            "hardening.weebo.io/kubearmor-policy"
        );
    }

    #[test]
    fn mode_has_no_implicit_default_in_this_feature_either() {
        let without_mode = serde_json::json!({
            "catalog": [],
            "baseline": "base",
        });
        let parsed: Result<KubeArmorPolicyConfig, _> = serde_json::from_value(without_mode);
        assert!(
            parsed.is_err(),
            "an absent mode must be a rejected write, per RFC 0002"
        );
    }

    #[test]
    fn a_minimal_configuration_round_trips_through_json() {
        let json = serde_json::json!({
            "mode": "DryRun",
            "catalog": [
                {"key": "base", "templateRef": {"name": "weebo-base-runtime", "namespace": "weebo-si-hardening"}}
            ],
            "baseline": "base",
        });
        let parsed: KubeArmorPolicyConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.baseline, RuntimeProfileKey::new("base"));
        assert_eq!(parsed.catalog.entries().len(), 1);
        assert_eq!(
            parsed.enforcement.backend,
            RuntimeEnforcementBackend::Auto,
            "an absent enforcement block resolves the backend automatically"
        );
        assert_eq!(parsed.on_not_granted, OnNotGranted::Default);
    }
}
