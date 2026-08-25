//! The resolution chain, per RFC 0006's *Design → Contract* — the same two-tier selection
//! `network-profiles` defines, over this feature's own key type. Pure — no I/O, no `kube` — so
//! it is exhaustively table-tested without a cluster.
//!
//! **Ported rather than shared**, which is a deliberate choice worth stating. The chain is the
//! same shape, but its inputs are not the same types: a `ProfileGrant` holds `ProfileKey`s
//! naming `NetworkPolicy` templates, a [`RuntimeProfileGrant`] holds [`RuntimeProfileKey`]s
//! naming `KubeArmorPolicy` templates, and the whole point of those being separate newtypes
//! (see [`weebo_si_crd::kubearmor_policy`]'s module doc) is that a grant for one must not
//! typecheck against the other's catalogue. Generifying the chain over a `Key` trait would buy
//! back the fifty lines below at the cost of the one property that keeps the two features'
//! grants from being confused.

use std::collections::BTreeMap;

use weebo_si_crd::{
    KubeArmorPolicyConfig, OnNotGranted, RuntimeProfileGrant, RuntimeProfileKey, Team, TeamName,
};

/// Which step of the resolution chain produced the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The workspace's own devfile attribute named the complete list.
    WorkspaceAttribute,
    /// The namespace's selection annotation named the complete list.
    NamespaceAnnotation,
    /// Nothing more specific applied, or every requested key was dropped as not granted; the
    /// grant's (or the synthetic empty grant's) `default` won.
    GrantDefault,
}

/// "Which team matched, which keys won, at which step, and what was dropped along the way."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// Which step of the resolution chain produced `resolved`.
    pub step: ResolutionStep,
    /// The runtime profile keys this workspace gets, beyond the baseline. Always a subset of the
    /// matched grant's `allowed`.
    pub resolved: Vec<RuntimeProfileKey>,
    /// Set when a requested key was outside the grant's `allowed` and [`OnNotGranted::Default`]
    /// dropped the whole request in favour of the grant's `default` — carries the offending keys
    /// for the `not_granted` metric and log line even though they did not change the outcome
    /// beyond that fallback.
    pub dropped_not_granted: Vec<RuntimeProfileKey>,
}

/// A requested key was outside the reachable grant, under [`OnNotGranted::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The requested keys the grant does not allow.
    pub requested: Vec<RuntimeProfileKey>,
}

/// Parse a comma-separated key list, trimming whitespace, dropping empty segments, and
/// deduplicating while preserving first-seen order.
fn parse_keys(raw: &str) -> Vec<RuntimeProfileKey> {
    let mut seen = std::collections::HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter(|segment| seen.insert((*segment).to_string()))
        .map(RuntimeProfileKey::new)
        .collect()
}

/// The resolution chain, stopping at the first source that applies:
///
/// 1. The team matching the namespace's labels — `teams` is ordered, first match wins — and that
///    team's grant. No team, or a team with no grant, resolves to the synthetic empty grant
///    `{allowed: [], default: []}`: the baseline and nothing else.
/// 2. `workspace_attribute`, if `Some` — the complete requested list, even when that value is the
///    empty string (a workspace explicitly asking for nothing beyond the baseline).
/// 3. `namespace_annotation`, if `Some` and `workspace_attribute` is `None`.
/// 4. The grant's `default`.
///
/// Whatever list wins is checked against the grant's `allowed`: if every key is inside it, that
/// list is the answer. If any key is outside it,
/// [`KubeArmorPolicyConfig::on_not_granted`] decides — [`OnNotGranted::Default`] discards the
/// whole requested list and falls back to the grant's `default` (flagging which keys were
/// dropped); [`OnNotGranted::Deny`] refuses, naming them.
pub fn resolve(
    teams: &[Team],
    config: &KubeArmorPolicyConfig,
    namespace_labels: &BTreeMap<String, String>,
    namespace_annotation: Option<&str>,
    workspace_attribute: Option<&str>,
) -> Result<Provenance, NotGranted> {
    let matched_team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(namespace_labels));

    let owned_grant;
    let (team_name, grant): (Option<TeamName>, &RuntimeProfileGrant) = match matched_team {
        Some(team) => match config.grant_for(&team.name) {
            Some(grant) => (Some(team.name.clone()), grant),
            None => {
                owned_grant = RuntimeProfileGrant::default();
                (Some(team.name.clone()), &owned_grant)
            }
        },
        None => {
            owned_grant = RuntimeProfileGrant::default();
            (None, &owned_grant)
        }
    };

    let (requested, step) = if let Some(raw) = workspace_attribute {
        (parse_keys(raw), ResolutionStep::WorkspaceAttribute)
    } else if let Some(raw) = namespace_annotation {
        (parse_keys(raw), ResolutionStep::NamespaceAnnotation)
    } else {
        (grant.default.clone(), ResolutionStep::GrantDefault)
    };

    let not_granted: Vec<RuntimeProfileKey> = requested
        .iter()
        .filter(|key| !grant.allowed.contains(key))
        .cloned()
        .collect();

    if not_granted.is_empty() {
        return Ok(Provenance {
            team: team_name,
            step,
            resolved: requested,
            dropped_not_granted: Vec::new(),
        });
    }

    match config.on_not_granted {
        OnNotGranted::Deny => Err(NotGranted {
            team: team_name,
            requested: not_granted,
        }),
        OnNotGranted::Default => Ok(Provenance {
            team: team_name,
            step: ResolutionStep::GrantDefault,
            resolved: grant.default.clone(),
            dropped_not_granted: not_granted,
        }),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::{
        FeatureMode, NamespaceName, RuntimeEnforcement, RuntimeNamespaceSelection, RuntimeProfile,
        RuntimeProfileCatalog, RuntimeWorkspaceSelection, Selector, TemplateRef,
    };

    use super::*;

    fn entry(key: &str) -> RuntimeProfile {
        RuntimeProfile {
            key: RuntimeProfileKey::new(key),
            template_ref: TemplateRef {
                name: format!("weebo-{key}-runtime"),
                namespace: NamespaceName::new("weebo-si-hardening"),
            },
        }
    }

    fn config(
        baseline: &str,
        grants: BTreeMap<String, RuntimeProfileGrant>,
    ) -> KubeArmorPolicyConfig {
        KubeArmorPolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: RuntimeProfileCatalog::new(vec![
                entry("base"),
                entry("git-write"),
                entry("net-raw"),
            ]),
            baseline: RuntimeProfileKey::new(baseline),
            grants,
            namespace_selection: RuntimeNamespaceSelection::default(),
            workspace_selection: RuntimeWorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: RuntimeEnforcement::default(),
        }
    }

    fn team(name: &str, label_value: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), label_value.to_string())].into(),
                match_expressions: Vec::new(),
            },
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn team1_grant() -> RuntimeProfileGrant {
        RuntimeProfileGrant {
            allowed: vec![
                RuntimeProfileKey::new("git-write"),
                RuntimeProfileKey::new("net-raw"),
            ],
            default: vec![RuntimeProfileKey::new("git-write")],
        }
    }

    fn team1_grants() -> BTreeMap<String, RuntimeProfileGrant> {
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        grants
    }

    #[test]
    fn no_team_falls_back_to_the_synthetic_empty_grant() {
        let cfg = config("base", BTreeMap::new());
        let provenance = resolve(&[], &cfg, &BTreeMap::new(), None, None).unwrap();
        assert_eq!(provenance.team, None);
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn a_team_with_no_grant_falls_back_to_the_synthetic_empty_grant() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", BTreeMap::new());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn first_of_two_matching_teams_wins() {
        let teams = [team("team-1", "shared"), team("team-2", "shared")];
        let mut grants = team1_grants();
        grants.insert(
            "team-2".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("net-raw")],
                default: vec![RuntimeProfileKey::new("net-raw")],
            },
        );
        // team-1 is declared first and its selector matches, so team-2's grant is never reached.
        let mut teams_grants = grants;
        teams_grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", teams_grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "shared")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(
            provenance.resolved,
            vec![RuntimeProfileKey::new("git-write")]
        );
    }

    #[test]
    fn with_no_override_the_grant_default_wins() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(
            provenance.resolved,
            vec![RuntimeProfileKey::new("git-write")]
        );
    }

    #[test]
    fn the_workspace_attribute_names_the_complete_list() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git-write,net-raw"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(
            provenance.resolved,
            vec![
                RuntimeProfileKey::new("git-write"),
                RuntimeProfileKey::new("net-raw")
            ]
        );
    }

    #[test]
    fn an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("net-raw"),
            Some(""),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert!(
            provenance.resolved.is_empty(),
            "a workspace asking for nothing beyond the baseline gets exactly that"
        );
    }

    #[test]
    fn the_namespace_annotation_is_used_when_the_attribute_is_absent() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("net-raw"),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert_eq!(provenance.resolved, vec![RuntimeProfileKey::new("net-raw")]);
    }

    #[test]
    fn the_workspace_attribute_wins_over_the_namespace_annotation_when_both_are_present() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("net-raw"),
            Some("git-write"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(
            provenance.resolved,
            vec![RuntimeProfileKey::new("git-write")]
        );
    }

    #[test]
    fn an_ungranted_request_under_default_falls_back_to_the_grant_default_and_is_flagged() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("git-write")],
                default: vec![RuntimeProfileKey::new("git-write")],
            },
        );
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-2")]),
            None,
            Some("net-raw"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(
            provenance.resolved,
            vec![RuntimeProfileKey::new("git-write")]
        );
        assert_eq!(
            provenance.dropped_not_granted,
            vec![RuntimeProfileKey::new("net-raw")]
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_is_refused() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            RuntimeProfileGrant {
                allowed: vec![RuntimeProfileKey::new("git-write")],
                default: vec![RuntimeProfileKey::new("git-write")],
            },
        );
        let mut cfg = config("base", grants);
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-2")]),
            None,
            Some("net-raw"),
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-2")));
        assert_eq!(err.requested, vec![RuntimeProfileKey::new("net-raw")]);
    }

    #[test]
    fn a_partially_granted_request_under_deny_names_only_the_ungranted_keys() {
        let teams = [team("team-1", "team-1")];
        let mut cfg = config("base", team1_grants());
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git-write,nope"),
        )
        .unwrap_err();
        assert_eq!(err.requested, vec![RuntimeProfileKey::new("nope")]);
    }

    #[test]
    fn duplicate_keys_in_the_attribute_are_deduplicated_preserving_order() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git-write, net-raw ,git-write"),
        )
        .unwrap();
        assert_eq!(
            provenance.resolved,
            vec![
                RuntimeProfileKey::new("git-write"),
                RuntimeProfileKey::new("net-raw")
            ]
        );
    }

    #[test]
    fn the_baseline_is_never_something_a_grant_can_withhold() {
        // The baseline key is not consulted by `resolve` at all — it is applied unconditionally
        // by the namespace pass. Stated as a test so a future refactor that routes the baseline
        // through the grant chain fails here rather than in a cluster.
        let teams = [team("team-1", "team-1")];
        let cfg = config("base", team1_grants());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some(""),
        )
        .unwrap();
        assert!(
            !provenance
                .resolved
                .contains(&RuntimeProfileKey::new("base")),
            "resolve never returns the baseline; the namespace pass owns it"
        );
    }
}
