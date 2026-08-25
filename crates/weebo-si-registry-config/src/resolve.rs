//! The resolution chain, per RFC 0007's *Design → Contract*. Pure — no I/O, no `kube` — so it is
//! exhaustively table-tested without a cluster.
//!
//! **One selection tier, where `network-profiles` and `kubearmor-policy` have two.** Not a
//! simplification and not an omission: DevWorkspace Operator's automount is a property of the
//! *namespace*, so a devfile attribute has nothing to select. RFC 0007's *The unit is the
//! namespace, not the workspace*: "`registryConfig` has no `workspaceSelection` field — not
//! because per-workspace routing is undesirable, but because there is no mechanism to route to."
//!
//! The signature below is nonetheless written to take a *selection source* rather than a
//! namespace annotation specifically, which is what makes that RFC's own promise cheap to keep:
//! "If DevWorkspace Operator ever grows a per-workspace automount selector, `workspaceSelection`
//! becomes an additive amendment to this RFC, not a redesign."

use std::collections::BTreeMap;

use weebo_si_crd::{OnNotGranted, RegistryConfig, RegistryGrant, RegistryKey, Team, TeamName};

/// Which step of the resolution chain produced the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
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
    /// The registry keys this namespace gets. Always a subset of the matched grant's `allowed`.
    pub resolved: Vec<RegistryKey>,
    /// Set when a requested key was outside the grant's `allowed` and [`OnNotGranted::Default`]
    /// dropped the whole request in favour of the grant's `default` — carries the offending keys
    /// for the `not_granted` metric and log line even though they did not change the outcome
    /// beyond that fallback.
    pub dropped_not_granted: Vec<RegistryKey>,
}

/// A requested key was outside the reachable grant, under [`OnNotGranted::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The requested keys the grant does not allow.
    pub requested: Vec<RegistryKey>,
}

/// Parse a comma-separated key list, trimming whitespace, dropping empty segments, and
/// deduplicating while preserving first-seen order.
fn parse_keys(raw: &str) -> Vec<RegistryKey> {
    let mut seen = std::collections::HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter(|segment| seen.insert((*segment).to_string()))
        .map(RegistryKey::new)
        .collect()
}

/// The resolution chain, stopping at the first source that applies:
///
/// 1. The team matching the namespace's labels — `teams` is ordered, first match wins — and that
///    team's grant. No team, or a team with no grant, resolves to the synthetic empty grant
///    `{allowed: [], default: []}`: no registry configuration at all, which is a legitimate
///    answer in a brick with no baseline.
/// 2. `namespace_annotation`, if `Some` — the complete requested list, even when that value is
///    the empty string (a namespace explicitly asking for nothing).
/// 3. The grant's `default`.
///
/// Whatever list wins is checked against the grant's `allowed`: if every key is inside it, that
/// list is the answer. If any key is outside it, [`RegistryConfig::on_not_granted`] decides —
/// [`OnNotGranted::Default`] discards the whole requested list and falls back to the grant's
/// `default` (flagging which keys were dropped); [`OnNotGranted::Deny`] refuses, naming them.
pub fn resolve(
    teams: &[Team],
    config: &RegistryConfig,
    namespace_labels: &BTreeMap<String, String>,
    namespace_annotation: Option<&str>,
) -> Result<Provenance, NotGranted> {
    let matched_team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(namespace_labels));

    let owned_grant;
    let (team_name, grant): (Option<TeamName>, &RegistryGrant) = match matched_team {
        Some(team) => match config.grant_for(&team.name) {
            Some(grant) => (Some(team.name.clone()), grant),
            None => {
                owned_grant = RegistryGrant::default();
                (Some(team.name.clone()), &owned_grant)
            }
        },
        None => {
            owned_grant = RegistryGrant::default();
            (None, &owned_grant)
        }
    };

    let (requested, step) = match namespace_annotation {
        Some(raw) => (parse_keys(raw), ResolutionStep::NamespaceAnnotation),
        None => (grant.default.clone(), ResolutionStep::GrantDefault),
    };

    let not_granted: Vec<RegistryKey> = requested
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
        Ecosystem, FeatureMode, NamespaceName, RegistryCatalog, RegistryEntry,
        RegistryNamespaceSelection, RegistrySource, Selector, SourceKind, TemplateRef,
    };

    use super::*;

    fn entry(key: &str) -> RegistryEntry {
        RegistryEntry {
            key: RegistryKey::new(key),
            ecosystem: Ecosystem::Other,
            sources: vec![RegistrySource {
                kind: SourceKind::ConfigMap,
                template_ref: TemplateRef {
                    name: format!("weebo-{key}"),
                    namespace: NamespaceName::new("weebo-si-hardening"),
                },
            }],
        }
    }

    fn config(grants: BTreeMap<String, RegistryGrant>) -> RegistryConfig {
        RegistryConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: RegistryCatalog::new(vec![
                entry("internal-npm"),
                entry("internal-pypi"),
                entry("internal-maven"),
            ]),
            grants,
            namespace_selection: RegistryNamespaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
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
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn team1_grants() -> BTreeMap<String, RegistryGrant> {
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
        grants
    }

    #[test]
    fn no_team_falls_back_to_the_synthetic_empty_grant() {
        let provenance = resolve(&[], &config(BTreeMap::new()), &BTreeMap::new(), None).unwrap();
        assert_eq!(provenance.team, None);
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn a_team_with_no_grant_gets_nothing_rather_than_a_baseline() {
        // The structural difference from every prior brick: there is no baseline to fall back
        // to, so "no grant" means "no registry configuration", not "the minimum".
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(BTreeMap::new()),
            &labels(&[("weebo.io/team", "team-1")]),
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
            RegistryGrant {
                allowed: vec![RegistryKey::new("internal-maven")],
                default: vec![RegistryKey::new("internal-maven")],
            },
        );
        let provenance = resolve(
            &teams,
            &config(grants),
            &labels(&[("weebo.io/team", "shared")]),
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(provenance.resolved, vec![RegistryKey::new("internal-npm")]);
    }

    #[test]
    fn with_no_annotation_the_grant_default_wins() {
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![RegistryKey::new("internal-npm")]);
    }

    #[test]
    fn the_namespace_annotation_names_the_complete_list() {
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-npm,internal-pypi"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert_eq!(
            provenance.resolved,
            vec![
                RegistryKey::new("internal-npm"),
                RegistryKey::new("internal-pypi"),
            ]
        );
    }

    #[test]
    fn an_empty_annotation_means_explicitly_nothing_and_does_not_fall_through() {
        // A namespace opting out of the mirror entirely — say, one whose builds are fully
        // vendored — gets exactly that, not the grant's default back.
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            Some(""),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn an_ungranted_request_under_default_falls_back_and_is_flagged() {
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-maven"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![RegistryKey::new("internal-npm")]);
        assert_eq!(
            provenance.dropped_not_granted,
            vec![RegistryKey::new("internal-maven")]
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_is_refused() {
        let teams = [team("team-1", "team-1")];
        let mut cfg = config(team1_grants());
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-maven"),
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-1")));
        assert_eq!(err.requested, vec![RegistryKey::new("internal-maven")]);
    }

    #[test]
    fn a_partially_granted_request_under_deny_names_only_the_ungranted_keys() {
        let teams = [team("team-1", "team-1")];
        let mut cfg = config(team1_grants());
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-npm,nope"),
        )
        .unwrap_err();
        assert_eq!(err.requested, vec![RegistryKey::new("nope")]);
    }

    #[test]
    fn duplicate_keys_in_the_annotation_are_deduplicated_preserving_order() {
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-npm, internal-pypi ,internal-npm"),
        )
        .unwrap();
        assert_eq!(
            provenance.resolved,
            vec![
                RegistryKey::new("internal-npm"),
                RegistryKey::new("internal-pypi"),
            ]
        );
    }

    #[test]
    fn a_namespace_annotation_is_a_request_never_a_grant() {
        // RFC 0007's *Security considerations → Trust boundary*: "a workspace *user* can
        // annotate their own namespace where RBAC allows it, which is a request for a key, never
        // a grant of one." The user's annotation names a key their team does not have; what
        // comes back is their team's default, not what they asked for.
        let teams = [team("team-1", "team-1")];
        let provenance = resolve(
            &teams,
            &config(team1_grants()),
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal-maven"),
        )
        .unwrap();
        assert!(
            !provenance
                .resolved
                .contains(&RegistryKey::new("internal-maven"))
        );
    }
}
