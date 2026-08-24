//! The resolution chain, per RFC 0004's *Design → Contract*, "Resolution." Pure — no I/O, no
//! `kube` — so it is exhaustively table-tested without a cluster, mirroring
//! `weebo-si-dwoc-pin::resolve`'s shape.
//!
//! **Deliberately does not take `weebo_si_chassis::NamespaceFacts`.** That type's
//! `selection_annotation` field holds one feature's projected annotation value — it was shaped
//! for `dwoc-pin`, the chassis's first (and so far only) consumer, and has no room for a second
//! feature reading a *different* annotation key from the same namespace. Rather than misuse that
//! field or silently collide with `dwoc-pin`'s, this function takes the labels (for team
//! matching, the one thing `NamespaceFacts` is genuinely chassis-generic about) and this
//! feature's own already-extracted annotation value as separate parameters. How
//! `weebo-si-runtime`'s namespace cache ends up projecting *two* features' annotations at once
//! is a Phase 2 (adapter-layer) question this crate does not need to answer to be correct.

use std::collections::BTreeMap;

use weebo_si_crd::{NetworkProfilesConfig, OnNotGranted, ProfileGrant, ProfileKey, Team, TeamName};

/// Which step of the resolution chain produced the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The workspace's own devfile attribute named the complete list.
    WorkspaceAttribute,
    /// The namespace's selection annotation named the complete list.
    NamespaceAnnotation,
    /// Nothing more specific applied, or every requested key was dropped as not granted; the
    /// grant's (or the chassis' synthetic empty grant's) `default` won.
    GrantDefault,
}

/// "Which team matched, which profile keys won, at which step, and what (if anything) was
/// dropped along the way" — the full picture, private to this crate's callers'
/// `ReconcileFeature` implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// Which step of the resolution chain produced `resolved`.
    pub step: ResolutionStep,
    /// The profile keys this workspace gets, beyond the baseline. Always a subset of the
    /// matched grant's `allowed`.
    pub resolved: Vec<ProfileKey>,
    /// Set when a requested key was outside the grant's `allowed` and
    /// [`OnNotGranted::Default`] dropped the whole request in favour of the grant's `default` —
    /// carries the offending keys for the `not_granted` metric and log line even though they did
    /// not change the outcome beyond that fallback.
    pub dropped_not_granted: Vec<ProfileKey>,
}

/// A requested key was outside the reachable grant, under [`OnNotGranted::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The requested keys the grant does not allow.
    pub requested: Vec<ProfileKey>,
}

/// Parse a comma-separated profile key list, trimming whitespace, dropping empty segments, and
/// deduplicating while preserving first-seen order.
fn parse_keys(raw: &str) -> Vec<ProfileKey> {
    let mut seen = std::collections::HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter(|segment| seen.insert((*segment).to_string()))
        .map(ProfileKey::new)
        .collect()
}

/// The resolution chain, stopping at the first source that applies:
///
/// 1. The team matching the namespace's labels — `teams` is ordered, first match wins — and
///    that team's grant. No team, or a team with no grant, resolves to the synthetic empty grant
///    `{allowed: [], default: []}`: the baseline and nothing else.
/// 2. `workspace_attribute`, if `Some` — the complete requested list (parsed from the raw
///    value), even when that value is the empty string (a workspace explicitly asking for
///    nothing beyond the baseline).
/// 3. `namespace_annotation`, if `Some` and `workspace_attribute` is `None`.
/// 4. The grant's `default`.
///
/// Whatever list wins is checked against the grant's `allowed`: if every key is inside it,
/// that list is the answer. If any key is outside it, [`NetworkProfilesConfig::on_not_granted`]
/// decides: [`OnNotGranted::Default`] discards the whole requested list and falls back to the
/// grant's `default` (flagging which keys were dropped); [`OnNotGranted::Deny`] refuses,
/// naming them.
pub fn resolve(
    teams: &[Team],
    config: &NetworkProfilesConfig,
    namespace_labels: &BTreeMap<String, String>,
    namespace_annotation: Option<&str>,
    workspace_attribute: Option<&str>,
) -> Result<Provenance, NotGranted> {
    let matched_team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(namespace_labels));

    let owned_grant;
    let (team_name, grant): (Option<TeamName>, &ProfileGrant) = match matched_team {
        Some(team) => match config.grant_for(&team.name) {
            Some(grant) => (Some(team.name.clone()), grant),
            None => {
                owned_grant = ProfileGrant::default();
                (Some(team.name.clone()), &owned_grant)
            }
        },
        None => {
            owned_grant = ProfileGrant::default();
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

    let not_granted: Vec<ProfileKey> = requested
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
        Enforcement, FeatureMode, Profile, ProfileCatalog, ProfileNamespaceSelection, Selector,
        Variant, WorkspaceSelection,
    };

    use super::*;

    fn profile(key: &str) -> Profile {
        Profile {
            key: ProfileKey::new(key),
            variants: vec![Variant {
                backend: weebo_si_crd::Backend::NetworkPolicy,
                template_ref: weebo_si_crd::TemplateRef {
                    name: format!("weebo-{key}"),
                    namespace: weebo_si_crd::NamespaceName::new("weebo-si-hardening"),
                },
            }],
        }
    }

    fn catalog() -> ProfileCatalog {
        ProfileCatalog::new(vec![profile("base"), profile("git"), profile("vault")])
    }

    fn config(baseline: &str, grants: BTreeMap<String, ProfileGrant>) -> NetworkProfilesConfig {
        NetworkProfilesConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            baseline: ProfileKey::new(baseline),
            grants,
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: Enforcement::default(),
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

    fn team1_grant() -> ProfileGrant {
        ProfileGrant {
            allowed: vec![ProfileKey::new("git"), ProfileKey::new("vault")],
            default: vec![ProfileKey::new("git")],
        }
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
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        grants.insert(
            "team-2".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("vault")],
                default: vec![ProfileKey::new("vault")],
            },
        );
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "shared")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
    }

    #[test]
    fn with_no_override_the_grant_default_wins() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
    }

    #[test]
    fn the_workspace_attribute_names_the_complete_list_teams_second_project() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git,vault"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(
            provenance.resolved,
            vec![ProfileKey::new("git"), ProfileKey::new("vault")]
        );
    }

    #[test]
    fn an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("vault"),
            Some(""),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn the_namespace_annotation_is_used_when_the_attribute_is_absent() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("vault"),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("vault")]);
    }

    #[test]
    fn the_workspace_attribute_wins_over_the_namespace_annotation_when_both_are_present() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("vault"),
            Some("git"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
    }

    #[test]
    fn an_ungranted_request_under_default_falls_back_to_the_grant_default_and_is_flagged() {
        // The RFC's own example: team-2's grant only allows/defaults to git; a workspace names
        // vault; the log line reports `result=not_granted applied=[git]`.
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git")],
                default: vec![ProfileKey::new("git")],
            },
        );
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-2")]),
            None,
            Some("vault"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert_eq!(
            provenance.dropped_not_granted,
            vec![ProfileKey::new("vault")]
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_is_refused() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git")],
                default: vec![ProfileKey::new("git")],
            },
        );
        let mut cfg = config("base", grants);
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-2")]),
            None,
            Some("vault"),
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-2")));
        assert_eq!(err.requested, vec![ProfileKey::new("vault")]);
    }

    #[test]
    fn a_partially_granted_request_under_deny_names_only_the_ungranted_keys() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let mut cfg = config("base", grants);
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git,nope"),
        )
        .unwrap_err();
        assert_eq!(err.requested, vec![ProfileKey::new("nope")]);
    }

    #[test]
    fn duplicate_keys_in_the_attribute_are_deduplicated_preserving_order() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let cfg = config("base", grants);
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("git, vault ,git"),
        )
        .unwrap();
        assert_eq!(
            provenance.resolved,
            vec![ProfileKey::new("git"), ProfileKey::new("vault")]
        );
    }
}
