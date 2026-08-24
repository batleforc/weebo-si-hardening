//! The four-step resolution chain, per RFC 0002's *Resolution*. Pure — no I/O, no `kube` — so
//! it is exhaustively table-tested without a cluster.

use weebo_si_chassis::NamespaceFacts;
use weebo_si_crd::{CatalogKey, DwocPinConfig, DwocRef, Grant, OnUnknownKey, Team, TeamName};

/// Which step of the resolution chain produced the answer. Private to this crate — never
/// crosses into `weebo-si-chassis`, see the RFC amendment's note on `Decision<S>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The team's grant alone determined the answer (no more specific step applied).
    TeamGrant,
    /// The workspace's own attribute was kept because it named an allowed key the baseline
    /// resolution did not already choose.
    WorkspaceAttribute,
    /// The namespace's selection annotation named an allowed key.
    NamespaceAnnotation,
    /// Nothing more specific applied; the grant's (or the chassis') default won.
    GrantDefault,
}

/// "Which team matched, which catalogue key won, and at which step of the chain" — the full
/// picture, private to `weebo-si-dwoc-pin`. [`crate::DwocPin::evaluate`] renders the parts that
/// matter beyond this crate's boundary (`team`, and a human `note`) into `weebo_si_chassis::Decision`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// Which step of the resolution chain produced the answer.
    pub step: ResolutionStep,
    /// `None` only when the caller is building a denial's provenance from an [`UnknownKey`] —
    /// [`resolve`] itself never returns a successful `Provenance` without a resolved key.
    pub resolved_key: Option<CatalogKey>,
    /// Set when the namespace annotation named a key outside the reachable grant and resolution
    /// fell through under [`OnUnknownKey::Default`]. Carries the offending value for the
    /// `unknown_key` metric and log line even though it did not change the outcome.
    pub unknown_key: Option<String>,
}

/// The namespace annotation named a key outside the reachable grant, under
/// [`OnUnknownKey::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The annotation value that named the unreachable key.
    pub annotation_value: String,
}

fn synthetic_grant(default: &CatalogKey) -> Grant {
    Grant {
        allowed: vec![default.clone()],
        default: default.clone(),
    }
}

/// The four-step resolution chain, stopping at the first answer:
///
/// 1. The team matching `namespace`'s labels — `teams` is ordered, first match wins — and that
///    team's grant. No team, or a team with no grant, resolves to the synthetic grant
///    `{allowed: [default], default}`.
/// 2. `current_ref`, if it names a catalogued entry inside the grant's `allowed` set *and that
///    entry differs from what steps 3 and 4 would produce* — otherwise keeping it changes
///    nothing, and the answer is credited to whichever of steps 3/4 already agreed with it.
/// 3. `namespace.selection_annotation`, if it names a key inside `allowed`; otherwise
///    `onUnknownKey` decides whether resolution falls through (flagged) or is refused.
/// 4. The grant's `default`.
pub fn resolve(
    teams: &[Team],
    config: &DwocPinConfig,
    namespace: &NamespaceFacts,
    current_ref: Option<&DwocRef>,
) -> Result<Provenance, UnknownKey> {
    let matched_team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(&namespace.labels));

    let owned_grant;
    let (team_name, grant): (Option<TeamName>, &Grant) = match matched_team {
        Some(team) => match config.grant_for(&team.name) {
            Some(grant) => (Some(team.name.clone()), grant),
            None => {
                owned_grant = synthetic_grant(&config.default);
                (Some(team.name.clone()), &owned_grant)
            }
        },
        None => {
            owned_grant = synthetic_grant(&config.default);
            (None, &owned_grant)
        }
    };

    // Steps 3 and 4: the answer ignoring the workspace's own attribute entirely.
    let baseline = if let Some(value) = &namespace.selection_annotation {
        let annotation_key = CatalogKey::new(value.clone());
        if grant.allowed.contains(&annotation_key) {
            Provenance {
                team: team_name.clone(),
                step: ResolutionStep::NamespaceAnnotation,
                resolved_key: Some(annotation_key),
                unknown_key: None,
            }
        } else {
            match config.namespace_selection.on_unknown_key {
                OnUnknownKey::Deny => {
                    return Err(UnknownKey {
                        team: team_name,
                        annotation_value: value.clone(),
                    });
                }
                OnUnknownKey::Default => Provenance {
                    team: team_name.clone(),
                    step: ResolutionStep::GrantDefault,
                    resolved_key: Some(grant.default.clone()),
                    unknown_key: Some(value.clone()),
                },
            }
        }
    } else {
        Provenance {
            team: team_name.clone(),
            step: ResolutionStep::GrantDefault,
            resolved_key: Some(grant.default.clone()),
            unknown_key: None,
        }
    };

    // Step 2: does the workspace's own attribute name an allowed key the baseline did not
    // already choose?
    if let Some(current) = current_ref
        && let Some(key) = config.catalog.resolve_ref(current)
        && grant.allowed.contains(key)
        && Some(key) != baseline.resolved_key.as_ref()
    {
        return Ok(Provenance {
            team: team_name,
            step: ResolutionStep::WorkspaceAttribute,
            resolved_key: Some(key.clone()),
            unknown_key: None,
        });
    }

    Ok(baseline)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_crd::{
        Catalog, CatalogEntry, FeatureMode, NamespaceName, NamespaceSelection, OnMissingTarget,
        Selector,
    };

    use super::*;

    fn ns(labels: &[(&str, &str)], annotation: Option<&str>) -> NamespaceFacts {
        NamespaceFacts {
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            selection_annotation: annotation.map(str::to_string),
        }
    }

    fn dwoc(name: &str) -> DwocRef {
        DwocRef {
            name: name.to_string(),
            namespace: NamespaceName::new("eclipse-che"),
        }
    }

    fn catalog() -> Catalog {
        Catalog::new(vec![
            CatalogEntry {
                key: CatalogKey::new("baseline"),
                target: dwoc("weebo-hardened-config"),
            },
            CatalogEntry {
                key: CatalogKey::new("gpu"),
                target: dwoc("gpu-config"),
            },
            CatalogEntry {
                key: CatalogKey::new("amd"),
                target: dwoc("amd-config"),
            },
        ])
    }

    fn config(
        default: &str,
        grants: BTreeMap<String, Grant>,
        on_unknown_key: OnUnknownKey,
    ) -> DwocPinConfig {
        DwocPinConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            default: CatalogKey::new(default),
            grants,
            namespace_selection: NamespaceSelection {
                annotation: "hardening.weebo.io/dwoc".to_string(),
                on_unknown_key,
            },
            on_missing_target: OnMissingTarget::default(),
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

    #[test]
    fn no_team_falls_back_to_the_single_target() {
        let cfg = config("baseline", BTreeMap::new(), OnUnknownKey::Default);
        let provenance = resolve(&[], &cfg, &ns(&[], None), None).unwrap();
        assert_eq!(provenance.team, None);
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("baseline")));
    }

    #[test]
    fn first_of_two_matching_teams_wins() {
        let teams = [team("team-1", "shared"), team("team-2", "shared")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu")],
                default: CatalogKey::new("gpu"),
            },
        );
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("amd")],
                default: CatalogKey::new("amd"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "shared")], None),
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("gpu")));
    }

    #[test]
    fn a_team_with_no_grant_falls_back_to_the_synthetic_default_grant() {
        let teams = [team("team-1", "team-1")];
        let cfg = config("baseline", BTreeMap::new(), OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-1")], None),
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("baseline")));
    }

    #[test]
    fn the_workspace_attribute_is_kept_when_it_names_an_allowed_key() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu"), CatalogKey::new("baseline")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-1")], None),
            Some(&dwoc("gpu-config")),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("gpu")));
    }

    #[test]
    fn an_uncatalogued_workspace_attribute_is_ignored_and_falls_through() {
        let cfg = config("baseline", BTreeMap::new(), OnUnknownKey::Default);
        let provenance = resolve(
            &[],
            &cfg,
            &ns(&[], None),
            Some(&dwoc("user-alice/my-config")),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("baseline")));
    }

    #[test]
    fn a_disallowed_workspace_attribute_is_ignored_and_falls_through() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline"), CatalogKey::new("amd")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-2")], None),
            Some(&dwoc("gpu-config")),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("baseline")));
    }

    #[test]
    fn the_namespace_annotation_is_kept_when_it_names_an_allowed_key() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline"), CatalogKey::new("amd")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-2")], Some("amd")),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("amd")));
    }

    #[test]
    fn an_unknown_annotation_key_under_default_falls_through_to_the_grant_default_and_is_flagged() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-2")], Some("gpu")),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("baseline")));
        assert_eq!(provenance.unknown_key, Some("gpu".to_string()));
    }

    #[test]
    fn an_unknown_annotation_key_under_deny_is_refused() {
        let teams = [team("team-2", "team-2")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline")],
                default: CatalogKey::new("baseline"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Deny);
        let err = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-2")], Some("gpu")),
            None,
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-2")));
        assert_eq!(err.annotation_value, "gpu");
    }

    #[test]
    fn step_two_outranks_step_three() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("gpu"), CatalogKey::new("amd")],
                default: CatalogKey::new("gpu"),
            },
        );
        let cfg = config("baseline", grants, OnUnknownKey::Default);
        let provenance = resolve(
            &teams,
            &cfg,
            &ns(&[("weebo.io/team", "team-1")], Some("amd")),
            Some(&dwoc("gpu-config")),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(provenance.resolved_key, Some(CatalogKey::new("gpu")));
    }
}
