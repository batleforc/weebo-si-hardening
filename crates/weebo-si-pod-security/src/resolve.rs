//! The resolution, per RFC 0013's *Resolution*. Pure, table-tested without a cluster.

use std::collections::BTreeMap;

use weebo_si_crd::{PodSecurityLevel, ResolvedPodSecurityConfig, Team, TeamName};

/// Something the resolution did that is worth a log line and a counter, without changing whether
/// the namespace gets a level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// The level was looser than the ceiling and was raised to it — `result=clamped`. An admin
    /// wrote a level they cannot have.
    Clamped {
        /// The level before the clamp.
        from: PodSecurityLevel,
    },
    /// The namespace annotation named a level no stricter than the team's, and was ignored —
    /// `result=not_tightening`.
    NotTightening {
        /// The level the annotation named.
        requested: PodSecurityLevel,
    },
    /// The namespace annotation named no level at all. Ignored, like a looser one.
    UnknownAnnotation {
        /// The annotation's value.
        raw: String,
    },
    /// The team's `warnLevel` was looser than the enforce level and was raised to it.
    WarnRaised {
        /// The configured `warnLevel`.
        from: PodSecurityLevel,
    },
}

/// Which team matched, and the two levels the namespace gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The `enforce` level.
    pub level: PodSecurityLevel,
    /// The `warn` and `audit` level. Never looser than `level`.
    pub warn_level: PodSecurityLevel,
    /// What the resolution did on the way.
    pub notes: Vec<Note>,
}

/// Resolve one namespace's levels:
///
/// 1. `team_level` is the matching team's `level` — `teams` is ordered, first match wins — or the
///    cluster `default` when no team matches or the team sets none.
/// 2. A namespace annotation naming a **stricter** level wins. A looser or equal one is ignored,
///    and a looser one noted: the annotation can only tighten.
/// 3. The result is clamped to the `ceiling`.
/// 4. The warn level is the team's `warnLevel`, else its enforce level before the annotation; it
///    is raised to the final enforce level when looser.
///
/// Strictness order: `privileged` < `baseline` < `restricted`.
pub fn resolve(
    teams: &[Team],
    config: &ResolvedPodSecurityConfig,
    namespace_labels: &BTreeMap<String, String>,
    annotation: Option<&str>,
) -> Resolution {
    let mut notes = Vec::new();
    let team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(namespace_labels))
        .map(|team| team.name.clone());
    let grant = team
        .as_ref()
        .and_then(|team| config.grant_for(team))
        .copied()
        .unwrap_or_default();

    let team_level = grant.level.unwrap_or(config.default);

    let mut level = team_level;
    match annotation.map(|raw| (raw, PodSecurityLevel::parse(raw))) {
        Some((_, Some(requested))) if requested > team_level => level = requested,
        Some((_, Some(requested))) if requested < team_level => {
            notes.push(Note::NotTightening { requested });
        }
        Some((raw, None)) => notes.push(Note::UnknownAnnotation {
            raw: raw.to_string(),
        }),
        _ => {}
    }

    if level < config.ceiling {
        notes.push(Note::Clamped { from: level });
        level = config.ceiling;
    }

    let warn_base = grant.warn_level.unwrap_or(team_level);
    let warn_level = warn_base.max(level);
    if let Some(configured) = grant.warn_level
        && configured < level
    {
        notes.push(Note::WarnRaised { from: configured });
    }

    Resolution {
        team,
        level,
        warn_level,
        notes,
    }
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
        FeatureMode, PodSecurityBackend, PodSecurityConfig, PodSecurityNamespaceSelection,
        PodSecurityVersion, Resolved, Selector, TeamPodSecurity,
    };

    use super::*;
    use PodSecurityLevel::{Baseline, Privileged, Restricted};

    fn config(
        default: PodSecurityLevel,
        ceiling: PodSecurityLevel,
        grants: &[(&str, TeamPodSecurity)],
    ) -> ResolvedPodSecurityConfig {
        Resolved::without_teams(PodSecurityConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            default,
            ceiling,
            version: PodSecurityVersion::new("v1.34"),
            backend: PodSecurityBackend::Labels,
            namespace_selection: PodSecurityNamespaceSelection::default(),
        })
        .with_grants(
            grants
                .iter()
                .map(|(team, grant)| ((*team).to_string(), *grant))
                .collect(),
        )
    }

    fn team(name: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), name.to_string())].into(),
                match_expressions: Vec::new(),
            },
        }
    }

    fn labels(team: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("weebo.io/team".to_string(), team.to_string())])
    }

    fn level(level: PodSecurityLevel) -> TeamPodSecurity {
        TeamPodSecurity {
            level: Some(level),
            warn_level: None,
        }
    }

    /// One row of RFC 0013's *Resolution*: given the team's block, the annotation and the
    /// ceiling, the resolved `(level, warn_level)` and the notes.
    struct Row {
        name: &'static str,
        default: PodSecurityLevel,
        grant: Option<TeamPodSecurity>,
        annotation: Option<&'static str>,
        ceiling: PodSecurityLevel,
        level: PodSecurityLevel,
        warn_level: PodSecurityLevel,
        notes: Vec<Note>,
    }

    #[test]
    fn every_row_of_the_resolution() {
        let rows = [
            Row {
                name: "no team level: the cluster default",
                default: Restricted,
                grant: None,
                annotation: None,
                ceiling: Baseline,
                level: Restricted,
                warn_level: Restricted,
                notes: vec![],
            },
            Row {
                name: "a team level wins over the default",
                default: Restricted,
                grant: Some(level(Baseline)),
                annotation: None,
                ceiling: Baseline,
                level: Baseline,
                warn_level: Baseline,
                notes: vec![],
            },
            Row {
                name: "a stricter annotation tightens",
                default: Restricted,
                grant: Some(level(Baseline)),
                annotation: Some("restricted"),
                ceiling: Baseline,
                level: Restricted,
                warn_level: Restricted,
                notes: vec![],
            },
            Row {
                name: "a looser annotation is ignored and noted",
                default: Restricted,
                grant: Some(level(Baseline)),
                annotation: Some("privileged"),
                ceiling: Privileged,
                level: Baseline,
                warn_level: Baseline,
                notes: vec![Note::NotTightening {
                    requested: Privileged,
                }],
            },
            Row {
                name: "an equal annotation changes nothing and says nothing",
                default: Restricted,
                grant: Some(level(Baseline)),
                annotation: Some("baseline"),
                ceiling: Baseline,
                level: Baseline,
                warn_level: Baseline,
                notes: vec![],
            },
            Row {
                name: "an annotation naming no level is ignored and noted",
                default: Restricted,
                grant: Some(level(Baseline)),
                annotation: Some("Restricted"),
                ceiling: Baseline,
                level: Baseline,
                warn_level: Baseline,
                notes: vec![Note::UnknownAnnotation {
                    raw: "Restricted".to_string(),
                }],
            },
            Row {
                name: "a team level looser than the ceiling is clamped",
                default: Restricted,
                grant: Some(level(Privileged)),
                annotation: None,
                ceiling: Baseline,
                level: Baseline,
                warn_level: Baseline,
                notes: vec![Note::Clamped { from: Privileged }],
            },
            Row {
                name: "a privileged ceiling lets a team have privileged",
                default: Restricted,
                grant: Some(level(Privileged)),
                annotation: None,
                ceiling: Privileged,
                level: Privileged,
                warn_level: Privileged,
                notes: vec![],
            },
            Row {
                name: "warnLevel stricter than the level is kept",
                default: Restricted,
                grant: Some(TeamPodSecurity {
                    level: Some(Baseline),
                    warn_level: Some(Restricted),
                }),
                annotation: None,
                ceiling: Baseline,
                level: Baseline,
                warn_level: Restricted,
                notes: vec![],
            },
            Row {
                name: "warnLevel looser than the level is raised and noted",
                default: Restricted,
                grant: Some(TeamPodSecurity {
                    level: Some(Restricted),
                    warn_level: Some(Baseline),
                }),
                annotation: None,
                ceiling: Baseline,
                level: Restricted,
                warn_level: Restricted,
                notes: vec![Note::WarnRaised { from: Baseline }],
            },
            Row {
                name: "an annotation tightening past warnLevel raises warn too",
                default: Restricted,
                grant: Some(TeamPodSecurity {
                    level: Some(Privileged),
                    warn_level: Some(Baseline),
                }),
                annotation: Some("restricted"),
                ceiling: Privileged,
                level: Restricted,
                warn_level: Restricted,
                notes: vec![Note::WarnRaised { from: Baseline }],
            },
            Row {
                name: "a team with only warnLevel enforces the default",
                default: Baseline,
                grant: Some(TeamPodSecurity {
                    level: None,
                    warn_level: Some(Restricted),
                }),
                annotation: None,
                ceiling: Privileged,
                level: Baseline,
                warn_level: Restricted,
                notes: vec![],
            },
        ];

        for row in rows {
            let grants: Vec<(&str, TeamPodSecurity)> = row
                .grant
                .into_iter()
                .map(|grant| ("team-1", grant))
                .collect();
            let config = config(row.default, row.ceiling, &grants);
            let resolution = resolve(
                &[team("team-1")],
                &config,
                &labels("team-1"),
                row.annotation,
            );
            assert_eq!(resolution.level, row.level, "{}: level", row.name);
            assert_eq!(
                resolution.warn_level, row.warn_level,
                "{}: warn level",
                row.name
            );
            assert_eq!(resolution.notes, row.notes, "{}: notes", row.name);
            assert_eq!(
                resolution.team,
                Some(TeamName::new("team-1")),
                "{}",
                row.name
            );
        }
    }

    #[test]
    fn a_namespace_of_no_team_gets_the_default_and_no_team() {
        let config = config(Restricted, Baseline, &[("team-1", level(Baseline))]);
        let resolution = resolve(&[team("team-1")], &config, &labels("other"), None);
        assert_eq!(resolution.team, None);
        assert_eq!(resolution.level, Restricted);
    }

    #[test]
    fn the_first_matching_team_wins() {
        let config = config(
            Restricted,
            Privileged,
            &[("first", level(Baseline)), ("second", level(Privileged))],
        );
        let everyone = Team {
            name: TeamName::new("second"),
            namespace_selector: Selector::default(),
        };
        let first = Team {
            name: TeamName::new("first"),
            namespace_selector: Selector::default(),
        };
        let resolution = resolve(&[first, everyone], &config, &labels("x"), None);
        assert_eq!(resolution.team, Some(TeamName::new("first")));
        assert_eq!(resolution.level, Baseline);
    }

    #[test]
    fn the_annotation_can_never_produce_a_level_looser_than_without_it() {
        // The property that lets the annotation stay writable by the namespace's own user.
        for team_level in PodSecurityLevel::ALL {
            for ceiling in PodSecurityLevel::ALL {
                let config = config(Restricted, ceiling, &[("team-1", level(team_level))]);
                let without = resolve(&[team("team-1")], &config, &labels("team-1"), None);
                for raw in ["privileged", "baseline", "restricted", "nonsense", ""] {
                    let with = resolve(&[team("team-1")], &config, &labels("team-1"), Some(raw));
                    assert!(with.level >= without.level, "{team_level} {ceiling} {raw}");
                    assert!(with.warn_level >= with.level);
                }
            }
        }
    }
}
