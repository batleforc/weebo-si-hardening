//! The resolution, per RFC 0014's *Resolution*: one profile per namespace. Pure.

use std::collections::BTreeMap;

use weebo_si_crd::{OnNotGranted, QuotaProfileKey, ResolvedResourceQuotasConfig, Team, TeamName};

/// Which step produced the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The namespace annotation named a granted profile.
    NamespaceAnnotation,
    /// The team's `default`, or the cluster's for a namespace of no team.
    Default,
}

/// Which team matched and which profile won.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The profile.
    pub profile: QuotaProfileKey,
    /// Where it came from.
    pub step: ResolutionStep,
    /// A key the annotation named and the team is not granted, dropped for the default under
    /// `onNotGranted: Default` — `result=not_granted` all the same.
    pub not_granted: Option<QuotaProfileKey>,
}

/// The annotation named a key the team is not granted, under `onNotGranted: Deny`: the namespace
/// keeps what it has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The key asked for.
    pub requested: QuotaProfileKey,
}

/// Resolve one namespace's profile:
///
/// 1. The first team matching the namespace's labels, and its grant. A namespace of no team, or
///    of a team with no block, reaches only the cluster `default`.
/// 2. An annotation naming a reachable key wins.
/// 3. Otherwise the grant's `default`.
///
/// An annotation naming a key outside the grant follows `onNotGranted`. The annotation is **not**
/// narrowing-only: profiles are not ordered, and the grant is the bound.
pub fn resolve(
    teams: &[Team],
    config: &ResolvedResourceQuotasConfig,
    namespace_labels: &BTreeMap<String, String>,
    annotation: Option<&str>,
) -> Result<Provenance, NotGranted> {
    let team = teams
        .iter()
        .find(|team| team.namespace_selector.matches(namespace_labels))
        .map(|team| team.name.clone());
    let (allowed, default) = match team.as_ref().and_then(|team| config.grant_for(team)) {
        Some(grant) => (grant.allowed.clone(), grant.default.clone()),
        None => (vec![config.default.clone()], config.default.clone()),
    };

    let requested = annotation
        .map(str::trim)
        .filter(|raw| !raw.is_empty())
        .map(QuotaProfileKey::new);
    match requested {
        Some(key) if allowed.contains(&key) => Ok(Provenance {
            team,
            profile: key,
            step: ResolutionStep::NamespaceAnnotation,
            not_granted: None,
        }),
        Some(key) if config.on_not_granted == OnNotGranted::Deny => Err(NotGranted {
            team,
            requested: key,
        }),
        Some(key) => Ok(Provenance {
            team,
            profile: default,
            step: ResolutionStep::Default,
            not_granted: Some(key),
        }),
        None => Ok(Provenance {
            team,
            profile: default,
            step: ResolutionStep::Default,
            not_granted: None,
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
        FeatureMode, NamespaceName, QuotaCatalog, QuotaGrant, QuotaNamespaceSelection,
        QuotaProfile, Resolved, ResourceQuotasConfig, Selector, TemplateRef,
    };

    use super::*;

    fn key(raw: &str) -> QuotaProfileKey {
        QuotaProfileKey::new(raw)
    }

    fn profile(raw: &str) -> QuotaProfile {
        QuotaProfile {
            key: key(raw),
            quota_ref: Some(TemplateRef {
                name: format!("quota-{raw}"),
                namespace: NamespaceName::new("weebo-si-hardening-templates"),
            }),
            limit_range_ref: None,
        }
    }

    fn config(on_not_granted: OnNotGranted) -> ResolvedResourceQuotasConfig {
        Resolved::without_teams(ResourceQuotasConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: QuotaCatalog::new(vec![profile("standard"), profile("large"), profile("gpu")]),
            default: key("standard"),
            namespace_selection: QuotaNamespaceSelection::default(),
            on_not_granted,
        })
        .with_grants(BTreeMap::from([(
            "team-data".to_string(),
            QuotaGrant {
                allowed: vec![key("large"), key("standard")],
                default: key("large"),
            },
        )]))
    }

    fn teams() -> Vec<Team> {
        vec![Team {
            name: TeamName::new("team-data"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-data".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }]
    }

    fn labels(team: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("weebo.io/team".to_string(), team.to_string())])
    }

    #[test]
    fn a_namespace_of_no_team_gets_the_cluster_default() {
        let provenance =
            resolve(&teams(), &config(OnNotGranted::Default), &labels("x"), None).unwrap();
        assert_eq!(provenance.team, None);
        assert_eq!(provenance.profile, key("standard"));
        assert_eq!(provenance.step, ResolutionStep::Default);
    }

    #[test]
    fn a_team_namespace_gets_the_team_default() {
        let provenance = resolve(
            &teams(),
            &config(OnNotGranted::Default),
            &labels("team-data"),
            None,
        )
        .unwrap();
        assert_eq!(provenance.profile, key("large"));
    }

    #[test]
    fn the_annotation_picks_among_granted_profiles_in_either_direction() {
        let provenance = resolve(
            &teams(),
            &config(OnNotGranted::Default),
            &labels("team-data"),
            Some("standard"),
        )
        .unwrap();
        assert_eq!(provenance.profile, key("standard"));
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
    }

    #[test]
    fn an_ungranted_key_falls_back_to_the_default_and_is_reported() {
        let provenance = resolve(
            &teams(),
            &config(OnNotGranted::Default),
            &labels("team-data"),
            Some("gpu"),
        )
        .unwrap();
        assert_eq!(provenance.profile, key("large"));
        assert_eq!(provenance.not_granted, Some(key("gpu")));
    }

    #[test]
    fn an_ungranted_key_under_deny_changes_nothing() {
        let result = resolve(
            &teams(),
            &config(OnNotGranted::Deny),
            &labels("team-data"),
            Some("gpu"),
        );
        assert_eq!(
            result,
            Err(NotGranted {
                team: Some(TeamName::new("team-data")),
                requested: key("gpu"),
            })
        );
    }

    #[test]
    fn a_namespace_of_no_team_can_only_name_the_cluster_default() {
        let config = config(OnNotGranted::Default);
        let provenance = resolve(&teams(), &config, &labels("x"), Some("large")).unwrap();
        assert_eq!(provenance.profile, key("standard"));
        assert_eq!(provenance.not_granted, Some(key("large")));
    }

    #[test]
    fn an_empty_annotation_is_no_request() {
        let provenance = resolve(
            &teams(),
            &config(OnNotGranted::Deny),
            &labels("team-data"),
            Some("  "),
        )
        .unwrap();
        assert_eq!(provenance.profile, key("large"));
        assert_eq!(provenance.not_granted, None);
    }
}
