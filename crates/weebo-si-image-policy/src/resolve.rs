//! The three-scope resolution chain, the grant intersection, and the union that judges one
//! image — RFC 0005's *Resolution* and *A pattern set is a union*. Pure: no I/O, no `kube`, so
//! it is exhaustively table-tested without a cluster, mirroring `weebo-si-network-profiles`'
//! `resolve.rs`.
//!
//! Two shapes rather than one, because the two enforcement points deliberately compute different
//! answers (RFC 0005's *Two enforcement points*): [`resolve`] is the `DevWorkspace` half's
//! selection-precise chain, and [`allowed_set`] is the `Pod` half's team boundary. They share
//! the team match and the grant lookup, and diverge in exactly one step, which is what keeps
//! "the row above is the only thing the two layers disagree about" true rather than aspirational.

use std::collections::BTreeMap;

use weebo_si_crd::{EntryKey, ImageGrant, ImagePolicyConfig, OnUnknownKey, Team, TeamName};

use crate::pattern::Pattern;
use crate::reference::ImageReference;
use crate::variable::VariableValues;
use crate::verdict::{PermittedBy, Verdict};

/// Which step of the resolution chain produced the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStep {
    /// The workspace's own devfile attribute named the complete list.
    WorkspaceAttribute,
    /// The namespace's selection annotation named the complete list.
    NamespaceAnnotation,
    /// Nothing more specific applied, or every requested key was dropped as not granted; the
    /// grant's `default` (or the top-level `default`, for a namespace with no team) won.
    GrantDefault,
    /// The `Pod` half, which enforces the team's whole `allowed` set rather than a selection.
    TeamBoundary,
}

/// Which team matched, which entry keys won, at which step, and what was dropped along the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// Which step produced `resolved`.
    pub step: ResolutionStep,
    /// The entry keys this subject reaches, beyond the platform set. Always a subset of the
    /// matched grant's `allowed`.
    pub resolved: Vec<EntryKey>,
    /// Set when a requested key was outside the grant's `allowed` and [`OnUnknownKey::Default`]
    /// dropped the whole request in favour of the default — carried for the
    /// `weebo_si_image_policy_total{result="not_granted"}` counter and the log line, even though
    /// it did not change the outcome beyond that fallback.
    pub dropped_not_granted: Vec<EntryKey>,
}

/// A requested key was outside the reachable grant, under [`OnUnknownKey::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The requested keys the grant does not allow.
    pub requested: Vec<EntryKey>,
}

/// Parse a comma-separated entry key list, trimming whitespace, dropping empty segments, and
/// deduplicating while preserving first-seen order. The same grammar `network-profiles` uses,
/// deliberately: an admin learns the routing once.
fn parse_keys(raw: &str) -> Vec<EntryKey> {
    let mut seen = std::collections::HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter(|segment| seen.insert((*segment).to_string()))
        .map(EntryKey::new)
        .collect()
}

/// The team whose selector matches these namespace labels — ordered, first match wins, per the
/// chassis.
// The lifetime is named rather than elided: the return borrows from `teams`, not from `labels`,
// and with two reference parameters there is no elision rule that says so.
#[allow(clippy::needless_lifetimes, reason = "two inputs, one borrowed output")]
fn match_team<'a>(teams: &'a [Team], labels: &BTreeMap<String, String>) -> Option<&'a Team> {
    teams
        .iter()
        .find(|team| team.namespace_selector.matches(labels))
}

/// The grant in effect for a namespace.
///
/// **No team, and a team with no grant, are the same case**, and both come from the top-level
/// `default` — which is where this diverges from `network-profiles`, whose equivalent falls back
/// to an empty grant. The difference is not an inconsistency: `network-profiles`' floor is the
/// baseline, applied unconditionally, so an ungranted namespace is still protected; here the
/// floor is the platform set, and a namespace with no team that reached *nothing* would be a
/// namespace where no workspace can start. RFC 0005 makes `default` required for exactly that
/// reason: the no-team case is an admin's decision rather than a policy hiding in the chassis.
fn grant_for(config: &ImagePolicyConfig, team: Option<&Team>) -> (Option<TeamName>, ImageGrant) {
    let fallback = || ImageGrant {
        allowed: config.default.clone(),
        default: config.default.clone(),
    };
    match team {
        Some(team) => match config.grant_for(&team.name) {
            Some(grant) => (Some(team.name.clone()), grant.clone()),
            None => (Some(team.name.clone()), fallback()),
        },
        None => (None, fallback()),
    }
}

/// The `DevWorkspace` half: the three-scope chain, then the grant intersection.
///
/// 1. The team matching the namespace's labels, and its grant.
/// 2. `workspace_attribute`, if `Some` — the complete requested list, even when empty (a project
///    explicitly asking for nothing beyond the platform set).
/// 3. `namespace_annotation`, if `Some` and the attribute is `None`.
/// 4. The grant's `default`.
///
/// Whatever wins is intersected with `allowed`. Keys outside it follow `on_not_granted`:
/// [`OnUnknownKey::Default`] discards the whole requested list and falls back to the default
/// (flagging what was dropped); [`OnUnknownKey::Deny`] refuses, naming them.
pub fn resolve(
    teams: &[Team],
    config: &ImagePolicyConfig,
    namespace_labels: &BTreeMap<String, String>,
    namespace_annotation: Option<&str>,
    workspace_attribute: Option<&str>,
) -> Result<Provenance, NotGranted> {
    let (team_name, grant) = grant_for(config, match_team(teams, namespace_labels));

    let (requested, step) = if let Some(raw) = workspace_attribute {
        (parse_keys(raw), ResolutionStep::WorkspaceAttribute)
    } else if let Some(raw) = namespace_annotation {
        (parse_keys(raw), ResolutionStep::NamespaceAnnotation)
    } else {
        (grant.default.clone(), ResolutionStep::GrantDefault)
    };

    let not_granted: Vec<EntryKey> = requested
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
        OnUnknownKey::Deny => Err(NotGranted {
            team: team_name,
            requested: not_granted,
        }),
        OnUnknownKey::Default => Ok(Provenance {
            team: team_name,
            step: ResolutionStep::GrantDefault,
            resolved: grant.default.clone(),
            dropped_not_granted: not_granted,
        }),
    }
}

/// The `Pod` half: the team's whole `allowed` set, and no selection at all.
///
/// **Never fails**, which is the point. A pod carries `controller.devfile.io/devworkspace_id`,
/// not the selection attribute, and resolving the attribute from the id would mean a
/// DevWorkspace watch in the webhook role, new RBAC, a cache that scales with the fleet, and a
/// startup race in which a cold replica denies pods belonging to workspaces it has not observed
/// yet. What that costs is exactly one thing — a workspace running an image its team is granted
/// but its own selection excluded is not caught here — and that is a policy nicety, not a
/// security boundary: the team boundary is intact, and the selection is enforced where it was
/// authored.
pub fn allowed_set(
    teams: &[Team],
    config: &ImagePolicyConfig,
    namespace_labels: &BTreeMap<String, String>,
) -> Provenance {
    let (team_name, grant) = grant_for(config, match_team(teams, namespace_labels));
    Provenance {
        team: team_name,
        step: ResolutionStep::TeamBoundary,
        resolved: grant.allowed,
        dropped_not_granted: Vec::new(),
    }
}

/// The parsed patterns of the entries `resolved` names, plus the platform set — the effective
/// union for one subject.
///
/// A key naming an entry that is not in the catalogue contributes nothing rather than erroring:
/// that is a configuration violation `validate` already reports as `Degraded`, and refusing to
/// judge at all would turn a catalogue typo into a fleet-wide outage.
///
/// **An entry with an unparseable pattern grants nothing at all** — not "its other patterns" —
/// because a half-applied entry is an allow-list whose contents differ from what an admin reads,
/// which is the failure mode this whole design is shaped against.
pub fn effective_patterns(
    config: &ImagePolicyConfig,
    resolved: &[EntryKey],
    platform: &[Pattern],
) -> Vec<(PermittedBy, Pattern)> {
    let mut out: Vec<(PermittedBy, Pattern)> = platform
        .iter()
        .map(|pattern| (PermittedBy::Platform, pattern.clone()))
        .collect();

    for key in resolved {
        let Some(entry) = config.catalog.entry(key) else {
            continue;
        };
        let mut parsed = Vec::with_capacity(entry.patterns.len());
        let mut usable = true;
        for raw in &entry.patterns {
            match Pattern::parse(raw) {
                Ok(pattern) => parsed.push(pattern),
                Err(_) => {
                    usable = false;
                    break;
                }
            }
        }
        if usable {
            out.extend(
                parsed
                    .into_iter()
                    .map(|pattern| (PermittedBy::Entry(key.clone()), pattern)),
            );
        }
    }
    out
}

/// Judge one raw reference against an effective union.
///
/// The union is scanned in order and the **first** match wins, so the platform set — placed
/// first by [`effective_patterns`] — is what a platform image is attributed to. That ordering is
/// what makes `weebo_si_image_policy_platform_total` mean "permitted only by the platform set"
/// rather than "matched the platform set among others".
pub fn judge(raw: &str, union: &[(PermittedBy, Pattern)], variables: &VariableValues) -> Verdict {
    let reference = match ImageReference::parse(raw) {
        Ok(reference) => reference,
        // Parse failure denies. No knob.
        Err(err) => return Verdict::Unparseable(err),
    };
    for (by, pattern) in union {
        if pattern.matches(&reference, variables) {
            return Verdict::Permitted(by.clone());
        }
    }
    Verdict::NoMatchingPattern
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::{
        Entry, FeatureMode, ImageCatalog, ImageNamespaceSelection, ImageWorkspaceSelection,
        PlatformConfig, Selector,
    };

    use super::*;
    use crate::platform::platform_patterns;
    use crate::variable::{PathComponent, TEAM_NAME, VariableName};

    fn entry(key: &str, patterns: &[&str]) -> Entry {
        Entry {
            key: EntryKey::new(key),
            patterns: patterns.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn catalog() -> ImageCatalog {
        ImageCatalog::new(vec![
            entry("internal", &["registry.internal/shared/**"]),
            entry("team-registry", &["registry.internal/teams/{TEAM_NAME}/**"]),
            entry(
                "devfile-udi",
                &["quay.io/devfile/universal-developer-image:ubi9-*"],
            ),
            entry("dockerhub-library", &["docker.io/library/**"]),
        ])
    }

    fn config(default: &[&str], grants: BTreeMap<String, ImageGrant>) -> ImagePolicyConfig {
        ImagePolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            variables: BTreeMap::new(),
            default: default.iter().map(|k| EntryKey::new(*k)).collect(),
            grants,
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
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

    fn team1_grant() -> ImageGrant {
        ImageGrant {
            allowed: vec![
                EntryKey::new("internal"),
                EntryKey::new("team-registry"),
                EntryKey::new("devfile-udi"),
            ],
            default: vec![EntryKey::new("internal"), EntryKey::new("team-registry")],
        }
    }

    fn grants(pairs: &[(&str, ImageGrant)]) -> BTreeMap<String, ImageGrant> {
        pairs
            .iter()
            .map(|(name, grant)| ((*name).to_string(), grant.clone()))
            .collect()
    }

    fn keys(provenance: &Provenance) -> Vec<&str> {
        provenance.resolved.iter().map(EntryKey::as_str).collect()
    }

    // --- the three-scope chain --------------------------------------------------------------

    #[test]
    fn no_team_falls_back_to_the_top_level_default() {
        let cfg = config(&["internal"], BTreeMap::new());
        let provenance = resolve(&[], &cfg, &BTreeMap::new(), None, None).unwrap();
        assert_eq!(provenance.team, None);
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(keys(&provenance), vec!["internal"]);
    }

    #[test]
    fn a_team_with_no_grant_is_the_same_case_as_no_team() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&["internal"], BTreeMap::new());
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(keys(&provenance), vec!["internal"]);
    }

    #[test]
    fn first_of_two_matching_teams_wins() {
        let teams = [team("team-1", "shared"), team("team-2", "shared")];
        let cfg = config(
            &[],
            grants(&[
                ("team-1", team1_grant()),
                (
                    "team-2",
                    ImageGrant {
                        allowed: vec![EntryKey::new("dockerhub-library")],
                        default: vec![EntryKey::new("dockerhub-library")],
                    },
                ),
            ]),
        );
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "shared")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.team, Some(TeamName::new("team-1")));
        assert_eq!(keys(&provenance), vec!["internal", "team-registry"]);
    }

    #[test]
    fn with_no_override_the_grant_default_wins() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(keys(&provenance), vec!["internal", "team-registry"]);
    }

    #[test]
    fn the_workspace_attribute_names_the_complete_list() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("internal,devfile-udi"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(keys(&provenance), vec!["internal", "devfile-udi"]);
    }

    #[test]
    fn an_empty_workspace_attribute_means_explicitly_nothing_and_does_not_fall_through() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("internal"),
            Some(""),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert!(provenance.resolved.is_empty());
    }

    #[test]
    fn the_namespace_annotation_is_used_when_the_attribute_is_absent() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("devfile-udi"),
            None,
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::NamespaceAnnotation);
        assert_eq!(keys(&provenance), vec!["devfile-udi"]);
    }

    #[test]
    fn the_workspace_attribute_wins_over_the_namespace_annotation() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            Some("devfile-udi"),
            Some("internal"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(keys(&provenance), vec!["internal"]);
    }

    #[test]
    fn duplicate_keys_are_deduplicated_preserving_order() {
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("internal, devfile-udi ,internal"),
        )
        .unwrap();
        assert_eq!(keys(&provenance), vec!["internal", "devfile-udi"]);
    }

    // --- the grant intersection -------------------------------------------------------------

    #[test]
    fn an_ungranted_request_under_default_falls_back_and_is_flagged() {
        // The RFC's own DryRun log line: team-2 grants [internal], the workspace names postgres'
        // entry, the result is `not_granted` with the default applied.
        let teams = [team("team-2", "team-2")];
        let cfg = config(
            &[],
            grants(&[(
                "team-2",
                ImageGrant {
                    allowed: vec![EntryKey::new("internal")],
                    default: vec![EntryKey::new("internal")],
                },
            )]),
        );
        let provenance = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-2")]),
            None,
            Some("dockerhub-library"),
        )
        .unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(keys(&provenance), vec!["internal"]);
        assert_eq!(
            provenance.dropped_not_granted,
            vec![EntryKey::new("dockerhub-library")]
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_is_refused_naming_only_the_ungranted_keys() {
        let teams = [team("team-1", "team-1")];
        let mut cfg = config(&[], grants(&[("team-1", team1_grant())]));
        cfg.on_not_granted = OnUnknownKey::Deny;
        let err = resolve(
            &teams,
            &cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            None,
            Some("internal,dockerhub-library"),
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-1")));
        assert_eq!(err.requested, vec![EntryKey::new("dockerhub-library")]);
    }

    // --- the pod half ------------------------------------------------------------------------

    #[test]
    fn the_pod_half_enforces_the_whole_allowed_set_not_the_selection() {
        // The one row the two enforcement points deliberately disagree about.
        let teams = [team("team-1", "team-1")];
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let ns = labels(&[("weebo.io/team", "team-1")]);

        let workspace = resolve(&teams, &cfg, &ns, None, Some("internal")).unwrap();
        assert_eq!(keys(&workspace), vec!["internal"]);

        let pod = allowed_set(&teams, &cfg, &ns);
        assert_eq!(pod.step, ResolutionStep::TeamBoundary);
        assert_eq!(keys(&pod), vec!["internal", "team-registry", "devfile-udi"]);
    }

    #[test]
    fn the_pod_half_never_fails_even_where_the_workspace_half_would_deny() {
        let teams = [team("team-1", "team-1")];
        let mut cfg = config(&[], grants(&[("team-1", team1_grant())]));
        cfg.on_not_granted = OnUnknownKey::Deny;
        let ns = labels(&[("weebo.io/team", "team-1")]);
        // No `Result` to unwrap — the signature is the guarantee.
        let pod = allowed_set(&teams, &cfg, &ns);
        assert_eq!(pod.team, Some(TeamName::new("team-1")));
    }

    #[test]
    fn the_pod_half_falls_back_to_the_top_level_default_for_a_namespace_with_no_team() {
        let cfg = config(&["internal"], BTreeMap::new());
        let pod = allowed_set(&[], &cfg, &BTreeMap::new());
        assert_eq!(keys(&pod), vec!["internal"]);
    }

    // --- the union, and judging --------------------------------------------------------------

    fn team1_vars() -> VariableValues {
        VariableValues::from_pairs([(
            VariableName::new(TEAM_NAME).unwrap(),
            PathComponent::new("team-1").unwrap(),
        )])
    }

    fn union_for(cfg: &ImagePolicyConfig, resolved: &[&str]) -> Vec<(PermittedBy, Pattern)> {
        let platform = platform_patterns(&cfg.platform).unwrap();
        let keys: Vec<EntryKey> = resolved.iter().map(|k| EntryKey::new(*k)).collect();
        effective_patterns(cfg, &keys, &platform)
    }

    #[test]
    fn the_rfcs_audit_table_is_executable() {
        // Every row of `images audit --all-namespaces`, judged with team-1's own variables.
        let cfg = config(&[], grants(&[("team-1", team1_grant())]));
        let union = union_for(&cfg, &["internal", "team-registry", "devfile-udi"]);
        let vars = team1_vars();

        let cases: &[(&str, bool)] = &[
            (
                "quay.io/devfile/universal-developer-image:ubi9-latest",
                true,
            ),
            ("registry.internal/teams/team-1/dev-java:21", true),
            ("registry.internal/shared/base:2026.3", true),
            ("quay.io/devfile/project-clone:v0.30.0", true),
            // team-3's registry path, in a team-1 namespace: the case a per-team path exists to
            // catch.
            ("registry.internal/teams/team-3/dev-go:1.24", false),
            ("ghcr.io/someone/scratch-image:main", false),
        ];
        for (raw, permitted) in cases {
            assert_eq!(
                judge(raw, &union, &vars).is_permitted(),
                *permitted,
                "{raw:?} should be {}",
                if *permitted { "permitted" } else { "denied" }
            );
        }
    }

    #[test]
    fn a_platform_image_is_attributed_to_the_platform_set() {
        let cfg = config(&[], BTreeMap::new());
        let union = union_for(&cfg, &[]);
        assert_eq!(
            judge(
                "quay.io/devfile/project-clone:v0.30.0",
                &union,
                &team1_vars()
            ),
            Verdict::Permitted(PermittedBy::Platform)
        );
    }

    #[test]
    fn a_catalogued_image_is_attributed_to_its_entry() {
        let cfg = config(&[], BTreeMap::new());
        let union = union_for(&cfg, &["internal"]);
        assert_eq!(
            judge("registry.internal/shared/base:1", &union, &team1_vars()),
            Verdict::Permitted(PermittedBy::Entry(EntryKey::new("internal")))
        );
    }

    #[test]
    fn an_unresolved_reference_is_denied_as_unparseable_never_passed_through() {
        let cfg = config(&[], BTreeMap::new());
        let union = union_for(&cfg, &["internal", "dockerhub-library"]);
        for hostile in ["registry.internal/DEV", "", "not a reference", "a@b"] {
            assert!(
                matches!(
                    judge(hostile, &union, &team1_vars()),
                    Verdict::Unparseable(_)
                ),
                "{hostile:?} must be denied as unparseable"
            );
        }
    }

    #[test]
    fn selecting_more_entries_can_only_ever_permit_more() {
        // The union property, as a property: no selection can *remove* a permission another
        // selection granted. This is what makes the grant intersection the security boundary
        // rather than one input among several.
        let cfg = config(&[], BTreeMap::new());
        let narrow = union_for(&cfg, &["internal"]);
        let wide = union_for(&cfg, &["internal", "dockerhub-library"]);
        let vars = team1_vars();
        for raw in [
            "registry.internal/shared/base:1",
            "nginx",
            "ghcr.io/someone/x:1",
            "quay.io/devfile/project-clone:1",
        ] {
            if judge(raw, &narrow, &vars).is_permitted() {
                assert!(
                    judge(raw, &wide, &vars).is_permitted(),
                    "{raw:?} was permitted by the narrower selection and not the wider one"
                );
            }
        }
    }

    #[test]
    fn an_entry_with_an_unparseable_pattern_grants_nothing_at_all() {
        // Not "its other patterns": a half-applied entry is an allow-list whose contents differ
        // from what an admin reads.
        let mut cfg = config(&[], BTreeMap::new());
        cfg.catalog =
            ImageCatalog::new(vec![entry("mixed", &["registry.internal/good/**", "*/**"])]);
        let union = union_for(&cfg, &["mixed"]);
        assert!(
            !judge("registry.internal/good/x:1", &union, &team1_vars()).is_permitted(),
            "a broken entry must fail toward denying"
        );
    }

    #[test]
    fn an_uncatalogued_key_contributes_nothing_rather_than_erroring() {
        let cfg = config(&[], BTreeMap::new());
        let union = union_for(&cfg, &["ghost", "internal"]);
        // The catalogued half still works — a catalogue typo is a Degraded condition, not a
        // fleet-wide outage.
        assert!(judge("registry.internal/shared/x:1", &union, &team1_vars()).is_permitted());
    }

    #[test]
    fn a_namespace_with_no_team_reaches_no_team_registry_image_at_all() {
        // `{TEAM_NAME}` is undefined, so the entry's one pattern matches nothing — the
        // "undefined variable matches nothing" rule, reached through the real resolution chain.
        let cfg = config(&["team-registry"], BTreeMap::new());
        let provenance = resolve(&[], &cfg, &BTreeMap::new(), None, None).unwrap();
        let union = union_for(&cfg, &["team-registry"]);
        let mut vars = VariableValues::new();
        vars.bind_team(provenance.team.as_ref());
        assert!(!judge("registry.internal/teams/team-1/dev:1", &union, &vars).is_permitted());
        assert!(!judge("registry.internal/teams/anything/dev:1", &union, &vars).is_permitted());
    }
}
