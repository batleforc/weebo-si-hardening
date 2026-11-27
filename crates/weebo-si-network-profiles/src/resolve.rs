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

use weebo_si_crd::{
    OnNotGranted, ProfileGrant, ProfileKey, ResolvedNetworkProfilesConfig, Team, TeamName,
};

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
    /// matched grant's `allowed`, minus every restricted key the namespace does not grant.
    pub resolved: Vec<ProfileKey>,
    /// Set when a requested key was outside the grant's `allowed` and
    /// [`OnNotGranted::Default`] dropped the whole request in favour of the grant's `default` —
    /// carries the offending keys for the `not_granted` metric and log line even though they did
    /// not change the outcome beyond that fallback. Never holds a restricted key: those are in
    /// `restricted_refused`.
    pub dropped_not_granted: Vec<ProfileKey>,
    /// Restricted keys in `resolved`: the namespace's grant annotation names each (RFC 0021).
    pub restricted_honoured: Vec<ProfileKey>,
    /// Restricted keys the team allows and the request (or the team default) named, refused
    /// because the namespace's grant annotation does not name them (RFC 0021).
    pub restricted_refused: Vec<ProfileKey>,
}

/// A requested key was outside the reachable grant, under [`OnNotGranted::Deny`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotGranted {
    /// The team that matched, if any.
    pub team: Option<TeamName>,
    /// The requested keys the grant does not allow, restricted ones included, in request order.
    pub requested: Vec<ProfileKey>,
    /// The subset of `requested` the team allows but which is restricted and not granted by the
    /// namespace (RFC 0021).
    pub restricted_refused: Vec<ProfileKey>,
}

impl NotGranted {
    /// Whether every refused key is a restricted one — the gate words the refusal for the
    /// namespace grant and reports `denied_restricted`.
    pub fn restricted(&self) -> bool {
        !self.requested.is_empty() && self.requested.len() == self.restricted_refused.len()
    }
}

/// What a present attribute that is not a string (a YAML list, say) is read as: never a valid
/// [`ProfileKey`], so it is outside every grant (refused under `Deny`, dropped and reported under
/// `Default`), never the team default.
pub const INVALID_KEY: &str = "<invalid>";

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
/// Whatever list wins is checked against the grant's `allowed`, from which every restricted
/// catalogue key that `namespace_grant` (the namespace's grant annotation, RFC 0021) does not name
/// is removed first. If every key is inside it, that list is the answer. If any key is outside
/// it, [`NetworkProfilesConfig::on_not_granted`] decides: [`OnNotGranted::Default`] discards the
/// whole requested list and falls back to the grant's `default` (flagging which keys were
/// dropped); [`OnNotGranted::Deny`] refuses, naming them. The grant's `default` is filtered the
/// same way, and never refused: a workspace that asked for nothing is not denied for it.
/// `namespace_grant` only unlocks: it never selects, and never reaches past the team's `allowed`.
pub fn resolve(
    teams: &[Team],
    config: &ResolvedNetworkProfilesConfig,
    namespace_labels: &BTreeMap<String, String>,
    namespace_annotation: Option<&str>,
    namespace_grant: Option<&str>,
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

    let unlocked = namespace_grant.map(parse_keys).unwrap_or_default();
    let restricted = |key: &ProfileKey| {
        config
            .catalog
            .profile(key)
            .is_some_and(|profile| profile.restricted)
    };
    let locked = |key: &ProfileKey| restricted(key) && !unlocked.contains(key);
    let only = |keys: &[ProfileKey], keep: &dyn Fn(&ProfileKey) -> bool| -> Vec<ProfileKey> {
        keys.iter().filter(|key| keep(key)).cloned().collect()
    };
    // The team default minus every locked key — what a workspace gets when it asks for nothing,
    // and what `Default` falls back to. The locked ones are refused, never denied.
    let default = only(&grant.default, &|key| !locked(key));
    let default_refused = only(&grant.default, &locked);

    let (requested, step) = if let Some(raw) = workspace_attribute {
        (parse_keys(raw), ResolutionStep::WorkspaceAttribute)
    } else if let Some(raw) = namespace_annotation {
        (parse_keys(raw), ResolutionStep::NamespaceAnnotation)
    } else {
        (default.clone(), ResolutionStep::GrantDefault)
    };

    let not_granted = only(&requested, &|key| !grant.allowed.contains(key));
    let restricted_refused = only(&requested, &|key| {
        grant.allowed.contains(key) && locked(key)
    });

    if not_granted.is_empty() && restricted_refused.is_empty() {
        return Ok(Provenance {
            team: team_name,
            restricted_honoured: only(&requested, &restricted),
            restricted_refused: if step == ResolutionStep::GrantDefault {
                default_refused
            } else {
                Vec::new()
            },
            step,
            resolved: requested,
            dropped_not_granted: Vec::new(),
        });
    }

    match config.on_not_granted {
        OnNotGranted::Deny => Err(NotGranted {
            team: team_name,
            requested: only(&requested, &|key| {
                !grant.allowed.contains(key) || locked(key)
            }),
            restricted_refused,
        }),
        OnNotGranted::Default => {
            let mut refused = restricted_refused;
            for key in default_refused {
                if !refused.contains(&key) {
                    refused.push(key);
                }
            }
            Ok(Provenance {
                team: team_name,
                step: ResolutionStep::GrantDefault,
                restricted_honoured: only(&default, &restricted),
                resolved: default,
                dropped_not_granted: not_granted,
                restricted_refused: refused,
            })
        }
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
        Enforcement, FeatureMode, NetworkProfilesConfig, Profile, ProfileCatalog,
        ProfileNamespaceSelection, Resolved, Selector, Variant, WorkspaceSelection,
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
            restricted: false,
        }
    }

    fn catalog() -> ProfileCatalog {
        ProfileCatalog::new(vec![profile("base"), profile("git"), profile("vault")])
    }

    fn config(
        baseline: &str,
        grants: BTreeMap<String, ProfileGrant>,
    ) -> ResolvedNetworkProfilesConfig {
        Resolved::without_teams(NetworkProfilesConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            baseline: ProfileKey::new(baseline),
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: Enforcement::default(),
            namespace_grant: Default::default(),
        })
        .with_grants(grants)
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
        let provenance = resolve(&[], &cfg, &BTreeMap::new(), None, None, None).unwrap();
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
            None,
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
            None,
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
            None,
            Some("vault"),
        )
        .unwrap_err();
        assert_eq!(err.team, Some(TeamName::new("team-2")));
        assert_eq!(err.requested, vec![ProfileKey::new("vault")]);
    }

    #[test]
    fn the_invalid_key_is_refused_under_deny_and_flagged_under_default() {
        let teams = [team("team-1", "team-1")];
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let mut cfg = config("base", grants);
        let ns = labels(&[("weebo.io/team", "team-1")]);
        let invalid = vec![ProfileKey::new(INVALID_KEY)];
        let provenance = resolve(&teams, &cfg, &ns, None, None, Some(INVALID_KEY)).unwrap();
        assert_eq!(provenance.dropped_not_granted, invalid);
        cfg.on_not_granted = OnNotGranted::Deny;
        let err = resolve(&teams, &cfg, &ns, None, None, Some(INVALID_KEY)).unwrap_err();
        assert_eq!(err.requested, invalid);
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
            None,
            Some("git, vault ,git"),
        )
        .unwrap();
        assert_eq!(
            provenance.resolved,
            vec![ProfileKey::new("git"), ProfileKey::new("vault")]
        );
    }

    /// Team-1 reaches `git` and `internet`, `internet` is restricted; `default` is `[git]` unless
    /// a test says otherwise.
    fn restricted_config(on_not_granted: OnNotGranted) -> ResolvedNetworkProfilesConfig {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git"), ProfileKey::new("internet")],
                default: vec![ProfileKey::new("git")],
            },
        );
        let mut cfg = config("base", grants);
        let mut internet = profile("internet");
        internet.restricted = true;
        cfg.catalog = ProfileCatalog::new(vec![profile("base"), profile("git"), internet]);
        cfg.on_not_granted = on_not_granted;
        cfg
    }

    fn resolve_team1(
        cfg: &ResolvedNetworkProfilesConfig,
        selection: Option<&str>,
        grant: Option<&str>,
        attribute: Option<&str>,
    ) -> Result<Provenance, NotGranted> {
        resolve(
            &[team("team-1", "team-1")],
            cfg,
            &labels(&[("weebo.io/team", "team-1")]),
            selection,
            grant,
            attribute,
        )
    }

    /// RFC 0021 S1 (T-07): the workspace names `internet` itself; the namespace grants nothing.
    #[test]
    fn a_restricted_key_requested_by_the_attribute_without_the_namespace_grant_is_not_granted() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, None, None, Some("internet")).unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert_eq!(
            provenance.restricted_refused,
            vec![ProfileKey::new("internet")]
        );
        assert!(provenance.restricted_honoured.is_empty());
        assert!(
            provenance.dropped_not_granted.is_empty(),
            "a restricted refusal is not an ungranted key"
        );
    }

    #[test]
    fn a_restricted_key_named_by_the_grant_annotation_is_honoured() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, None, Some("internet"), Some("git,internet")).unwrap();
        assert_eq!(provenance.step, ResolutionStep::WorkspaceAttribute);
        assert_eq!(
            provenance.resolved,
            vec![ProfileKey::new("git"), ProfileKey::new("internet")]
        );
        assert_eq!(
            provenance.restricted_honoured,
            vec![ProfileKey::new("internet")]
        );
        assert!(provenance.restricted_refused.is_empty());
    }

    /// The selection annotation is selection only: naming `internet` there grants nothing.
    #[test]
    fn the_selection_annotation_does_not_grant_a_restricted_key() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, Some("internet"), None, None).unwrap();
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert_eq!(
            provenance.restricted_refused,
            vec![ProfileKey::new("internet")]
        );
    }

    /// RFC 0021 S11: a grant unlocks; what an attribute-less workspace gets does not move.
    #[test]
    fn a_grant_never_selects() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, None, Some("internet"), None).unwrap();
        assert_eq!(provenance.step, ResolutionStep::GrantDefault);
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert!(provenance.restricted_honoured.is_empty());
        assert!(provenance.restricted_refused.is_empty());
    }

    #[test]
    fn the_grant_annotation_is_read_as_a_set() {
        let cfg = restricted_config(OnNotGranted::Default);
        for grant in [
            " internet ",
            "nope,,internet",
            "internet,internet",
            "git , internet",
        ] {
            let provenance = resolve_team1(&cfg, None, Some(grant), Some("internet")).unwrap();
            assert_eq!(
                provenance.resolved,
                vec![ProfileKey::new("internet")],
                "{grant:?}"
            );
        }
        for grant in ["", "internet;git", "Internet"] {
            let provenance = resolve_team1(&cfg, None, Some(grant), Some("internet")).unwrap();
            assert_eq!(
                provenance.restricted_refused,
                vec![ProfileKey::new("internet")],
                "{grant:?}"
            );
        }
    }

    /// The grant never widens past the team catalogue: an ungranted key stays the ordinary
    /// not-granted case.
    #[test]
    fn an_annotation_naming_a_key_the_team_lacks_unlocks_nothing() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, None, Some("vault"), Some("vault")).unwrap();
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert_eq!(
            provenance.dropped_not_granted,
            vec![ProfileKey::new("vault")]
        );
        assert!(provenance.restricted_refused.is_empty());
    }

    /// RFC 0021 S5, runtime side: a restricted default is filtered, reported, never denied.
    #[test]
    fn a_restricted_default_is_a_violation_and_is_filtered() {
        let mut cfg = restricted_config(OnNotGranted::Deny);
        cfg.grants.get_mut("team-1").unwrap().default =
            vec![ProfileKey::new("git"), ProfileKey::new("internet")];
        let provenance = resolve_team1(&cfg, None, None, None).unwrap();
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert_eq!(
            provenance.restricted_refused,
            vec![ProfileKey::new("internet")]
        );

        let granted = resolve_team1(&cfg, None, Some("internet"), None).unwrap();
        assert_eq!(
            granted.resolved,
            vec![ProfileKey::new("git"), ProfileKey::new("internet")]
        );
    }

    #[test]
    fn under_deny_a_restricted_refusal_is_named_as_restricted() {
        let cfg = restricted_config(OnNotGranted::Deny);
        let err = resolve_team1(&cfg, None, None, Some("git,internet")).unwrap_err();
        assert_eq!(err.requested, vec![ProfileKey::new("internet")]);
        assert!(err.restricted());

        let mixed = resolve_team1(&cfg, None, None, Some("internet,vault")).unwrap_err();
        assert_eq!(
            mixed.requested,
            vec![ProfileKey::new("internet"), ProfileKey::new("vault")]
        );
        assert_eq!(mixed.restricted_refused, vec![ProfileKey::new("internet")]);
        assert!(!mixed.restricted());
    }

    #[test]
    fn non_restricted_keys_ignore_the_grant_annotation() {
        let cfg = restricted_config(OnNotGranted::Default);
        let provenance = resolve_team1(&cfg, None, Some("git"), Some("git")).unwrap();
        assert_eq!(provenance.resolved, vec![ProfileKey::new("git")]);
        assert!(provenance.restricted_honoured.is_empty());
        assert!(provenance.restricted_refused.is_empty());
    }
}
