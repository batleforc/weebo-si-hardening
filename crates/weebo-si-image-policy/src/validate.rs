//! The parse-dependent half of `spec.features.imagePolicy`'s validation, and the one function
//! callers should use.
//!
//! [`weebo_si_crd::ImagePolicyConfig::validate`] proves everything structural without a parser;
//! this proves the rest, and [`validate`] runs both. The split is what the dependency direction
//! forces — `weebo-si-crd` is this crate's dependency, so it cannot call
//! [`crate::pattern::Pattern::parse`] — and it is recorded in that module's own header rather
//! than left to be rediscovered.

use weebo_si_crd::{ImagePolicyConfig, ImagePolicyConfigViolation, RESERVED_VARIABLES, Team};

use crate::pattern::Pattern;
use crate::platform::platform_patterns;
use crate::variable::{PathComponent, VariableName};

/// Every violation this configuration has — structural and parse-dependent, in that order.
///
/// Returns all of them rather than the first, mirroring `NetworkProfilesConfig::validate`: the
/// reconcile loop reports one `Degraded` condition per violation, and an admin fixing a
/// catalogue wants the whole list rather than one round trip per mistake.
pub fn validate(config: &ImagePolicyConfig, teams: &[Team]) -> Vec<ImagePolicyConfigViolation> {
    let mut violations = config.validate(teams);

    // Which names a pattern may legally use: the two built in, plus whatever `spec.variables`
    // declared. A name outside this set is a reported typo, never a literal — "never matches"
    // is indistinguishable from "correctly restrictive" from the outside.
    let declared: Vec<&str> = config.variables.keys().map(String::as_str).collect();
    let mut used_variables: Vec<String> = Vec::new();
    let mut any_pattern_uses_team_name = false;

    for entry in config.catalog.entries() {
        for raw in &entry.patterns {
            let pattern = match Pattern::parse(raw) {
                Ok(pattern) => pattern,
                Err(reason) => {
                    violations.push(ImagePolicyConfigViolation::UnparseablePattern {
                        entry: entry.key.clone(),
                        pattern: raw.clone(),
                        reason: reason.to_string(),
                    });
                    continue;
                }
            };
            for name in pattern.variables() {
                if !used_variables.iter().any(|seen| seen == name.as_str()) {
                    used_variables.push(name.as_str().to_string());
                }
                if name.is_builtin() {
                    continue;
                }
                if !declared.contains(&name.as_str()) {
                    violations.push(ImagePolicyConfigViolation::UndeclaredVariable {
                        entry: entry.key.clone(),
                        pattern: raw.clone(),
                        variable: name.as_str().to_string(),
                    });
                }
            }
            if pattern.interpolates_team_name() {
                any_pattern_uses_team_name = true;
            }
        }
    }

    // An unparseable `platform.extra` entry is reported against a synthetic `platform` key: it
    // is not a catalogue entry, and inventing an entry key for it would be less honest than
    // naming the field it came from.
    if let Err((raw, reason)) = platform_patterns(&config.platform) {
        violations.push(ImagePolicyConfigViolation::UnparseablePattern {
            entry: weebo_si_crd::EntryKey::new("platform.extra"),
            pattern: raw,
            reason: reason.to_string(),
        });
    }

    // A declared variable no pattern uses is either a typo in the pattern or a leftover.
    for name in config.variables.keys() {
        if RESERVED_VARIABLES.contains(&name.as_str()) {
            // Already reported as `ReservedVariableName`; reporting it as unused too would be
            // two conditions for one mistake.
            continue;
        }
        if !used_variables.iter().any(|used| used == name) {
            violations.push(ImagePolicyConfigViolation::UnusedVariable(name.clone()));
        }
    }

    // A team name that is not a legal path component can never be substituted into a pattern.
    // Statically checkable, in the admin's own file, and it is not going to become legal at
    // admission time — so the controller catches it at reconcile, loudly. Its per-namespace
    // counterpart (a *declared* variable's illegal value) deliberately does the opposite: see
    // `VariableValues::bind_team`.
    if any_pattern_uses_team_name {
        for team in teams {
            if PathComponent::new(team.name.as_str()).is_err() {
                violations.push(ImagePolicyConfigViolation::TeamNameNotAPathComponent(
                    team.name.clone(),
                ));
            }
        }
    }

    // The top-level `default` applies exactly where there is no team, so an entry whose every
    // pattern interpolates `{TEAM_NAME}` can only ever grant nothing.
    for key in &config.default {
        let Some(entry) = config.catalog.entry(key) else {
            // Already reported as `DefaultUnknownKey`.
            continue;
        };
        let parsed: Vec<Pattern> = entry
            .patterns
            .iter()
            .filter_map(|raw| Pattern::parse(raw).ok())
            .collect();
        if !parsed.is_empty() && parsed.iter().all(Pattern::interpolates_team_name) {
            violations
                .push(ImagePolicyConfigViolation::DefaultEntryInterpolatesTeamName(key.clone()));
        }
    }

    violations
}

/// Whether `name` may be used in a pattern under this configuration — the two built in, plus
/// whatever `spec.variables` declares. Exposed for `images check`, which reports an undeclared
/// name the same way this validator does.
pub fn is_usable_variable(config: &ImagePolicyConfig, name: &VariableName) -> bool {
    name.is_builtin() || config.variables.contains_key(name.as_str())
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
        Entry, EntryKey, FeatureMode, ImageCatalog, ImageGrant, ImageNamespaceSelection,
        ImageWorkspaceSelection, OnUnknownKey, PlatformConfig, Selector, TeamName, VariableBinding,
    };

    use super::*;

    fn entry(key: &str, patterns: &[&str]) -> Entry {
        Entry {
            key: EntryKey::new(key),
            patterns: patterns.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn config(entries: Vec<Entry>, default: &[&str]) -> ImagePolicyConfig {
        ImagePolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: ImageCatalog::new(entries),
            variables: BTreeMap::new(),
            default: default.iter().map(|k| EntryKey::new(*k)).collect(),
            grants: BTreeMap::new(),
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
        }
    }

    fn team(name: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector::default(),
        }
    }

    fn declare(config: &mut ImagePolicyConfig, name: &str, annotation: &str) {
        config.variables.insert(
            name.to_string(),
            VariableBinding {
                from_namespace_annotation: annotation.to_string(),
            },
        );
    }

    #[test]
    fn the_rfcs_own_example_configuration_is_clean() {
        let mut cfg = config(
            vec![
                entry("internal", &["registry.internal/shared/**"]),
                entry("team-registry", &["registry.internal/teams/{TEAM_NAME}/**"]),
                entry(
                    "project-registry",
                    &["registry.internal/projects/{PROJECT}/**"],
                ),
                entry(
                    "devfile-udi",
                    &["quay.io/devfile/universal-developer-image:ubi9-*"],
                ),
                entry("dockerhub-library", &["docker.io/library/**"]),
            ],
            &["internal"],
        );
        declare(&mut cfg, "PROJECT", "weebo.io/project");
        cfg.grants.insert(
            "team-1".to_string(),
            ImageGrant {
                allowed: vec![
                    EntryKey::new("internal"),
                    EntryKey::new("team-registry"),
                    EntryKey::new("devfile-udi"),
                ],
                default: vec![EntryKey::new("internal"), EntryKey::new("team-registry")],
            },
        );
        let violations = validate(&cfg, &[team("team-1")]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn an_unparseable_pattern_is_reported_against_its_entry() {
        let cfg = config(vec![entry("wide", &["*/**"])], &[]);
        assert!(validate(&cfg, &[]).iter().any(|v| matches!(
            v,
            ImagePolicyConfigViolation::UnparseablePattern { entry, .. } if entry.as_str() == "wide"
        )));
    }

    #[test]
    fn an_undeclared_variable_is_a_reported_typo_not_a_literal() {
        // `{TEMA_NAME}` — the RFC's own example. "Never matches" is indistinguishable from
        // "correctly restrictive" from the outside, so it has to be loud.
        let cfg = config(
            vec![entry("typo", &["registry.internal/teams/{TEMA_NAME}/**"])],
            &[],
        );
        assert!(validate(&cfg, &[]).iter().any(|v| matches!(
            v,
            ImagePolicyConfigViolation::UndeclaredVariable { variable, .. }
                if variable == "TEMA_NAME"
        )));
    }

    #[test]
    fn a_declared_variable_is_not_reported_as_undeclared() {
        let mut cfg = config(
            vec![entry(
                "project",
                &["registry.internal/projects/{PROJECT}/**"],
            )],
            &[],
        );
        declare(&mut cfg, "PROJECT", "weebo.io/project");
        assert!(
            !validate(&cfg, &[])
                .iter()
                .any(|v| matches!(v, ImagePolicyConfigViolation::UndeclaredVariable { .. }))
        );
    }

    #[test]
    fn the_two_builtins_never_need_declaring() {
        let cfg = config(
            vec![entry(
                "both",
                &["registry.internal/{NAMESPACE}/{TEAM_NAME}/**"],
            )],
            &[],
        );
        assert!(
            !validate(&cfg, &[team("team-1")])
                .iter()
                .any(|v| matches!(v, ImagePolicyConfigViolation::UndeclaredVariable { .. }))
        );
    }

    #[test]
    fn a_declared_variable_no_pattern_uses_is_reported() {
        let mut cfg = config(vec![entry("internal", &["registry.internal/**"])], &[]);
        declare(&mut cfg, "PROJECT", "weebo.io/project");
        assert!(
            validate(&cfg, &[]).contains(&ImagePolicyConfigViolation::UnusedVariable(
                "PROJECT".to_string()
            ))
        );
    }

    #[test]
    fn rebinding_a_reserved_name_is_one_violation_not_two() {
        let mut cfg = config(vec![entry("internal", &["registry.internal/**"])], &[]);
        declare(&mut cfg, "NAMESPACE", "weebo.io/ns");
        let violations = validate(&cfg, &[]);
        assert!(
            violations.contains(&ImagePolicyConfigViolation::ReservedVariableName(
                "NAMESPACE".to_string()
            ))
        );
        assert!(
            !violations.contains(&ImagePolicyConfigViolation::UnusedVariable(
                "NAMESPACE".to_string()
            ))
        );
    }

    #[test]
    fn an_illegal_team_name_is_reported_only_when_a_pattern_interpolates_it() {
        let interpolating = config(
            vec![entry("teams", &["registry.internal/teams/{TEAM_NAME}/**"])],
            &[],
        );
        let literal = config(vec![entry("shared", &["registry.internal/shared/**"])], &[]);
        let hostile = [team("a/**")];

        assert!(validate(&interpolating, &hostile).contains(
            &ImagePolicyConfigViolation::TeamNameNotAPathComponent(TeamName::new("a/**"))
        ));
        // A team name nothing substitutes is not this feature's business to police.
        assert!(
            !validate(&literal, &hostile)
                .iter()
                .any(|v| matches!(v, ImagePolicyConfigViolation::TeamNameNotAPathComponent(_)))
        );
    }

    #[test]
    fn a_team_name_illegal_only_by_case_or_space_is_still_reported() {
        let cfg = config(
            vec![entry("teams", &["registry.internal/teams/{TEAM_NAME}/**"])],
            &[],
        );
        for name in ["Team One", "TEAM-1", "team_1/x"] {
            assert!(
                validate(&cfg, &[team(name)]).iter().any(|v| matches!(
                    v,
                    ImagePolicyConfigViolation::TeamNameNotAPathComponent(t) if t.as_str() == name
                )),
                "{name:?} is not a legal path component and should be reported"
            );
        }
    }

    #[test]
    fn a_top_level_default_entry_that_can_only_grant_nothing_is_reported() {
        // `default` applies exactly where there is no team, so `{TEAM_NAME}` there is undefined
        // by construction.
        let cfg = config(
            vec![entry("teams", &["registry.internal/teams/{TEAM_NAME}/**"])],
            &["teams"],
        );
        assert!(validate(&cfg, &[]).contains(
            &ImagePolicyConfigViolation::DefaultEntryInterpolatesTeamName(EntryKey::new("teams"))
        ));
    }

    #[test]
    fn a_default_entry_with_one_non_interpolating_pattern_is_fine() {
        let cfg = config(
            vec![entry(
                "mixed",
                &[
                    "registry.internal/teams/{TEAM_NAME}/**",
                    "registry.internal/shared/**",
                ],
            )],
            &["mixed"],
        );
        assert!(!validate(&cfg, &[]).iter().any(|v| matches!(
            v,
            ImagePolicyConfigViolation::DefaultEntryInterpolatesTeamName(_)
        )));
    }

    #[test]
    fn an_unparseable_platform_extra_is_reported_against_the_field_it_came_from() {
        let mut cfg = config(vec![entry("internal", &["registry.internal/**"])], &[]);
        cfg.platform.extra = vec!["*/**".to_string()];
        assert!(validate(&cfg, &[]).iter().any(|v| matches!(
            v,
            ImagePolicyConfigViolation::UnparseablePattern { entry, .. }
                if entry.as_str() == "platform.extra"
        )));
    }

    #[test]
    fn the_structural_half_still_runs_and_both_halves_report_together() {
        let mut cfg = config(vec![entry("wide", &["*/**"])], &["ghost"]);
        declare(&mut cfg, "lowercase", "weebo.io/x");
        let violations = validate(&cfg, &[]);
        assert!(
            violations.contains(&ImagePolicyConfigViolation::DefaultUnknownKey(
                EntryKey::new("ghost")
            ))
        );
        assert!(
            violations.contains(&ImagePolicyConfigViolation::IllegalVariableName(
                "lowercase".to_string()
            ))
        );
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, ImagePolicyConfigViolation::UnparseablePattern { .. }))
        );
    }

    #[test]
    fn is_usable_variable_agrees_with_the_validator() {
        let mut cfg = config(vec![entry("internal", &["registry.internal/**"])], &[]);
        declare(&mut cfg, "PROJECT", "weebo.io/project");
        assert!(is_usable_variable(
            &cfg,
            &VariableName::new("TEAM_NAME").unwrap()
        ));
        assert!(is_usable_variable(
            &cfg,
            &VariableName::new("NAMESPACE").unwrap()
        ));
        assert!(is_usable_variable(
            &cfg,
            &VariableName::new("PROJECT").unwrap()
        ));
        assert!(!is_usable_variable(
            &cfg,
            &VariableName::new("NOPE").unwrap()
        ));
    }
}
