//! The parse-dependent half of `spec.features.imagePolicy`'s validation, and the one function
//! callers should use.
//!
//! [`weebo_si_crd::ResolvedImagePolicyConfig::validate`] proves everything structural without a parser;
//! this proves the rest, and [`validate`] runs both. The split is what the dependency direction
//! forces — `weebo-si-crd` is this crate's dependency, so it cannot call
//! [`crate::pattern::Pattern::parse`] — and it is recorded in that module's own header rather
//! than left to be rediscovered.

use weebo_si_crd::{
    FeatureMode, ImagePolicyConfigViolation, ImageRewriteConfig, Operator, RESERVED_VARIABLES,
    ResolvedImagePolicyConfig, Team,
};

use crate::pattern::Pattern;
use crate::platform::platform_patterns;
use crate::rewrite::Rules;

/// The label the chart's pod webhooks select on (`templates/mutatingwebhookconfiguration.yaml`):
/// a namespace without it gets no `/mutate/v1/pods` call, so its injected images are never
/// rewritten (RFC 0017, T10).
pub const POD_WEBHOOK_LABEL: &str = "hardening.weebo.io/workspace-namespace";
use crate::variable::{PathComponent, VariableName};

/// Every violation this configuration has — structural and parse-dependent, in that order.
///
/// Returns all of them rather than the first, mirroring `ResolvedNetworkProfilesConfig::validate`: the
/// reconcile loop reports one `Degraded` condition per violation, and an admin fixing a
/// catalogue wants the whole list rather than one round trip per mistake.
pub fn validate(
    config: &ResolvedImagePolicyConfig,
    teams: &[Team],
) -> Vec<ImagePolicyConfigViolation> {
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
    if let Err((raw, reason)) = platform_patterns(&config.platform, None) {
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

/// RFC 0017's `image-rewrite` warnings, worded as its *Operational considerations* table fixes
/// them: things that work but not as the admin probably meant, reported in the feature's status
/// message and never as `Degraded`. Empty when the feature is `Off` — nothing runs to warn about.
///
/// `policy` is `imagePolicy`, when present: without it nothing judges a rewritten image, so no
/// rule can be "refused by every pattern".
pub fn rewrite_warnings(
    config: &ImageRewriteConfig,
    rules: &Rules,
    policy: Option<&ResolvedImagePolicyConfig>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.mode == FeatureMode::Off {
        return warnings;
    }
    if rules.is_empty() {
        warnings.push("no rules: nothing is rewritten".to_string());
    }
    if let Some(policy) = policy {
        let mut patterns = platform_patterns(&policy.platform, Some(rules)).unwrap_or_default();
        patterns.extend(
            policy
                .catalog
                .entries()
                .iter()
                .flat_map(|entry| &entry.patterns)
                .filter_map(|raw| Pattern::parse(raw).ok()),
        );
        for (from, to) in rules.iter() {
            let (host, prefix) = to.split_once('/').unwrap_or((&to, ""));
            if !patterns
                .iter()
                .any(|pattern| pattern.may_match_under(host, prefix))
            {
                warnings.push(format!(
                    "rule {from} → {to}: no imagePolicy pattern permits anything under it"
                ));
            }
        }
    }
    let requires_label = config.namespace_selector.as_ref().is_some_and(|selector| {
        selector.match_labels.contains_key(POD_WEBHOOK_LABEL)
            || selector.match_expressions.iter().any(|expression| {
                expression.key == POD_WEBHOOK_LABEL
                    && matches!(expression.operator, Operator::Exists | Operator::In)
            })
    });
    if !requires_label {
        warnings.push(format!(
            "selects namespaces without {POD_WEBHOOK_LABEL}: injected images there are not rewritten"
        ));
    }
    warnings
}

/// Whether `name` may be used in a pattern under this configuration — the two built in, plus
/// whatever `spec.variables` declares. Exposed for `images check`, which reports an undeclared
/// name the same way this validator does.
pub fn is_usable_variable(config: &ResolvedImagePolicyConfig, name: &VariableName) -> bool {
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
        ImagePolicyConfig, ImageWorkspaceSelection, OnUnknownKey, PlatformConfig, Resolved,
        Selector, TeamName, VariableBinding,
    };

    use super::*;

    fn entry(key: &str, patterns: &[&str]) -> Entry {
        Entry {
            key: EntryKey::new(key),
            patterns: patterns.iter().map(|p| (*p).to_string()).collect(),
        }
    }

    fn config(entries: Vec<Entry>, default: &[&str]) -> ResolvedImagePolicyConfig {
        Resolved::without_teams(ImagePolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: ImageCatalog::new(entries),
            variables: BTreeMap::new(),
            default: default.iter().map(|k| EntryKey::new(*k)).collect(),
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
        })
    }

    fn rewrite(selector: Option<Selector>, rules: &[(&str, &str)]) -> ImageRewriteConfig {
        ImageRewriteConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: selector,
            rules: rules
                .iter()
                .map(|(from, to)| weebo_si_crd::RewriteRule {
                    from: (*from).to_string(),
                    to: (*to).to_string(),
                })
                .collect(),
        }
    }

    fn workspace_selector() -> Option<Selector> {
        Some(Selector {
            match_labels: BTreeMap::from([(POD_WEBHOOK_LABEL.to_string(), "true".to_string())]),
            match_expressions: Vec::new(),
        })
    }

    fn warnings(config: &ImageRewriteConfig, policy: &ResolvedImagePolicyConfig) -> Vec<String> {
        rewrite_warnings(config, &Rules::new(config).unwrap(), Some(policy))
    }

    #[test]
    fn selector_wider_than_pod_webhook_warns() {
        // RFC 0017, T10: no selector, or one not requiring the pod webhook's label, selects
        // namespaces whose injected images the pod route never sees.
        let policy = config(
            vec![entry("mirror", &["registry.pkg.weebo.poc/**"])],
            &["mirror"],
        );
        let rules = [("quay.io", "registry.pkg.weebo.poc/quay")];
        let wider = "selects namespaces without hardening.weebo.io/workspace-namespace: \
                     injected images there are not rewritten";
        assert_eq!(warnings(&rewrite(None, &rules), &policy), vec![wider]);
        let other = Some(Selector {
            match_labels: BTreeMap::from([("team".to_string(), "a".to_string())]),
            match_expressions: Vec::new(),
        });
        assert_eq!(warnings(&rewrite(other, &rules), &policy), vec![wider]);
        assert!(warnings(&rewrite(workspace_selector(), &rules), &policy).is_empty());
        let exists = Some(Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![weebo_si_crd::Expression {
                key: POD_WEBHOOK_LABEL.to_string(),
                operator: Operator::Exists,
                values: Vec::new(),
            }],
        });
        assert!(warnings(&rewrite(exists, &rules), &policy).is_empty());
    }

    #[test]
    fn a_rule_no_pattern_permits_and_an_empty_set_warn_and_off_warns_nothing() {
        let policy = config(
            vec![entry("hub", &["registry.pkg.weebo.poc/hub/**"])],
            &["hub"],
        );
        let config = rewrite(
            workspace_selector(),
            &[
                ("docker.io", "registry.pkg.weebo.poc/hub"),
                ("ghcr.io", "registry.pkg.weebo.poc/ghcr"),
            ],
        );
        assert_eq!(
            warnings(&config, &policy),
            vec![
                "rule ghcr.io → registry.pkg.weebo.poc/ghcr: no imagePolicy pattern permits \
                 anything under it"
            ]
        );
        // `quay.io`'s rule is permitted by the patterns it derives from the builtin list.
        let quay = rewrite(
            workspace_selector(),
            &[("quay.io", "registry.pkg.weebo.poc/quay")],
        );
        assert!(warnings(&quay, &policy).is_empty());
        let empty = rewrite(workspace_selector(), &[]);
        assert_eq!(
            warnings(&empty, &policy),
            vec!["no rules: nothing is rewritten"]
        );
        let mut off = rewrite(None, &[]);
        off.mode = FeatureMode::Off;
        assert!(rewrite_warnings(&off, &Rules::default(), Some(&policy)).is_empty());
    }

    fn team(name: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector::default(),
        }
    }

    fn declare(config: &mut ResolvedImagePolicyConfig, name: &str, annotation: &str) {
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
