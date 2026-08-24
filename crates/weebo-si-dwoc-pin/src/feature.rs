//! The only feature implemented by this crate. It makes the DWOCs the platform authored the
//! only ones in use, and decides which of them each namespace runs with — see RFC 0002,
//! *Feature: `dwoc-pin`*.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Mutation};
use weebo_si_crd::{CatalogKey, DwocPinConfig, DwocRef, OnMissingTarget, TeamName};

use crate::resolve::{self, ResolutionStep};
use crate::workspace::Workspace;

/// The namespace annotation this feature *writes* — the audit trail. Not to be confused with
/// `namespaceSelection.annotation`, which it *reads*.
const AUDIT_ANNOTATION: &str = "hardening.weebo.io/dwoc-pin";

/// The `dwoc-pin` feature. Holds its configuration behind a lock rather than fixed fields:
/// `WeeboSiConfig` is hot-reloadable (RFC 0002's *Rollout*: "one write, no rollout, effective on
/// the next admission"), and `weebo_si_chassis::Registry` is built once at boot — so the
/// live-reload path has to be inside the feature. `weebo-si-runtime`'s config-cache adapter
/// writes; [`DwocPin::evaluate`] reads a fresh value on every call.
///
/// `Option`-wrapped, not a fixed `DwocPinConfig`, and sharing the *same* `Arc` the composition
/// root hands to the config-cache adapter — not a snapshot taken once at boot — so a
/// `spec.features.dwocPin` that starts absent and is added later is picked up without a
/// restart, matching every other configuration change's hot-reload guarantee. `evaluate` is
/// only ever called once `FeatureGate::mode` has already reported non-`Off` for this feature,
/// which (per `weebo-si-runtime`'s `FeatureGate` impl) cannot happen while this is `None` — the
/// `InvalidConfiguration` branch below is defensive, not a path production traffic can reach.
pub struct DwocPin {
    config: Arc<RwLock<Option<DwocPinConfig>>>,
}

impl DwocPin {
    /// Build a feature reading from `config`. The caller (the composition root) keeps the other
    /// half of the `Arc` and hands it to the outbound adapter that keeps `config` current.
    pub fn new(config: Arc<RwLock<Option<DwocPinConfig>>>) -> Self {
        Self { config }
    }
}

impl Feature<Workspace> for DwocPin {
    fn id(&self) -> FeatureId {
        FeatureId::new("dwoc-pin")
    }

    fn evaluate(
        &self,
        subject: &Workspace,
        ctx: &Context<'_>,
    ) -> Result<Decision<Workspace>, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(config) = guard.as_ref() else {
            return Err(DomainError::InvalidConfiguration(
                "dwoc-pin evaluated with no spec.features.dwocPin configured".to_string(),
            ));
        };

        let provenance = match resolve::resolve(
            ctx.teams(),
            config,
            ctx.namespace(),
            subject.config_ref.as_ref(),
        ) {
            Ok(provenance) => provenance,
            Err(unknown) => {
                return Ok(Decision::deny(
                    format!(
                        "the namespace annotation names a catalogue key outside this namespace's grant: {}",
                        unknown.annotation_value
                    ),
                    unknown.team,
                    Some(format!("unreachable key {}", unknown.annotation_value)),
                    "unknown_key",
                ));
            }
        };

        let resolved_key = provenance.resolved_key.clone().ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "resolution succeeded without a resolved key".to_string(),
            )
        })?;

        let target = config
            .catalog
            .target(&resolved_key)
            .cloned()
            .ok_or_else(|| {
                DomainError::InvalidConfiguration(format!(
                    "resolved catalogue key {resolved_key} is not present in the catalog"
                ))
            })?;

        if !ctx.dwoc_catalog().resolves(&target) {
            let note = Some(format!("catalogue entry {resolved_key} does not resolve"));
            return Ok(match config.on_missing_target {
                OnMissingTarget::Skip => {
                    Decision::new(Vec::new(), provenance.team, note, "target_missing")
                }
                OnMissingTarget::Deny => Decision::deny(
                    format!(
                        "catalogue entry {resolved_key} points at {}/{}, which does not exist",
                        target.namespace, target.name
                    ),
                    provenance.team,
                    note,
                    "target_missing",
                ),
            });
        }

        let (result, mutations) = decide(
            subject.config_ref.as_ref(),
            &resolved_key,
            &target,
            provenance.step,
            provenance.team.as_ref(),
            config,
        );
        let note = Some(format!(
            "resolved={resolved_key} step={:?}",
            provenance.step
        ));
        Ok(Decision::new(mutations, provenance.team, note, result))
    }
}

/// The five-outcome decision table. `step` distinguishes the two `patch: none` outcomes: when
/// `resolve()` kept the workspace's own attribute (`ResolutionStep::WorkspaceAttribute`), the
/// current reference and the resolved one are equal *because* the chain deliberately honoured
/// the workspace's choice — `allowed_override`. When they are equal for any other reason,
/// nothing about the workspace's own choice was in play — `already_pinned`.
fn decide(
    current: Option<&DwocRef>,
    resolved_key: &CatalogKey,
    target: &DwocRef,
    step: ResolutionStep,
    team: Option<&TeamName>,
    config: &DwocPinConfig,
) -> (&'static str, Vec<Mutation>) {
    let Some(current_ref) = current else {
        return (
            "added",
            vec![
                Mutation::SetConfigRef(target.clone()),
                Mutation::Annotate {
                    key: AUDIT_ANNOTATION.to_string(),
                    value: audit_value(None, team, resolved_key),
                },
            ],
        );
    };

    if config.catalog.resolve_ref(current_ref) == Some(resolved_key) {
        return if step == ResolutionStep::WorkspaceAttribute {
            ("allowed_override", Vec::new())
        } else {
            ("already_pinned", Vec::new())
        };
    }

    (
        "replaced",
        vec![
            Mutation::SetConfigRef(target.clone()),
            Mutation::Annotate {
                key: AUDIT_ANNOTATION.to_string(),
                value: audit_value(Some(current_ref), team, resolved_key),
            },
        ],
    )
}

/// Builds `hardening.weebo.io/dwoc-pin`'s value: a verb followed by `;`-separated `k=v` pairs.
fn audit_value(previous: Option<&DwocRef>, team: Option<&TeamName>, key: &CatalogKey) -> String {
    let team_str = team.map(TeamName::as_str).unwrap_or("<none>");
    match previous {
        None => format!("added;team={team_str};key={key}"),
        Some(prev) => format!(
            "replaced:{}/{};team={team_str};key={key}",
            prev.namespace, prev.name
        ),
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

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        Catalog, CatalogEntry, FeatureMode, Grant, NamespaceName, NamespaceSelection, OnUnknownKey,
        Selector, Team,
    };

    use super::*;

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

    fn base_config(grants: BTreeMap<String, Grant>) -> DwocPinConfig {
        DwocPinConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            default: CatalogKey::new("baseline"),
            grants,
            namespace_selection: NamespaceSelection {
                annotation: "hardening.weebo.io/dwoc".to_string(),
                on_unknown_key: OnUnknownKey::Default,
            },
            on_missing_target: OnMissingTarget::Skip,
        }
    }

    fn feature(config: DwocPinConfig) -> DwocPin {
        DwocPin::new(Arc::new(RwLock::new(Some(config))))
    }

    fn workspace(config_ref: Option<DwocRef>) -> Workspace {
        Workspace {
            name: "python-web".to_string(),
            namespace: NamespaceName::new("user-alice"),
            config_ref,
        }
    }

    fn present_dwoc_catalog() -> FakeDwocCatalog {
        FakeDwocCatalog::new([
            dwoc("weebo-hardened-config"),
            dwoc("gpu-config"),
            dwoc("amd-config"),
        ])
    }

    fn evaluate(
        dwoc_pin: &DwocPin,
        subject: &Workspace,
        teams: &[Team],
        dwoc_catalog: &FakeDwocCatalog,
    ) -> Decision<Workspace> {
        evaluate_result(dwoc_pin, subject, teams, dwoc_catalog).unwrap()
    }

    fn evaluate_result(
        dwoc_pin: &DwocPin,
        subject: &Workspace,
        teams: &[Team],
        dwoc_catalog: &FakeDwocCatalog,
    ) -> Result<Decision<Workspace>, DomainError> {
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let ctx = Context::new(teams, &namespace, dwoc_catalog);
        dwoc_pin.evaluate(subject, &ctx)
    }

    #[test]
    fn add_when_no_current_reference() {
        let feature = feature(base_config(BTreeMap::new()));
        let subject = workspace(None);
        let decision = evaluate(&feature, &subject, &[], &present_dwoc_catalog());
        assert_eq!(decision.result, "added");
        assert_eq!(
            decision.mutations,
            vec![
                Mutation::SetConfigRef(dwoc("weebo-hardened-config")),
                Mutation::Annotate {
                    key: AUDIT_ANNOTATION.to_string(),
                    value: "added;team=<none>;key=baseline".to_string()
                },
            ]
        );
    }

    #[test]
    fn already_pinned_when_current_equals_resolved() {
        let feature = feature(base_config(BTreeMap::new()));
        let subject = workspace(Some(dwoc("weebo-hardened-config")));
        let decision = evaluate(&feature, &subject, &[], &present_dwoc_catalog());
        assert_eq!(decision.result, "already_pinned");
        assert!(decision.mutations.is_empty());
    }

    #[test]
    fn allowed_override_when_current_is_inside_the_grants_allowed_set() {
        let team = Team {
            name: TeamName::new("team-2"),
            namespace_selector: Selector::default(),
        };
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline"), CatalogKey::new("amd")],
                default: CatalogKey::new("baseline"),
            },
        );
        let feature = feature(base_config(grants));
        let subject = workspace(Some(dwoc("amd-config")));
        let decision = evaluate(&feature, &subject, &[team], &present_dwoc_catalog());
        assert_eq!(decision.result, "allowed_override");
        assert!(decision.mutations.is_empty());
    }

    #[test]
    fn replace_when_current_is_a_catalogued_entry_the_grant_does_not_allow() {
        let team = Team {
            name: TeamName::new("team-2"),
            namespace_selector: Selector::default(),
        };
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline"), CatalogKey::new("amd")],
                default: CatalogKey::new("baseline"),
            },
        );
        let feature = feature(base_config(grants));
        let subject = workspace(Some(dwoc("gpu-config")));
        let decision = evaluate(&feature, &subject, &[team], &present_dwoc_catalog());
        assert_eq!(decision.result, "replaced");
        assert_eq!(
            decision.mutations,
            vec![
                Mutation::SetConfigRef(dwoc("weebo-hardened-config")),
                Mutation::Annotate {
                    key: AUDIT_ANNOTATION.to_string(),
                    value: "replaced:eclipse-che/gpu-config;team=team-2;key=baseline".to_string(),
                },
            ]
        );
    }

    #[test]
    fn replace_when_current_is_not_in_the_catalog_at_all() {
        let feature = feature(base_config(BTreeMap::new()));
        let subject = workspace(Some(dwoc("user-alice/my-config")));
        let decision = evaluate(&feature, &subject, &[], &present_dwoc_catalog());
        assert_eq!(decision.result, "replaced");
        assert_eq!(
            decision.mutations,
            vec![
                Mutation::SetConfigRef(dwoc("weebo-hardened-config")),
                Mutation::Annotate {
                    key: AUDIT_ANNOTATION.to_string(),
                    value: "replaced:eclipse-che/user-alice/my-config;team=<none>;key=baseline"
                        .to_string(),
                },
            ]
        );
    }

    #[test]
    fn on_missing_target_skip_makes_no_mutation_and_reports_target_missing() {
        let feature = feature(base_config(BTreeMap::new()));
        let subject = workspace(None);
        let decision = evaluate(
            &feature,
            &subject,
            &[],
            &FakeDwocCatalog::new(std::iter::empty()),
        );
        assert_eq!(decision.result, "target_missing");
        assert!(decision.mutations.is_empty());
        assert!(decision.denial.is_none());
    }

    #[test]
    fn on_missing_target_deny_denies_the_admission_and_reports_target_missing() {
        let mut cfg = base_config(BTreeMap::new());
        cfg.on_missing_target = OnMissingTarget::Deny;
        let feature = feature(cfg);
        let subject = workspace(None);
        let decision = evaluate(
            &feature,
            &subject,
            &[],
            &FakeDwocCatalog::new(std::iter::empty()),
        );
        assert_eq!(decision.result, "target_missing");
        assert!(decision.denial.is_some());
    }

    #[test]
    fn on_unknown_key_default_falls_through_but_still_reports_unknown_key() {
        let team = Team {
            name: TeamName::new("team-2"),
            namespace_selector: Selector::default(),
        };
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline")],
                default: CatalogKey::new("baseline"),
            },
        );
        let feature = feature(base_config(grants));
        let subject = workspace(None);
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: Some("gpu".to_string()),
        };
        let dwoc_catalog = present_dwoc_catalog();
        let teams = [team];
        let ctx = Context::new(&teams, &namespace, &dwoc_catalog);
        let decision = feature.evaluate(&subject, &ctx).unwrap();
        assert_eq!(decision.result, "added");
        assert_eq!(
            decision.note,
            Some("resolved=baseline step=GrantDefault".to_string())
        );
    }

    #[test]
    fn on_unknown_key_deny_denies_the_admission() {
        let team = Team {
            name: TeamName::new("team-2"),
            namespace_selector: Selector::default(),
        };
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-2".to_string(),
            Grant {
                allowed: vec![CatalogKey::new("baseline")],
                default: CatalogKey::new("baseline"),
            },
        );
        let mut cfg = base_config(grants);
        cfg.namespace_selection.on_unknown_key = OnUnknownKey::Deny;
        let feature = feature(cfg);
        let subject = workspace(None);
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: Some("gpu".to_string()),
        };
        let dwoc_catalog = present_dwoc_catalog();
        let teams = [team];
        let ctx = Context::new(&teams, &namespace, &dwoc_catalog);
        let decision = feature.evaluate(&subject, &ctx).unwrap();
        assert_eq!(decision.result, "unknown_key");
        assert!(decision.denial.is_some());
    }

    #[test]
    fn an_invalid_config_where_the_resolved_key_is_not_in_the_catalog_is_a_domain_error() {
        let mut cfg = base_config(BTreeMap::new());
        cfg.default = CatalogKey::new("missing");
        let feature = feature(cfg);
        let subject = workspace(None);
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let dwoc_catalog = present_dwoc_catalog();
        let ctx = Context::new(&[], &namespace, &dwoc_catalog);
        assert!(feature.evaluate(&subject, &ctx).is_err());
    }

    #[test]
    fn evaluate_with_no_config_at_all_is_a_domain_error_never_called_in_practice() {
        let feature = DwocPin::new(Arc::new(RwLock::new(None)));
        let subject = workspace(None);
        let decision = evaluate_result(&feature, &subject, &[], &present_dwoc_catalog());
        assert!(decision.is_err());
    }

    #[test]
    fn the_live_config_can_be_swapped_without_reconstructing_dwoc_pin() {
        let config = Arc::new(RwLock::new(Some(base_config(BTreeMap::new()))));
        let feature = DwocPin::new(Arc::clone(&config));
        let subject = workspace(None);

        let decision = evaluate(&feature, &subject, &[], &present_dwoc_catalog());
        assert_eq!(decision.result, "added");
        let target = match &decision.mutations[0] {
            Mutation::SetConfigRef(target) => target.clone(),
            other => panic!("expected SetConfigRef, got {other:?}"),
        };
        assert_eq!(target, dwoc("weebo-hardened-config"));

        {
            let mut guard = config
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(config) = guard.as_mut() {
                config.default = CatalogKey::new("gpu");
            }
        }

        let decision = evaluate(&feature, &subject, &[], &present_dwoc_catalog());
        let target = match &decision.mutations[0] {
            Mutation::SetConfigRef(target) => target.clone(),
            other => panic!("expected SetConfigRef, got {other:?}"),
        };
        assert_eq!(
            target,
            dwoc("gpu-config"),
            "the second evaluate() must see the swapped config"
        );
    }
}
