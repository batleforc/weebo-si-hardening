//! `reconcile` and `teardown`: decide, diff against what exists, write only in `Enforce`.

use weebo_si_chassis::managed::{Applied, Diff, compute_diff};
use weebo_si_chassis::{Context, DomainError, ReconcileFeature, Subject};
use weebo_si_crd::{FeatureMode, NamespaceName, QuotaProfileKey, TeamName};

use crate::feature::resource_quotas::{DesiredState, NamespaceSubject};
use crate::model::object::{ManagedQuotaObject, SaturationBand, saturation};
use crate::model::validate::ProfileViolation;
use crate::port::{ForeignObjects, ManagedQuotaStore};

/// One value of `weebo_si_resource_quotas_reconcile_total`'s `result`. A pass can count several.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReconcileResult {
    /// An object was created or updated (`Enforce`), or would be (`DryRun`).
    Applied,
    /// Nothing to write.
    Unchanged,
    /// A managed object was deleted, or would be: the new profile has no template of that kind.
    Deleted,
    /// The annotation named a key the team is not granted.
    NotGranted,
    /// The profile is invalid; the namespace keeps what it has.
    Invalid,
    /// The pass failed.
    Error,
}

impl ReconcileResult {
    /// Every value, for a counter that publishes its zeroes.
    pub const ALL: [ReconcileResult; 6] = [
        Self::Applied,
        Self::Unchanged,
        Self::Deleted,
        Self::NotGranted,
        Self::Invalid,
        Self::Error,
    ];

    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
            Self::Deleted => "deleted",
            Self::NotGranted => "not_granted",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }
}

/// One value of `weebo_si_resource_quotas_namespaces`' `state`. A namespace with a foreign object
/// is reported under it whatever else is true: that is the state that needs a look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NamespaceState {
    /// The namespace carries its profile.
    Applied,
    /// It does not yet: `DryRun`, an invalid profile, or a refused request.
    Pending,
    /// A `ResourceQuota` this feature did not write also applies.
    ForeignQuota,
    /// A `LimitRange` this feature did not write also applies: two sets of defaults.
    ForeignLimitRange,
}

impl NamespaceState {
    /// Every value.
    pub const ALL: [NamespaceState; 4] = [
        Self::Applied,
        Self::Pending,
        Self::ForeignQuota,
        Self::ForeignLimitRange,
    ];

    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Pending => "pending",
            Self::ForeignQuota => "foreign_quota",
            Self::ForeignLimitRange => "foreign_limitrange",
        }
    }
}

/// What one pass decided and, in `Enforce`, did.
#[derive(Debug, Clone, PartialEq)]
pub struct ReconcileOutcome {
    /// The namespace — the log line's subject, never a metric label.
    pub namespace: NamespaceName,
    /// The team that matched.
    pub team: Option<TeamName>,
    /// The profile resolved.
    pub profile: Option<QuotaProfileKey>,
    /// The diff against the managed objects. Empty when the namespace is held.
    pub diffs: Vec<Diff<ManagedQuotaObject>>,
    /// `Some` in `Enforce`: what was written.
    pub applied: Option<Applied>,
    /// Every `result` this pass counts.
    pub results: Vec<ReconcileResult>,
    /// The key the annotation named and the team is not granted.
    pub not_granted: Option<QuotaProfileKey>,
    /// Why the profile was not applied.
    pub violations: Vec<ProfileViolation>,
    /// The objects this feature did not write.
    pub foreign: ForeignObjects,
    /// The managed quota's band, from its status.
    pub saturation: Option<SaturationBand>,
    /// The gauge state.
    pub state: NamespaceState,
}

/// Run one pass. **`mode` must be `DryRun` or `Enforce`**; `Off` is [`teardown`].
pub async fn reconcile(
    feature: &dyn ReconcileFeature<NamespaceSubject, Desired = DesiredState>,
    subject: &NamespaceSubject,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn ManagedQuotaStore,
) -> Result<ReconcileOutcome, DomainError> {
    if mode == FeatureMode::Off {
        return Err(DomainError::InvalidConfiguration(
            "reconcile called with mode Off — the caller must tear down an Off feature rather \
             than reconcile it"
                .to_string(),
        ));
    }
    let desired = feature.desired(subject, ctx)?;
    let namespace = subject.namespace();
    let diffs = if desired.hold {
        Vec::new()
    } else {
        compute_diff(&desired.objects, &store.managed_in(namespace))
    };

    let mut results = Vec::new();
    if desired.not_granted.is_some() {
        results.push(ReconcileResult::NotGranted);
    }
    if !desired.violations.is_empty() {
        results.push(ReconcileResult::Invalid);
    }
    if diffs
        .iter()
        .any(|diff| matches!(diff, Diff::Create(_) | Diff::Update(_)))
    {
        results.push(ReconcileResult::Applied);
    }
    if diffs.iter().any(|diff| matches!(diff, Diff::Delete { .. })) {
        results.push(ReconcileResult::Deleted);
    }
    if !desired.hold
        && results
            .iter()
            .all(|result| *result == ReconcileResult::NotGranted)
    {
        results.push(ReconcileResult::Unchanged);
    }

    let writes = diffs.iter().any(|diff| !matches!(diff, Diff::Unchanged(_)));
    let applied = if mode == FeatureMode::Enforce && writes {
        Some(store.apply(&diffs).await?)
    } else if mode == FeatureMode::Enforce {
        Some(weebo_si_chassis::managed::tally(&diffs))
    } else {
        None
    };

    let foreign = store.foreign_in(namespace);
    let saturation = store
        .usage_in(namespace)
        .and_then(|usage| saturation(&usage.hard, &usage.used));
    let carries_profile = !desired.hold && (mode == FeatureMode::Enforce || !writes);
    let state = if foreign.limit_ranges > 0 {
        NamespaceState::ForeignLimitRange
    } else if foreign.quotas > 0 {
        NamespaceState::ForeignQuota
    } else if carries_profile {
        NamespaceState::Applied
    } else {
        NamespaceState::Pending
    };

    Ok(ReconcileOutcome {
        namespace: namespace.clone(),
        team: desired.team,
        profile: desired.profile,
        diffs,
        applied,
        results,
        not_granted: desired.not_granted,
        violations: desired.violations,
        foreign,
        saturation,
        state,
    })
}

/// Delete every managed object in `namespace` — the rollback `mode: Off` is. Foreign objects are
/// never seen, so never touched.
///
/// **The caller decides that the feature is deliberately off**: a gate answering `Off` while a
/// cache is cold is not an instruction to remove a ceiling.
pub async fn teardown(
    namespace: &NamespaceName,
    store: &dyn ManagedQuotaStore,
) -> Result<Applied, DomainError> {
    let existing = store.managed_in(namespace);
    if existing.is_empty() {
        return Ok(Applied::default());
    }
    store.apply(&compute_diff(&[], &existing)).await
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, RwLock};

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        OnNotGranted, QuotaCatalog, QuotaGrant, QuotaNamespaceSelection, QuotaProfile, Resolved,
        ResolvedResourceQuotasConfig, ResourceQuotasConfig, Selector, Team, TemplateRef,
    };

    use super::*;
    use crate::feature::resource_quotas::ResourceQuotasFeature;
    use crate::model::template::{LimitRangeTemplate, QuotaTemplate};
    use crate::port::QuotaUsage;
    use crate::port::testing::{FakeQuotaStore, FakeTemplateStore};

    const TEMPLATES: &str = "weebo-si-hardening-templates";

    fn reference(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new(TEMPLATES),
        }
    }

    fn key(raw: &str) -> QuotaProfileKey {
        QuotaProfileKey::new(raw)
    }

    fn config(on_not_granted: OnNotGranted) -> ResolvedResourceQuotasConfig {
        Resolved::without_teams(ResourceQuotasConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            catalog: QuotaCatalog::new(vec![
                QuotaProfile {
                    key: key("standard"),
                    quota_ref: Some(reference("quota-standard")),
                    limit_range_ref: Some(reference("limits-standard")),
                },
                QuotaProfile {
                    key: key("counts"),
                    quota_ref: Some(reference("quota-counts")),
                    limit_range_ref: None,
                },
                QuotaProfile {
                    key: key("broken"),
                    quota_ref: Some(reference("quota-standard")),
                    limit_range_ref: None,
                },
            ]),
            default: key("standard"),
            namespace_selection: QuotaNamespaceSelection::default(),
            on_not_granted,
        })
        .with_grants(BTreeMap::from([(
            "team-1".to_string(),
            QuotaGrant {
                allowed: vec![key("standard"), key("counts"), key("broken")],
                default: key("standard"),
            },
        )]))
    }

    fn templates() -> FakeTemplateStore {
        FakeTemplateStore {
            quotas: HashMap::from([
                (
                    reference("quota-standard"),
                    QuotaTemplate {
                        spec: serde_json::json!({"hard": {"requests.cpu": "4", "pods": "20"}}),
                    },
                ),
                (
                    reference("quota-counts"),
                    QuotaTemplate {
                        spec: serde_json::json!({"hard": {"pods": "20", "services.nodeports": "0"}}),
                    },
                ),
            ]),
            limit_ranges: HashMap::from([(
                reference("limits-standard"),
                LimitRangeTemplate {
                    spec: serde_json::json!({"limits": [{"type": "Container", "defaultRequest": {"cpu": "100m"}}]}),
                },
            )]),
        }
    }

    fn feature(on_not_granted: OnNotGranted) -> ResourceQuotasFeature {
        ResourceQuotasFeature::new(
            Arc::new(RwLock::new(Some(config(on_not_granted)))),
            Arc::new(templates()),
            NamespaceName::new(TEMPLATES),
        )
    }

    fn teams() -> Vec<Team> {
        vec![Team {
            name: TeamName::new("team-1"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }]
    }

    fn namespace() -> NamespaceName {
        NamespaceName::new("user-bob")
    }

    async fn pass(
        store: &FakeQuotaStore,
        annotation: Option<&str>,
        mode: FeatureMode,
        on_not_granted: OnNotGranted,
    ) -> ReconcileOutcome {
        let teams = teams();
        let facts = NamespaceFacts {
            labels: BTreeMap::from([("weebo.io/team".to_string(), "team-1".to_string())]),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        reconcile(
            &feature(on_not_granted),
            &NamespaceSubject {
                namespace: namespace(),
                annotation: annotation.map(str::to_string),
            },
            &Context::new(&teams, &facts, &catalog),
            mode,
            store,
        )
        .await
        .unwrap()
    }

    fn names(store: &FakeQuotaStore) -> Vec<String> {
        let mut names: Vec<String> = store.all().into_iter().map(|o| o.key.name).collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn enforce_writes_exactly_the_two_fixed_names() {
        let store = FakeQuotaStore::default();
        let outcome = pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
        assert_eq!(names(&store), vec!["weebo-limits", "weebo-quota"]);
        assert!(
            store
                .all()
                .iter()
                .all(|object| object.profile == key("standard"))
        );
        assert_eq!(outcome.state, NamespaceState::Applied);
    }

    #[tokio::test]
    async fn a_second_pass_is_unchanged_and_writes_nothing() {
        let store = FakeQuotaStore::default();
        pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        let outcome = pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        assert_eq!(outcome.results, vec![ReconcileResult::Unchanged]);
        assert_eq!(*store.applies.read().unwrap(), 1);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let store = FakeQuotaStore::default();
        let outcome = pass(&store, None, FeatureMode::DryRun, OnNotGranted::Default).await;
        assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
        assert_eq!(outcome.diffs.len(), 2);
        assert_eq!(outcome.state, NamespaceState::Pending);
        assert!(store.all().is_empty());
    }

    #[tokio::test]
    async fn switching_to_a_profile_without_a_limit_range_deletes_ours() {
        let store = FakeQuotaStore::default();
        pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        let outcome = pass(
            &store,
            Some("counts"),
            FeatureMode::Enforce,
            OnNotGranted::Default,
        )
        .await;
        assert_eq!(
            outcome.results,
            vec![ReconcileResult::Applied, ReconcileResult::Deleted]
        );
        assert_eq!(names(&store), vec!["weebo-quota"]);
        assert_eq!(store.all()[0].profile, key("counts"));
    }

    #[tokio::test]
    async fn an_invalid_profile_keeps_the_existing_ceiling() {
        let store = FakeQuotaStore::default();
        pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        let before = store.all();
        // `broken` constrains requests.cpu with no LimitRange to default it.
        let outcome = pass(
            &store,
            Some("broken"),
            FeatureMode::Enforce,
            OnNotGranted::Default,
        )
        .await;
        assert_eq!(outcome.results, vec![ReconcileResult::Invalid]);
        assert!(!outcome.violations.is_empty());
        assert!(outcome.diffs.is_empty());
        assert_eq!(store.all(), before);
        assert_eq!(outcome.state, NamespaceState::Pending);
    }

    #[tokio::test]
    async fn an_invalid_profile_on_a_bare_namespace_writes_nothing() {
        let store = FakeQuotaStore::default();
        pass(
            &store,
            Some("broken"),
            FeatureMode::Enforce,
            OnNotGranted::Default,
        )
        .await;
        assert!(store.all().is_empty());
    }

    #[tokio::test]
    async fn not_granted_under_deny_keeps_the_namespace_as_it_is() {
        let store = FakeQuotaStore::default();
        pass(&store, None, FeatureMode::Enforce, OnNotGranted::Deny).await;
        let before = store.all();
        let outcome = pass(
            &store,
            Some("gpu"),
            FeatureMode::Enforce,
            OnNotGranted::Deny,
        )
        .await;
        assert_eq!(outcome.results, vec![ReconcileResult::NotGranted]);
        assert_eq!(store.all(), before);
    }

    #[tokio::test]
    async fn not_granted_under_default_applies_the_default_and_says_so() {
        let store = FakeQuotaStore::default();
        let outcome = pass(
            &store,
            Some("gpu"),
            FeatureMode::Enforce,
            OnNotGranted::Default,
        )
        .await;
        assert_eq!(
            outcome.results,
            vec![ReconcileResult::NotGranted, ReconcileResult::Applied]
        );
        assert_eq!(outcome.profile, Some(key("standard")));
    }

    #[tokio::test]
    async fn foreign_objects_are_counted_never_touched() {
        let store = FakeQuotaStore {
            foreign: HashMap::from([(
                namespace(),
                ForeignObjects {
                    quotas: 1,
                    limit_ranges: 1,
                },
            )]),
            ..FakeQuotaStore::default()
        };
        let outcome = pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        assert_eq!(outcome.state, NamespaceState::ForeignLimitRange);
        assert_eq!(names(&store), vec!["weebo-limits", "weebo-quota"]);
    }

    #[tokio::test]
    async fn saturation_comes_from_the_managed_quotas_status() {
        let store = FakeQuotaStore {
            usage: HashMap::from([(
                namespace(),
                QuotaUsage {
                    hard: BTreeMap::from([("pods".to_string(), "20".to_string())]),
                    used: BTreeMap::from([("pods".to_string(), "23".to_string())]),
                },
            )]),
            ..FakeQuotaStore::default()
        };
        let outcome = pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        assert_eq!(outcome.saturation, Some(SaturationBand::AtLimit));
    }

    #[tokio::test]
    async fn teardown_deletes_only_what_it_manages() {
        let store = FakeQuotaStore::default();
        pass(&store, None, FeatureMode::Enforce, OnNotGranted::Default).await;
        let applied = teardown(&namespace(), &store).await.unwrap();
        assert_eq!(applied.deleted, 2);
        assert!(store.all().is_empty());
        assert_eq!(
            teardown(&namespace(), &store).await.unwrap(),
            Applied::default()
        );
    }

    #[tokio::test]
    async fn check_catalog_names_the_invalid_profile() {
        let checked = feature(OnNotGranted::Default).check_catalog().unwrap();
        let invalid: Vec<&QuotaProfileKey> = checked
            .iter()
            .filter(|(_, violations)| !violations.is_empty())
            .map(|(key, _)| key)
            .collect();
        assert_eq!(invalid, vec![&key("broken")]);
    }

    #[tokio::test]
    async fn reconcile_refuses_mode_off() {
        let teams = teams();
        let facts = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let result = reconcile(
            &feature(OnNotGranted::Default),
            &NamespaceSubject {
                namespace: namespace(),
                annotation: None,
            },
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::Off,
            &FakeQuotaStore::default(),
        )
        .await;
        assert!(result.is_err());
    }
}
