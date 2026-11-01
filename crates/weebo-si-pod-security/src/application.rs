//! `reconcile` and `teardown` — read the mode, call `desired()`, and write only in `Enforce`.
//!
//! Lives here rather than in an adapter for the reason every sibling's `application` module
//! does: the decision has to be testable without the I/O that would otherwise be the only way to
//! exercise it. The controller loop is a thin adapter calling these.

use weebo_si_chassis::{Context, DomainError, ReconcileFeature, Subject};
use weebo_si_crd::{FeatureMode, NamespaceName, PodSecurityLevel, TeamName};

use crate::feature::pod_security::NamespaceSubject;
use crate::model::labels::{LabelChange, diff};
use crate::model::plan::{DesiredState, Found, Plan};
use crate::model::restore::{Restore, restore};
use crate::port::{LabelWrite, NamespaceLabelStore};
use crate::resolve::Note;

/// One value of `weebo_si_pod_security_reconcile_total`'s `result` label. A pass can produce
/// several — a clamped level that is then applied counts as both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReconcileResult {
    /// The labels were written (`Enforce`) or would be (`DryRun`); on `ObserveSynced`, the
    /// synced level is at least as strict as the resolved one.
    Applied,
    /// Nothing to write.
    Unchanged,
    /// The labels were put back on leaving.
    Restored,
    /// A level looser than the ceiling was raised to it.
    Clamped,
    /// The namespace annotation was ignored: it named a looser level, or no level.
    NotTightening,
    /// A stricter level somebody else set was left alone.
    StricterExisting,
    /// `ObserveSynced`: the synced level is looser than the resolved one.
    LooserSynced,
    /// The `-previous` annotation was missing or unreadable on a namespace this feature wrote.
    PreviousLost,
    /// The pass failed.
    Error,
}

impl ReconcileResult {
    /// Every value, for a counter that publishes its zeroes.
    pub const ALL: [ReconcileResult; 9] = [
        Self::Applied,
        Self::Unchanged,
        Self::Restored,
        Self::Clamped,
        Self::NotTightening,
        Self::StricterExisting,
        Self::LooserSynced,
        Self::PreviousLost,
        Self::Error,
    ];

    /// The metric label value and the log line's `result=`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
            Self::Restored => "restored",
            Self::Clamped => "clamped",
            Self::NotTightening => "not_tightening",
            Self::StricterExisting => "stricter_existing",
            Self::LooserSynced => "looser_synced",
            Self::PreviousLost => "previous_lost",
            Self::Error => "error",
        }
    }
}

/// One value of `weebo_si_pod_security_namespaces`' `state` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NamespaceState {
    /// The namespace enforces its resolved level.
    Applied,
    /// It enforces a stricter level somebody else set.
    StricterExisting,
    /// It does not enforce its resolved level yet: `DryRun`, or a looser synced level.
    Pending,
}

impl NamespaceState {
    /// Every value, for a gauge that publishes its zeroes.
    pub const ALL: [NamespaceState; 3] = [Self::Applied, Self::StricterExisting, Self::Pending];

    /// The metric label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::StricterExisting => "stricter_existing",
            Self::Pending => "pending",
        }
    }
}

/// What one `reconcile` call decided and, in `Enforce`, did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// The namespace — the log line's subject, never a metric label.
    pub namespace: NamespaceName,
    /// The team that matched.
    pub team: Option<TeamName>,
    /// The level the namespace enforces after this pass, or would: the resolved one, or the
    /// stricter one left alone.
    pub level: PodSecurityLevel,
    /// The resolved `warn`/`audit` level.
    pub warn_level: PodSecurityLevel,
    /// Every `result` this pass counts.
    pub results: Vec<ReconcileResult>,
    /// What the labels change by. Empty when nothing is written.
    pub changes: Vec<LabelChange>,
    /// `true` when a write happened — `Enforce` with something to write.
    pub written: bool,
    /// The apiserver's warnings for the write: one per existing pod the new level refuses.
    pub warnings: Vec<String>,
    /// A label this feature owns was changed by somebody else and put back.
    pub drift: bool,
    /// The gauge state this namespace is in after the pass.
    pub state: NamespaceState,
    /// What the resolution did on the way, for the log line.
    pub notes: Vec<Note>,
}

/// Run one pass for `subject`: decide, and write only in `Enforce`.
///
/// **`mode` must be `DryRun` or `Enforce`.** `Off` is [`teardown`], not a reconcile; passing it
/// here is a caller bug, reported rather than treated as either.
pub async fn reconcile(
    feature: &dyn ReconcileFeature<NamespaceSubject, Desired = DesiredState>,
    subject: &NamespaceSubject,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn NamespaceLabelStore,
) -> Result<ReconcileOutcome, DomainError> {
    if mode == FeatureMode::Off {
        return Err(DomainError::InvalidConfiguration(
            "reconcile called with mode Off — the caller must tear down an Off feature rather \
             than reconcile it"
                .to_string(),
        ));
    }

    let desired = feature.desired(subject, ctx)?;
    let mut results: Vec<ReconcileResult> = desired
        .resolution
        .notes
        .iter()
        .filter_map(|note| match note {
            Note::Clamped { .. } => Some(ReconcileResult::Clamped),
            Note::NotTightening { .. } | Note::UnknownAnnotation { .. } => {
                Some(ReconcileResult::NotTightening)
            }
            Note::WarnRaised { .. } => None,
        })
        .collect();
    results.dedup();

    let mut level = desired.resolution.level;
    let mut changes = Vec::new();
    let mut written = false;
    let mut warnings = Vec::new();
    let state = match &desired.plan {
        Plan::Apply {
            labels,
            previous,
            current,
        } => {
            results.push(ReconcileResult::Applied);
            changes = diff(current, labels);
            if mode == FeatureMode::Enforce {
                let write = LabelWrite::Apply {
                    labels: labels.clone(),
                    previous: previous.clone(),
                };
                warnings = store.write(subject.namespace(), &write).await?;
                written = true;
                NamespaceState::Applied
            } else {
                NamespaceState::Pending
            }
        }
        Plan::Unchanged => {
            results.push(ReconcileResult::Unchanged);
            NamespaceState::Applied
        }
        Plan::StricterExisting { existing } => {
            results.push(ReconcileResult::StricterExisting);
            level = *existing;
            NamespaceState::StricterExisting
        }
        Plan::Observed { looser: true, .. } => {
            results.push(ReconcileResult::LooserSynced);
            NamespaceState::Pending
        }
        Plan::Observed {
            synced,
            looser: false,
        } => {
            results.push(ReconcileResult::Applied);
            level = synced.unwrap_or(level);
            NamespaceState::Applied
        }
    };
    if desired.previous_lost {
        results.push(ReconcileResult::PreviousLost);
    }

    Ok(ReconcileOutcome {
        namespace: subject.namespace().clone(),
        team: desired.resolution.team,
        level,
        warn_level: desired.resolution.warn_level,
        results,
        changes,
        written,
        warnings,
        drift: desired.drift,
        state,
        notes: desired.resolution.notes,
    })
}

/// What one `teardown` call put back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownOutcome {
    /// The namespace.
    pub namespace: NamespaceName,
    /// `restored`, and `previous_lost` when there was nothing older to put back.
    pub results: Vec<ReconcileResult>,
    /// The write.
    pub restore: Restore,
}

/// Put `namespace` back as this feature found it, and remove the `-previous` annotation — the
/// rollback `mode: Off` is, and what a namespace leaving scope gets.
///
/// Returns `None`, and writes nothing, for a namespace this feature never wrote to.
///
/// **The caller decides that the namespace is deliberately leaving.** A gate that answers `Off`
/// because a cache is still cold is not an instruction to restore anything, and this function
/// cannot tell the two apart.
pub async fn teardown(
    namespace: &NamespaceName,
    found: &Found,
    store: &dyn NamespaceLabelStore,
) -> Result<Option<TeardownOutcome>, DomainError> {
    let Some(restore) = restore(found) else {
        return Ok(None);
    };
    store
        .write(namespace, &LabelWrite::Restore(restore.clone()))
        .await?;
    let mut results = vec![ReconcileResult::Restored];
    if restore.previous_lost {
        results.push(ReconcileResult::PreviousLost);
    }
    Ok(Some(TeardownOutcome {
        namespace: namespace.clone(),
        results,
        restore,
    }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        PodSecurityBackend, PodSecurityConfig, PodSecurityNamespaceSelection, PodSecurityVersion,
        Resolved, ResolvedPodSecurityConfig, Selector, Team, TeamPodSecurity,
    };

    use super::*;
    use crate::feature::pod_security::PodSecurityFeature;
    use crate::model::labels::{ENFORCE, KEYS, PREVIOUS_ANNOTATION, PodSecurityLabels};
    use crate::port::testing::{FakeNamespace, FakeNamespaceLabelStore};

    fn config(team_level: PodSecurityLevel) -> ResolvedPodSecurityConfig {
        Resolved::without_teams(PodSecurityConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            default: PodSecurityLevel::Restricted,
            ceiling: PodSecurityLevel::Baseline,
            version: PodSecurityVersion::new("v1.34"),
            backend: PodSecurityBackend::Labels,
            namespace_selection: PodSecurityNamespaceSelection::default(),
        })
        .with_grants(BTreeMap::from([(
            "team-1".to_string(),
            TeamPodSecurity {
                level: Some(team_level),
                warn_level: None,
            },
        )]))
    }

    fn feature(team_level: PodSecurityLevel) -> PodSecurityFeature {
        PodSecurityFeature::new(Arc::new(RwLock::new(Some(config(team_level)))), false)
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

    /// The subject an adapter would build from the store's current view of the namespace —
    /// `owned` once this feature's apply landed, as server-side apply's managed fields would say.
    fn subject_from(store: &FakeNamespaceLabelStore, owned: bool) -> NamespaceSubject {
        let ns = store.namespace(&namespace());
        NamespaceSubject {
            namespace: namespace(),
            annotation: None,
            found: Found {
                labels: PodSecurityLabels::from_namespace(&ns.labels),
                previous: ns.annotations.get(PREVIOUS_ANNOTATION).cloned(),
                owned,
                foreign_owned: false,
            },
        }
    }

    fn facts(store: &FakeNamespaceLabelStore) -> NamespaceFacts {
        let mut labels = store.namespace(&namespace()).labels;
        labels.insert("weebo.io/team".to_string(), "team-1".to_string());
        NamespaceFacts {
            labels,
            selection_annotation: None,
        }
    }

    async fn pass(
        store: &FakeNamespaceLabelStore,
        team_level: PodSecurityLevel,
        mode: FeatureMode,
        owned: bool,
    ) -> ReconcileOutcome {
        let teams = teams();
        let facts = facts(store);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        reconcile(
            &feature(team_level),
            &subject_from(store, owned),
            &Context::new(&teams, &facts, &catalog),
            mode,
            store,
        )
        .await
        .unwrap()
    }

    fn store_with(labels: &[(&str, &str)]) -> FakeNamespaceLabelStore {
        let store = FakeNamespaceLabelStore::default();
        store.namespaces.write().unwrap().insert(
            namespace(),
            FakeNamespace {
                labels: labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
                annotations: BTreeMap::new(),
            },
        );
        store
    }

    #[tokio::test]
    async fn dry_run_says_what_it_would_write_and_writes_nothing() {
        let store = store_with(&[]);
        let outcome = pass(
            &store,
            PodSecurityLevel::Restricted,
            FeatureMode::DryRun,
            false,
        )
        .await;
        assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
        assert_eq!(outcome.state, NamespaceState::Pending);
        assert!(!outcome.written);
        assert_eq!(outcome.changes.len(), 6);
        assert_eq!(outcome.changes[0].to_string(), "set:enforce=restricted");
        assert!(store.writes().is_empty(), "DryRun must never write");
    }

    #[tokio::test]
    async fn enforce_writes_exactly_the_six_labels_and_the_previous_annotation() {
        let store = store_with(&[("weebo.io/team", "team-1")]);
        let outcome = pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            false,
        )
        .await;
        assert!(outcome.written);
        assert_eq!(outcome.state, NamespaceState::Applied);

        let ns = store.namespace(&namespace());
        let mut keys: Vec<&str> = ns.labels.keys().map(String::as_str).collect();
        keys.retain(|key| *key != "weebo.io/team");
        let mut expected = KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert_eq!(ns.labels.get(ENFORCE).map(String::as_str), Some("baseline"));
        assert_eq!(
            ns.annotations.get(PREVIOUS_ANNOTATION).map(String::as_str),
            Some("{}")
        );
    }

    #[tokio::test]
    async fn a_second_pass_over_what_it_wrote_is_unchanged_and_writes_nothing() {
        let store = store_with(&[]);
        pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            false,
        )
        .await;
        let outcome = pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            true,
        )
        .await;
        assert_eq!(outcome.results, vec![ReconcileResult::Unchanged]);
        assert_eq!(store.writes().len(), 1);
    }

    #[tokio::test]
    async fn the_warnings_the_apiserver_returns_reach_the_outcome() {
        let store = FakeNamespaceLabelStore {
            warnings: vec!["existing pod python-web-7d9c violates restricted".to_string()],
            ..FakeNamespaceLabelStore::default()
        };
        let outcome = pass(
            &store,
            PodSecurityLevel::Restricted,
            FeatureMode::Enforce,
            false,
        )
        .await;
        assert_eq!(outcome.warnings.len(), 1);
    }

    #[tokio::test]
    async fn a_clamped_level_counts_as_clamped_and_applied() {
        let store = store_with(&[]);
        let outcome = pass(
            &store,
            PodSecurityLevel::Privileged,
            FeatureMode::Enforce,
            false,
        )
        .await;
        assert_eq!(
            outcome.results,
            vec![ReconcileResult::Clamped, ReconcileResult::Applied]
        );
        assert_eq!(outcome.level, PodSecurityLevel::Baseline);
    }

    #[tokio::test]
    async fn a_stricter_level_set_by_hand_is_reported_and_left_alone() {
        let store = store_with(&[(ENFORCE, "restricted")]);
        let outcome = pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            false,
        )
        .await;
        assert_eq!(outcome.results, vec![ReconcileResult::StricterExisting]);
        assert_eq!(outcome.state, NamespaceState::StricterExisting);
        assert_eq!(outcome.level, PodSecurityLevel::Restricted);
        assert!(store.writes().is_empty());
    }

    #[tokio::test]
    async fn enforce_then_teardown_gives_the_namespace_back_exactly_as_found() {
        let found_labels = [(ENFORCE, "privileged"), ("weebo.io/team", "team-1")];
        let store = store_with(&found_labels);
        let before = store.namespace(&namespace());

        pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            false,
        )
        .await;
        assert_ne!(store.namespace(&namespace()), before);

        let subject = subject_from(&store, true);
        let outcome = teardown(&namespace(), &subject.found, &store)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.results, vec![ReconcileResult::Restored]);
        assert_eq!(store.namespace(&namespace()), before);
    }

    #[tokio::test]
    async fn teardown_of_a_namespace_never_written_to_writes_nothing() {
        let store = store_with(&[(ENFORCE, "restricted")]);
        let subject = subject_from(&store, false);
        assert_eq!(
            teardown(&namespace(), &subject.found, &store)
                .await
                .unwrap(),
            None
        );
        assert!(store.writes().is_empty());
    }

    #[tokio::test]
    async fn teardown_after_the_annotation_was_lost_removes_the_labels() {
        let store = store_with(&[]);
        pass(
            &store,
            PodSecurityLevel::Baseline,
            FeatureMode::Enforce,
            false,
        )
        .await;
        store
            .namespaces
            .write()
            .unwrap()
            .get_mut(&namespace())
            .unwrap()
            .annotations
            .clear();

        let subject = subject_from(&store, true);
        let outcome = teardown(&namespace(), &subject.found, &store)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            outcome.results,
            vec![ReconcileResult::Restored, ReconcileResult::PreviousLost]
        );
        assert!(store.namespace(&namespace()).labels.is_empty());
    }

    #[tokio::test]
    async fn reconcile_refuses_mode_off() {
        let store = store_with(&[]);
        let teams = teams();
        let facts = facts(&store);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let result = reconcile(
            &feature(PodSecurityLevel::Baseline),
            &subject_from(&store, false),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::Off,
            &store,
        )
        .await;
        assert!(result.is_err());
    }
}
