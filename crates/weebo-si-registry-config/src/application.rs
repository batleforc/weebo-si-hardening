//! `reconcile` — reads the mode, calls `desired()`, diffs against live state, and applies only in
//! `Enforce`.
//!
//! Lives here rather than in `weebo-si-controller` for the reason its two siblings' own
//! `application::reconcile` does: the decision needs to be testable without the I/O that would
//! otherwise be the only way to exercise it. A controller watch loop is a thin adapter calling
//! this function.

use weebo_si_chassis::{Context, DomainError, ReconcileFeature, Subject};
use weebo_si_crd::{FeatureMode, RegistryKey, TeamName};

use crate::model::diff::{Applied, DesiredState, Diff, RefusedTemplate, compute_diff};
use crate::port::ObjectStore;

/// What one `reconcile` call decided and (in `Enforce`) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// The namespace this pass was for — the log line's subject, never a metric label.
    pub namespace: weebo_si_crd::NamespaceName,
    /// The full diff between `desired()` and what `store` reported existed.
    ///
    /// **A `DryRun` renders this by object name only, never by content.** RFC 0007's *Security
    /// considerations*: "`DryRun`'s output names *which* objects would change, never *how*, which
    /// is a deliberate reduction in usefulness relative to every other feature's dry run." The
    /// type enforces the reduction rather than the log line remembering to —
    /// [`crate::model::object::ObjectBody`] has no `Debug` that prints bytes.
    pub diffs: Vec<Diff>,
    /// `None` in `DryRun` — nothing was applied, `diffs` is the whole story. `Some` in
    /// `Enforce`, the counts `store.apply` returned.
    pub applied: Option<Applied>,
    /// The team that matched this namespace.
    pub team: Option<TeamName>,
    /// Keys the namespace asked for and its grant does not allow.
    pub not_granted: Vec<RegistryKey>,
    /// Sources of resolved keys that produced no copy, and why.
    pub refused: Vec<RefusedTemplate>,
    /// Whether every source of every resolved key for this namespace resolved — the value behind
    /// `weebo_si_registry_ready`, and the signal an operator alerts on.
    ///
    /// Carried through from [`DesiredState::is_ready`] rather than recomputed from `diffs`: a
    /// diff line says what would be written, not whether everything that *should* have been
    /// written could be.
    pub ready: bool,
}

/// Run one reconcile pass for `subject`: compute what should exist, diff it against what `store`
/// reports exists now, and — only in `Enforce` — apply the diff.
///
/// **`mode` must be `DryRun` or `Enforce`.** A feature whose mode is `Off` is never reconciled at
/// all; passing `Off` here is a caller bug, reported as a `DomainError` rather than silently
/// treated as `DryRun` — a silent choice between two plausible interpretations is exactly the
/// ambiguity a hardening control cannot afford.
pub async fn reconcile<S: Subject>(
    feature: &dyn ReconcileFeature<S, Desired = DesiredState>,
    subject: &S,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn ObjectStore,
) -> Result<ReconcileOutcome, DomainError> {
    if mode == FeatureMode::Off {
        return Err(DomainError::InvalidConfiguration(
            "reconcile called with mode Off — the caller must skip reconciling an Off feature \
             rather than call this function at all"
                .to_string(),
        ));
    }

    let desired = feature.desired(subject, ctx)?;
    let existing = store.managed_in(subject.namespace());
    let diffs = compute_diff(&desired.objects, &existing);

    let applied = if mode == FeatureMode::Enforce {
        Some(store.apply(&diffs).await?)
    } else {
        None
    };

    let ready = desired.is_ready();
    Ok(ReconcileOutcome {
        namespace: subject.namespace().clone(),
        diffs,
        applied,
        team: desired.team,
        not_granted: desired.not_granted,
        refused: desired.refused,
        ready,
    })
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
        Ecosystem, NamespaceName, OnNotGranted, RegistryCatalog, RegistryConfig, RegistryEntry,
        RegistryGrant, RegistryNamespaceSelection, RegistrySource, Selector, SourceKind, Team,
        TemplateRef,
    };

    use super::*;
    use crate::feature::registry_config::{NamespaceSubject, RegistryConfigFeature};
    use crate::model::object::ObjectBody;
    use crate::port::testing::{FakeObjectStore, FakeTemplateStore};

    fn template_ref() -> TemplateRef {
        TemplateRef {
            name: "weebo-npmrc".to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn config() -> RegistryConfig {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RegistryGrant {
                allowed: vec![RegistryKey::new("internal-npm")],
                default: vec![RegistryKey::new("internal-npm")],
            },
        );
        RegistryConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: RegistryCatalog::new(vec![RegistryEntry {
                key: RegistryKey::new("internal-npm"),
                ecosystem: Ecosystem::Npm,
                sources: vec![RegistrySource {
                    kind: SourceKind::ConfigMap,
                    template_ref: template_ref(),
                }],
            }]),
            grants,
            namespace_selection: RegistryNamespaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
        }
    }

    fn feature() -> RegistryConfigFeature {
        RegistryConfigFeature::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(FakeTemplateStore::automountable([(
                (SourceKind::ConfigMap, template_ref()),
                b"registry=https://batlehub.internal/npm/".to_vec(),
            )])),
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

    fn namespace_facts() -> NamespaceFacts {
        NamespaceFacts {
            labels: BTreeMap::from([("weebo.io/team".to_string(), "team-1".to_string())]),
            selection_annotation: None,
        }
    }

    fn subject() -> NamespaceSubject {
        NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
            annotation: None,
        }
    }

    #[tokio::test]
    async fn dry_run_computes_a_diff_and_touches_nothing() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::DryRun,
            &store,
        )
        .await
        .unwrap();

        assert_eq!(outcome.diffs.len(), 1);
        assert!(matches!(outcome.diffs[0], Diff::Create(_)));
        assert_eq!(outcome.applied, None);
        assert!(store.all().is_empty(), "DryRun must never call apply");
    }

    #[tokio::test]
    async fn a_dry_runs_rendered_output_never_carries_the_payload() {
        // RFC 0007's *Security considerations*: `DryRun` names *which* objects would change,
        // never *how*. The type is what enforces it, so this asserts against the rendering a
        // controller would actually produce.
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::DryRun,
            &store,
        )
        .await
        .unwrap();

        let rendered = format!("{:?}", outcome.diffs);
        assert!(
            !rendered.contains("batlehub.internal"),
            "a dry run must not print what the object contains: {rendered}"
        );
        assert!(
            rendered.contains("weebo-si-internal-npm-weebo-npmrc"),
            "but it must name which object would change"
        );
    }

    #[tokio::test]
    async fn enforce_applies_the_diff() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::Enforce,
            &store,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome.applied,
            Some(Applied {
                created: 1,
                ..Applied::default()
            })
        );
        assert_eq!(store.all().len(), 1);
        assert_eq!(store.all()[0].key.name, "weebo-si-internal-npm-weebo-npmrc");
        assert!(outcome.ready);
    }

    #[tokio::test]
    async fn a_second_enforce_pass_with_nothing_changed_reports_unchanged() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let context = Context::new(&teams, &facts, &catalog);
        let feature = feature();

        reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();
        let outcome = reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();

        assert_eq!(
            outcome.applied,
            Some(Applied {
                unchanged: 1,
                ..Applied::default()
            }),
            "a steady state must not rewrite the object on every pass"
        );
    }

    #[tokio::test]
    async fn drift_is_corrected_on_the_next_enforce_pass() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let context = Context::new(&teams, &facts, &catalog);
        let feature = feature();

        reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();

        // A developer points their own `.npmrc` copy somewhere else.
        let mut tampered = store.all();
        tampered[0].body = ObjectBody::opaque(b"registry=https://registry.npmjs.org/".to_vec());
        let store = FakeObjectStore::new(tampered);

        let outcome = reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();
        assert_eq!(
            outcome.applied,
            Some(Applied {
                updated: 1,
                ..Applied::default()
            })
        );
        assert_eq!(
            store.all()[0].body,
            ObjectBody::opaque(b"registry=https://batlehub.internal/npm/".to_vec())
        );
    }

    #[tokio::test]
    async fn a_key_that_stops_being_granted_has_its_copy_deleted() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let context = Context::new(&teams, &facts, &catalog);

        let handle = Arc::new(RwLock::new(Some(config())));
        let feature = RegistryConfigFeature::new(
            Arc::clone(&handle),
            Arc::new(FakeTemplateStore::automountable([(
                (SourceKind::ConfigMap, template_ref()),
                b"registry=https://batlehub.internal/npm/".to_vec(),
            )])),
        );

        reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();
        assert_eq!(store.all().len(), 1);

        {
            let mut guard = handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cfg) = guard.as_mut() {
                cfg.grants.clear();
            }
        }

        let outcome = reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();
        assert_eq!(
            outcome.applied,
            Some(Applied {
                deleted: 1,
                ..Applied::default()
            })
        );
        assert!(store.all().is_empty());
    }

    #[tokio::test]
    async fn dry_run_and_enforce_compute_the_identical_diff_against_the_same_starting_state() {
        // `desired()`'s signature carries no mode parameter, so it cannot branch on it. This is
        // the executable proof that `reconcile`'s own mode-gating is the only difference.
        let dry_run_store = FakeObjectStore::default();
        let enforce_store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let context = Context::new(&teams, &facts, &catalog);

        let dry = reconcile(
            &feature(),
            &subject(),
            &context,
            FeatureMode::DryRun,
            &dry_run_store,
        )
        .await
        .unwrap();
        let enforced = reconcile(
            &feature(),
            &subject(),
            &context,
            FeatureMode::Enforce,
            &enforce_store,
        )
        .await
        .unwrap();

        assert_eq!(dry.diffs, enforced.diffs);
        assert_ne!(
            dry.applied, enforced.applied,
            "the two modes must legitimately differ in what got applied"
        );
    }

    #[tokio::test]
    async fn off_mode_is_a_domain_error_not_a_silent_no_op() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let result = reconcile(
            &feature(),
            &subject(),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::Off,
            &store,
        )
        .await;
        assert!(result.is_err());
        assert!(store.all().is_empty());
    }

    #[tokio::test]
    async fn a_namespace_whose_template_has_not_landed_reports_not_ready() {
        let store = FakeObjectStore::default();
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let feature = RegistryConfigFeature::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(FakeTemplateStore::default()),
        );

        let outcome = reconcile(
            &feature,
            &subject(),
            &Context::new(&teams, &facts, &catalog),
            FeatureMode::Enforce,
            &store,
        )
        .await
        .unwrap();

        assert!(!outcome.ready);
        assert_eq!(outcome.refused.len(), 1);
        assert!(store.all().is_empty());
    }
}
