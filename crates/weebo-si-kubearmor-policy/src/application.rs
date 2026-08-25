//! `reconcile` — reads the mode, calls `desired()`, diffs against live state, and applies only in
//! `Enforce`, plus `observe_enforcement`, this brick's after-the-fact half.
//!
//! Lives here rather than in `weebo-si-controller` for the reason `network-profiles`' own
//! `application::reconcile` does: the decision needs to be testable without the I/O that would
//! otherwise be the only way to exercise it. A controller watch loop is a thin adapter calling
//! these functions.

use weebo_si_chassis::{Context, DomainError, ReconcileFeature, Subject};
use weebo_si_crd::{DefaultPosture, FeatureMode, NamespaceName, RuntimeProfileKey, TeamName};

use crate::model::diff::{Applied, DesiredState, Diff, compute_diff};
use crate::port::{Enforcement, NodeEnforcerView, PolicyStore};

/// What one `reconcile` call decided and (in `Enforce`) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// The full diff between `desired()` and what `store` reported existed.
    pub diffs: Vec<Diff>,
    /// `None` in `DryRun` — nothing was applied, `diffs` is the whole story. `Some` in `Enforce`,
    /// the counts `store.apply` returned.
    pub applied: Option<Applied>,
    /// The posture this subject's namespace should carry, straight from `desired()`. `Some` only
    /// on a namespace pass, and — like `applied` — only acted on in `Enforce`, which the
    /// [`Self::posture_to_write`] accessor below is what an adapter should ask rather than
    /// re-deriving the rule.
    pub posture: Option<DefaultPosture>,
    /// The team that matched this subject's namespace.
    pub team: Option<TeamName>,
    /// Keys the subject asked for and its grant does not allow.
    pub not_granted: Vec<RuntimeProfileKey>,
}

impl ReconcileOutcome {
    /// The posture an adapter should actually write onto the namespace, if any.
    ///
    /// `None` in `DryRun`, always — annotating a namespace is a write, and a dry run that
    /// changes what KubeArmor does with an unmatched operation is not a dry run. The rule lives
    /// here rather than in the adapter because "`DryRun` writes nothing" is the chassis'
    /// promise, not an adapter's discretion, and this is the one output of a pass that is not
    /// already gated by `applied` being `None`.
    pub fn posture_to_write(&self) -> Option<DefaultPosture> {
        self.applied.and(self.posture)
    }
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
    store: &dyn PolicyStore,
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

    Ok(ReconcileOutcome {
        diffs,
        applied,
        posture: desired.posture,
        team: desired.team,
        not_granted: desired.not_granted,
    })
}

/// Ask [`NodeEnforcerView`] what the node hosting `workspace_id` reports, and hand the answer
/// back for `weebo_si_kubearmor_enforced`.
///
/// A function rather than a direct port call at the metric site, for one reason worth the
/// indirection: this is the only place in the brick that turns "a policy object exists" into "a
/// policy object is enforced", and RFC 0006's *Bypass* section rests entirely on those two being
/// separately observable. Keeping the question in the application layer means a future caller
/// cannot accidentally infer the second from the first.
///
/// Deliberately **not** part of [`reconcile`]'s return value. A reconcile pass runs when
/// configuration or a workspace changes; enforcement state changes when a pod is scheduled onto
/// a different node, which is a different clock. Joining them would report a stale answer at a
/// convenient moment instead of a fresh one at the right moment.
pub fn observe_enforcement(
    view: &dyn NodeEnforcerView,
    ns: &NamespaceName,
    workspace_id: &str,
) -> Enforcement {
    view.enforcement(ns, workspace_id)
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
        KubeArmorPolicyConfig, OnNotGranted, Posture, RuntimeBackend, RuntimeEnforcement,
        RuntimeNamespaceSelection, RuntimeProfile, RuntimeProfileCatalog,
        RuntimeWorkspaceSelection, TemplateRef,
    };

    use super::*;
    use crate::feature::kubearmor_policy::{KubeArmorPolicy, NamespaceSubject};
    use crate::port::testing::{FakeNodeEnforcerView, FakePolicyStore, FakeTemplateStore};

    fn template_ref(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn config() -> KubeArmorPolicyConfig {
        KubeArmorPolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: RuntimeProfileCatalog::new(vec![RuntimeProfile {
                key: RuntimeProfileKey::new("base"),
                template_ref: template_ref("weebo-base-runtime"),
            }]),
            baseline: RuntimeProfileKey::new("base"),
            grants: BTreeMap::new(),
            namespace_selection: RuntimeNamespaceSelection::default(),
            workspace_selection: RuntimeWorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: RuntimeEnforcement {
                default_posture: DefaultPosture {
                    file: Posture::Block,
                    ..DefaultPosture::default()
                },
                ..RuntimeEnforcement::default()
            },
        }
    }

    fn feature() -> KubeArmorPolicy {
        KubeArmorPolicy::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
            Arc::new(FakeTemplateStore::new([(
                template_ref("weebo-base-runtime"),
                b"base-rules".to_vec(),
            )])),
        )
    }

    fn subject() -> NamespaceSubject {
        NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        }
    }

    fn empty_context<'a>(
        namespace: &'a NamespaceFacts,
        catalog: &'a FakeDwocCatalog,
    ) -> Context<'a> {
        Context::new(&[], namespace, catalog)
    }

    #[tokio::test]
    async fn dry_run_computes_a_diff_and_touches_nothing() {
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
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
    async fn dry_run_never_writes_the_posture_either() {
        // The one output of a pass that is not already gated by `applied` being `None`. A dry
        // run that changes what KubeArmor does with an unmatched operation is not a dry run.
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::DryRun,
            &store,
        )
        .await
        .unwrap();

        assert!(
            outcome.posture.is_some(),
            "the pass still computed it, and a dry run reports what it would do"
        );
        assert_eq!(
            outcome.posture_to_write(),
            None,
            "but nothing is written in DryRun"
        );
    }

    #[tokio::test]
    async fn enforce_applies_the_diff_and_writes_the_posture() {
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let outcome = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
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
        assert_eq!(store.all()[0].key.name, "weebo-base");
        assert_eq!(
            outcome.posture_to_write().map(|p| p.file),
            Some(Posture::Block)
        );
    }

    #[tokio::test]
    async fn a_second_enforce_pass_with_nothing_changed_reports_unchanged() {
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let feature = feature();

        reconcile(
            &feature,
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::Enforce,
            &store,
        )
        .await
        .unwrap();

        let outcome = reconcile(
            &feature,
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::Enforce,
            &store,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome.applied,
            Some(Applied {
                unchanged: 1,
                ..Applied::default()
            }),
            "a steady state must not reprogram the LSM on every pass"
        );
        assert_eq!(store.all().len(), 1);
    }

    #[tokio::test]
    async fn drift_is_corrected_on_the_next_enforce_pass() {
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let feature = feature();
        let context = empty_context(&namespace, &catalog);

        reconcile(&feature, &subject(), &context, FeatureMode::Enforce, &store)
            .await
            .unwrap();

        // Someone edits the object's rules out from under us.
        let mut tampered = store.all();
        tampered[0].body = crate::model::policy::RuleBody::opaque(b"nothing-at-all".to_vec());
        let store = FakePolicyStore::new(tampered);

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
        assert_eq!(store.all()[0].body.as_bytes(), b"base-rules");
    }

    #[tokio::test]
    async fn dry_run_and_enforce_compute_the_identical_diff_against_the_same_starting_state() {
        // `desired()`'s signature carries no mode parameter, so it cannot branch on it. This is
        // the executable proof that `reconcile`'s own mode-gating is the only difference.
        let dry_run_store = FakePolicyStore::default();
        let enforce_store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());

        let dry_run_outcome = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::DryRun,
            &dry_run_store,
        )
        .await
        .unwrap();
        let enforce_outcome = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::Enforce,
            &enforce_store,
        )
        .await
        .unwrap();

        assert_eq!(dry_run_outcome.diffs, enforce_outcome.diffs);
        assert_eq!(dry_run_outcome.posture, enforce_outcome.posture);
        assert_ne!(
            dry_run_outcome.applied, enforce_outcome.applied,
            "the two modes must legitimately differ in what got applied"
        );
    }

    #[tokio::test]
    async fn off_mode_is_a_domain_error_not_a_silent_no_op() {
        let store = FakePolicyStore::default();
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let result = reconcile(
            &feature(),
            &subject(),
            &empty_context(&namespace, &catalog),
            FeatureMode::Off,
            &store,
        )
        .await;
        assert!(result.is_err());
        assert!(store.all().is_empty());
    }

    #[test]
    fn a_workspace_on_a_node_with_an_lsm_is_reported_enforced() {
        let view = FakeNodeEnforcerView::new([(
            ("user-alice".to_string(), "workspacede4f56".to_string()),
            Enforcement::Enforced("bpf".to_string()),
        )]);
        assert_eq!(
            observe_enforcement(&view, &NamespaceName::new("user-alice"), "workspacede4f56"),
            Enforcement::Enforced("bpf".to_string())
        );
    }

    #[test]
    fn a_workspace_on_a_node_without_one_is_reported_not_enforced_not_absent() {
        // RFC 0006's *Bypass*: the object exists, KubeArmor runs it in visibility-only mode, and
        // the gap has to be visible rather than silent.
        let view = FakeNodeEnforcerView::new([(
            ("user-alice".to_string(), "workspacede4f56".to_string()),
            Enforcement::NotEnforced,
        )]);
        let observed =
            observe_enforcement(&view, &NamespaceName::new("user-alice"), "workspacede4f56");
        assert_eq!(observed, Enforcement::NotEnforced);
        assert_eq!(observed.gauge(), Some(0.0));
    }

    #[test]
    fn a_workspace_with_no_scheduled_pod_is_unknown_rather_than_a_zero() {
        let view = FakeNodeEnforcerView::default();
        assert_eq!(
            observe_enforcement(&view, &NamespaceName::new("user-alice"), "not-scheduled"),
            Enforcement::Unknown
        );
    }
}
