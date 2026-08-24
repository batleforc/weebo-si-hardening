//! `reconcile` — reads the mode, calls `desired()`, diffs against live state, and applies only in
//! `Enforce`. Mirrors `weebo_si_chassis::admit`'s shape for the reconcile side, per RFC 0004's
//! *Design → Architecture*: "`application::reconcile` reads the mode, calls `desired`, diffs
//! against the live objects through a port, and then — and only then — applies or discards."
//!
//! Lives here, not in `weebo-si-controller`, for the reason `admit()` lives in `weebo-si-chassis`
//! rather than `weebo-si-webhook`: the decision needs to be testable without the I/O that would
//! otherwise be the only way to exercise it — an HTTP server for `admit()`, a `kube::Client`
//! here. A future controller watch loop is a thin adapter calling this function, exactly as
//! `weebo-si-webhook`'s router is a thin adapter calling `admit()`.

use weebo_si_chassis::{Context, DomainError, ReconcileFeature, Subject};
use weebo_si_crd::{FeatureMode, ProfileKey, TeamName};

use crate::canary::{CanaryVerdict, Reachability, verdict};
use crate::model::diff::{Applied, DesiredState, Diff, compute_diff};
use crate::port::{CanaryProbe, PolicyStore};

/// What one `reconcile` call decided and (in `Enforce`) did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// The full diff between `desired()` and what `store` reported existed.
    pub diffs: Vec<Diff>,
    /// `None` in `DryRun` — nothing was applied, `diffs` is the whole story. `Some` in
    /// `Enforce`, the counts `store.apply` returned.
    pub applied: Option<Applied>,
    /// The team that matched this subject's namespace, straight from `desired()` — see
    /// [`DesiredState::team`].
    pub team: Option<TeamName>,
    /// Profile keys the subject asked for and its grant does not allow — see
    /// [`DesiredState::not_granted`].
    pub not_granted: Vec<ProfileKey>,
    /// Profile keys with no variant for the resolved backend — see
    /// [`DesiredState::unsupported`].
    pub unsupported: Vec<ProfileKey>,
}

/// Run one reconcile pass for `subject`: compute what should exist, diff it against what
/// `store` reports exists now, and — only in `Enforce` — apply the diff.
///
/// **`mode` must be `DryRun` or `Enforce`.** Per RFC 0002's chassis rule (mirrored here for
/// reconcile features), a feature whose mode is `Off` is never reconciled at all — the caller
/// (a controller watch loop) is expected to have already skipped calling this function, the same
/// way `weebo-si-webhook`'s registry loop skips a feature whose `FeatureGate::mode` is `Off`
/// before ever calling `admit`. Passing `Off` here is therefore a caller bug, reported as a
/// `DomainError` rather than silently treated as `DryRun` — a silent choice between two
/// plausible interpretations (no-op? same as DryRun?) is exactly the kind of ambiguity a
/// hardening control cannot afford.
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
        team: desired.team,
        not_granted: desired.not_granted,
        unsupported: desired.unsupported,
    })
}

/// Run one full canary probe: reach the target with nothing in the way, then reach it again with
/// a deny policy applied, and read the pair as a verdict.
///
/// The two-phase shape is the whole point and is why this is a function rather than a single
/// port call. A single "is it blocked" probe cannot distinguish *the CNI enforced the policy*
/// from *the probe itself is broken* — a pod that never scheduled, an image that never pulled, a
/// port nobody is listening on. Running the unrestricted leg first turns that ambiguity into
/// [`CanaryVerdict::Unknown`], which is the honest answer and the one RFC 0004 asks the metric to
/// report until the first probe completes.
pub async fn run_canary(probe: &dyn CanaryProbe) -> Result<CanaryVerdict, DomainError> {
    let unrestricted = probe.reachability(false).await?;
    if unrestricted != Reachability::Reached {
        // The restricted leg would tell us nothing: something other than policy is already in
        // the way. Skip it rather than spend a second pod on an answer we cannot read.
        return Ok(verdict(unrestricted, Reachability::Inconclusive));
    }
    let restricted = probe.reachability(true).await?;
    Ok(verdict(unrestricted, restricted))
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
        Backend, Enforcement, NamespaceName, NetworkProfilesConfig, OnNotGranted, Profile,
        ProfileCatalog, ProfileKey, ProfileNamespaceSelection, TemplateRef, Variant,
        WorkspaceSelection,
    };

    use super::*;
    use crate::feature::network_profiles::{NamespaceSubject, NetworkProfiles};
    use crate::port::testing::{FakeCanaryProbe, FakePolicyStore, FakeTemplateStore};

    fn template_ref(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn config() -> NetworkProfilesConfig {
        NetworkProfilesConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: ProfileCatalog::new(vec![Profile {
                key: ProfileKey::new("base"),
                variants: vec![Variant {
                    backend: Backend::NetworkPolicy,
                    template_ref: template_ref("weebo-base"),
                }],
            }]),
            baseline: ProfileKey::new("base"),
            grants: BTreeMap::new(),
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: Enforcement::default(),
        }
    }

    fn feature() -> NetworkProfiles {
        NetworkProfiles::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(RwLock::new(Backend::NetworkPolicy)),
            Arc::new(FakeTemplateStore::new([(
                template_ref("weebo-base"),
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
    async fn enforce_applies_the_diff_and_the_store_reflects_it() {
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
    }

    #[tokio::test]
    async fn a_second_enforce_pass_with_nothing_changed_reports_unchanged_and_leaves_the_store_alone()
     {
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
            })
        );
        assert_eq!(store.all().len(), 1);
    }

    #[tokio::test]
    async fn dry_run_and_enforce_compute_the_identical_diff_against_the_same_starting_state() {
        // Mirrors weebo_si_chassis::admit's DryRun/Enforce test for the admission side:
        // `desired()`'s signature carries no mode parameter, so it cannot branch on it — this is
        // the executable proof, run against two independent stores starting from the same empty
        // state, that `reconcile`'s own mode-gating is the only difference between the two modes.
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

    #[tokio::test]
    async fn a_canary_that_reaches_then_is_blocked_reports_enforcing() {
        let probe = FakeCanaryProbe::new(Reachability::Reached, Reachability::Blocked);
        assert_eq!(run_canary(&probe).await.unwrap(), CanaryVerdict::Enforcing);
        assert_eq!(probe.legs_run(), vec![false, true], "both legs run");
    }

    #[tokio::test]
    async fn a_canary_that_reaches_in_both_legs_reports_not_enforcing() {
        let probe = FakeCanaryProbe::new(Reachability::Reached, Reachability::Reached);
        assert_eq!(
            run_canary(&probe).await.unwrap(),
            CanaryVerdict::NotEnforcing
        );
    }

    #[tokio::test]
    async fn a_canary_whose_first_leg_fails_skips_the_second_and_reports_unknown() {
        // The cost argument as well as the correctness one: the restricted leg spends a second
        // pod on a question whose answer is already unreadable.
        let probe = FakeCanaryProbe::new(Reachability::Blocked, Reachability::Blocked);
        assert_eq!(run_canary(&probe).await.unwrap(), CanaryVerdict::Unknown);
        assert_eq!(
            probe.legs_run(),
            vec![false],
            "the restricted leg must not run once the unrestricted one already failed"
        );
    }

    #[tokio::test]
    async fn an_inconclusive_first_leg_also_short_circuits() {
        let probe = FakeCanaryProbe::new(Reachability::Inconclusive, Reachability::Blocked);
        assert_eq!(run_canary(&probe).await.unwrap(), CanaryVerdict::Unknown);
        assert_eq!(probe.legs_run(), vec![false]);
    }
}
