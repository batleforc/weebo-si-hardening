//! The two `Feature<PodSubject>`s, one `FeatureId`: one `mode` and one `namespaceSelector`
//! govern both, as image-policy's two halves share theirs.
//!
//! **`DryRun` judges the pod as the mutation would leave it (L23).** The chassis discards the
//! mutation in `DryRun`, so validation sees the raw pod: it reports each violation with
//! `fixable_by_mutation`, computed on `identity_rewrite` applied in memory, while the decision
//! stays on the raw pod — in `Enforce` a fixable refusal means the mutation did not run.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId};
use weebo_si_crd::PodIdentityConfig;

use crate::port::{Judged, PodIdentityObserver};
use crate::rewrite::{Rewrite, identity_rewrite};
use crate::subject::PodSubject;
use crate::violation::identity_violations;

/// The feature identifier both routes report.
pub const FEATURE_ID: &str = "pod-identity";

/// The live config, or the error `evaluate` returns without one.
fn load(config: &RwLock<Option<PodIdentityConfig>>) -> Result<PodIdentityConfig, DomainError> {
    config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "pod-identity evaluated with no spec.features.podIdentity configured".to_string(),
            )
        })
}

/// A namespace pinned to an exempt dwoc key is left untouched (L27).
fn exempt(config: &PodIdentityConfig, ctx: &Context<'_>) -> bool {
    ctx.namespace()
        .selection_annotation
        .as_ref()
        .is_some_and(|key| config.exempt_dwoc_keys.contains(key))
}

/// The mutating half: rewrites the pod level, never denies.
pub struct PodIdentityMutation {
    config: Arc<RwLock<Option<PodIdentityConfig>>>,
    observer: Arc<dyn PodIdentityObserver>,
}

impl PodIdentityMutation {
    /// Build it over the config store's live handle.
    pub fn new(
        config: Arc<RwLock<Option<PodIdentityConfig>>>,
        observer: Arc<dyn PodIdentityObserver>,
    ) -> Self {
        Self { config, observer }
    }
}

impl Feature<PodSubject> for PodIdentityMutation {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &PodSubject,
        ctx: &Context<'_>,
    ) -> Result<Decision<PodSubject>, DomainError> {
        let config = load(&self.config)?;
        if exempt(&config, ctx) {
            return Ok(Decision::new(Vec::new(), None, None, "exempt"));
        }
        let rewrites = identity_rewrite(subject, &config);
        self.observer.rewrites(subject, &rewrites);
        if rewrites.is_empty() {
            return Ok(Decision::new(Vec::new(), None, None, "unchanged"));
        }
        let note = rewrites
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        Ok(Decision::new(
            rewrites.iter().map(Rewrite::mutation).collect(),
            None,
            Some(note),
            "rewritten",
        ))
    }
}

/// The validating half: refuses what `identity_violations` finds on the pod as admitted.
pub struct PodIdentityValidation {
    config: Arc<RwLock<Option<PodIdentityConfig>>>,
    observer: Arc<dyn PodIdentityObserver>,
}

impl PodIdentityValidation {
    /// Build it over the config store's live handle.
    pub fn new(
        config: Arc<RwLock<Option<PodIdentityConfig>>>,
        observer: Arc<dyn PodIdentityObserver>,
    ) -> Self {
        Self { config, observer }
    }
}

impl Feature<PodSubject> for PodIdentityValidation {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &PodSubject,
        ctx: &Context<'_>,
    ) -> Result<Decision<PodSubject>, DomainError> {
        let config = load(&self.config)?;
        if exempt(&config, ctx) {
            return Ok(Decision::new(Vec::new(), None, None, "exempt"));
        }
        let raw = identity_violations(subject, &config);
        if raw.is_empty() {
            self.observer.violations(subject, &[]);
            let result = if config.grant_group_zero {
                "group_zero_granted"
            } else {
                "allowed"
            };
            return Ok(Decision::new(Vec::new(), None, None, result));
        }
        let mutated = subject.rewritten(&identity_rewrite(subject, &config));
        let remaining = identity_violations(&mutated, &config);
        let judged: Vec<Judged> = raw
            .into_iter()
            .map(|violation| Judged {
                fixable_by_mutation: !remaining.contains(&violation),
                violation,
            })
            .collect();
        self.observer.violations(subject, &judged);
        let reason = judged
            .iter()
            .map(|judged| judged.violation.to_string())
            .collect::<Vec<_>>()
            .join(". "); // each message already uses "; " inside
        // Still a refusal (the decision is on the raw pod, L23), but labelled apart so a DryRun
        // tells "the mutation would fix it" from real breakage.
        let result = if judged.iter().all(|judged| judged.fixable_by_mutation) {
            "refused_fixable"
        } else {
            "refused"
        };
        Ok(Decision::deny(reason, None, None, result))
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

    use super::*;
    use crate::port::testing::RecordingObserver;
    use crate::rewrite::tests::{config, container, dwo_pod, fixed_pod};
    use crate::violation::Violation;

    struct Harness {
        observer: Arc<RecordingObserver>,
        mutation: PodIdentityMutation,
        validation: PodIdentityValidation,
    }

    fn harness(config: Option<PodIdentityConfig>) -> Harness {
        let handle = Arc::new(RwLock::new(config));
        let observer = Arc::new(RecordingObserver::default());
        Harness {
            mutation: PodIdentityMutation::new(Arc::clone(&handle), observer.clone()),
            validation: PodIdentityValidation::new(handle, observer.clone()),
            observer,
        }
    }

    fn run<F: Feature<PodSubject>>(
        feature: &F,
        pod: &PodSubject,
        dwoc: Option<&str>,
    ) -> Result<Decision<PodSubject>, DomainError> {
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: dwoc.map(str::to_string),
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        feature.evaluate(pod, &Context::new(&[], &namespace, &catalog))
    }

    #[test]
    fn the_mutation_rewrites_and_never_denies() {
        let h = harness(Some(config()));
        let decision = run(&h.mutation, &dwo_pod(), Some("che")).unwrap();
        assert_eq!(decision.result, "rewritten");
        assert!(decision.denial.is_none());
        assert_eq!(decision.mutations.len(), 5);
        assert_eq!(
            decision.note.as_deref(),
            Some(
                "hostUsers=unset->false runAsGroup=0->1234 \
                 fsGroupChangePolicy=unset->OnRootMismatch \
                 supplementalGroupsPolicy=unset->Strict runAsNonRoot=unset->true"
            )
        );
        assert_eq!(h.observer.rewrites()[0].1.len(), 5);

        let mut root = fixed_pod();
        root.security_context.run_as_user = Some(0);
        let decision = run(&h.mutation, &root, None).unwrap();
        assert_eq!((decision.result, decision.denial), ("unchanged", None));
        assert!(h.observer.rewrites()[1].1.is_empty());
    }

    #[test]
    fn exempt_dwoc_key_is_untouched() {
        let h = harness(Some(config()));
        let mut pod = dwo_pod();
        pod.security_context.run_as_user = Some(0);
        for decision in [
            run(&h.mutation, &pod, Some("build")).unwrap(),
            run(&h.validation, &pod, Some("build")).unwrap(),
        ] {
            assert_eq!(decision.result, "exempt");
            assert!(decision.mutations.is_empty() && decision.denial.is_none());
        }
        assert!(h.observer.rewrites().is_empty() && h.observer.violations().is_empty());
        // Another key, or none, is in scope.
        assert_eq!(
            run(&h.validation, &pod, Some("che")).unwrap().result,
            "refused"
        );
        assert_eq!(run(&h.validation, &pod, None).unwrap().result, "refused");
    }

    #[test]
    fn violation_fixable_by_mutation_is_flagged() {
        let h = harness(Some(config()));
        let mut pod = dwo_pod();
        pod.containers.push(container("sidecar", None, Some(0)));
        let decision = run(&h.validation, &pod, None).unwrap();
        assert_eq!(decision.result, "refused");
        let flags: Vec<(&str, bool)> = h.observer.violations()[0]
            .1
            .iter()
            .map(|judged| (judged.violation.reason(), judged.fixable_by_mutation))
            .collect();
        assert_eq!(
            flags,
            [
                ("host_users", true),
                ("gid_zero", true), // tools inherits the pod's 0, rewritten to 1234
                ("gid_zero", false), // sidecar sets its own 0
                ("policy", true),
            ]
        );
        let denial = decision.denial.unwrap();
        assert!(denial.contains("container \"sidecar\": securityContext.runAsGroup=0"));
        assert_eq!(denial.split(". ").count(), 4);
    }

    #[test]
    fn a_pod_the_mutation_would_fix_is_refused_as_fixable() {
        let h = harness(Some(config()));
        let decision = run(&h.validation, &dwo_pod(), None).unwrap();
        assert_eq!(decision.result, "refused_fixable");
        assert!(decision.denial.is_some());
    }

    #[test]
    fn the_validation_allows_a_fixed_pod() {
        let h = harness(Some(config()));
        let decision = run(&h.validation, &fixed_pod(), None).unwrap();
        assert_eq!((decision.result, decision.denial), ("allowed", None));
        assert_eq!(
            h.observer.violations(),
            [("workspace4f-7d9c-".to_string(), vec![])]
        );
    }

    #[test]
    fn granted_group_zero_is_logged_as_such() {
        let mut granted = config();
        granted.grant_group_zero = true;
        let h = harness(Some(granted));
        let mut pod = fixed_pod();
        pod.security_context.supplemental_groups = vec![0];
        assert_eq!(
            run(&h.validation, &pod, None).unwrap().result,
            "group_zero_granted"
        );
    }

    #[test]
    fn reinvocation_on_rewritten_pod_emits_no_patch() {
        let h = harness(Some(config()));
        let decision = run(&h.mutation, &fixed_pod(), None).unwrap();
        assert!(decision.mutations.is_empty());
        assert_eq!(decision.result, "unchanged");
    }

    #[test]
    fn no_config_is_an_error_not_an_allow() {
        let h = harness(None);
        assert!(matches!(
            run(&h.mutation, &dwo_pod(), None),
            Err(DomainError::InvalidConfiguration(_))
        ));
        assert!(matches!(
            run(&h.validation, &dwo_pod(), None),
            Err(DomainError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn both_halves_share_one_feature_id() {
        let h = harness(None);
        assert_eq!(h.mutation.id().kebab(), FEATURE_ID);
        assert_eq!(h.validation.id().kebab(), FEATURE_ID);
        assert_eq!(FeatureId::new(FEATURE_ID).camel(), "podIdentity");
    }

    #[test]
    fn the_denial_is_the_violation_message() {
        let h = harness(Some(config()));
        let mut pod = fixed_pod();
        pod.security_context.fs_group = Some(0);
        assert_eq!(
            run(&h.validation, &pod, None).unwrap().denial,
            Some(Violation::FsGroupZero.to_string())
        );
    }
}
