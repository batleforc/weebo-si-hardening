//! Mode application at the edge, per RFC 0002: "`DryRun` runs the identical code path as
//! `Enforce` and discards the mutations. A feature that could branch on its mode would make the
//! shadow phase measure something other than what enforcement does."

use weebo_si_crd::FeatureMode;

use crate::error::DomainError;
use crate::feature::{Context, FeatureOutcome, Registry, Subject};
use crate::mutation::Mutation;
use crate::port::dwoc_catalog::DwocCatalog;
use crate::port::feature_gate::FeatureGate;
use crate::port::namespace_view::NamespaceView;
use crate::port::observer::Observer;

/// What admission does with the mutations every enabled feature computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// Apply these mutations (empty if nothing changed).
    Allow(Vec<Mutation>),
    /// Deny the admission with this reason.
    Deny(String),
}

/// Run every feature registered for `S` whose mode is not `Off`, in registry order, over
/// `subject`. Each feature's `evaluate()` runs identically regardless of mode — `Enforce`
/// applies what it decided, `DryRun` discards it — and every outcome is reported to `observer`
/// unconditionally, so a shadow run is visible before it is trusted.
///
/// No inter-feature mutation folding: with exactly one feature registered today, a second
/// feature's `evaluate()` never needs to see the first one's mutation applied to `subject`. RFC
/// 0002's *Ordering* rule ("each feature seeing the object as the previous one left it") is a
/// contract for the day a second `Feature<S>` is added, not a mechanism this function builds
/// today against a sample size of one.
pub fn admit<S: Subject>(
    registry: &Registry<S>,
    subject: &S,
    gate: &dyn FeatureGate,
    namespace_view: &dyn NamespaceView,
    dwoc_catalog: &dyn DwocCatalog,
    observer: &dyn Observer,
) -> Result<AdmitOutcome, DomainError> {
    let namespace = namespace_view
        .facts(subject.namespace())
        .ok_or_else(|| DomainError::NamespaceNotObserved(subject.namespace().clone()))?;
    let teams = gate.teams();

    let mut mutations = Vec::new();

    for feature in registry.iter() {
        let mode = gate.mode(feature.id(), subject.namespace());
        if mode == FeatureMode::Off {
            continue;
        }

        let ctx = Context::new(&teams, &namespace, dwoc_catalog);
        let decision = feature.evaluate(subject, &ctx)?;
        observer.decided(
            feature.id(),
            mode,
            &FeatureOutcome::from_decision(&decision, subject),
        );

        if let Some(reason) = decision.denial {
            if mode == FeatureMode::Enforce {
                return Ok(AdmitOutcome::Deny(reason));
            }
            continue;
        }

        if mode == FeatureMode::Enforce {
            mutations.extend(decision.mutations);
        }
    }

    Ok(AdmitOutcome::Allow(mutations))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_crd::{DwocRef, NamespaceName};

    use super::*;
    use crate::feature::{Decision, Feature, FeatureId};
    use crate::namespace_facts::NamespaceFacts;
    use crate::port::dwoc_catalog::testing::FakeDwocCatalog;
    use crate::port::feature_gate::testing::FakeFeatureGate;
    use crate::port::namespace_view::testing::FakeNamespaceView;
    use crate::port::observer::testing::RecordingObserver;

    #[derive(Debug)]
    struct Workspace(NamespaceName);
    impl Subject for Workspace {
        fn namespace(&self) -> &NamespaceName {
            &self.0
        }

        fn resource(&self) -> &'static str {
            "DevWorkspace"
        }
    }

    struct AlwaysMutates;
    impl Feature<Workspace> for AlwaysMutates {
        fn id(&self) -> FeatureId {
            FeatureId::new("always-mutates")
        }
        fn evaluate(
            &self,
            _subject: &Workspace,
            _ctx: &Context<'_>,
        ) -> Result<Decision<Workspace>, DomainError> {
            Ok(Decision::new(
                vec![Mutation::SetConfigRef(DwocRef {
                    name: "config".to_string(),
                    namespace: NamespaceName::new("eclipse-che"),
                })],
                None,
                None,
                "mutated",
            ))
        }
    }

    struct AlwaysDenies;
    impl Feature<Workspace> for AlwaysDenies {
        fn id(&self) -> FeatureId {
            FeatureId::new("always-denies")
        }
        fn evaluate(
            &self,
            _subject: &Workspace,
            _ctx: &Context<'_>,
        ) -> Result<Decision<Workspace>, DomainError> {
            Ok(Decision::deny("no".to_string(), None, None, "denied"))
        }
    }

    fn registry<F: Feature<Workspace> + Send + Sync + 'static>(feature: F) -> Registry<Workspace> {
        let mut registry = Registry::new();
        registry.register(feature);
        registry
    }

    fn subject() -> Workspace {
        Workspace(NamespaceName::new("user-alice"))
    }

    fn namespace_view() -> FakeNamespaceView {
        FakeNamespaceView::new([(
            NamespaceName::new("user-alice"),
            NamespaceFacts {
                labels: BTreeMap::new(),
                selection_annotation: None,
            },
        )])
    }

    fn dwoc_catalog() -> FakeDwocCatalog {
        FakeDwocCatalog::new(std::iter::empty())
    }

    #[test]
    fn off_mode_never_calls_evaluate_and_records_nothing() {
        let registry = registry(AlwaysMutates);
        let gate = FakeFeatureGate::new(FeatureMode::Off, Vec::new());
        let observer = RecordingObserver::default();
        let outcome = admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();
        assert_eq!(outcome, AdmitOutcome::Allow(Vec::new()));
        assert!(observer.events().is_empty());
    }

    #[test]
    fn dry_run_discards_mutations_but_still_records_the_outcome() {
        let registry = registry(AlwaysMutates);
        let gate = FakeFeatureGate::new(FeatureMode::DryRun, Vec::new());
        let observer = RecordingObserver::default();
        let outcome = admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();
        assert_eq!(outcome, AdmitOutcome::Allow(Vec::new()));
        assert_eq!(observer.events().len(), 1);
        assert!(observer.events()[0].2.mutated);
    }

    #[test]
    fn enforce_applies_mutations() {
        let registry = registry(AlwaysMutates);
        let gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());
        let observer = RecordingObserver::default();
        let outcome = admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();
        match outcome {
            AdmitOutcome::Allow(mutations) => assert!(!mutations.is_empty()),
            AdmitOutcome::Deny(reason) => {
                panic!("expected mutations to be applied, got denial: {reason}")
            }
        }
    }

    /// A second subject type, reporting a different kind — the whole point of `Subject::resource`
    /// being per-type rather than a constant somewhere in the observability adapter.
    #[derive(Debug)]
    struct PolicyWrite(NamespaceName);
    impl Subject for PolicyWrite {
        fn namespace(&self) -> &NamespaceName {
            &self.0
        }

        fn resource(&self) -> &'static str {
            "KubeArmorPolicy"
        }
    }

    impl Feature<PolicyWrite> for AlwaysDenies {
        fn id(&self) -> FeatureId {
            FeatureId::new("always-denies")
        }
        fn evaluate(
            &self,
            _subject: &PolicyWrite,
            _ctx: &Context<'_>,
        ) -> Result<Decision<PolicyWrite>, DomainError> {
            Ok(Decision::deny("no".to_string(), None, None, "denied"))
        }
    }

    /// **The chassis half of RFC 0008's `resource`-label fix.** The observability record's
    /// `resource` is the *subject's* kind, carried by `admit` — not a value the observer picks.
    ///
    /// Two subject types through the same `admit`, asserting the recorded kinds differ: a
    /// literal anywhere downstream (which is exactly what `PrometheusObserver` used to hold)
    /// makes these two equal, and that is the failure this test names.
    #[test]
    fn the_recorded_resource_is_the_subjects_kind_not_a_fixed_one() {
        let gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());

        let workspace_observer = RecordingObserver::default();
        admit(
            &registry(AlwaysDenies),
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &workspace_observer,
        )
        .unwrap();

        let mut policy_registry: Registry<PolicyWrite> = Registry::new();
        policy_registry.register(AlwaysDenies);
        let policy_observer = RecordingObserver::default();
        admit(
            &policy_registry,
            &PolicyWrite(NamespaceName::new("user-alice")),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &policy_observer,
        )
        .unwrap();

        assert_eq!(workspace_observer.events()[0].2.resource, "DevWorkspace");
        assert_eq!(policy_observer.events()[0].2.resource, "KubeArmorPolicy");
        assert_ne!(
            workspace_observer.events()[0].2.resource,
            policy_observer.events()[0].2.resource,
            "two subject types must not report the same resource — a literal downstream of \
             `admit` is what made every route report DevWorkspace"
        );
    }

    #[test]
    fn dry_run_and_enforce_observe_the_identical_outcome_and_only_differ_in_applied_mutations() {
        let registry = registry(AlwaysMutates);
        let ns_view = namespace_view();
        let catalog = dwoc_catalog();

        let dry_run_gate = FakeFeatureGate::new(FeatureMode::DryRun, Vec::new());
        let dry_run_observer = RecordingObserver::default();
        let dry_run_outcome = admit(
            &registry,
            &subject(),
            &dry_run_gate,
            &ns_view,
            &catalog,
            &dry_run_observer,
        )
        .unwrap();

        let enforce_gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());
        let enforce_observer = RecordingObserver::default();
        let enforce_outcome = admit(
            &registry,
            &subject(),
            &enforce_gate,
            &ns_view,
            &catalog,
            &enforce_observer,
        )
        .unwrap();

        // The recorded *mode* legitimately differs — that's the whole point of `mode` being part
        // of the record. What must be identical is the feature's own decision: same `FeatureOutcome`,
        // proving `evaluate()` never branched on which mode it's running under.
        let dry_run_decisions: Vec<_> = dry_run_observer
            .events()
            .into_iter()
            .map(|(id, _, outcome)| (id, outcome))
            .collect();
        let enforce_decisions: Vec<_> = enforce_observer
            .events()
            .into_iter()
            .map(|(id, _, outcome)| (id, outcome))
            .collect();
        assert_eq!(dry_run_decisions, enforce_decisions);
        assert_eq!(dry_run_outcome, AdmitOutcome::Allow(Vec::new()));
        assert_ne!(dry_run_outcome, enforce_outcome);
    }

    #[test]
    fn a_denial_in_enforce_mode_short_circuits_admission_and_applies_no_mutation() {
        let registry = registry(AlwaysDenies);
        let gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());
        let observer = RecordingObserver::default();
        let outcome = admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();
        assert!(matches!(outcome, AdmitOutcome::Deny(_)));
    }

    #[test]
    fn a_denial_in_dry_run_mode_is_recorded_but_never_blocks_admission() {
        let registry = registry(AlwaysDenies);
        let gate = FakeFeatureGate::new(FeatureMode::DryRun, Vec::new());
        let observer = RecordingObserver::default();
        let outcome = admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();
        assert_eq!(outcome, AdmitOutcome::Allow(Vec::new()));
        assert_eq!(observer.events().len(), 1);
    }

    struct Stub(&'static str);
    impl Feature<Workspace> for Stub {
        fn id(&self) -> FeatureId {
            FeatureId::new(self.0)
        }
        fn evaluate(
            &self,
            _subject: &Workspace,
            _ctx: &Context<'_>,
        ) -> Result<Decision<Workspace>, DomainError> {
            Ok(Decision::new(Vec::new(), None, None, "stub"))
        }
    }

    #[test]
    fn registry_order_is_preserved_across_two_enabled_stub_features() {
        let mut registry: Registry<Workspace> = Registry::new();
        registry.register(Stub("first"));
        registry.register(Stub("second"));

        let gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());
        let observer = RecordingObserver::default();
        admit(
            &registry,
            &subject(),
            &gate,
            &namespace_view(),
            &dwoc_catalog(),
            &observer,
        )
        .unwrap();

        let ids: Vec<&str> = observer
            .events()
            .iter()
            .map(|(id, _, _)| id.kebab())
            .collect();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[test]
    fn an_unobserved_namespace_is_a_domain_error_not_a_silent_no_team_default() {
        let registry = registry(AlwaysMutates);
        let gate = FakeFeatureGate::new(FeatureMode::Enforce, Vec::new());
        let observer = RecordingObserver::default();
        let empty_namespace_view = FakeNamespaceView::new(std::iter::empty());
        let result = admit(
            &registry,
            &subject(),
            &gate,
            &empty_namespace_view,
            &dwoc_catalog(),
            &observer,
        );
        assert!(matches!(result, Err(DomainError::NamespaceNotObserved(_))));
    }
}
