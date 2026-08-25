//! RFC 0007's *Observability contract*, implemented — the same reconcile-side shape
//! [`crate::network_metrics`] and [`crate::kubearmor_metrics`] have, with this brick's own
//! readiness gauge in place of a canary.
//!
//! **Amendment, carried forward from RFC 0006's own.** RFC 0007 writes its metrics with a
//! `namespace` label: `weebo_si_registry_reconcile_total{namespace,result}`,
//! `weebo_si_registry_ready{namespace}`, `weebo_si_registry_managed_objects{namespace,key,kind}`.
//! RFC 0004's *Observability contract* forbids exactly that, project-wide: "No metric carries a
//! namespace or a workspace id as a label. Both scale with the cluster, and a per-workspace time
//! series is how a metrics backend is taken down by a hardening component." `kubearmor-policy`
//! hit the same conflict and resolved it the same way, and doing otherwise here would make this
//! the brick that takes the metrics backend down.
//!
//! So the labels are bounded by the *configuration* rather than by the fleet:
//!
//! | RFC 0007 | Shipped | Why it still answers the same question |
//! | --- | --- | --- |
//! | `reconcile_total{namespace,result}` | `{result,team}` | teams are declared in `spec.teams`; namespaces are not |
//! | `managed_objects{namespace,key,kind}` | `{kind,ecosystem}` | `ecosystem` is a closed enum, `key` is per-catalogue |
//! | `ready{namespace}` | `{state}` | the count of namespaces in each state — `state="degraded" > 0` alerts identically |
//! | `drift_total{namespace,key,kind}` | `{action}` | matching `weebo_si_kubearmor_drift_total` |
//!
//! **Which namespace** is a log line and a `kubectl get configmap -n <ns> -l
//! hardening.weebo.io/managed-by=weebo-si-operator` away — the same answer RFC 0004 gives for
//! its own per-namespace questions, and the reason
//! [`weebo-si-operator registry resolve`](../../weebo-si-operator/src/registry_cmd.rs) exists.

use std::collections::HashMap;
use std::sync::RwLock;

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{Ecosystem, NamespaceName, RegistryCatalog, RegistryKey, SourceKind, TeamName};
use weebo_si_registry_config::{Diff, ManagedObject, ReconcileObserver, ReconcileOutcome};

/// The `team` label's value when no team matched. A literal rather than an empty string, so a
/// dashboard query does not have to distinguish "no team" from "label missing".
const NO_TEAM: &str = "_none";

/// The `state` values [`RegistryMetrics::set_ready`] always publishes, zeroes included: a metric
/// that is absent until something is wrong is one nobody has a dashboard panel for.
const READY_STATES: [&str; 2] = ["ready", "degraded"];

/// The six reconcile-driven metrics of RFC 0007.
#[derive(Clone)]
pub struct RegistryMetrics {
    reconcile_total: IntCounterVec,
    managed_objects: IntGaugeVec,
    ready: IntGaugeVec,
    drift_total: IntCounterVec,
    not_granted_total: IntCounterVec,
    template_invalid_total: IntCounterVec,
    /// Which namespaces are currently ready, so [`Self::set_ready`] can publish *counts* from a
    /// running picture rather than a per-namespace time series.
    ///
    /// A map inside the observer rather than a gauge with a namespace label is the whole of the
    /// amendment above: the cardinality lives in this process's memory, where it is bounded by
    /// the number of namespaces this operator reconciles and costs nothing downstream, instead
    /// of in the metrics backend, where it is unbounded and permanent.
    readiness: std::sync::Arc<RwLock<HashMap<String, bool>>>,
}

impl RegistryMetrics {
    /// Register every metric against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_registry_reconcile_total",
                "registry-config reconcile outcomes, by result and team",
            ),
            &["result", "team"],
        )?;
        let managed_objects = IntGaugeVec::new(
            Opts::new(
                "weebo_si_registry_managed_objects",
                "Registry configuration objects this operator currently owns, by kind and \
                 ecosystem",
            ),
            &["kind", "ecosystem"],
        )?;
        let ready = IntGaugeVec::new(
            Opts::new(
                "weebo_si_registry_ready",
                "Namespaces by whether every source of every key they resolve is in place",
            ),
            &["state"],
        )?;
        let drift_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_registry_drift_total",
                "Managed registry objects the controller had to put back or take away",
            ),
            &["action"],
        )?;
        let not_granted_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_registry_not_granted_total",
                "Registry keys a namespace asked for that its team's grant does not allow",
            ),
            &["team", "key"],
        )?;
        let template_invalid_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_registry_template_invalid_total",
                "Catalogue sources refused before they were ever copied, by key and reason",
            ),
            &["key", "reason"],
        )?;

        for metric in [
            &reconcile_total,
            &drift_total,
            &not_granted_total,
            &template_invalid_total,
        ] {
            registry.register(Box::new(metric.clone()))?;
        }
        for metric in [&managed_objects, &ready] {
            registry.register(Box::new(metric.clone()))?;
        }

        Ok(Self {
            reconcile_total,
            managed_objects,
            ready,
            drift_total,
            not_granted_total,
            template_invalid_total,
            readiness: std::sync::Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Record one reconcile pass.
    ///
    /// In `Enforce` the counters follow what was actually applied; in `DryRun` every diff line
    /// lands on `result="dry_run"` instead, so the two modes are comparable on one dashboard
    /// without `dry_run` ever being mistaken for a write.
    pub fn observe_reconcile(&self, outcome: &ReconcileOutcome) {
        let team = outcome
            .team
            .as_ref()
            .map(TeamName::as_str)
            .unwrap_or(NO_TEAM);

        match &outcome.applied {
            Some(applied) => {
                for (result, count) in [
                    ("created", applied.created),
                    ("updated", applied.updated),
                    ("deleted", applied.deleted),
                    ("unchanged", applied.unchanged),
                ] {
                    if count > 0 {
                        self.reconcile_total
                            .with_label_values(&[result, team])
                            .inc_by(u64::from(count));
                    }
                }
                // Drift is only readable in `Enforce`, because only there did anything move. A
                // `Create` is deliberately not counted: it is indistinguishable from the very
                // first reconcile of a new namespace, and a drift counter that ticks on every
                // install teaches nothing.
                for diff in &outcome.diffs {
                    match diff {
                        Diff::Update(_) => {
                            self.drift_total.with_label_values(&["restored"]).inc();
                        }
                        Diff::Delete { .. } => {
                            self.drift_total.with_label_values(&["removed"]).inc();
                        }
                        Diff::Create(_) | Diff::Unchanged(_) => {}
                    }
                }
            }
            None => {
                if !outcome.diffs.is_empty() {
                    self.reconcile_total
                        .with_label_values(&["dry_run", team])
                        .inc_by(outcome.diffs.len() as u64);
                }
            }
        }

        for key in &outcome.not_granted {
            self.not_granted_total
                .with_label_values(&[team, key.as_str()])
                .inc();
        }

        for refused in &outcome.refused {
            self.template_invalid_total
                .with_label_values(&[refused.entry.as_str(), refused.reason()])
                .inc();
        }

        self.record_readiness(outcome.namespace.as_str(), outcome.ready);
    }

    /// A reconcile pass that did not finish. Counted separately from every other result because
    /// sustained `error` is the fleet drifting away from its intended state one namespace at a
    /// time.
    pub fn observe_error(&self) {
        self.reconcile_total
            .with_label_values(&["error", NO_TEAM])
            .inc();
    }

    /// Note one namespace's readiness and republish the counts.
    fn record_readiness(&self, namespace: &str, ready: bool) {
        {
            let mut guard = self
                .readiness
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.insert(namespace.to_string(), ready);
        }
        self.publish_readiness();
    }

    /// Forget a namespace this feature no longer reconciles — one that went `Off`, fell outside
    /// `namespaceSelector`, or was deleted.
    ///
    /// Without this the gauge would count a namespace that no longer exists as degraded forever,
    /// which is the one way an alertable metric becomes an ignored one.
    pub fn forget(&self, namespace: &str) {
        {
            let mut guard = self
                .readiness
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard.remove(namespace).is_none() {
                return;
            }
        }
        self.publish_readiness();
    }

    fn publish_readiness(&self) {
        let guard = self
            .readiness
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ready = guard.values().filter(|value| **value).count();
        for state in READY_STATES {
            let count = match state {
                "ready" => ready,
                _ => guard.len() - ready,
            };
            self.ready.with_label_values(&[state]).set(count as i64);
        }
    }

    /// Set `weebo_si_registry_managed_objects` from a full snapshot of what this operator owns.
    ///
    /// Takes the whole population rather than a delta on purpose: a gauge maintained by
    /// increments drifts permanently the first time a decrement is missed, and this one is cheap
    /// to recompute from watch caches that already hold every object.
    ///
    /// `catalog` is what turns a catalogue key into its ecosystem — the label RFC 0007 asks for
    /// and the only place `Ecosystem` is used at all. An object whose key has left the catalogue
    /// (a rename mid-rollout) counts as [`Ecosystem::Other`] rather than being dropped: it
    /// exists, and a gauge that under-reports what this operator owns is worse than one with a
    /// blunt label.
    pub fn set_managed_objects(&self, objects: &[ManagedObject], catalog: &RegistryCatalog) {
        let ecosystem_of = |key: &RegistryKey| {
            catalog
                .entry(key)
                .map(|entry| entry.ecosystem)
                .unwrap_or(Ecosystem::Other)
        };

        self.managed_objects.reset();
        for kind in SourceKind::ALL {
            for ecosystem in Ecosystem::ALL {
                let count = objects
                    .iter()
                    .filter(|object| {
                        object.kind == kind && ecosystem_of(&object.entry) == ecosystem
                    })
                    .count();
                self.managed_objects
                    .with_label_values(&[kind.as_str(), ecosystem.label()])
                    .set(count as i64);
            }
        }
    }
}

/// The port the controller actually holds. The inherent methods above stay public so a test (and
/// the CLI, which has no controller around it) can drive one metric without implementing the
/// whole port.
impl ReconcileObserver for RegistryMetrics {
    fn reconciled(&self, outcome: &ReconcileOutcome) {
        self.observe_reconcile(outcome);
    }

    fn failed(&self) {
        self.observe_error();
    }

    fn managed_objects(&self, objects: &[ManagedObject], catalog: &RegistryCatalog) {
        self.set_managed_objects(objects, catalog);
    }

    fn forget(&self, namespace: &NamespaceName) {
        RegistryMetrics::forget(self, namespace.as_str());
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_crd::{RegistryEntry, RegistrySource, TemplateRef};
    use weebo_si_registry_config::{
        Applied, ObjectBody, ObjectKey, RefusedTemplate, TemplateRefusal,
    };

    use super::*;

    fn sample(registry: &Registry, name: &str, labels: &[(&str, &str)]) -> i64 {
        registry
            .gather()
            .into_iter()
            .filter(|family| family.name() == name)
            .flat_map(|family| family.get_metric().to_vec())
            .find(|metric| {
                labels.iter().all(|(key, value)| {
                    metric
                        .get_label()
                        .iter()
                        .any(|pair| pair.name() == *key && pair.value() == *value)
                })
            })
            .map(|metric| (metric.get_counter().value() + metric.get_gauge().value()) as i64)
            .unwrap_or_else(|| panic!("no sample for {name}{labels:?}"))
    }

    fn object(kind: SourceKind, entry: &str) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: format!("weebo-si-{entry}-t"),
            },
            kind,
            entry: RegistryKey::new(entry),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            body: ObjectBody::opaque(b"{}".to_vec()),
        }
    }

    fn outcome(namespace: &str, applied: Option<Applied>, diffs: Vec<Diff>) -> ReconcileOutcome {
        ReconcileOutcome {
            namespace: NamespaceName::new(namespace),
            diffs,
            applied,
            team: Some(TeamName::new("team-1")),
            not_granted: Vec::new(),
            refused: Vec::new(),
            ready: true,
        }
    }

    fn catalog() -> RegistryCatalog {
        RegistryCatalog::new(vec![RegistryEntry {
            key: RegistryKey::new("internal-npm"),
            ecosystem: Ecosystem::Npm,
            sources: vec![RegistrySource {
                kind: SourceKind::ConfigMap,
                template_ref: TemplateRef {
                    name: "weebo-npmrc".to_string(),
                    namespace: NamespaceName::new("weebo-si-hardening"),
                },
            }],
        }])
    }

    #[test]
    fn an_enforce_pass_counts_what_was_applied() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            "user-alice",
            Some(Applied {
                created: 2,
                ..Applied::default()
            }),
            vec![],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_reconcile_total",
                &[("result", "created"), ("team", "team-1")]
            ),
            2
        );
    }

    #[test]
    fn a_dry_run_pass_never_lands_on_a_write_result() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            "user-alice",
            None,
            vec![Diff::Create(object(SourceKind::ConfigMap, "internal-npm"))],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_reconcile_total",
                &[("result", "dry_run"), ("team", "team-1")]
            ),
            1
        );
    }

    #[test]
    fn an_update_in_enforce_is_counted_as_restored_drift() {
        // "How often someone is fighting this brick" — RFC 0007's *Observability contract*.
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            "user-alice",
            Some(Applied {
                updated: 1,
                ..Applied::default()
            }),
            vec![Diff::Update(object(SourceKind::ConfigMap, "internal-npm"))],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_drift_total",
                &[("action", "restored")]
            ),
            1
        );
    }

    #[test]
    fn a_create_is_not_drift() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            "user-alice",
            Some(Applied {
                created: 1,
                ..Applied::default()
            }),
            vec![Diff::Create(object(SourceKind::ConfigMap, "internal-npm"))],
        ));
        assert!(
            registry
                .gather()
                .iter()
                .filter(|family| family.name() == "weebo_si_registry_drift_total")
                .flat_map(|family| family.get_metric().to_vec())
                .all(|metric| metric.get_counter().value() == 0.0),
            "the first reconcile of a new namespace is not somebody editing ours"
        );
    }

    #[test]
    fn a_refused_template_is_counted_by_key_and_reason() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        let mut pass = outcome("user-alice", None, vec![]);
        pass.refused = vec![RefusedTemplate {
            entry: RegistryKey::new("internal-npm"),
            kind: SourceKind::ConfigMap,
            name: "weebo-npmrc".to_string(),
            refusal: Some(TemplateRefusal::MountShadowsPath),
        }];
        metrics.observe_reconcile(&pass);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_template_invalid_total",
                &[("key", "internal-npm"), ("reason", "mount_shadows_path")]
            ),
            1
        );
    }

    #[test]
    fn readiness_is_published_as_counts_never_as_a_namespace_label() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();

        let mut degraded = outcome("user-bob", None, vec![]);
        degraded.ready = false;
        metrics.observe_reconcile(&outcome("user-alice", None, vec![]));
        metrics.observe_reconcile(&degraded);

        assert_eq!(
            sample(&registry, "weebo_si_registry_ready", &[("state", "ready")]),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_ready",
                &[("state", "degraded")]
            ),
            1
        );
        assert!(
            registry
                .gather()
                .iter()
                .flat_map(|family| family.get_metric().to_vec())
                .flat_map(|metric| metric.get_label().to_vec())
                .all(|label| label.name() != "namespace"),
            "no metric in this brick carries a namespace label"
        );
    }

    #[test]
    fn a_namespace_that_recovers_moves_between_states_rather_than_being_counted_twice() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();

        let mut degraded = outcome("user-alice", None, vec![]);
        degraded.ready = false;
        metrics.observe_reconcile(&degraded);
        metrics.observe_reconcile(&outcome("user-alice", None, vec![]));

        assert_eq!(
            sample(&registry, "weebo_si_registry_ready", &[("state", "ready")]),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_ready",
                &[("state", "degraded")]
            ),
            0
        );
    }

    #[test]
    fn a_forgotten_namespace_stops_being_counted_at_all() {
        // A namespace that went `Off`, left `namespaceSelector`, or was deleted must not be
        // counted as degraded forever — that is how an alertable metric becomes an ignored one.
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        let mut degraded = outcome("user-alice", None, vec![]);
        degraded.ready = false;
        metrics.observe_reconcile(&degraded);
        metrics.forget("user-alice");
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_ready",
                &[("state", "degraded")]
            ),
            0
        );
    }

    #[test]
    fn the_managed_objects_gauge_labels_by_kind_and_ecosystem() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(
            &[
                object(SourceKind::ConfigMap, "internal-npm"),
                object(SourceKind::Secret, "internal-npm"),
            ],
            &catalog(),
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_managed_objects",
                &[("kind", "ConfigMap"), ("ecosystem", "npm")]
            ),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_managed_objects",
                &[("kind", "Secret"), ("ecosystem", "npm")]
            ),
            1
        );
    }

    #[test]
    fn an_object_whose_key_left_the_catalogue_is_still_counted() {
        // A rename mid-rollout. A gauge that under-reports what this operator owns is worse than
        // one with a blunt label.
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[object(SourceKind::ConfigMap, "gone")], &catalog());
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_managed_objects",
                &[("kind", "ConfigMap"), ("ecosystem", "other")]
            ),
            1
        );
    }

    #[test]
    fn the_gauge_is_recomputed_from_a_snapshot_rather_than_incremented() {
        let registry = Registry::new();
        let metrics = RegistryMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[object(SourceKind::ConfigMap, "internal-npm")], &catalog());
        metrics.set_managed_objects(&[], &catalog());
        assert_eq!(
            sample(
                &registry,
                "weebo_si_registry_managed_objects",
                &[("kind", "ConfigMap"), ("ecosystem", "npm")]
            ),
            0
        );
    }
}
