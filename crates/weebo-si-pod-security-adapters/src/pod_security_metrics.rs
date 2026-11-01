//! RFC 0013's *Observability contract*: four metrics, none of them carrying a namespace or a pod
//! name. Which namespace is the log line's job; a per-namespace series is how a metrics backend is
//! taken down by a hardening component (RFC 0004).
//!
//! The two gauges are recomputed from a picture held in this process — one entry per namespace
//! reconciled — rather than incremented, so a namespace that leaves scope drops out of them.

use std::collections::HashMap;
use std::sync::RwLock;

use prometheus::{IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{NamespaceName, PodSecurityLevel};
use weebo_si_pod_security::{
    NamespaceState, ReconcileObserver, ReconcileOutcome, ReconcileResult, TeardownOutcome,
};

/// The four metrics.
pub struct PodSecurityMetrics {
    namespaces: IntGaugeVec,
    reconcile_total: IntCounterVec,
    drift_total: IntCounter,
    violations: IntGaugeVec,
    /// Each reconciled namespace's level, state, and how many existing pods the last write was
    /// warned about.
    picture: RwLock<HashMap<NamespaceName, (PodSecurityLevel, NamespaceState, i64)>>,
}

/// How many existing pods a write's warnings name. The apiserver sends one summary line
/// (`existing pods in namespace "x" violate the new PodSecurity enforce level "…"`) and then one
/// line per pod, or per group of pods with the same violations; the summary is not a pod.
pub fn violating_pods(warnings: &[String]) -> i64 {
    let count = warnings
        .iter()
        .filter(|warning| !warning.starts_with("existing pods in namespace"))
        .count();
    i64::try_from(count).unwrap_or(i64::MAX)
}

impl PodSecurityMetrics {
    /// Register every metric against `registry`, every label value at zero.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let namespaces = IntGaugeVec::new(
            Opts::new(
                "weebo_si_pod_security_namespaces",
                "Namespaces this feature reconciles, by the level they enforce and whether it is \
                 the resolved one",
            ),
            &["level", "state"],
        )?;
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_pod_security_reconcile_total",
                "pod-security reconcile outcomes, by result",
            ),
            &["result"],
        )?;
        let drift_total = IntCounter::new(
            "weebo_si_pod_security_drift_total",
            "Pod Security labels this feature owns that somebody else changed, put back",
        )?;
        let violations = IntGaugeVec::new(
            Opts::new(
                "weebo_si_pod_security_violations",
                "Existing pods the apiserver warned about on the last write, by level",
            ),
            &["level"],
        )?;
        registry.register(Box::new(namespaces.clone()))?;
        registry.register(Box::new(reconcile_total.clone()))?;
        registry.register(Box::new(drift_total.clone()))?;
        registry.register(Box::new(violations.clone()))?;

        for result in ReconcileResult::ALL {
            reconcile_total.with_label_values(&[result.as_str()]);
        }
        for level in PodSecurityLevel::ALL {
            violations.with_label_values(&[level.as_str()]).set(0);
            for state in NamespaceState::ALL {
                namespaces
                    .with_label_values(&[level.as_str(), state.as_str()])
                    .set(0);
            }
        }

        Ok(Self {
            namespaces,
            reconcile_total,
            drift_total,
            violations,
            picture: RwLock::new(HashMap::new()),
        })
    }

    fn count(&self, results: &[ReconcileResult]) {
        for result in results {
            self.reconcile_total
                .with_label_values(&[result.as_str()])
                .inc();
        }
    }

    /// Republish both gauges from the picture.
    fn publish(&self) {
        let picture = self
            .picture
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for level in PodSecurityLevel::ALL {
            let in_level = picture.values().filter(|(found, _, _)| *found == level);
            self.violations
                .with_label_values(&[level.as_str()])
                .set(in_level.clone().map(|(_, _, pods)| pods).sum());
            for state in NamespaceState::ALL {
                let count = in_level
                    .clone()
                    .filter(|(_, found, _)| *found == state)
                    .count();
                self.namespaces
                    .with_label_values(&[level.as_str(), state.as_str()])
                    .set(i64::try_from(count).unwrap_or(i64::MAX));
            }
        }
    }
}

impl ReconcileObserver for PodSecurityMetrics {
    fn reconciled(&self, outcome: &ReconcileOutcome) {
        self.count(&outcome.results);
        if outcome.drift {
            self.drift_total.inc();
        }
        {
            let mut picture = self
                .picture
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // A pass that wrote nothing keeps the last write's count: the pods it warned about
            // are still there until a write says otherwise.
            let pods = if outcome.written {
                violating_pods(&outcome.warnings)
            } else {
                picture
                    .get(&outcome.namespace)
                    .map_or(0, |(_, _, pods)| *pods)
            };
            picture.insert(
                outcome.namespace.clone(),
                (outcome.level, outcome.state, pods),
            );
        }
        self.publish();
    }

    fn torn_down(&self, outcome: &TeardownOutcome) {
        self.count(&outcome.results);
        self.forget(&outcome.namespace);
    }

    fn failed(&self) {
        self.count(&[ReconcileResult::Error]);
    }

    fn forget(&self, namespace: &NamespaceName) {
        let removed = self
            .picture
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(namespace)
            .is_some();
        if removed {
            self.publish();
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_pod_security::Restore;

    use super::*;

    fn outcome(ns: &str, state: NamespaceState, warnings: &[&str]) -> ReconcileOutcome {
        ReconcileOutcome {
            namespace: NamespaceName::new(ns),
            team: None,
            level: PodSecurityLevel::Restricted,
            warn_level: PodSecurityLevel::Restricted,
            results: vec![ReconcileResult::Applied],
            changes: Vec::new(),
            written: !warnings.is_empty(),
            warnings: warnings.iter().map(ToString::to_string).collect(),
            drift: false,
            state,
            notes: Vec::new(),
        }
    }

    fn gauge(metrics: &PodSecurityMetrics, state: NamespaceState) -> i64 {
        metrics
            .namespaces
            .with_label_values(&["restricted", state.as_str()])
            .get()
    }

    #[test]
    fn the_summary_warning_is_not_a_pod() {
        let warnings = vec![
            r#"existing pods in namespace "user-bob" violate the new PodSecurity enforce level "restricted:v1.34""#.to_string(),
            "python-web-7d9c: allowPrivilegeEscalation != false".to_string(),
            "debug: runAsNonRoot != true".to_string(),
        ];
        assert_eq!(violating_pods(&warnings), 2);
        assert_eq!(violating_pods(&[]), 0);
    }

    #[test]
    fn every_series_starts_at_zero() {
        let registry = Registry::new();
        let metrics = PodSecurityMetrics::register(&registry).unwrap();
        let families = registry.gather();
        let namespaces = families
            .iter()
            .find(|family| family.name() == "weebo_si_pod_security_namespaces")
            .unwrap();
        assert_eq!(namespaces.get_metric().len(), 9);
        assert_eq!(gauge(&metrics, NamespaceState::Applied), 0);
    }

    #[test]
    fn the_gauges_follow_the_namespaces_and_forget_drops_one() {
        let registry = Registry::new();
        let metrics = PodSecurityMetrics::register(&registry).unwrap();
        metrics.reconciled(&outcome("a", NamespaceState::Applied, &["a: x", "b: y"]));
        metrics.reconciled(&outcome("b", NamespaceState::Applied, &[]));
        metrics.reconciled(&outcome("c", NamespaceState::Pending, &[]));
        assert_eq!(gauge(&metrics, NamespaceState::Applied), 2);
        assert_eq!(gauge(&metrics, NamespaceState::Pending), 1);
        assert_eq!(
            metrics.violations.with_label_values(&["restricted"]).get(),
            2
        );

        metrics.forget(&NamespaceName::new("a"));
        assert_eq!(gauge(&metrics, NamespaceState::Applied), 1);
        assert_eq!(
            metrics.violations.with_label_values(&["restricted"]).get(),
            0
        );
    }

    #[test]
    fn a_pass_that_writes_nothing_keeps_the_last_writes_violations() {
        let registry = Registry::new();
        let metrics = PodSecurityMetrics::register(&registry).unwrap();
        metrics.reconciled(&outcome("a", NamespaceState::Applied, &["a: x"]));
        metrics.reconciled(&outcome("a", NamespaceState::Applied, &[]));
        assert_eq!(
            metrics.violations.with_label_values(&["restricted"]).get(),
            1
        );
    }

    #[test]
    fn results_and_drift_are_counted_and_teardown_forgets() {
        let registry = Registry::new();
        let metrics = PodSecurityMetrics::register(&registry).unwrap();
        let mut drifted = outcome("a", NamespaceState::Applied, &[]);
        drifted.drift = true;
        metrics.reconciled(&drifted);
        metrics.failed();
        metrics.torn_down(&TeardownOutcome {
            namespace: NamespaceName::new("a"),
            results: vec![ReconcileResult::Restored],
            restore: Restore {
                set: Default::default(),
                remove: Vec::new(),
                previous_lost: false,
            },
        });
        let count = |result: &str| metrics.reconcile_total.with_label_values(&[result]).get();
        assert_eq!(count("applied"), 1);
        assert_eq!(count("error"), 1);
        assert_eq!(count("restored"), 1);
        assert_eq!(metrics.drift_total.get(), 1);
        assert_eq!(gauge(&metrics, NamespaceState::Applied), 0);
    }
}
