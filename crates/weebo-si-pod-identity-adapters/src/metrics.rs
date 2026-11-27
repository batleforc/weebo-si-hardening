//! The Prometheus implementation of [`PodIdentityObserver`]: RFC 0018's two counters, and the
//! decision log line, one per admission call (the `DryRun` mock of the RFC).
//!
//! The domain is never told its mode (RFC 0002); the counters and the log line need it, so the
//! observer reads it from the gate, as `admit` just did for the same namespace. No metric
//! carries a namespace or a pod name: both are unbounded, and the log line carries them.

use std::sync::{Arc, RwLock};

use prometheus::{IntCounterVec, Opts, Registry};
use weebo_si_chassis::FeatureId;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_crd::{FeatureMode, PodIdentityConfig};
use weebo_si_pod_identity::{FEATURE_ID, Judged, PodIdentityObserver, PodSubject, Rewrite};

/// `weebo_si_pod_identity_refusals_total` and `weebo_si_pod_identity_rewrites_total`.
#[derive(Clone)]
pub struct PodIdentityMetrics {
    refusals_total: IntCounterVec,
    rewrites_total: IntCounterVec,
    gate: Arc<dyn FeatureGate + Send + Sync>,
    /// Read only to tell `allowed` from `group_zero_granted` in the log line.
    config: Arc<RwLock<Option<PodIdentityConfig>>>,
}

impl PodIdentityMetrics {
    /// Register both counters against `registry`.
    pub fn register(
        registry: &Registry,
        gate: Arc<dyn FeatureGate + Send + Sync>,
        config: Arc<RwLock<Option<PodIdentityConfig>>>,
    ) -> Result<Self, prometheus::Error> {
        let refusals_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_pod_identity_refusals_total",
                "pod-identity violations found by the validating webhook, by mode, reason and \
                 whether the mutation would have fixed them",
            ),
            &["mode", "reason", "fixable_by_mutation"],
        )?;
        let rewrites_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_pod_identity_rewrites_total",
                "Pod-level fields the mutating webhook rewrote (or would, in DryRun), by mode \
                 and field, reinvocations included",
            ),
            &["mode", "field"],
        )?;
        registry.register(Box::new(refusals_total.clone()))?;
        registry.register(Box::new(rewrites_total.clone()))?;
        Ok(Self {
            refusals_total,
            rewrites_total,
            gate,
            config,
        })
    }

    /// Read again after `admit`'s own read: a config change between the two labels one admission
    /// with the new mode. Accepted, the port carries no mode by design (RFC 0002).
    fn mode(&self, pod: &PodSubject) -> FeatureMode {
        self.gate
            .mode_for_admission(FeatureId::new(FEATURE_ID), &pod.namespace)
    }

    fn group_zero_granted(&self) -> bool {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(|config| config.grant_group_zero)
    }
}

/// The `mode` label and log field, as the RFC's alerts and mocks write it (`mode="Enforce"`).
fn mode_label(mode: FeatureMode) -> &'static str {
    match mode {
        FeatureMode::Off => "Off",
        FeatureMode::DryRun => "DryRun",
        FeatureMode::Enforce => "Enforce",
    }
}

impl PodIdentityObserver for PodIdentityMetrics {
    fn rewrites(&self, pod: &PodSubject, rewrites: &[Rewrite]) {
        let mode = self.mode(pod);
        for rewrite in rewrites {
            self.rewrites_total
                .with_label_values(&[mode_label(mode), rewrite.field.label()])
                .inc();
        }
        let result = match (rewrites.is_empty(), mode) {
            (true, _) => "unchanged",
            (false, FeatureMode::Enforce) => "rewritten",
            (false, _) => "would_rewrite",
        };
        let fields = rewrites
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        // `{:?}`: the name is attacker-shaped and admission runs before the apiserver checks it.
        tracing::info!(
            "feature={FEATURE_ID} mode={} ns={} resource=Pod name={:?} result={result} {fields}",
            mode_label(mode),
            pod.namespace,
            pod.name,
        );
    }

    fn violations(&self, pod: &PodSubject, violations: &[Judged]) {
        let mode = self.mode(pod);
        let mode_name = mode_label(mode);
        for judged in violations {
            self.refusals_total
                .with_label_values(&[
                    mode_name,
                    judged.violation.reason(),
                    if judged.fixable_by_mutation {
                        "true"
                    } else {
                        "false"
                    },
                ])
                .inc();
        }
        if violations.is_empty() {
            let result = if self.group_zero_granted() {
                "group_zero_granted"
            } else {
                "allowed"
            };
            tracing::info!(
                "feature={FEATURE_ID} mode={mode_name} ns={} resource=Pod name={:?} result={result}",
                pod.namespace,
                pod.name,
            );
            return;
        }
        // Everything fixable under DryRun is what the mutation, once enforced, makes pass: one
        // quiet line (the mock's `would_allow`). Anything else is one warning per reason.
        if mode != FeatureMode::Enforce && violations.iter().all(|j| j.fixable_by_mutation) {
            let reasons = violations
                .iter()
                .map(|judged| judged.violation.reason())
                .collect::<Vec<_>>()
                .join(",");
            tracing::info!(
                "feature={FEATURE_ID} mode={mode_name} ns={} resource=Pod name={:?} \
                 result=would_allow fixable_by_mutation={reasons}",
                pod.namespace,
                pod.name,
            );
            return;
        }
        let result = if mode == FeatureMode::Enforce {
            "refused"
        } else {
            "would_refuse"
        };
        for judged in violations {
            let container = judged
                .violation
                .container()
                .map(|container| format!(" container={:?}", container.name))
                .unwrap_or_default();
            tracing::warn!(
                "feature={FEATURE_ID} mode={mode_name} ns={} resource=Pod name={:?} \
                 result={result} reason={}{container} fixable_by_mutation={}",
                pod.namespace,
                pod.name,
                judged.violation.reason(),
                judged.fixable_by_mutation,
            );
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
    use weebo_si_chassis::port::feature_gate::testing::FakeFeatureGate;
    use weebo_si_crd::NamespaceName;
    use weebo_si_pod_identity::{Admission, PodSecurityContext, Violation};

    use super::*;

    fn metrics(mode: FeatureMode) -> (Registry, PodIdentityMetrics) {
        let registry = Registry::new();
        let metrics = PodIdentityMetrics::register(
            &registry,
            Arc::new(FakeFeatureGate::new(mode, Vec::new())),
            Arc::new(RwLock::new(None)),
        )
        .unwrap();
        (registry, metrics)
    }

    fn pod() -> PodSubject {
        PodSubject {
            name: "workspace4f-7d9c-".to_string(),
            namespace: NamespaceName::new("dev-ws-test"),
            host_users: None,
            security_context: PodSecurityContext::default(),
            containers: Vec::new(),
            admission: Admission::Create,
        }
    }

    fn series(registry: &Registry) -> Vec<String> {
        registry
            .gather()
            .iter()
            .flat_map(|family| {
                family.get_metric().iter().map(move |metric| {
                    let labels = metric
                        .get_label()
                        .iter()
                        .map(|l| format!("{}={}", l.name(), l.value()))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        "{}{{{labels}}} {}",
                        family.name(),
                        metric.get_counter().value()
                    )
                })
            })
            .collect()
    }

    #[test]
    fn refusals_carry_mode_reason_and_fixability() {
        let (registry, metrics) = metrics(FeatureMode::DryRun);
        metrics.violations(
            &pod(),
            &[
                Judged {
                    violation: Violation::HostUsers(None),
                    fixable_by_mutation: true,
                },
                Judged {
                    violation: Violation::FsGroupZero,
                    fixable_by_mutation: false,
                },
            ],
        );
        assert_eq!(
            series(&registry),
            [
                "weebo_si_pod_identity_refusals_total{fixable_by_mutation=false,mode=DryRun,reason=fs_group_zero} 1",
                "weebo_si_pod_identity_refusals_total{fixable_by_mutation=true,mode=DryRun,reason=host_users} 1",
            ]
        );
    }

    #[test]
    fn rewrites_are_counted_per_field_and_nothing_for_unchanged() {
        let (registry, metrics) = metrics(FeatureMode::Enforce);
        metrics.rewrites(&pod(), &[]);
        assert!(series(&registry).is_empty());
        let pod = pod();
        let rewrites = weebo_si_pod_identity::identity_rewrite(
            &pod,
            &serde_json::from_value(serde_json::json!({"mode": "Enforce"})).unwrap(),
        );
        metrics.rewrites(&pod, &rewrites);
        let series = series(&registry);
        assert!(
            series.contains(
                &"weebo_si_pod_identity_rewrites_total{field=host_users,mode=Enforce} 1"
                    .to_string()
            ),
            "{series:?}"
        );
        assert_eq!(series.len(), rewrites.len());
    }
}
