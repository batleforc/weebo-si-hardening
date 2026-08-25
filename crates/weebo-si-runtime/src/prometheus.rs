//! `Observer` implementation backing RFC 0002's *Observability contract*.
//!
//! **Known simplification**: `weebo_si_admission_duration_seconds` (a per-request timer) and
//! `weebo_si_dwoc_pin_catalog_entries`/`weebo_si_config_observed_generation` (config-shape
//! gauges, not decision events) aren't driven from this port — they belong at the HTTP-handler
//! and reconcile-loop call sites respectively, which know things `Observer::decided` never
//! sees. This adapter covers what an admission *decision* can report:
//! `weebo_si_admission_requests_total` and `weebo_si_dwoc_pin_total`.

use prometheus::{IntCounterVec, Opts, Registry};
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{FeatureId, FeatureOutcome};
use weebo_si_crd::FeatureMode;

/// The `Observer` port's outbound implementation.
pub struct PrometheusObserver {
    admission_requests_total: IntCounterVec,
    dwoc_pin_total: IntCounterVec,
}

impl PrometheusObserver {
    /// Register this adapter's metrics against `registry`.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let admission_requests_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_admission_requests_total",
                "Admission decisions, by feature, resource, mode and outcome",
            ),
            &["feature", "resource", "mode", "outcome"],
        )?;
        let dwoc_pin_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_dwoc_pin_total",
                "dwoc-pin decisions, by result and team",
            ),
            &["result", "team"],
        )?;
        registry.register(Box::new(admission_requests_total.clone()))?;
        registry.register(Box::new(dwoc_pin_total.clone()))?;
        Ok(Self {
            admission_requests_total,
            dwoc_pin_total,
        })
    }
}

fn mode_label(mode: FeatureMode) -> &'static str {
    match mode {
        FeatureMode::Off => "off",
        FeatureMode::DryRun => "dry_run",
        FeatureMode::Enforce => "enforce",
    }
}

impl Observer for PrometheusObserver {
    fn decided(&self, feature: FeatureId, mode: FeatureMode, outcome: &FeatureOutcome) {
        let admission_outcome = if outcome.denied {
            "denied"
        } else if mode == FeatureMode::DryRun {
            "dry_run"
        } else if outcome.mutated {
            "patched"
        } else {
            "unchanged"
        };

        // `outcome.resource`, not a literal. It *was* a literal `"DevWorkspace"` here — so
        // `policy-guard`'s NetworkPolicy denials, `image-policy`'s Pod refusals and the registry
        // guard's ConfigMap verdicts all reported the one kind `dwoc-pin` admits, and an alert
        // broken down by `resource` said nothing. The value now travels from the subject through
        // `FeatureOutcome`, which is the only place that can know it. See RFC 0008's *Changelog*.
        self.admission_requests_total
            .with_label_values(&[
                feature.kebab(),
                outcome.resource,
                mode_label(mode),
                admission_outcome,
            ])
            .inc();

        if feature.kebab() == "dwoc-pin" {
            let team = outcome.team.as_ref().map(|t| t.as_str()).unwrap_or("_none");
            self.dwoc_pin_total
                .with_label_values(&[outcome.result, team])
                .inc();
        }
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
    use weebo_si_crd::NamespaceName;

    use super::*;

    fn outcome(resource: &'static str, denied: bool) -> FeatureOutcome {
        FeatureOutcome {
            namespace: NamespaceName::new("user-alice"),
            resource,
            team: None,
            result: "denied_managed_object",
            mutated: false,
            denied,
        }
    }

    /// Every `(feature, resource)` pair the counter carries, with its value.
    fn series(registry: &Registry) -> Vec<(String, String, u64)> {
        let mut out = Vec::new();
        for family in registry.gather() {
            if family.name() != "weebo_si_admission_requests_total" {
                continue;
            }
            for metric in family.get_metric() {
                let label = |name: &str| {
                    metric
                        .get_label()
                        .iter()
                        .find(|l| l.name() == name)
                        .map(|l| l.value().to_string())
                        .unwrap_or_default()
                };
                out.push((
                    label("feature"),
                    label("resource"),
                    metric.get_counter().value() as u64,
                ));
            }
        }
        out.sort();
        out
    }

    /// **The regression test for the bug RFC 0008's implementation found.** This adapter wrote a
    /// literal `"DevWorkspace"` into the `resource` label for every feature on every route, so
    /// `policy-guard`'s NetworkPolicy denials, `image-policy`'s Pod refusals and the registry
    /// guard's Secret verdicts were indistinguishable from a `dwoc-pin` patch. The label now
    /// comes off the subject, through `FeatureOutcome`.
    ///
    /// Asserting the *whole* label set rather than one series is deliberate: the failure mode was
    /// never "the label is missing", it was "every series collapsed onto one wrong value", and a
    /// test that checks one expected series in isolation passes in exactly that state.
    #[test]
    fn the_resource_label_is_the_subjects_kind_and_not_a_literal() {
        let registry = Registry::new();
        let observer = PrometheusObserver::new(&registry).expect("metrics should register");

        observer.decided(
            FeatureId::new("policy-guard"),
            FeatureMode::Enforce,
            &outcome("KubeArmorPolicy", true),
        );
        observer.decided(
            FeatureId::new("policy-guard"),
            FeatureMode::Enforce,
            &outcome("NetworkPolicy", true),
        );
        observer.decided(
            FeatureId::new("image-policy"),
            FeatureMode::Enforce,
            &outcome("Pod", true),
        );
        observer.decided(
            FeatureId::new("dwoc-pin"),
            FeatureMode::Enforce,
            &outcome("DevWorkspace", false),
        );

        assert_eq!(
            series(&registry),
            vec![
                ("dwoc-pin".to_string(), "DevWorkspace".to_string(), 1),
                ("image-policy".to_string(), "Pod".to_string(), 1),
                ("policy-guard".to_string(), "KubeArmorPolicy".to_string(), 1),
                ("policy-guard".to_string(), "NetworkPolicy".to_string(), 1),
            ],
            "four decisions over four kinds must produce four series; collapsing them onto \
             DevWorkspace is the bug this test exists for"
        );
    }

    /// `dwoc_pin_total` is keyed on the feature id, not on the resource — so widening the
    /// `resource` label must not have started counting other features' decisions into it.
    #[test]
    fn only_dwoc_pin_decisions_reach_the_dwoc_pin_counter() {
        let registry = Registry::new();
        let observer = PrometheusObserver::new(&registry).expect("metrics should register");
        observer.decided(
            FeatureId::new("policy-guard"),
            FeatureMode::Enforce,
            &outcome("NetworkPolicy", true),
        );

        let total: u64 = registry
            .gather()
            .iter()
            .filter(|family| family.name() == "weebo_si_dwoc_pin_total")
            .flat_map(|family| family.get_metric())
            .map(|metric| metric.get_counter().value() as u64)
            .sum();
        assert_eq!(total, 0);
    }
}
