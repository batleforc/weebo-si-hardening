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

        self.admission_requests_total
            .with_label_values(&[
                feature.kebab(),
                "DevWorkspace",
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
