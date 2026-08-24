//! `weebo_si_admission_duration_seconds`, per RFC 0002's *Observability contract* — the one
//! metric only the HTTP handler itself can measure (a request's wall time), so it lives here
//! rather than behind the `Observer` port, which is called *within* that wall time, not around
//! it.

use prometheus::{Histogram, HistogramOpts, HistogramVec};

/// The webhook's own metrics, separate from [`weebo_si_chassis::port::observer::Observer`]'s.
/// `Clone` is cheap — `HistogramVec` is `Arc`-backed — so one registration is shared by both
/// admission routes (`dwoc-pin`'s and `policy-guard`'s) rather than each registering its own
/// copy of the same metric name against the same registry, which `prometheus::Registry` refuses.
#[derive(Clone)]
pub struct WebhookMetrics {
    duration_seconds: HistogramVec,
}

impl WebhookMetrics {
    /// Register this adapter's metrics against `registry`.
    pub fn register(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "weebo_si_admission_duration_seconds",
                "Wall time spent handling one AdmissionReview, by feature and resource",
            ),
            &["feature", "resource"],
        )?;
        registry.register(Box::new(duration_seconds.clone()))?;
        Ok(Self { duration_seconds })
    }

    /// The timer for one admission of `resource`, by `feature` — `"dwoc-pin"` on the mutating
    /// route, `"policy-guard"` on the validating one, each timing only its own share of the
    /// request.
    pub fn timer(&self, feature: &str, resource: &str) -> Histogram {
        self.duration_seconds
            .with_label_values(&[feature, resource])
    }
}
