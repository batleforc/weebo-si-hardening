//! `weebo_si_admission_duration_seconds`, per RFC 0002's *Observability contract* — the one
//! metric only the HTTP handler itself can measure (a request's wall time), so it lives here
//! rather than behind the `Observer` port, which is called *within* that wall time, not around
//! it.

use prometheus::{Histogram, HistogramOpts, HistogramVec};

/// The webhook's own metrics, separate from [`weebo_si_chassis::port::observer::Observer`]'s.
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

    /// The timer for one admission of `resource`. Labelled `feature="dwoc-pin"` — the only
    /// feature this endpoint serves today; a second feature on the same endpoint would need its
    /// own timer around its own share of the request, not a rename of this one.
    pub fn timer(&self, resource: &str) -> Histogram {
        self.duration_seconds
            .with_label_values(&["dwoc-pin", resource])
    }
}
