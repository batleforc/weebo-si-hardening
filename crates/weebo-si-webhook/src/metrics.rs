//! `weebo_si_admission_duration_seconds`, per RFC 0002's *Observability contract* — the one
//! metric only the HTTP handler itself can measure (a request's wall time), so it lives here
//! rather than behind the `Observer` port, which is called *within* that wall time, not around
//! it.
//!
//! And `weebo_si_admission_unguarded_total`, for the same reason turned inside out: it counts
//! requests that never reached a feature at all, so no `Observer::decided` call exists to carry
//! them.

use prometheus::{Histogram, HistogramOpts, HistogramVec, IntCounterVec, Opts};

/// The webhook's own metrics, separate from [`weebo_si_chassis::port::observer::Observer`]'s.
/// `Clone` is cheap — `HistogramVec` is `Arc`-backed — so one registration is shared by both
/// admission routes (`dwoc-pin`'s and `policy-guard`'s) rather than each registering its own
/// copy of the same metric name against the same registry, which `prometheus::Registry` refuses.
#[derive(Clone)]
pub struct WebhookMetrics {
    duration_seconds: HistogramVec,
    unguarded_total: IntCounterVec,
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
        let unguarded_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_admission_unguarded_total",
                "AdmissionReviews allowed without a verdict because the handler does not \
                 recognise the resource they are against, by feature and webhook path",
            ),
            &["feature", "path"],
        )?;
        registry.register(Box::new(duration_seconds.clone()))?;
        registry.register(Box::new(unguarded_total.clone()))?;
        Ok(Self {
            duration_seconds,
            unguarded_total,
        })
    }

    /// The timer for one admission of `resource`, by `feature` — `"dwoc-pin"` on the mutating
    /// route, `"policy-guard"` on the validating ones, each timing only its own share of the
    /// request.
    ///
    /// Every call site passes `subject.resource()` — the same value
    /// `weebo_si_admission_requests_total` carries for that decision, via
    /// [`weebo_si_chassis::FeatureOutcome`]. Passing it rather than a literal is what makes the
    /// two admission metrics agree by construction: a `duration_seconds{resource="Pod"}` with no
    /// matching `requests_total{resource="Pod"}` would be two views of one request disagreeing
    /// about what the request was.
    pub fn timer(&self, feature: &str, resource: &str) -> Histogram {
        self.duration_seconds
            .with_label_values(&[feature, resource])
    }

    /// One request a guard handler allowed **without deciding anything**, because the resource it
    /// was against is not one that handler knows.
    ///
    /// That branch is correct — a guard protects objects this operator wrote, and it did not
    /// write that one — but it was also *silent*: it returns before the timer, before
    /// `admit()`, and therefore before every metric and log line the request would otherwise
    /// produce. So the one configuration that makes it dangerous, a `ValidatingWebhookConfiguration`
    /// rule routing a fourth resource to a handler whose enum has three, looked exactly like a
    /// resource nobody was writing. This counter is the difference. Nonzero and climbing means
    /// the chart and the code disagree about what is guarded, and the log line beside each
    /// increment names the resource.
    ///
    /// **`path` and `feature`, not the resource.** The unrecognised plural is the one useful
    /// thing to know and the one thing that must not be a label: nothing authenticates the caller
    /// of an admission endpoint, so any pod that can dial the webhook Service can put an
    /// arbitrary string in `request.resource.resource`. As a label that mints unbounded series
    /// on demand; in the log line next to it, it is just a string. Both labels here are
    /// compile-time constants, which is the same rule `weebo_si_admission_requests_total`'s
    /// `resource` follows via `Subject::resource() -> &'static str`.
    pub fn unguarded(&self, feature: &str, path: &'static str) {
        self.unguarded_total
            .with_label_values(&[feature, path])
            .inc();
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
    use super::*;

    fn unguarded_series(registry: &prometheus::Registry) -> Vec<(String, String, u64)> {
        let mut out = Vec::new();
        for family in registry.gather() {
            if family.name() != "weebo_si_admission_unguarded_total" {
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
                    label("path"),
                    metric.get_counter().value() as u64,
                ));
            }
        }
        out.sort();
        out
    }

    /// The counter exists only when something was actually skipped — a series that appears at
    /// zero would read as "drift is being watched for" on a deployment where the metric was
    /// never wired to the branch at all.
    #[test]
    fn no_series_exists_until_a_request_is_actually_skipped() {
        let registry = prometheus::Registry::new();
        let metrics = WebhookMetrics::register(&registry).expect("metrics should register");
        assert_eq!(unguarded_series(&registry), Vec::new());

        metrics.unguarded("policy-guard", crate::VALIDATE_KUBEARMOR_POLICIES_PATH);
        assert_eq!(
            unguarded_series(&registry),
            vec![(
                "policy-guard".to_string(),
                "/validate/v1/kubearmorpolicies".to_string(),
                1
            )]
        );
    }

    /// The two guard handlers share a `feature` label, so `path` is the only thing separating
    /// them — a drifted rule on one route must not be indistinguishable from one on the other.
    #[test]
    fn the_two_guard_routes_are_distinguishable_under_one_feature_label() {
        let registry = prometheus::Registry::new();
        let metrics = WebhookMetrics::register(&registry).expect("metrics should register");
        metrics.unguarded("policy-guard", crate::VALIDATE_NETWORK_POLICIES_PATH);
        metrics.unguarded("policy-guard", crate::VALIDATE_NETWORK_POLICIES_PATH);
        metrics.unguarded("policy-guard", crate::VALIDATE_REGISTRY_CONFIGS_PATH);

        assert_eq!(
            unguarded_series(&registry),
            vec![
                (
                    "policy-guard".to_string(),
                    "/validate/v1/networkpolicies".to_string(),
                    2
                ),
                (
                    "policy-guard".to_string(),
                    "/validate/v1/registryconfigs".to_string(),
                    1
                ),
            ]
        );
    }
}
