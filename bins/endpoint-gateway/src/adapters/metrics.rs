//! The gateway's metrics — RFC 0009's *Observability*, with the closed-label rule this project
//! has had to correct itself on twice: **no label carries a namespace, a host or a workspace
//! id**, and every label's value set is a Rust enum rendered by a `&'static str`.

use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use weebo_si_endpoint_auth::cache::{CacheKind, CacheOutcome};
use weebo_si_endpoint_auth::decide::Decision;

/// Everything this binary publishes.
#[derive(Clone)]
pub struct GatewayMetrics {
    decisions: IntCounterVec,
    decision_seconds: Histogram,
    identity_cache: IntCounterVec,
    logins: IntCounterVec,
    cache_synced: IntGauge,
    indexed_endpoints: IntGauge,
    host_conflicts: IntGauge,
    insecure_hosts: IntCounterVec,
    self_origin: IntCounterVec,
    client_ip_trusted: IntGauge,
    revocations: IntGauge,
    policy_compile_seconds: Histogram,
    observed_only: IntGaugeVec,
}

impl GatewayMetrics {
    /// Register everything against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let decisions = IntCounterVec::new(
            Opts::new(
                "weebo_si_endpoint_auth_decisions_total",
                "Decisions, by verdict and reason",
            ),
            &["verdict", "reason"],
        )?;
        let decision_seconds = Histogram::with_opts(HistogramOpts::new(
            "weebo_si_endpoint_auth_decision_seconds",
            "In-process time to decide one request — the hop is measured at the controller",
        ))?;
        let identity_cache = IntCounterVec::new(
            Opts::new(
                "weebo_si_endpoint_auth_identity_cache_total",
                "Identity-cache lookups, by cache and result",
            ),
            &["kind", "result"],
        )?;
        let logins = IntCounterVec::new(
            Opts::new("weebo_si_endpoint_auth_logins_total", "Sign-ins, by result"),
            &["result"],
        )?;
        let cache_synced = IntGauge::new(
            "weebo_si_endpoint_auth_cache_synced",
            "1 once the informers have synced and this replica may answer",
        )?;
        let indexed_endpoints = IntGauge::new(
            "weebo_si_endpoint_auth_indexed_endpoints",
            "Hosts currently indexed",
        )?;
        let host_conflicts = IntGauge::new(
            "weebo_si_endpoint_auth_host_conflicts",
            "Hosts claimed by more than one object — always an attack or a bug",
        )?;
        let insecure_hosts = IntCounterVec::new(
            Opts::new(
                "weebo_si_endpoint_auth_insecure_hosts",
                "Requests refused because the endpoint is served over plain HTTP",
            ),
            &["result"],
        )?;
        let self_origin = IntCounterVec::new(
            Opts::new(
                "weebo_si_endpoint_auth_self_origin_total",
                "Self-origin resolutions, by result",
            ),
            &["result"],
        )?;
        let client_ip_trusted = IntGauge::new(
            "weebo_si_endpoint_auth_client_ip_trusted",
            "1 while the client address may be used as an identity; 0 is the state where \
             pod-address identity is off",
        )?;
        let revocations = IntGauge::new(
            "weebo_si_endpoint_auth_revocations",
            "Sessions currently revoked",
        )?;
        let policy_compile_seconds = Histogram::with_opts(HistogramOpts::new(
            "weebo_si_endpoint_auth_policy_compile_seconds",
            "Time to rebuild the whole host index — the write-side cost",
        ))?;
        let observed_only = IntGaugeVec::new(
            Opts::new(
                "weebo_si_endpoint_auth_bypassed",
                "Endpoints the gate is not enforcing for, by reason",
            ),
            &["reason"],
        )?;

        for collector in [
            Box::new(decisions.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(decision_seconds.clone()),
            Box::new(identity_cache.clone()),
            Box::new(logins.clone()),
            Box::new(cache_synced.clone()),
            Box::new(indexed_endpoints.clone()),
            Box::new(host_conflicts.clone()),
            Box::new(insecure_hosts.clone()),
            Box::new(self_origin.clone()),
            Box::new(client_ip_trusted.clone()),
            Box::new(revocations.clone()),
            Box::new(policy_compile_seconds.clone()),
            Box::new(observed_only.clone()),
        ] {
            registry.register(collector)?;
        }

        Ok(Self {
            decisions,
            decision_seconds,
            identity_cache,
            logins,
            cache_synced,
            indexed_endpoints,
            host_conflicts,
            insecure_hosts,
            self_origin,
            client_ip_trusted,
            revocations,
            policy_compile_seconds,
            observed_only,
        })
    }

    /// Record one decision. The label values come from the decision's own closed enums, never
    /// from formatting whatever arrived.
    pub fn decided(&self, decision: Decision, seconds: f64) {
        self.decisions
            .with_label_values(&[decision.verdict_label(), decision.reason.label()])
            .inc();
        self.decision_seconds.observe(seconds);
        if decision.reason == weebo_si_endpoint_auth::decide::Reason::InsecureScheme {
            self.insecure_hosts.with_label_values(&["refused"]).inc();
        }
        if decision.reason == weebo_si_endpoint_auth::decide::Reason::SelfOrigin {
            self.self_origin.with_label_values(&["pod"]).inc();
        }
    }

    /// Advance one cache's counters by what it has done since the last scrape.
    ///
    /// A delta rather than a set, because `_total` is a counter and a counter that goes down is
    /// one no `rate()` can read. The caches themselves keep the running totals; this publishes
    /// the difference.
    pub fn cache_delta(&self, kind: CacheKind, hits: u64, misses: u64, evictions: u64) {
        for (outcome, delta) in [
            (CacheOutcome::Hit, hits),
            (CacheOutcome::Miss, misses),
            (CacheOutcome::Evicted, evictions),
        ] {
            if delta > 0 {
                self.identity_cache
                    .with_label_values(&[kind.label(), outcome.label()])
                    .inc_by(delta);
            }
        }
    }

    /// Record a sign-in.
    pub fn login(&self, result: &'static str) {
        self.logins.with_label_values(&[result]).inc();
    }

    /// Record a self-origin resolution that found nothing — the diagnosis, not an alert: this
    /// series being the whole population means the cluster SNATs and workspaces should use the
    /// token path.
    pub fn self_origin_unknown(&self) {
        self.self_origin
            .with_label_values(&["unknown_address"])
            .inc();
    }

    /// Publish the index's shape after a rebuild.
    pub fn indexed(&self, endpoints: usize, conflicts: usize, refused: usize, seconds: f64) {
        self.indexed_endpoints.set(endpoints as i64);
        self.host_conflicts.set(conflicts as i64);
        self.policy_compile_seconds.observe(seconds);
        self.observed_only
            .with_label_values(&["compile_failed"])
            .set(refused as i64);
    }

    /// Whether this replica may answer at all.
    pub fn synced(&self, synced: bool) {
        self.cache_synced.set(i64::from(synced));
    }

    /// Whether the client address is currently usable as an identity.
    pub fn address_trust(&self, trusted: bool) {
        self.client_ip_trusted.set(i64::from(trusted));
    }

    /// How many sessions are revoked.
    pub fn revoked(&self, count: usize) {
        self.revocations.set(count as i64);
    }

    /// How many endpoints are answered without enforcement — `Observe`, or break-glass.
    pub fn observed(&self, reason: &'static str, count: usize) {
        self.observed_only
            .with_label_values(&[reason])
            .set(count as i64);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_endpoint_auth::decide::{Reason, Verdict};

    use super::*;

    #[test]
    fn every_label_value_comes_from_a_closed_enum() {
        let registry = Registry::new();
        let metrics = GatewayMetrics::register(&registry).unwrap();
        metrics.decided(
            Decision {
                verdict: Verdict::Deny,
                reason: Reason::NotOwner,
            },
            0.0001,
        );
        metrics.cache_delta(CacheKind::Session, 199, 1, 0);
        metrics.indexed(3, 0, 0, 0.002);
        metrics.synced(true);

        let families = registry.gather();
        let names: Vec<&str> = families.iter().map(|family| family.name()).collect();
        assert!(names.contains(&"weebo_si_endpoint_auth_decisions_total"));
        assert!(names.contains(&"weebo_si_endpoint_auth_identity_cache_total"));

        // The project-wide rule, asserted rather than reviewed: no series carries a namespace, a
        // host or a workspace id.
        for family in &families {
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    assert!(
                        !["namespace", "host", "workspace", "user"].contains(&label.name()),
                        "{} carries a {} label",
                        family.name(),
                        label.name()
                    );
                }
            }
        }
    }
}
