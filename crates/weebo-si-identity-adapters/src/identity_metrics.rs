//! RFC 0011's three counters: teams resolved, people's objects reconciled by outcome, and
//! provisioning failures by kind.
//!
//! No namespace and no username in any label, per RFC 0004's project-wide observability rule: a
//! per-person time series is exactly the kind of unbounded cardinality a hardening component must
//! not create. Which person is `Conflict` is a `kubectl get weebosiusers` away.

use prometheus::{IntCounterVec, Opts, Registry};
use weebo_si_crd::TargetState;
use weebo_si_identity::port::ProvisionObserver;

/// The `state` label of a [`TargetState`].
///
/// Lowercase, like every other label value in this project (`enforced`, `not_granted`,
/// `replaced`) and unlike the `status` field it comes from, which is written in the API's own
/// PascalCase. The mapping is spelled out here rather than derived from `Display` so a rename on
/// either side cannot silently rewrite a dashboard query.
fn state_label(state: TargetState) -> &'static str {
    match state {
        TargetState::Off => "off",
        TargetState::Created => "created",
        TargetState::Adopted => "adopted",
        TargetState::Absent => "absent",
        TargetState::Conflict => "conflict",
    }
}

/// The identity feature's counters.
#[derive(Clone)]
pub struct IdentityMetrics {
    teams_total: IntCounterVec,
    users_total: IntCounterVec,
    errors_total: IntCounterVec,
}

impl IdentityMetrics {
    /// Register every metric against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let teams_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_identity_teams_total",
                "WeeboSiTeam reconcile passes, by whether the team reported violations",
            ),
            &["result"],
        )?;
        let users_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_identity_users_total",
                "Provisioned objects reconciled for a WeeboSiUser, by kind and outcome",
            ),
            &["kind", "state"],
        )?;
        let errors_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_identity_errors_total",
                "Provisioning calls that failed, by kind",
            ),
            &["kind"],
        )?;

        for metric in [&teams_total, &users_total, &errors_total] {
            registry.register(Box::new(metric.clone()))?;
        }

        Ok(Self {
            teams_total,
            users_total,
            errors_total,
        })
    }
}

impl ProvisionObserver for IdentityMetrics {
    fn team_reconciled(&self, degraded: bool) {
        let result = if degraded { "degraded" } else { "ok" };
        self.teams_total.with_label_values(&[result]).inc();
    }

    fn user_reconciled(&self, kind: &str, state: TargetState) {
        self.users_total
            .with_label_values(&[kind, state_label(state)])
            .inc();
    }

    fn provision_failed(&self, kind: &str) {
        self.errors_total.with_label_values(&[kind]).inc();
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn every_state_has_a_lowercase_label() {
        for state in [
            TargetState::Off,
            TargetState::Created,
            TargetState::Adopted,
            TargetState::Absent,
            TargetState::Conflict,
        ] {
            let label = state_label(state);
            assert_eq!(label, label.to_lowercase(), "{state} labelled as {label}");
        }
        assert_eq!(state_label(TargetState::Conflict), "conflict");
    }
}
