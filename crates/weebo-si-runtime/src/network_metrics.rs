//! RFC 0004's *Observability contract*, the reconcile-side half.
//!
//! Two of the seven metrics are not here: `weebo_si_network_backend` and
//! `weebo_si_network_profile_unsupported` are facts about the *configuration* (which backend
//! resolved, which catalogue entries have no variant for it), not about any one reconcile pass,
//! so they are set from [`crate::config_store`]'s own sync where the config and the resolved
//! backend already live. Driving them from here would mean a gauge whose value depends on which
//! namespace was reconciled last.
//!
//! **No metric carries a namespace or a workspace id**, per the RFC: "Both scale with the
//! cluster, and a per-workspace time series is how a metrics backend is taken down by a hardening
//! component." Every label below is bounded by the catalogue, the team list, or a fixed enum.

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{Backend, TeamName};
use weebo_si_network_profiles::{
    CanaryVerdict, Diff, ManagedObject, PodSelector, ReconcileObserver, ReconcileOutcome,
};

/// The `team` label's value when no team matched. A literal rather than an empty string, so a
/// dashboard query does not have to distinguish "no team" from "label missing".
const NO_TEAM: &str = "_none";

/// The `kind` label for a managed object's `weebo_si_network_managed_objects` series.
fn kind_label(backend: Backend) -> &'static str {
    match backend {
        Backend::NetworkPolicy => "NetworkPolicy",
        Backend::Cilium => "CiliumNetworkPolicy",
    }
}

/// The `backend` label — the enum's own name, matching `hardening.weebo.io/backend`'s value.
pub fn backend_label(backend: Backend) -> &'static str {
    match backend {
        Backend::NetworkPolicy => "NetworkPolicy",
        Backend::Cilium => "Cilium",
    }
}

/// Which of the two objects RFC 0004 writes this is — read off the pod selector, since that is
/// the difference between them: `{}` governs every pod in the namespace, a `devworkspace_id`
/// selector governs one workspace's.
fn scope_label(object: &ManagedObject) -> &'static str {
    match object.pod_selector {
        PodSelector::Empty => "baseline",
        PodSelector::DevWorkspaceId(_) => "profile",
    }
}

/// The five reconcile-driven metrics from RFC 0004's *Observability contract*.
#[derive(Clone)]
pub struct NetworkMetrics {
    reconcile_total: IntCounterVec,
    managed_objects: IntGaugeVec,
    drift_total: IntCounterVec,
    canary: IntGaugeVec,
    not_granted_total: IntCounterVec,
}

impl NetworkMetrics {
    /// Register every metric against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_network_reconcile_total",
                "network-profiles reconcile outcomes, by result and team",
            ),
            &["result", "team"],
        )?;
        let managed_objects = IntGaugeVec::new(
            Opts::new(
                "weebo_si_network_managed_objects",
                "Policy objects this operator currently owns, by kind and scope",
            ),
            &["kind", "scope"],
        )?;
        let drift_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_network_drift_total",
                "Managed objects the controller had to put back or take away",
            ),
            &["action"],
        )?;
        let canary = IntGaugeVec::new(
            Opts::new(
                "weebo_si_network_canary",
                "1 for the enforcement probe's current verdict",
            ),
            &["result"],
        )?;
        let not_granted_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_network_not_granted_total",
                "Profile keys a workspace asked for that its team's grant does not allow",
            ),
            &["team", "profile"],
        )?;

        for metric in [&reconcile_total, &drift_total, &not_granted_total] {
            registry.register(Box::new(metric.clone()))?;
        }
        for metric in [&managed_objects, &canary] {
            registry.register(Box::new(metric.clone()))?;
        }
        Ok(Self {
            reconcile_total,
            managed_objects,
            drift_total,
            canary,
            not_granted_total,
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
                // Drift is only readable in `Enforce`, because only there did anything move.
                // `restored` counts an object that existed but no longer matched what it should
                // be — the unambiguous "somebody edited ours" signal. A `Create` is deliberately
                // not counted: it is indistinguishable from the very first reconcile of a new
                // namespace, and a drift counter that ticks on every install teaches nothing.
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

        for profile in &outcome.not_granted {
            self.not_granted_total
                .with_label_values(&[team, profile.as_str()])
                .inc();
        }
    }

    /// A reconcile pass that did not finish. Counted separately from every other result because
    /// sustained `error` is the fleet drifting away from its intended state one namespace at a
    /// time — see the RFC's *Observability*.
    pub fn observe_error(&self) {
        self.reconcile_total
            .with_label_values(&["error", NO_TEAM])
            .inc();
    }

    /// Set `weebo_si_network_managed_objects` from a full snapshot of what this operator owns.
    ///
    /// Takes the whole population rather than a delta on purpose: a gauge maintained by
    /// increments drifts permanently the first time a decrement is missed, and this one is
    /// cheap to recompute from a watch cache that already holds every object.
    pub fn set_managed_objects(&self, objects: &[ManagedObject]) {
        self.managed_objects.reset();
        for backend in [Backend::NetworkPolicy, Backend::Cilium] {
            for scope in ["baseline", "profile"] {
                let count = objects
                    .iter()
                    .filter(|obj| obj.backend == backend && scope_label(obj) == scope)
                    .count();
                self.managed_objects
                    .with_label_values(&[kind_label(backend), scope])
                    .set(count as i64);
            }
        }
    }

    /// Set `weebo_si_network_canary` to `1` for `verdict` and `0` for the other two — so a query
    /// for `not_enforcing` reads `0` rather than *absent* on a healthy cluster, which is what
    /// makes it alertable.
    pub fn set_canary(&self, verdict: CanaryVerdict) {
        for candidate in [
            CanaryVerdict::Enforcing,
            CanaryVerdict::NotEnforcing,
            CanaryVerdict::Unknown,
        ] {
            self.canary
                .with_label_values(&[candidate.label()])
                .set(i64::from(candidate == verdict));
        }
    }
}

/// The port the controller actually holds. The inherent methods above stay public so a test (and
/// the `canary` subcommand, which has no controller around it) can drive one metric without
/// implementing the whole port.
impl ReconcileObserver for NetworkMetrics {
    fn reconciled(&self, outcome: &ReconcileOutcome) {
        self.observe_reconcile(outcome);
    }

    fn failed(&self) {
        self.observe_error();
    }

    fn managed_objects(&self, objects: &[ManagedObject]) {
        self.set_managed_objects(objects);
    }

    fn canary(&self, verdict: CanaryVerdict) {
        self.set_canary(verdict);
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
    use weebo_si_crd::{NamespaceName, ProfileKey};
    use weebo_si_network_profiles::{Applied, ObjectKey, PolicyBody};

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
            .unwrap_or_default()
    }

    fn object(name: &str, selector: PodSelector) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            backend: Backend::NetworkPolicy,
            profile: ProfileKey::new("base"),
            pod_selector: selector,
            body: PolicyBody::opaque(b"rules".to_vec()),
        }
    }

    fn outcome(applied: Option<Applied>, diffs: Vec<Diff>) -> ReconcileOutcome {
        ReconcileOutcome {
            diffs,
            applied,
            team: Some(TeamName::new("team-1")),
            not_granted: Vec::new(),
            unsupported: Vec::new(),
        }
    }

    #[test]
    fn enforce_counts_what_was_applied_under_the_matched_team() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            Some(Applied {
                created: 2,
                updated: 1,
                deleted: 0,
                unchanged: 3,
            }),
            Vec::new(),
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "created"), ("team", "team-1")]
            ),
            2
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "unchanged"), ("team", "team-1")]
            ),
            3
        );
    }

    #[test]
    fn dry_run_never_lands_on_a_write_result() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        let diffs = vec![
            Diff::Create(object("weebo-base", PodSelector::Empty)),
            Diff::Create(object(
                "weebo-git-abc",
                PodSelector::DevWorkspaceId("abc".into()),
            )),
        ];
        metrics.observe_reconcile(&outcome(None, diffs));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "dry_run"), ("team", "team-1")]
            ),
            2
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "created"), ("team", "team-1")]
            ),
            0,
            "a DryRun pass must never increment a write result"
        );
    }

    #[test]
    fn an_update_is_drift_restored_and_a_create_is_not() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            Some(Applied::default()),
            vec![
                Diff::Update(object("weebo-base", PodSelector::Empty)),
                Diff::Create(object(
                    "weebo-git-abc",
                    PodSelector::DevWorkspaceId("abc".into()),
                )),
            ],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_drift_total",
                &[("action", "restored")]
            ),
            1,
            "the Update is the 'somebody edited ours' signal"
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_drift_total",
                &[("action", "removed")]
            ),
            0
        );
    }

    #[test]
    fn an_ungranted_key_is_counted_per_team_and_profile() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        let mut result = outcome(Some(Applied::default()), Vec::new());
        result.not_granted = vec![ProfileKey::new("vault")];
        metrics.observe_reconcile(&result);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_not_granted_total",
                &[("team", "team-1"), ("profile", "vault")]
            ),
            1
        );
    }

    #[test]
    fn a_reconcile_with_no_team_is_still_counted_under_a_real_label_value() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        let mut result = outcome(
            Some(Applied {
                created: 1,
                ..Applied::default()
            }),
            Vec::new(),
        );
        result.team = None;
        metrics.observe_reconcile(&result);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "created"), ("team", NO_TEAM)]
            ),
            1
        );
    }

    #[test]
    fn managed_objects_splits_the_baseline_from_the_profile_objects() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[
            object("weebo-base", PodSelector::Empty),
            object("weebo-git-abc", PodSelector::DevWorkspaceId("abc".into())),
            object("weebo-vault-abc", PodSelector::DevWorkspaceId("abc".into())),
        ]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_managed_objects",
                &[("kind", "NetworkPolicy"), ("scope", "baseline")]
            ),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_managed_objects",
                &[("kind", "NetworkPolicy"), ("scope", "profile")]
            ),
            2
        );
    }

    #[test]
    fn a_shrinking_population_shrinks_the_gauge() {
        // The reason `set_managed_objects` takes a snapshot: an incrementing gauge that missed
        // one decrement over-reports for the lifetime of the process.
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[
            object("weebo-base", PodSelector::Empty),
            object("weebo-git-abc", PodSelector::DevWorkspaceId("abc".into())),
        ]);
        metrics.set_managed_objects(&[object("weebo-base", PodSelector::Empty)]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_managed_objects",
                &[("kind", "NetworkPolicy"), ("scope", "profile")]
            ),
            0
        );
    }

    #[test]
    fn the_canary_gauge_reports_zero_for_the_verdicts_that_did_not_happen() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.set_canary(CanaryVerdict::Enforcing);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_canary",
                &[("result", "enforcing")]
            ),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_canary",
                &[("result", "not_enforcing")]
            ),
            0,
            "absent is not alertable; zero is"
        );

        metrics.set_canary(CanaryVerdict::NotEnforcing);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_canary",
                &[("result", "enforcing")]
            ),
            0
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_canary",
                &[("result", "not_enforcing")]
            ),
            1
        );
    }

    #[test]
    fn an_error_is_its_own_result_not_a_missing_increment() {
        let registry = Registry::new();
        let metrics = NetworkMetrics::register(&registry).unwrap();
        metrics.observe_error();
        assert_eq!(
            sample(
                &registry,
                "weebo_si_network_reconcile_total",
                &[("result", "error")]
            ),
            1
        );
    }
}
