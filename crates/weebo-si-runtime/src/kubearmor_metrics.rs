//! RFC 0006's observability, the reconcile-side half — the same five-metric shape
//! [`crate::network_metrics`] has for `network-profiles`, with the canary replaced by this
//! brick's own enforcement gauge.
//!
//! **`weebo_si_kubearmor_enforced` is labelled by `state`, not by `{namespace, workspace}`.**
//! RFC 0006's *Contract* wrote it the second way; RFC 0004's *Observability contract* forbids
//! exactly that, project-wide: "No metric carries a namespace or a workspace id as a label. Both
//! scale with the cluster, and a per-workspace time series is how a metrics backend is taken down
//! by a hardening component." Implementing 0006 as written would have made this brick the one
//! that does it. The gauge therefore publishes the *count of workspaces* in each of the three
//! states, which alerts identically (`state="not_enforced" > 0`) and costs three series instead
//! of two per workspace. Which workspace is unenforced is a log line and a `kubectl get pod -o
//! wide` away — the same answer RFC 0004 gives for its own per-namespace questions. RFC 0006 has
//! been amended to match.

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};
use weebo_si_crd::{RuntimeBackend, TeamName};
use weebo_si_kubearmor_policy::{
    Diff, Enforcement, ManagedObject, PodSelector, ReconcileObserver, ReconcileOutcome,
};

/// The `team` label's value when no team matched. A literal rather than an empty string, so a
/// dashboard query does not have to distinguish "no team" from "label missing".
const NO_TEAM: &str = "_none";

/// The `kind` label for a managed object's `weebo_si_kubearmor_managed_objects` series.
fn kind_label(backend: RuntimeBackend) -> &'static str {
    match backend {
        RuntimeBackend::KubeArmor => "KubeArmorPolicy",
    }
}

/// Which of the two objects RFC 0006 writes this is — read off the pod selector, since that is
/// the difference between them.
fn scope_label(object: &ManagedObject) -> &'static str {
    match object.pod_selector {
        PodSelector::Empty => "baseline",
        PodSelector::DevWorkspaceId(_) => "profile",
    }
}

/// The `state` label of [`Enforcement`].
fn state_label(state: &Enforcement) -> &'static str {
    match state {
        Enforcement::Enforced(_) => "enforced",
        Enforcement::NotEnforced => "not_enforced",
        Enforcement::Unknown => "unknown",
    }
}

/// Every `state` value, so the gauge always publishes all three and a query for `not_enforced`
/// reads `0` rather than *absent* on a healthy cluster — which is what makes it alertable.
const STATES: [&str; 3] = ["enforced", "not_enforced", "unknown"];

/// The five reconcile-driven metrics of RFC 0006.
#[derive(Clone)]
pub struct KubeArmorMetrics {
    reconcile_total: IntCounterVec,
    managed_objects: IntGaugeVec,
    drift_total: IntCounterVec,
    enforced: IntGaugeVec,
    not_granted_total: IntCounterVec,
}

impl KubeArmorMetrics {
    /// Register every metric against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_kubearmor_reconcile_total",
                "kubearmor-policy reconcile outcomes, by result and team",
            ),
            &["result", "team"],
        )?;
        let managed_objects = IntGaugeVec::new(
            Opts::new(
                "weebo_si_kubearmor_managed_objects",
                "KubeArmor policy objects this operator currently owns, by kind and scope",
            ),
            &["kind", "scope"],
        )?;
        let drift_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_kubearmor_drift_total",
                "Managed policy objects the controller had to put back or take away",
            ),
            &["action"],
        )?;
        let enforced = IntGaugeVec::new(
            Opts::new(
                "weebo_si_kubearmor_enforced",
                "Workspaces by whether the node hosting them can enforce policy at all",
            ),
            &["state"],
        )?;
        let not_granted_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_kubearmor_not_granted_total",
                "Runtime profile keys a workspace asked for that its team's grant does not allow",
            ),
            &["team", "profile"],
        )?;

        for metric in [&reconcile_total, &drift_total, &not_granted_total] {
            registry.register(Box::new(metric.clone()))?;
        }
        for metric in [&managed_objects, &enforced] {
            registry.register(Box::new(metric.clone()))?;
        }
        Ok(Self {
            reconcile_total,
            managed_objects,
            drift_total,
            enforced,
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
                // A `Create` is deliberately not counted: it is indistinguishable from the very
                // first reconcile of a new namespace, and a drift counter that ticks on every
                // install teaches nothing.
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
    /// time.
    pub fn observe_error(&self) {
        self.reconcile_total
            .with_label_values(&["error", NO_TEAM])
            .inc();
    }

    /// Set `weebo_si_kubearmor_managed_objects` from a full snapshot of what this operator owns.
    ///
    /// Takes the whole population rather than a delta on purpose: a gauge maintained by
    /// increments drifts permanently the first time a decrement is missed, and this one is cheap
    /// to recompute from a watch cache that already holds every object.
    pub fn set_managed_objects(&self, objects: &[ManagedObject]) {
        self.managed_objects.reset();
        for backend in [RuntimeBackend::KubeArmor] {
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

    /// Set `weebo_si_kubearmor_enforced` from a full snapshot of every workspace's state.
    ///
    /// All three states are always published, including the zeroes: RFC 0006's whole *Bypass*
    /// argument is that an unenforced workspace must be **visible**, and a metric that is absent
    /// until something is wrong is one nobody has a dashboard panel for.
    pub fn set_enforcement(&self, states: &[Enforcement]) {
        for state in STATES {
            let count = states
                .iter()
                .filter(|observed| state_label(observed) == state)
                .count();
            self.enforced.with_label_values(&[state]).set(count as i64);
        }
    }
}

/// The port the controller actually holds. The inherent methods above stay public so a test (and
/// the CLI, which has no controller around it) can drive one metric without implementing the
/// whole port.
impl ReconcileObserver for KubeArmorMetrics {
    fn reconciled(&self, outcome: &ReconcileOutcome) {
        self.observe_reconcile(outcome);
    }

    fn failed(&self) {
        self.observe_error();
    }

    fn managed_objects(&self, objects: &[ManagedObject]) {
        self.set_managed_objects(objects);
    }

    fn enforcement_snapshot(&self, states: &[Enforcement]) {
        self.set_enforcement(states);
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
    use weebo_si_crd::{NamespaceName, RuntimeProfileKey};
    use weebo_si_kubearmor_policy::{Applied, ObjectKey, RuleBody};

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
            .unwrap_or_else(|| panic!("no sample for {name}{labels:?}"))
    }

    fn object(name: &str, selector: PodSelector) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            backend: RuntimeBackend::KubeArmor,
            profile: RuntimeProfileKey::new("base"),
            pod_selector: selector,
            body: RuleBody::opaque(b"rules".to_vec()),
        }
    }

    fn outcome(applied: Option<Applied>, diffs: Vec<Diff>) -> ReconcileOutcome {
        ReconcileOutcome {
            diffs,
            applied,
            posture: None,
            team: Some(TeamName::new("team-1")),
            not_granted: Vec::new(),
        }
    }

    #[test]
    fn an_enforce_pass_counts_what_was_applied() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            Some(Applied {
                created: 2,
                ..Applied::default()
            }),
            vec![],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_reconcile_total",
                &[("result", "created"), ("team", "team-1")]
            ),
            2
        );
    }

    #[test]
    fn a_dry_run_pass_never_lands_on_a_write_result() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            None,
            vec![Diff::Create(object("weebo-base", PodSelector::Empty))],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_reconcile_total",
                &[("result", "dry_run"), ("team", "team-1")]
            ),
            1
        );
    }

    #[test]
    fn an_update_in_enforce_is_counted_as_restored_drift() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            Some(Applied {
                updated: 1,
                ..Applied::default()
            }),
            vec![Diff::Update(object("weebo-base", PodSelector::Empty))],
        ));
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_drift_total",
                &[("action", "restored")]
            ),
            1
        );
    }

    #[test]
    fn a_create_is_not_drift() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            Some(Applied {
                created: 1,
                ..Applied::default()
            }),
            vec![Diff::Create(object("weebo-base", PodSelector::Empty))],
        ));
        assert!(
            registry
                .gather()
                .iter()
                .filter(|family| family.name() == "weebo_si_kubearmor_drift_total")
                .flat_map(|family| family.get_metric().to_vec())
                .all(|metric| metric.get_counter().value() == 0.0),
            "the first reconcile of a new namespace is not somebody editing ours"
        );
    }

    #[test]
    fn managed_objects_are_counted_by_kind_and_scope() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[
            object("weebo-base", PodSelector::Empty),
            object(
                "weebo-git-write-ws1",
                PodSelector::DevWorkspaceId("ws1".to_string()),
            ),
            object(
                "weebo-git-write-ws2",
                PodSelector::DevWorkspaceId("ws2".to_string()),
            ),
        ]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_managed_objects",
                &[("kind", "KubeArmorPolicy"), ("scope", "baseline")]
            ),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_managed_objects",
                &[("kind", "KubeArmorPolicy"), ("scope", "profile")]
            ),
            2
        );
    }

    #[test]
    fn the_managed_objects_gauge_is_recomputed_not_incremented() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.set_managed_objects(&[object("weebo-base", PodSelector::Empty)]);
        metrics.set_managed_objects(&[]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_managed_objects",
                &[("kind", "KubeArmorPolicy"), ("scope", "baseline")]
            ),
            0,
            "a namespace whose objects went away must read 0, not the last non-zero count"
        );
    }

    #[test]
    fn the_enforcement_gauge_counts_workspaces_per_state() {
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.set_enforcement(&[
            Enforcement::Enforced("bpf".to_string()),
            Enforcement::Enforced("apparmor".to_string()),
            Enforcement::NotEnforced,
            Enforcement::Unknown,
        ]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_enforced",
                &[("state", "enforced")]
            ),
            2
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_enforced",
                &[("state", "not_enforced")]
            ),
            1
        );
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_enforced",
                &[("state", "unknown")]
            ),
            1
        );
    }

    #[test]
    fn the_enforcement_gauge_publishes_zeroes_on_a_healthy_cluster() {
        // "not a metric that goes quiet": `not_enforced` has to read 0 rather than be absent,
        // or nobody can build the alert that RFC 0006's *Bypass* section depends on.
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.set_enforcement(&[Enforcement::Enforced("bpf".to_string())]);
        assert_eq!(
            sample(
                &registry,
                "weebo_si_kubearmor_enforced",
                &[("state", "not_enforced")]
            ),
            0
        );
    }

    #[test]
    fn no_metric_carries_a_namespace_or_a_workspace_label() {
        // RFC 0004's *Observability contract*, which binds every brick: "No metric carries a
        // namespace or a workspace id as a label." Asserted here rather than only argued in a
        // doc comment, because this brick's own RFC originally specified one that did.
        let registry = Registry::new();
        let metrics = KubeArmorMetrics::register(&registry).unwrap();
        metrics.observe_reconcile(&outcome(
            None,
            vec![Diff::Unchanged(ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-base".to_string(),
            })],
        ));
        metrics.set_managed_objects(&[object("weebo-base", PodSelector::Empty)]);
        metrics.set_enforcement(&[Enforcement::NotEnforced]);

        for family in registry.gather() {
            for metric in family.get_metric() {
                for label in metric.get_label() {
                    assert!(
                        !["namespace", "workspace", "workspace_id", "pod"].contains(&label.name()),
                        "{} carries a per-workspace label: {}",
                        family.name(),
                        label.name()
                    );
                }
            }
        }
    }
}
