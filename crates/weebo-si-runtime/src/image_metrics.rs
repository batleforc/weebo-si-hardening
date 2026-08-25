//! RFC 0005's *Observability contract* — the admission-driven half.
//!
//! One of the five metrics is not here: `weebo_si_image_policy_catalog_entries` is a fact about
//! the *configuration* (how many entries parse), not about any one admission, so it is set from
//! [`crate::config_store`]'s own sync where the config already lives — the same split RFC 0004
//! makes for `weebo_si_network_backend`. Driving it from here would mean a gauge whose value
//! depends on which request arrived last.
//!
//! **No metric carries an image reference, and no metric carries a variable's value.** Both are
//! attacker-influenced and unbounded, so a per-image or per-value time series is how a metrics
//! backend is taken down by a hardening component. The reference lives in the log line and the
//! API error, which are the two places it is actually useful; the variable's *name* is a label,
//! because names are written by an admin in one file and are bounded by that file's length.
//!
//! A variable's *value* does cross the port, in
//! [`ImagePolicyObserver::variable_value_seen`](weebo_si_image_policy::ImagePolicyObserver::variable_value_seen),
//! and stops here: it is compared against the last one seen and counted as a *change*, never
//! labelled. That is the whole of `weebo_si_image_policy_variable_changed_total`.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use prometheus::{IntCounterVec, Opts, Registry};
use weebo_si_crd::{NamespaceName, TeamName};
use weebo_si_image_policy::port::{ImagePolicyObserver, Resource};
use weebo_si_image_policy::{ImageVerdict, VariableName, VariableResult};

/// The `team` label's value when no team matched. A literal rather than an empty string, so a
/// dashboard query does not have to distinguish "no team" from "label missing". Same convention
/// as [`crate::network_metrics`]'s.
const NO_TEAM: &str = "_none";

fn team_label(team: Option<&TeamName>) -> &str {
    team.map_or(NO_TEAM, TeamName::as_str)
}

/// The four admission-driven metrics from RFC 0005's *Observability contract*.
#[derive(Clone)]
pub struct ImageMetrics {
    policy_total: IntCounterVec,
    platform_total: IntCounterVec,
    variable_total: IntCounterVec,
    variable_changed_total: IntCounterVec,
    /// Last-seen value per (namespace, variable), so a *change* can be told from a first
    /// observation. Bounded by the namespace count times the declared-variable count, and held
    /// here rather than exported: it is the counter's state, not a metric of its own — the
    /// unbounded thing never becomes a label.
    seen: Arc<RwLock<BTreeMap<(String, String), String>>>,
}

impl ImageMetrics {
    /// Register this adapter's metrics against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let policy_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_image_policy_total",
                "Image verdicts, by result, resource and team",
            ),
            &["result", "resource", "team"],
        )?;
        let platform_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_image_policy_platform_total",
                "Images permitted only by the platform set, by resource",
            ),
            &["resource"],
        )?;
        let variable_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_image_policy_variable_total",
                "Pattern variable resolutions, by variable name and result",
            ),
            &["variable", "result"],
        )?;
        let variable_changed_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_image_policy_variable_changed_total",
                "Times a bound namespace annotation's value changed, by variable name",
            ),
            &["variable"],
        )?;

        registry.register(Box::new(policy_total.clone()))?;
        registry.register(Box::new(platform_total.clone()))?;
        registry.register(Box::new(variable_total.clone()))?;
        registry.register(Box::new(variable_changed_total.clone()))?;

        Ok(Self {
            policy_total,
            platform_total,
            variable_total,
            variable_changed_total,
            seen: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }
}

impl ImagePolicyObserver for ImageMetrics {
    fn image_judged(
        &self,
        resource: Resource,
        team: Option<&TeamName>,
        verdict: &ImageVerdict,
        permitted_by_platform_only: bool,
    ) {
        self.policy_total
            .with_label_values(&[verdict.verdict.label(), resource.label(), team_label(team)])
            .inc();
        if permitted_by_platform_only {
            self.platform_total
                .with_label_values(&[resource.label()])
                .inc();
        }
    }

    fn not_granted(&self, resource: Resource, team: Option<&TeamName>, count: usize) {
        // One tick per *decision*, not per dropped key: the question the counter answers is "how
        // often does a workspace ask for something its team lacks", and a devfile naming three
        // ungranted keys is one such workspace.
        let _ = count;
        self.policy_total
            .with_label_values(&["not_granted", resource.label(), team_label(team)])
            .inc();
    }

    fn variable_resolved(&self, variable: &VariableName, result: VariableResult) {
        self.variable_total
            .with_label_values(&[variable.as_str(), result.label()])
            .inc();
    }

    /// **A detection control, not a diagnostic** — RFC 0005's answer to "how would we notice the
    /// RBAC assumption stopping being true". Where `variables` is declared, a bound annotation
    /// changing is either an admin doing something deliberate — rare — or a workspace user doing
    /// exactly the thing the design assumes they cannot. A sustained rate is an RBAC regression
    /// to go and verify with the checklist command, not a metrics problem.
    ///
    /// The *first* observation for a (namespace, variable) pair is not a change: every namespace
    /// would otherwise tick the counter once on the operator's first restart, which would teach
    /// nothing and would bury the signal this exists for.
    fn variable_value_seen(&self, namespace: &NamespaceName, variable: &VariableName, value: &str) {
        let key = (
            namespace.as_str().to_string(),
            variable.as_str().to_string(),
        );
        let mut seen = self
            .seen
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match seen.get(&key) {
            Some(previous) if previous == value => {}
            Some(_) => {
                self.variable_changed_total
                    .with_label_values(&[variable.as_str()])
                    .inc();
                seen.insert(key, value.to_string());
            }
            None => {
                seen.insert(key, value.to_string());
            }
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
    use weebo_si_crd::EntryKey;
    use weebo_si_image_policy::{PermittedBy, Verdict};

    use super::*;

    fn metrics() -> ImageMetrics {
        ImageMetrics::register(&Registry::new()).expect("registration should succeed")
    }

    fn counter(metrics: &ImageMetrics, labels: &[&str]) -> u64 {
        metrics.policy_total.with_label_values(labels).get()
    }

    fn name(raw: &str) -> VariableName {
        VariableName::new(raw).unwrap_or_else(|err| panic!("{err}"))
    }

    fn verdict(reference: &str, verdict: Verdict) -> ImageVerdict {
        ImageVerdict {
            container: "dev".to_string(),
            reference: reference.to_string(),
            verdict,
        }
    }

    #[test]
    fn a_verdict_is_counted_by_result_resource_and_team() {
        let metrics = metrics();
        metrics.image_judged(
            Resource::DevWorkspace,
            Some(&TeamName::new("team-1")),
            &verdict(
                "registry.internal/x:1",
                Verdict::Permitted(PermittedBy::Entry(EntryKey::new("internal"))),
            ),
            false,
        );
        assert_eq!(counter(&metrics, &["allowed", "devworkspace", "team-1"]), 1);
    }

    #[test]
    fn the_four_result_labels_are_all_reachable() {
        let metrics = metrics();
        metrics.image_judged(
            Resource::Pod,
            None,
            &verdict("x", Verdict::NoMatchingPattern),
            false,
        );
        metrics.image_judged(
            Resource::Pod,
            None,
            &verdict(
                "x",
                Verdict::Unparseable(weebo_si_image_policy::ParseError::Malformed),
            ),
            false,
        );
        metrics.not_granted(Resource::Pod, None, 1);
        assert_eq!(counter(&metrics, &["denied", "pod", NO_TEAM]), 1);
        assert_eq!(counter(&metrics, &["unparseable", "pod", NO_TEAM]), 1);
        assert_eq!(counter(&metrics, &["not_granted", "pod", NO_TEAM]), 1);
    }

    #[test]
    fn a_namespace_with_no_team_gets_a_named_label_not_an_empty_one() {
        let metrics = metrics();
        metrics.not_granted(Resource::Pod, None, 1);
        assert_eq!(counter(&metrics, &["not_granted", "pod", NO_TEAM]), 1);
    }

    #[test]
    fn a_platform_only_image_ticks_its_own_counter_as_well_as_the_main_one() {
        let metrics = metrics();
        metrics.image_judged(
            Resource::Pod,
            None,
            &verdict(
                "quay.io/devfile/project-clone:1",
                Verdict::Permitted(PermittedBy::Platform),
            ),
            true,
        );
        assert_eq!(counter(&metrics, &["allowed", "pod", NO_TEAM]), 1);
        assert_eq!(metrics.platform_total.with_label_values(&["pod"]).get(), 1);
    }

    #[test]
    fn an_ungranted_request_is_one_tick_per_decision_not_per_key() {
        let metrics = metrics();
        metrics.not_granted(Resource::DevWorkspace, Some(&TeamName::new("team-2")), 3);
        assert_eq!(
            counter(&metrics, &["not_granted", "devworkspace", "team-2"]),
            1
        );
    }

    #[test]
    fn a_variable_resolution_is_counted_by_name_and_result() {
        let metrics = metrics();
        metrics.variable_resolved(&name("PROJECT"), VariableResult::Illegal);
        assert_eq!(
            metrics
                .variable_total
                .with_label_values(&["PROJECT", "illegal"])
                .get(),
            1
        );
    }

    #[test]
    fn the_first_observation_of_a_value_is_not_counted_as_a_change() {
        // Otherwise every namespace ticks the counter once on the operator's first restart,
        // burying the signal this metric exists for.
        let metrics = metrics();
        let ns = NamespaceName::new("user-alice");
        metrics.variable_value_seen(&ns, &name("PROJECT"), "apollo");
        metrics.variable_value_seen(&ns, &name("PROJECT"), "apollo");
        assert_eq!(
            metrics
                .variable_changed_total
                .with_label_values(&["PROJECT"])
                .get(),
            0
        );
    }

    #[test]
    fn a_changed_bound_annotation_is_counted() {
        let metrics = metrics();
        let ns = NamespaceName::new("user-alice");
        metrics.variable_value_seen(&ns, &name("PROJECT"), "apollo");
        metrics.variable_value_seen(&ns, &name("PROJECT"), "gemini");
        assert_eq!(
            metrics
                .variable_changed_total
                .with_label_values(&["PROJECT"])
                .get(),
            1
        );
    }

    #[test]
    fn two_namespaces_do_not_look_like_one_namespace_changing() {
        let metrics = metrics();
        metrics.variable_value_seen(
            &NamespaceName::new("user-alice"),
            &name("PROJECT"),
            "apollo",
        );
        metrics.variable_value_seen(&NamespaceName::new("user-bob"), &name("PROJECT"), "gemini");
        assert_eq!(
            metrics
                .variable_changed_total
                .with_label_values(&["PROJECT"])
                .get(),
            0
        );
    }

    /// The contract RFC 0005 states as a rule: "No metric carries an image reference as a
    /// label", and its sibling for a variable's value. A textual check, because "this string
    /// never reaches that call" is not something the type system can be asked — and the failure
    /// it guards against is a metrics backend taken down by a hardening component on purpose.
    #[test]
    fn no_metric_label_is_built_from_an_image_reference_or_a_variable_value() {
        let source = include_str!("image_metrics.rs");
        let body = source.split("mod tests").next().unwrap_or_default();
        for forbidden in [
            "verdict.reference",
            "with_label_values(&[value",
            "with_label_values(&[&value",
            "with_label_values(&[verdict.reference",
        ] {
            assert!(
                !body.contains(forbidden),
                "an image reference or a variable value must never become a metric label \
                 (found {forbidden:?})"
            );
        }
    }
}
