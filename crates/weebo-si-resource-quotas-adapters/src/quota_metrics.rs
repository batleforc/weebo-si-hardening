//! RFC 0014's *Observability contract*. No metric carries a namespace: the gauges are recomputed
//! from a picture held in this process, one entry per reconciled namespace.

use std::collections::HashMap;
use std::sync::RwLock;

use prometheus::{IntCounter, IntCounterVec, IntGaugeVec, Opts, Registry};
use weebo_si_chassis::managed::Applied;
use weebo_si_crd::NamespaceName;
use weebo_si_resource_quotas::{
    NamespaceState, ReconcileObserver, ReconcileOutcome, ReconcileResult, SaturationBand,
};

/// The `profile` label of a namespace with no profile resolved.
const NO_PROFILE: &str = "_none";

#[derive(Default)]
struct Picture {
    namespaces: HashMap<NamespaceName, (String, NamespaceState, Option<SaturationBand>)>,
    selections: HashMap<NamespaceName, Option<String>>,
}

/// The five metrics.
pub struct ResourceQuotasMetrics {
    namespaces: IntGaugeVec,
    saturation: IntGaugeVec,
    reconcile_total: IntCounterVec,
    profiles: IntGaugeVec,
    selection_changed_total: IntCounter,
    picture: RwLock<Picture>,
}

impl ResourceQuotasMetrics {
    /// Register every metric against `registry`, label values known in advance at zero.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let namespaces = IntGaugeVec::new(
            Opts::new(
                "weebo_si_resource_quotas_namespaces",
                "Namespaces this feature reconciles, by profile and state",
            ),
            &["profile", "state"],
        )?;
        let saturation = IntGaugeVec::new(
            Opts::new(
                "weebo_si_resource_quotas_saturation",
                "Namespaces by their most-used quota resource; at_limit refuses its next pod",
            ),
            &["band"],
        )?;
        let reconcile_total = IntCounterVec::new(
            Opts::new(
                "weebo_si_resource_quotas_reconcile_total",
                "resource-quotas reconcile outcomes, by result",
            ),
            &["result"],
        )?;
        let profiles = IntGaugeVec::new(
            Opts::new(
                "weebo_si_resource_quotas_profiles",
                "Quota profiles in the catalogue, by whether they are safe to apply",
            ),
            &["state"],
        )?;
        let selection_changed_total = IntCounter::new(
            "weebo_si_resource_quotas_selection_changed_total",
            "Changes to a namespace's quota profile annotation",
        )?;
        registry.register(Box::new(namespaces.clone()))?;
        registry.register(Box::new(saturation.clone()))?;
        registry.register(Box::new(reconcile_total.clone()))?;
        registry.register(Box::new(profiles.clone()))?;
        registry.register(Box::new(selection_changed_total.clone()))?;
        for result in ReconcileResult::ALL {
            reconcile_total.with_label_values(&[result.as_str()]);
        }
        for band in SaturationBand::ALL {
            saturation.with_label_values(&[band.as_str()]).set(0);
        }
        for state in ["valid", "invalid"] {
            profiles.with_label_values(&[state]).set(0);
        }
        Ok(Self {
            namespaces,
            saturation,
            reconcile_total,
            profiles,
            selection_changed_total,
            picture: RwLock::new(Picture::default()),
        })
    }

    fn count(&self, result: ReconcileResult) {
        self.reconcile_total
            .with_label_values(&[result.as_str()])
            .inc();
    }

    fn publish(&self) {
        let picture = self
            .picture
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Reset, then recount: a profile renamed or removed must drop out, not keep its last value.
        self.namespaces.reset();
        let mut counts: HashMap<(&str, NamespaceState), i64> = HashMap::new();
        for (profile, state, _) in picture.namespaces.values() {
            *counts.entry((profile.as_str(), *state)).or_default() += 1;
        }
        for ((profile, state), count) in counts {
            self.namespaces
                .with_label_values(&[profile, state.as_str()])
                .set(count);
        }
        for band in SaturationBand::ALL {
            let count = picture
                .namespaces
                .values()
                .filter(|(_, _, found)| *found == Some(band))
                .count();
            self.saturation
                .with_label_values(&[band.as_str()])
                .set(i64::try_from(count).unwrap_or(i64::MAX));
        }
    }
}

impl ReconcileObserver for ResourceQuotasMetrics {
    fn reconciled(&self, outcome: &ReconcileOutcome) {
        for result in &outcome.results {
            self.count(*result);
        }
        let profile = outcome
            .profile
            .as_ref()
            .map_or(NO_PROFILE.to_string(), ToString::to_string);
        self.picture
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .namespaces
            .insert(
                outcome.namespace.clone(),
                (profile, outcome.state, outcome.saturation),
            );
        self.publish();
    }

    fn torn_down(&self, namespace: &NamespaceName, applied: &Applied) {
        for _ in 0..applied.deleted {
            self.count(ReconcileResult::Deleted);
        }
        self.forget(namespace);
    }

    fn failed(&self) {
        self.count(ReconcileResult::Error);
    }

    fn forget(&self, namespace: &NamespaceName) {
        let removed = {
            let mut picture = self
                .picture
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            picture.selections.remove(namespace);
            picture.namespaces.remove(namespace).is_some()
        };
        if removed {
            self.publish();
        }
    }

    fn profiles(&self, valid: usize, invalid: usize) {
        self.profiles
            .with_label_values(&["valid"])
            .set(i64::try_from(valid).unwrap_or(i64::MAX));
        self.profiles
            .with_label_values(&["invalid"])
            .set(i64::try_from(invalid).unwrap_or(i64::MAX));
    }

    fn selection(&self, namespace: &NamespaceName, annotation: Option<&str>) {
        let mut picture = self
            .picture
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = annotation.map(str::to_string);
        // The first value seen is a baseline, not a change: a restart must not count the fleet.
        if let Some(before) = picture.selections.insert(namespace.clone(), now.clone())
            && before != now
        {
            self.selection_changed_total.inc();
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::QuotaProfileKey;
    use weebo_si_resource_quotas::ForeignObjects;

    use super::*;

    fn outcome(ns: &str, profile: &str, band: Option<SaturationBand>) -> ReconcileOutcome {
        ReconcileOutcome {
            namespace: NamespaceName::new(ns),
            team: None,
            profile: Some(QuotaProfileKey::new(profile)),
            diffs: Vec::new(),
            applied: None,
            results: vec![ReconcileResult::Unchanged],
            not_granted: None,
            violations: Vec::new(),
            foreign: ForeignObjects::default(),
            saturation: band,
            state: NamespaceState::Applied,
        }
    }

    #[test]
    fn namespaces_and_saturation_follow_the_picture() {
        let metrics = ResourceQuotasMetrics::register(&Registry::new()).unwrap();
        metrics.reconciled(&outcome("a", "standard", Some(SaturationBand::AtLimit)));
        metrics.reconciled(&outcome("b", "standard", Some(SaturationBand::Under80)));
        metrics.reconciled(&outcome("c", "large", None));
        assert_eq!(
            metrics
                .namespaces
                .with_label_values(&["standard", "applied"])
                .get(),
            2
        );
        assert_eq!(metrics.saturation.with_label_values(&["at_limit"]).get(), 1);
        metrics.forget(&NamespaceName::new("a"));
        assert_eq!(metrics.saturation.with_label_values(&["at_limit"]).get(), 0);
        assert_eq!(
            metrics
                .namespaces
                .with_label_values(&["standard", "applied"])
                .get(),
            1
        );
    }

    #[test]
    fn a_namespace_moving_profile_leaves_the_old_series() {
        let metrics = ResourceQuotasMetrics::register(&Registry::new()).unwrap();
        metrics.reconciled(&outcome("a", "standard", None));
        metrics.reconciled(&outcome("a", "large", None));
        assert_eq!(
            metrics
                .namespaces
                .with_label_values(&["large", "applied"])
                .get(),
            1
        );
        assert_eq!(
            metrics
                .namespaces
                .with_label_values(&["standard", "applied"])
                .get(),
            0
        );
    }

    #[test]
    fn only_a_change_of_the_annotation_counts() {
        let metrics = ResourceQuotasMetrics::register(&Registry::new()).unwrap();
        let ns = NamespaceName::new("a");
        metrics.selection(&ns, Some("large"));
        metrics.selection(&ns, Some("large"));
        assert_eq!(metrics.selection_changed_total.get(), 0);
        metrics.selection(&ns, Some("standard"));
        metrics.selection(&ns, None);
        assert_eq!(metrics.selection_changed_total.get(), 2);
    }

    #[test]
    fn profiles_are_set_not_added() {
        let metrics = ResourceQuotasMetrics::register(&Registry::new()).unwrap();
        metrics.profiles(3, 1);
        metrics.profiles(4, 0);
        assert_eq!(metrics.profiles.with_label_values(&["valid"]).get(), 4);
        assert_eq!(metrics.profiles.with_label_values(&["invalid"]).get(), 0);
    }
}
