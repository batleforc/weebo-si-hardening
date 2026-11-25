//! The audit of restricted catalogue keys (RFC 0021): the counter both features share, and the
//! change-only memory that makes the counter, the Event and the log line fire when an object's
//! honoured or refused set changes, not on every pass (R-15).

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use prometheus::{IntCounterVec, Opts, Registry};

/// `weebo_si_restricted_grant_total{feature,key,result}`, registered once by the composition
/// root and handed to each feature's adapters. Never a namespace, user or workspace label: `key`
/// is bounded by the catalogue, `feature` and `result` by this code.
#[derive(Clone)]
pub struct RestrictedGrantCounter(IntCounterVec);

impl RestrictedGrantCounter {
    /// Register the counter against `registry`.
    pub fn register(registry: &Registry) -> Result<Self, prometheus::Error> {
        let counter = IntCounterVec::new(
            Opts::new(
                "weebo_si_restricted_grant_total",
                "Restricted catalogue keys an object started to use (honoured) or was refused, \
                 by feature, key and result",
            ),
            &["feature", "key", "result"],
        )?;
        registry.register(Box::new(counter.clone()))?;
        Ok(Self(counter))
    }
}

/// What changed for one object since its last pass: the keys that entered its honoured set and
/// those that entered its refused set. Each was counted once already.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestrictedChange {
    /// Keys honoured now and not at the last pass.
    pub honoured: Vec<String>,
    /// Keys refused now and not at the last pass.
    pub refused: Vec<String>,
}

#[derive(Default, PartialEq, Eq)]
struct Sets {
    honoured: BTreeSet<String>,
    refused: BTreeSet<String>,
}

/// One feature's memory of each object's last restricted sets, keyed by object UID. In memory
/// only: after a restart each object meeting a restricted key reports once more. Objects with
/// both sets empty are not kept, so the map holds only objects that use a restricted key.
pub struct RestrictedReporter {
    counter: RestrictedGrantCounter,
    feature: &'static str,
    last: Mutex<HashMap<String, Sets>>,
}

impl RestrictedReporter {
    /// A reporter for `feature` (`network-profiles` or `endpoint-auth`).
    pub fn new(counter: RestrictedGrantCounter, feature: &'static str) -> Self {
        Self {
            counter,
            feature,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// Record `uid`'s sets for this pass, count every key that entered either set, and return
    /// them for the caller's Event and log line.
    pub fn observe(
        &self,
        uid: &str,
        honoured: impl IntoIterator<Item = String>,
        refused: impl IntoIterator<Item = String>,
    ) -> RestrictedChange {
        let now = Sets {
            honoured: honoured.into_iter().collect(),
            refused: refused.into_iter().collect(),
        };
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = last.remove(uid).unwrap_or_default();
        let change = RestrictedChange {
            honoured: now.honoured.difference(&before.honoured).cloned().collect(),
            refused: now.refused.difference(&before.refused).cloned().collect(),
        };
        if now != Sets::default() {
            last.insert(uid.to_string(), now);
        }
        drop(last);
        for (keys, result) in [(&change.honoured, "honoured"), (&change.refused, "refused")] {
            for key in keys {
                self.counter
                    .0
                    .with_label_values(&[self.feature, key.as_str(), result])
                    .inc();
            }
        }
        change
    }

    /// Drop `uid`'s memory: the object is being deleted.
    pub fn forget(&self, uid: &str) {
        self.last
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(uid);
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

    fn keys(list: &[&str]) -> Vec<String> {
        list.iter().map(|key| (*key).to_string()).collect()
    }

    fn reporter() -> (Registry, RestrictedReporter) {
        let registry = Registry::new();
        let counter = RestrictedGrantCounter::register(&registry).unwrap();
        (
            registry,
            RestrictedReporter::new(counter, "network-profiles"),
        )
    }

    fn value(registry: &Registry, key: &str, result: &str) -> u64 {
        registry
            .gather()
            .iter()
            .flat_map(|family| family.get_metric())
            .filter(|metric| {
                let labels: Vec<(&str, &str)> = metric
                    .get_label()
                    .iter()
                    .map(|pair| (pair.name(), pair.value()))
                    .collect();
                labels.contains(&("key", key)) && labels.contains(&("result", result))
            })
            .map(|metric| metric.get_counter().value() as u64)
            .sum()
    }

    #[test]
    fn the_reporter_fires_on_a_change_and_not_on_an_unchanged_second_pass() {
        let (registry, reporter) = reporter();
        let first = reporter.observe("uid-1", keys(&[]), keys(&["internet"]));
        assert_eq!(first.refused, keys(&["internet"]));
        assert_eq!(
            reporter.observe("uid-1", keys(&[]), keys(&["internet"])),
            RestrictedChange::default()
        );
        assert_eq!(value(&registry, "internet", "refused"), 1);

        let granted = reporter.observe("uid-1", keys(&["internet"]), keys(&[]));
        assert_eq!(granted.honoured, keys(&["internet"]));
        assert_eq!(value(&registry, "internet", "honoured"), 1);

        // Revoked then refused again: a change, reported again.
        let again = reporter.observe("uid-1", keys(&[]), keys(&["internet"]));
        assert_eq!(again.refused, keys(&["internet"]));
        assert_eq!(value(&registry, "internet", "refused"), 2);
    }

    #[test]
    fn a_forgotten_object_reports_once_more() {
        let (registry, reporter) = reporter();
        reporter.observe("uid-1", keys(&["internet"]), keys(&[]));
        reporter.forget("uid-1");
        reporter.observe("uid-1", keys(&["internet"]), keys(&[]));
        assert_eq!(value(&registry, "internet", "honoured"), 2);
    }

    #[test]
    fn objects_without_a_restricted_key_are_not_remembered() {
        let (_registry, reporter) = reporter();
        reporter.observe("uid-1", keys(&[]), keys(&[]));
        assert!(reporter.last.lock().unwrap().is_empty());
    }

    /// RFC 0021 S8.
    #[test]
    fn the_restricted_counter_never_carries_a_namespace() {
        let (registry, reporter) = reporter();
        reporter.observe("uid-1", keys(&["internet"]), keys(&[]));
        let family = registry
            .gather()
            .into_iter()
            .find(|family| family.name() == "weebo_si_restricted_grant_total")
            .unwrap();
        for metric in family.get_metric() {
            let names: Vec<&str> = metric.get_label().iter().map(|pair| pair.name()).collect();
            assert_eq!(names, vec!["feature", "key", "result"]);
        }
    }
}
