//! What a namespace uses today, against a profile's `hard` limits — the arithmetic behind `quotas
//! audit`. RFC 0014's *CLI*: the CLI runs the admission-time rule itself, "one comparison per
//! resource, documented upstream", and only advises.

use std::collections::BTreeMap;

use crate::model::quantity::Quantity;

/// One pod's requests and limits, per container, as raw quantities.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodResources {
    /// `spec.containers[].resources`: `(requests, limits)`.
    pub containers: Vec<(BTreeMap<String, String>, BTreeMap<String, String>)>,
    /// `spec.initContainers[].resources`: `(requests, limits)`.
    pub init_containers: Vec<(BTreeMap<String, String>, BTreeMap<String, String>)>,
}

/// One resource a namespace is already above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Over {
    /// The quota key.
    pub resource: String,
    /// What is used.
    pub used: Quantity,
    /// The limit.
    pub hard: Quantity,
}

fn parse_or_zero(value: Option<&String>) -> Quantity {
    value
        .and_then(|value| Quantity::parse(value).ok())
        .unwrap_or(Quantity::ZERO)
}

impl PodResources {
    /// The pod's effective value for `resource` in `requests` (`true`) or `limits`: the sum over
    /// its containers, or the largest init container if that is higher — the rule the quota
    /// admission plugin applies.
    pub fn effective(&self, resource: &str, requests: bool) -> Quantity {
        let pick = |pair: &(BTreeMap<String, String>, BTreeMap<String, String>)| {
            parse_or_zero(if requests {
                pair.0.get(resource)
            } else {
                pair.1.get(resource)
            })
        };
        let sum: i128 = self.containers.iter().map(|pair| pick(pair).nanos()).sum();
        let init = self
            .init_containers
            .iter()
            .map(|pair| pick(pair).nanos())
            .max()
            .unwrap_or(0);
        Quantity::from_nanos(sum.max(init))
    }
}

/// The compute quota keys and how to read them off pods. Bare `cpu`/`memory` are requests.
fn compute(resource: &str) -> Option<(&str, bool)> {
    match resource {
        "requests.cpu" | "cpu" => Some(("cpu", true)),
        "requests.memory" | "memory" => Some(("memory", true)),
        "requests.ephemeral-storage" | "ephemeral-storage" => Some(("ephemeral-storage", true)),
        "limits.cpu" => Some(("cpu", false)),
        "limits.memory" => Some(("memory", false)),
        "limits.ephemeral-storage" => Some(("ephemeral-storage", false)),
        _ => None,
    }
}

/// The compute usage of `pods` for every compute key in `hard`, merged with `counted` — object
/// counts and storage the caller measured itself — and compared with `hard`. Keys neither side can
/// measure are left out rather than guessed.
pub fn over(
    hard: &BTreeMap<String, String>,
    pods: &[PodResources],
    counted: &BTreeMap<String, Quantity>,
) -> Vec<Over> {
    hard.iter()
        .filter_map(|(resource, limit)| {
            let hard = Quantity::parse(limit).ok()?;
            let used = match compute(resource) {
                Some((name, requests)) => Quantity::from_nanos(
                    pods.iter()
                        .map(|pod| pod.effective(name, requests).nanos())
                        .sum(),
                ),
                None => *counted.get(resource)?,
            };
            (used > hard).then(|| Over {
                resource: resource.clone(),
                used,
                hard,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn pod(requests: &[(&str, &str)], limits: &[(&str, &str)]) -> PodResources {
        PodResources {
            containers: vec![(map(requests), map(limits))],
            init_containers: Vec::new(),
        }
    }

    #[test]
    fn the_rfcs_example_bob_is_over_memory_and_pods() {
        let hard = map(&[
            ("requests.memory", "8Gi"),
            ("pods", "20"),
            ("requests.cpu", "4"),
        ]);
        let pods: Vec<PodResources> = (0..5)
            .map(|_| pod(&[("memory", "1946Mi"), ("cpu", "500m")], &[]))
            .collect();
        let counted = BTreeMap::from([("pods".to_string(), Quantity::parse("23").unwrap())]);
        let over = over(&hard, &pods, &counted);
        let resources: Vec<&str> = over.iter().map(|over| over.resource.as_str()).collect();
        assert_eq!(resources, vec!["pods", "requests.memory"]);
    }

    #[test]
    fn an_init_container_counts_when_it_is_the_larger() {
        let pod = PodResources {
            containers: vec![
                (map(&[("cpu", "100m")]), map(&[])),
                (map(&[("cpu", "100m")]), map(&[])),
            ],
            init_containers: vec![(map(&[("cpu", "1")]), map(&[]))],
        };
        assert_eq!(pod.effective("cpu", true), Quantity::parse("1").unwrap());
        assert_eq!(pod.effective("cpu", false), Quantity::parse("0").unwrap());
    }

    #[test]
    fn unmeasured_keys_are_left_out() {
        let hard = map(&[("count/devworkspaces.workspace.devfile.io", "0")]);
        assert!(over(&hard, &[], &BTreeMap::new()).is_empty());
    }

    #[test]
    fn within_limits_is_nothing() {
        let hard = map(&[("limits.cpu", "8")]);
        let pods = vec![pod(&[], &[("cpu", "2")]), pod(&[], &[("cpu", "6")])];
        assert!(over(&hard, &pods, &BTreeMap::new()).is_empty());
    }
}
