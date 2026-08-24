//! A `metav1.LabelSelector`, reimplemented as the CRD field's native type.
//!
//! RFC 0002's original design converted `k8s_openapi`'s `LabelSelector` into a hand-rolled
//! domain type at config-load time, specifically to keep the domain layer free of
//! `k8s-openapi`. Now that `weebo-si-crd` is a deliberate, named exception to that rule (see the
//! RFC's amendment), this type can simply *be* the wire type directly — deleting that whole
//! conversion step, at the cost of this crate owning the one place a drift from upstream
//! selector semantics would be caught: [`Selector::matches`]'s test suite below.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A `matchExpressions` operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Operator {
    /// The label's value is one of `values`.
    In,
    /// The label is absent, or its value is not one of `values`.
    NotIn,
    /// The label key is present, whatever its value.
    Exists,
    /// The label key is absent.
    DoesNotExist,
}

/// One `matchExpressions` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Expression {
    /// The label key this expression tests.
    pub key: String,
    /// How `values` is compared against the label's value, if any.
    pub operator: Operator,
    /// The comparison values `operator` reads. Unused by `Exists`/`DoesNotExist`.
    #[serde(default)]
    pub values: Vec<String>,
}

/// `matchLabels` plus `matchExpressions`, ANDed together. The default value — both empty —
/// matches everything, per upstream `LabelSelector` semantics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    /// Every key must be present with exactly this value.
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
    /// Every expression must hold.
    #[serde(default)]
    pub match_expressions: Vec<Expression>,
}

impl Selector {
    /// Whether `labels` satisfies every `match_labels` pair and every `match_expressions` entry.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        let labels_match = self
            .match_labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value));

        labels_match
            && self
                .match_expressions
                .iter()
                .all(|expr| Self::expression_matches(expr, labels))
    }

    fn expression_matches(expr: &Expression, labels: &BTreeMap<String, String>) -> bool {
        match expr.operator {
            Operator::In => labels
                .get(expr.key.as_str())
                .is_some_and(|value| expr.values.iter().any(|v| v == value)),
            Operator::NotIn => !labels
                .get(expr.key.as_str())
                .is_some_and(|value| expr.values.iter().any(|v| v == value)),
            Operator::Exists => labels.contains_key(expr.key.as_str()),
            Operator::DoesNotExist => !labels.contains_key(expr.key.as_str()),
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
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_selector_matches_everything() {
        let selector = Selector::default();
        assert!(selector.matches(&BTreeMap::new()));
        assert!(selector.matches(&labels(&[("weebo.io/team", "team-1")])));
    }

    #[test]
    fn match_labels_requires_every_pair_to_match() {
        let selector = Selector {
            match_labels: labels(&[("weebo.io/team", "team-1"), ("env", "prod")]),
            match_expressions: Vec::new(),
        };
        assert!(selector.matches(&labels(&[("weebo.io/team", "team-1"), ("env", "prod")])));
        assert!(!selector.matches(&labels(&[("weebo.io/team", "team-1")])));
        assert!(!selector.matches(&labels(&[("weebo.io/team", "team-1"), ("env", "dev")])));
    }

    #[test]
    fn a_missing_match_labels_key_fails_the_match() {
        let selector = Selector {
            match_labels: labels(&[("weebo.io/team", "team-1")]),
            match_expressions: Vec::new(),
        };
        assert!(!selector.matches(&BTreeMap::new()));
    }

    #[test]
    fn match_labels_and_match_expressions_are_anded_together() {
        let selector = Selector {
            match_labels: labels(&[("weebo.io/team", "team-1")]),
            match_expressions: vec![Expression {
                key: "env".to_string(),
                operator: Operator::In,
                values: vec!["prod".to_string()],
            }],
        };
        assert!(selector.matches(&labels(&[("weebo.io/team", "team-1"), ("env", "prod")])));
        assert!(!selector.matches(&labels(&[("weebo.io/team", "team-1"), ("env", "dev")])));
        assert!(!selector.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn in_operator_matches_when_the_label_value_is_in_the_list() {
        let expr = Expression {
            key: "env".to_string(),
            operator: Operator::In,
            values: vec!["prod".to_string(), "staging".to_string()],
        };
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![expr],
        };
        assert!(selector.matches(&labels(&[("env", "staging")])));
        assert!(!selector.matches(&labels(&[("env", "dev")])));
    }

    #[test]
    fn in_operator_with_empty_values_matches_nothing() {
        let expr = Expression {
            key: "env".to_string(),
            operator: Operator::In,
            values: Vec::new(),
        };
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![expr],
        };
        assert!(!selector.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn not_in_operator_matches_when_the_key_is_absent_or_the_value_is_not_listed() {
        let expr = Expression {
            key: "env".to_string(),
            operator: Operator::NotIn,
            values: vec!["prod".to_string()],
        };
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![expr],
        };
        assert!(selector.matches(&BTreeMap::new()));
        assert!(selector.matches(&labels(&[("env", "dev")])));
        assert!(!selector.matches(&labels(&[("env", "prod")])));
    }

    #[test]
    fn exists_operator_ignores_values_and_checks_key_presence() {
        let expr = Expression {
            key: "weebo.io/pilot".to_string(),
            operator: Operator::Exists,
            values: Vec::new(),
        };
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![expr],
        };
        assert!(selector.matches(&labels(&[("weebo.io/pilot", "anything")])));
        assert!(!selector.matches(&BTreeMap::new()));
    }

    #[test]
    fn does_not_exist_operator_matches_when_the_key_is_absent() {
        let expr = Expression {
            key: "weebo.io/pilot".to_string(),
            operator: Operator::DoesNotExist,
            values: Vec::new(),
        };
        let selector = Selector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![expr],
        };
        assert!(selector.matches(&BTreeMap::new()));
        assert!(!selector.matches(&labels(&[("weebo.io/pilot", "anything")])));
    }

    /// Guards against drifting from upstream `LabelSelector` JSON shape: `matchLabels`,
    /// `matchExpressions[].{key,operator,values}`, and the operator spelled exactly as upstream
    /// spells it (`"In"`/`"NotIn"`/`"Exists"`/`"DoesNotExist"`) — this is what replaces the
    /// deleted load-time conversion step's own round-trip test.
    #[test]
    fn wire_shape_matches_upstream_label_selector() {
        let json = serde_json::json!({
            "matchLabels": {"weebo.io/team": "team-1"},
            "matchExpressions": [
                {"key": "env", "operator": "In", "values": ["prod"]}
            ],
        });
        let selector: Selector = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            selector.match_labels.get("weebo.io/team"),
            Some(&"team-1".to_string())
        );
        assert_eq!(selector.match_expressions[0].operator, Operator::In);
        assert_eq!(serde_json::to_value(&selector).unwrap(), json);
    }

    #[test]
    fn an_empty_json_object_deserializes_to_the_matches_everything_default() {
        let selector: Selector = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(selector, Selector::default());
    }
}
