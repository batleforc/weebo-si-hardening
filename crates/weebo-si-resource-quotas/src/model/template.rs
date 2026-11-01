//! A profile's two templates, as domain values: the `spec` to copy, opaque, and the few fields the
//! validation table reads, projected out of it.

use std::collections::BTreeMap;

/// A `ResourceQuota` template.
#[derive(Debug, Clone, PartialEq)]
pub struct QuotaTemplate {
    /// `spec`, copied unchanged into `weebo-quota`.
    pub spec: serde_json::Value,
}

/// A `LimitRange` template.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitRangeTemplate {
    /// `spec`, copied unchanged into `weebo-limits`.
    pub spec: serde_json::Value,
}

/// One `spec.limits[]` item of a `LimitRange`, as raw quantity strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LimitItem {
    /// `type`: `Container`, `Pod` or `PersistentVolumeClaim`.
    pub kind: String,
    /// `default`: the limit a container gets when it sets none.
    pub default: BTreeMap<String, String>,
    /// `defaultRequest`: the request a container gets when it sets none.
    pub default_request: BTreeMap<String, String>,
    /// `max`.
    pub max: BTreeMap<String, String>,
}

fn string_map(value: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    value
        .and_then(serde_json::Value::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| {
                    let value = match value {
                        serde_json::Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (key.clone(), value)
                })
                .collect()
        })
        .unwrap_or_default()
}

impl QuotaTemplate {
    /// `spec.hard`.
    pub fn hard(&self) -> BTreeMap<String, String> {
        string_map(self.spec.get("hard"))
    }

    /// Whether `spec.scopes` or `spec.scopeSelector` is set: a quota counting only part of the
    /// pods.
    pub fn is_scoped(&self) -> bool {
        let non_empty = |key: &str| {
            self.spec.get(key).is_some_and(|value| {
                !value.is_null() && value.as_array().is_none_or(|items| !items.is_empty())
            })
        };
        non_empty("scopes") || non_empty("scopeSelector")
    }
}

impl LimitRangeTemplate {
    /// `spec.limits`.
    pub fn items(&self) -> Vec<LimitItem> {
        self.spec
            .get("limits")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| LimitItem {
                        kind: item
                            .get("type")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        default: string_map(item.get("default")),
                        default_request: string_map(item.get("defaultRequest")),
                        max: string_map(item.get("max")),
                    })
                    .collect()
            })
            .unwrap_or_default()
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
    fn hard_and_scopes_are_read_from_the_spec() {
        let quota = QuotaTemplate {
            spec: serde_json::json!({"hard": {"pods": "20", "requests.cpu": "4"}}),
        };
        assert_eq!(quota.hard()["requests.cpu"], "4");
        assert!(!quota.is_scoped());
        let scoped = QuotaTemplate {
            spec: serde_json::json!({"hard": {}, "scopes": ["BestEffort"]}),
        };
        assert!(scoped.is_scoped());
        let empty_scopes = QuotaTemplate {
            spec: serde_json::json!({"hard": {}, "scopes": []}),
        };
        assert!(!empty_scopes.is_scoped());
    }

    #[test]
    fn limit_items_are_read_from_the_spec() {
        let limits = LimitRangeTemplate {
            spec: serde_json::json!({"limits": [{
                "type": "Container",
                "defaultRequest": {"cpu": "100m", "memory": "256Mi"},
                "default": {"cpu": "1"},
                "max": {"cpu": "4"},
            }]}),
        };
        let items = limits.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, "Container");
        assert_eq!(items[0].default_request["memory"], "256Mi");
        assert_eq!(items[0].default["cpu"], "1");
        assert_eq!(items[0].max["cpu"], "4");
    }
}
