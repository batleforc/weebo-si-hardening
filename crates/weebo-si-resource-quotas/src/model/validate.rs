//! RFC 0014's *Validation of a profile*: a profile that would make pod creation fail is refused
//! before it reaches a namespace.
//!
//! **What "has a default" means is upstream's LimitRanger, not the letter of the RFC table.** A
//! container with no request gets the `LimitRange`'s `defaultRequest`; with none set, the
//! `default`; with none set, the `max`. A container with no limit gets `default`, or else `max`.
//! So a compute quota on `requests.cpu` is safe when the `Container` item sets any of
//! `defaultRequest.cpu`, `default.cpu` or `max.cpu`, and one on `limits.cpu` when it sets
//! `default.cpu` or `max.cpu`.

use std::fmt;

use weebo_si_crd::{NamespaceName, QuotaProfile, QuotaProfileKey, TemplateRef};

use crate::model::quantity::Quantity;
use crate::model::template::{LimitItem, LimitRangeTemplate, QuotaTemplate};

/// Which of a profile's two templates a violation is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateKind {
    /// The `ResourceQuota`.
    ResourceQuota,
    /// The `LimitRange`.
    LimitRange,
}

impl fmt::Display for TemplateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ResourceQuota => "ResourceQuota",
            Self::LimitRange => "LimitRange",
        })
    }
}

/// One way a profile would break the namespaces it reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileViolation {
    /// A ref is outside the template namespace. A template is a live object, enforced where it
    /// lives, so templates live in a namespace that runs no pods (RFC 0014's *Where templates
    /// live*).
    OutsideTemplateNamespace {
        /// Which template.
        kind: TemplateKind,
        /// The ref.
        template: TemplateRef,
    },
    /// A ref names no object of that kind.
    TemplateNotFound {
        /// Which template.
        kind: TemplateKind,
        /// The ref.
        template: TemplateRef,
    },
    /// The quota constrains a compute resource every pod must then state, and the `LimitRange`
    /// gives a container that states nothing no value for it: every such pod is refused.
    NoContainerDefault {
        /// The quota key: `requests.cpu`, `limits.memory`, ...
        constrained: String,
    },
    /// A `LimitRange` item's `defaultRequest` is above its `default`, or either is above `max`.
    DefaultsOutOfOrder {
        /// The item's `type`.
        item: String,
        /// The resource.
        resource: String,
    },
    /// A quantity does not parse.
    InvalidQuantity {
        /// Where it is.
        field: String,
        /// The value.
        value: String,
    },
    /// The quota has `scopes` or `scopeSelector`: it counts only part of the pods, which is not
    /// the ceiling RFC 0014 promises.
    ScopedQuota,
}

impl fmt::Display for ProfileViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutsideTemplateNamespace { kind, template } => write!(
                f,
                "{kind} {}/{} is outside the template namespace",
                template.namespace, template.name
            ),
            Self::TemplateNotFound { kind, template } => write!(
                f,
                "{kind} {}/{} does not exist",
                template.namespace, template.name
            ),
            Self::NoContainerDefault { constrained } => write!(
                f,
                "the quota constrains {constrained} but the LimitRange gives a container that \
                 sets none no value for it: every such pod would be refused"
            ),
            Self::DefaultsOutOfOrder { item, resource } => write!(
                f,
                "LimitRange {item} item: defaultRequest, default and max for {resource} are not \
                 in increasing order"
            ),
            Self::InvalidQuantity { field, value } => {
                write!(f, "{field}: {value:?} is not a resource quantity")
            }
            Self::ScopedQuota => f.write_str(
                "the quota is scoped (scopes or scopeSelector) and would count only part of the \
                 pods",
            ),
        }
    }
}

/// The compute resource a quota key constrains, and whether it is a request or a limit. Bare
/// `cpu` and `memory` are requests, as upstream reads them.
fn compute(constrained: &str) -> Option<(&'static str, bool)> {
    match constrained {
        "requests.cpu" | "cpu" => Some(("cpu", true)),
        "requests.memory" | "memory" => Some(("memory", true)),
        "limits.cpu" => Some(("cpu", false)),
        "limits.memory" => Some(("memory", false)),
        _ => None,
    }
}

/// Whether a container that states nothing gets a value for `resource` from `item`.
fn defaulted(item: &LimitItem, resource: &str, request: bool) -> bool {
    item.default.contains_key(resource)
        || item.max.contains_key(resource)
        || (request && item.default_request.contains_key(resource))
}

/// Check one profile against its templates. `quota` and `limits` are what the template store
/// returned for the profile's refs, `None` when a ref is absent or does not resolve.
pub fn validate(
    profile: &QuotaProfile,
    quota: Option<&QuotaTemplate>,
    limits: Option<&LimitRangeTemplate>,
    template_namespace: &NamespaceName,
) -> Vec<ProfileViolation> {
    let mut violations = Vec::new();
    for (kind, template, found) in [
        (
            TemplateKind::ResourceQuota,
            profile.quota_ref.as_ref(),
            quota.is_some(),
        ),
        (
            TemplateKind::LimitRange,
            profile.limit_range_ref.as_ref(),
            limits.is_some(),
        ),
    ] {
        let Some(template) = template else { continue };
        if &template.namespace != template_namespace {
            violations.push(ProfileViolation::OutsideTemplateNamespace {
                kind,
                template: template.clone(),
            });
        } else if !found {
            violations.push(ProfileViolation::TemplateNotFound {
                kind,
                template: template.clone(),
            });
        }
    }

    let items = limits.map(LimitRangeTemplate::items).unwrap_or_default();

    if let Some(quota) = quota {
        if quota.is_scoped() {
            violations.push(ProfileViolation::ScopedQuota);
        }
        for (constrained, value) in quota.hard() {
            if Quantity::parse(&value).is_err() && !constrained.starts_with("count/") {
                violations.push(ProfileViolation::InvalidQuantity {
                    field: format!("hard.{constrained}"),
                    value,
                });
            }
            if let Some((resource, request)) = compute(&constrained) {
                let covered = items
                    .iter()
                    .filter(|item| item.kind == "Container")
                    .any(|item| defaulted(item, resource, request));
                if !covered {
                    violations.push(ProfileViolation::NoContainerDefault { constrained });
                }
            }
        }
    }

    for item in &items {
        let resources: std::collections::BTreeSet<&String> = item
            .default
            .keys()
            .chain(item.default_request.keys())
            .chain(item.max.keys())
            .collect();
        for resource in resources {
            let mut parsed = |field: &str, map: &std::collections::BTreeMap<String, String>| {
                let value = map.get(resource)?;
                match Quantity::parse(value) {
                    Ok(quantity) => Some(quantity),
                    Err(_) => {
                        violations.push(ProfileViolation::InvalidQuantity {
                            field: format!("limits[{}].{field}.{resource}", item.kind),
                            value: value.clone(),
                        });
                        None
                    }
                }
            };
            let request = parsed("defaultRequest", &item.default_request);
            let limit = parsed("default", &item.default);
            let max = parsed("max", &item.max);
            let ordered = [request, limit, max]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .windows(2)
                .all(|pair| pair[0] <= pair[1]);
            if !ordered {
                violations.push(ProfileViolation::DefaultsOutOfOrder {
                    item: item.kind.clone(),
                    resource: resource.clone(),
                });
            }
        }
    }

    violations
}

/// A profile whose validation came back empty. The only way to get a value of this type, so the
/// feature cannot write a profile nobody checked.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidProfile {
    /// The profile's key.
    pub key: QuotaProfileKey,
    /// The quota template, if the profile has one.
    pub quota: Option<QuotaTemplate>,
    /// The `LimitRange` template, if the profile has one.
    pub limits: Option<LimitRangeTemplate>,
}

impl ValidProfile {
    /// Validate, and keep the templates only when nothing is wrong.
    pub fn check(
        profile: &QuotaProfile,
        quota: Option<QuotaTemplate>,
        limits: Option<LimitRangeTemplate>,
        template_namespace: &NamespaceName,
    ) -> Result<Self, Vec<ProfileViolation>> {
        let violations = validate(profile, quota.as_ref(), limits.as_ref(), template_namespace);
        if violations.is_empty() {
            Ok(Self {
                key: profile.key.clone(),
                quota,
                limits,
            })
        } else {
            Err(violations)
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

    fn namespace() -> NamespaceName {
        NamespaceName::new("weebo-si-hardening-templates")
    }

    fn reference(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: namespace(),
        }
    }

    fn profile() -> QuotaProfile {
        QuotaProfile {
            key: QuotaProfileKey::new("standard"),
            quota_ref: Some(reference("quota-standard")),
            limit_range_ref: Some(reference("limits-standard")),
        }
    }

    fn quota(hard: serde_json::Value) -> QuotaTemplate {
        QuotaTemplate {
            spec: serde_json::json!({ "hard": hard }),
        }
    }

    fn limits(container: serde_json::Value) -> LimitRangeTemplate {
        let mut item = container;
        item["type"] = serde_json::json!("Container");
        LimitRangeTemplate {
            spec: serde_json::json!({ "limits": [item] }),
        }
    }

    /// The RFC's own example profile.
    fn standard() -> (QuotaTemplate, LimitRangeTemplate) {
        (
            quota(serde_json::json!({
                "requests.cpu": "4", "requests.memory": "8Gi",
                "limits.cpu": "8", "limits.memory": "12Gi",
                "requests.storage": "50Gi", "persistentvolumeclaims": "10", "pods": "20",
                "services.nodeports": "0", "services.loadbalancers": "0",
                "count/devworkspaces.workspace.devfile.io": "10",
            })),
            limits(serde_json::json!({
                "defaultRequest": {"cpu": "100m", "memory": "256Mi"},
                "default": {"cpu": "1", "memory": "1Gi"},
                "max": {"cpu": "4", "memory": "8Gi"},
            })),
        )
    }

    fn check(
        quota: Option<&QuotaTemplate>,
        limits: Option<&LimitRangeTemplate>,
    ) -> Vec<ProfileViolation> {
        validate(&profile(), quota, limits, &namespace())
    }

    #[test]
    fn the_rfcs_example_profile_is_valid() {
        let (quota, limits) = standard();
        assert_eq!(check(Some(&quota), Some(&limits)), vec![]);
    }

    #[test]
    fn a_missing_template_is_reported_by_kind() {
        let (quota, _) = standard();
        assert!(
            check(Some(&quota), None).contains(&ProfileViolation::TemplateNotFound {
                kind: TemplateKind::LimitRange,
                template: reference("limits-standard"),
            })
        );
    }

    #[test]
    fn a_template_outside_the_template_namespace_is_refused() {
        let (quota, limits) = standard();
        let mut profile = profile();
        profile.quota_ref = Some(TemplateRef {
            name: "quota-standard".to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        });
        let violations = validate(&profile, Some(&quota), Some(&limits), &namespace());
        assert!(matches!(
            violations.as_slice(),
            [ProfileViolation::OutsideTemplateNamespace {
                kind: TemplateKind::ResourceQuota,
                ..
            }]
        ));
    }

    #[test]
    fn a_compute_quota_without_a_container_default_is_an_outage_and_refused() {
        // The RFC's own warning: limits.memory constrained, no default memory limit.
        let quota = quota(serde_json::json!({"limits.memory": "12Gi"}));
        let limits = limits(serde_json::json!({"defaultRequest": {"memory": "256Mi"}}));
        assert_eq!(
            check(Some(&quota), Some(&limits)),
            vec![ProfileViolation::NoContainerDefault {
                constrained: "limits.memory".to_string()
            }]
        );
    }

    #[test]
    fn a_compute_quota_without_any_limit_range_is_refused() {
        let quota = quota(serde_json::json!({"cpu": "4"}));
        let mut profile = profile();
        profile.limit_range_ref = None;
        assert_eq!(
            validate(&profile, Some(&quota), None, &namespace()),
            vec![ProfileViolation::NoContainerDefault {
                constrained: "cpu".to_string()
            }]
        );
    }

    #[test]
    fn upstreams_fallbacks_count_as_defaults() {
        // A request falls back to default then max; a limit falls back to max.
        let quota = quota(serde_json::json!({"requests.cpu": "4", "limits.cpu": "8"}));
        assert_eq!(
            check(
                Some(&quota),
                Some(&limits(serde_json::json!({"max": {"cpu": "4"}})))
            ),
            vec![]
        );
        let only_request = limits(serde_json::json!({"defaultRequest": {"cpu": "100m"}}));
        assert_eq!(
            check(Some(&quota), Some(&only_request)),
            vec![ProfileViolation::NoContainerDefault {
                constrained: "limits.cpu".to_string()
            }]
        );
    }

    #[test]
    fn a_pod_item_does_not_default_a_container() {
        let quota = quota(serde_json::json!({"requests.memory": "8Gi"}));
        let pod_only = LimitRangeTemplate {
            spec: serde_json::json!({"limits": [{"type": "Pod", "max": {"memory": "8Gi"}}]}),
        };
        assert_eq!(check(Some(&quota), Some(&pod_only)).len(), 1);
    }

    #[test]
    fn object_count_quotas_need_no_defaults() {
        // The RFC's cautious first profile: counts and service types only.
        let quota = quota(serde_json::json!({
            "pods": "20", "services.nodeports": "0", "persistentvolumeclaims": "10",
            "count/devworkspaces.workspace.devfile.io": "10",
        }));
        let mut profile = profile();
        profile.limit_range_ref = None;
        assert_eq!(validate(&profile, Some(&quota), None, &namespace()), vec![]);
    }

    #[test]
    fn defaults_out_of_order_are_refused() {
        let (quota, _) = standard();
        let limits = limits(serde_json::json!({
            "defaultRequest": {"cpu": "2"}, "default": {"cpu": "1"}, "max": {"cpu": "4"},
        }));
        assert!(check(Some(&quota), Some(&limits)).contains(
            &ProfileViolation::DefaultsOutOfOrder {
                item: "Container".to_string(),
                resource: "cpu".to_string(),
            }
        ));
        let above_max = super::tests::limits(serde_json::json!({
            "default": {"memory": "16Gi"}, "max": {"memory": "8Gi"},
        }));
        assert!(!check(None, Some(&above_max)).is_empty());
    }

    #[test]
    fn a_scoped_quota_is_refused() {
        let quota = QuotaTemplate {
            spec: serde_json::json!({"hard": {"pods": "5"}, "scopes": ["BestEffort"]}),
        };
        assert!(check(Some(&quota), None).contains(&ProfileViolation::ScopedQuota));
    }

    #[test]
    fn an_unparseable_quantity_is_refused() {
        let quota = quota(serde_json::json!({"requests.storage": "50GB"}));
        assert!(
            check(Some(&quota), None).contains(&ProfileViolation::InvalidQuantity {
                field: "hard.requests.storage".to_string(),
                value: "50GB".to_string(),
            })
        );
    }

    #[test]
    fn only_a_valid_profile_yields_a_value_to_write() {
        let (quota, limits) = standard();
        assert!(
            ValidProfile::check(&profile(), Some(quota.clone()), Some(limits), &namespace())
                .is_ok()
        );
        assert!(ValidProfile::check(&profile(), Some(quota), None, &namespace()).is_err());
    }
}
