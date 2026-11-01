//! What a `Namespace` object says about this feature: the six keys, the `-previous` annotation, and
//! who owns the keys — read from the object the controller's own watch delivers, so no new watch.

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry;
use weebo_si_pod_security::{FIELD_MANAGER, Found, KEYS, PREVIOUS_ANNOTATION, PodSecurityLabels};

/// Project `ns` into what the domain decides on.
///
/// Ownership comes from `metadata.managedFields`, the apiserver's own record of which field
/// manager last set each field:
///
/// * `owned`: an `Apply` entry of [`FIELD_MANAGER`] lists at least one of the six keys.
/// * `foreign_owned`: an entry of any other manager lists one of the six keys the namespace
///   carries. Before this feature's first write that is just whoever set the label; after it, it
///   is somebody changing a label this feature wrote.
pub fn found(ns: &Namespace) -> Found {
    let labels = ns
        .metadata
        .labels
        .as_ref()
        .map(PodSecurityLabels::from_namespace)
        .unwrap_or_default();
    let previous = ns
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PREVIOUS_ANNOTATION))
        .cloned();
    let entries = ns.metadata.managed_fields.as_deref().unwrap_or_default();
    let owned = entries.iter().any(|entry| {
        entry.manager.as_deref() == Some(FIELD_MANAGER)
            && entry.operation.as_deref() == Some("Apply")
            && owned_keys(entry).next().is_some()
    });
    let foreign_owned = entries.iter().any(|entry| {
        entry.manager.as_deref() != Some(FIELD_MANAGER)
            && owned_keys(entry).any(|key| labels.get(key).is_some())
    });
    Found {
        labels,
        previous,
        owned,
        foreign_owned,
    }
}

/// Which of the six keys `entry` lists under `f:metadata.f:labels`.
fn owned_keys(entry: &ManagedFieldsEntry) -> impl Iterator<Item = &'static str> + '_ {
    let labels = entry
        .fields_v1
        .as_ref()
        .and_then(|fields| fields.0.get("f:metadata"))
        .and_then(|metadata| metadata.get("f:labels"));
    KEYS.into_iter()
        .filter(move |key| labels.is_some_and(|labels| labels.get(format!("f:{key}")).is_some()))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{FieldsV1, ObjectMeta};
    use weebo_si_pod_security::ENFORCE;

    use super::*;

    fn entry(manager: &str, operation: &str, keys: &[&str]) -> ManagedFieldsEntry {
        let labels: serde_json::Map<String, serde_json::Value> = keys
            .iter()
            .map(|key| (format!("f:{key}"), serde_json::json!({})))
            .collect();
        ManagedFieldsEntry {
            manager: Some(manager.to_string()),
            operation: Some(operation.to_string()),
            fields_v1: Some(FieldsV1(serde_json::json!({
                "f:metadata": {"f:labels": labels}
            }))),
            ..ManagedFieldsEntry::default()
        }
    }

    fn namespace(
        labels: &[(&str, &str)],
        previous: Option<&str>,
        entries: Vec<ManagedFieldsEntry>,
    ) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some("user-bob".to_string()),
                labels: Some(
                    labels
                        .iter()
                        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                        .collect(),
                ),
                annotations: previous.map(|value| {
                    BTreeMap::from([(PREVIOUS_ANNOTATION.to_string(), value.to_string())])
                }),
                managed_fields: Some(entries),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        }
    }

    #[test]
    fn a_bare_namespace_is_neither_owned_nor_foreign() {
        let found = found(&Namespace::default());
        assert_eq!(found, Found::default());
    }

    #[test]
    fn keys_applied_by_this_field_manager_are_owned() {
        let ns = namespace(
            &[(ENFORCE, "restricted")],
            Some("{}"),
            vec![entry(FIELD_MANAGER, "Apply", &[ENFORCE])],
        );
        let found = found(&ns);
        assert!(found.owned);
        assert!(!found.foreign_owned);
        assert_eq!(found.previous.as_deref(), Some("{}"));
        assert_eq!(found.labels.get(ENFORCE), Some("restricted"));
    }

    #[test]
    fn a_key_kubectl_set_is_foreign() {
        let ns = namespace(
            &[(ENFORCE, "privileged")],
            Some("{}"),
            vec![
                entry(FIELD_MANAGER, "Apply", &[]),
                entry("kubectl-label", "Update", &[ENFORCE]),
            ],
        );
        let found = found(&ns);
        assert!(!found.owned, "the manager no longer lists any of the keys");
        assert!(found.foreign_owned);
    }

    #[test]
    fn an_update_under_this_managers_name_is_not_an_apply() {
        let ns = namespace(
            &[(ENFORCE, "restricted")],
            None,
            vec![entry(FIELD_MANAGER, "Update", &[ENFORCE])],
        );
        assert!(!found(&ns).owned);
    }

    #[test]
    fn a_foreign_entry_for_a_label_no_longer_present_does_not_count() {
        let ns = namespace(&[], None, vec![entry("someone", "Update", &[ENFORCE])]);
        assert!(!found(&ns).foreign_owned);
    }

    #[test]
    fn other_labels_in_a_foreign_entry_do_not_count() {
        let ns = namespace(
            &[("weebo.io/team", "team-1")],
            None,
            vec![entry("argocd", "Apply", &["weebo.io/team"])],
        );
        let found = found(&ns);
        assert!(!found.foreign_owned);
        assert!(found.labels.is_empty());
    }
}
