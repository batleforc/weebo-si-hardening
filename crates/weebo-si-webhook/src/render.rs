//! Renders `weebo-si-chassis`'s typed [`Mutation`]s into an RFC 6902 JSON Patch. The domain
//! never imports `json-patch`, does not know what a JSON Pointer is, and never has to worry
//! about escaping `/`/`~` in the attribute key — that's what this module, and the crate it
//! reaches for, exist to own.

use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::PointerBuf;
use serde_json::Value;
use weebo_si_chassis::Mutation;

use crate::extract::CONFIG_REF_ATTRIBUTE;

/// Build the JSON Patch for `mutations` against `object`, whose current shape decides whether
/// an intermediate object (`spec.template.attributes`, `metadata.annotations`) already exists —
/// `add`ing a key under a path that does not yet exist is a JSON Patch error, not a no-op.
pub fn render_patch(object: &Value, mutations: &[Mutation]) -> Patch {
    let has_attributes = object.pointer("/spec/template/attributes").is_some();
    let has_annotations = object.pointer("/metadata/annotations").is_some();

    let mut ops = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        match mutation {
            Mutation::SetConfigRef(target) => {
                let value = serde_json::json!({"name": target.name, "namespace": target.namespace.as_str()});
                ops.push(if has_attributes {
                    add(
                        ["spec", "template", "attributes", CONFIG_REF_ATTRIBUTE],
                        value,
                    )
                } else {
                    add(
                        ["spec", "template", "attributes"],
                        serde_json::json!({CONFIG_REF_ATTRIBUTE: value}),
                    )
                });
            }
            Mutation::Annotate { key, value } => {
                ops.push(if has_annotations {
                    add(
                        ["metadata", "annotations", key.as_str()],
                        Value::String(value.clone()),
                    )
                } else {
                    add(
                        ["metadata", "annotations"],
                        serde_json::json!({key.clone(): value.clone()}),
                    )
                });
            }
        }
    }
    Patch(ops)
}

fn add<'t>(tokens: impl IntoIterator<Item = &'t str>, value: Value) -> PatchOperation {
    PatchOperation::Add(AddOperation {
        path: PointerBuf::from_tokens(tokens),
        value,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::{DwocRef, NamespaceName};

    use super::*;

    #[test]
    fn set_config_ref_adds_the_whole_attributes_map_when_absent() {
        let object = serde_json::json!({"spec": {"template": {}}});
        let mutations = vec![Mutation::SetConfigRef(DwocRef {
            name: "baseline-config".to_string(),
            namespace: NamespaceName::new("eclipse-che"),
        })];
        let patch = render_patch(&object, &mutations);
        assert_eq!(patch.0.len(), 1);
        match &patch.0[0] {
            PatchOperation::Add(op) => {
                assert_eq!(op.path.to_string(), "/spec/template/attributes");
            }
            other => panic!("expected an Add operation, got {other:?}"),
        }
    }

    #[test]
    fn set_config_ref_adds_just_the_key_when_attributes_already_exists() {
        let object =
            serde_json::json!({"spec": {"template": {"attributes": {"some.other/key": "value"}}}});
        let mutations = vec![Mutation::SetConfigRef(DwocRef {
            name: "baseline-config".to_string(),
            namespace: NamespaceName::new("eclipse-che"),
        })];
        let patch = render_patch(&object, &mutations);
        match &patch.0[0] {
            PatchOperation::Add(op) => {
                assert_eq!(
                    op.path.to_string(),
                    "/spec/template/attributes/controller.devfile.io~1devworkspace-config"
                );
            }
            other => panic!("expected an Add operation, got {other:?}"),
        }
    }

    #[test]
    fn annotate_adds_the_whole_annotations_map_when_absent() {
        let object = serde_json::json!({"metadata": {}});
        let mutations = vec![Mutation::Annotate {
            key: "hardening.weebo.io/dwoc-pin".to_string(),
            value: "added;team=<none>;key=baseline".to_string(),
        }];
        let patch = render_patch(&object, &mutations);
        match &patch.0[0] {
            PatchOperation::Add(op) => assert_eq!(op.path.to_string(), "/metadata/annotations"),
            other => panic!("expected an Add operation, got {other:?}"),
        }
    }
}
