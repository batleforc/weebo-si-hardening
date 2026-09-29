//! Renders `weebo-si-chassis`'s typed [`Mutation`]s into an RFC 6902 JSON Patch. The domain
//! never imports `json-patch`, does not know what a JSON Pointer is, and never has to worry
//! about escaping `/`/`~` in the attribute key — that's what this module, and the crate it
//! reaches for, exist to own.

use std::collections::BTreeSet;

use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::PointerBuf;
use serde_json::Value;
use weebo_si_chassis::Mutation;

use crate::extract::CONFIG_REF_ATTRIBUTE;

/// Build the JSON Patch for `mutations` against `object`, whose current shape decides whether
/// an intermediate object (`spec.template.attributes`, `metadata.annotations`) already exists —
/// `add`ing a key under a path that does not yet exist is a JSON Patch error, not a no-op.
///
/// **"Already exists" means *by the time this operation runs*, not "in the submitted object".**
/// The patch is applied in order, so an operation that creates a missing map makes it present for
/// every operation after it — and an implementation that keeps asking the *original* object emits
/// a whole-map `add` per key, each one replacing the map the previous one built. Two annotations
/// onto an object carrying none would leave one. That is why the three flags below are mutable
/// and why `created` exists.
pub fn render_patch(object: &Value, mutations: &[Mutation]) -> Patch {
    // "Exists" means "exists and is not `null`": a key present with `null` (which a client may
    // send) cannot take a child, so it is replaced with a map exactly like an absent one — `add`
    // over an existing key replaces it.
    let mut has_attributes = is_map(object, "/spec/template/attributes");
    let mut has_annotations = is_map(object, "/metadata/annotations");
    // Parents this patch has already created, so two `SetString`s under one missing parent do not
    // each reset it — the same failure as the annotations one, in the shape the `Route` dialect
    // reaches for when it writes `spec.port.targetPort`.
    let mut created: BTreeSet<String> = BTreeSet::new();

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
                    has_attributes = true;
                    add(
                        ["spec", "template", "attributes"],
                        serde_json::json!({CONFIG_REF_ATTRIBUTE: value}),
                    )
                });
            }
            Mutation::SetString { path, value } => {
                // Every parent on the way down has to exist, or `add` is an error rather than a
                // no-op — the same rule the two branches above follow, generalised. A `Route`
                // always has `spec.to`; it does not always have `spec.port`.
                for depth in 1..path.len() {
                    let parent = &path[..depth];
                    let pointer = PointerBuf::from_tokens(parent.iter().map(String::as_str));
                    let path = pointer.to_string();
                    if !is_map(object, pointer.as_str()) && created.insert(path) {
                        ops.push(add(
                            parent.iter().map(String::as_str),
                            Value::Object(serde_json::Map::new()),
                        ));
                    }
                }
                ops.push(add(
                    path.iter().map(String::as_str),
                    Value::String(value.clone()),
                ));
            }
            Mutation::Annotate { key, value } => {
                ops.push(if has_annotations {
                    add(
                        ["metadata", "annotations", key.as_str()],
                        Value::String(value.clone()),
                    )
                } else {
                    // The map is created here, and every annotation after this one adds a key to
                    // it rather than building a second map over the top.
                    has_annotations = true;
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

/// Whether `pointer` names something other than nothing inside `object` — absent and `null` both
/// count as nothing. Anything else is left as it is, so a patch against a malformed object fails
/// at the apiserver rather than silently replacing a value with a map.
fn is_map(object: &Value, pointer: &str) -> bool {
    object
        .pointer(pointer)
        .is_some_and(|value| !value.is_null())
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
    clippy::expect_used,
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

    /// The bug RFC 0009's OpenShift envtest tier found on its first run, and the reason that
    /// tier is worth having: the patch is applied **in order**, so the operation that creates a
    /// missing `metadata.annotations` makes it present for every operation after it. Asking the
    /// *original* object each time emits a whole-map `add` per annotation, and each one replaces
    /// the map the last one built — so an object carrying no annotations at all came back with
    /// exactly one of them, the alphabetically last.
    ///
    /// What that cost in practice: the `hardening.weebo.io/endpoint-auth: managed` marker was the
    /// one dropped on both the Traefik and the OpenShiftRoute dialect, which is the marker the
    /// guard computes what-should-be-here from and the reconciler finds its own objects by. An
    /// endpoint the developer wrote with no annotations — which RFC 0009 explicitly supports —
    /// ended up gated but unmarked.
    #[test]
    fn two_annotations_onto_an_object_carrying_none_both_survive() {
        let object = serde_json::json!({"metadata": {"name": "api"}, "spec": {}});
        let mutations = vec![
            Mutation::Annotate {
                key: "hardening.weebo.io/endpoint-auth".into(),
                value: "managed".into(),
            },
            Mutation::Annotate {
                key: "traefik.ingress.kubernetes.io/router.middlewares".into(),
                value: "weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd".into(),
            },
        ];
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &render_patch(&object, &mutations).0)
            .expect("the patch must apply");
        let annotations = patched
            .pointer("/metadata/annotations")
            .and_then(Value::as_object)
            .expect("annotations should exist");
        assert_eq!(annotations.len(), 2, "{annotations:?}");
        assert_eq!(
            annotations["hardening.weebo.io/endpoint-auth"],
            Value::String("managed".into())
        );
        assert!(annotations.contains_key("traefik.ingress.kubernetes.io/router.middlewares"));
    }

    /// A parent present as `null` is as good as absent: `add` under it would fail, so it is
    /// replaced with a map — for annotations, attributes and a `SetString` parent alike.
    #[test]
    fn a_null_parent_is_replaced_rather_than_written_under() {
        let object = serde_json::json!({
            "metadata": {"name": "api", "annotations": null},
            "spec": {"port": null, "template": {"attributes": null}},
        });
        let mutations = vec![
            Mutation::Annotate {
                key: "hardening.weebo.io/endpoint-auth".into(),
                value: "managed".into(),
            },
            Mutation::SetString {
                path: vec!["spec".into(), "port".into(), "targetPort".into()],
                value: "http".into(),
            },
            Mutation::SetConfigRef(weebo_si_crd::DwocRef {
                name: "gpu".into(),
                namespace: weebo_si_crd::NamespaceName::new("che"),
            }),
        ];
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &render_patch(&object, &mutations).0)
            .expect("the patch must apply");
        assert_eq!(
            patched.pointer("/metadata/annotations/hardening.weebo.io~1endpoint-auth"),
            Some(&Value::String("managed".into()))
        );
        assert_eq!(
            patched.pointer("/spec/port/targetPort"),
            Some(&Value::String("http".into()))
        );
        assert!(
            patched
                .pointer("/spec/template/attributes")
                .is_some_and(Value::is_object)
        );
    }

    /// The same failure in the shape `SetString` can reach: two writes under one missing parent.
    #[test]
    fn two_values_under_one_missing_parent_both_survive() {
        let object = serde_json::json!({"spec": {}});
        let mutations = vec![
            Mutation::SetString {
                path: vec!["spec".into(), "port".into(), "targetPort".into()],
                value: "http".into(),
            },
            Mutation::SetString {
                path: vec!["spec".into(), "port".into(), "name".into()],
                value: "web".into(),
            },
        ];
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &render_patch(&object, &mutations).0)
            .expect("the patch must apply");
        assert_eq!(
            patched.pointer("/spec/port/targetPort"),
            Some(&Value::String("http".into()))
        );
        assert_eq!(
            patched.pointer("/spec/port/name"),
            Some(&Value::String("web".into()))
        );
    }

    #[test]
    fn set_string_creates_the_parents_a_route_does_not_already_have() {
        // Attaching the gate on OpenShift writes `spec.to.name` — which exists — and
        // `spec.port.targetPort`, which on a Route without an explicit port does not.
        let object = serde_json::json!({"spec": {"to": {"kind": "Service", "name": "my-app"}}});
        let mutations = vec![
            Mutation::SetString {
                path: vec!["spec".into(), "to".into(), "name".into()],
                value: "weebo-si-endpoint-gateway".into(),
            },
            Mutation::SetString {
                path: vec!["spec".into(), "port".into(), "targetPort".into()],
                value: "http".into(),
            },
        ];
        let patch = render_patch(&object, &mutations);
        let paths: Vec<String> = patch
            .0
            .iter()
            .map(|op| match op {
                PatchOperation::Add(op) => op.path.to_string(),
                other => panic!("expected an Add operation, got {other:?}"),
            })
            .collect();
        assert_eq!(
            paths,
            vec!["/spec/to/name", "/spec/port", "/spec/port/targetPort"]
        );
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
