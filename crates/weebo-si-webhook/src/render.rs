//! Renders `weebo-si-chassis`'s typed [`Mutation`]s into an RFC 6902 JSON Patch. The domain
//! never imports `json-patch`, does not know what a JSON Pointer is, and never has to worry
//! about escaping `/`/`~` in the attribute key — that's what this module, and the crate it
//! reaches for, exist to own.

use std::collections::BTreeSet;

use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::PointerBuf;
use kube::core::admission::AdmissionResponse;
use serde_json::Value;
use weebo_si_chassis::Mutation;
use weebo_si_chassis::admit::bound_warnings;

use crate::extract::CONFIG_REF_ATTRIBUTE;

/// Build the JSON Patch for `mutations` against `object`, whose current shape decides whether
/// an intermediate object (`spec.template.attributes`, `metadata.annotations`) already exists —
/// `add`ing a key under a path that does not yet exist is a JSON Patch error, not a no-op.
///
/// **"Already exists" means *by the time this operation runs*, not "in the submitted object".**
/// The patch is applied in order, so an operation that creates a missing map makes it present for
/// every operation after it — and an implementation that keeps asking the *original* object emits
/// a whole-map `add` per key, each one replacing the map the previous one built. Two annotations
/// onto an object carrying none would leave one. That is why every arm checks and records the
/// parents it creates in one `created` set.
pub fn render_patch(object: &Value, mutations: &[Mutation]) -> Patch {
    // "Exists" means "exists and is not `null`": a key present with `null` (which a client may
    // send) cannot take a child, so it is replaced with a map exactly like an absent one — `add`
    // over an existing key replaces it.
    // Parents this patch has already created, shared by every arm, so no later write under the
    // same missing parent (two annotations, an annotation and a scalar, `SetInt` and `SetBool`
    // under one `securityContext`) resets it.
    let mut created: BTreeSet<String> = BTreeSet::new();

    let mut ops = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        match mutation {
            Mutation::SetConfigRef(target) => {
                let value = serde_json::json!({"name": target.name, "namespace": target.namespace.as_str()});
                ops.push(if !creates(object, &mut created, ATTRIBUTES) {
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
            Mutation::SetString { path, value } => {
                set(
                    object,
                    &mut created,
                    &mut ops,
                    path,
                    Value::String(value.clone()),
                );
            }
            Mutation::SetInt { path, value } => {
                set(object, &mut created, &mut ops, path, Value::from(*value));
            }
            Mutation::SetBool { path, value } => {
                set(object, &mut created, &mut ops, path, Value::Bool(*value));
            }
            Mutation::Annotate { key, value } => {
                ops.push(if !creates(object, &mut created, ANNOTATIONS) {
                    add(
                        ["metadata", "annotations", key.as_str()],
                        Value::String(value.clone()),
                    )
                } else {
                    // The map is created here, and every annotation after this one adds a key to
                    // it rather than building a second map over the top.
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

/// Put the merged warnings of every registry a route ran on `response`, bounded once
/// ([`bound_warnings`], RFC 0019 D-14). No warning leaves `warnings` at `None`, so a response
/// without one is byte-identical to what it was before warnings existed.
pub fn with_warnings(mut response: AdmissionResponse, warnings: Vec<String>) -> AdmissionResponse {
    let warnings = bound_warnings(warnings);
    response.warnings = (!warnings.is_empty()).then_some(warnings);
    response
}

/// Add `value` at `path`, creating every missing parent on the way down first — `add` under a
/// missing parent is an error rather than a no-op (a `Route` always has `spec.to`, not always
/// `spec.port`). One `created` set per patch, shared by every scalar arm, so a `SetInt` and a
/// `SetBool` under one missing `spec.securityContext` add it once instead of the second wiping
/// the first (RFC 0018, L26).
fn set(
    object: &Value,
    created: &mut BTreeSet<String>,
    ops: &mut Vec<PatchOperation>,
    path: &[String],
    value: Value,
) {
    // An empty path would be an `add` at the root, replacing the whole object with a scalar.
    if path.is_empty() {
        return;
    }
    for depth in 1..path.len() {
        let parent = path.get(..depth).unwrap_or_default();
        let pointer = PointerBuf::from_tokens(parent.iter().map(String::as_str));
        if creates(object, created, pointer.as_str()) {
            ops.push(add(
                parent.iter().map(String::as_str),
                Value::Object(serde_json::Map::new()),
            ));
        }
    }
    ops.push(add(path.iter().map(String::as_str), value));
}

const ATTRIBUTES: &str = "/spec/template/attributes";
const ANNOTATIONS: &str = "/metadata/annotations";

/// Whether the map at `pointer` is missing, neither in `object` nor already created by this
/// patch — and if so, records that the caller now creates it.
fn creates(object: &Value, created: &mut BTreeSet<String>, pointer: &str) -> bool {
    !is_map(object, pointer) && created.insert(pointer.to_string())
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
    fn set_string_on_an_array_element_is_one_add_and_creates_no_parent() {
        // RFC 0017 relies on this: an existing array element is replaced in place.
        let object = serde_json::json!({"spec": {"initContainers": [{"image": "quay.io/a/b:1"}]}});
        let mutations = vec![Mutation::SetString {
            path: ["spec", "initContainers", "0", "image"]
                .map(str::to_string)
                .to_vec(),
            value: "mirror.io/quay/a/b:1".to_string(),
        }];
        let patch = render_patch(&object, &mutations);
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &patch).unwrap();
        assert_eq!(patch.0.len(), 1);
        assert_eq!(
            patched,
            serde_json::json!({"spec": {"initContainers": [{"image": "mirror.io/quay/a/b:1"}]}})
        );
    }

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

    fn path(segments: &str) -> Vec<String> {
        segments.split('/').map(str::to_string).collect()
    }

    /// RFC 0018's shape: ids, flags and a policy string under one missing `securityContext`. The
    /// parent is added once, and every value keeps its JSON type (L26).
    #[test]
    fn mixed_scalars_under_one_missing_parent_add_it_once_and_all_survive() {
        let object = serde_json::json!({"spec": {"containers": []}});
        let mutations = vec![
            Mutation::SetInt {
                path: path("spec/securityContext/runAsUser"),
                value: 1_000_100_000,
            },
            Mutation::SetBool {
                path: path("spec/securityContext/runAsNonRoot"),
                value: true,
            },
            Mutation::SetString {
                path: path("spec/securityContext/fsGroupChangePolicy"),
                value: "OnRootMismatch".into(),
            },
            Mutation::SetBool {
                path: path("spec/hostUsers"),
                value: false,
            },
        ];
        let patch = render_patch(&object, &mutations);
        let parents = patch
            .0
            .iter()
            .filter(|op| op.path().as_str() == "/spec/securityContext")
            .count();
        assert_eq!(parents, 1);

        let mut patched = object.clone();
        json_patch::patch(&mut patched, &patch.0).expect("the patch must apply");
        assert_eq!(
            patched["spec"]["securityContext"],
            serde_json::json!({
                "runAsUser": 1_000_100_000_i64,
                "runAsNonRoot": true,
                "fsGroupChangePolicy": "OnRootMismatch"
            })
        );
        assert_eq!(patched["spec"]["hostUsers"], Value::Bool(false));
    }

    /// A scalar under `metadata.annotations` and an `Annotate` share one record of the map they
    /// create: the second never writes a whole map over the first.
    #[test]
    fn a_scalar_and_an_annotation_under_one_missing_map_both_survive() {
        let object = serde_json::json!({"metadata": {}});
        let mutations = vec![
            Mutation::SetString {
                path: path("metadata/annotations/a"),
                value: "1".into(),
            },
            Mutation::Annotate {
                key: "b".into(),
                value: "2".into(),
            },
        ];
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &render_patch(&object, &mutations).0)
            .expect("the patch must apply");
        assert_eq!(
            patched["metadata"]["annotations"],
            serde_json::json!({"a": "1", "b": "2"})
        );
    }

    /// RFC 0018: a pod that asks for `hostUsers: true` leaves the mutation with `false`.
    #[test]
    fn host_users_true_replaced_by_false() {
        let object = serde_json::json!({"spec": {"hostUsers": true}});
        let mutations = vec![Mutation::SetBool {
            path: path("spec/hostUsers"),
            value: false,
        }];
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &render_patch(&object, &mutations).0)
            .expect("the patch must apply");
        assert_eq!(patched, serde_json::json!({"spec": {"hostUsers": false}}));
    }

    #[test]
    fn an_empty_path_writes_nothing() {
        let object = serde_json::json!({"spec": {}});
        let mutations = vec![Mutation::SetBool {
            path: Vec::new(),
            value: true,
        }];
        assert!(render_patch(&object, &mutations).0.is_empty());
    }

    /// An existing parent keeps its other fields: no `{}` is written over it.
    #[test]
    fn a_scalar_under_an_existing_parent_adds_only_the_field() {
        let object = serde_json::json!({"spec": {"securityContext": {"fsGroup": 5}}});
        let mutations = vec![Mutation::SetInt {
            path: path("spec/securityContext/runAsGroup"),
            value: 0,
        }];
        let patch = render_patch(&object, &mutations);
        assert_eq!(patch.0.len(), 1);
        let mut patched = object.clone();
        json_patch::patch(&mut patched, &patch.0).expect("the patch must apply");
        assert_eq!(
            patched["spec"]["securityContext"],
            serde_json::json!({"fsGroup": 5, "runAsGroup": 0})
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
    fn no_warning_leaves_the_response_unchanged() {
        let response = with_warnings(AdmissionResponse::invalid("x"), Vec::new());
        assert_eq!(response.warnings, None);
    }

    /// Two registries of four warnings each: one bound over the merged list keeps six, where a
    /// bound per registry would have let eight through (RFC 0019 D-14).
    #[test]
    fn the_bound_runs_once_after_the_merge() {
        let first = (0..4).map(|i| format!("first {i}"));
        let second = (0..4).map(|i| format!("second {i}\n"));
        let response = with_warnings(
            AdmissionResponse::invalid("x"),
            first.chain(second).collect(),
        );
        assert_eq!(
            response.warnings.unwrap(),
            [
                "first 0",
                "first 1",
                "first 2",
                "first 3",
                "second 0 ",
                "second 1 "
            ]
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
