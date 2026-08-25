//! `image-policy`'s two validating admission routes: `AdmissionReview` in, allow/deny out —
//! never a patch, since this feature never mutates. See RFC 0005's *Two enforcement points*.
//!
//! The two routes deliberately compute different answers, and everything about that difference
//! lives in the domain: this module reads a `DevWorkspace`'s components or a `Pod`'s three
//! container lists, hands the result to the matching `Feature`, and renders the verdict. The one
//! thing it does for both identically is resolve the declared variables — through
//! [`weebo_si_image_policy::variable::resolve_declared`], one function in the *domain*, so RFC
//! 0005's "variables resolve identically at both layers" is a consequence of there being one
//! implementation rather than a promise about two adapters that could drift.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{AdmitOutcome, Registry};
use weebo_si_crd::{ImagePolicyConfig, NamespaceName};
use weebo_si_image_policy::port::Resource;
use weebo_si_image_policy::variable::resolve_declared;
use weebo_si_image_policy::{
    ContainerImage, ImagePolicyObserver, PodImages, PodImagesFeature, VariableValues,
    WorkspaceImages, WorkspaceImagesFeature, escape_reference,
};

use crate::metrics::WebhookMetrics;

/// Path the `DevWorkspace` rule points at.
pub const VALIDATE_DEVWORKSPACES_PATH: &str = "/validate/v1alpha1/devworkspaces";
/// Path the `Pod` rule points at — serving `pods` and `pods/ephemeralcontainers` alike, since
/// the subresource carries the same object shape and the verdict does not depend on which one
/// the write arrived through.
pub const VALIDATE_PODS_PATH: &str = "/validate/v1/pods";

/// Everything the two handlers need, injected once at boot — the composition root is the only
/// place naming concrete adapters, per `docs/architecture/hexagonal.md`.
pub struct ImagePolicyState {
    /// `spec.features.imagePolicy`, hot-reloaded — read fresh on every request, and shared with
    /// both features so the two enforcement points can never disagree.
    pub config: Arc<RwLock<Option<ImagePolicyConfig>>>,
    /// The `DevWorkspace` half.
    pub workspace_registry: Registry<WorkspaceImages>,
    /// The `Pod` half.
    pub pod_registry: Registry<PodImages>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and annotations of a namespace — the only lookup either route makes, and one
    /// that already existed. This feature adds no cache and no RBAC.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Unused by either feature, required structurally by `weebo_si_chassis::admit`'s `Context`.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// RFC 0005's own metrics — the same handle both features hold, so the variable counters the
    /// resolver drives and the verdict counters the features drive land on one registration.
    pub image_observer: Arc<dyn ImagePolicyObserver>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

impl ImagePolicyState {
    /// Resolve the declared variables for one namespace. `None` config yields an empty set,
    /// which is correct rather than merely convenient: with no `imagePolicy` block the gate
    /// already reports `Off`, so nothing will read these.
    fn variables(&self, namespace: &NamespaceName) -> VariableValues {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(config) => resolve_declared(
                config,
                namespace,
                self.namespace_view.as_ref(),
                self.image_observer.as_ref(),
            ),
            None => VariableValues::new(),
        }
    }

    /// `workspaceSelection.attribute` and `namespaceSelection.annotation`, as currently
    /// configured. An empty string disables its channel, which is the caller's live
    /// configuration to know rather than the extractor's.
    fn selection_keys(&self) -> (String, String) {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(config) => (
                config.workspace_selection.attribute.clone(),
                config.namespace_selection.annotation.clone(),
            ),
            None => (String::new(), String::new()),
        }
    }
}

/// The `image-policy` router. Merged with the other two in the composition root.
pub fn image_policy_router(state: Arc<ImagePolicyState>) -> Router {
    Router::new()
        .route(VALIDATE_DEVWORKSPACES_PATH, post(validate_devworkspaces))
        .route(VALIDATE_PODS_PATH, post(validate_pods))
        .with_state(state)
}

/// Read `spec.template.components[*].container.image`.
///
/// `spec.template.components[].plugin` and `spec.contributions[]` are deliberately not read:
/// they name a plugin by URI or id, DevWorkspace Operator resolves them to images long after
/// admission, and a resolver we wrote would be a second implementation of somebody else's
/// resolution that is wrong the day theirs changes. The `Pod` route sees the result.
pub fn workspace_images_from_object(
    namespace: &NamespaceName,
    obj: &DynamicObject,
    attribute_key: &str,
    namespace_annotation: Option<String>,
    variables: VariableValues,
) -> WorkspaceImages {
    let images = obj
        .data
        .pointer("/spec/template/components")
        .and_then(|components| components.as_array())
        .map(|components| {
            components
                .iter()
                .filter_map(|component| {
                    let image = component.pointer("/container/image")?.as_str()?;
                    let name = component
                        .get("name")
                        .and_then(|name| name.as_str())
                        .unwrap_or("<unnamed>");
                    Some(ContainerImage::new(name, image))
                })
                .collect()
        })
        .unwrap_or_default();

    let attribute = if attribute_key.is_empty() {
        None
    } else {
        obj.data
            .pointer("/spec/template/attributes")
            .and_then(|attributes| attributes.get(attribute_key))
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };

    WorkspaceImages {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        images,
        attribute,
        namespace_annotation,
        variables,
    }
}

/// Read `spec.containers[*]`, `spec.initContainers[*]` and `spec.ephemeralContainers[*]`.
///
/// All three, flattened, in that order. Which list a container came from is not carried: the
/// verdict does not depend on it, and the name is what the error message needs. Missing the
/// ephemeral list would leave `kubectl debug` as a one-command bypass, which is also the most
/// convenient one available to anybody who already has workspace access.
pub fn pod_images_from_object(
    namespace: &NamespaceName,
    obj: &DynamicObject,
    variables: VariableValues,
) -> PodImages {
    let mut images = Vec::new();
    for list in ["containers", "initContainers", "ephemeralContainers"] {
        let Some(containers) = obj
            .data
            .pointer(&format!("/spec/{list}"))
            .and_then(|value| value.as_array())
        else {
            continue;
        };
        for container in containers {
            let Some(image) = container.get("image").and_then(|value| value.as_str()) else {
                // A container with no image is one the apiserver will reject on its own, and
                // "deny because a field is absent" would be this webhook answering for a
                // validation that is not ours.
                continue;
            };
            let name = container
                .get("name")
                .and_then(|name| name.as_str())
                .unwrap_or("<unnamed>");
            images.push(ContainerImage::new(name, image));
        }
    }

    PodImages {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        images,
        variables,
    }
}

/// Logs one decision — namespace, subject name, the count of images seen, and the verdict.
///
/// **Never the object**, per RFC 0002's rule this route inherits: a DevWorkspace template
/// carries the user's environment variables and can carry a token, and a `Pod` spec carries
/// more. The denial reason is included and already carries the offending reference through
/// [`escape_reference`] — the only attacker-controlled value that reaches this line, and it is
/// escaped and length-bounded before it does.
fn log_decision(
    resource: Resource,
    namespace: &NamespaceName,
    subject: &str,
    images: usize,
    denial: Option<&str>,
) {
    let resource = resource.label();
    match denial {
        Some(reason) => println!(
            "weebo-si-webhook: image-policy deny resource={resource} namespace={namespace} \
             subject={} images={images} reason={reason}",
            escape_reference(subject)
        ),
        None => println!(
            "weebo-si-webhook: image-policy allow resource={resource} namespace={namespace} \
             subject={} images={images}",
            escape_reference(subject)
        ),
    }
}

async fn validate_devworkspaces(
    State(state): State<Arc<ImagePolicyState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return Json(
                AdmissionResponse::invalid("the AdmissionReview carried no request").into_review(),
            );
        }
    };

    let response = AdmissionResponse::from(&request);
    let Some(object) = &request.object else {
        return Json(response.into_review());
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let (attribute_key, annotation_key) = state.selection_keys();
    let namespace_annotation = (!annotation_key.is_empty())
        .then(|| state.namespace_view.annotation(&namespace, &annotation_key))
        .flatten();
    let subject = workspace_images_from_object(
        &namespace,
        object,
        &attribute_key,
        namespace_annotation,
        state.variables(&namespace),
    );

    let _timer = state
        .metrics
        .timer("image-policy", Resource::DevWorkspace.kind())
        .start_timer();
    let outcome = weebo_si_chassis::admit(
        &state.workspace_registry,
        &subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );

    let response = match outcome {
        Ok(AdmitOutcome::Allow(_)) => {
            log_decision(
                Resource::DevWorkspace,
                &namespace,
                &subject.name,
                subject.images.len(),
                None,
            );
            response
        }
        Ok(AdmitOutcome::Deny(reason)) => {
            log_decision(
                Resource::DevWorkspace,
                &namespace,
                &subject.name,
                subject.images.len(),
                Some(&reason),
            );
            response.deny(reason)
        }
        Err(err) => {
            let reason = err.to_string();
            log_decision(
                Resource::DevWorkspace,
                &namespace,
                &subject.name,
                subject.images.len(),
                Some(&reason),
            );
            response.deny(reason)
        }
    };

    Json(response.into_review())
}

async fn validate_pods(
    State(state): State<Arc<ImagePolicyState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return Json(
                AdmissionResponse::invalid("the AdmissionReview carried no request").into_review(),
            );
        }
    };

    let response = AdmissionResponse::from(&request);
    let Some(object) = &request.object else {
        return Json(response.into_review());
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let subject = pod_images_from_object(&namespace, object, state.variables(&namespace));

    let _timer = state
        .metrics
        .timer("image-policy", Resource::Pod.kind())
        .start_timer();
    let outcome = weebo_si_chassis::admit(
        &state.pod_registry,
        &subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );

    let response = match outcome {
        Ok(AdmitOutcome::Allow(_)) => {
            log_decision(
                Resource::Pod,
                &namespace,
                &subject.name,
                subject.images.len(),
                None,
            );
            response
        }
        Ok(AdmitOutcome::Deny(reason)) => {
            log_decision(
                Resource::Pod,
                &namespace,
                &subject.name,
                subject.images.len(),
                Some(&reason),
            );
            response.deny(reason)
        }
        Err(err) => {
            let reason = err.to_string();
            log_decision(
                Resource::Pod,
                &namespace,
                &subject.name,
                subject.images.len(),
                Some(&reason),
            );
            response.deny(reason)
        }
    };

    Json(response.into_review())
}

/// Build both registries against one shared config handle and one shared observer — the shape
/// the composition root and the envtest suite both use, so what the tests prove is the wiring
/// production runs.
pub fn registries(
    config: Arc<RwLock<Option<ImagePolicyConfig>>>,
    observer: Arc<dyn ImagePolicyObserver>,
) -> (Registry<WorkspaceImages>, Registry<PodImages>) {
    let mut workspace_registry: Registry<WorkspaceImages> = Registry::new();
    workspace_registry.register(WorkspaceImagesFeature::new(
        Arc::clone(&config),
        Arc::clone(&observer),
    ));
    let mut pod_registry: Registry<PodImages> = Registry::new();
    pod_registry.register(PodImagesFeature::new(config, observer));
    (workspace_registry, pod_registry)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn object(
        kind: &str,
        plural: &str,
        group: &str,
        version: &str,
        spec: serde_json::Value,
    ) -> DynamicObject {
        let mut obj = DynamicObject::new(
            "subject",
            &kube::core::ApiResource {
                group: group.to_string(),
                version: version.to_string(),
                api_version: if group.is_empty() {
                    version.to_string()
                } else {
                    format!("{group}/{version}")
                },
                kind: kind.to_string(),
                plural: plural.to_string(),
            },
        );
        obj.data = serde_json::json!({ "spec": spec });
        obj
    }

    fn workspace(spec: serde_json::Value) -> DynamicObject {
        object(
            "DevWorkspace",
            "devworkspaces",
            "controller.devfile.io",
            "v1alpha1",
            spec,
        )
    }

    fn pod(spec: serde_json::Value) -> DynamicObject {
        object("Pod", "pods", "", "v1", spec)
    }

    fn ns() -> NamespaceName {
        NamespaceName::new("user-alice")
    }

    const ATTRIBUTE: &str = "hardening.weebo.io/image-policy";

    #[test]
    fn devworkspace_component_images_are_extracted_with_their_component_names() {
        let obj = workspace(serde_json::json!({
            "template": {
                "components": [
                    {"name": "dev", "container": {"image": "registry.internal/shared/base:1"}},
                    {"name": "tools", "container": {"image": "docker.io/library/postgres:16"}},
                ]
            }
        }));
        let subject =
            workspace_images_from_object(&ns(), &obj, ATTRIBUTE, None, VariableValues::new());
        assert_eq!(
            subject.images,
            vec![
                ContainerImage::new("dev", "registry.internal/shared/base:1"),
                ContainerImage::new("tools", "docker.io/library/postgres:16"),
            ]
        );
    }

    #[test]
    fn a_plugin_component_is_not_read_because_dwo_resolves_it_after_admission() {
        let obj = workspace(serde_json::json!({
            "template": {
                "components": [
                    {"name": "dev", "container": {"image": "registry.internal/shared/base:1"}},
                    {"name": "editor", "plugin": {"uri": "https://example.test/plugin.yaml"}},
                ]
            }
        }));
        let subject =
            workspace_images_from_object(&ns(), &obj, ATTRIBUTE, None, VariableValues::new());
        assert_eq!(subject.images.len(), 1);
        assert_eq!(subject.images[0].name, "dev");
    }

    #[test]
    fn a_workspace_with_no_components_yields_no_images_rather_than_failing() {
        let obj = workspace(serde_json::json!({"template": {}}));
        let subject =
            workspace_images_from_object(&ns(), &obj, ATTRIBUTE, None, VariableValues::new());
        assert!(subject.images.is_empty());
    }

    #[test]
    fn the_selection_attribute_is_extracted_verbatim() {
        let obj = workspace(serde_json::json!({
            "template": {"attributes": {(ATTRIBUTE): "internal,devfile-udi"}}
        }));
        let subject =
            workspace_images_from_object(&ns(), &obj, ATTRIBUTE, None, VariableValues::new());
        assert_eq!(subject.attribute.as_deref(), Some("internal,devfile-udi"));
    }

    #[test]
    fn an_empty_attribute_key_disables_the_channel_entirely() {
        let obj = workspace(serde_json::json!({
            "template": {"attributes": {(ATTRIBUTE): "devfile-udi"}}
        }));
        let subject = workspace_images_from_object(&ns(), &obj, "", None, VariableValues::new());
        assert_eq!(subject.attribute, None);
    }

    #[test]
    fn all_three_pod_container_lists_are_read() {
        // Missing the ephemeral list would leave `kubectl debug` as a one-command bypass.
        let obj = pod(serde_json::json!({
            "containers": [{"name": "dev", "image": "registry.internal/a:1"}],
            "initContainers": [{"name": "clone", "image": "quay.io/devfile/project-clone:1"}],
            "ephemeralContainers": [{"name": "debugger", "image": "ghcr.io/x/debug:1"}],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        let names: Vec<&str> = subject.images.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, vec!["dev", "clone", "debugger"]);
    }

    #[test]
    fn a_pod_with_only_containers_still_works() {
        let obj = pod(serde_json::json!({
            "containers": [{"name": "dev", "image": "registry.internal/a:1"}],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        assert_eq!(subject.images.len(), 1);
    }

    #[test]
    fn a_container_with_no_image_is_skipped_not_denied() {
        // The apiserver rejects that on its own; denying here would be this webhook answering
        // for a validation that is not ours.
        let obj = pod(serde_json::json!({
            "containers": [{"name": "broken"}, {"name": "dev", "image": "registry.internal/a:1"}],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        assert_eq!(subject.images.len(), 1);
        assert_eq!(subject.images[0].name, "dev");
    }

    #[test]
    fn an_unnamed_container_still_produces_a_usable_message() {
        let obj = pod(serde_json::json!({
            "containers": [{"image": "registry.internal/a:1"}],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        assert_eq!(subject.images[0].name, "<unnamed>");
    }

    #[test]
    fn the_reference_reaches_the_domain_exactly_as_written_never_normalized_here() {
        // Normalizing in the adapter would mean it happens twice, and two copies can drift.
        let obj = pod(serde_json::json!({
            "containers": [{"name": "dev", "image": "REGISTRY.INTERNAL/Weebo/dev"}],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        assert_eq!(subject.images[0].reference, "REGISTRY.INTERNAL/Weebo/dev");
    }

    /// RFC 0002's rule, inherited by these routes and re-asserted here because a `Pod` spec
    /// carries more than a `DevWorkspace` template does.
    #[test]
    fn the_admitted_objects_data_field_is_read_only_by_the_two_extractors() {
        let needle = ["object", ".data"].join("");
        let source = include_str!("image_policy.rs");
        let body = source.split("mod tests").next().unwrap_or_default();
        let occurrences = body.matches(&needle).count();
        assert_eq!(
            occurrences, 0,
            "the handlers must reach the object's data only through \
             workspace_images_from_object / pod_images_from_object, which take `obj` and read \
             exactly the fields RFC 0005 names — found {occurrences} direct reads"
        );
    }
}
