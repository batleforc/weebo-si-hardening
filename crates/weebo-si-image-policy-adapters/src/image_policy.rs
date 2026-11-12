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
use weebo_si_chassis::{AdmitOutcome, Registry, Subject};
use weebo_si_crd::{IMAGE_REWRITE_ANNOTATION, NamespaceName, ResolvedImagePolicyConfig};
use weebo_si_image_policy::port::Resource;
use weebo_si_image_policy::variable::resolve_declared;
use weebo_si_image_policy::{
    ContainerImage, ImagePolicyObserver, ImageRewriteFeature, ImageSlot, LoadedRewrite, PodImages,
    PodImagesFeature, RewriteImages, VariableValues, WorkspaceImages, WorkspaceImagesFeature,
    escape_reference,
};

use weebo_si_webhook::metrics::WebhookMetrics;

/// Path the `DevWorkspace` rule points at.
pub const VALIDATE_DEVWORKSPACES_PATH: &str = "/validate/v1alpha1/devworkspaces";
/// Path the `Pod` rule points at — serving `pods` and `pods/ephemeralcontainers` alike, since
/// the subresource carries the same object shape and the verdict does not depend on which one
/// the write arrived through.
pub const VALIDATE_PODS_PATH: &str = "/validate/v1/pods";
/// RFC 0017's `Pod` rewrite — `pods` and `pods/ephemeralcontainers`, like the validating rule.
pub const MUTATE_PODS_PATH: &str = "/mutate/v1/pods";
/// RFC 0017's `DevWorkspace` rewrite: its own path beside `dwoc-pin`'s, so `weebo-si-webhook`
/// stays untouched (resolved 8).
pub const MUTATE_DEVWORKSPACE_IMAGES_PATH: &str = "/mutate/v1alpha1/devworkspaces/images";

/// Everything the two handlers need, injected once at boot — the composition root is the only
/// place naming concrete adapters, per `docs/architecture/hexagonal.md`.
pub struct ImagePolicyState {
    /// `spec.features.imagePolicy`, hot-reloaded — read fresh on every request, and shared with
    /// both features so the two enforcement points can never disagree.
    pub config: Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    /// The `DevWorkspace` half.
    pub workspace_registry: Registry<WorkspaceImages>,
    /// The `Pod` half.
    pub pod_registry: Registry<PodImages>,
    /// RFC 0017's `image-rewrite`, both mutating routes.
    pub rewrite_registry: Registry<RewriteImages>,
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
        .route(MUTATE_PODS_PATH, post(mutate_pods))
        .route(MUTATE_DEVWORKSPACE_IMAGES_PATH, post(mutate_devworkspaces))
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

/// Where a pod carries an image: each list under `spec`, and the field of an entry holding the
/// reference. Containers, init containers and ephemeral containers — missing the last would leave
/// `kubectl debug` as a one-command bypass — and OCI image volumes, which pull from a registry
/// exactly as a container does (a pod could otherwise mount any registry's content next to an
/// admitted container). One table, read by both `image-policy` and `image-rewrite`, so the two
/// can never disagree about which locations exist (RFC 0017, *Architecture*).
const POD_IMAGE_LISTS: &[(&str, &str)] = &[
    ("/spec/containers", "/image"),
    ("/spec/initContainers", "/image"),
    ("/spec/ephemeralContainers", "/image"),
    ("/spec/volumes", "/image/reference"),
];

/// One image found by [`image_entries`].
struct ImageEntry<'a> {
    list: &'static str,
    field: &'static str,
    index: usize,
    entry: &'a serde_json::Value,
    /// The entry's `name`, as `volume/<name>` for an image volume so a message says which kind
    /// of thing it is; `<unnamed>` when absent.
    name: String,
    image: &'a str,
}

/// Every image in `data` under `lists`, in table order. An entry with no image is skipped: the
/// apiserver rejects it on its own, and "deny because a field is absent" would be this webhook
/// answering for a validation that is not ours.
fn image_entries<'a>(
    data: &'a serde_json::Value,
    lists: &'static [(&'static str, &'static str)],
) -> impl Iterator<Item = ImageEntry<'a>> {
    lists.iter().flat_map(move |(list, field)| {
        data.pointer(list)
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(move |(index, entry)| {
                let image = entry.pointer(field)?.as_str()?;
                let name = entry
                    .get("name")
                    .and_then(|name| name.as_str())
                    .unwrap_or("<unnamed>");
                let name = if *list == "/spec/volumes" {
                    format!("volume/{name}")
                } else {
                    name.to_string()
                };
                Some(ImageEntry {
                    list,
                    field,
                    index,
                    entry,
                    name,
                    image,
                })
            })
    })
}

/// Read every image location of [`POD_IMAGE_LISTS`], flattened in that order. Which list an
/// image came from is not carried: the verdict does not depend on it, and the name is what the
/// error message needs.
pub fn pod_images_from_object(
    namespace: &NamespaceName,
    obj: &DynamicObject,
    variables: VariableValues,
) -> PodImages {
    let images = image_entries(&obj.data, POD_IMAGE_LISTS)
        .map(|found| ContainerImage::new(found.name, found.image))
        .collect();

    PodImages {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        images,
        variables,
    }
}

/// The images `image-rewrite` may change, with where each one sits — RFC 0017's *What is
/// rewritten, and when*.
///
/// `old` is the `oldObject` of an `UPDATE`: an entry whose image equals the old one is left out
/// (a container at the same index, a `DevWorkspace` component of the same name — components can
/// be inserted anywhere, so an index would see every later one as changed), so switching to `Enforce` or editing a rule never restarts a running
/// container; an existing ephemeral container (immutable) is left out by name; an image volume
/// (immutable) only on `CREATE`. `ephemeral` is the `pods/ephemeralcontainers` subresource, whose
/// write keeps nothing but `spec.ephemeralContainers` — no annotation can be recorded there.
pub fn rewrite_images_from_object(
    namespace: &NamespaceName,
    resource: Resource,
    obj: &DynamicObject,
    old: Option<&DynamicObject>,
    ephemeral: bool,
) -> RewriteImages {
    let old_at = |pointer: &str| old.and_then(|old| old.data.pointer(pointer));
    let lists: &'static [(&'static str, &'static str)] = match resource {
        Resource::DevWorkspace => &[("/spec/template/components", "/container/image")],
        Resource::Pod if ephemeral => &[("/spec/ephemeralContainers", "/image")],
        Resource::Pod => POD_IMAGE_LISTS,
    };
    let same_name_in_old = |found: &ImageEntry<'_>| {
        old_at(found.list)
            .and_then(|value| value.as_array())
            .and_then(|old| {
                old.iter()
                    .find(|e| e.get("name") == found.entry.get("name"))
            })
    };
    let mut images = Vec::new();
    for found in image_entries(&obj.data, lists) {
        let unchanged = match found.list {
            // Immutable once created: only a new entry, recognised by its name.
            "/spec/ephemeralContainers" => same_name_in_old(&found).is_some(),
            "/spec/volumes" => old.is_some(),
            "/spec/template/components" => {
                same_name_in_old(&found)
                    .and_then(|old| old.pointer(found.field))
                    .and_then(|value| value.as_str())
                    == Some(found.image)
            }
            _ => {
                old_at(&format!("{}/{}{}", found.list, found.index, found.field))
                    .and_then(|value| value.as_str())
                    == Some(found.image)
            }
        };
        if unchanged {
            continue;
        }
        let mut location: Vec<String> = found.list[1..].split('/').map(str::to_string).collect();
        location.push(found.index.to_string());
        location.extend(found.field[1..].split('/').map(str::to_string));
        images.push(ImageSlot {
            location,
            name: found.name,
            image: found.image.to_string(),
        });
    }

    // An annotation that is not a string map is replaced rather than trusted: it is a record a
    // user can write, never an input to a decision.
    let recorded = (!ephemeral).then(|| {
        obj.metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(IMAGE_REWRITE_ANNOTATION))
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default()
    });

    RewriteImages {
        name: obj.metadata.name.clone().unwrap_or_default(),
        namespace: namespace.clone(),
        resource,
        images,
        recorded,
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
        Some(reason) => tracing::info!(
            "image-policy deny resource={resource} namespace={namespace} \
             subject={} images={images} reason={reason}",
            escape_reference(subject)
        ),
        None => tracing::info!(
            "image-policy allow resource={resource} namespace={namespace} \
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
        // The same value `weebo_si_admission_requests_total` will carry, read from the same
        // subject — so the two admission metrics cannot disagree about what was admitted.
        .timer("image-policy", subject.resource())
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
        .timer("image-policy", subject.resource())
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

async fn mutate_pods(
    State(state): State<Arc<ImagePolicyState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    Json(mutate(&state, review, Resource::Pod))
}

async fn mutate_devworkspaces(
    State(state): State<Arc<ImagePolicyState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    Json(mutate(&state, review, Resource::DevWorkspace))
}

/// RFC 0017's two mutating routes. **They never deny**: an error — `NamespaceNotObserved` for a
/// namespace the watch has not seen, a patch that will not render — is *allow, unchanged*,
/// counted as `result="error"`. Whatever then needs refusing, `image-policy` refuses after us.
fn mutate(
    state: &ImagePolicyState,
    review: AdmissionReview<DynamicObject>,
    resource: Resource,
) -> AdmissionReview<DynamicObject> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return AdmissionResponse::invalid("the AdmissionReview carried no request")
                .into_review();
        }
    };
    let response = AdmissionResponse::from(&request);
    let Some(object) = &request.object else {
        return response.into_review();
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let ephemeral = request.sub_resource.as_deref() == Some("ephemeralcontainers");
    let subject = rewrite_images_from_object(
        &namespace,
        resource,
        object,
        request.old_object.as_ref(),
        ephemeral,
    );
    if subject.images.is_empty() {
        return response.into_review();
    }

    let _timer = state
        .metrics
        .timer("image-rewrite", subject.resource())
        .start_timer();
    let outcome = weebo_si_chassis::admit(
        &state.rewrite_registry,
        &subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );
    let error = |reason: &str| {
        state
            .image_observer
            .image_rewritten(resource, &subject.name, "error", None);
        tracing::warn!(
            "image-rewrite error resource={} namespace={namespace} subject={} reason={reason}",
            resource.kind(),
            escape_reference(&subject.name),
        );
    };
    match outcome {
        Ok(AdmitOutcome::Allow(mutations)) if mutations.is_empty() => response.into_review(),
        Ok(AdmitOutcome::Allow(mutations)) => {
            // A `Null` body would make `render_patch` re-create every parent over the object.
            let body = match serde_json::to_value(object) {
                Ok(body) => body,
                Err(err) => {
                    error(&err.to_string());
                    return response.into_review();
                }
            };
            let patch = weebo_si_webhook::render::render_patch(&body, &mutations);
            match response.with_patch(patch) {
                Ok(response) => response.into_review(),
                Err(err) => {
                    error(&err.to_string());
                    AdmissionResponse::from(&request).into_review()
                }
            }
        }
        // Unreachable — the feature never denies — and allowed for the same reason as an error.
        Ok(AdmitOutcome::Deny(reason)) => {
            error(&reason);
            response.into_review()
        }
        Err(err) => {
            error(&err.to_string());
            response.into_review()
        }
    }
}

/// Build both registries against one shared config handle and one shared observer — the shape
/// the composition root and the envtest suite both use, so what the tests prove is the wiring
/// production runs.
///
/// `rewrite` is RFC 0017's handle: the two validating features read it to derive the mirrored
/// platform patterns, the rewrite feature to rewrite.
pub fn registries(
    config: Arc<RwLock<Option<ResolvedImagePolicyConfig>>>,
    rewrite: Arc<RwLock<Option<LoadedRewrite>>>,
    observer: Arc<dyn ImagePolicyObserver>,
) -> (
    Registry<WorkspaceImages>,
    Registry<PodImages>,
    Registry<RewriteImages>,
) {
    let mut workspace_registry: Registry<WorkspaceImages> = Registry::new();
    workspace_registry.register(
        WorkspaceImagesFeature::new(Arc::clone(&config), Arc::clone(&observer))
            .with_rewrite(Arc::clone(&rewrite)),
    );
    let mut pod_registry: Registry<PodImages> = Registry::new();
    pod_registry.register(
        PodImagesFeature::new(config, Arc::clone(&observer)).with_rewrite(Arc::clone(&rewrite)),
    );
    let mut rewrite_registry: Registry<RewriteImages> = Registry::new();
    rewrite_registry.register(ImageRewriteFeature::new(rewrite, observer));
    (workspace_registry, pod_registry, rewrite_registry)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_image_policy::port::testing::RecordingObserver;

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
            "workspace.devfile.io",
            "v1alpha2",
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
    fn an_image_volume_is_judged_like_a_container_image() {
        let obj = pod(serde_json::json!({
            "containers": [{"name": "dev", "image": "registry.internal/a:1"}],
            "volumes": [
                {"name": "data", "image": {"reference": "ghcr.io/x/data:1", "pullPolicy": "Always"}},
                {"name": "scratch", "emptyDir": {}},
                {"name": "broken", "image": {}},
            ],
        }));
        let subject = pod_images_from_object(&ns(), &obj, VariableValues::new());
        assert_eq!(
            subject.images,
            vec![
                ContainerImage::new("dev", "registry.internal/a:1"),
                ContainerImage::new("volume/data", "ghcr.io/x/data:1"),
            ]
        );
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

    fn slots(subject: &RewriteImages) -> Vec<(String, &str)> {
        subject
            .images
            .iter()
            .map(|slot| (slot.location.join("/"), slot.image.as_str()))
            .collect()
    }

    #[test]
    fn a_created_pod_offers_every_image_location_to_the_rewrite() {
        let obj = pod(serde_json::json!({
            "initContainers": [{"name": "project-clone", "image": "quay.io/devfile/project-clone:v1"}],
            "containers": [{"name": "dev", "image": "postgres:18"}],
            "volumes": [{"name": "tools", "image": {"reference": "quay.io/a/tools:1"}}],
        }));
        let subject = rewrite_images_from_object(&ns(), Resource::Pod, &obj, None, false);
        assert_eq!(
            slots(&subject),
            vec![
                ("spec/containers/0/image".to_string(), "postgres:18"),
                (
                    "spec/initContainers/0/image".to_string(),
                    "quay.io/devfile/project-clone:v1"
                ),
                (
                    "spec/volumes/0/image/reference".to_string(),
                    "quay.io/a/tools:1"
                ),
            ]
        );
        assert_eq!(subject.images[2].name, "volume/tools");
        assert_eq!(subject.recorded, Some(Default::default()));
    }

    #[test]
    fn an_update_offers_only_what_changed_so_nothing_running_restarts() {
        // RFC 0017, T4: a label update on a pod admitted before `Enforce` leaves its images.
        let old = pod(serde_json::json!({
            "containers": [
                {"name": "dev", "image": "postgres:18"},
                {"name": "cache", "image": "redis:7"},
            ],
            "ephemeralContainers": [{"name": "debug-1", "image": "busybox"}],
            "volumes": [{"name": "tools", "image": {"reference": "quay.io/a/tools:1"}}],
        }));
        let new = pod(serde_json::json!({
            "containers": [
                {"name": "dev", "image": "postgres:18"},
                {"name": "cache", "image": "redis:8"},
            ],
            "ephemeralContainers": [
                {"name": "debug-1", "image": "busybox"},
                {"name": "debug-2", "image": "busybox"},
            ],
            "volumes": [{"name": "tools", "image": {"reference": "quay.io/a/tools:1"}}],
        }));
        let subject = rewrite_images_from_object(&ns(), Resource::Pod, &new, Some(&old), false);
        assert_eq!(
            slots(&subject),
            vec![
                ("spec/containers/1/image".to_string(), "redis:8"),
                ("spec/ephemeralContainers/1/image".to_string(), "busybox"),
            ]
        );
    }

    #[test]
    fn the_ephemeral_subresource_offers_only_new_debug_containers_and_records_nothing() {
        let old = pod(serde_json::json!({"containers": [{"name": "dev", "image": "postgres:18"}]}));
        let new = pod(serde_json::json!({
            "containers": [{"name": "dev", "image": "postgres:18"}],
            "ephemeralContainers": [{"name": "debug", "image": "busybox"}],
        }));
        let subject = rewrite_images_from_object(&ns(), Resource::Pod, &new, Some(&old), true);
        assert_eq!(
            slots(&subject),
            vec![("spec/ephemeralContainers/0/image".to_string(), "busybox")]
        );
        assert_eq!(subject.recorded, None);
    }

    #[test]
    fn a_workspace_offers_its_component_images_and_its_existing_record() {
        let mut obj = workspace(serde_json::json!({"template": {"components": [
            {"name": "db", "container": {"image": "postgres:18"}},
            {"name": "plugin", "plugin": {"uri": "x"}},
        ]}}));
        obj.metadata.annotations = Some(
            [(
                IMAGE_REWRITE_ANNOTATION.to_string(),
                r#"{"cache":"redis:7"}"#.to_string(),
            )]
            .into(),
        );
        let subject = rewrite_images_from_object(&ns(), Resource::DevWorkspace, &obj, None, false);
        assert_eq!(
            slots(&subject),
            vec![(
                "spec/template/components/0/container/image".to_string(),
                "postgres:18"
            )]
        );
        assert_eq!(
            subject.recorded.unwrap().get("cache").map(String::as_str),
            Some("redis:7")
        );
    }

    #[test]
    fn a_workspace_update_matches_components_by_name_not_position() {
        // A component inserted at the head must not make every later one look new.
        let old = workspace(serde_json::json!({"template": {"components": [
            {"name": "db", "container": {"image": "postgres:18"}},
        ]}}));
        let new = workspace(serde_json::json!({"template": {"components": [
            {"name": "tools", "container": {"image": "quay.io/a/tools:1"}},
            {"name": "db", "container": {"image": "postgres:18"}},
        ]}}));
        let subject =
            rewrite_images_from_object(&ns(), Resource::DevWorkspace, &new, Some(&old), false);
        assert_eq!(
            slots(&subject),
            vec![(
                "spec/template/components/0/container/image".to_string(),
                "quay.io/a/tools:1"
            )]
        );
    }

    /// Discards the chassis' decision events: these tests read the image observer instead.
    struct QuietObserver;

    impl Observer for QuietObserver {
        fn decided(
            &self,
            _feature: weebo_si_chassis::FeatureId,
            _mode: weebo_si_crd::FeatureMode,
            _outcome: &weebo_si_chassis::FeatureOutcome,
        ) {
        }
    }

    /// The state the webhook role builds, over fakes: `quay.io` rewritten onto the mirror, the
    /// gate answering `mode` everywhere, and `user-alice` observed unless `observed` is false.
    fn rewrite_state(
        mode: weebo_si_crd::FeatureMode,
        observed: bool,
        observer: Arc<RecordingObserver>,
    ) -> ImagePolicyState {
        use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
        use weebo_si_chassis::port::feature_gate::testing::FakeFeatureGate;
        use weebo_si_chassis::port::namespace_view::testing::FakeNamespaceView;

        let rewrite: weebo_si_crd::ImageRewriteConfig = serde_json::from_value(serde_json::json!({
            "mode": "Enforce",
            "rules": [{"from": "quay.io", "to": "registry.pkg.weebo.poc/quay"}],
        }))
        .unwrap();
        let config = Arc::new(RwLock::new(None));
        let loaded = Arc::new(RwLock::new(Some(LoadedRewrite::load(None, Some(&rewrite)))));
        let image_observer: Arc<dyn ImagePolicyObserver> = observer;
        let (workspace_registry, pod_registry, rewrite_registry) =
            registries(Arc::clone(&config), loaded, Arc::clone(&image_observer));
        let facts = weebo_si_chassis::NamespaceFacts {
            labels: Default::default(),
            selection_annotation: None,
        };
        ImagePolicyState {
            config,
            workspace_registry,
            pod_registry,
            rewrite_registry,
            gate: Arc::new(FakeFeatureGate::new(mode, Vec::new())),
            namespace_view: Arc::new(FakeNamespaceView::new(observed.then(|| (ns(), facts)))),
            dwoc_catalog: Arc::new(FakeDwocCatalog::new(std::iter::empty())),
            observer: Arc::new(QuietObserver),
            image_observer,
            metrics: WebhookMetrics::register(&prometheus::Registry::new()).unwrap(),
        }
    }

    fn review(
        obj: &DynamicObject,
        old: Option<&DynamicObject>,
        sub_resource: Option<&str>,
    ) -> AdmissionReview<DynamicObject> {
        let (group, version, kind, resource) = match obj.types.as_ref().map(|t| t.kind.as_str()) {
            Some("DevWorkspace") => (
                "workspace.devfile.io",
                "v1alpha2",
                "DevWorkspace",
                "devworkspaces",
            ),
            _ => ("", "v1", "Pod", "pods"),
        };
        serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test",
                "kind": {"group": group, "version": version, "kind": kind},
                "resource": {"group": group, "version": version, "resource": resource},
                "subResource": sub_resource,
                "name": "subject",
                "namespace": ns().as_str(),
                "operation": if old.is_some() { "UPDATE" } else { "CREATE" },
                "userInfo": {"username": "alice"},
                "object": obj,
                "oldObject": old,
            }
        }))
        .unwrap()
    }

    /// The response's verdict and its JSON patch, as `(op, path)` pairs.
    fn answer(review: AdmissionReview<DynamicObject>) -> (bool, Vec<(String, String)>) {
        let response = review.response.unwrap();
        let ops = response
            .patch
            .map(|patch| {
                let patch: Vec<serde_json::Value> = serde_json::from_slice(&patch).unwrap();
                patch
                    .iter()
                    .map(|op| {
                        (
                            op["op"].as_str().unwrap().to_string(),
                            op["path"].as_str().unwrap().to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        (response.allowed, ops)
    }

    fn upstream_pod() -> DynamicObject {
        pod(serde_json::json!({
            "containers": [
                {"name": "dev", "image": "quay.io/devfile/universal-developer-image:ubi9"},
                {"name": "db", "image": "postgres:18"},
            ],
        }))
    }

    #[test]
    fn enforce_patches_each_matching_image_and_records_its_original() {
        let observer = Arc::new(RecordingObserver::default());
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::Enforce,
            true,
            Arc::clone(&observer),
        );
        let (allowed, ops) = answer(mutate(
            &state,
            review(&upstream_pod(), None, None),
            Resource::Pod,
        ));
        assert!(allowed);
        assert!(ops.contains(&("add".to_string(), "/spec/containers/0/image".to_string())));
        assert!(
            !ops.iter()
                .any(|(_, path)| path == "/spec/containers/1/image")
        );
        // The pod carries no annotations yet, so the whole map is added.
        assert!(ops.contains(&("add".to_string(), "/metadata/annotations".to_string())));
    }

    #[test]
    fn dry_run_counts_the_rewrite_and_sends_no_patch() {
        let observer = Arc::new(RecordingObserver::default());
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::DryRun,
            true,
            Arc::clone(&observer),
        );
        let (allowed, ops) = answer(mutate(
            &state,
            review(&upstream_pod(), None, None),
            Resource::Pod,
        ));
        assert!(allowed);
        assert!(ops.is_empty(), "{ops:?}");
        let results: Vec<&str> = observer.rewrites().iter().map(|r| r.2).collect();
        assert_eq!(results, vec!["rewritten", "unmatched"]);
    }

    #[test]
    fn an_update_that_changes_no_image_sends_no_patch() {
        // RFC 0017, T4: switching to `Enforce` restarts nothing already admitted.
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::Enforce,
            true,
            Arc::new(RecordingObserver::default()),
        );
        let pod = upstream_pod();
        let (allowed, ops) = answer(mutate(
            &state,
            review(&pod, Some(&pod), None),
            Resource::Pod,
        ));
        assert!(allowed);
        assert!(ops.is_empty(), "{ops:?}");
    }

    #[test]
    fn the_devworkspace_route_patches_the_component_image() {
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::Enforce,
            true,
            Arc::new(RecordingObserver::default()),
        );
        let obj = workspace(serde_json::json!({"template": {"components": [
            {"name": "tools", "container": {"image": "quay.io/devfile/universal-developer-image:ubi9"}},
        ]}}));
        let (allowed, ops) = answer(mutate(
            &state,
            review(&obj, None, None),
            Resource::DevWorkspace,
        ));
        assert!(allowed);
        assert!(ops.contains(&(
            "add".to_string(),
            "/spec/template/components/0/container/image".to_string()
        )));
    }

    #[test]
    fn the_ephemeral_subresource_patches_only_the_new_container_and_no_annotation() {
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::Enforce,
            true,
            Arc::new(RecordingObserver::default()),
        );
        let old = upstream_pod();
        let mut new = upstream_pod();
        new.data["spec"]["ephemeralContainers"] =
            serde_json::json!([{"name": "debug", "image": "quay.io/a/debug:1"}]);
        let (allowed, ops) = answer(mutate(
            &state,
            review(&new, Some(&old), Some("ephemeralcontainers")),
            Resource::Pod,
        ));
        assert!(allowed);
        assert_eq!(
            ops,
            vec![(
                "add".to_string(),
                "/spec/ephemeralContainers/0/image".to_string()
            )]
        );
    }

    #[test]
    fn an_error_allows_the_object_unchanged_and_counts_it() {
        // A namespace the watch has not observed yet: never a denial on a mutating route.
        let observer = Arc::new(RecordingObserver::default());
        let state = rewrite_state(
            weebo_si_crd::FeatureMode::Enforce,
            false,
            Arc::clone(&observer),
        );
        let (allowed, ops) = answer(mutate(
            &state,
            review(&upstream_pod(), None, None),
            Resource::Pod,
        ));
        assert!(allowed);
        assert!(ops.is_empty());
        assert_eq!(observer.rewrites().last().map(|r| r.2), Some("error"));
    }

    /// RFC 0002's rule, inherited by these routes and re-asserted here because a `Pod` spec
    /// carries more than a `DevWorkspace` template does.
    #[test]
    fn the_admitted_objects_data_field_is_read_only_by_the_extractors() {
        let needle = ["object", ".data"].join("");
        let source = include_str!("image_policy.rs");
        let body = source.split("mod tests").next().unwrap_or_default();
        let occurrences = body.matches(&needle).count();
        assert_eq!(
            occurrences, 0,
            "the handlers must reach the object's data only through \
             workspace_images_from_object / pod_images_from_object / \
             rewrite_images_from_object, which take `obj` and read exactly the fields RFC 0005 \
             and RFC 0017 name — found {occurrences} direct reads"
        );
    }
}
