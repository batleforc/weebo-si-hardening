//! `pod-identity`'s two Pod routes (RFC 0018, *Webhooks*): `AdmissionReview` in, a patch or a
//! verdict out. Their own paths, not registries on `/mutate/v1/pods` and `/validate/v1/pods`:
//! those take the admin's image `failurePolicy` and would fail open under `Ignore` (Q2).
//!
//! The mutation never denies: on an error it allows the pod unchanged and validation, which runs
//! after every mutation, refuses it. Validation fails closed: an error is a refusal, so a
//! namespace the watch has not seen yet is refused rather than waved through (`mode_for_admission`).

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation};
use serde_json::Value;
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{AdmitOutcome, FeatureId, Registry};
use weebo_si_crd::{FeatureMode, NamespaceName, PodIdentityConfig};
use weebo_si_pod_identity::{
    Admission, ContainerIdentity, ContainerKind, FEATURE_ID, PodIdentityMutation,
    PodIdentityObserver, PodIdentityValidation, PodSecurityContext, PodSubject,
};
use weebo_si_webhook::metrics::WebhookMetrics;
use weebo_si_webhook::render::{render_patch, with_warnings};

/// The mutating route: `pods` CREATE.
pub const MUTATE_PODS_IDENTITY_PATH: &str = "/mutate/v1/pods/identity";
/// The validating route: `pods` CREATE and `pods/ephemeralcontainers` UPDATE (L21).
pub const VALIDATE_PODS_IDENTITY_PATH: &str = "/validate/v1/pods/identity";

/// Everything the two handlers need, injected once by the composition root.
pub struct PodIdentityState {
    /// [`PodIdentityMutation`] alone.
    pub mutation: Registry<PodSubject>,
    /// [`PodIdentityValidation`] alone.
    pub validation: Registry<PodSubject>,
    /// Which mode `pod-identity` runs in for a namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The namespace's labels and projected dwoc selection (L27).
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Unused by the feature, required by `admit`'s `Context`.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// `weebo_si_admission_requests_total`.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// The two registries over one config handle and one observer, so the halves never disagree.
pub fn registries(
    config: Arc<RwLock<Option<PodIdentityConfig>>>,
    observer: Arc<dyn PodIdentityObserver>,
) -> (Registry<PodSubject>, Registry<PodSubject>) {
    let mut mutation = Registry::new();
    mutation.register(PodIdentityMutation::new(
        Arc::clone(&config),
        Arc::clone(&observer),
    ));
    let mut validation = Registry::new();
    validation.register(PodIdentityValidation::new(config, observer));
    (mutation, validation)
}

/// The `pod-identity` router, merged with the others in the composition root.
pub fn pod_identity_router(state: Arc<PodIdentityState>) -> Router {
    Router::new()
        .route(MUTATE_PODS_IDENTITY_PATH, post(mutate))
        .route(VALIDATE_PODS_IDENTITY_PATH, post(validate))
        .with_state(state)
}

fn int(value: &Value, pointer: &str) -> Option<i64> {
    value.pointer(pointer).and_then(Value::as_i64)
}

fn string(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn list<'a>(data: &'a Value, list: &str) -> impl Iterator<Item = &'a Value> {
    data.pointer(list)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn container(kind: ContainerKind, entry: &Value) -> ContainerIdentity {
    ContainerIdentity {
        kind,
        name: string(entry, "/name").unwrap_or_default(),
        run_as_user: int(entry, "/securityContext/runAsUser"),
        run_as_group: int(entry, "/securityContext/runAsGroup"),
    }
}

/// Project an admission request onto [`PodSubject`]. `None` for anything but a pod CREATE or a
/// `pods/ephemeralcontainers` UPDATE (L21: those are the only writes judged; the chart registers
/// no other), and for a request without an object.
///
/// On CREATE the containers are `initContainers` then `containers`; on an ephemeral UPDATE only
/// the ephemeral containers `oldObject` did not have, by name: the others were judged when added.
pub fn pod_subject_from_request(request: &AdmissionRequest<DynamicObject>) -> Option<PodSubject> {
    let object = request.object.as_ref()?;
    let data = &object.data;
    let ephemeral = request.sub_resource.as_deref() == Some("ephemeralcontainers");
    let (admission, containers): (Admission, Vec<ContainerIdentity>) =
        match (&request.operation, ephemeral) {
            (Operation::Create, false) => (
                Admission::Create,
                list(data, "/spec/initContainers")
                    .map(|entry| container(ContainerKind::Init, entry))
                    .chain(
                        list(data, "/spec/containers")
                            .map(|entry| container(ContainerKind::Container, entry)),
                    )
                    .collect(),
            ),
            (Operation::Update, true) => {
                let old = request.old_object.as_ref().map(|old| &old.data);
                let existed = |entry: &Value| {
                    old.into_iter()
                        .flat_map(|old| list(old, "/spec/ephemeralContainers"))
                        .any(|known| known.get("name") == entry.get("name"))
                };
                (
                    Admission::EphemeralUpdate {
                        old_host_users: old
                            .and_then(|old| old.pointer("/spec/hostUsers"))
                            .and_then(Value::as_bool),
                    },
                    list(data, "/spec/ephemeralContainers")
                        .filter(|entry| !existed(entry))
                        .map(|entry| container(ContainerKind::Ephemeral, entry))
                        .collect(),
                )
            }
            _ => return None,
        };
    let context = |field: &str| format!("/spec/securityContext/{field}");
    Some(PodSubject {
        name: object
            .metadata
            .name
            .clone()
            .or_else(|| object.metadata.generate_name.clone())
            .unwrap_or_default(),
        namespace: NamespaceName::new(request.namespace.clone().unwrap_or_default()),
        host_users: data.pointer("/spec/hostUsers").and_then(Value::as_bool),
        security_context: PodSecurityContext {
            run_as_user: int(data, &context("runAsUser")),
            run_as_group: int(data, &context("runAsGroup")),
            fs_group: int(data, &context("fsGroup")),
            fs_group_change_policy: string(data, &context("fsGroupChangePolicy")),
            supplemental_groups: list(data, &context("supplementalGroups"))
                .filter_map(Value::as_i64)
                .collect(),
            supplemental_groups_policy: string(data, &context("supplementalGroupsPolicy")),
            run_as_non_root: data
                .pointer(&context("runAsNonRoot"))
                .and_then(Value::as_bool),
        },
        containers,
        admission,
    })
}

fn admit(
    state: &PodIdentityState,
    registry: &Registry<PodSubject>,
    subject: &PodSubject,
) -> Result<AdmitOutcome, weebo_si_chassis::DomainError> {
    let _timer = state.metrics.timer(FEATURE_ID, "Pod").start_timer();
    weebo_si_chassis::admit(
        registry,
        subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    )
}

/// `/mutate/v1/pods/identity`. Never denies.
pub fn mutate_review(
    state: &PodIdentityState,
    review: AdmissionReview<DynamicObject>,
) -> AdmissionReview<DynamicObject> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return AdmissionResponse::invalid("the AdmissionReview carried no request")
                .into_review();
        }
    };
    let response = AdmissionResponse::from(&request);
    let (Some(subject), Some(object)) = (pod_subject_from_request(&request), &request.object)
    else {
        return response.into_review();
    };
    let error = |reason: &str| {
        tracing::warn!(
            "feature={FEATURE_ID} ns={} resource=Pod name={:?} result=error reason={reason}",
            subject.namespace,
            subject.name,
        );
    };
    match admit(state, &state.mutation, &subject) {
        Ok(AdmitOutcome::Allow {
            mutations,
            warnings,
        }) if mutations.is_empty() => with_warnings(response, warnings).into_review(),
        Ok(AdmitOutcome::Allow {
            mutations,
            warnings,
        }) => {
            // The whole object, metadata included: `DynamicObject.data` has no `metadata`.
            let body = match serde_json::to_value(object) {
                Ok(body) => body,
                Err(err) => {
                    error(&err.to_string());
                    return response.into_review();
                }
            };
            match response.with_patch(render_patch(&body, &mutations)) {
                Ok(response) => with_warnings(response, warnings).into_review(),
                Err(err) => {
                    error(&err.to_string());
                    AdmissionResponse::from(&request).into_review()
                }
            }
        }
        // Unreachable, the mutation never denies; allowed like an error for validation to judge.
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

/// `/validate/v1/pods/identity`. Fails closed under `Enforce`.
pub fn validate_review(
    state: &PodIdentityState,
    review: AdmissionReview<DynamicObject>,
) -> AdmissionReview<DynamicObject> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return AdmissionResponse::invalid("the AdmissionReview carried no request")
                .into_review();
        }
    };
    let response = AdmissionResponse::from(&request);
    let Some(subject) = pod_subject_from_request(&request) else {
        return response.into_review();
    };
    match admit(state, &state.validation, &subject) {
        Ok(AdmitOutcome::Allow { warnings, .. }) => with_warnings(response, warnings).into_review(),
        // The observer already logged each reason.
        Ok(AdmitOutcome::Deny(reason)) => response.deny(reason).into_review(),
        Err(err) => {
            let reason = err.to_string();
            // DryRun never refuses, not even on an error: it is the mode an admin observes in.
            let enforce = state
                .gate
                .mode_for_admission(FeatureId::new(FEATURE_ID), &subject.namespace)
                == FeatureMode::Enforce;
            let result = if enforce { "refused" } else { "would_refuse" };
            tracing::warn!(
                "feature={FEATURE_ID} ns={} resource=Pod name={:?} result={result} reason={reason}",
                subject.namespace,
                subject.name,
            );
            if enforce {
                response.deny(reason).into_review()
            } else {
                response.into_review()
            }
        }
    }
}

async fn mutate(
    State(state): State<Arc<PodIdentityState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    Json(mutate_review(&state, review))
}

async fn validate(
    State(state): State<Arc<PodIdentityState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    Json(validate_review(&state, review))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::metrics::PodIdentityMetrics;
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_chassis::port::feature_gate::testing::FakeFeatureGate;
    use weebo_si_chassis::port::namespace_view::testing::FakeNamespaceView;

    const NS: &str = "dev-ws-test";

    struct Quiet;
    impl Observer for Quiet {
        fn decided(
            &self,
            _: weebo_si_chassis::FeatureId,
            _: FeatureMode,
            _: &weebo_si_chassis::FeatureOutcome,
        ) {
        }
    }

    /// DWO v1.1.1's workspace pod: `runAsUser 1234`, `runAsGroup 0`, `fsGroup 1234`.
    fn dwo_pod() -> Value {
        serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"generateName": "workspace4f-7d9c-", "namespace": NS},
            "spec": {
                "securityContext": {"runAsUser": 1234, "runAsGroup": 0, "fsGroup": 1234},
                "initContainers": [{"name": "project-clone", "image": "x"}],
                "containers": [{"name": "tools", "image": "x", "securityContext": {"runAsGroup": 7}}],
            },
        })
    }

    fn review(
        operation: &str,
        sub_resource: Option<&str>,
        namespace: &str,
        object: Value,
        old: Option<Value>,
    ) -> AdmissionReview<DynamicObject> {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "1",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "subResource": sub_resource,
                "operation": operation,
                "userInfo": {},
                "namespace": namespace,
                "object": object,
                "oldObject": old,
                "dryRun": false,
            },
        }))
        .unwrap()
    }

    fn request(review: AdmissionReview<DynamicObject>) -> AdmissionRequest<DynamicObject> {
        review.try_into().unwrap()
    }

    fn state(mode: FeatureMode, observed: bool) -> PodIdentityState {
        let config: PodIdentityConfig =
            serde_json::from_value(serde_json::json!({"mode": mode})).unwrap();
        let config = Arc::new(RwLock::new(Some(config)));
        let gate: Arc<FakeFeatureGate> = Arc::new(FakeFeatureGate::new(mode, Vec::new()));
        let observer = PodIdentityMetrics::register(
            &prometheus::Registry::new(),
            Arc::clone(&gate) as _,
            Arc::clone(&config),
        )
        .unwrap();
        let (mutation, validation) = registries(config, Arc::new(observer));
        let facts = observed.then(|| {
            (
                NamespaceName::new(NS),
                NamespaceFacts {
                    labels: BTreeMap::new(),
                    selection_annotation: None,
                },
            )
        });
        PodIdentityState {
            mutation,
            validation,
            gate,
            namespace_view: Arc::new(FakeNamespaceView::new(facts)),
            dwoc_catalog: Arc::new(FakeDwocCatalog::new(std::iter::empty())),
            observer: Arc::new(Quiet),
            metrics: WebhookMetrics::register(&prometheus::Registry::new()).unwrap(),
        }
    }

    fn response(review: AdmissionReview<DynamicObject>) -> AdmissionResponse {
        review.response.unwrap()
    }

    #[test]
    fn a_create_reads_init_then_regular_containers_and_the_generate_name() {
        let subject =
            pod_subject_from_request(&request(review("CREATE", None, NS, dwo_pod(), None)))
                .unwrap();
        assert_eq!(subject.name, "workspace4f-7d9c-");
        assert_eq!(subject.admission, Admission::Create);
        assert_eq!(subject.host_users, None);
        assert_eq!(subject.security_context.run_as_group, Some(0));
        assert_eq!(subject.security_context.fs_group, Some(1234));
        let names: Vec<(ContainerKind, &str, Option<i64>)> = subject
            .containers
            .iter()
            .map(|c| (c.kind, c.name.as_str(), c.run_as_group))
            .collect();
        assert_eq!(
            names,
            [
                (ContainerKind::Init, "project-clone", None),
                (ContainerKind::Container, "tools", Some(7)),
            ]
        );
    }

    #[test]
    fn an_ephemeral_update_reads_only_the_new_ephemeral_containers() {
        let mut old = dwo_pod();
        old["spec"]["ephemeralContainers"] = serde_json::json!([{"name": "debugger-a"}]);
        let mut new = old.clone();
        new["spec"]["ephemeralContainers"] = serde_json::json!([
            {"name": "debugger-a"},
            {"name": "debugger-b", "securityContext": {"runAsUser": 0}},
        ]);
        let subject = pod_subject_from_request(&request(review(
            "UPDATE",
            Some("ephemeralcontainers"),
            NS,
            new,
            Some(old),
        )))
        .unwrap();
        assert_eq!(
            subject.admission,
            Admission::EphemeralUpdate {
                old_host_users: None
            }
        );
        assert_eq!(subject.containers.len(), 1);
        assert_eq!(subject.containers[0].name, "debugger-b");
        assert_eq!(subject.containers[0].kind, ContainerKind::Ephemeral);
        assert_eq!(subject.containers[0].run_as_user, Some(0));
    }

    #[test]
    fn a_plain_pod_update_or_delete_is_not_judged() {
        // L21: an UPDATE cannot change the identity fields, and judging it would block
        // finalizer removal during an outage.
        let update = review("UPDATE", None, NS, dwo_pod(), Some(dwo_pod()));
        assert!(pod_subject_from_request(&request(update)).is_none());
        let delete = review("DELETE", None, NS, dwo_pod(), None);
        assert!(pod_subject_from_request(&request(delete)).is_none());
        let state = state(FeatureMode::Enforce, true);
        let update = review("UPDATE", None, NS, dwo_pod(), Some(dwo_pod()));
        assert!(response(validate_review(&state, update)).allowed);
    }

    #[test]
    fn enforce_patches_the_dwo_pod_and_refuses_it_unpatched() {
        let state = state(FeatureMode::Enforce, true);
        let mutated = response(mutate_review(
            &state,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(mutated.allowed);
        let patch = String::from_utf8(mutated.patch.unwrap()).unwrap();
        for expected in [
            "/spec/hostUsers",
            "/spec/securityContext/runAsGroup",
            "/spec/securityContext/supplementalGroupsPolicy",
            "/spec/securityContext/runAsNonRoot",
        ] {
            assert!(patch.contains(expected), "{expected} missing from {patch}");
        }
        // The validating webhook seeing the raw pod means the mutation did not run.
        let validated = response(validate_review(
            &state,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(!validated.allowed);
        assert!(validated.result.message.contains("hostUsers"));
    }

    #[test]
    fn dry_run_patches_nothing_and_refuses_nothing() {
        let state = state(FeatureMode::DryRun, true);
        let mutated = response(mutate_review(
            &state,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(mutated.allowed && mutated.patch.is_none());
        let mut root = dwo_pod();
        root["spec"]["securityContext"]["runAsUser"] = 0.into();
        let validated = response(validate_review(
            &state,
            review("CREATE", None, NS, root, None),
        ));
        assert!(validated.allowed);
    }

    #[test]
    fn an_unobserved_namespace_is_refused_by_validation_and_left_to_it_by_the_mutation() {
        let state = state(FeatureMode::Enforce, false);
        let mutated = response(mutate_review(
            &state,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(mutated.allowed && mutated.patch.is_none());
        let validated = response(validate_review(
            &state,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(!validated.allowed);
        assert!(
            validated.result.message.contains("not observed"),
            "{}",
            validated.result.message
        );
        // DryRun refuses nothing, an error included.
        let dry_run = self::state(FeatureMode::DryRun, false);
        let validated = response(validate_review(
            &dry_run,
            review("CREATE", None, NS, dwo_pod(), None),
        ));
        assert!(validated.allowed);
    }
}
