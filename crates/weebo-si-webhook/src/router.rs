//! The admission HTTP adapter: `AdmissionReview` in, JSON Patch out — the axum router the
//! composition root (and the envtest suite) both serve, so what the envtest tier proves is the
//! same wiring production runs.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{AdmitOutcome, Mutation, Registry};
use weebo_si_crd::{DwocRef, NamespaceName};
use weebo_si_dwoc_pin::Workspace;

use crate::extract::workspace_from_object;
use crate::metrics::WebhookMetrics;
use crate::render::render_patch;

/// Logs one admission decision — namespace, workspace name, the current and target references,
/// and the decision — per RFC 0002's *Security considerations*: "Logs carry the namespace, the
/// workspace name, the current and target references and the decision — **never the object**,
/// because a DevWorkspace template carries the user's environment variables and can carry a
/// token." Signature is the enforcement: there is no parameter here a caller could pass the
/// admitted object's `data` through, so a future call site cannot silently start logging it.
fn log_admission(
    namespace: &NamespaceName,
    workspace: &str,
    current: Option<&DwocRef>,
    mutations: &[Mutation],
    denial: Option<&str>,
) {
    let current = current
        .map(|dwoc_ref| format!("{}/{}", dwoc_ref.namespace, dwoc_ref.name))
        .unwrap_or_else(|| "<none>".to_string());
    let target = mutations
        .iter()
        .find_map(|mutation| match mutation {
            Mutation::SetConfigRef(dwoc_ref) => {
                Some(format!("{}/{}", dwoc_ref.namespace, dwoc_ref.name))
            }
            Mutation::Annotate { .. } => None,
        })
        .unwrap_or_else(|| "<unchanged>".to_string());
    match denial {
        Some(reason) => println!(
            "weebo-si-webhook: deny namespace={namespace} workspace={workspace} current={current} reason={reason}"
        ),
        None => println!(
            "weebo-si-webhook: allow namespace={namespace} workspace={workspace} current={current} target={target}"
        ),
    }
}

/// The Kubernetes resource this endpoint serves — a label on
/// `weebo_si_admission_duration_seconds` and `weebo_si_admission_requests_total`.
const RESOURCE: &str = "DevWorkspace";

/// Path `MutatingWebhookConfiguration.webhooks[].clientConfig` points `dwoc-pin`'s rule at, per
/// RFC 0002's *Webhook configuration*.
pub const MUTATE_DEVWORKSPACES_PATH: &str = "/mutate/v1alpha1/devworkspaces";

/// Everything the handler needs, injected once at boot — the composition root (`main.rs`) is
/// the only place naming concrete adapters, per `docs/architecture/hexagonal.md`.
pub struct AppState {
    /// Every registered feature, in declaration order.
    pub registry: Registry<Workspace>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Whether a resolved DWOC reference exists.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// The webhook's router. Also built by the envtest suite, pointed at real
/// `weebo-si-runtime` adapters — proving the wiring, not just the rules.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(MUTATE_DEVWORKSPACES_PATH, post(mutate_devworkspaces))
        .with_state(state)
}

async fn mutate_devworkspaces(
    State(state): State<Arc<AppState>>,
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
        // No object to mutate (e.g. a DELETE) — allow, unchanged.
        return Json(response.into_review());
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let workspace = workspace_from_object(&namespace, object);

    // Named (not `let _ = ...`, which would drop immediately): the histogram observation
    // happens on drop, at the end of this function's scope.
    let _timer = state.metrics.timer(RESOURCE).start_timer();
    let outcome = weebo_si_chassis::admit(
        &state.registry,
        &workspace,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );

    let response = match outcome {
        Ok(AdmitOutcome::Allow(mutations)) if mutations.is_empty() => {
            log_admission(
                &namespace,
                &workspace.name,
                workspace.config_ref.as_ref(),
                &mutations,
                None,
            );
            response
        }
        Ok(AdmitOutcome::Allow(mutations)) => {
            log_admission(
                &namespace,
                &workspace.name,
                workspace.config_ref.as_ref(),
                &mutations,
                None,
            );
            let patch = render_patch(&object.data, &mutations);
            match response.with_patch(patch) {
                Ok(response) => response,
                Err(err) => {
                    AdmissionResponse::from(&request).deny(format!("failed to render patch: {err}"))
                }
            }
        }
        Ok(AdmitOutcome::Deny(reason)) => {
            log_admission(
                &namespace,
                &workspace.name,
                workspace.config_ref.as_ref(),
                &[],
                Some(&reason),
            );
            response.deny(reason)
        }
        Err(err) => {
            let reason = err.to_string();
            log_admission(
                &namespace,
                &workspace.name,
                workspace.config_ref.as_ref(),
                &[],
                Some(&reason),
            );
            response.deny(reason)
        }
    };

    Json(response.into_review())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    /// A textual regression test, not a type-level one — `log_admission`'s signature already
    /// makes "pass the object through" impossible (there is no parameter to carry it), but this
    /// catches the case a future call site reads the admitted object's field access expression
    /// for some *other* reason (a new log line, a new mutation, a debug print) without that
    /// reader realizing it now sits next to the one call this file is allowed to make. Per RFC
    /// 0002's *Security considerations*: "never the object, because a DevWorkspace template
    /// carries the user's environment variables and can carry a token."
    ///
    /// The needle is assembled at runtime, not written as a literal, so this test does not count
    /// its own source as a second occurrence.
    #[test]
    fn the_admitted_objects_data_field_is_read_in_exactly_one_place() {
        let needle = ["object", "data"].join(".");
        let source = include_str!("router.rs");
        let occurrences = source.matches(&needle).count();
        assert_eq!(
            occurrences, 1,
            "router.rs must read the admitted object's data field in exactly one place — the \
             JSON Patch render call — found {occurrences} occurrences; if this is a deliberate \
             new read, it must not be a log line (see RFC 0002's Security considerations)"
        );
    }
}
