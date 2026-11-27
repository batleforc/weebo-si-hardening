//! The `pod-identity` feature's adapters (RFC 0012, RFC 0018 *Architecture*): its two Pod
//! admission routes and the Prometheus implementation of its observer port. No store, no
//! controller loop. The decisions stay in `weebo-si-pod-identity`.

pub mod admission;
pub mod metrics;

pub use admission::{
    MUTATE_PODS_IDENTITY_PATH, PodIdentityState, VALIDATE_PODS_IDENTITY_PATH, mutate_review,
    pod_identity_router, pod_subject_from_request, registries, validate_review,
};
pub use metrics::PodIdentityMetrics;

use std::sync::Arc;

use weebo_si_webhook::AdmissionShared;

/// `/mutate/v1/pods/identity` and `/validate/v1/pods/identity`: one config handle, one observer,
/// two registries. They answer in every mode, `Off` included (L22); inert until
/// `spec.features.podIdentity` exists.
pub fn admission_routes(shared: &AdmissionShared) -> Result<axum::Router, String> {
    let config = shared.config_store.pod_identity_config();
    let observer: Arc<dyn weebo_si_pod_identity::PodIdentityObserver> = Arc::new(
        PodIdentityMetrics::register(
            &shared.prometheus,
            Arc::clone(&shared.config_store) as _,
            Arc::clone(&config),
        )
        .map_err(|err| err.to_string())?,
    );
    let (mutation, validation) = registries(config, observer);
    Ok(pod_identity_router(Arc::new(PodIdentityState {
        mutation,
        validation,
        gate: Arc::clone(&shared.config_store) as _,
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        observer: Arc::clone(&shared.observer) as _,
        metrics: shared.metrics.clone(),
    })))
}
