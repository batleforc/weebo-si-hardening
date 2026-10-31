//! The `image-policy` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-image-policy`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod image_metrics;
pub mod image_policy;

pub use image_metrics::ImageMetrics;
pub use image_policy::{
    ImagePolicyState, VALIDATE_DEVWORKSPACES_PATH, VALIDATE_PODS_PATH, image_policy_router,
    registries,
};

use std::sync::Arc;

use weebo_si_webhook::AdmissionShared;

/// RFC 0005's two routes, `/validate/v1alpha1/devworkspaces` and `/validate/v1/pods`.
///
/// **One `ImageMetrics`, one config handle, two registries.** The two enforcement points must
/// never disagree about the catalogue, and sharing the handle rather than reading the config
/// twice is what makes that structural. Inert until `spec.features.imagePolicy` exists.
pub fn admission_routes(shared: &AdmissionShared) -> Result<axum::Router, String> {
    let metrics = ImageMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?;
    let image_observer: Arc<dyn weebo_si_image_policy::ImagePolicyObserver> = Arc::new(metrics);
    let (workspace_registry, pod_registry) = registries(
        shared.config_store.image_policy_config(),
        Arc::clone(&image_observer),
    );
    Ok(image_policy_router(Arc::new(ImagePolicyState {
        config: shared.config_store.image_policy_config(),
        workspace_registry,
        pod_registry,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        observer: Arc::clone(&shared.observer) as _,
        image_observer,
        metrics: shared.metrics.clone(),
    })))
}
