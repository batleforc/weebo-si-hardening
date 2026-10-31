//! The `endpoint-auth` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-endpoint-auth`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod endpoint_auth;

pub use controller::EndpointAuthDeps;
pub use endpoint_auth::{
    EndpointAuthState, GateMutation, MUTATE_INGRESSES_PATH, MUTATE_ROUTES_PATH, RoutingObjectWrite,
    VALIDATE_INGRESSES_PATH, VALIDATE_ROUTES_PATH, endpoint_auth_router,
};

use std::sync::Arc;

use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_webhook::AdmissionShared;

/// RFC 0009's two routes — the mutation that attaches the gate and the guard that pins it.
/// Inert until `spec.features.endpointAuth` exists: the gate reports `Off` until then, so the
/// mutation never runs and the guard never denies.
pub fn admission_routes(shared: &AdmissionShared) -> axum::Router {
    endpoint_auth_router(Arc::new(EndpointAuthState {
        operator_identity: shared.operator_identity.clone(),
        config: shared.config_store.endpoint_auth_config(),
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        observer: Arc::clone(&shared.observer) as _,
        metrics: shared.metrics.clone(),
    }))
}

/// The sweep's deps — `None` when this role may not watch `ingresses` (`endpointAuth.rbac.enabled`
/// off). It covers the routing objects that existed before the feature was switched on, puts the
/// annotations back when anything strips them, and owns the one shared Traefik `Middleware`.
pub async fn controller_deps(
    shared: &ControllerShared,
) -> Result<Option<EndpointAuthDeps>, String> {
    let watchable =
        weebo_si_runtime::access::can_watch(&shared.client, "networking.k8s.io", "ingresses", None)
            .await
            .map_err(|err| {
                format!("could not ask whether endpoint-auth may watch ingresses: {err}")
            })?;
    if !watchable {
        tracing::info!(
            "endpoint-auth's sweep is inert — this ServiceAccount may not watch ingresses \
             (set endpointAuth.rbac.enabled in the chart)"
        );
        return Ok(None);
    }
    Ok(Some(EndpointAuthDeps {
        config: shared.config_store.endpoint_auth_config(),
        gate: shared.config_store.clone(),
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
    }))
}
