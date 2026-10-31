//! The `policy-guard` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-policy-guard`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod policy_guard;
pub mod registry_guard;

pub use policy_guard::{
    PolicyGuardState, VALIDATE_KUBEARMOR_POLICIES_PATH, VALIDATE_NETWORK_POLICIES_PATH,
    policy_guard_router,
};
pub use registry_guard::{
    RegistryGuardState, VALIDATE_REGISTRY_CONFIGS_PATH, registry_guard_router,
};

use std::sync::Arc;

use weebo_si_webhook::AdmissionShared;

/// The guard's routes: `/validate/v1/networkpolicies` and `/validate/v1/kubearmorpolicies`
/// (RFC 0004, RFC 0008), and `/validate/v1/registryconfigs` (RFC 0007's rule). One `policyGuard`
/// configuration handle for all three, so one `mode` and one `allowedIdentities` govern them;
/// which paths a rule actually points at is the chart's decision.
pub fn admission_routes(shared: &AdmissionShared) -> axum::Router {
    let policies = policy_guard_router(Arc::new(PolicyGuardState {
        operator_identity: shared.operator_identity.clone(),
        policy_guard_config: shared.config_store.policy_guard_config(),
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        observer: Arc::clone(&shared.observer) as _,
        metrics: shared.metrics.clone(),
    }));
    let registry = registry_guard_router(Arc::new(RegistryGuardState {
        operator_identity: shared.operator_identity.clone(),
        policy_guard_config: shared.config_store.policy_guard_config(),
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        observer: Arc::clone(&shared.observer) as _,
        metrics: shared.metrics.clone(),
    }));
    policies.merge(registry)
}
