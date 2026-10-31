//! The `network-profiles` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-network-profiles`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod kube_canary;
pub mod kube_capabilities;
pub mod kube_policy_store;
pub mod kube_template_store;
pub mod network_metrics;

pub use controller::NetworkProfilesDeps;
pub use kube_canary::{CLIENT_POD, DEFAULT_CANARY_IMAGE, DENY_POLICY, KubeCanary, SERVER_POD};
pub use kube_capabilities::KubeCapabilities;
pub use kube_policy_store::KubePolicyStore;
pub use kube_template_store::KubeTemplateStore;
pub use network_metrics::NetworkMetrics;

use std::sync::Arc;

use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_network_profiles::NetworkProfiles;

/// Start this feature's watches and assemble what its reconcile loops need. Called by the
/// controller role before it waits for the lease, so a standby replica's caches are warm when it
/// takes over; [`controller::spawn`] starts the loops once it holds the lease.
pub async fn controller_deps(shared: &ControllerShared) -> Result<NetworkProfilesDeps, String> {
    let templates = Arc::new(
        KubeTemplateStore::spawn(
            shared.client.clone(),
            &shared.operator_namespace,
            shared.cilium_enabled,
        )
        .await
        .map_err(|err| format!("could not start the policy template watch: {err}"))?,
    );
    let policy_store = Arc::new(
        KubePolicyStore::spawn(shared.client.clone(), shared.cilium_enabled)
            .await
            .map_err(|err| format!("could not start the managed-policy watch: {err}"))?,
    );
    let config = shared.config_store.network_profiles_config();
    let feature = Arc::new(NetworkProfiles::new(
        Arc::clone(&config),
        shared.config_store.resolved_backend(),
        templates,
    ));
    let metrics =
        Arc::new(NetworkMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?);
    Ok(NetworkProfilesDeps {
        feature,
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        policy_store,
        observer: metrics as _,
        canary: Arc::new(KubeCanary::new(
            shared.client.clone(),
            shared.operator_namespace.clone(),
            &shared.canary_image,
        )),
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
    })
}
