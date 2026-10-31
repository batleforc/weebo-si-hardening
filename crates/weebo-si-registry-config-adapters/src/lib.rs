//! The `registry-config` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-registry-config`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod registry_metrics;
pub mod registry_object_store;
pub mod registry_template_store;

pub use controller::RegistryConfigDeps;
pub use registry_metrics::RegistryMetrics;
pub use registry_object_store::KubeRegistryObjectStore;
pub use registry_template_store::{KubeRegistryTemplateStore, OWNED_PREFIX};

use std::sync::Arc;

use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_registry_config::RegistryConfigFeature;

/// Start this feature's two watches and assemble what its loop needs — `None` when this role may
/// not watch `ConfigMap`s and `Secret`s cluster-wide (`registryConfig.rbac.enabled` off): a watch
/// without the grant would retry a `403` forever and never let the process finish starting.
pub async fn controller_deps(
    shared: &ControllerShared,
) -> Result<Option<RegistryConfigDeps>, String> {
    let watchable = async {
        Ok::<bool, kube::Error>(
            weebo_si_runtime::access::can_watch(&shared.client, "", "configmaps", None).await?
                && weebo_si_runtime::access::can_watch(&shared.client, "", "secrets", None).await?,
        )
    }
    .await
    .map_err(|err| format!("could not ask whether registry-config may watch: {err}"))?;
    if !watchable {
        tracing::info!(
            "registry-config is inert — this ServiceAccount may not watch configmaps and secrets \
             (set registryConfig.rbac.enabled in the chart)"
        );
        return Ok(None);
    }
    let config = shared.config_store.registry_config();
    let templates = Arc::new(
        KubeRegistryTemplateStore::spawn(shared.client.clone(), &shared.operator_namespace)
            .await
            .map_err(|err| format!("could not start the registry template watch: {err}"))?,
    );
    let store = Arc::new(
        KubeRegistryObjectStore::spawn(shared.client.clone())
            .await
            .map_err(|err| format!("could not start the managed-registry-object watch: {err}"))?,
    );
    let metrics =
        Arc::new(RegistryMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?);
    Ok(Some(RegistryConfigDeps {
        feature: Arc::new(RegistryConfigFeature::new(Arc::clone(&config), templates)),
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        object_store: store as _,
        observer: metrics as _,
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
    }))
}
