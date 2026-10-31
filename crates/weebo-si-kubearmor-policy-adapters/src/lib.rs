//! The `kubearmor-policy` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-kubearmor-policy`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod kubearmor_capabilities;
pub mod kubearmor_metrics;
pub mod kubearmor_policy_store;
pub mod kubearmor_template_store;
pub mod node_enforcer;

pub use controller::KubeArmorPolicyDeps;
pub use kubearmor_capabilities::KubeArmorCapabilities;
pub use kubearmor_metrics::KubeArmorMetrics;
pub use kubearmor_policy_store::KubeArmorPolicyStore;
pub use kubearmor_template_store::{
    KUBEARMOR_GROUP, KubeArmorTemplateStore, kubearmor_policy_resource,
};
pub use node_enforcer::KubeNodeEnforcerView;

use std::sync::Arc;

use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_kubearmor_policy::KubeArmorPolicy;

/// Start this feature's watches and assemble what its reconcile loops need — `None` on a cluster
/// that does not serve the `KubeArmorPolicy` CRD (or a role that may not watch it): the loops are
/// then never started, rather than started and failing every pass. RFC 0006's *Bypass* asks for
/// the gap to be visible, and this log line plus `backends kubearmor` is where it is.
pub async fn controller_deps(
    shared: &ControllerShared,
) -> Result<Option<KubeArmorPolicyDeps>, String> {
    if !shared.kubearmor_enabled {
        tracing::info!(
            "kubearmor-policy is inert — this cluster does not serve the KubeArmorPolicy CRD"
        );
        return Ok(None);
    }
    let templates = Arc::new(
        KubeArmorTemplateStore::spawn(shared.client.clone(), &shared.operator_namespace)
            .await
            .map_err(|err| format!("could not start the KubeArmorPolicy template watch: {err}"))?,
    );
    let store = Arc::new(
        KubeArmorPolicyStore::spawn(shared.client.clone())
            .await
            .map_err(|err| format!("could not start the managed-KubeArmorPolicy watch: {err}"))?,
    );
    let node_enforcer = Arc::new(
        KubeNodeEnforcerView::spawn(shared.client.clone())
            .await
            .map_err(|err| format!("could not start the pod/node enforcement watches: {err}"))?,
    );
    let config = shared.config_store.kubearmor_policy_config();
    let feature = Arc::new(KubeArmorPolicy::new(
        Arc::clone(&config),
        shared.config_store.resolved_runtime_backend(),
        templates,
    ));
    let metrics =
        Arc::new(KubeArmorMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?);
    Ok(Some(KubeArmorPolicyDeps {
        feature,
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        policy_store: store as _,
        node_enforcer: Arc::clone(&node_enforcer) as _,
        enforcement_subjects: node_enforcer as _,
        observer: metrics as _,
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
    }))
}
