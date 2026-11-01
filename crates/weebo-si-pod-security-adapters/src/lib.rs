//! The `pod-security` feature's adapters (RFC 0013): what talks to the cluster on its behalf —
//! its namespace label store, its metrics and its reconcile loop — next to the composition
//! function `weebo-si-operator` calls. The decisions stay in `weebo-si-pod-security`, which
//! depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod found;
pub mod namespace_label_store;
pub mod pod_security_metrics;

pub use controller::PodSecurityDeps;
pub use found::found;
pub use namespace_label_store::{KubeNamespaceLabelStore, RESTORE_FIELD_MANAGER};
pub use pod_security_metrics::PodSecurityMetrics;

use std::sync::Arc;

use kube::Client;
use kube::discovery::Discovery;
use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_pod_security::PodSecurityFeature;

/// OpenShift's SCC API group: whether the apiserver serves it is what `backend: Auto` resolves on.
pub const OPENSHIFT_SECURITY_GROUP: &str = "security.openshift.io";

/// Whether the apiserver serves `security.openshift.io`. Asked once, at boot, like every other
/// capability in this operator: a cluster does not become OpenShift while the process runs.
pub async fn serves_scc(client: &Client) -> Result<bool, kube::Error> {
    let discovery = Discovery::new(client.clone())
        .filter(&[OPENSHIFT_SECURITY_GROUP])
        .run()
        .await?;
    Ok(discovery.has_group(OPENSHIFT_SECURITY_GROUP))
}

/// Assemble what this feature's loop needs — `None` when this role may not patch namespaces
/// (`podSecurity.rbac.enabled` off) and the cluster is not OpenShift, where the feature only
/// observes and needs no write.
pub async fn controller_deps(shared: &ControllerShared) -> Result<Option<PodSecurityDeps>, String> {
    let openshift = serves_scc(&shared.client)
        .await
        .map_err(|err| format!("could not discover whether this is OpenShift: {err}"))?;
    let patchable = weebo_si_runtime::access::can_patch(&shared.client, "", "namespaces", None)
        .await
        .map_err(|err| format!("could not ask whether pod-security may patch namespaces: {err}"))?;
    if !patchable && !openshift {
        tracing::info!(
            "pod-security is inert — this ServiceAccount may not patch namespaces (set \
             podSecurity.rbac.enabled in the chart)"
        );
        return Ok(None);
    }
    if !patchable {
        tracing::info!(
            "pod-security may not patch namespaces: backend Auto observes the levels OpenShift \
             syncs, and backend Labels would fail every write"
        );
    }
    let config = shared.config_store.pod_security_config();
    let metrics =
        Arc::new(PodSecurityMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?);
    Ok(Some(PodSecurityDeps {
        feature: Arc::new(PodSecurityFeature::new(Arc::clone(&config), openshift)),
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        store: Arc::new(KubeNamespaceLabelStore::new(shared.client.clone())),
        observer: metrics as _,
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
    }))
}
