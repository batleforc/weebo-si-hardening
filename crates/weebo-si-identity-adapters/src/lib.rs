//! The `identity` feature's adapters (RFC 0012): what talks to the cluster on its behalf —
//! its watch-backed stores, its metrics, its admission routes and its reconcile loops — next to
//! the composition functions `weebo-si-operator` calls. The decisions themselves stay in
//! `weebo-si-identity`, which still depends on `weebo-si-chassis` and `weebo-si-crd` only.

pub mod controller;
pub mod identity_metrics;
pub mod kube_provisioner;

pub use controller::{IdentityDeps, reconcile_team, reconcile_user};
pub use identity_metrics::IdentityMetrics;
pub use kube_provisioner::{ARGO_GROUP, AUTHENTIK_GROUP, KubeProvisioner, OWNER_API_VERSION};

use std::sync::Arc;

use weebo_si_controller::ControllerShared;

/// Assemble what the team and user loops need. Inert until `spec.features.identity` exists: the
/// loops still report team and user status, and neither provisioner is called while the feature
/// is absent or `Off`. Both provisioners discover their kind lazily, so a cluster that installs
/// the Authentik operator or Argo CD later starts provisioning without a restart.
pub fn controller_deps(shared: &ControllerShared) -> Result<IdentityDeps, String> {
    let metrics = IdentityMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?;
    Ok(IdentityDeps {
        config: shared.config_store.identity_config(),
        config_changes: shared.config_store.identity_changes(),
        authentik: Arc::new(KubeProvisioner::authentik_user(shared.client.clone())) as _,
        workspace: Arc::new(KubeProvisioner::argo_application(shared.client.clone())) as _,
        observer: Arc::new(metrics) as _,
    })
}
