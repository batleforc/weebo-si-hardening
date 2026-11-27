//! The `team-tools` feature's adapters (RFC 0020): the template cache, the object store with its
//! per-tools-namespace watches and the `/scale` writer, one reconcile pass per subject, the loop
//! that runs them, the team status writer and the metrics.

pub mod controller;
pub mod kube_template_store;
pub mod kube_tool_store;
pub mod metrics;
pub mod objects;
pub mod port;
pub mod reconcile;
pub mod status;

pub use controller::TeamToolsDeps;
pub use kube_template_store::KubeToolTemplateStore;
pub use kube_tool_store::{KubeToolStore, Watch};
pub use metrics::TeamToolsMetrics;
pub use port::{Adoption, StoreError, ToolObjectStore};
pub use reconcile::{
    Converged, RequesterOutcome, ScaleWrite, ToolOutcome, WorkspaceOutcome, reconcile_requester,
    reconcile_tool, reconcile_workspace,
};

use std::sync::Arc;

use kube::api::GroupVersionKind;
use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_team_tools::TeamToolsFeature;

/// The clock the scale decision reads.
struct SystemClock;

impl weebo_si_team_tools::Clock for SystemClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

/// Start this feature's watches and assemble what its loop needs — `None` when this role may not
/// read the templates and the cluster-wide ConfigMaps (`teamTools.rbac.enabled` off).
pub async fn controller_deps(shared: &ControllerShared) -> Result<Option<TeamToolsDeps>, String> {
    let client = &shared.client;
    let template_namespace = NamespaceName::new(shared.team_tools_template_namespace.clone());
    let allowed = async {
        Ok::<bool, kube::Error>(
            weebo_si_runtime::access::can_watch(
                client,
                "apps",
                "statefulsets",
                Some(template_namespace.as_str()),
            )
            .await?
                && weebo_si_runtime::access::can_watch(client, "", "configmaps", None).await?,
        )
    }
    .await
    .map_err(|err| format!("could not ask whether team-tools may run: {err}"))?;
    if !allowed {
        tracing::info!(
            "team-tools is inert — this ServiceAccount may not read the tool templates and \
             ConfigMaps cluster-wide (set teamTools.rbac.enabled in the chart)"
        );
        return Ok(None);
    }
    // A cluster without cert-manager runs every other feature unchanged; entries with `tls`
    // simply fail their Certificate write there (RFC 0020, *Data and state*).
    let cert_manager = kube::discovery::pinned_kind(
        client,
        &GroupVersionKind::gvk("cert-manager.io", "v1", "Certificate"),
    )
    .await
    .is_ok();
    let templates = Arc::new(
        KubeToolTemplateStore::spawn(client.clone(), &template_namespace, shared.cilium_enabled)
            .await
            .map_err(|err| format!("could not start the team tool template watch: {err}"))?,
    );
    let store = Arc::new(
        KubeToolStore::spawn(client.clone(), shared.cilium_enabled, cert_manager)
            .await
            .map_err(|err| format!("could not start the team tool object watches: {err}"))?,
    );
    let metrics =
        Arc::new(TeamToolsMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?);
    let config = shared.config_store.team_tools_config();
    let operator_namespace = NamespaceName::new(shared.operator_namespace.clone());
    Ok(Some(TeamToolsDeps {
        feature: Arc::new(TeamToolsFeature::new(
            Arc::clone(&config),
            Arc::clone(&templates) as _,
            Arc::new(SystemClock),
            operator_namespace.clone(),
            template_namespace,
            // shortcut: the chart's `teamTools.allowedRuntimeClasses` (RFC default `[]`) is not
            // plumbed yet, so a template naming any runtimeClassName is invalid; add the value
            // and a flag when a tool needs a RuntimeClass.
            Vec::new(),
        )),
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        templates,
        store,
        metrics,
        operator_namespace,
        report: Arc::clone(&shared.team_tools_report),
    }))
}
