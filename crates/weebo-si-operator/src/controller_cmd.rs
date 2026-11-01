//! `weebo-si-operator controller` — the composition root for the controller role.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use weebo_si_controller::ControllerShared;
use weebo_si_kubearmor_policy_adapters::KubeArmorCapabilities;
use weebo_si_network_profiles_adapters::{DEFAULT_CANARY_IMAGE, KubeCapabilities};
use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore};

use crate::cli::{flag, has_flag};
use crate::observability;

const DEFAULT_LEASE_NAMESPACE: &str = "default";
const DEFAULT_HOLDER_ID: &str = "not-a-pod";

/// The `Lease` one controller replica holds at a time — the same name as before RFC 0012, so a
/// rolling upgrade hands over through it rather than running two leaders.
const LEASE_NAME: &str = "weebo-si-controller-leader";

/// Run the controller role until the process is asked to stop.
pub async fn run(args: &[String]) -> Result<(), String> {
    let telemetry = weebo_kit_runtime::telemetry::init("weebo-si-operator")
        .map_err(|err| format!("could not set up telemetry: {err}"))?;
    let result = reconcile(args).await;
    telemetry.shutdown();
    result
}

async fn reconcile(args: &[String]) -> Result<(), String> {
    let metrics_addr: SocketAddr = flag(args, "--metrics-addr")
        .unwrap_or("0.0.0.0:8080")
        .parse()
        .map_err(|err| format!("invalid --metrics-addr: {err}"))?;
    let health_addr: SocketAddr = flag(args, "--health-addr")
        .unwrap_or("0.0.0.0:8081")
        .parse()
        .map_err(|err| format!("invalid --health-addr: {err}"))?;

    // Health first, readiness last. The watches below each wait for their initial list, which on
    // a large cluster can take longer than a liveness probe's patience; serving `/healthz` from
    // the start means a slow start is a slow start, not a restart loop.
    let prometheus_registry = prometheus::Registry::new();
    let health = observability::health();
    weebo_si_runtime::watch::report_to(health.clone());
    tokio::spawn(observability::serve(
        health_addr,
        health.clone(),
        prometheus_registry.clone(),
    ));

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;

    // `POD_NAMESPACE`/`HOSTNAME` are the standard downward-API env vars a Deployment sets — the
    // manifest wires `POD_NAMESPACE` from `metadata.namespace` and `HOSTNAME` is set by the
    // kubelet to the pod name automatically. The fallbacks only matter outside a cluster, where
    // leader election is off by default anyway (single-replica local runs).
    let operator_namespace =
        std::env::var("POD_NAMESPACE").unwrap_or_else(|_| DEFAULT_LEASE_NAMESPACE.to_string());

    let annotation_key = Arc::new(RwLock::new(
        weebo_si_runtime::config_store::DEFAULT_ANNOTATION.to_string(),
    ));
    let ns_store = Arc::new(
        KubeNsStore::spawn(client.clone(), Arc::clone(&annotation_key))
            .await
            .map_err(|err| format!("could not start the Namespace watch: {err}"))?,
    );
    let dwoc_store =
        Arc::new(KubeDwocStore::spawn(client.clone()).await.map_err(|err| {
            format!("could not start the DevWorkspaceOperatorConfig watch: {err}")
        })?);
    let capabilities = Arc::new(
        KubeCapabilities::discover(client.clone())
            .await
            .map_err(|err| format!("could not discover apiserver capabilities: {err}"))?,
    );
    let cilium_enabled = weebo_si_network_profiles::Capabilities::offers(
        capabilities.as_ref(),
        weebo_si_crd::Backend::Cilium,
    );
    let runtime_capabilities = Arc::new(
        KubeArmorCapabilities::discover(client.clone())
            .await
            .map_err(|err| format!("could not discover KubeArmor capabilities: {err}"))?,
    );
    // Whether this cluster serves the `KubeArmorPolicy` CRD at all. Every `kubearmor-policy`
    // watch below is started only when it does: starting one without the CRD fails the initial
    // list, and a cluster without KubeArmor is a supported cluster — the feature simply never
    // runs there, which `weebo-si-operator backends kubearmor` reports and this line logs.
    let kubearmor_enabled = weebo_si_kubearmor_policy::Capabilities::offers(
        runtime_capabilities.as_ref(),
        weebo_si_crd::RuntimeBackend::KubeArmor,
    );

    let config_store = Arc::new(
        KubeConfigStore::spawn(
            client.clone(),
            &prometheus_registry,
            Arc::clone(&ns_store),
            annotation_key,
            Arc::clone(&dwoc_store),
            capabilities,
            Arc::clone(&runtime_capabilities) as _,
        )
        .await
        .map_err(|err| format!("could not start the WeeboSiConfig watch: {err}"))?,
    );

    // The image is a flag rather than a constant so an air-gapped cluster can point it at its
    // own mirror without a rebuild — but it has a real default, because the CRD defaults
    // `enforcement.canary.enabled` to `true` and a canary that cannot start is a canary that
    // reports `unknown` forever.
    let canary_image = flag(args, "--canary-image")
        .unwrap_or(DEFAULT_CANARY_IMAGE)
        .to_string();
    let quota_template_namespace = flag(args, "--quota-template-namespace")
        .unwrap_or(weebo_si_resource_quotas_adapters::DEFAULT_TEMPLATE_NAMESPACE)
        .to_string();
    let shared = ControllerShared {
        client: client.clone(),
        config_store,
        ns_store,
        dwoc_store,
        prometheus: prometheus_registry,
        recorder: weebo_si_controller::events::recorder(client.clone()),
        operator_namespace,
        cilium_enabled,
        kubearmor_enabled,
        canary_image,
        quota_template_namespace,
    };

    // Every feature's watches start here, before the lease, so a standby replica's caches are
    // warm when it takes over; its loops start only once it holds the lease (RFC 0012).
    let network_profiles = weebo_si_network_profiles_adapters::controller_deps(&shared).await?;
    let kubearmor_policy = weebo_si_kubearmor_policy_adapters::controller_deps(&shared).await?;
    let registry_config = weebo_si_registry_config_adapters::controller_deps(&shared).await?;
    let endpoint_auth = weebo_si_endpoint_auth_adapters::controller_deps(&shared).await?;
    let pod_security = weebo_si_pod_security_adapters::controller_deps(&shared).await?;
    let resource_quotas = weebo_si_resource_quotas_adapters::controller_deps(&shared).await?;
    let identity = weebo_si_identity_adapters::controller_deps(&shared)?;

    // `--metrics-addr` is parsed for the CLI contract's sake: metrics and probes share
    // `--health-addr` (see `observability::serve`).
    let _ = metrics_addr;
    health.set_ready(true);

    // A standby replica is ready — nothing routes to this role — and waits here, its caches warm,
    // until the lease is free. The kit exits the process (code 1) the moment the lease may be
    // lost, so no loop below ever runs on a replica that is not the leader.
    let leadership = if has_flag(args, "--leader-election") {
        let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| DEFAULT_HOLDER_ID.to_string());
        Some(weebo_kit_runtime::leader::acquire_leadership(&client, holder_id, LEASE_NAME).await)
    } else {
        None
    };

    tracing::info!(
        leader_election = leadership.is_some(),
        %health_addr,
        "controller running, metrics and probes on the health address"
    );
    let (client, recorder) = (&shared.client, &shared.recorder);
    weebo_si_network_profiles_adapters::controller::spawn(
        client.clone(),
        network_profiles,
        recorder.clone(),
    )
    .await;
    if let Some(deps) = kubearmor_policy {
        weebo_si_kubearmor_policy_adapters::controller::spawn(
            client.clone(),
            deps,
            recorder.clone(),
        )
        .await;
    }
    if let Some(deps) = registry_config {
        weebo_si_registry_config_adapters::controller::spawn(
            client.clone(),
            deps,
            recorder.clone(),
        )
        .await;
    }
    if let Some(deps) = endpoint_auth {
        weebo_si_endpoint_auth_adapters::controller::spawn(client.clone(), deps, recorder.clone())
            .await;
    }
    if let Some(deps) = resource_quotas {
        weebo_si_resource_quotas_adapters::controller::spawn(
            client.clone(),
            deps,
            recorder.clone(),
        )
        .await;
    }
    if let Some(deps) = pod_security {
        weebo_si_pod_security_adapters::controller::spawn(client.clone(), deps, recorder.clone())
            .await;
    }
    weebo_si_identity_adapters::controller::spawn(client.clone(), identity, recorder.clone()).await;
    weebo_si_controller::run(&shared).await;
    // Shutting down: hand the lease back so the next replica takes over now, not after its TTL.
    if let Some(leadership) = leadership {
        leadership.release().await;
    }
    Ok(())
}
