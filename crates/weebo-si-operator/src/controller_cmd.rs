//! `weebo-si-operator controller` — the composition root for the controller role.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use weebo_si_controller::{LeaderElection, NetworkProfilesDeps};
use weebo_si_crd::NamespaceName;
use weebo_si_network_profiles::NetworkProfiles;
use weebo_si_runtime::{
    DEFAULT_CANARY_IMAGE, KubeCanary, KubeCapabilities, KubeConfigStore, KubeDwocStore,
    KubeNsStore, KubePolicyStore, KubeTemplateStore, NetworkMetrics,
};

use crate::cli::{flag, has_flag};
use crate::observability::{self, Ready};

const DEFAULT_LEASE_NAMESPACE: &str = "default";
const DEFAULT_HOLDER_ID: &str = "not-a-pod";

/// Run the controller role until the process is asked to stop.
pub async fn run(args: &[String]) -> Result<(), String> {
    let metrics_addr: SocketAddr = flag(args, "--metrics-addr")
        .unwrap_or("0.0.0.0:8080")
        .parse()
        .map_err(|err| format!("invalid --metrics-addr: {err}"))?;
    let health_addr: SocketAddr = flag(args, "--health-addr")
        .unwrap_or("0.0.0.0:8081")
        .parse()
        .map_err(|err| format!("invalid --health-addr: {err}"))?;

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

    let prometheus_registry = prometheus::Registry::new();
    let config_store = Arc::new(
        KubeConfigStore::spawn(
            client.clone(),
            &prometheus_registry,
            Arc::clone(&ns_store),
            annotation_key,
            Arc::clone(&dwoc_store),
            capabilities,
        )
        .await
        .map_err(|err| format!("could not start the WeeboSiConfig watch: {err}"))?,
    );

    let templates = Arc::new(
        KubeTemplateStore::spawn(client.clone(), &operator_namespace, cilium_enabled)
            .await
            .map_err(|err| format!("could not start the policy template watch: {err}"))?,
    );
    let policy_store = Arc::new(
        KubePolicyStore::spawn(client.clone(), cilium_enabled)
            .await
            .map_err(|err| format!("could not start the managed-policy watch: {err}"))?,
    );

    let network_profiles_config = config_store.network_profiles_config();
    let feature = Arc::new(NetworkProfiles::new(
        Arc::clone(&network_profiles_config),
        config_store.resolved_backend(),
        templates,
    ));
    let network_metrics =
        Arc::new(NetworkMetrics::register(&prometheus_registry).map_err(|err| err.to_string())?);
    // The image is a flag rather than a constant so an air-gapped cluster can point it at its
    // own mirror without a rebuild — but it has a real default, because the CRD defaults
    // `enforcement.canary.enabled` to `true` and a canary that cannot start is a canary that
    // reports `unknown` forever.
    let canary_image = flag(args, "--canary-image").unwrap_or(DEFAULT_CANARY_IMAGE);
    let network_profiles = NetworkProfilesDeps {
        feature,
        config: network_profiles_config,
        gate: config_store.clone(),
        namespace_view: ns_store as _,
        dwoc_catalog: dwoc_store as _,
        policy_store,
        observer: network_metrics as _,
        canary: Arc::new(KubeCanary::new(
            client.clone(),
            operator_namespace.clone(),
            canary_image,
        )),
        operator_namespace: NamespaceName::new(operator_namespace.clone()),
    };

    let ready = Ready::default();
    ready.mark_ready();
    tokio::spawn(observability::serve(
        health_addr,
        ready,
        prometheus_registry,
    ));

    let leader_election = has_flag(args, "--leader-election").then(|| LeaderElection {
        namespace: operator_namespace,
        holder_id: std::env::var("HOSTNAME").unwrap_or_else(|_| DEFAULT_HOLDER_ID.to_string()),
    });

    println!(
        "weebo-si-operator controller running (leader-election={}), metrics/health on {metrics_addr}/{health_addr}",
        leader_election.is_some()
    );
    weebo_si_controller::run(client, leader_election, Some(network_profiles)).await;
    Ok(())
}
