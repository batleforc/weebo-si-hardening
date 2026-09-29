//! `weebo-si-operator controller` — the composition root for the controller role.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use weebo_si_controller::{
    KubeArmorPolicyDeps, LeaderElection, NetworkProfilesDeps, RegistryConfigDeps,
};
use weebo_si_crd::NamespaceName;
use weebo_si_kubearmor_policy::KubeArmorPolicy;
use weebo_si_network_profiles::NetworkProfiles;
use weebo_si_registry_config::RegistryConfigFeature;
use weebo_si_runtime::{
    DEFAULT_CANARY_IMAGE, IdentityMetrics, KubeArmorCapabilities, KubeArmorMetrics,
    KubeArmorPolicyStore, KubeArmorTemplateStore, KubeCanary, KubeCapabilities, KubeConfigStore,
    KubeDwocStore, KubeNodeEnforcerView, KubeNsStore, KubePolicyStore, KubeProvisioner,
    KubeRegistryObjectStore, KubeRegistryTemplateStore, KubeTemplateStore, NetworkMetrics,
    RegistryMetrics,
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

    // Health first, readiness last. The watches below each wait for their initial list, which on
    // a large cluster can take longer than a liveness probe's patience; serving `/healthz` from
    // the start means a slow start is a slow start, not a restart loop.
    let prometheus_registry = prometheus::Registry::new();
    let ready = Ready::default();
    tokio::spawn(observability::serve(
        health_addr,
        ready.clone(),
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
        namespace_view: Arc::clone(&ns_store) as _,
        dwoc_catalog: Arc::clone(&dwoc_store) as _,
        policy_store,
        observer: network_metrics as _,
        canary: Arc::new(KubeCanary::new(
            client.clone(),
            operator_namespace.clone(),
            canary_image,
        )),
        operator_namespace: NamespaceName::new(operator_namespace.clone()),
    };

    // `None` on a cluster with no KubeArmor CRD: the loops are never started, rather than
    // started and failing every pass. RFC 0006's *Bypass* asks for the gap to be visible, and a
    // startup line plus `backends kubearmor` is where that visibility lives — a metric would
    // imply the feature is running.
    let kubearmor_policy = if kubearmor_enabled {
        let kubearmor_templates = Arc::new(
            KubeArmorTemplateStore::spawn(client.clone(), &operator_namespace)
                .await
                .map_err(|err| {
                    format!("could not start the KubeArmorPolicy template watch: {err}")
                })?,
        );
        let kubearmor_store = Arc::new(
            KubeArmorPolicyStore::spawn(client.clone())
                .await
                .map_err(|err| {
                    format!("could not start the managed-KubeArmorPolicy watch: {err}")
                })?,
        );
        let node_enforcer = Arc::new(
            KubeNodeEnforcerView::spawn(client.clone())
                .await
                .map_err(|err| {
                    format!("could not start the pod/node enforcement watches: {err}")
                })?,
        );
        let kubearmor_config = config_store.kubearmor_policy_config();
        let kubearmor_feature = Arc::new(KubeArmorPolicy::new(
            Arc::clone(&kubearmor_config),
            config_store.resolved_runtime_backend(),
            kubearmor_templates,
        ));
        let kubearmor_metrics = Arc::new(
            KubeArmorMetrics::register(&prometheus_registry).map_err(|err| err.to_string())?,
        );
        Some(KubeArmorPolicyDeps {
            feature: kubearmor_feature,
            config: kubearmor_config,
            gate: config_store.clone(),
            namespace_view: Arc::clone(&ns_store) as _,
            dwoc_catalog: Arc::clone(&dwoc_store) as _,
            policy_store: Arc::clone(&kubearmor_store) as _,
            node_enforcer: Arc::clone(&node_enforcer) as _,
            enforcement_subjects: node_enforcer as _,
            observer: kubearmor_metrics as _,
            operator_namespace: NamespaceName::new(operator_namespace.clone()),
        })
    } else {
        println!(
            "weebo-si-operator controller: kubearmor-policy is inert — this cluster does not \
             serve the KubeArmorPolicy CRD"
        );
        None
    };

    // RFC 0007's `registry-config`. `ConfigMap` and `Secret` are core resources every apiserver
    // serves, so the question here is not the cluster's but the chart's: the read on them is
    // granted only behind `registryConfig.rbac.enabled`, and a watch without it would retry a
    // `403` forever and never let this process finish starting. Without the grant the loop is
    // not wired at all, like `kubearmor-policy` on a cluster without the CRD.
    let registry_config = if registry_watchable(&client)
        .await
        .map_err(|err| format!("could not ask whether registry-config may watch: {err}"))?
    {
        Some(
            registry_config_deps(
                &client,
                &config_store,
                &ns_store,
                &dwoc_store,
                &prometheus_registry,
                &operator_namespace,
            )
            .await?,
        )
    } else {
        println!(
            "weebo-si-operator controller: registry-config is inert — this ServiceAccount may \
             not watch configmaps and secrets (set registryConfig.rbac.enabled in the chart)"
        );
        None
    };

    // RFC 0009's sweep: it covers the routing objects that existed before the feature was
    // switched on, puts the annotations back when anything strips them, and owns the one shared
    // Traefik `Middleware` every gated Ingress names. Constructed unconditionally and inert
    // until `spec.features.endpointAuth` exists, like the admission half — but only started
    // when this ServiceAccount may watch `ingresses` (`endpointAuth.rbac.enabled`), for the
    // reason `registry-config` gives above.
    let endpoint_auth = if weebo_si_runtime::access::can_watch(
        &client,
        "networking.k8s.io",
        "ingresses",
        None,
    )
    .await
    .map_err(|err| format!("could not ask whether endpoint-auth may watch ingresses: {err}"))?
    {
        Some(weebo_si_controller::EndpointAuthDeps {
            config: config_store.endpoint_auth_config(),
            gate: config_store.clone(),
            operator_namespace: NamespaceName::new(operator_namespace.clone()),
        })
    } else {
        println!(
            "weebo-si-operator controller: endpoint-auth's sweep is inert — this ServiceAccount \
             may not watch ingresses (set endpointAuth.rbac.enabled in the chart)"
        );
        None
    };

    // RFC 0011's `identity`.
    // RFC 0011's `identity`. Constructed unconditionally and inert until
    // `spec.features.identity` exists: the two loops still report team and user status, and
    // neither provisioner is called at all while the feature is absent or `Off`. Both handles
    // discover their kind lazily, so a cluster that installs the Authentik operator or Argo CD
    // later starts provisioning without a restart.
    let identity_metrics =
        IdentityMetrics::register(&prometheus_registry).map_err(|err| err.to_string())?;
    let identity = weebo_si_controller::IdentityDeps {
        config: config_store.identity_config(),
        authentik: Arc::new(KubeProvisioner::authentik_user(client.clone())) as _,
        workspace: Arc::new(KubeProvisioner::argo_application(client.clone())) as _,
        observer: Arc::new(identity_metrics) as _,
    };

    ready.mark_ready();

    let leader_election = has_flag(args, "--leader-election").then(|| LeaderElection {
        namespace: operator_namespace,
        holder_id: std::env::var("HOSTNAME").unwrap_or_else(|_| DEFAULT_HOLDER_ID.to_string()),
    });

    println!(
        "weebo-si-operator controller running (leader-election={}), metrics/health on {metrics_addr}/{health_addr}",
        leader_election.is_some()
    );
    weebo_si_controller::run(
        client,
        leader_election,
        Some(network_profiles),
        kubearmor_policy,
        registry_config,
        endpoint_auth,
        Some(identity),
    )
    .await;
    Ok(())
}

/// Whether this ServiceAccount may watch both kinds `registry-config` copies, cluster-wide. An
/// error asking is an error, not a "no" — see `weebo_si_runtime::access`.
async fn registry_watchable(client: &kube::Client) -> Result<bool, kube::Error> {
    Ok(
        weebo_si_runtime::access::can_watch(client, "", "configmaps", None).await?
            && weebo_si_runtime::access::can_watch(client, "", "secrets", None).await?,
    )
}

/// Start `registry-config`'s two watches and assemble what its loop needs.
async fn registry_config_deps(
    client: &kube::Client,
    config_store: &Arc<KubeConfigStore>,
    ns_store: &Arc<KubeNsStore>,
    dwoc_store: &Arc<KubeDwocStore>,
    prometheus_registry: &prometheus::Registry,
    operator_namespace: &str,
) -> Result<RegistryConfigDeps, String> {
    let registry_config_handle = config_store.registry_config();
    let registry_templates = Arc::new(
        KubeRegistryTemplateStore::spawn(client.clone(), operator_namespace)
            .await
            .map_err(|err| format!("could not start the registry template watch: {err}"))?,
    );
    let registry_store = Arc::new(
        KubeRegistryObjectStore::spawn(client.clone())
            .await
            .map_err(|err| format!("could not start the managed-registry-object watch: {err}"))?,
    );
    let registry_metrics =
        Arc::new(RegistryMetrics::register(prometheus_registry).map_err(|err| err.to_string())?);
    Ok(RegistryConfigDeps {
        feature: Arc::new(RegistryConfigFeature::new(
            Arc::clone(&registry_config_handle),
            registry_templates,
        )),
        config: registry_config_handle,
        gate: config_store.clone(),
        namespace_view: Arc::clone(ns_store) as _,
        dwoc_catalog: Arc::clone(dwoc_store) as _,
        object_store: registry_store as _,
        observer: registry_metrics as _,
        operator_namespace: NamespaceName::new(operator_namespace.to_string()),
    })
}
