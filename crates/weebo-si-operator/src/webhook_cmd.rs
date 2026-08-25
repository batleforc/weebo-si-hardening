//! `weebo-si-operator webhook` — the composition root for the admission webhook role. The only
//! place naming concrete adapters, per `docs/architecture/hexagonal.md`.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use weebo_si_chassis::Registry;
use weebo_si_crd::NamespaceName;
use weebo_si_dwoc_pin::{DwocPin, Workspace};
use weebo_si_network_profiles::{WorkspaceAdmission, WorkspaceGate};
use weebo_si_runtime::config_store::DEFAULT_ANNOTATION;
use weebo_si_runtime::{
    ImageMetrics, KubeArmorCapabilities, KubeCapabilities, KubeConfigStore, KubeDwocStore,
    KubeNsStore, KubePolicyStore, PrometheusObserver,
};
use weebo_si_webhook::{
    AppState, ImagePolicyState, NetworkProfilesAdmission, PolicyGuardState, RegistryGuardState,
};

use crate::cli::flag;
use crate::observability::{self, Ready};

/// Run the webhook role until the process is asked to stop.
pub async fn run(args: &[String]) -> Result<(), String> {
    let addr: SocketAddr = flag(args, "--addr")
        .unwrap_or("0.0.0.0:9443")
        .parse()
        .map_err(|err| format!("invalid --addr: {err}"))?;
    let cert_dir = flag(args, "--cert-dir")
        .unwrap_or("/etc/webhook/certs")
        .to_string();
    let metrics_addr: SocketAddr = flag(args, "--metrics-addr")
        .unwrap_or("0.0.0.0:8080")
        .parse()
        .map_err(|err| format!("invalid --metrics-addr: {err}"))?;
    let health_addr: SocketAddr = flag(args, "--health-addr")
        .unwrap_or("0.0.0.0:8081")
        .parse()
        .map_err(|err| format!("invalid --health-addr: {err}"))?;
    // The controller's own `system:serviceaccount:<ns>:<name>` identity — `policy-guard`'s one
    // exemption. Passed explicitly (the Helm chart renders the exact string its own
    // ServiceAccount naming produces) rather than guessed here, per RFC 0004's *Operational
    // considerations*: "an identity-matching bug is a permanent self-lockout... the exemption
    // matches the service account's full name, which changes only when a manifest changes."
    let operator_identity = flag(args, "--operator-identity")
        .ok_or_else(|| {
            "--operator-identity is required (the controller's own identity)".to_string()
        })?
        .to_string();

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;

    // `annotation_key` is shared between `ns_store` (reader) and `config_store` (writer, on
    // every WeeboSiConfig sync) so `namespaceSelection.annotation` is hot-reloaded rather than
    // fixed at boot. `ns_store` and `dwoc_store` are built before `config_store` because
    // `config_store` needs both: the first for its own `namespaceSelector` rollout-scoping
    // check, the second for the `weebo_si_dwoc_pin_catalog_entries` gauge.
    let annotation_key = Arc::new(RwLock::new(DEFAULT_ANNOTATION.to_string()));
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
    // The webhook role never writes a `KubeArmorPolicy`, but `KubeConfigStore` resolves every
    // feature's backend on the one code path both roles share — so this role discovers it too
    // rather than the store growing a "sometimes absent" capability source.
    let runtime_capabilities = Arc::new(
        KubeArmorCapabilities::discover(client.clone())
            .await
            .map_err(|err| format!("could not discover KubeArmor capabilities: {err}"))?,
    );
    // This role's own namespace, for `network-profiles`' structural exclusion — the webhook has
    // to reach the same verdict the controller does about which namespaces will never get a
    // baseline, or it would refuse every workspace in them forever.
    let operator_namespace =
        std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "weebo-si-hardening".to_string());

    let prometheus_registry = prometheus::Registry::new();

    let config_store = Arc::new(
        KubeConfigStore::spawn(
            client.clone(),
            &prometheus_registry,
            Arc::clone(&ns_store),
            Arc::clone(&annotation_key),
            Arc::clone(&dwoc_store),
            capabilities,
            runtime_capabilities,
        )
        .await
        .map_err(|err| format!("could not start the WeeboSiConfig watch: {err}"))?,
    );

    let observer =
        Arc::new(PrometheusObserver::new(&prometheus_registry).map_err(|err| err.to_string())?);
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .map_err(|err| err.to_string())?;

    // Registered unconditionally: `DwocPin` shares the *same* live `Arc` the config-cache
    // adapter keeps current, so a `spec.features.dwocPin` block that is absent at boot and
    // added later is picked up without a restart — `FeatureGate::mode` already reports `Off`
    // for it until then, so `evaluate()` is simply never called in the meantime.
    let mut dwoc_pin_registry: Registry<Workspace> = Registry::new();
    dwoc_pin_registry.register(DwocPin::new(config_store.dwoc_pin_config()));

    // `network-profiles`' admission half. It needs the *managed-policy* watch — the same one the
    // controller reconciles against — to answer "does this namespace have its baseline yet".
    // Read-only here: the webhook role holds `BaselineView`, not `PolicyStore`, so nothing on
    // this path can write, matching RFC 0002's split of the two roles' permissions.
    let baselines = Arc::new(
        KubePolicyStore::spawn(client.clone(), cilium_enabled)
            .await
            .map_err(|err| format!("could not start the managed-policy watch: {err}"))?,
    );
    let mut workspace_gate_registry: Registry<WorkspaceAdmission> = Registry::new();
    workspace_gate_registry.register(WorkspaceGate::new(
        config_store.network_profiles_config(),
        baselines as _,
        NamespaceName::new(operator_namespace),
    ));

    let dwoc_pin_state = Arc::new(AppState {
        registry: dwoc_pin_registry,
        network_profiles: Some(NetworkProfilesAdmission {
            registry: workspace_gate_registry,
            config: config_store.network_profiles_config(),
        }),
        gate: config_store.clone(),
        namespace_view: Arc::clone(&ns_store) as _,
        dwoc_catalog: Arc::clone(&dwoc_store) as _,
        observer: Arc::clone(&observer) as _,
        metrics: metrics.clone(),
    });
    let policy_guard_state = Arc::new(PolicyGuardState {
        operator_identity: operator_identity.clone(),
        policy_guard_config: config_store.policy_guard_config(),
        gate: config_store.clone(),
        namespace_view: Arc::clone(&ns_store) as _,
        dwoc_catalog: Arc::clone(&dwoc_store) as _,
        observer: Arc::clone(&observer) as _,
        metrics: metrics.clone(),
    });
    // The registry half of the same guard, per RFC 0007. Its own path and its own
    // `ValidatingWebhookConfiguration` rule (ownership `objectSelector`, `failurePolicy: Ignore`)
    // so the two can be enabled independently — but the *same* `policyGuard` configuration
    // handle, so one `mode` and one `allowedIdentities` govern both.
    let registry_guard_state = Arc::new(RegistryGuardState {
        operator_identity,
        policy_guard_config: config_store.policy_guard_config(),
        gate: config_store.clone(),
        namespace_view: Arc::clone(&ns_store) as _,
        dwoc_catalog: Arc::clone(&dwoc_store) as _,
        observer: Arc::clone(&observer) as _,
        metrics: metrics.clone(),
    });

    // `image-policy`'s two routes, per RFC 0005. Registered unconditionally, same as `dwoc-pin`
    // above and for the same reason: both features hold the *same* live `Arc` the config-cache
    // keeps current, so an `imagePolicy` block added after boot is picked up without a restart,
    // and `FeatureGate::mode` reports `Off` for it until then.
    //
    // **One `ImageMetrics`, one config handle, two registries.** The two enforcement points must
    // never disagree about the catalogue, and sharing the handle rather than reading the config
    // twice is what makes that structural.
    let image_metrics =
        ImageMetrics::register(&prometheus_registry).map_err(|err| err.to_string())?;
    let image_observer: Arc<dyn weebo_si_image_policy::ImagePolicyObserver> =
        Arc::new(image_metrics);
    let (workspace_registry, pod_registry) = weebo_si_webhook::registries(
        config_store.image_policy_config(),
        Arc::clone(&image_observer),
    );
    let image_policy_state = Arc::new(ImagePolicyState {
        config: config_store.image_policy_config(),
        workspace_registry,
        pod_registry,
        gate: config_store.clone(),
        namespace_view: ns_store as _,
        dwoc_catalog: dwoc_store as _,
        observer,
        image_observer,
        metrics,
    });

    let ready = Ready::default();
    ready.mark_ready();
    tokio::spawn(observability::serve(
        health_addr,
        ready,
        prometheus_registry,
    ));

    let app = weebo_si_webhook::router(dwoc_pin_state)
        .merge(weebo_si_webhook::policy_guard_router(policy_guard_state))
        .merge(weebo_si_webhook::registry_guard_router(
            registry_guard_state,
        ))
        .merge(weebo_si_webhook::image_policy_router(image_policy_state));
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        format!("{cert_dir}/tls.crt"),
        format!("{cert_dir}/tls.key"),
    )
    .await
    .map_err(|err| format!("could not load the serving certificate from {cert_dir}: {err}"))?;

    println!(
        "weebo-si-operator webhook listening on {addr}, metrics/health on {metrics_addr}/{health_addr}"
    );
    let _ = metrics_addr; // metrics and health are combined on health_addr; see observability::serve
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|err| format!("webhook server error: {err}"))
}
