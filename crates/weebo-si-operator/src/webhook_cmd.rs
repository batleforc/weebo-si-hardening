//! `weebo-si-operator webhook` — the composition root for the admission webhook role. The only
//! place naming concrete adapters, per `docs/architecture/hexagonal.md`.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use weebo_kit_runtime::Shutdown;
use weebo_kit_runtime::webhook_server::{self, MissingCertificate, WebhookServerConfig};
use weebo_si_chassis::Registry;
use weebo_si_crd::NamespaceName;
use weebo_si_dwoc_pin::{DwocPin, Workspace};
use weebo_si_kubearmor_policy_adapters::KubeArmorCapabilities;
use weebo_si_network_profiles::{WorkspaceAdmission, WorkspaceGate};
use weebo_si_network_profiles_adapters::{KubeCapabilities, KubePolicyStore};
use weebo_si_runtime::config_store::DEFAULT_ANNOTATION;
use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore, PrometheusObserver};
use weebo_si_webhook::{AdmissionShared, AppState, NetworkProfilesAdmission};

use crate::cli::flag;
use crate::observability;

/// Run the webhook role until the process is asked to stop.
pub async fn run(args: &[String]) -> Result<(), String> {
    let telemetry = weebo_kit_runtime::telemetry::init("weebo-si-operator")
        .map_err(|err| format!("could not set up telemetry: {err}"))?;
    let result = serve(args).await;
    telemetry.shutdown();
    result
}

async fn serve(args: &[String]) -> Result<(), String> {
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

    // Health first, readiness last — see the controller role for why. Readiness here also waits
    // for the serving certificate, since a pod that cannot terminate TLS is not one to route to.
    let prometheus_registry = prometheus::Registry::new();
    let health = observability::health();
    weebo_si_runtime::watch::report_to(health.clone());
    tokio::spawn(observability::serve(
        health_addr,
        health.clone(),
        prometheus_registry.clone(),
    ));
    let shutdown = Shutdown::on_termination()
        .map_err(|err| format!("could not install the signal handlers: {err}"))?;

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

    // Every other feature's routes, from its adapters crate (RFC 0012). Each is registered
    // unconditionally and inert until its `spec.features` block exists: the gate reports `Off`
    // until then, and each feature holds the same live config handle the cache keeps current, so
    // a block added after boot is picked up without a restart.
    let shared = AdmissionShared {
        config_store,
        ns_store,
        dwoc_store,
        observer,
        metrics,
        prometheus: prometheus_registry,
        operator_identity,
    };
    let app = weebo_si_webhook::router(dwoc_pin_state)
        .merge(weebo_si_policy_guard_adapters::admission_routes(&shared))
        .merge(weebo_si_image_policy_adapters::admission_routes(&shared)?)
        .merge(weebo_si_endpoint_auth_adapters::admission_routes(&shared))
        // An UPDATE review carries the object twice (`object` and `oldObject`), and the
        // apiserver accepts objects up to ~1.5 MiB — axum's 2 MiB default would answer a large
        // DevWorkspace update with a 413, which a `Fail` webhook turns into a refused write.
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REVIEW_BYTES));
    // `weebo-kit-runtime`'s server (RFC 0012): TLS with the certificate re-read every minute, so
    // a cert-manager or service-ca rotation is picked up before the old one expires; on SIGTERM,
    // `/readyz` fails first, the server keeps answering for `DRAIN_DELAY` while the endpoint
    // leaves the Service, then in-flight reviews finish; a review still running after 30 s gets
    // a 503. `Fail` on a missing certificate: this role sits behind `failurePolicy: Fail` rules,
    // and a pod ready without serving would refuse every write they cover.
    let config = WebhookServerConfig {
        addr,
        cert_file: format!("{cert_dir}/tls.crt").into(),
        key_file: format!("{cert_dir}/tls.key").into(),
        drain: DRAIN_DELAY,
        missing_certificate: MissingCertificate::Fail,
    };
    let server = webhook_server::spawn_with(config, app, health, shutdown)
        .await
        .map_err(|err| format!("could not serve the webhook from {cert_dir}: {err}"))?;
    tracing::info!(%addr, %health_addr, "webhook listening, metrics and probes on the health address");
    // `--metrics-addr` is parsed for the CLI contract's sake: metrics and probes share
    // `--health-addr` (see `observability::serve`).
    let _ = metrics_addr;
    server.stopped().await;
    Ok(())
}

/// The largest AdmissionReview body accepted: two copies of an object at the apiserver's own
/// ~1.5 MiB limit, plus the review's envelope.
const MAX_REVIEW_BYTES: usize = 4 * 1024 * 1024;

/// How long to keep answering after SIGTERM with `/readyz` already failing, so the endpoint is
/// removed from the Service before the listener closes.
const DRAIN_DELAY: Duration = Duration::from_secs(5);
