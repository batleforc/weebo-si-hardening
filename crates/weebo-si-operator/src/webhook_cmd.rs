//! `weebo-si-operator webhook` — the composition root for the admission webhook role. The only
//! place naming concrete adapters, per `docs/architecture/hexagonal.md`.

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use weebo_si_chassis::Registry;
use weebo_si_dwoc_pin::{DwocPin, Workspace};
use weebo_si_runtime::config_store::DEFAULT_ANNOTATION;
use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore, PrometheusObserver};
use weebo_si_webhook::AppState;

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

    let prometheus_registry = prometheus::Registry::new();

    let config_store = KubeConfigStore::spawn(
        client.clone(),
        &prometheus_registry,
        Arc::clone(&ns_store),
        Arc::clone(&annotation_key),
        Arc::clone(&dwoc_store),
    )
    .await
    .map_err(|err| format!("could not start the WeeboSiConfig watch: {err}"))?;

    let observer = PrometheusObserver::new(&prometheus_registry).map_err(|err| err.to_string())?;
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .map_err(|err| err.to_string())?;

    // Registered unconditionally: `DwocPin` shares the *same* live `Arc` the config-cache
    // adapter keeps current, so a `spec.features.dwocPin` block that is absent at boot and
    // added later is picked up without a restart — `FeatureGate::mode` already reports `Off`
    // for it until then, so `evaluate()` is simply never called in the meantime.
    let mut registry: Registry<Workspace> = Registry::new();
    registry.register(DwocPin::new(config_store.dwoc_pin_config()));

    let state = Arc::new(AppState {
        registry,
        gate: Arc::new(config_store),
        namespace_view: ns_store,
        dwoc_catalog: dwoc_store,
        observer: Arc::new(observer),
        metrics,
    });

    let ready = Ready::default();
    ready.mark_ready();
    tokio::spawn(observability::serve(
        health_addr,
        ready,
        prometheus_registry,
    ));

    let app = weebo_si_webhook::router(state);
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
