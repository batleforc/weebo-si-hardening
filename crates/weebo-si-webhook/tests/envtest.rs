//! The envtest tier, against a real ephemeral kube-apiserver — and, unlike `weebo-si-crd`'s and
//! `weebo-si-controller`'s suites, a **real running webhook** the apiserver calls back into
//! through a real `MutatingWebhookConfiguration`. This is the only tier that proves the whole
//! chain RFC 0002 describes: a `DevWorkspace`-shaped object is actually admitted, actually
//! routed to our server over TLS, actually resolved against a live `WeeboSiConfig`, and actually
//! patched — not just that the pieces individually do the right thing in isolation.
//!
//! We do not own the DevWorkspace CRD, so this suite installs a minimal stand-in fixture
//! (`tests/fixtures/devworkspace-crd.yaml`) rather than a hand-rolled typed binding — see that
//! file's own comment for why.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, RuleWithOperations, ServiceReference, WebhookClientConfig,
};
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{
    Api, DeleteParams, DynamicObject, GroupVersionKind, ObjectMeta, Patch, PatchParams, PostParams,
};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_chassis::Registry;
use weebo_si_crd::WeeboSiConfig;
use weebo_si_dwoc_pin::{DwocPin, Workspace};
use weebo_si_envtest_support::{EnvTest, free_port, generate_webhook_tls};
use weebo_si_runtime::{
    KubeCapabilities, KubeConfigStore, KubeDwocStore, KubeNsStore, PrometheusObserver,
};
use weebo_si_webhook::AppState;

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

const DEVWORKSPACE_CRD: &str = include_str!("fixtures/devworkspace-crd.yaml");
const DEVWORKSPACE_OPERATOR_CONFIG_CRD: &str =
    include_str!("fixtures/devworkspaceoperatorconfig-crd.yaml");

async fn install_crds(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    let devworkspace: CustomResourceDefinition =
        serde_yaml_bw::from_str(DEVWORKSPACE_CRD).expect("the fixture should parse");
    let devworkspace_operator_config: CustomResourceDefinition =
        serde_yaml_bw::from_str(DEVWORKSPACE_OPERATOR_CONFIG_CRD)
            .expect("the fixture should parse");
    let weebosiconfig = WeeboSiConfig::crd();

    for crd in [devworkspace, devworkspace_operator_config, weebosiconfig] {
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .unwrap_or_else(|err| panic!("installing {name} should succeed: {err}"));
        wait_established(&crds, &name).await;
    }
}

async fn wait_established(crds: &Api<CustomResourceDefinition>, name: &str) {
    for _ in 0..60 {
        if let Ok(crd) = crds.get(name).await {
            let established = crd
                .status
                .and_then(|status| status.conditions)
                .map(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                })
                .unwrap_or(false);
            if established {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("{name} never became established");
}

fn devworkspace_resource() -> kube::api::ApiResource {
    let gvk = GroupVersionKind::gvk("controller.devfile.io", "v1alpha1", "DevWorkspace");
    kube::api::ApiResource::from_gvk_with_plural(&gvk, "devworkspaces")
}

/// Boots the real production webhook stack — the runtime adapters, the registry with `DwocPin`
/// registered, and the axum router `weebo-si-operator`'s `main.rs` serves — against `env_test`,
/// then registers a real `MutatingWebhookConfiguration` pointing at it. Returns the port the
/// webhook listens on, for readiness polling.
async fn start_webhook(env_test: &EnvTest, cert_dir: &std::path::Path) -> u16 {
    let client = env_test.client().expect("client should build");

    let annotation_key = Arc::new(std::sync::RwLock::new(
        "hardening.weebo.io/dwoc".to_string(),
    ));
    let ns_store = Arc::new(
        KubeNsStore::spawn(client.clone(), Arc::clone(&annotation_key))
            .await
            .expect("namespace store should start"),
    );
    let dwoc_store = Arc::new(
        KubeDwocStore::spawn(client.clone())
            .await
            .expect("dwoc store should start"),
    );

    let capabilities = Arc::new(
        KubeCapabilities::discover(client.clone())
            .await
            .expect("capabilities discovery should succeed"),
    );
    let prometheus_registry = prometheus::Registry::new();
    let config_store = KubeConfigStore::spawn(
        client.clone(),
        &prometheus_registry,
        Arc::clone(&ns_store),
        annotation_key,
        Arc::clone(&dwoc_store),
        capabilities,
    )
    .await
    .expect("config store should start");
    let observer = PrometheusObserver::new(&prometheus_registry).expect("observer should register");
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .expect("metrics should register");

    let mut registry: Registry<Workspace> = Registry::new();
    registry.register(DwocPin::new(config_store.dwoc_pin_config()));

    let state = Arc::new(AppState {
        registry,
        // `dwoc-pin`'s own scenarios below run without `network-profiles`' gate in the way —
        // RFC 0004's admission half has its own suite at the bottom of this file.
        network_profiles: None,
        gate: Arc::new(config_store),
        namespace_view: ns_store,
        dwoc_catalog: dwoc_store,
        observer: Arc::new(observer),
        metrics,
    });

    let (key_path, cert_path) =
        generate_webhook_tls(cert_dir).expect("cert generation should succeed");
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("tls config should load");

    let port = free_port().expect("a free port should be available");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("addr should parse");
    let app = weebo_si_webhook::router(state);
    tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await;
    });

    let ca_bundle =
        weebo_si_envtest_support::read_ca_bundle(&cert_path).expect("cert should be readable");

    let webhooks_api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let webhook_config = MutatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-devworkspaces-envtest".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![
            k8s_openapi::api::admissionregistration::v1::MutatingWebhook {
                name: "devworkspaces.hardening.weebo.io".to_string(),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: "None".to_string(),
                match_policy: Some("Equivalent".to_string()),
                failure_policy: Some("Fail".to_string()),
                timeout_seconds: Some(5),
                reinvocation_policy: Some("IfNeeded".to_string()),
                rules: Some(vec![RuleWithOperations {
                    operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                    api_groups: Some(vec!["controller.devfile.io".to_string()]),
                    api_versions: Some(vec!["v1alpha1".to_string()]),
                    resources: Some(vec!["devworkspaces".to_string()]),
                    scope: Some("Namespaced".to_string()),
                }]),
                client_config: WebhookClientConfig {
                    url: Some(format!(
                        "https://127.0.0.1:{port}/mutate/v1alpha1/devworkspaces"
                    )),
                    ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                    service: None::<ServiceReference>,
                },
                ..Default::default()
            },
        ]),
    };
    webhooks_api
        .create(&PostParams::default(), &webhook_config)
        .await
        .expect("webhook configuration should be accepted");

    port
}

async fn wait_for_namespace_synced(client: kube::Client, name: &str) {
    let namespaces: Api<Namespace> = Api::all(client);
    for _ in 0..40 {
        if namespaces.get(name).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn devworkspace(namespace: &str, name: &str) -> DynamicObject {
    let mut obj = DynamicObject::new(name, &devworkspace_resource());
    obj.metadata.namespace = Some(namespace.to_string());
    obj.data = serde_json::json!({"spec": {"started": true, "template": {}}});
    obj
}

/// Retries a DevWorkspace create until the webhook is actually routing (the apiserver may need a
/// moment to pick up the freshly-registered `MutatingWebhookConfiguration`).
async fn create_with_retry(api: &Api<DynamicObject>, obj: &DynamicObject) -> DynamicObject {
    let mut last_err = None;
    for _ in 0..40 {
        match api.create(&PostParams::default(), obj).await {
            Ok(created) => return created,
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    panic!("create never succeeded: {last_err:?}");
}

/// Creates the singleton `WeeboSiConfig` named `cluster` from a raw `spec` — every scenario test
/// below builds its own `spec`, so the boilerplate around it (apiVersion/kind/metadata) is
/// factored out here rather than repeated per test.
async fn create_config(client: kube::Client, spec: serde_json::Value) {
    let config_api: Api<WeeboSiConfig> = Api::all(client);
    let value = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": spec,
    });
    config_api
        .create(
            &PostParams::default(),
            &serde_json::from_value(value).expect("resource should deserialize"),
        )
        .await
        .expect("config should be accepted");
}

/// Creates a namespace, waits for it to be visible to the watch-backed namespace cache, and
/// applies any labels/annotations relevant to team matching or `namespaceSelection.annotation`.
async fn create_namespace(
    client: kube::Client,
    name: &str,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
) {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: (!labels.is_empty()).then_some(labels),
            annotations: (!annotations.is_empty()).then_some(annotations),
            ..Default::default()
        },
        ..Default::default()
    };
    namespaces
        .create(&PostParams::default(), &namespace)
        .await
        .expect("namespace should be created");
    wait_for_namespace_synced(client, name).await;
}

/// Creates a `DevWorkspaceOperatorConfig`-shaped target in `namespace`, catalogued as `name` —
/// the fixture the `dwoc-pin` feature resolves catalogue keys against.
async fn create_target(client: kube::Client, namespace: &str, name: &str) {
    let dwoc_resource = weebo_si_runtime::dwoc_store::devworkspace_operator_config_resource();
    let dwocs: Api<DynamicObject> = Api::namespaced_with(client, namespace, &dwoc_resource);
    let mut target = DynamicObject::new(name, &dwoc_resource);
    target.metadata.namespace = Some(namespace.to_string());
    target.data = serde_json::json!({});
    dwocs
        .create(&PostParams::default(), &target)
        .await
        .expect("target DWOC should be created");
}

/// The headline check: a live apiserver, calling back into a live webhook over TLS, actually
/// pins a `DevWorkspace` — the attribute and the audit annotation both land.
#[tokio::test]
async fn a_devworkspace_is_pinned_by_a_real_running_webhook() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;

    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    let config_api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": {
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        },
    });
    config_api
        .create(
            &PostParams::default(),
            &serde_json::from_value(spec).expect("resource should deserialize"),
        )
        .await
        .expect("config should be accepted");

    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some("user-alice".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    namespaces
        .create(&PostParams::default(), &namespace)
        .await
        .expect("namespace should be created");
    wait_for_namespace_synced(client.clone(), "user-alice").await;
    // The DWOC target does not need to exist for `onMissingTarget: Skip` (the config's default)
    // — but with no live catalog cache entries `dwoc_catalog().resolves()` reports `false` for
    // everything, which would make every admission a no-op `target_missing`. Give the watch a
    // moment regardless; `KubeDwocStore` waits for its own initial sync at construction, so a
    // real target only matters if `onMissingTarget: Deny` is set, which this test does not use —
    // Skip means the mutation is simply omitted rather than the test failing outright, so create
    // the target DWOC-stand-in for a real pin instead of relying on Skip's leniency.
    let dwoc_resource = weebo_si_runtime::dwoc_store::devworkspace_operator_config_resource();
    let dwocs: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "eclipse-che", &dwoc_resource);
    let _ = namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some("eclipse-che".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await;
    wait_for_namespace_synced(client.clone(), "eclipse-che").await;
    let mut target = DynamicObject::new("weebo-hardened-config", &dwoc_resource);
    target.metadata.namespace = Some("eclipse-che".to_string());
    target.data = serde_json::json!({});
    dwocs
        .create(&PostParams::default(), &target)
        .await
        .expect("target DWOC should be created");
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-alice", &devworkspace_resource());
    let created =
        create_with_retry(&devworkspaces, &devworkspace("user-alice", "python-web")).await;

    assert_eq!(
        created.data["spec"]["template"]["attributes"]["controller.devfile.io/devworkspace-config"]
            ["name"],
        serde_json::json!("weebo-hardened-config"),
        "the DevWorkspace should have been pinned: {:#?}",
        created.data
    );
    let audit_annotation = created
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("hardening.weebo.io/dwoc-pin"))
        .cloned()
        .unwrap_or_default();
    assert!(
        audit_annotation.starts_with("added;"),
        "the audit annotation should record the pin, got: {audit_annotation:?}"
    );

    let _ = devworkspaces
        .delete("python-web", &DeleteParams::default())
        .await;
}

/// `failurePolicy: Fail`: with the webhook unreachable, admission is refused rather than
/// silently passing the object through.
#[tokio::test]
async fn an_unreachable_webhook_fails_closed() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;

    // Register a `MutatingWebhookConfiguration` pointing at a port nothing listens on.
    let dead_port = free_port().expect("a free port should be available");
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let (_key, cert) =
        generate_webhook_tls(cert_dir.path()).expect("cert generation should succeed");
    let ca_bundle =
        weebo_si_envtest_support::read_ca_bundle(&cert).expect("cert should be readable");

    let webhooks_api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let webhook_config = MutatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-devworkspaces-dead".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![
            k8s_openapi::api::admissionregistration::v1::MutatingWebhook {
                name: "devworkspaces.hardening.weebo.io".to_string(),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: "None".to_string(),
                failure_policy: Some("Fail".to_string()),
                timeout_seconds: Some(2),
                rules: Some(vec![RuleWithOperations {
                    operations: Some(vec!["CREATE".to_string()]),
                    api_groups: Some(vec!["controller.devfile.io".to_string()]),
                    api_versions: Some(vec!["v1alpha1".to_string()]),
                    resources: Some(vec!["devworkspaces".to_string()]),
                    scope: Some("Namespaced".to_string()),
                }]),
                client_config: WebhookClientConfig {
                    url: Some(format!(
                        "https://127.0.0.1:{dead_port}/mutate/v1alpha1/devworkspaces"
                    )),
                    ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                    service: None::<ServiceReference>,
                },
                ..Default::default()
            },
        ]),
    };
    webhooks_api
        .create(&PostParams::default(), &webhook_config)
        .await
        .expect("webhook configuration should be accepted");

    let namespaces: Api<Namespace> = Api::all(client.clone());
    namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some("user-bob".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .expect("namespace should be created");

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-bob", &devworkspace_resource());
    let mut last_err = None;
    let mut denied = false;
    for _ in 0..40 {
        match devworkspaces
            .create(
                &PostParams::default(),
                &devworkspace("user-bob", "should-fail"),
            )
            .await
        {
            Ok(_) => break,
            Err(err) => {
                if err.to_string().to_lowercase().contains("webhook")
                    || err.to_string().to_lowercase().contains("dial")
                {
                    denied = true;
                    break;
                }
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    assert!(
        denied,
        "expected the apiserver to refuse admission when the webhook is unreachable, last error: {last_err:?}"
    );
}

/// A `DevWorkspace` with a pre-existing `controller.devfile.io/devworkspace-config` attribute,
/// for the outcomes that depend on what the workspace already asked for.
fn devworkspace_with_ref(
    namespace: &str,
    name: &str,
    ref_name: &str,
    ref_namespace: &str,
) -> DynamicObject {
    let mut obj = DynamicObject::new(name, &devworkspace_resource());
    obj.metadata.namespace = Some(namespace.to_string());
    obj.data = serde_json::json!({
        "spec": {
            "started": true,
            "template": {
                "attributes": {
                    (weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE): {
                        "name": ref_name,
                        "namespace": ref_namespace,
                    }
                }
            }
        }
    });
    obj
}

fn audit_annotation(obj: &DynamicObject) -> Option<String> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get("hardening.weebo.io/dwoc-pin"))
        .cloned()
}

/// `mode: DryRun` runs the identical decision path as `Enforce` but discards the mutation — per
/// RFC 0002, "`DryRun` runs the identical code path... and discards the mutation." Proven live:
/// the object comes back with neither the attribute nor the audit annotation.
#[tokio::test]
async fn dry_run_mode_leaves_the_devworkspace_unmutated() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "DryRun",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        }),
    )
    .await;
    create_namespace(
        client.clone(),
        "user-dryrun",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-dryrun", &devworkspace_resource());
    let created =
        create_with_retry(&devworkspaces, &devworkspace("user-dryrun", "dry-run-ws")).await;

    assert!(
        created.data.pointer("/spec/template/attributes").is_none(),
        "DryRun should not mutate the object: {:#?}",
        created.data
    );
    assert!(
        audit_annotation(&created).is_none(),
        "DryRun should not write the audit annotation"
    );

    let _ = devworkspaces
        .delete("dry-run-ws", &DeleteParams::default())
        .await;
}

/// Idempotence: an already-pinned workspace re-admitted (here, via a `spec.started` toggle —
/// exactly the update RFC 0002's *Rollout* worries about, since every reconcile of the owning
/// controller re-touches `started`) produces no further change — the `already_pinned` outcome,
/// not a second `replaced`.
#[tokio::test]
async fn a_started_toggle_on_an_already_pinned_workspace_is_a_no_op() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        }),
    )
    .await;
    create_namespace(
        client.clone(),
        "user-idem",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-idem", &devworkspace_resource());
    let created = create_with_retry(&devworkspaces, &devworkspace("user-idem", "idem-ws")).await;
    let first_annotation =
        audit_annotation(&created).expect("the first admission should pin and annotate");
    assert!(first_annotation.starts_with("added;"));

    let patched = devworkspaces
        .patch(
            "idem-ws",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"spec": {"started": false}})),
        )
        .await
        .expect("the started toggle should be admitted");

    assert_eq!(
        patched.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("weebo-hardened-config"),
        "already_pinned must not disturb the existing attribute"
    );
    assert_eq!(
        audit_annotation(&patched),
        Some(first_annotation),
        "already_pinned must not rewrite the audit annotation"
    );

    let _ = devworkspaces
        .delete("idem-ws", &DeleteParams::default())
        .await;
}

/// The `allowed_override` and `replaced` outcomes, live, against a real team grant: a workspace
/// naming an allowed-but-non-default key keeps it untouched, while one naming a key outside the
/// grant is replaced with the grant's default.
#[tokio::test]
async fn team_grants_drive_allowed_override_and_replaced_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "teams": [
                {"name": "team-1", "namespaceSelector": {"matchLabels": {"weebo.io/team": "team-1"}}},
            ],
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "gpu", "name": "gpu-config", "namespace": "eclipse-che"},
                        {"key": "amd", "name": "amd-config", "namespace": "eclipse-che"},
                    ],
                    "default": "baseline",
                    "grants": {
                        "team-1": {"allowed": ["baseline", "gpu"], "default": "baseline"},
                    },
                }
            }
        }),
    )
    .await;
    let mut labels = BTreeMap::new();
    labels.insert("weebo.io/team".to_string(), "team-1".to_string());
    create_namespace(client.clone(), "team-alpha", labels, BTreeMap::new()).await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;
    create_target(client.clone(), "eclipse-che", "gpu-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "team-alpha", &devworkspace_resource());

    // `gpu` is allowed but not the default: the workspace's own choice is kept as-is.
    let overridden = create_with_retry(
        &devworkspaces,
        &devworkspace_with_ref("team-alpha", "override-ws", "gpu-config", "eclipse-che"),
    )
    .await;
    assert_eq!(
        overridden.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("gpu-config"),
        "allowed_override must keep the workspace's own choice"
    );
    assert!(
        audit_annotation(&overridden).is_none(),
        "allowed_override makes no mutation, so it writes no audit annotation"
    );

    // `amd` is outside team-1's grant: the workspace's choice is replaced with the default.
    let replaced = create_with_retry(
        &devworkspaces,
        &devworkspace_with_ref("team-alpha", "replace-ws", "amd-config", "eclipse-che"),
    )
    .await;
    assert_eq!(
        replaced.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("weebo-hardened-config"),
        "replaced must fall back to the grant's default"
    );
    let replaced_annotation =
        audit_annotation(&replaced).expect("replaced must write the audit annotation");
    assert!(
        replaced_annotation.starts_with("replaced:eclipse-che/amd-config"),
        "unexpected audit annotation: {replaced_annotation:?}"
    );

    let _ = devworkspaces
        .delete("override-ws", &DeleteParams::default())
        .await;
    let _ = devworkspaces
        .delete("replace-ws", &DeleteParams::default())
        .await;
}

/// `spec.teams` is ordered and first-match-wins — proven live against two teams whose selectors
/// both match the same namespace.
#[tokio::test]
async fn two_teams_matching_the_same_namespace_the_first_declared_wins_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "teams": [
                {"name": "team-1", "namespaceSelector": {"matchLabels": {"weebo.io/team": "shared"}}},
                {"name": "team-2", "namespaceSelector": {"matchLabels": {"weebo.io/team": "shared"}}},
            ],
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "gpu", "name": "gpu-config", "namespace": "eclipse-che"},
                        {"key": "amd", "name": "amd-config", "namespace": "eclipse-che"},
                    ],
                    "default": "baseline",
                    "grants": {
                        "team-1": {"allowed": ["gpu"], "default": "gpu"},
                        "team-2": {"allowed": ["amd"], "default": "amd"},
                    },
                }
            }
        }),
    )
    .await;
    let mut labels = BTreeMap::new();
    labels.insert("weebo.io/team".to_string(), "shared".to_string());
    create_namespace(client.clone(), "shared-ns", labels, BTreeMap::new()).await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "gpu-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "shared-ns", &devworkspace_resource());
    let created = create_with_retry(&devworkspaces, &devworkspace("shared-ns", "shared-ws")).await;

    assert_eq!(
        created.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("gpu-config"),
        "team-1, declared first, should have won: {:#?}",
        created.data
    );

    let _ = devworkspaces
        .delete("shared-ws", &DeleteParams::default())
        .await;
}

/// A namespace's `namespaceSelection.annotation` moving it to a key inside its team's `allowed`
/// set is honoured live, ahead of the grant's default.
#[tokio::test]
async fn a_namespace_annotation_inside_the_allowed_set_is_honoured_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "teams": [
                {"name": "team-2", "namespaceSelector": {"matchLabels": {"weebo.io/team": "team-2"}}},
            ],
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "amd", "name": "amd-config", "namespace": "eclipse-che"},
                    ],
                    "default": "baseline",
                    "grants": {
                        "team-2": {"allowed": ["baseline", "amd"], "default": "baseline"},
                    },
                }
            }
        }),
    )
    .await;
    let mut labels = BTreeMap::new();
    labels.insert("weebo.io/team".to_string(), "team-2".to_string());
    let mut annotations = BTreeMap::new();
    annotations.insert("hardening.weebo.io/dwoc".to_string(), "amd".to_string());
    create_namespace(client.clone(), "team-beta", labels, annotations).await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "amd-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "team-beta", &devworkspace_resource());
    let created =
        create_with_retry(&devworkspaces, &devworkspace("team-beta", "annotated-ws")).await;

    assert_eq!(
        created.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("amd-config"),
        "the namespace annotation should have picked amd: {:#?}",
        created.data
    );

    let _ = devworkspaces
        .delete("annotated-ws", &DeleteParams::default())
        .await;
}

/// `onUnknownKey: Deny` refuses admission live when the namespace annotation names a key outside
/// the reachable grant, rather than silently falling through to the default.
#[tokio::test]
async fn on_unknown_key_deny_refuses_admission_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "teams": [
                {"name": "team-2", "namespaceSelector": {"matchLabels": {"weebo.io/team": "team-2"}}},
            ],
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                    ],
                    "default": "baseline",
                    "grants": {
                        "team-2": {"allowed": ["baseline"], "default": "baseline"},
                    },
                    "namespaceSelection": {"onUnknownKey": "Deny"},
                }
            }
        }),
    )
    .await;
    let mut labels = BTreeMap::new();
    labels.insert("weebo.io/team".to_string(), "team-2".to_string());
    let mut annotations = BTreeMap::new();
    annotations.insert("hardening.weebo.io/dwoc".to_string(), "gpu".to_string());
    create_namespace(client.clone(), "team-deny", labels, annotations).await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "team-deny", &devworkspace_resource());

    let mut last_err = None;
    let mut denied = false;
    for _ in 0..40 {
        match devworkspaces
            .create(
                &PostParams::default(),
                &devworkspace("team-deny", "deny-ws"),
            )
            .await
        {
            Ok(_) => break,
            Err(err) => {
                if err.to_string().contains("outside this namespace's grant") {
                    denied = true;
                    break;
                }
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    assert!(
        denied,
        "expected onUnknownKey: Deny to refuse admission, last error: {last_err:?}"
    );
}

/// `onMissingTarget: Skip` (the default) makes no patch when the resolved catalogue entry does
/// not point at a live target — the workspace is admitted unchanged rather than denied.
#[tokio::test]
async fn on_missing_target_skip_admits_unmutated_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        }),
    )
    .await;
    create_namespace(
        client.clone(),
        "user-skip",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    // Deliberately no `create_target`: the catalogued entry never resolves.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-skip", &devworkspace_resource());
    let created = create_with_retry(&devworkspaces, &devworkspace("user-skip", "skip-ws")).await;

    assert!(
        created.data.pointer("/spec/template/attributes").is_none(),
        "target_missing under Skip must make no patch: {:#?}",
        created.data
    );

    let _ = devworkspaces
        .delete("skip-ws", &DeleteParams::default())
        .await;
}

/// `onMissingTarget: Deny` refuses admission live when the resolved catalogue entry does not
/// point at a live target.
#[tokio::test]
async fn on_missing_target_deny_refuses_admission_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                    "onMissingTarget": "Deny",
                }
            }
        }),
    )
    .await;
    create_namespace(
        client.clone(),
        "user-missing-deny",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        "user-missing-deny",
        &devworkspace_resource(),
    );

    let mut last_err = None;
    let mut denied = false;
    for _ in 0..40 {
        match devworkspaces
            .create(
                &PostParams::default(),
                &devworkspace("user-missing-deny", "missing-deny-ws"),
            )
            .await
        {
            Ok(_) => break,
            Err(err) => {
                if err.to_string().contains("does not exist") {
                    denied = true;
                    break;
                }
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    assert!(
        denied,
        "expected onMissingTarget: Deny to refuse admission, last error: {last_err:?}"
    );
}

/// A `spec.features.dwocPin` block that does not exist at boot, and is added later, is observed
/// by an already-running webhook pod with **no restart** — proving live what
/// `webhook_cmd.rs`'s own comment claims: `DwocPin` is registered unconditionally at boot,
/// sharing the same `Arc` the config-cache adapter writes, so `FeatureGate::mode` simply reports
/// `Off` (and `evaluate()` is never called) until the block exists, with no special-casing of
/// "never configured yet" as a state requiring a restart.
#[tokio::test]
async fn a_dwoc_pin_block_added_after_boot_is_observed_without_a_restart() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    // No `WeeboSiConfig` exists yet at this point — the webhook is already serving.
    start_webhook(&env_test, cert_dir.path()).await;

    create_namespace(
        client.clone(),
        "user-late-config",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-late-config", &devworkspace_resource());

    // Before any config exists, `dwoc-pin`'s mode is `Off`: admitted unchanged.
    let before = create_with_retry(
        &devworkspaces,
        &devworkspace("user-late-config", "before-config"),
    )
    .await;
    assert!(
        before.data.pointer("/spec/template/attributes").is_none(),
        "with no WeeboSiConfig at all, dwoc-pin must be Off: {:#?}",
        before.data
    );

    // Now the config appears — no restart, nothing re-registered.
    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let after = create_with_retry(
        &devworkspaces,
        &devworkspace("user-late-config", "after-config"),
    )
    .await;
    assert_eq!(
        after.data["spec"]["template"]["attributes"]
            [weebo_si_webhook::extract::CONFIG_REF_ATTRIBUTE]["name"],
        serde_json::json!("weebo-hardened-config"),
        "the same already-running pod should now pin, with no restart: {:#?}",
        after.data
    );

    let _ = devworkspaces
        .delete("before-config", &DeleteParams::default())
        .await;
    let _ = devworkspaces
        .delete("after-config", &DeleteParams::default())
        .await;
}

/// `devworkspaces/status` is not covered by the webhook's rule (only the parent `devworkspaces`
/// resource is) — proven live by patching the status subresource of an already-pinned workspace
/// and asserting the audit annotation (a `metadata` mutation the webhook would perform, never the
/// status controller) is untouched.
#[tokio::test]
async fn a_status_only_update_bypasses_the_webhook_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    start_webhook(&env_test, cert_dir.path()).await;

    create_config(
        client.clone(),
        serde_json::json!({
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        }),
    )
    .await;
    create_namespace(
        client.clone(),
        "user-status",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "eclipse-che",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_target(client.clone(), "eclipse-che", "weebo-hardened-config").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "user-status", &devworkspace_resource());
    let created =
        create_with_retry(&devworkspaces, &devworkspace("user-status", "status-ws")).await;
    let pinned_annotation =
        audit_annotation(&created).expect("the create should have pinned and annotated");

    let after_status = devworkspaces
        .patch_status(
            "status-ws",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": {"phase": "Running"}})),
        )
        .await
        .expect("the status-only update should be admitted without going through the webhook");

    assert_eq!(
        audit_annotation(&after_status),
        Some(pinned_annotation),
        "a status-only update must not re-trigger the webhook's mutation"
    );

    let _ = devworkspaces
        .delete("status-ws", &DeleteParams::default())
        .await;
}

/// Renders `charts/weebo-si-operator`'s real `MutatingWebhookConfiguration` template and returns
/// its `namespaceSelector` — RFC 0002's *Webhook configuration* documents this as the mechanism
/// protecting a namespace carrying `namespaceExclusionLabel` (the operator's own namespace, most
/// notably — see *Self-deadlock*), but that selector lives only in the Helm template, never in
/// Rust, so nothing before this test exercised the rendered value against a real apiserver.
fn chart_namespace_selector() -> k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
    let chart_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../charts/weebo-si-operator"
    );
    let output = std::process::Command::new("helm")
        .args([
            "template",
            "ci",
            chart_dir,
            "--namespace",
            "weebo-si-hardening",
            "--show-only",
            "templates/mutatingwebhookconfiguration.yaml",
        ])
        .output()
        .expect("helm must be on PATH to render charts/weebo-si-operator — see task helm:lint");
    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("helm output should be utf8");
    let config: MutatingWebhookConfiguration =
        serde_yaml_bw::from_str(&rendered).expect("the rendered manifest should parse");
    config
        .webhooks
        .expect("the rendered manifest should have one webhook")
        .into_iter()
        .next()
        .expect("the rendered manifest should have one webhook")
        .namespace_selector
        .expect("the rendered manifest should carry a namespaceSelector")
}

/// Registers the real, chart-rendered `namespaceSelector` pointed at a dead port — same trick as
/// `an_unreachable_webhook_fails_closed` above — so a `DevWorkspace`'s fate hinges purely on
/// whether the apiserver's own selector evaluation calls the webhook at all: a namespace carrying
/// the exclusion label must be admitted (the webhook is never reached), one without it must be
/// refused (fail-closed: reached, and nothing answers).
#[tokio::test]
async fn the_real_chart_namespace_selector_excludes_labelled_namespaces_live() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;

    let namespace_selector = chart_namespace_selector();
    let exclusion_label = namespace_selector
        .match_expressions
        .as_ref()
        .and_then(|exprs| exprs.first())
        .map(|expr| expr.key.clone())
        .expect("the rendered selector should name the exclusion label");

    let dead_port = free_port().expect("a free port should be available");
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let (_key, cert) =
        generate_webhook_tls(cert_dir.path()).expect("cert generation should succeed");
    let ca_bundle =
        weebo_si_envtest_support::read_ca_bundle(&cert).expect("cert should be readable");

    let webhooks_api: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    let webhook_config = MutatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-devworkspaces-selector".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![
            k8s_openapi::api::admissionregistration::v1::MutatingWebhook {
                name: "devworkspaces.hardening.weebo.io".to_string(),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: "None".to_string(),
                failure_policy: Some("Fail".to_string()),
                timeout_seconds: Some(2),
                namespace_selector: Some(namespace_selector),
                rules: Some(vec![RuleWithOperations {
                    operations: Some(vec!["CREATE".to_string()]),
                    api_groups: Some(vec!["controller.devfile.io".to_string()]),
                    api_versions: Some(vec!["v1alpha1".to_string()]),
                    resources: Some(vec!["devworkspaces".to_string()]),
                    scope: Some("Namespaced".to_string()),
                }]),
                client_config: WebhookClientConfig {
                    url: Some(format!(
                        "https://127.0.0.1:{dead_port}/mutate/v1alpha1/devworkspaces"
                    )),
                    ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                    service: None::<ServiceReference>,
                },
                ..Default::default()
            },
        ]),
    };
    webhooks_api
        .create(&PostParams::default(), &webhook_config)
        .await
        .expect("webhook configuration should be accepted");

    let mut excluded_labels = BTreeMap::new();
    excluded_labels.insert(exclusion_label, "true".to_string());
    create_namespace(
        client.clone(),
        "excluded-ns",
        excluded_labels,
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        client.clone(),
        "included-ns",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;

    // The excluded namespace's create must succeed even though nothing listens on `dead_port` —
    // the apiserver's namespaceSelector evaluation must skip the webhook entirely. Retried like
    // every other webhook-registration-dependent create in this suite: the apiserver may need a
    // moment to pick up the just-registered `MutatingWebhookConfiguration`.
    let excluded_devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "excluded-ns", &devworkspace_resource());
    create_with_retry(
        &excluded_devworkspaces,
        &devworkspace("excluded-ns", "should-pass"),
    )
    .await;

    let included_devworkspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), "included-ns", &devworkspace_resource());
    let mut last_err = None;
    let mut denied = false;
    for _ in 0..40 {
        match included_devworkspaces
            .create(
                &PostParams::default(),
                &devworkspace("included-ns", "should-fail"),
            )
            .await
        {
            Ok(_) => break,
            Err(err) => {
                if err.to_string().to_lowercase().contains("webhook")
                    || err.to_string().to_lowercase().contains("dial")
                {
                    denied = true;
                    break;
                }
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    assert!(
        denied,
        "a namespace without the exclusion label should still reach the (dead) webhook: {last_err:?}"
    );

    let _ = excluded_devworkspaces
        .delete("should-pass", &DeleteParams::default())
        .await;
}

// ---------------------------------------------------------------------------------------------
// RFC 0004 — the two admission surfaces `network-profiles` and `policy-guard` add, end to end.
//
// What makes this suite different from `weebo-si-runtime`'s (which exercises `PolicyGuard`'s
// decision logic directly against real objects) is that here the verdict travels the whole way:
// a real `ValidatingWebhookConfiguration` on the apiserver, calling back into a real running
// webhook over TLS, against a request made by a *distinct identity*. That is the only shape in
// which the question RFC 0004's *Operational considerations* calls a permanent self-lockout —
// "can the controller write through its own guard?" — has a real answer.
// ---------------------------------------------------------------------------------------------

use k8s_openapi::api::admissionregistration::v1::{
    RuleWithOperations as ValidatingRule, ValidatingWebhook, ValidatingWebhookConfiguration,
};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicySpec};
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, NamespaceFacts};
use weebo_si_crd::{
    Backend, Enforcement, FeatureMode, NamespaceName, NetworkProfilesConfig, OnNotGranted, Profile,
    ProfileCatalog, ProfileKey, ProfileNamespaceSelection, TemplateRef, Variant,
    WorkspaceSelection,
};
use weebo_si_network_profiles::{
    NamespaceSubject, NetworkProfiles, WorkspaceAdmission, WorkspaceGate,
};
use weebo_si_runtime::{KubePolicyStore, KubeTemplateStore};
use weebo_si_webhook::{NetworkProfilesAdmission, PolicyGuardState, policy_guard_router};

/// The identity the guard must never lock out. Deliberately the exact
/// `system:serviceaccount:<ns>:<name>` shape the Helm chart renders — RFC 0004: "the exemption
/// matches the service account's full name, which changes only when a manifest changes."
const CONTROLLER_IDENTITY: &str =
    "system:serviceaccount:weebo-si-hardening:weebo-si-operator-controller";
const CONTROLLER_TOKEN: &str = "controller-token";
/// A workspace owner. Authenticated, deliberately *not* exempt.
const USER_IDENTITY: &str = "system:serviceaccount:user-alice:default";
const USER_TOKEN: &str = "alice-token";

const OPERATOR_NAMESPACE: &str = "weebo-si-hardening";
const RFC4_WORKSPACE_NAMESPACE: &str = "user-alice";
/// The positive label RFC 0004's `ValidatingWebhookConfiguration` requires. Inverted polarity
/// from `dwoc-pin`'s opt-out, on purpose — see the RFC's *Design*.
const WORKSPACE_NAMESPACE_LABEL: &str = "hardening.weebo.io/workspace-namespace";

fn rfc4_config(mode: FeatureMode) -> NetworkProfilesConfig {
    NetworkProfilesConfig {
        mode,
        namespace_selector: None,
        catalog: ProfileCatalog::new(vec![Profile {
            key: ProfileKey::new("base"),
            variants: vec![Variant {
                backend: Backend::NetworkPolicy,
                template_ref: TemplateRef {
                    name: "weebo-base".to_string(),
                    namespace: NamespaceName::new(OPERATOR_NAMESPACE),
                },
            }],
        }]),
        baseline: ProfileKey::new("base"),
        grants: BTreeMap::new(),
        namespace_selection: ProfileNamespaceSelection::default(),
        workspace_selection: WorkspaceSelection::default(),
        on_not_granted: OnNotGranted::default(),
        enforcement: Enforcement::default(),
    }
}

/// The `spec` half of the same thing, for the `WeeboSiConfig` the live webhook reads its mode
/// from. Written as JSON rather than serialized from `rfc4_config` so a schema mismatch between
/// the Rust type and the CRD shows up here as a rejected create.
fn rfc4_config_spec(network_profiles_mode: &str, policy_guard_mode: &str) -> serde_json::Value {
    serde_json::json!({
        "features": {
            "networkProfiles": {
                "mode": network_profiles_mode,
                "catalog": [{
                    "key": "base",
                    "variants": [{
                        "backend": "NetworkPolicy",
                        "templateRef": {"name": "weebo-base", "namespace": OPERATOR_NAMESPACE},
                    }],
                }],
                "baseline": "base",
            },
            "policyGuard": {"mode": policy_guard_mode},
        }
    })
}

async fn create_policy_template(client: kube::Client) {
    let api: Api<NetworkPolicy> = Api::namespaced(client, OPERATOR_NAMESPACE);
    let template = NetworkPolicy {
        metadata: ObjectMeta {
            name: Some("weebo-base".to_string()),
            namespace: Some(OPERATOR_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(Default::default()),
            policy_types: Some(vec!["Egress".to_string()]),
            egress: Some(vec![NetworkPolicyEgressRule::default()]),
            ..Default::default()
        }),
    };
    api.create(&PostParams::default(), &template)
        .await
        .expect("the template should be created");
}

/// An ordinary, *unmanaged* policy — what a workspace owner would write to undo the baseline.
fn user_authored_policy(name: &str) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(RFC4_WORKSPACE_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(Default::default()),
            policy_types: Some(vec!["Egress".to_string()]),
            egress: Some(vec![NetworkPolicyEgressRule::default()]),
            ..Default::default()
        }),
    }
}

/// Serve `router` on a fresh port over TLS and return `(port, ca_bundle)`.
async fn serve_router(cert_dir: &std::path::Path, app: axum::Router) -> (u16, Vec<u8>) {
    let (key_path, cert_path) =
        generate_webhook_tls(cert_dir).expect("cert generation should succeed");
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("tls config should load");
    let port = free_port().expect("a free port should be available");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("addr should parse");
    tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await;
    });
    let ca_bundle =
        weebo_si_envtest_support::read_ca_bundle(&cert_path).expect("cert should be readable");
    (port, ca_bundle)
}

/// Register RFC 0004's own `ValidatingWebhookConfiguration`, pointed at a local port.
async fn register_policy_guard_webhook(client: kube::Client, port: u16, ca_bundle: Vec<u8>) {
    let api: Api<ValidatingWebhookConfiguration> = Api::all(client);
    let config = ValidatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-policies-envtest".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![ValidatingWebhook {
            name: "policies.hardening.weebo.io".to_string(),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: "None".to_string(),
            match_policy: Some("Equivalent".to_string()),
            failure_policy: Some("Fail".to_string()),
            timeout_seconds: Some(5),
            rules: Some(vec![ValidatingRule {
                // DELETE included, which is the entire point — see the RFC's *Design*.
                operations: Some(vec![
                    "CREATE".to_string(),
                    "UPDATE".to_string(),
                    "DELETE".to_string(),
                ]),
                api_groups: Some(vec!["networking.k8s.io".to_string()]),
                api_versions: Some(vec!["v1".to_string()]),
                resources: Some(vec!["networkpolicies".to_string()]),
                scope: Some("Namespaced".to_string()),
            }]),
            namespace_selector: Some(
                k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_expressions: Some(vec![
                        k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement {
                            key: WORKSPACE_NAMESPACE_LABEL.to_string(),
                            operator: "Exists".to_string(),
                            values: None,
                        },
                    ]),
                    match_labels: None,
                },
            ),
            client_config: WebhookClientConfig {
                url: Some(format!(
                    "https://127.0.0.1:{port}/validate/v1/networkpolicies"
                )),
                ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                service: None::<ServiceReference>,
            },
            ..Default::default()
        }]),
    };
    api.create(&PostParams::default(), &config)
        .await
        .expect("the validating webhook configuration should be accepted");
}

/// Poll until an operation stops failing with "no endpoints available"/"connection refused" —
/// the apiserver needs a moment to pick up a freshly registered webhook, exactly as
/// `create_with_retry` does for the mutating one.
async fn retry_until_webhook_routes<T, F, Fut>(mut attempt: F) -> Result<T, kube::Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, kube::Error>>,
{
    let mut last = None;
    for _ in 0..40 {
        match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let message = err.to_string();
                // A *verdict* is a real answer and must not be retried away; only the
                // "webhook not reachable yet" shapes are.
                if !message.contains("failed to call webhook")
                    && !message.contains("connection refused")
                    && !message.contains("no endpoints")
                {
                    return Err(err);
                }
                last = Some(err);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
            "webhook never became reachable".to_string(),
        ))
    }))
}

/// Everything the RFC 0004 suites share: caches, config store, observer, metrics.
struct Rfc4Stack {
    config_store: Arc<KubeConfigStore>,
    ns_store: Arc<KubeNsStore>,
    dwoc_store: Arc<KubeDwocStore>,
    policy_store: Arc<KubePolicyStore>,
    observer: Arc<PrometheusObserver>,
    metrics: weebo_si_webhook::WebhookMetrics,
}

async fn rfc4_stack(client: kube::Client) -> Rfc4Stack {
    let annotation_key = Arc::new(std::sync::RwLock::new(
        "hardening.weebo.io/dwoc".to_string(),
    ));
    let ns_store = Arc::new(
        KubeNsStore::spawn(client.clone(), Arc::clone(&annotation_key))
            .await
            .expect("namespace store should start"),
    );
    let dwoc_store = Arc::new(
        KubeDwocStore::spawn(client.clone())
            .await
            .expect("dwoc store should start"),
    );
    let capabilities = Arc::new(
        KubeCapabilities::discover(client.clone())
            .await
            .expect("capabilities discovery should succeed"),
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
        .expect("config store should start"),
    );
    let policy_store = Arc::new(
        KubePolicyStore::spawn(client, false)
            .await
            .expect("policy store should start"),
    );
    let observer =
        Arc::new(PrometheusObserver::new(&prometheus_registry).expect("observer should register"));
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .expect("metrics should register");
    Rfc4Stack {
        config_store,
        ns_store,
        dwoc_store,
        policy_store,
        observer,
        metrics,
    }
}

/// **The test RFC 0004's *Implementation plan* names as a gap and its *Operational
/// considerations* argues is the one that matters**: the controller writes its own objects
/// *through* a live `policy-guard`, and a workspace owner cannot.
///
/// The identity-matching bug this guards against is the one the RFC calls "a permanent
/// self-lockout": a renamed service account, a namespace moved, and the guard denies the
/// controller's own writes with a verdict rather than a timeout — deterministically, so no retry
/// helps. Only an end-to-end test with two distinct authenticated identities can catch it,
/// because the bug lives in the comparison against `userInfo`, which a direct call to
/// `PolicyGuard::evaluate` supplies by hand and therefore always gets right.
#[tokio::test]
async fn the_controller_writes_through_its_own_live_policy_guard() {
    let Some(env_test) = EnvTest::try_start_with_identities(&[
        (CONTROLLER_TOKEN, CONTROLLER_IDENTITY),
        (USER_TOKEN, USER_IDENTITY),
    ])
    .await
    else {
        return;
    };
    let admin = env_test.client().expect("client should build");
    install_crds(admin.clone()).await;

    create_namespace(
        admin.clone(),
        OPERATOR_NAMESPACE,
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        admin.clone(),
        RFC4_WORKSPACE_NAMESPACE,
        [(WORKSPACE_NAMESPACE_LABEL.to_string(), "true".to_string())].into(),
        BTreeMap::new(),
    )
    .await;
    create_policy_template(admin.clone()).await;
    create_config(admin.clone(), rfc4_config_spec("Enforce", "Enforce")).await;

    let stack = rfc4_stack(admin.clone()).await;
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let guard_state = Arc::new(PolicyGuardState {
        operator_identity: CONTROLLER_IDENTITY.to_string(),
        policy_guard_config: stack.config_store.policy_guard_config(),
        gate: Arc::clone(&stack.config_store) as _,
        namespace_view: Arc::clone(&stack.ns_store) as _,
        dwoc_catalog: Arc::clone(&stack.dwoc_store) as _,
        observer: Arc::clone(&stack.observer) as _,
        metrics: stack.metrics.clone(),
    });
    let (port, ca_bundle) = serve_router(cert_dir.path(), policy_guard_router(guard_state)).await;
    register_policy_guard_webhook(admin.clone(), port, ca_bundle).await;
    // The config store's first sync has to have landed before the guard can report a mode.
    tokio::time::sleep(Duration::from_millis(750)).await;

    // --- 1. The controller writes, as itself, through the guard. ---
    let controller_client = env_test
        .client_as(CONTROLLER_TOKEN)
        .expect("controller client should build");
    let templates = Arc::new(
        KubeTemplateStore::spawn(controller_client.clone(), OPERATOR_NAMESPACE, false)
            .await
            .expect("template store should start"),
    );
    let controller_policy_store = KubePolicyStore::spawn(controller_client.clone(), false)
        .await
        .expect("controller policy store should start");
    let feature = NetworkProfiles::new(
        Arc::new(std::sync::RwLock::new(Some(rfc4_config(
            FeatureMode::Enforce,
        )))),
        Arc::new(std::sync::RwLock::new(Backend::NetworkPolicy)),
        templates,
    );
    let namespace_facts = NamespaceFacts::default();
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(RFC4_WORKSPACE_NAMESPACE),
    };

    let outcome = retry_until_webhook_routes(|| async {
        weebo_si_network_profiles::reconcile(
            &feature,
            &subject,
            &ctx,
            FeatureMode::Enforce,
            &controller_policy_store,
        )
        .await
        .map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })
    })
    .await
    .expect("the controller must be able to write through its own guard");
    assert_eq!(
        outcome.applied.expect("Enforce applies").created,
        1,
        "the baseline write was denied by our own guard — this is the self-lockout RFC 0004's \
         Operational considerations warns about"
    );

    let admin_policies: Api<NetworkPolicy> =
        Api::namespaced(admin.clone(), RFC4_WORKSPACE_NAMESPACE);
    admin_policies
        .get("weebo-base")
        .await
        .expect("the baseline should really exist");

    // --- 2. A workspace owner cannot author their own policy. ---
    let user_client = env_test
        .client_as(USER_TOKEN)
        .expect("user client should build");
    let user_policies: Api<NetworkPolicy> =
        Api::namespaced(user_client.clone(), RFC4_WORKSPACE_NAMESPACE);
    let create_error = user_policies
        .create(
            &PostParams::default(),
            &user_authored_policy("my-own-allow-everything"),
        )
        .await
        .expect_err("an unmanaged CREATE by a workspace owner must be denied");
    assert!(
        create_error.to_string().contains("belongs to the platform"),
        "the denial should be the guard's, not an unrelated failure: {create_error}"
    );

    // --- 3. And cannot delete ours, which is the cheapest bypass. ---
    let delete_error = user_policies
        .delete("weebo-base", &DeleteParams::default())
        .await
        .expect_err("deleting a managed object must be denied");
    assert!(
        delete_error
            .to_string()
            .contains("managed by weebo-si-operator"),
        "the DELETE rule must be the one that fired: {delete_error}"
    );
    admin_policies
        .get("weebo-base")
        .await
        .expect("the baseline the guard protected should still be there");

    // --- 4. And the controller can still delete its own, after all of the above. ---
    // The asymmetry is the whole contract: same object, same verb, different identity.
    let controller_policies: Api<NetworkPolicy> =
        Api::namespaced(controller_client, RFC4_WORKSPACE_NAMESPACE);
    controller_policies
        .delete("weebo-base", &DeleteParams::default())
        .await
        .expect("the operator's own DELETE of its own object must be allowed");
}

/// The other half of RFC 0004's admission surface: a `DevWorkspace` `CREATE` is refused while its
/// namespace carries no baseline, and admitted once it does.
#[tokio::test]
async fn a_devworkspace_is_refused_until_its_namespace_has_a_baseline_live() {
    let env_test = envtest_or_skip!();
    let admin = env_test.client().expect("client should build");
    install_crds(admin.clone()).await;

    create_namespace(
        admin.clone(),
        OPERATOR_NAMESPACE,
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_namespace(
        admin.clone(),
        RFC4_WORKSPACE_NAMESPACE,
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;
    create_policy_template(admin.clone()).await;
    create_config(admin.clone(), rfc4_config_spec("Enforce", "Off")).await;

    let stack = rfc4_stack(admin.clone()).await;
    let mut dwoc_pin_registry: Registry<Workspace> = Registry::new();
    dwoc_pin_registry.register(DwocPin::new(stack.config_store.dwoc_pin_config()));
    let mut gate_registry: Registry<WorkspaceAdmission> = Registry::new();
    gate_registry.register(WorkspaceGate::new(
        stack.config_store.network_profiles_config(),
        Arc::clone(&stack.policy_store) as _,
        NamespaceName::new(OPERATOR_NAMESPACE),
    ));
    let state = Arc::new(AppState {
        registry: dwoc_pin_registry,
        network_profiles: Some(NetworkProfilesAdmission {
            registry: gate_registry,
            config: stack.config_store.network_profiles_config(),
        }),
        gate: Arc::clone(&stack.config_store) as _,
        namespace_view: Arc::clone(&stack.ns_store) as _,
        dwoc_catalog: Arc::clone(&stack.dwoc_store) as _,
        observer: Arc::clone(&stack.observer) as _,
        metrics: stack.metrics.clone(),
    });

    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let (port, ca_bundle) = serve_router(cert_dir.path(), weebo_si_webhook::router(state)).await;
    let webhooks_api: Api<MutatingWebhookConfiguration> = Api::all(admin.clone());
    let webhook_config = MutatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-devworkspaces-rfc4".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![
            k8s_openapi::api::admissionregistration::v1::MutatingWebhook {
                name: "devworkspaces.hardening.weebo.io".to_string(),
                admission_review_versions: vec!["v1".to_string()],
                side_effects: "None".to_string(),
                match_policy: Some("Equivalent".to_string()),
                failure_policy: Some("Fail".to_string()),
                timeout_seconds: Some(5),
                rules: Some(vec![RuleWithOperations {
                    operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                    api_groups: Some(vec!["controller.devfile.io".to_string()]),
                    api_versions: Some(vec!["v1alpha1".to_string()]),
                    resources: Some(vec!["devworkspaces".to_string()]),
                    scope: Some("Namespaced".to_string()),
                }]),
                client_config: WebhookClientConfig {
                    url: Some(format!(
                        "https://127.0.0.1:{port}/mutate/v1alpha1/devworkspaces"
                    )),
                    ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                    service: None::<ServiceReference>,
                },
                ..Default::default()
            },
        ]),
    };
    webhooks_api
        .create(&PostParams::default(), &webhook_config)
        .await
        .expect("webhook configuration should be accepted");
    tokio::time::sleep(Duration::from_millis(750)).await;

    let workspaces: Api<DynamicObject> = Api::namespaced_with(
        admin.clone(),
        RFC4_WORKSPACE_NAMESPACE,
        &devworkspace_resource(),
    );

    // --- Before the baseline: refused, and the message says why. ---
    let refusal = retry_until_webhook_routes(|| async {
        match workspaces
            .create(
                &PostParams::default(),
                &devworkspace(RFC4_WORKSPACE_NAMESPACE, "too-early"),
            )
            .await
        {
            Ok(_) => panic!("a workspace must not be admitted before its namespace has a baseline"),
            Err(err) if err.to_string().contains("baseline") => Ok(err),
            Err(err) => Err(err),
        }
    })
    .await
    .expect("the gate should have refused with its own message");
    assert!(
        refusal.to_string().contains("would start unprotected"),
        "the denial should name the risk, not just fail: {refusal}"
    );

    // --- Write the baseline, exactly as the controller would. ---
    let templates = Arc::new(
        KubeTemplateStore::spawn(admin.clone(), OPERATOR_NAMESPACE, false)
            .await
            .expect("template store should start"),
    );
    let feature = NetworkProfiles::new(
        Arc::new(std::sync::RwLock::new(Some(rfc4_config(
            FeatureMode::Enforce,
        )))),
        Arc::new(std::sync::RwLock::new(Backend::NetworkPolicy)),
        templates,
    );
    let namespace_facts = NamespaceFacts::default();
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    weebo_si_network_profiles::reconcile(
        &feature,
        &NamespaceSubject {
            namespace: NamespaceName::new(RFC4_WORKSPACE_NAMESPACE),
        },
        &ctx,
        FeatureMode::Enforce,
        stack.policy_store.as_ref(),
    )
    .await
    .expect("the baseline should be written");

    // --- After it lands in the gate's watch cache: admitted. ---
    let mut admitted = false;
    for _ in 0..40 {
        match workspaces
            .create(
                &PostParams::default(),
                &devworkspace(RFC4_WORKSPACE_NAMESPACE, "in-time"),
            )
            .await
        {
            Ok(_) => {
                admitted = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    assert!(
        admitted,
        "once the baseline exists the same workspace must be admitted — a gate that never \
         reopens is an outage, not a control"
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 0005 — `image-policy`, end to end at both enforcement points.
//
// What this tier proves that the pure tests in `weebo-si-image-policy` cannot: that a real
// apiserver actually routes a `DevWorkspace` *and* a `Pod` to our server over TLS, that the two
// webhooks' opposite `namespaceSelector` polarities scope the way the chart renders them, that
// `pods/ephemeralcontainers` and `UPDATE` are really covered rather than merely listed in a
// rule, and that `{TEAM_NAME}` resolves per namespace at *both* layers — which is the one thing
// no single-namespace test can show.
//
// envtest has no kubelet, so a `Pod` created here stays `Pending` forever. That is irrelevant:
// admission runs before scheduling, and admission is the whole of what this feature does.
// ---------------------------------------------------------------------------------------------

use k8s_openapi::api::core::v1::{Container, EphemeralContainer, Pod, PodSpec};
use weebo_si_image_policy::ImagePolicyObserver;
use weebo_si_runtime::ImageMetrics;
use weebo_si_webhook::{ImagePolicyState, image_policy_router};

const TEAM_1_NAMESPACE: &str = "rfc5-team-1";
const TEAM_2_NAMESPACE: &str = "rfc5-team-2";
const TEAM_LABEL: &str = "weebo.io/team";

/// The `spec` the live webhook reads. Written as JSON rather than serialized from the Rust type
/// so a schema mismatch between `ImagePolicyConfig` and the generated CRD shows up here as a
/// rejected create rather than as a silently-dropped field.
fn rfc5_config_spec(mode: &str) -> serde_json::Value {
    serde_json::json!({
        "teams": [
            {
                "name": "team-1",
                "namespaceSelector": {"matchLabels": {TEAM_LABEL: "team-1"}},
            },
            {
                "name": "team-2",
                "namespaceSelector": {"matchLabels": {TEAM_LABEL: "team-2"}},
            },
        ],
        "features": {
            "imagePolicy": {
                "mode": mode,
                "catalog": [
                    {"key": "internal", "patterns": ["registry.internal/shared/**"]},
                    // The entry the whole per-team-path argument exists for.
                    {"key": "team-registry", "patterns": ["registry.internal/teams/{TEAM_NAME}/**"]},
                ],
                "default": ["internal"],
                "grants": {
                    "team-1": {
                        "allowed": ["internal", "team-registry"],
                        "default": ["internal", "team-registry"],
                    },
                    "team-2": {"allowed": ["internal"], "default": ["internal"]},
                },
            }
        },
    })
}

/// Boot `image-policy`'s router against `env_test` and register both
/// `ValidatingWebhookConfiguration`s — the two the chart renders, with the same opposite
/// selector polarities, so what this suite proves is the wiring production runs.
async fn start_image_policy_webhook(env_test: &EnvTest, cert_dir: &std::path::Path) {
    let client = env_test.client().expect("client should build");

    let annotation_key = Arc::new(std::sync::RwLock::new(
        "hardening.weebo.io/dwoc".to_string(),
    ));
    let ns_store = Arc::new(
        KubeNsStore::spawn(client.clone(), Arc::clone(&annotation_key))
            .await
            .expect("namespace store should start"),
    );
    let dwoc_store = Arc::new(
        KubeDwocStore::spawn(client.clone())
            .await
            .expect("dwoc store should start"),
    );
    let capabilities = Arc::new(
        KubeCapabilities::discover(client.clone())
            .await
            .expect("capabilities discovery should succeed"),
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
        .expect("config store should start"),
    );
    let observer =
        Arc::new(PrometheusObserver::new(&prometheus_registry).expect("observer should register"));
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .expect("metrics should register");
    let image_observer: Arc<dyn ImagePolicyObserver> = Arc::new(
        ImageMetrics::register(&prometheus_registry).expect("image metrics should register"),
    );

    let (workspace_registry, pod_registry) = weebo_si_webhook::registries(
        config_store.image_policy_config(),
        Arc::clone(&image_observer),
    );
    let state = Arc::new(ImagePolicyState {
        config: config_store.image_policy_config(),
        workspace_registry,
        pod_registry,
        gate: Arc::clone(&config_store) as _,
        namespace_view: ns_store as _,
        dwoc_catalog: dwoc_store as _,
        observer,
        image_observer,
        metrics,
    });

    let (port, ca_bundle) = serve_router(cert_dir, image_policy_router(state)).await;
    register_image_policy_webhooks(client, port, ca_bundle).await;
}

async fn register_image_policy_webhooks(client: kube::Client, port: u16, ca_bundle: Vec<u8>) {
    let api: Api<ValidatingWebhookConfiguration> = Api::all(client);

    // The DevWorkspace half: opt-OUT selector, per RFC 0005 — every DevWorkspace is a workspace
    // by definition, so a namespace reached by accident is one that got hardened.
    let devworkspaces = ValidatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-devworkspaces-validate-envtest".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![ValidatingWebhook {
            name: "images.hardening.weebo.io".to_string(),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: "None".to_string(),
            match_policy: Some("Equivalent".to_string()),
            failure_policy: Some("Fail".to_string()),
            timeout_seconds: Some(5),
            rules: Some(vec![ValidatingRule {
                operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                api_groups: Some(vec!["controller.devfile.io".to_string()]),
                api_versions: Some(vec!["v1alpha1".to_string()]),
                resources: Some(vec!["devworkspaces".to_string()]),
                scope: Some("Namespaced".to_string()),
            }]),
            client_config: WebhookClientConfig {
                url: Some(format!(
                    "https://127.0.0.1:{port}/validate/v1alpha1/devworkspaces"
                )),
                ca_bundle: Some(k8s_openapi::ByteString(ca_bundle.clone())),
                service: None::<ServiceReference>,
            },
            ..Default::default()
        }]),
    };

    // The Pod half: opt-IN selector, inverted on purpose — a mis-scoped deny-pods webhook is a
    // cluster outage rather than an over-hardened namespace. The positive label is also what
    // keeps this suite from wedging pod creation for the rest of the apiserver, which is the
    // same containment it buys in production.
    let pods = ValidatingWebhookConfiguration {
        metadata: ObjectMeta {
            name: Some("weebo-si-hardening-pods-envtest".to_string()),
            ..Default::default()
        },
        webhooks: Some(vec![ValidatingWebhook {
            name: "images.hardening.weebo.io".to_string(),
            admission_review_versions: vec!["v1".to_string()],
            side_effects: "None".to_string(),
            match_policy: Some("Equivalent".to_string()),
            failure_policy: Some("Fail".to_string()),
            timeout_seconds: Some(5),
            rules: Some(vec![ValidatingRule {
                operations: Some(vec!["CREATE".to_string(), "UPDATE".to_string()]),
                api_groups: Some(vec![String::new()]),
                api_versions: Some(vec!["v1".to_string()]),
                resources: Some(vec![
                    "pods".to_string(),
                    "pods/ephemeralcontainers".to_string(),
                ]),
                scope: Some("Namespaced".to_string()),
            }]),
            namespace_selector: Some(
                k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_expressions: Some(vec![
                        k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement {
                            key: WORKSPACE_NAMESPACE_LABEL.to_string(),
                            operator: "Exists".to_string(),
                            values: None,
                        },
                    ]),
                    match_labels: None,
                },
            ),
            client_config: WebhookClientConfig {
                url: Some(format!("https://127.0.0.1:{port}/validate/v1/pods")),
                ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                service: None::<ServiceReference>,
            },
            ..Default::default()
        }]),
    };

    for config in [devworkspaces, pods] {
        api.create(&PostParams::default(), &config)
            .await
            .expect("the validating webhook configuration should be accepted");
    }
}

/// A workspace namespace belonging to `team`, carrying the positive label the Pod rule requires.
async fn create_rfc5_namespace(client: kube::Client, name: &str, team: &str) {
    create_namespace(
        client,
        name,
        BTreeMap::from([
            (TEAM_LABEL.to_string(), team.to_string()),
            (WORKSPACE_NAMESPACE_LABEL.to_string(), String::new()),
        ]),
        BTreeMap::new(),
    )
    .await;
}

/// A `DevWorkspace` whose one component names `image`.
fn devworkspace_with_image(namespace: &str, name: &str, image: &str) -> DynamicObject {
    let mut obj = DynamicObject::new(name, &devworkspace_resource());
    obj.metadata.namespace = Some(namespace.to_string());
    obj.data = serde_json::json!({
        "spec": {
            "started": true,
            "template": {
                "components": [
                    {"name": "dev", "container": {"image": image}},
                ]
            }
        }
    });
    obj
}

fn pod_with_image(namespace: &str, name: &str, image: &str) -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            containers: vec![Container {
                name: "dev".to_string(),
                image: Some(image.to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Boot the whole RFC 0005 stack and return a client — every test below opens with this.
async fn rfc5_stack(env_test: &EnvTest, cert_dir: &std::path::Path, mode: &str) -> kube::Client {
    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    start_image_policy_webhook(env_test, cert_dir).await;
    create_config(client.clone(), rfc5_config_spec(mode)).await;
    create_rfc5_namespace(client.clone(), TEAM_1_NAMESPACE, "team-1").await;
    create_rfc5_namespace(client.clone(), TEAM_2_NAMESPACE, "team-2").await;
    // The config cache is watch-backed; give the first sync a moment to land before the first
    // admission asks it for a mode.
    tokio::time::sleep(Duration::from_millis(750)).await;
    client
}

/// The headline check for the readable half: a live apiserver, a live webhook, and a developer's
/// own `kubectl apply` refused with a message naming the component and the image.
#[tokio::test]
async fn a_devworkspace_naming_an_ungranted_image_is_refused_with_a_readable_message() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let workspaces: Api<DynamicObject> =
        Api::namespaced_with(client, TEAM_1_NAMESPACE, &devworkspace_resource());

    let err = retry_until_webhook_routes(|| async {
        workspaces
            .create(
                &PostParams::default(),
                &devworkspace_with_image(TEAM_1_NAMESPACE, "scratch", "ghcr.io/someone/tool:main"),
            )
            .await
    })
    .await
    .expect_err("an uncatalogued image must be refused");

    let message = err.to_string();
    assert!(message.contains("component"), "{message}");
    assert!(message.contains("ghcr.io/someone/tool:main"), "{message}");
    assert!(message.contains("team team-1"), "{message}");
}

#[tokio::test]
async fn a_devworkspace_naming_a_granted_image_is_admitted() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let workspaces: Api<DynamicObject> =
        Api::namespaced_with(client, TEAM_1_NAMESPACE, &devworkspace_resource());
    retry_until_webhook_routes(|| async {
        workspaces
            .create(
                &PostParams::default(),
                &devworkspace_with_image(
                    TEAM_1_NAMESPACE,
                    "ok",
                    "registry.internal/shared/base:2026.3",
                ),
            )
            .await
    })
    .await
    .expect("a catalogued image must be admitted");
}

/// The whole rollout story, as a test: `DryRun` runs the identical code path and throws the
/// verdict away. A feature that could branch on its mode would make the shadow phase measure
/// something other than what enforcement does — so the *only* observable difference between
/// this test and the ones above it is that the object lands.
#[tokio::test]
async fn dry_run_admits_exactly_what_enforce_would_have_denied() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "DryRun").await;

    let workspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), TEAM_1_NAMESPACE, &devworkspace_resource());
    retry_until_webhook_routes(|| async {
        workspaces
            .create(
                &PostParams::default(),
                &devworkspace_with_image(TEAM_1_NAMESPACE, "shadow", "ghcr.io/someone/tool:main"),
            )
            .await
    })
    .await
    .expect("DryRun must not refuse anything");

    // ...and the same is true at the Pod layer, which is the one an admin is most likely to be
    // surprised by during a rollout.
    let pods: Api<Pod> = Api::namespaced(client, TEAM_1_NAMESPACE);
    retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image(TEAM_1_NAMESPACE, "shadow-pod", "ghcr.io/someone/tool:main"),
        )
        .await
    })
    .await
    .expect("DryRun must not refuse a pod either");
}

/// The floor: a pod carrying an image no DevWorkspace ever named — which is the case the
/// DevWorkspace half structurally cannot see.
#[tokio::test]
async fn a_pod_naming_an_ungranted_image_is_refused_at_the_floor() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let pods: Api<Pod> = Api::namespaced(client, TEAM_1_NAMESPACE);
    let err = retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image(TEAM_1_NAMESPACE, "sidecar-pod", "ghcr.io/someone/tool:main"),
        )
        .await
    })
    .await
    .expect_err("an uncatalogued image must be refused at the pod");

    let message = err.to_string();
    assert!(message.contains("container"), "{message}");
    assert!(message.contains("ghcr.io/someone/tool:main"), "{message}");
}

#[tokio::test]
async fn a_platform_image_is_admitted_at_the_pod_layer_whatever_the_grant_says() {
    // Without this, no workspace pod could ever start: DWO injects `project-clone` into every
    // one of them, and nobody writes it down.
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let pods: Api<Pod> = Api::namespaced(client, TEAM_2_NAMESPACE);
    retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image(
                TEAM_2_NAMESPACE,
                "clone-pod",
                "quay.io/devfile/project-clone:v0.30.0",
            ),
        )
        .await
    })
    .await
    .expect("a platform image must be admitted even for a team granted nothing but `internal`");
}

/// `UPDATE` on a running pod. `spec.containers[].image` is one of the few mutable fields, so a
/// rule covering only `CREATE` would mean "start a permitted image, then patch it".
#[tokio::test]
async fn patching_a_new_image_onto_a_running_pod_is_refused() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let pods: Api<Pod> = Api::namespaced(client, TEAM_1_NAMESPACE);
    retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image(
                TEAM_1_NAMESPACE,
                "patched",
                "registry.internal/shared/base:1",
            ),
        )
        .await
    })
    .await
    .expect("the permitted image should be admitted first");

    let patch = serde_json::json!({
        "spec": {"containers": [{"name": "dev", "image": "ghcr.io/someone/tool:main"}]}
    });
    let err = pods
        .patch(
            "patched",
            &PatchParams::default(),
            &Patch::Strategic(&patch),
        )
        .await
        .expect_err("repointing a running pod's image must be refused");
    assert!(
        err.to_string().contains("ghcr.io/someone/tool:main"),
        "{err}"
    );
}

/// `kubectl debug`'s route in. It adds a container through the `ephemeralcontainers`
/// subresource and never through `pods` UPDATE, so a rule listing only `pods` leaves a
/// one-command bypass — and the most convenient one available to anybody with workspace access.
#[tokio::test]
async fn an_ephemeral_debug_container_is_refused_through_its_own_subresource() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let pods: Api<Pod> = Api::namespaced(client, TEAM_1_NAMESPACE);
    retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image(
                TEAM_1_NAMESPACE,
                "debuggable",
                "registry.internal/shared/base:1",
            ),
        )
        .await
    })
    .await
    .expect("the permitted image should be admitted first");

    let mut with_debugger = pods
        .get("debuggable")
        .await
        .expect("the pod should be readable");
    if let Some(spec) = with_debugger.spec.as_mut() {
        spec.ephemeral_containers = Some(vec![EphemeralContainer {
            name: "debugger".to_string(),
            image: Some("ghcr.io/someone/debug:main".to_string()),
            ..Default::default()
        }]);
    }
    let err = pods
        .replace_subresource(
            "ephemeralcontainers",
            "debuggable",
            &PostParams::default(),
            &with_debugger,
        )
        .await
        .expect_err("an ungranted ephemeral container must be refused");
    assert!(
        err.to_string().contains("ghcr.io/someone/debug:main"),
        "{err}"
    );
}

/// The case a per-team registry path exists for, and the one no single-namespace test can show:
/// `registry.internal/teams/{TEAM_NAME}/**` means something *different* in every namespace.
#[tokio::test]
async fn team_name_resolves_per_namespace_and_denies_across_teams_at_both_layers() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    // --- team-1's own path, in team-1's namespace: admitted, at both layers. ---
    let team1_workspaces: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), TEAM_1_NAMESPACE, &devworkspace_resource());
    retry_until_webhook_routes(|| async {
        team1_workspaces
            .create(
                &PostParams::default(),
                &devworkspace_with_image(
                    TEAM_1_NAMESPACE,
                    "own-path",
                    "registry.internal/teams/team-1/dev-java:21",
                ),
            )
            .await
    })
    .await
    .expect("team-1 must reach its own registry path");

    let team1_pods: Api<Pod> = Api::namespaced(client.clone(), TEAM_1_NAMESPACE);
    team1_pods
        .create(
            &PostParams::default(),
            &pod_with_image(
                TEAM_1_NAMESPACE,
                "own-path-pod",
                "registry.internal/teams/team-1/dev-java:21",
            ),
        )
        .await
        .expect("team-1's own path must be admitted at the pod layer too");

    // --- team-3's path, in team-1's namespace: refused. The image is not team-1's, and no
    // amount of it being "a registry.internal image" makes it so. ---
    let err = team1_workspaces
        .create(
            &PostParams::default(),
            &devworkspace_with_image(
                TEAM_1_NAMESPACE,
                "other-path",
                "registry.internal/teams/team-3/dev-go:1.24",
            ),
        )
        .await
        .expect_err("team-1 must not reach team-3's registry path");
    assert!(err.to_string().contains("team-3"), "{err}");

    // --- The *same shape* of image, in team-2's namespace: also refused, and for a different
    // reason — team-2 was never granted `team-registry` at all, so that entry contributes no
    // pattern to its union whatever the namespace's own team happens to be. ---
    let team2_pods: Api<Pod> = Api::namespaced(client, TEAM_2_NAMESPACE);
    let err = team2_pods
        .create(
            &PostParams::default(),
            &pod_with_image(
                TEAM_2_NAMESPACE,
                "cross-team",
                "registry.internal/teams/team-2/dev-go:1.24",
            ),
        )
        .await
        .expect_err("team-2 was never granted team-registry, so even its own path is refused");
    assert!(err.to_string().contains("team team-2"), "{err}");
}

/// A namespace without the positive label is invisible to the Pod rule — which is exactly the
/// containment the opt-IN selector buys, and the reason a mis-scoped deny-pods webhook is not a
/// cluster outage.
#[tokio::test]
async fn a_namespace_without_the_workspace_label_is_out_of_the_pod_rules_scope() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    create_namespace(
        client.clone(),
        "rfc5-unlabelled",
        BTreeMap::new(),
        BTreeMap::new(),
    )
    .await;

    let pods: Api<Pod> = Api::namespaced(client, "rfc5-unlabelled");
    retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            &pod_with_image("rfc5-unlabelled", "unchecked", "ghcr.io/someone/tool:main"),
        )
        .await
    })
    .await
    .expect("a namespace the Pod rule does not select must be untouched by it");
}

/// An unparseable reference denies, and it denies *at admission* rather than becoming an
/// `ImagePullBackOff` nobody can explain. The one rule in RFC 0005 with no configurable knob.
#[tokio::test]
async fn an_unparseable_reference_is_refused_rather_than_passed_through() {
    let env_test = envtest_or_skip!();
    let cert_dir = tempfile::tempdir().expect("scratch dir");
    let client = rfc5_stack(&env_test, cert_dir.path(), "Enforce").await;

    let pods: Api<Pod> = Api::namespaced(client, TEAM_1_NAMESPACE);
    let err = retry_until_webhook_routes(|| async {
        pods.create(
            &PostParams::default(),
            // Uppercase in the repository path: not a legal reference, and a lenient parser that
            // shrugged at it would be a bypass.
            &pod_with_image(
                TEAM_1_NAMESPACE,
                "malformed",
                "registry.internal/Shared/base",
            ),
        )
        .await
    })
    .await
    .expect_err("an unparseable reference must be refused");
    assert!(
        err.to_string().contains("not a parseable image reference"),
        "{err}"
    );
}
