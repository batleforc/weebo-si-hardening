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
use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore, PrometheusObserver};
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

    let prometheus_registry = prometheus::Registry::new();
    let config_store = KubeConfigStore::spawn(
        client.clone(),
        &prometheus_registry,
        Arc::clone(&ns_store),
        annotation_key,
        Arc::clone(&dwoc_store),
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
