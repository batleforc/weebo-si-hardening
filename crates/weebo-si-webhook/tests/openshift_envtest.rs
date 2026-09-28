//! RFC 0009's `OpenShiftRoute` dialect, against a real ephemeral kube-apiserver.
//!
//! **What this proves, and what it deliberately does not.** It proves that a real `Route` is
//! routed to our server by a real `MutatingWebhookConfiguration`, that the dialect repoints
//! `spec.to.name` at the companion `Service` and records the backend it displaced, that the guard
//! refuses a developer repointing it back, and that DevWorkspace Operator regenerating the object
//! from the devfile does not leave the endpoint ungated. Every one of those is an *admission*
//! fact, and admission is what an apiserver can settle.
//!
//! It proves nothing whatever about an OpenShift **router**. No request has been served through
//! the `ReverseProxy` shell by the thing that would serve it in production, and RFC 0009's
//! implementation plan keeps "written" and "supported" apart on purpose — so this suite is not
//! the item that closes that line, and the dialect's own `#[ignore]`d unit tier stays where it
//! is. What changes here is only that the admission half is no longer asserted by hand-written
//! `AdmissionReview`s alone.
//!
//! Its own target rather than more cases in `endpoint_auth_envtest.rs`, for the reason that suite
//! is its own: this one installs a `Route` CRD and registers admission rules over
//! `route.openshift.io/v1`, and a suite that installs a CRD should not share an apiserver with
//! one that assumes a bare cluster.

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
    MutatingWebhook, MutatingWebhookConfiguration, RuleWithOperations, ServiceReference,
    ValidatingWebhook, ValidatingWebhookConfiguration, WebhookClientConfig,
};
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use kube::api::{Api, ApiResource, DynamicObject, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_crd::{COMPANION_SERVICE, UPSTREAM_ANNOTATION, WeeboSiConfig, WeeboSiTeam};
use weebo_si_envtest_support::{EnvTest, free_port, generate_webhook_tls};
use weebo_si_runtime::{
    KubeArmorCapabilities, KubeCapabilities, KubeConfigStore, KubeDwocStore, KubeNsStore,
    PrometheusObserver,
};
use weebo_si_webhook::EndpointAuthState;

const OPERATOR: &str = "system:serviceaccount:weebo-si-hardening:weebo-si-operator";
const DWO: &str =
    "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount";
const ALICE: &str = "alice";

const ENDPOINT_AUTH: &str = "hardening.weebo.io/endpoint-auth";
const NAMESPACE_LABEL: &str = "app.kubernetes.io/part-of";
const NAMESPACE_LABEL_VALUE: &str = "che.eclipse.org";
/// What the devfile said the endpoint serves, and what the gate displaces.
const APPLICATION: &str = "my-app";

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start_with_identities(&[("dwo-token", DWO), ("alice-token", ALICE)])
            .await
        {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

/// The same cluster configuration the `Ingress` suite uses, with one field different — which is
/// the point: the dialect is the only thing that changes, and everything else about the feature
/// is supposed to be indifferent to which routing object it attaches to.
fn config_yaml() -> String {
    format!(
        r#"
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features:
    endpointAuth:
      mode: Enforce
      gateway:
        externalUrl: https://auth.weebo.si
        service: {{ name: endpoint-gateway, namespace: weebo-si-hardening, port: 4180 }}
        dialect: OpenShiftRoute
        enforcement: Enforce
      owner:
        namespaceAnnotation: che.eclipse.org/username
        devworkspaceOperatorIdentity: "{DWO}"
      hosts:
        suffix: .weebo.si
        ownership:
          - template: "{{user}}-{{workspace}}-{{endpoint}}"
        exclude: [che.weebo.si, auth.weebo.si]
      catalog:
        - {{ key: private, delegation: [] }}
      default: private
"#
    )
}

/// The team half of the same configuration, per RFC 0011.
fn team_yaml() -> String {
    r#"
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: team-1
spec:
  namespaceSelector:
    matchLabels:
      hardening.weebo.io/team: "1"
  features:
    endpointAuth:
      catalog:
        - { key: team, delegation: [Team] }
        - { key: shared, delegation: [Team, UsersAndGroups] }
      default: team
"#
    .to_string()
}

/// See the fixture's own header for why this one carries a real schema where the others preserve
/// unknown fields: `spec.to.name` *is* the dialect.
const ROUTE_CRD: &str = include_str!("fixtures/route-crd.yaml");
/// Installed for the reason the sibling suite gives: the webhook's shared wiring holds a
/// `KubeDwocStore` whose reflector waits for its resource to exist.
const DEVWORKSPACE_OPERATOR_CONFIG_CRD: &str =
    include_str!("fixtures/devworkspaceoperatorconfig-crd.yaml");

/// The dynamic API for `route.openshift.io/v1` `Route`, which has no generated Rust type here —
/// the same `DynamicObject` the webhook itself sees.
fn route_resource() -> ApiResource {
    ApiResource {
        group: "route.openshift.io".to_string(),
        version: "v1".to_string(),
        api_version: "route.openshift.io/v1".to_string(),
        kind: "Route".to_string(),
        plural: "routes".to_string(),
    }
}

async fn install_crds(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let route: CustomResourceDefinition =
        serde_yaml_bw::from_str(ROUTE_CRD).expect("the Route fixture should parse");
    let dwoc: CustomResourceDefinition = serde_yaml_bw::from_str(DEVWORKSPACE_OPERATOR_CONFIG_CRD)
        .expect("the DWOC fixture should parse");

    for crd in [WeeboSiConfig::crd(), WeeboSiTeam::crd(), route, dwoc] {
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .unwrap_or_else(|err| panic!("installing {name} should succeed: {err}"));

        let mut established = false;
        for _ in 0..60 {
            established = crds.get(&name).await.ok().is_some_and(|crd| {
                crd.status.iter().any(|status| {
                    status.conditions.iter().flatten().any(|condition| {
                        condition.type_ == "Established" && condition.status == "True"
                    })
                })
            });
            if established {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        assert!(established, "{name} should become Established");
    }
}

async fn create_namespace(client: kube::Client, name: &str, owner: &str) {
    let namespaces: Api<Namespace> = Api::all(client);
    namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(BTreeMap::from([
                        (
                            NAMESPACE_LABEL.to_string(),
                            NAMESPACE_LABEL_VALUE.to_string(),
                        ),
                        ("hardening.weebo.io/team".to_string(), "1".to_string()),
                    ])),
                    annotations: Some(BTreeMap::from([(
                        "che.eclipse.org/username".to_string(),
                        owner.to_string(),
                    )])),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .expect("namespace should be created");
}

/// Start the webhook and register both rules over `routes` — the rules the operator's chart
/// renders when `dialect.target_kind()` is `Route`.
async fn serve_and_register(env_test: &EnvTest, cert_dir: &std::path::Path) {
    let client = env_test.client().expect("client should build");
    let annotation_key = Arc::new(std::sync::RwLock::new(
        weebo_si_runtime::config_store::DEFAULT_ANNOTATION.to_string(),
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
    let runtime_capabilities = Arc::new(
        KubeArmorCapabilities::discover(client.clone())
            .await
            .expect("KubeArmor capabilities discovery should succeed"),
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
            runtime_capabilities,
        )
        .await
        .expect("config store should start"),
    );
    let observer =
        Arc::new(PrometheusObserver::new(&prometheus_registry).expect("observer should register"));
    let metrics = weebo_si_webhook::WebhookMetrics::register(&prometheus_registry)
        .expect("metrics should register");

    let state = Arc::new(EndpointAuthState {
        operator_identity: OPERATOR.to_string(),
        config: config_store.endpoint_auth_config(),
        gate: Arc::clone(&config_store) as _,
        namespace_view: ns_store as _,
        dwoc_catalog: dwoc_store as _,
        observer: observer as _,
        metrics,
    });

    let (key_path, cert_path) =
        generate_webhook_tls(cert_dir).expect("cert generation should succeed");
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
        .await
        .expect("tls config should load");
    let port = free_port().expect("a free port should be available");
    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let app = weebo_si_webhook::endpoint_auth_router(state);
    tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await;
    });

    let ca_bundle =
        weebo_si_envtest_support::read_ca_bundle(&cert_path).expect("cert should be readable");
    let selector = LabelSelector {
        match_expressions: Some(vec![LabelSelectorRequirement {
            key: NAMESPACE_LABEL.to_string(),
            operator: "In".to_string(),
            values: Some(vec![NAMESPACE_LABEL_VALUE.to_string()]),
        }]),
        ..Default::default()
    };
    // `routes`, not `ingresses` — the whole difference the dialect makes to the operator's
    // rendered webhook rules.
    let rules = |operations: Vec<&str>| {
        Some(vec![RuleWithOperations {
            operations: Some(operations.into_iter().map(ToString::to_string).collect()),
            api_groups: Some(vec!["route.openshift.io".to_string()]),
            api_versions: Some(vec!["v1".to_string()]),
            resources: Some(vec!["routes".to_string()]),
            scope: Some("Namespaced".to_string()),
        }])
    };

    let mutating: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    mutating
        .create(
            &PostParams::default(),
            &MutatingWebhookConfiguration {
                metadata: ObjectMeta {
                    name: Some("weebo-si-routes-envtest".to_string()),
                    ..Default::default()
                },
                webhooks: Some(vec![MutatingWebhook {
                    name: "routes.endpointauth.hardening.weebo.io".to_string(),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: "None".to_string(),
                    match_policy: Some("Equivalent".to_string()),
                    failure_policy: Some("Fail".to_string()),
                    timeout_seconds: Some(5),
                    reinvocation_policy: Some("IfNeeded".to_string()),
                    rules: rules(vec!["CREATE", "UPDATE"]),
                    namespace_selector: Some(selector.clone()),
                    client_config: WebhookClientConfig {
                        url: Some(format!(
                            "https://127.0.0.1:{port}{}",
                            weebo_si_webhook::MUTATE_ROUTES_PATH
                        )),
                        ca_bundle: Some(k8s_openapi::ByteString(ca_bundle.clone())),
                        service: None::<ServiceReference>,
                    },
                    ..Default::default()
                }]),
            },
        )
        .await
        .expect("the mutating configuration should be accepted");

    let validating: Api<ValidatingWebhookConfiguration> = Api::all(client);
    validating
        .create(
            &PostParams::default(),
            &ValidatingWebhookConfiguration {
                metadata: ObjectMeta {
                    name: Some("weebo-si-routes-guard-envtest".to_string()),
                    ..Default::default()
                },
                webhooks: Some(vec![ValidatingWebhook {
                    name: "routes.endpointauthguard.hardening.weebo.io".to_string(),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: "None".to_string(),
                    match_policy: Some("Equivalent".to_string()),
                    failure_policy: Some("Fail".to_string()),
                    timeout_seconds: Some(5),
                    rules: rules(vec!["CREATE", "UPDATE", "DELETE"]),
                    namespace_selector: Some(selector),
                    client_config: WebhookClientConfig {
                        url: Some(format!(
                            "https://127.0.0.1:{port}{}",
                            weebo_si_webhook::VALIDATE_ROUTES_PATH
                        )),
                        ca_bundle: Some(k8s_openapi::ByteString(ca_bundle)),
                        service: None::<ServiceReference>,
                    },
                    ..Default::default()
                }]),
            },
        )
        .await
        .expect("the validating configuration should be accepted");
}

/// A `Route` as DevWorkspace Operator would publish one: a host on the governed suffix, and a
/// backend pointing at the workspace's own application.
fn route(name: &str, namespace: &str, host: &str, backend: &str) -> DynamicObject {
    DynamicObject {
        types: Some(kube::api::TypeMeta {
            api_version: "route.openshift.io/v1".to_string(),
            kind: "Route".to_string(),
        }),
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: serde_json::json!({
            "spec": { "host": host, "to": { "kind": "Service", "name": backend } }
        }),
    }
}

fn backend_of(object: &DynamicObject) -> Option<&str> {
    object.data.pointer("/spec/to/name")?.as_str()
}

/// One apiserver, one webhook, every scenario — the harness costs about a second to start and
/// there is nothing to gain from paying it four times.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_is_retargeted_pinned_and_reattached_after_dwo_regenerates_it() {
    let env_test = envtest_or_skip!();
    let admin = env_test.client().expect("client should build");
    install_crds(admin.clone()).await;

    let configs: Api<WeeboSiConfig> = Api::all(admin.clone());
    let config: WeeboSiConfig =
        serde_yaml_bw::from_str(&config_yaml()).expect("the fixture config should parse");
    configs
        .create(&PostParams::default(), &config)
        .await
        .expect("a WeeboSiConfig naming the OpenShiftRoute dialect should be accepted");

    let teams: Api<WeeboSiTeam> = Api::all(admin.clone());
    teams
        .create(
            &PostParams::default(),
            &serde_yaml_bw::from_str::<WeeboSiTeam>(&team_yaml())
                .expect("the fixture team should parse"),
        )
        .await
        .expect("the WeeboSiTeam should be accepted by the real schema");

    create_namespace(admin.clone(), "user-alice", "alice").await;
    create_namespace(admin.clone(), "user-bob", "bob").await;

    let cert_dir = tempfile::tempdir().expect("temp dir");
    serve_and_register(&env_test, cert_dir.path()).await;
    // The watches behind the gate need a moment to see the objects created above.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let resource = route_resource();
    let as_dwo = env_test.client_as("dwo-token").expect("dwo client");
    let as_alice = env_test.client_as("alice-token").expect("alice client");
    let dwo_routes: Api<DynamicObject> = Api::namespaced_with(as_dwo, "user-alice", &resource);
    let alice_routes: Api<DynamicObject> = Api::namespaced_with(as_alice, "user-alice", &resource);

    // --- the mutation: a Route comes back pointing at the gate, not at the application --------
    let generated = dwo_routes
        .create(
            &PostParams::default(),
            &route(
                "alice-ws-api",
                "user-alice",
                "alice-ws-api.weebo.si",
                APPLICATION,
            ),
        )
        .await
        .expect("DevWorkspace Operator's own create must be admitted — guard row 2");
    assert_eq!(
        backend_of(&generated),
        Some(COMPANION_SERVICE),
        "the ReverseProxy dialect must repoint spec.to at the companion Service"
    );
    assert_eq!(
        generated
            .annotations()
            .get(UPSTREAM_ANNOTATION)
            .map(String::as_str),
        Some("my-app:80"),
        "and record the backend it displaced, which is the only way the gateway can reach it"
    );
    assert_eq!(
        generated
            .annotations()
            .get(ENDPOINT_AUTH)
            .map(String::as_str),
        Some("managed"),
        "the object should be marked gated"
    );

    // --- host ownership, on `spec.host` rather than `spec.rules[].host` -----------------------
    // The Route-shaped half of a check the Ingress suite already makes: the host lives somewhere
    // else on this kind, and a dialect that read the wrong field would let alice claim bob's FQDN.
    let stolen = alice_routes
        .create(
            &PostParams::default(),
            &route("steal", "user-alice", "bob-ws-api.weebo.si", APPLICATION),
        )
        .await;
    let error = stolen.expect_err("a host another namespace owns must be refused");
    assert!(
        format!("{error}").contains("does not belong"),
        "the refusal should name the reason: {error}"
    );

    // --- spec.to is pinned: a developer may not point their endpoint back at the application ---
    // The dialect's own version of row 6. On a forward-auth dialect the gate is an annotation and
    // tampering means editing one; here the gate *is* the backend, so the field that has to be
    // pinned is a field of the spec — which is why `ManagedField` has a `Path` variant at all.
    let error = alice_routes
        .patch(
            "alice-ws-api",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "spec": { "to": { "name": APPLICATION } }
            })),
        )
        .await
        .expect_err("repointing spec.to away from the gate must be refused");
    assert!(
        format!("{error}").contains("managed by weebo-si-operator"),
        "the refusal should say the backend is managed: {error}"
    );

    // ...and the object still points at the gate, which is the assertion that would have caught a
    // guard that refused the request *after* the write.
    let after = dwo_routes
        .get("alice-ws-api")
        .await
        .expect("the Route should still exist");
    assert_eq!(backend_of(&after), Some(COMPANION_SERVICE));

    // --- the retarget survives DevWorkspace Operator regenerating the object -------------------
    // The failure this closes is the one the whole feature is built against: DWO rebuilds the
    // routing object from the devfile at every workspace start, dropping our annotations and
    // resetting the backend. If the mutation did not re-attach, every endpoint in the cluster
    // would quietly open on the next restart.
    let regenerated = dwo_routes
        .replace(
            "alice-ws-api",
            &PostParams::default(),
            &DynamicObject {
                metadata: ObjectMeta {
                    name: Some("alice-ws-api".to_string()),
                    namespace: Some("user-alice".to_string()),
                    resource_version: after.metadata.resource_version.clone(),
                    ..Default::default()
                },
                ..route(
                    "alice-ws-api",
                    "user-alice",
                    "alice-ws-api.weebo.si",
                    APPLICATION,
                )
            },
        )
        .await
        .expect("DevWorkspace Operator may rewrite its own object — guard row 2");
    assert_eq!(
        backend_of(&regenerated),
        Some(COMPANION_SERVICE),
        "a regenerated Route must come back gated, or every endpoint opens at the next restart"
    );
    assert_eq!(
        regenerated
            .annotations()
            .get(UPSTREAM_ANNOTATION)
            .map(String::as_str),
        Some("my-app:80"),
        "and the displaced backend must be recorded again"
    );

    // --- the developer's own annotations are still the developer's ----------------------------
    // The dialect changes what the gate *is*; it does not change whose the delegation keys are.
    let shared = alice_routes
        .patch(
            "alice-ws-api",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": {
                    "hardening.weebo.io/access": "shared",
                    "hardening.weebo.io/allow-users": "bob"
                } }
            })),
        )
        .await
        .expect("sharing an endpoint must work on a Route exactly as it does on an Ingress");
    assert_eq!(
        shared
            .annotations()
            .get("hardening.weebo.io/allow-users")
            .map(String::as_str),
        Some("bob")
    );
    assert_eq!(
        backend_of(&shared),
        Some(COMPANION_SERVICE),
        "and an annotation edit must not disturb the retarget"
    );
}
