//! RFC 0009's admission tier, against a real ephemeral kube-apiserver.
//!
//! What this proves that a unit test cannot: a real `Ingress` is actually routed to our server by
//! a real `MutatingWebhookConfiguration`, actually mutated by the dialect, and actually refused
//! by the guard when the identity writing it is not one of the three that may — with the verdicts
//! decided from the `userInfo` the *apiserver* puts in the review rather than from one a test
//! hand-wrote.
//!
//! Its own target rather than more cases in `envtest.rs`, for the reason RFC 0007's suite is one:
//! this suite installs a `WeeboSiConfig` carrying `features.endpointAuth` and registers two
//! webhook configurations over `ingresses`, and a suite that puts a cluster-wide admission rule
//! on a core resource should not share an apiserver with one that assumes a bare cluster.

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
use k8s_openapi::api::networking::v1::{Ingress, IngressRule, IngressSpec};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_crd::WeeboSiConfig;
use weebo_si_envtest_support::{EnvTest, free_port, generate_webhook_tls};
use weebo_si_runtime::{
    KubeArmorCapabilities, KubeCapabilities, KubeConfigStore, KubeDwocStore, KubeNsStore,
    PrometheusObserver,
};
use weebo_si_webhook::EndpointAuthState;

/// The three identities the guard's first rows are about, plus the developer everything else is.
const OPERATOR: &str = "system:serviceaccount:weebo-si-hardening:weebo-si-operator";
const DWO: &str =
    "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount";
const ALICE: &str = "alice";
const BREAK_GLASS: &str = "system:serviceaccount:platform:break-glass";

const CHAIN: &str = "traefik.ingress.kubernetes.io/router.middlewares";
const NAMESPACE_LABEL: &str = "app.kubernetes.io/part-of";
const NAMESPACE_LABEL_VALUE: &str = "che.eclipse.org";

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start_with_identities(&[
            ("dwo-token", DWO),
            ("alice-token", ALICE),
            ("break-glass-token", BREAK_GLASS),
        ])
        .await
        {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

fn config_yaml() -> String {
    format!(
        r#"
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams:
    - name: team-1
      namespaceSelector:
        matchLabels:
          hardening.weebo.io/team: "1"
  features:
    endpointAuth:
      mode: Enforce
      gateway:
        externalUrl: https://auth.weebo.si
        service: {{ name: endpoint-gateway, namespace: weebo-si-hardening, port: 4180 }}
        dialect: Traefik
        enforcement: Enforce
      breakGlassIdentities: ["{BREAK_GLASS}"]
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
        - {{ key: team, delegation: [Team] }}
        - {{ key: shared, delegation: [Team, UsersAndGroups] }}
      default: private
      grants:
        team-1: {{ allowed: [private, team, shared], default: team }}
"#
    )
}

/// The `DevWorkspaceOperatorConfig` CRD, from the sibling suite's fixture.
///
/// **Installed even though this feature never reads one**, and that is worth a sentence: the
/// webhook's shared wiring holds `KubeDwocStore`, whose reflector waits for its resource to
/// exist. On an apiserver without that CRD the wait never finishes — not a bug in the store (a
/// real cluster running Che has DevWorkspace Operator), but it does mean any suite that builds
/// the real wiring has to install it.
const DEVWORKSPACE_OPERATOR_CONFIG_CRD: &str =
    include_str!("fixtures/devworkspaceoperatorconfig-crd.yaml");

async fn install_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let dwoc: CustomResourceDefinition = serde_yaml_bw::from_str(DEVWORKSPACE_OPERATOR_CONFIG_CRD)
        .expect("the fixture should parse");

    for crd in [WeeboSiConfig::crd(), dwoc] {
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

async fn create_namespace(client: kube::Client, name: &str, owner: &str, team: bool) {
    let namespaces: Api<Namespace> = Api::all(client);
    let mut labels = BTreeMap::from([(
        NAMESPACE_LABEL.to_string(),
        NAMESPACE_LABEL_VALUE.to_string(),
    )]);
    if team {
        labels.insert("hardening.weebo.io/team".to_string(), "1".to_string());
    }
    namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(labels),
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

/// Start the webhook, register both rules, and hand back nothing: everything after this talks to
/// the apiserver, which is the point of the tier.
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
    let rules = |operations: Vec<&str>| {
        Some(vec![RuleWithOperations {
            operations: Some(operations.into_iter().map(ToString::to_string).collect()),
            api_groups: Some(vec!["networking.k8s.io".to_string()]),
            api_versions: Some(vec!["v1".to_string()]),
            resources: Some(vec!["ingresses".to_string()]),
            scope: Some("Namespaced".to_string()),
        }])
    };

    let mutating: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    mutating
        .create(
            &PostParams::default(),
            &MutatingWebhookConfiguration {
                metadata: ObjectMeta {
                    name: Some("weebo-si-endpoints-envtest".to_string()),
                    ..Default::default()
                },
                webhooks: Some(vec![MutatingWebhook {
                    name: "ingresses.endpointauth.hardening.weebo.io".to_string(),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: "None".to_string(),
                    match_policy: Some("Equivalent".to_string()),
                    failure_policy: Some("Fail".to_string()),
                    timeout_seconds: Some(5),
                    reinvocation_policy: Some("IfNeeded".to_string()),
                    rules: rules(vec!["CREATE", "UPDATE"]),
                    namespace_selector: Some(selector.clone()),
                    client_config: WebhookClientConfig {
                        url: Some(format!("https://127.0.0.1:{port}/mutate/v1/ingresses")),
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
                    name: Some("weebo-si-endpoints-guard-envtest".to_string()),
                    ..Default::default()
                },
                webhooks: Some(vec![ValidatingWebhook {
                    name: "ingresses.endpointauthguard.hardening.weebo.io".to_string(),
                    admission_review_versions: vec!["v1".to_string()],
                    side_effects: "None".to_string(),
                    match_policy: Some("Equivalent".to_string()),
                    failure_policy: Some("Fail".to_string()),
                    timeout_seconds: Some(5),
                    rules: rules(vec!["CREATE", "UPDATE", "DELETE"]),
                    namespace_selector: Some(selector),
                    client_config: WebhookClientConfig {
                        url: Some(format!("https://127.0.0.1:{port}/validate/v1/ingresses")),
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

fn ingress(
    name: &str,
    namespace: &str,
    host: &str,
    annotations: BTreeMap<String, String>,
) -> Ingress {
    Ingress {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            annotations: Some(annotations),
            ..Default::default()
        },
        spec: Some(IngressSpec {
            rules: Some(vec![IngressRule {
                host: Some(host.to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// One apiserver, one webhook, every scenario — the harness costs about a second to start and
/// there is nothing to gain from paying it seven times.
#[tokio::test(flavor = "multi_thread")]
async fn the_gate_is_attached_pinned_and_refused_the_way_rfc_0009_says() {
    let env_test = envtest_or_skip!();
    let admin = env_test.client().expect("client should build");
    install_crd(admin.clone()).await;

    let configs: Api<WeeboSiConfig> = Api::all(admin.clone());
    let config: WeeboSiConfig =
        serde_yaml_bw::from_str(&config_yaml()).expect("the fixture config should parse");
    configs
        .create(&PostParams::default(), &config)
        .await
        .expect("the WeeboSiConfig should be accepted by the real schema");

    create_namespace(admin.clone(), "user-alice", "alice", true).await;
    create_namespace(admin.clone(), "user-bob", "bob", true).await;

    let cert_dir = tempfile::tempdir().expect("temp dir");
    serve_and_register(&env_test, cert_dir.path()).await;
    // The watches behind the gate need a moment to see the objects created above.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let as_dwo = env_test.client_as("dwo-token").expect("dwo client");
    let as_alice = env_test.client_as("alice-token").expect("alice client");
    let alice_ingresses: Api<Ingress> = Api::namespaced(as_alice.clone(), "user-alice");
    let dwo_ingresses: Api<Ingress> = Api::namespaced(as_dwo, "user-alice");

    // --- the mutation: DevWorkspace Operator's own object comes back gated -------------------
    let generated = dwo_ingresses
        .create(
            &PostParams::default(),
            &ingress(
                "alice-ws-api",
                "user-alice",
                "alice-ws-api.weebo.si",
                BTreeMap::from([("hardening.weebo.io/access".to_string(), "team".to_string())]),
            ),
        )
        .await
        .expect("DevWorkspace Operator's own create must be admitted — guard row 2");
    let annotations = generated.annotations();
    assert_eq!(
        annotations
            .get("hardening.weebo.io/endpoint-auth")
            .map(String::as_str),
        Some("managed"),
        "the mutation should mark the object gated"
    );
    assert_eq!(
        annotations.get(CHAIN).map(String::as_str),
        Some("weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd"),
        "the Traefik dialect should attach its middleware chain"
    );

    // --- row 5: a developer's own endpoint is gated, not refused ------------------------------
    let own = alice_ingresses
        .create(
            &PostParams::default(),
            &ingress(
                "alice-ws-preview",
                "user-alice",
                "alice-preview-ui.weebo.si",
                BTreeMap::new(),
            ),
        )
        .await
        .expect("a developer's own Ingress for their own host must be admitted — guard row 5");
    assert!(own.annotations().contains_key(CHAIN));

    // --- host ownership: alice may not claim bob's host ---------------------------------------
    let stolen = alice_ingresses
        .create(
            &PostParams::default(),
            &ingress(
                "steal",
                "user-alice",
                "bob-ws-api.weebo.si",
                BTreeMap::new(),
            ),
        )
        .await;
    let error = stolen.expect_err("a host another namespace owns must be refused");
    assert!(
        format!("{error}").contains("does not belong"),
        "the refusal should name the reason: {error}"
    );

    // --- row 6: the gate is pinned by value ----------------------------------------------------
    let mut tampered = own.clone();
    tampered.metadata.annotations.as_mut().unwrap().insert(
        CHAIN.to_string(),
        "user-alice-rewrite@kubernetescrd,weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd"
            .to_string(),
    );
    tampered.metadata.managed_fields = None;
    let error = alice_ingresses
        .replace("alice-ws-preview", &PostParams::default(), &tampered)
        .await
        .expect_err("prepending a middleware in front of the gate must be refused");
    assert!(
        format!("{error}").contains("managed by weebo-si-operator"),
        "the refusal should say the gate is managed: {error}"
    );

    // --- the delegation annotations are the developer's ---------------------------------------
    let shared = alice_ingresses
        .patch(
            "alice-ws-preview",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": {
                    "hardening.weebo.io/access": "shared",
                    "hardening.weebo.io/allow-users": "bob,carol"
                } }
            })),
        )
        .await
        .expect("sharing an endpoint with kubectl must work — RFC 0009's *Two ways in*");
    assert_eq!(
        shared
            .annotations()
            .get("hardening.weebo.io/allow-users")
            .map(String::as_str),
        Some("bob,carol")
    );

    // --- an unusable rule list is refused with the reason --------------------------------------
    let error = alice_ingresses
        .patch(
            "alice-ws-preview",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": {
                    "hardening.weebo.io/rules": "this is not a list of rules"
                } }
            })),
        )
        .await
        .expect_err("an unparseable rule list must be refused rather than silently dropped");
    assert!(
        format!("{error}").contains("not usable"),
        "the refusal should name what is wrong: {error}"
    );

    // --- a key the team was not granted is refused too -----------------------------------------
    let bob_ingresses: Api<Ingress> = Api::namespaced(as_alice.clone(), "user-alice");
    let error = bob_ingresses
        .patch(
            "alice-ws-preview",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": { "hardening.weebo.io/access": "open" } }
            })),
        )
        .await
        .expect_err("a catalogue key this team's grant does not reach must be refused");
    assert!(format!("{error}").contains("not usable"), "{error}");

    // --- row 9: delete is allowed, because the route dies with the gate ------------------------
    alice_ingresses
        .delete("alice-ws-preview", &DeleteParams::default())
        .await
        .expect("a developer may delete their own endpoint — guard row 9");

    // --- break-glass: a developer may not drop their own gate ---------------------------------
    // Attempted first, while the endpoint is still gated: once break-glass has legitimately set
    // `bypass` below, writing the same value again changes nothing and refusing it would be
    // refusing a no-op.
    let error = alice_ingresses
        .patch(
            "alice-ws-api",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": { "hardening.weebo.io/endpoint-auth": "bypass" } }
            })),
        )
        .await
        .expect_err("a developer may not drop their own gate");
    assert!(
        format!("{error}").contains("managed by weebo-si-operator"),
        "the refusal should say the gate is managed: {error}"
    );

    // --- ...and an identity in breakGlassIdentities may -----------------------------------------
    let as_break_glass = env_test
        .client_as("break-glass-token")
        .expect("break-glass client");
    let break_glass_ingresses: Api<Ingress> = Api::namespaced(as_break_glass, "user-alice");
    let bypassed = break_glass_ingresses
        .patch(
            "alice-ws-api",
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "annotations": { "hardening.weebo.io/endpoint-auth": "bypass" } }
            })),
        )
        .await
        .expect("an identity in breakGlassIdentities may drop the gate on one endpoint");
    assert_eq!(
        bypassed
            .annotations()
            .get("hardening.weebo.io/endpoint-auth")
            .map(String::as_str),
        Some("bypass"),
        "and the mutation must honour it by attaching nothing, rather than putting the gate back"
    );
}
