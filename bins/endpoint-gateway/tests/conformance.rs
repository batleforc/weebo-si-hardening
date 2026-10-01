//! RFC 0009's dialect conformance suite — a real Traefik, in front of the real gateway binary,
//! in front of a real backend.
//!
//! **Why a whole process tree for this.** Every other test in this repo asks whether the gateway
//! decides correctly. This one asks a different question, and it is the one the design actually
//! rests on: *does the router do what the dialect says it does.* `forwardAuth` is a contract with
//! somebody else's software — it must call `/auth` with the four inbound headers, it must return
//! a non-`2xx` auth response to the browser verbatim (body, `WWW-Authenticate` and `Set-Cookie`
//! included), it must replace the outbound identity headers rather than let a caller supply them,
//! and it must not let a client forge the address the gate reads. None of that is checkable
//! against a mock, because a mock is our belief about Traefik rather than Traefik.
//!
//! The tree, bottom to top: an ephemeral `kube-apiserver` (the gateway's informers are its only
//! source of policy), the `endpoint-gateway` binary itself, a backend that reports the headers it
//! was handed, and Traefik with a file-provider configuration that mirrors the `Middleware` the
//! controller writes — same `authResponseHeaders`, same `addAuthCookiesToResponse`, same
//! `trustForwardHeader: false`.
//!
//! # What this suite does not cover, named rather than dropped
//!
//! The rows needing a **user** identity — the three outbound `X-Auth-Request-*` headers carrying
//! a real username, and `Set-Cookie` on a `302` through the grant flow — are absent, and the
//! reason is structural rather than an omission. Both need a session this gateway minted, which
//! needs a sign-in, which needs an OpenID provider it will talk to; and it will not talk to a
//! local one, because `issuer` must be `https` (config validation) and its HTTP client trusts the
//! bundled Mozilla roots rather than a certificate a test could hand it. Weakening either of
//! those in production code to make a test pass would be trading the property for the test of it.
//! What *is* asserted here is the half that does not need an identity provider — including the
//! two rows an attacker cares about most, the spoofed `X-Auth-Request-User` and the forged
//! client address — with a workspace service-account token standing in wherever the suite needs a
//! caller the gate recognises.

#![cfg(feature = "conformance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{Namespace, Pod, PodSpec, ServiceAccount};
use k8s_openapi::api::networking::v1::{Ingress, IngressRule, IngressSpec};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_crd::{WeeboSiConfig, WeeboSiTeam};
use weebo_si_envtest_support::{EnvTest, free_port, generate_webhook_tls};

const GATEWAY_BIN: &str = env!("CARGO_BIN_EXE_endpoint-gateway");
/// Thirty-two bytes, in the *standard padded* base64 `openssl rand -base64 32` emits — which is
/// what an admin following the documentation would paste, and therefore the spelling worth
/// exercising here. A fixed key is right in a test: the suite never leaves this process tree, and
/// a random one would make a failure unreproducible.
const SESSION_KEYS: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const SUFFIX: &str = ".weebo.si";
const ALICE_HOST: &str = "alice-ws-api.weebo.si";
const BOB_HOST: &str = "bob-ws-api.weebo.si";
/// A host outside the gated suffix, routed by Traefik to the same backend with no middleware —
/// the control the gate's latency is measured against.
const CONTROL_HOST: &str = "control.local";
/// Requests per side for each row of the cost matrix, after the warm-up.
const LAG_SAMPLES: usize = 300;
/// Fresh credentials for the rows that time a first use — each one is one apiserver call.
const COLD_SAMPLES: usize = 25;
/// Forged tokens one client sends in the limiter row: well past the per-client `TokenReview`
/// burst (10), so most of them must be refused without asking the apiserver.
const FLOOD_SAMPLES: usize = 40;
/// The per-client `TokenReview` burst (`kube_workload::ReviewLimits`' default).
const PER_CLIENT_REVIEW_BURST: usize = 10;
/// The per-client bearer verification burst (`state::BEARER_VERIFY_PER_CLIENT`).
const PER_CLIENT_VERIFY_BURST: usize = 20;
/// RFC 0009's *Request cost*: p99 under 5 ms for the auth round trip.
const LAG_BUDGET: Duration = Duration::from_millis(5);
const ALICE_POD_IP: &str = "10.42.0.7";
const BOB_POD_IP: &str = "10.42.1.9";

/// Everything the suite starts, killed in reverse order when it drops.
struct Tree {
    _env_test: EnvTest,
    traefik: Child,
    gateway: Child,
    entry: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = self.traefik.kill();
        let _ = self.traefik.wait();
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
    }
}

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
        dialect: Traefik
        enforcement: Enforce
      owner:
        namespaceAnnotation: che.eclipse.org/username
        devworkspaceOperatorIdentity: "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount"
      hosts:
        suffix: "{SUFFIX}"
        ownership:
          - template: "{{user}}-{{workspace}}-{{endpoint}}"
        exclude: [auth.weebo.si]
      catalog:
        - {{ key: private, delegation: [] }}
      default: private
"#
    )
}

/// The team half of the same configuration, per RFC 0011: `open` is this team's own catalogue
/// entry, and `private` — the cluster default — stays reachable without being redeclared.
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
        - { key: open, anonymous: true, delegation: [] }
      default: private
"#
    .to_string()
}

/// The gateway's own configuration file.
///
/// `issuer` points at a host that does not resolve, on purpose: discovery fails, the gateway logs
/// that sign-in is unavailable and keeps serving — which is the documented behaviour and exactly
/// the shape this suite needs, since every caller below proves itself without one.
fn gateway_yaml(listen: u16, revocation_namespace: &str) -> String {
    format!(
        r#"
listen: "127.0.0.1:{listen}"
issuer: "https://sso.invalid.example/realms/weebo"
client_id: "che-client"
redirect_url: "https://auth.weebo.si/oidc/callback"
claims:
  username: preferred_username
  groups: groups
hosts:
  suffix: "{SUFFIX}"
  exclude: ["auth.weebo.si"]
bearer:
  audiences: ["endpoint-gateway"]
self_origin:
  pod_network: On
  client_ip_header: X-Real-Ip
  service_account_token: true
  trusted_proxy: any
probe:
  enabled: false
backchannel_logout:
  enabled: true
  configmap: endpoint-auth-revocations
  namespace: "{revocation_namespace}"
enforcement: Enforce
"#
    )
}

/// The file-provider mirror of the `Middleware` `weebo-si-controller` writes. Every field here is
/// a field of that object; a difference between the two would make this suite prove nothing.
fn traefik_dynamic(gateway: u16, backend: u16, cert: &Path, key: &Path) -> String {
    format!(
        r#"
http:
  routers:
    endpoint:
      rule: "HostRegexp(`^.+{0}$`)"
      entryPoints: [websecure]
      service: backend
      middlewares: [endpoint-auth]
      tls: {{}}
    control:
      rule: "Host(`{CONTROL_HOST}`)"
      entryPoints: [websecure]
      service: backend
      tls: {{}}
    # The same two routes on a plain-HTTP entrypoint: the gate must refuse an endpoint served
    # without TLS (its session cookie is `__Host-`), and the cost matrix times that refusal.
    endpoint-plain:
      rule: "HostRegexp(`^.+{0}$`)"
      entryPoints: [web]
      service: backend
      middlewares: [endpoint-auth]
    control-plain:
      rule: "Host(`{CONTROL_HOST}`)"
      entryPoints: [web]
      service: backend
  services:
    backend:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:{backend}"
  middlewares:
    endpoint-auth:
      forwardAuth:
        address: "http://127.0.0.1:{gateway}/auth"
        trustForwardHeader: false
        authResponseHeaders:
          - X-Auth-Request-User
          - X-Auth-Request-Groups
          - X-Auth-Request-Email
        addAuthCookiesToResponse:
          - __Host-weebo-endpoint
tls:
  certificates:
    - certFile: "{1}"
      keyFile: "{2}"
"#,
        // Two backslashes, because the rule is a Go regexp inside a YAML double-quoted scalar:
        // one belongs to the regexp and the other survives YAML unescaping. A single one is an
        // invalid YAML escape, and what it buys is a `404` from Traefik with nothing in the log
        // to say why.
        SUFFIX.replace('.', r"\\."),
        cert.display(),
        key.display(),
    )
}

fn traefik_static(entry: u16, web: u16, dynamic: &Path) -> String {
    format!(
        r#"
entryPoints:
  websecure:
    address: "127.0.0.1:{entry}"
  web:
    address: "127.0.0.1:{web}"
providers:
  file:
    filename: "{}"
    watch: false
log:
  level: ERROR
accessLog: {{}}
"#,
        dynamic.display()
    )
}

/// RFC 6455's `Sec-WebSocket-Accept` for a client key.
fn websocket_accept(key: &[u8]) -> String {
    use base64::Engine as _;
    let mut input = key.to_vec();
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// A backend that answers `200` with the request's own headers as the body, so an assertion can
/// be about *what the application was handed* rather than about what we hope Traefik forwarded.
///
/// A WebSocket handshake is answered `101` and the connection dropped once upgraded: the gate is
/// consulted on the handshake only, so the handshake is all the cost matrix has to time.
async fn spawn_backend() -> u16 {
    use axum::Router;
    use axum::response::IntoResponse;
    use axum::routing::any;

    let port = free_port().expect("a free port");
    let app = Router::new().fallback(any(|mut request: axum::extract::Request| async move {
        let headers = request.headers().clone();
        if let Some(key) = headers
            .get("sec-websocket-key")
            .filter(|_| {
                headers
                    .get("upgrade")
                    .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"websocket"))
            })
            .map(|key| websocket_accept(key.as_bytes()))
        {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let _ = upgrade.await;
            });
            return (
                axum::http::StatusCode::SWITCHING_PROTOCOLS,
                [
                    ("upgrade", "websocket".to_owned()),
                    ("connection", "Upgrade".to_owned()),
                    ("sec-websocket-accept", key),
                ],
            )
                .into_response();
        }
        let mut lines: Vec<String> = headers
            .iter()
            .map(|(name, value)| {
                format!(
                    "{}: {}",
                    name.as_str(),
                    value.to_str().unwrap_or("<binary>")
                )
            })
            .collect();
        lines.sort();
        lines.join("\n").into_response()
    }));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("backend should bind");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    port
}

async fn install_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    for crd in [WeeboSiConfig::crd(), WeeboSiTeam::crd()] {
        install_one_crd(&crds, crd).await;
    }
}

/// Apply one CRD and wait for it to be `Established`.
async fn install_one_crd(crds: &Api<CustomResourceDefinition>, crd: CustomResourceDefinition) {
    let name = crd.name_any();
    crds.patch(
        &name,
        &PatchParams::apply("conformance").force(),
        &Patch::Apply(&crd),
    )
    .await
    .expect("installing the CRD should succeed");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let established =
            crds.get(&name).await.ok().is_some_and(|crd| {
                crd.status.iter().any(|status| {
                    status.conditions.iter().flatten().any(|condition| {
                        condition.type_ == "Established" && condition.status == "True"
                    })
                })
            });
        if established {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("the CRD should become Established");
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
                            "app.kubernetes.io/part-of".to_string(),
                            "che.eclipse.org".to_string(),
                        ),
                        // In a team, because a path rule naming `open` has to be a key the
                        // namespace's grant reaches — otherwise the endpoint compiles closed and
                        // every assertion below is about the wrong thing.
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

/// A workspace pod, with the label that makes its address an identity and the `podIP` the gate
/// indexes. The status is written separately because that is where a real kubelet would put it.
async fn create_workspace_pod(client: kube::Client, namespace: &str, name: &str, ip: &str) {
    let pods: Api<Pod> = Api::namespaced(client, namespace);
    pods.create(
        &PostParams::default(),
        &Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                labels: Some(BTreeMap::from([(
                    "controller.devfile.io/devworkspace_id".to_string(),
                    "workspaceabc".to_string(),
                )])),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![k8s_openapi::api::core::v1::Container {
                    name: "tools".to_string(),
                    image: Some("registry.example/tools:1".to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: None,
        },
    )
    .await
    .expect("pod should be created");
    // The address is on the *status*, which is where a kubelet would have put it — and this
    // apiserver has no kubelet, so the suite plays one.
    pods.patch_status(
        name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({
            "status": { "podIP": ip, "phase": "Running" }
        })),
    )
    .await
    .expect("pod status should be written");
}

/// A service account in `namespace`, and a token for it that a `TokenReview` will accept.
async fn service_account_token(client: kube::Client, namespace: &str, name: &str) -> String {
    let accounts: Api<ServiceAccount> = Api::namespaced(client, namespace);
    accounts
        .create(
            &PostParams::default(),
            &ServiceAccount {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .expect("service account should be created");
    let request = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": { "audiences": ["https://kubernetes.default.svc"], "expirationSeconds": 3600 }
    });
    let response = accounts
        .create_subresource::<serde_json::Value, serde_json::Value>(
            "token",
            name,
            &PostParams::default(),
            &request,
        )
        .await
        .expect("a token should be issued");
    response
        .get("status")
        .and_then(|status| status.get("token"))
        .and_then(|token| token.as_str())
        .expect("the token request should carry a token")
        .to_string()
}

fn kubeconfig(dir: &Path, url: &str, token: &str) -> PathBuf {
    let path = dir.join("kubeconfig.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
apiVersion: v1
kind: Config
clusters:
  - name: envtest
    cluster:
      server: {url}
      insecure-skip-tls-verify: true
contexts:
  - name: envtest
    context: {{ cluster: envtest, user: envtest }}
current-context: envtest
users:
  - name: envtest
    user: {{ token: {token} }}
"#
        ),
    )
    .expect("kubeconfig should be written");
    path
}

/// Whether the router this suite drives is on `PATH`.
///
/// Absent means skip, so a laptop without Traefik still runs `task test` — **unless
/// `REQUIRE_ENVTEST` is set**, which CI does, and then it is a failure. That is the same contract
/// `EnvTest::try_start` follows below, and it exists because the two halves of this suite fail
/// differently: a missing apiserver is already loud in CI, and without this a missing Traefik
/// would be a green step that asserted nothing — the exact shape `docs/ci.md` records this repo
/// getting wrong once already.
fn traefik_present() -> bool {
    let present = Command::new("traefik")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    assert!(
        present || std::env::var("REQUIRE_ENVTEST").is_err(),
        "REQUIRE_ENVTEST is set but `traefik` is not on PATH: the conformance suite would have \
         skipped itself and reported success"
    );
    present
}

async fn wait_for(url: &str, client: &reqwest::Client, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if client.get(url).send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{what} at {url} never came up");
}

/// One request through Traefik, with the browser-visible result.
struct Answer {
    status: reqwest::StatusCode,
    headers: reqwest::header::HeaderMap,
    body: String,
}

impl Tree {
    async fn get(&self, client: &reqwest::Client, host: &str, path: &str) -> Answer {
        self.request(client, host, path, &[], reqwest::Method::GET)
            .await
    }

    async fn request(
        &self,
        client: &reqwest::Client,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        method: reqwest::Method,
    ) -> Answer {
        // The hostname goes in the **URL**, not in a `Host` header, and the client resolves it to
        // the loopback entrypoint. Overriding `Host` looks equivalent and is not: reqwest
        // negotiates HTTP/2 over ALPN, where the authority is a pseudo-header taken from the URL
        // and a `Host` header is ignored — which Traefik answers with a `404` nobody can read a
        // cause out of. Doing it this way also means SNI, the authority and the `Host` header all
        // say the same thing, which is what a browser does.
        let mut request = client.request(method, format!("https://{host}:{}{path}", self.entry));
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.send().await.expect("Traefik should answer");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.unwrap_or_default();
        Answer {
            status,
            headers,
            body,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn traefik_honours_every_promise_the_dialect_makes() {
    if !traefik_present() {
        eprintln!("SKIPPED: traefik is not on PATH");
        return;
    }
    let Some(env_test) = EnvTest::try_start().await else {
        eprintln!("conformance: no envtest binaries; skipping");
        return;
    };
    let admin = env_test.client().expect("client should build");
    install_crd(admin.clone()).await;

    let configs: Api<WeeboSiConfig> = Api::all(admin.clone());
    configs
        .create(
            &PostParams::default(),
            &serde_yaml_bw::from_str::<WeeboSiConfig>(&config_yaml()).expect("config parses"),
        )
        .await
        .expect("the WeeboSiConfig should be accepted");

    let teams: Api<WeeboSiTeam> = Api::all(admin.clone());
    teams
        .create(
            &PostParams::default(),
            &serde_yaml_bw::from_str::<WeeboSiTeam>(&team_yaml()).expect("team parses"),
        )
        .await
        .expect("the WeeboSiTeam should be accepted");

    create_namespace(admin.clone(), "user-alice", "alice").await;
    create_namespace(admin.clone(), "user-bob", "bob").await;
    create_workspace_pod(admin.clone(), "user-alice", "alice-ws", ALICE_POD_IP).await;
    create_workspace_pod(admin.clone(), "user-bob", "bob-ws", BOB_POD_IP).await;
    let alice_token = service_account_token(admin.clone(), "user-alice", "workspace").await;
    let bob_token = service_account_token(admin.clone(), "user-bob", "workspace").await;

    let ingresses: Api<Ingress> = Api::namespaced(admin.clone(), "user-alice");
    ingresses
        .create(
            &PostParams::default(),
            &Ingress {
                metadata: ObjectMeta {
                    name: Some("alice-ws-api".to_string()),
                    namespace: Some("user-alice".to_string()),
                    annotations: Some(BTreeMap::from([(
                        "hardening.weebo.io/rules".to_string(),
                        "- path: /healthz\n  access: open\n  methods: [GET]\n".to_string(),
                    )])),
                    ..Default::default()
                },
                spec: Some(IngressSpec {
                    rules: Some(vec![IngressRule {
                        host: Some(ALICE_HOST.to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("the Ingress should be created");

    // --- the process tree ---------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("temp dir");
    let gateway_port = free_port().expect("a free port");
    let entry_port = free_port().expect("a free port");
    let web_port = free_port().expect("a free port");
    let backend_port = spawn_backend().await;

    let gateway_config = dir.path().join("gateway.yaml");
    std::fs::write(&gateway_config, gateway_yaml(gateway_port, "default"))
        .expect("gateway config should be written");
    let kubeconfig = kubeconfig(dir.path(), env_test.url(), env_test.token());

    let gateway = Command::new(GATEWAY_BIN)
        .arg("--config")
        .arg(&gateway_config)
        .env("KUBECONFIG", &kubeconfig)
        .env("ENDPOINT_GATEWAY_SESSION_KEYS", SESSION_KEYS)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the gateway binary should start");

    let (key_path, cert_path) =
        generate_webhook_tls(dir.path()).expect("a certificate should be generated");
    let dynamic = dir.path().join("dynamic.yaml");
    std::fs::write(
        &dynamic,
        traefik_dynamic(gateway_port, backend_port, &cert_path, &key_path),
    )
    .expect("dynamic config should be written");
    let static_path = dir.path().join("traefik.yaml");
    std::fs::write(&static_path, traefik_static(entry_port, web_port, &dynamic))
        .expect("static config should be written");

    let traefik = Command::new("traefik")
        .arg("--configFile")
        .arg(&static_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("traefik should start");

    let tree = Tree {
        _env_test: env_test,
        traefik,
        gateway,
        entry: entry_port,
        _dir: dir,
    };

    let loopback: std::net::SocketAddr = format!("127.0.0.1:{entry_port}")
        .parse()
        .expect("a loopback address");
    let plain = reqwest::Client::builder()
        // The certificate is generated per run and signed by nobody; what this suite is about is
        // the router's behaviour, not the browser's trust store.
        .danger_accept_invalid_certs(true)
        .resolve(ALICE_HOST, loopback)
        .resolve(BOB_HOST, loopback)
        .resolve(CONTROL_HOST, loopback)
        .build()
        .expect("client should build");
    wait_for(
        &format!("http://127.0.0.1:{gateway_port}/healthz"),
        &plain,
        "the gateway",
    )
    .await;
    // Traefik binds its entrypoint a moment after it is spawned — long enough, on a CI runner,
    // for the first request below to be refused. Any answer at all means it is listening.
    wait_for(
        &format!("https://{ALICE_HOST}:{entry_port}/healthz"),
        &plain,
        "Traefik",
    )
    .await;

    // The informers need a moment to see everything created above; the gate answers `403` for an
    // unknown host until then, which is the right answer and the wrong one to assert on.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answer = tree
            .request(&plain, ALICE_HOST, "/healthz", &[], reqwest::Method::GET)
            .await;
        if answer.status == reqwest::StatusCode::OK || Instant::now() > deadline {
            assert_eq!(
                answer.status,
                reqwest::StatusCode::OK,
                "the open path rule should be reachable once the index is warm: {}",
                answer.body
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // --- the four inbound headers -------------------------------------------------------------
    // Asserted through their consequences rather than by reading them: the gate answers
    // differently for two paths and two methods on the same connection, which is only possible if
    // `X-Forwarded-Uri` and `X-Forwarded-Method` arrive and are the ones it reads. `/healthz` is
    // `open` for `GET` only; everything else on this host is the owner's alone.
    let open = tree.get(&plain, ALICE_HOST, "/healthz").await;
    assert_eq!(open.status, reqwest::StatusCode::OK, "{}", open.body);

    let wrong_method = tree
        .request(&plain, ALICE_HOST, "/healthz", &[], reqwest::Method::POST)
        .await;
    assert_eq!(
        wrong_method.status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a method the rule does not name must not reach the application: {}",
        wrong_method.body
    );

    let closed = tree.get(&plain, ALICE_HOST, "/actuator/env").await;
    assert_eq!(
        closed.status,
        reqwest::StatusCode::UNAUTHORIZED,
        "a path outside the open rule must be challenged: {}",
        closed.body
    );

    // `X-Forwarded-Proto` is the fourth, and the suite is served over TLS precisely so that it
    // arrives as `https`: the gate refuses a plain-HTTP endpoint outright, so a `200` above is
    // itself the assertion that Traefik stated the scheme and the gate believed it.

    // --- a non-2xx auth response reaches the browser verbatim ----------------------------------
    // The one property the two-cookie design cannot work without, and the only one in this file
    // that is purely about Traefik.
    assert!(
        closed
            .headers
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("Bearer realm=")),
        "the gate's WWW-Authenticate must survive the hop: {:?}",
        closed.headers
    );
    assert!(
        closed.body.contains("Not signed in"),
        "the gate's own body must reach the caller, not a Traefik error page: {}",
        closed.body
    );

    // --- an application's own parameter is not mistaken for the gateway's ---------------------
    // `__weebo_grant` is the one query parameter the gate acts on at an endpoint host. Only a
    // value shaped like a grant it sealed is redeemed; the same name carrying anything else is
    // the application's, decided on like any other request rather than refused.
    let namesake = tree
        .get(&plain, ALICE_HOST, "/healthz?__weebo_grant=promo-2026")
        .await;
    assert_eq!(
        namesake.status,
        reqwest::StatusCode::OK,
        "an application's own `__weebo_grant` must reach it on an open path: {}",
        namesake.body
    );

    // --- a spoofed identity header does not reach the application ------------------------------
    // The header the application trusts is the one the gate sets. A caller that can set it
    // themselves has the whole feature.
    let spoofed = tree
        .request(
            &plain,
            ALICE_HOST,
            "/healthz",
            &[("X-Auth-Request-User", "root")],
            reqwest::Method::GET,
        )
        .await;
    assert_eq!(spoofed.status, reqwest::StatusCode::OK);
    // The backend really answered — otherwise the absence below would be the absence of a body
    // rather than the absence of the header, and the assertion would pass for the wrong reason.
    assert!(
        spoofed.body.to_lowercase().contains("x-forwarded-host:"),
        "the backend should have answered: {}",
        spoofed.body
    );
    assert!(
        !spoofed
            .body
            .to_lowercase()
            .contains("x-auth-request-user: root"),
        "a spoofed identity header must not reach the application — Traefik strips every header \
         in `authResponseHeaders` from the inbound request and sets it from the auth response, \
         which is the only reason the application may trust it: {}",
        spoofed.body
    );

    // --- a forged client address is not an identity --------------------------------------------
    // `X-Real-Ip` is what the gate resolves a workspace pod by. A caller stating another
    // namespace's pod address must not become that namespace's owner — if this ever passes, every
    // endpoint in the cluster is reachable by anyone who can guess a pod IP.
    let forged = tree
        .request(
            &plain,
            ALICE_HOST,
            "/actuator/env",
            &[("X-Real-Ip", ALICE_POD_IP)],
            reqwest::Method::GET,
        )
        .await;
    assert_ne!(
        forged.status,
        reqwest::StatusCode::OK,
        "a client-stated pod address must not be an identity: {}",
        forged.body
    );
    // And the mechanism is worth stating, because the gateway here is configured with
    // `trusted_proxy: any` — it *would* believe an `X-Real-Ip` that reached it. It denies because
    // Traefik overwrote the client's copy with the address it saw on the connection, which is
    // exactly what the dialect is relying on and exactly what only a real router can demonstrate.
    assert_eq!(
        forged.status,
        reqwest::StatusCode::UNAUTHORIZED,
        "and the answer is a challenge, not a 403: nothing identified this caller at all: {}",
        forged.body
    );

    // --- a workspace service-account token is an identity, and only of its own namespace -------
    let own = tree
        .request(
            &plain,
            ALICE_HOST,
            "/actuator/env",
            &[("Authorization", &format!("Bearer {alice_token}"))],
            reqwest::Method::GET,
        )
        .await;
    assert_eq!(
        own.status,
        reqwest::StatusCode::OK,
        "alice's own workspace must reach her own endpoint: {}",
        own.body
    );
    assert!(
        own.body.to_lowercase().contains("x-forwarded-host:"),
        "and the request must actually have been carried to the application: {}",
        own.body
    );

    // --- a 403 that blocks ---------------------------------------------------------------------
    // Bob's workspace is a caller the gate recognises and refuses, which is a different answer
    // from "sign in" and must reach the application as nothing at all.
    let theirs = tree
        .request(
            &plain,
            ALICE_HOST,
            "/actuator/env",
            &[("Authorization", &format!("Bearer {bob_token}"))],
            reqwest::Method::GET,
        )
        .await;
    assert_eq!(
        theirs.status,
        reqwest::StatusCode::FORBIDDEN,
        "another workspace is refused rather than challenged: {}",
        theirs.body
    );
    assert!(
        !theirs.body.contains("x-forwarded-host"),
        "a 403 must be the gate's answer, never the application's: {}",
        theirs.body
    );

    // --- the path-confusion corpus, through a real router --------------------------------------
    // The bug class forward-auth gates actually die of: the gate answers about one path and the
    // application serves another, because something between them normalised. Only a real router
    // can settle it — the corpus is in the domain's unit tests as *strings*, and the question
    // here is what Traefik hands over after it has had its own opinion.
    //
    // **Sent with `curl --path-as-is`, not with the Rust client**, and that is the whole reason
    // this block is shaped differently from every other one above: `reqwest` resolves `.` and
    // `..` in the URL before the request leaves the process, so a dot-segment attempt would
    // arrive already collapsed and the assertion would pass without ever having tested anything.
    // An attacker's client does no such favour. `--path-as-is` is the closest thing to writing
    // the request line by hand.
    //
    // `/healthz` is the one open path on this host; every attempt is a way of spelling
    // "something under /actuator" that one of the two layers might read as "/healthz".
    // cspell:ignore factuator fenv -- fragments of the `%2f` encodings below, not words
    for attempt in [
        "/healthz/../actuator/env",
        "/healthz/..%2factuator/env",
        "/healthz%2f..%2factuator%2fenv",
        "/./healthz/../actuator/env",
        "//healthz/../actuator/env",
        "/healthz/./../actuator/env",
        "/healthz/%2e%2e/actuator/env",
    ] {
        let status = raw_get(ALICE_HOST, tree.entry, attempt);
        assert_ne!(
            status, 200,
            "{attempt:?} reached the application: the gate and the router disagree about what \
             path this request has, which is the bug class *Path normalisation* exists to close"
        );
    }

    // ...and the open path itself still answers through the same client, so the loop above is a
    // corpus of refusals rather than a gate — or a `curl` invocation — that refuses everything.
    assert_eq!(
        raw_get(ALICE_HOST, tree.entry, "/healthz"),
        200,
        "the open path must still be reachable when asked for literally"
    );

    // --- what the gate costs, per credential and per protocol -------------------------------
    // RFC 0009's *Request cost* promises p99 under 5 ms for the gate's round trip and says this
    // step tracks it. Two views, because they answer different questions:
    //
    // - **through Traefik**, each row interleaved with the same request to the same backend on a
    //   route with no middleware, so the column that matters is the *difference* and whatever
    //   else the runner is doing lands on both sides alike;
    // - **straight at `/auth`**, the gateway's own service time with no router in front — the
    //   only way to time a credential Traefik cannot carry from a loopback client (a pod's own
    //   address) and to separate the gateway's share from the router's.
    //
    // The rows needing a *user* identity (session cookie, OIDC bearer) cannot be produced here —
    // see the module comment — and are timed in-process by the binary's own `cost` tests.
    let matrix = cost_matrix(
        &tree,
        &admin,
        gateway_port,
        web_port,
        &alice_token,
        &bob_token,
    )
    .await;
    matrix.report();
    let open = matrix
        .row("anonymous, open rule", "HTTPS h1")
        .expect("the open-rule row is always measured");
    assert!(
        open.added_p99() < LAG_BUDGET,
        "the gate adds {:?} at p99 on the open rule, over RFC 0009's {LAG_BUDGET:?} budget — a \
         latency regression in front of every workspace endpoint",
        open.added_p99(),
    );
    let service_account = matrix
        .row("service-account token, cached", "HTTPS h1")
        .expect("the service-account row is always measured");
    assert!(
        service_account.added_p99() < LAG_BUDGET,
        "a cached service-account token costs {:?} at p99 over the ungated route",
        service_account.added_p99(),
    );
}

/// One row of the cost matrix: a credential, a protocol, the statuses the gate answered with,
/// and latencies sorted ascending — through the gate, and around it where a control route exists.
struct CostRow {
    case: &'static str,
    protocol: &'static str,
    statuses: BTreeMap<u16, usize>,
    gated: Vec<Duration>,
    control: Option<Vec<Duration>>,
}

fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    sorted[(sorted.len() - 1) * pct / 100]
}

fn ms(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1e3)
}

impl CostRow {
    /// What the gate adds at `pct`: the difference from the ungated route where there is one,
    /// the whole service time where there is not (the `/auth` rows).
    fn added(&self, pct: usize) -> Duration {
        let gated = percentile(&self.gated, pct);
        self.control.as_ref().map_or(gated, |control| {
            gated.saturating_sub(percentile(control, pct))
        })
    }

    fn added_p99(&self) -> Duration {
        self.added(99)
    }

    fn status(&self) -> String {
        self.statuses
            .iter()
            .map(|(status, count)| {
                if self.statuses.len() == 1 {
                    status.to_string()
                } else {
                    format!("{status}×{count}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

struct CostMatrix {
    rows: Vec<CostRow>,
}

impl CostMatrix {
    fn row(&self, case: &str, protocol: &str) -> Option<&CostRow> {
        self.rows
            .iter()
            .find(|row| row.case == case && row.protocol == protocol)
    }

    /// On stderr always, and in the job summary when GitHub Actions provides one, so the numbers
    /// are read on every run rather than only on the one that fails.
    fn report(&self) {
        // The profile is in the title because it changes the numbers tenfold: CI runs this suite
        // against a debug build, where the margin to the budget is the point, and `--release`
        // gives the figures a production gateway would show.
        let profile = if cfg!(debug_assertions) {
            "debug build"
        } else {
            "release build"
        };
        let mut table = format!(
            "### endpoint-auth cost, per credential and protocol (ms, {profile})\n\n\
             | credential | path | status | gated p50 | gated p99 | ungated p50 | ungated p99 \
             | added p50 | added p99 |\n\
             | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n",
        );
        for row in &self.rows {
            let (control50, control99) = row.control.as_ref().map_or_else(
                || ("—".to_owned(), "—".to_owned()),
                |control| (ms(percentile(control, 50)), ms(percentile(control, 99))),
            );
            table.push_str(&format!(
                "| {} | {} | {} | {} | {} | {control50} | {control99} | {} | {} |\n",
                row.case,
                row.protocol,
                row.status(),
                ms(percentile(&row.gated, 50)),
                ms(percentile(&row.gated, 99)),
                ms(row.added(50)),
                ms(row.added(99)),
            ));
        }
        table.push_str(&format!(
            "\n{LAG_SAMPLES} requests per warm row, {COLD_SAMPLES} per first-use row. \"added\" is \
             gated minus ungated through Traefik, and the whole service time on the `/auth` rows. \
             Budget: p99 added under {} ms (RFC 0009, *Request cost*).\n",
            LAG_BUDGET.as_millis()
        ));
        eprintln!("{table}");
        if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
            use std::io::Write as _;
            if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(summary) {
                let _ = file.write_all(table.as_bytes());
            }
        }
    }
}

async fn timed(request: reqwest::RequestBuilder) -> (u16, Duration) {
    let start = Instant::now();
    let response = request
        .send()
        .await
        .expect("the request should be answered");
    let status = response.status().as_u16();
    // The body is part of the answer a caller waits for; reading it also returns the connection
    // to the pool, so the next request reuses it the way a browser would.
    let _ = response.bytes().await;
    (status, start.elapsed())
}

/// One row: `warmup` unrecorded rounds, then `samples` recorded ones, each gated request
/// followed by the same request on the control route when there is one. `gated` is given the
/// round's index, which is how a first-use row hands every request a credential of its own.
#[allow(
    clippy::too_many_arguments,
    reason = "a row is these seven facts; a struct for them would be a struct used once"
)]
async fn series(
    case: &'static str,
    protocol: &'static str,
    expected: u16,
    warmup: usize,
    samples: usize,
    gated: &dyn Fn(usize) -> reqwest::RequestBuilder,
    control: Option<&dyn Fn() -> reqwest::RequestBuilder>,
) -> CostRow {
    for round in 0..warmup {
        timed(gated(round)).await;
        if let Some(control) = control {
            timed(control()).await;
        }
    }
    let mut statuses = BTreeMap::new();
    let mut times = Vec::with_capacity(samples);
    let mut control_times = control.map(|_| Vec::with_capacity(samples));
    for round in 0..samples {
        let (status, elapsed) = timed(gated(warmup + round)).await;
        *statuses.entry(status).or_insert(0) += 1;
        times.push(elapsed);
        if let (Some(control), Some(control_times)) = (control, control_times.as_mut()) {
            let (status, elapsed) = timed(control()).await;
            assert!(
                status < 400,
                "{case} over {protocol}: the ungated control answered {status}, so its time is \
                 not a baseline"
            );
            control_times.push(elapsed);
        }
    }
    times.sort_unstable();
    if let Some(control_times) = control_times.as_mut() {
        control_times.sort_unstable();
    }
    let row = CostRow {
        case,
        protocol,
        statuses,
        gated: times,
        control: control_times,
    };
    assert_eq!(
        row.statuses.keys().copied().collect::<Vec<_>>(),
        vec![expected],
        "{case} over {protocol}: the gate should answer {expected} every time, answered {}",
        row.status()
    );
    row
}

/// One counter from the gateway's own `/metrics`, `0` when it has not been emitted yet.
async fn gateway_metric(client: &reqwest::Client, gateway_port: u16, name: &str) -> f64 {
    client
        .get(format!("http://127.0.0.1:{gateway_port}/metrics"))
        .send()
        .await
        .expect("the gateway should serve /metrics")
        .text()
        .await
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .filter(|rest| rest.starts_with(' '))
                .and_then(|rest| rest.trim().parse().ok())
        })
        .unwrap_or(0.0)
}

/// A token the apiserver issues for `name` in `namespace` — a new one on every call, so the
/// gateway has never seen it and must ask for a `TokenReview`.
async fn fresh_token(client: kube::Client, namespace: &str, name: &str) -> String {
    let accounts: Api<ServiceAccount> = Api::namespaced(client, namespace);
    let request = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": { "audiences": ["https://kubernetes.default.svc"], "expirationSeconds": 3600 }
    });
    accounts
        .create_subresource::<serde_json::Value, serde_json::Value>(
            "token",
            name,
            &PostParams::default(),
            &request,
        )
        .await
        .expect("a token should be issued")
        .pointer("/status/token")
        .and_then(serde_json::Value::as_str)
        .expect("the token request should carry a token")
        .to_owned()
}

/// A JWT naming this gateway's own issuer (`gateway_yaml`'s), unique per `nonce` and signed by
/// nobody — the token that costs a signature verification on every first sight.
fn forged_oidc_bearer(nonce: usize) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "{}.{}.{}",
        b64.encode(br#"{"alg":"ES256","kid":"forged"}"#),
        b64.encode(
            serde_json::json!({
                "iss": "https://sso.invalid.example/realms/weebo",
                "sub": "nobody",
                "jti": format!("forged-{nonce}"),
            })
            .to_string()
        ),
        b64.encode([0_u8; 64]),
    )
}

/// A token shaped like this cluster's service-account tokens — same issuer, the Kubernetes claim,
/// an expiry in the future — and signed by nobody. It passes every free check, so each fresh one
/// costs the gateway a `TokenReview` until its limits refuse to ask: the flood a caller can aim at
/// the apiserver through the gate.
fn forged_token(like: &str, nonce: usize) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let issuer = like
        .split('.')
        .nth(1)
        .and_then(|payload| b64.decode(payload).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|claims| claims.get("iss").cloned())
        .expect("a real service-account token names its issuer");
    let header = b64.encode(br#"{"alg":"RS256","kid":"forged"}"#);
    let payload = b64.encode(
        serde_json::json!({
            "iss": issuer,
            "sub": "system:serviceaccount:user-alice:workspace",
            "aud": ["https://kubernetes.default.svc"],
            "exp": 4_102_444_800_u64,
            "jti": format!("forged-{nonce}"),
            "kubernetes.io": { "namespace": "user-alice", "serviceaccount": { "name": "workspace" } },
        })
        .to_string(),
    );
    format!("{header}.{payload}.{}", b64.encode(b"not-a-signature"))
}

/// Every row of the matrix. Statuses are asserted as well as timed: a fast `500` is not a fast
/// gate, and a row that silently changed answer would be timing something else.
async fn cost_matrix(
    tree: &Tree,
    admin: &kube::Client,
    gateway_port: u16,
    web_port: u16,
    alice_token: &str,
    bob_token: &str,
) -> CostMatrix {
    let loopback: std::net::SocketAddr = format!("127.0.0.1:{}", tree.entry)
        .parse()
        .expect("a loopback address");
    let build = |builder: reqwest::ClientBuilder| {
        builder
            .danger_accept_invalid_certs(true)
            .resolve(ALICE_HOST, loopback)
            .resolve(CONTROL_HOST, loopback)
            .build()
            .expect("client should build")
    };
    let h1 = build(reqwest::Client::builder().http1_only());
    let h2 = build(reqwest::Client::builder().http2_prior_knowledge());
    // A WebSocket handshake ends its connection's life as HTTP, so nothing is pooled.
    let ws = build(
        reqwest::Client::builder()
            .http1_only()
            .pool_max_idle_per_host(0),
    );
    let plain = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client should build");
    let entry = tree.entry;
    let https = |client: &reqwest::Client, host: &str, path: &str| {
        client.get(format!("https://{host}:{entry}{path}"))
    };
    let bearer = |token: &str| format!("Bearer {token}");
    let mut rows = Vec::new();

    // --- through Traefik, each request next to the same one on an ungated route --------------
    for (protocol, client) in [("HTTPS h1", &h1), ("HTTPS h2", &h2)] {
        rows.push(
            series(
                "anonymous, open rule",
                protocol,
                200,
                30,
                LAG_SAMPLES,
                &|_| https(client, ALICE_HOST, "/healthz"),
                Some(&|| https(client, CONTROL_HOST, "/healthz")),
            )
            .await,
        );
        rows.push(
            series(
                "service-account token, cached",
                protocol,
                200,
                30,
                LAG_SAMPLES,
                &|_| https(client, ALICE_HOST, "/api").header("authorization", bearer(alice_token)),
                Some(&|| {
                    https(client, CONTROL_HOST, "/api").header("authorization", bearer(alice_token))
                }),
            )
            .await,
        );
    }
    rows.push(
        series(
            "anonymous, challenged",
            "HTTPS h1",
            401,
            30,
            LAG_SAMPLES,
            &|_| https(&h1, ALICE_HOST, "/api").header("accept", "application/json"),
            Some(&|| https(&h1, CONTROL_HOST, "/api").header("accept", "application/json")),
        )
        .await,
    );
    rows.push(
        series(
            "another workspace's token, denied",
            "HTTPS h1",
            403,
            30,
            LAG_SAMPLES,
            &|_| https(&h1, ALICE_HOST, "/api").header("authorization", bearer(bob_token)),
            Some(&|| https(&h1, CONTROL_HOST, "/api").header("authorization", bearer(bob_token))),
        )
        .await,
    );
    let handshake = |client: &reqwest::Client, host: &str| {
        https(client, host, "/ws")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("authorization", bearer(alice_token))
    };
    rows.push(
        series(
            "service-account token, cached",
            "WebSocket handshake",
            101,
            10,
            LAG_SAMPLES,
            &|_| handshake(&ws, ALICE_HOST),
            Some(&|| handshake(&ws, CONTROL_HOST)),
        )
        .await,
    );
    let web = |host: &str| {
        plain
            .get(format!("http://127.0.0.1:{web_port}/healthz"))
            .header("host", host.to_owned())
    };
    rows.push(
        series(
            "anonymous, open rule",
            "plain HTTP (refused)",
            421,
            30,
            LAG_SAMPLES,
            &|_| web(ALICE_HOST),
            Some(&|| web(CONTROL_HOST)),
        )
        .await,
    );

    // --- straight at /auth: the gateway's own service time --------------------------------------
    let direct = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client should build");
    let auth = |path: &str| {
        direct
            .get(format!("http://127.0.0.1:{gateway_port}/auth"))
            .header("x-forwarded-host", ALICE_HOST)
            .header("x-forwarded-uri", path.to_owned())
            .header("x-forwarded-method", "GET")
            .header("x-forwarded-proto", "https")
    };
    rows.push(
        series(
            "anonymous, open rule",
            "/auth direct",
            200,
            30,
            LAG_SAMPLES,
            &|_| auth("/healthz"),
            None,
        )
        .await,
    );
    rows.push(
        series(
            "service-account token, cached",
            "/auth direct",
            200,
            30,
            LAG_SAMPLES,
            &|_| auth("/api").header("authorization", bearer(alice_token)),
            None,
        )
        .await,
    );
    rows.push(
        series(
            "pod's own address",
            "/auth direct",
            200,
            30,
            LAG_SAMPLES,
            &|_| auth("/api").header("x-real-ip", ALICE_POD_IP),
            None,
        )
        .await,
    );
    rows.push(
        series(
            "anonymous, challenged",
            "/auth direct",
            401,
            30,
            LAG_SAMPLES,
            &|_| auth("/api").header("accept", "application/json"),
            None,
        )
        .await,
    );
    let mut fresh = Vec::with_capacity(COLD_SAMPLES);
    for _ in 0..COLD_SAMPLES {
        fresh.push(fresh_token(admin.clone(), "user-alice", "workspace").await);
    }
    rows.push(
        series(
            "service-account token, first use",
            "/auth direct",
            200,
            0,
            COLD_SAMPLES,
            &|round| auth("/api").header("authorization", bearer(&fresh[round])),
            None,
        )
        .await,
    );
    rows.push(
        series(
            "forged service-account token, fresh each",
            "/auth direct",
            401,
            0,
            COLD_SAMPLES,
            &|round| {
                auth("/api").header("authorization", bearer(&forged_token(alice_token, round)))
            },
            None,
        )
        .await,
    );
    // The limiter, exercised rather than assumed: one client (the address a router states in
    // `X-Real-Ip`) sending fresh forged tokens. Past the per-client burst the gateway must stop
    // asking the apiserver — the throttled counter moves by the overflow, and the row's median
    // falls to an answer with no round trip in it. Without the header, the direct rows above
    // are held to the global limit only, which is why they each paid a `TokenReview`.
    let throttled_before = gateway_metric(
        &direct,
        gateway_port,
        "weebo_si_endpoint_auth_token_reviews_throttled_total",
    )
    .await;
    let flood = series(
        "forged service-account token, one client flooding",
        "/auth direct",
        401,
        0,
        FLOOD_SAMPLES,
        &|round| {
            auth("/api").header("x-real-ip", "198.51.100.7").header(
                "authorization",
                bearer(&forged_token(alice_token, 10_000 + round)),
            )
        },
        None,
    )
    .await;
    let throttled = gateway_metric(
        &direct,
        gateway_port,
        "weebo_si_endpoint_auth_token_reviews_throttled_total",
    )
    .await
        - throttled_before;
    assert!(
        throttled >= (FLOOD_SAMPLES - PER_CLIENT_REVIEW_BURST) as f64 - 2.0,
        "one client sent {FLOOD_SAMPLES} fresh forged tokens and only {throttled} were refused a \
         TokenReview — the per-client limit (burst {PER_CLIENT_REVIEW_BURST}) is not holding, \
         so one caller can spend the apiserver's budget"
    );
    let reviewed = rows
        .iter()
        .find(|row| row.case == "forged service-account token, fresh each")
        .map(|row| percentile(&row.gated, 50))
        .expect("the unthrottled forged row is measured above");
    assert!(
        percentile(&flood.gated, 50) < reviewed,
        "a throttled forged token should answer faster than one that cost a TokenReview \
         ({:?} vs {reviewed:?})",
        percentile(&flood.gated, 50)
    );
    rows.push(flood);

    // The same for bearer signatures: fresh tokens naming *this gateway's* issuer are the ones
    // that cost a signature verification, so one client sending them past the per-client burst
    // must stop being verified. (The issuer here is never reached, so every one is refused
    // either way — what is asserted is that the gateway stopped trying.)
    let verified_before = gateway_metric(
        &direct,
        gateway_port,
        "weebo_si_endpoint_auth_bearer_verifications_throttled_total",
    )
    .await;
    rows.push(
        series(
            "forged OIDC bearer, one client flooding",
            "/auth direct",
            401,
            0,
            FLOOD_SAMPLES,
            &|round| {
                auth("/api")
                    .header("x-real-ip", "203.0.113.9")
                    .header("authorization", bearer(&forged_oidc_bearer(round)))
            },
            None,
        )
        .await,
    );
    let refused = gateway_metric(
        &direct,
        gateway_port,
        "weebo_si_endpoint_auth_bearer_verifications_throttled_total",
    )
    .await
        - verified_before;
    assert!(
        refused >= (FLOOD_SAMPLES - PER_CLIENT_VERIFY_BURST) as f64 - 2.0,
        "one client sent {FLOOD_SAMPLES} fresh bearers naming this gateway's issuer and only \
         {refused} were refused a verification — the per-client limit (burst \
         {PER_CLIENT_VERIFY_BURST}) is not holding"
    );
    rows.push(
        series(
            "opaque bearer, fresh each",
            "/auth direct",
            401,
            0,
            COLD_SAMPLES,
            &|round| auth("/api").header("authorization", bearer(&format!("opaque-{round}"))),
            None,
        )
        .await,
    );
    // Hundreds of challenges to one host for one reason went by above: the decision log must
    // have stopped writing a line for each of them (`logging.deny_per_minute`).
    assert!(
        gateway_metric(
            &direct,
            gateway_port,
            "weebo_si_endpoint_auth_log_lines_suppressed_total",
        )
        .await
            > 0.0,
        "a loop of refused requests must not be a log line per request"
    );
    CostMatrix { rows }
}

/// One request with the path exactly as written, and nothing normalising it on the way out.
///
/// Shelling out to `curl` rather than reaching for another Rust HTTP client: every one of them
/// parses the target into a URL type that collapses dot segments, which is correct of a client
/// and useless for a test about what an incorrect client can send.
fn raw_get(host: &str, entry: u16, path: &str) -> u16 {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--insecure",
            "--path-as-is",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--resolve",
            &format!("{host}:{entry}:127.0.0.1"),
            &format!("https://{host}:{entry}{path}"),
        ])
        .output()
        .expect("curl should run");
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or_else(|_| {
            panic!(
                "curl should report a status for {path:?}: {:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}
