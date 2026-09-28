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
      rule: "HostRegexp(`^.+{}$`)"
      entryPoints: [websecure]
      service: backend
      middlewares: [endpoint-auth]
      tls: {{}}
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
    - certFile: "{}"
      keyFile: "{}"
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

fn traefik_static(entry: u16, dynamic: &Path) -> String {
    format!(
        r#"
entryPoints:
  websecure:
    address: "127.0.0.1:{entry}"
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

/// A backend that answers `200` with the request's own headers as the body, so an assertion can
/// be about *what the application was handed* rather than about what we hope Traefik forwarded.
async fn spawn_backend() -> u16 {
    use axum::Router;
    use axum::http::HeaderMap;
    use axum::routing::any;

    let port = free_port().expect("a free port");
    let app = Router::new().fallback(any(|headers: HeaderMap| async move {
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
        lines.join("\n")
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
    std::fs::write(&static_path, traefik_static(entry_port, &dynamic))
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
        .build()
        .expect("client should build");
    wait_for(
        &format!("http://127.0.0.1:{gateway_port}/healthz"),
        &plain,
        "the gateway",
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
