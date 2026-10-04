//! The endpoint-auth suite: the `Traefik` dialect, the real endpoint gateway and the rig's
//! Keycloak, asserted over HTTPS through the real ingress controller against a workspace Che
//! actually started — the path a developer's browser takes, minus the browser.
//!
//! Traefik hands the gate's answer back verbatim (ground-truth row 9), so both challenge shapes
//! are asserted: a navigation is redirected to sign in, anything else is a `401` naming the
//! scheme. docs/bricks/endpoint-gateway.md *Ground truth* is the reference for every expected
//! status below.
//!
//! People: alice owns the workspaces; carol shares alice's team; bob is in no team with either.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use weebo_si_e2e::{
    Cleanup, DOMAIN, Endpoint, Ingress, Namespace, OPERATOR_NAMESPACE, RECONCILE, Value, Workspace,
    WorkspaceSpec, apply, gateway_metric_sum, get, json, kubectl, must, set_features, team, text,
    wait_until,
};

fn endpoint_auth() -> Value {
    json!({
        "mode": "Enforce",
        "gateway": {
            "externalUrl": format!("https://auth.{DOMAIN}"),
            "service": { "name": "endpoint-gateway", "namespace": OPERATOR_NAMESPACE, "port": 4180 },
            "dialect": "Traefik",
        },
        "owner": {
            "namespaceAnnotation": "che.eclipse.org/username",
            // Not DWO's own account: a `routingClass: che` workspace's routing objects are
            // written by the routing controller che-operator embeds, under che-operator's account.
            "devworkspaceOperatorIdentity": "system:serviceaccount:eclipse-che:che-operator",
        },
        "hosts": {
            "suffix": format!(".{DOMAIN}"),
            "ownership": [{ "template": "{user}-{workspace}-{endpoint}" }],
            "exclude": [DOMAIN, format!("auth.{DOMAIN}"), format!("sso.{DOMAIN}"), format!("eclipse-che.{DOMAIN}"), format!("control.{DOMAIN}")],
        },
        "catalog": [{ "key": "private", "delegation": [] }],
        "default": "private",
    })
}

/// Team `payments` — alice's and carol's namespaces — reaches `team` and `open` on top of the
/// cluster's `private`.
fn payments_team() -> Cleanup {
    team(
        "e2e-payments",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "payments" } },
            "features": { "endpointAuth": {
                "catalog": [
                    { "key": "team", "delegation": ["Team"] },
                    { "key": "open", "anonymous": true, "delegation": [] },
                ],
                "default": "private",
            } },
        }),
    )
}

/// A served workspace and the host Che routed its one endpoint to.
struct Served {
    workspace: Workspace,
    host: String,
}

/// Start a workspace in `ns` whose `web` endpoint carries `annotation`, and wait until the
/// Ingress Che generates for it carries the gate.
fn serve(ns: &Namespace, name: &str, annotation: Value) -> Served {
    let mut annotation = annotation;
    annotation["hardening.weebo.io/endpoint-auth"] = json!("managed");
    let endpoints = [Endpoint {
        name: "web",
        port: 8080,
        exposure: "public",
        annotation,
    }];
    let workspace = Workspace::create(
        &ns.name,
        name,
        &WorkspaceSpec {
            endpoints: &endpoints,
            ..WorkspaceSpec::default()
        },
    );
    workspace.wait_running();
    let id = workspace.id();
    let ingress = wait_until(
        "the gated Ingress Che generated for `web`",
        RECONCILE,
        || {
            let list = get(&[
                "ingress",
                "-n",
                &ns.name,
                "-l",
                &format!("controller.devfile.io/devworkspace_id={id}"),
            ])
            .ok_or("no list")?;
            let items = list
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let web = items
                .into_iter()
                // `che.routing…/endpoint-name` is what Che's routing solver writes; DWO's own
                // `controller.devfile.io/endpoint_name` only appears under `routingClass: basic`.
                .find(|ingress| {
                    text(
                        ingress,
                        "/metadata/annotations/che.routing.controller.devfile.io~1endpoint-name",
                    ) == "web"
                })
                .ok_or("no Ingress for endpoint web yet")?;
            if text(&web, MIDDLEWARES).is_empty() {
                return Err(format!(
                    "not gated yet: {}",
                    web.pointer("/metadata/annotations")
                        .cloned()
                        .unwrap_or_default()
                ));
            }
            Ok(web)
        },
    );
    // The chain is pinned by value: the shared `Middleware` in the operator's namespace, alone.
    assert_eq!(
        text(&ingress, MIDDLEWARES),
        format!("{OPERATOR_NAMESPACE}-weebo-si-endpoint-auth@kubernetescrd")
    );
    Served {
        workspace,
        host: text(&ingress, "/spec/rules/0/host"),
    }
}

/// Where the `Traefik` dialect attaches the gate, as a JSON pointer into an `Ingress`.
const MIDDLEWARES: &str = "/metadata/annotations/traefik.ingress.kubernetes.io~1router.middlewares";

/// Send a request, sending it again while Traefik has not routed the host yet.
///
/// Traefik answers 404 until it has loaded an Ingress it has just seen — and the `Middleware` that
/// Ingress names — and 503 while a backend has no endpoints; no row here expects either, so they
/// are waited out rather than asserted on.
fn settled(send: impl Fn() -> reqwest::blocking::Response) -> reqwest::blocking::Response {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut response = send();
    while matches!(response.status().as_u16(), 404 | 503) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_secs(3));
        response = send();
    }
    response
}

fn status(
    ingress: &Ingress,
    host: &str,
    path: &str,
    bearer: Option<&str>,
) -> (u16, String, String) {
    let response = settled(|| {
        let mut request = ingress.client.get(ingress.url(host, path));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .unwrap_or_else(|err| panic!("GET https://{host}{path}: {err}"))
    });
    let code = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (code, location, response.text().unwrap_or_default())
}

/// An anonymous `GET` shaped like a browser navigation: the status and the `Location`.
fn navigate(ingress: &Ingress, host: &str, path: &str) -> (u16, String) {
    let response = settled(|| {
        ingress
            .client
            .get(ingress.url(host, path))
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .unwrap_or_else(|err| panic!("GET https://{host}{path}: {err}"))
    });
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (response.status().as_u16(), location)
}

/// An anonymous `GET` that is not a navigation: the status and the `WWW-Authenticate`.
fn unauthenticated(ingress: &Ingress, host: &str, path: &str) -> (u16, String) {
    let response = settled(|| {
        ingress
            .client
            .get(ingress.url(host, path))
            .send()
            .unwrap_or_else(|err| panic!("GET https://{host}{path}: {err}"))
    });
    let authenticate = response
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (response.status().as_u16(), authenticate)
}

fn setup() -> Cleanup {
    let team = payments_team();
    set_features(json!({ "endpointAuth": endpoint_auth() }));
    team
}

#[test]
fn the_owner_opens_their_endpoint_and_nobody_else_does() {
    let _team = setup();
    let ns = Namespace::workspace("alice", "gate-private", Some("payments"));
    let served = serve(&ns, "private", json!({}));
    let ingress = Ingress::open();

    let (code, location) = navigate(&ingress, &served.host, "/");
    assert_eq!(code, 302, "an anonymous browser is sent to sign in");
    assert!(
        location.starts_with(&format!("https://auth.{DOMAIN}/host-session?rd=")),
        "location {location}"
    );
    let (code, authenticate) = unauthenticated(&ingress, &served.host, "/");
    assert_eq!(
        code, 401,
        "an anonymous non-browser caller is told how to authenticate"
    );
    assert!(
        authenticate.starts_with("Bearer realm=\"weebo\""),
        "WWW-Authenticate {authenticate}"
    );

    let (code, _, body) = status(&ingress, &served.host, "/", Some(&ingress.token("alice")));
    assert_eq!((code, body.as_str()), (200, "hello from the workspace\n"));

    for stranger in ["bob", "carol"] {
        let (code, _, _) = status(&ingress, &served.host, "/", Some(&ingress.token(stranger)));
        assert_eq!(
            code, 403,
            "{stranger} may not open alice's private endpoint"
        );
    }
    drop(served.workspace);
}

#[test]
fn a_team_endpoint_opens_to_a_teammate_and_stays_shut_to_a_stranger() {
    let _team = setup();
    let alice = Namespace::workspace("alice", "gate-team", Some("payments"));
    // Team membership is derived from namespace ownership: carol is a member because she owns
    // a namespace the team selects.
    let _carol = Namespace::workspace("carol", "gate-team", Some("payments"));
    let served = serve(
        &alice,
        "shared",
        json!({ "hardening.weebo.io/access": "team" }),
    );
    let ingress = Ingress::open();

    let (code, _, _) = status(&ingress, &served.host, "/", Some(&ingress.token("carol")));
    assert_eq!(code, 200, "carol shares alice's team");
    let (code, _, _) = status(&ingress, &served.host, "/", Some(&ingress.token("bob")));
    assert_eq!(code, 403, "bob does not");
}

#[test]
fn an_open_rule_serves_one_path_to_anybody_and_nothing_else() {
    let _team = setup();
    let ns = Namespace::workspace("alice", "gate-open", Some("payments"));
    let served = serve(
        &ns,
        "health",
        json!({ "hardening.weebo.io/rules": "- { path: /healthz, match: exact, access: open }" }),
    );
    let ingress = Ingress::open();

    let (code, _, body) = status(&ingress, &served.host, "/healthz", None);
    assert_eq!((code, body.as_str()), (200, "ok\n"));
    let (code, _) = unauthenticated(&ingress, &served.host, "/");
    assert_eq!(code, 401, "every other path stays behind the gate");
    let (code, _, _) = status(&ingress, &served.host, "/healthz/../", None);
    assert_ne!(
        code, 200,
        "a path that normalises elsewhere must not ride the open rule"
    );
}

#[test]
fn a_workspace_proves_itself_with_its_own_service_account_token_and_not_with_another() {
    let _team = setup();
    let own = Namespace::workspace("alice", "gate-sa", Some("payments"));
    let other = Namespace::workspace("bob", "gate-sa", None);
    let served = serve(&own, "self", json!({}));
    let ingress = Ingress::open();

    let own_token = must(&["create", "token", "default", "-n", &own.name]);
    let (code, _, _) = status(&ingress, &served.host, "/", Some(own_token.trim()));
    assert_eq!(
        code, 200,
        "the workspace's own namespace may call its own endpoint"
    );

    let foreign_token = must(&["create", "token", "default", "-n", &other.name]);
    let (code, _, _) = status(&ingress, &served.host, "/", Some(foreign_token.trim()));
    assert_eq!(code, 403, "another namespace's service account may not");
}

#[test]
fn a_caller_stated_identity_never_reaches_the_workspace() {
    let _team = setup();
    let ns = Namespace::workspace("alice", "gate-spoof", Some("payments"));
    let served = serve(&ns, "echo", json!({}));
    let ingress = Ingress::open();

    let token = ingress.token("alice");
    let response = settled(|| {
        ingress
            .client
            .get(ingress.url(&served.host, "/headers"))
            .bearer_auth(&token)
            .header("X-Auth-Request-User", "bob")
            .header("X-Auth-Request-Groups", "platform-admins")
            .send()
            .unwrap()
    });
    assert_eq!(response.status().as_u16(), 200);
    let headers: Value = response.json().unwrap();
    let seen = |name: &str| {
        headers
            .as_object()
            .and_then(|map| map.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)))
            .map(|(_, value)| value.as_str().unwrap_or_default().to_string())
            .unwrap_or_default()
    };
    assert_ne!(
        seen("X-Auth-Request-User"),
        "bob",
        "a forged identity reached the workspace: {headers}"
    );
    assert!(
        !seen("X-Auth-Request-Groups").contains("platform-admins"),
        "{headers}"
    );
}

#[test]
fn a_developer_cannot_take_the_gate_off_their_own_endpoint() {
    let _team = setup();
    let ns = Namespace::workspace("alice", "gate-bypass", Some("payments"));
    // What Che grants a user in their own namespace.
    apply(
        &json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": { "name": "alice-admin", "namespace": ns.name },
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "admin" },
            "subjects": [{ "apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "alice" }],
        })
        .to_string(),
    );
    let served = serve(&ns, "mine", json!({}));
    let ingress_name = must(&[
        "get",
        "ingress",
        "-n",
        &ns.name,
        "-l",
        &format!(
            "controller.devfile.io/devworkspace_id={}",
            served.workspace.id()
        ),
        "-o",
        "jsonpath={.items[0].metadata.name}",
    ]);

    for (key, value) in [
        ("hardening.weebo.io/endpoint-auth", "bypass"),
        (
            "traefik.ingress.kubernetes.io/router.middlewares",
            "default-nothing@kubernetescrd",
        ),
    ] {
        let err = kubectl(&[
            "annotate",
            "--overwrite",
            "ingress",
            "-n",
            &ns.name,
            &ingress_name,
            &format!("{key}={value}"),
            "--as=alice",
        ])
        .expect_err("a developer rewriting the gate must be refused");
        assert!(err.contains("denied"), "{key}: {err}");
    }
}

#[test]
fn preauth_proxy_logs_in_once_injects_the_credential_and_renews_it_on_a_401() {
    let ns = Namespace::workspace("alice", "preauth", Some("payments"));
    // The application: serve.py, with the one credential it accepts.
    apply(
        &json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": { "name": "app-login", "namespace": ns.name },
            "stringData": { "user": "robot", "secret": "robot & secret=1" },
        })
        .to_string(),
    );
    apply(
        &json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": { "name": "app", "namespace": ns.name },
            "spec": {
                "selector": { "matchLabels": { "app": "app" } },
                "template": {
                    "metadata": { "labels": { "app": "app" } },
                    "spec": { "containers": [{
                        "name": "app", "image": weebo_si_e2e::WORKSPACE_IMAGE,
                        "env": [
                            { "name": "E2E_LOGIN_USER", "valueFrom": { "secretKeyRef": { "name": "app-login", "key": "user" } } },
                            { "name": "E2E_LOGIN_SECRET", "valueFrom": { "secretKeyRef": { "name": "app-login", "key": "secret" } } },
                        ],
                    }] },
                },
            },
        })
        .to_string(),
    );
    must(&["expose", "deployment", "app", "-n", &ns.name, "--port=8080"]);
    must(&[
        "rollout",
        "status",
        "deployment/app",
        "-n",
        &ns.name,
        "--timeout=300s",
    ]);

    let config = "listen: \"[::]:8080\"\n\
                  upstream: \"http://app:8080\"\n\
                  passthrough: { header: Cookie, contains: \"session=\" }\n\
                  credential:\n  origin: \"http://app:8080\"\n  request:\n    method: POST\n    path: /login\n    \
                  headers: { Content-Type: application/x-www-form-urlencoded }\n    \
                  body: \"email=${CRED_USER}&password=${CRED_SECRET}\"\n  accept_status: [200]\n  \
                  extract: { from_header: Set-Cookie, take: cookie-pair }\n\
                  inject: { header: Cookie, mode: append }\n\
                  renew: { on_status: [401], max_replays: 1 }\n";
    let values = std::env::temp_dir().join(format!("preauth-{}.yaml", ns.name));
    std::fs::write(
        &values,
        format!(
            "image: {{ repository: localhost/preauth-proxy, tag: e2e, pullPolicy: Never }}\n\
             credentials: {{ existingSecret: app-login }}\n\
             config: |\n{}",
            config
                .lines()
                .map(|line| format!("  {line}\n"))
                .collect::<String>()
        ),
    )
    .unwrap();
    let helm = std::process::Command::new("helm")
        .args([
            "upgrade",
            "--install",
            "preauth-proxy",
            &format!("{}/charts/preauth-proxy", weebo_si_e2e::repo_root()),
            "-n",
            &ns.name,
            "-f",
            values.to_str().unwrap(),
            "--wait",
            "--timeout",
            "5m",
        ])
        .output()
        .unwrap();
    assert!(
        helm.status.success(),
        "helm: {}",
        String::from_utf8_lossy(&helm.stderr)
    );

    // Asked from inside the namespace, the way the gated Ingress in front of it would.
    let through_proxy = || {
        must(&[
            "exec",
            "-n",
            &ns.name,
            "deploy/app",
            "--",
            "curl",
            "-s",
            "-i",
            "--max-time",
            "10",
            "http://preauth-proxy:8080/private",
        ])
    };
    // The status line's version is the upstream's own — the app is Python's `http.server`, which
    // answers HTTP/1.0, and the proxy relays that as it is — so only the code is asserted.
    let is_ok = |answer: &str| answer.split_whitespace().nth(1) == Some("200");
    let answer = through_proxy();
    assert!(is_ok(&answer), "{answer}");
    assert!(answer.contains("private data"), "{answer}");
    assert!(
        !answer.to_ascii_lowercase().contains("set-cookie: session="),
        "the upstream's session must not be handed to the caller: {answer}"
    );

    // The credential goes stale behind the proxy's back; the next request is renewed and replayed.
    must(&[
        "exec",
        "-n",
        &ns.name,
        "deploy/app",
        "--",
        "curl",
        "-s",
        "-X",
        "POST",
        "http://localhost:8080/expire",
    ]);
    let answer = through_proxy();
    assert!(
        is_ok(&answer),
        "a 401 must be renewed and replayed: {answer}"
    );
    let logs = must(&["logs", "-n", &ns.name, "deploy/preauth-proxy"]);
    assert!(logs.contains("acquired credential from origin"), "{logs}");
    assert!(
        logs.contains("re-acquired and replayed 1 time(s)"),
        "{logs}"
    );
    let _ = std::fs::remove_file(values);
}

/// RFC 0009's *Request cost*, in the cluster rather than on loopback: the same workspace reached
/// through Traefik with the gate and without it, interleaved, so the difference is the gate's
/// in-cluster hop — the `forwardAuth` call, the gateway's decision and the way back. And RFC
/// 0009's rule 1, *connection reuse is part of the contract*: a burst of gated requests costs the
/// gateway a handful of connections, not one per request. Traefik keeps two idle connections per
/// gateway address and these requests go one at a time, so a burst rides one or two of them.
#[test]
fn the_gate_costs_a_short_in_cluster_hop_on_connections_it_keeps() {
    const SAMPLES: usize = 200;
    let _team = setup();
    let ns = Namespace::workspace("alice", "gate-cost", Some("payments"));
    let served = serve(
        &ns,
        "cost",
        json!({ "hardening.weebo.io/rules": "- { path: /healthz, match: exact, access: open }" }),
    );

    // The ungated control: an Ingress outside the webhook's scope, on a host the gate excludes,
    // pointed at the same workspace `Service` through an ExternalName.
    let backend = get(&[
        "ingress",
        "-n",
        &ns.name,
        "-l",
        &format!(
            "controller.devfile.io/devworkspace_id={}",
            served.workspace.id()
        ),
    ])
    .and_then(|list| {
        list.pointer("/items/0/spec/rules/0/http/paths/0/backend/service")
            .cloned()
    })
    .expect("the gated Ingress names its backend");
    let (service, port) = (
        text(&backend, "/name"),
        backend
            .pointer("/port/number")
            .and_then(Value::as_u64)
            .expect("the backend names a port number"),
    );
    let control_ns = format!("{}-control", ns.name);
    let control_host = format!("control.{DOMAIN}");
    apply(
        &json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": { "name": control_ns, "labels": { "hardening.weebo.io/exclude": "true" } },
        })
        .to_string(),
    );
    let _control = Cleanup::new(&["namespace", &control_ns]);
    apply(
        &json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": { "name": "workspace", "namespace": control_ns },
            "spec": {
                "type": "ExternalName",
                "externalName": format!("{service}.{}.svc.cluster.local", ns.name),
                "ports": [{ "port": port }],
            },
        })
        .to_string(),
    );
    apply(
        &json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": { "name": "control", "namespace": control_ns },
            "spec": {
                "ingressClassName": "traefik",
                "tls": [{ "hosts": [control_host] }],
                "rules": [{ "host": control_host, "http": { "paths": [{
                    "path": "/", "pathType": "Prefix",
                    "backend": { "service": { "name": "workspace", "port": { "number": port } } },
                }] } }],
            },
        })
        .to_string(),
    );

    let ingress = Ingress::open();
    wait_until("the ungated control route", RECONCILE, || {
        let (code, _, _) = status(&ingress, &control_host, "/healthz", None);
        if code == 200 {
            Ok(())
        } else {
            Err(format!("{code}"))
        }
    });
    let timed = |host: &str| {
        let start = std::time::Instant::now();
        let (code, _, _) = status(&ingress, host, "/healthz", None);
        assert_eq!(code, 200, "{host}/healthz");
        start.elapsed()
    };
    for _ in 0..20 {
        timed(&served.host);
        timed(&control_host);
    }

    let accepted = "weebo_si_endpoint_auth_connections_accepted_total";
    let before = gateway_metric_sum(accepted, &[]);
    let mut gated = Vec::with_capacity(SAMPLES);
    let mut ungated = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        gated.push(timed(&served.host));
        ungated.push(timed(&control_host));
    }
    let opened = gateway_metric_sum(accepted, &[]) - before;

    gated.sort_unstable();
    ungated.sort_unstable();
    let at = |sorted: &[std::time::Duration], pct: usize| sorted[(sorted.len() - 1) * pct / 100];
    let added = |pct: usize| at(&gated, pct).saturating_sub(at(&ungated, pct));
    let report = format!(
        "### endpoint-auth, in-cluster hop through Traefik ({SAMPLES} requests per side)\n\n\
         | | gated | ungated | added |\n| --- | --- | --- | --- |\n\
         | p50 | {:?} | {:?} | {:?} |\n| p99 | {:?} | {:?} | {:?} |\n\n\
         Connections the gateway accepted for {SAMPLES} gated requests: {opened}.\n",
        at(&gated, 50),
        at(&ungated, 50),
        added(50),
        at(&gated, 99),
        at(&ungated, 99),
        added(99),
    );
    eprintln!("{report}");
    if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY")
        && let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(summary)
    {
        let _ = std::io::Write::write_all(&mut file, report.as_bytes());
    }

    assert!(
        added(50) < std::time::Duration::from_millis(5),
        "the gate adds {:?} at p50 in the cluster — over RFC 0009's 5 ms budget",
        added(50)
    );
    // Two is Traefik's idle pool; the slack is for a gateway pod closing an idle connection
    // mid-burst, not for re-dialling per request.
    assert!(
        opened <= 4.0,
        "{SAMPLES} gated requests opened {opened} connections to the gateway — Traefik is not \
         keeping its `forwardAuth` connections"
    );
}
