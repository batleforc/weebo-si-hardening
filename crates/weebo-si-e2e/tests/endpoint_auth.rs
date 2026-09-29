//! The endpoint-auth suite: the `Nginx` dialect, the real endpoint gateway and the rig's
//! Keycloak, asserted over HTTPS through the real ingress controller against a workspace Che
//! actually started — the path a developer's browser takes, minus the browser.
//!
//! What the `Nginx` dialect cannot do is not asserted as if it could: a refusal reaches the caller
//! without its body (ground-truth row 6a), and a challenge to a non-browser caller is the `302`
//! `auth-signin` writes (row 6c). docs/bricks/endpoint-gateway.md *Ground truth* is the reference
//! for every expected status below.
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
    WorkspaceSpec, apply, get, json, kubectl, must, set_features, team, text, wait_until,
};

fn endpoint_auth() -> Value {
    json!({
        "mode": "Enforce",
        "gateway": {
            "externalUrl": format!("https://auth.{DOMAIN}"),
            "service": { "name": "endpoint-gateway", "namespace": OPERATOR_NAMESPACE, "port": 4180 },
            "dialect": "Nginx",
        },
        "owner": {
            "namespaceAnnotation": "che.eclipse.org/username",
            "devworkspaceOperatorIdentity":
                "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount",
        },
        "hosts": {
            "suffix": format!(".{DOMAIN}"),
            "ownership": [{ "template": "{user}-{workspace}-{endpoint}" }],
            "exclude": [DOMAIN, format!("auth.{DOMAIN}"), format!("sso.{DOMAIN}"), format!("eclipse-che.{DOMAIN}")],
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
                .find(|ingress| {
                    text(
                        ingress,
                        "/metadata/annotations/controller.devfile.io~1endpoint_name",
                    ) == "web"
                })
                .ok_or("no Ingress for endpoint web yet")?;
            if text(
                &web,
                "/metadata/annotations/nginx.ingress.kubernetes.io~1auth-url",
            )
            .is_empty()
            {
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
    let auth_url = text(
        &ingress,
        "/metadata/annotations/nginx.ingress.kubernetes.io~1auth-url",
    );
    assert!(
        auth_url.starts_with(&format!(
            "http://endpoint-gateway.{OPERATOR_NAMESPACE}.svc:4180/auth?"
        )),
        "auth-url {auth_url}"
    );
    assert_eq!(
        text(
            &ingress,
            "/metadata/annotations/nginx.ingress.kubernetes.io~1auth-always-set-cookie"
        ),
        "true"
    );
    Served {
        workspace,
        host: text(&ingress, "/spec/rules/0/host"),
    }
}

fn status(
    ingress: &Ingress,
    host: &str,
    path: &str,
    bearer: Option<&str>,
) -> (u16, String, String) {
    let mut request = ingress.client.get(ingress.url(host, path));
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .unwrap_or_else(|err| panic!("GET https://{host}{path}: {err}"));
    let code = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (code, location, response.text().unwrap_or_default())
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

    let (code, location, _) = status(&ingress, &served.host, "/", None);
    assert_eq!(code, 302, "an anonymous caller is sent to sign in");
    assert!(
        location.starts_with(&format!("https://auth.{DOMAIN}/oidc/start?rd=")),
        "location {location}"
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
    let (code, _, _) = status(&ingress, &served.host, "/", None);
    assert_eq!(code, 302, "every other path stays behind the gate");
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

    let response = ingress
        .client
        .get(ingress.url(&served.host, "/headers"))
        .bearer_auth(ingress.token("alice"))
        .header("X-Auth-Request-User", "bob")
        .header("X-Auth-Request-Groups", "platform-admins")
        .send()
        .unwrap();
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
            "nginx.ingress.kubernetes.io/auth-url",
            "http://nowhere.invalid/",
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
    let answer = through_proxy();
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
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
        answer.starts_with("HTTP/1.1 200"),
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
