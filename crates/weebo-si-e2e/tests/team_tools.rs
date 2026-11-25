//! The team-tools suite: RFC 0020's *Proof against a real client*, observations 1–3, 5–9 and 12,
//! plus E2 (the chart's RBAC), with a real BuildKit daemon in a tools namespace and `buildctl`
//! inside Che workspaces (`scripts/e2e.sh addons team-tools` opens the node to user-namespaced
//! pods, serves Cilium's policy CRD and preloads BuildKit).
//!
//! kind's CNI does not enforce `CiliumNetworkPolicy`: observation 5 here is its second layer alone
//! (the daemon refusing another team's client certificate), the RFC's "with the CNP removed"
//! case. Observations 4 and 10 (angos, Hubble) are cluster checks, not rows here.
//!
//! Each test makes its own teams and tools namespaces, so the per-team counters it reads move
//! only for its own tools. Run with `--test-threads=1`: they share the cluster's one singleton.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use weebo_si_e2e::{
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, Value, WORKSPACE_START, Workspace,
    WorkspaceSpec, apply, delete, fail, get, json, kubectl, kubectl_with, metric_sum, must,
    set_features, stays, team, text, try_apply, wait_until,
};

/// The pinned image of `scripts/e2e.sh` (`BUILDKIT_IMAGE`), preloaded on the node.
const BUILDKIT_IMAGE: &str = "docker.io/moby/buildkit:v0.35.1-rootless";
/// The chart's template namespace (`resourceQuotas.templateNamespace.name`, shared by default).
const TEMPLATES: &str = "weebo-si-hardening-templates";
/// The ConfigMap template holding buildkitd's `/etc/subuid` and `/etc/subgid`.
const SUBID: &str = "buildkitd-subid";
const KEY: &str = "buildkit";
const ATTRIBUTE: &str = "hardening.weebo.io/team-tools";
const MANAGED: &str = "hardening.weebo.io/managed-by=weebo-si-operator";
const MOUNT: &str = "/home/user/.config/weebo/buildkit";
const CONTROLLER_SA: &str = "system:serviceaccount:weebo-si-hardening:weebo-si-operator-controller";
/// The root of every team CA here. Shared by every test and left in place on purpose: a
/// self-signed issuer holds no key and costs nothing, and deleting it under a parallel rerun would
/// break the teams still being made.
const SELF_SIGNED: &str = "e2e-team-tools-selfsigned";

// --- fixtures ---------------------------------------------------------------------------------------

/// The BuildKit tool templates, as the RFC's reference entry has them minus the TOML config and
/// the egress policy (neither is observed on kind).
fn templates() {
    apply(
        &json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "buildkitd", "namespace": TEMPLATES },
            "spec": statefulset_spec(0),
        })
        .to_string(),
    );
    apply(
        &json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "buildkitd", "namespace": TEMPLATES },
            "spec": service_spec(),
        })
        .to_string(),
    );
    // rootlesskit maps the image's `user:100000:65536`, beyond the 65536 ids of a `hostUsers:
    // false` pod: newuidmap fails with EPERM. These ranges are every pod id but 0 and 1000 (the
    // daemon's own, mapped to nested root), so nested ids run 0..=65534.
    let subid = "user:1:999\nuser:1001:64535\n";
    apply(
        &json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": SUBID, "namespace": TEMPLATES },
            "data": { "subuid": subid, "subgid": subid },
        })
        .to_string(),
    );
}

/// The daemon: rootless, its own user namespace, the process sandbox kept (no
/// `--oci-worker-no-process-sandbox`), mTLS from the team CA's server certificate.
fn statefulset_spec(replicas: u8) -> Value {
    json!({
        "replicas": replicas,
        "serviceName": "buildkitd",
        "selector": { "matchLabels": { "app": "buildkitd" } },
        "template": {
            "metadata": { "labels": { "app": "buildkitd" } },
            "spec": {
                "hostUsers": false,
                "automountServiceAccountToken": false,
                "containers": [{
                    "name": "buildkitd",
                    "image": BUILDKIT_IMAGE,
                    "args": ["--addr", "tcp://0.0.0.0:1234",
                             "--tlscacert", "/certs/ca.crt", "--tlscert", "/certs/tls.crt",
                             "--tlskey", "/certs/tls.key"],
                    "ports": [{ "name": "buildkit", "containerPort": 1234 }],
                    "resources": {
                        "requests": { "cpu": "100m", "memory": "256Mi" },
                        "limits": { "memory": "1Gi" },
                    },
                    "securityContext": {
                        "runAsUser": 1000,
                        "runAsGroup": 1000,
                        "procMount": "Unmasked",
                        "seccompProfile": { "type": "Unconfined" },
                        "appArmorProfile": { "type": "Unconfined" },
                    },
                    "volumeMounts": [
                        { "name": "certs", "mountPath": "/certs", "readOnly": true },
                        { "name": "cache", "mountPath": "/home/user/.local/share/buildkit" },
                        { "name": "subid", "mountPath": "/etc/subuid", "subPath": "subuid", "readOnly": true },
                        { "name": "subid", "mountPath": "/etc/subgid", "subPath": "subgid", "readOnly": true },
                    ],
                }],
                "volumes": [
                    { "name": "certs", "secret": { "secretName": "buildkitd-tls" } },
                    { "name": "subid", "configMap": { "name": SUBID } },
                ],
            },
        },
        "volumeClaimTemplates": [{
            "metadata": { "name": "cache" },
            "spec": {
                "accessModes": ["ReadWriteOnce"],
                "resources": { "requests": { "storage": "1Gi" } },
            },
        }],
    })
}

fn service_spec() -> Value {
    json!({
        "selector": { "app": "buildkitd" },
        "ports": [{ "name": "buildkit", "port": 1234, "targetPort": "buildkit" }],
    })
}

/// The block: one BuildKit entry, `Enforce` on every workspace namespace.
fn team_tools(on_not_granted: &str, idle_grace_seconds: u32) -> Value {
    let template =
        |kind: &str| json!({ "kind": kind, "name": "buildkitd", "namespace": TEMPLATES });
    json!({ "teamTools": {
        "mode": "Enforce",
        "onNotGranted": on_not_granted,
        "namespaceSelector": { "matchExpressions": [
            { "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" },
        ] },
        "catalog": [{
            "key": KEY,
            "workload": { "kind": "StatefulSet", "name": "buildkitd" },
            "service": { "name": "buildkitd", "port": 1234 },
            "clientEnv": "BUILDKIT_HOST",
            "idleGraceSeconds": idle_grace_seconds,
            // cert-manager's minimum, so a renewal is a forced one (observation 8).
            "tls": { "serverSecretName": "buildkitd-tls", "clientDuration": "1h", "clientMountPath": MOUNT },
            "toolTemplates": [
                template("StatefulSet"),
                template("Service"),
                json!({ "kind": "ConfigMap", "name": SUBID, "namespace": TEMPLATES }),
            ],
        }],
    } })
}

fn wait_issuer_ready(name: &str) {
    wait_until(
        &format!("ClusterIssuer {name} to be Ready"),
        RECONCILE,
        || {
            let issuer = get(&["clusterissuer", name]).ok_or("absent")?;
            let ready = issuer
                .pointer("/status/conditions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|c| c["type"] == "Ready" && c["status"] == "True");
            if ready {
                Ok(())
            } else {
                Err(issuer["status"].to_string())
            }
        },
    );
}

/// A team with its own CA, its tools namespace (label, quota, RoleBinding) and its
/// `WeeboSiTeam`, `buildkit` allowed. Everything is deleted when dropped.
struct ToolTeam {
    name: String,
    tools: String,
    _cleanups: Vec<Cleanup>,
}

impl ToolTeam {
    #[track_caller]
    fn new(name: &str) -> Self {
        let tools = format!("team-{name}-tools");
        let issuer = format!("team-{name}-ca");
        apply(
            &json!({
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": { "name": SELF_SIGNED },
                "spec": { "selfSigned": {} },
            })
            .to_string(),
        );
        apply(
            &json!({
                "apiVersion": "cert-manager.io/v1",
                "kind": "Certificate",
                "metadata": { "name": issuer, "namespace": "cert-manager" },
                "spec": {
                    "isCA": true,
                    "commonName": format!("{name} team tools CA"),
                    "secretName": issuer,
                    "issuerRef": { "kind": "ClusterIssuer", "name": SELF_SIGNED },
                },
            })
            .to_string(),
        );
        apply(
            &json!({
                "apiVersion": "cert-manager.io/v1",
                "kind": "ClusterIssuer",
                "metadata": { "name": issuer },
                "spec": { "ca": { "secretName": issuer } },
            })
            .to_string(),
        );
        wait_issuer_ready(&issuer);
        apply(
            &json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": { "name": tools, "labels": {
                    "hardening.weebo.io/team-tools": name,
                    "pod-security.kubernetes.io/enforce": "privileged",
                } },
            })
            .to_string(),
        );
        apply(
            &json!({
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": { "name": "tools-quota", "namespace": tools },
                "spec": { "hard": {
                    "limits.memory": "4Gi", "requests.storage": "10Gi", "pods": "4",
                    "services.nodeports": "0", "services.loadbalancers": "0",
                } },
            })
            .to_string(),
        );
        role_binding(&tools, "weebo-si-team-tools");
        let team_object = team(
            name,
            json!({
                "priority": 10,
                "namespaceSelector": { "matchLabels": { "weebo.io/team": name } },
                "features": { "teamTools": {
                    "namespace": tools,
                    "issuerRef": { "kind": "ClusterIssuer", "name": issuer },
                    "allowed": [KEY],
                    "default": [],
                } },
            }),
        );
        Self {
            name: name.to_string(),
            tools: tools.clone(),
            // The team first, so the controller lets go before its namespace goes.
            _cleanups: vec![
                team_object,
                Cleanup::new(&["namespace", &tools]),
                Cleanup::new(&["clusterissuer", &issuer]),
                Cleanup::new(&["certificate", "-n", "cert-manager", &issuer]),
                Cleanup::new(&["secret", "-n", "cert-manager", &issuer]),
            ],
        }
    }

    fn host(&self) -> String {
        format!("tcp://buildkitd.{}.svc:1234", self.tools)
    }

    /// With its `managedFields`, which `kubectl get` drops unless asked.
    fn statefulset(&self) -> Option<Value> {
        get(&[
            "statefulset",
            "-n",
            &self.tools,
            "buildkitd",
            "--show-managed-fields",
        ])
    }

    fn scaled_up(&self) -> f64 {
        metric_sum(
            "controller",
            "weebo_si_team_tools_scale_total",
            &[
                ("team", &self.name),
                ("tool", KEY),
                ("direction", "up"),
                ("result", "ok"),
            ],
        )
    }

    /// The team's `TeamToolsReady` condition, once it has one.
    fn ready(&self) -> Value {
        wait_until(
            &format!("team {} to report TeamToolsReady", self.name),
            RECONCILE,
            || {
                let object = get(&["weebositeam", &self.name]).ok_or("no team")?;
                object
                    .pointer("/status/conditions")
                    .and_then(Value::as_array)
                    .and_then(|conditions| {
                        conditions
                            .iter()
                            .find(|c| c["type"] == "TeamToolsReady")
                            .cloned()
                    })
                    .ok_or_else(|| format!("status {}", object["status"]))
            },
        )
    }
}

/// A RoleBinding of `cluster_role` to the controller in `namespace`, as Git renders it.
fn role_binding(namespace: &str, cluster_role: &str) {
    apply(
        &json!({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": { "name": cluster_role, "namespace": namespace },
            "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": cluster_role },
            "subjects": [{
                "kind": "ServiceAccount",
                "name": "weebo-si-operator-controller",
                "namespace": OPERATOR_NAMESPACE,
            }],
        })
        .to_string(),
    );
}

/// A workspace namespace of `team` the controller may write requester objects in. The client
/// certificate needs `workspace-namespace=true` exactly (the harness label is empty).
#[track_caller]
fn requester_namespace(user: &str, team: &ToolTeam) -> Namespace {
    let namespace = Namespace::workspace(user, "tt", Some(&team.name));
    must(&[
        "label",
        "--overwrite",
        "namespace",
        &namespace.name,
        "hardening.weebo.io/workspace-namespace=true",
    ]);
    role_binding(&namespace.name, "weebo-si-team-tools-requester");
    namespace
}

fn spec(attribute: &str) -> WorkspaceSpec<'static> {
    WorkspaceSpec {
        image: BUILDKIT_IMAGE,
        attributes: json!({ ATTRIBUTE: attribute }),
        command: &["sleep", "infinity"],
        memory_limit: "256Mi",
        ..WorkspaceSpec::default()
    }
}

/// A requesting workspace created stopped, so the requester objects exist before its first
/// start (the RFC's "render early").
#[track_caller]
fn stopped_workspace(namespace: &str, name: &str) -> Workspace {
    let mut manifest = Workspace::manifest(namespace, name, &spec(KEY));
    manifest["spec"]["started"] = json!(false);
    apply(&manifest.to_string());
    Workspace {
        namespace: namespace.to_string(),
        name: name.to_string(),
    }
}

fn set_started(workspace: &Workspace, started: bool) {
    must(&[
        "patch",
        "devworkspace",
        "-n",
        &workspace.namespace,
        &workspace.name,
        "--type=merge",
        "-p",
        &json!({ "spec": { "started": started } }).to_string(),
    ]);
}

/// Wait for the endpoint ConfigMap and the client certificate's Secret in `namespace`.
fn wait_requester_objects(namespace: &str) {
    wait_until(
        &format!("the requester objects in {namespace}"),
        RECONCILE,
        || {
            get(&["configmap", "-n", namespace, "weebo-team-tool-buildkit"])
                .ok_or("no endpoint ConfigMap")?;
            get(&["secret", "-n", namespace, "weebo-team-tool-buildkit-client"])
                .ok_or("no client certificate Secret")?;
            Ok(())
        },
    );
}

/// `buildctl debug workers` from the workspace with its mounted client certificate.
fn buildctl(workspace: &Workspace, addr: &str, ca: &str) -> Result<String, String> {
    workspace.exec(&[
        "buildctl",
        "--addr",
        addr,
        "--tlscacert",
        ca,
        "--tlscert",
        &format!("{MOUNT}/tls.crt"),
        "--tlskey",
        &format!("{MOUNT}/tls.key"),
        "debug",
        "workers",
    ])
}

/// The subject of a PEM certificate, read by the host's `openssl` (RFC 2253, `CN=…,O=…`).
fn subject(pem: &str) -> String {
    let mut child = Command::new("openssl")
        .args(["x509", "-noout", "-subject", "-nameopt", "RFC2253"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("openssl is required");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(pem.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "openssl could not read {pem}");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn pod_uid(namespace: &str, pod: &str) -> String {
    text(
        &get(&["pod", "-n", namespace, pod]).unwrap_or(Value::Null),
        "/metadata/uid",
    )
}

fn replicas(team: &ToolTeam) -> Result<i64, String> {
    team.statefulset()
        .and_then(|sts| sts.pointer("/spec/replicas").and_then(Value::as_i64))
        .ok_or_else(|| format!("no StatefulSet buildkitd in {}", team.tools))
}

fn managed_in(namespace: &str, kinds: &str) -> Vec<String> {
    get(&[kinds, "-n", namespace, "-l", MANAGED])
        .and_then(|list| list["items"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|item| format!("{}/{}", text(item, "/kind"), text(item, "/metadata/name")))
        .collect()
}

// --- observations 1, 2, 3, 9 ------------------------------------------------------------------------

#[test]
fn a_requested_tool_renders_at_zero_scales_with_its_workspace_and_idles_after_grace() {
    templates();
    let weebo = ToolTeam::new("tt-weebo");
    set_features(team_tools("Default", 60));
    let namespace = requester_namespace("tt-alice", &weebo);
    let workspace = stopped_workspace(&namespace.name, "build");

    // 1. Requested by a stopped workspace: rendered at 0, no pod.
    wait_until("the rendered StatefulSet", RECONCILE, || replicas(&weebo));
    wait_requester_objects(&namespace.name);
    stays(
        "the tool at 0 replicas with no pod",
        Duration::from_secs(15),
        || {
            let now = replicas(&weebo)?;
            let pods = pods_in(&weebo.tools);
            if now == 0 && pods == 0 {
                Ok(())
            } else {
                Err(format!("replicas {now}, {pods} pods"))
            }
        },
    );

    // 2. Started: the scale manager alone owns replicas, at 1, counted once.
    let before = weebo.scaled_up();
    set_started(&workspace, true);
    workspace.wait_running();
    wait_until("the scale manager to own replicas at 1", RECONCILE, || {
        let sts = weebo.statefulset().ok_or("no StatefulSet")?;
        // A set: the scale manager may hold replicas through its apply and its /scale write.
        let owners: Vec<String> = sts
            .pointer("/metadata/managedFields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.pointer("/fieldsV1/f:spec/f:replicas").is_some())
            .map(|entry| text(entry, "/manager"))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let now = sts.pointer("/spec/replicas").and_then(Value::as_i64);
        if now == Some(1) && owners == ["weebo-si-team-tools-scale"] {
            Ok(())
        } else {
            Err(format!("replicas {now:?}, owned by {owners:?}"))
        }
    });
    assert_eq!(weebo.scaled_up() - before, 1.0, "one scale-up write");
    assert_eq!(
        text(
            &workspace.object(),
            "/metadata/annotations/hardening.weebo.io~1team-tools"
        ),
        "granted=buildkit;dropped=",
    );

    // 3. Inside the workspace: the endpoint, the certificate, the owner's CN; a call goes through.
    let env = workspace.exec(&["env"]).unwrap_or_else(|err| fail(&err));
    assert!(
        env.lines()
            .any(|line| line == format!("BUILDKIT_HOST={}", weebo.host())),
        "BUILDKIT_HOST missing or wrong:\n{env}"
    );
    let listing = workspace
        .exec(&["ls", MOUNT])
        .unwrap_or_else(|err| fail(&err));
    for file in ["ca.crt", "tls.crt", "tls.key"] {
        assert!(
            listing.lines().any(|line| line == file),
            "{file} not in {MOUNT}: {listing}"
        );
    }
    let pem = workspace
        .exec(&["cat", &format!("{MOUNT}/tls.crt")])
        .unwrap_or_else(|err| fail(&err));
    assert_eq!(subject(&pem), "subject=CN=tt-alice,O=tt-weebo");
    // Cold start: the daemon may still be starting when the IDE is up; the client retries.
    wait_until("buildctl to reach the team daemon", WORKSPACE_START, || {
        buildctl(&workspace, &weebo.host(), &format!("{MOUNT}/ca.crt"))
    });
    let tool = wait_until("the team status to say Running", RECONCILE, || {
        let object = get(&["weebositeam", &weebo.name]).ok_or("no team")?;
        let tool = object
            .pointer("/status/teamTools/0")
            .cloned()
            .ok_or("no teamTools")?;
        if tool["state"] == "Running" {
            Ok(tool)
        } else {
            Err(tool.to_string())
        }
    });
    assert_eq!(tool["replicas"], 1);
    assert_eq!(tool["requesters"], 1);
    assert_eq!(weebo.ready()["status"], "True");

    // 9. Stopped: 1 for the grace (60 s here), then 0; the cache PVC stays.
    set_started(&workspace, false);
    stays(
        "the tool up during its grace",
        Duration::from_secs(40),
        || {
            replicas(&weebo).and_then(|n| {
                if n == 1 {
                    Ok(())
                } else {
                    Err(format!("replicas {n}"))
                }
            })
        },
    );
    wait_until("the tool to idle at 0", RECONCILE, || {
        replicas(&weebo).and_then(|n| {
            if n == 0 {
                Ok(())
            } else {
                Err(format!("replicas {n}"))
            }
        })
    });
    assert!(
        get(&["pvc", "-n", &weebo.tools, "cache-buildkitd-0"]).is_some(),
        "the cache PVC must survive scale to zero (T-41)"
    );
}

fn pods_in(namespace: &str) -> usize {
    get(&["pods", "-n", namespace])
        .and_then(|list| list["items"].as_array().map(Vec::len))
        .unwrap_or(0)
}

// --- observation 8 ----------------------------------------------------------------------------------

#[test]
fn a_renewed_client_certificate_is_used_without_a_restart() {
    templates();
    let weebo = ToolTeam::new("tt-renew");
    set_features(team_tools("Default", 600));
    let namespace = requester_namespace("tt-carol", &weebo);
    let workspace = stopped_workspace(&namespace.name, "build");
    wait_requester_objects(&namespace.name);
    set_started(&workspace, true);
    workspace.wait_running();
    let ca = format!("{MOUNT}/ca.crt");
    wait_until("buildctl to reach the team daemon", WORKSPACE_START, || {
        buildctl(&workspace, &weebo.host(), &ca)
    });
    let pod = workspace.pod();
    let uid = pod_uid(&namespace.name, &pod);
    let first = workspace
        .exec(&["cat", &format!("{MOUNT}/tls.crt")])
        .unwrap();

    // What `cmctl renew` does: an `Issuing` condition on the Certificate's status.
    must(&[
        "patch",
        "certificate",
        "-n",
        &namespace.name,
        "weebo-team-tool-buildkit-client",
        "--subresource=status",
        "--type=json",
        "-p",
        &json!([{ "op": "add", "path": "/status/conditions/-", "value": {
            "type": "Issuing", "status": "True", "reason": "ManuallyTriggered",
            "message": "e2e: renewal compressed from 24 h",
        } }])
        .to_string(),
    ]);
    // The kubelet refreshes a Secret volume on its sync period (about a minute).
    wait_until(
        "the renewed certificate in the workspace",
        RECONCILE,
        || {
            let now = workspace.exec(&["cat", &format!("{MOUNT}/tls.crt")])?;
            if now == first {
                Err("still the first certificate".into())
            } else {
                Ok(())
            }
        },
    );
    buildctl(&workspace, &weebo.host(), &ca).unwrap_or_else(|err| fail(&err));
    assert_eq!(
        pod_uid(&namespace.name, &pod),
        uid,
        "the workspace restarted"
    );
}

// --- observation 5 (T-39), the mTLS layer -----------------------------------------------------------

#[test]
fn another_teams_client_certificate_is_refused_by_the_daemon() {
    templates();
    let weebo = ToolTeam::new("tt-red");
    let data = ToolTeam::new("tt-blue");
    set_features(team_tools("Default", 600));
    let alice_ns = requester_namespace("tt-ruth", &weebo);
    let bob_ns = requester_namespace("tt-bob", &data);
    let alice = stopped_workspace(&alice_ns.name, "build");
    let bob = stopped_workspace(&bob_ns.name, "build");
    for (workspace, namespace) in [(&alice, &alice_ns), (&bob, &bob_ns)] {
        wait_requester_objects(&namespace.name);
        set_started(workspace, true);
    }
    alice.wait_running();
    bob.wait_running();
    let own_ca = format!("{MOUNT}/ca.crt");
    wait_until("alice to reach her team's daemon", WORKSPACE_START, || {
        buildctl(&alice, &weebo.host(), &own_ca)
    });

    // Bob's client does not trust weebo's server...
    let refused = buildctl(&bob, &weebo.host(), &own_ca)
        .expect_err("bob reached weebo's daemon with his own CA");
    assert!(
        refused.contains("certificate"),
        "not a TLS refusal: {refused}"
    );

    // ...and, given weebo's CA, weebo's daemon does not trust bob's certificate.
    let weebo_ca = must(&[
        "get",
        "secret",
        "-n",
        &weebo.tools,
        "buildkitd-tls",
        "-o",
        r#"go-template={{index .data "ca.crt" | base64decode}}"#,
    ]);
    let pod = bob.pod();
    kubectl_with(
        &[
            "exec",
            "-i",
            "-n",
            &bob_ns.name,
            &pod,
            "-c",
            "tools",
            "--",
            "sh",
            "-c",
            "cat > /tmp/weebo-ca.crt",
        ],
        Some(&weebo_ca),
    )
    .unwrap_or_else(|err| fail(&err));
    let refused = buildctl(&bob, &weebo.host(), "/tmp/weebo-ca.crt")
        .expect_err("weebo's daemon accepted a certificate of team tt-blue");
    // A TLS alert from the daemon, not a client-side x509 error. shortcut: the alert itself
    // (`unknown certificate authority` per the RFC, or `bad certificate`) is not pinned; pin it on
    // the first kind run.
    assert!(
        refused.contains("remote error: tls:"),
        "not the daemon refusing the certificate: {refused}"
    );
}

// --- observation 6 ----------------------------------------------------------------------------------

#[test]
fn an_ungranted_key_is_refused_under_deny_and_nothing_is_rendered() {
    templates();
    let weebo = ToolTeam::new("tt-deny");
    set_features(team_tools("Deny", 600));
    let namespace = requester_namespace("tt-dave", &weebo);
    let manifest = Workspace::manifest(&namespace.name, "android", &spec("android")).to_string();
    // Until the webhook has seen the namespace the gate may admit: retry until it refuses.
    let refusal = wait_until("the Deny refusal", RECONCILE, || {
        match try_apply(&manifest) {
            Ok(_) => {
                delete(&["devworkspace", "-n", &namespace.name, "android"]);
                Err("admitted".to_string())
            }
            Err(err) if err.contains("denied the request") => Ok(err),
            Err(err) => Err(err),
        }
    });
    assert!(refusal.contains("exit status: 1"), "{refusal}");
    assert!(refusal.contains("Error from server"), "{refusal}");
    assert!(
        refusal.contains(
            "admission webhook \"devworkspaces.hardening.weebo.io\" denied the request: \
             team tool \"android\" is not granted to team tt-deny"
        ),
        "{refusal}"
    );
    stays("nothing rendered", Duration::from_secs(20), || {
        let tools = managed_in(&weebo.tools, "statefulsets,services,ciliumnetworkpolicies");
        let requester = managed_in(&namespace.name, "configmaps,certificates");
        if tools.is_empty() && requester.is_empty() {
            Ok(())
        } else {
            Err(format!("rendered: {tools:?} {requester:?}"))
        }
    });
}

// --- observation 7 and E2 ---------------------------------------------------------------------------

#[test]
fn a_forged_tools_namespace_is_never_written() {
    templates();
    set_features(team_tools("Default", 600));
    let bound = ToolTeam::new("tt-bound");
    let _forged = team(
        "tt-forged",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "tt-forged" } },
            "features": { "teamTools": {
                "namespace": "kube-system",
                "issuerRef": { "kind": "ClusterIssuer", "name": "team-tt-forged-ca" },
                "allowed": [KEY],
                "default": [],
            } },
        }),
    );
    let condition = wait_until("tt-forged to be unbound", RECONCILE, || {
        let object = get(&["weebositeam", "tt-forged"]).ok_or("no team")?;
        object
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .and_then(|all| all.iter().find(|c| c["type"] == "TeamToolsReady").cloned())
            .ok_or_else(|| format!("status {}", object["status"]))
    });
    assert_eq!(condition["status"], "False");
    assert_eq!(condition["reason"], "NamespaceNotBound");
    assert!(
        managed_in(
            "kube-system",
            "statefulsets,deployments,services,configmaps,certificates,ciliumnetworkpolicies"
        )
        .is_empty(),
        "the controller wrote in kube-system"
    );

    // E2: the chart's RBAC, not the controller's goodwill, is the boundary.
    // `resource/name` would name an object: the subresource is its own flag.
    let can = |verb: &str, resource: &str, namespace: &str| match kubectl(&[
        "auth",
        "can-i",
        verb,
        resource,
        "-n",
        namespace,
        "--as",
        CONTROLLER_SA,
        &format!(
            "--subresource={}",
            if verb == "update" { "scale" } else { "" }
        ),
    ]) {
        Ok(out) => out.trim() == "yes",
        Err(err) if err.trim_end().ends_with("no") => false,
        Err(err) => fail(&err),
    };
    for (verb, resource) in [
        ("create", "statefulsets.apps"),
        ("create", "deployments.apps"),
        ("update", "statefulsets.apps"), // /scale
        ("create", "services"),
        ("create", "certificates.cert-manager.io"),
    ] {
        assert!(
            !can(verb, resource, "kube-system"),
            "{verb} {resource} allowed in kube-system"
        );
        assert!(
            can(verb, resource, &bound.tools),
            "{verb} {resource} refused in {}",
            bound.tools
        );
    }
}

// --- observation 12 ---------------------------------------------------------------------------------

#[test]
fn a_phase_zero_tool_is_adopted_in_place() {
    templates();
    let weebo = ToolTeam::new("tt-adopt");
    // Phase 0: no `teamTools` block, the chart's objects without `managed-by`, scaled by hand.
    set_features(json!({}));
    apply(
        &json!({
            "apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": { "name": "buildkitd", "namespace": weebo.tools },
            "spec": statefulset_spec(1),
        })
        .to_string(),
    );
    apply(
        &json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": { "name": "buildkitd", "namespace": weebo.tools },
            "spec": service_spec(),
        })
        .to_string(),
    );
    // The pod waits on its server Secret until the controller writes the server certificate; it
    // exists, and its PVC is bound, from the start.
    let pod_before = wait_until("the phase-0 pod", RECONCILE, || {
        let uid = pod_uid(&weebo.tools, "buildkitd-0");
        if uid.is_empty() {
            Err("no pod yet".to_string())
        } else {
            Ok(uid)
        }
    });
    let pvc_before = wait_until("the phase-0 cache PVC", RECONCILE, || {
        let uid = text(
            &get(&["pvc", "-n", &weebo.tools, "cache-buildkitd-0"]).unwrap_or(Value::Null),
            "/metadata/uid",
        );
        if uid.is_empty() {
            Err("no PVC yet".to_string())
        } else {
            Ok(uid)
        }
    });

    // Phase 1: the block on, one (stopped) requester so the tool is wanted and inside its grace.
    let namespace = requester_namespace("tt-erin", &weebo);
    let _workspace = stopped_workspace(&namespace.name, "build");
    set_features(team_tools("Default", 600));
    wait_until("the StatefulSet to be adopted", RECONCILE, || {
        let sts = weebo.statefulset().ok_or("no StatefulSet")?;
        if text(&sts, "/metadata/labels/hardening.weebo.io~1managed-by") == "weebo-si-operator" {
            Ok(())
        } else {
            Err("not managed yet".to_string())
        }
    });
    // The adopting pass does not scale, a later one may: hold over passes (2 s fingerprint
    // poll, 30 s resync) once the team status shows a pass after the adoption.
    wait_until("a pass to report the adopted tool", RECONCILE, || {
        let object = get(&["weebositeam", &weebo.name]).ok_or("no team")?;
        let tool = object
            .pointer("/status/teamTools/0")
            .cloned()
            .ok_or("no teamTools")?;
        if tool["replicas"] == 1 {
            Ok(())
        } else {
            Err(tool.to_string())
        }
    });
    stays(
        "the adopted tool untouched",
        Duration::from_secs(40),
        || {
            let now = replicas(&weebo)?;
            let uid = pod_uid(&weebo.tools, "buildkitd-0");
            if now == 1 && uid == pod_before {
                Ok(())
            } else {
                Err(format!("replicas {now}, pod uid {uid} (was {pod_before})"))
            }
        },
    );
    assert_eq!(
        text(
            &get(&["pvc", "-n", &weebo.tools, "cache-buildkitd-0"]).unwrap(),
            "/metadata/uid"
        ),
        pvc_before,
        "the cache PVC was re-created"
    );
}
