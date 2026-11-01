//! The pod-security suite: RFC 0013 against a real apiserver and a real Eclipse Che. The labels
//! are only half of it; the other half is the apiserver's own `PodSecurity` admission plugin
//! refusing a pod because of them, and a workspace Che starts still running under them.
//!
//! The last test is a **measurement**, not an assertion: whether a Che workspace starts in a
//! `restricted` namespace depends on Che's own security context, and RFC 0013 leaves that as a
//! question to measure. It prints the answer and passes either way.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::time::{Duration, Instant};

use weebo_si_e2e::{
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, Value, Workspace, WorkspaceSpec, apply,
    feature_status, get, json, kubectl_with, metric_sum, set_features, team, text, try_apply,
    wait_until,
};

const ENFORCE: &str = "pod-security.kubernetes.io~1enforce";
const WARN: &str = "pod-security.kubernetes.io~1warn";
const PREVIOUS: &str = "hardening.weebo.io~1pod-security-previous";

fn pod_security(mode: &str) -> Value {
    json!({
        "mode": mode,
        "namespaceSelector": { "matchExpressions": [{ "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" }] },
        "default": "restricted",
        "ceiling": "baseline",
        "version": "latest",
        "backend": "Labels",
    })
}

fn namespace_object(name: &str) -> Value {
    get(&["namespace", name]).unwrap()
}

/// Wait until the namespace enforces `level`.
fn wait_for_level(namespace: &str, level: &str) -> Value {
    wait_until(
        &format!("namespace {namespace} to enforce {level}"),
        RECONCILE,
        || {
            let object = namespace_object(namespace);
            let found = text(&object, &format!("/metadata/labels/{ENFORCE}"));
            if found == level {
                Ok(object)
            } else {
                Err(format!("enforce={found:?}"))
            }
        },
    )
}

/// A pod `baseline` refuses: privileged, with the host's PID namespace. RFC 0013's motivation.
fn privileged_pod(namespace: &str) -> String {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "root", "namespace": namespace },
        "spec": {
            "hostPID": true,
            "containers": [{
                "name": "root",
                "image": weebo_si_e2e::WORKSPACE_IMAGE,
                "securityContext": { "privileged": true },
            }],
        },
    })
    .to_string()
}

/// A pod `baseline` admits and `restricted` refuses: it sets no security context at all.
fn plain_pod(namespace: &str) -> String {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "plain", "namespace": namespace },
        "spec": { "containers": [{ "name": "plain", "image": weebo_si_e2e::WORKSPACE_IMAGE }] },
    })
    .to_string()
}

fn server_dry_run(manifest: &str) -> Result<String, String> {
    kubectl_with(&["apply", "--dry-run=server", "-f", "-"], Some(manifest))
}

#[test]
fn enforce_refuses_a_privileged_pod_and_off_gives_the_namespace_back() {
    set_features(json!({ "podSecurity": pod_security("Enforce") }));
    let ns = Namespace::workspace("alice", "psa", None);

    let object = wait_for_level(&ns.name, "restricted");
    assert_eq!(
        text(&object, &format!("/metadata/annotations/{PREVIOUS}")),
        "{}"
    );
    assert_eq!(text(&feature_status("pod-security"), "/state"), "Active");

    let err = try_apply(&privileged_pod(&ns.name))
        .expect_err("a privileged pod must be refused by the apiserver");
    assert!(err.contains("violates PodSecurity"), "{err}");

    set_features(json!({ "podSecurity": pod_security("Off") }));
    wait_until(
        "the labels and the annotation to be gone",
        RECONCILE,
        || {
            let object = namespace_object(&ns.name);
            let enforce = text(&object, &format!("/metadata/labels/{ENFORCE}"));
            let previous = text(&object, &format!("/metadata/annotations/{PREVIOUS}"));
            if enforce.is_empty() && previous.is_empty() {
                Ok(())
            } else {
                Err(format!("enforce={enforce:?} previous={previous:?}"))
            }
        },
    );
    server_dry_run(&privileged_pod(&ns.name))
        .expect("with the labels gone, the namespace is privileged again, as it was found");
}

#[test]
fn a_build_team_gets_baseline_and_a_che_workspace_starts_there() {
    let _team = team(
        "e2e-build",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "build" } },
            "features": { "podSecurity": { "level": "baseline", "warnLevel": "restricted" } },
        }),
    );
    set_features(json!({ "podSecurity": pod_security("Enforce") }));
    let ns = Namespace::workspace("carol", "psa-build", Some("build"));

    let object = wait_for_level(&ns.name, "baseline");
    assert_eq!(
        text(&object, &format!("/metadata/labels/{WARN}")),
        "restricted"
    );
    let admitted = server_dry_run(&plain_pod(&ns.name))
        .expect("baseline admits a pod that sets no security context");
    println!("baseline dry run: {admitted}");
    assert!(try_apply(&privileged_pod(&ns.name)).is_err());

    let workspace = Workspace::create(&ns.name, "tools", &WorkspaceSpec::default());
    workspace.wait_running();

    wait_until("the namespaces gauge", RECONCILE, || {
        let applied = metric_sum(
            "controller",
            "weebo_si_pod_security_namespaces",
            &[("level", "baseline"), ("state", "applied")],
        );
        if applied >= 1.0 {
            Ok(())
        } else {
            Err(format!("applied {applied}"))
        }
    });
}

#[test]
fn measure_whether_a_che_workspace_starts_under_restricted() {
    set_features(json!({ "podSecurity": pod_security("Enforce") }));
    let ns = Namespace::workspace("dave", "psa-restricted", None);
    wait_for_level(&ns.name, "restricted");

    let workspace = Workspace::create(&ns.name, "tools", &WorkspaceSpec::default());
    let started = Instant::now();
    let window = Duration::from_secs(300);
    let verdict = loop {
        let object = get(&["devworkspace", "-n", &ns.name, "tools"]).unwrap_or(Value::Null);
        let phase = text(&object, "/status/phase");
        let message = text(&object, "/status/message");
        if phase == "Running" {
            break format!("Running after {:?}", started.elapsed());
        }
        if phase == "Failed" || started.elapsed() > window {
            let events = kubectl_with(
                &[
                    "get",
                    "events",
                    "-n",
                    &ns.name,
                    "--field-selector",
                    "reason=FailedCreate",
                    "-o",
                    "jsonpath={range .items[*]}{.message}{\"\\n\"}{end}",
                ],
                None,
            )
            .unwrap_or_default();
            break format!("not running ({phase}: {message}); FailedCreate: {events}");
        }
        std::thread::sleep(Duration::from_secs(10));
    };
    println!("MEASURED che workspace under restricted: {verdict}");
    drop(workspace);
}

/// Pinned by digest, the image the runtime matrix measured (scripts/runtime-matrix-k8s.sh).
const BUILDAH: &str = "quay.io/buildah/stable@sha256:77a555756c942f4f0e2916a2a95bace8f109622201b3b70b008a597cf5b7aa69";
const BUSYBOX: &str = "quay.io/libpod/busybox@sha256:a9286defaba7b3a519d585ba0e37d0b2cbee74ebfe590960b0b1d6a5e97d1e1d";

/// RFC 0013's build DWOC: a user namespace for the pod, an unmasked `/proc` for the nested
/// container, and `seccomp` as given — the build profile, or `RuntimeDefault` to show what the
/// profile is for. UID 1000 is the image's own `build` user, which owns its subuid range.
fn build_dwoc(name: &str, seccomp: Value) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "controller.devfile.io/v1alpha1",
            "kind": "DevWorkspaceOperatorConfig",
            "metadata": { "name": name, "namespace": OPERATOR_NAMESPACE },
            "config": { "workspace": {
                "imagePullPolicy": "IfNotPresent",
                "hostUsers": false,
                "podSecurityContext": {
                    "runAsUser": 1000,
                    "runAsGroup": 1000,
                    "fsGroup": 1000,
                    "seccompProfile": seccomp,
                },
                "containerSecurityContext": {
                    "allowPrivilegeEscalation": true,
                    "procMount": "Unmasked",
                },
            } },
        })
        .to_string(),
    );
    Cleanup::new(&["devworkspaceoperatorconfig", "-n", OPERATOR_NAMESPACE, name])
}

fn build_workspace(namespace: &str, name: &str, dwoc: &str) -> Workspace {
    Workspace::create(
        namespace,
        name,
        &WorkspaceSpec {
            image: BUILDAH,
            attributes: json!({
                "controller.devfile.io/devworkspace-config": {
                    "name": dwoc,
                    "namespace": OPERATOR_NAMESPACE,
                },
            }),
            command: &["sleep", "infinity"],
            memory_limit: "1Gi",
            ..WorkspaceSpec::default()
        },
    )
}

/// A build with a `RUN` step and OCI isolation: a real nested container, as the matrix runs it.
fn build(workspace: &Workspace) -> Result<String, String> {
    let script = format!(
        "export HOME=/home/build; mkdir -p /tmp/ctx && \\
         printf 'FROM {BUSYBOX}\\nRUN echo built > /built\\n' > /tmp/ctx/Containerfile && \\
         buildah build --isolation oci --network host --storage-driver=overlay -t t /tmp/ctx"
    );
    workspace.exec(&["sh", "-c", &script])
}

#[test]
fn a_build_workspace_builds_an_image_under_its_profile_and_not_under_runtime_default() {
    let _team = team(
        "e2e-builders",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "builders" } },
            "features": { "podSecurity": { "level": "baseline" } },
        }),
    );
    set_features(json!({ "podSecurity": pod_security("Enforce") }));
    let ns = Namespace::workspace("erin", "psa-build", Some("builders"));
    wait_for_level(&ns.name, "baseline");

    let _profile = build_dwoc(
        "e2e-build-profile",
        json!({ "type": "Localhost", "localhostProfile": "profiles/weebo-container-build.json" }),
    );
    let builder = build_workspace(&ns.name, "builder", "e2e-build-profile");
    builder.wait_running();
    let pod = get(&[
        "pods",
        "-n",
        &ns.name,
        "-l",
        "controller.devfile.io/devworkspace_name=builder",
    ])
    .unwrap();
    assert_eq!(
        pod.pointer("/items/0/spec/hostUsers"),
        Some(&json!(false)),
        "DevWorkspace Operator must carry hostUsers from the DWOC onto the pod"
    );
    let built = build(&builder);
    assert!(
        built.is_ok(),
        "the build profile must let a nested build run: {built:?}"
    );

    let _default = build_dwoc("e2e-build-default", json!({ "type": "RuntimeDefault" }));
    let refused = build_workspace(&ns.name, "refused", "e2e-build-default");
    refused.wait_running();
    let err = build(&refused).expect_err("RuntimeDefault must stop a nested build");
    println!(
        "MEASURED nested build under RuntimeDefault: {}",
        err.lines().last().unwrap_or(&err)
    );
}
