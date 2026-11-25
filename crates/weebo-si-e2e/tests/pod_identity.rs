//! The pod-identity suite: RFC 0018's *Proof against a real client*, observations 1–6 and 8,
//! against Che workspaces DevWorkspace Operator starts on a kind node that runs user-namespaced
//! pods (`scripts/e2e.sh addons pod-identity` prepares it; rootless podman cannot, see there).
//!
//! This is the tier where a rewritten pod is admitted: the envtest apiserver (1.32) drops
//! `hostUsers` and `supplementalGroupsPolicy` between mutation and validation. Observation 7
//! (KubeArmor still blocking) is a cluster check (V-07), not a row here.
//!
//! Every test scopes the feature to its own namespace, so the global counters it reads move only
//! for its own pods. Run with `--test-threads=1`: they share the cluster's one singleton.

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
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, Value, WORKSPACE_IMAGE, WORKSPACE_START,
    Workspace, WorkspaceSpec, apply, fail, get, json, kubectl, kubectl_with, metric_sum, must,
    set_features, text, try_apply, wait_until,
};

const VALIDATE: &str = "pod-identity-validate.hardening.weebo.io";
const MUTATING_CONFIGURATION: &str = "weebo-si-operator-pods-identity";

/// The block, scoped to one namespace.
fn pod_identity(mode: &str, namespace: &str) -> Value {
    json!({ "podIdentity": {
        "mode": mode,
        "namespaceSelector": { "matchLabels": { "kubernetes.io/metadata.name": namespace } },
        "runAsUser": 1234,
        "runAsGroup": 1234,
    } })
}

/// A bare pod, `spec` merged over a single `probe` container.
fn probe_pod(namespace: &str, spec: &Value) -> Value {
    let mut pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": { "name": "probe", "namespace": namespace },
        "spec": {
            "restartPolicy": "Never",
            "containers": [{ "name": "probe", "image": WORKSPACE_IMAGE }],
        },
    });
    if let (Some(base), Some(extra)) = (pod["spec"].as_object_mut(), spec.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    pod
}

/// The pod as admission leaves it, without creating it: every webhook runs on a server dry run.
fn dry_run(pod: &Value) -> Result<Value, String> {
    let out = kubectl_with(
        &["create", "--dry-run=server", "-o", "json", "-f", "-"],
        Some(&pod.to_string()),
    )?;
    serde_json::from_str(&out).map_err(|err| format!("{err}: {out}"))
}

/// Wait until the webhooks rewrite a bare pod in `namespace`: the configuration and the namespace
/// have both reached every webhook replica (validation refuses a namespace it has not seen yet).
fn wait_rewritten(namespace: &str) {
    wait_until(
        &format!("the mutation to rewrite a pod in {namespace}"),
        RECONCILE,
        || {
            let pod = dry_run(&probe_pod(namespace, &json!({})))?;
            if pod.pointer("/spec/hostUsers") == Some(&json!(false)) {
                Ok(())
            } else {
                Err(format!("admitted unrewritten: {}", pod["spec"]))
            }
        },
    );
}

fn running_pod(workspace: &Workspace) -> Value {
    get(&["pod", "-n", &workspace.namespace, &workspace.pod()]).unwrap()
}

fn sh(workspace: &Workspace, script: &str) -> String {
    workspace
        .exec(&["sh", "-c", script])
        .unwrap_or_else(|err| fail(&err))
        .trim()
        .to_string()
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

/// Wait for `Failed`, returning DevWorkspace Operator's message and the namespace's
/// `FailedCreate` events: the message is DWO's copy of the event and may be cut.
fn wait_failed(workspace: &Workspace) -> String {
    let message = wait_until(
        &format!("devworkspace {} to fail", workspace.name),
        WORKSPACE_START,
        || {
            let object = workspace.object();
            match text(&object, "/status/phase").as_str() {
                "Failed" => Ok(text(&object, "/status/message")),
                "Running" => fail(&format!("{} runs: it should be refused", workspace.name)),
                phase => Err(format!("phase {phase:?}")),
            }
        },
    );
    let events = kubectl(&[
        "get",
        "events",
        "-n",
        &workspace.namespace,
        "--field-selector",
        "reason=FailedCreate",
        "-o",
        "jsonpath={range .items[*]}{.message}{\"\\n\"}{end}",
    ])
    .unwrap_or_default();
    format!("{message}\n{events}")
}

/// Every decision line of every webhook replica about `namespace` under `mode`.
fn webhook_lines(mode: &str, namespace: &str) -> Vec<String> {
    let needle = format!("feature=pod-identity mode={mode} ns={namespace} ");
    weebo_si_e2e::operator_pods("webhook")
        .iter()
        .filter_map(|pod| kubectl(&["logs", "-n", OPERATOR_NAMESPACE, pod, "--since=15m"]).ok())
        .flat_map(|logs| logs.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|line| line.contains(&needle))
        .collect()
}

fn counter(name: &str, labels: &[(&str, &str)]) -> f64 {
    metric_sum("webhook", name, labels)
}

/// The mutating half unregistered for the life of the guard, so a pod reaches validation as its
/// author wrote it (observation 3). Dropping it re-creates the configuration as it was.
struct MutationUnregistered(Value);

impl MutationUnregistered {
    #[track_caller]
    fn new(namespace: &str) -> Self {
        let mut saved = get(&["mutatingwebhookconfiguration", MUTATING_CONFIGURATION])
            .unwrap_or_else(|| {
                fail("no pod-identity mutating webhook: is podIdentity.webhooks.enabled on?")
            });
        if let Some(metadata) = saved["metadata"].as_object_mut() {
            for key in [
                "resourceVersion",
                "uid",
                "creationTimestamp",
                "generation",
                "managedFields",
            ] {
                metadata.remove(key);
            }
        }
        must(&[
            "delete",
            "mutatingwebhookconfiguration",
            MUTATING_CONFIGURATION,
        ]);
        let guard = Self(saved);
        wait_until("the mutation to be gone", RECONCILE, || {
            match dry_run(&probe_pod(namespace, &json!({}))) {
                Err(err) if err.contains("hostUsers is unset") => Ok(()),
                other => Err(format!("{other:?}")),
            }
        });
        guard
    }
}

impl Drop for MutationUnregistered {
    fn drop(&mut self) {
        // No panic in a drop: say it loudly instead, or later refusals point at the feature.
        if let Err(err) = kubectl_with(&["create", "-f", "-"], Some(&self.0.to_string())) {
            eprintln!("RESTORE FAILED for {MUTATING_CONFIGURATION}: {err}");
        }
        let deadline = Instant::now() + RECONCILE;
        while Instant::now() < deadline {
            if get(&["mutatingwebhookconfiguration", MUTATING_CONFIGURATION]).is_some() {
                return;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        eprintln!("RESTORE FAILED: {MUTATING_CONFIGURATION} still absent after {RECONCILE:?}");
    }
}

/// Observations 1, 2 and 4: two workspaces started at once, each at 1234:1234 with no group 0,
/// each in a node range of its own.
#[test]
fn two_workspaces_run_as_1234_without_group_zero_in_ranges_of_their_own() {
    let ns_name = "alice-identity";
    set_features(pod_identity("Enforce", ns_name));
    let ns = Namespace::workspace("alice", "identity", None);
    wait_rewritten(&ns.name);

    let first = Workspace::create(&ns.name, "first", &WorkspaceSpec::default());
    let second = Workspace::create(&ns.name, "second", &WorkspaceSpec::default());
    let mut starts = Vec::new();
    for workspace in [&first, &second] {
        workspace.wait_running();
        let pod = running_pod(workspace);
        assert_eq!(pod.pointer("/spec/hostUsers"), Some(&json!(false)));
        let context = &pod["spec"]["securityContext"];
        assert_eq!(context["runAsUser"], json!(1234), "{context}");
        assert_eq!(context["runAsGroup"], json!(1234), "{context}");
        assert_eq!(context["fsGroup"], json!(1234), "{context}");
        assert_eq!(
            context["supplementalGroupsPolicy"],
            json!("Strict"),
            "{context}"
        );
        assert_eq!(
            context["fsGroupChangePolicy"],
            json!("OnRootMismatch"),
            "{context}"
        );
        assert_eq!(context["runAsNonRoot"], json!(true), "{context}");

        // 1. (The e2e image carries no passwd entry for 1234, so `id` prints numbers only.)
        assert_eq!(
            sh(workspace, "echo $(id -u) $(id -g) $(id -G)"),
            "1234 1234 1234"
        );
        assert_eq!(
            sh(
                workspace,
                "test -w /etc/passwd && echo writable || echo read-only"
            ),
            "read-only",
            "/etc/passwd is g=u root:root in the image: only group 0 could write it"
        );
        // 4. The image's /etc/group cannot add a group under `Strict`.
        assert_eq!(
            sh(
                workspace,
                "grep '^Groups:' /proc/self/status | cut -f2- | xargs"
            ),
            "1234"
        );
        // Q20 in one line: a group-0 directory of the image is no longer writable.
        assert_eq!(
            sh(
                workspace,
                "test -w /home/user && echo writable || echo read-only"
            ),
            "read-only"
        );
        // 2.
        let map = sh(workspace, "head -1 /proc/self/uid_map");
        let fields: Vec<&str> = map.split_whitespace().collect();
        assert_eq!(fields.len(), 3, "{map}");
        assert_eq!(fields[0], "0", "{map}");
        assert_ne!(
            fields[1], "0",
            "the pod shares the node's user namespace: {map}"
        );
        assert_eq!(fields[2], "65536", "{map}");
        starts.push(fields[1].to_string());
    }
    println!("MEASURED node ranges: {starts:?}");
    assert_ne!(
        starts[0], starts[1],
        "two pods were given the same node range"
    );
}

/// Observation 3: each refusal names its fix, a workspace refused goes `Failed` with it, and a
/// refused direct pod leaves nothing behind.
#[test]
fn each_refusal_names_its_fix_and_leaves_no_pod() {
    let ns_name = "bob-identity";
    set_features(pod_identity("Enforce", ns_name));
    let ns = Namespace::workspace("bob", "identity", None);
    wait_rewritten(&ns.name);
    let denied = format!("admission webhook \"{VALIDATE}\" denied the request");

    // A container-level group 0 is the devfile's own choice: the mutation leaves it to validation.
    let mut manifest = Workspace::manifest(&ns.name, "group-zero", &WorkspaceSpec::default());
    manifest["spec"]["template"]["components"][0]["attributes"] =
        json!({ "container-overrides": { "securityContext": { "runAsGroup": 0 } } });
    apply(&manifest.to_string());
    let group_zero = Workspace {
        namespace: ns.name.clone(),
        name: "group-zero".to_string(),
    };
    let failure = wait_failed(&group_zero);
    assert!(failure.contains(&denied), "{failure}");
    assert!(
        failure.contains(
            "container \"tools\": securityContext.runAsGroup=0 is not allowed in a workspace \
             namespace; remove runAsGroup from the devfile's container-overrides or set a non-zero group"
        ),
        "{failure}"
    );
    drop(group_zero);

    let _unregistered = MutationUnregistered::new(&ns.name);

    let spec = WorkspaceSpec {
        attributes: json!({ "pod-overrides": { "spec": { "securityContext": { "fsGroup": 0 } } } }),
        ..WorkspaceSpec::default()
    };
    let fs_group = Workspace::create(&ns.name, "fs-group-zero", &spec);
    let failure = wait_failed(&fs_group);
    assert!(failure.contains(&denied), "{failure}");
    assert!(
        failure.contains(
            "securityContext.fsGroup=0 is not allowed in a workspace namespace; remove fsGroup \
             from the devfile's pod-overrides"
        ),
        "{failure}"
    );

    // Denials carry no status reason, so kubectl prints a bare "Error from server:" (seen on kind
    // 1.35), not the RFC mock's Forbidden.
    let err = try_apply(&probe_pod(&ns.name, &json!({ "hostUsers": true })).to_string())
        .expect_err("hostUsers: true must be refused");
    assert!(err.contains("exit status: 1"), "{err}");
    assert!(err.contains("Error from server"), "{err}");
    assert!(err.contains(&denied), "{err}");
    assert!(
        err.contains(
            "hostUsers=true: pods in a workspace namespace run in their own user namespace; \
             remove hostUsers from the pod spec (or the devfile's pod-overrides)"
        ),
        "{err}"
    );
    assert!(
        get(&["pod", "-n", &ns.name, "probe"]).is_none(),
        "a refused pod must not exist"
    );
}

/// Observations 6 and 5: a volume written before `Enforce` keeps its owner and stays writable
/// after a restart under it, and DevWorkspace Operator's cleanup Job, run under `Enforce` when
/// the workspace is deleted, is rewritten and completes.
#[test]
fn a_volume_from_before_enforce_keeps_its_owner_and_the_cleanup_job_is_rewritten() {
    let ns_name = "carol-identity";
    set_features(pod_identity("Off", ns_name));
    let ns = Namespace::workspace("carol", "identity", None);
    let mut manifest = Workspace::manifest(&ns.name, "volume", &WorkspaceSpec::default());
    manifest["spec"]["template"]["attributes"]["controller.devfile.io/storage-type"] =
        json!("common");
    manifest["spec"]["template"]["components"][0]["container"]["mountSources"] = json!(true);
    apply(&manifest.to_string());
    let workspace = Workspace {
        namespace: ns.name.clone(),
        name: "volume".to_string(),
    };
    workspace.wait_running();
    assert_ne!(
        running_pod(&workspace).pointer("/spec/hostUsers"),
        Some(&json!(false)),
        "under Off the pod keeps the node's user namespace"
    );
    let before = sh(
        &workspace,
        "echo before > /projects/before && stat -c %u /projects/before",
    );

    set_started(&workspace, false);
    wait_until("the workspace to stop", WORKSPACE_START, || {
        match text(&workspace.object(), "/status/phase").as_str() {
            "Stopped" => Ok(()),
            phase => Err(format!("phase {phase:?}")),
        }
    });
    set_features(pod_identity("Enforce", ns_name));
    wait_rewritten(&ns.name);
    set_started(&workspace, true);
    workspace.wait_running();
    assert_eq!(
        running_pod(&workspace).pointer("/spec/hostUsers"),
        Some(&json!(false))
    );
    println!("ls -n /projects: {}", sh(&workspace, "ls -n /projects"));
    assert_eq!(sh(&workspace, "stat -c %u /projects/before"), before);
    sh(&workspace, "touch /projects/after && cat /projects/before");

    let id = workspace.id();
    must(&[
        "delete",
        "devworkspace",
        "-n",
        &ns.name,
        "volume",
        "--wait=false",
    ]);
    // Read off the decision log, not the pod: a quick Job's pod can be created, succeed and be
    // collected with the workspace between two polls.
    let job = format!("name=\"cleanup-{id}");
    wait_until("the cleanup pod's decisions", RECONCILE, || {
        let lines: Vec<String> = webhook_lines("Enforce", &ns.name)
            .into_iter()
            .filter(|line| line.contains(&job))
            .collect();
        let rewritten = lines.iter().any(|line| line.contains("result=rewritten"));
        let allowed = lines.iter().any(|line| line.contains("result=allowed"));
        if rewritten && allowed {
            Ok(())
        } else {
            Err(format!(
                "cleanup pod not rewritten and allowed yet: {lines:?}"
            ))
        }
    });
    // DWO removes its finalizer only once the Job succeeded.
    wait_until("the workspace to be gone", WORKSPACE_START, || {
        match get(&["devworkspace", "-n", &ns.name, "volume"]) {
            None => Ok(()),
            Some(object) => Err(format!(
                "still there: {} {}",
                text(&object, "/status/phase"),
                text(&object, "/status/message")
            )),
        }
    });
}

/// Observation 8: once DevWorkspace Operator's config carries the values, `DryRun` has nothing to
/// say: `unchanged`, no rewrite counted, no real breakage counted.
#[test]
fn dry_run_is_quiet_on_a_pod_already_in_shape() {
    let ns_name = "dave-identity";
    let dwoc = "e2e-pod-identity";
    apply(
        &json!({
            "apiVersion": "controller.devfile.io/v1alpha1",
            "kind": "DevWorkspaceOperatorConfig",
            "metadata": { "name": dwoc, "namespace": "eclipse-che" },
            "config": { "workspace": {
                "hostUsers": false,
                "podSecurityContext": {
                    "runAsUser": 1234,
                    "runAsGroup": 1234,
                    "fsGroup": 1234,
                    "fsGroupChangePolicy": "OnRootMismatch",
                    "supplementalGroupsPolicy": "Strict",
                    "runAsNonRoot": true,
                },
            } },
        })
        .to_string(),
    );
    let _dwoc = Cleanup::new(&["devworkspaceoperatorconfig", "-n", "eclipse-che", dwoc]);
    set_features(pod_identity("DryRun", ns_name));
    let ns = Namespace::workspace("dave", "identity", None);
    // A namespace the webhook has not seen yet is an error, logged without a mode: wait until a
    // probe's decision is logged under DryRun. Its lines are left out below by name.
    wait_until(
        "the webhook to judge a pod in the namespace",
        RECONCILE,
        || {
            dry_run(&probe_pod(&ns.name, &json!({})))?;
            if webhook_lines("DryRun", &ns.name).is_empty() {
                Err("no DryRun decision yet".to_string())
            } else {
                Ok(())
            }
        },
    );

    let breakage = [("mode", "DryRun"), ("fixable_by_mutation", "false")];
    let refusals = counter("weebo_si_pod_identity_refusals_total", &breakage);
    let rewrites = counter(
        "weebo_si_pod_identity_rewrites_total",
        &[("mode", "DryRun")],
    );

    let spec = WorkspaceSpec {
        attributes: json!({
            "controller.devfile.io/devworkspace-config": { "name": dwoc, "namespace": "eclipse-che" },
        }),
        ..WorkspaceSpec::default()
    };
    let workspace = Workspace::create(&ns.name, "clean", &spec);
    workspace.wait_running();
    assert_eq!(
        running_pod(&workspace).pointer("/spec/hostUsers"),
        Some(&json!(false)),
        "DevWorkspace Operator must carry hostUsers from the DWOC onto the pod"
    );

    let lines = wait_until("the DryRun decision lines", RECONCILE, || {
        let lines: Vec<String> = webhook_lines("DryRun", &ns.name)
            .into_iter()
            .filter(|line| !line.contains("name=\"probe\""))
            .collect();
        if lines.iter().any(|line| line.contains("result=unchanged")) {
            Ok(lines)
        } else {
            Err(format!("no result=unchanged yet: {lines:?}"))
        }
    });
    for line in &lines {
        assert!(
            line.contains("result=unchanged") || line.contains("result=allowed"),
            "{line}"
        );
    }
    assert_eq!(
        counter("weebo_si_pod_identity_refusals_total", &breakage),
        refusals
    );
    assert_eq!(
        counter(
            "weebo_si_pod_identity_rewrites_total",
            &[("mode", "DryRun")]
        ),
        rewrites
    );
}
