//! The kubearmor suite: `kubearmor-policy` against a real KubeArmor, asserted where it matters —
//! a process the policy blocks is refused inside a workspace DevWorkspace Operator started, and
//! the same process runs in the neighbour the policy does not select.
//!
//! Enforcement needs an LSM KubeArmor can drive on the node (BPF-LSM or AppArmor). The first
//! test says which one the node reported, so a red run on a node without one reads as that rather
//! than as a policy bug.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use weebo_si_e2e::{
    Cleanup, Namespace, OPERATOR_NAMESPACE, RECONCILE, Value, Workspace, WorkspaceSpec, apply,
    feature_status, get, json, kubectl, metric_sum, must, set_features, team, text, wait_until,
};

/// A template blocking one binary. Its own selector matches nothing: it is a live object in the
/// operator's namespace, and the operator replaces the selector on every copy it writes anyway.
fn block_template(name: &str, path: &str) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "security.kubearmor.com/v1",
            "kind": "KubeArmorPolicy",
            "metadata": { "name": name, "namespace": OPERATOR_NAMESPACE },
            "spec": {
                "selector": { "matchLabels": { "e2e.weebo.io/template": "never-matches" } },
                "process": { "matchPaths": [{ "path": path }] },
                "action": "Block",
            },
        })
        .to_string(),
    );
    Cleanup::new(&["kubearmorpolicy", "-n", OPERATOR_NAMESPACE, name])
}

fn kubearmor_policy() -> Value {
    json!({
        "mode": "Enforce",
        "namespaceSelector": { "matchExpressions": [{ "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" }] },
        "catalog": [{ "key": "base", "templateRef": { "name": "e2e-no-nc", "namespace": OPERATOR_NAMESPACE } }],
        "baseline": "base",
        "onNotGranted": "Deny",
        "enforcement": {
            "backend": "KubeArmor",
            "defaultPosture": { "file": "Audit", "network": "Audit", "capabilities": "Audit" },
        },
    })
}

fn no_cat_team() -> Cleanup {
    team(
        "e2e-locked",
        json!({
            "priority": 10,
            "namespaceSelector": { "matchLabels": { "weebo.io/team": "locked" } },
            "features": { "kubearmorPolicy": {
                "catalog": [{ "key": "no-cat", "templateRef": { "name": "e2e-no-cat", "namespace": OPERATOR_NAMESPACE } }],
                "default": [],
            } },
        }),
    )
}

fn node_enforcer() -> String {
    let nodes = get(&["nodes"]).unwrap();
    text(&nodes, "/items/0/metadata/labels/kubearmor.io~1enforcer")
}

fn blocked(workspace: &Workspace, command: &[&str]) -> bool {
    match workspace.exec(command) {
        Ok(_) => false,
        Err(err) => err.contains("Permission denied") || err.contains("permission denied"),
    }
}

#[test]
fn the_baseline_and_the_posture_land_on_every_namespace_in_scope() {
    let _base = block_template("e2e-no-nc", "/usr/bin/nc");
    set_features(json!({ "kubearmorPolicy": kubearmor_policy() }));
    let ns = Namespace::workspace("alice", "armor-base", None);

    let baseline = wait_until("the baseline KubeArmorPolicy", RECONCILE, || {
        get(&["kubearmorpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    assert_eq!(
        text(&baseline, "/metadata/labels/hardening.weebo.io~1backend"),
        "KubeArmor"
    );
    assert_eq!(
        baseline
            .pointer("/spec/process/matchPaths/0/path")
            .and_then(Value::as_str),
        Some("/usr/bin/nc")
    );
    assert_ne!(
        text(
            &baseline,
            "/spec/selector/matchLabels/e2e.weebo.io~1template"
        ),
        "never-matches",
        "the template's own selector must not survive into the copy"
    );

    let namespace = get(&["namespace", &ns.name]).unwrap();
    for kind in ["file", "network", "capabilities"] {
        assert_eq!(
            text(
                &namespace,
                &format!("/metadata/annotations/kubearmor-{kind}-posture")
            ),
            "audit",
            "posture annotation for {kind}"
        );
    }
    assert_eq!(
        text(&feature_status("kubearmor-policy"), "/state"),
        "Active"
    );
    println!("node enforcer: {:?}", node_enforcer());
}

#[test]
fn a_granted_profile_blocks_a_process_in_its_own_workspace_only() {
    let _base = block_template("e2e-no-nc", "/usr/bin/nc");
    let _cat = block_template("e2e-no-cat", "/usr/bin/cat");
    let _team = no_cat_team();
    set_features(json!({ "kubearmorPolicy": kubearmor_policy() }));
    let enforcer = node_enforcer();
    assert!(
        !enforcer.is_empty() && enforcer != "none",
        "KubeArmor reports no enforcer on this node (label kubearmor.io/enforcer={enforcer:?}); \
         nothing below can be enforced here"
    );

    let ns = Namespace::workspace("carol", "armor", Some("locked"));
    let locked = Workspace::create(
        &ns.name,
        "locked",
        &WorkspaceSpec {
            attributes: json!({ "hardening.weebo.io/kubearmor-policy": "no-cat" }),
            ..WorkspaceSpec::default()
        },
    );
    let free = Workspace::create(&ns.name, "free", &WorkspaceSpec::default());
    locked.wait_running();
    free.wait_running();

    let id = locked.id();
    wait_until("the workspace's own profile object", RECONCILE, || {
        let object = get(&[
            "kubearmorpolicy",
            "-n",
            &ns.name,
            &format!("weebo-no-cat-{id}"),
        ])
        .ok_or("absent")?;
        let selected = text(
            &object,
            "/spec/selector/matchLabels/controller.devfile.io~1devworkspace_id",
        );
        if selected == id {
            Ok(())
        } else {
            Err(format!("selects {selected:?}"))
        }
    });

    wait_until(
        "cat to be refused in the locked workspace",
        RECONCILE,
        || {
            if blocked(&locked, &["cat", "/etc/hostname"]) {
                Ok(())
            } else {
                Err("cat still runs".into())
            }
        },
    );
    assert!(
        free.exec(&["cat", "/etc/hostname"]).is_ok(),
        "the profile must select its own workspace only"
    );
    wait_until("the enforced gauge", RECONCILE, || {
        let enforced = metric_sum(
            "controller",
            "weebo_si_kubearmor_enforced",
            &[("state", "enforced")],
        );
        if enforced >= 1.0 {
            Ok(())
        } else {
            Err(format!("enforced {enforced}"))
        }
    });
}

#[test]
fn a_managed_kubearmor_policy_is_guarded_like_a_network_policy() {
    let _base = block_template("e2e-no-nc", "/usr/bin/nc");
    set_features(json!({
        "kubearmorPolicy": kubearmor_policy(),
        "policyGuard": { "mode": "Enforce", "namespaceSelector": { "matchExpressions": [{ "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" }] } },
    }));
    let ns = Namespace::workspace("bob", "armor-guard", None);
    wait_until("the baseline", RECONCILE, || {
        get(&["kubearmorpolicy", "-n", &ns.name, "weebo-base"]).ok_or_else(|| "absent".to_string())
    });
    let err = kubectl(&["delete", "kubearmorpolicy", "-n", &ns.name, "weebo-base"])
        .expect_err("deleting a managed KubeArmorPolicy must be refused");
    assert!(err.contains("is managed by weebo-si-operator"), "{err}");
    let _ = must(&["get", "kubearmorpolicy", "-n", &ns.name, "weebo-base"]);
}
