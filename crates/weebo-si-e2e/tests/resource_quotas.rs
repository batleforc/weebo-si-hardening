//! The resource-quotas suite: RFC 0014 against a real apiserver with its quota controller running,
//! which the envtest has not. The point is the refusal: a namespace given a profile by this feature
//! refuses what the profile forbids, `mode: Off` takes the profile away, and a foreign quota is
//! never touched.
//!
//! The last test is a **measurement**: whether a workspace refused by a quota shows why in the
//! DevWorkspace status, which is what Che's dashboard displays (RFC 0014's open question).

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
    Cleanup, Namespace, RECONCILE, Value, Workspace, WorkspaceSpec, apply, feature_status, get,
    json, set_features, text, try_apply, wait_until,
};

const TEMPLATES: &str = "weebo-si-hardening-templates";

fn template(kind: &str, name: &str, spec: Value) -> Cleanup {
    apply(
        &json!({
            "apiVersion": "v1",
            "kind": kind,
            "metadata": { "name": name, "namespace": TEMPLATES },
            "spec": spec,
        })
        .to_string(),
    );
    Cleanup::new(&[&kind.to_lowercase(), "-n", TEMPLATES, name])
}

/// The RFC's cautious first profile: object counts and service types, no compute quota.
fn counts_template() -> Cleanup {
    template(
        "ResourceQuota",
        "quota-counts",
        json!({ "hard": { "services.nodeports": "0", "persistentvolumeclaims": "2" } }),
    )
}

fn quotas(mode: &str, default: &str) -> Value {
    json!({
        "mode": mode,
        "namespaceSelector": { "matchExpressions": [{ "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" }] },
        "catalog": [
            { "key": "counts", "quotaRef": { "name": "quota-counts", "namespace": TEMPLATES } },
            { "key": "no-pods", "quotaRef": { "name": "quota-no-pods", "namespace": TEMPLATES } },
            { "key": "broken", "quotaRef": { "name": "quota-compute", "namespace": TEMPLATES } },
        ],
        "default": default,
    })
}

fn node_port_service(namespace: &str) -> String {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": { "name": "exposed", "namespace": namespace },
        "spec": { "type": "NodePort", "selector": { "app": "none" }, "ports": [{ "port": 80 }] },
    })
    .to_string()
}

fn wait_for_quota(namespace: &str) -> Value {
    wait_until(&format!("weebo-quota in {namespace}"), RECONCILE, || {
        get(&["resourcequota", "-n", namespace, "weebo-quota"]).ok_or_else(|| "absent".to_string())
    })
}

#[test]
fn a_profile_is_enforced_by_the_apiserver_and_off_takes_it_away() {
    let _counts = counts_template();
    set_features(json!({ "resourceQuotas": quotas("Enforce", "counts") }));
    let ns = Namespace::workspace("alice", "quota", None);

    // Che's own kind of foreign quota, which must survive everything below.
    apply(
        &json!({
            "apiVersion": "v1",
            "kind": "ResourceQuota",
            "metadata": { "name": "foreign", "namespace": ns.name },
            "spec": { "hard": { "pods": "100" } },
        })
        .to_string(),
    );

    let quota = wait_for_quota(&ns.name);
    assert_eq!(
        text(&quota, "/metadata/labels/hardening.weebo.io~1profile"),
        "counts"
    );
    // The quota controller fills `status.hard` before admission enforces it.
    wait_until("the quota controller to fill status", RECONCILE, || {
        let quota = get(&["resourcequota", "-n", &ns.name, "weebo-quota"]).ok_or("absent")?;
        if text(&quota, "/status/hard/services.nodeports") == "0" {
            Ok(())
        } else {
            Err("no status yet".to_string())
        }
    });
    let err = try_apply(&node_port_service(&ns.name))
        .expect_err("services.nodeports: 0 must refuse a NodePort service");
    assert!(err.contains("exceeded quota"), "{err}");
    assert_eq!(text(&feature_status("resource-quotas"), "/state"), "Active");

    set_features(json!({ "resourceQuotas": quotas("Off", "counts") }));
    wait_until("weebo-quota to be deleted", RECONCILE, || {
        match get(&["resourcequota", "-n", &ns.name, "weebo-quota"]) {
            None => Ok(()),
            Some(_) => Err("still there".to_string()),
        }
    });
    assert!(
        get(&["resourcequota", "-n", &ns.name, "foreign"]).is_some(),
        "a quota this feature did not write is never deleted"
    );
}

#[test]
fn an_invalid_profile_is_never_written() {
    // A compute quota and no LimitRange: every pod without a request would be refused.
    let _compute = template(
        "ResourceQuota",
        "quota-compute",
        json!({ "hard": { "requests.cpu": "4" } }),
    );
    let _counts = counts_template();
    set_features(json!({ "resourceQuotas": quotas("Enforce", "broken") }));
    let ns = Namespace::workspace("bob", "quota-broken", None);

    std::thread::sleep(Duration::from_secs(20));
    assert!(
        get(&["resourcequota", "-n", &ns.name, "weebo-quota"]).is_none(),
        "an invalid profile must not reach a namespace"
    );
}

#[test]
fn measure_whether_a_quota_refusal_reaches_the_devworkspace_status() {
    let _no_pods = template(
        "ResourceQuota",
        "quota-no-pods",
        json!({ "hard": { "pods": "0" } }),
    );
    let _counts = counts_template();
    set_features(json!({ "resourceQuotas": quotas("Enforce", "no-pods") }));
    let ns = Namespace::workspace("carol", "quota-ws", None);
    wait_for_quota(&ns.name);
    wait_until("the quota controller to fill status", RECONCILE, || {
        let quota = get(&["resourcequota", "-n", &ns.name, "weebo-quota"]).ok_or("absent")?;
        if text(&quota, "/status/hard/pods") == "0" {
            Ok(())
        } else {
            Err("no status yet".to_string())
        }
    });

    let workspace = Workspace::create(&ns.name, "tools", &WorkspaceSpec::default());
    let started = Instant::now();
    let verdict = loop {
        let object = get(&["devworkspace", "-n", &ns.name, "tools"]).unwrap_or(Value::Null);
        let phase = text(&object, "/status/phase");
        let message = text(&object, "/status/message");
        if phase == "Running" {
            break "Running — the quota did not refuse it".to_string();
        }
        if message.contains("quota")
            || phase == "Failed"
            || started.elapsed() > Duration::from_secs(300)
        {
            break format!("phase {phase:?}, status message: {message:?}");
        }
        std::thread::sleep(Duration::from_secs(10));
    };
    println!("MEASURED devworkspace refused by a quota: {verdict}");
    drop(workspace);
}
