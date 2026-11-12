//! The upgrade suite: a rolling upgrade from the previous published release to the build under
//! test — first written for RFC 0012's move onto `weebo-operator-kit`, now also RFC 0017's
//! webhooks switching on.
//!
//! `scripts/e2e.sh deploy upgrade` installs the *published* chart at `E2E_PREVIOUS_VERSION`
//! (default `0.3.0`) with its own images from GHCR; this suite then upgrades to the local chart
//! and the `:e2e` image itself, **in the two steps the chart documents for a release without RFC
//! 0017's routes**: first with `imageRewrite.webhooks.enabled=false`, which rolls the pods onto
//! the build that serves the routes, then with the default, which only registers the webhooks.
//! Throughout, it watches:
//!
//! - **Admission never fails.** A server-side dry run of a `DevWorkspace` goes through the
//!   mutating webhook (`failurePolicy: Fail`) every half second during the roll; a single
//!   `failed calling webhook` is a refused write in production.
//! - **A workspace pod is never refused** (RFC 0017). The same probe, as a pod in a workspace
//!   namespace, goes through the `/mutate/v1/pods` webhook once the second step registers it with
//!   `failurePolicy: Fail`. Registering it while a 0.3.0 pod still answered would be a 404 here;
//!   so would a webhook created before cainjector filled its `caBundle`, which the chart avoids by
//!   copying the bundle `dwoc-pin`'s webhook already carries.
//! - **`imageRewrite` survives the CRD step.** `helm upgrade` never touches `crds/`, so the suite
//!   applies them first, as the upgrade notes say, then writes an `imageRewrite` block and reads
//!   it back: a stale CRD prunes it silently and leaves the feature `Off`.
//! - **One leader at a time.** The old controller elects through `kube-leader-election`, the new
//!   one through the kit's lease, on the same `Lease`. Every holder the `Lease` names during the
//!   roll must be a running controller pod, the holder must change at most once per controller
//!   pod replaced, and once the roll is over it must be a pod of the new version.

#![cfg(feature = "e2e")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use weebo_si_e2e::{
    Namespace, OPERATOR_NAMESPACE, Value, apply, get, json, kubectl, kubectl_with, must,
    operator_pods, repo_root, text, wait_until,
};

const LEASE: &str = "weebo-si-controller-leader";

fn lease() -> (String, i64) {
    let lease = get(&["lease", LEASE, "-n", OPERATOR_NAMESPACE]).unwrap_or(Value::Null);
    let holder = text(&lease, "/spec/holderIdentity");
    let transitions = lease
        .pointer("/spec/leaseTransitions")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    (holder, transitions)
}

fn controller_image(pod: &str) -> String {
    let pod = get(&["pod", pod, "-n", OPERATOR_NAMESPACE]).unwrap_or(Value::Null);
    text(&pod, "/spec/containers/0/image")
}

const PROBE: &str = r#"apiVersion: workspace.devfile.io/v1alpha2
kind: DevWorkspace
metadata: { name: e2e-upgrade-probe, namespace: default }
spec: { started: false, template: {} }
"#;

#[test]
fn a_rolling_upgrade_onto_the_kit_keeps_admission_up_and_one_leader() {
    let before = operator_pods("controller");
    assert!(
        !before.is_empty(),
        "no controller pod running — run `scripts/e2e.sh deploy upgrade` first"
    );
    let (holder, transitions_before) = lease();
    assert!(
        before.contains(&holder),
        "the previous release's leader {holder:?} is not one of its controller pods {before:?}"
    );
    let old_images: Vec<String> = before.iter().map(|pod| controller_image(pod)).collect();

    // The release the suite upgrades from was installed seconds ago: `helm --wait` returns on
    // pod readiness, and kube-proxy programs the Service's endpoints a moment later, during
    // which the apiserver's call to the ClusterIP is refused. A failure before the roll has
    // begun measures that start-up, not the roll (nightly of 2026-11-01), so the first dry run
    // must pass before the probe starts counting.
    wait_until(
        "the previous release admits a dry run",
        Duration::from_secs(60),
        || kubectl_with(&["apply", "--dry-run=server", "-f", "-"], Some(PROBE)).map(drop),
    );

    // The CRD step of the upgrade notes, then an `imageRewrite` block read back whole.
    let root = repo_root();
    must(&[
        "apply",
        "--server-side",
        "--force-conflicts",
        "-f",
        &format!("{root}/charts/weebo-si-operator/crds/"),
    ]);
    let rules = json!([{ "from": "example.invalid", "to": "localhost/e2e" }]);
    apply(
        &json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiConfig",
            "metadata": { "name": "cluster" },
            "spec": { "features": { "imageRewrite": { "mode": "Enforce", "rules": rules } } },
        })
        .to_string(),
    );
    let stored = get(&["weebosiconfig", "cluster"]).unwrap_or(Value::Null);
    assert_eq!(
        stored.pointer("/spec/features/imageRewrite/rules"),
        Some(&rules),
        "the CRD step did not take: imageRewrite was pruned from the stored config"
    );
    let ns = Namespace::workspace("upgrade", "pods", None);

    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(Mutex::new(Vec::<String>::new()));
    let holders = Arc::new(Mutex::new(Vec::<(String, Vec<String>)>::new()));

    let admission = {
        let (stop, failures) = (Arc::clone(&stop), Arc::clone(&failures));
        let namespace = ns.name.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let workspace =
                    kubectl_with(&["apply", "--dry-run=server", "-f", "-"], Some(PROBE));
                let pod = kubectl(&[
                    "run",
                    "e2e-upgrade-pod",
                    "-n",
                    &namespace,
                    "--image=example.invalid/e2e-workspace:e2e",
                    "--restart=Never",
                    "--dry-run=server",
                ]);
                for result in [workspace, pod] {
                    if let Err(err) = result
                        && err.contains("failed calling webhook")
                    {
                        failures.lock().unwrap().push(err);
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        })
    };
    let leadership = {
        let (stop, holders) = (Arc::clone(&stop), Arc::clone(&holders));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let (holder, _) = lease();
                let running = operator_pods("controller");
                holders.lock().unwrap().push((holder, running));
                std::thread::sleep(Duration::from_secs(1));
            }
        })
    };

    let helm_upgrade = |extra: &[&str]| {
        let chart = format!("{root}/charts/weebo-si-operator");
        let values = format!("{root}/e2e/values/weebo-si-operator.yaml");
        let mut args = vec![
            "upgrade",
            "weebo-si-operator",
            chart.as_str(),
            "-n",
            OPERATOR_NAMESPACE,
            "-f",
            values.as_str(),
            "--set",
            "image.repository=localhost/weebo-si-operator",
            "--set",
            "image.tag=e2e",
            "--set",
            "image.pullPolicy=Never",
            "--set",
            "namespace.create=false",
            "--wait",
            "--timeout",
            "10m",
        ];
        args.extend_from_slice(extra);
        let status = Command::new("helm")
            .args(&args)
            .status()
            .expect("helm runs");
        assert!(
            status.success(),
            "helm upgrade {extra:?} to the build under test failed"
        );
    };
    // Step 1: the pods roll onto the build that serves the routes, webhooks still unregistered.
    helm_upgrade(&["--set", "imageRewrite.webhooks.enabled=false"]);
    // Step 2: the webhooks, served by pods that all have the routes now.
    helm_upgrade(&[]);
    // The new leader takes the lease once the old one released it or its TTL ran out. An old pod
    // in its 30s grace period still reads `Running`, so wait for the handover rather than a fixed
    // delay; the probes keep sampling throughout.
    wait_until(
        "the lease to move to a controller pod on the build under test",
        Duration::from_secs(120),
        || {
            let (holder, _) = lease();
            let image = controller_image(&holder);
            if operator_pods("controller").contains(&holder)
                && image == "localhost/weebo-si-operator:e2e"
            {
                Ok(())
            } else {
                Err(format!("held by {holder:?} ({image})"))
            }
        },
    );
    stop.store(true, Ordering::Relaxed);
    admission.join().unwrap();
    leadership.join().unwrap();

    let failures = failures.lock().unwrap();
    assert!(
        failures.is_empty(),
        "admission failed {} time(s) during the roll; first: {}",
        failures.len(),
        failures.first().map(String::as_str).unwrap_or_default()
    );

    let holders = holders.lock().unwrap();
    for (holder, running) in holders.iter() {
        assert!(
            holder.is_empty() || running.contains(holder) || before.contains(holder),
            "the Lease named {holder:?}, which is not a controller pod (running: {running:?})"
        );
    }
    let mut changes = 0usize;
    for pair in holders.windows(2) {
        if !pair[1].0.is_empty() && pair[1].0 != pair[0].0 {
            changes += 1;
        }
    }
    assert!(
        changes <= before.len() + 1,
        "the leader changed {changes} times while {} controller pod(s) were replaced — flapping",
        before.len()
    );

    let after = operator_pods("controller");
    let (holder, transitions_after) = lease();
    assert!(
        after.contains(&holder),
        "after the roll the leader {holder:?} is not one of the new controller pods {after:?}"
    );
    let new_image = controller_image(&holder);
    assert_eq!(new_image, "localhost/weebo-si-operator:e2e");
    assert!(
        !old_images.contains(&new_image),
        "the controller image did not change — was the previous release really installed?"
    );
    assert!(
        transitions_after > transitions_before,
        "leaseTransitions did not move ({transitions_before} → {transitions_after})"
    );

    // After the roll the rewrite runs: the probe pod comes back under the mirror name.
    let rewritten = kubectl(&[
        "run",
        "e2e-upgrade-pod",
        "-n",
        &ns.name,
        "--image=example.invalid/e2e-workspace:e2e",
        "--restart=Never",
        "--dry-run=server",
        "-o",
        "jsonpath={.spec.containers[0].image}",
    ])
    .expect("the probe pod is admitted after the roll");
    assert_eq!(rewritten, "localhost/e2e/e2e-workspace:e2e");
}
