//! The upgrade suite: RFC 0012's rolling upgrade, from the last release published before the
//! operator moved onto `weebo-operator-kit` to the build under test.
//!
//! `scripts/e2e.sh deploy upgrade` installs the *published* chart at `E2E_PREVIOUS_VERSION`
//! (default `0.2.1`) with its own images from GHCR; this suite then runs the `helm upgrade` to the
//! local chart and the `:e2e` image itself, while it watches two things:
//!
//! - **Admission never fails.** A server-side dry run of a `DevWorkspace` goes through the
//!   mutating webhook (`failurePolicy: Fail`) every half second during the roll; a single
//!   `failed calling webhook` is a refused write in production.
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

use weebo_si_e2e::{OPERATOR_NAMESPACE, Value, get, kubectl_with, operator_pods, repo_root, text};

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

    let stop = Arc::new(AtomicBool::new(false));
    let failures = Arc::new(Mutex::new(Vec::<String>::new()));
    let holders = Arc::new(Mutex::new(Vec::<(String, Vec<String>)>::new()));

    let admission = {
        let (stop, failures) = (Arc::clone(&stop), Arc::clone(&failures));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Err(err) =
                    kubectl_with(&["apply", "--dry-run=server", "-f", "-"], Some(PROBE))
                    && err.contains("failed calling webhook")
                {
                    failures.lock().unwrap().push(err);
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

    let root = repo_root();
    let status = Command::new("helm")
        .args([
            "upgrade",
            "weebo-si-operator",
            &format!("{root}/charts/weebo-si-operator"),
            "-n",
            OPERATOR_NAMESPACE,
            "-f",
            &format!("{root}/e2e/values/weebo-si-operator.yaml"),
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
        ])
        .status()
        .expect("helm runs");
    assert!(
        status.success(),
        "helm upgrade to the build under test failed"
    );
    // The new leader takes the lease once the old one released it or its TTL ran out: give the
    // probes a lease TTL past the end of the roll.
    std::thread::sleep(Duration::from_secs(20));
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
}
