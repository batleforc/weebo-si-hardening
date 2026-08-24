//! `weebo-si-operator canary` — "run the enforcement probe once and report, without the
//! controller," per RFC 0004's *Design → CLI*.
//!
//! It exists so that "is this cluster's CNI actually enforcing policy" is answerable **during an
//! install**, before `network-profiles` is switched on and before anyone trusts it — which is
//! step 1 of the RFC's own rollout: "If the canary says `not_enforcing`, stop: nothing below this
//! line will do anything, and finding that out now costs an afternoon rather than a quarter."
//!
//! That is why it runs a *pod pair* rather than dialing from this process: run by hand during an
//! install, this command is typically executed from outside the cluster, where the operator's own
//! network namespace is not the one under test.

use weebo_si_network_profiles::CanaryVerdict;
use weebo_si_runtime::{DEFAULT_CANARY_IMAGE, KubeCanary};

use crate::cli::flag;

/// Where the probe's pods are created when `--namespace` is not given and no downward-API
/// `POD_NAMESPACE` is set — the case of running this from a laptop against a remote cluster.
const DEFAULT_NAMESPACE: &str = "weebo-si-hardening";

/// Run the probe once, print the verdict, and exit.
///
/// A `not_enforcing` or `unknown` verdict is an `Err`, so the process exits non-zero and the
/// command is usable from a script or a CI gate. That is deliberate rather than incidental: the
/// failure this probe exists to catch is one where every object looks correct, so a command that
/// exits `0` while printing bad news is a command whose news gets missed.
pub async fn run(args: &[String]) -> Result<(), String> {
    let namespace = flag(args, "--namespace")
        .map(str::to_string)
        .or_else(|| std::env::var("POD_NAMESPACE").ok())
        .unwrap_or_else(|| DEFAULT_NAMESPACE.to_string());
    let image = flag(args, "--canary-image").unwrap_or(DEFAULT_CANARY_IMAGE);

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let canary = KubeCanary::new(client, &namespace, image);

    println!("weebo-si-operator canary: probing in namespace {namespace} with image {image}");
    let verdict = weebo_si_network_profiles::run_canary(&canary).await;

    // Unconditionally, and before reporting: a probe that errored still created pods, and this
    // command must not be the reason a namespace is left carrying a deny policy.
    if let Err(err) = weebo_si_network_profiles::CanaryProbe::cleanup(&canary).await {
        eprintln!("weebo-si-operator canary: cleanup failed: {err}");
    }

    let verdict = verdict.map_err(|err| format!("the canary probe could not run: {err}"))?;
    println!("weebo-si-operator canary: result={}", verdict.label());
    match verdict {
        CanaryVerdict::Enforcing => Ok(()),
        CanaryVerdict::NotEnforcing => Err(
            "this cluster's CNI does not enforce NetworkPolicy — network-profiles would write \
             objects that do nothing. Do not enable it until this is fixed."
                .to_string(),
        ),
        CanaryVerdict::Unknown => Err("the probe could not establish a baseline: the server pod \
                                       was unreachable before any policy was applied. Check the \
                                       pod's events and the canary image."
            .to_string()),
    }
}
