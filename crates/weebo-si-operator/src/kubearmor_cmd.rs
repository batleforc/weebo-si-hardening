//! `weebo-si-operator backends kubearmor` — per RFC 0006's *Design → CLI*: "prints whether the
//! `KubeArmorPolicy` CRD is installed (cluster-wide capability) and, if `--verbose`, every node's
//! `kubearmor.io/enforcer` label (node-level capability) — the two are different questions and
//! the command answers both rather than collapsing them."
//!
//! Answering both is the whole point of the subcommand. A cluster can serve the CRD on every
//! apiserver and enforce nothing on half its nodes, and an operator who reads only the first
//! answer believes a policy is enforced when it is merely present.

use k8s_openapi::api::core::v1::Node;
use kube::api::{Api, ListParams};
use kube::{Client, ResourceExt};
use weebo_si_crd::{KUBEARMOR_ENFORCER_LABEL, RuntimeBackend};
use weebo_si_kubearmor_policy::Capabilities;
use weebo_si_runtime::KubeArmorCapabilities;

/// Exit code when the cluster does not serve the CRD at all — distinct from a connection failure,
/// so a pipeline can tell "KubeArmor is not installed here" from "I could not ask".
const NOT_INSTALLED: &str = "this cluster does not serve the KubeArmorPolicy CRD";

/// Run the `backends kubearmor` subcommand: connect, discover, print, exit.
pub async fn run(verbose: bool) -> Result<(), String> {
    let client = Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;

    let capabilities = KubeArmorCapabilities::discover(client.clone())
        .await
        .map_err(|err| format!("could not discover KubeArmor capabilities: {err}"))?;
    let offered = capabilities.offers(RuntimeBackend::KubeArmor);

    println!("{:<16} {:<12} OFFERED", "BACKEND", "COMPILED-IN");
    println!(
        "{:<16} {:<12} {}",
        "KubeArmor",
        "yes",
        if offered { "yes" } else { "no" }
    );

    if !verbose {
        if !offered {
            println!("\n{NOT_INSTALLED}");
        }
        return Ok(());
    }

    // The second question. Asked as a one-shot list rather than through
    // `KubeNodeEnforcerView` — a CLI invocation has no watch cache to read and no reason to
    // build one, and the projection that adapter enforces is about what stays in a long-lived
    // process's memory, not about what a human runs once.
    let nodes: Api<Node> = Api::all(client);
    let list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|err| format!("could not list nodes: {err}"))?;

    println!("\n{:<40} ENFORCER", "NODE");
    let mut unenforced = 0usize;
    for node in &list {
        let enforcer = node
            .labels()
            .get(KUBEARMOR_ENFORCER_LABEL)
            .filter(|value| !value.is_empty());
        if enforcer.is_none() {
            unenforced += 1;
        }
        println!(
            "{:<40} {}",
            node.name_any(),
            enforcer.map(String::as_str).unwrap_or("<none>")
        );
    }

    if unenforced > 0 {
        // Printed, not returned as an error: a node with no LSM is a fact about the cluster, and
        // this command reports facts. Refusing here would make it unusable as the pre-install
        // check it exists to be.
        println!(
            "\n{unenforced} of {} nodes report no usable enforcer — a policy scheduled there is \
             present, not enforced",
            list.items.len()
        );
    }

    Ok(())
}
