//! `weebo-si-operator backends` — "which are compiled in and which the cluster actually offers,"
//! per RFC 0004's *Design → CLI*: answerable during an install, before `network-profiles` is
//! switched on and before anyone trusts it.

use weebo_si_crd::Backend;
use weebo_si_network_profiles::Capabilities;
use weebo_si_runtime::KubeCapabilities;

/// Every backend this binary knows how to write, in the order `Auto` resolution prefers them —
/// see `weebo_si_network_profiles::backend::resolve_backend`.
const COMPILED_IN: &[Backend] = &[Backend::Cilium, Backend::NetworkPolicy];

/// Run the `backends` subcommand: connect, discover, print, exit.
pub async fn run() -> Result<(), String> {
    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;
    let capabilities = KubeCapabilities::discover(client)
        .await
        .map_err(|err| format!("could not discover apiserver capabilities: {err}"))?;

    println!("{:<14} {:<12} OFFERED", "BACKEND", "COMPILED-IN");
    for backend in COMPILED_IN {
        let offered = capabilities.offers(*backend);
        println!(
            "{:<14} {:<12} {}",
            format!("{backend:?}"),
            "yes",
            if offered { "yes" } else { "no" }
        );
    }
    Ok(())
}
