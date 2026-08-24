//! `weebo-si-operator controller` — the composition root for the controller role.

use std::net::SocketAddr;

use weebo_si_controller::LeaderElection;

use crate::cli::{flag, has_flag};
use crate::observability::{self, Ready};

const DEFAULT_LEASE_NAMESPACE: &str = "default";
const DEFAULT_HOLDER_ID: &str = "not-a-pod";

/// Run the controller role until the process is asked to stop.
pub async fn run(args: &[String]) -> Result<(), String> {
    let metrics_addr: SocketAddr = flag(args, "--metrics-addr")
        .unwrap_or("0.0.0.0:8080")
        .parse()
        .map_err(|err| format!("invalid --metrics-addr: {err}"))?;
    let health_addr: SocketAddr = flag(args, "--health-addr")
        .unwrap_or("0.0.0.0:8081")
        .parse()
        .map_err(|err| format!("invalid --health-addr: {err}"))?;

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;

    let ready = Ready::default();
    ready.mark_ready();
    let prometheus_registry = prometheus::Registry::new();
    tokio::spawn(observability::serve(
        health_addr,
        ready,
        prometheus_registry,
    ));

    // `POD_NAMESPACE`/`HOSTNAME` are the standard downward-API env vars a Deployment sets — the
    // manifest wires `POD_NAMESPACE` from `metadata.namespace` and `HOSTNAME` is set by the
    // kubelet to the pod name automatically. The fallbacks only matter outside a cluster, where
    // leader election is off by default anyway (single-replica local runs).
    let leader_election = has_flag(args, "--leader-election").then(|| LeaderElection {
        namespace: std::env::var("POD_NAMESPACE")
            .unwrap_or_else(|_| DEFAULT_LEASE_NAMESPACE.to_string()),
        holder_id: std::env::var("HOSTNAME").unwrap_or_else(|_| DEFAULT_HOLDER_ID.to_string()),
    });

    println!(
        "weebo-si-operator controller running (leader-election={}), metrics/health on {metrics_addr}/{health_addr}",
        leader_election.is_some()
    );
    weebo_si_controller::run(client, leader_election).await;
    Ok(())
}
