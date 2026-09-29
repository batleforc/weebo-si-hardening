//! The `WeeboSiConfig` reconcile loop — see RFC 0002, the controller role — and, per RFC 0004,
//! the `network-profiles` `Namespace`/`DevWorkspace` reconcile loops.

pub mod endpoint_auth;
pub mod identity;
pub mod kubearmor_policy;
pub mod network_profiles;
pub mod reconcile;
pub mod registry_config;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use kube::runtime::Controller;
use kube::runtime::watcher::Config;
use kube::{Api, Client};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use weebo_si_crd::WeeboSiConfig;

pub use endpoint_auth::EndpointAuthDeps;
pub use identity::{IdentityDeps, reconcile_team, reconcile_user};
pub use kubearmor_policy::KubeArmorPolicyDeps;
pub use network_profiles::NetworkProfilesDeps;
pub use reconcile::{Ctx, Error, error_policy, reconcile as reconcile_fn};
pub use registry_config::RegistryConfigDeps;

/// Leader election parameters. Not optional fields on [`run`] itself — constructing this at all
/// is the caller's decision to enable leader election, matching the CLI's `--leader-election`
/// flag being off by default.
pub struct LeaderElection {
    /// The namespace the `Lease` object lives in — typically this pod's own namespace.
    pub namespace: String,
    /// This replica's identity in the lease — typically this pod's name.
    pub holder_id: String,
}

/// Run the reconcile loop until the process is asked to stop. Runs to completion of the input
/// stream, which in practice means "forever" — `kube-runtime`'s watcher retries on its own.
///
/// Without `leader_election`, every replica reconciles — safe for exactly one replica, per RFC
/// 0002's original single-replica assumption. With it, every replica watches (kube-runtime gives
/// every replica the same stream), but only the lease holder's [`reconcile::reconcile`] actually
/// writes; the rest requeue without acting. `network_profiles`, `kubearmor_policy` and
/// `registry_config`, when `Some`, share the same `is_leader` flag — one lease covers every loop
/// this role runs.
pub async fn run(
    client: Client,
    leader_election: Option<LeaderElection>,
    network_profiles: Option<NetworkProfilesDeps>,
    kubearmor_policy: Option<KubeArmorPolicyDeps>,
    registry_config: Option<RegistryConfigDeps>,
    endpoint_auth: Option<EndpointAuthDeps>,
    identity: Option<IdentityDeps>,
) {
    let is_leader = Arc::new(AtomicBool::new(leader_election.is_none()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::clone(&is_leader),
    });

    if let Some(deps) = network_profiles {
        network_profiles::spawn(client.clone(), deps, Arc::clone(&is_leader)).await;
    }

    if let Some(deps) = kubearmor_policy {
        kubearmor_policy::spawn(client.clone(), deps, Arc::clone(&is_leader)).await;
    }

    if let Some(deps) = registry_config {
        registry_config::spawn(client.clone(), deps, Arc::clone(&is_leader)).await;
    }

    if let Some(deps) = endpoint_auth {
        endpoint_auth::spawn(client.clone(), deps, Arc::clone(&is_leader)).await;
    }

    if let Some(deps) = identity {
        identity::spawn(client.clone(), deps, Arc::clone(&is_leader)).await;
    }

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let controller = Controller::new(api, Config::default())
        .shutdown_on_signal()
        .run(reconcile_fn, error_policy, ctx)
        .for_each(|_| futures_util::future::ready(()));

    match leader_election {
        Some(election) => {
            let leadership = LeaseLock::new(
                client,
                &election.namespace,
                LeaseLockParams {
                    holder_id: election.holder_id,
                    lease_name: "weebo-si-controller-leader".to_string(),
                    lease_ttl: Duration::from_secs(15),
                },
            );
            tokio::select! {
                () = controller => {},
                () = run_leader_election(&leadership, Arc::clone(&is_leader)) => {},
            }
            // Shutting down: stop acting as leader first, then hand the lease back so the next
            // replica takes over now rather than after the lease's TTL runs out.
            // Only the holder has a lease to give back: `step_down` on any other replica answers
            // `ReleaseLockWhenNotLeading`, which is not an error worth a log line on every
            // rollout.
            let was_leader = is_leader.swap(false, Ordering::Relaxed);
            if was_leader
                && let Ok(Err(err)) =
                    tokio::time::timeout(RENEW_TIMEOUT, leadership.step_down()).await
            {
                eprintln!("ERROR weebo-si-controller: releasing the leader lease: {err}");
            }
        }
        None => controller.await,
    }
}

/// Acquire-or-renew the lease every 5s, keeping `is_leader` current. Demotes as well as
/// promotes: `try_acquire_or_renew` returns `Ok(NotAcquired)` (not an `Err`) when another
/// instance holds the lease, so a leader that fails to renew in time must have this loop clear
/// `is_leader` itself — otherwise a stale leader keeps reconciling alongside the new one
/// (split-brain).
///
/// Each attempt is bounded by [`RENEW_TIMEOUT`], well inside the lease's 15s TTL: an apiserver
/// call that hangs would otherwise leave `is_leader` true after the lease expired and another
/// replica took it — the same split-brain, reached by waiting rather than by failing.
async fn run_leader_election(leadership: &LeaseLock, is_leader: Arc<AtomicBool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        match tokio::time::timeout(RENEW_TIMEOUT, leadership.try_acquire_or_renew()).await {
            Ok(Ok(lease)) => {
                let acquired = matches!(lease, LeaseLockResult::Acquired(_));
                is_leader.store(acquired, Ordering::Relaxed);
            }
            Ok(Err(err)) => {
                eprintln!("ERROR weebo-si-controller: leader election: {err}");
                is_leader.store(false, Ordering::Relaxed);
            }
            Err(_) => {
                eprintln!(
                    "ERROR weebo-si-controller: leader election: renew timed out after {}s",
                    RENEW_TIMEOUT.as_secs()
                );
                is_leader.store(false, Ordering::Relaxed);
            }
        }
        interval.tick().await;
    }
}

/// How long one acquire-or-renew may take before this replica stops considering itself leader.
const RENEW_TIMEOUT: Duration = Duration::from_secs(4);
