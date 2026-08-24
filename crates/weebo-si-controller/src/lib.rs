//! The `WeeboSiConfig` reconcile loop — see RFC 0002, the controller role.

pub mod reconcile;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use kube::runtime::Controller;
use kube::runtime::watcher::Config;
use kube::{Api, Client};
use kube_leader_election::{LeaseLock, LeaseLockParams, LeaseLockResult};
use weebo_si_crd::WeeboSiConfig;

pub use reconcile::{Ctx, Error, error_policy, reconcile as reconcile_fn};

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
/// writes; the rest requeue without acting.
pub async fn run(client: Client, leader_election: Option<LeaderElection>) {
    let is_leader = Arc::new(AtomicBool::new(leader_election.is_none()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::clone(&is_leader),
    });

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
                () = run_leader_election(leadership, is_leader) => {},
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
async fn run_leader_election(leadership: LeaseLock, is_leader: Arc<AtomicBool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        match leadership.try_acquire_or_renew().await {
            Ok(lease) => {
                let acquired = matches!(lease, LeaseLockResult::Acquired(_));
                is_leader.store(acquired, Ordering::Relaxed);
            }
            Err(err) => {
                eprintln!("ERROR weebo-si-controller: leader election: {err}");
                is_leader.store(false, Ordering::Relaxed);
            }
        }
        interval.tick().await;
    }
}
