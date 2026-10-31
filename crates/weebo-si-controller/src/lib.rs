//! The controller role's shared half (RFC 0012): the `WeeboSiConfig` status loop (RFC 0002), the
//! Event and retry policy every loop uses, the workspace helpers the template-driven features
//! share, and [`ControllerShared`] — what the composition root hands every feature's adapters
//! crate. The features' own loops live in their adapters crates.

pub mod events;
pub mod reconcile;
pub mod workspace;

use std::sync::Arc;

use futures_util::StreamExt;
use kube::runtime::Controller;
use kube::runtime::events::Recorder;
use kube::runtime::watcher::Config;
use kube::{Api, Client};
use weebo_si_crd::WeeboSiConfig;
use weebo_si_runtime::{KubeConfigStore, KubeDwocStore, KubeNsStore};

pub use reconcile::{Ctx, Error, error_policy, reconcile as reconcile_fn};

/// What every feature's reconcile loops may use, built once by the composition root
/// (`weebo-si-operator controller`) and handed to each adapters crate's `spawn_controllers`
/// (RFC 0012). Adding a feature adds one call, not a field.
pub struct ControllerShared {
    /// The client every loop reads and writes through.
    pub client: Client,
    /// The `WeeboSiConfig`/`WeeboSiTeam` cache: the feature gate and every feature's live config.
    pub config_store: Arc<KubeConfigStore>,
    /// Every namespace's labels and selection annotation.
    pub ns_store: Arc<KubeNsStore>,
    /// Every `DevWorkspaceOperatorConfig`, for the `dwoc-pin` catalogue check.
    pub dwoc_store: Arc<KubeDwocStore>,
    /// The registry `/metrics` serves; each feature registers its own series on it.
    pub prometheus: prometheus::Registry,
    /// The one Event recorder of the process (see [`events::recorder`]).
    pub recorder: Recorder,
    /// This pod's own namespace: where the templates live and what is never a target.
    pub operator_namespace: String,
    /// Whether the cluster serves, and this role may watch, `CiliumNetworkPolicy`.
    pub cilium_enabled: bool,
    /// Whether the cluster serves, and this role may watch, `KubeArmorPolicy`.
    pub kubearmor_enabled: bool,
    /// The image `network-profiles`' enforcement canary runs (`--canary-image`).
    pub canary_image: String,
}

/// Run the `WeeboSiConfig` status loop until the process is asked to stop. Every feature's own
/// loops are spawned before, by its adapters crate.
///
/// **Leader election is the caller's.** With more than one replica, the composition root takes
/// the lease first (`weebo-kit-runtime::leader::acquire_leadership`, RFC 0012) and starts any loop
/// only once it holds it; the kit exits the process the moment the lease may be lost, so no loop
/// ever runs on a replica that is not the leader.
pub async fn run(shared: &ControllerShared) {
    let ctx = Arc::new(Ctx {
        client: shared.client.clone(),
        recorder: shared.recorder.clone(),
    });
    let api: Api<WeeboSiConfig> = Api::all(shared.client.clone());
    Controller::new(api, Config::default())
        .shutdown_on_signal()
        .run(
            |object, ctx| events::tracked(Arc::clone(&object), reconcile_fn(object, ctx)),
            error_policy,
            ctx,
        )
        .for_each(|_| futures_util::future::ready(()))
        .await;
}
