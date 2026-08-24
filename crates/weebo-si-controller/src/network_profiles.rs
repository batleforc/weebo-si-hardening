//! The `network-profiles` reconcile loops: one over `Namespace` (the baseline), one over
//! `DevWorkspace` (profile objects) — see RFC 0004's *Design → Architecture*, "the DevWorkspace
//! and Namespace reconcile loops."
//!
//! Thin adapters over `weebo_si_network_profiles::application::reconcile`, mirroring how
//! `weebo-si-webhook`'s router is a thin adapter over `weebo_si_chassis::admit` — every
//! mode-gating, resolution-chain and diff decision already lives in, and is tested in,
//! `weebo-si-network-profiles`. This module's own job is: watch, exclude two namespaces
//! structurally, build a `Subject`, call `reconcile`, requeue.

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId};
use weebo_si_crd::{DEVWORKSPACE_ID_LABEL, FeatureMode, NamespaceName, NetworkProfilesConfig};
use weebo_si_network_profiles::{
    CanaryProbe, NamespaceSubject, NetworkProfiles, PolicyStore, ReconcileObserver,
    ReconcileOutcome, Workspace, is_excluded_namespace,
};

/// The `DevWorkspace` GVK, matching this repo's own convention (see
/// `charts/weebo-si-operator/templates/mutatingwebhookconfiguration.yaml`) rather than upstream
/// DevWorkspace Operator's actual group — consistent with every other reference to this resource
/// in this codebase.
pub fn devworkspace_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk("controller.devfile.io", "v1alpha1", "DevWorkspace");
    ApiResource::from_gvk_with_plural(&gvk, "devworkspaces")
}

/// How often the enforcement canary's verdict is refreshed when `enforcement.canary.enabled` is
/// set but `intervalSeconds` is not usable (zero). The CRD's own default is 300s; this only
/// guards against a configuration that would otherwise spin.
const MIN_CANARY_INTERVAL: u64 = 60;

/// Everything the two loops need, built by the composition root (`weebo-si-operator
/// controller`) — concrete adapters live in `weebo-si-runtime`, injected here as ports so this
/// crate never names one, per `docs/architecture/hexagonal.md`.
pub struct NetworkProfilesDeps {
    /// The feature, sharing its config `Arc` with `config` below (one hot-reload source, two
    /// consumers: `desired()` reads it through `feature`, this module reads the two selection
    /// keys through `config` directly).
    pub feature: Arc<NetworkProfiles>,
    /// The same `Arc<RwLock<Option<NetworkProfilesConfig>>>` `feature` was constructed with.
    pub config: Arc<RwLock<Option<NetworkProfilesConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Whether a resolved DWOC reference exists — required structurally by `Context`, unused by
    /// `network-profiles`' own decision logic.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// What exists now, and applying a diff against it.
    pub policy_store: Arc<dyn PolicyStore + Send + Sync>,
    /// Where every pass's outcome, and the canary's verdict, is reported — RFC 0004's
    /// *Observability contract*.
    pub observer: Arc<dyn ReconcileObserver>,
    /// The enforcement probe. Held unconditionally and gated by
    /// `enforcement.canary.enabled` at each tick, so turning the canary on is a `WeeboSiConfig`
    /// edit rather than a restart.
    pub canary: Arc<dyn CanaryProbe>,
    /// This operator's own namespace — excluded structurally alongside Che's.
    pub operator_namespace: NamespaceName,
}

struct Ctx {
    deps: NetworkProfilesDeps,
    is_leader: Arc<AtomicBool>,
}

/// Something that stopped a reconcile from completing. Never panics the loop —
/// `kube-runtime` calls the error policy and requeues.
#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network-profiles reconcile failed: {}", self.0)
    }
}
impl std::error::Error for Error {}

fn error_policy<K>(_obj: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: network-profiles: {error}");
    ctx.deps.observer.failed();
    Action::requeue(Duration::from_secs(30))
}

/// The `WARN ... result=unsupported` line RFC 0004's *Guide-level explanation* shows verbatim.
/// One line per profile, because an admin reading this needs to know *which* permission their
/// team believes it has and does not.
fn warn_unsupported(outcome: &ReconcileOutcome, backend: &str) {
    for profile in &outcome.unsupported {
        eprintln!(
            "WARN weebo-si-controller: feature=network-profiles profile={profile} \
             backend={backend} result=unsupported — no variant for the resolved backend, \
             profile not applied"
        );
    }
}

/// The `WARN ... result=not_granted` line, likewise — the workspace asked for something its team
/// does not have, and under `onNotGranted: Default` nothing else says so.
fn warn_not_granted(outcome: &ReconcileOutcome, workspace: &str) {
    if outcome.not_granted.is_empty() {
        return;
    }
    let requested: Vec<&str> = outcome.not_granted.iter().map(|key| key.as_str()).collect();
    let team = outcome
        .team
        .as_ref()
        .map(|team| team.as_str())
        .unwrap_or("<none>");
    eprintln!(
        "WARN weebo-si-controller: feature=network-profiles team={team} workspace={workspace} \
         requested=[{}] result=not_granted",
        requested.join(",")
    );
}

async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let name = NamespaceName::new(ns.name_any());
    if is_excluded_namespace(&name, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    let mode = ctx
        .deps
        .gate
        .mode(FeatureId::new("network-profiles"), &name);
    if mode == FeatureMode::Off {
        return Ok(Action::await_change());
    }

    let teams = ctx.deps.gate.teams();
    let facts = ctx.deps.namespace_view.facts(&name).unwrap_or_default();
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = NamespaceSubject {
        namespace: name.clone(),
    };

    let outcome = weebo_si_network_profiles::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.policy_store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;

    ctx.deps.observer.reconciled(&outcome);
    warn_unsupported(&outcome, &format!("{:?}", ctx.deps.feature.backend()));
    println!(
        "weebo-si-controller: network-profiles namespace={name} mode={mode:?} diffs={} applied={:?}",
        outcome.diffs.len(),
        outcome.applied
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn reconcile_devworkspace(obj: Arc<DynamicObject>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let namespace = NamespaceName::new(obj.metadata.namespace.clone().unwrap_or_default());
    if is_excluded_namespace(&namespace, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    let mode = ctx
        .deps
        .gate
        .mode(FeatureId::new("network-profiles"), &namespace);
    if mode == FeatureMode::Off {
        return Ok(Action::await_change());
    }

    let Some(workspace_id) = obj
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
        .cloned()
    else {
        // DevWorkspace Operator has not assigned the id yet — nothing to key a profile object
        // by. A short requeue rather than `await_change`: the object will change again shortly
        // once the id lands, but this reconcile pass has no watch event to wait for in the
        // meantime.
        return Ok(Action::requeue(Duration::from_secs(15)));
    };

    let (attribute_key, annotation_key) = {
        let guard = ctx
            .deps
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(config) => (
                config.workspace_selection.attribute.clone(),
                config.namespace_selection.annotation.clone(),
            ),
            // `mode` above already confirmed the feature is not Off, which the FeatureGate
            // cannot report without a config present — this is defensive, not a reachable path.
            None => return Ok(Action::await_change()),
        }
    };

    let attribute = if attribute_key.is_empty() {
        None
    } else {
        obj.data
            .pointer("/spec/template/attributes")
            .and_then(|attributes| attributes.get(&attribute_key))
            .and_then(|value| value.as_str())
            .map(str::to_string)
    };
    let namespace_annotation = ctx
        .deps
        .namespace_view
        .annotation(&namespace, &annotation_key);

    let teams = ctx.deps.gate.teams();
    let facts = ctx
        .deps
        .namespace_view
        .facts(&namespace)
        .unwrap_or_default();
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = Workspace {
        name: obj.name_any(),
        namespace: namespace.clone(),
        workspace_id,
        attribute,
        namespace_annotation,
    };

    let outcome = weebo_si_network_profiles::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.policy_store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;

    ctx.deps.observer.reconciled(&outcome);
    warn_unsupported(&outcome, &format!("{:?}", ctx.deps.feature.backend()));
    warn_not_granted(&outcome, &subject.name);
    println!(
        "weebo-si-controller: network-profiles workspace={}/{} mode={mode:?} diffs={} applied={:?}",
        subject.namespace,
        subject.name,
        outcome.diffs.len(),
        outcome.applied
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// How often the managed-object gauge is recomputed. A tick of its own rather than a line in
/// each reconcile pass: the snapshot walks every managed object in the cluster, and doing that
/// per namespace would make the cost quadratic in the fleet for a number that changes slowly.
const MANAGED_OBJECTS_TICK: Duration = Duration::from_secs(30);

/// Keep `weebo_si_network_managed_objects` current from the policy store's own watch cache.
async fn managed_objects_loop(ctx: Arc<Ctx>) {
    let mut interval = tokio::time::interval(MANAGED_OBJECTS_TICK);
    loop {
        interval.tick().await;
        if !ctx.is_leader.load(Ordering::Relaxed) {
            continue;
        }
        let objects = ctx.deps.policy_store.managed_everywhere();
        ctx.deps.observer.managed_objects(&objects);
    }
}

/// The enforcement canary, on the interval `enforcement.canary` asks for.
///
/// Leader-gated like every other write in this role — the probe creates pods, and two replicas
/// racing to create the same two pod names would have one of them permanently reporting
/// `Unknown`. Re-reads its configuration every tick rather than capturing it at boot, so
/// `enabled` and `intervalSeconds` are `WeeboSiConfig` edits like everything else.
async fn canary_loop(ctx: Arc<Ctx>) {
    loop {
        let canary = {
            let guard = ctx
                .deps
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.as_ref().map(|config| config.enforcement.canary)
        };

        let Some(settings) = canary else {
            tokio::time::sleep(Duration::from_secs(MIN_CANARY_INTERVAL)).await;
            continue;
        };
        let interval =
            Duration::from_secs(u64::from(settings.interval_seconds).max(MIN_CANARY_INTERVAL));

        if !settings.enabled || !ctx.is_leader.load(Ordering::Relaxed) {
            // Deliberately does *not* reset the gauge to `unknown` on a follower: the leader is
            // the one reporting, and a follower clearing the series would make the verdict flap
            // with whichever replica scraped last.
            tokio::time::sleep(interval).await;
            continue;
        }

        match weebo_si_network_profiles::run_canary(ctx.deps.canary.as_ref()).await {
            Ok(verdict) => {
                ctx.deps.observer.canary(verdict);
                println!(
                    "weebo-si-controller: network-profiles canary result={}",
                    verdict.label()
                );
            }
            Err(err) => {
                // A probe that could not run is `Unknown`, never `enforcing` — the whole point of
                // this metric is that "we could not check" and "we checked and it is fine" are
                // different answers.
                ctx.deps
                    .observer
                    .canary(weebo_si_network_profiles::CanaryVerdict::Unknown);
                eprintln!("ERROR weebo-si-controller: network-profiles canary: {err}");
            }
        }
        // Always, including after an error: the probe is the only thing here that creates a
        // workload, and a failed run must not leave a pod or a deny policy behind.
        if let Err(err) = ctx.deps.canary.cleanup().await {
            eprintln!("ERROR weebo-si-controller: network-profiles canary cleanup: {err}");
        }

        tokio::time::sleep(interval).await;
    }
}

/// Start both loops. Runs until the input streams end, which in practice means "forever" —
/// `kube-runtime`'s watcher retries on its own, matching [`crate::run`]'s own `WeeboSiConfig`
/// loop.
pub async fn spawn(client: Client, deps: NetworkProfilesDeps, is_leader: Arc<AtomicBool>) {
    let ctx = Arc::new(Ctx { deps, is_leader });

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new(ns_api, WatcherConfig::default())
            .run(reconcile_namespace, error_policy, ns_ctx)
            .for_each(|_| futures_util::future::ready(())),
    );

    let resource = devworkspace_resource();
    let dw_api: Api<DynamicObject> = Api::all_with(client, &resource);
    let dw_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new_with(dw_api, WatcherConfig::default(), resource)
            .run(reconcile_devworkspace, error_policy, dw_ctx)
            .for_each(|_| futures_util::future::ready(())),
    );

    tokio::spawn(managed_objects_loop(Arc::clone(&ctx)));
    tokio::spawn(canary_loop(ctx));
}
