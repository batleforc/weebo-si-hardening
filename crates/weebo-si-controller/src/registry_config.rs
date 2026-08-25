//! The `registry-config` reconcile loop: one over `Namespace`, plus the periodic tick that keeps
//! this brick's managed-object gauge current — see RFC 0007's *Design → Architecture*.
//!
//! **One loop, where `network-profiles` and `kubearmor-policy` each have two.** There is no
//! `DevWorkspace` loop because there is nothing per-workspace to write: DevWorkspace Operator's
//! automount is a property of the namespace. That absence is also why this brick has no race to
//! argue about — a namespace is reconciled when it appears, long before anyone opens a workspace
//! in it (RFC 0007's *The unit is the namespace, not the workspace*).
//!
//! Thin adapter over `weebo_si_registry_config::reconcile`, mirroring [`crate::network_profiles`]
//! and [`crate::kubearmor_policy`]: every mode-gating, resolution-chain and diff decision already
//! lives in, and is tested in, `weebo-si-registry-config`. This module's own job is: watch,
//! exclude two namespaces structurally, build a `Subject`, call `reconcile`, requeue.
//!
//! **The two namespaces excluded structurally are `network-profiles`'** —
//! [`weebo_si_network_profiles::is_excluded_namespace`], imported rather than restated. The
//! reason differs from the sibling bricks' (nothing here can sever an apiserver connection) but
//! the answer must not: this operator does not automount registry configuration into its own
//! namespace or Che's, neither of which is a workspace namespace, and two copies of a
//! compiled-in refusal free to disagree is how one of them ends up with objects nobody meant.

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId};
use weebo_si_crd::{FeatureMode, NamespaceName, RegistryCatalog, RegistryConfig};
use weebo_si_network_profiles::is_excluded_namespace;
use weebo_si_registry_config::{
    NamespaceSubject, ObjectStore, ReconcileObserver, ReconcileOutcome, RegistryConfigFeature,
};

/// This feature's identifier, as the gate and the log lines name it.
const FEATURE: &str = "registry-config";

/// What a caller must provide to keep `weebo_si_registry_managed_objects` labelled by ecosystem.
///
/// A closure rather than a `RegistryCatalog` value because the catalogue is hot-reloaded: capturing
/// one at boot would label every object with whichever ecosystem the catalogue said at startup.
type CatalogSnapshot = Arc<dyn Fn() -> RegistryCatalog + Send + Sync>;

/// Everything the loop needs, built by the composition root (`weebo-si-operator controller`) —
/// concrete adapters live in `weebo-si-runtime`, injected here as ports so this crate never names
/// one, per `docs/architecture/hexagonal.md`.
pub struct RegistryConfigDeps {
    /// The feature, sharing its config `Arc` with `config` below.
    pub feature: Arc<RegistryConfigFeature>,
    /// The same `Arc<RwLock<Option<RegistryConfig>>>` `feature` was constructed with. Read here
    /// for `namespaceSelection.annotation` alone.
    pub config: Arc<RwLock<Option<RegistryConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `Context`, unused by this feature's own decision logic.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// What exists now, and applying a diff against it.
    pub object_store: Arc<dyn ObjectStore + Send + Sync>,
    /// Where every pass's outcome is reported.
    pub observer: Arc<dyn ReconcileObserver>,
    /// This operator's own namespace — excluded structurally alongside Che's.
    pub operator_namespace: NamespaceName,
}

struct Ctx {
    deps: RegistryConfigDeps,
    catalog: CatalogSnapshot,
    is_leader: Arc<AtomicBool>,
}

/// Something that stopped a reconcile from completing. Never panics the loop — `kube-runtime`
/// calls the error policy and requeues.
#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "registry-config reconcile failed: {}", self.0)
    }
}
impl std::error::Error for Error {}

fn error_policy<K>(_obj: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: {FEATURE}: {error}");
    ctx.deps.observer.failed();
    Action::requeue(Duration::from_secs(30))
}

/// The `WARN ... result=not_granted` line — the namespace asked for something its team does not
/// have, and under `onNotGranted: Default` nothing else says so.
fn warn_not_granted(outcome: &ReconcileOutcome) {
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
        "WARN weebo-si-controller: feature={FEATURE} team={team} namespace={} \
         requested=[{}] result=not_granted",
        outcome.namespace,
        requested.join(",")
    );
}

/// The `WARN ... result=template_invalid` line, one per refused source.
///
/// **Names the template object and the reason, never its content** — RFC 0007's *Security
/// considerations*: "Logs and metrics carry the namespace, team, key, source kind and object
/// name — never a key of `data`, never a value, and never a content diff." The signature is the
/// enforcement: there is no parameter here a caller could pass a body through.
fn warn_refused(outcome: &ReconcileOutcome) {
    for refused in &outcome.refused {
        eprintln!(
            "WARN weebo-si-controller: feature={FEATURE} namespace={} key={} source={}/{} \
             result=template_invalid reason={}",
            outcome.namespace,
            refused.entry,
            refused.kind,
            refused.name,
            refused.reason()
        );
    }
}

async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(Duration::from_secs(15)));
    }

    let name = NamespaceName::new(ns.name_any());
    if is_excluded_namespace(&name, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    let mode = ctx.deps.gate.mode(FeatureId::new(FEATURE), &name);
    if mode == FeatureMode::Off {
        // A namespace this feature no longer reconciles must stop being counted, or the readiness
        // gauge reports a degradation for a namespace nobody is configuring any more.
        ctx.deps.observer.forget(&name);
        return Ok(Action::await_change());
    }

    let annotation_key = {
        let guard = ctx
            .deps
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(config) => config.namespace_selection.annotation.clone(),
            // `mode` above already confirmed the feature is not Off, which the FeatureGate cannot
            // report without a config present — defensive, not a reachable path.
            None => return Ok(Action::await_change()),
        }
    };
    let annotation = ctx.deps.namespace_view.annotation(&name, &annotation_key);

    let teams = ctx.deps.gate.teams();
    let facts = ctx.deps.namespace_view.facts(&name).unwrap_or_default();
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = NamespaceSubject {
        namespace: name.clone(),
        annotation,
    };

    let outcome = weebo_si_registry_config::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.object_store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;

    ctx.deps.observer.reconciled(&outcome);
    warn_not_granted(&outcome);
    warn_refused(&outcome);
    println!(
        "weebo-si-controller: {FEATURE} namespace={name} mode={mode:?} diffs={} applied={:?} \
         ready={}",
        outcome.diffs.len(),
        outcome.applied,
        outcome.ready,
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// How often the managed-object gauge is recomputed. A tick of its own rather than a line in each
/// reconcile pass: the snapshot walks every managed object in the cluster, and doing that per
/// namespace would make the cost quadratic in the fleet for a number that changes slowly.
const MANAGED_OBJECTS_TICK: Duration = Duration::from_secs(30);

/// Keep `weebo_si_registry_managed_objects` current from the object store's own watch caches.
async fn managed_objects_loop(ctx: Arc<Ctx>) {
    let mut interval = tokio::time::interval(MANAGED_OBJECTS_TICK);
    loop {
        interval.tick().await;
        if !ctx.is_leader.load(Ordering::Relaxed) {
            continue;
        }
        let objects = ctx.deps.object_store.managed_everywhere();
        let catalog = (ctx.catalog)();
        ctx.deps.observer.managed_objects(&objects, &catalog);
    }
}

/// Start the reconcile loop and the gauge tick. Runs until the input stream ends, which in
/// practice means "forever" — `kube-runtime`'s watcher retries on its own.
pub async fn spawn(client: Client, deps: RegistryConfigDeps, is_leader: Arc<AtomicBool>) {
    // The catalogue is read fresh at every tick through this closure rather than captured as a
    // value, so a catalogue edit relabels the gauge without a restart.
    let config = Arc::clone(&deps.config);
    let catalog: CatalogSnapshot = Arc::new(move || {
        config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|cfg| cfg.catalog.clone())
            .unwrap_or_default()
    });

    let ctx = Arc::new(Ctx {
        deps,
        catalog,
        is_leader,
    });

    let ns_api: Api<Namespace> = Api::all(client);
    let ns_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new(ns_api, WatcherConfig::default())
            .run(reconcile_namespace, error_policy, ns_ctx)
            .for_each(|_| futures_util::future::ready(())),
    );

    tokio::spawn(managed_objects_loop(ctx));
}
