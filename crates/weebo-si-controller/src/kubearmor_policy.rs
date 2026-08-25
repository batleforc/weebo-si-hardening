//! The `kubearmor-policy` reconcile loops: one over `Namespace` (the baseline and the default
//! posture), one over `DevWorkspace` (profile objects), plus the two periodic ticks that keep
//! this brick's gauges current — see RFC 0006's *Design → Architecture*.
//!
//! Thin adapters over `weebo_si_kubearmor_policy::reconcile`, mirroring
//! [`crate::network_profiles`]: every mode-gating, resolution-chain and diff decision already
//! lives in, and is tested in, `weebo-si-kubearmor-policy`. This module's own job is: watch,
//! exclude two namespaces structurally, build a `Subject`, call `reconcile`, write the posture,
//! requeue.
//!
//! **The two namespaces excluded structurally are `network-profiles`'** —
//! [`weebo_si_network_profiles::is_excluded_namespace`], imported rather than restated. A
//! `KubeArmorPolicy` blocking process execution in the operator's own namespace is the same
//! class of self-inflicted outage a deny-all `NetworkPolicy` there is, and two copies of a
//! compiled-in refusal free to disagree is a wedged namespace.

use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Client, ResourceExt};
use serde_json::{Value, json};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, DomainError, FeatureId};
use weebo_si_crd::{
    DEVWORKSPACE_ID_LABEL, DefaultPosture, FeatureMode, KubeArmorPolicyConfig, NamespaceName,
};
use weebo_si_kubearmor_policy::{
    EnforcementSubjects, KubeArmorPolicy, NamespaceSubject, NodeEnforcerView, PolicyStore,
    ReconcileObserver, ReconcileOutcome, Workspace,
};
use weebo_si_network_profiles::is_excluded_namespace;

use crate::network_profiles::devworkspace_resource;

/// This feature's identifier, as the gate and the log lines name it.
const FEATURE: &str = "kubearmor-policy";

/// Everything the loops need, built by the composition root (`weebo-si-operator controller`) —
/// concrete adapters live in `weebo-si-runtime`, injected here as ports so this crate never names
/// one, per `docs/architecture/hexagonal.md`.
pub struct KubeArmorPolicyDeps {
    /// The feature, sharing its config `Arc` with `config` below.
    pub feature: Arc<KubeArmorPolicy>,
    /// The same `Arc<RwLock<Option<KubeArmorPolicyConfig>>>` `feature` was constructed with.
    pub config: Arc<RwLock<Option<KubeArmorPolicyConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `Context`, unused by this feature's own decision logic.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// What exists now, and applying a diff against it.
    pub policy_store: Arc<dyn PolicyStore + Send + Sync>,
    /// The pod/node join behind `weebo_si_kubearmor_enforced`.
    pub node_enforcer: Arc<dyn NodeEnforcerView + Send + Sync>,
    /// Every `{namespace, workspace_id}` the enforcement tick should ask about — the same
    /// adapter as `node_enforcer` in practice, taken as its own handle so this loop never needs
    /// to list pods itself.
    pub enforcement_subjects: Arc<dyn EnforcementSubjects + Send + Sync>,
    /// Where every pass's outcome and every gauge refresh is reported.
    pub observer: Arc<dyn ReconcileObserver>,
    /// This operator's own namespace — excluded structurally alongside Che's.
    pub operator_namespace: NamespaceName,
}

struct Ctx {
    deps: KubeArmorPolicyDeps,
    is_leader: Arc<AtomicBool>,
    client: Client,
}

/// Something that stopped a reconcile from completing. Never panics the loop — `kube-runtime`
/// calls the error policy and requeues.
#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kubearmor-policy reconcile failed: {}", self.0)
    }
}
impl std::error::Error for Error {}

fn error_policy<K>(_obj: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: {FEATURE}: {error}");
    ctx.deps.observer.failed();
    Action::requeue(Duration::from_secs(30))
}

/// The `WARN ... result=not_granted` line — the workspace asked for something its team does not
/// have, and under `onNotGranted: Default` nothing else says so.
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
        "WARN weebo-si-controller: feature={FEATURE} team={team} workspace={workspace} \
         requested=[{}] result=not_granted",
        requested.join(",")
    );
}

/// The merge patch that carries KubeArmor's three posture annotations, and nothing else.
///
/// Split out from [`write_posture`] so the document this controller sends can be asserted
/// without an apiserver: "nothing else" is the whole security property here, and a patch that
/// grew a fourth key — or reached outside `metadata.annotations` — would be a controller
/// quietly editing namespaces it does not own.
pub fn posture_patch(posture: DefaultPosture) -> Value {
    let annotations: serde_json::Map<String, Value> = posture
        .annotations()
        .into_iter()
        .map(|(key, value)| (key.to_string(), json!(value)))
        .collect();
    json!({"metadata": {"annotations": annotations}})
}

/// Write KubeArmor's three posture annotations onto `namespace`.
///
/// A strategic-merge patch of `metadata.annotations` alone, not a server-side apply of the whole
/// object: the namespace is not this operator's to own, only these three keys are, and an apply
/// would make this controller a co-owner of a `Namespace` that Che or a cluster admin created.
/// The same reasoning `dwoc-pin` uses for patching rather than owning a
/// `DevWorkspaceOperatorConfig`.
///
/// `pub` for the envtest suite, which drives exactly the call the namespace loop makes below —
/// the alternative is a posture mechanism whose only proof is that it compiles.
pub async fn write_posture(
    client: &Client,
    namespace: &NamespaceName,
    posture: DefaultPosture,
) -> Result<(), DomainError> {
    let api: Api<Namespace> = Api::all(client.clone());
    api.patch(
        namespace.as_str(),
        &PatchParams::default(),
        &Patch::Merge(posture_patch(posture)),
    )
    .await
    .map_err(|err| DomainError::PortFailed(err.to_string()))?;
    Ok(())
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
        return Ok(Action::await_change());
    }

    let teams = ctx.deps.gate.teams();
    let facts = ctx.deps.namespace_view.facts(&name).unwrap_or_default();
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = NamespaceSubject {
        namespace: name.clone(),
    };

    let outcome = weebo_si_kubearmor_policy::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.policy_store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;

    ctx.deps.observer.reconciled(&outcome);

    // `posture_to_write` is `None` in `DryRun` — the domain owns that rule, so this call site
    // cannot get it wrong by reading `mode` a second time.
    if let Some(posture) = outcome.posture_to_write() {
        write_posture(&ctx.client, &name, posture)
            .await
            .map_err(|err| Error(err.to_string()))?;
    }

    println!(
        "weebo-si-controller: {FEATURE} namespace={name} mode={mode:?} diffs={} applied={:?} \
         posture={}",
        outcome.diffs.len(),
        outcome.applied,
        outcome
            .posture
            .map(|p| format!(
                "file={},network={},capabilities={}",
                p.file, p.network, p.capabilities
            ))
            .unwrap_or_else(|| "<none>".to_string()),
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

    let mode = ctx.deps.gate.mode(FeatureId::new(FEATURE), &namespace);
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
        // by, and nothing to select on either.
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
            // cannot report without a config present — defensive, not a reachable path.
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

    let outcome = weebo_si_kubearmor_policy::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.policy_store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;

    ctx.deps.observer.reconciled(&outcome);
    warn_not_granted(&outcome, &subject.name);
    println!(
        "weebo-si-controller: {FEATURE} workspace={}/{} mode={mode:?} diffs={} applied={:?}",
        subject.namespace,
        subject.name,
        outcome.diffs.len(),
        outcome.applied
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// How often the managed-object gauge is recomputed. A tick of its own rather than a line in each
/// reconcile pass: the snapshot walks every managed object in the cluster, and doing that per
/// namespace would make the cost quadratic in the fleet for a number that changes slowly.
const MANAGED_OBJECTS_TICK: Duration = Duration::from_secs(30);

/// How often the enforcement gauge is refreshed. Slower than the object gauge on purpose: it
/// answers a question about *nodes*, which change when a node reboots into a kernel with a
/// different LSM available — not something worth asking every thirty seconds.
const ENFORCEMENT_TICK: Duration = Duration::from_secs(60);

/// Keep `weebo_si_kubearmor_managed_objects` current from the policy store's own watch cache.
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

/// Keep `weebo_si_kubearmor_enforced` current: ask the join about every workspace with a running
/// pod, publish the counts, and name each unenforced workspace in a log line.
///
/// The log line is where the per-workspace answer lives, deliberately — RFC 0004's observability
/// rule forbids a namespace or workspace id as a metric label, so "which workspace is
/// unenforced" is answered here and by `kubectl`, not by a time series.
async fn enforcement_loop(ctx: Arc<Ctx>) {
    let mut interval = tokio::time::interval(ENFORCEMENT_TICK);
    loop {
        interval.tick().await;
        if !ctx.is_leader.load(Ordering::Relaxed) {
            // Deliberately does not clear the gauge on a follower: the leader is the one
            // reporting, and a follower zeroing the series would make it flap with whichever
            // replica scraped last.
            continue;
        }

        // A node relabelled by KubeArmor's operator (an LSM that became available after a
        // reboot, or one that stopped being) is only picked up if the memoised answers go first.
        ctx.deps.enforcement_subjects.invalidate();

        let subjects = ctx.deps.enforcement_subjects.workspaces();
        let mut states = Vec::with_capacity(subjects.len());
        for (namespace, workspace_id) in subjects {
            let state = weebo_si_kubearmor_policy::observe_enforcement(
                ctx.deps.node_enforcer.as_ref(),
                &namespace,
                &workspace_id,
            );
            if state == weebo_si_kubearmor_policy::Enforcement::NotEnforced {
                eprintln!(
                    "WARN weebo-si-controller: feature={FEATURE} namespace={namespace} \
                     workspace_id={workspace_id} result=not_enforced — policy objects exist and \
                     the node hosting this workspace reports no usable LSM"
                );
            }
            states.push(state);
        }
        ctx.deps.observer.enforcement_snapshot(&states);
    }
}

/// Start both reconcile loops and both gauge ticks. Runs until the input streams end, which in
/// practice means "forever" — `kube-runtime`'s watcher retries on its own.
pub async fn spawn(client: Client, deps: KubeArmorPolicyDeps, is_leader: Arc<AtomicBool>) {
    let ctx = Arc::new(Ctx {
        deps,
        is_leader,
        client: client.clone(),
    });

    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ns_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new(ns_api, WatcherConfig::default())
            .run(reconcile_namespace, error_policy, ns_ctx)
            .for_each(|_| futures_util::future::ready(())),
    );

    let resource: ApiResource = devworkspace_resource();
    let dw_api: Api<DynamicObject> = Api::all_with(client, &resource);
    let dw_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new_with(dw_api, WatcherConfig::default(), resource)
            .run(reconcile_devworkspace, error_policy, dw_ctx)
            .for_each(|_| futures_util::future::ready(())),
    );

    tokio::spawn(managed_objects_loop(Arc::clone(&ctx)));
    tokio::spawn(enforcement_loop(ctx));
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::Posture;

    use super::*;

    #[test]
    fn the_posture_patch_carries_exactly_kubearmors_three_annotations() {
        let patch = posture_patch(DefaultPosture {
            file: Posture::Block,
            network: Posture::Audit,
            capabilities: Posture::Block,
        });
        assert_eq!(
            patch,
            json!({"metadata": {"annotations": {
                "kubearmor-file-posture": "block",
                "kubearmor-network-posture": "audit",
                "kubearmor-capabilities-posture": "block",
            }}})
        );
    }

    #[test]
    fn the_posture_patch_touches_nothing_outside_metadata_annotations() {
        // The security property: this controller edits three keys of a namespace it does not
        // own. A patch that reached `spec`, `labels`, or a fourth annotation would be a
        // different, much larger claim on the object.
        let patch = posture_patch(DefaultPosture::default());
        let metadata = patch
            .get("metadata")
            .expect("metadata should be the only top-level key");
        assert_eq!(
            patch.as_object().map(serde_json::Map::len),
            Some(1),
            "only metadata: {patch}"
        );
        assert_eq!(
            metadata.as_object().map(serde_json::Map::len),
            Some(1),
            "only annotations under metadata: {metadata}"
        );
        assert_eq!(
            metadata
                .get("annotations")
                .and_then(Value::as_object)
                .map(serde_json::Map::len),
            Some(3)
        );
    }

    #[test]
    fn every_annotation_key_is_kubearmors_own() {
        let patch = posture_patch(DefaultPosture::default());
        let annotations = patch
            .pointer("/metadata/annotations")
            .and_then(Value::as_object)
            .expect("annotations should be an object");
        assert!(
            annotations.keys().all(|key| key.starts_with("kubearmor-")),
            "this controller writes KubeArmor's keys, never its own: {annotations:?}"
        );
    }
}
