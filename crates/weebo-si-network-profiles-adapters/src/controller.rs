//! The `network-profiles` reconcile loops: one over `Namespace` (the baseline), one over
//! `DevWorkspace` (profile objects) — see RFC 0004's *Design → Architecture*, "the DevWorkspace
//! and Namespace reconcile loops."
//!
//! Thin adapters over `weebo_si_network_profiles::application::reconcile`, mirroring how
//! `weebo-si-webhook`'s router is a thin adapter over `weebo_si_chassis::admit` — every
//! mode-gating, resolution-chain and diff decision already lives in, and is tested in,
//! `weebo-si-network-profiles`. This module's own job is: watch, exclude two namespaces
//! structurally, build a `Subject`, call `reconcile`, requeue.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::DynamicObject;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;

use kube::runtime::events::Recorder;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId};
use weebo_si_controller::events::{self, ReasonCode, Regarding};
use weebo_si_controller::restricted::{AnnotationChanges, RestrictedReporter};
use weebo_si_crd::{FeatureMode, NamespaceName, OnNotGranted, ResolvedNetworkProfilesConfig};
use weebo_si_network_profiles::{
    CanaryProbe, NamespaceSubject, NetworkProfiles, PolicyStore, ReconcileObserver,
    ReconcileOutcome, Workspace, is_excluded_namespace,
};

pub use weebo_si_controller::workspace::{
    devworkspace_id, devworkspace_owner, devworkspace_resource, held_warnings, indexed,
    off_recheck, warn_held,
};

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
    /// The same `Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>` `feature` was constructed with.
    pub config: Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
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
    /// The change-only audit of restricted profile keys (RFC 0021).
    pub restricted: Arc<RestrictedReporter>,
}

struct Ctx {
    deps: NetworkProfilesDeps,
    recorder: Recorder,
    /// The live read of a namespace's grant annotation (RFC 0021 R-14).
    namespaces: Api<Namespace>,
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

fn error_policy<K: Regarding>(object: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    ctx.deps.observer.failed();
    events::retry(
        &ctx.recorder,
        object.as_ref(),
        ReasonCode::NetworkProfilesFailed,
        error,
    )
}

/// The `WARN ... result=unsupported` line RFC 0004's *Guide-level explanation* shows verbatim.
/// One line per profile, because an admin reading this needs to know *which* permission their
/// team believes it has and does not.
fn warn_unsupported(outcome: &ReconcileOutcome, backend: &str) {
    for profile in &outcome.unsupported {
        tracing::warn!(
            "feature=network-profiles profile={profile} \
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
    tracing::warn!(
        "feature=network-profiles team={team} workspace={workspace} \
         requested=[{}] result=not_granted",
        requested.join(",")
    );
}

/// The RFC 0021 audit of one pass: for each restricted key that entered the workspace's honoured
/// or refused set since its last pass, one count (in the reporter), one INFO line and one Event.
async fn report_restricted(
    ctx: &Ctx,
    obj: &DynamicObject,
    outcome: &ReconcileOutcome,
    mode: FeatureMode,
    grant_key: &str,
    on_not_granted: OnNotGranted,
) {
    let Some(uid) = obj.metadata.uid.as_deref() else {
        return;
    };
    let keys = |list: &[weebo_si_crd::ProfileKey]| {
        list.iter()
            .map(|key| key.as_str().to_string())
            .collect::<Vec<_>>()
    };
    let change = ctx.deps.restricted.observe(
        uid,
        keys(&outcome.restricted_honoured),
        keys(&outcome.restricted_refused),
    );
    let namespace = obj.metadata.namespace.as_deref().unwrap_or_default();
    let workspace = obj.name_any();
    for key in &change.honoured {
        tracing::info!(
            "feature=network-profiles restricted={key} namespace={namespace} \
             workspace={workspace} mode={mode:?} result=honoured"
        );
        events::restricted_grant(&ctx.recorder, obj, true, honoured_note(key, grant_key)).await;
    }
    for key in &change.refused {
        tracing::info!(
            "feature=network-profiles restricted={key} namespace={namespace} \
             workspace={workspace} mode={mode:?} result=refused reason=no_namespace_grant"
        );
        events::restricted_grant(
            &ctx.recorder,
            obj,
            false,
            refused_note(key, namespace, grant_key, on_not_granted, &outcome.resolved),
        )
        .await;
    }
}

/// The `RestrictedGrantHonoured` Event's note, in the RFC 0021 mock's words.
fn honoured_note(key: &str, grant_key: &str) -> String {
    format!("network profile {key} is restricted; granted by namespace annotation {grant_key}")
}

/// The `RestrictedGrantRefused` Event's note, in the RFC 0021 mock's words.
fn refused_note(
    key: &str,
    namespace: &str,
    grant_key: &str,
    on_not_granted: OnNotGranted,
    applied: &[weebo_si_crd::ProfileKey],
) -> String {
    let why = if grant_key.is_empty() {
        "restricted grants are disabled (namespaceGrant.annotation is empty)".to_string()
    } else {
        format!("namespace {namespace} does not grant it (annotation {grant_key})")
    };
    let applied: Vec<&str> = applied.iter().map(|key| key.as_str()).collect();
    // Under `Deny` the refused key may still come from the team default, which is then filtered
    // and applied rather than refused: name what was applied whenever something was.
    let then = match on_not_granted {
        OnNotGranted::Deny if applied.is_empty() => {
            "onNotGranted=Deny: no profile beyond the baseline applied".to_string()
        }
        _ => format!(
            "onNotGranted={on_not_granted:?} applied the team default [{}]",
            applied.join(",")
        ),
    };
    format!("network profile {key} is restricted and {why}; {then}")
}

/// Whether the loaded configuration itself says `mode: Off`, as opposed to the gate answering
/// `Off` for a namespace it cannot yet see or a singleton it has not yet read.
fn configured_off(ctx: &Ctx) -> bool {
    ctx.deps
        .config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|config| config.mode == FeatureMode::Off)
}

async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let name = NamespaceName::new(ns.name_any());
    // A namespace being deleted is being emptied by the namespace controller; writing its
    // objects back would be refused (the namespace is terminating) and retried every pass until
    // it is gone.
    if ns.metadata.deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    if is_excluded_namespace(&name, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    // Sampled before the gate, never after: see `off_recheck`.
    let was_indexed = indexed(ctx.deps.namespace_view.as_ref(), &name);
    let mode = ctx
        .deps
        .gate
        .mode(FeatureId::new("network-profiles"), &name);
    if mode == FeatureMode::Off {
        // `mode: Off` is a rollback: the baselines this feature wrote come away, or an admin who
        // reaches for `Off` mid-incident is left with deny-all objects and nothing repairing
        // them. Only when the configuration *says* `Off` — the gate also answers `Off` while the
        // namespace cache is cold or the singleton has not loaded, and neither is an instruction
        // to delete anything.
        if configured_off(&ctx) {
            let applied =
                weebo_si_network_profiles::teardown(&name, ctx.deps.policy_store.as_ref())
                    .await
                    .map_err(|err| Error(err.to_string()))?;
            if applied.deleted > 0 {
                tracing::info!(
                    "network-profiles namespace={name} mode=Off torn down deleted={}",
                    applied.deleted
                );
            }
        }
        // Re-checked rather than awaited: the gate answers from the namespace index and the
        // singleton, either of which can lag the event that got us here, and a namespace seen
        // `Off` once would otherwise never be looked at again when the feature reaches it.
        return Ok(Action::requeue(off_recheck(was_indexed)));
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
    warn_held("network-profiles", &outcome.held);
    tracing::info!(
        "network-profiles namespace={name} mode={mode:?} diffs={} applied={:?}",
        outcome.diffs.len(),
        outcome.applied
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

async fn reconcile_devworkspace(obj: Arc<DynamicObject>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // The reporter's memory is dropped when the workspace goes, and whenever no pass reports for
    // it (excluded, `Off`), so it reports afresh once the feature reaches it again. DWO puts a
    // finalizer on every DevWorkspace, so a deletion is always seen as a `deletionTimestamp`.
    let forget = || {
        if let Some(uid) = obj.metadata.uid.as_deref() {
            ctx.deps.restricted.forget(uid);
        }
    };
    if obj.metadata.deletion_timestamp.is_some() {
        forget();
    }
    let namespace = NamespaceName::new(obj.metadata.namespace.clone().unwrap_or_default());
    if is_excluded_namespace(&namespace, &ctx.deps.operator_namespace) {
        forget();
        return Ok(Action::await_change());
    }

    // Sampled before the gate, never after: see `off_recheck`.
    let was_indexed = indexed(ctx.deps.namespace_view.as_ref(), &namespace);
    let mode = ctx
        .deps
        .gate
        .mode(FeatureId::new("network-profiles"), &namespace);
    if mode == FeatureMode::Off {
        // Re-checked rather than awaited: the gate answers from the namespace index and the
        // singleton, either of which can lag the event that got us here, and a namespace seen
        // `Off` once would otherwise never be looked at again when the feature reaches it.
        forget();
        return Ok(Action::requeue(off_recheck(was_indexed)));
    }

    let Some(workspace_id) = devworkspace_id(&obj) else {
        // DevWorkspace Operator has not assigned the id yet — nothing to key a profile object
        // by. A short requeue rather than `await_change`: the object will change again shortly
        // once the id lands, but this reconcile pass has no watch event to wait for in the
        // meantime.
        return Ok(Action::requeue(Duration::from_secs(15)));
    };

    let (attribute_key, annotation_key, grant_key, on_not_granted, any_restricted) = {
        let guard = ctx
            .deps
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.as_ref() {
            Some(config) => (
                config.workspace_selection.attribute.clone(),
                config.namespace_selection.annotation.clone(),
                config.namespace_grant.annotation.clone(),
                config.on_not_granted,
                config
                    .catalog
                    .entries()
                    .iter()
                    .any(|entry| entry.restricted),
            ),
            // `mode` above already confirmed the feature is not Off, which the FeatureGate
            // cannot report without a config present — this is defensive, not a reachable path.
            None => return Ok(Action::await_change()),
        }
    };

    let attribute = attribute_of(&obj, &attribute_key);
    let namespace_annotation = ctx
        .deps
        .namespace_view
        .annotation(&namespace, &annotation_key);
    // The grant, live (R-14): the Namespace event that re-queued this pass may be ahead of the
    // namespace cache. Skipped while nothing is restricted — the grant could not change anything.
    // A failed GET fails the pass, which is retried: a grant is never read as absent because a
    // read failed.
    let namespace_grant = if any_restricted && !grant_key.is_empty() {
        ctx.namespaces
            .get_opt(namespace.as_str())
            .await
            .map_err(|err| Error(format!("could not read namespace {namespace}: {err}")))?
            .and_then(|ns| ns.metadata.annotations)
            .and_then(|mut annotations| annotations.remove(&grant_key))
    } else {
        None
    };

    let teams = ctx.deps.gate.teams();
    let facts = ctx
        .deps
        .namespace_view
        .facts(&namespace)
        .unwrap_or_default();
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let owner = devworkspace_owner(&obj).ok_or_else(|| {
        Error("DevWorkspace carries no name or uid to own its objects".to_string())
    })?;
    let subject = Workspace {
        name: obj.name_any(),
        namespace: namespace.clone(),
        workspace_id,
        attribute,
        namespace_annotation,
        namespace_grant,
        owner,
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
    if obj.metadata.deletion_timestamp.is_none() {
        report_restricted(&ctx, &obj, &outcome, mode, &grant_key, on_not_granted).await;
    }
    warn_held("network-profiles", &outcome.held);
    tracing::info!(
        "network-profiles workspace={}/{} mode={mode:?} diffs={} applied={:?}",
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

        if !settings.enabled {
            // Deliberately does *not* reset the gauge to `unknown` on a follower: the leader is
            // the one reporting, and a follower clearing the series would make the verdict flap
            // with whichever replica scraped last.
            tokio::time::sleep(interval).await;
            continue;
        }

        match weebo_si_network_profiles::run_canary(ctx.deps.canary.as_ref()).await {
            Ok(verdict) => {
                ctx.deps.observer.canary(verdict);
                tracing::info!("network-profiles canary result={}", verdict.label());
            }
            Err(err) => {
                // A probe that could not run is `Unknown`, never `enforcing` — the whole point of
                // this metric is that "we could not check" and "we checked and it is fine" are
                // different answers.
                ctx.deps
                    .observer
                    .canary(weebo_si_network_profiles::CanaryVerdict::Unknown);
                tracing::error!("network-profiles canary: {err}");
            }
        }
        // Always, including after an error: the probe is the only thing here that creates a
        // workload, and a failed run must not leave a pod or a deny policy behind.
        if let Err(err) = ctx.deps.canary.cleanup().await {
            tracing::error!("network-profiles canary cleanup: {err}");
        }

        tokio::time::sleep(interval).await;
    }
}

/// Start both loops. Runs until the input streams end, which in practice means "forever" —
/// `kube-runtime`'s watcher retries on its own, matching `run`'s own `WeeboSiConfig`
/// loop.
pub async fn spawn(client: Client, deps: NetworkProfilesDeps, recorder: Recorder) {
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let ctx = Arc::new(Ctx {
        deps,
        recorder,
        namespaces: ns_api.clone(),
    });

    let ns_ctx = Arc::clone(&ctx);
    tokio::spawn(
        Controller::new(ns_api, WatcherConfig::default())
            .run(
                |object, ctx| {
                    events::tracked(Arc::clone(&object), reconcile_namespace(object, ctx))
                },
                error_policy,
                ns_ctx,
            )
            .for_each(|_| futures_util::future::ready(())),
    );

    let resource = devworkspace_resource();
    let dw_api: Api<DynamicObject> = Api::all_with(client, &resource);
    let dw_ctx = Arc::clone(&ctx);
    let controller = Controller::new_with(dw_api, WatcherConfig::default(), resource.clone());
    // RFC 0021 R-12: a Namespace whose annotations change re-queues every DevWorkspace in it, so a
    // removed grant takes the restricted profile away in seconds, not at the 300 s requeue.
    let workspaces = controller.store();
    let changes = AnnotationChanges::default();
    let controller = controller.watches(
        ctx.namespaces.clone(),
        WatcherConfig::default(),
        move |ns: Namespace| {
            if !changes.changed(&ns) {
                return Vec::new();
            }
            let name = ns.name_any();
            workspaces
                .state()
                .iter()
                .filter(|dw| dw.metadata.namespace.as_deref() == Some(name.as_str()))
                .map(|dw| ObjectRef::from_obj_with(dw.as_ref(), resource.clone()))
                .collect::<Vec<_>>()
        },
    );
    tokio::spawn(
        controller
            .run(
                |object, ctx| {
                    events::tracked(Arc::clone(&object), reconcile_devworkspace(object, ctx))
                },
                error_policy,
                dw_ctx,
            )
            .for_each(|_| futures_util::future::ready(())),
    );

    tokio::spawn(managed_objects_loop(Arc::clone(&ctx)));
    tokio::spawn(canary_loop(ctx));
}

/// The DevWorkspace attribute, `None` when absent or when requests are off (`""`). A value that
/// is not a string (a YAML list, say) is an invalid key, never the team default.
fn attribute_of(object: &DynamicObject, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    object
        .data
        .pointer("/spec/template/attributes")
        .and_then(|attributes| attributes.get(key))
        .map(|value| {
            value.as_str().map_or_else(
                || weebo_si_network_profiles::INVALID_KEY.to_string(),
                str::to_string,
            )
        })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_chassis::managed::{ObjectKey, Owner};
    use weebo_si_crd::DEVWORKSPACE_ID_LABEL;

    use kube::api::ObjectMeta;

    use super::*;

    fn devworkspace(name: Option<&str>, uid: Option<&str>) -> DynamicObject {
        DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: name.map(str::to_string),
                namespace: Some("user-alice".to_string()),
                uid: uid.map(str::to_string),
                ..ObjectMeta::default()
            },
            data: serde_json::Value::Null,
        }
    }

    #[test]
    fn the_owner_names_the_resource_this_controller_watches() {
        // The garbage collector resolves an owner through the apiVersion written; it must be the
        // one the uid was read from.
        let resource = devworkspace_resource();
        assert_eq!(
            devworkspace_owner(&devworkspace(Some("data-pipeline"), Some("uid-1"))),
            Some(Owner {
                api_version: resource.api_version,
                kind: "DevWorkspace".to_string(),
                name: "data-pipeline".to_string(),
                uid: "uid-1".to_string(),
            })
        );
    }

    /// DWO keeps the id in `status.devworkspaceId`, not in a label on the DevWorkspace — reading
    /// only the label meant every workspace pass requeued forever on a real cluster.
    #[test]
    fn the_workspace_id_comes_from_status_and_falls_back_to_the_label() {
        let mut from_status = devworkspace(Some("ws"), Some("uid-1"));
        from_status.data = serde_json::json!({"status": {"devworkspaceId": "workspace0a1b2c"}});
        assert_eq!(
            devworkspace_id(&from_status).as_deref(),
            Some("workspace0a1b2c")
        );

        let mut from_label = devworkspace(Some("ws"), Some("uid-1"));
        from_label.metadata.labels = Some(
            [(DEVWORKSPACE_ID_LABEL.to_string(), "workspace9f".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(devworkspace_id(&from_label).as_deref(), Some("workspace9f"));

        let mut not_yet = devworkspace(Some("ws"), Some("uid-1"));
        not_yet.data = serde_json::json!({"status": {"devworkspaceId": ""}});
        assert_eq!(devworkspace_id(&not_yet), None);
    }

    #[test]
    fn a_non_string_attribute_is_an_invalid_key_not_an_absent_one() {
        let mut listed = devworkspace(Some("ws"), Some("uid-1"));
        listed.data = serde_json::json!({"spec": {"template": {"attributes": {"k": ["git"]}}}});
        assert_eq!(
            attribute_of(&listed, "k").as_deref(),
            Some(weebo_si_network_profiles::INVALID_KEY)
        );
        assert_eq!(attribute_of(&listed, "other"), None);
        assert_eq!(attribute_of(&listed, ""), None);
    }

    #[test]
    fn a_devworkspace_without_a_uid_has_no_owner_to_offer() {
        assert_eq!(devworkspace_owner(&devworkspace(Some("x"), None)), None);
        assert_eq!(devworkspace_owner(&devworkspace(None, Some("uid-1"))), None);
    }

    #[test]
    fn one_warning_per_held_object_naming_feature_and_object() {
        let held = [
            ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-base".to_string(),
            },
            ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-git-ws1".to_string(),
            },
        ];
        let lines = held_warnings("network-profiles", &held);
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0]
                .starts_with("feature=network-profiles object=user-alice/weebo-base result=held")
        );
        assert!(lines[1].contains("object=user-alice/weebo-git-ws1"));
        assert!(
            lines
                .iter()
                .all(|line| line.contains("template unresolved"))
        );
    }

    #[test]
    fn nothing_held_means_nothing_logged() {
        assert!(held_warnings("kubearmor-policy", &[]).is_empty());
    }

    #[test]
    fn the_event_notes_follow_the_rfc_mocks() {
        assert_eq!(
            refused_note(
                "internet",
                "dev-ws-batleforc-test",
                "hardening.weebo.io/network-grants",
                OnNotGranted::Default,
                &[
                    weebo_si_crd::ProfileKey::new("dev-registries"),
                    weebo_si_crd::ProfileKey::new("anthropic")
                ],
            ),
            "network profile internet is restricted and namespace dev-ws-batleforc-test does not \
             grant it (annotation hardening.weebo.io/network-grants); onNotGranted=Default \
             applied the team default [dev-registries,anthropic]"
        );
        assert_eq!(
            honoured_note("internet", "hardening.weebo.io/network-grants"),
            "network profile internet is restricted; granted by namespace annotation \
             hardening.weebo.io/network-grants"
        );
        assert_eq!(
            refused_note("internet", "ns", "", OnNotGranted::Deny, &[]),
            "network profile internet is restricted and restricted grants are disabled \
             (namespaceGrant.annotation is empty); onNotGranted=Deny: no profile beyond the \
             baseline applied"
        );
        // A restricted key in the team default is filtered, the rest applied, under Deny too.
        assert!(
            refused_note(
                "internet",
                "ns",
                "a",
                OnNotGranted::Deny,
                &[weebo_si_crd::ProfileKey::new("git")]
            )
            .ends_with("onNotGranted=Deny applied the team default [git]")
        );
    }
}
