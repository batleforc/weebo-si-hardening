//! The `resource-quotas` reconcile loop: one over `Namespace`, re-run for every namespace when the
//! configuration, a template or a managed object changes, plus a tick that checks the catalogue.
//!
//! Thin adapter over `weebo_si_resource_quotas::{reconcile, teardown}`.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use weebo_si_chassis::managed::Diff;
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId, NamespaceFacts};
use weebo_si_controller::events::{self, ReasonCode, Regarding};
use weebo_si_controller::workspace::{CONFIG_POLL, config_changes, indexed, off_recheck};
use weebo_si_crd::{FeatureMode, NamespaceName, ResolvedResourceQuotasConfig};
use weebo_si_network_profiles::is_excluded_namespace;
use weebo_si_resource_quotas::{
    ManagedQuotaStore, NamespaceSubject, ReconcileObserver, ReconcileOutcome, ResourceQuotasFeature,
};

/// This feature's identifier.
const FEATURE: &str = "resource-quotas";

/// A namespace's periodic requeue. Changes arrive sooner through [`spawn`]'s triggers.
const RESYNC: Duration = Duration::from_secs(300);

/// How often the catalogue is checked for `weebo_si_resource_quotas_profiles`.
const PROFILES_TICK: Duration = Duration::from_secs(30);

/// A fingerprint of whatever a trigger watches: when it changes, every namespace is reconciled.
pub type Fingerprint = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Everything the loop needs, built by [`crate::controller_deps`].
pub struct ResourceQuotasDeps {
    /// The feature.
    pub feature: Arc<ResourceQuotasFeature>,
    /// The handle `feature` reads.
    pub config: Arc<RwLock<Option<ResolvedResourceQuotasConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The namespace index, for `off_recheck`.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `Context`.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// The managed objects.
    pub store: Arc<dyn ManagedQuotaStore>,
    /// Where outcomes go.
    pub observer: Arc<dyn ReconcileObserver>,
    /// This operator's namespace, excluded structurally.
    pub operator_namespace: NamespaceName,
    /// The templates' and the managed objects' fingerprints: a template edit re-applies the
    /// profile everywhere it is used, and a managed object somebody edited is put back.
    pub fingerprints: Vec<Fingerprint>,
}

struct Ctx {
    deps: ResourceQuotasDeps,
    recorder: Recorder,
}

#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resource-quotas reconcile failed: {}", self.0)
    }
}

impl std::error::Error for Error {}

fn error_policy<K: Regarding>(object: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    ctx.deps.observer.failed();
    events::retry(
        &ctx.recorder,
        object.as_ref(),
        ReasonCode::ResourceQuotasFailed,
        error,
    )
}

fn configured_off(ctx: &Ctx) -> bool {
    ctx.deps
        .config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .is_some_and(|config| config.mode == FeatureMode::Off)
}

/// The log lines of RFC 0014's *Guide-level explanation*.
fn log(outcome: &ReconcileOutcome, mode: FeatureMode) {
    let team = outcome.team.as_ref().map_or("<none>", |team| team.as_str());
    let profile = outcome
        .profile
        .as_ref()
        .map_or("<none>", |profile| profile.as_str());
    let diff: Vec<String> = outcome
        .diffs
        .iter()
        .filter_map(|diff| match diff {
            Diff::Create(object) => Some(format!("create:{}", object.key.name)),
            Diff::Update(object) => Some(format!("update:{}", object.key.name)),
            Diff::Delete { key, .. } => Some(format!("delete:{}", key.name)),
            Diff::Unchanged(_) => None,
        })
        .collect();
    let results: Vec<&str> = outcome
        .results
        .iter()
        .map(|result| result.as_str())
        .collect();
    tracing::info!(
        "feature={FEATURE} mode={mode:?} ns={} team={team} profile={profile} result={} diff={}",
        outcome.namespace,
        results.join(","),
        if diff.is_empty() {
            "none".to_string()
        } else {
            diff.join(",")
        },
    );
    if let Some(requested) = &outcome.not_granted {
        tracing::warn!(
            "feature={FEATURE} ns={} team={team} requested={requested} result=not_granted",
            outcome.namespace
        );
    }
    for violation in &outcome.violations {
        tracing::warn!(
            "feature={FEATURE} ns={} profile={profile} result=invalid {violation} — profile not \
             applied, the namespace keeps what it has",
            outcome.namespace
        );
    }
    if outcome.foreign.limit_ranges > 0 {
        tracing::warn!(
            "feature={FEATURE} ns={} foreign_limitranges={}: two sets of container defaults apply",
            outcome.namespace,
            outcome.foreign.limit_ranges
        );
    }
}

async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let name = NamespaceName::new(ns.name_any());
    if ns.metadata.deletion_timestamp.is_some() {
        ctx.deps.observer.forget(&name);
        return Ok(Action::await_change());
    }
    if is_excluded_namespace(&name, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    let was_indexed = indexed(ctx.deps.namespace_view.as_ref(), &name);
    let mode = ctx.deps.gate.mode(FeatureId::new(FEATURE), &name);
    if mode == FeatureMode::Off {
        ctx.deps.observer.forget(&name);
        // Only when the configuration says `Off`: a cold cache is not an instruction to remove a
        // ceiling. A namespace leaving the selector keeps its objects, like every other feature
        // writing objects here; `mode: Off` is the cleanup.
        if configured_off(&ctx) {
            let applied = weebo_si_resource_quotas::teardown(&name, ctx.deps.store.as_ref())
                .await
                .map_err(|err| Error(err.to_string()))?;
            if applied.deleted > 0 {
                ctx.deps.observer.torn_down(&name, &applied);
                tracing::info!(
                    "feature={FEATURE} ns={name} mode=Off deleted={}",
                    applied.deleted
                );
            }
        }
        return Ok(Action::requeue(off_recheck(was_indexed)));
    }

    let annotation_key = ctx
        .deps
        .config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|config| config.namespace_selection.annotation.clone());
    let Some(annotation_key) = annotation_key else {
        return Ok(Action::await_change());
    };
    let annotation = (!annotation_key.is_empty())
        .then(|| ns.annotations().get(&annotation_key).cloned())
        .flatten();
    ctx.deps.observer.selection(&name, annotation.as_deref());

    let teams = ctx.deps.gate.teams();
    let facts = NamespaceFacts {
        labels: ns.labels().clone(),
        selection_annotation: None,
    };
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = NamespaceSubject {
        namespace: name,
        annotation,
    };
    let outcome = weebo_si_resource_quotas::reconcile(
        ctx.deps.feature.as_ref(),
        &subject,
        &context,
        mode,
        ctx.deps.store.as_ref(),
    )
    .await
    .map_err(|err| Error(err.to_string()))?;
    ctx.deps.observer.reconciled(&outcome);
    log(&outcome, mode);
    Ok(Action::requeue(RESYNC))
}

/// A stream that yields when `fingerprint` changes, polled like [`config_changes`].
fn fingerprint_changes(fingerprint: Fingerprint) -> impl futures_util::Stream<Item = ()> + Send {
    let first = fingerprint();
    futures_util::stream::unfold((first, fingerprint), |(mut last, fingerprint)| async move {
        loop {
            tokio::time::sleep(CONFIG_POLL).await;
            let now = fingerprint();
            if now != last {
                last = now;
                return Some(((), (last, fingerprint)));
            }
        }
    })
}

async fn profiles_loop(ctx: Arc<Ctx>) {
    let mut interval = tokio::time::interval(PROFILES_TICK);
    loop {
        interval.tick().await;
        // No configuration is not "zero valid profiles" worth reporting; the gauge keeps its zeros.
        if let Ok(checked) = ctx.deps.feature.check_catalog() {
            let invalid = checked
                .iter()
                .filter(|(_, violations)| !violations.is_empty())
                .count();
            ctx.deps.observer.profiles(checked.len() - invalid, invalid);
            for (key, violations) in &checked {
                for violation in violations {
                    tracing::warn!("feature={FEATURE} profile={key} result=invalid {violation}");
                }
            }
        }
    }
}

/// Start the loop and the catalogue tick.
pub async fn spawn(client: Client, deps: ResourceQuotasDeps, recorder: Recorder) {
    let mut triggers: Vec<futures_util::stream::BoxStream<'static, ()>> =
        vec![config_changes(Arc::clone(&deps.config)).boxed()];
    for fingerprint in &deps.fingerprints {
        triggers.push(fingerprint_changes(Arc::clone(fingerprint)).boxed());
    }
    let ctx = Arc::new(Ctx { deps, recorder });
    let api: Api<Namespace> = Api::all(client);
    tokio::spawn(
        Controller::new(api, WatcherConfig::default())
            .reconcile_all_on(futures_util::stream::select_all(triggers))
            .run(
                |object, ctx| {
                    events::tracked(Arc::clone(&object), reconcile_namespace(object, ctx))
                },
                error_policy,
                Arc::clone(&ctx),
            )
            .for_each(|_| futures_util::future::ready(())),
    );
    tokio::spawn(profiles_loop(ctx));
}
