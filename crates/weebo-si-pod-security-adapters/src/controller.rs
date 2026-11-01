//! The `pod-security` reconcile loop: one over `Namespace` — see RFC 0013's *Architecture*.
//!
//! Thin adapter over `weebo_si_pod_security::{reconcile, teardown}`: every resolution, ownership
//! and restore decision lives in, and is tested in, the domain crate. This module watches, skips
//! the structurally excluded namespaces, builds the subject from the `Namespace` object the watch
//! delivered, and calls the domain.
//!
//! **Everything is read from the delivered object**, not from the shared namespace index: the
//! six labels, the `-previous` annotation and the managed fields have to describe the same version
//! of the namespace, or ownership is decided against labels from another moment.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId, NamespaceFacts};
use weebo_si_controller::events::{self, ReasonCode, Regarding};
use weebo_si_controller::workspace::{indexed, off_recheck};
use weebo_si_crd::{FeatureMode, NamespaceName, ResolvedPodSecurityConfig};
use weebo_si_network_profiles::is_excluded_namespace;
use weebo_si_pod_security::{
    NamespaceLabelStore, NamespaceSubject, PodSecurityFeature, ReconcileObserver, ReconcileOutcome,
    ReconcileResult,
};

use crate::found::found;

/// This feature's identifier, as the gate and the log lines name it.
const FEATURE: &str = "pod-security";

/// How often a reconciled namespace is looked at again without an event: a team or a ceiling
/// change re-resolves every namespace through the singleton's own watch, so this only bounds how
/// long a missed event can last.
const RESYNC: Duration = Duration::from_secs(300);

/// Everything the loop needs, built by [`crate::controller_deps`].
pub struct PodSecurityDeps {
    /// The feature, sharing its config `Arc` with `config`.
    pub feature: Arc<PodSecurityFeature>,
    /// The same handle `feature` reads: for `mode` and `namespaceSelection.annotation`.
    pub config: Arc<RwLock<Option<ResolvedPodSecurityConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// Whether the namespace index holds a namespace — the sample `off_recheck` takes, and how a
    /// namespace leaving scope is told from a cache that is still cold.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `Context`, unused by this feature.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Writes to namespaces.
    pub store: Arc<dyn NamespaceLabelStore>,
    /// Where every pass's outcome is reported.
    pub observer: Arc<dyn ReconcileObserver>,
    /// This operator's own namespace, excluded structurally alongside Che's.
    pub operator_namespace: NamespaceName,
}

struct Ctx {
    deps: PodSecurityDeps,
    recorder: Recorder,
}

/// Something that stopped a pass. Never panics the loop — `kube-runtime` calls the error policy
/// and requeues.
#[derive(Debug)]
struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pod-security reconcile failed: {}", self.0)
    }
}

impl std::error::Error for Error {}

fn error_policy<K: Regarding>(object: Arc<K>, error: &Error, ctx: Arc<Ctx>) -> Action {
    ctx.deps.observer.failed();
    events::retry(
        &ctx.recorder,
        object.as_ref(),
        ReasonCode::PodSecurityFailed,
        error,
    )
}

/// Whether a namespace the gate answers `Off` for is really being left, as opposed to not being
/// known yet: the configuration is loaded, and either it says `mode: Off` or the namespace index
/// holds the namespace — so the gate saw its labels and the selector excluded it.
fn leaving(config: Option<&ResolvedPodSecurityConfig>, was_indexed: bool) -> bool {
    config.is_some_and(|config| config.mode == FeatureMode::Off || was_indexed)
}

/// The log line RFC 0013's *Guide-level explanation* shows, plus one `WARN` per pod the apiserver
/// said the level refuses.
fn log(outcome: &ReconcileOutcome, mode: FeatureMode) {
    let team = outcome.team.as_ref().map_or("<none>", |team| team.as_str());
    let results: Vec<&str> = outcome
        .results
        .iter()
        .map(|result| result.as_str())
        .collect();
    let diff: Vec<String> = outcome.changes.iter().map(ToString::to_string).collect();
    tracing::info!(
        "feature={FEATURE} mode={mode:?} ns={} team={team} level={} warn={} result={} diff={}",
        outcome.namespace,
        outcome.level,
        outcome.warn_level,
        results.join(","),
        if diff.is_empty() {
            "none".to_string()
        } else {
            diff.join(",")
        },
    );
    if outcome.results.contains(&ReconcileResult::Clamped)
        || outcome.results.contains(&ReconcileResult::LooserSynced)
        || outcome.results.contains(&ReconcileResult::PreviousLost)
    {
        tracing::warn!(
            "feature={FEATURE} ns={} team={team} result={} notes={:?}",
            outcome.namespace,
            results.join(","),
            outcome.notes,
        );
    }
    if outcome.drift {
        tracing::warn!(
            "feature={FEATURE} ns={} result=drift a Pod Security label was changed by another \
             field manager and is put back",
            outcome.namespace
        );
    }
    for warning in &outcome.warnings {
        tracing::warn!(
            "feature={FEATURE} ns={} level={} apiserver: {warning}",
            outcome.namespace,
            outcome.level
        );
    }
}

async fn reconcile_namespace(ns: Arc<Namespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let name = NamespaceName::new(ns.name_any());
    // A namespace being deleted is being emptied; a write would be refused and retried until it
    // is gone, and there is nothing left to protect.
    if ns.metadata.deletion_timestamp.is_some() {
        ctx.deps.observer.forget(&name);
        return Ok(Action::await_change());
    }
    if is_excluded_namespace(&name, &ctx.deps.operator_namespace) {
        return Ok(Action::await_change());
    }

    let found = found(&ns);
    // Sampled before the gate, never after: see `off_recheck`.
    let was_indexed = indexed(ctx.deps.namespace_view.as_ref(), &name);
    let mode = ctx.deps.gate.mode(FeatureId::new(FEATURE), &name);
    let (is_leaving, annotation_key) = {
        let guard = ctx
            .deps
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            leaving(guard.as_ref(), was_indexed),
            guard
                .as_ref()
                .map(|config| config.namespace_selection.annotation.clone()),
        )
    };

    if mode == FeatureMode::Off {
        ctx.deps.observer.forget(&name);
        // `mode: Off` and leaving scope both put the namespace back. A gate answering `Off`
        // because the singleton or the namespace index is not loaded yet is neither.
        if is_leaving
            && let Some(outcome) =
                weebo_si_pod_security::teardown(&name, &found, ctx.deps.store.as_ref())
                    .await
                    .map_err(|err| Error(err.to_string()))?
        {
            ctx.deps.observer.torn_down(&outcome);
            let results: Vec<&str> = outcome.results.iter().map(|r| r.as_str()).collect();
            tracing::info!(
                "feature={FEATURE} ns={name} result={} set={:?} removed={}",
                results.join(","),
                outcome.restore.set,
                outcome.restore.remove.len(),
            );
        }
        return Ok(Action::requeue(off_recheck(was_indexed)));
    }

    // `mode` is not Off, which the gate cannot answer without a configuration: defensive.
    let Some(annotation_key) = annotation_key else {
        return Ok(Action::await_change());
    };
    let annotation = (!annotation_key.is_empty())
        .then(|| {
            ns.metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(&annotation_key))
                .cloned()
        })
        .flatten();

    let teams = ctx.deps.gate.teams();
    let facts = NamespaceFacts {
        labels: ns.metadata.labels.clone().unwrap_or_default(),
        selection_annotation: None,
    };
    let context = Context::new(&teams, &facts, ctx.deps.dwoc_catalog.as_ref());
    let subject = NamespaceSubject {
        namespace: name,
        annotation,
        found,
    };

    let outcome = weebo_si_pod_security::reconcile(
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

/// Start the loop. Runs until the watch stream ends, which in practice means forever —
/// `kube-runtime`'s watcher retries on its own.
pub async fn spawn(client: Client, deps: PodSecurityDeps, recorder: Recorder) {
    let changes = weebo_si_controller::workspace::config_changes(Arc::clone(&deps.config));
    let ctx = Arc::new(Ctx { deps, recorder });
    let api: Api<Namespace> = Api::all(client);
    tokio::spawn(
        Controller::new(api, WatcherConfig::default())
            // A configuration change — `mode: Off`, a new ceiling, a team's level — reaches every
            // namespace now rather than at its next resync.
            .reconcile_all_on(changes)
            .run(
                |object, ctx| {
                    events::tracked(Arc::clone(&object), reconcile_namespace(object, ctx))
                },
                error_policy,
                ctx,
            )
            .for_each(|_| futures_util::future::ready(())),
    );
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::{
        PodSecurityBackend, PodSecurityConfig, PodSecurityLevel, PodSecurityNamespaceSelection,
        PodSecurityVersion, Resolved,
    };

    use super::*;

    fn config(mode: FeatureMode) -> ResolvedPodSecurityConfig {
        Resolved::without_teams(PodSecurityConfig {
            mode,
            namespace_selector: None,
            default: PodSecurityLevel::Restricted,
            ceiling: PodSecurityLevel::Baseline,
            version: PodSecurityVersion::new("latest"),
            backend: PodSecurityBackend::Labels,
            namespace_selection: PodSecurityNamespaceSelection::default(),
        })
    }

    #[test]
    fn an_unloaded_configuration_never_restores_anything() {
        assert!(!leaving(None, true));
        assert!(!leaving(None, false));
    }

    #[test]
    fn mode_off_restores_even_a_namespace_the_index_has_not_seen() {
        assert!(leaving(Some(&config(FeatureMode::Off)), false));
    }

    #[test]
    fn a_namespace_the_selector_excludes_is_left_once_the_index_knows_it() {
        let config = config(FeatureMode::Enforce);
        assert!(leaving(Some(&config), true));
        assert!(
            !leaving(Some(&config), false),
            "a cold index is not a namespace leaving scope"
        );
    }
}
