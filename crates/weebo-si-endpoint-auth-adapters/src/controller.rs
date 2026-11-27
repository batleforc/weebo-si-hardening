//! The `endpoint-auth` reconcile loop — RFC 0009's *Operator-side: mutate, reconcile, guard*,
//! second bullet.
//!
//! The mutating webhook gates every routing object written **from now on**; this loop is what
//! covers the ones that already existed when the feature was switched on, and what puts the
//! annotations back if anything strips them between DevWorkspace Operator's write and the
//! webhook's. It also owns the one shared Traefik `Middleware` the annotations point at: an
//! `Ingress` referencing a middleware that does not exist is an `Ingress` Traefik refuses to
//! route, so the object has to exist before the first annotation names it.
//!
//! **`mode: Off` is a rollback, not a pause.** The sweep then strips exactly the keys the dialect
//! owns — never the developer's `access`/`allow-users`/`allow-groups`/`rules`, which are theirs
//! and which a re-enable should find where they left them.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Patch, PatchParams};
use kube::core::{DynamicObject, GroupVersionKind, ObjectMeta, TypeMeta};
use kube::discovery::ApiResource;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;

use kube::runtime::events::Recorder;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use serde_json::{Value, json};
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_controller::events::{self, ReasonCode};
use weebo_si_controller::restricted::{AnnotationChanges, RestrictedReporter};
use weebo_si_crd::{
    AttachmentMode, COMPANION_SERVICE, Dialect, FeatureMode, MIDDLEWARE_NAME, NamespaceName,
    ResolvedEndpointAuthConfig,
};
use weebo_si_endpoint_auth::compile::{CompileError, UnknownKey};
use weebo_si_endpoint_auth::policy::{EndpointPolicy, RestrictedResult};
use weebo_si_network_profiles::is_excluded_namespace;

use crate::endpoint_auth::{NamespaceInputs, compile_annotations, gateway_overrides};

/// The largest auth response body Traefik will read from the gate, in bytes — two orders of
/// magnitude above what the gate sends.
const TRAEFIK_MAX_AUTH_BODY: u64 = 65_536;

/// This feature's identifier, as the gate and the log lines name it.
const FEATURE: &str = "endpoint-auth";

/// How often the sweep re-examines an object it already agreed with — long, because every
/// interesting change arrives as a watch event and this is only the backstop for the ones that
/// do not (a `WeeboSiConfig` edit that changes the dialect, a controller restart).
const REQUEUE: Duration = Duration::from_secs(300);

/// How often the shared `Middleware` is re-applied.
const MIDDLEWARE_TICK: Duration = Duration::from_secs(30);

/// The `Route` sweep runs once per this many [`MIDDLEWARE_TICK`]s — the old five-minute cadence.
const ROUTE_SWEEP_EVERY: u64 = 10;

/// Everything the loop needs, built by the composition root.
pub struct EndpointAuthDeps {
    /// `spec.features.endpointAuth`, hot-reloaded — the dialect and the gateway are read fresh on
    /// every pass, so changing either re-sweeps the cluster without a restart.
    pub config: Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The operator's own namespace — where the shared `Middleware` lives.
    pub operator_namespace: NamespaceName,
    /// The namespace cache: owner, team labels and the `endpoint-access` grant (RFC 0021).
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// The change-only audit of restricted access keys (RFC 0021).
    pub restricted: Arc<RestrictedReporter>,
}

struct Ctx {
    client: Client,
    deps: EndpointAuthDeps,
    recorder: Recorder,
}

/// Start the loop. Returns once the initial watch is established; the loop itself runs until the
/// process stops.
pub async fn spawn(client: Client, deps: EndpointAuthDeps, recorder: Recorder) {
    // The periodic half of this loop: the objects that are not `Ingress`es. The shared Traefik
    // `Middleware` on one dialect, and the `Route` sweep plus its companions on the other —
    // neither of which a watch over `Ingress` would ever reach.
    let ticker_client = client.clone();
    let ticker_config = Arc::clone(&deps.config);
    let ticker_namespace = deps.operator_namespace.clone();
    tokio::spawn(async move {
        // Short, because the `Middleware` has to exist before the first annotation names it and
        // a five-minute tick leaves a freshly elected leader (or a deleted `Middleware`) with
        // unroutable `Ingress`es for that long. The server-side apply is a no-op when nothing
        // changed; the heavier `Route` listing keeps its old cadence.
        let mut interval = tokio::time::interval(MIDDLEWARE_TICK);
        let mut ticks: u64 = 0;
        loop {
            interval.tick().await;
            ticks = ticks.wrapping_add(1);
            let Some(config) = read(&ticker_config) else {
                continue;
            };
            if config.mode != FeatureMode::Enforce {
                continue;
            }
            match config.gateway.dialect {
                Dialect::Traefik => {
                    // The annotation names the middleware by the *gateway's* namespace, and the
                    // controller's RBAC lets it write one only in its own: when they differ the
                    // annotation points at an object nobody creates.
                    if config.gateway.service.namespace != ticker_namespace.as_str() {
                        tracing::error!(
                            "endpoint-auth gateway.service.namespace={} \
                             is not the operator's namespace {}; the shared Middleware cannot be \
                             created where the annotations name it",
                            config.gateway.service.namespace,
                            ticker_namespace
                        );
                        continue;
                    }
                    if let Err(err) =
                        ensure_middleware(&ticker_client, &ticker_namespace, &config).await
                    {
                        tracing::error!("endpoint-auth middleware: {err}");
                    }
                }
                dialect if dialect.mode() == AttachmentMode::ReverseProxy => {
                    // `ticks` is already 1 on the interval's immediate first tick: sweep then, so a
                    // fresh controller or new leader does not leave Routes unreconciled for a
                    // whole sweep period.
                    if ticks.wrapping_sub(1).is_multiple_of(ROUTE_SWEEP_EVERY)
                        && let Err(err) = sweep_routes(&ticker_client, &config).await
                    {
                        tracing::error!("endpoint-auth route sweep: {err}");
                    }
                }
                _ => {}
            }
        }
    });

    let ctx = Arc::new(Ctx {
        client: client.clone(),
        deps,
        recorder,
    });
    let api: Api<Ingress> = Api::all(client.clone());
    let controller = Controller::new(api, WatcherConfig::default());
    // RFC 0021 R-12: a Namespace whose annotations change re-queues every `Ingress` in it, so a
    // removed `endpoint-access` grant is audited in seconds, not at the 300 s requeue.
    let ingresses = controller.store();
    let changes = AnnotationChanges::default();
    let controller = controller.watches(
        Api::<Namespace>::all(client),
        WatcherConfig::default(),
        move |ns: Namespace| {
            if !changes.changed(&ns) {
                return Vec::new();
            }
            let name = ns.name_any();
            ingresses
                .state()
                .iter()
                .filter(|ingress| ingress.metadata.namespace.as_deref() == Some(name.as_str()))
                .map(|ingress| ObjectRef::from_obj(ingress.as_ref()))
                .collect::<Vec<_>>()
        },
    );
    // A deleted `Ingress` (DWO's carry no finalizer) is never reconciled, so its audit memory is
    // pruned against the controller's own cache, at the sweep's backstop cadence.
    let live = controller.store();
    let restricted = Arc::clone(&ctx.deps.restricted);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REQUEUE);
        loop {
            interval.tick().await;
            let uids: std::collections::HashSet<String> = live
                .state()
                .iter()
                .filter_map(|ingress| ingress.metadata.uid.clone())
                .collect();
            restricted.retain(|uid| uids.contains(uid));
        }
    });
    tokio::spawn(async move {
        controller
            .shutdown_on_signal()
            .run(
                |object, ctx| events::tracked(Arc::clone(&object), reconcile(object, ctx)),
                error_policy,
                ctx,
            )
            .for_each(|_| futures_util::future::ready(()))
            .await;
    });
}

fn read(
    config: &Arc<RwLock<Option<ResolvedEndpointAuthConfig>>>,
) -> Option<ResolvedEndpointAuthConfig> {
    config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// What one pass decided for one object — returned rather than logged inline so the unit tests
/// can assert on it without a cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// The object already carries what the dialect wants.
    Unchanged,
    /// These annotations would be written.
    Attach(BTreeMap<String, String>),
    /// These annotation keys would be removed — `mode: Off`, or a dialect that no longer owns
    /// them.
    Detach(Vec<String>),
}

/// What the sweep would do to one object's annotations, given the mode.
///
/// Pure, and the whole decision of this module: the loop below is the watch, the patch and the
/// requeue around it.
pub fn sweep(
    config: &ResolvedEndpointAuthConfig,
    mode: FeatureMode,
    annotations: &BTreeMap<String, String>,
    backend: Option<(&str, u16)>,
) -> SweepOutcome {
    if mode == FeatureMode::Off {
        // Only an object this feature gated. `router.middlewares` is a key a developer or another
        // controller may own on an object we never touched, and a rollback that strips it there
        // would be the incident.
        if annotations
            .get(weebo_si_crd::ENDPOINT_AUTH_ANNOTATION)
            .map(String::as_str)
            != Some("managed")
        {
            return SweepOutcome::Unchanged;
        }
        let present: Vec<String> = config
            .detachment()
            .into_iter()
            .filter(|key| annotations.contains_key(key))
            .collect();
        return if present.is_empty() {
            SweepOutcome::Unchanged
        } else {
            SweepOutcome::Detach(present)
        };
    }

    let attachment = config.attachment(annotations, backend);
    let missing: BTreeMap<String, String> = attachment
        .annotations
        .into_iter()
        .filter(|(key, value)| annotations.get(key) != Some(value))
        .collect();
    if missing.is_empty() {
        SweepOutcome::Unchanged
    } else {
        SweepOutcome::Attach(missing)
    }
}

async fn reconcile(ingress: Arc<Ingress>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // The audit's memory is dropped whenever no pass reports for the object (deleted, feature
    // absent, not governed, `Off`, a `Route` dialect), so it reports afresh once one does.
    let forget = || {
        if let Some(uid) = ingress.metadata.uid.as_deref() {
            ctx.deps.restricted.forget(uid);
        }
    };
    let Some(config) = read(&ctx.deps.config) else {
        forget();
        return Ok(Action::requeue(REQUEUE));
    };
    let namespace = NamespaceName::new(ingress.namespace().unwrap_or_default());
    // The webhook's scope, restated here because the sweep patches objects the webhook never saw:
    // without it an unset `namespaceSelector` makes this loop gate every `Ingress` in the
    // cluster, the gateway's own and Che's included, and users are locked out of the login page.
    if !governs_ingress(&config, &namespace, &ctx.deps.operator_namespace, &ingress) {
        forget();
        return Ok(Action::requeue(REQUEUE));
    }
    let mode = ctx
        .deps
        .gate
        .mode(weebo_si_chassis::FeatureId::new(FEATURE), &namespace);

    // A dialect that targets `Route`s does not sweep `Ingress`es: the objects it gates are not
    // these, and writing our annotations onto them would be a gate nothing consults. What it
    // *does* need in every workspace namespace is the pair of companion objects, since a
    // `Route`'s backend is a local reference.
    if config.gateway.dialect.target_kind() != weebo_si_crd::RoutingKind::Ingress {
        // `sweep_routes` in the ticker above owns that dialect's objects, companions included.
        forget();
        return Ok(Action::requeue(REQUEUE));
    }

    let annotations: BTreeMap<String, String> = ingress.annotations().clone().into_iter().collect();
    // Before the sweep's patch, whose failure ends the pass: the gateway serves the object either
    // way, so its audit must not depend on that write.
    if mode == FeatureMode::Off || ingress.metadata.deletion_timestamp.is_some() {
        forget();
    } else {
        report_restricted(&ctx, &ingress, &config, &namespace, &annotations, mode).await;
    }
    let outcome = sweep(&config, mode, &annotations, None);
    let name = ingress.name_any();

    match outcome {
        SweepOutcome::Unchanged => {}
        SweepOutcome::Attach(missing) if mode == FeatureMode::Enforce => {
            // The patch replaces these values wholesale. The guard pins the chain by value, so a
            // middleware someone put there (strip-prefix, rate-limit) could not stay anyway, but
            // dropping it silently is how "the route stopped working" gets reported.
            for (key, value) in &missing {
                if let Some(existing) = annotations.get(key)
                    && !existing.is_empty()
                    && existing != value
                {
                    tracing::warn!(
                        "endpoint-auth replacing {key} namespace={namespace} \
                         ingress={name} was={existing:?} now={value:?}"
                    );
                }
            }
            patch_annotations(&ctx, &namespace, &name, annotation_patch(&missing, false)).await?;
            tracing::info!(
                "endpoint-auth attached namespace={namespace} ingress={name} keys={}",
                missing.len()
            );
        }
        // `sweep` only returns `Detach` for `Off`, so this arm is the rollback RFC 0009 promises.
        // Guarding it on `Enforce` made it unreachable. It also needs the configuration itself to
        // say `Off`: with a `namespaceSelector` the gate answers `Off` for a namespace its cache
        // has not seen yet, and a fresh leader would otherwise ungate every endpoint it reaches
        // before the Namespace reflector fills.
        SweepOutcome::Detach(keys)
            if mode == FeatureMode::Off && config.mode == FeatureMode::Off =>
        {
            let removals: BTreeMap<String, String> = keys
                .iter()
                .map(|key| (key.clone(), String::new()))
                .collect();
            patch_annotations(&ctx, &namespace, &name, annotation_patch(&removals, true)).await?;
            tracing::info!(
                "endpoint-auth detached namespace={namespace} ingress={name} keys={}",
                keys.len()
            );
        }
        other => tracing::info!(
            "endpoint-auth would-change namespace={namespace} ingress={name} outcome={other:?} mode={mode:?}"
        ),
    }

    Ok(Action::requeue(REQUEUE))
}

/// The RFC 0021 audit of one pass: compile the `Ingress` as the gateway does, and for each
/// restricted key that entered its honoured or refused set since the last pass, one count (in
/// the reporter), one INFO line and one Event. Runs in `DryRun` too (S9). A namespace with no
/// owner is not indexed by the gateway, and a policy that does not compile is indexed closed:
/// neither serves a restricted key, so neither reports one.
async fn report_restricted(
    ctx: &Ctx,
    ingress: &Ingress,
    config: &ResolvedEndpointAuthConfig,
    namespace: &NamespaceName,
    annotations: &BTreeMap<String, String>,
    mode: FeatureMode,
) {
    let Some(uid) = ingress.metadata.uid.as_deref() else {
        return;
    };
    let inputs = NamespaceInputs::read(
        ctx.deps.namespace_view.as_ref(),
        ctx.deps.gate.as_ref(),
        config,
        namespace,
    );
    let compiled = inputs.owner.as_ref().and_then(|_| {
        compile_annotations(
            config,
            annotations,
            namespace,
            &inputs,
            &gateway_overrides(config),
            UnknownKey::Default,
        )
    });
    let (honoured, refused) = restricted_sets(compiled.as_ref());
    let change = ctx
        .deps
        .restricted
        .observe(uid, honoured, refused.keys().cloned());
    let name = ingress.name_any();
    for key in &change.honoured {
        tracing::info!(
            "feature=endpoint-auth restricted={key} namespace={namespace} ingress={name} \
             mode={mode:?} result=honoured"
        );
        events::restricted_grant(&ctx.recorder, ingress, true, honoured_note(key)).await;
    }
    for key in &change.refused {
        tracing::info!(
            "feature=endpoint-auth restricted={key} namespace={namespace} ingress={name} \
             mode={mode:?} result=refused reason=no_namespace_grant"
        );
        let served_as = refused.get(key).map(String::as_str).unwrap_or_default();
        events::restricted_grant(
            &ctx.recorder,
            ingress,
            false,
            refused_note(key, namespace.as_str(), served_as),
        )
        .await;
    }
}

/// What a refused restricted key is served as when no default can replace it.
const CLOSED: &str = "closed";

/// The restricted keys a compiled policy honoured, and those it refused with the key served in
/// each one's place. A restricted default with no grant leaves nothing to serve: the endpoint is
/// closed, and that refusal gets the same Event and metric as one served as the default.
fn restricted_sets(
    compiled: Option<&Result<EndpointPolicy, CompileError>>,
) -> (Vec<String>, BTreeMap<String, String>) {
    let mut honoured = Vec::new();
    let mut refused = BTreeMap::new();
    let policy = match compiled {
        Some(Ok(policy)) => Some(policy),
        Some(Err(CompileError::RestrictedNotGranted { default, requested })) => {
            for key in std::iter::once(default).chain(requested) {
                refused.insert(key.to_string(), CLOSED.to_string());
            }
            None
        }
        Some(Err(_)) | None => None,
    };
    for (key, result) in policy
        .map(|policy| policy.restricted.as_slice())
        .unwrap_or_default()
    {
        match result {
            RestrictedResult::Honoured => honoured.push(key.to_string()),
            RestrictedResult::Refused { served_as } => {
                refused.insert(key.to_string(), served_as.to_string());
            }
        }
    }
    (honoured, refused)
}

/// The `RestrictedGrantHonoured` Event's note, in the RFC 0021 mock's words.
fn honoured_note(key: &str) -> String {
    format!(
        "access key {key} is restricted; granted by namespace annotation {}",
        weebo_si_crd::ENDPOINT_ACCESS_NAMESPACE_ANNOTATION
    )
}

/// The `RestrictedGrantRefused` Event's note, in the RFC 0021 mock's words.
fn refused_note(key: &str, namespace: &str, served_as: &str) -> String {
    format!(
        "access key {key} is restricted and namespace {namespace} does not grant it \
         (annotation {}); served as {served_as}",
        weebo_si_crd::ENDPOINT_ACCESS_NAMESPACE_ANNOTATION
    )
}

/// Whether this feature governs `ingress` at all: not in a namespace the operator never touches,
/// and naming at least one host under the governed suffix that is not excluded. An `Ingress` with
/// no host is not an endpoint on its own FQDN, which is the only thing this feature governs.
fn governs_ingress(
    config: &ResolvedEndpointAuthConfig,
    namespace: &NamespaceName,
    operator_namespace: &NamespaceName,
    ingress: &Ingress,
) -> bool {
    if is_excluded_namespace(namespace, operator_namespace) {
        return false;
    }
    ingress
        .spec
        .as_ref()
        .and_then(|spec| spec.rules.as_ref())
        .is_some_and(|rules| {
            rules
                .iter()
                .filter_map(|rule| rule.host.as_deref())
                .any(|host| config.hosts.governs(host))
        })
}

/// A merge patch over `metadata.annotations`. Removing a key is `null`, which is why this cannot
/// be a server-side apply of the annotations we own: an apply would also have to claim ownership
/// of keys DevWorkspace Operator writes into the same map.
fn annotation_patch(annotations: &BTreeMap<String, String>, remove: bool) -> Value {
    let entries: serde_json::Map<String, Value> = annotations
        .iter()
        .map(|(key, value)| {
            let value = if remove {
                Value::Null
            } else {
                Value::String(value.clone())
            };
            (key.clone(), value)
        })
        .collect();
    json!({ "metadata": { "annotations": entries } })
}

async fn patch_annotations(
    ctx: &Ctx,
    namespace: &NamespaceName,
    name: &str,
    patch: Value,
) -> Result<(), Error> {
    let api: Api<Ingress> = Api::namespaced(ctx.client.clone(), namespace.as_str());
    api.patch(name, &PatchParams::default(), &Patch::Merge(patch))
        .await
        .map(|_| ())
        .map_err(Error)
}

/// Create or update the one shared `forwardAuth` `Middleware` every gated `Ingress` names.
///
/// `trustForwardHeader: false` is the line that matters: Traefik sets `X-Forwarded-*` itself from
/// the connection, and trusting the client's copies would let a caller state its own host, path
/// and scheme to the gate — the header forgery the whole contract rests on not being possible.
pub async fn ensure_middleware(
    client: &Client,
    namespace: &NamespaceName,
    config: &ResolvedEndpointAuthConfig,
) -> Result<(), kube::Error> {
    let gvk = GroupVersionKind::gvk("traefik.io", "v1alpha1", "Middleware");
    let resource = ApiResource::from_gvk(&gvk);
    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), namespace.as_str(), &resource);
    let object = DynamicObject {
        types: Some(TypeMeta {
            api_version: "traefik.io/v1alpha1".to_owned(),
            kind: "Middleware".to_owned(),
        }),
        metadata: ObjectMeta {
            name: Some(MIDDLEWARE_NAME.to_owned()),
            namespace: Some(namespace.as_str().to_owned()),
            labels: Some(
                [(
                    weebo_si_crd::MANAGED_BY_LABEL.to_owned(),
                    weebo_si_crd::MANAGED_BY_VALUE.to_owned(),
                )]
                .into_iter()
                .collect(),
            ),
            ..ObjectMeta::default()
        },
        data: middleware_data(config),
    };
    api.patch(
        MIDDLEWARE_NAME,
        &PatchParams::apply("weebo-si-operator").force(),
        &Patch::Apply(&object),
    )
    .await
    .map(|_| ())
}

/// The shared `Middleware`'s body. The conformance suite runs Traefik against a hand-written copy
/// of it (`bins/endpoint-gateway/tests/conformance.rs`), so a change here belongs there too.
fn middleware_data(config: &ResolvedEndpointAuthConfig) -> Value {
    json!({
        "spec": {
            "forwardAuth": {
                "address": format!("{}/auth", config.gateway.service_url()),
                "trustForwardHeader": false,
                "authResponseHeaders": [
                    "X-Auth-Request-User",
                    "X-Auth-Request-Groups",
                    "X-Auth-Request-Email"
                ],
                // What makes the sliding re-mint of RFC 0009's *Developer continuity*
                // possible at all: without it a `Set-Cookie` on the gate's own `200` never
                // reaches the browser, and an endpoint in continuous use would still expire
                // under the person using it.
                "addAuthCookiesToResponse": ["__Host-weebo-endpoint"],
                // Traefik reads a non-2xx auth answer's body to return it, and without this
                // bound reads it whole — it warns as much on every middleware it loads. The
                // gate's own bodies (a sign-in page, a refusal) are a few hundred bytes.
                "maxResponseBodySize": TRAEFIK_MAX_AUTH_BODY
            }
        }
    })
}

/// What can go wrong in one pass. A newtype over the one thing that can — the apiserver refusing
/// a read or a write — matching [`weebo_si_controller::reconcile::Error`]'s own shape rather than inventing a
/// richer error nobody branches on.
#[derive(Debug)]
pub struct Error(pub kube::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

fn error_policy(object: Arc<Ingress>, error: &Error, ctx: Arc<Ctx>) -> Action {
    events::retry(
        &ctx.recorder,
        object.as_ref(),
        ReasonCode::EndpointAuthFailed,
        error,
    )
}

/// One pass over every `Route` this feature governs: attach the gate, repoint the backend, and
/// give each namespace the companion objects a local `spec.to` needs.
///
/// A poll rather than a watch, unlike the `Ingress` half. `Route` is not a type this operator
/// links — it exists only on OpenShift — so the sweep goes through `DynamicObject`, and a
/// five-minute pass over objects DevWorkspace Operator writes at workspace start is the right
/// trade against carrying a second typed watch for a kind most clusters do not serve. The
/// mutating webhook is what makes a *new* `Route` gated immediately; this is what covers the ones
/// that predate the feature.
pub async fn sweep_routes(
    client: &Client,
    config: &ResolvedEndpointAuthConfig,
) -> Result<(), kube::Error> {
    let resource =
        ApiResource::from_gvk(&GroupVersionKind::gvk("route.openshift.io", "v1", "Route"));
    let routes: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
    let all = routes.list(&kube::api::ListParams::default()).await?;

    let mut namespaces: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for route in all.items {
        let Some(namespace) = route.metadata.namespace.clone() else {
            continue;
        };
        let host = route
            .data
            .pointer("/spec/host")
            .and_then(|host| host.as_str())
            .unwrap_or_default();
        // Only hosts this feature governs: a `Route` on some other suffix is none of its
        // business, and repointing one would take an unrelated application off the air.
        if host.is_empty() || !config.hosts.governs(host) {
            continue;
        }
        namespaces.insert(namespace.clone());

        let annotations: BTreeMap<String, String> = route
            .metadata
            .annotations
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let backend = route
            .data
            .pointer("/spec/to/name")
            .and_then(|name| name.as_str())
            .map(|name| {
                let port = route
                    .data
                    .pointer("/spec/port/targetPort")
                    .and_then(|port| port.as_u64())
                    .unwrap_or(80) as u16;
                (name.to_owned(), port)
            });
        let attachment = config.attachment(
            &annotations,
            backend.as_ref().map(|(name, port)| (name.as_str(), *port)),
        );
        if !attachment.changes(&annotations) {
            continue;
        }

        let name = route.metadata.name.clone().unwrap_or_default();
        let mut patch = annotation_patch(&attachment.annotations, false);
        if let Some(retarget) = attachment.retarget.as_ref() {
            patch["spec"] = json!({
                "to": { "name": retarget.service },
                "port": { "targetPort": "http" },
            });
        }
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), &namespace, &resource);
        api.patch(&name, &PatchParams::default(), &Patch::Merge(patch))
            .await?;
        tracing::info!("endpoint-auth attached namespace={namespace} route={name}");
    }

    if namespaces.is_empty() {
        return Ok(());
    }
    let addresses = gateway_endpoints(client, config).await?;
    if addresses.is_empty() {
        tracing::warn!(
            "endpoint-auth found no ready gateway endpoints; leaving \
             the companion EndpointSlices as they are"
        );
        return Ok(());
    }
    for namespace in namespaces {
        reconcile_companions(client, &NamespaceName::new(namespace), config, &addresses).await?;
    }
    Ok(())
}

/// Reconcile the companion objects a `ReverseProxy` dialect needs in one workspace namespace.
///
/// Two objects, because a `Route`'s `spec.to` is a local reference with no cross-namespace form:
/// a selector-less `Service` and an `EndpointSlice` pointing at the gateway's own pods. This is
/// the shape RFC 0009's question 4 predicted in the abstract when it chose one shared Traefik
/// `Middleware` over a per-namespace copy — **a dialect needing a companion object in the user's
/// namespace brings the problem back in its original form** — and the answer is the same one:
/// the objects carry the operator's ownership label, so `policy-guard`'s original three-row
/// table refuses a developer's edit of them without a new rule.
pub async fn reconcile_companions(
    client: &Client,
    namespace: &NamespaceName,
    config: &ResolvedEndpointAuthConfig,
    gateway_endpoints: &[String],
) -> Result<(), kube::Error> {
    let params = PatchParams::apply("weebo-si-operator").force();

    let services: Api<k8s_openapi::api::core::v1::Service> =
        Api::namespaced(client.clone(), namespace.as_str());
    services
        .patch(
            COMPANION_SERVICE,
            &params,
            &Patch::Apply(&companion_service(namespace, config)),
        )
        .await?;

    // Addresses rather than a selector: the pods behind this `Service` live in the operator's
    // namespace, and a selector cannot reach across one. Reconciled from the gateway's own
    // endpoints, so a gateway rollout moves this slice with it.
    let slices: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        namespace.as_str(),
        &ApiResource::from_gvk(&GroupVersionKind::gvk(
            "discovery.k8s.io",
            "v1",
            "EndpointSlice",
        )),
    );
    slices
        .patch(
            COMPANION_SERVICE,
            &params,
            &Patch::Apply(&companion_slice(namespace, config, gateway_endpoints)),
        )
        .await
        .map(|_| ())
}

/// The companion `Service` a `ReverseProxy` dialect needs in each workspace namespace, since a
/// `Route`'s `spec.to` is a local reference with no cross-namespace form.
pub fn companion_service(namespace: &NamespaceName, config: &ResolvedEndpointAuthConfig) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": COMPANION_SERVICE,
            "namespace": namespace.as_str(),
            "labels": { weebo_si_crd::MANAGED_BY_LABEL: weebo_si_crd::MANAGED_BY_VALUE },
        },
        // Selector-less on purpose: its endpoints are the gateway's, reconciled from the
        // gateway's own EndpointSlice rather than matched by a label in a namespace the gateway
        // does not run in.
        "spec": {
            "ports": [ { "name": "http", "port": config.gateway.service.port, "targetPort": config.gateway.service.port } ]
        }
    })
}

/// The `EndpointSlice` that gives the companion `Service` its addresses.
pub fn companion_slice(
    namespace: &NamespaceName,
    config: &ResolvedEndpointAuthConfig,
    addresses: &[String],
) -> Value {
    json!({
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSlice",
        "metadata": {
            "name": COMPANION_SERVICE,
            "namespace": namespace.as_str(),
            "labels": {
                weebo_si_crd::MANAGED_BY_LABEL: weebo_si_crd::MANAGED_BY_VALUE,
                // What ties the slice to the Service above. Kubernetes reads this label, not a
                // reference, which is why the two names must match.
                "kubernetes.io/service-name": COMPANION_SERVICE,
            },
        },
        "addressType": "IPv4",
        "ports": [ { "name": "http", "port": config.gateway.service.port } ],
        "endpoints": addresses.iter().map(|address| json!({
            "addresses": [address],
            "conditions": { "ready": true }
        })).collect::<Vec<_>>(),
    })
}

/// Whether this dialect needs [`companion_service`] at all.
pub fn needs_companion(config: &ResolvedEndpointAuthConfig) -> bool {
    config.gateway.dialect.mode() == AttachmentMode::ReverseProxy
}

/// The gateway's own ready pod addresses, read from its `EndpointSlice`s in the operator's
/// namespace — the source the companions above are reconciled from.
pub async fn gateway_endpoints(
    client: &Client,
    config: &ResolvedEndpointAuthConfig,
) -> Result<Vec<String>, kube::Error> {
    let api: Api<DynamicObject> = Api::namespaced_with(
        client.clone(),
        &config.gateway.service.namespace,
        &ApiResource::from_gvk(&GroupVersionKind::gvk(
            "discovery.k8s.io",
            "v1",
            "EndpointSlice",
        )),
    );
    let slices = api
        .list(&kube::api::ListParams::default().labels(&format!(
            "kubernetes.io/service-name={}",
            config.gateway.service.name
        )))
        .await?;
    Ok(slices
        .items
        .iter()
        .filter_map(|slice| slice.data.get("endpoints")?.as_array().cloned())
        .flatten()
        .filter(|endpoint| {
            // Only ready addresses: pointing a workspace namespace's companion at a gateway pod
            // that is still syncing its informers would answer `503` to a developer who did
            // nothing wrong.
            endpoint
                .get("conditions")
                .and_then(|conditions| conditions.get("ready"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|endpoint| endpoint.get("addresses")?.as_array().cloned())
        .flatten()
        .filter_map(|address| address.as_str().map(ToOwned::to_owned))
        .collect())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::{
        AccessEntry, AccessKey, ENDPOINT_AUTH_ANNOTATION, EndpointAuthConfig, EndpointSelection,
        GateEnforcement, GatewayRef, HostOwnership, HostsConfig, OwnerConfig, Resolved,
        SelfOriginConfig, ServiceRef,
    };

    use super::*;

    const CHAIN: &str = "traefik.ingress.kubernetes.io/router.middlewares";

    fn config() -> ResolvedEndpointAuthConfig {
        Resolved::without_teams(EndpointAuthConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            gateway: GatewayRef {
                external_url: "https://auth.weebo.si".to_owned(),
                cluster_domain: "cluster.local".to_owned(),
                service: ServiceRef {
                    name: "endpoint-gateway".to_owned(),
                    namespace: "weebo-si-hardening".to_owned(),
                    port: 4180,
                },
                dialect: Dialect::Traefik,
                enforcement: GateEnforcement::Enforce,
                allowed_middlewares: Vec::new(),
                error_page_middleware: None,
                custom: None,
                haproxy_prerequisite: false,
            },
            break_glass_identities: Vec::new(),
            owner: OwnerConfig {
                namespace_annotation: "che.eclipse.org/username".to_owned(),
                devworkspace_operator_identity: "system:serviceaccount:dwo:dwo".to_owned(),
            },
            hosts: HostsConfig {
                suffix: ".weebo.si".to_owned(),
                ownership: vec![HostOwnership {
                    template: Some("{user}-{workspace}-{endpoint}".to_owned()),
                    regex: None,
                }],
                exclude: Vec::new(),
            },
            catalog: vec![AccessEntry {
                key: AccessKey::new("private"),
                anonymous: false,
                delegation: Vec::new(),
                restricted: false,
            }],
            default: AccessKey::new("private"),
            overrides: Vec::new(),
            endpoint_selection: EndpointSelection::default(),
            self_origin: SelfOriginConfig::default(),
            allowed_issuers: vec!["vault-issuer".to_owned()],
        })
    }

    fn attached() -> BTreeMap<String, String> {
        config()
            .attachment(&BTreeMap::new(), None)
            .annotations
            .into_iter()
            .collect()
    }

    #[test]
    fn the_sweep_covers_an_object_created_before_the_feature_was_switched_on() {
        let outcome = sweep(&config(), FeatureMode::Enforce, &BTreeMap::new(), None);
        match outcome {
            SweepOutcome::Attach(missing) => {
                assert_eq!(missing[ENDPOINT_AUTH_ANNOTATION], "managed");
                assert!(missing.contains_key(CHAIN));
            }
            other => panic!("expected an attach, got {other:?}"),
        }
    }

    #[test]
    fn an_object_that_already_agrees_is_left_alone() {
        assert_eq!(
            sweep(&config(), FeatureMode::Enforce, &attached(), None),
            SweepOutcome::Unchanged
        );
    }

    #[test]
    fn a_stripped_annotation_is_put_back_on_the_next_pass() {
        // The self-healing half: DevWorkspace Operator rewrites these objects on its own
        // schedule, and if it uses Update rather than apply, its write drops what we added.
        let mut annotations = attached();
        annotations.remove(CHAIN);
        match sweep(&config(), FeatureMode::Enforce, &annotations, None) {
            SweepOutcome::Attach(missing) => {
                assert_eq!(missing.len(), 1);
                assert!(missing.contains_key(CHAIN));
            }
            other => panic!("expected an attach, got {other:?}"),
        }
    }

    #[test]
    fn off_strips_the_dialects_keys_and_never_the_developers() {
        let mut annotations = attached();
        annotations.insert(
            "hardening.weebo.io/allow-users".to_owned(),
            "bob".to_owned(),
        );
        match sweep(&config(), FeatureMode::Off, &annotations, None) {
            SweepOutcome::Detach(keys) => {
                assert!(keys.contains(&CHAIN.to_owned()));
                assert!(keys.contains(&ENDPOINT_AUTH_ANNOTATION.to_owned()));
                assert!(
                    !keys.contains(&"hardening.weebo.io/allow-users".to_owned()),
                    "a rollback must leave the developer's sharing where they left it"
                );
            }
            other => panic!("expected a detach, got {other:?}"),
        }
    }

    #[test]
    fn off_leaves_a_chain_on_an_object_this_feature_never_gated() {
        // A developer's own middleware chain, no managed marker.
        let annotations = BTreeMap::from([(CHAIN.to_owned(), "mine@kubernetescrd".to_owned())]);
        assert_eq!(
            sweep(&config(), FeatureMode::Off, &annotations, None),
            SweepOutcome::Unchanged
        );
    }

    fn ingress_for(hosts: &[&str]) -> Ingress {
        serde_json::from_value(json!({
            "metadata": { "name": "x", "namespace": "user-alice" },
            "spec": { "rules": hosts.iter().map(|host| json!({ "host": host })).collect::<Vec<_>>() }
        }))
        .unwrap()
    }

    #[test]
    fn the_sweep_governs_only_what_the_webhook_governs() {
        let mut config = config();
        config.hosts.exclude = vec!["auth.weebo.si".to_owned()];
        let operator = NamespaceName::new("weebo-si-hardening");
        let alice = NamespaceName::new("user-alice");

        assert!(governs_ingress(
            &config,
            &alice,
            &operator,
            &ingress_for(&["alice-ws-api.weebo.si"])
        ));
        // The gateway's own login host, which gating would lock everyone out of.
        assert!(!governs_ingress(
            &config,
            &alice,
            &operator,
            &ingress_for(&["auth.weebo.si"])
        ));
        // Another suffix, and no host at all.
        assert!(!governs_ingress(
            &config,
            &alice,
            &operator,
            &ingress_for(&["x.example.org"])
        ));
        assert!(!governs_ingress(
            &config,
            &alice,
            &operator,
            &ingress_for(&[])
        ));
        // The operator's namespace and Che's, whatever host they carry.
        for namespace in [operator.clone(), NamespaceName::new("eclipse-che")] {
            assert!(!governs_ingress(
                &config,
                &namespace,
                &operator,
                &ingress_for(&["alice-ws-api.weebo.si"])
            ));
        }
    }

    #[test]
    fn off_on_an_object_that_was_never_gated_does_nothing() {
        assert_eq!(
            sweep(&config(), FeatureMode::Off, &BTreeMap::new(), None),
            SweepOutcome::Unchanged
        );
    }

    #[test]
    fn break_glass_survives_the_sweep_rather_than_being_quietly_undone() {
        let annotations =
            BTreeMap::from([(ENDPOINT_AUTH_ANNOTATION.to_owned(), "bypass".to_owned())]);
        assert_eq!(
            sweep(&config(), FeatureMode::Enforce, &annotations, None),
            SweepOutcome::Unchanged
        );
    }

    #[test]
    fn the_removal_patch_is_nulls_and_the_attach_patch_is_values() {
        let patch = annotation_patch(&BTreeMap::from([("a".to_owned(), "b".to_owned())]), false);
        assert_eq!(patch["metadata"]["annotations"]["a"], json!("b"));
        let patch = annotation_patch(&BTreeMap::from([("a".to_owned(), String::new())]), true);
        assert!(patch["metadata"]["annotations"]["a"].is_null());
    }

    /// Pinned whole: the conformance suite runs Traefik against a hand-written copy of this body,
    /// so a field dropped or changed here must fail here rather than pass there.
    #[test]
    fn the_middleware_never_trusts_forwarded_headers_and_bounds_the_auth_body() {
        let config = config();
        assert_eq!(
            middleware_data(&config),
            json!({
                "spec": {
                    "forwardAuth": {
                        "address": format!("{}/auth", config.gateway.service_url()),
                        "trustForwardHeader": false,
                        "authResponseHeaders": [
                            "X-Auth-Request-User",
                            "X-Auth-Request-Groups",
                            "X-Auth-Request-Email"
                        ],
                        "addAuthCookiesToResponse": ["__Host-weebo-endpoint"],
                        "maxResponseBodySize": 65_536
                    }
                }
            })
        );
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_companion_slice_carries_the_gateways_addresses_and_the_label_that_ties_it() {
        let mut config = config();
        config.gateway.dialect = Dialect::OpenShiftRoute;
        let slice = companion_slice(
            &NamespaceName::new("user-alice"),
            &config,
            &["10.128.0.7".to_owned(), "10.128.1.9".to_owned()],
        );
        assert_eq!(
            slice["metadata"]["labels"]["kubernetes.io/service-name"],
            json!(COMPANION_SERVICE)
        );
        assert_eq!(slice["endpoints"].as_array().unwrap().len(), 2);
        assert_eq!(slice["endpoints"][0]["addresses"][0], json!("10.128.0.7"));
        assert_eq!(slice["endpoints"][0]["conditions"]["ready"], json!(true));
        // The operator's ownership label, so `policy-guard`'s original three-row table refuses a
        // developer's edit of it without this feature needing a rule of its own.
        assert_eq!(
            slice["metadata"]["labels"][weebo_si_crd::MANAGED_BY_LABEL],
            json!(weebo_si_crd::MANAGED_BY_VALUE)
        );
    }

    /// RFC 0021: the audit reads what `compile` recorded, and words it as the mocks do.
    #[test]
    fn the_restricted_audit_reads_the_compiled_policy_in_the_mocks_words() {
        use weebo_si_endpoint_auth::policy::CatalogueKey;
        let mut policy = weebo_si_endpoint_auth::testing::policy_for("dev-ws-alice", "api");
        policy.restricted = vec![
            (
                CatalogueKey::new("open"),
                RestrictedResult::Refused {
                    served_as: CatalogueKey::new("private"),
                },
            ),
            (CatalogueKey::new("team"), RestrictedResult::Honoured),
        ];
        let (honoured, refused) = restricted_sets(Some(&Ok(policy)));
        assert_eq!(honoured, vec!["team".to_owned()]);
        assert_eq!(
            refused,
            BTreeMap::from([("open".to_owned(), "private".to_owned())])
        );
        assert_eq!(restricted_sets(None), (Vec::new(), BTreeMap::new()));
        assert_eq!(
            restricted_sets(Some(&Err(CompileError::RestrictedNotGranted {
                default: CatalogueKey::new("private"),
                requested: Some(CatalogueKey::new("open")),
            }))),
            (
                Vec::new(),
                BTreeMap::from([
                    ("open".to_owned(), "closed".to_owned()),
                    ("private".to_owned(), "closed".to_owned())
                ])
            )
        );
        assert_eq!(
            restricted_sets(Some(&Err(CompileError::NotGranted(CatalogueKey::new(
                "open"
            ))))),
            (Vec::new(), BTreeMap::new())
        );
        assert_eq!(
            refused_note("open", "dev-ws-batleforc-test", "private"),
            "access key open is restricted and namespace dev-ws-batleforc-test does not grant it \
             (annotation hardening.weebo.io/endpoint-access); served as private"
        );
        assert_eq!(
            honoured_note("open"),
            "access key open is restricted; granted by namespace annotation \
             hardening.weebo.io/endpoint-access"
        );
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_companion_service_is_selector_less_and_only_for_a_reverse_proxy_dialect() {
        let mut config = config();
        assert!(!needs_companion(&config));
        config.gateway.dialect = Dialect::OpenShiftRoute;
        assert!(needs_companion(&config));
        let service = companion_service(&NamespaceName::new("user-alice"), &config);
        assert_eq!(service["metadata"]["name"], json!(COMPANION_SERVICE));
        assert!(service["spec"]["selector"].is_null());
    }
}
