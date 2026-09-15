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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::{Patch, PatchParams};
use kube::core::{DynamicObject, GroupVersionKind, ObjectMeta, TypeMeta};
use kube::discovery::ApiResource;
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Api, Client, ResourceExt};
use serde_json::{Value, json};
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_crd::{
    AttachmentMode, COMPANION_SERVICE, Dialect, EndpointAuthConfig, FeatureMode, MIDDLEWARE_NAME,
    NamespaceName,
};

/// This feature's identifier, as the gate and the log lines name it.
const FEATURE: &str = "endpoint-auth";

/// How often the sweep re-examines an object it already agreed with — long, because every
/// interesting change arrives as a watch event and this is only the backstop for the ones that
/// do not (a `WeeboSiConfig` edit that changes the dialect, a controller restart).
const REQUEUE: Duration = Duration::from_secs(300);

/// Everything the loop needs, built by the composition root.
pub struct EndpointAuthDeps {
    /// `spec.features.endpointAuth`, hot-reloaded — the dialect and the gateway are read fresh on
    /// every pass, so changing either re-sweeps the cluster without a restart.
    pub config: Arc<RwLock<Option<EndpointAuthConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The operator's own namespace — where the shared `Middleware` lives.
    pub operator_namespace: NamespaceName,
}

struct Ctx {
    client: Client,
    deps: EndpointAuthDeps,
    is_leader: Arc<AtomicBool>,
}

/// Start the loop. Returns once the initial watch is established; the loop itself runs until the
/// process stops.
pub async fn spawn(client: Client, deps: EndpointAuthDeps, is_leader: Arc<AtomicBool>) {
    // The periodic half of this loop: the objects that are not `Ingress`es. The shared Traefik
    // `Middleware` on one dialect, and the `Route` sweep plus its companions on the other —
    // neither of which a watch over `Ingress` would ever reach.
    let ticker_client = client.clone();
    let ticker_config = Arc::clone(&deps.config);
    let ticker_namespace = deps.operator_namespace.clone();
    let ticker_leader = Arc::clone(&is_leader);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REQUEUE);
        loop {
            interval.tick().await;
            if !ticker_leader.load(Ordering::Relaxed) {
                continue;
            }
            let Some(config) = read(&ticker_config) else {
                continue;
            };
            if config.mode != FeatureMode::Enforce {
                continue;
            }
            match config.gateway.dialect {
                Dialect::Traefik => {
                    if let Err(err) =
                        ensure_middleware(&ticker_client, &ticker_namespace, &config).await
                    {
                        eprintln!("ERROR weebo-si-controller: endpoint-auth middleware: {err}");
                    }
                }
                dialect if dialect.mode() == AttachmentMode::ReverseProxy => {
                    if let Err(err) = sweep_routes(&ticker_client, &config).await {
                        eprintln!("ERROR weebo-si-controller: endpoint-auth route sweep: {err}");
                    }
                }
                _ => {}
            }
        }
    });

    let ctx = Arc::new(Ctx {
        client: client.clone(),
        deps,
        is_leader,
    });
    let api: Api<Ingress> = Api::all(client);
    tokio::spawn(async move {
        Controller::new(api, WatcherConfig::default())
            .shutdown_on_signal()
            .run(reconcile, error_policy, ctx)
            .for_each(|_| futures_util::future::ready(()))
            .await;
    });
}

fn read(config: &Arc<RwLock<Option<EndpointAuthConfig>>>) -> Option<EndpointAuthConfig> {
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
    config: &EndpointAuthConfig,
    mode: FeatureMode,
    annotations: &BTreeMap<String, String>,
    backend: Option<(&str, u16)>,
) -> SweepOutcome {
    if mode == FeatureMode::Off {
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
    if !ctx.is_leader.load(Ordering::Relaxed) {
        return Ok(Action::requeue(REQUEUE));
    }
    let Some(config) = read(&ctx.deps.config) else {
        return Ok(Action::requeue(REQUEUE));
    };
    let namespace = NamespaceName::new(ingress.namespace().unwrap_or_default());
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
        return Ok(Action::requeue(REQUEUE));
    }

    let annotations: BTreeMap<String, String> = ingress.annotations().clone().into_iter().collect();
    let outcome = sweep(&config, mode, &annotations, None);
    let name = ingress.name_any();

    match outcome {
        SweepOutcome::Unchanged => {}
        SweepOutcome::Attach(missing) if mode == FeatureMode::Enforce => {
            patch_annotations(&ctx, &namespace, &name, annotation_patch(&missing, false)).await?;
            println!(
                "weebo-si-controller: endpoint-auth attached namespace={namespace} ingress={name} keys={}",
                missing.len()
            );
        }
        SweepOutcome::Detach(keys) if mode == FeatureMode::Enforce => {
            let removals: BTreeMap<String, String> = keys
                .iter()
                .map(|key| (key.clone(), String::new()))
                .collect();
            patch_annotations(&ctx, &namespace, &name, annotation_patch(&removals, true)).await?;
            println!(
                "weebo-si-controller: endpoint-auth detached namespace={namespace} ingress={name} keys={}",
                keys.len()
            );
        }
        other => println!(
            "weebo-si-controller: endpoint-auth would-change namespace={namespace} ingress={name} outcome={other:?} mode={mode:?}"
        ),
    }

    Ok(Action::requeue(REQUEUE))
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
    config: &EndpointAuthConfig,
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
        data: json!({
            "spec": {
                "forwardAuth": {
                    "address": format!("{}/auth", config.gateway.service.url()),
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
                    "addAuthCookiesToResponse": ["__Host-weebo-endpoint"]
                }
            }
        }),
    };
    api.patch(
        MIDDLEWARE_NAME,
        &PatchParams::apply("weebo-si-operator").force(),
        &Patch::Apply(&object),
    )
    .await
    .map(|_| ())
}

/// What can go wrong in one pass. A newtype over the one thing that can — the apiserver refusing
/// a read or a write — matching [`crate::reconcile::Error`]'s own shape rather than inventing a
/// richer error nobody branches on.
#[derive(Debug)]
pub struct Error(pub kube::Error);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

fn error_policy(_object: Arc<Ingress>, error: &Error, _ctx: Arc<Ctx>) -> Action {
    eprintln!("ERROR weebo-si-controller: endpoint-auth: {error}");
    Action::requeue(Duration::from_secs(30))
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
pub async fn sweep_routes(client: &Client, config: &EndpointAuthConfig) -> Result<(), kube::Error> {
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
        println!("weebo-si-controller: endpoint-auth attached namespace={namespace} route={name}");
    }

    if namespaces.is_empty() {
        return Ok(());
    }
    let addresses = gateway_endpoints(client, config).await?;
    if addresses.is_empty() {
        println!(
            "WARN weebo-si-controller: endpoint-auth found no ready gateway endpoints; leaving \
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
    config: &EndpointAuthConfig,
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
pub fn companion_service(namespace: &NamespaceName, config: &EndpointAuthConfig) -> Value {
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
    config: &EndpointAuthConfig,
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
pub fn needs_companion(config: &EndpointAuthConfig) -> bool {
    config.gateway.dialect.mode() == AttachmentMode::ReverseProxy
}

/// The gateway's own ready pod addresses, read from its `EndpointSlice`s in the operator's
/// namespace — the source the companions above are reconciled from.
pub async fn gateway_endpoints(
    client: &Client,
    config: &EndpointAuthConfig,
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
        AccessEntry, AccessKey, ENDPOINT_AUTH_ANNOTATION, EndpointSelection, GateEnforcement,
        GatewayRef, HostOwnership, HostsConfig, OwnerConfig, SelfOriginConfig, ServiceRef,
    };

    use super::*;

    const CHAIN: &str = "traefik.ingress.kubernetes.io/router.middlewares";

    fn config() -> EndpointAuthConfig {
        EndpointAuthConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            gateway: GatewayRef {
                external_url: "https://auth.weebo.si".to_owned(),
                service: ServiceRef {
                    name: "endpoint-gateway".to_owned(),
                    namespace: "weebo-si-hardening".to_owned(),
                    port: 4180,
                },
                dialect: Dialect::Traefik,
                enforcement: GateEnforcement::Enforce,
                allowed_middlewares: Vec::new(),
                custom: None,
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
            }],
            default: AccessKey::new("private"),
            overrides: Vec::new(),
            endpoint_selection: EndpointSelection::default(),
            self_origin: SelfOriginConfig::default(),
            grants: Default::default(),
        }
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
