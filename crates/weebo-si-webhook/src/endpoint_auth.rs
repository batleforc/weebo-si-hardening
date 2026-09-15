//! `endpoint-auth`'s two admission routes — RFC 0009's *Operator-side: mutate, reconcile, guard*.
//!
//! * **Mutating**, on `CREATE`/`UPDATE`: writes the dialect's annotations plus
//!   `hardening.weebo.io/endpoint-auth: managed`, and normalises the developer's delegation
//!   annotations. This is the rule Kyverno would otherwise hold.
//! * **Validating**, on `CREATE`/`UPDATE`/`DELETE`: host ownership, and
//!   [`weebo_si_policy_guard::EndpointRoutingGuard`]'s nine-row table.
//!
//! **The narrowing is the namespace, not the object.** An `objectSelector` on the DevWorkspace
//! label would be tighter and would leave a developer's own `Ingress` outside the webhook and
//! therefore outside the gate — the bypass RFC 0009's *Which `Ingress` answers for a host*
//! closes. The `namespaceSelector` on Che workspace namespaces is what makes `failurePolicy:
//! Fail` affordable: a failure closes workspace endpoints, not every `kubectl apply` in the
//! cluster.
//!
//! The mutation feature lives here rather than in a brick of its own because there is no decision
//! in it: [`EndpointAuthConfig::attachment`] is a pure function in `weebo-si-crd`, and what this
//! module adds is the chassis plumbing that gives it a mode, a metric and an observer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::port::observer::Observer;
use weebo_si_chassis::{
    AdmitOutcome, Context, Decision, DomainError, Feature, FeatureId, Mutation, Registry, Subject,
};
use weebo_si_crd::{
    ACCESS_ANNOTATION, ALLOW_GROUPS_ANNOTATION, ALLOW_USERS_ANNOTATION, AttachmentMode,
    DEVELOPER_ANNOTATIONS, DEVWORKSPACE_ID_LABEL, EndpointAuthConfig, NamespaceName,
    RULES_ANNOTATION, RoutingKind,
};
use weebo_si_policy_guard::{
    EndpointRoutingGuard, EndpointRoutingWrite, ManagedField, Provenance, WriteOperation,
};

use crate::metrics::WebhookMetrics;
use crate::render::render_patch;

/// Path the mutating rule on `networking.k8s.io/v1` `ingresses` points at.
pub const MUTATE_INGRESSES_PATH: &str = "/mutate/v1/ingresses";
/// Path the mutating rule on `route.openshift.io/v1` `routes` points at — rendered only where
/// the configured dialect targets `Route`s.
pub const MUTATE_ROUTES_PATH: &str = "/mutate/v1/routes";
/// Path the validating rule on `ingresses` points at.
pub const VALIDATE_INGRESSES_PATH: &str = "/validate/v1/ingresses";
/// Path the validating rule on `routes` points at.
pub const VALIDATE_ROUTES_PATH: &str = "/validate/v1/routes";

/// Everything both handlers need, injected once at boot.
pub struct EndpointAuthState {
    /// The operator's own identity — row 1 of the guard table.
    pub operator_identity: String,
    /// `spec.features.endpointAuth`, hot-reloaded: the dialect, the gateway and the host
    /// patterns are read fresh per request, so changing any of them takes effect without a
    /// restart.
    pub config: Arc<RwLock<Option<EndpointAuthConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace — and the owner annotation.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `weebo_si_chassis::admit`'s `Context`; unused here.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// Both routes, merged in the composition root.
pub fn endpoint_auth_router(state: Arc<EndpointAuthState>) -> Router {
    Router::new()
        .route(MUTATE_INGRESSES_PATH, post(mutate))
        .route(MUTATE_ROUTES_PATH, post(mutate))
        .route(VALIDATE_INGRESSES_PATH, post(validate))
        .route(VALIDATE_ROUTES_PATH, post(validate))
        .with_state(state)
}

/// A routing object under admission, in the vocabulary the mutation needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingObjectWrite {
    /// Which write this is. The mutation branches on it, for the reason
    /// [`GateMutation::evaluate`] gives: on a `CREATE` it owns the managed annotations outright,
    /// and on an `UPDATE` it must not overwrite a *conflicting* value, because doing so would
    /// silently correct the edit the guard exists to refuse.
    pub operation: WriteOperation,
    /// The namespace it lives in.
    pub namespace: NamespaceName,
    /// Which routing kind — a metric label, never a branch.
    pub kind: RoutingKind,
    /// Its annotations as submitted.
    pub annotations: BTreeMap<String, String>,
    /// Its current backend, for a `ReverseProxy` dialect: `(service, port)`.
    pub backend: Option<(String, u16)>,
}

impl Subject for RoutingObjectWrite {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        self.kind.kind()
    }
}

/// The mutation: attach the gate, and normalise what the developer wrote.
pub struct GateMutation {
    config: EndpointAuthConfig,
}

impl GateMutation {
    /// Build it around the configuration read for this request.
    pub fn new(config: EndpointAuthConfig) -> Self {
        Self { config }
    }
}

impl Feature<RoutingObjectWrite> for GateMutation {
    fn id(&self) -> FeatureId {
        FeatureId::new("endpoint-auth")
    }

    fn evaluate(
        &self,
        subject: &RoutingObjectWrite,
        _ctx: &Context<'_>,
    ) -> Result<Decision<RoutingObjectWrite>, DomainError> {
        let backend = subject
            .backend
            .as_ref()
            .map(|(service, port)| (service.as_str(), *port));
        let attachment = self.config.attachment(&subject.annotations, backend);

        // **Absent means attach; present-but-different means leave it to the guard.**
        //
        // This asymmetry is the whole relationship between the two webhooks, and it was wrong in
        // the first implementation: overwriting a conflicting value made the mutation *correct* a
        // developer who prepended a middleware in front of the gate, so the validating webhook
        // never saw the tampering and row 6 of the guard table could not fire. The developer's
        // edit vanished silently and they were told nothing — which is a worse outcome than the
        // refusal RFC 0009 promises, and it is also how a guard rule quietly becomes dead code.
        //
        // On a `CREATE` there is nothing to refuse — no previous object means no gate to compare
        // against, and the guard's row 5 admits a developer's own endpoint — so there the
        // mutation does own the value outright, and an object created with a hand-written chain
        // is corrected rather than admitted ungated.
        let mut mutations: Vec<Mutation> = attachment
            .annotations
            .iter()
            .filter(|(key, value)| match subject.annotations.get(*key) {
                None => true,
                Some(present) => present != *value && subject.operation == WriteOperation::Create,
            })
            .map(|(key, value)| Mutation::Annotate {
                key: key.clone(),
                value: value.clone(),
            })
            .collect();

        if let Some(retarget) = attachment.retarget.as_ref() {
            mutations.push(Mutation::SetString {
                path: vec!["spec".into(), "to".into(), "name".into()],
                value: retarget.service.clone(),
            });
            mutations.push(Mutation::SetString {
                path: vec!["spec".into(), "port".into(), "targetPort".into()],
                value: "http".into(),
            });
        }

        // Normalising the developer's own lists is the other half of the mutation, and it is not
        // cosmetic: `"bob, bob ,"` and `"bob"` must be one delegation, or the gateway's compiled
        // policy and the annotation a developer reads back disagree about who is allowed.
        for key in [ALLOW_USERS_ANNOTATION, ALLOW_GROUPS_ANNOTATION] {
            if let Some(raw) = subject.annotations.get(key) {
                let normalised = normalise_names(raw);
                if &normalised != raw {
                    mutations.push(Mutation::Annotate {
                        key: key.to_owned(),
                        value: normalised,
                    });
                }
            }
        }

        let note = format!(
            "dialect={:?};mode={:?};annotations={}",
            self.config.gateway.dialect,
            self.config.gateway.dialect.mode(),
            attachment.annotations.len()
        );
        Ok(Decision::new(mutations, None, Some(note), "attached"))
    }
}

/// Trim, drop empties, dedupe, and keep the order the developer wrote.
fn normalise_names(raw: &str) -> String {
    let mut seen = BTreeSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter(|name| seen.insert(name.to_owned()))
        .collect::<Vec<_>>()
        .join(",")
}

fn routing_kind(request: &AdmissionRequest<DynamicObject>) -> Option<RoutingKind> {
    RoutingKind::from_plural(&request.resource.resource)
}

fn annotations_of(object: Option<&DynamicObject>) -> BTreeMap<String, String> {
    object
        .and_then(|object| object.metadata.annotations.clone())
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// The backend a `Route` points at today, which a `ReverseProxy` dialect repoints and records.
fn backend_of(object: Option<&DynamicObject>, kind: RoutingKind) -> Option<(String, u16)> {
    if kind != RoutingKind::Route {
        return None;
    }
    let data = &object?.data;
    let service = data.pointer("/spec/to/name")?.as_str()?.to_owned();
    let port = data
        .pointer("/spec/port/targetPort")
        .and_then(|port| port.as_u64())
        .unwrap_or(80) as u16;
    Some((service, port))
}

/// The hosts a routing object claims — `spec.rules[].host` on an `Ingress`, `spec.host` on a
/// `Route`.
fn hosts_of(object: Option<&DynamicObject>, kind: RoutingKind) -> Vec<String> {
    let Some(object) = object else {
        return Vec::new();
    };
    match kind {
        RoutingKind::Route => object
            .data
            .pointer("/spec/host")
            .and_then(|host| host.as_str())
            .map(|host| vec![host.to_owned()])
            .unwrap_or_default(),
        RoutingKind::Ingress => object
            .data
            .pointer("/spec/rules")
            .and_then(|rules| rules.as_array())
            .map(|rules| {
                rules
                    .iter()
                    .filter_map(|rule| rule.get("host").and_then(|host| host.as_str()))
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

async fn mutate(
    State(state): State<Arc<EndpointAuthState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return Json(
                AdmissionResponse::invalid("the AdmissionReview carried no request").into_review(),
            );
        }
    };
    let response = AdmissionResponse::from(&request);
    let (Some(kind), Some(config)) = (routing_kind(&request), read_config(&state)) else {
        return Json(response.into_review());
    };
    let object = request.object.as_ref();
    let subject = RoutingObjectWrite {
        operation: match request.operation {
            Operation::Create => WriteOperation::Create,
            Operation::Update => WriteOperation::Update,
            Operation::Delete | Operation::Connect => WriteOperation::Delete,
        },
        namespace: NamespaceName::new(request.namespace.clone().unwrap_or_default()),
        kind,
        annotations: annotations_of(object),
        backend: backend_of(object, kind),
    };

    let mut registry: Registry<RoutingObjectWrite> = Registry::new();
    registry.register(GateMutation::new(config));

    let _timer = state
        .metrics
        .timer("endpoint-auth", subject.resource())
        .start_timer();
    let outcome = weebo_si_chassis::admit(
        &registry,
        &subject,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );

    let response = match outcome {
        Ok(AdmitOutcome::Allow(mutations)) if mutations.is_empty() => response,
        Ok(AdmitOutcome::Allow(mutations)) => {
            let body = object
                .map(|object| serde_json::to_value(object).unwrap_or_default())
                .unwrap_or_default();
            let patch = render_patch(&body, &mutations);
            println!(
                "weebo-si-webhook: endpoint-auth attach namespace={} kind={} operations={}",
                subject.namespace,
                kind.kind(),
                patch.0.len()
            );
            match response.with_patch(patch) {
                Ok(response) => response,
                // A patch that cannot be serialised is a bug in this crate, never a reason to
                // let an ungated endpoint through: refusing is the fail-closed answer, and it
                // names itself so the bug is findable.
                Err(err) => AdmissionResponse::from(&request)
                    .deny(format!("endpoint-auth could not render its patch: {err}")),
            }
        }
        Ok(AdmitOutcome::Deny(reason)) => response.deny(reason),
        Err(err) => response.deny(err.to_string()),
    };
    Json(response.into_review())
}

fn read_config(state: &EndpointAuthState) -> Option<EndpointAuthConfig> {
    state
        .config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn guard_subject(
    request: &AdmissionRequest<DynamicObject>,
    kind: RoutingKind,
    config: &EndpointAuthConfig,
    namespace_owner: Option<String>,
) -> EndpointRoutingWrite {
    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let actor = request
        .user_info
        .username
        .clone()
        .unwrap_or_else(|| "<unknown>".to_string());
    let operation = match request.operation {
        Operation::Create => WriteOperation::Create,
        Operation::Update => WriteOperation::Update,
        Operation::Delete | Operation::Connect => WriteOperation::Delete,
    };
    let submitted = match operation {
        WriteOperation::Delete => request.old_object.as_ref(),
        _ => request.object.as_ref(),
    };
    let previous = request.old_object.as_ref();

    let submitted_annotations = annotations_of(submitted);
    let previous_annotations = annotations_of(previous);
    let changed_annotations = submitted_annotations
        .iter()
        .filter(|(key, value)| previous_annotations.get(*key) != Some(*value))
        .map(|(key, _)| key.clone())
        .chain(
            previous_annotations
                .keys()
                .filter(|key| !submitted_annotations.contains_key(*key))
                .cloned(),
        )
        .collect::<BTreeSet<_>>();

    // Everything outside `metadata` — the backend, the TLS block, the paths. Compared as JSON
    // because the guard's question is "did the shape the devfile projects change", not "which
    // field": a DWO-generated object's spec is edited in the devfile whatever part of it moved.
    let other_fields_changed = match (submitted, previous) {
        (Some(submitted), Some(previous)) => submitted.data != previous.data,
        _ => false,
    };

    let carries_devworkspace_label = submitted
        .and_then(|object| object.metadata.labels.as_ref())
        .is_some_and(|labels| labels.contains_key(DEVWORKSPACE_ID_LABEL));
    let previously_devworkspace = previous
        .and_then(|object| object.metadata.labels.as_ref())
        .is_some_and(|labels| labels.contains_key(DEVWORKSPACE_ID_LABEL));
    // Provenance is read from the object that *exists*, never from the one being submitted: an
    // UPDATE that adds the label is row 4's forgery, and reading the submitted object would let
    // it decide how much of itself is frozen.
    let provenance = match operation {
        WriteOperation::Create if carries_devworkspace_label => Provenance::Devfile,
        WriteOperation::Create => Provenance::Author,
        _ if previously_devworkspace => Provenance::Devfile,
        _ => Provenance::Author,
    };

    let backend = backend_of(submitted, kind);
    // **What the gate should hold is computed from the object that already exists**, never from
    // the one being submitted. Reading the proposed object here would let an `UPDATE` write
    // `hardening.weebo.io/endpoint-auth: bypass` and, in the same request, make the guard compute
    // "this endpoint expects no gate" — a one-annotation bypass performed by the person the
    // feature constrains, which is precisely row 6's job to refuse. Same reasoning as
    // `target_is_managed` in RFC 0007's registry guard, and the same failure mode if it is got
    // wrong. On a `CREATE` there is no previous object and the submitted one is all there is,
    // which is safe: a brand-new object is gated by the mutation that runs before this.
    let baseline = match operation {
        WriteOperation::Create => &submitted_annotations,
        _ => &previous_annotations,
    };
    let expected = config
        .attachment(
            baseline,
            backend
                .as_ref()
                .map(|(service, port)| (service.as_str(), *port)),
        )
        .annotations
        .into_iter()
        .map(|(key, value)| (ManagedField::Annotation(key), value))
        .collect::<BTreeMap<_, _>>();
    let submitted_managed = expected
        .keys()
        .filter_map(|field| match field {
            ManagedField::Annotation(key) => submitted_annotations
                .get(key)
                .map(|value| (field.clone(), value.clone())),
            ManagedField::Path(_) => None,
        })
        .collect::<BTreeMap<_, _>>();

    let mut expected_managed = expected;
    let mut submitted_managed = submitted_managed;
    if config.gateway.dialect.mode() == AttachmentMode::ReverseProxy {
        expected_managed.insert(
            ManagedField::Path("spec.to"),
            weebo_si_crd::COMPANION_SERVICE.to_owned(),
        );
        if let Some((service, _)) = backend {
            submitted_managed.insert(ManagedField::Path("spec.to"), service);
        }
    }

    // A host no ownership pattern ties to this namespace's owner belongs to somebody else, and
    // `None` — a write naming no host at all — is not a refusal: an `Ingress` with no host is not
    // an endpoint on its own FQDN, which is the only thing this feature governs.
    let host_owned_by_namespace = match (namespace_owner, hosts_of(submitted, kind)) {
        (_, hosts) if hosts.is_empty() => None,
        (Some(owner), hosts) => Some(
            hosts
                .iter()
                .all(|host| config.hosts.owner_of(host).as_deref() == Some(owner.as_str())),
        ),
        (None, _) => Some(false),
    };

    EndpointRoutingWrite {
        namespace,
        actor,
        operation,
        kind,
        provenance,
        changed_annotations,
        other_fields_changed,
        expected_managed,
        submitted_managed,
        carries_devworkspace_label,
        host_owned_by_namespace,
    }
}

/// Compile the developer's annotations the way the gateway will, and report what it says.
///
/// **The same function, not an equivalent one.** RFC 0009 promises a developer that "an
/// unparseable list, an ungranted key, or a rule whose `access` is `open` when the team holds no
/// `open` grant is rejected with the reason, not silently dropped" — and a second implementation
/// of that check in the webhook would be a second answer to the same question, which is the
/// class of bug where admission accepts what the gate then refuses.
fn compile_error(
    config: &EndpointAuthConfig,
    annotations: &BTreeMap<String, String>,
    namespace: &NamespaceName,
    owner: Option<&str>,
    team: Option<&weebo_si_crd::TeamName>,
) -> Option<String> {
    use weebo_si_endpoint_auth::compile::{
        Catalogue, CompileSettings, Grant, RawEndpoint, UnknownKey, compile,
    };
    use weebo_si_endpoint_auth::policy::{CatalogueKey, Delegation};

    // Nothing written, nothing to validate. A developer who annotated nothing gets their team's
    // default and no opinion from this function.
    if DEVELOPER_ANNOTATIONS
        .iter()
        .all(|key| !annotations.contains_key(*key))
    {
        return None;
    }

    let catalogue = Catalogue::new(config.catalog.iter().map(|entry| {
        (
            CatalogueKey::new(entry.key.as_str()),
            entry.anonymous,
            entry
                .delegation
                .iter()
                .map(|kind| match kind {
                    weebo_si_crd::DelegationKind::Team => Delegation::Team,
                    weebo_si_crd::DelegationKind::UsersAndGroups => Delegation::UsersAndGroups,
                })
                .collect(),
        )
    }))
    .ok()?;
    let granted = config.grant_for(team);
    let grant = Grant {
        allowed: granted
            .allowed
            .iter()
            .map(|key| CatalogueKey::new(key.as_str()))
            .collect(),
        default: CatalogueKey::new(granted.default.as_str()),
    };
    let raw = RawEndpoint {
        namespace: weebo_si_endpoint_auth::identity::NamespaceName::new(namespace.as_str()),
        owner: weebo_si_endpoint_auth::identity::Username::new(owner.unwrap_or_default()),
        team: team.map(|team| weebo_si_endpoint_auth::identity::TeamName::new(team.as_str())),
        access: annotations.get(ACCESS_ANNOTATION).cloned(),
        allow_users: annotations.get(ALLOW_USERS_ANNOTATION).cloned(),
        allow_groups: annotations.get(ALLOW_GROUPS_ANNOTATION).cloned(),
        rules: annotations.get(RULES_ANNOTATION).cloned(),
        upstream: None,
        provenance: weebo_si_endpoint_auth::policy::Provenance::Author,
    };
    let settings = CompileSettings {
        foreign_bearer: weebo_si_endpoint_auth::policy::BearerMode::Reject,
        max_rules: 16,
        // Admission is stricter than the gateway on exactly one point, and deliberately: at
        // *runtime* an unknown key falls to the team's default, because an endpoint that stops
        // answering is worse than one that is more closed than its author meant. At *admission*
        // there is a person watching, so a key nobody defined is a typo worth naming.
        on_unknown_key: UnknownKey::Deny,
    };
    compile(&raw, &catalogue, &grant, &[], &settings, 0)
        .err()
        .map(|err| err.to_string())
}

async fn validate(
    State(state): State<Arc<EndpointAuthState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
) -> Json<AdmissionReview<DynamicObject>> {
    let request: AdmissionRequest<DynamicObject> = match review.try_into() {
        Ok(request) => request,
        Err(_) => {
            return Json(
                AdmissionResponse::invalid("the AdmissionReview carried no request").into_review(),
            );
        }
    };
    let response = AdmissionResponse::from(&request);
    let (Some(kind), Some(config)) = (routing_kind(&request), read_config(&state)) else {
        return Json(response.into_review());
    };

    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let namespace_owner_name = state
        .namespace_view
        .annotation(&namespace, &config.owner.namespace_annotation);
    // The namespace's team, resolved the same way every other feature resolves one: ordered,
    // first match wins, against the labels the namespace carries.
    let team = state
        .namespace_view
        .facts(&namespace)
        .and_then(|facts| {
            state
                .gate
                .teams()
                .into_iter()
                .find(|team| team.namespace_selector.matches(&facts.labels))
        })
        .map(|team| team.name);
    let write = guard_subject(&request, kind, &config, namespace_owner_name.clone());

    let mut registry: Registry<EndpointRoutingWrite> = Registry::new();
    registry.register(EndpointRoutingGuard::new(
        state.operator_identity.clone(),
        config.owner.devworkspace_operator_identity.clone(),
        config.break_glass_identities.clone(),
    ));

    let _timer = state
        .metrics
        .timer("endpoint-auth", write.resource())
        .start_timer();
    let outcome = weebo_si_chassis::admit(
        &registry,
        &write,
        state.gate.as_ref(),
        state.namespace_view.as_ref(),
        state.dwoc_catalog.as_ref(),
        state.observer.as_ref(),
    );

    let response = match outcome {
        Ok(AdmitOutcome::Allow(_)) => {
            // The guard said yes; the developer's own annotations still have to mean something.
            // Only on a write that is not a delete, and only in `Enforce` — a `DryRun` must not
            // refuse anything, which is the chassis's rule rather than this feature's.
            let refusal = (write.operation != WriteOperation::Delete
                && state.gate.mode(
                    weebo_si_chassis::FeatureId::new("endpoint-auth"),
                    &namespace,
                ) == weebo_si_crd::FeatureMode::Enforce)
                .then(|| {
                    compile_error(
                        &config,
                        &annotations_of(request.object.as_ref()),
                        &namespace,
                        namespace_owner_name.as_deref(),
                        team.as_ref(),
                    )
                })
                .flatten();
            match refusal {
                Some(reason) => {
                    println!(
                        "weebo-si-webhook: endpoint-auth deny namespace={namespace} actor={} \
                         kind={} reason=unusable_annotations",
                        write.actor,
                        kind.kind()
                    );
                    response.deny(format!(
                        "the endpoint-auth annotations on this {} are not usable: {reason}",
                        kind.kind()
                    ))
                }
                None => response,
            }
        }
        Ok(AdmitOutcome::Deny(reason)) => {
            println!(
                "weebo-si-webhook: endpoint-auth deny namespace={} actor={} kind={} operation={:?} reason={reason}",
                write.namespace,
                write.actor,
                kind.kind(),
                write.operation
            );
            response.deny(reason)
        }
        Err(err) => response.deny(err.to_string()),
    };
    Json(response.into_review())
}

/// The developer annotations this mutation normalises rather than rewrites — re-exported so the
/// controller's sweep and the conformance suite name the same list.
pub const NORMALISED_ANNOTATIONS: [&str; 4] = DEVELOPER_ANNOTATIONS;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use serde_json::json;
    use weebo_si_crd::{
        AccessEntry, AccessKey, DelegationKind, Dialect, ENDPOINT_AUTH_ANNOTATION,
        EndpointSelection, FeatureMode, GateEnforcement, GatewayRef, HostOwnership, HostsConfig,
        OwnerConfig, SelfOriginConfig, ServiceRef,
    };

    use super::*;

    fn config(dialect: Dialect) -> EndpointAuthConfig {
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
                dialect,
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
            catalog: vec![
                AccessEntry {
                    key: AccessKey::new("private"),
                    anonymous: false,
                    delegation: Vec::new(),
                },
                AccessEntry {
                    key: AccessKey::new("shared"),
                    anonymous: false,
                    delegation: vec![DelegationKind::Team, DelegationKind::UsersAndGroups],
                },
            ],
            default: AccessKey::new("private"),
            overrides: Vec::new(),
            endpoint_selection: EndpointSelection::default(),
            self_origin: SelfOriginConfig::default(),
            grants: BTreeMap::new(),
        }
    }

    fn ingress(annotations: serde_json::Value, host: &str) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": { "name": "api", "namespace": "user-alice", "annotations": annotations },
            "spec": { "rules": [ { "host": host } ] }
        }))
        .unwrap()
    }

    fn mutations_for(object: &DynamicObject, config: &EndpointAuthConfig) -> Vec<Mutation> {
        mutations_on(object, config, WriteOperation::Create)
    }

    fn mutations_on(
        object: &DynamicObject,
        config: &EndpointAuthConfig,
        operation: WriteOperation,
    ) -> Vec<Mutation> {
        let subject = RoutingObjectWrite {
            operation,
            namespace: NamespaceName::new("user-alice"),
            kind: RoutingKind::Ingress,
            annotations: annotations_of(Some(object)),
            backend: None,
        };
        let facts = weebo_si_chassis::NamespaceFacts {
            labels: Default::default(),
            selection_annotation: None,
        };
        let catalog = weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog::new([]);
        let ctx = Context::new(&[], &facts, &catalog);
        GateMutation::new(config.clone())
            .evaluate(&subject, &ctx)
            .unwrap()
            .mutations
    }

    #[test]
    fn the_mutation_attaches_the_dialects_annotations_and_the_managed_marker() {
        let object = ingress(json!({}), "alice-ws-api.weebo.si");
        let mutations = mutations_for(&object, &config(Dialect::Traefik));
        let annotated: BTreeMap<String, String> = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                Mutation::Annotate { key, value } => Some((key.clone(), value.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(annotated[ENDPOINT_AUTH_ANNOTATION], "managed");
        assert!(annotated.contains_key("traefik.ingress.kubernetes.io/router.middlewares"));
    }

    #[test]
    fn the_mutation_is_idempotent_so_reinvocation_costs_nothing() {
        let config = config(Dialect::Traefik);
        let first = mutations_for(&ingress(json!({}), "alice-ws-api.weebo.si"), &config);
        let applied: serde_json::Value = first
            .iter()
            .filter_map(|mutation| match mutation {
                Mutation::Annotate { key, value } => Some((key.clone(), json!(value))),
                _ => None,
            })
            .collect::<serde_json::Map<_, _>>()
            .into();
        let second = mutations_for(&ingress(applied, "alice-ws-api.weebo.si"), &config);
        assert!(second.is_empty(), "{second:?}");
    }

    #[test]
    fn break_glass_is_honoured_by_attaching_nothing() {
        let object = ingress(
            json!({ ENDPOINT_AUTH_ANNOTATION: "bypass" }),
            "alice-ws-api.weebo.si",
        );
        assert!(mutations_for(&object, &config(Dialect::Traefik)).is_empty());
    }

    #[test]
    fn the_developers_own_lists_are_normalised_rather_than_rewritten() {
        let object = ingress(
            json!({ ALLOW_USERS_ANNOTATION: " bob , bob ,, carol " }),
            "alice-ws-api.weebo.si",
        );
        let mutations = mutations_for(&object, &config(Dialect::Traefik));
        let normalised = mutations.iter().find_map(|mutation| match mutation {
            Mutation::Annotate { key, value } if key == ALLOW_USERS_ANNOTATION => Some(value),
            _ => None,
        });
        assert_eq!(normalised.map(String::as_str), Some("bob,carol"));
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_reverse_proxy_dialect_repoints_the_backend_and_records_it() {
        let route: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "metadata": { "name": "api", "namespace": "user-alice" },
            "spec": { "host": "alice-ws-api.weebo.si", "to": { "kind": "Service", "name": "my-app" } }
        }))
        .unwrap();
        let subject = RoutingObjectWrite {
            operation: WriteOperation::Create,
            namespace: NamespaceName::new("user-alice"),
            kind: RoutingKind::Route,
            annotations: BTreeMap::new(),
            backend: backend_of(Some(&route), RoutingKind::Route),
        };
        let facts = weebo_si_chassis::NamespaceFacts {
            labels: Default::default(),
            selection_annotation: None,
        };
        let catalog = weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog::new([]);
        let ctx = Context::new(&[], &facts, &catalog);
        let mutations = GateMutation::new(config(Dialect::OpenShiftRoute))
            .evaluate(&subject, &ctx)
            .unwrap()
            .mutations;
        assert!(mutations.contains(&Mutation::SetString {
            path: vec!["spec".into(), "to".into(), "name".into()],
            value: weebo_si_crd::COMPANION_SERVICE.to_owned(),
        }));
        assert!(mutations.iter().any(|mutation| matches!(
            mutation,
            Mutation::Annotate { key, value } if key == weebo_si_crd::UPSTREAM_ANNOTATION && value == "my-app:80"
        )));
    }

    #[test]
    fn a_host_another_namespace_owns_is_refused_and_a_hostless_object_is_not_judged() {
        let config = config(Dialect::Traefik);
        let object = ingress(json!({}), "bob-ws-api.weebo.si");
        let request = request_for(&object, Operation::Create, "alice");
        let write = guard_subject(
            &request,
            RoutingKind::Ingress,
            &config,
            Some("alice".into()),
        );
        assert_eq!(write.host_owned_by_namespace, Some(false));

        let hostless: DynamicObject = serde_json::from_value(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": { "name": "api", "namespace": "user-alice" },
            "spec": { "rules": [ { "http": {} } ] }
        }))
        .unwrap();
        let request = request_for(&hostless, Operation::Create, "alice");
        let write = guard_subject(
            &request,
            RoutingKind::Ingress,
            &config,
            Some("alice".into()),
        );
        assert_eq!(write.host_owned_by_namespace, None);
    }

    #[test]
    fn an_unusable_rule_list_is_refused_at_admission_with_the_reason() {
        // RFC 0009 promises a developer this is "rejected with the reason, not silently dropped".
        let config = config(Dialect::Traefik);
        let namespace = NamespaceName::new("user-alice");

        let unparseable = BTreeMap::from([(
            RULES_ANNOTATION.to_owned(),
            "this is not a list of rules".to_owned(),
        )]);
        let refusal = compile_error(&config, &unparseable, &namespace, Some("alice"), None);
        assert!(
            refusal.is_some_and(|why| why.contains("rules did not parse")),
            "unparseable"
        );

        // A key the *catalogue* does not define is a typo, and admission is where a person is
        // watching.
        let unknown = BTreeMap::from([(ACCESS_ANNOTATION.to_owned(), "shard".to_owned())]);
        assert!(compile_error(&config, &unknown, &namespace, Some("alice"), None).is_some());

        // A key the catalogue defines but this namespace's grant does not reach.
        let ungranted = BTreeMap::from([(ACCESS_ANNOTATION.to_owned(), "shared".to_owned())]);
        let refusal = compile_error(&config, &ungranted, &namespace, Some("alice"), None);
        assert!(
            refusal.is_some_and(|why| why.contains("not granted")),
            "a namespace in no team reaches only the cluster default"
        );
    }

    #[test]
    fn annotations_that_are_fine_are_not_an_opinion() {
        let config = config(Dialect::Traefik);
        let namespace = NamespaceName::new("user-alice");
        // The cluster default, which every namespace reaches.
        let allowed = BTreeMap::from([
            (ACCESS_ANNOTATION.to_owned(), "private".to_owned()),
            (ALLOW_USERS_ANNOTATION.to_owned(), "bob,carol".to_owned()),
        ]);
        assert_eq!(
            compile_error(&config, &allowed, &namespace, Some("alice"), None),
            None
        );
        // And an object with none of our annotations is never judged at all.
        assert_eq!(
            compile_error(&config, &BTreeMap::new(), &namespace, Some("alice"), None),
            None
        );
    }

    #[test]
    fn an_update_that_tampers_with_the_chain_is_left_for_the_guard_to_refuse() {
        // The mutation must not be the thing that "fixes" this: correcting it silently would
        // discard the developer's edit without telling them, and would make the guard's row 6
        // unreachable — a rule that cannot fire is a rule nobody notices has stopped working.
        let config = config(Dialect::Traefik);
        let tampered = ingress(
            json!({
                ENDPOINT_AUTH_ANNOTATION: "managed",
                "traefik.ingress.kubernetes.io/router.middlewares":
                    "user-alice-rewrite@kubernetescrd,weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd",
            }),
            "alice-ws-api.weebo.si",
        );
        assert!(
            mutations_on(&tampered, &config, WriteOperation::Update).is_empty(),
            "an UPDATE carrying a conflicting chain must be left alone"
        );
        // ...and on a CREATE there is no previous gate to compare against, so the mutation does
        // own the value: an object created with a hand-written chain is corrected, never admitted
        // ungated.
        let corrected = mutations_on(&tampered, &config, WriteOperation::Create);
        assert!(corrected.iter().any(|mutation| matches!(
            mutation,
            Mutation::Annotate { key, value }
                if key == "traefik.ingress.kubernetes.io/router.middlewares"
                    && value == "weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd"
        )));
    }

    #[test]
    fn an_annotation_dwo_dropped_is_put_back_on_an_update() {
        // The self-healing half: DevWorkspace Operator rewrites these objects on its own
        // schedule, and if it uses Update rather than apply, its write drops what we added.
        // Absent is not a conflict, so this one *is* the mutation's business.
        let config = config(Dialect::Traefik);
        let stripped = ingress(json!({}), "alice-ws-api.weebo.si");
        assert!(!mutations_on(&stripped, &config, WriteOperation::Update).is_empty());
    }

    #[test]
    fn writing_bypass_does_not_make_the_guard_forget_what_the_gate_should_be() {
        // The one-annotation bypass: flip `endpoint-auth` to `bypass` and, if the guard computed
        // what it expects from the *submitted* object, it would compute "nothing" and allow it.
        let config = config(Dialect::Traefik);
        let gated = ingress(
            json!({
                ENDPOINT_AUTH_ANNOTATION: "managed",
                "traefik.ingress.kubernetes.io/router.middlewares":
                    "weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd",
            }),
            "alice-ws-api.weebo.si",
        );
        let bypassing = ingress(
            json!({ ENDPOINT_AUTH_ANNOTATION: "bypass" }),
            "alice-ws-api.weebo.si",
        );
        let mut request = request_for(&bypassing, Operation::Update, "alice");
        request.old_object = Some(gated);

        let write = guard_subject(
            &request,
            RoutingKind::Ingress,
            &config,
            Some("alice".into()),
        );
        assert!(
            !write.tampered().is_empty(),
            "the guard must still expect the gate the existing object carries"
        );
    }

    #[test]
    fn provenance_is_read_from_the_object_that_already_exists() {
        // An UPDATE that *adds* the DevWorkspace label must not thereby become a devfile
        // projection: that is row 4's forgery, and reading the submitted object would let the
        // write decide how much of itself is frozen.
        let config = config(Dialect::Traefik);
        let mut submitted = ingress(json!({}), "alice-ws-api.weebo.si");
        submitted.metadata.labels = Some(
            [(DEVWORKSPACE_ID_LABEL.to_owned(), "ws-1".to_owned())]
                .into_iter()
                .collect(),
        );
        let existing = ingress(json!({}), "alice-ws-api.weebo.si");
        let mut request = request_for(&submitted, Operation::Update, "alice");
        request.old_object = Some(existing);
        let write = guard_subject(
            &request,
            RoutingKind::Ingress,
            &config,
            Some("alice".into()),
        );
        assert_eq!(write.provenance, Provenance::Author);
        assert!(write.carries_devworkspace_label);
    }

    fn request_for(
        object: &DynamicObject,
        operation: Operation,
        actor: &str,
    ) -> AdmissionRequest<DynamicObject> {
        let review: AdmissionReview<DynamicObject> = serde_json::from_value(json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "test",
                "kind": { "group": "networking.k8s.io", "version": "v1", "kind": "Ingress" },
                "resource": { "group": "networking.k8s.io", "version": "v1", "resource": "ingresses" },
                "name": "api",
                "namespace": "user-alice",
                "operation": match operation {
                    Operation::Create => "CREATE",
                    Operation::Update => "UPDATE",
                    Operation::Delete => "DELETE",
                    Operation::Connect => "CONNECT",
                },
                "userInfo": { "username": actor },
                "object": object,
            }
        }))
        .unwrap();
        review.try_into().unwrap()
    }
}
