//! The `policy-guard` validating admission adapter: `AdmissionReview` in, allow/deny out — never
//! a patch, since `policy-guard` never mutates. See RFC 0004's *Design → Contract*, `policyGuard`,
//! and RFC 0008 for the extension to `kubearmorpolicies`.
//!
//! **One handler, two paths.** The handler is resource-agnostic — it reads which resource the
//! request is against from the request's own `resource` field and hands it to the domain as a
//! [`GuardedResource`], which the verdict never branches on. The paths are separate because a
//! path named `networkpolicies` that also decides KubeArmor writes is a lie a future reader has
//! to discover, and — more concretely — a separate `ValidatingWebhookConfiguration` rule can be
//! gated on `kubearmorPolicy.rbac.enabled` and carry its own `failurePolicy` without touching
//! the rule that protects the network baseline.

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
use weebo_si_chassis::{AdmitOutcome, Registry, Subject};
use weebo_si_crd::{MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, PolicyGuardConfig};
use weebo_si_policy_guard::{GuardedResource, GuardedWrite, PolicyGuard, WriteOperation};

use crate::metrics::WebhookMetrics;

/// Path both `networkpolicies` and (where the backend is enabled) `ciliumnetworkpolicies` rules
/// point at — one handler, resource-agnostic, per RFC 0004's *Design → Contract*: "the webhook
/// path... are the contract."
pub const VALIDATE_NETWORK_POLICIES_PATH: &str = "/validate/v1/networkpolicies";

/// Path the `kubearmorpolicies` rule points at — RFC 0008's *A second webhook path, not a second
/// rule on the first*. Served by the same handler as [`VALIDATE_NETWORK_POLICIES_PATH`].
pub const VALIDATE_KUBEARMOR_POLICIES_PATH: &str = "/validate/v1/kubearmorpolicies";

/// Everything the handler needs, injected once at boot — the composition root is the only place
/// naming concrete adapters, per `docs/architecture/hexagonal.md`.
pub struct PolicyGuardState {
    /// The full `system:serviceaccount:<ns>:<name>` identity of `weebo-si-controller` — the only
    /// writer this guard must never lock out. Static per deployment, unlike `allowedIdentities`.
    pub operator_identity: String,
    /// `spec.features.policyGuard`, hot-reloaded — read fresh on every request so
    /// `allowedIdentities` and `mode` take effect without a restart.
    pub policy_guard_config: Arc<RwLock<Option<PolicyGuardConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Whether a resolved DWOC reference exists — unused by `PolicyGuard` itself, required
    /// structurally by `weebo_si_chassis::admit`'s `Context`.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// The `policy-guard` router. Merged with `dwoc-pin`'s in the composition root — see
/// `weebo-si-operator webhook`.
///
/// Both paths route to the same handler. A deployment whose chart did not render the KubeArmor
/// rule simply never receives a request on the second one; serving a path no rule points at
/// costs nothing and keeps the two roles' wiring identical.
///
/// Each route passes its own path constant through, so
/// `weebo_si_admission_unguarded_total{path=...}` names the route a drifted rule was registered
/// against. The value is the router's own `&'static str`, not anything read off the request.
pub fn policy_guard_router(state: Arc<PolicyGuardState>) -> Router {
    Router::new()
        .route(
            VALIDATE_NETWORK_POLICIES_PATH,
            post(
                |state: State<Arc<PolicyGuardState>>,
                 review: Json<AdmissionReview<DynamicObject>>| async move {
                    validate_policies(state, review, VALIDATE_NETWORK_POLICIES_PATH).await
                },
            ),
        )
        .route(
            VALIDATE_KUBEARMOR_POLICIES_PATH,
            post(
                |state: State<Arc<PolicyGuardState>>,
                 review: Json<AdmissionReview<DynamicObject>>| async move {
                    validate_policies(state, review, VALIDATE_KUBEARMOR_POLICIES_PATH).await
                },
            ),
        )
        .with_state(state)
}

fn guarded_write_from_request(
    request: &AdmissionRequest<DynamicObject>,
    resource: GuardedResource,
) -> GuardedWrite {
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

    // The *existing* object is what tells us whether the target is already ours — reading the
    // proposed `object` here would let an UPDATE strip the label in the same request that
    // bypasses the check it protects. `object` (not `old_object`) is correct only for CREATE,
    // where there is no existing object and the target can never already be managed.
    let existing = match operation {
        WriteOperation::Create => None,
        _ => request.old_object.as_ref(),
    };
    let target_is_managed = existing
        .and_then(|obj| obj.metadata.labels.as_ref())
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE);

    GuardedWrite {
        namespace,
        actor,
        operation,
        target_is_managed,
        resource,
    }
}

/// Logs one request this handler allowed without deciding anything, because it does not know the
/// resource. Pairs with `weebo_si_admission_unguarded_total`: the counter says drift is
/// happening, this says *what* drifted.
///
/// **The unrecognised plural is logged, never labelled.** Nothing authenticates the caller of an
/// admission endpoint, so any pod that can dial the webhook Service can put an arbitrary string
/// in `resource`. In a metric label that mints unbounded series on demand; in a log line, beside
/// the actor and namespace that are equally caller-shaped, it is just a string.
///
/// `WARN`, because there is no benign steady state for this: the routes are ours and the rules
/// are the chart's, so a request arriving here for a resource the enum does not carry means the
/// two disagree.
fn log_unguarded(request: &AdmissionRequest<DynamicObject>, path: &'static str) {
    println!(
        "WARN weebo-si-webhook: policy-guard allow-unguarded path={path} group={} resource={} \
         namespace={} operation={:?} reason=resource_not_guarded — a webhook rule routes this \
         resource here but GuardedResource has no variant for it; the write was NOT checked",
        request.resource.group,
        request.resource.resource,
        request.namespace.clone().unwrap_or_default(),
        request.operation,
    );
}

fn log_decision(write: &GuardedWrite, denial: Option<&str>) {
    match denial {
        Some(reason) => println!(
            "weebo-si-webhook: policy-guard deny namespace={} actor={} resource={} operation={:?} reason={reason}",
            write.namespace, write.actor, write.resource, write.operation
        ),
        None => println!(
            "weebo-si-webhook: policy-guard allow namespace={} actor={} resource={} operation={:?}",
            write.namespace, write.actor, write.resource, write.operation
        ),
    }
}

async fn validate_policies(
    State(state): State<Arc<PolicyGuardState>>,
    Json(review): Json<AdmissionReview<DynamicObject>>,
    path: &'static str,
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
    // Which resource this is, read from the request rather than from which path it arrived on:
    // the rules and the routes are configured separately, and the request is the only source
    // that cannot drift from what the apiserver actually sent.
    //
    // `None` — a resource no rule this handler serves lists — is **allowed**, per
    // `GuardedResource::from_plural`'s own doc: the guard protects objects this operator wrote,
    // and it did not write that one.
    //
    // Counted and logged rather than allowed silently. Allowing is right; being *invisible*
    // while doing it was not, because this branch returns before the timer, before `admit()`
    // and before `log_decision`, so the one configuration that makes it dangerous — a rule
    // routing a fourth resource here while this enum has three — produced no metric and no log
    // line to distinguish it from a resource nobody was writing.
    let Some(resource) = GuardedResource::from_plural(&request.resource.resource) else {
        state.metrics.unguarded("policy-guard", path);
        log_unguarded(&request, path);
        return Json(response.into_review());
    };
    let write = guarded_write_from_request(&request, resource);

    let allowed_identities = state
        .policy_guard_config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|config| config.allowed_identities.clone())
        .unwrap_or_default();
    let mut registry: Registry<GuardedWrite> = Registry::new();
    registry.register(PolicyGuard::new(
        state.operator_identity.clone(),
        allowed_identities,
    ));

    let _timer = state
        .metrics
        .timer("policy-guard", write.resource())
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
            log_decision(&write, None);
            response
        }
        Ok(AdmitOutcome::Deny(reason)) => {
            log_decision(&write, Some(&reason));
            response.deny(reason)
        }
        Err(err) => {
            let reason = err.to_string();
            log_decision(&write, Some(&reason));
            response.deny(reason)
        }
    };

    Json(response.into_review())
}
