//! The `policy-guard` validating admission adapter: `AdmissionReview` in, allow/deny out — never
//! a patch, since `policy-guard` never mutates. See RFC 0004's *Design → Contract*, `policyGuard`.

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
use weebo_si_chassis::{AdmitOutcome, Registry};
use weebo_si_crd::{MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, PolicyGuardConfig};
use weebo_si_network_profiles::{NetworkPolicyOperation, NetworkPolicyWrite, PolicyGuard};

use crate::metrics::WebhookMetrics;

/// Path both `networkpolicies` and (where the backend is enabled) `ciliumnetworkpolicies` rules
/// point at — one handler, resource-agnostic, per RFC 0004's *Design → Contract*: "the webhook
/// path... are the contract."
pub const VALIDATE_NETWORK_POLICIES_PATH: &str = "/validate/v1/networkpolicies";

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
pub fn policy_guard_router(state: Arc<PolicyGuardState>) -> Router {
    Router::new()
        .route(
            VALIDATE_NETWORK_POLICIES_PATH,
            post(validate_network_policies),
        )
        .with_state(state)
}

fn network_policy_write_from_request(
    request: &AdmissionRequest<DynamicObject>,
) -> NetworkPolicyWrite {
    let namespace = NamespaceName::new(request.namespace.clone().unwrap_or_default());
    let actor = request
        .user_info
        .username
        .clone()
        .unwrap_or_else(|| "<unknown>".to_string());
    let operation = match request.operation {
        Operation::Create => NetworkPolicyOperation::Create,
        Operation::Update => NetworkPolicyOperation::Update,
        Operation::Delete | Operation::Connect => NetworkPolicyOperation::Delete,
    };

    // The *existing* object is what tells us whether the target is already ours — reading the
    // proposed `object` here would let an UPDATE strip the label in the same request that
    // bypasses the check it protects. `object` (not `old_object`) is correct only for CREATE,
    // where there is no existing object and the target can never already be managed.
    let existing = match operation {
        NetworkPolicyOperation::Create => None,
        _ => request.old_object.as_ref(),
    };
    let target_is_managed = existing
        .and_then(|obj| obj.metadata.labels.as_ref())
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE);

    NetworkPolicyWrite {
        namespace,
        actor,
        operation,
        target_is_managed,
    }
}

fn log_decision(write: &NetworkPolicyWrite, denial: Option<&str>) {
    match denial {
        Some(reason) => println!(
            "weebo-si-webhook: policy-guard deny namespace={} actor={} operation={:?} reason={reason}",
            write.namespace, write.actor, write.operation
        ),
        None => println!(
            "weebo-si-webhook: policy-guard allow namespace={} actor={} operation={:?}",
            write.namespace, write.actor, write.operation
        ),
    }
}

async fn validate_network_policies(
    State(state): State<Arc<PolicyGuardState>>,
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
    let write = network_policy_write_from_request(&request);

    let allowed_identities = state
        .policy_guard_config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|config| config.allowed_identities.clone())
        .unwrap_or_default();
    let mut registry: Registry<NetworkPolicyWrite> = Registry::new();
    registry.register(PolicyGuard::new(
        state.operator_identity.clone(),
        allowed_identities,
    ));

    let _timer = state
        .metrics
        .timer("policy-guard", "NetworkPolicy")
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
