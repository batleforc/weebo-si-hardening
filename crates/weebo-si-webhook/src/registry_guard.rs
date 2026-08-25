//! The registry half of `policy-guard`'s validating admission adapter: `AdmissionReview` in,
//! allow/deny out — never a patch. See RFC 0007's *`policy-guard` covers these objects too*.
//!
//! **A separate path from `/validate/v1/networkpolicies`, not a second rule on it**, per that
//! RFC: "a separate path rather than a second rule on the network one so the two can be enabled
//! independently." They also differ in two ways a shared path could not express — an
//! `objectSelector` on the ownership label, and `failurePolicy: Ignore` — both argued in the
//! chart template that renders them.
//!
//! The verdict logic is [`weebo_si_registry_config::RegistryGuard`]'s, which is the same
//! three-row table [`weebo_si_policy_guard::PolicyGuard`] applies minus its unmanaged-`CREATE`
//! row.
//! See that type's own module doc for why the absence is load-bearing rather than an omission.

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
use weebo_si_crd::{
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, PolicyGuardConfig, SourceKind,
};
use weebo_si_registry_config::{RegistryGuard, RegistryObjectWrite, WriteOperation};

use crate::metrics::WebhookMetrics;

/// Path the `configmaps`/`secrets` rule points at — one handler, resource-agnostic, per RFC
/// 0007's *Design → Contract*.
pub const VALIDATE_REGISTRY_CONFIGS_PATH: &str = "/validate/v1/registryconfigs";

/// Everything the handler needs, injected once at boot — the composition root is the only place
/// naming concrete adapters, per `docs/architecture/hexagonal.md`.
///
/// Deliberately the same shape as [`crate::policy_guard::PolicyGuardState`] and reading the same
/// `policyGuard` configuration handle: one `mode` and one `allowedIdentities` govern every guard
/// rule this operator serves, which is what makes "turn the guard off" a single edit rather than
/// a hunt.
pub struct RegistryGuardState {
    /// The full `system:serviceaccount:<ns>:<name>` identity of `weebo-si-controller` — the only
    /// writer this guard must never lock out.
    pub operator_identity: String,
    /// `spec.features.policyGuard`, hot-reloaded — read fresh on every request so
    /// `allowedIdentities` and `mode` take effect without a restart.
    pub policy_guard_config: Arc<RwLock<Option<PolicyGuardConfig>>>,
    /// Which features are active, in which mode, for which namespace.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// The labels and selection annotation of a namespace.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `weebo_si_chassis::admit`'s `Context`; unused by this guard.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// Counters and decision events.
    pub observer: Arc<dyn Observer + Send + Sync>,
    /// `weebo_si_admission_duration_seconds`.
    pub metrics: WebhookMetrics,
}

/// The registry guard's router. Merged with the others' in the composition root — see
/// `weebo-si-operator webhook`.
pub fn registry_guard_router(state: Arc<RegistryGuardState>) -> Router {
    Router::new()
        .route(
            VALIDATE_REGISTRY_CONFIGS_PATH,
            post(validate_registry_configs),
        )
        .with_state(state)
}

/// Which kind the request is against, read from the admission request's own `resource` rather
/// than guessed.
///
/// `None` for anything that is neither — the rule this handler serves lists exactly two
/// resources, so a third arriving means the webhook configuration and this code disagree, and
/// **allowing** is the right answer: this guard's whole job is to protect objects this operator
/// wrote, and it did not write that one.
fn kind_of(request: &AdmissionRequest<DynamicObject>) -> Option<SourceKind> {
    match request.resource.resource.as_str() {
        "configmaps" => Some(SourceKind::ConfigMap),
        "secrets" => Some(SourceKind::Secret),
        _ => None,
    }
}

fn write_from_request(
    request: &AdmissionRequest<DynamicObject>,
    kind: SourceKind,
) -> RegistryObjectWrite {
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
    //
    // Kubernetes evaluates the rule's `objectSelector` against both the old and the new object on
    // an UPDATE and calls the webhook if *either* matches, so a request that strips the label
    // still reaches this handler — and `old_object` still carries it. That is what makes the
    // selector an optimisation rather than an escape hatch.
    let existing = match operation {
        WriteOperation::Create => None,
        _ => request.old_object.as_ref(),
    };
    let target_is_managed = existing
        .and_then(|object| object.metadata.labels.as_ref())
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE);

    RegistryObjectWrite {
        namespace,
        actor,
        operation,
        kind,
        target_is_managed,
    }
}

/// Logs one decision — the namespace, the actor, the operation and the kind.
///
/// **Never the object, and never its name's contents.** RFC 0007's *Security considerations*:
/// logs carry "the namespace, team, key, source kind and object name — never a key of `data`,
/// never a value, and never a content diff." The signature is the enforcement: there is no
/// parameter here a caller could pass the admitted object through, which matters more on this
/// route than any other in this crate, because half the objects it sees are `Secret`s.
/// The counterpart of [`crate::policy_guard`]'s own `log_unguarded`, and it obeys this route's
/// stricter rule about what may be logged: the resource *name* and group, never the object.
/// `kind_of` returned `None`, so there is no `RegistryObjectWrite` and nothing here could reach
/// a `ConfigMap`'s or a `Secret`'s payload even by accident.
fn log_unguarded(request: &AdmissionRequest<DynamicObject>) {
    println!(
        "WARN weebo-si-webhook: policy-guard allow-unguarded path={VALIDATE_REGISTRY_CONFIGS_PATH} \
         group={} resource={} namespace={} operation={:?} reason=resource_not_guarded — a webhook \
         rule routes this resource here but this handler only knows configmaps and secrets; the \
         write was NOT checked",
        request.resource.group,
        request.resource.resource,
        request.namespace.clone().unwrap_or_default(),
        request.operation,
    );
}

fn log_decision(write: &RegistryObjectWrite, denial: Option<&str>) {
    match denial {
        Some(reason) => println!(
            "weebo-si-webhook: policy-guard deny namespace={} actor={} kind={} operation={:?} \
             reason={reason}",
            write.namespace, write.actor, write.kind, write.operation
        ),
        None => println!(
            "weebo-si-webhook: policy-guard allow namespace={} actor={} kind={} operation={:?}",
            write.namespace, write.actor, write.kind, write.operation
        ),
    }
}

async fn validate_registry_configs(
    State(state): State<Arc<RegistryGuardState>>,
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
    // Same branch, same argument and the same instrumentation as
    // [`crate::policy_guard`]'s: allowing is right, allowing *silently* was not. This one
    // matters at least as much — a drifted rule here means an unchecked write to a `Secret`.
    let Some(kind) = kind_of(&request) else {
        state
            .metrics
            .unguarded("policy-guard", VALIDATE_REGISTRY_CONFIGS_PATH);
        log_unguarded(&request);
        return Json(response.into_review());
    };
    let write = write_from_request(&request, kind);

    let allowed_identities = state
        .policy_guard_config
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .map(|config| config.allowed_identities.clone())
        .unwrap_or_default();
    let mut registry: Registry<RegistryObjectWrite> = Registry::new();
    registry.register(RegistryGuard::new(
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    /// A textual regression test in the shape [`crate::router`]'s own uses. Half the objects this
    /// route sees are `Secret`s, so "the handler never reads the admitted object's payload" is
    /// the property most worth a tripwire — `log_decision`'s signature already makes passing one
    /// impossible, but a future edit adding a debug print next to it would not be caught by the
    /// type system.
    ///
    /// The needle is assembled at runtime, not written as a literal, so this test does not count
    /// its own source as an occurrence.
    #[test]
    fn the_admitted_objects_data_field_is_never_read_on_this_route() {
        let needle = ["object", "data"].join(".");
        let source = include_str!("registry_guard.rs");
        assert_eq!(
            source.matches(&needle).count(),
            0,
            "the registry guard decides from metadata alone; it must never touch a ConfigMap's \
             or a Secret's payload"
        );
    }
}
