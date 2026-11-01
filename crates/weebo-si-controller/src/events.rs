//! What every reconcile loop does when a pass fails, and the Kubernetes `Event` that says so
//! (RFC 0012).
//!
//! Before RFC 0012 each loop had its own `error_policy`: log, requeue after a flat 30 s
//! (`todo.md` L5). [`retry`] is the one policy every loop now uses: `weebo-kit-runtime`'s
//! `retry_after_error`, which logs, publishes a `Warning` Event on the object the pass was about —
//! the `WeeboSiConfig`, the namespace, the workspace, the `Ingress`, the team or the user — and
//! backs off from 30 s to 5 min while the same object keeps failing. A pass that succeeds calls
//! [`reconciled`], so the next failure starts from 30 s again.

use std::sync::Arc;

use k8s_openapi::api::core::v1::{Namespace, ObjectReference};
use k8s_openapi::api::networking::v1::Ingress;
use kube::core::DynamicObject;
use kube::runtime::controller::Action;
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, Resource, ResourceExt};
use weebo_kit_domain::{Reason, Severity};
use weebo_si_crd::{WeeboSiConfig, WeeboSiTeam, WeeboSiUser};

/// The `reportingController` of every Event this operator publishes.
pub const REPORTER: &str = "weebo-si-operator";

pub use reason::ReasonCode;

/// The catalog, in its own module: `reason_codes!` also generates an undocumented `ALL`.
mod reason {
    #![allow(
        missing_docs,
        reason = "reason_codes! generates the undocumented `ALL` slice"
    )]

    weebo_kit_domain::reason_codes! {
        /// The `reason` of the Events the reconcile loops publish. Stable: an alert or a
        /// `kubectl get events --field-selector reason=…` may match on it.
        pub enum ReasonCode {
            /// A pass completed.
            Reconciled,
            /// The `WeeboSiConfig` status pass failed.
            ConfigReconcileFailed,
            /// A `network-profiles` pass failed on a namespace or a workspace.
            NetworkProfilesFailed,
            /// A `kubearmor-policy` pass failed on a namespace or a workspace.
            KubeArmorPolicyFailed,
            /// A `registry-config` pass failed on a namespace.
            RegistryConfigFailed,
            /// An `endpoint-auth` pass failed on an `Ingress`.
            EndpointAuthFailed,
            /// An `identity` pass failed on a team or a user.
            IdentityFailed,
            /// A `pod-security` pass failed on a namespace.
            PodSecurityFailed,
        }
    }
}

impl Reason for ReasonCode {
    /// A completed pass.
    const SUCCESS: Self = Self::Reconciled;

    fn as_str(self) -> &'static str {
        ReasonCode::as_str(self)
    }

    fn severity(self) -> Severity {
        Severity::Blocking
    }
}

/// The recorder every loop of this process publishes through: one, shared, so the kube
/// `Recorder` folds a repeated Event into a series instead of flooding the apiserver.
pub fn recorder(client: Client) -> Recorder {
    Recorder::new(
        client,
        Reporter {
            controller: REPORTER.into(),
            instance: std::env::var("HOSTNAME").ok(),
        },
    )
}

/// The object an Event is about. Implemented per kind rather than for every `Resource`:
/// `DevWorkspace` is a `DynamicObject`, whose kind lives in the object rather than in its type.
pub trait Regarding {
    /// The reference an Event's `regarding` field carries.
    fn regarding(&self) -> ObjectReference;
}

macro_rules! regarding_typed {
    ($($kind:ty),+ $(,)?) => {
        $(impl Regarding for $kind {
            fn regarding(&self) -> ObjectReference {
                self.object_ref(&())
            }
        })+
    };
}

regarding_typed!(Namespace, Ingress, WeeboSiConfig, WeeboSiTeam, WeeboSiUser);

impl Regarding for DynamicObject {
    fn regarding(&self) -> ObjectReference {
        ObjectReference {
            api_version: self.types.as_ref().map(|types| types.api_version.clone()),
            kind: self.types.as_ref().map(|types| types.kind.clone()),
            name: Some(self.name_any()),
            namespace: self.namespace(),
            uid: self.uid(),
            resource_version: self.resource_version(),
            ..ObjectReference::default()
        }
    }
}

/// The error policy of every loop: log, publish a `Warning` Event on `object` with `reason`,
/// requeue with backoff.
pub fn retry<K: Regarding>(
    recorder: &Recorder,
    object: &K,
    reason: ReasonCode,
    error: &dyn std::fmt::Display,
) -> Action {
    weebo_kit_runtime::controller::retry_after_error(
        recorder,
        object.regarding(),
        reason,
        weebo_kit_runtime::events::RECONCILE,
        error,
    )
}

/// End `object`'s failure streak after a pass that succeeded.
pub fn reconciled<K: Resource>(object: &K) {
    weebo_kit_runtime::controller::reconciled(object);
}

/// Run one reconcile `pass` over `object`, ending its failure streak when the pass succeeds —
/// what every loop's `Controller::run` wraps its reconcile function in.
pub async fn tracked<K, E>(
    object: Arc<K>,
    pass: impl Future<Output = Result<Action, E>>,
) -> Result<Action, E>
where
    K: Resource,
{
    let outcome = pass.await;
    if outcome.is_ok() {
        reconciled(object.as_ref());
    }
    outcome
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_is_a_valid_event_reason() {
        for reason in ReasonCode::ALL {
            let text = reason.as_str();
            assert!(text.chars().next().unwrap().is_ascii_uppercase(), "{text}");
            assert!(text.chars().all(|ch| ch.is_ascii_alphanumeric()), "{text}");
            assert!(text.len() <= 128, "{text}");
        }
    }

    #[test]
    fn a_devworkspace_reference_carries_its_kind() {
        let object: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "workspace.devfile.io/v1alpha2",
            "kind": "DevWorkspace",
            "metadata": { "name": "python-web", "namespace": "user-alice", "uid": "u-1" },
        }))
        .unwrap();
        let reference = object.regarding();
        assert_eq!(reference.kind.as_deref(), Some("DevWorkspace"));
        assert_eq!(
            reference.api_version.as_deref(),
            Some("workspace.devfile.io/v1alpha2")
        );
        assert_eq!(reference.namespace.as_deref(), Some("user-alice"));
        assert_eq!(reference.uid.as_deref(), Some("u-1"));
    }
}
