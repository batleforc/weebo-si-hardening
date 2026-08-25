//! `policy-guard`, extended to the objects this brick writes — RFC 0007's *`policy-guard` covers
//! these objects too*.
//!
//! A workspace namespace is one the *user* has edit rights in. So unlike a `NetworkPolicy` in
//! the same namespace, which a user typically cannot touch, an automounted `ConfigMap` is
//! squarely inside what a determined developer can delete, edit, or point at a registry of their
//! choosing. Left alone, "the mirror is configured" would be true only until someone found it
//! inconvenient.
//!
//! ## Two rows, not three — and this is the interesting part
//!
//! `network-profiles`' [`PolicyGuard`](weebo_si_network_profiles::PolicyGuard) has three rows:
//! the operator is always allowed, a managed object may not be touched by anyone else, and a
//! `CREATE` of an *unmanaged* object is refused unless the actor is in `allowedIdentities`.
//! **This guard has the first two and deliberately not the third.**
//!
//! The reason is not a preference; it follows from the webhook rule's `objectSelector`. RFC 0007
//! puts one on `hardening.weebo.io/managed-by` because `ConfigMap` writes are among the highest
//! volume writes in a cluster and a webhook in front of all of them is a cluster-wide risk. RFC
//! 0008 states the resulting general rule: "a guard rule that must refuse unmanaged creates
//! cannot use an ownership `objectSelector`; one that only protects existing objects should, if
//! the resource is high-volume."
//!
//! Encoding that here rather than relying on the selector is defence in depth with teeth: an
//! `objectSelector` accidentally dropped from the chart would otherwise turn this guard into
//! one that **denies every `ConfigMap` and `Secret` a developer creates in their own namespace**
//! — a far worse outage than the gap it was protecting. The third row is absent from the code,
//! so that misconfiguration cannot produce it.
//!
//! ## Relationship to RFC 0008
//!
//! [RFC 0008](../../../../docs/rfc/0008-policy-guard-coverage.md) promotes `PolicyGuard` into a
//! crate of its own with a resource-agnostic `GuardedWrite`, and names this rule as the second
//! kind it will absorb. Until that lands, this guard is ~40 lines local to the brick that writes
//! the objects rather than a dependency from `weebo-si-registry-config` on
//! `weebo-si-network-profiles` — which would be this crate's only dependency outside
//! `weebo-si-crd` + `weebo-si-chassis`, for two shared rows.
//!
//! It reports [`FeatureId`] `policy-guard`, not `registry-config`: one `mode` and one
//! `allowedIdentities` govern every guard rule in this operator, which is what makes "turn the
//! guard off" a single edit rather than a hunt.

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::{NamespaceName, SourceKind};

/// Which write is under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOperation {
    /// A new object.
    Create,
    /// An existing object's content.
    Update,
    /// An existing object, removed.
    Delete,
}

/// A `configmaps`/`secrets` write under admission, in domain vocabulary.
///
/// `target_is_managed` is the admission adapter's answer, read from `oldObject` for
/// `UPDATE`/`DELETE` — never from the proposed object, which would let an `UPDATE` strip the
/// label in the same request that bypasses the check it protects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryObjectWrite {
    /// The namespace the object lives (or would live) in.
    pub namespace: NamespaceName,
    /// The requesting identity's full name, e.g. `system:serviceaccount:ns:name`.
    pub actor: String,
    /// Which write this is.
    pub operation: WriteOperation,
    /// Which kind of object — a log field and a metric label, **never a branch**. A `match` on
    /// this inside `evaluate` would be the first step toward a guard that protects `Secret`s
    /// more than `ConfigMap`s, and the objects are equally this operator's.
    pub kind: SourceKind,
    /// Whether the target object carries `hardening.weebo.io/managed-by: weebo-si-operator`.
    /// Always `false` for `Create` — a brand-new object cannot already carry the label.
    pub target_is_managed: bool,
}

impl Subject for RegistryObjectWrite {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

/// The guard over this brick's own objects. Stateless per call, like `network-profiles`' —
/// `operator_identity` and `allowed_identities` are supplied by the caller.
pub struct RegistryGuard {
    operator_identity: String,
    allowed_identities: Vec<String>,
}

impl RegistryGuard {
    /// Build the guard. `operator_identity` is exempt from every rule below; `allowed_identities`
    /// is the break-glass list `spec.features.policyGuard.allowedIdentities` carries, exempt for
    /// the same reason it is on the network rule.
    pub fn new(operator_identity: String, allowed_identities: Vec<String>) -> Self {
        Self {
            operator_identity,
            allowed_identities,
        }
    }
}

impl Feature<RegistryObjectWrite> for RegistryGuard {
    fn id(&self) -> FeatureId {
        FeatureId::new("policy-guard")
    }

    fn evaluate(
        &self,
        subject: &RegistryObjectWrite,
        _ctx: &Context<'_>,
    ) -> Result<Decision<RegistryObjectWrite>, DomainError> {
        if subject.actor == self.operator_identity {
            return Ok(Decision::new(Vec::new(), None, None, "operator_allowed"));
        }

        // Everything this guard refuses. An object that is not ours is not this guard's
        // business, whatever the operation — see this module's doc for why that absence is
        // load-bearing rather than an omission.
        if !subject.target_is_managed {
            return Ok(Decision::new(Vec::new(), None, None, "allowed"));
        }

        if self.allowed_identities.contains(&subject.actor) {
            return Ok(Decision::new(
                Vec::new(),
                None,
                Some("allowed_identity".to_string()),
                "break_glass_allowed",
            ));
        }

        Ok(Decision::deny(
            format!(
                "{} {}/{:?} is managed by weebo-si-operator and may not be touched by {}",
                subject.kind, subject.namespace, subject.operation, subject.actor
            ),
            None,
            Some("managed_object".to_string()),
            "denied_managed_object",
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;

    use super::*;

    const OPERATOR: &str = "system:serviceaccount:weebo-si-hardening:weebo-si-operator";
    const BREAK_GLASS: &str = "system:serviceaccount:kube-system:break-glass";

    fn guard() -> RegistryGuard {
        RegistryGuard::new(OPERATOR.to_string(), vec![BREAK_GLASS.to_string()])
    }

    fn write(actor: &str, operation: WriteOperation, managed: bool) -> RegistryObjectWrite {
        RegistryObjectWrite {
            namespace: NamespaceName::new("user-alice"),
            actor: actor.to_string(),
            operation,
            kind: SourceKind::ConfigMap,
            target_is_managed: managed,
        }
    }

    const EVERY_OPERATION: [WriteOperation; 3] = [
        WriteOperation::Create,
        WriteOperation::Update,
        WriteOperation::Delete,
    ];

    fn decide(subject: &RegistryObjectWrite) -> Decision<RegistryObjectWrite> {
        let namespace = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        guard()
            .evaluate(subject, &Context::new(&[], &namespace, &catalog))
            .unwrap()
    }

    #[test]
    fn any_write_from_the_operator_is_allowed() {
        for op in EVERY_OPERATION {
            assert!(decide(&write(OPERATOR, op, true)).denial.is_none());
        }
    }

    #[test]
    fn a_user_touching_a_managed_object_is_denied_on_every_operation() {
        for op in EVERY_OPERATION {
            assert!(
                decide(&write("user-alice", op, true)).denial.is_some(),
                "operation {op:?} should be denied"
            );
        }
    }

    #[test]
    fn a_break_glass_identity_may_touch_a_managed_object() {
        for op in EVERY_OPERATION {
            assert!(decide(&write(BREAK_GLASS, op, true)).denial.is_none());
        }
    }

    #[test]
    fn an_ordinary_configmap_a_developer_creates_is_never_this_guards_business() {
        // The row this guard deliberately does not have. If the chart's `objectSelector` were
        // ever dropped, the third row would deny *every* ConfigMap and Secret write in every
        // workspace namespace — a much worse outage than the gap it protects. Absent from the
        // code, that misconfiguration cannot produce it.
        for op in EVERY_OPERATION {
            assert!(
                decide(&write("user-alice", op, false)).denial.is_none(),
                "operation {op:?} on an unmanaged object must be allowed"
            );
        }
    }

    #[test]
    fn a_secret_is_guarded_exactly_as_a_configmap_is() {
        // `kind` reaches the log line and the metric label, never the verdict.
        let mut as_secret = write("user-alice", WriteOperation::Update, true);
        as_secret.kind = SourceKind::Secret;
        let as_config_map = write("user-alice", WriteOperation::Update, true);
        assert_eq!(
            decide(&as_secret).result,
            decide(&as_config_map).result,
            "the verdict must not vary by kind"
        );
    }

    #[test]
    fn the_denial_names_the_kind_the_namespace_and_the_actor() {
        let denial = decide(&write("user-alice", WriteOperation::Delete, true))
            .denial
            .unwrap();
        assert!(denial.contains("ConfigMap"), "{denial}");
        assert!(denial.contains("user-alice"), "{denial}");
    }
}
