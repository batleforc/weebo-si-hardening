//! The `policy-guard` feature — see RFC 0004's *Design → Contract*, "`policyGuard`."
//!
//! Fits the existing `Feature<S>` trait rather than needing a new one: an admission-time
//! allow/deny decision over a NetworkPolicy write is exactly what `Decision::deny(...)` /
//! `Decision::new(vec![], ...)` already model, with no mutation ever produced.

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::NamespaceName;

/// Which write is under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicyOperation {
    /// A new object.
    Create,
    /// An existing object's spec.
    Update,
    /// An existing object, removed.
    Delete,
}

/// A `networkpolicies`/`ciliumnetworkpolicies` write under admission, in domain vocabulary. Per
/// RFC 0004's *Design*, `DELETE` carries the ownership label read from `oldObject` — the
/// admission adapter's job, not this type's; by the time a `NetworkPolicyWrite` exists,
/// `target_is_managed` already has that answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyWrite {
    /// The namespace the object lives (or would live) in.
    pub namespace: NamespaceName,
    /// The requesting identity's full name, e.g. `system:serviceaccount:ns:name`.
    pub actor: String,
    /// Which write this is.
    pub operation: NetworkPolicyOperation,
    /// Whether the target object (the existing one for `Update`/`Delete`) carries
    /// `hardening.weebo.io/managed-by: weebo-si-operator`. Always `false` for `Create` — a
    /// brand-new object cannot already carry the label.
    pub target_is_managed: bool,
}

impl Subject for NetworkPolicyWrite {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

/// The `policy-guard` feature: the three-row verdict table from RFC 0004's *Design → Contract*.
/// Stateless per call — `operator_identity` and `allowed_identities` are supplied by the caller,
/// since (unlike `dwoc-pin`'s hot-reloadable catalogue) neither ever changes without a redeploy.
pub struct PolicyGuard {
    operator_identity: String,
    allowed_identities: Vec<String>,
}

impl PolicyGuard {
    /// Build the guard. `operator_identity` is exempt from every rule below; `allowed_identities`
    /// is exempt from the second row only (it may still not touch a managed object).
    pub fn new(operator_identity: String, allowed_identities: Vec<String>) -> Self {
        Self {
            operator_identity,
            allowed_identities,
        }
    }
}

impl Feature<NetworkPolicyWrite> for PolicyGuard {
    fn id(&self) -> FeatureId {
        FeatureId::new("policy-guard")
    }

    fn evaluate(
        &self,
        subject: &NetworkPolicyWrite,
        _ctx: &Context<'_>,
    ) -> Result<Decision<NetworkPolicyWrite>, DomainError> {
        if subject.actor == self.operator_identity {
            return Ok(Decision::new(Vec::new(), None, None, "operator_allowed"));
        }

        if subject.target_is_managed {
            return Ok(Decision::deny(
                format!(
                    "{}/{:?} is managed by weebo-si-operator and may not be touched by {}",
                    subject.namespace, subject.operation, subject.actor
                ),
                None,
                Some("managed_object".to_string()),
                "denied_managed_object",
            ));
        }

        if subject.operation == NetworkPolicyOperation::Create
            && !self.allowed_identities.contains(&subject.actor)
        {
            return Ok(Decision::deny(
                format!(
                    "network policy authorship in workspace namespaces belongs to the platform; \
                     {} is not in allowedIdentities",
                    subject.actor
                ),
                None,
                Some("unmanaged_create".to_string()),
                "denied_unmanaged_create",
            ));
        }

        Ok(Decision::new(Vec::new(), None, None, "allowed"))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;

    use super::*;

    fn ctx<'a>(namespace: &'a NamespaceFacts, catalog: &'a FakeDwocCatalog) -> Context<'a> {
        Context::new(&[], namespace, catalog)
    }

    fn namespace_facts() -> NamespaceFacts {
        NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        }
    }

    fn write(actor: &str, operation: NetworkPolicyOperation, managed: bool) -> NetworkPolicyWrite {
        NetworkPolicyWrite {
            namespace: NamespaceName::new("user-alice"),
            actor: actor.to_string(),
            operation,
            target_is_managed: managed,
        }
    }

    fn guard() -> PolicyGuard {
        PolicyGuard::new(
            "system:serviceaccount:weebo-si-hardening:weebo-si-operator".to_string(),
            vec!["system:serviceaccount:kube-system:break-glass".to_string()],
        )
    }

    #[test]
    fn any_write_from_the_operator_is_allowed() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = guard()
            .evaluate(
                &write(
                    "system:serviceaccount:weebo-si-hardening:weebo-si-operator",
                    NetworkPolicyOperation::Delete,
                    true,
                ),
                &ctx(&namespace, &catalog),
            )
            .unwrap();
        assert!(decision.denial.is_none());
    }

    #[test]
    fn a_non_operator_touching_a_managed_object_is_denied_on_every_operation() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        for op in [
            NetworkPolicyOperation::Create,
            NetworkPolicyOperation::Update,
            NetworkPolicyOperation::Delete,
        ] {
            let decision = guard()
                .evaluate(&write("user-alice", op, true), &ctx(&namespace, &catalog))
                .unwrap();
            assert!(
                decision.denial.is_some(),
                "operation {op:?} should be denied"
            );
        }
    }

    #[test]
    fn a_create_of_an_unmanaged_object_by_a_non_allowed_identity_is_denied() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = guard()
            .evaluate(
                &write("user-alice", NetworkPolicyOperation::Create, false),
                &ctx(&namespace, &catalog),
            )
            .unwrap();
        assert!(decision.denial.is_some());
    }

    #[test]
    fn a_create_of_an_unmanaged_object_by_an_allowed_identity_is_allowed() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = guard()
            .evaluate(
                &write(
                    "system:serviceaccount:kube-system:break-glass",
                    NetworkPolicyOperation::Create,
                    false,
                ),
                &ctx(&namespace, &catalog),
            )
            .unwrap();
        assert!(decision.denial.is_none());
    }

    #[test]
    fn an_update_of_an_unmanaged_object_by_anyone_is_allowed() {
        // Only CREATE of an unmanaged object is gated by allowedIdentities — an UPDATE to an
        // object that was never ours is not this guard's business, per the RFC's three-row
        // table (only the managed-object row and the unmanaged-CREATE row deny).
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = guard()
            .evaluate(
                &write("user-alice", NetworkPolicyOperation::Update, false),
                &ctx(&namespace, &catalog),
            )
            .unwrap();
        assert!(decision.denial.is_none());
    }
}
