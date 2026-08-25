//! The `policy-guard` feature — RFC 0004's *Design → Contract*, "`policyGuard`", extended to
//! every resource this operator writes into a namespace it does not own (RFC 0008).
//!
//! Fits the existing `Feature<S>` trait rather than needing a new one: an admission-time
//! allow/deny decision over a guarded write is exactly what `Decision::deny(...)` /
//! `Decision::new(vec![], ...)` already model, with no mutation ever produced.

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::NamespaceName;

use crate::resource::GuardedResource;

/// Which write is under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOperation {
    /// A new object.
    Create,
    /// An existing object's spec.
    Update,
    /// An existing object, removed.
    Delete,
}

/// A write to one of the resources this operator owns, in domain vocabulary. Per RFC 0004's
/// *Design*, `DELETE` carries the ownership label read from `oldObject` — the admission
/// adapter's job, not this type's; by the time a `GuardedWrite` exists, `target_is_managed`
/// already has that answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedWrite {
    /// The namespace the object lives (or would live) in.
    pub namespace: NamespaceName,
    /// The requesting identity's full name, e.g. `system:serviceaccount:ns:name`.
    pub actor: String,
    /// Which write this is.
    pub operation: WriteOperation,
    /// Whether the target object (the existing one for `Update`/`Delete`) carries
    /// `hardening.weebo.io/managed-by: weebo-si-operator`. Always `false` for `Create` — a
    /// brand-new object cannot already carry the label.
    pub target_is_managed: bool,
    /// Which resource this write is against — **a metric label and a log field, never a
    /// branch**. See [`crate`]'s own module doc: the three-row table below is the same table for
    /// every resource, and that is the guard's whole claim.
    pub resource: GuardedResource,
}

impl Subject for GuardedWrite {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    /// Where [`GuardedWrite::resource`] actually goes: the `resource` label on
    /// `weebo_si_admission_requests_total`, which is what "a metric can be broken down" in RFC
    /// 0008's *Contract* was supposed to mean all along.
    ///
    /// Reading the field is not the branch that *Contract* forbids — that is about `evaluate`
    /// reaching a different verdict, and it cannot: this is the observability record, computed
    /// after the decision and incapable of changing it.
    fn resource(&self) -> &'static str {
        self.resource.as_str()
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

impl Feature<GuardedWrite> for PolicyGuard {
    fn id(&self) -> FeatureId {
        FeatureId::new("policy-guard")
    }

    fn evaluate(
        &self,
        subject: &GuardedWrite,
        _ctx: &Context<'_>,
    ) -> Result<Decision<GuardedWrite>, DomainError> {
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

        if subject.operation == WriteOperation::Create
            && !self.allowed_identities.contains(&subject.actor)
        {
            return Ok(Decision::deny(
                // `resource` is *formatted*, not branched on — the sentence is the same
                // sentence for every resource, and naming the one refused is what makes the
                // message actionable for a developer who wrote a `KubeArmorPolicy` rather than
                // a `NetworkPolicy`. RFC 0008's "never a branch" is about `evaluate` reaching a
                // different verdict, which it cannot do here.
                format!(
                    "{} authorship in workspace namespaces belongs to the platform; \
                     {} is not in allowedIdentities",
                    subject.resource, subject.actor
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

    fn write(
        actor: &str,
        operation: WriteOperation,
        managed: bool,
        resource: GuardedResource,
    ) -> GuardedWrite {
        GuardedWrite {
            namespace: NamespaceName::new("user-alice"),
            actor: actor.to_string(),
            operation,
            target_is_managed: managed,
            resource,
        }
    }

    fn guard() -> PolicyGuard {
        PolicyGuard::new(
            "system:serviceaccount:weebo-si-hardening:weebo-si-operator".to_string(),
            vec!["system:serviceaccount:kube-system:break-glass".to_string()],
        )
    }

    /// The whole table, on one resource, in one place — every row of RFC 0004's *Design →
    /// Contract* as `(actor, operation, managed) -> denied?`.
    const TABLE: [(&str, WriteOperation, bool, bool); 6] = [
        // The operator is exempt from every row, including a DELETE of its own object.
        (
            "system:serviceaccount:weebo-si-hardening:weebo-si-operator",
            WriteOperation::Delete,
            true,
            false,
        ),
        // Row two: a managed object may not be touched by anyone else, on any operation.
        ("user-alice", WriteOperation::Create, true, true),
        ("user-alice", WriteOperation::Update, true, true),
        ("user-alice", WriteOperation::Delete, true, true),
        // Row three: authorship of policy in a workspace namespace belongs to the platform —
        // but only on CREATE, and only outside `allowedIdentities`.
        ("user-alice", WriteOperation::Create, false, true),
        (
            "system:serviceaccount:kube-system:break-glass",
            WriteOperation::Create,
            false,
            false,
        ),
    ];

    /// **The test RFC 0008 asks for by name**: the three-row table over each `GuardedResource`,
    /// proving the verdict does not vary by resource.
    ///
    /// It is not redundant with the per-row tests below — those prove the rows are right, this
    /// proves `resource` is not read. A `match` on `subject.resource` inside `evaluate` is the
    /// change this catches, and it is the change RFC 0008 says must never land: "a cluster where
    /// that claim is true of a `NetworkPolicy` and false of a `KubeArmorPolicy` is a cluster
    /// where the claim is not true."
    #[test]
    fn the_verdict_table_is_identical_for_every_guarded_resource() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        for (actor, operation, managed, expect_denied) in TABLE {
            let mut verdicts = Vec::new();
            for resource in GuardedResource::ALL {
                let decision = guard()
                    .evaluate(
                        &write(actor, operation, managed, resource),
                        &ctx(&namespace, &catalog),
                    )
                    .unwrap();
                assert_eq!(
                    decision.denial.is_some(),
                    expect_denied,
                    "{resource}: ({actor}, {operation:?}, managed={managed}) should \
                     {} be denied",
                    if expect_denied { "" } else { "not" }
                );
                // The *verdict*, not the sentence: the unmanaged-CREATE denial names the
                // resource it refused (see `evaluate`), which is a rendering difference rather
                // than a decision one. `result` is the outcome label the metrics carry, so
                // comparing it is comparing exactly what "the same table" means.
                verdicts.push((decision.denial.is_some(), decision.result));
            }
            assert!(
                verdicts.windows(2).all(|pair| pair[0] == pair[1]),
                "({actor}, {operation:?}, managed={managed}) produced different verdicts for \
                 different resources — the guard has started reading `resource`, which RFC 0008 \
                 forbids: {verdicts:?}"
            );
        }
    }

    #[test]
    fn any_write_from_the_operator_is_allowed() {
        let namespace = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let decision = guard()
            .evaluate(
                &write(
                    "system:serviceaccount:weebo-si-hardening:weebo-si-operator",
                    WriteOperation::Delete,
                    true,
                    GuardedResource::NetworkPolicy,
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
            WriteOperation::Create,
            WriteOperation::Update,
            WriteOperation::Delete,
        ] {
            let decision = guard()
                .evaluate(
                    &write("user-alice", op, true, GuardedResource::KubeArmorPolicy),
                    &ctx(&namespace, &catalog),
                )
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
                &write(
                    "user-alice",
                    WriteOperation::Create,
                    false,
                    GuardedResource::KubeArmorPolicy,
                ),
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
                    WriteOperation::Create,
                    false,
                    GuardedResource::CiliumNetworkPolicy,
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
                &write(
                    "user-alice",
                    WriteOperation::Update,
                    false,
                    GuardedResource::NetworkPolicy,
                ),
                &ctx(&namespace, &catalog),
            )
            .unwrap();
        assert!(decision.denial.is_none());
    }
}
