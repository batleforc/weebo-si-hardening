//! The endpoint-auth guard — RFC 0009's *The guard rule, and why it is not a row in RFC 0008's
//! table*.
//!
//! A **third kind of guard rule** in this crate, beside [`crate::PolicyGuard`]'s three-row table
//! and `weebo-si-registry-config`'s registry guard, with its own subject. It cannot be a row in
//! the first one: that table decides from `target_is_managed` alone and is required to reach the
//! same verdict for every resource, while this needs a *field-level* verdict — this annotation
//! may change, that one may not, and this third one may only hold one value. Feeding
//! `ingresses` to the three-row table would be wrong in both directions: its second row denies
//! the delegation edit RFC 0009 promises a developer, and its third denies DevWorkspace
//! Operator's own `CREATE`, which stops every workspace endpoint in the cluster from existing.
//!
//! Two fields here need their difference stated, because RFC 0008 forbids branching on one of
//! them:
//!
//! - [`EndpointRoutingWrite::kind`] must **not** branch. The guard's claim is that it protects
//!   the operator's objects identically whatever they are made of, so an `Ingress` and a `Route`
//!   get the same verdict. It is a metric label and a log field.
//! - [`EndpointRoutingWrite::provenance`] **does** branch, and legitimately: a DWO-generated
//!   object's shape is a projection of a devfile and belongs to the platform, while a
//!   user-authored one was typed by the person whose namespace it is. Freezing the second like
//!   the first would forbid a developer to edit their own work, which is how controls get
//!   removed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::{DEVELOPER_ANNOTATIONS, NamespaceName, RoutingKind};

use crate::guard::WriteOperation;

/// Who authored the routing object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// DevWorkspace Operator generated it from a devfile — it carries
    /// `controller.devfile.io/devworkspace_id`.
    Devfile,
    /// The developer wrote it themselves.
    Author,
}

/// A managed annotation key, or — for a `ReverseProxy` dialect — a field path such as `spec.to`.
///
/// One type for both because the guard pins them the same way, by value, and because a dialect
/// that moves the gate from an annotation into a field must not need a second guard rule to
/// follow it there.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedField {
    /// An annotation key.
    Annotation(String),
    /// A field path, e.g. `spec.to`.
    Path(&'static str),
}

impl fmt::Display for ManagedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Annotation(key) => f.write_str(key),
            Self::Path(path) => f.write_str(path),
        }
    }
}

/// A write to a routing object in a workspace namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRoutingWrite {
    /// The namespace the object lives (or would live) in.
    pub namespace: NamespaceName,
    /// The requesting identity's full name.
    pub actor: String,
    /// Which write this is.
    pub operation: WriteOperation,
    /// Which routing kind — a metric label, never a branch.
    pub kind: RoutingKind,
    /// Who authored the object.
    pub provenance: Provenance,
    /// Annotation keys whose value differs between the old object and the submitted one.
    pub changed_annotations: BTreeSet<String>,
    /// Whether anything outside the annotations changed — a backend, a TLS block, a path. Only
    /// consulted for a DWO-generated object, whose shape is the devfile's rather than
    /// `kubectl`'s.
    pub other_fields_changed: bool,
    /// What the dialect says the managed annotations *and fields* must hold.
    pub expected_managed: BTreeMap<ManagedField, String>,
    /// What the submitted object actually holds for them.
    pub submitted_managed: BTreeMap<ManagedField, String>,
    /// Whether the submitted object carries the DevWorkspace Operator label. Forging it is how a
    /// namespace claims a policy it did not earn, which is why it is a field of its own rather
    /// than something derived from `provenance`.
    pub carries_devworkspace_label: bool,
    /// Whether the host the object claims is owned by this namespace, as
    /// `hosts.ownership` resolves it. `None` where the write names no host at all.
    pub host_owned_by_namespace: Option<bool>,
}

impl Subject for EndpointRoutingWrite {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        self.kind.kind()
    }
}

impl EndpointRoutingWrite {
    /// The managed fields whose submitted value differs from what the dialect expects — the
    /// whole of row 6, computed once so the verdict and the message agree about what is wrong.
    pub fn tampered(&self) -> Vec<&ManagedField> {
        self.expected_managed
            .iter()
            .filter(|(field, expected)| self.submitted_managed.get(*field) != Some(*expected))
            .map(|(field, _)| field)
            .collect()
    }

    /// Annotation changes outside the four keys a developer owns.
    pub fn non_developer_annotation_changes(&self) -> Vec<&String> {
        self.changed_annotations
            .iter()
            .filter(|key| !DEVELOPER_ANNOTATIONS.contains(&key.as_str()))
            .collect()
    }
}

/// The guard, holding the three identities that are exempt from it.
pub struct EndpointRoutingGuard {
    operator_identity: String,
    devworkspace_operator_identity: String,
    break_glass_identities: Vec<String>,
}

impl EndpointRoutingGuard {
    /// Build the guard.
    ///
    /// `devworkspace_operator_identity` is row 2 and must not be optimised away: DWO creates and
    /// reconciles every generated routing object, and denying it stops every workspace endpoint
    /// in the cluster from existing.
    pub fn new(
        operator_identity: String,
        devworkspace_operator_identity: String,
        break_glass_identities: Vec<String>,
    ) -> Self {
        Self {
            operator_identity,
            devworkspace_operator_identity,
            break_glass_identities,
        }
    }
}

impl Feature<EndpointRoutingWrite> for EndpointRoutingGuard {
    fn id(&self) -> FeatureId {
        FeatureId::new("endpoint-auth")
    }

    fn evaluate(
        &self,
        subject: &EndpointRoutingWrite,
        _ctx: &Context<'_>,
    ) -> Result<Decision<EndpointRoutingWrite>, DomainError> {
        // Rows 1 to 3: the three identities that write these objects legitimately.
        if subject.actor == self.operator_identity {
            return Ok(Decision::new(Vec::new(), None, None, "operator_allowed"));
        }
        if subject.actor == self.devworkspace_operator_identity {
            return Ok(Decision::new(Vec::new(), None, None, "dwo_allowed"));
        }
        if self.break_glass_identities.contains(&subject.actor) {
            return Ok(Decision::new(Vec::new(), None, None, "break_glass"));
        }

        // Row 9, before anything that reads the object's contents: the route dies with the gate,
        // so there is nothing left to reach. DWO recreates what DWO owns.
        if subject.operation == WriteOperation::Delete {
            return Ok(Decision::new(Vec::new(), None, None, "delete_allowed"));
        }

        // Row 4: forging DWO's own label is how a namespace claims a policy it did not earn —
        // provenance decides how much of an object is frozen, so authoring the marker for it is
        // authoring the answer.
        if subject.carries_devworkspace_label && subject.provenance == Provenance::Devfile {
            return Ok(Decision::deny(
                format!(
                    "{} may not write a DevWorkspace-generated {} in {}",
                    subject.actor,
                    subject.kind.kind(),
                    subject.namespace
                ),
                None,
                Some("forged_devworkspace_label".to_string()),
                "denied_forged_label",
            ));
        }

        // The host-ownership check, which is not a row because it applies to both remaining
        // rows: a host that no ownership pattern ties to this namespace is a host whose policy
        // belongs to somebody else.
        if subject.host_owned_by_namespace == Some(false) {
            return Ok(Decision::deny(
                format!(
                    "the host this {} claims does not belong to {}",
                    subject.kind.kind(),
                    subject.namespace
                ),
                None,
                Some("host_not_owned".to_string()),
                "denied_host_not_owned",
            ));
        }

        // Row 5: a developer's own endpoint is gated by the mutation, not refused.
        if subject.operation == WriteOperation::Create {
            return Ok(Decision::new(Vec::new(), None, None, "create_allowed"));
        }

        // Row 6, the one an attacker reads first: the gate is pinned **by value**. On Traefik
        // that value is the whole middleware chain, because the chain runs before `forwardAuth`
        // and a `headers` middleware prepended by the developer could set `X-Forwarded-Uri` to a
        // path covered by an `open` rule while the router still serves the real one.
        let tampered = subject.tampered();
        if !tampered.is_empty() {
            let named = tampered
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            return Ok(Decision::deny(
                format!("the gate is managed by weebo-si-operator: {named} may not be changed"),
                None,
                Some("managed_field".to_string()),
                "denied_managed_field",
            ));
        }

        // Row 7: a DWO-generated object's shape is a projection of the devfile. The delegation
        // and rule annotations are the developer's; everything else there is the devfile's, and
        // `kubectl` is not where it is edited.
        if subject.provenance == Provenance::Devfile {
            let annotations = subject.non_developer_annotation_changes();
            if !annotations.is_empty() || subject.other_fields_changed {
                let named = if annotations.is_empty() {
                    "the object's spec".to_string()
                } else {
                    annotations
                        .iter()
                        .map(|key| key.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                return Ok(Decision::deny(
                    format!(
                        "this {} is generated from a devfile; {named} is edited there, not here",
                        subject.kind.kind()
                    ),
                    None,
                    Some("devfile_projection".to_string()),
                    "denied_devfile_projection",
                ));
            }
        }

        // Row 8: they wrote it; only the managed fields are not theirs.
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
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::ENDPOINT_AUTH_ANNOTATION;

    use super::*;

    const OPERATOR: &str = "system:serviceaccount:weebo-si-hardening:weebo-si-operator";
    const DWO: &str =
        "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount";
    const CHAIN: &str = "traefik.ingress.kubernetes.io/router.middlewares";
    const EXPECTED_CHAIN: &str = "weebo-si-hardening-weebo-si-endpoint-auth@kubernetescrd";

    fn guard() -> EndpointRoutingGuard {
        EndpointRoutingGuard::new(
            OPERATOR.to_owned(),
            DWO.to_owned(),
            vec!["system:serviceaccount:platform:break-glass".to_owned()],
        )
    }

    fn expected() -> BTreeMap<ManagedField, String> {
        BTreeMap::from([
            (
                ManagedField::Annotation(CHAIN.to_owned()),
                EXPECTED_CHAIN.to_owned(),
            ),
            (
                ManagedField::Annotation(ENDPOINT_AUTH_ANNOTATION.to_owned()),
                "managed".to_owned(),
            ),
        ])
    }

    fn write(
        actor: &str,
        operation: WriteOperation,
        provenance: Provenance,
    ) -> EndpointRoutingWrite {
        EndpointRoutingWrite {
            namespace: NamespaceName::new("user-alice"),
            actor: actor.to_owned(),
            operation,
            kind: RoutingKind::Ingress,
            provenance,
            changed_annotations: BTreeSet::new(),
            other_fields_changed: false,
            expected_managed: expected(),
            submitted_managed: expected(),
            carries_devworkspace_label: provenance == Provenance::Devfile,
            host_owned_by_namespace: Some(true),
        }
    }

    fn verdict(subject: &EndpointRoutingWrite) -> Decision<EndpointRoutingWrite> {
        let facts = NamespaceFacts {
            labels: Default::default(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new([]);
        let ctx = Context::new(&[], &facts, &catalog);
        guard().evaluate(subject, &ctx).unwrap()
    }

    #[test]
    fn row_1_to_3_the_three_identities_that_may_write_the_gate() {
        for actor in [OPERATOR, DWO, "system:serviceaccount:platform:break-glass"] {
            let mut subject = write(actor, WriteOperation::Update, Provenance::Devfile);
            // Even a write that tampers with the chain: these three are the writers.
            subject.submitted_managed.insert(
                ManagedField::Annotation(CHAIN.to_owned()),
                "evil".to_owned(),
            );
            assert!(!verdict(&subject).denial.is_some(), "{actor}");
        }
    }

    #[test]
    fn row_2_is_the_one_that_must_not_be_optimised_away() {
        // DWO rewrites these objects on its own schedule, including the annotations we add.
        // Denying it does not protect anything; it stops every workspace endpoint existing.
        let mut subject = write(DWO, WriteOperation::Update, Provenance::Devfile);
        subject.other_fields_changed = true;
        subject.changed_annotations = BTreeSet::from(["something.devfile/else".to_owned()]);
        assert!(!verdict(&subject).denial.is_some());
    }

    #[test]
    fn row_4_a_forged_devworkspace_label_is_refused() {
        let subject = write("alice", WriteOperation::Create, Provenance::Devfile);
        let decision = verdict(&subject);
        assert!(decision.denial.is_some());
        assert_eq!(decision.result, "denied_forged_label");
    }

    #[test]
    fn row_5_a_developer_may_create_their_own_endpoint() {
        let subject = write("alice", WriteOperation::Create, Provenance::Author);
        assert!(!verdict(&subject).denial.is_some());
    }

    #[test]
    fn a_host_this_namespace_does_not_own_is_refused_whoever_wrote_it() {
        for provenance in [Provenance::Author, Provenance::Devfile] {
            let mut subject = write("alice", WriteOperation::Create, provenance);
            subject.carries_devworkspace_label = false;
            subject.host_owned_by_namespace = Some(false);
            let decision = verdict(&subject);
            assert!(decision.denial.is_some(), "{provenance:?}");
            assert_eq!(decision.result, "denied_host_not_owned");
        }
    }

    #[test]
    fn row_6_the_gate_is_pinned_by_value_and_not_by_presence() {
        // A prepended `headers` middleware is a complete bypass performed with one annotation,
        // by the person the feature constrains: the chain runs *before* forwardAuth.
        let mut subject = write("alice", WriteOperation::Update, Provenance::Author);
        subject.submitted_managed.insert(
            ManagedField::Annotation(CHAIN.to_owned()),
            format!("user-alice-rewrite@kubernetescrd,{EXPECTED_CHAIN}"),
        );
        let decision = verdict(&subject);
        assert!(decision.denial.is_some());
        assert_eq!(decision.result, "denied_managed_field");

        // And removing it entirely is the same denial, not a different one.
        subject
            .submitted_managed
            .remove(&ManagedField::Annotation(CHAIN.to_owned()));
        assert!(verdict(&subject).denial.is_some());
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn row_6_covers_a_field_on_a_reverse_proxy_dialect_too() {
        // On OpenShift the gate *is* the backend: repointing `spec.to` removes it with an edit
        // no annotation check would see.
        let mut subject = write("alice", WriteOperation::Update, Provenance::Author);
        subject.kind = RoutingKind::Route;
        subject.expected_managed.insert(
            ManagedField::Path("spec.to"),
            "weebo-si-endpoint-gateway".to_owned(),
        );
        subject
            .submitted_managed
            .insert(ManagedField::Path("spec.to"), "my-app".to_owned());
        let decision = verdict(&subject);
        assert!(decision.denial.is_some());
        assert!(
            decision
                .denial
                .as_deref()
                .is_some_and(|m| m.contains("spec.to"))
        );
    }

    #[test]
    fn row_7_a_devfile_projection_is_edited_in_the_devfile() {
        let mut subject = write("alice", WriteOperation::Update, Provenance::Devfile);
        subject.carries_devworkspace_label = false;
        subject.other_fields_changed = true;
        let decision = verdict(&subject);
        assert!(decision.denial.is_some());
        assert_eq!(decision.result, "denied_devfile_projection");
    }

    #[test]
    fn the_delegation_annotations_are_the_developers_on_a_generated_object() {
        // The whole point of *Two ways in*: `kubectl annotate ... allow-users=bob,carol` must
        // work on the Ingress DWO generated, or "share now" needs a workspace restart.
        let mut subject = write("alice", WriteOperation::Update, Provenance::Devfile);
        subject.carries_devworkspace_label = false;
        subject.changed_annotations = BTreeSet::from([
            "hardening.weebo.io/allow-users".to_owned(),
            "hardening.weebo.io/rules".to_owned(),
        ]);
        assert!(!verdict(&subject).denial.is_some());
    }

    #[test]
    fn row_8_a_user_authored_object_stays_theirs() {
        let mut subject = write("alice", WriteOperation::Update, Provenance::Author);
        subject.other_fields_changed = true;
        subject.changed_annotations =
            BTreeSet::from(["nginx.ingress.kubernetes.io/proxy-body-size".to_owned()]);
        assert!(
            !verdict(&subject).denial.is_some(),
            "a control forbidding people to edit their own work is how controls get removed"
        );
    }

    #[test]
    fn row_9_delete_is_allowed_because_the_route_dies_with_the_gate() {
        let subject = write("alice", WriteOperation::Delete, Provenance::Devfile);
        assert!(!verdict(&subject).denial.is_some());
    }

    #[test]
    fn the_verdict_is_the_same_verdict_for_an_ingress_and_for_a_route() {
        // `kind` is a label, never a branch — RFC 0008's rule, which this subject inherits.
        let mut ingress = write("alice", WriteOperation::Update, Provenance::Author);
        ingress.submitted_managed.insert(
            ManagedField::Annotation(CHAIN.to_owned()),
            "evil".to_owned(),
        );
        let mut route = ingress.clone();
        route.kind = RoutingKind::Route;
        assert_eq!(verdict(&ingress).result, verdict(&route).result);
        assert_eq!(ingress.resource(), "Ingress");
        assert_eq!(route.resource(), "Route");
    }
}
