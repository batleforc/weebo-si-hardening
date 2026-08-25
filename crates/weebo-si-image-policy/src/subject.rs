//! The two bounded projections this feature is entitled to see — RFC 0005's *Architecture*.
//!
//! A `Subject` is what one feature may look at, not a shared type every feature widens: the
//! pattern `weebo-si-dwoc-pin`'s `Workspace` and `weebo-si-network-profiles`'
//! `WorkspaceAdmission` established. Neither type here carries a `Container`, a `Pod` or a
//! `DevWorkspace` — an image is a `String` in the domain and a `String` in the adapter, which is
//! what keeps this crate's dependency list at two and its test suite fixture-free.

use weebo_si_chassis::Subject;
use weebo_si_crd::NamespaceName;

use crate::variable::VariableValues;

/// One container's image, as the adapter read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerImage {
    /// The container or devfile component name — what the denial message names, because
    /// "component `tools`" is actionable where "one of this workspace's images" is not.
    pub name: String,
    /// The reference **exactly as the user wrote it**. Not parsed here: the adapter must hand
    /// the domain the raw string, or normalization happens twice and the two copies can drift.
    pub reference: String,
}

impl ContainerImage {
    /// Build one.
    pub fn new(name: impl Into<String>, reference: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            reference: reference.into(),
        }
    }
}

/// A `DevWorkspace` under admission — the selection-precise half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceImages {
    /// The workspace's name, for the denial message.
    pub name: String,
    /// The namespace it is being written in.
    pub namespace: NamespaceName,
    /// `spec.template.components[*].container.image`, in devfile order.
    ///
    /// `spec.template.components[].plugin` and `spec.contributions[]` are deliberately **not**
    /// here. They name a plugin by URI or id, DevWorkspace Operator resolves them to images long
    /// after admission, and a resolver we wrote would be a second implementation of somebody
    /// else's resolution that is wrong the day theirs changes. [`PodImages`] sees the result,
    /// which is the honest place to check it.
    pub images: Vec<ContainerImage>,
    /// The workspace's own selection attribute, if it carries one.
    pub attribute: Option<String>,
    /// The namespace annotation, read through `NamespaceView::annotation`.
    pub namespace_annotation: Option<String>,
    /// Already-resolved values for the variables `spec.variables` **declared**, and only those.
    ///
    /// Not a raw annotation bag: the adapter reads only the declared keys and validates each
    /// value before it lands here, so an illegal one is *absent* rather than present and
    /// dangerous. The two built-ins are not here either — `{TEAM_NAME}` is not known until the
    /// resolution chain runs and `{NAMESPACE}` is derivable from the field above, so both are
    /// bound by the feature rather than trusted from an adapter that could get them wrong.
    pub variables: VariableValues,
}

impl Subject for WorkspaceImages {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
}

/// A `Pod` under admission — the team-boundary floor.
///
/// **Carries no selection attribute and no selection annotation**, which is the type-level
/// statement of RFC 0005's "team boundary, not selection" decision: there is no field a later
/// change could start reading a workspace's own selection from, so the Pod half cannot quietly
/// grow the DevWorkspace watch, the new RBAC and the startup race that resolving one would cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodImages {
    /// The pod's name, for the denial message and the event.
    pub name: String,
    /// The namespace it is being created in.
    pub namespace: NamespaceName,
    /// `spec.containers[*]`, `spec.initContainers[*]` and `spec.ephemeralContainers[*]`, in that
    /// order. Which list a container came from is not carried: the verdict does not depend on
    /// it, and the name is what the error message needs.
    pub images: Vec<ContainerImage>,
    /// The same declared-variable map [`WorkspaceImages`] carries, populated by the same adapter
    /// code — which is what makes "variables resolve identically at both layers" a consequence
    /// of the types rather than a promise. Every variable derives from the subject's namespace,
    /// and a `Pod` carries its namespace exactly as a `DevWorkspace` does.
    pub variables: VariableValues,
}

impl Subject for PodImages {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }
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
    fn both_subjects_report_their_namespace_to_the_chassis() {
        let workspace = WorkspaceImages {
            name: "data-pipeline".to_string(),
            namespace: NamespaceName::new("user-alice"),
            images: Vec::new(),
            attribute: None,
            namespace_annotation: None,
            variables: VariableValues::new(),
        };
        let pod = PodImages {
            name: "scratch-abc123".to_string(),
            namespace: NamespaceName::new("user-bob"),
            images: Vec::new(),
            variables: VariableValues::new(),
        };
        assert_eq!(workspace.namespace().as_str(), "user-alice");
        assert_eq!(pod.namespace().as_str(), "user-bob");
    }

    /// The compile-time claim in [`PodImages`]'s own docs, as a test a reviewer can run.
    ///
    /// A textual check rather than a type-level one, because "this struct has no field of that
    /// shape" is not something the type system can be asked. It fires when someone adds a
    /// selection-shaped field to `PodImages` — which is exactly the change RFC 0005's *Two
    /// enforcement points* argues costs new RBAC, a fleet-scaled cache and a startup race, and
    /// therefore belongs in an RFC rather than in a struct.
    #[test]
    fn the_pod_subject_exposes_no_path_to_a_workspace_selection() {
        let source = include_str!("subject.rs");
        let pod_struct = source
            .split("pub struct PodImages {")
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_default();
        assert!(
            !pod_struct.is_empty(),
            "PodImages' definition should be findable"
        );
        for forbidden in ["attribute", "namespace_annotation", "workspace"] {
            assert!(
                !pod_struct.contains(&format!("pub {forbidden}")),
                "PodImages must not carry a `{forbidden}` field — the Pod half enforces the team \
                 boundary, not the per-workspace selection (RFC 0005, Two enforcement points)"
            );
        }
    }
}
