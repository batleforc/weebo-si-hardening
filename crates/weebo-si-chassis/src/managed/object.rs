//! `ObjectKey` and `PodSelector` — see this module's parent for why they live in the chassis.

use weebo_si_crd::NamespaceName;

/// A namespace-scoped object's `{namespace, name}` identity — the diff key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    /// The namespace the object lives in.
    pub namespace: NamespaceName,
    /// The object's name.
    pub name: String,
}

/// The pod selector a managed object carries. An enum rather than a raw label map so a baseline
/// object can never accidentally be constructed with a workspace selector, or a profile object
/// with the baseline's "every pod" selector — the two have very different blast radii and the
/// type keeps them from being confused at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodSelector {
    /// `{}` — every pod in the namespace. Only ever the baseline's.
    Empty,
    /// `controller.devfile.io/devworkspace_id: <id>` — one workspace's pods. Only ever a
    /// profile object's.
    DevWorkspaceId(String),
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
    fn two_keys_in_different_namespaces_are_different_objects() {
        let alice = ObjectKey {
            namespace: NamespaceName::new("user-alice"),
            name: "weebo-base".to_string(),
        };
        let bob = ObjectKey {
            namespace: NamespaceName::new("user-bob"),
            name: "weebo-base".to_string(),
        };
        assert_ne!(alice, bob);
    }

    #[test]
    fn the_baseline_selector_and_a_workspace_selector_are_never_equal() {
        assert_ne!(
            PodSelector::Empty,
            PodSelector::DevWorkspaceId("workspacede4f56".to_string())
        );
    }

    #[test]
    fn two_workspace_selectors_differ_by_workspace_id() {
        assert_ne!(
            PodSelector::DevWorkspaceId("one".to_string()),
            PodSelector::DevWorkspaceId("two".to_string())
        );
    }
}
