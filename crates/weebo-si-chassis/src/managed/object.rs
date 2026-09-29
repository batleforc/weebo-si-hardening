//! `ObjectKey`, `PodSelector` and `Owner` — see this module's parent for why they live in the
//! chassis.

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

/// The object a managed object is garbage-collected with — in practice always the DevWorkspace a
/// profile object was written for, per RFC 0004's *The objects written*: "Profile objects carry
/// an `ownerReference` to their DevWorkspace, so the apiserver garbage collects them when the
/// workspace is deleted." The baseline carries none, because a namespace outliving its
/// workspaces must keep its floor.
///
/// Plain strings rather than a `kube` type, for the reason this crate names no `kube` type at all:
/// a store adapter turns this into `metadata.ownerReferences` (and reads it back), and the
/// domain only ever carries it from the subject into the object and compares it.
///
/// `api_version` and `kind` are carried rather than implied: the garbage collector resolves the
/// owner through exactly the `apiVersion` written, so it has to be the one the controller
/// actually read the owner's `uid` from — something only the adapter building the subject knows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Owner {
    /// The owner's `apiVersion`, e.g. `group/version`.
    pub api_version: String,
    /// The owner's `kind`.
    pub kind: String,
    /// The owner's `metadata.name`.
    pub name: String,
    /// The owner's `metadata.uid` — what the garbage collector actually matches on, so a
    /// workspace deleted and recreated under the same name is a *different* owner.
    pub uid: String,
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
