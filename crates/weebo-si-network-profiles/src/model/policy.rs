//! `ManagedObject` — one policy object this feature owns, and the opaque body it copies from a
//! template. See RFC 0004's *Design → Architecture*, "`PolicyBody` is opaque."

use weebo_si_crd::{Backend, NamespaceName, ProfileKey};

/// A namespace-scoped object's `{namespace, name}` identity — the diff key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    /// The namespace the object lives in.
    pub namespace: NamespaceName,
    /// The object's name.
    pub name: String,
}

/// The pod (or endpoint) selector a `ManagedObject` carries. An enum rather than a raw label
/// map so a baseline object can never accidentally be constructed with a workspace selector, or
/// a profile object with the baseline's "every pod" selector — the two have very different
/// blast radii and the type keeps them from being confused at a call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodSelector {
    /// `{}` — every pod in the namespace. Only ever the baseline's.
    Empty,
    /// `controller.devfile.io/devworkspace_id: <id>` — one workspace's pods. Only ever a
    /// profile object's.
    DevWorkspaceId(String),
}

/// A template's `policyTypes`/`ingress`/`egress` (or the Cilium equivalent), copied verbatim and
/// never *interpreted* — see the RFC's "the operator never parses a rule." The domain's own
/// decision logic (`desired()`, `compute_diff`) never calls [`PolicyBody::as_bytes`]; it only
/// compares bodies for equality and clones them. [`PolicyBody::as_bytes`] exists for the one
/// place that legitimately needs the bytes back out — a `PolicyStore` adapter serializing a
/// `ManagedObject` into the real `NetworkPolicy`/`CiliumNetworkPolicy` object it writes, which is
/// mechanical I/O, not a decision. That boundary is enforced by which crate can see this type at
/// all (`weebo-si-network-profiles`'s own domain code vs. `weebo-si-runtime`'s adapters), not by
/// withholding the accessor — a `TemplateStore`/`PolicyStore` adapter cannot do its job without
/// reading and writing these bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBody(Vec<u8>);

impl PolicyBody {
    /// Wrap a template's rule content. The caller (a `TemplateStore` adapter) is trusted to have
    /// copied it verbatim from the template object — this type does not, and cannot, check that.
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes, for a `PolicyStore` adapter to serialize into the object it writes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One policy object this feature owns: a baseline (one per namespace in scope) or a profile
/// object (one per workspace per selected key). The difference between the two is entirely in
/// `profile`/`pod_selector`, not in a separate type — see RFC 0004's *Design*, "the two objects
/// written."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedObject {
    /// This object's identity.
    pub key: ObjectKey,
    /// Which dialect this object is written in.
    pub backend: Backend,
    /// The catalogue key this object was built from — carried in the
    /// `hardening.weebo.io/profile` label.
    pub profile: ProfileKey,
    /// Which pods this object governs.
    pub pod_selector: PodSelector,
    /// The rule content, copied verbatim from the resolved template.
    pub body: PolicyBody,
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
    fn policy_bodies_with_equal_bytes_are_equal() {
        let a = PolicyBody::opaque(b"same".to_vec());
        let b = PolicyBody::opaque(b"same".to_vec());
        assert_eq!(a, b);
    }

    #[test]
    fn policy_bodies_with_different_bytes_are_not_equal() {
        let a = PolicyBody::opaque(b"one".to_vec());
        let b = PolicyBody::opaque(b"other".to_vec());
        assert_ne!(a, b);
    }
}
