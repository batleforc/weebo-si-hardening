//! `ManagedObject` — one `KubeArmorPolicy` this feature owns, and the opaque body it copies from
//! a template. See RFC 0006's *Design → Architecture*.
//!
//! [`ObjectKey`] and [`PodSelector`] are the chassis' — promoted there by this RFC's own
//! *Implementation plan* precisely so this module does not redefine them. KubeArmor selects pods
//! by `matchLabels` exactly as `NetworkPolicy` does, so "the baseline selects every pod, a
//! profile object selects one workspace" is one rule with one home.
//!
//! [`RuleBody`] is **not** shared with `network-profiles`' `PolicyBody`, despite both being
//! opaque bytes. They document different contents — five rule sections here
//! (`process`/`file`/`network`/`capabilities`/`syscalls`) against `policyTypes`/`ingress`/
//! `egress` there — and nothing in the chassis' diff needs to name either: `Managed::content_eq`
//! compares bodies inside the feature that owns them. Sharing the type would buy a rename across
//! two adapter crates and cost the doc comment that tells a reader what the bytes actually are.

pub use weebo_si_chassis::managed::{ObjectKey, PodSelector};
use weebo_si_crd::{RuntimeBackend, RuntimeProfileKey};

/// A template's `spec.process`, `spec.file`, `spec.network`, `spec.capabilities` and
/// `spec.syscalls`, copied verbatim and never *interpreted* — this brick never reads a rule, per
/// RFC 0006's *Guide-level explanation*: "This brick never reads their rules — it copies
/// `spec.process`, `spec.file`, `spec.network`, `spec.capabilities` and `spec.syscalls`
/// verbatim."
///
/// The domain's own decision logic never calls [`RuleBody::as_bytes`]; it only compares bodies
/// for equality and clones them. The accessor exists for the one place that legitimately needs
/// the bytes back out — a [`crate::port::PolicyStore`] adapter serializing a [`ManagedObject`]
/// into the real `KubeArmorPolicy` it writes, which is mechanical I/O, not a decision. That
/// boundary is enforced by which crate can see this type at all (this crate's domain code vs.
/// `weebo-si-runtime`'s adapters), not by withholding the accessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleBody(Vec<u8>);

impl RuleBody {
    /// Wrap a template's rule content. The caller (a [`crate::port::TemplateStore`] adapter) is
    /// trusted to have copied it verbatim from the template object — this type does not, and
    /// cannot, check that.
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The wrapped bytes, for a [`crate::port::PolicyStore`] adapter to serialize into the object
    /// it writes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One `KubeArmorPolicy` this feature owns: a baseline (one per namespace in scope) or a profile
/// object (one per workspace per selected key). The difference between the two is entirely in
/// `profile`/`pod_selector`, not in a separate type — same split `network-profiles` makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedObject {
    /// This object's identity.
    pub key: ObjectKey,
    /// Which engine this object is written for.
    pub backend: RuntimeBackend,
    /// The catalogue key this object was built from — carried in the
    /// `hardening.weebo.io/profile` label.
    pub profile: RuntimeProfileKey,
    /// Which pods this object governs.
    pub pod_selector: PodSelector,
    /// The rule content, copied verbatim from the resolved template.
    pub body: RuleBody,
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
    fn rule_bodies_with_equal_bytes_are_equal() {
        assert_eq!(
            RuleBody::opaque(b"same".to_vec()),
            RuleBody::opaque(b"same".to_vec())
        );
    }

    #[test]
    fn rule_bodies_with_different_bytes_are_not_equal() {
        assert_ne!(
            RuleBody::opaque(b"one".to_vec()),
            RuleBody::opaque(b"other".to_vec())
        );
    }

    #[test]
    fn a_rule_body_hands_back_exactly_the_bytes_it_was_given() {
        // The verbatim-copy guarantee, as an executable assertion: nothing between
        // `TemplateStore` and `PolicyStore` normalises, reorders or reserialises a rule.
        let bytes = b"{\"process\":{\"matchPaths\":[{\"path\":\"/usr/bin/git\"}]}}".to_vec();
        assert_eq!(RuleBody::opaque(bytes.clone()).as_bytes(), bytes.as_slice());
    }
}
