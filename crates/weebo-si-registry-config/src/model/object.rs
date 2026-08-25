//! `ManagedObject` — one `ConfigMap` or `Secret` this feature owns — and [`ObjectBody`], the
//! opaque payload it carries from a template into a workspace namespace.
//!
//! [`ObjectKey`] is the chassis'. [`PodSelector`] is deliberately **not** used here and not
//! re-exported: an automounted object carries no selector at all, which is the whole of RFC
//! 0007's *The unit is the namespace, not the workspace*. A type in this module that could
//! express "this object governs one workspace" would be a type describing something no mechanism
//! can deliver.

use std::collections::BTreeMap;

pub use weebo_si_chassis::managed::ObjectKey;
use weebo_si_crd::{RegistryKey, SourceKind};

/// A template's `data`, `binaryData`, `stringData` and `type`, copied verbatim and never
/// *interpreted*.
///
/// **Typed opaque on purpose, and more strictly than its siblings.** `network-profiles`'
/// `PolicyBody` and `kubearmor-policy`'s `RuleBody` are opaque because nothing in the domain
/// needs their contents; this one is opaque because something in the domain must never be able
/// to *reach* them. RFC 0007's *Architecture*: "`TemplateStore` here reads `Secret` objects,
/// which no port in this project has done before. It is typed to return an opaque body that the
/// domain compares and copies but cannot destructure, so that 'the domain never sees credential
/// material in a form it could log' is a property of the type rather than a review convention."
///
/// Concretely, that means three things this type does and its siblings do not:
///
/// * **No `Debug` derive.** A `#[derive(Debug)]` here would put a decoded token in any
///   `dbg!`/`{:?}` of a `ManagedObject`, including the ones a controller writes for a diff.
///   [`ManagedObject`]'s own `Debug` prints this field as a redaction marker and a length.
/// * **No `Display`, no `as_str`, no `AsRef<[u8]>`.** The only way back out is
///   [`ObjectBody::into_bytes`], which consumes the value, so a body cannot be borrowed for a
///   format argument at all.
/// * **`PartialEq` is the whole API the domain uses.** Comparing two bodies is what the diff
///   needs; reading one is not.
#[derive(Clone, PartialEq, Eq)]
pub struct ObjectBody(Vec<u8>);

impl ObjectBody {
    /// Wrap a template's payload. The caller (a [`crate::port::TemplateStore`] adapter) is
    /// trusted to have copied it verbatim — this type does not, and cannot, check that.
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// How many bytes this body carries. Safe to log: a length is not a credential, and it is
    /// what makes a "the body changed" log line useful at all.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this body is empty — a template with no `data` at all, which is legal and
    /// occasionally intentional.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The wrapped bytes, for a [`crate::port::ObjectStore`] adapter to serialize into the
    /// object it writes.
    ///
    /// **Consumes the body**, unlike its siblings' borrowing accessors. That is the point: an
    /// adapter that needs the bytes takes ownership of a clone at the moment it writes, and no
    /// call site can borrow them for a `format!` while the object it came from is still alive.
    /// RFC 0007's *Data and state*: the adapter "holds them between a `get` and an `apply`."
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Prints the length and nothing else — never the bytes, per RFC 0007's *Security
/// considerations*: "Logs and metrics carry the namespace, team, key, source kind and object
/// name — never a key of `data`, never a value, and never a content diff."
impl core::fmt::Debug for ObjectBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ObjectBody(<redacted, {} bytes>)", self.0.len())
    }
}

/// A template object as a [`crate::port::TemplateStore`] hands it back: the labels and
/// annotations that decide how it mounts, plus the payload nothing reads.
///
/// Deliberately not a [`ManagedObject`] with a placeholder key. A template lives in the operator
/// namespace and has no identity in a workspace namespace at all — the copy's name is computed
/// from the catalogue key and the template's name, not carried from the template — and a type
/// that made the two interchangeable would let a caller apply a template as if it were already a
/// copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// The template's own labels. Carries DevWorkspace Operator's automount label; read only by
    /// [`crate::model::mount`], copied verbatim otherwise.
    pub labels: BTreeMap<String, String>,
    /// The template's own annotations. Carries `mount-as` and `mount-path`.
    pub annotations: BTreeMap<String, String>,
    /// The payload, opaque.
    pub body: ObjectBody,
}

/// One `ConfigMap` or `Secret` this feature owns: a copy of a catalogue entry's template, in a
/// workspace namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedObject {
    /// This object's identity.
    pub key: ObjectKey,
    /// Which kind of object this is. The diff's `Backend`, in the chassis' vocabulary — an
    /// adapter needs it to know which API to issue a delete against.
    pub kind: SourceKind,
    /// The catalogue key this object was built from — carried in the
    /// `hardening.weebo.io/profile` label.
    pub entry: RegistryKey,
    /// The template's own labels, copied verbatim except for this operator's own
    /// `hardening.weebo.io/`-prefixed keys, which an adapter adds. Carries DevWorkspace
    /// Operator's automount label, which is the reason the copy does anything at all.
    pub labels: BTreeMap<String, String>,
    /// The template's own annotations, copied verbatim. Carries `mount-as` and `mount-path`.
    pub annotations: BTreeMap<String, String>,
    /// The payload, copied verbatim from the resolved template.
    pub body: ObjectBody,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::NamespaceName;

    use super::*;

    fn object(body: &[u8]) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-si-internal-npm-weebo-npm-token".to_string(),
            },
            kind: SourceKind::Secret,
            entry: RegistryKey::new("internal-npm"),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            body: ObjectBody::opaque(body.to_vec()),
        }
    }

    #[test]
    fn bodies_with_equal_bytes_are_equal() {
        assert_eq!(
            ObjectBody::opaque(b"same".to_vec()),
            ObjectBody::opaque(b"same".to_vec())
        );
    }

    #[test]
    fn bodies_with_different_bytes_are_not_equal() {
        assert_ne!(
            ObjectBody::opaque(b"one".to_vec()),
            ObjectBody::opaque(b"other".to_vec())
        );
    }

    #[test]
    fn a_body_hands_back_exactly_the_bytes_it_was_given() {
        // The verbatim-copy guarantee, as an executable assertion: nothing between
        // `TemplateStore` and `ObjectStore` normalises or reserialises a payload.
        let bytes = b"{\"data\":{\".npmrc\":\"cmVnaXN0cnk9\"}}".to_vec();
        assert_eq!(
            ObjectBody::opaque(bytes.clone()).into_bytes(),
            bytes.as_slice()
        );
    }

    #[test]
    fn a_bodys_debug_output_carries_no_payload_byte() {
        // The property RFC 0007 asks the *type* to hold rather than a review convention: a
        // `{:?}` of anything containing a body must not be a credential disclosure.
        let rendered = format!(
            "{:?}",
            ObjectBody::opaque(b"hunter2-the-real-token".to_vec())
        );
        assert!(
            !rendered.contains("hunter2"),
            "a body's Debug must not print its bytes: {rendered}"
        );
        assert!(rendered.contains("22 bytes"), "but a length is useful");
    }

    #[test]
    fn a_managed_objects_debug_output_carries_no_payload_byte_either() {
        // The realistic call site: a controller printing a diff line, not a body directly.
        let rendered = format!("{:?}", object(b"hunter2-the-real-token"));
        assert!(
            !rendered.contains("hunter2"),
            "a managed object's Debug must not print its body: {rendered}"
        );
        assert!(
            rendered.contains("internal-npm"),
            "but the provenance a log line needs is still there"
        );
    }

    #[test]
    fn an_empty_body_is_a_legal_body() {
        let empty = ObjectBody::opaque(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }
}
