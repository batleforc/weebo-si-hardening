//! A namespace, as far as this workspace is entitled to know it.

use std::collections::BTreeMap;

/// Labels plus the one selection annotation, and nothing else. The projection is bounded here
/// in the domain type so a watch-backed cache (`weebo-si-runtime`) can drop the rest of a
/// `Namespace` object, and so no feature can quietly start depending on its `spec` or `status`.
///
/// Deliberately **not** part of `WeeboSiConfig`'s wire schema — a `Namespace` isn't ours, so
/// this lives in the chassis rather than `weebo-si-crd`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceFacts {
    /// The namespace's labels — what a [`weebo_si_crd::Team`]'s and a [`weebo_si_crd::Selector`]'s
    /// selector match against.
    pub labels: BTreeMap<String, String>,
    /// The already-projected value of `namespaceSelection.annotation`, if the namespace carries
    /// it. `None` covers two cases the domain does not need to distinguish: the namespace lacks
    /// the annotation, and `namespaceSelection.annotation` is the empty string (selection
    /// disabled) — both mean the namespace-annotation resolution step contributes nothing.
    pub selection_annotation: Option<String>,
}
