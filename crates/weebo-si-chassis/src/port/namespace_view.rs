//! The labels and the selection annotation of a namespace — the bounded projection the
//! watch-backed cache (`weebo-si-runtime`) stores instead of the full `Namespace` object.

use weebo_si_crd::NamespaceName;

use crate::namespace_facts::NamespaceFacts;

/// The labels and the selection annotation of a namespace.
pub trait NamespaceView {
    /// The namespace's labels and selection annotation, or `None` if it has not been observed.
    fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts>;

    /// An arbitrary annotation, by key, or `None` if the namespace is unobserved, lacks it, or
    /// `key` is empty (a feature's own "selection disabled" convention).
    ///
    /// **Why this exists alongside `facts().selection_annotation`**: that field is a single slot
    /// shaped for `dwoc-pin`'s one, fixed annotation key — RFC 0004's `network-profiles` reads a
    /// *different* key from the same namespace, and a second fixed slot would not scale to a
    /// third feature either. This method is the general form; `facts()` stays as the
    /// convenience `dwoc-pin` already depends on, unchanged.
    fn annotation(&self, ns: &NamespaceName, key: &str) -> Option<String>;
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::HashMap;

    use super::*;

    pub struct FakeNamespaceView(HashMap<NamespaceName, NamespaceFacts>);

    impl FakeNamespaceView {
        pub fn new(facts: impl IntoIterator<Item = (NamespaceName, NamespaceFacts)>) -> Self {
            Self(facts.into_iter().collect())
        }
    }

    impl NamespaceView for FakeNamespaceView {
        fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts> {
            self.0.get(ns).cloned()
        }

        fn annotation(&self, _ns: &NamespaceName, _key: &str) -> Option<String> {
            None
        }
    }
}
