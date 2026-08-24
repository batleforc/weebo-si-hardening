//! The labels and the selection annotation of a namespace — the bounded projection the
//! watch-backed cache (`weebo-si-runtime`) stores instead of the full `Namespace` object.

use weebo_si_crd::NamespaceName;

use crate::namespace_facts::NamespaceFacts;

/// The labels and the selection annotation of a namespace.
pub trait NamespaceView {
    /// The namespace's labels and selection annotation, or `None` if it has not been observed.
    fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts>;
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
    }
}
