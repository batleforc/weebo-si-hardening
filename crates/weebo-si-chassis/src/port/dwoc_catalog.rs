//! Does this DWOC reference resolve — the watch, the cache and the informer are the adapter's
//! problem, and the fake is a `HashSet`.

use weebo_si_crd::DwocRef;

/// Does this DWOC reference resolve.
///
/// `Send + Sync` as a supertrait — not just annotated at each call site's `Arc<dyn DwocCatalog +
/// Send + Sync>` — because [`crate::Context`] stores a bare `&dyn DwocCatalog`. Without the
/// supertrait, that stored reference loses the Send/Sync annotation any particular caller's
/// concrete `Arc` had, which makes `Context` itself never `Send` — invisible until a caller holds
/// a `Context` across an `.await` (RFC 0004's `application::reconcile` is the first one).
pub trait DwocCatalog: Send + Sync {
    /// Whether `r` names a `DevWorkspaceOperatorConfig` that actually exists.
    fn resolves(&self, r: &DwocRef) -> bool;
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::collections::HashSet;

    use super::*;

    pub struct FakeDwocCatalog(HashSet<DwocRef>);

    impl FakeDwocCatalog {
        pub fn new(present: impl IntoIterator<Item = DwocRef>) -> Self {
            Self(present.into_iter().collect())
        }
    }

    impl DwocCatalog for FakeDwocCatalog {
        fn resolves(&self, r: &DwocRef) -> bool {
            self.0.contains(r)
        }
    }
}
