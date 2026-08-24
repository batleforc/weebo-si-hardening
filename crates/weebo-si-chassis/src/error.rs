//! Domain errors. Never `kube::Error`, never an HTTP status — those belong to the adapters that
//! know what a Kubernetes API or an admission response is.

use std::fmt;

use weebo_si_crd::NamespaceName;

/// Something that stopped a domain computation from producing an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// The feature's own configuration violates an invariant reconcile-time validation should
    /// already have rejected — e.g. a resolved catalogue key that is not actually in the
    /// catalog. `evaluate` refuses to guess against unproven configuration rather than mutate
    /// on it.
    InvalidConfiguration(String),
    /// [`crate::port::namespace_view::NamespaceView::facts`] returned `None` for the subject's
    /// namespace. The `/readyz` gate should prevent this in production; if it happens anyway,
    /// admission refuses to treat an unobserved namespace as matching no team.
    NamespaceNotObserved(NamespaceName),
    /// An outbound port's real-world operation failed for a reason the domain cannot classify
    /// further — a `PolicyStore::apply` call rejected by the apiserver, for example. Unlike
    /// [`Self::InvalidConfiguration`] (this feature's own configuration is wrong) or
    /// [`Self::NamespaceNotObserved`] (a specific, anticipated cache-miss), this variant exists
    /// for a *reconcile* feature's ports, which — unlike every admission-side port so far — can
    /// genuinely fail at the point of writing rather than only report "not found." The domain
    /// still never sees `kube::Error` or any adapter-specific type; the adapter renders its
    /// failure into a string before it crosses into this crate.
    PortFailed(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(why) => write!(f, "invalid configuration: {why}"),
            Self::NamespaceNotObserved(ns) => write!(f, "namespace {ns} not observed"),
            Self::PortFailed(why) => write!(f, "port failed: {why}"),
        }
    }
}

impl std::error::Error for DomainError {}
