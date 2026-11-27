//! The write port the three reconcile subjects share: RFC 0020's `ToolsNamespaceStore` and
//! `RequesterStore` are one trait here, because both read label-filtered objects of one key in
//! one namespace and apply a diff; what differs is whether an existing object is adopted.

use std::future::Future;
use std::pin::Pin;

use weebo_si_chassis::ObjectKey;
use weebo_si_chassis::managed::{Applied, Diff};
use weebo_si_crd::{NamespaceName, ToolKey};
use weebo_si_team_tools::{ToolObject, ToolObjectKind};

/// A boxed future, so the store can be called through `&dyn`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why a write did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The apiserver answered 403 in this namespace: no RoleBinding there.
    Forbidden(NamespaceName),
    /// Anything else.
    Failed(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forbidden(namespace) => write!(f, "forbidden (403) in namespace {namespace}"),
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

/// Whether an existing object lacking `managed-by` may be taken over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    /// The tools namespace: phase-0 objects are adopted by a forced server-side apply, never
    /// deleted and re-created (RFC 0020, *Integration*, Resolved 16).
    Adopt,
    /// A workspace namespace: an object of the same name the user owns is left alone.
    Never,
}

/// The objects this feature wrote, and the writes.
pub trait ToolObjectStore: Send + Sync {
    /// Every object of `tool` in `namespace` carrying `managed-by`, as the diff compares them
    /// (see [`crate::objects::from_live`]).
    fn managed(&self, namespace: &NamespaceName, tool: &ToolKey) -> Vec<ToolObject>;

    /// Apply every line of `diffs`. A workload is created at 0 replicas and never has
    /// `spec.replicas` in a later apply.
    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff<ToolObject>],
        adoption: Adoption,
    ) -> BoxFuture<'a, Result<Applied, StoreError>>;

    /// Write `replicas` through the `/scale` subresource under
    /// [`weebo_si_team_tools::SCALE_FIELD_MANAGER`].
    fn scale<'a>(
        &'a self,
        kind: ToolObjectKind,
        workload: &'a ObjectKey,
        replicas: i32,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}
