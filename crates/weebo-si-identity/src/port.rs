//! The ports this feature talks to the world through.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use serde_json::Value;
use weebo_si_chassis::DomainError;
use weebo_si_crd::TargetState;

/// One object this operator would write for one person, fully rendered.
///
/// Deliberately untyped in its `spec`: the two kinds this feature writes belong to two other
/// projects, and depending on their Rust types would be depending on their whole schemas. The
/// mapping from a `WeeboSiUser` to these few fields is RFC 0011's *What gets created*, and the
/// tests that pin it read like that table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredObject {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.namespace`, absent for a cluster-scoped kind.
    pub namespace: Option<String>,
    /// `metadata.labels` — always carrying `app.kubernetes.io/managed-by`.
    pub labels: BTreeMap<String, String>,
    /// The `spec` block, verbatim.
    pub spec: Value,
    /// The `WeeboSiUser` this object belongs to. Written as an `ownerReference`, which is what
    /// makes deleting the person delete what was created for them — this operator never needs,
    /// and never holds, a `delete` verb on either kind.
    pub owner: ObjectOwner,
}

/// The `WeeboSiUser` an object is owned by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectOwner {
    /// `ownerReferences[].apiVersion`.
    pub api_version: String,
    /// `ownerReferences[].kind`.
    pub kind: String,
    /// `ownerReferences[].name`.
    pub name: String,
    /// `ownerReferences[].uid` — the field that makes ownership unforgeable, and the one that
    /// tells a second `WeeboSiUser` claiming the same target apart from the first.
    pub uid: String,
}

/// What the cluster holds under one name right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The kind itself is not served by this cluster — the Authentik operator or Argo CD is not
    /// installed. Reported, never treated as "nothing there yet": creating is impossible, and
    /// saying so is the difference between a missing dependency and a missing object.
    KindAbsent,
    /// Nothing under that name.
    Missing,
    /// Something under that name.
    Present {
        /// The `uid` of the `WeeboSiUser` that owns it, if any owns it. `None` means the object
        /// belongs to somebody else — an admin, another operator — and is therefore read-only
        /// to this loop, whatever it contains.
        owner_uid: Option<String>,
        /// Its current `spec`, for the "already what we would write" comparison.
        spec: Value,
    },
}

/// Boxed future, because this port is called through `&dyn Provisioner` and native `async fn` in
/// a trait is not object-safe — the same shape `weebo-si-kubearmor-policy`'s `PolicyStore::apply`
/// uses, and for the same reason.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DomainError>> + Send + 'a>>;

/// Reading and writing one provisioned kind.
///
/// **One port, two instances** — the `AuthentikUser` handle and the `Application` handle — where
/// RFC 0011 first proposed two traits. They would have had identical methods over identical
/// types, and the one difference that matters (cluster-scoped versus namespaced) is already in
/// [`DesiredObject::namespace`]. Two handles keep what two traits were for: a cluster with
/// Authentik and no Argo CD wires one and leaves the other reporting
/// [`Observation::KindAbsent`].
pub trait Provisioner: Send + Sync {
    /// The kind this handle writes, for log lines, metric labels and conditions.
    fn kind(&self) -> &'static str;

    /// What the cluster holds under `name` (in `namespace`, for a namespaced kind).
    fn observe<'a>(
        &'a self,
        name: &'a str,
        namespace: Option<&'a str>,
    ) -> PortFuture<'a, Observation>;

    /// Create or update `desired`. Never deletes: what this operator created goes away with the
    /// `WeeboSiUser` that owns it, through garbage collection.
    fn apply<'a>(&'a self, desired: &'a DesiredObject) -> PortFuture<'a, ()>;
}

/// Where every pass reports what it did, for the metrics RFC 0011's *Observability* names.
pub trait ProvisionObserver: Send + Sync {
    /// One team reconciled, with or without violations.
    fn team_reconciled(&self, degraded: bool);
    /// One person's one target reconciled, with the state it reached.
    fn user_reconciled(&self, kind: &str, state: TargetState);
    /// One port call failed. Counted separately from a `Conflict` or an `Absent`, which are
    /// answers rather than failures.
    fn provision_failed(&self, kind: &str);
}
