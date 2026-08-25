//! The `policy-guard` feature — see [RFC 0004](../../../docs/rfc/0004-network-profiles.md) for
//! the three-row verdict table, and [RFC 0008](../../../docs/rfc/0008-policy-guard-coverage.md)
//! for why it lives here rather than inside `weebo-si-network-profiles`.
//!
//! ## Why a crate of its own
//!
//! RFC 0004 introduced the guard alongside `network-profiles`, so it shipped inside that crate.
//! That placement became wrong the moment a second brick started writing objects into workspace
//! namespaces: `weebo-si-kubearmor-policy` would have to depend on `weebo-si-network-profiles`
//! to be guarded by it, which is a dependency between two sibling features with nothing to say
//! to each other.
//!
//! Here, the guard depends on `weebo-si-crd` + `weebo-si-chassis` only, and **every feature
//! crate stays unaware of it** — the webhook's composition root is the one place that knows both
//! the guard and the features whose objects it protects.
//!
//! ## The one thing not to add
//!
//! [`GuardedWrite::resource`] is a metric label and a log field, never a branch. A `match` on it
//! inside [`PolicyGuard::evaluate`] would be the first step toward a guard that protects some of
//! this operator's objects more than others, and the guard's whole claim is that they are
//! equally its own.

pub mod guard;
pub mod resource;

pub use guard::{GuardedWrite, PolicyGuard, WriteOperation};
pub use resource::GuardedResource;
