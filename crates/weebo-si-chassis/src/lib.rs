//! Operator-wide runtime abstractions: everything a hardening feature plugs into that is *not*
//! part of `WeeboSiConfig`'s own wire schema (that lives in `weebo-si-crd`). See RFC 0002's
//! *Architecture* section, "The feature trait, and the invariant."
//!
//! No `serde`, no `kube` — the strongest, fully compiler-enforced version of "a feature never
//! learns its own mode" and "the chassis never depends on a feature": this crate cannot even
//! name a JSON type, let alone a live cluster.

pub mod admit;
pub mod error;
pub mod feature;
pub mod managed;
pub mod mutation;
pub mod namespace_facts;
pub mod port;

pub use admit::{AdmitOutcome, admit};
pub use error::DomainError;
pub use feature::{
    Context, Decision, Feature, FeatureId, FeatureOutcome, ReconcileFeature, Registry, Subject,
};
pub use managed::{ObjectKey, PodSelector};
pub use mutation::Mutation;
pub use namespace_facts::NamespaceFacts;
