//! Everything this binary plugs into `weebo-si-endpoint-auth`'s ports.
//!
//! The split is the one `docs/architecture/hexagonal.md` describes, with the crate holding the
//! domain and this binary holding the adapters — a departure from RFC 0009's *Architecture*,
//! which put the adapters in the crate, and one made for a reason RFC 0002's own amendment
//! already established: the operator (`weebo-si-webhook`, `weebo-si-controller`,
//! `weebo-si-policy-guard`) depends on the decision's vocabulary, and would otherwise link
//! `reqwest`, `aes-gcm`, `jsonwebtoken` and a Kubernetes client to read a type.

pub mod kube_catalog;
pub mod kube_revocations;
pub mod kube_workload;
pub mod metrics;
pub mod oidc;
pub mod session;
