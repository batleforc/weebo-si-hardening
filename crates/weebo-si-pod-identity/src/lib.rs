//! The `pod-identity` feature — see RFC 0018.
//!
//! Every pod DevWorkspace Operator builds in a workspace namespace runs as one fixed, non-root
//! identity in its own user namespace (`hostUsers: false`), with no group 0. Two features share
//! one `FeatureId` and two pure functions: [`PodIdentityMutation`] rewrites the pod level with
//! [`identity_rewrite`] and never denies; [`PodIdentityValidation`] refuses what
//! [`identity_violations`] finds, after every mutation. Admission-only and stateless: the
//! decision reads the pod, the resolved config and the namespace's projected dwoc selection.
//!
//! Same dependency floor as `weebo-si-image-policy`: `weebo-si-crd` + `weebo-si-chassis` only.
//! The adapter projects the `Pod` into [`PodSubject`]; this crate never sees a `k8s-openapi` type.

pub mod feature;
pub mod port;
pub mod rewrite;
pub mod subject;
pub mod violation;

pub use feature::{FEATURE_ID, PodIdentityMutation, PodIdentityValidation};
pub use port::{Judged, PodIdentityObserver};
pub use rewrite::{Field, Rewrite, Value, identity_rewrite};
pub use subject::{Admission, ContainerIdentity, ContainerKind, PodSecurityContext, PodSubject};
pub use violation::{ContainerRef, Violation, identity_violations};
