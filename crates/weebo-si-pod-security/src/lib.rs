//! The `pod-security` feature — see RFC 0013.
//!
//! **This crate writes no admission code.** The kube-apiserver's built-in `PodSecurity` admission
//! plugin evaluates pods against the Pod Security Standards; this feature only decides which
//! level each workspace namespace carries, and remembers what the namespace carried before so that
//! `mode: Off` puts it back. A second implementation of the standards here would be wrong the
//! first time upstream changes a check.
//!
//! What is decided here, and tested without a cluster:
//!
//! * **The resolution** ([`resolve`]): team level or cluster default, a tighten-only namespace
//!   annotation, a clamp to the ceiling, a warn level never looser than the enforce level.
//! * **What is written** ([`feature`]): exactly six labels and one annotation, nothing when a
//!   level somebody else set is already stricter, and the `-previous` annotation written once.
//! * **What leaving restores** ([`model::restore`]): the six keys as they were found.
//!
//! **No `exclusion` module**, like the sibling bricks: structural exclusions are asked once by
//! the controller loop reconciling every feature.

pub mod application;
pub mod feature;
pub mod model;
pub mod port;
pub mod resolve;

pub use application::{
    NamespaceState, ReconcileOutcome, ReconcileResult, TeardownOutcome, reconcile, teardown,
};
pub use feature::pod_security::{NamespaceSubject, PodSecurityFeature};
pub use model::backend::{EffectiveBackend, effective_backend};
pub use model::labels::{
    AUDIT, AUDIT_VERSION, ENFORCE, ENFORCE_VERSION, FIELD_MANAGER, KEYS, LabelChange,
    PREVIOUS_ANNOTATION, PodSecurityLabels, PreviousError, WARN, WARN_VERSION, diff,
};
pub use model::plan::{DesiredState, Found, Plan, plan};
pub use model::restore::{Restore, restore};
pub use port::{LabelWrite, NamespaceLabelStore, ReconcileObserver};
pub use resolve::{Note, Resolution, resolve};
