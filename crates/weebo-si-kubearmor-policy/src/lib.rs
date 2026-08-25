//! The `kubearmor-policy` feature — see RFC 0006.
//!
//! Fewest dependencies in the workspace on purpose, same as `weebo-si-network-profiles`:
//! `weebo-si-crd` + `weebo-si-chassis` only, matching "tested exhaustively without a cluster."
//!
//! **Notably absent: an `exclusion` module.** `network-profiles` compiles in its refusal to touch
//! the operator's own namespace and Che's, because a deny-all baseline in either severs this
//! operator's own apiserver connection. That rule is not this feature's to restate — a
//! controller loop reconciling both features asks
//! `weebo_si_network_profiles::is_excluded_namespace` once, and two copies of a
//! compiled-in refusal that disagree is exactly the wedged namespace the original comment warns
//! about.

pub mod application;
pub mod backend;
pub mod feature;
pub mod model;
pub mod port;
pub mod resolve;

pub use application::{ReconcileOutcome, observe_enforcement, reconcile};
pub use backend::resolve_backend;
pub use feature::kubearmor_policy::{KubeArmorPolicy, NamespaceSubject, Workspace};
pub use model::diff::{Applied, DesiredState, Diff, compute_diff, tally};
pub use model::policy::{ManagedObject, ObjectKey, PodSelector, RuleBody};
pub use port::{
    BaselineView, Capabilities, Enforcement, EnforcementSubjects, NodeEnforcerView, PolicyStore,
    ReconcileObserver, TemplateStore,
};
pub use resolve::{NotGranted, Provenance, ResolutionStep, resolve};
