//! The `network-profiles` and `policy-guard` features — see RFC 0004.
//!
//! Fewest dependencies in the workspace on purpose, same as `weebo-si-dwoc-pin`:
//! `weebo-si-crd` + `weebo-si-chassis` only, matching "tested exhaustively without a cluster."

pub mod application;
pub mod backend;
pub mod canary;
pub mod exclusion;
pub mod feature;
pub mod model;
pub mod port;
pub mod resolve;

pub use application::{ReconcileOutcome, reconcile, run_canary};
pub use backend::resolve_backend;
pub use canary::{CanaryVerdict, Reachability, verdict};
pub use exclusion::{CHE_NAMESPACE, is_excluded_namespace};
pub use feature::network_profiles::{NamespaceSubject, NetworkProfiles, Workspace};
pub use feature::policy_guard::{NetworkPolicyOperation, NetworkPolicyWrite, PolicyGuard};
pub use feature::workspace_gate::{WorkspaceAdmission, WorkspaceGate, WorkspaceOperation};
pub use model::diff::{Applied, DesiredState, Diff, compute_diff, tally};
pub use model::policy::{ManagedObject, ObjectKey, PodSelector, PolicyBody};
pub use port::{
    BaselineView, CanaryProbe, Capabilities, PolicyStore, ReconcileObserver, TemplateStore,
};
pub use resolve::{NotGranted, Provenance, ResolutionStep, resolve};
