//! The `registry-config` feature — see RFC 0007.
//!
//! Fewest dependencies in the workspace on purpose, same as its two siblings: `weebo-si-crd` +
//! `weebo-si-chassis` only, matching "tested exhaustively without a cluster."
//!
//! **What this brick is, and is not.** It is the first in the series that *adds* something to a
//! workspace instead of narrowing it, and the first whose effect is not enforcement at all:
//! nothing here stops a developer from pointing a build at any registry they like. A
//! project-local `.npmrc` beats the user-level one npm reads; `pip install -i` beats `pip.conf`.
//! The guarantee that the alternative registry cannot answer belongs to
//! [RFC 0004](../../../docs/rfc/0004-network-profiles.md)'s egress policy. This brick's job is to
//! make the reachable registry the one that works by default, so that guarantee stops costing
//! the developer their afternoon.
//!
//! **Notably absent, and each for a reason worth reading before adding it back:**
//!
//! * **No `baseline`** — there is no universally correct `.npmrc`, and a mandatory entry would
//!   write a file into containers whose image has no tool to read it.
//! * **No workspace-scoped subject** — DevWorkspace Operator's automount is a property of the
//!   *namespace*, with no selector and no per-workspace opt-out, so there is nothing to route to.
//! * **No `Capabilities` port** — no second backend, no cluster capability to probe.
//! * **No `exclusion` module** — the operator's own namespace and Che's are excluded
//!   structurally by [`weebo_si_network_profiles::is_excluded_namespace`], asked once by the
//!   controller loop reconciling every feature. Two copies of a compiled-in refusal free to
//!   disagree is a wedged namespace, so this crate does not restate it.

pub mod application;
pub mod feature;
pub mod model;
pub mod port;
pub mod resolve;

pub use application::{ReconcileOutcome, reconcile};
pub use feature::registry_config::{NamespaceSubject, RegistryConfigFeature};
pub use feature::registry_guard::{RegistryGuard, RegistryObjectWrite, WriteOperation};
pub use model::diff::{Applied, DesiredState, Diff, RefusedTemplate, compute_diff, tally};
pub use model::mount::{
    MOUNT_AS_ANNOTATION, MOUNT_PATH_ANNOTATION, MOUNT_TO_DEVWORKSPACE_LABEL, MountAs,
    TemplateRefusal, admit, is_automountable, shadows_directory,
};
pub use model::object::{ManagedObject, ObjectBody, ObjectKey, Template};
pub use port::{ObjectStore, ReconcileObserver, TemplateStore};
pub use resolve::{NotGranted, Provenance, ResolutionStep, resolve};
