//! The `identity` feature: what a `WeeboSiUser` becomes outside this cluster's own API, and the
//! one port that writes it. See RFC 0011.
//!
//! The split between this crate and `weebo-si-crd` is the usual one and worth stating once: the
//! *plan* — what an `AuthentikUser` and an `Application` should contain for this person, and
//! every allow-list that could refuse to produce one — is a pure function over CRD values and
//! lives there, as [`weebo_si_crd::IdentityConfig::plan_for`]. What lives here is everything
//! that needs to know what the cluster currently holds: whether the object exists, who owns it,
//! and therefore whether this pass creates, updates, adopts or refuses.
//!
//! Hexagonal, per RFC 0011's *Architecture*: one outbound port with two instances (the
//! identity-provider object and the workspace application), one observer port, and a decision
//! function with no I/O in it at all.

pub mod application;
pub mod port;

pub use application::{Action, Claimant, decide, reconcile_target, username_holder};
pub use port::{DesiredObject, ObjectOwner, Observation, ProvisionObserver, Provisioner};

#[cfg(any(test, feature = "testing"))]
pub mod testing;
