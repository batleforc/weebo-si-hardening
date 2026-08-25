//! The vocabulary every reconcile feature that *writes objects into workspace namespaces* shares:
//! which object ([`ObjectKey`]), which pods it governs ([`PodSelector`]), and the diff between
//! what should exist and what does ([`Diff`], [`compute_diff`]).
//!
//! Promoted here from `weebo-si-network-profiles`' own `model/` by RFC 0006's *Implementation
//! plan* — "promote `PodSelector` (and any other genuinely backend-agnostic type
//! `network_profiles.rs` currently owns) to `weebo-si-chassis`, so this crate does not duplicate
//! it" — and by that RFC's *Architecture*, which describes `kubearmor-policy`'s `model/diff.rs`
//! as **reused** diff machinery: "a `KubeArmorPolicy` and a `NetworkPolicy` diff the same way:
//! compare spec bodies under a managed-by label filter." Two copies of that comparison are two
//! copies free to drift, and the second feature is the moment to stop copying.
//!
//! What deliberately did **not** move is `ManagedObject` itself. Its `backend` field is typed to
//! the owning feature's own backend enum (`weebo_si_crd::Backend` for `network-profiles`,
//! `weebo_si_crd::RuntimeBackend` for `kubearmor-policy`), and a chassis type naming both would
//! be a chassis that knows how many policy dialects exist — the dependency direction this
//! crate's module doc forbids. Each feature keeps its own object type and implements [`Managed`]
//! for it; they share the parts and the algorithm, not the payload.
//!
//! Neither did `DesiredState`. What a feature computed *and why* (which team matched, which keys
//! were dropped as not granted, which had no usable variant) is the feature's own observability
//! contract, and every feature's is different.

pub mod diff;
pub mod object;

pub use diff::{Applied, Diff, Managed, compute_diff, tally};
pub use object::{ObjectKey, PodSelector};
