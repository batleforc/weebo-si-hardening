//! The `network-profiles` feature — see RFC 0004's *Design*.
//!
//! It has two shapes rather than one: a `ReconcileFeature` writing the objects
//! (`network_profiles`), and a `Feature` refusing a `DevWorkspace` the reconcile side could not
//! protect in time (`workspace_gate`). Both report the same `FeatureId`, so one `mode` governs
//! both.
//!
//! **`policy-guard` used to live here too**, because RFC 0004 introduced both. It now has a
//! crate of its own, `weebo-si-policy-guard` — see RFC 0008: a guard that also covers
//! `weebo-si-kubearmor-policy`'s objects cannot sit inside a sibling feature without that
//! sibling becoming a dependency of it.

pub mod network_profiles;
pub mod workspace_gate;
