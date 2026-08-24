//! The two features this crate implements — see RFC 0004's *Design*.
//!
//! `network-profiles` has two shapes rather than one: a `ReconcileFeature` writing the objects
//! (`network_profiles`), and a `Feature` refusing a `DevWorkspace` the reconcile side could not
//! protect in time (`workspace_gate`). Both report the same `FeatureId`, so one `mode` governs
//! both.

pub mod network_profiles;
pub mod policy_guard;
pub mod workspace_gate;
