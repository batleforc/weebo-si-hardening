//! The `kubearmor-policy` feature's `ReconcileFeature` implementations. One module today; a
//! directory rather than a file because RFC 0006's *Future work* names an admission-side
//! companion, which will land beside this one exactly as `network-profiles`' `workspace_gate`
//! landed beside its own reconcile half.

pub mod kubearmor_policy;
