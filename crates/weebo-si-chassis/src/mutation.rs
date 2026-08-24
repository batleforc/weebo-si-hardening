//! A patch a feature decided to apply. No JSON, no `serde_json::Value` — rendering to RFC 6902
//! JSON Patch is `weebo-si-webhook`'s job, per the dependency rule: the chassis does not import
//! `k8s-openapi`/`serde_json` and does not know what a JSON Pointer is.
//!
//! Chassis-owned, not any one feature's: `weebo-si-webhook` renders *every* registered feature's
//! mutations into one JSON Patch without importing every feature crate to do it, which is only
//! possible if the enum lives where [`crate::feature::Registry`]'s type erasure already lives.
//! It grows additively as features are added — today, one variant for `dwoc-pin`.

use weebo_si_crd::DwocRef;

/// A patch a feature decided to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Set `controller.devfile.io/devworkspace-config` to the given reference.
    SetConfigRef(DwocRef),
    /// Set one annotation.
    Annotate {
        /// The annotation key.
        key: String,
        /// The annotation value.
        value: String,
    },
}
