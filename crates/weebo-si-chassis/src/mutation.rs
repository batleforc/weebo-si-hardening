//! A patch a feature decided to apply. No JSON, no `serde_json::Value` — rendering to RFC 6902
//! JSON Patch is `weebo-si-webhook`'s job, per the dependency rule: the chassis does not import
//! `k8s-openapi`/`serde_json` and does not know what a JSON Pointer is.
//!
//! Chassis-owned, not any one feature's: `weebo-si-webhook` renders *every* registered feature's
//! mutations into one JSON Patch without importing every feature crate to do it, which is only
//! possible if the enum lives where [`crate::feature::Registry`]'s type erasure already lives.
//! It grows additively as features are added: `dwoc-pin`'s two, plus [`Mutation::SetString`],
//! which RFC 0009's `ReverseProxy` dialect needs — on OpenShift the gate *is* the route's
//! backend, so attaching it means writing `spec.to.name`, which no annotation variant can
//! express.

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
    /// Set one string-valued field, named by its path segments — `["spec", "to", "name"]`.
    ///
    /// Segments rather than a pointer string for the reason this whole module exists: a JSON
    /// Pointer needs `/` and `~` escaped, and the chassis does not know what a JSON Pointer is.
    /// String-valued only, deliberately: every field RFC 0009's dialects pin is a name or a port
    /// name, and a variant that could carry arbitrary structure would be a way for a feature to
    /// rewrite an object rather than to annotate it.
    SetString {
        /// The path to the field, from the object's root.
        path: Vec<String>,
        /// The value to set.
        value: String,
    },
}
