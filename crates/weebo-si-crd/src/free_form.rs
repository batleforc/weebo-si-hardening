//! The one schema an admin writes into and the operator never reads: a free-form object.
//!
//! Helm values are somebody else's contract — a chart's, and a different chart's tomorrow — so
//! the CRD carries them as an opaque tree rather than pretending to know their shape. The
//! generated OpenAPI schema says `x-kubernetes-preserve-unknown-fields`, which is what stops the
//! API server from pruning every key this schema does not name; without it a `values` block
//! would be silently emptied on apply, which is the single worst failure an opaque field can
//! have.
//!
//! `preserve-unknown` is used **here and nowhere else**. Every other field in this crate is
//! typed, per RFC 0002's *Contract*: "a feature the binary does not know about cannot be written
//! into the resource at all."

use schemars::{Schema, SchemaGenerator};

/// The schema for a free-form object: `{"type": "object",
/// "x-kubernetes-preserve-unknown-fields": true}`.
///
/// Named by `#[schemars(schema_with = "crate::free_form::object_schema")]` on the fields that
/// carry one.
pub fn object_schema(_generator: &mut SchemaGenerator) -> Schema {
    let mut schema = serde_json::Map::new();
    schema.insert(
        "type".to_owned(),
        serde_json::Value::String("object".into()),
    );
    schema.insert(
        "x-kubernetes-preserve-unknown-fields".to_owned(),
        serde_json::Value::Bool(true),
    );
    Schema::from(schema)
}
