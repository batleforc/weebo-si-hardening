//! The bounded view of a `DevWorkspaceOperatorConfig` reference this workspace ever holds.
//!
//! Per RFC 0002's *Security considerations*: a `DwocRef` is checked for existence and looked up
//! in the catalogue, never dereferenced into the DWOC's contents. No field here, and no type in
//! this workspace, carries what a DWOC actually says.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::namespace::NamespaceName;

/// A `{name, namespace}` pair naming a `DevWorkspaceOperatorConfig`. This is exactly the shape
/// of the `controller.devfile.io/devworkspace-config` attribute value DevWorkspace Operator
/// reads, and of one `catalog` entry's `{name, namespace}` half.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct DwocRef {
    /// The `DevWorkspaceOperatorConfig`'s name.
    pub name: String,
    /// The namespace it lives in.
    pub namespace: NamespaceName,
}
