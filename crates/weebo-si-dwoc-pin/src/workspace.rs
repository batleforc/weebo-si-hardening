//! The DevWorkspace under admission, in domain vocabulary: name, namespace, and the one
//! attribute this feature cares about. Nothing else about a DevWorkspace ever reaches this
//! feature — see RFC 0002's *Security considerations*, "never reads the user's DWOC."

use weebo_si_chassis::Subject;
use weebo_si_crd::{DwocRef, NamespaceName};

/// The DevWorkspace under admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The workspace's name.
    pub name: String,
    /// The namespace it was created in.
    pub namespace: NamespaceName,
    /// The current value of `controller.devfile.io/devworkspace-config`, if the workspace
    /// carries the attribute at all.
    pub config_ref: Option<DwocRef>,
}

impl Subject for Workspace {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}
