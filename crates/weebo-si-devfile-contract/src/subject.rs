//! The bounded projection of a `DevWorkspace` this feature is entitled to see (RFC 0019,
//! *Attributes and annotations read*). Every field is written by the workspace's user or token:
//! untrusted, read as data only.

use serde_json::Value;
use weebo_si_chassis::Subject;
use weebo_si_crd::NamespaceName;

/// `spec.template.parent`, as the developer wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parent {
    /// `parent.uri`.
    Uri(String),
    /// `parent.id`, with `parent.version` when set (`registryUrl` is never evaluated).
    Id {
        /// The registry stack id.
        id: String,
        /// The stack version; `None` resolves to the stack's moving default.
        version: Option<String>,
    },
    /// `parent.kubernetes`: a DevWorkspaceTemplate the workspace itself can edit.
    Kubernetes,
}

/// A `DevWorkspace` under admission.
#[derive(Debug, Clone, PartialEq)]
pub struct DevfileWorkspace {
    /// The workspace's name, for the log line.
    pub name: String,
    /// Its namespace.
    pub namespace: NamespaceName,
    /// `spec.template.attributes["weebo.io/platform-contract"]`, raw.
    pub platform_contract: Option<Value>,
    /// `spec.template.attributes["weebo.io/generator"]` when a string — logged, never evaluated.
    pub generator: Option<String>,
    /// `spec.template.parent`.
    pub parent: Option<Parent>,
    /// The first 4 KiB of the `che.eclipse.org/devfile` annotation.
    pub che_devfile: Option<String>,
    /// The stored `hardening.weebo.io/devfile-contract` value.
    pub stored_verdict: Option<String>,
    /// The stored `hardening.weebo.io/devfile-contract-reason` value.
    pub stored_reasons: Option<String>,
    /// Whether this admission is a start (D-13), see [`is_start`].
    pub starting: bool,
}

impl Subject for DevfileWorkspace {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}

/// Whether an admission starts the workspace (D-13): a `CREATE`, `spec.started` turning `true`,
/// or `spec.template` changing while `spec.started` is `true`. Every other `UPDATE` (finalizers,
/// a stop, labels) is never refused by this feature.
pub fn is_start(create: bool, old_started: bool, started: bool, template_changed: bool) -> bool {
    create || (started && (!old_started || template_changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_create_a_start_or_a_running_template_change_is_a_start() {
        assert!(is_start(true, false, false, false));
        assert!(is_start(false, false, true, false));
        assert!(is_start(false, true, true, true));
        assert!(
            !is_start(false, true, true, false),
            "finalizer or label update"
        );
        assert!(
            !is_start(false, true, false, true),
            "a stop, even with a new template"
        );
        assert!(
            !is_start(false, false, false, true),
            "editing a stopped workspace"
        );
    }
}
