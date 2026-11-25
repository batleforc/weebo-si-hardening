//! What this feature needs from the outside, without knowing how to ask for it. The stores that
//! write (`ToolsNamespaceStore`, `RequesterStore`) are RFC 0020 PR 4's, with the adapters.

use std::collections::BTreeMap;
use std::time::SystemTime;

use weebo_si_crd::{NamespaceName, ToolTemplateRef};

/// A template object, as a domain value: what is copied, and the metadata the render keeps.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolTemplate {
    /// `kind`.
    pub kind: String,
    /// `metadata.name`.
    pub name: String,
    /// `metadata.namespace`.
    pub namespace: NamespaceName,
    /// `metadata.labels`.
    pub labels: BTreeMap<String, String>,
    /// `metadata.annotations`.
    pub annotations: BTreeMap<String, String>,
    /// Every top-level field but `apiVersion`, `kind`, `metadata` and `status` (`spec`, `data`,
    /// `binaryData`, …), unchanged.
    pub body: serde_json::Value,
}

/// The templates, by reference. `None` covers "does not exist" and "not in the watch cache yet";
/// both make the entry invalid, and an invalid entry keeps what is rendered.
pub trait ToolTemplateStore: Send + Sync {
    /// The object `template` names, if its kind and name are found in its namespace.
    fn template(&self, template: &ToolTemplateRef) -> Option<ToolTemplate>;
}

/// The clock, as a port, so the scale decision cannot read one by accident (RFC 0020,
/// *Architecture*; same shape as endpoint-auth's, not shared).
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> SystemTime;
}

#[cfg(any(test, feature = "testing"))]
#[allow(
    missing_docs,
    reason = "test-support fakes, not a documented public API"
)]
pub mod testing {
    use std::sync::RwLock;
    use std::time::{Duration, SystemTime};

    use super::*;

    /// Templates in memory, matched on kind, name and namespace.
    #[derive(Default)]
    pub struct FakeTemplateStore {
        pub templates: Vec<ToolTemplate>,
    }

    impl ToolTemplateStore for FakeTemplateStore {
        fn template(&self, template: &ToolTemplateRef) -> Option<ToolTemplate> {
            self.templates
                .iter()
                .find(|candidate| {
                    candidate.kind == template.kind
                        && candidate.name == template.name
                        && candidate.namespace == template.namespace
                })
                .cloned()
        }
    }

    /// A clock that only moves when told to.
    pub struct FakeClock(RwLock<SystemTime>);

    impl FakeClock {
        pub fn at(seconds: u64) -> Self {
            Self(RwLock::new(
                SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            ))
        }

        pub fn advance(&self, by: Duration) {
            let mut now = self
                .0
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *now += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> SystemTime {
            *self
                .0
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }
}
