//! The bounded projection of a `Pod` this feature is entitled to see (RFC 0018, *Architecture*).
//!
//! Only the identity fields: `hostUsers`, the pod-level `securityContext` ids and group policy,
//! and each container's own `runAsUser`/`runAsGroup`, `allowPrivilegeEscalation`, whether it has
//! a `capabilities.drop` list, and whether it asks for privilege (`privileged`, `SYS_ADMIN`). The
//! adapter reads the `Pod`; nothing else of it reaches the domain.

use weebo_si_chassis::Subject;
use weebo_si_crd::NamespaceName;

/// `supplementalGroupsPolicy` value that keeps the image's `/etc/group` out (L14).
pub const STRICT: &str = "Strict";
/// `fsGroupChangePolicy` value set when pod-level ids are rewritten (L10).
pub const ON_ROOT_MISMATCH: &str = "OnRootMismatch";
/// The capability a container drops to have none (PSA `restricted`).
pub const DROP_ALL: &str = "ALL";

/// The pod-level `spec.securityContext` fields this feature reads. `Default` is an absent
/// `securityContext`: the domain does not need to tell it apart from an empty one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodSecurityContext {
    /// `runAsUser`.
    pub run_as_user: Option<i64>,
    /// `runAsGroup`.
    pub run_as_group: Option<i64>,
    /// `fsGroup`.
    pub fs_group: Option<i64>,
    /// `fsGroupChangePolicy`, as written.
    pub fs_group_change_policy: Option<String>,
    /// `supplementalGroups`.
    pub supplemental_groups: Vec<i64>,
    /// `supplementalGroupsPolicy`, as written.
    pub supplemental_groups_policy: Option<String>,
    /// `runAsNonRoot`.
    pub run_as_non_root: Option<bool>,
}

/// Which list of the pod spec a container comes from — part of the refusal message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// `spec.containers[]`.
    Container,
    /// `spec.initContainers[]`.
    Init,
    /// `spec.ephemeralContainers[]`.
    Ephemeral,
}

impl ContainerKind {
    /// How a refusal message names it.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Init => "init container",
            Self::Ephemeral => "ephemeral container",
        }
    }
}

/// One container's own ids (its `securityContext`, not the pod's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerIdentity {
    /// Which list it comes from.
    pub kind: ContainerKind,
    /// Its name, as written (attacker-shaped: messages quote it with `{:?}`).
    pub name: String,
    /// `securityContext.runAsUser`.
    pub run_as_user: Option<i64>,
    /// `securityContext.runAsGroup`.
    pub run_as_group: Option<i64>,
    /// `securityContext.allowPrivilegeEscalation`.
    pub allow_privilege_escalation: Option<bool>,
    /// Whether `securityContext.capabilities.drop` is set, whatever it holds.
    pub drop_set: bool,
    /// `privileged: true`, or `SYS_ADMIN` in `capabilities.add`: the apiserver refuses
    /// `allowPrivilegeEscalation: false` next to either.
    pub needs_privilege: bool,
}

/// Which admission call this is (L21: `pods` CREATE and `pods/ephemeralcontainers` UPDATE only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// A pod CREATE: everything is judged, and the mutation may rewrite the pod level.
    Create,
    /// A `pods/ephemeralcontainers` UPDATE. The pod level is immutable and was judged at
    /// creation; only the added ephemeral containers are, plus whether the pod still shares the
    /// node's user namespace (L18). Never rewritten.
    EphemeralUpdate {
        /// `oldObject.spec.hostUsers`.
        old_host_users: Option<bool>,
    },
}

/// A `Pod` under admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSubject {
    /// The pod's name, or its `generateName` when the name is not set yet — for the log line.
    pub name: String,
    /// The namespace it is being created in.
    pub namespace: NamespaceName,
    /// `spec.hostUsers`.
    pub host_users: Option<bool>,
    /// `spec.securityContext`.
    pub security_context: PodSecurityContext,
    /// On [`Admission::Create`], `spec.initContainers[]` and `spec.containers[]`; on
    /// [`Admission::EphemeralUpdate`], only the ephemeral containers `oldObject` did not have.
    pub containers: Vec<ContainerIdentity>,
    /// Which admission call this is.
    pub admission: Admission,
}

impl Subject for PodSubject {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "Pod"
    }
}
