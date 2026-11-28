//! `identity_rewrite`: what the mutation changes (RFC 0018, Q21, L10, L14).
//!
//! Pod-level paths (`spec.hostUsers`, `spec.securityContext.*`), plus two fields of each init
//! container and container when it leaves them unset: `allowPrivilegeEscalation: false` and
//! `capabilities.drop: [ALL]`, PSA `restricted`'s container half, which DevWorkspace Operator
//! leaves off `project-clone`. A container that states its privilege is left as written.
//! A container path always names an index the pod has (counted from the pod's own lists): the
//! chassis renderer creates a missing parent as an object even before an array index, so an
//! index the pod does not have would corrupt it (review of patch 02). No path here is the parent
//! of another, and `securityContext` itself is never written as a scalar.

use std::fmt;

use weebo_si_chassis::Mutation;
use weebo_si_crd::PodIdentityConfig;

use crate::subject::{Admission, ContainerKind, DROP_ALL, ON_ROOT_MISMATCH, PodSubject, STRICT};

/// A field the mutation may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    /// `spec.hostUsers`.
    HostUsers,
    /// `spec.securityContext.runAsUser`.
    RunAsUser,
    /// `spec.securityContext.runAsGroup`.
    RunAsGroup,
    /// `spec.securityContext.fsGroup`.
    FsGroup,
    /// `spec.securityContext.fsGroupChangePolicy`.
    FsGroupChangePolicy,
    /// `spec.securityContext.supplementalGroupsPolicy`.
    SupplementalGroupsPolicy,
    /// `spec.securityContext.runAsNonRoot`.
    RunAsNonRoot,
    /// A container's `securityContext.allowPrivilegeEscalation`.
    AllowPrivilegeEscalation,
    /// A container's `securityContext.capabilities.drop`.
    CapabilitiesDrop,
}

impl Field {
    /// The `field` label of `weebo_si_pod_identity_rewrites_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::HostUsers => "host_users",
            Self::RunAsUser => "run_as_user",
            Self::RunAsGroup => "run_as_group",
            Self::FsGroup => "fs_group",
            Self::FsGroupChangePolicy => "fs_group_change_policy",
            Self::SupplementalGroupsPolicy => "supplemental_groups_policy",
            Self::RunAsNonRoot => "run_as_non_root",
            Self::AllowPrivilegeEscalation => "allow_privilege_escalation",
            Self::CapabilitiesDrop => "capabilities_drop",
        }
    }

    /// The field's name in the pod spec, as the `DryRun` line prints it.
    pub fn name(self) -> &'static str {
        match self {
            Self::HostUsers => "hostUsers",
            Self::RunAsUser => "runAsUser",
            Self::RunAsGroup => "runAsGroup",
            Self::FsGroup => "fsGroup",
            Self::FsGroupChangePolicy => "fsGroupChangePolicy",
            Self::SupplementalGroupsPolicy => "supplementalGroupsPolicy",
            Self::RunAsNonRoot => "runAsNonRoot",
            Self::AllowPrivilegeEscalation => "allowPrivilegeEscalation",
            Self::CapabilitiesDrop => "capabilities.drop",
        }
    }

    /// The path under the `securityContext` that holds it, pod or container (`hostUsers` aside).
    fn context_path(self) -> Vec<String> {
        match self {
            Self::CapabilitiesDrop => vec!["capabilities".to_string(), "drop".to_string()],
            other => vec![other.name().to_string()],
        }
    }
}

/// The container a [`Rewrite`] lands on: its list, its index in that list, and its name (for the
/// `DryRun` line only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSlot {
    /// Which list it comes from.
    pub kind: ContainerKind,
    /// Its index in that list, as the pod has it.
    pub index: usize,
    /// Its name, as written (attacker-shaped: printed with `{:?}`).
    pub name: String,
}

impl ContainerSlot {
    fn list(&self) -> &'static str {
        match self.kind {
            ContainerKind::Init => "initContainers",
            ContainerKind::Container => "containers",
            ContainerKind::Ephemeral => "ephemeralContainers",
        }
    }
}

/// A scalar value of one [`Field`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An id.
    Int(i64),
    /// A flag.
    Bool(bool),
    /// A policy name.
    Str(String),
    /// A list of names (`capabilities.drop`).
    Strings(Vec<String>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => write!(f, "{value}"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Str(value) => f.write_str(value),
            Self::Strings(values) => write!(f, "[{}]", values.join(",")),
        }
    }
}

/// One field the mutation changes, with what it held before (`None`: unset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
    /// The container it lands on, `None` for a pod-level field.
    pub container: Option<ContainerSlot>,
    /// The field.
    pub field: Field,
    /// Its value before, `None` when unset.
    pub from: Option<Value>,
    /// The value written.
    pub to: Value,
}

impl Rewrite {
    /// The chassis mutation that writes it.
    pub fn mutation(&self) -> Mutation {
        let path = self.path();
        match &self.to {
            Value::Int(value) => Mutation::SetInt {
                path,
                value: *value,
            },
            Value::Bool(value) => Mutation::SetBool {
                path,
                value: *value,
            },
            Value::Str(value) => Mutation::SetString {
                path,
                value: value.clone(),
            },
            Value::Strings(values) => Mutation::SetStrings {
                path,
                values: values.clone(),
            },
        }
    }

    fn path(&self) -> Vec<String> {
        let mut path = vec!["spec".to_string()];
        match &self.container {
            Some(slot) => {
                path.push(slot.list().to_string());
                path.push(slot.index.to_string());
                path.push("securityContext".to_string());
            }
            None if self.field == Field::HostUsers => {
                path.push("hostUsers".to_string());
                return path;
            }
            None => path.push("securityContext".to_string()),
        }
        path.extend(self.field.context_path());
        path
    }

    /// Apply it to an in-memory pod, for judging the pod as the mutation would leave it (L23).
    fn apply(&self, pod: &mut PodSubject) {
        if let Some(slot) = &self.container {
            let Some(container) = pod
                .containers
                .iter_mut()
                .filter(|container| container.kind == slot.kind)
                .nth(slot.index)
            else {
                return;
            };
            match (self.field, &self.to) {
                (Field::AllowPrivilegeEscalation, Value::Bool(value)) => {
                    container.allow_privilege_escalation = Some(*value);
                }
                (Field::CapabilitiesDrop, Value::Strings(_)) => container.drop_set = true,
                // identity_rewrite writes no other field on a container.
                _ => {}
            }
            return;
        }
        let context = &mut pod.security_context;
        match (self.field, &self.to) {
            (Field::HostUsers, Value::Bool(value)) => pod.host_users = Some(*value),
            (Field::RunAsUser, Value::Int(value)) => context.run_as_user = Some(*value),
            (Field::RunAsGroup, Value::Int(value)) => context.run_as_group = Some(*value),
            (Field::FsGroup, Value::Int(value)) => context.fs_group = Some(*value),
            (Field::FsGroupChangePolicy, Value::Str(value)) => {
                context.fs_group_change_policy = Some(value.clone());
            }
            (Field::SupplementalGroupsPolicy, Value::Str(value)) => {
                context.supplemental_groups_policy = Some(value.clone());
            }
            (Field::RunAsNonRoot, Value::Bool(value)) => context.run_as_non_root = Some(*value),
            // identity_rewrite never pairs a field with another type.
            _ => {}
        }
    }
}

impl fmt::Display for Rewrite {
    /// `runAsGroup=0->1234`, the `DryRun` line's shape; a container field is prefixed with its
    /// list and name, `initContainers["project-clone"].allowPrivilegeEscalation=unset->false`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(slot) = &self.container {
            write!(f, "{}[{:?}].", slot.list(), slot.name)?;
        }
        match &self.from {
            Some(from) => write!(f, "{}={from}->{}", self.field.name(), self.to),
            None => write!(f, "{}=unset->{}", self.field.name(), self.to),
        }
    }
}

impl PodSubject {
    /// The pod as `rewrites` would leave it.
    pub fn rewritten(&self, rewrites: &[Rewrite]) -> Self {
        let mut pod = self.clone();
        for rewrite in rewrites {
            rewrite.apply(&mut pod);
        }
        pod
    }
}

/// What the mutation changes on `pod` (Q21). Empty on an ephemeral-container update, and on a
/// pod already in shape — so a reinvocation on a rewritten pod patches nothing.
///
/// Pod-level `runAsUser`, `runAsGroup`, `fsGroup` absent → the configured ids; `runAsGroup: 0`
/// or `fsGroup: 0` (unless `grantGroupZero`) → the configured gid; any other non-zero id kept; `runAsUser: 0` kept for
/// validation to refuse. `hostUsers` → `false`, `supplementalGroupsPolicy` → `Strict`,
/// `runAsNonRoot` → `true`, and `fsGroupChangePolicy: OnRootMismatch` when an id is rewritten.
/// On every init container and container, only where unset: `allowPrivilegeEscalation` →
/// `false`, and `capabilities.drop` → `[ALL]`.
pub fn identity_rewrite(pod: &PodSubject, config: &PodIdentityConfig) -> Vec<Rewrite> {
    if pod.admission != Admission::Create {
        return Vec::new();
    }
    let context = &pod.security_context;
    let mut out = Vec::new();
    if pod.host_users != Some(false) {
        out.push(Rewrite {
            container: None,
            field: Field::HostUsers,
            from: pod.host_users.map(Value::Bool),
            to: Value::Bool(false),
        });
    }
    let ids = [
        (
            Field::RunAsUser,
            context.run_as_user,
            None,
            config.run_as_user,
        ),
        (
            Field::RunAsGroup,
            context.run_as_group,
            Some(0),
            config.run_as_group,
        ),
        (
            Field::FsGroup,
            context.fs_group,
            // grantGroupZero lets `fsGroup: 0` through validation, so it is kept as asked.
            (!config.grant_group_zero).then_some(0),
            config.run_as_group,
        ),
    ];
    let mut ids_rewritten = false;
    for (field, current, also, to) in ids {
        if current.is_none() || current == also {
            ids_rewritten = true;
            out.push(Rewrite {
                container: None,
                field,
                from: current.map(Value::Int),
                to: Value::Int(to),
            });
        }
    }
    if ids_rewritten && context.fs_group_change_policy.as_deref() != Some(ON_ROOT_MISMATCH) {
        out.push(Rewrite {
            container: None,
            field: Field::FsGroupChangePolicy,
            from: context.fs_group_change_policy.clone().map(Value::Str),
            to: Value::Str(ON_ROOT_MISMATCH.to_string()),
        });
    }
    if context.supplemental_groups_policy.as_deref() != Some(STRICT) {
        out.push(Rewrite {
            container: None,
            field: Field::SupplementalGroupsPolicy,
            from: context.supplemental_groups_policy.clone().map(Value::Str),
            to: Value::Str(STRICT.to_string()),
        });
    }
    if context.run_as_non_root != Some(true) {
        out.push(Rewrite {
            container: None,
            field: Field::RunAsNonRoot,
            from: context.run_as_non_root.map(Value::Bool),
            to: Value::Bool(true),
        });
    }
    out.extend(container_rewrites(pod));
    out
}

/// The container half: PSA `restricted`'s `allowPrivilegeEscalation: false` and `drop: [ALL]`,
/// written only where the container says nothing. An explicit value is a choice (RFC 0013's build
/// DWOC asks for escalation, and `drop: [ALL]` would empty the bounding set `newuidmap` needs):
/// it is kept, and PSA or validation refuses it if it must. Nothing is written next to
/// `privileged: true` or `SYS_ADMIN`, which the apiserver refuses with `false`.
/// The index is counted per list over the pod's own containers, so it always exists.
fn container_rewrites(pod: &PodSubject) -> Vec<Rewrite> {
    let mut out = Vec::new();
    let (mut init, mut regular) = (0_usize, 0_usize);
    for container in &pod.containers {
        let counter = match container.kind {
            ContainerKind::Init => &mut init,
            ContainerKind::Container => &mut regular,
            // Only on an ephemeral update, which identity_rewrite never rewrites.
            ContainerKind::Ephemeral => continue,
        };
        let slot = ContainerSlot {
            kind: container.kind,
            index: *counter,
            name: container.name.clone(),
        };
        *counter = counter.saturating_add(1);
        if container.allow_privilege_escalation.is_none() && !container.needs_privilege {
            out.push(Rewrite {
                container: Some(slot.clone()),
                field: Field::AllowPrivilegeEscalation,
                from: None,
                to: Value::Bool(false),
            });
        }
        let asks_privilege =
            container.allow_privilege_escalation == Some(true) || container.needs_privilege;
        if !container.drop_set && !asks_privilege {
            out.push(Rewrite {
                container: Some(slot),
                field: Field::CapabilitiesDrop,
                from: None,
                to: Value::Strings(vec![DROP_ALL.to_string()]),
            });
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
pub(crate) mod tests {
    use weebo_si_crd::{FeatureMode, NamespaceName};

    use super::*;
    use crate::subject::{ContainerIdentity, PodSecurityContext};

    pub(crate) fn config() -> PodIdentityConfig {
        PodIdentityConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            run_as_user: 1234,
            run_as_group: 1234,
            exempt_dwoc_keys: vec!["build".to_string()],
            grant_group_zero: false,
        }
    }

    pub(crate) fn container(name: &str, uid: Option<i64>, gid: Option<i64>) -> ContainerIdentity {
        ContainerIdentity {
            kind: ContainerKind::Container,
            name: name.to_string(),
            run_as_user: uid,
            run_as_group: gid,
            allow_privilege_escalation: Some(false),
            drop_set: true,
            needs_privilege: false,
        }
    }

    /// DWO v1.1.1's workspace pod: `1234:0`, `fsGroup: 1234`, no `hostUsers` [R16].
    pub(crate) fn dwo_pod() -> PodSubject {
        PodSubject {
            name: "workspace4f-7d9c-".to_string(),
            namespace: NamespaceName::new("dev-ws-batleforc-test"),
            host_users: None,
            security_context: PodSecurityContext {
                run_as_user: Some(1234),
                run_as_group: Some(0),
                fs_group: Some(1234),
                ..PodSecurityContext::default()
            },
            containers: vec![container("tools", None, None)],
            admission: Admission::Create,
        }
    }

    /// A pod already in the shape the mutation leaves.
    pub(crate) fn fixed_pod() -> PodSubject {
        let pod = dwo_pod();
        pod.rewritten(&identity_rewrite(&pod, &config()))
    }

    fn rendered(pod: &PodSubject) -> Vec<String> {
        identity_rewrite(pod, &config())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn pod_level_rewritten_to_fixed_identity() {
        assert_eq!(
            rendered(&dwo_pod()),
            [
                "hostUsers=unset->false",
                "runAsGroup=0->1234",
                "fsGroupChangePolicy=unset->OnRootMismatch",
                "supplementalGroupsPolicy=unset->Strict",
                "runAsNonRoot=unset->true",
            ]
        );
        let context = fixed_pod().security_context;
        assert_eq!(
            (context.run_as_user, context.run_as_group, context.fs_group),
            (Some(1234), Some(1234), Some(1234))
        );
    }

    #[test]
    fn pod_level_already_fixed_is_kept() {
        assert!(identity_rewrite(&fixed_pod(), &config()).is_empty());
    }

    #[test]
    fn host_users_set_false_on_rewrite() {
        let mut pod = fixed_pod();
        pod.host_users = Some(true);
        let rewrites = identity_rewrite(&pod, &config());
        assert_eq!(rendered(&pod), ["hostUsers=true->false"]);
        assert_eq!(
            rewrites[0].mutation(),
            Mutation::SetBool {
                path: vec!["spec".to_string(), "hostUsers".to_string()],
                value: false,
            }
        );
    }

    #[test]
    fn fs_group_change_policy_set_on_rewrite() {
        let mut pod = fixed_pod();
        pod.security_context.fs_group = Some(0);
        pod.security_context.fs_group_change_policy = Some("Always".to_string());
        assert_eq!(
            rendered(&pod),
            [
                "fsGroup=0->1234",
                "fsGroupChangePolicy=Always->OnRootMismatch"
            ]
        );
        // No id rewritten: the policy someone chose stays.
        pod.security_context.fs_group = Some(1234);
        assert!(rendered(&pod).is_empty());
    }

    #[test]
    fn pod_level_absent_ids_set_to_fixed_identity() {
        let mut pod = dwo_pod();
        pod.security_context = PodSecurityContext::default();
        let rewrites = identity_rewrite(&pod, &config());
        let ids: Vec<Mutation> = rewrites
            .iter()
            .filter(|rewrite| {
                matches!(
                    rewrite.field,
                    Field::RunAsUser | Field::RunAsGroup | Field::FsGroup
                )
            })
            .map(Rewrite::mutation)
            .collect();
        let path = |field: &str| {
            vec![
                "spec".to_string(),
                "securityContext".to_string(),
                field.to_string(),
            ]
        };
        assert_eq!(
            ids,
            [
                Mutation::SetInt {
                    path: path("runAsUser"),
                    value: 1234
                },
                Mutation::SetInt {
                    path: path("runAsGroup"),
                    value: 1234
                },
                Mutation::SetInt {
                    path: path("fsGroup"),
                    value: 1234
                },
            ]
        );
    }

    #[test]
    fn pod_level_nonzero_uid_is_kept() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_user = Some(10100);
        pod.security_context.run_as_group = Some(10100);
        pod.security_context.fs_group = Some(999);
        assert!(identity_rewrite(&pod, &config()).is_empty());
    }

    #[test]
    fn pod_level_gid_zero_rewritten() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_group = Some(0);
        pod.security_context.fs_group = Some(0);
        assert_eq!(rendered(&pod), ["runAsGroup=0->1234", "fsGroup=0->1234"]);
    }

    #[test]
    fn granted_group_zero_keeps_fs_group_zero() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_group = Some(0);
        pod.security_context.fs_group = Some(0);
        let config = PodIdentityConfig {
            grant_group_zero: true,
            ..config()
        };
        let rewrites = identity_rewrite(&pod, &config);
        let got: Vec<String> = rewrites.iter().map(ToString::to_string).collect();
        assert_eq!(got, ["runAsGroup=0->1234"]);
    }

    #[test]
    fn pod_level_uid_zero_is_not_rewritten() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_user = Some(0);
        assert!(identity_rewrite(&pod, &config()).is_empty());
    }

    #[test]
    fn the_configured_ids_are_the_ones_written() {
        let mut config = config();
        config.run_as_user = 1000;
        config.run_as_group = 2000;
        let mut pod = dwo_pod();
        pod.security_context = PodSecurityContext::default();
        let context = pod
            .rewritten(&identity_rewrite(&pod, &config))
            .security_context;
        assert_eq!(
            (context.run_as_user, context.run_as_group, context.fs_group),
            (Some(1000), Some(2000), Some(2000))
        );
    }

    /// Every rewrite lands on the in-memory pod (`apply` has no silent arm for it), so the
    /// rewritten pod is a fixed point and `fixable_by_mutation` is computed on what is written.
    #[test]
    fn the_rewritten_pod_is_a_fixed_point() {
        let mut pod = dwo_pod();
        pod.host_users = Some(true);
        pod.security_context = PodSecurityContext::default();
        let rewrites = identity_rewrite(&pod, &config());
        assert_eq!(rewrites.len(), 7, "every field is written");
        assert!(identity_rewrite(&pod.rewritten(&rewrites), &config()).is_empty());
    }

    fn bare(kind: ContainerKind, name: &str) -> ContainerIdentity {
        ContainerIdentity {
            kind,
            allow_privilege_escalation: None,
            drop_set: false,
            ..container(name, None, None)
        }
    }

    /// DWO's `project-clone`: no `securityContext` at all. Both PSA `restricted` fields land on
    /// its own index, and nothing else changes.
    #[test]
    fn project_clone_gets_no_escalation_and_drop_all() {
        let mut pod = fixed_pod();
        pod.containers
            .insert(0, bare(ContainerKind::Init, "project-clone"));
        let rewrites = identity_rewrite(&pod, &config());
        assert_eq!(
            rewrites.iter().map(ToString::to_string).collect::<Vec<_>>(),
            [
                r#"initContainers["project-clone"].allowPrivilegeEscalation=unset->false"#,
                r#"initContainers["project-clone"].capabilities.drop=unset->[ALL]"#,
            ]
        );
        let at = |tail: &[&str]| {
            ["spec", "initContainers", "0", "securityContext"]
                .iter()
                .chain(tail)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            rewrites.iter().map(Rewrite::mutation).collect::<Vec<_>>(),
            [
                Mutation::SetBool {
                    path: at(&["allowPrivilegeEscalation"]),
                    value: false,
                },
                Mutation::SetStrings {
                    path: at(&["capabilities", "drop"]),
                    values: vec!["ALL".to_string()],
                },
            ]
        );
    }

    /// The index is counted per list, init containers apart from containers.
    #[test]
    fn container_index_counted_per_list() {
        let mut pod = fixed_pod();
        pod.containers = vec![
            ContainerIdentity {
                kind: ContainerKind::Init,
                ..container("hardened-init", None, None)
            },
            bare(ContainerKind::Init, "second-init"),
            ContainerIdentity {
                drop_set: true,
                ..bare(ContainerKind::Container, "tools")
            },
        ];
        let paths: Vec<String> = identity_rewrite(&pod, &config())
            .iter()
            .map(|rewrite| rewrite.path().join("/"))
            .collect();
        assert_eq!(
            paths,
            [
                "spec/initContainers/1/securityContext/allowPrivilegeEscalation",
                "spec/initContainers/1/securityContext/capabilities/drop",
                "spec/containers/0/securityContext/allowPrivilegeEscalation",
            ]
        );
    }

    #[test]
    /// RFC 0013's build DWOC: escalation asked for, no capabilities. Both are left alone —
    /// `drop: [ALL]` would empty the bounding set `newuidmap` needs.
    fn container_asking_for_escalation_is_left_as_written() {
        let mut pod = fixed_pod();
        pod.containers = vec![ContainerIdentity {
            allow_privilege_escalation: Some(true),
            ..bare(ContainerKind::Container, "tools")
        }];
        assert!(rendered(&pod).is_empty());
    }

    /// `privileged: true` or `SYS_ADMIN`: the apiserver refuses `allowPrivilegeEscalation: false`
    /// next to them, so nothing is written and PSA or validation gives the refusal.
    #[test]
    fn privileged_container_is_left_as_written() {
        let mut pod = fixed_pod();
        pod.containers = vec![ContainerIdentity {
            needs_privilege: true,
            ..bare(ContainerKind::Container, "tools")
        }];
        assert!(rendered(&pod).is_empty());
    }

    /// A drop list someone wrote is kept, even without `ALL`; only an unset escalation is filled.
    #[test]
    fn an_existing_drop_list_is_kept() {
        let mut pod = fixed_pod();
        pod.containers = vec![ContainerIdentity {
            drop_set: true,
            ..bare(ContainerKind::Container, "tools")
        }];
        assert_eq!(
            rendered(&pod),
            [r#"containers["tools"].allowPrivilegeEscalation=unset->false"#]
        );
    }

    #[test]
    fn the_rewritten_pod_with_bare_containers_is_a_fixed_point() {
        let mut pod = dwo_pod();
        pod.containers = vec![
            bare(ContainerKind::Init, "project-clone"),
            bare(ContainerKind::Container, "tools"),
        ];
        let rewrites = identity_rewrite(&pod, &config());
        assert!(identity_rewrite(&pod.rewritten(&rewrites), &config()).is_empty());
    }

    #[test]
    fn an_ephemeral_update_is_never_rewritten() {
        let mut pod = dwo_pod();
        pod.admission = Admission::EphemeralUpdate {
            old_host_users: None,
        };
        assert!(identity_rewrite(&pod, &config()).is_empty());
    }

    #[test]
    fn no_written_path_is_the_parent_of_another() {
        let mut pod = dwo_pod();
        pod.security_context = PodSecurityContext::default();
        let paths: Vec<Vec<String>> = identity_rewrite(&pod, &config())
            .iter()
            .map(Rewrite::path)
            .collect();
        for path in &paths {
            assert!(path.len() >= 2);
            for other in &paths {
                assert!(
                    other == path || !other.starts_with(path),
                    "{path:?} under {other:?}"
                );
            }
        }
    }
}
