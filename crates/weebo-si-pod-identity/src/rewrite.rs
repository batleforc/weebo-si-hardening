//! `identity_rewrite`: what the mutation changes at the pod level (RFC 0018, Q21, L10, L14).
//!
//! Only pod-level paths (`spec.hostUsers`, `spec.securityContext.*`), never a container's: the
//! chassis renderer creates a missing parent as an object even before an array index, so a
//! container path the pod does not have would corrupt it (review of patch 02). No path here is
//! the parent of another, and `securityContext` itself is never written as a scalar.

use std::fmt;

use weebo_si_chassis::Mutation;
use weebo_si_crd::PodIdentityConfig;

use crate::subject::{Admission, ON_ROOT_MISMATCH, PodSubject, STRICT};

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
        }
    }

    fn path(self) -> Vec<String> {
        match self {
            Self::HostUsers => vec!["spec".to_string(), "hostUsers".to_string()],
            other => vec![
                "spec".to_string(),
                "securityContext".to_string(),
                other.name().to_string(),
            ],
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
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(value) => write!(f, "{value}"),
            Self::Bool(value) => write!(f, "{value}"),
            Self::Str(value) => f.write_str(value),
        }
    }
}

/// One field the mutation changes, with what it held before (`None`: unset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewrite {
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
        let path = self.field.path();
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
        }
    }

    /// Apply it to an in-memory pod, for judging the pod as the mutation would leave it (L23).
    fn apply(&self, pod: &mut PodSubject) {
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
    /// `runAsGroup=0->1234`, the `DryRun` line's shape.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
/// or `fsGroup: 0` → the configured gid; any other non-zero id kept; `runAsUser: 0` kept for
/// validation to refuse. `hostUsers` → `false`, `supplementalGroupsPolicy` → `Strict`,
/// `runAsNonRoot` → `true`, and `fsGroupChangePolicy: OnRootMismatch` when an id is rewritten.
pub fn identity_rewrite(pod: &PodSubject, config: &PodIdentityConfig) -> Vec<Rewrite> {
    if pod.admission != Admission::Create {
        return Vec::new();
    }
    let context = &pod.security_context;
    let mut out = Vec::new();
    if pod.host_users != Some(false) {
        out.push(Rewrite {
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
            Some(0),
            config.run_as_group,
        ),
    ];
    let mut ids_rewritten = false;
    for (field, current, also, to) in ids {
        if current.is_none() || current == also {
            ids_rewritten = true;
            out.push(Rewrite {
                field,
                from: current.map(Value::Int),
                to: Value::Int(to),
            });
        }
    }
    if ids_rewritten && context.fs_group_change_policy.as_deref() != Some(ON_ROOT_MISMATCH) {
        out.push(Rewrite {
            field: Field::FsGroupChangePolicy,
            from: context.fs_group_change_policy.clone().map(Value::Str),
            to: Value::Str(ON_ROOT_MISMATCH.to_string()),
        });
    }
    if context.supplemental_groups_policy.as_deref() != Some(STRICT) {
        out.push(Rewrite {
            field: Field::SupplementalGroupsPolicy,
            from: context.supplemental_groups_policy.clone().map(Value::Str),
            to: Value::Str(STRICT.to_string()),
        });
    }
    if context.run_as_non_root != Some(true) {
        out.push(Rewrite {
            field: Field::RunAsNonRoot,
            from: context.run_as_non_root.map(Value::Bool),
            to: Value::Bool(true),
        });
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
    use crate::subject::{ContainerIdentity, ContainerKind, PodSecurityContext};

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
            .map(|rewrite| rewrite.field.path())
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
