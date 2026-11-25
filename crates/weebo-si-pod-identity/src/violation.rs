//! `identity_violations`: what validation refuses (RFC 0018, *Invariant*, L16–L18, Q21), one
//! message per reason, each naming the field and what to change (L28).

use std::fmt;

use weebo_si_crd::PodIdentityConfig;

use crate::subject::{Admission, ContainerIdentity, ContainerKind, PodSubject, STRICT};

/// The container a violation names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRef {
    /// Which list it comes from.
    pub kind: ContainerKind,
    /// Its name.
    pub name: String,
}

impl From<&ContainerIdentity> for ContainerRef {
    fn from(container: &ContainerIdentity) -> Self {
        Self {
            kind: container.kind,
            name: container.name.clone(),
        }
    }
}

impl fmt::Display for ContainerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `{:?}` quotes and escapes: the name is attacker-shaped and admission runs before the
        // apiserver validates it.
        write!(f, "{} {:?}", self.kind.noun(), self.name)
    }
}

/// One reason to refuse a pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// `hostUsers` is not `false` (the value, `None` when unset).
    HostUsers(Option<bool>),
    /// An effective uid of 0: a container's (`Some`) or the pod level's (`None`).
    UidZero(Option<ContainerRef>),
    /// A container's effective gid is 0.
    GidZero(ContainerRef),
    /// No uid at container or pod level: the image's `USER` applies.
    UidUnset(ContainerRef),
    /// No gid at container or pod level: the image's primary group applies.
    GidUnset(ContainerRef),
    /// `fsGroup: 0`.
    FsGroupZero,
    /// `0` in `supplementalGroups`.
    GroupZero,
    /// `supplementalGroupsPolicy` other than `Strict` (the value, `None` when unset).
    Policy(Option<String>),
    /// A new ephemeral container on a pod still in the node's user namespace (L18).
    EphemeralOnHostUserns(String),
}

impl Violation {
    /// The `reason` label of `weebo_si_pod_identity_refusals_total`.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::HostUsers(_) => "host_users",
            Self::UidZero(_) => "uid_zero",
            Self::GidZero(_) => "gid_zero",
            Self::UidUnset(_) => "uid_unset",
            Self::GidUnset(_) => "gid_unset",
            Self::FsGroupZero => "fs_group_zero",
            Self::GroupZero => "group_zero",
            Self::Policy(_) => "policy",
            Self::EphemeralOnHostUserns(_) => "ephemeral_on_host_userns",
        }
    }

    /// The container it names, if any — the `container=` field of the log line.
    pub fn container(&self) -> Option<&ContainerRef> {
        match self {
            Self::UidZero(container) => container.as_ref(),
            Self::GidZero(container) | Self::UidUnset(container) | Self::GidUnset(container) => {
                Some(container)
            }
            _ => None,
        }
    }
}

impl fmt::Display for Violation {
    /// The refusal message, as the RFC's mocks word it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostUsers(Some(value)) => write!(
                f,
                "hostUsers={value}: pods in a workspace namespace run in their own user \
                 namespace; remove hostUsers from the pod spec (or the devfile's pod-overrides)"
            ),
            // Unset only reaches validation when the mutation did not run: nothing to remove.
            Self::HostUsers(None) => f.write_str(
                "hostUsers is unset: pods in a workspace namespace run in their own user \
                 namespace; set hostUsers: false in the pod spec (the pod-identity mutation did \
                 not run)",
            ),
            Self::UidZero(container) => {
                if let Some(container) = container {
                    write!(f, "{container}: ")?;
                }
                f.write_str(
                    "securityContext.runAsUser=0 is not allowed in a workspace namespace; set a \
                     non-zero runAsUser or remove it",
                )
            }
            Self::GidZero(container) => write!(
                f,
                "{container}: securityContext.runAsGroup=0 is not allowed in a workspace \
                 namespace; remove runAsGroup from the devfile's container-overrides or set a \
                 non-zero group"
            ),
            Self::UidUnset(container) => write!(
                f,
                "{container}: no runAsUser at container or pod level, so the image's USER \
                 applies and may be root; set runAsUser at pod level"
            ),
            Self::GidUnset(container) => write!(
                f,
                "{container}: no runAsGroup at container or pod level, so the image's primary \
                 group applies and may be root; set runAsGroup at pod level"
            ),
            Self::FsGroupZero => f.write_str(
                "securityContext.fsGroup=0 is not allowed in a workspace namespace; remove \
                 fsGroup from the devfile's pod-overrides",
            ),
            Self::GroupZero => f.write_str(
                "securityContext.supplementalGroups contains 0; remove it from the devfile's \
                 pod-overrides",
            ),
            Self::Policy(Some(policy)) => write!(
                f,
                "securityContext.supplementalGroupsPolicy={policy:?} lets the image's /etc/group \
                 add group 0; remove it from the devfile's pod-overrides"
            ),
            Self::Policy(None) => f.write_str(
                "securityContext.supplementalGroupsPolicy is unset, so the default Merge lets the \
                 image's /etc/group add group 0; set it to Strict",
            ),
            Self::EphemeralOnHostUserns(name) => write!(
                f,
                "ephemeral container {name:?}: this pod still shares the node's user namespace \
                 (created before pod-identity was enforced); restart the workspace, then debug it"
            ),
        }
    }
}

/// Every reason to refuse `pod`, in the flowchart's order: `hostUsers`, each container's
/// effective uid and gid (container value, else pod value), `fsGroup` and supplementary group 0
/// (unless `grantGroupZero`, L16), the policy.
///
/// On an ephemeral-container update the pod level is immutable and was judged at creation: a
/// pod whose `oldObject.spec.hostUsers` is not `false` refuses every new container (L18),
/// otherwise only the new containers' ids are judged.
pub fn identity_violations(pod: &PodSubject, config: &PodIdentityConfig) -> Vec<Violation> {
    let context = &pod.security_context;
    let mut out = Vec::new();
    let create = match pod.admission {
        Admission::Create => true,
        Admission::EphemeralUpdate { old_host_users } => {
            if old_host_users != Some(false) {
                return pod
                    .containers
                    .iter()
                    .map(|container| Violation::EphemeralOnHostUserns(container.name.clone()))
                    .collect();
            }
            false
        }
    };
    if create && pod.host_users != Some(false) {
        out.push(Violation::HostUsers(pod.host_users));
    }
    // Pod-level uid 0 is refused even when every container overrides it (Q21), once.
    let pod_uid_zero = create && context.run_as_user == Some(0);
    if pod_uid_zero {
        out.push(Violation::UidZero(None));
    }
    for container in &pod.containers {
        match (container.run_as_user, context.run_as_user) {
            (Some(0), _) => out.push(Violation::UidZero(Some(container.into()))),
            (None, Some(0)) if !pod_uid_zero => {
                out.push(Violation::UidZero(Some(container.into())));
            }
            (None, None) => out.push(Violation::UidUnset(container.into())),
            _ => {}
        }
        match container.run_as_group.or(context.run_as_group) {
            Some(0) => out.push(Violation::GidZero(container.into())),
            None => out.push(Violation::GidUnset(container.into())),
            Some(_) => {}
        }
    }
    if !create {
        return out;
    }
    if !config.grant_group_zero {
        if context.fs_group == Some(0) {
            out.push(Violation::FsGroupZero);
        }
        if context.supplemental_groups.contains(&0) {
            out.push(Violation::GroupZero);
        }
    }
    if context.supplemental_groups_policy.as_deref() != Some(STRICT) {
        out.push(Violation::Policy(
            context.supplemental_groups_policy.clone(),
        ));
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::rewrite::identity_rewrite;
    use crate::rewrite::tests::{config, container, dwo_pod, fixed_pod};

    fn reasons(pod: &PodSubject, config: &PodIdentityConfig) -> Vec<&'static str> {
        identity_violations(pod, config)
            .iter()
            .map(Violation::reason)
            .collect()
    }

    fn tools() -> ContainerRef {
        ContainerRef {
            kind: ContainerKind::Container,
            name: "tools".to_string(),
        }
    }

    #[test]
    fn the_fixed_pod_passes() {
        assert!(identity_violations(&fixed_pod(), &config()).is_empty());
    }

    #[test]
    fn host_users_true_is_refused() {
        let mut pod = fixed_pod();
        pod.host_users = Some(true);
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::HostUsers(Some(true))]
        );
    }

    #[test]
    fn host_users_unset_is_refused_when_unmutated() {
        let mut pod = fixed_pod();
        pod.host_users = None;
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::HostUsers(None)]
        );
    }

    #[test]
    fn container_uid_zero_is_refused() {
        let mut pod = fixed_pod();
        pod.containers.push(container("sidecar", Some(0), None));
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::UidZero(Some(ContainerRef {
                kind: ContainerKind::Container,
                name: "sidecar".to_string()
            }))]
        );
    }

    #[test]
    fn container_gid_zero_is_refused() {
        let mut pod = fixed_pod();
        pod.containers = vec![container("tools", None, Some(0))];
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::GidZero(tools())]
        );
    }

    #[test]
    fn unset_uid_with_root_image_is_refused_when_unmutated() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_user = None;
        pod.security_context.run_as_group = None;
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::UidUnset(tools()), Violation::GidUnset(tools())]
        );
        // The container's own ids are enough.
        pod.containers = vec![container("tools", Some(999), Some(999))];
        assert!(identity_violations(&pod, &config()).is_empty());
    }

    #[test]
    fn container_nonzero_other_uid_is_allowed() {
        let mut pod = fixed_pod();
        pod.containers
            .push(container("otel", Some(999), Some(10001)));
        assert!(identity_violations(&pod, &config()).is_empty());
    }

    #[test]
    fn init_containers_are_judged_too() {
        let mut pod = fixed_pod();
        pod.containers.push(ContainerIdentity {
            kind: ContainerKind::Init,
            name: "copy-vault-env".to_string(),
            run_as_user: Some(0),
            run_as_group: None,
        });
        assert_eq!(reasons(&pod, &config()), ["uid_zero"]);
    }

    #[test]
    fn fs_group_zero_is_refused() {
        let mut pod = fixed_pod();
        pod.security_context.fs_group = Some(0);
        assert_eq!(reasons(&pod, &config()), ["fs_group_zero"]);
    }

    #[test]
    fn group_zero_refused_by_default() {
        let mut pod = fixed_pod();
        pod.security_context.supplemental_groups = vec![1234, 0];
        assert_eq!(reasons(&pod, &config()), ["group_zero"]);
    }

    #[test]
    fn group_zero_absent_unless_opted_in() {
        let mut pod = fixed_pod();
        pod.security_context.supplemental_groups = vec![0];
        pod.security_context.fs_group = Some(0);
        let mut granted = config();
        granted.grant_group_zero = true;
        assert!(identity_violations(&pod, &granted).is_empty());
        // The mutation never writes `supplementalGroups` (Q18), granted or not.
        assert!(
            identity_rewrite(&fixed_pod(), &granted).is_empty(),
            "grantGroupZero only relaxes validation"
        );
    }

    #[test]
    fn merge_policy_is_refused() {
        let mut pod = fixed_pod();
        pod.security_context.supplemental_groups_policy = Some("Merge".to_string());
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::Policy(Some("Merge".to_string()))]
        );
    }

    #[test]
    fn pod_level_uid_zero_is_refused_not_rewritten() {
        let mut pod = fixed_pod();
        pod.security_context.run_as_user = Some(0);
        assert!(identity_rewrite(&pod, &config()).is_empty());
        assert_eq!(
            identity_violations(&pod, &config()),
            [Violation::UidZero(None)]
        );
        // Refused even when every container chose its own uid.
        pod.containers = vec![container("tools", Some(1000), None)];
        assert_eq!(reasons(&pod, &config()), ["uid_zero"]);
    }

    #[test]
    fn the_raw_dwo_pod_is_refused_for_what_the_mutation_fixes() {
        assert_eq!(
            reasons(&dwo_pod(), &config()),
            ["host_users", "gid_zero", "policy"]
        );
    }

    fn ephemeral(old_host_users: Option<bool>, uid: Option<i64>) -> PodSubject {
        let mut pod = fixed_pod();
        pod.admission = Admission::EphemeralUpdate { old_host_users };
        pod.containers = vec![ContainerIdentity {
            kind: ContainerKind::Ephemeral,
            name: "debugger-x7".to_string(),
            run_as_user: uid,
            run_as_group: None,
        }];
        pod
    }

    #[test]
    fn ephemeral_container_uid_zero_is_refused() {
        assert_eq!(
            reasons(&ephemeral(Some(false), Some(0)), &config()),
            ["uid_zero"]
        );
        assert!(identity_violations(&ephemeral(Some(false), None), &config()).is_empty());
    }

    #[test]
    fn ephemeral_on_host_userns_pod_is_refused() {
        for old in [None, Some(true)] {
            assert_eq!(
                identity_violations(&ephemeral(old, None), &config()),
                [Violation::EphemeralOnHostUserns("debugger-x7".to_string())]
            );
        }
    }

    #[test]
    fn each_refusal_reason_has_its_message() {
        let cases = [
            (
                Violation::HostUsers(Some(true)),
                "hostUsers=true: pods in a workspace namespace run in their own user namespace; \
                 remove hostUsers from the pod spec (or the devfile's pod-overrides)",
            ),
            (
                Violation::HostUsers(None),
                "hostUsers is unset: pods in a workspace namespace run in their own user \
                 namespace; set hostUsers: false in the pod spec (the pod-identity mutation did \
                 not run)",
            ),
            (
                Violation::UidZero(Some(tools())),
                "container \"tools\": securityContext.runAsUser=0 is not allowed in a workspace \
                 namespace; set a non-zero runAsUser or remove it",
            ),
            (
                Violation::UidZero(None),
                "securityContext.runAsUser=0 is not allowed in a workspace namespace; set a \
                 non-zero runAsUser or remove it",
            ),
            (
                Violation::GidZero(tools()),
                "container \"tools\": securityContext.runAsGroup=0 is not allowed in a workspace \
                 namespace; remove runAsGroup from the devfile's container-overrides or set a \
                 non-zero group",
            ),
            (
                Violation::UidUnset(tools()),
                "container \"tools\": no runAsUser at container or pod level, so the image's \
                 USER applies and may be root; set runAsUser at pod level",
            ),
            (
                Violation::GidUnset(tools()),
                "container \"tools\": no runAsGroup at container or pod level, so the image's \
                 primary group applies and may be root; set runAsGroup at pod level",
            ),
            (
                Violation::FsGroupZero,
                "securityContext.fsGroup=0 is not allowed in a workspace namespace; remove \
                 fsGroup from the devfile's pod-overrides",
            ),
            (
                Violation::GroupZero,
                "securityContext.supplementalGroups contains 0; remove it from the devfile's \
                 pod-overrides",
            ),
            (
                Violation::Policy(Some("Merge".to_string())),
                "securityContext.supplementalGroupsPolicy=\"Merge\" lets the image's /etc/group \
                 add group 0; remove it from the devfile's pod-overrides",
            ),
            (
                Violation::Policy(None),
                "securityContext.supplementalGroupsPolicy is unset, so the default Merge lets \
                 the image's /etc/group add group 0; set it to Strict",
            ),
            (
                Violation::EphemeralOnHostUserns("debugger-x7".to_string()),
                "ephemeral container \"debugger-x7\": this pod still shares the node's user \
                 namespace (created before pod-identity was enforced); restart the workspace, \
                 then debug it",
            ),
        ];
        for (violation, message) in cases {
            assert_eq!(violation.to_string(), message, "{}", violation.reason());
        }
    }

    #[test]
    fn a_hostile_container_name_is_escaped() {
        let violation = Violation::GidZero(ContainerRef {
            kind: ContainerKind::Init,
            name: "x\"; allowed\n".to_string(),
        });
        assert!(
            violation
                .to_string()
                .starts_with("init container \"x\\\"; allowed\\n\":")
        );
    }
}
