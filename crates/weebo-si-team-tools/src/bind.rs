//! The binding gate and the client identity gate — RFC 0020, *Validation* rows "Team
//! `namespace` exists …", "Tools namespace holds at least one `ResourceQuota` …" and "A client
//! certificate is minted only for …". Both fail closed: nothing is written in a namespace that
//! fails the first, no certificate is asked for a namespace that fails the second.

use std::collections::BTreeMap;

use weebo_si_crd::{NamespaceName, TEAM_TOOLS_NAMESPACE_LABEL, TeamName};

/// The label every workspace namespace carries (the pod webhooks select it). A tools namespace
/// must not carry it.
pub const WORKSPACE_NAMESPACE_LABEL: &str = "hardening.weebo.io/workspace-namespace";
/// The structural exclusion label (`namespaceExclusionLabel`'s default): present, whatever its
/// value, means out of scope.
pub const EXCLUDE_LABEL: &str = "hardening.weebo.io/exclude";
/// The namespace owner, written by Che and writable by admins only; the client certificate's CN.
pub const USERNAME_ANNOTATION: &str = "che.eclipse.org/username";
/// The quota resource the binding gate requires (RFC 0020, D1).
pub const MEMORY_LIMIT_RESOURCE: &str = "limits.memory";
/// The longest X.509 `commonName` (RFC 5280, `ub-common-name`).
const MAX_COMMON_NAME: usize = 64;

/// What the controller knows of a tools namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolsNamespace {
    /// `metadata.labels`.
    pub labels: BTreeMap<String, String>,
    /// `spec.hard` of every `ResourceQuota` in it.
    pub quotas: Vec<BTreeMap<String, String>>,
}

/// Why a team's tools namespace is not bound. Each is `TeamToolsReady=False` with
/// [`Unbound::reason`]; nothing is written in the namespace, nothing is deleted there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unbound {
    /// Missing, not labelled for this team, a workspace namespace, or the operator's or the
    /// template namespace.
    NamespaceNotBound(String),
    /// No `ResourceQuota` constrains `limits.memory`.
    NoQuota(String),
    /// A write returned 403: the admin did not bind the ClusterRole there.
    Forbidden(String),
}

impl Unbound {
    /// The 403 case, reported by the adapter that saw it.
    pub fn forbidden(namespace: &NamespaceName) -> Self {
        Self::Forbidden(format!(
            "writing in namespace {namespace} was refused (403): bind the ClusterRole \
             weebo-si-team-tools there with a RoleBinding"
        ))
    }

    /// The condition reason.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NamespaceNotBound(_) => "NamespaceNotBound",
            Self::NoQuota(_) => "NoQuota",
            Self::Forbidden(_) => "Forbidden",
        }
    }

    /// The condition message.
    pub fn message(&self) -> &str {
        match self {
            Self::NamespaceNotBound(message)
            | Self::NoQuota(message)
            | Self::Forbidden(message) => message,
        }
    }
}

/// Whether one of `quotas` constrains `limits.memory`.
pub fn has_memory_quota(quotas: &[BTreeMap<String, String>]) -> bool {
    quotas
        .iter()
        .any(|hard| hard.contains_key(MEMORY_LIMIT_RESOURCE))
}

/// The binding gate (RFC 0020, T3 and D1): `facts` is `None` when the namespace does not exist.
/// The third gate, the RoleBinding, is the apiserver's ([`Unbound::forbidden`]).
pub fn check_tools_namespace(
    team: &TeamName,
    namespace: &NamespaceName,
    facts: Option<&ToolsNamespace>,
    operator_namespace: &NamespaceName,
    template_namespace: &NamespaceName,
) -> Result<(), Unbound> {
    let not_bound = |why: String| {
        Err(Unbound::NamespaceNotBound(format!(
            "namespace {namespace} {why}; nothing is rendered there"
        )))
    };
    if namespace == operator_namespace || namespace == template_namespace {
        return not_bound("is the operator's or the template namespace".to_string());
    }
    let Some(facts) = facts else {
        return not_bound("does not exist".to_string());
    };
    if facts
        .labels
        .get(TEAM_TOOLS_NAMESPACE_LABEL)
        .map(String::as_str)
        != Some(team.as_str())
    {
        return not_bound(format!(
            "does not carry {TEAM_TOOLS_NAMESPACE_LABEL}={team}"
        ));
    }
    if facts.labels.contains_key(WORKSPACE_NAMESPACE_LABEL) {
        return not_bound(format!(
            "carries {WORKSPACE_NAMESPACE_LABEL}: a workspace namespace is never a tools namespace"
        ));
    }
    if !has_memory_quota(&facts.quotas) {
        return Err(Unbound::NoQuota(format!(
            "namespace {namespace} holds no ResourceQuota constraining {MEMORY_LIMIT_RESOURCE}; \
             nothing is rendered there"
        )));
    }
    Ok(())
}

/// The client certificate's CN, or `None` (no certificate, fail closed): the namespace is a
/// workspace namespace (`workspace-namespace=true`), not excluded, and carries a usable
/// `che.eclipse.org/username`. Never read from the DevWorkspace (RFC 0020, S2).
pub fn client_identity<'a>(
    labels: &BTreeMap<String, String>,
    username: Option<&'a str>,
) -> Option<&'a str> {
    if labels.get(WORKSPACE_NAMESPACE_LABEL).map(String::as_str) != Some("true")
        || labels.contains_key(EXCLUDE_LABEL)
    {
        return None;
    }
    username.filter(|name| {
        !name.is_empty()
            && name.trim() == *name
            && name.len() <= MAX_COMMON_NAME
            && !name.chars().any(char::is_control)
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::fixtures::{
        OPERATOR_NS, TEMPLATE_NS, TOOLS_NS, bound_tools_namespace, weebo_labels,
    };

    fn check(namespace: &str, facts: Option<&ToolsNamespace>) -> Result<(), Unbound> {
        check_tools_namespace(
            &TeamName::new("weebo"),
            &NamespaceName::new(namespace),
            facts,
            &NamespaceName::new(OPERATOR_NS),
            &NamespaceName::new(TEMPLATE_NS),
        )
    }

    #[test]
    fn a_labelled_namespace_with_a_memory_quota_is_bound() {
        assert_eq!(check(TOOLS_NS, Some(&bound_tools_namespace())), Ok(()));
    }

    #[test]
    fn an_unlabelled_namespace_is_never_written() {
        let mut facts = bound_tools_namespace();
        facts.labels.remove(TEAM_TOOLS_NAMESPACE_LABEL);
        let unbound = check("kube-system", Some(&facts)).unwrap_err();
        assert_eq!(unbound.reason(), "NamespaceNotBound");
        assert_eq!(
            unbound.message(),
            "namespace kube-system does not carry hardening.weebo.io/team-tools=weebo; nothing is \
             rendered there"
        );
        // Labelled for another team.
        facts
            .labels
            .insert(TEAM_TOOLS_NAMESPACE_LABEL.to_string(), "data".to_string());
        assert_eq!(
            check(TOOLS_NS, Some(&facts)).unwrap_err().reason(),
            "NamespaceNotBound"
        );
        assert_eq!(
            check(TOOLS_NS, None).unwrap_err().reason(),
            "NamespaceNotBound"
        );
    }

    #[test]
    fn a_workspace_namespace_is_never_a_tools_namespace() {
        let mut facts = bound_tools_namespace();
        facts
            .labels
            .insert(WORKSPACE_NAMESPACE_LABEL.to_string(), "false".to_string());
        assert_eq!(
            check(TOOLS_NS, Some(&facts)).unwrap_err().reason(),
            "NamespaceNotBound"
        );
    }

    #[test]
    fn the_operator_and_template_namespaces_are_never_tools_namespaces() {
        let facts = bound_tools_namespace();
        assert!(check(OPERATOR_NS, Some(&facts)).is_err());
        assert!(check(TEMPLATE_NS, Some(&facts)).is_err());
    }

    #[test]
    fn a_namespace_without_quota_is_unbound() {
        let mut facts = bound_tools_namespace();
        facts.quotas = vec![BTreeMap::from([(
            "requests.cpu".to_string(),
            "4".to_string(),
        )])];
        assert_eq!(
            check(TOOLS_NS, Some(&facts)).unwrap_err().reason(),
            "NoQuota"
        );
        facts.quotas.clear();
        assert_eq!(
            check(TOOLS_NS, Some(&facts)).unwrap_err().reason(),
            "NoQuota"
        );
    }

    #[test]
    fn a_forbidden_write_is_its_own_reason() {
        let unbound = Unbound::forbidden(&NamespaceName::new(TOOLS_NS));
        assert_eq!(unbound.reason(), "Forbidden");
        assert!(unbound.message().contains("RoleBinding"));
    }

    #[test]
    fn no_username_means_no_certificate() {
        let labels = weebo_labels();
        assert_eq!(client_identity(&labels, None), None);
        assert_eq!(client_identity(&labels, Some("  ")), None);
        assert_eq!(client_identity(&labels, Some(" bob")), None);
        assert_eq!(client_identity(&labels, Some(&"a".repeat(65))), None);
        assert_eq!(client_identity(&labels, Some("bob\nadmin")), None);
        assert_eq!(
            client_identity(&labels, Some("batleforc-test")),
            Some("batleforc-test")
        );
    }

    #[test]
    fn an_excluded_or_non_workspace_namespace_gets_no_certificate() {
        let mut labels = weebo_labels();
        labels.insert(EXCLUDE_LABEL.to_string(), String::new());
        assert_eq!(client_identity(&labels, Some("bob")), None);
        let mut labels = weebo_labels();
        labels.remove(WORKSPACE_NAMESPACE_LABEL);
        assert_eq!(client_identity(&labels, Some("bob")), None);
    }
}
