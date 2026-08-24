//! The two namespaces `network-profiles` refuses to touch, wherever it runs.
//!
//! Per RFC 0004's *Security considerations*: "Two namespaces are excluded **structurally**: the
//! operator's own and Che's... The exclusion is a compiled-in refusal, not a configuration
//! default, because a configuration default can be overwritten by the person debugging at three
//! in the morning."
//!
//! It lives in the domain crate, not next to the controller loop that first needed it, because
//! both roles need the same answer: the controller must not *write* a baseline into these
//! namespaces, and the webhook's [`crate::feature::workspace_gate::WorkspaceGate`] must not
//! *reject a workspace* for the absence of a baseline that will, correctly, never arrive. Two
//! copies of this rule that disagree is a wedged namespace.

use weebo_si_crd::NamespaceName;

/// Che's own namespace, by this repo's established convention — see RFC 0002's and
/// `weebo-si-dwoc-pin`'s own tests.
pub const CHE_NAMESPACE: &str = "eclipse-che";

/// Whether `namespace` is structurally out of `network-profiles`' reach.
///
/// A deny-all baseline in the operator's own namespace severs our own apiserver connection, and
/// the recovery for that is editing objects by hand from outside the cluster.
pub fn is_excluded_namespace(
    namespace: &NamespaceName,
    operator_namespace: &NamespaceName,
) -> bool {
    namespace.as_str() == operator_namespace.as_str() || namespace.as_str() == CHE_NAMESPACE
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn operator_ns() -> NamespaceName {
        NamespaceName::new("weebo-si-hardening")
    }

    #[test]
    fn the_operators_own_namespace_is_excluded() {
        assert!(is_excluded_namespace(
            &NamespaceName::new("weebo-si-hardening"),
            &operator_ns()
        ));
    }

    #[test]
    fn ches_namespace_is_excluded_whatever_the_operator_runs_in() {
        assert!(is_excluded_namespace(
            &NamespaceName::new(CHE_NAMESPACE),
            &NamespaceName::new("somewhere-else")
        ));
    }

    #[test]
    fn an_ordinary_workspace_namespace_is_not_excluded() {
        assert!(!is_excluded_namespace(
            &NamespaceName::new("user-alice"),
            &operator_ns()
        ));
    }

    /// The compiled-in refusal, stated as a signature test: `is_excluded_namespace` takes
    /// exactly two namespaces and nothing else. There is no parameter here through which a
    /// `WeeboSiConfig` value could reach it, which is the RFC's guarantee — "not a configuration
    /// default, because a configuration default can be overwritten by the person debugging at
    /// three in the morning" — expressed the same way `weebo-si-webhook`'s `log_admission`
    /// expresses its own ("there is no parameter a caller could pass the object through").
    #[test]
    fn the_exclusion_takes_no_configuration_parameter() {
        let signature: fn(&NamespaceName, &NamespaceName) -> bool = is_excluded_namespace;
        assert!(signature(
            &NamespaceName::new(CHE_NAMESPACE),
            &operator_ns()
        ));
    }
}
