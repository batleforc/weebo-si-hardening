//! Which resource a guarded write is against — RFC 0008's *Design → Contract*.

use std::fmt;

/// The resources `policy-guard` covers.
///
/// **Closed on purpose**, for the reason RFC 0007 gives about `Ecosystem`: it becomes a metric
/// label, and a label whose value set is open is a label nobody can write an alert against.
/// Adding the next guarded resource is a variant here, a rule in the chart and a row in
/// [`crate::guard::PolicyGuard`]'s test matrix — not a new decision about what the guard means.
///
/// It is deliberately *not* a superset of every object this operator writes: `configmaps` and
/// `secrets` are guarded by `weebo-si-registry-config`'s own two-row guard (RFC 0007), which
/// differs in a way this enum cannot express — it has no unmanaged-`CREATE` row, because its
/// webhook rule carries an ownership `objectSelector`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GuardedResource {
    /// `networking.k8s.io/v1` `NetworkPolicy` — RFC 0004's baseline.
    NetworkPolicy,
    /// `cilium.io/v2` `CiliumNetworkPolicy` — the same baseline on a Cilium cluster.
    CiliumNetworkPolicy,
    /// `security.kubearmor.com/v1` `KubeArmorPolicy` — RFC 0006's runtime baseline.
    KubeArmorPolicy,
}

impl GuardedResource {
    /// The Kubernetes kind, as it appears in a manifest and as the `resource` label on
    /// `weebo_si_admission_requests_total` and `weebo_si_admission_duration_seconds`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NetworkPolicy => "NetworkPolicy",
            Self::CiliumNetworkPolicy => "CiliumNetworkPolicy",
            Self::KubeArmorPolicy => "KubeArmorPolicy",
        }
    }

    /// The plural, lower-case name the apiserver puts in an `AdmissionRequest`'s `resource` —
    /// the string an admission adapter matches on to build a [`crate::GuardedWrite`].
    ///
    /// Paired with [`Self::as_str`] here rather than left to the adapter so that adding a
    /// variant cannot produce a resource the guard knows by kind but not by wire name.
    pub fn plural(&self) -> &'static str {
        match self {
            Self::NetworkPolicy => "networkpolicies",
            Self::CiliumNetworkPolicy => "ciliumnetworkpolicies",
            Self::KubeArmorPolicy => "kubearmorpolicies",
        }
    }

    /// Every member — for a test that must cover the whole table, and for a metric that
    /// publishes one series per resource.
    pub const ALL: [GuardedResource; 3] = [
        GuardedResource::NetworkPolicy,
        GuardedResource::CiliumNetworkPolicy,
        GuardedResource::KubeArmorPolicy,
    ];

    /// The resource an `AdmissionRequest`'s plural names, or `None` for anything else.
    ///
    /// `None` is not an error and must not be treated as one: the rules this guard's paths serve
    /// list exactly these resources, so a fourth arriving means the webhook configuration and
    /// this code disagree — and **allowing** is the right answer, because the guard's whole job
    /// is to protect objects this operator wrote, and it did not write that one.
    pub fn from_plural(plural: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|resource| resource.plural() == plural)
    }
}

impl fmt::Display for GuardedResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_round_trips_through_its_plural() {
        for resource in GuardedResource::ALL {
            assert_eq!(
                GuardedResource::from_plural(resource.plural()),
                Some(resource),
                "{resource} does not round-trip — an adapter matching on the plural would \
                 silently stop guarding it"
            );
        }
    }

    #[test]
    fn an_unknown_plural_is_not_guessed_at() {
        assert_eq!(GuardedResource::from_plural("configmaps"), None);
        assert_eq!(GuardedResource::from_plural(""), None);
    }
}
