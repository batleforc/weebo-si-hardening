//! `backend: Auto` resolved — see RFC 0013's *OpenShift*.

use weebo_si_crd::PodSecurityBackend;

/// What this feature does on this cluster: write the labels, or only read OpenShift's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveBackend {
    /// Write the six labels and the `-previous` annotation.
    Labels,
    /// Write nothing; compare the level OpenShift's label syncer set with the resolved one.
    ObserveSynced,
}

/// Resolve the configured backend. `serves_scc` is whether the apiserver serves
/// `security.openshift.io/v1`, which an adapter learns by discovery at startup — the same way
/// `kubearmor-policy` resolves its enforcement backend.
///
/// On OpenShift the `cluster-policy-controller` owns the `pod-security.kubernetes.io/*` labels,
/// and the fleet keeps it on. Two writers on one label is not a state anyone should be
/// debugging, so `Auto` never writes there.
pub fn effective_backend(configured: PodSecurityBackend, serves_scc: bool) -> EffectiveBackend {
    match configured {
        PodSecurityBackend::Labels => EffectiveBackend::Labels,
        PodSecurityBackend::ObserveSynced => EffectiveBackend::ObserveSynced,
        PodSecurityBackend::Auto if serves_scc => EffectiveBackend::ObserveSynced,
        PodSecurityBackend::Auto => EffectiveBackend::Labels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_observes_on_openshift_and_writes_elsewhere() {
        assert_eq!(
            effective_backend(PodSecurityBackend::Auto, true),
            EffectiveBackend::ObserveSynced
        );
        assert_eq!(
            effective_backend(PodSecurityBackend::Auto, false),
            EffectiveBackend::Labels
        );
    }

    #[test]
    fn an_explicit_backend_wins_over_discovery() {
        for serves_scc in [true, false] {
            assert_eq!(
                effective_backend(PodSecurityBackend::Labels, serves_scc),
                EffectiveBackend::Labels
            );
            assert_eq!(
                effective_backend(PodSecurityBackend::ObserveSynced, serves_scc),
                EffectiveBackend::ObserveSynced
            );
        }
    }
}
