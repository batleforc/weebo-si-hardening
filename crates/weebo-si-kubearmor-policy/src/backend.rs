//! `Auto`→concrete [`RuntimeBackend`] resolution, per RFC 0006's *Design → Contract*:
//! "`enforcement.backend: EnforcementBackend` — `Auto | KubeArmor`, mirroring
//! `network-profiles::EnforcementBackend`'s shape for the one real reason to keep it: a second
//! backend later is a new variant and a resolver change, not a schema break."
//!
//! Pure — the discovery call itself is a [`Capabilities`] adapter's job; this function only
//! answers "given what the cluster offers, which engine wins."
//!
//! **Trivial today, and written so it stays honest when it stops being trivial.** With one
//! member, `Auto` could have been a one-liner returning `Some(KubeArmor)` unconditionally. It is
//! not: it asks `Capabilities` like the two-member version will, so a cluster with no
//! `KubeArmorPolicy` CRD resolves to `None` rather than to an engine that is not there.

use weebo_si_crd::{RuntimeBackend, RuntimeEnforcementBackend};

use crate::port::Capabilities;

/// Preference order when resolving `Auto`. One entry today; the order is the contract for the
/// day there are two, exactly as `network-profiles`' `AUTO_PREFERENCE` is.
const AUTO_PREFERENCE: [RuntimeBackend; 1] = [RuntimeBackend::KubeArmor];

/// Resolve `preference` against what `capabilities` reports. `Auto` tries each engine in
/// [`AUTO_PREFERENCE`] order and returns the first one offered. An explicit engine is checked
/// directly — **never silently substituted for another**.
///
/// `None` means nothing usable is available; the caller writes nothing rather than approximating,
/// per RFC 0006's *Guide-level explanation*: "not applied, not approximated."
pub fn resolve_backend(
    preference: RuntimeEnforcementBackend,
    capabilities: &dyn Capabilities,
) -> Option<RuntimeBackend> {
    match preference {
        RuntimeEnforcementBackend::Auto => AUTO_PREFERENCE
            .into_iter()
            .find(|backend| capabilities.offers(*backend)),
        RuntimeEnforcementBackend::KubeArmor => capabilities
            .offers(RuntimeBackend::KubeArmor)
            .then_some(RuntimeBackend::KubeArmor),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use crate::port::testing::FakeCapabilities;

    use super::*;

    #[test]
    fn auto_resolves_to_kubearmor_when_the_cluster_offers_it() {
        let caps = FakeCapabilities::new([RuntimeBackend::KubeArmor]);
        assert_eq!(
            resolve_backend(RuntimeEnforcementBackend::Auto, &caps),
            Some(RuntimeBackend::KubeArmor)
        );
    }

    #[test]
    fn auto_resolves_to_none_on_a_cluster_without_the_kubearmor_crd() {
        // The reason `Auto` asks rather than assuming: a cluster with no `KubeArmorPolicy` CRD
        // must produce no objects, not objects the apiserver will reject one at a time.
        let caps = FakeCapabilities::new([]);
        assert_eq!(
            resolve_backend(RuntimeEnforcementBackend::Auto, &caps),
            None
        );
    }

    #[test]
    fn an_explicit_backend_is_returned_when_offered() {
        let caps = FakeCapabilities::new([RuntimeBackend::KubeArmor]);
        assert_eq!(
            resolve_backend(RuntimeEnforcementBackend::KubeArmor, &caps),
            Some(RuntimeBackend::KubeArmor)
        );
    }

    #[test]
    fn an_explicit_backend_not_offered_resolves_to_none_never_a_substitute() {
        let caps = FakeCapabilities::new([]);
        assert_eq!(
            resolve_backend(RuntimeEnforcementBackend::KubeArmor, &caps),
            None,
            "an admin who pinned an engine must never silently get another one"
        );
    }
}
