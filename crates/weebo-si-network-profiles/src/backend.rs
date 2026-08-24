//! `Auto`→concrete `Backend` resolution, per RFC 0004's *Design*: "`Auto` resolves to the most
//! capable backend the apiserver advertises, in declaration order." Pure — the discovery call
//! itself is `Capabilities`' adapter's job (a later phase's); this function only answers "given
//! what the cluster offers, which backend wins."

use weebo_si_crd::{Backend, EnforcementBackend};

use crate::port::Capabilities;

/// Preference order when resolving `Auto`: `Cilium` before `NetworkPolicy`, per the RFC's
/// *Alternatives* — Cilium is the richer dialect (`toFQDNs`, identity-based rules) wherever it's
/// available.
const AUTO_PREFERENCE: [Backend; 2] = [Backend::Cilium, Backend::NetworkPolicy];

/// Resolve `preference` against what `capabilities` reports. `Auto` tries each backend in
/// [`AUTO_PREFERENCE`] order and returns the first one offered. An explicit backend is checked
/// directly — **never silently substituted for another**: an admin who named `NetworkPolicy` on
/// a Cilium-only cluster gets `None`, not a surprise `Cilium` object, per the RFC's "no coarser
/// fallback unless the admin wrote it as a variant."
///
/// `None` means nothing usable is available; the caller decides what that means for the object
/// under construction (the baseline refuses to enforce at all, a profile is simply not applied
/// for that backend — see RFC 0004's *Design*, "Backends and degradation").
pub fn resolve_backend(
    preference: EnforcementBackend,
    capabilities: &dyn Capabilities,
) -> Option<Backend> {
    match preference {
        EnforcementBackend::Auto => AUTO_PREFERENCE
            .into_iter()
            .find(|backend| capabilities.offers(*backend)),
        EnforcementBackend::NetworkPolicy => capabilities
            .offers(Backend::NetworkPolicy)
            .then_some(Backend::NetworkPolicy),
        EnforcementBackend::Cilium => capabilities
            .offers(Backend::Cilium)
            .then_some(Backend::Cilium),
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
    fn auto_prefers_cilium_when_both_are_offered() {
        let caps = FakeCapabilities::new([Backend::NetworkPolicy, Backend::Cilium]);
        assert_eq!(
            resolve_backend(EnforcementBackend::Auto, &caps),
            Some(Backend::Cilium)
        );
    }

    #[test]
    fn auto_falls_back_to_network_policy_when_cilium_is_not_offered() {
        let caps = FakeCapabilities::new([Backend::NetworkPolicy]);
        assert_eq!(
            resolve_backend(EnforcementBackend::Auto, &caps),
            Some(Backend::NetworkPolicy)
        );
    }

    #[test]
    fn auto_resolves_to_none_when_neither_is_offered() {
        let caps = FakeCapabilities::new([]);
        assert_eq!(resolve_backend(EnforcementBackend::Auto, &caps), None);
    }

    #[test]
    fn an_explicit_backend_is_returned_when_offered() {
        let caps = FakeCapabilities::new([Backend::NetworkPolicy]);
        assert_eq!(
            resolve_backend(EnforcementBackend::NetworkPolicy, &caps),
            Some(Backend::NetworkPolicy)
        );
    }

    #[test]
    fn an_explicit_backend_not_offered_resolves_to_none_never_a_substitute() {
        let caps = FakeCapabilities::new([Backend::Cilium]);
        assert_eq!(
            resolve_backend(EnforcementBackend::NetworkPolicy, &caps),
            None,
            "an admin who pinned NetworkPolicy must never silently get Cilium instead"
        );
    }

    #[test]
    fn explicit_cilium_not_offered_resolves_to_none() {
        let caps = FakeCapabilities::new([Backend::NetworkPolicy]);
        assert_eq!(resolve_backend(EnforcementBackend::Cilium, &caps), None);
    }
}
