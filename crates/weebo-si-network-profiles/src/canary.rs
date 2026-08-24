//! The enforcement canary's verdict logic — per RFC 0004's *Security considerations*, the bypass
//! that "makes everything above decorative while every object looks correct":
//!
//! > `kubectl get networkpolicy` is not evidence of enforcement; only traffic is.
//!
//! Pure. Two observations in, one verdict out. Creating the pods, applying the deny policy and
//! reading the result off the cluster is [`crate::port::CanaryProbe`]'s adapter's job; the
//! sequencing of the two legs is [`crate::application::run_canary`]'s.

/// What one leg of the probe observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// The client reached the target.
    Reached,
    /// The client was refused or timed out reaching the target.
    Blocked,
    /// The probe could not produce an answer — the pod never scheduled, the image never pulled,
    /// the pod never reached a terminal phase. **Not** the same as `Blocked`, and conflating the
    /// two is how a broken canary reports a healthy cluster.
    Inconclusive,
}

/// What the pair of legs says about this cluster's CNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryVerdict {
    /// Reachable without a policy, unreachable with one: the CNI enforces.
    Enforcing,
    /// Reachable in both legs: **every policy this operator writes is decoration**.
    NotEnforcing,
    /// One of the legs could not be read. Reported until the first complete probe, and after any
    /// probe that could not finish — never silently folded into either of the other two.
    Unknown,
}

impl CanaryVerdict {
    /// The `result` label value on `weebo_si_network_canary`, per RFC 0004's *Observability
    /// contract*. Part of the metric contract — changing one needs a new RFC.
    pub fn label(self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::NotEnforcing => "not_enforcing",
            Self::Unknown => "unknown",
        }
    }
}

/// Read the two legs as a verdict.
///
/// The asymmetry is deliberate: only *reached-then-blocked* proves enforcement, and only
/// *reached-then-reached* disproves it. Every other pair means the probe failed to establish a
/// baseline, and a probe that cannot reach its own target with nothing in the way has measured
/// its own plumbing, not the cluster's.
pub fn verdict(unrestricted: Reachability, restricted: Reachability) -> CanaryVerdict {
    match (unrestricted, restricted) {
        (Reachability::Reached, Reachability::Blocked) => CanaryVerdict::Enforcing,
        (Reachability::Reached, Reachability::Reached) => CanaryVerdict::NotEnforcing,
        _ => CanaryVerdict::Unknown,
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
    fn reachable_then_blocked_is_the_only_proof_of_enforcement() {
        assert_eq!(
            verdict(Reachability::Reached, Reachability::Blocked),
            CanaryVerdict::Enforcing
        );
    }

    #[test]
    fn reachable_in_both_legs_means_the_cni_ignores_policy() {
        assert_eq!(
            verdict(Reachability::Reached, Reachability::Reached),
            CanaryVerdict::NotEnforcing
        );
    }

    #[test]
    fn a_target_unreachable_before_any_policy_is_unknown_never_enforcing() {
        // The trap this test exists for: a canary whose server pod never came up observes
        // "blocked" on both legs, and a naive `restricted == Blocked` check would report
        // `Enforcing` for a cluster that enforces nothing at all.
        assert_eq!(
            verdict(Reachability::Blocked, Reachability::Blocked),
            CanaryVerdict::Unknown
        );
    }

    #[test]
    fn an_inconclusive_leg_is_never_folded_into_a_definite_verdict() {
        for restricted in [
            Reachability::Reached,
            Reachability::Blocked,
            Reachability::Inconclusive,
        ] {
            assert_eq!(
                verdict(Reachability::Inconclusive, restricted),
                CanaryVerdict::Unknown
            );
        }
        assert_eq!(
            verdict(Reachability::Reached, Reachability::Inconclusive),
            CanaryVerdict::Unknown
        );
    }

    #[test]
    fn the_metric_labels_are_the_rfcs_own() {
        assert_eq!(CanaryVerdict::Enforcing.label(), "enforcing");
        assert_eq!(CanaryVerdict::NotEnforcing.label(), "not_enforcing");
        assert_eq!(CanaryVerdict::Unknown.label(), "unknown");
    }
}
