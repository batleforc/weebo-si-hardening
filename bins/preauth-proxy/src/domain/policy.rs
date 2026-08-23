//! The per-request decision, and the replay state machine.
//!
//! Both are pure functions over facts. No I/O, no `async`, no HTTP client — which is the point:
//! the lifecycle logic is the whole value of the brick, and it is tested here against a table
//! rather than against a live login form.

use super::config::Renew;
use http::StatusCode;

/// What the inbound adapter observed about one request, reduced to what the decision needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestFacts {
    /// Whether the passthrough marker was found in the configured request header.
    pub marker_present: bool,
}

/// What the proxy is holding when the decision is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheState {
    /// Whether a credential is currently held.
    pub holds_credential: bool,
}

/// What to do with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Forward untouched. The caller brought its own credential.
    PassThrough,
    /// Attach the held credential and forward.
    Inject,
    /// Mint a credential first, then attach it and forward.
    AcquireThenInject,
}

/// Decide what happens to one request.
///
/// The marker check comes first and is unconditional: **a request that already carries its own
/// credential is never overridden**, whatever the cache holds. That is what keeps the automated
/// jobs that log in for themselves from being re-attributed to the proxy's identity.
pub const fn decide(facts: RequestFacts, cache: CacheState) -> Action {
    if facts.marker_present {
        Action::PassThrough
    } else if cache.holds_credential {
        Action::Inject
    } else {
        Action::AcquireThenInject
    }
}

/// What to do with one upstream response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterResponse {
    /// Give it to the caller as-is.
    Relay,
    /// The held credential is stale: discard it, acquire a fresh one, and replay the request.
    RenewAndReplay,
}

/// The replay budget for one inbound request.
///
/// A fresh [`Exchange`] is created per request, so the budget can never leak between callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    replays_used: u32,
}

impl Exchange {
    /// Start a request with a full replay budget.
    pub const fn new() -> Self {
        Self { replays_used: 0 }
    }

    /// How many replays this request has already spent — the count the adapter logs.
    pub const fn replays_used(self) -> u32 {
        self.replays_used
    }

    /// Decide what to do with a response, spending a replay if one is taken.
    ///
    /// `injected` is false for a passed-through request: renewing on behalf of a caller whose own
    /// credential the upstream rejected would replace their identity with ours, which is exactly
    /// what *pass through* promised not to do.
    pub fn on_response(
        &mut self,
        status: StatusCode,
        renew: &Renew,
        injected: bool,
    ) -> AfterResponse {
        if !injected || self.replays_used >= renew.max_replays || !renew.triggers(status) {
            return AfterResponse::Relay;
        }
        self.replays_used += 1;
        AfterResponse::RenewAndReplay
    }
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
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

    const fn facts(marker_present: bool) -> RequestFacts {
        RequestFacts { marker_present }
    }

    const fn cache(holds_credential: bool) -> CacheState {
        CacheState { holds_credential }
    }

    fn renew_on_401(max_replays: u32) -> Renew {
        Renew {
            on_status: vec![StatusCode::UNAUTHORIZED],
            max_replays,
        }
    }

    #[test]
    fn the_full_decision_table() {
        // (marker present, holds credential) -> action
        let cases = [
            ((true, true), Action::PassThrough),
            ((true, false), Action::PassThrough),
            ((false, true), Action::Inject),
            ((false, false), Action::AcquireThenInject),
        ];
        for ((marker, held), expected) in cases {
            assert_eq!(
                decide(facts(marker), cache(held)),
                expected,
                "marker={marker} held={held}"
            );
        }
    }

    #[test]
    fn a_marker_carrying_request_is_never_injected_into() {
        // Stated as its own test because it is the property the security section leans on.
        assert_eq!(decide(facts(true), cache(true)), Action::PassThrough);
    }

    #[test]
    fn a_renewal_status_spends_one_replay() {
        let renew = renew_on_401(1);
        let mut exchange = Exchange::new();
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
            AfterResponse::RenewAndReplay
        );
        assert_eq!(exchange.replays_used(), 1);
    }

    #[test]
    fn replays_exhausted_surfaces_the_status() {
        let renew = renew_on_401(1);
        let mut exchange = Exchange::new();
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
            AfterResponse::RenewAndReplay
        );
        // The second failure is the caller's problem, not another round trip.
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
            AfterResponse::Relay
        );
        assert_eq!(exchange.replays_used(), 1);
    }

    #[test]
    fn a_status_outside_the_list_is_relayed() {
        let renew = renew_on_401(1);
        let mut exchange = Exchange::new();
        for status in [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::FOUND,
        ] {
            assert_eq!(
                exchange.on_response(status, &renew, true),
                AfterResponse::Relay,
                "{status} should not trigger a renewal"
            );
        }
        assert_eq!(exchange.replays_used(), 0);
    }

    #[test]
    fn an_empty_status_list_disables_renewal() {
        let never = Renew::default();
        let mut exchange = Exchange::new();
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &never, true),
            AfterResponse::Relay
        );
    }

    #[test]
    fn a_passed_through_request_is_never_renewed_on_behalf_of_its_caller() {
        let renew = renew_on_401(1);
        let mut exchange = Exchange::new();
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, false),
            AfterResponse::Relay,
            "renewing here would swap the caller's identity for ours"
        );
        assert_eq!(exchange.replays_used(), 0);
    }

    #[test]
    fn a_zero_replay_budget_never_replays() {
        let renew = renew_on_401(0);
        let mut exchange = Exchange::new();
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
            AfterResponse::Relay
        );
    }

    #[test]
    fn a_larger_budget_allows_more_replays() {
        let renew = renew_on_401(2);
        let mut exchange = Exchange::new();
        for expected_used in 1..=2 {
            assert_eq!(
                exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
                AfterResponse::RenewAndReplay
            );
            assert_eq!(exchange.replays_used(), expected_used);
        }
        assert_eq!(
            exchange.on_response(StatusCode::UNAUTHORIZED, &renew, true),
            AfterResponse::Relay
        );
    }
}
