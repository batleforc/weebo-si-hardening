//! The self-origin probe — RFC 0009's *Checking that assumption rather than configuring it*.
//!
//! Pod-address identity rests on one property of the cluster's network: that the address the
//! ingress controller reports is the *connection's* address and not something a caller stated.
//! That property cannot be inferred passively — a header the controller derived and one it
//! repeated are identical on the wire — so it is **probed**.
//!
//! The probe sends one request to the gateway's own public URL carrying a forged client-address
//! header, and `/selftest` — on whichever replica the `Service` picks, since every replica derives
//! the same probe token from the shared session keys — reports what address it saw:
//!
//! * **the forged one**: the controller repeats client headers, and any pod in the cluster can
//!   claim any namespace's identity. Pod-address identity goes off on this replica at once and
//!   is recorded on the revocation `ConfigMap`, so every other replica turns it off too.
//! * **anything else**: the controller stripped or overwrote the header — conclusive, and under
//!   `pod_network: Auto` the only thing that turns pod-address identity **on**. `Auto` starts
//!   off (second-pass finding 2), so a replica whose probe has never been answered does not
//!   believe the header.
//! * **no answer**: inconclusive, retried with backoff. It changes nothing for a while — an
//!   outage in front of the gateway is not evidence about the controller — but a trust that has
//!   not been re-confirmed for [`STALE_AFTER_INTERVALS`] intervals lapses under `Auto`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::PodNetwork;
use crate::state::GatewayState;

/// An address no pod holds, and no controller would derive: if this comes back, the header was
/// repeated rather than derived.
const FORGED_ADDRESS: &str = "203.0.113.255";
/// How soon an inconclusive probe is retried, doubling up to the configured interval.
const RETRY_INITIAL: Duration = Duration::from_secs(5);
/// Under `Auto`, how many intervals a clean result stays good for without being re-confirmed.
pub const STALE_AFTER_INTERVALS: u32 = 3;

/// What one probe established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The forged address came back: the controller repeats client headers.
    Forged,
    /// `/selftest` answered and the forged address did not come back.
    Clean,
    /// Nothing was learned about the controller.
    Inconclusive(String),
}

/// Run the probe forever.
pub async fn run(state: Arc<GatewayState>, url: String, interval: Duration) {
    let client = crate::outbound::client();
    let mut retry = RETRY_INITIAL;
    let mut last_clean: Option<Instant> = None;
    loop {
        let result = probe_once(&client, &state, &url).await;
        let wait = match &result {
            ProbeResult::Inconclusive(_) => {
                let wait = retry.min(interval);
                retry = retry.saturating_mul(2).min(interval);
                wait
            }
            _ => {
                retry = RETRY_INITIAL;
                interval
            }
        };
        if result == ProbeResult::Clean {
            last_clean = Some(Instant::now());
        }
        let stale = last_clean
            .is_none_or(|at| at.elapsed() > interval.saturating_mul(STALE_AFTER_INTERVALS));
        apply(&state, &url, result, stale).await;
        tokio::time::sleep(wait).await;
    }
}

/// Act on one result.
async fn apply(state: &GatewayState, url: &str, result: ProbeResult, stale: bool) {
    let auto = state.config.self_origin.pod_network == PodNetwork::Auto;
    match result {
        ProbeResult::Forged => {
            state.metrics.probe("forged");
            state.workloads.revoke_address_trust();
            if let Err(err) = state.revocations.record_address_forgery(state.now()).await {
                eprintln!(
                    "WARN endpoint-gateway: could not record the forgery for the other replicas: \
                     {err}"
                );
            }
            eprintln!(
                "WARN endpoint-gateway: the probe's forged client address came back through \
                 {url}; pod-address identity is now OFF on every replica. Workspaces must use the \
                 service-account token path."
            );
        }
        ProbeResult::Clean => {
            state.metrics.probe("clean");
            if auto && !state.workloads.confirm_address_trust() {
                println!(
                    "endpoint-gateway: self-origin probe clean, but a forgery is recorded on the \
                     revocation ConfigMap; pod-address identity stays off"
                );
            } else {
                println!(
                    "endpoint-gateway: self-origin probe ok ({} workspace pods indexed)",
                    state.workloads.indexed_pods()
                );
            }
        }
        ProbeResult::Inconclusive(err) => {
            state.metrics.probe("inconclusive");
            if auto && stale && state.workloads.addresses_trusted() {
                state.workloads.revoke_address_trust();
                eprintln!(
                    "WARN endpoint-gateway: self-origin probe has not been conclusive for {} \
                     intervals; pod-address identity is off until it is",
                    STALE_AFTER_INTERVALS
                );
            }
            println!("WARN endpoint-gateway: self-origin probe inconclusive: {err}");
        }
    }
    state
        .metrics
        .address_trust(state.workloads.addresses_trusted());
}

/// One probe.
async fn probe_once(client: &reqwest::Client, state: &GatewayState, url: &str) -> ProbeResult {
    let Some(token) = state.selftest_tokens.first() else {
        return ProbeResult::Inconclusive("no probe token".to_owned());
    };
    let response = match client
        .get(format!("{url}/selftest"))
        .header(&state.config.self_origin.client_ip_header, FORGED_ADDRESS)
        .header("x-weebo-selftest", token.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return ProbeResult::Inconclusive(err.to_string()),
    };
    let status = response.status();
    let body = response.json::<serde_json::Value>().await.ok();
    classify(status, body.as_ref())
}

/// What a `/selftest` answer establishes.
pub fn classify(status: reqwest::StatusCode, body: Option<&serde_json::Value>) -> ProbeResult {
    if !status.is_success() {
        return ProbeResult::Inconclusive(format!("/selftest answered {status}"));
    }
    let Some(body) = body.filter(|body| body.get("address_seen").is_some()) else {
        return ProbeResult::Inconclusive("/selftest answered something else".to_owned());
    };
    if body
        .get("address_seen")
        .and_then(|seen| seen.as_str())
        .is_some_and(|seen| seen == FORGED_ADDRESS)
    {
        ProbeResult::Forged
    } else {
        ProbeResult::Clean
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
    fn the_forged_address_is_documentation_space_and_not_a_pod_address() {
        // TEST-NET-3 (RFC 5737): reserved for documentation, so it can never collide with a real
        // pod address and make the probe report a forgery that did not happen.
        assert!(FORGED_ADDRESS.starts_with("203.0.113."));
    }

    /// Second-pass finding 2: only an answered `/selftest` is conclusive either way; a `404`
    /// (another replica's token, before the token was derived) or an unreachable URL is not.
    #[test]
    fn only_an_answered_selftest_is_conclusive() {
        let ok = reqwest::StatusCode::OK;
        assert_eq!(
            classify(
                ok,
                Some(&serde_json::json!({"address_seen": FORGED_ADDRESS}))
            ),
            ProbeResult::Forged
        );
        assert_eq!(
            classify(ok, Some(&serde_json::json!({"address_seen": "10.128.0.9"}))),
            ProbeResult::Clean
        );
        // The header stripped altogether is conclusive too: the forgery did not survive.
        assert_eq!(
            classify(ok, Some(&serde_json::json!({"address_seen": null}))),
            ProbeResult::Clean
        );
        assert!(matches!(
            classify(reqwest::StatusCode::NOT_FOUND, None),
            ProbeResult::Inconclusive(_)
        ));
        assert!(matches!(
            classify(ok, Some(&serde_json::json!({"hello": "world"}))),
            ProbeResult::Inconclusive(_)
        ));
        assert!(matches!(classify(ok, None), ProbeResult::Inconclusive(_)));
    }
}
