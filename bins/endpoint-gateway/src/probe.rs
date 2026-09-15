//! The self-origin probe — RFC 0009's *Checking that assumption rather than configuring it*.
//!
//! Pod-address identity rests on one property of the cluster's network: that the address the
//! ingress controller reports is the *connection's* address and not something a caller stated.
//! That property cannot be inferred passively — a header the controller derived and one it
//! repeated are identical on the wire — so it is **probed**.
//!
//! The probe sends one request to the gateway's own public URL carrying a forged client-address
//! header. If the gateway sees the forged value, the controller is repeating client headers and
//! any pod in the cluster can claim any namespace's identity. The answer is to turn the
//! mechanism off, and the probe can only ever do that: **it never turns pod-address identity on**,
//! because "the forgery did not arrive this time" is not evidence that it cannot.

use std::sync::Arc;
use std::time::Duration;

use crate::state::GatewayState;

/// An address no pod holds, and no controller would derive: if this comes back, the header was
/// repeated rather than derived.
const FORGED_ADDRESS: &str = "203.0.113.255";

/// Run the probe forever.
pub async fn run(state: Arc<GatewayState>, url: String, interval: Duration) {
    let client = reqwest::Client::new();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match probe_once(&client, &state, &url).await {
            Ok(true) => {
                state.workloads.revoke_address_trust();
                state.metrics.address_trust(false);
                println!(
                    "WARN endpoint-gateway: the probe's forged client address came back through \
                     {url}; pod-address identity is now OFF. Workspaces must use the \
                     service-account token path."
                );
            }
            Ok(false) => {
                state
                    .metrics
                    .address_trust(state.workloads.addresses_trusted());
                println!(
                    "endpoint-gateway: self-origin probe ok ({} workspace pods indexed)",
                    state.workloads.indexed_pods()
                );
            }
            Err(err) => {
                // A probe that cannot reach its own public URL says nothing about the property
                // it tests, so it changes nothing: revoking on a network error would turn an
                // outage in front of the gateway into a silent loss of self-origin.
                println!("WARN endpoint-gateway: self-origin probe inconclusive: {err}");
            }
        }
    }
}

/// One probe. `Ok(true)` means a forged address survived the trip.
async fn probe_once(
    client: &reqwest::Client,
    state: &GatewayState,
    url: &str,
) -> Result<bool, String> {
    let response = client
        .get(format!("{url}/selftest"))
        .header(&state.config.self_origin.client_ip_header, FORGED_ADDRESS)
        .header("x-weebo-selftest", state.selftest_token.clone())
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("/selftest answered {}", response.status()));
    }
    let body: serde_json::Value = response.json().await.map_err(|err| err.to_string())?;
    Ok(body
        .get("address_seen")
        .and_then(|seen| seen.as_str())
        .is_some_and(|seen| seen == FORGED_ADDRESS))
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
}
