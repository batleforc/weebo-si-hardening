//! `/readyz`, `/livez`, `/healthz` and `/metrics`, per RFC 0002's *Observability contract* and
//! RFC 0012.
//!
//! Readiness and liveness are `weebo-kit-runtime`'s [`Health`]: `/readyz` answers only once the
//! caller marks the process ready (every watch cache synced), so a pod that cannot see one of
//! them receives no admission traffic instead of guessing; `/livez` fails once a component —
//! a watch erroring in a loop — has kept failing past the kit's threshold, so the kubelet
//! restarts a pod that would otherwise sit `Ready` doing nothing. `/healthz` is the kit's alias
//! of `/readyz`; the chart's liveness probe points at `/livez`, never at it.
//!
//! `/metrics` stays the `prometheus` crate's registry: the metric names are a contract, and the
//! kit's OpenTelemetry exporter derives names of its own (RFC 0012, *Data and state*).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use prometheus::{Encoder, Registry, TextEncoder};
use weebo_kit_runtime::Health;

/// How long a component may keep failing before `/livez` reports the process dead.
pub const LIVENESS_THRESHOLD: Duration = weebo_kit_runtime::health::DEFAULT_LIVENESS_THRESHOLD;

/// A fresh, not-yet-ready health handle.
pub fn health() -> Arc<Health> {
    Arc::new(Health::new(LIVENESS_THRESHOLD))
}

/// Serve the probes and `/metrics` on `addr` until the process exits.
pub async fn serve(
    addr: SocketAddr,
    health: Arc<Health>,
    registry: Registry,
) -> std::io::Result<()> {
    let app = weebo_kit_runtime::health::routes(health).route(
        "/metrics",
        get(move || {
            let registry = registry.clone();
            async move {
                let encoder = TextEncoder::new();
                let families = registry.gather();
                let mut buffer = Vec::new();
                if encoder.encode(&families, &mut buffer).is_err() {
                    return (StatusCode::INTERNAL_SERVER_ERROR, String::new());
                }
                (
                    StatusCode::OK,
                    String::from_utf8_lossy(&buffer).into_owned(),
                )
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}
