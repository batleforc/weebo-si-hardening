//! `/healthz`, `/readyz` and `/metrics`, per RFC 0002's *Observability contract*.
//!
//! `/healthz` answers as soon as the process serves; `/readyz` answers only once the caller
//! marks it ready (every watch cache synced), so a pod that cannot see one of them receives no
//! admission traffic instead of guessing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::routing::get;
use axum::{Router, http::StatusCode};
use prometheus::{Encoder, Registry, TextEncoder};

/// Flips to `true` once every watch cache this process depends on has synced.
#[derive(Clone, Default)]
pub struct Ready(Arc<AtomicBool>);

impl Ready {
    pub fn mark_ready(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    fn is_ready(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Serve `/healthz`, `/readyz` and `/metrics` on `addr` until the process exits.
pub async fn serve(addr: SocketAddr, ready: Ready, registry: Registry) -> std::io::Result<()> {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/readyz",
            get(move || {
                let ready = ready.clone();
                async move {
                    if ready.is_ready() {
                        (StatusCode::OK, "ok")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
                    }
                }
            }),
        )
        .route(
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
