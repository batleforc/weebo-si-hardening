//! The `dwoc-pin` mutating admission webhook adapter. `AdmissionReview` in, JSON Patch out —
//! see RFC 0002's *Webhook configuration*.

pub mod extract;
pub mod metrics;
pub mod render;
pub mod router;

pub use metrics::WebhookMetrics;
pub use router::{AppState, MUTATE_DEVWORKSPACES_PATH, router};
