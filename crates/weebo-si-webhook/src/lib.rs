//! Two admission adapters: `dwoc-pin`'s mutating webhook (`AdmissionReview` in, JSON Patch out —
//! see RFC 0002's *Webhook configuration*) and `policy-guard`'s validating webhook
//! (`AdmissionReview` in, allow/deny out — see RFC 0004's *Design → Contract*).

pub mod extract;
pub mod metrics;
pub mod policy_guard;
pub mod render;
pub mod router;

pub use metrics::WebhookMetrics;
pub use policy_guard::{PolicyGuardState, VALIDATE_NETWORK_POLICIES_PATH, policy_guard_router};
pub use router::{AppState, MUTATE_DEVWORKSPACES_PATH, NetworkProfilesAdmission, router};
