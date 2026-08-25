//! The admission adapters: `dwoc-pin`'s mutating webhook (`AdmissionReview` in, JSON Patch out —
//! see RFC 0002's *Webhook configuration*), `policy-guard`'s validating webhook
//! (`AdmissionReview` in, allow/deny out — see RFC 0004's *Design → Contract*), and
//! `image-policy`'s two validating routes over `DevWorkspace` and `Pod` (RFC 0005's *Two
//! enforcement points*).

pub mod extract;
pub mod image_policy;
pub mod metrics;
pub mod policy_guard;
pub mod registry_guard;
pub mod render;
pub mod router;

pub use image_policy::{
    ImagePolicyState, VALIDATE_DEVWORKSPACES_PATH, VALIDATE_PODS_PATH, image_policy_router,
    registries,
};
pub use metrics::WebhookMetrics;
pub use policy_guard::{PolicyGuardState, VALIDATE_NETWORK_POLICIES_PATH, policy_guard_router};
pub use registry_guard::{
    RegistryGuardState, VALIDATE_REGISTRY_CONFIGS_PATH, registry_guard_router,
};
pub use router::{AppState, MUTATE_DEVWORKSPACES_PATH, NetworkProfilesAdmission, router};
