//! The two halves of `image-policy` — see RFC 0005's *Two enforcement points*.
//!
//! Both are ordinary [`Feature<S>`](weebo_si_chassis::Feature) implementations, which is worth
//! stating: [RFC 0004](../../../../docs/rfc/0004-network-profiles.md) needed a second chassis
//! trait because a reconcile feature returns objects that belong somewhere else, and a
//! *validating* feature does not — it returns a `Decision` with `denial: Some(..)` and no
//! mutations, which is what `policy-guard` already does. So this RFC adds no trait, and it gets
//! the mode invariant for free: **`DryRun` on a validating feature is "who would I have denied",
//! computed by the identical code path that will deny them.**
//!
//! Both report the same `FeatureId` — `image-policy` — so one `mode` and one `namespaceSelector`
//! govern both, exactly as `network-profiles`' reconcile and admission halves share theirs.

pub mod core;
pub mod pod_images;
pub mod workspace_images;
