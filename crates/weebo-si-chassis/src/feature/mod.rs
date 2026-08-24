//! Chassis-level value types shared by every feature, and the `Feature<S>` trait + registry.
//! See RFC 0002's *Contract* section, "Terminology," and *Architecture*, "The feature trait, and
//! the invariant."

mod registry;
mod value;

pub use registry::{Context, Feature, Registry, Subject};
pub use value::{Decision, FeatureId, FeatureOutcome};
