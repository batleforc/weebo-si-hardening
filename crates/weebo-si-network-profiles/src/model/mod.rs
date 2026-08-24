//! The reconcile-specific object model — never shared with the chassis, per RFC 0004's
//! *Architecture*: "desired state" is resource-specific vocabulary.

pub mod diff;
pub mod policy;
