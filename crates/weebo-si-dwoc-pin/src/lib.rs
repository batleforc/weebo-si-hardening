//! The `dwoc-pin` feature — see RFC 0002, *Feature: `dwoc-pin`*.
//!
//! Fewest dependencies in the workspace on purpose: `weebo-si-crd` + `weebo-si-chassis` only,
//! matching "tested exhaustively without a cluster."

pub mod feature;
pub mod resolve;
pub mod workspace;

pub use feature::DwocPin;
pub use resolve::{Provenance, ResolutionStep, UnknownKey, resolve};
pub use workspace::Workspace;
