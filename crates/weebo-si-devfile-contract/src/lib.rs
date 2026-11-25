//! The `devfile-contract` feature — see RFC 0019.
//!
//! Tells a developer, through admission warnings and a verdict annotation, that their devfile was
//! written for old platform rules or follows a parent that can change under it; refuses a start
//! only for an admin-listed denied contract or parent. Pure: the subject and the config handle
//! are all it reads, so it has no port and no adapters crate (RFC 0019, *Architecture*). It
//! never fetches the parent.
//!
//! Dependency floor: `weebo-si-crd` + `weebo-si-chassis`, plus `serde_json` for the free-form
//! contract attribute.

pub mod feature;
pub mod parse;
pub mod subject;

pub use feature::{DevfileContract, FEATURE_ID, Verdict, denied_match};
pub use parse::{
    Contract, SchemaVersion, UriPin, classify_parent_uri, excerpt, normalise_uri, parse_contract,
    scan_schema_version,
};
pub use subject::{DevfileWorkspace, Parent, is_start};
