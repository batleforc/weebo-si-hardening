//! The rules, and the traits the outside implements for them.
//!
//! Nothing in here imports a HTTP client, a server, or a framework. It does use the `http` and
//! `bytes` crates — pure data types with no I/O and no runtime, and the vocabulary a proxy's
//! domain is actually written in. [RFC 0003](../../../../docs/rfc/0003-preauth-proxy.md) allows
//! exactly that much: "no HTTP client type, no framework".

pub mod config;
pub mod credential;
pub mod exchange;
pub mod policy;
pub mod port;
