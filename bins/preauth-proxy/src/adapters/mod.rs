//! What drives the application, and what the application drives.
//!
//! Adapters know about [`crate::domain`]; nothing in the domain knows about them.

pub mod config_file;
pub mod http_client;
pub mod inbound_http;
