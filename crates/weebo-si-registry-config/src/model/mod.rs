//! The values `registry-config` decides over: the objects it owns ([`object`]), the diff between
//! what should exist and what does ([`diff`]), and DevWorkspace Operator's automount vocabulary
//! ([`mount`]).

pub mod diff;
pub mod mount;
pub mod object;
