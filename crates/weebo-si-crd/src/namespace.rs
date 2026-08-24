//! A namespace name, as it appears on the wire in every place `WeeboSiConfig` names one.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A namespace name. A newtype rather than a bare `String` so a namespace can never be passed
/// where a team name or a catalogue key is expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct NamespaceName(String);

impl NamespaceName {
    /// Wrap a namespace name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NamespaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
