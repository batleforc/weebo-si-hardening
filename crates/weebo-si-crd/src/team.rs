//! `spec.teams` — chassis-level, identity only, no policy. Every feature reads its own answer
//! from a team through the `grants` map it owns; see RFC 0002, "Teams are chassis-level."

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::selector::Selector;

/// A team name. A newtype so a team can never be passed where a catalogue key or a namespace
/// name is expected.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct TeamName(String);

impl TeamName {
    /// Wrap a team name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TeamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One entry of `spec.teams`. `spec.teams` as a whole is ordered and first-match-wins — that
/// rule is applied by [`crate::dwoc_pin::DwocPinConfig::validate`] and by the resolution chain
/// in `weebo-si-dwoc-pin`, not encoded on this type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Team {
    /// This team's identity, referenced by every feature's `grants`.
    pub name: TeamName,
    /// The namespaces that belong to this team.
    pub namespace_selector: Selector,
}
