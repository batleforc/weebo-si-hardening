//! `spec.features.<name>.mode` — see RFC 0002's *Contract*, "Modes, and why three rather than a
//! boolean."

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A feature absent from `spec.features` is `Off`. Not "default on", not "inherit" — a
/// behaviour nobody wrote down does not run. **Deliberately no `Default` impl and no
/// `#[serde(default)]` anywhere this type is used**: the RFC is explicit that a *present*
/// feature's `mode` has no implicit default in the resource — omitting it entirely is a
/// rejected write, not a silent `Off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum FeatureMode {
    /// The feature does not run.
    Off,
    /// The feature runs and is counted and logged; nothing is applied.
    DryRun,
    /// The feature runs, is counted and logged, and its result is applied.
    Enforce,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    struct HasMode {
        mode: FeatureMode,
    }

    #[test]
    fn mode_has_no_implicit_default() {
        let result: Result<HasMode, _> = serde_json::from_value(serde_json::json!({}));
        assert!(
            result.is_err(),
            "an absent `mode` must be a rejected write, not a silent Off"
        );
    }
}
