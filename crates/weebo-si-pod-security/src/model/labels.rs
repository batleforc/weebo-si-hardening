//! The six labels and the one annotation this feature owns — RFC 0013's *What is written*.

use std::collections::BTreeMap;
use std::fmt;

use weebo_si_crd::{PodSecurityLevel, PodSecurityVersion};

/// `pod-security.kubernetes.io/enforce`: the level the apiserver refuses pods against.
pub const ENFORCE: &str = "pod-security.kubernetes.io/enforce";
/// `pod-security.kubernetes.io/enforce-version`.
pub const ENFORCE_VERSION: &str = "pod-security.kubernetes.io/enforce-version";
/// `pod-security.kubernetes.io/warn`: the level the apiserver warns against, on every write.
pub const WARN: &str = "pod-security.kubernetes.io/warn";
/// `pod-security.kubernetes.io/warn-version`.
pub const WARN_VERSION: &str = "pod-security.kubernetes.io/warn-version";
/// `pod-security.kubernetes.io/audit`: the level the audit log annotates against.
pub const AUDIT: &str = "pod-security.kubernetes.io/audit";
/// `pod-security.kubernetes.io/audit-version`.
pub const AUDIT_VERSION: &str = "pod-security.kubernetes.io/audit-version";

/// The six label keys, and the only labels this feature ever touches.
pub const KEYS: [&str; 6] = [
    ENFORCE,
    ENFORCE_VERSION,
    WARN,
    WARN_VERSION,
    AUDIT,
    AUDIT_VERSION,
];

/// The six keys' values from before this feature first wrote to the namespace, as JSON. Written
/// once, never rewritten, removed on restore.
pub const PREVIOUS_ANNOTATION: &str = "hardening.weebo.io/pod-security-previous";

/// The server-side apply field manager. Part of the contract: it is how the operator owns exactly
/// these keys and no other label on the namespace.
pub const FIELD_MANAGER: &str = "weebo-si-pod-security";

/// The six keys' values, as found on a namespace or as this feature wants them. Holds no other
/// key: a namespace's other labels are none of this feature's business, and a type that could
/// carry them would let a bug write them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PodSecurityLabels(BTreeMap<String, String>);

/// The `-previous` annotation could not be read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousError(pub String);

impl fmt::Display for PreviousError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unreadable {PREVIOUS_ANNOTATION}: {}", self.0)
    }
}

impl PodSecurityLabels {
    /// The six keys a namespace carries, out of all its labels.
    pub fn from_namespace(labels: &BTreeMap<String, String>) -> Self {
        Self(
            labels
                .iter()
                .filter(|(key, _)| KEYS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    }

    /// What a resolved `(level, warn_level)` writes: all six keys, every version label set to
    /// `version`, `warn` and `audit` both at `warn_level`.
    pub fn desired(
        level: PodSecurityLevel,
        warn_level: PodSecurityLevel,
        version: &PodSecurityVersion,
    ) -> Self {
        let version = version.as_str().to_string();
        Self(BTreeMap::from([
            (ENFORCE.to_string(), level.as_str().to_string()),
            (ENFORCE_VERSION.to_string(), version.clone()),
            (WARN.to_string(), warn_level.as_str().to_string()),
            (WARN_VERSION.to_string(), version.clone()),
            (AUDIT.to_string(), warn_level.as_str().to_string()),
            (AUDIT_VERSION.to_string(), version),
        ]))
    }

    /// The level the namespace enforces, if its `enforce` label names one the apiserver reads.
    pub fn enforce(&self) -> Option<PodSecurityLevel> {
        self.0
            .get(ENFORCE)
            .and_then(|value| PodSecurityLevel::parse(value))
    }

    /// The value of one key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Every key present, with its value.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    /// Whether none of the six keys is present.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The `-previous` annotation's value for these labels: a JSON object, `{}` when there were
    /// none. Keys sorted, so the same labels always serialize the same way.
    pub fn to_previous(&self) -> String {
        let object: serde_json::Map<String, serde_json::Value> = self
            .0
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect();
        serde_json::Value::Object(object).to_string()
    }

    /// Read a `-previous` annotation back. Strict: an object of string values, every key one of
    /// the six. Anything else was not written by this feature, and restoring from it would write
    /// labels this feature does not own.
    pub fn from_previous(raw: &str) -> Result<Self, PreviousError> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|err| PreviousError(err.to_string()))?;
        let serde_json::Value::Object(object) = value else {
            return Err(PreviousError("not a JSON object".to_string()));
        };
        let mut labels = BTreeMap::new();
        for (key, value) in object {
            if !KEYS.contains(&key.as_str()) {
                return Err(PreviousError(format!("{key} is not a Pod Security label")));
            }
            let serde_json::Value::String(value) = value else {
                return Err(PreviousError(format!("{key} is not a string")));
            };
            labels.insert(key, value);
        }
        Ok(Self(labels))
    }
}

impl FromIterator<(String, String)> for PodSecurityLabels {
    /// Keeps the six keys and drops anything else, like [`PodSecurityLabels::from_namespace`].
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .filter(|(key, _)| KEYS.contains(&key.as_str()))
                .collect(),
        )
    }
}

/// One line of the difference between two label sets — what a `DryRun` logs as `diff=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelChange {
    /// The key is set to this value, created or changed.
    Set {
        /// The full label key.
        key: String,
        /// Its new value.
        value: String,
    },
    /// The key is removed.
    Remove {
        /// The full label key.
        key: String,
    },
}

impl fmt::Display for LabelChange {
    /// `set:enforce=restricted` or `remove:warn`, the key without its `pod-security.kubernetes.io/`
    /// prefix — the RFC's log line format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |key: &str| {
            key.strip_prefix("pod-security.kubernetes.io/")
                .unwrap_or(key)
                .to_string()
        };
        match self {
            Self::Set { key, value } => write!(f, "set:{}={value}", short(key)),
            Self::Remove { key } => write!(f, "remove:{}", short(key)),
        }
    }
}

/// What turns `current` into `desired`, in key order. Empty when they are equal.
pub fn diff(current: &PodSecurityLabels, desired: &PodSecurityLabels) -> Vec<LabelChange> {
    KEYS.iter()
        .filter_map(|key| match (current.get(key), desired.get(key)) {
            (old, Some(new)) if old != Some(new) => Some(LabelChange::Set {
                key: (*key).to_string(),
                value: new.to_string(),
            }),
            (Some(_), None) => Some(LabelChange::Remove {
                key: (*key).to_string(),
            }),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn version() -> PodSecurityVersion {
        PodSecurityVersion::new("v1.34")
    }

    #[test]
    fn desired_writes_exactly_the_six_keys() {
        let labels = PodSecurityLabels::desired(
            PodSecurityLevel::Baseline,
            PodSecurityLevel::Restricted,
            &version(),
        );
        let keys: Vec<&str> = labels.as_map().keys().map(String::as_str).collect();
        let mut expected = KEYS.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
        assert_eq!(labels.get(ENFORCE), Some("baseline"));
        assert_eq!(labels.get(WARN), Some("restricted"));
        assert_eq!(labels.get(AUDIT), Some("restricted"));
        for key in [ENFORCE_VERSION, WARN_VERSION, AUDIT_VERSION] {
            assert_eq!(labels.get(key), Some("v1.34"));
        }
    }

    #[test]
    fn a_namespaces_other_labels_are_dropped() {
        let labels = PodSecurityLabels::from_namespace(&BTreeMap::from([
            ("weebo.io/team".to_string(), "team-1".to_string()),
            (ENFORCE.to_string(), "baseline".to_string()),
        ]));
        assert_eq!(labels.as_map().len(), 1);
        assert_eq!(labels.enforce(), Some(PodSecurityLevel::Baseline));
    }

    #[test]
    fn an_enforce_value_the_apiserver_does_not_read_is_no_level() {
        let labels: PodSecurityLabels = [(ENFORCE.to_string(), "Restricted".to_string())]
            .into_iter()
            .collect();
        assert_eq!(labels.enforce(), None);
    }

    #[test]
    fn previous_round_trips_and_is_an_empty_object_for_no_labels() {
        assert_eq!(PodSecurityLabels::default().to_previous(), "{}");
        let labels: PodSecurityLabels = [
            (ENFORCE.to_string(), "privileged".to_string()),
            (WARN.to_string(), "baseline".to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            PodSecurityLabels::from_previous(&labels.to_previous()).unwrap(),
            labels
        );
    }

    #[test]
    fn previous_refuses_anything_this_feature_would_not_have_written() {
        for raw in [
            "",
            "[]",
            "\"restricted\"",
            r#"{"weebo.io/team":"team-1"}"#,
            r#"{"pod-security.kubernetes.io/enforce":3}"#,
        ] {
            assert!(PodSecurityLabels::from_previous(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn diff_lists_sets_and_removals_in_key_order() {
        let current: PodSecurityLabels = [
            (ENFORCE.to_string(), "privileged".to_string()),
            (AUDIT.to_string(), "baseline".to_string()),
        ]
        .into_iter()
        .collect();
        let desired: PodSecurityLabels = [(ENFORCE.to_string(), "restricted".to_string())]
            .into_iter()
            .collect();
        let rendered: Vec<String> = diff(&current, &desired)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(rendered, vec!["set:enforce=restricted", "remove:audit"]);
        assert!(diff(&desired, &desired).is_empty());
    }
}
