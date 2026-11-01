//! What leaving puts back — RFC 0013's *Leaving is symmetric*.
//!
//! A namespace leaves when `mode` goes to `Off`, or when it leaves scope (selector,
//! `hardening.weebo.io/exclude`, a structural exclusion). Unlike `network-profiles`, cleanup here is
//! free: the state lives on the namespace object, which the controller already watches.

use std::collections::BTreeMap;

use crate::model::labels::{KEYS, PodSecurityLabels};
use crate::model::plan::Found;

/// The write that undoes this feature on one namespace: set some of the six keys back, remove the
/// others, and remove the `-previous` annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restore {
    /// Keys put back to the value they had before the first write.
    pub set: BTreeMap<String, String>,
    /// Keys that were absent before the first write, removed.
    pub remove: Vec<String>,
    /// The `-previous` annotation was missing or unreadable, so the labels are removed instead of
    /// restored — `result=previous_lost`.
    pub previous_lost: bool,
}

/// What to write to undo this feature, or `None` when it never wrote to this namespace.
///
/// * A readable `-previous`: its keys are set back, every other of the six removed.
/// * No readable `-previous`, but keys this feature owns: the six are removed. There is nothing
///   older to restore.
/// * Neither: nothing. A namespace this feature never touched keeps whatever it carries, including
///   labels an admin set by hand.
pub fn restore(found: &Found) -> Option<Restore> {
    let previous = found
        .previous
        .as_deref()
        .map(PodSecurityLabels::from_previous);
    match previous {
        Some(Ok(previous)) => Some(Restore {
            set: previous.as_map().clone(),
            remove: KEYS
                .iter()
                .filter(|key| previous.get(key).is_none())
                .map(|key| (*key).to_string())
                .collect(),
            previous_lost: false,
        }),
        Some(Err(_)) => Some(remove_all()),
        None if found.owned => Some(remove_all()),
        None => None,
    }
}

fn remove_all() -> Restore {
    Restore {
        set: BTreeMap::new(),
        remove: KEYS.iter().map(|key| (*key).to_string()).collect(),
        previous_lost: true,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::model::labels::{AUDIT, ENFORCE, WARN};

    #[test]
    fn the_keys_found_before_the_first_write_are_set_back_and_the_rest_removed() {
        let restore = restore(&Found {
            previous: Some(r#"{"pod-security.kubernetes.io/enforce":"privileged"}"#.to_string()),
            owned: true,
            ..Found::default()
        })
        .unwrap();
        assert_eq!(
            restore.set,
            BTreeMap::from([(ENFORCE.to_string(), "privileged".to_string())])
        );
        assert_eq!(restore.remove.len(), 5);
        assert!(!restore.remove.contains(&ENFORCE.to_string()));
        assert!(!restore.previous_lost);
    }

    #[test]
    fn an_empty_previous_removes_all_six() {
        let restore = restore(&Found {
            previous: Some("{}".to_string()),
            ..Found::default()
        })
        .unwrap();
        assert!(restore.set.is_empty());
        assert_eq!(restore.remove.len(), 6);
        assert!(restore.remove.contains(&WARN.to_string()));
        assert!(restore.remove.contains(&AUDIT.to_string()));
        assert!(!restore.previous_lost);
    }

    #[test]
    fn owned_labels_with_no_previous_are_removed_and_reported() {
        let restore = restore(&Found {
            owned: true,
            ..Found::default()
        })
        .unwrap();
        assert!(restore.set.is_empty());
        assert_eq!(restore.remove.len(), 6);
        assert!(restore.previous_lost);
    }

    #[test]
    fn an_unreadable_previous_removes_the_labels_rather_than_guessing() {
        let restore = restore(&Found {
            previous: Some(r#"{"weebo.io/team":"x"}"#.to_string()),
            ..Found::default()
        })
        .unwrap();
        assert!(restore.set.is_empty());
        assert!(restore.previous_lost);
    }

    #[test]
    fn a_namespace_this_feature_never_wrote_to_is_left_alone() {
        let found = Found {
            labels: [(ENFORCE.to_string(), "restricted".to_string())]
                .into_iter()
                .collect(),
            previous: None,
            owned: false,
            foreign_owned: true,
        };
        assert_eq!(restore(&found), None);
    }
}
