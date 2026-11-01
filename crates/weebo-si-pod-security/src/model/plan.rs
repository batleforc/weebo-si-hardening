//! What to do with one namespace, given its resolution and what it carries now — RFC 0013's
//! *What is written*.

use weebo_si_crd::{PodSecurityLevel, PodSecurityVersion};

use crate::model::backend::EffectiveBackend;
use crate::model::labels::PodSecurityLabels;
use crate::resolve::Resolution;

/// The decision for one namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Server-side apply the six labels and the `-previous` annotation.
    Apply {
        /// The six labels, as resolved.
        labels: PodSecurityLabels,
        /// The `-previous` annotation's value. Sent on every apply, not only the first: under
        /// server-side apply, an apply that omits a field this manager owns removes it.
        previous: String,
        /// What the namespace carries now — for the `diff=` of a `DryRun` log line.
        current: PodSecurityLabels,
    },
    /// The namespace already carries exactly what this feature would write.
    Unchanged,
    /// Somebody else enforces a stricter level than the resolved one. Nothing is written: this
    /// feature raises a floor, and lowering one somebody else set would be a hardening component
    /// weakening a namespace.
    StricterExisting {
        /// The level found.
        existing: PodSecurityLevel,
    },
    /// `ObserveSynced`: nothing is written, the synced level is compared with the resolved one.
    Observed {
        /// The level OpenShift's label syncer set, if any.
        synced: Option<PodSecurityLevel>,
        /// Whether it is looser than the resolved level — `looser_synced`, and the SCC grant is the
        /// lever, not a label.
        looser: bool,
    },
}

/// Everything `desired()` decides for one namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredState {
    /// The resolved levels, with the team and the notes.
    pub resolution: Resolution,
    /// What to do.
    pub plan: Plan,
    /// The `-previous` annotation was gone (or unreadable) on a namespace this feature already
    /// wrote, so the current labels are taken as its own and `{}` is recorded —
    /// `result=previous_lost`. `mode: Off` will then remove the labels instead of restoring.
    pub previous_lost: bool,
    /// A label this feature owns was changed by someone else, and is being put back.
    pub drift: bool,
}

/// What the namespace carries that this decision needs, read by an adapter from the namespace
/// object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// The six keys, as they are.
    pub labels: PodSecurityLabels,
    /// The raw `-previous` annotation, if present.
    pub previous: Option<String>,
    /// Whether this feature's field manager owns at least one of the six keys.
    pub owned: bool,
    /// Whether at least one of the six keys present is owned by another field manager.
    pub foreign_owned: bool,
}

/// Decide what to write. The rules, in order:
///
/// * `ObserveSynced` writes nothing, and only compares.
/// * A namespace this feature has not written to — no `-previous` annotation, no key owned — whose
///   `enforce` level is **stricter** than the resolved one is left alone.
/// * A namespace already carrying exactly the resolved labels and its annotation is unchanged.
/// * Otherwise the labels are applied. The `-previous` annotation keeps its value once it exists;
///   before the first write it records the six keys as found, or `{}` when this feature already
///   owned them and the annotation was lost.
pub fn plan(
    resolution: Resolution,
    version: &PodSecurityVersion,
    backend: EffectiveBackend,
    found: &Found,
) -> DesiredState {
    let current = found.labels.clone();

    if backend == EffectiveBackend::ObserveSynced {
        let synced = current.enforce();
        let looser = synced.is_none_or(|synced| synced < resolution.level);
        return DesiredState {
            resolution,
            plan: Plan::Observed { synced, looser },
            previous_lost: false,
            drift: false,
        };
    }

    let desired = PodSecurityLabels::desired(resolution.level, resolution.warn_level, version);
    let readable_previous = found
        .previous
        .as_deref()
        .filter(|raw| PodSecurityLabels::from_previous(raw).is_ok());
    let ours = found.previous.is_some() || found.owned;

    if !ours
        && let Some(existing) = current.enforce()
        && existing > resolution.level
    {
        return DesiredState {
            resolution,
            plan: Plan::StricterExisting { existing },
            previous_lost: false,
            drift: false,
        };
    }

    if found.previous.is_some() && current == desired {
        return DesiredState {
            resolution,
            plan: Plan::Unchanged,
            previous_lost: readable_previous.is_none(),
            drift: false,
        };
    }

    let (previous, previous_lost) = match (&found.previous, readable_previous) {
        // Never rewritten once it exists, even unreadable: it is the only record of the
        // namespace before this feature, and a guess would overwrite it for good.
        (Some(raw), Some(_)) => (raw.clone(), false),
        (Some(raw), None) => (raw.clone(), true),
        (None, _) if found.owned => (PodSecurityLabels::default().to_previous(), true),
        (None, _) => (current.to_previous(), false),
    };
    let drift = found.previous.is_some() && found.foreign_owned;

    DesiredState {
        resolution,
        plan: Plan::Apply {
            labels: desired,
            previous,
            current,
        },
        previous_lost,
        drift,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::PodSecurityLevel::{Baseline, Privileged, Restricted};

    use super::*;
    use crate::model::labels::{ENFORCE, WARN};

    fn version() -> PodSecurityVersion {
        PodSecurityVersion::new("v1.34")
    }

    fn resolution(level: PodSecurityLevel) -> Resolution {
        Resolution {
            team: None,
            level,
            warn_level: level,
            notes: Vec::new(),
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> PodSecurityLabels {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    fn found(labels: PodSecurityLabels) -> Found {
        Found {
            labels,
            ..Found::default()
        }
    }

    fn written(level: PodSecurityLevel) -> PodSecurityLabels {
        PodSecurityLabels::desired(level, level, &version())
    }

    #[test]
    fn a_bare_namespace_gets_the_six_labels_and_an_empty_previous() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found::default(),
        );
        assert_eq!(
            desired.plan,
            Plan::Apply {
                labels: written(Restricted),
                previous: "{}".to_string(),
                current: PodSecurityLabels::default(),
            }
        );
        assert!(!desired.previous_lost && !desired.drift);
    }

    #[test]
    fn a_looser_existing_level_is_taken_over_and_remembered() {
        let existing = labels(&[(ENFORCE, "privileged"), (WARN, "baseline")]);
        let desired = plan(
            resolution(Baseline),
            &version(),
            EffectiveBackend::Labels,
            &found(existing.clone()),
        );
        let Plan::Apply { previous, .. } = desired.plan else {
            panic!("expected an apply, got {:?}", desired.plan);
        };
        assert_eq!(
            PodSecurityLabels::from_previous(&previous).unwrap(),
            existing
        );
    }

    #[test]
    fn a_stricter_level_somebody_else_set_is_left_alone() {
        let desired = plan(
            resolution(Baseline),
            &version(),
            EffectiveBackend::Labels,
            &found(labels(&[(ENFORCE, "restricted")])),
        );
        assert_eq!(
            desired.plan,
            Plan::StricterExisting {
                existing: Restricted
            }
        );
    }

    #[test]
    fn an_equal_level_somebody_else_set_is_taken_over() {
        let existing = labels(&[(ENFORCE, "baseline")]);
        let desired = plan(
            resolution(Baseline),
            &version(),
            EffectiveBackend::Labels,
            &found(existing),
        );
        assert!(matches!(desired.plan, Plan::Apply { .. }));
    }

    #[test]
    fn a_stricter_level_this_feature_wrote_is_lowered_when_the_resolution_loosens() {
        let desired = plan(
            resolution(Baseline),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: written(Restricted),
                previous: Some("{}".to_string()),
                owned: true,
                foreign_owned: false,
            },
        );
        let Plan::Apply {
            labels, previous, ..
        } = desired.plan
        else {
            panic!("expected an apply, got {:?}", desired.plan);
        };
        assert_eq!(labels, written(Baseline));
        assert_eq!(previous, "{}", "the first previous is never rewritten");
    }

    #[test]
    fn exactly_what_would_be_written_is_unchanged() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: written(Restricted),
                previous: Some(
                    r#"{"pod-security.kubernetes.io/enforce":"privileged"}"#.to_string(),
                ),
                owned: true,
                foreign_owned: false,
            },
        );
        assert_eq!(desired.plan, Plan::Unchanged);
        assert!(!desired.previous_lost);
    }

    #[test]
    fn the_previous_annotation_keeps_its_first_value_on_every_later_apply() {
        let first = r#"{"pod-security.kubernetes.io/enforce":"privileged"}"#;
        let desired = plan(
            resolution(Restricted),
            &PodSecurityVersion::new("v1.35"),
            EffectiveBackend::Labels,
            &Found {
                labels: written(Restricted),
                previous: Some(first.to_string()),
                owned: true,
                foreign_owned: false,
            },
        );
        let Plan::Apply { previous, .. } = desired.plan else {
            panic!("a version bump is a write, got {:?}", desired.plan);
        };
        assert_eq!(previous, first);
    }

    #[test]
    fn labels_this_feature_owns_without_their_annotation_are_previous_lost() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: written(Baseline),
                previous: None,
                owned: true,
                foreign_owned: false,
            },
        );
        let Plan::Apply { previous, .. } = &desired.plan else {
            panic!("expected an apply, got {:?}", desired.plan);
        };
        assert_eq!(previous, "{}");
        assert!(desired.previous_lost);
    }

    #[test]
    fn an_unreadable_previous_is_kept_as_is_and_reported() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: written(Baseline),
                previous: Some("not json".to_string()),
                owned: true,
                foreign_owned: false,
            },
        );
        let Plan::Apply { previous, .. } = &desired.plan else {
            panic!("expected an apply, got {:?}", desired.plan);
        };
        assert_eq!(previous, "not json");
        assert!(desired.previous_lost);
    }

    #[test]
    fn a_label_changed_by_somebody_else_after_the_first_write_is_drift() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: labels(&[(ENFORCE, "privileged")]),
                previous: Some("{}".to_string()),
                owned: true,
                foreign_owned: true,
            },
        );
        assert!(matches!(desired.plan, Plan::Apply { .. }));
        assert!(desired.drift);
    }

    #[test]
    fn a_foreign_owner_before_the_first_write_is_not_drift() {
        let desired = plan(
            resolution(Restricted),
            &version(),
            EffectiveBackend::Labels,
            &Found {
                labels: labels(&[(ENFORCE, "privileged")]),
                previous: None,
                owned: false,
                foreign_owned: true,
            },
        );
        assert!(!desired.drift);
    }

    #[test]
    fn observe_synced_writes_nothing_and_compares() {
        for (synced, level, looser) in [
            (Some("restricted"), Baseline, false),
            (Some("baseline"), Baseline, false),
            (Some("privileged"), Baseline, true),
            (None, Baseline, true),
            (Some("nonsense"), Privileged, true),
        ] {
            let existing = synced.map_or_else(PodSecurityLabels::default, |value| {
                labels(&[(ENFORCE, value)])
            });
            let desired = plan(
                resolution(level),
                &version(),
                EffectiveBackend::ObserveSynced,
                &found(existing),
            );
            let Plan::Observed {
                looser: observed, ..
            } = desired.plan
            else {
                panic!(
                    "ObserveSynced must never plan a write, got {:?}",
                    desired.plan
                );
            };
            assert_eq!(observed, looser, "{synced:?} against {level}");
        }
    }
}
