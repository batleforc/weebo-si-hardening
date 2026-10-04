//! `DesiredState` — what a `desired()` call computed for one namespace — over the diff machinery
//! the chassis owns.
//!
//! [`Diff`], `compute_diff`, `Applied` and `tally` are [`weebo_si_chassis::managed`]'s. RFC
//! 0007's *Implementation plan* asked for that promotion; RFC 0006 had already made it, so this
//! crate is the third consumer rather than the third copy. What this module owns is what is
//! genuinely this feature's: [`DesiredState`] and its provenance, and the [`Managed`] impl
//! saying what "same content" means for a copied `ConfigMap`.

use weebo_si_chassis::managed::{Managed, ObjectKey};
use weebo_si_crd::{RegistryKey, SourceKind, TeamName};

use super::mount::TemplateRefusal;
use super::object::ManagedObject;

pub use weebo_si_chassis::managed::{Applied, compute_diff, tally};

/// One line of the diff between `desired` and what a [`crate::port::ObjectStore`] reports exists
/// now — the chassis' generic [`weebo_si_chassis::managed::Diff`] at this feature's object type.
pub type Diff = weebo_si_chassis::managed::Diff<ManagedObject>;

impl Managed for ManagedObject {
    type Backend = SourceKind;

    fn key(&self) -> &ObjectKey {
        &self.key
    }

    fn backend(&self) -> SourceKind {
        self.kind
    }

    /// Kind, labels, annotations and payload — everything that reaches a container.
    ///
    /// **Labels and annotations are compared here, unlike in either sibling feature**, and the
    /// reason is specific to this brick: for a `NetworkPolicy` the metadata is decoration and the
    /// `spec` is the whole meaning, but for an automounted object the annotations *are* the
    /// meaning. A template whose `mount-path` moved from `/home/user` to `/etc` has changed what
    /// it does without changing one byte of `data`, and a diff that ignored that would report
    /// `Unchanged` forever.
    ///
    /// `entry` is deliberately not compared — it is provenance carried into a label, and a
    /// catalogue key renamed over identical content is not a reason to rewrite every copy in the
    /// fleet.
    fn content_eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.labels == other.labels
            && self.annotations == other.annotations
            && self.body == other.body
    }
}

/// A catalogue entry's source that could not be turned into a copy, and why.
///
/// Carried out of `desired()` rather than logged inside it, for the reason every provenance
/// field in this project is: the decision is made in a crate with no logger and no metrics
/// registry, and a caller that recomputed the reason would be a second copy of the rule free to
/// drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedTemplate {
    /// The catalogue key whose source was refused.
    pub entry: RegistryKey,
    /// Which kind of object the source named.
    pub kind: SourceKind,
    /// The template object's name — never its content.
    pub name: String,
    /// Why it was refused. `None` means "the template does not exist, or has not landed in the
    /// watch cache yet" — the `not_found` reason, which is not a [`TemplateRefusal`] because
    /// nothing was inspected.
    pub refusal: Option<TemplateRefusal>,
}

impl RefusedTemplate {
    /// The `reason` label on `weebo_si_registry_template_invalid_total`.
    pub fn reason(&self) -> &'static str {
        match self.refusal {
            Some(refusal) => refusal.label(),
            None => "not_found",
        }
    }
}

/// What a `ReconcileFeature::desired` call computed for one namespace: the objects that should
/// exist there, and the three facts about *how* that answer was reached that RFC 0007's
/// observability needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DesiredState {
    /// The objects that should exist in this namespace.
    pub objects: Vec<ManagedObject>,
    /// The team that matched this namespace, if any — the `team` label on
    /// `weebo_si_registry_reconcile_total` and `weebo_si_registry_not_granted_total`.
    pub team: Option<TeamName>,
    /// Keys the namespace asked for that its team's grant does not allow.
    pub not_granted: Vec<RegistryKey>,
    /// Sources of resolved keys that produced no copy. **This is what makes
    /// `weebo_si_registry_ready` mean something**: a namespace whose every resolved source
    /// became an object is ready, and one with any entry here is not — which is the difference
    /// between "the developer's `npm install` failed because of us" and "it did not".
    pub refused: Vec<RefusedTemplate>,
    /// Objects this namespace should carry but could not build this pass — the template is
    /// missing, not yet in the watch cache, or refused. Their live copy is **held**: never
    /// deleted, never updated, until the template resolves again.
    ///
    /// Dropping them from `objects` alone would turn a cold watch cache after an operator
    /// restart, or an admin's bad edit to a template, into a `Delete` of every namespace's
    /// registry configuration — and a developer whose `.npmrc` copy vanished silently falls back
    /// to the public registry, which is the bypass this feature exists to stop (fail-open).
    pub held: Vec<ObjectKey>,
}

/// [`compute_diff`], except that a `held` object's live copy is left exactly as it is and that an
/// object is identified by its **kind and name**, not its name alone.
///
/// The second half matters because a `ConfigMap` and a `Secret` of one name are two objects: with
/// the chassis' name-only comparison, a catalogue entry with a `ConfigMap` source and a `Secret`
/// source over the same template name would find the other kind's live object, report `Update`
/// on every pass, and never `Delete` the one a removed source left behind.
pub fn compute_held_diff(
    desired: &[ManagedObject],
    held: &[ObjectKey],
    existing: &[ManagedObject],
) -> Vec<Diff> {
    let live: Vec<ManagedObject> = existing
        .iter()
        .filter(|object| !held.contains(&object.key))
        .cloned()
        .collect();

    let mut kinds: Vec<SourceKind> = Vec::new();
    for object in desired.iter().chain(live.iter()) {
        if !kinds.contains(&object.kind) {
            kinds.push(object.kind);
        }
    }

    kinds
        .into_iter()
        .flat_map(|kind| {
            let wanted: Vec<ManagedObject> = desired
                .iter()
                .filter(|object| object.kind == kind)
                .cloned()
                .collect();
            let present: Vec<ManagedObject> = live
                .iter()
                .filter(|object| object.kind == kind)
                .cloned()
                .collect();
            compute_diff(&wanted, &present)
        })
        .collect()
}

impl DesiredState {
    /// Whether every source of every resolved key for this namespace produced a copy.
    ///
    /// The value behind `weebo_si_registry_ready`. Deliberately **not** "objects is non-empty":
    /// a namespace that resolves no key at all is not degraded, it is simply not configured, and
    /// reporting it as a failure would make the one alertable signal in this brick fire for
    /// every namespace nobody granted anything.
    pub fn is_ready(&self) -> bool {
        self.refused.is_empty() && self.not_granted.is_empty()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_crd::NamespaceName;

    use super::super::object::ObjectBody;
    use super::*;

    fn object(name: &str, body: &[u8]) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            kind: SourceKind::ConfigMap,
            entry: RegistryKey::new("internal-npm"),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            body: ObjectBody::opaque(body.to_vec()),
        }
    }

    // The algorithm is tested exhaustively in `weebo_si_chassis::managed::diff`. What is this
    // feature's own — and therefore tested here — is the `Managed` impl above.

    #[test]
    fn same_key_different_body_is_an_update() {
        let desired = [object("weebo-si-internal-npm-weebo-npmrc", b"new")];
        let existing = [object("weebo-si-internal-npm-weebo-npmrc", b"old")];
        assert_eq!(
            compute_diff(&desired, &existing),
            vec![Diff::Update(desired[0].clone())]
        );
    }

    #[test]
    fn a_changed_mount_path_alone_is_an_update() {
        // The reason this feature's `content_eq` compares annotations and its siblings' do not:
        // for an automounted object the annotations *are* the meaning. A template moved from
        // `/home/user` to `/etc` has changed what it does without changing one byte of `data`.
        let mut desired = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        desired.annotations.insert(
            "controller.devfile.io/mount-path".to_string(),
            "/etc".to_string(),
        );
        let mut existing = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        existing.annotations.insert(
            "controller.devfile.io/mount-path".to_string(),
            "/home/user".to_string(),
        );
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_lost_automount_label_is_an_update() {
        // Someone stripping the label from a copy leaves an object that reaches no container.
        // The reconciler has to notice, or "the mirror is configured" is true only in `kubectl`.
        let mut desired = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        desired.labels.insert(
            "controller.devfile.io/mount-to-devworkspace".to_string(),
            "true".to_string(),
        );
        let existing = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_renamed_catalogue_key_alone_does_not_rewrite_the_copy() {
        let mut desired = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        desired.entry = RegistryKey::new("internal-npm-v2");
        let existing = object("weebo-si-internal-npm-weebo-npmrc", b"same");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Unchanged(desired.key.clone())]
        );
    }

    #[test]
    fn the_delete_line_carries_the_kind_an_adapter_needs() {
        // A `ConfigMap` and a `Secret` are deleted against different APIs, and by the time a
        // delete is computed there is no object left to read the kind from.
        let existing = [object("weebo-si-internal-npm-weebo-npmrc", b"a")];
        assert_eq!(
            compute_diff(&[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: SourceKind::ConfigMap,
                uid: None,
            }]
        );
    }

    #[test]
    fn a_held_object_is_neither_deleted_nor_updated() {
        let existing = [object("weebo-si-internal-npm-weebo-npmrc", b"old")];
        let held = [existing[0].key.clone()];
        // Not desired this pass (its template is unreadable): no `Delete`.
        assert!(compute_held_diff(&[], &held, &existing).is_empty());
        // Desired with new content but held: no `Update` either.
        let desired = [object("weebo-si-internal-npm-weebo-npmrc", b"new")];
        assert!(
            compute_held_diff(&desired, &held, &existing)
                .iter()
                .all(|line| !matches!(line, Diff::Update(_) | Diff::Delete { .. }))
        );
        // Without the hold, the same absence is a delete.
        assert_eq!(
            compute_held_diff(&[], &[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: SourceKind::ConfigMap,
                uid: None,
            }]
        );
    }

    #[test]
    fn a_config_map_and_a_secret_of_one_name_are_two_objects() {
        let config_map = object("weebo-si-internal-npm-token", b"same");
        let mut secret = config_map.clone();
        secret.kind = SourceKind::Secret;

        // Both live, both desired and identical: nothing to do, not an `Update` per pass.
        let diffs = compute_held_diff(
            &[config_map.clone(), secret.clone()],
            &[],
            &[config_map.clone(), secret.clone()],
        );
        assert_eq!(diffs.len(), 2);
        assert!(diffs.iter().all(|line| matches!(line, Diff::Unchanged(_))));

        // The `Secret` source removed: its live copy is deleted, as a `Secret`, and the
        // `ConfigMap` of the same name stays.
        let diffs = compute_held_diff(
            std::slice::from_ref(&config_map),
            &[],
            &[config_map.clone(), secret.clone()],
        );
        assert!(diffs.contains(&Diff::Delete {
            key: secret.key.clone(),
            backend: SourceKind::Secret,
            uid: None,
        }));
        assert!(diffs.contains(&Diff::Unchanged(config_map.key.clone())));
    }

    #[test]
    fn a_namespace_that_resolves_nothing_is_ready_not_degraded() {
        // The one alertable signal in this brick must not fire for every namespace nobody
        // granted anything.
        assert!(DesiredState::default().is_ready());
    }

    #[test]
    fn a_refused_template_makes_the_namespace_not_ready() {
        let state = DesiredState {
            refused: vec![RefusedTemplate {
                entry: RegistryKey::new("internal-npm"),
                kind: SourceKind::ConfigMap,
                name: "weebo-npmrc".to_string(),
                refusal: Some(TemplateRefusal::MountShadowsPath),
            }],
            ..DesiredState::default()
        };
        assert!(!state.is_ready());
    }

    #[test]
    fn an_ungranted_request_makes_the_namespace_not_ready_too() {
        // The namespace asked for something and did not get it. Whether the operator considers
        // that an admin error or a user error, the workspace in it is not configured the way its
        // annotation says.
        let state = DesiredState {
            not_granted: vec![RegistryKey::new("internal-pypi")],
            ..DesiredState::default()
        };
        assert!(!state.is_ready());
    }

    #[test]
    fn a_missing_template_reports_not_found_rather_than_a_refusal() {
        let refused = RefusedTemplate {
            entry: RegistryKey::new("internal-npm"),
            kind: SourceKind::ConfigMap,
            name: "weebo-npmrc".to_string(),
            refusal: None,
        };
        assert_eq!(refused.reason(), "not_found");
    }
}
