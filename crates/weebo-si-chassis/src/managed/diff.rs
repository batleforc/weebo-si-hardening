//! The diff between what a reconcile feature says should exist and what a store reports does.
//! Pure — no I/O, no `kube` — so it is exhaustively tested without a cluster.

use super::object::ObjectKey;

/// One feature's managed object, seen through the three questions the diff needs to ask it.
///
/// The trait exists so the algorithm below can be written once over `network-profiles`'
/// `ManagedObject` and `kubearmor-policy`'s, which agree on identity and disagree on payload.
/// It asks for exactly what a diff needs and nothing more — deliberately not a
/// "here is my whole object" accessor, which would let a future implementor route a decision
/// through the chassis that belongs in its own feature.
pub trait Managed: Clone {
    /// The policy dialect this feature writes. `network-profiles` has two members here,
    /// `kubearmor-policy` one; the chassis only ever carries the value through a
    /// [`Diff::Delete`] so an adapter knows which API to issue the delete against.
    type Backend: Copy + PartialEq + core::fmt::Debug;

    /// This object's identity — the key both sides of the diff are matched on.
    fn key(&self) -> &ObjectKey;

    /// Which dialect this object is written in.
    fn backend(&self) -> Self::Backend;

    /// Whether `other` is the same object *content*: same dialect, same selector, same body.
    ///
    /// A method rather than a `PartialEq` bound because the two are genuinely different
    /// questions. A feature may legitimately carry a field that must not force an update when
    /// it differs (a provenance label, a resolved-at timestamp), and `PartialEq` would make
    /// every such field a write to the apiserver on every pass.
    fn content_eq(&self, other: &Self) -> bool;
}

/// One line of the diff between the desired objects and what a store reports exists now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Diff<M: Managed> {
    /// Present in `desired`, absent from `existing`.
    Create(M),
    /// Present in both, but their content differs per [`Managed::content_eq`].
    Update(M),
    /// Present in `existing`, absent from `desired`. Carries `backend` — unlike
    /// `Create`/`Update` there is no object to read it from, and a store adapter needs it to
    /// know which API to issue the delete against.
    Delete {
        /// The object's identity.
        key: ObjectKey,
        /// Which dialect it was written in.
        backend: M::Backend,
    },
    /// Present in both, identical.
    Unchanged(ObjectKey),
}

/// Compute the diff between what should exist (`desired`) and what a store reports exists now
/// (`existing`).
///
/// `existing` is trusted to already be filtered to the calling feature's own managed objects —
/// the `hardening.weebo.io/managed-by` label check is a store *port* responsibility, not this
/// function's, per RFC 0004's *Security considerations*: "the operator reads, updates and
/// deletes only objects carrying the label." A caller that never puts an unmanaged object into
/// `existing` gets that invariant for free — this function cannot produce a `Delete` for an
/// object it was never told about.
pub fn compute_diff<M: Managed>(desired: &[M], existing: &[M]) -> Vec<Diff<M>> {
    let mut diffs = Vec::new();

    for wanted in desired {
        match existing.iter().find(|obj| obj.key() == wanted.key()) {
            None => diffs.push(Diff::Create(wanted.clone())),
            Some(current) => {
                if current.content_eq(wanted) {
                    diffs.push(Diff::Unchanged(wanted.key().clone()));
                } else {
                    diffs.push(Diff::Update(wanted.clone()));
                }
            }
        }
    }

    for present in existing {
        if !desired.iter().any(|obj| obj.key() == present.key()) {
            diffs.push(Diff::Delete {
                key: present.key().clone(),
                backend: present.backend(),
            });
        }
    }

    diffs
}

/// Counts of what a store's `apply` call did, one per [`Diff`] variant — never the objects
/// themselves, since a caller already has those in the `Diff`s it passed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// How many `Diff::Create` lines were applied.
    pub created: u32,
    /// How many `Diff::Update` lines were applied.
    pub updated: u32,
    /// How many `Diff::Delete` lines were applied.
    pub deleted: u32,
    /// How many `Diff::Unchanged` lines needed no write.
    pub unchanged: u32,
}

/// Tally `diffs` by variant. Pure — a store adapter calls this over whatever it actually wrote,
/// but the counting itself needs no I/O to test.
pub fn tally<M: Managed>(diffs: &[Diff<M>]) -> Applied {
    let mut applied = Applied::default();
    for diff in diffs {
        match diff {
            Diff::Create(_) => applied.created += 1,
            Diff::Update(_) => applied.updated += 1,
            Diff::Delete { .. } => applied.deleted += 1,
            Diff::Unchanged(_) => applied.unchanged += 1,
        }
    }
    applied
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_crd::NamespaceName;

    use super::*;

    /// A minimal `Managed` standing in for a feature's own object: two dialects, a body, and a
    /// deliberately diff-invisible field (`note`) proving `content_eq` is what decides, not
    /// structural equality.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Fake {
        key: ObjectKey,
        backend: FakeBackend,
        body: Vec<u8>,
        note: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeBackend {
        One,
        Two,
    }

    impl Managed for Fake {
        type Backend = FakeBackend;

        fn key(&self) -> &ObjectKey {
            &self.key
        }

        fn backend(&self) -> Self::Backend {
            self.backend
        }

        fn content_eq(&self, other: &Self) -> bool {
            self.backend == other.backend && self.body == other.body
        }
    }

    fn object(name: &str, body: &[u8]) -> Fake {
        Fake {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: name.to_string(),
            },
            backend: FakeBackend::One,
            body: body.to_vec(),
            note: String::new(),
        }
    }

    #[test]
    fn present_only_in_desired_is_a_create() {
        let desired = [object("weebo-base", b"a")];
        assert_eq!(
            compute_diff(&desired, &[]),
            vec![Diff::Create(desired[0].clone())]
        );
    }

    #[test]
    fn present_only_in_existing_is_a_delete_carrying_its_backend() {
        let existing = [object("weebo-base", b"a")];
        assert_eq!(
            compute_diff(&[], &existing),
            vec![Diff::Delete {
                key: existing[0].key.clone(),
                backend: FakeBackend::One,
            }]
        );
    }

    #[test]
    fn identical_in_both_is_unchanged() {
        let desired = [object("weebo-base", b"a")];
        let existing = [object("weebo-base", b"a")];
        assert_eq!(
            compute_diff(&desired, &existing),
            vec![Diff::Unchanged(desired[0].key.clone())]
        );
    }

    #[test]
    fn same_key_different_body_is_an_update() {
        let desired = [object("weebo-base", b"new")];
        let existing = [object("weebo-base", b"old")];
        assert_eq!(
            compute_diff(&desired, &existing),
            vec![Diff::Update(desired[0].clone())]
        );
    }

    #[test]
    fn same_key_different_backend_is_an_update() {
        let mut desired = object("weebo-base", b"a");
        desired.backend = FakeBackend::Two;
        let existing = object("weebo-base", b"a");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Update(desired)]
        );
    }

    #[test]
    fn a_field_content_eq_ignores_does_not_force_an_update() {
        // The reason `Managed::content_eq` exists rather than a `PartialEq` bound: a field the
        // feature does not consider part of the object's content must not become an apiserver
        // write on every reconcile pass.
        let mut desired = object("weebo-base", b"a");
        desired.note = "reconciled just now".to_string();
        let existing = object("weebo-base", b"a");
        assert_ne!(desired, existing, "the two are structurally different");
        assert_eq!(
            compute_diff(&[desired.clone()], &[existing]),
            vec![Diff::Unchanged(desired.key.clone())],
            "but content_eq is what the diff asks"
        );
    }

    #[test]
    fn an_empty_desired_and_an_empty_existing_produce_no_diff() {
        assert!(compute_diff::<Fake>(&[], &[]).is_empty());
    }

    #[test]
    fn with_an_empty_existing_the_only_diffs_possible_are_creates() {
        // The scope check happens before this function is ever called: a namespace outside
        // `namespaceSelector` produces an empty `existing` slice at the call site. This test
        // documents that this function has no way to reintroduce a delete for it.
        let desired = [object("weebo-base", b"a")];
        assert!(
            compute_diff(&desired, &[])
                .iter()
                .all(|d| matches!(d, Diff::Create(_)))
        );
    }

    #[test]
    fn tally_of_no_diffs_is_all_zero() {
        assert_eq!(tally::<Fake>(&[]), Applied::default());
    }

    #[test]
    fn tally_counts_one_of_each_kind() {
        let obj = object("weebo-base", b"a");
        let diffs = vec![
            Diff::Create(obj.clone()),
            Diff::Update(obj.clone()),
            Diff::Delete {
                key: obj.key.clone(),
                backend: obj.backend,
            },
            Diff::Unchanged(obj.key.clone()),
        ];
        assert_eq!(
            tally(&diffs),
            Applied {
                created: 1,
                updated: 1,
                deleted: 1,
                unchanged: 1,
            }
        );
    }

    #[test]
    fn tally_counts_multiple_of_the_same_kind() {
        let diffs = vec![
            Diff::Create(object("weebo-base", b"a")),
            Diff::Create(object("weebo-git", b"b")),
        ];
        assert_eq!(
            tally(&diffs),
            Applied {
                created: 2,
                ..Applied::default()
            }
        );
    }
}
