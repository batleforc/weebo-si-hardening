//! A feature configuration after RFC 0011's *Resolution* — the explicit type that replaced the
//! transitional `#[serde(skip)] grants` field every feature block used to carry.
//!
//! The wire types (`DwocPinConfig`, `ImagePolicyConfig`, …) describe what an admin wrote into
//! the singleton and nothing more. What a feature evaluates against is different: the cluster
//! catalogue merged with every `WeeboSiTeam`'s, plus the grant each team resolves to. Keeping
//! both in one struct, half of it invisible to serde, meant a configuration nobody resolved was
//! indistinguishable from one resolved against zero teams. As a separate type, "forgot to
//! resolve" is a compile error rather than every namespace silently falling to the cluster
//! default.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

/// One feature's configuration, resolved against the `WeeboSiTeam` objects.
///
/// Built by each feature's `resolve`, or by [`Resolved::without_teams`] where no team can
/// apply. Dereferences to the wire configuration so every read that does not concern teams —
/// `mode`, `catalog`, `default` — is spelled exactly as it was.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<C, G, K = String> {
    /// The wire configuration, its catalogue already merged with every team's.
    pub config: C,
    /// What each team may reach, keyed by team name. A team with no block for this feature has
    /// no entry, and resolves to the cluster default.
    pub grants: BTreeMap<K, G>,
}

impl<C, G, K: Ord> Resolved<C, G, K> {
    /// A configuration no team contributes to: the cluster catalogue alone, no grants — what
    /// `resolve` returns for an empty team list.
    pub fn without_teams(config: C) -> Self {
        Self {
            config,
            grants: BTreeMap::new(),
        }
    }

    /// Replace the grants — for callers that build a resolved configuration by hand, which in
    /// practice means tests.
    #[must_use]
    pub fn with_grants(mut self, grants: BTreeMap<K, G>) -> Self {
        self.grants = grants;
        self
    }
}

impl<C, G, K> Deref for Resolved<C, G, K> {
    type Target = C;

    fn deref(&self) -> &C {
        &self.config
    }
}

impl<C, G, K> DerefMut for Resolved<C, G, K> {
    fn deref_mut(&mut self) -> &mut C {
        &mut self.config
    }
}
