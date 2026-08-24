use weebo_si_crd::{NamespaceName, Team};

use super::value::Decision;
use crate::error::DomainError;
use crate::namespace_facts::NamespaceFacts;
use crate::port::dwoc_catalog::DwocCatalog;

/// Anything a `Feature<S>` can be evaluated for. Minimal on purpose: only what the chassis
/// needs to look up a mode and a namespace's facts.
pub trait Subject {
    /// The namespace the mode and the team routing are looked up for.
    fn namespace(&self) -> &NamespaceName;
}

/// Everything one `evaluate()` call is allowed to see.
///
/// **Deliberately does not hold a `&dyn FeatureGate`, or a `FeatureMode` anywhere.**
/// `FeatureGate::mode()` is the one method that answers "what mode am I running in" — if
/// `Context` exposed the port itself, a feature could call
/// `gate.mode(self.id(), subject.namespace())` and learn its own mode even though `evaluate`'s
/// signature carries no mode parameter. Excluding the *port*, not just the *value*, is what
/// makes RFC 0002's "a feature never learns its own mode" true by construction rather than by
/// convention: there is no path from inside `evaluate()` to the answer, not merely no obvious
/// one. `Context` instead holds the three things a feature is entitled to: the teams (already
/// resolved via `FeatureGate::teams()`), the subject's namespace facts (already resolved via
/// `NamespaceView::facts()`), and the catalog port for the existence check the resolution chain
/// itself needs to make (`onMissingTarget`).
///
/// The executable proof that this holds end-to-end — not just "the type has no field for it" —
/// is [`crate::admit`]'s test running the identical scenario under `DryRun` and `Enforce` and
/// asserting `evaluate()` produced the same [`Decision`] both times.
pub struct Context<'a> {
    teams: &'a [Team],
    namespace: &'a NamespaceFacts,
    dwoc_catalog: &'a dyn DwocCatalog,
}

impl<'a> Context<'a> {
    /// Build a context from the three things a feature is entitled to.
    pub fn new(
        teams: &'a [Team],
        namespace: &'a NamespaceFacts,
        dwoc_catalog: &'a dyn DwocCatalog,
    ) -> Self {
        Self {
            teams,
            namespace,
            dwoc_catalog,
        }
    }

    /// The chassis-level teams, ordered, first match wins.
    pub fn teams(&self) -> &'a [Team] {
        self.teams
    }

    /// The subject's namespace's labels and selection annotation.
    pub fn namespace(&self) -> &'a NamespaceFacts {
        self.namespace
    }

    /// Whether a resolved DWOC reference exists.
    pub fn dwoc_catalog(&self) -> &'a dyn DwocCatalog {
        self.dwoc_catalog
    }
}

/// One named hardening behaviour with its own flag, evaluated over one `Subject`.
pub trait Feature<S: Subject> {
    /// This feature's identifier.
    fn id(&self) -> super::value::FeatureId;
    /// Decide what to do with `subject`. Never told which mode is in effect.
    fn evaluate(&self, subject: &S, ctx: &Context<'_>) -> Result<Decision<S>, DomainError>;
}

/// Features registered for the same subject, in declaration order. The order is stable and
/// part of the contract: each feature sees the object as the previous one left it (RFC 0002's
/// *Ordering*). With one feature this is trivially satisfied — see [`crate::admit`] for the
/// note on what a second feature will need.
pub struct Registry<S: Subject> {
    // `Send + Sync` on the trait object, not just the `Vec`: a `Registry` is built once at boot
    // and served from an axum handler across many concurrent requests, so every registered
    // feature must be safe to share across threads.
    features: Vec<Box<dyn Feature<S> + Send + Sync>>,
}

impl<S: Subject> Registry<S> {
    /// An empty registry.
    pub fn new() -> Self {
        Self {
            features: Vec::new(),
        }
    }

    /// Register a feature, appending it after every feature already registered.
    pub fn register<F: Feature<S> + Send + Sync + 'static>(&mut self, feature: F) -> &mut Self {
        self.features.push(Box::new(feature));
        self
    }

    /// Every registered feature, in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Feature<S>> {
        self.features.iter().map(|f| f.as_ref() as &dyn Feature<S>)
    }
}

impl<S: Subject> Default for Registry<S> {
    fn default() -> Self {
        Self::new()
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

    use super::super::value::FeatureId;
    use super::*;
    use crate::port::dwoc_catalog::testing::FakeDwocCatalog;

    struct Workspace(NamespaceName);
    impl Subject for Workspace {
        fn namespace(&self) -> &NamespaceName {
            &self.0
        }
    }

    struct Stub(&'static str);

    impl Feature<Workspace> for Stub {
        fn id(&self) -> FeatureId {
            FeatureId::new(self.0)
        }

        fn evaluate(
            &self,
            _subject: &Workspace,
            _ctx: &Context<'_>,
        ) -> Result<Decision<Workspace>, DomainError> {
            Ok(Decision::new(Vec::new(), None, None, "stub"))
        }
    }

    #[test]
    fn registry_preserves_declaration_order() {
        let mut registry: Registry<Workspace> = Registry::new();
        registry.register(Stub("first")).register(Stub("second"));
        let ids: Vec<&str> = registry.iter().map(|f| f.id().kebab()).collect();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[test]
    fn context_exposes_teams_namespace_and_catalog_and_nothing_else() {
        let teams: Vec<Team> = Vec::new();
        let namespace = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &namespace, &catalog);
        assert!(ctx.teams().is_empty());
        assert_eq!(ctx.namespace(), &namespace);
    }
}
