//! The `pod-security` feature — see RFC 0013's *Design → Architecture*.
//!
//! **One subject, the namespace.** A Pod Security level is a property of the namespace: the
//! apiserver reads it there for every pod, however the pod was created.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, DomainError, FeatureId, ReconcileFeature, Subject};
use weebo_si_crd::{NamespaceName, ResolvedPodSecurityConfig};

use crate::model::backend::effective_backend;
use crate::model::plan::{DesiredState, Found, plan};
use crate::resolve;

/// The namespace under reconciliation, with what it carries that this feature reads.
///
/// Carries the selection annotation and [`Found`] itself rather than reading them off
/// `Context::namespace()`, for the reason every sibling feature's subject does:
/// `weebo_si_chassis::NamespaceFacts` holds labels and *one* feature's projected annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceSubject {
    /// The namespace.
    pub namespace: NamespaceName,
    /// The raw value of `namespaceSelection.annotation`, if the namespace carries it and the
    /// annotation is not disabled.
    pub annotation: Option<String>,
    /// The six keys, the `-previous` annotation, and who owns the keys.
    pub found: Found,
}

impl Subject for NamespaceSubject {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "Namespace"
    }
}

/// The `pod-security` feature. Holds its configuration behind a lock, the live-reload shape of
/// every sibling feature.
pub struct PodSecurityFeature {
    config: Arc<RwLock<Option<ResolvedPodSecurityConfig>>>,
    serves_scc: bool,
}

impl PodSecurityFeature {
    /// Build a feature reading `config`. `serves_scc` is whether the apiserver serves
    /// `security.openshift.io/v1`, learnt once at startup: it is what `backend: Auto` resolves
    /// against.
    pub fn new(config: Arc<RwLock<Option<ResolvedPodSecurityConfig>>>, serves_scc: bool) -> Self {
        Self { config, serves_scc }
    }

    fn current_config(&self) -> Result<ResolvedPodSecurityConfig, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone().ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "pod-security evaluated with no spec.features.podSecurity configured".to_string(),
            )
        })
    }
}

impl ReconcileFeature<NamespaceSubject> for PodSecurityFeature {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("pod-security")
    }

    fn desired(
        &self,
        subject: &NamespaceSubject,
        ctx: &Context<'_>,
    ) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let resolution = resolve::resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.annotation.as_deref(),
        );
        let backend = effective_backend(config.backend, self.serves_scc);
        Ok(plan(resolution, &config.version, backend, &subject.found))
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

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        FeatureMode, PodSecurityBackend, PodSecurityConfig, PodSecurityLevel,
        PodSecurityNamespaceSelection, PodSecurityVersion, Resolved, Selector, Team, TeamName,
        TeamPodSecurity,
    };

    use super::*;
    use crate::model::labels::{ENFORCE, PodSecurityLabels};
    use crate::model::plan::Plan;

    fn config(backend: PodSecurityBackend) -> ResolvedPodSecurityConfig {
        Resolved::without_teams(PodSecurityConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            default: PodSecurityLevel::Restricted,
            ceiling: PodSecurityLevel::Baseline,
            version: PodSecurityVersion::new("v1.34"),
            backend,
            namespace_selection: PodSecurityNamespaceSelection::default(),
        })
        .with_grants(BTreeMap::from([(
            "team-build".to_string(),
            TeamPodSecurity {
                level: Some(PodSecurityLevel::Baseline),
                warn_level: Some(PodSecurityLevel::Restricted),
            },
        )]))
    }

    fn feature(backend: PodSecurityBackend, serves_scc: bool) -> PodSecurityFeature {
        PodSecurityFeature::new(Arc::new(RwLock::new(Some(config(backend)))), serves_scc)
    }

    fn teams() -> Vec<Team> {
        vec![Team {
            name: TeamName::new("team-build"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-build".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }]
    }

    fn facts() -> NamespaceFacts {
        NamespaceFacts {
            labels: BTreeMap::from([("weebo.io/team".to_string(), "team-build".to_string())]),
            selection_annotation: None,
        }
    }

    fn subject(found: Found) -> NamespaceSubject {
        NamespaceSubject {
            namespace: NamespaceName::new("user-carol"),
            annotation: None,
            found,
        }
    }

    #[test]
    fn a_build_team_gets_baseline_enforced_and_restricted_warned() {
        let teams = teams();
        let facts = facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let desired = feature(PodSecurityBackend::Labels, false)
            .desired(
                &subject(Found::default()),
                &Context::new(&teams, &facts, &catalog),
            )
            .unwrap();
        assert_eq!(desired.resolution.team, Some(TeamName::new("team-build")));
        let Plan::Apply { labels, .. } = desired.plan else {
            panic!("expected an apply, got {:?}", desired.plan);
        };
        assert_eq!(
            labels,
            PodSecurityLabels::desired(
                PodSecurityLevel::Baseline,
                PodSecurityLevel::Restricted,
                &PodSecurityVersion::new("v1.34"),
            )
        );
    }

    #[test]
    fn auto_on_openshift_observes_instead_of_writing() {
        let teams = teams();
        let facts = facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let found = Found {
            labels: [(ENFORCE.to_string(), "restricted".to_string())]
                .into_iter()
                .collect(),
            ..Found::default()
        };
        let desired = feature(PodSecurityBackend::Auto, true)
            .desired(&subject(found), &Context::new(&teams, &facts, &catalog))
            .unwrap();
        assert_eq!(
            desired.plan,
            Plan::Observed {
                synced: Some(PodSecurityLevel::Restricted),
                looser: false,
            }
        );
    }

    #[test]
    fn no_configuration_is_an_error_not_a_guess() {
        let feature = PodSecurityFeature::new(Arc::new(RwLock::new(None)), false);
        let teams = teams();
        let facts = facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        assert!(
            feature
                .desired(
                    &subject(Found::default()),
                    &Context::new(&teams, &facts, &catalog)
                )
                .is_err()
        );
    }
}
