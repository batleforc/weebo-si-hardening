//! The `resource-quotas` feature — see RFC 0014's *Architecture*. One subject, the namespace:
//! neither a `ResourceQuota` nor a `LimitRange` has a selector, so there is nothing per-workspace.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, DomainError, FeatureId, ReconcileFeature, Subject};
use weebo_si_crd::{NamespaceName, QuotaProfileKey, ResolvedResourceQuotasConfig, TeamName};

use crate::model::object::{ManagedQuotaObject, QuotaKind};
use crate::model::validate::{ProfileViolation, ValidProfile};
use crate::port::QuotaTemplateStore;
use crate::resolve;

/// The namespace under reconciliation, with the raw selection annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceSubject {
    /// The namespace.
    pub namespace: NamespaceName,
    /// The value of `namespaceSelection.annotation`, if present and not disabled.
    pub annotation: Option<String>,
}

impl Subject for NamespaceSubject {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "Namespace"
    }
}

/// What `desired()` decided for one namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct DesiredState {
    /// The team that matched.
    pub team: Option<TeamName>,
    /// The profile resolved, if one was.
    pub profile: Option<QuotaProfileKey>,
    /// The objects that should exist. Meaningless when `hold` is set.
    pub objects: Vec<ManagedQuotaObject>,
    /// **Keep what the namespace has.** Set when the profile is invalid or the request is refused
    /// under `onNotGranted: Deny`: "the new configuration is broken" never means "remove the
    /// existing ceiling", and an empty template cache must never read as "remove every quota".
    pub hold: bool,
    /// A key the annotation named that the team is not granted.
    pub not_granted: Option<QuotaProfileKey>,
    /// Why the profile was not applied.
    pub violations: Vec<ProfileViolation>,
}

/// The `resource-quotas` feature.
pub struct ResourceQuotasFeature {
    config: Arc<RwLock<Option<ResolvedResourceQuotasConfig>>>,
    templates: Arc<dyn QuotaTemplateStore>,
    template_namespace: NamespaceName,
}

impl ResourceQuotasFeature {
    /// Build a feature reading `config`, fetching templates from `templates`, which every profile
    /// must reference in `template_namespace` — a namespace that runs no pods, because a template
    /// is enforced where it lives.
    pub fn new(
        config: Arc<RwLock<Option<ResolvedResourceQuotasConfig>>>,
        templates: Arc<dyn QuotaTemplateStore>,
        template_namespace: NamespaceName,
    ) -> Self {
        Self {
            config,
            templates,
            template_namespace,
        }
    }

    fn current_config(&self) -> Result<ResolvedResourceQuotasConfig, DomainError> {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                DomainError::InvalidConfiguration(
                    "resource-quotas evaluated with no spec.features.resourceQuotas configured"
                        .to_string(),
                )
            })
    }

    /// Validate one profile against the live templates.
    fn check(
        &self,
        config: &ResolvedResourceQuotasConfig,
        key: &QuotaProfileKey,
    ) -> Result<ValidProfile, Vec<ProfileViolation>> {
        let Some(profile) = config.catalog.profile(key) else {
            return Err(Vec::new());
        };
        let quota = profile
            .quota_ref
            .as_ref()
            .and_then(|template| self.templates.quota(template));
        let limits = profile
            .limit_range_ref
            .as_ref()
            .and_then(|template| self.templates.limit_range(template));
        ValidProfile::check(profile, quota, limits, &self.template_namespace)
    }

    /// Every profile of the catalogue with what is wrong with it — the
    /// `weebo_si_resource_quotas_profiles` gauge and the CLI's pre-flight.
    pub fn check_catalog(
        &self,
    ) -> Result<Vec<(QuotaProfileKey, Vec<ProfileViolation>)>, DomainError> {
        let config = self.current_config()?;
        Ok(config
            .catalog
            .entries()
            .iter()
            .map(|profile| {
                let violations = self.check(&config, &profile.key).err().unwrap_or_default();
                (profile.key.clone(), violations)
            })
            .collect())
    }
}

impl ReconcileFeature<NamespaceSubject> for ResourceQuotasFeature {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("resource-quotas")
    }

    fn desired(
        &self,
        subject: &NamespaceSubject,
        ctx: &Context<'_>,
    ) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let provenance = match resolve::resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.annotation.as_deref(),
        ) {
            Ok(provenance) => provenance,
            Err(refused) => {
                return Ok(DesiredState {
                    team: refused.team,
                    profile: None,
                    objects: Vec::new(),
                    hold: true,
                    not_granted: Some(refused.requested),
                    violations: Vec::new(),
                });
            }
        };
        // A resolved key outside the catalogue cannot happen against a configuration that passed
        // `validate()`; refuse to guess rather than write on an inconsistent one.
        if !config.catalog.contains(&provenance.profile) {
            return Err(DomainError::InvalidConfiguration(format!(
                "resolved quota profile {} is not in the catalog",
                provenance.profile
            )));
        }

        match self.check(&config, &provenance.profile) {
            Err(violations) => Ok(DesiredState {
                team: provenance.team,
                profile: Some(provenance.profile),
                objects: Vec::new(),
                hold: true,
                not_granted: provenance.not_granted,
                violations,
            }),
            Ok(valid) => {
                let mut objects = Vec::new();
                if let Some(quota) = valid.quota {
                    objects.push(ManagedQuotaObject::desired(
                        &subject.namespace,
                        QuotaKind::ResourceQuota,
                        &valid.key,
                        quota.spec,
                    ));
                }
                if let Some(limits) = valid.limits {
                    objects.push(ManagedQuotaObject::desired(
                        &subject.namespace,
                        QuotaKind::LimitRange,
                        &valid.key,
                        limits.spec,
                    ));
                }
                Ok(DesiredState {
                    team: provenance.team,
                    profile: Some(provenance.profile),
                    objects,
                    hold: false,
                    not_granted: provenance.not_granted,
                    violations: Vec::new(),
                })
            }
        }
    }
}
