//! The `network-profiles` feature — see RFC 0004's *Design → Architecture*.
//!
//! Two `Subject`s, not one, splitting the baseline (namespace-scoped) from profile objects
//! (workspace-scoped) — an ambiguity the RFC's own Rust sketch left implicit. This avoids
//! recomputing the baseline on every workspace event and matches the *Architecture* section's
//! "the DevWorkspace and Namespace reconcile loops" (plural, separate).
//!
//! **`Auto`-backend resolution is out of scope here.** The RFC's own *Implementation plan*
//! groups it with `kube_capabilities.rs`, not with the domain feature — this crate operates
//! against an already-resolved, concrete [`Backend`], hot-reloadable the same way `config` is.
//! Which backend is currently resolved, and reporting `Degraded` when neither the baseline nor a
//! profile has a usable variant, is a Phase 2 (controller-adapter) concern; this feature simply
//! writes nothing for an object it cannot build, per the RFC's "not applied... not approximated."

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, DomainError, FeatureId, ReconcileFeature, Subject};
use weebo_si_crd::{Backend, NamespaceName, NetworkProfilesConfig};

use crate::model::diff::DesiredState;
use crate::model::policy::{ManagedObject, ObjectKey, PodSelector};
use crate::port::TemplateStore;
use crate::resolve::{self};

/// The name every baseline object is written under, per RFC 0004's *Design*: "one per namespace
/// in scope, `weebo-base`."
const BASELINE_NAME: &str = "weebo-base";

/// The namespace-scoped half of `network-profiles`: produces the baseline object, or nothing if
/// the resolved backend cannot express it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceSubject {
    /// The namespace to compute the baseline for.
    pub namespace: NamespaceName,
}

impl Subject for NamespaceSubject {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    /// A reconcile subject, not an admission one: nothing reaches `weebo_si_chassis::admit`
    /// through it, so this is the kind it reconciles *over* rather than a label any admission
    /// metric will carry.
    fn resource(&self) -> &'static str {
        "Namespace"
    }
}

/// The DevWorkspace under reconciliation, in domain vocabulary.
///
/// Carries `namespace_annotation` alongside the workspace's own `attribute`, rather than relying
/// on `Context::namespace()` for it — see `crate::resolve`'s module doc for why
/// `weebo_si_chassis::NamespaceFacts` cannot carry a second feature's annotation value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    /// The workspace's name.
    pub name: String,
    /// The namespace it was created in.
    pub namespace: NamespaceName,
    /// `controller.devfile.io/devworkspace_id` — the label every profile object selects on.
    pub workspace_id: String,
    /// The raw value of `workspaceSelection.attribute`, if the DevWorkspace carries it.
    pub attribute: Option<String>,
    /// The raw value of `namespaceSelection.annotation`, if the namespace carries it.
    pub namespace_annotation: Option<String>,
}

impl Subject for Workspace {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    /// A reconcile subject — see [`NamespaceSubject::resource`].
    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}

/// The `network-profiles` feature. Holds its configuration and resolved backend behind a lock,
/// same live-reload shape as `weebo-si-dwoc-pin::DwocPin`.
pub struct NetworkProfiles {
    config: Arc<RwLock<Option<NetworkProfilesConfig>>>,
    backend: Arc<RwLock<Backend>>,
    templates: Arc<dyn TemplateStore + Send + Sync>,
}

impl NetworkProfiles {
    /// Build a feature reading `config` and `backend`, fetching template bodies from
    /// `templates`. The caller keeps the other half of `config`'s and `backend`'s `Arc`s and
    /// hands them to whatever keeps them current.
    pub fn new(
        config: Arc<RwLock<Option<NetworkProfilesConfig>>>,
        backend: Arc<RwLock<Backend>>,
        templates: Arc<dyn TemplateStore + Send + Sync>,
    ) -> Self {
        Self {
            config,
            backend,
            templates,
        }
    }

    fn current_config(&self) -> Result<NetworkProfilesConfig, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone().ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "network-profiles evaluated with no spec.features.networkProfiles configured"
                    .to_string(),
            )
        })
    }

    fn current_backend(&self) -> Backend {
        *self
            .backend
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The backend currently resolved, for a caller that needs to *report* it — a log line naming
    /// which dialect a profile has no variant for, or the `backend` label on a metric. Never used
    /// to make a decision outside this type; `desired()` reads the same value through
    /// [`Self::current_backend`].
    pub fn backend(&self) -> Backend {
        self.current_backend()
    }
}

impl ReconcileFeature<NamespaceSubject> for NetworkProfiles {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("network-profiles")
    }

    fn desired(
        &self,
        subject: &NamespaceSubject,
        _ctx: &Context<'_>,
    ) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let backend = self.current_backend();

        let profile = config.catalog.profile(&config.baseline).ok_or_else(|| {
            DomainError::InvalidConfiguration(format!(
                "baseline profile key {} is not present in the catalog",
                config.baseline
            ))
        })?;

        let Some(variant) = profile.variant(backend) else {
            // Per the RFC's "the baseline is different: no usable variant means the feature
            // refuses to enforce at all" — writes nothing rather than approximating, and says
            // so through `unsupported` so `weebo_si_network_profile_unsupported` can report it.
            return Ok(DesiredState {
                unsupported: vec![config.baseline.clone()],
                ..DesiredState::default()
            });
        };

        let Some(body) = self.templates.body(backend, &variant.template_ref) else {
            return Ok(DesiredState::default());
        };

        Ok(DesiredState::objects(vec![ManagedObject {
            key: ObjectKey {
                namespace: subject.namespace.clone(),
                name: BASELINE_NAME.to_string(),
            },
            backend,
            profile: config.baseline.clone(),
            pod_selector: PodSelector::Empty,
            body,
        }]))
    }
}

impl ReconcileFeature<Workspace> for NetworkProfiles {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("network-profiles")
    }

    fn desired(&self, subject: &Workspace, ctx: &Context<'_>) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let backend = self.current_backend();

        // `OnNotGranted::Deny` refuses the *DevWorkspace*, at admission — see
        // `crate::feature::workspace_gate`, which is the admission-side half of this feature and
        // reaches the same `resolve()` verdict from the webhook role. Reconcile-side, the
        // fail-safe reading of a `Deny` is unchanged: write nothing beyond the baseline for a
        // workspace whose request could not be resolved, rather than guess. The refused keys
        // still travel out through `not_granted` so the counter and the log line name them.
        let resolved = resolve::resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.namespace_annotation.as_deref(),
            subject.attribute.as_deref(),
        );
        let provenance = match resolved {
            Ok(provenance) => provenance,
            Err(not_granted) => {
                return Ok(DesiredState {
                    team: not_granted.team,
                    not_granted: not_granted.requested,
                    ..DesiredState::default()
                });
            }
        };

        let mut unsupported = Vec::new();
        let mut objects = Vec::with_capacity(provenance.resolved.len());
        for key in &provenance.resolved {
            let Some(profile) = config.catalog.profile(key) else {
                continue;
            };
            let Some(variant) = profile.variant(backend) else {
                // Not applied, and never approximated with another backend's variant — the RFC's
                // "an admin who wants a coarser fallback writes it as the NetworkPolicy variant,
                // deliberately."
                unsupported.push(key.clone());
                continue;
            };
            let Some(body) = self.templates.body(backend, &variant.template_ref) else {
                continue;
            };
            objects.push(ManagedObject {
                key: ObjectKey {
                    namespace: subject.namespace.clone(),
                    name: format!("weebo-{key}-{}", subject.workspace_id),
                },
                backend,
                profile: key.clone(),
                pod_selector: PodSelector::DevWorkspaceId(subject.workspace_id.clone()),
                body,
            });
        }

        Ok(DesiredState {
            objects,
            team: provenance.team,
            not_granted: provenance.dropped_not_granted,
            unsupported,
        })
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
        Enforcement, FeatureMode, OnNotGranted, Profile, ProfileCatalog, ProfileGrant, ProfileKey,
        ProfileNamespaceSelection, Selector, Team, TeamName, TemplateRef, Variant,
        WorkspaceSelection,
    };

    use super::*;
    use crate::port::testing::FakeTemplateStore;

    fn template_ref(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn profile(key: &str) -> Profile {
        Profile {
            key: ProfileKey::new(key),
            variants: vec![Variant {
                backend: Backend::NetworkPolicy,
                template_ref: template_ref(&format!("weebo-{key}")),
            }],
        }
    }

    fn config(grants: BTreeMap<String, ProfileGrant>) -> NetworkProfilesConfig {
        NetworkProfilesConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: ProfileCatalog::new(vec![profile("base"), profile("git"), profile("vault")]),
            baseline: ProfileKey::new("base"),
            grants,
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: Enforcement::default(),
        }
    }

    fn templates() -> FakeTemplateStore {
        FakeTemplateStore::new([
            (template_ref("weebo-base"), b"base-rules".to_vec()),
            (template_ref("weebo-git"), b"git-rules".to_vec()),
            (template_ref("weebo-vault"), b"vault-rules".to_vec()),
        ])
    }

    fn feature(config: NetworkProfilesConfig) -> NetworkProfiles {
        NetworkProfiles::new(
            Arc::new(RwLock::new(Some(config))),
            Arc::new(RwLock::new(Backend::NetworkPolicy)),
            Arc::new(templates()),
        )
    }

    fn namespace_facts() -> NamespaceFacts {
        NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        }
    }

    fn ctx<'a>(
        teams: &'a [Team],
        namespace: &'a NamespaceFacts,
        catalog: &'a FakeDwocCatalog,
    ) -> Context<'a> {
        Context::new(teams, namespace, catalog)
    }

    #[test]
    fn the_baseline_object_carries_the_empty_selector_and_the_baseline_key() {
        let feature = feature(config(BTreeMap::new()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let subject = NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        };
        let desired = feature.desired(&subject, &context).unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(desired.objects[0].key.name, BASELINE_NAME);
        assert_eq!(desired.objects[0].pod_selector, PodSelector::Empty);
        assert_eq!(desired.objects[0].profile, ProfileKey::new("base"));
    }

    #[test]
    fn the_baseline_writes_nothing_when_the_resolved_backend_has_no_variant() {
        let mut cfg = config(BTreeMap::new());
        cfg.catalog = ProfileCatalog::new(vec![Profile {
            key: ProfileKey::new("base"),
            variants: vec![Variant {
                backend: Backend::Cilium,
                template_ref: template_ref("weebo-base-cilium"),
            }],
        }]);
        let feature = feature(cfg);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let subject = NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        };
        let desired = feature.desired(&subject, &context).unwrap();
        assert!(desired.objects.is_empty());
    }

    fn team1() -> Team {
        Team {
            name: TeamName::new("team-1"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }
    }

    fn team1_grant() -> ProfileGrant {
        ProfileGrant {
            allowed: vec![ProfileKey::new("git"), ProfileKey::new("vault")],
            default: vec![ProfileKey::new("git")],
        }
    }

    fn workspace(attribute: Option<&str>) -> Workspace {
        Workspace {
            name: "data-pipeline".to_string(),
            namespace: NamespaceName::new("user-alice"),
            workspace_id: "workspacede4f56".to_string(),
            attribute: attribute.map(str::to_string),
            namespace_annotation: None,
        }
    }

    #[test]
    fn a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id() {
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let feature = feature(config(grants));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let mut namespace = namespace_facts();
        namespace
            .labels
            .insert("weebo.io/team".to_string(), "team-1".to_string());
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let subject = workspace(Some("git,vault"));

        let desired = feature.desired(&subject, &context).unwrap();
        let mut names: Vec<&str> = desired
            .objects
            .iter()
            .map(|o| o.key.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["weebo-git-workspacede4f56", "weebo-vault-workspacede4f56"]
        );
        assert!(
            desired.objects.iter().all(
                |o| o.pod_selector == PodSelector::DevWorkspaceId(subject.workspace_id.clone())
            )
        );
    }

    #[test]
    fn a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default() {
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let feature = feature(config(grants));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let mut namespace = namespace_facts();
        namespace
            .labels
            .insert("weebo.io/team".to_string(), "team-1".to_string());
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let subject = workspace(None);

        let desired = feature.desired(&subject, &context).unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(desired.objects[0].profile, ProfileKey::new("git"));
    }

    #[test]
    fn an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline() {
        let mut grants = BTreeMap::new();
        grants.insert("team-1".to_string(), team1_grant());
        let mut cfg = config(grants);
        cfg.on_not_granted = OnNotGranted::Deny;
        let feature = feature(cfg);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let mut namespace = namespace_facts();
        namespace
            .labels
            .insert("weebo.io/team".to_string(), "team-1".to_string());
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let subject = workspace(Some("nope"));

        let desired = feature.desired(&subject, &context).unwrap();
        assert!(desired.objects.is_empty());
    }

    #[test]
    fn evaluate_with_no_config_at_all_is_a_domain_error() {
        let feature = NetworkProfiles::new(
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(Backend::NetworkPolicy)),
            Arc::new(templates()),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let subject = NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        };
        assert!(feature.desired(&subject, &context).is_err());
    }

    #[test]
    fn the_live_config_can_be_swapped_without_reconstructing_network_profiles() {
        let config_handle = Arc::new(RwLock::new(Some(config(BTreeMap::new()))));
        let feature = NetworkProfiles::new(
            Arc::clone(&config_handle),
            Arc::new(RwLock::new(Backend::NetworkPolicy)),
            Arc::new(templates()),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let subject = NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        };

        let desired = feature.desired(&subject, &context).unwrap();
        assert_eq!(desired.objects[0].profile, ProfileKey::new("base"));

        {
            let mut guard = config_handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cfg) = guard.as_mut() {
                cfg.baseline = ProfileKey::new("git");
            }
        }

        let desired = feature.desired(&subject, &context).unwrap();
        assert_eq!(
            desired.objects[0].profile,
            ProfileKey::new("git"),
            "the second desired() must see the swapped config"
        );
    }
}
