//! The `kubearmor-policy` feature — see RFC 0006's *Design → Architecture*.
//!
//! Two `Subject`s, not one, splitting the baseline (namespace-scoped, and the only pass that
//! carries the default posture) from profile objects (workspace-scoped) — "same split as
//! `network-profiles` and the same reason: the baseline should not be recomputed on every
//! workspace event."
//!
//! **`Auto`-backend resolution is out of scope here**, as it is for `network-profiles`: this
//! crate operates against an already-resolved, concrete [`RuntimeBackend`], hot-reloadable the
//! same way `config` is. [`crate::backend::resolve_backend`] is what the composition root calls
//! to produce it, and a cluster where it resolves to `None` never starts these loops at all.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, DomainError, FeatureId, ReconcileFeature, Subject};
use weebo_si_crd::{KubeArmorPolicyConfig, NamespaceName, RuntimeBackend};

use crate::model::diff::DesiredState;
use crate::model::policy::{ManagedObject, ObjectKey, PodSelector};
use crate::port::TemplateStore;
use crate::resolve;

/// The name every baseline object is written under, mirroring `network-profiles`' own
/// `weebo-base` and RFC 0006's *Guide-level explanation*: "`kubectl get kubearmorpolicy -n
/// <workspace-ns>` lists `weebo-base` and, if the workspace asked for it, `weebo-git-write`."
///
/// The two features' baselines share this name across two different API resources, which is
/// deliberate: an operator reading `kubectl get networkpolicy,kubearmorpolicy -n user-alice`
/// sees one name for one concept.
const BASELINE_NAME: &str = "weebo-base";

/// The namespace-scoped half of `kubearmor-policy`: the baseline object, plus the default
/// posture the namespace should carry.
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
/// Carries `namespace_annotation` alongside the workspace's own `attribute` rather than reading
/// it off `Context::namespace()`, for the reason `network-profiles`' `Workspace` does:
/// `weebo_si_chassis::NamespaceFacts::selection_annotation` holds *one* feature's projected
/// annotation, and this is now the fourth feature that would want that field.
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

/// The `kubearmor-policy` feature. Holds its configuration and resolved backend behind a lock,
/// same live-reload shape as `network-profiles`.
pub struct KubeArmorPolicy {
    config: Arc<RwLock<Option<KubeArmorPolicyConfig>>>,
    backend: Arc<RwLock<RuntimeBackend>>,
    templates: Arc<dyn TemplateStore + Send + Sync>,
}

impl KubeArmorPolicy {
    /// Build a feature reading `config` and `backend`, fetching template bodies from
    /// `templates`. The caller keeps the other half of `config`'s and `backend`'s `Arc`s and
    /// hands them to whatever keeps them current.
    pub fn new(
        config: Arc<RwLock<Option<KubeArmorPolicyConfig>>>,
        backend: Arc<RwLock<RuntimeBackend>>,
        templates: Arc<dyn TemplateStore + Send + Sync>,
    ) -> Self {
        Self {
            config,
            backend,
            templates,
        }
    }

    fn current_config(&self) -> Result<KubeArmorPolicyConfig, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone().ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "kubearmor-policy evaluated with no spec.features.kubearmorPolicy configured"
                    .to_string(),
            )
        })
    }

    fn current_backend(&self) -> RuntimeBackend {
        *self
            .backend
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The backend currently resolved, for a caller that needs to *report* it. Never used to make
    /// a decision outside this type; `desired()` reads the same value through
    /// [`Self::current_backend`].
    pub fn backend(&self) -> RuntimeBackend {
        self.current_backend()
    }
}

impl ReconcileFeature<NamespaceSubject> for KubeArmorPolicy {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("kubearmor-policy")
    }

    fn desired(
        &self,
        subject: &NamespaceSubject,
        _ctx: &Context<'_>,
    ) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let backend = self.current_backend();
        let posture = Some(config.enforcement.default_posture);

        let profile = config.catalog.profile(&config.baseline).ok_or_else(|| {
            DomainError::InvalidConfiguration(format!(
                "baseline runtime profile key {} is not present in the catalog",
                config.baseline
            ))
        })?;

        // The posture travels even when the baseline object itself cannot be built. It is the
        // namespace's own property, it is what decides what an *unmatched* operation does, and
        // withholding it because a template has not landed yet would leave a namespace at
        // whatever posture it last carried — which is the one state nobody chose.
        let Some(body) = self.templates.body(backend, &profile.template_ref) else {
            return Ok(DesiredState {
                posture,
                ..DesiredState::default()
            });
        };

        Ok(DesiredState {
            objects: vec![ManagedObject {
                key: ObjectKey {
                    namespace: subject.namespace.clone(),
                    name: BASELINE_NAME.to_string(),
                },
                backend,
                profile: config.baseline.clone(),
                pod_selector: PodSelector::Empty,
                body,
            }],
            posture,
            ..DesiredState::default()
        })
    }
}

impl ReconcileFeature<Workspace> for KubeArmorPolicy {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("kubearmor-policy")
    }

    fn desired(&self, subject: &Workspace, ctx: &Context<'_>) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;
        let backend = self.current_backend();

        // Reconcile-side, the fail-safe reading of an `OnNotGranted::Deny` is to write nothing
        // beyond the baseline for a workspace whose request could not be resolved, rather than
        // guess. The refused keys still travel out through `not_granted` so the counter and the
        // log line name them.
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

        let mut objects = Vec::with_capacity(provenance.resolved.len());
        for key in &provenance.resolved {
            let Some(profile) = config.catalog.profile(key) else {
                continue;
            };
            let Some(body) = self.templates.body(backend, &profile.template_ref) else {
                continue;
            };
            objects.push(ManagedObject {
                // The workspace id is part of the name, not only of the selector: two workspaces
                // in one namespace granted the same key would otherwise write the same object
                // twice with different selectors, and the second pass would fight the first.
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
            // Never `Some` here: posture is the namespace pass's to own. Two workspaces starting
            // at once must not race each other to rewrite their namespace's annotations.
            posture: None,
            team: provenance.team,
            not_granted: provenance.dropped_not_granted,
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
        DefaultPosture, FeatureMode, OnNotGranted, Posture, RuntimeEnforcement,
        RuntimeNamespaceSelection, RuntimeProfile, RuntimeProfileCatalog, RuntimeProfileGrant,
        RuntimeProfileKey, RuntimeWorkspaceSelection, Selector, Team, TeamName, TemplateRef,
    };

    use super::*;
    use crate::port::testing::FakeTemplateStore;

    fn template_ref(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn entry(key: &str) -> RuntimeProfile {
        RuntimeProfile {
            key: RuntimeProfileKey::new(key),
            template_ref: template_ref(&format!("weebo-{key}-runtime")),
        }
    }

    fn config(grants: BTreeMap<String, RuntimeProfileGrant>) -> KubeArmorPolicyConfig {
        KubeArmorPolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: RuntimeProfileCatalog::new(vec![
                entry("base"),
                entry("git-write"),
                entry("net-raw"),
            ]),
            baseline: RuntimeProfileKey::new("base"),
            grants,
            namespace_selection: RuntimeNamespaceSelection::default(),
            workspace_selection: RuntimeWorkspaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
            enforcement: RuntimeEnforcement::default(),
        }
    }

    fn templates() -> FakeTemplateStore {
        FakeTemplateStore::new([
            (template_ref("weebo-base-runtime"), b"base-rules".to_vec()),
            (
                template_ref("weebo-git-write-runtime"),
                b"git-write-rules".to_vec(),
            ),
            (
                template_ref("weebo-net-raw-runtime"),
                b"net-raw-rules".to_vec(),
            ),
        ])
    }

    fn feature(config: KubeArmorPolicyConfig) -> KubeArmorPolicy {
        KubeArmorPolicy::new(
            Arc::new(RwLock::new(Some(config))),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
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

    fn namespace_subject() -> NamespaceSubject {
        NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
        }
    }

    #[test]
    fn the_baseline_object_carries_the_empty_selector_and_the_baseline_key() {
        let feature = feature(config(BTreeMap::new()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let desired = feature.desired(&namespace_subject(), &context).unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(desired.objects[0].key.name, BASELINE_NAME);
        assert_eq!(desired.objects[0].pod_selector, PodSelector::Empty);
        assert_eq!(desired.objects[0].profile, RuntimeProfileKey::new("base"));
    }

    #[test]
    fn the_namespace_pass_carries_the_configured_posture() {
        let mut cfg = config(BTreeMap::new());
        cfg.enforcement = RuntimeEnforcement {
            default_posture: DefaultPosture {
                file: Posture::Block,
                network: Posture::Audit,
                capabilities: Posture::Block,
            },
            ..RuntimeEnforcement::default()
        };
        let feature = feature(cfg);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let desired = feature.desired(&namespace_subject(), &context).unwrap();
        assert_eq!(
            desired.posture,
            Some(DefaultPosture {
                file: Posture::Block,
                network: Posture::Audit,
                capabilities: Posture::Block,
            })
        );
    }

    #[test]
    fn a_missing_baseline_template_still_carries_the_posture() {
        // The namespace's posture decides what an *unmatched* operation does. Withholding it
        // because a template has not landed leaves the namespace at whatever it last carried.
        let feature = KubeArmorPolicy::new(
            Arc::new(RwLock::new(Some(config(BTreeMap::new())))),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
            Arc::new(FakeTemplateStore::new([])),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        let desired = feature.desired(&namespace_subject(), &context).unwrap();
        assert!(desired.objects.is_empty());
        assert!(desired.posture.is_some());
    }

    #[test]
    fn a_baseline_key_absent_from_the_catalog_is_a_domain_error() {
        let mut cfg = config(BTreeMap::new());
        cfg.baseline = RuntimeProfileKey::new("missing");
        let feature = feature(cfg);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        assert!(feature.desired(&namespace_subject(), &context).is_err());
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

    fn team1_grants() -> BTreeMap<String, RuntimeProfileGrant> {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RuntimeProfileGrant {
                allowed: vec![
                    RuntimeProfileKey::new("git-write"),
                    RuntimeProfileKey::new("net-raw"),
                ],
                default: vec![RuntimeProfileKey::new("git-write")],
            },
        );
        grants
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

    fn team1_namespace() -> NamespaceFacts {
        let mut namespace = namespace_facts();
        namespace
            .labels
            .insert("weebo.io/team".to_string(), "team-1".to_string());
        namespace
    }

    #[test]
    fn a_workspace_with_two_granted_profiles_gets_two_objects_keyed_by_workspace_id() {
        let feature = feature(config(team1_grants()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let subject = workspace(Some("git-write,net-raw"));

        let desired = feature.desired(&subject, &context).unwrap();
        let mut names: Vec<&str> = desired
            .objects
            .iter()
            .map(|o| o.key.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "weebo-git-write-workspacede4f56",
                "weebo-net-raw-workspacede4f56"
            ]
        );
        assert!(
            desired.objects.iter().all(
                |o| o.pod_selector == PodSelector::DevWorkspaceId(subject.workspace_id.clone())
            )
        );
    }

    #[test]
    fn the_workspace_pass_never_carries_a_posture() {
        // Posture is the namespace's property. Two workspaces starting at once must not race to
        // rewrite their namespace's annotations.
        let feature = feature(config(team1_grants()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let desired = feature.desired(&workspace(None), &context).unwrap();
        assert_eq!(desired.posture, None);
    }

    #[test]
    fn a_workspace_asking_for_nothing_beyond_the_default_gets_the_grant_default() {
        let feature = feature(config(team1_grants()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let desired = feature.desired(&workspace(None), &context).unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(
            desired.objects[0].profile,
            RuntimeProfileKey::new("git-write")
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_writes_nothing_beyond_the_baseline() {
        let mut cfg = config(team1_grants());
        cfg.on_not_granted = OnNotGranted::Deny;
        let feature = feature(cfg);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let desired = feature.desired(&workspace(Some("nope")), &context).unwrap();
        assert!(desired.objects.is_empty());
        assert_eq!(desired.not_granted, vec![RuntimeProfileKey::new("nope")]);
    }

    #[test]
    fn a_granted_key_whose_template_has_not_landed_writes_nothing_for_that_key_alone() {
        let feature = KubeArmorPolicy::new(
            Arc::new(RwLock::new(Some(config(team1_grants())))),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
            Arc::new(FakeTemplateStore::new([(
                template_ref("weebo-git-write-runtime"),
                b"git-write-rules".to_vec(),
            )])),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = ctx(&teams, &namespace, &catalog);
        let desired = feature
            .desired(&workspace(Some("git-write,net-raw")), &context)
            .unwrap();
        assert_eq!(
            desired.objects.len(),
            1,
            "the resolvable key is still applied; the other is simply not written"
        );
        assert_eq!(
            desired.objects[0].profile,
            RuntimeProfileKey::new("git-write")
        );
    }

    #[test]
    fn evaluate_with_no_config_at_all_is_a_domain_error() {
        let feature = KubeArmorPolicy::new(
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
            Arc::new(templates()),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);
        assert!(feature.desired(&namespace_subject(), &context).is_err());
    }

    #[test]
    fn the_live_config_can_be_swapped_without_reconstructing_the_feature() {
        let config_handle = Arc::new(RwLock::new(Some(config(BTreeMap::new()))));
        let feature = KubeArmorPolicy::new(
            Arc::clone(&config_handle),
            Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
            Arc::new(templates()),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = namespace_facts();
        let context = ctx(&[], &namespace, &catalog);

        let desired = feature.desired(&namespace_subject(), &context).unwrap();
        assert_eq!(desired.objects[0].profile, RuntimeProfileKey::new("base"));

        {
            let mut guard = config_handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cfg) = guard.as_mut() {
                cfg.baseline = RuntimeProfileKey::new("git-write");
            }
        }

        let desired = feature.desired(&namespace_subject(), &context).unwrap();
        assert_eq!(
            desired.objects[0].profile,
            RuntimeProfileKey::new("git-write"),
            "the second desired() must see the swapped config"
        );
    }
}
