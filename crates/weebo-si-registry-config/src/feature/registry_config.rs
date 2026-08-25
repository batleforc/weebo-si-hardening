//! The `registry-config` feature — see RFC 0007's *Design → Architecture*.
//!
//! **One `Subject`, where `network-profiles` and `kubearmor-policy` have two.** Not a
//! simplification: an automounted object has no pod selector, so there is no workspace-scoped
//! object to compute. Everything this feature writes is a property of the namespace, which is
//! also why this brick has no race the sibling bricks have to argue about — a namespace is
//! reconciled long before anyone opens a workspace in it (RFC 0007's *The unit is the namespace,
//! not the workspace*, consequence 2).

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, DomainError, FeatureId, ReconcileFeature, Subject};
use weebo_si_crd::{NamespaceName, RegistryConfig as RegistryConfigSpec, copy_name};

use crate::model::diff::{DesiredState, RefusedTemplate};
use crate::model::mount;
use crate::model::object::{ManagedObject, ObjectKey};
use crate::port::TemplateStore;
use crate::resolve;

/// The namespace under reconciliation.
///
/// Carries `annotation` alongside its name rather than reading it off `Context::namespace()`,
/// for the reason every sibling feature's subject does: `weebo_si_chassis::NamespaceFacts`'s
/// `selection_annotation` holds *one* feature's projected annotation, and this is the fifth
/// feature that would want that field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceSubject {
    /// The namespace to compute registry configuration for.
    pub namespace: NamespaceName,
    /// The raw value of `namespaceSelection.annotation`, if the namespace carries it.
    pub annotation: Option<String>,
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

/// The `registry-config` feature. Holds its configuration behind a lock, same live-reload shape
/// as `network-profiles` and `kubearmor-policy`.
///
/// Named `RegistryConfigFeature` rather than `RegistryConfig` because
/// [`weebo_si_crd::RegistryConfig`] already owns that name for the wire type, and a call site
/// importing both would have to alias one of them anyway.
pub struct RegistryConfigFeature {
    config: Arc<RwLock<Option<RegistryConfigSpec>>>,
    templates: Arc<dyn TemplateStore + Send + Sync>,
}

impl RegistryConfigFeature {
    /// Build a feature reading `config`, fetching templates from `templates`. The caller keeps
    /// the other half of `config`'s `Arc` and hands it to whatever keeps it current.
    pub fn new(
        config: Arc<RwLock<Option<RegistryConfigSpec>>>,
        templates: Arc<dyn TemplateStore + Send + Sync>,
    ) -> Self {
        Self { config, templates }
    }

    fn current_config(&self) -> Result<RegistryConfigSpec, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone().ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "registry-config evaluated with no spec.features.registryConfig configured"
                    .to_string(),
            )
        })
    }
}

impl ReconcileFeature<NamespaceSubject> for RegistryConfigFeature {
    type Desired = DesiredState;

    fn id(&self) -> FeatureId {
        FeatureId::new("registry-config")
    }

    fn desired(
        &self,
        subject: &NamespaceSubject,
        ctx: &Context<'_>,
    ) -> Result<DesiredState, DomainError> {
        let config = self.current_config()?;

        // Reconcile-side, the fail-safe reading of an `OnNotGranted::Deny` is to write nothing
        // for a namespace whose request could not be resolved, rather than guess. The refused
        // keys still travel out through `not_granted` so the counter and the log line name them.
        let provenance = match resolve::resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.annotation.as_deref(),
        ) {
            Ok(provenance) => provenance,
            Err(not_granted) => {
                return Ok(DesiredState {
                    team: not_granted.team,
                    not_granted: not_granted.requested,
                    ..DesiredState::default()
                });
            }
        };

        let mut objects = Vec::new();
        let mut refused = Vec::new();

        for key in &provenance.resolved {
            // A resolved key with no catalogue entry cannot happen against a configuration that
            // passed `validate()` — a grant may only allow catalogued keys, and a namespace
            // annotation is filtered through that grant. Reaching here means the configuration
            // is internally inconsistent, and this feature refuses to guess against unproven
            // configuration rather than write on it.
            let entry = config.catalog.entry(key).ok_or_else(|| {
                DomainError::InvalidConfiguration(format!(
                    "resolved registry key {key} is not present in the catalog"
                ))
            })?;

            for source in &entry.sources {
                let Some(template) = self.templates.template(source.kind, &source.template_ref)
                else {
                    refused.push(RefusedTemplate {
                        entry: key.clone(),
                        kind: source.kind,
                        name: source.template_ref.name.clone(),
                        refusal: None,
                    });
                    continue;
                };

                // The whole of the content inspection this brick does. Everything below this
                // line copies bytes it has not looked at.
                if let Err(refusal) = mount::admit(&template.labels, &template.annotations) {
                    refused.push(RefusedTemplate {
                        entry: key.clone(),
                        kind: source.kind,
                        name: source.template_ref.name.clone(),
                        refusal: Some(refusal),
                    });
                    continue;
                }

                objects.push(ManagedObject {
                    key: ObjectKey {
                        namespace: subject.namespace.clone(),
                        name: copy_name(key, &source.template_ref.name),
                    },
                    kind: source.kind,
                    entry: key.clone(),
                    labels: template.labels,
                    annotations: template.annotations,
                    body: template.body,
                });
            }
        }

        Ok(DesiredState {
            objects,
            team: provenance.team,
            not_granted: provenance.dropped_not_granted,
            refused,
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
        Ecosystem, FeatureMode, OnNotGranted, RegistryCatalog, RegistryEntry, RegistryGrant,
        RegistryKey, RegistryNamespaceSelection, RegistrySource, Selector, SourceKind, Team,
        TeamName, TemplateRef,
    };

    use super::*;
    use crate::model::mount::{
        MOUNT_AS_ANNOTATION, MOUNT_PATH_ANNOTATION, MOUNT_TO_DEVWORKSPACE_LABEL, TemplateRefusal,
    };
    use crate::model::object::{ObjectBody, Template};
    use crate::port::testing::FakeTemplateStore;

    fn template_ref(name: &str) -> TemplateRef {
        TemplateRef {
            name: name.to_string(),
            namespace: NamespaceName::new("weebo-si-hardening"),
        }
    }

    fn catalog() -> RegistryCatalog {
        RegistryCatalog::new(vec![
            RegistryEntry {
                key: RegistryKey::new("internal-npm"),
                ecosystem: Ecosystem::Npm,
                sources: vec![
                    RegistrySource {
                        kind: SourceKind::ConfigMap,
                        template_ref: template_ref("weebo-npmrc"),
                    },
                    RegistrySource {
                        kind: SourceKind::Secret,
                        template_ref: template_ref("weebo-npm-token"),
                    },
                ],
            },
            RegistryEntry {
                key: RegistryKey::new("internal-pypi"),
                ecosystem: Ecosystem::Pypi,
                sources: vec![RegistrySource {
                    kind: SourceKind::ConfigMap,
                    template_ref: template_ref("weebo-pip-conf"),
                }],
            },
        ])
    }

    fn config(grants: BTreeMap<String, RegistryGrant>) -> RegistryConfigSpec {
        RegistryConfigSpec {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: catalog(),
            grants,
            namespace_selection: RegistryNamespaceSelection::default(),
            on_not_granted: OnNotGranted::default(),
        }
    }

    fn templates() -> FakeTemplateStore {
        FakeTemplateStore::automountable([
            (
                (SourceKind::ConfigMap, template_ref("weebo-npmrc")),
                b"registry=https://batlehub.internal/npm/".to_vec(),
            ),
            (
                (SourceKind::Secret, template_ref("weebo-npm-token")),
                b"token".to_vec(),
            ),
            (
                (SourceKind::ConfigMap, template_ref("weebo-pip-conf")),
                b"index-url=https://batlehub.internal/pypi/simple".to_vec(),
            ),
        ])
    }

    fn feature(
        config: RegistryConfigSpec,
        templates: impl TemplateStore + Send + Sync + 'static,
    ) -> RegistryConfigFeature {
        RegistryConfigFeature::new(Arc::new(RwLock::new(Some(config))), Arc::new(templates))
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

    fn team1_grants() -> BTreeMap<String, RegistryGrant> {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            RegistryGrant {
                allowed: vec![
                    RegistryKey::new("internal-npm"),
                    RegistryKey::new("internal-pypi"),
                ],
                default: vec![RegistryKey::new("internal-npm")],
            },
        );
        grants
    }

    fn team1_namespace() -> NamespaceFacts {
        NamespaceFacts {
            labels: BTreeMap::from([("weebo.io/team".to_string(), "team-1".to_string())]),
            selection_annotation: None,
        }
    }

    fn subject(annotation: Option<&str>) -> NamespaceSubject {
        NamespaceSubject {
            namespace: NamespaceName::new("user-alice"),
            annotation: annotation.map(str::to_string),
        }
    }

    #[test]
    fn a_granted_key_with_two_sources_produces_two_objects() {
        let feature = feature(config(team1_grants()), templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        let mut names: Vec<&str> = desired
            .objects
            .iter()
            .map(|o| o.key.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "weebo-si-internal-npm-weebo-npm-token",
                "weebo-si-internal-npm-weebo-npmrc",
            ]
        );
        assert!(desired.is_ready());
    }

    #[test]
    fn the_copy_carries_the_templates_own_mount_annotations_verbatim() {
        // The mount semantics stay the admin's decision, expressed in DevWorkspace Operator's own
        // vocabulary — RFC 0007's *Guide-level explanation*: "the alternative is inventing a
        // mount DSL this project would then own forever."
        let feature = feature(config(team1_grants()), templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        let object = &desired.objects[0];
        assert_eq!(
            object
                .annotations
                .get(MOUNT_AS_ANNOTATION)
                .map(String::as_str),
            Some("subpath")
        );
        assert_eq!(
            object
                .annotations
                .get(MOUNT_PATH_ANNOTATION)
                .map(String::as_str),
            Some("/home/user")
        );
        assert_eq!(
            object
                .labels
                .get(MOUNT_TO_DEVWORKSPACE_LABEL)
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn an_ungranted_team_gets_nothing_and_is_still_ready() {
        // No baseline: a namespace whose team was granted nothing is not configured, and that is
        // not a degradation. If it were, `weebo_si_registry_ready` would alert on every
        // namespace in a cluster running this brick for one pilot team.
        let feature = feature(config(BTreeMap::new()), templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = NamespaceFacts::default();
        let context = Context::new(&[], &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        assert!(desired.objects.is_empty());
        assert!(desired.is_ready());
    }

    #[test]
    fn the_namespace_annotation_selects_a_different_granted_key() {
        let feature = feature(config(team1_grants()), templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature
            .desired(&subject(Some("internal-pypi")), &context)
            .unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(
            desired.objects[0].key.name,
            "weebo-si-internal-pypi-weebo-pip-conf"
        );
    }

    #[test]
    fn a_template_that_has_not_landed_is_reported_as_not_found_and_not_ready() {
        let feature = feature(
            config(team1_grants()),
            FakeTemplateStore::automountable([(
                (SourceKind::ConfigMap, template_ref("weebo-npmrc")),
                b"registry=".to_vec(),
            )]),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        assert_eq!(
            desired.objects.len(),
            1,
            "the resolvable source is still copied; the other is simply not written"
        );
        assert_eq!(desired.refused.len(), 1);
        assert_eq!(desired.refused[0].reason(), "not_found");
        assert!(
            !desired.is_ready(),
            "half an entry is what a broken build looks like — the gauge has to say so"
        );
    }

    #[test]
    fn a_template_shadowing_a_home_directory_is_refused_and_never_copied() {
        // The failure this brick inspects content at all to prevent: silent, total, and looking
        // like a broken image rather than a broken config.
        let feature = feature(
            config(team1_grants()),
            FakeTemplateStore::new([(
                (SourceKind::ConfigMap, template_ref("weebo-npmrc")),
                Template {
                    labels: BTreeMap::from([(
                        MOUNT_TO_DEVWORKSPACE_LABEL.to_string(),
                        "true".to_string(),
                    )]),
                    // No `mount-as` at all — DWO's default is `file`, which mounts a directory.
                    annotations: BTreeMap::from([(
                        MOUNT_PATH_ANNOTATION.to_string(),
                        "/home/user".to_string(),
                    )]),
                    body: ObjectBody::opaque(b"registry=".to_vec()),
                },
            )]),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        assert!(
            desired.objects.is_empty(),
            "a shadowing template is never copied"
        );
        assert_eq!(
            desired.refused[0].refusal,
            Some(TemplateRefusal::MountShadowsPath)
        );
    }

    #[test]
    fn a_template_without_the_automount_label_is_refused() {
        let feature = feature(
            config(team1_grants()),
            FakeTemplateStore::new([(
                (SourceKind::ConfigMap, template_ref("weebo-npmrc")),
                Template {
                    labels: BTreeMap::new(),
                    annotations: BTreeMap::new(),
                    body: ObjectBody::opaque(b"registry=".to_vec()),
                },
            )]),
        );
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(None), &context).unwrap();
        assert!(desired.objects.is_empty());
        assert_eq!(
            desired.refused[0].refusal,
            Some(TemplateRefusal::NotAutomountable)
        );
    }

    #[test]
    fn an_ungranted_request_under_deny_writes_nothing_at_all() {
        let mut cfg = config(team1_grants());
        cfg.on_not_granted = OnNotGranted::Deny;
        let feature = feature(cfg, templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        let desired = feature.desired(&subject(Some("nope")), &context).unwrap();
        assert!(desired.objects.is_empty());
        assert_eq!(desired.not_granted, vec![RegistryKey::new("nope")]);
        assert!(!desired.is_ready());
    }

    #[test]
    fn evaluate_with_no_config_at_all_is_a_domain_error() {
        let feature =
            RegistryConfigFeature::new(Arc::new(RwLock::new(None)), Arc::new(templates()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = NamespaceFacts::default();
        let context = Context::new(&[], &namespace, &catalog);
        assert!(feature.desired(&subject(None), &context).is_err());
    }

    #[test]
    fn a_resolved_key_absent_from_the_catalog_is_a_domain_error() {
        // Unreachable against a configuration that passed `validate()`, and a refusal to guess
        // rather than a silent skip if it ever is reached.
        let mut cfg = config(team1_grants());
        cfg.catalog = RegistryCatalog::new(Vec::new());
        let feature = feature(cfg, templates());
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);
        assert!(feature.desired(&subject(None), &context).is_err());
    }

    #[test]
    fn the_live_config_can_be_swapped_without_reconstructing_the_feature() {
        let handle = Arc::new(RwLock::new(Some(config(team1_grants()))));
        let feature = RegistryConfigFeature::new(Arc::clone(&handle), Arc::new(templates()));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let namespace = team1_namespace();
        let teams = [team1()];
        let context = Context::new(&teams, &namespace, &catalog);

        assert_eq!(
            feature
                .desired(&subject(None), &context)
                .unwrap()
                .objects
                .len(),
            2
        );

        {
            let mut guard = handle
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cfg) = guard.as_mut() {
                cfg.grants.insert(
                    "team-1".to_string(),
                    RegistryGrant {
                        allowed: vec![RegistryKey::new("internal-pypi")],
                        default: vec![RegistryKey::new("internal-pypi")],
                    },
                );
            }
        }

        let desired = feature.desired(&subject(None), &context).unwrap();
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(
            desired.objects[0].key.name, "weebo-si-internal-pypi-weebo-pip-conf",
            "the second desired() must see the swapped config"
        );
    }
}
