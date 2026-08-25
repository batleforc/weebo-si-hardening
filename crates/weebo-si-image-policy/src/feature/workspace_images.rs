//! `Feature<WorkspaceImages>` — the selection-precise half, on the `DevWorkspace` webhook.
//!
//! This is where a developer gets a readable error on their own `kubectl apply`, and where the
//! per-workspace selection is actually enforced. What it cannot see is what DevWorkspace
//! Operator injects and what a plugin resolves to; [`crate::PodImagesFeature`] is the floor
//! underneath it for exactly those.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::ImagePolicyConfig;

use crate::feature::core::{FEATURE_ID, bind_builtins, judge_images, render_note};
use crate::port::{ImagePolicyObserver, Resource};
use crate::resolve::resolve;
use crate::subject::WorkspaceImages;

/// `image-policy`'s `DevWorkspace` half.
pub struct WorkspaceImagesFeature {
    config: Arc<RwLock<Option<ImagePolicyConfig>>>,
    observer: Arc<dyn ImagePolicyObserver>,
}

impl WorkspaceImagesFeature {
    /// Build it. Holds the same live configuration `Arc` as [`crate::PodImagesFeature`] so the
    /// two halves of one feature can never disagree about the catalogue, the grants or the
    /// platform set.
    pub fn new(
        config: Arc<RwLock<Option<ImagePolicyConfig>>>,
        observer: Arc<dyn ImagePolicyObserver>,
    ) -> Self {
        Self { config, observer }
    }
}

impl Feature<WorkspaceImages> for WorkspaceImagesFeature {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &WorkspaceImages,
        ctx: &Context<'_>,
    ) -> Result<Decision<WorkspaceImages>, DomainError> {
        let config = {
            let guard = self
                .config
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.clone().ok_or_else(|| {
                DomainError::InvalidConfiguration(
                    "image-policy evaluated with no spec.features.imagePolicy configured"
                        .to_string(),
                )
            })?
        };

        // `resolve` only ever returns `Err` under `onNotGranted: Deny`; under `Default` an
        // ungranted key is dropped and flagged, which the judging core counts.
        let provenance = match resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.namespace_annotation.as_deref(),
            subject.attribute.as_deref(),
        ) {
            Ok(provenance) => provenance,
            Err(not_granted) => {
                let keys: Vec<&str> = not_granted
                    .requested
                    .iter()
                    .map(weebo_si_crd::EntryKey::as_str)
                    .collect();
                let team = not_granted
                    .team
                    .as_ref()
                    .map(|team| team.as_str().to_string())
                    .unwrap_or_else(|| "<none>".to_string());
                self.observer.not_granted(
                    Resource::DevWorkspace,
                    not_granted.team.as_ref(),
                    not_granted.requested.len(),
                );
                return Ok(Decision::deny(
                    format!(
                        "workspace {} requests image-policy entr{} [{}], which team {team} is \
                         not granted",
                        subject.name,
                        if keys.len() == 1 { "y" } else { "ies" },
                        keys.join(",")
                    ),
                    not_granted.team,
                    None,
                    "not_granted",
                ));
            }
        };

        let variables = bind_builtins(
            &subject.variables,
            subject.namespace(),
            provenance.team.as_ref(),
            &config,
            self.observer.as_ref(),
        );

        let judgement = judge_images(
            &config,
            &provenance,
            &subject.images,
            &variables,
            Resource::DevWorkspace,
            &subject.name,
            self.observer.as_ref(),
        );

        let note = Some(render_note(&provenance, subject.images.len()));
        match judgement.denial {
            Some(reason) => Ok(Decision::deny(
                reason,
                provenance.team,
                note,
                judgement.result,
            )),
            // Never a mutation. RFC 0005 rejects the rewrite-the-registry alternative on the
            // ground that it would run different bytes than the devfile asked for, silently.
            None => Ok(Decision::new(Vec::new(), provenance.team, note, "allowed")),
        }
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
        Entry, EntryKey, FeatureMode, ImageCatalog, ImageGrant, ImageNamespaceSelection,
        ImagePolicyConfig, ImageWorkspaceSelection, NamespaceName, OnUnknownKey, PlatformConfig,
        Selector, Team, TeamName,
    };

    use super::*;
    use crate::port::testing::{NullObserver, RecordingObserver};
    use crate::subject::ContainerImage;
    use crate::variable::VariableValues;

    fn catalog() -> ImageCatalog {
        ImageCatalog::new(vec![
            Entry {
                key: EntryKey::new("internal"),
                patterns: vec!["registry.internal/shared/**".to_string()],
            },
            Entry {
                key: EntryKey::new("team-registry"),
                patterns: vec!["registry.internal/teams/{TEAM_NAME}/**".to_string()],
            },
            Entry {
                key: EntryKey::new("devfile-udi"),
                patterns: vec!["quay.io/devfile/universal-developer-image:ubi9-*".to_string()],
            },
            Entry {
                key: EntryKey::new("dockerhub-library"),
                patterns: vec!["docker.io/library/**".to_string()],
            },
        ])
    }

    fn config() -> ImagePolicyConfig {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ImageGrant {
                allowed: vec![
                    EntryKey::new("internal"),
                    EntryKey::new("team-registry"),
                    EntryKey::new("devfile-udi"),
                ],
                default: vec![EntryKey::new("internal"), EntryKey::new("team-registry")],
            },
        );
        grants.insert(
            "team-2".to_string(),
            ImageGrant {
                allowed: vec![EntryKey::new("internal")],
                default: vec![EntryKey::new("internal")],
            },
        );
        ImagePolicyConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            catalog: catalog(),
            variables: BTreeMap::new(),
            default: vec![EntryKey::new("internal")],
            grants,
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
        }
    }

    fn teams() -> Vec<Team> {
        ["team-1", "team-2"]
            .iter()
            .map(|name| Team {
                name: TeamName::new(*name),
                namespace_selector: Selector {
                    match_labels: [("weebo.io/team".to_string(), (*name).to_string())].into(),
                    match_expressions: Vec::new(),
                },
            })
            .collect()
    }

    fn facts(team: Option<&str>) -> NamespaceFacts {
        NamespaceFacts {
            labels: team
                .map(|team| {
                    [("weebo.io/team".to_string(), team.to_string())]
                        .into_iter()
                        .collect()
                })
                .unwrap_or_default(),
            selection_annotation: None,
        }
    }

    fn subject(
        name: &str,
        namespace: &str,
        images: &[(&str, &str)],
        attribute: Option<&str>,
    ) -> WorkspaceImages {
        WorkspaceImages {
            name: name.to_string(),
            namespace: NamespaceName::new(namespace),
            images: images
                .iter()
                .map(|(component, reference)| ContainerImage::new(*component, *reference))
                .collect(),
            attribute: attribute.map(str::to_string),
            namespace_annotation: None,
            variables: VariableValues::new(),
        }
    }

    fn evaluate(
        config: ImagePolicyConfig,
        subject: &WorkspaceImages,
        team_label: Option<&str>,
        observer: Arc<dyn ImagePolicyObserver>,
    ) -> Decision<WorkspaceImages> {
        let feature = WorkspaceImagesFeature::new(Arc::new(RwLock::new(Some(config))), observer);
        let teams = teams();
        let namespace = facts(team_label);
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &namespace, &catalog);
        feature
            .evaluate(subject, &ctx)
            .unwrap_or_else(|err| panic!("evaluate should not error: {err}"))
    }

    fn null() -> Arc<dyn ImagePolicyObserver> {
        Arc::new(NullObserver)
    }

    #[test]
    fn a_workspace_running_only_granted_images_is_allowed() {
        let subject = subject(
            "data-pipeline",
            "user-alice",
            &[
                ("dev", "registry.internal/shared/base:2026.3"),
                ("java", "registry.internal/teams/team-1/dev-java:21"),
            ],
            None,
        );
        let decision = evaluate(config(), &subject, Some("team-1"), null());
        assert_eq!(decision.denial, None);
        assert_eq!(decision.result, "allowed");
        assert_eq!(decision.team, Some(TeamName::new("team-1")));
    }

    #[test]
    fn the_rfcs_own_denial_message_is_what_a_developer_sees() {
        // `kubectl apply` against team-2's namespace, naming postgres.
        let subject = subject(
            "scratch",
            "user-bob",
            &[("tools", "docker.io/library/postgres:16")],
            None,
        );
        let decision = evaluate(config(), &subject, Some("team-2"), null());
        let denial = decision.denial.unwrap();
        assert!(denial.contains("component \"tools\""), "{denial}");
        assert!(denial.contains("docker.io/library/postgres:16"), "{denial}");
        assert!(denial.contains("team team-2"), "{denial}");
        assert!(denial.contains("[internal]"), "{denial}");
        assert!(
            denial.contains(".spec.features.imagePolicy.catalog"),
            "{denial}"
        );
    }

    #[test]
    fn a_platform_image_is_permitted_whatever_the_grant_says() {
        // Nobody writes these down, and no grant can withhold them.
        let subject = subject(
            "any",
            "user-bob",
            &[("clone", "quay.io/devfile/project-clone:v0.30.0")],
            // An explicitly empty selection: the platform set and nothing else.
            Some(""),
        );
        let decision = evaluate(config(), &subject, Some("team-2"), null());
        assert_eq!(decision.denial, None);
    }

    #[test]
    fn platform_builtin_false_withdraws_the_compiled_in_set() {
        let mut config = config();
        config.platform.builtin = false;
        let subject = subject(
            "any",
            "user-bob",
            &[("clone", "quay.io/devfile/project-clone:v0.30.0")],
            Some(""),
        );
        assert!(
            evaluate(config, &subject, Some("team-2"), null())
                .denial
                .is_some()
        );
    }

    #[test]
    fn team_name_resolves_per_namespace_and_denies_across_teams() {
        // The `images audit` row a per-team registry path exists to catch: a team-1 namespace
        // running an image out of team-3's path.
        let subject = subject(
            "data-pipeline",
            "user-alice",
            &[("go", "registry.internal/teams/team-3/dev-go:1.24")],
            None,
        );
        assert!(
            evaluate(config(), &subject, Some("team-1"), null())
                .denial
                .is_some()
        );
    }

    #[test]
    fn a_namespace_with_no_team_gets_the_top_level_default() {
        let subject = subject(
            "orphan",
            "user-carol",
            &[("dev", "registry.internal/shared/base:1")],
            None,
        );
        let decision = evaluate(config(), &subject, None, null());
        assert_eq!(decision.denial, None);
        assert_eq!(decision.team, None);
    }

    #[test]
    fn the_workspace_attribute_widens_within_the_grant_and_no_further() {
        let udi = subject(
            "data-pipeline",
            "user-alice",
            &[(
                "dev",
                "quay.io/devfile/universal-developer-image:ubi9-latest",
            )],
            Some("internal,devfile-udi"),
        );
        assert_eq!(
            evaluate(config(), &udi, Some("team-1"), null()).denial,
            None
        );

        // ...and the same attribute cannot reach an entry the *team* was never granted.
        let postgres = subject(
            "data-pipeline",
            "user-alice",
            &[("db", "docker.io/library/postgres:16")],
            Some("dockerhub-library"),
        );
        assert!(
            evaluate(config(), &postgres, Some("team-1"), null())
                .denial
                .is_some()
        );
    }

    #[test]
    fn under_deny_an_ungranted_key_refuses_the_workspace_naming_the_key() {
        let mut config = config();
        config.on_not_granted = OnUnknownKey::Deny;
        let subject = subject(
            "scratch",
            "user-bob",
            &[("dev", "registry.internal/shared/base:1")],
            Some("dockerhub-library"),
        );
        let decision = evaluate(config, &subject, Some("team-2"), null());
        let denial = decision.denial.unwrap();
        assert!(denial.contains("dockerhub-library"), "{denial}");
        assert!(denial.contains("team team-2"), "{denial}");
        assert_eq!(decision.result, "not_granted");
    }

    #[test]
    fn under_default_an_ungranted_key_falls_back_and_is_counted() {
        let observer = Arc::new(RecordingObserver::default());
        let subject = subject(
            "scratch",
            "user-bob",
            &[("dev", "registry.internal/shared/base:1")],
            Some("dockerhub-library"),
        );
        let decision = evaluate(config(), &subject, Some("team-2"), observer.clone());
        // The default (`internal`) applied, so the shared image still runs.
        assert_eq!(decision.denial, None);
        assert_eq!(observer.not_granted().len(), 1);
    }

    #[test]
    fn the_feature_never_mutates() {
        // RFC 0005 rejects the rewrite-the-registry-to-a-mirror alternative outright: it would
        // run different bytes than the devfile asked for, silently.
        let subject = subject(
            "any",
            "user-alice",
            &[("dev", "registry.internal/shared/base:1")],
            None,
        );
        assert!(
            evaluate(config(), &subject, Some("team-1"), null())
                .mutations
                .is_empty()
        );
    }

    #[test]
    fn an_absent_configuration_is_an_error_not_a_silent_allow() {
        let feature = WorkspaceImagesFeature::new(Arc::new(RwLock::new(None)), null());
        let teams = teams();
        let namespace = facts(Some("team-1"));
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &namespace, &catalog);
        let subject = subject("any", "user-alice", &[], None);
        assert!(matches!(
            feature.evaluate(&subject, &ctx),
            Err(DomainError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn a_workspace_with_no_images_is_allowed_and_says_so() {
        let subject = subject("empty", "user-alice", &[], None);
        let decision = evaluate(config(), &subject, Some("team-1"), null());
        assert_eq!(decision.denial, None);
        assert!(decision.note.unwrap().contains("images=0"));
    }
}
