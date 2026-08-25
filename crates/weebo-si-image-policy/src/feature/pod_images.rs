//! `Feature<PodImages>` — the team-boundary floor, on the `Pod` webhook.
//!
//! This is what catches the images DevWorkspace Operator injects, the plugin sidecars a devfile
//! pulls in by URI, and any pod created without a workspace at all — a `Deployment`, a `Job`, a
//! `kubectl debug` ephemeral container. Its error message is worse than the `DevWorkspace`
//! half's, and that is deliberate: it fires for images the developer did not write down, which
//! is exactly the case where the good error message was never available.
//!
//! **It enforces the team's whole `allowed` set, not the per-workspace selection**, and that is
//! the one row of RFC 0005's two-enforcement-point table that is a decision rather than a
//! consequence. A pod carries `controller.devfile.io/devworkspace_id`, not the selection
//! attribute, and resolving the attribute from the id would mean a DevWorkspace watch in the
//! webhook role, new RBAC, a cache that scales with the fleet, and a startup race in which a
//! cold replica denies pods belonging to workspaces it has not observed yet. What it buys is
//! that this feature adds **zero** new RBAC and no new cache — the property RFC 0005's
//! *Security considerations* leans on.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::ImagePolicyConfig;

use crate::feature::core::{FEATURE_ID, bind_builtins, judge_images, render_note};
use crate::port::{ImagePolicyObserver, Resource};
use crate::resolve::allowed_set;
use crate::subject::PodImages;

/// `image-policy`'s `Pod` half.
pub struct PodImagesFeature {
    config: Arc<RwLock<Option<ImagePolicyConfig>>>,
    observer: Arc<dyn ImagePolicyObserver>,
}

impl PodImagesFeature {
    /// Build it. Holds the same live configuration `Arc` as
    /// [`crate::WorkspaceImagesFeature`].
    pub fn new(
        config: Arc<RwLock<Option<ImagePolicyConfig>>>,
        observer: Arc<dyn ImagePolicyObserver>,
    ) -> Self {
        Self { config, observer }
    }
}

impl Feature<PodImages> for PodImagesFeature {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &PodImages,
        ctx: &Context<'_>,
    ) -> Result<Decision<PodImages>, DomainError> {
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

        // No `Result`, and no `onNotGranted` branch: there is no selection here to be ungranted.
        // The team boundary is not something a pod can ask to widen.
        let provenance = allowed_set(ctx.teams(), &config, &ctx.namespace().labels);

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
            Resource::Pod,
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
        ImageWorkspaceSelection, NamespaceName, OnUnknownKey, PlatformConfig, Selector, Team,
        TeamName,
    };

    use super::*;
    use crate::port::testing::NullObserver;
    use crate::subject::ContainerImage;
    use crate::variable::VariableValues;

    fn config() -> ImagePolicyConfig {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ImageGrant {
                allowed: vec![EntryKey::new("internal"), EntryKey::new("devfile-udi")],
                // Deliberately narrower than `allowed` — the gap the Pod half does not close.
                default: vec![EntryKey::new("internal")],
            },
        );
        grants.insert("team-2".to_string(), ImageGrant::default());
        ImagePolicyConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            catalog: ImageCatalog::new(vec![
                Entry {
                    key: EntryKey::new("internal"),
                    patterns: vec!["registry.internal/shared/**".to_string()],
                },
                Entry {
                    key: EntryKey::new("devfile-udi"),
                    patterns: vec!["quay.io/devfile/universal-developer-image:ubi9-*".to_string()],
                },
            ]),
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

    fn subject(name: &str, namespace: &str, images: &[(&str, &str)]) -> PodImages {
        PodImages {
            name: name.to_string(),
            namespace: NamespaceName::new(namespace),
            images: images
                .iter()
                .map(|(container, reference)| ContainerImage::new(*container, *reference))
                .collect(),
            variables: VariableValues::new(),
        }
    }

    fn evaluate(subject: &PodImages, team_label: Option<&str>) -> Decision<PodImages> {
        let feature = PodImagesFeature::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(NullObserver),
        );
        let teams = teams();
        let namespace = NamespaceFacts {
            labels: team_label
                .map(|team| {
                    [("weebo.io/team".to_string(), team.to_string())]
                        .into_iter()
                        .collect()
                })
                .unwrap_or_default(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &namespace, &catalog);
        feature
            .evaluate(subject, &ctx)
            .unwrap_or_else(|err| panic!("evaluate should not error: {err}"))
    }

    #[test]
    fn the_rfcs_own_pod_denial_is_what_lands_on_a_replicaset_event() {
        // A plugin the devfile imported by URI, resolved to an image long after admission.
        let pod = subject(
            "scratch-abc123",
            "user-bob",
            &[("sidecar", "ghcr.io/someone/tool:main")],
        );
        let denial = evaluate(&pod, Some("team-2")).denial.unwrap();
        assert!(denial.contains("container \"sidecar\""), "{denial}");
        assert!(denial.contains("ghcr.io/someone/tool:main"), "{denial}");
        assert!(denial.contains("team team-2"), "{denial}");
    }

    #[test]
    fn the_pod_half_enforces_the_whole_allowed_set_not_the_selection() {
        // The deliberate gap: `devfile-udi` is in team-1's `allowed` but not its `default`, so a
        // workspace whose selection excluded it would be refused at the DevWorkspace layer — and
        // is *not* refused here. That is a policy nicety, not a security boundary.
        let pod = subject(
            "python-web-abc",
            "user-alice",
            &[(
                "dev",
                "quay.io/devfile/universal-developer-image:ubi9-latest",
            )],
        );
        assert_eq!(evaluate(&pod, Some("team-1")).denial, None);
    }

    #[test]
    fn the_team_boundary_is_intact_even_though_the_selection_is_not_enforced() {
        // The other side of the same test: outside `allowed` is still refused.
        let pod = subject(
            "python-web-abc",
            "user-alice",
            &[("db", "docker.io/library/postgres:16")],
        );
        assert!(evaluate(&pod, Some("team-1")).denial.is_some());
    }

    #[test]
    fn every_container_list_is_judged_because_the_subject_carries_them_flattened() {
        // The adapter flattens containers/initContainers/ephemeralContainers into one list;
        // which list a container came from does not change the verdict, and the name is what the
        // message needs.
        let pod = subject(
            "scratch-abc123",
            "user-bob",
            &[
                ("clone", "quay.io/devfile/project-clone:v0.30.0"),
                ("debugger", "ghcr.io/someone/debug:main"),
            ],
        );
        let denial = evaluate(&pod, Some("team-2")).denial.unwrap();
        assert!(denial.contains("\"debugger\""), "{denial}");
    }

    #[test]
    fn a_platform_image_is_permitted_in_a_namespace_whose_team_is_granted_nothing() {
        // team-2's grant is empty. Without the platform set, no workspace pod could ever start.
        let pod = subject(
            "scratch-abc123",
            "user-bob",
            &[("clone", "quay.io/devfile/project-clone:v0.30.0")],
        );
        assert_eq!(evaluate(&pod, Some("team-2")).denial, None);
    }

    #[test]
    fn a_namespace_with_no_team_gets_the_top_level_default() {
        let pod = subject(
            "orphan-abc",
            "user-carol",
            &[("dev", "registry.internal/shared/base:1")],
        );
        let decision = evaluate(&pod, None);
        assert_eq!(decision.denial, None);
        assert_eq!(decision.team, None);
    }

    #[test]
    fn an_unparseable_reference_on_a_pod_is_denied_too() {
        let pod = subject("odd-abc", "user-bob", &[("x", "registry.internal/DEV")]);
        let decision = evaluate(&pod, Some("team-2"));
        assert_eq!(decision.result, "unparseable");
        assert!(decision.denial.is_some());
    }

    #[test]
    fn the_pod_half_never_mutates() {
        let pod = subject(
            "any-abc",
            "user-alice",
            &[("dev", "registry.internal/shared/base:1")],
        );
        assert!(evaluate(&pod, Some("team-1")).mutations.is_empty());
    }

    #[test]
    fn both_halves_report_the_same_feature_id_so_one_mode_gates_both() {
        let config = Arc::new(RwLock::new(Some(config())));
        let pod = PodImagesFeature::new(Arc::clone(&config), Arc::new(NullObserver));
        let workspace = crate::WorkspaceImagesFeature::new(config, Arc::new(NullObserver));
        assert_eq!(pod.id().kebab(), workspace.id().kebab());
        assert_eq!(pod.id().kebab(), FEATURE_ID);
    }
}
