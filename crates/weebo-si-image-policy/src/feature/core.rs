//! The judging core both enforcement points share.
//!
//! The two halves differ in exactly one step — which entry keys they enforce — and that
//! difference is the *caller's*, expressed by which `resolve` function it calls. Everything
//! after it (bind the variables, build the union, judge each image, report, render the denial)
//! is identical, and it lives here rather than being written twice, so "variables resolve
//! identically at both layers" is a consequence of there being one implementation rather than a
//! promise about two.

use weebo_si_crd::{ImagePolicyConfig, NamespaceName, TeamName};

use crate::port::{ImagePolicyObserver, Resource};
use crate::resolve::{Provenance, effective_patterns, judge};
use crate::subject::ContainerImage;
use crate::variable::{VariableName, VariableValues};
use crate::verdict::{ImageVerdict, PermittedBy, Verdict, escape_reference};

/// The feature identifier both halves report. One `mode` gates both.
pub const FEATURE_ID: &str = "image-policy";

/// What one judging pass concluded.
pub struct Judgement {
    /// Every image's verdict, in the order the subject carried them.
    pub verdicts: Vec<ImageVerdict>,
    /// The first refusal, rendered as the API error message, or `None` if every image passed.
    pub denial: Option<String>,
    /// The `Decision::result` label.
    pub result: &'static str,
}

/// Bind the two built-in variables on top of the adapter-supplied declared ones, reporting each
/// outcome.
///
/// The built-ins are bound **here**, never by an adapter: `{TEAM_NAME}` is not known until the
/// resolution chain has run, and `{NAMESPACE}` is derivable from the subject — so an adapter
/// that supplied either could get it wrong in a way no test of the adapter would catch.
pub fn bind_builtins(
    declared: &VariableValues,
    namespace: &NamespaceName,
    team: Option<&TeamName>,
    config: &ImagePolicyConfig,
    observer: &dyn ImagePolicyObserver,
) -> VariableValues {
    let mut values = declared.clone();
    let team_result = values.bind_team(team);
    let namespace_result = values.bind_namespace(namespace);

    if let Ok(name) = VariableName::new(crate::variable::TEAM_NAME) {
        observer.variable_resolved(&name, team_result);
    }
    if let Ok(name) = VariableName::new(crate::variable::NAMESPACE) {
        observer.variable_resolved(&name, namespace_result);
    }
    // A declared variable the adapter could not resolve is absent from `declared` — reported
    // here as `undefined` so the counter covers every declared name on every request rather
    // than only the ones that happened to work.
    for declared_name in config.variables.keys() {
        let Ok(name) = VariableName::new(declared_name.clone()) else {
            continue;
        };
        if values.get(&name).is_none() {
            observer.variable_resolved(&name, crate::variable::VariableResult::Undefined);
        }
    }
    values
}

/// Judge every image a subject carries against the entries `provenance` resolved.
///
/// Every image is judged, not just up to the first failure: the log line and the metrics are
/// worth more complete, and `DryRun`'s whole job is telling an admin the full list of what would
/// break rather than the first thing that would.
pub fn judge_images(
    config: &ImagePolicyConfig,
    provenance: &Provenance,
    images: &[ContainerImage],
    variables: &VariableValues,
    resource: Resource,
    subject_name: &str,
    observer: &dyn ImagePolicyObserver,
) -> Judgement {
    // An unparseable `platform.extra` leaves the platform set *empty* rather than partially
    // applied — the same fail-toward-denying rule a broken catalogue entry gets. `validate` has
    // already reported it as `Degraded`, so this is the runtime half of a fault an admin is
    // being told about, not a silent one.
    let platform = crate::platform::platform_patterns(&config.platform).unwrap_or_default();
    let union = effective_patterns(config, &provenance.resolved, &platform);

    if !provenance.dropped_not_granted.is_empty() {
        observer.not_granted(
            resource,
            provenance.team.as_ref(),
            provenance.dropped_not_granted.len(),
        );
    }

    let mut verdicts = Vec::with_capacity(images.len());
    let mut denial = None;
    let mut result = "allowed";

    for image in images {
        let verdict = judge(&image.reference, &union, variables);
        let platform_only = matches!(verdict, Verdict::Permitted(PermittedBy::Platform));
        let entry = ImageVerdict {
            container: image.name.clone(),
            reference: image.reference.clone(),
            verdict,
        };
        observer.image_judged(resource, provenance.team.as_ref(), &entry, platform_only);

        if !entry.verdict.is_permitted() && denial.is_none() {
            result = entry.verdict.label();
            denial = Some(render_denial(&entry, provenance, resource, subject_name));
        }
        verdicts.push(entry);
    }

    Judgement {
        verdicts,
        denial,
        result,
    }
}

/// The API error a developer reads.
///
/// The reference goes through [`escape_reference`] — it is attacker-controlled text on its way
/// into a message the apiserver will echo, and RFC 0005 makes escaping it a rule rather than a
/// nicety. The message names the container, the reference, the team and the entries in play, and
/// points at where the permitted patterns are, because a denial that does not say what would
/// have worked is a denial the developer files a ticket about instead of fixing.
fn render_denial(
    verdict: &ImageVerdict,
    provenance: &Provenance,
    resource: Resource,
    subject_name: &str,
) -> String {
    let team = provenance
        .team
        .as_ref()
        .map(|team| format!("team {team}"))
        .unwrap_or_else(|| "no team".to_string());
    let entries: Vec<&str> = provenance
        .resolved
        .iter()
        .map(weebo_si_crd::EntryKey::as_str)
        .collect();
    let reference = escape_reference(&verdict.reference);

    let what = match &verdict.verdict {
        Verdict::Unparseable(err) => format!("is not a parseable image reference ({err})"),
        _ => "is not permitted".to_string(),
    };

    match resource {
        Resource::DevWorkspace => format!(
            "component {:?}: image {reference} {what} ({team}, entries [{}]); permitted patterns \
             are in WeeboSiConfig/cluster .spec.features.imagePolicy.catalog",
            verdict.container,
            entries.join(", ")
        ),
        Resource::Pod => format!(
            "container {:?}: image {reference} {what} ({team}); pod {subject_name} in a workspace \
             namespace may run only images WeeboSiConfig/cluster \
             .spec.features.imagePolicy grants its team",
            verdict.container
        ),
    }
}

/// The `note` a decision carries into the log line — which team, which step, which entries.
/// Opaque to the chassis, read by logging, and deliberately free of any image reference: the
/// reference lives in the denial message and in the adapter's own log line, both of which escape
/// it, and a third unescaped copy is exactly the regression this keeps out.
pub fn render_note(provenance: &Provenance, image_count: usize) -> String {
    let entries: Vec<&str> = provenance
        .resolved
        .iter()
        .map(weebo_si_crd::EntryKey::as_str)
        .collect();
    format!(
        "step={:?} entries=[{}] images={image_count}",
        provenance.step,
        entries.join(",")
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_crd::{
        Entry, EntryKey, FeatureMode, ImageCatalog, ImageNamespaceSelection,
        ImageWorkspaceSelection, OnUnknownKey, PlatformConfig, VariableBinding,
    };

    use super::*;
    use crate::port::testing::RecordingObserver;
    use crate::resolve::ResolutionStep;
    use crate::variable::{NAMESPACE, PathComponent, TEAM_NAME, VariableResult};

    fn config() -> ImagePolicyConfig {
        ImagePolicyConfig {
            mode: FeatureMode::DryRun,
            namespace_selector: None,
            catalog: ImageCatalog::new(vec![Entry {
                key: EntryKey::new("internal"),
                patterns: vec!["registry.internal/shared/**".to_string()],
            }]),
            variables: BTreeMap::new(),
            default: vec![EntryKey::new("internal")],
            grants: BTreeMap::new(),
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
        }
    }

    fn provenance(resolved: &[&str], dropped: &[&str]) -> Provenance {
        Provenance {
            team: Some(TeamName::new("team-1")),
            step: ResolutionStep::GrantDefault,
            resolved: resolved.iter().map(|k| EntryKey::new(*k)).collect(),
            dropped_not_granted: dropped.iter().map(|k| EntryKey::new(*k)).collect(),
        }
    }

    #[test]
    fn the_builtins_are_bound_by_the_feature_not_by_an_adapter() {
        let observer = RecordingObserver::default();
        let values = bind_builtins(
            &VariableValues::new(),
            &NamespaceName::new("user-alice"),
            Some(&TeamName::new("team-1")),
            &config(),
            &observer,
        );
        assert_eq!(
            values
                .get(&VariableName::new(TEAM_NAME).unwrap())
                .map(PathComponent::as_str),
            Some("team-1")
        );
        assert_eq!(
            values
                .get(&VariableName::new(NAMESPACE).unwrap())
                .map(PathComponent::as_str),
            Some("user-alice")
        );
    }

    #[test]
    fn both_builtins_report_their_outcome_every_request() {
        let observer = RecordingObserver::default();
        bind_builtins(
            &VariableValues::new(),
            &NamespaceName::new("user-alice"),
            None,
            &config(),
            &observer,
        );
        let reported: Vec<(String, VariableResult)> = observer
            .variables()
            .into_iter()
            .map(|(name, result)| (name.as_str().to_string(), result))
            .collect();
        assert!(reported.contains(&(TEAM_NAME.to_string(), VariableResult::Undefined)));
        assert!(reported.contains(&(NAMESPACE.to_string(), VariableResult::Resolved)));
    }

    #[test]
    fn a_declared_variable_the_adapter_could_not_resolve_is_reported_undefined() {
        let mut cfg = config();
        cfg.variables.insert(
            "PROJECT".to_string(),
            VariableBinding {
                from_namespace_annotation: "weebo.io/project".to_string(),
            },
        );
        let observer = RecordingObserver::default();
        bind_builtins(
            &VariableValues::new(),
            &NamespaceName::new("user-alice"),
            None,
            &cfg,
            &observer,
        );
        assert!(observer.variables().iter().any(|(name, result)| {
            name.as_str() == "PROJECT" && *result == VariableResult::Undefined
        }));
    }

    #[test]
    fn a_declared_variable_the_adapter_resolved_is_not_reported_undefined() {
        let mut cfg = config();
        cfg.variables.insert(
            "PROJECT".to_string(),
            VariableBinding {
                from_namespace_annotation: "weebo.io/project".to_string(),
            },
        );
        let declared = VariableValues::from_pairs([(
            VariableName::new("PROJECT").unwrap(),
            PathComponent::new("apollo").unwrap(),
        )]);
        let observer = RecordingObserver::default();
        bind_builtins(
            &declared,
            &NamespaceName::new("user-alice"),
            None,
            &cfg,
            &observer,
        );
        assert!(!observer.variables().iter().any(|(name, result)| {
            name.as_str() == "PROJECT" && *result == VariableResult::Undefined
        }));
    }

    #[test]
    fn every_image_is_judged_not_just_up_to_the_first_failure() {
        // DryRun's whole job is telling an admin the full list of what would break.
        let observer = RecordingObserver::default();
        let judgement = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &[
                ContainerImage::new("bad", "ghcr.io/someone/x:1"),
                ContainerImage::new("good", "registry.internal/shared/base:1"),
                ContainerImage::new("worse", "docker.io/library/postgres:16"),
            ],
            &VariableValues::new(),
            Resource::DevWorkspace,
            "data-pipeline",
            &observer,
        );
        assert_eq!(judgement.verdicts.len(), 3);
        assert_eq!(observer.images().len(), 3);
        assert_eq!(judgement.result, "denied");
    }

    #[test]
    fn the_first_refusal_is_the_one_the_message_names() {
        let observer = RecordingObserver::default();
        let judgement = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &[
                ContainerImage::new("tools", "docker.io/library/postgres:16"),
                ContainerImage::new("other", "ghcr.io/someone/x:1"),
            ],
            &VariableValues::new(),
            Resource::DevWorkspace,
            "scratch",
            &observer,
        );
        let denial = judgement.denial.unwrap();
        assert!(denial.contains("\"tools\""), "{denial}");
        assert!(denial.contains("postgres"), "{denial}");
        assert!(!denial.contains("ghcr.io"), "{denial}");
    }

    #[test]
    fn a_platform_only_image_is_flagged_as_such_for_its_own_counter() {
        let observer = RecordingObserver::default();
        judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &[
                ContainerImage::new("clone", "quay.io/devfile/project-clone:v0.30.0"),
                ContainerImage::new("dev", "registry.internal/shared/base:1"),
            ],
            &VariableValues::new(),
            Resource::Pod,
            "pod",
            &observer,
        );
        let flags: Vec<bool> = observer
            .images()
            .into_iter()
            .map(|(_, _, _, platform_only)| platform_only)
            .collect();
        assert_eq!(flags, vec![true, false]);
    }

    #[test]
    fn a_dropped_not_granted_key_is_counted_once_per_decision() {
        let observer = RecordingObserver::default();
        judge_images(
            &config(),
            &provenance(&["internal"], &["dockerhub-library"]),
            &[],
            &VariableValues::new(),
            Resource::DevWorkspace,
            "scratch",
            &observer,
        );
        assert_eq!(observer.not_granted().len(), 1);
        assert_eq!(observer.not_granted()[0].2, 1);
    }

    #[test]
    fn an_unparseable_reference_denies_and_says_so() {
        let observer = RecordingObserver::default();
        let judgement = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &[ContainerImage::new("tools", "registry.internal/DEV")],
            &VariableValues::new(),
            Resource::DevWorkspace,
            "scratch",
            &observer,
        );
        assert_eq!(judgement.result, "unparseable");
        let denial = judgement.denial.unwrap();
        assert!(
            denial.contains("not a parseable image reference"),
            "{denial}"
        );
    }

    #[test]
    fn an_attacker_controlled_reference_is_escaped_before_it_reaches_the_api_error() {
        let observer = RecordingObserver::default();
        let judgement = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &[ContainerImage::new("tools", "evil\u{1b}[31m\"name")],
            &VariableValues::new(),
            Resource::DevWorkspace,
            "scratch",
            &observer,
        );
        let denial = judgement.denial.unwrap();
        assert!(!denial.contains('\u{1b}'), "{denial}");
        assert!(denial.contains("\\u{001b}"), "{denial}");
    }

    #[test]
    fn the_two_resources_render_different_messages_because_their_audiences_differ() {
        let observer = RecordingObserver::default();
        let images = [ContainerImage::new("tools", "ghcr.io/someone/x:1")];
        let workspace = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &images,
            &VariableValues::new(),
            Resource::DevWorkspace,
            "data-pipeline",
            &observer,
        );
        let pod = judge_images(
            &config(),
            &provenance(&["internal"], &[]),
            &images,
            &VariableValues::new(),
            Resource::Pod,
            "scratch-abc123",
            &observer,
        );
        assert!(workspace.denial.unwrap().starts_with("component "));
        assert!(pod.denial.unwrap().starts_with("container "));
    }

    #[test]
    fn the_note_carries_provenance_and_never_an_image_reference() {
        let note = render_note(&provenance(&["internal", "devfile-udi"], &[]), 3);
        assert!(note.contains("entries=[internal,devfile-udi]"), "{note}");
        assert!(note.contains("images=3"), "{note}");
        assert!(!note.contains("registry"), "{note}");
    }
}
