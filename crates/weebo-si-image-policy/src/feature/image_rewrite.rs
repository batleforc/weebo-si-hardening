//! `Feature<RewriteImages>` — RFC 0017's `image-rewrite`, on both mutating routes.
//!
//! A mutating feature on the same chassis as everything else: it returns `SetString` mutations
//! and one `Annotate`, `DryRun` discards them, and it **never denies** — whatever needs
//! refusing, `image-policy` refuses after it, judging the rewritten name (the apiserver runs
//! every mutating webhook before any validating one).
//!
//! Its own `FeatureId`, not `image-policy`'s (RFC 0017, resolved 6): an admin can dry-run the
//! rewrite while `image-policy` enforces, and the reverse.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Mutation};
use weebo_si_crd::IMAGE_REWRITE_ANNOTATION;

use crate::port::ImagePolicyObserver;
use crate::rewrite::{LoadedRewrite, Rewrite};
use crate::subject::RewriteImages;

/// The feature identifier both routes report.
pub const REWRITE_FEATURE_ID: &str = "image-rewrite";

/// `image-rewrite`, for the `DevWorkspace` and the `Pod` route alike.
pub struct ImageRewriteFeature {
    loaded: Arc<RwLock<Option<LoadedRewrite>>>,
    observer: Arc<dyn ImagePolicyObserver>,
}

impl ImageRewriteFeature {
    /// Build it over the config store's live handle, whose rules are validated once per reload.
    pub fn new(
        loaded: Arc<RwLock<Option<LoadedRewrite>>>,
        observer: Arc<dyn ImagePolicyObserver>,
    ) -> Self {
        Self { loaded, observer }
    }
}

impl Feature<RewriteImages> for ImageRewriteFeature {
    fn id(&self) -> FeatureId {
        FeatureId::new(REWRITE_FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &RewriteImages,
        _ctx: &Context<'_>,
    ) -> Result<Decision<RewriteImages>, DomainError> {
        let loaded = self
            .loaded
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(loaded) = loaded.as_ref().filter(|loaded| loaded.config.is_some()) else {
            return Err(DomainError::InvalidConfiguration(
                "image-rewrite evaluated with no spec.features.imageRewrite configured".to_string(),
            ));
        };
        // An invalid set applies nothing; the reconcile loop reports why on the object.
        let Ok(rules) = &loaded.rules else {
            return Ok(Decision::new(Vec::new(), None, None, "invalid"));
        };

        let mut mutations = Vec::new();
        let mut originals = BTreeMap::new();
        for slot in &subject.images {
            let result = match rules.rewrite(&slot.image) {
                Rewrite::Rewritten { reference, .. } => {
                    let to = reference.to_string();
                    self.observer.image_rewritten(
                        subject.resource,
                        &subject.name,
                        "rewritten",
                        Some((&slot.image, &to)),
                    );
                    mutations.push(Mutation::SetString {
                        path: slot.location.clone(),
                        value: to,
                    });
                    originals.insert(slot.name.clone(), slot.image.clone());
                    continue;
                }
                Rewrite::Unmatched => "unmatched",
                Rewrite::Unparseable => "unparseable",
            };
            self.observer
                .image_rewritten(subject.resource, &subject.name, result, None);
        }

        if mutations.is_empty() {
            return Ok(Decision::new(Vec::new(), None, None, "unchanged"));
        }
        if let Some(recorded) = &subject.recorded {
            // Merged per entry, so a later rewrite of one container keeps the others' records.
            let mut merged = recorded.clone();
            merged.extend(originals);
            mutations.push(Mutation::Annotate {
                key: IMAGE_REWRITE_ANNOTATION.to_string(),
                value: to_json(&merged),
            });
        }
        Ok(Decision::new(mutations, None, None, "rewritten"))
    }
}

/// A flat string map as a JSON object. Hand-written because this crate takes no `serde_json`;
/// every string is escaped, so a hostile container name cannot break out of its value.
fn to_json(map: &BTreeMap<String, String>) -> String {
    fn string(out: &mut String, value: &str) {
        out.push('"');
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if c.is_control() => {
                    let _ = write!(out, "\\u{:04x}", u32::from(c));
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }
    let mut out = String::from("{");
    for (index, (key, value)) in map.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        string(&mut out, key);
        out.push(':');
        string(&mut out, value);
    }
    out.push('}');
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{FeatureMode, ImageRewriteConfig, NamespaceName, RewriteRule};

    use super::*;
    use crate::port::Resource;
    use crate::port::testing::RecordingObserver;
    use crate::subject::ImageSlot;

    fn feature(rules: &[(&str, &str)]) -> ImageRewriteFeature {
        feature_observed(rules, Arc::new(RecordingObserver::default()))
    }

    fn feature_observed(
        rules: &[(&str, &str)],
        observer: Arc<RecordingObserver>,
    ) -> ImageRewriteFeature {
        let config = ImageRewriteConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            rules: rules
                .iter()
                .map(|(from, to)| RewriteRule {
                    from: (*from).to_string(),
                    to: (*to).to_string(),
                })
                .collect(),
        };
        ImageRewriteFeature::new(
            Arc::new(RwLock::new(Some(LoadedRewrite::load(None, Some(&config))))),
            observer,
        )
    }

    fn subject(
        images: &[(&str, &str)],
        recorded: Option<BTreeMap<String, String>>,
    ) -> RewriteImages {
        RewriteImages {
            name: "workspace8c1".to_string(),
            namespace: NamespaceName::new("dev-ws-alice"),
            resource: Resource::Pod,
            images: images
                .iter()
                .enumerate()
                .map(|(index, (name, image))| ImageSlot {
                    location: vec![
                        "spec".to_string(),
                        "containers".to_string(),
                        index.to_string(),
                        "image".to_string(),
                    ],
                    name: (*name).to_string(),
                    image: (*image).to_string(),
                })
                .collect(),
            recorded,
        }
    }

    fn evaluate(feature: &ImageRewriteFeature, subject: &RewriteImages) -> Decision<RewriteImages> {
        let facts = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        feature
            .evaluate(subject, &Context::new(&[], &facts, &catalog))
            .unwrap()
    }

    #[test]
    fn a_matching_image_is_set_in_place_and_its_original_recorded() {
        let feature = feature(&[("docker.io", "registry.pkg.weebo.poc/hub")]);
        let decision = evaluate(
            &feature,
            &subject(
                &[("db", "postgres:18"), ("tools", "ghcr.io/x/y:1")],
                Some(BTreeMap::new()),
            ),
        );
        assert_eq!(decision.result, "rewritten");
        assert!(decision.denial.is_none());
        assert_eq!(
            decision.mutations,
            vec![
                Mutation::SetString {
                    path: vec![
                        "spec".to_string(),
                        "containers".to_string(),
                        "0".to_string(),
                        "image".to_string()
                    ],
                    value: "registry.pkg.weebo.poc/hub/library/postgres:18".to_string(),
                },
                Mutation::Annotate {
                    key: IMAGE_REWRITE_ANNOTATION.to_string(),
                    value: r#"{"db":"postgres:18"}"#.to_string(),
                },
            ]
        );
    }

    #[test]
    fn the_annotation_is_merged_with_the_record_already_there() {
        let feature = feature(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        let recorded = BTreeMap::from([("db".to_string(), "postgres:18".to_string())]);
        let decision = evaluate(
            &feature,
            &subject(
                &[("clone", "quay.io/devfile/project-clone:v1")],
                Some(recorded),
            ),
        );
        assert_eq!(
            decision.mutations.last(),
            Some(&Mutation::Annotate {
                key: IMAGE_REWRITE_ANNOTATION.to_string(),
                value: r#"{"clone":"quay.io/devfile/project-clone:v1","db":"postgres:18"}"#
                    .to_string(),
            })
        );
    }

    #[test]
    fn nothing_matching_is_no_mutation_and_never_a_denial() {
        let feature = feature(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        let decision = evaluate(
            &feature,
            &subject(
                &[("db", "postgres:18"), ("bad", "NOT AN IMAGE")],
                Some(BTreeMap::new()),
            ),
        );
        assert_eq!(decision.result, "unchanged");
        assert!(decision.mutations.is_empty());
        assert!(decision.denial.is_none());
    }

    #[test]
    fn an_invalid_rule_set_rewrites_nothing() {
        let feature = feature(&[("quay.io", "registry.pkg.weebo.poc")]);
        let decision = evaluate(&feature, &subject(&[("x", "quay.io/a/b:1")], None));
        assert_eq!(decision.result, "invalid");
        assert!(decision.mutations.is_empty());
    }

    #[test]
    fn a_write_that_cannot_carry_an_annotation_gets_only_the_image() {
        let feature = feature(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        let decision = evaluate(&feature, &subject(&[("debug", "quay.io/a/b:1")], None));
        assert_eq!(decision.mutations.len(), 1);
    }

    #[test]
    fn every_image_is_counted_once_with_its_result() {
        // `port.rs`: a dry run counts exactly what would be rewritten — the feature reports each
        // image whatever its mode, and `admit` alone decides whether the patch is kept.
        let observer = Arc::new(RecordingObserver::default());
        let feature = feature_observed(
            &[("docker.io", "registry.pkg.weebo.poc/hub")],
            Arc::clone(&observer),
        );
        evaluate(
            &feature,
            &subject(
                &[
                    ("db", "postgres:18"),
                    ("tools", "ghcr.io/x/y:1"),
                    ("bad", "NOT AN IMAGE"),
                ],
                None,
            ),
        );
        assert_eq!(
            observer.rewrites(),
            vec![
                (
                    Resource::Pod,
                    "workspace8c1".to_string(),
                    "rewritten",
                    Some((
                        "postgres:18".to_string(),
                        "registry.pkg.weebo.poc/hub/library/postgres:18".to_string()
                    )),
                ),
                (Resource::Pod, "workspace8c1".to_string(), "unmatched", None),
                (
                    Resource::Pod,
                    "workspace8c1".to_string(),
                    "unparseable",
                    None
                ),
            ]
        );
    }

    #[test]
    fn a_hostile_name_cannot_break_out_of_the_annotation_json() {
        let map = BTreeMap::from([("a\"}\\\n".to_string(), "x".to_string())]);
        assert_eq!(to_json(&map), r#"{"a\"}\\\u000a":"x"}"#);
    }
}
