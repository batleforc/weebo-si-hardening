//! `image-rewrite`'s rules, validated — RFC 0017's *Contract* and *Architecture*.
//!
//! Here rather than in a crate of its own because the rewrite is a pure function over
//! [`crate::reference`]'s parser: a second copy of the normalisation elsewhere would be two
//! normalisations free to disagree, the bypass generator that module exists to prevent.
//!
//! **The invariant: the rewrite is idempotent within one rule set.** No `to` host may equal any
//! `from` host ([`Rules::new`] refuses it, as the CRD's CEL rule does at write), so a rewritten
//! name never matches a rule again and `rewrite(rewrite(x)) = rewrite(x)`.

use std::fmt;

use weebo_si_crd::{ImageRewriteConfig, MAX_REWRITE_RULES, ResolvedImagePolicyConfig};

use crate::pattern::Pattern;
use crate::platform::platform_patterns;
use crate::reference::{ImageReference, ParseError, parse_host, parse_prefix};

/// One validated rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    from: String,
    to_host: String,
    to_path: String,
}

/// A rule set [`Rules::new`] accepted. The only way to get one (or the empty set, `default`), so
/// holding a `Rules` means every `from` is a host, every `to` a host and a path, and no rule
/// chains into another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rules {
    rules: Vec<Rule>,
}

/// Why a rule set was refused. A refused set applies nothing and derives nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// More than [`MAX_REWRITE_RULES`] rules.
    TooMany(usize),
    /// A `from` that is not a registry host.
    From {
        /// The text as written.
        from: String,
        /// Why it did not parse.
        reason: ParseError,
    },
    /// A `to` that is not a registry host followed by a path.
    To {
        /// The text as written.
        to: String,
        /// Why it did not parse.
        reason: ParseError,
    },
    /// Two rules with the same normalised `from`.
    DuplicateFrom(String),
    /// A `to` whose host is a rule's `from` — a chain or a loop.
    ToIsFrom {
        /// The `to` as written.
        to: String,
    },
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany(count) => write!(
                f,
                "imageRewrite: {count} rules, at most {MAX_REWRITE_RULES} are allowed"
            ),
            Self::From { from, reason } => {
                write!(
                    f,
                    "imageRewrite: from {from:?} is not a registry host ({reason})"
                )
            }
            Self::To { to, reason } => write!(
                f,
                "imageRewrite: to {to:?} is not a registry host followed by a path ({reason})"
            ),
            Self::DuplicateFrom(from) => {
                write!(f, "imageRewrite: two rules share the from {from:?}")
            }
            Self::ToIsFrom { to } => write!(
                f,
                "imageRewrite: to {to:?} points at another rule's from (chain or loop)"
            ),
        }
    }
}

/// What one image became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rewrite {
    /// A rule matched; the image is now `reference`.
    Rewritten {
        /// The rewritten reference.
        reference: ImageReference,
        /// The matching rule's normalised `from`.
        rule: String,
    },
    /// No rule matched; the image is left as written.
    Unmatched,
    /// The image does not parse, or would not once rewritten; it is left as written and
    /// `image-policy` judges it.
    Unparseable,
}

impl Rules {
    /// Validate a configuration's rules: all of them, or none (every error is returned).
    pub fn new(config: &ImageRewriteConfig) -> Result<Self, Vec<RuleError>> {
        let mut errors = Vec::new();
        if config.rules.len() > MAX_REWRITE_RULES {
            errors.push(RuleError::TooMany(config.rules.len()));
        }
        let mut rules: Vec<Rule> = Vec::with_capacity(config.rules.len());
        for raw in &config.rules {
            let from = parse_host(&raw.from).map_err(|reason| RuleError::From {
                from: raw.from.clone(),
                reason,
            });
            let to = parse_prefix(&raw.to).map_err(|reason| RuleError::To {
                to: raw.to.clone(),
                reason,
            });
            match (from, to) {
                (Ok(from), Ok((to_host, to_path))) => {
                    if rules.iter().any(|rule| rule.from == from) {
                        errors.push(RuleError::DuplicateFrom(from));
                    } else {
                        rules.push(Rule {
                            from,
                            to_host,
                            to_path,
                        });
                    }
                }
                (from, to) => errors.extend(from.err().into_iter().chain(to.err())),
            }
        }
        for rule in &rules {
            if rules.iter().any(|other| other.from == rule.to_host) {
                errors.push(RuleError::ToIsFrom {
                    to: format!("{}/{}", rule.to_host, rule.to_path),
                });
            }
        }
        if errors.is_empty() {
            Ok(Self { rules })
        } else {
            Err(errors)
        }
    }

    /// Whether the set rewrites nothing.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Each rule as `(from, to)`, both normalised — for the status warnings.
    pub fn iter(&self) -> impl Iterator<Item = (&str, String)> {
        self.rules.iter().map(|rule| {
            (
                rule.from.as_str(),
                format!("{}/{}", rule.to_host, rule.to_path),
            )
        })
    }

    /// Rewrite one image as written. Matching is on the host after normalisation, port included:
    /// `postgres` matches `from: docker.io`, `quay.io:443/x` does not match `from: quay.io`.
    pub fn rewrite(&self, raw: &str) -> Rewrite {
        let Ok(reference) = ImageReference::parse(raw) else {
            return Rewrite::Unparseable;
        };
        let Some(rule) = self.rule_for(reference.host()) else {
            return Rewrite::Unmatched;
        };
        match reference.with_prefix(&rule.to_host, &rule.to_path) {
            Ok(reference) => Rewrite::Rewritten {
                reference,
                rule: rule.from.clone(),
            },
            Err(_) => Rewrite::Unparseable,
        }
    }

    /// The `host/path` prefix images of `host` are rewritten to, and the rule's `from`.
    pub fn target_for(&self, host: &str) -> Option<(String, &str)> {
        self.rule_for(host).map(|rule| {
            (
                format!("{}/{}", rule.to_host, rule.to_path),
                rule.from.as_str(),
            )
        })
    }

    fn rule_for(&self, host: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.from == host)
    }
}

/// What one config reload derives for RFC 0017, built once by the config store so no admission
/// re-validates the rules or re-parses the platform set (*Architecture*, *Capacity*).
#[derive(Debug, Clone)]
pub struct LoadedRewrite {
    /// `spec.features.imageRewrite` as written; `None` when absent.
    pub config: Option<ImageRewriteConfig>,
    /// Its rules, validated: empty when the block is absent, every error when refused.
    pub rules: Result<Rules, Vec<RuleError>>,
    /// `imagePolicy`'s platform set, derived through `rules` when they are valid. Empty when
    /// `imagePolicy` is absent or its `extra` does not parse — the fail-toward-denying rule
    /// `judge_images` has always applied.
    pub platform: Vec<Pattern>,
}

impl LoadedRewrite {
    /// Derive everything from one reload's two blocks.
    pub fn load(
        policy: Option<&ResolvedImagePolicyConfig>,
        rewrite: Option<&ImageRewriteConfig>,
    ) -> Self {
        let rules = rewrite.map_or_else(|| Ok(Rules::default()), Rules::new);
        let platform = policy
            .and_then(|policy| platform_patterns(&policy.platform, rules.as_ref().ok()).ok())
            .unwrap_or_default();
        Self {
            config: rewrite.cloned(),
            rules,
            platform,
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
    use weebo_si_crd::{
        FeatureMode, ImageCatalog, ImageNamespaceSelection, ImagePolicyConfig,
        ImageWorkspaceSelection, OnUnknownKey, PlatformConfig, Resolved, RewriteRule,
    };

    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn config(rules: &[(&str, &str)]) -> ImageRewriteConfig {
        ImageRewriteConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            rules: rules
                .iter()
                .map(|(from, to)| RewriteRule {
                    from: (*from).to_string(),
                    to: (*to).to_string(),
                })
                .collect(),
        }
    }

    fn standard() -> Rules {
        Rules::new(&config(&[
            ("docker.io", "registry.pkg.weebo.poc/hub"),
            ("quay.io", "registry.pkg.weebo.poc/quay"),
        ]))
        .unwrap()
    }

    fn rewritten(rules: &Rules, raw: &str) -> String {
        match rules.rewrite(raw) {
            Rewrite::Rewritten { reference, .. } => reference.to_string(),
            other => panic!("{raw:?} should be rewritten, got {other:?}"),
        }
    }

    #[test]
    fn the_host_is_matched_after_normalisation() {
        let rules = standard();
        for raw in [
            "postgres:18",
            "docker.io/library/postgres:18",
            "DOCKER.IO./postgres:18",
        ] {
            assert_eq!(
                rewritten(&rules, raw),
                "registry.pkg.weebo.poc/hub/library/postgres:18"
            );
        }
        assert_eq!(
            rewritten(&rules, "postgres"),
            "registry.pkg.weebo.poc/hub/library/postgres:latest"
        );
    }

    #[test]
    fn a_lookalike_host_or_another_port_is_left_alone() {
        // RFC 0017, T1: the match is equality on the normalised host, port included.
        let rules = standard();
        for raw in [
            "quay.io.evil.com/devfile/project-clone:v1",
            "quay.io:443/devfile/project-clone:v1",
            "ghcr.io/batleforc/tool:v1",
            "registry.pkg.weebo.poc/quay/devfile/project-clone:v1",
        ] {
            assert_eq!(rules.rewrite(raw), Rewrite::Unmatched, "{raw}");
        }
    }

    #[test]
    fn the_digest_survives_and_the_tag_beside_it_is_dropped() {
        // RFC 0017's third invariant: a digest-pinned image stays the same bytes.
        let rules = standard();
        assert_eq!(
            rewritten(
                &rules,
                &format!("quay.io/devfile/project-clone:v1@{DIGEST}")
            ),
            format!("registry.pkg.weebo.poc/quay/devfile/project-clone@{DIGEST}")
        );
    }

    #[test]
    fn the_rewrite_is_idempotent() {
        let rules = standard();
        let once = rewritten(&rules, "quay.io/che-incubator/che-code:latest");
        assert_eq!(rules.rewrite(&once), Rewrite::Unmatched);
    }

    #[test]
    fn an_unparseable_image_is_left_to_image_policy() {
        let rules = standard();
        assert_eq!(rules.rewrite("Not An Image"), Rewrite::Unparseable);
        // A rewrite that would cross the length cap is not applied.
        let long = format!("quay.io/{}:v1", "a".repeat(490));
        assert_eq!(rules.rewrite(&long), Rewrite::Unparseable);
    }

    #[test]
    fn a_chain_a_duplicate_or_a_bad_rule_refuses_the_whole_set() {
        // RFC 0017, T3/T9/T10: an invalid set applies nothing.
        let cases: &[&[(&str, &str)]] = &[
            &[("quay.io", "mirror.io/quay"), ("mirror.io", "other.io/x")],
            &[("quay.io", "quay.io/mirror")],
            &[("quay.io", "mirror.io/a"), ("QUAY.IO", "mirror.io/b")],
            &[("quay.io", "mirror.io")],
            &[("quay.io", "mirror.io/*")],
            &[("quay.io", "mirror.io/{TEAM_NAME}")],
            &[("quay.io/devfile", "mirror.io/quay")],
            &[("quay.io", "mirror.io/quay"), ("", "mirror.io/x")],
            &[("quay.io", "harbor/quay")],
            &[("quay", "mirror.io/quay")],
        ];
        for rules in cases {
            assert!(Rules::new(&config(rules)).is_err(), "{rules:?}");
        }
        let too_many: Vec<(String, String)> = (0..=MAX_REWRITE_RULES)
            .map(|i| (format!("r{i}.io"), format!("mirror.io/r{i}")))
            .collect();
        let too_many: Vec<(&str, &str)> = too_many
            .iter()
            .map(|(from, to)| (from.as_str(), to.as_str()))
            .collect();
        assert!(matches!(
            Rules::new(&config(&too_many)).unwrap_err()[0],
            RuleError::TooMany(_)
        ));
    }

    #[test]
    fn a_chain_is_reported_on_its_own_rule_after_a_refused_one() {
        let errors = Rules::new(&config(&[
            ("-bad", "a.io/x"),
            ("x.io", "y.io/p"),
            ("y.io", "z.io/q"),
        ]))
        .unwrap_err();
        assert!(errors.contains(&RuleError::ToIsFrom {
            to: "y.io/p".to_string()
        }));
    }

    #[test]
    fn a_reload_derives_the_platform_set_once_and_an_invalid_set_derives_nothing() {
        let policy = Resolved::without_teams(ImagePolicyConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            catalog: ImageCatalog::new(Vec::new()),
            variables: Default::default(),
            default: Vec::new(),
            namespace_selection: ImageNamespaceSelection::default(),
            workspace_selection: ImageWorkspaceSelection::default(),
            on_not_granted: OnUnknownKey::default(),
            platform: PlatformConfig::default(),
        });
        let builtin = LoadedRewrite::load(Some(&policy), None).platform.len();
        let valid = config(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        assert!(
            LoadedRewrite::load(Some(&policy), Some(&valid))
                .platform
                .len()
                > builtin
        );
        let invalid = config(&[("quay.io", "registry.pkg.weebo.poc")]);
        let loaded = LoadedRewrite::load(Some(&policy), Some(&invalid));
        assert!(loaded.rules.is_err());
        assert_eq!(loaded.platform.len(), builtin);
        assert!(LoadedRewrite::load(None, Some(&valid)).platform.is_empty());
    }

    #[test]
    fn an_empty_set_is_valid_and_rewrites_nothing() {
        let rules = Rules::new(&config(&[])).unwrap();
        assert!(rules.is_empty());
        assert_eq!(rules.rewrite("postgres"), Rewrite::Unmatched);
    }
}
