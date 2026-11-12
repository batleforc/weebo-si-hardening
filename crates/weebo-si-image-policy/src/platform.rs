//! The compiled-in platform pattern set, and nothing else — RFC 0005's *Contract*.
//!
//! **Nobody writes these down.** They are the images Che and DevWorkspace Operator inject into
//! every workspace pod, they are allowed for every team, and no grant can withhold them — the
//! same non-negotiable position [RFC 0004](../../../docs/rfc/0004-network-profiles.md)'s
//! `baseline` holds, for the same reason: a control that can be configured into breaking the
//! platform it protects is a control nobody will leave on.
//!
//! **This list is explicitly not contract** (RFC 0005's *Stability*). It tracks somebody else's
//! release cadence, so pinning it in a document would guarantee it goes stale, and
//! `platform.extra` exists so that an admin whose registry mirrors these does not need an
//! operator release to say so. `weebo-si-operator images platform` prints it, which is the
//! interface an admin actually has.
//!
//! It is a standing exemption over *image names*, and it is scoped as narrowly as an exemption
//! can be: not an identity exemption and not a namespace exemption. RFC 0005's *Security
//! considerations* closes the identity-based alternative on a fact rather than a preference —
//! DevWorkspace Operator creates a `Deployment`, so the workspace pod's creator is
//! `system:serviceaccount:kube-system:replicaset-controller`, which carries no signal about
//! whether the image is platform or user.

use weebo_si_crd::PlatformConfig;

use crate::pattern::Pattern;
use crate::reference::ParseError;
use crate::rewrite::Rules;

/// The compiled-in platform patterns, as text. Parsed once per config load by
/// [`platform_patterns`], never per request.
pub const BUILTIN_PLATFORM_PATTERNS: &[&str] = &[
    "quay.io/devfile/project-clone:*@*",
    "quay.io/che-incubator/che-code:*@*",
    "quay.io/che-incubator/configbump:*@*",
    "quay.io/eclipse/che--traefik:*@*",
];

/// One compiled-in pattern carried onto a mirror by an `imageRewrite` rule (RFC 0017).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPattern {
    /// The derived pattern's text.
    pub text: String,
    /// The compiled-in pattern it was derived from.
    pub builtin: &'static str,
    /// The rule's normalised `from`.
    pub rule: String,
}

/// The compiled-in patterns, each with its host replaced by the `to` of the rule whose `from` it
/// is — `quay.io/devfile/project-clone:*@*` under `{from: quay.io, to: mirror.io/quay}` gives
/// `mirror.io/quay/devfile/project-clone:*@*`. Only these four are ever derived; `extra` and
/// the catalogue are written by the admin and never are.
///
/// A derived text that does not parse is dropped, never returned: a derivation adds to the
/// platform set and can never shrink it. Since `to` passed `parse_prefix` (no glob, no
/// variable) and only the host is replaced, every derived pattern names one of the four Che
/// images and nothing else.
pub fn derived_platform_patterns(rules: &Rules) -> Vec<DerivedPattern> {
    BUILTIN_PLATFORM_PATTERNS
        .iter()
        .filter_map(|builtin| {
            let (host, rest) = builtin.split_once('/')?;
            let (target, from) = rules.target_for(host)?;
            let text = format!("{target}/{rest}");
            Pattern::parse(&text).ok()?;
            Some(DerivedPattern {
                text,
                builtin,
                rule: from.to_string(),
            })
        })
        .collect()
}

/// The platform pattern set for one configuration: the compiled-in list when
/// `platform.builtin` is on, its rewritten form under `rewrite` (RFC 0017), plus
/// `platform.extra`. `rewrite` is `None` when `imageRewrite` is absent or invalid, which derives
/// nothing.
///
/// An unparseable `platform.extra` entry is returned as an error rather than skipped. That is
/// the same fail-toward-denying rule the catalogue follows, applied to the one set no grant can
/// withhold: an admin who mistypes their mirror's pattern should be told, not handed a platform
/// set quietly missing the entry they added.
pub fn platform_patterns(
    config: &PlatformConfig,
    rewrite: Option<&Rules>,
) -> Result<Vec<Pattern>, (String, ParseError)> {
    let builtin = if config.builtin {
        BUILTIN_PLATFORM_PATTERNS
    } else {
        &[][..]
    };
    let derived = match rewrite {
        Some(rules) if config.builtin => derived_platform_patterns(rules),
        _ => Vec::new(),
    };
    let mut patterns = Vec::with_capacity(builtin.len() + derived.len() + config.extra.len());
    for raw in builtin
        .iter()
        .map(|raw| (*raw).to_string())
        .chain(derived.into_iter().map(|derived| derived.text))
        .chain(config.extra.iter().map(std::string::ToString::to_string))
    {
        match Pattern::parse(&raw) {
            Ok(pattern) => patterns.push(pattern),
            Err(err) => return Err((raw, err)),
        }
    }
    Ok(patterns)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::reference::ImageReference;
    use crate::variable::VariableValues;

    #[test]
    fn every_compiled_in_pattern_parses() {
        // The list is not contract, but "it parses" is: a typo here would silently shrink the
        // platform set to whatever happened to survive, which at `Enforce` is a fleet that
        // stops starting.
        for raw in BUILTIN_PLATFORM_PATTERNS {
            assert!(
                Pattern::parse(raw).is_ok(),
                "compiled-in platform pattern {raw:?} must parse"
            );
        }
    }

    #[test]
    fn the_platform_set_permits_the_images_dwo_actually_injects() {
        let patterns = platform_patterns(&PlatformConfig::default(), None).unwrap();
        let values = VariableValues::new();
        for raw in [
            "quay.io/devfile/project-clone:v0.30.0",
            "quay.io/che-incubator/che-code:latest",
            "quay.io/eclipse/che--traefik:v2.9.10",
        ] {
            let reference = ImageReference::parse(raw).unwrap();
            assert!(
                patterns.iter().any(|p| p.matches(&reference, &values)),
                "{raw:?} should be permitted by the platform set"
            );
        }
    }

    #[test]
    fn the_platform_set_permits_the_digest_pinned_form_of_its_own_repositories_only() {
        // Mirrored and `RELATED_IMAGE_*`-pinned installs inject `repo@sha256:…`, which carries no
        // tag; without the `@*` opt-in every workspace pod would be refused at `Enforce`.
        let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let patterns = platform_patterns(&PlatformConfig::default(), None).unwrap();
        let values = VariableValues::new();
        let allowed = |raw: String| {
            let reference = ImageReference::parse(&raw).unwrap();
            patterns.iter().any(|p| p.matches(&reference, &values))
        };
        for repo in [
            "quay.io/devfile/project-clone",
            "quay.io/che-incubator/che-code",
            "quay.io/che-incubator/configbump",
            "quay.io/eclipse/che--traefik",
        ] {
            assert!(allowed(format!("{repo}@{digest}")), "{repo}");
            assert!(allowed(format!("{repo}:v1@{digest}")), "{repo}");
        }
        // A neighbour, a lookalike host and another port are still refused.
        assert!(!allowed(format!("quay.io/someone/tool@{digest}")));
        assert!(!allowed(format!(
            "quay.io.evil.com/devfile/project-clone@{digest}"
        )));
        assert!(!allowed(format!(
            "quay.io:5000/devfile/project-clone@{digest}"
        )));
        assert!(!allowed(format!(
            "quay.io/devfile/project-clone-evil@{digest}"
        )));
    }

    #[test]
    fn the_platform_set_does_not_permit_a_neighbour_in_the_same_registry() {
        // A platform exemption over `quay.io/**` would be an exemption over most of the public
        // internet; these are repository-scoped for that reason.
        let patterns = platform_patterns(&PlatformConfig::default(), None).unwrap();
        let values = VariableValues::new();
        let reference = ImageReference::parse("quay.io/someone/tool:main").unwrap();
        assert!(!patterns.iter().any(|p| p.matches(&reference, &values)));
    }

    #[test]
    fn builtin_false_empties_the_compiled_in_half() {
        let config = PlatformConfig {
            builtin: false,
            extra: Vec::new(),
        };
        assert!(platform_patterns(&config, None).unwrap().is_empty());
    }

    #[test]
    fn extra_is_how_an_admin_names_their_mirror() {
        let config = PlatformConfig {
            builtin: false,
            extra: vec!["registry.internal/mirror/che/**".to_string()],
        };
        let patterns = platform_patterns(&config, None).unwrap();
        let reference = ImageReference::parse("registry.internal/mirror/che/che-code:1").unwrap();
        assert!(
            patterns
                .iter()
                .any(|p| p.matches(&reference, &VariableValues::new()))
        );
    }

    #[test]
    fn an_unparseable_extra_is_an_error_not_a_silent_skip() {
        let config = PlatformConfig {
            builtin: false,
            extra: vec!["*/**".to_string()],
        };
        let (raw, err) = platform_patterns(&config, None).unwrap_err();
        assert_eq!(raw, "*/**");
        assert_eq!(err, ParseError::IllegalHost);
    }

    fn rules(pairs: &[(&str, &str)]) -> Rules {
        Rules::new(&weebo_si_crd::ImageRewriteConfig {
            mode: weebo_si_crd::FeatureMode::Enforce,
            namespace_selector: None,
            rules: pairs
                .iter()
                .map(|(from, to)| weebo_si_crd::RewriteRule {
                    from: (*from).to_string(),
                    to: (*to).to_string(),
                })
                .collect(),
        })
        .unwrap()
    }

    #[test]
    fn every_compiled_in_host_is_a_plain_host_so_the_text_split_is_the_parsed_one() {
        // The derivation splits the text at its first `/`; that equals the parsed host only
        // while every compiled-in pattern starts with a literal, lowercase, port-less host.
        for raw in BUILTIN_PLATFORM_PATTERNS {
            let (host, _) = raw.split_once('/').unwrap();
            assert_eq!(crate::reference::parse_host(host).unwrap(), host, "{raw}");
        }
    }

    #[test]
    fn a_rule_derives_the_mirrored_form_of_the_four_platform_images_only() {
        let rules = rules(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        let derived = derived_platform_patterns(&rules);
        assert_eq!(derived.len(), BUILTIN_PLATFORM_PATTERNS.len());
        assert_eq!(
            derived[0].text,
            "registry.pkg.weebo.poc/quay/devfile/project-clone:*@*"
        );

        let patterns = platform_patterns(&PlatformConfig::default(), Some(&rules)).unwrap();
        let values = VariableValues::new();
        let allowed = |raw: &str| {
            let reference = ImageReference::parse(raw).unwrap();
            patterns.iter().any(|p| p.matches(&reference, &values))
        };
        // RFC 0017's second invariant: the mirrored platform images and nothing beside them.
        assert!(allowed(
            "registry.pkg.weebo.poc/quay/devfile/project-clone:v0.30.0"
        ));
        assert!(allowed("quay.io/devfile/project-clone:v0.30.0"));
        assert!(!allowed("registry.pkg.weebo.poc/quay/someone/tool:main"));
        assert!(!allowed("registry.pkg.weebo.poc/hub/library/postgres:18"));
    }

    #[test]
    fn nothing_is_derived_without_builtin_or_without_a_matching_rule() {
        let rules = rules(&[("docker.io", "registry.pkg.weebo.poc/hub")]);
        assert!(derived_platform_patterns(&rules).is_empty());
        let config = PlatformConfig {
            builtin: false,
            extra: Vec::new(),
        };
        let quay = super::tests::rules(&[("quay.io", "registry.pkg.weebo.poc/quay")]);
        assert!(platform_patterns(&config, Some(&quay)).unwrap().is_empty());
    }
}
