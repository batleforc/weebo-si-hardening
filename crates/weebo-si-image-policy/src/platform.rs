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

/// The compiled-in platform patterns, as text. Parsed once per config load by
/// [`platform_patterns`], never per request.
pub const BUILTIN_PLATFORM_PATTERNS: &[&str] = &[
    "quay.io/devfile/project-clone:*",
    "quay.io/che-incubator/che-code:*",
    "quay.io/che-incubator/configbump:*",
    "quay.io/eclipse/che--traefik:*",
];

/// The platform pattern set for one configuration: the compiled-in list when
/// `platform.builtin` is on, plus `platform.extra`.
///
/// An unparseable `platform.extra` entry is returned as an error rather than skipped. That is
/// the same fail-toward-denying rule the catalogue follows, applied to the one set no grant can
/// withhold: an admin who mistypes their mirror's pattern should be told, not handed a platform
/// set quietly missing the entry they added.
pub fn platform_patterns(config: &PlatformConfig) -> Result<Vec<Pattern>, (String, ParseError)> {
    let builtin = if config.builtin {
        BUILTIN_PLATFORM_PATTERNS
    } else {
        &[][..]
    };
    let mut patterns = Vec::with_capacity(builtin.len() + config.extra.len());
    for raw in builtin
        .iter()
        .map(|raw| (*raw).to_string())
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
        let patterns = platform_patterns(&PlatformConfig::default()).unwrap();
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
    fn the_platform_set_does_not_permit_a_neighbour_in_the_same_registry() {
        // A platform exemption over `quay.io/**` would be an exemption over most of the public
        // internet; these are repository-scoped for that reason.
        let patterns = platform_patterns(&PlatformConfig::default()).unwrap();
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
        assert!(platform_patterns(&config).unwrap().is_empty());
    }

    #[test]
    fn extra_is_how_an_admin_names_their_mirror() {
        let config = PlatformConfig {
            builtin: false,
            extra: vec!["registry.internal/mirror/che/**".to_string()],
        };
        let patterns = platform_patterns(&config).unwrap();
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
        let (raw, err) = platform_patterns(&config).unwrap_err();
        assert_eq!(raw, "*/**");
        assert_eq!(err, ParseError::IllegalHost);
    }
}
