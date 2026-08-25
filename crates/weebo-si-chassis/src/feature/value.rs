use std::fmt;
use std::marker::PhantomData;

use weebo_si_crd::TeamName;

use crate::mutation::Mutation;

/// A feature identifier. Has two spellings, mechanically derived from each other — kebab-case
/// in logs, metrics, annotations and the CLI; camelCase as the CRD field name. There is no
/// third spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FeatureId(&'static str);

impl FeatureId {
    /// Wrap the kebab-case spelling — the canonical one this type stores.
    pub const fn new(kebab: &'static str) -> Self {
        Self(kebab)
    }

    /// The kebab-case spelling.
    pub const fn kebab(&self) -> &'static str {
        self.0
    }

    /// The camelCase spelling, computed from the kebab-case one.
    pub fn camel(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        let mut capitalize_next = false;
        for ch in self.0.chars() {
            if ch == '-' {
                capitalize_next = true;
            } else if capitalize_next {
                out.extend(ch.to_uppercase());
                capitalize_next = false;
            } else {
                out.push(ch);
            }
        }
        out
    }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Chassis-level summary of one decision, for [`crate::port::observer::Observer`]. `result` is
/// a feature-chosen label (e.g. dwoc-pin's `"added"`/`"replaced"`/...), not a fixed chassis
/// enum, so a future feature's outcome vocabulary never has to fit dwoc-pin's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureOutcome {
    /// The namespace the decision was made for.
    pub namespace: weebo_si_crd::NamespaceName,
    /// The Kubernetes kind the decision was about — the `resource` label on
    /// `weebo_si_admission_requests_total`. Read from the subject, never chosen by the observer:
    /// the adapter that hard-coded it is the bug this field exists to make unrepeatable.
    pub resource: &'static str,
    /// The team the resolution attributed the decision to, if any.
    pub team: Option<TeamName>,
    /// The feature-chosen outcome label.
    pub result: &'static str,
    /// Whether the decision, once applied, would change anything.
    pub mutated: bool,
    /// Whether this decision was a refusal rather than a patch.
    pub denied: bool,
}

impl FeatureOutcome {
    /// Summarize a [`Decision`] for [`crate::port::observer::Observer`].
    ///
    /// Takes the *subject*, not a namespace — both record fields come off it, and passing them
    /// separately is an invitation to pair one subject's namespace with another's resource.
    pub fn from_decision<S: crate::feature::Subject>(decision: &Decision<S>, subject: &S) -> Self {
        Self {
            namespace: subject.namespace().clone(),
            resource: subject.resource(),
            team: decision.team.clone(),
            result: decision.result,
            mutated: !decision.mutations.is_empty(),
            denied: decision.denial.is_some(),
        }
    }
}

/// What one `evaluate()` call decided.
///
/// **Deliberately does not carry a feature-specific provenance type.** `Registry<S>` holds
/// `Vec<Box<dyn Feature<S>>>`, so every feature's `Decision<S>` must share this one shape
/// forever — a per-feature "which catalogue key won, at which resolution step" struct here
/// would make the chassis depend on the feature that defines it. `team` is genuinely
/// chassis-generic (every feature has a notion of team); anything more specific a feature wants
/// to explain renders into `note` as a plain string before `evaluate` returns — the audit
/// annotation, the log line and the `team` metric label are computed from `team`+`note`+
/// `result`, still one value with three consumers, just not one *type* shared across crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<S> {
    /// What to change, if the mode applying this decision keeps them.
    pub mutations: Vec<Mutation>,
    /// Set when the decision is a refusal rather than a patch.
    pub denial: Option<String>,
    /// The team the resolution attributed this decision to, if any.
    pub team: Option<TeamName>,
    /// A feature-rendered explanation of how it reached this decision (e.g. which catalogue key
    /// won, at which resolution step) — opaque to the chassis, read by logging/observability.
    pub note: Option<String>,
    /// The feature-chosen outcome label.
    pub result: &'static str,
    _subject: PhantomData<S>,
}

impl<S> Decision<S> {
    /// An allowed decision: apply `mutations` (which may be empty).
    pub fn new(
        mutations: Vec<Mutation>,
        team: Option<TeamName>,
        note: Option<String>,
        result: &'static str,
    ) -> Self {
        Self {
            mutations,
            denial: None,
            team,
            note,
            result,
            _subject: PhantomData,
        }
    }

    /// A denied decision: no mutation, admission refused for `reason`.
    pub fn deny(
        reason: String,
        team: Option<TeamName>,
        note: Option<String>,
        result: &'static str,
    ) -> Self {
        Self {
            mutations: Vec::new(),
            denial: Some(reason),
            team,
            note,
            result,
            _subject: PhantomData,
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
    use super::*;

    #[test]
    fn camel_case_is_mechanically_derived_from_kebab_case() {
        assert_eq!(FeatureId::new("dwoc-pin").camel(), "dwocPin");
        assert_eq!(
            FeatureId::new("image-restriction").camel(),
            "imageRestriction"
        );
        assert_eq!(FeatureId::new("dwoc-pin").kebab(), "dwoc-pin");
    }
}
