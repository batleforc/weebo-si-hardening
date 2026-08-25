//! The closed variable set, and the value validator — RFC 0005's *Variables in a pattern*.
//!
//! **Substitution happens after parsing, into one slot, never into the string.** This module is
//! the half of that rule the compiler enforces: a [`PathComponent`] is a newtype whose only
//! constructor validates, [`VariableValues`] maps a name to one, and [`crate::pattern`] holds a
//! `Segment::Var(VariableName)` that resolves to a `PathComponent` at match time. There is no
//! function anywhere in this crate taking a pattern and a `&str` and returning a pattern, so the
//! `format!`-the-value-into-the-text version of this feature cannot be written by accident.
//!
//! Why that matters is worth restating, because the alternative is a one-liner: a team named
//! `a/**` interpolated by string would silently widen every pattern using `{TEAM_NAME}` while
//! the CRD still reads `registry.internal/teams/{TEAM_NAME}/**`. The pattern an admin reviews
//! would stop being the pattern that runs, which is the same failure mode
//! [RFC 0004](../../../docs/rfc/0004-network-profiles.md) refuses to accept when it declines to
//! parse network rules.

use std::collections::BTreeMap;
use std::fmt;

use weebo_si_crd::{NamespaceName, TeamName, is_legal_variable_name};

use crate::reference::{ParseError, validate_path_component};

/// The resolved chassis team's name, usable in a host, a path segment, or a tag.
pub const TEAM_NAME: &str = "TEAM_NAME";
/// The subject's namespace, usable in a path segment or a tag — **never in a host**.
pub const NAMESPACE: &str = "NAMESPACE";

/// A pattern variable's name — `[A-Z][A-Z0-9_]*`, validated on construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VariableName(String);

impl VariableName {
    /// Wrap a variable name, or refuse it. The charset is
    /// [`weebo_si_crd::is_legal_variable_name`]'s, shared with the CRD's own validation so the
    /// two can never disagree about what an admin is allowed to declare.
    pub fn new(name: impl Into<String>) -> Result<Self, IllegalVariableName> {
        let name = name.into();
        if is_legal_variable_name(&name) {
            Ok(Self(name))
        } else {
            Err(IllegalVariableName(name))
        }
    }

    /// The wrapped value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name is one of the two the operator resolves itself.
    pub fn is_builtin(&self) -> bool {
        self.0 == TEAM_NAME || self.0 == NAMESPACE
    }

    /// Whether this variable may appear in a pattern's **host**.
    ///
    /// Only `{TEAM_NAME}` may. The host is the trust anchor of the whole allow-list, so a
    /// variable there means the set of registries depends on data resolved per request;
    /// `{TEAM_NAME}`'s value comes from `spec.teams`, which is the admin's own file and is
    /// validated once. There is no comparable statement about a namespace name, and emphatically
    /// none about an annotation.
    pub fn allowed_in_host(&self) -> bool {
        self.0 == TEAM_NAME
    }
}

impl fmt::Display for VariableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A name outside `[A-Z][A-Z0-9_]*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalVariableName(pub String);

impl fmt::Display for IllegalVariableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "variable name {:?} is outside [A-Z][A-Z0-9_]*", self.0)
    }
}

/// A value that is safe to place in exactly one pattern slot: a single legal image path
/// component, with no `/`, no `*`, and no brace.
///
/// **The only constructor validates**, and there is no `From<String>`, no `Deref<Target = str>`
/// and no public field. That is the type-level half of RFC 0005's three substitution rules — a
/// value that did not pass the validator is not representable, so a caller cannot forget to
/// check one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathComponent(String);

impl PathComponent {
    /// Validate a value and wrap it, or refuse it.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ParseError> {
        let value = value.as_ref();
        validate_path_component(value)?;
        Ok(Self(value.to_string()))
    }

    /// The validated value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why one variable's value did not become a [`PathComponent`] — the vocabulary of
/// `weebo_si_image_policy_variable_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariableResult {
    /// The variable had a legal value and is available for substitution.
    Resolved,
    /// The variable has no value in this namespace — no team, or the bound annotation is
    /// absent. A pattern carrying it matches nothing.
    Undefined,
    /// The variable had a value and the value failed the path-component validator. Treated
    /// exactly as `Undefined` for matching; counted separately so the two are distinguishable
    /// on a dashboard.
    Illegal,
}

impl VariableResult {
    /// The metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Undefined => "undefined",
            Self::Illegal => "illegal",
        }
    }
}

/// Every variable that has a value for one subject, ready to substitute.
///
/// **A name absent from this map is undefined, and an undefined variable matches nothing.** It
/// is emphatically *not* an empty segment: treating it as one would collapse
/// `registry.internal/teams/{TEAM_NAME}/**` into `registry.internal/teams/**` and hand every
/// namespace with no team every team's images — the single most damaging way this feature could
/// be implemented, per RFC 0005's *Contract*. The whole reason `get` returns `Option` rather
/// than a defaulted `&str` is to make that mistake require typing something.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariableValues(BTreeMap<VariableName, PathComponent>);

impl VariableValues {
    /// An empty set — every variable undefined.
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Build from already-validated pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (VariableName, PathComponent)>) -> Self {
        Self(pairs.into_iter().collect())
    }

    /// Bind one variable, replacing any previous value.
    pub fn insert(&mut self, name: VariableName, value: PathComponent) -> &mut Self {
        self.0.insert(name, value);
        self
    }

    /// Bind `{TEAM_NAME}`, if the resolution chain matched a team **and** that team's name is a
    /// legal path component. An illegal team name leaves the variable undefined here — the
    /// *loud* half of that case is
    /// [`ImagePolicyConfigViolation::TeamNameNotAPathComponent`](weebo_si_crd::ImagePolicyConfigViolation::TeamNameNotAPathComponent),
    /// raised at reconcile against `spec.teams` where an admin can act on it, rather than per
    /// request where it would be noise.
    pub fn bind_team(&mut self, team: Option<&TeamName>) -> VariableResult {
        let Some(team) = team else {
            return VariableResult::Undefined;
        };
        match PathComponent::new(team.as_str()) {
            Ok(value) => {
                self.0.insert(builtin(TEAM_NAME), value);
                VariableResult::Resolved
            }
            Err(_) => VariableResult::Illegal,
        }
    }

    /// Bind `{NAMESPACE}`. A namespace name is a DNS-1123 label, which is a strict subset of a
    /// legal path component and which the apiserver already enforced — so this is the one value
    /// in this feature that cannot fail for a real object. It is validated anyway rather than
    /// trusted, because "cannot fail" is a property of a caller we do not compile against.
    pub fn bind_namespace(&mut self, namespace: &NamespaceName) -> VariableResult {
        match PathComponent::new(namespace.as_str()) {
            Ok(value) => {
                self.0.insert(builtin(NAMESPACE), value);
                VariableResult::Resolved
            }
            Err(_) => VariableResult::Illegal,
        }
    }

    /// This variable's value, or `None` if it is undefined for this subject.
    pub fn get(&self, name: &VariableName) -> Option<&PathComponent> {
        self.0.get(name)
    }

    /// Every bound name, in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &VariableName> {
        self.0.keys()
    }
}

/// The two built-in names, which are legal by construction — a fallible constructor at every
/// call site for two compile-time constants would be noise, and `unwrap` is denied workspace-
/// wide, so the fallback is the literal itself rather than a panic.
fn builtin(name: &'static str) -> VariableName {
    VariableName::new(name).unwrap_or_else(|_| VariableName(name.to_string()))
}

/// Resolve the variables `spec.variables` **declared**, for one namespace.
///
/// **One function, both enforcement points.** RFC 0005 makes "variables resolve identically at
/// both layers" a property rather than a coincidence, and this is where that is true: the
/// `DevWorkspace` route and the `Pod` route both call it, with the namespace each subject
/// already carries. It lives in the domain rather than in an adapter for the same reason — an
/// adapter-side copy per route is two implementations that can drift, and the drift would be
/// invisible until the two layers disagreed about one namespace.
///
/// It reads only the declared keys, through the chassis' existing
/// [`NamespaceView::annotation`] — this feature adds no cache and no RBAC, which is the property
/// RFC 0005's *Security considerations* leans on.
///
/// Each value is validated before it lands in the map, so an illegal one yields an **absent**
/// entry rather than a present and dangerous one, and **raises no CRD condition**. That
/// asymmetry with an illegal *team* name is deliberate and load-bearing: a value a namespace
/// carries must never be able to drive the status of a cluster-scoped singleton, or on the day
/// the RBAC assumption stops holding, anyone able to annotate a namespace could flip
/// `WeeboSiConfig` to `Degraded` at will, and the condition that reports a broken catalogue
/// would be full of noise anyone can generate. It is counted instead.
pub fn resolve_declared(
    config: &weebo_si_crd::ImagePolicyConfig,
    namespace: &NamespaceName,
    namespace_view: &dyn weebo_si_chassis::port::namespace_view::NamespaceView,
    observer: &dyn crate::port::ImagePolicyObserver,
) -> VariableValues {
    let mut values = VariableValues::new();
    for (raw_name, binding) in &config.variables {
        let Ok(name) = VariableName::new(raw_name.clone()) else {
            // Already reported as `IllegalVariableName` at reconcile.
            continue;
        };
        if name.is_builtin() {
            // Already reported as `ReservedVariableName`; the built-ins are bound by the feature.
            continue;
        }
        let Some(raw_value) =
            namespace_view.annotation(namespace, &binding.from_namespace_annotation)
        else {
            // Undefined. Reported by the feature, which knows every declared name whether or not
            // this function found a value for one.
            continue;
        };

        // Before validation on purpose: a hostile value is a value that *changed*, and the
        // detection control exists to see exactly that.
        observer.variable_value_seen(namespace, &name, &raw_value);

        match PathComponent::new(&raw_value) {
            Ok(value) => {
                values.insert(name.clone(), value);
                observer.variable_resolved(&name, VariableResult::Resolved);
            }
            Err(_) => {
                // Absent rather than present-and-dangerous. `../other-project` and `a/**` land
                // here, and the variable is simply undefined for this namespace — so every
                // pattern using it matches nothing.
                observer.variable_resolved(&name, VariableResult::Illegal);
            }
        }
    }
    values
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
    fn a_variable_name_is_validated_on_construction() {
        assert!(VariableName::new("PROJECT").is_ok());
        assert!(VariableName::new("TEAM_NAME").is_ok());
        assert_eq!(
            VariableName::new("project"),
            Err(IllegalVariableName("project".to_string()))
        );
        assert!(VariableName::new("2PROJECT").is_err());
        assert!(VariableName::new("").is_err());
    }

    #[test]
    fn only_team_name_is_allowed_in_a_host() {
        assert!(VariableName::new(TEAM_NAME).unwrap().allowed_in_host());
        assert!(!VariableName::new(NAMESPACE).unwrap().allowed_in_host());
        assert!(!VariableName::new("PROJECT").unwrap().allowed_in_host());
    }

    #[test]
    fn the_two_builtins_report_themselves_as_builtin() {
        assert!(VariableName::new(TEAM_NAME).unwrap().is_builtin());
        assert!(VariableName::new(NAMESPACE).unwrap().is_builtin());
        assert!(!VariableName::new("PROJECT").unwrap().is_builtin());
    }

    #[test]
    fn a_path_component_refuses_everything_that_could_widen_a_pattern() {
        // The three shapes RFC 0005's *Bypass* table names, plus the brace.
        for hostile in ["a/**", "a/b", "*", "a*", "{X}", "../other-project", "", "A"] {
            assert!(
                PathComponent::new(hostile).is_err(),
                "{hostile:?} must not become a PathComponent — it would widen every pattern \
                 interpolating it"
            );
        }
    }

    #[test]
    fn a_path_component_accepts_what_a_real_team_or_project_is_named() {
        for legal in [
            "team-1",
            "team1",
            "a",
            "some.project",
            "a__b",
            "che--traefik",
        ] {
            assert!(
                PathComponent::new(legal).is_ok(),
                "{legal:?} should be legal"
            );
        }
    }

    #[test]
    fn an_illegal_team_name_leaves_team_name_undefined_rather_than_substituting_it() {
        let mut values = VariableValues::new();
        assert_eq!(
            values.bind_team(Some(&TeamName::new("a/**"))),
            VariableResult::Illegal
        );
        assert_eq!(values.get(&builtin(TEAM_NAME)), None);
    }

    #[test]
    fn a_team_name_with_a_space_is_illegal_not_silently_trimmed() {
        let mut values = VariableValues::new();
        assert_eq!(
            values.bind_team(Some(&TeamName::new("Team One"))),
            VariableResult::Illegal
        );
        assert_eq!(values.get(&builtin(TEAM_NAME)), None);
    }

    #[test]
    fn no_team_leaves_team_name_undefined() {
        let mut values = VariableValues::new();
        assert_eq!(values.bind_team(None), VariableResult::Undefined);
        assert_eq!(values.get(&builtin(TEAM_NAME)), None);
    }

    #[test]
    fn a_namespace_binds_because_dns_1123_is_a_subset_of_a_path_component() {
        let mut values = VariableValues::new();
        assert_eq!(
            values.bind_namespace(&NamespaceName::new("user-alice")),
            VariableResult::Resolved
        );
        assert_eq!(
            values.get(&builtin(NAMESPACE)).map(PathComponent::as_str),
            Some("user-alice")
        );
    }

    #[test]
    fn an_absent_name_is_undefined_rather_than_empty() {
        let values = VariableValues::new();
        assert_eq!(values.get(&VariableName::new("PROJECT").unwrap()), None);
    }

    #[test]
    fn the_variable_result_labels_are_the_metrics_contract() {
        assert_eq!(VariableResult::Resolved.label(), "resolved");
        assert_eq!(VariableResult::Undefined.label(), "undefined");
        assert_eq!(VariableResult::Illegal.label(), "illegal");
    }

    mod resolve_declared {
        use std::collections::{BTreeMap, HashMap};

        use weebo_si_chassis::NamespaceFacts;
        use weebo_si_chassis::port::namespace_view::NamespaceView;
        use weebo_si_crd::{
            Entry, EntryKey, FeatureMode, ImageCatalog, ImageNamespaceSelection, ImagePolicyConfig,
            ImageWorkspaceSelection, OnUnknownKey, PlatformConfig, VariableBinding,
        };

        use super::super::*;
        use crate::port::testing::RecordingObserver;

        /// A `NamespaceView` whose `annotation` actually answers — the chassis' own fake returns
        /// `None` unconditionally, which is exactly the method under test here.
        struct AnnotatingView(HashMap<String, HashMap<String, String>>);

        impl AnnotatingView {
            fn new(pairs: &[(&str, &[(&str, &str)])]) -> Self {
                Self(
                    pairs
                        .iter()
                        .map(|(ns, annotations)| {
                            (
                                (*ns).to_string(),
                                annotations
                                    .iter()
                                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                                    .collect(),
                            )
                        })
                        .collect(),
                )
            }
        }

        impl NamespaceView for AnnotatingView {
            fn facts(&self, _ns: &NamespaceName) -> Option<NamespaceFacts> {
                Some(NamespaceFacts::default())
            }
            fn annotation(&self, ns: &NamespaceName, key: &str) -> Option<String> {
                self.0.get(ns.as_str()).and_then(|a| a.get(key)).cloned()
            }
        }

        fn config(variables: &[(&str, &str)]) -> ImagePolicyConfig {
            ImagePolicyConfig {
                mode: FeatureMode::Enforce,
                namespace_selector: None,
                catalog: ImageCatalog::new(vec![Entry {
                    key: EntryKey::new("internal"),
                    patterns: vec!["registry.internal/**".to_string()],
                }]),
                variables: variables
                    .iter()
                    .map(|(name, annotation)| {
                        (
                            (*name).to_string(),
                            VariableBinding {
                                from_namespace_annotation: (*annotation).to_string(),
                            },
                        )
                    })
                    .collect(),
                default: vec![EntryKey::new("internal")],
                grants: BTreeMap::new(),
                namespace_selection: ImageNamespaceSelection::default(),
                workspace_selection: ImageWorkspaceSelection::default(),
                on_not_granted: OnUnknownKey::default(),
                platform: PlatformConfig::default(),
            }
        }

        #[test]
        fn a_declared_variable_resolves_from_its_bound_annotation() {
            let observer = RecordingObserver::default();
            let view = AnnotatingView::new(&[("user-alice", &[("weebo.io/project", "apollo")])]);
            let values = resolve_declared(
                &config(&[("PROJECT", "weebo.io/project")]),
                &NamespaceName::new("user-alice"),
                &view,
                &observer,
            );
            assert_eq!(
                values
                    .get(&VariableName::new("PROJECT").unwrap())
                    .map(PathComponent::as_str),
                Some("apollo")
            );
        }

        #[test]
        fn an_illegal_value_yields_an_absent_entry_and_raises_no_condition() {
            // The RFC's own example: an annotation valued `../other-project`. It must not widen
            // the pattern, and — unlike an illegal team name — it must not be able to flip a
            // cluster-scoped singleton to Degraded.
            for hostile in ["../other-project", "a/**", "*", "A", "{X}"] {
                let observer = RecordingObserver::default();
                let view = AnnotatingView::new(&[("user-alice", &[("weebo.io/project", hostile)])]);
                let values = resolve_declared(
                    &config(&[("PROJECT", "weebo.io/project")]),
                    &NamespaceName::new("user-alice"),
                    &view,
                    &observer,
                );
                assert_eq!(
                    values.get(&VariableName::new("PROJECT").unwrap()),
                    None,
                    "{hostile:?} must leave PROJECT undefined"
                );
                assert!(
                    observer
                        .variables()
                        .iter()
                        .any(|(_, result)| *result == VariableResult::Illegal),
                    "{hostile:?} should be counted as illegal"
                );
            }
        }

        #[test]
        fn a_hostile_value_is_still_seen_by_the_detection_control() {
            // Counted *before* validation: a hostile value is a value that changed, and that is
            // exactly what the change counter exists to notice.
            let observer = RecordingObserver::default();
            let view = AnnotatingView::new(&[("user-alice", &[("weebo.io/project", "a/**")])]);
            resolve_declared(
                &config(&[("PROJECT", "weebo.io/project")]),
                &NamespaceName::new("user-alice"),
                &view,
                &observer,
            );
            assert_eq!(observer.values().len(), 1);
            assert_eq!(observer.values()[0].2, "a/**");
        }

        #[test]
        fn only_the_declared_keys_are_read_never_the_whole_annotation_bag() {
            let observer = RecordingObserver::default();
            let view = AnnotatingView::new(&[(
                "user-alice",
                &[
                    ("weebo.io/project", "apollo"),
                    ("weebo.io/secret", "something-else"),
                ],
            )]);
            let values = resolve_declared(
                &config(&[("PROJECT", "weebo.io/project")]),
                &NamespaceName::new("user-alice"),
                &view,
                &observer,
            );
            let names: Vec<&str> = values.names().map(VariableName::as_str).collect();
            assert_eq!(names, vec!["PROJECT"]);
        }

        #[test]
        fn a_missing_annotation_leaves_the_variable_undefined() {
            let observer = RecordingObserver::default();
            let view = AnnotatingView::new(&[("user-alice", &[])]);
            let values = resolve_declared(
                &config(&[("PROJECT", "weebo.io/project")]),
                &NamespaceName::new("user-alice"),
                &view,
                &observer,
            );
            assert_eq!(values.get(&VariableName::new("PROJECT").unwrap()), None);
            // Nothing to have "seen" — an absent annotation is not a value that changed.
            assert!(observer.values().is_empty());
        }

        #[test]
        fn a_reserved_or_illegal_declared_name_is_skipped_rather_than_resolved() {
            let observer = RecordingObserver::default();
            let view = AnnotatingView::new(&[(
                "user-alice",
                &[("weebo.io/x", "apollo"), ("weebo.io/y", "gemini")],
            )]);
            let values = resolve_declared(
                &config(&[("TEAM_NAME", "weebo.io/x"), ("lowercase", "weebo.io/y")]),
                &NamespaceName::new("user-alice"),
                &view,
                &observer,
            );
            assert!(values.names().next().is_none());
        }
    }
}
