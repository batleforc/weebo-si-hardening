//! The admission-side half of `network-profiles`: what a `DevWorkspace` `CREATE` is refused for.
//!
//! Two refusals, both of which RFC 0004 states in *Design* and neither of which a
//! [`ReconcileFeature`](weebo_si_chassis::ReconcileFeature) can make — a controller watches
//! objects that already exist, and by then the pod is running:
//!
//! - **A namespace with no baseline yet.** Profile objects are purely additive; without the
//!   baseline underneath them they grant access rather than restrict it. A workspace that starts
//!   in the window before its namespace's baseline reconciles starts *unprotected*, and the
//!   fail-closed answer is to hold it back rather than let it run and tighten later.
//! - **`onNotGranted: Deny`.** The RFC's own words: `Deny` "refuses the DevWorkspace at admission
//!   with a message naming the ungranted key." This is where that sentence becomes true.
//!
//! Fits the existing `Feature<S>` trait, like `policy-guard` and for the same reason: an
//! allow/deny verdict with no mutation is exactly what `Decision` already models. It reports the
//! `network-profiles` [`FeatureId`], not one of its own — it is not a separate feature with a
//! separate flag, it is the same feature's admission surface, so `mode: DryRun` records what it
//! *would* refuse without refusing it, and `mode: Off` skips it entirely. That is the chassis's
//! own gate doing the work, with nothing added here.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Subject};
use weebo_si_crd::{NamespaceName, ProfileKey, ResolvedNetworkProfilesConfig};

use crate::exclusion::is_excluded_namespace;
use crate::port::BaselineView;
use crate::resolve;

/// Which write to a `DevWorkspace` is under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceOperation {
    /// A new workspace.
    Create,
    /// An existing one, changed.
    Update,
}

/// A `DevWorkspace` write under admission, in domain vocabulary. Distinct from
/// [`crate::feature::network_profiles::Workspace`] (the reconcile subject): that one carries a
/// `workspace_id`, which DevWorkspace Operator has not assigned yet at `CREATE` time — the exact
/// reason this check has to happen at admission and cannot be a reconcile pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAdmission {
    /// The workspace's name, for the denial message.
    pub name: String,
    /// The namespace it is being created in.
    pub namespace: NamespaceName,
    /// Which write this is.
    pub operation: WorkspaceOperation,
    /// The raw value of `workspaceSelection.attribute`, if the DevWorkspace carries it.
    pub attribute: Option<String>,
    /// The raw value of `namespaceSelection.annotation`, if the namespace carries it.
    pub namespace_annotation: Option<String>,
    /// The raw value of `namespaceGrant.annotation`, if the namespace carries it (RFC 0021).
    pub namespace_grant: Option<String>,
}

impl Subject for WorkspaceAdmission {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}

/// `network-profiles`' admission surface. Holds the same live configuration `Arc` as
/// [`crate::NetworkProfiles`] so the two halves of one feature can never disagree about the
/// catalogue, the grants or `onNotGranted`.
pub struct WorkspaceGate {
    config: Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
    baselines: Arc<dyn BaselineView>,
    operator_namespace: NamespaceName,
}

impl WorkspaceGate {
    /// Build the gate. `operator_namespace` feeds the structural exclusion — see
    /// [`crate::exclusion`] for why the webhook has to apply the identical rule the controller
    /// does.
    pub fn new(
        config: Arc<RwLock<Option<ResolvedNetworkProfilesConfig>>>,
        baselines: Arc<dyn BaselineView>,
        operator_namespace: NamespaceName,
    ) -> Self {
        Self {
            config,
            baselines,
            operator_namespace,
        }
    }
}

impl Feature<WorkspaceAdmission> for WorkspaceGate {
    fn id(&self) -> FeatureId {
        FeatureId::new("network-profiles")
    }

    fn evaluate(
        &self,
        subject: &WorkspaceAdmission,
        ctx: &Context<'_>,
    ) -> Result<Decision<WorkspaceAdmission>, DomainError> {
        let excluded = is_excluded_namespace(&subject.namespace, &self.operator_namespace);
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        // Computed before the CREATE-only check, and refusing nothing on its own (RFC 0021): a
        // restricted key the namespace does not grant is dropped by the reconcile, and the
        // warning tells a `kubectl` user why at the write that asked for it.
        let resolved = match (&config, excluded) {
            (Some(config), false) => Some(resolve::resolve(
                ctx.teams(),
                config,
                &ctx.namespace().labels,
                subject.namespace_annotation.as_deref(),
                subject.namespace_grant.as_deref(),
                subject.attribute.as_deref(),
            )),
            _ => None,
        };
        let grant_annotation = config
            .as_ref()
            .map(|config| config.namespace_grant.annotation.as_str())
            .unwrap_or_default();
        let refused: &[ProfileKey] = match &resolved {
            Some(Ok(provenance)) => &provenance.restricted_refused,
            Some(Err(not_granted)) => &not_granted.restricted_refused,
            None => &[],
        };
        let warnings: Vec<String> = if refused.is_empty() {
            Vec::new()
        } else {
            // Under `Deny` the reconcile writes nothing beyond the baseline for a refused request.
            let effect = if matches!(resolved, Some(Err(_))) {
                "onNotGranted=Deny: no profile beyond the baseline is applied"
            } else {
                "the workspace does not get them"
            };
            vec![format!(
                "network profile(s) [{}] {}; {effect}",
                join(refused),
                restricted_clause(&subject.namespace, grant_annotation)
            )]
        };

        // An UPDATE to a workspace that already exists is past the point this check protects:
        // its pods are running, and refusing the update neither un-starts them nor produces the
        // missing baseline. It would only wedge a workspace nobody can now edit.
        if subject.operation != WorkspaceOperation::Create {
            return Ok(
                Decision::new(Vec::new(), None, None, "not_a_create").with_warnings(warnings)
            );
        }

        if excluded {
            return Ok(Decision::new(Vec::new(), None, None, "namespace_excluded"));
        }

        let resolved = resolved.ok_or_else(|| {
            DomainError::InvalidConfiguration(
                "network-profiles evaluated with no spec.features.networkProfiles configured"
                    .to_string(),
            )
        })?;

        // `resolve` only ever returns `Err` under `onNotGranted: Deny` — under `Default` an
        // ungranted key is dropped, which is a reconcile-side outcome and not something to
        // refuse a workspace over.
        if let Err(not_granted) = resolved {
            let team = not_granted
                .team
                .as_ref()
                .map(|team| team.as_str().to_string())
                .unwrap_or_else(|| "<none>".to_string());
            if not_granted.restricted() {
                return Ok(Decision::deny(
                    format!(
                        "workspace {} requests network profile(s) [{}], which {}",
                        subject.name,
                        join(&not_granted.requested),
                        restricted_clause(&subject.namespace, grant_annotation)
                    ),
                    not_granted.team,
                    Some("restricted".to_string()),
                    "denied_restricted",
                ));
            }
            // Only the keys outside the team grant: the restricted ones get their own clause.
            let outside_team: Vec<ProfileKey> = not_granted
                .requested
                .iter()
                .filter(|key| !not_granted.restricted_refused.contains(key))
                .cloned()
                .collect();
            let mut reason = format!(
                "workspace {} requests network profile(s) [{}], which team {team} is not granted",
                subject.name,
                join(&outside_team)
            );
            if !not_granted.restricted_refused.is_empty() {
                reason.push_str(&format!(
                    "; [{}] {}",
                    join(&not_granted.restricted_refused),
                    restricted_clause(&subject.namespace, grant_annotation)
                ));
            }
            return Ok(Decision::deny(
                reason,
                not_granted.team,
                Some("not_granted".to_string()),
                "denied_not_granted",
            ));
        }

        if !self.baselines.has_baseline(&subject.namespace) {
            return Ok(Decision::deny(
                format!(
                    "namespace {} carries no weebo-si-operator network policy baseline yet; \
                     workspace {} would start unprotected",
                    subject.namespace, subject.name
                ),
                None,
                Some("no_baseline".to_string()),
                "denied_no_baseline",
            ));
        }

        Ok(Decision::new(Vec::new(), None, None, "allowed").with_warnings(warnings))
    }
}

fn join(keys: &[ProfileKey]) -> String {
    keys.iter()
        .map(ProfileKey::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// Why a restricted key is refused, in the RFC 0021 mock's words.
fn restricted_clause(namespace: &NamespaceName, annotation: &str) -> String {
    if annotation.is_empty() {
        "are restricted: restricted grants are disabled (namespaceGrant.annotation is empty)"
            .to_string()
    } else {
        format!(
            "are restricted: namespace {namespace} does not grant them (annotation {annotation})"
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;

    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        Backend, Enforcement, FeatureMode, NetworkProfilesConfig, OnNotGranted, Profile,
        ProfileCatalog, ProfileGrant, ProfileKey, ProfileNamespaceSelection, Resolved, Selector,
        Team, TeamName, TemplateRef, Variant, WorkspaceSelection,
    };

    use super::*;
    use crate::port::testing::FakeBaselineView;

    const WORKSPACE_NS: &str = "user-alice";

    fn profile(key: &str) -> Profile {
        Profile {
            key: ProfileKey::new(key),
            variants: vec![Variant {
                backend: Backend::NetworkPolicy,
                template_ref: TemplateRef {
                    name: format!("weebo-{key}"),
                    namespace: NamespaceName::new("weebo-si-hardening"),
                },
            }],
            restricted: false,
        }
    }

    fn config(on_not_granted: OnNotGranted) -> ResolvedNetworkProfilesConfig {
        let mut grants = BTreeMap::new();
        grants.insert(
            "team-1".to_string(),
            ProfileGrant {
                allowed: vec![ProfileKey::new("git"), ProfileKey::new("internet")],
                default: vec![ProfileKey::new("git")],
            },
        );
        Resolved::without_teams(NetworkProfilesConfig {
            mode: FeatureMode::Enforce,
            namespace_selector: None,
            catalog: ProfileCatalog::new(vec![
                profile("base"),
                profile("git"),
                profile("vault"),
                Profile {
                    restricted: true,
                    ..profile("internet")
                },
            ]),
            baseline: ProfileKey::new("base"),
            namespace_selection: ProfileNamespaceSelection::default(),
            workspace_selection: WorkspaceSelection::default(),
            on_not_granted,
            enforcement: Enforcement::default(),
            namespace_grant: Default::default(),
        })
        .with_grants(grants)
    }

    fn gate(on_not_granted: OnNotGranted, namespaces_with_baseline: &[&str]) -> WorkspaceGate {
        WorkspaceGate::new(
            Arc::new(RwLock::new(Some(config(on_not_granted)))),
            Arc::new(FakeBaselineView::new(
                namespaces_with_baseline
                    .iter()
                    .map(|ns| NamespaceName::new(*ns)),
            )),
            NamespaceName::new("weebo-si-hardening"),
        )
    }

    fn teams() -> Vec<Team> {
        vec![Team {
            name: TeamName::new("team-1"),
            namespace_selector: Selector {
                match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
                match_expressions: Vec::new(),
            },
        }]
    }

    fn namespace_facts() -> NamespaceFacts {
        let mut facts = NamespaceFacts::default();
        facts
            .labels
            .insert("weebo.io/team".to_string(), "team-1".to_string());
        facts
    }

    fn workspace(namespace: &str, attribute: Option<&str>) -> WorkspaceAdmission {
        WorkspaceAdmission {
            name: "data-pipeline".to_string(),
            namespace: NamespaceName::new(namespace),
            operation: WorkspaceOperation::Create,
            attribute: attribute.map(str::to_string),
            namespace_annotation: None,
            namespace_grant: None,
        }
    }

    fn evaluate(
        gate: &WorkspaceGate,
        subject: &WorkspaceAdmission,
    ) -> Decision<WorkspaceAdmission> {
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &facts, &catalog);
        gate.evaluate(subject, &ctx).unwrap()
    }

    #[test]
    fn a_create_in_a_namespace_with_no_baseline_is_denied() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[]),
            &workspace(WORKSPACE_NS, None),
        );
        let denial = decision
            .denial
            .expect("a namespace with no baseline is denied");
        assert!(denial.contains("no weebo-si-operator network policy baseline yet"));
    }

    #[test]
    fn a_create_in_a_namespace_that_already_has_its_baseline_is_allowed() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, None),
        );
        assert_eq!(decision.denial, None);
        assert!(decision.mutations.is_empty(), "this gate never mutates");
    }

    #[test]
    fn an_update_is_never_refused_even_with_no_baseline() {
        let mut subject = workspace(WORKSPACE_NS, None);
        subject.operation = WorkspaceOperation::Update;
        let decision = evaluate(&gate(OnNotGranted::Default, &[]), &subject);
        assert_eq!(
            decision.denial, None,
            "an UPDATE cannot un-start a running workspace; refusing it only wedges it"
        );
    }

    #[test]
    fn the_operators_own_namespace_is_never_refused_for_a_baseline_it_will_never_have() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[]),
            &workspace("weebo-si-hardening", None),
        );
        assert_eq!(decision.denial, None);
    }

    #[test]
    fn ches_namespace_is_never_refused_either() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[]),
            &workspace("eclipse-che", None),
        );
        assert_eq!(decision.denial, None);
    }

    #[test]
    fn an_ungranted_key_under_deny_refuses_the_workspace_and_names_the_key() {
        let decision = evaluate(
            &gate(OnNotGranted::Deny, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("vault")),
        );
        let denial = decision
            .denial
            .expect("onNotGranted: Deny must refuse the DevWorkspace");
        assert!(
            denial.contains("vault"),
            "the message names the ungranted key: {denial}"
        );
        assert!(denial.contains("team-1"));
    }

    #[test]
    fn an_ungranted_key_under_default_is_not_an_admission_failure() {
        // Under `Default` the reconcile side silently falls back to the team default — refusing
        // the workspace here would make `Default` and `Deny` the same setting.
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("vault")),
        );
        assert_eq!(decision.denial, None);
    }

    #[test]
    fn a_granted_key_under_deny_is_allowed() {
        let decision = evaluate(
            &gate(OnNotGranted::Deny, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("git")),
        );
        assert_eq!(decision.denial, None);
    }

    #[test]
    fn the_ungranted_refusal_wins_over_the_missing_baseline_one() {
        // Both are true here. The ungranted message names something the *author* can fix; the
        // baseline one names something only the operator can, and it resolves on its own within
        // a reconcile period. Reporting the actionable one first is the point of the ordering.
        let decision = evaluate(
            &gate(OnNotGranted::Deny, &[]),
            &workspace(WORKSPACE_NS, Some("vault")),
        );
        let denial = decision.denial.expect("denied");
        assert!(denial.contains("vault"), "{denial}");
    }

    #[test]
    fn the_gate_reports_the_network_profiles_id_not_one_of_its_own() {
        // Load-bearing: it is what makes `networkProfiles.mode` gate this check too, so
        // `DryRun` records a refusal without making it, and `Off` skips it — without a second
        // flag anyone could set inconsistently with the first.
        assert_eq!(
            gate(OnNotGranted::Default, &[]).id(),
            FeatureId::new("network-profiles")
        );
    }

    #[test]
    fn no_configuration_at_all_is_a_domain_error_not_a_silent_allow() {
        let gate = WorkspaceGate::new(
            Arc::new(RwLock::new(None)),
            Arc::new(FakeBaselineView::new(std::iter::empty())),
            NamespaceName::new("weebo-si-hardening"),
        );
        let teams = teams();
        let facts = namespace_facts();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &facts, &catalog);
        assert!(matches!(
            gate.evaluate(&workspace(WORKSPACE_NS, None), &ctx),
            Err(DomainError::InvalidConfiguration(_))
        ));
    }

    /// The RFC 0021 *Mocks* refusal under `onNotGranted: Deny`.
    #[test]
    fn a_restricted_key_under_deny_is_refused_as_restricted() {
        let decision = evaluate(
            &gate(OnNotGranted::Deny, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("internet")),
        );
        assert_eq!(
            decision.denial.as_deref(),
            Some(
                "workspace data-pipeline requests network profile(s) [internet], which are \
                 restricted: namespace user-alice does not grant them (annotation \
                 hardening.weebo.io/network-grants)"
            )
        );
        assert_eq!(decision.result, "denied_restricted");
    }

    /// A refusal mixing both kinds blames the team only for the keys outside its grant.
    #[test]
    fn a_mixed_refusal_names_the_restricted_key_only_in_the_restricted_clause() {
        let decision = evaluate(
            &gate(OnNotGranted::Deny, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("internet,nope")),
        );
        let denial = decision.denial.unwrap_or_default();
        assert!(
            denial.contains("[nope], which team") && denial.contains("; [internet] are restricted"),
            "{denial}"
        );
        assert_eq!(decision.result, "denied_not_granted");
    }

    #[test]
    fn a_granted_restricted_key_under_deny_is_allowed_without_a_warning() {
        let mut subject = workspace(WORKSPACE_NS, Some("internet"));
        subject.namespace_grant = Some("internet".to_string());
        let decision = evaluate(&gate(OnNotGranted::Deny, &[WORKSPACE_NS]), &subject);
        assert_eq!(decision.denial, None);
        assert!(decision.warnings.is_empty());
    }

    /// R-11: an UPDATE is never refused; the warning is the only admission-side trace.
    #[test]
    fn an_update_naming_an_ungranted_restricted_key_is_allowed_with_a_warning() {
        let mut subject = workspace(WORKSPACE_NS, Some("internet"));
        subject.operation = WorkspaceOperation::Update;
        let decision = evaluate(&gate(OnNotGranted::Deny, &[WORKSPACE_NS]), &subject);
        assert_eq!(decision.denial, None);
        assert!(
            decision.warnings[0].ends_with("no profile beyond the baseline is applied"),
            "{:?}",
            decision.warnings
        );
        let decision = evaluate(&gate(OnNotGranted::Default, &[WORKSPACE_NS]), &subject);
        assert_eq!(decision.denial, None);
        assert_eq!(
            decision.warnings,
            vec![
                "network profile(s) [internet] are restricted: namespace user-alice does not \
                 grant them (annotation hardening.weebo.io/network-grants); the workspace does \
                 not get them"
                    .to_string()
            ]
        );
    }

    #[test]
    fn a_create_under_default_naming_an_ungranted_restricted_key_is_allowed_with_a_warning() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("git,internet")),
        );
        assert_eq!(decision.denial, None);
        assert_eq!(decision.result, "allowed");
        assert_eq!(decision.warnings.len(), 1);
    }

    #[test]
    fn no_restricted_key_no_warning() {
        let decision = evaluate(
            &gate(OnNotGranted::Default, &[WORKSPACE_NS]),
            &workspace(WORKSPACE_NS, Some("git")),
        );
        assert!(decision.warnings.is_empty());
    }
}
