//! The admission side of `team-tools` — RFC 0020, *Admission*, *Behaviour rules* and Resolved 15.
//!
//! Under `onNotGranted: Deny`, refuses only a `CREATE` naming an ungranted key, or an `UPDATE`
//! that starts the workspace (`spec.started` false to true). Every other `UPDATE` is admitted with
//! the key dropped and a warning, so a revoked grant never wedges a DevWorkspace. Otherwise its
//! only mutation is the verdict annotation `granted=<keys>;dropped=<keys>`, which the chassis
//! writes in `Enforce` only. Shaped like network-profiles' `WorkspaceAdmission`; the route wiring
//! is RFC 0020 PR 5.

use std::sync::{Arc, RwLock};

use weebo_si_chassis::{Context, Decision, DomainError, Feature, FeatureId, Mutation, Subject};
use weebo_si_crd::{
    NamespaceName, OnNotGranted, ResolvedTeamToolsConfig, TEAM_TOOLS_ATTRIBUTE, ToolKey,
};

use crate::feature::FEATURE_ID;
use crate::resolve::resolve;

/// Which write to a DevWorkspace is under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolsOperation {
    /// A new workspace.
    Create,
    /// An existing one; `starts` when `spec.started` goes from false to true.
    Update {
        /// Whether this update starts the workspace.
        starts: bool,
    },
}

/// A DevWorkspace write under admission, in domain vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsWorkspaceAdmission {
    /// The workspace's name.
    pub name: String,
    /// Its namespace.
    pub namespace: NamespaceName,
    /// Which write this is.
    pub operation: ToolsOperation,
    /// The raw value of `workspaceSelection.attribute`, `None` when absent.
    pub attribute: Option<String>,
    /// The verdict annotation the DevWorkspace already carries, if any.
    pub stored_verdict: Option<String>,
}

impl Subject for ToolsWorkspaceAdmission {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}

/// `team-tools`' admission surface, over the same live configuration as the reconcile feature.
pub struct TeamToolsAdmission {
    config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>,
}

impl TeamToolsAdmission {
    /// Build the gate over the live configuration.
    pub fn new(config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>) -> Self {
        Self { config }
    }
}

/// The verdict of a workspace with no tool.
const EMPTY_VERDICT: &str = "granted=;dropped=";

fn join(keys: &[ToolKey]) -> String {
    keys.iter()
        .map(ToolKey::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

impl Feature<ToolsWorkspaceAdmission> for TeamToolsAdmission {
    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn evaluate(
        &self,
        subject: &ToolsWorkspaceAdmission,
        ctx: &Context<'_>,
    ) -> Result<Decision<ToolsWorkspaceAdmission>, DomainError> {
        let guard = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(config) = guard.as_ref() else {
            return Err(DomainError::InvalidConfiguration(
                "team-tools evaluated with no spec.features.teamTools configured".to_string(),
            ));
        };
        let request = resolve(
            ctx.teams(),
            config,
            &ctx.namespace().labels,
            subject.attribute.as_deref(),
        );
        if request.granted.is_empty() && request.dropped.is_empty() {
            // A verdict left from an earlier request would show a tool the workspace no longer
            // has: it is emptied, otherwise the workspace is untouched.
            let mutations = subject
                .stored_verdict
                .as_deref()
                .filter(|stored| *stored != EMPTY_VERDICT)
                .map(|_| Mutation::Annotate {
                    key: TEAM_TOOLS_ATTRIBUTE.to_string(),
                    value: EMPTY_VERDICT.to_string(),
                })
                .into_iter()
                .collect();
            return Ok(Decision::new(mutations, request.team, None, "no_request"));
        }
        let team = request
            .team
            .as_ref()
            .map_or_else(|| "<none>".to_string(), ToString::to_string);
        let verdict = format!(
            "granted={};dropped={}",
            join(&request.granted),
            join(&request.dropped)
        );
        let refusable = matches!(
            subject.operation,
            ToolsOperation::Create | ToolsOperation::Update { starts: true }
        );
        if !request.dropped.is_empty() && config.on_not_granted == OnNotGranted::Deny && refusable {
            let reason = request
                .dropped
                .iter()
                .map(|key| format!("team tool {:?} is not granted to team {team}", key.as_str()))
                .collect::<Vec<_>>()
                .join(". ");
            return Ok(Decision::deny(
                reason,
                request.team,
                Some(verdict),
                "denied_not_granted",
            ));
        }
        let warnings = request
            .dropped
            .iter()
            .map(|key| match config.on_not_granted {
                OnNotGranted::Default => {
                    format!(
                        "team tool {:?} is not granted to team {team}; ignored",
                        key.as_str()
                    )
                }
                OnNotGranted::Deny => format!(
                    "team tool {:?} is no longer granted to team {team}; dropped",
                    key.as_str()
                ),
            })
            .collect();
        let result = if request.dropped.is_empty() {
            "granted"
        } else {
            "not_granted"
        };
        Ok(Decision::new(
            vec![Mutation::Annotate {
                key: TEAM_TOOLS_ATTRIBUTE.to_string(),
                value: verdict.clone(),
            }],
            request.team,
            Some(verdict),
            result,
        )
        .with_warnings(warnings))
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
    use weebo_si_crd::Team;

    use super::*;
    use crate::fixtures::{config, grant, team, weebo_labels};

    fn evaluate(
        on_not_granted: OnNotGranted,
        allowed: &[&str],
        operation: ToolsOperation,
        attribute: Option<&str>,
    ) -> Decision<ToolsWorkspaceAdmission> {
        let gate = TeamToolsAdmission::new(Arc::new(RwLock::new(Some(config(
            on_not_granted,
            grant(allowed, &[]),
        )))));
        let teams: Vec<Team> = vec![team()];
        let facts = NamespaceFacts {
            labels: weebo_labels(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let subject = ToolsWorkspaceAdmission {
            name: "python-web".to_string(),
            namespace: NamespaceName::new("dev-ws-batleforc-test"),
            operation,
            attribute: attribute.map(str::to_string),
            stored_verdict: None,
        };
        gate.evaluate(&subject, &Context::new(&teams, &facts, &catalog))
            .unwrap()
    }

    fn annotation(decision: &Decision<ToolsWorkspaceAdmission>) -> Option<&str> {
        decision.mutations.iter().find_map(|m| match m {
            Mutation::Annotate { key, value } if key == TEAM_TOOLS_ATTRIBUTE => {
                Some(value.as_str())
            }
            _ => None,
        })
    }

    #[test]
    fn a_granted_key_is_annotated() {
        let decision = evaluate(
            OnNotGranted::Deny,
            &["buildkit"],
            ToolsOperation::Create,
            Some("buildkit"),
        );
        assert_eq!(decision.denial, None);
        assert_eq!(annotation(&decision), Some("granted=buildkit;dropped="));
        assert_eq!(decision.result, "granted");
        assert!(decision.warnings.is_empty());
    }

    #[test]
    fn no_request_leaves_the_workspace_untouched() {
        let decision = evaluate(
            OnNotGranted::Deny,
            &["buildkit"],
            ToolsOperation::Create,
            None,
        );
        assert!(decision.mutations.is_empty() && decision.denial.is_none());
        assert_eq!(decision.result, "no_request");
    }

    #[test]
    fn a_stale_verdict_is_emptied() {
        let gate = TeamToolsAdmission::new(Arc::new(RwLock::new(Some(config(
            OnNotGranted::Deny,
            grant(&["buildkit"], &[]),
        )))));
        let teams: Vec<Team> = vec![team()];
        let facts = NamespaceFacts {
            labels: weebo_labels(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &facts, &catalog);
        let mut subject = ToolsWorkspaceAdmission {
            name: "python-web".to_string(),
            namespace: NamespaceName::new("dev-ws-batleforc-test"),
            operation: ToolsOperation::Update { starts: false },
            attribute: Some(String::new()),
            stored_verdict: Some("granted=buildkit;dropped=".to_string()),
        };
        let decision = gate.evaluate(&subject, &ctx).unwrap();
        assert_eq!(annotation(&decision), Some(EMPTY_VERDICT));
        subject.stored_verdict = Some(EMPTY_VERDICT.to_string());
        assert!(gate.evaluate(&subject, &ctx).unwrap().mutations.is_empty());
    }

    #[test]
    fn an_ungranted_key_is_denied_under_deny() {
        for operation in [
            ToolsOperation::Create,
            ToolsOperation::Update { starts: true },
        ] {
            let decision = evaluate(
                OnNotGranted::Deny,
                &["buildkit"],
                operation,
                Some("android"),
            );
            assert_eq!(
                decision.denial.as_deref(),
                Some("team tool \"android\" is not granted to team weebo")
            );
            assert_eq!(decision.result, "denied_not_granted");
        }
    }

    #[test]
    fn a_revoked_grant_never_wedges_an_update() {
        let decision = evaluate(
            OnNotGranted::Deny,
            &[],
            ToolsOperation::Update { starts: false },
            Some("buildkit"),
        );
        assert_eq!(decision.denial, None);
        assert_eq!(annotation(&decision), Some("granted=;dropped=buildkit"));
        assert_eq!(
            decision.warnings,
            vec!["team tool \"buildkit\" is no longer granted to team weebo; dropped".to_string()]
        );
    }

    #[test]
    fn an_ungranted_key_is_dropped_with_a_warning_under_default() {
        let decision = evaluate(
            OnNotGranted::Default,
            &["buildkit"],
            ToolsOperation::Create,
            Some("android,buildkit"),
        );
        assert_eq!(decision.denial, None);
        assert_eq!(
            annotation(&decision),
            Some("granted=buildkit;dropped=android")
        );
        assert_eq!(
            decision.warnings,
            vec!["team tool \"android\" is not granted to team weebo; ignored".to_string()]
        );
        assert_eq!(decision.result, "not_granted");
    }

    #[test]
    fn a_hostile_key_is_never_echoed() {
        let decision = evaluate(
            OnNotGranted::Deny,
            &["buildkit"],
            ToolsOperation::Create,
            Some("a;granted=buildkit"),
        );
        assert_eq!(
            decision.denial.as_deref(),
            Some("team tool \"<invalid>\" is not granted to team weebo")
        );
    }

    #[test]
    fn a_namespace_with_no_team_is_named_none() {
        let gate = TeamToolsAdmission::new(Arc::new(RwLock::new(Some(config(
            OnNotGranted::Deny,
            grant(&["buildkit"], &[]),
        )))));
        let teams: Vec<Team> = vec![team()];
        let facts = NamespaceFacts {
            labels: BTreeMap::new(),
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let subject = ToolsWorkspaceAdmission {
            name: "w".to_string(),
            namespace: NamespaceName::new("other"),
            operation: ToolsOperation::Create,
            attribute: Some("buildkit".to_string()),
            stored_verdict: None,
        };
        let decision = gate
            .evaluate(&subject, &Context::new(&teams, &facts, &catalog))
            .unwrap();
        assert_eq!(
            decision.denial.as_deref(),
            Some("team tool \"buildkit\" is not granted to team <none>")
        );
    }
}
