//! The three reconcile subjects and their `desired()` — RFC 0020, *Architecture*.
//!
//! | Subject | Owns |
//! | --- | --- |
//! | [`TeamTool`] `{team, key}` | the tool templates, the ingress policy and the server certificate in the tools namespace |
//! | [`RequesterNamespace`] `{ns, key}` | the endpoint `ConfigMap`, the copied requester `ConfigMap`s and the client certificate |
//! | [`RequestingWorkspace`] `{devworkspaceId, key}` | the per-workspace egress policy |
//!
//! A tools namespace or a workspace namespace holds the objects of several keys, all
//! [`PodSelector::Empty`] but the egress policies: the store hands each subject only the objects
//! labelled `hardening.weebo.io/team-tool=<its key>` before `compute_owned_diff` runs.
//!
//! `hold` means **keep what exists**: no apply, no delete. It is set for an unsynced cache, an
//! unbound namespace, an invalid team block and an invalid entry.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use weebo_si_chassis::managed::{OwnedScope, Owner};
use weebo_si_chassis::{Context, DomainError, FeatureId, PodSelector, ReconcileFeature, Subject};
use weebo_si_crd::{
    NamespaceName, ResolvedTeamToolsConfig, TeamName, TeamTeamTools, TeamToolState, ToolKey,
};

use crate::bind::{ToolsNamespace, Unbound, check_tools_namespace, client_identity};
use crate::port::{Clock, ToolTemplateStore};
use crate::render::{
    ToolObject, client_certificate, egress_policy, endpoint_config_map, from_template,
    ingress_policy, server_certificate,
};
use crate::resolve::{resolve, team_for};
use crate::scale::{Phase, ScaleDecision, decide};
use crate::validate::{EntryViolation, TeamViolation, ValidEntry, validate_entry, validate_team};

/// The feature identifier.
pub const FEATURE_ID: &str = "team-tools";

/// One tool of one team, in the team's tools namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct TeamTool {
    /// The team.
    pub team: TeamName,
    /// The catalogue key.
    pub key: ToolKey,
    /// The tools namespace the objects live in (the team block's, or the one they were rendered
    /// in before the block changed).
    pub namespace: NamespaceName,
    /// The tools namespace, `None` when it does not exist.
    pub tools_namespace: Option<ToolsNamespace>,
    /// Whether the tools namespace's cache is synced. `false` holds everything: an empty cache
    /// must never read as "no requester, scale to 0".
    pub synced: bool,
    /// DevWorkspaces of the team whose request resolves to this key, any phase.
    pub requesters: usize,
    /// Those started, `Starting` or `Running`.
    pub active: usize,
    /// The workload's live `spec.replicas`, `None` before it exists.
    pub replicas: Option<i32>,
    /// The grace timer kept for `(team, key)`.
    pub grace_since: Option<SystemTime>,
}

impl Subject for TeamTool {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "WeeboSiTeam"
    }
}

impl OwnedScope for TeamTool {
    fn owned_selector(&self) -> PodSelector {
        PodSelector::Empty
    }
}

/// What [`TeamTool`]'s `desired()` decided.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDesired {
    /// `status.teamTools[].state`.
    pub state: TeamToolState,
    /// The objects that should exist. Meaningless when `hold` is set.
    pub objects: Vec<ToolObject>,
    /// Keep what the namespace has.
    pub hold: bool,
    /// The replicas, `None` when nothing is scaled (held, or removed).
    pub scale: Option<ScaleDecision>,
    /// Why the namespace is not bound.
    pub unbound: Option<Unbound>,
    /// Why the team block is ignored.
    pub team_violations: Vec<TeamViolation>,
    /// Why the entry is not applied.
    pub entry_violations: Vec<EntryViolation>,
}

impl ToolDesired {
    fn held(state: TeamToolState) -> Self {
        Self {
            state,
            objects: Vec::new(),
            hold: true,
            scale: None,
            unbound: None,
            team_violations: Vec::new(),
            entry_violations: Vec::new(),
        }
    }

    fn removed() -> Self {
        Self {
            hold: false,
            ..Self::held(TeamToolState::Idle)
        }
    }
}

/// The client side of one key in one requesting namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterNamespace {
    /// The workspace namespace.
    pub namespace: NamespaceName,
    /// The catalogue key.
    pub key: ToolKey,
    /// The namespace's `che.eclipse.org/username` annotation.
    pub username: Option<String>,
    /// DevWorkspaces in the namespace whose request resolves to this key.
    pub requesters: usize,
    /// Whether the DevWorkspace cache is synced. `false` holds: an empty cache must never read
    /// as "no requester, delete the client side".
    pub synced: bool,
}

impl Subject for RequesterNamespace {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "Namespace"
    }
}

impl OwnedScope for RequesterNamespace {
    fn owned_selector(&self) -> PodSelector {
        PodSelector::Empty
    }
}

/// What [`RequesterNamespace`]'s `desired()` decided.
#[derive(Debug, Clone, PartialEq)]
pub struct RequesterDesired {
    /// The namespace's team.
    pub team: Option<TeamName>,
    /// The objects that should exist. Meaningless when `hold` is set.
    pub objects: Vec<ToolObject>,
    /// Keep what the namespace has.
    pub hold: bool,
    /// The entry has `tls` and the namespace fails the identity gate: no certificate, requester
    /// `Pending`, Event `TeamToolNoIdentity`.
    pub no_identity: bool,
}

/// One requesting DevWorkspace's egress towards one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestingWorkspace {
    /// The workspace namespace.
    pub namespace: NamespaceName,
    /// `status.devworkspaceId`.
    pub devworkspace_id: String,
    /// The DevWorkspace, the egress policy's owner.
    pub owner: Owner,
    /// The catalogue key.
    pub key: ToolKey,
    /// The raw attribute value, `None` when absent.
    pub attribute: Option<String>,
}

impl Subject for RequestingWorkspace {
    fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    fn resource(&self) -> &'static str {
        "DevWorkspace"
    }
}

impl OwnedScope for RequestingWorkspace {
    fn owned_selector(&self) -> PodSelector {
        PodSelector::DevWorkspaceId(self.devworkspace_id.clone())
    }
}

/// What [`RequestingWorkspace`]'s `desired()` decided.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceDesired {
    /// The namespace's team.
    pub team: Option<TeamName>,
    /// Whether the workspace's request resolves to the key.
    pub requested: bool,
    /// The objects that should exist. Meaningless when `hold` is set.
    pub objects: Vec<ToolObject>,
    /// Keep what the namespace has.
    pub hold: bool,
}

/// What a `(team, key)` resolves to in the configuration.
enum Lookup {
    /// The team has no block, does not allow the key, or the catalogue lost it: nothing should
    /// exist.
    NotGranted,
    /// The team block fails [`validate_team`].
    TeamInvalid(Vec<TeamViolation>),
    /// The entry fails [`validate_entry`].
    EntryInvalid(Vec<EntryViolation>),
    /// Everything checks out.
    Valid(Box<(TeamTeamTools, ValidEntry)>),
}

/// The `team-tools` feature.
pub struct TeamToolsFeature {
    config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>,
    templates: Arc<dyn ToolTemplateStore>,
    clock: Arc<dyn Clock>,
    operator_namespace: NamespaceName,
    template_namespace: NamespaceName,
    allowed_runtime_classes: Vec<String>,
}

impl TeamToolsFeature {
    /// Build the feature over the live configuration, the template store, the clock, the
    /// operator's and the template namespace, and the chart's `teamTools.allowedRuntimeClasses`.
    pub fn new(
        config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>,
        templates: Arc<dyn ToolTemplateStore>,
        clock: Arc<dyn Clock>,
        operator_namespace: NamespaceName,
        template_namespace: NamespaceName,
        allowed_runtime_classes: Vec<String>,
    ) -> Self {
        Self {
            config,
            templates,
            clock,
            operator_namespace,
            template_namespace,
            allowed_runtime_classes,
        }
    }

    fn current_config(&self) -> Result<ResolvedTeamToolsConfig, DomainError> {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| {
                DomainError::InvalidConfiguration(
                    "team-tools evaluated with no spec.features.teamTools configured".to_string(),
                )
            })
    }

    fn lookup(&self, config: &ResolvedTeamToolsConfig, team: &TeamName, key: &ToolKey) -> Lookup {
        let Some(grant) = config.grants.get(team.as_str()) else {
            return Lookup::NotGranted;
        };
        let violations = validate_team(grant, &config.catalog);
        if !violations.is_empty() {
            return Lookup::TeamInvalid(violations);
        }
        let Some(entry) = config
            .catalog
            .iter()
            .find(|entry| &entry.key == key)
            .filter(|_| grant.allowed.contains(key))
        else {
            return Lookup::NotGranted;
        };
        match validate_entry(
            entry,
            &config.catalog,
            self.templates.as_ref(),
            &self.template_namespace,
            &self.allowed_runtime_classes,
        ) {
            Ok(valid) => Lookup::Valid(Box::new((grant.clone(), valid))),
            Err(violations) => Lookup::EntryInvalid(violations),
        }
    }

    /// Every catalogue entry with what is wrong with it — the `weebo_si_team_tools_entries`
    /// gauge and the `Degraded` condition.
    pub fn check_catalog(&self) -> Result<Vec<(ToolKey, Vec<EntryViolation>)>, DomainError> {
        let config = self.current_config()?;
        Ok(config
            .catalog
            .iter()
            .map(|entry| {
                let violations = validate_entry(
                    entry,
                    &config.catalog,
                    self.templates.as_ref(),
                    &self.template_namespace,
                    &self.allowed_runtime_classes,
                )
                .err()
                .unwrap_or_default();
                (entry.key.clone(), violations)
            })
            .collect())
    }
}

impl ReconcileFeature<TeamTool> for TeamToolsFeature {
    type Desired = ToolDesired;

    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn desired(&self, subject: &TeamTool, ctx: &Context<'_>) -> Result<ToolDesired, DomainError> {
        let config = self.current_config()?;
        if !subject.synced {
            return Ok(ToolDesired::held(TeamToolState::Held));
        }
        // The team moved its tools elsewhere: what is here goes, even once the admin unlabelled
        // the old namespace (the delete only reaches objects labelled managed-by, under RBAC).
        if config
            .grants
            .get(subject.team.as_str())
            .is_some_and(|grant| grant.namespace != subject.namespace)
        {
            return Ok(ToolDesired::removed());
        }
        if let Err(unbound) = check_tools_namespace(
            &subject.team,
            &subject.namespace,
            subject.tools_namespace.as_ref(),
            &self.operator_namespace,
            &self.template_namespace,
        ) {
            return Ok(ToolDesired {
                unbound: Some(unbound),
                ..ToolDesired::held(TeamToolState::Unbound)
            });
        }
        let (grant, entry) = match self.lookup(&config, &subject.team, &subject.key) {
            Lookup::NotGranted => return Ok(ToolDesired::removed()),
            Lookup::TeamInvalid(team_violations) => {
                return Ok(ToolDesired {
                    team_violations,
                    ..ToolDesired::held(TeamToolState::Invalid)
                });
            }
            Lookup::EntryInvalid(entry_violations) => {
                return Ok(ToolDesired {
                    entry_violations,
                    ..ToolDesired::held(TeamToolState::Invalid)
                });
            }
            Lookup::Valid(found) => *found,
        };
        if subject.requesters == 0 {
            return Ok(ToolDesired::removed());
        }
        let team = ctx
            .teams()
            .iter()
            .find(|team| team.name == subject.team)
            .ok_or_else(|| {
                DomainError::InvalidConfiguration(format!(
                    "team {} has a teamTools grant but no WeeboSiTeam",
                    subject.team
                ))
            })?;

        let key = &subject.key;
        let mut objects: Vec<ToolObject> = entry
            .tools
            .iter()
            .filter_map(|template| from_template(template, &subject.namespace, key))
            .collect();
        objects.push(ingress_policy(
            &subject.namespace,
            &entry,
            &team.namespace_selector,
        ));
        if let Some(issuer) = &grant.issuer_ref {
            objects.extend(server_certificate(&subject.namespace, &entry, issuer));
        }

        let grace = entry
            .entry
            .idle_grace_seconds
            .unwrap_or(config.idle_grace_seconds);
        let scale = decide(
            subject.requesters,
            subject.active,
            subject.replicas,
            subject.grace_since,
            self.clock.now(),
            Duration::from_secs(u64::from(grace)),
        );
        let state = match scale.phase {
            Phase::Up => TeamToolState::Running,
            Phase::Grace => TeamToolState::Grace,
            Phase::Idle | Phase::Removed => TeamToolState::Idle,
        };
        Ok(ToolDesired {
            state,
            objects,
            hold: false,
            scale: Some(scale),
            unbound: None,
            team_violations: Vec::new(),
            entry_violations: Vec::new(),
        })
    }
}

impl ReconcileFeature<RequesterNamespace> for TeamToolsFeature {
    type Desired = RequesterDesired;

    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn desired(
        &self,
        subject: &RequesterNamespace,
        ctx: &Context<'_>,
    ) -> Result<RequesterDesired, DomainError> {
        let config = self.current_config()?;
        let labels = &ctx.namespace().labels;
        if !subject.synced {
            return Ok(RequesterDesired {
                team: None,
                objects: Vec::new(),
                hold: true,
                no_identity: false,
            });
        }
        let team = team_for(ctx.teams(), labels).map(|team| team.name.clone());
        let mut desired = RequesterDesired {
            team: team.clone(),
            objects: Vec::new(),
            hold: false,
            no_identity: false,
        };
        let Some(team) = team else {
            return Ok(desired);
        };
        let (grant, entry) = match self.lookup(&config, &team, &subject.key) {
            Lookup::NotGranted => return Ok(desired),
            Lookup::TeamInvalid(_) | Lookup::EntryInvalid(_) => {
                desired.hold = true;
                return Ok(desired);
            }
            Lookup::Valid(found) => *found,
        };
        if subject.requesters == 0 {
            return Ok(desired);
        }
        let key = &subject.key;
        desired.objects.extend(endpoint_config_map(
            &subject.namespace,
            &entry,
            &grant.namespace,
        ));
        desired.objects.extend(
            entry
                .requesters
                .iter()
                .filter_map(|template| from_template(template, &subject.namespace, key)),
        );
        if entry.entry.tls.is_some()
            && let Some(issuer) = &grant.issuer_ref
        {
            match client_identity(labels, subject.username.as_deref()) {
                Some(common_name) => desired.objects.extend(client_certificate(
                    &subject.namespace,
                    &entry,
                    issuer,
                    &team,
                    common_name,
                )),
                None => desired.no_identity = true,
            }
        }
        Ok(desired)
    }
}

impl ReconcileFeature<RequestingWorkspace> for TeamToolsFeature {
    type Desired = WorkspaceDesired;

    fn id(&self) -> FeatureId {
        FeatureId::new(FEATURE_ID)
    }

    fn desired(
        &self,
        subject: &RequestingWorkspace,
        ctx: &Context<'_>,
    ) -> Result<WorkspaceDesired, DomainError> {
        let config = self.current_config()?;
        let request = resolve(
            ctx.teams(),
            &config,
            &ctx.namespace().labels,
            subject.attribute.as_deref(),
        );
        let mut desired = WorkspaceDesired {
            team: request.team.clone(),
            requested: request.granted.contains(&subject.key),
            objects: Vec::new(),
            hold: false,
        };
        // DWO has not assigned the id yet: there is nothing to select, and nothing to name.
        if subject.devworkspace_id.is_empty() {
            desired.hold = true;
            return Ok(desired);
        }
        let Some(team) = &request.team else {
            return Ok(desired);
        };
        let (grant, entry) = match self.lookup(&config, team, &subject.key) {
            Lookup::NotGranted => return Ok(desired),
            Lookup::TeamInvalid(_) | Lookup::EntryInvalid(_) => {
                desired.hold = true;
                return Ok(desired);
            }
            Lookup::Valid(found) => *found,
        };
        if desired.requested {
            desired.objects.push(egress_policy(
                &subject.namespace,
                &subject.devworkspace_id,
                &subject.owner,
                &entry,
                &grant.namespace,
            ));
        }
        Ok(desired)
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
    use weebo_si_crd::{OnNotGranted, PROFILE_LABEL, Team};

    use super::*;
    use crate::bind::USERNAME_ANNOTATION;
    use crate::fixtures::{
        OPERATOR_NS, TEMPLATE_NS, TOOLS_NS, bound_tools_namespace, config, config_with, grant,
        owner, store, store_with, team, weebo_labels,
    };
    use crate::port::testing::{FakeClock, FakeTemplateStore};
    use crate::render::ToolObjectKind;

    fn feature_over(
        config: ResolvedTeamToolsConfig,
        templates: FakeTemplateStore,
    ) -> TeamToolsFeature {
        TeamToolsFeature::new(
            Arc::new(RwLock::new(Some(config))),
            Arc::new(templates),
            Arc::new(FakeClock::at(1_000)),
            NamespaceName::new(OPERATOR_NS),
            NamespaceName::new(TEMPLATE_NS),
            Vec::new(),
        )
    }

    fn feature() -> TeamToolsFeature {
        feature_over(config_with(&["buildkit"], &[]), store())
    }

    fn with_ctx<T>(labels: BTreeMap<String, String>, run: impl FnOnce(&Context<'_>) -> T) -> T {
        let teams: Vec<Team> = vec![team()];
        let facts = NamespaceFacts {
            labels,
            selection_annotation: None,
        };
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        run(&Context::new(&teams, &facts, &catalog))
    }

    fn tool(requesters: usize, active: usize) -> TeamTool {
        TeamTool {
            team: TeamName::new("weebo"),
            key: ToolKey::new("buildkit"),
            namespace: NamespaceName::new(TOOLS_NS),
            tools_namespace: Some(bound_tools_namespace()),
            synced: true,
            requesters,
            active,
            replicas: Some(0),
            grace_since: None,
        }
    }

    fn tool_desired(feature: &TeamToolsFeature, subject: &TeamTool) -> ToolDesired {
        with_ctx(BTreeMap::new(), |ctx| feature.desired(subject, ctx)).unwrap()
    }

    fn names(objects: &[ToolObject]) -> Vec<String> {
        objects
            .iter()
            .map(|o| format!("{}/{}", o.kind.as_str(), o.key.name))
            .collect()
    }

    #[test]
    fn a_requested_tool_is_rendered_and_scaled_up() {
        let desired = tool_desired(&feature(), &tool(1, 1));
        assert_eq!(desired.state, TeamToolState::Running);
        assert!(!desired.hold);
        assert_eq!(desired.scale.unwrap().write(Some(0)), Some(1));
        assert_eq!(
            names(&desired.objects),
            vec![
                "StatefulSet/buildkitd",
                "Service/buildkitd",
                "ConfigMap/buildkitd-toml",
                "CiliumNetworkPolicy/buildkitd-egress",
                "CiliumNetworkPolicy/weebo-team-tool-buildkit-ingress",
                "Certificate/weebo-team-tool-buildkit-server",
            ]
        );
        assert!(
            desired
                .objects
                .iter()
                .all(|o| o.key.namespace.as_str() == TOOLS_NS
                    && o.selector == PodSelector::Empty
                    && !o.labels.contains_key(PROFILE_LABEL))
        );
    }

    #[test]
    fn a_stopped_requester_keeps_the_tool_rendered_at_zero() {
        let desired = tool_desired(&feature(), &tool(1, 0));
        assert_eq!(desired.state, TeamToolState::Idle);
        assert_eq!(desired.objects.len(), 6);
        assert_eq!(desired.scale.unwrap().replicas, Some(0));
    }

    #[test]
    fn the_entry_grace_overrides_the_block() {
        let mut config = config_with(&["buildkit"], &[]);
        config.config.catalog[0].idle_grace_seconds = Some(0);
        let mut subject = tool(1, 0);
        subject.replicas = Some(1);
        let desired = tool_desired(&feature_over(config, store()), &subject);
        assert_eq!(desired.state, TeamToolState::Idle);
        let desired = tool_desired(&feature(), &subject);
        assert_eq!(desired.state, TeamToolState::Grace);
    }

    #[test]
    fn no_requester_or_no_grant_removes_everything() {
        let desired = tool_desired(&feature(), &tool(0, 0));
        assert_eq!(desired, ToolDesired::removed());
        let revoked = feature_over(config_with(&[], &[]), store());
        assert_eq!(tool_desired(&revoked, &tool(2, 1)), ToolDesired::removed());
        let mut moved = tool(1, 1);
        // The team block now names another namespace, and the old one was unlabelled.
        moved.namespace = NamespaceName::new("team-weebo-old");
        moved.tools_namespace = None;
        assert_eq!(tool_desired(&feature(), &moved), ToolDesired::removed());
    }

    #[test]
    fn an_unsynced_cache_holds_and_never_scales() {
        let mut subject = tool(0, 0);
        subject.synced = false;
        let desired = tool_desired(&feature(), &subject);
        assert_eq!(desired.state, TeamToolState::Held);
        assert!(desired.hold && desired.scale.is_none());
    }

    #[test]
    fn an_unbound_namespace_holds() {
        let mut subject = tool(1, 1);
        subject.tools_namespace = None;
        let desired = tool_desired(&feature(), &subject);
        assert_eq!(desired.state, TeamToolState::Unbound);
        assert!(desired.hold && desired.objects.is_empty() && desired.scale.is_none());
        assert_eq!(desired.unbound.unwrap().reason(), "NamespaceNotBound");
    }

    #[test]
    fn an_invalid_entry_keeps_what_is_rendered() {
        let templates = store_with(|kind, body| {
            if kind == "StatefulSet" {
                body["spec"]["template"]["spec"]["hostNetwork"] = true.into();
            }
        });
        let desired = tool_desired(
            &feature_over(config_with(&["buildkit"], &[]), templates),
            &tool(0, 0),
        );
        assert_eq!(desired.state, TeamToolState::Invalid);
        assert!(desired.hold && desired.scale.is_none());
        assert_eq!(desired.entry_violations.len(), 1);
    }

    #[test]
    fn an_invalid_team_block_keeps_what_is_rendered() {
        let mut team = grant(&["buildkit"], &[]);
        team.issuer_ref = None;
        let feature = feature_over(config(OnNotGranted::Default, team), store());
        let desired = tool_desired(&feature, &tool(1, 1));
        assert_eq!(desired.state, TeamToolState::Invalid);
        assert!(desired.hold);
        assert_eq!(desired.team_violations.len(), 1);
        // The client side holds too.
        let requester = RequesterNamespace {
            namespace: NamespaceName::new("dev-ws-bob"),
            key: ToolKey::new("buildkit"),
            username: Some("bob".to_string()),
            requesters: 0,
            synced: true,
        };
        assert!(
            with_ctx(weebo_labels(), |ctx| feature.desired(&requester, ctx))
                .unwrap()
                .hold
        );
    }

    #[test]
    fn no_configuration_is_an_error() {
        let feature = TeamToolsFeature::new(
            Arc::new(RwLock::new(None)),
            Arc::new(store()),
            Arc::new(FakeClock::at(0)),
            NamespaceName::new(OPERATOR_NS),
            NamespaceName::new(TEMPLATE_NS),
            Vec::new(),
        );
        assert!(with_ctx(BTreeMap::new(), |ctx| feature.desired(&tool(1, 1), ctx)).is_err());
        assert!(feature.check_catalog().is_err());
    }

    #[test]
    fn check_catalog_reports_every_entry() {
        assert_eq!(
            feature().check_catalog().unwrap(),
            vec![(ToolKey::new("buildkit"), Vec::new())]
        );
    }

    fn requester(username: Option<&str>, requesters: usize) -> RequesterNamespace {
        RequesterNamespace {
            namespace: NamespaceName::new("dev-ws-batleforc-test"),
            key: ToolKey::new("buildkit"),
            username: username.map(str::to_string),
            requesters,
            synced: true,
        }
    }

    #[test]
    fn a_requesting_namespace_gets_the_client_side() {
        let desired = with_ctx(weebo_labels(), |ctx| {
            feature().desired(&requester(Some("batleforc-test"), 1), ctx)
        })
        .unwrap();
        assert_eq!(desired.team, Some(TeamName::new("weebo")));
        assert!(!desired.no_identity);
        assert_eq!(
            names(&desired.objects),
            vec![
                "ConfigMap/weebo-team-tool-buildkit",
                "ConfigMap/buildx-client",
                "Certificate/weebo-team-tool-buildkit-client",
            ]
        );
    }

    #[test]
    fn the_client_certificate_cn_is_the_namespace_owner() {
        let desired = with_ctx(weebo_labels(), |ctx| {
            feature().desired(&requester(Some("batleforc-test"), 1), ctx)
        })
        .unwrap();
        let cert = desired
            .objects
            .iter()
            .find(|o| o.kind == ToolObjectKind::Certificate)
            .unwrap();
        assert_eq!(cert.body["spec"]["commonName"], "batleforc-test");
        assert_eq!(USERNAME_ANNOTATION, "che.eclipse.org/username");
    }

    #[test]
    fn a_namespace_without_identity_gets_no_certificate() {
        let desired = with_ctx(weebo_labels(), |ctx| {
            feature().desired(&requester(None, 1), ctx)
        })
        .unwrap();
        assert!(desired.no_identity);
        assert!(
            desired
                .objects
                .iter()
                .all(|o| o.kind != ToolObjectKind::Certificate)
        );
    }

    #[test]
    fn a_namespace_without_requester_or_team_gets_nothing() {
        let none = with_ctx(weebo_labels(), |ctx| {
            feature().desired(&requester(Some("bob"), 0), ctx)
        })
        .unwrap();
        assert!(none.objects.is_empty() && !none.hold);
        let teamless = with_ctx(BTreeMap::new(), |ctx| {
            feature().desired(&requester(Some("bob"), 1), ctx)
        })
        .unwrap();
        assert_eq!(teamless.team, None);
        assert!(teamless.objects.is_empty());
    }

    #[test]
    fn an_unsynced_workspace_cache_holds_the_client_side() {
        let mut subject = requester(Some("bob"), 0);
        subject.synced = false;
        let desired = with_ctx(weebo_labels(), |ctx| feature().desired(&subject, ctx)).unwrap();
        assert!(desired.hold && desired.objects.is_empty());
    }

    #[test]
    fn a_workspace_without_an_id_yet_holds() {
        let mut subject = workspace(Some("buildkit"));
        subject.devworkspace_id = String::new();
        let desired = with_ctx(weebo_labels(), |ctx| feature().desired(&subject, ctx)).unwrap();
        assert!(desired.hold && desired.objects.is_empty());
    }

    fn workspace(attribute: Option<&str>) -> RequestingWorkspace {
        RequestingWorkspace {
            namespace: NamespaceName::new("dev-ws-batleforc-test"),
            devworkspace_id: "workspace1234".to_string(),
            owner: owner(),
            key: ToolKey::new("buildkit"),
            attribute: attribute.map(str::to_string),
        }
    }

    #[test]
    fn a_requesting_workspace_gets_its_egress_policy() {
        let subject = workspace(Some("buildkit"));
        let desired = with_ctx(weebo_labels(), |ctx| feature().desired(&subject, ctx)).unwrap();
        assert!(desired.requested);
        assert_eq!(desired.objects.len(), 1);
        assert_eq!(desired.objects[0].selector, subject.owned_selector());
    }

    #[test]
    fn a_workspace_that_stops_requesting_loses_its_egress_policy() {
        for attribute in [Some(""), Some("android"), None] {
            let desired = with_ctx(weebo_labels(), |ctx| {
                feature().desired(&workspace(attribute), ctx)
            })
            .unwrap();
            assert!(!desired.requested, "{attribute:?}");
            assert!(desired.objects.is_empty() && !desired.hold);
        }
        // Absent is the team default.
        let defaulted = feature_over(config_with(&["buildkit"], &["buildkit"]), store());
        let desired = with_ctx(weebo_labels(), |ctx| {
            defaulted.desired(&workspace(None), ctx)
        })
        .unwrap();
        assert!(desired.requested);
    }
}
