//! The `team-tools` loop. Its subjects are aggregates — a tool's requesters are every
//! DevWorkspace of the team — so it runs **whole passes** rather than one reconcile per object:
//! a pass reads the DevWorkspace cache once, counts, then reconciles every tool, every requester
//! namespace and every requesting workspace. A pass runs when anything it reads changed
//! (polled every [`TICK`]) and at least every [`RESYNC`], which is what moves a grace timer.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use k8s_openapi::api::core::v1::ObjectReference;
use kube::api::{Api, DynamicObject};
use kube::runtime::events::Recorder;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, ResourceExt};
use weebo_si_chassis::managed::{Applied, Diff, compute_diff};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_chassis::port::feature_gate::FeatureGate;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_chassis::{Context, FeatureId, NamespaceFacts, ObjectKey};
use weebo_si_controller::TeamToolsReport;
use weebo_si_controller::events::{ReasonCode, Regarding, publish};
use weebo_si_controller::workspace::{devworkspace_id, devworkspace_owner, devworkspace_resource};
use weebo_si_crd::{
    FeatureMode, NamespaceName, ResolvedTeamToolsConfig, TEAM_TOOLS_NAMESPACE_LABEL, Team,
    TeamName, TeamToolState, TeamToolStatus, ToolKey, WeeboSiTeam, WorkloadKind,
};
use weebo_si_team_tools::{
    FEATURE_ID, RequesterNamespace, RequestingWorkspace, TeamTool, TeamToolsFeature, ToolObject,
    ToolObjectKind, ToolsNamespace, USERNAME_ANNOTATION, WORKSPACE_NAMESPACE_LABEL, resolve,
};

use crate::kube_template_store::KubeToolTemplateStore;
use crate::kube_tool_store::{KubeToolStore, Watch};
use crate::metrics::{TeamToolsMetrics, ToolGauges};
use crate::objects::ALL_KINDS;
use crate::port::{Adoption, StoreError, ToolObjectStore};
use crate::reconcile::{
    Converged, ToolOutcome, reconcile_requester, reconcile_tool, reconcile_workspace,
};
use crate::status::{self, TeamReport};

/// How often the inputs' fingerprint is compared.
const TICK: Duration = Duration::from_secs(2);
/// The longest time between two passes.
const RESYNC: Duration = Duration::from_secs(30);
/// What `weebo_si_team_tools_up_without_requester` waits past the grace (RFC 0020).
const UP_WITHOUT_REQUESTER_SLACK: Duration = Duration::from_secs(60);

/// Everything the loop needs, built by [`crate::controller_deps`].
pub struct TeamToolsDeps {
    /// The feature.
    pub feature: Arc<TeamToolsFeature>,
    /// The handle `feature` reads.
    pub config: Arc<RwLock<Option<ResolvedTeamToolsConfig>>>,
    /// Modes per requesting namespace, and the teams.
    pub gate: Arc<dyn FeatureGate + Send + Sync>,
    /// Namespace labels and annotations.
    pub namespace_view: Arc<dyn NamespaceView + Send + Sync>,
    /// Required structurally by `Context`.
    pub dwoc_catalog: Arc<dyn DwocCatalog + Send + Sync>,
    /// The templates.
    pub templates: Arc<KubeToolTemplateStore>,
    /// The rendered objects and the writes.
    pub store: Arc<KubeToolStore>,
    /// The six metrics.
    pub metrics: Arc<TeamToolsMetrics>,
    /// This operator's namespace: never a requesting namespace.
    pub operator_namespace: NamespaceName,
    /// What the `WeeboSiConfig` status loop reports for this feature.
    pub report: Arc<RwLock<Option<TeamToolsReport>>>,
}

/// An Event's target that the loop knows only by name: a `WeeboSiTeam`.
struct TeamRef(String);

impl Regarding for TeamRef {
    fn regarding(&self) -> ObjectReference {
        ObjectReference {
            api_version: Some("hardening.weebo.io/v1alpha1".to_string()),
            kind: Some("WeeboSiTeam".to_string()),
            name: Some(self.0.clone()),
            ..ObjectReference::default()
        }
    }
}

/// One requesting DevWorkspace, as a pass reads it.
struct Requester {
    object: Arc<DynamicObject>,
    namespace: NamespaceName,
    attribute: Option<String>,
    team: Option<TeamName>,
    granted: Vec<ToolKey>,
    dropped: Vec<ToolKey>,
    active: bool,
    running: bool,
}

/// What the loop remembers between passes; nothing of it is persisted (RFC 0020, *Data and
/// state*: a restart re-arms the grace from "now").
#[derive(Default)]
struct Memory {
    grace: HashMap<(TeamName, ToolKey), SystemTime>,
    idle_since: HashMap<(TeamName, ToolKey), SystemTime>,
    written: BTreeSet<String>,
    listed: bool,
    not_granted: HashMap<String, Vec<ToolKey>>,
    no_identity: BTreeSet<(NamespaceName, ToolKey)>,
    overlaps: BTreeSet<String>,
}

struct Loop {
    deps: TeamToolsDeps,
    client: Client,
    recorder: Recorder,
    workspaces: Store<DynamicObject>,
    memory: Memory,
}

fn mode_of(config: &ResolvedTeamToolsConfig) -> FeatureMode {
    config.config.mode
}

fn keys(list: &[ToolKey]) -> String {
    list.iter()
        .map(ToolKey::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// The reconcile-result label of one converge.
fn converged_result(converged: &Converged) -> &'static str {
    match &converged.error {
        Some(StoreError::Forbidden(_)) => return "forbidden",
        Some(StoreError::Failed(_)) => return "error",
        None => {}
    }
    let mut deleted = false;
    for diff in &converged.diffs {
        match diff {
            Diff::Create(_) | Diff::Update(_) => return "applied",
            Diff::Delete { .. } => deleted = true,
            Diff::Unchanged(_) => {}
        }
    }
    if deleted { "deleted" } else { "unchanged" }
}

fn tool_result(outcome: &ToolOutcome) -> &'static str {
    match outcome.state() {
        TeamToolState::Unbound => {
            if outcome
                .unbound()
                .is_some_and(|unbound| unbound.reason() == "Forbidden")
            {
                "forbidden"
            } else {
                "unbound"
            }
        }
        TeamToolState::Invalid => "invalid",
        _ => converged_result(&outcome.converged),
    }
}

/// The DevWorkspace attribute, `None` when absent or when requests are off (`""`).
fn attribute_of(object: &DynamicObject, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    object
        .data
        .pointer("/spec/template/attributes")
        .and_then(|attributes| attributes.get(key))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn phase(object: &DynamicObject) -> Option<&str> {
    object
        .data
        .pointer("/status/phase")
        .and_then(serde_json::Value::as_str)
}

/// Started, `Starting` or `Running` (RFC 0020, *Behaviour rules*, "Scale").
fn is_active(object: &DynamicObject) -> bool {
    object
        .data
        .pointer("/spec/started")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        || matches!(phase(object), Some("Starting" | "Running"))
}

/// `mode: Off`: every object this feature wrote goes, the StatefulSets' PVCs excepted (a
/// `StatefulSet` delete keeps them by default). A namespace whose delete fails is logged and
/// retried next pass; the others still go.
pub async fn teardown(store: &KubeToolStore) -> Applied {
    let namespaces: BTreeSet<NamespaceName> = store
        .all()
        .into_iter()
        .map(|object| object.key.namespace)
        .collect();
    let mut total = Applied::default();
    for namespace in namespaces {
        let existing = store.all_in(&namespace);
        let mut diffs = Vec::new();
        for kind in ALL_KINDS {
            let of_kind: Vec<ToolObject> = existing
                .iter()
                .filter(|object| object.kind == kind)
                .cloned()
                .collect();
            diffs.extend(compute_diff(&[], &of_kind));
        }
        match store.apply(&diffs, Adoption::Never).await {
            Ok(applied) => total.deleted = total.deleted.saturating_add(applied.deleted),
            Err(err) => {
                tracing::warn!(
                    "feature={FEATURE_ID} mode=Off ns={namespace} teardown failed: {err}"
                );
            }
        }
    }
    total
}

/// The namespaces holding DevWorkspaces that match the selectors of two teams which both have
/// team tools: their workspaces reach both teams' tools on the network (coordinator decision
/// after RFC 0020 PR 2: reported, not refused; per-user mTLS stays the boundary).
pub fn overlaps(
    teams: &[Team],
    config: &ResolvedTeamToolsConfig,
    namespaces: &BTreeMap<NamespaceName, BTreeMap<String, String>>,
) -> Vec<(String, Vec<String>)> {
    namespaces
        .iter()
        .filter_map(|(namespace, labels)| {
            let matching: Vec<&str> = teams
                .iter()
                .filter(|team| config.grants.contains_key(team.name.as_str()))
                .filter(|team| team.namespace_selector.matches(labels))
                .map(|team| team.name.as_str())
                .collect();
            (matching.len() > 1).then(|| {
                (
                    format!(
                        "namespace {namespace} matches the selectors of teams {}, which all have \
                         team tools: its workspaces reach each of their tools on the network \
                         (per-user mTLS stays the boundary)",
                        matching.join(", ")
                    ),
                    matching.iter().map(|team| (*team).to_string()).collect(),
                )
            })
        })
        .collect()
}

impl Loop {
    fn config(&self) -> Option<ResolvedTeamToolsConfig> {
        self.deps
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn facts(&self, namespace: &NamespaceName) -> NamespaceFacts {
        self.deps
            .namespace_view
            .facts(namespace)
            .unwrap_or_default()
    }

    /// Everything that can change a pass's outcome, hashed.
    fn fingerprint(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        format!("{:?}", self.config()).hash(&mut hasher);
        format!("{:?}", self.deps.gate.teams()).hash(&mut hasher);
        self.deps.templates.versions().hash(&mut hasher);
        let mut versions = self.deps.store.versions();
        versions.extend(self.workspaces.state().iter().map(|object| {
            format!(
                "{}@{}",
                object.uid().unwrap_or_default(),
                object.resource_version().unwrap_or_default()
            )
        }));
        versions.sort();
        versions.hash(&mut hasher);
        hasher.finish()
    }

    async fn teardown(&mut self) {
        let applied = teardown(&self.deps.store).await;
        if applied.deleted > 0 {
            self.deps.metrics.reconciled("deleted");
            tracing::info!("feature={FEATURE_ID} mode=Off deleted={}", applied.deleted);
        }
        self.memory.grace.clear();
        self.memory.idle_since.clear();
    }

    fn set_report(&self, report: TeamToolsReport) {
        *self
            .deps
            .report
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(report);
    }

    async fn pass(&mut self) {
        // No block: nothing is decided, and nothing is torn down — as every feature here, only
        // an explicit `mode: Off` removes what was written (a singleton being re-applied must
        // not stop every tool). The statuses and the report are cleared.
        let Some(config) = self.config() else {
            self.set_report(TeamToolsReport::default());
            self.write_statuses(None, BTreeMap::new(), &BTreeSet::new())
                .await;
            return;
        };
        let mode = mode_of(&config);
        if mode == FeatureMode::Off {
            self.teardown().await;
            self.set_report(TeamToolsReport::default());
            self.write_statuses(None, BTreeMap::new(), &BTreeSet::new())
                .await;
            return;
        }
        let teams = self.deps.gate.teams();
        let synced = self.workspaces_synced().await;

        // The catalogue, for the entries gauge and the WeeboSiConfig status.
        let mut invalid = BTreeSet::new();
        match self.deps.feature.check_catalog() {
            Ok(checked) => {
                let bad = checked
                    .iter()
                    .filter(|(_, violations)| !violations.is_empty())
                    .count();
                self.deps
                    .metrics
                    .entries(checked.len().saturating_sub(bad), bad);
                for (key, violations) in &checked {
                    for violation in violations {
                        tracing::warn!(
                            "feature={FEATURE_ID} tool={key} result=invalid {violation}"
                        );
                        invalid.insert(format!("tool {key}: {violation}"));
                    }
                }
            }
            Err(err) => {
                tracing::warn!("feature={FEATURE_ID} the catalogue could not be checked: {err}");
                invalid.insert(format!("the catalogue could not be checked: {err}"));
            }
        }

        let requesters = self.requesters(&config, &teams);
        let warnings = self.report_overlaps(&teams, &config, &requesters).await;

        let mut reports: BTreeMap<String, TeamReport> = BTreeMap::new();
        let mut failed = BTreeSet::new();
        self.tools(
            &config,
            &teams,
            &requesters,
            synced,
            mode,
            &mut reports,
            &mut invalid,
            &mut failed,
        )
        .await;
        self.requester_namespaces(&config, &teams, &requesters, synced)
            .await;
        self.requesting_workspaces(&teams, &requesters).await;

        self.set_report(TeamToolsReport {
            invalid: invalid.into_iter().collect(),
            warnings,
        });
        self.write_statuses(Some(&config), reports, &failed).await;
    }

    async fn workspaces_synced(&self) -> bool {
        // `wait_until_ready` returns at once once the first list is in.
        tokio::time::timeout(Duration::from_millis(1), self.workspaces.wait_until_ready())
            .await
            .is_ok_and(|ready| ready.is_ok())
    }

    fn requesters(&self, config: &ResolvedTeamToolsConfig, teams: &[Team]) -> Vec<Requester> {
        let attribute_key = config.config.workspace_selection.attribute.clone();
        self.workspaces
            .state()
            .into_iter()
            .filter(|object| object.metadata.deletion_timestamp.is_none())
            .filter_map(|object| {
                let namespace = NamespaceName::new(object.namespace()?);
                if namespace == self.deps.operator_namespace
                    || self.deps.gate.mode(FeatureId::new(FEATURE_ID), &namespace)
                        == FeatureMode::Off
                {
                    return None;
                }
                let attribute = attribute_of(&object, &attribute_key);
                let facts = self.facts(&namespace);
                let request = resolve(teams, config, &facts.labels, attribute.as_deref());
                Some(Requester {
                    active: is_active(&object),
                    running: phase(&object) == Some("Running"),
                    object,
                    namespace,
                    attribute,
                    team: request.team,
                    granted: request.granted,
                    dropped: request.dropped,
                })
            })
            .collect()
    }

    async fn report_overlaps(
        &mut self,
        teams: &[Team],
        config: &ResolvedTeamToolsConfig,
        requesters: &[Requester],
    ) -> Vec<String> {
        let namespaces: BTreeMap<NamespaceName, BTreeMap<String, String>> = requesters
            .iter()
            .map(|requester| {
                (
                    requester.namespace.clone(),
                    self.facts(&requester.namespace).labels,
                )
            })
            .collect();
        let found = overlaps(teams, config, &namespaces);
        for (warning, named) in &found {
            if self.memory.overlaps.insert(warning.clone()) {
                tracing::warn!("feature={FEATURE_ID} result=overlapping_selectors {warning}");
                for team in named {
                    publish(
                        &self.recorder,
                        &TeamRef(team.clone()),
                        true,
                        ReasonCode::TeamToolsSelectorOverlap,
                        warning.clone(),
                    )
                    .await;
                }
            }
        }
        let warnings: Vec<String> = found.into_iter().map(|(warning, _)| warning).collect();
        self.memory
            .overlaps
            .retain(|warning| warnings.contains(warning));
        warnings
    }

    /// Every `(team, key, tools namespace)` with something to decide: the team's allowed keys in
    /// its namespace, plus every key that has objects in a tools namespace this loop watches.
    fn tool_subjects(
        &self,
        config: &ResolvedTeamToolsConfig,
    ) -> BTreeSet<(TeamName, ToolKey, NamespaceName)> {
        let mut subjects = BTreeSet::new();
        for (team, grant) in &config.grants {
            for key in &grant.allowed {
                subjects.insert((
                    TeamName::new(team.clone()),
                    key.clone(),
                    grant.namespace.clone(),
                ));
            }
        }
        for (namespace, team) in self.deps.store.watched() {
            for key in self.deps.store.keys_in(&namespace) {
                let team = config
                    .grants
                    .iter()
                    .find(|(_, grant)| grant.namespace == namespace)
                    .map_or(team.clone(), |(name, _)| TeamName::new(name.clone()));
                subjects.insert((team, key, namespace.clone()));
            }
        }
        subjects
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one pass's shared state, threaded once"
    )]
    async fn tools(
        &mut self,
        config: &ResolvedTeamToolsConfig,
        teams: &[Team],
        requesters: &[Requester],
        synced: bool,
        mode: FeatureMode,
        reports: &mut BTreeMap<String, TeamReport>,
        invalid: &mut BTreeSet<String>,
        failed: &mut BTreeSet<String>,
    ) {
        let now = SystemTime::now();
        let mut gauges = Vec::new();
        for (team, key, namespace) in self.tool_subjects(config) {
            let facts = self.facts(&namespace);
            let observed = self.deps.namespace_view.facts(&namespace).is_some();
            let labelled = facts
                .labels
                .get(TEAM_TOOLS_NAMESPACE_LABEL)
                .map(String::as_str)
                == Some(team.as_str())
                && !facts.labels.contains_key(WORKSPACE_NAMESPACE_LABEL);
            let watched = self
                .deps
                .store
                .watched()
                .iter()
                .any(|(watched, _)| watched == &namespace);
            let watch = if labelled || watched {
                match self
                    .deps
                    .store
                    .watch_tools_namespace(&team, &namespace)
                    .await
                {
                    Ok(watch) => Some(watch),
                    Err(err) => {
                        tracing::warn!(
                            "feature={FEATURE_ID} team={team} ns={namespace} could not ask for watch access: {err}"
                        );
                        Some(Watch::Syncing)
                    }
                }
            } else {
                None
            };
            let of_team: Vec<&Requester> = requesters
                .iter()
                .filter(|requester| {
                    requester.team.as_ref() == Some(&team) && requester.granted.contains(&key)
                })
                .collect();
            let workload = config
                .catalog
                .iter()
                .find(|entry| entry.key == key)
                .map(|entry| {
                    let kind = match entry.workload.kind {
                        WorkloadKind::Deployment => ToolObjectKind::Deployment,
                        WorkloadKind::StatefulSet => ToolObjectKind::StatefulSet,
                    };
                    (
                        kind,
                        ObjectKey {
                            namespace: namespace.clone(),
                            name: entry.workload.name.clone(),
                        },
                    )
                });
            let replicas = workload
                .as_ref()
                .and_then(|(kind, workload)| self.deps.store.replicas(*kind, workload));
            let memory_key = (team.clone(), key.clone());
            let subject = TeamTool {
                team: team.clone(),
                key: key.clone(),
                namespace: namespace.clone(),
                tools_namespace: observed.then(|| ToolsNamespace {
                    labels: facts.labels.clone(),
                    quotas: self.deps.store.quotas(&namespace),
                }),
                synced: synced && watch.is_none_or(|watch| watch != Watch::Syncing),
                requesters: of_team.len(),
                active: of_team.iter().filter(|requester| requester.active).count(),
                replicas,
                grace_since: self.memory.grace.get(&memory_key).copied(),
            };

            let outcome = if watch == Some(Watch::Forbidden) {
                None
            } else {
                let context = Context::new(teams, &facts, self.deps.dwoc_catalog.as_ref());
                match reconcile_tool(
                    &self.deps.feature,
                    &subject,
                    &context,
                    mode,
                    self.deps.store.as_ref(),
                    workload.clone(),
                )
                .await
                {
                    Ok(outcome) => Some(outcome),
                    Err(err) => {
                        self.deps.metrics.reconciled("error");
                        tracing::warn!(
                            "feature={FEATURE_ID} team={team} tool={key} result=error {err}"
                        );
                        failed.insert(team.to_string());
                        continue;
                    }
                }
            };
            let (state, unbound) = match &outcome {
                Some(outcome) => (outcome.state(), outcome.unbound()),
                None => (
                    TeamToolState::Unbound,
                    Some(weebo_si_team_tools::Unbound::forbidden(&namespace)),
                ),
            };
            self.deps.metrics.reconciled(match &outcome {
                Some(outcome) => tool_result(outcome),
                None => "forbidden",
            });

            let mut replicas_now = replicas.unwrap_or(0);
            if let Some(outcome) = &outcome {
                if let Some(decision) = &outcome.desired.scale {
                    match decision.grace_since {
                        Some(since) => self.memory.grace.insert(memory_key.clone(), since),
                        None => self.memory.grace.remove(&memory_key),
                    };
                } else if !outcome.desired.hold {
                    self.memory.grace.remove(&memory_key);
                }
                if let Some(scale) = &outcome.scale {
                    let written = match &scale.result {
                        Some(Ok(())) => {
                            replicas_now = scale.to;
                            self.deps.metrics.scaled(
                                team.as_str(),
                                key.as_str(),
                                scale.to > scale.from,
                                true,
                            );
                            "written"
                        }
                        Some(Err(err)) => {
                            self.deps.metrics.scaled(
                                team.as_str(),
                                key.as_str(),
                                scale.to > scale.from,
                                false,
                            );
                            tracing::warn!(
                                "feature={FEATURE_ID} team={team} tool={key} scale failed: {err}"
                            );
                            "failed"
                        }
                        None => "not written",
                    };
                    tracing::info!(
                        "feature={FEATURE_ID} mode={mode:?} team={team} tool={key} requesters={} scale={}->{} ({written})",
                        subject.requesters,
                        scale.from,
                        scale.to
                    );
                }
                let summary = outcome.converged.summary();
                if summary != "none" {
                    tracing::info!(
                        "feature={FEATURE_ID} mode={mode:?} team={team} tool={key} requesters={} diff={summary}{}",
                        subject.requesters,
                        if mode == FeatureMode::Enforce {
                            ""
                        } else {
                            " (not written)"
                        }
                    );
                }
                if let Some(StoreError::Failed(err)) = &outcome.converged.error {
                    tracing::warn!(
                        "feature={FEATURE_ID} team={team} tool={key} result=error {err}"
                    );
                }
                for violation in &outcome.desired.team_violations {
                    invalid.insert(format!("team {team}: {violation}"));
                }
            }
            if let Some(unbound) = &unbound {
                tracing::warn!(
                    "feature={FEATURE_ID} team={team} tool={key} result={} {}",
                    unbound.reason(),
                    unbound.message()
                );
            }

            // Up with nobody asking: measured from when it was first seen so, past the grace.
            let grace = config
                .catalog
                .iter()
                .find(|entry| entry.key == key)
                .and_then(|entry| entry.idle_grace_seconds)
                .unwrap_or(config.config.idle_grace_seconds);
            let up_without = if replicas_now > 0 && subject.active == 0 {
                let since = *self
                    .memory
                    .idle_since
                    .entry(memory_key.clone())
                    .or_insert(now);
                now.duration_since(since).unwrap_or(Duration::ZERO)
                    > Duration::from_secs(u64::from(grace))
                        .saturating_add(UP_WITHOUT_REQUESTER_SLACK)
            } else {
                self.memory.idle_since.remove(&memory_key);
                false
            };
            gauges.push(ToolGauges {
                team: team.to_string(),
                tool: key.to_string(),
                replicas: i64::from(replicas_now),
                requesters: i64::try_from(subject.requesters).unwrap_or(i64::MAX),
                up_without_requester: up_without,
            });

            // Only the team's current namespace is reported; a tool being removed from an old one
            // is not the team's state.
            let current = config
                .grants
                .get(team.as_str())
                .is_some_and(|grant| grant.namespace == namespace);
            if current {
                let report = reports
                    .entry(team.to_string())
                    .or_insert_with(|| TeamReport {
                        tools: Vec::new(),
                        ready: Some((
                            true,
                            "Bound".to_string(),
                            format!("tools namespace {namespace} is bound"),
                        )),
                    });
                report.tools.push(TeamToolStatus {
                    key: key.clone(),
                    namespace: namespace.clone(),
                    replicas: replicas_now,
                    requesters: i64::try_from(subject.requesters).unwrap_or(i64::MAX),
                    state,
                });
                let team_invalid = outcome
                    .as_ref()
                    .map(|outcome| outcome.desired.team_violations.clone())
                    .unwrap_or_default();
                if let Some(unbound) = unbound {
                    report.ready = Some((
                        false,
                        unbound.reason().to_string(),
                        unbound.message().to_string(),
                    ));
                } else if !team_invalid.is_empty() {
                    let message = team_invalid
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ");
                    report.ready = Some((
                        false,
                        "Invalid".to_string(),
                        format!("team block ignored: {message}"),
                    ));
                }
            }
        }
        self.deps.metrics.tools(&gauges);
    }

    async fn requester_namespaces(
        &mut self,
        config: &ResolvedTeamToolsConfig,
        teams: &[Team],
        requesters: &[Requester],
        synced: bool,
    ) {
        let tools_namespaces: BTreeSet<NamespaceName> = config
            .grants
            .values()
            .map(|grant| grant.namespace.clone())
            .chain(
                self.deps
                    .store
                    .watched()
                    .into_iter()
                    .map(|(namespace, _)| namespace),
            )
            .collect();
        let mut subjects: BTreeMap<(NamespaceName, ToolKey), usize> = BTreeMap::new();
        for requester in requesters {
            for key in &requester.granted {
                *subjects
                    .entry((requester.namespace.clone(), key.clone()))
                    .or_default() += 1;
            }
        }
        // Client objects left where nobody requests any more.
        for object in self.deps.store.all() {
            if object.selector == weebo_si_chassis::PodSelector::Empty
                && !tools_namespaces.contains(&object.key.namespace)
            {
                subjects
                    .entry((object.key.namespace, object.tool))
                    .or_default();
            }
        }
        let mut no_identity = BTreeSet::new();
        for ((namespace, key), count) in subjects {
            if tools_namespaces.contains(&namespace) {
                continue;
            }
            let mode = self.deps.gate.mode(FeatureId::new(FEATURE_ID), &namespace);
            if mode == FeatureMode::Off {
                continue;
            }
            let facts = self.facts(&namespace);
            let subject = RequesterNamespace {
                namespace: namespace.clone(),
                key: key.clone(),
                username: self
                    .deps
                    .namespace_view
                    .annotation(&namespace, USERNAME_ANNOTATION),
                requesters: count,
                synced,
            };
            let context = Context::new(teams, &facts, self.deps.dwoc_catalog.as_ref());
            let outcome = match reconcile_requester(
                &self.deps.feature,
                &subject,
                &context,
                mode,
                self.deps.store.as_ref(),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    self.deps.metrics.reconciled("error");
                    tracing::warn!(
                        "feature={FEATURE_ID} ns={namespace} tool={key} result=error {err}"
                    );
                    continue;
                }
            };
            self.deps
                .metrics
                .reconciled(converged_result(&outcome.converged));
            let summary = outcome.converged.summary();
            if summary != "none" {
                tracing::info!(
                    "feature={FEATURE_ID} mode={mode:?} ns={namespace} tool={key} diff={summary}"
                );
            }
            if let Some(err) = &outcome.converged.error {
                tracing::warn!("feature={FEATURE_ID} ns={namespace} tool={key} result=error {err}");
            }
            if outcome.desired.no_identity {
                no_identity.insert((namespace.clone(), key.clone()));
                if !self
                    .memory
                    .no_identity
                    .contains(&(namespace.clone(), key.clone()))
                {
                    let note = format!(
                        "no client certificate for team tool {key:?}: namespace {namespace} is not a \
                         workspace namespace with a {USERNAME_ANNOTATION} annotation"
                    );
                    tracing::warn!(
                        "feature={FEATURE_ID} ns={namespace} tool={key} result=no_identity"
                    );
                    for requester in requesters.iter().filter(|requester| {
                        requester.namespace == namespace && requester.granted.contains(&key)
                    }) {
                        publish(
                            &self.recorder,
                            requester.object.as_ref(),
                            true,
                            ReasonCode::TeamToolNoIdentity,
                            note.clone(),
                        )
                        .await;
                    }
                }
            }
        }
        self.memory.no_identity = no_identity;
    }

    async fn requesting_workspaces(&mut self, teams: &[Team], requesters: &[Requester]) {
        let mut seen = HashMap::new();
        for requester in requesters {
            let object = requester.object.as_ref();
            let uid = object.uid().unwrap_or_default();
            let team = requester.team.as_ref().map_or("<none>", TeamName::as_str);
            if requester.dropped.is_empty() {
                // nothing to say
            } else if self.memory.not_granted.get(&uid) != Some(&requester.dropped) {
                self.deps.metrics.reconciled("not_granted");
                tracing::warn!(
                    "feature={FEATURE_ID} ns={} workspace={} team={team} requested={} result=not_granted",
                    requester.namespace,
                    object.name_any(),
                    keys(&requester.dropped)
                );
                for key in &requester.dropped {
                    publish(
                        &self.recorder,
                        object,
                        true,
                        ReasonCode::TeamToolNotGranted,
                        format!(
                            "team tool {:?} is not granted to team {team}; ignored",
                            key.as_str()
                        ),
                    )
                    .await;
                }
            }
            seen.insert(uid, requester.dropped.clone());

            let (Some(id), Some(owner)) = (devworkspace_id(object), devworkspace_owner(object))
            else {
                continue;
            };
            let mut keys_here: BTreeSet<ToolKey> = requester.granted.iter().cloned().collect();
            keys_here.extend(
                self.deps
                    .store
                    .all_in(&requester.namespace)
                    .into_iter()
                    .filter(|existing| {
                        existing.selector
                            == weebo_si_chassis::PodSelector::DevWorkspaceId(id.clone())
                    })
                    .map(|existing| existing.tool),
            );
            let mode = self
                .deps
                .gate
                .mode(FeatureId::new(FEATURE_ID), &requester.namespace);
            let facts = self.facts(&requester.namespace);
            for key in keys_here {
                let subject = RequestingWorkspace {
                    namespace: requester.namespace.clone(),
                    devworkspace_id: id.clone(),
                    owner: owner.clone(),
                    key: key.clone(),
                    attribute: requester.attribute.clone(),
                };
                let context = Context::new(teams, &facts, self.deps.dwoc_catalog.as_ref());
                let outcome = match reconcile_workspace(
                    &self.deps.feature,
                    &subject,
                    &context,
                    mode,
                    self.deps.store.as_ref(),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        self.deps.metrics.reconciled("error");
                        tracing::warn!(
                            "feature={FEATURE_ID} ns={} workspace={} tool={key} result=error {err}",
                            requester.namespace,
                            object.name_any()
                        );
                        continue;
                    }
                };
                self.deps
                    .metrics
                    .reconciled(converged_result(&outcome.converged));
                let summary = outcome.converged.summary();
                if summary != "none" {
                    tracing::info!(
                        "feature={FEATURE_ID} mode={mode:?} ns={} workspace={} tool={key} diff={summary}",
                        requester.namespace,
                        object.name_any()
                    );
                }
                let created = outcome
                    .converged
                    .applied
                    .is_some_and(|applied| applied.created > 0);
                // DWO mounts the client objects only when it builds the pod (RFC 0020, Resolved 11).
                if created && requester.running {
                    publish(&self.recorder, object, true, ReasonCode::TeamToolRestartNeeded,
                        format!("team tool {:?} was added to a running workspace: restart it once to mount its client side", key.as_str())).await;
                }
            }
        }
        self.memory.not_granted = seen;
    }

    /// Write each team's status. `config` `None` clears every team this loop wrote; a team in
    /// `failed` keeps what it has (a pass that errored says nothing new about it).
    async fn write_statuses(
        &mut self,
        config: Option<&ResolvedTeamToolsConfig>,
        mut reports: BTreeMap<String, TeamReport>,
        failed: &BTreeSet<String>,
    ) {
        let api: Api<WeeboSiTeam> = Api::all(self.client.clone());
        if !self.memory.listed {
            // After a restart: the teams carrying this feature's status, so a block removed
            // while the operator was down is still cleared.
            match api.list(&kube::api::ListParams::default()).await {
                Ok(list) => {
                    self.memory.written.extend(
                        list.items
                            .iter()
                            .filter(|team| {
                                team.status.as_ref().is_some_and(|status| {
                                    !status.team_tools.is_empty()
                                        || status
                                            .conditions
                                            .iter()
                                            .any(|condition| condition.type_ == status::CONDITION)
                                })
                            })
                            .map(ResourceExt::name_any),
                    );
                    self.memory.listed = true;
                }
                Err(err) => tracing::warn!("feature={FEATURE_ID} could not list teams: {err}"),
            }
        }
        // A team with a block but no tool still says whether its namespace is usable.
        for team in config.iter().flat_map(|config| config.grants.keys()) {
            reports.entry(team.clone()).or_insert_with(|| TeamReport {
                tools: Vec::new(),
                ready: Some((true, "Bound".to_string(), "no tool allowed".to_string())),
            });
        }
        // A team that lost its block (or the feature turned Off) is cleared once.
        for team in &self.memory.written {
            reports.entry(team.clone()).or_insert_with(|| TeamReport {
                tools: Vec::new(),
                ready: None,
            });
        }
        for (team, report) in reports {
            if failed.contains(&team) {
                continue;
            }
            // `status::write` compares with the live status: a value another writer reverted is
            // put back on the next pass, an unchanged one costs a GET.
            match status::write(&api, &team, &report).await {
                Ok(_) if report.ready.is_none() => {
                    self.memory.written.remove(&team);
                }
                Ok(_) => {
                    self.memory.written.insert(team);
                }
                Err(err) => tracing::warn!(
                    "feature={FEATURE_ID} team={team} could not write its status (retried next pass): {err}"
                ),
            }
        }
    }
}

/// Start the DevWorkspace cache and the loop. The loop holds no lease of its own: the caller
/// starts it only on the leader (RFC 0012).
pub async fn spawn(client: Client, deps: TeamToolsDeps, recorder: Recorder) {
    let resource = devworkspace_resource();
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
    let writer = reflector::store::Writer::<DynamicObject>::new(resource);
    let workspaces = writer.as_reader();
    let stream =
        reflector::reflector(writer, watcher(api, watcher::Config::default())).default_backoff();
    tokio::spawn(weebo_si_runtime::watch::drive(
        "team-tools-devworkspaces",
        stream,
    ));
    let mut state = Loop {
        deps,
        client,
        recorder,
        workspaces,
        memory: Memory::default(),
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TICK);
        let mut last: Option<(u64, Instant)> = None;
        loop {
            interval.tick().await;
            let fingerprint = state.fingerprint();
            let due =
                last.is_none_or(|(previous, at)| previous != fingerprint || at.elapsed() >= RESYNC);
            if due {
                state.pass().await;
                // Taken after the pass: its own writes change the caches, and the next tick
                // should not count them as news.
                last = Some((state.fingerprint(), Instant::now()));
            }
        }
    });
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use serde_json::json;
    use weebo_si_crd::{Selector, TeamTeamTools, TeamToolsConfig};

    use super::*;

    fn team(name: &str, label: &str) -> Team {
        Team {
            name: TeamName::new(name),
            namespace_selector: Selector {
                match_labels: BTreeMap::from([(label.to_string(), "yes".to_string())]),
                ..Selector::default()
            },
        }
    }

    fn config(teams: &[&str]) -> ResolvedTeamToolsConfig {
        let config: TeamToolsConfig =
            serde_json::from_value(json!({"mode": "Enforce", "catalog": []})).unwrap();
        ResolvedTeamToolsConfig {
            config,
            grants: teams
                .iter()
                .map(|team| {
                    let grant: TeamTeamTools =
                        serde_json::from_value(json!({"namespace": format!("{team}-tools")}))
                            .unwrap();
                    ((*team).to_string(), grant)
                })
                .collect(),
        }
    }

    #[test]
    fn a_namespace_matching_two_tool_teams_is_reported_once() {
        let teams = vec![
            team("a", "team-a"),
            team("b", "team-b"),
            team("c", "team-c"),
        ];
        let namespaces = BTreeMap::from([
            (
                NamespaceName::new("both"),
                BTreeMap::from([
                    ("team-a".to_string(), "yes".to_string()),
                    ("team-b".to_string(), "yes".to_string()),
                ]),
            ),
            (
                NamespaceName::new("only-a"),
                BTreeMap::from([("team-a".to_string(), "yes".to_string())]),
            ),
            (
                NamespaceName::new("a-and-toolless-c"),
                BTreeMap::from([
                    ("team-a".to_string(), "yes".to_string()),
                    ("team-c".to_string(), "yes".to_string()),
                ]),
            ),
        ]);
        let found = overlaps(&teams, &config(&["a", "b"]), &namespaces);
        assert_eq!(found.len(), 1);
        assert!(found[0].0.contains("namespace both") && found[0].0.contains("a, b"));
        assert_eq!(found[0].1, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn the_active_rule_follows_the_rfc() {
        let dw = |data: serde_json::Value| -> DynamicObject {
            let mut object: DynamicObject = serde_json::from_value(json!({
                "apiVersion": "workspace.devfile.io/v1alpha2", "kind": "DevWorkspace",
                "metadata": {"name": "w", "namespace": "n"}}))
            .unwrap();
            object.data = data;
            object
        };
        assert!(is_active(&dw(json!({"spec": {"started": true}}))));
        assert!(is_active(&dw(
            json!({"spec": {"started": false}, "status": {"phase": "Running"}})
        )));
        assert!(is_active(&dw(json!({"status": {"phase": "Starting"}}))));
        assert!(!is_active(&dw(
            json!({"spec": {"started": false}, "status": {"phase": "Stopped"}})
        )));
        assert_eq!(
            attribute_of(
                &dw(json!({"spec": {"template": {"attributes": {"k": "buildkit"}}}})),
                "k"
            )
            .as_deref(),
            Some("buildkit")
        );
        assert_eq!(
            attribute_of(
                &dw(json!({"spec": {"template": {"attributes": {"k": "buildkit"}}}})),
                ""
            ),
            None
        );
    }
}
