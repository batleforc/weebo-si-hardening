//! One pass of each reconcile subject: `desired()`, the diff restricted to what the subject
//! owns, and — under `Enforce` only — the writes. Mode-blind `desired()`, mode-aware here, as
//! every reconcile feature of this operator.
//!
//! `hold` writes nothing and deletes nothing. A tools namespace's 403 is reported as
//! [`Unbound::forbidden`] and stops the pass before any `/scale` write.

use weebo_si_chassis::managed::{Applied, Diff, OwnedScope, compute_owned_diff};
use weebo_si_chassis::{Context, DomainError, ObjectKey, PodSelector, ReconcileFeature};
use weebo_si_crd::{FeatureMode, NamespaceName, TeamToolState, ToolKey};
use weebo_si_team_tools::{
    RequesterDesired, RequesterNamespace, RequestingWorkspace, TeamTool, TeamToolsFeature,
    ToolDesired, ToolObject, ToolObjectKind, Unbound, WorkspaceDesired,
};

use crate::objects::{ALL_KINDS, comparable};
use crate::port::{Adoption, StoreError, ToolObjectStore};

/// What the writes of one pass did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Converged {
    /// The diff, desired objects in full (an empty list when held).
    pub diffs: Vec<Diff<ToolObject>>,
    /// The counts, `None` when nothing was written (held, or not `Enforce`).
    pub applied: Option<Applied>,
    /// The write that failed.
    pub error: Option<StoreError>,
}

impl Converged {
    /// `create:Kind/name,…` for the log line; `none` when nothing changes.
    pub fn summary(&self) -> String {
        let lines: Vec<String> = self
            .diffs
            .iter()
            .filter_map(|diff| match diff {
                Diff::Create(object) => Some(format!(
                    "create:{}/{}",
                    object.kind.as_str(),
                    object.key.name
                )),
                Diff::Update(object) => Some(format!(
                    "update:{}/{}",
                    object.kind.as_str(),
                    object.key.name
                )),
                Diff::Delete { key, backend, .. } => {
                    Some(format!("delete:{}/{}", backend.as_str(), key.name))
                }
                Diff::Unchanged(_) => None,
            })
            .collect();
        if lines.is_empty() {
            "none".to_string()
        } else {
            lines.join(",")
        }
    }
}

/// The `/scale` write a tool pass decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleWrite {
    /// The live replicas (0 before the workload exists).
    pub from: i32,
    /// The target.
    pub to: i32,
    /// `None` when not written (not `Enforce`, or the apply failed first).
    pub result: Option<Result<(), StoreError>>,
}

/// One [`TeamTool`] pass.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolOutcome {
    /// What `desired()` decided.
    pub desired: ToolDesired,
    /// The writes.
    pub converged: Converged,
    /// The scale write, if the replicas must move.
    pub scale: Option<ScaleWrite>,
}

impl ToolOutcome {
    /// The state the team status reports: a 403 makes the tool `Unbound`.
    pub fn state(&self) -> TeamToolState {
        if self.unbound().is_some() {
            TeamToolState::Unbound
        } else {
            self.desired.state
        }
    }

    /// Why the tools namespace is not bound, the apiserver's 403 included.
    pub fn unbound(&self) -> Option<Unbound> {
        match (&self.desired.unbound, &self.converged.error) {
            (Some(unbound), _) => Some(unbound.clone()),
            (None, Some(StoreError::Forbidden(namespace))) => Some(Unbound::forbidden(namespace)),
            _ => None,
        }
    }
}

/// One [`RequesterNamespace`] pass.
#[derive(Debug, Clone, PartialEq)]
pub struct RequesterOutcome {
    /// What `desired()` decided.
    pub desired: RequesterDesired,
    /// The writes.
    pub converged: Converged,
}

/// One [`RequestingWorkspace`] pass.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceOutcome {
    /// What `desired()` decided.
    pub desired: WorkspaceDesired,
    /// The writes.
    pub converged: Converged,
}

/// Diff `objects` against what `store` holds of `key` in `namespace` for `owner`, and apply it
/// under `Enforce`.
#[expect(
    clippy::too_many_arguments,
    reason = "private helper shared by the three subjects; a parameter struct would only rename them"
)]
async fn converge(
    store: &dyn ToolObjectStore,
    owner: &PodSelector,
    namespace: &NamespaceName,
    key: &ToolKey,
    objects: &[ToolObject],
    hold: bool,
    mode: FeatureMode,
    adoption: Adoption,
) -> Result<Converged, DomainError> {
    if hold {
        return Ok(Converged::default());
    }
    // One diff per kind: the diff keys on `{namespace, name}`, and a tool's `StatefulSet` and
    // `Service` usually share a name.
    let existing = store.managed(namespace, key);
    let mut diffs: Vec<Diff<ToolObject>> = Vec::new();
    for kind in ALL_KINDS {
        let full = |key: &ObjectKey| {
            objects
                .iter()
                .find(|object| object.kind == kind && &object.key == key)
                .cloned()
        };
        let wanted: Vec<ToolObject> = objects
            .iter()
            .filter(|object| object.kind == kind)
            .map(comparable)
            .collect();
        let live: Vec<ToolObject> = existing
            .iter()
            .filter(|object| object.kind == kind)
            .cloned()
            .collect();
        diffs.extend(
            compute_owned_diff(owner, &wanted, &[], &live)?
                .into_iter()
                .filter_map(|diff| match diff {
                    Diff::Create(object) => full(&object.key).map(Diff::Create),
                    Diff::Update(object) => full(&object.key).map(Diff::Update),
                    other => Some(other),
                }),
        );
    }
    if mode != FeatureMode::Enforce {
        return Ok(Converged {
            diffs,
            applied: None,
            error: None,
        });
    }
    let (applied, error) = match store.apply(&diffs, adoption).await {
        Ok(applied) => (Some(applied), None),
        Err(error) => (None, Some(error)),
    };
    Ok(Converged {
        diffs,
        applied,
        error,
    })
}

/// One pass of a tool: render into the tools namespace, then hold the replicas the scale state
/// machine decided through `/scale`. `workload` is the catalogue entry's workload in the tools
/// namespace.
pub async fn reconcile_tool(
    feature: &TeamToolsFeature,
    subject: &TeamTool,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn ToolObjectStore,
    workload: Option<(ToolObjectKind, ObjectKey)>,
) -> Result<ToolOutcome, DomainError> {
    let desired = ReconcileFeature::<TeamTool>::desired(feature, subject, ctx)?;
    let converged = converge(
        store,
        &subject.owned_selector(),
        &subject.namespace,
        &subject.key,
        &desired.objects,
        desired.hold,
        mode,
        Adoption::Adopt,
    )
    .await?;
    let target = desired
        .scale
        .as_ref()
        .and_then(|decision| decision.write(subject.replicas));
    // A workload this pass creates — or adopts from phase 0, whose replicas the cache could not
    // see — is scaled from the next pass, once the cache holds its live replicas: an adopted
    // tool in use is never scaled down on the strength of a missing number.
    let creates_workload = mode == FeatureMode::Enforce
        && workload.as_ref().is_some_and(|(kind, key)| {
        converged
            .diffs
            .iter()
            .any(|diff| matches!(diff, Diff::Create(object) if object.kind == *kind && &object.key == key))
    });
    let scale = match (target, workload) {
        (Some(_), Some(_)) if creates_workload => None,
        (Some(to), Some((kind, key))) => {
            let result = if mode == FeatureMode::Enforce && converged.error.is_none() {
                Some(store.scale(kind, &key, to).await)
            } else {
                None
            };
            Some(ScaleWrite {
                from: subject.replicas.unwrap_or(0),
                to,
                result,
            })
        }
        _ => None,
    };
    Ok(ToolOutcome {
        desired,
        converged,
        scale,
    })
}

/// One pass of the client side of one key in one workspace namespace. Never adopts.
pub async fn reconcile_requester(
    feature: &TeamToolsFeature,
    subject: &RequesterNamespace,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn ToolObjectStore,
) -> Result<RequesterOutcome, DomainError> {
    let desired = ReconcileFeature::<RequesterNamespace>::desired(feature, subject, ctx)?;
    let converged = converge(
        store,
        &subject.owned_selector(),
        &subject.namespace,
        &subject.key,
        &desired.objects,
        desired.hold,
        mode,
        Adoption::Never,
    )
    .await?;
    Ok(RequesterOutcome { desired, converged })
}

/// One pass of one workspace's egress policy towards one tool. Never adopts.
pub async fn reconcile_workspace(
    feature: &TeamToolsFeature,
    subject: &RequestingWorkspace,
    ctx: &Context<'_>,
    mode: FeatureMode,
    store: &dyn ToolObjectStore,
) -> Result<WorkspaceOutcome, DomainError> {
    let desired = ReconcileFeature::<RequestingWorkspace>::desired(feature, subject, ctx)?;
    let converged = converge(
        store,
        &subject.owned_selector(),
        &subject.namespace,
        &subject.key,
        &desired.objects,
        desired.hold,
        mode,
        Adoption::Never,
    )
    .await?;
    Ok(WorkspaceOutcome { desired, converged })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, RwLock};

    use serde_json::json;
    use weebo_si_chassis::NamespaceFacts;
    use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
    use weebo_si_crd::{
        FeatureMode, ResolvedTeamToolsConfig, Selector, TEAM_TOOLS_NAMESPACE_LABEL, Team, TeamName,
        TeamTeamTools, TeamToolsConfig, ToolEntry,
    };
    use weebo_si_team_tools::port::testing::{FakeClock, FakeTemplateStore};
    use weebo_si_team_tools::{ToolTemplate, ToolsNamespace};

    use super::*;
    use crate::objects::{apply_document, from_live};
    use crate::port::BoxFuture;

    const TEMPLATES: &str = "weebo-si-hardening-templates";
    const TOOLS: &str = "team-weebo-tools";

    /// Applies into memory, through the same document and read-back the real store uses.
    #[derive(Default)]
    struct MemoryStore {
        live: Mutex<Vec<(ToolObjectKind, serde_json::Value)>>,
        scaled: Mutex<Vec<i32>>,
        forbid: bool,
    }

    impl ToolObjectStore for MemoryStore {
        fn managed(&self, namespace: &NamespaceName, tool: &ToolKey) -> Vec<ToolObject> {
            self.live
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(kind, document)| {
                    from_live(*kind, &serde_json::from_value(document.clone()).unwrap())
                })
                .filter(|object| &object.key.namespace == namespace && &object.tool == tool)
                .collect()
        }

        fn apply<'a>(
            &'a self,
            diffs: &'a [Diff<ToolObject>],
            _adoption: Adoption,
        ) -> BoxFuture<'a, Result<Applied, StoreError>> {
            Box::pin(async move {
                if self.forbid {
                    return Err(StoreError::Forbidden(NamespaceName::new(TOOLS)));
                }
                let mut live = self.live.lock().unwrap();
                for diff in diffs {
                    match diff {
                        Diff::Create(object) | Diff::Update(object) => {
                            live.retain(|(kind, document)| {
                                (*kind, &document["metadata"]["name"])
                                    != (object.kind, &json!(object.key.name))
                            });
                            live.push((object.kind, apply_document(object, None)));
                        }
                        Diff::Delete { key, backend, .. } => {
                            live.retain(|(kind, document)| {
                                (*kind, &document["metadata"]["name"])
                                    != (*backend, &json!(key.name))
                            });
                        }
                        Diff::Unchanged(_) => {}
                    }
                }
                Ok(weebo_si_chassis::managed::tally(diffs))
            })
        }

        fn scale<'a>(
            &'a self,
            _kind: ToolObjectKind,
            _workload: &'a ObjectKey,
            replicas: i32,
        ) -> BoxFuture<'a, Result<(), StoreError>> {
            Box::pin(async move {
                self.scaled.lock().unwrap().push(replicas);
                Ok(())
            })
        }
    }

    fn template(kind: &str, name: &str, body: serde_json::Value) -> ToolTemplate {
        ToolTemplate {
            kind: kind.to_string(),
            name: name.to_string(),
            namespace: NamespaceName::new(TEMPLATES),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            body,
        }
    }

    fn templates() -> FakeTemplateStore {
        FakeTemplateStore {
            templates: vec![
                template(
                    "StatefulSet",
                    "buildkitd",
                    json!({"spec": {"replicas": 0, "serviceName": "buildkitd",
                        "selector": {"matchLabels": {"app": "buildkitd"}},
                        "template": {"metadata": {"labels": {"app": "buildkitd"}},
                            "spec": {"automountServiceAccountToken": false,
                                "containers": [{"name": "buildkitd", "image": "moby/buildkit"}]}}}}),
                ),
                template(
                    "Service",
                    "buildkitd",
                    json!({"spec": {"selector": {"app": "buildkitd"},
                        "ports": [{"port": 1234, "protocol": "TCP", "targetPort": 1234}]}}),
                ),
            ],
        }
    }

    fn feature() -> TeamToolsFeature {
        let entry: ToolEntry = serde_json::from_value(json!({
            "key": "buildkit",
            "workload": {"kind": "StatefulSet", "name": "buildkitd"},
            "service": {"name": "buildkitd", "port": 1234},
            "toolTemplates": [
                {"kind": "StatefulSet", "name": "buildkitd", "namespace": TEMPLATES},
                {"kind": "Service", "name": "buildkitd", "namespace": TEMPLATES},
            ],
        }))
        .unwrap();
        let config: TeamToolsConfig = serde_json::from_value(json!({
            "mode": "Enforce", "catalog": [entry],
        }))
        .unwrap();
        let grant: TeamTeamTools = serde_json::from_value(json!({
            "namespace": TOOLS, "allowed": ["buildkit"],
        }))
        .unwrap();
        let resolved = ResolvedTeamToolsConfig {
            config,
            grants: BTreeMap::from([("weebo".to_string(), grant)]),
        };
        TeamToolsFeature::new(
            Arc::new(RwLock::new(Some(resolved))),
            Arc::new(templates()),
            Arc::new(FakeClock::at(1_000)),
            NamespaceName::new("weebo-si-hardening"),
            NamespaceName::new(TEMPLATES),
            Vec::new(),
        )
    }

    fn tool(requesters: usize, active: usize, replicas: Option<i32>) -> TeamTool {
        TeamTool {
            team: TeamName::new("weebo"),
            key: ToolKey::new("buildkit"),
            namespace: NamespaceName::new(TOOLS),
            tools_namespace: Some(ToolsNamespace {
                labels: BTreeMap::from([(
                    TEAM_TOOLS_NAMESPACE_LABEL.to_string(),
                    "weebo".to_string(),
                )]),
                quotas: vec![BTreeMap::from([(
                    "limits.memory".to_string(),
                    "12Gi".to_string(),
                )])],
            }),
            synced: true,
            requesters,
            active,
            replicas,
            grace_since: None,
        }
    }

    fn workload() -> Option<(ToolObjectKind, ObjectKey)> {
        Some((
            ToolObjectKind::StatefulSet,
            ObjectKey {
                namespace: NamespaceName::new(TOOLS),
                name: "buildkitd".to_string(),
            },
        ))
    }

    async fn run(store: &MemoryStore, subject: &TeamTool, mode: FeatureMode) -> ToolOutcome {
        let teams = vec![Team {
            name: TeamName::new("weebo"),
            namespace_selector: Selector {
                match_labels: BTreeMap::from([("weebo.io/team".to_string(), "weebo".to_string())]),
                ..Selector::default()
            },
        }];
        let facts = NamespaceFacts::default();
        let catalog = FakeDwocCatalog::new(std::iter::empty());
        let ctx = Context::new(&teams, &facts, &catalog);
        reconcile_tool(&feature(), subject, &ctx, mode, store, workload())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_requester_renders_then_scales_from_the_next_pass() {
        let store = MemoryStore::default();
        let first = run(&store, &tool(1, 1, None), FeatureMode::Enforce).await;
        assert!(
            first
                .converged
                .summary()
                .contains("create:StatefulSet/buildkitd")
        );
        assert!(
            first
                .converged
                .summary()
                .contains("create:CiliumNetworkPolicy/weebo-team-tool-buildkit-ingress")
        );
        // Created at 0; scaled from the next pass, once the cache holds the workload.
        assert_eq!(first.scale, None);

        let second = run(&store, &tool(1, 1, Some(0)), FeatureMode::Enforce).await;
        assert_eq!(second.converged.summary(), "none");
        assert_eq!(
            second.scale.as_ref().map(|scale| (scale.from, scale.to)),
            Some((0, 1))
        );
        assert_eq!(*store.scaled.lock().unwrap(), vec![1]);

        let third = run(&store, &tool(1, 1, Some(1)), FeatureMode::Enforce).await;
        assert_eq!(third.scale, None);
    }

    #[tokio::test]
    async fn dry_run_diffs_and_writes_nothing() {
        let store = MemoryStore::default();
        let outcome = run(&store, &tool(1, 1, None), FeatureMode::DryRun).await;
        assert_ne!(outcome.converged.summary(), "none");
        assert_eq!(outcome.converged.applied, None);
        assert_eq!(
            outcome
                .scale
                .as_ref()
                .and_then(|scale| scale.result.clone()),
            None
        );
        assert!(store.live.lock().unwrap().is_empty());
        assert!(store.scaled.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_requester_left_deletes_the_rendered_objects() {
        let store = MemoryStore::default();
        run(&store, &tool(1, 0, None), FeatureMode::Enforce).await;
        assert!(!store.live.lock().unwrap().is_empty());
        let removed = run(&store, &tool(0, 0, Some(0)), FeatureMode::Enforce).await;
        assert!(removed.converged.summary().starts_with("delete:"));
        assert!(store.live.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unsynced_namespace_holds_everything() {
        let store = MemoryStore::default();
        run(&store, &tool(1, 0, None), FeatureMode::Enforce).await;
        let before = store.live.lock().unwrap().len();
        let mut unsynced = tool(0, 0, Some(1));
        unsynced.synced = false;
        let held = run(&store, &unsynced, FeatureMode::Enforce).await;
        assert_eq!(held.state(), TeamToolState::Held);
        assert_eq!(held.converged, Converged::default());
        assert_eq!(held.scale, None);
        assert_eq!(store.live.lock().unwrap().len(), before);
    }

    #[tokio::test]
    async fn a_403_is_unbound_and_never_scales() {
        let store = MemoryStore {
            forbid: true,
            ..MemoryStore::default()
        };
        let outcome = run(&store, &tool(1, 1, None), FeatureMode::Enforce).await;
        assert_eq!(outcome.state(), TeamToolState::Unbound);
        assert_eq!(
            outcome.unbound().map(|unbound| unbound.reason()),
            Some("Forbidden")
        );
        assert_eq!(
            outcome
                .scale
                .as_ref()
                .and_then(|scale| scale.result.clone()),
            None
        );
        assert!(store.scaled.lock().unwrap().is_empty());
    }
}
