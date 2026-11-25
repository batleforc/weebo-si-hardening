//! Proves RFC 0020's object store against a real, ephemeral apiserver: the one-writer rule on
//! `spec.replicas`, adoption of phase-0 objects in a tools namespace (and never in a workspace
//! namespace), and that a delete never reaches an object without `managed-by`.
//!
//! The store is driven directly with rendered objects: envtest serves neither Cilium's nor
//! cert-manager's CRD, so a whole tool pass (which renders a `CiliumNetworkPolicy`) is the kind
//! e2e's to run.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Service};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::CustomResourceExt;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use serde_json::{Value, json};
use weebo_si_chassis::ObjectKey;
use weebo_si_chassis::managed::Diff;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, NamespaceFacts};
use weebo_si_crd::{
    FeatureMode, MANAGED_BY_LABEL, NamespaceName, ResolvedTeamToolsConfig, Selector,
    TEAM_TOOLS_NAMESPACE_LABEL, Team, TeamName, TeamTeamTools, TeamToolState, TeamToolStatus,
    TeamToolsConfig, ToolKey, WeeboSiTeam,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_team_tools::port::testing::{FakeClock, FakeTemplateStore};
use weebo_si_team_tools::render::from_template;
use weebo_si_team_tools::{
    SCALE_FIELD_MANAGER, TeamTool, TeamToolsFeature, ToolObject, ToolObjectKind, ToolTemplate,
    ToolsNamespace,
};
use weebo_si_team_tools_adapters::controller::teardown;
use weebo_si_team_tools_adapters::status::{self, TeamReport};
use weebo_si_team_tools_adapters::{
    Adoption, KubeToolStore, ToolObjectStore, ToolOutcome, reconcile_tool,
};

const TOOLS: &str = "team-weebo-tools";
const WORKSPACE: &str = "dev-ws-alice";
const TEMPLATES: &str = "weebo-si-hardening-templates";

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

async fn namespace(client: &kube::Client, name: &str) {
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        )
        .await
        .unwrap();
}

fn statefulset_body(image: &str, annotations: Value) -> Value {
    json!({"spec": {
        "replicas": 0,
        "serviceName": "buildkitd",
        "selector": {"matchLabels": {"app": "buildkitd"}},
        "template": {
            "metadata": {"labels": {"app": "buildkitd"}, "annotations": annotations},
            "spec": {"automountServiceAccountToken": false,
                     "containers": [{"name": "buildkitd", "image": image}]},
        },
    }})
}

fn rendered(kind: &str, name: &str, namespace: &str, body: Value) -> ToolObject {
    let template = ToolTemplate {
        kind: kind.to_string(),
        name: name.to_string(),
        namespace: NamespaceName::new(TEMPLATES),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        body,
    };
    from_template(
        &template,
        &NamespaceName::new(namespace),
        &ToolKey::new("buildkit"),
    )
    .unwrap()
}

fn key(namespace: &str, name: &str) -> ObjectKey {
    ObjectKey {
        namespace: NamespaceName::new(namespace),
        name: name.to_string(),
    }
}

async fn statefulset(client: &kube::Client) -> StatefulSet {
    Api::<StatefulSet>::namespaced(client.clone(), TOOLS)
        .get("buildkitd")
        .await
        .unwrap()
}

fn replicas_owners(statefulset: &StatefulSet) -> Vec<String> {
    statefulset
        .metadata
        .managed_fields
        .iter()
        .flatten()
        .filter(|entry| {
            entry
                .fields_v1
                .as_ref()
                .is_some_and(|fields| fields.0.pointer("/f:spec/f:replicas").is_some())
        })
        .filter_map(|entry| entry.manager.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[tokio::test]
async fn a_template_update_never_resets_replicas() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().unwrap();
    namespace(&client, TOOLS).await;
    let store = KubeToolStore::spawn(client.clone(), false, false)
        .await
        .unwrap();

    let first = rendered(
        "StatefulSet",
        "buildkitd",
        TOOLS,
        statefulset_body("moby/buildkit:v0.35.0", json!({"weebo.io/drop-me": "x"})),
    );
    assert!(first.body.pointer("/spec/replicas").is_none());
    store
        .apply(&[Diff::Create(first)], Adoption::Adopt)
        .await
        .unwrap();
    let created = statefulset(&client).await;
    assert_eq!(created.spec.as_ref().unwrap().replicas, Some(0));
    assert_eq!(
        replicas_owners(&created),
        vec![SCALE_FIELD_MANAGER.to_string()]
    );

    store
        .scale(ToolObjectKind::StatefulSet, &key(TOOLS, "buildkitd"), 1)
        .await
        .unwrap();
    assert_eq!(statefulset(&client).await.spec.unwrap().replicas, Some(1));

    // The template moves on: a new image, and an annotation it no longer carries.
    let second = rendered(
        "StatefulSet",
        "buildkitd",
        TOOLS,
        statefulset_body("moby/buildkit:v0.35.1", json!({})),
    );
    store
        .apply(&[Diff::Update(second)], Adoption::Adopt)
        .await
        .unwrap();
    let updated = statefulset(&client).await;
    let spec = updated.spec.as_ref().unwrap();
    assert_eq!(spec.replicas, Some(1), "a template update reset replicas");
    let pod = spec.template.spec.as_ref().unwrap();
    assert_eq!(
        pod.containers[0].image.as_deref(),
        Some("moby/buildkit:v0.35.1")
    );
    assert!(
        spec.template
            .metadata
            .as_ref()
            .and_then(|meta| meta.annotations.as_ref())
            .is_none_or(|annotations| !annotations.contains_key("weebo.io/drop-me")),
        "a field the template dropped must go"
    );
    assert_eq!(
        replicas_owners(&updated),
        vec![SCALE_FIELD_MANAGER.to_string()]
    );
}

#[tokio::test]
async fn a_phase_zero_object_is_adopted_in_place() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().unwrap();
    namespace(&client, TOOLS).await;
    let mut phase_zero: StatefulSet = serde_json::from_value(json!({
        "apiVersion": "apps/v1", "kind": "StatefulSet",
        "metadata": {"name": "buildkitd", "namespace": TOOLS},
    }))
    .unwrap();
    let mut body = statefulset_body("moby/buildkit:v0.35.1", json!({}));
    body["spec"]["replicas"] = json!(1);
    phase_zero.spec = Some(serde_json::from_value(body["spec"].clone()).unwrap());
    let before = Api::<StatefulSet>::namespaced(client.clone(), TOOLS)
        .create(&PostParams::default(), &phase_zero)
        .await
        .unwrap();

    let store = KubeToolStore::spawn(client.clone(), false, false)
        .await
        .unwrap();
    let desired = rendered(
        "StatefulSet",
        "buildkitd",
        TOOLS,
        statefulset_body("moby/buildkit:v0.35.1", json!({})),
    );
    store
        .apply(&[Diff::Create(desired)], Adoption::Adopt)
        .await
        .unwrap();
    let after = statefulset(&client).await;
    assert_eq!(
        after.metadata.uid, before.metadata.uid,
        "never delete-then-create"
    );
    assert_eq!(
        after.spec.unwrap().replicas,
        Some(1),
        "adoption keeps the replicas"
    );
    assert!(
        after
            .metadata
            .labels
            .unwrap()
            .contains_key(MANAGED_BY_LABEL)
    );
}

#[tokio::test]
async fn a_workspace_object_without_managed_by_is_never_adopted_nor_deleted() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().unwrap();
    namespace(&client, WORKSPACE).await;
    let configmaps = Api::<ConfigMap>::namespaced(client.clone(), WORKSPACE);
    let users: ConfigMap = serde_json::from_value(json!({
        "metadata": {"name": "weebo-team-tool-buildkit"},
        "data": {"mine": "yes"},
    }))
    .unwrap();
    configmaps
        .create(&PostParams::default(), &users)
        .await
        .unwrap();

    let store = KubeToolStore::spawn(client.clone(), false, false)
        .await
        .unwrap();
    let desired = rendered(
        "ConfigMap",
        "weebo-team-tool-buildkit",
        WORKSPACE,
        json!({"data": {"BUILDKIT_HOST": "tcp://buildkitd.team-weebo-tools.svc:1234"}}),
    );
    store
        .apply(&[Diff::Create(desired)], Adoption::Never)
        .await
        .unwrap();
    let kept = configmaps.get("weebo-team-tool-buildkit").await.unwrap();
    assert_eq!(kept.data, users.data);
    assert!(kept.metadata.labels.is_none());

    store
        .apply(
            &[Diff::Delete {
                key: key(WORKSPACE, "weebo-team-tool-buildkit"),
                backend: ToolObjectKind::ConfigMap,
                uid: None,
            }],
            Adoption::Never,
        )
        .await
        .unwrap();
    assert!(
        configmaps
            .get_opt("weebo-team-tool-buildkit")
            .await
            .unwrap()
            .is_some()
    );
}

/// A `CiliumNetworkPolicy` CRD that keeps whatever it is given: enough for a whole tool pass,
/// which renders an ingress policy.
fn cilium_crd() -> CustomResourceDefinition {
    serde_json::from_value(json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "ciliumnetworkpolicies.cilium.io"},
        "spec": {
            "group": "cilium.io",
            "scope": "Namespaced",
            "names": {"plural": "ciliumnetworkpolicies", "singular": "ciliumnetworkpolicy",
                      "kind": "CiliumNetworkPolicy", "listKind": "CiliumNetworkPolicyList"},
            "versions": [{"name": "v2", "served": true, "storage": true,
                "schema": {"openAPIV3Schema": {"type": "object",
                    "x-kubernetes-preserve-unknown-fields": true}}}],
        },
    }))
    .unwrap()
}

async fn install(client: &kube::Client, crd: CustomResourceDefinition) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let name = crd.metadata.name.clone().unwrap();
    crds.patch(
        &name,
        &PatchParams::apply("envtest").force(),
        &Patch::Apply(&crd),
    )
    .await
    .unwrap();
    for _ in 0..60 {
        let established = crds
            .get(&name)
            .await
            .ok()
            .and_then(|crd| crd.status)
            .and_then(|status| status.conditions)
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|c| c.type_ == "Established" && c.status == "True")
            });
        if established {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("{name} never became established");
}

fn template(kind: &str, name: &str, body: Value) -> ToolTemplate {
    ToolTemplate {
        kind: kind.to_string(),
        name: name.to_string(),
        namespace: NamespaceName::new(TEMPLATES),
        labels: BTreeMap::new(),
        annotations: BTreeMap::new(),
        body,
    }
}

fn feature(templates: Vec<ToolTemplate>) -> TeamToolsFeature {
    let config: TeamToolsConfig = serde_json::from_value(json!({
        "mode": "Enforce",
        "catalog": [{
            "key": "buildkit",
            "workload": {"kind": "StatefulSet", "name": "buildkitd"},
            "service": {"name": "buildkitd", "port": 1234},
            "toolTemplates": [
                {"kind": "StatefulSet", "name": "buildkitd", "namespace": TEMPLATES},
                {"kind": "Service", "name": "buildkitd", "namespace": TEMPLATES},
            ],
        }],
    }))
    .unwrap();
    let grant: TeamTeamTools =
        serde_json::from_value(json!({"namespace": TOOLS, "allowed": ["buildkit"]})).unwrap();
    TeamToolsFeature::new(
        Arc::new(RwLock::new(Some(ResolvedTeamToolsConfig {
            config,
            grants: BTreeMap::from([("weebo".to_string(), grant)]),
        }))),
        Arc::new(FakeTemplateStore { templates }),
        Arc::new(FakeClock::at(1_000)),
        NamespaceName::new("weebo-si-hardening"),
        NamespaceName::new(TEMPLATES),
        Vec::new(),
    )
}

fn templates() -> Vec<ToolTemplate> {
    vec![
        template(
            "StatefulSet",
            "buildkitd",
            statefulset_body("moby/buildkit:v0.35.1", json!({})),
        ),
        template(
            "Service",
            "buildkitd",
            json!({"spec": {"selector": {"app": "buildkitd"},
                "ports": [{"port": 1234, "protocol": "TCP", "targetPort": 1234}]}}),
        ),
    ]
}

fn tool(requesters: usize, replicas: Option<i32>) -> TeamTool {
    TeamTool {
        team: TeamName::new("weebo"),
        key: ToolKey::new("buildkit"),
        namespace: NamespaceName::new(TOOLS),
        tools_namespace: Some(ToolsNamespace {
            labels: BTreeMap::from([(TEAM_TOOLS_NAMESPACE_LABEL.to_string(), "weebo".to_string())]),
            quotas: vec![BTreeMap::from([(
                "limits.memory".to_string(),
                "12Gi".to_string(),
            )])],
        }),
        synced: true,
        requesters,
        active: requesters,
        replicas,
        grace_since: None,
    }
}

async fn pass(
    feature: &TeamToolsFeature,
    store: &KubeToolStore,
    subject: &TeamTool,
) -> ToolOutcome {
    let teams = vec![Team {
        name: TeamName::new("weebo"),
        namespace_selector: Selector::default(),
    }];
    let facts = NamespaceFacts::default();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);
    let workload = Some((ToolObjectKind::StatefulSet, key(TOOLS, "buildkitd")));
    reconcile_tool(
        feature,
        subject,
        &context,
        FeatureMode::Enforce,
        store,
        workload,
    )
    .await
    .unwrap()
}

async fn wait_for<F: Fn() -> bool>(what: &str, check: F) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn an_invalid_entry_keeps_what_is_rendered_and_off_deletes_only_ours() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().unwrap();
    install(&client, cilium_crd()).await;
    namespace(&client, TOOLS).await;
    let store = KubeToolStore::spawn(client.clone(), true, false)
        .await
        .unwrap();
    store
        .watch_tools_namespace(&TeamName::new("weebo"), &NamespaceName::new(TOOLS))
        .await
        .unwrap();
    wait_for("the tools namespace watch", || !store.watched().is_empty()).await;

    let first = pass(&feature(templates()), &store, &tool(1, None)).await;
    assert_eq!(first.converged.error, None);
    assert_eq!(first.converged.applied.unwrap().created, 3);
    wait_for("the rendered objects in the caches", || {
        store.all_in(&NamespaceName::new(TOOLS)).len() == 3
    })
    .await;

    // The Service template disappears: the entry is invalid, and nothing rendered goes.
    let broken = pass(
        &feature(templates()[..1].to_vec()),
        &store,
        &tool(1, Some(0)),
    )
    .await;
    assert_eq!(broken.state(), TeamToolState::Invalid);
    assert_eq!(broken.converged.diffs.len(), 0);
    assert!(
        Api::<Service>::namespaced(client.clone(), TOOLS)
            .get_opt("buildkitd")
            .await
            .unwrap()
            .is_some()
    );

    // `mode: Off`: every managed object goes, a foreign one stays.
    let foreign: ConfigMap =
        serde_json::from_value(json!({"metadata": {"name": "admins-own"}})).unwrap();
    Api::<ConfigMap>::namespaced(client.clone(), TOOLS)
        .create(&PostParams::default(), &foreign)
        .await
        .unwrap();
    let applied = teardown(&store).await;
    assert_eq!(applied.deleted, 3);
    assert!(
        Api::<StatefulSet>::namespaced(client.clone(), TOOLS)
            .get_opt("buildkitd")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        Api::<ConfigMap>::namespaced(client.clone(), TOOLS)
            .get_opt("admins-own")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn the_team_status_keeps_identitys_condition() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().unwrap();
    install(&client, WeeboSiTeam::crd()).await;
    let teams: Api<WeeboSiTeam> = Api::all(client.clone());
    let team: WeeboSiTeam = serde_json::from_value(json!({
        "apiVersion": "hardening.weebo.io/v1alpha1", "kind": "WeeboSiTeam",
        "metadata": {"name": "weebo"},
        "spec": {"namespaceSelector": {"matchLabels": {"weebo.io/team": "weebo"}}},
    }))
    .unwrap();
    teams.create(&PostParams::default(), &team).await.unwrap();
    // Identity's write: a merge patch of its own condition.
    teams
        .patch_status(
            "weebo",
            &PatchParams::default(),
            &Patch::Merge(json!({"status": {"conditions": [{
                "type": "Ready", "status": "True", "reason": "AsExpected", "message": "",
                "lastTransitionTime": "2026-11-25T00:00:00Z"}]}})),
        )
        .await
        .unwrap();

    let report = TeamReport {
        tools: vec![TeamToolStatus {
            key: ToolKey::new("buildkit"),
            namespace: NamespaceName::new(TOOLS),
            replicas: 1,
            requesters: 2,
            state: TeamToolState::Running,
        }],
        ready: Some((true, "Bound".to_string(), "bound".to_string())),
    };
    assert!(status::write(&teams, "weebo", &report).await.unwrap());
    let written = teams.get_status("weebo").await.unwrap().status.unwrap();
    let types: Vec<&str> = written
        .conditions
        .iter()
        .map(|c| c.type_.as_str())
        .collect();
    assert_eq!(types, vec!["Ready", status::CONDITION]);
    assert_eq!(written.team_tools, report.tools);

    let cleared = TeamReport {
        tools: Vec::new(),
        ready: None,
    };
    assert!(status::write(&teams, "weebo", &cleared).await.unwrap());
    let written = teams.get_status("weebo").await.unwrap().status.unwrap();
    let types: Vec<&str> = written
        .conditions
        .iter()
        .map(|c| c.type_.as_str())
        .collect();
    assert_eq!(types, vec!["Ready"]);
    assert!(written.team_tools.is_empty());
    assert!(!status::write(&teams, "gone", &cleared).await.unwrap());
}
