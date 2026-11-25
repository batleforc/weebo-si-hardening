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

use k8s_openapi::api::apps::v1::StatefulSet;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use kube::api::{Api, ObjectMeta, PostParams};
use serde_json::{Value, json};
use weebo_si_chassis::ObjectKey;
use weebo_si_chassis::managed::Diff;
use weebo_si_crd::{MANAGED_BY_LABEL, NamespaceName, ToolKey};
use weebo_si_envtest_support::EnvTest;
use weebo_si_team_tools::render::from_template;
use weebo_si_team_tools::{SCALE_FIELD_MANAGER, ToolObject, ToolObjectKind, ToolTemplate};
use weebo_si_team_tools_adapters::{Adoption, KubeToolStore, ToolObjectStore};

const TOOLS: &str = "team-weebo-tools";
const WORKSPACE: &str = "dev-ws-alice";

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
        namespace: NamespaceName::new("weebo-si-hardening-templates"),
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
