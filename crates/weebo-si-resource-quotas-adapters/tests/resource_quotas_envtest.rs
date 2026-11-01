//! Proves RFC 0014's adapters against a real, ephemeral apiserver: what the stores read and write,
//! that an invalid profile keeps the objects a namespace already has, that a foreign quota is
//! counted and never touched, and that `mode: Off` removes exactly what this feature wrote.
//!
//! Each test calls `weebo_si_resource_quotas::{reconcile, teardown}` directly, not the watch loop.
//! There is no controller-manager here, so no quota controller fills `status`, and the quota
//! admission plugin enforces nothing until it has: whether a pod over quota is refused, and the
//! saturation band, are the kind e2e's and the unit tests' to check.

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

use k8s_openapi::api::core::v1::{LimitRange, Namespace, ResourceQuota};
use kube::api::{Api, ObjectMeta, PostParams};
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, NamespaceFacts};
use weebo_si_crd::{
    FeatureMode, MANAGED_BY_LABEL, NamespaceName, OnNotGranted, PROFILE_LABEL, QuotaCatalog,
    QuotaGrant, QuotaNamespaceSelection, QuotaProfile, QuotaProfileKey, Resolved,
    ResolvedResourceQuotasConfig, ResourceQuotasConfig, Selector, Team, TeamName, TemplateRef,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_resource_quotas::{
    ManagedQuotaStore, NamespaceSubject, ReconcileOutcome, ReconcileResult, ResourceQuotasFeature,
};
use weebo_si_resource_quotas_adapters::{KubeManagedQuotaStore, KubeQuotaTemplateStore};

const TEMPLATES: &str = "weebo-si-hardening-templates";

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

async fn create_namespace(client: &kube::Client, name: &str) {
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(BTreeMap::from([(
                        "weebo.io/team".to_string(),
                        "team-1".to_string(),
                    )])),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        )
        .await
        .unwrap();
}

async fn create<K>(client: &kube::Client, namespace: &str, object: serde_json::Value)
where
    K: kube::Resource<DynamicType = (), Scope = kube::core::NamespaceResourceScope>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + serde::Serialize,
{
    let object: K = serde_json::from_value(object).unwrap();
    Api::<K>::namespaced(client.clone(), namespace)
        .create(&PostParams::default(), &object)
        .await
        .unwrap();
}

/// The RFC's own templates, plus a broken profile: a compute quota with no `LimitRange`.
async fn templates(client: &kube::Client) {
    create_namespace(client, TEMPLATES).await;
    create::<ResourceQuota>(
        client,
        TEMPLATES,
        serde_json::json!({
            "metadata": {"name": "quota-standard"},
            "spec": {"hard": {"requests.cpu": "4", "pods": "20", "services.nodeports": "0"}},
        }),
    )
    .await;
    create::<ResourceQuota>(
        client,
        TEMPLATES,
        serde_json::json!({
            "metadata": {"name": "quota-large"},
            "spec": {"hard": {"requests.cpu": "8", "pods": "40", "services.nodeports": "0"}},
        }),
    )
    .await;
    create::<LimitRange>(
        client,
        TEMPLATES,
        serde_json::json!({
            "metadata": {"name": "limits-standard"},
            "spec": {"limits": [{
                "type": "Container",
                "defaultRequest": {"cpu": "100m", "memory": "256Mi"},
                "default": {"cpu": "1", "memory": "1Gi"},
                "max": {"cpu": "4", "memory": "8Gi"},
            }]},
        }),
    )
    .await;
}

fn reference(name: &str) -> TemplateRef {
    TemplateRef {
        name: name.to_string(),
        namespace: NamespaceName::new(TEMPLATES),
    }
}

fn key(raw: &str) -> QuotaProfileKey {
    QuotaProfileKey::new(raw)
}

fn config() -> ResolvedResourceQuotasConfig {
    Resolved::without_teams(ResourceQuotasConfig {
        mode: FeatureMode::Enforce,
        namespace_selector: None,
        catalog: QuotaCatalog::new(vec![
            QuotaProfile {
                key: key("standard"),
                quota_ref: Some(reference("quota-standard")),
                limit_range_ref: Some(reference("limits-standard")),
            },
            QuotaProfile {
                key: key("large"),
                quota_ref: Some(reference("quota-large")),
                limit_range_ref: Some(reference("limits-standard")),
            },
            QuotaProfile {
                key: key("broken"),
                quota_ref: Some(reference("quota-large")),
                limit_range_ref: None,
            },
        ]),
        default: key("standard"),
        namespace_selection: QuotaNamespaceSelection::default(),
        on_not_granted: OnNotGranted::Default,
    })
    .with_grants(BTreeMap::from([(
        "team-1".to_string(),
        QuotaGrant {
            allowed: vec![key("standard"), key("large"), key("broken")],
            default: key("standard"),
        },
    )]))
}

struct Rig {
    feature: ResourceQuotasFeature,
    store: KubeManagedQuotaStore,
}

async fn rig(client: &kube::Client) -> Rig {
    templates(client).await;
    let template_store =
        KubeQuotaTemplateStore::spawn(client.clone(), &NamespaceName::new(TEMPLATES))
            .await
            .unwrap();
    // The reflectors list asynchronously after the namespace's objects were created.
    tokio::time::sleep(Duration::from_millis(500)).await;
    Rig {
        feature: ResourceQuotasFeature::new(
            Arc::new(RwLock::new(Some(config()))),
            Arc::new(template_store),
            NamespaceName::new(TEMPLATES),
        ),
        store: KubeManagedQuotaStore::spawn(client.clone()).await.unwrap(),
    }
}

async fn pass(rig: &Rig, namespace: &str, annotation: Option<&str>) -> ReconcileOutcome {
    let teams = vec![Team {
        name: TeamName::new("team-1"),
        namespace_selector: Selector {
            match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
            match_expressions: Vec::new(),
        },
    }];
    let facts = NamespaceFacts {
        labels: BTreeMap::from([("weebo.io/team".to_string(), "team-1".to_string())]),
        selection_annotation: None,
    };
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let outcome = weebo_si_resource_quotas::reconcile(
        &rig.feature,
        &NamespaceSubject {
            namespace: NamespaceName::new(namespace),
            annotation: annotation.map(str::to_string),
        },
        &Context::new(&teams, &facts, &catalog),
        FeatureMode::Enforce,
        &rig.store,
    )
    .await
    .unwrap();
    // Let the managed-object watch see what was just written.
    tokio::time::sleep(Duration::from_millis(500)).await;
    outcome
}

async fn quota(client: &kube::Client, namespace: &str, name: &str) -> Option<ResourceQuota> {
    Api::<ResourceQuota>::namespaced(client.clone(), namespace)
        .get_opt(name)
        .await
        .unwrap()
}

#[tokio::test]
async fn enforce_writes_the_two_objects_and_a_second_pass_is_unchanged() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    let rig = rig(&client).await;
    create_namespace(&client, "user-alice").await;

    let outcome = pass(&rig, "user-alice", None).await;
    assert_eq!(outcome.results, vec![ReconcileResult::Applied]);

    let written = quota(&client, "user-alice", "weebo-quota").await.unwrap();
    let labels = written.metadata.labels.clone().unwrap();
    assert_eq!(labels[PROFILE_LABEL], "standard");
    assert!(labels.contains_key(MANAGED_BY_LABEL));
    assert_eq!(written.spec.unwrap().hard.unwrap()["requests.cpu"].0, "4");
    assert!(
        Api::<LimitRange>::namespaced(client.clone(), "user-alice")
            .get_opt("weebo-limits")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        rig.store
            .managed_in(&NamespaceName::new("user-alice"))
            .len(),
        2
    );

    let again = pass(&rig, "user-alice", None).await;
    assert_eq!(again.results, vec![ReconcileResult::Unchanged]);
}

#[tokio::test]
async fn an_invalid_profile_keeps_the_ceiling_the_namespace_already_has() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    let rig = rig(&client).await;
    create_namespace(&client, "user-bob").await;
    pass(&rig, "user-bob", None).await;
    let before = quota(&client, "user-bob", "weebo-quota").await.unwrap();

    let outcome = pass(&rig, "user-bob", Some("broken")).await;
    assert_eq!(outcome.results, vec![ReconcileResult::Invalid]);
    let after = quota(&client, "user-bob", "weebo-quota").await.unwrap();
    assert_eq!(
        after.metadata.resource_version,
        before.metadata.resource_version
    );
    assert!(
        Api::<LimitRange>::namespaced(client.clone(), "user-bob")
            .get_opt("weebo-limits")
            .await
            .unwrap()
            .is_some(),
        "the LimitRange stays too"
    );
}

#[tokio::test]
async fn switching_profile_updates_the_spec_and_the_label() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    let rig = rig(&client).await;
    create_namespace(&client, "user-carol").await;
    pass(&rig, "user-carol", None).await;

    let outcome = pass(&rig, "user-carol", Some("large")).await;
    assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
    let written = quota(&client, "user-carol", "weebo-quota").await.unwrap();
    assert_eq!(written.metadata.labels.unwrap()[PROFILE_LABEL], "large");
    assert_eq!(written.spec.unwrap().hard.unwrap()["pods"].0, "40");
}

#[tokio::test]
async fn a_foreign_quota_is_counted_and_survives_teardown() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    let rig = rig(&client).await;
    create_namespace(&client, "user-dave").await;
    create::<ResourceQuota>(
        &client,
        "user-dave",
        serde_json::json!({
            "metadata": {"name": "che-workspaces-config"},
            "spec": {"hard": {"pods": "50"}},
        }),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let outcome = pass(&rig, "user-dave", None).await;
    assert_eq!(outcome.foreign.quotas, 1);
    assert_eq!(outcome.foreign.limit_ranges, 0);

    let applied = weebo_si_resource_quotas::teardown(&NamespaceName::new("user-dave"), &rig.store)
        .await
        .unwrap();
    assert_eq!(applied.deleted, 2);
    assert!(quota(&client, "user-dave", "weebo-quota").await.is_none());
    assert!(
        quota(&client, "user-dave", "che-workspaces-config")
            .await
            .is_some(),
        "an object this feature did not write is never deleted"
    );
}
