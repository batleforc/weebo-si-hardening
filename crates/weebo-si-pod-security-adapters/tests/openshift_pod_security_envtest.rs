//! RFC 0013's OpenShift half against a real apiserver that serves `security.openshift.io`: a
//! `SecurityContextConstraints` CRD is installed, discovery finds the group, `backend: Auto`
//! resolves to `ObserveSynced`, and the controller writes **nothing** — it compares the level
//! OpenShift's label syncer set with the resolved one and reports `looser_synced`.
//!
//! Its own target, like `openshift_envtest` for RFC 0009: it installs a CRD the other suites'
//! apiservers must not serve, or `Auto` would resolve differently there.
//!
//! **What it cannot prove**: anything about the real syncer or an SCC grant. The synced labels are
//! written here by hand, the way `cluster-policy-controller` would write them.

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

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, NamespaceFacts};
use weebo_si_crd::{
    FeatureMode, NamespaceName, PodSecurityBackend, PodSecurityConfig, PodSecurityLevel,
    PodSecurityNamespaceSelection, PodSecurityVersion, Resolved,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_pod_security::{
    ENFORCE, NamespaceState, NamespaceSubject, PodSecurityFeature, ReconcileResult,
};
use weebo_si_pod_security_adapters::{KubeNamespaceLabelStore, found, serves_scc};

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

/// The least of OpenShift's `SecurityContextConstraints` CRD that makes the apiserver serve the
/// group: discovery is all `backend: Auto` asks.
fn scc_crd() -> CustomResourceDefinition {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "securitycontextconstraints.security.openshift.io"},
        "spec": {
            "group": "security.openshift.io",
            "scope": "Cluster",
            "names": {
                "plural": "securitycontextconstraints",
                "singular": "securitycontextconstraints",
                "kind": "SecurityContextConstraints",
                "shortNames": ["scc"],
            },
            "versions": [{
                "name": "v1",
                "served": true,
                "storage": true,
                "schema": {"openAPIV3Schema": {
                    "type": "object",
                    "x-kubernetes-preserve-unknown-fields": true,
                }},
            }],
        },
    }))
    .unwrap()
}

async fn install_scc(client: &kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let crd = scc_crd();
    crds.patch(
        "securitycontextconstraints.security.openshift.io",
        &PatchParams::apply("envtest").force(),
        &Patch::Apply(&crd),
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if serves_scc(client).await.unwrap() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("security.openshift.io never appeared in discovery");
}

/// A namespace carrying the `enforce` label OpenShift's syncer would have set.
async fn synced_namespace(client: &kube::Client, name: &str, synced: &str) {
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams {
                field_manager: Some("cluster-policy-controller".to_string()),
                ..PostParams::default()
            },
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    labels: Some(BTreeMap::from([(ENFORCE.to_string(), synced.to_string())])),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        )
        .await
        .unwrap();
}

fn feature(serves_scc: bool) -> PodSecurityFeature {
    let config = Resolved::without_teams(PodSecurityConfig {
        mode: FeatureMode::Enforce,
        namespace_selector: None,
        default: PodSecurityLevel::Restricted,
        ceiling: PodSecurityLevel::Baseline,
        version: PodSecurityVersion::new("latest"),
        backend: PodSecurityBackend::Auto,
        namespace_selection: PodSecurityNamespaceSelection::default(),
    });
    PodSecurityFeature::new(Arc::new(RwLock::new(Some(config))), serves_scc)
}

async fn pass(
    client: &kube::Client,
    name: &str,
    serves_scc: bool,
) -> weebo_si_pod_security::ReconcileOutcome {
    let ns = Api::<Namespace>::all(client.clone())
        .get(name)
        .await
        .unwrap();
    let facts = NamespaceFacts {
        labels: ns.metadata.labels.clone().unwrap_or_default(),
        selection_annotation: None,
    };
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    weebo_si_pod_security::reconcile(
        &feature(serves_scc),
        &NamespaceSubject {
            namespace: NamespaceName::new(name),
            annotation: None,
            found: found(&ns),
        },
        &Context::new(&[], &facts, &catalog),
        FeatureMode::Enforce,
        &KubeNamespaceLabelStore::new(client.clone()),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn auto_observes_on_openshift_and_reports_a_looser_synced_level_without_writing() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    assert!(
        !serves_scc(&client).await.unwrap(),
        "a bare apiserver is not OpenShift"
    );
    install_scc(&client).await;
    let openshift = serves_scc(&client).await.unwrap();
    assert!(openshift);

    synced_namespace(&client, "user-alice", "privileged").await;
    let before = Api::<Namespace>::all(client.clone())
        .get("user-alice")
        .await
        .unwrap();
    let outcome = pass(&client, "user-alice", openshift).await;
    assert_eq!(outcome.results, vec![ReconcileResult::LooserSynced]);
    assert_eq!(outcome.state, NamespaceState::Pending);
    assert!(!outcome.written);
    let after = Api::<Namespace>::all(client.clone())
        .get("user-alice")
        .await
        .unwrap();
    assert_eq!(
        after.metadata.resource_version, before.metadata.resource_version,
        "ObserveSynced must never write: the syncer owns the labels"
    );

    synced_namespace(&client, "user-bob", "restricted").await;
    let outcome = pass(&client, "user-bob", openshift).await;
    assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
    assert_eq!(outcome.state, NamespaceState::Applied);
    assert!(!outcome.written);

    let teardown = weebo_si_pod_security::teardown(
        &NamespaceName::new("user-alice"),
        &found(&after),
        &KubeNamespaceLabelStore::new(client.clone()),
    )
    .await
    .unwrap();
    assert_eq!(teardown, None, "nothing written, nothing to restore");
}
