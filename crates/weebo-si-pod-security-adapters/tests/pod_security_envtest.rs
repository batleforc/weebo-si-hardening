//! Proves RFC 0013's adapters against a real, ephemeral apiserver — the layer the domain crate's
//! unit tests cannot reach: what the server-side apply writes, what the managed fields say about it
//! afterwards, the `Warning` headers a level change returns, and that a restore leaves the
//! namespace exactly as it was found.
//!
//! Each test calls `weebo_si_pod_security::{reconcile, teardown}` directly rather than through the
//! watch-driven loop, so every assertion is deterministic — the same shape as the sibling suites.
//!
//! **What it cannot prove**: that the apiserver then refuses a pod. That is upstream's admission
//! plugin doing its job, and the kind e2e is where the RFC checks it.

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

use k8s_openapi::api::core::v1::{
    Capabilities, Container, HostPathVolumeSource, Namespace, Pod, PodSpec, SecurityContext,
    ServiceAccount, Volume, VolumeMount,
};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, NamespaceFacts};
use weebo_si_crd::{
    FeatureMode, NamespaceName, PodSecurityBackend, PodSecurityConfig, PodSecurityLevel,
    PodSecurityNamespaceSelection, PodSecurityVersion, Resolved, Selector, Team, TeamName,
    TeamPodSecurity,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_pod_security::{
    ENFORCE, KEYS, NamespaceSubject, PREVIOUS_ANNOTATION, PodSecurityFeature, ReconcileOutcome,
    ReconcileResult,
};
use weebo_si_pod_security_adapters::pod_security_metrics::violating_pods;
use weebo_si_pod_security_adapters::{KubeNamespaceLabelStore, found};

const TEAM_LABEL: &str = "weebo.io/team";

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

fn feature(team_level: PodSecurityLevel) -> PodSecurityFeature {
    let config = Resolved::without_teams(PodSecurityConfig {
        mode: FeatureMode::Enforce,
        namespace_selector: None,
        default: PodSecurityLevel::Restricted,
        ceiling: PodSecurityLevel::Baseline,
        version: PodSecurityVersion::new("latest"),
        backend: PodSecurityBackend::Labels,
        namespace_selection: PodSecurityNamespaceSelection::default(),
    })
    .with_grants(BTreeMap::from([(
        "team-1".to_string(),
        TeamPodSecurity {
            level: Some(team_level),
            warn_level: None,
        },
    )]));
    PodSecurityFeature::new(Arc::new(RwLock::new(Some(config))), false)
}

fn teams() -> Vec<Team> {
    vec![Team {
        name: TeamName::new("team-1"),
        namespace_selector: Selector {
            match_labels: [(TEAM_LABEL.to_string(), "team-1".to_string())].into(),
            match_expressions: Vec::new(),
        },
    }]
}

/// Create `name` with `labels`, written by a field manager that is not this feature's — the way
/// an admin or another tool would have.
async fn create_namespace(client: &kube::Client, name: &str, labels: &[(&str, &str)]) {
    let api: Api<Namespace> = Api::all(client.clone());
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(
                labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
            ),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    };
    api.create(
        &PostParams {
            field_manager: Some("admin".to_string()),
            ..PostParams::default()
        },
        &ns,
    )
    .await
    .unwrap();
}

async fn get(client: &kube::Client, name: &str) -> Namespace {
    Api::<Namespace>::all(client.clone())
        .get(name)
        .await
        .unwrap()
}

/// One pass over the namespace as the apiserver has it now — what the controller loop does with
/// the object its watch delivers.
async fn pass(
    client: &kube::Client,
    name: &str,
    team_level: PodSecurityLevel,
    mode: FeatureMode,
) -> ReconcileOutcome {
    let ns = get(client, name).await;
    let teams = teams();
    let facts = NamespaceFacts {
        labels: ns.metadata.labels.clone().unwrap_or_default(),
        selection_annotation: None,
    };
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(name),
        annotation: None,
        found: found(&ns),
    };
    weebo_si_pod_security::reconcile(
        &feature(team_level),
        &subject,
        &Context::new(&teams, &facts, &catalog),
        mode,
        &KubeNamespaceLabelStore::new(client.clone()),
    )
    .await
    .unwrap()
}

fn labels(ns: &Namespace) -> BTreeMap<String, String> {
    ns.metadata.labels.clone().unwrap_or_default()
}

fn annotations(ns: &Namespace) -> BTreeMap<String, String> {
    ns.metadata.annotations.clone().unwrap_or_default()
}

/// A pod `baseline` refuses, in `namespace`: an added capability and a `hostPath`. This apiserver
/// runs without `--allow-privileged`, so `privileged` and the host namespaces of RFC 0013's
/// motivation are refused before Pod Security sees them.
async fn create_violating_pod(client: &kube::Client, namespace: &str) {
    // No controller-manager here, so no default ServiceAccount unless we make one.
    Api::<ServiceAccount>::namespaced(client.clone(), namespace)
        .create(
            &PostParams::default(),
            &ServiceAccount {
                metadata: ObjectMeta {
                    name: Some("default".to_string()),
                    ..ObjectMeta::default()
                },
                ..ServiceAccount::default()
            },
        )
        .await
        .unwrap();
    Api::<Pod>::namespaced(client.clone(), namespace)
        .create(
            &PostParams::default(),
            &Pod {
                metadata: ObjectMeta {
                    name: Some("root".to_string()),
                    ..ObjectMeta::default()
                },
                spec: Some(PodSpec {
                    automount_service_account_token: Some(false),
                    volumes: Some(vec![Volume {
                        name: "host".to_string(),
                        host_path: Some(HostPathVolumeSource {
                            path: "/".to_string(),
                            ..HostPathVolumeSource::default()
                        }),
                        ..Volume::default()
                    }]),
                    containers: vec![Container {
                        name: "root".to_string(),
                        image: Some("registry.internal/shared/base:2026.3".to_string()),
                        security_context: Some(SecurityContext {
                            capabilities: Some(Capabilities {
                                add: Some(vec!["SYS_ADMIN".to_string()]),
                                ..Capabilities::default()
                            }),
                            ..SecurityContext::default()
                        }),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "host".to_string(),
                            mount_path: "/host".to_string(),
                            ..VolumeMount::default()
                        }]),
                        ..Container::default()
                    }],
                    ..PodSpec::default()
                }),
                ..Pod::default()
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn enforce_writes_the_six_labels_and_restore_gives_the_namespace_back() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(
        &client,
        "user-alice",
        &[(TEAM_LABEL, "team-1"), (ENFORCE, "privileged")],
    )
    .await;
    let before = get(&client, "user-alice").await;

    let outcome = pass(
        &client,
        "user-alice",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    assert!(outcome.written);
    assert_eq!(outcome.results, vec![ReconcileResult::Applied]);

    let ns = get(&client, "user-alice").await;
    let written = labels(&ns);
    for key in KEYS {
        assert!(written.contains_key(key), "{key} must be written");
    }
    assert_eq!(written[ENFORCE], "baseline");
    assert_eq!(
        written[TEAM_LABEL], "team-1",
        "another label is never touched"
    );
    // The team label, and the one the apiserver puts on every namespace.
    assert_eq!(written.len(), KEYS.len() + 2);
    assert_eq!(
        annotations(&ns)[PREVIOUS_ANNOTATION],
        r#"{"pod-security.kubernetes.io/enforce":"privileged"}"#
    );
    let found_after = found(&ns);
    assert!(
        found_after.owned,
        "the managed fields name this feature's field manager"
    );
    assert!(
        !found_after.foreign_owned,
        "the forced apply took the key over"
    );

    let again = pass(
        &client,
        "user-alice",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    assert_eq!(again.results, vec![ReconcileResult::Unchanged]);

    let outcome = weebo_si_pod_security::teardown(
        &NamespaceName::new("user-alice"),
        &found(&ns),
        &KubeNamespaceLabelStore::new(client.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(outcome.results, vec![ReconcileResult::Restored]);

    let restored = get(&client, "user-alice").await;
    assert_eq!(labels(&restored), labels(&before));
    assert!(!annotations(&restored).contains_key(PREVIOUS_ANNOTATION));
    let found_restored = found(&restored);
    assert!(
        !found_restored.owned,
        "after a restore the keys are not this feature's any more"
    );
    assert_eq!(found_restored.previous, None);
}

#[tokio::test]
async fn a_restore_with_nothing_before_removes_every_key() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(&client, "user-bob", &[(TEAM_LABEL, "team-1")]).await;

    pass(
        &client,
        "user-bob",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    let ns = get(&client, "user-bob").await;
    weebo_si_pod_security::teardown(
        &NamespaceName::new("user-bob"),
        &found(&ns),
        &KubeNamespaceLabelStore::new(client.clone()),
    )
    .await
    .unwrap()
    .unwrap();

    let restored = get(&client, "user-bob").await;
    assert_eq!(
        labels(&restored),
        BTreeMap::from([
            (
                "kubernetes.io/metadata.name".to_string(),
                "user-bob".to_string()
            ),
            (TEAM_LABEL.to_string(), "team-1".to_string()),
        ])
    );
}

#[tokio::test]
async fn dry_run_writes_nothing() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(&client, "user-carol", &[(TEAM_LABEL, "team-1")]).await;
    let before = get(&client, "user-carol").await;

    let outcome = pass(
        &client,
        "user-carol",
        PodSecurityLevel::Baseline,
        FeatureMode::DryRun,
    )
    .await;
    assert_eq!(outcome.results, vec![ReconcileResult::Applied]);
    assert!(!outcome.written);
    assert_eq!(outcome.changes.len(), KEYS.len());

    let after = get(&client, "user-carol").await;
    assert_eq!(labels(&after), labels(&before));
    assert_eq!(
        after.metadata.resource_version,
        before.metadata.resource_version
    );
}

#[tokio::test]
async fn a_stricter_level_an_admin_set_is_left_alone() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(
        &client,
        "user-dave",
        &[(TEAM_LABEL, "team-1"), (ENFORCE, "restricted")],
    )
    .await;
    let before = get(&client, "user-dave").await;

    let outcome = pass(
        &client,
        "user-dave",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    assert_eq!(outcome.results, vec![ReconcileResult::StricterExisting]);
    let after = get(&client, "user-dave").await;
    assert_eq!(
        after.metadata.resource_version,
        before.metadata.resource_version
    );
}

#[tokio::test]
async fn a_label_somebody_else_changes_is_drift_and_is_put_back() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(&client, "user-erin", &[(TEAM_LABEL, "team-1")]).await;
    pass(
        &client,
        "user-erin",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;

    // `kubectl label --overwrite`, as a user who may patch their own namespace would.
    Api::<Namespace>::all(client.clone())
        .patch(
            "user-erin",
            &PatchParams {
                field_manager: Some("kubectl-label".to_string()),
                ..PatchParams::default()
            },
            &Patch::Merge(serde_json::json!({"metadata": {"labels": {ENFORCE: "privileged"}}})),
        )
        .await
        .unwrap();
    assert!(found(&get(&client, "user-erin").await).foreign_owned);

    let outcome = pass(
        &client,
        "user-erin",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    assert!(outcome.drift);
    let ns = get(&client, "user-erin").await;
    assert_eq!(labels(&ns)[ENFORCE], "baseline");
    assert!(
        !found(&ns).foreign_owned,
        "the forced apply took the key back"
    );
}

#[tokio::test]
async fn raising_the_level_returns_the_apiservers_warnings_for_existing_pods() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(&client, "user-frank", &[(TEAM_LABEL, "team-1")]).await;

    create_violating_pod(&client, "user-frank").await;

    let outcome = pass(
        &client,
        "user-frank",
        PodSecurityLevel::Baseline,
        FeatureMode::Enforce,
    )
    .await;
    assert!(
        !outcome.warnings.is_empty(),
        "the apiserver warns about the existing privileged pod"
    );
    assert!(
        outcome
            .warnings
            .iter()
            .any(|warning| warning.contains("root")),
        "the pod is named: {:?}",
        outcome.warnings
    );
    assert!(violating_pods(&outcome.warnings) >= 1);
}

#[tokio::test]
async fn the_audit_dry_run_returns_the_warnings_and_writes_nothing() {
    let env = envtest_or_skip!();
    let client = env.client().unwrap();
    create_namespace(&client, "user-grace", &[(TEAM_LABEL, "team-1")]).await;
    create_violating_pod(&client, "user-grace").await;
    let before = get(&client, "user-grace").await;

    let warnings = KubeNamespaceLabelStore::new(client.clone())
        .dry_run_enforce(
            &NamespaceName::new("user-grace"),
            PodSecurityLevel::Baseline,
            &PodSecurityVersion::new("latest"),
        )
        .await
        .unwrap();
    assert!(
        warnings.iter().any(|warning| warning.contains("root")),
        "{warnings:?}"
    );

    let after = get(&client, "user-grace").await;
    assert_eq!(
        after.metadata.resource_version,
        before.metadata.resource_version
    );
    assert!(!labels(&after).contains_key(ENFORCE));
}
