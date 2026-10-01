//! The envtest tier, against a real ephemeral kube-apiserver: does the reconcile loop's status
//! patch actually land, and does it report exactly the violation `validate()` finds.
//!
//! Calls [`weebo_si_controller::reconcile_fn`] directly rather than running the full
//! `Controller` watch loop — deterministic, and the watch loop itself is `kube-runtime`'s own
//! well-tested machinery, not this crate's logic.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::sync::Arc;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_controller::{Ctx, reconcile_fn};
use weebo_si_crd::{
    FeatureState, Resolved, ResolvedKubeArmorPolicyConfig, WeeboSiConfig, WeeboSiTeam,
};
use weebo_si_envtest_support::EnvTest;

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

/// Both kinds this loop reads: the singleton, and the `WeeboSiTeam` objects RFC 0011 resolves it
/// against. Installing only the first is not a smaller test — the reconcile would report "no
/// teams" for a reason that has nothing to do with the configuration under test.
async fn install_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for crd in [WeeboSiConfig::crd(), WeeboSiTeam::crd()] {
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .expect("CRD install");
        let mut established = false;
        for _ in 0..60 {
            if let Ok(installed) = crds.get(&name).await {
                established = installed
                    .status
                    .and_then(|status| status.conditions)
                    .map(|conditions| {
                        conditions
                            .iter()
                            .any(|c| c.type_ == "Established" && c.status == "True")
                    })
                    .unwrap_or(false);
                if established {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        assert!(established, "the CRD {name} never became established");
    }
}

/// Apply one `WeeboSiTeam`, as JSON so a test can write a shape the typed builder would make
/// verbose.
async fn create_team(client: kube::Client, spec: serde_json::Value) {
    let teams: Api<WeeboSiTeam> = Api::all(client);
    teams
        .create(
            &PostParams::default(),
            &serde_json::from_value(spec).expect("the team should deserialize"),
        )
        .await
        .expect("the team should be accepted by the real schema");
}

/// A team redefining a catalogue key the cluster already defines — the violation RFC 0011 put
/// in place of RFC 0002's `GrantNamesUndeclaredTeam`, which the wire can no longer express now
/// that grants are built from the team objects themselves.
#[tokio::test]
async fn a_team_redefining_a_catalogue_key_is_reported_degraded() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    create_team(
        client.clone(),
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": "ghost-team" },
            "spec": {
                "namespaceSelector": {},
                "features": {
                    "dwocPin": {
                        // Same key as the cluster's, different target: CatalogKeyConflict.
                        "catalog": [{"key": "baseline", "name": "other-config", "namespace": "eclipse-che"}],
                        "default": "baseline",
                    }
                },
            },
        }),
    )
    .await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": {
            "features": {
                "dwocPin": {
                    "mode": "DryRun",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        },
    });
    api.create(
        &PostParams::default(),
        &serde_json::from_value(spec).expect("resource should deserialize"),
    )
    .await
    .expect("the resource itself is schema-valid, only semantically wrong");

    let config = api.get("cluster").await.expect("the resource should exist");
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    reconcile_fn(Arc::new(config), ctx)
        .await
        .expect("reconcile should complete, degraded or not");

    let updated = api
        .get_status("cluster")
        .await
        .expect("status should be readable");
    let status = updated.status.expect("status should have been written");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.type_ == "Degraded" && c.message.contains("ghost-team")),
        "expected a Degraded condition naming ghost-team, got: {:?}",
        status.conditions
    );

    let _ = api.delete("cluster", &DeleteParams::default()).await;
    let teams: Api<WeeboSiTeam> = Api::all(client.clone());
    let _ = teams.delete("ghost-team", &DeleteParams::default()).await;
}

/// A well-formed configuration reports `Ready`, and the feature's state matches its mode.
#[tokio::test]
async fn a_well_formed_configuration_is_reported_ready_and_active() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": {
            "features": {
                "dwocPin": {
                    "mode": "Enforce",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                }
            }
        },
    });
    api.create(
        &PostParams::default(),
        &serde_json::from_value(spec).expect("resource should deserialize"),
    )
    .await
    .expect("a well-formed resource should be accepted");

    let config = api.get("cluster").await.expect("the resource should exist");
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    reconcile_fn(Arc::new(config), ctx)
        .await
        .expect("reconcile should complete");

    let updated = api
        .get_status("cluster")
        .await
        .expect("status should be readable");
    let status = updated.status.expect("status should have been written");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
    );
    assert_eq!(status.features[0].name, "dwoc-pin");

    let _ = api.delete("cluster", &DeleteParams::default()).await;
}

/// RFC 0009's `HaproxyIngress` prerequisite, which is an assertion rather than a check — so the
/// only place its absence is ever said out loud is this condition. Proven through a real
/// reconcile, because until this feature was wired in, `EndpointAuthConfig::validate()` existed
/// and nothing called it: the violations were real and reached nobody.
#[tokio::test]
async fn haproxy_without_its_prerequisite_is_reported_degraded() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let endpoint_auth = |prerequisite: bool| {
        serde_json::json!({
            "mode": "Enforce",
            "gateway": {
                "externalUrl": "https://auth.weebo.si",
                "service": {"name": "endpoint-gateway", "namespace": "weebo-si-hardening", "port": 4180},
                "dialect": "HaproxyIngress",
                "haproxyPrerequisite": prerequisite,
            },
            "owner": {
                "namespaceAnnotation": "che.eclipse.org/username",
                "devworkspaceOperatorIdentity":
                    "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount",
            },
            "hosts": {
                "suffix": ".weebo.si",
                "ownership": [{"template": "{user}-{workspace}-{endpoint}"}],
            },
            "catalog": [{"key": "private"}],
            "default": "private",
        })
    };

    let create = |body: serde_json::Value| {
        let api = api.clone();
        async move {
            let spec = serde_json::json!({
                "apiVersion": "hardening.weebo.io/v1alpha1",
                "kind": "WeeboSiConfig",
                "metadata": { "name": "cluster" },
                "spec": { "features": { "endpointAuth": body } },
            });
            api.create(
                &PostParams::default(),
                &serde_json::from_value(spec).expect("resource should deserialize"),
            )
            .await
            .expect("a schema-valid resource should be accepted");
        }
    };

    let reconcile_once = || {
        let api = api.clone();
        let client = client.clone();
        async move {
            let config = api.get("cluster").await.expect("the resource should exist");
            let ctx = Arc::new(Ctx {
                client,
                is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            });
            reconcile_fn(Arc::new(config), ctx)
                .await
                .expect("reconcile should complete");
            api.get_status("cluster")
                .await
                .expect("status should be readable")
                .status
                .expect("status should have been written")
        }
    };

    // The dialect selected the way an admin who has not read the prerequisite would select it.
    create(endpoint_auth(false)).await;
    let status = reconcile_once().await;
    let feature = status
        .features
        .iter()
        .find(|feature| feature.name == "endpoint-auth")
        .expect("the feature should report its own status");
    assert!(
        matches!(feature.state, FeatureState::Degraded),
        "state was {:?}",
        feature.state
    );
    assert!(
        feature.message.contains("haproxyPrerequisite"),
        "the message has to name the field that fixes it, got: {}",
        feature.message
    );
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Degraded" && condition.status == "True"),
        "an assertion nobody can check has to reach the object itself"
    );

    api.delete("cluster", &DeleteParams::default())
        .await
        .expect("cleanup should succeed");

    // And with the assertion made, the same configuration is ordinary.
    create(endpoint_auth(true)).await;
    let status = reconcile_once().await;
    let feature = status
        .features
        .iter()
        .find(|feature| feature.name == "endpoint-auth")
        .expect("the feature should report its own status");
    assert!(
        matches!(feature.state, FeatureState::Active),
        "state was {:?}",
        feature.state
    );
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True")
    );

    let _ = api.delete("cluster", &DeleteParams::default()).await;
}

/// Every `validate()` violation `weebo-si-crd`'s unit tests exercise in isolation is proven here
/// to reach `status.conditions` together, through one real reconcile — not just the one
/// (`GrantNamesUndeclaredTeam`) the headline test above covers.
#[tokio::test]
async fn every_validate_violation_reaches_status() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    // Its default is neither one of its own entries nor the cluster's:
    // GrantDefaultOutsideAllowed.
    create_team(
        client.clone(),
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": "team-1" },
            "spec": {
                "namespaceSelector": {},
                "features": {
                    "dwocPin": {
                        "catalog": [{"key": "gpu", "name": "dwoc-gpu", "namespace": "eclipse-che"}],
                        "default": "elsewhere",
                    }
                },
            },
        }),
    )
    .await;
    // Redefines the cluster's own key: CatalogKeyConflict.
    create_team(
        client.clone(),
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": "team-2" },
            "spec": {
                "namespaceSelector": {},
                "features": {
                    "dwocPin": {
                        "catalog": [{"key": "baseline", "name": "another-config", "namespace": "eclipse-che"}],
                        "default": "baseline",
                    }
                },
            },
        }),
    )
    .await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": {
            "features": {
                "dwocPin": {
                    "mode": "DryRun",
                    // "baseline" declared twice: DuplicateCatalogKey.
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "baseline", "name": "other-config", "namespace": "eclipse-che"},
                    ],
                    // absent from the catalogue: DefaultNotInCatalog, and — since every team
                    // reaches the cluster default — GrantAllowedUnknownKey for every team too.
                    "default": "missing",
                }
            }
        },
    });
    api.create(
        &PostParams::default(),
        &serde_json::from_value(spec).expect("resource should deserialize"),
    )
    .await
    .expect("the resource itself is schema-valid, only semantically wrong");

    let config = api.get("cluster").await.expect("the resource should exist");
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    reconcile_fn(Arc::new(config), ctx)
        .await
        .expect("reconcile should complete, degraded or not");

    let updated = api
        .get_status("cluster")
        .await
        .expect("status should be readable");
    let status = updated.status.expect("status should have been written");
    let message = format!(
        "{}; {}",
        status.features[0].message,
        status
            .conditions
            .iter()
            .map(|condition| condition.message.clone())
            .collect::<Vec<_>>()
            .join("; ")
    );
    for needle in ["baseline", "missing", "team-1", "team-2"] {
        assert!(
            message.contains(needle),
            "expected the Degraded message to name every violation (missing {needle:?}): {message}"
        );
    }

    let _ = api.delete("cluster", &DeleteParams::default()).await;
    let teams: Api<WeeboSiTeam> = Api::all(client.clone());
    for team in ["team-1", "team-2"] {
        let _ = teams.delete(team, &DeleteParams::default()).await;
    }
}

/// A `WeeboSiConfig` under any name but `cluster` is ignored and reported `Degraded` on the
/// object itself, per RFC 0002's *Contract* — `reconcile.rs`'s `degraded_status` path.
#[tokio::test]
async fn a_config_under_the_wrong_name_is_reported_degraded() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "not-cluster" },
        "spec": { "features": {} },
    });
    api.create(
        &PostParams::default(),
        &serde_json::from_value(spec).expect("resource should deserialize"),
    )
    .await
    .expect("the name is not validated by the schema, only by reconcile");

    let config = api
        .get("not-cluster")
        .await
        .expect("the resource should exist");
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });
    reconcile_fn(Arc::new(config), ctx)
        .await
        .expect("reconcile should complete");

    let updated = api
        .get_status("not-cluster")
        .await
        .expect("status should be readable");
    let status = updated.status.expect("status should have been written");
    assert!(
        status
            .conditions
            .iter()
            .any(|c| c.type_ == "Degraded" && c.message.contains("not-cluster")),
        "expected a Degraded condition naming the wrong name, got: {:?}",
        status.conditions
    );

    let _ = api.delete("not-cluster", &DeleteParams::default()).await;
}

/// `mode: Off` → `DryRun` → `Enforce` is reflected in `status.features[].state` across repeated
/// reconciles, with no restart between them — the same claim RFC 0002's *Rollout* makes about
/// admission, proven here for the controller's own status reporting.
#[tokio::test]
async fn mode_transitions_are_reflected_in_status_across_reconciles() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        is_leader: Arc::new(std::sync::atomic::AtomicBool::new(true)),
    });

    let catalog = serde_json::json!([{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}]);
    let make_spec = |mode: &str| {
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiConfig",
            "metadata": { "name": "cluster" },
            "spec": { "features": { "dwocPin": { "mode": mode, "catalog": catalog, "default": "baseline" } } },
        })
    };

    api.create(
        &PostParams::default(),
        &serde_json::from_value(make_spec("Off")).expect("resource should deserialize"),
    )
    .await
    .expect("resource should be accepted");

    use weebo_si_crd::FeatureState;
    for (mode, expected_state) in [
        ("Off", FeatureState::Disabled),
        ("DryRun", FeatureState::DryRun),
        ("Enforce", FeatureState::Active),
    ] {
        if mode != "Off" {
            let mut current = api.get("cluster").await.expect("the resource should exist");
            current.spec = serde_json::from_value(make_spec(mode)["spec"].clone())
                .expect("spec should deserialize");
            api.replace("cluster", &PostParams::default(), &current)
                .await
                .expect("mode update should be accepted");
        }
        let config = api.get("cluster").await.expect("the resource should exist");
        reconcile_fn(Arc::new(config), Arc::clone(&ctx))
            .await
            .expect("reconcile should complete");
        let updated = api
            .get_status("cluster")
            .await
            .expect("status should be readable");
        let status = updated.status.expect("status should have been written");
        assert_eq!(
            status.features[0].state, expected_state,
            "mode {mode} should report state {expected_state:?}"
        );
    }

    let _ = api.delete("cluster", &DeleteParams::default()).await;
}

// --- RFC 0006: the posture write ---------------------------------------------------------------
//
// The one output of a `kubearmor-policy` reconcile pass that is not a `KubeArmorPolicy` object,
// and the one this project had no coverage for at all: three annotations patched onto a namespace
// this operator does not own. `posture_patch`'s shape is unit-tested next to it; what these two
// prove is that the patch actually lands, and that `DryRun` never sends it.

use k8s_openapi::api::core::v1::Namespace;
use std::collections::BTreeMap;
use std::sync::RwLock;
use weebo_si_chassis::Context;
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_controller::kubearmor_policy::write_posture;
use weebo_si_crd::{
    DefaultPosture, FeatureMode, KubeArmorPolicyConfig, NamespaceName, OnNotGranted, Posture,
    RuntimeBackend, RuntimeEnforcement, RuntimeEnforcementBackend, RuntimeNamespaceSelection,
    RuntimeProfile, RuntimeProfileCatalog, RuntimeProfileKey, RuntimeWorkspaceSelection,
    TemplateRef,
};
use weebo_si_kubearmor_policy::port::testing::{FakePolicyStore, FakeTemplateStore};
use weebo_si_kubearmor_policy::{KubeArmorPolicy, NamespaceSubject};

const POSTURE_NAMESPACE: &str = "user-posture";

fn kubearmor_config(mode: FeatureMode, posture: DefaultPosture) -> ResolvedKubeArmorPolicyConfig {
    Resolved::without_teams(KubeArmorPolicyConfig {
        mode,
        namespace_selector: None,
        catalog: RuntimeProfileCatalog::new(vec![RuntimeProfile {
            key: RuntimeProfileKey::new("base"),
            template_ref: TemplateRef {
                name: "weebo-base-runtime".to_string(),
                namespace: NamespaceName::new("weebo-si-hardening"),
            },
        }]),
        baseline: RuntimeProfileKey::new("base"),
        namespace_selection: RuntimeNamespaceSelection::default(),
        workspace_selection: RuntimeWorkspaceSelection::default(),
        on_not_granted: OnNotGranted::default(),
        enforcement: RuntimeEnforcement {
            backend: RuntimeEnforcementBackend::KubeArmor,
            default_posture: posture,
        },
    })
}

fn kubearmor_feature(config: ResolvedKubeArmorPolicyConfig) -> KubeArmorPolicy {
    KubeArmorPolicy::new(
        Arc::new(RwLock::new(Some(config))),
        Arc::new(RwLock::new(RuntimeBackend::KubeArmor)),
        Arc::new(FakeTemplateStore::new([(
            TemplateRef {
                name: "weebo-base-runtime".to_string(),
                namespace: NamespaceName::new("weebo-si-hardening"),
            },
            b"base-rules".to_vec(),
        )])),
    )
}

async fn create_posture_namespace(client: kube::Client) {
    let api: Api<Namespace> = Api::all(client);
    let namespace = Namespace {
        metadata: kube::api::ObjectMeta {
            name: Some(POSTURE_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = api.create(&PostParams::default(), &namespace).await;
}

async fn annotations_of(client: kube::Client, namespace: &str) -> BTreeMap<String, String> {
    Api::<Namespace>::all(client)
        .get(namespace)
        .await
        .expect("the namespace should exist")
        .metadata
        .annotations
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// The whole path the namespace loop takes in `Enforce`: reconcile, ask
/// `posture_to_write()`, patch. Asserts the three annotations are on the real object afterwards.
#[tokio::test]
async fn enforce_writes_kubearmors_three_posture_annotations_onto_the_namespace() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    create_posture_namespace(client.clone()).await;

    let feature = kubearmor_feature(kubearmor_config(
        FeatureMode::Enforce,
        DefaultPosture {
            file: Posture::Block,
            network: Posture::Audit,
            capabilities: Posture::Block,
        },
    ));
    let store = FakePolicyStore::default();
    let namespace_facts = NamespaceFacts::default();
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(POSTURE_NAMESPACE),
    };

    let outcome = weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &store,
    )
    .await
    .expect("reconcile should succeed");

    let posture = outcome
        .posture_to_write()
        .expect("Enforce should have a posture to write");
    write_posture(&client, &subject.namespace, posture)
        .await
        .expect("the posture patch should be accepted");

    let annotations = annotations_of(client, POSTURE_NAMESPACE).await;
    assert_eq!(
        annotations
            .get("kubearmor-file-posture")
            .map(String::as_str),
        Some("block")
    );
    assert_eq!(
        annotations
            .get("kubearmor-network-posture")
            .map(String::as_str),
        Some("audit")
    );
    assert_eq!(
        annotations
            .get("kubearmor-capabilities-posture")
            .map(String::as_str),
        Some("block")
    );
}

/// The same path in `DryRun`, which must stop at `posture_to_write()` returning `None` — a dry
/// run that changes what KubeArmor does with an unmatched operation is not a dry run.
#[tokio::test]
async fn dry_run_leaves_the_namespaces_posture_alone() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    create_posture_namespace(client.clone()).await;

    let feature = kubearmor_feature(kubearmor_config(
        FeatureMode::DryRun,
        DefaultPosture {
            file: Posture::Block,
            ..DefaultPosture::default()
        },
    ));
    let store = FakePolicyStore::default();
    let namespace_facts = NamespaceFacts::default();
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(POSTURE_NAMESPACE),
    };

    let outcome =
        weebo_si_kubearmor_policy::reconcile(&feature, &subject, &ctx, FeatureMode::DryRun, &store)
            .await
            .expect("reconcile should succeed");

    assert!(
        outcome.posture.is_some(),
        "the pass still computes what it would write"
    );
    // The loop's own line, verbatim: nothing to write means nothing is sent.
    if let Some(posture) = outcome.posture_to_write() {
        write_posture(&client, &subject.namespace, posture)
            .await
            .expect("patch");
    }

    let annotations = annotations_of(client, POSTURE_NAMESPACE).await;
    assert!(
        !annotations
            .keys()
            .any(|key| key.starts_with("kubearmor-") && key.ends_with("-posture")),
        "DryRun must not have touched the namespace: {annotations:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// RFC 0011: the `WeeboSiTeam` and `WeeboSiUser` loops, against a real apiserver carrying the two
// upstream CRDs this operator provisions into.
//
// What a unit test with a fake provisioner cannot prove, and these do: that the `ownerReference`
// this operator writes is accepted and readable back (it is what makes `Created` distinguishable
// from `Adopted` after a restart), that a cluster missing one of the two CRDs answers `Absent`
// rather than failing the pass, and that `DryRun` leaves an apiserver with nothing in it.
// ---------------------------------------------------------------------------------------------

use std::sync::atomic::AtomicBool;

use kube::api::{ApiResource, DynamicObject, ListParams};
use weebo_si_controller::{IdentityDeps, reconcile_team, reconcile_user};
use weebo_si_crd::{
    AuthentikProvisioning, CheProvisioning, IdentityConfig, TargetState, WeeboSiUser,
};
use weebo_si_identity::testing::FakeObserver;
use weebo_si_runtime::KubeProvisioner;

const AUTHENTIK_USER_CRD: &str = include_str!("fixtures/authentikuser-crd.yaml");
const APPLICATION_CRD: &str = include_str!("fixtures/application-crd.yaml");

/// The `WeeboSiConfig`/`WeeboSiTeam`/`WeeboSiUser` kinds, plus whichever provisioned kinds this
/// test wants the cluster to serve.
async fn install_identity_crds(client: kube::Client, upstream: &[&str]) {
    install_crd(client.clone()).await;
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for crd in [weebo_si_crd::WeeboSiUser::crd()] {
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .expect("CRD install");
        wait_established(&crds, &name).await;
    }
    for fixture in upstream {
        let crd: CustomResourceDefinition =
            serde_yaml_bw::from_str(fixture).expect("the fixture should parse");
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .expect("CRD install");
        wait_established(&crds, &name).await;
    }
}

async fn wait_established(crds: &Api<CustomResourceDefinition>, name: &str) {
    for _ in 0..60 {
        if let Ok(crd) = crds.get(name).await {
            let established = crd
                .status
                .and_then(|status| status.conditions)
                .map(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                })
                .unwrap_or(false);
            if established {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("the CRD {name} never became established");
}

fn identity_config(mode: FeatureMode) -> IdentityConfig {
    IdentityConfig {
        mode,
        authentik: AuthentikProvisioning {
            allowed_group_refs: vec!["platform".to_string(), "oncall-*".to_string()],
        },
        che: CheProvisioning {
            application_namespace: "argocd".to_string(),
            allowed_projects: vec!["weebo-dev".to_string()],
            allowed_repo_urls: vec!["https://charts.weebo.io*".to_string()],
        },
    }
}

fn identity_ctx(
    client: kube::Client,
    mode: FeatureMode,
) -> Arc<weebo_si_controller::identity::Ctx> {
    Arc::new(weebo_si_controller::identity::Ctx {
        client: client.clone(),
        deps: IdentityDeps {
            config: Arc::new(std::sync::RwLock::new(Some(identity_config(mode)))),
            authentik: Arc::new(KubeProvisioner::authentik_user(client.clone())) as _,
            workspace: Arc::new(KubeProvisioner::argo_application(client)) as _,
            observer: Arc::new(FakeObserver::default()) as _,
        },
        is_leader: Arc::new(AtomicBool::new(true)),
    })
}

fn authentik_users(client: kube::Client) -> Api<DynamicObject> {
    let gvk = kube::api::GroupVersionKind::gvk("authentik.weebo.io", "v1alpha1", "AuthentikUser");
    Api::all_with(
        client,
        &ApiResource::from_gvk_with_plural(&gvk, "authentikusers"),
    )
}

fn applications(client: kube::Client, namespace: &str) -> Api<DynamicObject> {
    let gvk = kube::api::GroupVersionKind::gvk("argoproj.io", "v1alpha1", "Application");
    Api::namespaced_with(
        client,
        namespace,
        &ApiResource::from_gvk_with_plural(&gvk, "applications"),
    )
}

/// Create one `WeeboSiUser` and read it back, so the test holds the `uid` the loop owns by.
async fn create_user(client: kube::Client, spec: serde_json::Value) -> Arc<WeeboSiUser> {
    let users: Api<WeeboSiUser> = Api::all(client);
    let value = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiUser",
        "metadata": { "name": spec["username"].as_str().unwrap_or("max") },
        "spec": spec,
    });
    let created = users
        .create(
            &PostParams::default(),
            &serde_json::from_value(value).expect("the user should deserialize"),
        )
        .await
        .expect("the user should be accepted by the real schema");
    Arc::new(created)
}

/// The headline check for the identity half: a person with `authentik.mode: Ensure` gets an
/// `AuthentikUser`, owned by them, carrying exactly RFC 0011's mapping.
#[tokio::test]
async fn a_person_gets_an_authentik_user_owned_by_their_own_object() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[AUTHENTIK_USER_CRD]).await;

    create_team(
        client.clone(),
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": "platform" },
            "spec": {
                "namespaceSelector": {},
                "identity": { "authentik": { "groupRefs": ["platform"] } },
            },
        }),
    )
    .await;

    let user = create_user(
        client.clone(),
        serde_json::json!({
            "username": "max",
            "displayName": "Max Leriche",
            "email": "max@weebo.io",
            "team": "platform",
            "authentik": { "mode": "Ensure", "groupRefs": ["oncall-eu"] },
        }),
    )
    .await;

    reconcile_user(
        Arc::clone(&user),
        identity_ctx(client.clone(), FeatureMode::Enforce),
    )
    .await
    .expect("the pass should complete");

    let created = authentik_users(client.clone())
        .get("max")
        .await
        .expect("the AuthentikUser should have been created");
    assert_eq!(created.data["spec"]["username"], serde_json::json!("max"));
    assert_eq!(
        created.data["spec"]["name"],
        serde_json::json!("Max Leriche")
    );
    assert_eq!(
        created.data["spec"]["groupRefs"],
        serde_json::json!(["oncall-eu", "platform"]),
        "the team's groups and the person's own, merged and sorted"
    );
    let owner = created
        .metadata
        .owner_references
        .as_ref()
        .and_then(|owners| owners.first())
        .expect("the object should be owned by the person it was created for");
    assert_eq!(owner.kind, "WeeboSiUser");
    assert_eq!(owner.uid, user.metadata.uid.clone().unwrap_or_default());

    let users: Api<WeeboSiUser> = Api::all(client.clone());
    let status = users
        .get_status("max")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    let authentik = status.authentik.expect("the authentik half should report");
    assert_eq!(authentik.state, TargetState::Created);
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True"),
        "{:?}",
        status.conditions
    );

    // A second pass over an object already in shape must neither fail nor rewrite it.
    let user = Arc::new(users.get("max").await.expect("the user should exist"));
    reconcile_user(user, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("the second pass should complete");
    let status = users
        .get_status("max")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    assert_eq!(
        status.authentik.expect("still reported").message,
        "AuthentikUser/max is up to date".to_string()
    );
}

/// `DryRun` plans everything and writes nothing — the property that makes it a safe first step.
#[tokio::test]
async fn a_dry_run_reports_what_it_would_create_and_creates_nothing() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[AUTHENTIK_USER_CRD]).await;

    let user = create_user(
        client.clone(),
        serde_json::json!({
            "username": "max",
            "email": "max@weebo.io",
            "authentik": { "mode": "Ensure" },
        }),
    )
    .await;

    reconcile_user(user, identity_ctx(client.clone(), FeatureMode::DryRun))
        .await
        .expect("the pass should complete");

    let listed = authentik_users(client.clone())
        .list(&ListParams::default())
        .await
        .expect("listing should succeed");
    assert!(listed.items.is_empty(), "a dry run writes nothing");

    let users: Api<WeeboSiUser> = Api::all(client.clone());
    let status = users
        .get_status("max")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    assert_eq!(
        status.authentik.expect("reported").message,
        "would create AuthentikUser/max".to_string()
    );
}

/// Two people asking for one username: the first object keeps the login, the second writes
/// nothing and is `Degraded` — whichever of the two the loop happens to reconcile first.
#[tokio::test]
async fn a_second_person_claiming_a_taken_username_writes_nothing() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[AUTHENTIK_USER_CRD]).await;

    let users: Api<WeeboSiUser> = Api::all(client.clone());
    let mut created = Vec::new();
    for name in ["ivan-one", "ivan-two"] {
        let value = serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiUser",
            "metadata": { "name": name },
            "spec": { "username": "ivan", "email": "ivan@weebo.io", "authentik": { "mode": "Ensure" } },
        });
        let user = users
            .create(
                &PostParams::default(),
                &serde_json::from_value(value).expect("the user should deserialize"),
            )
            .await
            .expect("the user should be accepted by the real schema");
        created.push(Arc::new(user));
    }

    // The duplicate first: holding a username is decided by who claimed it, not by who the loop
    // reaches first. Created in the same second, the two tie and the lower name holds it.
    for user in created.iter().rev() {
        reconcile_user(
            Arc::clone(user),
            identity_ctx(client.clone(), FeatureMode::Enforce),
        )
        .await
        .expect("the pass should complete");
    }

    let accounts = authentik_users(client.clone());
    accounts
        .get("ivan-one")
        .await
        .expect("the first claimant's AuthentikUser should exist");
    assert!(
        accounts
            .get_opt("ivan-two")
            .await
            .expect("reading should succeed")
            .is_none(),
        "the second claimant must write nothing"
    );

    let status = users
        .get_status("ivan-two")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    let authentik = status.authentik.expect("the authentik half should report");
    assert_eq!(authentik.state, TargetState::Conflict);
    assert_eq!(
        authentik.message,
        "username ivan is already claimed by WeeboSiUser ivan-one"
    );
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Degraded" && condition.status == "True"),
        "{:?}",
        status.conditions
    );
}

/// An object somebody else made is referenced, never written — RFC 0011's `Adopted`.
#[tokio::test]
async fn an_object_owned_by_somebody_else_is_adopted_and_left_alone() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[AUTHENTIK_USER_CRD]).await;

    let existing = serde_json::json!({
        "apiVersion": "authentik.weebo.io/v1alpha1",
        "kind": "AuthentikUser",
        "metadata": { "name": "max" },
        "spec": {
            "username": "max",
            "name": "An admin wrote this",
            "email": "admin@weebo.io",
        },
    });
    authentik_users(client.clone())
        .create(
            &PostParams::default(),
            &serde_json::from_value(existing).expect("the object should deserialize"),
        )
        .await
        .expect("the pre-existing object should be accepted");

    let user = create_user(
        client.clone(),
        serde_json::json!({
            "username": "max",
            "displayName": "Max Leriche",
            "email": "max@weebo.io",
            "authentik": { "mode": "Ensure" },
        }),
    )
    .await;

    reconcile_user(user, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("the pass should complete");

    let untouched = authentik_users(client.clone())
        .get("max")
        .await
        .expect("the object should still exist");
    assert_eq!(
        untouched.data["spec"]["name"],
        serde_json::json!("An admin wrote this"),
        "an object this operator does not own is never written"
    );
    assert!(untouched.metadata.owner_references.is_none());

    let users: Api<WeeboSiUser> = Api::all(client.clone());
    let status = users
        .get_status("max")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    assert_eq!(
        status.authentik.expect("reported").state,
        TargetState::Adopted
    );
}

/// A cluster that does not serve the kind answers `Absent` — a missing dependency, reported, and
/// never a create retried forever.
#[tokio::test]
async fn a_kind_this_cluster_does_not_serve_is_absent_not_missing() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    // Deliberately no upstream CRD at all.
    install_identity_crds(client.clone(), &[]).await;

    let user = create_user(
        client.clone(),
        serde_json::json!({
            "username": "max",
            "email": "max@weebo.io",
            "authentik": { "mode": "Ensure" },
        }),
    )
    .await;

    reconcile_user(user, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("a missing dependency must not fail the pass");

    let users: Api<WeeboSiUser> = Api::all(client.clone());
    let status = users
        .get_status("max")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    let authentik = status.authentik.expect("reported");
    assert_eq!(authentik.state, TargetState::Absent);
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Degraded"),
        "{:?}",
        status.conditions
    );
}

/// The workspace half: a team's Helm template, rendered for one person into one `Application` in
/// the one namespace the cluster config names.
#[tokio::test]
async fn a_persons_workspace_application_is_rendered_from_their_teams_template() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[APPLICATION_CRD]).await;
    create_namespace(client.clone(), "argocd").await;

    create_team(
        client.clone(),
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiTeam",
            "metadata": { "name": "platform" },
            "spec": {
                "namespaceSelector": {},
                "workspace": {
                    "che": {
                        "mode": "Ensure",
                        "name": "che-{USERNAME}",
                        "project": "weebo-dev",
                        "source": {
                            "repoUrl": "https://charts.weebo.io",
                            "chart": "che-user",
                            "targetRevision": "1.4.2",
                            "values": {
                                "username": "{USERNAME}",
                                "namespace": "{USER_NAMESPACE}",
                                "storage": { "size": "10Gi" },
                            },
                        },
                        "destination": {
                            "server": "https://kubernetes.default.svc",
                            "namespace": "{USERNAME}-che",
                        },
                        "syncPolicy": { "automated": { "prune": true, "selfHeal": true } },
                    }
                },
            },
        }),
    )
    .await;

    let user = create_user(
        client.clone(),
        serde_json::json!({
            "username": "max",
            "email": "max@weebo.io",
            "team": "platform",
            "che": { "mode": "Ensure", "values": { "storage": { "size": "30Gi" } } },
        }),
    )
    .await;

    reconcile_user(user, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("the pass should complete");

    let application = applications(client.clone(), "argocd")
        .get("che-max")
        .await
        .expect("the Application should have been created");
    assert_eq!(
        application.data["spec"]["destination"]["namespace"],
        serde_json::json!("max-che")
    );
    assert_eq!(
        application.data["spec"]["source"]["helm"]["valuesObject"]["namespace"],
        serde_json::json!("max-che"),
        "{{USER_NAMESPACE}} binds to the namespace the template itself rendered"
    );
    assert_eq!(
        application.data["spec"]["source"]["helm"]["valuesObject"]["storage"]["size"],
        serde_json::json!("30Gi"),
        "the person's own values win over their team's"
    );
    assert_eq!(
        application.data["spec"]["project"],
        serde_json::json!("weebo-dev")
    );
}

/// The team loop: what it owns, who is in it, and the namespace a higher-priority team took.
#[tokio::test]
async fn a_team_reports_its_namespaces_its_members_and_what_it_lost() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_identity_crds(client.clone(), &[]).await;

    for (name, priority) in [("platform", 200), ("research", 100)] {
        create_team(
            client.clone(),
            serde_json::json!({
                "apiVersion": "hardening.weebo.io/v1alpha1",
                "kind": "WeeboSiTeam",
                "metadata": { "name": name },
                "spec": {
                    "priority": priority,
                    "namespaceSelector": { "matchLabels": { "weebo.io/team": "shared" } },
                },
            }),
        )
        .await;
    }
    create_labelled_namespace(client.clone(), "shared-ns", "shared").await;
    create_user(
        client.clone(),
        serde_json::json!({ "username": "max", "team": "platform" }),
    )
    .await;

    let teams: Api<WeeboSiTeam> = Api::all(client.clone());
    let platform = Arc::new(teams.get("platform").await.expect("the team should exist"));
    reconcile_team(platform, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("the pass should complete");

    let status = teams
        .get_status("platform")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    assert_eq!(status.members, 1, "one WeeboSiUser names this team");
    assert_eq!(
        status.namespaces, 0,
        "research has the lower priority, so it owns the contested namespace"
    );
    let degraded = status
        .conditions
        .iter()
        .find(|condition| condition.type_ == "Degraded")
        .expect("the contested namespace should be reported");
    assert!(
        degraded.message.contains("owned by research"),
        "{}",
        degraded.message
    );

    // And the team that won reports it as its own.
    let research = Arc::new(teams.get("research").await.expect("the team should exist"));
    reconcile_team(research, identity_ctx(client.clone(), FeatureMode::Enforce))
        .await
        .expect("the pass should complete");
    let status = teams
        .get_status("research")
        .await
        .expect("status should be readable")
        .status
        .expect("status should have been written");
    assert_eq!(status.namespaces, 1);
    assert_eq!(status.members, 0);
    assert!(
        status
            .conditions
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True")
    );
}

/// A bare namespace, for the workspace application's destination.
async fn create_namespace(client: kube::Client, name: &str) {
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client);
    let namespace = k8s_openapi::api::core::v1::Namespace {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = namespaces.create(&PostParams::default(), &namespace).await;
}

/// A namespace carrying the team label both teams select on.
async fn create_labelled_namespace(client: kube::Client, name: &str, team: &str) {
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client);
    let namespace = k8s_openapi::api::core::v1::Namespace {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(std::collections::BTreeMap::from([(
                "weebo.io/team".to_string(),
                team.to_string(),
            )])),
            ..Default::default()
        },
        ..Default::default()
    };
    namespaces
        .create(&PostParams::default(), &namespace)
        .await
        .expect("the namespace should be accepted");
}
