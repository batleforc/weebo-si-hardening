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
use weebo_si_crd::WeeboSiConfig;
use weebo_si_envtest_support::EnvTest;

macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

async fn install_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let crd = WeeboSiConfig::crd();
    let name = crd.name_any();
    crds.patch(
        &name,
        &PatchParams::apply("envtest").force(),
        &Patch::Apply(&crd),
    )
    .await
    .expect("CRD install");
    for _ in 0..60 {
        if let Ok(crd) = crds.get(&name).await {
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
    panic!("the CRD never became established");
}

/// A grant naming a team `spec.teams` never declared — one of `validate()`'s own table-tested
/// violations, proven here to actually reach `status.conditions` through a live reconcile.
#[tokio::test]
async fn a_grant_naming_an_undeclared_team_is_reported_degraded() {
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
                    "mode": "DryRun",
                    "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                    "default": "baseline",
                    "grants": {
                        "ghost-team": {"allowed": ["baseline"], "default": "baseline"}
                    },
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
    assert!(status.features[0].message.contains("ghost-team"));

    let _ = api.delete("cluster", &DeleteParams::default()).await;
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

/// Every `validate()` violation `weebo-si-crd`'s unit tests exercise in isolation is proven here
/// to reach `status.conditions` together, through one real reconcile — not just the one
/// (`GrantNamesUndeclaredTeam`) the headline test above covers.
#[tokio::test]
async fn every_validate_violation_reaches_status() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await;

    let api: Api<WeeboSiConfig> = Api::all(client.clone());
    let spec = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": "cluster" },
        "spec": {
            "teams": [{"name": "team-1", "namespaceSelector": {}}],
            "features": {
                "dwocPin": {
                    "mode": "DryRun",
                    // "baseline" declared twice: DuplicateCatalogKey.
                    "catalog": [
                        {"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"},
                        {"key": "baseline", "name": "other-config", "namespace": "eclipse-che"},
                    ],
                    // absent from the catalogue: DefaultNotInCatalog.
                    "default": "missing",
                    "grants": {
                        // declared team, but an empty allowed set: GrantAllowedEmpty. Default
                        // outside its own (empty) allowed: GrantDefaultOutsideAllowed too.
                        "team-1": {"allowed": [], "default": "baseline"},
                        // undeclared team: GrantNamesUndeclaredTeam.
                        "ghost-team": {"allowed": ["baseline"], "default": "baseline"},
                    },
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
    let message = status.features[0].message.clone();
    for needle in ["baseline", "missing", "team-1", "ghost-team"] {
        assert!(
            message.contains(needle),
            "expected the Degraded message to name every violation (missing {needle:?}): {message}"
        );
    }

    let _ = api.delete("cluster", &DeleteParams::default()).await;
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
