//! The envtest tier, against a real ephemeral kube-apiserver.
//!
//! What a unit test of `validate()` cannot fake: that the *generated* CRD — the schema
//! `WeeboSiConfig::crd()` actually emits — is accepted by a real apiserver, and that the
//! apiserver's own OpenAPI validation rejects what our types say is required (`mode` has no
//! implicit default, per `feature_mode::tests::mode_has_no_implicit_default` — this is the same
//! claim, proven live).
//!
//! Gated behind the `envtest` feature so a plain `cargo test` needs no binaries.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, DeleteParams, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
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

async fn install_crd(client: kube::Client) -> Result<CustomResourceDefinition, kube::Error> {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let crd = WeeboSiConfig::crd();
    let name = crd.name_any();
    crds.patch(
        &name,
        &PatchParams::apply("envtest").force(),
        &Patch::Apply(&crd),
    )
    .await
}

async fn wait_for_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    for _ in 0..60 {
        if let Ok(crd) = crds.get("weebosiconfigs.hardening.weebo.io").await {
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

fn config(name: &str, spec: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": name },
        "spec": spec,
    })
}

type DynamicApi = Api<kube::api::DynamicObject>;

fn configs(client: kube::Client) -> DynamicApi {
    let gvk = kube::api::GroupVersionKind::gvk("hardening.weebo.io", "v1alpha1", "WeeboSiConfig");
    let resource = kube::api::ApiResource::from_gvk_with_plural(&gvk, "weebosiconfigs");
    Api::all_with(client, &resource)
}

/// The headline check: the CRD this crate generates is accepted as-is.
#[tokio::test]
async fn the_generated_crd_is_accepted_by_a_real_apiserver() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");

    let installed = install_crd(client.clone())
        .await
        .expect("the generated CRD should be accepted");

    assert_eq!(installed.spec.group, "hardening.weebo.io");
    assert_eq!(installed.spec.names.kind, "WeeboSiConfig");
}

/// `spec.features: {}` is deliberately the simplest useful configuration, per RFC 0002's
/// *Guide-level explanation* — installing the operator must change nothing.
#[tokio::test]
async fn an_empty_features_block_is_accepted() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await.expect("CRD install");
    wait_for_crd(client.clone()).await;

    let api = configs(client);
    let created = api
        .create(
            &PostParams::default(),
            &serde_json::from_value(config("cluster", serde_json::json!({})))
                .expect("resource should deserialize"),
        )
        .await
        .expect("an empty features block should be accepted");

    assert_eq!(created.name_any(), "cluster");
    let _ = api.delete("cluster", &DeleteParams::default()).await;
}

/// `mode` has no implicit default — the same claim `feature_mode::tests::mode_has_no_implicit_default`
/// proves against `serde_json` alone, proven here against a real apiserver's OpenAPI validation.
#[tokio::test]
async fn admission_rejects_a_dwoc_pin_block_missing_mode() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await.expect("CRD install");
    wait_for_crd(client.clone()).await;

    let spec = serde_json::json!({
        "features": {
            "dwocPin": {
                "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                "default": "baseline",
            }
        }
    });

    let error = configs(client)
        .create(
            &PostParams::default(),
            &serde_json::from_value(config("cluster", spec)).expect("resource should deserialize"),
        )
        .await
        .expect_err("admission should reject a dwocPin block with no mode");

    assert!(
        error.to_string().contains("mode"),
        "unexpected error: {error}"
    );
}

/// A well-formed `dwocPin` block, with `mode` present, is accepted.
#[tokio::test]
async fn a_well_formed_dwoc_pin_block_is_accepted() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await.expect("CRD install");
    wait_for_crd(client.clone()).await;

    let spec = serde_json::json!({
        "features": {
            "dwocPin": {
                "mode": "DryRun",
                "catalog": [{"key": "baseline", "name": "weebo-hardened-config", "namespace": "eclipse-che"}],
                "default": "baseline",
            }
        }
    });

    let api = configs(client);
    let created = api
        .create(
            &PostParams::default(),
            &serde_json::from_value(config("cluster", spec)).expect("resource should deserialize"),
        )
        .await
        .expect("a well-formed dwocPin block should be accepted");

    assert_eq!(
        created.data["spec"]["features"]["dwocPin"]["mode"],
        serde_json::json!("DryRun")
    );
    let _ = api.delete("cluster", &DeleteParams::default()).await;
}

/// `spec.teams`' `namespaceSelector.matchExpressions` round-trips through a real apiserver —
/// the wire-compatibility claim `selector::tests::wire_shape_matches_upstream_label_selector`
/// proves against `serde_json` alone, proven here against the apiserver's own OpenAPI validation
/// (which would reject an operator it does not recognize as one of the closed set upstream
/// defines) and its schema defaulting (an omitted `values` on `Exists`).
#[tokio::test]
async fn teams_with_match_expressions_round_trip() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    install_crd(client.clone()).await.expect("CRD install");
    wait_for_crd(client.clone()).await;

    let spec = serde_json::json!({
        "teams": [
            {
                "name": "team-1",
                "namespaceSelector": {
                    "matchLabels": {"weebo.io/team": "team-1"},
                    "matchExpressions": [
                        {"key": "env", "operator": "In", "values": ["prod", "staging"]},
                        {"key": "weebo.io/legacy", "operator": "DoesNotExist"},
                    ],
                },
            },
        ],
        "features": {},
    });

    let api = configs(client);
    let created = api
        .create(
            &PostParams::default(),
            &serde_json::from_value(config("cluster", spec)).expect("resource should deserialize"),
        )
        .await
        .expect("teams with matchExpressions should be accepted");

    let expressions = &created.data["spec"]["teams"][0]["namespaceSelector"]["matchExpressions"];
    assert_eq!(expressions[0]["operator"], serde_json::json!("In"));
    assert_eq!(
        expressions[1]["operator"],
        serde_json::json!("DoesNotExist")
    );

    let _ = api.delete("cluster", &DeleteParams::default()).await;
}
