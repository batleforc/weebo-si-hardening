//! RFC 0020's CA guard, the chart's `ValidatingAdmissionPolicy` rendered by `helm template` and
//! evaluated by a real apiserver: only the operator's controller may ask a team's CA for a
//! `Certificate`, only cert-manager may write a `CertificateRequest` to it, and every other
//! issuer is left alone. No webhook runs: the apiserver itself is the guard under test.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::time::Duration;

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{
    Api, ApiResource, DynamicObject, GroupVersionKind, ObjectMeta, Patch, PatchParams, PostParams,
};
use kube::{CustomResourceExt, ResourceExt};
use serde_json::{Value, json};
use weebo_si_crd::WeeboSiTeam;
use weebo_si_envtest_support::EnvTest;

const RELEASE_NAMESPACE: &str = "weebo-si-hardening";
const WORKSPACE: &str = "dev-ws-alice";
const TEAM_CA: &str = "team-weebo-tools-ca";
// The identities the rendered policy must name, spelled out rather than re-derived from it.
const OPERATOR: &str = "system:serviceaccount:weebo-si-hardening:ci-weebo-si-operator-controller";
const CERT_MANAGER: &str = "system:serviceaccount:cert-manager:cert-manager";
const OPERATOR_TOKEN: &str = "ca-guard-operator-token";
const CERT_MANAGER_TOKEN: &str = "ca-guard-cert-manager-token";
const ALICE_TOKEN: &str = "ca-guard-alice-token";
const CERT_MANAGER_CRDS: &str =
    include_str!("../../weebo-si-envtest-support/fixtures/cert-manager-crd.yaml");

fn resource(group: &str, version: &str, kind: &str, plural: &str) -> ApiResource {
    ApiResource::from_gvk_with_plural(&GroupVersionKind::gvk(group, version, kind), plural)
}

fn certificates(client: &kube::Client) -> Api<DynamicObject> {
    let ar = resource("cert-manager.io", "v1", "Certificate", "certificates");
    Api::namespaced_with(client.clone(), WORKSPACE, &ar)
}

fn certificate_requests(client: &kube::Client) -> Api<DynamicObject> {
    let ar = resource(
        "cert-manager.io",
        "v1",
        "CertificateRequest",
        "certificaterequests",
    );
    Api::namespaced_with(client.clone(), WORKSPACE, &ar)
}

fn object(kind: &str, name: &str, issuer: &str, extra: Value) -> DynamicObject {
    let mut spec =
        json!({"issuerRef": {"group": "cert-manager.io", "kind": "ClusterIssuer", "name": issuer}});
    spec.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(json!({
        "apiVersion": "cert-manager.io/v1",
        "kind": kind,
        "metadata": {"name": name, "namespace": WORKSPACE},
        "spec": spec,
    }))
    .unwrap()
}

fn certificate(name: &str, issuer: &str, common_name: &str) -> DynamicObject {
    object(
        "Certificate",
        name,
        issuer,
        json!({"commonName": common_name, "secretName": name}),
    )
}

fn render_policy() -> Vec<DynamicObject> {
    let chart_dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../charts/weebo-si-operator"
    );
    let output = std::process::Command::new("helm")
        .args([
            "template",
            "ci",
            chart_dir,
            "--namespace",
            RELEASE_NAMESPACE,
            "--set",
            "teamTools.rbac.enabled=true",
            "--show-only",
            "templates/validatingadmissionpolicy-team-tools-ca.yaml",
        ])
        .output()
        .expect("helm must be on PATH to render charts/weebo-si-operator — see task helm:lint");
    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .split("\n---")
        .filter(|doc| doc.contains("kind:"))
        .map(|doc| serde_yaml_bw::from_str(doc).expect("each document should parse"))
        .collect()
}

async fn apply_all(client: &kube::Client, documents: Vec<DynamicObject>, plurals: &[&str]) {
    for (doc, plural) in documents.into_iter().zip(plurals) {
        let types = doc.types.clone().unwrap();
        let (group, version) = types.api_version.split_once('/').unwrap();
        let api: Api<DynamicObject> = Api::all_with(
            client.clone(),
            &resource(group, version, &types.kind, plural),
        );
        api.patch(
            &doc.name_any(),
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&doc),
        )
        .await
        .unwrap();
    }
}

async fn wait_established(client: &kube::Client, names: &[&str]) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    for name in names {
        for attempt in 0..60 {
            let established = crds
                .get(name)
                .await
                .ok()
                .and_then(|crd| crd.status)
                .is_some_and(|status| {
                    status
                        .conditions
                        .unwrap_or_default()
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                });
            if established {
                break;
            }
            assert!(attempt < 59, "{name} never became established");
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

fn refused(result: Result<DynamicObject, kube::Error>, message: &str) {
    match result {
        Err(kube::Error::Api(status)) => assert!(
            status.message.contains(message),
            "refused for the wrong reason: {}",
            status.message
        ),
        other => panic!("expected a refusal naming {message:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn only_the_operator_and_cert_manager_reach_a_team_ca() {
    let Some(env_test) = EnvTest::try_start_with_identities(&[
        (OPERATOR_TOKEN, OPERATOR),
        (CERT_MANAGER_TOKEN, CERT_MANAGER),
        (ALICE_TOKEN, "alice"),
    ])
    .await
    else {
        return;
    };
    let admin = env_test.client().unwrap();
    let operator = env_test.client_as(OPERATOR_TOKEN).unwrap();
    let cert_manager = env_test.client_as(CERT_MANAGER_TOKEN).unwrap();
    let alice = env_test.client_as(ALICE_TOKEN).unwrap();

    let crds: Api<CustomResourceDefinition> = Api::all(admin.clone());
    let mut fixtures: Vec<CustomResourceDefinition> = CERT_MANAGER_CRDS
        .split("\n---")
        .map(|doc| serde_yaml_bw::from_str(doc).unwrap())
        .collect();
    fixtures.push(WeeboSiTeam::crd());
    for crd in &fixtures {
        crds.patch(
            &crd.name_any(),
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(crd),
        )
        .await
        .unwrap();
    }
    wait_established(
        &admin,
        &[
            "certificates.cert-manager.io",
            "certificaterequests.cert-manager.io",
            "weebositeams.hardening.weebo.io",
        ],
    )
    .await;
    Api::<Namespace>::all(admin.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(WORKSPACE.to_string()),
                    ..ObjectMeta::default()
                },
                ..Namespace::default()
            },
        )
        .await
        .unwrap();

    // Three teams: two without team tools, so the policy also runs against a param with no CA.
    let teams: Api<WeeboSiTeam> = Api::all(admin.clone());
    for team in [
        json!({"metadata": {"name": "weebo"}, "spec": {
            "namespaceSelector": {"matchLabels": {"weebo.io/team": "weebo"}},
            "features": {"teamTools": {
                "namespace": "team-weebo-tools",
                "issuerRef": {"kind": "ClusterIssuer", "name": TEAM_CA},
            }},
        }}),
        json!({"metadata": {"name": "plain"}, "spec": {
            "namespaceSelector": {"matchLabels": {"weebo.io/team": "plain"}},
        }}),
        // A null block (the CRD's fields are nullable) must not break the expression either.
        json!({"metadata": {"name": "nulled"}, "spec": {
            "namespaceSelector": {"matchLabels": {"weebo.io/team": "nulled"}},
            "features": {"teamTools": null},
        }}),
    ] {
        let mut team = team;
        team["apiVersion"] = json!("hardening.weebo.io/v1alpha1");
        team["kind"] = json!("WeeboSiTeam");
        teams
            .create(
                &PostParams::default(),
                &serde_json::from_value(team).unwrap(),
            )
            .await
            .unwrap();
    }

    apply_all(
        &admin,
        render_policy(),
        &[
            "validatingadmissionpolicies",
            "validatingadmissionpolicybindings",
        ],
    )
    .await;

    // The policy and its params reach the apiserver's informers asynchronously: wait for the
    // first refusal, deleting what slipped through before it.
    let forged = certificate("forged", TEAM_CA, "bob");
    let mut first = None;
    for _ in 0..80 {
        match certificates(&alice)
            .create(&PostParams::default(), &forged)
            .await
        {
            Ok(_) => {
                certificates(&admin)
                    .delete("forged", &Default::default())
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            err => {
                first = Some(err);
                break;
            }
        }
    }
    refused(
        first.expect("the policy never started refusing"),
        "only the weebo-si operator may request a certificate from team tools CA team-weebo-tools-ca",
    );

    // The same Certificate with an empty group and an omitted one is still the team CA.
    let mut no_group = certificate("no-group", TEAM_CA, "bob");
    no_group.data["spec"]["issuerRef"]
        .as_object_mut()
        .unwrap()
        .remove("group");
    refused(
        certificates(&alice)
            .create(&PostParams::default(), &no_group)
            .await,
        "only the weebo-si operator",
    );

    // The operator's controller is the one writer.
    certificates(&operator)
        .create(
            &PostParams::default(),
            &certificate("issued", TEAM_CA, "alice"),
        )
        .await
        .expect("the operator's controller may ask the team CA");

    // A user may not repoint it, but may touch its metadata.
    let mut tampered = certificates(&alice).get("issued").await.unwrap();
    tampered.data["spec"]["commonName"] = json!("bob");
    refused(
        certificates(&alice)
            .replace("issued", &PostParams::default(), &tampered)
            .await,
        "only the weebo-si operator",
    );
    let mut labelled = certificates(&alice).get("issued").await.unwrap();
    labelled
        .labels_mut()
        .insert("note".to_string(), "x".to_string());
    certificates(&alice)
        .replace("issued", &PostParams::default(), &labelled)
        .await
        .expect("a metadata-only update leaves the issued identity alone");

    // Any other issuer is none of the guard's business, whoever asks.
    certificates(&alice)
        .create(
            &PostParams::default(),
            &certificate("own", "letsencrypt", "alice"),
        )
        .await
        .expect("a non-team issuer is left alone");
    let mut namespaced = certificate("namespaced", TEAM_CA, "bob");
    namespaced.data["spec"]["issuerRef"]["kind"] = json!("Issuer");
    certificates(&alice)
        .create(&PostParams::default(), &namespaced)
        .await
        .expect("a namespaced Issuer of the same name is another issuer");

    // CertificateRequests: cert-manager only.
    let request = object(
        "CertificateRequest",
        "csr",
        TEAM_CA,
        json!({"request": "LS0t"}),
    );
    refused(
        certificate_requests(&alice)
            .create(&PostParams::default(), &request)
            .await,
        "only cert-manager may write a CertificateRequest to team tools CA",
    );
    certificate_requests(&cert_manager)
        .create(&PostParams::default(), &request)
        .await
        .expect("cert-manager writes the CertificateRequests of the operator's Certificates");
}
