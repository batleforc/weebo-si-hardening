//! Pins the RBAC table `charts/weebo-si-operator/templates/rbac.yaml`'s own comment quotes from
//! RFC 0002's *Security considerations* — "the webhook role needs, cluster-wide: get, list,
//! watch on weebosiconfigs / devworkspaceoperatorconfigs / namespaces ... and the controller
//! role adds update and patch on weebosiconfigs/status, plus create on events" — against a real,
//! RBAC-enforcing apiserver, not `helm lint`/`helm template`'s syntax check alone.
//!
//! Unlike every other suite in this workspace, this one does not use
//! `weebo_si_envtest_support::EnvTest::start`: that tier runs with `--authorization-mode
//! AlwaysAllow` on purpose (see its own doc comment) because those suites are about CRD
//! admission and controller/webhook behaviour, not RBAC. This suite uses
//! [`EnvTest::start_rbac`] instead, authenticating as the exact `ServiceAccount` identities the
//! rendered chart's `ClusterRoleBinding`s name — so every assertion below is a real API request
//! the RBAC authorizer actually evaluates against the rendered rules, not a `helm template` read
//! of the source text.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{Event, Namespace, ObjectReference};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{
    Api, DeleteParams, DynamicObject, GroupVersionKind, ListParams, ObjectMeta, Patch, PatchParams,
    PostParams,
};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_crd::WeeboSiConfig;
use weebo_si_envtest_support::EnvTest;

const RELEASE_NAMESPACE: &str = "weebo-si-hardening";
const WEBHOOK_TOKEN: &str = "rbac-envtest-webhook-token";
const CONTROLLER_TOKEN: &str = "rbac-envtest-controller-token";

const DEVWORKSPACE_OPERATOR_CONFIG_CRD: &str =
    include_str!("../../weebo-si-webhook/tests/fixtures/devworkspaceoperatorconfig-crd.yaml");

#[derive(serde::Deserialize)]
struct KindProbe {
    kind: String,
}

fn dwoc_resource() -> kube::api::ApiResource {
    let gvk = GroupVersionKind::gvk(
        "controller.devfile.io",
        "v1alpha1",
        "DevWorkspaceOperatorConfig",
    );
    kube::api::ApiResource::from_gvk_with_plural(&gvk, "devworkspaceoperatorconfigs")
}

/// Renders one template of `charts/weebo-si-operator` with the chart's own defaults — the
/// values `rbac.create`/`controller.leaderElection` govern are both `true` out of the box, which
/// is exactly the shape a real install ships.
fn helm_show(show_only: &str) -> String {
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
            "--show-only",
            show_only,
        ])
        .output()
        .expect("helm must be on PATH to render charts/weebo-si-operator — see task helm:lint");
    assert!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("helm output should be utf8")
}

/// Splits a `helm template` render on its `---` document separators.
fn split_documents(rendered: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut current = String::new();
    for line in rendered.lines() {
        if line.trim() == "---" {
            if !current.trim().is_empty() {
                docs.push(std::mem::take(&mut current));
            }
            current.clear();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.trim().is_empty() {
        docs.push(current);
    }
    docs
}

/// The `ServiceAccount` identity a `ClusterRoleBinding` whose name ends with `suffix` grants —
/// read from the rendered manifest itself rather than reconstructed from the chart's naming
/// helpers, so this test cannot silently pass by re-deriving the same name it should be
/// checking against.
fn service_account_identity(documents: &[String], suffix: &str) -> String {
    for doc in documents {
        let probe: KindProbe =
            serde_yaml_bw::from_str(doc).expect("each document should have a kind");
        if probe.kind != "ClusterRoleBinding" {
            continue;
        }
        let binding: ClusterRoleBinding =
            serde_yaml_bw::from_str(doc).expect("should parse as a ClusterRoleBinding");
        let name = binding.name_any();
        if !name.ends_with(suffix) {
            continue;
        }
        let subject = binding
            .subjects
            .and_then(|subjects| subjects.into_iter().next())
            .unwrap_or_else(|| panic!("{name} should carry a subject"));
        assert_eq!(
            subject.kind, "ServiceAccount",
            "{name}'s subject should be a ServiceAccount"
        );
        let namespace = subject
            .namespace
            .unwrap_or_else(|| panic!("{name}'s subject should carry a namespace"));
        return format!("system:serviceaccount:{namespace}:{}", subject.name);
    }
    panic!("no ClusterRoleBinding named *{suffix} found in the rendered manifest");
}

/// Applies one rendered document as its real typed kind — proving the chart's own RBAC objects,
/// not a hand-written stand-in, actually govern the assertions below.
async fn apply_document(admin: kube::Client, doc: &str) {
    let probe: KindProbe = serde_yaml_bw::from_str(doc).expect("each document should have a kind");
    match probe.kind.as_str() {
        "ClusterRole" => {
            let object: ClusterRole =
                serde_yaml_bw::from_str(doc).expect("should parse as a ClusterRole");
            let name = object.name_any();
            let api: Api<ClusterRole> = Api::all(admin);
            api.create(&PostParams::default(), &object)
                .await
                .unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
        }
        "ClusterRoleBinding" => {
            let object: ClusterRoleBinding =
                serde_yaml_bw::from_str(doc).expect("should parse as a ClusterRoleBinding");
            let name = object.name_any();
            let api: Api<ClusterRoleBinding> = Api::all(admin);
            api.create(&PostParams::default(), &object)
                .await
                .unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
        }
        "Role" => {
            let object: Role = serde_yaml_bw::from_str(doc).expect("should parse as a Role");
            let name = object.name_any();
            let api: Api<Role> = Api::namespaced(admin, RELEASE_NAMESPACE);
            api.create(&PostParams::default(), &object)
                .await
                .unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
        }
        "RoleBinding" => {
            let object: RoleBinding =
                serde_yaml_bw::from_str(doc).expect("should parse as a RoleBinding");
            let name = object.name_any();
            let api: Api<RoleBinding> = Api::namespaced(admin, RELEASE_NAMESPACE);
            api.create(&PostParams::default(), &object)
                .await
                .unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
        }
        other => panic!("unexpected kind in rbac.yaml: {other}"),
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
    panic!("{name} never became established");
}

async fn install_crds(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let dwoc: CustomResourceDefinition = serde_yaml_bw::from_str(DEVWORKSPACE_OPERATOR_CONFIG_CRD)
        .expect("the fixture should parse");
    for crd in [dwoc, WeeboSiConfig::crd()] {
        let name = crd.name_any();
        crds.patch(
            &name,
            &PatchParams::apply("envtest").force(),
            &Patch::Apply(&crd),
        )
        .await
        .unwrap_or_else(|err| panic!("installing {name} should succeed: {err}"));
        wait_established(&crds, &name).await;
    }
}

async fn create_release_namespace(client: kube::Client) {
    let namespaces: Api<Namespace> = Api::all(client);
    let namespace = Namespace {
        metadata: ObjectMeta {
            name: Some(RELEASE_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = namespaces.create(&PostParams::default(), &namespace).await;
}

/// Creates the singleton `WeeboSiConfig`, as the admin identity — neither role under test may
/// write it directly, only the controller role's own `status` slice.
async fn create_weebosiconfig(client: kube::Client) {
    let api: Api<WeeboSiConfig> = Api::all(client);
    let value = serde_json::json!({
        "apiVersion": "hardening.weebo.io/v1alpha1",
        "kind": "WeeboSiConfig",
        "metadata": { "name": weebo_si_crd::SINGLETON_NAME },
        "spec": {},
    });
    api.create(
        &PostParams::default(),
        &serde_json::from_value(value).expect("resource should deserialize"),
    )
    .await
    .expect("the admin identity should be able to create the config");
}

fn test_event(name: &str) -> Event {
    Event {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(RELEASE_NAMESPACE.to_string()),
            ..Default::default()
        },
        involved_object: ObjectReference {
            api_version: Some("hardening.weebo.io/v1alpha1".to_string()),
            kind: Some("WeeboSiConfig".to_string()),
            name: Some(weebo_si_crd::SINGLETON_NAME.to_string()),
            // Core validation requires this to match the Event's own namespace, even though the
            // referenced `WeeboSiConfig` is itself cluster-scoped — not a real-world constraint
            // this test cares about, just what the apiserver demands to accept the object at all.
            namespace: Some(RELEASE_NAMESPACE.to_string()),
            ..Default::default()
        },
        reason: Some("RbacEnvtest".to_string()),
        message: Some("emitted by the RBAC envtest suite".to_string()),
        type_: Some("Normal".to_string()),
        ..Default::default()
    }
}

fn test_lease(name: &str) -> Lease {
    Lease {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(RELEASE_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: None,
    }
}

/// Asserts `result` failed with a `403 Forbidden` — the RBAC authorizer actually refusing the
/// request, not the object simply not existing (`404`) or failing validation.
fn assert_forbidden<T: std::fmt::Debug>(result: Result<T, kube::Error>, message: &str) {
    match result {
        Err(kube::Error::Api(ref err)) if err.code == 403 => {}
        other => panic!("{message}, got: {other:?}"),
    }
}

/// Shared fixture: renders and applies the real `rbac.yaml`, installs the CRDs its rules name,
/// and returns the two `ServiceAccount` clients + the admin client (for setup the test itself
/// still needs, e.g. reading back a status write).
async fn rbac_fixture() -> Option<(EnvTest, kube::Client, kube::Client, kube::Client)> {
    let rendered = helm_show("templates/rbac.yaml");
    let documents = split_documents(&rendered);
    let webhook_identity = service_account_identity(&documents, "-webhook-watch");
    let controller_identity = service_account_identity(&documents, "-controller-watch");

    let env_test = EnvTest::try_start_rbac(&[
        (WEBHOOK_TOKEN, webhook_identity.as_str()),
        (CONTROLLER_TOKEN, controller_identity.as_str()),
    ])
    .await?;
    let admin = env_test.client().expect("client should build");

    install_crds(admin.clone()).await;
    create_release_namespace(admin.clone()).await;
    for doc in &documents {
        apply_document(admin.clone(), doc).await;
    }
    create_weebosiconfig(admin.clone()).await;

    let webhook = env_test
        .client_as(WEBHOOK_TOKEN)
        .expect("client should build");
    let controller = env_test
        .client_as(CONTROLLER_TOKEN)
        .expect("client should build");
    Some((env_test, admin, webhook, controller))
}

/// The webhook role's documented grant: `get`/`list`/`watch` on `weebosiconfigs`,
/// `devworkspaceoperatorconfigs` and `namespaces`, cluster-wide, and nothing else — no write on
/// `weebosiconfigs` or its `status`, no `events`, no lease.
#[tokio::test]
async fn webhook_role_matches_the_documented_grants() {
    let Some((_env_test, _admin, webhook, _controller)) = rbac_fixture().await else {
        return;
    };

    assert!(
        Api::<WeeboSiConfig>::all(webhook.clone())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the webhook role should be able to list weebosiconfigs"
    );
    assert!(
        Api::<DynamicObject>::all_with(webhook.clone(), &dwoc_resource())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the webhook role should be able to list devworkspaceoperatorconfigs"
    );
    assert!(
        Api::<Namespace>::all(webhook.clone())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the webhook role should be able to list namespaces"
    );

    assert_forbidden(
        Api::<WeeboSiConfig>::all(webhook.clone())
            .patch_status(
                weebo_si_crd::SINGLETON_NAME,
                &PatchParams::apply("rbac-envtest"),
                &Patch::Merge(serde_json::json!({"status": {"observedGeneration": 1}})),
            )
            .await,
        "the webhook role must not be able to write weebosiconfigs/status",
    );
    assert_forbidden(
        Api::<WeeboSiConfig>::all(webhook.clone())
            .patch(
                weebo_si_crd::SINGLETON_NAME,
                &PatchParams::apply("rbac-envtest"),
                &Patch::Merge(serde_json::json!({"spec": {"teams": []}})),
            )
            .await,
        "the webhook role must not be able to write weebosiconfigs' spec either",
    );
    assert_forbidden(
        Api::<Event>::namespaced(webhook.clone(), RELEASE_NAMESPACE)
            .create(&PostParams::default(), &test_event("webhook-should-fail"))
            .await,
        "the webhook role must not be able to create events",
    );
    assert_forbidden(
        Api::<Lease>::namespaced(webhook.clone(), RELEASE_NAMESPACE)
            .list(&ListParams::default())
            .await,
        "the webhook role must not be able to touch the leader-election lease",
    );
    assert_forbidden(
        Api::<WeeboSiConfig>::all(webhook)
            .delete(weebo_si_crd::SINGLETON_NAME, &DeleteParams::default())
            .await,
        "the webhook role must not be able to delete weebosiconfigs",
    );
}

/// The controller role's documented grant: everything the webhook role has, plus `update`/`patch`
/// on `weebosiconfigs/status` and `create` on `events`, plus (the leader-election amendment) full
/// control of its own namespace's `Lease` — and still no write on `weebosiconfigs` itself.
#[tokio::test]
async fn controller_role_matches_the_documented_grants() {
    let Some((_env_test, admin, _webhook, controller)) = rbac_fixture().await else {
        return;
    };

    assert!(
        Api::<WeeboSiConfig>::all(controller.clone())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the controller role should be able to list weebosiconfigs"
    );
    assert!(
        Api::<DynamicObject>::all_with(controller.clone(), &dwoc_resource())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the controller role should be able to list devworkspaceoperatorconfigs"
    );
    assert!(
        Api::<Namespace>::all(controller.clone())
            .list(&ListParams::default())
            .await
            .is_ok(),
        "the controller role should be able to list namespaces"
    );

    Api::<WeeboSiConfig>::all(controller.clone())
        .patch_status(
            weebo_si_crd::SINGLETON_NAME,
            &PatchParams::apply("weebo-si-controller"),
            &Patch::Merge(serde_json::json!({"status": {"observedGeneration": 7}})),
        )
        .await
        .expect("the controller role should be able to write weebosiconfigs/status");
    let refreshed: WeeboSiConfig = Api::all(admin)
        .get(weebo_si_crd::SINGLETON_NAME)
        .await
        .expect("the admin identity should still be able to read it back");
    assert_eq!(
        refreshed.status.map(|status| status.observed_generation),
        Some(7),
        "the controller role's status write should actually have landed"
    );

    Api::<Event>::namespaced(controller.clone(), RELEASE_NAMESPACE)
        .create(
            &PostParams::default(),
            &test_event("controller-should-pass"),
        )
        .await
        .expect("the controller role should be able to create events");

    Api::<Lease>::namespaced(controller.clone(), RELEASE_NAMESPACE)
        .create(
            &PostParams::default(),
            &test_lease("controller-should-pass"),
        )
        .await
        .expect("the controller role should be able to create the leader-election lease");

    assert_forbidden(
        Api::<WeeboSiConfig>::all(controller.clone())
            .patch(
                weebo_si_crd::SINGLETON_NAME,
                &PatchParams::apply("rbac-envtest"),
                &Patch::Merge(serde_json::json!({"spec": {"teams": []}})),
            )
            .await,
        "the controller role must not be able to write weebosiconfigs' spec, only its status",
    );
    assert_forbidden(
        Api::<WeeboSiConfig>::all(controller)
            .delete(weebo_si_crd::SINGLETON_NAME, &DeleteParams::default())
            .await,
        "the controller role must not be able to delete weebosiconfigs",
    );
}
