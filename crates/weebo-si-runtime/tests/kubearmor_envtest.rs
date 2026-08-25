//! Proves RFC 0006's kube adapters (`KubeArmorTemplateStore`, `KubeArmorPolicyStore`,
//! `KubeArmorCapabilities`) against a real, ephemeral apiserver — the layer the pure unit tests
//! in `weebo-si-kubearmor-policy` cannot reach, since none of them touch `kube`.
//!
//! Each test builds `weebo_si_kubearmor_policy::reconcile`'s inputs directly rather than going
//! through the watch-driven controller loop, so each assertion is deterministic and fast — same
//! shape as [`super::envtest`]'s suite for `network-profiles`.
//!
//! **What this suite proves and what it cannot.** It proves what the adapter writes, that a
//! written object reads back as the same `ManagedObject` it was built from, and that `DryRun`
//! writes nothing. It cannot prove KubeArmor accepts or enforces any of it: the CRD here is a
//! `x-kubernetes-preserve-unknown-fields` stand-in and there is no KubeArmor daemonset behind
//! it, so no green run here should be read as proof of runtime behaviour. What the baseline's
//! empty `matchLabels` *means* to KubeArmor — every pod in the namespace — is confirmed and
//! asserted below; the posture annotations' effect is not, and is RFC 0006's own outstanding
//! item.

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

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::ResourceExt;
use kube::api::{Api, DynamicObject, ObjectMeta, Patch, PatchParams, PostParams};
use serde_json::json;
use weebo_si_chassis::Context;
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_crd::{
    FeatureMode, KubeArmorPolicyConfig, NamespaceName, OnNotGranted, RuntimeBackend,
    RuntimeEnforcement, RuntimeEnforcementBackend, RuntimeNamespaceSelection, RuntimeProfile,
    RuntimeProfileCatalog, RuntimeProfileGrant, RuntimeProfileKey, RuntimeWorkspaceSelection,
    Selector, Team, TeamName, TemplateRef,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_kubearmor_policy::{
    Capabilities, KubeArmorPolicy, NamespaceSubject, PodSelector, PolicyStore, Workspace,
};
use weebo_si_runtime::{
    KubeArmorCapabilities, KubeArmorPolicyStore, KubeArmorTemplateStore, kubearmor_policy_resource,
};

const TEMPLATES_NAMESPACE: &str = "weebo-si-hardening";
const WORKSPACE_NAMESPACE: &str = "user-alice";
const WORKSPACE_ID: &str = "workspacede4f56";

const KUBEARMOR_POLICY_CRD: &str = include_str!("fixtures/kubearmorpolicy-crd.yaml");

/// Start an apiserver or skip — envtest binaries are an opt-in tier, per `task envtest:setup`.
macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
}

async fn install_kubearmor_crd(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let crd: CustomResourceDefinition =
        serde_yaml_bw::from_str(KUBEARMOR_POLICY_CRD).expect("the fixture should parse");
    let name = crd.name_any();
    crds.patch(
        &name,
        &PatchParams::apply("envtest").force(),
        &Patch::Apply(&crd),
    )
    .await
    .unwrap_or_else(|err| panic!("installing {name} should succeed: {err}"));

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
    panic!("{name} never became established");
}

async fn create_namespace(client: kube::Client, name: &str) {
    let api: Api<Namespace> = Api::all(client);
    let ns = Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let _ = api.create(&PostParams::default(), &ns).await;
}

/// An admin-authored template: rule content plus a `selector` this project must ignore.
async fn create_template(client: kube::Client, key: &str) {
    let resource = kubearmor_policy_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(client, TEMPLATES_NAMESPACE, &resource);
    let mut obj = DynamicObject::new(&format!("weebo-{key}-runtime"), &resource);
    obj.metadata.namespace = Some(TEMPLATES_NAMESPACE.to_string());
    obj.data = json!({
        "spec": {
            // The selector an admin wrote into the template. RFC 0006: scoping belongs to the
            // operator, so this must never reach a workspace namespace.
            "selector": {"matchLabels": {"app": "whatever-the-admin-typed"}},
            "process": {"matchPaths": [{"path": format!("/usr/bin/{key}")}]},
            "capabilities": {"matchCapabilities": [{"capability": "net_raw"}]},
        }
    });
    api.create(&PostParams::default(), &obj)
        .await
        .expect("template should be created");
}

fn config(
    mode: FeatureMode,
    baseline: &str,
    catalog_keys: &[&str],
    grants: BTreeMap<String, RuntimeProfileGrant>,
) -> KubeArmorPolicyConfig {
    let catalog = RuntimeProfileCatalog::new(
        catalog_keys
            .iter()
            .map(|key| RuntimeProfile {
                key: RuntimeProfileKey::new(*key),
                template_ref: TemplateRef {
                    name: format!("weebo-{key}-runtime"),
                    namespace: NamespaceName::new(TEMPLATES_NAMESPACE),
                },
            })
            .collect(),
    );
    KubeArmorPolicyConfig {
        mode,
        namespace_selector: None,
        catalog,
        baseline: RuntimeProfileKey::new(baseline),
        grants,
        namespace_selection: RuntimeNamespaceSelection::default(),
        workspace_selection: RuntimeWorkspaceSelection::default(),
        on_not_granted: OnNotGranted::default(),
        enforcement: RuntimeEnforcement::default(),
    }
}

async fn feature_with(
    client: kube::Client,
    cfg: KubeArmorPolicyConfig,
) -> (KubeArmorPolicy, KubeArmorPolicyStore) {
    let capabilities = KubeArmorCapabilities::discover(client.clone())
        .await
        .expect("discovery should succeed");
    assert!(
        capabilities.offers(RuntimeBackend::KubeArmor),
        "the fixture CRD is installed, so discovery must report the engine offered"
    );
    let backend =
        weebo_si_kubearmor_policy::resolve_backend(RuntimeEnforcementBackend::Auto, &capabilities)
            .expect("KubeArmor should resolve once its CRD is installed");
    let templates = Arc::new(
        KubeArmorTemplateStore::spawn(client.clone(), TEMPLATES_NAMESPACE)
            .await
            .expect("template store should start"),
    );
    let policy_store = KubeArmorPolicyStore::spawn(client)
        .await
        .expect("policy store should start");
    let feature = KubeArmorPolicy::new(
        Arc::new(RwLock::new(Some(cfg))),
        Arc::new(RwLock::new(backend)),
        templates,
    );
    (feature, policy_store)
}

fn empty_context() -> (NamespaceFacts, FakeDwocCatalog) {
    (
        NamespaceFacts::default(),
        FakeDwocCatalog::new(std::iter::empty()),
    )
}

async fn written(client: kube::Client, name: &str) -> DynamicObject {
    let resource = kubearmor_policy_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(client, WORKSPACE_NAMESPACE, &resource);
    api.get(name)
        .await
        .unwrap_or_else(|err| panic!("{name} should exist in {WORKSPACE_NAMESPACE}: {err}"))
}

async fn bootstrap(client: kube::Client, keys: &[&str]) {
    install_kubearmor_crd(client.clone()).await;
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    for key in keys {
        create_template(client.clone(), key).await;
    }
}

#[tokio::test]
async fn the_baseline_is_written_for_real_in_enforce_mode() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    bootstrap(client.clone(), &["base"]).await;

    let (feature, policy_store) = feature_with(
        client.clone(),
        config(FeatureMode::Enforce, "base", &["base"], BTreeMap::new()),
    )
    .await;

    let (namespace_facts, dwoc_catalog) = empty_context();
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
    };

    let outcome = weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");
    assert_eq!(outcome.applied.expect("Enforce should apply").created, 1);

    let object = written(client, "weebo-base").await;
    let labels = object
        .metadata
        .labels
        .as_ref()
        .expect("labels should be set");
    assert_eq!(
        labels.get("hardening.weebo.io/managed-by"),
        Some(&"weebo-si-operator".to_string())
    );
    assert_eq!(
        labels.get("hardening.weebo.io/profile"),
        Some(&"base".to_string())
    );
    assert_eq!(
        labels.get("hardening.weebo.io/backend"),
        Some(&"KubeArmor".to_string())
    );

    let spec = object.data.get("spec").expect("spec should be set");
    assert_eq!(
        spec.pointer("/process/matchPaths/0/path"),
        Some(&json!("/usr/bin/base")),
        "the template's rule content should have round-tripped verbatim"
    );
    assert_eq!(
        spec.get("selector"),
        Some(&json!({"matchLabels": {}})),
        "the baseline governs every pod in the namespace, and the template's own selector is gone"
    );
}

#[tokio::test]
async fn a_workspace_object_selects_only_that_workspaces_pods() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    bootstrap(client.clone(), &["base", "git-write"]).await;

    let mut grants = BTreeMap::new();
    grants.insert(
        "team-1".to_string(),
        RuntimeProfileGrant {
            allowed: vec![RuntimeProfileKey::new("git-write")],
            default: vec![RuntimeProfileKey::new("git-write")],
        },
    );
    let (feature, policy_store) = feature_with(
        client.clone(),
        config(FeatureMode::Enforce, "base", &["base", "git-write"], grants),
    )
    .await;

    let teams = [Team {
        name: TeamName::new("team-1"),
        namespace_selector: Selector {
            match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
            match_expressions: Vec::new(),
        },
    }];
    let namespace_facts = NamespaceFacts {
        labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
        selection_annotation: None,
    };
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let ctx = Context::new(&teams, &namespace_facts, &dwoc_catalog);
    let subject = Workspace {
        name: "data-pipeline".to_string(),
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
        workspace_id: WORKSPACE_ID.to_string(),
        attribute: None,
        namespace_annotation: None,
    };

    weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");

    let object = written(client, &format!("weebo-git-write-{WORKSPACE_ID}")).await;
    assert_eq!(
        object.data.pointer("/spec/selector/matchLabels"),
        Some(&json!({"controller.devfile.io/devworkspace_id": WORKSPACE_ID})),
        "a profile object governs one workspace's pods, never the whole namespace"
    );
}

#[tokio::test]
async fn dry_run_writes_nothing_at_all() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    bootstrap(client.clone(), &["base"]).await;

    let (feature, policy_store) = feature_with(
        client.clone(),
        config(FeatureMode::DryRun, "base", &["base"], BTreeMap::new()),
    )
    .await;

    let (namespace_facts, dwoc_catalog) = empty_context();
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
    };

    let outcome = weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::DryRun,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");
    assert_eq!(outcome.diffs.len(), 1, "the pass still computes the diff");
    assert_eq!(outcome.applied, None);
    assert!(
        outcome.posture.is_some(),
        "and still reports the posture it would write"
    );
    assert_eq!(
        outcome.posture_to_write(),
        None,
        "but a dry run must not change what KubeArmor does with an unmatched operation"
    );

    let resource = kubearmor_policy_resource();
    let api: Api<DynamicObject> = Api::namespaced_with(client, WORKSPACE_NAMESPACE, &resource);
    assert!(
        api.get_opt("weebo-base")
            .await
            .expect("get should work")
            .is_none(),
        "DryRun must never write to the cluster"
    );
}

#[tokio::test]
async fn a_written_object_reads_back_as_the_same_managed_object() {
    // The property every reconcile after the first one depends on: if a round trip through the
    // apiserver did not preserve the body byte-for-byte, every pass would see a change and
    // rewrite the policy — which for KubeArmor means reprogramming the LSM on every node.
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    bootstrap(client.clone(), &["base"]).await;

    let (feature, policy_store) = feature_with(
        client.clone(),
        config(FeatureMode::Enforce, "base", &["base"], BTreeMap::new()),
    )
    .await;

    let (namespace_facts, dwoc_catalog) = empty_context();
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
    };

    weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("first reconcile should succeed");

    // The watch cache has to catch up before the second pass can see what the first wrote.
    for _ in 0..40 {
        if !policy_store
            .managed_in(&NamespaceName::new(WORKSPACE_NAMESPACE))
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let managed = policy_store.managed_in(&NamespaceName::new(WORKSPACE_NAMESPACE));
    assert_eq!(managed.len(), 1);
    assert_eq!(managed[0].pod_selector, PodSelector::Empty);
    assert_eq!(managed[0].profile, RuntimeProfileKey::new("base"));
    assert_eq!(managed[0].backend, RuntimeBackend::KubeArmor);

    let outcome = weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("second reconcile should succeed");
    let applied = outcome.applied.expect("Enforce should apply");
    assert_eq!(
        (applied.created, applied.updated, applied.unchanged),
        (0, 0, 1),
        "a steady state must be unchanged, not a rewrite: {:?}",
        outcome.diffs
    );
}

#[tokio::test]
async fn drift_is_put_back_on_the_next_enforce_pass() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    bootstrap(client.clone(), &["base"]).await;

    let (feature, policy_store) = feature_with(
        client.clone(),
        config(FeatureMode::Enforce, "base", &["base"], BTreeMap::new()),
    )
    .await;

    let (namespace_facts, dwoc_catalog) = empty_context();
    let ctx = Context::new(&[], &namespace_facts, &dwoc_catalog);
    let subject = NamespaceSubject {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
    };

    weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("first reconcile should succeed");

    // Somebody edits the rules out from under us, keeping the ownership label on.
    let resource = kubearmor_policy_resource();
    let api: Api<DynamicObject> =
        Api::namespaced_with(client.clone(), WORKSPACE_NAMESPACE, &resource);
    api.patch(
        "weebo-base",
        &PatchParams::default(),
        &Patch::Merge(json!({"spec": {"process": {"matchPaths": [{"path": "/bin/anything"}]}}})),
    )
    .await
    .expect("the tamper should apply");

    for _ in 0..40 {
        let managed = policy_store.managed_in(&NamespaceName::new(WORKSPACE_NAMESPACE));
        if managed.first().is_some_and(|obj| {
            String::from_utf8_lossy(obj.body.as_bytes()).contains("/bin/anything")
        }) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }

    let outcome = weebo_si_kubearmor_policy::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("second reconcile should succeed");
    assert_eq!(
        outcome.applied.expect("Enforce should apply").updated,
        1,
        "the edit should have been put back: {:?}",
        outcome.diffs
    );

    let object = written(client, "weebo-base").await;
    assert_eq!(
        object.data.pointer("/spec/process/matchPaths/0/path"),
        Some(&json!("/usr/bin/base")),
        "the template's content is what should be in the cluster, not the tamper"
    );
}

#[tokio::test]
async fn a_cluster_without_the_crd_offers_no_engine() {
    // The precondition the controller checks at boot before starting a single watch: on a
    // cluster with no KubeArmor, `resolve_backend` must produce `None` so nothing is written,
    // rather than objects the apiserver rejects one at a time.
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");

    let capabilities = KubeArmorCapabilities::discover(client)
        .await
        .expect("discovery should succeed even with nothing installed");
    assert!(!capabilities.offers(RuntimeBackend::KubeArmor));
    assert_eq!(
        weebo_si_kubearmor_policy::resolve_backend(RuntimeEnforcementBackend::Auto, &capabilities),
        None
    );
}

/// The GVK every object this brick writes and watches carries. A contract check rather than an
/// adapter check: RFC 0006 names `security.kubearmor.com/v1` `KubeArmorPolicy`, and a typo here
/// would fail at runtime as a missing resource rather than at compile time.
#[test]
fn the_managed_resource_is_kubearmors_own_gvk() {
    let resource = kubearmor_policy_resource();
    assert_eq!(resource.group, "security.kubearmor.com");
    assert_eq!(resource.version, "v1");
    assert_eq!(resource.kind, "KubeArmorPolicy");
    assert_eq!(resource.plural, "kubearmorpolicies");
}

// --- The enforcement join ----------------------------------------------------------------------
//
// `KubeNodeEnforcerView` is the data path behind `weebo_si_kubearmor_enforced`, and RFC 0006's
// whole *Bypass* argument rests on it: a policy object existing is not a policy being enforced.
// Its pure halves (the two projections, the label reading) are unit-tested next to them; what
// these cases prove is the join itself — two watches, a real apiserver, and the three states.
//
// envtest runs no kubelet and no scheduler, which is exactly why this works: `spec.nodeName` is a
// plain field the API accepts, and the join reads nothing a kubelet would have had to fill in.

use k8s_openapi::api::core::v1::{Container, Node, Pod, PodSpec};
use weebo_si_crd::{DEVWORKSPACE_ID_LABEL, KUBEARMOR_ENFORCER_LABEL};
use weebo_si_kubearmor_policy::{Enforcement, EnforcementSubjects, NodeEnforcerView};
use weebo_si_runtime::KubeNodeEnforcerView;

async fn create_node(client: kube::Client, name: &str, enforcer: Option<&str>) {
    let api: Api<Node> = Api::all(client);
    let node = Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: enforcer
                .map(|value| [(KUBEARMOR_ENFORCER_LABEL.to_string(), value.to_string())].into()),
            ..Default::default()
        },
        ..Default::default()
    };
    api.create(&PostParams::default(), &node)
        .await
        .unwrap_or_else(|err| panic!("node {name} should be created: {err}"));
}

async fn create_workspace_pod(
    client: kube::Client,
    name: &str,
    workspace_id: &str,
    node_name: Option<&str>,
) {
    let api: Api<Pod> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(WORKSPACE_NAMESPACE.to_string()),
            labels: Some([(DEVWORKSPACE_ID_LABEL.to_string(), workspace_id.to_string())].into()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            node_name: node_name.map(str::to_string),
            containers: vec![Container {
                name: "theia".to_string(),
                image: Some("registry.internal/udi:latest".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    api.create(&PostParams::default(), &pod)
        .await
        .unwrap_or_else(|err| panic!("pod {name} should be created: {err}"));
}

/// All three states of the join, against one apiserver holding all three shapes at once.
#[tokio::test]
async fn the_join_reports_enforced_not_enforced_and_unknown() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;

    create_node(client.clone(), "node-with-lsm", Some("bpf")).await;
    create_node(client.clone(), "node-without-lsm", None).await;
    create_workspace_pod(
        client.clone(),
        "ws-enforced",
        "ws-enforced",
        Some("node-with-lsm"),
    )
    .await;
    create_workspace_pod(
        client.clone(),
        "ws-unenforced",
        "ws-unenforced",
        Some("node-without-lsm"),
    )
    .await;
    create_workspace_pod(client.clone(), "ws-pending", "ws-pending", None).await;

    let view = KubeNodeEnforcerView::spawn(client)
        .await
        .expect("the pod and node watches should start");
    let namespace = NamespaceName::new(WORKSPACE_NAMESPACE);

    assert_eq!(
        view.enforcement(&namespace, "ws-enforced"),
        Enforcement::Enforced("bpf".to_string()),
        "a pod on a node whose enforcer label names an LSM is enforced, and the gauge says which"
    );
    assert_eq!(
        view.enforcement(&namespace, "ws-unenforced"),
        Enforcement::NotEnforced,
        "a pod on a node with no enforcer label is the gap RFC 0006 exists to make visible"
    );
    assert_eq!(
        view.enforcement(&namespace, "ws-pending"),
        Enforcement::Unknown,
        "a scheduled-nowhere pod is not a zero — nothing has been observed about it yet"
    );
    assert_eq!(
        view.enforcement(&namespace, "no-such-workspace"),
        Enforcement::Unknown,
        "and neither is a workspace with no pod at all"
    );
    assert_eq!(
        view.enforcement(&NamespaceName::new("some-other-namespace"), "ws-enforced"),
        Enforcement::Unknown,
        "the join is per namespace: the same workspace id elsewhere is not this one"
    );
}

/// The roster the controller's gauge tick iterates. It must contain every workspace with a pod —
/// including the ones with no node yet, since `unknown` is a state the gauge publishes rather
/// than a workspace it drops.
#[tokio::test]
async fn the_roster_lists_every_workspace_with_a_pod_scheduled_or_not() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;

    create_node(client.clone(), "node-1", Some("apparmor")).await;
    create_workspace_pod(client.clone(), "ws-a", "ws-a", Some("node-1")).await;
    create_workspace_pod(client.clone(), "ws-b", "ws-b", None).await;
    // Two pods, one workspace — a restarted workspace briefly has both. The roster must not
    // double-count it, or the gauge reports more workspaces than exist.
    create_workspace_pod(client.clone(), "ws-a-old", "ws-a", Some("node-1")).await;
    // Not a workspace pod at all: no devworkspace_id label, so the watch never sees it.
    Api::<Pod>::namespaced(client.clone(), WORKSPACE_NAMESPACE)
        .create(
            &PostParams::default(),
            &Pod {
                metadata: ObjectMeta {
                    name: Some("some-other-pod".to_string()),
                    namespace: Some(WORKSPACE_NAMESPACE.to_string()),
                    ..Default::default()
                },
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "c".to_string(),
                        image: Some("busybox".to_string()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("the unrelated pod should be created");

    let view = KubeNodeEnforcerView::spawn(client)
        .await
        .expect("the pod and node watches should start");

    let mut roster: Vec<String> = view
        .workspaces()
        .into_iter()
        .map(|(namespace, id)| format!("{namespace}/{id}"))
        .collect();
    roster.sort();
    assert_eq!(
        roster,
        vec![
            format!("{WORKSPACE_NAMESPACE}/ws-a"),
            format!("{WORKSPACE_NAMESPACE}/ws-b"),
        ],
        "one entry per workspace, and nothing that is not a workspace"
    );
}

/// A node relabelled after the first observation — the reason the gauge tick calls `invalidate()`
/// before every sweep rather than trusting the memo forever.
#[tokio::test]
async fn a_relabelled_node_is_picked_up_after_invalidate() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;

    create_node(client.clone(), "node-reboot", Some("apparmor")).await;
    create_workspace_pod(client.clone(), "ws-r", "ws-r", Some("node-reboot")).await;

    let view = KubeNodeEnforcerView::spawn(client.clone())
        .await
        .expect("the pod and node watches should start");
    let namespace = NamespaceName::new(WORKSPACE_NAMESPACE);
    assert_eq!(
        view.enforcement(&namespace, "ws-r"),
        Enforcement::Enforced("apparmor".to_string()),
        "the first observation is memoised"
    );

    // The node reboots into a kernel with BPF-LSM available and KubeArmor's operator relabels it.
    Api::<Node>::all(client)
        .patch(
            "node-reboot",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"labels": {KUBEARMOR_ENFORCER_LABEL: "bpf"}}})),
        )
        .await
        .expect("the relabel should apply");

    // Deliberately no assertion that the pre-invalidate read is stale: it would race the watch,
    // and both outcomes would read the same. What matters is that after the tick's own
    // `invalidate()`, the new label is what the gauge reports.
    view.invalidate();
    for _ in 0..40 {
        if view.enforcement(&namespace, "ws-r") == Enforcement::Enforced("bpf".to_string()) {
            return;
        }
        view.invalidate();
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!(
        "the relabelled node was never picked up: {:?}",
        view.enforcement(&namespace, "ws-r")
    );
}
