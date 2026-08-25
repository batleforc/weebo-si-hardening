//! Proves RFC 0004's kube adapters (`KubeTemplateStore`, `KubePolicyStore`, `KubeCapabilities`)
//! and `policy-guard`'s decision logic against a real, ephemeral apiserver — the layer 47 pure
//! unit tests in `weebo-si-network-profiles` cannot reach, since none of them touch `kube`.
//!
//! Each test builds `weebo_si_network_profiles::reconcile`'s inputs directly (a hand-built
//! config, a `FakeDwocCatalog`/default `NamespaceFacts` — this suite is about the adapters, not
//! the resolution chain, which already has its own exhaustive coverage) rather than going through
//! the full watch-driven controller loop, so each assertion is deterministic and fast.

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
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicySpec};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, Decision, Registry};
use weebo_si_crd::{
    Backend, Enforcement, FeatureMode, NamespaceName, NetworkProfilesConfig, OnNotGranted, Profile,
    ProfileCatalog, ProfileGrant, ProfileKey, ProfileNamespaceSelection, Selector, Team, TeamName,
    TemplateRef, Variant, WorkspaceSelection,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_network_profiles::{NamespaceSubject, NetworkProfiles, Workspace};
use weebo_si_policy_guard::{GuardedResource, GuardedWrite, PolicyGuard, WriteOperation};
use weebo_si_runtime::{KubeCapabilities, KubePolicyStore, KubeTemplateStore};

const TEMPLATES_NAMESPACE: &str = "weebo-si-hardening";
const WORKSPACE_NAMESPACE: &str = "user-alice";

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

async fn create_template(client: kube::Client, name: &str) {
    let api: Api<NetworkPolicy> = Api::namespaced(client, TEMPLATES_NAMESPACE);
    let np = NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(TEMPLATES_NAMESPACE.to_string()),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            // Content is arbitrary for this suite — the domain copies it verbatim and never
            // inspects it, so what matters is that it round-trips, not what it means.
            pod_selector: Some(Default::default()),
            policy_types: Some(vec!["Egress".to_string()]),
            egress: Some(vec![NetworkPolicyEgressRule::default()]),
            ..Default::default()
        }),
    };
    api.create(&PostParams::default(), &np)
        .await
        .expect("template should be created");
}

fn config(
    mode: FeatureMode,
    baseline: &str,
    catalog_keys: &[&str],
    grants: BTreeMap<String, ProfileGrant>,
) -> NetworkProfilesConfig {
    let catalog = ProfileCatalog::new(
        catalog_keys
            .iter()
            .map(|key| Profile {
                key: ProfileKey::new(*key),
                variants: vec![Variant {
                    backend: Backend::NetworkPolicy,
                    template_ref: TemplateRef {
                        name: format!("weebo-{key}"),
                        namespace: NamespaceName::new(TEMPLATES_NAMESPACE),
                    },
                }],
            })
            .collect(),
    );
    NetworkProfilesConfig {
        mode,
        namespace_selector: None,
        catalog,
        baseline: ProfileKey::new(baseline),
        grants,
        namespace_selection: ProfileNamespaceSelection::default(),
        workspace_selection: WorkspaceSelection::default(),
        on_not_granted: OnNotGranted::default(),
        enforcement: Enforcement::default(),
    }
}

async fn feature_with(
    client: kube::Client,
    cfg: NetworkProfilesConfig,
) -> (NetworkProfiles, KubePolicyStore) {
    let capabilities = KubeCapabilities::discover(client.clone())
        .await
        .expect("discovery should succeed");
    let backend =
        weebo_si_network_profiles::resolve_backend(cfg.enforcement.backend, &capabilities)
            .expect("NetworkPolicy should always resolve");
    let templates = Arc::new(
        KubeTemplateStore::spawn(client.clone(), TEMPLATES_NAMESPACE, false)
            .await
            .expect("template store should start"),
    );
    let policy_store = KubePolicyStore::spawn(client, false)
        .await
        .expect("policy store should start");
    let feature = NetworkProfiles::new(
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

#[tokio::test]
async fn the_baseline_is_written_for_real_in_enforce_mode() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    create_template(client.clone(), "weebo-base").await;

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

    let outcome = weebo_si_network_profiles::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");
    assert_eq!(outcome.applied.expect("Enforce should apply").created, 1);

    let api: Api<NetworkPolicy> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let written = api
        .get("weebo-base")
        .await
        .expect("the baseline object should actually exist in the workspace namespace");
    let labels = written
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
        written.spec.as_ref().unwrap().policy_types,
        Some(vec!["Egress".to_string()]),
        "the template's rule content should have round-tripped verbatim"
    );
    assert_eq!(
        written.spec.as_ref().unwrap().pod_selector,
        Some(Default::default()),
        "the baseline's own podSelector must be {{}} — every pod — regardless of the template's"
    );
}

#[tokio::test]
async fn dry_run_writes_nothing_to_the_real_apiserver() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    create_template(client.clone(), "weebo-base").await;

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

    let outcome = weebo_si_network_profiles::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::DryRun,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");
    assert_eq!(outcome.applied, None);

    let api: Api<NetworkPolicy> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    assert!(
        api.get_opt("weebo-base")
            .await
            .expect("a missing object is Ok(None), not an error")
            .is_none(),
        "DryRun must never write to the real apiserver"
    );
}

#[tokio::test]
async fn a_workspace_with_two_granted_profiles_gets_two_real_objects() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    for name in ["weebo-base", "weebo-git", "weebo-vault"] {
        create_template(client.clone(), name).await;
    }

    let mut grants = BTreeMap::new();
    grants.insert(
        "team-1".to_string(),
        ProfileGrant {
            allowed: vec![ProfileKey::new("git"), ProfileKey::new("vault")],
            default: vec![ProfileKey::new("git")],
        },
    );
    let (feature, policy_store) = feature_with(
        client.clone(),
        config(
            FeatureMode::Enforce,
            "base",
            &["base", "git", "vault"],
            grants,
        ),
    )
    .await;

    let team = Team {
        name: TeamName::new("team-1"),
        namespace_selector: Selector {
            match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
            match_expressions: Vec::new(),
        },
    };
    let mut namespace_facts = NamespaceFacts::default();
    namespace_facts
        .labels
        .insert("weebo.io/team".to_string(), "team-1".to_string());
    let dwoc_catalog = FakeDwocCatalog::new(std::iter::empty());
    let teams = [team];
    let ctx = Context::new(&teams, &namespace_facts, &dwoc_catalog);
    let subject = Workspace {
        name: "data-pipeline".to_string(),
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
        workspace_id: "workspacede4f56".to_string(),
        attribute: Some("git,vault".to_string()),
        namespace_annotation: None,
    };

    let outcome = weebo_si_network_profiles::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("reconcile should succeed");
    assert_eq!(outcome.applied.expect("Enforce should apply").created, 2);

    let api: Api<NetworkPolicy> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let git = api
        .get("weebo-git-workspacede4f56")
        .await
        .expect("the git profile object should exist");
    assert_eq!(
        git.spec
            .as_ref()
            .unwrap()
            .pod_selector
            .as_ref()
            .unwrap()
            .match_labels
            .as_ref()
            .unwrap()
            .get("controller.devfile.io/devworkspace_id"),
        Some(&"workspacede4f56".to_string())
    );
    api.get("weebo-vault-workspacede4f56")
        .await
        .expect("the vault profile object should exist");
}

#[tokio::test]
async fn policy_guard_denies_a_non_operator_delete_of_a_real_managed_object() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    create_template(client.clone(), "weebo-base").await;

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
    weebo_si_network_profiles::reconcile(
        &feature,
        &subject,
        &ctx,
        FeatureMode::Enforce,
        &policy_store,
    )
    .await
    .expect("the baseline should be written first");

    // The object is real; `PolicyGuard`'s own decision logic is what this test actually
    // exercises — `target_is_managed: true` is what a real admission adapter would compute by
    // reading the label off the object this reconcile pass just wrote, per
    // `weebo-si-webhook::policy_guard`'s `guarded_write_from_request`.
    let guard = PolicyGuard::new(
        "system:serviceaccount:weebo-si-hardening:weebo-si-operator-controller".to_string(),
        Vec::new(),
    );
    let mut registry: Registry<GuardedWrite> = Registry::new();
    registry.register(guard);
    let write = GuardedWrite {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
        actor: "system:serviceaccount:user-alice:default".to_string(),
        operation: WriteOperation::Delete,
        target_is_managed: true,
        resource: GuardedResource::NetworkPolicy,
    };

    let decision: Decision<GuardedWrite> = registry
        .iter()
        .next()
        .expect("one feature registered")
        .evaluate(&write, &ctx)
        .expect("evaluate should not error");
    assert!(
        decision.denial.is_some(),
        "a non-operator DELETE of a managed object must be denied"
    );

    // And the object is still there — this test denied the decision, it did not perform the
    // delete (policy-guard is an admission check; nothing here calls the apiserver's delete).
    let api: Api<NetworkPolicy> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    api.get("weebo-base")
        .await
        .expect("the object the guard protected should still exist");
}

// ---------------------------------------------------------------------------------------------
// The enforcement canary, against a real apiserver.
//
// envtest has no kubelet, so the probe's pods never actually run — but the probe never talks to a
// kubelet. It reads **pod status**, which a test can write itself through the `/status`
// subresource. So the whole sequence is reachable here: create the server, wait for an IP, put
// the deny policy in place, create the client, read its terminal phase, clean up.
//
// `fake_kubelet` below is the trick, and it is a more faithful simulation than it first looks:
// it decides the client pod's exit status by *reading whether the deny policy exists*. Set
// `cni_enforces: true` and it behaves like a cluster whose CNI evaluates NetworkPolicy; set it
// false and it behaves like one that ignores it. Those are exactly the two clusters this probe
// exists to tell apart, so `run_canary` returning `Enforcing` against the first and
// `NotEnforcing` against the second is the real contract under test.
//
// **What this still cannot prove**: that a real CNI drops a real packet. Nothing short of a
// policy-enforcing cluster can, which is why the RFC keeps that in *Known limitations*.
// ---------------------------------------------------------------------------------------------

use k8s_openapi::api::core::v1::Pod;
use weebo_si_network_profiles::{CanaryProbe, CanaryVerdict, Reachability};
use weebo_si_runtime::{CLIENT_POD, DENY_POLICY, KubeCanary, SERVER_POD};

const CANARY_NAMESPACE: &str = "weebo-si-hardening";
const FAKE_POD_IP: &str = "10.42.0.7";

/// Stands in for the kubelet + CNI this apiserver does not have.
///
/// Gives the server pod an IP once it appears, and settles the client pod into a terminal phase —
/// `Succeeded` when it would have reached the server, `Failed` when the deny policy is in place
/// *and* this cluster is one that enforces policy. Runs until dropped.
fn spawn_fake_kubelet(client: kube::Client, cni_enforces: bool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let pods: Api<Pod> = Api::namespaced(client.clone(), CANARY_NAMESPACE);
        let policies: Api<NetworkPolicy> = Api::namespaced(client, CANARY_NAMESPACE);
        let params = PatchParams::default();
        loop {
            if let Ok(Some(pod)) = pods.get_opt(SERVER_POD).await
                && pod
                    .status
                    .as_ref()
                    .and_then(|s| s.pod_ip.as_ref())
                    .is_none()
            {
                let _ = pods
                    .patch_status(
                        SERVER_POD,
                        &params,
                        &Patch::Merge(
                            serde_json::json!({"status": {"phase": "Running", "podIP": FAKE_POD_IP}}),
                        ),
                    )
                    .await;
            }

            if let Ok(Some(pod)) = pods.get_opt(CLIENT_POD).await {
                let phase = pod.status.as_ref().and_then(|s| s.phase.clone());
                if !matches!(phase.as_deref(), Some("Succeeded") | Some("Failed")) {
                    let denied = matches!(policies.get_opt(DENY_POLICY).await, Ok(Some(_)));
                    // The whole simulation, in one line: a cluster that enforces policy is one
                    // where the deny object changes the outcome, and a cluster that does not is
                    // one where it does not.
                    let outcome = if denied && cni_enforces {
                        "Failed"
                    } else {
                        "Succeeded"
                    };
                    let _ = pods
                        .patch_status(
                            CLIENT_POD,
                            &params,
                            &Patch::Merge(serde_json::json!({"status": {"phase": outcome}})),
                        )
                        .await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
}

async fn canary_fixture(
    cni_enforces: bool,
) -> Option<(
    EnvTest,
    kube::Client,
    KubeCanary,
    tokio::task::JoinHandle<()>,
)> {
    let env_test = EnvTest::try_start().await?;
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), CANARY_NAMESPACE).await;
    let canary = KubeCanary::new(
        client.clone(),
        CANARY_NAMESPACE,
        "registry.invalid/probe:test",
    );
    let kubelet = spawn_fake_kubelet(client.clone(), cni_enforces);
    Some((env_test, client, canary, kubelet))
}

/// The headline: against a cluster whose CNI evaluates NetworkPolicy, the probe says so.
#[tokio::test]
async fn the_canary_reports_enforcing_against_a_cluster_that_enforces() {
    let Some((_env_test, client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };

    let verdict = weebo_si_network_profiles::run_canary(&canary)
        .await
        .expect("the probe should run");
    assert_eq!(verdict, CanaryVerdict::Enforcing);

    // Both legs really happened against the apiserver: the server pod was created for real.
    let pods: Api<Pod> = Api::namespaced(client, CANARY_NAMESPACE);
    pods.get(SERVER_POD)
        .await
        .expect("the server pod should still be there until cleanup runs");
    kubelet.abort();
}

/// The failure this whole feature exists to make visible: every object correct, nothing enforced.
#[tokio::test]
async fn the_canary_reports_not_enforcing_when_the_deny_policy_changes_nothing() {
    let Some((_env_test, _client, canary, kubelet)) = canary_fixture(false).await else {
        return;
    };

    let verdict = weebo_si_network_profiles::run_canary(&canary)
        .await
        .expect("the probe should run");
    assert_eq!(
        verdict,
        CanaryVerdict::NotEnforcing,
        "a cluster where the deny object changes nothing must be reported, not silently passed"
    );
    kubelet.abort();
}

/// The unrestricted leg, on its own: no deny policy in place, and the client reaches the server.
#[tokio::test]
async fn the_unrestricted_leg_finds_the_server_reachable_and_writes_no_policy() {
    let Some((_env_test, client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };

    let observed = canary
        .reachability(false)
        .await
        .expect("the unrestricted leg should run");
    assert_eq!(observed, Reachability::Reached);

    let policies: Api<NetworkPolicy> = Api::namespaced(client, CANARY_NAMESPACE);
    assert!(
        policies
            .get_opt(DENY_POLICY)
            .await
            .expect("a missing object is Ok(None)")
            .is_none(),
        "the unrestricted leg must leave no deny policy behind — the next leg's whole meaning \
         depends on it not being there"
    );
    kubelet.abort();
}

/// The restricted leg writes the deny policy for real, and the apiserver accepts the shape.
#[tokio::test]
async fn the_restricted_leg_writes_a_real_deny_policy_selecting_only_the_server() {
    let Some((_env_test, client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };

    let observed = canary
        .reachability(true)
        .await
        .expect("the restricted leg should run");
    assert_eq!(observed, Reachability::Blocked);

    let policies: Api<NetworkPolicy> = Api::namespaced(client, CANARY_NAMESPACE);
    let policy = policies
        .get(DENY_POLICY)
        .await
        .expect("the deny policy should really exist in the apiserver");
    let spec = policy.spec.as_ref().expect("spec");
    assert_eq!(spec.policy_types, Some(vec!["Ingress".to_string()]));
    assert!(
        spec.ingress.as_ref().is_none_or(|rules| rules.is_empty()),
        "nothing may be permitted in"
    );
    assert_eq!(
        spec.pod_selector
            .as_ref()
            .and_then(|selector| selector.match_labels.as_ref())
            .and_then(|labels| labels.get("hardening.weebo.io/canary")),
        Some(&"server".to_string()),
    );
    kubelet.abort();
}

/// A listener that exited is not the same as a blocked flow. This is the case that, read wrong,
/// reports `Enforcing` for a cluster that enforces nothing.
#[tokio::test]
async fn a_server_pod_that_terminated_is_inconclusive_never_blocked() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    let client = env_test.client().expect("client should build");
    create_namespace(client.clone(), CANARY_NAMESPACE).await;
    let canary = KubeCanary::new(
        client.clone(),
        CANARY_NAMESPACE,
        "registry.invalid/probe:test",
    );

    // A "kubelet" that only ever reports the listener as having exited — no IP, ever.
    let pods: Api<Pod> = Api::namespaced(client.clone(), CANARY_NAMESPACE);
    let kubelet = tokio::spawn(async move {
        loop {
            if let Ok(Some(_)) = pods.get_opt(SERVER_POD).await {
                let _ = pods
                    .patch_status(
                        SERVER_POD,
                        &PatchParams::default(),
                        &Patch::Merge(serde_json::json!({"status": {"phase": "Failed"}})),
                    )
                    .await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    let observed = canary
        .reachability(false)
        .await
        .expect("the leg should run rather than error");
    assert_eq!(
        observed,
        Reachability::Inconclusive,
        "a listener that exited must never be read as a blocked flow"
    );

    let verdict = weebo_si_network_profiles::run_canary(&canary)
        .await
        .expect("the probe should run");
    assert_eq!(verdict, CanaryVerdict::Unknown);
    kubelet.abort();
}

/// The probe is the only thing in this brick that creates a workload, so it has to take it away.
#[tokio::test]
async fn cleanup_removes_every_object_the_probe_created() {
    let Some((_env_test, client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };

    weebo_si_network_profiles::run_canary(&canary)
        .await
        .expect("the probe should run");
    canary.cleanup().await.expect("cleanup should succeed");

    let pods: Api<Pod> = Api::namespaced(client.clone(), CANARY_NAMESPACE);
    let policies: Api<NetworkPolicy> = Api::namespaced(client, CANARY_NAMESPACE);
    for name in [SERVER_POD, CLIENT_POD] {
        assert!(
            pods.get_opt(name)
                .await
                .expect("a missing object is Ok(None)")
                .is_none(),
            "{name} should have been deleted"
        );
    }
    assert!(
        policies
            .get_opt(DENY_POLICY)
            .await
            .expect("a missing object is Ok(None)")
            .is_none(),
        "a stale deny policy is a namespace left in a state nobody remembers asking for"
    );
    kubelet.abort();
}

/// Cleanup is idempotent — the controller calls it after every run, including runs that errored
/// before creating anything.
#[tokio::test]
async fn cleanup_is_a_no_op_when_the_probe_never_ran() {
    let Some((_env_test, _client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };
    canary
        .cleanup()
        .await
        .expect("deleting objects that were never created must not be an error");
    kubelet.abort();
}

/// An interrupted run leaves the server pod behind; the next run reuses it rather than failing on
/// the 409, which is what keeps the probe self-healing across a controller restart.
#[tokio::test]
async fn a_leftover_server_pod_from_an_interrupted_run_is_reused() {
    let Some((_env_test, _client, canary, kubelet)) = canary_fixture(true).await else {
        return;
    };

    canary
        .reachability(false)
        .await
        .expect("first leg should run");
    // Deliberately no cleanup — this is the interrupted-run state.
    let observed = canary
        .reachability(false)
        .await
        .expect("a second run must not fail on the already-existing server pod");
    assert_eq!(observed, Reachability::Reached);
    kubelet.abort();
}
