//! Proves RFC 0007's kube adapters (`KubeRegistryTemplateStore`, `KubeRegistryObjectStore`) and
//! the registry guard's decision logic against a real, ephemeral apiserver — the layer the pure
//! unit tests in `weebo-si-registry-config` cannot reach, since none of them touch `kube`.
//!
//! Each test builds `weebo_si_registry_config::reconcile`'s inputs directly rather than going
//! through the watch-driven controller loop, so each assertion is deterministic and fast — the
//! same shape as this crate's other two suites.
//!
//! **Its own target rather than more cases in [`super::envtest`]**, for the reason RFC 0006's
//! suite is its own: that one assumes a bare cluster with no `ConfigMap`/`Secret` traffic, and
//! this one is specifically about a store that watches every `ConfigMap` and `Secret` in it.
//!
//! **What this suite proves and what it cannot.** It proves what the adapter writes, that a
//! written copy reads back as the same `ManagedObject` it was built from (the property the whole
//! diff rests on), that a `Secret`'s payload survives the round trip byte for byte, that `DryRun`
//! writes nothing, and that drift is corrected. It cannot prove DevWorkspace Operator actually
//! mounts any of it — there is no DWO here — so no green run should be read as proof that a
//! developer's `~/.npmrc` appears. What the automount labels *mean* is upstream's contract, and
//! `weebo-si-registry-config`'s `model/mount` is where this project pins it.

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

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret};
use kube::api::{Api, ObjectMeta, PostParams};
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::dwoc_catalog::testing::FakeDwocCatalog;
use weebo_si_chassis::{Context, Decision, Feature, Registry};
use weebo_si_crd::{
    Ecosystem, FeatureMode, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, OnNotGranted,
    RegistryCatalog, RegistryConfig, RegistryEntry, RegistryGrant, RegistryKey,
    RegistryNamespaceSelection, RegistrySource, Selector, SourceKind, Team, TeamName, TemplateRef,
};
use weebo_si_envtest_support::EnvTest;
use weebo_si_registry_config::{
    MOUNT_AS_ANNOTATION, MOUNT_PATH_ANNOTATION, MOUNT_TO_DEVWORKSPACE_LABEL, NamespaceSubject,
    ObjectStore, RegistryConfigFeature, RegistryGuard, RegistryObjectWrite, WriteOperation,
};
use weebo_si_runtime::{KubeRegistryObjectStore, KubeRegistryTemplateStore};

const TEMPLATES_NAMESPACE: &str = "weebo-si-hardening";
const WORKSPACE_NAMESPACE: &str = "user-alice";
const NPMRC: &str = "registry=https://batlehub.internal/npm/\nalways-auth=true\n";
const TOKEN: &[u8] = b"//batlehub.internal/npm/:_authToken=not-a-real-token";

/// Start an apiserver or skip — envtest binaries are an opt-in tier, per `task envtest:setup`.
macro_rules! envtest_or_skip {
    () => {
        match EnvTest::try_start().await {
            Some(env_test) => env_test,
            None => return,
        }
    };
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

fn automount_metadata(name: &str, mount_as: &str, mount_path: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.to_string()),
        namespace: Some(TEMPLATES_NAMESPACE.to_string()),
        labels: Some(BTreeMap::from([(
            MOUNT_TO_DEVWORKSPACE_LABEL.to_string(),
            "true".to_string(),
        )])),
        annotations: Some(BTreeMap::from([
            (MOUNT_AS_ANNOTATION.to_string(), mount_as.to_string()),
            (MOUNT_PATH_ANNOTATION.to_string(), mount_path.to_string()),
        ])),
        ..Default::default()
    }
}

/// The RFC's own `weebo-npmrc` example, applied for real.
async fn create_config_map_template(client: kube::Client, name: &str, mount_as: &str) {
    let api: Api<ConfigMap> = Api::namespaced(client, TEMPLATES_NAMESPACE);
    let object = ConfigMap {
        metadata: automount_metadata(name, mount_as, "/home/user"),
        data: Some(BTreeMap::from([(".npmrc".to_string(), NPMRC.to_string())])),
        ..ConfigMap::default()
    };
    let _ = api.create(&PostParams::default(), &object).await;
}

async fn create_secret_template(client: kube::Client, name: &str) {
    let api: Api<Secret> = Api::namespaced(client, TEMPLATES_NAMESPACE);
    let object = Secret {
        metadata: automount_metadata(name, "subpath", "/home/user"),
        // Authored as `stringData`, the way a human writes one — the apiserver merges it into
        // `data` and never serves it back, which is exactly the asymmetry the adapter's
        // projection is written around.
        string_data: Some(BTreeMap::from([(
            ".npmrc-token".to_string(),
            String::from_utf8_lossy(TOKEN).to_string(),
        )])),
        type_: Some("Opaque".to_string()),
        ..Secret::default()
    };
    let _ = api.create(&PostParams::default(), &object).await;
}

fn entry(key: &str, ecosystem: Ecosystem, sources: Vec<(SourceKind, &str)>) -> RegistryEntry {
    RegistryEntry {
        key: RegistryKey::new(key),
        ecosystem,
        sources: sources
            .into_iter()
            .map(|(kind, name)| RegistrySource {
                kind,
                template_ref: TemplateRef {
                    name: name.to_string(),
                    namespace: NamespaceName::new(TEMPLATES_NAMESPACE),
                },
            })
            .collect(),
    }
}

fn config(catalog: RegistryCatalog, allowed: Vec<&str>) -> RegistryConfig {
    let mut grants = BTreeMap::new();
    grants.insert(
        "team-1".to_string(),
        RegistryGrant {
            allowed: allowed.iter().map(|key| RegistryKey::new(*key)).collect(),
            default: allowed.iter().map(|key| RegistryKey::new(*key)).collect(),
        },
    );
    RegistryConfig {
        mode: FeatureMode::DryRun,
        namespace_selector: None,
        catalog,
        grants,
        namespace_selection: RegistryNamespaceSelection::default(),
        on_not_granted: OnNotGranted::default(),
    }
}

fn teams() -> Vec<Team> {
    vec![Team {
        name: TeamName::new("team-1"),
        namespace_selector: Selector {
            match_labels: [("weebo.io/team".to_string(), "team-1".to_string())].into(),
            match_expressions: Vec::new(),
        },
    }]
}

fn namespace_facts() -> NamespaceFacts {
    NamespaceFacts {
        labels: BTreeMap::from([("weebo.io/team".to_string(), "team-1".to_string())]),
        selection_annotation: None,
    }
}

fn subject() -> NamespaceSubject {
    NamespaceSubject {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
        annotation: None,
    }
}

/// A cluster with both namespaces, both templates, and the two adapters started.
async fn fixture(
    config: RegistryConfig,
) -> Option<(
    EnvTest,
    kube::Client,
    RegistryConfigFeature,
    Arc<KubeRegistryObjectStore>,
)> {
    let env_test = match EnvTest::try_start().await {
        Some(env_test) => env_test,
        None => return None,
    };
    let client = env_test.client().expect("a client");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    create_config_map_template(client.clone(), "weebo-npmrc", "subpath").await;
    create_secret_template(client.clone(), "weebo-npm-token").await;

    let templates = Arc::new(
        KubeRegistryTemplateStore::spawn(client.clone(), TEMPLATES_NAMESPACE)
            .await
            .expect("the template watch should start"),
    );
    let store = Arc::new(
        KubeRegistryObjectStore::spawn(client.clone())
            .await
            .expect("the managed-object watch should start"),
    );
    let feature = RegistryConfigFeature::new(Arc::new(RwLock::new(Some(config))), templates);
    Some((env_test, client, feature, store))
}

fn npm_catalog() -> RegistryCatalog {
    RegistryCatalog::new(vec![entry(
        "internal-npm",
        Ecosystem::Npm,
        vec![
            (SourceKind::ConfigMap, "weebo-npmrc"),
            (SourceKind::Secret, "weebo-npm-token"),
        ],
    )])
}

/// The whole point of the brick, end to end against a real apiserver: a granted namespace gets a
/// `ConfigMap` and a `Secret` carrying the template's payload and its automount metadata.
#[tokio::test]
async fn a_granted_namespace_converges_to_a_configmap_and_a_secret() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);

    let outcome = weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the pass should complete");
    assert!(outcome.ready, "refused: {:?}", outcome.refused);

    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), WORKSPACE_NAMESPACE);
    let copy = config_maps
        .get("weebo-si-internal-npm-weebo-npmrc")
        .await
        .expect("the ConfigMap copy should exist");
    assert_eq!(
        copy.data.as_ref().and_then(|data| data.get(".npmrc")),
        Some(&NPMRC.to_string()),
        "the payload travels verbatim"
    );
    let labels = copy.metadata.labels.expect("labels");
    assert_eq!(
        labels.get(MOUNT_TO_DEVWORKSPACE_LABEL),
        Some(&"true".to_string()),
        "without the automount label the copy reaches no container"
    );
    assert_eq!(
        labels.get(MANAGED_BY_LABEL),
        Some(&MANAGED_BY_VALUE.to_string())
    );
    assert_eq!(
        copy.metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(MOUNT_AS_ANNOTATION)),
        Some(&"subpath".to_string()),
        "the mount semantics stay the admin's decision"
    );

    let secrets: Api<Secret> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let secret = secrets
        .get("weebo-si-internal-npm-weebo-npm-token")
        .await
        .expect("the Secret copy should exist");
    assert_eq!(
        secret
            .data
            .as_ref()
            .and_then(|data| data.get(".npmrc-token")),
        Some(&ByteString(TOKEN.to_vec())),
        "a Secret authored as stringData round-trips through data, byte for byte"
    );
    assert_eq!(secret.type_.as_deref(), Some("Opaque"));
}

/// The property the whole diff rests on: an object this adapter wrote, read back from the watch
/// cache, must produce the same `ManagedObject` it was built from. Without it every reconcile
/// pass would see a change and rewrite every copy in the fleet.
#[tokio::test]
async fn a_second_enforce_pass_reports_unchanged() {
    let Some((_env_test, _client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);

    weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the first pass should complete");

    // The watch cache has to catch up with what the first pass wrote before the second can see
    // it; a reflector is eventually consistent by construction.
    let mut unchanged = None;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let outcome = weebo_si_registry_config::reconcile(
            &feature,
            &subject(),
            &context,
            FeatureMode::Enforce,
            store.as_ref(),
        )
        .await
        .expect("the second pass should complete");
        if outcome.applied.map(|applied| applied.unchanged) == Some(2) {
            unchanged = Some(outcome);
            break;
        }
    }
    assert!(
        unchanged.is_some(),
        "a steady state must not rewrite both copies on every pass — the read-back projection \
         and the written one have to agree"
    );
}

/// Drift is corrected: a developer editing their own copy has it put back.
#[tokio::test]
async fn an_edited_copy_is_restored_on_the_next_pass() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);

    weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the first pass should complete");

    // Someone points their `.npmrc` at the public registry. This is a plain `replace`, not a
    // server-side apply, so it makes the editor a field manager of `data` — which is precisely
    // the 409 the store's `.force()` exists to survive.
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), WORKSPACE_NAMESPACE);
    let mut edited = config_maps
        .get("weebo-si-internal-npm-weebo-npmrc")
        .await
        .expect("the copy should exist");
    edited.data = Some(BTreeMap::from([(
        ".npmrc".to_string(),
        "registry=https://registry.npmjs.org/\n".to_string(),
    )]));
    config_maps
        .replace(
            "weebo-si-internal-npm-weebo-npmrc",
            &PostParams::default(),
            &edited,
        )
        .await
        .expect("the edit should land");

    let mut restored = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        weebo_si_registry_config::reconcile(
            &feature,
            &subject(),
            &context,
            FeatureMode::Enforce,
            store.as_ref(),
        )
        .await
        .expect("the pass should complete even against a foreign field manager");
        let current = config_maps
            .get("weebo-si-internal-npm-weebo-npmrc")
            .await
            .expect("the copy should still exist");
        if current.data.as_ref().and_then(|data| data.get(".npmrc")) == Some(&NPMRC.to_string()) {
            restored = true;
            break;
        }
    }
    assert!(
        restored,
        "the drift this brick exists to correct must not become the drift it cannot correct"
    );
}

/// `DryRun` computes the diff and writes nothing — the chassis' promise, against a real
/// apiserver rather than an in-memory fake.
#[tokio::test]
async fn dry_run_writes_nothing() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);

    let outcome = weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::DryRun,
        store.as_ref(),
    )
    .await
    .expect("the pass should complete");
    assert_eq!(outcome.diffs.len(), 2);
    assert_eq!(outcome.applied, None);

    let config_maps: Api<ConfigMap> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    assert!(
        config_maps
            .get_opt("weebo-si-internal-npm-weebo-npmrc")
            .await
            .expect("a missing object is Ok(None)")
            .is_none()
    );
}

/// An ungranted key is dropped, and the namespace is left with nothing rather than with someone
/// else's mirror.
#[tokio::test]
async fn an_ungranted_key_writes_nothing() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), Vec::new())).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let catalog = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &catalog);

    let outcome = weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the pass should complete");
    assert!(outcome.diffs.is_empty());

    let config_maps: Api<ConfigMap> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    assert!(
        config_maps
            .get_opt("weebo-si-internal-npm-weebo-npmrc")
            .await
            .expect("a missing object is Ok(None)")
            .is_none()
    );
}

/// A template that would replace a home directory is refused before it is ever copied — the one
/// piece of content this brick inspects, against a real object.
#[tokio::test]
async fn a_shadowing_template_is_refused_and_never_copied() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("a client");
    create_namespace(client.clone(), TEMPLATES_NAMESPACE).await;
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    // `mount-as: file` at `/home/user` — the failure that presents as a broken image.
    create_config_map_template(client.clone(), "weebo-npmrc", "file").await;

    let templates = Arc::new(
        KubeRegistryTemplateStore::spawn(client.clone(), TEMPLATES_NAMESPACE)
            .await
            .expect("the template watch should start"),
    );
    let store = KubeRegistryObjectStore::spawn(client.clone())
        .await
        .expect("the managed-object watch should start");
    let catalog = RegistryCatalog::new(vec![entry(
        "internal-npm",
        Ecosystem::Npm,
        vec![(SourceKind::ConfigMap, "weebo-npmrc")],
    )]);
    let feature = RegistryConfigFeature::new(
        Arc::new(RwLock::new(Some(config(catalog, vec!["internal-npm"])))),
        templates,
    );

    let teams = teams();
    let facts = namespace_facts();
    let dwoc = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &dwoc);
    let outcome = weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        &store,
    )
    .await
    .expect("the pass should complete");

    assert!(outcome.diffs.is_empty(), "nothing is written");
    assert_eq!(outcome.refused.len(), 1);
    assert_eq!(outcome.refused[0].reason(), "mount_shadows_path");
    assert!(!outcome.ready, "and the gauge says so");
}

/// Turning the feature `Off` takes away what it managed, and leaves alone what it never wrote.
#[tokio::test]
async fn a_key_that_stops_being_granted_has_its_copies_deleted() {
    let Some((_env_test, client, _feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let dwoc = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &dwoc);

    // A `ConfigMap` in the workspace namespace that is none of this operator's business. The
    // label filter is the only thing standing between it and a `Delete` line.
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), WORKSPACE_NAMESPACE);
    let bystander = ConfigMap {
        metadata: ObjectMeta {
            name: Some("someone-elses-configmap".to_string()),
            namespace: Some(WORKSPACE_NAMESPACE.to_string()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([("key".to_string(), "value".to_string())])),
        ..ConfigMap::default()
    };
    config_maps
        .create(&PostParams::default(), &bystander)
        .await
        .expect("the bystander should be created");

    let templates = Arc::new(
        KubeRegistryTemplateStore::spawn(client.clone(), TEMPLATES_NAMESPACE)
            .await
            .expect("the template watch should start"),
    );
    let handle = Arc::new(RwLock::new(Some(config(
        npm_catalog(),
        vec!["internal-npm"],
    ))));
    let feature = RegistryConfigFeature::new(Arc::clone(&handle), templates);

    weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the first pass should complete");

    {
        let mut guard = handle
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cfg) = guard.as_mut() {
            cfg.grants.clear();
        }
    }

    let mut deleted = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        weebo_si_registry_config::reconcile(
            &feature,
            &subject(),
            &context,
            FeatureMode::Enforce,
            store.as_ref(),
        )
        .await
        .expect("the pass should complete");
        if config_maps
            .get_opt("weebo-si-internal-npm-weebo-npmrc")
            .await
            .expect("a missing object is Ok(None)")
            .is_none()
        {
            deleted = true;
            break;
        }
    }
    assert!(deleted, "an ungranted key's copies must be taken away");
    assert!(
        config_maps
            .get_opt("someone-elses-configmap")
            .await
            .expect("a missing object is Ok(None)")
            .is_some(),
        "a workspace namespace is full of ConfigMaps that are none of this operator's business"
    );
}

/// The store only ever reports objects carrying the ownership label. Asserted directly, because
/// this is the invariant that keeps `managed_in` from producing a `Delete` for every `ConfigMap`
/// in a workspace namespace.
#[tokio::test]
async fn the_store_reports_only_labelled_objects() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let config_maps: Api<ConfigMap> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    for name in ["kube-root-ca.crt-lookalike", "user-scratch"] {
        let object = ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(WORKSPACE_NAMESPACE.to_string()),
                ..Default::default()
            },
            ..ConfigMap::default()
        };
        let _ = config_maps.create(&PostParams::default(), &object).await;
    }

    let teams = teams();
    let facts = namespace_facts();
    let dwoc = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &dwoc);
    weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the pass should complete");

    let mut saw_two = false;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let managed = store.managed_in(&NamespaceName::new(WORKSPACE_NAMESPACE));
        if managed.len() == 2 {
            saw_two = true;
            assert!(
                managed
                    .iter()
                    .all(|object| object.key.name.starts_with("weebo-si-")),
                "{managed:?}"
            );
            break;
        }
    }
    assert!(saw_two, "the store should see exactly its own two copies");
}

// The guard's verdict table is exercised exhaustively in `weebo-si-registry-config`. What is
// worth proving here is that a real `ConfigMap`'s label — read the way an admission adapter
// reads it — reaches the same answer.

fn guard() -> RegistryGuard {
    RegistryGuard::new(
        "system:serviceaccount:weebo-si-hardening:weebo-si-operator".to_string(),
        Vec::new(),
    )
}

fn decide(write: &RegistryObjectWrite) -> Decision<RegistryObjectWrite> {
    let facts = NamespaceFacts::default();
    let dwoc = FakeDwocCatalog::new(std::iter::empty());
    let mut registry: Registry<RegistryObjectWrite> = Registry::new();
    registry.register(guard());
    let context = Context::new(&[], &facts, &dwoc);
    guard()
        .evaluate(write, &context)
        .expect("the guard never errors")
}

/// A copy this operator wrote, read back from the apiserver, carries the label the guard keys on.
#[tokio::test]
async fn a_written_copy_carries_the_label_the_guard_denies_writes_to() {
    let Some((_env_test, client, feature, store)) =
        fixture(config(npm_catalog(), vec!["internal-npm"])).await
    else {
        return;
    };
    let teams = teams();
    let facts = namespace_facts();
    let dwoc = FakeDwocCatalog::new(std::iter::empty());
    let context = Context::new(&teams, &facts, &dwoc);
    weebo_si_registry_config::reconcile(
        &feature,
        &subject(),
        &context,
        FeatureMode::Enforce,
        store.as_ref(),
    )
    .await
    .expect("the pass should complete");

    let config_maps: Api<ConfigMap> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let copy = config_maps
        .get("weebo-si-internal-npm-weebo-npmrc")
        .await
        .expect("the copy should exist");
    let target_is_managed = copy
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE);
    assert!(target_is_managed);

    let denied = decide(&RegistryObjectWrite {
        namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
        actor: "user-alice".to_string(),
        operation: WriteOperation::Delete,
        kind: SourceKind::ConfigMap,
        target_is_managed,
    });
    assert!(
        denied.denial.is_some(),
        "deleting the copy is the cheapest bypass, and the guard has to refuse it"
    );
}

/// And an ordinary `ConfigMap` in the same namespace is not the guard's business — the row this
/// guard deliberately does not have, checked against a real object.
#[tokio::test]
async fn an_ordinary_configmap_in_the_same_namespace_is_allowed() {
    let env_test = envtest_or_skip!();
    let client = env_test.client().expect("a client");
    create_namespace(client.clone(), WORKSPACE_NAMESPACE).await;
    let config_maps: Api<ConfigMap> = Api::namespaced(client, WORKSPACE_NAMESPACE);
    let object = ConfigMap {
        metadata: ObjectMeta {
            name: Some("user-scratch".to_string()),
            namespace: Some(WORKSPACE_NAMESPACE.to_string()),
            ..Default::default()
        },
        ..ConfigMap::default()
    };
    let created = config_maps
        .create(&PostParams::default(), &object)
        .await
        .expect("a developer's own ConfigMap");
    let target_is_managed = created
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .is_some_and(|value| value == MANAGED_BY_VALUE);
    assert!(!target_is_managed);

    for operation in [
        WriteOperation::Create,
        WriteOperation::Update,
        WriteOperation::Delete,
    ] {
        let allowed = decide(&RegistryObjectWrite {
            namespace: NamespaceName::new(WORKSPACE_NAMESPACE),
            actor: "user-alice".to_string(),
            operation,
            kind: SourceKind::ConfigMap,
            target_is_managed,
        });
        assert!(allowed.denial.is_none(), "{operation:?} must be allowed");
    }
}
