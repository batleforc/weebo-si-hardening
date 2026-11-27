//! [`ToolObjectStore`] over watch caches (RFC 0020, *Data and state*):
//!
//! * cluster-wide, filtered by `managed-by` and `team-tool`: `ConfigMap`, `CiliumNetworkPolicy`
//!   (when Cilium's CRD is served) and `Certificate` (when cert-manager's is). The chart grants
//!   that read cluster-wide; it is what both a tools namespace and a workspace namespace hold.
//! * per tools namespace, started on first use and only where the RoleBinding lets this role
//!   watch: `Deployment`, `StatefulSet`, `Service` (filtered the same way) and every
//!   `ResourceQuota` (the binding gate reads `spec.hard`). Until every one of them has listed,
//!   the namespace is [`Watch::Syncing`] and its tools are held: an empty cache must never read as
//!   "no object, no replica".
//!
//! Writes are server-side apply under [`FIELD_MANAGER`], forced. `spec.replicas` has exactly one
//! writer, [`SCALE_FIELD_MANAGER`]: a workload is created by an apply carrying `replicas: 0`,
//! which [`SCALE_FIELD_MANAGER`] claims at once (an apply of `spec.replicas` alone), then
//! re-applied without the field, so [`FIELD_MANAGER`] never owns it past the create and no later
//! apply can hand it back to the API default of 1; `/scale` moves it. (Not the RFC's plain
//! create: a create's manager keeps every field it set, so a field later dropped from the
//! template would never be removed.) Deletes re-read the
//! live object, refuse one without `managed-by`, and pin the delete to its uid.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::ResourceQuota;
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams, Preconditions};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, ResourceExt};
use serde_json::json;
use weebo_si_chassis::ObjectKey;
use weebo_si_chassis::managed::{Applied, Diff};
use weebo_si_crd::{
    MANAGED_BY_LABEL, MANAGED_BY_VALUE, NamespaceName, TEAM_TOOL_LABEL, TeamName, ToolKey,
};
use weebo_si_team_tools::{FIELD_MANAGER, SCALE_FIELD_MANAGER, ToolObject, ToolObjectKind};

use crate::kube_template_store::spawn_reflector;
use crate::objects::{
    apply_document, from_live, is_managed, is_tools_side, is_workload, replicas_of, resource,
};
use crate::port::{Adoption, BoxFuture, StoreError, ToolObjectStore};

/// How long a tools namespace this role may not watch is not asked about again.
const FORBIDDEN_RECHECK: Duration = Duration::from_secs(60);

/// The kinds watched per tools namespace (the chart grants no cluster-wide read on them).
const NAMESPACED_KINDS: [ToolObjectKind; 3] = [
    ToolObjectKind::Deployment,
    ToolObjectKind::StatefulSet,
    ToolObjectKind::Service,
];

/// Where a tools namespace's caches stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// Every cache listed.
    Synced,
    /// Started, not listed yet (or its list keeps failing).
    Syncing,
    /// This role may not watch there: no RoleBinding.
    Forbidden,
}

fn managed_selector() -> watcher::Config {
    watcher::Config::default().labels(&format!(
        "{MANAGED_BY_LABEL}={MANAGED_BY_VALUE},{TEAM_TOOL_LABEL}"
    ))
}

struct NamespaceWatch {
    team: Mutex<TeamName>,
    objects: Vec<(ToolObjectKind, Store<DynamicObject>)>,
    quotas: Store<ResourceQuota>,
    synced: Arc<AtomicBool>,
    /// Set by a watch error: the slot is dropped and access asked again on the next use.
    broken: Arc<AtomicBool>,
    tasks: Vec<tokio::task::AbortHandle>,
}

impl Drop for NamespaceWatch {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl NamespaceWatch {
    fn state(&self) -> Watch {
        if self.synced.load(Ordering::Acquire) {
            Watch::Synced
        } else {
            Watch::Syncing
        }
    }
}

enum Slot {
    Watching(Arc<NamespaceWatch>),
    Forbidden(Instant),
}

/// Drive one tools-namespace watch. Unlike [`weebo_si_runtime::watch::drive`] it never reports
/// to liveness: a team whose RoleBinding was removed must not fail the whole operator's probes
/// (RFC 0020, *Data and state*). An error marks the watch broken; its namespace is held until
/// the next pass asks for access again.
async fn drive_namespaced<S, T, E>(stream: S, broken: Arc<AtomicBool>, synced: Arc<AtomicBool>)
where
    S: futures_util::Stream<Item = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    while let Some(item) = futures_util::StreamExt::next(&mut stream).await {
        if let Err(err) = item {
            tracing::warn!(
                "feature=team-tools tools-namespace watch error, the namespace is held: {err}"
            );
            synced.store(false, Ordering::Release);
            broken.store(true, Ordering::Release);
        }
    }
}

/// The stores, cluster-wide and per tools namespace.
pub struct KubeToolStore {
    client: Client,
    global: Vec<(ToolObjectKind, Store<DynamicObject>)>,
    namespaces: Mutex<HashMap<NamespaceName, Slot>>,
}

impl KubeToolStore {
    /// Start the cluster-wide watches; `CiliumNetworkPolicy` only when `cilium`,
    /// `Certificate` only when `cert_manager`, and each only when this role may watch it
    /// cluster-wide (a watch the apiserver refuses would never list, and this would never
    /// return). Blocks until each started one has listed.
    pub async fn spawn(
        client: Client,
        cilium: bool,
        cert_manager: bool,
    ) -> Result<Self, kube::Error> {
        let mut global = Vec::new();
        for (kind, group, plural, wanted) in [
            (ToolObjectKind::ConfigMap, "", "configmaps", true),
            (
                ToolObjectKind::CiliumNetworkPolicy,
                "cilium.io",
                "ciliumnetworkpolicies",
                cilium,
            ),
            (
                ToolObjectKind::Certificate,
                "cert-manager.io",
                "certificates",
                cert_manager,
            ),
        ] {
            if !wanted {
                continue;
            }
            if !weebo_si_runtime::access::can_watch(&client, group, plural, None).await? {
                tracing::warn!(
                    "feature=team-tools not watching {plural} cluster-wide: this ServiceAccount \
                     may not (CiliumNetworkPolicy needs networkProfiles.cilium.enabled, the others \
                     teamTools.rbac.enabled); those objects are never written"
                );
                continue;
            }
            let (reader, _task) = spawn_reflector(
                client.clone(),
                None,
                kind,
                managed_selector(),
                "team-tool-objects",
            );
            reader.wait_until_ready().await.map_err(|err| {
                kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                    err.to_string(),
                ))
            })?;
            global.push((kind, reader));
        }
        Ok(Self {
            client,
            global,
            namespaces: Mutex::new(HashMap::new()),
        })
    }

    fn slots(&self) -> std::sync::MutexGuard<'_, HashMap<NamespaceName, Slot>> {
        self.namespaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn watch_of(&self, namespace: &NamespaceName) -> Option<Arc<NamespaceWatch>> {
        match self.slots().get(namespace) {
            Some(Slot::Watching(watch)) => Some(Arc::clone(watch)),
            _ => None,
        }
    }

    /// Start (once) the caches of `team`'s tools namespace `namespace` and say where they stand.
    /// Asks the apiserver first whether this role may watch there: a namespace without the
    /// admin's RoleBinding gets no watch, only [`Watch::Forbidden`], asked again after a minute.
    /// A watch that failed since is dropped and asked again the same way.
    pub async fn watch_tools_namespace(
        &self,
        team: &TeamName,
        namespace: &NamespaceName,
    ) -> Result<Watch, kube::Error> {
        {
            let mut slots = self.slots();
            match slots.get(namespace) {
                Some(Slot::Watching(watch)) if !watch.broken.load(Ordering::Acquire) => {
                    let state = watch.state();
                    // The namespace may have changed hands: same caches, the new team's name.
                    *watch
                        .team
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = team.clone();
                    return Ok(state);
                }
                Some(Slot::Forbidden(at)) if at.elapsed() < FORBIDDEN_RECHECK => {
                    return Ok(Watch::Forbidden);
                }
                Some(_) => {
                    slots.remove(namespace);
                }
                None => {}
            }
        }
        let allowed = weebo_si_runtime::access::can_watch(
            &self.client,
            "apps",
            "statefulsets",
            Some(namespace.as_str()),
        )
        .await?;
        if !allowed {
            self.slots()
                .insert(namespace.clone(), Slot::Forbidden(Instant::now()));
            return Ok(Watch::Forbidden);
        }
        let mut slots = self.slots();
        // Another pass may have started it while this one asked.
        if let Some(Slot::Watching(watch)) = slots.get(namespace) {
            return Ok(watch.state());
        }
        let synced = Arc::new(AtomicBool::new(false));
        let broken = Arc::new(AtomicBool::new(false));
        let mut tasks = Vec::new();
        let mut objects = Vec::new();
        for kind in NAMESPACED_KINDS {
            let resource = resource(kind);
            let api: Api<DynamicObject> =
                Api::namespaced_with(self.client.clone(), namespace.as_str(), &resource);
            let writer = reflector::store::Writer::<DynamicObject>::new(resource);
            objects.push((kind, writer.as_reader()));
            let stream =
                reflector::reflector(writer, watcher(api, managed_selector())).default_backoff();
            tasks.push(
                tokio::spawn(drive_namespaced(
                    stream,
                    Arc::clone(&broken),
                    Arc::clone(&synced),
                ))
                .abort_handle(),
            );
        }
        let (quotas, writer) = reflector::store::<ResourceQuota>();
        let api: Api<ResourceQuota> = Api::namespaced(self.client.clone(), namespace.as_str());
        let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
            .default_backoff();
        tasks.push(
            tokio::spawn(drive_namespaced(
                stream,
                Arc::clone(&broken),
                Arc::clone(&synced),
            ))
            .abort_handle(),
        );
        let waiting: Vec<Store<DynamicObject>> =
            objects.iter().map(|(_, store)| store.clone()).collect();
        let quotas_waiting = quotas.clone();
        let flag = Arc::clone(&synced);
        let failed = Arc::clone(&broken);
        tasks.push(
            tokio::spawn(async move {
                for store in waiting {
                    if store.wait_until_ready().await.is_err() {
                        return;
                    }
                }
                if quotas_waiting.wait_until_ready().await.is_ok()
                    && !failed.load(Ordering::Acquire)
                {
                    flag.store(true, Ordering::Release);
                }
            })
            .abort_handle(),
        );
        // A watch lives as long as its namespace, even once its team moved elsewhere (it is what
        // finds the objects left there); after a restart, [`Self::tools_side_namespaces`] finds
        // them again.
        slots.insert(
            namespace.clone(),
            Slot::Watching(Arc::new(NamespaceWatch {
                team: Mutex::new(team.clone()),
                objects,
                quotas,
                synced,
                broken,
                tasks,
            })),
        );
        Ok(Watch::Syncing)
    }

    /// Every tools namespace watched, with the team that first asked for it.
    pub fn watched(&self) -> Vec<(NamespaceName, TeamName)> {
        self.slots()
            .iter()
            .filter_map(|(namespace, slot)| match slot {
                Slot::Watching(watch) => Some((
                    namespace.clone(),
                    watch
                        .team
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone(),
                )),
                Slot::Forbidden(_) => None,
            })
            .collect()
    }

    /// Whether `namespace`'s caches are watched and listed.
    pub fn synced(&self, namespace: &NamespaceName) -> bool {
        self.watch_of(namespace)
            .is_some_and(|watch| watch.state() == Watch::Synced)
    }

    /// Drop `namespace`'s caches (a namespace that no longer exists).
    pub fn forget(&self, namespace: &NamespaceName) {
        self.slots().remove(namespace);
    }

    /// Every namespace where a cluster-wide cache holds a tool's ingress policy or server
    /// certificate: a tools namespace, watched or not (a restart forgets which were).
    pub fn tools_side_namespaces(&self) -> BTreeSet<NamespaceName> {
        self.global
            .iter()
            .flat_map(|(kind, store)| store.state().into_iter().map(move |object| (*kind, object)))
            .filter_map(|(kind, object)| from_live(kind, &object))
            .filter(is_tools_side)
            .map(|object| object.key.namespace)
            .collect()
    }

    /// `spec.hard` of every `ResourceQuota` in a watched tools namespace.
    pub fn quotas(&self, namespace: &NamespaceName) -> Vec<BTreeMap<String, String>> {
        let Some(watch) = self.watch_of(namespace) else {
            return Vec::new();
        };
        watch
            .quotas
            .state()
            .iter()
            .map(|quota| {
                quota
                    .spec
                    .as_ref()
                    .and_then(|spec| spec.hard.as_ref())
                    .map(|hard| {
                        hard.iter()
                            .map(|(resource, quantity)| (resource.clone(), quantity.0.clone()))
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect()
    }

    /// The live `spec.replicas` of a managed workload, `None` before it exists.
    pub fn replicas(&self, kind: ToolObjectKind, workload: &ObjectKey) -> Option<i32> {
        let watch = self.watch_of(&workload.namespace)?;
        let (_, store) = watch
            .objects
            .iter()
            .find(|(candidate, _)| *candidate == kind)?;
        let reference =
            ObjectRef::new_with(&workload.name, resource(kind)).within(workload.namespace.as_str());
        store
            .get(&reference)
            .filter(|object| is_managed(object))
            .and_then(|object| replicas_of(&object))
    }

    /// The keys present in `namespace`'s managed objects: a key dropped from the catalogue still
    /// has objects to remove.
    pub fn keys_in(&self, namespace: &NamespaceName) -> Vec<ToolKey> {
        let mut keys: Vec<ToolKey> = self
            .live_in(namespace)
            .into_iter()
            .filter_map(|(kind, object)| from_live(kind, &object).map(|object| object.tool))
            .collect();
        keys.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        keys.dedup();
        keys
    }

    /// `namespace/kind/name@resourceVersion` of every cached managed object, for the controller's
    /// change trigger.
    pub fn versions(&self) -> Vec<String> {
        let watches: Vec<Arc<NamespaceWatch>> = self
            .slots()
            .values()
            .filter_map(|slot| match slot {
                Slot::Watching(watch) => Some(Arc::clone(watch)),
                Slot::Forbidden(_) => None,
            })
            .collect();
        let mut stores: Vec<(ToolObjectKind, &Store<DynamicObject>)> = self
            .global
            .iter()
            .map(|(kind, store)| (*kind, store))
            .collect();
        stores.extend(
            watches
                .iter()
                .flat_map(|watch| watch.objects.iter().map(|(kind, store)| (*kind, store))),
        );
        let mut versions: Vec<String> = stores
            .into_iter()
            .flat_map(|(kind, store)| store.state().into_iter().map(move |object| (kind, object)))
            .map(|(kind, object)| {
                format!(
                    "{}/{}/{}@{}",
                    object.namespace().unwrap_or_default(),
                    kind.as_str(),
                    object.name_any(),
                    object.resource_version().unwrap_or_default()
                )
            })
            .collect();
        for watch in &watches {
            versions.extend(watch.quotas.state().iter().map(|quota| {
                format!(
                    "{}/ResourceQuota/{}@{}",
                    quota.namespace().unwrap_or_default(),
                    quota.name_any(),
                    quota.resource_version().unwrap_or_default()
                )
            }));
        }
        versions.sort();
        versions
    }

    /// Every managed object in `namespace`, any key, as the diff compares them.
    pub fn all_in(&self, namespace: &NamespaceName) -> Vec<ToolObject> {
        self.live_in(namespace)
            .into_iter()
            .filter_map(|(kind, object)| from_live(kind, &object))
            .collect()
    }

    /// Every managed object this store caches, every namespace.
    pub fn all(&self) -> Vec<ToolObject> {
        let mut namespaces: Vec<NamespaceName> = self
            .slots()
            .iter()
            .filter(|(_, slot)| matches!(slot, Slot::Watching(_)))
            .map(|(namespace, _)| namespace.clone())
            .collect();
        namespaces.extend(self.global.iter().flat_map(|(_, store)| {
            store
                .state()
                .into_iter()
                .filter_map(|object| object.namespace().map(NamespaceName::new))
        }));
        namespaces.sort();
        namespaces.dedup();
        namespaces
            .iter()
            .flat_map(|namespace| self.all_in(namespace))
            .collect()
    }

    fn live_in(&self, namespace: &NamespaceName) -> Vec<(ToolObjectKind, Arc<DynamicObject>)> {
        let mut live: Vec<(ToolObjectKind, Arc<DynamicObject>)> = self
            .global
            .iter()
            .flat_map(|(kind, store)| store.state().into_iter().map(move |object| (*kind, object)))
            .filter(|(_, object)| object.metadata.namespace.as_deref() == Some(namespace.as_str()))
            .collect();
        if let Some(watch) = self.watch_of(namespace) {
            live.extend(watch.objects.iter().flat_map(|(kind, store)| {
                store.state().into_iter().map(move |object| (*kind, object))
            }));
        }
        live
    }

    fn api(&self, kind: ToolObjectKind, namespace: &NamespaceName) -> Api<DynamicObject> {
        Api::namespaced_with(self.client.clone(), namespace.as_str(), &resource(kind))
    }

    async fn write(&self, object: &ToolObject, adoption: Adoption) -> Result<bool, StoreError> {
        let api = self.api(object.kind, &object.key.namespace);
        let fail = |err: kube::Error| failure(&object.key, err);
        let live = api.get_opt(&object.key.name).await.map_err(fail)?;
        let workload = is_workload(object.kind);
        match &live {
            None if workload => {
                apply(&api, object, FIELD_MANAGER, apply_document(object, Some(0))).await?;
                claim_replicas(&api, object, 0, None).await?;
                // The apply below, without the field, releases it to the scale manager alone.
            }
            None => {}
            Some(live) if !is_managed(live) => {
                if adoption == Adoption::Never {
                    tracing::warn!(
                        "feature=team-tools not writing {} {}/{}: an object of that name exists \
                         without {MANAGED_BY_LABEL} and a workspace namespace's objects are never \
                         adopted",
                        object.kind.as_str(),
                        object.key.namespace,
                        object.key.name
                    );
                    return Ok(false);
                }
                tracing::info!(
                    "feature=team-tools adopting {} {}/{} (no {MANAGED_BY_LABEL}): forced apply, \
                     its replicas kept",
                    object.kind.as_str(),
                    object.key.namespace,
                    object.key.name
                );
            }
            Some(live) => {
                // A create interrupted before its re-apply left `replicas` with the apply
                // manager: claim the live value first, pinned to the version read, so this apply
                // cannot hand it back to the default nor undo a scale that landed meanwhile.
                if workload
                    && apply_manager_owns_replicas(live)
                    && let Some(current) = replicas_of(live)
                {
                    claim_replicas(
                        &api,
                        object,
                        current,
                        live.metadata.resource_version.clone(),
                    )
                    .await?;
                }
            }
        }
        apply(&api, object, FIELD_MANAGER, apply_document(object, None)).await?;
        Ok(true)
    }

    async fn delete(
        &self,
        key: &ObjectKey,
        kind: ToolObjectKind,
        uid: Option<&str>,
    ) -> Result<bool, StoreError> {
        let api = self.api(kind, &key.namespace);
        let fail = |err: kube::Error| failure(key, err);
        let Some(live) = api.get_opt(&key.name).await.map_err(fail)? else {
            return Ok(false);
        };
        if !is_managed(&live) {
            tracing::warn!(
                "feature=team-tools not deleting {} {}/{}: the live object does not carry \
                 {MANAGED_BY_LABEL}={MANAGED_BY_VALUE}",
                kind.as_str(),
                key.namespace,
                key.name
            );
            return Ok(false);
        }
        let uid = uid
            .map(str::to_string)
            .or_else(|| live.metadata.uid.clone());
        let params = DeleteParams {
            preconditions: Some(Preconditions {
                uid,
                resource_version: None,
            }),
            ..DeleteParams::background()
        };
        match api.delete(&key.name, &params).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(status)) if status.code == 404 || status.code == 409 => Ok(false),
            Err(err) => Err(failure(key, err)),
        }
    }
}

fn failure(key: &ObjectKey, err: kube::Error) -> StoreError {
    match err {
        kube::Error::Api(status) if status.code == 403 => {
            StoreError::Forbidden(key.namespace.clone())
        }
        other => StoreError::Failed(format!("{}/{}: {other}", key.namespace, key.name)),
    }
}

async fn apply(
    api: &Api<DynamicObject>,
    object: &ToolObject,
    manager: &str,
    document: serde_json::Value,
) -> Result<(), StoreError> {
    api.patch(
        &object.key.name,
        &PatchParams::apply(manager).force(),
        &Patch::Apply(document),
    )
    .await
    .map(|_| ())
    .map_err(|err| failure(&object.key, err))
}

/// Whether [`FIELD_MANAGER`]'s apply entry owns `spec.replicas`.
fn apply_manager_owns_replicas(live: &DynamicObject) -> bool {
    live.metadata.managed_fields.iter().flatten().any(|entry| {
        entry.manager.as_deref() == Some(FIELD_MANAGER)
            && entry.operation.as_deref() == Some("Apply")
            && entry
                .fields_v1
                .as_ref()
                .is_some_and(|fields| fields.0.pointer("/f:spec/f:replicas").is_some())
    })
}

/// Make [`SCALE_FIELD_MANAGER`] an owner of `spec.replicas` at its current value, refused (409)
/// when `resource_version` is given and the object moved since.
async fn claim_replicas(
    api: &Api<DynamicObject>,
    object: &ToolObject,
    replicas: i32,
    resource_version: Option<String>,
) -> Result<(), StoreError> {
    let mut metadata = json!({"name": object.key.name, "namespace": object.key.namespace.as_str()});
    if let Some(version) = resource_version {
        metadata["resourceVersion"] = json!(version);
    }
    let document = json!({
        "apiVersion": object.kind.api_version(),
        "kind": object.kind.as_str(),
        "metadata": metadata,
        "spec": {"replicas": replicas},
    });
    apply(api, object, SCALE_FIELD_MANAGER, document).await
}

impl ToolObjectStore for KubeToolStore {
    fn managed(&self, namespace: &NamespaceName, tool: &ToolKey) -> Vec<ToolObject> {
        self.live_in(namespace)
            .into_iter()
            .filter_map(|(kind, object)| from_live(kind, &object))
            .filter(|object| &object.tool == tool)
            .collect()
    }

    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff<ToolObject>],
        adoption: Adoption,
    ) -> BoxFuture<'a, Result<Applied, StoreError>> {
        Box::pin(async move {
            let mut applied = Applied::default();
            for diff in diffs {
                match diff {
                    Diff::Create(object) => {
                        if self.write(object, adoption).await? {
                            applied.created = applied.created.saturating_add(1);
                        }
                    }
                    Diff::Update(object) => {
                        if self.write(object, adoption).await? {
                            applied.updated = applied.updated.saturating_add(1);
                        }
                    }
                    Diff::Delete { key, backend, uid } => {
                        if self.delete(key, *backend, uid.as_deref()).await? {
                            applied.deleted = applied.deleted.saturating_add(1);
                        }
                    }
                    Diff::Unchanged(_) => applied.unchanged = applied.unchanged.saturating_add(1),
                }
            }
            Ok(applied)
        })
    }

    fn scale<'a>(
        &'a self,
        kind: ToolObjectKind,
        workload: &'a ObjectKey,
        replicas: i32,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let params = PatchParams {
                field_manager: Some(SCALE_FIELD_MANAGER.to_string()),
                ..PatchParams::default()
            };
            self.api(kind, &workload.namespace)
                .patch_scale(
                    &workload.name,
                    &params,
                    &Patch::Merge(json!({"spec": {"replicas": replicas}})),
                )
                .await
                .map(|_| ())
                .map_err(|err| failure(workload, err))
        })
    }
}
