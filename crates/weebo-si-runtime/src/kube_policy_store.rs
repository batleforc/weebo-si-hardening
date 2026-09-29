//! `PolicyStore` implementation: server-side apply, one field manager, label-filtered watches of
//! both backends. See RFC 0004's *Design*, "The objects written," and *Security considerations*,
//! "The label is the ownership boundary."

use std::future::Future;
use std::pin::Pin;

use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Client;
use kube::api::{Api, DeleteParams, DynamicObject, Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::{Value, json};
use weebo_si_chassis::DomainError;
use weebo_si_crd::{
    BACKEND_LABEL, Backend, DEVWORKSPACE_ID_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE,
    NamespaceName, PROFILE_LABEL, ProfileKey,
};
use weebo_si_network_profiles::{
    Applied, BaselineView, Diff, ManagedObject, ObjectKey, PodSelector, PolicyBody, PolicyStore,
};

use crate::kube_template_store::{cilium_network_policy_resource, selector_field};
use crate::ns_index::NsIndex;
use crate::owner_reference::{owner_from_references, owner_references_json};

/// Every write from this adapter goes through server-side apply under this one manager, per the
/// RFC's *Operational considerations*: "a rolling update never produces two managers fighting."
const FIELD_MANAGER: &str = "weebo-si-operator";

fn backend_label_value(backend: Backend) -> &'static str {
    match backend {
        Backend::NetworkPolicy => "NetworkPolicy",
        Backend::Cilium => "Cilium",
    }
}

fn pod_selector_json(pod_selector: &PodSelector) -> Value {
    match pod_selector {
        PodSelector::Empty => json!({}),
        PodSelector::DevWorkspaceId(id) => json!({"matchLabels": {DEVWORKSPACE_ID_LABEL: id}}),
    }
}

/// The pod selector a live object actually carries, read back from its own
/// `podSelector`/`endpointSelector`'s `matchLabels`. `None` for anything that is not exactly one
/// of the two shapes this adapter itself ever writes — a foreign object could never carry the
/// management label in the first place (the watch is label-filtered), so this only has to
/// recognise this adapter's own output.
fn pod_selector_from_match_labels(value: Option<&Value>) -> PodSelector {
    let id = value
        .and_then(|v| v.get("matchLabels"))
        .and_then(|labels| labels.get(DEVWORKSPACE_ID_LABEL))
        .and_then(Value::as_str);
    match id {
        Some(id) => PodSelector::DevWorkspaceId(id.to_string()),
        None => PodSelector::Empty,
    }
}

fn labels_json(profile: &ProfileKey, backend: Backend) -> Value {
    json!({
        MANAGED_BY_LABEL: MANAGED_BY_VALUE,
        PROFILE_LABEL: profile.as_str(),
        BACKEND_LABEL: backend_label_value(backend),
    })
}

/// `metadata` for an apply of `obj`: identity, the managed labels, and — for a profile object
/// only — the `ownerReferences` entry that lets the apiserver garbage-collect it with its
/// DevWorkspace (see [`crate::owner_reference`]).
fn metadata_json(obj: &ManagedObject) -> Value {
    let mut metadata = json!({
        "name": obj.key.name,
        "namespace": obj.key.namespace.as_str(),
        "labels": labels_json(&obj.profile, obj.backend),
    });
    if let (Value::Object(map), Some(references)) =
        (&mut metadata, owner_references_json(obj.owner.as_ref()))
    {
        map.insert("ownerReferences".to_string(), references);
    }
    metadata
}

/// Watch-backed `PolicyStore`: both backends, cluster-wide, filtered server-side to this
/// operator's own managed objects.
///
/// Each store is paired with a [`NsIndex`] fed from the same watch, so the per-namespace reads
/// (`managed_in`, and `has_baseline` on every DevWorkspace admission) touch only that namespace's
/// objects instead of scanning the whole cluster-wide cache.
pub struct KubePolicyStore {
    client: Client,
    network_policy: Store<NetworkPolicy>,
    network_policy_index: NsIndex<NetworkPolicy>,
    cilium: Option<(Store<DynamicObject>, NsIndex<DynamicObject>)>,
}

impl KubePolicyStore {
    /// Start watching every managed `NetworkPolicy`, and — when `cilium_enabled` — every managed
    /// `CiliumNetworkPolicy`, cluster-wide. Blocks until every started watch's initial list
    /// completes.
    pub async fn spawn(client: Client, cilium_enabled: bool) -> Result<Self, kube::Error> {
        let label_selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");

        let api: Api<NetworkPolicy> = Api::all(client.clone());
        let (reader, writer) = reflector::store();
        let network_policy_index = NsIndex::<NetworkPolicy>::new(());
        let watcher_config = watcher::Config::default().labels(&label_selector);
        let indexed = {
            use futures_util::TryStreamExt;
            let index = network_policy_index.clone();
            watcher(api, watcher_config).map_ok(move |event| {
                index.observe(&event);
                event
            })
        };
        let stream = reflector::reflector(writer, indexed).default_backoff();
        tokio::spawn(async move {
            use futures_util::StreamExt;
            let mut stream = std::pin::pin!(stream);
            while stream.next().await.is_some() {}
        });
        reader.wait_until_ready().await.map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;

        let cilium = if cilium_enabled {
            let resource = cilium_network_policy_resource();
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
            let writer = reflector::store::Writer::<DynamicObject>::new(resource.clone());
            let cilium_reader = writer.as_reader();
            let cilium_index = NsIndex::<DynamicObject>::new(resource.clone());
            let watcher_config = watcher::Config::default().labels(&label_selector);
            let indexed = {
                use futures_util::TryStreamExt;
                let index = cilium_index.clone();
                watcher(api, watcher_config).map_ok(move |event| {
                    index.observe(&event);
                    event
                })
            };
            let stream = reflector::reflector(writer, indexed).default_backoff();
            tokio::spawn(async move {
                use futures_util::StreamExt;
                let mut stream = std::pin::pin!(stream);
                while stream.next().await.is_some() {}
            });
            cilium_reader.wait_until_ready().await.map_err(|err| {
                kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                    err.to_string(),
                ))
            })?;
            Some((cilium_reader, cilium_index))
        } else {
            None
        };

        Ok(Self {
            client,
            network_policy: reader,
            network_policy_index,
            cilium,
        })
    }

    fn from_network_policy(obj: &NetworkPolicy) -> Option<ManagedObject> {
        let labels = obj.metadata.labels.as_ref()?;
        let profile = ProfileKey::new(labels.get(PROFILE_LABEL)?.clone());
        let mut spec = serde_json::to_value(obj.spec.as_ref()?).ok()?;
        let pod_selector = pod_selector_from_match_labels(spec.get("podSelector"));
        if let Value::Object(map) = &mut spec {
            map.remove(selector_field(Backend::NetworkPolicy));
        }
        Some(ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new(obj.metadata.namespace.clone()?),
                name: obj.metadata.name.clone()?,
            },
            backend: Backend::NetworkPolicy,
            profile,
            pod_selector,
            body: PolicyBody::opaque(serde_json::to_vec(&spec).ok()?),
            owner: owner_from_references(obj.metadata.owner_references.as_deref()),
        })
    }

    fn from_cilium(obj: &DynamicObject) -> Option<ManagedObject> {
        let labels = obj.metadata.labels.as_ref()?;
        let profile = ProfileKey::new(labels.get(PROFILE_LABEL)?.clone());
        let mut spec = obj.data.get("spec")?.clone();
        let pod_selector = pod_selector_from_match_labels(spec.get("endpointSelector"));
        if let Value::Object(map) = &mut spec {
            map.remove(selector_field(Backend::Cilium));
        }
        Some(ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new(obj.metadata.namespace.clone()?),
                name: obj.metadata.name.clone()?,
            },
            backend: Backend::Cilium,
            profile,
            pod_selector,
            body: PolicyBody::opaque(serde_json::to_vec(&spec).ok()?),
            owner: owner_from_references(obj.metadata.owner_references.as_deref()),
        })
    }

    async fn apply_network_policy(&self, obj: &ManagedObject) -> Result<(), DomainError> {
        let mut spec: Value = serde_json::from_slice(obj.body.as_bytes())
            .map_err(|err| DomainError::PortFailed(format!("malformed policy body: {err}")))?;
        if let Value::Object(map) = &mut spec {
            map.insert(
                "podSelector".to_string(),
                pod_selector_json(&obj.pod_selector),
            );
        }
        let apply = json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata_json(obj),
            "spec": spec,
        });
        let api: Api<NetworkPolicy> =
            Api::namespaced(self.client.clone(), obj.key.namespace.as_str());
        api.patch(
            &obj.key.name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(apply),
        )
        .await
        .map_err(|err| DomainError::PortFailed(err.to_string()))?;
        Ok(())
    }

    async fn apply_cilium(&self, obj: &ManagedObject) -> Result<(), DomainError> {
        let mut spec: Value = serde_json::from_slice(obj.body.as_bytes())
            .map_err(|err| DomainError::PortFailed(format!("malformed policy body: {err}")))?;
        if let Value::Object(map) = &mut spec {
            map.insert(
                "endpointSelector".to_string(),
                pod_selector_json(&obj.pod_selector),
            );
        }
        let apply = json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": metadata_json(obj),
            "spec": spec,
        });
        let resource = cilium_network_policy_resource();
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), obj.key.namespace.as_str(), &resource);
        api.patch(
            &obj.key.name,
            &PatchParams::apply(FIELD_MANAGER),
            &Patch::Apply(apply),
        )
        .await
        .map_err(|err| DomainError::PortFailed(err.to_string()))?;
        Ok(())
    }

    async fn delete(&self, key: &ObjectKey, backend: Backend) -> Result<(), DomainError> {
        let result = match backend {
            Backend::NetworkPolicy => {
                let api: Api<NetworkPolicy> =
                    Api::namespaced(self.client.clone(), key.namespace.as_str());
                api.delete(&key.name, &DeleteParams::default())
                    .await
                    .map(|_| ())
            }
            Backend::Cilium => {
                let resource = cilium_network_policy_resource();
                let api: Api<DynamicObject> =
                    Api::namespaced_with(self.client.clone(), key.namespace.as_str(), &resource);
                api.delete(&key.name, &DeleteParams::default())
                    .await
                    .map(|_| ())
            }
        };
        match result {
            Ok(()) => Ok(()),
            // Deleting an object that is already gone is the outcome we wanted, not a failure —
            // this is what keeps a repeated Enforce pass over a namespace idempotent.
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(()),
            Err(err) => Err(DomainError::PortFailed(err.to_string())),
        }
    }
}

/// The baseline is the object whose selector governs *every* pod in the namespace — read off
/// [`PodSelector`] rather than off the object's name, so a rename in the naming scheme cannot
/// silently turn this check into "always false" and start refusing every workspace.
impl BaselineView for KubePolicyStore {
    fn has_baseline(&self, ns: &NamespaceName) -> bool {
        self.managed_in(ns)
            .iter()
            .any(|obj| obj.pod_selector == PodSelector::Empty)
    }
}

impl PolicyStore for KubePolicyStore {
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ManagedObject> {
        let mut objects: Vec<ManagedObject> = self
            .network_policy_index
            .objects_in(&self.network_policy, ns.as_str())
            .iter()
            .filter_map(|np| Self::from_network_policy(np))
            .collect();

        if let Some((store, index)) = &self.cilium {
            objects.extend(
                index
                    .objects_in(store, ns.as_str())
                    .iter()
                    .filter_map(|obj| Self::from_cilium(obj)),
            );
        }

        objects
    }

    /// Free: the watch caches already hold exactly this population, filtered server-side by the
    /// ownership label — so "everything this operator owns, cluster-wide" costs no apiserver
    /// round-trip, which is what makes recomputing the gauge from a full snapshot affordable.
    fn managed_everywhere(&self) -> Vec<ManagedObject> {
        let mut objects: Vec<ManagedObject> = self
            .network_policy
            .state()
            .iter()
            .filter_map(|np| Self::from_network_policy(np))
            .collect();
        if let Some((store, _)) = &self.cilium {
            objects.extend(
                store
                    .state()
                    .iter()
                    .filter_map(|obj| Self::from_cilium(obj)),
            );
        }
        objects
    }

    fn apply<'a>(
        &'a self,
        diffs: &'a [Diff],
    ) -> Pin<Box<dyn Future<Output = Result<Applied, DomainError>> + Send + 'a>> {
        Box::pin(async move {
            for diff in diffs {
                match diff {
                    Diff::Create(obj) | Diff::Update(obj) => match obj.backend {
                        Backend::NetworkPolicy => self.apply_network_policy(obj).await?,
                        Backend::Cilium => self.apply_cilium(obj).await?,
                    },
                    Diff::Delete { key, backend } => self.delete(key, *backend).await?,
                    Diff::Unchanged(_) => {}
                }
            }
            Ok(weebo_si_network_profiles::tally(diffs))
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use weebo_si_network_profiles::Owner;

    use super::*;

    fn profile_object(owner: Option<Owner>) -> ManagedObject {
        ManagedObject {
            key: ObjectKey {
                namespace: NamespaceName::new("user-alice"),
                name: "weebo-git-workspacede4f56".to_string(),
            },
            backend: Backend::NetworkPolicy,
            profile: ProfileKey::new("git"),
            pod_selector: PodSelector::DevWorkspaceId("workspacede4f56".to_string()),
            body: PolicyBody::opaque(br#"{"policyTypes":["Egress"]}"#.to_vec()),
            owner,
        }
    }

    /// The document `apply_network_policy` sends, minus the apiserver round trip.
    fn written(obj: &ManagedObject) -> NetworkPolicy {
        let mut spec: Value = serde_json::from_slice(obj.body.as_bytes()).unwrap();
        spec.as_object_mut().unwrap().insert(
            "podSelector".to_string(),
            pod_selector_json(&obj.pod_selector),
        );
        serde_json::from_value(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata_json(obj),
            "spec": spec,
        }))
        .unwrap()
    }

    #[test]
    fn a_profile_object_round_trips_its_owner_through_what_this_adapter_writes() {
        // `content_eq` compares owners: an object read back with a different owner than it was
        // written with would be rewritten on every pass.
        let obj = profile_object(Some(Owner {
            api_version: "workspace.devfile.io/v1alpha2".to_string(),
            kind: "DevWorkspace".to_string(),
            name: "data-pipeline".to_string(),
            uid: "8f0c2a4e-uid".to_string(),
        }));
        assert_eq!(
            KubePolicyStore::from_network_policy(&written(&obj)),
            Some(obj)
        );
    }

    #[test]
    fn an_unowned_object_is_written_without_owner_references_and_reads_back_unowned() {
        let obj = profile_object(None);
        let policy = written(&obj);
        assert_eq!(policy.metadata.owner_references, None);
        assert_eq!(KubePolicyStore::from_network_policy(&policy), Some(obj));
    }
}
