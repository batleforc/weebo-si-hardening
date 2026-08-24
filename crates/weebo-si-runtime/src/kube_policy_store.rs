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

/// Watch-backed `PolicyStore`: both backends, cluster-wide, filtered server-side to this
/// operator's own managed objects.
pub struct KubePolicyStore {
    client: Client,
    network_policy: Store<NetworkPolicy>,
    cilium: Option<Store<DynamicObject>>,
}

impl KubePolicyStore {
    /// Start watching every managed `NetworkPolicy`, and — when `cilium_enabled` — every managed
    /// `CiliumNetworkPolicy`, cluster-wide. Blocks until every started watch's initial list
    /// completes.
    pub async fn spawn(client: Client, cilium_enabled: bool) -> Result<Self, kube::Error> {
        let label_selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");

        let api: Api<NetworkPolicy> = Api::all(client.clone());
        let (reader, writer) = reflector::store();
        let watcher_config = watcher::Config::default().labels(&label_selector);
        let stream = reflector::reflector(writer, watcher(api, watcher_config)).default_backoff();
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
            let watcher_config = watcher::Config::default().labels(&label_selector);
            let stream =
                reflector::reflector(writer, watcher(api, watcher_config)).default_backoff();
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
            Some(cilium_reader)
        } else {
            None
        };

        Ok(Self {
            client,
            network_policy: reader,
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
            "metadata": {
                "name": obj.key.name,
                "namespace": obj.key.namespace.as_str(),
                "labels": labels_json(&obj.profile, obj.backend),
            },
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
            "metadata": {
                "name": obj.key.name,
                "namespace": obj.key.namespace.as_str(),
                "labels": labels_json(&obj.profile, obj.backend),
            },
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
            .network_policy
            .state()
            .iter()
            .filter(|np| np.metadata.namespace.as_deref() == Some(ns.as_str()))
            .filter_map(|np| Self::from_network_policy(np))
            .collect();

        if let Some(store) = &self.cilium {
            objects.extend(
                store
                    .state()
                    .iter()
                    .filter(|obj| obj.metadata.namespace.as_deref() == Some(ns.as_str()))
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
        if let Some(store) = &self.cilium {
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
