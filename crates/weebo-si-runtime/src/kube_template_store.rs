//! Watch-backed template cache, implementing `TemplateStore` — one namespace, per RFC 0004's
//! *Data and state*: "Templates, watch-backed, in one namespace."
//!
//! **Known simplification**: a template edit is picked up by the next reconcile pass that reads
//! it (the watch keeps the cache fresh), but nothing here *triggers* a re-reconcile of every
//! namespace using the template the way the RFC's *Data and state* section describes ("a change
//! to one is a legitimate trigger to re-reconcile every namespace using it") — that trigger
//! belongs to the controller's watch wiring, not this cache.

use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::Value;
use weebo_si_crd::{Backend, TemplateRef};
use weebo_si_network_profiles::{PolicyBody, TemplateStore};

/// The `CiliumNetworkPolicy` GVK — a CRD Cilium installs, not a builtin, so it is watched as a
/// [`DynamicObject`] via a hand-built [`ApiResource`], the same pattern `dwoc_store` uses for
/// `DevWorkspaceOperatorConfig`.
pub fn cilium_network_policy_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk("cilium.io", "v2", "CiliumNetworkPolicy");
    ApiResource::from_gvk_with_plural(&gvk, "ciliumnetworkpolicies")
}

/// The JSON key each backend's template carries its pod-selecting field under — the one field
/// this adapter strips from a template before handing its rules on as an opaque body, since RFC
/// 0004's *Design* is explicit that "a template's own `podSelector` is ignored... scoping belongs
/// to the operator."
pub(crate) fn selector_field(backend: Backend) -> &'static str {
    match backend {
        Backend::NetworkPolicy => "podSelector",
        Backend::Cilium => "endpointSelector",
    }
}

/// Watch-backed `NetworkPolicy` + (optionally) `CiliumNetworkPolicy` template cache, both scoped
/// to one namespace.
pub struct KubeTemplateStore {
    network_policy: Store<NetworkPolicy>,
    cilium: Option<Store<DynamicObject>>,
}

impl KubeTemplateStore {
    /// Start watching `NetworkPolicy` templates in `namespace`, and `CiliumNetworkPolicy`
    /// templates there too when `cilium_enabled` — starting that second watch unconditionally on
    /// a cluster without Cilium's CRD installed would fail the initial list, so the caller (which
    /// already ran discovery to resolve the backend) decides. Blocks until every started watch's
    /// initial list completes.
    pub async fn spawn(
        client: Client,
        namespace: &str,
        cilium_enabled: bool,
    ) -> Result<Self, kube::Error> {
        let api: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
        let (reader, writer) = reflector::store();
        let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
            .default_backoff();
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
            let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &resource);
            let writer = reflector::store::Writer::<DynamicObject>::new(resource.clone());
            let cilium_reader = writer.as_reader();
            let stream = reflector::reflector(writer, watcher(api, watcher::Config::default()))
                .default_backoff();
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
            network_policy: reader,
            cilium,
        })
    }
}

impl TemplateStore for KubeTemplateStore {
    fn body(&self, backend: Backend, template_ref: &TemplateRef) -> Option<PolicyBody> {
        let mut value = match backend {
            Backend::NetworkPolicy => {
                let obj = self.network_policy.state().into_iter().find(|np| {
                    np.metadata.name.as_deref() == Some(template_ref.name.as_str())
                        && np.metadata.namespace.as_deref() == Some(template_ref.namespace.as_str())
                })?;
                serde_json::to_value(obj.spec.as_ref()?).ok()?
            }
            Backend::Cilium => {
                let store = self.cilium.as_ref()?;
                let obj = store.state().into_iter().find(|c| {
                    c.metadata.name.as_deref() == Some(template_ref.name.as_str())
                        && c.metadata.namespace.as_deref() == Some(template_ref.namespace.as_str())
                })?;
                obj.data.get("spec")?.clone()
            }
        };

        if let Value::Object(map) = &mut value {
            map.remove(selector_field(backend));
        }

        serde_json::to_vec(&value).ok().map(PolicyBody::opaque)
    }
}
