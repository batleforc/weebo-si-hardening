//! Watch-backed `KubeArmorPolicy` template cache, implementing `kubearmor-policy`'s
//! `TemplateStore` — one namespace, mirroring [`crate::kube_template_store`]'s shape for
//! `network-profiles`.
//!
//! **Known simplification**, inherited from that module: a template edit is picked up by the next
//! reconcile pass that reads it (the watch keeps the cache fresh), but nothing here *triggers* a
//! re-reconcile of every namespace using it — that trigger belongs to the controller's watch
//! wiring, not this cache.

use kube::Client;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use serde_json::Value;
use weebo_si_crd::{RuntimeBackend, TemplateRef};
use weebo_si_kubearmor_policy::{RuleBody, TemplateStore};

/// The API group `KubeArmorPolicy` lives in — present only when KubeArmor's CRDs are installed.
pub const KUBEARMOR_GROUP: &str = "security.kubearmor.com";

/// The `KubeArmorPolicy` GVK. A CRD KubeArmor installs, not a builtin, so it is watched as a
/// [`DynamicObject`] via a hand-built [`ApiResource`] — the same pattern `dwoc_store` uses for
/// `DevWorkspaceOperatorConfig` and `kube_template_store` for `CiliumNetworkPolicy`.
pub fn kubearmor_policy_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk(KUBEARMOR_GROUP, "v1", "KubeArmorPolicy");
    ApiResource::from_gvk_with_plural(&gvk, "kubearmorpolicies")
}

/// The field a `KubeArmorPolicy` carries its pod-selecting labels under, and the one field this
/// adapter strips from a template before handing its rules on as an opaque body.
///
/// A template's own `selector` is ignored for the reason RFC 0004 gives for `podSelector` and
/// RFC 0006 restates: "it copies `spec.process`, `spec.file`, `spec.network`,
/// `spec.capabilities` and `spec.syscalls` verbatim into a per-workspace copy whose
/// `selector.matchLabels` is rewritten." Scoping belongs to the operator; an admin who writes a
/// selector into a template is writing a field that never reaches a cluster.
pub const SELECTOR_FIELD: &str = "selector";

/// Watch-backed `KubeArmorPolicy` template cache, scoped to one namespace.
pub struct KubeArmorTemplateStore {
    templates: Store<DynamicObject>,
}

impl KubeArmorTemplateStore {
    /// Start watching `KubeArmorPolicy` templates in `namespace`. Blocks until the initial list
    /// completes.
    ///
    /// Unlike [`crate::KubeTemplateStore`], there is no "enabled" flag: this store is only ever
    /// constructed on a cluster where [`crate::KubeArmorCapabilities`] already reported the CRD
    /// present, since starting the watch without it fails the initial list.
    pub async fn spawn(client: Client, namespace: &str) -> Result<Self, kube::Error> {
        let resource = kubearmor_policy_resource();
        let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &resource);
        let writer = reflector::store::Writer::<DynamicObject>::new(resource);
        let reader = writer.as_reader();
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

        Ok(Self { templates: reader })
    }
}

impl TemplateStore for KubeArmorTemplateStore {
    fn body(&self, backend: RuntimeBackend, template_ref: &TemplateRef) -> Option<RuleBody> {
        match backend {
            RuntimeBackend::KubeArmor => {}
        }

        let obj = self.templates.state().into_iter().find(|obj| {
            obj.metadata.name.as_deref() == Some(template_ref.name.as_str())
                && obj.metadata.namespace.as_deref() == Some(template_ref.namespace.as_str())
        })?;
        let mut spec = obj.data.get("spec")?.clone();
        if let Value::Object(map) = &mut spec {
            map.remove(SELECTOR_FIELD);
        }
        serde_json::to_vec(&spec).ok().map(RuleBody::opaque)
    }
}
