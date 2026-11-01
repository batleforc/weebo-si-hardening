//! The `resource-quotas` feature's adapters (RFC 0014): its template and managed-object stores,
//! its metrics and its reconcile loop, next to the composition function `weebo-si-operator` calls.

pub mod controller;
pub mod quota_metrics;
pub mod quota_stores;

pub use controller::ResourceQuotasDeps;
pub use quota_metrics::ResourceQuotasMetrics;
pub use quota_stores::{KubeManagedQuotaStore, KubeQuotaTemplateStore};

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use kube::Resource;
use kube::runtime::reflector::Store;
use weebo_si_controller::ControllerShared;
use weebo_si_crd::NamespaceName;
use weebo_si_resource_quotas::ResourceQuotasFeature;

/// The template namespace when `--quota-template-namespace` is not given: what the chart creates.
pub const DEFAULT_TEMPLATE_NAMESPACE: &str = "weebo-si-hardening-templates";

/// A fingerprint of a cache's objects: name, labels and `spec`, never `status`. A quota's
/// `status.used` moves with every pod, and re-reconciling the fleet on each would be pointless.
fn fingerprint<K>(store: Store<K>, spec: fn(&K) -> String) -> controller::Fingerprint
where
    K: Resource<DynamicType = ()> + Clone + Send + Sync + 'static,
{
    Arc::new(move || {
        let mut entries: Vec<String> = store
            .state()
            .iter()
            .map(|object| {
                let meta = object.meta();
                format!(
                    "{}/{}|{:?}|{}",
                    meta.namespace.as_deref().unwrap_or_default(),
                    meta.name.as_deref().unwrap_or_default(),
                    meta.labels,
                    spec(object)
                )
            })
            .collect();
        entries.sort();
        let mut hasher = DefaultHasher::new();
        entries.hash(&mut hasher);
        hasher.finish()
    })
}

/// Start this feature's watches and assemble what its loop needs — `None` when this role may not
/// watch and write `resourcequotas` and `limitranges` (`resourceQuotas.rbac.enabled` off).
pub async fn controller_deps(
    shared: &ControllerShared,
) -> Result<Option<ResourceQuotasDeps>, String> {
    let client = &shared.client;
    let allowed = async {
        Ok::<bool, kube::Error>(
            weebo_si_runtime::access::can_watch(client, "", "resourcequotas", None).await?
                && weebo_si_runtime::access::can_watch(client, "", "limitranges", None).await?
                && weebo_si_runtime::access::can_patch(client, "", "resourcequotas", None).await?
                && weebo_si_runtime::access::can_patch(client, "", "limitranges", None).await?,
        )
    }
    .await
    .map_err(|err| format!("could not ask whether resource-quotas may run: {err}"))?;
    if !allowed {
        tracing::info!(
            "resource-quotas is inert — this ServiceAccount may not watch and patch \
             resourcequotas and limitranges (set resourceQuotas.rbac.enabled in the chart)"
        );
        return Ok(None);
    }

    let template_namespace = NamespaceName::new(shared.quota_template_namespace.clone());
    let templates = Arc::new(
        KubeQuotaTemplateStore::spawn(client.clone(), &template_namespace)
            .await
            .map_err(|err| format!("could not start the quota template watch: {err}"))?,
    );
    let store = Arc::new(
        KubeManagedQuotaStore::spawn(client.clone())
            .await
            .map_err(|err| format!("could not start the managed quota watch: {err}"))?,
    );
    let metrics = Arc::new(
        ResourceQuotasMetrics::register(&shared.prometheus).map_err(|err| err.to_string())?,
    );
    let (template_quotas, template_limits) = templates.stores();
    let (managed_quotas, managed_limits) = store.stores();
    let fingerprints = vec![
        fingerprint(template_quotas, |object| format!("{:?}", object.spec)),
        fingerprint(template_limits, |object| format!("{:?}", object.spec)),
        fingerprint(managed_quotas, |object| format!("{:?}", object.spec)),
        fingerprint(managed_limits, |object| format!("{:?}", object.spec)),
    ];
    let config = shared.config_store.resource_quotas_config();
    Ok(Some(ResourceQuotasDeps {
        feature: Arc::new(ResourceQuotasFeature::new(
            Arc::clone(&config),
            templates,
            template_namespace,
        )),
        config,
        gate: shared.config_store.clone(),
        namespace_view: Arc::clone(&shared.ns_store) as _,
        dwoc_catalog: Arc::clone(&shared.dwoc_store) as _,
        store: store as _,
        observer: metrics as _,
        operator_namespace: NamespaceName::new(shared.operator_namespace.clone()),
        fingerprints,
    }))
}
