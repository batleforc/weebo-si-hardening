//! Watch-backed `DevWorkspaceOperatorConfig` cache, implementing `DwocCatalog`.
//!
//! DevWorkspace Operator owns this CRD, not us — there is no upstream Rust type for it, so this
//! adapter watches it as [`kube::api::DynamicObject`] via a hand-built [`ApiResource`] and only
//! ever asks "does this `{name, namespace}` exist," per RFC 0002's *Security considerations*: an
//! entry is checked for existence and nothing more, never dereferenced into its contents.

use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use weebo_si_chassis::port::dwoc_catalog::DwocCatalog;
use weebo_si_crd::DwocRef;

/// The `DevWorkspaceOperatorConfig` GVK, per RFC 0002's *Motivation*.
pub fn devworkspace_operator_config_resource() -> ApiResource {
    let gvk = GroupVersionKind::gvk(
        "controller.devfile.io",
        "v1alpha1",
        "DevWorkspaceOperatorConfig",
    );
    ApiResource::from_gvk_with_plural(&gvk, "devworkspaceoperatorconfigs")
}

/// Watch-backed `DevWorkspaceOperatorConfig` cache.
pub struct KubeDwocStore {
    store: Store<DynamicObject>,
}

impl KubeDwocStore {
    /// Start watching every `DevWorkspaceOperatorConfig`, cluster-wide. Blocks until the initial
    /// list completes.
    pub async fn spawn(client: Client) -> Result<Self, kube::Error> {
        let resource = devworkspace_operator_config_resource();
        let api: Api<DynamicObject> = Api::all_with(client, &resource);
        // `DynamicObject`'s dynamic type (`ApiResource`) has no `Default`, so the parameterless
        // `reflector::store()` doesn't fit — build the writer with the GVK explicitly instead.
        let writer = reflector::store::Writer::<DynamicObject>::new(resource.clone());
        let reader = writer.as_reader();
        let watcher_config = watcher::Config::default();
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

        Ok(Self { store: reader })
    }
}

impl DwocCatalog for KubeDwocStore {
    fn resolves(&self, r: &DwocRef) -> bool {
        self.store.state().into_iter().any(|dwoc| {
            dwoc.metadata.name.as_deref() == Some(r.name.as_str())
                && dwoc.metadata.namespace.as_deref() == Some(r.namespace.as_str())
        })
    }
}
