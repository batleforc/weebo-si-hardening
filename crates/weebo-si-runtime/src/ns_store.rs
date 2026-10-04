//! Watch-backed `Namespace` cache, implementing `NamespaceView`.
//!
//! The only cache scaling with the cluster, per RFC 0002's *Data and state* — stored as a
//! projection (metadata without `managedFields`, no `spec` or `status`) rather than the full
//! `Namespace` object, and read back into the bounded [`NamespaceFacts`] by a keyed lookup, so
//! neither the memory nor the per-request cost grows with more than the namespaces' own labels
//! and annotations.
//!
//! The selection annotation key is read fresh on every [`NamespaceView::facts`] call from a
//! shared handle — [`crate::KubeConfigStore`] writes it on every `WeeboSiConfig` sync — so
//! `namespaceSelection.annotation` is hot-reloaded exactly like every other part of the config.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use weebo_si_chassis::NamespaceFacts;
use weebo_si_chassis::port::namespace_view::NamespaceView;
use weebo_si_crd::NamespaceName;

/// Watch-backed `Namespace` cache.
pub struct KubeNsStore {
    store: Store<Namespace>,
    annotation_key: Arc<RwLock<String>>,
}

impl KubeNsStore {
    /// Start watching every `Namespace`, projecting the current value of `*annotation_key` into
    /// [`NamespaceFacts::selection_annotation`] on every read. Blocks until the initial list
    /// completes. `annotation_key` is shared with [`crate::KubeConfigStore`], which keeps it
    /// current.
    pub async fn spawn(
        client: Client,
        annotation_key: Arc<RwLock<String>>,
    ) -> Result<Self, kube::Error> {
        let api: Api<Namespace> = Api::all(client);
        let (reader, writer) = reflector::store();
        // Projected in the stream, before anything reaches the cache: labels and annotations are
        // all either read needs, and `managedFields` alone is usually most of an object's bytes.
        let stream = reflector::reflector(
            writer,
            watcher(api, watcher::Config::default()).modify(|namespace| {
                namespace.metadata.managed_fields = None;
                namespace.spec = None;
                namespace.status = None;
            }),
        )
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

        Ok(Self {
            store: reader,
            annotation_key,
        })
    }
}

impl KubeNsStore {
    /// One namespace by name — a keyed lookup in the reflector's map, where `state()` would clone
    /// every namespace in the cluster on each admission request just to find one.
    fn lookup(&self, ns: &NamespaceName) -> Option<Arc<Namespace>> {
        self.store.get(&ObjectRef::new(ns.as_str()))
    }
}

impl NamespaceView for KubeNsStore {
    fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts> {
        let annotation_key = self
            .annotation_key
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.lookup(ns).map(|namespace| {
            let labels: BTreeMap<String, String> = namespace
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            let selection_annotation = namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(annotation_key.as_str()))
                .filter(|value| !annotation_key.is_empty() && !value.is_empty())
                .cloned();
            NamespaceFacts {
                labels,
                selection_annotation,
            }
        })
    }

    fn annotation(&self, ns: &NamespaceName, key: &str) -> Option<String> {
        if key.is_empty() {
            return None;
        }
        self.lookup(ns).and_then(|namespace| {
            namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(key))
                .filter(|value| !value.is_empty())
                .cloned()
        })
    }

    fn annotated_anywhere(&self, key: &str, value: &str) -> bool {
        if key.is_empty() || value.is_empty() {
            return false;
        }
        self.store.state().iter().any(|namespace| {
            namespace
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(key))
                .is_some_and(|found| found.eq_ignore_ascii_case(value))
        })
    }
}
