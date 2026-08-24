//! Watch-backed `Namespace` cache, implementing `NamespaceView`.
//!
//! The only cache scaling with the cluster, per RFC 0002's *Data and state* — stored as the
//! bounded [`NamespaceFacts`] projection (labels and one annotation), not the full `Namespace`
//! object, so a cluster with thousands of namespaces costs kilobytes rather than the full
//! objects.
//!
//! The selection annotation key is read fresh on every [`NamespaceView::facts`] call from a
//! shared handle — [`crate::KubeConfigStore`] writes it on every `WeeboSiConfig` sync — so
//! `namespaceSelection.annotation` is hot-reloaded exactly like every other part of the config.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use k8s_openapi::api::core::v1::Namespace;
use kube::runtime::reflector::{self, Store};
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

        Ok(Self {
            store: reader,
            annotation_key,
        })
    }
}

impl NamespaceView for KubeNsStore {
    fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts> {
        let annotation_key = self
            .annotation_key
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.store
            .state()
            .into_iter()
            .find(|namespace| namespace.metadata.name.as_deref() == Some(ns.as_str()))
            .map(|namespace| {
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
}
