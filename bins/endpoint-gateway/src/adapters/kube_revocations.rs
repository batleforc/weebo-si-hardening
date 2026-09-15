//! The revocation set — RFC 0009's *Revocation, and the hour a stateless session would otherwise
//! owe you*.
//!
//! The one piece of state this gateway is not stateless about, and the reason is stated rather
//! than worked around: a revocation has to mean the same thing on every replica, and a set each
//! replica keeps its own copy of means a logged-out session keeps working on two replicas out of
//! three. So it lives in a `ConfigMap` the apiserver holds and every replica watches — the same
//! informer machinery already here, one extra watch, and no new stateful dependency for a
//! component whose failure closes the cluster's endpoints.
//!
//! **Bounded by `sso_ttl`.** A revoked session id is worth remembering exactly as long as the
//! session could still be presented; the sweep drops the rest, which is what keeps a `ConfigMap`
//! an appropriate home for it.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Patch, PatchParams};
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client};
use serde_json::json;
use weebo_si_endpoint_auth::identity::SessionId;
use weebo_si_endpoint_auth::port::RevocationStore;
use weebo_si_endpoint_auth::time::Timestamp;

/// Watch-backed revocation set, plus the one write verb this gateway holds.
pub struct KubeRevocations {
    revoked: Arc<RwLock<BTreeMap<String, u64>>>,
    client: Client,
    namespace: String,
    name: String,
}

impl KubeRevocations {
    /// Start watching the revocation `ConfigMap`.
    ///
    /// A missing object is not an error: back-channel logout may never have fired, and a gateway
    /// that refused to start without it would turn "nobody has logged out yet" into an outage.
    pub async fn spawn(
        client: Client,
        namespace: String,
        name: String,
    ) -> Result<Arc<Self>, kube::Error> {
        let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
        let config = watcher::Config::default().fields(&format!("metadata.name={name}"));
        let (store, writer) = reflector::store();
        let revoked: Arc<RwLock<BTreeMap<String, u64>>> = Arc::default();

        let index = Arc::clone(&revoked);
        let reader: Store<ConfigMap> = store.clone();
        tokio::spawn(async move {
            let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
            let mut stream = std::pin::pin!(stream);
            while stream.next().await.is_some() {
                let mut rebuilt = BTreeMap::new();
                for map in reader.state() {
                    for (sid, expiry) in map.data.clone().unwrap_or_default() {
                        if let Ok(expiry) = expiry.trim().parse::<u64>() {
                            rebuilt.insert(sid, expiry);
                        }
                    }
                }
                if let Ok(mut current) = index.write() {
                    *current = rebuilt;
                }
            }
        });

        Ok(Arc::new(Self {
            revoked,
            client,
            namespace,
            name,
        }))
    }

    /// Record a revocation, so every replica sees it within informer lag.
    pub async fn revoke(&self, session: &str, until: Timestamp) -> Result<(), kube::Error> {
        let api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &self.namespace);
        let patch = json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": self.name },
            "data": { session: until.as_secs().to_string() }
        });
        api.patch(
            &self.name,
            &PatchParams::apply("endpoint-gateway").force(),
            &Patch::Apply(&patch),
        )
        .await
        .map(|_| ())
    }

    /// Drop every entry whose session could no longer be presented anyway.
    pub async fn sweep(&self, now: Timestamp) -> Result<usize, kube::Error> {
        let expired: Vec<String> = self
            .revoked
            .read()
            .map(|revoked| {
                revoked
                    .iter()
                    .filter(|(_, until)| now.is_at_or_after(Timestamp::from_secs(**until)))
                    .map(|(sid, _)| sid.clone())
                    .collect()
            })
            .unwrap_or_default();
        if expired.is_empty() {
            return Ok(0);
        }
        let api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &self.namespace);
        let data: serde_json::Map<String, serde_json::Value> = expired
            .iter()
            .map(|sid| (sid.clone(), serde_json::Value::Null))
            .collect();
        api.patch(
            &self.name,
            &PatchParams::default(),
            &Patch::Merge(json!({ "data": data })),
        )
        .await?;
        Ok(expired.len())
    }

    /// Run [`Self::sweep`] forever, hourly.
    pub async fn sweep_forever(self: Arc<Self>, clock: impl Fn() -> Timestamp + Send + 'static) {
        let mut interval = tokio::time::interval(Duration::from_secs(3_600));
        loop {
            interval.tick().await;
            match self.sweep(clock()).await {
                Ok(0) => {}
                Ok(count) => println!("endpoint-gateway: swept {count} expired revocations"),
                Err(err) => eprintln!("WARN endpoint-gateway: revocation sweep failed: {err}"),
            }
        }
    }

    /// How many sessions are currently revoked — `weebo_si_endpoint_auth_revocations`.
    pub fn len(&self) -> usize {
        self.revoked
            .read()
            .map(|revoked| revoked.len())
            .unwrap_or(0)
    }
}

impl RevocationStore for KubeRevocations {
    fn is_revoked(&self, session: &SessionId) -> bool {
        self.revoked
            .read()
            .map(|revoked| revoked.contains_key(session.as_str()))
            .unwrap_or(false)
    }
}
