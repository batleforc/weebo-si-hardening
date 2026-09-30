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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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

/// The annotation on the revocation `ConfigMap` that records "a replica's self-origin probe saw
/// a forged client address come back". Its presence turns pod-address identity off on every
/// replica; an admin removes it once the ingress controller is fixed.
pub const ADDRESS_FORGERY_ANNOTATION: &str = "endpoint-auth.weebo.si/address-forgery-seen";

/// The most revoked sessions the `ConfigMap` holds. A `ConfigMap` is capped at 1 MiB and an
/// entry is well under a hundred bytes, so this is far inside it — and a set this large means
/// something other than people signing out is happening, which is worth being loud about.
pub const MAX_REVOCATIONS: usize = 10_000;

/// Why a revocation was not recorded.
#[derive(Debug)]
pub enum RevokeError {
    /// The set is at [`MAX_REVOCATIONS`] live entries even after pruning the expired ones.
    Full,
    /// The apiserver refused the write.
    Kube(kube::Error),
}

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(
                f,
                "the revocation set is full ({MAX_REVOCATIONS} live sessions); refusing to drop \
                 one silently"
            ),
            Self::Kube(err) => write!(f, "{err}"),
        }
    }
}

/// Watch-backed revocation set, plus the one write verb this gateway holds.
pub struct KubeRevocations {
    revoked: Arc<RwLock<BTreeMap<String, u64>>>,
    address_forgery: Arc<AtomicBool>,
    /// When this replica saw a forgery the `ConfigMap` does not show yet, in seconds; `0` for
    /// none. Held until the watch shows the annotation, so neither an unrelated event nor a failed
    /// patch can clear the flag in between — see [`Self::record_address_forgery`].
    forgery_pending: Arc<AtomicU64>,
    client: Client,
    namespace: String,
    name: String,
}

/// The `data` merge patch that records `session` until `until`: every entry already expired at
/// `now` is pruned in the same write, and a set still at `cap` live entries is refused rather
/// than grown past what a `ConfigMap` holds or trimmed by dropping somebody's revocation.
pub fn plan_revocation(
    current: &BTreeMap<String, u64>,
    session: &str,
    until: Timestamp,
    now: Timestamp,
    cap: usize,
) -> Result<serde_json::Map<String, serde_json::Value>, RevokeError> {
    let mut data = serde_json::Map::new();
    let mut live = 0_usize;
    for (sid, expiry) in current {
        if now.is_at_or_after(Timestamp::from_secs(*expiry)) {
            data.insert(sid.clone(), serde_json::Value::Null);
        } else if sid != session {
            live += 1;
        }
    }
    if live >= cap {
        return Err(RevokeError::Full);
    }
    data.insert(
        session.to_owned(),
        serde_json::Value::String(until.as_secs().to_string()),
    );
    Ok(data)
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
        address_forgery: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, kube::Error> {
        let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
        let config = watcher::Config::default().fields(&format!("metadata.name={name}"));
        let (store, writer) = reflector::store();
        let revoked: Arc<RwLock<BTreeMap<String, u64>>> = Arc::default();

        let index = Arc::clone(&revoked);
        let forgery = Arc::clone(&address_forgery);
        let forgery_pending: Arc<AtomicU64> = Arc::default();
        let pending = Arc::clone(&forgery_pending);
        let reader: Store<ConfigMap> = store.clone();
        tokio::spawn(async move {
            let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
            let mut stream = std::pin::pin!(stream);
            while stream.next().await.is_some() {
                let mut rebuilt = BTreeMap::new();
                let seen = reader.state().iter().any(|map| {
                    map.metadata
                        .annotations
                        .as_ref()
                        .is_some_and(|annotations| {
                            annotations.contains_key(ADDRESS_FORGERY_ANNOTATION)
                        })
                });
                if seen {
                    if !forgery.swap(true, Ordering::SeqCst) {
                        eprintln!(
                            "WARN endpoint-gateway: a self-origin probe recorded a forged client \
                             address ({ADDRESS_FORGERY_ANNOTATION}); pod-address identity is OFF \
                             on every replica until an admin removes that annotation"
                        );
                    }
                    // The annotation now carries it, and its removal by an admin is what clears
                    // it on every replica, this one included.
                    pending.store(0, Ordering::SeqCst);
                } else {
                    forgery.store(false, Ordering::SeqCst);
                    // A forgery recorded here but not visible yet must survive this event: an
                    // unrelated revocation, a relist, or a patch that never landed.
                    if pending.load(Ordering::SeqCst) != 0 {
                        forgery.store(true, Ordering::SeqCst);
                    }
                }
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
            address_forgery,
            forgery_pending,
            client,
            namespace,
            name,
        }))
    }

    /// Record a revocation, so every replica sees it within informer lag.
    ///
    /// A **merge** patch, not server-side apply: every replica applies as the same field manager,
    /// and an apply that names only one key tells the apiserver the manager no longer wants the
    /// keys it applied before — so each revocation silently dropped the previous one. Expired
    /// entries are pruned in the same write, and a set still at [`MAX_REVOCATIONS`] is an error
    /// the caller makes loud rather than an entry quietly lost.
    pub async fn revoke(
        &self,
        session: &str,
        until: Timestamp,
        now: Timestamp,
    ) -> Result<(), RevokeError> {
        let data = {
            let current = self
                .revoked
                .read()
                .map(|revoked| revoked.clone())
                .unwrap_or_default();
            plan_revocation(&current, session, until, now, MAX_REVOCATIONS)?
        };
        self.merge_or_create(json!({ "data": data }))
            .await
            .map_err(RevokeError::Kube)
    }

    /// Record, for every replica, that a self-origin probe watched a forged client address come
    /// back. Sets the shared flag locally at once rather than waiting for the watch, and keeps it
    /// set until the watch shows the annotation: a patch that fails leaves this replica off
    /// rather than letting the next watch event turn it back on, and
    /// [`Self::retry_address_forgery`] keeps trying until the annotation lands — where an admin
    /// can see it and remove it, the one way it is cleared.
    pub async fn record_address_forgery(&self, now: Timestamp) -> Result<(), kube::Error> {
        // The first sighting's time, not the latest retry's.
        let _ = self.forgery_pending.compare_exchange(
            0,
            now.as_secs().max(1),
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        self.address_forgery.store(true, Ordering::SeqCst);
        self.patch_address_forgery().await
    }

    /// Whether this replica saw a forgery the `ConfigMap` does not show yet.
    pub fn address_forgery_unrecorded(&self) -> bool {
        self.forgery_pending.load(Ordering::SeqCst) != 0
    }

    /// Try again to record a forgery an earlier patch failed to — called on every probe,
    /// whatever it found, so a controller fixed since does not strand this replica with a
    /// finding nobody else can see or clear. `Ok(false)` when there was nothing to retry.
    pub async fn retry_address_forgery(&self) -> Result<bool, kube::Error> {
        if !self.address_forgery_unrecorded() {
            return Ok(false);
        }
        self.patch_address_forgery().await.map(|()| true)
    }

    async fn patch_address_forgery(&self) -> Result<(), kube::Error> {
        let at = self.forgery_pending.load(Ordering::SeqCst);
        self.merge_or_create(json!({
            "metadata": { "annotations": {
                ADDRESS_FORGERY_ANNOTATION: at.to_string()
            } }
        }))
        .await
    }

    /// Whether any replica has recorded a forged client address.
    pub fn address_forgery_recorded(&self) -> bool {
        self.address_forgery.load(Ordering::Relaxed)
    }

    /// Merge `patch` into the `ConfigMap`, creating it first on a fresh install.
    async fn merge_or_create(&self, patch: serde_json::Value) -> Result<(), kube::Error> {
        let api: Api<ConfigMap> = Api::namespaced(self.client.clone(), &self.namespace);
        match api
            .patch(&self.name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(status)) if status.code == 404 => {
                let mut created = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": { "name": self.name, "namespace": self.namespace },
                });
                if let (Some(created), Some(patch)) = (created.as_object_mut(), patch.as_object()) {
                    for (key, value) in patch {
                        if key == "metadata" {
                            if let (Some(meta), Some(extra)) = (
                                created.get_mut("metadata").and_then(|m| m.as_object_mut()),
                                value.as_object(),
                            ) {
                                meta.extend(extra.clone());
                            }
                        } else {
                            created.insert(key.clone(), value.clone());
                        }
                    }
                }
                let map: ConfigMap =
                    serde_json::from_value(created).map_err(kube::Error::SerdeError)?;
                match api.create(&kube::api::PostParams::default(), &map).await {
                    Ok(_) => Ok(()),
                    // Another replica created it between the two calls: patch the one it made.
                    Err(kube::Error::Api(status)) if status.code == 409 => api
                        .patch(&self.name, &PatchParams::default(), &Patch::Merge(&patch))
                        .await
                        .map(|_| ()),
                    Err(err) => Err(err),
                }
            }
            Err(err) => Err(err),
        }
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn set(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
        entries
            .iter()
            .map(|(sid, until)| ((*sid).to_owned(), *until))
            .collect()
    }

    /// Second-pass finding 10: the revocation `ConfigMap` grew without bound between hourly
    /// sweeps. Every write now prunes what has expired, and a set still full is refused loudly.
    #[test]
    fn a_revocation_prunes_the_expired_and_refuses_to_overflow() {
        let now = Timestamp::from_secs(1_000);
        let current = set(&[("old-1", 500), ("old-2", 1_000), ("live", 5_000)]);
        let data = plan_revocation(&current, "new", now.plus_secs(60), now, 10).unwrap();
        assert_eq!(data.get("old-1"), Some(&serde_json::Value::Null));
        assert_eq!(data.get("old-2"), Some(&serde_json::Value::Null));
        assert!(!data.contains_key("live"), "a live entry is left alone");
        assert_eq!(data.get("new"), Some(&serde_json::json!("1060")));

        // Full of live entries: refused, not trimmed.
        let full = set(&[("a", 5_000), ("b", 5_000)]);
        assert!(matches!(
            plan_revocation(&full, "c", now.plus_secs(60), now, 2),
            Err(RevokeError::Full)
        ));
        // Re-revoking a session already in the set is not growth.
        assert!(plan_revocation(&full, "a", now.plus_secs(60), now, 2).is_ok());
        // Full only until something expires.
        let expiring = set(&[("a", 900), ("b", 5_000)]);
        assert!(plan_revocation(&expiring, "c", now.plus_secs(60), now, 2).is_ok());
    }
}
