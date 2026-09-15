//! Self-origin: is this caller the workspace itself? — RFC 0009's *Self-origin: two ways a
//! workspace proves it is itself*.
//!
//! Two mechanisms behind one port. The pod index answers from a watch, synchronously, on the
//! request path. The `TokenReview` cannot: it is an API call, and the request path may not make
//! one. So the review happens in the *inbound adapter*, before the decision, and only on a cache
//! miss — the sync port then reads what it left behind. That keeps RFC 0009's "no I/O on the
//! request path" true in the only way that is honest: the I/O is not hidden inside the decision,
//! it is visible in the handler, and it happens once per token rather than once per request.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use futures_util::StreamExt;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use k8s_openapi::api::core::v1::Pod;
use kube::api::PostParams;
use kube::runtime::reflector::{self, Store};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};
use weebo_si_crd::DEVWORKSPACE_ID_LABEL;
use weebo_si_endpoint_auth::cache::{CacheKind, Fingerprint, IdentityCache};
use weebo_si_endpoint_auth::host::ClientAddress;
use weebo_si_endpoint_auth::identity::NamespaceName;
use weebo_si_endpoint_auth::port::{ServiceAccountIdentity, WorkloadIdentity};
use weebo_si_endpoint_auth::time::Timestamp;

/// Pod addresses and service-account tokens, both resolved to a namespace.
pub struct KubeWorkloadIdentity {
    pods: Store<Pod>,
    addresses: Arc<RwLock<HashMap<String, String>>>,
    reviews: IdentityCache<NamespaceName>,
    client: Client,
    /// Whether the pod-address mechanism is trusted at all — `Off` where the cluster SNATs, or
    /// where the probe watched a forged address come back.
    trust_addresses: Arc<std::sync::atomic::AtomicBool>,
    /// Whether a workspace service-account token is accepted.
    accept_service_account_tokens: bool,
}

impl KubeWorkloadIdentity {
    /// Start the pod watch, restricted to DevWorkspace-labelled pods.
    ///
    /// The label selector is the security boundary, not an optimisation: an index over *every*
    /// pod would resolve the address of any pod in the cluster to its namespace, and "a pod of
    /// some namespace" is not the same claim as "a pod of the workspace whose endpoint this is".
    pub async fn spawn(
        client: Client,
        trust_addresses: bool,
        accept_service_account_tokens: bool,
        cache_entries: usize,
    ) -> Result<Arc<Self>, kube::Error> {
        let api: Api<Pod> = Api::all(client.clone());
        let config = watcher::Config::default().labels(DEVWORKSPACE_ID_LABEL);
        let (store, writer) = reflector::store();
        let addresses: Arc<RwLock<HashMap<String, String>>> = Arc::default();

        let index = Arc::clone(&addresses);
        let reader = store.clone();
        tokio::spawn(async move {
            let stream = reflector::reflector(writer, watcher(api, config)).default_backoff();
            let mut stream = std::pin::pin!(stream);
            while stream.next().await.is_some() {
                let mut rebuilt = HashMap::new();
                for pod in reader.state() {
                    let Some(namespace) = pod.namespace() else {
                        continue;
                    };
                    let status = pod.status.as_ref();
                    for ip in status
                        .and_then(|status| status.pod_ips.clone())
                        .unwrap_or_default()
                        .into_iter()
                        .map(|ip| ip.ip)
                        .chain(status.and_then(|status| status.pod_ip.clone()))
                    {
                        rebuilt.insert(ip, namespace.clone());
                    }
                }
                if let Ok(mut current) = index.write() {
                    *current = rebuilt;
                }
            }
        });

        store.wait_until_ready().await.map_err(|err| {
            kube::Error::Discovery(kube::error::DiscoveryError::MissingResource(
                err.to_string(),
            ))
        })?;

        Ok(Arc::new(Self {
            pods: store,
            addresses,
            reviews: IdentityCache::new(CacheKind::TokenReview, cache_entries, 3_600),
            client,
            trust_addresses: Arc::new(std::sync::atomic::AtomicBool::new(trust_addresses)),
            accept_service_account_tokens,
        }))
    }

    /// Turn the pod-address mechanism off at runtime — what the self-origin probe does when it
    /// watches a forged address come back, per RFC 0009's *Checking that assumption rather than
    /// configuring it*. The probe can only ever revoke: it never turns the mechanism on.
    pub fn revoke_address_trust(&self) {
        self.trust_addresses
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the pod-address mechanism is currently trusted —
    /// `weebo_si_endpoint_auth_client_ip_trusted`.
    pub fn addresses_trusted(&self) -> bool {
        self.trust_addresses
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many workspace pods are indexed.
    pub fn indexed_pods(&self) -> usize {
        self.pods.state().len()
    }

    /// Resolve a service-account token through the apiserver, and remember the answer until the
    /// token's own expiry. Called from the inbound adapter *before* the decision, never inside
    /// it.
    pub async fn review(&self, token: &str, now: Timestamp) -> Option<ServiceAccountIdentity> {
        if !self.accept_service_account_tokens {
            return None;
        }
        let key = Fingerprint::of(token);
        if let Some(namespace) = self.reviews.get(&key, now) {
            return Some(ServiceAccountIdentity {
                namespace,
                expires_at: now.plus_secs(3_600),
            });
        }
        let api: Api<TokenReview> = Api::all(self.client.clone());
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: Some(token.to_owned()),
                audiences: None,
            },
            ..TokenReview::default()
        };
        let reviewed = api.create(&PostParams::default(), &review).await.ok()?;
        let status = reviewed.status?;
        if !status.authenticated.unwrap_or(false) {
            return None;
        }
        // `system:serviceaccount:<namespace>:<name>` — the only username shape this accepts. A
        // *person's* token reviewed here would otherwise resolve to whatever its username parsed
        // to, which is not a namespace and must never be treated as one.
        let username = status.user?.username?;
        let namespace = username
            .strip_prefix("system:serviceaccount:")?
            .split(':')
            .next()?;
        let namespace = NamespaceName::new(namespace);
        // Bounded by the cache's own TTL rather than by the token's `exp`, which a TokenReview
        // does not report: an hour of "this token belongs to this namespace" is the same claim
        // the apiserver just made, and the token is re-reviewed after it.
        let expires_at = now.plus_secs(3_600);
        self.reviews.insert(key, namespace.clone(), expires_at, now);
        Some(ServiceAccountIdentity {
            namespace,
            expires_at,
        })
    }

    /// Whether this token looks like a Kubernetes service-account token at all — what the
    /// handler asks before spending an API call on it.
    pub fn looks_like_service_account_token(token: &str) -> bool {
        // Three dot-separated segments, and a payload naming the Kubernetes service-account
        // claim. A cheap shape check, not a verification: the apiserver does the verifying, and
        // this only decides whether asking it is worth a round trip.
        let mut parts = token.split('.');
        let (_, Some(payload), Some(_), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .is_some_and(|claims| claims.contains("kubernetes.io"))
    }
}

impl WorkloadIdentity for KubeWorkloadIdentity {
    fn namespace_of_address(&self, address: &ClientAddress) -> Option<NamespaceName> {
        if !self.addresses_trusted() {
            return None;
        }
        self.addresses
            .read()
            .ok()?
            .get(address.as_str())
            .map(NamespaceName::new)
    }

    fn namespace_of_service_account(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Option<ServiceAccountIdentity> {
        let namespace = self.reviews.get(&Fingerprint::of(token), now)?;
        Some(ServiceAccountIdentity {
            namespace,
            expires_at: now.plus_secs(3_600),
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
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    #[test]
    fn only_something_shaped_like_a_service_account_token_is_worth_an_api_call() {
        let payload = B64.encode(br#"{"kubernetes.io":{"namespace":"user-alice"}}"#);
        let token = format!("header.{payload}.signature");
        assert!(KubeWorkloadIdentity::looks_like_service_account_token(
            &token
        ));

        let other = B64.encode(br#"{"iss":"https://sso.weebo.si","sub":"alice"}"#);
        assert!(!KubeWorkloadIdentity::looks_like_service_account_token(
            &format!("header.{other}.signature")
        ));
        assert!(!KubeWorkloadIdentity::looks_like_service_account_token(
            "not-a-jwt"
        ));
    }
}
