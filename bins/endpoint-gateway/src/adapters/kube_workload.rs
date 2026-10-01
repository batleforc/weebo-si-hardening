//! Self-origin: is this caller the workspace itself? — RFC 0009's *Self-origin: two ways a
//! workspace proves it is itself*.
//!
//! Two mechanisms behind one port. The pod index answers from a watch, synchronously, on the
//! request path. The `TokenReview` cannot: it is an API call, and the request path may not make
//! one. So the review happens in the *inbound adapter*, before the decision, and only on a cache
//! miss — the sync port then reads what it left behind. That keeps RFC 0009's "no I/O on the
//! request path" true in the only way that is honest: the I/O is not hidden inside the decision,
//! it is visible in the handler, and it happens once per token rather than once per request.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

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

use jsonwebtoken::jwk::JwkSet;

use crate::adapters::oidc::{JWKS_RETRY_INITIAL, JWKS_RETRY_MAX, JwksCache, KeyLookup};
use crate::ratelimit::{Rate, RateLimiter};

/// Where the kubelet mounts this pod's own service-account token — read once at boot for its
/// (unverified) `iss`, which is the cluster's service-account issuer.
const OWN_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
/// The issuer legacy, secret-based service-account tokens carry.
const LEGACY_ISSUER: &str = "kubernetes/serviceaccount";

/// Pod addresses and service-account tokens, both resolved to a namespace.
pub struct KubeWorkloadIdentity {
    pods: Store<Pod>,
    addresses: Arc<RwLock<HashMap<String, String>>>,
    reviewer: TokenReviewer,
    /// This cluster's service-account issuer, where it could be read at boot.
    cluster_issuer: Option<String>,
    /// Whether the pod-address mechanism is trusted at all.
    trust: AddressTrust,
}

/// Whether a client address may currently be used as an identity — this replica's own view,
/// and the one every replica shares.
///
/// Second-pass finding 2 changed the starting point: under `Auto` the mechanism used to start
/// **trusted** and only a probe that watched a forgery come back turned it off — on that replica
/// alone, while the others kept believing the header. Now:
///
/// * `Auto` starts **untrusted**, and only a *conclusive* probe — `/selftest` answered, and the
///   forged address did not come back because the controller stripped or overwrote it — turns it
///   on. No probe, or no answer, means no pod-address identity.
/// * `On` starts trusted, as the admin asserted; a probe can still revoke it.
/// * A forgery seen by **any** replica is recorded on the revocation `ConfigMap`, which every
///   replica watches, and `shared_forgery` overrides the local answer everywhere within informer
///   lag. It is sticky until an admin removes the annotation.
pub struct AddressTrust {
    local: AtomicBool,
    shared_forgery: Arc<AtomicBool>,
}

impl AddressTrust {
    /// A trust state starting at `initially`, deferring to `shared_forgery`.
    pub fn new(initially: bool, shared_forgery: Arc<AtomicBool>) -> Self {
        Self {
            local: AtomicBool::new(initially),
            shared_forgery,
        }
    }

    /// Whether the address may be believed right now.
    pub fn trusted(&self) -> bool {
        self.local.load(Ordering::Relaxed) && !self.shared_forgery.load(Ordering::Relaxed)
    }

    /// Turn it on — after a conclusive probe, and never over a recorded forgery.
    pub fn confirm(&self) -> bool {
        if self.shared_forgery.load(Ordering::Relaxed) {
            return false;
        }
        self.local.store(true, Ordering::Relaxed);
        true
    }

    /// Turn it off on this replica.
    pub fn revoke(&self) {
        self.local.store(false, Ordering::Relaxed);
    }
}

/// How long a `TokenReview` may take before the request it is in front of gives up on it.
pub const TOKEN_REVIEW_TIMEOUT: Duration = Duration::from_secs(5);
/// How long "the apiserver said this token is not a workspace service account" is remembered.
const REFUSED_TTL_SECS: u64 = 60;
/// How long "the apiserver could not be asked" is remembered — short, because it is about the
/// apiserver rather than about the token, and a real workspace token should recover quickly.
const UNAVAILABLE_TTL_SECS: u64 = 5;

/// What bounds the `TokenReview`s this gateway spends, whatever arrives.
#[derive(Debug, Clone, Copy)]
pub struct ReviewLimits {
    /// Reviews in flight at once. Over it, a new review is not started: fail closed.
    pub concurrency: usize,
    /// Reviews per minute, all callers together.
    pub global: Rate,
    /// Reviews per minute per client key (the address the limiter keys on).
    pub per_client: Rate,
    /// Reviews per minute, all callers together, that only a **known** client may draw on once
    /// `global` is spent — one that has had a token accepted within [`KNOWN_CLIENT_TTL_SECS`].
    /// `global` is shared, so a caller rotating addresses could otherwise spend it and make every
    /// legitimate workspace's next new token fail closed; this is the part they cannot reach.
    pub reserved: Rate,
}

/// How long a client that had a service-account token accepted counts as known for the
/// [`ReviewLimits::reserved`] budget — a day, so a workspace's hourly token rotation keeps it known.
pub const KNOWN_CLIENT_TTL_SECS: u64 = 86_400;

impl Default for ReviewLimits {
    fn default() -> Self {
        // A workspace's token is reviewed once per cache lifetime (an hour), so a cluster of a
        // thousand workspaces needs a few hundred reviews an *hour*; these are far above that and
        // far below what an apiserver notices.
        Self {
            concurrency: 16,
            global: Rate {
                burst: 100,
                per_minute: 300,
            },
            per_client: Rate {
                burst: 10,
                per_minute: 30,
            },
            reserved: Rate {
                burst: 30,
                per_minute: 100,
            },
        }
    }
}

/// The `TokenReview` half of self-origin, with both of its caches.
///
/// **Failures are cached too** (H8), for a minute, and an unreachable apiserver for a few
/// seconds; the call itself has an explicit timeout.
///
/// **And the negative cache is not the defence** (second-pass finding 1). It is keyed per token,
/// while "worth a review" is decided on an unsigned payload anybody can mint — so a caller that
/// varies one byte per request gets a fresh key every time, and the cache is never hit. What
/// bounds the apiserver's work is in front of the call instead:
///
/// * **cheap pre-checks** ([`KubeWorkloadIdentity::worth_reviewing`]): the claimed `iss` must be
///   this cluster's service-account issuer where it is known, and a claimed `exp` must be in the
///   future;
/// * **single-flight per fingerprint**: concurrent requests with the same token share one call;
/// * **a global concurrency cap and two token buckets** — cluster-wide and per client key.
///
/// Over any limit the answer is *no identity* and no review: fail closed, counted, and never
/// cached, so a real workspace's token is not remembered as refused because of somebody else's
/// flood.
pub struct TokenReviewer {
    client: Client,
    reviews: IdentityCache<NamespaceName>,
    refused: IdentityCache<()>,
    timeout: Duration,
    accept: bool,
    in_flight: Mutex<HashMap<Fingerprint, Arc<tokio::sync::OnceCell<Option<NamespaceName>>>>>,
    permits: tokio::sync::Semaphore,
    global: RateLimiter,
    per_client: RateLimiter,
    /// See [`ReviewLimits::reserved`].
    reserved: RateLimiter,
    /// Client keys that have had a token accepted, by hash — who may draw on `reserved`.
    known: IdentityCache<()>,
    throttled: std::sync::atomic::AtomicU64,
    /// The service-account issuer's public keys (`/openid/v1/jwks`), kept current by
    /// [`refresh_service_account_keys`] — what lets a forged token be refused with no
    /// `TokenReview` at all.
    keys: JwksCache,
    /// The `kid`s, at the key-set generation they were proven at, that have verified a token the
    /// apiserver then accepted — see [`TokenReviewer::offline`].
    proven: Mutex<(u64, HashSet<String>)>,
    /// `TokenReview`s not asked because the signature alone refused the token.
    avoided: std::sync::atomic::AtomicU64,
}

/// What the signature alone says about a service-account token, before any `TokenReview`.
enum Offline {
    /// Signed by a key this cluster publishes and that is proven to verify its tokens here, and
    /// the signature does not hold: refused, with no apiserver call.
    Forged,
    /// The signature holds under `kid`. Still reviewed — a valid signature says nothing about
    /// whether the pod it was bound to still exists — and, once the review agrees, proof that
    /// this key verifies here.
    Valid(String),
    /// Nothing the signature can settle: no keys yet, a `kid` the set does not hold (a rotation
    /// not fetched yet), an algorithm or key not verifiable here, or a key not proven yet. The
    /// `TokenReview`, inside its limits, decides — exactly as before this check existed.
    Undecided,
}

/// How often the service-account issuer keys are re-read when nothing asks earlier.
const SERVICE_ACCOUNT_KEYS_INTERVAL: Duration = Duration::from_secs(600);

/// The one key every caller shares in the global bucket.
const GLOBAL_KEY: &str = "*";

/// One caller's hold on a single-flight entry, which removes the entry however that caller's
/// wait ends.
///
/// The review is awaited inside a request handler, and a handler's future is dropped when its
/// client disconnects: removing the entry after the `.await` leaked it on every hang-up, so a
/// caller sending fresh service-account-shaped tokens and closing the connection grew the map
/// without bound.
///
/// **Only once the answer is in, or by the last holder.** A waiter that hangs up while another
/// caller's review is still running must leave the entry alone: removing it let the next caller
/// with the same token start a second review, so a caller replaying somebody's token and
/// disconnecting could spend a review per hang-up.
struct InFlightEntry<'a> {
    in_flight: &'a Mutex<HashMap<Fingerprint, Arc<tokio::sync::OnceCell<Option<NamespaceName>>>>>,
    key: Fingerprint,
    /// Taken in `drop`, so this holder's reference is released under the map's lock: counted
    /// outside it, two holders dropping together could each still see the other and both leave
    /// the entry behind.
    cell: Option<Arc<tokio::sync::OnceCell<Option<NamespaceName>>>>,
}

impl Drop for InFlightEntry<'_> {
    fn drop(&mut self) {
        let Some(cell) = self.cell.take() else {
            return;
        };
        let Ok(mut in_flight) = self.in_flight.lock() else {
            return;
        };
        let ours = in_flight
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &cell));
        // Every holder clones under this lock and releases under it, so the count is exact: the
        // map's reference plus this one means nobody else is waiting.
        if ours && (cell.initialized() || Arc::strong_count(&cell) <= 2) {
            in_flight.remove(&self.key);
        }
        drop(cell);
    }
}

impl TokenReviewer {
    /// A reviewer holding at most `cache_entries` answers of each kind.
    pub fn new(client: Client, accept: bool, cache_entries: usize, timeout: Duration) -> Self {
        Self::with_limits(
            client,
            accept,
            cache_entries,
            timeout,
            ReviewLimits::default(),
        )
    }

    /// [`Self::new`] with explicit limits.
    pub fn with_limits(
        client: Client,
        accept: bool,
        cache_entries: usize,
        timeout: Duration,
        limits: ReviewLimits,
    ) -> Self {
        Self {
            client,
            reviews: IdentityCache::new(CacheKind::TokenReview, cache_entries, 3_600),
            refused: IdentityCache::new(CacheKind::TokenReview, cache_entries, REFUSED_TTL_SECS),
            timeout,
            accept,
            in_flight: Mutex::new(HashMap::new()),
            permits: tokio::sync::Semaphore::new(limits.concurrency.max(1)),
            global: RateLimiter::new(limits.global, 1),
            per_client: RateLimiter::new(limits.per_client, 10_000),
            reserved: RateLimiter::new(limits.reserved, 1),
            known: IdentityCache::new(CacheKind::TokenReview, 10_000, KNOWN_CLIENT_TTL_SECS),
            throttled: std::sync::atomic::AtomicU64::new(0),
            keys: JwksCache::default(),
            proven: Mutex::new((0, HashSet::new())),
            avoided: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The cached answer for `token`, without asking anyone.
    pub fn cached(&self, token: &str, now: Timestamp) -> Option<ServiceAccountIdentity> {
        let namespace = self.reviews.get(&Fingerprint::of(token), now)?;
        Some(ServiceAccountIdentity {
            namespace,
            expires_at: now.plus_secs(3_600),
        })
    }

    /// How many reviews were refused by a limit rather than asked — for the log and tests.
    pub fn throttled(&self) -> u64 {
        self.throttled.load(Ordering::Relaxed)
    }

    /// Resolve a service-account token through the apiserver — at most once per token per
    /// cache lifetime, whichever way the answer went, and only inside the limits.
    ///
    /// `client` is the per-client key; empty means "unknown", which is held to the global limit
    /// only rather than putting every such caller in one small bucket.
    pub async fn review(
        &self,
        token: &str,
        client: &str,
        now: Timestamp,
    ) -> Option<ServiceAccountIdentity> {
        if !self.accept {
            return None;
        }
        let key = Fingerprint::of(token);
        if let Some(namespace) = self.reviews.get(&key, now) {
            return Some(ServiceAccountIdentity {
                namespace,
                expires_at: now.plus_secs(3_600),
            });
        }
        if self.refused.get(&key, now).is_some() {
            return None;
        }
        // In front of the limits as well as the apiserver: a forgery the signature settles
        // spends neither, which is what keeps a flood of them from draining the budget a real
        // workspace's next token needs.
        let offline = self.offline(token, now);
        if matches!(offline, Offline::Forged) {
            self.avoided
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        // Single flight: whoever arrives first asks, everyone else with the same token waits for
        // that answer rather than asking again.
        let entry = match self.in_flight.lock() {
            Ok(mut in_flight) => InFlightEntry {
                in_flight: &self.in_flight,
                key,
                cell: Some(Arc::clone(in_flight.entry(key).or_default())),
            },
            Err(_) => return None,
        };
        let namespace = match entry.cell.as_ref() {
            Some(cell) => cell
                .get_or_init(|| self.review_uncached(token, key, client, now))
                .await
                .clone(),
            None => None,
        };
        drop(entry);
        if let (Some(_), Offline::Valid(kid)) = (namespace.as_ref(), offline) {
            self.prove(kid);
        }
        namespace.map(|namespace| ServiceAccountIdentity {
            namespace,
            expires_at: now.plus_secs(3_600),
        })
    }

    /// The service-account issuer's key set, for [`refresh_service_account_keys`] to keep.
    pub fn keys(&self) -> &JwksCache {
        &self.keys
    }

    /// How many `TokenReview`s the signature alone made unnecessary.
    pub fn avoided(&self) -> u64 {
        self.avoided.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// What the signature alone says, with no I/O.
    ///
    /// **A key refuses only once it has proven it verifies here.** `ring` answers "this
    /// signature does not hold" and "this key is not one I verify with" (an RSA modulus under
    /// 2048 bits, say) with the same error, and the second, read as the first, would refuse every
    /// real token in the cluster. So a failed signature counts as a forgery only under a `kid`
    /// that has already verified a token the apiserver then accepted, at the current key-set
    /// generation; until then the `TokenReview` decides, as it did before this check existed.
    fn offline(&self, token: &str, now: Timestamp) -> Offline {
        use jsonwebtoken::Algorithm;

        let Ok(header) = jsonwebtoken::decode_header(token) else {
            return Offline::Undecided;
        };
        let Some(kid) = header.kid else {
            return Offline::Undecided;
        };
        if !matches!(
            header.alg,
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 | Algorithm::ES256
        ) {
            return Offline::Undecided;
        }
        let key = match self.keys.key(&kid) {
            KeyLookup::Found(key) => key,
            KeyLookup::Unknown => {
                // A rotation this replica has not fetched yet looks exactly like this; asking
                // for the set early is rate-limited at the cache.
                self.keys.request_refresh(now);
                return Offline::Undecided;
            }
            KeyLookup::NoKeys | KeyLookup::Unusable => return Offline::Undecided,
        };
        let Some((message, signature)) = token.rsplit_once('.') else {
            return Offline::Undecided;
        };
        match jsonwebtoken::crypto::verify(signature, message.as_bytes(), &key, header.alg) {
            Ok(true) => Offline::Valid(kid),
            Ok(false) if self.is_proven(&kid) => Offline::Forged,
            _ => Offline::Undecided,
        }
    }

    fn is_proven(&self, kid: &str) -> bool {
        let generation = self.keys.generation();
        let Ok(mut proven) = self.proven.lock() else {
            return false;
        };
        if proven.0 != generation {
            *proven = (generation, HashSet::new());
        }
        proven.1.contains(kid)
    }

    fn prove(&self, kid: String) {
        let generation = self.keys.generation();
        if let Ok(mut proven) = self.proven.lock() {
            if proven.0 != generation {
                *proven = (generation, HashSet::new());
            }
            proven.1.insert(kid);
        }
    }

    async fn review_uncached(
        &self,
        token: &str,
        key: Fingerprint,
        client: &str,
        now: Timestamp,
    ) -> Option<NamespaceName> {
        // In front of the call, in this order: the cheapest refusal first, and a client's own
        // bucket before the one everybody shares, so one noisy caller drains only its own.
        // The global bucket first; past it, only a client already known to hold good tokens may
        // draw on the reserve. The per-client bucket applies to everybody either way.
        let known =
            || !client.is_empty() && self.known.get(&Fingerprint::of(client), now).is_some();
        let within = (client.is_empty() || self.per_client.allow(client, now))
            && (self.global.allow(GLOBAL_KEY, now)
                || (known() && self.reserved.allow(GLOBAL_KEY, now)));
        let permit = within.then(|| self.permits.try_acquire().ok()).flatten();
        let Some(_permit) = permit else {
            let throttled = self.throttled.fetch_add(1, Ordering::Relaxed);
            if throttled.is_power_of_two() {
                eprintln!(
                    "WARN endpoint-gateway: TokenReview over its limit ({} refused so far); \
                     service-account tokens are failing closed",
                    throttled + 1
                );
            }
            return None;
        };
        let api: Api<TokenReview> = Api::all(self.client.clone());
        let review = TokenReview {
            spec: TokenReviewSpec {
                token: Some(token.to_owned()),
                audiences: None,
            },
            ..TokenReview::default()
        };
        let reviewed =
            match tokio::time::timeout(self.timeout, api.create(&PostParams::default(), &review))
                .await
            {
                Ok(Ok(reviewed)) => reviewed,
                // Timed out, or the apiserver answered with an error: nothing learned about the
                // token, so remembered only briefly.
                Ok(Err(_)) | Err(_) => {
                    self.refused
                        .insert(key, (), now.plus_secs(UNAVAILABLE_TTL_SECS), now);
                    return None;
                }
            };
        let Some(namespace) = namespace_of_review(reviewed) else {
            self.refused
                .insert(key, (), now.plus_secs(REFUSED_TTL_SECS), now);
            return None;
        };
        // Bounded by the cache's own TTL rather than by the token's `exp`, which a TokenReview
        // does not report: an hour of "this token belongs to this namespace" is the same claim
        // the apiserver just made, and the token is re-reviewed after it.
        self.reviews
            .insert(key, namespace.clone(), now.plus_secs(3_600), now);
        if !client.is_empty() {
            self.known.insert(
                Fingerprint::of(client),
                (),
                now.plus_secs(KNOWN_CLIENT_TTL_SECS),
                now,
            );
        }
        Some(namespace)
    }
}

/// Keep `keys` current with this cluster's service-account issuer keys, forever: one fetch now,
/// then every `interval`, or earlier when a token names a `kid` the set does not hold.
///
/// Read from the apiserver's own `/openid/v1/jwks` through the gateway's client — the issuer
/// discovery endpoint, which needs nothing but a `get` on that one path — rather than from the
/// issuer URL, which a cluster may not publish anywhere this pod can reach. A failure only means
/// every service-account token is reviewed, as it was before this check existed.
pub async fn refresh_service_account_keys(client: Client, keys: JwksCache, interval: Duration) {
    let mut retry = JWKS_RETRY_INITIAL;
    let mut warned = false;
    loop {
        let fetched = match axum::http::Request::get("/openid/v1/jwks").body(Vec::new()) {
            Ok(request) => match client.request::<JwkSet>(request).await {
                Ok(set) => {
                    keys.store(set);
                    warned = false;
                    true
                }
                Err(err) => {
                    if !warned {
                        eprintln!(
                            "WARN endpoint-gateway: service-account issuer keys unavailable                              ({err}); every service-account token is reviewed until they are"
                        );
                        warned = true;
                    }
                    false
                }
            },
            Err(_) => false,
        };
        let wait = if !fetched && !keys.is_loaded() {
            let wait = retry.min(interval);
            retry = retry.saturating_mul(2).min(JWKS_RETRY_MAX);
            wait
        } else {
            retry = JWKS_RETRY_INITIAL;
            interval
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = keys.woken() => {}
        }
    }
}

/// The namespace an authenticated service-account review names, or `None`.
fn namespace_of_review(reviewed: TokenReview) -> Option<NamespaceName> {
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
    Some(NamespaceName::new(namespace))
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
        shared_forgery: Arc<AtomicBool>,
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

        let issuer = std::fs::read_to_string(OWN_TOKEN)
            .ok()
            .and_then(|token| crate::adapters::oidc::unverified_issuer(token.trim()));
        match issuer.as_deref() {
            Some(issuer) => println!(
                "endpoint-gateway: service-account tokens are reviewed only when they claim \
                 issuer {issuer:?}"
            ),
            None => println!(
                "endpoint-gateway: this cluster's service-account issuer is unknown (no token at \
                 {OWN_TOKEN}); the TokenReview pre-check skips the issuer comparison"
            ),
        }

        let reviewer = TokenReviewer::new(
            client.clone(),
            accept_service_account_tokens,
            cache_entries,
            TOKEN_REVIEW_TIMEOUT,
        );
        if accept_service_account_tokens {
            tokio::spawn(refresh_service_account_keys(
                client,
                reviewer.keys().clone(),
                SERVICE_ACCOUNT_KEYS_INTERVAL,
            ));
        }
        Ok(Arc::new(Self {
            pods: store,
            addresses,
            reviewer,
            cluster_issuer: issuer,
            trust: AddressTrust::new(trust_addresses, shared_forgery),
        }))
    }

    /// Turn the pod-address mechanism off on this replica — what the self-origin probe does when
    /// it watches a forged address come back, per RFC 0009's *Checking that assumption rather
    /// than configuring it* (the probe also records it for every other replica).
    pub fn revoke_address_trust(&self) {
        self.trust.revoke();
    }

    /// Turn it on after a conclusive probe — `Auto` only, and never over a recorded forgery.
    /// Returns whether it is now on.
    pub fn confirm_address_trust(&self) -> bool {
        self.trust.confirm()
    }

    /// Whether the pod-address mechanism is currently trusted —
    /// `weebo_si_endpoint_auth_client_ip_trusted`.
    pub fn addresses_trusted(&self) -> bool {
        self.trust.trusted()
    }

    /// How many workspace pods are indexed.
    pub fn indexed_pods(&self) -> usize {
        self.pods.state().len()
    }

    /// Resolve a service-account token through the apiserver, and remember the answer until the
    /// token's own expiry. Called from the inbound adapter *before* the decision, never inside
    /// it.
    pub async fn review(
        &self,
        token: &str,
        client: &str,
        now: Timestamp,
    ) -> Option<ServiceAccountIdentity> {
        self.reviewer.review(token, client, now).await
    }

    /// How many reviews a limit refused.
    pub fn reviews_throttled(&self) -> u64 {
        self.reviewer.throttled()
    }

    /// How many reviews a forged signature made unnecessary.
    pub fn reviews_avoided(&self) -> u64 {
        self.reviewer.avoided()
    }

    /// Whether this token is worth a `TokenReview` at all: shaped like a service-account token,
    /// claiming this cluster's issuer where that is known, and not claiming to have expired.
    /// Everything here is read unverified — it decides whether to *ask*, never what the answer is.
    pub fn worth_reviewing(&self, token: &str, now: Timestamp) -> bool {
        worth_reviewing(token, self.cluster_issuer.as_deref(), now)
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

/// See [`KubeWorkloadIdentity::worth_reviewing`].
pub fn worth_reviewing(token: &str, cluster_issuer: Option<&str>, now: Timestamp) -> bool {
    if !KubeWorkloadIdentity::looks_like_service_account_token(token) {
        return false;
    }
    use base64::Engine;
    let Some(claims) = token
        .split('.')
        .nth(1)
        .and_then(|payload| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    else {
        return false;
    };
    let issuer = claims.get("iss").and_then(|iss| iss.as_str());
    if let Some(cluster) = cluster_issuer
        && issuer != Some(cluster)
        && issuer != Some(LEGACY_ISSUER)
    {
        return false;
    }
    // A projected token always carries `exp`; a legacy one never does. A claimed `exp` in the
    // past is a token the apiserver would refuse, so it is refused here for free.
    match claims.get("exp") {
        None => true,
        Some(exp) => exp.as_u64().is_some_and(|exp| exp > now.as_secs()),
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
        self.reviewer.cached(token, now)
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

    /// A local stand-in for the apiserver's `TokenReview` endpoint that counts its callers and
    /// answers after `delay`.
    async fn fake_apiserver(
        delay: Duration,
        authenticated: bool,
    ) -> (Client, Arc<std::sync::atomic::AtomicUsize>) {
        use axum::routing::post;

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/apis/authentication.k8s.io/v1/tokenreviews",
            post(move || {
                let counted = Arc::clone(&counted);
                async move {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    axum::Json(serde_json::json!({
                        "apiVersion": "authentication.k8s.io/v1",
                        "kind": "TokenReview",
                        "spec": {},
                        "status": {
                            "authenticated": authenticated,
                            "user": {"username": "system:serviceaccount:user-alice:default"}
                        }
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = kube::Config::new(format!("http://{address}").parse().unwrap());
        (Client::try_from(config).unwrap(), calls)
    }

    fn sa_shaped() -> String {
        let payload = B64.encode(br#"{"kubernetes.io":{"namespace":"user-alice"}}"#);
        format!("header.{payload}.signature")
    }

    /// H8: an unverified token shaped like a service-account token cost one `TokenReview` per
    /// request, because only a *successful* review was remembered.
    #[tokio::test]
    async fn a_refused_token_review_is_remembered_rather_than_repeated() {
        let (client, calls) = fake_apiserver(Duration::ZERO, false).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        let now = Timestamp::from_secs(1_000);
        for _ in 0..20 {
            assert!(reviewer.review(&sa_shaped(), "", now).await.is_none());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // ...for a short while only.
        assert!(
            reviewer
                .review(&sa_shaped(), "", now.plus_secs(REFUSED_TTL_SECS))
                .await
                .is_none()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_accepted_token_review_resolves_to_its_namespace_once() {
        let (client, calls) = fake_apiserver(Duration::ZERO, true).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        let now = Timestamp::from_secs(1_000);
        for _ in 0..5 {
            let identity = reviewer.review(&sa_shaped(), "", now).await.unwrap();
            assert_eq!(identity.namespace.as_str(), "user-alice");
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(reviewer.cached(&sa_shaped(), now).is_some());
    }

    /// H8: the call has its own deadline, and a timeout is remembered briefly too.
    #[tokio::test]
    async fn a_slow_apiserver_is_given_up_on_and_not_asked_again_at_once() {
        let (client, calls) = fake_apiserver(Duration::from_secs(5), true).await;
        let reviewer = TokenReviewer::new(client, true, 100, Duration::from_millis(100));
        let now = Timestamp::from_secs(1_000);
        let started = std::time::Instant::now();
        assert!(reviewer.review(&sa_shaped(), "", now).await.is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(reviewer.review(&sa_shaped(), "", now).await.is_none());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    fn sa_token(n: usize) -> String {
        let payload = B64.encode(
            format!(r#"{{"iss":"https://kubernetes.default.svc","kubernetes.io":{{"n":{n}}}}}"#)
                .as_bytes(),
        );
        format!("header.{payload}.signature")
    }

    fn limits(concurrency: usize, global: u32, per_client: u32) -> ReviewLimits {
        ReviewLimits {
            concurrency,
            global: Rate {
                burst: global,
                per_minute: global,
            },
            per_client: Rate {
                burst: per_client,
                per_minute: per_client,
            },
            reserved: Rate {
                burst: 0,
                per_minute: 0,
            },
        }
    }

    /// A service-account issuer key pair, and tokens it signs — so the offline check runs
    /// against real cryptography.
    struct Issuer {
        key: jsonwebtoken::EncodingKey,
        keys: JwkSet,
    }

    impl Issuer {
        fn new() -> Self {
            use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

            crate::adapters::jwt_crypto::install();
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let point = pair.public_key().as_ref().to_vec();
            let keys = serde_json::from_value::<JwkSet>(serde_json::json!({
                "keys": [{
                    "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "sa-key",
                    "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
                }]
            }))
            .unwrap();
            Self {
                key: jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()),
                keys,
            }
        }

        fn sign(&self, kid: &str, n: usize) -> String {
            let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
            header.kid = Some(kid.to_owned());
            jsonwebtoken::encode(
                &header,
                &serde_json::json!({"iss": "https://kubernetes.default.svc", "n": n}),
                &self.key,
            )
            .unwrap()
        }

        /// A token naming the issuer's real key, with a signature that key never made.
        fn forge(&self, n: usize) -> String {
            let real = self.sign("sa-key", n);
            let (message, _) = real.rsplit_once('.').unwrap();
            format!("{message}.{}", B64.encode([7_u8; 64]))
        }
    }

    #[tokio::test]
    async fn a_forged_signature_under_a_proven_key_costs_no_token_review() {
        let issuer = Issuer::new();
        let (client, calls) = fake_apiserver(Duration::ZERO, true).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        reviewer.keys().store(issuer.keys.clone());
        let now = Timestamp::from_secs(1_000);
        let reviews = || calls.load(std::sync::atomic::Ordering::SeqCst);

        // A real token: verified offline, then reviewed — which proves the key verifies here.
        assert!(
            reviewer
                .review(&issuer.sign("sa-key", 1), "", now)
                .await
                .is_some()
        );
        assert_eq!(reviews(), 1);
        // A forgery under that key: refused on the signature, the apiserver never asked.
        for n in 0..20 {
            assert!(
                reviewer
                    .review(&issuer.forge(100 + n), "", now)
                    .await
                    .is_none()
            );
        }
        assert_eq!(reviews(), 1);
        assert_eq!(reviewer.avoided(), 20);
        // A key the set does not hold is a rotation as far as this replica knows: reviewed.
        assert!(
            reviewer
                .review(&issuer.sign("rotated", 2), "", now)
                .await
                .is_some()
        );
        assert_eq!(reviews(), 2);
    }

    /// The safety half: until a key has verified a token the apiserver accepted, a failed
    /// signature is not trusted to mean "forged" — it might mean "a key this gateway cannot
    /// verify with", and refusing on it would refuse every real token in the cluster.
    #[tokio::test]
    async fn an_unproven_key_leaves_the_decision_to_the_token_review() {
        let issuer = Issuer::new();
        let (client, calls) = fake_apiserver(Duration::ZERO, true).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        reviewer.keys().store(issuer.keys.clone());
        let now = Timestamp::from_secs(1_000);
        let _ = reviewer.review(&issuer.forge(1), "", now).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(reviewer.avoided(), 0);
    }

    /// A rotation drops what was proven: the new set's keys prove themselves again.
    #[tokio::test]
    async fn a_new_key_set_has_to_prove_itself_again() {
        let issuer = Issuer::new();
        let (client, calls) = fake_apiserver(Duration::ZERO, true).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        reviewer.keys().store(issuer.keys.clone());
        let now = Timestamp::from_secs(1_000);
        assert!(
            reviewer
                .review(&issuer.sign("sa-key", 1), "", now)
                .await
                .is_some()
        );
        let rotated = Issuer::new();
        reviewer.keys().store(rotated.keys.clone());
        let _ = reviewer.review(&rotated.forge(2), "", now).await;
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(reviewer.avoided(), 0);
    }

    /// Second-pass gap: the global bucket is shared, so strangers rotating addresses could spend
    /// it and leave a workspace that already proved itself failing closed on its next token. The
    /// reserve is the share they cannot reach.
    #[tokio::test]
    async fn a_known_client_keeps_a_reserve_when_strangers_spend_the_global_budget() {
        let (client, _calls) = fake_apiserver(Duration::ZERO, true).await;
        let mut budget = limits(16, 3, 100);
        budget.reserved = Rate {
            burst: 2,
            per_minute: 2,
        };
        let reviewer = TokenReviewer::with_limits(client, true, 100, TOKEN_REVIEW_TIMEOUT, budget);
        let now = Timestamp::from_secs(1_000);
        // A workspace proves itself once: it is known from here on.
        assert!(
            reviewer
                .review(&sa_token(0), "10.0.0.1", now)
                .await
                .is_some()
        );
        // Strangers, one address each, spend what is left of the global bucket and then some.
        for n in 1..20 {
            let _ = reviewer
                .review(&sa_token(n), &format!("198.51.100.{n}"), now)
                .await;
        }
        // A newcomer is out of luck — the global bucket is empty and the reserve is not theirs.
        assert!(
            reviewer
                .review(&sa_token(100), "203.0.113.1", now)
                .await
                .is_none()
        );
        // The known workspace's next token is still reviewed, out of the reserve...
        assert!(
            reviewer
                .review(&sa_token(101), "10.0.0.1", now)
                .await
                .is_some()
        );
        assert!(
            reviewer
                .review(&sa_token(102), "10.0.0.1", now)
                .await
                .is_some()
        );
        // ...which is finite too.
        assert!(
            reviewer
                .review(&sa_token(103), "10.0.0.1", now)
                .await
                .is_none()
        );
    }

    /// Second-pass finding 1: concurrent requests carrying one uncached token each asked the
    /// apiserver. They now share one call.
    #[tokio::test]
    async fn concurrent_reviews_of_one_token_share_one_call() {
        let (client, calls) = fake_apiserver(Duration::from_millis(200), true).await;
        let reviewer = Arc::new(TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT));
        let now = Timestamp::from_secs(1_000);
        let waiting = (0..20)
            .map(|_| {
                let reviewer = Arc::clone(&reviewer);
                tokio::spawn(async move { reviewer.review(&sa_token(1), "", now).await })
            })
            .collect::<Vec<_>>();
        for task in waiting {
            assert!(task.await.unwrap().is_some());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Second-pass finding 1: the negative cache is per token and "SA-shaped" is an unsigned
    /// payload, so a caller varying the token got one review per request. The buckets bound it.
    #[tokio::test]
    async fn a_flood_of_distinct_tokens_is_held_to_the_limits_and_fails_closed() {
        let (client, calls) = fake_apiserver(Duration::ZERO, false).await;
        let reviewer =
            TokenReviewer::with_limits(client, true, 100, TOKEN_REVIEW_TIMEOUT, limits(4, 5, 100));
        let now = Timestamp::from_secs(1_000);
        for n in 0..200 {
            assert!(reviewer.review(&sa_token(n), "", now).await.is_none());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(reviewer.throttled(), 195);
    }

    #[tokio::test]
    async fn one_noisy_client_drains_its_own_bucket_and_not_everybody_elses() {
        let (client, calls) = fake_apiserver(Duration::ZERO, true).await;
        let reviewer =
            TokenReviewer::with_limits(client, true, 100, TOKEN_REVIEW_TIMEOUT, limits(4, 100, 2));
        let now = Timestamp::from_secs(1_000);
        let mut accepted = 0;
        for n in 0..10 {
            accepted += usize::from(
                reviewer
                    .review(&sa_token(n), "10.0.0.1", now)
                    .await
                    .is_some(),
            );
        }
        assert_eq!(accepted, 2);
        // Another client still gets its reviews.
        assert!(
            reviewer
                .review(&sa_token(99), "10.0.0.2", now)
                .await
                .is_some()
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
        // And a throttled answer is not remembered as a refusal: once the bucket refills the
        // same token is reviewed and accepted.
        assert!(
            reviewer
                .review(&sa_token(5), "10.0.0.1", now.plus_secs(60))
                .await
                .is_some()
        );
    }

    /// A review whose caller hung up used to leave its single-flight entry behind for good.
    #[tokio::test]
    async fn an_abandoned_review_does_not_leave_its_single_flight_entry_behind() {
        let (client, _calls) = fake_apiserver(Duration::from_secs(5), true).await;
        let reviewer = TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT);
        let now = Timestamp::from_secs(1_000);
        for n in 0..10 {
            let abandoned = tokio::time::timeout(
                Duration::from_millis(20),
                reviewer.review(&sa_token(n), "", now),
            )
            .await;
            assert!(abandoned.is_err());
        }
        assert!(reviewer.in_flight.lock().unwrap().is_empty());
    }

    /// A waiter hanging up while another caller's review runs used to remove the entry, so the
    /// next caller with the same token started a second review.
    #[tokio::test]
    async fn a_waiter_hanging_up_does_not_start_a_second_review() {
        let (client, calls) = fake_apiserver(Duration::from_millis(300), true).await;
        let reviewer = Arc::new(TokenReviewer::new(client, true, 100, TOKEN_REVIEW_TIMEOUT));
        let now = Timestamp::from_secs(1_000);
        let first = {
            let reviewer = Arc::clone(&reviewer);
            tokio::spawn(async move { reviewer.review(&sa_token(1), "", now).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..5 {
            let abandoned = tokio::time::timeout(
                Duration::from_millis(10),
                reviewer.review(&sa_token(1), "", now),
            )
            .await;
            assert!(abandoned.is_err());
        }
        let late = {
            let reviewer = Arc::clone(&reviewer);
            tokio::spawn(async move { reviewer.review(&sa_token(1), "", now).await })
        };
        assert!(first.await.unwrap().is_some());
        assert!(late.await.unwrap().is_some());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(reviewer.in_flight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reviews_in_flight_are_capped_and_the_overflow_fails_closed() {
        let (client, calls) = fake_apiserver(Duration::from_millis(300), true).await;
        let reviewer = Arc::new(TokenReviewer::with_limits(
            client,
            true,
            100,
            TOKEN_REVIEW_TIMEOUT,
            limits(1, 100, 100),
        ));
        let now = Timestamp::from_secs(1_000);
        let first = {
            let reviewer = Arc::clone(&reviewer);
            tokio::spawn(async move { reviewer.review(&sa_token(1), "", now).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = std::time::Instant::now();
        assert!(reviewer.review(&sa_token(2), "", now).await.is_none());
        assert!(started.elapsed() < Duration::from_millis(200), "it waited");
        assert!(first.await.unwrap().is_some());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Second-pass finding 1's cheap half: an issuer that is not this cluster's, or an `exp` in
    /// the past, is not worth asking about.
    #[test]
    fn only_a_token_claiming_this_clusters_issuer_and_not_expired_is_worth_a_review() {
        let token = |claims: serde_json::Value| {
            format!("h.{}.s", B64.encode(serde_json::to_vec(&claims).unwrap()))
        };
        let cluster = Some("https://kubernetes.default.svc");
        let now = Timestamp::from_secs(1_000);
        let projected = token(serde_json::json!({
            "iss": "https://kubernetes.default.svc", "exp": 2_000,
            "kubernetes.io": {"namespace": "user-alice"}
        }));
        assert!(worth_reviewing(&projected, cluster, now));
        // Issuer unknown at boot: the comparison is skipped, nothing else is.
        assert!(worth_reviewing(&projected, None, now));
        let foreign = token(serde_json::json!({
            "iss": "https://evil.example", "exp": 2_000, "kubernetes.io": {}
        }));
        assert!(!worth_reviewing(&foreign, cluster, now));
        let expired = token(serde_json::json!({
            "iss": "https://kubernetes.default.svc", "exp": 999, "kubernetes.io": {}
        }));
        assert!(!worth_reviewing(&expired, cluster, now));
        let legacy = token(serde_json::json!({
            "iss": "kubernetes/serviceaccount",
            "kubernetes.io/serviceaccount/namespace": "user-alice"
        }));
        assert!(worth_reviewing(&legacy, cluster, now));
    }

    /// Second-pass finding 2: `Auto` starts untrusted, only a conclusive probe turns it on, and a
    /// forgery any replica recorded overrides every replica's own answer.
    #[test]
    fn address_trust_starts_where_the_mode_says_and_a_shared_forgery_wins() {
        let shared = Arc::new(AtomicBool::new(false));
        let auto = AddressTrust::new(false, Arc::clone(&shared));
        assert!(!auto.trusted(), "Auto must not start trusted");
        assert!(auto.confirm());
        assert!(auto.trusted());

        let on = AddressTrust::new(true, Arc::clone(&shared));
        assert!(on.trusted());
        shared.store(true, Ordering::Relaxed);
        assert!(!auto.trusted());
        assert!(!on.trusted());
        // A later clean probe on this replica does not outvote the recorded forgery.
        assert!(!auto.confirm());
        assert!(!auto.trusted());
        // Until an admin clears it.
        shared.store(false, Ordering::Relaxed);
        assert!(auto.confirm());
        auto.revoke();
        assert!(!auto.trusted());
    }
}
