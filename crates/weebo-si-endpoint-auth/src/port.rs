//! What the decision needs from the outside, in the domain's vocabulary.
//!
//! **Every port on the request path is synchronous.** That is RFC 0009's "no I/O on the request
//! path" written where the compiler can hold it: an adapter that wanted to call the apiserver
//! while a request waits has nowhere to `await`, so the only way to answer is from memory a watch
//! already filled. The ports are named for what the decision needs — "which namespace is this
//! address", not "list pods" — so swapping an informer for something else never reaches the
//! domain.
//!
//! The one asynchronous port is [`IdentityProvider`], which is the login path: a code exchange
//! happens once per session, not once per asset, and it is the only place in this crate where a
//! network round trip is the right answer.

use std::future::Future;
use std::pin::Pin;

use crate::host::{ClientAddress, Host, HostScope};
use crate::identity::{Claims, NamespaceName, SessionId};
use crate::index::CatalogLookup;
use crate::time::Timestamp;

/// Host to policy, plus the suffix this feature governs.
///
/// Implemented over the `Ingress`/`Route` informer's compiled index. A real implementation
/// answers from an [`crate::index::HostIndex`] behind an atomic swap; the lookup is a map read,
/// and the `Arc` in [`CatalogLookup::Policy`] is why handing it out costs nothing.
pub trait EndpointCatalog: Send + Sync {
    /// What answers for `host`.
    fn policy_for(&self, host: &Host) -> CatalogLookup;

    /// The governed suffix and its exclusions.
    fn scope(&self) -> &HostScope;
}

/// A sealed session, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedSession {
    /// Who the cookie says the caller is.
    pub claims: Claims,
    /// When the cookie stops being valid — the deadline any cache entry for it inherits.
    pub expires_at: Timestamp,
}

/// Seal and open the two cookies.
///
/// Opening is a pure function of the cookie, the host and the key, which is exactly why its
/// result may be cached: the cache is remembering arithmetic, not a decision.
pub trait SessionCodec: Send + Sync {
    /// Open a host session cookie presented on `host`. `None` covers every way a cookie can fail
    /// — wrong key, wrong host, expired, corrupt — because a caller can act on none of them
    /// differently: the answer is always "sign in again".
    fn open_host_session(&self, host: &Host, sealed: &str, now: Timestamp)
    -> Option<OpenedSession>;
}

/// What an `Authorization: Bearer` turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenOutcome {
    /// A token this cluster's issuer minted, verified against its keys.
    Ours {
        /// Who it is for.
        claims: Claims,
        /// Its `exp`.
        expires_at: Timestamp,
    },
    /// A well-formed token from somewhere else. Not an identity here; the only thing it can reach
    /// is a rule that opted into `bearer: Passthrough`.
    Foreign,
    /// Malformed, or signed by a key this issuer does not publish.
    Invalid,
}

/// Verify a bearer token against the issuer's keys.
///
/// A port of its own rather than a method on [`IdentityProvider`] for a reason the domain cares
/// about: verifying a bearer must not be able to reach the network on the request path. The
/// adapter holds a JWKS cache refreshed in the background, so a decision is a signature check
/// against keys already in memory — and an identity provider that is down cannot stop a `curl`
/// that already has a valid token.
pub trait TokenVerifier: Send + Sync {
    /// Verify one token.
    fn verify(&self, token: &str, now: Timestamp) -> TokenOutcome;
}

/// A workspace's service-account token, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccountIdentity {
    /// The namespace the service account belongs to.
    pub namespace: NamespaceName,
    /// When the answer stops being valid — the token's own `exp`, which is what bounds the
    /// `TokenReview` cache entry.
    pub expires_at: Timestamp,
}

/// Is this caller the workspace itself?
///
/// Two mechanisms, one port, because they answer the same question: the client address the
/// controller reported, and the service-account token DevWorkspace Operator already mounts. A port
/// rather than two fields on the request so that "this caller is the owner, by origin" can be
/// asserted in a table-driven test with no cluster, no CNI and no SNAT in the way.
pub trait WorkloadIdentity: Send + Sync {
    /// Which namespace's pod holds this address, if any. `None` where the address is not a pod's
    /// — including every cluster that SNATs, where the mechanism degrades to "sign in" and the
    /// answer is the service-account token below.
    fn namespace_of_address(&self, address: &ClientAddress) -> Option<NamespaceName>;

    /// Which namespace this service-account token belongs to. Backed by a `TokenReview` whose
    /// result is cached against the token's hash until its `exp`, so a polling loop costs one API
    /// call rather than one per request.
    fn namespace_of_service_account(
        &self,
        token: &str,
        now: Timestamp,
    ) -> Option<ServiceAccountIdentity>;
}

/// Sessions the identity provider has ended.
///
/// A port rather than a field so the `ConfigMap`-backed implementation of RFC 0009 can be
/// replaced without the domain learning about it — the one shared-store seam this design leaves
/// open, and the reason *Request cost* can answer the Valkey question with "not today" rather
/// than "not ever".
pub trait RevocationStore: Send + Sync {
    /// Whether this session was revoked. Answered from an informer over the store, so it is a set
    /// lookup rather than a round trip.
    fn is_revoked(&self, session: &SessionId) -> bool;
}

/// Which team a person is in.
///
/// Derived, never claimed: a team's members are the owners of its namespaces, so this is a map
/// the namespace informer fills and not a group in the identity provider anybody has to keep
/// aligned. Resolved per request rather than sealed into the cookie for the same reason the
/// verdict is not cached — team membership is authorisation input, and authorisation input must
/// be live.
pub trait Teams: Send + Sync {
    /// The team `username` is in, if any.
    fn team_of(&self, username: &crate::identity::Username) -> Option<crate::identity::TeamName>;
}

/// The clock, as a port, so no decision can read one by accident.
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> Timestamp;
}

/// What the identity provider is asked for, on the login path only.
///
/// Boxed-future rather than `async fn` in the trait, matching `weebo-si-registry-config`'s
/// `ObjectStore`: this port is used behind a `dyn` reference from a composition root, and a
/// concrete `Future` type per implementation is what makes that possible.
pub trait IdentityProvider: Send + Sync {
    /// Exchange an authorization code for claims. The only network call in this crate's
    /// vocabulary, and it happens once per sign-in.
    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        verifier: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<OpenedSession>> + Send + 'a>>;
}
