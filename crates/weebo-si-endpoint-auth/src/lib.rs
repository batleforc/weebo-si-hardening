//! The `endpoint-auth` decision — see [RFC 0009](../../../docs/rfc/0009-endpoint-auth.md).
//!
//! Every workspace endpoint exposed on its own FQDN is gated by one process, `endpoint-gateway`,
//! which answers one question per HTTP request: may *this* caller reach *this* host, on *this*
//! path, with *this* method. This crate is that answer. It owns no HTTP server, no Kubernetes
//! client and no OIDC client; it owns the decision and the shapes the decision is made of, so
//! that the whole of RFC 0009's flowchart can be exercised by a table of cases with no cluster,
//! no identity provider and no network in the way.
//!
//! # The invariant this crate exists to hold
//!
//! **Nothing on the request path does I/O.** Every port [`decide`](decide::decide) and
//! [`application`] reach for is a *synchronous* trait answered from memory — a watch put the
//! data there before the request arrived. That is not a style preference: it is RFC 0009's
//! *Request cost* section expressed in the type system, since an adapter that wanted to make a
//! network call on the request path would have nowhere to `await` it. The one asynchronous port,
//! [`port::IdentityProvider`], is the login path, which happens once per session rather than
//! once per asset.
//!
//! # What is here, and in which order to read it
//!
//! 1. [`policy`] — what an endpoint's access rules *are*, already compiled: an
//!    [`EndpointPolicy`](policy::EndpointPolicy) is the immutable result of reading annotations,
//!    a catalogue, a team grant and an admin override, not a bag of strings to be parsed per
//!    request.
//! 2. [`compile`] — the parsing and the grant/override intersection that produce one, exactly
//!    once, on an informer event.
//! 3. [`index`] — host to policy, with the host-collision detection RFC 0009 calls a security
//!    boundary rather than a tidiness rule.
//! 4. [`path`] — path normalisation, which is where forward-auth gates are bypassed.
//! 5. [`decide`] — the pure function every other module exists to serve.
//! 6. [`application`] — resolving what a request presented into an identity, through the ports,
//!    and running the decision under the feature's own enforcement mode.
//! 7. [`cache`] — the identity caches, bounded and keyed by hash, which make the burst of 200
//!    assets on one page load cost one AEAD open and 199 map reads.

pub mod application;
pub mod cache;
pub mod compile;
pub mod decide;
pub mod host;
pub mod identity;
pub mod index;
pub mod path;
pub mod policy;
pub mod port;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod time;

pub use application::{Enforcement, Gateway, GatewayPorts, Outcome, Presented};
pub use cache::{CacheKind, CacheOutcome, Fingerprint, IdentityCache};
pub use compile::{Catalogue, CompileError, Grant, Override, RawEndpoint, compile};
pub use decide::{AuthRequest, Challenge, Decision, Reason, RequestShape, Scheme, Verdict, decide};
pub use host::{ClientAddress, Host, HostError, HostScope, ScopeError};
pub use identity::{
    Claims, Credential, EndpointIdentity, GroupName, NamespaceName, SessionId, TeamName, Username,
};
pub use index::{CatalogLookup, HostConflict, HostIndex};
pub use path::{NormalisedPath, PathError, normalise};
pub use policy::{
    AccessProfile, BearerMode, CatalogueKey, Delegation, EndpointPolicy, MatchKind, Method,
    MethodSet, PathRule, Provenance, Selected, Upstream,
};
pub use time::Timestamp;
