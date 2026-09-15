//! The `ReverseProxy` shell — RFC 0009's *Attaching the gate*, the OpenShift half.
//!
//! On a router with no external-auth hook there is no question to ask, so the `Route` is
//! repointed at this gateway and the gateway carries the traffic: it runs the **same**
//! [`decide()`](weebo_si_endpoint_auth::decide) and, on `allow`, forwards to the backend the
//! operator recorded in `hardening.weebo.io/upstream`.
//!
//! **The domain does not know which mode it is in.** That is the property that keeps OpenShift
//! from forking the design, and the test at the bottom of this file is the one RFC 0009 asks for:
//! the two shells produce the same verdict for the same request.
//!
//! Three things this mode costs, stated where the code is rather than in a footnote:
//!
//! * **This process is on the data path.** WebSocket upgrades, streamed responses and large
//!   uploads go through it, so its timeouts and body handling have to match the router's.
//! * **A bug here can corrupt an application response**, which on a forward-auth dialect it
//!   structurally cannot.
//! * **Capacity is bandwidth-shaped**, not decisions-per-second-shaped. Do not size this mode
//!   from RFC 0009's *Capacity* numbers, which are about a gate that answers a question.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use weebo_si_endpoint_auth::decide::Verdict;
use weebo_si_endpoint_auth::host::Host;
use weebo_si_endpoint_auth::index::CatalogLookup;
use weebo_si_endpoint_auth::policy::Method;

use crate::http::{
    HOST_COOKIE, challenge_response, deny_response, presented_from, set_identity_headers,
};
use crate::state::GatewayState;

/// The client this shell forwards with. Streaming in both directions: an `axum::body::Body` is an
/// `http_body::Body`, so a two-gigabyte upload is copied through rather than buffered.
pub type ProxyClient = Client<HttpConnector, Body>;

/// Build the forwarding client.
pub fn client() -> ProxyClient {
    let mut connector = HttpConnector::new();
    // The gateway speaks plain HTTP inside the cluster to the workspace `Service`, exactly as
    // that `Service` is reached today; TLS on OpenShift stays the router's.
    connector.enforce_http(true);
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Hop-by-hop headers, which belong to one connection and must not be copied to the next.
///
/// `Connection` and `Upgrade` are the exceptions handled separately below: an upgrade has to be
/// *forwarded* for a WebSocket to work at all, and then honoured on both sides.
const HOP_BY_HOP: [&str; 6] = [
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// The fallback handler: anything that is not one of the gateway's own routes.
///
/// In `ForwardAuth` mode this is a `404` — the gateway answers questions and carries nothing. In
/// `ReverseProxy` mode it is the application's traffic.
pub async fn fallback(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: Request,
) -> Response {
    if !state.config.reverse_proxy {
        return (StatusCode::NOT_FOUND, "no such route on this gateway\n").into_response();
    }
    serve(state, Some(peer), request).await
}

async fn serve(
    state: Arc<GatewayState>,
    peer: Option<std::net::SocketAddr>,
    request: Request,
) -> Response {
    let started = std::time::Instant::now();
    let headers = request.headers().clone();
    let Some(host) = host_of(&headers, request.uri()) else {
        return (StatusCode::BAD_REQUEST, "no host\n").into_response();
    };

    // The router terminated TLS and said so; a request that arrives claiming `http` is refused by
    // the same rule that refuses a plain-HTTP endpoint on a forward-auth dialect.
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("https")
        .to_owned();
    let auth = crate::http::auth_request(
        &state,
        host.clone(),
        request
            .uri()
            .path_and_query()
            .map(ToString::to_string)
            .unwrap_or_else(|| "/".to_owned()),
        Method::parse(request.method().as_str()),
        &proto,
        &headers,
    );

    let presented = presented_from(&state, &headers, peer);
    // The same `TokenReview` pre-step the `/auth` handler makes, for the same reason: the
    // decision may not do I/O, so the one call this mechanism needs happens above it.
    state
        .prewarm_service_account(presented.bearer.as_deref())
        .await;

    state.drop_identities_on_key_rotation();
    let outcome = state.gateway().authorize(&auth, &presented);
    state
        .metrics
        .decided(outcome.decision, started.elapsed().as_secs_f64());
    state.log_decision(&auth, &outcome, &presented);

    match outcome.answered {
        Verdict::Deny => return deny_response(&state, &auth, outcome.decision.reason),
        Verdict::Challenge(challenge) => return challenge_response(&state, &auth, challenge),
        Verdict::Allow => {}
    }

    let CatalogLookup::Policy(policy) = state.catalog_lookup(&host) else {
        // Allowed, and nowhere to send it. Only reachable in `Observe`, where every verdict is
        // answered `200` including the ones about hosts this gateway has no policy for.
        return (
            StatusCode::BAD_GATEWAY,
            "this endpoint has no recorded backend\n",
        )
            .into_response();
    };
    let Some(upstream) = policy.upstream.as_ref() else {
        return (
            StatusCode::BAD_GATEWAY,
            "this endpoint was never repointed at the gateway; its backend is unknown\n",
        )
            .into_response();
    };

    let identity = state.identity_of(&auth, &presented);
    forward(
        &state,
        request,
        &upstream.url(policy.namespace.as_str()),
        identity,
    )
    .await
}

/// The host under decision, from the `Host` header or the absolute-form URI.
fn host_of(headers: &HeaderMap, uri: &Uri) -> Option<Host> {
    let raw = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| uri.host().map(ToOwned::to_owned))?;
    Host::parse(&raw).ok()
}

/// Copy the request to the backend, and the backend's answer back.
async fn forward(
    state: &GatewayState,
    mut request: Request,
    upstream: &str,
    identity: Option<weebo_si_endpoint_auth::identity::Claims>,
) -> Response {
    let path = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| "/".to_owned());
    let Ok(uri) = format!("{upstream}{path}").parse::<Uri>() else {
        return (StatusCode::BAD_GATEWAY, "unusable backend address\n").into_response();
    };
    *request.uri_mut() = uri;

    let upgrade = request
        .headers()
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut request));

    {
        let headers = request.headers_mut();
        for name in HOP_BY_HOP {
            headers.remove(name);
        }
        // The identity, overwritten rather than merged: a caller presenting its own
        // `X-Auth-Request-User` must not reach the application with it.
        headers.remove("x-auth-request-user");
        headers.remove("x-auth-request-groups");
        headers.remove("x-auth-request-email");
        if let Some(claims) = identity.as_ref() {
            set_identity_headers(headers, claims);
        }
        // The gate's own cookie is the gateway's business, not the application's: an application
        // that could read it could replay a session it was never given.
        strip_cookie(headers, HOST_COOKIE);
    }

    let response = match state.proxy.request(request).await {
        Ok(response) => response,
        Err(err) => {
            eprintln!("WARN endpoint-gateway: backend {upstream} unreachable: {err}");
            return (
                StatusCode::BAD_GATEWAY,
                "the application behind this endpoint did not answer\n",
            )
                .into_response();
        }
    };

    let (mut parts, body) = response.into_parts();
    let switching = parts.status == StatusCode::SWITCHING_PROTOCOLS;
    for name in HOP_BY_HOP {
        parts.headers.remove(name);
    }
    let mut response = Response::from_parts(parts, Body::new(body));

    // An `Upgrade` has to be honoured on both sides or an HMR socket reconnecting on every save
    // hangs — RFC 0009's *Developer continuity* promises that case works, and this mode is the
    // only one where the gateway has to do anything for it.
    if switching && let Some(client_upgrade) = client_upgrade {
        let backend_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, backend_upgrade) {
                Ok((client, backend)) => {
                    let mut client = hyper_util::rt::TokioIo::new(client);
                    let mut backend = hyper_util::rt::TokioIo::new(backend);
                    if let Err(err) = tokio::io::copy_bidirectional(&mut client, &mut backend).await
                    {
                        eprintln!("WARN endpoint-gateway: upgraded connection ended: {err}");
                    }
                }
                Err(err) => eprintln!("WARN endpoint-gateway: upgrade failed: {err}"),
            }
        });
    }
    response
}

/// Remove one cookie from the `Cookie` header, leaving the rest as the caller sent them.
fn strip_cookie(headers: &mut HeaderMap, name: &str) {
    let remaining: Vec<String> = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.starts_with(&format!("{name}=")))
        .map(ToOwned::to_owned)
        .collect();
    headers.remove(header::COOKIE);
    if !remaining.is_empty()
        && let Ok(value) = axum::http::HeaderValue::from_str(&remaining.join("; "))
    {
        headers.insert(header::COOKIE, value);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_gates_own_cookie_never_reaches_the_application() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("app_session=abc; __Host-weebo-endpoint=sealed; theme=dark"),
        );
        strip_cookie(&mut headers, HOST_COOKIE);
        let remaining = headers.get(header::COOKIE).unwrap().to_str().unwrap();
        assert!(!remaining.contains("weebo-endpoint"), "{remaining}");
        // ...and the application's own cookies are untouched, which is the half a naive
        // implementation drops.
        assert!(remaining.contains("app_session=abc"));
        assert!(remaining.contains("theme=dark"));
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn a_request_with_only_our_cookie_arrives_with_no_cookie_header_at_all() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("__Host-weebo-endpoint=sealed"),
        );
        strip_cookie(&mut headers, HOST_COOKIE);
        assert!(headers.get(header::COOKIE).is_none());
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_host_comes_from_the_header_or_from_an_absolute_form_uri() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("alice-ws-api.weebo.si"),
        );
        let uri: Uri = "/api/items".parse().unwrap();
        assert_eq!(
            host_of(&headers, &uri).unwrap().as_str(),
            "alice-ws-api.weebo.si"
        );

        let absolute: Uri = "http://bob-ws-api.weebo.si/x".parse().unwrap();
        assert_eq!(
            host_of(&HeaderMap::new(), &absolute).unwrap().as_str(),
            "bob-ws-api.weebo.si"
        );
        assert!(host_of(&HeaderMap::new(), &uri).is_none());
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn hop_by_hop_headers_are_the_ones_that_belong_to_one_connection() {
        // `Connection` and `Upgrade` are deliberately absent from the list: an upgrade has to be
        // forwarded for a WebSocket to work at all, and is then honoured on both sides.
        assert!(!HOP_BY_HOP.contains(&"upgrade"));
        assert!(!HOP_BY_HOP.contains(&"connection"));
        assert!(HOP_BY_HOP.contains(&"transfer-encoding"));
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod shell_equivalence {
    //! The one test RFC 0009 asks for by name: *"one test asserting the two shells produce the
    //! same verdict for the same request"*.
    //!
    //! Asserted at the point where the two shells could actually diverge — how each one builds
    //! the `AuthRequest` — rather than against a running server, because that is the difference
    //! a refactor introduces and a live test would hide behind a network.

    use axum::http::HeaderValue;
    use weebo_si_endpoint_auth::decide::{RequestShape, Scheme};

    use super::*;

    /// What a forward-auth dialect states, and what the same request looks like arriving at a
    /// reverse-proxy shell.
    fn both_shapes() -> (HeaderMap, HeaderMap) {
        let mut forward = HeaderMap::new();
        for (name, value) in [
            ("x-forwarded-host", "alice-ws-api.weebo.si"),
            ("x-forwarded-uri", "/api/items?page=2"),
            ("x-forwarded-method", "POST"),
            ("x-forwarded-proto", "https"),
            ("accept", "application/json"),
        ] {
            forward.insert(name, HeaderValue::from_static(value));
        }

        let mut carried = HeaderMap::new();
        carried.insert(
            header::HOST,
            HeaderValue::from_static("alice-ws-api.weebo.si"),
        );
        carried.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        carried.insert("accept", HeaderValue::from_static("application/json"));
        (forward, carried)
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn the_two_shells_see_the_same_request() {
        let (forward, carried) = both_shapes();
        // The forward-auth shell reads the four inputs the controller stated.
        let stated_host = forward
            .get("x-forwarded-host")
            .and_then(|value| value.to_str().ok())
            .unwrap();
        let from_forward_auth = (
            Host::parse(stated_host).unwrap(),
            forward
                .get("x-forwarded-uri")
                .and_then(|value| value.to_str().ok())
                .unwrap()
                .to_owned(),
            Method::parse(
                forward
                    .get("x-forwarded-method")
                    .and_then(|value| value.to_str().ok())
                    .unwrap(),
            ),
            crate::http::shape_of(&forward),
        );

        // The reverse-proxy shell reads them off the request it is about to carry.
        let uri: Uri = "/api/items?page=2".parse().unwrap();
        let from_reverse_proxy = (
            host_of(&carried, &uri).unwrap(),
            uri.path_and_query().map(ToString::to_string).unwrap(),
            Method::parse("POST"),
            crate::http::shape_of(&carried),
        );

        assert_eq!(from_forward_auth, from_reverse_proxy);
        assert_eq!(from_forward_auth.3, RequestShape::Other);
    }

    #[ignore = "OpenShift's ReverseProxy dialect is deferred (RFC 0009): the code is here, nothing has run it against a router, and the base suite does not assert it. Run this tier with `task test:openshift`."]
    #[test]
    fn a_reverse_proxy_request_without_the_proto_header_is_still_https() {
        // The OpenShift router terminates TLS and does not always restate it. Defaulting to
        // `http` here would refuse every request on the dialect with a `421`.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_static("alice-ws-api.weebo.si"),
        );
        let proto = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("https");
        assert_eq!(proto, "https");
        assert_eq!(
            if proto.eq_ignore_ascii_case("https") {
                Scheme::Https
            } else {
                Scheme::Http
            },
            Scheme::Https
        );
    }
}
