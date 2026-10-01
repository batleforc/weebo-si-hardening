//! The HTTP surface — RFC 0009's table of paths, and the three shapes a challenge takes.
//!
//! Everything here is shell. The decision is `weebo_si_endpoint_auth::decide`, reached through
//! `Gateway::authorize`; this module's job is to turn a controller's forward-auth request into
//! an `AuthRequest`, and a verdict back into the response that particular caller can act on.
//!
//! Two details in here are load-bearing rather than cosmetic:
//!
//! * **`/auth` accepts any method and never reads the one it was called with.** Traefik replays
//!   the original method while nginx's `auth_request` always sends `GET`, so the method under
//!   decision is `X-Forwarded-Method` — the one the controller *states* — and never the
//!   transport's own.
//! * **The four inputs arrive either as headers or as query parameters, never mixed.** The Nginx
//!   dialect carries them in the URL because `allow-snippet-annotations` is off by default; a
//!   request arriving with both is refused rather than merged, because "the header says one path
//!   and the query says another" is the path-confusion bug this design spends a section closing.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::routing::{any, get, post};
use weebo_si_endpoint_auth::cache::Fingerprint;
use weebo_si_endpoint_auth::decide::{
    AuthRequest, Challenge, Reason, RequestShape, Scheme, Verdict,
};
use weebo_si_endpoint_auth::host::{ClientAddress, Host};
use weebo_si_endpoint_auth::identity::Claims;
use weebo_si_endpoint_auth::policy::Method;

use weebo_si_endpoint_auth::{Gateway, GatewayPorts, Presented};

use crate::adapters::session::{Binding, LoginState, SealedCodec, SealedPayload, random_id};
use crate::state::GatewayState;

/// The cookie the gateway's own host carries.
pub const SSO_COOKIE: &str = "__Host-weebo-sso";
/// The cookie an endpoint host carries.
pub const HOST_COOKIE: &str = "__Host-weebo-endpoint";
/// The query parameter a one-time grant arrives in.
pub const GRANT_PARAM: &str = "__weebo_grant";
/// The cookie a sign-in in flight carries between `/oidc/start` and `/oidc/callback`.
pub const STATE_COOKIE: &str = "__Host-weebo-state";
/// How long a sign-in may take between `/oidc/start` and `/oidc/callback`.
const LOGIN_STATE_TTL_SECS: u64 = 600;

/// Every path this binary serves on its main listener.
///
/// `/metrics` is here only when `metrics_listen` is empty; otherwise it is served on its own
/// listener by [`metrics_router`], so that nothing routed to the main port — and in particular
/// nothing the public `Ingress` forwards — can reach it.
pub fn router(state: Arc<GatewayState>) -> Router {
    let router = Router::new()
        .route("/auth", any(auth))
        .route("/oidc/start", get(oidc_start))
        .route("/oidc/callback", get(oidc_callback))
        .route("/host-session", get(host_session))
        .route("/sign_out", post(sign_out).get(sign_out_form))
        .route("/oidc/backchannel-logout", post(backchannel_logout))
        .route("/selftest", get(selftest))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));
    let router = if state.config.metrics_listen.is_empty() {
        router.route("/metrics", get(metrics))
    } else {
        router
    };
    router
        // Anything else: a `404` on a forward-auth deployment, and the application's own traffic
        // on a `ReverseProxy` one. One router, two shells, one `decide()`.
        .fallback(crate::proxy::fallback)
        // ...and before any of the routes above is matched, an endpoint host's request is the
        // application's whatever its path — see `proxy::is_endpoint_traffic`.
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            endpoint_traffic_first,
        ))
        .with_state(state)
}

/// Hand a governed host's request to the reverse-proxy shell before this gateway's own routes
/// can claim its path.
async fn endpoint_traffic_first(
    State(state): State<Arc<GatewayState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if crate::proxy::is_endpoint_traffic(
        state.config.reverse_proxy,
        &state.scope,
        request.headers(),
        request.uri(),
    ) {
        let peer = request
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|ConnectInfo(peer)| *peer);
        return crate::proxy::serve(state, peer, request).await;
    }
    next.run(request).await
}

/// The metrics listener's paths: `/metrics` and nothing else.
pub fn metrics_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(state)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The four inputs, from headers or from the query, never from both.
pub(crate) struct Forwarded {
    host: String,
    uri: String,
    method: String,
    proto: String,
}

pub(crate) enum ForwardedError {
    Missing,
    Mixed,
}

pub(crate) fn forwarded(
    headers: &HeaderMap,
    query: &HashMap<String, String>,
) -> Result<Forwarded, ForwardedError> {
    let from_headers = header_str(headers, "x-forwarded-host").is_some();
    let from_query = query.contains_key("host");
    match (from_headers, from_query) {
        (true, true) => Err(ForwardedError::Mixed),
        (true, false) => Ok(Forwarded {
            host: header_str(headers, "x-forwarded-host")
                .unwrap_or_default()
                .to_owned(),
            uri: header_str(headers, "x-forwarded-uri")
                .unwrap_or("/")
                .to_owned(),
            method: header_str(headers, "x-forwarded-method")
                .unwrap_or("GET")
                .to_owned(),
            proto: header_str(headers, "x-forwarded-proto")
                .unwrap_or("https")
                .to_owned(),
        }),
        (false, true) => Ok(Forwarded {
            host: query.get("host").cloned().unwrap_or_default(),
            uri: query.get("uri").cloned().unwrap_or_else(|| "/".to_owned()),
            method: query
                .get("method")
                .cloned()
                .unwrap_or_else(|| "GET".to_owned()),
            proto: query
                .get("proto")
                .cloned()
                .unwrap_or_else(|| "https".to_owned()),
        }),
        (false, false) => Err(ForwardedError::Missing),
    }
}

/// How to challenge this caller, read from the request rather than from configuration.
pub fn shape_of(headers: &HeaderMap) -> RequestShape {
    if let Some("iframe" | "frame") = header_str(headers, "sec-fetch-dest") {
        return RequestShape::Framed;
    }
    let navigation = header_str(headers, "sec-fetch-mode") == Some("navigate")
        || header_str(headers, "accept").is_some_and(|accept| accept.contains("text/html"));
    if navigation {
        RequestShape::Navigation
    } else {
        RequestShape::Other
    }
}

/// A genuine CORS preflight is the *pair* of preflight headers, not merely an `OPTIONS`.
pub fn is_preflight(headers: &HeaderMap, method: Method) -> bool {
    method == Method::Options
        && headers.contains_key("access-control-request-method")
        && headers.contains_key("origin")
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().to_owned())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    header_str(headers, "authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
}

fn query_of(uri: &str) -> HashMap<String, String> {
    uri.split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// What a request presented, built identically for both shells — the forward-auth handler and
/// the reverse-proxy one — so the two cannot drift about which header carries what.
///
/// `peer` is the connection's own address, which only the proxy shell has: it is what decides
/// whether the client-address header may be believed at all.
pub fn presented_from(
    state: &GatewayState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Presented {
    let header = state
        .config
        .self_origin
        .client_ip_header
        .to_ascii_lowercase();
    let stated = header_str(headers, &header).map(ClientAddress::new);
    let client_address = match (state.trusts_client_address(peer), stated) {
        (true, stated) => stated,
        // The header is not believed, so it is not read. Dropping it here rather than deciding
        // on it later is what keeps "the controller derived this" and "a caller stated this"
        // from ever being the same value to the decision.
        (false, _) => None,
    };
    Presented {
        cookie: cookie(headers, HOST_COOKIE),
        bearer: bearer(headers),
        client_address,
    }
}

/// The request under decision, built from what the controller stated and how the caller asked.
///
/// **One constructor, two shells.** The forward-auth handler reads the four inputs out of
/// `X-Forwarded-*` (or the Nginx query parameters) and the reverse-proxy shell reads them off the
/// request it is about to carry — and then both call this, so the property RFC 0009 asks for
/// ("the two shells produce the same verdict for the same request") is a matter of construction
/// rather than of two code paths staying in step.
pub fn auth_request(
    state: &GatewayState,
    host: Host,
    raw_path: String,
    method: Method,
    proto: &str,
    headers: &HeaderMap,
) -> AuthRequest {
    AuthRequest {
        host,
        raw_path,
        method,
        scheme: if proto.eq_ignore_ascii_case("https") {
            Scheme::Https
        } else {
            Scheme::Http
        },
        shape: shape_of(headers),
        preflight: state.config.preflight && is_preflight(headers, method),
    }
}

/// `/auth` — the forward-auth decision.
async fn auth(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let started = std::time::Instant::now();
    let forwarded = match forwarded(&headers, &query) {
        Ok(forwarded) => forwarded,
        Err(ForwardedError::Mixed) => {
            return (
                StatusCode::BAD_REQUEST,
                "the request arrived with both forwarded headers and query parameters; a dialect \
                 declares one transport and this gateway will not merge two",
            )
                .into_response();
        }
        Err(ForwardedError::Missing) => {
            return (
                StatusCode::BAD_REQUEST,
                "no forwarded host: /auth is called by an ingress controller, not directly",
            )
                .into_response();
        }
    };

    let Ok(host) = Host::parse(&forwarded.host) else {
        return (StatusCode::FORBIDDEN, "unusable host").into_response();
    };
    let method = Method::parse(&forwarded.method);
    let request = auth_request(
        &state,
        host.clone(),
        forwarded.uri.clone(),
        method,
        &forwarded.proto,
        &headers,
    );

    // A one-time grant redeems itself here, because the endpoint host has no other path to the
    // gateway: the response is a redirect to the same URL without the parameter, carrying the
    // host cookie. Traefik returns a non-2xx auth response verbatim, `Set-Cookie` included,
    // which is the one property the two-cookie design cannot work without.
    let params = query_of(&forwarded.uri);
    // Only a value shaped like one this gateway sealed: an application's own `__weebo_grant`
    // parameter is the application's, and is decided on like any other request rather than
    // refused as a grant that does not open.
    if let Some(grant) = params
        .get(GRANT_PARAM)
        .filter(|grant| SealedCodec::looks_sealed(grant))
    {
        return redeem(&state, &host, grant, &forwarded.uri);
    }

    let presented = presented_from(&state, &headers, None);

    // The only I/O on this path, and it is deliberately *outside* the decision: a service-account
    // token that is not cached yet costs one `TokenReview`, and an opaque one costs one
    // introspection — both here, where a reader can see them, never inside `decide()`. Each is
    // once per token rather than once per request, which is what makes a page load of two hundred
    // assets pay for neither.
    state
        .prewarm_bearer(
            presented.bearer.as_deref(),
            Some(&state.limit_key(&headers, None)),
        )
        .await;

    // A key rotation invalidates every cached bearer: the claims in the cache were verified
    // against keys this issuer no longer publishes, and a cache is not allowed to be the reason
    // one of them still passes.
    state.drop_identities_on_key_rotation();

    let authorized = state.gateway().authorize_resolved(&request, &presented);
    let outcome = authorized.outcome;
    state
        .metrics
        .decided(outcome.decision, started.elapsed().as_secs_f64());
    if outcome.decision.reason == Reason::NoIdentity && presented.client_address.is_some() {
        state.metrics.self_origin_unknown();
    }
    state.log_decision(&request, &outcome, &presented);

    match outcome.answered {
        Verdict::Allow => {
            let mut response = StatusCode::OK.into_response();
            // Overwritten rather than merged, so a caller cannot present them itself — and
            // written from the credential the decision was made on, never re-derived.
            if let Some(claims) = authorized.person() {
                set_identity_headers(response.headers_mut(), claims);
            }
            // Sliding re-mint past half-life: an endpoint in continuous use never expires under
            // the person using it, and a submit after a long lunch still fails as a `401` the
            // application can surface rather than as a redirect that discards the body.
            if let Some(sealed) = state.slide(&request, &presented)
                && let Ok(value) = HeaderValue::from_str(&sealed)
            {
                response.headers_mut().insert(header::SET_COOKIE, value);
            }
            response
        }
        Verdict::Deny => deny_response(&state, &request, outcome.decision.reason),
        Verdict::Challenge(challenge) => {
            challenge_response(&state, &request, challenge, &presented)
        }
    }
}

pub fn set_identity_headers(headers: &mut HeaderMap, claims: &Claims) {
    let groups = claims
        .groups
        .iter()
        .map(|group| group.as_str())
        .collect::<Vec<_>>()
        .join(",");
    for (name, value) in [
        ("x-auth-request-user", claims.username.as_str()),
        ("x-auth-request-groups", groups.as_str()),
    ] {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    }
}

pub fn deny_response(state: &GatewayState, request: &AuthRequest, reason: Reason) -> Response {
    if reason == Reason::InsecureScheme {
        return (
            StatusCode::MISDIRECTED_REQUEST,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "This endpoint is served over plain HTTP. The platform's session cookie requires \
             TLS, so it cannot hold a session here. Serve the endpoint over https.",
        )
            .into_response();
    }
    let owner = state
        .owner_of(&request.host)
        .filter(|_| state.config.reveal_owner);
    let body = match owner {
        Some(owner) => format!(
            "You are not permitted to reach this endpoint. It belongs to {owner}; ask them to \
             share it with you.\n"
        ),
        None => "You are not permitted to reach this endpoint.\n".to_owned(),
    };
    (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

pub fn challenge_response(
    state: &GatewayState,
    request: &AuthRequest,
    challenge: Challenge,
    presented: &Presented,
) -> Response {
    let target = format!(
        "{}/host-session?rd={}",
        state.config.redirect_base(),
        crate::adapters::oidc::urlencode(&format!("https://{}{}", request.host, request.raw_path))
    );
    match challenge {
        Challenge::Redirect => redirect(&target),
        Challenge::FramedPage => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "<!doctype html><html lang=\"en\"><body style=\"font-family:system-ui;padding:2rem\">\
                 <h1>Sign in to see this endpoint</h1>\
                 <p>This preview is shown inside the IDE, and the sign-in page cannot be framed.</p>\
                 <p><a href=\"{target}\" target=\"_blank\" rel=\"noopener\">Open it in a new tab</a>, \
                 then reload this panel.</p></body></html>"
            ),
        )
            .into_response(),
        Challenge::Unauthorized => {
            // Naming which check refused the token is the difference between a five-second fix
            // and an afternoon of reading one's own `fetch` wrapper — and the two answers a
            // client has to tell apart are exactly these: `invalid_token` means renew and retry,
            // while a token belonging to somebody not allowed here is the `403` above. Worth one
            // signature check because it is on the *denial* path, which is rare when the feature
            // is working and is itself the signal when it is not.
            let refused = presented
                .bearer
                .as_deref()
                .map(|token| state.verifier.examine(token, state.now()).result);
            let mut authenticate = format!(
                "Bearer realm=\"weebo\", authorization_uri=\"{}\"",
                state.config.redirect_base()
            );
            let mut body = "Not signed in. Open this URL in a browser to sign in, or present a \
                            bearer token this cluster's identity provider minted for this \
                            gateway's audience.\n"
                .to_owned();
            if let Some(refused) = refused {
                authenticate = format!(
                    "Bearer realm=\"weebo\", error=\"invalid_token\", error_description=\"{}\", \
                     authorization_uri=\"{}\"",
                    // No quote can reach a header value that is quoted-string syntax.
                    refused.advice().replace('"', "'"),
                    state.config.redirect_base()
                );
                body = format!(
                    "The token you presented was refused: {refused}.\n{}\n",
                    refused.advice()
                );
            }
            (
                StatusCode::UNAUTHORIZED,
                [
                    (header::WWW_AUTHENTICATE, authenticate),
                    (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
                ],
                body,
            )
                .into_response()
        }
    }
}

fn redirect(target: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, target.to_owned())],
        "",
    )
        .into_response()
}

/// `uri` with every `name=` query parameter removed and everything else — path, other
/// parameters, their order and encoding — left exactly as it was.
///
/// Used to drop the grant from the URL a redemption redirects to. It used to drop the whole query
/// string, which silently discarded whatever the application had in it (a search, a deep link's
/// id) on the one redirect a developer never sees.
pub fn strip_query_param(uri: &str, name: &str) -> String {
    let Some((path, query)) = uri.split_once('?') else {
        return uri.to_owned();
    };
    let kept = query
        .split('&')
        .filter(|pair| {
            let key = pair.split_once('=').map_or(*pair, |(key, _)| key);
            !pair.is_empty() && key != name
        })
        .collect::<Vec<_>>();
    if kept.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", kept.join("&"))
    }
}

/// The endpoint host a return URL names, if it is one this gateway governs — the closed
/// redirector both `/oidc/start` and `/host-session` apply to `rd`.
///
/// An open redirector in front of every workspace endpoint is a phishing primitive; the suffix is
/// what makes this one closed.
///
/// Second pass (finding 10): a `#` anywhere is refused — a fragment has no business in a return
/// URL this gateway appends a grant to, and `https://a.weebo.si#@evil` is exactly the shape
/// parser disagreements are made of — and so is any explicit port but `:443`, since no endpoint
/// of this cluster is served on another one and `Host::parse` would otherwise drop the port
/// silently and approve a URL that goes somewhere else.
pub fn endpoint_target(
    scope: &weebo_si_endpoint_auth::host::HostScope,
    target: &str,
) -> Option<Host> {
    if target.contains('#') {
        return None;
    }
    let authority = target.strip_prefix("https://")?.split(['/', '?']).next()?;
    if let Some((_, port)) = authority.rsplit_once(':')
        && port != "443"
    {
        return None;
    }
    Host::parse(authority)
        .ok()
        .filter(|host| scope.governs(host))
}

/// A host cookie's expiry: `host_ttl` from now, and never past the SSO session it came from.
pub fn capped_expiry(now: u64, ttl: u64, session_expires_at: Option<u64>) -> u64 {
    let wanted = now.saturating_add(ttl);
    session_expires_at.map_or(wanted, |cap| wanted.min(cap))
}

/// Where a redemption sends the browser: the same URL on the same host, minus the grant — or
/// `None` when `uri` is not a path, because `https://{host}{uri}` with `uri = "@evil.example/"`
/// is a URL on somebody else's host.
pub fn same_host_location(host: &Host, uri: &str) -> Option<String> {
    uri.starts_with('/')
        .then(|| format!("https://{host}{}", strip_query_param(uri, GRANT_PARAM)))
}

/// Redeem a one-time grant into a host cookie.
fn redeem(state: &GatewayState, host: &Host, grant: &str, uri: &str) -> Response {
    // The redirect is `https://{host}{uri}`, so a `uri` that is not a path would rewrite the
    // authority: `@evil.example/` makes it `https://alice.weebo.si@evil.example/`. The controller
    // always sends a path; anything else is refused before any cryptography.
    let Some(location) = same_host_location(host, uri) else {
        return (StatusCode::BAD_REQUEST, "the forwarded URI is not a path").into_response();
    };
    let now = state.now();
    let Some(payload) = state
        .codec
        .open(grant, Binding::HostBound(host.as_str()), now)
    else {
        return (StatusCode::FORBIDDEN, "this grant is not usable here").into_response();
    };
    let Some(id) = payload.grant_id.clone() else {
        return (StatusCode::FORBIDDEN, "not a grant").into_response();
    };
    if !state.redeem_grant(&id, now) {
        // At-most-once *per replica*, and that is the whole claim: the grant is sealed, bound to
        // one host, and valid for thirty seconds, so what a second redemption yields is a cookie
        // for an identity its holder already had.
        return (StatusCode::FORBIDDEN, "this grant has already been used").into_response();
    }
    let expires_at = capped_expiry(
        now.as_secs(),
        state.config.session.host_ttl_secs,
        payload.session_expires_at,
    );
    let session = SealedPayload {
        expires_at,
        grant_id: None,
        // A host cookie travels to the endpoint host, so it carries no refresh token: the one
        // credential that could mint new sessions stays on the gateway's own host.
        refresh: None,
        ..payload
    };
    let Some(sealed) = state
        .codec
        .seal(&session, Binding::HostBound(host.as_str()))
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not mint a session",
        )
            .into_response();
    };
    let cookie = format!(
        "{HOST_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        expires_at.saturating_sub(now.as_secs())
    );
    (
        StatusCode::FOUND,
        [(header::LOCATION, location), (header::SET_COOKIE, cookie)],
        "",
    )
        .into_response()
}

/// The per-address limit in front of the login surface — RFC 0009's *The login surface is a
/// surface*.
///
/// `/oidc/start`, `/oidc/callback`, `/host-session` and `/oidc/backchannel-logout` are reachable
/// by anyone who can resolve this gateway's host, and three of them do public-key or symmetric
/// cryptography per call. This runs **before** any of it, which is the whole point: a limiter
/// behind the signature check has already paid for the attack it exists to stop.
///
/// `/auth` is exempt. It is the hot path, the ingress controller is its only caller, and the peer
/// check of *Checking that assumption* is what protects it instead — a per-address limit there
/// would rate-limit the controller.
fn over_the_login_limit(
    state: &GatewayState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
) -> Option<Response> {
    if state.config.rate_limit.login_per_address_per_minute == 0
        || state
            .login_limiter
            .allow(&state.limit_key(headers, peer), state.now())
    {
        return None;
    }
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            "too many sign-in attempts from this address; try again in a minute\n",
        )
            .into_response(),
    )
}

/// `/host-session` — exchange the SSO cookie for a one-time grant on the target host.
async fn host_session(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Some(limited) = over_the_login_limit(&state, &headers, Some(peer)) {
        return limited;
    }
    let Some(target) = query.get("rd") else {
        return (StatusCode::BAD_REQUEST, "no target").into_response();
    };
    let Some(host) = endpoint_target(&state.scope, target) else {
        return (
            StatusCode::BAD_REQUEST,
            "target is not an endpoint of this cluster",
        )
            .into_response();
    };
    let now = state.now();
    let Some(sso) = cookie(&headers, SSO_COOKIE)
        .and_then(|sealed| state.codec.open(&sealed, Binding::Sso, now))
    else {
        return redirect(&format!(
            "{}/oidc/start?rd={}",
            state.config.redirect_base(),
            crate::adapters::oidc::urlencode(target)
        ));
    };
    if let Some(session) = sso.session.as_deref()
        && state.is_revoked(session)
    {
        return redirect(&format!(
            "{}/oidc/start?rd={}",
            state.config.redirect_base(),
            crate::adapters::oidc::urlencode(target)
        ));
    }

    // Periodic revalidation, lazily and only on use: a session that nobody is using costs
    // nothing, and one in use re-proves itself at the token endpoint — which also renews its
    // claims, so a group added this morning is not waiting for tonight's expiry.
    let (sso, refreshed) = match state.revalidate(sso).await {
        Ok(pair) => pair,
        Err(()) => {
            return redirect(&format!(
                "{}/oidc/start?rd={}",
                state.config.redirect_base(),
                crate::adapters::oidc::urlencode(target)
            ));
        }
    };
    let Some(id) = random_id() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no randomness").into_response();
    };
    let grant = SealedPayload {
        expires_at: now.plus_secs(state.config.session.grant_ttl_secs).as_secs(),
        grant_id: Some(id),
        refresh: None,
        // What every host cookie minted from this grant — and every slide of it — is capped at.
        session_expires_at: Some(sso.expires_at),
        ..sso
    };
    let Some(sealed) = state.codec.seal(&grant, Binding::HostBound(host.as_str())) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not mint a grant").into_response();
    };
    let separator = if target.contains('?') { '&' } else { '?' };
    let location = format!("{target}{separator}{GRANT_PARAM}={sealed}");
    match refreshed {
        // The session re-proved itself, so the SSO cookie is re-minted in the same response the
        // grant travels in: one round trip, not two.
        Some(sealed_sso) => (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (
                    header::SET_COOKIE,
                    format!(
                        "{SSO_COOKIE}={sealed_sso}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
                        state.config.session.sso_ttl_secs
                    ),
                ),
            ],
            "",
        )
            .into_response(),
        None => redirect(&location),
    }
}

/// `/oidc/start` — begin the authorization-code exchange.
async fn oidc_start(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Some(limited) = over_the_login_limit(&state, &headers, Some(peer)) {
        return limited;
    }
    let Some(oidc) = state.oidc() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no identity provider configured",
        )
            .into_response();
    };
    let target = query.get("rd").cloned().unwrap_or_default();
    // The same closed redirector `/host-session` applies, here too: the return URL rides through
    // the identity provider and back, and a sign-in that ends on somebody else's site is the
    // phishing primitive that check exists to remove. Empty is allowed and means "the gateway's
    // own page".
    if !target.is_empty() && endpoint_target(&state.scope, &target).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "target is not an endpoint of this cluster",
        )
            .into_response();
    }
    let Some((sealed, location)) = start_login(&state.codec, oidc, target, state.now()) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not mint state").into_response();
    };
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (
                header::SET_COOKIE,
                format!(
                    "{STATE_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; \
                     Max-Age={LOGIN_STATE_TTL_SECS}"
                ),
            ),
        ],
        "",
    )
        .into_response()
}

/// Mint the sealed sign-in state and the authorization URL it goes with.
///
/// State and verifier travel in a sealed, short-lived cookie rather than in server memory: three
/// replicas behind one Service means the callback can land on a different one than the start did,
/// and a server-side map would make a sign-in fail two times out of three. Sealed against
/// [`Binding::LoginState`] as a [`LoginState`] — never as an SSO payload, which is what made the
/// state cookie replayable as a session (B1).
fn start_login(
    codec: &crate::adapters::session::SealedCodec,
    oidc: &crate::adapters::oidc::OidcClient,
    return_to: String,
    now: weebo_si_endpoint_auth::time::Timestamp,
) -> Option<(String, String)> {
    let (verifier, id) = (random_id()?, random_id()?);
    let login = LoginState {
        return_to,
        verifier,
        state: id,
        expires_at: now.plus_secs(LOGIN_STATE_TTL_SECS).as_secs(),
    };
    let sealed = codec.seal_login_state(&login)?;
    Some((
        sealed,
        oidc.authorization_url(&login.state, &login.verifier),
    ))
}

/// The `Set-Cookie` that removes the sign-in state — sent by the callback on every answer once
/// the state has been read, and by `/sign_out`, so a used or abandoned state does not linger for
/// its ten minutes.
fn clear_state_cookie() -> String {
    format!("{STATE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// `/oidc/callback` — the only registered redirect URI.
async fn oidc_callback(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Some(limited) = over_the_login_limit(&state, &headers, Some(peer)) {
        return limited;
    }
    let Some(oidc) = state.oidc() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no identity provider configured",
        )
            .into_response();
    };
    let now = state.now();
    // Every answer from here on clears the state cookie: it is single-use, and one that failed
    // is one to start again from rather than to retry.
    let clear = AppendHeaders([(header::SET_COOKIE, clear_state_cookie())]);
    let (Some(code), Some(returned_state)) = (query.get("code"), query.get("state")) else {
        // The identity provider's `error=access_denied` lands here too, and the sign-in it ends
        // is over: its state is cleared like every other answer's (second-pass finding 9).
        state.metrics.login("bad_request");
        return (StatusCode::BAD_REQUEST, clear, "no code").into_response();
    };
    let Some(stored) = cookie(&headers, STATE_COOKIE)
        .and_then(|sealed| state.codec.open_login_state(&sealed, now))
    else {
        state.metrics.login("no_state");
        return (
            StatusCode::BAD_REQUEST,
            clear,
            "no state cookie; start again",
        )
            .into_response();
    };
    if !constant_time_eq(&stored.state, returned_state) {
        state.metrics.login("state_mismatch");
        return (StatusCode::BAD_REQUEST, clear, "state mismatch").into_response();
    }
    let tokens = match oidc.exchange(code, &stored.verifier).await {
        Ok(tokens) => tokens,
        Err(err) => {
            state.metrics.login("exchange_failed");
            eprintln!("WARN endpoint-gateway: code exchange failed: {err}");
            return (StatusCode::BAD_GATEWAY, clear, "sign-in failed").into_response();
        }
    };
    let Some(claims) = state.claims_of_id_token(&tokens.id_token) else {
        state.metrics.login("unusable_id_token");
        return (
            StatusCode::BAD_GATEWAY,
            clear,
            "the identity provider's token is unusable",
        )
            .into_response();
    };
    let sso = SealedPayload {
        username: claims.username.as_str().to_owned(),
        // Only the groups some endpoint in the cluster actually names, capped: sealing every
        // group a directory hands out is how a 4 KB cookie limit becomes a login loop.
        groups: state.catalog.filter_groups(
            claims.groups.iter().map(|group| group.as_str().to_owned()),
            state.config.session.max_groups,
        ),
        session: claims.session.as_ref().map(|sid| sid.as_str().to_owned()),
        expires_at: now.plus_secs(state.config.session.sso_ttl_secs).as_secs(),
        generation: state.catalog.groups_generation(),
        grant_id: None,
        proved_at: now.as_secs(),
        refresh: tokens.refresh_token.clone(),
        session_expires_at: None,
    };
    let Some(sealed) = state.codec.seal(&sso, Binding::Sso) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            clear,
            "could not mint a session",
        )
            .into_response();
    };
    state.metrics.login("success");
    // No return URL: the sign-in was started from the gateway's own host, and there is no
    // endpoint to go on to. Anything else was checked at `/oidc/start` and is checked again by
    // `/host-session`.
    if stored.return_to.is_empty() {
        return (
            StatusCode::OK,
            AppendHeaders([
                (header::SET_COOKIE, clear_state_cookie()),
                (header::SET_COOKIE, sso_cookie(&state, &sealed)),
            ]),
            "Signed in.\n",
        )
            .into_response();
    }
    (
        StatusCode::FOUND,
        [(
            header::LOCATION,
            format!(
                "{}/host-session?rd={}",
                state.config.redirect_base(),
                crate::adapters::oidc::urlencode(&stored.return_to)
            ),
        )],
        AppendHeaders([
            (header::SET_COOKIE, clear_state_cookie()),
            (header::SET_COOKIE, sso_cookie(&state, &sealed)),
        ]),
        "",
    )
        .into_response()
}

fn sso_cookie(state: &GatewayState, sealed: &str) -> String {
    format!(
        "{SSO_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        state.config.session.sso_ttl_secs
    )
}

/// `POST /sign_out` — clears the SSO cookie and any sign-in in flight.
///
/// **What it does not do**, on purpose: record a revocation. The only session id this gateway
/// holds is the identity provider's `sid`, and revoking it here would outlive the sign-out — a
/// sign-in straight after, silently re-using the same provider session, gets the same `sid` back
/// and would be refused until the revocation expired. Host cookies already minted on endpoint
/// hosts are therefore not reachable from here (they are host-only cookies on other origins) and
/// live out their `host_ttl_secs`; ending *those* is back-channel logout's job, which revokes by
/// `sid` because the identity provider has ended that session. See RFC 0009's changelog.
///
/// **Same-origin only** (second-pass finding 8). A cross-site form auto-submitting here signs the
/// victim out — a nuisance rather than a compromise, and precisely the nuisance that makes
/// "log in again" phishing believable. The browser's `Sec-Fetch-Site` decides where it is sent;
/// failing that, an `Origin` equal to this gateway's own; with neither, the request is refused.
async fn sign_out(State(state): State<Arc<GatewayState>>, headers: HeaderMap) -> Response {
    if !same_origin_post(&headers, state.config.redirect_base()) {
        return (
            StatusCode::FORBIDDEN,
            "sign-out is accepted from this gateway's own page only\n",
        )
            .into_response();
    }
    signed_out()
}

/// Whether a state-changing `POST` came from the gateway's own origin.
pub fn same_origin_post(headers: &HeaderMap, redirect_base: &str) -> bool {
    if let Some(site) = header_str(headers, "sec-fetch-site") {
        return matches!(site, "same-origin" | "none");
    }
    let own = origin_of(redirect_base);
    header_str(headers, "origin").is_some_and(|origin| origin.eq_ignore_ascii_case(own))
}

/// `scheme://authority` of a URL, without its path.
fn origin_of(url: &str) -> &str {
    let after_scheme = url.find("://").map_or(0, |at| at + 3);
    match url[after_scheme..].find('/') {
        Some(slash) => &url[..after_scheme + slash],
        None => url,
    }
}

/// The response that ends a session on this browser.
fn signed_out() -> Response {
    (
        StatusCode::OK,
        AppendHeaders([
            (
                header::SET_COOKIE,
                format!("{SSO_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
            ),
            (header::SET_COOKIE, clear_state_cookie()),
        ]),
        "Signed out.\n",
    )
        .into_response()
}

/// `GET /sign_out` — the form that posts to it.
///
/// A `GET` that destroys a session is reachable from any page on the suffix with one `<img>`
/// tag; the cost of the form is one click and the bug class goes away.
async fn sign_out_form() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<!doctype html><html lang=\"en\"><body style=\"font-family:system-ui;padding:2rem\">\
         <form method=\"post\" action=\"/sign_out\"><button type=\"submit\">Sign out</button></form>\
         </body></html>",
    )
        .into_response()
}

/// `POST /oidc/backchannel-logout` — the identity provider telling us a session ended.
async fn backchannel_logout(
    State(state): State<Arc<GatewayState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !state.config.backchannel_logout.enabled {
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    // Its own bucket, not the sign-in one (second-pass finding 5): every call comes from the
    // identity provider's one egress address, and a realm-wide logout is a burst from it that
    // the provider will not retry. Over the limit is `503` — "not now", which is what it is —
    // rather than a `429` that reads as the provider misbehaving.
    if state.config.rate_limit.backchannel_logout_per_minute > 0
        && !state
            .logout_limiter
            .allow(&state.limit_key(&headers, Some(peer)), state.now())
    {
        eprintln!("WARN endpoint-gateway: back-channel logout over its rate limit; answered 503");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "5")],
            "back-channel logout is over its rate limit\n",
        )
            .into_response();
    }
    let Some(token) = body
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "logout_token")
        .map(|(_, value)| value.to_owned())
    else {
        return (StatusCode::BAD_REQUEST, "no logout_token").into_response();
    };
    match state.revoke_from_logout_token(&token).await {
        Ok(Some(session)) => {
            println!("endpoint-gateway: revoked session {session}");
            StatusCode::OK.into_response()
        }
        Ok(None) => (StatusCode::BAD_REQUEST, "logout token carried no session").into_response(),
        Err(crate::adapters::kube_revocations::RevokeError::Full) => {
            // Loud, because the alternative is a logout that silently did not happen.
            state.metrics.revocation_refused("full");
            eprintln!(
                "ERROR endpoint-gateway: revocation NOT recorded: the revocation ConfigMap holds \
                 {} live sessions; this logout is not in effect",
                crate::adapters::kube_revocations::MAX_REVOCATIONS
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "the revocation set is full; the session was not revoked",
            )
                .into_response()
        }
        Err(err) => {
            state.metrics.revocation_refused("write_failed");
            eprintln!("WARN endpoint-gateway: revocation failed: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not record the revocation",
            )
                .into_response()
        }
    }
}

/// `/selftest` — what the gate observed for this request. Reports observations, never secrets,
/// and answers nothing at all to a caller that does not hold this process's own probe token.
async fn selftest(State(state): State<Arc<GatewayState>>, headers: HeaderMap) -> Response {
    let presented = header_str(&headers, "x-weebo-selftest").unwrap_or_default();
    // Any key's token, not only the newest: during a key rotation two replicas can disagree
    // about which key is first, and the probe lands on whichever the Service picks.
    let known = state.selftest_tokens.iter().fold(false, |known, token| {
        known | constant_time_eq(presented, token)
    });
    if presented.is_empty() || !known {
        return (StatusCode::NOT_FOUND, "").into_response();
    }
    let address = header_str(
        &headers,
        &state
            .config
            .self_origin
            .client_ip_header
            .to_ascii_lowercase(),
    )
    .map(ClientAddress::new);
    let namespace = address.as_ref().and_then(|address| {
        weebo_si_endpoint_auth::port::WorkloadIdentity::namespace_of_address(
            state.workloads.as_ref(),
            address,
        )
    });
    let body = serde_json::json!({
        "address_seen": address.as_ref().map(|address| address.as_str()),
        "resolved_namespace": namespace.as_ref().map(|namespace| namespace.as_str()),
        "addresses_trusted": state.workloads.addresses_trusted(),
        "address_forgery_recorded": state.revocations.address_forgery_recorded(),
        "indexed_endpoints": state.catalog.len(),
        // How many groups any endpoint in this cluster actually names. One is the common answer,
        // and a large one is the diagnosis behind "why did my session get re-authenticated".
        "interesting_groups": state.catalog.interesting_group_count(),
        "groups_generation": state.catalog.groups_generation(),
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

/// Compare two secrets in time that depends on neither's contents.
///
/// Both sides are hashed first, so the comparison is always over 32 bytes and the length of the
/// secret leaks no more than its contents do; the fold then touches every byte whatever the first
/// difference is.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    use sha2::{Digest, Sha256};

    let (left, right) = (
        Sha256::digest(left.as_bytes()),
        Sha256::digest(right.as_bytes()),
    );
    left.iter()
        .zip(right.iter())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

async fn healthz() -> Response {
    (StatusCode::OK, "ok\n").into_response()
}

/// `/readyz` — informer-cache readiness. A cold replica must not answer "allow" from an empty
/// cache, which is why readiness and not just liveness is wired to it.
async fn readyz(State(state): State<Arc<GatewayState>>) -> Response {
    // Draining: out of the rotation first, so the endpoints controller stops sending new
    // requests here while the in-flight ones finish.
    if state.is_shutting_down() {
        return (StatusCode::SERVICE_UNAVAILABLE, "shutting down\n").into_response();
    }
    // Both halves, because a replica missing either one denies traffic it should allow: no index
    // means every host is unknown, and no keys mean every bearer is unverifiable.
    if !state.verifier.keys_loaded() {
        state.metrics.synced(false);
        return (StatusCode::SERVICE_UNAVAILABLE, "no signing keys yet\n").into_response();
    }
    if state.catalog.is_ready() {
        state.metrics.synced(true);
        state.metrics.indexed(
            state.catalog.len(),
            state.catalog.conflicts(),
            state.catalog.refused(),
            0.0,
        );
        (StatusCode::OK, "ready\n").into_response()
    } else {
        state.metrics.synced(false);
        (StatusCode::SERVICE_UNAVAILABLE, "informers not synced\n").into_response()
    }
}

async fn metrics(State(state): State<Arc<GatewayState>>) -> Response {
    state.publish_cache_stats();
    state.metrics.observed(
        "enforcement_observe",
        usize::from(state.enforcement == weebo_si_endpoint_auth::Enforcement::Observe),
    );
    state.metrics.revoked(state.revocations.len());
    state
        .metrics
        .token_reviews_throttled(state.workloads.reviews_throttled());
    state
        .metrics
        .address_trust(state.workloads.addresses_trusted());
    let families = state.registry.gather();
    let mut buffer = String::new();
    match prometheus::TextEncoder::new().encode_utf8(&families, &mut buffer) {
        Ok(()) => (StatusCode::OK, buffer).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

impl GatewayState {
    /// The ports, wired — rebuilt per request because a `Gateway` is a handful of references and
    /// building one costs nothing.
    pub fn gateway(&self) -> Gateway<'_> {
        Gateway::new(
            GatewayPorts {
                catalog: self.catalog.as_ref(),
                sessions: &self.codec,
                tokens: &self.verifier,
                workloads: self.workloads.as_ref(),
                revocations: self.revocations.as_ref(),
                teams: self.catalog.as_ref(),
                clock: &self.clock,
                session_cache: &self.session_cache,
                bearer_cache: &self.bearer_cache,
                service_account_cache: &self.service_account_cache,
            },
            self.enforcement,
        )
    }

    /// Whether the fingerprint of a grant has been redeemed on this replica already.
    pub fn redeem_grant(&self, id: &str, now: weebo_si_endpoint_auth::time::Timestamp) -> bool {
        let key = Fingerprint::of(id);
        if self.redeemed.get(&key, now).is_some() {
            return false;
        }
        self.redeemed.insert(
            key,
            (),
            now.plus_secs(self.config.session.grant_ttl_secs.max(60)),
            now,
        );
        true
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

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn the_four_inputs_arrive_from_headers_or_from_the_query_and_never_from_both() {
        // Traefik's dialect.
        let traefik = headers(&[
            ("x-forwarded-host", "alice-ws-api.weebo.si"),
            ("x-forwarded-uri", "/api/items"),
            ("x-forwarded-method", "POST"),
            ("x-forwarded-proto", "https"),
        ]);
        let from_headers = forwarded(&traefik, &HashMap::new()).ok().unwrap();
        assert_eq!(from_headers.host, "alice-ws-api.weebo.si");
        assert_eq!(from_headers.method, "POST");

        // The Nginx dialect, which carries them in the URL because snippets are off by default.
        let query = HashMap::from([
            ("host".to_owned(), "alice-ws-api.weebo.si".to_owned()),
            ("uri".to_owned(), "/api/items".to_owned()),
            ("method".to_owned(), "GET".to_owned()),
            ("proto".to_owned(), "https".to_owned()),
        ]);
        assert!(forwarded(&HeaderMap::new(), &query).is_ok());

        // Both is refused rather than merged: "the header says one path and the query says
        // another" is the path-confusion bug this design spends a section closing.
        assert!(matches!(
            forwarded(&traefik, &query),
            Err(ForwardedError::Mixed)
        ));
        assert!(matches!(
            forwarded(&HeaderMap::new(), &HashMap::new()),
            Err(ForwardedError::Missing)
        ));
    }

    #[test]
    fn the_challenge_shape_is_read_from_the_request() {
        assert_eq!(
            shape_of(&headers(&[("sec-fetch-dest", "iframe")])),
            RequestShape::Framed
        );
        assert_eq!(
            shape_of(&headers(&[("sec-fetch-mode", "navigate")])),
            RequestShape::Navigation
        );
        assert_eq!(
            shape_of(&headers(&[("accept", "text/html,application/xhtml+xml")])),
            RequestShape::Navigation
        );
        // An XHR: no navigation markers, so a `401` rather than a redirect the browser turns
        // into an opaque CORS failure.
        assert_eq!(
            shape_of(&headers(&[("accept", "application/json")])),
            RequestShape::Other
        );
        assert_eq!(shape_of(&HeaderMap::new()), RequestShape::Other);
    }

    #[test]
    fn a_preflight_is_the_pair_of_headers_and_not_merely_an_options() {
        let preflight = headers(&[
            ("origin", "https://alice-ws-ui.weebo.si"),
            ("access-control-request-method", "POST"),
        ]);
        assert!(is_preflight(&preflight, Method::Options));
        // An OPTIONS some frameworks route to an ordinary handler.
        assert!(!is_preflight(&HeaderMap::new(), Method::Options));
        assert!(!is_preflight(&preflight, Method::Get));
    }

    #[test]
    fn cookies_and_bearers_are_read_the_way_a_browser_sends_them() {
        let with_cookies = headers(&[(
            "cookie",
            "other=1; __Host-weebo-endpoint=sealed-value; third=3",
        )]);
        assert_eq!(
            cookie(&with_cookies, HOST_COOKIE).as_deref(),
            Some("sealed-value")
        );
        assert_eq!(cookie(&with_cookies, SSO_COOKIE), None);

        let with_bearer = headers(&[("authorization", "Bearer a.b.c")]);
        assert_eq!(bearer(&with_bearer).as_deref(), Some("a.b.c"));
        // Anything that is not a bearer is not a token this gateway will look at.
        assert_eq!(bearer(&headers(&[("authorization", "Basic abc")])), None);
    }

    #[test]
    fn the_grant_parameter_is_read_out_of_the_forwarded_uri() {
        let params = query_of("/app?x=1&__weebo_grant=v1.abc.def");
        assert_eq!(
            params.get(GRANT_PARAM).map(String::as_str),
            Some("v1.abc.def")
        );
        assert!(query_of("/app").is_empty());
    }

    fn scope() -> weebo_si_endpoint_auth::host::HostScope {
        weebo_si_endpoint_auth::host::HostScope::new(".weebo.si", ["che.weebo.si", "auth.weebo.si"])
            .unwrap()
    }

    fn codec() -> crate::adapters::session::SealedCodec {
        crate::adapters::session::SealedCodec::new(&[
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_owned(),
        ])
        .unwrap()
    }

    fn oidc() -> crate::adapters::oidc::OidcClient {
        crate::adapters::oidc::OidcClient::new(
            crate::adapters::oidc::Discovery {
                authorization_endpoint: "https://sso.weebo.si/auth".into(),
                token_endpoint: "https://sso.weebo.si/token".into(),
                jwks_uri: "https://sso.weebo.si/certs".into(),
                backchannel_logout_supported: true,
                backchannel_logout_session_supported: true,
                introspection_endpoint: None,
                claims_supported: Vec::new(),
            },
            "che-client".into(),
            String::new(),
            "https://auth.weebo.si/oidc/callback".into(),
        )
    }

    /// B1, end to end through the code `/oidc/start` runs: the state cookie it sets, replayed as
    /// the SSO cookie `/host-session` reads, used to open as a session for a "user" named after
    /// the caller's own `rd`. It must not open as an SSO cookie at all.
    #[test]
    fn the_login_state_cookie_cannot_be_replayed_as_a_session() {
        let codec = codec();
        let now = weebo_si_endpoint_auth::time::Timestamp::from_secs(1_000);
        let (sealed, location) = start_login(
            &codec,
            &oidc(),
            "https://alice-ws-api.weebo.si/".into(),
            now,
        )
        .unwrap();
        assert!(location.starts_with("https://sso.weebo.si/auth?"));
        // The attack: present it where `/host-session` looks for the SSO cookie.
        assert_eq!(codec.open(&sealed, Binding::Sso, now), None);
        // It is still the state it was meant to be, for the callback.
        let state = codec.open_login_state(&sealed, now).unwrap();
        assert_eq!(state.return_to, "https://alice-ws-api.weebo.si/");
        assert!(location.contains(&format!("state={}", state.state)));
    }

    /// B1's second half: `/oidc/start` is the same closed redirector `/host-session` is.
    #[test]
    fn a_return_url_must_be_an_endpoint_of_this_cluster() {
        let scope = scope();
        assert_eq!(
            endpoint_target(&scope, "https://alice-ws-api.weebo.si/app?x=1")
                .unwrap()
                .as_str(),
            "alice-ws-api.weebo.si"
        );
        for refused in [
            "https://evil.example/",
            "http://alice-ws-api.weebo.si/",
            "https://alice-ws-api.weebo.si.evil.example/",
            "https://evil.example\\@alice-ws-api.weebo.si/",
            "https://evil.example@alice-ws-api.weebo.si/",
            "//evil.example/",
            "https://auth.weebo.si/",
            "https://che.weebo.si/",
            "javascript:alert(1)",
        ] {
            assert!(endpoint_target(&scope, refused).is_none(), "{refused}");
        }
    }

    /// Second-pass finding 10: `rd` with a fragment or a non-443 port was approved, because the
    /// host parser drops the port and nothing looked past the authority.
    #[test]
    fn a_return_url_with_a_fragment_or_another_port_is_refused() {
        let scope = scope();
        for refused in [
            "https://alice-ws-api.weebo.si/#x",
            "https://alice-ws-api.weebo.si#@evil.example/",
            "https://alice-ws-api.weebo.si:8443/",
            "https://alice-ws-api.weebo.si:80/",
            "https://alice-ws-api.weebo.si:/",
        ] {
            assert!(endpoint_target(&scope, refused).is_none(), "{refused}");
        }
        for allowed in [
            "https://alice-ws-api.weebo.si:443/app",
            "https://alice-ws-api.weebo.si?x=1",
            "https://alice-ws-api.weebo.si",
        ] {
            assert!(endpoint_target(&scope, allowed).is_some(), "{allowed}");
        }
    }

    /// Second-pass finding 10: the redemption redirect concatenated host and forwarded URI.
    #[test]
    fn a_redemption_only_redirects_to_a_path_on_the_same_host() {
        let host = Host::parse("alice-ws-api.weebo.si").unwrap();
        assert_eq!(
            same_host_location(&host, "/app?x=1&__weebo_grant=g").as_deref(),
            Some("https://alice-ws-api.weebo.si/app?x=1")
        );
        for refused in ["@evil.example/", ".evil.example/", "", "app"] {
            assert!(same_host_location(&host, refused).is_none(), "{refused:?}");
        }
    }

    /// Second-pass finding 8: `/sign_out` accepted a cross-site `POST`.
    #[test]
    fn sign_out_is_accepted_from_the_gateways_own_origin_only() {
        let base = "https://auth.weebo.si";
        assert!(same_origin_post(
            &headers(&[("sec-fetch-site", "same-origin")]),
            base
        ));
        assert!(same_origin_post(
            &headers(&[("sec-fetch-site", "none")]),
            base
        ));
        for refused in ["cross-site", "same-site"] {
            // `Sec-Fetch-Site` wins over an `Origin` that happens to match.
            assert!(!same_origin_post(
                &headers(&[("sec-fetch-site", refused), ("origin", base)]),
                base
            ));
        }
        assert!(same_origin_post(
            &headers(&[("origin", "https://auth.weebo.si")]),
            base
        ));
        assert!(same_origin_post(
            &headers(&[("origin", "https://auth.weebo.si")]),
            "https://auth.weebo.si/prefix"
        ));
        assert!(!same_origin_post(
            &headers(&[("origin", "https://alice-ws-api.weebo.si")]),
            base
        ));
        assert!(!same_origin_post(&headers(&[("origin", "null")]), base));
        assert!(!same_origin_post(&HeaderMap::new(), base));
    }

    /// L3: redeeming a grant used to drop the whole query string with it.
    #[test]
    fn redeeming_a_grant_removes_the_grant_and_nothing_else() {
        assert_eq!(
            strip_query_param("/search?q=rust&__weebo_grant=v1.a.b&page=2", GRANT_PARAM),
            "/search?q=rust&page=2"
        );
        assert_eq!(
            strip_query_param("/app?__weebo_grant=v1.a.b", GRANT_PARAM),
            "/app"
        );
        assert_eq!(strip_query_param("/app", GRANT_PARAM), "/app");
        // A parameter whose name merely starts the same is somebody else's.
        assert_eq!(
            strip_query_param("/app?__weebo_grant_x=1&__weebo_grant=g", GRANT_PARAM),
            "/app?__weebo_grant_x=1"
        );
    }

    /// M1, at redemption: a host cookie never outlives the SSO session its grant came from.
    #[test]
    fn a_host_cookie_is_capped_at_its_sessions_expiry() {
        assert_eq!(capped_expiry(1_000, 3_600, Some(2_000)), 2_000);
        assert_eq!(capped_expiry(1_000, 3_600, Some(100_000)), 4_600);
        assert_eq!(capped_expiry(1_000, 3_600, None), 4_600);
    }

    /// L2: the probe token is compared in constant time, and still compared.
    #[test]
    fn the_selftest_token_comparison_is_exact() {
        assert!(constant_time_eq("secret-token", "secret-token"));
        assert!(!constant_time_eq("secret-token", "secret-tokeN"));
        assert!(!constant_time_eq("secret-token", "secret"));
        assert!(!constant_time_eq("", "secret-token"));
    }

    /// L1: signing out clears a sign-in in flight as well as the session.
    #[tokio::test]
    async fn signing_out_clears_the_session_and_the_login_state() {
        let response = signed_out();
        let cleared = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        for name in [SSO_COOKIE, STATE_COOKIE] {
            assert!(
                cleared
                    .iter()
                    .any(|cookie| cookie.starts_with(&format!("{name}=;"))
                        && cookie.contains("Max-Age=0")),
                "{name} not cleared: {cleared:?}"
            );
        }
    }
}
