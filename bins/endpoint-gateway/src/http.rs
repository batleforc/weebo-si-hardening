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
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use weebo_si_endpoint_auth::cache::Fingerprint;
use weebo_si_endpoint_auth::decide::{
    AuthRequest, Challenge, Reason, RequestShape, Scheme, Verdict,
};
use weebo_si_endpoint_auth::host::{ClientAddress, Host};
use weebo_si_endpoint_auth::identity::Claims;
use weebo_si_endpoint_auth::policy::Method;

use weebo_si_endpoint_auth::{Gateway, GatewayPorts, Presented};

use crate::adapters::session::{Binding, SealedPayload, random_id};
use crate::state::GatewayState;

/// The cookie the gateway's own host carries.
pub const SSO_COOKIE: &str = "__Host-weebo-sso";
/// The cookie an endpoint host carries.
pub const HOST_COOKIE: &str = "__Host-weebo-endpoint";
/// The query parameter a one-time grant arrives in.
pub const GRANT_PARAM: &str = "__weebo_grant";

/// Every path this binary serves.
pub fn router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/auth", any(auth))
        .route("/oidc/start", get(oidc_start))
        .route("/oidc/callback", get(oidc_callback))
        .route("/host-session", get(host_session))
        .route("/sign_out", post(sign_out).get(sign_out_form))
        .route("/oidc/backchannel-logout", post(backchannel_logout))
        .route("/selftest", get(selftest))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        // Anything else: a `404` on a forward-auth deployment, and the application's own traffic
        // on a `ReverseProxy` one. One router, two shells, one `decide()`.
        .fallback(crate::proxy::fallback)
        .with_state(state)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The four inputs, from headers or from the query, never from both.
struct Forwarded {
    host: String,
    uri: String,
    method: String,
    proto: String,
}

enum ForwardedError {
    Missing,
    Mixed,
}

fn forwarded(
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
    if let Some(grant) = params.get(GRANT_PARAM) {
        return redeem(&state, &host, grant, &forwarded.uri);
    }

    // The one piece of I/O on this path, and it is deliberately *outside* the decision: a
    // service-account token that is not cached yet costs one `TokenReview`, here, where a reader
    // can see it — never inside `decide()`.
    state
        .prewarm_service_account(bearer(&headers).as_deref())
        .await;

    let presented = presented_from(&state, &headers, None);

    // A key rotation invalidates every cached bearer: the claims in the cache were verified
    // against keys this issuer no longer publishes, and a cache is not allowed to be the reason
    // one of them still passes.
    state.drop_identities_on_key_rotation();

    let outcome = state.gateway().authorize(&request, &presented);
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
            // Overwritten rather than merged, so a caller cannot present them itself.
            if let Some(claims) = state.identity_of(&request, &presented) {
                set_identity_headers(response.headers_mut(), &claims);
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
        Verdict::Challenge(challenge) => challenge_response(&state, &request, challenge),
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
        Challenge::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            [
                (
                    header::WWW_AUTHENTICATE,
                    format!(
                        "Bearer realm=\"weebo\", authorization_uri=\"{}\"",
                        state.config.redirect_base()
                    ),
                ),
                (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_owned()),
            ],
            "Not signed in. Open this URL in a browser to sign in, or present a bearer token \
             this cluster's identity provider minted.\n",
        )
            .into_response(),
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

/// Redeem a one-time grant into a host cookie.
fn redeem(state: &GatewayState, host: &Host, grant: &str, uri: &str) -> Response {
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
    let session = SealedPayload {
        expires_at: now.plus_secs(state.config.session.host_ttl_secs).as_secs(),
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
    let clean = uri.split('?').next().unwrap_or("/");
    let cookie = format!(
        "{HOST_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        state.config.session.host_ttl_secs
    );
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, format!("https://{host}{clean}")),
            (header::SET_COOKIE, cookie),
        ],
        "",
    )
        .into_response()
}

/// `/host-session` — exchange the SSO cookie for a one-time grant on the target host.
async fn host_session(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(target) = query.get("rd") else {
        return (StatusCode::BAD_REQUEST, "no target").into_response();
    };
    let Some(host) = target
        .strip_prefix("https://")
        .and_then(|rest| rest.split('/').next())
        .and_then(|host| Host::parse(host).ok())
        .filter(|host| state.scope.governs(host))
    else {
        // An open redirector in front of every workspace endpoint is a phishing primitive; the
        // suffix is what makes this one closed.
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
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no identity provider configured",
        )
            .into_response();
    };
    let target = query.get("rd").cloned().unwrap_or_default();
    let (Some(verifier), Some(id)) = (random_id(), random_id()) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no randomness").into_response();
    };
    // State and verifier travel in a sealed, short-lived cookie rather than in server memory:
    // three replicas behind one Service means the callback can land on a different one than the
    // start did, and a server-side map would make a sign-in fail two times out of three.
    let now = state.now();
    let payload = SealedPayload {
        username: target.clone(),
        groups: vec![verifier.clone()],
        session: None,
        expires_at: now.plus_secs(600).as_secs(),
        generation: 0,
        grant_id: Some(id.clone()),
        proved_at: now.as_secs(),
        refresh: None,
    };
    let Some(sealed) = state.codec.seal(&payload, Binding::Sso) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not mint state").into_response();
    };
    let location = oidc.authorization_url(&id, &verifier);
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (
                header::SET_COOKIE,
                format!("__Host-weebo-state={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
            ),
        ],
        "",
    )
        .into_response()
}

/// `/oidc/callback` — the only registered redirect URI.
async fn oidc_callback(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no identity provider configured",
        )
            .into_response();
    };
    let now = state.now();
    let (Some(code), Some(returned_state)) = (query.get("code"), query.get("state")) else {
        state.metrics.login("bad_request");
        return (StatusCode::BAD_REQUEST, "no code").into_response();
    };
    let Some(stored) = cookie(&headers, "__Host-weebo-state")
        .and_then(|sealed| state.codec.open(&sealed, Binding::Sso, now))
    else {
        state.metrics.login("no_state");
        return (StatusCode::BAD_REQUEST, "no state cookie; start again").into_response();
    };
    if stored.grant_id.as_deref() != Some(returned_state.as_str()) {
        state.metrics.login("state_mismatch");
        return (StatusCode::BAD_REQUEST, "state mismatch").into_response();
    }
    let verifier = stored.groups.first().cloned().unwrap_or_default();
    let tokens = match oidc.exchange(code, &verifier).await {
        Ok(tokens) => tokens,
        Err(err) => {
            state.metrics.login("exchange_failed");
            eprintln!("WARN endpoint-gateway: code exchange failed: {err}");
            return (StatusCode::BAD_GATEWAY, "sign-in failed").into_response();
        }
    };
    let Some(claims) = state.claims_of_id_token(&tokens.id_token) else {
        state.metrics.login("unusable_id_token");
        return (
            StatusCode::BAD_GATEWAY,
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
    };
    let Some(sealed) = state.codec.seal(&sso, Binding::Sso) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not mint a session",
        )
            .into_response();
    };
    state.metrics.login("success");
    let target = if stored.username.is_empty() {
        state.config.redirect_base().to_owned()
    } else {
        stored.username.clone()
    };
    (
        StatusCode::FOUND,
        [
            (
                header::LOCATION,
                format!(
                    "{}/host-session?rd={}",
                    state.config.redirect_base(),
                    crate::adapters::oidc::urlencode(&target)
                ),
            ),
            (
                header::SET_COOKIE,
                format!(
                    "{SSO_COOKIE}={sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
                    state.config.session.sso_ttl_secs
                ),
            ),
        ],
        "",
    )
        .into_response()
}

/// `POST /sign_out` — clears the SSO cookie.
async fn sign_out() -> Response {
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            format!("{SSO_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
        )],
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
async fn backchannel_logout(State(state): State<Arc<GatewayState>>, body: String) -> Response {
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
        Err(err) => {
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
    if header_str(&headers, "x-weebo-selftest") != Some(state.selftest_token.as_str()) {
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
        "indexed_endpoints": state.catalog.len(),
        // How many groups any endpoint in this cluster actually names. One is the common answer,
        // and a large one is the diagnosis behind "why did my session get re-authenticated".
        "interesting_groups": state.catalog.interesting_group_count(),
        "groups_generation": state.catalog.groups_generation(),
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}

async fn healthz() -> Response {
    (StatusCode::OK, "ok\n").into_response()
}

/// `/readyz` — informer-cache readiness. A cold replica must not answer "allow" from an empty
/// cache, which is why readiness and not just liveness is wired to it.
async fn readyz(State(state): State<Arc<GatewayState>>) -> Response {
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
}
