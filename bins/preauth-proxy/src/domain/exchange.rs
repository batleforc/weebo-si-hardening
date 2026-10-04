//! The use case: run one inbound request through the policy, the cache and the two ports.
//!
//! This is the orchestration [RFC 0003](../../../../docs/rfc/0003-preauth-proxy.md) describes
//! under *Request handling*. It is `async` only because ports do I/O; every decision it takes
//! comes from [`super::policy`], and it is exercised against fakes rather than sockets.

use bytes::Bytes;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response};

use super::config::{Config, InjectMode};
use super::credential::Cache;
use super::policy::{self, Action, AfterResponse, CacheState, Exchange, RequestFacts};
use super::port::{AcquireError, Credential, CredentialSource, GatewayError, Upstream};
use http::StatusCode;

/// Headers that describe one hop and must not be forwarded, per RFC 7230 §6.1.
const HOP_BY_HOP: [HeaderName; 8] = [
    http::header::CONNECTION,
    http::header::PROXY_AUTHENTICATE,
    http::header::PROXY_AUTHORIZATION,
    http::header::TE,
    http::header::TRAILER,
    http::header::TRANSFER_ENCODING,
    http::header::UPGRADE,
    // `Keep-Alive` has no constant in `http`.
    HeaderName::from_static("keep-alive"),
];

/// Why the proxy could not produce an upstream response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// No credential could be minted.
    Acquire(AcquireError),
    /// The upstream could not be reached.
    Gateway(GatewayError),
    /// The request could not be rebuilt for the upstream.
    Malformed(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acquire(err) => write!(f, "acquisition failed: {err}"),
            Self::Gateway(err) => write!(f, "upstream unreachable: {err}"),
            Self::Malformed(why) => write!(f, "request could not be forwarded: {why}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Remove every hop-by-hop header, including the ones the `Connection` header names.
///
/// Applied in **both** directions: a `Connection: X-Thing` on the way out would leave the
/// upstream honouring a directive meant for our socket, and on the way back would leak the
/// upstream's connection management to the caller.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // `Connection` may list further headers that are themselves hop-by-hop for this exchange.
    let named: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| token.trim().parse::<HeaderName>().ok())
        .collect();

    for name in HOP_BY_HOP.iter().chain(named.iter()) {
        headers.remove(name);
    }
}

/// The cookie names an injected credential sets, or `None` when they cannot be told apart.
///
/// `None` when:
///
/// - the credential is injected through a header other than `Cookie` (`Authorization`, an API
///   key header…). The upstream then authenticates the request from that header and may well
///   answer with a session cookie of its own for the **service** identity — whose name the
///   proxy has no way to know. Every cookie might be the service session;
/// - it is a `Cookie` injection whose credential has a `;`-separated part with no `=` — a shape
///   `take: whole` can produce, and one where "which cookie is ours" has no reliable answer.
///
/// The caller treats `None` as "every cookie might be ours".
fn injected_cookie_names<'a>(config: &Config, credential: &'a Credential) -> Option<Vec<&'a str>> {
    if config.inject.header != http::header::COOKIE {
        return None;
    }
    credential
        .expose()
        .split(';')
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').map(|(name, _)| name.trim()))
        .collect()
}

/// Drop every `Set-Cookie` that would hand the caller the **service** session.
///
/// A response to an injected request was produced for the service identity. An upstream that
/// refreshes its session on the way out (sliding expiry, rotation) would otherwise set that
/// session in the caller's browser — the service credential escaping the proxy, and, where the
/// cookie also carries the passthrough marker, turning every later request from that browser into
/// a *pass-through* that bypasses injection, renewal and this very filter. A `Set-Cookie` is
/// dropped when:
///
/// - the credential was injected as a `Cookie` and the `Set-Cookie` names one of its cookies —
///   or the credential's cookie names cannot be determined, in which case **every** `Set-Cookie`
///   is dropped (fail-closed: the caller loses at most an unrelated preference cookie);
/// - the credential was injected through any header **other than** `Cookie`: then **every**
///   `Set-Cookie` is dropped, because a session the upstream mints off an `Authorization` (or
///   similar) header carries a name the proxy cannot predict. There is deliberately no opt-out:
///   relaying "just the harmless ones" would need the very name the proxy does not have;
/// - the passthrough marker lives in `Cookie` and the `Set-Cookie`'s `name=value` contains it.
///
/// Anything else (a CSRF token, a UI preference) is relayed for a `Cookie` injection, so the
/// upstream keeps working.
fn strip_service_cookies(headers: &mut HeaderMap, config: &Config, credential: &Credential) {
    if !headers.contains_key(http::header::SET_COOKIE) {
        return;
    }
    let ours = injected_cookie_names(config, credential);
    let marker = (config.passthrough.header == http::header::COOKIE)
        .then_some(config.passthrough.contains.as_str());

    let kept: Vec<HeaderValue> = headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter(|value| {
            let Some(names) = &ours else {
                return false;
            };
            // An unreadable value cannot be inspected, so it cannot be shown to be harmless.
            let Ok(text) = value.to_str() else {
                return false;
            };
            let pair = text.split(';').next().unwrap_or(text).trim();
            let name = pair.split_once('=').map_or(pair, |(name, _)| name).trim();
            let sets_ours = names.contains(&name);
            let sets_marker = marker.is_some_and(|marker| pair.contains(marker));
            !sets_ours && !sets_marker
        })
        .cloned()
        .collect();

    headers.remove(http::header::SET_COOKIE);
    for value in kept {
        headers.append(http::header::SET_COOKIE, value);
    }
}

/// Whether the passthrough marker is present in the configured header.
///
/// A substring test for every header but `Cookie`. Suppressing injection only ever costs the
/// caller its own session — the upstream challenges them — so a false positive here is
/// fail-closed for that caller.
///
/// **`Cookie` is the exception, and it is matched per cookie.** The value is a `;`-delimited list,
/// so a bare substring over the whole value lets `contains: "session="` match a cookie *named*
/// `_gw_session`, or one whose value merely contains the text — and a cookie the forward-auth
/// gateway sets on every user would then switch injection off for everyone. Each `name=value`
/// pair is instead tested for *starting with* the configured text, so `session=` means a cookie
/// named `session` and `_gw_session=abc` does not match. Every line of the header is read, not
/// the first.
pub fn marker_present(headers: &HeaderMap, config: &Config) -> bool {
    let marker = config.passthrough.contains.as_str();
    let per_cookie = config.passthrough.header == http::header::COOKIE;
    headers
        .get_all(&config.passthrough.header)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| {
            if per_cookie {
                value
                    .split(';')
                    .any(|pair| pair.trim_start().starts_with(marker))
            } else {
                value.contains(marker)
            }
        })
}

/// The separator used when appending to an existing header value.
///
/// `Cookie` is a `;`-delimited list; everything else in HTTP is `,`-delimited. Getting this wrong
/// produces a header the upstream parses as one malformed value rather than two good ones.
const fn append_separator(header: &HeaderName) -> &'static str {
    if matches!(*header, http::header::COOKIE) {
        "; "
    } else {
        ", "
    }
}

/// Write the credential into the request per `inject.mode`.
fn inject(
    headers: &mut HeaderMap,
    config: &Config,
    credential: &Credential,
) -> Result<(), RelayError> {
    let name = &config.inject.header;
    let combined = match config.inject.mode {
        InjectMode::Set => credential.expose().to_owned(),
        InjectMode::Append => {
            // Every line, joined: a caller may send several `Cookie` headers (HTTP/2 splits
            // them), and `insert` below replaces them all, so reading only the first would drop
            // the rest of what the caller sent.
            let separator = append_separator(name);
            let mut existing = Vec::new();
            for value in headers.get_all(name) {
                match value.to_str() {
                    Ok(text) if !text.is_empty() => existing.push(text),
                    Ok(_) => {}
                    // Not text, so it cannot be joined — and dropping it would send the upstream
                    // a request that is not the one the caller made. Refuse it by name instead.
                    Err(_) => {
                        return Err(RelayError::Malformed(format!(
                            "{name} carries a value that is not text and cannot be appended to"
                        )));
                    }
                }
            }
            existing.push(credential.expose());
            existing.join(separator)
        }
    };

    let value = HeaderValue::from_str(&combined).map_err(|_| {
        // The credential came from an origin response header, so it was a header value once —
        // but the concatenation, or a caller-supplied existing value, may not be.
        RelayError::Malformed(format!("{name} would not be a valid header value"))
    })?;
    headers.insert(name, value);
    Ok(())
}

/// Rebuild a request from its parts and body, so an attempt can be made more than once.
fn attempt(
    method: &http::Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<Request<Bytes>, RelayError> {
    let mut builder = Request::builder().method(method.clone()).uri(uri.clone());
    if let Some(map) = builder.headers_mut() {
        *map = headers.clone();
    }
    builder
        .body(body.clone())
        .map_err(|err| RelayError::Malformed(err.to_string()))
}

/// The result of one inbound request, and what happened on the way.
///
/// The counts exist so the **adapter** can log them: the domain does no I/O, and RFC 0003 asks
/// for "one structured line per acquisition and per renewal" with no metrics behind it — which
/// makes those lines the only signal an operator gets that renewal is working at all.
#[derive(Debug)]
pub struct Relayed<B> {
    /// What to give the caller.
    pub response: Response<B>,
    /// How many times the credential was discarded and the request replayed.
    pub renewals: u32,
    /// The status that triggered the last renewal, if any.
    pub renewed_on: Option<StatusCode>,
}

/// Run one inbound request to completion, renewing and replaying if the upstream says so.
///
/// # Errors
///
/// [`RelayError`], which the inbound adapter turns into a `502` — the caller gets no injected
/// session, which for a gated route means the upstream's own challenge, never open access.
pub async fn relay<S, U>(
    request: Request<Bytes>,
    config: &Config,
    cache: &Cache,
    source: &S,
    upstream: &U,
) -> Result<Relayed<U::Body>, RelayError>
where
    S: CredentialSource,
    U: Upstream,
{
    let mut renewed_on = None;
    let (parts, body) = request.into_parts();
    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers);

    let facts = RequestFacts {
        marker_present: marker_present(&headers, config),
    };
    let state = CacheState {
        holds_credential: cache.holds_credential().await,
    };

    let action = policy::decide(facts, state);
    let mut exchange = Exchange::new();
    let injected = !matches!(action, Action::PassThrough);

    // `Inject` and `AcquireThenInject` differ only in whether the cache is warm; the cache's
    // single-flight rule already handles both, so they share a path here.
    let mut held = if injected {
        Some(
            cache
                .get_or_acquire(source)
                .await
                .map_err(RelayError::Acquire)?,
        )
    } else {
        None
    };

    loop {
        let mut outgoing = headers.clone();
        if let Some(credential) = &held {
            inject(&mut outgoing, config, credential)?;
        }

        let response = upstream
            .forward(attempt(&parts.method, &parts.uri, &outgoing, &body)?)
            .await
            .map_err(RelayError::Gateway)?;

        match exchange.on_response(response.status(), &config.renew, injected) {
            AfterResponse::Relay => {
                let (mut parts, body) = response.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                if let Some(credential) = &held {
                    strip_service_cookies(&mut parts.headers, config, credential);
                }
                return Ok(Relayed {
                    response: Response::from_parts(parts, body),
                    renewals: exchange.replays_used(),
                    renewed_on,
                });
            }
            AfterResponse::RenewAndReplay => {
                renewed_on = Some(response.status());
                if let Some(stale) = held.take() {
                    cache.invalidate(&stale).await;
                }
                held = Some(
                    cache
                        .get_or_acquire(source)
                        .await
                        .map_err(RelayError::Acquire)?,
                );
            }
        }
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
    use crate::domain::config::{Acquisition, Inject, Limits, Origin, Passthrough, Renew, Take};
    use http::{Method, StatusCode};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config(mode: InjectMode, renew_on: &[u16], max_replays: u32) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstream: Origin::parse("upstream", "http://app:3000").unwrap(),
            passthrough: Passthrough {
                header: http::header::COOKIE,
                contains: "session=".to_owned(),
            },
            credential: Acquisition {
                origin: Origin::parse("credential.origin", "http://app-auth:8000").unwrap(),
                method: Method::POST,
                path: "/login".to_owned(),
                headers: vec![],
                body: String::new(),
                accept_status: vec![StatusCode::OK],
                from_header: http::header::SET_COOKIE,
                take: Take::CookiePair,
            },
            inject: Inject {
                header: http::header::COOKIE,
                mode,
            },
            renew: Renew {
                on_status: renew_on
                    .iter()
                    .map(|s| StatusCode::from_u16(*s).unwrap())
                    .collect(),
                max_replays,
            },
            limits: Limits::default(),
        }
    }

    /// Hands out `sid=token0`, `sid=token1`, … so a replay is visible in the assertion.
    #[derive(Default)]
    struct Minting(AtomicUsize);

    impl CredentialSource for Minting {
        async fn acquire(&self) -> Result<Credential, AcquireError> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Credential::new(format!("sid=token{n}")))
        }
    }

    struct Refuses;

    impl CredentialSource for Refuses {
        async fn acquire(&self) -> Result<Credential, AcquireError> {
            Err(AcquireError::Rejected(403))
        }
    }

    /// Records what was injected and returns a scripted status per attempt.
    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Option<String>>>,
        script: Mutex<Vec<StatusCode>>,
        set_cookies: Vec<&'static str>,
    }

    impl Recorder {
        fn scripted(statuses: &[u16]) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                script: Mutex::new(
                    statuses
                        .iter()
                        .rev()
                        .map(|s| StatusCode::from_u16(*s).unwrap())
                        .collect(),
                ),
                set_cookies: Vec::new(),
            }
        }

        fn setting(mut self, cookies: &[&'static str]) -> Self {
            self.set_cookies = cookies.to_vec();
            self
        }

        fn injected(&self) -> Vec<Option<String>> {
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl Upstream for Recorder {
        type Body = Bytes;

        async fn forward(
            &self,
            request: Request<Bytes>,
        ) -> Result<Response<Self::Body>, GatewayError> {
            let cookie = request
                .headers()
                .get(http::header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(cookie);

            let status = self
                .script
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
                .unwrap_or(StatusCode::OK);
            let mut builder = Response::builder().status(status);
            for cookie in &self.set_cookies {
                builder = builder.header(http::header::SET_COOKIE, *cookie);
            }
            Ok(builder.body(Bytes::from_static(b"body")).unwrap())
        }
    }

    fn request(cookie: Option<&str>) -> Request<Bytes> {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("http://app:3000/page");
        if let Some(cookie) = cookie {
            builder = builder.header(http::header::COOKIE, cookie);
        }
        builder.body(Bytes::new()).unwrap()
    }

    #[tokio::test]
    async fn a_request_without_the_marker_is_injected_into() {
        let cfg = config(InjectMode::Append, &[401], 1);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);

        let response = relay(request(None), &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap();

        assert_eq!(response.response.status(), StatusCode::OK);
        assert_eq!(upstream.injected(), vec![Some("sid=token0".to_owned())]);
    }

    #[tokio::test]
    async fn a_request_carrying_the_marker_is_forwarded_untouched() {
        let cfg = config(InjectMode::Append, &[401], 1);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);
        let source = Minting::default();

        relay(
            request(Some("session=mine")),
            &cfg,
            &cache,
            &source,
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(
            upstream.injected(),
            vec![Some("session=mine".to_owned())],
            "the caller's own credential was modified"
        );
        assert!(
            !cache.holds_credential().await,
            "a passed-through request minted a credential it did not need"
        );
    }

    #[tokio::test]
    async fn append_joins_the_callers_cookie_rather_than_replacing_it() {
        let cfg = config(InjectMode::Append, &[], 0);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);

        relay(
            request(Some("theme=dark")),
            &cfg,
            &cache,
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(
            upstream.injected(),
            vec![Some("theme=dark; sid=token0".to_owned())]
        );
    }

    #[tokio::test]
    async fn set_replaces_the_callers_header() {
        let cfg = config(InjectMode::Set, &[], 0);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);

        relay(
            request(Some("theme=dark")),
            &cfg,
            &cache,
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(upstream.injected(), vec![Some("sid=token0".to_owned())]);
    }

    #[tokio::test]
    async fn a_renewal_status_replays_the_request_with_a_fresh_credential() {
        let cfg = config(InjectMode::Set, &[401], 1);
        let cache = Cache::new();
        // First attempt is rejected, the replay succeeds.
        let upstream = Recorder::scripted(&[401, 200]);

        let response = relay(request(None), &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap();

        assert_eq!(response.response.status(), StatusCode::OK);
        assert_eq!(
            upstream.injected(),
            vec![Some("sid=token0".to_owned()), Some("sid=token1".to_owned()),],
            "the replay reused the credential the upstream had just rejected"
        );
    }

    #[tokio::test]
    async fn a_relay_reports_what_it_did_so_the_adapter_can_log_it() {
        let cfg = config(InjectMode::Set, &[401], 1);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[401, 200]);

        let relayed = relay(request(None), &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap();

        // RFC 0003 ships no metrics, so this is the only thing that can tell an operator renewal
        // is working. If it were not reported here, the adapter could not log it.
        assert_eq!(relayed.renewals, 1);
        assert_eq!(relayed.renewed_on, Some(StatusCode::UNAUTHORIZED));

        // A request that needed no renewal says so, rather than reporting nothing at all.
        let quiet = Recorder::scripted(&[200]);
        let relayed = relay(request(None), &cfg, &cache, &Minting::default(), &quiet)
            .await
            .unwrap();
        assert_eq!(relayed.renewals, 0);
        assert_eq!(relayed.renewed_on, None);
    }

    #[tokio::test]
    async fn a_second_failure_is_surfaced_rather_than_replayed_again() {
        let cfg = config(InjectMode::Set, &[401], 1);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[401, 401]);

        let response = relay(request(None), &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap();

        assert_eq!(response.response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(upstream.injected().len(), 2, "replayed more than once");
    }

    #[tokio::test]
    async fn a_failed_acquisition_is_an_error_not_an_unauthenticated_forward() {
        let cfg = config(InjectMode::Set, &[], 0);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);

        let err = relay(request(None), &cfg, &cache, &Refuses, &upstream)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            RelayError::Acquire(AcquireError::Rejected(403))
        ));
        assert!(
            upstream.injected().is_empty(),
            "the request reached the upstream without a credential"
        );
    }

    #[tokio::test]
    async fn a_passed_through_request_is_not_renewed_on_a_401() {
        let cfg = config(InjectMode::Set, &[401], 1);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[401, 200]);

        let response = relay(
            request(Some("session=mine")),
            &cfg,
            &cache,
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(response.response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            upstream.injected().len(),
            1,
            "the caller's 401 was replayed as us"
        );
    }

    fn set_cookies<B>(relayed: &Relayed<B>) -> Vec<String> {
        relayed
            .response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn a_set_cookie_refreshing_the_injected_session_never_reaches_the_caller() {
        let cfg = config(InjectMode::Append, &[], 0);
        let upstream = Recorder::scripted(&[200]).setting(&[
            "sid=rotated; Path=/; HttpOnly",
            "theme=dark; Path=/",
            "csrf=abc",
        ]);

        let relayed = relay(
            request(None),
            &cfg,
            &Cache::new(),
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(
            set_cookies(&relayed),
            vec!["theme=dark; Path=/".to_owned(), "csrf=abc".to_owned()],
            "the service session was handed to the caller, or an unrelated cookie was lost"
        );
    }

    #[tokio::test]
    async fn a_set_cookie_carrying_the_passthrough_marker_is_dropped_too() {
        // Were it relayed, the caller's next request would carry the marker and be passed
        // through with a service-minted session.
        let cfg = config(InjectMode::Set, &[], 0);
        let upstream = Recorder::scripted(&[200]).setting(&["session=svc; Path=/", "lang=fr"]);

        let relayed = relay(
            request(None),
            &cfg,
            &Cache::new(),
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(set_cookies(&relayed), vec!["lang=fr".to_owned()]);
    }

    #[tokio::test]
    async fn a_credential_whose_cookie_name_is_unclear_drops_every_set_cookie() {
        struct Nameless;
        impl CredentialSource for Nameless {
            async fn acquire(&self) -> Result<Credential, AcquireError> {
                Ok(Credential::new("opaque-token"))
            }
        }

        let cfg = config(InjectMode::Set, &[], 0);
        let upstream = Recorder::scripted(&[200]).setting(&["opaque=x", "lang=fr"]);

        let relayed = relay(request(None), &cfg, &Cache::new(), &Nameless, &upstream)
            .await
            .unwrap();

        assert!(
            set_cookies(&relayed).is_empty(),
            "{:?}",
            set_cookies(&relayed)
        );
    }

    #[tokio::test]
    async fn a_passed_through_response_keeps_its_set_cookie() {
        // The caller brought its own session; what the upstream sets is theirs.
        let cfg = config(InjectMode::Set, &[], 0);
        let upstream = Recorder::scripted(&[200]).setting(&["session=theirs-rotated", "sid=x"]);

        let relayed = relay(
            request(Some("session=mine")),
            &cfg,
            &Cache::new(),
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(
            set_cookies(&relayed),
            vec!["session=theirs-rotated".to_owned(), "sid=x".to_owned()]
        );
    }

    #[tokio::test]
    async fn a_non_cookie_injection_drops_every_set_cookie() {
        // Injected as `Authorization`: the upstream may mint a session cookie of its own for the
        // service identity (`grafana_session`, `connect.sid`…) under a name the proxy cannot
        // know. Every `Set-Cookie` goes, harmless-looking ones included.
        let mut cfg = config(InjectMode::Set, &[], 0);
        cfg.inject.header = http::header::AUTHORIZATION;
        let upstream =
            Recorder::scripted(&[200]).setting(&["app_session=svc", "lang=fr", "session=svc"]);

        let relayed = relay(
            request(None),
            &cfg,
            &Cache::new(),
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert!(
            set_cookies(&relayed).is_empty(),
            "{:?}",
            set_cookies(&relayed)
        );
    }

    #[tokio::test]
    async fn a_non_cookie_injection_still_relays_set_cookie_on_passthrough() {
        // The caller's own session: nothing was injected, so what the upstream sets is theirs.
        let mut cfg = config(InjectMode::Set, &[], 0);
        cfg.inject.header = http::header::AUTHORIZATION;
        let upstream = Recorder::scripted(&[200]).setting(&["lang=fr"]);

        let relayed = relay(
            request(Some("session=mine")),
            &cfg,
            &Cache::new(),
            &Minting::default(),
            &upstream,
        )
        .await
        .unwrap();

        assert_eq!(set_cookies(&relayed), vec!["lang=fr".to_owned()]);
    }

    #[test]
    fn hop_by_hop_headers_are_stripped_including_the_ones_connection_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, X-Custom-Hop".parse().unwrap(),
        );
        headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(
            HeaderName::from_static("x-custom-hop"),
            "1".parse().unwrap(),
        );
        headers.insert(http::header::HOST, "app:3000".parse().unwrap());

        strip_hop_by_hop(&mut headers);

        assert!(headers.get(http::header::CONNECTION).is_none());
        assert!(headers.get(http::header::TRANSFER_ENCODING).is_none());
        assert!(headers.get(http::header::UPGRADE).is_none());
        assert!(
            headers.get("x-custom-hop").is_none(),
            "a header named by Connection survived"
        );
        assert_eq!(headers.get(http::header::HOST).unwrap(), "app:3000");
    }

    #[test]
    fn the_marker_test_is_a_substring_over_every_value_of_the_header() {
        let cfg = config(InjectMode::Set, &[], 0);
        let mut headers = HeaderMap::new();
        assert!(!marker_present(&headers, &cfg));

        headers.append(http::header::COOKIE, "theme=dark".parse().unwrap());
        assert!(!marker_present(&headers, &cfg));

        headers.append(http::header::COOKIE, "session=abc".parse().unwrap());
        assert!(marker_present(&headers, &cfg));
    }

    #[test]
    fn a_cookie_merely_ending_in_the_marker_name_is_not_the_marker() {
        let cfg = config(InjectMode::Set, &[], 0);
        let mut headers = HeaderMap::new();
        // The gateway's own cookie, set for every user.
        headers.insert(
            http::header::COOKIE,
            "_gw_session=abc; theme=session=x".parse().unwrap(),
        );
        assert!(!marker_present(&headers, &cfg));

        // Whereas the real one is found anywhere in the list, and on any line.
        headers.insert(
            http::header::COOKIE,
            "_gw_session=abc; session=mine".parse().unwrap(),
        );
        assert!(marker_present(&headers, &cfg));
    }

    #[tokio::test]
    async fn append_keeps_every_cookie_line_the_caller_sent() {
        let cfg = config(InjectMode::Append, &[], 0);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);
        let mut req = request(Some("theme=dark"));
        req.headers_mut()
            .append(http::header::COOKIE, "lang=fr".parse().unwrap());

        relay(req, &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap();

        assert_eq!(
            upstream.injected(),
            vec![Some("theme=dark; lang=fr; sid=token0".to_owned())]
        );
    }

    #[tokio::test]
    async fn append_refuses_a_cookie_value_it_cannot_join_rather_than_dropping_it() {
        let cfg = config(InjectMode::Append, &[], 0);
        let cache = Cache::new();
        let upstream = Recorder::scripted(&[200]);
        let mut req = request(None);
        req.headers_mut().insert(
            http::header::COOKIE,
            HeaderValue::from_bytes(b"a=\xff").unwrap(),
        );

        let err = relay(req, &cfg, &cache, &Minting::default(), &upstream)
            .await
            .unwrap_err();
        assert!(matches!(err, RelayError::Malformed(_)), "{err}");
    }
}
