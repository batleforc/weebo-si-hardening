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

/// Whether the passthrough marker is present in the configured header.
///
/// A coarse substring test, exactly as the contract says. Suppressing injection only ever costs
/// the caller its own session — the upstream challenges them — so a false positive here is
/// fail-closed.
pub fn marker_present(headers: &HeaderMap, config: &Config) -> bool {
    headers
        .get_all(&config.passthrough.header)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.contains(&config.passthrough.contains))
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
        InjectMode::Append => match headers.get(name).and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => {
                format!(
                    "{existing}{}{}",
                    append_separator(name),
                    credential.expose()
                )
            }
            _ => credential.expose().to_owned(),
        },
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
    use crate::domain::config::{Acquisition, Inject, Origin, Passthrough, Renew, Take};
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
            }
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
            Ok(Response::builder()
                .status(status)
                .body(Bytes::from_static(b"body"))
                .unwrap())
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
}
