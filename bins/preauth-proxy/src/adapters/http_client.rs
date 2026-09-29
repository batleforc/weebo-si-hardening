//! The two outbound HTTP adapters: the acquisition exchange, and the forward to the upstream.
//!
//! Both sit on one `hyper` client over plain HTTP. Redirects are deliberately **not** followed —
//! the acquisition response itself carries the credential, and a `3xx` `Location` on a login
//! exchange typically points at a public host this process has no business calling.
//!
//! Every exchange is bounded: the connector by `limits.connect_timeout`, and each request — connect
//! included — by `limits.response_timeout` until its response head arrives. Without the latter a
//! stalled upstream would pin a task and its buffered request body for as long as the socket
//! stayed open.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, header};
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::domain::config::{Acquisition, Origin};
use crate::domain::port::{AcquireError, Credential, CredentialSource, GatewayError, Upstream};

/// Longest credential accepted out of an origin response header.
///
/// `take: whole` would otherwise copy an arbitrarily large header into memory and then into every
/// forwarded request. The origin is a trusted in-cluster service, so this is a bound rather than
/// a defence — but an unbounded one is a bound nobody chose.
const MAX_CREDENTIAL_LEN: usize = 8 * 1024;

/// The shared client type. `Full<Bytes>` because every request this binary sends has an in-memory
/// body: the acquisition body is config, and a forwarded body must stay replayable.
type HttpClient = Client<HttpConnector, Full<Bytes>>;

/// Build the client both adapters share, with `connect_timeout` on every new connection.
pub fn client(connect_timeout: Duration) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(connect_timeout));
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Send `request`, giving up if no response head arrives within `limit`.
async fn send(
    client: &HttpClient,
    request: Request<Full<Bytes>>,
    limit: Duration,
) -> Result<Response<hyper::body::Incoming>, String> {
    match tokio::time::timeout(limit, client.request(request)).await {
        Ok(result) => result.map_err(|err| err.to_string()),
        Err(_) => Err(format!("no response within {}s", limit.as_secs_f32())),
    }
}

/// [`CredentialSource`] over the configured HTTP exchange.
#[derive(Clone)]
pub struct HttpCredentialSource {
    client: HttpClient,
    acquisition: Acquisition,
    timeout: Duration,
}

impl HttpCredentialSource {
    /// Wire the adapter to one acquisition config; `timeout` bounds each exchange.
    pub const fn new(client: HttpClient, acquisition: Acquisition, timeout: Duration) -> Self {
        Self {
            client,
            acquisition,
            timeout,
        }
    }

    /// Build the acquisition request. Separated so the header assembly is testable.
    fn build(&self) -> Result<Request<Full<Bytes>>, AcquireError> {
        let malformed = |why: String| AcquireError::Unreachable(why);

        let uri = self
            .acquisition
            .origin
            .uri(&self.acquisition.path)
            .map_err(|err| malformed(err.to_string()))?;

        let mut builder = Request::builder()
            .method(self.acquisition.method.clone())
            .uri(uri);

        // An explicit Host: the client would derive one, and being explicit keeps the exchange
        // identical whatever the connector does.
        let host = HeaderValue::from_str(self.acquisition.origin.authority())
            .map_err(|err| malformed(err.to_string()))?;
        builder = builder.header(header::HOST, host);

        for (name, value) in &self.acquisition.headers {
            let value = HeaderValue::from_str(value).map_err(|_| {
                // The value came from the config, possibly after `${ENV}` substitution, so a
                // secret with a newline in it lands here. Never echo it.
                malformed(format!("{name} is not a valid header value"))
            })?;
            builder = builder.header(name, value);
        }

        builder
            .body(Full::new(Bytes::from(self.acquisition.body.clone())))
            .map_err(|err| malformed(err.to_string()))
    }
}

impl CredentialSource for HttpCredentialSource {
    async fn acquire(&self) -> Result<Credential, AcquireError> {
        let response = send(&self.client, self.build()?, self.timeout)
            .await
            .map_err(AcquireError::Unreachable)?;

        let status = response.status();
        if !self.acquisition.accept_status.contains(&status) {
            return Err(AcquireError::Rejected(status.as_u16()));
        }

        let name = &self.acquisition.from_header;
        let raw = response
            .headers()
            .get(name)
            .ok_or_else(|| AcquireError::NoHeader(name.to_string()))?
            .to_str()
            .map_err(|_| AcquireError::NothingExtracted(name.to_string()))?;

        let taken = self
            .acquisition
            .take
            .apply(raw)
            .ok_or_else(|| AcquireError::NothingExtracted(name.to_string()))?;

        if taken.len() > MAX_CREDENTIAL_LEN {
            return Err(AcquireError::NothingExtracted(format!(
                "{name} (over {MAX_CREDENTIAL_LEN} bytes)"
            )));
        }

        Ok(Credential::new(taken))
    }
}

/// [`Upstream`] over HTTP, streaming response bodies.
#[derive(Clone)]
pub struct HttpUpstream {
    client: HttpClient,
    origin: Origin,
    timeout: Duration,
}

impl HttpUpstream {
    /// Wire the adapter to one upstream origin; `timeout` bounds each response head.
    pub const fn new(client: HttpClient, origin: Origin, timeout: Duration) -> Self {
        Self {
            client,
            origin,
            timeout,
        }
    }
}

impl Upstream for HttpUpstream {
    /// The upstream's body, relayed as-is: `hyper` yields it in chunks, so a multi-megabyte
    /// response never sits whole in memory.
    type Body = hyper::body::Incoming;

    async fn forward(&self, request: Request<Bytes>) -> Result<Response<Self::Body>, GatewayError> {
        let (parts, body) = request.into_parts();

        let path = parts
            .uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let uri = self
            .origin
            .uri(path)
            .map_err(|err| GatewayError(err.to_string()))?;

        let mut builder = Request::builder().method(parts.method).uri(uri);
        if let Some(headers) = builder.headers_mut() {
            *headers = parts.headers;
            // The caller's Host names the gateway, not the upstream. Rewriting it is what makes
            // the upstream see a request addressed to itself.
            let host = HeaderValue::from_str(self.origin.authority())
                .map_err(|err| GatewayError(err.to_string()))?;
            headers.insert(header::HOST, host);
        }

        let request = builder
            .body(Full::new(body))
            .map_err(|err| GatewayError(err.to_string()))?;

        send(&self.client, request, self.timeout)
            .await
            .map_err(GatewayError)
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
    use crate::domain::config::Take;
    use http::{Method, StatusCode};
    use std::time::Instant;

    const SECOND: Duration = Duration::from_secs(1);

    /// A socket that accepts and then never says a word: the stalled-upstream shape.
    async fn silent_origin() -> (Origin, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        (
            Origin::parse("upstream", &format!("http://{addr}")).unwrap(),
            task,
        )
    }

    #[tokio::test]
    async fn a_silent_upstream_is_a_gateway_error_after_the_response_timeout() {
        let (origin, task) = silent_origin().await;
        let limit = Duration::from_millis(150);
        let upstream = HttpUpstream::new(client(SECOND), origin, limit);

        let started = Instant::now();
        let request = Request::builder()
            .uri("http://gateway/page")
            .body(Bytes::new())
            .unwrap();
        let err = upstream.forward(request).await.unwrap_err();

        assert!(err.0.contains("no response within"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout did not bound the wait"
        );
        task.abort();
    }

    #[tokio::test]
    async fn a_silent_origin_is_an_acquisition_failure_after_the_response_timeout() {
        let (origin, task) = silent_origin().await;
        let mut acq = acquisition();
        acq.origin = origin;
        let source = HttpCredentialSource::new(client(SECOND), acq, Duration::from_millis(150));

        let err = source.acquire().await.unwrap_err();
        assert!(
            matches!(err, AcquireError::Unreachable(ref why) if why.contains("no response within")),
            "{err}"
        );
        task.abort();
    }

    fn acquisition() -> Acquisition {
        Acquisition {
            origin: Origin::parse("credential.origin", "http://app-auth:8000").unwrap(),
            method: Method::POST,
            path: "/login".to_owned(),
            headers: vec![(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded".to_owned(),
            )],
            body: "email=svc&password=hunter2".to_owned(),
            accept_status: vec![StatusCode::OK],
            from_header: header::SET_COOKIE,
            take: Take::CookiePair,
        }
    }

    #[test]
    fn the_acquisition_request_is_built_from_the_config_alone() {
        let source = HttpCredentialSource::new(client(SECOND), acquisition(), SECOND);
        let request = source.build().unwrap();

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().to_string(), "http://app-auth:8000/login");
        assert_eq!(
            request.headers().get(header::HOST).unwrap(),
            "app-auth:8000"
        );
        assert_eq!(
            request.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded"
        );
    }

    #[test]
    fn a_header_value_that_cannot_be_a_header_never_echoes_the_value() {
        let mut acq = acquisition();
        // A secret with a newline in it: the classic header-injection shape.
        acq.headers = vec![(header::AUTHORIZATION, "Bearer x\r\nX-Evil: 1".to_owned())];
        let source = HttpCredentialSource::new(client(SECOND), acq, SECOND);

        let err = source.build().unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("authorization"), "{rendered}");
        assert!(
            !rendered.contains("Bearer x"),
            "the error echoed the secret: {rendered}"
        );
    }
}
