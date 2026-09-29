//! The listener: one connection at a time turned into a domain call.
//!
//! It owns no policy. It collects the request facts, hands them to
//! [`crate::domain::exchange::relay`], and turns whatever comes back into a response.
//!
//! It does own the resource bounds of `limits` that concern the caller's side: how long a caller
//! may take to send its request, how many requests run at once (a request counts until its
//! response body has been streamed out or dropped), how long a streamed response body may go
//! silent, how many request-body bytes are buffered across all of them, and how long a `SIGTERM`
//! waits for what is in flight.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Body, Frame, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};

use crate::domain::config::{Config, MAX_REQUEST_BODY};
use crate::domain::credential::Cache;
use crate::domain::exchange::{RelayError, Relayed, relay};
use crate::domain::port::{CredentialSource, Upstream};

/// A body error of any origin, as `hyper` accepts it.
type BoxError = Box<dyn StdError + Send + Sync>;

/// The body type every response this server produces shares.
type ResponseBody = BoxBody<Bytes, BoxError>;

/// Everything a request handler needs, shared across connections.
pub struct Proxy<S, U> {
    /// The validated configuration.
    pub config: Config,
    /// The single held credential.
    pub cache: Cache,
    /// The acquisition port.
    pub source: S,
    /// The forwarding port.
    pub upstream: U,
    /// One permit per request being handled (`limits.max_in_flight`).
    in_flight: Arc<Semaphore>,
    /// One permit per buffered request-body byte, across all requests (`limits.max_buffered_bytes`).
    buffered: Arc<Semaphore>,
}

impl<S, U> Proxy<S, U> {
    /// Assemble the handler state, sizing the admission gates from `config.limits`.
    pub fn new(config: Config, cache: Cache, source: S, upstream: U) -> Self {
        let in_flight = Arc::new(Semaphore::new(
            config.limits.max_in_flight.min(Semaphore::MAX_PERMITS),
        ));
        let buffered = Arc::new(Semaphore::new(
            config.limits.max_buffered_bytes.min(Semaphore::MAX_PERMITS),
        ));
        Self {
            config,
            cache,
            source,
            upstream,
            in_flight,
            buffered,
        }
    }
}

/// Wrap a fixed message as a response body.
fn message(status: StatusCode, text: &'static str) -> Response<ResponseBody> {
    let body = Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        // `Builder::body` only fails on an invalid status or header, both fixed above.
        .unwrap_or_else(|_| Response::new(BoxBody::default()))
}

/// A relayed response body that keeps its request's `max_in_flight` slot until it ends, and
/// ends itself with an error if the upstream goes silent for `limits.response_idle_timeout`.
///
/// Without this the slot would be returned as soon as the response head was handed back, and an
/// unbounded number of streamed bodies could be in progress at once; and a stalled upstream body
/// would hold its connection (and, now, its slot) forever. Every field is `Unpin` — `BoxBody` is,
/// and the timer is boxed — so no pin projection is needed.
struct Guarded {
    /// The upstream's body.
    inner: ResponseBody,
    /// The gap allowed between two frames.
    idle: Duration,
    /// When the current gap runs out; pushed back on every frame.
    deadline: Pin<Box<Sleep>>,
    /// The request's admission slot. Released at end-of-stream, on error, or on drop — whichever
    /// comes first.
    admitted: Option<OwnedSemaphorePermit>,
    /// Set once the body has ended (cleanly or not); later polls yield nothing.
    finished: bool,
}

/// The error a body cut for idleness ends with.
#[derive(Debug)]
struct IdleTimeout(Duration);

impl std::fmt::Display for IdleTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "upstream response body idle for {}s",
            self.0.as_secs_f32()
        )
    }
}

impl StdError for IdleTimeout {}

impl Guarded {
    fn new(inner: ResponseBody, idle: Duration, admitted: OwnedSemaphorePermit) -> Self {
        Self {
            inner,
            idle,
            deadline: Box::pin(tokio::time::sleep(idle)),
            admitted: Some(admitted),
            finished: false,
        }
    }

    /// Mark the body over and give the slot back.
    fn finish(&mut self) {
        self.finished = true;
        self.admitted = None;
    }
}

impl Body for Guarded {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        if this.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let next = Instant::now() + this.idle;
                this.deadline.as_mut().reset(next);
                if this.inner.is_end_stream() {
                    this.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(err))) => {
                this.finish();
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.deadline.as_mut().poll(cx).is_ready() {
                    eprintln!(
                        "WARN  preauth-proxy: upstream response body idle for {}s, cutting it",
                        this.idle.as_secs()
                    );
                    this.finish();
                    return Poll::Ready(Some(Err(Box::new(IdleTimeout(this.idle)))));
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Why a request body was not accepted.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// Over [`MAX_REQUEST_BODY`].
    TooLarge,
    /// The shared buffer budget is spent; another request may fit in a moment.
    Saturated,
    /// The caller went away, or sent something that was not a body.
    Unreadable,
}

/// Buffer a request body, charging every byte against the shared `budget`.
///
/// The returned permit holds those bytes' share of the budget; dropping it returns them. A
/// `Content-Length` is not trusted up front — bytes are charged as they arrive, so a chunked body
/// is bounded exactly like a declared one.
async fn collect<B>(
    body: B,
    budget: &Arc<Semaphore>,
) -> Result<(Bytes, Option<OwnedSemaphorePermit>), Refusal>
where
    B: Body<Data = Bytes>,
{
    let mut body = std::pin::pin!(body);
    let mut buffer = BytesMut::new();
    let mut held: Option<OwnedSemaphorePermit> = None;

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Refusal::Unreadable)?;
        // Trailers are not forwarded; only data frames are buffered.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        if buffer.len().saturating_add(data.len()) > MAX_REQUEST_BODY {
            return Err(Refusal::TooLarge);
        }
        let charge = u32::try_from(data.len()).map_err(|_| Refusal::TooLarge)?;
        let permit = Arc::clone(budget)
            .try_acquire_many_owned(charge)
            .map_err(|_| Refusal::Saturated)?;
        match &mut held {
            Some(existing) => existing.merge(permit),
            None => held = Some(permit),
        }
        buffer.extend_from_slice(&data);
    }

    Ok((buffer.freeze(), held))
}

/// Handle one request end to end.
async fn handle<S, U, B>(
    proxy: Arc<Proxy<S, U>>,
    request: Request<B>,
) -> Result<Response<ResponseBody>, Infallible>
where
    S: CredentialSource + Send + Sync,
    U: Upstream + Send + Sync,
    U::Body: Body<Data = Bytes> + Send + Sync + 'static,
    <U::Body as Body>::Error: Into<BoxError>,
    B: Body<Data = Bytes>,
{
    // Admission first: a saturated proxy says so at once rather than queueing without bound. The
    // permit is held until the relayed response **body** ends or is dropped (see [`Guarded`]),
    // so `max_in_flight` bounds streams in progress, not just heads being awaited.
    let Ok(admitted) = Arc::clone(&proxy.in_flight).try_acquire_owned() else {
        eprintln!("WARN  preauth-proxy: max_in_flight reached, refusing a request with 503");
        return Ok(message(
            StatusCode::SERVICE_UNAVAILABLE,
            "preauth-proxy: too many requests in flight\n",
        ));
    };

    let (parts, body) = request.into_parts();

    let read_timeout = proxy.config.limits.client_read_timeout;
    let collected = tokio::time::timeout(read_timeout, collect(body, &proxy.buffered)).await;
    let (collected, _charged) = match collected {
        Ok(Ok(collected)) => collected,
        Ok(Err(Refusal::TooLarge)) => {
            return Ok(message(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large to forward\n",
            ));
        }
        Ok(Err(Refusal::Saturated)) => {
            eprintln!(
                "WARN  preauth-proxy: max_buffered_bytes reached, refusing a request with 503"
            );
            return Ok(message(
                StatusCode::SERVICE_UNAVAILABLE,
                "preauth-proxy: request buffers exhausted\n",
            ));
        }
        // The caller went away mid-body. Nobody is left to read this, and it is not worth a
        // credential either way.
        Ok(Err(Refusal::Unreadable)) => {
            return Ok(message(
                StatusCode::BAD_REQUEST,
                "request body could not be read\n",
            ));
        }
        Err(_) => {
            return Ok(message(
                StatusCode::REQUEST_TIMEOUT,
                "request body not received in time\n",
            ));
        }
    };

    let request = Request::from_parts(parts, collected);

    match relay(
        request,
        &proxy.config,
        &proxy.cache,
        &proxy.source,
        &proxy.upstream,
    )
    .await
    {
        Ok(Relayed {
            response,
            renewals,
            renewed_on,
        }) => {
            // RFC 0003 ships no metrics, so this line is the only thing that tells an operator
            // renewal is working. It is emitted per renewal, not per request.
            if let Some(status) = renewed_on {
                eprintln!(
                    "INFO  preauth-proxy: upstream returned {}, re-acquired and replayed {renewals} time(s)",
                    status.as_u16()
                );
            }
            let (parts, body) = response.into_parts();
            let body = Guarded::new(
                body.map_err(Into::into).boxed(),
                proxy.config.limits.response_idle_timeout,
                admitted,
            );
            Ok(Response::from_parts(parts, body.boxed()))
        }
        Err(err) => {
            // Fail-closed: the caller gets no injected session, which for a gated route means the
            // upstream's own challenge, never open access.
            match &err {
                RelayError::Acquire(why) => {
                    eprintln!("ERROR preauth-proxy: acquisition failed: {why}");
                }
                RelayError::Gateway(why) => {
                    eprintln!("ERROR preauth-proxy: upstream unreachable: {why}");
                }
                RelayError::Malformed(why) => {
                    eprintln!("ERROR preauth-proxy: {why}");
                }
            }
            Ok(message(
                StatusCode::BAD_GATEWAY,
                "preauth-proxy: upstream unavailable\n",
            ))
        }
    }
}

/// Serve one connection until it ends, or until `stop` asks it to wind down.
///
/// On `stop` the connection is shut down **gracefully**: a request in progress is answered and
/// its response written, then the connection is closed instead of kept alive.
async fn connection<S, U>(
    proxy: Arc<Proxy<S, U>>,
    stream: TcpStream,
    mut stop: watch::Receiver<bool>,
) where
    S: CredentialSource + Send + Sync + 'static,
    U: Upstream + Send + Sync + 'static,
    U::Body: Body<Data = Bytes> + Send + Sync + 'static,
    <U::Body as Body>::Error: Into<BoxError>,
{
    let read_timeout = proxy.config.limits.client_read_timeout;
    let service = service_fn(move |req| handle(Arc::clone(&proxy), req));

    let mut builder = hyper::server::conn::http1::Builder::new();
    // Without a timer hyper enforces no header timeout at all, and a caller trickling one byte a
    // minute would hold the connection forever.
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(read_timeout);
    let conn = builder.serve_connection(TokioIo::new(stream), service);
    let mut conn = std::pin::pin!(conn);

    // `wait_for` hands back a watch guard that is not `Send`; drop it before the next await.
    let finished = tokio::select! {
        result = conn.as_mut() => Some(result),
        _ = stop.wait_for(|stop| *stop) => None,
    };
    let result = match finished {
        Some(result) => result,
        None => {
            conn.as_mut().graceful_shutdown();
            conn.await
        }
    };
    if let Err(err) = result {
        // Client disconnects and header timeouts land here and are entirely routine.
        eprintln!("DEBUG preauth-proxy: connection ended: {err}");
    }
}

/// Serve until `shutdown` resolves, then drain.
///
/// Draining: the listener closes, every open connection finishes the request it is serving and
/// closes, and `serve` returns once none are left — or once `limits.drain_timeout` has passed, at
/// which point whatever remains is dropped. The deadline exists so the process always exits
/// before the kubelet's `SIGKILL`, on its own terms.
///
/// # Errors
///
/// Propagates an accept failure that is not transient.
pub async fn serve<S, U>(
    proxy: Arc<Proxy<S, U>>,
    listener: TcpListener,
    mut shutdown: impl Future<Output = ()> + Unpin,
) -> std::io::Result<()>
where
    S: CredentialSource + Send + Sync + 'static,
    U: Upstream + Send + Sync + 'static,
    U::Body: Body<Data = Bytes> + Send + Sync + 'static,
    <U::Body as Body>::Error: Into<BoxError>,
{
    let (stop, stopped) = watch::channel(false);
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => {
                    connections.spawn(connection(Arc::clone(&proxy), stream, stopped.clone()));
                }
                // A single connection failing to arrive is not a reason to stop serving the rest.
                Err(err) => eprintln!("WARN  preauth-proxy: accept failed: {err}"),
            },
            // Reap finished connections as they end, so the set tracks only live ones.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            () = &mut shutdown => break,
        }
    }

    drop(listener);
    stop.send_replace(true);

    let drain = proxy.config.limits.drain_timeout;
    let open = connections.len();
    if open > 0 {
        eprintln!(
            "INFO  preauth-proxy: waiting up to {}s for {open} connection(s) to finish",
            drain.as_secs()
        );
    }
    let drained = tokio::time::timeout(drain, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        eprintln!(
            "WARN  preauth-proxy: drain deadline reached, closing {} connection(s)",
            connections.len()
        );
        connections.shutdown().await;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;
    use crate::domain::config::{
        Acquisition, Inject, InjectMode, Limits, Origin, Passthrough, Renew, Take,
    };
    use crate::domain::port::{AcquireError, Credential, GatewayError};
    use http::Method;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::Notify;

    fn config(limits: Limits) -> Config {
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
                mode: InjectMode::Set,
            },
            renew: Renew::default(),
            limits,
        }
    }

    struct Fixed;

    impl CredentialSource for Fixed {
        async fn acquire(&self) -> Result<Credential, AcquireError> {
            Ok(Credential::new("sid=x"))
        }
    }

    /// Answers `200` — after `gate` is notified, when there is one.
    #[derive(Default)]
    struct Slow {
        gate: Option<Arc<Notify>>,
        started: Arc<Notify>,
    }

    impl Upstream for Slow {
        type Body = Full<Bytes>;

        async fn forward(
            &self,
            _request: Request<Bytes>,
        ) -> Result<Response<Self::Body>, GatewayError> {
            self.started.notify_one();
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            Ok(Response::new(Full::new(Bytes::from_static(b"done"))))
        }
    }

    fn proxy(limits: Limits, upstream: Slow) -> Arc<Proxy<Fixed, Slow>> {
        Arc::new(Proxy::new(config(limits), Cache::new(), Fixed, upstream))
    }

    fn get(body: &'static [u8]) -> Request<Full<Bytes>> {
        Request::builder()
            .uri("/page")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn a_saturated_proxy_answers_503_at_once() {
        let limits = Limits {
            max_in_flight: 1,
            ..Limits::default()
        };
        let proxy = proxy(limits, Slow::default());
        let busy = Arc::clone(&proxy.in_flight).try_acquire_owned().unwrap();

        let response = handle(Arc::clone(&proxy), get(b"")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(busy);
        let response = handle(proxy, get(b"")).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the permit was not returned"
        );
    }

    #[tokio::test]
    async fn an_exhausted_body_budget_answers_503_and_bodyless_requests_still_pass() {
        let proxy = proxy(Limits::default(), Slow::default());
        let spent = proxy.config.limits.max_buffered_bytes - 3;
        let _spent = Arc::clone(&proxy.buffered)
            .try_acquire_many_owned(u32::try_from(spent).unwrap())
            .unwrap();

        let response = handle(Arc::clone(&proxy), get(b"four")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let response = handle(Arc::clone(&proxy), get(b"")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A request's charge is released once it has been answered.
        let response = handle(Arc::clone(&proxy), get(b"thr")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(proxy.buffered.available_permits(), 3);
    }

    /// A response body fed frame by frame from the test, over a channel.
    struct Fed(tokio::sync::mpsc::Receiver<Bytes>);

    impl Body for Fed {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            self.0
                .poll_recv(cx)
                .map(|next| next.map(|data| Ok(Frame::data(data))))
        }
    }

    /// Answers `200` with a body the test drives through the paired sender.
    struct Streaming(std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Bytes>>>);

    impl Upstream for Streaming {
        type Body = Fed;

        async fn forward(
            &self,
            _request: Request<Bytes>,
        ) -> Result<Response<Self::Body>, GatewayError> {
            let rx = self.0.lock().unwrap().take().unwrap();
            Ok(Response::new(Fed(rx)))
        }
    }

    fn streaming(
        limits: Limits,
    ) -> (
        Arc<Proxy<Fixed, Streaming>>,
        tokio::sync::mpsc::Sender<Bytes>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let upstream = Streaming(std::sync::Mutex::new(Some(rx)));
        (
            Arc::new(Proxy::new(config(limits), Cache::new(), Fixed, upstream)),
            tx,
        )
    }

    #[tokio::test]
    async fn the_in_flight_slot_is_held_until_the_body_ends() {
        let limits = Limits {
            max_in_flight: 1,
            ..Limits::default()
        };
        let (proxy, tx) = streaming(limits);

        let response = handle(Arc::clone(&proxy), get(b"")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            proxy.in_flight.available_permits(),
            0,
            "the slot was released with the head, before the body streamed"
        );
        let mut body = response.into_body();

        tx.send(Bytes::from_static(b"part")).await.unwrap();
        let frame = body.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"part"));
        assert_eq!(
            proxy.in_flight.available_permits(),
            0,
            "released mid-stream"
        );

        drop(tx);
        assert!(body.frame().await.is_none());
        assert_eq!(
            proxy.in_flight.available_permits(),
            1,
            "end-of-stream did not release the slot"
        );
        drop(body);
        assert_eq!(proxy.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_dropped_body_releases_its_slot() {
        let limits = Limits {
            max_in_flight: 1,
            ..Limits::default()
        };
        let (proxy, _tx) = streaming(limits);

        let response = handle(Arc::clone(&proxy), get(b"")).await.unwrap();
        assert_eq!(proxy.in_flight.available_permits(), 0);
        // The caller hung up mid-stream: hyper drops the body.
        drop(response);
        assert_eq!(proxy.in_flight.available_permits(), 1);
    }

    #[tokio::test]
    async fn an_idle_response_body_is_cut_after_the_idle_timeout() {
        let limits = Limits {
            max_in_flight: 1,
            response_idle_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let (proxy, tx) = streaming(limits);

        let mut body = handle(Arc::clone(&proxy), get(b""))
            .await
            .unwrap()
            .into_body();

        // Frames keep arriving within the idle window: each one resets the deadline, so a
        // stream longer than the timeout in total is not cut.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            tx.send(Bytes::from_static(b"tick")).await.unwrap();
            assert!(body.frame().await.unwrap().is_ok());
        }

        // Then the upstream goes silent without ending the body.
        let begun = Instant::now();
        let cut = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .unwrap_or_else(|_| panic!("the idle body was never cut"));
        assert!(matches!(cut, Some(Err(_))), "expected an error frame");
        assert!(begun.elapsed() >= Duration::from_millis(90));
        assert_eq!(
            proxy.in_flight.available_permits(),
            1,
            "the cut body kept its slot"
        );
        assert!(
            body.frame().await.is_none(),
            "a cut body yields nothing more"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn a_body_over_the_cap_is_413() {
        let big: &'static [u8] = Box::leak(vec![b'x'; MAX_REQUEST_BODY + 1].into_boxed_slice());
        let proxy = proxy(Limits::default(), Slow::default());

        let response = handle(Arc::clone(&proxy), get(big)).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            proxy.buffered.available_permits(),
            proxy.config.limits.max_buffered_bytes,
            "a refused body kept its charge"
        );
    }

    async fn bound(
        proxy: Arc<Proxy<Fixed, Slow>>,
    ) -> (
        SocketAddr,
        Arc<Notify>,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(Notify::new());
        let signal = Arc::clone(&shutdown);
        let server = tokio::spawn(serve(
            proxy,
            listener,
            Box::pin(async move { signal.notified().await }),
        ));
        (addr, shutdown, server)
    }

    async fn raw_get(addr: SocketAddr) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /page HTTP/1.1\r\nHost: proxy\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        // A connection closed by the drain deadline may end in a reset; either way, what was
        // read is the answer.
        let _ = stream.read_to_string(&mut out).await;
        out
    }

    #[tokio::test]
    async fn shutdown_lets_an_in_flight_request_finish() {
        let gate = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let upstream = Slow {
            gate: Some(Arc::clone(&gate)),
            started: Arc::clone(&started),
        };
        let (addr, shutdown, server) = bound(proxy(Limits::default(), upstream)).await;

        let client = tokio::spawn(raw_get(addr));
        started.notified().await;

        // SIGTERM arrives while the upstream is still working on the request.
        shutdown.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !server.is_finished(),
            "serve returned with a request in flight"
        );

        gate.notify_one();
        let response = client.await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("done"), "{response}");
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_drain_is_bounded_by_its_deadline() {
        let started = Arc::new(Notify::new());
        let upstream = Slow {
            // Never notified: this request never completes on its own.
            gate: Some(Arc::new(Notify::new())),
            started: Arc::clone(&started),
        };
        let limits = Limits {
            drain_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let (addr, shutdown, server) = bound(proxy(limits, upstream)).await;

        let client = tokio::spawn(raw_get(addr));
        started.notified().await;

        let begun = Instant::now();
        shutdown.notify_one();
        server.await.unwrap().unwrap();
        assert!(
            begun.elapsed() < Duration::from_secs(5),
            "the drain outlived its deadline"
        );
        // The stuck connection was closed rather than left open.
        let response = client.await.unwrap();
        assert!(response.is_empty(), "{response}");
    }

    #[tokio::test]
    async fn a_caller_that_never_finishes_its_headers_is_disconnected() {
        let limits = Limits {
            client_read_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let (addr, shutdown, server) = bound(proxy(limits, Slow::default())).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /page HTTP/1.1\r\nHost: pr")
            .await
            .unwrap();

        let mut out = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out)).await;
        assert!(
            read.is_ok(),
            "a half-sent request head held the connection open"
        );

        shutdown.notify_one();
        server.await.unwrap().unwrap();
    }
}
