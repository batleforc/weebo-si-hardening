//! The listener: one connection at a time turned into a domain call.
//!
//! It owns no policy. It collects the request facts, hands them to
//! [`crate::domain::exchange::relay`], and turns whatever comes back into a response.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::domain::config::Config;
use crate::domain::credential::Cache;
use crate::domain::exchange::{RelayError, Relayed, relay};
use crate::domain::port::{CredentialSource, Upstream};

/// Largest request body accepted.
///
/// A body has to be buffered because a request may be **replayed** after a renewal, and a stream
/// cannot be replayed. Response bodies are streamed and are not bounded by this.
const MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;

/// The body type every response this server produces shares.
type ResponseBody = BoxBody<Bytes, hyper::Error>;

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

/// Handle one request end to end.
async fn handle<S, U>(
    proxy: Arc<Proxy<S, U>>,
    request: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible>
where
    S: CredentialSource + Send + Sync,
    U: Upstream<Body = Incoming> + Send + Sync,
{
    let (parts, body) = request.into_parts();

    let collected = match Limited::new(body, MAX_REQUEST_BODY).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            // Either the body exceeded the cap or the caller went away. Both are the caller's,
            // and neither is worth a credential.
            return Ok(message(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large to forward\n",
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

/// Serve until `shutdown` resolves.
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
    U: Upstream<Body = Incoming> + Send + Sync + 'static,
{
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _peer)) => stream,
                // A single connection failing to arrive is not a reason to stop serving the rest.
                Err(err) => {
                    eprintln!("WARN  preauth-proxy: accept failed: {err}");
                    continue;
                }
            },
            () = &mut shutdown => return Ok(()),
        };

        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(Arc::clone(&proxy), req));
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                // Client disconnects land here and are entirely routine.
                eprintln!("DEBUG preauth-proxy: connection ended: {err}");
            }
        });
    }
}
