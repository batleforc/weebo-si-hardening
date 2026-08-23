//! End-to-end tests: the real binary, a fake origin and a fake upstream on real sockets.
//!
//! These cover what the unit suites cannot — the process actually binding, acquiring at startup,
//! and the exit codes [RFC 0003](../../../docs/rfc/0003-preauth-proxy.md) makes a contract of.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]

use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::{TcpListener, TcpStream};

const BIN: &str = env!("CARGO_BIN_EXE_preauth-proxy");

/// How the fake origin should answer the acquisition exchange.
#[derive(Clone, Copy)]
enum OriginBehaviour {
    /// Mint `sid=token<N>`, incrementing per call.
    Mint,
    /// Refuse with `403`.
    Refuse,
    /// Answer `200` but with no `Set-Cookie`.
    NoHeader,
}

#[derive(Default)]
struct Counters {
    logins: AtomicUsize,
    upstream_hits: AtomicUsize,
}

/// A fake origin: the thing the acquisition exchange talks to.
async fn spawn_origin(behaviour: OriginBehaviour, counters: Arc<Counters>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let counters = Arc::clone(&counters);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| {
                    let counters = Arc::clone(&counters);
                    async move {
                        let n = counters.logins.fetch_add(1, Ordering::SeqCst);
                        let response = match behaviour {
                            OriginBehaviour::Mint => Response::builder()
                                .status(StatusCode::OK)
                                .header("Set-Cookie", format!("sid=token{n}; Path=/; HttpOnly"))
                                .body(Empty::<Bytes>::new()),
                            OriginBehaviour::Refuse => Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Empty::<Bytes>::new()),
                            OriginBehaviour::NoHeader => Response::builder()
                                .status(StatusCode::OK)
                                .body(Empty::<Bytes>::new()),
                        };
                        response.map_err(|err| std::io::Error::other(err.to_string()))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

/// A fake upstream that echoes the `Cookie` it received and answers a scripted status.
///
/// `reject_first` makes the first request answer `401`, which is how the renewal path is driven.
async fn spawn_upstream(reject_first: bool, counters: Arc<Counters>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let counters = Arc::clone(&counters);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let counters = Arc::clone(&counters);
                    async move {
                        let n = counters.upstream_hits.fetch_add(1, Ordering::SeqCst);
                        let cookie = req
                            .headers()
                            .get(http::header::COOKIE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_owned();
                        let host = req
                            .headers()
                            .get(http::header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_owned();
                        let status = if reject_first && n == 0 {
                            StatusCode::UNAUTHORIZED
                        } else {
                            StatusCode::OK
                        };
                        Response::builder()
                            .status(status)
                            .header("X-Seen-Cookie", &cookie)
                            .header("X-Seen-Host", &host)
                            .body(Full::new(Bytes::from(format!("cookie={cookie}"))))
                            .map_err(|err| std::io::Error::other(err.to_string()))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    addr
}

/// Grab a port the proxy can bind. Racy in principle, fine in a test.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn config_document(listen: u16, upstream: SocketAddr, origin: SocketAddr, renew: bool) -> String {
    let renew_block = if renew {
        "renew:\n  on_status: [401]\n  max_replays: 1\n"
    } else {
        ""
    };
    format!(
        "listen: \"127.0.0.1:{listen}\"\n\
         upstream: \"http://{upstream}\"\n\
         passthrough:\n  \
           header: Cookie\n  \
           contains: \"session=\"\n\
         credential:\n  \
           origin: \"http://{origin}\"\n  \
           request:\n    \
             method: POST\n    \
             path: \"/login\"\n    \
             headers:\n      \
               Content-Type: \"application/x-www-form-urlencoded\"\n    \
             body: \"email=${{CRED_USER}}&password=${{CRED_SECRET}}\"\n  \
           accept_status: [200]\n  \
           extract:\n    \
             from_header: \"Set-Cookie\"\n    \
             take: cookie-pair\n\
         inject:\n  \
           header: Cookie\n  \
           mode: append\n\
         {renew_block}"
    )
}

#[derive(Debug)]
struct Proxy {
    child: std::process::Child,
    addr: SocketAddr,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write the config, start the binary, and wait until it accepts connections.
///
/// Every exit path reaps the child: the `Ok` path hands it to [`Proxy`], whose `Drop` kills and
/// waits; the `Err` path has already seen `try_wait` return; the timeout path waits explicitly.
#[allow(
    clippy::zombie_processes,
    reason = "reaped by Proxy::drop, by try_wait, or explicitly below"
)]
async fn start_proxy(dir: &tempfile::TempDir, document: &str) -> Result<Proxy, i32> {
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, document).unwrap();

    let listen: SocketAddr = document
        .lines()
        .find_map(|line| line.strip_prefix("listen: "))
        .unwrap()
        .trim_matches('"')
        .parse()
        .unwrap();

    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .env("CRED_USER", "svc@example.test")
        .env("CRED_SECRET", "hunter2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Err(status.code().unwrap_or(-1));
        }
        if TcpStream::connect(listen).await.is_ok() {
            return Ok(Proxy {
                child,
                addr: listen,
            });
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("the proxy never started listening on {listen}");
}

/// One request through the proxy.
async fn get(addr: SocketAddr, path: &str, cookie: Option<&str>) -> Response<Bytes> {
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let mut builder = Request::builder()
        .method("GET")
        .uri(format!("http://{addr}{path}"));
    if let Some(cookie) = cookie {
        builder = builder.header(http::header::COOKIE, cookie);
    }
    let request = builder.body(Full::new(Bytes::new())).unwrap();

    let response = client.request(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Response::from_parts(parts, bytes)
}

fn header(response: &Response<Bytes>, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn a_first_request_acquires_and_injects() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(false, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header(&response, "X-Seen-Cookie"), "sid=token0");
    // The Host was rewritten to the upstream, not left naming the proxy.
    assert_eq!(header(&response, "X-Seen-Host"), upstream.to_string());
    // One login at startup, and none since: the second request reuses the cache.
    get(proxy.addr, "/again", None).await;
    assert_eq!(counters.logins.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_request_carrying_the_marker_is_passed_through_untouched() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(false, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", Some("session=mine")).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header(&response, "X-Seen-Cookie"),
        "session=mine",
        "the caller's own session was overridden"
    );
}

#[tokio::test]
async fn a_caller_cookie_without_the_marker_is_joined_not_replaced() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(false, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", Some("theme=dark")).await;

    assert_eq!(header(&response, "X-Seen-Cookie"), "theme=dark; sid=token0");
}

#[tokio::test]
async fn a_401_renews_and_replays_once() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(true, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", None).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the replay did not succeed"
    );
    assert_eq!(
        header(&response, "X-Seen-Cookie"),
        "sid=token1",
        "the replay reused the rejected credential"
    );
    assert_eq!(counters.upstream_hits.load(Ordering::SeqCst), 2);
    assert_eq!(counters.logins.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn without_renewal_configured_the_401_is_relayed() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(true, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, false);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(counters.upstream_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unreachable_upstream_is_a_502_never_an_open_door() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Mint, Arc::clone(&counters)).await;
    // An address nothing is listening on.
    let dead: SocketAddr = format!("127.0.0.1:{}", free_port().await).parse().unwrap();
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, dead, origin, true);
    let proxy = start_proxy(&dir, &doc).await.unwrap();

    let response = get(proxy.addr, "/page", None).await;

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn a_refusing_origin_stops_the_rollout_with_exit_three() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::Refuse, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(false, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let code = start_proxy(&dir, &doc).await.unwrap_err();

    assert_eq!(
        code, 3,
        "a bad credential must fail the deploy, not degrade"
    );
}

#[tokio::test]
async fn an_origin_that_mints_nothing_also_exits_three() {
    let counters = Arc::new(Counters::default());
    let origin = spawn_origin(OriginBehaviour::NoHeader, Arc::clone(&counters)).await;
    let upstream = spawn_upstream(false, Arc::clone(&counters)).await;
    let dir = tempfile::tempdir().unwrap();

    let doc = config_document(free_port().await, upstream, origin, true);
    let code = start_proxy(&dir, &doc).await.unwrap_err();

    assert_eq!(code, 3);
}

#[test]
fn check_validates_without_touching_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    // Origins that resolve to nothing: --check must not care.
    let doc = config_document(
        8080,
        "127.0.0.1:1".parse().unwrap(),
        "127.0.0.1:2".parse().unwrap(),
        true,
    );
    std::fs::write(&path, &doc).unwrap();

    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .env("CRED_USER", "svc@example.test")
        .env("CRED_SECRET", "hunter2")
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("reference(s) resolved"), "{stdout}");
    assert!(
        !stdout.contains("hunter2"),
        "--check printed the service password: {stdout}"
    );
    assert!(
        !stdout.contains("svc@example.test"),
        "--check printed the service account: {stdout}"
    );
}

#[test]
fn an_unset_secret_is_exit_two_and_never_an_empty_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let doc = config_document(
        8080,
        "127.0.0.1:1".parse().unwrap(),
        "127.0.0.1:2".parse().unwrap(),
        true,
    );
    std::fs::write(&path, &doc).unwrap();

    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .env("CRED_USER", "svc")
        .env_remove("CRED_SECRET")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CRED_SECRET"));
}

#[test]
fn a_malformed_config_is_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    std::fs::write(&path, "listen: [\n").unwrap();

    let out = Command::new(BIN)
        .arg("--config")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn a_missing_config_is_exit_one() {
    let out = Command::new(BIN)
        .arg("--config")
        .arg("/nonexistent/preauth.yaml")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("/nonexistent/preauth.yaml"));
}
