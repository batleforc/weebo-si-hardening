//! `endpoint-gateway` — one OIDC relying party and one authorisation decision in front of every
//! workspace endpoint exposed on its own FQDN.
//!
//! The design is [RFC 0009](../../../docs/rfc/0009-endpoint-auth.md). This file is the
//! composition root and nothing else: it reads a configuration file, builds the adapters, and
//! hands them to `weebo-si-endpoint-auth`, which owns every decision this process makes.
//!
//! The property to keep in view while reading the rest: **`/auth` performs no I/O.** Every input
//! to a decision is in memory before the request arrives, put there by one of the watches started
//! below. That is RFC 0009's *Request cost*, and it is the reason a page load of two hundred
//! assets costs two hundred map reads rather than two hundred round trips.

mod adapters;
mod config;
mod http;
mod probe;
mod proxy;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use adapters::kube_catalog::KubeCatalog;
use adapters::kube_revocations::KubeRevocations;
use adapters::kube_workload::KubeWorkloadIdentity;
use adapters::metrics::GatewayMetrics;
use adapters::oidc::{JwksCache, JwksVerifier, OidcClient, discover, refresh_jwks};
use adapters::session::SealedCodec;
use config::{Enforcement as ConfigEnforcement, GatewayConfig, PodNetwork};
use state::{GatewayState, SystemClock};
use weebo_si_endpoint_auth::Enforcement;

/// Default config path.
const DEFAULT_CONFIG: &str = "/etc/endpoint-gateway/config.yaml";
/// The environment variable holding the session keys, newest first, comma-separated base64.
const SESSION_KEYS_ENV: &str = "ENDPOINT_GATEWAY_SESSION_KEYS";

const USAGE: &str = "\
endpoint-gateway — authenticate and authorise every workspace endpoint on its own FQDN

usage: endpoint-gateway [--config <PATH>] [--check]

options:
  --config <PATH>   config file (env ENDPOINT_GATEWAY_CONFIG, default: /etc/endpoint-gateway/config.yaml)
  --check           parse and validate the config, check the issuer's discovery document, exit
  -h, --help        this text

The session keys are supplied as ENDPOINT_GATEWAY_SESSION_KEYS: base64, 32 bytes each, newest
first, comma-separated. The client secret is supplied as the variable config names in
`client_secret_env`.
";

mod exit {
    /// Clean shutdown, or `--check` on a valid configuration.
    pub const OK: u8 = 0;
    /// The configuration is unusable.
    pub const CONFIG: u8 = 2;
    /// The cluster or the identity provider refused something this process cannot start without.
    pub const STARTUP: u8 = 3;
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print!("{USAGE}");
        return ExitCode::from(exit::OK);
    }
    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        eprintln!("endpoint-gateway: could not install the ring crypto provider: {err:?}");
        return ExitCode::from(exit::STARTUP);
    }

    let path = flag(&args, "--config")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("ENDPOINT_GATEWAY_CONFIG")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let config = match GatewayConfig::load(&path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("endpoint-gateway: {err}");
            return ExitCode::from(exit::CONFIG);
        }
    };

    if args.iter().any(|arg| arg == "--check") {
        return check(&config).await;
    }

    match run(config).await {
        Ok(()) => ExitCode::from(exit::OK),
        Err(err) => {
            eprintln!("endpoint-gateway: {err}");
            ExitCode::from(exit::STARTUP)
        }
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|at| args.get(at + 1))
        .map(String::as_str)
}

/// `--check`: everything that can be verified without serving a request.
async fn check(config: &GatewayConfig) -> ExitCode {
    println!("config: valid");
    println!("  listen:  {}", config.listen);
    println!("  issuer:  {}", config.issuer);
    println!("  suffix:  {}", config.hosts.suffix);
    println!(
        "  claims:  username={} groups={}",
        config.claims.username, config.claims.groups
    );
    match discover(&config.issuer).await {
        Ok(discovery) => {
            println!("discovery: ok");
            println!(
                "  authorization_endpoint: {}",
                discovery.authorization_endpoint
            );
            println!("  jwks_uri:               {}", discovery.jwks_uri);
            // RFC 0009's *Revocation*: absent back-channel logout is a `Degraded` condition and a
            // fallback to periodic revalidation, never a silent twelve-hour window.
            match discovery.advertises_claim(&config.claims.username) {
                Some(true) => println!("  claims.username:        advertised by the issuer"),
                Some(false) => println!(
                    "  claims.username:        NOT advertised — {:?} is not in claims_supported; \
                     every owner check would fail closed",
                    config.claims.username
                ),
                None => {
                    println!("  claims.username:        the issuer publishes no claims_supported")
                }
            }
            println!(
                "  backchannel logout:     {}",
                match (
                    discovery.backchannel_logout_supported,
                    discovery.backchannel_logout_session_supported,
                ) {
                    // A logout token with no `sid` names no session, so the mechanism exists and
                    // cannot revoke one: reporting "supported" for it would be the worst of the
                    // three answers.
                    (true, true) => "supported, with a session id",
                    (true, false) => {
                        "advertised WITHOUT a session id — nothing to revoke by; revalidation is                          the mechanism"
                    }
                    (false, _) =>
                        "NOT supported — sessions are cut off at revalidation, not at logout",
                }
            );
            ExitCode::from(exit::OK)
        }
        Err(err) => {
            eprintln!("discovery: {err}");
            ExitCode::from(exit::STARTUP)
        }
    }
}

async fn run(config: GatewayConfig) -> Result<(), String> {
    let addr: SocketAddr = config
        .listen
        .parse()
        .map_err(|err| format!("invalid listen address {:?}: {err}", config.listen))?;
    let scope = config
        .scope()
        .map_err(|err| format!("invalid host scope: {err:?}"))?;

    let keys: Vec<String> = std::env::var(SESSION_KEYS_ENV)
        .map_err(|_| format!("{SESSION_KEYS_ENV} is not set: without it this gateway would mint cookies nothing can open"))?
        .split(',')
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .collect();
    let codec = SealedCodec::new(&keys).map_err(|err| err.to_string())?;

    let registry = prometheus::Registry::new();
    let metrics = GatewayMetrics::register(&registry).map_err(|err| err.to_string())?;

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("could not build a Kubernetes client: {err}"))?;

    // Discovery and the JWKS refresh are the only network calls this process makes outside a
    // sign-in, and both are off the request path: the keys land in a cache a synchronous verifier
    // reads.
    let jwks = JwksCache::default();
    let discovery = discover(&config.issuer).await;
    let oidc = match discovery {
        Ok(discovery) => {
            // The startup check RFC 0009 keeps even though question 3 answered "yes": it is one
            // call, and it turns a cluster-wide lockout into a line an admin reads at boot.
            if discovery.advertises_claim(&config.claims.username) == Some(false) {
                eprintln!(
                    "WARN endpoint-gateway: the issuer does not advertise {:?}; if it is not the \
                     claim Che derives usernames from, every owner check will fail closed",
                    config.claims.username
                );
            }
            if !discovery.backchannel_logout_supported {
                eprintln!(
                    "WARN endpoint-gateway: the issuer does not support back-channel logout; \
                     sessions are cut off at revalidation ({}s), not at logout",
                    config.revalidation.interval_secs
                );
            }
            tokio::spawn(refresh_jwks(
                discovery.jwks_uri.clone(),
                jwks.clone(),
                Duration::from_secs(600),
            ));
            let secret = std::env::var(&config.client_secret_env).unwrap_or_default();
            if secret.is_empty() {
                println!(
                    "WARN endpoint-gateway: {} is empty; a public client cannot complete a code exchange",
                    config.client_secret_env
                );
            }
            Some(OidcClient::new(
                discovery,
                config.client_id.clone(),
                secret,
                config.redirect_url.clone(),
            ))
        }
        Err(err) => {
            // Not fatal on purpose: an identity provider that is down must not stop a gateway
            // from answering with the cookies and tokens it already holds. What is unavailable
            // is a *new* sign-in, which is what the metric and this line say.
            eprintln!("WARN endpoint-gateway: discovery failed ({err}); sign-in is unavailable");
            None
        }
    };
    let verifier = JwksVerifier::new(
        jwks,
        config.issuer.clone(),
        [config.client_id.clone()],
        config.claims.username.clone(),
        config.claims.groups.clone(),
    );

    let catalog = KubeCatalog::spawn(
        client.clone(),
        scope.clone(),
        config.compile_settings(),
        Some((
            "app.kubernetes.io/part-of".to_owned(),
            "che.eclipse.org".to_owned(),
        )),
    )
    .await
    .map_err(|err| format!("could not start the endpoint watches: {err}"))?;

    let workloads = KubeWorkloadIdentity::spawn(
        client.clone(),
        config.self_origin.pod_network != PodNetwork::Off,
        config.self_origin.service_account_token,
        config.cache.token_review_max_entries,
    )
    .await
    .map_err(|err| format!("could not start the workspace-pod watch: {err}"))?;

    let revocations = KubeRevocations::spawn(
        client,
        config.backchannel_logout.namespace.clone(),
        config.backchannel_logout.configmap.clone(),
    )
    .await
    .map_err(|err| format!("could not start the revocation watch: {err}"))?;
    tokio::spawn(Arc::clone(&revocations).sweep_forever(|| SystemClock.now_timestamp()));

    let caches = GatewayState::caches(&config);
    let enforcement = match config.enforcement {
        ConfigEnforcement::Observe => Enforcement::Observe,
        ConfigEnforcement::Enforce => Enforcement::Enforce,
    };
    if enforcement == Enforcement::Observe {
        println!(
            "endpoint-gateway: enforcement=Observe — every decision is computed, logged and \
             counted, and every verdict is answered 200"
        );
    }

    let state = Arc::new(GatewayState {
        config,
        scope,
        catalog,
        workloads,
        revocations,
        codec,
        verifier,
        oidc,
        clock: SystemClock,
        session_cache: caches.sessions,
        bearer_cache: caches.bearers,
        service_account_cache: caches.service_accounts,
        redeemed: caches.redeemed,
        logged: caches.logged,
        allows: std::sync::atomic::AtomicU64::new(0),
        metrics,
        registry,
        enforcement,
        proxy: proxy::client(),
        selftest_token: adapters::session::random_id()
            .ok_or_else(|| "no randomness available for the probe token".to_string())?,
        keys_generation: std::sync::atomic::AtomicU64::new(0),
        published: std::sync::Mutex::new(Default::default()),
    });

    if state.config.probe.enabled && state.config.self_origin.pod_network != PodNetwork::Off {
        let url = if state.config.probe.url.is_empty() {
            state.config.redirect_base().to_owned()
        } else {
            state.config.probe.url.clone()
        };
        let interval = Duration::from_secs(state.config.probe.interval_seconds.max(60));
        tokio::spawn(probe::run(Arc::clone(&state), url, interval));
    }

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("could not bind {addr}: {err}"))?;
    if state.config.reverse_proxy {
        // Said out loud, once, at the only moment somebody is looking: the dialect is
        // implemented and it is not *supported* — nothing has run it against a real OpenShift
        // router, and its tests are a deferred tier the base suite skips.
        println!(
            "WARN endpoint-gateway: reverse_proxy is enabled. That mode puts this process on the \
             data path of every request, and it has never been validated against a real \
             OpenShift router — see RFC 0009's implementation plan before relying on it."
        );
    }
    println!(
        "endpoint-gateway listening on {addr} ({})",
        if state.config.reverse_proxy {
            "reverse-proxy: this process carries application traffic"
        } else {
            "forward-auth: this process answers questions and carries nothing"
        }
    );
    // `ConnectInfo`, because the reverse-proxy shell decides whether to believe a client-address
    // header from the *connection* rather than from the header.
    axum::serve(
        listener,
        http::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|err| format!("server error: {err}"))
}
