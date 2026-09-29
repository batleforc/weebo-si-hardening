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
mod outbound;
mod probe;
mod proxy;
mod ratelimit;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use adapters::introspection::{Introspector, IntrospectorPorts};
use adapters::kube_catalog::KubeCatalog;
use adapters::kube_revocations::KubeRevocations;
use adapters::kube_workload::KubeWorkloadIdentity;
use adapters::metrics::GatewayMetrics;
use adapters::oidc::{JwksCache, JwksVerifier, OidcClient, VerifierPorts, discover, refresh_jwks};
use adapters::session::SealedCodec;
use config::{Enforcement as ConfigEnforcement, GatewayConfig, PodNetwork};
use ratelimit::{Rate, RateLimiter};
use state::{GatewayState, SystemClock};
use weebo_si_endpoint_auth::Enforcement;
use weebo_si_endpoint_auth::port::RevocationStore;

/// Default config path.
const DEFAULT_CONFIG: &str = "/etc/endpoint-gateway/config.yaml";
/// The environment variable holding the session keys, newest first, comma-separated base64.
const SESSION_KEYS_ENV: &str = "ENDPOINT_GATEWAY_SESSION_KEYS";

const USAGE: &str = "\
endpoint-gateway — authenticate and authorise every workspace endpoint on its own FQDN

usage: endpoint-gateway [--config <PATH>] [--check [--explain-token]]

options:
  --config <PATH>   config file (env ENDPOINT_GATEWAY_CONFIG, default: /etc/endpoint-gateway/config.yaml)
  --check           parse and validate the config, check the issuer's discovery document, exit
  --explain-token   with --check: read a token on stdin and print which check accepts or refuses it
  -h, --help        this text

The session keys are supplied as ENDPOINT_GATEWAY_SESSION_KEYS: 32 random bytes each, base64
(standard or url-safe, padded or not — `openssl rand -base64 32`), newest first,
comma-separated. The client secret is supplied as the variable config names in
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

    if let Err(err) = outbound::init(&config.extra_ca_file) {
        eprintln!("endpoint-gateway: {err}");
        return ExitCode::from(exit::CONFIG);
    }

    if args.iter().any(|arg| arg == "--check") {
        return check(&config, args.iter().any(|arg| arg == "--explain-token")).await;
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
///
/// The one thing it cannot do is invent a cluster, so the revocation set it checks a token
/// against is empty — said out loud in the output rather than left for a reader to wonder about.
async fn check(config: &GatewayConfig, explain_token: bool) -> ExitCode {
    println!("config: valid");
    println!("  listen:  {}", config.listen);
    println!("  issuer:  {}", config.issuer);
    if !config.extra_ca_file.is_empty() {
        println!("  extra CA: {}", config.extra_ca_file);
    }
    println!("  suffix:  {}", config.hosts.suffix);
    println!(
        "  claims:  username={} groups={}",
        config.claims.username, config.claims.groups
    );
    // Already enforced at load — an empty list with `verify_own_issuer` on never reaches here —
    // so this reports what was accepted rather than re-deriving it.
    let rules = match config.bearer_rules() {
        Ok(rules) => rules,
        Err(err) => {
            eprintln!("bearer: {err}");
            return ExitCode::from(exit::CONFIG);
        }
    };
    match rules.as_ref() {
        None => println!("  bearer:  verify_own_issuer is off; every bearer is foreign"),
        Some(rules) => {
            println!(
                "  bearer:  audiences=[{}]",
                rules.audiences().collect::<Vec<_>>().join(", ")
            );
            for party in rules.authorized_parties() {
                println!(
                    "  bearer:  WARNING authorized_parties accepts tokens minted for {party:?} \
                     with an audience this gateway does not know. That is the compatibility mode \
                     — it accepts a credential minted for somebody else's audience. Prefer an \
                     audience mapper on that client."
                );
            }
        }
    }

    let discovery = match discover(&config.issuer).await {
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
            discovery
        }
        Err(err) => {
            eprintln!("discovery: {err}");
            return ExitCode::from(exit::STARTUP);
        }
    };

    // The check that turns "introspection is on" into "introspection has somewhere to go". A
    // gateway that starts without it would refuse every non-browser caller on the one platform
    // the feature exists for, while looking healthy.
    if config.bearer.introspection.enabled {
        let endpoint = if config.bearer.introspection.endpoint.is_empty() {
            discovery.introspection_endpoint.clone()
        } else {
            Some(config.bearer.introspection.endpoint.clone())
        };
        match endpoint {
            Some(endpoint) => println!("  introspection:          {endpoint}"),
            None => {
                eprintln!(
                    "introspection: enabled, and the issuer advertises no introspection_endpoint \
                     — set bearer.introspection.endpoint or turn it off"
                );
                return ExitCode::from(exit::CONFIG);
            }
        }
    }

    if explain_token {
        return explain(config, &discovery, rules.as_ref()).await;
    }
    ExitCode::from(exit::OK)
}

/// An empty revocation set, for `--explain-token`: there is no cluster here to read one from, and
/// the output says so rather than implying a `sid` was checked.
struct NoRevocations;

impl RevocationStore for NoRevocations {
    fn is_revoked(&self, _session: &weebo_si_endpoint_auth::identity::SessionId) -> bool {
        false
    }
}

/// `--check --explain-token`: read a token on stdin and print the path the verifier took.
///
/// The failure this removes is a developer reading their own `fetch` wrapper for an afternoon
/// because a gate nobody told them about answered `401` to a token that looked, from where they
/// were standing, entirely valid.
async fn explain(
    config: &GatewayConfig,
    discovery: &adapters::oidc::Discovery,
    rules: Option<&weebo_si_endpoint_auth::bearer::BearerRules>,
) -> ExitCode {
    use std::io::Read;

    let mut token = String::new();
    if std::io::stdin().read_to_string(&mut token).is_err() || token.trim().is_empty() {
        eprintln!("--explain-token reads a token on stdin, and stdin was empty");
        return ExitCode::from(exit::CONFIG);
    }
    let token = token.trim().trim_start_matches("Bearer ").trim();

    println!();
    if Introspector::is_opaque(token) {
        println!("shape     opaque — not a JWT, so only introspection can resolve it");
        println!(
            "          introspection is {}",
            if config.bearer.introspection.enabled {
                "on; run this token against the issuer's introspection endpoint to see its claims"
            } else {
                "OFF — this gateway would answer 401 to it"
            }
        );
        return ExitCode::from(if config.bearer.introspection.enabled {
            exit::OK
        } else {
            exit::CONFIG
        });
    }

    // One fetch, not the background refresh: this is a command, not a process.
    let jwks = JwksCache::default();
    match outbound::client()
        .get(&discovery.jwks_uri)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(response) => match response.json::<jsonwebtoken::jwk::JwkSet>().await {
            Ok(keys) => jwks.store(keys),
            Err(err) => {
                eprintln!("jwks: unreadable: {err}");
                return ExitCode::from(exit::STARTUP);
            }
        },
        Err(err) => {
            eprintln!("jwks: unreachable: {err}");
            return ExitCode::from(exit::STARTUP);
        }
    }

    let verifier = JwksVerifier::new(VerifierPorts {
        cache: jwks,
        issuer: config.issuer.clone(),
        client_id: config.client_id.clone(),
        rules: rules.cloned(),
        revocations: Arc::new(NoRevocations),
        metrics: None,
        username_claim: config.claims.username.clone(),
        groups_claim: config.claims.groups.clone(),
    });
    let now = SystemClock.now_timestamp();
    let examined = verifier.examine(token, now);
    for line in examined.report(&config.issuer, now) {
        println!("{line}");
    }
    ExitCode::from(if examined.result.is_identity() {
        exit::OK
    } else {
        exit::CONFIG
    })
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
    let discovered = match discover(&config.issuer).await {
        Ok(discovery) => Some(discovery),
        Err(err) => {
            // Not fatal on purpose: an identity provider that is down must not stop a gateway
            // from answering with the cookies and tokens it already holds. What is unavailable
            // is a *new* sign-in — and only until discovery succeeds, which is retried in the
            // background below rather than never (H3).
            eprintln!(
                "WARN endpoint-gateway: discovery failed ({err}); sign-in is unavailable until \
                 it succeeds, retrying in the background"
            );
            None
        }
    };
    // Built before the verifier because the verifier holds it: *Which tokens are ours* checks a
    // bearer's `sid` against the same set the cookie is checked against, so a back-channel logout
    // ends the access tokens minted from that session and not only its cookies.
    // "Some replica's probe watched a forged client address come back", shared through the
    // revocation `ConfigMap` so that one replica's finding turns pod-address identity off on all
    // of them — and read by the workload identity below.
    let address_forgery = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let revocations = KubeRevocations::spawn(
        client.clone(),
        config.backchannel_logout.namespace.clone(),
        config.backchannel_logout.configmap.clone(),
        Arc::clone(&address_forgery),
    )
    .await
    .map_err(|err| format!("could not start the revocation watch: {err}"))?;
    tokio::spawn(Arc::clone(&revocations).sweep_forever(|| SystemClock.now_timestamp()));

    // Validated at config load, so this cannot be the empty list that would accept every token
    // the realm has ever minted; unwrapped through the same call rather than re-derived, so the
    // two can never disagree about what this gateway accepts.
    let rules = config
        .bearer_rules()
        .map_err(|err| format!("bearer: {err}"))?;
    if let Some(rules) = rules.as_ref() {
        for party in rules.authorized_parties() {
            eprintln!(
                "WARN endpoint-gateway: bearer.authorized_parties accepts tokens minted for \
                 {party:?} with an audience this gateway does not know. That is a compatibility \
                 mode for a realm whose client cannot be given an audience mapper, and it accepts \
                 a credential minted for somebody else's audience — see RFC 0009's `Which tokens \
                 are ours`. Traffic relying on it counts in \
                 weebo_si_endpoint_auth_bearer_total{{result=\"accepted_authorized_party\"}}."
            );
        }
    }

    let verifier = JwksVerifier::new(VerifierPorts {
        cache: jwks.clone(),
        issuer: config.issuer.clone(),
        client_id: config.client_id.clone(),
        rules,
        revocations: Arc::clone(&revocations) as Arc<dyn RevocationStore>,
        metrics: Some(metrics.clone()),
        username_claim: config.claims.username.clone(),
        groups_claim: config.claims.groups.clone(),
    });

    // Introspection needs three things the JWT path does not: somewhere to ask, a secret to ask
    // with, and the admission that a caller holding a valid opaque token stops working while the
    // identity provider is down. Each of the three is a startup line rather than a surprise at
    // the first `401`.
    let introspector = if config.bearer.introspection.enabled {
        let endpoint = if config.bearer.introspection.endpoint.is_empty() {
            discovered
                .as_ref()
                .and_then(|discovery| discovery.introspection_endpoint.clone())
                .ok_or_else(|| {
                    "bearer.introspection.enabled is on and the issuer's discovery document                      advertises no introspection_endpoint — set bearer.introspection.endpoint, or                      turn introspection off; a gateway that starts here would refuse every                      non-browser caller on this platform while looking healthy"
                        .to_owned()
                })?
        } else {
            config.bearer.introspection.endpoint.clone()
        };
        let Some(rules) = verifier.rules().cloned() else {
            return Err("bearer.introspection.enabled is on with bearer.verify_own_issuer off,                         which leaves nothing for an introspected token to be checked against"
                .to_owned());
        };
        println!(
            "endpoint-gateway: opaque bearers are resolved at {endpoint}. An identity-provider              outage now stops a caller holding a valid opaque token — there is nothing to check              offline. Where the issuer can mint JWT access tokens (RFC 9068), that is the shape              to ask for."
        );
        Some(Introspector::new(IntrospectorPorts {
            endpoint,
            client_id: config.client_id.clone(),
            client_secret: std::env::var(&config.client_secret_env).unwrap_or_default(),
            username_claim: config.claims.username.clone(),
            groups_claim: config.claims.groups.clone(),
            negative_ttl_secs: config.bearer.introspection.negative_ttl_secs,
            identity_ttl_secs: config.cache.identity_ttl_secs,
            rules,
            revocations: Arc::clone(&revocations) as Arc<dyn RevocationStore>,
            limiter: RateLimiter::new(
                Rate {
                    burst: config.bearer.introspection.per_address_per_minute.max(1),
                    per_minute: config.bearer.introspection.per_address_per_minute.max(1),
                },
                10_000,
            ),
        }))
    } else {
        None
    };

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

    // `On` starts trusted, as the admin asserted. `Auto` starts **untrusted** and is turned on
    // only by a conclusive probe (`probe.rs`) — a forged address that did not come back.
    if config.self_origin.pod_network == PodNetwork::Auto && !config.probe.enabled {
        eprintln!(
            "WARN endpoint-gateway: self_origin.pod_network is Auto and the probe is disabled, so \
             nothing can confirm the controller overwrites the client-address header: pod-address \
             identity stays OFF. Enable the probe, or set pod_network: On if you have verified it."
        );
    }
    let workloads = KubeWorkloadIdentity::spawn(
        client.clone(),
        config.self_origin.pod_network == PodNetwork::On,
        address_forgery,
        config.self_origin.service_account_token,
        config.cache.token_review_max_entries,
    )
    .await
    .map_err(|err| format!("could not start the workspace-pod watch: {err}"))?;

    let caches = GatewayState::caches(&config);
    // `max(1)` because a zero-capacity bucket would refuse everything; `0` means *off*, and the
    // handler checks the configured value rather than asking the limiter.
    let state_rate = config.rate_limit.login_per_address_per_minute.max(1);
    let logout_rate = config.rate_limit.backchannel_logout_per_minute.max(1);
    // Derived from the keys every replica holds, so any replica can answer any replica's probe.
    let selftest_tokens =
        adapters::session::selftest_tokens(&keys).map_err(|err| err.to_string())?;
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
        introspector,
        oidc: std::sync::OnceLock::new(),
        shutting_down: std::sync::atomic::AtomicBool::new(false),
        clock: SystemClock,
        session_cache: caches.sessions,
        bearer_cache: caches.bearers,
        service_account_cache: caches.service_accounts,
        redeemed: caches.redeemed,
        introspection_negative: caches.introspection_negative,
        login_limiter: RateLimiter::new(
            Rate {
                burst: state_rate,
                per_minute: state_rate,
            },
            10_000,
        ),
        logout_limiter: RateLimiter::new(
            Rate {
                burst: logout_rate,
                per_minute: logout_rate,
            },
            1_000,
        ),
        logged: caches.logged,
        allows: std::sync::atomic::AtomicU64::new(0),
        metrics,
        registry,
        enforcement,
        proxy: proxy::client(),
        selftest_tokens,
        keys_generation: std::sync::atomic::AtomicU64::new(0),
        published: std::sync::Mutex::new(Default::default()),
    });

    match discovered {
        Some(discovery) => install_oidc(&state, discovery, &jwks),
        None => {
            let state = Arc::clone(&state);
            let jwks = jwks.clone();
            tokio::spawn(async move {
                let issuer = state.config.issuer.clone();
                let discovery = until_ok(
                    || discover(&issuer),
                    DISCOVERY_RETRY_INITIAL,
                    DISCOVERY_RETRY_MAX,
                    |err, next| {
                        eprintln!(
                            "WARN endpoint-gateway: discovery failed ({err}); next attempt in \
                             {}s",
                            next.as_secs()
                        );
                    },
                )
                .await;
                println!("endpoint-gateway: discovery succeeded; sign-in is available");
                install_oidc(&state, discovery, &jwks);
            });
        }
    }

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
    // H2: SIGTERM (and SIGINT) mark the replica not-ready, wait for that to reach the
    // endpoints controller, then stop accepting and let in-flight requests finish — bounded, so a
    // keep-alive connection that never goes idle cannot hold the pod past its grace period.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            termination().await;
            state.begin_shutdown();
            println!(
                "endpoint-gateway: shutting down — not ready, draining for {}s",
                SHUTDOWN_DELAY.as_secs()
            );
            tokio::time::sleep(SHUTDOWN_DELAY).await;
            let _ = stop_tx.send(true);
        });
    }

    let metrics_server = if state.config.metrics_listen.is_empty() {
        None
    } else {
        let metrics_addr: SocketAddr = state.config.metrics_listen.parse().map_err(|err| {
            format!(
                "invalid metrics_listen address {:?}: {err}",
                state.config.metrics_listen
            )
        })?;
        let metrics_listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .map_err(|err| format!("could not bind {metrics_addr}: {err}"))?;
        println!("endpoint-gateway metrics on {metrics_addr}");
        Some(tokio::spawn(serve_until(
            metrics_listener,
            http::metrics_router(Arc::clone(&state)),
            stop_rx.clone(),
            DRAIN_TIMEOUT,
        )))
    };

    // `ConnectInfo`, because the reverse-proxy shell decides whether to believe a client-address
    // header from the *connection* rather than from the header.
    let served = serve_until(listener, http::router(state), stop_rx, DRAIN_TIMEOUT).await;
    if let Some(metrics_server) = metrics_server {
        metrics_server.abort();
    }
    served
}

/// How long discovery waits before its first retry, and the most it ever waits between two.
const DISCOVERY_RETRY_INITIAL: Duration = Duration::from_secs(2);
const DISCOVERY_RETRY_MAX: Duration = Duration::from_secs(300);
/// Between SIGTERM and closing the listener: long enough for `/readyz`'s `503` to be seen and the
/// endpoint removed, so no new request is routed to a listener that is about to close.
const SHUTDOWN_DELAY: Duration = Duration::from_secs(5);
/// The most in-flight requests are waited for once the listener has closed. With
/// `SHUTDOWN_DELAY`, inside the chart's 30-second `terminationGracePeriodSeconds`.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(20);

/// Build the login path from a discovery document, start the key refresh it names, and make it
/// available to the handlers — at boot, or whenever the background retry first succeeds.
fn install_oidc(state: &GatewayState, discovery: adapters::oidc::Discovery, jwks: &JwksCache) {
    let config = &state.config;
    // The startup check RFC 0009 keeps even though question 3 answered "yes": it is one call,
    // and it turns a cluster-wide lockout into a line an admin reads at boot.
    if discovery.advertises_claim(&config.claims.username) == Some(false) {
        eprintln!(
            "WARN endpoint-gateway: the issuer does not advertise {:?}; if it is not the claim \
             Che derives usernames from, every owner check will fail closed",
            config.claims.username
        );
    }
    if !discovery.backchannel_logout_supported {
        eprintln!(
            "WARN endpoint-gateway: the issuer does not support back-channel logout; sessions \
             are cut off at revalidation ({}s), not at logout",
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
    let client = OidcClient::new(
        discovery,
        config.client_id.clone(),
        secret,
        config.redirect_url.clone(),
    );
    // `set` fails only if it is already set, which cannot happen: boot and the retry are
    // exclusive.
    let _ = state.oidc.set(client);
}

/// Call `attempt` until it succeeds, sleeping `initial`, then twice that, up to `max`, between
/// failures — each of which is handed to `on_error` with the delay before the next try.
async fn until_ok<T, E, F, Fut>(
    mut attempt: F,
    initial: Duration,
    max: Duration,
    mut on_error: impl FnMut(E, Duration),
) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = initial;
    loop {
        match attempt().await {
            Ok(value) => return value,
            Err(err) => {
                on_error(err, delay);
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(max);
            }
        }
    }
}

/// Resolve on SIGTERM — what the kubelet sends — or SIGINT.
async fn termination() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            // No handler could be installed: SIGINT is still honoured below.
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = terminate => {}
    }
}

/// Serve `router` until `stop` turns true, then stop accepting and give in-flight requests up to
/// `drain` to finish.
async fn serve_until(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    mut stop: tokio::sync::watch::Receiver<bool>,
    drain: Duration,
) -> Result<(), String> {
    let mut stopped = stop.clone();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = stop.wait_for(|stop| *stop).await;
    });
    tokio::select! {
        served = server => served.map_err(|err| format!("server error: {err}")),
        () = async move {
            let _ = stopped.wait_for(|stop| *stop).await;
            tokio::time::sleep(drain).await;
        } => {
            eprintln!(
                "WARN endpoint-gateway: connections still open after the drain timeout; exiting"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    /// H3: discovery that failed at boot used to leave sign-in off for the life of the pod.
    #[tokio::test]
    async fn a_failing_attempt_is_retried_with_backoff_until_it_succeeds() {
        let mut calls = 0_u32;
        let mut delays = Vec::new();
        let value = until_ok(
            || {
                calls += 1;
                let now = calls;
                async move { if now < 5 { Err("down") } else { Ok(now) } }
            },
            Duration::from_millis(1),
            Duration::from_millis(4),
            |_, next| delays.push(next.as_millis()),
        )
        .await;
        assert_eq!(value, 5);
        assert_eq!(delays, vec![1, 2, 4, 4]);
    }

    /// H2: a stop lets the request already in flight finish, and then the server returns.
    #[tokio::test]
    async fn stopping_drains_the_request_in_flight_and_then_returns() {
        use axum::routing::get;

        let router = axum::Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                "done"
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve_until(
            listener,
            router,
            stop_rx,
            Duration::from_secs(10),
        ));

        let request = tokio::spawn(async move {
            reqwest::get(format!("http://{address}/slow"))
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop_tx.send(true).unwrap();
        assert_eq!(request.await.unwrap(), "done");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("the server must return once drained")
            .unwrap()
            .unwrap();
    }
}
