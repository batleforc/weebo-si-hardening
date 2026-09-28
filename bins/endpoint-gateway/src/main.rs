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
    match reqwest::Client::new()
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
    // Built before the verifier because the verifier holds it: *Which tokens are ours* checks a
    // bearer's `sid` against the same set the cookie is checked against, so a back-channel logout
    // ends the access tokens minted from that session and not only its cookies.
    let revocations = KubeRevocations::spawn(
        client.clone(),
        config.backchannel_logout.namespace.clone(),
        config.backchannel_logout.configmap.clone(),
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
        cache: jwks,
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
            oidc.as_ref()
                .and_then(|oidc| oidc.discovery().introspection_endpoint.clone())
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

    let workloads = KubeWorkloadIdentity::spawn(
        client.clone(),
        config.self_origin.pod_network != PodNetwork::Off,
        config.self_origin.service_account_token,
        config.cache.token_review_max_entries,
    )
    .await
    .map_err(|err| format!("could not start the workspace-pod watch: {err}"))?;

    let caches = GatewayState::caches(&config);
    // `max(1)` because a zero-capacity bucket would refuse everything; `0` means *off*, and the
    // handler checks the configured value rather than asking the limiter.
    let state_rate = config.rate_limit.login_per_address_per_minute.max(1);
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
        oidc,
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
