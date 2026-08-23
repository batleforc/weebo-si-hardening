//! `preauth-proxy` — attach a configured credential to requests a forward-auth gateway has
//! already authorised, so the upstream stops presenting its own second login.
//!
//! The design is [RFC 0003](../../../docs/rfc/0003-preauth-proxy.md). The one property to keep in
//! view while reading this file: **this process performs no authentication of its own.** It hands
//! every request that reaches it a valid, full-privilege upstream credential. That is safe only
//! while the gateway sits ahead of it on the route — the gateway middleware is not defence in
//! depth, it is the entire authentication story.

mod adapters;
mod domain;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use adapters::config_file;
use adapters::http_client::{HttpCredentialSource, HttpUpstream, client};
use adapters::inbound_http::{Proxy, serve};
use domain::credential::Cache;

/// Default config path, per the RFC's *Contract*.
const DEFAULT_CONFIG: &str = "/etc/preauth-proxy/config.yaml";

const USAGE: &str = "\
preauth-proxy — attach a configured credential to already-authorised requests

usage: preauth-proxy [--config <PATH>] [--check]

options:
  --config <PATH>   config file      (env PREAUTH_CONFIG, default: /etc/preauth-proxy/config.yaml)
  --check           parse and validate the config, print it, exit. Touches no network.
  -h, --help        this text

Secrets are supplied as environment variables and referenced from the config as ${NAME}.
";

/// Exit codes, per the RFC's *Contract*. Changing one needs a new RFC.
mod exit {
    /// Clean shutdown, or `--check` on a valid config.
    pub const OK: u8 = 0;
    /// Bind failure, unreadable config path.
    pub const INTERNAL: u8 = 1;
    /// Malformed config, unknown key, or an unset `${ENV}` reference.
    pub const CONFIG: u8 = 2;
    /// The startup acquisition failed.
    pub const STARTUP_ACQUISITION: u8 = 3;
}

macro_rules! log {
    ($level:literal, $($arg:tt)*) => {
        eprintln!("{:<5} preauth-proxy: {}", $level, format_args!($($arg)*))
    };
}

#[derive(Debug, Default)]
struct Args {
    config: Option<PathBuf>,
    check: bool,
    help: bool,
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = argv.into_iter();

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--config" => {
                args.config = Some(PathBuf::from(
                    it.next()
                        .ok_or_else(|| "--config needs a value".to_owned())?,
                ));
            }
            "--check" => args.check = true,
            "-h" | "--help" => args.help = true,
            other => return Err(format!("unknown flag {other}")),
        }
    }

    Ok(args)
}

/// Print the effective config, with every secret left as its `${NAME}` reference.
///
/// `--check` deliberately does **not** print substituted values. The acquisition body is where
/// the service password ends up, and a `--check` an operator pastes into a ticket would carry it.
/// Validation still resolves every reference — the check that matters is that they resolve, not
/// that a human sees them.
fn print_effective(config: &domain::config::Config, path: &std::path::Path, document: &str) {
    println!("# effective configuration from {}", path.display());
    println!("# ${{...}} references resolved successfully and are shown unsubstituted");
    println!("listen: {}", config.listen);
    println!("upstream: http://{}", config.upstream.authority());
    println!(
        "passthrough: {} contains {:?}",
        config.passthrough.header, config.passthrough.contains
    );
    println!(
        "credential: {} http://{}{} accept={:?}",
        config.credential.method,
        config.credential.origin.authority(),
        config.credential.path,
        config
            .credential
            .accept_status
            .iter()
            .map(|s| s.as_u16())
            .collect::<Vec<_>>()
    );
    println!(
        "extract: {} via {:?}",
        config.credential.from_header, config.credential.take
    );
    println!("inject: {} {:?}", config.inject.header, config.inject.mode);
    println!(
        "renew: on={:?} max_replays={}",
        config
            .renew
            .on_status
            .iter()
            .map(|s| s.as_u16())
            .collect::<Vec<_>>(),
        config.renew.max_replays
    );
    // The number of references proves substitution ran without disclosing any result.
    let references = document.matches("${").count();
    println!("# {references} ${{...}} reference(s) resolved");
}

async fn run(args: Args) -> u8 {
    let path = args
        .config
        .or_else(|| std::env::var_os("PREAUTH_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));

    let document = match std::fs::read_to_string(&path) {
        Ok(document) => document,
        Err(err) => {
            log!("ERROR", "cannot read {}: {err}", path.display());
            return exit::INTERNAL;
        }
    };

    let config = match config_file::parse(&document, &|key| std::env::var(key).ok()) {
        Ok(config) => config,
        Err(err) => {
            log!("ERROR", "{err}");
            return exit::CONFIG;
        }
    };

    if args.check {
        print_effective(&config, &path, &document);
        return exit::OK;
    }

    let http = client();
    let source = HttpCredentialSource::new(http.clone(), config.credential.clone());
    let upstream = HttpUpstream::new(http, config.upstream.clone());
    let cache = Cache::new();

    // Acquire once before listening. A failure here stops the rollout, rather than surfacing as
    // request-time 502s an hour later.
    match cache.get_or_acquire(&source).await {
        Ok(credential) => log!(
            "INFO",
            "acquired credential from origin, {} bytes, marker={}",
            credential.len(),
            config.inject.header
        ),
        Err(err) => {
            log!("ERROR", "startup acquisition failed: {err}");
            return exit::STARTUP_ACQUISITION;
        }
    }

    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            log!("ERROR", "cannot bind {}: {err}", config.listen);
            return exit::INTERNAL;
        }
    };
    log!("INFO", "listening on {}", config.listen);

    let proxy = Arc::new(Proxy {
        config,
        cache,
        source,
        upstream,
    });

    let shutdown = Box::pin(async {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(term) => term,
                Err(err) => {
                    log!("WARN", "cannot listen for SIGTERM: {err}");
                    return;
                }
            };
        tokio::select! {
            _ = term.recv() => log!("INFO", "SIGTERM, draining"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => log!("INFO", "SIGINT, draining"),
                Err(err) => log!("WARN", "cannot listen for SIGINT: {err}"),
            },
        }
    });

    match serve(proxy, listener, shutdown).await {
        Ok(()) => exit::OK,
        Err(err) => {
            log!("ERROR", "server stopped: {err}");
            exit::INTERNAL
        }
    }
}

fn main() -> ExitCode {
    let args = match parse(std::env::args().skip(1).collect()) {
        Ok(args) => args,
        Err(err) => {
            log!("ERROR", "{err}");
            eprint!("{USAGE}");
            return ExitCode::from(exit::CONFIG);
        }
    };

    if args.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            log!("ERROR", "cannot start the runtime: {err}");
            return ExitCode::from(exit::INTERNAL);
        }
    };

    ExitCode::from(runtime.block_on(run(args)))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_config_flag_takes_a_path() {
        let args = parse(argv(&["--config", "/tmp/x.yaml"])).unwrap();
        assert_eq!(args.config, Some(PathBuf::from("/tmp/x.yaml")));
        assert!(!args.check);
    }

    #[test]
    fn check_is_a_boolean() {
        assert!(parse(argv(&["--check"])).unwrap().check);
    }

    #[test]
    fn an_unknown_flag_is_refused() {
        assert!(parse(argv(&["--insecure"])).is_err());
    }

    #[test]
    fn a_flag_missing_its_value_is_refused() {
        assert!(parse(argv(&["--config"])).is_err());
    }
}
