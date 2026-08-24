//! The composition root — see RFC 0002's *CLI* contract. Only this file, `webhook_cmd.rs` and
//! `controller_cmd.rs` may name a concrete adapter.

mod cli;
mod controller_cmd;
mod features;
mod observability;
mod webhook_cmd;

use std::process::ExitCode;

use kube::CustomResourceExt;

/// Exit codes are the RFC's *Contract* — changing one needs a new RFC.
mod exit {
    pub const OK: u8 = 0;
    pub const INTERNAL: u8 = 1;
    pub const USAGE: u8 = 2;
    #[allow(dead_code, reason = "no code path in this build returns it yet")]
    pub const CACHES_NEVER_SYNCED: u8 = 3;
}

const USAGE: &str = "\
weebo-si-operator — admission webhook and controller for weebo-si-hardening

usage: weebo-si-operator <features|webhook|controller|crd>

  webhook     [--addr 0.0.0.0:9443] [--cert-dir /etc/webhook/certs]
              [--metrics-addr :8080] [--health-addr :8081]
  controller  [--metrics-addr :8080] [--health-addr :8081] [--leader-election]
  crd         print the generated CRD YAML
  features    print the registry: id, originating RFC, target resource
";

fn main() -> ExitCode {
    // The kube client speaks TLS to the apiserver, so rustls needs its provider installed
    // before any client is built — otherwise `Client::try_default()` fails with an opaque
    // "TLS required but no TLS stack selected".
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("features") => {
            print_features();
            ExitCode::from(exit::OK)
        }
        Some("crd") => {
            print_crd();
            ExitCode::from(exit::OK)
        }
        Some("webhook") => run_async(webhook_cmd::run(&args[2..])),
        Some("controller") => run_async(controller_cmd::run(&args[2..])),
        Some("-h") | Some("--help") => {
            print!("{USAGE}");
            ExitCode::from(exit::OK)
        }
        Some(other) => {
            eprintln!("weebo-si-operator: unrecognized command '{other}'");
            eprint!("{USAGE}");
            ExitCode::from(exit::USAGE)
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(exit::USAGE)
        }
    }
}

fn run_async(future: impl std::future::Future<Output = Result<(), String>>) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("weebo-si-operator: could not start the async runtime: {err}");
            return ExitCode::from(exit::INTERNAL);
        }
    };
    match runtime.block_on(future) {
        Ok(()) => ExitCode::from(exit::OK),
        Err(err) => {
            eprintln!("weebo-si-operator: {err}");
            ExitCode::from(exit::INTERNAL)
        }
    }
}

fn print_features() {
    println!("{:<12} {:<10} RESOURCE", "ID", "RFC");
    for feature in features::REGISTERED {
        println!(
            "{:<12} {:<10} {}",
            feature.id, feature.rfc, feature.resource
        );
    }
}

fn print_crd() {
    let crd = weebo_si_crd::WeeboSiConfig::crd();
    match serde_yaml_bw::to_string(&crd) {
        Ok(yaml) => print!("{yaml}"),
        Err(err) => eprintln!("weebo-si-operator: could not render the CRD: {err}"),
    }
}
