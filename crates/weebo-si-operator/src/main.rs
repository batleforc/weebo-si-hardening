//! The composition root — see RFC 0002's *CLI* contract. Only this file, `webhook_cmd.rs` and
//! `controller_cmd.rs` may name a concrete adapter.

mod backends_cmd;
mod canary_cmd;
mod cli;
mod controller_cmd;
mod features;
mod images_cmd;
mod kubearmor_cmd;
mod observability;
mod pods_cmd;
mod registry_cmd;
mod teams_cmd;
mod webhook_cmd;

use std::process::ExitCode;

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
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

usage: weebo-si-operator <features|webhook|controller|crd|backends|canary|images|registry|pods|teams>

  webhook     [--addr 0.0.0.0:9443] [--cert-dir /etc/webhook/certs]
              [--metrics-addr :8080] [--health-addr :8081]
              --operator-identity <system:serviceaccount:ns:name>
  controller  [--metrics-addr :8080] [--health-addr :8081] [--leader-election]
              [--canary-image <ref>]
  crd         [weebosiconfigs|weebositeams|weebosiusers]
              print the generated CRD YAML — every kind as a multi-document
              stream, or the one named
  features    print the registry: id, originating RFC, target resource
  backends    print which network-profiles backends are compiled in and which
              this cluster actually offers
              kubearmor [--verbose]
                the same two questions for kubearmor-policy: whether this
                cluster serves the KubeArmorPolicy CRD, and (--verbose) which
                nodes can actually enforce one
  canary      [--namespace <ns>] [--canary-image <ref>]
              run the enforcement probe once and report whether this cluster's
              CNI actually enforces NetworkPolicy; non-zero exit if it does not
  images      platform
                print the compiled-in image-policy platform patterns
              check <ref> [--team <name>] [--namespace <ns>]
                parse, normalize and judge one reference; non-zero if denied
              audit [--namespace <ns> | --all-namespaces]
                every image running now and the verdict this configuration
                would give it — run this BEFORE switching image-policy on
  registry    resolve --namespace <ns>
                the registry keys that namespace resolves to, the objects each
                expands into, and where each would mount
              check
                validate every catalogue entry against its template: exists,
                automountable, does not shadow a home path; non-zero on any
                violation, so it works as a pipeline pre-flight
  pods        audit [--level L] [--version V] [--namespace <ns> | --all-namespaces]
                the existing pods each namespace's Pod Security level would
                refuse, from a server-side dry run of the enforce label —
                run this BEFORE switching pod-security to Enforce. --level
                overrides the configured level; writes nothing, needs patch
                on namespaces like the real write
  teams       export [--from <file>] [--check]
                RFC 0011's migration: read the old singleton's spec.teams and
                grants maps and print one WeeboSiTeam per team. --from reads a
                manifest instead of the live cluster; --check diffs what is
                applied against what the singleton says, non-zero if they
                disagree. Writes nothing to the cluster, ever
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
        Some("crd") => match print_crd(args.get(2).map(String::as_str)) {
            Ok(()) => ExitCode::from(exit::OK),
            Err(message) => {
                eprintln!("weebo-si-operator: {message}");
                ExitCode::from(exit::USAGE)
            }
        },
        Some("webhook") => run_async(webhook_cmd::run(&args[2..])),
        Some("controller") => run_async(controller_cmd::run(&args[2..])),
        // `backends` with no argument keeps its RFC 0004 meaning — the network backends —
        // rather than growing a summary of both. `backends kubearmor` is its own answer
        // because the questions it asks (a CRD, then every node's label) have no counterpart
        // on the network side.
        Some("backends") => match args.get(2).map(String::as_str) {
            None => run_admin(backends_cmd::run()),
            Some("kubearmor") => {
                run_admin(kubearmor_cmd::run(cli::has_flag(&args[3..], "--verbose")))
            }
            Some(other) => {
                eprintln!("weebo-si-operator: unrecognized backends target '{other}'");
                eprint!("{USAGE}");
                ExitCode::from(exit::USAGE)
            }
        },
        Some("canary") => run_admin(canary_cmd::run(&args[2..])),
        Some("images") => run_admin(images_cmd::run(&args[2..])),
        Some("registry") => run_admin(registry_cmd::run(&args[2..])),
        Some("pods") => run_admin(pods_cmd::run(&args[2..])),
        Some("teams") => run_admin(teams_cmd::run(&args[2..])),
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

/// An admin subcommand: run from a workstation, its stdout is its output. What the adapters it
/// shares with the two roles log goes to stderr, `WARN` and up unless `RUST_LOG` says otherwise —
/// not through the roles' telemetry, which writes to stdout.
fn run_admin(future: impl std::future::Future<Output = Result<(), String>>) -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
    run_async(future)
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

/// The plain scalars YAML 1.1 reads as booleans and YAML 1.2 reads as strings.
const YAML11_BOOLEANS: [&str; 16] = [
    "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO", "on", "On", "ON", "off", "Off",
    "OFF",
];

/// Quote every plain scalar that YAML 1.1 would read as a boolean.
///
/// `serde_yaml_bw` writes YAML 1.2, where `Off` is a string, so it leaves `- Off` unquoted. kubectl,
/// Helm and the apiserver read YAML 1.1 (go-yaml v2), where `Off` and `On` are booleans: the CRD's
/// `mode` enum then reads `false, DryRun, Enforce`, and every `mode: Off` is refused with
/// `Unsupported value: "Off"`. Only list items and mapping values are rewritten, and only when the
/// whole scalar is one of these words — a description mentioning `Off` is left alone.
fn quote_yaml11_booleans(yaml: &str) -> String {
    let quote = |value: &str| {
        if YAML11_BOOLEANS.contains(&value) {
            format!("'{value}'")
        } else {
            value.to_string()
        }
    };
    let mut out = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        let indent = &line[..line.len() - line.trim_start().len()];
        let body = line.trim_start();
        let rewritten = if let Some(item) = body.strip_prefix("- ") {
            format!("{indent}- {}", quote(item))
        } else if let Some((key, value)) = body.split_once(": ")
            && !key.starts_with(['\'', '"'])
        {
            format!("{indent}{key}: {}", quote(value))
        } else {
            line.to_string()
        };
        out.push_str(&rewritten);
        out.push('\n');
    }
    out
}

/// Every CRD this operator owns, in the order they are installed: the singleton first, then the
/// two RFC 0011 kinds it resolves against.
///
/// Printed as one document per kind, and as a `---`-separated stream when no kind is named, so
/// `kubectl apply -f -` takes all three and the chart's `crds/` can still carry one file each.
fn print_crd(kind: Option<&str>) -> Result<(), String> {
    let documents: Vec<(&str, CustomResourceDefinition)> = vec![
        ("weebosiconfigs", weebo_si_crd::WeeboSiConfig::crd()),
        ("weebositeams", weebo_si_crd::WeeboSiTeam::crd()),
        ("weebosiusers", weebo_si_crd::WeeboSiUser::crd()),
    ];

    let selected: Vec<&(&str, CustomResourceDefinition)> = match kind {
        None => documents.iter().collect(),
        Some(name) => {
            let found: Vec<&(&str, CustomResourceDefinition)> = documents
                .iter()
                .filter(|(plural, _)| *plural == name)
                .collect();
            if found.is_empty() {
                return Err(format!(
                    "unrecognized CRD '{name}' (expected weebosiconfigs, weebositeams or \
                     weebosiusers)"
                ));
            }
            found
        }
    };

    for (index, (_, crd)) in selected.iter().enumerate() {
        let yaml = serde_yaml_bw::to_string(crd)
            .map(|yaml| quote_yaml11_booleans(&yaml))
            .map_err(|err| format!("could not render the CRD: {err}"))?;
        if index > 0 {
            println!("---");
        }
        print!("{yaml}");
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "a failed assertion is the test failing"
)]
mod crd_render_tests {
    use super::*;

    #[test]
    fn yaml11_booleans_are_quoted_and_nothing_else_moves() {
        let input =
            "enum:\n- Off\n- DryRun\n- On\nmode: Off\ndescription: 'Off | DryRun'\nname: offset\n";
        assert_eq!(
            quote_yaml11_booleans(input),
            "enum:\n- 'Off'\n- DryRun\n- 'On'\nmode: 'Off'\ndescription: 'Off | DryRun'\nname: offset\n"
        );
    }

    #[test]
    fn every_rendered_crd_has_no_unquoted_yaml11_boolean() {
        for crd in [
            weebo_si_crd::WeeboSiConfig::crd(),
            weebo_si_crd::WeeboSiTeam::crd(),
            weebo_si_crd::WeeboSiUser::crd(),
        ] {
            let yaml = quote_yaml11_booleans(&serde_yaml_bw::to_string(&crd).unwrap());
            for line in yaml.lines() {
                let body = line.trim_start();
                let value = body
                    .strip_prefix("- ")
                    .or_else(|| body.split_once(": ").map(|(_, value)| value));
                if let Some(value) = value {
                    assert!(!YAML11_BOOLEANS.contains(&value), "unquoted: {line}");
                }
            }
            let back: CustomResourceDefinition = serde_yaml_bw::from_str(&yaml).unwrap();
            assert_eq!(back, crd, "quoting must not change the document");
        }
    }
}
