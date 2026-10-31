//! The operator's resource budget (RFC 0012 *Future work*): the release-built `controller` role,
//! run as the real binary against a real ephemeral apiserver, asked to bring a fleet of workspace
//! namespaces under `network-profiles`, and measured from the outside.
//!
//! Why the binary and not `weebo_si_controller::run` in-process: what the budget is about — the
//! resident memory of the process a Deployment runs, the CPU it burns idle, the time from start to
//! `/readyz` — is a property of that process, not of a test harness sharing its heap and its
//! runtime. Why not `weebo-kit-perf`: it judges the kit's reconcile metrics, which our loops do not
//! emit, and runs on `weebo-kit-testkit` (Go and `libclang` at build) — see RFC 0012's *Changelog*.
//!
//! What it measures, in order:
//!
//! 1. **Start** — spawn to `/readyz` answering 200: every watch has listed once.
//! 2. **Convergence** — `PERF_NAMESPACES` workspace namespaces are created; for each, the time
//!    until its `weebo-base` NetworkPolicy exists. p50, p99, max, and the whole fleet's wall time.
//! 3. **Idle** — `PERF_IDLE_SECONDS` with nothing changing: the CPU the process burns doing
//!    nothing, which on a real cluster it does all day.
//! 4. **Memory** — peak (`VmHWM`) and resident after idle (`VmRSS`), from `/proc`.
//!
//! Every figure lands in a Markdown table (stdout, and `GITHUB_STEP_SUMMARY` when set), then is
//! judged against its budget. A budget is an env var (`PERF_BUDGET_*`) with a default: the defaults
//! are the margin the nightly runs set, written down in `docs/operator-performance.md` — tighten
//! them there and here together.
//!
//! Run with `task envtest:operator-perf`; the `Operator perf` workflow runs it nightly. It is in
//! the `envtest` feature, but in no suite list: a debug build measures the wrong binary.

#![cfg(feature = "envtest")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    missing_docs,
    reason = "an integration test's assertions ARE its documentation; a failed expect/panic is the test failing"
)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::{CustomResourceExt, ResourceExt};
use weebo_si_crd::{WeeboSiConfig, WeeboSiTeam, WeeboSiUser};
use weebo_si_envtest_support::{EnvTest, free_port};

const OPERATOR_NAMESPACE: &str = "weebo-si-hardening";
const MANAGED_BY: &str = "hardening.weebo.io/managed-by=weebo-si-operator";

/// The upstream CRDs the controller's watches list at start. `route.openshift.io` is left out on
/// purpose: its presence switches endpoint-auth to the OpenShift dialect, which is not the cluster
/// this budget describes.
const FIXTURES: [&str; 5] = [
    include_str!("../../weebo-si-envtest-support/fixtures/devworkspace-crd.yaml"),
    include_str!("../../weebo-si-envtest-support/fixtures/devworkspaceoperatorconfig-crd.yaml"),
    include_str!("../../weebo-si-envtest-support/fixtures/kubearmorpolicy-crd.yaml"),
    include_str!("../../weebo-si-envtest-support/fixtures/application-crd.yaml"),
    include_str!("../../weebo-si-envtest-support/fixtures/authentikuser-crd.yaml"),
];

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

async fn install_crds(client: kube::Client) {
    let crds: Api<CustomResourceDefinition> = Api::all(client);
    let mut all: Vec<CustomResourceDefinition> =
        vec![WeeboSiConfig::crd(), WeeboSiTeam::crd(), WeeboSiUser::crd()];
    all.extend(
        FIXTURES
            .iter()
            .map(|yaml| serde_yaml_bw::from_str(yaml).expect("the fixture should parse")),
    );
    for crd in &all {
        crds.patch(
            &crd.name_any(),
            &PatchParams::apply("perf").force(),
            &Patch::Apply(crd),
        )
        .await
        .expect("CRD install");
    }
    for crd in &all {
        let name = crd.name_any();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let established = crds
                .get(&name)
                .await
                .ok()
                .and_then(|crd| crd.status)
                .and_then(|status| status.conditions)
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Established" && c.status == "True")
                });
            if established {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the CRD {name} never became established"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

async fn apply<K>(api: &Api<K>, name: &str, object: serde_json::Value)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    api.patch(
        name,
        &PatchParams::apply("perf").force(),
        &Patch::Apply(object),
    )
    .await
    .unwrap_or_else(|err| panic!("apply {name}: {err}"));
}

/// The operator namespace, the baseline template, and a singleton putting every labelled workspace
/// namespace under `network-profiles` in `Enforce`, with the canary off (envtest runs no pods).
async fn configure(client: kube::Client) {
    let namespaces: Api<Namespace> = Api::all(client.clone());
    apply(
        &namespaces,
        OPERATOR_NAMESPACE,
        serde_json::json!({ "apiVersion": "v1", "kind": "Namespace", "metadata": { "name": OPERATOR_NAMESPACE } }),
    )
    .await;
    let templates: Api<NetworkPolicy> = Api::namespaced(client.clone(), OPERATOR_NAMESPACE);
    apply(
        &templates,
        "perf-base",
        serde_json::json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": { "name": "perf-base", "namespace": OPERATOR_NAMESPACE },
            "spec": {
                "podSelector": { "matchLabels": { "perf.weebo.io/template": "never-matches" } },
                "policyTypes": ["Egress"],
                "egress": [{ "ports": [{ "protocol": "UDP", "port": 53 }, { "protocol": "TCP", "port": 53 }] }],
            },
        }),
    )
    .await;
    let configs: Api<WeeboSiConfig> = Api::all(client);
    apply(
        &configs,
        "cluster",
        serde_json::json!({
            "apiVersion": "hardening.weebo.io/v1alpha1",
            "kind": "WeeboSiConfig",
            "metadata": { "name": "cluster" },
            "spec": { "features": { "networkProfiles": {
                "mode": "Enforce",
                "namespaceSelector": { "matchExpressions": [
                    { "key": "hardening.weebo.io/workspace-namespace", "operator": "Exists" },
                ] },
                "catalog": [{
                    "key": "base",
                    "variants": [{ "backend": "NetworkPolicy",
                                   "templateRef": { "name": "perf-base", "namespace": OPERATOR_NAMESPACE } }],
                }],
                "baseline": "base",
                "onNotGranted": "Deny",
                "enforcement": { "backend": "NetworkPolicy", "canary": { "enabled": false, "intervalSeconds": 300 } },
            } } },
        }),
    )
    .await;
}

/// A kubeconfig for the binary: the same apiserver and admin token the suite's own client uses.
fn write_kubeconfig(dir: &Path, env_test: &EnvTest) -> std::path::PathBuf {
    let path = dir.join("kubeconfig");
    let config = format!(
        "apiVersion: v1
kind: Config
clusters:
- name: envtest
  cluster: {{ server: \"{}\", insecure-skip-tls-verify: true }}
users:
- name: admin
  user: {{ token: \"{}\" }}
contexts:
- name: envtest
  context: {{ cluster: envtest, user: admin }}
current-context: envtest
",
        env_test.url(),
        env_test.token()
    );
    std::fs::write(&path, config).expect("write the kubeconfig");
    path
}

/// The controller process, killed when dropped so a failed assertion never leaks it.
struct Controller {
    child: Child,
    log: std::path::PathBuf,
}

impl Controller {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A plain HTTP/1.0 GET against the health address: status code and body. No client crate for a
/// loopback probe the binary serves itself.
fn http_get(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status = response.split_whitespace().nth(1)?.parse().ok()?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Some((status, body))
}

/// `/proc/<pid>/status` fields in kibibytes (`VmRSS`, `VmHWM`).
fn proc_status_kib(pid: u32, field: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

/// User plus system CPU time the process has consumed, in seconds.
fn cpu_seconds(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // Fields after the parenthesised command name, which may itself hold spaces.
    let fields: Vec<&str> = stat
        .rsplit_once(") ")
        .map(|(_, rest)| rest.split_whitespace().collect())
        .unwrap_or_default();
    // utime and stime are fields 14 and 15 of the whole line: 11 and 12 after the name.
    let ticks: u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0)
        + fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
    ticks as f64 / clock_ticks()
}

fn clock_ticks() -> f64 {
    Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(100.0)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

struct Row {
    what: &'static str,
    measured: String,
    budget: String,
    within: bool,
}

#[tokio::test(flavor = "multi_thread")]
async fn the_controller_brings_a_fleet_under_network_profiles_within_its_budget() {
    let Some(env_test) = EnvTest::try_start().await else {
        return;
    };
    if cfg!(debug_assertions) {
        panic!(
            "the budget describes the release binary — run with `cargo test --release` (task envtest:operator-perf)"
        );
    }
    let fleet: usize = env_or("PERF_NAMESPACES", 300);
    let idle = Duration::from_secs(env_or("PERF_IDLE_SECONDS", 30));
    let budget_start = Duration::from_secs_f64(env_or("PERF_BUDGET_START_SECONDS", 5.0));
    let budget_p99 = Duration::from_secs_f64(env_or("PERF_BUDGET_P99_SECONDS", 2.0));
    let budget_fleet = Duration::from_secs_f64(env_or("PERF_BUDGET_FLEET_SECONDS", 15.0));
    let budget_idle_millicores: f64 = env_or("PERF_BUDGET_IDLE_MILLICORES", 10.0);
    let budget_peak_mib: f64 = env_or("PERF_BUDGET_PEAK_MIB", 96.0);
    let budget_rss_mib: f64 = env_or("PERF_BUDGET_RSS_MIB", 64.0);

    let client = env_test.client().expect("client should build");
    install_crds(client.clone()).await;
    configure(client.clone()).await;

    let workdir = tempfile::tempdir().expect("tempdir");
    let kubeconfig = write_kubeconfig(workdir.path(), &env_test);
    let health_port = free_port().expect("a free port");
    // `PERF_CONTROLLER_LOG` keeps the controller's log past the run (CI uploads it).
    let log = std::env::var_os("PERF_CONTROLLER_LOG").map_or_else(
        || workdir.path().join("controller.log"),
        std::path::PathBuf::from,
    );
    let spawned = Instant::now();
    let mut controller = Controller {
        child: Command::new(env!("CARGO_BIN_EXE_weebo-si-operator"))
            .args([
                "controller",
                "--health-addr",
                &format!("127.0.0.1:{health_port}"),
            ])
            .env("KUBECONFIG", &kubeconfig)
            .env("POD_NAMESPACE", OPERATOR_NAMESPACE)
            .env(
                "RUST_LOG",
                std::env::var("PERF_RUST_LOG").unwrap_or_else(|_| "info".to_string()),
            )
            // Telemetry writes to stdout: both streams go to the log a failure prints.
            .stdout(std::fs::File::create(&log).expect("controller log"))
            .stderr(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&log)
                    .expect("controller log"),
            )
            .spawn()
            .expect("the controller binary should start"),
        log,
    };
    let pid = controller.pid();

    // 1. Start.
    let ready = loop {
        if http_get(health_port, "/readyz").is_some_and(|(status, _)| status == 200) {
            break spawned.elapsed();
        }
        if let Some(status) = controller.exited() {
            panic!(
                "the controller exited before it was ready ({status}):\n{}",
                controller.log_tail()
            );
        }
        assert!(
            spawned.elapsed() < Duration::from_secs(60),
            "the controller never became ready:\n{}",
            controller.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // 2. Convergence: every namespace created, then its baseline awaited.
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let cpu_before = cpu_seconds(pid);
    let fleet_started = Instant::now();
    let created = Arc::new(tokio::sync::Mutex::new(HashMap::<String, Instant>::new()));
    let gate = Arc::new(tokio::sync::Semaphore::new(16));
    let mut creations = tokio::task::JoinSet::new();
    for index in 0..fleet {
        let (namespaces, created, gate) =
            (namespaces.clone(), Arc::clone(&created), Arc::clone(&gate));
        creations.spawn(async move {
            let _permit = gate.acquire().await.expect("semaphore");
            let name = format!("perf-user-{index:04}-che");
            let namespace: Namespace = serde_json::from_value(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": name,
                    "labels": {
                        "app.kubernetes.io/part-of": "che.eclipse.org",
                        "app.kubernetes.io/component": "workspaces-namespace",
                        "hardening.weebo.io/workspace-namespace": "",
                    },
                    "annotations": { "che.eclipse.org/username": format!("perf-user-{index:04}") },
                },
            }))
            .expect("namespace");
            let at = Instant::now();
            namespaces
                .create(&PostParams::default(), &namespace)
                .await
                .expect("namespace create");
            created.lock().await.insert(name, at);
        });
    }

    // Polled while the fleet is still being created, not after: on a slow runner creating 500
    // namespaces takes seconds, and a poll that started only at the end would charge that time
    // to the controller.
    let policies: Api<NetworkPolicy> = Api::all(client.clone());
    let mut latencies: HashMap<String, Duration> = HashMap::new();
    let mut fleet_created = None;
    let deadline = fleet_started + budget_fleet.max(Duration::from_secs(30)) * 3;
    while latencies.len() < fleet {
        while let Some(result) = creations.try_join_next() {
            result.expect("namespace task");
        }
        if fleet_created.is_none() && creations.is_empty() {
            fleet_created = Some(fleet_started.elapsed());
        }
        let seen = Instant::now();
        let list = policies
            .list(&ListParams::default().labels(MANAGED_BY))
            .await
            .expect("list NetworkPolicies");
        let created = created.lock().await;
        for policy in list.items {
            let namespace = policy.namespace().unwrap_or_default();
            if policy.name_any() == "weebo-base"
                && let Some(at) = created.get(&namespace)
            {
                latencies
                    .entry(namespace)
                    .or_insert_with(|| seen.saturating_duration_since(*at));
            }
        }
        drop(created);
        assert!(
            Instant::now() < deadline,
            "only {} of {fleet} namespaces got their baseline:\n{}",
            latencies.len(),
            controller.log_tail()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let fleet_time = fleet_started.elapsed();
    let converge_cpu = cpu_seconds(pid) - cpu_before;
    let slowest = latencies
        .iter()
        .max_by_key(|(_, latency)| **latency)
        .map(|(namespace, _)| namespace.clone())
        .unwrap_or_default();
    let mut sorted: Vec<Duration> = latencies.into_values().collect();
    sorted.sort();
    let (p50, p99, max) = (
        percentile(&sorted, 50.0),
        percentile(&sorted, 99.0),
        *sorted.last().unwrap(),
    );

    // 3. Idle: let the last events settle, then measure a window where nothing changes.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let idle_before = cpu_seconds(pid);
    tokio::time::sleep(idle).await;
    let idle_millicores = (cpu_seconds(pid) - idle_before) / idle.as_secs_f64() * 1000.0;

    // 4. Memory.
    let peak_mib = proc_status_kib(pid, "VmHWM") as f64 / 1024.0;
    let rss_mib = proc_status_kib(pid, "VmRSS") as f64 / 1024.0;

    // Still alive and serving: a process that died mid-run would measure as wonderfully idle.
    assert!(
        http_get(health_port, "/livez").is_some_and(|(status, _)| status == 200),
        "the controller stopped answering /livez:\n{}",
        controller.log_tail()
    );
    let metrics = http_get(health_port, "/metrics")
        .map(|(_, body)| body)
        .unwrap_or_default();
    assert!(
        metrics.contains("weebo_si_config_observed_generation"),
        "/metrics does not expose the operator's own gauges"
    );

    let secs = |d: Duration| format!("{:.2} s", d.as_secs_f64());
    let rows = [
        Row {
            what: "start → /readyz",
            measured: secs(ready),
            budget: secs(budget_start),
            within: ready <= budget_start,
        },
        Row {
            what: "fleet created (apiserver)",
            measured: secs(fleet_created.unwrap_or(fleet_time)),
            budget: "—".into(),
            within: true,
        },
        Row {
            what: "baseline latency p50",
            measured: secs(p50),
            budget: "—".into(),
            within: true,
        },
        Row {
            what: "baseline latency p99",
            measured: secs(p99),
            budget: secs(budget_p99),
            within: p99 <= budget_p99,
        },
        Row {
            what: "baseline latency max",
            measured: format!("{} ({slowest})", secs(max)),
            budget: "—".into(),
            within: true,
        },
        Row {
            what: "whole fleet converged",
            measured: secs(fleet_time),
            budget: secs(budget_fleet),
            within: fleet_time <= budget_fleet,
        },
        Row {
            what: "CPU spent converging",
            measured: format!("{converge_cpu:.2} s"),
            budget: "—".into(),
            within: true,
        },
        Row {
            what: "CPU idle",
            measured: format!("{idle_millicores:.1} m"),
            budget: format!("{budget_idle_millicores:.0} m"),
            within: idle_millicores <= budget_idle_millicores,
        },
        Row {
            what: "memory peak (VmHWM)",
            measured: format!("{peak_mib:.1} MiB"),
            budget: format!("{budget_peak_mib:.0} MiB"),
            within: peak_mib <= budget_peak_mib,
        },
        Row {
            what: "memory resident after idle",
            measured: format!("{rss_mib:.1} MiB"),
            budget: format!("{budget_rss_mib:.0} MiB"),
            within: rss_mib <= budget_rss_mib,
        },
    ];

    let mut report = format!(
        "### Operator resource budget — controller, {fleet} workspace namespaces, {}s idle\n\n\
         | measure | measured | budget | |\n| --- | --- | --- | --- |\n",
        idle.as_secs()
    );
    for row in &rows {
        let verdict = if row.within { "✅" } else { "❌" };
        writeln!(
            report,
            "| {} | {} | {} | {verdict} |",
            row.what, row.measured, row.budget
        )
        .unwrap();
    }
    println!("{report}");
    if let Ok(summary) = std::env::var("GITHUB_STEP_SUMMARY") {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(summary)
            .expect("open the job summary");
        writeln!(file, "{report}").expect("write the job summary");
    }

    let over: Vec<&str> = rows
        .iter()
        .filter(|row| !row.within)
        .map(|row| row.what)
        .collect();
    assert!(over.is_empty(), "over budget: {}", over.join(", "));
}
