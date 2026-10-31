# weebo-si-operator: the controller's resource budget

RFC 0012 left the operator's resource budget to *Future work*: the kit's `weebo-kit-perf` judges
reconcile metrics our loops do not emit, and needs Go to build its harness. This page sets that
budget, says how it is measured, and records what was measured against it. Change a budget here
and in `crates/weebo-si-operator/tests/perf_envtest.rs` in the same commit.

## How it is measured

| Tool | What it measures | Run it |
| --- | --- | --- |
| The [`operator-perf`](../.github/workflows/operator-perf.yaml) workflow, nightly and on demand | The test below on a **release** build, 500 namespaces and a 60 s idle window; the table in the job summary, red when a figure is over budget. | `gh workflow run operator-perf.yaml [-f namespaces=1000]` |
| `crates/weebo-si-operator/tests/perf_envtest.rs` | The real `weebo-si-operator controller` binary, spawned against an envtest apiserver with every upstream CRD its watches list (Route aside — it would switch endpoint-auth to the OpenShift dialect). A singleton puts labelled workspace namespaces under `network-profiles` in `Enforce`, canary off; then the test creates the fleet and reads the process from the outside: `/readyz`, `/proc/<pid>/stat`, `/proc/<pid>/status`. | `task envtest:operator-perf` (`PERF_NAMESPACES`, `PERF_IDLE_SECONDS` to change the run) |

The test refuses a debug build: the memory and CPU of a debug binary describe nothing we ship.

What it does **not** measure: the webhook role (its cost per admission request is RFC 0009's
territory for endpoint-auth, and has no budget of its own yet), the apiserver's side of the load,
and a real cluster's network round trip — envtest is loopback, so latencies here are a floor.

## The budget

| Measure | Budget | Override | Why this figure |
| --- | --- | --- | --- |
| Start → `/readyz` | ≤ 5 s | `PERF_BUDGET_START_SECONDS` | Readiness waits for every watch's first list. Past a few seconds a rolling upgrade leaves the lease without a warm standby longer than it should. |
| Baseline latency p99 (namespace created → its `weebo-base` exists) | ≤ 2 s | `PERF_BUDGET_P99_SECONDS` | The window in which a new workspace namespace runs without its baseline. |
| Whole fleet converged | ≤ 15 s | `PERF_BUDGET_FLEET_SECONDS` | A full resync after a restart or an upgrade, at 500 namespaces. |
| CPU idle | ≤ 10 millicores | `PERF_BUDGET_IDLE_MILLICORES` | What the controller costs all day on a cluster where nothing changes. |
| Memory peak (`VmHWM`) | ≤ 96 MiB | `PERF_BUDGET_PEAK_MIB` | Three quarters of the chart's controller limit (`128Mi`), headroom for a larger fleet. |
| Memory resident after idle (`VmRSS`) | ≤ 64 MiB | `PERF_BUDGET_RSS_MIB` | The steady state the memory request should be sized for. |

Latency is timed from each namespace's `create` returning to the first list that shows its
baseline. The list polls every 100 ms while the fleet is still being created, so a figure is at
most 100 ms pessimistic. Polling only once the fleet existed would charge the controller with the
apiserver's creation time, several seconds on a CI runner.

The defaults sit well above the first local measurement below: a shared CI runner is slower
and noisier than a laptop, and the nightly converges 500 namespaces, not 300. Tighten them once
the nightly trend is known.

## What was measured

### 2026-10-31, release build, laptop, 500 namespaces

After the fixes below; 20 runs in a row, all within budget. One of them:

| Measure | Measured |
| --- | --- |
| Start → `/readyz` | 0.67 s |
| Fleet created (the apiserver's own share) | 0.28 s |
| Baseline latency p50 / p99 / max | 0.09 s / 0.61 s / 0.61 s |
| Whole fleet converged | 0.86 s |
| CPU spent converging | 0.32 s |
| CPU idle | 0.0 m |
| Memory peak / resident after idle | 44.9 MiB / 44.9 MiB |

The max across the 20 runs stayed between 0.21 s and 0.63 s.

The resident figure is above the chart's controller memory request (`32Mi`): the request
under-reserves what the process actually holds. Raising it to `48Mi` is a chart change of its
own, left for when the nightly figures confirm it.

Add the first nightly run's table here, with its date and run link, once it has run.

## What the budget found

**A new namespace could wait a minute for its baseline** (fixed 2026-10-31). The first run at 500
namespaces measured p99 and max at 60 s against a p50 of 0.1 s. The loops' Namespace watch can
deliver a new namespace before the shared namespace index has it. The gate, which reads labels
from that index, then answered `Off`, and the namespace was rechecked after `OFF_RECHECK`, 60 s.
`weebo_si_controller::workspace::off_recheck` now retries a namespace the index had not seen
after 0.5 s instead. `network-profiles`, `kubearmor-policy` and `registry-config` share it.

The first version of that fix still lost one namespace in about ten runs. It looked the
namespace up *after* the gate had answered `Off`, and the index could receive it between the two
reads: "seen" then meant the slow recheck for exactly the namespace the gate had missed. Every
call site now samples the index (`workspace::indexed`) *before* asking the gate.

**The controller could hang at startup, never ready** (fixed 2026-10-31). About one start in ten
never reached `/readyz`. During the hang the apiserver answered the stuck request's URL in under
10 ms. The request had gone out on a keep-alive connection the client's pool handed over in a
broken state, and kube sets no read timeout, so it waited forever. In a cluster that is a pod that
never becomes ready, and that liveness never restarts. hyper 1.12.0 and hyper-util 0.1.21, whose
legacy client pool fixes shipped in September 2026, end it: 60 starts in a row, no hang.

**Debugging a red run.** The workflow uploads the controller's log as an artifact when the job
fails. Locally, `PERF_CONTROLLER_LOG=<file>` keeps the log, and `PERF_RUST_LOG` sets its filter,
for example `info,kube_client=debug,hyper_util=debug` to see every request and connection. The
table's *baseline latency max* row names the slowest namespace, to look up in that log.
