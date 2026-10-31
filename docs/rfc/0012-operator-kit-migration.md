---
rfc: 0012
title: operator kit migration
status: Accepted
authors: [batleforc]
created: 2026-10-31
updated: 2026-10-31
decided: 2026-10-31
brick: crates/weebo-si-operator
supersedes: []
superseded-by: []
---

# RFC 0012 — operator kit migration

## Summary

Move `weebo-si-operator`'s plumbing (telemetry, health, shutdown, the TLS webhook server, leader
election, requeue, Events, conditions, the envtest harness) onto
[`weebo-operator-kit`](https://github.com/batleforc/weebo-operator-kit), the shared core every
other weebo operator already runs on. In the same effort, regroup each feature's adapters with the
feature itself so the shared crates stop holding one file per feature. This is a migration, done
one mergeable step at a time. It is not a rewrite, and it changes no CRD and no admission
decision.

## Motivation

`weebo-si-hardening` predates the kit. It grew its own version of everything the kit now provides,
and its own version has gaps the kit has already closed:

- **Logs are `println!`.** There is no level, no structure, no trace, and no `LOG_FORMAT=json` for
  a log pipeline to parse.
- **No Kubernetes `Event`.** A `Degraded` `WeeboSiConfig` is visible in its status, but nothing
  says *when* it became degraded, and `kubectl describe` on a workspace namespace says nothing.
- **Readiness never fails on a broken watch** (`todo.md` M12, deferred). The kit's `Health`
  reports the process dead after a component keeps failing for 5 minutes.
- **Every reconcile error requeues after a flat 30 s** (`todo.md` L5, deferred), with the same
  `error_policy` copied into five controllers. The kit's `retry_after_error` adds jitter and a
  steady requeue.
- **Leader election is a third-party crate** (`kube-leader-election`) wrapped by hand in
  `controller/src/lib.rs`. The kit's lease works on the monotonic clock and was hardened by two
  reviews (kit v0.14.0, v0.14.1).

The structure costs more than the plumbing. Adding a feature touches six places
([`operator-internals.md`](../architecture/operator-internals.md#adding-a-feature)):

- `weebo-si-runtime` holds 5 per-feature `*_metrics.rs` files and 3 per-feature
  `*_template_store.rs` files.
- `weebo-si-webhook` holds one router file per feature.
- `weebo-si-controller` holds one loop file per feature.

Once this RFC is `Implemented`:

- The operator logs, traces, reports health and elects a leader exactly the way every other weebo
  operator does.
- A kit fix reaches it with a `task kit:sync`.
- A new feature means one schema, one domain crate and one adapters crate, plus a line in the
  composition root and its chart objects.
- No admission decision, no CRD and no metric name has changed.

## Guide-level explanation

For the person running the cluster, the upgrades this RFC produces are ordinary chart upgrades.
What they will notice:

- **Logs become `tracing` lines.** The fields stay the same: namespace, workspace, current and
  target reference, decision, and never the object. `LOG_FORMAT=json` turns them into JSON. A
  `grep weebo-si-webhook: allow` in a runbook becomes a `grep 'decision=allow'`.

  ```text
  2026-11-02T10:14:03Z  INFO weebo_si_webhook::dwoc_pin: admission decision=allow namespace=user-alice workspace=python-web current=<none> target=eclipse-che/weebo-hardened-config
  ```

- **Events appear.** `kubectl describe weebosiconfig cluster` lists when a feature changed mode,
  when a catalogue entry went missing, and when a reconcile failed and why. The namespace a
  feature writes into gets an Event when its objects are applied or torn down.
- **The controller's standby replica waits for the lease before starting its loops.** Failover
  still takes at most the lease TTL (15 s). A replica that loses the lease exits with code `1` and
  is restarted. Today it carries on watching with its loops idle.
- **Liveness can now fail.** A watch that keeps erroring for 5 minutes makes the pod not live,
  and the kubelet restarts it. Today such a pod stays `Ready` and does nothing. The chart's
  liveness probe moves from `/healthz` to `/livez`: in the kit, `/healthz` is an alias of
  `/readyz`, and a liveness probe on readiness would kill a pod whose caches are still syncing.
- **Probes and metrics ports may move** (see *Contract* and *Unresolved questions*). The chart
  moves with them, so nothing needs editing unless you render the Deployments yourself.

What they will not notice: every `WeeboSiConfig`, `WeeboSiTeam` and `WeeboSiUser` object, every
webhook path, every `failurePolicy`, every admission verdict and every metric name stays as it is.

## Design

### Contract

**Unchanged, and tested as unchanged:**

- The three CRDs. No schema change. `task crd:check` must pass on every PR of this RFC without
  regenerating anything.
- Every admission path, its rules and its `failurePolicy`
  ([table](../architecture/operator-internals.md#an-admission-request-end-to-end)).
- Every admission decision. The envtest and e2e suites are the oracle, and they must stay green
  with no expected value edited.
- Every metric name and label set listed in the brick pages' *Observability* sections.
- The admin subcommands (`crd`, `features`, `backends`, `canary`, `images`, `registry`, `teams`),
  their flags and their exit codes.
- Exit codes `0`/`1`/`2`. Losing the lease exits `1` ("internal error"), which is what the code
  already means.

**Changed, deliberately:**

| Surface | Today | After | Why |
| --- | --- | --- | --- |
| Log format | plain `println!`, prefix `weebo-si-<crate>:` | `tracing`, same fields, `LOG_FORMAT=json` optional | the kit's telemetry |
| Traces | none | OTLP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set | the kit's telemetry |
| Events | none | `events.k8s.io/v1` Events on `WeeboSiConfig`, `WeeboSiTeam`, `WeeboSiUser` and the namespaces written into | the kit's `events` |
| Liveness | `/healthz`, always `200` once started | `/livez`, `503` after 5 min of a component failing; `/healthz` becomes an alias of `/readyz` | closes `todo.md` M12 |
| Reconcile retry | flat 30 s | kit's `retry_after_error`: jittered retry, steady requeue | closes `todo.md` L5 |
| Standby controller replica | watches, loops idle | waits for the lease; exits `1` if the lease is lost | the kit's `acquire_leadership` |
| Controller RBAC | — | `create`/`patch` on `events.k8s.io/events` | Events |

**Kept, through a kit addition:** `webhook --addr`, `--cert-dir`, `--health-addr` and
`--metrics-addr`. The kit's `webhook_server::spawn` reads `WEBHOOK_PORT`,
`WEBHOOK_TLS_CERT_FILE` and `WEBHOOK_TLS_KEY_FILE` from the environment and serves the probes on
the TLS port (default `8443`). Today the probes are on a plain-HTTP `8081`, and the webhook is on
`9443`. `std::env::set_var` is `unsafe` in edition 2024 and `unsafe_code` is forbidden here, so
the flags cannot simply be forwarded at run time. The kit gains
`webhook_server::spawn_with(WebhookServerConfig)`, which takes the listen address, the
certificate paths and an optional separate health address. `spawn` becomes `spawn_with` fed from
the environment, so no other operator changes. The addition names no product, so it passes the
kit's inclusion rule, and any operator with CLI flags can use it. The probes stay on plain HTTP on
`8081`, where the chart's probes and `NetworkPolicy` already point.

### Architecture

Hexagonal: **yes, unchanged in principle.** This RFC changes where the adapters live, not the
dependency rule. A feature's domain still depends on `weebo-si-chassis` and `weebo-si-crd` only.

**What comes from the kit, and what does not:**

| Kit piece | Adopted | Replaces | Note |
| --- | --- | --- | --- |
| `weebo-kit-runtime::telemetry` | yes | `println!`/`eprintln!` | logs and traces only at first (see *Data and state* on metrics) |
| `weebo-kit-runtime::health`, `shutdown` | yes | `operator/src/observability.rs`, the hand-written SIGTERM handling | |
| `weebo-kit-runtime::webhook_server::spawn` | yes | `operator/src/webhook_cmd.rs` TLS, reload and drain | it takes any `axum::Router`, so our routers mount unchanged |
| `weebo-kit-runtime::admission` (`Admission`, `router`) | **no** | — | see below |
| `weebo-kit-runtime::leader` | yes | `kube-leader-election` and `run_leader_election` | same Lease name, `weebo-si-controller-leader` |
| `weebo-kit-runtime::controller` (`jittered`, `requeue_after`, `retry_after_error`, `drive`) | yes | five copies of `error_policy` | |
| `weebo-kit-runtime::events`, `conditions`, `status` | yes | the hand-written status patch in `controller/src/reconcile.rs` and `identity.rs` | |
| `weebo-kit-runtime::shared` (`SharedWatches`) | partly | duplicate `Namespace` watches across loops | typed kinds only (`DynamicType = ()`). `DevWorkspace`, `CiliumNetworkPolicy` and `KubeArmorPolicy` are `DynamicObject` here and stay on plain watchers until they get typed derives |
| `weebo-kit-testkit` | **no** | — | see *Changelog*, 2026-10-31: it lacks what our suites rely on |
| `weebo-kit-perf` | **not yet** | — | see *Changelog*: it measures the kit's own reconcile metrics |
| `weebo-kit-domain::Reason`/`reason_codes!` | later | free-text denial reasons | *Future work*: denial reasons become a contract only if we want them to |
| `weebo-kit-api`, `-application`, `-adapters` | no | — | secret stores and instance references: si-hardening has none |
| `charts/weebo-operator-lib` | **no** | — | it renders one Deployment and a `ValidatingWebhookConfiguration` on the operator's own group only. We need two Deployments, mutating configurations, and rules on core, `workspace.devfile.io`, `networking.k8s.io`, `cilium.io`, `security.kubearmor.com` and `route.openshift.io` |
| `tasks/{rust,helm,repo}.yaml`, `templates/kit.yaml` | **no** | — | see *Changelog*: ours are stricter |
| `.github/workflows/checks.yml` | yes, alongside ours | the lint and audit jobs only | envtest, conformance, e2e and the brick scans stay in our workflows |
| `.github/workflows/publish.yml` | no, for now | — | it publishes one image and one chart. We publish four images and three charts |
| `@weebo/operator-docs` | yes | `docs/generator/`, once the site's CRD form covers it | a site in `site/`; see *Documentation site* below |

**Why not the kit's `Admission` trait.** The kit's `decide()` hard-codes two rules that are right
for an operator admitting its own CRs and wrong for us:

1. **`DELETE` is always allowed.** `policy-guard` exists to refuse a developer's `DELETE` of the
   `NetworkPolicy` baseline in their own namespace. Routing it through the kit's router would
   silently turn the guard off for its most important verb.
2. **An `UPDATE` with an unchanged `spec` is allowed without a decision.** Ownership lives in
   `metadata`: `policy-guard` recognises its objects by the `hardening.weebo.io/managed-by`
   label. Under the kit's shortcut, a metadata-only `UPDATE` that strips the label would pass
   with no decision made, and the object would then be the developer's to delete. `endpoint-auth` likewise
   reads its opt-in from `metadata.annotations`.

The trait also has no mutating response. Our routers stay ours, mounted on the kit's server. If a
second operator ever needs mutating admission or a guard on foreign kinds, that becomes a kit
proposal under its own inclusion rule (the kit's `docs/plan.md`, section on what goes into the
kit), not a prerequisite for this RFC.

**Regrouping the adapters.** Each feature gets an adapters crate next to its domain crate:

```text
crates/
├── weebo-si-crd/                   # unchanged
├── weebo-si-chassis/               # unchanged, plus the wiring traits below
├── weebo-si-image-policy/          # domain: unchanged, still depends on crd + chassis only
├── weebo-si-image-policy-adapters/ # new: its kube stores, its metrics, its axum router,
│                                   #      its controller loop — moved out of runtime, webhook
│                                   #      and controller
├── …                               # the same pair for every feature
├── weebo-si-runtime/               # shrinks to what is genuinely shared: KubeConfigStore,
│                                   # KubeNsStore, KubeDwocStore, access, capabilities
├── weebo-si-webhook/               # shrinks to admit() → AdmissionResponse, JSON Patch render,
│                                   # the shared admission metrics
├── weebo-si-controller/            # shrinks to the WeeboSiConfig status loop
└── weebo-si-operator/              # composition root: iterates the features' wiring
```

The composition root stops naming every adapter by hand. Each adapters crate exposes two
functions with one signature shape per role:

```rust
// in each weebo-si-<feature>-adapters crate, as it applies
pub fn admission_routes(shared: &AdmissionShared) -> axum::Router;
pub async fn controller_deps(shared: &ControllerShared) -> Result<Option<Deps>, String>;
pub async fn controller::spawn(client: Client, deps: Deps, recorder: Recorder);
```

`controller_deps` runs before the replica waits for the lease and starts the feature's watches,
so a standby's caches are warm when it takes over; `controller::spawn` runs once it holds the
lease. A feature the cluster or the role's RBAC does not allow returns `None` and is never
started, as before.

`AdmissionShared`/`ControllerShared` carry what every feature may use: the client, the config
store, the namespace view, the Prometheus registry, the health handle and the leader flag.
`webhook_cmd.rs` merges the routers and `controller_cmd.rs` spawns the loops. Adding a feature
adds a line or two to each.

A trait object (`Box<dyn FeatureWiring>`) was considered. Plain functions in a fixed list keep
the "what does this build contain" question answerable by reading `features.rs`. The list is
already there, and a trait would only hide it.

Ports and adapters per feature do not change. They move house. The ports stay in the domain
crate, and the adapters that implement them move from `weebo-si-runtime` into the feature's
adapters crate.

### Documentation site

A Fumadocs site built on `@weebo/operator-docs` lives in `site/`, as in the kit's own repository.
It does not go in `docs/`, as it does in the other operators, because `docs/` is plain markdown
and stays that way. It provides:

- the CRD reference generated by `weebo-crd-docs` from the chart's `crds/`: the three kinds,
  every field, plus the CRD form and editor that today's `docs/generator/` provides by hand;
- the kit's runtime pages (metrics, Events, health, leader election), quoted from the kit, so
  they cannot drift from the code;
- pages for the features, the architecture and the RFCs, which link to the markdown files in
  `docs/`. The markdown stays the source and keeps readable diffs.

`docs/generator/` is removed in the same PR that publishes the site, once the site's form covers
the three kinds. GitHub Pages switches from the generator to the site's static export.

### Data and state

- **No persisted state changes.** The operator keeps no state outside the cluster objects it
  writes, and this RFC writes the same objects with the same labels.
- **Metrics stay on the `prometheus` crate at first.** The kit's telemetry exports metrics through
  OpenTelemetry's Prometheus exporter. That exporter derives names from the instrument name and
  unit, which can add `_total` or a unit suffix where today's names have none. The metric names
  are a contract, so the migration keeps today's `prometheus::Registry` and serves it from the
  same `/metrics`, and enables only the kit's logs and traces. Moving instruments to OpenTelemetry
  is *Future work*. It needs a test asserting the exported names, series by series, against this
  RFC's list.
- **The lease.** The same Lease name, so a rolling upgrade from the old controller to the new one
  hands over through the lease rather than running two leaders. The two implementations must
  agree on the lease's fields (`holderIdentity`, `leaseDurationSeconds`, `renewTime`). Both
  implement the coordination.k8s.io semantics, and the e2e upgrade test in the *Implementation
  plan* checks that a hand-over between them works.

## Security considerations

- **Privileges.** The webhook role's RBAC does not change. The controller role gains
  `create`/`patch` on `events.k8s.io/events`, nothing else. The webhook role does **not** get
  Events. It is the role untrusted `AdmissionReview` bodies reach, and an Event written from there
  would be a write path an attacker can trigger at will.
- **Trust boundary.** Unchanged. The admission routers keep their extraction code
  (`webhook/src/extract.rs`) and its regression test that the object's `data` is read in exactly
  one place. The kit's server adds a 30 s request timeout that answers `503`, which is below the
  apiserver's own maximum and so changes nothing a caller can observe.
- **Bypass.** The one real bypass risk in this RFC is adopting the kit's `Admission` router by
  mistake (see *Architecture*), which would allow every `DELETE`. It is rejected by design, and
  the envtest case "a developer deletes the baseline `NetworkPolicy` and is refused" is already in
  the suite. It must stay green and unmodified on every PR.
- **Blast radius.** Unchanged in kind. The "exit on lease loss" behaviour makes a flapping
  apiserver restart the controller rather than leave it reconciling on a stale lease. That is the
  safer of the two.
- **Secrets.** Logs keep today's field set. `tracing`'s `?debug` formatting of a whole object is
  exactly the mistake that would leak a token. The PR that moves logging adds a test, next to the
  existing `data` one, that no `tracing` macro in `weebo-si-webhook` takes an admitted object or a
  `DynamicObject`.
- **Supply chain.** The kit comes in as a git dependency pinned to a tag. `deny.toml` today has
  `unknown-git = "deny"`, so the kit's repository is added to `allow-git` explicitly, and
  `task supply-chain` covers it like any other dependency. A kit release is a dependency bump,
  reviewed like one.

## Operational considerations

- **Failure mode.** No `failurePolicy` changes. The kit's server keeps answering for
  `WEEBO_SHUTDOWN_DRAIN_SECONDS` (default 5 s) after SIGTERM, which matches today's drain.
- **Rollout.** One release per phase of the *Implementation plan*, each a normal chart upgrade
  with the e2e suite green before it is tagged. Telemetry and health come first, because they
  change nothing a decision depends on and they give visibility on the phases that follow.
- **Rollback.** The previous chart version. No CRD or stored object changes, so going back is
  `helm rollback` and nothing else, at any phase.
- **Observability.** Existing dashboards and alerts keep working: same metric names. New signals:
  Events, traces, and a liveness probe that fails.
- **Upgrade.** During a rolling update, old and new webhook pods answer side by side with the same
  decisions, which is the e2e oracle. Old and new controller pods hand over through the same
  Lease.

## Alternatives considered

- **Rewrite from scratch on the kit's `cargo-generate` template.** The template is shaped for an
  operator driving a remote product through an API gateway (Instance / LocalInstance / Object).
  si-hardening generates policies and admits other people's workloads. The rewrite would replace
  ~5–6k lines of plumbing by re-typing ~65k lines of tested decisions. It would also re-open the
  production-readiness review's fixes (B1–B7, H1–H14 in `todo.md`), most of which live in
  decision code, not plumbing. Rejected.
- **Do nothing.** It keeps working, but every kit fix (the monotonic-clock lease, the TLS reload,
  the request timeout) has to be re-derived here by hand, and M12/L5 stay open. Rejected.
- **Adopt the kit wholesale, adding what is missing to the kit first** (a mutating `Admission`, rules on
  foreign kinds, a multi-Deployment library chart). It blocks this work on three kit features that
  no other operator needs today, which fails the kit's own inclusion rule. Kept as the path if a
  second operator ever needs them.
- **Upstream si-hardening's chassis into the kit.** `Feature<S>`, `Registry<S>` and
  `admit()` are built around namespace-scoped hardening of workloads the operator does not own. No
  other operator has that shape. Rejected for the same inclusion rule.
- **Per-feature cargo features instead of adapters crates** (one crate per feature, `kube`
  behind `#[cfg(feature = "adapters")]`). It has fewer crates, but the "domain cannot name `kube`"
  rule is enforced by a feature flag any `cargo test --all-features` turns off. Today's
  separate-crate rule is enforced by the dependency graph. Rejected.

## Drawbacks and risks

- **A second release train to follow.** Kit releases are frequent (v0.25.1 at the time of writing,
  some minors breaking). Pinning by tag means choosing when to move. `task kit:sync` makes the move
  cheap but not free.
- **More crates.** Eight adapters crates bring the workspace from 16 to 24 members. Build times
  are dominated by `kube` and `k8s-openapi`, which are already compiled once, so the cost is
  readability of the tree rather than compile time. `repo-layout.md` must explain the pairing.
- **The lease hand-over between two implementations** is the one step where an upgrade could run
  two leaders. Mitigated by the same Lease name, the e2e upgrade test, and by the fact that the
  reconcile loops are idempotent server-side applies: two leaders write the same objects.
- **Log-based runbooks break.** Anything grepping `weebo-si-webhook: allow` must change. The brick
  pages' *Reading the logs* sections are updated in the same PR.

## Unresolved questions

Resolved on 2026-10-31:

1. **The webhook's CLI flags.** Kept, through `webhook_server::spawn_with` in the kit (see
   *Contract*).
2. **The docs site.** Adopt `@weebo/operator-docs`, in `site/` (see *Documentation site*).

Not blocking:

1. **`publish.yml`.** Call the kit's reusable workflow once per image and chart, or keep our
   `release.yaml`. It depends on whether `publish.yml` can be called four times in one release
   without four GitHub releases.
2. **`endpoint-gateway` and `preauth-proxy`.** Both have their own telemetry, health and
   shutdown. Moving them onto `weebo-kit-runtime` is the same work at a smaller scale. It can
   follow this RFC or be folded in.

## Future work

- **A resource budget with `weebo-kit-perf`**, once the two prerequisites below exist: the loops
  emitting the kit's reconcile metrics alongside ours, and a harness that runs without Go.

- **OpenTelemetry metrics**, with a test pinning every exported name to the contract list.
- **Reason codes for denials** (`weebo-kit-domain::reason_codes!`). Today a denial reason is free
  text. A code would make "why was I refused" countable and alertable.
- **Typed `DevWorkspace`, `CiliumNetworkPolicy` and `KubeArmorPolicy`**, so they can share one
  watch through `SharedWatches`.
- **Moving mutating admission into the kit** to the kit, if and when a second operator needs it.
- **A validating webhook on our own CRDs**, shared *Future work* with RFC 0002 and RFC 0005. The
  kit's `Admission` trait *is* the right tool there, since those are our own CRs.

## Implementation plan

Each box is one mergeable PR. Every PR keeps `task lint`, `task test`, the envtest suites and the
nightly e2e green with no expected value edited, and `task crd:check` clean without regenerating.

- [x] Docs: `architecture/operator-internals.md`, one brick page per feature, `repo-layout.md`
      brought up to date (the starting point this RFC refers to)
- [x] Tooling: kit added as a git dependency pinned to a tag, `allow-git` in `deny.toml`
- [x] Telemetry: `weebo-kit-runtime::telemetry` in both roles, a stderr subscriber for the admin
      subcommands.
      `println!`/`eprintln!` become `tracing` with today's fields, plus the "no object in a
      `tracing` macro" test. *Reading the logs* sections updated
- [x] Health and shutdown: kit `Health` and `Shutdown`, liveness fed by every watch (closes M12)
- [x] Kit: `webhook_server::spawn_with(WebhookServerConfig)` (listen address, certificate
      paths, optional separate health address), released in a kit minor
- [x] Webhook server: `webhook_server::spawn_with`, and `reload_certificate`/`drain_on_signal`
      deleted
- [x] Controller: kit leader election (same Lease name), `retry_after_error` in every loop
      (closes L5), Events and conditions on `WeeboSiConfig`/`WeeboSiTeam`/`WeeboSiUser`,
      `events.k8s.io` RBAC in the chart
- [x] e2e: a rolling upgrade from the last pre-kit release to the current build, asserting one
      leader at a time and no admission error during the roll
- [x] Wiring: `AdmissionShared`/`ControllerShared` and the two per-feature functions, with the
      composition root iterating them. No feature moved yet
- [x] Adapters crates, one PR per feature, smallest first: `dwoc-pin`, `policy-guard`,
      `registry-config`, `kubearmor-policy`, `network-profiles`, `image-policy`, `identity`,
      `endpoint-auth`. Each moves that feature's files out of `weebo-si-runtime`,
      `weebo-si-webhook` and `weebo-si-controller`
- [x] Dedup: nothing left to do — see *Changelog*
- [x] Docs site: `site/` on `@weebo/operator-docs`, the CRD reference generated from the
      chart's `crds/`, published to GitHub Pages in place of `docs/generator/`, which is removed
- [~] Perf: deferred to *Future work* — see *Changelog*
- [ ] Docs updated: `operator-internals.md` (crate map, *Adding a feature*), `repo-layout.md`,
      each brick page's *Reading the logs* and *Observability*, and `ci.md`
- [ ] RFC flipped to `Implemented`

## References

- [`weebo-operator-kit`](https://github.com/batleforc/weebo-operator-kit), and its `docs/plan.md`
  (design, inclusion rule, migration log of the other operators)
- [`architecture/operator-internals.md`](../architecture/operator-internals.md): the structure
  this RFC changes
- [RFC 0002](./0002-weebo-si-operator.md): the chassis, the two roles, the exit codes
- [RFC 0004](./0004-network-profiles.md) and [RFC 0008](./0008-policy-guard-coverage.md): why
  `policy-guard` must judge `DELETE`
- `todo.md`: M12 and L5, the two deferred items this RFC closes

## Changelog

| Date | Change |
| --- | --- |
| 2026-10-31 | `weebo-kit-testkit` dropped from the plan, `weebo-si-envtest-support` kept. The kit's harness runs RBAC only, so it cannot authenticate several identities with `AlwaysAllow`, which the guard suites need so that the webhook's verdict is what gets tested (`start_with_identities`). It has no webhook TLS helpers. It also needs Go and `libclang` at build time through `bindgen`, and CI has neither. Found while starting the *Tests* step |
| 2026-10-31 | The kit's shared tasks and `templates/kit.yaml` dropped from the plan. Our `rust:*` tasks run with `--locked` and `--all-features` and split the e2e crate out, and the kit's do neither. `kit:cog` would re-render our `cog.toml` from the kit's template and lose its hooks (`task recu`, gitleaks, the whitespace scripts). The kit tag is bumped by hand in `Cargo.toml` |
| 2026-10-31 | *Dedup* had nothing to do: the three `model/diff.rs` files already re-export `chassis::managed`'s algorithm since RFC 0006, and keep only their feature's `Managed` impl and `DesiredState`, which are feature-specific by design. The *Motivation* bullet came from a survey that read the file names, not their contents |
| 2026-10-31 | The kit gains `controller::reconciled(object)` in the same release as `spawn_with`: our loops requeue on their own schedule, so without it a recovered object's next failure would resume the previous streak's backoff instead of 30 s |
| 2026-10-31 | *Wiring*: `spawn_controllers` became `controller_deps` (before the lease) plus `controller::spawn` (after it). One function would have started the watches only once the lease is held, and a standby would then take over with cold caches |
| 2026-10-31 | *Adapters*: seven crates, not eight — `dwoc-pin` has no adapters of its own (its route is the shared `DevWorkspace` mutation it runs with the `network-profiles` gate, its catalogue the shared `KubeDwocStore`). `kubearmor-policy`, `registry-config` and `endpoint-auth`'s adapters read `weebo-si-network-profiles::is_excluded_namespace`, as the old controller crate did. The envtest suites moved with the code they test; the two that drive several features at once moved to `weebo-si-operator/tests/` as `admission_envtest` and `controller_envtest`, and the CRD fixtures to `weebo-si-envtest-support/fixtures/` |
| 2026-10-31 | *e2e*: the `upgrade` suite is written (script, test, nightly matrix) but has not run yet: it needs the e2e kind cluster with Che and the GHCR packages public (`todo.md` F3) |
| 2026-10-31 | *Perf* deferred. `weebo-kit-perf` runs the binary against `weebo-kit-testkit`'s envtest (Go and `libclang` at build, which this RFC already declined), hands it its metrics address through `WEEBO_METRICS_ADDR` (our contract is `--health-addr`), and judges the kit's `<prefix>_reconcile_total`/`_duration_seconds`, which our loops do not emit because the metric names stayed ours. A budget measured without its reconcile half would read green for the wrong reason |
| 2026-10-31 | Liveness probe moves to `/livez`: the kit serves `/healthz` as an alias of `/readyz`. Found while reading `weebo-kit-runtime::health` for the *Health* step |
