# How `weebo-si-operator` works inside

How the operator is built: which crate does what, what each of its two roles runs, and how an
admission request and a reconcile flow through the code. The operator's *usage* — install, CLI,
rollout — is [`bricks/weebo-si-operator.md`](../bricks/weebo-si-operator.md); the *why* of each
rule below is in the RFC it cites.

## One binary, two roles

`crates/weebo-si-operator` builds the single binary `weebo-si-operator`. The chart runs it twice,
as two Deployments with two `ServiceAccount`s:

| Role | Command | What it serves | Writes to the cluster |
| --- | --- | --- | --- |
| **webhook** | `weebo-si-operator webhook` | every admission route, on `:9443` (TLS) | nothing — it answers `AdmissionReview`s |
| **controller** | `weebo-si-operator controller` | the reconcile loops | the objects each feature owns, and status |

Both serve `/readyz`, `/livez`, `/healthz` and `/metrics` on `--health-addr` (`:8081`,
`crates/weebo-si-operator/src/observability.rs`); the probes are `weebo-kit-runtime`'s `Health`. The split is a security boundary, not a
scaling one: the webhook is the role an untrusted `AdmissionReview` body reaches, so its RBAC is
read-only and never holds the controller's writes (RFC 0002, *Security considerations*).

Every other subcommand (`crd`, `features`, `backends`, `canary`, `images`, `registry`, `teams`) is
an admin tool run from a workstation with the admin's own kubeconfig.

## The crates

```text
                               weebo-si-operator   (bin, the only composition root)
                                       │ calls each feature's composition functions
        ┌──────────────┬───────────────┼───────────────┬───────────────┐
  weebo-si-<feature>-adapters  (one per feature: its stores, metrics, admission routes, loops)
        │                      │                       │
  weebo-si-webhook      weebo-si-controller      weebo-si-runtime
  (shared admission:    (shared reconcile:       (shared adapters: the config and namespace
   DevWorkspace route,   WeeboSiConfig status,    caches, watch driving, access checks,
   extract, render,      Events and retry,        managed-object delete)
   metrics,              workspace helpers,
   AdmissionShared)      ControllerShared)
        │                      │                       │
  weebo-si-<feature>  (the decision: subject, Feature/ReconcileFeature impl, ports)
        │
  weebo-si-chassis    (Feature<S>, Registry<S>, admit(), ports, managed diff)
        │
  weebo-si-crd        (the three CRDs and every feature's config schema)
```

| Crate | Layer | Holds |
| --- | --- | --- |
| `weebo-si-crd` | schema | `WeeboSiConfig`, `WeeboSiTeam`, `WeeboSiUser` (`hardening.weebo.io/v1alpha1`, cluster-scoped) and every feature's config types, their merge and their `Resolved*` forms |
| `weebo-si-chassis` | domain | the feature traits, the registry, `admit()`, the ports every feature shares, the managed-object diff. **No `kube`, no `serde`** — it cannot name a cluster |
| `weebo-si-<feature>` | domain + application | one feature each: its subject, its decision, its ports, and (for reconcile features) its `application::reconcile` |
| `weebo-si-<feature>-adapters` | adapters | one feature each: the kube stores behind its ports, its Prometheus metrics, its admission routes, its reconcile loops, and the composition functions below |
| `weebo-si-runtime` | shared adapters | `KubeConfigStore`, `KubeNsStore`, `KubeDwocStore`, `PrometheusObserver`, `watch` (driving a watch, feeding liveness), `access` (an access review before a watch), `delete` (uid-pinned deletes) |
| `weebo-si-webhook` | shared admission | the `DevWorkspace` mutation route (`dwoc-pin` plus the `network-profiles` gate), `AdmissionReview` extraction, JSON Patch rendering, the admission metrics, `AdmissionShared` |
| `weebo-si-controller` | shared reconcile | the `WeeboSiConfig` status loop, `events` (reason codes, Events, retry), `workspace` (DevWorkspace id/owner, `held` warnings), `ControllerShared` |
| `weebo-si-operator` | composition root | CLI parsing, the shared caches, one call per feature, TLS, health, leader election, shutdown |
| `weebo-si-envtest-support` | test | a real etcd + kube-apiserver for the envtest tier, and the CRD fixtures every suite installs |
| `weebo-si-e2e` | test | the nightly suites on kind with real Eclipse Che |

There are seven adapters crates: `network-profiles`, `kubearmor-policy`, `registry-config`,
`image-policy`, `policy-guard`, `endpoint-auth` and `identity`. `dwoc-pin` has none: its one
route is the shared `DevWorkspace` mutation in `weebo-si-webhook`, which it shares with the
`network-profiles` gate, and its catalogue is the shared `KubeDwocStore`.

The dependency rule is [`hexagonal.md`](./hexagonal.md)'s: a feature's domain crate depends on
`chassis` and `crd` only, never on another feature and never on `kube`. An adapters crate depends
on its domain crate and the shared adapter crates; the three that skip the structural namespace
exclusions also read `weebo-si-network-profiles::is_excluded_namespace`, the one domain helper
shared across features. Only the operator names every adapters crate.

`endpoint-gateway` (`bins/endpoint-gateway`) is a separate process with its own chart. It shares
`weebo-si-endpoint-auth`'s decision code with the operator, but not its runtime: the operator
attaches the gate to workspace routes, the gateway answers the forward-auth calls. See
[`bricks/endpoint-gateway.md`](../bricks/endpoint-gateway.md).

### The composition functions

Each adapters crate exposes the same small surface, which is all the composition root calls:

| Function | Role | Returns |
| --- | --- | --- |
| `admission_routes(&AdmissionShared)` | webhook | an `axum::Router` of the feature's admission paths |
| `controller_deps(&ControllerShared)` | controller, **before** the lease | the feature's started watches and wiring — or `None` when the cluster or the role's RBAC does not allow the feature at all |
| `controller::spawn(client, deps, recorder)` | controller, **after** the lease | the feature's reconcile loops, running |

The split on the controller side is what keeps a standby replica's caches warm: every feature's
watches start and sync before the replica waits for the lease, and only its loops wait.

## Features: the two shapes

A feature is one named behaviour with one config field under `spec.features`, one `mode`
(`Off` / `DryRun` / `Enforce`) and one `FeatureId` (kebab-case in logs and metrics, camelCase as the
CRD field — `chassis/src/feature/value.rs`).

| Shape | Trait | Returns | Used by |
| --- | --- | --- | --- |
| admission | `Feature<S>::evaluate(subject, ctx)` | a `Decision<S>`: mutations, or a denial | `dwoc-pin`, `image-policy`, `policy-guard`, `endpoint-auth` (mutation and guard), the `network-profiles` workspace gate |
| reconcile | `ReconcileFeature<S>::desired(subject, ctx)` | a feature-specific `Desired` value: the objects that should exist | `network-profiles`, `kubearmor-policy`, `registry-config`, `endpoint-auth` (sweep) |

Two invariants hold for both, by construction:

- **A feature never learns its own mode.** `Context` (`chassis/src/feature/registry.rs`) carries
  the teams, the namespace's facts and the DWOC catalogue — and deliberately not the
  `FeatureGate` port, so there is no path from inside `evaluate()` to the mode.
- **`DryRun` runs the code `Enforce` runs.** The mode is applied at the edge — by `admit()` for
  admission, by each feature's `application::reconcile` for reconcile — after the decision is
  made. A test in `chassis/src/admit.rs` runs the same scenario in both modes and asserts the same
  decision.

`identity` (RFC 0011) is the exception: it reconciles `WeeboSiTeam`/`WeeboSiUser` into an
`AuthentikUser` and an Argo CD `Application`, is switched by `spec.features.identity`, and does not
go through the namespace-scoped feature gate.

## Configuration: one singleton, hot-reloaded

`KubeConfigStore` (`runtime/src/config_store.rs`) watches the `WeeboSiConfig` named `cluster` and
every `WeeboSiTeam`. On each event it resolves the features' configs and publishes them into
`Arc<RwLock<Option<Resolved…>>>` handles each feature was built with. It implements
`FeatureGate`: the mode a feature runs in for a namespace, after `namespaceSelector` and teams.

Consequences worth knowing:

- A config change takes effect on the next admission or the next reconcile. No restart.
- No singleton, or a singleton with no `features`, means every feature is `Off`. Deleting it
  stops the features; it does not undo what they wrote.
- Teams are chassis-level: one ordered list, shared by every feature, first match wins.
- A namespace the watch has not seen yet: admission fails closed if a feature that needs its facts
  is on (`FeatureGate::mode_for_admission`), and a controller treats it as out of scope.

`KubeNsStore` is the other shared cache: each namespace's labels and its selection annotation
(`NamespaceFacts`), used for team routing.

## An admission request, end to end

```text
kube-apiserver ──AdmissionReview──▶ axum (webhook_cmd.rs, TLS :9443)
                                     │ route by path
                                     ▼
                         weebo-si-<feature>-adapters (or weebo-si-webhook/router.rs)
                           extract.rs: object → Subject (never logs the object)
                                     │
                                     ▼
                     weebo_si_chassis::admit(registry, subject, gate, ns_view, catalog, observer)
                       for each feature, in registry order:
                         mode = gate.mode_for_admission(id, ns)   ── Off → skip
                         decision = feature.evaluate(subject, ctx)
                         observer.decided(...)                    ── always, DryRun included
                         Enforce + denial → Deny ; Enforce → keep mutations ; DryRun → discard
                                     │
                                     ▼
                     render.rs: Vec<Mutation> → RFC 6902 JSON Patch ── AdmissionResponse
```

The routes and the webhook configurations that point at them
(`charts/weebo-si-operator/templates/`):

| Path | Kind | Configuration | Feature |
| --- | --- | --- | --- |
| `/mutate/v1alpha1/devworkspaces` | mutating | `…-devworkspaces` | `dwoc-pin`, then the `network-profiles` workspace gate |
| `/validate/v1alpha1/devworkspaces` | validating | `…-devworkspaces-validate` | `image-policy` (workspace layer) |
| `/validate/v1/pods` | validating | `…-pods` | `image-policy` (pod floor) |
| `/validate/v1/networkpolicies` | validating | `…-policies` | `policy-guard` |
| `/validate/v1/kubearmorpolicies` | validating | `…-kubearmor-policies` | `policy-guard` (RFC 0008) |
| `/validate/v1/registryconfigs` | validating | `…-registry-configs` | `policy-guard`'s registry rule (RFC 0007) |
| `/mutate/v1/ingresses`, `/mutate/v1/routes` | mutating | `…-endpoints` | `endpoint-auth` |
| `/validate/v1/ingresses` or `/validate/v1/routes` | validating | `…-endpoints` | `endpoint-auth` guard (by dialect) |

Every rule skips namespaces carrying `namespaceExclusionLabel` (`hardening.weebo.io/exclude` by
default) — the operator's own included. The DevWorkspace rules are `failurePolicy: Fail`, fixed;
the pod floor, `policy-guard`, the registry rule and `endpoint-auth` each take theirs from a chart
value (`imagePolicy.podWebhook.failurePolicy`, `policyGuard.failurePolicy`,
`registryConfig.failurePolicy`, `endpointAuth.failurePolicy`). Deleting a configuration is the
break-glass for its feature.

Two features take different subjects on the same request — `dwoc-pin`'s `Workspace` and the
network gate's `WorkspaceAdmission` — so `/mutate/v1alpha1/devworkspaces` runs two registries one
after the other rather than one (`webhook/src/router.rs`, `AppState`).

## A reconcile, end to end

```text
kube watch (Namespace, DevWorkspace, Ingress, …) ──▶ kube::runtime::Controller
                                                      (weebo-si-<feature>-adapters/controller.rs)
                                                      │ is_leader? no → requeue, do nothing
                                                      ▼
                          weebo_si_<feature>::application::reconcile
                            mode = gate.mode(id, ns)                ── Off → teardown(): delete what we own
                            desired = feature.desired(subject, ctx)
                            live    = store.list(owned by us, in this subject's scope)
                            diff    = chassis::managed::compute_owned_diff(desired, live)
                            Enforce → apply diff ; DryRun → report diff only
                                                      │
                                                      ▼
                          metrics (<feature>-adapters/*_metrics.rs) and status
```

- **`Off` is a rollback.** A feature the config deliberately sets to `Off` gets its objects
  deleted by the loop's `teardown()`; a gate answering `Off` because a cache is still cold does
  not (`network-profiles/src/application.rs`).
- **Ownership.** Every written object carries the `hardening.weebo.io/managed-by` label; the diff only ever sees objects
  in its own subject's scope (`OwnedScope`), so two features writing into the same namespace cannot
  delete each other's objects (`chassis/src/managed/scope.rs`).
- **Protection.** `policy-guard` refuses any write to those objects except from the controller's
  own identity (`--operator-identity`), the namespace controller and the garbage collector on
  `DELETE` (`chassis/src/teardown.rs`).
- **Leader election.** `--leader-election` takes the `Lease` `weebo-si-controller-leader` through
  `weebo-kit-runtime::leader` (15 s TTL, released on shutdown). A standby replica syncs its caches,
  reports ready, and waits for the lease before starting any loop; the leader exits with code `1`
  the moment it may have lost the lease. One lease covers every loop
  (`operator/src/controller_cmd.rs`).
- **Optional watches.** A loop whose RBAC the chart did not grant is not started:
  `runtime/src/access.rs` asks a `SelfSubjectAccessReview` first, so a disabled feature never
  crash-loops the controller on a forbidden watch.
- **Errors** go through `controller/src/events.rs::retry`: a `Warning` Event on the object
  (`reason` from `ReasonCode`), and a retry backing off 30 s → 5 min per object, reset by the next
  pass that succeeds (`events::tracked`).

## Observability

Logs go through `tracing`, set up by `weebo-kit-runtime::telemetry` in both roles (`LOG_FORMAT=json`,
`RUST_LOG`, OTLP traces with `OTEL_EXPORTER_OTLP_ENDPOINT`): one line per decision, never the
admitted object (`webhook/src/router.rs::log_admission` takes no parameter the object could pass
through). The admin subcommands log to stderr instead, so their stdout stays their output.

Every watch-backed store drives its stream through `runtime/src/watch.rs`, which logs each watch
error and reports it to the process's `Health`: a watch that keeps failing for 5 minutes fails
`/livez`, and the kubelet restarts the pod.

Metrics are Prometheus, registered per feature in `weebo-si-runtime` and `weebo-si-webhook`; the
contract is each brick page's *Observability* section. Events: see *A reconcile, end to end*.

## Adding a feature

1. `weebo-si-crd`: its config type under `spec.features`, its `Resolved*` form, its team fields,
   and its handle in `KubeConfigStore` (`weebo-si-runtime`).
2. `weebo-si-<feature>`: the subject, the `Feature`/`ReconcileFeature` impl, its ports.
3. `weebo-si-<feature>-adapters`: the stores behind its ports, its metrics, its routes and/or
   loops, and `admission_routes` / `controller_deps`.
4. `weebo-si-operator`: one line per role in `webhook_cmd.rs`/`controller_cmd.rs`, and its line
   in `features.rs`.
5. `charts/weebo-si-operator`: its webhook configuration and RBAC.

Plus a RFC, a brick page and its section in [`weebosiconfig.md`](../weebosiconfig.md). No shared
crate gains a file for it: that was the point of
[RFC 0012](../rfc/0012-operator-kit-migration.md).
