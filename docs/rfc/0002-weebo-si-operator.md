---
rfc: 0002
title: weebo-si-operator
status: Proposed
authors: [batleforc]
created: 2026-08-23
updated: 2026-08-23
decided:
brick: crates/weebo-si-operator
supersedes: []
superseded-by: []
---

# RFC 0002 — weebo-si-operator

## Summary

`weebo-si-operator` is the Kubernetes component of `weebo-si-hardening`: one binary, two
deployed roles — an admission webhook server and a controller — and a registry of **runtime
feature-flagged** hardening features. Nothing it does is on by default; every feature is named,
gated by a cluster-scoped `WeeboSiConfig` CRD, and runs in one of three modes: `Off`, `DryRun`,
`Enforce`.

This RFC defines the chassis — the CRD, the flag semantics, the webhook wiring, the hexagonal
layout, the RBAC — and ships exactly **one** feature through it: `dwoc-pin`, a mutating webhook
that pins every DevWorkspace to the platform's mandated DevWorkspaceOperatorConfig, so a
workspace cannot steer itself onto a configuration that weakens the baseline. The controller
role and the follow-up features are **scaffolded, not implemented**: the registry, the reconcile
loop and the CRD have room for them, so that adding one is a module plus a schema field rather
than a re-architecture.

## Motivation

DevWorkspace Operator resolves the configuration for a workspace from two places. There is a
global `DevWorkspaceOperatorConfig` (DWOC) named `devworkspace-operator-config` in its install
namespace, and a DevWorkspace may name a second one through the
`controller.devfile.io/devworkspace-config` attribute, giving a `{name, namespace}` pair. The
referenced config is merged **over** the global one, field by field.

That merge direction is the problem. Everything the platform mandates in the global config — the
pod and container security context, `hostUsers`, the storage class, the init containers, the
image pull policy — is a default that any DevWorkspace can override by pointing at a DWOC it
wrote itself, in its own namespace:

```yaml
apiVersion: controller.devfile.io/v1alpha1
kind: DevWorkspace
spec:
  template:
    attributes:
      controller.devfile.io/devworkspace-config:
        name: my-config           # in the user's own namespace
        namespace: user-alice     # written by the user, wins over the global config
```

Concretely, a workspace owner who can create a DevWorkspace and a DWOC in their own namespace —
which is what a Che user is — can hand themselves a different `containerSecurityContext`, drop
the platform's init containers, or change the storage class the platform pays for. Nothing in
DevWorkspace Operator treats the global config as a floor. It is a default, and defaults lose.

There is no RBAC answer. RBAC grants verbs on resources, not on fields: "may create a
DevWorkspace but may not set one attribute inside it" is not expressible. The workspace has to
be inspected as it is written, which is an admission-time decision.

### What exists today

Nothing, on the cluster side. Two partial answers a Che admin has instead:

- **Put everything in the global DWOC and hope.** This is the current state. It works until
  someone reads the DevWorkspace Operator documentation, which describes the external config
  attribute as a supported feature rather than as a hole.
- **A hand-written Kyverno or Gatekeeper policy.** Genuinely workable for this one rule, and
  discussed under *Alternatives considered*. It stops scaling at the second and third features.

The same shape of problem is already queued behind this one. The [readme](../../readme.md) names
three targets for this brick — restrict which images may run, check which DevWorkspaceOperator
config is in use, inject configuration into targeted pods. Each is an admission-time decision
over someone else's workload, each needs a rollout that does not take Che down on the day it
lands, and each needs to be switchable off in seconds when it turns out to be wrong.

**Outcome we are buying:** a cluster admin installs one operator, writes one cluster-scoped
resource, and the DWOC the platform mandates becomes the one every workspace actually runs with
— with an allow-list for the workspaces genuinely entitled to something else. The same resource
turns any individual hardening behaviour from "measuring only" to "enforcing" to "off" without a
rebuild, without a rollout, and scoped to a namespace label while confidence is being gained.

## Guide-level explanation

An admin installs the CRD, the operator and its webhook configuration, then writes the singleton
config. Every feature starts `Off`, so installing the operator changes nothing:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features: {}
```

Turning the first feature on is a two-step move, and the first step mutates nothing:

```yaml
spec:
  features:
    dwocPin:
      mode: DryRun
      target:
        name: weebo-hardened-config
        namespace: eclipse-che
```

In `DryRun` the webhook does all the work and throws the answer away. It logs the decision and
counts it, so an admin sees what would have happened across the cluster before it happens:

```text
INFO  feature=dwoc-pin mode=DryRun ns=user-alice devworkspace=python-web
      current=user-alice/my-config target=eclipse-che/weebo-hardened-config
      decision=replace
INFO  feature=dwoc-pin mode=DryRun ns=user-bob devworkspace=java-api
      current=<none> target=eclipse-che/weebo-hardened-config decision=add
```

```console
$ kubectl get weebosiconfig cluster -o jsonpath='{.status.features}'
[{"name":"dwocPin","state":"DryRun","observedGeneration":2,
  "message":"evaluated 214 workspaces: 6 would be replaced, 208 would be pinned"}]
```

Then it enforces, narrowed to one namespace first:

```yaml
spec:
  features:
    dwocPin:
      mode: Enforce
      target:
        name: weebo-hardened-config
        namespace: eclipse-che
      allowedOverrides:
        - name: gpu-config
          namespace: eclipse-che
      namespaceSelector:
        matchLabels:
          hardening.weebo.io/pilot: "true"
```

A DevWorkspace created in a pilot namespace comes out pinned, whatever it asked for:

```yaml
metadata:
  name: python-web
  namespace: user-alice
  annotations:
    hardening.weebo.io/dwoc-pin: "replaced:user-alice/my-config"
spec:
  template:
    attributes:
      controller.devfile.io/devworkspace-config:
        name: weebo-hardened-config
        namespace: eclipse-che
```

The annotation is the audit trail: it records what the workspace asked for, so "my storage class
changed" has an answer that is one `kubectl get` away rather than a webhook log search.

A workspace naming something on the allow-list is left alone, and says so:

```text
INFO  feature=dwoc-pin mode=Enforce ns=user-carol devworkspace=cuda-train
      current=eclipse-che/gpu-config decision=allowed-override
```

Widening the rollout is deleting the `namespaceSelector`. Turning it off is `mode: Off` — one
write, no rollout, effective on the next admission. Turning **everything** off is deleting the
`MutatingWebhookConfiguration`, which is the break-glass and is documented as such, because this
webhook is `failurePolicy: Fail`.

## Design

### Contract

Four surfaces bind to this brick: the CRD, the webhook configuration, the binary's CLI, and the
metric, annotation and log names. All four are covered by *Stability* at the end of this section.

**Terminology.** A **feature** is one named hardening behaviour with its own flag. The
**chassis** is everything in this RFC that is not a feature: the CRD, the gate, the servers, the
registry. A **feature identifier** has two spellings, mechanically derived from each other:
kebab-case (`dwoc-pin`) in logs, metrics, annotations and the CLI, camelCase (`dwocPin`) as the
CRD field name, because that is the Kubernetes API convention. There is no third spelling.

#### The `WeeboSiConfig` CRD

- Group and version: `hardening.weebo.io/v1alpha1` — see *Unresolved questions* on the group.
- Kind: `WeeboSiConfig`, **cluster-scoped**, singleton named `cluster`. Any other name is
  ignored, and reported as a `Degraded` condition on the object so the mistake is visible.
- The schema is **generated** from the Rust types by `task recu`, the same way the RFC index is.
  Adding a feature therefore updates the CRD in the same commit as the code, and a feature the
  binary does not know about cannot be written into the resource at all — the apiserver rejects
  it. That is deliberate, and it is the reason the schema is typed rather than a
  `x-kubernetes-preserve-unknown-fields` map.

```yaml
spec:
  features:
    <featureName>:                   # one optional field per registered feature, typed
      mode: Off | DryRun | Enforce      # required; there is no implicit default in the resource
      namespaceSelector: {}             # optional metav1.LabelSelector, narrows within the webhook's own scope
      <feature-specific fields>
status:
  observedGeneration: 0
  features:
    - name: <featureName>
      state: Disabled | DryRun | Active | Degraded
      message: <human text>
      observedGeneration: 0
  conditions: []                     # standard metav1.Condition list: Ready, Degraded
```

**Modes, and why three rather than a boolean.**

| Mode | The feature runs | The result is applied | Counted and logged |
| --- | --- | --- | --- |
| `Off` | no | no | no |
| `DryRun` | yes | no | yes |
| `Enforce` | yes | yes | yes |

A mutating webhook that has never run against real traffic is a guess. `DryRun` is how it stops
being one, and it is why the flag is not a boolean — for `dwoc-pin` specifically it is the only
way to find out how many workspaces are relying on an override before taking overrides away. The
load-bearing invariant, stated once here and enforced in *Architecture*: **a feature never learns
its own mode.** The mode is applied at the edge — `DryRun` runs the identical code path as
`Enforce` and discards the mutations. A feature that could branch on its mode would make the
shadow phase measure something other than what enforcement does, which is the only thing the
shadow phase is for.

**A feature absent from `spec.features` is `Off`.** Not "default on", not "inherit". A behaviour
nobody wrote down does not run.

**Selector layering.** The `MutatingWebhookConfiguration` decides which objects reach the
process at all; `spec.features.<name>.namespaceSelector` decides which of those a given feature
acts on. Two levels, because one webhook endpoint serves every feature for a resource (see
below) and the features do not share a rollout schedule. The in-process selector can only
narrow, never widen: a namespace the webhook configuration excludes is invisible here.

#### Webhook configuration

One endpoint per resource and verb, **not** one per feature. N webhook entries means N serial
admission round trips per object, N `clientConfig` blocks and N certificates; the features
multiplex behind a single entry instead.

```text
POST /mutate/v1alpha1/devworkspaces     # every mutating feature registered for DevWorkspace
POST /validate/v1alpha1/devworkspaces   # reserved, no feature registered yet
POST /mutate/v1/pods                    # reserved, no feature registered yet
```

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: weebo-si-hardening-devworkspaces
  annotations:
    service.beta.openshift.io/inject-cabundle: "true"
webhooks:
  - name: devworkspaces.hardening.weebo.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    matchPolicy: Equivalent
    failurePolicy: Fail
    timeoutSeconds: 5
    reinvocationPolicy: IfNeeded
    rules:
      - operations: ["CREATE", "UPDATE"]
        apiGroups: ["controller.devfile.io"]
        apiVersions: ["v1alpha1"]
        resources: ["devworkspaces"]
        scope: Namespaced
    namespaceSelector:
      matchExpressions:
        - key: hardening.weebo.io/exclude
          operator: DoesNotExist
    clientConfig:
      service:
        name: weebo-si-operator-webhook
        namespace: weebo-si-hardening
        path: /mutate/v1alpha1/devworkspaces
        port: 443
```

Every non-obvious value on that object is a decision:

- **`operations: ["CREATE", "UPDATE"]`.** `CREATE` alone would be a one-line bypass: create a
  compliant workspace, then `kubectl patch` the attribute in. The rule matches `devworkspaces`
  and **not** `devworkspaces/status`, so DevWorkspace Operator's own status writes — by far the
  highest-volume traffic on this type — never reach the webhook. What does reach it is the
  `spec.started` toggle on every workspace start and stop, which is exactly the moment we want to
  re-check anyway.
- **No `objectSelector`.** Every DevWorkspace is in scope. There is no label that distinguishes
  the ones worth checking, and a workspace that removed such a label would be the bypass.
- **`namespaceSelector` as an opt-*out*.** An opt-in label would mean a new workspace namespace
  is unprotected until someone remembers to label it, and Che creates those namespaces
  automatically. Opt-out fails toward hardened. Per-feature rollout scoping is the CRD's
  `namespaceSelector`, which is opt-in — the two selectors have opposite polarity on purpose.
- **`timeoutSeconds: 5`**, not the default `10`. Everything the handler needs is in a warm
  in-process cache; five seconds is already an outlier.
- **`reinvocationPolicy: IfNeeded`.** DevWorkspace Operator runs its own mutating webhook over
  the same objects, and a later webhook rewriting `spec.template.attributes` would drop our
  patch. Reinvocation costs nothing here because **the patch is idempotent**: a workspace already
  carrying the mandated reference produces an empty patch. This is the same single-shot property
  [RFC 0001](./0001-passwd-append.md) argues for the binary, for the same reason and at a
  different layer.
- **`sideEffects: None`.** The handler writes nothing outside the admission response — no API
  call, no file. This is what makes `kubectl apply --dry-run=server` safe against us.
- **`failurePolicy: Fail`.** Argued in *Operational considerations*, and it is the decision most
  worth reading in this RFC.

**Certificates.** The operator never generates, stores or rotates a private key. It reads a
serving certificate from a mounted Secret, and the CA bundle is injected into the webhook
configuration by the platform: `service.beta.openshift.io/serving-cert-secret-name` plus
`service.beta.openshift.io/inject-cabundle` on OpenShift, cert-manager's
`cert-manager.io/inject-ca-from` elsewhere. One of the two is a **prerequisite**; there is no
self-signed fallback in this RFC.

#### Feature: `dwoc-pin`

The only feature implemented here. It makes the platform's DWOC a floor rather than a default.

**Configuration**

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis |
| `target` | `{name, namespace}` | — | required. The mandated DWOC every workspace is pinned to. |
| `allowedOverrides` | list of `{name, namespace}` | empty | References a workspace may keep instead of the target. Empty means no override is permitted. |
| `onMissingTarget` | `Skip` \| `Deny` | `Skip` | What to do when `target` does not resolve. |

**Behaviour.** Read `spec.template.attributes["controller.devfile.io/devworkspace-config"]` from
the incoming DevWorkspace, then:

| Current reference | Decision | Patch |
| --- | --- | --- |
| absent | `add` | set the attribute to `target` |
| equal to `target` | `already-pinned` | none |
| in `allowedOverrides` | `allowed-override` | none |
| anything else | `replace` | set the attribute to `target` |

On `add` and `replace`, the annotation `hardening.weebo.io/dwoc-pin` is set to
`added` or `replaced:<namespace>/<name>` — the value the workspace asked for. That annotation is
the whole audit story for this feature, and it is why the decision is a mutation rather than a
silent rewrite.

**Validating the target.** Before pinning anything, the feature checks that `target` resolves to
a `DevWorkspaceOperatorConfig` in the watch-backed cache. Pinning to a dangling reference is
worse than not pinning: DevWorkspace Operator would fail to resolve the config for every
workspace in the cluster at once. When the target is missing:

- `onMissingTarget: Skip` (default) — the feature makes no patch, the workspace proceeds with
  whatever it asked for, and the CRD gets a `Degraded` condition plus a
  `weebo_si_dwoc_pin_total{result="target_missing"}` increment.
- `onMissingTarget: Deny` — the admission response denies the request with a message naming the
  missing target. For clusters where an unpinned workspace is not acceptable even briefly.

This is the fail-open/fail-closed knob **inside** the feature, and it is separate from the
webhook's `failurePolicy`, which covers the case where the operator cannot answer at all.

**Where the mandated DWOC lives is a deployment requirement, not a detail.** `target` must sit in
a namespace workspace owners cannot write to — the Che namespace, or the operator's own. A
mandated config in a namespace the user can edit is a control that hands the user the thing it
was protecting. This is stated again, with the reasoning, under *Security considerations*.

**Ordering.** Features registered for the same endpoint run in registry declaration order, each
seeing the object as the previous one left it. The order is stable and part of the contract. With
one feature it is trivially satisfied; it is written down now because it is much harder to
introduce later.

#### CLI

```text
weebo-si-operator webhook     [--addr 0.0.0.0:9443] [--cert-dir /etc/webhook/certs]
                              [--metrics-addr :8080] [--health-addr :8081] [--config-name cluster]
weebo-si-operator controller  [--metrics-addr :8080] [--health-addr :8081] [--leader-election]
weebo-si-operator crd         # print the generated CRD YAML — what `task recu` writes
weebo-si-operator features    # print the registry: id, originating RFC, target resource, mode
```

Two roles, one binary, two Deployments in production: the webhook is latency-critical and
horizontally scaled, the controller writes status and wants a single leader. `features` exists so
that "what does this build actually contain" is answerable from the image rather than from the
source tree.

| Code | Meaning |
| --- | --- |
| `0` | clean shutdown |
| `1` | internal error (cache subscription lost, listener cannot bind, certificate unreadable) |
| `2` | usage error |
| `3` | caches never synced within the readiness deadline |

#### Observability contract

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_admission_requests_total` | counter | `feature`, `resource`, `mode`, `outcome` ∈ `patched`/`unchanged`/`dry_run`/`denied`/`error` |
| `weebo_si_admission_duration_seconds` | histogram | `feature`, `resource` |
| `weebo_si_feature_mode` | gauge | `feature` — `0`/`1`/`2` for `Off`/`DryRun`/`Enforce` |
| `weebo_si_dwoc_pin_total` | counter | `result` ∈ `added`/`replaced`/`already_pinned`/`allowed_override`/`target_missing` |
| `weebo_si_config_observed_generation` | gauge | — |

`/healthz` is liveness and answers as soon as the process serves. `/readyz` answers only once
every watch cache is synced, so a pod that cannot see the CRD or the DWOCs receives no admission
traffic instead of deciding `target_missing` on everything.

**Stability.** The CRD group, version, kind, and field names; the feature identifiers; the webhook
paths; the annotation keys and their value grammar; the metric names and label values; and the
exit codes are the contract. Changing any of them needs a new RFC, per
[the RFC process](./readme.md#when-is-an-rfc-required).

### Architecture

**Hexagonal, and it is the case the layout was written for.** Measured against the three criteria
in [`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. *A real decision.* Four outcomes from a current reference, an allow-list, a target that may
   not exist, a per-namespace selector and a three-state mode. Every one of those is a branch a
   user can get wrong.
2. *Touches an external system.* The Kubernetes API, two resource types, plus the admission path
   itself.
3. *We want the decision tested without it.* The decision table above is exactly the thing that
   must be exhaustively tested, and it must not need a cluster or a pile of `AdmissionReview`
   fixtures to do so.

All three hold, which is the opposite of [RFC 0001](./0001-passwd-append.md)'s answer to the same
question.

```text
crates/weebo-si-operator/src/
├── lib.rs
├── main.rs                        # composition root — the only place naming concrete adapters
├── domain/
│   ├── model/
│   │   ├── feature.rs             # FeatureId, FeatureMode, FeatureOutcome
│   │   ├── mutation.rs            # Mutation — typed. No JSON, no serde_json::Value.
│   │   ├── workspace.rs           # the DevWorkspace in domain vocabulary: name, namespace, config_ref
│   │   └── dwoc.rs                # DwocRef, and the bounded view of a DWOC we read
│   ├── feature/
│   │   ├── mod.rs                 # the Feature trait and the registry
│   │   └── dwoc_pin.rs            # the one implemented feature   <- where the tests are
│   ├── error.rs                   # DomainError. Never kube::Error, never a HTTP status.
│   └── port/
│       ├── feature_gate.rs        # which features are active, in which mode, for which namespace
│       ├── dwoc_catalog.rs        # does this DWOC reference resolve
│       └── observer.rs            # counters and decision events
├── application/
│   ├── admit.rs                   # run the enabled features over one object, apply the mode
│   └── reconcile_config.rs        # validate WeeboSiConfig, compute its status
└── adapters/
    ├── inbound/
    │   ├── admission.rs           # axum: AdmissionReview -> domain -> JSON Patch -> AdmissionResponse
    │   ├── controller.rs          # kube-runtime reconcile loops
    │   └── cli.rs
    └── outbound/
        ├── kube_config_store.rs   # watch-backed WeeboSiConfig cache, implements FeatureGate
        ├── kube_dwoc_store.rs     # watch-backed DWOC cache, implements DwocCatalog
        └── prometheus.rs          # implements Observer
```

**The ports, in domain vocabulary.**

```rust
// domain/port/feature_gate.rs
pub trait FeatureGate {
    fn mode(&self, feature: FeatureId, namespace: &NamespaceName) -> FeatureMode;
}

// domain/port/dwoc_catalog.rs
pub trait DwocCatalog {
    fn resolves(&self, r: &DwocRef) -> bool;
}

// domain/port/observer.rs
pub trait Observer {
    fn decided(&self, feature: FeatureId, outcome: &FeatureOutcome);
}
```

Each is named for what the application needs. `DwocCatalog::resolves` says "is this a real
config" — the watch, the cache and the informer are the adapter's problem, and the fake is a
`HashSet`.

**The feature trait, and the invariant.**

```rust
pub trait Feature<S: Subject> {
    fn id(&self) -> FeatureId;
    fn evaluate(&self, subject: &S, ctx: &Context<'_>)
        -> Result<Decision<S>, DomainError>;
}
```

The trait is generic over the admitted resource, so `Feature<Workspace>` and the future
`Feature<Pod>` are distinct instantiations with distinct registries — which is the type-level
version of the "one endpoint per resource" rule, and the reason a feature cannot accidentally be
registered against a resource it does not understand.

`evaluate` takes no mode and returns no JSON. `application::admit` reads the mode from the gate,
calls `evaluate` for every feature whose mode is not `Off`, and then — and only then — either
renders the decision to a JSON Patch or throws it away and records it. **A feature cannot tell
`DryRun` from `Enforce`, by construction.** This is what makes the shadow phase meaningful, and
it is the reason the trait signature is worth pinning in a RFC.

`Decision` carries a `Vec<Mutation>` and an optional denial reason; `Mutation` is a small typed
enum (`SetConfigRef`, `Annotate`) rather than a patch fragment. Rendering it to RFC 6902 JSON
Patch is `adapters/inbound/admission.rs`'s job, per the dependency rule: the domain does not
import `k8s-openapi` and does not know what a JSON Pointer is.

**What is scaffolded but not implemented.** `adapters/inbound/controller.rs` ships with one
reconcile loop — `WeeboSiConfig` → validate → status — and no other. `domain/feature/mod.rs`
ships a registry with one entry, and `Feature<Pod>` has a registry with none. The named
follow-ups in *Future work* are registry entries and `domain/feature/*.rs` modules that do not
exist yet; the point of building the chassis now is that landing them touches no file outside
`domain/feature/`, the generated CRD, and one line in the registry.

**Enforcement of the dependency rule** is by review, per `hexagonal.md`. The escape hatch, when
`domain` starts importing adapter types, is promoting it to its own crate. Not preemptively.

### Data and state

**Effectively stateless.** Three things exist at runtime and none of them is authoritative:

- **Watch-backed caches** of `WeeboSiConfig` and `DevWorkspaceOperatorConfig`, in memory. Lost on
  restart and rebuilt by a relist; `/readyz` stays false until they are synced, so a cold pod
  takes no traffic rather than deciding on stale data. Both are small — one singleton and a
  handful of configs — which is why the target-existence check is affordable on every admission.
  Note what is **not** cached: DevWorkspaces. The object under admission arrives in the request,
  so the feature needs no view of the workspace population at all.
- **`WeeboSiConfig.status`**, written by the controller. Entirely derived from `spec` and the
  registry: deleting it costs one reconcile.
- **The pinned workspaces themselves**, which are not our state — they belong to the apiserver,
  and the attribute plus the annotation are the only things we wrote.

Nothing is persisted to disk. There is no PVC, no cache directory, no leader-elected state beyond
the lease itself. The webhook role runs without leader election on purpose: every replica must be
able to answer, and every replica computes the same answer from the same watch.

There is nothing to migrate and nothing to back up. The undo for every piece of state here is
"delete it and let it be recomputed".

## Security considerations

**Privileges.** The webhook role needs, cluster-wide:

| Verb | Resource |
| --- | --- |
| `get`, `list`, `watch` | `hardening.weebo.io/weebosiconfigs` |
| `get`, `list`, `watch` | `controller.devfile.io/devworkspaceoperatorconfigs` |

and the controller role adds `update` and `patch` on `weebosiconfigs/status`, plus `create` on
`events`. That is the whole list. Two read-only watches.

**It has no permission on DevWorkspaces at all — not even read.** A mutating webhook receives the
object in the request and returns a patch to the apiserver; it neither reads nor writes the
resource it governs. This is worth stating because the obvious mental model — "the operator edits
workspaces" — implies an RBAC grant that would be a far larger blast radius than what is actually
requested. It also has no `escalate`, no `bind`, no `impersonate`, and no access to Secrets other
than its own mounted serving certificate.

**The privilege it does hold** is `spec.features.dwocPin.target`: one field naming the
configuration every workspace in the cluster will run with. Whoever writes that field sets the
pod and container security context, the init containers, the storage class and the image pull
policy for the entire fleet, indirectly. It is the most powerful field in this design. Two things
bound it, both deliberate:

- The CRD is **cluster-scoped**. Writing it is a cluster-admin action; a namespace admin cannot
  reach it, which is the entire reason the flags are not per-namespace resources.
- The target must resolve before anything is pinned, so a typo degrades to "no pinning" rather
  than to "every workspace references a config that does not exist".

**The mandated DWOC must live where users cannot write it.** This is the one deployment
requirement that is a security control rather than a convenience. Pinning every workspace to
`user-alice/hardened-config` would let user Alice edit the configuration the whole cluster is
pinned to — the control would be handing the attacker the object it protects. The target belongs
in the Che namespace or the operator's own, and RBAC there is the thing that makes this feature
mean anything. The operator does not and cannot verify this; it is on the install checklist.

**Trust boundary.** The `AdmissionReview` body is the only untrusted input, and any user who can
create a DevWorkspace controls it. Handled as untrusted: the handler parses into typed
structures, touches a bounded set of fields, and returns an error response rather than panicking
on anything unexpected — which is what the workspace lint table (`panic = "deny"`,
`unwrap_used = "deny"`) exists to make hard to get wrong in the admission path specifically.

Worth noting what the feature deliberately **does not** do: it never reads the user's DWOC. An
earlier draft of this RFC had the webhook resolve the effective configuration — global merged
with the user's — and act on its contents, which made a user-authored object part of our input.
Overwriting the reference instead of reading what it points at removes that surface entirely.
The only user-controlled value that reaches a decision is the reference itself, and it is
compared against an admin-authored allow-list, never dereferenced.

**Bypass.**

- **The namespace exclusion label.** Anyone able to label a namespace `hardening.weebo.io/exclude`
  opts it out wholesale. In a Che cluster namespace labels are an admin-level operation; if that
  ever stops being true, this label is the first thing to revisit.
- **Workspaces created before installation.** They keep whatever reference they have until
  something updates them — and `spec.started` toggles on every start and stop, so in practice a
  workspace is pinned the first time it is used. Workspaces that are never restarted stay
  unpinned; the drift reconciler in *Future work* is what closes that properly.
- **Not going through DevWorkspace at all.** A user who can create raw pods in their namespace is
  untouched by this feature. This control governs the DevWorkspace path, and only that path. It
  is not a substitute for PSA or an SCC, and nothing here should be read as one.
- **Editing the target DWOC.** Covered above: the entire control collapses to the RBAC on the
  target's namespace.
- **Making the webhook unavailable.** Closed by `failurePolicy: Fail` — which is the trade
  discussed at length in *Operational considerations*, and the reason the fail-open default from
  the pod-oriented draft of this RFC did not survive contact with a feature that is actually a
  control.

**Blast radius.** A wrong `target` misconfigures every workspace in the cluster on its next
start, and at `failurePolicy: Fail` an operator outage stops workspaces from being created or
started. Those are the two numbers. They are bounded by `DryRun`, by the per-feature
`namespaceSelector` during rollout, by the target-existence check, and by the break-glass in
*Rollback*. A compromise of the operator is worse than either: it is the ability to pin every
workspace to an attacker-chosen configuration, which is the ability to set a security context
fleet-wide. Nothing in this design reduces that below "do not let this deployment be
compromised"; what it does is keep the reachable surface small — two read-only watches, no writes
on the governed resource, no Secret access, no outbound network.

**Secrets.** It reads none. Its serving certificate arrives as a mounted Secret it never logs and
never writes. Logs carry the namespace, the workspace name, the current and target references and
the decision — **never the object**, because a DevWorkspace template carries the user's
environment variables and can carry a token. That is a rule about the logging call sites, not a
property of the design, so it is on the implementation checklist as its own item.

## Operational considerations

**Failure mode: `failurePolicy: Fail`, fail-closed.** Both sides, because this reverses the
instinct:

*For `Ignore`.* A webhook in the admission path of a core workflow is a new way for that workflow
to break. At `Fail`, an operator that is unavailable — crash-looping on a bad config, mid-upgrade,
or unschedulable because its node drained — means no DevWorkspace can be created or started
cluster-wide. That is a Che outage caused by a hardening component.

*For `Fail`.* This feature is a control, not a shim. At `Ignore` the bypass is a single sentence:
make the webhook unavailable, then create a workspace with your own configuration. A control
whose bypass is "cause an error" is not a control, and shipping it as one would be worse than
shipping nothing, because it would be believed.

*The decision.* `Fail`, with the cost paid down rather than argued away: two replicas across
nodes, a `PodDisruptionBudget`, `timeoutSeconds: 5`, and an admission path that makes no API call
so it cannot be slowed by apiserver load. The blast radius is also narrower than it first looks —
the rule matches `devworkspaces` only, so an outage stops workspace creation and start/stop,
while every pod already running, and every other resource in the cluster, is untouched.

The rule this sets for the chassis: **`failurePolicy` follows the feature, not the operator.** A
future usability shim over pods — the kind of thing [RFC 0001](./0001-passwd-append.md) describes
itself as — belongs at `Ignore`, and since one `MutatingWebhookConfiguration` carries one policy,
it gets its own configuration and its own endpoint. That is why the endpoint path carries the
resource rather than the feature: splitting a configuration later is a new object, not a re-route.

**Rollout.** Four steps, each independently reversible:

1. Install the CRD, the operator and the webhook configuration with `spec.features: {}`. Nothing
   is changed beyond a no-op round trip on DevWorkspace writes; watch
   `weebo_si_admission_duration_seconds` to see the cost of that round trip alone. This is also
   the step that proves the `Fail` policy is survivable before any feature depends on it.
2. `mode: DryRun`. Read `weebo_si_dwoc_pin_total` and the decision logs. The number that matters
   is `result="replaced"` — every one of those is a workspace that will change behaviour, and
   `DryRun` is the only chance to look at them before they do.
3. `mode: Enforce` with a `namespaceSelector` on a pilot label. One namespace, real pins.
4. Remove the selector.

Steps 2 through 4 are writes to one resource, effective on the next admission, with no rollout.

**Rollback.** Three levels, in increasing order of bluntness:

- `mode: Off` — seconds, no restart. The webhook still answers, and answers with an empty patch.
- **Delete the `MutatingWebhookConfiguration`** — the break-glass, and the one that matters at
  `failurePolicy: Fail`, because it is the only lever that works when the operator itself is the
  thing that is broken. Every admin who installs this needs to know it exists; it belongs in the
  runbook, not in this paragraph alone.
- Uninstall.

**None of them un-pins a workspace.** The attribute and the annotation stay until something
rewrites them. That is deliberate — silently reverting a fleet's configuration on uninstall would
be a second uncontrolled change — but it means rollback restores the *policy*, not the *state*,
and the state is what the workspaces run with. Un-pinning is a `kubectl` loop over the annotated
workspaces, and it belongs in the runbook.

**Observability.** `weebo_si_admission_requests_total{outcome="error"}` is the first alert: at
`Fail`, a nonzero rate is user-visible failures, not a silent gap. `result="target_missing"` is
the second, because it means the feature is doing nothing while appearing to be `Active`. A
`Degraded` condition on the CRD means a feature's configuration was rejected at reconcile. From
the apiserver side, `apiserver_admission_webhook_admission_duration_seconds` and
`apiserver_admission_webhook_rejection_count` for `devworkspaces.hardening.weebo.io` are the
ground truth about what this webhook costs, and they belong on the dashboard next to ours,
because ours cannot report a request that never arrived.

**Upgrade.** Two replicas behind a PodDisruptionBudget, rolling, `maxUnavailable: 0` — at `Fail`
a moment with no ready endpoint is a moment when no workspace starts. Old and new pods serve the
same endpoint and compute independently from their own watches, so a mixed fleet is safe, and
where it would not be, idempotence makes a doubled invocation an empty patch. Within `v1alpha1`
the CRD only grows fields; removing or retyping one is a new version and a new RFC.

**Self-deadlock.** The operator is not a DevWorkspace and does not run in a workspace namespace,
so it cannot block its own creation. Its namespace also carries the exclusion label — redundant
by construction, kept because a mutating webhook that must run to allow its own pods is
unrecoverable without editing the webhook configuration by hand.

## Alternatives considered

**A validating webhook that rejects a non-compliant reference, instead of rewriting it.** The
honest contender, and it is more transparent: the user learns immediately, in the API error, that
the attribute is not theirs to set. Rejected as the default because the failure lands on someone
who mostly did not do anything wrong — a devfile copied from a colleague, or a Che-generated
workspace — and a rejected DevWorkspace is a workspace that does not exist, which is a support
ticket. Mutating with an annotation recording what was replaced keeps the workspace working and
keeps the change auditable. A validating companion for the cases where silent correction is not
acceptable is in *Future work*, and `onMissingTarget: Deny` is already the narrow version of it.

**Put everything in the global DWOC and pin nothing.** The current state, and free. Rejected for
the reason in *Motivation*: the merge direction makes the global config a default, so it is only
a floor for workspaces that do not care to override it. That is the definition of not a control.

**RBAC on the attribute.** The answer people reach for first. It does not exist: RBAC grants
verbs on resources, never on fields within them. There is no way to say "may create a
DevWorkspace, may not set this attribute" without admission control.

**Kyverno or Gatekeeper instead of a bespoke operator.** For `dwoc-pin` **alone** this probably
wins on cost — a Kyverno `ClusterPolicy` mutating one attribute is a dozen lines, and `Audit`
mode is `DryRun` by another name. Rejected on three grounds. First, the queued features do not
fit a policy DSL: image restriction needs registry resolution, and drift reconciliation needs a
controller. Second, "one operator we own" against "a policy engine plus the policies" is a
smaller thing to run and to reason about in an incident. Third, this repo has already committed
to a Rust operator in its readme, and splitting the hardening story across two enforcement
mechanisms is worse than either one alone. Worth revisiting if the second and third features
never get written.

**Cargo `[features]` instead of runtime flags.** Rejected outright, and this is the decision the
"feature flagged" requirement actually turns on. A build-time flag means the binary in the
cluster is not the binary that was tested, turning a feature off needs a rebuild and a rollout,
and `DryRun` cannot exist at all. Cargo features stay reserved for optional dependencies;
behaviour is never gated at compile time in this crate.

**A boolean `enabled` instead of three modes.** Rejected: with a boolean there is no way to
measure a mutating webhook before it mutates. Every operational argument in *Rollout* depends on
step 2 existing, and for this feature step 2 is how the fleet's existing overrides are
discovered.

**ConfigMap, or environment variables, for the flags.** A watched ConfigMap gets hot reload
without inventing a CRD, but no schema validation, no `status`, and no way for the apiserver to
reject a typo — a misspelled feature name is silently `Off`, which is the worst possible failure
for a security toggle. Environment variables additionally need a rollout per change, and at
`failurePolicy: Fail` a rollout of the webhook deployment is a window where workspaces do not
start. The CRD costs one more installed object and buys apiserver-side validation, a reportable
status, and `kubectl get weebosiconfig`.

**One Deployment and one webhook entry per feature.** Rejected: N serial admission round trips
per object, N certificates, N things to roll. The multiplexed endpoint costs a stable ordering
rule instead, which is one paragraph.

**A separate `weebo-si-webhook` crate.** Rejected: the two roles share the domain, the registry
and the config type. One crate, two subcommands, two Deployments — the split that matters is at
deploy time, not at compile time.

**Injecting the hardening into workspace pods instead** — the operator adding
[RFC 0001](./0001-passwd-append.md)'s binary and entrypoint to pods that never opted in. Dropped
from this RFC: the Weebo dev image ships `passwd-append` in its entrypoint by default, so the
injection would duplicate work already done at build time for the images that matter. See
*Future work* for what remains of the idea.

## Drawbacks and risks

- **Workspace creation now depends on our availability.** `failurePolicy: Fail` is the right call
  for a control and it is still a new hard dependency for Che. Two replicas and a PDB reduce the
  probability; they do not change the shape.
- **It removes a capability that upstream supports.** Per-workspace DWOC references are a
  documented DevWorkspace Operator feature, and this turns them off by default. `allowedOverrides`
  is the escape hatch, and every entry in it is an exception someone has to maintain.
- **It governs the DevWorkspace path only.** A user creating pods directly is unaffected. The
  feature is easy to over-read as "workspaces are now hardened", and it is not that.
- **A chassis built before the features that justify it.** Two follow-ups are named, neither is
  written, and the registry shape is being fixed against a sample size of one. The mitigation is
  that the chassis is small; the risk is that feature two does not fit `Feature<S>` and the trait
  is a published contract by then.
- **Coupling to `controller.devfile.io/v1alpha1`**, an alpha API, and to DevWorkspace Operator's
  merge semantics, which are documented behaviour rather than a versioned contract. A change
  there is a silent behaviour change here, caught only by the end-to-end suite.
- **The target DWOC is a single point of configuration** for the whole fleet, and its blast
  radius is the fleet. That is the point, and it is also the risk.
- **Rollback restores the policy, not the state.** Pinned workspaces stay pinned after `mode: Off`
  or after uninstall. Un-pinning is a manual loop.
- **The CRD schema grows with every feature**, so every feature is also a CRD upgrade. Generated,
  additive and cheap — still a cluster-scoped object to apply on every release.
- **Registry order is an implicit contract between features.** With one feature it is free. With
  four it is the thing that breaks when two of them touch the same field.
- **Two components to keep certified.** The cert-manager or OpenShift prerequisite is a real
  install-time dependency this repo did not have before.

## Unresolved questions

**Blocking acceptance:**

- **The API group.** `hardening.weebo.io` assumes a domain we control. A group rename after the
  CRD ships is a new CRD and a migration, so this is settled before the first `kubectl apply`,
  not after.
- **Where the mandated DWOC comes from.** This RFC pins workspaces to a `target` and says it must
  live in a namespace users cannot write. It does not say who authors that config or what is in
  it. If the answer is "the operator should own and reconcile it", that is a second feature and
  changes the RBAC — so it is settled before acceptance even though it is not built here.

**Not blocking:**

- Whether `allowedOverrides` should match on a label on the DWOC rather than on `{name,
  namespace}` pairs. A label is less to maintain as exceptions accumulate; an explicit list is
  auditable in the one place the policy already lives.
- Whether `DryRun` logs one line per admission — accurate and noisy on a busy cluster, where
  every start and stop is an admission — or aggregates into the CRD status only.
- Whether the controller role ships at all in the first increment, given its only reconcile is
  `WeeboSiConfig` → status. Folding it into the webhook process behind a lease is possible; two
  Deployments is the shape this RFC assumes, and collapsing it is not a contract change.
- Whether a self-signed certificate mode is worth having for clusters with neither cert-manager
  nor OpenShift service serving certificates. It would mean the operator holds a private key it
  generated, which this design currently avoids entirely.

## Future work

- **A validating companion to `dwoc-pin`** — reject rather than rewrite, for clusters where a
  silently corrected workspace is not acceptable. Its own RFC; `onMissingTarget: Deny` is the
  only piece of it that exists here.
- **Image restriction — a validating webhook** on workspace pods, rejecting images from
  registries not on an allow-list. Its own RFC, its own webhook configuration at
  `failurePolicy: Fail`, per the rule in *Operational considerations*.
- **DWOC content validation** — reject a `DevWorkspaceOperatorConfig` that weakens the baseline,
  wherever it lives, rather than steering workspaces away from it. The complement to this RFC:
  `dwoc-pin` controls which config is used, that one controls what a config may say.
- **Drift reconciliation** for workspaces that exist and are never restarted, closing the
  "created before installation" bypass with a controller rather than with admission.
- **Pod-level injection of [RFC 0001](./0001-passwd-append.md)'s binary**, for third-party images
  the Weebo dev image does not cover. Explicitly declined for now — the dev image ships
  `passwd-append` by default, which covers the fleet that matters — and kept here so the idea is
  not rediscovered as new.
- **A validating webhook on our own CRD**, so a bad feature configuration is rejected at write
  time rather than reported as `Degraded` afterwards.
- **`v1beta1` and a conversion webhook**, once the feature set stops moving.
- **OLM bundle or Helm chart** for installation, rather than raw manifests.
- **Multi-arch images** (`arm64`), tracked with the same item in
  [RFC 0001](./0001-passwd-append.md).

## Implementation plan

- [ ] `crates/weebo-si-operator` scaffold: workspace member, inherited lints, the hexagonal
      module tree above with empty `domain`/`application`/`adapters`
- [ ] `domain/model` — `FeatureId`, `FeatureMode`, `Mutation`, `Decision`, `Workspace`,
      `DwocRef`, `DomainError`. Pure, no `kube`, no `k8s-openapi`
- [ ] `domain/port` — `FeatureGate`, `DwocCatalog`, `Observer`, with in-memory fakes in
      `#[cfg(test)]`
- [ ] `domain/feature/mod.rs` — the `Feature<S>` trait and the per-subject registries, plus the
      test asserting `evaluate` cannot observe its mode
- [ ] `WeeboSiConfig` CRD types with `kube-derive`, and `task recu` generating the CRD YAML the
      way it already generates the RFC index
- [ ] `application/admit.rs` — mode application at the edge, feature ordering, denial handling
- [ ] `domain/feature/dwoc_pin.rs` — the four-outcome decision table, `allowedOverrides`,
      `onMissingTarget`, and the annotation grammar, table-tested exhaustively
- [ ] `adapters/inbound/admission.rs` — `AdmissionReview` in, JSON Patch out, one round-trip test
      per direction proving the translation is faithful, including the escaping of `/` and `~`
      in the attribute key's JSON Pointer
- [ ] `adapters/outbound/kube_dwoc_store.rs` and `kube_config_store.rs` — watch-backed caches
- [ ] `adapters/outbound/prometheus.rs`
- [ ] `adapters/inbound/controller.rs` — the `WeeboSiConfig` reconcile and its status, with
      leader election
- [ ] Idempotence tests: a second pass over an already-pinned workspace produces an empty patch;
      a `spec.started` toggle on a pinned workspace produces an empty patch
- [ ] Logging audit: assert no call site can emit a DevWorkspace template, its attributes or its
      environment variables
- [ ] Manifests: RBAC, Deployment ×2 with `maxUnavailable: 0`, PDB, Service,
      `MutatingWebhookConfiguration`, serving certificate for both OpenShift and cert-manager
- [ ] Containerfile with a multi-stage build, and `task audit` covering the crate
- [ ] End-to-end suite against a real apiserver: install, `Off` → `DryRun` → `Enforce`, an
      allow-listed override, a missing target under both `Skip` and `Deny`, and the break-glass
- [ ] Docs: install and rollout runbook in `docs/`, including the un-pin loop and the
      break-glass, and the RBAC requirement on the target's namespace
- [ ] RFC flipped to `Implemented`

## References

- [DevWorkspace Operator — additional configuration](https://github.com/devfile/devworkspace-operator/blob/main/docs/additional-configuration.adoc)
  — the `controller.devfile.io/devworkspace-config` attribute and the merge direction this RFC
  exists to correct
- [DevWorkspace Operator — `DevWorkspaceOperatorConfig` types](https://github.com/devfile/devworkspace-operator/blob/main/apis/controller/v1alpha1/devworkspaceoperatorconfig_types.go)
  — what a DWOC can set, and therefore what an override can take
- [DevWorkspace Operator — `pkg/constants`](https://pkg.go.dev/github.com/devfile/devworkspace-operator/pkg/constants)
  — the attribute key, verbatim
- [Eclipse Che — DevWorkspace Operator overview](https://eclipse.dev/che/docs/stable/administration-guide/devworkspace-operator/)
- [Kubernetes — dynamic admission control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
  — `failurePolicy`, `reinvocationPolicy`, `matchPolicy`, `sideEffects`
- [OpenShift — service serving certificates](https://docs.openshift.com/container-platform/latest/security/certificates/service-serving-certificate.html)
- [cert-manager — CA injector](https://cert-manager.io/docs/concepts/ca-injector/)
- [RFC 0001](./0001-passwd-append.md) — the first brick, and the source of the single-shot and
  usability-shim arguments this RFC reuses
- [`../architecture/hexagonal.md`](../architecture/hexagonal.md) — the criteria this RFC is
  measured against when it adopts the layout
- [`../architecture/repo-layout.md`](../architecture/repo-layout.md) — why this brick is in
  `crates/` rather than `bins/`

## Changelog

| Date | Change |
</content>
