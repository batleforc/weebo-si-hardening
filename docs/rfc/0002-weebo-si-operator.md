---
rfc: 0002
title: weebo-si-operator
status: Proposed
authors: [batleforc]
created: 2026-08-23
updated: 2026-08-24
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
that pins every DevWorkspace to a DevWorkspaceOperatorConfig the platform authored. The set of
those is a catalogue in the same cluster-scoped resource, and a namespace reaches only the
entries an admin bound to it — so a workspace cannot steer itself onto a configuration that
weakens the baseline, while a team with a real need for a different one gets it without an
exception per workspace. The controller
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

**One mandated config for the whole cluster is the wrong shape too.** A fleet is not uniform. A
team on GPU nodes needs a different storage class and a different set of init containers from a
team running web workloads, and both needs are legitimate. A design with a single mandated
target answers that with a per-workspace exception list, which grows one entry per team per
workspace, and which is an allow-list of *references* rather than of *configurations*. The
distinction worth building on is not how many configurations exist — it is **who authors them**.
Several admin-authored configurations, routed to teams by an admin, is a control. One
admin-authored configuration plus a per-workspace escape hatch is a control with a queue of
exceptions in front of it.

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
resource, and every workspace in the cluster runs with a DWOC that resource names — the team's
default where a team was given one, the cluster default everywhere else, and never a
configuration the workspace owner wrote. The same resource turns any individual hardening
behaviour from "measuring only" to "enforcing" to "off" without a
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

Turning the first feature on is a two-step move, and the first step mutates nothing. The
configuration has two halves: a **catalogue** of the DWOCs an admin is willing to see in use,
and the **grants** deciding which of them a team reaches.

```yaml
spec:
  features:
    dwocPin:
      mode: DryRun
      catalog:
        - key: baseline
          name: weebo-hardened-config
          namespace: eclipse-che
        - key: gpu
          name: gpu-config
          namespace: eclipse-che
        - key: amd
          name: amd-config
          namespace: eclipse-che
      default: baseline
```

With no `spec.teams` and no `grants` written yet, every namespace resolves to `baseline`. That
is deliberately the simplest useful configuration — one mandated DWOC for the whole cluster —
and it is the right thing to measure before any routing exists.

In `DryRun` the webhook does all the work and throws the answer away. It logs the decision and
counts it, so an admin sees what would have happened across the cluster before it happens:

```text
INFO  feature=dwoc-pin mode=DryRun ns=user-alice devworkspace=python-web team=<none>
      current=user-alice/my-config resolved=baseline decision=replace
INFO  feature=dwoc-pin mode=DryRun ns=user-bob devworkspace=java-api team=<none>
      current=<none> resolved=baseline decision=add
```

```console
$ kubectl get weebosiconfig cluster -o jsonpath='{.status.features}'
[{"name":"dwocPin","state":"DryRun","observedGeneration":2,
  "message":"evaluated 214 workspaces: 6 would be replaced, 208 would be pinned"}]
```

Then the teams are declared once, at the top of the resource, and each feature says what a team
gets. Enforcement is narrowed to one namespace first:

```yaml
spec:
  teams:                                # chassis-level: identity only, no policy
    - name: team-1
      namespaceSelector:
        matchLabels:
          weebo.io/team: team-1
    - name: team-2
      namespaceSelector:
        matchLabels:
          weebo.io/team: team-2
  features:
    dwocPin:
      mode: Enforce
      catalog: [ ... ]                  # unchanged
      default: baseline                 # for a namespace in no team
      grants:                           # what dwoc-pin gives each team
        team-1: {allowed: [gpu], default: gpu}
        team-2: {allowed: [baseline, amd], default: baseline}
      namespaceSelection:
        annotation: hardening.weebo.io/dwoc
        onUnknownKey: Default
      namespaceSelector:
        matchLabels:
          hardening.weebo.io/pilot: "true"
```

`spec.teams` answers "who is team-1" once, for the whole operator. `grants` answers "and what
does team-1 get from *this* feature", so a second feature adds a second `grants` map rather than
a second copy of the selector.

Team 1 runs on GPU nodes: every one of its namespaces gets `gpu`, and it has nothing else to
reach for. Team 2 defaults to the baseline and may move one of its namespaces onto `amd` — by
annotating the namespace, which is an admin operation rather than a workspace one:

```console
$ kubectl annotate namespace user-dave hardening.weebo.io/dwoc=amd
```

A DevWorkspace created in a bound namespace comes out pinned, whatever it asked for:

```yaml
metadata:
  name: python-web
  namespace: user-alice
  annotations:
    hardening.weebo.io/dwoc-pin: "replaced:user-alice/my-config;team=team-1;key=gpu"
spec:
  template:
    attributes:
      controller.devfile.io/devworkspace-config:
        name: gpu-config
        namespace: eclipse-che
```

The annotation is the audit trail: it records what the workspace asked for **and which rule
answered**, so "my storage class changed" has an answer one `kubectl get` away rather than a
webhook log search — and "why is this team on that config" has one too, which matters more once
more than one config exists.

A workspace naming a catalogue entry its own team is granted is left alone, and says so — which
is how one user gets both a GPU workspace and a web workspace, given that Che hands each user a
single namespace and therefore a single annotation:

```text
INFO  feature=dwoc-pin mode=Enforce ns=user-carol devworkspace=cuda-train team=team-2
      current=eclipse-che/amd-config resolved=amd decision=allowed-override
```

A workspace in the same team naming `gpu-config` — a real config, catalogued, but granted to
team 1 — is replaced like any other, and the log line names the team whose grant refused it.

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
registry, and — see below — the teams. A **team** is a named set of namespaces, defined once for
the whole operator and referenced by every feature. A **feature identifier** has two spellings,
mechanically derived from each other: kebab-case (`dwoc-pin`) in logs, metrics, annotations and
the CLI, camelCase (`dwocPin`) as the CRD field name, because that is the Kubernetes API
convention. There is no third spelling.

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
  teams:                             # chassis-level, ordered, first match wins
    - name: <teamName>                  # referenced by every feature's `grants`
      namespaceSelector: {}             # metav1.LabelSelector over namespaces
  features:
    <featureName>:                   # one optional field per registered feature, typed
      mode: Off | DryRun | Enforce      # required; there is no implicit default in the resource
      namespaceSelector: {}             # optional metav1.LabelSelector, narrows within the webhook's own scope
      grants:                           # optional, per team; the shape is the feature's own
        <teamName>: <feature-specific>
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

`spec.teams` adds a third selector, and it is a different kind of thing. The first two answer
*whether* a feature runs on a namespace; a team's `namespaceSelector` answers *which group a
namespace belongs to*, which every feature then reads its own answer from. Keeping the two roles
apart is what lets a rollout widen without touching the routing, and a namespace move between
teams without touching any rollout. The rule for the chassis: a selector either scopes a feature
or names a team, never both.

**Teams are chassis-level, and that is a decision worth its own paragraph.** A team is
`{name, namespaceSelector}` and nothing else — it carries no policy, only identity. Every
feature then declares what that team gets, under its own `grants` map keyed by team name, in
whatever shape the feature needs: `dwoc-pin` grants a set of catalogue keys and a default,
another feature grants something else entirely. The alternative — each feature carrying its own
list of `{name, namespaceSelector, ...}` — was the first draft of this RFC and is rejected under
*Alternatives considered*: two features routing the same teams would carry two copies of the
same selector, and the day they diverge nothing reports it, because both are individually valid.
Identity is defined once; entitlement is per feature.

Three rules follow, all chassis-level so no feature restates them:

- **`spec.teams` is ordered and the first match wins.** A namespace matching two teams belongs
  to the first. Inferring intent from selector specificity is a well-known source of surprise,
  and this list is written by one admin in one file, where reading order is an intuition already
  available.
- **A namespace matching no team has no team**, and every feature must define what it does for
  one. There is no implicit "default team", because a default team would be a policy hiding in
  the chassis.
- **A `grants` key naming an unknown team is a `Degraded` condition** at reconcile, never a
  silently ignored entry. A grant nobody can reach is the security-toggle equivalent of a
  misspelled feature name, which is the failure the CRD exists to make impossible.

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

The only feature implemented here. It makes the DWOCs the platform authored the only ones in
use, and decides which of them each namespace runs with.

**Configuration**

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis |
| `catalog` | list of `{key, name, namespace}` | — | required, non-empty. Every DWOC a workspace is permitted to run with. `key` is a short identifier, unique in the list. |
| `default` | catalogue key | — | required. The entry for a namespace belonging to no team. |
| `grants` | map, team name → `{allowed, default}` | empty | What each team may reach. `allowed` is a non-empty list of catalogue keys; `default` is one of them. |
| `namespaceSelection.annotation` | string | `hardening.weebo.io/dwoc` | Namespace annotation naming a catalogue key, choosing inside what the team is granted. The empty string disables namespace selection entirely. |
| `namespaceSelection.onUnknownKey` | `Default` \| `Deny` | `Default` | What to do when that annotation names a key the namespace cannot reach. |
| `onMissingTarget` | `Skip` \| `Deny` | `Skip` | What to do when the resolved entry does not point at a live DWOC. |

The team names are `spec.teams` entries and nothing else — a `grants` key naming a team nobody
declared is a `Degraded` condition, per the chassis. A team with no grant here falls back to
`default`, exactly like a namespace with no team: a team is an identity, and a feature saying
nothing about it is a feature that has nothing to say.

**Why keys rather than references.** A grant and a namespace annotation name a catalogue `key`,
never a `{name, namespace}` pair. Three reasons, in order of weight. The key is validated
against the catalogue, so the set of reachable configurations is closed by construction and no
namespace can name a DWOC nobody catalogued. Moving or renaming a DWOC is then one edit in the
catalogue rather than an edit in every namespace pointing at it. And a `{name, namespace}` pair
does not fit in a label value — `/` is not allowed there — so the key is also what keeps the
door open to routing by label instead of by annotation later.

**Resolution.** For an incoming DevWorkspace, in this order, stopping at the first answer:

1. **The team, and its grant.** The first entry of `spec.teams` whose `namespaceSelector`
   matches the workspace's namespace, then this feature's `grants` entry for that team. When the
   namespace belongs to no team, or its team has no grant here, the allowed set is `[default]`
   and the default is `default` — which is exactly the single-target behaviour, and is why a
   configuration with no teams at all is the simplest useful one.
2. **The workspace's own attribute.** Read
   `spec.template.attributes["controller.devfile.io/devworkspace-config"]`. When it names a
   catalogue entry inside the grant's `allowed` set, it is kept.
3. **The namespace annotation.** When the namespace carries `namespaceSelection.annotation` and
   its value is a key inside `allowed`, that entry is the target. A value outside it — an
   unknown key, or a key the team is not granted, indistinguishable to whoever wrote it and
   therefore treated identically — follows `onUnknownKey`.
4. **The grant's `default`.**

**Three steps, and they are three scopes.** Che gives each user their own namespace, so the
chain is not four arbitrary lookups: the **team** is a namespace label, the **user** is that
namespace's annotation, and the **workspace** is the attribute. Most specific wins, which is
the rule a reader already expects from a configuration system, and it is why step 2 sits above
step 3 rather than below it.

It is also why step 2 exists at all. With one namespace per user, "a namespace runs exactly one
configuration" means "a user runs exactly one configuration" — so a developer with a GPU
workspace and a web workspace would need a second identity to have both, and the per-namespace
answer would be strictly less useful than the per-workspace attribute it replaced. The `allowed`
set is what keeps the most specific level from being a hole: a user picks among the
configurations an admin gave their team, and widening that set is not something they can reach.
Were namespaces shared by teams rather than owned by users, this step would be worth dropping —
that reading is recorded under *Alternatives considered*, because the cluster's namespace model
is what decides it, and a different Che topology would decide it differently.

**Decision table.** `resolved` is the outcome of the four steps above.

| Current reference on the workspace | Decision | Patch |
| --- | --- | --- |
| absent | `add` | set the attribute to `resolved` |
| equal to `resolved` | `already-pinned` | none |
| a catalogue entry inside the grant's `allowed` | `allowed-override` | none |
| a catalogue entry the grant does not allow | `replace` | set the attribute to `resolved` |
| anything else, including a DWOC absent from the catalogue | `replace` | set the attribute to `resolved` |

The last two rows are one behaviour, written as two because they are two different mistakes: a
team reaching for another team's configuration, and a workspace naming a config its owner wrote.
Both are replaced; the log line and the annotation record which.

On `add` and `replace`, the annotation `hardening.weebo.io/dwoc-pin` records what happened, as a
verb followed by `;`-separated `k=v` pairs:

```text
added;team=team-1;key=gpu
replaced:user-alice/my-config;team=team-1;key=gpu
replaced:eclipse-che/amd-config;team=team-1;key=gpu
added;team=<none>;key=baseline
```

The verb is `added` or `replaced:<namespace>/<name>` — the value the workspace asked for — and
the pairs name the rule answering. That annotation is the whole audit story for this feature,
and it is why the decision is a mutation rather than a silent rewrite.

**Validating the resolved entry.** Before pinning anything, the feature checks that the resolved
catalogue entry points at a `DevWorkspaceOperatorConfig` present in the watch-backed cache.
Pinning to a dangling reference is worse than not pinning: DevWorkspace Operator would fail to
resolve the config for every workspace routed there. When it is missing:

- `onMissingTarget: Skip` (default) — the feature makes no patch, the workspace proceeds with
  whatever it asked for, and the CRD gets a `Degraded` condition plus a
  `weebo_si_dwoc_pin_total{result="target_missing"}` increment.
- `onMissingTarget: Deny` — the admission response denies the request with a message naming the
  missing entry. For clusters where an unpinned workspace is not acceptable even briefly.

The check is per-entry and at admission time, so a broken catalogue entry degrades the teams
granted it rather than the cluster. A single mandated target did not have that property, and it
is the one place where the catalogue is safer than what it replaces rather than merely more
expressive.

**Validating the configuration itself belongs to the controller**, at reconcile, not to the
webhook: duplicate keys, a `default` absent from the catalogue, a grant whose `allowed` is empty
or names an unknown key, a grant `default` outside its own `allowed`, and — from the chassis — a
`grants` key naming a team nobody declared. Each is a `Degraded` condition naming the offending
grant. This is also what earns the controller role its place; against a single target its only
reconcile was copying `spec` into `status`.

Ambiguity between teams is the chassis's problem and is resolved by order, never by specificity;
`dwoc-pin` restates none of that.

**Where the catalogued DWOCs live is a deployment requirement, not a detail.** Every entry must
sit in a namespace workspace owners cannot write to — the Che namespace, or the operator's own.
A mandated config in a namespace the user can edit is a control handing the user the thing it
was protecting. This is stated again, with the reasoning, under *Security considerations*.

**Two fail-open/fail-closed knobs, and neither is the webhook's.** `onMissingTarget` covers a
catalogue entry pointing nowhere; `namespaceSelection.onUnknownKey` covers a namespace asking
for something it cannot have. Both default to degrading toward the admin-authored answer rather
than toward a rejected workspace, and both are separate from `failurePolicy`, which covers the
case where the operator cannot answer at all.

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
| `weebo_si_dwoc_pin_total` | counter | `result` ∈ `added`/`replaced`/`already_pinned`/`allowed_override`/`unknown_key`/`target_missing`, and `team` — the team name, or `_none` |
| `weebo_si_dwoc_pin_catalog_entries` | gauge | `state` ∈ `resolvable`/`missing` |
| `weebo_si_config_observed_generation` | gauge | — |

The `team` label is what makes a per-team rollout readable: `result="replaced"` summed over the
fleet says how much is changing, and broken down by team it says *whose* workspaces are
changing, which is the question asked during step 3 of the rollout. Its cardinality is the
number of teams an admin wrote in one file, so it is bounded by the same thing bounding the
file's length — and because teams are chassis-level, the label means the same thing on every
feature's metrics, which is most of the point of hoisting them.

`/healthz` is liveness and answers as soon as the process serves. `/readyz` answers only once
every watch cache is synced — the CRD, the DWOCs **and** the namespaces — so a pod that cannot
see one of them receives no admission traffic instead of routing every namespace to the cluster
default and reporting `target_missing` on everything.

**Stability.** The CRD group, version, kind, and field names; the feature identifiers; the webhook
paths; the annotation keys and their value grammar; the metric names and label values; and the
exit codes are the contract. Changing any of them needs a new RFC, per
[the RFC process](./readme.md#when-is-an-rfc-required).

### Architecture

**Hexagonal, and it is the case the layout was written for.** Measured against the three criteria
in [`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. *A real decision.* A four-step resolution chain — team grant, workspace attribute, namespace
   annotation, grant default — over an admin-written catalogue, five outcomes from it, an
   entry that may not exist, two fail-open/fail-closed knobs, a per-namespace selector and a
   three-state mode. Every one of those is a branch a user can get wrong, and their product is
   larger than any of them.
2. *Touches an external system.* The Kubernetes API, three resource types, plus the admission
   path itself.
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
│   │   ├── dwoc.rs                # DwocRef, and the bounded view of a DWOC we read
│   │   ├── namespace.rs           # NamespaceName, NamespaceFacts — labels and one annotation
│   │   ├── selector.rs            # Selector: matchLabels + matchExpressions, over NamespaceFacts
│   │   ├── team.rs                # TeamName, Team — chassis-level, shared by every feature
│   │   └── catalog.rs             # CatalogKey, Catalog, Grant — and the resolution chain
│   ├── feature/
│   │   ├── mod.rs                 # the Feature trait and the registry
│   │   └── dwoc_pin.rs            # the one implemented feature   <- where the tests are
│   ├── error.rs                   # DomainError. Never kube::Error, never a HTTP status.
│   └── port/
│       ├── feature_gate.rs        # which features are active, in which mode, for which namespace
│       ├── dwoc_catalog.rs        # does this DWOC reference resolve
│       ├── namespace_view.rs      # the labels and the selection annotation of a namespace
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
        ├── kube_ns_store.rs       # watch-backed Namespace cache, implements NamespaceView
        └── prometheus.rs          # implements Observer
```

**The ports, in domain vocabulary.**

```rust
// domain/port/feature_gate.rs
pub trait FeatureGate {
    fn mode(&self, feature: FeatureId, namespace: &NamespaceName) -> FeatureMode;
    fn teams(&self) -> &[Team];   // ordered, chassis-level, shared by every feature
}

// domain/port/dwoc_catalog.rs
pub trait DwocCatalog {
    fn resolves(&self, r: &DwocRef) -> bool;
}

// domain/port/namespace_view.rs
pub trait NamespaceView {
    fn facts(&self, ns: &NamespaceName) -> Option<NamespaceFacts>;
}

// domain/port/observer.rs
pub trait Observer {
    fn decided(&self, feature: FeatureId, outcome: &FeatureOutcome);
}
```

Each is named for what the application needs. `DwocCatalog::resolves` says "is this a real
config" — the watch, the cache and the informer are the adapter's problem, and the fake is a
`HashSet`. `NamespaceFacts` is labels plus the one selection annotation and nothing else: the
projection is bounded in the domain type, so the cache can drop the rest of a Namespace object
and no later feature can quietly start depending on its `spec` or its `status`.

**The one place the dependency rule bites.** A team's `namespaceSelector` is a
`metav1.LabelSelector` in the CRD, and matching one is a `k8s-openapi` concern — but *choosing a
team* is the decision itself, and the decision belongs to the domain. So the domain owns a
small `Selector` over `NamespaceFacts::labels`, and the config adapter converts into it once at
load rather than at every admission. Re-implementing `matchExpressions` is a genuine cost, paid
for the resolution chain being exhaustively testable without a cluster; the conversion is the
single place where a change in upstream selector semantics has to be tracked, and it is where
that test lives.

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

`Decision` carries a `Vec<Mutation>`, an optional denial reason, and the **provenance** of the
answer — which team matched, which catalogue key won, and at which step of the chain. The
provenance is one value with three consumers: the audit annotation, the log line and the `team`
metric label. Computing it once inside `evaluate` is what keeps those three from
drifting apart, and it is also what makes `DryRun` worth reading, since the shadow run reports
the same provenance the enforcing run would have applied. `Mutation` is a small typed enum
(`SetConfigRef`, `Annotate`) rather than a patch fragment. Rendering it to RFC 6902 JSON
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

- **Watch-backed caches** of `WeeboSiConfig`, `DevWorkspaceOperatorConfig` and `Namespace`, in
  memory. Lost on restart and rebuilt by a relist; `/readyz` stays false until they are synced,
  so a cold pod takes no traffic rather than deciding on stale data. The first two are tiny —
  one singleton and a handful of configs — which is why the entry-existence check is affordable
  on every admission. The namespace cache is the only one scaling with the cluster, and it is
  stored as the bounded `NamespaceFacts` projection — labels and one annotation — so a cluster
  with thousands of workspace namespaces costs kilobytes rather than the full objects. Note what
  is **not** cached: DevWorkspaces. The object under admission arrives in the request, so the
  feature needs no view of the workspace population at all.
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
| `get`, `list`, `watch` | `namespaces` |

and the controller role adds `update` and `patch` on `weebosiconfigs/status`, plus `create` on
`events`. That is the whole list. Three read-only watches.

The namespace watch is the one this RFC added, and it is worth being explicit about its cost:
RBAC grants a resource, never a field, so "read namespace labels and one annotation" is not
expressible and the grant is the whole object. It is a low-value one — a Namespace carries
metadata, a finalizer list and a phase, no payload — and the projection to `NamespaceFacts`
happens in our own cache rather than at the apiserver, so it bounds what the process holds, not
what it is permitted to read. Anyone auditing this should read the row as "list every namespace
in the cluster", because that is what it is.

**It has no permission on DevWorkspaces at all — not even read.** A mutating webhook receives the
object in the request and returns a patch to the apiserver; it neither reads nor writes the
resource it governs. This is worth stating because the obvious mental model — "the operator edits
workspaces" — implies an RBAC grant that would be a far larger blast radius than what is actually
requested. It also has no `escalate`, no `bind`, no `impersonate`, and no access to Secrets other
than its own mounted serving certificate.

**The privilege it does hold** is `spec.features.dwocPin`: the catalogue naming every
configuration any workspace in the cluster may run with, and the grants deciding who gets which
— together with `spec.teams`, which decides who "who" is. Whoever writes those fields sets the pod and container security context, the init
containers, the storage class and the image pull policy for the entire fleet, indirectly. It is
the most powerful field in this design. Three things bound it, all deliberate:

- The CRD is **cluster-scoped**. Writing it is a cluster-admin action; a namespace admin cannot
  reach it, which is the entire reason the flags are not per-namespace resources.
- A resolved entry must exist before anything is pinned, so a typo degrades to "no pinning for
  that team" rather than to "every workspace references a config that does not exist".
- **The catalogue is closed.** Every path through the resolution chain ends on a catalogue
  entry: a grant names keys, a namespace annotation names a key, and a workspace attribute is
  only ever *kept* — never adopted — and only when it already names a catalogued entry the
  grant allows. There is no input to this feature that turns an arbitrary `{name, namespace}`
  into a pin. That property is what makes delegating the choice to a namespace acceptable at
  all, and it is the invariant to defend if the schema ever grows a fourth way to select.

**Delegation is bounded by the catalogue, not by trust in the namespace.** The namespace
annotation is the one input to this feature written outside the cluster-scoped resource, so the
question is what someone able to write it can obtain. The answer is: any entry their team is
already granted, and nothing else. An unknown key, another team's key, or a hand-written
reference all land on `onUnknownKey` or on `replace`. So the worst case for a compromised or
over-permissive namespace annotation is *a configuration an admin authored and bound to that
team* — a downgrade within an admin-chosen set, not an escape from it. That is a materially
different failure from the one this RFC exists to fix, where the user supplies the configuration
itself.

That said, **who may annotate a namespace is a real question with a cluster-specific answer**,
and it belongs on the install checklist next to the exclusion label. In a Che cluster, user
namespaces are created by Che and their users hold rights *inside* the namespace, not on the
Namespace object — patching namespace metadata is an admin verb. Where that is not true, the
mitigation is one line: set `namespaceSelection.annotation` to the empty string, which removes
step 3 of the chain entirely and leaves routing to the teams and their grants, which only a
cluster admin can write. The feature is designed so that this is a configuration change rather than a redesign.

**Namespace labels are load-bearing now, and they were not before.** A team matches on labels,
so labelling a namespace into another team moves it onto that team's configurations — and,
because teams are chassis-level, onto that team's answer from **every** feature at once. That is
the cost of hoisting them, and it is the right trade: one mislabel is easier to find than two
routing tables that disagree, and the audit annotation names the team on every pinned workspace. This is the same privilege as the `hardening.weebo.io/exclude` label — namespace
labels are an admin-level operation in a Che cluster — but it is now used for routing rather
than only for opting out, so a wrong label routes silently instead of leaving a visible gap.
The audit annotation on every pinned workspace names the team that answered, and it is the
cheapest way to catch one.

**The catalogued DWOCs must live where users cannot write them.** This is the one deployment
requirement that is a security control rather than a convenience. Cataloguing
`user-alice/hardened-config` would let user Alice edit a configuration other namespaces are
pinned to — the control would be handing the attacker the object it protects. Every entry
belongs in the Che namespace or the operator's own, and RBAC there is the thing making this
feature mean anything. A catalogue makes this both easier to get wrong and easier to check,
since the list of namespaces to audit is written down in one place. The operator does not and
cannot verify it; it is on the install checklist.

**Trust boundary.** Two inputs cross it. The `AdmissionReview` body is the untrusted one — any
user able to create a DevWorkspace controls it — and namespace metadata is the
admin-controlled-in-practice one, which is handled with the same suspicion because "in practice"
is a statement about a cluster's RBAC rather than about this code. Both are parsed into typed
structures, touch a bounded set of fields, and produce an error response rather than a panic on
anything unexpected — which is what the workspace lint table (`panic = "deny"`,
`unwrap_used = "deny"`) exists to make hard to get wrong in the admission path specifically. The
annotation value in particular is a free-form string reaching us from the apiserver: it is
looked **up** in the catalogue, never parsed into a reference, so the only two outcomes are a
catalogue entry and `onUnknownKey`.

Worth noting what the feature deliberately **does not** do: it never reads the user's DWOC. An
earlier draft of this RFC had the webhook resolve the effective configuration — global merged
with the user's — and act on its contents, which made a user-authored object part of our input.
Overwriting the reference instead of reading what it points at removes that surface entirely.
The only user-controlled value reaching a decision is the reference itself, and it is compared
against the admin-authored catalogue, never dereferenced. The catalogue survives that rule
intact: an entry is checked for **existence** and nothing more, so no DWOC's contents — not even
an admin-authored one — is an input to any branch in this feature.

**Bypass.**

- **The namespace exclusion label.** Anyone able to label a namespace `hardening.weebo.io/exclude`
  opts it out wholesale. In a Che cluster namespace labels are an admin-level operation; if that
  ever stops being true, this label is the first thing to revisit.
- **Namespace labels and the selection annotation.** Both are covered above: a label moves a
  namespace between teams, an annotation moves it inside one. Neither reaches outside the
  catalogue, so both are downgrades within an admin-authored set rather than escapes from it —
  and the annotation half is removable with `namespaceSelection.annotation: ""`. They are listed
  here rather than only under *Delegation* because a bypass list nobody can read to the end is
  not a bypass list.
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

**Blast radius.** A wrong `default`, or a wrong entry behind a widely-bound key, misconfigures
every workspace it routes on its next start; and at `failurePolicy: Fail` an operator outage
stops workspaces from being created or started cluster-wide. Those are the two numbers. The
first is now bounded by the grant rather than by the cluster — a mistake in a team's entry
reaches that team — which is a genuine improvement over a single mandated target, and it is
paid for with a routing table that can itself be wrong. They are bounded by `DryRun`, by the
per-feature `namespaceSelector` during rollout, by the per-entry existence check, and by the
break-glass in *Rollback*. A compromise of the operator is worse than either: it is the ability to pin every
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

**Rollout.** Five steps, each independently reversible:

1. Install the CRD, the operator and the webhook configuration with `spec.features: {}`. Nothing
   is changed beyond a no-op round trip on DevWorkspace writes; watch
   `weebo_si_admission_duration_seconds` to see the cost of that round trip alone. This is also
   the step that proves the `Fail` policy is survivable before any feature depends on it.
2. `mode: DryRun`, with the catalogue and `default` written and **no teams**. Read
   `weebo_si_dwoc_pin_total` and the decision logs. The number that matters is
   `result="replaced"` — every one of those is a workspace that will change behaviour, and
   `DryRun` is the only chance to look at them before they do.
3. **Add `spec.teams` and the grants, still in `DryRun`.** This step is new with the catalogue
   and it is the one worth not skipping: routing is the part with no analogue in the previous
   behaviour, and `result` broken down by `team` is how an admin confirms that team-1's
   namespaces are the ones landing on team-1's config. A namespace routed to the wrong team is
   invisible in aggregate and obvious per team.
4. `mode: Enforce` with a `namespaceSelector` on a pilot label. One namespace, real pins.
5. Remove the selector.

Steps 2 through 5 are writes to one resource, effective on the next admission, with no rollout.

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
the second, because it means the feature is doing nothing while appearing to be `Active`, and
`weebo_si_dwoc_pin_catalog_entries{state="missing"}` is the same signal seen from the
configuration rather than from the traffic — it fires on a deleted DWOC even for a team whose
workspaces nobody has restarted yet, which the counter cannot. `result="unknown_key"` is the
third: it is a namespace asking for something it cannot reach, which is either a typo in an
annotation or a team believing it has an entitlement it does not have. Neither is urgent;
both are silent without it. A `Degraded` condition on the CRD means a feature's configuration
was rejected at reconcile — with a catalogue that now includes a grant naming a key nobody
catalogued, or a team nobody declared, which are the two most likely ways to break this
configuration by hand. From
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

**One mandated target, plus a flat `allowedOverrides` list.** The shape this RFC had until this
revision, and the honest baseline for everything above: one `target` for the cluster, and a list
of `{name, namespace}` references a workspace was permitted to keep. Rejected because the
allow-list is a list of *references*, not a routing table. It cannot express "team 1 defaults to
the GPU config", only "any workspace anywhere may keep the GPU config if it asks" — so a team
with a real need gets it by having every one of its workspaces ask, which is an entitlement
implemented as a habit, invisible to anyone reading the policy, and lost the moment a workspace
is created from an unmodified devfile. It also has no *default* per team, which is the thing an
admin actually wants to control. The catalogue costs a resolution chain and a second selector;
what it buys is that the answer to "what does this team run" is written down rather than
inferred from what the team's workspaces happen to request.

**Per-feature bindings instead of chassis-level teams.** Each feature carrying its own list of
`{name, namespaceSelector, allowed, default}`, which is what this RFC said until the
network-profiles feature was sketched against it. It reads well with one feature and it is a trap with two: the
same team is described by two selectors in two places, both individually valid, and the day one
is edited and the other is not, nothing reports it — the features simply disagree about who
team-1 is, silently, in a security control. Rejected in favour of `spec.teams` holding identity
once and each feature holding entitlement. The cost is real and worth naming: teams become a
shared contract, so re-labelling a namespace moves it for every feature at once, and a feature
can no longer roll out its routing independently of the others. The rollout knob that remains
per feature is `namespaceSelector`, which is the one that was designed for it.

**Dropping step 2 — a namespace runs exactly one configuration, and the workspace attribute is
always replaced.** The strictest reading, and the easiest to audit: one namespace, one config,
answerable without reading a single DevWorkspace, and `allowed` would mean "a namespace may be
moved here" rather than "a workspace may ask for this". Rejected on the cluster's namespace
model rather than on principle. Che gives each user their own namespace, so *namespace* and
*user* are the same scope, and this reading would let a developer run exactly one configuration
across all of their workspaces — worse than the upstream behaviour this RFC constrains, for a
user with a GPU workspace and a web one. It is the right answer in a cluster where namespaces
are owned by teams rather than by people, which is why the decision is recorded here with its
premise attached: if the Che topology changes, this is the paragraph to re-read.

**The namespace annotation carrying a `{name, namespace}` reference instead of a catalogue
key.** Fewer concepts — no keys, no catalogue, just "this namespace uses that DWOC". Rejected on
the security property in *Design*: a reference in an annotation is an open set, so the feature
would have to validate it against an allow-list anyway, which is the catalogue with the
indirection removed and the maintenance burden added back. It also puts the DWOC's location in
every namespace that uses it, so moving one config is an edit per namespace.

**A namespaced CRD per team — `WeeboSiNamespaceConfig` — instead of teams in the singleton.**
Tempting, because a team's configuration would live next to the team. Rejected: it moves a
security-relevant choice into a namespaced object, and the whole reason the flags are
cluster-scoped is that a namespace admin must not reach them. A namespaced CRD would need its
own RBAC story to be safe, and that story is "only cluster admins may write it" — at which point
it is the singleton with extra objects. The namespace annotation is the deliberate, bounded
version of this idea: it delegates the *choice*, never the *set*.

**Routing by namespace label instead of by annotation.** A label would reuse the selector
machinery already present and be searchable with `kubectl get ns -l`. Rejected for the layering:
labels are what *teams* match on, so using labels for both the team and the choice inside the
team would make one mechanism carry two meanings, and a `kubectl label` intended as one would
sometimes be the other. Annotation for the choice, label for the group, is one rule to remember.
The catalogue key is deliberately label-value-shaped, so reversing this later is a schema
addition rather than a redesign.

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
  documented DevWorkspace Operator feature, and this turns them off by default. A team's
  `allowed` set is the escape hatch, and it is narrower than it looks: a workspace may keep a
  reference, never introduce one.
- **The routing table is a second thing to get right.** A single mandated target could be wrong
  in one way. A catalogue with teams and grants can be wrong in five: a key nobody catalogued, a
  namespace matching no team, a namespace matching the wrong team first, an `allowed` set
  missing the entry a team was promised, and a default outside it. Four of those are caught at
  reconcile and reported as `Degraded`; the third is not, because a selector matching the wrong
  namespace is indistinguishable from one matching the right namespace. That one is caught by
  reading `weebo_si_dwoc_pin_total` by team during step 3 of the rollout, which is why that step
  exists.
- **Teams are a shared contract across features.** Hoisting them removes the risk of two
  features disagreeing about who team-1 is, and creates a smaller one: a change to
  `spec.teams` moves a namespace for every feature at once, so what used to be a one-feature
  edit is now a cluster-wide one. With one feature this is free. It is the kind of coupling that
  is correct and still deserves a change-review habit.
- **Namespace metadata becomes security-relevant.** Labels route and an annotation selects, so
  "who can edit a Namespace object" moves from a question nobody in this repo asked to a
  question on the install checklist. The blast radius is bounded by the catalogue, and the
  exposure is removable with `namespaceSelection.annotation: ""` — but the coupling is new.
- **A four-step resolution chain is four chances to be surprised.** Most-specific-wins over
  team, user and workspace is a familiar shape, and it still has to be learned before an admin
  can predict what a given workspace will run. The awkward case is a workspace keeping its own
  reference: nothing was mutated, so nothing is annotated, and the only trace that the
  namespace's annotation was overruled is a log line. "Why is my namespace annotation being
  ignored" is the one question this feature answers worse than the others.
- **A third watch, on every namespace in the cluster.** It is the only cache scaling with the
  cluster, the only RBAC grant reaching outside two niche CRDs, and one more thing `/readyz`
  waits for before a pod takes traffic.
- **It governs the DevWorkspace path only.** A user creating pods directly is unaffected. The
  feature is easy to over-read as "workspaces are now hardened", and it is not that.
- **A chassis built before the features that justify it.** Two follow-ups are named, neither is
  written, and the registry shape is being fixed against a sample size of one. The mitigation is
  that the chassis is small; the risk is that feature two does not fit `Feature<S>` and the trait
  is a published contract by then.
- **Coupling to `controller.devfile.io/v1alpha1`**, an alpha API, and to DevWorkspace Operator's
  merge semantics, which are documented behaviour rather than a versioned contract. A change
  there is a silent behaviour change here, caught only by the end-to-end suite.
- **The catalogue is a single point of configuration** for the whole fleet. Per-entry blast
  radius is now a team rather than the cluster, which is better; the resource holding all of
  them is still one object whose corruption is every team at once. That is the point, and it is
  also the risk.
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
- **Where the catalogued DWOCs come from.** This RFC pins workspaces to catalogue entries and
  says every one of them must live in a namespace users cannot write. It does not say who
  authors those configs or what is in them — and with several of them, "who authors the GPU
  team's config" is a question with a plausible answer of "the GPU team", which would defeat the
  whole thing. If the answer is instead "the operator should own and reconcile them", that is a
  second feature and changes the RBAC from read-only to writing DWOCs. Settled before
  acceptance, even though it is not built here.

**Not blocking:**

- Whether `already-pinned` and `allowed-override` should also write the audit annotation. They
  mutate nothing today, so the only record of them is a log line — see *Drawbacks*. Annotating
  them stays idempotent, and it would make `kubectl get devworkspace -o yaml` a complete answer
  rather than an answer about replacements only; it also turns two no-op decisions into writes
  on objects nobody was going to touch.
- Whether a grant should be able to say "this team may use any catalogue entry" rather than
  listing keys. Convenient for a permissive tier, and a wildcard in an allow-list is a thing
  people later wish they had not added.
- Whether `DryRun` logs one line per admission — accurate and noisy on a busy cluster, where
  every start and stop is an admission — or aggregates into the CRD status only.
- Whether the controller role ships at all in the first increment. Less open than it was: the
  catalogue gives it real validation work — duplicate keys, dangling keys, a grant naming an
  undeclared team, a grant default outside its own `allowed` — rather than copying `spec` into
  `status`. Folding it into the
  webhook process behind a lease is still possible; two Deployments is the shape this RFC
  assumes, and collapsing it is not a contract change.
- Whether `status` should report the resolved team **per namespace** rather than only
  aggregate counters. It is the fastest answer to "why is this namespace on that config", and it
  is also a status field growing with the cluster, which is the thing status fields must not do.
  The audit annotation on each workspace is the version of this that costs nothing.
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
- [ ] `domain/model` — `FeatureId`, `FeatureMode`, `Mutation`, `Decision` with its provenance,
      `Workspace`, `DwocRef`, `NamespaceFacts`, `CatalogKey`, `Catalog`, `Binding`, `Selector`,
      `DomainError`. Pure, no `kube`, no `k8s-openapi`
- [ ] `domain/model/selector.rs` — `matchLabels` and `matchExpressions` matching, tested against
      the upstream semantics table including the empty-selector-matches-everything case
- [ ] `domain/model/catalog.rs` — the four-step resolution chain as one pure function, table
      tested: no team, first-of-two teams, allowed attribute kept, disallowed attribute
      replaced, annotation inside and outside `allowed`, both `onUnknownKey` values
- [ ] `domain/port` — `FeatureGate`, `DwocCatalog`, `NamespaceView`, `Observer`, with in-memory
      fakes in `#[cfg(test)]`
- [ ] `domain/feature/mod.rs` — the `Feature<S>` trait and the per-subject registries, plus the
      test asserting `evaluate` cannot observe its mode
- [ ] `WeeboSiConfig` CRD types with `kube-derive`, and `task recu` generating the CRD YAML the
      way it already generates the RFC index
- [ ] `application/admit.rs` — mode application at the edge, feature ordering, denial handling
- [ ] `domain/feature/dwoc_pin.rs` — the five-outcome decision table over the resolved entry,
      `onMissingTarget`, and the annotation grammar, table-tested exhaustively
- [ ] `adapters/inbound/admission.rs` — `AdmissionReview` in, JSON Patch out, one round-trip test
      per direction proving the translation is faithful, including the escaping of `/` and `~`
      in the attribute key's JSON Pointer
- [ ] `adapters/outbound/kube_dwoc_store.rs`, `kube_config_store.rs` and `kube_ns_store.rs` —
      watch-backed caches, the last one projecting to `NamespaceFacts` on the way in
- [ ] The `LabelSelector` → `Selector` conversion at config load, with the round-trip test that
      is the only guard against drifting from upstream selector semantics
- [ ] `adapters/outbound/prometheus.rs`
- [ ] `adapters/inbound/controller.rs` — the `WeeboSiConfig` reconcile and its status, with
      leader election, including catalogue validation: duplicate keys, `default` absent from the
      catalogue, an empty or dangling `allowed`, a grant `default` outside its own `allowed`, a
      grant naming an undeclared team, each a `Degraded` condition naming the grant
- [ ] Idempotence tests: a second pass over an already-pinned workspace produces an empty patch;
      a `spec.started` toggle on a pinned workspace produces an empty patch
- [ ] Logging audit: assert no call site can emit a DevWorkspace template, its attributes or its
      environment variables
- [ ] Manifests: RBAC, Deployment ×2 with `maxUnavailable: 0`, PDB, Service,
      `MutatingWebhookConfiguration`, serving certificate for both OpenShift and cert-manager
- [ ] Containerfile with a multi-stage build, and `task audit` covering the crate
- [ ] End-to-end suite against a real apiserver: install, `Off` → `DryRun` → `Enforce`, a
      namespace in no team, a namespace in two teams taking the first, an annotation
      moving a namespace inside its `allowed` set, an annotation naming another team's key under
      both `onUnknownKey` values, an allowed reference kept, a missing entry under both
      `onMissingTarget` values, and the break-glass
- [ ] Docs: install and rollout runbook in `docs/`, including the un-pin loop and the
      break-glass, the RBAC requirement on every catalogued namespace, and who is permitted to
      label and annotate a workspace namespace
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
- [Kubernetes — labels and selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors)
  — the `matchExpressions` semantics a team's selector has to reproduce, and the reason an
  empty selector matches everything
- [Kubernetes — annotations](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)
  — why the namespace's choice is an annotation and its team is a label
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
| --- | --- |
| 2026-08-24 | Amended before review, a second time and in the same revision: **teams are hoisted into the chassis.** `spec.teams` holds `{name, namespaceSelector}` once for the whole operator, ordered and first-match-wins, and each feature declares what a team gets under its own `grants` map keyed by team name. The trigger was sketching a second feature — network policy profiles, RFC 0004 — against the shape below and finding it would carry a second copy of every team's selector. Two features disagreeing about who team-1 is, both individually valid, with nothing reporting the divergence, is a failure mode a security control cannot have. The cost is stated under *Drawbacks* and is real: teams become a shared contract, so re-labelling a namespace moves it for every feature at once, and per-feature routing rollout is gone — `namespaceSelector`, which was designed for that, remains. The rejected shape is kept under *Alternatives considered*. |
| 2026-08-24 | Amended before review: `dwoc-pin` gains a **catalogue and per-team grants** in place of a single `target` plus a flat `allowedOverrides` list. The trigger was a requirement the old shape could not express — team 1 reaches only the GPU config and defaults to it, team 2 defaults to the baseline and may also reach AMD — and the reason the old shape could not is worth recording: `allowedOverrides` was an allow-list of *references*, so an entitlement could only be exercised by every workspace of a team asking for it, one workspace at a time. It had no notion of a default per team, which is the thing an admin wants to set. The new shape is a closed catalogue of admin-authored DWOCs keyed by a short identifier, a per-team grant of a subset with a default inside it, and a namespace annotation choosing within that subset. Three consequences the design had to absorb. **A third watch**, on `namespaces`, which is the first RBAC grant in this brick reaching outside two niche CRDs — bounded in the cache by a `NamespaceFacts` projection, not at the apiserver, and `/readyz` now waits for it. **Namespace metadata becomes security-relevant**: a label routes and an annotation selects, so "who may edit a Namespace" moved onto the install checklist, with `namespaceSelection.annotation: ""` as the one-line way to remove the annotation half where the answer is wrong. The containment argument is that the catalogue is *closed* — every path through the resolution chain ends on a catalogued entry, a workspace attribute is only ever kept and never adopted — so delegating the choice to a namespace is a downgrade within an admin-authored set, never an escape from it. And **the controller earns its keep**: duplicate keys, dangling keys and a grant default outside its own `allowed` are reconcile-time `Degraded` conditions, where before its only job was copying `spec` into `status`. One question was raised and settled while writing this: whether step 2 of the chain should exist at all — whether a workspace may keep a reference its team is granted, or whether a namespace runs exactly one configuration and the attribute is always replaced. **It exists.** Che gives each user their own namespace, so *namespace* and *user* are the same scope here, and the strict reading would let a developer run exactly one configuration across all of their workspaces — worse than the upstream behaviour this RFC constrains. The chain therefore reads as three nested scopes, team by label, user by annotation, workspace by attribute, most specific winning; `allowed` is what keeps the most specific level from being a hole. The rejected reading is kept under *Alternatives considered* with its premise attached, because a Che topology where namespaces belong to teams rather than to people would decide it the other way. |
