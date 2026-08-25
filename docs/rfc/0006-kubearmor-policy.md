---
rfc: 0006
title: kubearmor-policy
status: Implemented
authors: [batleforc]
created: 2026-08-24
updated: 2026-08-25
decided: 2026-08-25
brick: crates/weebo-si-kubearmor-policy
supersedes: []
superseded-by: []
---

# RFC 0006 — kubearmor-policy

## Summary

`kubearmor-policy` decides what a workspace pod is allowed to *do* — which binaries it may
execute, which paths it may touch, which Linux capabilities it may use — per team, on the
[RFC 0002](./0002-weebo-si-operator.md) chassis. Same catalogue-and-grants shape
[`network-profiles`](./0004-network-profiles.md) and [`image-policy`](./0005-image-policy.md)
already use: an admin authors a catalogue of `KubeArmorPolicy` templates, grants each team a
subset, and a workspace picks inside what its team was granted. This is the first brick in the
series enforced through the kernel — via KubeArmor's LSM backend (BPF-LSM, AppArmor, or SELinux,
whichever the node offers) — rather than through the network stack or the apiserver, and the
first whose enforcement guarantee is a property of the *node*, not the *cluster*.

`kubearmor-policy` is the first of what the title says: a runtime security policy brick. It
targets [KubeArmor](https://kubearmor.io/) because that is the enforcement engine already
evaluated for this project; a second engine — for example one built on
[Tetragon](https://tetragon.io/) — is a distinct `Backend` variant and its own RFC amendment,
per *Alternatives considered* and *Future work* below, not a redesign of this one.

## Motivation

Everything up to this RFC narrows what a workspace pod can *reach*
([RFC 0004](./0004-network-profiles.md)) and what image it can *run*
([RFC 0005](./0005-image-policy.md)). Neither narrows what the process inside that image, once
running, can *do* on the node it lands on. A devfile's `postStart` command, an `npm install`
script, an extension pulled in by URI — all of it runs as the container's own process tree, with
every syscall, every file under the container's rootfs, and every Linux capability the container
spec grants, available to use. `image-policy` stops the wrong binary from being pulled;
nothing stops the right binary from spawning a shell, reading `/etc/shadow` if it is mounted, or
using `CAP_NET_RAW` to build a raw socket the network baseline never anticipated.

Kubernetes' own primitives cover part of this and stop short in a specific way: a `SecurityContext`
and a `seccomp`/`AppArmor` profile are set once, at pod creation, from whatever the devfile or the
DevWorkspace Operator config wrote, and enforced identically for the life of the container. There
is no per-team routing — the same profile a data team's project needs (writing to a mounted
credential helper) is either granted cluster-wide or denied cluster-wide, the exact problem
[RFC 0004](./0004-network-profiles.md) and [RFC 0005](./0005-image-policy.md) both name for their
own layer. And a static profile cannot express "audit for two weeks, then block" — the rollout
shape every other brick in this project uses.

**KubeArmor exists precisely to close this**, as a `DaemonSet` watching pod creation and
programming the node's LSM (BPF-LSM on a 5.7+ kernel, AppArmor, or SELinux, in that
preference) with rules from a `KubeArmorPolicy` object: process execution, file access, network
operation, and Linux capability use, each rule carrying its own `Allow`/`Audit`/`Block` action.
It is the runtime-enforcement half of what this project's `NetworkPolicy`/`CiliumNetworkPolicy`
pair is for the network layer. **What KubeArmor does not do is decide *who* gets *which*
policy** — that routing, exactly like `network-profiles`' routing over `NetworkPolicy`, is what
this RFC adds.

**The granularity is per team, not per cluster**, for the same reason as every prior brick: a
team whose workloads need to write to `/tmp` and spawn `git` should not set the policy every
other team runs under, and a team that needs nothing beyond the baseline should not have to ask
for it.

**Outcome we are buying:** every workspace pod runs under a mandatory process/file/capability
baseline, reachable beyond it only through profiles its team was granted; a cluster where
KubeArmor's LSM backend is unavailable on a node says so — the workspace either does not start
there or runs visibly unenforced, never silently — and the admin authors real `KubeArmorPolicy`
objects, never a DSL this project invented.

## Guide-level explanation

`kubearmor-policy` starts `Off`, per the chassis. It needs the same three things
`network-profiles` needs — a catalogue, a baseline, and grants against `spec.teams` — plus one
KubeArmor is opinionated about that `NetworkPolicy` never was: a default posture per rule domain
for what happens when nothing in a policy matches.

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams:
    - name: team-1
      namespaceSelector:
        matchLabels: { weebo.io/team: team-1 }
  features:
    kubearmorPolicy:
      mode: DryRun
      catalog:
        - key: base
          templateRef: { name: weebo-base-runtime, namespace: weebo-si-hardening }
        - key: git-write
          templateRef: { name: weebo-git-write-runtime, namespace: weebo-si-hardening }
      baseline: base
      grants:
        team-1:
          allowed: [git-write]
          default: [git-write]
      onNotGranted: Default
      enforcement:
        backend: KubeArmor
```

`weebo-base-runtime` and `weebo-git-write-runtime` are ordinary `KubeArmorPolicy` objects an
admin writes and applies to the `weebo-si-hardening` namespace, the same way `weebo-base` is an
ordinary `NetworkPolicy` for `network-profiles`. This brick never reads their rules — it copies
`spec.process`, `spec.file`, `spec.network`, `spec.capabilities` and `spec.syscalls` verbatim
into a per-workspace copy whose `selector.matchLabels` is rewritten to
`controller.devfile.io/devworkspace_id: <this workspace>`, exactly as `network-profiles` rewrites
a `NetworkPolicy`'s `podSelector`.

At `DryRun`, the reconciler computes the diff and logs it; nothing is written. At `Enforce`, the
object is applied and KubeArmor picks it up on its own watch — this brick writes `KubeArmorPolicy`
objects only, never the pod itself, so the per-pod `kubearmor-policy: enabled | audited |
disabled` annotation KubeArmor optionally reads is out of its reach: it exists only when the
cluster's KubeArmor install opted into `enableEnforcerPerPod`, and setting it would mean mutating
a pod this brick does not create, which is `dwoc-pin`'s and DevWorkspace Operator's territory, not
this one's (see *Unresolved questions*). This RFC's design assumes the more common install shape
— enforcement on by default, no per-pod opt-in required — and treats the opt-in case as something
this brick observes and reports on, never drives. What an operator sees when it works: `kubectl get kubearmorpolicy -n
<workspace-ns>` lists `weebo-base` — one per namespace — and, if the workspace asked for it,
`weebo-git-write-<devworkspace-id>`, one per workspace per granted key: the id is part of the
*name* and not only of the selector, since two workspaces in one namespace granted the same key
would otherwise write the same object twice and each pass would fight the other;
`kubearmor-relay`'s logs carry an `Audit` or `Block` event per matched rule, tagged with the
policy name. What they see when the *node* a workspace pod landed on cannot enforce at all: that
node's `kubearmor.io/enforcer` label is absent or reports nothing usable — a label KubeArmor's
own operator sets per node, not a signal this brick invents — and this brick's
`weebo_si_kubearmor_enforced` gauge drops for that pod once it cross-references the pod's
`spec.nodeName` against the label. The degradation is named, per `network-profiles`' own bar for
this ("not applied, not approximated"), just off a node label instead of a pod annotation.

## Design

### Contract

- **`spec.features.kubearmorPolicy`** on `WeeboSiConfig`, following the shape
  [`NetworkProfilesConfig`](../../crates/weebo-si-crd/src/network_profiles.rs) already
  establishes, with the fields renamed to this brick's vocabulary and one field added:

  - `mode: FeatureMode` — required, no implicit default, per RFC 0002.
  - `namespaceSelector: Selector` — optional, narrows the controller's own scope.
  - `catalog: RuntimeProfileCatalog` — `{key: RuntimeProfileKey, templateRef: TemplateRef}[]`.
    Unlike `network-profiles`, there is exactly one backend today, so a catalogue entry carries
    one `templateRef` directly rather than a `variants` list — the `Variant`/multi-backend shape
    is deferred until a second backend actually exists (see *Alternatives considered*), not
    speculatively built now.
  - `baseline: RuntimeProfileKey` — applied to every workspace pod in scope, never negotiable.
  - `grants: BTreeMap<String, RuntimeProfileGrant>` — `{allowed: [...], default: [...]}`, same
    shape and same validation rules as `ProfileGrant` (`GrantAllowedUnknownKey`,
    `GrantDefaultOutsideAllowed`, `GrantNamesUndeclaredTeam`).
  - `onNotGranted: OnNotGranted` — `Default | Deny`, same enum `network-profiles` defines,
    reused rather than redeclared.
  - `workspaceSelection` / `namespaceSelection` — same two-tier selection (devfile attribute,
    then namespace annotation) as `network-profiles`, same default annotation/attribute name
    pattern (`hardening.weebo.io/kubearmor-policy`).
  - `enforcement.backend: EnforcementBackend` — `Auto | KubeArmor`, mirroring
    `network-profiles::EnforcementBackend`'s shape for the one real reason to keep it: a second
    backend later is a new variant and a resolver change, not a schema break.
  - `enforcement.defaultPosture: DefaultPosture` (**new relative to `network-profiles`**) —
    `{file: Posture, network: Posture, capabilities: Posture}`, `Posture = Audit | Block`,
    written onto KubeArmor's own namespace-level `kubearmor-file-posture` /
    `kubearmor-network-posture` / `kubearmor-capabilities-posture` annotations. **Three fields,
    not four**: KubeArmor has no separate process posture — process rules are evaluated under
    the *file* posture — so a fourth field would be dead contract surface asking to be
    misconfigured. `NetworkPolicy` has no equivalent knob at all — an unmatched packet is simply
    dropped by the baseline's own default-deny rule — so this is genuinely new surface, not a
    renamed field.

- **Managed objects**: `KubeArmorPolicy` (namespaced), written with
  `hardening.weebo.io/managed-by: weebo-si-operator`, one per `{workspace, granted profile}` plus
  one baseline per namespace — same population shape `network-profiles` reports through
  `weebo_si_network_managed_objects`, this brick's equivalent named
  `weebo_si_kubearmor_managed_objects`.

  The baseline's selector is `matchLabels: {}`, which KubeArmor reads as **every pod in the
  policy's own namespace** — the baseline's meaning exactly, and the reason it needs no label of
  its own to select on. Stated in the contract rather than left to the JSON's shape because the
  alternative reading is silent: if an empty map selected nothing, every baseline this brick
  writes would be inert while `weebo_si_kubearmor_managed_objects` and
  `weebo_si_kubearmor_enforced` both read healthy.
- **New metric**: `weebo_si_kubearmor_enforced{state}` — a gauge counting workspaces per state:
  `enforced` (the node hosting the workspace's pods carries a `kubearmor.io/enforcer` label
  naming a real enforcer), `not_enforced` (the label is absent or empty), `unknown` (no pod is
  scheduled, or its node is not in the cache). All three are always published, including the
  zeroes, so `state="not_enforced" > 0` reads `0` rather than *absent* on a healthy cluster and
  is therefore alertable. This is the canary `network-profiles` gets from a synthetic probe; here
  it is derived by joining two read-only watches (`Node` labels, `Pod.spec.nodeName`) instead,
  because there is no cluster-wide "does the CNI support this" question to ask — the answer is
  per node (see *Security considerations → Bypass*).

  > **Amended during implementation.** This was first specified as
  > `weebo_si_kubearmor_enforced{namespace,workspace}` — a gauge per workspace. That contradicts
  > [RFC 0004](./0004-network-profiles.md)'s *Observability contract*, which rules project-wide
  > that "no metric carries a namespace or a workspace id as a label... a per-workspace time
  > series is how a metrics backend is taken down by a hardening component." Building it as
  > written would have made this brick the one that does it. Counting workspaces per state alerts
  > identically and costs three series instead of two per workspace; **which** workspace is
  > unenforced is a `WARN` log line and a `kubectl get pod -o wide`, the same answer RFC 0004
  > gives for its own per-namespace questions. The `unknown` state is new here and is not folded
  > into `not_enforced` on purpose: "we have not looked" and "we looked and there is nothing
  > there" are different claims, and only the second should page anyone.
- **CLI**: `weebo-si-operator backends kubearmor` — prints whether the `KubeArmorPolicy` CRD is
  installed (cluster-wide capability) and, if `--verbose`, every node's `kubearmor.io/enforcer`
  label (node-level capability) — the two are different questions and the command answers both
  rather than collapsing them.

### Architecture

**Hexagonal, yes**, against the three criteria in
[`hexagonal.md`](../architecture/hexagonal.md):

1. Real decision — the same catalogue/grant/backend resolution `network-profiles` makes, table-driven.
2. Touches an external system — the Kubernetes API, same as every reconciling feature.
3. We want the routing decision (does this workspace's team reach this profile key?) tested
   without a cluster, and it is the same test suite shape `network_profiles.rs`'s `validate()`
   already proves out.

`crates/weebo-si-kubearmor-policy` mirrors `weebo-si-network-profiles`'s module layout exactly:
`feature/` (the `ReconcileFeature<S>` implementation, one `Subject` for the namespace-scoped
baseline and one for the workspace-scoped grants, same split as `network-profiles` and the same
reason — the baseline should not be recomputed on every workspace event), `model/policy.rs`
(`ManagedObject`, `ObjectKey`, `PodSelector` — reused, not redefined: KubeArmor selects pods by
`matchLabels` exactly like `NetworkPolicy` does, so `PodSelector` moves to `weebo-si-chassis`
in this RFC's implementation plan rather than being duplicated), `model/diff.rs` (reused diff
machinery — a `KubeArmorPolicy` and a `NetworkPolicy` diff the same way: compare spec bodies
under a managed-by label filter), `port.rs` (`Capabilities`, `TemplateStore`, `PolicyStore`,
`BaselineView` — same four ports, same signatures, parameterized over this crate's `Backend`
which today has one member).

**One real difference from `network-profiles`'s architecture, not cosmetic:** `Capabilities`
there answers a cluster-wide question (does the apiserver serve `CiliumNetworkPolicy`) that is
stable and knowable *before* writing anything. Here, "is this cluster capable" (does it serve
`KubeArmorPolicy`) and "does the object actually get enforced on the node this pod lands on"
are two different questions, and only the first is knowable in advance — the domain's decision
to write the object is still made from `Capabilities` alone, per the existing port, but the
*consequence* of that decision is now something a separate signal (the `kubearmor.io/enforcer`
node label, joined against the pod's `spec.nodeName` and surfaced as
`weebo_si_kubearmor_enforced`) reports after the fact rather than something `resolve_backend`
can guarantee up front. That join is a new port on this crate — `NodeEnforcerView`, alongside
`Capabilities`/`TemplateStore`/`PolicyStore`/`BaselineView` — since it reads a resource
(`Node`) none of `network-profiles`' ports ever needed. This asymmetry is called out again in
*Security considerations* and is why this RFC adds a metric where `network-profiles` added a
canary probe instead — a synthetic probe would tell us the CRD works, not that a real workspace's
random node has the LSM engaged.

### Data and state

Effectively stateless, same as every reconciling feature on this chassis: a watch-backed cache of
`WeeboSiConfig`, `DevWorkspace`, and `Namespace`, rebuilt on restart before `/readyz` goes true.
Two additions, both read-only and both feeding `NodeEnforcerView` alone — neither the reconcile
decision nor `PolicyStore` ever reads them: a watch on `Pod` (filtered to workspace pods by
`controller.devfile.io/devworkspace_id`, projected down to `spec.nodeName` only — the same
"bounded projection, not the full object" discipline `NamespaceFacts` already established), and
a **cluster-scoped** watch on `Node` (projected to `metadata.labels["kubearmor.io/enforcer"]`
only). `network-profiles` never needed either, because `NetworkPolicy` enforcement is invisible
to the object itself and to the node; this brick's is not, and the `Node` watch in particular is
this project's first cluster-scoped watch outside the chassis's own `WeeboSiConfig` — flagged
again under *Security considerations*.

## Security considerations

- **Privileges.** The controller role gains `get`/`list`/`watch`/`create`/`update`/`delete` on
  `kubearmorpolicies.security.kubearmor.com` in workspace namespaces, read-only `watch` on `pods`
  (the `spec.nodeName` field only — see *Secrets*), and — **new for this project** — read-only
  `get`/`list`/`watch` on the cluster-scoped `nodes` resource, narrowed in the adapter to one
  label. Every prior brick's RBAC stayed inside namespaces it already reconciled; this is the
  first time this project's controller reads anything cluster-scoped that is not its own CRD.
  The narrowing is enforced in the adapter (project to one label before the value leaves the
  watch handler), not by RBAC, because Kubernetes RBAC has no field-level grant for `Node` — the
  same "RBAC can't express it, so the boundary is in code and reviewed as code" trade this
  project already accepts for `NamespaceFacts`. No new privilege on KubeArmor's own `DaemonSet`;
  this brick never talks to the KubeArmor agent directly, only writes objects KubeArmor's own
  controller watches and reads a label KubeArmor's own operator writes, same trust split as
  `network-profiles` has with the CNI.
- **Trust boundary.** The catalogue and grants are admin-authored, same boundary as every prior
  brick — not attacker-controlled. The attacker-controlled input is the devfile attribute /
  namespace annotation selecting *which granted key* to apply, exactly the boundary
  `network-profiles`' `WorkspaceSelection` already defends: an ungranted key is dropped to the
  team's default (or denied, per `onNotGranted`), never escalated.
- **Bypass — the one genuinely new one.** A `KubeArmorPolicy` object existing does not mean it is
  enforced: a node without BPF-LSM, without the AppArmor kernel module, and without SELinux in
  enforcing mode gives KubeArmor nothing to program. KubeArmor's own documented behaviour is to
  run that node in audit/visibility-only mode — observability continues via eBPF, which needs no
  LSM, but `Block` rules never actually block — and to say so via that node's own
  `kubearmor.io/enforcer` label, never by refusing to run. **This brick inherits that fail-open
  behaviour and does not override it** — overriding it would mean refusing to schedule a
  workspace pod on a node the scheduler already picked, which is a cluster-admission decision
  this brick does not own (see *Future work*, a validating companion). What this brick owns is
  making the gap visible: `weebo_si_kubearmor_enforced` at `0`, not a metric that goes quiet. A
  related bypass this brick cannot close, only observe: on a cluster where `enableEnforcerPerPod`
  is on, the `kubearmor-policy` pod annotation is the thing that actually decides
  `enabled`/`audited`/`disabled` for a given pod, and nothing about *this* brick's objects
  touches it — a workspace owner (or a devfile) setting it to `disabled` on their own pod, where
  RBAC allows that at all, is invisible to `weebo_si_kubearmor_managed_objects` and only shows up
  in the same `weebo_si_kubearmor_enforced` gauge, indistinguishable from a genuine node
  capability gap. Every other bypass is the same shape as `network-profiles`': a workspace created
  before this feature's rollout and never restarted, a `namespaceSelector` gap, a workspace pod
  created without going through DevWorkspace at all.
- **Blast radius.** A wrong `default` or a wrong entry behind a widely-granted key over-permits a
  process/file/capability surface for every workspace routed through it on its next start — the
  same shape as `network-profiles`, bounded the same way (`DryRun`, per-feature
  `namespaceSelector`, per-entry catalogue validation, rollback by reverting the config). A
  compromise of the operator is again worse than either individually reachable failure: the
  ability to write an arbitrary `KubeArmorPolicy` **allowing** what the baseline denies,
  fleet-wide. Nothing here reduces that below "do not let this deployment be compromised."
- **Secrets.** Reads none. The `Pod` watch reads labels and annotations only — the field list is
  explicit in the adapter (`kubearmor-policy`/`kubearmor.io/enforcer` and the
  `devworkspace_id` label), never the pod spec, never env vars, never mounted volumes. Logs carry
  the namespace, workspace, profile key and decision — never the object.

## Operational considerations

- **Failure mode.** This is a controller writing objects, not a webhook — same failure shape as
  `network-profiles`: an outage stops new/changed grants from being applied, existing
  `KubeArmorPolicy` objects (and their enforcement) are unaffected. Fail-open at the *brick*
  level in the sense that nothing here blocks pod creation; the node-level fail-open described
  under *Bypass* is KubeArmor's own documented behaviour, inherited rather than chosen.
- **Rollout.** `DryRun` first, cluster-wide or behind a `namespaceSelector`, exactly like
  `network-profiles`. The natural first `baseline` is intentionally narrow (deny process
  execution outside the image's own installed paths, deny writes outside `/tmp` and the
  workspace's project mount) precisely because KubeArmor's per-rule `Audit` action lets an admin
  author a template that logs without blocking — the rollout shape this project already uses one
  layer up (`mode: DryRun`) is available a second time, inside the template itself, and both
  should typically be used together during the first rollout.
- **Rollback.** Flip `mode` back to `Off` or `DryRun`; the reconciler deletes what it manages
  (`managed-by: weebo-si-operator`) on the next pass, same as `network-profiles`. Faster rollback
  — for a single misbehaving profile — is deleting or editing the template object directly, since
  templates are ordinary objects an admin already has RBAC on.
- **Observability.** `weebo_si_kubearmor_managed_objects`, `weebo_si_kubearmor_enforced`, and
  KubeArmor's own `kubearmor-relay` event stream (`Audit`/`Block` per rule, per pod) together
  answer "is this working" and "is this actually enforced here" — two questions
  `network-profiles` could answer with one signal (the canary) because its enforcement guarantee
  did not vary per node.
- **Upgrade.** Rolling update of the controller: the watch caches rebuild, `/readyz` gates
  traffic, no `KubeArmorPolicy` object is touched mid-rollout because the desired state is
  unchanged. A version bump of KubeArmor itself, upstream, is out of this project's control —
  the annotation name it uses to report enforcement is a dependency to pin against, called out
  under *Unresolved questions*.

## Alternatives considered

- **Do nothing — leave runtime behaviour to `SecurityContext`/`seccomp` alone.** Cluster-wide
  granularity only, the exact problem this RFC's *Motivation* argues against; kept as the floor
  this brick builds on top of, not a replacement for it.
- **Tetragon**, an eBPF-based alternative with strong observability and an
  in-kernel enforcement mode of its own. Not chosen as the *first* backend because KubeArmor's
  policy CRD is closer in shape to `NetworkPolicy` (declarative, matchLabels-selected,
  per-rule action) which keeps this RFC's catalogue/grant pattern a direct port rather than a
  redesign; the `EnforcementBackend` enum is built with a second variant in mind specifically so
  Tetragon (or another engine) is an amendment, not a rewrite, if the KubeArmor bet does not pay
  off or a cluster genuinely needs both.
- **Falco**, detection-only by design (it alerts, it does not block). Valuable as a second,
  independent signal but not a substitute for an enforcement engine — this project already has
  a pattern (`network-profiles`' canary) for "prove the control still works," and a
  detection-only tool does not give us a *control* to prove.
- **Hand-written `KubeArmorPolicy` per namespace.** Works for a fixed cluster, same objection as
  every prior brick's *Alternatives*: a new workspace namespace goes unprotected until someone
  notices it exists.
- **A policy engine's `generate` rules (Kyverno).** Handles the "stamp a namespace baseline"
  half well, same as it does for `network-profiles`; stops short of the per-workspace,
  per-team-grant half, and stops short entirely of anything KubeArmor-specific like reading the
  enforced/not-enforced annotation back.

## Drawbacks and risks

A fourth CRD this project's controller now watches and writes, a fourth external dependency
(KubeArmor itself, which this project does not install or manage) whose upstream API and
annotation names can move under us — pinned in the implementation, not vendored. The node-level
enforcement gap described under *Security considerations* is a real limitation of the underlying
tool, not something this RFC's design can close; the honest position is to surface it, not to
promise more than KubeArmor itself promises. Running a fourth reconcile loop per workspace event
adds apiserver load proportional to workspace count, same shape `network-profiles` already
carries and already budgets for.

## Unresolved questions

Resolved since the first draft, kept here as a record rather than deleted silently:

- ~~The exact per-pod signal reporting enforcement status.~~ **Resolved: there is no per-pod
  signal.** KubeArmor reports enforcement capability per *node*, via the `kubearmor.io/enforcer`
  label its own operator sets (`bpf` / `apparmor` / `selinux`, absent when nothing usable); the
  per-pod `kubearmor-policy` annotation (`enabled` / `audited` / `disabled`) is a desired-state
  request, not an observed-state report. *Design → Contract* and *Architecture* now reflect this.
  Version pinned to the v1.7 line (current stable at the time of writing, v1.7.3) — worth
  reconfirming the label name and its semantics have not changed once implementation actually
  starts, since it is documented behaviour rather than a versioned API guarantee.
- ~~Where `defaultPosture` belongs.~~ **Resolved: kept local to this feature.** No second brick
  needs a shared "how strict by default" knob today; hoisting it to the chassis is a future
  amendment if that changes, per the same pattern RFC 0002 used for `spec.teams`.
- ~~Whether `KubeArmorHostPolicy` is in scope.~~ **Resolved: explicitly out of scope**, tracked
  under *Future work*. It governs the node, not the workspace — a cluster-operator-facing
  surface with a different trust boundary than this RFC's per-team routing, and nothing today
  drives building it alongside this brick.

Genuinely still open:

- **`weebo_si_kubearmor_enforced` cannot distinguish "this node has no usable LSM" from "this pod
  was opted out via its own `kubearmor-policy` annotation"** on a cluster running with
  `enableEnforcerPerPod` on — both read back as the same `0`, per *Security considerations →
  Bypass*. Splitting them needs a second metric label or a second gauge; deferred rather than
  guessed at, since it only matters on an install shape this RFC does not assume by default.
- **Whether this project should document, or actively check for, `enableEnforcerPerPod: false`**
  as a supported-install precondition — since this brick has no way to *set* the per-pod
  annotation itself (see *Guide-level explanation*), a cluster running the opt-in mode gets
  enforcement this brick cannot fully account for. Leaning toward documenting it as a
  precondition rather than building around it, but not decided.
- **Whether `policy-guard` should cover `kubearmorpolicies`.** *(Raised by implementation;
  answered yes — the design is [RFC 0008](./0008-policy-guard-coverage.md), and this entry closes
  when that RFC ships.)* RFC
  0004's guard denies non-operator writes to objects carrying the managed-by label, and it covers
  `networkpolicies` and `ciliumnetworkpolicies` only. Nothing stops a user with `edit` on
  `kubearmorpolicies` in their own namespace from rewriting the policy that constrains their own
  workspace — the controller puts it back on the next pass, but there is a window, and unlike the
  network case there is no admission-time refusal. Extending the guard is a new target for an
  existing brick and therefore its own RFC amendment, per [the process](./readme.md).

  This has a concrete consequence already in the code: the `KubeArmorPolicy` store **force-applies**
  where `network-profiles`' store does not. Server-side apply refuses to overwrite a field another
  manager owns, so a single `kubectl edit` would otherwise make this operator's every subsequent
  apply fail with a 409 — the drift this brick exists to correct becoming exactly the drift it can
  no longer correct. `network-profiles` can afford not to force because the guard stops the edit
  before a field manager exists; this brick cannot, until the guard covers it.

## Future work

- **A validating companion**, rejecting a workspace pod scheduled to a node that cannot enforce
  its assigned profile, rather than letting it run not-enforced — the admission-side complement
  the *Bypass* discussion above explicitly declines to build in this RFC. Needs its own
  fail-open/fail-closed argument, likely harder than `image-policy`'s because "can this node
  enforce" is not knowable at admission time without a node-readiness signal this project does
  not yet have.
- **A second `EnforcementBackend` variant** (Tetragon or another eBPF-based engine), once a
  concrete cluster needs it — the enum and the `Auto` resolution are shaped for this already,
  per *Design → Contract*.
- **`KubeArmorHostPolicy` support**, per the unresolved question above.
- **Feeding `kubearmor-relay`'s `Block` events into this project's own alerting**, rather than
  leaving them in KubeArmor's own log stream — valuable, and explicitly deferred so this RFC
  stays about routing policy, not about building a SIEM pipeline.

## Implementation plan

- [x] `weebo-si-crd`: `RuntimeProfileKey`, `RuntimeProfileCatalog`, `RuntimeProfileGrant`,
      `KubeArmorPolicyConfig` (`mode`, `namespaceSelector`, `catalog`, `baseline`, `grants`,
      `onNotGranted`, `namespaceSelection`, `workspaceSelection`, `enforcement`), reusing
      `OnNotGranted` and `TemplateRef` from `network_profiles.rs` rather than redeclaring them
- [x] Promote `PodSelector` (and any other genuinely backend-agnostic type `network_profiles.rs`
      currently owns) to `weebo-si-chassis`, so this crate does not duplicate it — `ObjectKey`
      came with it, and so did the diff machinery this RFC's *Architecture* calls reused
      (`Diff`, `compute_diff`, `Applied`, `tally`, now generic over a `Managed` trait each
      feature implements for its own object type). That last part was RFC 0007's checklist item
      until this brick made it due a release earlier
- [x] `crates/weebo-si-kubearmor-policy`: `port.rs` (`Capabilities`, `TemplateStore`,
      `PolicyStore`, `BaselineView`, `NodeEnforcerView`), `model/` (`ManagedObject`, diff),
      `feature/` (namespace and workspace `Subject`s, `ReconcileFeature<S>` impl), `resolve.rs`
      (grant resolution, ported from `network-profiles`' `resolve.rs` with the vocabulary renamed)
- [x] `backend.rs`: `resolve_backend` over `EnforcementBackend::{Auto, KubeArmor}` — trivial today
      (one member), written so a second variant is additive
- [x] Outbound adapter: `KubeArmorPolicy` CRD client, `managed_in`/`managed_everywhere`/`apply`
      against the real apiserver
- [x] `Pod` watch adapter projecting `spec.nodeName` only, and a cluster-scoped `Node` watch
      adapter projecting `metadata.labels["kubearmor.io/enforcer"]` only, joined behind
      `NodeEnforcerView`; `weebo_si_kubearmor_enforced` gauge built from the join
- [x] `weebo-si-operator backends kubearmor` CLI subcommand, `--verbose` listing every node's
      `kubearmor.io/enforcer` label
- [x] Envtest suite: catalogue/grant validation table, diff/apply round-trip, `DryRun` writes
      nothing, `Enforce` writes and reconciles drift
- [x] Helm RBAC behind `kubearmorPolicy.rbac.enabled` (off by default): write on
      `kubearmorpolicies`, `patch` on `namespaces` for the posture annotations, read on
      `nodes`/`pods` for the join — not a box this plan anticipated, and the largest grant
      in the repo after `network-profiles`'
- [x] Docs updated
- [x] RFC flipped to `Implemented`

## References

- [KubeArmor](https://kubearmor.io/) — project docs, `KubeArmorPolicy` CRD reference.
- [KubeArmor: policy specification](https://docs.kubearmor.io/kubearmor/documentation/security_policy_specification) —
  `process`/`file`/`network`/`capabilities`/`syscalls` rule domains and the `Allow`/`Audit`/`Block`
  action model this RFC's templates copy verbatim.
- [KubeArmor: Security Posture](https://docs.kubearmor.io/kubearmor/documentation/default_posture) —
  the `defaultFilePosture`/`defaultNetworkPosture`/`defaultCapabilitiesPosture` config and the
  matching `kubearmor-*-posture` namespace annotations `enforcement.defaultPosture` maps onto;
  the source for "process has no separate posture, it is evaluated under file."
- [KubeArmor: FAQ](https://github.com/kubearmor/KubeArmor/blob/main/getting-started/FAQ.md) and
  [`karmor probe`](https://github.com/kubearmor/kubearmor-client) — how enforcement capability is
  detected per node (`Active LSM`), the source for treating this as a node question, not a pod one.
- [GitHub discussion: why use annotation `kubearmor-policy: enabled`](https://github.com/kubearmor/KubeArmor/discussions/282) —
  confirms `kubearmor-policy` (`enabled`/`audited`/`disabled`) is a desired-state request tied to
  `enableEnforcerPerPod`, not an observed-state report.
- [Tetragon](https://tetragon.io/) — the alternative engine discussed under *Alternatives*.
- [RFC 0002](./0002-weebo-si-operator.md) — the chassis, `spec.teams`, `ReconcileFeature<S>`.
- [RFC 0004](./0004-network-profiles.md) — the catalogue/grant/backend pattern this RFC ports.
- [RFC 0005](./0005-image-policy.md) — the sibling brick narrowing what image runs, as this one
  narrows what that image's process is allowed to do once running.

## Changelog

| Date | Change |
| --- | --- |
| 2026-08-25 | A profile object's name carries the devworkspace id (`weebo-<key>-<id>`), not only its selector. Two workspaces in one namespace granted the same key would otherwise write one object twice and fight over it every pass — and RFC 0004 had already settled this naming, which this RFC's *Guide-level explanation* had quietly diverged from. |
| 2026-08-25 | `weebo_si_kubearmor_enforced` is labelled `{state}` and counts workspaces, not `{namespace,workspace}`. Writing it as first specified would have made this the brick that breaks RFC 0004's project-wide "no metric carries a namespace or a workspace id" rule. Taught us that a per-brick observability contract can contradict a project-wide one without either author noticing. |
| 2026-08-25 | The `KubeArmorPolicy` store force-applies, where `network-profiles`' store does not. Found by envtest, not by review: one `kubectl edit` makes the editor a field manager, and every later server-side apply fails 409 — the drift this brick exists to correct becoming the drift it can no longer correct. `network-profiles` is safe only because `policy-guard` refuses that edit first, which is why the guard's coverage gap is now an open question rather than an omission. |
| 2026-08-25 | The baseline's `selector.matchLabels: {}` is recorded in the *Contract* as meaning every pod in the namespace. It was an inference from the CRD schema until confirmed; the alternative reading is silent, and would have left every baseline inert while both gauges read healthy. |
