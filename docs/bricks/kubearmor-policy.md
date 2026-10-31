# `kubearmor-policy`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and rationale:
[RFC 0006](../rfc/0006-kubearmor-policy.md), and [RFC 0008](../rfc/0008-policy-guard-coverage.md)
for how `policy-guard` protects what it writes. Field reference:
[`features.kubearmorPolicy`](../weebosiconfig.md#featureskubearmorpolicy). The operator's own
install, CLI and break-glass are on [`weebo-si-operator.md`](./weebo-si-operator.md); this page
assumes it is installed.

[`network-profiles`](./network-profiles.md) decides what a workspace may *reach* and
[`image-policy`](./image-policy.md) which image it may *run*.
This feature decides what the process inside that image may *do* on the node it lands on — which
binaries it may execute, which paths it may touch, which capabilities it may use — per team,
through [KubeArmor](https://kubearmor.io/).

**It is the first control in this operator whose enforcement is a property of the node, not the
cluster.** A `KubeArmorPolicy` this operator writes is enforced only where KubeArmor found a
usable LSM (BPF-LSM, AppArmor, or SELinux). On a node without one, KubeArmor's documented
behaviour is to run in visibility-only mode: the object exists, the events flow, and `Block`
rules do not block. This operator does not override that — it makes it visible. Read
*Observability* below before you rely on this feature for anything.

## Install checklist

1. **KubeArmor is installed and its CRDs are served.** This operator does not install it. Check
   with the CLI:

   ```bash
   weebo-si-operator backends kubearmor --verbose
   ```

   The first table answers "does this cluster serve `KubeArmorPolicy`" — the cluster-wide
   question. The second answers "which nodes can actually enforce one" — the per-node question.
   They are different questions and a cluster can pass the first and fail the second on half its
   fleet. Run this before switching anything on.

   If the CRD is absent, the controller logs `kubearmor-policy is inert` at boot and starts none
   of its watches. That is a supported state: the feature simply does not run there.

2. **Grant the RBAC.** Off by default, because granting write on a CRD a cluster does not have is
   a permission nobody can use and everybody has to review:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set kubearmorPolicy.rbac.enabled=true
   ```

   This adds, on the controller role only: write on `kubearmorpolicies` cluster-wide, `patch` on
   `namespaces` (for KubeArmor's three posture annotations), and read on `nodes` and `pods`. The
   last two are this project's first cluster-scoped reads outside its own CRD — see *What this
   reads* below.

3. **Author the templates.** Ordinary `KubeArmorPolicy` objects in `weebo-si-hardening`, exactly
   as `network-profiles`' templates are ordinary `NetworkPolicy` objects. Their own `selector` is
   stripped from every copy — scoping belongs to the operator — **but it is live on the template
   itself**, which KubeArmor enforces in `weebo-si-hardening` like any other policy. Select a
   label no pod carries, or a `Block` rule meant for workspaces lands on the operator's own pods.

   ```yaml
   apiVersion: security.kubearmor.com/v1
   kind: KubeArmorPolicy
   metadata:
     name: weebo-base-runtime
     namespace: weebo-si-hardening
   spec:
     selector:
       # Stripped from every copy, but live on this template: select nothing here.
       matchLabels: { hardening.weebo.io/template: "never-matches" }
     process:
       matchPaths:
         - path: /usr/bin/git
           action: Audit
   ```

   **Start every rule at `action: Audit`.** KubeArmor's per-rule action gives you a second dry run
   *inside* the template, and the first rollout should use both it and `mode: DryRun`.

4. **Configure the feature**, starting at `DryRun`:

   ```yaml
   features:
     kubearmorPolicy:
       mode: DryRun
       catalog:
         - key: base
           templateRef: { name: weebo-base-runtime, namespace: weebo-si-hardening }
         - key: git-write
           templateRef: { name: weebo-git-write-runtime, namespace: weebo-si-hardening }
       baseline: base
       onNotGranted: Default
       enforcement:
         backend: Auto
         defaultPosture:
           file: Audit
           network: Audit
           capabilities: Audit
   ```

   `defaultPosture` is what KubeArmor does with an operation **no rule matched**, written onto
   each namespace as its three `kubearmor-*-posture` annotations. There are three, not four:
   process rules are evaluated under the *file* posture. All three default to `Audit`, and moving
   one to `Block` is the single most consequential edit in this feature — it denies everything the
   template did not think to allow, which for a workspace container is most of what it does.

## What gets written

| Object | One per | Name | Selector |
| --- | --- | --- | --- |
| `KubeArmorPolicy` | namespace in scope | `weebo-base` | `matchLabels: {}` — every pod |
| `KubeArmorPolicy` | workspace × granted key | `weebo-<key>-<devworkspace-id>` | that workspace's pods |
| namespace annotations | namespace in scope | `kubearmor-{file,network,capabilities}-posture` | — |

Everything carries `hardening.weebo.io/managed-by: weebo-si-operator`, and the operator only ever
reads, updates or deletes objects that do.

## Rollout

1. `mode: DryRun`, ideally behind `namespaceSelector` scoped to one pilot team. Read
   `weebo_si_kubearmor_reconcile_total{result="dry_run"}` and the per-namespace log line.
2. `mode: Enforce` with every template rule still at `action: Audit`. Objects are now real,
   postures are written, and nothing is denied yet. Watch `kubearmor-relay`'s event stream for
   what *would* have been blocked — this is the phase that finds the rule you did not know your
   workspaces needed.
3. Flip individual rules to `action: Block` in the templates, narrowest first. A template edit is
   picked up on the next reconcile pass; a running workspace's policy is updated in place.
4. Only then consider `defaultPosture.file: Block`, and only for a team whose audit stream has
   been quiet for a while.

## Rollback

- **One profile is wrong**: edit or delete the template object. Fastest, and needs no
  `WeeboSiConfig` edit.
- **The feature is wrong**: `mode: Off`. The reconciler deletes everything it manages on the next
  pass. Namespace posture annotations are **not** removed — they are KubeArmor's own field and
  removing them would be a second guess about what the namespace should do without us.
- **Break glass**: `helm upgrade --set kubearmorPolicy.rbac.enabled=false` removes the write
  permission entirely. Existing objects stay; nothing can change them.

## Reading the logs

```text
weebo-si-controller: kubearmor-policy namespace=user-alice mode=Enforce diffs=1
  applied=Some(Applied { created: 1, ... }) posture=file=audit,network=audit,capabilities=audit
weebo-si-controller: kubearmor-policy workspace=user-alice/data-pipeline mode=Enforce diffs=1
  applied=Some(Applied { created: 1, ... })
WARN weebo-si-controller: feature=kubearmor-policy team=team-2 workspace=scratch
  requested=[net-raw] result=not_granted
WARN weebo-si-controller: feature=kubearmor-policy namespace=user-alice
  workspace_id=workspacede4f56 result=not_enforced — policy objects exist and the node hosting
  this workspace reports no usable LSM
```

That last line is the one to page on the first time you see it, and the reason the per-workspace
answer lives in a log line rather than a metric label — see below.

## Observability

| Metric | Type | Labels | Where it comes from |
| --- | --- | --- | --- |
| `weebo_si_kubearmor_reconcile_total` | counter | `result` ∈ `created`/`updated`/`unchanged`/`deleted`/`dry_run`/`error`, `team` | reconcile |
| `weebo_si_kubearmor_managed_objects` | gauge | `kind`, `scope` ∈ `baseline`/`profile` | 30s tick |
| `weebo_si_kubearmor_drift_total` | counter | `action` ∈ `restored`/`removed` | reconcile |
| `weebo_si_kubearmor_enforced` | gauge | `state` ∈ `enforced`/`not_enforced`/`unknown` | 60s tick |
| `weebo_si_kubearmor_not_granted_total` | counter | `team`, `profile` | reconcile |
| `weebo_si_feature_mode{feature="kubearmor-policy"}` | gauge | `feature` | config sync |

**`weebo_si_kubearmor_enforced{state="not_enforced"} > 0` is the alert this feature exists to
make possible.** It counts workspaces whose policy objects are present on a node that reports no
usable enforcer — the gap KubeArmor fails open into, made visible. All three states are always
published, including the zeroes, so the query reads `0` rather than *absent* on a healthy cluster.

It counts workspaces rather than naming one: RFC 0004's observability rule ("no metric carries a
namespace or a workspace id as a label") binds every brick here, and a per-workspace time series
is how a metrics backend is taken down by a hardening component. Which workspace is unenforced is
the `WARN` line above, plus `kubectl get pod -o wide`. RFC 0006 originally specified
`weebo_si_kubearmor_enforced{namespace,workspace}`; it was amended during implementation.

`state="unknown"` is not a failure — it is a workspace with no scheduled pod, or one on a node
not yet in the cache. It is deliberately not folded into `not_enforced`: "we have not looked"
and "we looked and there is nothing there" are different claims and only the second should page.

## What this reads

Two read-only watches this project never needed before, both projected before anything is stored:

- **`pods`**, filtered server-side to workspace pods, projected to `{namespace, workspace_id,
  nodeName}`. The spec is dropped in the watch stream — no env, no volumes, no containers.
- **`nodes`**, cluster-scoped, projected to the `kubearmor.io/enforcer` label alone.

Kubernetes RBAC has no field-level grant for either, so that narrowing lives in
`crates/weebo-si-kubearmor-policy-adapters/src/node_enforcer.rs` and is reviewed as code — the same trade this
project already accepts for `NamespaceFacts`.

## Known limitations, specific to this feature

- **A policy object is not enforcement.** Covered above; it is the whole reason for the
  `enforced` gauge. On a cluster whose nodes have no LSM, this feature is an audit trail.
- **The objects are guarded; the posture annotations are not.** `policy-guard` covers
  `kubearmorpolicies` since RFC 0008 — turn on `kubearmorPolicy.rbac.enabled` and the rule is
  rendered with the RBAC grant. What it does *not* cover is the three `kubearmor-*-posture`
  annotations this feature writes onto workspace namespaces: a namespace carries no ownership
  label, and the guard is object-scoped. A user who can annotate their own namespace can move
  their posture from `Block` back to `Audit`. That is visible in the reconcile log and corrected
  on the next pass; guarding it would mean a webhook in front of every namespace write in the
  cluster, which RFC 0008 decided against.
- **The store still force-applies, and that is deliberate.** With the guard on, no conflicting
  field manager should ever be created — but an object edited *before* the guard was installed
  already has one, and without force that object is wedged forever on a 409. The guard prevents
  new conflicts; force is what recovers from old ones.
- **`enableEnforcerPerPod` clusters are only partly accounted for.** Where KubeArmor is installed
  in that mode, a per-pod `kubearmor-policy: disabled` annotation opts a pod out, and this
  operator neither sets nor reads it — such a pod reads back as `not_enforced`, indistinguishable
  from a node with no LSM.
- **Posture annotations are written but never removed.** `mode: Off` deletes the policy objects
  and leaves the namespace's posture as it was.
- **The envtest suite proves what we write, not what KubeArmor does with it.** It runs against a
  stand-in CRD with no daemonset behind it. The baseline's `selector.matchLabels: {}` is
  confirmed to mean "every pod in this namespace" to KubeArmor; the posture annotations' effect
  on a real deployment is not yet confirmed here, and is RFC 0006's own outstanding item.
