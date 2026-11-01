---
rfc: 0014
title: resource-quotas
status: Accepted
authors: [batleforc]
created: 2026-10-31
updated: 2026-11-01
decided: 2026-11-01
brick: crates/weebo-si-resource-quotas
supersedes: []
superseded-by: []
---

# RFC 0014 — resource-quotas

## Summary

`resource-quotas` gives every workspace namespace a `ResourceQuota` and a `LimitRange`, per team,
on the [RFC 0002](./0002-weebo-si-operator.md) chassis. An admin writes each quota profile as real
Kubernetes objects in the operator namespace, the same way [RFC 0004](./0004-network-profiles.md)
templates policies. Each team gets a default profile and may be granted others, and the
controller keeps exactly one of each object in every namespace in scope.

The feature sets a ceiling on what one workspace namespace can consume, and a default for pods
that ask for nothing. It does not size workspaces or manage idling: those belong to DevWorkspace
Operator, through the DWOC that `dwoc-pin` already routes.

## Motivation

A workspace namespace can consume whatever the cluster has.

Nothing in Eclipse Che or in this repository puts a `ResourceQuota` in a workspace namespace. A Che
user is the administrator of their own namespace, so they can create as many pods, persistent
volume claims and services as the cluster will schedule. Che's own limits — the maximum number of
workspaces, or of running workspaces, per user — are checked by Che's components on the paths
they serve. A `kubectl apply` in the user's namespace does not go through them.

That is a security problem as well as a capacity one, and the security half is the one this RFC
cares about:

- **A compromised dependency mines cryptocurrency.** The usual outcome of a malicious `npm`
  post-install script in a CI-like environment, and a workspace is a CI-like environment with a
  person attached. Without a limit, it takes every CPU it can get on the node, and the node's
  other workspaces with it.
- **One namespace takes the node down.** No memory limit means the node's OOM killer chooses
  what dies, and it does not choose by tenant.
- **A `NodePort` or `LoadBalancer` service exposes a workspace outside the cluster.** It bypasses
  the gateway, so [`endpoint-auth`](./0009-endpoint-auth.md) never sees the traffic. A quota of
  zero on `services.nodeports` and `services.loadbalancers` closes that, and nothing else in this
  repo does.
- **Storage fills up.** Persistent volume claims are paid for, and a script that creates them in a
  loop costs real money before anybody notices.

**The granularity is per team, and the unit is the namespace.** A data team training models and
a web team running a dev server need different ceilings. But a `ResourceQuota` is a namespace
object with no selector, so — as [RFC 0007](./0007-registry-config.md) found for automounted
configuration — there is nothing to route per workspace.

### What exists today

- **Nothing, in a stock Che install.**
- **Che's `workspaces-config` replication.** Recent Che versions copy objects carrying the
  `app.kubernetes.io/component: workspaces-config` label from Che's namespace into every user
  namespace, and that includes `ResourceQuota` and `LimitRange`. It is the closest thing to this
  RFC, and it is discussed first under *Alternatives considered*.
- **OpenShift's `ClusterResourceQuota`**, a quota pooled across all namespaces matching a
  selector. A different shape — one budget per team rather than one per person — and a
  complement, under *Future work*.
- **A policy engine** — Kyverno's `generate` rules do the per-namespace copy well.

**Outcome we are buying:** every workspace namespace in scope has a ceiling an admin wrote down,
sized for its team. A pod that asks for no resources gets a default instead of the whole node.
A workspace cannot expose itself through a `NodePort` or a `LoadBalancer`. And an admin can see
which namespaces are at their ceiling before users start reporting workspaces that will not start.

## Guide-level explanation

The feature starts `Off`, per the chassis. A profile is a pair of ordinary objects in the
operator namespace, authored with `kubectl` or GitOps like any other:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: quota-standard
  namespace: weebo-si-hardening
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 12Gi
    requests.storage: 50Gi
    persistentvolumeclaims: "10"
    pods: "20"
    services.nodeports: "0"
    services.loadbalancers: "0"
    count/devworkspaces.workspace.devfile.io: "10"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: limits-standard
  namespace: weebo-si-hardening
spec:
  limits:
    - type: Container
      defaultRequest: {cpu: 100m, memory: 256Mi}
      default: {cpu: "1", memory: 1Gi}
      max: {cpu: "4", memory: 8Gi}
```

The configuration names them, and grants them, as [RFC 0004](./0004-network-profiles.md) does
for network profiles:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features:
    resourceQuotas:
      mode: DryRun
      catalog:
        - key: standard
          quotaRef: {name: quota-standard, namespace: weebo-si-hardening}
          limitRangeRef: {name: limits-standard, namespace: weebo-si-hardening}
      default: standard          # a namespace belonging to no team
---
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: team-data
spec:
  namespaceSelector:
    matchLabels: {weebo.io/team: team-data}
  features:
    resourceQuotas:
      catalog:
        - key: large
          quotaRef: {name: quota-large, namespace: weebo-si-hardening}
          limitRangeRef: {name: limits-standard, namespace: weebo-si-hardening}
      default: large
```

Before switching anything on, the question is "who is already above this". The CLI answers it
from the pods that are running, with the admin's own kubeconfig:

```console
$ weebo-si-operator quotas audit --all-namespaces
NAMESPACE    TEAM       PROFILE   OVER
user-alice   team-1     standard  -
user-bob     team-1     standard  requests.memory 9.5Gi/8Gi, pods 23/20
user-carol   team-data  large     -
user-dave    (none)     standard  services.nodeports 1/0
```

In `DryRun` the controller computes what it would write and logs the difference:

```text
INFO  feature=resource-quotas mode=DryRun ns=user-bob team=team-1 profile=standard
      diff=create:weebo-quota,create:weebo-limits
```

At `Enforce`, narrowed to a pilot namespace first, the objects appear, and Kubernetes reports
usage against them:

```console
$ kubectl describe resourcequota weebo-quota -n user-bob
Resource                 Used   Hard
--------                 ----   ----
limits.cpu               6      8
requests.cpu             2500m  4
requests.memory          9.5Gi  8Gi
pods                     23     20
services.nodeports       0      0
...
```

Pods already running keep running: a `ResourceQuota` refuses new requests, it never evicts. Bob's
namespace is over its memory quota, so the next pod it creates is refused. In practice that means
the next workspace he starts:

```console
$ kubectl get events -n user-bob
Warning  FailedCreate  replicaset/python-web-7d9c  Error creating: pods "python-web-7d9c-x2"
  is forbidden: exceeded quota: weebo-quota, requested: requests.memory=2Gi,
  used: requests.memory=9.5Gi, limited: requests.memory=8Gi
```

A profile that would make pod creation fail for everyone is refused at configuration time,
before it reaches a namespace:

```text
WARN  feature=resource-quotas profile=strict result=invalid
      quota-strict constrains limits.memory but limits-strict sets no default memory limit:
      every container without one would be refused — profile not applied, condition Degraded
```

## Design

### Contract

#### `resourceQuotas`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis — the rollout knob |
| `catalog` | list of profiles | — | required, non-empty. Each is `{key, quotaRef?, limitRangeRef?}` with at least one ref. |
| `default` | profile key | — | required. The profile of a namespace belonging to no team. |
| per-team catalogue and default | on `WeeboSiTeam` | absent | `spec.features.resourceQuotas.{catalog,default}`, per [RFC 0011](./0011-teams-and-users.md). |
| `namespaceSelection.annotation` | string | `hardening.weebo.io/resource-quota` | Namespace annotation naming one profile key among those the namespace's team is granted. Empty string disables it. |
| `onNotGranted` | `Default` \| `Deny` | `Default` | What a namespace naming a key its team lacks gets: the team default, or no change at all with `Degraded`. |

A **profile** names at most one `ResourceQuota` template and at most one `LimitRange` template,
both in the operator namespace.

#### One profile per namespace, not a set

Every other catalogue in this repo resolves to a **set** of entries, because the objects it writes
add up: two network policies allow the union of both. Quotas do the opposite. Two
`ResourceQuota`s in one namespace are both enforced, so the effective ceiling is the stricter of
the two on each resource. Two `LimitRange`s both apply, and which default a container gets is not
something anyone should have to reason about.

So a namespace resolves to **exactly one profile**, written as exactly one `ResourceQuota` named
`weebo-quota` and one `LimitRange` named `weebo-limits`. There is no `workspaceSelection`:
neither object has a selector, so there is no per-workspace routing to offer. The reasoning is
[RFC 0007](./0007-registry-config.md)'s *The unit is the namespace*.

#### Resolution

1. If the namespace carries the selection annotation and names a key its team is granted, that
   profile.
2. Otherwise, the team's `default`, or the cluster `default` if the namespace has no team.
3. A key the team is not granted follows `onNotGranted`, and is logged with `result=not_granted`.

**The annotation is not narrowing-only**, unlike RFC 0013's. A quota profile is not ordered:
"large" has more CPU and maybe fewer pods. What keeps it safe is that it can only choose among
profiles the team was granted, and that the selection is logged. Who can write it is the
RBAC question RFC 0005 already documents, with the same detection: a change to the annotation's
value counts in `weebo_si_resource_quotas_selection_changed_total`.

#### What is written

The template's `spec`, unchanged, into an object whose name is fixed (`weebo-quota`,
`weebo-limits`), labelled `hardening.weebo.io/managed-by=weebo-si-operator` and
`hardening.weebo.io/profile=<key>`, by server-side apply under the field manager
`weebo-si-resource-quotas`. The template's own metadata is never copied.

Objects in the namespace that this feature did not write are **never modified or deleted**.

- **A foreign `ResourceQuota`** — from Che's `workspaces-config`, an admin, another tool — still
  applies alongside ours, and it can only make the namespace stricter. It is counted
  (`state="foreign_quota"`) and left alone.
- **A foreign `LimitRange`** is a real conflict: two sets of defaults apply, with no defined
  winner. It is counted (`state="foreign_limitrange"`), logged per namespace, and does not stop
  our object from being written. `Degraded` names the count, not the namespaces.

#### Validation of a profile

A profile is checked when it is resolved, and an invalid profile is **not applied anywhere**. It
is counted, logged and reported as `Degraded`. Namespaces that already had it keep their current
objects: "the new configuration is broken" never means "remove the existing ceiling".

| Rule | Why |
| --- | --- |
| A ref resolves to an existing object of the right kind. | Obvious, and the most common edit mistake. |
| If the quota constrains `requests.cpu`/`requests.memory` (or bare `cpu`/`memory`), the profile's `LimitRange` gives a `Container` that sets no request a value for that resource: `defaultRequest`, or else `default`, or else `max`, which is the order upstream's LimitRanger falls back in. | Once a compute quota exists, the apiserver refuses every pod that does not state the resource. DevWorkspace Operator sets defaults on workspace containers, but not on every pod a user or a tool creates. Without a default, the quota is a pod-creation outage. |
| Same for `limits.cpu`/`limits.memory`, where the fallbacks are `default`, then `max`. | Same reason. |
| The `LimitRange` `defaultRequest` is not above `default`, and neither is above `max`. | The apiserver rejects such a `LimitRange` anyway. Checking first gives an error that names the profile. |
| Every template ref is in the template namespace (see *Where templates live*). | A template is enforced where it lives; one anywhere else would constrain whatever runs there. |
| Every quantity parses. | A typo (`50GB`) would be refused by the apiserver on every namespace at once. |
| No `scopes` or `scopeSelector` on the quota. | A scoped quota (`Terminating`, `BestEffort`, priority classes) counts only part of the pods. That is legitimate, but it is not the ceiling this RFC promises. Kept out until someone needs it. |

#### CLI

```text
weebo-si-operator quotas audit      # usage today against each namespace's resolved profile
                                    # [--profile KEY] [--namespace NS | --all-namespaces]
```

`audit` sums the requests and limits of the running pods, and counts the objects the quota names,
using the invoking kubeconfig. It runs the admission-time rules itself, which is acceptable here
and not for RFC 0013 because the rule is one comparison per resource, documented upstream, and
the CLI only advises.

#### Observability contract

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_resource_quotas_namespaces` | gauge | `profile`, `state` ∈ `applied`/`pending`/`foreign_quota`/`foreign_limitrange` |
| `weebo_si_resource_quotas_saturation` | gauge | `band` ∈ `under_80`/`80_to_99`/`at_limit` — namespaces by their most-used resource, from each managed quota's `status` |
| `weebo_si_resource_quotas_reconcile_total` | counter | `result` ∈ `applied`/`unchanged`/`deleted`/`not_granted`/`invalid`/`error` |
| `weebo_si_resource_quotas_profiles` | gauge | `state` ∈ `valid`/`invalid` |
| `weebo_si_resource_quotas_selection_changed_total` | counter | none |

`profile` is an admin-written catalogue key, which is bounded by the size of the catalogue. No
metric carries a namespace. `at_limit` is the number to watch: those namespaces will refuse their
next pod.

**Stability.** The feature identifier, CRD fields, object names (`weebo-quota`, `weebo-limits`),
labels, annotation key, field manager, validation rules and metric names are the contract.

### Architecture

**Hexagonal, as a reconcile feature, with no new chassis trait.** It is the closest sibling of
`registry-config`: a catalogue of templates, one profile per namespace, objects copied into the
namespace.

1. *A real decision.* Resolution with grants, a validation table that has to be right before
   three hundred namespaces stop creating pods, and a rule never to touch foreign objects.
2. *Touches an external system.* Two resource types, templates and managed copies.
3. *We want the decision tested without it.* The validation table especially.

Crates `weebo-si-resource-quotas` (subject, `ReconcileFeature::desired`, resolution, validation)
and `weebo-si-resource-quotas-adapters` (template store, managed object store, metrics, loop).
Ports:

- `QuotaTemplateStore` — templates by `{name, namespace}`, as domain values, not `k8s-openapi`
  types.
- `ManagedQuotaStore` — the managed objects in one namespace, their `status.used`, the count of
  foreign ones, and apply/delete.
- The chassis's `NamespaceView`, `TeamView`, `FeatureGate`, and the managed-object diff.

The domain represents quantities with its own parsed type for the validation table, so the crate
does not depend on `k8s-openapi`.

### Data and state

**Effectively stateless**, with two new watches:

- **Templates**, `resourcequotas` and `limitranges` in the operator namespace only. A template
  change re-reconciles every namespace using it.
- **Managed objects**, filtered server-side by the management label. This is what makes drift a
  cache lookup and gives the saturation gauge its `status`.

Foreign objects are counted with a separate, unfiltered metadata-only watch of `limitranges` and
`resourcequotas`. They are small and rare, and a metadata watch carries no `spec`.

Nothing is persisted. The managed objects are derived entirely from `spec`, and the undo is
deleting them by label. `/readyz` waits for the template and managed caches. A controller that
cannot see the templates would compute "no valid profile". That is why an invalid profile
**keeps** existing objects rather than deleting them: an empty cache must never read as "remove
every quota".

## Security considerations

**Privileges.** New, controller role only: `create`, `update`, `patch`, `delete` on
`resourcequotas` and `limitranges`, cluster-wide, plus `get`, `list`, `watch`. Kubernetes RBAC
cannot narrow a create to a name, so the narrowing is the adapter's: it writes exactly two names
and deletes only objects carrying the management label, uid-pinned like the other features'
deletes. The webhook role is unchanged.

**Trust boundary.** Templates and the `WeeboSiConfig`/`WeeboSiTeam` are admin-written. The
selection annotation is written by whoever can annotate the namespace, and can only choose among
granted profiles. Nothing in a workspace reaches this feature.

**Bypass.**

- **Deleting or editing the quota.** The stock `admin` and `edit` ClusterRoles grant only read on
  `resourcequotas` and `limitranges`, so a Che user cannot change them. If a cluster's RBAC does
  allow it, the controller re-applies on the next watch event and counts the drift.
  [`policy-guard`](./0008-policy-guard-coverage.md) gets two rows for them as a second line —
  see *Implementation plan*.
- **Moving work to another namespace.** A user who can create namespaces escapes a per-namespace
  quota. Che users cannot, by default. A pooled per-team budget would close it; see *Future
  work*.
- **Consumption that is not a quota resource.** Ephemeral storage on the node, network bandwidth
  and the number of processes are not counted unless the template names them
  (`requests.ephemeral-storage` is supported, PID limits are a kubelet setting). The template is
  where an admin adds them.
- **Nested containers.** Containers a workspace runs itself (Che's container-run mode, a build's
  `RUN` steps) are processes inside the workspace container, so they count against that
  container's limits and the namespace's quota. They cannot get around either.
- **Being within quota and still mining.** A quota bounds the damage, it does not detect it.
  Spotting a workspace that uses its full CPU limit for hours is
  [`kubearmor-policy`](./0006-kubearmor-policy.md)'s and monitoring's job.

**Blast radius, if this brick misbehaves.** A wrong quota stops pod creation in the namespaces it
reaches: workspaces do not start, running ones keep running. A quota cannot grant anything, so
the worst case is denial of service, never escalation. The validation table and "invalid keeps
the existing objects" are the two defences against the most likely bug, which is a bad profile
going everywhere at once. A compromised controller could set every quota to zero, which is an
outage of every workspace, and nothing more.

**Secrets.** None read.

## Operational considerations

**Failure mode.** Enforcement is the apiserver's built-in `ResourceQuota` and `LimitRanger`
admission. Neither depends on the operator. If the operator is down, existing objects keep being
enforced, new namespaces get none until it comes back, and drift is not corrected. That is
fail-open for new namespaces, and accepted: the window is the time to the first reconcile, and the
alternative is a webhook in front of every namespace creation.

**Rollout.**

0. **`weebo-si-operator quotas audit --all-namespaces`**, before installing anything. Every
   namespace over a draft profile is a workspace that will not restart. Size profiles from this,
   not from guesses.
1. `mode: DryRun`, catalogue and `default` written, no teams. Check `profiles{state="invalid"}`
   is zero.
2. Teams' catalogues and defaults, still in `DryRun`.
3. `mode: Enforce` on a pilot label.
4. Remove the selector. Watch `saturation{band="at_limit"}`.

A cautious first profile constrains only object counts and the two service types, with no compute
quota. It closes the `NodePort` exposure and the PVC loop on day one and cannot refuse a
workspace for lack of CPU. Compute ceilings come once usage is known.

**Rollback.**

- `mode: Off` — every managed object is deleted on the next reconcile.
- Move a namespace or a team to a bigger profile — the surgical undo, and the right one for
  "this person needs more".
- The break-glass: delete `weebo-quota` in the namespace and add `hardening.weebo.io/exclude`.

**Observability.** `saturation{band="at_limit"}` is the first alert: those namespaces will refuse
their next pod, and their users will notice before anyone else does. `namespaces{state=
"foreign_limitrange"}` above zero means two sets of defaults apply somewhere. `profiles{state=
"invalid"}` above zero means a configuration edit was rejected. From the apiserver,
`kube_resourcequota` from kube-state-metrics gives per-namespace detail where cardinality allows.

**Upgrade.** Old and new controllers compute the same objects from the same `spec`, and
server-side apply under one field manager makes a mixed fleet converge. Within `v1alpha1` the CRD
only grows fields.

**Self-deadlock.** The operator namespace is structurally excluded from scope. Templates are the
trap: a `ResourceQuota` or `LimitRange` is enforced wherever it lives, so a template in the
operator namespace would constrain the operator. Hence the recommended pod-less template
namespace under *Unresolved questions*.

## Alternatives considered

**Che's `workspaces-config` replication.** Che copies labelled objects from its namespace into
every user namespace and keeps them in sync. If one quota for everybody is enough, it is the
right answer and this RFC should not be built. It is rejected here for three things it does not
do: a different profile per team, a way to see what would change before it changes, and a check
that a profile will not stop every pod from starting. It is also Che's only, so a namespace not
created by Che is not covered.

**Kyverno `generate` rules.** Per-namespace copies with selectors, so per-team is possible. Rejected
for the reason RFC 0004 gives for network policies: a second engine to run, a rule language
instead of real objects, no validation of the pair, and a team concept that would duplicate the
one in `WeeboSiTeam`.

**Write the quota inline in the CRD**, rather than referencing a template. One file instead of
two. Rejected because a `ResourceQuota` template can be applied and tested on its own, with
`kubectl`, and because RFC 0004 set the rule that an admin writes real objects rather than a
schema of ours that mirrors them.

**Quota per workspace.** Not possible: neither object has a selector. Workspace sizing per devfile
is DevWorkspace Operator's, through container resource fields and DWOC defaults.

## Drawbacks and risks

**A quota is the most user-visible thing in this repo.** Every other feature refuses something a
user rarely does on purpose. This one refuses the next workspace start of someone who is simply
working, the day they cross a line. That is why the saturation gauge and the audit command exist,
and why the cautious first profile has no compute quota.

**The error lands in the wrong place.** "Exceeded quota" is a ReplicaSet event. The developer sees
a workspace that does not start, and what Che's dashboard shows is up to DevWorkspace Operator's
status message. Better messages are DevWorkspace Operator's to give.

**New write permission on two cluster-wide resource types.** Low blast radius, as argued above,
but it is one more write than before.

## Unresolved questions

- ~~**Where templates live.**~~ Decided 2026-11-01: the recommendation below. The feature takes
  the template namespace as a parameter and refuses a profile whose ref points anywhere else. A template is a real
  object, so it is also enforced in the namespace that holds it. A `ResourceQuota` template in
  the operator namespace caps the operator's own pods, and one sized for a workspace (four CPUs,
  twenty pods) would block an operator rollout as soon as old and new replicas overlap. A
  `LimitRange` template is worse: it injects its defaults into the operator's containers and
  refuses any above its `max`, silently changing how the operator itself is scheduled. With
  several profiles, every quota template applies at once, so the strictest one wins. **Recommended:**
  the chart creates a dedicated `weebo-si-hardening-templates` namespace that runs no pods, and
  every profile references it. Templates there constrain nothing, since nothing runs there.
  `templateNamespace` in the chart values, and the controller's template watch limited to it.
- **Does Che's dashboard show the quota error?** (Not blocking.) If DevWorkspace Operator copies
  the `FailedCreate` message into the DevWorkspace status, it does. To be checked on the kind e2e,
  and recorded in the brick doc either way.

## Future work

- **A pooled budget per team**, on OpenShift with `ClusterResourceQuota`, or by summing namespace
  usage per team in the controller. One quota per person does not stop a team of fifty from using
  the whole cluster.
- **Idling and maximum run time**, which live in the DWOC (`secondsOfInactivityBeforeIdling`,
  `secondsOfRunBeforeIdling`) and so belong with `dwoc-pin`, not here.
- **Scoped quotas** (`PriorityClass`, `BestEffort`), once someone needs them.
- **A drift-to-alert path**, shared with every other feature's `*_drift_total`.

## Implementation plan

- [x] `weebo-si-crd`: `QuotaProfile`, `ResourceQuotasConfig`, the team fields, `Resolved*`, and
      the `resource-quotas` entry in the `WeeboSiConfig` status.
- [x] `weebo-si-resource-quotas`: subject, resolution, validation table with a test per row,
      desired state, the saturation band, reconcile and teardown over two ports.
- [x] `weebo-si-resource-quotas-adapters`: template store, managed store with foreign counts,
      metrics, loop; envtest for "invalid profile keeps existing objects". The loop
      re-reconciles every namespace when the configuration, a template or a managed object's spec
      changes.
- [x] `weebo-si-policy-guard`: `GuardedResource::{ResourceQuota, LimitRange}`, two rows. Their
      webhook rule carries an ownership `objectSelector`, so a foreign quota stays creatable.
- [x] `weebo-si-operator`: wiring, `--quota-template-namespace`.
- [x] `weebo-si-operator`: `quotas audit` CLI.
- [x] Chart: controller RBAC for the two resources behind `resourceQuotas.rbac.enabled`, the
      template namespace (`resourceQuotas.templateNamespace`, created by default).
- [x] Chart: the guard's webhook rule (`-resource-quotas`, path `/validate/v1/resourcequotas`).
- [x] e2e on kind (the `resource-quotas` suite): a write over quota refused at `Enforce`, objects
      removed at `Off` with a foreign quota left alone, an invalid profile written nowhere, and a
      measurement of whether the refusal reaches the DevWorkspace status.
- [x] Docs: brick page, `weebosiconfig.md`, `weebositeam.md`.
- [ ] RFC flipped to `Implemented`

## References

- [Resource quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas/)
- [Limit ranges](https://kubernetes.io/docs/concepts/policy/limit-range/)
- [Che: configuring a user namespace](https://eclipse.dev/che/docs/stable/administration-guide/configuring-a-user-namespace/) — `workspaces-config` replication
- [OpenShift `ClusterResourceQuota`](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/building_applications/quotas)
- [RFC 0004](./0004-network-profiles.md) — templates as real objects
- [RFC 0007](./0007-registry-config.md) — the unit is the namespace
- [RFC 0008](./0008-policy-guard-coverage.md) — `GuardedResource`
- [RFC 0013](./0013-pod-security.md) — the other half of a workspace's node footprint

## Changelog

| Date | Change |
| --- | --- |
| 2026-11-01 | `Accepted`. Templates live in a dedicated, pod-less namespace, and a ref elsewhere is a validation failure. The "has a default" rule follows LimitRanger's fallbacks (`defaultRequest` → `default` → `max`). Two more rules: every quantity parses, every ref is in the template namespace. `reconcile_total` gains `result="invalid"`. |
