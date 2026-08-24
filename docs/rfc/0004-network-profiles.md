---
rfc: 0004
title: network-profiles
status: Draft
authors: [batleforc]
created: 2026-08-24
updated: 2026-08-24
decided:
brick: crates/weebo-si-operator
supersedes: []
superseded-by: []
---

# RFC 0004 — network-profiles

## Summary

Two features on the [RFC 0002](./0002-weebo-si-operator.md) chassis, sharing one catalogue.
`network-profiles` gives every workspace namespace a mandatory NetworkPolicy baseline and lets a
workspace opt into additional, admin-authored profiles its team is granted — team 1's base
project reaches git, its second project reaches git and Vault, and neither reaches anything
else. `policy-guard` keeps a workspace owner from writing their own policy to undo it — a second
line of defence in a cluster whose RBAC already forbids that, and the only line in a cluster
whose RBAC does not.

This is the first feature that **writes objects**, the first to use the controller role, and the
first with a pluggable enforcement backend: plain `NetworkPolicy` where that is all the cluster
has, `CiliumNetworkPolicy` where the CNI offers more, with the degradation named rather than
silent. It stays `Draft` until [RFC 0002](./0002-weebo-si-operator.md) is accepted, because it
builds on an amendment to that RFC — `spec.teams` — that has not been reviewed yet.

## Motivation

A workspace pod today can reach everything the cluster network permits. Every other user's
workspace, the Che control plane, the apiserver, the in-cluster Vault, the registry, the
internet. Nothing in Eclipse Che or in DevWorkspace Operator narrows that, and no Che
installation ships a NetworkPolicy for workspace namespaces.

The exposure is not the developer. It is the code the developer runs, which is not the same
thing: a devfile from a repository they cloned, a VS Code extension the devfile installs, an
`npm install` running a post-install script. All of it executes inside the workspace pod, with
the workspace pod's network position. A cluster where Vault answers on
`vault.vault.svc.cluster.local` is a cluster where one line in a post-install script reaches it,
from any workspace, with no lateral movement worth the name — there is nothing to move laterally
*through*.

The granularity to fix this already exists and nobody uses it. Che gives each user a namespace;
NetworkPolicy is namespaced and selects pods by label; DevWorkspace Operator labels every
workspace pod with `controller.devfile.io/devworkspace_id` and
`controller.devfile.io/devworkspace_name` ([`pkg/constants`](https://pkg.go.dev/github.com/devfile/devworkspace-operator/pkg/constants)).
A policy can therefore target exactly one workspace, in plain `networking.k8s.io/v1`, with no
CNI-specific extension. What is missing is anything that writes those policies.

**The shape of the need is per project, not per user.** A developer has one namespace and
several workspaces: a base project needing git, a second project needing git and Vault. Granting
the *user* Vault to satisfy the second project hands it to the first, which is the whole problem
restated one level down.

### What exists today

- **Nothing, in a stock Che install.** Workspace namespaces are created by Che with no
  NetworkPolicy, so the default is "everything reaches everything".
- **Hand-written policies per namespace.** Works for a fixed cluster, and Che creates workspace
  namespaces automatically, so a new user is unprotected until someone notices they exist.
- **A policy engine generating them** — Kyverno's `generate` rules do the namespace baseline
  well, and are discussed under *Alternatives considered*. They stop short of the per-workspace
  half.
- **A service mesh.** A much stronger answer to a much larger question, and a much larger thing
  to run. Also under *Alternatives*.

**Outcome we are buying:** every workspace namespace carries a default-deny baseline plus
exactly the flows an admin wrote down; a workspace reaches beyond it only by naming a profile
its team was granted; and a compromised extension in a project that never asked for Vault cannot
reach Vault, whatever it runs. The admin authors real policy objects and never learns a DSL we
invented, and a cluster whose CNI cannot express a profile says so out loud instead of applying
something weaker and looking healthy.

## Guide-level explanation

Both features start `Off`, per the chassis. `network-profiles` needs three things: a catalogue,
a baseline, and grants against the teams `spec.teams` already declares.

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams:                                  # chassis-level, shared with dwoc-pin
    - name: team-1
      namespaceSelector:
        matchLabels: {weebo.io/team: team-1}
  features:
    networkProfiles:
      mode: DryRun
      catalog:
        - key: base
          variants:
            - backend: NetworkPolicy
              templateRef: {name: weebo-base, namespace: weebo-si-hardening}
        - key: git
          variants:
            - backend: NetworkPolicy
              templateRef: {name: weebo-git, namespace: weebo-si-hardening}
        - key: vault
          variants:
            - backend: NetworkPolicy
              templateRef: {name: weebo-vault, namespace: weebo-si-hardening}
      baseline: base                      # applied to every namespace in scope, never negotiable
      grants:
        team-1: {allowed: [git, vault], default: [git]}
```

A template is an ordinary policy object in a namespace users cannot write, authored with
`kubectl` or GitOps like any other:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: weebo-vault
  namespace: weebo-si-hardening
spec:
  podSelector: {}                         # ignored — the operator sets it
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: vault}
          podSelector:
            matchLabels: {app.kubernetes.io/name: vault}
      ports:
        - {protocol: TCP, port: 8200}
```

In `DryRun` the controller computes every object it would write and diffs it against what is
there, writing nothing:

```text
INFO  feature=network-profiles mode=DryRun ns=user-alice team=team-1
      workspace=python-web id=workspacec1a2b3 profiles=[git] backend=NetworkPolicy
      diff=create:weebo-base,create:weebo-git-workspacec1a2b3
INFO  feature=network-profiles mode=DryRun ns=user-alice team=team-1
      workspace=data-pipeline id=workspacede4f56 profiles=[git,vault]
      diff=create:weebo-git-workspacede4f56,create:weebo-vault-workspacede4f56
```

A developer asks for the second profile in the devfile, so the request travels with the project
rather than with the person:

```yaml
schemaVersion: 2.2.0
metadata:
  name: data-pipeline
attributes:
  hardening.weebo.io/network-profiles: "git,vault"
```

Switching to `Enforce`, narrowed to a pilot namespace first, the objects appear:

```console
$ kubectl get networkpolicy -n user-alice
NAME                            POD-SELECTOR                                     AGE
weebo-base                      <none>                                           2m
weebo-git-workspacec1a2b3       controller.devfile.io/devworkspace_id=workspacec1a2b3   2m
weebo-git-workspacede4f56       controller.devfile.io/devworkspace_id=workspacede4f56   2m
weebo-vault-workspacede4f56     controller.devfile.io/devworkspace_id=workspacede4f56   2m
```

`python-web` reaches git and nothing else. `data-pipeline` reaches git and Vault. Neither
reaches the other's pods, the apiserver, or the internet, because `weebo-base` denies everything
the profiles do not restore.

A workspace asking for a profile its team was not granted is told so, and gets the team default
instead of the thing it asked for:

```text
WARN  feature=network-profiles mode=Enforce ns=user-bob team=team-2 workspace=scratch
      requested=[vault] granted=[git] result=not_granted applied=[git]
```

And a cluster whose backend cannot express a profile refuses to pretend:

```text
WARN  feature=network-profiles profile=vault backend=NetworkPolicy result=unsupported
      no variant for the resolved backend — profile not applied, condition Degraded
```

Then `policy-guard` closes the door behind it. Until it is on, a workspace owner with write
access to their own namespace can delete `weebo-base`:

```console
$ kubectl delete networkpolicy weebo-base -n user-alice
Error from server: admission webhook "policies.hardening.weebo.io" denied the request:
  networkpolicy user-alice/weebo-base is managed by weebo-si-operator and may not be deleted
$ kubectl apply -f my-own-allow-everything.yaml
Error from server: admission webhook "policies.hardening.weebo.io" denied the request:
  workspace namespaces may not carry user-authored network policies
```

## Design

### Contract

Terminology is the chassis's, plus one word. A **profile** is a named, admin-authored set of
network permissions, one catalogue entry. The **baseline** is the profile applied to every
namespace in scope regardless of team, and it is the only one no grant can withhold.

#### `networkProfiles`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis — the rollout knob |
| `catalog` | list of profiles | — | required, non-empty. Each is `{key, variants}`. |
| `baseline` | profile key | — | required. Applied to every namespace in scope. |
| `grants` | map, team name → `{allowed, default}` | empty | `allowed` is the set of keys a team may reach; `default` is the subset applied when a workspace asks for nothing. Both may be empty. |
| `namespaceSelection.annotation` | string | `hardening.weebo.io/network-profiles` | Namespace annotation carrying a comma-separated key list, overriding the team default for that namespace. Empty string disables it. |
| `workspaceSelection.attribute` | string | `hardening.weebo.io/network-profiles` | DevWorkspace attribute carrying the same, overriding the namespace. Empty string disables it. |
| `onNotGranted` | `Default` \| `Deny` | `Default` | What to do when a workspace names a key its team lacks. |
| `enforcement.backend` | `Auto` \| `NetworkPolicy` \| `Cilium` | `Auto` | Which policy dialect to write. |
| `enforcement.canary` | `{enabled, intervalSeconds}` | `{true, 300}` | Periodic proof that the CNI enforces at all. |

A **profile** is `{key, variants}`; a **variant** is `{backend, templateRef}` where `templateRef`
is `{name, namespace}` pointing at a real policy object. One profile may carry one variant per
backend, and needs at least one.

**Resolution**, for one DevWorkspace, mirrors `dwoc-pin` deliberately — same three scopes, same
order, so an admin learns it once:

1. **The team, and its grant.** Per the chassis. No team, or no grant, means `allowed: []` and
   `default: []`: the baseline and nothing else.
2. **The workspace attribute**, if set — the complete list, not an addition. A workspace may ask
   for fewer profiles than its default, including none, which is how a project drops a
   permission it does not need.
3. **The namespace annotation**, if set and the attribute is not.
4. **The grant's `default`.**

Whatever wins is intersected with `allowed`. Keys outside it follow `onNotGranted`: `Default`
drops them and applies the team default, `Deny` refuses the DevWorkspace at admission with a
message naming the ungranted key. The baseline is added unconditionally at the end, and it is
not a member of any `allowed` set — asking for it is asking for something already applied.

**The objects written.** Two kinds, and the difference matters for their lifecycle:

| Object | Scope | Name | `podSelector` | Owner |
| --- | --- | --- | --- | --- |
| baseline | one per namespace in scope | `weebo-base` | `{}` — every pod in the namespace | none; reconciled |
| profile | one per workspace per selected key | `weebo-<key>-<workspaceId>` | `controller.devfile.io/devworkspace_id: <id>` | the DevWorkspace |

Every object carries `hardening.weebo.io/managed-by: weebo-si-operator`,
`hardening.weebo.io/profile: <key>` and `hardening.weebo.io/backend: <backend>`. The label is
the ownership boundary: **the operator never touches a policy that does not carry it**, which is
what keeps a cluster's existing policies safe from a feature that writes cluster-wide.

Profile objects carry an `ownerReference` to their DevWorkspace, so the apiserver garbage
collects them when the workspace is deleted. That is deliberate: workspace deletion cleanup then
survives our downtime, and there is no reconcile path that has to notice a workspace is gone.
The baseline has no owner because a namespace outliving its workspaces must keep its floor.

**The template is data, not a decision.** The operator copies the template's `policyTypes`,
`ingress` and `egress` verbatim and sets `podSelector` itself. A template's own `podSelector` is
ignored, and that is the point: scoping belongs to the operator, content belongs to the admin.
The operator never parses a rule, never validates that a CIDR is sane, and never rewrites a
selector inside a rule — a mistranslation in that position would be a security bug that looks
like a working control, which is the argument in *Alternatives* against inventing an intent
language.

**Backends and degradation.** A backend is a policy dialect the binary knows how to write:
`NetworkPolicy` (`networking.k8s.io/v1`) and `Cilium` (`cilium.io/v2`, `CiliumNetworkPolicy`) at
first. Adding one is a module plus an RBAC rule, not a redesign, because a backend only has to
say which kind it writes and where the pod selector lives in it. `weebo-si-operator backends`
prints which are compiled in and which the cluster actually offers.

`Auto` resolves to the most capable backend the apiserver advertises, in declaration order, and
reports it in `status` and in `weebo_si_network_backend`. Explicit values skip discovery, which
is what a cluster wanting reproducibility should use.

Degradation is per profile and never silent:

- A profile with a variant for the resolved backend is applied from that variant.
- A profile with no such variant is **not applied**, raises a `Degraded` condition naming the
  profile and the backend, and increments `weebo_si_network_profile_unsupported`. It is not
  approximated with the nearest other variant — an admin who wants a coarser fallback writes it
  as the `NetworkPolicy` variant, deliberately, and can see what they wrote.
- **The baseline is different: no usable variant means the feature refuses to enforce at all.**
  It stays in `DryRun` behaviour, reports `Degraded`, and writes nothing. A cluster where the
  floor cannot be expressed must not receive the profiles either, because profiles are purely
  additive: without the baseline they grant access rather than restrict it, and the feature
  would be a permission dispenser wearing a hardening name.

That last rule is the one to remember, and it comes from the semantics: **NetworkPolicy is a
union.** Any policy allowing a flow allows it; there is no merge order, no override, no deny
that wins. So a profile can only ever add, the baseline must be the most restrictive common
denominator, and the interesting failure is not a policy that is too strict — it is a policy
that is missing.

#### `policyGuard`

The other half of the union problem: a user who can write a NetworkPolicy in their own namespace
can grant themselves anything, and the most efficient way is deleting the baseline.

**How much this feature is load-bearing depends on the cluster, and the design refuses to assume
either answer.** In the Che installation this repo targets, a workspace user has no write verb on
`networkpolicies` in their own namespace, so the guard is defence in depth: it catches an RBAC
regression, a `ClusterRoleBinding` someone widened, and the day Che changes what it grants. In a
cluster where the user namespace carries something closer to the built-in `edit` role, the same
feature is the only thing standing between a user and a self-granted allow-all. Same code, two
very different importances — so the guard ships as its own flag rather than as a part of
`network-profiles`, its `failurePolicy` is an install-time choice argued under *Operational
considerations*, and "which cluster am I in" is the first line of the install checklist rather
than an assumption buried in a paragraph.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis |
| `allowedIdentities` | list of usernames or service accounts | empty | Identities exempt from the rules below, in addition to the operator's own. |

A validating webhook on `networkpolicies` and, where the backend is enabled,
`ciliumnetworkpolicies`, in namespaces the selector matches:

| Request | Verdict |
| --- | --- |
| any verb on an object labelled `hardening.weebo.io/managed-by: weebo-si-operator`, from anyone but the operator | denied |
| `CREATE` of an unmanaged policy by anyone but the operator or an `allowedIdentities` entry | denied |
| anything from the operator's own service account | allowed |

The second row is the one that surprises, and it is the one that matters. Denying edits to our
objects while permitting a user to create their own would be theatre: their policy unions with
ours and reinstates whatever the baseline removed. **In a workspace namespace, network policy
authorship belongs to the platform.** `allowedIdentities` is the escape hatch for the cluster
operator who needs to debug one namespace at three in the morning.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: weebo-si-hardening-policies
webhooks:
  - name: policies.hardening.weebo.io
    admissionReviewVersions: ["v1"]
    sideEffects: None
    matchPolicy: Equivalent
    failurePolicy: Fail
    timeoutSeconds: 5
    rules:
      - operations: ["CREATE", "UPDATE", "DELETE"]
        apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        resources: ["networkpolicies"]
        scope: Namespaced
    namespaceSelector:
      matchExpressions:
        - key: hardening.weebo.io/exclude
          operator: DoesNotExist
        - key: hardening.weebo.io/workspace-namespace
          operator: Exists
    clientConfig:
      service:
        name: weebo-si-operator-webhook
        namespace: weebo-si-hardening
        path: /validate/v1/networkpolicies
        port: 443
```

Three values differ from [RFC 0002](./0002-weebo-si-operator.md)'s webhook and all three are
decisions:

- **`operations` includes `DELETE`.** Unusual, and the entire point — deleting the baseline is
  the cheapest bypass, and an admission rule that does not cover `DELETE` does not cover it. On
  a `DELETE` the object arrives in `oldObject`, which is where the ownership label is read from.
- **The `namespaceSelector` requires a positive label**, unlike `dwoc-pin`'s opt-out. Inverted
  polarity on purpose: this webhook denies writes, so a namespace it reaches by accident is a
  namespace whose owner cannot manage their own policies. Failing toward "not protected" is
  wrong for `dwoc-pin` and right here, because the blast radius of over-reach is an outage in
  someone else's namespace. Which namespaces are workspace namespaces is Che's to label, and it
  goes on the install checklist.
- **`failurePolicy` is the one value in this RFC set at install time rather than by this
  document.** `Fail` is what ships, because it is the safe default and because a control whose
  bypass is "make the webhook unavailable" is not a control. A cluster that has *verified* its
  users cannot write `networkpolicies` may run the same webhook at `Ignore`, and gets something
  in return — see the self-interference paragraph under *Operational considerations*. The two
  manifests differ by one line and both ship; picking one is a decision the checklist asks for
  explicitly, so that `Fail` is chosen rather than merely inherited.

#### CLI

Two additions to [RFC 0002](./0002-weebo-si-operator.md)'s table; the rest is unchanged.

```text
weebo-si-operator backends    # compiled-in backends, and which the cluster offers
weebo-si-operator canary      # run the enforcement probe once and report, without the controller
```

`canary` exists so "is this cluster's CNI actually enforcing policy" is answerable during an
install, before the feature is switched on and before anyone trusts it.

#### Observability contract

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_network_reconcile_total` | counter | `result` ∈ `created`/`updated`/`unchanged`/`deleted`/`dry_run`/`error`, `team` |
| `weebo_si_network_managed_objects` | gauge | `kind`, `scope` ∈ `baseline`/`profile` |
| `weebo_si_network_drift_total` | counter | `action` ∈ `restored`/`removed` |
| `weebo_si_network_backend` | gauge | `backend` — `1` for the resolved one |
| `weebo_si_network_profile_unsupported` | gauge | `profile`, `backend` |
| `weebo_si_network_canary` | gauge | `result` ∈ `enforcing`/`not_enforcing`/`unknown` |
| `weebo_si_network_not_granted_total` | counter | `team`, `profile` |

No metric carries a namespace or a workspace id as a label. Both scale with the cluster, and a
per-workspace time series is how a metrics backend is taken down by a hardening component. The
per-namespace answer lives in the objects themselves, which is what `kubectl get networkpolicy`
is for.

`policy-guard` reuses the chassis's `weebo_si_admission_requests_total` with
`feature="policy-guard"`, so a denial rate is readable next to `dwoc-pin`'s on one dashboard.

**Stability.** The two feature identifiers, their CRD fields, the object naming scheme
`weebo-base` and `weebo-<key>-<workspaceId>`, the three management labels, the attribute and
annotation keys and their comma-separated grammar, the webhook path, and the metric names are
the contract. Changing one needs a new RFC, per [the RFC process](./readme.md#when-is-an-rfc-required).

### Architecture

**Hexagonal, and it extends the chassis rather than reusing it unchanged.** Against the three
criteria in [`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. *A real decision.* A resolution chain over three scopes, an intersection with a grant, a
   backend that may not support a profile, a baseline that may not be expressible, and a diff
   against live state. Testing that without a cluster is the difference between shipping this
   and hoping.
2. *Touches an external system.* Five resource types, two API groups, plus admission.
3. *We want the decision tested without it.* Emphatically — the desired-state computation is
   where a mistake writes a deny-all into three hundred namespaces.

**The chassis needs a second trait, and [RFC 0002](./0002-weebo-si-operator.md) predicted it.**
That RFC names the risk in *Drawbacks*: "the risk is that feature two does not fit `Feature<S>`".
This is feature two, and it does not. `Feature<S>::evaluate` returns mutations to the object
under admission; a reconcile feature returns objects that should exist somewhere else.

```rust
// domain/feature/mod.rs — alongside the existing Feature<S>
pub trait ReconcileFeature<S: Subject> {
    fn id(&self) -> FeatureId;
    fn desired(&self, subject: &S, ctx: &Context<'_>)
        -> Result<DesiredState, DomainError>;
}
```

The two traits share `FeatureId`, `FeatureMode`, the gate, the teams and the registry —
everything the chassis was built for — and differ only in what a decision *is*. The invariant
survives intact, and the three modes map onto reconciliation without straining:

| Mode | `desired` runs | The diff is applied | Counted and logged |
| --- | --- | --- | --- |
| `Off` | no | no | no |
| `DryRun` | yes | no | yes |
| `Enforce` | yes | yes | yes |

`application::reconcile` reads the mode, calls `desired`, diffs against the live objects through
a port, and then — and only then — applies or discards. **A reconcile feature cannot tell
`DryRun` from `Enforce`**, exactly as an admission feature cannot, and for a better reason: here
`DryRun` produces a diff an admin can read line by line before three hundred namespaces change
at once.

```text
crates/weebo-si-operator/src/
├── domain/
│   ├── model/
│   │   ├── policy.rs              # ManagedObject, PolicyBody (opaque), ObjectKey, Backend
│   │   ├── profile.rs             # ProfileKey, Profile, Variant, ProfileSet
│   │   └── diff.rs                # DesiredState, Diff — create / update / delete / unchanged
│   ├── feature/
│   │   ├── network_profiles.rs    # the resolution chain and the desired-state computation
│   │   └── policy_guard.rs        # the three-row verdict table
│   └── port/
│       ├── policy_store.rs        # what exists now, and applying a diff
│       ├── template_store.rs      # fetch a template body by reference
│       └── capabilities.rs        # which backends this cluster offers
└── adapters/outbound/
    ├── kube_policy_store.rs       # server-side apply, one field manager
    ├── kube_template_store.rs     # watch-backed template cache
    └── kube_capabilities.rs       # apiserver discovery
```

```rust
// domain/port/policy_store.rs
pub trait PolicyStore {
    fn managed_in(&self, ns: &NamespaceName) -> Vec<ObjectKey>;
    fn apply(&self, diff: &Diff) -> Result<Applied, DomainError>;
}

// domain/port/capabilities.rs
pub trait Capabilities {
    fn offers(&self, backend: Backend) -> bool;
}
```

**`PolicyBody` is opaque, and that is the load-bearing type decision.** The domain carries the
template's rules as bytes it never inspects: it decides *which* policies exist and *what
selector* they carry, never *what they permit*. So the domain still has no `k8s-openapi`
dependency, the interesting logic is still pure, and the part we could get catastrophically
wrong — rewriting someone's network rules — is a part we never wrote. A body is compared for
equality when diffing and copied otherwise. Nothing else is done to it, and a test asserts the
domain exposes no accessor that could start.

**What is scaffolded but not implemented.** The `Cilium` backend ships as a variant the config
can name and the binary can write, with the same copy-and-set-selector shape as
`NetworkPolicy` — `CiliumNetworkPolicy` carries its pod selector at `spec.endpointSelector`
instead of `spec.podSelector`, which is the whole of the difference at our layer. Anything
richer, `toFQDNs` included, is content in the admin's template, so it needs no code here.

### Data and state

**Effectively stateless, with a fourth and a fifth watch.** On top of
[RFC 0002](./0002-weebo-si-operator.md)'s `WeeboSiConfig`, DWOC and `Namespace` caches:

- **DevWorkspaces**, watch-backed. This is new and it is the one that scales with the fleet, so
  it is stored as a bounded projection — namespace, name, workspace id, and the one attribute —
  never the template. [RFC 0002](./0002-weebo-si-operator.md) makes a point of caching no
  DevWorkspaces at all because admission delivers the object; a controller has no such luxury,
  and this is the first place that argument stops applying.
- **Managed policies**, watch-backed and filtered server-side by the management label, which is
  what makes drift detection a cache lookup rather than a list call per reconcile.
- **Templates**, watch-backed, in one namespace. Small, and a change to one is a legitimate
  trigger to re-reconcile every namespace using it.
- **The canary's verdict**, in memory, with its timestamp. Lost on restart and reported
  `unknown` until the first probe completes.

Nothing is persisted. The objects in workspace namespaces are the only durable output, they are
fully derived from `spec` plus the DevWorkspace population, and the undo for all of it is
deleting them by label and letting a reconcile decide again. `/readyz` waits for all five caches
for the same reason [RFC 0002](./0002-weebo-si-operator.md) waits for three: a controller that
cannot see the workspaces would compute "no workspace wants any profile" and delete every
profile object in the cluster. That failure is the reason the readiness gate is not optional.

## Security considerations

**Privileges.** This is where the brick changes character, and the change deserves to be read
carefully rather than skimmed off a table. [RFC 0002](./0002-weebo-si-operator.md) argues at
length that the operator holds three read-only watches, no write on any governed resource, and
no permission on DevWorkspaces at all. **Both halves of that stop being true here.**

| Verb | Resource | Why |
| --- | --- | --- |
| `get`, `list`, `watch` | `controller.devfile.io/devworkspaces` | a controller has no admission request to read the object from |
| `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | `networking.k8s.io/networkpolicies` | the objects this feature exists to write |
| `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` | `cilium.io/ciliumnetworkpolicies` | only when the Cilium backend is enabled; omitted from the manifest otherwise |
| `create`, `delete` | `pods` **in the operator's own namespace only**, via a `Role` | the canary, and nothing else |

The last row is a `Role`, not a `ClusterRole`, and it is worth the extra object: the canary is
the only thing here that creates a workload, and it must be impossible for it to create one
anywhere but at home.

**Writing NetworkPolicies cluster-wide is the ability to cut the network of anything in the
cluster**, Che and this operator included. There is no smaller grant — RBAC does not scope a
verb to "namespaces matching a selector" — so the bound has to come from the code and be
verifiable by reading it. Four rules, each testable:

- **The label is the ownership boundary.** The operator reads, updates and deletes only objects
  carrying `hardening.weebo.io/managed-by: weebo-si-operator`. A cluster's existing policies are
  invisible to the diff, and no reconcile path can produce a delete for one.
- **Scope is a selector, applied before anything is computed.** Namespaces outside the feature's
  `namespaceSelector` produce an empty desired state *and are never diffed*, so an empty
  workspace list cannot turn into a deletion sweep.
- **Two namespaces are excluded structurally**: the operator's own and Che's. A deny-all
  baseline in our namespace severs our own apiserver connection, and the recovery for that is
  editing objects by hand from outside. The exclusion is a compiled-in refusal, not a
  configuration default, because a configuration default can be overwritten by the person
  debugging at three in the morning.
- **The canary is the only pod we create**, in our own namespace, from a pinned image, with no
  service account token mounted.

**Trust boundary, and the honest limit of this control.** Three inputs cross it, in increasing
order of hostility: the templates (admin-authored, read as opaque bytes, never parsed), the
namespace annotation (admin-level in a Che cluster, per
[RFC 0002](./0002-weebo-si-operator.md)), and the **DevWorkspace attribute, which is entirely
user-controlled**. A user writes their own devfile; nothing stops them writing
`hardening.weebo.io/network-profiles: "vault"`.

The containment is the same closed-catalogue argument as
[RFC 0002](./0002-weebo-si-operator.md)'s, and it carries more weight here because it is doing
more work: the requested set is **intersected with the team's `allowed`**, so a user obtains
exactly what an admin already granted their team, and an ungranted key is dropped or denied. A
user cannot name a template, cannot reference a policy object, and cannot express a rule. The
only thing they choose is a subset of what they already had.

Which leads to the sentence this RFC most needs to be read for:

> **The per-workspace level is least privilege, not an authorization boundary.** A user whose
> team is granted `vault` can give any of their workspaces `vault`, by editing a devfile. The
> boundary is the grant, and only a cluster admin writes grants.

What that buys is still worth having, and it is worth being precise about what it is: a
workspace that never asked for Vault cannot reach Vault *whatever runs inside it*. The threat
this closes is the extension, the post-install script, the dependency — code executing in a
workspace whose owner never intended to reach Vault from that project. It does not close a
malicious owner, and any document describing it as "project 1 cannot reach Vault" is describing
something else.

**Bypass.**

- **Writing your own policy.** The union semantics make this total: one user-authored policy
  reinstates everything the baseline removed. The first control is RBAC, and in the Che
  installation this repo targets it holds — a workspace user has no write verb on
  `networkpolicies` in their own namespace, so the bypass is closed before admission is
  involved. That is a property of *that* cluster, not of Che, and it is not one this brick can
  verify: it is a `RoleBinding` someone else owns, one `kubectl` away from being widened by
  somebody solving an unrelated problem. `policy-guard` is what turns "currently true" into
  "enforced", and in a cluster granting users something closer to the built-in `edit` role it is
  the only control at all. **Which of the two a cluster is must be checked at install** — it is
  the first item on the checklist, and it decides the guard's `failurePolicy` rather than
  whether the guard ships.
- **Deleting our objects.** Covered by the guard's `DELETE` rule, and by drift reconciliation
  behind it. Without the guard, the window between a delete and the next reconcile is real and
  unbounded by anything we control.
- **`hostNetwork` pods.** NetworkPolicy does not apply to them. A workspace that can run with
  `hostNetwork: true` is outside this control entirely — which is one of the things
  [RFC 0002](./0002-weebo-si-operator.md)'s DWOC pinning exists to prevent, and a good example
  of why these two features are worth more together than apart.
- **The CNI not enforcing.** The failure that makes everything above decorative while every
  object looks correct. `kubectl get networkpolicy` is not evidence of enforcement; only traffic
  is. This is what the canary answers, and why it defaults to on.
- **DNS.** A baseline must allow DNS or nothing resolves, and a permitted DNS channel is a
  permitted exfiltration channel. Accepted, named here so nobody discovers it as news, and
  bounded only by an egress DNS policy the cluster may or may not have.
- **Transitive reach.** A profile permitting a shared in-cluster service that itself reaches
  Vault grants Vault by proxy. NetworkPolicy has no notion of transitivity, so this is a
  property of the templates an admin writes, and it belongs in whatever review those templates
  get.
- **Address-based rules.** Two hostnames behind one address are one rule. An `ipBlock` cannot
  distinguish them, and no amount of care in the catalogue changes that.
- **Workspaces started before installation.** Their pods keep running with no profile object
  until the controller reaches them — the baseline arriving *later* tightens rather than
  loosens, so the direction is safe, but the window exists.

**Blast radius.** Larger than [RFC 0002](./0002-weebo-si-operator.md)'s in kind, not only in
degree, and for one reason worth stating plainly: **NetworkPolicy applies to pods that are
already running.** `dwoc-pin` changes what a workspace gets on its next start; a bad baseline
here severs every workspace's network in the cluster within seconds of the write, with no
restart involved and no gradual rollout to notice it during. That is the risk this design is
shaped around: `DryRun` prints the diff, the per-feature `namespaceSelector` bounds the first
enforcement to one namespace, the ownership label bounds what can be deleted, and the break-glass
in *Rollback* is a single labelled delete.

A compromise of the operator is correspondingly worse than before: it is the ability to write
network policy anywhere, which is both an outage and, in the other direction, the ability to
grant a workspace anything an attacker's template describes. Nothing in this design reduces that
below "do not let this deployment be compromised". What it does is keep the reachable surface
small and the writes labelled, so what was done is always visible.

**Secrets.** Still none. Templates are policy objects with no credential in them, the canary
mounts no service account token, and the logs carry namespace, workspace name, workspace id,
profile keys and diff verbs — never a template body, because a body is content we chose not to
understand and would therefore log without knowing what is in it.

## Operational considerations

**Failure mode, and it differs per feature — which is the chassis rule from
[RFC 0002](./0002-weebo-si-operator.md) meeting its first real test.**

`network-profiles` is a controller and sits in nobody's request path, so its failure mode is
*lag*, not rejection. The direction of that lag is the design's best property: a workspace whose
profile object has not been created yet reaches **less** than intended, not more, because the
baseline is namespace-scoped and already present while profiles are additive and arrive later. A
lagging controller produces a workspace that cannot reach Vault yet — a startup error someone
files a ticket about — rather than one that can reach Vault it should not have.

The exception is a **brand-new namespace**, where the baseline itself has not landed. Che creates
workspace namespaces automatically, so this window is real and it is the one place where lag is
unsafe. It is closed from the admission side: `policy-guard` also rejects a DevWorkspace
`CREATE` in a namespace whose baseline is absent from our cache, with a message saying to retry.
That is a fail-closed answer with no side effects, computed from a warm cache — the same
properties [RFC 0002](./0002-weebo-si-operator.md)'s webhook argues for.

`policy-guard` is a validating webhook and ships at `failurePolicy: Fail`, per the rule that
`failurePolicy` follows the feature: a control whose bypass is "make the webhook unavailable" is
not a control. The cost is bounded by its `namespaceSelector` requiring a positive label — when
the operator is down, network policy writes fail **in workspace namespaces only**, and the rest
of the cluster, Che's own namespace included, is untouched.

**The two features can block each other, and that is specific to this pair.** `policy-guard`
intercepts every write to `networkpolicies` in workspace namespaces, and workspace namespaces
are exactly where `network-profiles` writes. So the sibling feature's own reconcile passes
through our own webhook, every time. Two consequences, one tolerable and one not:

- **At `failurePolicy: Fail`, a webhook outage freezes the controller.** The apiserver rejects
  the controller's writes because the endpoint is unreachable, not because the verdict said no.
  This is tolerable: the two roles are separate Deployments per
  [RFC 0002](./0002-weebo-si-operator.md), the webhook runs two replicas behind a PDB with
  `maxUnavailable: 0`, and a rejected reconcile is retried rather than lost. The steady state
  after the outage is correct; only the lag grows, and lag degrades toward less access.
- **An identity-matching bug is a permanent self-lockout.** The exemption for our own writes is
  a comparison against `userInfo` in the admission request. If that comparison is ever wrong —
  a renamed service account, a namespace moved, a token issued by a different mechanism — the
  guard denies the controller's writes with a verdict rather than a timeout, retries do not help
  because the answer is deterministic, and the operator has locked itself out of the objects it
  is responsible for. It fails *safe* in the network sense, since existing policies stay in
  place, and it fails badly in every operational sense.

  Three things bound it: the exemption matches the service account's full
  `system:serviceaccount:<ns>:<name>` name, which changes only when a manifest changes; an
  end-to-end test asserts the controller can write through its own guard, which is the test that
  would catch a rename; and the break-glass is deleting the `ValidatingWebhookConfiguration`,
  which is [RFC 0002](./0002-weebo-si-operator.md)'s break-glass applied to a second object and
  belongs in the runbook next to it.

This is why a cluster that has verified its users cannot write policy has a real reason to run
the guard at `Ignore`: it keeps the regression-catching value, and removes the case where our
own webhook is between our own controller and its objects. That is a trade to make deliberately,
not a default to inherit — the guard at `Ignore` is worth nothing on the day the RBAC widens,
which is the day nobody announces.

[RFC 0002](./0002-weebo-si-operator.md) reasons about the operator not being able to block its
own pods. This is the same class of problem one level up: not the operator blocking its own
scheduling, but one feature blocking another's writes. A chassis carrying both admission and
reconcile features needs the question asked every time a pair of them touches the same resource,
and this RFC is where that rule starts.

**Rollout.** Six steps, and the order between the two features is not interchangeable:

1. Install, both features `Off`. Run `weebo-si-operator canary` and `backends` by hand. If the
   canary says `not_enforcing`, stop: nothing below this line will do anything, and finding that
   out now costs an afternoon rather than a quarter.
2. `networkProfiles: mode: DryRun`, catalogue and baseline written, no grants. Read the diff.
   Every namespace should show one `create:weebo-base` and nothing else.
3. Add the grants, still `DryRun`. Read the diff per team. This is where a wrong `spec.teams`
   label shows up as a namespace on the wrong grant.
4. `mode: Enforce` with a `namespaceSelector` on a pilot label, one namespace, and **then start
   a workspace in it**. The objects existing is not the test; the workspace working is.
5. Remove the selector. Widening is the step to do during working hours: it is the one that
   touches running pods.
6. **Only then** `policyGuard: mode: Enforce`. Turning the guard on before the profiles are
   correct means locking yourself out of fixing them by hand — and in a cluster where users
   cannot write policy anyway, there is no hurry: nothing is exposed between step 5 and step 6,
   so this step can wait for a calm afternoon and its own verification.

**Rollback**, and here it diverges from [RFC 0002](./0002-weebo-si-operator.md) in a way worth
understanding:

- `policyGuard: mode: Off` — seconds, restores everyone's ability to write policy in their own
  namespace. Do this first, always, because it is what makes manual repair possible.
- `networkProfiles: mode: Off` — **deletes every managed object.** This is the opposite of
  `dwoc-pin`, where rollback deliberately leaves pinned workspaces pinned, and the asymmetry is
  not an inconsistency. A workspace left pinned to a valid DWOC keeps working; a namespace left
  carrying a deny-all baseline with nothing reconciling it is a namespace nobody can fix and
  nothing will repair. State that outlives its controller must be state that is safe on its own,
  and a default-deny is not.
- **The break-glass**, when the operator itself is what is broken:

  ```console
  $ kubectl delete networkpolicy -A -l hardening.weebo.io/managed-by=weebo-si-operator
  ```

  One command, every namespace, nothing else touched — which is the third reason the ownership
  label exists, after bounding the diff and bounding the deletes. It belongs in the runbook next
  to [RFC 0002](./0002-weebo-si-operator.md)'s "delete the MutatingWebhookConfiguration", and an
  admin who installs this needs to know both before they need either.

**Observability.** `weebo_si_network_canary{result="not_enforcing"}` is the first alert and the
one nobody expects to need: it means every object is correct and none of them does anything.
`weebo_si_network_profile_unsupported` is the second — a profile silently not applied is a team
believing it has a permission it does not have, or a restriction that is not there.
`weebo_si_network_drift_total{action="restored"}` climbing means someone is fighting the
controller, which is either a user working around a policy or an admin who does not know the
guard exists. And `weebo_si_network_reconcile_total{result="error"}` sustained is the fleet
drifting away from its intended state one namespace at a time.

From the cluster's side, the CNI's own metrics for dropped flows are the ground truth about what
these policies actually do, and they belong on the same dashboard, because ours only report what
we *wrote*.

**Upgrade.** All writes go through server-side apply with a single field manager, so a rolling
update never produces two managers fighting over one object, and an interrupted apply is
resumable rather than half-done. The controller is leader-elected, so exactly one replica
writes; the webhook role stays horizontally scaled and writes nothing. A mixed-version fleet is
safe because the desired state is a pure function of `spec` and the workspace population, and
two versions computing it produce the same objects unless the RFC changed — which is why the
naming scheme is in the contract.

## Alternatives considered

**Kyverno `generate` rules.** The strongest contender, and stronger here than it was for
`dwoc-pin`: a `ClusterPolicy` with `generate` and `synchronize: true` creates a NetworkPolicy in
every matching namespace and puts it back when deleted, which is the baseline half of this RFC
in about thirty lines, with drift reconciliation included. Rejected on the other half. The
per-workspace part needs a resolution chain over three scopes, an intersection with a per-team
grant, an ownership-labelled diff, a backend that may not support a profile, and a `DELETE`-aware
guard — expressible in a policy DSL only as a growing pile of rules that nobody can read as one
decision, and untestable without a cluster. Worth revisiting for a cluster that wants the
baseline alone: for that, this RFC is the more expensive answer.

**A service mesh — Istio or Linkerd authorization policies.** Genuinely better security: L7,
identity-based, mTLS, per-path rules, and none of the address-versus-name problem that limits
*everything* in this RFC. Rejected on cost and blast radius, not on merit. A mesh is a sidecar
in every workspace pod, a control plane to run and upgrade, and a new failure mode for every
workspace start — against a hardening brick whose entire premise is that it can be switched off
in seconds. It is also not a substitute at the layer this operates on: without a mesh-only
network posture, raw egress still leaves the pod. The honest summary is that a mesh is a
different project, and this RFC is what a cluster does before deciding to have that project.

**Inventing an intent language and rendering it per backend.** Tempting: one `allow: {service:
vault, port: 8200}` vocabulary, rendered to NetworkPolicy or Cilium as available, with genuine
degradation logic. Rejected, and this is the design decision most worth defending. A renderer is
a translator, every mistranslation is a policy that permits more than it reads as, and that
class of bug is invisible in review because the source looks right. Copying an admin-authored
object and setting one field has no such failure mode. The cost is that an admin who wants two
backends authors two templates — real duplication, in exchange for the operator never being
wrong about what a rule means. If the duplication becomes the dominant pain, an intent layer
that *generates templates* offline is the way to add it without putting a translator in the
enforcement path.

**Embedding policy specs inline in `WeeboSiConfig`.** Everything in one object, no template
namespace, no second RBAC concern. Rejected: the CRD would embed `NetworkPolicySpec` and grow a
schema dependency on `networking.k8s.io`, the singleton would become the largest object in the
cluster, and admins would lose `kubectl diff`, GitOps and every other tool that already knows
how to review a NetworkPolicy. Templates keep policy content in the format the reviewer already
reads.

**Doing it at admission — mutating the DevWorkspace to carry its own policy.** Impossible, and
worth writing down so it is not proposed again: an admission webhook returns a patch for the
object under review and cannot create a second object. `sideEffects: None`, which
[RFC 0002](./0002-weebo-si-operator.md) relies on for `--dry-run=server`, is exactly the promise
that forbids it.

**One policy per namespace instead of one per workspace.** Simpler: no DevWorkspace watch, no
ownership references, no per-workspace naming, and the whole RBAC grant on `devworkspaces`
disappears. Rejected because it collapses the case this RFC was asked for — one user, one
namespace, two projects with different needs — into "the union of everything the user does",
which is the permission model we are trying to leave. It remains the right shape for a cluster
where namespaces are per team rather than per user, and is cheap to fall back to: write one
grant with a single-key `default` and never set the attribute.

**Cilium-only, using `toFQDNs` for everything.** The best answer for external targets by a wide
margin, and unavailable on any cluster without Cilium — which includes the OpenShift clusters
this repo's other bricks target. Rejected as the *only* backend, kept as a backend, which is the
whole reason backends exist.

**Doing nothing and relying on Che's namespace isolation.** Che isolates by namespace at the
RBAC layer and not at all at the network layer. There is no isolation to rely on.

## Drawbacks and risks

- **The operator now writes objects in namespaces it does not own.** Every argument
  [RFC 0002](./0002-weebo-si-operator.md) makes about a small read-only footprint stops applying
  to the deployment as a whole once this ships, and the cluster-wide write on `networkpolicies`
  is the largest single grant in this repo.
- **The blast radius is immediate.** Policies apply to running pods, so a bad baseline is a
  cluster-wide network outage in seconds, without the restart delay that makes `dwoc-pin`'s
  mistakes survivable.
- **The control is only as real as the CNI.** If policy is not enforced, every object is correct
  and nothing is protected. The canary makes this visible; it does not make it impossible, and a
  canary that itself breaks reports `unknown`, which is easy to ignore on a dashboard.
- **Per-workspace selection is hygiene, not authorization.** Restated here because it is the
  thing most likely to be over-read by someone skimming for a compliance answer.
- **NetworkPolicy cannot express a hostname.** Anything outside the cluster is a CIDR, CIDRs
  drift, and a wrong one is either an outage or a hole. The Cilium backend narrows this for the
  clusters that have it and widens the gap between what two clusters running this brick actually
  enforce.
- **Two features, two flags, two failure modes**, and an ordering constraint between them at
  rollout that is not enforced by anything but the runbook.
- **The two features sit in each other's path.** `policy-guard` intercepts writes to the objects
  `network-profiles` creates, so one feature's availability is on the other's write path. The
  outage case is survivable and the identity-matching case is not, and both are argued in
  *Operational considerations*. It is a coupling neither feature would have alone, and it is the
  first evidence that a chassis mixing admission and reconcile features needs the question asked
  for every pair of them that touches one resource.
- **The guard's importance is a property of the cluster, not of this repo.** In the target
  installation it catches a regression; elsewhere it is the whole control. That means the same
  code carries two very different risk profiles, and a reader who calibrates on one will be
  wrong about the other.
- **Templates are a second artefact to author, review and version**, in a namespace with its own
  RBAC requirement — and a template edit changes the network posture of every namespace using
  it, with no per-namespace rollout.
- **A DevWorkspace watch that scales with the fleet**, which is the first cache in this brick
  proportional to how much the cluster is used.
- **The chassis grows a second trait** on the evidence of one reconcile feature, which is the
  same sample-size-of-one risk [RFC 0002](./0002-weebo-si-operator.md) took with `Feature<S>`,
  taken again knowingly.
- **`mode: Off` deletes objects.** Correct, argued in *Rollback*, and still a rollback that
  changes cluster state rather than only policy — the opposite of the promise `dwoc-pin` makes,
  which is a thing to be careful about in a runbook covering both.

## Unresolved questions

**Blocking acceptance:**

- **Whether the workspace-side selector is a devfile attribute or an object annotation.** The
  table says `spec.template.attributes`, so the request travels with the project — which is what
  "my second project needs Vault" means, and it survives a workspace being recreated from the
  devfile. The cost is that a repository now carries a hardening key, and anyone forking it
  carries it too, bounded by the grant. An annotation on the DevWorkspace object is the
  alternative: closer to the cluster, invisible to the repo, and lost every time the workspace is
  recreated. This is the user-facing contract and it is settled before implementation.

**Not blocking:**

- Whether the shipped default for `policy-guard`'s `failurePolicy` should be `Fail` or `Ignore`.
  Settled at `Fail` for now, on the ground that a safe default beats a convenient one and that
  the RBAC it leans on belongs to someone else. The counter-argument is real and is in
  *Operational considerations*: in a cluster where users cannot write policy — which is the
  target cluster — `Ignore` keeps everything the guard is worth there and removes the case where
  our own webhook stands between our own controller and its objects.
- Whether `policy-guard` should also watch for the RBAC that makes it load-bearing: a periodic
  `SelfSubjectAccessReview`-style check answering "can a workspace user write policy here", and
  reporting it as a condition. It would turn an install-checklist item into a monitored fact,
  which is the difference between "true when we looked" and "true".
- Whether the canary should default to enabled. It is the only thing here that creates a pod,
  and it is also the only thing that can tell an admin the feature does nothing.
- Whether the baseline should be per team rather than one for the cluster. A team-specific floor
  is expressible today by granting a narrower profile set, and a genuinely different floor is
  not. Nobody has asked for one yet.
- Whether `weebo_si_network_reconcile_total` should carry a `profile` label. Bounded by the
  catalogue, useful for "who uses Vault", and one more dimension on the busiest counter.
- Whether a workspace naming an ungranted profile should be denied by default rather than
  silently dropped to the team default. `Deny` teaches faster and breaks workspaces that copied
  a devfile from a better-privileged team.
- Whether the guard should also cover `AdminNetworkPolicy` once clusters carry it.

## Future work

- **Egress through a filtering proxy**, so external targets can be named rather than addressed,
  on clusters without Cilium. It is the only portable answer to the hostname problem and it is a
  brick of its own.
- **`AdminNetworkPolicy` and `BaselineAdminNetworkPolicy`** as a third backend, once they are
  broadly available: they express a cluster-wide floor that a namespace-local policy cannot
  override, which is a better baseline than the one this RFC writes into each namespace.
- **Ingress profiles.** This RFC's baseline covers both directions, but every profile in the
  catalogue is egress-shaped, because that is where the exposure is. Workspace-to-workspace
  ingress deserves its own thinking.
- **Time-boxed grants** — a team granted Vault for the duration of an incident, expiring without
  anyone remembering to remove it.
- **Reporting effective reachability** rather than applied objects: "what can this workspace
  actually reach" is the question an auditor asks, and neither `kubectl get networkpolicy` nor
  our metrics answer it.
- **A drift reconciler for namespaces that leave scope**, cleaning up objects in a namespace the
  selector no longer matches, which today is left to `mode: Off` or the break-glass.

## Implementation plan

- [ ] `domain/model/policy.rs`, `profile.rs`, `diff.rs` — `ManagedObject`, opaque `PolicyBody`,
      `Backend`, `ProfileSet`, `Diff`. Pure, and a test asserting `PolicyBody` exposes no way to
      read its contents
- [ ] `domain/feature/mod.rs` — the `ReconcileFeature<S>` trait beside `Feature<S>`, sharing the
      registry, plus the test asserting `desired` cannot observe its mode
- [ ] `domain/port` — `PolicyStore`, `TemplateStore`, `Capabilities`, with in-memory fakes
- [ ] `domain/feature/network_profiles.rs` — the resolution chain, the intersection with
      `allowed`, `onNotGranted`, unsupported-variant handling, and the baseline refusal, table
      tested exhaustively
- [ ] The desired-state computation and the diff, tested against a fake store: create, update,
      no-op, delete, and the two cases that must never produce a delete — an unlabelled object,
      and a namespace out of scope
- [ ] `application/reconcile_network.rs` — mode at the edge, diff rendering for `DryRun`
- [ ] CRD types for both features, and `task recu` regenerating the schema
- [ ] `adapters/outbound/kube_policy_store.rs` — server-side apply with one field manager,
      label-filtered watch
- [ ] `adapters/outbound/kube_template_store.rs` and `kube_capabilities.rs`, plus the `Auto`
      backend resolution and its `status` reporting
- [ ] `adapters/inbound/controller.rs` — the DevWorkspace and Namespace reconcile loops, with
      the structural exclusion of our own and Che's namespaces as a compiled-in refusal and a
      test proving it cannot be configured away
- [ ] `domain/feature/policy_guard.rs` and its admission adapter — the three-row verdict table,
      including reading the ownership label from `oldObject` on `DELETE`
- [ ] The DevWorkspace `CREATE` rejection when a namespace has no baseline yet
- [ ] The canary: pod pair, probe, verdict, metric, and the `canary` subcommand
- [ ] `backends` subcommand
- [ ] Manifests: the `ClusterRole` above, the namespaced `Role` for the canary, the
      `ValidatingWebhookConfiguration` in both a `Fail` and an `Ignore` variant with the
      checklist question that picks one, and the Cilium rules in a separate overlay so a cluster
      without Cilium never grants them
- [ ] The end-to-end test that the controller can write through its own guard — the one that
      catches a service account rename before it becomes a permanent self-lockout
- [ ] End-to-end suite against a real apiserver with a policy-enforcing CNI: baseline created,
      profile per workspace, an ungranted request under both `onNotGranted` values, drift
      restored, `mode: Off` deleting everything, the guard denying a delete and a create, and a
      real connectivity assertion rather than an object assertion
- [ ] Docs: the runbook — the install checklist opening with "can a workspace user write
      `networkpolicies` in their own namespace", since it picks the guard's `failurePolicy`;
      then the canary; the rollout order between the two features; and both break-glasses, the
      labelled delete and the `ValidatingWebhookConfiguration` one
- [ ] RFC flipped to `Implemented`

## References

- [DevWorkspace Operator — `pkg/constants`](https://pkg.go.dev/github.com/devfile/devworkspace-operator/pkg/constants)
  — `controller.devfile.io/devworkspace_id`, the label every per-workspace policy selects on
- [Kubernetes — network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
  — the union semantics this whole design is shaped by, and the explicit note that policies do
  not apply to host-networked pods
- [Kubernetes — server-side apply](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
  — the field manager that keeps a rolling update from fighting itself
- [Kubernetes — owner references and garbage collection](https://kubernetes.io/docs/concepts/architecture/garbage-collection/)
  — why workspace deletion needs no code here
- [Cilium — network policy](https://docs.cilium.io/en/stable/security/policy/)
  — `CiliumNetworkPolicy`, `endpointSelector` and `toFQDNs`
- [Kubernetes — AdminNetworkPolicy](https://network-policy-api.sigs.k8s.io/)
  — the cluster-scoped floor named under *Future work*
- [RFC 0002](./0002-weebo-si-operator.md) — the chassis, the teams, the mode semantics and the
  `failurePolicy` rule this RFC inherits and extends
- [`../architecture/hexagonal.md`](../architecture/hexagonal.md) — the criteria the layout is
  measured against

## Changelog

| Date | Change |
| --- | --- |
