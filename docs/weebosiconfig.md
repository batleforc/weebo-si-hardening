# `WeeboSiConfig` — the configuration reference

Every hardening feature in this repo is configured by one object: a cluster-scoped
`WeeboSiConfig` named `cluster`. This page documents every field of it — what it means, whether
it is required, what it defaults to, and what happens when it is wrong.

This is the *reference*. Each feature's **why** is its RFC and each feature's **how to roll it
out** is [`bricks/weebo-si-operator.md`](./bricks/weebo-si-operator.md); when this page and an
RFC disagree, the RFC is right and this page is a bug.

The schema itself is generated from the Rust types in `crates/weebo-si-crd/` and checked in twice
(`crates/weebo-si-operator/deploy/crd.yaml` and `charts/weebo-si-operator/crds/`). Print it from
the binary that enforces it:

```bash
weebo-si-operator crd          # the generated CRD YAML
weebo-si-operator features     # which features this build actually contains
kubectl explain weebosiconfig.spec.features --recursive
```

## The object

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams: []
  features: {}
```

| | |
| --- | --- |
| Group / version | `hardening.weebo.io/v1alpha1` |
| Kind | `WeeboSiConfig` (plural `weebosiconfigs`) |
| Scope | Cluster |
| Name | **must be `cluster`** |

**Any other name is ignored**, and reported as a `Degraded` condition on that object rather than
silently obeyed — per RFC 0002. There is one configuration for the cluster; a second object is a
mistake, and a mistake that reads as "my settings are not taking effect" unless something says
so.

`spec.teams` and `spec.features` both default to empty. An empty `spec.features` means every
feature is `Off`: a behaviour nobody wrote down does not run.

## Shared vocabulary

Five things recur across features. They mean the same thing everywhere, and are documented once
here rather than five times below.

### `mode`

| Value | Meaning |
| --- | --- |
| `Off` | The feature does not run at all. |
| `DryRun` | The feature runs, is counted and logged; **nothing is applied or denied**. |
| `Enforce` | The feature runs, is counted and logged, and its result is applied. |

**`mode` is required on every feature block and has no default.** Omitting it is a rejected
write, not a silent `Off` — the two readings ("they forgot" and "they meant off") are
indistinguishable in a hardening control, so the schema refuses to choose. A feature *absent*
from `spec.features` is `Off`; a feature *present* must say which.

`DryRun` is the same computation as `Enforce` with the write or the denial withheld — features
are never told their own mode, so a dry run cannot measure something different from what
enforcement would do.

### `namespaceSelector`

Optional on every feature. Narrows that feature **within its own scope**: a namespace the
selector excludes is treated as `Off` for that feature, whatever the global `mode` says. Absent
(the common case) matches every namespace.

```yaml
namespaceSelector:
  matchLabels:
    weebo.io/tier: pilot
  matchExpressions:
    - key: weebo.io/team
      operator: In            # In | NotIn | Exists | DoesNotExist
      values: [team-1, team-2]
```

`matchLabels` and `matchExpressions` are ANDed. Both empty — the default — matches everything,
per upstream `LabelSelector` semantics. `values` is unused by `Exists`/`DoesNotExist`.

### Catalogue and grants

Four of the five features share one shape: an admin writes a **catalogue** of named entries, and
**grants** name which entries each team may reach.

```yaml
catalog:
  - key: base            # the short identifier everything else names
    # ...entry payload, different per feature
grants:
  team-1:
    allowed: [git-write, net-raw]   # what this team MAY reach
    default: [git-write]            # what it gets when nothing more specific is asked for
```

- A key is a short identifier, never a `{name, namespace}` pair — so a grant reads as a
  permission rather than as a pointer.
- `default` must be a subset of `allowed`; a team's own `allowed` must be catalogued.
- A team with no grant, and a namespace matching no team, reach the feature's own fallback
  (`default` at the top level for `dwoc-pin` and `image-policy`, the baseline alone for
  `network-profiles` and `kubearmor-policy`).

### The selection chain

Where a feature lets a workspace pick from what its team was granted, the chain is the same and
stops at the first source that applies:

1. **The devfile attribute** (`workspaceSelection.attribute`) — the complete requested list.
   Present-but-empty means "explicitly nothing beyond the baseline", and does **not** fall
   through.
2. **The namespace annotation** (`namespaceSelection.annotation`), when the attribute is absent.
3. **The grant's `default`**.

Both are comma-separated lists; whitespace is trimmed, empty segments dropped, duplicates removed
keeping first-seen order. Setting either key to the empty string disables that step.

A requested key outside the team's `allowed` is handled by `onNotGranted` / `onUnknownKey`:

| Value | Meaning |
| --- | --- |
| `Default` | Drop the whole request, apply the grant's `default`, and flag what was dropped. |
| `Deny` | Refuse the request, naming the ungranted keys. |

`Default` is the default.

### `templateRef`

`network-profiles` and `kubearmor-policy` copy their rule content from **real objects an admin
authors**, never from a DSL in the CRD:

```yaml
templateRef:
  name: weebo-base
  namespace: weebo-si-hardening
```

The operator copies the template's rule fields verbatim and rewrites the selector to scope the
copy. A template's own selector is ignored — scoping belongs to the operator.

## `spec.teams`

```yaml
spec:
  teams:
    - name: team-1
      namespaceSelector:
        matchLabels: { weebo.io/team: team-1 }
    - name: team-2
      namespaceSelector:
        matchExpressions:
          - { key: weebo.io/team, operator: In, values: [team-2, team-2-sandbox] }
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `name` | string | yes | The team's identity — what every feature's `grants` keys on. |
| `namespaceSelector` | [Selector](#namespaceselector) | yes | Which namespaces belong to this team. |

**The list is ordered and the first match wins.** A namespace matching two teams belongs to the
first one declared; that is a defined outcome rather than an error, so overlapping selectors are
a readability problem and not an outage.

A team named by a feature's `grants` but absent from `spec.teams` is a configuration violation,
reported as `Degraded`.

## `spec.features`

One optional block per feature. A feature this build does not know about cannot be written into
the object at all — the schema is typed, so a typo in a feature name is rejected by the apiserver
rather than ignored at runtime.

| Field | RFC | Acts on |
| --- | --- | --- |
| [`dwocPin`](#featuresdwocpin) | [0002](./rfc/0002-weebo-si-operator.md) | `DevWorkspace` (mutating admission) |
| [`networkProfiles`](#featuresnetworkprofiles) | [0004](./rfc/0004-network-profiles.md) | `Namespace`, `DevWorkspace` (reconcile) |
| [`policyGuard`](#featurespolicyguard) | [0004](./rfc/0004-network-profiles.md) | `NetworkPolicy`, `CiliumNetworkPolicy` (validating admission) |
| [`imagePolicy`](#featuresimagepolicy) | [0005](./rfc/0005-image-policy.md) | `DevWorkspace`, `Pod` (validating admission) |
| [`kubearmorPolicy`](#featureskubearmorpolicy) | [0006](./rfc/0006-kubearmor-policy.md) | `Namespace`, `DevWorkspace` (reconcile) |

### `features.dwocPin`

Pins every admitted `DevWorkspace` to an admin-authored `DevWorkspaceOperatorConfig`, so a config
override a user's own devfile carries never reaches one.

```yaml
dwocPin:
  mode: Enforce
  catalog:
    - key: standard
      name: devworkspace-config
      namespace: eclipse-che
    - key: gpu
      name: dwoc-gpu
      namespace: eclipse-che
  default: standard
  grants:
    team-1:
      allowed: [standard, gpu]
      default: gpu
  namespaceSelection:
    annotation: hardening.weebo.io/dwoc
    onUnknownKey: Default
  onMissingTarget: Skip
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `catalog` | list | yes | — | Every DWOC a workspace may run with. |
| `catalog[].key` | string | yes | — | The short identifier grants and annotations name. |
| `catalog[].name` | string | yes | — | The `DevWorkspaceOperatorConfig`'s name. |
| `catalog[].namespace` | string | yes | — | The namespace it lives in. |
| `default` | key | yes | — | The entry a namespace belonging to no team gets. |
| `grants` | map team → grant | no | `{}` | |
| `grants.<team>.allowed` | list of keys | yes | — | Must be non-empty. |
| `grants.<team>.default` | **one** key | yes | — | Singular here, unlike every other feature: a workspace runs with exactly one DWOC. |
| `namespaceSelection.annotation` | string | no | `hardening.weebo.io/dwoc` | Empty string disables namespace selection. |
| `namespaceSelection.onUnknownKey` | `Default`/`Deny` | no | `Default` | An uncatalogued or ungranted key in that annotation. |
| `onMissingTarget` | `Skip`/`Deny` | no | `Skip` | The resolved entry does not point at a live DWOC. |

`Skip` means the workspace proceeds with whatever it asked for — deliberately fail-open on a
*catalogue* mistake, since a missing DWOC is an admin error and denying every workspace in the
cluster for it is worse than not pinning them.

### `features.networkProfiles`

Gives every workspace namespace a `NetworkPolicy` baseline plus admin-granted per-workspace
profiles.

```yaml
networkProfiles:
  mode: Enforce
  catalog:
    - key: base
      variants:
        - backend: NetworkPolicy
          templateRef: { name: weebo-base, namespace: weebo-si-hardening }
    - key: git
      variants:
        - backend: NetworkPolicy
          templateRef: { name: weebo-git, namespace: weebo-si-hardening }
        - backend: Cilium
          templateRef: { name: weebo-git-cilium, namespace: weebo-si-hardening }
  baseline: base
  grants:
    team-1: { allowed: [git], default: [git] }
  namespaceSelection: { annotation: hardening.weebo.io/network-profiles }
  workspaceSelection: { attribute: hardening.weebo.io/network-profiles }
  onNotGranted: Default
  enforcement:
    backend: Auto
    canary: { enabled: true, intervalSeconds: 300 }
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `catalog[].key` | string | yes | — | |
| `catalog[].variants[].backend` | `NetworkPolicy`/`Cilium` | yes | — | Which dialect this variant is written in. |
| `catalog[].variants[].templateRef` | `{name, namespace}` | yes | — | The object whose rules are copied. |
| `baseline` | key | yes | — | Applied to every namespace in scope; **no grant can withhold it**. |
| `grants` | map team → `{allowed, default}` | no | `{}` | Both lists, both may be empty. |
| `namespaceSelection.annotation` | string | no | `hardening.weebo.io/network-profiles` | |
| `workspaceSelection.attribute` | string | no | `hardening.weebo.io/network-profiles` | |
| `onNotGranted` | `Default`/`Deny` | no | `Default` | |
| `enforcement.backend` | `Auto`/`NetworkPolicy`/`Cilium` | no | `Auto` | `Auto` picks the most capable dialect the apiserver offers, preferring Cilium. |
| `enforcement.canary.enabled` | bool | no | `true` | The periodic probe that proves the CNI enforces policy at all. |
| `enforcement.canary.intervalSeconds` | integer | no | `300` | Clamped to a 60s floor. |

`enforcement.canary` as a whole defaults, but its two fields do not: **write `canary` at all and
you must write both `enabled` and `intervalSeconds`.** A partial block is rejected by the
apiserver, which is a confusing error for a field whose defaults are documented above — omit the
block entirely to take them.

A profile with **no variant for the resolved backend is not applied** — never approximated with
another dialect's rules. An admin who wants a coarser fallback writes it as that backend's
variant, deliberately. Check what a cluster offers with `weebo-si-operator backends`.

### `features.policyGuard`

Refuses writes to the policy objects this operator owns.

```yaml
policyGuard:
  mode: Enforce
  allowedIdentities:
    - system:serviceaccount:platform:network-admin
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `allowedIdentities` | list of strings | no | `[]` | Identities that may author *unmanaged* policies in workspace namespaces. |

The operator's own identity is always exempt and is **not** configured here — it is the
`--operator-identity` flag on the webhook, which the chart renders from its own `ServiceAccount`.
Getting it wrong locks the controller out of the objects it is responsible for.

`allowedIdentities` exempts an identity from the "authorship belongs to the platform" rule only.
**Nobody but the operator may touch an object carrying the management label**, including these
identities. The guard covers `networkpolicies` and `ciliumnetworkpolicies`;
[RFC 0008](./rfc/0008-policy-guard-coverage.md) is the design for extending it to
`kubearmorpolicies`.

### `features.imagePolicy`

Decides which container images a workspace may run, per team.

```yaml
imagePolicy:
  mode: Enforce
  catalog:
    - key: internal
      patterns:
        - registry.internal/**
        - registry.internal/teams/{TEAM_NAME}/**
    - key: devfile-udi
      patterns: ["quay.io/devfile/universal-developer-image:*"]
  variables:
    COST_CENTRE: { fromNamespaceAnnotation: weebo.io/cost-centre }
  default: [devfile-udi]
  grants:
    team-1: { allowed: [internal, devfile-udi], default: [internal] }
  namespaceSelection: { annotation: hardening.weebo.io/image-policy }
  workspaceSelection: { attribute: hardening.weebo.io/image-policy }
  onNotGranted: Default
  platform:
    builtin: true
    extra: ["registry.internal/mirror/che/**"]
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `catalog[].key` | string | yes | — | |
| `catalog[].patterns` | list of strings | yes | — | Non-empty. Held as the text an admin wrote, so the CRD stays readable. |
| `variables` | map name → binding | no | `{}` | Declaring one opts into an annotation-sourced pattern value. |
| `variables.<NAME>.fromNamespaceAnnotation` | string | yes | — | The only binding form that ships. |
| `default` | list of keys | yes | — | Applied to a namespace with no team, or a team with no grant. May be empty (platform set only). |
| `grants` | map team → `{allowed, default}` | no | `{}` | |
| `namespaceSelection.annotation` | string | no | `hardening.weebo.io/image-policy` | |
| `workspaceSelection.attribute` | string | no | `hardening.weebo.io/image-policy` | |
| `onNotGranted` | `Default`/`Deny` | no | `Default` | |
| `platform.builtin` | bool | no | `true` | The compiled-in platform patterns (Che, DevWorkspace Operator). Explicitly **not** contract — they track upstream. |
| `platform.extra` | list of strings | no | `[]` | Additional always-allowed patterns, for a mirrored platform. |

**Variable names are `[A-Z][A-Z0-9_]*`.** `TEAM_NAME` and `NAMESPACE` are reserved and resolved
by the operator; rebinding either in `variables` is a violation. A variable read from a namespace
annotation is only as trustworthy as the RBAC on that namespace — see RFC 0005's *Security
considerations* before declaring one.

The platform set is allowed in every namespace regardless of team, and is the one set no grant
can withhold. Inspect what a reference resolves to with `weebo-si-operator images check <ref>`.

### `features.kubearmorPolicy`

Decides what a workspace's processes may do — execute, read, write, which capabilities — per
team, through KubeArmor.

```yaml
kubearmorPolicy:
  mode: DryRun
  catalog:
    - key: base
      templateRef: { name: weebo-base-runtime, namespace: weebo-si-hardening }
    - key: git-write
      templateRef: { name: weebo-git-write-runtime, namespace: weebo-si-hardening }
  baseline: base
  grants:
    team-1: { allowed: [git-write], default: [git-write] }
  namespaceSelection: { annotation: hardening.weebo.io/kubearmor-policy }
  workspaceSelection: { attribute: hardening.weebo.io/kubearmor-policy }
  onNotGranted: Default
  enforcement:
    backend: Auto
    defaultPosture:
      file: Audit
      network: Audit
      capabilities: Audit
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `catalog[].key` | string | yes | — | |
| `catalog[].templateRef` | `{name, namespace}` | yes | — | One ref, not a `variants` list: there is one engine today. |
| `baseline` | key | yes | — | Applied to every workspace pod in scope; no grant can withhold it. |
| `grants` | map team → `{allowed, default}` | no | `{}` | |
| `namespaceSelection.annotation` | string | no | `hardening.weebo.io/kubearmor-policy` | |
| `workspaceSelection.attribute` | string | no | `hardening.weebo.io/kubearmor-policy` | |
| `onNotGranted` | `Default`/`Deny` | no | `Default` | |
| `enforcement.backend` | `Auto`/`KubeArmor` | no | `Auto` | `Auto` resolves to nothing at all on a cluster that does not serve the `KubeArmorPolicy` CRD, and the feature writes nothing there. |
| `enforcement.defaultPosture.file` | `Audit`/`Block` | no | `Audit` | Unmatched **file and process** operations. |
| `enforcement.defaultPosture.network` | `Audit`/`Block` | no | `Audit` | Unmatched network operations. |
| `enforcement.defaultPosture.capabilities` | `Audit`/`Block` | no | `Audit` | Unmatched capability use. |

**`defaultPosture` has three fields, not four**: KubeArmor evaluates process rules under the
*file* posture, so a `process` field would be one nothing reads. It is written onto each
namespace in scope as the `kubearmor-file-posture` / `kubearmor-network-posture` /
`kubearmor-capabilities-posture` annotations, and it is what happens to an operation **no rule
matched**. Moving one to `Block` denies everything the templates did not think to allow — read
the rollout in [`bricks/weebo-si-operator.md`](./bricks/weebo-si-operator.md) before doing it.

Check the cluster first: `weebo-si-operator backends kubearmor --verbose` answers both whether
the CRD is served and which nodes can actually enforce a policy.

## `status`

Written by the controller, derived entirely from `spec` — deleting it costs one reconcile.

```yaml
status:
  observedGeneration: 7
  features:
    - name: network-profiles
      state: Active
      message: "evaluated 214 workspaces: 6 would be replaced"
      observedGeneration: 7
  conditions:
    - type: Ready
      status: "True"
```

| Field | Meaning |
| --- | --- |
| `observedGeneration` | The `metadata.generation` this status reflects. Lagging means the controller has not caught up. |
| `features[]` | One entry per registered feature, whatever its mode. |
| `features[].name` | The feature's kebab-case id, as `weebo-si-operator features` prints it. |
| `features[].state` | `Disabled` (`Off`), `DryRun`, `Active` (`Enforce`), or `Degraded`. |
| `features[].message` | Human-readable detail. |
| `features[].observedGeneration` | The generation this feature's state was computed from. |
| `conditions` | Standard `metav1.Condition` list: `Ready`, `Degraded`. |

**`Degraded` means the configuration was rejected at reconcile**, not that the cluster is
unhealthy. One condition per violation, so a broken catalogue tells you every problem at once
rather than one per edit round-trip.

## When the configuration is wrong

Validation is **reconcile-time, not write-time**: the apiserver accepts a structurally valid
object, and the controller reports what is semantically wrong as `Degraded` conditions. A
validating webhook on our own CRD is shared future work across RFC 0002 and RFC 0005.

Every feature with a catalogue reports the same family of violations:

| Violation | Meaning |
| --- | --- |
| Duplicate key | The same `catalog[].key` appears twice. |
| Baseline / default not in catalogue | `baseline` (or top-level `default`) names a key nothing declares. |
| Grant allows an uncatalogued key | A team's `allowed` names a key nothing declares. |
| Grant default outside its own allowed | A team's `default` is not a subset of its `allowed`. |
| Grant names an undeclared team | `grants` keys on a name absent from `spec.teams`. |

Plus, per feature: `dwoc-pin` reports an empty `allowed`; `network-profiles` reports a profile
with no variants, or two variants for one backend; `image-policy` reports an unparseable pattern,
an illegal variable name, or a rebound reserved variable.

## Keys this configuration puts in other objects' hands

Worth knowing because they are the surface a *user* touches, not an admin.

| Key | On | Who writes it | Effect |
| --- | --- | --- | --- |
| `hardening.weebo.io/dwoc` | Namespace | admin | Selects a `dwoc-pin` catalogue key. |
| `hardening.weebo.io/network-profiles` | Namespace, DevWorkspace attribute | admin / workspace author | Selects network profile keys. |
| `hardening.weebo.io/image-policy` | Namespace, DevWorkspace attribute | admin / workspace author | Selects image entry keys. |
| `hardening.weebo.io/kubearmor-policy` | Namespace, DevWorkspace attribute | admin / workspace author | Selects runtime profile keys. |
| `hardening.weebo.io/managed-by` | objects the operator writes | **operator** | The ownership boundary. Never set it by hand. |
| `hardening.weebo.io/profile` | objects the operator writes | **operator** | Which catalogue key the object came from. |
| `hardening.weebo.io/backend` | objects the operator writes | **operator** | Which dialect it is written in. |
| `kubearmor-{file,network,capabilities}-posture` | Namespace | **operator** | KubeArmor's default posture. |
| `kubearmor.io/enforcer` | Node | **KubeArmor** | Which LSM that node can enforce with. Read-only for us. |

A selection key naming something the team was not granted is not an escalation: it is a
*request*, bounded by the grant, resolved by `onNotGranted`. The boundary is the grant, and only
a cluster admin writes grants.
