# `WeeboSiConfig` — the configuration reference

Every hardening feature in this repo is configured by one object: a cluster-scoped
`WeeboSiConfig` named `cluster`. This page documents every field of it — what it means, whether
it is required, what it defaults to, and what happens when it is wrong.

This is the *reference*. Each feature's **why** is its RFC and each feature's **how to roll it
out** is [`bricks/weebo-si-operator.md`](./bricks/weebo-si-operator.md) — or, for the two kinds
below and the `identity` feature, [`bricks/teams-and-users.md`](./bricks/teams-and-users.md).
The two other kinds have their own field references: [`weebositeam.md`](./weebositeam.md) and
[`weebosiuser.md`](./weebosiuser.md). When this page and an RFC disagree, the RFC is right and
this page is a bug.

The schema itself is generated from the Rust types in `crates/weebo-si-crd/` and checked in twice
(`crates/weebo-si-operator/deploy/crd.yaml`, which carries all three kinds, and
`charts/weebo-si-operator/crds/`, one file each). Print it from the binary that enforces it:

```bash
weebo-si-operator crd          # every generated CRD, as one document stream
weebo-si-operator crd weebositeams   # or just one kind
weebo-si-operator features     # which features this build actually contains
kubectl explain weebosiconfig.spec.features --recursive
```

To build one without hand-writing YAML, the [config generator](https://batleforc.github.io/weebo-si-hardening/#WeeboSiConfig) renders a form
from this same schema, validates as you type and prints the object.

## The object

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
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

`spec.features` defaults to empty, and an empty `spec.features` means every feature is `Off`: a
behaviour nobody wrote down does not run.

`spec.teams` used to live here and does not any more. Since
[RFC 0011](./rfc/0011-teams-and-users.md) a team is its own cluster-scoped object,
[`WeeboSiTeam`](#teams-and-people), carrying its own catalogue entries and its own defaults; a
manifest still carrying `spec.teams` has that field pruned by the API server.

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

Four of the five features share one shape: a **catalogue** of named entries, and a per-team answer
saying which of them that team reaches. Since [RFC 0011](./rfc/0011-teams-and-users.md) the two
halves live in two objects:

```yaml
# WeeboSiConfig — the platform's own entries, and what a namespace with no team gets
catalog:
  - key: base            # the short identifier everything else names
    # ...entry payload, different per feature
default: [base]          # or `baseline:`, depending on the feature
```

```yaml
# WeeboSiTeam — this team's own entries, and what its namespaces get
features:
  <feature>:
    catalog:
      - key: git-write
        # ...same entry payload
    default: [git-write]
```

- A key is a short identifier, never a `{name, namespace}` pair — so a grant reads as a
  permission rather than as a pointer.
- **A key means one thing cluster-wide.** The evaluated catalogue is the cluster's entries plus
  every team's; two teams may declare one key only if the entries are identical, and a
  redefinition is reported on the offending team while the first definition stands.
- **A team never writes an `allowed` list.** What it reaches is the catalogue it declares, plus
  whatever the cluster hands everybody (`default`, or `baseline`).
- A team with no block for a feature, and a namespace matching no team, both reach the feature's
  own fallback (`default` at the top level for `dwoc-pin` and `image-policy`, the baseline alone
  for `network-profiles` and `kubearmor-policy`).

### The selection chain

Where a feature lets a workspace pick from what its team was granted, the chain is the same and
stops at the first source that applies:

1. **The devfile attribute** (`workspaceSelection.attribute`) — the complete requested list.
   Present-but-empty means "explicitly nothing beyond the baseline", and does **not** fall
   through.
2. **The namespace annotation** (`namespaceSelection.annotation`), when the attribute is absent.
3. **The team's `default`**, or the cluster's for a namespace with no team.

Both are comma-separated lists; whitespace is trimmed, empty segments dropped, duplicates removed
keeping first-seen order. Setting either key to the empty string disables that step.

A requested key outside what the team reaches is handled by `onNotGranted` / `onUnknownKey`:

| Value | Meaning |
| --- | --- |
| `Default` | Drop the whole request, apply the team's `default`, and flag what was dropped. |
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
copy. A template's own selector is ignored *for the copies* — scoping belongs to the operator.

**It is not ignored where the template itself lives.** A template is a live `NetworkPolicy` (or
`KubeArmorPolicy`) in the operator's namespace, enforced there like any other, so its own selector
decides which *operator* pods it applies to. Give every template a selector no pod carries:

```yaml
spec:
  podSelector:
    matchLabels: { hardening.weebo.io/template: "never-matches" }
```

`podSelector: {}` on a restrictive egress template applies that egress to the operator's own
webhook and controller — the webhook then cannot reach the apiserver, and with `failurePolicy:
Fail` every workspace admission in the cluster fails with it.

## Teams and people

Two cluster-scoped kinds, added by [RFC 0011](./rfc/0011-teams-and-users.md) and installed by the
same chart: `WeeboSiTeam` (`wsteam`) and `WeeboSiUser` (`wsuser`). **Both are security objects**:
whoever may write a `WeeboSiTeam` decides which DevWorkspace Operator configs, image patterns and
registries that team reaches.

**They are admin-only, and that is a decision rather than a default.** A team lead does not get
`edit` on their own team's object — not by `resourceNames`, not by moving it into a namespace they
own. The set of people who may write a `WeeboSiTeam` is exactly the set who may already write the
singleton, and the per-team catalogue ships with no ceiling over its contents *because* of that.
Granting a team write access to its own object without adding that ceiling first would let it
catalogue anything it likes.

This section is the summary; every field of both kinds, their validation and their `status` are in
[`weebositeam.md`](./weebositeam.md) and [`weebosiuser.md`](./weebosiuser.md).

### `WeeboSiTeam`

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: platform
spec:
  displayName: Platform
  priority: 100
  namespaceSelector:
    matchLabels: { weebo.io/team: platform }
  features:
    dwocPin:
      catalog:
        - key: platform-gpu
          name: dwoc-gpu
          namespace: eclipse-che
      default: platform-gpu
  identity:
    authentik:
      groupRefs: [platform]
  workspace:
    che:
      mode: Ensure
      project: weebo-dev
      source:
        repoUrl: https://charts.weebo.io
        chart: che-user
        targetRevision: 1.4.2
        values:
          username: "{USERNAME}"
      destination:
        server: https://kubernetes.default.svc
        namespace: "{USERNAME}-che"
      syncPolicy:
        automated: { prune: true, selfHeal: true }
        options: ["CreateNamespace=true"]
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `metadata.name` | string | yes | — | **Is** the team name — what a `WeeboSiUser` references. |
| `displayName` | string | no | the name | Human label. Nothing branches on it. |
| `priority` | int32 | no | `1000` | Precedence when a namespace matches two teams: lowest wins, ties break on name. |
| `namespaceSelector` | [Selector](#namespaceselector) | yes | — | Which namespaces belong to this team. |
| `features.<feature>` | object | no | absent | This team's `catalog` and `default` for one feature. Absent means the cluster answer applies unchanged. |
| `identity.authentik.groupRefs` | `[string]` | no | `[]` | Authentik group names every member receives, each checked against the cluster allow-list. |
| `workspace.che` | object | no | absent | The Argo CD `Application` template each member instantiates — `mode`, `project`, `source`, `destination`, `syncPolicy`, rendered per person. |

**Ordering is explicit.** `spec.teams` was a list, and reading order decided who owned an
overlapping namespace; separate objects have no order, so `priority` replaces it.

### `WeeboSiUser`

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiUser
metadata:
  name: max
spec:
  username: max
  displayName: Max Leriche
  email: max@weebo.io
  team: platform
  authentik:
    mode: Ensure
    groupRefs: [oncall-eu]
  che:
    mode: Ensure
    values:
      storage: { size: 30Gi }
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `username` | string | yes | — | The Kubernetes identity. Two objects claiming one username is a violation on both. |
| `displayName` | string | no | `username` | Passed to Authentik as `name`. |
| `email` | string | when provisioning | — | Required unless `authentik.mode` is `Off`. |
| `team` | string | no | — | A `WeeboSiTeam` name. Empty is legal and reported: no entitlement, no workspace. |
| `active` | bool | no | `true` | `false` suspends provisioning without deleting anything. |
| `authentik.mode` | `Off`/`Ensure` | when the block is present | — | `Ensure` creates the `AuthentikUser` when missing and references it when somebody else owns it. |
| `authentik.name` | string | no | `metadata.name` | The `AuthentikUser` this person maps to. |
| `authentik.groupRefs` | `[string]` | no | `[]` | Groups **in addition** to the team's. |
| `che.mode` | `Off`/`Ensure` | when the block is present | — | Instantiate the team's workspace template. |
| `che.namespace` | string | no | the rendered template | Overrides the destination namespace, and with it `{USER_NAMESPACE}`. |
| `che.values` | object | no | — | Helm values deep-merged **over** the team's. |

Membership declared here wins over the one `endpoint-auth` derives from namespace ownership; the
derivation stays as the answer for somebody with no object.

### Migrating from `spec.teams`

`weebo-si-operator teams export` reads the old singleton — `spec.teams` plus every `grants` map,
the two shapes the current schema no longer has a type for — and prints one `WeeboSiTeam` per
team. It writes nothing to the cluster, ever: the objects go to a file you keep, because the
rollback for the last step of this migration is the old manifest and nothing else.

```bash
# from the live cluster, or from the manifest you still have in git
weebo-si-operator teams export > teams.yaml
weebo-si-operator teams export --from weebosiconfig.yaml > teams.yaml

kubectl apply -f teams.yaml
weebo-si-operator teams export --check     # non-zero until the cluster matches
```

What the conversion does, and what it refuses to guess:

- **Document order becomes `priority`** — the first team gets `100`, the second `200`, and so on,
  so first-match-wins keeps meaning what it meant with room to insert a team later.
- **A grant becomes the team's own catalogue**, minus whatever the cluster already hands
  everybody: an entry the cluster `default` or `baseline` names stays reachable without being
  redeclared.
- **A grant that named only the cluster floor is dropped.** It granted nothing, and a team with
  no block for a feature already gets exactly that.
- **A grant naming a team `spec.teams` never declared, or a key the catalogue never declared, is
  reported on stderr and dropped** — the two mistakes the old schema could hold and the new one
  cannot.
- `identity` and `workspace` are left empty. Nothing in the old schema describes an Authentik
  group or a workspace template, and inventing one is not a migration.

Only when `--check` is clean: remove `spec.teams` and every `grants` map from the singleton and
upgrade the deployment. Doing that first means every namespace falls to the cluster default until
the teams land — safe, and visible in the feature metrics as a step change.

### Template variables

`workspace.che` is rendered per person with RFC 0005's `{VARIABLE}` notation. An unknown name is a
violation, never a literal; `{{ ... }}` is copied through verbatim, so a Helm template inside
`values` survives.

| Variable | Value |
| --- | --- |
| `{USERNAME}` | `spec.username` |
| `{OBJECT_NAME}` | the `WeeboSiUser`'s `metadata.name` |
| `{TEAM_NAME}` | `spec.team`, empty when they have none |
| `{EMAIL}` | `spec.email`, empty when unset |
| `{DISPLAY_NAME}` | `spec.displayName`, defaulted to the username |
| `{USER_NAMESPACE}` | the rendered `destination.namespace` — resolved first, so the namespace template cannot name it |

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
| [`registryConfig`](#featuresregistryconfig) | [0007](./rfc/0007-registry-config.md) | `Namespace` (reconcile) |
| [`endpointAuth`](#featuresendpointauth) | [0009](./rfc/0009-endpoint-auth.md) | `Ingress`, `Route` (mutating + validating admission, reconcile) |

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
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.dwocPin.{catalog,default}`. The team's `default` is **one** key here, unlike every other feature: a workspace runs with exactly one DWOC. |
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
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.networkProfiles.{catalog,default}`. The baseline applies either way. |
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
identities — with one exception on the registry rule below, where an `allowedIdentity` *may*
touch a managed object, because there is no unmanaged-authorship row for it to be exempt from
instead.

The guard covers `networkpolicies` and `ciliumnetworkpolicies`, and — when
`registryConfig.rbac.enabled` is set in the chart — the `configmaps` and `secrets`
`registryConfig` writes, on its own webhook path. The registry rule differs from the network one
in three ways, all argued in [RFC 0007](./rfc/0007-registry-config.md):

| | Network rule | Registry rule |
| --- | --- | --- |
| Path | `/validate/v1/networkpolicies` | `/validate/v1/registryconfigs` |
| `objectSelector` | none | `hardening.weebo.io/managed-by: weebo-si-operator` |
| `failurePolicy` | `Fail` | `Ignore` |
| Refuses unmanaged `CREATE`? | yes | **no** |

The last two rows are the same decision seen twice: `ConfigMap` writes are among the highest
volume in a cluster, so the rule is scoped to objects this operator wrote and does not take the
apiserver down with it when the webhook is unavailable. A guard rule that must refuse unmanaged
creates cannot use an ownership `objectSelector`; one that only protects existing objects should.

[RFC 0008](./rfc/0008-policy-guard-coverage.md) is the design for extending the guard to
`kubearmorpolicies` and unifying the two shapes.

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
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.imagePolicy.{catalog,default}`. The platform set applies either way. |
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
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.kubearmorPolicy.{catalog,default}`. The baseline applies either way. |
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

### `features.registryConfig`

Puts the package-manager configuration a workspace needs — the `.npmrc`, the `pip.conf`, the
Cargo `config.toml`, the Maven `settings.xml` — inside every workspace container of a namespace,
per team. See [RFC 0007](./rfc/0007-registry-config.md).

```yaml
registryConfig:
  mode: DryRun
  catalog:
    - key: internal-npm
      ecosystem: Npm
      sources:
        - kind: ConfigMap
          templateRef: { name: weebo-npmrc, namespace: weebo-si-hardening }
        - kind: Secret
          templateRef: { name: weebo-npm-token, namespace: weebo-si-hardening }
    - key: internal-pypi
      ecosystem: Pypi
      sources:
        - kind: ConfigMap
          templateRef: { name: weebo-pip-conf, namespace: weebo-si-hardening }
  namespaceSelection: { annotation: hardening.weebo.io/registry-config }
  onNotGranted: Default
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | |
| `namespaceSelector` | Selector | no | matches all | |
| `catalog[].key` | string | yes | — | |
| `catalog[].ecosystem` | closed enum | no | `Other` | `Npm`/`Pypi`/`Cargo`/`Go`/`Maven`/`RubyGems`/`Composer`/`Conda`/`Terraform`/`OpenVsx`/`Other`. **A metric label and a CLI grouping — nothing branches on it.** |
| `catalog[].sources[].kind` | `ConfigMap`/`Secret` | yes | — | |
| `catalog[].sources[].templateRef` | `{name, namespace}` | yes | — | The object copied verbatim. At least one source per entry; at most one per `{kind, name, namespace}`. |
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.registryConfig.{catalog,default}`. A team with no block mounts nothing. |
| `namespaceSelection.annotation` | string | no | `hardening.weebo.io/registry-config` | |
| `onNotGranted` | `Default`/`Deny` | no | `Default` | |

**Two fields every other catalogue feature has and this one does not**, and both absences are
deliberate:

- **No `baseline`.** There is no universally correct `.npmrc` — a mandatory entry would write a
  file into a container whose image may not even have the tool it configures. "Everyone gets the
  mirror" is a grant every team has, not a mandatory entry.
- **No `workspaceSelection`.** DevWorkspace Operator's automount is a property of the
  *namespace*: an object labelled `controller.devfile.io/mount-to-devworkspace: "true"` is
  mounted into every container of every workspace in the namespace hosting it, with no selector.
  There is no per-workspace mechanism to route to. A team wanting two different npm mirrors needs
  two namespaces.

The templates are **ordinary `ConfigMap`/`Secret` objects an admin applies** to the operator's
namespace, carrying DevWorkspace Operator's own automount labels and annotations. This feature
never reads their `data`; it copies them into each granted namespace, preserving their metadata
and rewriting only the namespace and this operator's own ownership labels.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: weebo-npmrc
  namespace: weebo-si-hardening
  labels:
    controller.devfile.io/mount-to-devworkspace: "true"
  annotations:
    controller.devfile.io/mount-as: subpath      # ← see below
    controller.devfile.io/mount-path: /home/user
data:
  .npmrc: |
    registry=https://batlehub.internal/npm/
    always-auth=true
```

**`mount-as: subpath`, not `file`, is the difference between a working home directory and an
empty one.** `file` — DevWorkspace Operator's default *when the annotation is absent* — mounts
the object as a **directory** at `mount-path`, so a `ConfigMap` mounted at `/home/user` replaces
the home directory with one containing only `.npmrc`. A template whose mount path is a home or
dot-directory *and* whose `mount-as` is `file` or absent is **refused and never copied**, reported
as `weebo_si_registry_template_invalid_total{reason="mount_shadows_path"}` and a `WARN` line.
That is the only content this feature inspects.

Two things to know before enabling it:

- **A copied credential is a disclosed credential.** A `Secret` copied into a workspace namespace
  is readable by anyone with `get secrets` there — the workspace's owner — and by every process
  in every container in that namespace, including an `npm` lifecycle script from a dependency
  nobody audited. Use read-only, per-team, rotatable tokens; a publish token in this catalogue is
  a publish token in every workspace of every namespace that team owns.
- **This is not a control.** A project-local `.npmrc` beats the user-level one npm reads; `pip
  install -i` beats `pip.conf`. What stops the alternative registry from answering is
  `networkProfiles`' egress policy. The two are designed to be deployed together:
  `registryConfig` without `networkProfiles` is a convenience, and `networkProfiles` without
  `registryConfig` is a support ticket.

Explain a namespace's answer with `weebo-si-operator registry resolve --namespace <ns>`, and
validate the catalogue against its templates with `weebo-si-operator registry check` before
switching the mode.

### `features.endpointAuth`

Puts an authenticating, authorising gate in front of every workspace endpoint exposed on its own
FQDN. See [RFC 0009](./rfc/0009-endpoint-auth.md).

**This block configures three things at once** — the mutating webhook that attaches the gate, the
guard that pins it, and the `endpoint-gateway` deployment that decides. One `mode` governs all
three, which is what makes turning the feature off a single edit.

```yaml
endpointAuth:
  mode: Enforce
  gateway:
    externalUrl: https://auth.weebo.si
    service: { name: endpoint-gateway, namespace: weebo-si-hardening, port: 4180 }
    dialect: Traefik # Traefik | Nginx | HaproxyIngress | OpenShiftRoute | Custom
    enforcement: Enforce # Observe | Enforce — the gate's own verdict, not the feature's mode
    allowedMiddlewares: [] # Traefik only: entries an Ingress may name *after* ours
    haproxyPrerequisite: false # HaproxyIngress only, and required there — see below
  breakGlassIdentities: []
  owner:
    namespaceAnnotation: che.eclipse.org/username
    devworkspaceOperatorIdentity: "system:serviceaccount:devworkspace-controller:devworkspace-controller-serviceaccount"
  hosts:
    suffix: .weebo.si
    ownership:
      - { template: "{user}-{workspace}-{endpoint}" }
      - { template: "dev.{user}-{workspace}" }
    exclude: [che.weebo.si, auth.weebo.si]
  catalog:
    - { key: private, delegation: [] }
    - { key: team, delegation: [Team] }
    - { key: shared, delegation: [Team, UsersAndGroups] }
    - { key: open, anonymous: true }
  default: private
  overrides:
    - match: { users: ["contractor-*"] }
      allowed: [private]
      default: private
      delegation: []
  endpointSelection: { annotation: hardening.weebo.io/access, onUnknownKey: Default }
  selfOrigin: { podNetwork: Auto, serviceAccountToken: true }
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | `Off` also strips the annotations the sweep wrote. |
| `namespaceSelector` | selector | no | everything | Narrows within the webhook's own scope. |
| `gateway.externalUrl` | URL | yes | — | Where a browser is sent to sign in. Must be `https`. |
| `gateway.service` | `{name,namespace,port}` | yes | — | The gateway's in-cluster `Service`. |
| `gateway.dialect` | enum | yes | — | Which router attaches the gate. Decides which *kind* the webhook rules cover. `Traefik` is the one with no caveat. `Nginx` is **partial** (a refused caller gets a bare `401`, and `auth-signin` redirects everybody — RFC 0009's *Future work*). `HaproxyIngress` needs the prerequisite below. `OpenShiftRoute` is **deferred** to [RFC 0010](./rfc/0010-endpoint-auth-openshift.md) — written, never run against a router. |
| `gateway.enforcement` | `Observe`/`Enforce` | no | `Enforce` | `Observe` computes and counts every decision and answers `200` — the rollout step that finds the unauthenticated probe before it breaks. |
| `gateway.allowedMiddlewares` | `[string]` | no | `[]` | Traefik only. Entries an `Ingress` may carry **after** ours; anything else is denied, because the chain runs before `forwardAuth`. |
| `gateway.haproxyPrerequisite` | bool | on `HaproxyIngress` | `false` | Your assertion that the controller carries the `config-frontend` lines that dialect needs. Nothing can check it, and `false` raises `Degraded` — see below. |
| `breakGlassIdentities` | `[string]` | no | `[]` | May set `hardening.weebo.io/endpoint-auth: bypass` on one object. |
| `owner.namespaceAnnotation` | string | yes | — | Where Che writes the namespace's owner. Its **value** must match what `claims.username` yields — read a real namespace before choosing, because Che may write the display name where you expected the username. See *Ground truth* row 2a in [`bricks/endpoint-gateway.md`](./bricks/endpoint-gateway.md). |
| `owner.devworkspaceOperatorIdentity` | string | yes | — | Guard row 2: whoever writes the generated routing objects. Wrong here means every workspace endpoint stops being created. Under Eclipse Che (`routingClass: che`) that is che-operator, not DWO — `system:serviceaccount:eclipse-che:che-operator`. |
| `hosts.suffix` | string | yes | — | Must start with a dot. |
| `hosts.ownership` | `[{template}\|{regex}]` | yes | — | How a host names its owner. First match wins; a host no pattern describes is refused at admission. |
| `hosts.exclude` | `[string]` | no | `[]` | Hosts the gate never attaches to — Che's own, and the gateway's. |
| `catalog[].key` | string | yes | — | `private`, `team`, `shared`, `open`… admin vocabulary; a developer names one and never defines one. |
| `catalog[].anonymous` | bool | no | `false` | No authentication at all. May not be combined with `delegation`. |
| `catalog[].delegation` | `[Team\|UsersAndGroups]` | no | `[]` | `[]` is "the owner and nobody else". |
| `default` | key | yes | — | What a namespace in no team resolves to. |
| `overrides[]` | list | no | `[]` | Per-user narrowing. Intersected with the team's grant — it can only ever take away. |
| `endpointSelection.annotation` | string | no | `hardening.weebo.io/access` | |
| `endpointSelection.onUnknownKey` | `Default`/`Deny` | no | `Default` | |
| `selfOrigin.podNetwork` | `Auto`/`On`/`Off` | no | `Auto` | `Auto` trusts the client address only while the gateway's own probe says it can. |
| `selfOrigin.serviceAccountToken` | bool | no | `true` | The answer where the cluster SNATs. |
| per-team catalogue and default | on [`WeeboSiTeam`](#weebositeam) | no | — | `spec.features.endpointAuth.{catalog,default}`. A team with no block gets `default` and nothing else. |

What a **developer** writes is four annotations, on the devfile endpoint or on their own routing
object — and usually none of them:

| Annotation | Meaning |
| --- | --- |
| `hardening.weebo.io/access` | A catalogue key their team was granted. |
| `hardening.weebo.io/allow-users` | Comma-separated usernames. |
| `hardening.weebo.io/allow-groups` | Comma-separated groups. |
| `hardening.weebo.io/rules` | An ordered YAML list refining the profile per path. |

Two write paths, and the difference is worth telling people once: `kubectl annotate` is live and
the devfile is durable, and **the devfile wins at the next workspace start**. Share now with
`kubectl`, share for good in the devfile.

**On `HaproxyIngress`, the dialect needs six lines you install yourself.** That controller builds
its auth request by copying the *caller's* own headers onto a fixed path, so on a default install
the gate is handed no host and no path, a caller can state the `X-Forwarded-Host` they are judged
against, and a caller's own `X-Auth-Request-User` reaches the application on any allow the gate
does not put a name on. Put these in the haproxy-ingress controller's own ConfigMap, under
`config-frontend`:

```text
http-request del-header X-Auth-Request-User
http-request del-header X-Auth-Request-Groups
http-request del-header X-Auth-Request-Email
http-request set-header X-Forwarded-Host %[req.hdr(host)]
http-request set-header X-Forwarded-Uri %[pathq]
http-request set-header X-Forwarded-Method %[method]
```

Then set `gateway.haproxyPrerequisite: true`. **The field is an assertion, not a check**: the
header a controller sets and the header a caller sends are the same header, so nothing downstream
can tell them apart, and an annotation cannot do the job either — a per-ingress `config-backend`
snippet is emitted *after* the auth call, so it rewrites what the application is handed rather
than what the gate was asked. Leaving the field `false` raises `Degraded` with the reason and
still attaches the gate, because a gate a knowing attacker can bypass refuses everybody who is not
attacking, and an unattached gate refuses nobody. All of this was read off a cluster rather than a
manual — `task spike:live`, and the record is in
[`bricks/endpoint-gateway.md`](./bricks/endpoint-gateway.md).

The gateway reads this block through its own watch on the `WeeboSiConfig`, so a grant edit takes
effect at informer lag rather than at a redeploy. Its *own* configuration — the issuer, the
claims, the cookie lifetimes, the caches — is a file the `endpoint-gateway` chart renders; see
[`bricks/endpoint-gateway.md`](./bricks/endpoint-gateway.md).

### `features.identity`

Creates the objects a person needs outside this cluster: an `AuthentikUser` in the identity
provider, and the Argo CD `Application` their team describes. Per
[RFC 0011](./rfc/0011-teams-and-users.md), and the only feature here that writes into somebody
else's system — so it is `Off` unless written down, and every target is allow-listed.

```yaml
identity:
  mode: Enforce
  authentik:
    allowedGroupRefs: ["platform", "research", "oncall-*"]
  che:
    applicationNamespace: argocd
    allowedProjects: ["weebo-dev"]
    allowedRepoUrls: ["https://charts.weebo.io*"]
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`DryRun`/`Enforce` | yes | — | `DryRun` plans everything and writes nothing. |
| `authentik.allowedGroupRefs` | `[string]` | no | `[]` | Groups a team or a person may request. A trailing `*` matches by prefix. |
| `che.applicationNamespace` | string | no | `argocd` | The one namespace `Application` objects are created in — and the only one this operator holds RBAC for. |
| `che.allowedProjects` | `[string]` | no | `[]` | Argo CD projects a team template may name. |
| `che.allowedRepoUrls` | `[string]` | no | `[]` | Repositories a team template may name. Trailing `*` matches by prefix. |

**An empty allow-list allows nothing.** Turning this feature on with no list provisions people
with no group rather than people with every group, and refuses every workspace template rather
than accepting every chart.

A request outside an allow-list refuses the **whole** object rather than trimming the offending
entry — a partially honoured provisioning request is the failure nobody notices. What was created
is reported per person, in `WeeboSiUser.status.{authentik,che}.state`:

| State | Meaning |
| --- | --- |
| `Off` | The block is absent or `Off`. Nothing was looked for. |
| `Created` | This operator created it and owns it: deleting the person deletes it. |
| `Adopted` | It already existed, owned by somebody else. Referenced, **never written**. |
| `Absent` | The target CRD is not installed, or the reference names nothing. |
| `Conflict` | Another `WeeboSiUser` claims the same target. |

#### Turning provisioning on

Two switches, in this order, and neither alone does anything:

1. `identity.rbac.enabled=true` in the chart — it grants `authentikusers` cluster-wide and
   `applications` **in one namespace**, `identity.argoNamespace`, which must match
   `che.applicationNamespace` below. No `delete` on either: what this operator creates carries an
   `ownerReference` to the person it was created for, so removal happens through garbage
   collection.
2. `spec.features.identity` on the singleton, starting at `mode: DryRun`. Every decision is
   taken, every template rendered, and each person's `status` says `would create …` — the step
   that finds a bad allow-list before it finds a bad object.

What to watch while it rolls out:

| Metric | Reads |
| --- | --- |
| `weebo_si_identity_users_total{kind,state}` | Provisioned objects by outcome — `state="conflict"` and `state="absent"` are the two that need somebody. |
| `weebo_si_identity_errors_total{kind}` | Calls the apiserver refused. Non-zero for longer than a reconcile period is the alert worth writing. |
| `weebo_si_identity_teams_total{result}` | Team passes, by whether the team reported violations. |

No metric here carries a username or a namespace, per the project-wide rule in RFC 0004: which
person is `Conflict` is a `kubectl get weebosiusers` away.

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
| Grant allows an uncatalogued key | A team reaches a key nothing declares. |
| Grant default outside its own allowed | A team's `default` is not among the keys it reaches. |
| Catalogue key conflict | A `WeeboSiTeam` redefines a key somebody already defined, differently. The first definition stands. |

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
*request*, bounded by what the team reaches, resolved by `onNotGranted`. The boundary is the
`WeeboSiTeam` object, and only a cluster admin writes one.
