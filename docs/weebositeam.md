# `WeeboSiTeam` — the team reference

A team is one cluster-scoped `WeeboSiTeam` object: which namespaces belong to it, what it is
entitled to in each feature, which Authentik groups its members receive, and the Argo CD
`Application` each member gets. This page documents every field of it — what it means, whether it
is required, what it defaults to, and what happens when it is wrong.

This is the *reference*. The **why** is [RFC 0011](./rfc/0011-teams-and-users.md), and **how to
install, migrate to and roll it out** is [`bricks/teams-and-users.md`](./bricks/teams-and-users.md).
The person half is [`weebosiuser.md`](./weebosiuser.md); the cluster half — the catalogues and
defaults a team adds to — is [`weebosiconfig.md`](./weebosiconfig.md). When this page and the code
disagree, the code is right and this page is a bug.

The schema is generated from `crates/weebo-si-crd/src/team.rs` and checked in as
`charts/weebo-si-operator/crds/weebositeams.hardening.weebo.io.yaml`. Print it from the binary
that enforces it:

```bash
weebo-si-operator crd weebositeams
kubectl explain weebositeam.spec --recursive
```

To build one without hand-writing YAML, the [config generator](https://batleforc.github.io/weebo-si-hardening/#WeeboSiTeam) renders a form
from this same schema, validates as you type and prints the object.

> **A `WeeboSiTeam` is a security object.** Whoever may write one decides which DevWorkspace
> Operator configs, image patterns, registries, network and runtime profiles and endpoint access
> profiles that team reaches — there is no cluster-level ceiling over what a team may catalogue.
> That is safe only because teams are **admin-only**: no team lead gets `edit` on their own team's
> object, by `resourceNames` or otherwise. See
> [`weebosiconfig.md`](./weebosiconfig.md#teams-and-people).

## The object

Every field, with a realistic value:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: platform                  # IS the team name
spec:
  displayName: Platform
  priority: 100
  namespaceSelector:
    matchLabels: { weebo.io/team: platform }
    matchExpressions:
      - { key: weebo.io/tier, operator: NotIn, values: [sandbox] }
  features:
    dwocPin:
      catalog:
        - { key: platform-gpu, name: dwoc-gpu, namespace: eclipse-che }
      default: platform-gpu
    networkProfiles:
      catalog:
        - key: platform-db
          variants:
            - backend: NetworkPolicy
              templateRef: { name: weebo-platform-db, namespace: weebo-si-hardening }
      default: [platform-db]
    imagePolicy:
      catalog:
        - key: platform-tools
          patterns: ["registry.internal/platform/**"]
      default: [platform-tools]
    kubearmorPolicy:
      catalog:
        - key: platform-debug
          templateRef: { name: weebo-platform-debug, namespace: weebo-si-hardening }
      default: []
    registryConfig:
      catalog:
        - key: platform-npm
          ecosystem: Npm
          sources:
            - kind: ConfigMap
              templateRef: { name: platform-npmrc, namespace: weebo-si-hardening }
      default: [platform-npm]
    endpointAuth:
      catalog:
        - { key: platform-shared, delegation: [Team, UsersAndGroups] }
      default: private
  identity:
    authentik:
      groupRefs: [platform]
  workspace:
    che:
      mode: Ensure
      name: "che-{USERNAME}"
      project: weebo-dev
      source:
        repoUrl: https://charts.weebo.io
        chart: che-user
        targetRevision: 1.4.2
        values:
          username: "{USERNAME}"
          email: "{EMAIL}"
          storage: { size: 10Gi }
      destination:
        server: https://kubernetes.default.svc
        namespace: "{USERNAME}-che"
      syncPolicy:
        automated: { prune: true, selfHeal: true }
        options: ["CreateNamespace=true"]
```

| | |
| --- | --- |
| Group / version | `hardening.weebo.io/v1alpha1` |
| Kind | `WeeboSiTeam` (plural `weebositeams`, short name `wsteam`) |
| Scope | Cluster |
| Name | **is** the team name |
| Status | subresource — see [`status`](#status) |

The smallest legal team is a name and a selector. Everything else is optional, and every block
left out means "the cluster answer, unchanged":

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: research
spec:
  namespaceSelector:
    matchLabels: { weebo.io/team: research }
```

## Top-level fields

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `metadata.name` | string | yes | — | The team's identity: what `WeeboSiUser.spec.team` names, what every grant is keyed by, what `{TEAM_NAME}` resolves to in an image pattern. |
| `spec.displayName` | string | no | the name | A human label. **Nothing branches on it.** |
| `spec.priority` | int32 | no | `1000` | Precedence when a namespace matches more than one team: **lowest wins**, ties break on `metadata.name` ascending. |
| `spec.namespaceSelector` | [Selector](./weebosiconfig.md#namespaceselector) | **yes** | — | Which namespaces belong to this team. |
| `spec.features` | object | no | `{}` | This team's catalogue entries and defaults, one optional block per feature. |
| `spec.identity.authentik.groupRefs` | `[string]` | no | `[]` | Authentik group names every member receives. |
| `spec.workspace.che` | object | no | absent | The Argo CD `Application` template each member instantiates. |

### `metadata.name`

**Renaming a team is a delete and a create.** Every `WeeboSiUser` naming the old name stops
resolving to it — reported on the singleton, and on the person only if they asked for a workspace;
see [`weebosiuser.md`](./weebosiuser.md#team) — and every namespace it owned falls to the next
matching team, or to the cluster default. There is no alias field.

### `priority`

`spec.teams` used to be an ordered list, and document order decided who owned a namespace two
teams matched. Separate objects have no order, so `priority` is the explicit replacement. The
sort is `(priority, metadata.name)` — total and deterministic, so two replicas can never disagree
about which team owns a namespace.

**The default is high on purpose.** A team with an opinion about precedence states it, and lands
ahead of every team that did not. Two teams both left at `1000` resolve alphabetically, which is
deterministic and almost certainly not what anybody meant: give overlapping teams explicit values.
`weebo-si-operator teams export` hands them out as `100`, `200`, … so a team can be inserted later.

A negative value is legal and sorts first.

### `namespaceSelector`

Required — a team that owns no namespace can still carry members and a workspace template, but it
has to say so with a selector matching nothing rather than by omission. Same shape and semantics as
[every other selector here](./weebosiconfig.md#namespaceselector): `matchLabels` and
`matchExpressions` are ANDed, `operator` is one of `In`/`NotIn`/`Exists`/`DoesNotExist`, and `values`
is unused by the last two.

**An empty selector — `{}` — matches every namespace, and is legal.** Every namespace then
belongs to this team unless a team with a lower `priority` claims it first. Two teams matching one
namespace is not rejected; the loser is told (next paragraph).

A namespace this team's selector matches but a higher-precedence team owns is reported on **this**
team's `Degraded` condition, naming up to three such namespaces and the team that owns each, plus a
count of the rest. `status.namespaces` counts only the namespaces this team actually won.

## `spec.features`

One optional block per feature, in that feature's own vocabulary. The payload of each catalogue
entry is exactly the cluster catalogue's — read the matching section of
[`weebosiconfig.md`](./weebosiconfig.md#specfeatures) for what a `templateRef`, a pattern or a
delegation means. What this page adds is how a team's block combines with the cluster's.

| Block | `catalog` entry | `default` | The team reaches |
| --- | --- | --- | --- |
| [`dwocPin`](#featuresdwocpin) | `{key, name, namespace}` | **one** key, **required** | its own keys, plus the cluster `default` |
| [`networkProfiles`](#featuresnetworkprofiles) | `{key, variants[]}` | list of keys, `[]` | its own keys, plus the cluster `baseline` |
| [`imagePolicy`](#featuresimagepolicy) | `{key, patterns[]}` | list of keys, `[]` | its own keys, plus the cluster `default` keys |
| [`kubearmorPolicy`](#featureskubearmorpolicy) | `{key, templateRef}` | list of keys, `[]` | its own keys, plus the cluster `baseline` |
| [`registryConfig`](#featuresregistryconfig) | `{key, ecosystem, sources[]}` | list of keys, `[]` | **its own keys only** |
| [`endpointAuth`](#featuresendpointauth) | `{key, anonymous, delegation[]}` | **one** key, **required** | its own keys, plus the cluster `default` |

Four rules hold for every block:

- **A block absent means the cluster answer, unchanged.** A namespace of a team with no
  `imagePolicy` block resolves exactly like a namespace belonging to no team. That is the rule that
  makes a partially written team safe: a feature nobody thought about cannot be widened by the
  team existing.
- **A block for a feature the singleton does not configure does nothing.** Team catalogues are
  merged *into* `spec.features.<feature>` of the `WeeboSiConfig`; with no such block there is
  nothing to merge into, the feature is `Off`, and the team's entries are not read or validated.
- **A team never writes an `allowed` list.** What it reaches is the catalogue it declares, widened
  only by what the cluster hands everybody (column above). An entry it catalogues is an entry it
  may use; there is no way to declare one and withhold it.
- **A key means one thing cluster-wide.** A team's entries are merged into the cluster catalogue —
  cluster entries first, then teams in `(priority, name)` order, first definition winning. A team
  declaring a key somebody already declared **with an identical entry** is fine and silent;
  **with a different entry** it is a violation reported on this team *and* on the singleton, and
  the team reaches the winning definition instead of its own. A typo can therefore never delete or
  replace a platform entry. Team-prefixed keys (`platform/gpu`) do not exist: keys are typed into
  annotations and devfile attributes, where no team is available to prefix with.

A team's `default` is what a namespace — or a workspace — of this team gets when it names nothing
through the [selection chain](./weebosiconfig.md#the-selection-chain). It must be inside what the
team reaches; a `default` naming a key the team does not reach is a *Grant default outside its own
allowed* violation, reported on the singleton's feature status, not on the team.

### `features.dwocPin`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | This team's DWOC entries. |
| `catalog[].key` | string | yes | — | The identifier the namespace annotation names. |
| `catalog[].name` | string | yes | — | The `DevWorkspaceOperatorConfig`'s name. |
| `catalog[].namespace` | string | yes | — | The namespace it lives in. |
| `default` | key | **yes** | — | The **one** DWOC a namespace of this team gets. A workspace runs with exactly one, so this is a scalar, unlike every list-valued `default` below. |

An entry is flat — `{key, name, namespace}` — not `{key, target: {…}}`. A `dwocPin` block with an
empty catalogue is legal and useful: it reaches only the cluster `default`, and `default` must then
name it.

### `features.networkProfiles`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | |
| `catalog[].key` | string | yes | — | **DNS-1123 label**, 1–63 characters, `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, checked by the API server — it is interpolated into object names and label values. |
| `catalog[].variants[].backend` | `NetworkPolicy`/`Cilium` | yes | — | At most one variant per backend. |
| `catalog[].variants[].templateRef` | `{name, namespace}` | yes | — | The template whose `policyTypes`/`ingress`/`egress` are copied. |
| `default` | list of keys | no | `[]` | Profiles a workspace of this team gets when it names none. Each item has the same DNS-1123 pattern. May be empty: the cluster `baseline` applies either way. |

### `features.imagePolicy`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | |
| `catalog[].key` | string | yes | — | |
| `catalog[].patterns` | list of strings | yes | — | Non-empty. Held as written; parsed by the webhook. `{TEAM_NAME}` and `{NAMESPACE}` resolve per namespace, exactly as in the cluster catalogue. |
| `default` | list of keys | no | `[]` | May be empty: the platform set and the cluster `default` still apply. |

An entry carries no scope, no exception and no negation: selecting more entries can only ever
permit more.

### `features.kubearmorPolicy`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | |
| `catalog[].key` | string | yes | — | DNS-1123 label, 1–63 characters, same pattern as `networkProfiles`. |
| `catalog[].templateRef` | `{name, namespace}` | yes | — | The `KubeArmorPolicy` whose rules are copied. One ref, not a `variants` list. |
| `default` | list of keys | no | `[]` | Each item DNS-1123. May be empty: the cluster `baseline` applies either way. |

### `features.registryConfig`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | |
| `catalog[].key` | string | yes | — | |
| `catalog[].ecosystem` | closed enum | no | `Other` | `Npm`/`Pypi`/`Cargo`/`Go`/`Maven`/`RubyGems`/`Composer`/`Conda`/`Terraform`/`OpenVsx`/`Other`. A metric label — nothing branches on it. |
| `catalog[].sources[].kind` | `ConfigMap`/`Secret` | yes | — | |
| `catalog[].sources[].templateRef` | `{name, namespace}` | yes | — | Copied verbatim into each granted namespace. At least one source per entry, at most one per `{kind, name, namespace}`. |
| `default` | list of keys | no | `[]` | What a namespace of this team mounts when its annotation names nothing. **Empty means it mounts nothing.** |

**The one block that widens nothing.** `registryConfig` has no cluster `baseline` and no
cluster-level `default`, so a team reaches exactly the entries it catalogues — and a team with no
`registryConfig` block mounts nothing at all. Read the two warnings under
[`features.registryConfig`](./weebosiconfig.md#featuresregistryconfig) before cataloguing a
`Secret` here: a copied credential is readable by everyone in every namespace this team owns.

### `features.endpointAuth`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `catalog` | list | no | `[]` | This team's access profiles. |
| `catalog[].key` | string | yes | — | What a developer's `hardening.weebo.io/access` annotation names. |
| `catalog[].anonymous` | bool | no | `false` | No authentication at all. May not be combined with a non-empty `delegation`. |
| `catalog[].delegation` | `[Team\|UsersAndGroups]` | no | `[]` | Who besides the owner the profile lets in. `[]` is "the owner and nobody else". |
| `default` | key | **yes** | — | The **one** profile an endpoint of this team resolves to when it names none. |

The cluster `default` stays reachable whatever the team catalogues: a team never loses the profile
everybody has. The cluster's `overrides[]` still apply on top, and can only narrow.

## `spec.identity`

```yaml
identity:
  authentik:
    groupRefs: [platform, oncall-eu]
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `authentik.groupRefs` | `[string]` | no | `[]` | Authentik group **names** (`AuthentikGroup.spec.name`), resolved by the upstream operator against Authentik's own API — never against Kubernetes objects. |

Every member provisioned with `authentik.mode: Ensure` receives these groups, merged with their own
`spec.authentik.groupRefs`, deduplicated and sorted. Nothing here is used unless
`spec.features.identity` is configured on the singleton.

**Every entry is checked against `spec.features.identity.authentik.allowedGroupRefs`** (exact, or
by prefix for an entry ending in `*`; an empty list allows nothing). One group outside it is a
violation on this team, and **refuses provisioning for every member who asks for an Authentik
account** — the whole plan, not just the offending group, because a partially honoured request is
the failure nobody notices.

A typo *inside* the allow-list is not caught here: the name is a string, and only the upstream
operator's own reconcile finds that the group does not exist.

## `spec.workspace.che`

The Argo CD `Application` each member with `spec.che.mode: Ensure` gets, rendered once per person.
Shaped like an `ApplicationSet` template on purpose: `project`, `source`, `destination` and
`syncPolicy` are Argo's own fields under Argo's own names. Only the fields listed here exist; an
`Application` field not modelled here is one a team cannot set.

| Field | Type | Required | Default | Templated | Meaning |
| --- | --- | --- | --- | --- | --- |
| `mode` | `Off`/`Ensure` | **yes** | — | — | `Ensure` provisions for every member who asks. `Off` keeps the template without acting on it. |
| `name` | string | no | `{OBJECT_NAME}` | yes | The `Application`'s `metadata.name`. |
| `project` | string | **yes** | — | **no** | The Argo CD `AppProject` — the outer fence. Must be non-empty and on `allowedProjects`. |
| `source.repoUrl` | string | **yes** | — | yes | Chart repository or git repository. Must be non-empty and on `allowedRepoUrls`. Written to the `Application` as `repoURL`. |
| `source.chart` | string | one of | — | yes | A Helm chart name. |
| `source.path` | string | one of | — | yes | A path inside a git repository. |
| `source.targetRevision` | string | **yes** | — | yes | Chart version, git revision or branch. Must be non-empty. |
| `source.values` | free-form object | no | — | every string, recursively | Base Helm values every member gets. Written as `helm.valuesObject`. |
| `destination.server` | string | one of | — | no | The cluster API URL. |
| `destination.name` | string | one of | — | no | The cluster's registered name in Argo CD. |
| `destination.namespace` | string | **yes** | — | yes, first | Where the chart is deployed. Its rendered value **is** `{USER_NAMESPACE}`. |
| `syncPolicy.automated.prune` | bool | no | `false` | no | Delete resources no longer in the chart. |
| `syncPolicy.automated.selfHeal` | bool | no | `false` | no | Revert drift written by hand. |
| `syncPolicy.options` | `[string]` | no | `[]` | no | e.g. `CreateNamespace=true`. |

`syncPolicy` is passed through verbatim — this operator has no opinion on how Argo syncs. Absent
`syncPolicy`, or absent `automated`, is a manual sync.

**Where the `Application` lands is not a team's choice.** Its `metadata.namespace` is always
`spec.features.identity.che.applicationNamespace` on the singleton (default `argocd`): one
namespace is what keeps this operator's RBAC to one namespace.

### `mode: Off`

Switches the template off for the whole team without losing it. It is not a silent skip: a member
whose own `spec.che.mode` is `Ensure` gets a *team has it switched off* violation, and — because a
refused plan is refused whole — **their Authentik half is not written either** until one of the two
modes changes. Write `"Off"` quoted: unquoted, YAML 1.1 parsers read it as the boolean `false`,
which the schema refuses for a string field.

### What the schema does not check, and the controller does

The CRD marks only `mode`, `project`, `source`, `destination`, `source.repoUrl`,
`source.targetRevision` and `destination.namespace` as required. Everything else below is checked
by the controller, reported on this team's `Degraded` condition, and refuses the workspace half of
every member until fixed:

| Violation | Meaning |
| --- | --- |
| `source must set exactly one of 'chart' and 'path'` | Neither or both. |
| `destination must set exactly one of 'server' and 'name'` | Neither or both. |
| `<field> is empty` | `project`, `source.repoUrl` or `source.targetRevision` is empty or whitespace. The API server would accept the rendered `Application`, and Argo would never sync it. |
| `template … names unknown variable {X}` | A `{X}` outside the [six variables](#template-variables) — including a lower-case `{team_name}`. Never treated as a literal. |
| `template … has a '{' with no matching '}'` | Unterminated. |
| `destination.namespace names {USER_NAMESPACE}` | The namespace cannot name itself. |
| `names project …, which is outside allowedProjects` | `project` is not on `spec.features.identity.che.allowedProjects`. |
| `names repository …, which is outside allowedRepoUrls` | `source.repoUrl` is not on `spec.features.identity.che.allowedRepoUrls`. |

These run only when the singleton carries `spec.features.identity` — in any mode, `Off` included.

**The allow-lists are matched against the template as written, before rendering.** A `repoUrl` of
`https://charts.weebo.io/{TEAM_NAME}` is allowed by `https://charts.weebo.io*` and refused by
`https://charts.weebo.io/platform`. Allow-list entries match exactly, or by prefix when they end
in `*`; an empty list allows nothing.

Two errors can only surface per person, at render time, and are reported on that person instead:
a rendered `destination.namespace` (or the person's `spec.che.namespace` override) that is not a
DNS-1123 label — for example `{DISPLAY_NAME}-che` rendering to `Max Leriche-che` — and anything
wrong inside the person's own `values`.

**Never put a secret in `values`.** It lands verbatim in an `Application` object anybody with read
access to the Argo namespace can see. Reference a `SecretStore` or an existing `Secret` from the
chart instead.

### Template variables

RFC 0005's `{VARIABLE}` notation, with a closed set of names — there is no way to declare one.

| Variable | Value |
| --- | --- |
| `{USERNAME}` | the person's `spec.username` |
| `{OBJECT_NAME}` | the person's `metadata.name` |
| `{TEAM_NAME}` | the person's `spec.team`, empty when they have none |
| `{EMAIL}` | the person's `spec.email`, empty when unset |
| `{DISPLAY_NAME}` | the person's `spec.displayName`, defaulted to the username |
| `{USER_NAMESPACE}` | the rendered namespace — resolved first, so `destination.namespace` cannot name it |

Rendering is two passes: the namespace first, from the five other variables (or the person's
`spec.che.namespace` override, rendered the same way); then every other templated field, with all
six bound. Inside `values`, only **string values** are rendered — keys are never touched, and
numbers and booleans are never reinterpreted. `{{ … }}` is copied through verbatim, braces
included, so a Helm template inside `values` survives.

A person's `spec.che.values` is rendered the same way and deep-merged **over** these: objects merge
key by key, everything else — arrays included — is replaced.

## `status`

Written by the controller's team loop, derived entirely from the cluster — deleting it costs one
reconcile. The loop runs on every change to the team and every five minutes.

```yaml
status:
  observedGeneration: 4
  namespaces: 12
  members: 8
  conditions:
    - type: Ready
      status: "True"
      reason: AsExpected
      message: "12 namespace(s), 8 member(s)"
      observedGeneration: 4
```

| Field | Meaning |
| --- | --- |
| `observedGeneration` | The `metadata.generation` this status reflects. |
| `namespaces` | Namespaces this team **owns** — matched by its selector *and* won on priority. Not the ones its selector merely matches. |
| `members` | `WeeboSiUser` objects whose `spec.team` is this team's name. Namespace owners with no `WeeboSiUser` are not counted. |
| `conditions` | Exactly **one** condition. |

The condition is either `type: Ready` (`reason: AsExpected`, message the two counts) or
`type: Degraded` (`reason: NotProvisioned`, message every violation, semicolon-separated). Its
`status` is `"True"` in both cases — which condition is present is the answer, so the `READY`
printer column reads `True` for a healthy team and is **blank** for a degraded one.

```console
$ kubectl get wsteam
NAME       PRIORITY   NAMESPACES   MEMBERS   READY   AGE
platform   100        12           8         True    41d
research   200        4            3                 6d
```

## When the team is wrong

Validation is **reconcile-time, not write-time**, as for the singleton: the API server accepts
anything structurally valid, and the controller reports what is semantically wrong. Where it is
reported depends on who can fix it:

| Mistake | Reported on | Effect |
| --- | --- | --- |
| Catalogue key redefined with a different entry | this team **and** the singleton | The first definition stands; this team reaches it. |
| Namespace matched, but owned by a higher-precedence team | this team | That namespace resolves to the other team. |
| `workspace.che` malformed, or outside an allow-list | this team **and** the singleton's `identity` feature | No member's workspace is provisioned. |
| A `groupRefs` entry outside `allowedGroupRefs` | this team **and** the singleton's `identity` feature | No member's Authentik account is provisioned. |
| A team `default` outside what the team reaches | the singleton's feature status | The feature reports `Degraded`. |
| A catalogue entry wrong on its own terms (duplicate key within one catalogue, a network profile with two variants for one backend, an anonymous endpoint profile with a delegation, a bad image pattern…) | the singleton's feature status | As for the same mistake in the cluster catalogue — see [`weebosiconfig.md`](./weebosiconfig.md#when-the-configuration-is-wrong). |
| A key failing the DNS-1123 pattern (`networkProfiles`, `kubearmorPolicy`) | the API server | The write is rejected. |
| A missing required field (`namespaceSelector`, a `dwocPin`/`endpointAuth` `default`, a catalogue entry's `key`…) | the API server | The write is rejected. |

Failure is always in the narrow direction. A team that does not resolve contributes no
entitlement, and its namespaces get the cluster default — never something wider.

Explain a namespace's answer with the per-feature CLI
(`weebo-si-operator images check`, `weebo-si-operator registry resolve --namespace <ns>`, …), and
diff the teams in the cluster against an old singleton with `weebo-si-operator teams export
--check`.
