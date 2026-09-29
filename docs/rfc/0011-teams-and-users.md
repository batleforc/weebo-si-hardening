---
rfc: 0011
title: teams and users as objects
status: Implemented
authors: [batleforc]
created: 2026-09-25
updated: 2026-09-30
decided: 2026-09-30
brick: crates/weebo-si-crd
supersedes: []
superseded-by: []
---

# RFC 0011 — teams and users as objects

## Summary

A team stops being an entry in the `WeeboSiConfig` singleton and becomes its own cluster-scoped
object, `WeeboSiTeam`, carrying its own catalogue entries and its own defaults for every feature.
A person stops being a fact derived from namespace ownership and becomes `WeeboSiUser`: one
object holding the Kubernetes identity, the team it belongs to, and two optional provisioning
switches — an `AuthentikUser` in the identity provider, and an Argo CD `Application` instantiated
from the Helm template its team carries. `spec.teams` and every per-feature `grants` map leave the
schema in the same change; there is no transitional period where both shapes are read.

## Motivation

**Adding a team today is a diff on the object that also holds every kill switch.** `spec.teams`
lives in the singleton, and so does every feature's `grants` map. Granting one team one extra
catalogue entry means editing the same object that carries `mode: Enforce`, the enforcement
backend, the break-glass identity list and the gateway address. There is no way to let a platform
owner review "team `data-science` gets the GPU DevWorkspace Operator config" without handing them
a diff on the cluster's hardening posture, no per-team RBAC, no per-team `status`, and no per-team
audit trail beyond the singleton's own revision history.

**A team's entitlements do not share its lifetime.** A team is `{name, namespaceSelector}`; its
entitlements are rows in six unrelated maps keyed by a bare string. Deleting the team leaves six
orphans behind, each of which the controller correctly reports as `GrantNamesUndeclaredTeam` — so
a completed delete looks exactly like a typo, and the cluster sits `Degraded` until somebody
finds the other five maps. Renaming a team has the same shape and is worse, because the grants
keep applying to nothing while the renamed team silently falls back to the cluster default.

**A person exists nowhere.** `endpoint-auth` needs team membership to answer "may this user open
that endpoint", and derives it: a team's members are the owners of its namespaces
(`crates/weebo-si-endpoint-auth/src/port.rs`, `TeamMembership`). That derivation is sound as an
authorisation input and useless as an onboarding record. Nothing in the cluster says who somebody
is, and onboarding is a manual sequence across three systems — create the namespace so the
derivation works, create the user in Authentik, create the Argo application serving their Che
workspace — with three ways to stop halfway and no object reporting that it did.

**Once this exists:** a team is one object a platform owner can be given `edit` on by name; its
deletion takes its entitlements with it; and `kubectl get weebosiusers` answers "who is in this
cluster, in which team, with which identity, with which workspace" in one screen, with a `Ready`
condition per person naming whatever is missing.

## Guide-level explanation

### A team

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: platform
spec:
  displayName: Platform
  priority: 100
  namespaceSelector:
    matchLabels:
      weebo.io/team: platform
  features:
    dwocPin:
      catalog:
        - key: platform-gpu
          name: gpu-config
          namespace: eclipse-che
      default: platform-gpu
    imagePolicy:
      catalog:
        - key: platform-tools
          patterns: ["registry.internal/platform/*"]
      default: [platform-tools]
  identity:
    authentik:
      groupRefs: [platform]
  workspace:
    che:
      mode: Ensure
      source:
        repoUrl: https://charts.weebo.io
        chart: che-user
        targetRevision: 1.4.2
        values:
          username: "{USERNAME}"
          email: "{EMAIL}"
          storage:
            size: 10Gi
      destination:
        server: https://kubernetes.default.svc
        namespace: "{USERNAME}-che"
      project: weebo-dev
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        options: ["CreateNamespace=true"]
```

```console
$ kubectl get weebositeams
NAME       PRIORITY   NAMESPACES   MEMBERS   READY   AGE
platform   100        12           8         True    41d
research   200        4            3         True    6d
```

A team with no block for a feature gets exactly what a namespace with no team gets — the cluster
default. A team's catalogue entries are added to the cluster catalogue; its `default` may name one
of its own entries or one of the cluster's.

### A person

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
    groupRefs: [oncall]
  che:
    mode: Ensure
    values:
      storage:
        size: 30Gi
```

```console
$ kubectl get weebosiusers
NAME   USERNAME   TEAM       AUTHENTIK   CHE       READY   AGE
max    max        platform   Created     Created   True    41d
lea    lea        research   Adopted     Off       True    9d
sam    sam        —          Off         Off       False   3m
```

`sam` is `False` on purpose: `spec.team` names nothing, and the `Ready` condition says
`NoTeam: spec.team is empty, so no feature entitlement and no workspace applies`. The object is
valid, the person is simply not finished.

With `authentik.mode: Ensure`, the controller looks for an `AuthentikUser` named `max`
(`spec.authentik.name`, defaulting to `metadata.name`). Absent, it creates one with an
`ownerReference` back to the `WeeboSiUser`, so deleting the person deletes the identity it
created. Present and owned by this object, it is kept in step. Present and owned by somebody else,
it is **referenced, never written**: `status.authentik.state: Adopted`, and the operator reports
what it found rather than taking it over.

With `che.mode: Ensure`, the controller renders the team's Helm template with this person's
variables and creates one Argo CD `Application` named after them, in the namespace
`spec.features.identity.che.applicationNamespace` names. The same adoption rule applies.

### Turning provisioning on

Provisioning is a feature of the chassis like any other, with the same three modes and the same
`Off`-when-absent rule, plus the allow-lists that bound what a team may ask the operator to
create:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features:
    identity:
      mode: Enforce
      authentik:
        allowedGroupRefs: ["platform", "research", "oncall"]
      che:
        applicationNamespace: argocd
        allowedProjects: ["weebo-dev"]
        allowedRepoUrls: ["https://charts.weebo.io"]
```

An empty allow-list allows nothing. A team naming a chart repository outside `allowedRepoUrls`,
or a person asking for a group outside `allowedGroupRefs`, is a `Degraded` condition on that
object and **no** call to the API server — the object is refused, not trimmed, because a partially
honoured provisioning request is the failure nobody notices.

Without the `identity` block, the two CRDs still do half their job: teams still carry entitlement,
users still declare membership. Nothing is created anywhere. Provisioning is opt-in twice — once
in the cluster config, once per object.

## Design

### Contract

Three schema changes ship together: two new kinds, one new feature block, and the removal of
`spec.teams` and of every `grants` map from the wire.

#### `WeeboSiTeam`

| | |
| --- | --- |
| Group / version | `hardening.weebo.io/v1alpha1` |
| Kind | `WeeboSiTeam` (plural `weebositeams`, short name `wsteam`) |
| Scope | Cluster |
| Name | `metadata.name` **is** the team name — the identifier every other object references |
| Status | Subresource, `observedGeneration` + counts + conditions |

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `displayName` | string | no | `metadata.name` | Human label. Nothing branches on it. |
| `priority` | int32 | no | `1000` | Lower wins when a namespace matches two teams. Ties break on `metadata.name`, ascending. |
| `namespaceSelector` | selector | **yes** | — | The namespaces belonging to this team. An empty selector matches every namespace and is legal; two teams doing it is a conflict, reported. |
| `features.<feature>` | object | no | absent | This team's catalogue and defaults for one feature. Absent means the cluster answer applies unchanged. |
| `identity.authentik.groupRefs` | []string | no | `[]` | Authentik group names every member of this team receives, subject to the cluster allow-list. |
| `workspace.che` | object | no | absent | The Argo CD `Application` template each member instantiates. |

Per-feature team blocks, one row per feature, using each feature's own catalogue type unchanged:

| `features.` | Fields | The team's `allowed` set |
| --- | --- | --- |
| `dwocPin` | `catalog: []CatalogEntry`, `default: CatalogKey` | its own keys, plus the cluster `default` |
| `networkProfiles` | `catalog: ProfileCatalog`, `default: []ProfileKey` | its own keys, plus the cluster `baseline` |
| `imagePolicy` | `catalog: ImageCatalog`, `default: []EntryKey` | its own keys, plus the cluster `default` |
| `kubearmorPolicy` | `catalog: RuntimeProfileCatalog`, `default: []RuntimeProfileKey` | its own keys, plus the cluster `baseline` |
| `registryConfig` | `catalog: RegistryCatalog`, `default: []RegistryKey` | its own keys, plus the cluster `default` |
| `endpointAuth` | `catalog: []AccessEntry`, `default: AccessKey` | its own keys, plus the cluster `default` |

**A team never declares an `allowed` list.** Declaring a catalogue entry a team may not reach
would be a row with no reading, so the reachable set is the team's catalogue, widened only by
whatever the cluster hands to everybody. This is the one place where the split *removes* a field
rather than moving it.

#### Resolution — cluster catalogue plus team catalogues

The catalogue a feature evaluates against is the union of the cluster-level entries in
`WeeboSiConfig` and every team's entries. **A catalogue key means one thing cluster-wide.** Two
teams may declare the same key only if the entries are identical; a key declared twice with
different content is a violation on the team that redefined it, and **the first definition wins**
— cluster entries first, then teams in resolution order. The losing team still reaches the key,
and reaches a definition an admin already reviewed, rather than reaching nothing: dropping both
copies was the first draft of this rule and it would have let one team's typo delete a platform
baseline for everybody.

The alternative — prefixing every key with its team, so `platform/gpu` and `research/gpu` coexist
— is rejected under *Alternatives considered*: catalogue keys are written by hand in namespace
annotations and devfile attributes, printed by the CLI, and used as metric labels, and none of
those three places has a team to prefix with.

Cluster-level catalogues stay in `WeeboSiConfig`, holding the platform's own entries: the
never-negotiable `baseline` of `network-profiles` and `kubearmor-policy`, and the `default` a
namespace with no team receives. Those are cluster facts, not team property, and could not move
into an object a team owns without losing their meaning.

#### `WeeboSiUser`

| | |
| --- | --- |
| Group / version | `hardening.weebo.io/v1alpha1` |
| Kind | `WeeboSiUser` (plural `weebosiusers`, short name `wsuser`) |
| Scope | Cluster |
| Name | Free; `spec.username` carries the identity, `metadata.name` only has to be a legal object name |

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `username` | string | **yes** | — | The Kubernetes identity, as the API server sees it after authentication. Two objects claiming one `username` is a violation on both. |
| `displayName` | string | no | `username` | Passed to Authentik as `name`. |
| `email` | string | no | — | Required when `authentik.mode` is not `Off`, because `AuthentikUser` requires it. |
| `team` | string | no | — | A `WeeboSiTeam` name. Empty means no team, which is legal and reported. |
| `active` | bool | no | `true` | `false` maps to `AuthentikUser.spec.isActive: false` and suspends provisioning without deleting the object. |
| `authentik` | object | no | absent | `mode` (`Off`/`Ensure`, required when the block is present), `name`, `groupRefs`. |
| `che` | object | no | absent | `mode` (`Off`/`Ensure`), `namespace` override, `values` merged over the team's. |

Declared membership wins over the derived one: where `endpoint-auth` asks `team_of(username)`
today and gets the namespace-ownership answer, it asks the `WeeboSiUser` set first and falls back
to the derivation for people with no object. Both answers disagreeing is not an error — somebody
with a `WeeboSiUser` in team A owning a namespace of team B is a real situation, and the declared
answer is the one an admin wrote down.

#### `spec.features.identity`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | enum | **yes** | — | `Off`/`DryRun`/`Enforce`, per the chassis. `DryRun` renders everything, logs what it would create, writes nothing. |
| `authentik.allowedGroupRefs` | []string | no | `[]` | Group names a team or a user may request. `team-*` matches by prefix. Empty allows none. |
| `che.applicationNamespace` | string | no | `argocd` | The one namespace `Application` objects are created in. |
| `che.allowedProjects` | []string | no | `[]` | Argo CD projects a team template may name. Empty allows none. |
| `che.allowedRepoUrls` | []string | no | `[]` | Chart or git repositories a team template may name, prefix-matched. Empty allows none. |

#### Template variables

The team's `workspace.che` template is rendered per user with the same `{VARIABLE}` syntax RFC
0005 uses for image patterns, the same legality rule (`[A-Z][A-Z0-9_]*`), and the same
fail-closed treatment of an unknown name: an undeclared variable is a violation, never a literal.

| Variable | Value |
| --- | --- |
| `{USERNAME}` | `spec.username` |
| `{OBJECT_NAME}` | the `WeeboSiUser`'s `metadata.name` |
| `{TEAM_NAME}` | `spec.team` |
| `{EMAIL}` | `spec.email`, empty string when unset |
| `{DISPLAY_NAME}` | `spec.displayName`, defaulted to `username` |
| `{USER_NAMESPACE}` | the rendered `destination.namespace` |

Rendering is two passes, because `{USER_NAMESPACE}` is itself rendered: pass one resolves
`destination.namespace` from the five other variables; pass two renders every remaining string,
including every string inside `values`, with all six bound. `values` is free-form
(`x-kubernetes-preserve-unknown-fields`) and substitution walks it recursively — strings only,
keys untouched.

#### What gets created

`AuthentikUser` (`authentik.weebo.io/v1alpha1`, cluster-scoped, from
[batleforc/weebo-authentik](https://github.com/batleforc/weebo-authentik)):

| `AuthentikUser` field | Source |
| --- | --- |
| `metadata.name` | `spec.authentik.name`, defaulting to the `WeeboSiUser`'s `metadata.name` |
| `spec.username` | `spec.username` |
| `spec.name` | `spec.displayName` |
| `spec.email` | `spec.email` |
| `spec.isActive` | `spec.active` |
| `spec.groupRefs` | the team's `identity.authentik.groupRefs` plus the user's, deduplicated, sorted, every entry allow-listed |

`Application` (`argoproj.io/v1alpha1`, namespaced, in `che.applicationNamespace`):

| `Application` field | Source |
| --- | --- |
| `metadata.name` | the rendered `workspace.che.name`, defaulting to `{OBJECT_NAME}` |
| `spec.project` | the team's `project`, allow-listed |
| `spec.source` | the team's `source`, rendered |
| `spec.destination` | the team's `destination`, rendered, with `spec.che.namespace` overriding the namespace when set |
| `spec.syncPolicy` | the team's, verbatim |

Both carry `app.kubernetes.io/managed-by: weebo-si-hardening` and an `ownerReference` to the
`WeeboSiUser`, which is what makes deletion complete itself. Neither is created in `DryRun`.

#### Status and conditions

`WeeboSiTeam.status`: `observedGeneration`, `namespaces` (matched count), `members` (users naming
it), `conditions` — `Ready`, and `Degraded` with one message per violation.

`WeeboSiUser.status`: `observedGeneration`, `team`, `authentik: {name, state, message}`,
`che: {application, namespace, state, message}`, `conditions`. `state` is one of `Off`, `Created`,
`Adopted`, `Absent` (the target CRD is not installed, or the reference points at nothing), or
`Conflict` (another `WeeboSiUser` claims the same target).

#### What leaves the schema

`WeeboSiConfigSpec.teams`, and `grants` on all six feature blocks. Applying a manifest carrying
either is rejected by the API server, not silently ignored: `x-kubernetes-preserve-unknown-fields`
is off, so a removed field is a pruned field, and a pruned `spec.teams` reads as "my teams
vanished" — which is exactly the failure a hard cut should make loud. See *Rollout*.

### Architecture

**The CRD crate: no ports, unchanged.** `weebo-si-crd` stays plain deterministic values with no
`kube::Client`, no `async`, and the new types follow the existing rule — the struct tree *is* the
model. The resolution step (cluster config plus team objects to one evaluated configuration) is a
pure function over values and is tested as one.

**The provisioning controller: hexagonal, yes.** The criteria in
[`../architecture/hexagonal.md`](../architecture/hexagonal.md) are met the way `endpoint-auth`
meets them and `policy-guard` does not: the decision — what an `AuthentikUser` and an
`Application` should contain for this person, and whether this pass creates, updates, adopts or
refuses — is a pure function, and everything around it is I/O against two CRDs that may not be
installed at all. The fake behind that port is what lets "the Authentik operator is not
installed" be a test rather than an incident.

**One port with two instances, not two ports.** This RFC first specified `IdentityProvisioner`
and `WorkspaceProvisioner`; writing them produced two traits with identical methods over
identical types, and the one difference that matters — cluster-scoped versus namespaced — is a
field on the desired object rather than a difference in behaviour. `weebo-si-identity`'s
`Provisioner` is therefore one trait, wired twice by the composition root, which keeps what two
traits were for: a cluster with Authentik and no Argo CD wires one handle and leaves the other
reporting `Absent`.

The team and user reconcile loops themselves follow the shape already in
`crates/weebo-si-controller`: one `Controller` per kind, sharing the leader lease, with a `Deps`
struct built by the composition root, as `endpoint_auth::spawn` does today.

### Data and state

Stateless beyond object `status`, like every other loop here. The controller holds watch-backed
caches of `WeeboSiTeam` and `WeeboSiUser` — the same reflector pattern `weebo-si-runtime` already
uses for the config — and rebuilds the resolved configuration on every change to either kind or to
the singleton. Losing the cache costs one relist.

Two derived facts are worth naming as *not* persisted: team membership counts in `status`, which
are recomputed per pass, and the resolved catalogue, which lives only in memory. Nothing here is a
source of truth the way the objects are; deleting every `status` block costs one reconcile.

The one piece of genuine state is `ownerReference` on the created objects, and it is the API
server's, not ours: it is what distinguishes `Created` from `Adopted` after a restart, with no
bookkeeping of our own to get out of step.

## Security considerations

- **Privileges.** The controller gains `list`/`watch` on `weebositeams` and `weebosiusers`
  cluster-wide, `get`/`create`/`patch` on `authentikusers` (cluster-scoped), and
  `get`/`create`/`patch` on `applications.argoproj.io` **in one namespace** —
  `che.applicationNamespace`, never cluster-wide, and never `delete`: deletion happens through
  `ownerReference` garbage collection, so the operator has no verb with which to remove somebody
  else's `Application`. No `escalate`, no `bind`, no RBAC verbs at all.

- **Trust boundary.** Both new kinds are cluster-scoped and **admin-owned, with no delegation at
  all in this release** — decided, not left open: no team lead gets `edit` on their own
  `WeeboSiTeam`, by `resourceNames` or otherwise. That decision is what makes the per-team
  catalogue safe without a ceiling over its contents, and it is the assumption every other
  paragraph here rests on: whoever may write a `WeeboSiTeam` may add a DevWorkspace Operator
  config, an image pattern and a registry to that team's reachable set, so the set of people who
  may write one is exactly the set who may already write the singleton. The day that changes, the
  catalogue ceiling in *Future work* stops being future work and becomes a prerequisite. A team
  object is a security object, and the docs page says so where an operator will read it, not only
  here.

- **Bypass.** Three routes, each closed: a team widening its own catalogue is bounded by the
  admin-only rule above, which is why that decision is recorded rather than assumed; a team pointing its Helm template at a
  chart nobody reviewed is bounded by `allowedRepoUrls` and by the Argo CD `AppProject`'s own
  source and destination restrictions, which stay the outer fence; a user requesting an Authentik
  group that grants cluster admin is bounded by `allowedGroupRefs`, empty by default. An
  allow-list violation refuses the whole object rather than trimming the offending entry.

- **Blast radius.** The honest answer: larger than any previous RFC here. An operator that can
  create Argo CD `Application` objects can, through Argo, deploy arbitrary manifests wherever the
  named project permits — so a compromised operator is a compromised Argo project. The three
  mitigations are the allow-lists above, the single `Application` namespace, and the absence of a
  `delete` verb; the residual risk is real and is the reason `identity` is a feature with a `mode`
  and an `Off` default rather than always-on behaviour.

- **Secrets.** None read, none written. `AuthentikUser` has no credential field by design — the
  upstream CRD states it — and no password, token or kubeconfig is generated here. The one place a
  secret could leak is a team putting one inside `workspace.che.source.values`, which would land
  in an `Application` object and in this operator's logs at debug level. `values` is therefore
  never logged, only its rendered key set, and the docs page says to use a `SecretStore` reference
  instead.

## Operational considerations

- **Failure mode.** Fail-closed everywhere, and three flavours worth separating. A team that does
  not resolve (unknown name on a user, conflicting catalogue key) yields *no entitlement* and the
  cluster default applies — narrower than the team's own answer, never wider. A provisioning
  target that is missing (`AuthentikUser` CRD not installed) yields `state: Absent` and a
  `Degraded` condition, and never blocks the entitlement half from working. An allow-list
  violation yields no API call at all. Nothing in this RFC sits on the admission path, so no
  `failurePolicy` decision is involved: the webhook is untouched, and the worst outcome of the
  controller being down is that provisioning stops, not that workloads stop.

- **Rollout.** Three steps, in order, and the order is not optional. **(1)** Install the CRDs —
  the chart's `crds/` now carries three files. **(2)** Apply the `WeeboSiTeam` objects, generated
  from the running singleton by `weebo-si-operator teams export`, which reads `spec.teams` plus
  every `grants` map and prints one object per team; a `--check` mode diffs what is in the cluster
  against what the singleton says, so the migration can be verified before anything is removed.
  **(3)** Upgrade the deployment and apply the singleton without `spec.teams`. Doing (3) before
  (2) means every namespace falls to the cluster default for as long as the gap lasts — safe, and
  visible in the feature metrics as a step change.

- **Rollback.** The undo for (3) is a chart rollback plus re-applying the old singleton, and it is
  only fast if that manifest was kept — which is why `teams export` writes a file rather than
  piping into `kubectl`. Undoing (2) is `kubectl delete weebositeams --all`, which takes the
  entitlements with it and leaves the cluster on defaults. The provisioned objects are the slow
  part: `ownerReference` garbage collection deletes every `AuthentikUser` and `Application` the
  operator created when the `WeeboSiUser` objects go, so a rollback of the user half is a
  deprovisioning of everybody. `teams export` has no user counterpart for that reason — a person
  has no prior state to export.

- **Observability.** Per-object `Ready`/`Degraded` conditions carrying the violation text;
  printer columns so `kubectl get` answers the common question without `-o yaml`; and three
  counters alongside the existing feature metrics — teams resolved, users reconciled by outcome
  (`created`/`adopted`/`absent`/`conflict`), and provisioning errors by kind. The alert worth
  writing is on the last one being non-zero for longer than a reconcile period, and on any
  `WeeboSiUser` sitting `Ready=False` for more than an onboarding day.

- **Upgrade.** During a rolling update, an old replica and a new one see the same objects and
  disagree about where teams live: the old one reads `spec.teams` (now absent, so no teams) while
  the new one reads the `WeeboSiTeam` objects. Both answers are safe — the old replica's is
  "everybody gets the cluster default" — and the leader lease means only one is writing status.
  Provisioning has the same property in reverse: an old replica does not know the kinds exist and
  makes no calls. Neither direction produces a half-written object.

## Alternatives considered

- **Do nothing.** The singleton keeps working and the cost stays where it is: no delegation, no
  per-team lifetime, manual onboarding. Rejected because the third item is a repeated manual
  sequence across three systems, which is the definition of something an operator should own.

- **Split teams out, leave `grants` in the singleton.** The smallest change: `WeeboSiTeam` carries
  `{name, namespaceSelector}` only. Rejected because it moves the identity and leaves the
  entitlement, so "give team X access to Y" remains a diff on the cluster's kill switches — the
  motivation for the split in the first place — while adding a second object to keep in step.

- **Team-scoped catalogue keys (`platform/gpu`).** Lets two teams use one key for different
  targets. Rejected: keys are typed by hand into namespace annotations and devfile attributes,
  printed by the CLI and used as metric labels, and in none of those places is the team available
  to prefix with. The chosen rule — a key means one thing cluster-wide, a conflicting redefinition
  is a reported violation — keeps the existing vocabulary intact.

- **Namespaced `WeeboSiTeam`, one per team namespace.** True delegation without `resourceNames`
  RBAC. Rejected because a team's `namespaceSelector` spans namespaces, so a namespaced object
  would grant its namespace authority over others — the classic namespaced-object-with-cluster-
  effect escalation — and because `AuthentikUser` and the identity it mirrors are cluster-scoped
  anyway.

- **Keep both shapes for a release (dual read).** Rejected by the same reasoning `v1alpha1` was
  chosen for: two readable shapes means two code paths, four states (both, neither, each), and a
  precedence rule nobody remembers. The hard cut is one migration command and one ordered rollout.

- **Argo CD `ApplicationSet` with a plugin generator over `WeeboSiUser`.** Genuinely attractive:
  Argo owns the fan-out, and we write no `Application` at all. Rejected for now because the plugin
  generator is a second service to run and secure, the rendering rules would live in its
  configuration rather than in a reviewed CRD, and per-user status would report into
  `ApplicationSet` rather than onto the person's own object. Kept in *Future work*: the template
  in `workspace.che` is deliberately shaped like an `ApplicationSet` template, so moving later
  costs a generator and not a redesign.

- **Call the Authentik API directly instead of creating `AuthentikUser`.** Rejected: it would put
  an Authentik token in this operator, duplicate the reconciliation weebo-authentik already does,
  and give two writers to one upstream object. Creating a CR and letting its own operator own the
  API call keeps this brick free of any identity-provider credential.

## Drawbacks and risks

- **This brick stops being only a hardening control.** Everything here so far rewrites or refuses
  other people's workloads. Provisioning creates objects in other people's systems, and that is a
  different kind of blast radius, a different on-call story and a different review bar. Naming it
  is the point of this bullet: the `identity` feature is the boundary, and it is `Off` unless
  somebody writes it down.

- **Coupling to two upstream APIs that move.** `authentik.weebo.io/v1alpha1` is an alpha CRD in a
  sibling project, and `argoproj.io/v1alpha1` `Application` is stable but large. We depend on a
  handful of fields of each, by construction rather than by importing their types, and a schema
  change upstream surfaces as a rejected create rather than a compile error.

- **Object count.** A cluster with 200 people gains 200 objects, each watched, each with a status
  patched on change. The reflector cost is small; the etcd write cost of a status-per-person on
  every singleton edit is not trivial, and the loop has to be careful to patch only on change —
  which `reconcile.rs` currently does *not* do for `lastTransitionTime`, a known simplification
  that becomes a real cost at this object count.

- **The hard cut.** One botched ordering during rollout drops every team's entitlement to the
  cluster default until it is fixed. It is the safe direction and it is still an outage of intent.

## Unresolved questions

- **Non-blocking.** Should a `WeeboSiTeam` also own an `AuthentikGroup`, rather than referencing
  group names by string? It closes the loop on identity and makes `groupRefs` checkable at
  admission, and it is a straight extension of the same pattern — deliberately out of this RFC to
  keep the first cut at one provisioned kind per direction.
- **Non-blocking.** Printer columns and short names are proposed above and will settle in review.
- **Non-blocking.** Whether `status.members` should count `WeeboSiUser` objects only, or also the
  derived members `endpoint-auth` sees through namespace ownership. Two numbers disagreeing is
  informative; one number nobody can interpret is not.
- **Answered, 2026-09-25.** Whether team leads get `edit` on their own `WeeboSiTeam` by
  `resourceNames`: **no**. Teams stay strictly admin-owned in the first release, which is what
  lets the per-team catalogue ship with no cluster-level ceiling over its contents. The ceiling
  moves to *Future work*, where it stays a prerequisite for any later delegation rather than an
  improvement. This was the one blocking question; nothing here blocks acceptance now.

## Future work

- `AuthentikGroup` per team, and `groupRefs` validated against objects rather than a string list.
- The `ApplicationSet` plugin generator as an alternative back end for the same team template.
- A cluster-level ceiling over what a team catalogue may contain — registry prefixes, DevWorkspace
  Operator configs. **A prerequisite, not an improvement**: it is what a later decision to give
  team leads `edit` on their own `WeeboSiTeam` would have to land before, per the answer recorded
  under *Unresolved questions*.
- `weebo-si-operator users` CLI, mirroring `images`/`registry`: who is in which team, what each
  person resolves to, what would be created.
- Unifying `endpoint-auth`'s per-user `overrides` with `WeeboSiUser`: the narrowing-only rule is
  already exactly right, and the object to hang it on now exists.
- Group synchronisation in the other direction — an Authentik group as the source of membership —
  for clusters where the identity provider is the record.

## Implementation plan

- [x] This RFC, at `Draft`, reserving 0011
- [x] `weebo-si-crd`: `WeeboSiTeam`, `WeeboSiUser`, `spec.features.identity`, the per-feature team
      blocks, the template renderer, the resolution function and its violations; `spec.teams` and
      every `grants` map removed from the wire
- [x] CRD generation for three kinds: `weebo-si-operator crd`, `scripts/crd-regen.sh`, the chart's
      `crds/`, and `crd:check` covering all three
- [x] Every reader resolves: the webhook's config store, the endpoint gateway's index, the two
      CLI subcommands that judge against a grant, and the `WeeboSiConfig` reconcile — each
      watching or listing `WeeboSiTeam` and merging before it answers
- [x] RBAC for the two kinds — read on both roles, status write on the controller's — and the
      envtest that proves neither role may create one
- [x] `weebo-si-controller`: the `WeeboSiTeam` and `WeeboSiUser` reconcile loops, their
      conditions, their counts and their three counters
- [x] `weebo-si-identity`: the `Provisioner` port, its decision function, its fake, and the kube
      adapter in `weebo-si-runtime` — both halves proven against a real apiserver carrying the
      upstream CRDs (`crates/weebo-si-controller/tests/envtest.rs`)
- [x] RBAC for what provisioning writes: `authentikusers` cluster-wide, `applications` in the one
      namespace `che.applicationNamespace` names, no `delete` on either
- [x] `weebo-si-operator teams export [--from <file>] [--check]`
- [ ] The migration run against a real cluster, start to finish — **deferred to the first
      production rollout**, not a code deliverable: `teams export --check` is the tool, and the
      envtest suites prove each half against a real apiserver
- [x] The transitional non-wire `grants` field replaced by an explicit resolved type —
      `Resolved<C, G>` in `weebo-si-crd`, built only by `resolve`/`resolve_teams`
- [x] RFC 0002 amended: its guide-level example, its contract skeleton, *Teams are chassis-level*
      and the four paragraphs that followed from it, with a changelog line
- [x] Docs updated: `docs/weebosiconfig.md`, `docs/bricks/teams-and-users.md`, and the security
      note on who may write a `WeeboSiTeam`
- [x] RFC flipped to `Implemented`

## References

- [RFC 0002 — weebo-si-operator](./0002-weebo-si-operator.md), *Teams are chassis-level*, the
  decision this RFC amends
- [RFC 0004](./0004-network-profiles.md), [RFC 0005](./0005-image-policy.md),
  [RFC 0006](./0006-kubearmor-policy.md), [RFC 0007](./0007-registry-config.md) — the four
  features whose `grants` maps move
- [RFC 0009 — endpoint-auth](./0009-endpoint-auth.md), whose `TeamMembership` port derives what
  this RFC declares, and whose per-user `overrides` are the precedent for narrowing-only
- [batleforc/weebo-authentik](https://github.com/batleforc/weebo-authentik) — the `AuthentikUser`
  CRD this RFC creates, and its no-credential-field decision
- [Argo CD Application specification](https://argo-cd.readthedocs.io/en/stable/user-guide/application-specification/)
- [Argo CD AppProject](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#projects),
  the outer fence this RFC relies on rather than reimplementing

## Changelog

| Date | Change |
| --- | --- |
| 2026-09-30 | The `#[serde(skip)] grants` field left all six wire types. Resolution now returns `Resolved<Config, Grant>` (`ResolvedFeatures` for the whole spec) rather than mutating the wire struct in place, and `validate`/`grant_for` live on the resolved type — so a reader that forgot to resolve against the `WeeboSiTeam` objects is a compile error, not every namespace silently on the cluster default. |
| 2026-09-30 | Flipped to `Implemented`. The real-cluster migration run stays open and is deferred to the first production rollout; every code item of the plan is done and covered by the envtest suites. |
