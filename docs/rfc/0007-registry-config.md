---
rfc: 0007
title: registry-config
status: Implemented
authors: [batleforc]
created: 2026-08-25
updated: 2026-08-25
decided: 2026-08-25
brick: crates/weebo-si-registry-config
supersedes: []
superseded-by: []
---

# RFC 0007 — registry-config

## Summary

`registry-config` puts the package-manager configuration a workspace needs — the `.npmrc`, the
`pip.conf`, the Cargo `config.toml`, the Maven `settings.xml`, the `GOPROXY` variable — inside
every workspace container of a namespace, per team, on the
[RFC 0002](./0002-weebo-si-operator.md) chassis. It is the same catalogue-and-grants shape
[`network-profiles`](./0004-network-profiles.md), [`image-policy`](./0005-image-policy.md) and
[`kubearmor-policy`](./0006-kubearmor-policy.md) use: an admin authors real `ConfigMap` and
`Secret` objects, grants each team a subset, and the operator copies the granted ones into the
team's namespaces where DevWorkspace Operator's own automount mechanism mounts them.

This brick is the first in the series that *adds* something to a workspace instead of narrowing
it, and the first whose effect is not enforcement at all: nothing here stops a developer from
pointing a build at any registry they like. The guarantee that they cannot reach it belongs to
[RFC 0004](./0004-network-profiles.md); this brick's job is to make the reachable registry the
one that works by default, so that guarantee stops costing the developer their afternoon.

## Motivation

RFC 0004 gives a workspace an egress baseline: a default-deny `NetworkPolicy` plus whatever its
team was granted. The moment that baseline is real, `npm install` stops working. So does `pip
install`, `cargo build` on a cold registry cache, `mvn package`, `go mod download`, and the
extension the developer installs from the IDE marketplace. The internal mirror is reachable; the
public registry is not; and the tooling inside the container has no idea, because nothing told
it. What the developer sees is a hang, then a timeout, then a stack trace naming a host they were
never supposed to talk to.

The mirror this fleet reaches is [Batlehub](https://github.com/batleforc/batlehub): a caching
proxy in front of the public registries — npm, PyPI, Cargo, Go, Maven, RubyGems, Composer,
Conda, Terraform, GitHub Releases, OpenVSX and the JetBrains marketplace — with its own access
rules, release age gates and audit trail. That it exists is what makes RFC 0004's baseline
tenable at all: the egress a workspace needs collapses from "most of the internet" to one host.
This RFC is the other half of that sentence. A single reachable host is only useful if the
tooling inside the container knows to use it, and nothing in a workspace image knows that today.

The fix is a handful of small files with well-known names and well-known contents. That is not a
hard problem — it is a *distribution* problem, and today it is solved four bad ways at once:

- **In the image.** The `.npmrc` is baked into the workspace base image, which means a new
  registry, a rotated token, or a second team with a different mirror is a rebuild of every image
  in [RFC 0005](./0005-image-policy.md)'s catalogue, and a credential in a layer that outlives
  every rotation.
- **In the devfile.** A `postStart` command writes the file. The devfile belongs to the
  repository, so the configuration is per project rather than per cluster, it is edited by
  whoever opens a pull request, and it runs *after* the container is up — which is a race with
  anything the IDE starts on its own.
- **By hand, per user.** The developer is sent a wiki page. This works exactly as well as wiki
  pages ever work, and it fails silently: the workspace still starts, the build still runs, it
  just reaches for the wrong host and dies.
- **Not at all.** The team gets an egress exception to the public registry instead, because that
  is the five-minute fix, and RFC 0004's baseline quietly stops meaning anything.

Kubernetes and DevWorkspace Operator already solve the last mile of this. A `ConfigMap` or
`Secret` labelled `controller.devfile.io/mount-to-devworkspace: "true"` in a workspace namespace
is mounted by DevWorkspace Operator into every container of every workspace in that namespace,
at a path and in a form the object's own annotations pick. **What DevWorkspace Operator does not
do is decide *which* namespace gets *which* object** — that routing, exactly as with
`NetworkPolicy` in RFC 0004, is what this brick adds. Eclipse Che has a cluster-wide version of
the routing (objects labelled as workspace configuration in the Che namespace are copied to every
user namespace) and cluster-wide is the part that does not survive contact with more than one
team: the mirror a data team needs, with its own credential, is not the mirror everyone else
should be handed.

**The granularity is per team**, for the same reason as every prior brick, plus one specific to
this one: a registry credential is a secret with a blast radius, and "every workspace in the
cluster can read this token" is not a decision anyone makes on purpose — it is what
cluster-wide provisioning of a `Secret` means.

**Outcome we are buying:** a workspace in a namespace whose team was granted the `internal-npm`
profile starts with `~/.npmrc` already pointing at the mirror, `npm install` works on the first
try inside RFC 0004's egress baseline, the admin changed one `WeeboSiConfig` field to make that
true for a whole team, and the credential behind it is one object they can rotate in one place —
never a rebuilt image, never a line in someone's devfile.

### What exists today

Nothing in this project. In a cluster running Eclipse Che, the closest existing mechanism is
Che's own workspace-configuration provisioning (cluster-wide, no team routing, no `DryRun`, no
drift protection) layered on DevWorkspace Operator's automount (per namespace, no routing at
all — it mounts whatever is already there). This brick is deliberately built *on* the second one
rather than replacing either: it decides what lands in a namespace, and DevWorkspace Operator
keeps deciding how a mounted object reaches a container.

## Guide-level explanation

`registry-config` starts `Off`, per the chassis. It needs a catalogue, grants against
`spec.teams`, and — unlike every prior brick — **no baseline**, for a reason worth stating
loudly: there is no universally correct `.npmrc`. A cluster with one mirror for everyone
expresses that as a grant every team has, not as a mandatory entry, because "mandatory" here
would mean writing a file into a container whose image may not even have the tool it configures.

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
      grants:
        team-1:
          allowed: [internal-npm, internal-pypi]
          default: [internal-npm]
      onNotGranted: Default
```

`weebo-npmrc` is an ordinary `ConfigMap` an admin writes and applies to the
`weebo-si-hardening` namespace, carrying DevWorkspace Operator's own automount annotations —
the same way `weebo-base` is an ordinary `NetworkPolicy` for `network-profiles`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: weebo-npmrc
  namespace: weebo-si-hardening
  labels:
    controller.devfile.io/mount-to-devworkspace: "true"
    controller.devfile.io/watch-configmap: "true"
  annotations:
    controller.devfile.io/mount-as: subpath
    controller.devfile.io/mount-path: /home/user
data:
  .npmrc: |
    registry=https://batlehub.internal/npm/
    always-auth=true
```

This brick never reads `data`. It copies the object into each namespace the grant resolves to,
preserving the labels and annotations verbatim, and rewriting exactly three things: the
namespace, the ownership labels (`hardening.weebo.io/managed-by: weebo-si-operator`,
`hardening.weebo.io/profile: internal-npm`), and nothing else. The mount semantics stay the
admin's decision, expressed in Kubernetes' and DevWorkspace Operator's own vocabulary, because
the alternative is inventing a mount DSL this project would then own forever.

At `DryRun`, the reconciler computes the diff per namespace and logs it; nothing is written. At
`Enforce`, the copies are applied and DevWorkspace Operator mounts them at the next workspace
start. What an operator sees when it works: `kubectl get configmap -n <workspace-ns> -l
hardening.weebo.io/managed-by=weebo-si-operator` lists the granted entries, and a shell in the
workspace shows `~/.npmrc`. What they see when it does not: `weebo_si_registry_ready` at `0` for
that namespace, with a `Degraded` condition naming which template failed to resolve.

**`mount-as: subpath` rather than `file` is the difference between a working home directory and
an empty one**, and it is the single most common way this goes wrong. `file` — DevWorkspace
Operator's default when the annotation is absent — mounts the object as a *directory* at
`mount-path`, so a `ConfigMap` mounted at `/home/user` replaces the home directory with one
containing only `.npmrc`: no shell history, no IDE settings, and, depending on the image, no
writable home at all. `subpath` places each key individually and leaves the rest of the
directory alone. This brick therefore does one check on content it otherwise never inspects: a
template whose resolved mount path is a home or dot-directory *and* whose `mount-as` is `file`
(or absent) is refused as a `TemplateMountShadowsPath` violation, reported as `Degraded`, and
never copied. That is the whole of the content inspection — an explicit, enumerable exception to
"this brick does not read templates", and one that exists because the failure it prevents is
silent, total, and looks like a broken image rather than a broken config.

## Design

### Contract

- **`spec.features.registryConfig`** on `WeeboSiConfig`, following the shape
  [`NetworkProfilesConfig`](../../crates/weebo-si-crd/src/network_profiles.rs) establishes, with
  the fields renamed to this brick's vocabulary, one field added, and two deliberately absent:

  - `mode: FeatureMode` — required, no implicit default, per RFC 0002.
  - `namespaceSelector: Selector` — optional, narrows the controller's own scope.
  - `catalog: RegistryCatalog` — `{key, ecosystem, sources}[]`.
    - `key: RegistryKey` — the short identifier a grant or a namespace annotation names.
    - `ecosystem: Ecosystem` — a closed enum (`Npm | Pypi | Cargo | Go | Maven | RubyGems |
      Composer | Conda | Terraform | OpenVsx | Other`), **used only as a metric label and for
      CLI grouping, never for behaviour**. It is a closed enum rather than a free string for
      exactly one reason: it becomes a metric label, and a free string there is unbounded
      cardinality handed to whoever edits the config. The members are not a guess at what
      exists — they are the ecosystems [Batlehub](https://github.com/batleforc/batlehub) proxies
      *and* that have a configuration file worth distributing; the ones it serves without one to
      inject (GitHub Releases, the JetBrains marketplace) fall under `Other`, as does anything
      behind a mirror this fleet does not run.
    - `sources: RegistrySource[]` — `{kind: ConfigMap | Secret, templateRef: TemplateRef}`, at
      least one, at most one per `{kind, name, namespace}` triple. A list rather than a single
      ref because one ecosystem routinely needs two objects with different confidentiality: the
      `ConfigMap` holding the registry URL, and the `Secret` holding the token it authenticates
      with.
  - `grants: BTreeMap<String, RegistryGrant>` — `{allowed: [...], default: [...]}`, the same
    shape and the same validation rules as `ProfileGrant` (`GrantAllowedUnknownKey`,
    `GrantDefaultOutsideAllowed`, `GrantNamesUndeclaredTeam`), reused rather than redeclared.
  - `namespaceSelection: RegistryNamespaceSelection` — the namespace annotation naming a
    comma-separated key list, defaulting to `hardening.weebo.io/registry-config`, read when it
    is present and falling back to the team grant's `default` when it is not.
  - `onNotGranted: OnNotGranted` — `Default | Deny`, the same enum `network-profiles` defines.
  - **No `baseline`**, per *Guide-level explanation*: a mandatory entry would write a file into
    workspaces whose image has no tool to read it, and the "everyone gets the mirror" case is
    already expressible as a grant.
  - **No `workspaceSelection`**, and this one is a real constraint rather than a choice — see
    the next subsection.

#### The unit is the namespace, not the workspace

Every prior brick in this series resolves per workspace: `network-profiles` writes a
`NetworkPolicy` whose `podSelector` names one `controller.devfile.io/devworkspace_id`,
`kubearmor-policy` does the same with a `KubeArmorPolicy`. Both can, because the object they
write carries its own selector.

An automounted `ConfigMap` does not. DevWorkspace Operator's automount is a property of the
*namespace*: an object labelled `mount-to-devworkspace` is mounted into every container of every
workspace in the namespace that hosts it, with no selector and no per-workspace opt-out. So a
devfile attribute cannot select a mount, and `registryConfig` has no `workspaceSelection` field
— not because per-workspace routing is undesirable, but because there is no mechanism to route
to. Two consequences the RFC would rather state than have discovered:

1. **Selection is a namespace annotation only.** Where `network-profiles` has two tiers
   (attribute, then annotation), this brick has one. A team wanting two different npm mirrors
   needs two namespaces, which is how teams are separated in this project anyway.
2. **This is why the race that would otherwise exist does not.** A per-workspace object has to
   be written between the `DevWorkspace` being created and its pod starting; a namespace-scoped
   one is provisioned when the namespace is reconciled, long before anyone opens a workspace in
   it. A workspace created seconds after its namespace still sees `weebo_si_registry_ready` at
   `0` and starts unconfigured, but the steady state is "already there" rather than "written
   just in time", which is the difference between an occasional visible gap and a permanent
   race.

If DevWorkspace Operator ever grows a per-workspace automount selector, `workspaceSelection`
becomes an additive amendment to this RFC, not a redesign — the resolution chain is written to
take a selection source, and today it has one.

#### Managed objects

`ConfigMap` and `Secret`, namespaced, written with `hardening.weebo.io/managed-by:
weebo-si-operator` and `hardening.weebo.io/profile: <key>`, one per `{namespace, granted key,
source}`. Named `weebo-si-<key>-<source-name>` in the target namespace, so two entries whose
templates share a name do not collide. The population is reported through
`weebo_si_registry_managed_objects`, the same shape `network-profiles` reports through
`weebo_si_network_managed_objects`.

The copy preserves `data`, `binaryData`, `stringData`, `type`, and every label and annotation
whose key is not `hardening.weebo.io/`-prefixed. It never preserves
`metadata.ownerReferences`, `resourceVersion`, or `uid` — a copy is a new object, not a mirror
of one.

#### `policy-guard` covers these objects too

A workspace namespace is one the *user* has edit rights in — that is the point of a workspace
namespace. So unlike a `NetworkPolicy` in the same namespace, which a user typically cannot
touch, an automounted `ConfigMap` is squarely inside what a determined developer can delete,
edit, or point at a registry of their choosing. Left alone, "the mirror is configured" would be
true only until someone found it inconvenient.

RFC 0004's `policy-guard` already answers exactly this question for `NetworkPolicy`: a write to
an object carrying `hardening.weebo.io/managed-by: weebo-si-operator` by anyone other than the
operator or a configured `allowedIdentity` is denied. This RFC extends it — a contract change,
which is why it is in an RFC rather than a pull request:

- **New webhook path**: `/validate/v1/registryconfigs`, handling `configmaps` and `secrets`,
  `CREATE`/`UPDATE`/`DELETE`. Resource-agnostic like the existing path, and a separate path
  rather than a second rule on the network one so the two can be enabled independently.
- **`objectSelector` on the rule**, matching `hardening.weebo.io/managed-by: weebo-si-operator`.
  This is not an optimisation, it is the thing that makes guarding `configmaps` viable at all:
  without it, the webhook sits in the path of *every* `ConfigMap` and `Secret` write in the
  cluster, including the ones the apiserver itself depends on. With it, the webhook sees only
  objects this operator wrote. For an `UPDATE`, Kubernetes evaluates `objectSelector` against
  both the old and the new object and calls the webhook if either matches, so stripping the
  label is itself a guarded write rather than an escape hatch.
- **`failurePolicy: Ignore`** on this rule specifically, against `policy-guard`'s existing
  choice for network policies — argued in *Operational considerations*.

Deleting a namespace, or a workspace, is unaffected: the guard matches on the object, and a
namespace deletion is not a write to it.

#### Observability contract

- `weebo_si_registry_reconcile_total{namespace,result}` — one per pass, `result` in
  `applied | unchanged | dry_run | failed`.
- `weebo_si_registry_managed_objects{namespace,key,kind}` — gauge, the current population.
- `weebo_si_registry_ready{namespace}` — gauge, `1` when every source of every resolved key for
  that namespace exists and matches its template, `0` when any is missing, stale, or refused;
  absent when the feature resolves no key for that namespace. **This is the signal an operator
  alerts on**, and the one that answers "did the developer's `npm install` fail because of us."
- `weebo_si_registry_drift_total{namespace,key,kind}` — incremented when a managed object was
  found modified or absent and rewritten, which is the count of how often someone is fighting
  this brick.
- `weebo_si_registry_not_granted_total{team,key}` — a namespace annotation naming a key its team
  does not have, mirroring `weebo_si_network_not_granted_total`.
- `weebo_si_registry_template_invalid_total{key,reason}` — `reason` in `not_found |
  mount_shadows_path | not_automountable`, the three ways a template is refused before it is
  ever copied.

Every decision is logged with the namespace, team, key and outcome. **Never the object's
`data`**, and never a `Secret`'s `stringData` in any form, including in a diff — see *Security
considerations*.

#### CLI

- `weebo-si-operator registry resolve --namespace <ns>` — prints the keys that namespace
  resolves to, the source objects each expands into, and where each would mount. The
  "explain the decision" command every feature in this project has.
- `weebo-si-operator registry check` — validates every catalogue entry against its template:
  exists, is automountable (carries `mount-to-devworkspace`), does not shadow a home path. Exit
  non-zero on any violation, so it works as a pre-flight in a pipeline that edits the catalogue.

### Architecture

**Hexagonal, yes**, against the three criteria in
[`hexagonal.md`](../architecture/hexagonal.md):

1. Real decision — catalogue/grant resolution per namespace, table-driven and identical in shape
   to `network-profiles`' own, plus the template admissibility rules above.
2. Touches an external system — the Kubernetes API, same as every reconciling feature.
3. We want "does this namespace's team reach this key, and what does it expand into" tested
   without a cluster, which is the test suite shape `network_profiles.rs`'s `validate()` already
   proves out.

`crates/weebo-si-registry-config` mirrors `weebo-si-network-profiles`' module layout, with one
`Subject` instead of two — there is no workspace-scoped subject here, per *The unit is the
namespace*:

- `model/object.rs` — `ManagedObject`, `ObjectKey`, and `ObjectBody` (the copied payload). The
  diff machinery moves to `weebo-si-chassis` in this RFC's implementation plan rather than being
  written a third time: comparing a body under a managed-by label filter is the same operation
  for a `NetworkPolicy`, a `KubeArmorPolicy` and a `ConfigMap`.
- `model/mount.rs` — the automount annotation vocabulary (`mount-as`, `mount-path`,
  `mount-to-devworkspace`) and the `TemplateMountShadowsPath` rule, as pure functions over a
  label/annotation map. This is the only module that knows DevWorkspace Operator exists, and the
  only one that would change if the automount contract upstream moves.
- `port.rs` — `TemplateStore` (fetch a template by `TemplateRef`), `ObjectStore` (what exists
  now, and applying a diff), `NamespaceView` (chassis port, reused for the selection annotation),
  and no `Capabilities` port at all: there is no second backend, no cluster capability to probe,
  and nothing to resolve. Its absence is deliberate — `network-profiles` has one because a CNI
  question exists, and inventing one here to match the shape would be the wrong kind of
  symmetry.
- `feature/` — the `ReconcileFeature<S>` implementation over a `NamespaceSubject`.

**One difference from every prior brick worth naming:** `TemplateStore` here reads `Secret`
objects, which no port in this project has done before. It is typed to return an opaque body
that the domain compares and copies but cannot destructure, so that "the domain never sees
credential material in a form it could log" is a property of the type rather than a review
convention. `weebo-si-runtime`'s adapter is the only code that holds the decoded bytes, and it
holds them between a `get` and an `apply`.

### Data and state

Stateless, like every reconciling feature on this chassis: a watch-backed cache of
`WeeboSiConfig`, `Namespace`, and — new here — the managed `ConfigMap`/`Secret` objects
themselves, filtered by the managed-by label so the cache holds this operator's own objects and
nothing else. Losing the cache costs one resync; losing a managed object costs one reconcile,
during which workspaces already running keep the copy the kubelet mounted for them.

Templates are **not** cached across reconciles: they are fetched per pass from the operator
namespace. A `Secret` held in a long-lived in-memory cache is a credential kept warm for the
lifetime of the process, and the read is cheap enough that not doing it is not a saving worth
the exposure.

## Security considerations

- **Privileges.** The controller role gains `get`/`list`/`watch` on `configmaps` and `secrets`
  in the operator's own namespace (the templates), and `get`/`list`/`watch`/`create`/`update`/
  `delete` on `configmaps` and `secrets` in workspace namespaces (the copies). **This is the
  largest privilege increase in the series so far, and it should be read as one**: an operator
  that can write a `Secret` into a workspace namespace can write any `Secret` into any workspace
  namespace, and one that can read them in its own namespace can read every template. The
  minimum is real but not small — the write half cannot be narrowed by RBAC below "secrets in
  namespaces this controller reconciles", because Kubernetes RBAC has no name-level grant for
  create. What narrows it in practice is the same thing that narrows `network-profiles`: the
  controller only ever touches objects carrying its own managed-by label, enforced in the
  adapter and reviewed as code, plus the `namespaceSelector` bounding which namespaces it
  reconciles at all.
- **Trust boundary.** The catalogue, the grants and the templates are admin-authored. The
  attacker-controlled input is the namespace annotation naming keys — bounded by the team's
  grant exactly as `network-profiles`' is, dropping to `default` or denying per `onNotGranted`.
  A second, subtler one: a workspace *user* can annotate their own namespace where RBAC allows
  it, which is a request for a key, never a grant of one.
- **A copied credential is a disclosed credential.** This is the part reviewers should spend
  their time on. A `Secret` copied into a workspace namespace is readable by anyone with `get
  secrets` there — which, in a Che-style deployment, is the workspace's owner — and by every
  process in every container of every workspace in that namespace, which includes an `npm`
  lifecycle script from a dependency nobody audited. **`registry-config` does not protect
  registry credentials; it distributes them.** The mitigations are policy, not code, and the
  RFC states them so nobody assumes otherwise:
  - Templates holding credentials should hold **read-only, per-team, rotatable** tokens. A
    publish token in this catalogue is a publish token in every workspace of every namespace
    that team owns.
  - Rotation is a single edit of the template plus one reconcile, which is the one thing this
    design genuinely improves over baking the token into an image.
  - **The credential-free path is specific to this fleet, and it is the one to aim at.**
    [Batlehub](https://github.com/batleforc/batlehub) authenticates callers by Kubernetes
    service account as well as by static token, so a workspace can prove who it is with a
    projected service-account token the kubelet mounts, rotates and scopes on its own — nothing
    this brick copies, nothing that survives the pod, nothing a `kubectl get secret` in the
    user's namespace discloses. Where that works, the entry degenerates to a single `ConfigMap`
    holding a URL, and every paragraph above stops applying. It is not the design this RFC
    builds on because it needs the mirror's own auth configuration and a projected-token volume
    the automount mechanism does not provide, both tracked under *Future work* — but a
    reviewer weighing the blocking question below should read it as the intended destination,
    not as a hypothetical.
  - The generic version of the same idea, for a registry whose auth Batlehub does not front:
    point the injected configuration at [`preauth-proxy`](./0003-preauth-proxy.md), let the
    proxy hold the credential, and copy a `ConfigMap` with a URL and no token at all.
- **Bypass — and this brick is full of them, by construction.** A developer who does not want
  the injected configuration simply does not use it: a project-local `.npmrc` beats the
  user-level one npm reads, `pip install -i` beats `pip.conf`, `mvn -s` beats
  `~/.m2/settings.xml`, and a `./.cargo/config.toml` in the repository beats `$CARGO_HOME`'s.
  Only an environment variable (`npm_config_registry`, `PIP_INDEX_URL`, `GOPROXY`) outranks a
  project-local file, and whether an entry uses one is the admin's `mount-as: env` decision, not
  a knob this brick adds. **None of this is a hole in this brick, because this brick is not a
  control.** It sets a default. The control is RFC 0004's egress policy, which is what actually
  stops the alternative registry from answering, and the two are designed to be deployed
  together: `registry-config` without `network-profiles` is a convenience, and
  `network-profiles` without `registry-config` is a support ticket.
- **Blast radius.** A wrong template behind a widely-granted key writes a wrong `.npmrc` into
  every namespace of every team holding that grant, and every workspace started after that point
  resolves packages from wherever it says — which, if the value is attacker-chosen, is a supply
  chain compromise with this operator as the delivery mechanism. That is a strictly worse
  failure than any prior brick's, because prior bricks could only ever *narrow*. It is bounded
  the same ways (`DryRun`, `namespaceSelector`, per-entry validation, revert-and-reconcile) plus
  one specific to it: the templates are ordinary objects in the operator namespace, so the same
  review and RBAC that protect the `WeeboSiConfig` protect them, and neither should be writable
  by anyone who is not already a cluster admin.
- **Secrets.** Reads templates that are, by design, sometimes credentials. The domain sees an
  opaque body (see *Architecture*); the adapter holds decoded bytes only between a `get` and an
  `apply`. Logs and metrics carry the namespace, team, key, source kind and object name — never
  a key of `data`, never a value, and never a content diff. `DryRun`'s output names *which*
  objects would change, never *how*, which is a deliberate reduction in usefulness relative to
  every other feature's dry run.

## Operational considerations

- **Failure mode — the controller.** Fail-open, in the only sense available to a reconciler: an
  outage stops new and changed configuration from being distributed; copies already in place
  keep working, and workspaces already running keep their mounts regardless. A workspace started
  during the outage in a namespace that was never provisioned starts unconfigured, and
  `weebo_si_registry_ready` says so.
- **Failure mode — the guard, and why it differs from RFC 0004's.** `policy-guard`'s existing
  network rule is fail-closed: a webhook outage stops `NetworkPolicy` writes, which is
  acceptable because the alternative is a window in which a workspace's egress policy can be
  removed. The registry rule takes `failurePolicy: Ignore`, and the reasoning inverts cleanly:
  the object being guarded is a `ConfigMap`, the consequence of an unguarded write is a
  developer pointing their own workspace at their own registry inside an egress baseline that
  still holds, and the consequence of a fail-closed rule is that a webhook outage blocks
  `ConfigMap` and `Secret` writes in every namespace the rule matches. Weighing "a bad `.npmrc`
  for one namespace, visible in `weebo_si_registry_drift_total` and corrected on the next
  reconcile" against "an apiserver that cannot write configuration during an operator outage",
  the first is plainly the smaller failure. Stated plainly so the asymmetry with RFC 0004 is a
  decision on the record rather than an inconsistency someone finds later.
- **Rollout.** `DryRun` first, behind a `namespaceSelector` scoped to one pilot team — more
  strongly recommended here than elsewhere, because the failure mode of a bad mount is "the
  workspace looks broken" rather than "something is denied", and that is harder to attribute.
  Then one team at `Enforce`, then the rest. Enabling the `policy-guard` registry rule should
  come *after* the copies are steady, so the guard is not fighting a reconciler that is still
  converging.
- **Rollback.** Flip `mode` to `Off`: the reconciler deletes what it manages on the next pass,
  and running workspaces keep their already-mounted copies until they restart. Faster, for one
  bad entry: edit or delete the template object, since templates are ordinary objects an admin
  already has RBAC on. Fastest, for one namespace: remove its selection annotation.
- **Observability.** `weebo_si_registry_ready` is the alert. `weebo_si_registry_drift_total`
  climbing for one namespace is a person, not a bug — worth a conversation rather than a page.
  `weebo_si_registry_template_invalid_total` firing is always an admin error and always
  actionable.
- **Upgrade.** Rolling update of the controller: caches rebuild, `/readyz` gates, no managed
  object is touched mid-rollout because the desired state is unchanged. The one upgrade that is
  not free is DevWorkspace Operator's own: the automount labels and annotations are its
  contract, not a versioned API, and `model/mount.rs` exists so that a change upstream is a
  single-module change here — pinned under *Unresolved questions*.
- **A mounted change needs a workspace restart.** Editing a template propagates to the copies on
  the next reconcile, but a running container keeps what it was given: environment variables
  never update, and file mounts update on the kubelet's own schedule into a process that has
  already read the file. The operational rule is "rotate the token, then tell people to restart
  their workspace", and it should be in the runbook rather than discovered during an incident.

## Alternatives considered

- **Do nothing — grant every team egress to the public registries instead.** The five-minute
  fix, and the one that makes RFC 0004's baseline decorative. Rejected on the grounds RFC 0004
  was accepted on.
- **Eclipse Che's own workspace-configuration provisioning**, which copies labelled objects from
  the Che namespace into every user namespace. This is the closest existing tool, it works, and
  this brick deliberately mirrors its mechanism. Rejected as the whole answer for three reasons:
  it is cluster-wide with no team routing, which is the exact problem for a catalogue containing
  credentials; it has no `DryRun` and no drift signal; and it ties this project's configuration
  distribution to Che's own release cadence rather than to the chassis every other brick here
  is on. Where a cluster has one mirror, no credential, and one team, Che's mechanism is the
  right answer and this brick is overhead — worth saying out loud.
- **Bake the configuration into the workspace images.** RFC 0005 already governs which images
  run, so this is a real option with real advantages: no runtime distribution, no copies, no
  guard. Rejected because a rotated credential becomes a fleet rebuild, per-team variation
  becomes per-team images, and a token in an image layer outlives every rotation and every
  `kubectl delete`.
- **A `postStart` command in the devfile.** Rejected: the devfile lives in the repository, so
  cluster policy would be distributed through pull requests, and it runs after the container
  starts, racing whatever the IDE launches on its own.
- **A mutating webhook on the workspace pod**, injecting env vars and volumes directly. This is
  the only design that gets genuine per-workspace granularity, which is a real advantage over
  the chosen one. Rejected because it duplicates a mechanism DevWorkspace Operator already
  owns, because it puts this project in the pod-creation path for every workspace (a failure
  there stops workspaces from starting, rather than starting them unconfigured), and because a
  pod mutation is invisible in the objects an admin can inspect before a workspace runs.
- **Mutating the `DevWorkspace` instead of the pod**, adding a volume component. Rejected: Che
  regenerates `DevWorkspace` objects from the devfile on start, so the mutation is either
  transient or a permanent fight with Che's own reconciler.
- **A Kyverno `generate` rule.** Handles "copy this object into namespaces matching a selector"
  well, and would cover most of this. Rejected for the reason every prior brick rejects it: the
  per-team grant half is not expressible without encoding the team table into the policy, and
  this project already has a chassis that owns that table, a `DryRun` semantic, and a status
  surface.

## Drawbacks and risks

This is the first brick whose compromise makes the cluster *less* safe rather than merely
unprotected: an operator that distributes registry configuration is an operator that can
redirect every build in the fleet to a registry of the attacker's choosing. The privilege that
makes it work — write `secrets` in workspace namespaces — is the strongest one this project has
asked for, and there is no version of this design that does not need it.

Beyond that: a fourth reconcile loop, a second webhook path with its own `failurePolicy`
argument, and a dependency on a DevWorkspace Operator contract (automount labels and
annotations) that is documented behaviour rather than a versioned API. The brick also lands
squarely in a support path — when a build fails, "is the registry config right" is now a
question about this operator, and `weebo_si_registry_ready` exists mostly so the answer takes
seconds.

## Unresolved questions

Non-blocking:

- **Whether `ecosystem` earns its place.** It is metric-label-and-CLI-only today, which is a
  thin justification for a closed enum that has to grow every time a package manager does. The
  alternative is deriving it from nothing and losing the metric dimension. Leaning toward
  keeping it, and toward `Other` being an entirely respectable answer.
- **Copy naming.** `weebo-si-<key>-<source-name>` is unambiguous but ugly in a `kubectl get`
  listing a developer reads. A hash suffix is worse. Not worth blocking on.
- **DevWorkspace Operator's automount contract**, pinned at the version in use when
  implementation starts. The label/annotation names are documented behaviour, not an API
  guarantee, and `model/mount.rs` exists to absorb a change; worth reconfirming the exact
  `mount-as` values (`file`/`subpath`/`env`) and the default-when-absent before writing the
  shadow-path rule against them.

Blocking, in the sense that acceptance should settle it:

- **Whether `Secret` sources belong in this brick at all.** The argument for: a registry
  configuration without its credential is half an answer, and splitting them across two
  mechanisms guarantees they drift. The argument against: everything under *Security
  considerations → A copied credential is a disclosed credential*, and the existence of two
  designs — Batlehub's own Kubernetes service-account auth, and `preauth-proxy` in front of a
  registry that has no such thing — where no workspace ever holds a token. A defensible
  narrower v1 is **`ConfigMap` sources only**, with `Secret` support gated behind whichever of
  those two lands first. This RFC proposes the wider version, and asks reviewers to say plainly
  whether they want it or whether the fleet's own mirror already makes it unnecessary.

## Future work

- **Batlehub service-account auth instead of a copied token.** Configure the mirror to accept
  the workspace's projected Kubernetes service-account token and drop `Secret` sources for
  every entry it fronts. Needs two things this RFC does not have: the mirror's own RBAC mapped
  onto the service accounts DevWorkspace Operator gives workspaces, and a way to get a
  projected-token volume into a workspace container, which automount does not do. The second is
  the same gap the *pod-mutating webhook* alternative would close, which is worth revisiting if
  this becomes the priority.
- **`preauth-proxy` as the credential holder.** Point the injected configuration at a
  `preauth-proxy` instance in front of the internal registry, so the workspace holds a URL and
  the proxy holds the token. This is the design that removes the whole *copied credential*
  section above, and it is deferred only because it needs `preauth-proxy` to speak each
  registry's auth exchange.
- **Container registry pull credentials.** Deliberately out of scope: `imagePullSecrets` are a
  kubelet concern attached to a `ServiceAccount`, not an automounted file, and routing them is a
  different mechanism with a different blast radius. It belongs with [RFC 0005](./0005-image-policy.md)'s
  vocabulary more than this one's, if it is built at all.
- **Per-workspace injection**, if DevWorkspace Operator grows a selector for automount, per *The
  unit is the namespace*.
- **A drift-to-alert path**, turning `weebo_si_registry_drift_total` into something a team lead
  sees rather than something a dashboard holds — the same deliberate deferral RFC 0006 makes for
  KubeArmor's own events.
- **Serving the templates from a `git` source** rather than from objects in the operator
  namespace, so the catalogue is reviewable in a repository. Attractive, and an entirely
  separate concern from routing.

## Implementation plan

- [x] `weebo-si-crd`: `RegistryKey`, `Ecosystem`, `RegistrySource`, `RegistryCatalog`,
      `RegistryGrant`, `RegistryNamespaceSelection`, `RegistryConfig` (`mode`,
      `namespaceSelector`, `catalog`, `grants`, `namespaceSelection`, `onNotGranted`), reusing
      `OnNotGranted` and `TemplateRef` from `network_profiles.rs` rather than redeclaring them,
      plus `validate()` and its `RegistryConfigViolation` set
- [x] Promote the managed-object diff machinery from `weebo-si-network-profiles` to
      `weebo-si-chassis`, so this crate does not write it a third time
- [x] `crates/weebo-si-registry-config`: `port.rs` (`TemplateStore`, `ObjectStore`),
      `model/object.rs`, `model/mount.rs` (automount vocabulary, `TemplateMountShadowsPath`),
      `resolve.rs` (grant resolution per namespace), `feature/` (`NamespaceSubject`,
      `ReconcileFeature<S>` impl)
- [x] `weebo-si-runtime`: `TemplateStore`/`ObjectStore` adapters, with the opaque-body typing
      that keeps decoded `Secret` bytes out of the domain
- [x] `weebo-si-controller`: the `Namespace` reconcile loop, mirroring `network_profiles.rs`'s
- [x] `weebo-si-webhook`: `/validate/v1/registryconfigs`, reusing `policy-guard`'s decision logic
      over a resource-agnostic write
- [x] `charts/weebo-si-operator`: the new `ValidatingWebhookConfiguration` rule with its
      `objectSelector` and `failurePolicy: Ignore`, and the RBAC above
- [x] `weebo-si-operator`: `registry resolve` and `registry check` subcommands
- [x] Metrics per the *Observability contract*, and the `Degraded` conditions
- [x] envtest coverage: a granted namespace converges, drift is corrected, an ungranted key is
      dropped or denied, a shadowing template is refused, `Off` deletes what it managed
- [x] Docs updated — as a `## RFC 0007: registry-config` section of
      [`docs/bricks/weebo-si-operator.md`](../bricks/weebo-si-operator.md) rather than the
      separate `docs/bricks/weebo-si-registry-config.md` this plan named, matching what RFCs 0004,
      0005 and 0006 each did: `docs/bricks/` is indexed by *deployable*, and this brick ships
      inside the `weebo-si-operator` binary. Plus the RFC 0004 guard section pointing here, and
      `docs/weebosiconfig.md`'s `features.registryConfig` and `features.policyGuard` entries.
- [x] RFC flipped to `Implemented`

## References

- [Batlehub](https://github.com/batleforc/batlehub) — the caching registry proxy this fleet
  runs and the host every entry in the catalogue points at: the ecosystems it serves are what
  `Ecosystem`'s members are drawn from, its Kubernetes service-account auth is the
  credential-free path under *Security considerations*, and its existence is what makes RFC
  0004's egress baseline affordable.
- [DevWorkspace Operator: automatically mounting volumes, ConfigMaps and Secrets](https://github.com/devfile/devworkspace-operator/blob/main/docs/additional-configuration.adoc) —
  the `controller.devfile.io/mount-to-devworkspace` label, the `mount-as` and `mount-path`
  annotations, and the per-namespace scope this RFC's design follows from.
- [Eclipse Che: mounting ConfigMaps and Secrets into workspaces](https://eclipse.dev/che/docs/stable/administration-guide/mounting-configmaps/) —
  prior art, including the `settings.xml` example, and the cluster-wide provisioning discussed
  under *Alternatives*.
- [Kubernetes: dynamic admission control, `objectSelector`](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-objectselector) —
  the old-or-new evaluation on `UPDATE` the guard rule depends on.
- [npm: `.npmrc` precedence](https://docs.npmjs.com/cli/v10/configuring-npm/npmrc) and
  [`npm config`](https://docs.npmjs.com/cli/v10/using-npm/config) — the project-beats-user
  ordering behind *this brick steers, it does not enforce*.
- [RFC 0002](./0002-weebo-si-operator.md) — the chassis, `spec.teams`, `ReconcileFeature<S>`.
- [RFC 0003](./0003-preauth-proxy.md) — the credential-holding proxy this brick's *Future work*
  points at.
- [RFC 0004](./0004-network-profiles.md) — the egress baseline that makes this brick necessary,
  the catalogue/grant pattern it ports, and the `policy-guard` this RFC extends.
- [RFC 0005](./0005-image-policy.md) — the sibling brick governing which image runs, and the
  reason baking configuration into images was rejected.

## Changelog

| Date | Change |
| --- | --- |
| 2026-08-25 | Implemented in full, in one slice, with the `Secret` sources this RFC proposed rather than the narrower `ConfigMap`-only v1 its blocking question offers. The two credential-free designs under *Future work* remain the intended destination; nothing here forecloses them, and every entry that reaches one degenerates to a single `ConfigMap` holding a URL. |
| 2026-08-25 | Metrics are labelled `{result,team}` / `{kind,ecosystem}` / `{state}` / `{action}`, not by namespace as the *Observability contract* wrote them — the same amendment RFC 0006 made, for the same reason: RFC 0004's project-wide "no metric carries a namespace or a workspace id" rule. `weebo_si_registry_ready` therefore publishes counts of namespaces per state, which alerts identically (`state="degraded" > 0`). Which namespace is degraded is a log line and `weebo-si-operator registry resolve`. **Two RFCs in a row have now specified metrics that violate a project-wide rule neither author reread**; the rule belongs somewhere an RFC template surfaces it. |
| 2026-08-25 | `ReconcileObserver` gained `forget(namespace)`, which no prior brick's observer has. Publishing readiness as a *count* means the observer holds a per-namespace map, and a namespace that goes `Off` or leaves `namespaceSelector` has to be dropped from it — otherwise the one alertable signal in this brick reports a degradation for a namespace nobody is configuring, forever. The domain is the only thing that knows a namespace has left scope, so it is a port method rather than adapter bookkeeping. |
| 2026-08-25 | The guard's third row (refuse `CREATE` of an unmanaged object) is absent from the *code*, not only from the webhook rule. The RFC argued the `objectSelector` makes that row unreachable; implementing it that way would mean a selector accidentally dropped from the chart turns the guard into one that **denies every `ConfigMap` a developer creates in their own namespace** — much worse than the gap it protects. Defence in depth, with the failure mode inverted. |
| 2026-08-25 | `content_eq` compares labels and annotations, which neither sibling brick's does. For a `NetworkPolicy` the metadata is decoration and the `spec` is the meaning; for an automounted object the annotations *are* the meaning — a template whose `mount-path` moved from `/home/user` to `/etc` has changed what it does without changing one byte of `data`. A diff that ignored them would report `Unchanged` forever. |
| 2026-08-25 | `Secret` templates are projected without `stringData`. It is a write-only field the apiserver merges into `data` and never serves back, so a template authored the way a human writes one reads back as `data` — projecting both would make a template and its own copy disagree about which field holds the payload, and the diff would rewrite every copy on every pass. Found while writing the envtest fixture, which authors its `Secret` as `stringData` for exactly that reason. |
| 2026-08-25 | `kubectl.kubernetes.io/last-applied-configuration` is stripped from both sides of the diff. For any object it guarantees a rewrite whenever an admin re-applies an unchanged template; for a `Secret` it is a second, stale copy of the credential that would otherwise be copied into the workspace namespace in an annotation. |
| 2026-08-25 | `ObjectBody` has no `Debug` derive, no borrowing accessor, and a consuming `into_bytes` — stricter than `PolicyBody` and `RuleBody`, which are opaque only because nothing needs their contents. Here the requirement is that nothing *can* reach them: a `{:?}` of a diff line is a realistic call site, and "the domain never sees credential material in a form it could log" had to be a property of the type rather than a review convention. Two tests assert the redaction directly, one on the body and one on a `ManagedObject` containing it. |
| 2026-08-25 | `validate()` gained `DuplicateCopyName`, which the *Contract* did not list. `weebo-si-<key>-<source-name>` is not injective: `a` + `b-c` and `a-b` + `c` both render `weebo-si-a-b-c`, and the second entry would silently overwrite the first in every granted namespace — a supply-chain failure with this operator as the delivery mechanism, and the exact blast radius *Drawbacks and risks* describes. The *Unresolved questions* entry on copy naming should be read as answered: the scheme stays, and the collision is now a `Degraded` condition rather than a surprise. |
| 2026-08-25 | `Ecosystem` earns its place, per the non-blocking question: it is the `weebo_si_registry_managed_objects` label and the `registry check` grouping, and the closed enum is what keeps that label bounded. `#[serde(default)]` to `Other`, so an entry that omits it is under-labelled rather than rejected — refusing a whole catalogue over a dashboard dimension would be the wrong trade. |
