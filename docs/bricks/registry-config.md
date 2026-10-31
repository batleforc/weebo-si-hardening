# `registry-config`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and rationale:
[RFC 0007](../rfc/0007-registry-config.md). Field reference:
[`features.registryConfig`](../weebosiconfig.md#featuresregistryconfig). The operator's own
install, CLI and break-glass are on [`weebo-si-operator.md`](./weebo-si-operator.md); this page
assumes it is installed.

Every other feature of the operator **narrows** what a workspace may do. This one **adds** something: the
`.npmrc`, the `pip.conf`, the Cargo `config.toml`, the Maven `settings.xml` a workspace needs to
resolve packages from the internal mirror, copied into every workspace namespace of a team.

**It is not a control, and reading it as one is the mistake this section exists to prevent.**
Nothing here stops a developer pointing a build at any registry they like: a project-local
`.npmrc` beats the user-level one npm reads, `pip install -i` beats `pip.conf`, `mvn -s` beats
`~/.m2/settings.xml`. What stops the alternative registry from *answering* is `network-profiles`'
egress baseline. The two go together: `registry-config` without `network-profiles` is a
convenience, and `network-profiles` without `registry-config` is a support ticket — the moment
the baseline is real, `npm install` stops working and nothing in the container knows why.

## Install checklist

1. **Have a mirror.** This fleet runs [Batlehub](https://github.com/batleforc/batlehub), a caching
   proxy in front of npm, PyPI, Cargo, Go, Maven, RubyGems, Composer, Conda, Terraform, GitHub
   Releases, OpenVSX and the JetBrains marketplace. Any reachable mirror works; what this feature
   distributes is the *configuration pointing at it*, not the mirror.

2. **Grant the RBAC — and read what you are granting.** Off by default:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set registryConfig.rbac.enabled=true
   ```

   This adds `create`/`update`/`patch`/`delete` on `configmaps` **and `secrets`**, cluster-wide.
   **It is the strongest permission this project asks for**, and Kubernetes RBAC cannot narrow it
   — there is no name-level grant for `create`. The narrowing is in code: every object this
   operator touches carries its own `hardening.weebo.io/managed-by` label, the watch is filtered
   by it server-side, and `namespaceSelector` bounds which namespaces are reconciled at all.

   Enabling the flag also renders the `policy-guard` rule for these objects
   (`/validate/v1/registryconfigs`). See *The guard rule is shaped differently* below.

3. **Author the templates.** Ordinary `ConfigMap` and `Secret` objects in `weebo-si-hardening`,
   carrying DevWorkspace Operator's own automount label and annotations. This feature never reads
   their `data`.

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: weebo-npmrc
     namespace: weebo-si-hardening
     labels:
       controller.devfile.io/mount-to-devworkspace: "true"
     annotations:
       controller.devfile.io/mount-as: subpath
       controller.devfile.io/mount-path: /home/user
   data:
     .npmrc: |
       registry=https://batlehub.internal/npm/
       always-auth=true
   ```

   **`mount-as: subpath` is not optional in practice.** `file` — DevWorkspace Operator's default
   *when the annotation is absent* — mounts the object as a **directory** at `mount-path`, so this
   `ConfigMap` at `/home/user` would replace the home directory with one containing only `.npmrc`:
   no shell history, no IDE settings, possibly no writable home. It looks like a broken image
   rather than a broken config, which is why this operator refuses such a template outright rather
   than copying it. That refusal is the only content inspection it does.

4. **Check the catalogue against the cluster** before switching anything on:

   ```bash
   weebo-si-operator registry check
   ```

   Every entry, every source: does the template exist, does it carry the automount label, would it
   shadow a home directory. Non-zero on any violation, so it works as a pipeline pre-flight.

5. **Configure the feature**, starting at `DryRun` behind a `namespaceSelector` scoped to one
   pilot team. More strongly recommended here than for any other feature: the failure mode of a
   bad mount is "the workspace looks broken" rather than "something was denied", and that is much
   harder to attribute.

   ```yaml
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
       onNotGranted: Default
   ```

   **There is no `baseline` field.** A cluster with one mirror for everyone expresses that as a
   grant every team has. "Mandatory" would mean writing a file into a container whose image may
   not have the tool it configures.

## Before you put a `Secret` in the catalogue

A `Secret` copied into a workspace namespace is readable by anyone with `get secrets` there —
which, in a Che-style deployment, is the workspace's owner — and by every process in every
container of every workspace in that namespace, which includes an `npm` lifecycle script from a
dependency nobody audited.

**This feature does not protect registry credentials; it distributes them.** The mitigations are
policy, not code:

- Templates holding credentials should hold **read-only, per-team, rotatable** tokens. A publish
  token in this catalogue is a publish token in every workspace of every namespace that team owns.
- Rotation is one edit of the template plus one reconcile, which is the one thing this design
  genuinely improves over baking the token into an image.
- **The credential-free path is the one to aim at.** Batlehub authenticates callers by Kubernetes
  service account as well as by static token, so a workspace can prove who it is with a projected
  token the kubelet mounts and rotates — nothing this feature copies, nothing that survives the
  pod. Where that works, the entry degenerates to a single `ConfigMap` holding a URL. It needs a
  projected-token volume that automount does not provide, and is RFC 0007's *Future work*.
- The generic version, for a registry Batlehub does not front: point the injected configuration at
  [`preauth-proxy`](./preauth-proxy.md) and let the proxy hold the credential.

## What gets written

| Object | One per | Name |
| --- | --- | --- |
| `ConfigMap` | namespace × granted key × source | `weebo-si-<key>-<template-name>` |
| `Secret` | namespace × granted key × source | `weebo-si-<key>-<template-name>` |

Each copy carries the template's own labels and annotations verbatim — including the automount
label, which is the reason it does anything at all — plus
`hardening.weebo.io/managed-by: weebo-si-operator` and `hardening.weebo.io/profile: <key>`. It
never carries the template's `ownerReferences`, `resourceVersion` or `uid`: a copy is a new
object, not a mirror of one.

**Selection is a namespace annotation only**, unlike every other catalogue feature here. An
automounted object has no selector — DevWorkspace Operator mounts it into *every* container of
*every* workspace in the namespace hosting it — so there is no per-workspace routing to offer. A
team wanting two different npm mirrors needs two namespaces, which is how teams are separated in
this project anyway.

The same absence is why this feature has no race the others have to argue about: a namespace is
reconciled when it appears, long before anyone opens a workspace in it.

## Rollout

1. `mode: DryRun` with `namespaceSelector` scoped to one pilot team. `weebo-si-operator registry
   resolve --namespace <ns>` tells you what would land and where it would mount.
2. `mode: Enforce` for that team. Verify from inside a workspace:

   ```bash
   kubectl get configmap,secret -n <workspace-ns> -l hardening.weebo.io/managed-by=weebo-si-operator
   # then, in a workspace terminal:
   cat ~/.npmrc && npm install
   ```

   A workspace must be **restarted** to see a newly-landed mount.
3. Widen the selector, one team at a time.
4. **Enable the guard rule last**, once the copies are steady — the guard should not be fighting a
   reconciler that is still converging.

## Rollback

- Flip `mode` to `Off`: the reconciler deletes what it manages on the next pass. Running
  workspaces keep the copies the kubelet already mounted until they restart.
- Faster, for one bad entry: edit or delete the template object. Templates are ordinary objects an
  admin already has RBAC on.
- Fastest, for one namespace: remove its selection annotation.

## A mounted change needs a workspace restart

Editing a template propagates to the copies on the next reconcile, but a running container keeps
what it was given: environment variables never update, and file mounts update on the kubelet's own
schedule into a process that has already read the file. **The operational rule is "rotate the
token, then tell people to restart their workspace"** — it belongs in the runbook rather than
being discovered during an incident.

## The guard rule is shaped differently, on purpose

`policy-guard`'s registry rule is not the network rule with two more resources on it, and the
differences are decisions on the record rather than inconsistencies:

| | Policy rules (network, KubeArmor) | Registry rule |
| --- | --- | --- |
| `objectSelector` | none | `hardening.weebo.io/managed-by: weebo-si-operator` |
| `failurePolicy` | `Fail` | `Ignore` |
| Refuses unmanaged `CREATE`? | yes | **no** |

`ConfigMap` and `Secret` writes are among the highest-volume writes in a cluster. Without the
`objectSelector`, this webhook would sit in the path of every one of them, including the ones the
apiserver itself depends on — so the rule sees only objects this operator wrote, and consequently
cannot have a row that refuses *unmanaged* creates. That row is absent from the code as well as
from the rule, deliberately: if the selector were ever dropped from the chart, a guard with the
third row would deny every `ConfigMap` a developer creates in their own namespace, which is a far
worse outage than the gap it protects.

`failurePolicy: Ignore` follows from the same weighing. Fail-closed here means a webhook outage
blocks `ConfigMap` and `Secret` writes in every workspace namespace; fail-open means a developer
can point their own workspace at their own registry, inside an egress baseline that still holds,
visible in `weebo_si_registry_drift_total` and corrected on the next reconcile. The second is
plainly the smaller failure. Set `registryConfig.failurePolicy=Fail` if your cluster disagrees.

On an `UPDATE`, Kubernetes evaluates `objectSelector` against both the old and the new object and
calls the webhook if *either* matches — so stripping the ownership label is itself a guarded write
rather than an escape hatch.

## Reading the logs

```text
weebo-si-controller: registry-config namespace=user-alice mode=Enforce diffs=2 applied=Some(Applied { created: 2, .. }) ready=true
WARN weebo-si-controller: feature=registry-config team=team-1 namespace=user-alice requested=[internal-maven] result=not_granted
WARN weebo-si-controller: feature=registry-config namespace=user-alice key=internal-npm source=ConfigMap/weebo-npmrc result=template_invalid reason=mount_shadows_path
weebo-si-webhook: policy-guard deny namespace=user-alice actor=user-alice kind=ConfigMap operation=Delete reason=...
```

**No log line in this feature ever carries an object's contents**, and neither does a `DryRun`: it
names *which* objects would change, never *how*. That is a deliberate reduction in usefulness
relative to every other feature's dry run, and it is enforced by the type rather than by
convention — the payload type has no `Debug` that prints bytes and no accessor that borrows them.

## Observability

| Metric | Labels | Read it for |
| --- | --- | --- |
| `weebo_si_registry_ready` | `state` | **The alert.** `state="degraded" > 0` means at least one namespace resolves a key whose source did not land — the answer to "did the developer's `npm install` fail because of us". |
| `weebo_si_registry_reconcile_total` | `result`, `team` | `created`/`updated`/`deleted`/`unchanged`/`dry_run`/`error`. |
| `weebo_si_registry_managed_objects` | `kind`, `ecosystem` | What this operator currently owns. |
| `weebo_si_registry_drift_total` | `action` | How often someone is fighting this feature. Climbing for one namespace is a person, not a bug — a conversation rather than a page. |
| `weebo_si_registry_not_granted_total` | `team`, `key` | A namespace asking for something its team does not have. |
| `weebo_si_registry_template_invalid_total` | `key`, `reason` | `not_found`/`mount_shadows_path`/`not_automountable`. **Always an admin error and always actionable.** |

**None of these carries a namespace label**, and neither does any other metric in this operator —
RFC 0004's observability contract forbids it project-wide, because a per-namespace time series is
how a metrics backend is taken down by a hardening component. RFC 0007 wrote its metrics with one;
implementing it as written would have made this the brick that does it, so `ready` publishes
*counts of namespaces per state* instead, which alerts identically. Which namespace is degraded is
in the log line above and in `weebo-si-operator registry resolve --namespace <ns>`.

## Known limitations, specific to this feature

- **This is the first brick whose compromise makes the cluster *less* safe rather than merely
  unprotected.** An operator that distributes registry configuration is an operator that can
  redirect every build in the fleet to a registry of an attacker's choosing. Prior bricks could
  only ever *narrow*. Treat the templates and the `WeeboSiConfig` as equally privileged: neither
  should be writable by anyone who is not already a cluster admin.
- **`Secret` sources distribute credentials by design.** Covered above. Whether they belong in
  this feature at all is RFC 0007's own blocking question; the wider version shipped, and the two
  credential-free designs it names remain the intended destination.
- **The DevWorkspace Operator automount contract is documented behaviour, not a versioned API.**
  The label and annotation names, the `mount-as` values and the default-when-absent are pinned in
  one module (`weebo-si-registry-config`'s `model/mount`) so an upstream change is a
  single-module change here, but it is still an upstream change that can break this feature.
- **The envtest suite proves what we write, not that anything mounts it.** There is no
  DevWorkspace Operator behind the apiserver it runs against.
- **A namespace that leaves the feature's `namespaceSelector` keeps its copies**, the same gap
  every other reconciling feature here has. `mode: Off` or a template deletion is the cleanup.
- **Container registry pull credentials are out of scope.** `imagePullSecrets` are a kubelet
  concern attached to a `ServiceAccount`, not an automounted file.
