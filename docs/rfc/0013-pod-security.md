---
rfc: 0013
title: pod-security
status: Accepted
authors: [batleforc]
created: 2026-10-31
updated: 2026-11-01
decided: 2026-11-01
brick: crates/weebo-si-pod-security
supersedes: []
superseded-by: []
---

# RFC 0013 — pod-security

## Summary

`pod-security` gives every workspace namespace a Pod Security Admission level, per team, on the
[RFC 0002](./0002-weebo-si-operator.md) chassis. The operator writes the upstream
`pod-security.kubernetes.io/*` labels onto each namespace in scope; the kube-apiserver's built-in
`PodSecurity` admission plugin does the enforcing. A team doing container builds gets `baseline`,
every other team gets `restricted`, and nobody gets `privileged` unless the cluster explicitly
raises its ceiling.

This RFC writes no admission code. Its value is routing — which namespace gets which level — and
bookkeeping: what the namespace carried before, so that `mode: Off` puts it back.

## Motivation

Nothing in this repository constrains what a workspace pod may ask of its node.

A Che user is the administrator of their own namespace. That is how Che works and it is not
going to change: the user creates DevWorkspaces, and DevWorkspace Operator creates pods on their
behalf. It also means the user can create a pod directly, with whatever `securityContext` they
like:

```console
$ kubectl run -n user-alice root --image=registry.internal/shared/base:2026.3 \
    --overrides='{"spec":{"hostPID":true,"containers":[{"name":"root",
    "image":"registry.internal/shared/base:2026.3","securityContext":{"privileged":true},
    "volumeMounts":[{"name":"host","mountPath":"/host"}]}],
    "volumes":[{"name":"host","hostPath":{"path":"/"}}]}}'
pod/root created
```

On a plain Kubernetes cluster that pod has the node. Every other workspace on that node, the
kubelet's credentials, the container runtime socket — and from there, the cluster. The image is a
permitted one, so [`image-policy`](./0005-image-policy.md) allows it. The network baseline from
[`network-profiles`](./0004-network-profiles.md) applies to it, which no longer matters once it
shares the host's PID namespace and filesystem. [`kubearmor-policy`](./0006-kubearmor-policy.md)
confines processes inside a container, and a privileged container with the host mounted is not
really inside one.

The same hole exists one layer up, which is where [RFC 0002](./0002-weebo-si-operator.md)
started. The pod and container security context of a workspace come from the
`DevWorkspaceOperatorConfig`. `dwoc-pin` makes sure the platform's DWOC is the one a workspace
uses, but it does not check what that DWOC says, and it cannot stop a pod that was never created
from a DevWorkspace.

Today, the only answer is whatever the distribution ships:

### What exists today

- **OpenShift: SecurityContextConstraints.** A real control, and the reason this gap has been
  easy to miss. A workspace service account gets `restricted-v2` by default. If container builds
  are on, Che grants it `container-build` too. This RFC must work with SCCs, not replace them —
  see *Design → OpenShift*.
- **Kubernetes: Pod Security Admission, switched on but unused.** The `PodSecurity` admission
  plugin has been built into the kube-apiserver and enabled by default since 1.25. A namespace
  without labels is evaluated at the cluster default, which is `privileged`: no restriction.
  Che does not label workspace namespaces, so every workspace namespace is effectively
  `privileged`.
- **A policy engine.** Kyverno and Gatekeeper both ship the Pod Security Standards as policies.
  Discussed under *Alternatives considered*.

**Outcome we are buying:** every workspace namespace in scope is enforced at a named Pod Security
Standard level. No workspace pod gets host namespaces, `hostPath`, privileged mode or added
capabilities beyond what its team's level allows, however it was created. A team that needs
container builds gets `baseline` because an admin decided it, not because the cluster defaulted
to nothing. And `mode: Off` gives back every namespace exactly as it was found.

## Guide-level explanation

The feature starts `Off`, per the chassis. It needs a cluster default, and optionally a level per
team:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  features:
    podSecurity:
      mode: DryRun
      default: restricted        # a namespace belonging to no team
      ceiling: baseline          # no team, annotation or default may be looser than this
      version: v1.34             # which revision of the standards the labels pin
---
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: team-build
spec:
  namespaceSelector:
    matchLabels: {weebo.io/team: team-build}
  features:
    podSecurity:
      level: baseline            # this team runs podman / buildah inside its workspaces
      warnLevel: restricted      # and is told, on every write, what restricted would refuse
```

The question an admin has before switching anything on is "what would this refuse that runs
today". The kube-apiserver can answer it: a server-side dry-run of the label returns one warning
for each existing pod that the new level would refuse. The CLI runs that dry-run in each
namespace and reads back the warnings:

```console
$ weebo-si-operator pods audit --all-namespaces
NAMESPACE      TEAM        LEVEL       VIOLATIONS
user-alice     team-1      restricted  0
user-bob       team-1      restricted  2  python-web-7d9c (allowPrivilegeEscalation != false,
                                          unrestricted capabilities); debug (runAsNonRoot != true)
user-carol     team-build  baseline    0
user-dave      (none)      restricted  1  data-pipeline-55f1 (seccompProfile)
```

Like `images audit`, it uses the admin's own kubeconfig and writes nothing.

In `DryRun` the controller computes the labels it would write and logs the difference, without
writing:

```text
INFO  feature=pod-security mode=DryRun ns=user-bob team=team-1 level=restricted
      diff=set:enforce=restricted,set:warn=restricted,set:audit=restricted previous=none
```

At `Enforce`, narrowed to a pilot namespace first, the labels appear:

```console
$ kubectl get ns user-bob --show-labels | tr ',' '\n' | grep pod-security
pod-security.kubernetes.io/audit=restricted
pod-security.kubernetes.io/audit-version=v1.34
pod-security.kubernetes.io/enforce=restricted
pod-security.kubernetes.io/enforce-version=v1.34
pod-security.kubernetes.io/warn=restricted
pod-security.kubernetes.io/warn-version=v1.34
```

The pod from the motivation is now refused by the apiserver itself:

```console
$ kubectl run -n user-bob root ...
Error from server (Forbidden): pods "root" is forbidden: violates PodSecurity
  "restricted:v1.34": privileged (container "root" must not set
  securityContext.privileged=true), host namespaces (hostPID=true), hostPath volumes
  (volume "host")
```

A workspace whose DWOC asks for more than its level allows does not start. The error lands on
the workspace's ReplicaSet, and DevWorkspace Operator copies it into the DevWorkspace status:

```console
$ kubectl get events -n user-bob
Warning  FailedCreate  replicaset/python-web-7d9c  Error creating: pods "python-web-7d9c-x2"
  is forbidden: violates PodSecurity "restricted:v1.34": allowPrivilegeEscalation != false
```

Pods already running when the label is written keep running. Pod Security Admission checks pods
when they are created or updated, never afterwards. A violating pod is reported, and refused the
next time it is created.

## Design

### Contract

#### `podSecurity`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | — | required, per the chassis |
| `namespaceSelector` | LabelSelector | none | per the chassis — the rollout knob |
| `default` | `restricted` \| `baseline` \| `privileged` | — | required. The level of a namespace belonging to no team, or to a team that sets none. |
| `ceiling` | same enum | `baseline` | The loosest level this feature will ever write. A team or default looser than the ceiling is clamped to it, and the clamp is reported. |
| `version` | `latest` \| `v1.N` | — | required. Written to every `*-version` label. See *Pinning the version*. |
| `backend` | `Auto` \| `Labels` \| `ObserveSynced` | `Auto` | Write the labels, or only compare them with OpenShift's synced ones. See *OpenShift*. |
| `namespaceSelection.annotation` | string | `hardening.weebo.io/pod-security` | Namespace annotation naming a level. **It can only tighten** — see *Resolution*. Empty string disables it. |
| per-team `level` | on `WeeboSiTeam` | absent | `spec.features.podSecurity.level`: this team's enforce level. |
| per-team `warnLevel` | on `WeeboSiTeam` | the team's `level` | The level written to `warn` and `audit`. May only be **stricter or equal** to `level`. |

There is no catalogue. Every other feature in this repo routes catalogue entries; this one routes
one of three upstream values, and a catalogue on top of three fixed values would be a layer of
indirection with nothing in it.

#### Resolution

For a namespace in scope:

1. `team_level` = the team's `level`, or `default` if the namespace has no team or the team sets
   none.
2. If the namespace carries the selection annotation and it names a level **stricter** than
   `team_level`, that level wins. A looser level in the annotation is ignored and logged with
   `result=not_tightening`.
3. The result is clamped to `ceiling`. A clamp is logged with `result=clamped`, and it sets
   `Degraded` on the `WeeboSiConfig` with the team named, because it means an admin wrote a
   level they cannot have.
4. `warnLevel` resolves the same way. If it ends up looser than the enforce level, it is raised
   to the enforce level.

The order is `privileged` < `baseline` < `restricted`.

**The annotation can only tighten, and that is what makes it safe to leave unguarded.** RFC 0005
and RFC 0006 both carry a known gap: a user who can annotate their own namespace can loosen what
an annotation controls. Here, whoever can write the annotation can only make their own namespace
stricter. A developer who wants `restricted` on a `baseline` team can have it. A developer who
wants `privileged` cannot. No RBAC assumption is needed.

#### What is written

For a resolved `(level, warnLevel)`, exactly six labels and one annotation, on the namespace:

| Key | Value |
| --- | --- |
| `pod-security.kubernetes.io/enforce` | `level` |
| `pod-security.kubernetes.io/enforce-version` | `version` |
| `pod-security.kubernetes.io/warn` | `warnLevel` |
| `pod-security.kubernetes.io/warn-version` | `version` |
| `pod-security.kubernetes.io/audit` | `warnLevel` |
| `pod-security.kubernetes.io/audit-version` | `version` |
| annotation `hardening.weebo.io/pod-security-previous` | the six labels' values before the first write, as JSON, `{}` if there were none |

They are written with server-side apply under the field manager `weebo-si-pod-security`, so the
operator owns exactly these keys. It owns no other label and no other annotation on the namespace.

**An existing stricter level is left alone.** If the namespace already enforces a level stricter
than the resolved one — an admin labelled it by hand, or another tool did — the feature writes
nothing. It logs `result=stricter_existing` and counts the namespace. This feature exists to raise
a floor. Lowering one that somebody else set would be a hardening component weakening a namespace.

**An existing looser level is taken over, and remembered.** Before the first write, the
namespace's existing values for the six keys go into the `-previous` annotation. Once that
annotation exists, it is never rewritten: it records the state from before the operator touched
the namespace, not the state from before the last write.

**Leaving is symmetric.** When `mode` goes to `Off`, or a namespace leaves scope (selector,
`hardening.weebo.io/exclude`, a structural exclusion), the controller restores the six keys from
the annotation and then removes it. Unlike [RFC 0004](./0004-network-profiles.md), which leaves
scope exits to `mode: Off` or the break-glass, cleanup here is free: the state lives on the
namespace object, which the controller already watches.

**Whose labels are these.** "A namespace this feature wrote to" means one that carries the
`-previous` annotation, or one where the field manager `weebo-si-pod-security` owns at least one
of the six keys in the namespace's managed fields. That decides three things:

- The stricter-existing rule applies only to a namespace this feature has not written to. On its
  own namespace, a resolution that loosens (a team moved from `restricted` to `baseline`) is
  written.
- The `-previous` annotation is sent on every apply with the value it already has: under
  server-side apply, an apply that omits a field the manager owns removes it.
- **Drift** is a namespace carrying the annotation where one of the six keys is now owned by
  another field manager: somebody changed a label after this feature wrote it.
  `weebo_si_pod_security_drift_total` counts it, and the next apply takes the key back.

The restore is two writes. First an empty server-side apply under `weebo-si-pod-security`, which
gives up every field that manager owns; then a merge patch under a different field manager,
`weebo-si-pod-security-restore`, that sets the previous values back and removes the rest. Once
restored, the keys belong to the namespace again; were they still owned by
`weebo-si-pod-security`, a later pass would read them as its own and report the annotation lost.
The envtest checks that no key is left in that manager's name.

#### Pinning the version

The `*-version` labels pin which revision of the Pod Security Standards the apiserver checks
against. With `latest`, a cluster upgrade can tighten a level: a check added in a later
Kubernetes release starts refusing pods that were admitted the day before. With a pinned
`v1.N`, the checks change only when an admin edits `version`.

`version` is **required, with no default**, because both answers are defensible and the choice is
the admin's. *Operational considerations* recommends pinning and bumping deliberately, after a
`pods audit` with the new value.

#### Seccomp

Seccomp is where `baseline` and `restricted` differ most, and where `baseline` is weakest.

| Level | What it requires of `seccompProfile` | A pod that sets nothing |
| --- | --- | --- |
| `privileged` | nothing | runs with the node's default |
| `baseline` | must not be `Unconfined` | **admitted**, and runs with the node's default |
| `restricted` | must be `RuntimeDefault` or `Localhost`, set explicitly on the pod or on every container | **refused** |

The node's default is the gap. Unless the kubelet runs with `seccompDefault: true`, a container
with no profile runs `Unconfined`: every syscall the kernel offers, including the ones container
escapes have used — `unshare`, `keyctl`, `bpf`, `mount` in a new user namespace. On such a node, a
`baseline` team's workspace that sets nothing has no syscall filter at all, and `baseline` admits
it. The Pod Security Standards only refuse a pod that says `Unconfined` explicitly. They do not
refuse one that gets it by default.

This RFC does three things about it, and one of them is only a recommendation:

- **`restricted` makes it explicit.** A `restricted` namespace refuses any pod without a profile.
  The consequence for rollout is direct: the DWOC must set `podSecurityContext.seccompProfile.type:
  RuntimeDefault`, or every workspace in a `restricted` namespace fails to start. The check
  looks at the pod spec, not at the node's default, so `seccompDefault: true` on the kubelet does
  not satisfy it. That is the first line `pods audit` prints on most fleets (see *Rollout*).
- **`baseline` relies on the node.** The install checklist requires `seccompDefault: true` in the
  kubelet configuration of every node that runs workspaces. That setting is node configuration,
  outside the cluster API and outside this operator, so it is a documented prerequisite, not
  something this feature can enforce. Without it, `baseline` means "no seccomp unless the DWOC
  sets one".
- **The DWOC is where the profile is chosen.** `dwoc-pin` already decides which DWOC a team's
  workspaces use. A DWOC that sets `RuntimeDefault` gives every workspace a filter whatever its
  level. That is the recommended configuration, and the brick doc will show it.

**OpenShift is already there.** `restricted-v2` requires `runtime/default` and sets it on pods
that leave it empty. The gap above is a Kubernetes one, and on OpenShift it only reopens for
service accounts holding a looser SCC.

**Container builds need a `Localhost` profile — measured, not assumed.** Rootless `podman` and
`buildah` create a user namespace, then mount inside it. Under the moby/containerd default, which
is what `RuntimeDefault` means on containerd, `unshare(CLONE_NEWUSER)` is refused and the build
stops. CRI-O's default (`containers/common`) allows it, which is why container builds work on
OpenShift today and fail on a containerd cluster with `RuntimeDefault`. The answer is a filter
written for builds, not `Unconfined`.

#### A build workspace: user namespace, then a filter

A build team's workspace — one that builds images, and one that runs containers in Che's
container-run mode — is isolated in two layers, and seccomp is the second one.

1. **A user namespace for the pod** (`hostUsers: false`). The workspace's UIDs, root included, map
   to an unprivileged range on the node, and its capabilities only count inside its own user
   namespace. A process that escapes the container lands on the node as nobody in particular.
   This is what lets a build run a real OCI container inside the workspace: with a user namespace,
   the kubelet allows `procMount: Unmasked`, and crun needs an unmasked `/proc` to mount one for
   the build.
2. **A `Localhost` seccomp profile.** The user namespace limits what an escape is worth, not the
   kernel surface a build reaches. A build has to create nested user namespaces and mount inside
   them, and most kernel privilege escalations of recent years start exactly there. The profile
   opens the syscalls a build was measured to need, and keeps everything else upstream reserves
   for `CAP_SYS_ADMIN` closed.

The DWOC `dwoc-pin` routes a build team to carries all three settings:

```yaml
config:
  workspace:
    hostUsers: false
    podSecurityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: profiles/weebo-container-build.json
    containerSecurityContext:
      procMount: Unmasked
```

**Builds use the pod's network** (`--network host` for buildah, `netns="host"` in
`containers.conf`). The pod's network namespace is the one `network-profiles` writes policy for, so
a build reaches exactly what its workspace reaches. The alternative, pasta, needs `/dev/net/tun`,
which a pod does not get by default, and gives a build its own network namespace for no gain.

**Running containers needs nothing more from seccomp.** Che's container-run mode — `podman run`,
detached services with `exec`, pods, `--userns=keep-id`, custom networks — was measured under
`container-build.json` with no syscall added. It does need `/dev/net/tun`, which that mode gives
the workspace, for pasta: a nested container then gets its own network namespace, but its traffic
still leaves through the pod's, so `network-profiles` still applies to it, and a published port
stays inside the pod unless a Service or a route exposes it. The chroot profile is not enough for
it, which is fine: container-run requires user namespaces anyway.

**Nested containers are invisible to `image-policy`.** [RFC 0005](./0005-image-policy.md)'s pod
webhook sees the images in the workspace pod's spec. An image pulled by `podman run` or by a
build's `FROM` inside the workspace never appears in any spec, so no team grant applies to it. What
bounds it today is the network: a workspace pulls only from registries its network profiles reach.
The control that would name images is a containers `policy.json` and `registries.conf` in the
workspace, injected per team, which is [RFC 0007](./0007-registry-config.md)'s mechanism. Listed
under *Future work*.

**The level stays `baseline`.** Builds still need `allowPrivilegeEscalation` for
`newuidmap`/`newgidmap`, which `restricted` refuses. Whether `baseline` admits `procMount:
Unmasked` on a pod with `hostUsers: false`: KEP-4265 relaxes that check for user-namespaced pods,
and the runtime matrix measured it on Kubernetes 1.35 with `enforce-version: latest`. Every build
workspace Pod was admitted at `baseline`, `procMount: Unmasked` included, and ran as expected. A
`version` pinned below the release that carries the relaxation would refuse them; `pods audit`
says so before `Enforce`.

**Node prerequisites.** User namespaces need the `UserNamespacesSupport` feature (enabled by
default in recent Kubernetes releases), a runtime that supports them (containerd 2 or CRI-O), and
idmapped mounts for the filesystems the pod uses. These are node and cluster settings, so they
are prerequisites on the install checklist, like `seccompDefault`.

#### Localhost profiles

This repo ships three profiles, generated by `task seccomp:gen` into `deploy/seccomp/profiles/weebo-` from
moby's default profile, pinned by tag and checksum:

| Profile | `localhostProfile` | For | Allowed beyond the workspace profile |
| --- | --- | --- | --- |
| workspace | `profiles/weebo-workspace.json` | every team, optional | nothing: the upstream default, the same on every runtime and versioned here |
| container-build | `profiles/weebo-container-build.json` | build teams, with `hostUsers: false` and `procMount: Unmasked` — the target | `clone`, `unshare`, `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `mount_setattr`, `sethostname`, `setns` |
| container-build-chroot | `profiles/weebo-container-build-chroot.json` | build teams on nodes without user namespaces | `clone`, `unshare`, `mount`, `umount2`, `pivot_root` |

In both build profiles the kernel keyring answers `ENOSYS`, and `clone3` keeps upstream's
`ENOSYS`, so glibc falls back to `clone`.

Each syscall was found by elimination: removed one at a time, each breaks at least one scenario.
The scenarios were `buildah build` (chroot isolation and OCI isolation), `podman build` and a nested
`podman run`. Each ran as a non-root user, without `/dev/fuse`, without `CAP_SYS_ADMIN`, inside a user
namespace, with `/proc` masked and unmasked. The chroot set is enough while `/proc` is masked, and
OCI isolation needs the other five: crun's id-mapped and read-only mounts of `/sys` and `/proc`
(`open_tree`, `move_mount`, `mount_setattr`), the build container's hostname (`sethostname`) and
joining the namespaces it created (`setns`). The new `fsopen`/`fsmount` API, `setdomainname`,
`bpf` and `perf_event_open` stay refused. The method, versions and results are in
[`../seccomp-profiles.md`](../seccomp-profiles.md), and the measurement is repeated whenever the
fleet's podman or crun changes.

**The upstream file cannot be used as it is.** It is in Docker's format, where some rules apply
only `includes: {caps: [CAP_SYS_ADMIN]}`. The OCI format a kubelet hands to the runtime has no
such condition, and containerd drops the field. The `CAP_SYS_ADMIN`-only rules — `mount`,
`unshare`, `bpf` and the rest — would become unconditional allows. The generator therefore
resolves every condition once, for `amd64` and for the capability set `baseline` allows, and the
output carries none. `task seccomp:check`, run by `task lint`, fails if the committed profiles
differ from a regeneration.

**Distribution is node configuration.** Every profile is installed under
`/var/lib/kubelet/seccomp/profiles/`, the directory Talos writes `machine.seccompProfiles` to, so
`localhostProfile: profiles/weebo-<name>.json` is the same everywhere. The generator writes one
patch per platform:

- **Talos** (the weebo-si cluster): `deploy/seccomp/talos-patch.yaml`, `machine.seccompProfiles`
  entries, applied by `talosctl patch mc` or added to the Pulumi program next to the
  hand-written `ci-build.json` already there.
- **OpenShift**: `deploy/seccomp/machineconfig-worker.yaml`. The SCC a building workspace uses must
  also list `localhost/profiles/weebo-container-build.json` in `seccompProfiles` and allow user
  namespaces.
- **Anything else**: the same files by whatever manages the nodes, or Security Profiles Operator
  `SeccompProfile` objects.

A pod naming a profile that is missing on its node does not start, so the files are rolled out
**before** a DWOC references them.

**The node's runtime does not change the lists, as far as measured.** The syscalls come from the
tools inside the workspace, which ship their own crun. What the node's runtime decides is whether
the pod gets a user namespace and whether it applies the profile. On weebo-si, containerd runs
workspaces on runc — the `crun`, `youki` and `wasmedge` extensions are installed, but no
`RuntimeClass` declares them. runc 1.5.2 and crun 1.28 give the same result on every scenario,
and so does a kind node's containerd 2.2 / runc 1.2.9 running the scenarios as Pods with
`hostUsers: false`.
youki, gVisor and Kata are measured in the cluster tier of the runtime matrix
([`../runtime-matrix.md`](../runtime-matrix.md)). By default, gVisor and Kata do not apply the
pod's seccomp profile at all, so for them the comparison is between their sandbox and this filter,
not about which syscalls they need.

**Che does not set any of this on Kubernetes.** che-operator forces
`disableContainerBuildCapabilities: true` outside OpenShift, so it never adds the build settings
itself. The DWOC `dwoc-pin` routes a build team to is the only place they come from, which is
also what keeps them per team.

Every other team keeps `RuntimeDefault`, or `profiles/weebo-workspace.json` on a cluster mixing runtimes.
`hostUsers: false` is worth giving them too, where the nodes support it: it costs a non-build
workspace nothing and limits what any escape is worth.

#### OpenShift

On OpenShift, Pod Security Admission and SCCs are two independent gates. A pod must pass both.
Two consequences:

- **The level cannot be looser than the SCCs make sense with, but it can be stricter.** Writing
  `restricted` on a namespace whose workspace service account holds `container-build` means
  container builds stop working. That is a configuration error, and `pods audit` finds it before
  enforcement.
- **OpenShift's label syncer stays on, and it owns the labels.** The `cluster-policy-controller`
  sets `pod-security.kubernetes.io/*` on non-`openshift-*` namespaces from the SCCs their service
  accounts can use. Turning it off per namespace is possible, and declined: the fleet keeps it on,
  so the SCC grants remain the one place a level is decided on OpenShift. Two writers on one label
  is not a state anyone should be debugging.

So on OpenShift this feature **observes instead of writing**. It still resolves each namespace's
level, then compares it with the synced `enforce` label. Synced at least as strict: `applied`.
Synced looser: `looser_synced`, logged with the namespace and counted, and `Degraded` names the
team. The lever is then the SCC grant, not a label. The choice is the `backend` field:

| `backend` | Behaviour |
| --- | --- |
| `Auto` (default) | `ObserveSynced` when the cluster serves `security.openshift.io/v1`, otherwise `Labels` |
| `Labels` | write the labels, as described above |
| `ObserveSynced` | write nothing, compare the synced level with the resolved one |

`Auto` resolves at startup by API discovery, the way [RFC 0006](./0006-kubearmor-policy.md)
resolves its enforcement backend.

#### CLI

```text
weebo-si-operator pods audit        # existing pods each namespace's level would refuse
                                    # [--level L] [--version V]
                                    # [--namespace NS | --all-namespaces]
```

`audit` resolves each namespace's level from the live configuration, unless `--level` overrides
it. It then sends a server-side dry-run patch of the `enforce` label and prints the warnings the
apiserver returns. It uses the invoking kubeconfig, which needs `patch namespaces`: a dry-run
needs the same RBAC as the write. The operator's service account is never used.

#### Observability contract

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_pod_security_namespaces` | gauge | `level`, `state` ∈ `applied`/`stricter_existing`/`pending` |
| `weebo_si_pod_security_reconcile_total` | counter | `result` ∈ `applied`/`unchanged`/`restored`/`clamped`/`not_tightening`/`stricter_existing`/`looser_synced`/`previous_lost`/`error` |
| `weebo_si_pod_security_drift_total` | counter | none — a label this feature owns was changed by someone else and re-applied |
| `weebo_si_pod_security_violations` | gauge | `level` — existing pods the apiserver warned about on the last write |

No metric carries a namespace or a pod name, for the reason [RFC 0004](./0004-network-profiles.md)
gives: unbounded, user-chosen label values take a metrics backend down. They go in the log line.

**Stability.** The feature identifier, its CRD fields, the resolution order, the annotation keys,
the field manager name and the metric names are the contract. Changing one needs a new RFC.

### Architecture

**Hexagonal, as a reconcile feature, with no new chassis trait.** Against the criteria in
[`../architecture/hexagonal.md`](../architecture/hexagonal.md):

1. *A real decision.* A three-step resolution with a clamp and a tighten-only override, a
   stricter-existing rule, a "previous" annotation that must be written exactly once, and an
   exit path that must restore exactly what it found. Each is one line of code. Each is also one
   way to write `privileged` into three hundred namespaces, or to strip a label an admin set by
   hand.
2. *Touches an external system.* Namespaces, by server-side apply.
3. *We want the decision tested without it.* The restore rules especially.

It follows the layout of `registry-config`: a `crates/weebo-si-pod-security` domain crate (the
subject, `ReconcileFeature::desired`, the resolution, the label diff) and a
`crates/weebo-si-pod-security-adapters` crate (the namespace label store, metrics, the loop). The
ports are:

- `NamespaceLabelStore` — read the six keys and the annotation, server-side apply the desired set
  under the field manager, and return the apiserver's warnings.
- The chassis's existing `NamespaceView`, `TeamView` and `FeatureGate`.

The domain crate holds the level ordering and the resolution. It does **not** evaluate pods
against the standards: the apiserver does that, and a second implementation of the Pod Security
Standards in this repo would be wrong the first time upstream changes a check.

### Data and state

**Stateless in the operator, stateful on the namespace.** The one piece of state this feature
needs, "what was here before me", is stored in the `-previous` annotation on the namespace it
describes. It cannot get out of step with the namespace, and it survives operator restarts,
reinstalls and leader changes.

Caches: the existing `Namespace` watch, which already carries labels and annotations, and the
`WeeboSiConfig`/`WeeboSiTeam` stores. No new watch.

If the annotation is lost — an admin deletes it by hand — the feature treats the current labels as
its own on the next write, and records `{}` as previous. `mode: Off` then removes the labels
instead of restoring an older value. This is logged as `result=previous_lost` once per namespace.

## Security considerations

**Privileges. `patch` on `namespaces`, behind `podSecurity.rbac.enabled`.** This RFC first said
the controller role already held it, for [RFC 0006](./0006-kubearmor-policy.md)'s posture
annotations. It does only when `kubearmorPolicy.rbac.enabled` is on, so the chart grants the same
verb under its own switch, off by default. Without it the feature is inert and says so at startup,
except on OpenShift, where `backend: Auto` only observes and needs no write. Kubernetes RBAC
cannot narrow the verb to named label keys, so the narrowing lives in the adapter, as it does for
RFC 0006: a server-side apply whose object contains exactly the seven keys above and nothing else.
That is reviewed as code, and an envtest asserts the applied object's key set. The webhook role is
unchanged.

**Trust boundary.** The inputs are the `WeeboSiConfig` and `WeeboSiTeam` (admin-written), the
namespace's labels and annotations (written by whoever can patch namespaces), and the
apiserver's warnings, which are logged as quoted, length-bounded fields. Nothing in a workspace
reaches this feature.

**Bypass.** The list, honestly:

- **Patching the namespace labels.** A user who can patch their own namespace can lower its
  level. Stock RBAC does not give namespace `update`/`patch` to a namespace `admin`, and Che does
  not either. The controller watches namespaces and re-applies within seconds, counting
  `weebo_si_pod_security_drift_total`, but pods created in that window are admitted. Guarding
  namespace writes is the same thing [RFC 0008](./0008-policy-guard-coverage.md) declined for
  RFC 0006's annotations — a webhook in front of every namespace write — and it is declined here
  for the same reason.
- **Cluster-level exemptions.** The apiserver's `AdmissionConfiguration` can exempt usernames,
  runtime classes and namespaces. An exempt identity creating pods bypasses this. That
  configuration is outside the cluster API and outside this operator. It goes on the install
  checklist.
- **Pods that existed before.** Not evicted, per upstream. Reported in
  `weebo_si_pod_security_violations` and by `pods audit`.
- **A looser `ceiling`.** Whoever can edit the `WeeboSiConfig` can raise the ceiling to
  `privileged`. That is an admin decision by definition, and the CRD is cluster-scoped and
  admin-only.
- **Namespaces outside scope.** A workspace namespace without the scope label is not labelled.
  This is the same positive-selector trade every namespace-writing feature here makes.

**What this does not cover, and is not trying to.** Pod Security Admission checks a pod's spec at
admission. It does not look at the image (that is [`image-policy`](./0005-image-policy.md)), what
the process does once running ([`kubearmor-policy`](./0006-kubearmor-policy.md)), where it talks
to ([`network-profiles`](./0004-network-profiles.md)), or how much it consumes
([RFC 0014](./0014-resource-quotas.md)). It also does not check whether the service account token
is mounted, or whether the root filesystem is read-only: `restricted` allows both. Both are
listed under *Future work*.

**Seccomp at `baseline` is the largest residual gap**, and it is worth stating apart from the list
above. A `baseline` pod that sets no profile, on a node without `seccompDefault: true`, runs
`Unconfined`, and this feature admits it. KubeArmor does not fill that gap: it confines files,
processes and network through an LSM, which is a different layer from a syscall filter. The two
work together, and neither replaces the other. The mitigations are the kubelet prerequisite and
a DWOC that sets `RuntimeDefault`, both under *Seccomp*. A pod check that requires an explicit
profile even at `baseline` belongs to the pod webhook under *Future work*.

**Blast radius, if this brick misbehaves.** The worst bug writes `restricted` where `baseline` was
needed: container builds stop, and workspaces whose DWOC asks for more than `restricted` fail to
start. The `ceiling` means a bug cannot write `privileged` unless an admin already allowed it. A
bug in the restore path can strip labels an admin set by hand, which is why that path is the most
heavily tested part of the domain crate. A compromised controller could do both, and it could
already do worse with the RFC 0006 namespace permission it holds today.

**Secrets.** None read.

## Operational considerations

**Failure mode: not ours to choose, and that is the main argument for this design.**
Enforcement is the kube-apiserver's own admission plugin, in-process, with no webhook and no
network call. It cannot be made unavailable by taking the operator down. If the operator is down,
labels stop being written to new namespaces and stop being corrected after drift. Existing labels
keep being enforced.

A new namespace created while the operator is down is unlabelled until the controller sees it.
The window is the time from namespace creation to the first reconcile. The perf budget in
[`../operator-performance.md`](../operator-performance.md) measures that window at under a second
p99 for 500 namespaces. A workspace starting in that window is evaluated as `privileged`. Closing
the window would need a mutating webhook on namespace `CREATE`; see *Alternatives considered*.

**Rollout.**

0. **`weebo-si-operator pods audit --all-namespaces --level restricted`**, before installing
   anything. If this lists every workspace pod, the DWOC asks for more than `restricted`. That is
   a DWOC decision to make first, not an enforcement problem to discover later. The most likely
   line is `seccompProfile`: the DWOC sets no profile. The fix is one field in the DWOC, see
   *Seccomp*. On `baseline` nodes, also check the kubelet's `seccompDefault`.
1. `mode: DryRun`, `default` and `version` set, no teams. Read the diff log.
2. Add the teams' `level`s, still in `DryRun`. `pods audit` again, now with per-team levels.
3. `mode: Enforce` with a `namespaceSelector` on a pilot label.
4. Remove the selector.

A gentler path exists, and it is the one upstream recommends: enforce `baseline` everywhere with
`warnLevel: restricted`, read the warnings for a release, then move teams to `restricted` one at a
time.

**Rollback.**

- `mode: Off` — every managed namespace is restored from its `-previous` annotation on the next
  reconcile.
- A team's `level` loosened, up to `ceiling` — the surgical undo for "this team needs builds".
- The break-glass: `kubectl label ns X pod-security.kubernetes.io/enforce=privileged
  --overwrite` works at once. The controller then re-applies its level, unless the namespace is
  also given `hardening.weebo.io/exclude`, which takes it out of scope and restores it.

**Observability.** `weebo_si_pod_security_violations` going above zero after a write means
existing pods will not come back after their next restart. `reconcile_total{result="clamped"}`
means a team asks for more than the ceiling allows. `drift_total` should be flat at zero. A rate
there means something else writes these labels. On OpenShift `drift_total` does not apply, and
`reconcile_total{result="looser_synced"}` is the number to watch: an SCC grant looser than the
team's level.
From the apiserver, `pod_security_evaluations_total{decision="deny"}` is the ground truth, and it
belongs on the same dashboard.

**Upgrade.** A rolling upgrade of the operator changes nothing that is enforced: the labels are
already on the namespaces. A Kubernetes upgrade with `version: latest` can tighten the standards.
With a pinned version it cannot. Bump `version` after `pods audit --version v1.N+1`.

**Self-deadlock.** None. The operator namespace is structurally excluded, and enforcement does not
depend on the operator being up.

## Alternatives considered

**Do nothing, and rely on the distribution.** On OpenShift this is a real option, because SCCs
already enforce `restricted-v2`. On Kubernetes it means every workspace namespace is
`privileged`. Rejected, because the fleet this repo targets includes both.

**Label namespaces through Che.** Che can apply a namespace template to the namespaces it
creates. That covers creation only, for everyone the same, with no per-team level, no drift
correction and no undo. It is a reasonable first step on a cluster that wants one level for
everyone and will never change it, and the RFC would rather say so than pretend otherwise.

**Kyverno or Gatekeeper with the Pod Security Standards policies.** Mature, well tested, and able
to express finer rules than three levels. Rejected for the same reason
[RFC 0005](./0005-image-policy.md) gives: a second admission engine in front of every pod, at
`failurePolicy: Fail`, is a new availability dependency. The built-in plugin is already there, and
it cannot be taken down. The finer rules are the real loss, listed under *Future work*.

**A validating webhook on pods, written here.** `image-policy` already runs one, so the cost would
be a second check in an existing path rather than a new path. Rejected for the three-level part,
because reimplementing the Pod Security Standards is exactly what *Architecture* argues against.
It remains the natural home for checks the standards do not make; see *Future work*.

**A mutating webhook on namespace `CREATE`**, labelling a namespace before it exists rather than
right after. It closes the sub-second window described under *Failure mode*. Rejected for now: a
webhook in front of every namespace creation in the cluster, to close a window measured in
hundreds of milliseconds, is the wrong trade, and RFC 0008 declined a namespace webhook for a
stronger reason.

## Drawbacks and risks

**Three levels are coarse.** `baseline` allows a lot. A team that needs one capability for
container builds gets everything `baseline` allows, not just that capability. Pod Security
Admission has no finer grain, and this RFC buys simplicity and availability at that price.

**Writing into a shared object.** Namespaces are shared with Che, with OpenShift's syncer, and
with whatever the admin runs. Server-side apply with one field manager keeps ownership exact,
but this is still the first feature here whose main output is labels on an object it does not
own.

**Coupling to Che's security context.** A Che upgrade that changes the workspace security context
can turn a compliant fleet into a refused one. That is what `pods audit` before a Che upgrade is
for, and what the runbook must say.

## Unresolved questions

- ~~**Does kube-client surface the `Warning` headers of a server-side apply?**~~ Answered,
  2026-11-01: `Api::patch` does not, it returns the object only. The adapter builds the same
  request and sends it with `Client::send`, which returns the headers. The envtest raises a
  namespace to `baseline` over an existing pod with an added capability and a `hostPath`, and the
  pod's name comes back in the warnings.
- **Do the build profiles hold on the fleet's runtime?** (Not blocking.) Measured
  with podman 5.8, buildah 1.43 and crun 1.28 on kernel 7.2, under runc 1.5.2 and crun 1.28. A
  newer crun may use more of the new mount API (`fsopen`, `fsmount`, ...) and need it. The runtime
  matrix's local tier fails on that in CI, and `weebo-container-build-log.json` finds what is
  missing on a test node.
- ~~**Does `baseline` admit `procMount: Unmasked` with `hostUsers: false` at the pinned
  version?**~~ Answered, 2026-10-31: yes on Kubernetes 1.35 at `enforce-version: latest`. The
  runtime matrix's cluster tier ran every build scenario at `baseline` on kind: each Pod passed a
  server-side dry run and ran with the same result as at `privileged`. What remains is the
  `version` the fleet pins: it must be a release with KEP-4265's relaxation, or build teams would
  need `privileged` under the `ceiling`, which this RFC will not ship. `pods audit --level
  baseline` on a build workspace checks it before `Enforce`.
- **Che's container-build and container-run modes, level by level.** (Not blocking, to be
  measured.) The build setup above is designed to fit `baseline`. Step 0 of the rollout measures
  it on the real fleet, and the brick doc records the result.

## Future work

- **Checks the standards do not make**, in `image-policy`'s pod webhook path: no automounted
  service account token unless the team allows it, a read-only root filesystem, an allow-list of
  added capabilities finer than `baseline`, and an explicit `seccompProfile` even at `baseline`, so
  the node's default stops mattering. Its own RFC, because it is a `failurePolicy: Fail`
  decision on pods.
- **DWOC compatibility at config time**: warn when the DWOC `dwoc-pin` routes a team to asks for
  more than that team's level allows, before any workspace fails to start. This needs a way to
  evaluate a security context without reimplementing the standards, possibly a server-side
  dry-run of a sample pod.
- **An image policy for nested containers**: a containers `policy.json` (and `registries.conf`)
  injected per team by `registry-config`, built from the same catalogue as `image-policy`, so a
  `podman run` or a build's `FROM` inside a workspace is held to the team's grant. Until then, the
  network profile is what bounds it.
- **`arm64` profiles.** The generator resolves for one architecture; an `arm64` pool needs its own
  output, with the same Multi-arch trigger as [RFC 0001](./0001-passwd-append.md).
- **Security Profiles Operator as the distribution on Kubernetes**, with profile recording to keep
  the build profile in step with the workspace image.

## Implementation plan

- [x] `weebo-si-crd`: `PodSecurityLevel`, `PodSecurityConfig` (`mode`, `namespaceSelector`,
      `default`, `ceiling`, `version`, `namespaceSelection`), the team fields, `Resolved*`, and
      the `pod-security` entry in the `WeeboSiConfig` status.
- [x] `weebo-si-pod-security`: subject, resolution, label diff, previous/restore rules, unit tests
      for every row of *Resolution* and *What is written*.
- [x] `weebo-si-pod-security-adapters`: `NamespaceLabelStore` by server-side apply, metrics, loop,
      envtest asserting the exact key set written.
- [x] `weebo-si-operator`: wiring.
- [ ] `weebo-si-operator`: `pods audit` CLI.
- [x] Chart: `podSecurity.rbac.enabled` grants `patch` on `namespaces`, with a comment naming this
      RFC.
- [ ] e2e on kind: a privileged pod refused at `Enforce`, restored labels at `Off`.
- [x] `Localhost` seccomp profiles: `scripts/seccomp-profiles.sh`, `deploy/seccomp/`,
      `task seccomp:gen` / `seccomp:check` (in `task lint`), measured against nested builds.
- [x] Runtime matrix: `scripts/runtime-matrix.sh` (podman, `check` mode) and
      `scripts/runtime-matrix-k8s.sh` (Pods per runtime class, Pod Security level as a result),
      `task runtimes:*`, the `runtime-matrix` workflow, `docs/runtime-matrix.md`.
- [x] Runtime matrix, cluster tier: the `default` (runc) row on kind, in CI and checked, at
      `baseline` and `privileged`.
- [ ] Runtime matrix, cluster tier: crun, youki, gVisor and Kata on a test cluster.
- [ ] kind e2e: mount `deploy/seccomp/profiles` on the nodes, a build team's workspace
      (`hostUsers: false`, `procMount: Unmasked`) builds an image with OCI isolation under
      `profiles/weebo-container-build.json`, and fails under `RuntimeDefault`.
- [ ] e2e on OpenShift: `ObserveSynced` reports a looser SCC grant; the MachineConfig and an SCC
      listing `localhost/profiles/weebo-container-build.json` let a workspace build.
- [ ] Docs: brick page, `weebosiconfig.md`, `weebositeam.md`.
- [ ] RFC flipped to `Implemented`

## References

- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Migrate from PodSecurityPolicy to Pod Security Admission](https://kubernetes.io/docs/tasks/configure-pod-container/migrate-from-psp/) — the warn-then-enforce path
- [Restrict a container's syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) — `seccompDefault` on the kubelet
- [Security Profiles Operator](https://github.com/kubernetes-sigs/security-profiles-operator)
- [OpenShift: understanding and managing pod security admission](https://docs.redhat.com/en/documentation/openshift_container_platform/latest/html/authentication_and_authorization/understanding-and-managing-pod-security-admission)
- [RFC 0002](./0002-weebo-si-operator.md) — the DWOC carries the workspace security context
- [RFC 0006](./0006-kubearmor-policy.md) — the existing `patch namespaces` grant and its narrowing
- [RFC 0008](./0008-policy-guard-coverage.md) — why namespace writes stay unguarded
- [RFC 0014](./0014-resource-quotas.md) — the other half of a workspace's node footprint

## Changelog

| Date | Change |
| --- | --- |
| 2026-11-01 | The adapters land. The Warning-headers question is answered (a raw request returns them). `patch` on `namespaces` is a chart switch of its own, `podSecurity.rbac.enabled`, not a verb the role already had. |
| 2026-11-01 | `Accepted`. *What is written* says how ownership is read (the `-previous` annotation or the managed fields), what drift is, and that the restore write uses its own field manager. A team's level looser than the ceiling is reported on that team's own status as well as on the `WeeboSiConfig`. |
| 2026-10-31 | The runtime matrix's cluster tier ran on kind: `baseline` admits build workspaces with `hostUsers: false` and `procMount: Unmasked` on 1.35 (`latest`), and runc gives the expected cells. |
