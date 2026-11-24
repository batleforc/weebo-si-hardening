---
rfc: 0018
title: namespace UID range
status: Draft
authors: [batleforc]
created: 2026-11-24
updated: 2026-11-24
decided:
brick: crates/weebo-si-pod-identity
supersedes: []
superseded-by: []
---

# RFC 0018 — namespace UID range

> Reference material: past 4 000 words. Read *Summary*, *Motivation*, *Goals and non-goals* and
> *Unresolved questions* for the decision; the rest is the argument.

## Summary

`podIdentity` gives every workspace namespace its own block of Unix ids and makes every pod in
that namespace run inside it. The controller hands each namespace in scope the lowest free block
of 100 ids between 10000 and 65535 and records it as the namespace annotation
`hardening.weebo.io/uid-range: <start>/<size>`. A mutating Pod webhook sets the pod's
`runAsUser`, `runAsGroup` and `fsGroup` to the block's first id; a validating Pod webhook refuses
any id outside the block, and refuses every pod of a namespace that has no block yet. Today every
workspace of every user runs as uid 1234; after this RFC, `dev-ws-batleforc` runs as 10000 and
`dev-ws-batleforc-test` as 10100, on their volumes, in their processes, and in any in-container
log that records a uid. Under user namespaces KubeArmor reports the host-mapped uid instead (V-07
measured `1094909952`) [R46], so for KubeArmor events the attribution gain is nil there; it covers
files and in-container logs.

It is a new feature, a crate pair `weebo-si-pod-identity` + `weebo-si-pod-identity-adapters`,
independent of `podSecurity` ([RFC 0013](./0013-pod-security.md)), and it works with and without
user namespaces (`hostUsers: false`), which it does not set.

### Before / after

```text
# before: two users, one identity               # after: one block per namespace
dev-ws-batleforc       $ id                     dev-ws-batleforc       $ id
uid=1234 gid=0(root) groups=0(root),1234        uid=10000 gid=10000 groups=10000
dev-ws-batleforc-test  $ id                     dev-ws-batleforc-test  $ id
uid=1234 gid=0(root) groups=0(root),1234        uid=10100 gid=10100 groups=10100
```

```mermaid
flowchart LR
  subgraph before["Before"]
    DWO1["DWO v1.1.1<br/>podSecurityContext default<br/>runAsUser 1234, fsGroup 1234"] --> P1["pod in dev-ws-A<br/>uid 1234"]
    DWO1 --> P2["pod in dev-ws-B<br/>uid 1234"]
  end
  subgraph after["After"]
    DWO2["DWO v1.1.1<br/>same default"] --> M["/mutate/v1/pods/identity<br/>rewrite into the block"]
    M --> V{"/validate/v1/pods/identity<br/>every id inside the block?"}
    V -- "yes" --> PA["dev-ws-A uid 10000<br/>dev-ws-B uid 10100"]
    V -- "no, or no block" --> R["REFUSED"]
  end
```

The pod DevWorkspace Operator builds is **rewritten** at the pod level; a container that asks for
an id outside its namespace's block is **refused**.

## Motivation

1. **Every workspace runs as the same uid.** DevWorkspace Operator v1.1.1's Kubernetes default
   pod security context is `runAsUser: 1234`, `runAsGroup: 0`, `fsGroup: 1234` [R16], and the
   pinned DWOC sets no `podSecurityContext` [R24], so that default is what every workspace pod
   gets. *Falsifiable*: `id` in a workspace of `dev-ws-batleforc` and of `dev-ws-batleforc-test`
   prints the same `uid=1234`.
2. **Unix permissions separate nothing between two users.** A file written by one workspace
   belongs to the same uid as every other workspace's files: on any volume two pods could share,
   in any node path a process reaches after an escape. *Falsifiable*: after an escape (T-30) or
   on a shared mount, uid 1234's files are writable by every other workspace.
3. **A uid in a log does not say which namespace acted.** Node-side records (kernel audit,
   process accounting, files left on the node) carry a uid and nothing else; 1234 names every
   workspace at once. KubeArmor events already carry the namespace; under `hostUsers: false`
   they report the host-mapped uid, not the block (V-07 [R46], Q5), so the gain is for files and
   in-container records, and for node-side records only while user namespaces are off.
   *Falsifiable*: a node-side record with uid 1234 cannot be attributed.
4. **The fix cannot come from the DWOC.** One DWOC serves every namespace [R24], and a single
   value there gives the same uid everywhere again. DWO merges a DWOC's `podSecurityContext` onto
   its default with a strategic merge patch [R17], so even an empty one keeps 1234.
5. **The plan's own example range breaks user namespaces.** With `hostUsers: false` only ids
   0–65535 inside the pod are valid [R20]; the OpenShift-style `1010000/10000` from the plan [R28]
   would make every file owned by the overflow id and unmodifiable. Phase 5 of the plan turns
   user namespaces on later [R28], so the range must already fit.

**Outcome we are buying:** two workspace namespaces never share a uid or a gid, every pod in a
workspace namespace runs inside its namespace's block however it was created, a namespace without
a block runs nothing, and the block is the same for the namespace's whole life.

## Goals and non-goals

**Goals:** one stable, non-overlapping block per workspace namespace; every pod in scope runs
inside it; fail closed; `Off`, `DryRun`, `Enforce` independent of the PSA level.

**Non-goals:**

- **Setting `hostUsers: false`.** A DWOC field, owned by `dwocPin` and the pinned DWOC, decided
  in phase 5 [R28]. This RFC must work with and without it.
- **Choosing the PSA level.** `restricted` is RFC 0013's and V-10's call; this feature only sets
  `runAsNonRoot: true`, which `restricted` also needs.
- **Chowning existing volumes.** That needs a root container writing into user volumes, the
  opposite of the plan; migration is a runbook (*Operational considerations*).
- **Per-team ranges, or a block size per namespace.** One grid for the cluster; nothing asks for
  more.
- **Pods outside workspace namespaces.** The webhooks select on
  `hardening.weebo.io/workspace-namespace`, like every Pod webhook of this repo [R6][R7].
- **OpenShift.** The SCC already allocates a range per namespace (`openshift.io/sa.scc.uid-range`)
  [R28]; leave the feature `Off` there.
- **A new CLI command.** `kubectl` reads the annotation; see *Mocks*.
- **Changing `passwd-append`.** Without gid 0 it cannot write `/etc/passwd` and becomes a
  no-op with an expected `WARN` on this path [R14][R37]; the passwd entry comes from nss_wrapper
  in WeeboDevImage, chosen by V-27 (Q3, L12).

## Guide-level explanation

The feature starts `Off`. The admin adds one block to the `WeeboSiConfig`:

```yaml
spec:
  features:
    podIdentity:
      mode: DryRun
      namespaceSelector:          # the rollout knob: the test namespace first
        matchLabels:
          kubernetes.io/metadata.name: dev-ws-batleforc-test
      range:
        start: 10000              # first id handed out; 0 is never in a block
        end: 65535                # exclusive; must be <= 65536 (user namespaces)
        blockSize: 100            # ids per namespace; (65535-10000)/100 = 555 blocks
      grantGroupZero: false       # last resort, see below; true grants write on every
                                  # group-0-writable (g=u) file of every workspace image
```

There is no team block: a team does not change which ids a namespace gets.

**What the controller does.** For each namespace in the feature's scope that carries
`hardening.weebo.io/workspace-namespace` and has no `hardening.weebo.io/uid-range`, it picks the
lowest block that overlaps no block any other namespace holds and writes the annotation, in
`DryRun` as in `Enforce` (L5): the annotation is inert while the webhooks are not enforcing, and
writing it in `DryRun` is what lets `DryRun` measure real rewrites instead of 100 % "no block".
Allocations are serialised in the controller process (L1). A namespace that already has a block
keeps it, forever: the controller never rewrites one. Changing `range` or `blockSize` while blocks
are held is refused (L6). The user namespaces are created by GitOps (`2.helm/user-app`) [R27],
long before Che starts a workspace in them, so the block is there first.

**What the webhooks do, for a pod created in a workspace namespace:**

| Pod | Result |
| --- | --- |
| DWO's workspace pod, `runAsUser: 1234`, `runAsGroup: 0` at pod level | rewritten: `runAsUser`, `runAsGroup`, `fsGroup` = block start, `fsGroupChangePolicy: OnRootMismatch`, `supplementalGroupsPolicy: Strict`; no gid 0 anywhere (unless `grantGroupZero: true`, which adds `0` to `supplementalGroups`) |
| pod-level id already inside the block | kept; `fsGroupChangePolicy` and `supplementalGroupsPolicy` set as above |
| no pod-level `securityContext` at all | filled the same way, plus `runAsNonRoot: true` |
| a container (init, regular or ephemeral) with `runAsUser`/`runAsGroup` outside the block | **refused** |
| a container id inside the block (a sidecar wanting its own uid) | allowed |
| `supplementalGroups` entry outside the block (`0` included, unless `grantGroupZero: true`) | **refused** |
| `supplementalGroupsPolicy` other than `Strict` | **refused** (under `Merge`, the image's `/etc/group` can add groups) |
| namespace without a block, or with a malformed one, or in conflict, or range exhausted | **refused**, one message per case (L11) |
| pod UPDATE (labels, finalizers, ownerReferences) of a pod already running | allowed; only what the UPDATE adds is checked, i.e. new ephemeral containers (L3) |
| namespace outside the feature's scope, or `mode: Off` | untouched, as today |

**Why the pod level is rewritten rather than refused.** DWO always sends `runAsUser: 1234` [R16]
[R17]; refusing it would refuse every workspace. The pod-level identity belongs to the namespace,
so the webhook writes it. What a pod adds on top, per container, is checked and refused.

**No gid 0, and where the passwd entry comes from.** DWO's default puts every workspace in gid 0
[R16]. Images built for arbitrary uids, Che's and Weebo's, make `/etc/passwd`, `/etc/group` and
the home writable by gid 0, "the only identity we are sure to have" [R14]: whoever holds gid 0
can rewrite them. This feature drops gid 0: the primary group is the block's, and no
supplementary 0 is added. The price is that `passwd-append` can no longer write `/etc/passwd`; it
logs `WARN … is not writable, leaving it unchanged` and exits 0 [R37], a no-op on this path. The
arbitrary uid's entry then has to come from somewhere else. The upstream test **V-27** weighed
three mechanisms; it ran on 2026-11-24 on runc and settled the choice: **nss_wrapper** [R39].

1. **The runtime adds it at container start.** CRI-O does: when the uid has no entry and the
   image's `/etc/passwd` is group- or other-writable, it generates a passwd file with the entry
   and bind-mounts it over `/etc/passwd` [R36], from outside the container, so the process needs
   no gid 0 (this is the Red Hat behaviour seen in recent tests). containerd 2.3.7 has no
   equivalent in its source: it only reads `/etc/passwd` to resolve a uid, and falls back to the
   bare uid with gid 0 when there is none [R35]. **V-27 on runc: no entry.** In the real workspace
   image (`che-min-mise:main`, `/etc/passwd` `-rw-rw-r--+ root root`) with uid and gid 54321,
   `id` prints `cannot find name for user ID 54321`, `/etc/passwd` has no `:54321:` line and
   `whoami` fails [R39]. youki, run the same day, gives the same result (no entry) [R39]. youki
   cannot run user-namespaced pods at all: V-06 fails with `FailedCreatePodSandBox … RuntimeClass
   handler "youki" does not support user namespaces`, because `youki features` reports
   `mountExtensions.idmap.enabled: false` and containerd's `supportsCRIUserns` reads it [R45].
2. **nss_wrapper in WeeboDevImage — the chosen mechanism** (the other Red Hat/OpenShift
   pattern). It needs a WeeboDevImage change, listed under *Integration in weebo-si*.
   The entrypoint writes a passwd and a group file into a writable emptyDir or the home and runs
   with `LD_PRELOAD=libnss_wrapper.so`, `NSS_WRAPPER_PASSWD` and `NSS_WRAPPER_GROUP` pointing at
   them [R38]. `getpwuid`, `whoami`, `git`, `ssh` resolve; no group membership is needed.
   Processes that clear `LD_PRELOAD` or are statically linked do not see the entry.
   Containers not built from WeeboDevImage (`che-browser`, postgres, UDI) get no nss_wrapper and
   lose name resolution (`whoami`, `id -un`) without gid 0; V-28 showed they still run (Chrome
   with 0 restarts, postgres and dex with `HOME=/`) [R43].
3. **`grantGroupZero: true`** (last resort, default `false`). Adds `0` to `supplementalGroups`
   so `passwd-append` works as on OpenShift. Its field doc says plainly: it grants write on every
   `g=u` file of every workspace image (`/etc/passwd`, `/etc/group`, the home), and every
   namespace shares that group again.

**Existing pods** keep running as 1234 until they restart: admission runs at creation only.

### Validation

| Check | Kind | Where it is seen |
| --- | --- | --- |
| `start >= 1`, `start < end`, `end <= 65536`, `1 <= blockSize <= 65535`, `end - start >= blockSize` | hard error, CEL on the CRD | `kubectl apply` refuses the `WeeboSiConfig` |
| `range` or `blockSize` changed while blocks are held | config rejected for allocation | feature state `Degraded` in `status.features[]` with the message `range changed while N blocks are held; allocation suspended`, and the config's `Degraded` condition (reason `InvalidConfiguration`) [R47]; webhooks keep enforcing the held blocks (L6) |
| range exhausted: a namespace in scope gets no block | warning | feature state stays `Active`/`DryRun`, the warning goes in the feature's `message` [R47]; metric `weebo_si_pod_identity_blocks{state="free"}` = 0; alert |
| two namespaces carry overlapping blocks | warning | feature `message` names both namespaces (admins only read the status); the younger one's pods are refused by the webhook itself (L8); alert |
| a namespace allocated late while it already holds PVCs (Q8) | warning | feature `message`, log `result=allocated_late`, counter `allocations_total{result="allocated_late"}` |
| `start < 10000` | warning | feature `message`: image users (UDI's 10001, distro users below 1000) may collide |
| `grantGroupZero: true` | warning | feature `message` for as long as it is on, and log `result=group_zero_granted` at each pod: an opt-in that weakens the default is never silent |

There is one `Degraded` condition on a `WeeboSiConfig`, reason `InvalidConfiguration`, and a
feature's own state `Degraded` means "configuration rejected" [R47]; every warning above leaves
the feature `Active` (or `DryRun`) and goes in its `message`, as image-rewrite does [R47] (L4).
Both are in ClickStack through the controller logs.

### Mocks

The allocation, as the admin reads it (nominal, one namespace in scope during the pilot):

```text
$ task k -- get ns -l hardening.weebo.io/workspace-namespace \
    -o custom-columns='NAME:.metadata.name,UID-RANGE:.metadata.annotations.hardening\.weebo\.io/uid-range'
NAME                    UID-RANGE
dev-ws-batleforc        <none>
dev-ws-batleforc-test   10000/100
```

The same command before `Enforce` prints `<none>` on every row (empty state). It decides that no
CLI is needed.

The feature's status, nominal, with a warning, and with allocation suspended:

```text
$ task k -- get weebosiconfig cluster -o jsonpath='{.status.features[?(@.name=="podIdentity")]}' | jq
{ "name": "podIdentity", "state": "DryRun", "message": "configuration valid" }
{ "name": "podIdentity", "state": "Active",
  "message": "range exhausted: 1 namespace in scope has no block" }
{ "name": "podIdentity", "state": "Degraded",
  "message": "range changed while 2 blocks are held; allocation suspended" }
$ task k -- get weebosiconfig cluster -o jsonpath='{.status.conditions[0].reason}'
InvalidConfiguration                      # only in the third case
```

`DryRun` logs (the annotation is written, nothing is patched or refused):

```text
INFO  feature=pod-identity mode=DryRun ns=dev-ws-batleforc-test result=allocated block=10000/100
INFO  feature=pod-identity mode=DryRun ns=dev-ws-batleforc-test resource=Pod name=workspace4f…-7d9c result=would_rewrite from=1234/0/1234 to=10000/10000/10000
WARN  feature=pod-identity mode=DryRun ns=dev-ws-batleforc-test resource=Pod name=workspace4f…-7d9c result=would_refuse container=tools runAsUser=1234
```

The refusal, a container asking for 1234 through a devfile `container-overrides` attribute, as
it lands on the workspace's ReplicaSet and in the DevWorkspace status:

```text
$ task k -- get events -n dev-ws-batleforc-test --field-selector reason=FailedCreate
Warning  FailedCreate  replicaset/workspace4f…-7d9c  Error creating: admission webhook
  "pod-identity-validate.hardening.weebo.io" denied the request: container "tools":
  securityContext.runAsUser=1234 is outside this namespace's block 10000-10099
```

The same with a direct pod, as an admin (exit code 1):

```text
$ task k -- run -n dev-ws-batleforc-test probe --image=<angos image> --restart=Never \
    --overrides='{"spec":{"containers":[{"name":"probe","image":"<angos image>","securityContext":{"runAsUser":0}}]}}'
Error from server (Forbidden): admission webhook "pod-identity-validate.hardening.weebo.io"
  denied the request: container "probe": securityContext.runAsUser=0 is outside this namespace's
  block 10000-10099
```

The three "no usable block" cases get distinct messages, because they call for different
actions (L11). No block yet (transient; the ReplicaSet retries):

```text
Error creating: admission webhook "pod-identity-validate.hardening.weebo.io" denied the request:
  namespace dev-ws-new has no UID block yet; one is allocated within seconds of the namespace's
  creation, so this is retried automatically
```

Range exhausted (an admin must act):

```text
Error creating: admission webhook "pod-identity-validate.hardening.weebo.io" denied the request:
  no UID block is left for namespace dev-ws-new; ask an admin to widen the range
```

Malformed annotation (an admin hand-edited it):

```text
Error creating: admission webhook "pod-identity-validate.hardening.weebo.io" denied the request:
  this namespace's UID block annotation "10000-100" is not valid; ask an admin (runbook:
  pod-identity)
```

A namespace in conflict. The message names no other namespace: a namespace name is a username
(*Data and privacy*); the controller log names both for the admin:

```text
Error creating: admission webhook "pod-identity-validate.hardening.weebo.io" denied the request:
  this namespace's UID block 10000/100 is also held by another namespace; an admin must resolve
  it (runbook: pod-identity)
```

What a user sees if `Enforce` lands before the nss_wrapper image (which is why that image is an
`Enforce` checklist item, *Integration in weebo-si*):

```text
I have no name!@workspace4f…:/projects$ whoami
whoami: cannot find name for user ID 10100
```

What a user sees before the migration runbook ran on a volume written as 1234 (`fsGroup` made the
key group-readable, ssh refuses it):

```text
$ git fetch
Bad owner or permissions on /home/user/.ssh/config
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
Permissions 0660 for '/home/user/.ssh/id_ed25519' are too open.
```

## Design

### Contract

#### `spec.features.podIdentity`

| Field | Rust-ish type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | `Mode` (`Off`\|`DryRun`\|`Enforce`) | — | required, per the chassis |
| `namespaceSelector` | `Option<Selector>` | none | per the chassis |
| `range.start` | `u32` | `10000` | first id of the first block |
| `range.end` | `u32` | `65535` | exclusive; CEL `<= 65536` |
| `range.blockSize` | `u32` | `100` | ids per block; configurable only before the first allocation: changing it, or `start`/`end`, while blocks are held suspends allocation (Q6, L6) |
| `grantGroupZero` | `bool` | `false` | add `0` to `supplementalGroups`; grants write on every `g=u` file of the image (Q3) |

`Features` gains `pub pod_identity: Option<PodIdentityConfig>` beside `pod_security` [R1].

#### Namespace annotations (written by the controller only)

| Key | Value | Meaning |
| --- | --- | --- |
| `hardening.weebo.io/uid-range` | `<start>/<size>`, decimal, e.g. `10000/100` | the block; never rewritten |
| `hardening.weebo.io/uid-range-conflict` | `true` | level-based: set while an older namespace holds an overlapping block, removed when none does; informational, the webhook decides from its own index (L8) |

Parse rule (one function, `UidBlock::parse`, table-tested, L15): two decimal `u32` without sign
or leading `+`, `size >= 1`, `start >= 1`, `start + size <= 65536`. Anything else is a malformed
block, refused with its own message.

#### Webhooks

| Name | Path | Rules | `failurePolicy` | Notes |
| --- | --- | --- | --- | --- |
| `pod-identity-mutate.hardening.weebo.io` | `/mutate/v1/pods/identity` | `pods` CREATE | `Fail`, fixed | `reinvocationPolicy: IfNeeded`; never denies |
| `pod-identity-validate.hardening.weebo.io` | `/validate/v1/pods/identity` | `pods` CREATE, UPDATE; `pods/ephemeralcontainers` UPDATE | `Fail`, fixed | the gate; on UPDATE only what differs from `oldObject` (L3) |

Both: `namespaceSelector` `hardening.weebo.io/workspace-namespace Exists` and
`hardening.weebo.io/exclude DoesNotExist`, as the existing Pod webhooks [R6][R7]; no
`objectSelector` (a pod label is user-writable [R7]). Chart value
`podIdentity.webhooks.enabled` (default **`false`**, L7) registers them: the admin turns them on
once the release that serves the paths is running, so no upgrade ever registers a path old pods
answer 404 to [R8].

#### Metrics

| Metric | Labels | Meaning |
| --- | --- | --- |
| `weebo_si_pod_identity_blocks` (gauge) | `state` = `allocated`\|`free`\|`conflict` | bounded, no namespace label |
| `weebo_si_pod_identity_allocations_total` | `result` = `allocated`\|`allocated_late`\|`conflict`\|`exhausted`\|`suspended`\|`error` | controller |
| `weebo_si_pod_identity_refusals_total` | `reason` = `outside_block`\|`no_block`\|`exhausted`\|`malformed`\|`conflict`\|`policy` | webhook; the source of the alerts that must survive a controller outage (L9) |
| `weebo_si_admission_requests_total`, `weebo_si_admission_duration_seconds` | existing, `feature="pod-identity"` | the chassis's own [R2] |

No exit code changes; `weebo-si-operator features` lists `pod-identity` (RFC 0018, `Namespace,
Pod`) [R29].

### Architecture

**Hexagonal: yes.** All three criteria of `hexagonal.md` hold: a real decision (the allocation,
in/out of block, conflict), the Kubernetes API, and both wanted tested without it. The fake
namespace store is smaller than the real one.

- `crates/weebo-si-pod-identity` (domain): `UidBlock`, `Grid`, `allocate(grid, held) ->
  Option<UidBlock>` (lowest free), `NamespaceSubject` + `PodIdentityAllocation:
  ReconcileFeature` [R3], `PodSubject` + `PodIdentityMutation: Feature` and
  `PodIdentityValidation: Feature` returning `Decision` [R2]. Port: `UidRangeStore` (list held
  blocks fresh, write one annotation with a precondition). Features see only their subject and
  `Context`: the adapter reads `uid-range` and the webhook's conflict verdict into `PodSubject`.
- `crates/weebo-si-pod-identity-adapters`: `KubeUidRangeStore`, the controller loop, the metrics,
  and `admission_routes()` with the two handlers, merged in the composition root beside
  image-policy's [R30].

**Why its own two paths, not the existing Pod routes.** `/mutate/v1/pods` already exists: it is
RFC 0017's image rewrite, which never denies, accepts `UPDATE` and takes its `failurePolicy` from
the admin-chosen `imagePolicy.podWebhook.failurePolicy` [R5][R6][R8]. `/validate/v1/pods` takes
the same value [R7]. A second registry on either would make this identity check fail open the
day an admin sets `Ignore` for images. RFC 0017 met the same choice on DevWorkspaces and gave its
rewrite its own path beside dwoc-pin's [R15]; this follows it. (This deviates from the
coordinator's draft, see Q2.)

```mermaid
graph LR
  subgraph ctrl["controller (leader only)"]
    RF["PodIdentityAllocation<br/>ReconcileFeature"] --> ST["KubeUidRangeStore<br/>fresh LIST + guarded patch"]
  end
  subgraph wh["webhook (read-only RBAC)"]
    MU["/mutate/v1/pods/identity<br/>PodIdentityMutation"]
    VA["/validate/v1/pods/identity<br/>PodIdentityValidation"]
    AD["adapter: reads uid-range + overlap index<br/>into PodSubject"]
    NV["KubeNsStore<br/>(NamespaceView)"]
    AD --> NV
    MU --> AD
    VA --> AD
  end
  ST -- "writes uid-range" --> NS[("Namespace<br/>annotations")]
  NS -- "watched" --> NV
```

The graph proves the single-writer rule: only the controller writes the annotation, the webhook
only reads it through the namespace watch it already has [R9], so the webhook gains no RBAC.

```mermaid
sequenceDiagram
  participant Argo as Argo CD (user-app)
  participant API as kube-apiserver
  participant C as controller (leader)
  participant Che as Che / DWO v1.1.1
  participant W as webhook
  Argo->>API: create Namespace dev-ws-x (workspace-namespace=true)
  API-->>C: watch event
  Note over C: allocation mutex held
  C->>API: LIST workspace namespaces (fresh)
  C->>API: patch uid-range=10200/100 (resourceVersion precondition)
  C->>API: LIST again, release on overlap
  Note over Che: minutes or days later
  Che->>API: create Deployment, ReplicaSet creates Pod (runAsUser 1234)
  API->>W: /mutate/v1/pods/identity
  W-->>API: patch runAsUser/runAsGroup/fsGroup=10200
  API->>W: /validate/v1/pods/identity
  W-->>API: allowed
```

The sequence proves the ordering the fail-closed rule relies on: the block exists before any pod,
because the namespace is created by GitOps well before Che uses it [R27].

```mermaid
flowchart TD
  A["namespace in scope,<br/>workspace-namespace label"] --> B{"carries uid-range?"}
  B -- "yes" --> D{"an older namespace<br/>holds an overlapping block?"}
  D -- "no" --> OK["remove uid-range-conflict if set"]
  D -- "yes" --> X["set uid-range-conflict=true<br/>message, alert"]
  B -- "no" --> L["take the allocation mutex"]
  L --> E["fresh LIST, held = all parsed blocks"]
  E --> F{"lowest block overlapping none?"}
  F -- "none" --> G["exhausted: message, alert"]
  F -- "found" --> H["patch with resourceVersion<br/>precondition"]
  H --> R{"re-LIST: an older holder<br/>overlaps it?"}
  R -- "yes" --> U["remove own annotation, retry"]
  R -- "no" --> OK2["done, release the mutex"]
```

**Invariant:** *because the controller is the only writer, runs on the leader alone [R10],
serialises every allocation behind one process-wide mutex (kube-runtime reconciles different
namespaces concurrently [R48], so the lease alone is not enough), computes from a fresh LIST
rather than its cache, and re-LISTs after writing, two namespaces cannot be given overlapping
blocks by this operator; an overlap can only come from outside (a restored namespace, a hand
edit), and then the webhook, from its own index, refuses the younger namespace's pods
("younger" = later `creationTimestamp`, ties broken by name).*

### Data and state

- **State:** the annotation on each namespace. No ConfigMap, no CR, no cache of its own. The
  free list is recomputed from a LIST at each allocation (≤ 555 objects).
- **Lost:** a namespace deleted takes its block with it; the block is free for the next
  namespace (lowest free, Q4). An annotation removed by hand makes the controller
  allocate again, possibly a different block: the PVC's files then belong to the old uid
  (Q8).
- **`DryRun`:** writes the annotations too (L5); they are inert while the webhooks are not
  `Enforce`.
- **Stale:** the webhook reads the namespace through its watch; in the seconds between the
  controller's write and the watch event, pods of that namespace are refused and the ReplicaSet
  retries. Backup and restore: the annotation travels with the namespace in any backup of the
  Namespace object; a restored copy next to its original is the conflict case.
- **`Off`:** no allocation, no mutation, no refusal. The annotations stay: they are inert
  without the webhooks, and removing them would hand a block that files already carry to the
  next namespace. This is the one point where `Off` is not a full teardown, argued in
  *Operational considerations*.

### Detailed design

| File | Change |
| --- | --- |
| `crates/weebo-si-crd/src/spec.rs` | `Features::pod_identity` [R1]; new `crates/weebo-si-crd/src/pod_identity.rs`: `PodIdentityConfig`, `UidRangeConfig` with CEL rules |
| `crates/weebo-si-pod-identity/src/model/block.rs` | `UidBlock { start: u32, size: u32 }`, `parse`, `contains(u32)`, `Display` |
| `crates/weebo-si-chassis/src/mutation.rs`, `crates/weebo-si-webhook/src/render.rs` | two `Mutation` variants, `SetInt { path, value: i64 }` and `SetIntList { path, values: Vec<i64> }`, and their `render_patch` arms (L2). Today `Mutation` is `SetConfigRef`, `Annotate`, `SetString`, string-only on purpose [R49]: uids, gids and `fsGroup` are integers, and a string would be refused by the apiserver; the widening is still a field set at a path, never structure |
| `crates/weebo-si-crd/src/{spec,pod_identity}.rs`, `crates/weebo-si-runtime/src/config_store.rs` | `ResolvedFeatures` gains `pod_identity`, and `config_store.rs` a `pod_identity` handle beside `pod_security` [R50] |
| `crates/weebo-si-runtime/src/ns_store.rs`, `crates/weebo-si-chassis/src/port/namespace_view.rs` | `NamespaceView::holders(key) -> Vec<(NamespaceName, Time, String)>`, a scan of the reflector store like `annotated_anywhere` [R51]: the webhook's overlap index (L8) |
| `crates/weebo-si-pod-identity/src/model/grid.rs` | `Grid::from(&UidRangeConfig)`, `allocate(&self, held: &[UidBlock]) -> Option<UidBlock>` (overlap test, not equality), `overlaps(UidBlock, UidBlock) -> bool` |
| `crates/weebo-si-pod-identity/src/feature/allocation.rs` | `PodIdentityAllocation`, `desired()` = `Allocate(UidBlock)` \| `Keep` \| `Conflict` \| `Exhausted` |
| `crates/weebo-si-pod-identity/src/feature/pod.rs` | `PodIdentityMutation::evaluate` (mutations on `/spec/securityContext/*`), `PodIdentityValidation::evaluate` (walks `containers`, `initContainers`, `ephemeralContainers`, pod level, `supplementalGroups`) |
| `crates/weebo-si-pod-identity/src/port.rs` | `UidRangeStore` |
| `crates/weebo-si-pod-identity-adapters/src/{store,controller,admission,metrics}.rs` | the adapters; `KubeUidRangeStore` holds the allocation `tokio::sync::Mutex` (L1); `admission_routes(&shared)` |
| `crates/weebo-si-operator/src/{webhook_cmd,controller_cmd,features}.rs` | composition root: merge routes [R30], start the loop, register the descriptor [R29] |
| `charts/weebo-si-operator/templates/mutatingwebhookconfiguration.yaml`, new `validatingwebhookconfiguration-identity.yaml` | the two webhooks |
| `charts/weebo-si-operator/templates/rbac.yaml`, `values.yaml` | `podIdentity.rbac.enabled` (controller `patch namespaces`, as RFC 0013 [R11], and `list persistentvolumeclaims` for Q8's late-allocation check), `podIdentity.webhooks.enabled` (default `false`) |

**DWO's other pods.** The PVC cleanup Job, the async-storage Deployment and the backup CronJob all
copy the workspace `podSecurityContext` [R18], so they arrive with `runAsUser: 1234` and are
rewritten into the block like the workspace pod. That is what they need: the cleanup Job deletes
files the workspace (block uid) wrote. Files still owned by 1234 from before the migration are
deletable through the group, since `fsGroup` re-groups the volume on mount. The e2e suite
asserts that a cleanup Job completes (observation 6 below).

**DWO's own override restrictions** refuse `runAsUser=0` in `pod-overrides` and
`container-overrides` on Kubernetes [R19]. Confirmed live on 2026-11-24: the DWO controller logs
the resolved configuration on every reconcile, and it carries
`restrictedPodOverrideFields=[hostNetwork=true, hostPID=true, hostIPC=true,
securityContext.runAsNonRoot=false, securityContext.runAsUser=0, volumes.hostPath]` and
`restrictedContainerOverrideFields=[securityContext.privileged=true,
securityContext.runAsNonRoot=false, securityContext.runAsUser=0,
securityContext.allowPrivilegeEscalation=true, securityContext.procMount=Unmasked,
securityContext.capabilities.add]` [R44]. That is a layer in front of ours, not a substitute: it
does not see 1234 or another namespace's block, it does not see pods DWO did not build, and it is
a DWO default that a DWOC or a DWO upgrade can change — which is why `/validate/v1/pods/identity`
still refuses out-of-block ids itself. V-28 also showed [R43] that a non-zero uid such as 10100 passes
these restrictions through `pod-overrides`, so the workspace's own token (which can patch its
DevWorkspace) can pick any non-root uid today, until this RFC's Pod mutation rewrites it.

### Proof against a real client

**Consumers, pinned:** Che dashboard `ghcr.io/weebo-si/che-dashboard:develop` (floating tag: the
run records the image digest), DevWorkspace Operator `v1.1.1` (commit `bdd4530`) [R16],
`kubectl` against Kubernetes 1.36.2, containerd 2.3.7 [R25]; and the kind + Che e2e cluster of
`crates/weebo-si-e2e`.

1. **Allocation.** With the feature scoped to both namespaces, the mock command prints one of
   `10000/100` and `10100/100` on each (which one depends on reconcile order), and
   `weebo_si_pod_identity_blocks{state="allocated"}` reads 2. Below, `B` is the block
   `dev-ws-batleforc-test` got and `B'` the other one.
2. **Two identities, no gid 0.** A workspace started from the dashboard in each namespace: `id`
   prints `uid=10000 gid=10000 groups=10000` in one and `uid=10100 gid=10100 groups=10100` in the
   other; `test -w /etc/passwd` fails; `whoami` answers in both through nss_wrapper (`echo
   $LD_PRELOAD` names `libnss_wrapper.so`); the workspace log shows passwd-append's `WARN … is not
   writable` [R37].
3. **Refusals, three ids.** A devfile with `container-overrides` setting `runAsUser` to `1234`,
   then to `70000`, then to `B'`'s first id in `dev-ws-batleforc-test`: each workspace stays
   `Starting`, and the ReplicaSet event carries the mock's message with `B`'s bounds,
   `securityContext.runAsUser=1234 is outside this namespace's block <B>`. A
   direct pod with container-level `runAsUser: 0` as admin exits 1 with the same message. No pod
   object exists afterwards (`get pod probe` → `NotFound`): the refused pod never ran.
4. **Volume ownership.** In a fresh workspace, `touch /projects/x && ls -n /projects/x` prints
   `B`'s first id as owner and group.
4b. **UPDATE of a running 1234 pod.** `kubectl label pod <pre-Enforce pod> x=y` succeeds: an
   UPDATE that adds no ephemeral container is not refused (L3).
5. **No block, no pod.** A namespace created with the label while the controller is scaled to 0:
   a pod creation is refused with the "no UID block yet" message; once the controller is back,
   the ReplicaSet's next retry is admitted.
6. **DWO's cleanup Job.** Deleting a workspace runs DWO's PVC cleanup Job; its pod shows
   `runAsUser: 10100` and the Job completes.
7. **Annotation is not the user's.** `kubectl annotate ns dev-ws-batleforc-test
   hardening.weebo.io/uid-range=10000/100 --overwrite` as `labsso:batleforc-test@weebo.internal`
   is `Forbidden` [R22] (T-12).
8. **V-27, the passwd entry (run 2026-11-24, runc).** A pod in `dev-ws-batleforc-test`, image
   `che-min-mise:main` (its `/etc/passwd` is `g=u`), `runAsUser: 54321`, `runAsGroup: 54321`, no
   gid 0, no nss_wrapper: `id` → `cannot find name for user ID 54321`, `grep :54321:
   /etc/passwd` → nothing, `whoami` → `No such id: 54321` [R39]. Result: **FAIL on runc, no
   entry**, so containerd provides nothing and nss_wrapper is required; youki gives the same
   (run `20261124-084858`: `runc=absente youki=absente`) [R39]. To repeat with the nss_wrapper
   image once built: `whoami` prints the name.

**Suites:** e2e `crates/weebo-si-e2e/tests/pod_identity.rs` (observations 1–6 and 4b on kind +
Che);
envtest cases in `crates/weebo-si-operator/tests/admission_envtest.rs`. **Cluster ids:** T-11
(obs. 3), T-12 (obs. 7), V-05 (obs. 2 and 4 repeated with `hostUsers: false` on runc), V-06
(youki cannot run them, [R45]), V-07 (KubeArmor reports the host-mapped uid [R46]), V-10 (no `restricted` warning caused by this
feature), T-30 (inventory shows the block uid), T-10 (webhook down → refused) [R28], and the
new upstream test V-27 (obs. 8: runc and youki, FAIL = no entry) [R39].

**Deliberately untouched:**

- `hostUsers`, the DWOC and the CheCluster: no field set by this feature.
- RFC 0017's `/mutate/v1/pods` and RFC 0005's `/validate/v1/pods`, their handlers and their
  `failurePolicy` value.
- The DevWorkspace routes and `pod-overrides`: nothing is written into a DevWorkspace.
- PSA labels (RFC 0013), KubeArmor policies (RFC 0006), network policies (RFC 0004).
- `bins/passwd-append`: unchanged, a no-op on this path without gid 0.
- Existing PVC contents: no chown, no Job, no init container from the operator.
- Pods outside namespaces labelled `hardening.weebo.io/workspace-namespace`.

## Security considerations

**Rating:** High — two new admission webhooks on every workspace pod, at `Fail`, and an
allocation whose error would give two users the same identity.

```mermaid
flowchart LR
  subgraph user["Untrusted: user, workspace token, devfile"]
    U1["DevWorkspace + overrides"]
    U2["kubectl debug (ephemeral)"]
  end
  subgraph cp["Control plane"]
    API["kube-apiserver"]
  end
  subgraph op["Trusted: weebo-si-hardening"]
    WH["webhook (read-only)"]
    CT["controller (patch namespaces)"]
  end
  subgraph adm["Admin only"]
    NSA["Namespace annotations / labels"]
  end
  U1 -- "via DWO" --> API
  U2 --> API
  API -- "AdmissionReview (attacker-shaped pod)" --> WH
  CT -- "writes uid-range" --> NSA
  NSA -- "read" --> WH
```

The pod body is attacker-shaped; the namespace annotation is trusted because only an admin and
the operator can write it [R22].

| # | Threat | Where | Mitigation + enforcing fn | Negative test | Residual |
| --- | --- | --- | --- | --- | --- |
| 1 | E: container asks for uid 0, 1234 or another block | devfile `container-overrides`, direct pod | `PodIdentityValidation::evaluate` refuses any container `runAsUser`/`runAsGroup` outside the block | `container_uid_outside_block_is_refused` (0, 1234, other block, 70000) | none |
| 2 | E: ephemeral container with a foreign uid | `kubectl debug`, `pods/ephemeralcontainers` UPDATE | same fn, rule covers the subresource | `ephemeral_container_outside_block_is_refused` | none |
| 3 | E: pod-level id outside the block survives | a later mutating webhook, reinvocation | mutation rewrites; validation (runs after all mutations) refuses pod-level ids outside | `pod_level_outside_block_refused_when_unmutated` | none |
| 4 | E: join another block's files by group | `supplementalGroups`, `fsGroup` | validation: entries in block only (`0` refused unless opted in); `supplementalGroupsPolicy: Strict` set and required, so the image's `/etc/group` adds nothing (L14) | `supplemental_group_of_another_block_is_refused`, `group_zero_refused_by_default`, `merge_policy_is_refused` | none by default |
| 5 | T: user writes their own `uid-range` or `exclude` | namespace annotation/label | RBAC: neither user nor workspace SA can patch the namespace [R22] | T-12 | an admin hand-editing it (accepted) |
| 6 | T: duplicate block after a restore | namespace annotations | the webhook's own overlap index (`NamespaceView::holders`) refuses the younger namespace, whether or not the controller runs (L8) | `duplicate_block_refuses_the_younger_namespace` | the watch delay of the webhook's cache (seconds) |
| 7 | T: malformed annotation read as a block | parser | `UidBlock::parse`, strict; failure = malformed = refused | table test `uid_block_parse_cases`; `malformed_annotation_is_refused` | none |
| 8 | E: pod admitted before allocation | new namespace | validation refuses a namespace with no block; `NamespaceNotObserved` = deny, like `validate_pods` [R5] | `pod_in_namespace_without_block_is_refused` | none |
| 9 | D: webhook unavailable → no workspace pod starts | both webhooks at `Fail` | 2 replicas + PDB required before `Enforce` [R12]; selector limited to workspace namespaces | T-10; envtest `identity_webhooks_skip_excluded_namespaces` | outage of both replicas blocks workspaces (accepted, *Operational*) |
| 10 | I: refusal leaks another user's namespace | admission message | conflict message names no namespace | `conflict_message_names_no_other_namespace` | blocks are guessable, not secret |
| 11 | R: uid cannot be tied to a namespace in node logs | KubeArmor, node audit | one block per namespace, never shared at the same time | V-07 | under `hostUsers: false` node logs may show mapped host ids (Q5); a reused block names two namespaces at two times |
| 12 | E: two allocations race | controller | leader lease [R10] + process-wide allocation mutex (reconciles run concurrently [R48]), fresh LIST, `resourceVersion` precondition, re-LIST after write (L1) | envtest `n_namespaces_created_at_once_get_disjoint_blocks` | none within one operator |
| 13 | E/T: `grantGroupZero: true` — every workspace can rewrite its image's `/etc/passwd`, `/etc/group` and other `g=u` files, and gid 0 is shared across namespaces again | config opt-in | default `false`; `Degraded` while on; mutation adds `0` only when the flag is set | `group_zero_absent_unless_opted_in` | accepted by whoever sets the flag, recorded in the campaign page |
| 14 | S: a process without the nss_wrapper preload sees no passwd entry and falls back to the bare uid | nss_wrapper (mechanism 2) | identity is the uid itself, not the name; separation does not depend on the name | V-27 | tools that need a name and clear `LD_PRELOAD` fail (availability, not security) |
| 15 | E: an UPDATE refusal locks a running 1234 pod (no label, no finalizer removal) | pod UPDATE | validation checks only what the UPDATE adds (L3) | envtest `labelling_a_preexisting_1234_pod_is_allowed` | none |
| 16 | R/D: alerts go quiet when the controller is down | controller metrics | refusal counter emitted by the webhook; `absent()` on controller metrics (L9) | alert rule test in the runbook | none |

- **Privileges.** Controller: `patch namespaces` behind `podIdentity.rbac.enabled`, the same
  verb RFC 0013 and the KubeArmor feature already hold behind their own switches [R11]; RBAC
  cannot narrow it to one annotation key. Plus `list persistentvolumeclaims` for Q8 (names and
  counts only, no content). Webhook: nothing new; the namespace watch exists [R9].
- **Trust boundary.** The `AdmissionReview` pod is attacker-controlled (any field, any number of
  containers); the walk is bounded by the pod's own size limit. The annotation is admin-only.
- **Bypass.** `hardening.weebo.io/exclude` and the workspace label are admin-only (same probe);
  pods created before the webhook is registered keep 1234 until they restart (documented in the
  runbook: stop workspaces before `Enforce` and before each widening of the scope); UPDATE of
  pod-level ids is impossible (immutable), ephemeral containers are covered.
- **Blast radius.** A wrong allocation shares an identity between two users, the very thing this
  closes; a broken webhook stops workspace pods, never other namespaces'.
- **Secrets.** None read; no secret reaches a log.

## Supply chain

No new dependency in this repo: both crates use `kube`, `serde_json` and the chassis already in
`Cargo.lock`; the parser is covered by table tests, no fuzz infrastructure (L15). WeeboDevImage (outside this
repo) gains the distribution's `nss_wrapper` package [R38], chosen by V-27 [R39], checked on
2026-11-24 [R40]:

| Dependency | Version | Why this one | Licence | Known CVEs | Maintenance |
| --- | --- | --- | --- | --- | --- |
| `libnss-wrapper` (Ubuntu package of `nss_wrapper`) | upstream 1.1.16; Ubuntu 26.04 `nss-wrapper 1.1.16-5`, `universe` | the only way to resolve an arbitrary uid without group 0 when the runtime adds no passwd entry (V-27); the alternative is writing our own `LD_PRELOAD` shim | BSD-3-Clause | none in NVD (keyword `nss_wrapper`, 0 results) | Samba's cwrap project; release 1.1.16 on 2024-07-05, last commit 2025-07-24, essentially one maintainer (Andreas Schneider) |

The `universe` component means Canonical does not commit to security updates for it: the
WeeboDevImage weekly rebuild and its `trivy` scan are what keep it current. One maintainer is the
real supply-chain risk; it is accepted because the library is small, stable, and replaceable by a
fallback the RFC already describes (opt-in gid 0).

## Data and privacy

New datum: the block, on the namespace. A namespace name is `dev-ws-<username>` [R27], so the
pair (namespace, block) links a uid to a person; that link is the purpose (attribution). It lives
on the Namespace object, read by admins and the operator, and dies with the namespace. Logs carry
the namespace name, as every feature's logs already do, and go to ClickStack under its existing
retention. Metrics carry no namespace label. The conflict refusal names no other namespace. After
a block is reused, old logs with that uid refer to the previous owner: an investigation must join
on time, not uid alone.

## Operational considerations

**Failure modes.**

| Failure | Direction | Why |
| --- | --- | --- |
| webhook down or timing out | closed: workspace pods refused | a floor removable by causing an error is not a floor; same argument as image-policy's Pod half [R7] |
| mutation fails, validation answers | closed: the unrewritten 1234 is refused | security rests on validation; the mutation's `Fail` only makes the error name the right webhook |
| namespace not observed by the webhook | closed | `NamespaceNotObserved` = deny |
| controller down | new namespaces get no block, their pods refused; existing namespaces unaffected; overlap still refused by the webhook (L8) | allocation is rare and namespaces are created long before use |
| range exhausted | the new namespace runs nothing, feature `message` + alert | sharing a block is worse than refusing |

`failurePolicy: Fail` on both, fixed in the chart. Availability: the cluster runs the webhook at
1 replica today [R26] while the chart defaults to 2 with a PDB [R12]; phase 1's "make the
webhook reliable" item [R28] (2 replicas, PDB) **must land before `Enforce`**, or a webhook
restart blocks every workspace start and every reschedule.

**Rollout.** `Off` → `DryRun` (≥ 7 days; blocks are allocated and written, logs read for
`would_rewrite` and `would_refuse`) → `podIdentity.webhooks.enabled=true` → `Enforce` scoped by
`namespaceSelector` to `dev-ws-batleforc-test` → `dev-ws-batleforc` → all. **Gate at every scope
widening:** the namespaces entering scope have all their workspaces stopped, the migration
runbook ran on them, and the WeeboDevImage with nss_wrapper is the image their devfiles use;
T-11/T-12 after the first step.

**Migration (runbook `pod-identity-migration`).** `fsGroup` re-groups the volume on mount and adds
group read/write; it never changes the owner [R34]; Longhorn RWO volumes honour it (`fsGroupPolicy: ReadWriteOnceWithFSType`) [R23]. Files tools check by owner (`~/.ssh` keys,
`~/.gnupg`) are then refused. Per namespace: stop the workspace; move the namespace out of
`podIdentity`'s `namespaceSelector` (not the global `exclude` label, which would also take it out
of `podSecurity` and `networkProfiles`); run a one-shot Job as root mounting the PVC: `chown -R
<block>:<block>` and `chmod go-rwx` on `~/.ssh`; put the namespace back; start the workspace.
Alternative: recreate the workspace. Tested on `dev-ws-batleforc-test` first.

**Rollback.** `mode: Off`: new pods run as 1234 again; annotations stay; files on the PVC now
owned by the block uid stay group-accessible through `fsGroup: 1234`, owner-checked files need
the runbook in reverse.

**Observability.** Metrics above to ClickStack through the existing OTel scrape. The controller
metrics go stale when it is down, so the paging alerts read the webhook (L9):
`refusals_total{reason=~"conflict|exhausted|malformed"}` increase (page), `reason="no_block"`
sustained over 5 min (page: the controller is not allocating), `absent()` or staleness of
`weebo_si_pod_identity_blocks` for 10 min (page); `blocks{state="free"}` below 10 % (ticket).
Every decision logs `feature=pod-identity` with namespace, pod, result.

**Upgrade.** `podIdentity.webhooks.enabled` defaults to `false` (L7), so an upgrade never
registers a path that old webhook pods answer 404 to under `Fail` [R8]; the admin flips it after
the roll. Controller roll: the lease hands over
[R10]; the new leader's allocation LISTs fresh, so a write by the old leader is never missed.

**Capacity.** 555 blocks with the default grid; 2 namespaces today. One annotation lookup and
one overlap scan of the in-memory namespace cache per pod (≤ a few hundred entries), no
apiserver call; `perf_envtest.rs` gains the two paths beside
`/mutate/v1/pods` p50/p99 [R32]. One LIST of workspace namespaces per allocation.

## Other concerns

- **Accessibility:** no UI; the refusal text is plain, names the field and the block.
- **i18n:** admission messages are English, as every other webhook of this repo.
- **Compliance:** strengthens per-user separation and attribution (ISO 27001 A.8.2/A.8.15
  evidence: `id` per namespace, campaign page).
- **Licensing:** nothing new.
- **Documentation:** `docs/bricks/pod-identity.md`, `docs/weebosiconfig.md` (`podIdentity`), the
  install checklist (webhook HA first), the weebo-si runbook and campaign page.

## Alternatives considered

| Alternative | Rejected because |
| --- | --- |
| Do nothing | motivations 1–3 stand; user namespaces alone separate host ids, not volume or in-container ids [R20] |
| Extend `podSecurity` (the plan's other option) | `podSecurity` only writes namespace labels from a reconcile [R13]; this needs allocation state, a Pod mutation and a Pod validation, and staging "`restricted` without UID ranges" or the reverse would be impossible under one `mode` |
| The plan's literal range `1010000/10000` | ids above 65535 cannot be mapped under `hostUsers: false` [R20]; phase 5 turns it on |
| DevWorkspace `pod-overrides` | only DevWorkspace pods (not DWO's cleanup Jobs or any other pod in the namespace), and the workspace token can patch the DevWorkspace [R22], so a user-written override competes with ours |
| One DWOC per namespace through `dwocPin` | 555 copies of a che-operator-generated object that drift [R28] |
| Block = hash of the namespace name | no state, but with 555 blocks two of 30 namespaces collide with ~55 % probability |
| An allocation record of our own (ConfigMap/CR) | a second source of truth to reconcile with the annotation; the RBAC fact already protects the annotation [R22] |
| Kyverno mutate policy | a second admission engine for one rule, still needing the allocator, and already part of the reboot admission cycle [R28] |
| A second registry on the existing Pod routes | the routes' `failurePolicy` is the admin's image choice [R7][R8]; see Q2 |
| Operator chowns existing PVCs | a root container writing into user volumes from the operator |

## Drawbacks and risks

- Two more webhooks at `Fail` on the workspace path: more admission latency and one more reason a
  workspace does not start.
- `Off` does not remove what it wrote; the annotations outlive the feature by design.
- Migration is manual per namespace, and owner-checked files break without it.
- Reused blocks make historical uids ambiguous without a time join.
- Under user namespaces KubeArmor reports the host-mapped uid (V-07, `1094909952`) [R46]: the
  attribution gain covers files and in-container logs, not KubeArmor events.
- Containers outside WeeboDevImage (`che-browser`, postgres, UDI) lose name resolution; they run
  (V-28 [R43]), but anything that needs `whoami` in them fails.
- The design relies on GitOps creating namespaces long before use; a flow that creates the
  namespace and the workspace at once would see a few refused pod creations before the retry.

## Unresolved questions

### Resolved

| # | Question | Decision |
| --- | --- | --- |
| D1 | New feature or extend `podSecurity`? | **New feature `podIdentity`, crate pair `weebo-si-pod-identity` + `-adapters`.** Allocation state, a Pod mutation and a Pod validation, rollable back and dry-run independently of the PSA level. |
| D2 | Who allocates, where is it recorded? | **The leader controller, as `hardening.weebo.io/uid-range: <start>/<size>`, range 10000–65535, blocks of 100, lowest free wins, never rewritten, duplicates → `Degraded` and the younger namespace refused.** Under 65536 so it fits user namespaces [R20]; one writer, so no race. |
| D3 | How is the annotation protected? | **By RBAC alone: neither the user nor the workspace SA can patch the namespace [R22]; T-12 is the negative test; an admin hand-editing it is accepted residual.** A second record would be a second truth. |
| D4 | Where is it enforced? | **At the Pod, not via `pod-overrides`.** The Pod is the last point every path crosses (as OpenShift's SCC); DWO's cleanup/async/backup pods copy the same security context [R18] and are rewritten like the workspace. |
| D5 | `failurePolicy` of the mutating webhook? | **`Fail`, namespace selector limited to workspace namespaces plus the exclusion label.** Depends on webhook HA (2 replicas + PDB) landing before `Enforce`. |
| D6 | Chown existing PVCs automatically? | **No: runbook, tested on `dev-ws-batleforc-test` first.** A root container in user volumes is the opposite of the plan; `fsGroup` fixes the group, not the owner. |
| D7 | Set `hostUsers: false` here? | **No: a DWOC field for phase 5.** This feature works with and without; the < 65536 bound is what makes it compatible. |
| D8 | The `/etc/passwd` entry? | *Superseded by Q3 and L12.* ~~**`passwd-append` (RFC 0001), unchanged.**~~ It writes the entry for whatever uid it runs as [R14], but only with gid 0. |
| Q1 | (was Still open 1) Pod-level ids: rewrite or fill when absent? | **Rewrite pod-level ids outside the block; refuse container-level ones.** DWO always sends `runAsUser: 1234` and a DWOC cannot remove it [R16][R17]; "fill when absent" would never fire. Deviation from D4's draft wording, accepted as recommended. |
| Q2 | (was Still open 2) Own paths, or registries on the existing Pod routes? | **Own paths `/mutate/v1/pods/identity` and `/validate/v1/pods/identity`, `Fail` fixed.** The existing routes take the admin's image `failurePolicy` [R7][R8] and would fail open under `Ignore`. Accepted as recommended. |
| Q3 | (was Still open 3) Primary group, and gid 0? | **`runAsGroup` = the block's first id, and no supplementary gid 0 by default; the passwd entry comes from nss_wrapper in WeeboDevImage; gid 0 only behind `grantGroupZero` (default `false`), the documented last resort.** Went against the draft's recommendation (block + supplementary 0): maximise separation; gid 0 grants write on every `g=u` file of the image [R14]. V-27 (runc, 2026-11-24) showed containerd adds no entry, unlike CRI-O [R36][R39], so the runtime mechanism is out. |
| Q4 | (was Still open 4) Reuse of a freed block? | **Lowest free.** PVCs die with the namespace and storage is RWO-only; the residual (old logs, restored backups) is joined on time. |
| Q5 | (was Still open 5) Which uid does KubeArmor report under user namespaces? | **Ship regardless; V-07 settles the claim in the campaign page.** Files and in-container ids are separated whatever V-07 shows. V-07 ran on 2026-11-24 (runc, `hostUsers: false`): the `net_raw` Block held, and KubeArmor reported the node-side mapped uid `1094909952`, not the container uid, so under user namespaces motivation 3 holds for files and in-container logs only, not for KubeArmor events [R46]. |
| Q6 | (was Still open 6) Is 100 ids enough per namespace? | **`blockSize: 100`, configurable only before the first allocation.** Blocks are never rewritten; nothing asks for more than a handful of ids. |
| Q7 | (was Still open 7) DWO pods other than the workspace? | **Add the backup CronJob to the e2e suite when backups are switched on.** Source already shows it copies the workspace security context [R18]. |
| Q8 | (was Still open 8) A lost annotation on an old namespace? | **Allocate anyway, log `result=allocated_late`, and set `Degraded` when the namespace already holds PVCs, pointing to the runbook.** Refusing would block the namespace; a silent reallocation would hide the orphaned owner. |
| Q9 | (was Still open 9) Is `$HOME` writable without gid 0? | **Yes in a real workspace, provided `persistUserHome` stays on in Che's DWOC (it is, [R42]); no gid 0 needed.** V-28 (2026-11-24, `batlehub/batlehub` devfile `f4fdaf6053ea`, pod at 10100:10100 through `pod-overrides`): the home PVC is mounted on `/home/user` in every container, sidecars included, as `drwxrwsr-x root:10100`; `che-browser` runs Chrome with 0 restarts, postgres and dex run with `HOME=/` [R43]. Turning `persistUserHome` off re-opens the che-browser crash [R41], so it becomes a stated prerequisite of `Enforce`. |
| L1 | (from last review, resilience) Can two concurrent reconciles allocate the same block? | **Yes, so allocation is serialised: one process-wide mutex around LIST + patch in `KubeUidRangeStore`, a re-LIST after the write that releases on overlap, younger = later `creationTimestamp` then name, and an envtest creating N namespaces at once.** kube-runtime reconciles different objects concurrently [R48]; the precondition only guards the namespace it patches. |
| L2 | (from last review, code quality) How does the mutation write integers? | **Two new chassis variants, `SetInt` and `SetIntList`, with their `render_patch` arms.** `Mutation` is string-only today [R49]; ids are integers, and it is still a field set at a path, not structure. |
| L3 | (from last review, stability) Does validation run on every pod UPDATE? | **On UPDATE only what differs from `oldObject` is checked (new ephemeral containers); stopped workspaces stay a gate at each scope widening.** Otherwise a pre-`Enforce` 1234 pod could not be labelled or have its finalizers removed. |
| L4 | (from last review, UX) Where are warnings reported? | **Feature state stays `Active`/`DryRun`, warnings in the feature `message`, as image-rewrite; `Degraded` (reason `InvalidConfiguration`) only for a rejected config.** The six named reasons did not exist [R47]. |
| L5 | (from last review, code quality; **decided by the owner**) Does `DryRun` write the annotations? | **Yes.** Without them `DryRun` measures 100 % "no block"; the annotation is inert while the webhooks are not `Enforce`. Goes against the earlier text ("written only in `Enforce`"). |
| L6 | (from last review, resilience and honesty; **decided**) Grid changes and overlap? | **Allocation tests interval overlap against every held block, and a change of `range`/`blockSize` while blocks are held suspends allocation (feature `Degraded` with a message).** Q6 said the size is fixed after the first allocation; equality checks would miss overlapping blocks of another grid. |
| L7 | (from last review, stability; **decided**) Default of `podIdentity.webhooks.enabled`? | **`false`.** No upgrade registers paths old pods do not serve; the admin turns it on. |
| L8 | (from last review, resilience) Who refuses a duplicate? | **The webhook, from its own block→oldest-namespace index over its namespace cache; `uid-range-conflict` is level-based (set and removed by the controller) and informational.** A controller-only check fails open while the controller is down or the annotation is stale. |
| L9 | (from last review, resilience) Alerts when the controller is down? | **Page on the webhook's refusal counter and on `absent()`/staleness of controller metrics.** Controller-emitted gauges freeze with it. |
| L10 | (from last review, stability) When is `fsGroupChangePolicy` set? | **`OnRootMismatch` whenever pod-level ids are rewritten.** DWO always sends a securityContext, so "when absent" never fired. |
| L11 | (from last review, UX) One message for every "no block"? | **Distinct messages for no block yet (retry), range exhausted (ask an admin), malformed annotation, conflict, each mocked.** They call for different actions. |
| L12 | (from last review, UX/honesty/stability) D8 still claims passwd-append provides the entry? | **D8 is superseded by Q3: nss_wrapper provides it, passwd-append no-ops with an expected `WARN`; non-WeeboDevImage containers lose name resolution but run (V-28).** Without gid 0 passwd-append cannot write [R14][R37][R43]. |
| L13 | (from last review, honesty) Is Q8 wired through? | **Yes: Validation (feature message), Metrics (`allocated_late`), RBAC (`list persistentvolumeclaims`).** A decision with no surface would not be observable. |
| L14 | (from last review, security) Can the image's `/etc/group` add groups? | **The mutation sets `supplementalGroupsPolicy: Strict` and validation requires it.** Under `Merge` the image's group file adds groups to the uid. |
| L15 | (from last review; **decided**) Fuzz the parser? | **No fuzz infrastructure; table-driven tests.** The parser is two integers; a table covers it. |

### Still open

None: every question raised by this draft and by the last review is decided above (Q1 to Q9,
L1 to L15).

## Future work

- Auto-detect OpenShift (`security.openshift.io/v1`) and report `Degraded` if enabled there.
- A `weebo-si-operator pods identity` audit if `kubectl` columns stop being enough.
- Per-team block size, if a team ever needs many distinct uids.

## Test plan

- **Unit (domain):** `allocate_picks_lowest_free`, `allocate_skips_off_grid_blocks`,
  `allocate_returns_none_when_exhausted`, `block_parse_rejects_sign_overflow_and_zero`,
  `container_uid_outside_block_is_refused`, `ephemeral_container_outside_block_is_refused`,
  `pod_level_uid_rewritten_into_block`, `pod_level_inside_block_is_kept`,
  `pod_level_outside_block_refused_when_unmutated`,
  `supplemental_group_of_another_block_is_refused`, `pod_in_namespace_without_block_is_refused`,
  `malformed_annotation_is_no_block`, `conflict_message_names_no_other_namespace`,
  `group_zero_refused_by_default`, `group_zero_absent_unless_opted_in`,
  `duplicate_block_refuses_the_younger_namespace`, `allocate_rejects_overlapping_blocks`,
  `merge_policy_is_refused`, `fs_group_change_policy_set_on_rewrite`,
  `each_no_block_case_has_its_message`, `uid_block_parse_cases` (table, L15).
- **envtest:** allocation and conflict against a real apiserver
  (`n_namespaces_created_at_once_get_disjoint_blocks`, `conflict_annotation_is_level_based`,
  `labelling_a_preexisting_1234_pod_is_allowed`); both webhooks in
  `crates/weebo-si-operator/tests/admission_envtest.rs`, including
  `identity_webhooks_skip_excluded_namespaces`; `perf_envtest.rs` p50/p99 for the two paths.
- **e2e kind + Che:** new `crates/weebo-si-e2e/tests/pod_identity.rs` (obs. 1–6 and 4b).
- **Cluster:** V-05, V-06, V-07, V-10, **V-27** (passwd entry without gid 0, obs. 8: runc and youki FAIL = no entry; re-run with the nss_wrapper image), T-10,
  T-11, T-12, T-30, results on the campaign page.
- **Must stay green:** `pod_security.rs`, `workspace.rs`, `upgrade.rs` (the two-step), the image
  rewrite and image-policy envtests, `perf_envtest.rs` budgets.

## Implementation plan

- [ ] **PR 1 — CRD.** `podIdentity` config (with `grantGroupZero`, default `false`, and its
      warning doc), CEL rules, `docs/weebosiconfig.md`. Inert.
- [ ] **PR 2 — chassis + domain crate:** `Mutation::SetInt`/`SetIntList` and their
      `render_patch` arms (L2); `NamespaceView::holders` (L8); `weebo-si-pod-identity`: block,
      grid with overlap, allocation, the two admission features, table tests. No wiring.
- [ ] **PR 3 — controller adapter:** store with the allocation mutex (L1), loop, level-based
      conflict annotation, `allocated_late` (Q8), metrics, feature status/message (L4), envtest,
      RBAC switch (default off) with `list persistentvolumeclaims`. Annotations are written in
      `DryRun` and `Enforce` (L5) and are inert without the webhooks.
- [ ] **PR 4 — webhooks:** both handlers, composition root, both chart webhooks in the same PR
      (validation never later than mutation), `podIdentity.webhooks.enabled` default `false`
      (L7), the webhook's overlap index and refusal counter (L8, L9), admission and perf
      envtests.
- [ ] **PR 5 — e2e + docs:** `pod_identity.rs` (no gid 0 in `id`, `whoami` resolves),
      `docs/bricks/pod-identity.md`, install checklist, a note in `docs/bricks/passwd-append.md`
      that it is a no-op under `podIdentity` without gid 0.
- [ ] RFC flipped to `Implemented`.

### Estimate

An analogy with the measured RFCs, not a measurement.

| PR | Size | Compared to | Why |
| --- | --- | --- | --- |
| 1 CRD | S (≈ 800) | the CRD part of RFC 0014 | one small config block, CEL |
| 2 chassis + domain | M (≈ 3 500) | RFC 0017 (≈ 5 750, mutation in an existing feature) | two admission features + allocator + two chassis `Mutation` variants and a `NamespaceView` method |
| 3 controller | M (≈ 2 500) | RFC 0014's reconcile (≈ 6 800 total) | one annotation per namespace, simpler than two objects |
| 4 webhooks | M (≈ 3 500) | RFC 0017 | two new paths, chart, envtest, perf |
| 5 e2e + docs | M (≈ 2 000) | RFC 0013's e2e | one suite against kind + Che |
| **Total** | ≈ 12 300 | RFC 0013 (≈ 11 500, 2 days) | same shape: new feature + admission + e2e |
| WeeboDevImage nss_wrapper | S (≈ 100) | — | a package and a few entrypoint lines, outside this repo; required by V-27 |
| **Integration and validation on the cluster** | calendar-bound | — | webhook HA first; ≥ 7 days `DryRun`; migration and T-11/T-12 on `dev-ws-batleforc-test`, then `dev-ws-batleforc`; V-05/V-06/V-07 wait on phase 5 |

### Integration in weebo-si

- Prerequisite: `2.argo/helm/che/main/values.yaml` `che.hardening.replicas: 2` [R26] (phase 1).
- Prerequisite: `persistUserHome` stays enabled in Che's DWOC (CheCluster `devEnvironments.persistUserHome`); without it `/home/user` is the image's `drwxrwx--- user:root` and sidecars such as `che-browser` crash-loop without gid 0 (Q9, [R41][R42][R43]).
- Chart version bump in the same file; then `podIdentity.webhooks.enabled: true` once the new
  release runs (default `false`, L7).
- `che.hardening.operator.podIdentity.rbac.enabled: true` (operator switches).
- `2.argo/helm/che/hardening/values.yaml`: `config.features.podIdentity` with `enabled`, `mode`,
  `namespaceSelector` on `dev-ws-batleforc-test` first, `range`.
- `0.docs/content/docs/runbooks/pod-identity-migration.md`: the chown Job, the scope dance,
  rollback.
- **`Enforce` checklist item — WeeboDevImage with nss_wrapper deployed:** install `nss_wrapper`; the entrypoint writes a
  passwd and a group file (current uid and gid, name, home) into a writable emptyDir or the home
  and exports `LD_PRELOAD=libnss_wrapper.so`, `NSS_WRAPPER_PASSWD`, `NSS_WRAPPER_GROUP` [R38].
  Without it `whoami` breaks in every workspace (V-27 [R39]). Then V-27 re-run with the new
  image on runc (workspaces stay on runc: youki cannot do user namespaces, V-06, 2026-11-24).
- V-27 added to the validation table of `0.docs/content/todo/durcissement-workspaces.md`.
- Campaign page with V-05, V-06, V-07, V-10, V-27, T-10, T-11, T-12, T-30.

## References

| # | Source | Pinned at | Supports |
| --- | --- | --- | --- |
| R1 | `crates/weebo-si-crd/src/spec.rs:26`, `:54`, `:60` | `c412ee3` | `Features`, `pod_security`, `image_rewrite` fields |
| R2 | `crates/weebo-si-chassis/src/feature/value.rs:98` | `c412ee3` | `Decision<S>` shape |
| R3 | `crates/weebo-si-chassis/src/feature/reconcile.rs:22` | `c412ee3` | `ReconcileFeature::desired` |
| R5 | `crates/weebo-si-image-policy-adapters/src/image_policy.rs:40`, `:42`, `:114`, `:449`, `:534` | `c412ee3` | existing Pod paths, deny on error in `validate_pods`, rewrite never denies |
| R6 | `charts/weebo-si-operator/templates/mutatingwebhookconfiguration.yaml:93`–`132` | `c412ee3` | `/mutate/v1/pods` exists, CREATE+UPDATE, `failurePolicy` from value, selector `Exists` |
| R7 | `charts/weebo-si-operator/templates/validatingwebhookconfiguration-images.yaml:70`–`111` | `c412ee3` | `/validate/v1/pods`, its `failurePolicy` argument, no `objectSelector` |
| R8 | `charts/weebo-si-operator/values.yaml:356`, `:368` | `c412ee3` | `imagePolicy.podWebhook.failurePolicy`; two-step upgrade |
| R9 | `crates/weebo-si-chassis/src/port/namespace_view.rs:21` | `c412ee3` | `NamespaceView::annotation` |
| R10 | `crates/weebo-si-operator/src/controller_cmd.rs:19`, `:136`, `:152` | `c412ee3` | leader lease, loops only on the leader |
| R11 | `charts/weebo-si-operator/templates/rbac.yaml:146`–`172` | `c412ee3` | `patch namespaces` behind per-feature switches |
| R12 | `charts/weebo-si-operator/values.yaml:32`, `:42` | `c412ee3` | webhook `replicaCount: 2`, PDB |
| R13 | [RFC 0013](./0013-pod-security.md) | `c412ee3` | podSecurity writes labels only |
| R14 | [RFC 0001](./0001-passwd-append.md) lines 29, 131, 244 | `c412ee3` | passwd-append needs gid 0 to write `/etc/passwd` |
| R15 | `crates/weebo-si-image-policy-adapters/src/image_policy.rs:43`–`45`, [RFC 0017](./0017-image-rewrite.md) | `c412ee3` | own path beside an existing route (resolved 8) |
| R16 | devfile/devworkspace-operator `pkg/config/defaults.go:116`–`121` | `v1.1.1` (`bdd4530`), read 2026-11-24 | default `runAsUser 1234`, `runAsGroup 0`, `fsGroup 1234` |
| R17 | same repo `pkg/config/sync.go:345`–`346`, `:558`–`576` | `v1.1.1` | DWOC `podSecurityContext` strategic-merged onto the default |
| R18 | same repo `pkg/provision/storage/cleanup.go:158`, `pkg/provision/storage/asyncstorage/deployment.go:68`–`73`, `controllers/backupcronjob/backupcronjob_controller.go:423` | `v1.1.1` | DWO's other pods copy the workspace security context |
| R19 | same repo `pkg/config/defaults.go:129`–`146` | `v1.1.1` | restricted override fields on Kubernetes |
| R20 | <https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/> | read 2026-11-24 | valid ids 0–65535; outside = overflow, unmodifiable; volume inodes use in-container ids |
| R22 | probe `task k -- auth can-i patch namespace/dev-ws-batleforc-test --as=…` (user and workspace SA) | 2026-11-24 | neither can patch the namespace; SA can patch DevWorkspaces |
| R23 | probe `task k -- get csidriver driver.longhorn.io -o jsonpath='{.spec.fsGroupPolicy}'` → `ReadWriteOnceWithFSType` | 2026-11-24 | `fsGroup` applies to Longhorn RWO volumes |
| R24 | probe `task k -- get dwoc -A -o jsonpath='{…podSecurityContext}'` → empty for `devworkspace-config` and `devworkspace-operator-config` | 2026-11-24 | the pinned DWOC sets no pod security context |
| R25 | probe of cluster versions (images, `kubectl version`) | 2026-11-24 | DWO v1.1.1, Kubernetes 1.36.2, containerd 2.3.7, operator 0.5.0 |
| R26 | weebo-si `2.argo/helm/che/main/values.yaml:88` | weebo-si `b3bf9d67` | the cluster runs the webhook at 1 replica |
| R27 | weebo-si `2.helm/user-app/templates/dev-ns.yaml:14`; probe `task k -- get ns -l hardening.weebo.io/workspace-namespace --show-labels` | 2026-11-24 | namespaces created by GitOps with the label (weebo-si `b3bf9d67`); both test namespaces carry it |
| R28 | weebo-si `0.docs/content/todo/durcissement-workspaces.md` (phase 1 webhook item, phase 5 sections, test protocol) | weebo-si `b3bf9d67` | plan, test ids, OpenShift uid-range analogy, Kyverno admission cycle |
| R29 | `crates/weebo-si-operator/src/features.rs:17` | `c412ee3` | feature descriptor registry |
| R30 | `crates/weebo-si-operator/src/webhook_cmd.rs:183`–`185` | `c412ee3` | adapters' routes merged in the composition root |
| R32 | `crates/weebo-si-operator/tests/perf_envtest.rs:773`–`785` | `c412ee3` | Pod path latency budgets |
| R35 | containerd/containerd `pkg/oci/spec_opts.go:758`–`762` (`WithUserID`) | `v2.3.7` (`6f589cf`), read 2026-11-24 | containerd reads `/etc/passwd`, never writes; unknown uid → bare uid, gid 0 |
| R36 | cri-o/cri-o `server/container_create.go:325`–`343`, `utils/utils.go:208`–`224`, `:313`–`324` | `main` at `232f699` (2026-11-23), read 2026-11-24 | CRI-O generates and bind-mounts a passwd entry when the uid is missing and `/etc/passwd` is group/other-writable |
| R37 | `docs/bricks/passwd-append.md:98`–`99` | `c412ee3` | passwd-append's `WARN` and exit 0 when the entry resolves or the file is not writable |
| R38 | <https://cwrap.org/nss_wrapper.html> | read 2026-11-24 | `LD_PRELOAD=libnss_wrapper.so`, `NSS_WRAPPER_PASSWD`, `NSS_WRAPPER_GROUP` |
| R39 | probe `task hardening:validate -- V-27` (`0.task/scripts/hardening-validate.sh` in weebo-si): pod in `dev-ws-batleforc-test`, image `registry.pkg.weebo.poc/ghcr/batleforc/weebodevimage/che-min-mise:main`, `runAsUser/runAsGroup: 54321`, runc on containerd 2.3.7 | 2026-11-24 ~08:32 UTC+1; youki in run `20261124-084858` (`task hardening:validate -- V-04 V-07 V-27`: `runc=absente youki=absente`) | containerd/runc and youki add no passwd entry; `id`/`whoami` fail |
| R40 | `git clone https://git.samba.org/nss_wrapper.git` (`LICENSE`: BSD 3-Clause; tag `nss_wrapper-1.1.16` 2024-07-05; HEAD `9415ad5` 2025-07-24); Launchpad `getPublishedSources` for `nss-wrapper` in `resolute` (`1.1.16-5`, `universe`, Release); NVD `keywordSearch=nss_wrapper` (0 results); WeeboDevImage `che-min-mise:main` `/etc/os-release` = Ubuntu 26.04.1 LTS, no `libnss_wrapper` installed | 2026-11-24 | §Supply chain: licence, version, CVE and maintenance of nss_wrapper |
| R41 | Probe: pods `registry.pkg.weebo.poc/ghcr/batleforc/weebodevimage/che-browser:main` (`NO_START=false`) in a scratch namespace, PSA `restricted`, `hostUsers: false`, `runAsUser/runAsGroup` `1234:0` vs `54321:54321`; `ls -ld /home/user`, count of `chrome exited` in the log after 40 s (0 vs 39) | 2026-11-24 | §Unresolved 9: HOME needs gid 0 in today's images |
| R42 | Probe: `task k -- -n eclipse-che get dwoc devworkspace-config` → `config.workspace.persistUserHome.enabled: true` | 2026-11-24 | §Unresolved 9: HOME is a PVC in a real workspace |
| R43 | Probe V-28: DevWorkspace from `batlehub/batlehub` `devfile.yaml` at `main` `f4fdaf6053ea`, `pod-overrides` `runAsUser/runAsGroup/fsGroup: 10100`, in `dev-ws-batleforc-test`; per container `id`, `ls -ld $HOME`, `touch $HOME/.v28`, `/proc/mounts`; restart counts; `curl localhost:9222/json/version` | 2026-11-24 | §Resolved Q9 |
| R44 | Probe: `task k -- -n devworkspace-controller logs deploy/devworkspace-controller-manager -c devworkspace-controller`, `resolvedConfig` of the `Reconciling Workspace` line for `dev-ws-batleforc-test/hv-test` (DWO `v1.1.1`) | 2026-11-24 | §Detailed design: DWO's restricted override fields, live |
| R45 | probe `task hardening:validate -- V-06`: pod `hostUsers: false` + `runtimeClassName: youki` → `FailedCreatePodSandBox … RuntimeClass handler "youki" does not support user namespaces`; youki-dev/youki `crates/youki/src/commands/features.rs:82`–`83` (`idmap … enabled(false)`) at `v0.7.0` (`94ba653`), also `v0.8.0` and `main`; containerd/containerd `internal/cri/server/service.go:440` (`supportsCRIUserns`) at `v2.3.7` (`6f589cf`) | 2026-11-24 | youki cannot run user-namespaced pods, and why |
| R46 | probe V-07 (`task hardening:validate -- V-07`, run `20261124-084858`): runc, `hostUsers: false`, KubeArmor `net_raw` Block on the pod, `ping` refused; event uid `1094909952` | 2026-11-24 | KubeArmor reports the host-mapped uid under user namespaces |
| R47 | `crates/weebo-si-controller/src/reconcile.rs:453`–`468` (one `Degraded` condition, `InvalidConfiguration`), `:483`–`505` (image-rewrite: state by mode, warnings in `message`); `crates/weebo-si-crd/src/spec.rs:289`–`300` (`FeatureState::Degraded` = config rejected) | `c412ee3` | status reporting (L4) |
| R48 | `crates/weebo-si-pod-security-adapters/src/controller.rs:250`–`254` (`Controller::new(…).run(…)`, kube-runtime default concurrency) | `c412ee3` | reconciles of different namespaces run concurrently (L1) |
| R49 | `crates/weebo-si-chassis/src/mutation.rs:17`–`40` | `c412ee3` | `Mutation` = `SetConfigRef`, `Annotate`, `SetString`, string-only by design (L2) |
| R50 | `crates/weebo-si-runtime/src/config_store.rs:20`, `:79` | `c412ee3` | `ResolvedFeatures` and per-feature handles |
| R51 | `crates/weebo-si-runtime/src/ns_store.rs:25`–`76`; `crates/weebo-si-chassis/src/port/namespace_view.rs:23`–`35` | `c412ee3` | reflector-backed namespace cache; `annotated_anywhere` scan precedent (L8) |
| R34 | <https://kubernetes.io/docs/tasks/configure-pod-container/security-context/> | read 2026-11-24 | `fsGroup` sets group, not owner; `runAsGroup` omitted = gid 0 |

## Changelog

| Date | Change |
| --- | --- |
| 2026-11-24 | Draft |
| 2026-11-24 | Still open 9 added: HOME needs gid 0 in today's images (che-browser probe, V-28) |
| 2026-11-24 | Q9 resolved by V-28: persistUserHome makes HOME writable without gid 0 |
| 2026-11-24 | DWO's restricted override fields confirmed live (R44); any non-root uid passes them today |
| 2026-11-24 | nss_wrapper checked: BSD-3-Clause, 1.1.16, no CVE, Ubuntu 26.04 universe (R40) |
| 2026-11-24 | Last review applied (6 lenses): L1–L15, D8 superseded, V-06/V-07 probes pinned (R45, R46) |
