# `pod-identity`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and threat model:
[RFC 0018](../rfc/0018-namespace-uid-range.md). Every field:
[`features.podIdentity`](../weebosiconfig.md#featurespodidentity). This page assumes the operator
is installed.

Without this feature, every workspace pod on a node runs as uid 1234 with group 0, in the node's
own user namespace: the same identity for every user, and group 0 writes every group-0-writable
(`g=u`) file of the image. With it, every pod created in a workspace namespace in scope runs in
**its own user namespace** (`hostUsers: false`, so the kubelet maps it to a node range no other pod
on that node shares), as `1234:1234`, with **no group 0**.

Two webhooks do it, both `failurePolicy: Fail`:

| Webhook | Path | Does |
| --- | --- | --- |
| `pod-identity-mutate.hardening.weebo.io` | `/mutate/v1/pods/identity` | on `pods` CREATE, writes the pod level only: `hostUsers: false`, `runAsUser`/`runAsGroup`/`fsGroup` where absent, gid and `fsGroup` 0 rewritten to `runAsGroup`, `fsGroupChangePolicy: OnRootMismatch`, `supplementalGroupsPolicy: Strict`, `runAsNonRoot: true`. Never refuses. |
| `pod-identity-validate.hardening.weebo.io` | `/validate/v1/pods/identity` | on `pods` CREATE and `pods/ephemeralcontainers` UPDATE, refuses what is still wrong after every mutation: one reason each, below. |

A non-zero id someone chose (a devfile's `pod-overrides` with `10100`, a sidecar image built for
uid 999) is kept: inside the pod's own user namespace it is unprivileged. `runAsUser: 0` is
refused, never rewritten. Namespaces whose `hardening.weebo.io/dwoc` names a key in
`exemptDwocKeys` (the `build` teams) are left untouched. **Existing pods keep the node's user
namespace until they restart**: admission runs at creation only.

## Install checklist

1. **Nodes that run user-namespaced pods.** Kubernetes with `UserNamespacesSupport` (on by default
   since 1.33) and `SupplementalGroupsPolicy` (since 1.33), a runtime that supports them (containerd
   2 with runc or crun, or CRI-O; **not youki or gVisor**, which containerd refuses), and idmapped
   mounts on every filesystem a workspace mounts (the lab's Longhorn ext4 was measured, V-05). RFC
   0013's *Node prerequisites* has the same list. The webhooks cannot see the node: on a node that
   cannot, the pod is admitted and fails at sandbox creation with the runtime's message. A kind
   node needs `e2e/runtime-matrix/kind-userns.sh` first, and **rootless podman cannot run them at
   all** (65536 ids in total, all of which one pod needs).
2. **PSA `restricted` on every namespace about to enter scope** (the
   [`pod-security`](./pod-security.md) feature). It sets `allowPrivilegeEscalation: false`, which is
   what stops a setuid binary of the image from giving root back. PSA relaxes its non-root checks
   for user-namespaced pods, so `restricted` alone is not this feature either: you need both.
3. **Webhook availability.** Both webhooks are `Fail`: while no webhook replica is Ready, no
   workspace pod is created, and DevWorkspace Operator marks the workspace `Failed` without
   retrying. On a **multi-node cluster keep the chart's two webhook replicas and their
   `PodDisruptionBudget`** on different nodes. On a **single node** (the weebo-si lab, RFC 0018
   Q23) one replica is accepted: two replicas on one node do not survive a node reboot, and the
   image-policy Pod webhook already puts every workspace pod behind the same replica. After a
   reboot, restart the workspaces that went `Failed` once the webhook is Ready.
4. **The images.** Images that write group-0 directories at runtime must be rebuilt before any
   namespace reaches `Enforce` (*My sidecar now gets Permission denied* below).
5. **Register the webhooks**, off by default:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set podIdentity.webhooks.enabled=true
   ```

   The paths answer in every mode, `Off` included, so register them once the release runs and
   **before** `mode: DryRun`; otherwise `DryRun` sees no request at all.
6. **Label the workspace namespaces.** Both webhooks are registered only on namespaces that carry
   `hardening.weebo.io/workspace-namespace` and not `hardening.weebo.io/exclude` (the chart's
   `namespaceExclusionLabel`); the apiserver never sends them a pod from any other namespace,
   whatever `namespaceSelector` says. weebo-si labels every workspace namespace; elsewhere, label
   them yourself. A namespace that lacks the label is silently out of scope: no rewrite, no
   refusal, and no log line, since the request never reaches the operator.

## Configure it

```yaml
spec:
  features:
    podIdentity:
      mode: DryRun
      namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: dev-ws-batleforc-test }
      runAsUser: 1234        # the images' user; never 0
      runAsGroup: 1234       # its own group; never 0
      exemptDwocKeys: [build]
      grantGroupZero: false  # last resort, see the reference
```

`namespaceSelector` narrows the scope inside the namespaces the webhooks reach; it cannot widen
it. A namespace it selects without the `hardening.weebo.io/workspace-namespace` label is never
rewritten nor checked, and nothing logs it (install checklist, step 6).

## Refusals and their fixes

A refused pod is not created. A workspace pod is created by DevWorkspace Operator's ReplicaSet,
so the developer sees the refusal in the workspace's status (the dashboard, or `kubectl get dw`):
DWO does not retry, it marks the workspace `Failed` with the event. The fix is in the devfile, then
a restart. A direct pod gets the refusal from `kubectl`, exit code 1. Denials carry no status
reason, so kubectl prints a bare `Error from server:` (seen on kind, Kubernetes 1.35), not the RFC
mocks' `Forbidden`.

```text
$ kubectl run -n dev-ws-batleforc-test probe --image=<image> --restart=Never \
    --overrides='{"spec":{"hostUsers":true}}'
Error from server: admission webhook "pod-identity-validate.hardening.weebo.io"
  denied the request: hostUsers=true: pods in a workspace namespace run in their own user
  namespace; remove hostUsers from the pod spec (or the devfile's pod-overrides)
```

One message per reason; several reasons are joined with a period and a space:

| Reason (`reason=` label) | Message | Fix |
| --- | --- | --- |
| `host_users` | `hostUsers=true: pods in a workspace namespace run in their own user namespace; remove hostUsers from the pod spec (or the devfile's pod-overrides)` | remove `hostUsers` |
| `host_users` (unset) | `hostUsers is unset: … set hostUsers: false in the pod spec (the pod-identity mutation did not run)` | the mutating webhook is not registered or failed: an admin problem, see *Failure modes* |
| `uid_zero` | `container "tools": securityContext.runAsUser=0 is not allowed in a workspace namespace; set a non-zero runAsUser or remove it` (without the container prefix for the pod level) | a non-zero uid, or none |
| `gid_zero` | `container "tools": securityContext.runAsGroup=0 is not allowed in a workspace namespace; remove runAsGroup from the devfile's container-overrides or set a non-zero group` | remove it from `container-overrides` |
| `uid_unset` | `container "tools": no runAsUser at container or pod level, so the image's USER applies and may be root; set runAsUser at pod level` | the mutation sets one; seen only when it did not run |
| `gid_unset` | `container "tools": no runAsGroup at container or pod level, so the image's primary group applies and may be root; set runAsGroup at pod level` | same |
| `fs_group_zero` | `securityContext.fsGroup=0 is not allowed in a workspace namespace; remove fsGroup from the devfile's pod-overrides` | remove it; seen when a later mutating webhook wrote it back, or the mutation did not run |
| `group_zero` | `securityContext.supplementalGroups contains 0; remove it from the devfile's pod-overrides` | remove the `0` |
| `policy` | `securityContext.supplementalGroupsPolicy="Merge" lets the image's /etc/group add group 0; remove it from the devfile's pod-overrides` | remove it (the mutation sets `Strict`) |
| `policy` (unset) | `securityContext.supplementalGroupsPolicy is unset, so the default Merge lets the image's /etc/group add group 0; set it to Strict` | the mutation sets `Strict`; seen only when it did not run, as `host_users` (unset) |
| `ephemeral_on_host_userns` | `ephemeral container "debugger-x7": this pod still shares the node's user namespace (created before pod-identity was enforced); restart the workspace, then debug it` | restart the workspace, then `kubectl debug` |

`fsGroup: 0` and a `0` in `supplementalGroups` are accepted while `grantGroupZero: true`; nothing
adds them.

## My sidecar now gets "Permission denied"

The pod no longer has group 0. Anything the image made writable **through group 0 only**
(`chgrp -R 0 … && chmod -R g=u …`, the OpenShift arbitrary-uid recipe) is now read-only for
the workspace: che-lgtm's `/data`, che-android's SDK and Appium directories, che-min-mise's
`/home/tooling` and `/globals`. `id` inside the workspace shows it:

```text
$ id
uid=1234(user) gid=1234(user) groups=1234(user)
```

The fix is in the image, not in this feature: in the same `RUN` as each install, replace
`chgrp -R 0 <dir>` by `chown -R 1234:0 <dir>` and keep `chmod -R g=u <dir>`; a
`COPY --chown=0:0` of user-edited configuration becomes `--chown=1234:0`. Owner 1234 then writes
under this feature, and group 0 still writes for an arbitrary uid on OpenShift. A separate `RUN`
would copy every file into a new layer. Do not answer it with `grantGroupZero`: that gives group 0
back to every pod in scope.

A sidecar built for another uid (999, say) still runs: its id is kept. It cannot write files its
image gave to group 0 either; the same image fix applies.

## Rollout

1. The install checklist above: PSA `restricted` on the namespaces about to enter scope, the
   images rebuilt, the webhooks registered.
2. `mode: DryRun`, scoped by `namespaceSelector` to one test namespace, for at least seven days.
   Read the webhook's log: `would_refuse … fixable_by_mutation=false` is real breakage;
   `would_rewrite` and `would_allow` are what `Enforce` will fix. **No line at all** means the
   webhooks are not registered, not that everything is clean. `DryRun` cannot predict *Permission
   denied* at runtime.
3. `Enforce`, one namespace at a time. **Gate at each widening**: no pod of the namespaces
   entering scope may still be in the node's user namespace. This prints nothing when it is safe:

   ```bash
   kubectl get pods -n <ns> -o json | jq -r '.items[]|select(.spec.hostUsers!=false)|.metadata.name'
   ```

   Stop or restart the workspaces it lists first: an existing pod is never rewritten, and
   `kubectl debug` on it is refused until it restarts.
4. Last, Che's `DevWorkspaceOperatorConfig` carries the same values (`hostUsers: false`, the
   pod-level ids, `supplementalGroupsPolicy: Strict`); `weebo_si_pod_identity_rewrites_total` then
   falls to 0 and every pod logs `result=unchanged`.

Volumes need no migration: files are owned by 1234 and inodes keep their in-pod ids under user
namespaces. Files a workspace created with primary group 0 keep group 0; their owner, 1234, still
reads and writes them.

## Rollback

In order:

1. `mode: Off`: new pods are no longer rewritten or refused.
2. If Che's DWOC carries the values (rollout step 4): revert it, then restart the workspaces (until
   then they keep `hostUsers: false` from the DWOC).
3. `podIdentity.webhooks.enabled=false`: removes the two `Fail` webhooks, the only way `Off` becomes
   a full teardown. A chart **downgrade** to a release without the paths needs this step first,
   or the old pods answer 404 under `Fail`.

## Failure modes

| Failure | Direction |
| --- | --- |
| webhook down or timing out | closed: workspace pods refused; workspaces started meanwhile go `Failed` and are restarted by hand |
| mutation not registered, validation registered | closed: every DWO pod refused with `fixable_by_mutation=true` (page) |
| `WeeboSiConfig` absent or unparsed | **open**: every feature reads `Off` (house-wide) |
| node cannot run user-namespaced pods | the pod fails at sandbox creation with the runtime's message |

## Observability

Every decision logs one line, `feature=pod-identity mode=<Off|DryRun|Enforce> ns=<ns>
resource=Pod name="<name or generateName>" result=<…>`: `rewritten`/`would_rewrite` with the
fields changed (`hostUsers=unset->false runAsGroup=0->1234 …`), `unchanged`, `allowed`,
`group_zero_granted`, `would_allow fixable_by_mutation=<reasons>`, and one `refused`/`would_refuse
reason=<reason> [container=<name>] fixable_by_mutation=<bool>` line per reason. Two error lines
carry **no `mode=` field**, so a query filtering on it misses them: the mutation's `result=error
reason=<error>` (the pod is admitted unchanged, validation decides), and validation's
`result=refused|would_refuse reason=<error>`, which is how a namespace the webhook has not seen yet
is refused under `Enforce`.

| Metric | Labels |
| --- | --- |
| `weebo_si_pod_identity_refusals_total` | `mode` (`Off`/`DryRun`/`Enforce`), `reason` (table above), `fixable_by_mutation` |
| `weebo_si_pod_identity_rewrites_total` | `mode`, `field` (`host_users`, `run_as_user`, `run_as_group`, `fs_group`, `fs_group_change_policy`, `supplemental_groups_policy`, `run_as_non_root`) |
| `weebo_si_admission_requests_total`, `weebo_si_admission_duration_seconds` | `feature="pod-identity"` |

Alert on `refusals_total{mode="Enforce"}` increasing (page when `fixable_by_mutation="true"`: the
mutation is not running), and on `weebo_si_admission_requests_total{feature="pod-identity"}` flat
while workspace pods start (the webhooks are not registered).

## Tests

`crates/weebo-si-e2e/tests/pod_identity.rs` (`task e2e:run SUITE=pod-identity`, docker or rootful
podman) proves RFC 0018's observations 1–6 and 8 on a kind node: two workspaces at `1234:1234`
with no group 0 in two node ranges, the refusals with their texts, a volume written before
`Enforce` still owned and writable after it, DevWorkspace Operator's cleanup Job rewritten, and
`DryRun` silent on a pod already in shape.
