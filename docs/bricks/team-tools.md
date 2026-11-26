# `team-tools`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and threat model:
[RFC 0020](../rfc/0020-team-tools.md). Every field:
[`features.teamTools`](../weebosiconfig.md#featuresteamtools) and the team side
[`features.teamTools`](../weebositeam.md#featuresteamtools). This page assumes the operator is
installed.

A hardened workspace (PSA `restricted`, `hostUsers: false`, KubeArmor) cannot run BuildKit, which
wants a nested user namespace and unconfined seccomp and AppArmor. This feature moves such a tool
out of the workspace into a **tools namespace per team**, written by the admin in Git, and starts
it **on demand**: a devfile asks for it with an attribute, the controller renders the tool's
templates into the team's tools namespace, scales its workload to 1 through `/scale` while a
requester runs and back to 0 after an idle grace, and writes the client side (endpoint
`ConfigMap`, a per-user client `Certificate`, an egress `CiliumNetworkPolicy`) into the requesting
workspace namespace. The privileged exception stays in one namespace the admin named; another
team's workspace is refused by the network and by TLS.

A tool that needs no privilege, is light, and holds throwaway state (Postgres, Redis, Playwright)
stays a **sidecar** in the devfile: this feature is not for it (RFC 0020, *The rule*).

## Install checklist

1. **The chart RBAC**, off by default:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator -n weebo-si-hardening \
     --set teamTools.rbac.enabled=true --set networkProfiles.cilium.enabled=true
   ```

   `teamTools.rbac.enabled` renders two **unbound** ClusterRoles (`weebo-si-team-tools`,
   `weebo-si-team-tools-requester`), the cluster-wide read on `configmaps` and
   `certificates.cert-manager.io`, and a Role reading the template namespace. Without it the
   controller logs `team-tools is inert` once and the feature never runs.
   `networkProfiles.cilium.enabled` is the cluster-wide `ciliumnetworkpolicies` grant the ingress
   and egress policies need. The controller renders CNPs only when the apiserver serves Cilium's
   CRD (discovered at boot); without the CRD, or without the grant (the writes get 403), nothing
   isolates the tool on the network.
2. **The template namespace.** `teamTools.templateNamespace.name`, empty by default = the
   resource-quotas one (`weebo-si-hardening-templates`). A quota profile template kept there is a
   live `ResourceQuota` on the tool templates too: `services: 0` or a `count/configmaps` cap
   refuses them. Keep such profiles elsewhere or give team tools its own namespace.
3. **cert-manager** (`v1.21.3` on the lab) for any entry with `tls`, and **one `ClusterIssuer`
   per team** (the team CA, *Add a team tools namespace* below). Without cert-manager the other
   features run unchanged; an entry with `tls` fails its `Certificate` writes.
4. **The endpoint-auth issuer allow-list** (RFC 0020 S3, the `WeeboSiConfig` field
   [`spec.features.endpointAuth.allowedIssuers`](../weebosiconfig.md#featuresendpointauth), not a
   chart value; default `[vault-issuer]`) stays without the team CAs: otherwise a user mints a team client certificate
   through an `Ingress` annotated `cert-manager.io/cluster-issuer: <team CA>`.
5. **Per tools namespace and per workspace namespace**, the RoleBindings of the runbook below.
   RBAC cannot scope a write by label, so the RoleBinding *is* the scope: a namespace without it
   reports `Forbidden` and nothing else breaks.

## Configure it

The catalogue on the `WeeboSiConfig`, the grant on each `WeeboSiTeam`:

```yaml
spec:
  features:
    teamTools:
      mode: DryRun
      namespaceSelector:
        matchLabels: { kubernetes.io/metadata.name: dev-ws-batleforc-test }
      idleGraceSeconds: 600
      onNotGranted: Default
      catalog:
        - key: buildkit
          workload: {kind: StatefulSet, name: buildkitd}
          service: {name: buildkitd, port: 1234}
          clientEnv: BUILDKIT_HOST     # value generated: tcp://buildkitd.<tools ns>.svc:1234
          tls:
            serverSecretName: buildkitd-tls
            clientDuration: 24h
            clientMountPath: /home/user/.config/weebo/buildkit
          toolTemplates:
            - {kind: StatefulSet, name: buildkitd, namespace: weebo-si-hardening-templates}
            - {kind: Service, name: buildkitd, namespace: weebo-si-hardening-templates}
            - {kind: ConfigMap, name: buildkitd-toml, namespace: weebo-si-hardening-templates}
            - {kind: CiliumNetworkPolicy, name: buildkitd-egress, namespace: weebo-si-hardening-templates}
          requesterTemplates:
            - {kind: ConfigMap, name: buildx-client, namespace: weebo-si-hardening-templates}
---
# WeeboSiTeam weebo
spec:
  features:
    teamTools:
      namespace: team-weebo-tools
      issuerRef: {kind: ClusterIssuer, name: team-weebo-tools-ca}
      allowed: [buildkit]
      default: []                     # nobody gets a tool without asking
```

The templates are real objects in the template namespace, which runs no pod. The workload
template is written at `replicas: 0`, with `automountServiceAccountToken: false`, no
`privileged`, no added capability, no host namespace, port or path, and no `runtimeClassName`
(*Open points*). No template sets `immutable: true` (every later template update would fail), and
the workload never sets `persistentVolumeClaimRetentionPolicy.whenDeleted: Delete` (the cache PVC
outlives the StatefulSet). No template name starts with `kube-` or `openshift-`: adoption would
take over the `kube-root-ca.crt` or `openshift-service-ca.crt` every namespace carries. The
controller checks every template ref, kind and pod-spec rule and reports a broken entry
`Invalid` (the `WeeboSiConfig` goes `Degraded`); **an invalid entry keeps what is already
rendered**. RFC 0020's *What the admin writes* has the reference BuildKit StatefulSet.

That reference needs one more template with `hostUsers: false`: rootlesskit maps the image's
`/etc/subuid` range (`user:100000:65536`), which lies beyond the 65536 ids of a user-namespaced
pod, so the daemon exits at once with `newuidmap … write to uid_map failed: Operation not
permitted`. A `ConfigMap` template (`buildkitd-subid`, listed in `toolTemplates`) carries
`user:1:999` and `user:1001:64535` as both `subuid` and `subgid`, mounted with `subPath` over
`/etc/subuid` and `/etc/subgid`: every pod id but 0 and the daemon's own 1000, so a `RUN` step
sees ids 0 to 65534. Nothing is relaxed: the process sandbox, `hostUsers: false` and the other
fields stay as the RFC has them (reproduced with podman and a `RUN` step in `process-mode:
sandbox`; `crates/weebo-si-e2e/tests/team_tools.rs` carries the same fixture).

## What a developer sees

The request, in the devfile:

```yaml
attributes:
  hardening.weebo.io/team-tools: buildkit
```

A comma-separated list, at most 8 keys; more counts as the invalid key `<invalid>`, refused
under `Deny` and warned about under `Default`. **Absent** means the team `default`; **present and
empty** (`""`) means no tool, even with a default. Inside the workspace, once started:

```text
$ echo $BUILDKIT_HOST
tcp://buildkitd.team-weebo-tools.svc:1234
$ ls /home/user/.config/weebo/buildkit
ca.crt  tls.crt  tls.key
```

The client certificate's CN is the namespace's `che.eclipse.org/username` annotation (admin-
written), never anything the DevWorkspace says. The daemon starts with the IDE: the first build
may find it still starting, and `buildx`/`buildctl` retry the connection.

**The verdict annotation** (`Enforce` only), the answer to "why is my tool missing":

```text
$ kubectl get dw python-web -o jsonpath='{.metadata.annotations.hardening\.weebo\.io/team-tools}'
granted=buildkit;dropped=android
```

**Events on the DevWorkspace**:

| Reason | When | Message |
| --- | --- | --- |
| `TeamToolNotGranted` | a requested key is not in the team's `allowed` | `team tool "android" is not granted to team weebo; ignored` |
| `TeamToolNoIdentity` | no certificate is minted (fail closed): the namespace is not labelled `hardening.weebo.io/workspace-namespace=true`, is labelled `hardening.weebo.io/exclude`, or its `che.eclipse.org/username` is missing, empty, padded with spaces, longer than 64 characters or holds a control character | `no client certificate for team tool "buildkit": namespace <ns> is not a workspace namespace with a che.eclipse.org/username annotation` |
| `TeamToolRestartNeeded` | the attribute was added to a running workspace: DWO mounts the client objects only when it builds the pod | `team tool "buildkit" was added to a running workspace: restart it once to mount its client side` |

**Under `onNotGranted: Deny`**, a `CREATE` naming an ungranted key, or an `UPDATE` that starts the
workspace, is refused. Denials carry no status reason, so kubectl prints a bare
`Error from server:` (seen on kind, Kubernetes 1.35), not the RFC mock's `Forbidden`:

```text
$ kubectl apply -f devworkspace.yaml
Error from server: error when creating "devworkspace.yaml": admission webhook
"devworkspaces.hardening.weebo.io" denied the request: team tool "android" is not granted to
team weebo
```

Any other `UPDATE` (a grant revoked while the workspace exists, a label written by DWO) is
admitted with the key dropped, so a revocation never wedges a DevWorkspace; `kubectl` shows
`Warning: team tool "buildkit" is no longer granted to team weebo; dropped`. Under `Default` the
key is dropped and the warning reads `team tool "android" is not granted to team weebo; ignored`. The Che dashboard drops admission warnings: its users
read the annotation and the Events.

## How it works

- **Render.** While at least one DevWorkspace of the team requests a key, in any phase including
  stopped, the tool templates exist in the tools namespace (labelled
  `hardening.weebo.io/managed-by=weebo-si-operator` and `hardening.weebo.io/team-tool=<key>`),
  plus a generated ingress CNP `weebo-team-tool-<key>-ingress` admitting only the team's
  workspace namespaces on the tool port and, with `tls`, the server `Certificate`
  `weebo-team-tool-<key>-server`. Each requesting namespace gets the endpoint `ConfigMap`
  `weebo-team-tool-<key>`, the requester templates, the client `Certificate`
  `weebo-team-tool-<key>-client` (its Secret mounted by DWO), and one egress CNP
  `weebo-team-tool-<key>-<devworkspaceId>` per workspace, owned by the DevWorkspace. That CNP
  sets `enableDefaultDeny: {egress: false, ingress: false}` (Cilium ≥ 1.15), so it only adds the
  path to the tool and never puts the workspace into default-deny egress. Rendering
  early lets DWO mount the client side on the first start.
- **Scale.** Desired replicas is 1 while a requesting DevWorkspace of the team has
  `spec.started: true` or phase `Starting`/`Running`; when that count reaches 0 it stays 1 for
  `idleGraceSeconds`, then 0. The workload is created at 0, then applied with `spec.replicas`
  stripped: only the scale field manager `weebo-si-team-tools-scale` owns `replicas`, so a
  template update never resets it. The grace timer is in memory: a controller restart re-arms it,
  so a tool may stay up one extra grace.
- **Change detection.** A rendered object carries the annotation
  `hardening.weebo.io/team-tools-fingerprint`, a hash of what the controller wrote; the diff
  compares fingerprints, not bodies, because the apiserver adds defaults. Applies go under the
  field manager `weebo-si-team-tools`.
- **Unrequest.** When no DevWorkspace of the team requests the key, the tool's objects are
  deleted **except the StatefulSet's PVCs**: the cache survives. Requester objects go when their
  namespace has no requester left.
- **Binding.** The controller writes in a tools namespace only if it exists, carries
  `hardening.weebo.io/team-tools=<team>`, is not a workspace namespace nor the operator or
  template namespace, holds a `ResourceQuota` constraining `limits.memory`, and answers writes
  without 403. Otherwise the team's tools are `Unbound`.
- **Held.** While a tools namespace's cache is not synced, its tools are `Held`: no scale, no
  delete. An empty cache never reads as "no requester".
- The controller compares its inputs every 2 s and passes at least every 30 s; a namespace label
  change waits for the 30 s resync.

## Rollout

1. *Phase 0 → phase 1 adoption* below if the tool already runs from a chart, else *Add a team
   tools namespace*.
2. `mode: DryRun` with the catalogue and one team, `namespaceSelector` on one test namespace, for
   at least seven days. Read the `diff=` and `scale=` lines and the team status. Only the
   tools-namespace lines (`team=… tool=…`) end in `(not written)`; the workspace-namespace `diff=`
   lines (`ns=…`) carry no suffix in any mode, and under `DryRun` they are not written either.
3. `Enforce` on that namespace; run RFC 0020's cluster checks (V-16, T-39 to T-42).
4. Remove the `namespaceSelector`.

## Rollback

- **Surgical:** remove the key from the team's `allowed`. Workspaces keep running without it.
- **Whole feature:** `mode: Off` deletes every object this feature wrote, **the cache PVC
  excepted** (`feature=team-tools mode=Off deleted=<n>`). Deleting the cache is an admin's
  `kubectl delete pvc`.
- **Removing the `teamTools` block tears nothing down**: as for every feature here, only an
  explicit `mode: Off` removes what was written (a singleton re-applied without the block must not
  stop every tool). The statuses are cleared.
- `teamTools.rbac.enabled=false` last: the controller goes inert and keeps what exists.

## Runbook

### Add a team tools namespace

In Git, next to the team (weebo-si: the team's chart):

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-weebo-tools
  labels:
    hardening.weebo.io/team-tools: weebo            # must equal the WeeboSiTeam's name
    pod-security.kubernetes.io/enforce: privileged  # rootless BuildKit, V-16
    # never hardening.weebo.io/workspace-namespace
---
apiVersion: v1
kind: ResourceQuota
metadata: {name: tools-quota, namespace: team-weebo-tools}
spec:
  hard: {requests.cpu: "4", limits.memory: 12Gi, requests.storage: 60Gi, pods: "6",
         services.nodeports: "0", services.loadbalancers: "0"}   # limits.memory is required
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: weebo-si-team-tools, namespace: team-weebo-tools}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: weebo-si-team-tools}
subjects:
  - {kind: ServiceAccount, name: weebo-si-operator-controller, namespace: weebo-si-hardening}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: team-weebo-tools-ca}
spec:
  ca: {secretName: team-weebo-tools-ca}   # in cert-manager's namespace; no other team trusts it
```

And in **every workspace namespace** of the team (weebo-si: `2.helm/user-app`, next to
`dev-ns.yaml`), the requester RoleBinding:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: weebo-si-team-tools-requester, namespace: dev-ws-<user>}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: weebo-si-team-tools-requester}
subjects:
  - {kind: ServiceAccount, name: weebo-si-operator-controller, namespace: weebo-si-hardening}
```

Then the team's `features.teamTools` block. Check: `kubectl get weebositeam weebo -o yaml` shows
`TeamToolsReady=True` reason `Bound`; `NamespaceNotBound`, `NoQuota`, `Forbidden` or `Invalid` name the
missing piece. The namespace is checked only once the team is allowed a key: a block with
`allowed: []` reads `True`/`Bound`, message `no tool allowed`, whatever the namespace.

### Rotate a team CA

The team CA signs the daemon's server certificate and every client certificate of the team.

Each side trusts only the CA in its own Secret's `ca.crt`, so the server and **every** client
certificate must move together: a client still signed by the old CA cannot reach a daemon renewed
under the new one, and the other way round. Plan it while no build runs.

1. Write the new CA key pair into a new Secret in cert-manager's namespace and point the team's
   `ClusterIssuer` at it (same issuer name, so nothing in the operator changes).
2. Renew the server certificate: `cmctl renew -n team-weebo-tools weebo-team-tool-buildkit-server`
   (or delete its Secret). Whether buildkitd reloads a renewed server certificate without a
   restart is a V-16 item: until it is recorded, restart the daemon (`kubectl rollout restart sts
   buildkitd -n team-weebo-tools`).
3. **Required, at the same time:** renew every `weebo-team-tool-<key>-client` in the team's
   workspace namespaces (`cmctl renew -n <ns> weebo-team-tool-buildkit-client`). Left alone, they
   would renew only at the end of the entry's `tls.clientDuration`, and builds fail until then.
   The e2e suite proves a renewed client certificate is used without a workspace restart.
4. Delete the old CA Secret once every client certificate has been renewed (at the latest, one
   `clientDuration` after step 1).

### Phase 0 → phase 1 adoption

For a tool already deployed by a per-team chart (weebo-si's `2.helm/team-tools`, phase 0):

1. Set `argocd.argoproj.io/sync-options: Delete=false,Prune=false` on the chart's StatefulSet,
   Service, ConfigMap and CNPs, and sync.
2. Remove them from the chart and sync: Argo forgets them without deleting them. The chart keeps
   the Namespace, label, quota, RoleBinding and `ClusterIssuer`; drop its `ignoreDifferences` on
   `/spec/replicas`.
3. Write the templates and the `teamTools` blocks. The controller **adopts** each object of the
   same name in the tools namespace lacking `managed-by` by server-side apply with force, its
   replicas kept (`feature=team-tools adopting StatefulSet team-weebo-tools/buildkitd`): same
   pod, same PVC. Objects in a **workspace namespace** are never adopted (`not writing … a
   workspace namespace's objects are never adopted`): delete those by hand.

## Failure modes

| Failure | Direction |
| --- | --- |
| controller down | the tool keeps its replicas, no new client objects; the T-41 alerts below |
| template or tools-namespace cache not synced | tools `Held`: no scale, no delete |
| cert-manager down | no new client certificate; existing ones work until expiry |
| webhook down | DevWorkspace writes refused (`failurePolicy: Fail`, existing) |
| tools namespace unbound | nothing rendered; workspaces start without the tool |
| node out of memory | tool pod `Pending`, the tools quota bounds the rest |
| `WeeboSiConfig` absent or unparsed | **open**: every feature reads `Off` (house-wide) — no teardown, no new render |

## Open points

- **A hand edit of a rendered object is not reverted** while its fingerprint annotation is
  unchanged, that is until its template (or the render inputs) changes: change detection compares
  the stored fingerprint, not the live body. The tools namespace is admin-only, so this is an
  admin's edit.
- **Tool pods are outside the workspace pod checks.** The tools namespace never carries
  `hardening.weebo.io/workspace-namespace`, so the pod-identity webhooks skip it, and the
  template pod-spec checks do not refuse `runAsUser: 0`, `allowPrivilegeEscalation`, `procMount`
  or `hostUsers: true`. Accepted because templates are admin-written; the residual risk is a
  template mistake running a tool as root with the host's user namespace, bounded only by the
  tools namespace's quota and policies (its PSA level admits the BuildKit template, so it is
  loose).
- **Removing the `teamTools` block tears nothing down**; only `mode: Off` does (*Rollback*). RFC
  0020 suggests otherwise; the house behaviour is kept.
- **`teamTools.allowedRuntimeClasses` is not plumbed**: the chart has no such value, so any
  template `runtimeClassName` is `Invalid` for now.
- **Overlapping team selectors** are not refused: a workspace namespace matching the selectors of
  two teams with team tools reaches both teams' ingress policies. The controller reports it in the
  feature's `message` and as a `TeamToolsSelectorOverlap` Event on the teams named
  (`result=overlapping_selectors`); per-user mTLS from each team's CA stays the boundary.
- **`workspaceSelection.attribute: ""`** turns the request step off; the team `default` still
  applies, as in network-profiles.
- RFC 0020 PR 4 (the controller) was gated on the remaining V-16 items (sandbox mode, peer CN in
  the daemon's log, server certificate reload, RAM under a build): record them in the runbook
  when run.

## Observability

Logs, one line per change, `feature=team-tools`:

```text
INFO feature=team-tools mode=DryRun team=weebo tool=buildkit requesters=1 diff=create:StatefulSet/buildkitd,create:Service/buildkitd (not written)
INFO feature=team-tools mode=Enforce team=weebo tool=buildkit requesters=1 scale=0->1 (written)
INFO feature=team-tools mode=Enforce ns=dev-ws-batleforc-test workspace=python-web tool=buildkit diff=create:CiliumNetworkPolicy/weebo-team-tool-buildkit-<id>
WARN feature=team-tools ns=dev-ws-batleforc-test workspace=python-web team=weebo requested=android result=not_granted
WARN feature=team-tools team=weebo tool=buildkit result=NamespaceNotBound <message>
WARN feature=team-tools tool=buildkit result=invalid <violation>
```

`scale=` ends in `(written)`, `(failed)` or, outside `Enforce`, `(not written)`. The team status
carries counts only, never who requests:

```text
status:
  teamTools:
    - {key: buildkit, namespace: team-weebo-tools, replicas: 1, requesters: 2, state: Running}
  conditions:
    - {type: TeamToolsReady, status: "True", reason: Bound}
```

`state` is `Running`, `Grace`, `Idle`, `Held`, `Unbound` or `Invalid`.

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_team_tools_replicas` | gauge | `team`, `tool` |
| `weebo_si_team_tools_requesters` | gauge | `team`, `tool` |
| `weebo_si_team_tools_scale_total` | counter | `team`, `tool`, `direction` (`up`/`down`), `result` (`ok`/`error`) |
| `weebo_si_team_tools_up_without_requester` | gauge | `team`, `tool`: 1 when up with no *started* requester (stopped ones do not count) for longer than the grace + 60 s |
| `weebo_si_team_tools_reconcile_total` | counter | `result` (`applied`, `unchanged`, `deleted`, `not_granted`, `invalid`, `unbound`, `forbidden`, `error`) |
| `weebo_si_team_tools_entries` | gauge | `state` (`valid`/`invalid`) |

No metric carries a namespace or a user. Alerts (T-41 needs two, since the controller's own gauge
dies with it): `up_without_requester == 1` for 10 min, **and** kube-state-metrics'
`kube_statefulset_replicas` / `kube_deployment_spec_replicas` > 0 on a
`hardening.weebo.io/team-tool` workload while the controller's metrics are stale or its pod
restarted more than 3 times in 30 min. Also `reconcile_total{result=~"forbidden|unbound"}`
increasing and `entries{state="invalid"} > 0`.

## Tests

Unit tests in `crates/weebo-si-team-tools` (resolution, the validation table, the scale state
machine, the binding gates, one negative test per RFC 0020 STRIDE row); envtest in
`crates/weebo-si-team-tools-adapters` (a template update never resetting `replicas`, phase-0
adoption, a workspace object never adopted, an invalid entry keeping what is rendered and `Off`
deleting only its own objects, the team status keeping identity's condition); the chart RBAC test
`the_controller_cannot_write_outside_a_bound_namespace`; and
`crates/weebo-si-e2e/tests/team_tools.rs` (`task e2e:run SUITE=team-tools`), with real rootless
BuildKit and `buildctl` in Che workspaces: render at 0, scale on start, idle after the grace with
the cache PVC kept, a renewed client certificate used without a restart, another team's
certificate refused by the daemon, an ungranted key refused under `Deny`, a forged tools namespace
never written, and a phase-0 StatefulSet adopted in place. kind does not enforce the CNPs: the
network layer of the cross-team refusal is a cluster check.
