# `network-profiles` and `policy-guard`

Two features of the [`weebo-si-operator`](./weebo-si-operator.md), sharing one catalogue: every
workspace namespace gets a `NetworkPolicy` (or `CiliumNetworkPolicy`) baseline plus admin-granted
per-workspace profiles — `network-profiles` — and the objects it writes are protected from being
undone by anyone but the operator — `policy-guard`.

Design and rationale: [RFC 0004](../rfc/0004-network-profiles.md), and
[RFC 0008](../rfc/0008-policy-guard-coverage.md) for `policy-guard`'s coverage of
`KubeArmorPolicy`. Field reference: [`features.networkProfiles`](../weebosiconfig.md#featuresnetworkprofiles)
and [`features.policyGuard`](../weebosiconfig.md#featurespolicyguard). The operator's own install,
CLI and break-glass are on [`weebo-si-operator.md`](./weebo-si-operator.md); this page assumes
it is installed.

## Install checklist

Before writing `spec.features.networkProfiles` or `spec.features.policyGuard`, answer this first
— it decides `policyGuard`'s `failurePolicy` and how much the guard is worth in this cluster:

- **Can a workspace user write `networkpolicies` in their own namespace?** If RBAC already
  forbids it, `policy-guard` is defence in depth and can run at `policyGuard.failurePolicy:
  Ignore` in `values.yaml` once you have verified that. If it does not — closer to the built-in
  `edit` role — `policy-guard` is the only control, and `Fail` (the chart's default) is not
  optional.
- **`weebo-si-operator canary`** (once a client is configured against the target cluster) — does
  this cluster's CNI actually enforce NetworkPolicy? If it reports `not_enforcing`, **stop**:
  nothing below this line will do anything, and finding that out now costs an afternoon rather
  than a quarter. See *The enforcement canary* below.
- **`weebo-si-operator backends`** (once a client is configured against the target cluster)
  prints which policy dialects are compiled in and which the cluster actually offers. If it
  reports `Cilium` unavailable, `enforcement.backend: Cilium` in a profile resolves to nothing —
  set `networkProfiles.cilium.enabled: true` in `values.yaml` only when this reports `Cilium`
  available, so the RBAC grant and the watch match reality.
- **Which namespaces are workspace namespaces** — `policy-guard`'s
  `ValidatingWebhookConfiguration` only reaches namespaces carrying
  `hardening.weebo.io/workspace-namespace`. Labelling that is Che's job, or yours if Che does not
  do it automatically in this installation.

**`policy-guard` is one feature over several resources.** One `mode`, one `allowedIdentities`,
one `namespaceSelector`, and `policyGuard.failurePolicy` — but four `ValidatingWebhookConfiguration`
rules, each rendered only when the thing it protects is switched on:

| Rule | Path | Rendered when | `failurePolicy` | `objectSelector` |
| --- | --- | --- | --- | --- |
| `networkpolicies` | `/validate/v1/networkpolicies` | always | `policyGuard.failurePolicy` | none |
| `ciliumnetworkpolicies` | same path | `networkProfiles.cilium.enabled` | `policyGuard.failurePolicy` | none |
| `kubearmorpolicies` | `/validate/v1/kubearmorpolicies` | `kubearmorPolicy.rbac.enabled` | `policyGuard.failurePolicy` | none |
| `configmaps`/`secrets` | `/validate/v1/registryconfigs` | `registryConfig.rbac.enabled` | `registryConfig.failurePolicy` | ownership label |

There is **no per-resource mode**, and that is a decision rather than an omission (RFC 0008): the
guard's claim is "objects this operator owns are not yours to edit", and a cluster where that is
true of a `NetworkPolicy` and false of a `KubeArmorPolicy` is a cluster where the claim is not
true. Narrow by namespace with `spec.features.policyGuard.namespaceSelector`, not by resource.

The last row is the odd one out on both of its own columns, for a mechanical reason worth knowing
before you copy a rule: **a guard rule that must refuse unmanaged `CREATE`s cannot carry an
ownership `objectSelector`** — the selector makes that row unreachable — **and one that only
protects existing objects should, if the resource is high-volume.** `configmaps` are high-volume
and their rule has no unmanaged-`CREATE` row; policy objects are not, and theirs does.

## Rollout

Six steps, and the order between the two features is not interchangeable — see RFC 0004's own
*Operational considerations* for the full argument, condensed here:

1. Install with both features absent from `spec.features`. Run `weebo-si-operator backends`
   against the target cluster.
2. `networkProfiles: {mode: DryRun, ...}`, catalogue and `baseline` written, no teams yet. Every
   namespace's reconcile log line (`weebo-si-controller: network-profiles namespace=... diffs=...
   applied=None`) should show one `Diff::Create` — the baseline — and nothing else.
3. Add the `WeeboSiTeam` objects, still `DryRun`. Read the diff per namespace/team before
   trusting it.
4. `mode: Enforce` with a `namespaceSelector` naming a pilot label — one namespace — **then start
   a workspace in it**. The objects existing is not the test; the workspace working is.
5. Remove the selector. Do this during working hours: it is the step that touches running pods.
6. **Only then** `policyGuard: {mode: Enforce}`. Order matters for every resource it covers, not
   just this one: a guard that starts refusing writes while a controller is still converging
   turns a converging namespace into a stuck one. If `kubearmor-policy` is on, let it reach a
   steady state before enabling the guard rule over its objects.

Step 4 is also where `network-profiles`' own **admission gate** starts refusing things, so it is
worth knowing about before it surprises you. Under `mode: Enforce`, a `DevWorkspace` `CREATE` is
denied when:

- **its namespace has no baseline yet** — the workspace would start unprotected, and the
  fail-closed answer is to hold it back until the namespace reconciles (seconds, on the
  `Namespace` watch). This is the one place lag is unsafe, so it is the one place we block;
- **it names a profile its team is not granted, and `onNotGranted: Deny`** — under the default
  `onNotGranted: Default` the key is dropped and the team default applied instead, and nothing is
  refused.

Both denials carry the `network-profiles` feature id, so `mode: DryRun` records what they *would*
refuse without refusing anything, and `mode: Off` skips them entirely — there is no second flag.
The operator's own namespace and `eclipse-che` are excluded structurally (a compiled-in refusal,
not a configuration default), so a workspace there is never held back for a baseline that will
correctly never arrive.

## Rollback

- **`policyGuard: mode: Off`** — restores everyone's ability to write policy in their own
  namespace, for **every** resource the guard covers at once. Do this first, always — it is what
  makes manual repair possible.
- **`networkProfiles: mode: Off`** — deletes every managed object the controller reconciles away.
  Unlike `dwoc-pin`'s rollback, this changes cluster state: a namespace left with a `Enforce`-era
  baseline and nothing reconciling it is a namespace nobody can fix.
- **The break-glass**, when the operator itself is what is broken:

  ```console
  kubectl delete networkpolicy -A -l hardening.weebo.io/managed-by=weebo-si-operator
  kubectl delete ciliumnetworkpolicy -A -l hardening.weebo.io/managed-by=weebo-si-operator
  kubectl delete validatingwebhookconfiguration weebo-si-hardening-policies
  # ...and the guard's other rules, if they were rendered — deleting only the one above leaves
  # kubearmorpolicies and the registry objects still refused by a webhook nobody is answering.
  kubectl delete validatingwebhookconfiguration weebo-si-hardening-kubearmor-policies
  kubectl delete validatingwebhookconfiguration weebo-si-hardening-registry-configs
  ```

## Reading the logs

```text
weebo-si-controller: network-profiles namespace=user-alice mode=Enforce diffs=1 applied=Some(Applied { created: 1, updated: 0, deleted: 0, unchanged: 0 })
weebo-si-controller: network-profiles workspace=user-alice/data-pipeline mode=Enforce diffs=2 applied=Some(Applied { created: 2, updated: 0, deleted: 0, unchanged: 0 })
weebo-si-webhook: policy-guard deny namespace=user-alice actor=system:serviceaccount:user-alice:default resource=NetworkPolicy operation=Delete reason=user-alice/Delete is managed by weebo-si-operator and may not be touched by system:serviceaccount:user-alice:default
weebo-si-webhook: policy-guard deny namespace=user-alice actor=system:serviceaccount:user-alice:default resource=KubeArmorPolicy operation=Update reason=user-alice/Update is managed by weebo-si-operator and may not be touched by system:serviceaccount:user-alice:default
weebo-si-controller: network-profiles canary result=enforcing
```

Two `WARN` lines are the ones to grep for, because each means a team believes something that is
not true:

```text
WARN weebo-si-controller: feature=network-profiles profile=vault backend=NetworkPolicy result=unsupported — no variant for the resolved backend, profile not applied
WARN weebo-si-controller: feature=network-profiles team=team-2 workspace=scratch requested=[vault] result=not_granted
```

## The enforcement canary

`kubectl get networkpolicy` is not evidence of enforcement; only traffic is. The canary is the
only thing that answers "does this cluster's CNI actually do anything with the objects we write",
and it is the reason step 1 of the rollout above is *run it by hand before switching anything on*:

```console
$ weebo-si-operator canary
weebo-si-operator canary: probing in namespace weebo-si-hardening with image registry.k8s.io/e2e-test-images/agnhost:2.53
weebo-si-operator canary: result=enforcing
```

It creates a pod pair in the operator's own namespace — a listener and a client — and dials the
listener twice: once with nothing in the way, and once with a deny-all-ingress `NetworkPolicy`
selecting it. Reachable then blocked is `enforcing`; reachable both times is `not_enforcing`;
anything else is `unknown`, which is the honest answer when the probe could not establish a
baseline (the pod never scheduled, the image never pulled). **`unknown` is never folded into
`enforcing`** — "we could not check" and "we checked and it is fine" are different answers.

The command exits non-zero on anything but `enforcing`, so it works as a CI or install gate. Both
pods and the deny policy are deleted afterwards, including after a failed run.

In the controller it runs on `enforcement.canary.intervalSeconds` (default 300s, minimum 60s)
when `enforcement.canary.enabled` is true, on the leader replica only, and drives
`weebo_si_network_canary`. The probe image is `networkProfiles.canary.image` in `values.yaml` —
point it at your own mirror on an air-gapped cluster; the binary takes the same value as
`--canary-image`.

Its whole RBAC grant is `create`/`delete` on `pods` **in the operator's own namespace**, through a
`Role` rather than a `ClusterRole`, and the pods it creates mount no service account token.

## Observability

Every metric in RFC 0004's *Observability contract* is wired.

| Metric | Type | Labels | Where it comes from |
| --- | --- | --- | --- |
| `weebo_si_feature_mode` | gauge | `feature` ∈ `dwoc-pin`/`network-profiles`/`policy-guard` | config sync |
| `weebo_si_admission_duration_seconds` | histogram | `feature`, `resource` — `dwoc-pin`, `network-profiles` and `policy-guard` each label their own share; `policy-guard`'s splits three ways since RFC 0008 (`NetworkPolicy`/`CiliumNetworkPolicy`/`KubeArmorPolicy`), matching `weebo_si_admission_requests_total`'s | webhook |
| `weebo_si_network_reconcile_total` | counter | `result` ∈ `created`/`updated`/`unchanged`/`deleted`/`dry_run`/`error`, `team` | reconcile |
| `weebo_si_network_managed_objects` | gauge | `kind`, `scope` ∈ `baseline`/`profile` | policy watch, every 30s |
| `weebo_si_network_drift_total` | counter | `action` ∈ `restored`/`removed` | reconcile |
| `weebo_si_network_backend` | gauge | `backend` — `1` for the resolved one | config sync |
| `weebo_si_network_profile_unsupported` | gauge | `profile`, `backend` | config sync |
| `weebo_si_network_canary` | gauge | `result` ∈ `enforcing`/`not_enforcing`/`unknown` | canary loop |
| `weebo_si_network_not_granted_total` | counter | `team`, `profile` | reconcile |

Three of these are worth an alert, in this order:

- **`weebo_si_network_canary{result="not_enforcing"} == 1`** — every object is correct and none of
  them does anything. Nobody expects to need this one, which is exactly why it is first.
- **`weebo_si_network_profile_unsupported == 1`** — a profile is silently not applied, which is a
  team believing it has a permission it does not, or a restriction that is not there.
- **`rate(weebo_si_network_reconcile_total{result="error"}[15m])`** sustained — the fleet drifting
  away from its intended state one namespace at a time.

`weebo_si_network_drift_total{action="restored"}` climbing means somebody is fighting the
controller: either a user working around a policy, or an admin who does not know the guard exists.
Note that `restored` counts *edits* to our objects, not re-creations — a `Create` is
indistinguishable from the first reconcile of a new namespace, so it is deliberately not drift.

No metric carries a namespace or a workspace id: both scale with the cluster, and the
per-namespace answer lives in `kubectl get networkpolicy`. From the cluster's side, the CNI's own
dropped-flow metrics are the ground truth about what these policies do, and belong on the same
dashboard — ours only report what we *wrote*.

## Known limitations

- **`Auto` backend resolution is a boot-time snapshot** (`KubeCapabilities::discover` runs once).
  A CNI's CRD installed after the operator starts is not noticed until a restart.
- **The canary proves the CNI enforces *something*, not that your catalogue is right.** It probes
  one deny-all rule between two pods it owns. A template with a wrong CIDR still looks healthy.
- **No test anywhere asserts real connectivity.** The canary's own suite drives pod status by
  hand against a real apiserver, which covers the whole sequence but not whether a CNI drops a
  real packet — that needs a policy-enforcing cluster, which is the thing the canary exists to
  check for you at install time.
- **A namespace that leaves the feature's `namespaceSelector` keeps its objects.** There is no
  drift reconciler for out-of-scope namespaces; cleaning up is `mode: Off` or the break-glass.
