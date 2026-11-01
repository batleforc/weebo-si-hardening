# `resource-quotas`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and rationale:
[RFC 0014](../rfc/0014-resource-quotas.md). Field reference:
[`features.resourceQuotas`](../weebosiconfig.md#featuresresourcequotas) and the team block in
[`weebositeam.md`](../weebositeam.md#featuresresourcequotas). This page assumes the operator is
installed.

Without a quota, one workspace namespace can take what the cluster has: as many pods, CPU, memory,
`NodePort` services and volumes as it likes. This feature gives every workspace namespace in scope
**one quota profile**, per team: a `ResourceQuota` named `weebo-quota` and a `LimitRange` named
`weebo-limits`, copied from templates an admin writes. The apiserver's own `ResourceQuota` and
`LimitRanger` admission do the enforcing. The operator decides which namespace gets which profile,
and refuses a profile that would stop every pod from starting.

## Install checklist

1. **Grant the RBAC.** Off by default:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set resourceQuotas.rbac.enabled=true
   ```

   This adds create, update, patch and delete on `resourcequotas` and `limitranges`,
   cluster-wide. RBAC cannot narrow a create to a name, so the narrowing is the adapter's: it
   writes exactly `weebo-quota` and `weebo-limits`, and deletes only objects carrying
   `hardening.weebo.io/managed-by`, pinned to the uid it read. The same switch renders the
   `policy-guard` rule for these two objects and the template namespace.

2. **Write the templates in the template namespace**, `weebo-si-hardening-templates` by default
   (`resourceQuotas.templateNamespace`). **Never in the operator's own namespace**: a
   `ResourceQuota` or `LimitRange` is enforced in the namespace that holds it, so there it would
   cap and default the operator's pods. The template namespace runs nothing. A profile whose ref
   points anywhere else is refused.

   ```yaml
   apiVersion: v1
   kind: ResourceQuota
   metadata: {name: quota-standard, namespace: weebo-si-hardening-templates}
   spec:
     hard:
       requests.cpu: "4"
       requests.memory: 8Gi
       limits.cpu: "8"
       limits.memory: 12Gi
       pods: "20"
       services.nodeports: "0"
       services.loadbalancers: "0"
   ---
   apiVersion: v1
   kind: LimitRange
   metadata: {name: limits-standard, namespace: weebo-si-hardening-templates}
   spec:
     limits:
       - type: Container
         defaultRequest: {cpu: 100m, memory: 256Mi}
         default: {cpu: "1", memory: 1Gi}
         max: {cpu: "4", memory: 8Gi}
   ```

3. **Audit before you enforce.** See *Rollout*.

## What a profile must satisfy

A profile is checked against its templates before it is written anywhere. **An invalid profile is
not applied**, and namespaces that already have a profile keep it: a broken configuration never
removes an existing ceiling.

| Rule | Why |
| --- | --- |
| Every ref exists, in the template namespace. | The most common edit mistake, and a template elsewhere would constrain what runs there. |
| A quota on `requests.cpu`/`requests.memory` (or bare `cpu`/`memory`) has a `Container` default for it: `defaultRequest`, or `default`, or `max`. | Once a compute quota exists, the apiserver refuses every pod that does not state the resource. LimitRanger fills a missing request from those three, in that order. Without any, the quota is a pod-creation outage. |
| A quota on `limits.cpu`/`limits.memory` has a `Container` `default` or `max` for it. | Same reason. |
| `defaultRequest` ≤ `default` ≤ `max`, per resource. | The apiserver rejects such a `LimitRange` anyway; checking first names the profile. |
| Every quantity parses. | `50GB` is not a quantity; `50G` is. |
| No `scopes` or `scopeSelector` on the quota. | A scoped quota counts only part of the pods, which is not a ceiling. |

`weebo_si_resource_quotas_profiles{state="invalid"}` counts them, and the controller logs each
reason every 30 seconds.

## What gets written

One profile per namespace, never a set: two quotas in one namespace are both enforced, and two
`LimitRange`s apply with no defined winner. Which profile:

1. the namespace annotation `hardening.weebo.io/resource-quota`, when it names a profile the
   namespace's team is granted;
2. otherwise the team's `default`, or the cluster `default` for a namespace of no team.

The annotation is **not** tighten-only: profiles are not ordered ("large" may have more CPU and
fewer pods). The grant is the bound, and every change of the annotation counts in
`weebo_si_resource_quotas_selection_changed_total`. An ungranted key follows `onNotGranted`:
`Default` applies the default and logs `result=not_granted`; `Deny` leaves the namespace as it is.

The two objects carry the template's `spec`, unchanged, and two labels:
`hardening.weebo.io/managed-by=weebo-si-operator` and `hardening.weebo.io/profile=<key>`. A profile
with no `LimitRange` template removes `weebo-limits`.

**Objects this feature did not write are never touched.** A foreign `ResourceQuota` (Che's
`workspaces-config` replication, an admin's) still applies, and can only make the namespace
stricter. A foreign `LimitRange` is a real conflict, two sets of defaults; it is counted and logged,
and does not stop ours being written.

## Rollout

1. **Audit**, with your own kubeconfig, before installing anything:

   ```console
   $ weebo-si-operator quotas audit --all-namespaces
   NAMESPACE                TEAM           PROFILE      OVER
   user-alice               team-1         standard     -
   user-bob                 team-1         standard     pods 23/20, requests.memory 9.5Gi/8.0Gi
   ```

   Every line with something in `OVER` is a namespace whose next pod will be refused. Size the
   profiles from this, not from guesses. `--profile large` asks about another profile.

2. **`mode: DryRun`**, catalogue and `default` written. Check `profiles{state="invalid"}` is `0`.
   The log says what would be written:

   ```text
   feature=resource-quotas mode=DryRun ns=user-bob team=team-1 profile=standard result=applied diff=create:weebo-quota,create:weebo-limits
   ```

3. **A cautious first profile**: object counts and the two service types only, no compute quota.
   It closes the `NodePort` exposure and the volume loop on day one and cannot refuse a workspace
   for lack of CPU. Compute ceilings come once usage is known.

4. **`mode: Enforce` on a pilot** (`namespaceSelector`), then widen. Watch
   `saturation{band="at_limit"}`.

Pods already running keep running: a quota refuses new requests and never evicts. For a workspace,
the refusal lands at its next start, as a `FailedCreate` on its ReplicaSet that DevWorkspace
Operator copies into the DevWorkspace status.

## Rollback

- **`mode: Off`**: every managed object is deleted on the next reconcile. Foreign ones stay.
- **A bigger profile** for a team or a namespace: the surgical answer to "this person needs more".
- A namespace leaving the `namespaceSelector` **keeps** its objects, like every feature here that
  writes objects. `mode: Off` is the cleanup.

## Reading the logs

```text
feature=resource-quotas mode=Enforce ns=user-bob team=team-1 profile=standard result=applied diff=create:weebo-quota,create:weebo-limits
WARN feature=resource-quotas ns=user-bob team=team-1 requested=gpu result=not_granted
WARN feature=resource-quotas ns=user-bob profile=strict result=invalid the quota constrains limits.memory but the LimitRange gives a container that sets none no value for it: every such pod would be refused — profile not applied, the namespace keeps what it has
WARN feature=resource-quotas ns=user-dave foreign_limitranges=1: two sets of container defaults apply
```

## Observability

| Metric | Labels | Read it for |
| --- | --- | --- |
| `weebo_si_resource_quotas_saturation` | `band` | **The alert.** `at_limit > 0`: those namespaces will refuse their next pod, and their users will notice first. |
| `weebo_si_resource_quotas_namespaces` | `profile`, `state` | `applied`/`pending`/`foreign_quota`/`foreign_limitrange`. `foreign_limitrange > 0` means two sets of defaults apply somewhere. |
| `weebo_si_resource_quotas_profiles` | `state` | `invalid > 0`: a configuration edit was rejected and nothing new was applied. |
| `weebo_si_resource_quotas_reconcile_total` | `result` | `applied`/`unchanged`/`deleted`/`not_granted`/`invalid`/`error`. |
| `weebo_si_resource_quotas_selection_changed_total` | none | Changes to the annotation: who is moving between profiles. |

No metric carries a namespace. Per-namespace usage is kube-state-metrics' `kube_resourcequota`
where its cardinality is acceptable.

## Known limitations, specific to this feature

- **A quota per person is not a team budget.** A team of fifty can still use the cluster; a
  pooled budget is RFC 0014's future work.
- **The error lands on a ReplicaSet.** The developer sees a workspace that does not start;
  DevWorkspace Operator's status message is what explains it.
- **Nested containers count**: they are processes in the workspace container, inside its limits.
- **The envtest proves what is written**, not that a pod is refused: without a quota controller,
  the apiserver enforces nothing. The kind e2e checks the refusal.
