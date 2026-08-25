# `weebo-si-operator`

A cluster-scoped operator that pins every `DevWorkspace` it admits to an admin-authored
configuration, so the DevWorkspace Operator config override a user's own DevWorkspace could
otherwise carry never reaches one — `dwoc-pin`, RFC 0002. It also gives every workspace namespace
a `NetworkPolicy` baseline plus admin-granted per-workspace profiles, and protects those objects
from being undone — `network-profiles` and `policy-guard`, RFC 0004. And it decides which
container images a workspace may run at all, per team — `image-policy`, RFC 0005. And it decides
what the process inside that image may do once running — which binaries, which paths, which Linux
capabilities — through KubeArmor, per team: `kubearmor-policy`, RFC 0006.

Design and rationale: [RFC 0002](../rfc/0002-weebo-si-operator.md),
[RFC 0004](../rfc/0004-network-profiles.md), [RFC 0005](../rfc/0005-image-policy.md) and
[RFC 0006](../rfc/0006-kubearmor-policy.md). This page
is the operator's copy — how to install it, roll it out, and roll it back; the RFCs are the *why*
and stay the reference when the two disagree.

Each feature has its own section below with its own install checklist, rollout and rollback.
Everything above those sections is `dwoc-pin`'s and applies to all of them.

> **`failurePolicy: Fail`.** The webhook fails closed: while it is unavailable, no DevWorkspace can
> be created or started, cluster-wide. That is deliberate — see RFC 0002's *Operational
> considerations* — but it means the manifests in `crates/weebo-si-operator/deploy/` are not
> optional extras. Skipping the `PodDisruptionBudget` or the two-replica `Deployment` turns a
> routine node drain into a Che outage.

## Install

Two ways to install, same objects either way — pick one, don't mix them:

- **Helm**: `charts/weebo-si-operator/` — set `certificates.provider` to `cert-manager` (default),
  `openshift`, or `none`, and `image.repository`/`image.tag`. `helm install weebo-si-operator
  charts/weebo-si-operator -n weebo-si-hardening --create-namespace` renders every object below in
  the right order and installs the CRD from the chart's `crds/` directory (Helm installs `crds/`
  once and never manages it after, so a CRD schema change on upgrade still needs `kubectl apply
  -f charts/weebo-si-operator/crds/` by hand — see [Helm's own docs on
  `crds/`](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/)).
- **Raw manifests**: `crates/weebo-si-operator/deploy/`, below. Apply in this order — each step is
  independently reversible, per RFC 0002's *Rollout*:

1. `crd.yaml` — the `WeeboSiConfig` CRD. Generated from `weebo-si-crd`'s Rust types; never
   hand-edit it, `task recu` regenerates it whenever `crates/weebo-si-crd` is part of a commit.
2. `namespace.yaml` — the operator's own namespace, pre-labelled
   `hardening.weebo.io/exclude: "true"` so it never becomes a target of its own webhook.
3. `rbac.yaml` — two `ServiceAccount`s (`weebo-si-operator-webhook`,
   `weebo-si-operator-controller`), never one: the webhook role, the one an untrusted
   `AdmissionReview` body reaches, never holds the `weebosiconfigs/status` write the controller
   role needs.
4. The certificate, one of:
   - **OpenShift**: nothing to apply yet — `mutatingwebhookconfiguration-openshift.yaml` (step 6)
     carries the annotation that makes the platform issue it, once `service.yaml` (step 5) is
     itself annotated. See that file's own comment for the exact `oc annotate` command.
   - **cert-manager**: `certificate-cert-manager.yaml` — brings its own self-signed `Issuer`; swap
     `issuerRef` for a cluster CA if one already exists.

   RFC 0002 has no self-signed fallback of its own: one of these two is a prerequisite, not an
   option to skip.
5. `service.yaml` — the webhook `Service` (port `443` → `9443`) the `MutatingWebhookConfiguration`
   calls back into, and a shared `/metrics` `Service` (`8081`) for both roles.
6. `deployment.yaml` and `pdb.yaml` — both Deployments (two replicas each, pod anti-affinity across
   nodes) and both `PodDisruptionBudget`s. Replace the `image:` placeholder first; this repo has
   no registry decision yet.
7. `mutatingwebhookconfiguration-openshift.yaml` **or** `mutatingwebhookconfiguration-cert-manager.yaml`
   — never both. This is the step that actually puts the webhook in the admission path; nothing
   before it changes any DevWorkspace.

With no `WeeboSiConfig` object created yet, step 7 is still a no-op: `KubeConfigStore` reports
`Off` for every feature until one exists, so every DevWorkspace round-trips through the webhook
unmutated. That is deliberately the state to leave a fresh install in — see *Rollout*, below.

### Before creating a `WeeboSiConfig`

Two things belong on the checklist, not in code — the operator cannot verify either:

- **RBAC on every catalogued namespace.** A catalogue entry must live somewhere users cannot write
  it — the Che namespace or the operator's own. Cataloguing `user-alice/hardened-config` hands the
  attacker the object the control exists to protect.
- **Who may authorize a catalogued entry.** Whoever authors an entry must never be the team it is
  granted to — a team-authored entry granted to itself recreates the DWOC-override hole this
  operator exists to close, one layer up.

And two more, specific to `spec.teams` and `spec.features.dwocPin.namespaceSelection.annotation`:

- **Namespace labels are load-bearing.** A team matches on labels, so labelling a namespace moves
  it onto that team's configuration for *every* feature at once. Confirm who can label a namespace
  in this cluster before writing `spec.teams` — in a Che cluster this is already an admin-only
  operation, the same privilege `hardening.weebo.io/exclude` already relies on.
- **Who may annotate a namespace** decides who can choose within a team's grant. In a Che cluster,
  user namespaces are created by Che and their users hold rights *inside* them, not on the
  `Namespace` object, so this is already admin-only. Where that is not true,
  `namespaceSelection.annotation: ""` removes this step of the resolution chain entirely.

## Usage

```text
weebo-si-operator webhook     [--addr 0.0.0.0:9443] [--cert-dir /etc/webhook/certs]
                               [--metrics-addr :8080] [--health-addr :8081]
                               --operator-identity <system:serviceaccount:ns:name>
weebo-si-operator controller  [--metrics-addr :8080] [--health-addr :8081] [--leader-election]
weebo-si-operator crd         # print the generated CRD YAML — what `task recu` writes
weebo-si-operator features    # print the registry: id, originating RFC, target resource
weebo-si-operator backends    # print which network-profiles backends are compiled in and
                               # which this cluster actually offers
weebo-si-operator backends kubearmor [--verbose]
                               # whether this cluster serves the KubeArmorPolicy CRD, and
                               # (--verbose) which nodes can actually enforce one (RFC 0006)
weebo-si-operator canary      # run the enforcement probe once and report whether this
                               # cluster's CNI actually enforces NetworkPolicy (RFC 0004);
                               # non-zero exit on anything but `enforcing`
weebo-si-operator images platform          # the compiled-in image-policy platform patterns
weebo-si-operator images check <ref>       # parse, normalize and judge one reference
                               [--team <name>] [--namespace <ns>]
weebo-si-operator images audit             # every image running now and the verdict this
                               [--namespace <ns> | --all-namespaces]   # config would give it
```

`canary` and the three `images` subcommands read the cluster with **the invoking kubeconfig**,
not the operator's `ServiceAccount` — `images audit`'s `list pods` is deliberately the admin's
own permission, which is why RFC 0005 adds no RBAC at all.

`--operator-identity` is `policy-guard`'s one exemption — the controller's own
`system:serviceaccount:<namespace>:<name>` identity. The chart renders it for you from its own
`ServiceAccount` naming (`deployment-webhook.yaml`); a raw-manifest install must set it by hand
to match `rbac.yaml`'s controller `ServiceAccount` exactly, or `policy-guard` locks the
controller out of the objects it is responsible for — see RFC 0004's *Operational
considerations*.

`--metrics-addr` is accepted for the CLI contract's sake but not read separately today:
`/healthz`, `/readyz` and `/metrics` are all served together on `--health-addr` — the manifests in
this directory reflect that (one container port, `8081`, for both).

| Code | Meaning |
| --- | --- |
| `0` | clean shutdown |
| `1` | internal error (cache subscription lost, listener cannot bind, certificate unreadable) |
| `2` | usage error |
| `3` | reserved: caches never synced within the readiness deadline (not yet a code path that returns it — see *Known limitations*) |

## Rollout

Five steps, each a write to one `WeeboSiConfig` object, effective on the next admission, no pod
restart:

1. **`spec.features: {}`.** Nothing changes; watch `weebo_si_admission_duration_seconds` to see
   the cost of the round trip alone, and confirm `failurePolicy: Fail` is survivable before
   anything depends on it.
2. **`mode: DryRun`**, catalogue and `default` written, **no `spec.teams` yet**. Watch
   `weebo_si_dwoc_pin_total` and the decision log lines (see *Reading the logs*, below) —
   `result="replaced"` is every workspace that will change behaviour once `Enforce` is flipped.
3. **Add `spec.teams` and the grants, still in `DryRun`.** Read `result` broken down by `team`:
   a namespace routed to the wrong team is invisible in aggregate and obvious per team.
4. **`mode: Enforce`** with a `namespaceSelector` naming a pilot label. One namespace, real pins.
5. **Remove the selector.** Full rollout.

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster                # the only name the operator recognizes — anything else
                                # is ignored and reported Degraded
spec:
  teams:
    - name: team-1
      namespaceSelector:
        matchLabels: { weebo.io/team: team-1 }
  features:
    dwocPin:
      mode: DryRun
      catalog:
        - key: baseline
          name: weebo-hardened-config
          namespace: eclipse-che
        - key: gpu
          name: gpu-config
          namespace: eclipse-che
      default: baseline
      grants:
        team-1: { allowed: [baseline, gpu], default: gpu }
```

## Rollback

Three levels, increasingly blunt:

- **`mode: Off`** — seconds, no restart. The webhook still answers, with an empty patch.
- **Delete the `MutatingWebhookConfiguration`** — the break-glass. It is the only lever that works
  when the operator itself is broken, at `failurePolicy: Fail`. Every admin installing this needs
  to know it exists:

  ```console
  kubectl delete mutatingwebhookconfiguration weebo-si-hardening-devworkspaces
  ```

- **Uninstall.**

**None of them un-pins a workspace.** The attribute and the audit annotation stay until something
rewrites them — reverting policy is not reverting state. Un-pinning is a loop over the annotated
workspaces:

```console
$ kubectl get devworkspaces -A -o json \
    | jq -r '.items[] | select(.metadata.annotations["hardening.weebo.io/dwoc-pin"]) | "\(.metadata.namespace)/\(.metadata.name)"' \
    | while IFS=/ read -r ns name; do
        kubectl patch devworkspace "$name" -n "$ns" --type json -p '[
          {"op": "remove", "path": "/spec/template/attributes/controller.devfile.io~1devworkspace-config"},
          {"op": "remove", "path": "/metadata/annotations/hardening.weebo.io~1dwoc-pin"}
        ]'
      done
  ```

## Reading the logs

One line per admission decision, on stdout, plain text — no framework, matching every other
binary in this repository:

```text
weebo-si-operator: allow namespace=user-alice workspace=python-web current=<none> target=eclipse-che/weebo-hardened-config
weebo-si-operator: allow namespace=user-bob workspace=data-science current=eclipse-che/gpu-config target=<unchanged>
weebo-si-operator: deny namespace=user-carol workspace=custom-config current=<none> reason=the namespace annotation names a catalogue key outside this namespace's grant: gpu
```

Exactly what RFC 0002's *Security considerations* specifies and nothing more: the namespace, the
workspace name, the current and target `DevWorkspaceOperatorConfig` references, and the decision —
**never the object**. A DevWorkspace template carries the user's environment variables and can
carry a token; `weebo-si-webhook`'s own test suite pins this with a regression test asserting the
admitted object's `data` field is read in exactly one place in the whole crate — the JSON Patch
render call, never a log line.

## Observability

| Metric | Type | Labels |
| --- | --- | --- |
| `weebo_si_admission_requests_total` | counter | `feature`, `resource`, `mode`, `outcome` — `resource` is the subject's Kubernetes kind |
| `weebo_si_admission_duration_seconds` | histogram | `feature`, `resource` — the same pair the counter carries |
| `weebo_si_admission_unguarded_total` | counter | `feature`, `path` — requests a guard allowed **without checking**, because it does not know the resource |
| `weebo_si_feature_mode` | gauge | `feature` |
| `weebo_si_dwoc_pin_total` | counter | `result`, `team` |
| `weebo_si_dwoc_pin_catalog_entries` | gauge | `state` ∈ `resolvable`/`missing` |
| `weebo_si_config_observed_generation` | gauge | — |

Both admission metrics take `resource` from the subject the decision was made about
(`Subject::resource()`), so they always agree: every `weebo_si_admission_duration_seconds`
series has a `weebo_si_admission_requests_total` series with the same `feature` and `resource`.
The values are Kubernetes kinds as they appear in a manifest — `DevWorkspace`, `Pod`,
`NetworkPolicy`, `CiliumNetworkPolicy`, `KubeArmorPolicy`, `ConfigMap`, `Secret`.

> **If you are reading a dashboard built before 2026-08-25**, it may assume otherwise:
> `weebo_si_admission_requests_total`'s `resource` label was written as the literal
> `DevWorkspace` on every route, for every feature, so a `policy-guard` denial and a `dwoc-pin`
> patch landed on the same series. Anything summing that metric is unaffected; anything
> filtering or grouping by `resource` was silently wrong and is now right. Found while
> implementing RFC 0008.

**`weebo_si_admission_unguarded_total > 0` should alert, and it means one specific thing:** a
`ValidatingWebhookConfiguration` rule routes a resource to a guard handler that has no case for
it, so writes to that resource are being **allowed unchecked** while the chart says they are
guarded. It is a chart-versus-code drift, not an attack, and it is normally zero forever — the
guard's own rules and its enum are changed together. The `WARN` line beside each increment names
the group and resource:

```text
WARN weebo-si-webhook: policy-guard allow-unguarded path=/validate/v1/networkpolicies group=cilium.io resource=ciliumclusterwidenetworkpolicies namespace=user-alice operation=Create reason=resource_not_guarded — a webhook rule routes this resource here but GuardedResource has no variant for it; the write was NOT checked
```

Allowing rather than denying is deliberate: a guard protects objects this operator wrote, and it
did not write that one — denying every unrecognised resource would turn a typo in a chart rule
into a cluster-wide outage on whatever it typo'd. The fix is to add the enum variant (and the
metric label value it brings), or to remove the rule.

`weebo_si_admission_requests_total{outcome="error"}` is the first alert to wire: at `Fail`, a
nonzero rate is user-visible failures. `result="target_missing"` is the second — the feature is
doing nothing while `Active`. A `Degraded` condition on the `WeeboSiConfig` object itself means a
grant or a catalogue entry is broken; `kubectl describe weebosiconfig cluster` names which one.

## RFC 0004: `network-profiles` and `policy-guard`

### Install checklist

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

### Rollout

Six steps, and the order between the two features is not interchangeable — see RFC 0004's own
*Operational considerations* for the full argument, condensed here:

1. Install with both features absent from `spec.features`. Run `weebo-si-operator backends`
   against the target cluster.
2. `networkProfiles: {mode: DryRun, ...}`, catalogue and `baseline` written, no `grants`. Every
   namespace's reconcile log line (`weebo-si-controller: network-profiles namespace=... diffs=...
   applied=None`) should show one `Diff::Create` — the baseline — and nothing else.
3. Add `grants`, still `DryRun`. Read the diff per namespace/team before trusting it.
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

### Rollback

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

### Reading the logs

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

### The enforcement canary

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

### Observability

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

## RFC 0005: `image-policy`

Which container images a workspace is permitted to run, per team. One feature, two enforcement
points with deliberately different precision: a validating webhook on `DevWorkspace` gives the
developer a readable error at `kubectl apply` time and enforces the exact per-workspace
selection, and a validating webhook on `Pod` is the floor that catches the images DevWorkspace
Operator injects, the plugin sidecars a devfile pulls in by URI, and any pod created without a
workspace at all.

Both report the same feature id, so **one `mode` and one `namespaceSelector` govern both**.

### Install checklist

Four questions, and the first one is not optional.

- **What is actually running right now?** Run `weebo-si-operator images audit
  --all-namespaces` **before installing anything**. This is step 0 of the rollout and the one
  step no other feature in this repo has: a catalogue written from what is running beats one
  guessed and then discovered one denial at a time. Every `DENIED` row is a workspace that stops
  starting at `Enforce`.
- **`failurePolicy` for the `pods` webhook** — `imagePolicy.podWebhook.failurePolicy` in
  `values.yaml`, `Fail` by default. At `Fail`, an unavailable operator means **no pod is created
  in any workspace namespace, including rescheduling**: a node drains and its workspace pods do
  not come back until the operator does. At `Ignore`, the bypass is two steps — make the webhook
  unavailable, create the pod — and the Pod half is the *only* layer that sees injected images at
  all. This is a decision for whoever carries the pager. The `DevWorkspace` webhook is
  hard-coded to `Fail` and has no such switch; RFC 0002 already settled that argument.
- **Which namespaces are workspace namespaces** — the `pods` webhook only reaches namespaces
  carrying `hardening.weebo.io/workspace-namespace`, the same label `policy-guard` already
  depends on. A namespace missing it is a namespace the floor never sees. The `DevWorkspace`
  webhook has the *opposite* polarity (opt-out on `hardening.weebo.io/exclude`), on purpose:
  every `DevWorkspace` is a workspace by definition, so a namespace reached by accident there is
  one that got hardened, while a mis-scoped deny-pods webhook is a cluster outage.
- **Is your registry a pull-through cache?** If `registry.internal` proxies Docker Hub, then
  `registry.internal/**` permits Docker Hub through a name that looks internal. Nothing in this
  feature can detect that — an admin whose registry does this needs a narrower *path* pattern
  rather than a host pattern. This is the most likely way for this control to be believed while
  doing nothing.

And one more, **only if you declare `spec.features.imagePolicy.variables`**:

- **Can a workspace user annotate their own namespace?**

  ```console
  kubectl auth can-i patch namespace/<user-ns> --as=<workspace-user>
  ```

  A declared variable's value is a namespace annotation. If the answer is `no` — as it is in the
  Che installation this repo targets — `registry.internal/projects/{PROJECT}/**` is a real
  allow-list. If the answer is `yes`, the same configuration is an allow-list the constrained
  party fills in, and **it degrades silently**: every verdict still reads `allowed`, no condition
  is raised, and nothing about the CRD looks different. The value is still validated as a single
  path component, so the failure is "reaches another project's path", not "reaches every
  registry" — and
  `rate(weebo_si_image_policy_variable_changed_total[15m])` is the alert that tells you the day
  the answer changes. The two built-in variables carry none of this: `{TEAM_NAME}` comes from
  `spec.teams` and `{NAMESPACE}` from the apiserver's own naming, and neither is reachable by a
  workspace user under any RBAC.

### Usage

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiConfig
metadata:
  name: cluster
spec:
  teams:
    - name: team-1
      namespaceSelector:
        matchLabels: {weebo.io/team: team-1}
  features:
    imagePolicy:
      mode: DryRun
      variables:
        PROJECT:
          fromNamespaceAnnotation: weebo.io/project
      catalog:
        - key: internal
          patterns: ["registry.internal/shared/**"]
        - key: team-registry            # one entry, every team, no copy per team
          patterns: ["registry.internal/teams/{TEAM_NAME}/**"]
        - key: project-registry
          patterns: ["registry.internal/projects/{PROJECT}/**"]
        - key: devfile-udi
          patterns: ["quay.io/devfile/universal-developer-image:ubi9-*"]
      default: [internal]               # a namespace belonging to no team
      grants:
        team-1:
          allowed: [internal, team-registry, devfile-udi]
          default: [internal, team-registry]
      platform:
        builtin: true                   # the images Che and DWO inject — always allowed
```

A developer asks for a wider entry in the devfile, so the request travels with the project rather
than with the person:

```yaml
schemaVersion: 2.2.0
metadata:
  name: data-pipeline
attributes:
  hardening.weebo.io/image-policy: "internal,devfile-udi"
```

Three CLI commands, all of which read the cluster with **your** kubeconfig rather than the
operator's service account:

```console
weebo-si-operator images platform          # the compiled-in always-allowed patterns
weebo-si-operator images check nginx --team team-1
weebo-si-operator images audit --all-namespaces
```

`images check` exists so an admin can *see* the normalization rather than infer it. The string a
user types and the image a kubelet pulls are related by rules nobody has in their head — `nginx`
is `docker.io/library/nginx:latest`, `REGISTRY.INTERNAL/x` lowercases, `internal/weebo/dev` is
*not* a host because it has no dot and no port — and a control that judged the typed string
instead of the pulled image would be a bypass generator:

```console
$ weebo-si-operator images check registry.internal/teams/team-1/dev-java:21 --team team-1
reference  registry.internal/teams/team-1/dev-java:21
normalized registry.internal/teams/team-1/dev-java:21
           host=registry.internal path=teams/team-1/dev-java tag=21 digest=<none>
patterns   registry.internal/teams/{TEAM_NAME}/**  ->  registry.internal/teams/team-1/**
verdict    permitted by entry team-registry
```

The `patterns` line is not decoration: a pattern that interpolates is one you cannot check by
reading, so the command prints what it became.

### Rollout

Six steps. Step 0 is the valuable one.

0. **`weebo-si-operator images audit --all-namespaces`, before installing anything.**
1. Install the webhook configurations with no `imagePolicy` block. Nothing changes beyond a no-op
   round trip — watch `weebo_si_admission_duration_seconds{resource="Pod"}` specifically. Pod
   volume is not workspace volume, and this is the step that proves `Fail` is survivable on the
   busier of the two resources.
2. `mode: DryRun`, `catalog` and `default` written, **no teams**. The number that matters is
   `weebo_si_image_policy_total{result="denied"}` — every one is a workspace that will stop
   starting. `platform_total` is the second: if it is large, the platform list is doing more work
   than expected and deserves a look before it is depended on.
3. Add `spec.teams` and the `grants`, still `DryRun`. `result` broken down by `team` is how you
   confirm the routing — a namespace routed to the wrong team is invisible in aggregate and
   obvious per team.
4. `mode: Enforce` with a `namespaceSelector` on a pilot label. One namespace, real denials, and
   **then start a workspace in it**.
5. Remove the selector.

Steps 2 through 5 are writes to one resource, effective on the next admission, with no rollout.

### Rollback

Four levels, in the order to reach for them:

- **`mode: Off`** — seconds, no restart. Both webhooks still answer, and answer `allowed`.
- **Widen the grant, or add a catalogue entry** — the surgical undo, and the one that fits the
  most likely incident, which is not "the feature is broken" but "one team needs one more image".
- **Delete the two `ValidatingWebhookConfiguration`s** — the break-glass, and at `failurePolicy:
  Fail` the only lever that works when the operator itself is the broken thing:

  ```console
  kubectl delete validatingwebhookconfiguration \
    <release>-weebo-si-operator-devworkspaces-validate \
    <release>-weebo-si-operator-pods
  ```

  For the Pod half this is the difference between a bad afternoon and a cluster whose workspaces
  cannot be rescheduled. It belongs next to RFC 0002's "delete the MutatingWebhookConfiguration"
  and RFC 0004's labelled-delete break-glass — an admin who installs this needs to know all three
  before they need any.
- **Uninstall.**

Unlike RFC 0002's, **rollback here restores the state as well as the policy**, because this
feature writes nothing: the pods that were denied were never created, and the pods that exist were
never modified.

### The upgrade that actually breaks this is Che's, not ours

The compiled-in platform set tracks DevWorkspace Operator and che-code. A Che upgrade that changes
an injected image is, at `Enforce`, a fleet that stops starting — and it is the single most likely
operational failure of this feature. Three mitigations, in order:

1. Run `weebo-si-operator images audit --all-namespaces` **before a Che upgrade** as well as
   before installation. It names the new image before anything is applied.
2. `platform.extra` is the one-line fix, and it needs no operator release.
3. The denial is loud in `weebo_si_image_policy_total{result="denied", resource="pod"}`, which is
   otherwise flat. A spike there with no corresponding `devworkspace` movement is the signature.

### Reading the logs

```text
weebo-si-webhook: image-policy allow resource=devworkspace namespace=user-alice
  subject="data-pipeline" images=3
weebo-si-webhook: image-policy deny resource=pod namespace=user-bob subject="scratch-abc123"
  images=2 reason=container "sidecar": image "ghcr.io/someone/tool:main" is not permitted ...
```

`resource=devworkspace` denials are developers naming images; `resource=pod` denials are the
platform, and are the ones an admin needs to look at rather than the developer. The image
reference is the only attacker-controlled value that reaches a log line, and it is quoted,
escaped and length-bounded before it does — a control that can be made to write arbitrary bytes
into an operator's log stream has traded one problem for another.

The object itself is never logged, per RFC 0002's rule: a `DevWorkspace` template carries the
user's environment variables and can carry a token, and a `Pod` spec carries more.

### Observability

Every metric in RFC 0005's *Observability contract* is wired.

| Metric | Type | Labels | Where it comes from |
| --- | --- | --- | --- |
| `weebo_si_image_policy_total` | counter | `result` ∈ `allowed`/`denied`/`not_granted`/`unparseable`, `resource` ∈ `devworkspace`/`pod`, `team` | admission |
| `weebo_si_image_policy_platform_total` | counter | `resource` — permitted only by the platform set | admission |
| `weebo_si_image_policy_catalog_entries` | gauge | `state` ∈ `valid`/`invalid` | config sync |
| `weebo_si_image_policy_variable_total` | counter | `variable`, `result` ∈ `resolved`/`undefined`/`illegal` | admission |
| `weebo_si_image_policy_variable_changed_total` | counter | `variable` | namespace read |

Three are worth an alert:

- **`rate(weebo_si_image_policy_total{result="denied"}[15m])`** — at `Enforce` this is
  user-visible failure, either a real policy hit or a catalogue that is missing something. Break
  it down by `resource` to know which.
- **`rate(weebo_si_image_policy_total{result="unparseable"}[15m])`** — should be flat at zero
  forever. Nonzero is either a client we have never seen or someone probing the parser.
- **`rate(weebo_si_image_policy_variable_changed_total[15m])`**, wherever `variables` is
  declared — the only alert in this repo that watches an **assumption** rather than a behaviour.
  Expect zero between deliberate admin edits. A sustained rate is an RBAC regression to go and
  verify with the checklist command above, not a metrics problem.

`weebo_si_image_policy_catalog_entries{state="invalid"}` is the configuration-side view: it fires
on a pattern that stopped parsing after an edit, even in a team whose workspaces nobody has
restarted. A `Degraded` condition on the CRD carries the reason.

**No metric carries an image reference, and none carries a variable's value.** Both are
attacker-influenced and unbounded, so a per-image time series is how a metrics backend is taken
down by a hardening component. The reference lives in the log line and the API error, which are
the two places it is useful. From the apiserver's side,
`apiserver_admission_webhook_rejection_count{name="images.hardening.weebo.io"}` is the ground
truth and belongs on the same dashboard — ours cannot report a request that never arrived.

### This feature adds no RBAC

No verb, no resource, no `Role`, no `ClusterRole` rule, in either role. Both subjects arrive in
the admission body and the only lookup either route makes is the `namespaces` watch that already
existed. `images audit`'s `list pods` is *your* permission, exercised from your kubeconfig. **The
role an untrusted `AdmissionReview` body reaches is unchanged by RFC 0005.**

### What this does and does not close

Worth reading before quoting this feature in a compliance answer:

- **It is a control over names, not over content.** A permitted
  `quay.io/devfile/udi:ubi9-latest` says nothing about what those bytes are today. Anyone who can
  push that tag has pushed into every workspace using it, and this feature reports `allowed`. It
  closes "run something nobody catalogued", not "run something that changed under you".
- **The per-workspace attribute is least privilege, not an authorization boundary.** A user whose
  team is granted an entry can give any of their workspaces that entry, by editing a devfile. The
  boundary is the *grant*, and only a cluster admin writes grants.
- **The Pod half enforces the team boundary, not the per-workspace selection.** A workspace
  running an image its team allows but its own selection excluded is not caught at the pod. That
  is a policy nicety, not a security boundary — and it is what buys the feature its zero-RBAC,
  zero-cache footprint.

## RFC 0006: `kubearmor-policy`

Everything above this line decides what a workspace may *reach* and which image it may *run*.
This feature decides what the process inside that image may *do* on the node it lands on — which
binaries it may execute, which paths it may touch, which capabilities it may use — per team,
through [KubeArmor](https://kubearmor.io/).

**It is the first control in this operator whose enforcement is a property of the node, not the
cluster.** A `KubeArmorPolicy` this operator writes is enforced only where KubeArmor found a
usable LSM (BPF-LSM, AppArmor, or SELinux). On a node without one, KubeArmor's documented
behaviour is to run in visibility-only mode: the object exists, the events flow, and `Block`
rules do not block. This operator does not override that — it makes it visible. Read
*Observability* below before you rely on this feature for anything.

### Install checklist

1. **KubeArmor is installed and its CRDs are served.** This operator does not install it. Check
   with the CLI:

   ```bash
   weebo-si-operator backends kubearmor --verbose
   ```

   The first table answers "does this cluster serve `KubeArmorPolicy`" — the cluster-wide
   question. The second answers "which nodes can actually enforce one" — the per-node question.
   They are different questions and a cluster can pass the first and fail the second on half its
   fleet. Run this before switching anything on.

   If the CRD is absent, the controller logs `kubearmor-policy is inert` at boot and starts none
   of its watches. That is a supported state: the feature simply does not run there.

2. **Grant the RBAC.** Off by default, because granting write on a CRD a cluster does not have is
   a permission nobody can use and everybody has to review:

   ```bash
   helm upgrade weebo-si-operator charts/weebo-si-operator \
     -n weebo-si-hardening --set kubearmorPolicy.rbac.enabled=true
   ```

   This adds, on the controller role only: write on `kubearmorpolicies` cluster-wide, `patch` on
   `namespaces` (for KubeArmor's three posture annotations), and read on `nodes` and `pods`. The
   last two are this project's first cluster-scoped reads outside its own CRD — see *What this
   reads* below.

3. **Author the templates.** Ordinary `KubeArmorPolicy` objects in `weebo-si-hardening`, exactly
   as `network-profiles`' templates are ordinary `NetworkPolicy` objects. Their own `selector` is
   ignored and stripped — scoping belongs to the operator — so write whatever is convenient there.

   ```yaml
   apiVersion: security.kubearmor.com/v1
   kind: KubeArmorPolicy
   metadata:
     name: weebo-base-runtime
     namespace: weebo-si-hardening
   spec:
     selector:
       matchLabels: {}          # ignored and stripped; the operator rewrites it
     process:
       matchPaths:
         - path: /usr/bin/git
           action: Audit
   ```

   **Start every rule at `action: Audit`.** KubeArmor's per-rule action gives you a second dry run
   *inside* the template, and the first rollout should use both it and `mode: DryRun`.

4. **Configure the feature**, starting at `DryRun`:

   ```yaml
   features:
     kubearmorPolicy:
       mode: DryRun
       catalog:
         - key: base
           templateRef: { name: weebo-base-runtime, namespace: weebo-si-hardening }
         - key: git-write
           templateRef: { name: weebo-git-write-runtime, namespace: weebo-si-hardening }
       baseline: base
       grants:
         team-1:
           allowed: [git-write]
           default: [git-write]
       onNotGranted: Default
       enforcement:
         backend: Auto
         defaultPosture:
           file: Audit
           network: Audit
           capabilities: Audit
   ```

   `defaultPosture` is what KubeArmor does with an operation **no rule matched**, written onto
   each namespace as its three `kubearmor-*-posture` annotations. There are three, not four:
   process rules are evaluated under the *file* posture. All three default to `Audit`, and moving
   one to `Block` is the single most consequential edit in this feature — it denies everything the
   template did not think to allow, which for a workspace container is most of what it does.

### What gets written

| Object | One per | Name | Selector |
| --- | --- | --- | --- |
| `KubeArmorPolicy` | namespace in scope | `weebo-base` | `matchLabels: {}` — every pod |
| `KubeArmorPolicy` | workspace × granted key | `weebo-<key>-<devworkspace-id>` | that workspace's pods |
| namespace annotations | namespace in scope | `kubearmor-{file,network,capabilities}-posture` | — |

Everything carries `hardening.weebo.io/managed-by: weebo-si-operator`, and the operator only ever
reads, updates or deletes objects that do.

### Rollout

1. `mode: DryRun`, ideally behind `namespaceSelector` scoped to one pilot team. Read
   `weebo_si_kubearmor_reconcile_total{result="dry_run"}` and the per-namespace log line.
2. `mode: Enforce` with every template rule still at `action: Audit`. Objects are now real,
   postures are written, and nothing is denied yet. Watch `kubearmor-relay`'s event stream for
   what *would* have been blocked — this is the phase that finds the rule you did not know your
   workspaces needed.
3. Flip individual rules to `action: Block` in the templates, narrowest first. A template edit is
   picked up on the next reconcile pass; a running workspace's policy is updated in place.
4. Only then consider `defaultPosture.file: Block`, and only for a team whose audit stream has
   been quiet for a while.

### Rollback

- **One profile is wrong**: edit or delete the template object. Fastest, and needs no
  `WeeboSiConfig` edit.
- **The feature is wrong**: `mode: Off`. The reconciler deletes everything it manages on the next
  pass. Namespace posture annotations are **not** removed — they are KubeArmor's own field and
  removing them would be a second guess about what the namespace should do without us.
- **Break glass**: `helm upgrade --set kubearmorPolicy.rbac.enabled=false` removes the write
  permission entirely. Existing objects stay; nothing can change them.

### Reading the logs

```text
weebo-si-controller: kubearmor-policy namespace=user-alice mode=Enforce diffs=1
  applied=Some(Applied { created: 1, ... }) posture=file=audit,network=audit,capabilities=audit
weebo-si-controller: kubearmor-policy workspace=user-alice/data-pipeline mode=Enforce diffs=1
  applied=Some(Applied { created: 1, ... })
WARN weebo-si-controller: feature=kubearmor-policy team=team-2 workspace=scratch
  requested=[net-raw] result=not_granted
WARN weebo-si-controller: feature=kubearmor-policy namespace=user-alice
  workspace_id=workspacede4f56 result=not_enforced — policy objects exist and the node hosting
  this workspace reports no usable LSM
```

That last line is the one to page on the first time you see it, and the reason the per-workspace
answer lives in a log line rather than a metric label — see below.

### Observability

| Metric | Type | Labels | Where it comes from |
| --- | --- | --- | --- |
| `weebo_si_kubearmor_reconcile_total` | counter | `result` ∈ `created`/`updated`/`unchanged`/`deleted`/`dry_run`/`error`, `team` | reconcile |
| `weebo_si_kubearmor_managed_objects` | gauge | `kind`, `scope` ∈ `baseline`/`profile` | 30s tick |
| `weebo_si_kubearmor_drift_total` | counter | `action` ∈ `restored`/`removed` | reconcile |
| `weebo_si_kubearmor_enforced` | gauge | `state` ∈ `enforced`/`not_enforced`/`unknown` | 60s tick |
| `weebo_si_kubearmor_not_granted_total` | counter | `team`, `profile` | reconcile |
| `weebo_si_feature_mode{feature="kubearmor-policy"}` | gauge | `feature` | config sync |

**`weebo_si_kubearmor_enforced{state="not_enforced"} > 0` is the alert this feature exists to
make possible.** It counts workspaces whose policy objects are present on a node that reports no
usable enforcer — the gap KubeArmor fails open into, made visible. All three states are always
published, including the zeroes, so the query reads `0` rather than *absent* on a healthy cluster.

It counts workspaces rather than naming one: RFC 0004's observability rule ("no metric carries a
namespace or a workspace id as a label") binds every brick here, and a per-workspace time series
is how a metrics backend is taken down by a hardening component. Which workspace is unenforced is
the `WARN` line above, plus `kubectl get pod -o wide`. RFC 0006 originally specified
`weebo_si_kubearmor_enforced{namespace,workspace}`; it was amended during implementation.

`state="unknown"` is not a failure — it is a workspace with no scheduled pod, or one on a node
not yet in the cache. It is deliberately not folded into `not_enforced`: "we have not looked"
and "we looked and there is nothing there" are different claims and only the second should page.

### What this reads

Two read-only watches this project never needed before, both projected before anything is stored:

- **`pods`**, filtered server-side to workspace pods, projected to `{namespace, workspace_id,
  nodeName}`. The spec is dropped in the watch stream — no env, no volumes, no containers.
- **`nodes`**, cluster-scoped, projected to the `kubearmor.io/enforcer` label alone.

Kubernetes RBAC has no field-level grant for either, so that narrowing lives in
`crates/weebo-si-runtime/src/node_enforcer.rs` and is reviewed as code — the same trade this
project already accepts for `NamespaceFacts`.

### Known limitations, specific to this feature

- **A policy object is not enforcement.** Covered above; it is the whole reason for the
  `enforced` gauge. On a cluster whose nodes have no LSM, this feature is an audit trail.
- **The objects are guarded; the posture annotations are not.** `policy-guard` covers
  `kubearmorpolicies` since RFC 0008 — turn on `kubearmorPolicy.rbac.enabled` and the rule is
  rendered with the RBAC grant. What it does *not* cover is the three `kubearmor-*-posture`
  annotations this feature writes onto workspace namespaces: a namespace carries no ownership
  label, and the guard is object-scoped. A user who can annotate their own namespace can move
  their posture from `Block` back to `Audit`. That is visible in the reconcile log and corrected
  on the next pass; guarding it would mean a webhook in front of every namespace write in the
  cluster, which RFC 0008 decided against.
- **The store still force-applies, and that is deliberate.** With the guard on, no conflicting
  field manager should ever be created — but an object edited *before* the guard was installed
  already has one, and without force that object is wedged forever on a 409. The guard prevents
  new conflicts; force is what recovers from old ones.
- **`enableEnforcerPerPod` clusters are only partly accounted for.** Where KubeArmor is installed
  in that mode, a per-pod `kubearmor-policy: disabled` annotation opts a pod out, and this
  operator neither sets nor reads it — such a pod reads back as `not_enforced`, indistinguishable
  from a node with no LSM.
- **Posture annotations are written but never removed.** `mode: Off` deletes the policy objects
  and leaves the namespace's posture as it was.
- **The envtest suite proves what we write, not what KubeArmor does with it.** It runs against a
  stand-in CRD with no daemonset behind it. The baseline's `selector.matchLabels: {}` is
  confirmed to mean "every pod in this namespace" to KubeArmor; the posture annotations' effect
  on a real deployment is not yet confirmed here, and is RFC 0006's own outstanding item.

## RFC 0007: `registry-config`

Everything above this line **narrows** what a workspace may do. This one **adds** something: the
`.npmrc`, the `pip.conf`, the Cargo `config.toml`, the Maven `settings.xml` a workspace needs to
resolve packages from the internal mirror, copied into every workspace namespace of a team.

**It is not a control, and reading it as one is the mistake this section exists to prevent.**
Nothing here stops a developer pointing a build at any registry they like: a project-local
`.npmrc` beats the user-level one npm reads, `pip install -i` beats `pip.conf`, `mvn -s` beats
`~/.m2/settings.xml`. What stops the alternative registry from *answering* is `network-profiles`'
egress baseline. The two go together: `registry-config` without `network-profiles` is a
convenience, and `network-profiles` without `registry-config` is a support ticket — the moment
the baseline is real, `npm install` stops working and nothing in the container knows why.

### Install checklist

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
       grants:
         team-1:
           allowed: [internal-npm]
           default: [internal-npm]
       onNotGranted: Default
   ```

   **There is no `baseline` field.** A cluster with one mirror for everyone expresses that as a
   grant every team has. "Mandatory" would mean writing a file into a container whose image may
   not have the tool it configures.

### Before you put a `Secret` in the catalogue

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

### What gets written

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

### Rollout

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

### Rollback

- Flip `mode` to `Off`: the reconciler deletes what it manages on the next pass. Running
  workspaces keep the copies the kubelet already mounted until they restart.
- Faster, for one bad entry: edit or delete the template object. Templates are ordinary objects an
  admin already has RBAC on.
- Fastest, for one namespace: remove its selection annotation.

### A mounted change needs a workspace restart

Editing a template propagates to the copies on the next reconcile, but a running container keeps
what it was given: environment variables never update, and file mounts update on the kubelet's own
schedule into a process that has already read the file. **The operational rule is "rotate the
token, then tell people to restart their workspace"** — it belongs in the runbook rather than
being discovered during an incident.

### The guard rule is shaped differently, on purpose

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

### Reading the logs

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

### Observability

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

### Known limitations, specific to this feature

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

## Known limitations

- **Exit code `3`** ("caches never synced within the readiness deadline") is reserved but not yet
  a code path any binary returns — `/readyz` correctly reports not-ready while a cache is
  syncing, but the process does not yet time out and exit on its own if one never does.
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

RFC 0005's, specifically:

- **`image-policy` never contacts a registry**, so it cannot verify a signature, an attestation
  or a digest. It judges names. `requireDigest` and signature verification are both named in that
  RFC's *Future work*, and the second is Kyverno's or Sigstore's job rather than ours.
- **Workspaces and pods that predate installation are untouched.** Admission is not retroactive.
  The same gap is open in RFC 0002 and RFC 0004, and all three want one drift reconciler rather
  than three.
- **`spec.template.components[].plugin` and `spec.contributions[]` are not read** at the
  `DevWorkspace` layer. DevWorkspace Operator resolves them to images long after admission, so
  they are caught at the pod — with the worse error message, deliberately, because that is the
  case where the good message was never available.
- **A pattern that interpolates is not reviewable by reading the CRD.**
  `registry.internal/teams/{TEAM_NAME}/**` means something different in every namespace, so "what
  may this team run" becomes a question with a namespace-shaped argument. `images check` prints
  the interpolated pattern and `images audit` reports `VARIES` per namespace when verdicts
  differ, but there is no rendered "effective permission" report yet.
- **`Auto`-style catalogue validation is reconcile-time, not write-time.** A catalogue with an
  unparseable pattern is reported as `Degraded` and via
  `weebo_si_image_policy_catalog_entries{state="invalid"}` afterwards, rather than rejected at
  `kubectl apply`. A validating webhook on our own CRD is shared *Future work* with RFC 0002.
