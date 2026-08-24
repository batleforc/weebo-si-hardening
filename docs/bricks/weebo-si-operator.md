# `weebo-si-operator`

A cluster-scoped operator that pins every `DevWorkspace` it admits to an admin-authored
configuration, so the DevWorkspace Operator config override a user's own DevWorkspace could
otherwise carry never reaches one — `dwoc-pin`, RFC 0002. It also gives every workspace namespace
a `NetworkPolicy` baseline plus admin-granted per-workspace profiles, and protects those objects
from being undone — `network-profiles` and `policy-guard`, RFC 0004.

Design and rationale: [RFC 0002](../rfc/0002-weebo-si-operator.md) and
[RFC 0004](../rfc/0004-network-profiles.md). This page is the operator's copy — how to install
it, roll it out, and roll it back; the RFCs are the *why* and stay the reference when the two
disagree.

> **RFC 0004 is partially implemented.** The domain logic, the kube adapters
> (`KubePolicyStore`/`KubeTemplateStore`/`KubeCapabilities`), the two controller reconcile loops,
> `policy-guard`'s admission adapter, and the RBAC/`ValidatingWebhookConfiguration` manifests are
> in and covered by a real-apiserver test suite (`crates/weebo-si-runtime/tests/envtest.rs`). The
> canary, the `DevWorkspace` `CREATE` rejection for a namespace with no baseline yet, and the
> `backends` subcommand's sibling `canary` subcommand are **not implemented** — see RFC 0004's own
> *Implementation plan* for the current checklist. Do not enable `networkProfiles`/`policyGuard`
> in `Enforce` on a production cluster until those land; `DryRun` is safe today.

<!-- -->

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
```

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
| `weebo_si_admission_requests_total` | counter | `feature`, `resource`, `mode`, `outcome` |
| `weebo_si_admission_duration_seconds` | histogram | `feature`, `resource` |
| `weebo_si_feature_mode` | gauge | `feature` |
| `weebo_si_dwoc_pin_total` | counter | `result`, `team` |
| `weebo_si_dwoc_pin_catalog_entries` | gauge | `state` ∈ `resolvable`/`missing` |
| `weebo_si_config_observed_generation` | gauge | — |

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
6. **Only then** `policyGuard: {mode: Enforce}`.

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
  namespace. Do this first, always — it is what makes manual repair possible.
- **`networkProfiles: mode: Off`** — deletes every managed object the controller reconciles away.
  Unlike `dwoc-pin`'s rollback, this changes cluster state: a namespace left with a `Enforce`-era
  baseline and nothing reconciling it is a namespace nobody can fix.
- **The break-glass**, when the operator itself is what is broken:

  ```console
  kubectl delete networkpolicy -A -l hardening.weebo.io/managed-by=weebo-si-operator
  kubectl delete ciliumnetworkpolicy -A -l hardening.weebo.io/managed-by=weebo-si-operator
  kubectl delete validatingwebhookconfiguration weebo-si-hardening-policies
  ```

### Reading the logs

```text
weebo-si-controller: network-profiles namespace=user-alice mode=Enforce diffs=1 applied=Some(Applied { created: 1, updated: 0, deleted: 0, unchanged: 0 })
weebo-si-controller: network-profiles workspace=user-alice/data-pipeline mode=Enforce diffs=2 applied=Some(Applied { created: 2, updated: 0, deleted: 0, unchanged: 0 })
weebo-si-webhook: policy-guard deny namespace=user-alice actor=system:serviceaccount:user-alice:default operation=Delete reason=user-alice/Delete is managed by weebo-si-operator and may not be touched by system:serviceaccount:user-alice:default
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
| `weebo_si_admission_duration_seconds` | histogram | `feature`, `resource` — `dwoc-pin`, `network-profiles` and `policy-guard` each label their own share | webhook |
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
