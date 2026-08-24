# `weebo-si-operator`

A cluster-scoped operator that pins every `DevWorkspace` it admits to an admin-authored
configuration, so the DevWorkspace Operator config override a user's own DevWorkspace could
otherwise carry never reaches one. One implemented feature so far, `dwoc-pin`.

Design and rationale: [RFC 0002](../rfc/0002-weebo-si-operator.md). This page is the operator's
copy — how to install it, roll it out, and roll it back; the RFC is the *why* and stays the
reference when the two disagree.

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
weebo-si-operator controller  [--metrics-addr :8080] [--health-addr :8081] [--leader-election]
weebo-si-operator crd         # print the generated CRD YAML — what `task recu` writes
weebo-si-operator features    # print the registry: id, originating RFC, target resource
```

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

## Known limitations

- **Exit code `3`** ("caches never synced within the readiness deadline") is reserved but not yet
  a code path any binary returns — `/readyz` correctly reports not-ready while a cache is
  syncing, but the process does not yet time out and exit on its own if one never does.
