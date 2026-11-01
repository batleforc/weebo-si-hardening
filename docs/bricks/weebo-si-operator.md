# `weebo-si-operator`

One binary, two roles — an admission webhook and a controller — carrying every runtime
hardening feature of the platform. Each feature is switched on, per namespace, by one field of the
cluster-wide `WeeboSiConfig` singleton, and nothing happens until it is.

| Feature | What it does | Page | RFC |
| --- | --- | --- | --- |
| `dwoc-pin` | Pins every `DevWorkspace` to an admin-authored DevWorkspace Operator config | this page | [0002](../rfc/0002-weebo-si-operator.md) |
| `network-profiles` | `NetworkPolicy`/`CiliumNetworkPolicy` baseline and granted profiles per workspace namespace | [`network-profiles.md`](./network-profiles.md) | [0004](../rfc/0004-network-profiles.md) |
| `policy-guard` | Refuses anyone but the operator a write to the policies it owns | [`network-profiles.md`](./network-profiles.md) | [0004](../rfc/0004-network-profiles.md), [0008](../rfc/0008-policy-guard-coverage.md) |
| `image-policy` | Which container images a workspace may run, per team | [`image-policy.md`](./image-policy.md) | [0005](../rfc/0005-image-policy.md) |
| `kubearmor-policy` | What the process inside the image may do, through KubeArmor | [`kubearmor-policy.md`](./kubearmor-policy.md) | [0006](../rfc/0006-kubearmor-policy.md) |
| `registry-config` | Package-manager configuration copied into every workspace namespace of a team | [`registry-config.md`](./registry-config.md) | [0007](../rfc/0007-registry-config.md) |
| `endpoint-auth` | Who may reach a workspace endpoint on its own FQDN | [`endpoint-gateway.md`](./endpoint-gateway.md) | [0009](../rfc/0009-endpoint-auth.md) |
| `identity` | The Authentik account and Argo CD application a `WeeboSiUser` maps to | [`teams-and-users.md`](./teams-and-users.md) | [0011](../rfc/0011-teams-and-users.md) |

This page is the operator's copy — how to install it, roll it out, and roll it back; the RFCs are
the *why* and stay the reference when the two disagree. Everything here applies to every feature;
the rollout, rollback, logs and metrics sections use `dwoc-pin` as their example because it was
the first feature and has no page of its own. How the binary is built inside — the crates, the
two roles, how an admission request and a reconcile flow through them — is
[`architecture/operator-internals.md`](../architecture/operator-internals.md).

**Teams and people live on their own objects and have their own page.** Since
[RFC 0011](../rfc/0011-teams-and-users.md), every feature's `grants` map has moved onto a
`WeeboSiTeam`, and a `WeeboSiUser` declares who is in one — including the optional provisioning of
an Authentik account and an Argo CD workspace application. See
[`teams-and-users.md`](./teams-and-users.md) for those two kinds, and for migrating a
`spec.teams` off the singleton.

> **`failurePolicy: Fail`.** The webhook fails closed: while it is unavailable, no DevWorkspace can
> be created or started, cluster-wide. That is deliberate — see RFC 0002's *Operational
> considerations* — but it means the chart's `PodDisruptionBudget`s and two-replica `Deployment`s
> are not optional extras. Turning them off turns a routine node drain into a Che outage.

## Install

The Helm chart is the one supported install path: `charts/weebo-si-operator/`, published on every
release as `oci://ghcr.io/batleforc/charts/weebo-si-operator` (see [CI › Releases](../ci.md#releases)).

```bash
kubectl create namespace weebo-si-hardening
kubectl label namespace weebo-si-hardening hardening.weebo.io/exclude=true
helm install weebo-si-operator oci://ghcr.io/batleforc/charts/weebo-si-operator \
  --version <x.y.z> -n weebo-si-hardening --set namespace.create=false \
  --set certificates.provider=cert-manager   # or openshift, or none
```

Helm stores the release in its namespace, so that namespace has to exist before `helm install`
runs. Neither `--create-namespace` nor a pre-created namespace can be combined with the chart's
default `namespace.create: true`: the rendered `Namespace` would clash with the existing one. Hence
the namespace is created and labelled by hand first — the label before the install, so the
operator's own pods are never admitted through its own webhook — and the chart is told not to
render one. `namespace.create: true` is only for a `helm template … | kubectl apply` install.

The chart's `appVersion` is the release version, and `image.repository`/`image.tag` default to the
image that same release pushed (`ghcr.io/batleforc/weebo-si-operator:<x.y.z>`); set
`image.digest` to pin the exact cosign-signed artifact instead of the tag. The chart renders every
object in the right order — namespace (with `namespace.create: true`; pre-labelled `hardening.weebo.io/exclude: "true"` so it is
never a target of its own webhook), the two `ServiceAccount`s and their RBAC (never one: the
webhook role, the one an untrusted `AdmissionReview` body reaches, never holds the
`weebosiconfigs/status` write the controller role needs), the certificate for the chosen provider,
both `Service`s, both Deployments with their `PodDisruptionBudget`s, and last the
`MutatingWebhookConfiguration` — the one object that actually puts the webhook in the admission
path. It installs the CRD from the chart's `crds/` directory; Helm installs `crds/` once and never
manages it after, so a CRD schema change on upgrade still needs `kubectl apply -f
charts/weebo-si-operator/crds/` by hand — see [Helm's own docs on
`crds/`](https://helm.sh/docs/chart_best_practices/custom_resource_definitions/).

RFC 0002 has no self-signed fallback of its own: `certificates.provider` is a prerequisite
decision, not an option to skip.

**NetworkPolicy for the operator's own pods.** Off by default (`networkPolicy.enabled: false`),
like the gateway's and preauth-proxy's, because the peers are the cluster's to know — and a wrong
guess here is a cluster-wide outage: a policy that drops the kube-apiserver's calls to the webhook
blocks every write it covers at `failurePolicy: Fail`. Turned on, one `NetworkPolicy` over both
roles admits the kube-apiserver to the webhook port and metrics scrapers to the metrics port, and
allows egress to cluster DNS and the kube-apiserver only:

```yaml
networkPolicy:
  enabled: true
  kubeApiserver:
    cidrs: ["10.0.0.0/24"]   # kubectl get endpoints kubernetes -n default
    ports: [443, 6443]       # the endpoint port, not the kubernetes Service's 443
    namespaceSelector: {}    # only where the apiserver runs as a pod (hosted control planes)
    podSelector: {}
  monitoring:                # the metrics port, while metrics.service.enabled
    namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: monitoring } }
    podSelector: {}
  dns:                       # port 53 UDP+TCP
    enabled: true
    namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: kube-system } }
    podSelector: { matchLabels: { k8s-app: kube-dns } }
  extraIngress: []           # verbatim rules, e.g. the node CIDR if your CNI polices probes
  extraEgress: []
```

Enabling it without `kubeApiserver.cidrs` (or an apiserver selector with `matchLabels` or
`matchExpressions`) fails the render. The apiserver is matched by `ipBlock` because on most
clusters it is not a pod; on Cilium, `ipBlock` does not match node addresses unless
`policy-cidr-match-mode: nodes` is set, so use a `CiliumNetworkPolicy` with `kube-apiserver`
entities through `extraIngress`/`extraEgress` there instead.

**There are no raw manifests any more.** `crates/weebo-si-operator/deploy/` used to carry a
hand-written copy of the same objects; it had drifted to the point of not starting (the webhook
lacked the required `--operator-identity`, no `POD_NAMESPACE`, RBAC behind the chart's, only one of
the webhook configurations, a `:latest` image), and a second install path nobody tests is a second
thing to keep secure. Only `deploy/crd.yaml` remains — the generated CRD, for anyone who wants the
kinds without the operator (`kubectl apply -f crates/weebo-si-operator/deploy/crd.yaml`). Never
hand-edit it: `task recu` regenerates it whenever `crates/weebo-si-crd` is part of a commit, and
`task crd:check` fails on a stale one. For a manifest-only install, render the chart:
`helm template … > manifests.yaml`.

With no `WeeboSiConfig` object created yet, the webhook configuration is still a no-op: `KubeConfigStore` reports
`Off` for every feature until one exists, so every DevWorkspace round-trips through the webhook
unmutated. That is deliberately the state to leave a fresh install in — see *Rollout*, below.
Deleting the singleton later returns to exactly this state, live, with no restart: every feature
reads `Off` on the next watch event. It stops the features rather than rolling them back — objects
already written stay where they are, unrepaired, because only a config that *says* `mode: Off`
tears anything down. Set `mode: Off` first if the goal is a clean removal.

### Before creating a `WeeboSiConfig`

Two things belong on the checklist, not in code — the operator cannot verify either:

- **RBAC on every catalogued namespace.** A catalogue entry must live somewhere users cannot write
  it — the Che namespace or the operator's own. Cataloguing `user-alice/hardened-config` hands the
  attacker the object the control exists to protect.
- **Who may authorize a catalogued entry.** Whoever authors an entry must never be the team it is
  granted to — a team-authored entry granted to itself recreates the DWOC-override hole this
  operator exists to close, one layer up.

And two more, specific to the `WeeboSiTeam` objects and
`spec.features.dwocPin.namespaceSelection.annotation`:

- **Namespace labels are load-bearing.** A team matches on labels, so labelling a namespace moves
  it onto that team's configuration for *every* feature at once. Confirm who can label a namespace
  in this cluster before writing a `WeeboSiTeam` — in a Che cluster this is already an admin-only
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
                               [--canary-image <ref>]
weebo-si-operator crd         [weebosiconfigs|weebositeams|weebosiusers]
                               # print the generated CRD YAML — what `task recu` writes
weebo-si-operator features    # print the registry: id, originating RFC, target resource
weebo-si-operator backends    # print which network-profiles backends are compiled in and
                               # which this cluster actually offers
weebo-si-operator backends kubearmor [--verbose]
                               # whether this cluster serves the KubeArmorPolicy CRD, and
                               # (--verbose) which nodes can actually enforce one (RFC 0006)
weebo-si-operator canary      [--namespace <ns>] [--canary-image <ref>]
                               # run the enforcement probe once and report whether this
                               # cluster's CNI actually enforces NetworkPolicy (RFC 0004);
                               # non-zero exit on anything but `enforcing`
weebo-si-operator images platform          # the compiled-in image-policy platform patterns
weebo-si-operator images check <ref>       # parse, normalize and judge one reference
                               [--team <name>] [--namespace <ns>]
weebo-si-operator images audit             # every image running now and the verdict this
                               [--namespace <ns> | --all-namespaces]   # config would give it
weebo-si-operator registry resolve --namespace <ns>
                               # the registry keys a namespace resolves to and where each mounts
weebo-si-operator registry check
                               # validate every registry-config catalogue entry (RFC 0007);
                               # non-zero on any violation
weebo-si-operator pods audit                # the existing pods each namespace's Pod Security
                               [--level L] [--version V]               # level would refuse
                               [--namespace <ns> | --all-namespaces]   # (RFC 0013); writes nothing
weebo-si-operator quotas audit              # usage today against each namespace's quota
                               [--profile KEY]                         # profile (RFC 0014)
                               [--namespace <ns> | --all-namespaces]
weebo-si-operator teams export [--from <file>] [--check]
                               # RFC 0011's migration: one WeeboSiTeam per spec.teams entry;
                               # writes nothing to the cluster
```

`canary`, `images`, `registry`, `pods`, `quotas` and `teams` read the cluster with **the invoking kubeconfig**,
not the operator's `ServiceAccount` — `images audit`'s `list pods` is deliberately the admin's
own permission, which is why RFC 0005 adds no RBAC at all.

`--operator-identity` is `policy-guard`'s one exemption — the controller's own
`system:serviceaccount:<namespace>:<name>` identity. The chart renders it for you from its own
`ServiceAccount` naming (`deployment-webhook.yaml`); anything that renders the webhook's args
another way must set it to match the controller `ServiceAccount` exactly, or `policy-guard` locks
the controller out of the objects it is responsible for — see RFC 0004's *Operational
considerations*.

`--metrics-addr` is accepted for the CLI contract's sake but not read separately today:
the probes and `/metrics` are all served together on `--health-addr` — the chart's Deployments
reflect that (one container port, `8081`, for both). The probes are `weebo-kit-runtime`'s:

| Path | Answers `200` when |
| --- | --- |
| `/readyz` | every watch cache this role needs has synced, and the role is not shutting down |
| `/livez` | no watch has kept failing for longer than 5 minutes — the chart's startup and liveness probes |
| `/healthz` | an alias of `/readyz`, kept for anything that still probes it; **not** a liveness probe |

A controller replica started with `--leader-election` reports ready as soon as its caches have
synced, then waits for the `weebo-si-controller-leader` `Lease` before starting any loop. It
exits with code `1` the moment it may have lost the lease, and the kubelet restarts it as a
standby.

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
2. **`mode: DryRun`**, catalogue and `default` written, **no `WeeboSiTeam` yet**. Watch
   `weebo_si_dwoc_pin_total` and the decision log lines (see *Reading the logs*, below) —
   `result="replaced"` is every workspace that will change behaviour once `Enforce` is flipped.
3. **Add the `WeeboSiTeam` objects, still in `DryRun`.** Read `result` broken down by `team`:
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
```

The per-team half is a `WeeboSiTeam`, per [RFC 0011](../rfc/0011-teams-and-users.md):

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: team-1
spec:
  namespaceSelector:
    matchLabels: { weebo.io/team: team-1 }
  features:
    dwocPin:
      catalog:
        - key: gpu
          name: gpu-config
          namespace: eclipse-che
      default: gpu
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

One line per admission decision, on stdout, through `tracing` as every weebo operator logs
([RFC 0012](../rfc/0012-operator-kit-migration.md)): a timestamp, the level, the module that
logged it, then the decision. `LOG_FORMAT=json` turns each line into a JSON object for a log
pipeline; `RUST_LOG` sets the level (`info` by default).

```text
2026-11-02T10:14:03.201Z  INFO weebo_si_webhook::router: allow namespace=user-alice workspace=python-web current=<none> target=eclipse-che/weebo-hardened-config
2026-11-02T10:14:09.877Z  INFO weebo_si_webhook::router: allow namespace=user-bob workspace=data-science current=eclipse-che/gpu-config target=<unchanged>
2026-11-02T10:15:41.032Z  INFO weebo_si_webhook::router: deny namespace=user-carol workspace=custom-config current=<none> reason=the namespace annotation names a catalogue key outside this namespace's grant: gpu
```

Before RFC 0012 these lines were plain `println!` output prefixed `weebo-si-webhook:` (or
`weebo-si-controller:`, `ERROR weebo-si-…:`, `WARN weebo-si-…:`); a runbook grepping on that
prefix greps on the text after it instead (`allow namespace=`, `deny namespace=`), which did not
change. The level is now the line's own field, not a word in the message.

`OTEL_EXPORTER_OTLP_ENDPOINT` additionally exports traces over OTLP.

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

### Events

Since [RFC 0012](../rfc/0012-operator-kit-migration.md), a reconcile pass that fails publishes a
`Warning` Event on the object it was about, and is retried after 30 s, then 60 s, 120 s, 240 s, and
every 5 minutes while the same object keeps failing; a pass that succeeds starts the count over.

| `reason` | On | Means |
| --- | --- | --- |
| `ConfigReconcileFailed` | the `WeeboSiConfig` | the status pass could not complete |
| `NetworkProfilesFailed` | a `Namespace` or a `DevWorkspace` | a `network-profiles` pass failed |
| `KubeArmorPolicyFailed` | a `Namespace` or a `DevWorkspace` | a `kubearmor-policy` pass failed |
| `RegistryConfigFailed` | a `Namespace` | a `registry-config` pass failed |
| `EndpointAuthFailed` | an `Ingress` | an `endpoint-auth` pass failed |
| `IdentityFailed` | a `WeeboSiTeam` or a `WeeboSiUser` | an `identity` pass failed |

```console
kubectl get events -A --field-selector reportingComponent=weebo-si-operator
kubectl describe namespace user-alice        # the Events of one namespace's passes
```

The Event of a cluster-scoped object (`Namespace`, `WeeboSiConfig`, the teams and users) lives in
`default`, as for every controller. A repeated failure is one Event whose count grows, not one
Event per retry. Only the controller role publishes Events; its RBAC gains `create`/`patch` on
`events.k8s.io/events`.

`weebo_si_admission_requests_total{outcome="error"}` is the first alert to wire: at `Fail`, a
nonzero rate is user-visible failures. `result="target_missing"` is the second — the feature is
doing nothing while `Active`. A `Degraded` condition on the `WeeboSiConfig` object itself means a
grant or a catalogue entry is broken; `kubectl describe weebosiconfig cluster` names which one.

## Known limitations

- **Exit code `3`** ("caches never synced within the readiness deadline") is reserved but not yet
  a code path any binary returns — `/readyz` correctly reports not-ready while a cache is
  syncing, but the process does not yet time out and exit on its own if one never does.
