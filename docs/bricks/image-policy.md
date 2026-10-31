# `image-policy`

A feature of the [`weebo-si-operator`](./weebo-si-operator.md). Design and rationale:
[RFC 0005](../rfc/0005-image-policy.md). Field reference:
[`features.imagePolicy`](../weebosiconfig.md#featuresimagepolicy). The operator's own install,
CLI and break-glass are on [`weebo-si-operator.md`](./weebo-si-operator.md); this page assumes
it is installed.

Which container images a workspace is permitted to run, per team. One feature, two enforcement
points with deliberately different precision: a validating webhook on `DevWorkspace` gives the
developer a readable error at `kubectl apply` time and enforces the exact per-workspace
selection, and a validating webhook on `Pod` is the floor that catches the images DevWorkspace
Operator injects, the plugin sidecars a devfile pulls in by URI, and any pod created without a
workspace at all.

Both report the same feature id, so **one `mode` and one `namespaceSelector` govern both**.

## Install checklist

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
  a `WeeboSiTeam` and `{NAMESPACE}` from the apiserver's own naming, and neither is reachable by a
  workspace user under any RBAC.

## Usage

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

## Rollout

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
3. Add the `WeeboSiTeam` objects, still `DryRun`. `result` broken down by `team` is how you
   confirm the routing — a namespace routed to the wrong team is invisible in aggregate and
   obvious per team.
4. `mode: Enforce` with a `namespaceSelector` on a pilot label. One namespace, real denials, and
   **then start a workspace in it**.
5. Remove the selector.

Steps 2 through 5 are writes to one resource, effective on the next admission, with no rollout.

## Rollback

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

## The upgrade that actually breaks this is Che's, not ours

The compiled-in platform set tracks DevWorkspace Operator and che-code. A Che upgrade that changes
an injected image is, at `Enforce`, a fleet that stops starting — and it is the single most likely
operational failure of this feature. Three mitigations, in order:

1. Run `weebo-si-operator images audit --all-namespaces` **before a Che upgrade** as well as
   before installation. It names the new image before anything is applied.
2. `platform.extra` is the one-line fix, and it needs no operator release.
3. The denial is loud in `weebo_si_image_policy_total{result="denied", resource="pod"}`, which is
   otherwise flat. A spike there with no corresponding `devworkspace` movement is the signature.

## Reading the logs

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

## Observability

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

## This feature adds no RBAC

No verb, no resource, no `Role`, no `ClusterRole` rule, in either role. Both subjects arrive in
the admission body and the only lookup either route makes is the `namespaces` watch that already
existed. `images audit`'s `list pods` is *your* permission, exercised from your kubeconfig. **The
role an untrusted `AdmissionReview` body reaches is unchanged by RFC 0005.**

## What this does and does not close

Worth reading before quoting this feature in a compliance answer:

- **It is a control over names, not over content.** A permitted
  `quay.io/devfile/udi:ubi9-latest` says nothing about what those bytes are today. Anyone who can
  push that tag has pushed into every workspace using it, and this feature reports `allowed`. It
  closes "run something nobody catalogued", not "run something that changed under you".
- **The per-workspace attribute is least privilege, not an authorization boundary.** A user whose
  team is granted an entry can give any of their workspaces that entry, by editing a devfile. The
  boundary is the team's own catalogue, and only a cluster admin writes a `WeeboSiTeam`.
- **The Pod half enforces the team boundary, not the per-workspace selection.** A workspace
  running an image its team allows but its own selection excluded is not caught at the pod. That
  is a policy nicety, not a security boundary — and it is what buys the feature its zero-RBAC,
  zero-cache footprint.

## Known limitations

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
