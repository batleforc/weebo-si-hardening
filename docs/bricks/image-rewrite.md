# `image-rewrite`

Pulls upstream images through a mirror without anyone writing the mirror's name. A rule maps a
registry host onto a mirror prefix — `quay.io` → `registry.pkg.weebo.poc/quay` — and the
operator's mutating webhooks rewrite every matching image in a `DevWorkspace` and in a workspace
`Pod` before it is pulled. `image-policy` then judges the rewritten name: the rewrite turns a
refusal into a working pull, it never widens what a catalogue allows.

Design and threat model: [RFC 0017](../rfc/0017-image-rewrite.md). Every field:
[`weebosiconfig.md`](../weebosiconfig.md#featuresimagerewrite).

## Configure it

```yaml
spec:
  features:
    imageRewrite:
      mode: DryRun
      namespaceSelector:
        matchLabels: { hardening.weebo.io/workspace-namespace: "true" }
      rules:
        - { from: docker.io, to: registry.pkg.weebo.poc/hub }
        - { from: quay.io, to: registry.pkg.weebo.poc/quay }
        - { from: ghcr.io, to: registry.pkg.weebo.poc/ghcr }
```

| Written in a devfile or pod | Pulled as |
| --- | --- |
| `postgres:18` | `registry.pkg.weebo.poc/hub/library/postgres:18` |
| `quay.io/devfile/project-clone:v1@sha256:…` | `registry.pkg.weebo.poc/quay/devfile/project-clone@sha256:…` (the digest is kept, the tag beside it dropped) |
| `ghcr.io/batleforc/tool:main` | `registry.pkg.weebo.poc/ghcr/batleforc/tool:main` |
| `quay.io:443/x/y`, `quay.io.evil.com/x/y` | unchanged: the match is on the whole normalised host, port included |
| `registry.pkg.weebo.poc/quay/x/y` | unchanged: no `to` host is ever a `from`, so a rewritten name is never rewritten again |

The chart registers the webhooks by default (`imageRewrite.webhooks.enabled: true`); they let
everything through unchanged until this block exists. Check a name before enabling anything:

```bash
weebo-si-operator images check quay.io/devfile/project-clone:v1   # prints the `rewritten` line, then the verdict
weebo-si-operator images platform --cluster                        # the platform set, with each derived pattern's rule
```

## How it works

- **Two routes, one rule set.** `/mutate/v1alpha1/devworkspaces/images` rewrites the components
  a user wrote, so the stored `DevWorkspace` names the mirror; `/mutate/v1/pods` rewrites what
  DevWorkspace Operator and Che actually start, injected init containers and image volumes
  included. Kubernetes runs every mutating webhook before any validating one, so `image-policy`
  always sees the rewritten name.
- **It never denies.** Anything that goes wrong — a namespace the watch has not seen yet, an image
  that does not parse — lets the object through unchanged and counts `result="error"`.
  `image-policy` refuses what needs refusing.
- **Nothing running restarts.** On an `UPDATE`, only an image that differs from the old object's
  is rewritten (a `DevWorkspace` component is matched by name, a container by position);
  existing ephemeral containers and image volumes are immutable and left alone. Switching to
  `Enforce`, or editing a rule, takes effect at each workspace's next start.
- **The original is recorded** in the `hardening.weebo.io/image-rewrite` annotation, as JSON, on
  the `DevWorkspace` and on the `Pod` — except on a `pods/ephemeralcontainers` write, which can
  carry nothing but the ephemeral list. It is a record, never an input.
- **`DryRun` changes nothing** and still counts and logs every rewrite it would have made.

### The platform set follows the rules

With `imagePolicy.platform.builtin: true`, each compiled-in Che image whose host is a rule's
`from` is also allowed under that rule's `to`: `quay.io/devfile/project-clone:*@*` becomes
`registry.pkg.weebo.poc/quay/devfile/project-clone:*@*` as well. Only the compiled-in list is
derived — never `extra`, never a catalogue entry — and a derivation can only add a pattern,
never remove one. The upstream names stay allowed, for the namespaces the rewrite does not reach.

## Operate it

| Where | What |
| --- | --- |
| `kubectl get weebosiconfig cluster -o jsonpath='{.status.features[?(@.name=="image-rewrite")]}'` | `configuration valid`, or the warnings below; `Degraded` with every reason when a rule is refused |
| `weebo_si_image_rewrites_total{resource, result}` | `resource` ∈ `pod`, `devworkspace`; `result` ∈ `rewritten`, `unmatched`, `unparseable`, `error` |
| `weebo_si_feature_mode{feature="image-rewrite"}` | the mode in force |
| webhook logs | `image-rewrite match resource=… subject=… from=… to=…` per rewritten image |

**Warnings** (the feature stays `Active`):

| Message | Meaning |
| --- | --- |
| `no rules: nothing is rewritten` | the block is on and does nothing |
| `rule X → Y: no imagePolicy pattern permits anything under it` | every image this rule rewrites will be refused: grant `Y/**` somewhere, or drop the rule |
| `selects namespaces without hardening.weebo.io/workspace-namespace: injected images there are not rewritten` | the pod webhook only reaches labelled namespaces; select on that label |

**Refused by the apiserver** at `kubectl apply`: two rules with the same `from`, a chain (a `to`
whose host is another rule's `from`), a `to` with no path, and a host with no `.` or `:` other
than `localhost` — `harbor/quay` would be read as the Docker Hub namespace `harbor`. What only the
reference parser can judge makes the feature `Degraded`, and then **no rule applies**: upstream
names reach `image-policy` and are refused, the closed direction.

## Roll it out

1. `mode: DryRun`, and watch `weebo_si_image_rewrites_total{result="rewritten"}` and the log
   lines for a few days.
2. Make sure `image-policy` grants every `to`: the status warns about a rule nothing permits.
3. `mode: Enforce`. Workspaces pick it up at their next start.

On weebo-si, `deploy/weebo-si/` does exactly this: `DryRun` at stage 1, `Enforce` together with
`imagePolicy` at stage 4 ([the standard](../guides/weebo-si-standard.md#step-4--only-images-pulled-through-angos)).

**Rollback** is `mode: Off`: new pods keep upstream names again. Stored `DevWorkspace`s keep the
mirror name they were rewritten to, which is harmless while the mirror serves it.

## Moving a mirror

Changing a rule's `to` does not touch stored `DevWorkspace`s: their mirror name matches no
`from`, so they keep pulling from the old mirror. `images audit` lists them:

```bash
weebo-si-operator images audit --all-namespaces
# … the pod table, then:
# DEVWORKSPACE        COMPONENT   IMAGE                                   STALE-MIRROR
# alice/api           db          old.mirror.io/hub/library/postgres:18   now registry.pkg.weebo.poc/hub/library/postgres:18
```

The row is computed from the annotation: an image that is an earlier rewrite of the recorded
original and not what today's rules make of it. Edit each listed `DevWorkspace` (or ask its
owner to); the operator never rewrites a stored name twice.

## GitOps

A tool that re-applies a `DevWorkspace` with upstream names sees it rewritten each time: no storm,
but a permanent diff. With Argo CD, diff on the server with the mutating webhooks included:

```yaml
metadata:
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
```

## Upgrade

- **CRDs first.** `helm upgrade` never touches `crds/`: `kubectl apply --server-side -f
  charts/weebo-si-operator/crds/` before it, or the apiserver prunes `imageRewrite` from the stored
  object and the feature silently stays `Off`.
- **From 0.3.x or older**, upgrade twice: once with `--set imageRewrite.webhooks.enabled=false`,
  then with the default. A webhook registered while old pods without the route still serve
  answers 404 under `failurePolicy: Fail`, which refuses workspace pods for the length of the
  roll.

## Private upstream images

A rewritten pod pulls from the mirror, so the kubelet offers the pull secret whose registry
matches the **mirror's** host, not the upstream's. A private upstream image therefore needs the
mirror to hold the upstream credential (angos' upstream configuration), or no rule for that
host. See *T6* in the RFC; the probe that checked this is recorded in its §17.

The probe is `task deploy:t6-probe T6_NAMESPACE=<workspace namespace>` against a cluster where
`imageRewrite` is in `Enforce` and a rule covers `quay.io` (or set `T6_IMAGE` to a public image
one does cover). It pulls the image three times with `imagePullPolicy: Always`: with no secret,
with a bogus secret keyed on the mirror's host, and with the same secret keyed on the upstream
host. The last pulls like the first if the upstream secret was not offered to the mirror, and
fails like the second if it was. It prints a markdown block and exits `0` (holds), `1` (does not
hold) or `2` (inconclusive: the mirror requires auth, accepts any credential, or the node holds
its own; grep the mirror's access log for the run's `t6-probe-…` user).
