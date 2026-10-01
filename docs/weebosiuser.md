# `WeeboSiUser` — the person reference

A person is one cluster-scoped `WeeboSiUser` object: their Kubernetes identity, the team they
belong to, and two optional provisioning switches — an `AuthentikUser` in the identity provider,
and the Argo CD `Application` their team's workspace template describes. This page documents every
field of it — what it means, whether it is required, what it defaults to, and what happens when it
is wrong.

This is the *reference*. The **why** is [RFC 0011](./rfc/0011-teams-and-users.md), and **how to
turn provisioning on and roll it back** is
[`bricks/teams-and-users.md`](./bricks/teams-and-users.md). The team half — including the
workspace template a person instantiates — is [`weebositeam.md`](./weebositeam.md), and the
provisioning switch and its allow-lists are
[`features.identity`](./weebosiconfig.md#featuresidentity) on the singleton. When this page and the
code disagree, the code is right and this page is a bug.

The schema is generated from `crates/weebo-si-crd/src/user.rs` and checked in as
`charts/weebo-si-operator/crds/weebosiusers.hardening.weebo.io.yaml`. Print it from the binary that
enforces it:

```bash
weebo-si-operator crd weebosiusers
kubectl explain weebosiuser.spec --recursive
```

To build one without hand-writing YAML, the [config generator](https://batleforc.github.io/weebo-si-hardening/#WeeboSiUser) renders a form
from this same schema, validates as you type and prints the object.

**A `WeeboSiUser` is admin-only, like a team.** Whoever may write one decides which team somebody
is in and, with provisioning on, what gets created for them in two other systems. **Deleting one
deletes what was created for them** — see [Deleting a person](#deleting-a-person).

**What this object never carries is a credential.** `AuthentikUser` has no password field by
design, and neither does this: the identity provider owns its own invite and reset flows.

## The object

Every field, with a realistic value:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiUser
metadata:
  name: max
spec:
  username: max
  displayName: Max Leriche
  email: max@weebo.io
  team: platform
  active: true
  authentik:
    mode: Ensure
    name: max
    groupRefs: [oncall-eu]
  che:
    mode: Ensure
    namespace: max-che
    values:
      storage: { size: 30Gi }
```

| | |
| --- | --- |
| Group / version | `hardening.weebo.io/v1alpha1` |
| Kind | `WeeboSiUser` (plural `weebosiusers`, short name `wsuser`) |
| Scope | Cluster |
| Name | free — `spec.username` carries the identity; `metadata.name` only has to be a legal object name |
| Status | subresource — see [`status`](#status) |

The smallest legal person is a username. It declares somebody exists and nothing else:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiUser
metadata:
  name: lea
spec:
  username: lea
  team: research
```

**Provisioning is opt-in twice**: once on the singleton (`spec.features.identity`, absent means
`Off`), and once per person (`authentik` and `che`, absent means nothing is asked for). With either
switch missing, the object still declares membership, and nothing is created anywhere.

## `spec`

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `username` | string | **yes** | — | The Kubernetes identity, as the API server presents it after authentication. |
| `displayName` | string | no | `username` | Passed to Authentik as `name`, and bound to `{DISPLAY_NAME}`. |
| `email` | string | when `authentik.mode: Ensure` | — | Passed to Authentik; bound to `{EMAIL}`. |
| `team` | string | no | — | A `WeeboSiTeam`'s `metadata.name`. |
| `active` | bool | no | `true` | `false` writes the `AuthentikUser` with `isActive: false`. |
| `authentik` | object | no | absent | The identity-provider half. |
| `che` | object | no | absent | The workspace half. |

### `username`

Free-form: the schema checks only that it is present. It must be exactly what the API server
authenticates this person as — the value Che writes as the namespace owner, the value an OIDC
`username` claim yields — because that is what every other component compares against. A value
that matches nobody is not detected; the person simply never matches anything.

**One username, one object.** Two `WeeboSiUser` objects claiming one username is reported once, on
the singleton's `identity` feature status (`two WeeboSiUser objects claim username …`): an identity
resolving to two sets of entitlements has no correct reading. Neither person's own `status` says
so, so check the singleton when two objects disagree.

### `displayName`

Defaults to `username`. Rendered into a workspace template through `{DISPLAY_NAME}` — so a
template using it in a namespace name breaks for anybody whose display name contains a space or a
capital; use `{USERNAME}` there.

### `email`

Not format-checked. **Required when `authentik.mode` is `Ensure`** — `AuthentikUser` requires one —
and an empty string counts as missing: the person is refused with `user … asks for an Authentik
account with no email`, and neither half is written. Otherwise optional; `{EMAIL}` renders to the
empty string when it is unset.

### `team`

The team this person belongs to, by the team's `metadata.name`. It decides three things: which
`workspace.che` template the person instantiates, which `identity.authentik.groupRefs` they
receive, and what `{TEAM_NAME}` renders to.

**Empty or absent is legal**: a person with no team is not finished rather than wrong. What they
get:

| They asked for | Result |
| --- | --- |
| nothing | `Ready`. Nothing to provision. |
| `authentik` only | `Ready`, provisioned with their own `groupRefs` and no team groups. |
| `che` | `Degraded`: `user … asks for a workspace and has no team`. **Neither half is written.** |

**A `team` naming no existing `WeeboSiTeam`** is reported on the singleton's `identity` feature
(`user … names team …, which does not exist`), and otherwise behaves exactly as an empty team —
including the `has no team` message on the person if they asked for a workspace. This is what
renaming or deleting a team does to its members.

`spec.team` is **not** read by `endpoint-auth` today: the endpoint gateway still derives a person's
team from the namespaces they own, for everybody. RFC 0011 specifies that declared membership should
win over the derived one; that half is not implemented yet.

### `active`

`false` changes one thing: the `AuthentikUser` is written — created or updated — with
`isActive: false`, which disables the account in Authentik without deleting it. Nothing is deleted
anywhere. **The workspace half is not affected**: an `Application` is still created if missing and
kept in step. To stop provisioning a workspace, set `che.mode: "Off"`.

## `spec.authentik`

```yaml
authentik:
  mode: Ensure
  name: max-leriche
  groupRefs: [oncall-eu]
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`Ensure` | **yes**, when the block is present | — | `Ensure` creates the `AuthentikUser` when missing, keeps it in step when this operator owns it, and references it when somebody else does. `Off` asks for nothing — the same as omitting the block. |
| `name` | string | no | `metadata.name` | The `AuthentikUser`'s `metadata.name`. Set it to point this person at an existing object with another name. |
| `groupRefs` | `[string]` | no | `[]` | Groups **in addition** to the team's `identity.authentik.groupRefs`. |

`mode` has no default because "they forgot" and "they meant off" are indistinguishable. Write
`"Off"` quoted: unquoted, YAML 1.1 parsers read it as the boolean `false`, which the schema
refuses for a string field.

**Every group — the team's and the person's, merged — is checked against
`spec.features.identity.authentik.allowedGroupRefs`**: exact match, or prefix match for an entry
ending in `*`, and an empty list allows nothing. One group outside it refuses the person as a
whole (`… asks for group …, which is outside allowedGroupRefs`), workspace half included, rather
than provisioning them with the offending group trimmed.

What gets written, on `authentik.weebo.io/v1alpha1` `AuthentikUser` (cluster-scoped):

| `AuthentikUser` field | Source |
| --- | --- |
| `metadata.name` | `spec.authentik.name`, defaulting to this object's `metadata.name` |
| `spec.username` | `spec.username` |
| `spec.name` | `spec.displayName`, defaulting to the username |
| `spec.email` | `spec.email` |
| `spec.isActive` | `spec.active` |
| `spec.groupRefs` | the team's `groupRefs` plus the person's, deduplicated and sorted |

## `spec.che`

```yaml
che:
  mode: Ensure
  namespace: max-che
  values:
    storage: { size: 30Gi }
```

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `mode` | `Off`/`Ensure` | **yes**, when the block is present | — | `Ensure` instantiates the team's `workspace.che` template for this person. `Off` asks for nothing. |
| `namespace` | string | no | the team's rendered `destination.namespace` | Overrides the destination namespace — and with it `{USER_NAMESPACE}` everywhere else in the template, so one field moves the whole application. |
| `values` | free-form object | no | — | Helm values deep-merged **over** the team's `source.values`. |

Everything else about the `Application` — its name, project, chart, cluster, sync policy — is the
team's, and a person cannot change it. See
[`workspace.che`](./weebositeam.md#specworkspaceche) for the template and what gets written.

**`namespace`** is rendered like the template's own namespace: it may use `{USERNAME}`,
`{OBJECT_NAME}`, `{TEAM_NAME}`, `{EMAIL}` and `{DISPLAY_NAME}`, not `{USER_NAMESPACE}`, and must
render to a DNS-1123 label (lowercase alphanumerics and `-`, at most 63 characters). Anything else
refuses the person with `rendering the workspace of user …`.

**`values`** is the one free-form field on this object (`x-kubernetes-preserve-unknown-fields`), so
the API server accepts any object here and checks nothing inside it. It is rendered with the
[template variables](./weebositeam.md#template-variables) — string values only, keys untouched,
`{{ … }}` passed through — and then merged: objects merge key by key, and everything else,
**arrays included, is replaced**. Overriding `storage.size` keeps the rest of the team's `storage`
block; overriding a list replaces the team's list. An unknown `{VARIABLE}` inside it refuses the
person. Never put a secret here: it lands verbatim in the `Application`.

A person asking for a workspace is refused, neither half written, when:

| Message | Cause |
| --- | --- |
| `asks for a workspace and has no team` | `spec.team` is empty, or names no existing team. |
| `asks for a workspace and team … describes none` | The team has no `workspace.che`. |
| `asks for a workspace and team … has it switched off` | The team's `workspace.che.mode` is `Off`. Reported rather than skipped: the two objects say opposite things. |
| `team …'s workspace template: …`, `… outside allowedProjects`, `… outside allowedRepoUrls` | The team's template is wrong — also on the team, see [`weebositeam.md`](./weebositeam.md#what-the-schema-does-not-check-and-the-controller-does). |
| `rendering the workspace of user …` | This person's variables do not render: an illegal namespace, or an unknown variable in their `values`. |

## Provisioning, and who owns what

The user loop runs on every change to the object and every five minutes, on the leader only. Per
half, it looks the target object up by name and decides:

| What the cluster holds | `state` | Written? |
| --- | --- | --- |
| The kind is not served (Authentik operator or Argo CD not installed) | `Absent` | Never — reported, not retried as a write. |
| No object by that name | `Created` | Created, with an `ownerReference` to this `WeeboSiUser` and the label `hardening.weebo.io/managed-by: weebo-si-operator`. |
| An object owned by this `WeeboSiUser` (by `metadata.uid`) | `Created` | Updated when its `spec` has drifted, otherwise left alone. |
| An object with no `WeeboSiUser` owner | `Adopted` | **Never.** Referenced — an object an admin made is not this loop's to take over. |
| An object owned by a *different* `WeeboSiUser` | `Conflict` | Never. Two people claim one target; neither wins. |

**A username is held by one person.** Before either half is looked at, the loop checks whether
an older `WeeboSiUser` — earliest `creationTimestamp`, then lowest name, compared without case —
already names the same `spec.username`. If one does, both halves report `Conflict` with
`username <u> is already claimed by WeeboSiUser <name>`, the person is `Degraded`, and nothing is
written. The target objects are named after each `WeeboSiUser` and would not collide; the login
they ask for would, in Authentik and in `<username>-che`, where nothing reports it back. The
holder is never disturbed by a duplicate added later, and the duplicate is picked up within one
five-minute pass once the holder is deleted or renamed.

Ownership is compared by `uid`, never by name, so a person deleted and recreated under the same
name does not inherit the first one's objects — the old ones are garbage-collected and new ones
created. The operator holds no `delete` verb on either kind.

**In `DryRun`, the same decision is taken and nothing is written**, and the `state` is the one
enforcement would reach: a person who would be created reads `state: Created` with the message
`would create …`. Read the `message`, not only the `state`, while the feature is in `DryRun`.

With `spec.features.identity` absent or `mode: Off`, the loop still runs, writes no `authentik` or
`che` status, and reports `Ready` with `… nothing is provisioned`.

### Deleting a person

**Deleting a `WeeboSiUser` deletes everything this operator `Created` for them**, through the
`ownerReference` — their `AuthentikUser`, and their `Application`, after which Argo prunes what the
application deployed if its sync policy says so. `Adopted` objects are not touched. There is no
undo. To stop provisioning without deleting anything, set the halves to `"Off"`, or set `active:
false` to disable the Authentik account.

## `status`

Written by the controller's user loop, derived entirely from `spec` and the cluster.

```yaml
status:
  observedGeneration: 3
  team: platform
  authentik:
    name: max
    state: Created
    message: "AuthentikUser/max is up to date"
  che:
    name: max
    namespace: argocd
    state: Created
    message: "created Application/max"
  conditions:
    - type: Ready
      status: "True"
      reason: AsExpected
      message: provisioned
      observedGeneration: 3
```

| Field | Meaning |
| --- | --- |
| `observedGeneration` | The `metadata.generation` this status reflects. |
| `team` | `spec.team`, copied as written — present even when that team does not exist. |
| `authentik`, `che` | One per half, **absent** when the half was not asked for, when the feature is absent or `Off`, or when the person was refused. |
| `<half>.name` | The target object's name — the `AuthentikUser`, or the rendered `Application` name. |
| `<half>.namespace` | For `che`, the Argo namespace the `Application` lives in (`applicationNamespace`), not the destination namespace. Absent for `authentik`. |
| `<half>.state` | `Created`, `Adopted`, `Absent` or `Conflict` — see [the table above](#provisioning-and-who-owns-what). |
| `<half>.message` | Human-readable detail: `created …`, `would create …`, `… is up to date`, or why not. |
| `conditions` | Exactly **one** condition. |

The schema also allows `state: Off`, and the metrics count it, but the loop never writes it: a half
nobody asked for has no status entry at all, so the printer column is blank rather than `Off`.

The condition is either `type: Ready` (`reason: AsExpected`) or `type: Degraded`
(`reason: NotProvisioned`), with `status: "True"` in both cases. `Ready`'s message is
`provisioned`, `dry run: nothing written`, or why nothing is provisioned. `Degraded`'s message is
every problem, semicolon-separated: the refusal reasons above, a `Conflict` or `Absent` half, or a write
the API server refused. **`Adopted` is healthy** — the object exists and this person can use it.

The `READY` printer column reads the `Ready` condition's status, so it shows `True` for a healthy
person and is **blank** for a degraded one:

```console
$ kubectl get wsuser
NAME   USERNAME   TEAM       AUTHENTIK   CHE       READY   AGE
max    max        platform   Created     Created   True    41d
lea    lea        research   Adopted               True    9d
sam    sam        platform   Created     Absent            3m
```

## Keys

A `WeeboSiUser` writes nothing a user touches. Everything it produces carries two markers:

| Marker | On | Meaning |
| --- | --- | --- |
| `hardening.weebo.io/managed-by: weebo-si-operator` | created `AuthentikUser`, `Application` | This operator wrote it. |
| `ownerReference` → `WeeboSiUser/<name>` | same | Which person it belongs to; deleting them deletes it. |

No metric carries a username. Which person is `Conflict` is a `kubectl get wsuser` away; the
counters are listed in [`bricks/teams-and-users.md`](./bricks/teams-and-users.md#observability).
