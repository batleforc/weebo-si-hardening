# `WeeboSiTeam` and `WeeboSiUser`

Two cluster-scoped kinds that answer two questions the rest of this operator keeps asking: **which
namespaces belong to which team, and what is that team entitled to** — and **who is this person,
which team are they in, and what should exist for them outside this cluster**.

Design and rationale: [RFC 0011](../rfc/0011-teams-and-users.md). This page is the operator's copy
— how to install them, migrate to them, roll provisioning out and roll it back. The field-by-field
reference is [`weebosiconfig.md`](../weebosiconfig.md#teams-and-people); when this page and the RFC
disagree, the RFC is right and this page is a bug.

> **A `WeeboSiTeam` is a security object.** Whoever may write one decides which DevWorkspace
> Operator configs, image patterns, registries and runtime profiles that team reaches. They are
> **admin-only**: no team lead gets `edit` on their own team's object, not by `resourceNames` and
> not by moving it into a namespace they own. That decision is why the per-team catalogue ships
> with no cluster-level ceiling over its contents — granting a team write access to its own object
> without adding that ceiling first would let it catalogue anything it likes.

## Install

The three CRDs ship together — `weebosiconfigs`, `weebositeams`, `weebosiusers` — in the chart's
`crds/` directory, one file each, or as the single multi-document manifest in
`crates/weebo-si-operator/deploy/crd.yaml`:

```bash
helm upgrade --install weebo-si-operator charts/weebo-si-operator -n weebo-si-hardening
# or, without Helm:
kubectl apply -f crates/weebo-si-operator/deploy/crd.yaml
```

**The entitlement half needs nothing else switched on.** As soon as `WeeboSiTeam` objects exist,
the webhook, the controller and the endpoint gateway resolve every feature's catalogue against
them — the `identity` feature below is only about *provisioning*, and a cluster that never turns
it on still uses teams for everything RFC 0002 through RFC 0009 already do.

Both roles read both kinds and write neither; only `status` is ever written back. Print what the
chart actually granted:

```bash
kubectl get clusterrole weebo-si-operator-watch -o yaml | grep -A 3 weebositeams
```

## The objects

A team, cut down to what decides something:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: platform            # this IS the team name — what a WeeboSiUser references
spec:
  priority: 100             # lowest wins when a namespace matches two teams
  namespaceSelector:
    matchLabels: { weebo.io/team: platform }
  features:
    imagePolicy:            # this team's own catalogue entries, and its defaults
      catalog:
        - key: platform-tools
          patterns: ["registry.internal/platform/*"]
      default: [platform-tools]
```

A person:

```yaml
apiVersion: hardening.weebo.io/v1alpha1
kind: WeeboSiUser
metadata:
  name: max
spec:
  username: max             # the Kubernetes identity, as the API server sees it
  email: max@weebo.io
  team: platform
  authentik: { mode: Ensure }
  che: { mode: Ensure }
```

Both kinds carry printer columns, so the common question needs no `-o yaml`:

```console
$ kubectl get wsteam
NAME       PRIORITY   NAMESPACES   MEMBERS   READY   AGE
platform   100        12           8         True    41d
research   200        4            3         True    6d

$ kubectl get wsuser
NAME   USERNAME   TEAM       AUTHENTIK   CHE       READY   AGE
max    max        platform   Created     Created   True    41d
lea    lea        research   Adopted     Off       True    9d
sam    sam        —          Off         Off       False   3m
```

`sam` is `False` on purpose: `spec.team` is empty, so no feature entitlement and no workspace
applies. The object is valid; the person is not finished.

### Three rules worth knowing before writing the first one

- **Precedence is `priority`, not document order.** `spec.teams` was an ordered list and the first
  match won. Separate objects have no order, so the rule is explicit: lowest `priority` wins, ties
  break on name. A namespace two teams claim is reported on the team that lost, with the name of
  the one that won.
- **A key means one thing cluster-wide.** Two teams may declare the same catalogue key only if the
  entries are identical. A redefinition is reported on the team that wrote it, and the first
  definition stands — cluster entries first, then teams in priority order.
- **A team declares no `allowed` list.** What it reaches is the catalogue it declares, plus
  whatever the cluster hands everybody (`default`, or `baseline`). A team with no block for a
  feature gets exactly what a namespace with no team gets.

## Migrating from `spec.teams`

Three steps, in this order. Doing step 3 before step 2 means every namespace falls to the cluster
default until the teams land — safe, and visible in the feature metrics as a step change.

1. **Install the CRDs** (above). Nothing changes yet.

2. **Export, apply, verify.**

   ```bash
   weebo-si-operator teams export > teams.yaml          # or --from weebosiconfig.yaml
   kubectl apply -f teams.yaml
   weebo-si-operator teams export --check               # non-zero until the cluster matches
   ```

   Read the warnings it prints on stderr before applying: a grant naming a team `spec.teams` never
   declared, or a key the catalogue never declared, is reported and dropped. Those are the two
   mistakes the old schema could hold and the new one cannot.

   **Keep `teams.yaml`.** The command writes a file rather than piping into `kubectl` precisely
   because the rollback for step 3 is the old manifest and nothing else.

3. **Remove `spec.teams` and every `grants` map** from the singleton, and upgrade the deployment.
   The fields are gone from the schema, so the API server prunes them: a manifest that still
   carries them applies cleanly and silently loses them.

During a rolling update the two replica generations disagree about where teams live — an old
replica reads `spec.teams` (now absent, so no teams) while a new one reads the objects. Both
answers are safe, the old one being "everybody gets the cluster default", and the lease means only
one replica writes status.

## Provisioning: `spec.features.identity`

This is where the operator stops only constraining other people's workloads and starts creating
objects in other people's systems — an `AuthentikUser` in the identity provider, an Argo CD
`Application` for the workspace. It is off unless two separate switches say otherwise.

### 1. Grant the RBAC, and read what you are granting

```bash
helm upgrade weebo-si-operator charts/weebo-si-operator -n weebo-si-hardening \
  --set identity.rbac.enabled=true --set identity.argoNamespace=argocd
```

This adds `authentikusers` cluster-wide (the upstream CRD is cluster-scoped) and `applications`
**in one namespace only**. `identity.argoNamespace` must match
`spec.features.identity.che.applicationNamespace` below: that value is where the `Role` is bound,
this field is where the controller writes, and a mismatch is a refused write with a `Degraded`
condition naming it.

**No `delete` on either kind**, anywhere. Everything this operator creates carries an
`ownerReference` to the `WeeboSiUser` it was created for, so removal happens through garbage
collection and this ServiceAccount holds no verb that could remove somebody else's object.

An operator that can create Argo CD `Application` objects can, through Argo, deploy whatever the
named project permits. The fences are the allow-lists below, the single `Application` namespace,
and Argo's own `AppProject` restrictions — which stay the outer fence rather than being
reimplemented here.

### 2. Write the feature block, starting at `DryRun`

```yaml
spec:
  features:
    identity:
      mode: DryRun
      authentik:
        allowedGroupRefs: ["platform", "research", "oncall-*"]
      che:
        applicationNamespace: argocd
        allowedProjects: ["weebo-dev"]
        allowedRepoUrls: ["https://charts.weebo.io*"]
```

**An empty allow-list allows nothing.** Turning the feature on with no list provisions people with
no group rather than people with every group, and refuses every workspace template rather than
accepting every chart. A request outside an allow-list refuses the **whole** object rather than
trimming the offending entry — a partially honoured provisioning request is the failure nobody
notices.

`DryRun` takes every decision, renders every template and writes nothing. Each person's status
then reads `would create …`, which is how a bad allow-list is found before a bad object is.

### 3. Flip to `Enforce`

Watch `weebo_si_identity_users_total{state="conflict"}` and `{state="absent"}` on the way. Both
are answers rather than failures, and both need somebody:

| `status.<half>.state` | Means | What to do |
| --- | --- | --- |
| `Off` | The block is absent or `Off`. Nothing was looked for. | Nothing. |
| `Created` | This operator created it and owns it. | Nothing. Deleting the person deletes it. |
| `Adopted` | It already existed, owned by somebody else. Referenced, **never written**. | Nothing, or take ownership deliberately by deleting the foreign object and letting the loop recreate it. |
| `Absent` | The kind is not served by this cluster. | Install the Authentik operator or Argo CD, or set that half to `Off`. |
| `Conflict` | Another `WeeboSiUser` owns the same target. | Two people claim one object; decide which one keeps it and rename the other's target. |

## Rollback

Four levels, increasingly blunt, and one of them deletes things:

- **`identity.mode: Off`**, or removing the block entirely — seconds, no restart. Provisioning
  stops. **Nothing already created is deleted**, and both loops keep reporting team and user
  status.
- **`helm upgrade --set identity.rbac.enabled=false`** — the operator can no longer write either
  kind. The same outcome as `mode: Off`, enforced by RBAC rather than by configuration, and what
  to reach for when the configuration itself is what you distrust.
- **`kubectl delete weebositeams --all`** — the entitlements go with them and every namespace
  falls to the cluster default. Safe direction, and still an outage of intent: the cluster stops
  doing what somebody wrote down.
- **`kubectl delete weebosiuser <name>`** — ⚠️ **this deletes what was created for them.** The
  `ownerReference` is what makes that automatic, so a person removed takes their `AuthentikUser`
  and their Argo `Application` with them, and Argo prunes what the application deployed if its
  sync policy says so. There is no undo, and `teams export` has no user counterpart precisely
  because a person has no prior state to export.

## Reading the status

```bash
kubectl get wsteam platform -o jsonpath='{.status}' | jq
kubectl get wsuser max -o jsonpath='{.status}' | jq
```

A team's `status` carries `namespaces` — the namespaces it **owns**, having won against every
other team's priority, not the ones its selector matches — `members`, and one condition. A
namespace its selector matches but another team won is reported in the `Degraded` message, named,
up to three of them plus a count.

A person's `status` carries `team`, the two halves above, and one condition. `Adopted` is a
success: the object exists and this person can use it.

## Observability

| Metric | Reads |
| --- | --- |
| `weebo_si_identity_users_total{kind,state}` | Provisioned objects by outcome. `state="conflict"` and `state="absent"` are the two that need somebody. |
| `weebo_si_identity_errors_total{kind}` | Calls the API server refused. Non-zero for longer than a reconcile period is the alert worth writing. |
| `weebo_si_identity_teams_total{result}` | Team passes, by whether the team reported violations. |

No metric here carries a username or a namespace, per the project-wide rule in RFC 0004's
*Observability contract*: a per-person time series is exactly the unbounded cardinality a
hardening component must not create. Which person is `Conflict` is a `kubectl get wsuser` away.

The second alert worth writing is on a `WeeboSiUser` sitting `Ready=False` for longer than an
onboarding day.

## Failure modes

| What happens | What you see | What the operator does |
| --- | --- | --- |
| Neither loop is running (controller down) | Stale `status`, no new provisioning | Nothing is blocked. Neither loop is on an admission path, and the entitlement half keeps working from the objects themselves. |
| `weebositeams` cannot be listed (RBAC, CRD missing) | `Degraded` on the singleton naming the list error | Every namespace falls to the cluster default — narrower than its team's answer, never wider. |
| A team redefines a catalogue key | `Degraded` on that team | The first definition stands; the team reaches it instead of its own. |
| A person's team is deleted | `Degraded` on the person, and on the singleton's `identity` feature | **Nothing is deleted.** If they asked for a workspace, the plan refuses as a whole and neither half is written — including the half that was fine; if they only asked for an identity, it keeps being reconciled without their team's groups. |
| The Authentik operator is not installed | `status.authentik.state: Absent` | Reported, never retried as a write. The workspace half is unaffected. |
| The API server refuses a write | `Degraded`, `weebo_si_identity_errors_total` | The other half of that person still runs; the pass requeues. |
| Two `WeeboSiUser` objects claim one username | `Degraded` on the singleton's `identity` feature | Reported once, naming the username. An identity resolving to two sets of entitlements has no correct reading. |

## Known limitations

- **A team references Authentik groups by name, as strings.** There is no `AuthentikGroup` object
  per team yet, so a typo in `groupRefs` is caught by the allow-list if it is outside it and by
  the upstream operator's own reconcile if it is inside it — not at admission.
- **Membership is declared here and derived elsewhere.** `endpoint-auth` still derives team
  membership from namespace ownership for anybody with no `WeeboSiUser`; where both answers exist
  and disagree, the declared one wins.
- **One `Application` namespace for the whole cluster.** That is what keeps the RBAC to one
  namespace; a fleet wanting several Argo instances needs a second operator deployment.
- **No ceiling over what a team may catalogue.** Deliberate, and tied to teams being admin-only —
  see the warning at the top of this page.
- **The migration has not been run end to end on a real cluster.** `teams export` is unit-tested
  against a realistic singleton and its output round-trips through the real schema; the last item
  on RFC 0011's plan is somebody doing the three steps above on a live fleet.
