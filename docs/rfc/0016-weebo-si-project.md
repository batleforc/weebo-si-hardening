---
rfc: 0016
title: WeeboSiProject
status: Draft
authors: [batleforc]
created: 2026-10-06
updated: 2026-10-06
decided:
brick: crates/weebo-si-project
supersedes: []
superseded-by: []
---

# RFC 0016 — WeeboSiProject

## Summary

A project becomes an object: `WeeboSiProject` (`platform.weebo.io`, namespaced), declared by a team
in its own Git repository and synced into the team's namespace. From it, `weebo-si-operator`
composes everything a project needs around its code — the source repository, its read-only mirror,
a Che entry, an image repository in angos — by writing other operators' objects, never by calling
their APIs. `WeeboSiTeam` gains the two blocks that make this possible: where the team declares its
projects, and what the team is on Forgejo.

## Motivation

**Starting a project is a checklist across five systems.** Create the repository on
`git.batleforc.fr`, ask for a mirror on `git.weebo.poc`, get an image repository added to angos's
`values.yaml`, wire Che to it, write the Argo CD application. Each step is a pull request on a
different file, owned by the platform maintainer, and nothing records that the five belong
together — deleting a project is archaeology.

**Teams cannot serve themselves.** Every one of those steps is an edit to `weebo-si`, the repository
that also carries the cluster's hardening posture. There is no way to let a team add a project
without giving it a diff on everything else, which is the problem RFC 0011 solved for teams and
users and is now one level down.

**Once this exists:** a team adds a `WeeboSiProject` to its own repository; within a reconcile
period the source repository exists (or is attached), its mirror is syncing, its image path in angos
accepts pushes from CI, and `kubectl get weebosiprojects -n team-weebo` shows one line per project
with what is ready and what is not. Deleting the object removes the wiring and keeps the code.

## Guide-level explanation

### A team that declares projects

```yaml
apiVersion: platform.weebo.io/v1alpha1
kind: WeeboSiTeam
metadata:
  name: weebo
spec:
  # ... RFC 0011 fields unchanged
  projects:
    # The team's declaration repository. Created by the operator if missing.
    repo:
      instanceRef: batleforc            # a ForgejoInstance (weebo-forgejo)
      owner: weebo
      name: platform
    # Organizations of the source forge this team's projects may live in.
    sourceOrganizations: [weebo]
    # Templates the team may start a project from.
    templates:
      - key: rust-http
        owner: weebo-templates
        name: rust-http
  forgejo:
    mirror:
      instanceRef: weebo-mirror
      organization: weebo              # created on git.weebo.poc
      permission: read
```

The operator creates, for that team: the namespace `team-weebo`, an Argo CD `AppProject` and
`Application` syncing `weebo/platform` into that namespace only, and on the mirror an organization
`weebo` with a read-only team whose members are the team's `WeeboSiUser`s.

### A project

In `weebo/platform`, the team commits:

```yaml
apiVersion: platform.weebo.io/v1alpha1
kind: WeeboSiProject
metadata:
  name: foo
  namespace: team-weebo
spec:
  template: rust-http
  source:
    owner: weebo
    name: foo
    mode: Ensure        # Ensure: create from the template if absent / Adopt: attach an existing one
  mirror:
    enabled: true
  devEnv:
    enabled: true
  artifacts:
    images: true
```

```console
$ kubectl get weebosiprojects -n team-weebo
NAME   SOURCE      MIRROR   DEVENV   IMAGES   READY   AGE
foo    Created     Synced   Ready    Ready    True    4m
bar    Adopted     Stale    Ready    Off      False   21d
```

`kubectl describe` names the failing part: `MirrorStale` from the `ForgejoMirror`,
`SourceOrganizationNotAllowed` when `source.owner` is not in the team's list, and so on.

## Design

### Contract

#### `WeeboSiProject`

| | |
| --- | --- |
| Group / version | `platform.weebo.io/v1alpha1` |
| Kind | `WeeboSiProject` (plural `weebosiprojects`, short name `wsproject`) |
| Scope | Namespaced — only in a team namespace (below) |
| Team | the `platform.weebo.io/team` label of its **namespace**, set by the operator. There is no `spec.team`. |
| Status | Subresource |

| Field | Type | Required | Default | Meaning |
| --- | --- | --- | --- | --- |
| `template` | string | no | — | Key in the team's `projects.templates`. Required when `source.mode` is `Ensure`. |
| `source.owner` | string | **yes** | — | Organization on the source forge; must be in the team's `sourceOrganizations`. |
| `source.name` | string | no | `metadata.name` | Repository name. |
| `source.mode` | `Ensure` \| `Adopt` | **yes** | — | `Ensure` creates the repository from the template when it does not exist; `Adopt` attaches an existing one and fails if it is missing. |
| `mirror.enabled` | bool | no | `true` | Pull mirror on the team's mirror organization. |
| `mirror.interval` | duration | no | `8h` | |
| `devEnv.enabled` | bool | no | `true` | Che entry pointing at the source repository. |
| `artifacts.images` | bool | no | `false` | Image repository in angos. |

The schema is closed (`x-kubernetes-preserve-unknown-fields` off). `data`, `environments` and
`observability` (weebo-si RFC 0002) are not in this version; each arrives with its own RFC as an
additive field.

#### `WeeboSiTeam` additions

| Field | Type | Meaning |
| --- | --- | --- |
| `projects.repo.{instanceRef, owner, name}` | object | The team's declaration repository. Absent: the team cannot declare projects, and no team namespace is created. |
| `projects.sourceOrganizations` | []string | Source-forge organizations this team's projects may use. Empty allows none. |
| `projects.templates` | []`{key, owner, name}` | Template repositories, by key. |
| `forgejo.mirror.{instanceRef, organization, permission}` | object | The team's organization and team on the mirror instance. |

The cluster singleton gains an allow-list, in the same spirit as `authentik.allowedGroupRefs`:
`WeeboSiConfig.spec.platform.allowedForgejoInstances` and `allowedTemplateOwners`. A team cannot
name an instance or a template owner the cluster did not allow.

#### What gets created

Per team with `projects` (owned by the `WeeboSiTeam`):

| Object | Detail |
| --- | --- |
| `Namespace` `team-<team>` | labels `platform.weebo.io/team: <team>`, `weebo.io/team: <team>` |
| `ForgejoRepository` | the declaration repository, `deletionPolicy: Retain` |
| `AppProject` (Argo CD) | source: only the declaration repository; destination: only `team-<team>`; namespace resources whitelist: only `platform.weebo.io/WeeboSiProject`; no cluster resources |
| `Application` (Argo CD) | syncs the declaration repository into `team-<team>` |
| `ForgejoOrganization`, `ForgejoTeam` | on the mirror instance; `members` = `username` of every `WeeboSiUser` whose `team` is this team |

Per project (owned by the `WeeboSiProject`, in `team-<team>`):

| Object | When | Detail |
| --- | --- | --- |
| `ForgejoRepository` | always | on the source instance; `adopt: true` for `Adopt`, template for `Ensure`; `deletionPolicy: Retain` |
| `ForgejoMirror` | `mirror.enabled` | on the mirror instance, organization of the team; `deletionPolicy: Retain` |
| `ConfigMap` in Che's namespace | `devEnv.enabled` | a getting-started sample (`app.kubernetes.io/component: getting-started-samples`) pointing at the source repository |
| entry in `Secret` `angos-projects` | `artifacts.images` | `[repository."projects/<team>/<project>"]`, push for the CI provider, pull for `provider:kube` and `group:<team>` |

Every created object carries `app.kubernetes.io/managed-by: weebo-si-hardening`, the label
`platform.weebo.io/project`, and an `ownerReference` to its project or team. Deleting a project
deletes these objects; the remote repository and mirror survive because their weebo-forgejo
objects say `Retain` (weebo-si RFC 0002 P4). Objects of a tool with no retention policy of its
own (CNPG, RustFS, in later RFCs) will be created *without* an `ownerReference` instead.

#### angos

`angos-projects` is one Secret in angos's namespace, rewritten as a whole from every
`WeeboSiProject` with `artifacts.images`, and passed to angos as a third `-c` file between its base
configuration and its secrets (weebo-si RFC 0002 §4.4, verified on angos 1.9.2: repeatable `-c`,
tables merged by key, hot reload of every file).

Two angos behaviours shape the contract, both verified:

- **Prefixes must not overlap.** `weebo` and `weebo/foo` cannot coexist. Project repositories live
  under the reserved prefix `projects/` — the angos chart refuses a base repository named
  `projects`. Segments are compared as path segments: `projects/weebo/foo` and
  `projects/weebo/foo-bar` coexist.
- **An invalid file is refused at reload, fatal at restart.** On hot reload angos logs
  `Configuration was not applied; keeping the previous one`; on a restart it does not start. The
  operator therefore validates the whole file before writing it — keys under `projects/` only, no
  overlap — and a project that would break it is reported (`ImageRepositoryConflict`) and left out,
  rather than written.

#### Status

`observedGeneration`, `team`, one block per part — `source`, `mirror`, `devEnv`, `images` — each
`{state, message}` with `state` in `Off`, `Created`, `Adopted`, `Absent` (the target kind is not
installed), `Conflict`, and the target's own `Ready` reason copied when it is not ready
(`MirrorStale`, `ForgejoObjectAlreadyExists`…). `conditions`: `Ready`, `Degraded`.

### Architecture

Hexagonal, yes, and on the existing ports: RFC 0011's `Provisioner` takes a `DesiredObject` and
returns an `Observation`; a `ForgejoMirror`, a `ConfigMap` or an Argo CD `AppProject` is one more
desired object. The new crate `weebo-si-project` holds the pure function from
(`WeeboSiConfig`, `WeeboSiTeam`, `WeeboSiProject`, the team's users) to the list of desired objects,
and the angos file renderer and validator — pure as well, tested on the overlap and reload cases
above. The composition root wires one `Provisioner` handle per target kind, as RFC 0011 does for
two.

`weebo-si-operator` still holds no credential of any tool and makes no outbound HTTP call
(weebo-si RFC 0002 P9).

### Data and state

Stateless beyond `status` and `ownerReferences`, like RFC 0011. `angos-projects` is derived state:
deleting it costs one reconcile. The source of truth for projects is each team's declaration
repository; for teams, `weebo-si`.

## Security considerations

- **Privileges.** New verbs for the operator: create/patch/delete on `forgejo.weebo.io` kinds
  (namespaced ones in `team-*`, cluster ones by label), `Namespace` create for `team-*`, Argo CD
  `AppProject`/`Application` in `argocd`, one named `Secret` in angos's namespace (`resourceNames`),
  sample `ConfigMap`s in Che's namespace. No Secret read anywhere.
- **Trust boundary.** A team's repository content is attacker-controlled from the cluster's point
  of view. Three things contain it: the `AppProject` lets only `WeeboSiProject` into only
  `team-<team>`; the team comes from the namespace label, which the team cannot write; every name a
  project supplies is checked against the team's allow-lists, themselves checked against the
  cluster's.
- **Bypass.** Writing a `ForgejoRepository` directly in `team-<team>` would skip this operator's
  checks; weebo-forgejo's `ForgejoNamespacePolicy` and `allowedOrganizations` stop it independently.
  Adopting another team's repository needs that repository's organization in the team's
  `sourceOrganizations`.
- **Blast radius.** A bad angos file can no longer break the running registry (reload refuses it),
  but could stop the next restart; validation before write is mandatory, and a malformed file in
  the Secret blocks all projects' images, not the base registries' — the base configuration is a
  separate file.
- **Secrets.** None read. Mirror credentials for private sources are referenced by the
  `ForgejoMirror` and live with weebo-forgejo.

## Operational considerations

- **Failure mode.** Fail-closed per part: a violation creates nothing for that part and reports it,
  the other parts proceed. A target operator not installed yields `Absent`. Nothing here sits on the
  admission path.
- **Rollout.** Requires RFC 0015 (the group) and weebo-forgejo. Order: allow-lists in the
  singleton, `projects` on one team, then projects in that team's repository. The angos chart change
  (third `-c`, mount, reserved prefix) ships before the first project with `images`.
- **Rollback.** Deleting the projects removes the wiring and keeps repositories and mirrors.
  Removing `projects` from a team deletes its namespace and the projects with it — the team's
  repository survives (`Retain`).
- **Observability.** Printer columns, per-part states, counters of projects by outcome, an alert on
  `ImageRepositoryConflict` and on any project `Ready=False` longer than a day.
- **Upgrade.** The leader writes; an older replica does not know the kind and does nothing.

## Alternatives considered

- **Projects in `weebo-si`'s `values.yaml`**, like teams today — rejected by weebo-si RFC 0002 P3:
  teams must serve themselves.
- **Crossplane Compositions or Kratix Promises** for the composition — a second way of composing
  next to RFC 0011's, for a gain this cluster does not need.
- **`spec.team` on the project** — lets a team declare a project for another; the namespace is
  the only identity a team cannot forge.
- **One angos repository per team** (`<team>`) instead of per project — fewer entries, but no
  per-project push rights for CI and it would overlap the existing `weebo` base repository.

## Drawbacks and risks

- `weebo-si-operator` grows from guardrails and identity into composition across six kinds owned by
  other projects; their schemas are a moving dependency, kept loose by the untyped `DesiredObject`.
- Che samples are cluster-wide: every user sees every project's sample.
- The angos file is a single point where one bad project could block others' images; the validator
  is what keeps that theoretical.

## Unresolved questions

- Che samples visibility (non-blocking): per-team filtering is not something Che offers today.
- Whether the declaration repository should also be mirrored by default (non-blocking).
- CI identity in angos rules: `provider:` name for the source forge's Actions OIDC, once the
  network link exists (weebo-si RFC 0001 D11) — non-blocking, `images` can ship pull-only.

## Future work

- `data` (CNPG, RustFS), `environments` (Argo CD applications, ephemeral previews),
  `observability` — one RFC each.
- batlehub scopes through its operator (`artifacts.packages`).

## Implementation plan

- [ ] `WeeboSiTeam.projects`, `WeeboSiTeam.forgejo`, singleton allow-lists
- [ ] Team namespace, `AppProject`, `Application`, declaration repository
- [ ] Mirror organization and team with members from users
- [ ] `WeeboSiProject`: `source` (`Ensure`, `Adopt`)
- [ ] `mirror`
- [ ] `devEnv`
- [ ] `artifacts.images` and angos chart change
- [ ] Docs updated
- [ ] RFC flipped to `Implemented`

## References

- RFC 0011 — teams and users as objects
- RFC 0015 — platform API group
- weebo-si `.rfc/0001` (Forgejo mirror), `.rfc/0002` (platform), `.rfc/0003` (weebo-forgejo)
- angos configuration (`-c` merging, repository prefixes); Eclipse Che getting-started samples

## Changelog

| Date | Change |
| --- | --- |
