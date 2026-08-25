# RFC process

Every brick of `weebo-si-hardening` is described before it is built.

The bricks in this repo change how *other people's* workloads run: they rewrite pods,
reject deployments, and inject configuration into containers their owners did not write.
A bug in that position is not a broken feature, it is a cluster-wide incident — either
because something got through that should not have, or because everything got blocked.
The RFC is where we pay the thinking cost up front, in a diff we can argue with.

## When is an RFC required

**Required:**

- A new brick — binary, controller, admission or mutating webhook.
- A new *target* for an existing brick: a new rule enforced, a new resource mutated, a new
  field validated. Adding "we also reject images not from `registry.internal`" is an RFC.
- Any change to a contract someone else depends on: CRD schema, webhook configuration,
  CLI flags, config file format, exit codes, emitted metrics.
- Any change to a security-relevant default, or to a fail-open/fail-closed decision.
- Retiring or replacing a brick.

**Not required:**

- Bug fixes that restore the documented behaviour.
- Refactors that change no contract — including introducing the hexagonal layout into a
  brick that outgrew its simple form.
- Dependency bumps, CI changes, documentation.

When in doubt: if you would need a paragraph to explain the change to someone operating
the cluster, write the RFC.

## Statuses

| Status | Meaning |
| --- | --- |
| `Draft` | Being written. No review expected yet. Merging a `Draft` is fine and encouraged — it reserves the number and makes the work visible. |
| `Proposed` | Complete and open for review. Author is asking for a decision. |
| `Accepted` | Decision made, implementation may start. The design is now the reference. |
| `Implemented` | Shipped. The RFC describes what the code does; divergence is a bug in one or the other. |
| `Rejected` | Decision made not to build it. **The file stays**, with the reasoning — a rejected RFC is the cheapest way to stop relitigating the same idea. |
| `Superseded` | Replaced by a later RFC. `superseded-by` points at it. |

Transitions are `Draft → Proposed → Accepted → Implemented`, with `Rejected` reachable from
`Draft` or `Proposed`, and `Superseded` from `Accepted` or `Implemented`.

An `Accepted` RFC is not frozen: if implementation proves the design wrong, amend the RFC in
the same PR that changes course, and say what you learned in the *Changelog* section. The RFC
is a description of the system, not a contract with your past self.

## Numbering and naming

- `docs/rfc/NNNN-kebab-case-title.md`, four digits, zero-padded.
- `0000` is reserved for the template.
- The number is claimed by creating the file. Take the next free one; if two land at once, the
  second to merge renames.

Scaffold a new one with:

```bash
task rfc:new TITLE="restrict container images"
```

## Life of an RFC

1. **Write.** Copy the template (`task rfc:new`), fill it in, open a PR with status `Draft`.
   A `Draft` PR can merge as soon as it is coherent — do not sit on it.
2. **Propose.** Flip to `Proposed` when you want a decision. This is the review PR.
3. **Decide.** Review focuses on the *Security considerations*, *Operational considerations* and
   *Alternatives* sections — those are where this project gets hurt. Approval flips the status
   to `Accepted` and fills `decided`.
4. **Build.** Implementation PRs reference the RFC number in the commit scope
   (`feat(rfc-0001): ...`). The *Implementation plan* checklist is the tracker.
5. **Close.** The PR that completes the checklist flips the status to `Implemented`.

## Index

Generated from the front-matter of each RFC — do not edit the table by hand. `task recu`
regenerates it, and the pre-commit hook runs `task recu`, so it cannot drift. `task rfc:check`
fails if it is stale.

<!-- rfc-index:start -->

| # | Title | Status | Brick |
| --- | --- | --- | --- |
| [0001](./0001-passwd-append.md) | passwd-append | `Implemented` | `bins/passwd-append` |
| [0002](./0002-weebo-si-operator.md) | weebo-si-operator | `Implemented` | `crates/weebo-si-operator` |
| [0003](./0003-preauth-proxy.md) | preauth-proxy | `Implemented` | `bins/preauth-proxy` |
| [0004](./0004-network-profiles.md) | network-profiles | `Implemented` | `crates/weebo-si-network-profiles` |
| [0005](./0005-image-policy.md) | image-policy | `Implemented` | `crates/weebo-si-image-policy` |
| [0006](./0006-kubearmor-policy.md) | kubearmor-policy | `Implemented` | `crates/weebo-si-kubearmor-policy` |
| [0007](./0007-registry-config.md) | registry-config | `Implemented` | `crates/weebo-si-registry-config` |
| [0008](./0008-policy-guard-coverage.md) | policy-guard-coverage | `Draft` | `crates/weebo-si-policy-guard` |

<!-- rfc-index:end -->

## Checking a RFC

```bash
task rfc:check     # every RFC against the rules on this page
task rfc:index     # regenerate the index above
```

`rfc:check` validates the filename, the front-matter (keys, the number matching the filename,
ISO dates, a known status, a `decided` date once a decision was made), the title line, and the
presence of every mandatory section — including `### Architecture`, which is where a brick has to
state whether it uses [hexagonal layering](../architecture/hexagonal.md) and why. It also checks
the template itself, since every RFC is copied from it.

It runs in the pre-commit hook via `task lint`.

## Language

**RFCs are written in English.** Not because English is better, but because these bricks sit on
upstream Kubernetes, DevWorkspace and Eclipse Che vocabulary that has no settled French
translation, and half a RFC's value is being quotable in an upstream issue.

Thinking in French and writing in English is the normal way this goes wrong, so `rfc:check`
detects it: a curated list of French function words with no English or technical homograph, matched
case-insensitively and whole-word. One hit is enough. Words that spell something else in English
or in this repo's vocabulary — `est`/EST, `des`/DES, `du`/`du -sh`, `sans`/sans-serif, `ces`/CES,
`elle`/Elle, `tout`/to tout — are deliberately left out rather than guarded by a threshold.

If it fires on a legitimate English sentence, the fix is to remove the offending word from
`FRENCH_MARKERS` in `scripts/rfc-check.sh` and say why in the comment above the list — not to add
an exception for the file.
