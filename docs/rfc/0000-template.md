---
rfc: 0000
title: Template
status: Draft
authors: [batleforc]
created: 1970-01-01
updated: 1970-01-01
decided:
brick:
supersedes: []
superseded-by: []
---

# RFC 0000 — Template

> Copy this file with `task rfc:new TITLE="..."`.
> Delete every quoted instruction block as you fill the section in. A section that does not
> apply is answered with "N/A" and one line of why — never left blank, never deleted.

## Summary

> Two or three sentences. What is being built, for whom. Someone should be able to read only
> this and know whether the rest of the RFC concerns them.

## Motivation

> What is broken or missing today. Be concrete: the failing workflow, the manual step someone
> repeats, the attack this closes. If there is a real incident or ticket behind it, link it.
>
> Then: what does the world look like once this exists? State it as an outcome, not a feature
> list — that is what we will check against when the RFC flips to `Implemented`.

## Guide-level explanation

> Explain it as if to the person who will operate it, not implement it. What do they install,
> what do they configure, what do they see when it works, and what do they see when it does
> not. Show the YAML, the CLI invocation, the log line.

## Design

### Contract

> The surface other things bind to, spelled out: CRD schema or config format, CLI flags and
> exit codes, webhook path and the resources/verbs it intercepts, metrics emitted.
> This is the part that costs the most to change later — be precise here even if the internals
> stay vague.

### Architecture

> Does this brick use the hexagonal layout? Answer yes or no and justify it against the
> criteria in [`../architecture/hexagonal.md`](../architecture/hexagonal.md).
>
> If yes: list the ports (the traits the domain owns) and the adapters that implement them.
> If no: say what keeps it simple, and what would force the split later.

### Data and state

> What does this brick persist or cache, where, and what happens when that state is lost or
> stale? "Stateless" is a valid answer and a good one — say it explicitly.

## Security considerations

> Mandatory, and the section reviewers read first. At minimum:
>
> - **Privileges.** What RBAC/capabilities does this need, and why is that the minimum?
> - **Trust boundary.** What input is attacker-controlled? A webhook body is.
> - **Bypass.** How would someone get around this control? `namespaceSelector` gaps, resources
>   created before the webhook was installed, subresource updates, `--force`?
> - **Blast radius.** What breaks in the cluster if this brick is compromised or misbehaves?
> - **Secrets.** What does it read, and does any of it reach logs?

## Operational considerations

> - **Failure mode.** Fail-open or fail-closed, and the reasoning. For a webhook this is the
>   `failurePolicy` decision and it is a security *and* an availability call — argue both sides.
> - **Rollout.** How does this reach a cluster without breaking what is already running?
>   Dry-run mode, a warn-only phase, a `namespaceSelector` opt-in?
> - **Rollback.** What is the undo, and how fast is it?
> - **Observability.** What tells an operator this is working? What alerts on it being wrong?
> - **Upgrade.** What happens during a rolling update, when old and new run side by side?

## Alternatives considered

> At least one real alternative, including "do nothing" or "use an existing tool" (Kyverno,
> Gatekeeper, OPA, a `postStart` hook) where those apply. Say why each was not chosen. An RFC
> with no alternatives section reads as a decision that was never actually made.

## Drawbacks and risks

> What this costs us: maintenance surface, a new failure point in the admission path, coupling
> to an upstream API that moves. Honest, not defensive.

## Unresolved questions

> Open points that do not block acceptance, and the ones that do — mark which is which.
> Empty by the time the status reaches `Accepted`, or the leftovers move to *Future work*.

## Future work

> Explicitly out of scope for this RFC, kept here so reviewers stop asking.

## Implementation plan

> The tracker. Each box is a mergeable PR.

- [ ] ...
- [ ] Docs updated
- [ ] RFC flipped to `Implemented`

## References

> Upstream docs, related RFCs, prior art.

## Changelog

> Only once the RFC is `Accepted` and reality pushes back. One line per amendment: what
> changed and what taught us.

| Date | Change |
| --- | --- |
