---
rfc: 0001
title: passwd-append
status: Draft
authors: [batleforc]
created: 2026-08-23
updated: 2026-08-23
decided:
brick: bins/passwd-append
supersedes: []
superseded-by: []
---

# RFC 0001 — passwd-append

## Summary

`passwd-append` is a small static binary that gives the container's running UID a real entry in
`/etc/passwd` and `/etc/group` at startup, so that tooling which asks "who am I and where is my
home" gets an answer instead of an error. It reproduces, byte for byte, the entries che-code's
`entrypoint-volume.sh` writes today, and replaces the shell snippet currently
copy-pasted across the Weebo images. It is the first brick of `weebo-si-hardening` and the
reference case for "a brick that does *not* need hexagonal layering".

## Motivation

OpenShift — and any cluster with a comparable SCC/PSA posture — runs containers under an
arbitrary UID from the namespace's allocated range, with GID `0`. That UID exists nowhere in the
image's `/etc/passwd`. The image was built expecting `1000` or `user`; it gets `1000730000`.

To be taken into account, a future RFC will add a block allowing only the write to `/etc/passwd` and `/etc/group` from `passwd-append` to be allowed, and no other writes to those files. In addition, i'm thinking about adding the "uid" and "gid" per namespace to the `weebo-si-hardening` brick, so that the `passwd-append` can be used in a more generic way, and not only for OpenShift.

What breaks, concretely:

- `whoami`, `id -un`, `getpwuid(geteuid())` fail. Anything shelling out to them fails with it.
- `$HOME` resolves to `/` or to nothing. Tools then write their state into `/` — where they
  either fail on a read-only root filesystem or, worse, succeed and lose everything on restart.
- `git` refuses to commit without a resolvable identity. `ssh` refuses to read a key whose
  directory it cannot attribute. Node's `os.userInfo()` throws.

### What exists today

The reference implementation is upstream, in che-code's
[`build/scripts/entrypoint-volume.sh`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L61-L67),
and the Weebo images carry the same thing:

```sh
#!/bin/sh
# ...
# UDI8 support for adding current (arbitrary) user to /etc/passwd and /etc/group
if ! whoami &> /dev/null; then
  if [ -w /etc/passwd ]; then
    echo "${USER_NAME:-user}:x:$(id -u):0:${USER_NAME:-user} user:${HOME}:/bin/bash" >> /etc/passwd
    echo "${USER_NAME:-user}:x:$(id -u):" >> /etc/group
  fi
fi
```

**This is the format `passwd-append` must reproduce**, guards included. It is more careful than
the two bare `echo`s it is often quoted as: `! whoami` is the "does this UID already resolve"
check, so it is idempotent, and `[ -w /etc/passwd ]` means it declines rather than erroring when
the file is read-only. Those two decisions are inherited wholesale by this design — they are
steps 2 and 5 of *Behaviour* below.

What it still costs:

- **`&>` is a bashism, and the shebang is `/bin/sh`.** Under `dash` or busybox `ash` — Alpine, and
  the `micro` images this very script goes on to special-case a few lines later — `whoami &> /dev/null`
  does not parse as a redirect. It parses as `whoami &` (backgrounded) followed by `> /dev/null`
  (a redirection with no command). The `if !` therefore tests the exit status of *starting a
  background job*, which is always `0`, so the negation is always false and **the block never
  runs**. It works today only because the images that use it happen to ship bash as `/bin/sh`.
  This is the single strongest argument for replacing it: it is silently a no-op on exactly the
  slim images the hardened variants are moving to.
- **The writability guard covers the wrong number of files.** `[ -w /etc/passwd ]` gates both
  `echo`s, but the second writes to `/etc/group`. A writable passwd and a read-only group file
  gives a failed redirect on stderr and an entry that is half-applied.
- **It needs a shell, `whoami` and `id` in the final image.** That forecloses distroless and
  static-musl base images, which is a stated direction for the hardened variants.
- **It hardcodes `/bin/bash`.** On an image without bash — again, the direction the hardened
  variants are going — every entry it writes names a shell that is not there.
- **It has no field validation.** `HOME` and `USER_NAME` are set by whoever authors the pod spec
  or devfile. A `:` in `$HOME` silently produces a wrong home directory; a newline appends a
  second, attacker-chosen passwd entry. `>>` cannot tell the difference.
- **It assumes the file ends in a newline.** When it does not — and no rule says it must — the
  new entry is welded onto the previous line, corrupting both.
- **It is silent.** When the guard declines, nothing is logged. The symptom shows up much later,
  somewhere else.
- **It is duplicated per image and drifting.** Small enough that nobody factors it out and
  everybody edits their own copy.

**Outcome we are buying:** any image, including one with no shell, adds one entrypoint statement
and gets the same entries this snippet produces — but on musl and busybox too, with the fields
validated, and with a log line when it declines.

## Guide-level explanation

The image ships the binary and calls it as the entrypoint, handing over to the real command:

```dockerfile
COPY --from=build /out/passwd-append /usr/local/bin/passwd-append
# Both files must be writable by GID 0, since that is the only identity we are sure to have
RUN chmod g=u /etc/passwd /etc/group
ENTRYPOINT ["/usr/local/bin/passwd-append", "--", "/usr/local/bin/real-entrypoint"]
```

On start, for UID `1000730000` with `HOME=/home/user` and no `USER_NAME` set, it appends to
`/etc/passwd`:

```text
user:x:1000730000:0:user user:/home/user:/bin/bash
```

and to `/etc/group`:

```text
user:x:1000730000:
```

then `exec`s `real-entrypoint`, so the real process keeps PID 1 and its signal handling.

Byte-for-byte what
[`entrypoint-volume.sh#L64-L65`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L64-L65)
produces, on an image that has bash. On an image that does not, the shell field follows the
fallback chain below instead of naming a binary that is not there.

When the UID already resolves — the ordinary case on a cluster that does *not* randomize UIDs,
and on every re-run — it logs one line and execs immediately. Nothing to undo.

When `/etc/passwd` is not writable, the default is to warn and continue:

```text
WARN passwd-append: /etc/passwd is not writable, uid 1000730000 will stay unresolved
```

The container starts, degraded but alive. `--strict` turns that into a hard failure instead, for
images where an unresolved UID is a guaranteed outage further down.

## Design

### Contract

**Invocation**

```text
passwd-append [OPTIONS] [-- COMMAND [ARGS...]]
```

| Flag | Env | Default | Meaning |
| --- | --- | --- | --- |
| `--name <NAME>` | `USER_NAME` | `user` | Login name, and group name. |
| `--home <PATH>` | `HOME` | `/home/<name>` | Home directory field. |
| `--shell <PATH>` | — | first of `/bin/bash`, `/bin/zsh`, `/bin/sh` that exists | Shell field. |
| `--gecos <TEXT>` | — | `<name> user` | Comment field. |
| `--gid <GID>` | — | `0` | Primary GID in the passwd entry. |
| `--passwd <PATH>` | `NSS_WRAPPER_PASSWD` | `/etc/passwd` | passwd file to append to. |
| `--group <PATH>` | `NSS_WRAPPER_GROUP` | `/etc/group` | group file to append to. |
| `--no-group` | — | off | Skip the group entry entirely. |
| `--strict` | `WEEBO_PASSWD_STRICT` | off | Turn a failed append into a non-zero exit. |
| `--dry-run` | — | off | Print both lines that would be appended; write nothing. |

Precedence is flag > env > default, uniformly.

`--` separates the binary's own arguments from a command to `exec` afterwards. With no `--`,
`passwd-append` does its work and exits — for use as an init container or ahead of a shell
entrypoint.

**Defaults, and why they are these**

- **`--name` → `USER_NAME`, else `user`.** Exactly the snippet's `${USER_NAME:-user}`. Keeping
  the env var name means images that already set it need no change.
- **`--gecos` → `<name> user`.** Reproduces `${USER_NAME:-user} user`, which yields `user user`
  in the default case. Odd-looking, faithful, and nothing reads it.
- **`--gid` → `0`.** Hardcoded rather than read from `getegid()`. On OpenShift they are the same
  value, but the snippet's `0` is what is deployed today and a drop-in replacement should not
  quietly start emitting something else on a cluster where they differ.
- **`--shell` → probe `/bin/bash`, `/bin/zsh`, `/bin/sh` in order.** The snippet's hardcoded
  `/bin/bash` is the one thing that does not survive the move to slimmer images. The probe is a
  `stat` on up to three paths; the first that exists wins. If none do, the field is left empty,
  which `getpwnam` treats as "use `/bin/sh`" — the same outcome, without asserting a path we
  could not verify.
- **No `SHELL` env fallback**, deliberately. `$SHELL` in a container is usually inherited noise
  from the build, not a statement about this image. The probe answers the same question from the
  filesystem, which cannot be wrong.
- **`--home` → `HOME`, else `/home/<name>`.** The snippet uses `${HOME}` unguarded and writes an
  empty field when it is unset. An empty home is how tools end up writing to `/`; the fallback is
  a deliberate improvement, not a faithful reproduction.

**Behaviour**

1. Read the effective UID.
2. If the UID already resolves in the passwd database, skip the passwd append. Independently, if
   the name or the GID already resolves in the group database, skip the group append. Both
   skipped means there is nothing to do — go to step 6.
3. Build each entry and validate it (below).
4. Append with an `O_APPEND` write, ensuring the file ends in a newline first.
5. On write failure: warn and continue, or exit `3` under `--strict`. The two files are handled
   independently — a read-only `/etc/group` does not prevent the passwd entry.
6. If a command followed `--`, `execvp` it. Otherwise exit `0`.

**Entry formats**

```text
passwd:  <name>:<pw>:<uid>:<gid>:<gecos>:<home>:<shell>
group:   <name>:<pw>:<uid>:
```

`<pw>` is always the literal `x` — the placeholder meaning "the hash lives in the shadow file",
which is what the upstream snippet writes. It is never anything else, and there is no flag for it.

Note the group entry puts the **UID** in the GID field, and leaves the member list empty — that
is what the upstream snippet does. See *Unresolved questions*; the default is to reproduce it.

**Validation — this is the security-relevant part.** Every field is attacker-influenced, because
whoever writes the pod spec sets `HOME`, `USER_NAME` and the flags. A `:` or a newline in any
field does not corrupt one line, it *forges an additional entry*. So:

- Reject any field containing `:`, `\n`, `\r`, or a NUL.
- Reject a `name` that is not `[a-zA-Z0-9._-]{1,32}`, or that starts with `-`.
- Require `home` to be an absolute path, and `shell` to be absolute or empty.
- Ensure the file ends with a newline before appending.

A rejected field is a usage error (exit `2`), never a silently sanitized one. Silently dropping a
colon out of a path produces a wrong home directory that nobody notices for a week.

**Exit codes**

| Code | Meaning |
| --- | --- |
| `0` | Entries appended, or already present, or `--dry-run`. If a command was given, this is the command's own exit code after `exec`. |
| `1` | Internal error (cannot read own UID, cannot stat a target file). |
| `2` | Usage error: bad flag, or a field that failed validation. |
| `3` | An append failed and `--strict` was set. |

**Stability.** Exit codes, flag names, `USER_NAME`, and the emitted line formats are the
contract; changing any of them needs a new RFC.

### Architecture

**No hexagonal layout.** Measured against the three criteria in
[`../architecture/hexagonal.md`](../architecture/hexagonal.md): there is no policy (criterion 1
fails outright — the only branches are "does this already resolve" and "which shell exists"), and
while it does touch the filesystem, a port around "append a line to a file" would have a fake
larger than the real implementation. It lives in `bins/passwd-append` as flat modules:

```text
bins/passwd-append/src/
├── main.rs      # arg parsing, orchestration, exec handover
├── entry.rs     # build + validate the passwd and group lines   <- where the tests are
└── nss.rs       # read the databases, detect the uid/name, probe for a shell, append
```

`entry.rs` is a pure `PasswdEntry::new(...) -> Result<PasswdEntry, InvalidField>` and its group
counterpart, plus their `Display`. Neither does I/O, and between them they hold every validation
rule, so the security-relevant logic is table-testable without a filesystem. That is the 80% of
hexagonal's benefit at none of its cost, and it is the pattern the other `bins/` members should
copy.

The shell probe is the one impure default. It takes the candidate list as an argument
(`resolve_shell(&["/bin/bash", "/bin/zsh", "/bin/sh"], &probe)`) so the ordering logic is tested
against a fake `probe` and only the `stat` itself stays untested.

**Static linking.** Built against musl so it runs in a distroless or scratch final stage. An
LD_PRELOAD-based approach cannot make that claim, which is half the reason this exists.

### Data and state

Stateless. It reads `/etc/passwd` and `/etc/group` (or the `NSS_WRAPPER_*` targets) and appends
to them. Each write is a single `O_APPEND` `write(2)` of one line — atomic enough for our case,
since we are the only writer inside the container and the line is far under `PIPE_BUF`.

The mutation lives in the container's writable layer or in an `emptyDir`, and dies with the
container. Every restart re-derives it. There is nothing to migrate and nothing to back up.

## Security considerations

**Privileges.** None beyond the container's own. It needs no capabilities, no root, and no
Kubernetes RBAC. It writes two files that the running identity is already permitted to write —
if they are group-writable, that is a property of the image, established at build time by the
same `chmod g=u` the current snippet already requires. `passwd-append` grants no access that a
shell in the same container did not already have.

**Trust boundary.** `HOME`, `USER_NAME`, the flags: all set by whoever authors the pod spec or
the devfile, which in a Che context is not necessarily the cluster admin. Treated as untrusted;
see the validation rules above. This is the one place this brick can do real damage — an
unvalidated newline in `HOME` appends an arbitrary second passwd entry, and an entry naming UID
`0` is a plausible thing for an attacker to want. Today's `>>` has this hole; closing it is a
concrete reason to prefer a binary over the snippet.

**Bypass.** Trivially bypassable and that is fine: it is a usability shim, not a control. Nothing
depends on it having run. It must therefore never be *load-bearing* for a security decision — if
a later brick wants to trust the passwd entry as an identity claim, that is a different design
and a different RFC.

**Blast radius.** Confined to one container's `/etc/passwd` and `/etc/group`. It cannot see the
cluster.

**Secrets.** Reads no secret. Logs the constructed lines at `INFO` on success — they carry no
password material (`x` placeholder), but this is why `--gecos` is validated and why nothing else
from the environment is ever echoed.

**Refusing UID 0.** If the effective UID is `0`, root already resolves and step 2 short-circuits.
The binary never constructs an entry for a UID other than its own effective one — there is no
flag to override it, deliberately.

**Shell probe.** The probe only `stat`s a fixed list of three absolute paths. It never reads
`PATH`, never follows a caller-supplied candidate list, and cannot be steered into naming a
binary outside `/bin`. `--shell` can name anything, but `--shell` is already trusted input.

## Operational considerations

**Failure mode: fail-open by default.** An unresolved UID degrades a workspace; a container that
refuses to start takes it down entirely. For a convenience shim the asymmetry is clear, so the
default warns and continues — matching today's snippet, which cannot fail the container either.
`--strict` exists for images that will fail immediately anyway, so the operator gets the real
cause instead of a confusing downstream error.

**Rollout.** Per image, one line in a Containerfile. No cluster-side component, no coordination,
no ordering constraint. Images that keep the shell snippet keep working, and an image running
both is safe: step 2 makes whichever runs second a no-op. That overlap is what makes the
migration incremental — the snippet can be deleted per image, on its own schedule.

**Rollback.** Revert the image tag. There is no persistent state to unwind.

**Observability.** One structured log line per path (appended / already resolved / not writable /
rejected field), on stderr so it does not pollute a piped stdout. No metrics: this runs once and
exits, and there is nothing to scrape it.

**Upgrade.** Nothing runs concurrently. Old and new images coexist without interacting.

**PID 1 and signals.** With `--`, the binary `execvp`s rather than forking, so the real process
becomes PID 1 and receives `SIGTERM` directly. No signal forwarding to get wrong, no zombie
reaping to implement. Worth stating because the obvious `fork`+`wait` implementation would
quietly break graceful shutdown across every image that adopts this.

## Alternatives considered

**Keep the upstream snippet as-is.** Zero new code, and it works on every image that ships bash.
Rejected for the costs listed in *Motivation*, the `&>` bashism first — but note the alternative
is not "delete it now": the two coexist safely, so this is a migration, not a cutover.

**Fix the snippet upstream instead.** Change `&>` to `>/dev/null 2>&1`, add a `[ -w /etc/group ]`
guard, probe for the shell. That is the honest cheap option, it helps everyone using che-code, and
it should probably happen regardless of this RFC. It still leaves the image needing a shell,
`whoami` and `id`, and still has no field validation — so it narrows the gap rather than closing
it. **Worth opening upstream as a separate contribution**; see *Future work*.

**`nss_wrapper` (`LD_PRELOAD`).** The established answer, and it handles more of NSS than we do.
Rejected: it requires a dynamic loader and glibc in the final image, which forecloses distroless
and static-musl images — a stated goal of this repo. It also silently does nothing for statically
linked processes, which is a failure mode that is very hard to debug from the symptom.

**Pin a UID in the image and require `runAsUser`.** Simplest of all, when it is available.
Rejected as the general answer: it needs an SCC that permits a chosen UID, which is exactly the
posture this repo exists to avoid asking for.

**Set `HOME` and let tools cope.** Fixes the most common symptom and nothing else — `whoami`,
`git` and `os.userInfo()` still fail. Not a substitute; it is what people try first and abandon.

**Do it from the operator, via a mutating webhook.** A later brick could inject this binary and
its entrypoint into pods that did not opt in. That is a genuinely useful follow-up, but it needs
the binary to exist first, and it is a separate contract with a separate blast radius.

## Drawbacks and risks

- One more binary in every image, and one more thing to keep building for every target arch.
- It reimplements a slice of NSS. That slice is small and frozen (the passwd and group formats
  have not moved in decades), but it is not zero.
- The name says `passwd` and it also writes `group`. See *Unresolved questions*.
- Fail-open means a misconfigured image looks healthy at startup and fails later, further from
  the cause. The log line is the mitigation; it is a weaker mitigation than failing loudly.
- The shell probe makes the emitted entry depend on the image's contents, so the same invocation
  produces different output in different images. That is the point, and it is also the thing that
  will confuse someone diffing two `/etc/passwd` files.

## Unresolved questions

**Blocking acceptance:**

- **The name.** This brick writes `/etc/group` too, so `passwd-append` undersells it. Keep the
  name (treating "passwd" as shorthand for the NSS pair, and `--no-group` as the escape hatch),
  or rename to something like `nss-append`? Cheap to decide now, annoying later — the binary name
  is in every Containerfile that adopts it.

**Not blocking:**

- **The group entry's GID field.** The snippet writes the UID there, while the passwd entry's GID
  field is `0`. So the group named `user` gets GID = UID and is nobody's primary group — `id`
  reports `uid=1000730000(user) gid=0(root)` and the `user` group dangles. Harmless, and quite
  possibly a copy-paste artifact rather than a decision. Default is to reproduce it faithfully;
  worth a look before this is set in contract.
- **Empty shell field when no candidate exists.** Relying on `getpwnam`'s "empty means `/bin/sh`"
  is correct per `passwd(5)` but obscure. Writing `/bin/sh` unconditionally would be more legible
  and occasionally a lie.
- Is `--dry-run` worth its weight, or is it a flag nobody will ever type?
- Should `--strict` be the default, with images opting into leniency instead?

## Future work

- **Operator-side injection** of the binary and entrypoint via a mutating webhook, for pods that
  never opted in. Its own RFC.
- **Multi-arch builds** (`arm64`) once anything in the fleet needs them.
- **Deleting the shell snippet** from every Weebo image, tracked per image once this ships.
- **Reporting the `&>` bug upstream** to che-incubator/che-code, with the one-line fix. It costs
  us nothing, it is a real silent no-op on musl images, and it is the right thing to do whether or
  not this binary ever ships.

## Implementation plan

- [ ] `bins/passwd-append` scaffold: workspace member, inherited lints, musl target
- [ ] `entry.rs` — passwd and group entry construction and validation, with the table-driven test
      suite covering every rejection rule (`:`, newline, relative path, bad name, UID 0)
- [ ] `nss.rs` — passwd/group lookup, shell probe against an injected prober, trailing-newline
      handling, `O_APPEND` write
- [ ] `main.rs` — flag/env precedence, `--` split, `execvp` handover, exit codes
- [ ] Integration test over temp files: fresh append, idempotent re-run, file with no trailing
      newline, read-only target under both default and `--strict`, `--no-group`
- [ ] Golden test asserting the default output is byte-identical to what
      [che-code's `entrypoint-volume.sh#L64-L65`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L64-L65)
      produces, on an image where `/bin/bash` exists. This is the test that pins the contract —
      if it ever needs relaxing, that is a RFC amendment, not a fixture update.
- [ ] Containerfile with multi-stage musl build, plus the `chmod g=u` reference snippet
- [ ] `task audit` covers the crate
- [ ] Docs: usage in `docs/`, and the Containerfile snippet in the images that adopt it
- [ ] RFC flipped to `Implemented`

## References

- [che-code `build/scripts/entrypoint-volume.sh#L61-L67`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L61-L67)
  — **the format of record.** The entries this binary emits are defined by these two lines; any
  divergence is a bug in this RFC, not an improvement.
- [OpenShift: support arbitrary user IDs](https://docs.openshift.com/container-platform/latest/openshift_images/create-images.html#use-uid_create-images)
- [`nss_wrapper`](https://cwrap.org/nss_wrapper.html) — the alternative rejected above
- `passwd(5)` and `group(5)` — the field formats and their escaping rules
- [`../architecture/hexagonal.md`](../architecture/hexagonal.md) — the criteria this RFC is
  measured against when it declines the layout

## Changelog

| Date | Change |
| --- | --- |
