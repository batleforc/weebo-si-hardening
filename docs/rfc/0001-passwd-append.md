---
rfc: 0001
title: passwd-append
status: Accepted
authors: [batleforc]
created: 2026-08-23
updated: 2026-08-23
decided: 2026-08-23
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
copy-pasted across the Weebo images. It writes those entries **once per container and never
twice**, with no flag to override that. It is the first brick of `weebo-si-hardening` and the
reference case for "a brick that does *not* need hexagonal layering".

## Motivation

OpenShift — and any cluster with a comparable SCC/PSA posture — runs containers under an
arbitrary UID from the namespace's allocated range, with GID `0`. That UID exists nowhere in the
image's `/etc/passwd`. The image was built expecting `1000` or `user`; it gets `1000730000`.

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
the single-shot check and the writability handling in *Behaviour* below, which take both further.

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
and on every container restart — it logs one line and execs immediately. Nothing to undo.

The entry is written **once per container and never twice**. Calling the binary again is harmless
and does nothing — there is no flag that appends a second entry for the same UID:

```console
$ passwd-append
WARN  passwd-append: uid 1000730000 already resolves to 'user', nothing to do
$ echo $?
0
```

Details, and what that does and does not guarantee, in *Single-shot* below.

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
2. Build each entry and validate it (below). Validation happens before any file is touched, so a
   bad field costs nothing.
3. For each target file, in turn:
   1. Take an exclusive `flock` on it.
   2. **Under the lock**, scan it. If the UID already resolves in the passwd database, skip the
      passwd append; if the name or the GID already resolves in the group database, skip the
      group append.
   3. Otherwise ensure the file ends in a newline, append with an `O_APPEND` write, and release
      the lock.
4. On write failure: warn and continue, or exit `3` under `--strict`. The two files are handled
   independently — a read-only `/etc/group` does not prevent the passwd entry.
5. If nothing was appended because everything was already present, apply the single-shot rule
   below.
6. If a command followed `--`, `execvp` it. Otherwise exit `0`.

**Single-shot: the entry is written once per container, and never twice**

Two separate mechanisms, because they defend against two different things.

*Against a race.* Steps 3.ii and 3.iii are check-then-act, and check-then-act without a lock is
not idempotent — it only looks idempotent when nothing runs concurrently. Two invocations that
both read `/etc/passwd` before either writes will both conclude the UID is absent, and both
append. The upstream snippet has exactly this hole; it has never been hit because nothing calls
it twice at once. Holding an exclusive `flock` across the read *and* the write closes it, and
costs one syscall. The scan is deliberately re-done **inside** the lock — scanning before taking
it would reintroduce the window it exists to close.

*Against re-invocation.* Once an entry for the effective UID exists, there is nothing this binary
can legitimately do, so it does nothing — in every mode, whatever the flags:

```console
$ passwd-append
WARN  passwd-append: uid 1000730000 already resolves to 'user', nothing to do
$ echo $?
0
```

**There is no flag to append anyway.** No `--force`, no `--allow-duplicate`, no second `--name`
that writes a second entry for the same UID. The binary writes at most one passwd entry and one
group entry per container lifetime, for its own effective UID only, and that is not overridable
from the command line. See *Security considerations* for why that property is load-bearing.

**Be precise about what this guarantees.** Re-invocation is *neutralised*, not *refused*: a second
call succeeds and exits `0`, it simply writes nothing. Exiting non-zero was considered and
rejected — an already-present entry is the normal case on every container restart and on every
cluster that does not randomize UIDs, and an init container running `passwd-append` would go
`CrashLoopBackOff` on the second restart of a perfectly healthy pod. Turning a non-event into an
outage is the opposite of what this brick is for. The cost is that a caller looping on the binary
learns nothing from the exit code; the `WARN` line is the only signal, which is why it is `WARN`
and not `INFO`.

The property that actually matters is the write, and it is unconditional: no second entry is ever
appended for a UID that already resolves, by any caller, through any flag combination.

The check keys on the **UID** for passwd and on the **name or GID** for group — not on the exact
line we would have written. A caller that reruns with a different `--home` or `--gecos` therefore
gets refused rather than appending a second, differing entry for the same UID. That is the case
this rule exists to stop.

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
| `0` | Entries appended, already present, or `--dry-run`. If a command was given, this is the command's own exit code after `exec`. |
| `1` | Internal error (cannot read own UID, cannot stat or lock a target file). |
| `2` | Usage error: bad flag, or a field that failed validation. |
| `3` | An append failed and `--strict` was set. |

"Already present" is deliberately not its own exit code — see *Single-shot* above.

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

Stateless — and deliberately so. It keeps no marker, no lock file, no record of having run: the
only thing that says "this was already done" is the target file itself, read under the lock right
before the write. That is what makes the single-shot rule impossible to desynchronise, because
there are not two things that could disagree.

Each write is a single `O_APPEND` `write(2)` of one line, under an exclusive `flock` held across
the preceding scan. The line is far under `PIPE_BUF`, so the write itself is atomic; the lock is
there for the check-then-act window, not for the write.

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

**Refusing UID 0.** If the effective UID is `0`, root already resolves and the single-shot check
short-circuits. The binary never constructs an entry for a UID other than its own effective one —
there is no flag to override it, deliberately.

**Bounded write primitive.** Between the single-shot rule, the fixed UID, and the absence of any
`--force`, the binary's total authority over a container is: *at most one passwd line and one
group line, for its own effective UID, once*. That bound is deliberate and worth stating as a
property rather than an implementation detail, because it is what makes the binary safe to be the
**only** permitted writer of those files — the direction the confinement work in *Future work*
takes. A tool that can be called repeatedly is a repeatable write primitive; once the file is
writable by nothing else, that primitive is the whole attack surface. Bounding it now, while the
binary has no users, costs nothing; bounding it later is a breaking change.

What it does **not** buy: an attacker who can already write `/etc/passwd` directly does not need
this binary, and the single-shot rule does not slow them down. It is only meaningful in
combination with the confinement that removes every other writer.

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
both is safe: the single-shot check makes whichever runs second a no-op. That overlap is what makes the
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

**A marker file (`/run/passwd-append.done`) to enforce single-shot**, instead of re-reading the
target. Rejected: the marker and the thing it describes have different lifetimes. `/run` is a
fresh tmpfs on every container start while `/etc/passwd` may live on an `emptyDir` that outlives
it, so the two can disagree in both directions — a marker with no entry, or an entry with no
marker. Reading the file we are about to write cannot drift from it. A marker beside the target
(`/etc/.passwd-append.done`) would have matching lifetimes but needs `/etc` itself to be
group-writable, which the `chmod g=u /etc/passwd /etc/group` recipe deliberately does not grant.

**Making the file immutable afterwards** (`chattr +i`) so a second write is impossible. Rejected:
it needs `CAP_LINUX_IMMUTABLE`, which is exactly the kind of capability this repo exists to avoid
requesting, and it would also block the legitimate writers that still exist today.

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
- `flock` is advisory. It serialises `passwd-append` against itself, which is what the single-shot
  rule needs, but it does nothing about a concurrent `echo >> /etc/passwd` from elsewhere in the
  container. Only the confinement in *Future work* closes that, and until it lands the lock is a
  correctness fix rather than a security boundary.
- The single-shot rule is invisible in the exit code. A script that calls `passwd-append` in a
  loop gets `0` every time and never learns that only the first call did anything. That was the
  accepted trade against breaking init containers, but it means the `WARN` line is the only
  signal, and log lines are the first thing people stop reading.

## Unresolved questions

None. All of them were closed at acceptance; the ones that changed the design are in the
*Changelog*, the rest are recorded here so they are not reopened by accident.

- **The name.** Resolved: **keep `passwd-append`.** "passwd" is read as shorthand for the NSS
  passwd/group pair, and `--no-group` is the escape hatch for the passwd-only case. `nss-append`
  was the alternative; it describes the scope more precisely and was rejected as not worth
  changing a name that is already in use in conversation and would end up in every Containerfile.
- **The group entry's GID field.** Resolved: **reproduce the upstream line faithfully**, UID in
  the GID field and an empty member list, per the instruction that
  [`entrypoint-volume.sh#L64-L65`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L64-L65)
  is the format of record. The oddity is documented under *Entry formats*; changing it would be a
  divergence from the format, which is a new RFC by the *Stability* rule.
- **Standalone exit code when the entry is already present.** Resolved: **`0` with a `WARN`**, not
  a dedicated non-zero code. Reasoning and the cost of that choice are under *Single-shot* and in
  *Drawbacks*.
- **Empty shell field when no candidate exists.** Resolved: keep it empty and let `getpwnam` apply
  its `/bin/sh` default. Writing `/bin/sh` unconditionally would be more legible but would assert
  a path we did not verify, which is the thing the probe exists to avoid.
- **`--dry-run` and the `--strict` default.** Resolved: keep `--dry-run`, keep `--strict` off.
  Fail-open is argued under *Operational considerations*, and `--dry-run` costs one branch in a
  binary whose whole job is to write to `/etc/passwd`.

## Future work

- **Confining writes to `/etc/passwd` and `/etc/group` to this binary alone**, so that no other
  process in the container may modify them. Its own RFC. This is what turns the single-shot rule
  from tidiness into a real control: once `passwd-append` is the only permitted writer, "it can be
  called once" and "the file can be written once" become the same statement. The design here is
  built to be ready for that — see *Bounded write primitive* — but it does not depend on it.
- **Per-namespace `uid`/`gid` supplied by the `weebo-si-hardening` operator**, rather than read
  from the running process. That would make this brick useful beyond OpenShift's arbitrary-UID
  model, on clusters where the identity is assigned rather than discovered. Its own RFC, and note
  it collides with *Refusing UID 0*: today the binary writes its own effective UID and nothing
  else, deliberately. Accepting an externally supplied UID reopens that decision and needs the
  threat model redone, not just a flag added.
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
      handling, `flock` + re-scan-under-lock + `O_APPEND` write
- [ ] `main.rs` — flag/env precedence, `--` split, `execvp` handover, exit codes
- [ ] Integration test over temp files: fresh append, idempotent re-run, file with no trailing
      newline, read-only target under both default and `--strict`, `--no-group`
- [ ] Single-shot tests: a re-run writes nothing and exits `0` with the `WARN` line, in both
      standalone and entrypoint mode; a re-run with a different `--home`/`--gecos` still writes
      nothing; N concurrent invocations against one temp file produce exactly one entry (the test
      that would fail without the lock)
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
| 2026-08-23 | Accepted. Name kept as `passwd-append` rather than `nss-append`, despite the brick also writing `/etc/group`. |
| 2026-08-23 | Accepted with a change: a re-invocation whose entry is already present now exits `0` with a `WARN` in every mode, instead of `4` in standalone mode. Rejecting the non-zero code was an init-container call — `CrashLoopBackOff` on the second restart of a healthy pod is a worse failure than a caller not learning that its call was a no-op. The write-side guarantee is untouched. |
