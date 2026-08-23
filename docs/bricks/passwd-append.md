# `passwd-append`

Give the container's arbitrary UID a real `/etc/passwd` and `/etc/group` entry at startup, so
tooling that asks "who am I and where is my home" gets an answer instead of an error.

Design and rationale: [RFC 0001](../rfc/0001-passwd-append.md). This page is the operator's copy —
what to put in a Containerfile and what the output means.

## Adopting it

### Case 1 — an entrypoint you do not own (che-code, `WeeboDevImage`)

`entrypoint-volume.sh` *is* the command, not a wrapper around one, and everything after the
passwd block assumes an identity that resolves. So the block is replaced in place and the script
keeps running:

```dockerfile
COPY --from=passwd-append / /usr/local/bin/passwd-append
# Both files must be writable by GID 0, the only identity we are sure to have.
RUN chmod g=u /etc/passwd /etc/group
# The grep is the assertion — an upstream reword must fail the build, never silently no-op.
RUN grep -q '^if ! whoami' /entrypoint-volume.sh \
 && sed -i '/^if ! whoami/,/^fi$/c\/usr/local/bin/passwd-append' /entrypoint-volume.sh
# tini at PID 1, with -g so SIGTERM reaches the whole process group and not just the shell.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/entrypoint-volume.sh"]
```

`-g` is not optional. Without it the init forwards `SIGTERM` to the shell, which dies and orphans
the real process — reaping is fixed while graceful shutdown is not, and the vanished zombies make
it look fixed. See the RFC's *PID 1 and signals*.

### Case 2 — an entrypoint you do own

```dockerfile
COPY --from=passwd-append / /usr/local/bin/passwd-append
RUN chmod g=u /etc/passwd /etc/group
ENTRYPOINT ["/usr/bin/tini", "--", \
            "/usr/local/bin/passwd-append", "--", \
            "/usr/local/bin/real-entrypoint"]
```

No `-g` here: `passwd-append` `exec`s, so `real-entrypoint` is already the init's direct child.

## Usage

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
| `--strict` | `WEEBO_PASSWD_STRICT` | off | Turn a failed append into exit `3`. |
| `--dry-run` | — | off | Print both lines on stdout; write nothing. |
| `-h`, `--help` | — | — | Usage. |

Precedence is flag > env > default, uniformly. With no `--`, the binary does its work and exits —
which is the mode case 1 uses.

## What it writes

For UID `1000730000` with `HOME=/home/user` and no `USER_NAME`, on an image with bash:

```text
/etc/passwd:  user:x:1000730000:0:user user:/home/user:/bin/bash
/etc/group:   user:x:1000730000:
```

Byte for byte what che-code's
[`entrypoint-volume.sh#L64-L65`](https://github.com/che-incubator/che-code/blob/main/build/scripts/entrypoint-volume.sh#L64-L65)
produces. A golden test pins it; if that test ever needs relaxing, that is a RFC amendment.

The group line carries the **UID** in the GID field and an empty member list. That is upstream's
format, reproduced deliberately.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Appended, already present, or `--dry-run`. With a command, this is the command's own code. |
| `1` | Internal error: a target that could not be opened, locked or read at all, or a command that could not be `exec`'d. |
| `2` | Usage error: bad flag, or a field that failed validation. |
| `3` | An append failed and `--strict` was set. |

## Reading the logs

One line per path, on stderr, so a piped stdout stays clean.

```text
INFO  passwd-append: appended to /etc/passwd: user:x:1000730000:0:user user:/home/user:/bin/bash
WARN  passwd-append: /etc/passwd already resolves uid 1000730000 to 'user', nothing to do
WARN  passwd-append: /etc/passwd is not writable, leaving it unchanged
ERROR passwd-append: /etc/passwd: cannot open, lock or read it: Not a directory (os error 20)
```

The last one is the only one that stops the container. **A target that is absent or read-only is
declined with a `WARN` and exit `0`**; a target the process cannot open *to find out* is exit `1`.
The line matters because it is the difference between "your image did not make `/etc/passwd`
group-writable" and "something underneath is broken".

The `WARN` on an already-present entry is the **only** signal that a call was a no-op — the exit
code is `0` either way, deliberately, so that an init container running this does not
`CrashLoopBackOff` on the second restart of a healthy pod.

## Things it will not do

- **Write a second entry for a UID that already resolves.** In any mode, through any flag
  combination. There is no `--force`.
- **Write an entry for a UID other than its own effective one.**
- **Write an entry claiming UID `0`.**
- **Fail the container** unless you ask for it with `--strict`.
- **Sanitise a bad field.** A `:` or a newline in `HOME` is exit `2`, not a quietly corrected
  value — silently dropping a colon produces a wrong home directory nobody notices for a week.
