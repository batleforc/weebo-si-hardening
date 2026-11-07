# `che-min-mise` review

What WeeboDevImage's `che-min-mise` could change to be smaller and tighter while staying the
image people want to work in. It is the base image of every workspace on weebo-si, so it decides
how much of [the weebo-si standard](./guides/weebo-si-standard.md) holds by construction and how
much has to be worked around. Each finding below says what was measured, what to change, what it
saves, and what it costs the person in the workspace.

The changes themselves belong to [WeeboDevImage](https://github.com/batleforc/WeeboDevImage). This
page is the hardening side's case for them.

## What was measured

| | |
| --- | --- |
| Image | `ghcr.io/batleforc/weebodevimage/che-min-mise:main`, pulled from the registry |
| Index digest | `sha256:d74b234efeba80f281d69fc8d9d997a3fc6c7aecd8e3b3c9848b811c2edce3a3` |
| linux/amd64 manifest | `sha256:8856ebf75e424210c3ae13bb4258fdd111f11253fab0d7fc1c9f49509d1637bb` |
| Built | 2026-11-02 14:45 UTC, WeeboDevImage `main` at `19fa931` |
| Size | **1.45 GB** uncompressed |
| Date of review | 2026-11-03 |

Line numbers below refer to `che-min-mise/Containerfile.tpl` and `che-min-mise/entrypoint.sh` at
`19fa931`. The commits since `ccf1e0c` only bump versions and leave these lines where they were.
The measurements are reproducible, against the registry rather than a local build:

```bash
IMG=ghcr.io/batleforc/weebodevimage/che-min-mise:main
podman pull "$IMG"
podman history --format '{{.Size}}\t{{.CreatedBy}}' "$IMG"
podman run --rm --entrypoint bash "$IMG" -c '
  dpkg-query -Wf "${Installed-Size}\t${Package}\n" | sort -rn | head -25
  du -sh /usr/lib/llvm-* /usr/local/share/fonts /home/tooling/.local/bin /usr/local/bin
  find / -xdev -perm -4000 -type f'
```

### Where the 1.45 GB goes

Three layers carry almost all of it: the apt layer (965 MB), the versioned-tools layer (358 MB)
and the `ubuntu:26.04` base (113 MB). Everything after them is under 11 MB.

| Item | Size | Needed in a headless workspace? |
| --- | --- | --- |
| `libclang-dev` → `libclang-21-dev`, `libllvm21`, `libclang1-21`, `libclang-common-21-dev` | **~460 MB** | only by Rust crates that run `bindgen` |
| gcc toolchain (`gcc-15`, `cpp-15`, `libstdc++-15-dev`, `libgcc-15-dev`, `libasan8`, `libtsan2`) | ~150 MB | yes: cgo, node-gyp, Python sdists, Cargo build scripts |
| `mise` | 176 MB, **not stripped** | yes, but 25 MB of it is the symbol table |
| `kubectl` | 62 MB | yes |
| perl (pulled in by git) | ~50 MB | indirectly |
| FiraCode Nerd Font, 18 `.ttf` | 48 MB | **no**: see S2 |
| `chezmoi` | 42 MB | yes |
| neovim + runtime | 34 MB | yes, comfort |
| lazygit | 24 MB | comfort |

### What the image lacks

| Tool | Present | Why it matters |
| --- | --- | --- |
| `ssh` | **no** | git over SSH cannot work, though the `dev-registries` network profile opens port 22 for it |
| `jq` | no | the everyday companion of `kubectl -o json` and `curl` |
| `ip` | no | `ifconfig` (net-tools) is there instead, deprecated |

### setuid binaries

`/usr/bin/su`, `passwd`, `chsh`, `chfn`, `gpasswd`, `mount`, `umount`, `newuidmap`, `newgidmap`.

### The child images

Pulled from the registry on 2026-11-03, built from the same `19fa931` within two minutes of the
base:

| Image | Size | Δ vs base | `/etc/passwd` | apt | setuid | `/globals`, `/home/tooling` |
| --- | --- | --- | --- | --- | --- | --- |
| `che-mise-nss` (`sha256:a47c1eb2…`) | 1.45 GB | +1 MB, `libnss-wrapper` | `root:root 0644` | purged, `dpkg` set to `no-act` | the same 9 | 775 |
| `che-mise-pdm` (`sha256:5e886602…`) | 1.71 GB | +268 MB, podman, buildah, skopeo | 664 | present | the same 9 | 775 |
| `che-mise-webkit` (`sha256:ad17ea96…`) | 2.09 GB | +643 MB, WebKitGTK, build-essential | 664 | present | the same 9 | 775 |

`che-mise-nss` already applies H2 and H5 (its devfile sets `readOnlyRootFilesystem: true`), and
goes further by removing apt. H1 and H3 apply to it as to the base. Its devfile also asks for
`hostUsers: false` and `procMount: Unmasked`; the second is refused at the `baseline` and
`restricted` levels, so that devfile only starts in a namespace at `privileged`. The image itself
runs under the standard's `weebo-workspace` DWOC.

## Findings

Grouped by what they buy. **S** is size, **U** is usability, **H** is hardening, **C** is the build
pipeline.

### S1 — Move `libclang-dev` out of the base image

**Saves ~460 MB, about a third of the image.** Line 64. Only `bindgen` needs it (rocksdb,
`*-sys` crates that generate bindings at build time). `libdbus-1-dev` (line 63) serves the keyring
crates and belongs with it.

Put both in a child image, `che-mise-native` or into `che-mise-webkit`, which already carries
build-essential for Tauri. A workspace that needs them names that image in its devfile. That is
one line, for the few projects that need it. Keep gcc in the base: cgo, node-gyp and most `-sys`
crates need a C compiler and nothing more, and a workspace user cannot `apt install` one.

### S2 — Drop the fonts

**Saves 48 MB.** Lines 49, 100-104. A Che workspace is rendered in the browser: che-code's editor
and its terminal draw with the fonts of the machine the browser runs on, never with fonts inside
the container. The starship glyphs show up when the browser or che-code's terminal font setting
names a Nerd Font, which is a client setting. `fontconfig` and the `fc-cache` call go with them.
`che-browser` and `che-desktop`, which do render inside the container, are standalone images and
keep their own.

### S3 — Strip `mise`

**Saves 25 MB.** Line 92. The release binary ships with its symbol table. `strip` is already in
the image through binutils:

```dockerfile
install -m 755 mise-${MISE_VERSION}-linux-x64 /home/tooling/.local/bin/mise && \
strip /home/tooling/.local/bin/mise && \
```

The checksum is verified on the downloaded file, before stripping, so nothing about verification
changes.

### S4 — Small removals

`wget` (line 40) duplicates `curl`. `net-tools` (line 54) is deprecated; `iproute2` is the
replacement if a network tool is wanted at all. A few MB, mostly fewer packages to scan.

**S1 to S4 together take the image from 1.45 GB to roughly 0.9 GB**, with nothing a developer
uses every day removed.

### U1 — Add `openssh-client`

**~5 MB, and the most important line in this page for users.** Without it, `git clone
git@github.com:…` fails with `ssh: not found`, whatever the network allows. It is also what
`git push` over SSH to `git.batleforc.fr` needs.

### U2 — Add `jq`

About 1 MB. `yq` and other less common tools stay one `mise use` away.

### U3 — A one-word `mise trust`

Goes with H4: `alias mt='mise trust && mise install'` in `/globals/shellrc`. Trusting a cloned
repository becomes one command, typed once per repository.

### U4 — Fail chezmoi fast, and say so

`entrypoint.sh` line 256 waits up to `CHEZMOI_TIMEOUT=120` seconds for the dotfiles repository.
Under the weebo-si network baseline, a workspace whose profiles do not reach the dotfiles host
starts two minutes late with no explanation. Default to 30 seconds, and on failure print one line
naming the URL and the likely cause (the `dev-registries` network profile). The workspace still
starts; it just stops looking frozen.

### H1 — Remove the setuid bits nothing needs

**0 MB.** No root password exists in the image, so `su`, `passwd`, `chsh`, `chfn`, `gpasswd`,
`mount` and `umount` serve nobody as setuid:

```dockerfile
RUN chmod u-s /usr/bin/su /usr/bin/passwd /usr/bin/chsh /usr/bin/chfn \
              /usr/bin/gpasswd /usr/bin/mount /usr/bin/umount
```

Move `uidmap` (line 47, which brings `newuidmap`/`newgidmap`) to `che-mise-pdm`, the only image
running rootless podman.

Under the weebo-si standard's `restricted` level, `no_new_privs` already neuters these. Under
`baseline`, used by the build team, it does not. Combined with H2's writable `/etc/passwd`, `su`
is a way to become root inside the container (see the standard's step 5). Removing the bit closes
that in the image, whatever the namespace level, without waiting for KubeArmor.

### H2 — Stop writing `/etc/passwd`: ship `libnss-wrapper` in the base

**~1 MB.** Lines 153-162 make `/etc/passwd` and `/etc/group` writable by group 0. When
`libnss_wrapper.so` is absent, `entrypoint.sh` lines 51-54 append the arbitrary UID to them with an
unvalidated `echo`. Anything running as the workspace user can therefore rewrite who exists in the
container, including adding a UID 0 entry with a password hash of its choosing.

The entrypoint already has the fix. Lines 38-50 look for `libnss_wrapper.so`, and when they find
it they write the entry to `$HOME/.nss_passwd` and `$HOME/.nss_group` and export
`NSS_WRAPPER_PASSWD`, `NSS_WRAPPER_GROUP` and `LD_PRELOAD` instead of touching `/etc`.
`che-mise-nss` turns it on with nothing but a package and a `chmod`: see
[the child images](#the-child-images). Run under an arbitrary UID, it prints `Registered user
(4242) via nss_wrapper; /etc/passwd left read-only`, `whoami` answers `user`, and `/etc/passwd`
stays `root:root 0644`. `che-min-mise` under the same UID appends to `/etc/passwd` instead.

So the base image only needs `che-mise-nss`'s two changes, and the entrypoint stays as it is:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends libnss-wrapper && \
    rm -rf /var/lib/apt/lists/* && \
    chown 0:0 /etc/passwd /etc/group && chmod 0644 /etc/passwd /etc/group
```

`che-mise-pdm` and `che-mise-webkit` inherit it, and the append fallback stays for any image that
removes the library.

Two points to check, neither of which `che-mise-nss` shows yet:

- **Processes the entrypoint does not start.** The three variables are exported by the entrypoint,
  so only its children see them. On Che, che-code's terminals, `postStart` commands and
  `kubectl exec` are started by the kubelet, not by the entrypoint. In those, `whoami` fails and
  `git` cannot find a name for the UID. Export the same three variables from `/globals/shellrc`
  when `$HOME/.nss_passwd` exists. This was not tested on a Che workspace here.
- **Validation of the entry.** The `echo` at lines 46-47 does not check `USER_NAME` or `HOME` for
  `:` or a newline. Since the file is the user's own and only affects the user's own processes, this
  is hygiene rather than escalation. [`passwd-append`](./bricks/passwd-append.md) is the validated
  form, if it is ever wanted there.

What it unlocks on the hardening side: the standard's KubeArmor rule on `/etc/passwd` can move
from `Audit` to `Block`, and the `su` path of H1 loses its writable `/etc/passwd`.

### H3 — Make `/globals` and `/home/tooling` read-only for the user

**0 MB.** Lines 15-18 and 117 make the shell rc files every shell sources, and the directory
holding `mise`, `chezmoi` and `batlehub-cli`, writable by group 0. Any process running as the
workspace user can then prepend to `PATH` for every later shell, or replace `mise`. Use 755 for
directories and 644 for files.

**Check before changing.** `stow --no-folding` links files in `$HOME` to `/home/tooling`, so a user
editing a stowed file writes into `/home/tooling`. Every file meant to be edited must be in
`.copy-files` (copied once, owned by the user) rather than stowed. Personal shell settings already
go to `~/.bashrc_perso`, which stays writable.

### H4 — Do not trust `/projects` by default

**0 MB.** Line 94 puts `/projects` in `MISE_TRUSTED_CONFIG_PATHS`, so every repository cloned there
is trusted without a prompt. Its `[env]` and its hooks run as soon as a shell `cd`s into it. A
malicious or compromised repository runs code at `cd`, as the user, with the user's
ServiceAccount token at hand. Keep the image's and the user's own config directories trusted, drop
`/projects`, and pair it with U3.

### H5 — Run with a read-only root filesystem

Once H2 and H3 are in, the only write the start-up makes outside `$HOME` and `/tmp` is
`/etc/subuid` and `/etc/subgid` when `HOST_USERS=false` (entrypoint lines 62-110). That case only
concerns builds and moves to `che-mise-pdm` with `uidmap`. The DWOC can then set
`readOnlyRootFilesystem: true` for every workspace, as `che-mise-nss`'s devfile already does.

### C1 — Immutable tags, a pinned base, signatures

`:main` is overwritten every night, and children build `FROM …:main`. A workspace start or a
child build can therefore run a different image from one day to the next, and nothing can name
"the image that ran yesterday".

- Publish an immutable tag next to `:main` (date or git SHA) and let devfiles and the CheCluster
  pin a digest.
- Pin `ubuntu:26.04` by digest in `versions.yaml`, and let Renovate bump it.
- Sign with cosign, keyless, from GitHub Actions. This adds no size, and gives a verify step that
  a later admission policy can use.

### C2 — A size budget in CI

Fail the build when `podman image inspect --format '{{.Size}}'` exceeds a ceiling, for example
1 GB once S1 to S4 have landed. Without it, `libclang` comes back through some later dependency and
nobody notices for a month.

## Order of work

| Order | Finding | Gain | Effort | Risk to users |
| --- | --- | --- | --- | --- |
| 1 | S1 | −460 MB | one package line, one child image | `bindgen` projects switch image |
| 2 | U1 | `git` over SSH works | one package line | none |
| 3 | H1 | closes `su` in `baseline` | one `RUN` | none |
| 4 | S2, S3, S4, U2 | −75 MB, `jq` | a few lines | none |
| 5 | H4 + U3 | no code at `cd` | one line, one alias | one `mise trust` per repository |
| 6 | H2 | identity files read-only | one `RUN` (the entrypoint already supports it) and three exports in `/globals/shellrc` | test `whoami`, `git commit` and che-code's terminal |
| 7 | H3, H5 | tamper-proof tooling, RO rootfs | audit of `.copy-files` | an edited stowed file fails until moved to `.copy-files` |
| 8 | C1, C2 | reproducible, signed, bounded | CI changes | none |

Items 1 to 4 are an afternoon and make the image about 40% smaller, fix SSH, and close the one
in-container escalation, with nothing a developer uses removed.

## Effect on the weebo-si standard

| After | What the [standard](./guides/weebo-si-standard.md) can drop or tighten |
| --- | --- |
| H1 | step 5's `su` chain no longer exists in the image; step 8's first `Block` becomes defence in depth |
| H2 | step 8's `/etc/passwd`, `/etc/group` rules can move to `Block` |
| H3 | step 8's second rule (`/home/tooling`, `/globals`) can `Block` with nothing to measure first |
| H4 | the remark on code run at `cd` goes away |
| H5 | `weebo-workspace` DWOC can set `readOnlyRootFilesystem: true` |
| C1 | devfiles and `image-policy` grants can name digests |
| U1 | the `dev-registries` profile's port 22 is actually usable |
| U4 | step 3's 120-second start-up delay becomes 30 seconds and a message |
