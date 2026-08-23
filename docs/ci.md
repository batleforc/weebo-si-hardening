# CI

Every gate, what it blocks, and how to run it locally. All of it is GitHub
Actions — the remote is `github.com/batleforc/weebo-si-hardening`, and SARIF only
means something where the Security tab is.

Third-party actions are **pinned by commit SHA**, with the tag in a trailing
comment. A moving tag is a supply-chain hole in the thing that builds the
supply-chain gate.

## What runs, and when

| Workflow | Fires on | Blocks on |
| --- | --- | --- |
| [`build-passwd-append`](../.github/workflows/build-passwd-append.yaml) | `bins/passwd-append/**`, `Cargo.toml`, `Cargo.lock` · daily | a broken musl build, a dynamically linked binary, a HIGH/CRITICAL image CVE |
| [`build-preauth-proxy`](../.github/workflows/build-preauth-proxy.yaml) | `bins/preauth-proxy/**`, `Cargo.toml`, `Cargo.lock` · daily | same |
| [`test`](../.github/workflows/test.yaml) | any Rust or manifest change | `cargo fmt --check`, `clippy -D warnings`, the suite, a release build |
| [`repo`](../.github/workflows/repo.yaml) | `docs/**`, `scripts/**`, `.hooks/**`, configs | a malformed RFC, a stale RFC index, shellcheck, markdownlint, cspell |
| [`dep-audit`](../.github/workflows/dep-audit.yaml) | manifests, `deny.toml` · daily | `cargo deny check advisories bans licenses sources` |
| [`postmortem`](../.github/workflows/postmortem.yaml) | manifests · daily | a HIGH supply-chain vulnerability |
| [`codeql`](../.github/workflows/codeql.yaml) | Rust changes · weekly | CodeQL alerts |
| [`semgrep`](../.github/workflows/semgrep.yaml) | Rust and shell changes · weekly | any ERROR-severity finding |
| [`secret-scan`](../.github/workflows/secret-scan.yaml) | every push and PR · daily | a secret anywhere in history |

**The daily schedules are the point, not padding.** A CVE disclosed against a
base image or a dependency *after* the last commit has to trip something, and a
workflow that only fires on push never will.

## Per-brick builds

`build-passwd-append` and `build-preauth-proxy` are twelve-line triggers that
both call one reusable workflow, [`brick.yaml`](../.github/workflows/brick.yaml).
A brick rebuilds when **its own** code changes, or when `Cargo.toml`/`Cargo.lock`
does — a dependency bump changes what every binary links, so both rebuild.

The alternative was one workflow computing what changed, because GitHub's path
filters are per *workflow* and not per job. That needs a change-detection action
in the trigger path and makes untouched bricks report "skipped" rather than not
running. With two bricks, two small callers is the cheaper trade.

Each brick gets:

- a **static musl binary**, asserted static rather than assumed — a dynamically
  linked build silently cannot go in the `scratch` final stage
  [RFC 0001](./rfc/0001-passwd-append.md) requires;
- a **CycloneDX SBOM**, so a crate CVE disclosed *after* this build can be
  matched against this exact artifact with `trivy sbom sbom-<crate>.cdx.json`;
- a **container image**, built and scanned but never pushed — there is no
  registry decision in this repo yet;
- a **Trivy scan** of the image and of the Containerfile, HIGH/CRITICAL,
  `--ignore-unfixed`.

Binaries and SBOMs are uploaded as run artifacts, kept 14 days.

## Report first, gate second

Semgrep, Trivy and postmortem each run twice, or run soft and gate after. That
shape is load-bearing: the SARIF upload is a *later step*, so a scan that failed
the job outright would skip it and the findings would never reach the Security
tab. The scan reports; a separate step fails the build.

## Running the gates locally

```bash
task lint            # fmt, clippy, shellcheck, RFC format, actionlint
task test            # the whole suite
task audit           # cargo-deny + trivy fs
task supply-chain    # postmortem, the same scanner version CI pins
task ci:lint         # actionlint on the workflow files alone
task ci:image BRICK=passwd-append   # build + scan one image as CI does
```

`task supply-chain` is deliberately **not** part of `task audit`: it goes over
the network on every run and anonymous `vuln.mlab.sh` is capped at 8 scans an
hour, so folding it in would throttle the audit everyone runs. CI schedules it
daily instead.

`task ci:image` needs a container engine, which a Che workspace does not have.

## Two things CI does that the pre-commit hook cannot

- **Scan the full history.** `gitleaks` in the hook sees the staged tree; the
  workflow sees every commit, including ones pushed with `--no-verify` and
  everything that predates the hook.
- **Fail on a stale RFC index.** The hook regenerates it and stages the result,
  so it can never fail there. CI regenerates and diffs, which is what catches a
  bypassed hook.

## Known gaps

- **No CD.** Nothing is pushed to a registry and no release is cut. Images are
  built to be scanned. Wiring the push is a registry decision that has not been
  taken.
- **`mlab-sh/postmortem` is pinned by SHA, but the composite action it runs is
  not fully closed**: internally it installs its scanner with `curl | tar` and no
  checksum, and its SARIF upload calls `github/codeql-action/upload-sarif@v3` — a
  floating tag, where every other codeql-action use here is pinned. Closing
  either needs an upstream change or a fork.
- **postmortem's `max-risk` / `max-dep` are unset.** They score a *degree* rather
  than a count, and pinning a degree at 0 would fail on a dependency going
  slightly stale rather than on anything worth acting on. `max-high` and
  `max-sus` **are** set to 0, which is not a guess: a full run over this tree
  reports 63 nodes / 10 direct at 0 high-risk and 0 suspicious, so zero is the
  current state and the gate's job is to keep it there.
- **`VULN_MLAB_TOKEN` is optional and currently unset.** An absent secret
  resolves to anonymous, which is the action's default anyway — it just means the
  8 scans/hour cap applies.
