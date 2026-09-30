# CI

Every gate, what it blocks, and how to run it locally. All of it is GitHub
Actions — the remote is `github.com/batleforc/weebo-si-hardening`, and SARIF only
means something where the Security tab is.

Third-party actions are **pinned by commit SHA**, with the tag in a trailing
comment. A moving tag is a supply-chain hole in the thing that builds the
supply-chain gate. The same rule covers what the actions *install*: Helm
(`v4.3.0`), Semgrep, `markdownlint-cli2`, `cspell` and `cargo-cyclonedx` are
pinned to exact versions rather than `latest`; the envtest and Traefik tarballs
are checked against SHA-512/SHA-256 values pinned in `envtest.yaml` (and in
`.tasks/envtest.yaml` for the default envtest version); and every
Containerfile's `rust:*-alpine` build stage is pinned by digest. Bumping any of
them is a deliberate commit, never something that happens to a green build.

## What runs, and when

| Workflow | Fires on | Blocks on |
| --- | --- | --- |
| [`build-passwd-append`](../.github/workflows/build-passwd-append.yaml) | `bins/passwd-append/**`, `Cargo.toml`, `Cargo.lock` · daily | a broken musl build, a dynamically linked binary, a HIGH/CRITICAL image CVE |
| [`build-preauth-proxy`](../.github/workflows/build-preauth-proxy.yaml) | `bins/preauth-proxy/**`, `Cargo.toml`, `Cargo.lock` · daily | same |
| [`build-weebo-si-operator`](../.github/workflows/build-weebo-si-operator.yaml) | any of the 14 `weebo-si-*` crates its binary links, `Cargo.toml`, `Cargo.lock` · daily | same |
| [`build-endpoint-gateway`](../.github/workflows/build-endpoint-gateway.yaml) | `bins/endpoint-gateway/**`, `crates/weebo-si-crd/**`, `crates/weebo-si-endpoint-auth/**`, `Cargo.toml`, `Cargo.lock` · daily | same |
| [`test`](../.github/workflows/test.yaml) | any Rust or manifest change | `cargo fmt --check`, `clippy -D warnings`, the suite, the deferred OpenShift tier, RFC 0009's decision budget, a release build |
| [`envtest`](../.github/workflows/envtest.yaml) | `crates/**`, `bins/endpoint-gateway/**`, manifests | all five envtest suites, live against a real ephemeral `kube-apiserver` — `REQUIRE_ENVTEST` makes a broken setup a failure, not a silent skip — plus RFC 0009's dialect conformance suite, which drives a real Traefik |
| [`e2e`](../.github/workflows/e2e.yaml) | nightly · manual, per suite | any of the four end-to-end suites against a kind cluster running real Eclipse Che — see [End to end](#end-to-end) |
| [`helm`](../.github/workflows/helm.yaml) | `charts/**` | `helm lint` and `helm template` for all three charts, every certificate-provider variant and both endpoint-auth dialect shapes |
| [`repo`](../.github/workflows/repo.yaml) | `docs/**`, `scripts/**`, `.hooks/**`, `charts/weebo-si-operator/crds/**`, configs | a malformed RFC, a stale RFC index, a stale `docs/generator/schemas.js`, shellcheck, markdownlint, cspell |
| [`pages`](../.github/workflows/pages.yaml) | `docs/generator/**`, the chart's CRDs, on `main` · manual | a stale `docs/generator/schemas.js`; then publishes the [config generator](https://batleforc.github.io/weebo-si-hardening/) to GitHub Pages |
| [`dep-audit`](../.github/workflows/dep-audit.yaml) | manifests, `deny.toml` · daily | `cargo deny check advisories bans licenses sources` |
| [`postmortem`](../.github/workflows/postmortem.yaml) | manifests · daily | a HIGH supply-chain vulnerability |
| [`codeql`](../.github/workflows/codeql.yaml) | Rust changes · weekly | CodeQL alerts |
| [`semgrep`](../.github/workflows/semgrep.yaml) | Rust and shell changes · weekly | any ERROR-severity finding |
| [`secret-scan`](../.github/workflows/secret-scan.yaml) | every push and PR · daily | a secret anywhere in history |
| [`release`](../.github/workflows/release.yaml) | a `v*` tag | a tag that is not `v<semver>`; then every gate above that concerns code (`test`, `envtest`, `helm`, all four bricks) — and only after all of them, publishes. See [Releases](#releases) |

**Two steps in `test` are about a claim rather than about correctness.** The
*deferred OpenShift tier* runs the tests the base suite skips — RFC 0009's
`ReverseProxy` dialect is written and has never met a real router, so nothing
asserts it by default, but it still has to compile and still has to pass.
The *decision budget* runs `benches/decide.rs`, which fails the build if a
decision crosses 50 µs; RFC 0009 promises single-digit microseconds and measures
about 130 ns, and a budget nobody measures is a wish.

**`envtest` ran one suite out of four until 2026-09-15.** The workflow listed
`--test envtest` while `.tasks/envtest.yaml` listed four targets, so RFC 0006's,
RFC 0007's and RFC 0009's suites ran locally and never in CI. If you add a suite,
add it in both places — or better, notice that this is exactly the drift the two
lists invite. There are five as of 2026-09-23: RFC 0009's `openshift_envtest`
covers the `OpenShiftRoute` dialect's **admission** half against a `Route` CRD,
which is a different fact from the deferred tier above — that one is about a
router nobody has run this against, and this one needed no router at all.

**The conformance suite skips itself when its tools are missing, so CI installs them.**
`bins/endpoint-gateway/tests/conformance.rs` needs both the envtest binaries and
`traefik` on `PATH`, and answers a missing one by returning rather than
failing — which is right on a laptop and would be a silently green CI. The
`envtest` workflow therefore downloads Traefik next to the apiserver, runs the
suite in its own step, and `REQUIRE_ENVTEST=1` turns *both* missing tools into a
failure rather than a green skip — the apiserver by the envtest harness's own
rule, and Traefik by the same check written into the suite. It is the only place in this repo where a test drives
somebody else's proxy, and it is there because two of RFC 0009's security
properties are claims about what Traefik does rather than about what we do.

**The daily schedules are the point, not padding.** A CVE disclosed against a
base image or a dependency *after* the last commit has to trip something, and a
workflow that only fires on push never will.

## End to end

`e2e` is the one workflow that runs the platform rather than the code: a kind
cluster with real Eclipse Che, real DevWorkspace Operator, ingress-nginx, a
Keycloak realm, and this repo's images and charts on top. `scripts/e2e.sh`
builds the rig; `crates/weebo-si-e2e/tests/<suite>.rs` asserts against it. The
images and test binaries are built once, then each suite gets its **own**
cluster, so one suite's addons never change another's answer.

| Suite | Adds to the rig | Proves |
| --- | --- | --- |
| `workspace` | — | `dwoc-pin` pins a config DevWorkspace Operator **runs with** (read off the pod); team priority and namespace annotations; `image-policy` at the devfile and at the pod floor, dry run included; `network-profiles` dropping real traffic and a granted profile opening exactly its own path; `policy-guard` refusing a cluster admin; `registry-config` copies DevWorkspace Operator actually mounts; passwd-append under an arbitrary UID; team status and conflicts; the webhook failing closed |
| `kubearmor` | KubeArmor | the baseline and posture on every namespace in scope; a granted profile **blocking a process** in its own workspace and not in the neighbour's; the guard on managed `KubeArmorPolicy` objects |
| `endpoint-auth` | endpoint-gateway | the gate on the Ingress Che generates; owner, teammate, stranger and anonymous over HTTPS through ingress-nginx; an `open` rule; a workspace's own service-account token; a forged identity header stripped; a developer unable to take the gate off; preauth-proxy logging in, stripping the upstream session and renewing on a `401` |
| `identity` | Authentik, weebo-authentik, Argo CD, an in-cluster chart repository | a `WeeboSiUser` becoming a real Authentik account in the right groups and leaving with its object; an `Application` Argo CD syncs with the person's own values; adoption of a hand-made account; the allow-list refusing a whole person; dry run; a username conflict |

**Every upstream is pinned** in `scripts/e2e.sh` (charts, manifests, images) and
the kind node by digest in `scripts/kind-e2e.yaml`; a nightly that floats on
`latest` fails on somebody else's release and reads as ours. **A red suite
uploads `diag-<suite>`**: every pod, event and log worth reading, the operator's
objects and the DevWorkspaces.

**The rig has one certificate authority**, and everything chains to it: Keycloak,
the wildcard certificate ingress-nginx and Che serve, and the bundle the
endpoint gateway trusts through its chart's `extraCa`. That is deliberate — it
is how the suite proves the gateway reaches an identity provider behind a
private CA, instead of turning TLS verification off to get a green run.

**Templates select nothing.** A `NetworkPolicy` or `KubeArmorPolicy` template is
a live object in the operator's namespace, so its own selector applies *there*.
The suites' templates select a label no pod carries; a template written with
`podSelector: {}` would apply its egress rules to the operator's own webhook.

## Per-brick builds

`build-passwd-append`, `build-preauth-proxy` and `build-endpoint-gateway` are
twelve-line triggers that all call one reusable workflow, [`brick.yaml`](../.github/workflows/brick.yaml).
A brick rebuilds when **its own** code changes — its directory *and* every workspace crate its
binary links, as `cargo tree -p <crate> -e normal,build` lists them — or when
`Cargo.toml`/`Cargo.lock` does: a dependency bump changes what every binary links, so all of them
rebuild. The operator's filter listed 7 of its 14 crates until 2026-09-29, so a change to e.g.
`weebo-si-policy-guard` never rebuilt or scanned its image again; re-derive the list when a crate is
added.

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
- a **container image**, built and scanned but **never pushed from here** —
  publishing is [`release.yaml`](#releases)'s job alone;
- a **Trivy scan** of the image and of the Containerfile, HIGH/CRITICAL,
  `--ignore-unfixed`.

Binaries and SBOMs are uploaded as run artifacts, kept 14 days.

## Releases

A release is a `v*` git tag, and it is the **only** thing that publishes. The per-brick workflows
on `main`, PRs and the daily schedule build and scan; they hold no `packages: write`.

**Cutting one.** Commits already follow Conventional Commits (the `commit-msg` hook runs
`cog verify`), so cocogitto computes the version:

```bash
cog bump --auto                  # or: cog bump --version 0.1.0 for the first release
git push origin main "$(git describe --tags --abbrev=0)"   # the v* tag triggers release.yaml
```

Push the tag **by name**: `cog bump` creates a *lightweight* tag, and `git push --follow-tags`
only pushes annotated ones — it would push the bump commit and silently leave the tag behind, so
nothing would ever release.

**If a release run fails, use "Re-run failed jobs", not "Re-run all jobs".** Re-running every job
rebuilds and re-pushes images whose SBOM/provenance timestamps differ, so the tags would move to
new digests and the signatures already made would point at the old ones. The final
`gh release create` step is idempotent (it skips a release that already exists).

`cog bump`'s `pre_bump_hooks` (in `cog.toml`) stamp the new version into every chart's `version`
and `appVersion` before the bump commit, so the committed charts match the tag. **The first
release is `v0.1.0`**: the three charts already say `appVersion: "0.1.0"` and default their image
tag to it, so until that tag has been pushed and `release.yaml` has run, `helm install` from this
repo points at an image tag that does not exist yet.

**What [`release.yaml`](../.github/workflows/release.yaml) does, in order** — each stage `needs:`
the previous, so nothing is published off a red gate:

1. **Validates the tag** as `v<major>.<minor>.<patch>[-pre]`. The version (without the `v`) is
   what every later stage uses.
2. **Re-runs the gates against the tagged commit**, by calling the same workflow files through
   their `workflow_call` trigger: `test.yaml`, `envtest.yaml`, `helm.yaml`, and `brick.yaml` for
   all four bricks (static-binary assertion, SBOM, Trivy image + Containerfile). Re-running rather
   than trusting `main`'s last run is deliberate: `needs:` does not cross workflow boundaries, and
   a tag can point at a commit `main`'s path filters never built.
3. **Publishes the four images** through [`publish.yaml`](../.github/workflows/publish.yaml), to
   `ghcr.io/<owner>/<crate>` — the repository each chart's `values.yaml` defaults to. Tags:
   `<version>`, `<major>.<minor>` (skipped for pre-releases) and the full commit sha; no `latest`.
   The push attaches BuildKit's SBOM (`sbom: true`) and a max-mode build-provenance attestation
   (`provenance: mode=max`). The build is a cache replay of the layers `brick.yaml` just scanned.
4. **Signs each image by digest with cosign, keyless** — in a separate job, the only one in the
   repo holding `id-token: write`. Verify with:

   ```bash
   cosign verify ghcr.io/batleforc/<crate>@sha256:<digest> \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp '^https://github.com/batleforc/weebo-si-hardening/\.github/workflows/publish\.yaml@refs/tags/v'
   ```

5. **Pushes the three charts** to `oci://ghcr.io/<owner>/charts/<chart>`, packaged with
   `--version` and `--app-version` set from the tag — after the images, so a published chart never
   names an image tag that is not there yet:

   ```bash
   helm install weebo-si-operator oci://ghcr.io/batleforc/charts/weebo-si-operator --version 0.1.0
   ```

   Each chart's image helper renders `image.repository@image.digest` when `image.digest` is set
   (pin the signed artifact), else `image.repository:image.tag`, the tag defaulting to
   `appVersion`.
6. **Creates the GitHub release**, with `cog changelog --at <tag>` as the notes.

Two first-release chores no workflow can do: packages first published with `GITHUB_TOKEN` are
**private**, so flip each of the four images and three charts to public (or grant pull access) in
the package settings once; and the `release` job's `contents: write` needs the repository's
Actions permissions to allow it.

## Report first, gate second

Semgrep, Trivy and postmortem each run twice, or run soft and gate after. That
shape is load-bearing: the SARIF upload is a *later step*, so a scan that failed
the job outright would skip it and the findings would never reach the Security
tab. The scan reports; a separate step fails the build.

## Running the gates locally

```bash
task lint            # fmt, clippy, shellcheck, RFC format, crd + generator-schema freshness, helm lint, actionlint
task test            # the whole suite
task audit           # cargo-deny + trivy fs (covers charts/ too — see task helm:lint's own comment)
task supply-chain    # postmortem, the same scanner version CI pins
task ci:lint         # actionlint on the workflow files alone
task ci:image BRICK=passwd-append   # build + scan one image as CI does (bins/ or crates/, e.g. BRICK=weebo-si-operator)
task e2e:build && task e2e:run SUITE=workspace   # one end-to-end suite on a local kind cluster
task docs:generator  # the config generator on http://127.0.0.1:8765
```

`task supply-chain` is deliberately **not** part of `task audit`: it goes over
the network on every run and anonymous `vuln.mlab.sh` is capped at 8 scans an
hour, so folding it in would throttle the audit everyone runs. CI schedules it
daily instead.

`task ci:image` and the `e2e:*` tasks need a container engine, which a Che
workspace does not have; `e2e:up` also needs `fs.inotify.max_user_instances`
of at least 512 on the host.

## Two things CI does that the pre-commit hook cannot

- **Scan the full history.** `gitleaks` in the hook sees the staged tree; the
  workflow sees every commit, including ones pushed with `--no-verify` and
  everything that predates the hook.
- **Fail on a stale RFC index.** The hook regenerates it and stages the result,
  so it can never fail there. CI regenerates and diffs, which is what catches a
  bypassed hook.

## Known gaps

- **A published image is not rebuilt.** The daily per-brick schedules scan
  `main`'s build, not the released images; a CVE disclosed against a release's
  dependencies shows up on the next daily run of `main`, and fixing it means
  cutting a new release. The final stages are `scratch`, so there is no base
  image to go stale under a release — only the Rust dependencies, which the
  SBOM attached to each image lets you match with `trivy sbom`.
- **Charts are not signed.** Images are cosign-signed; the OCI charts are
  pushed as-is. `cosign sign` works on an OCI chart the same way, and it is the
  next step if something starts verifying charts.
- **`cocogitto-action` installs `cog` with `curl | tar` and no checksum.** It
  only renders release notes, in a job holding `contents: write` and nothing
  else, after everything has been published — but it is the same class of gap
  as postmortem's below.
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
- **Three upstreams float inside their pins.** The KubeArmor chart's images are
  pinned by `--set` because the chart itself tracks `stable`/`latest`;
  ingress-nginx is archived upstream, and `4.15.1` is its last chart; and the
  DevWorkspace Operator and che-operator manifests are fetched by tag from
  `raw.githubusercontent.com`, which pins the file but not the images it names.
