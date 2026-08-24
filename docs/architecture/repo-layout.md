# Repository layout

Single Cargo workspace, two families of members.

```text
Cargo.toml              # [workspace] — shared deps, shared lints, shared edition
bins/                   # simple binaries: one job, no ports, no adapters
├── passwd-append/
└── preauth-proxy/
crates/                        # libraries and the non-trivial bricks
├── weebo-si-crd/               # the WeeboSiConfig CRD schema — kube-derive, k8s-openapi, schemars
├── weebo-si-chassis/           # operator-wide runtime abstractions: Feature<S>, Registry<S>, ports
├── weebo-si-dwoc-pin/          # the dwoc-pin feature — depends on crd + chassis only
├── weebo-si-runtime/           # watch-backed outbound adapters, shared by webhook and controller
├── weebo-si-webhook/           # the admission webhook adapter (axum)
├── weebo-si-controller/        # the WeeboSiConfig reconcile loop
├── weebo-si-operator/          # the bin — sole composition root, sole binary
└── weebo-si-envtest-support/   # dev-only: a real ephemeral kube-apiserver for the envtest tier
charts/                 # one Helm chart per deployable brick, alongside its bins/crates/ deploy/ artifacts
├── weebo-si-operator/
└── preauth-proxy/
scripts/                # repo plumbing, POSIX sh (RFC validation and index generation)
docs/
├── rfc/
└── architecture/
```

`scripts/` holds repo tooling, not product code — it never ships in an image. POSIX `sh`, because
it runs in the pre-commit hook where "works on my shell" is not a guarantee we get.

`charts/<name>/` mirrors the brick's own name, not its `bins/`/`crates/` parent directory — a
chart is installed by name, and duplicating the parent would only be noise. Unlike
`crates/weebo-si-operator/deploy/`'s raw manifests (kept for anyone who does not want Helm as a
dependency), a chart is the templated, parameterized form of the same artifacts; where they
overlap — the generated CRD is the clearest case — `scripts/crd-regen.sh` regenerates both copies
from the same source so they cannot drift against each other.

## `bins/` or `crates/`?

The split is about *shape*, not about producing an executable — a hexagonal brick also ships a
binary.

- **`bins/`** — the brick is a single-purpose transformation with no policy in it. It reads
  input, produces output, exits. It has no reason to grow a port, and it can be read top to
  bottom in one sitting. `passwd-append` is the archetype.
- **`crates/`** — everything else: anything that talks to the Kubernetes API, anything that
  makes a decision someone might want to configure, anything that has to be tested without the
  system it drives. These follow [`hexagonal.md`](./hexagonal.md).

A `bins/` member that grows a second reason to change is a candidate for promotion to
`crates/`. That move is a refactor, not a RFC — see the RFC process for what needs one.

## Naming

- Workspace members are named after what they do: `passwd-append`, not `weebo-si-passwd`.
- Published crate names get the `weebo-si-` prefix; directory names do not repeat it when the
  parent folder already says it.
- The binary produced by a crate matches the directory name.

## Shared configuration

`Cargo.toml` at the root owns edition, `rust-version`, license, repository, dependency versions
and lints. Members inherit:

```toml
[package]
name = "passwd-append"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true
```

The workspace lints are deliberately strict (`unwrap_used = "deny"`, `panic = "deny"`,
`unsafe_code = "forbid"`). These bricks run inside other people's pods and in the admission
path; a panic there is someone else's outage. Silencing a lint is fine when it is the right
call — do it with a scoped `#[allow(...)]` and a comment saying why, never by loosening the
workspace lint table.
