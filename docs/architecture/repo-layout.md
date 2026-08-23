# Repository layout

Single Cargo workspace, two families of members.

```text
Cargo.toml              # [workspace] — shared deps, shared lints, shared edition
bins/                   # simple binaries: one job, no ports, no adapters
└── passwd-append/
crates/                 # libraries and the non-trivial bricks
├── weebo-si-common/    # shared building blocks (errors, tracing setup, k8s helpers)
└── weebo-si-operator/  # hexagonal: domain / application / adapters
scripts/                # repo plumbing, POSIX sh (RFC validation and index generation)
docs/
├── rfc/
└── architecture/
```

`scripts/` holds repo tooling, not product code — it never ships in an image. POSIX `sh`, because
it runs in the pre-commit hook where "works on my shell" is not a guarantee we get.

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
