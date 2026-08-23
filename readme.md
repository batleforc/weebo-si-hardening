# weebo-si-hardening

Hardening bricks for the Weebo SI: small binaries and a Kubernetes operator that make the
platform's workloads behave the way we say they should.

## What lives here

| Kind | Examples | Layout |
| --- | --- | --- |
| **Simple binaries** | `passwd-append` — give the container's arbitrary UID a real passwd entry | `bins/`, flat, no ceremony |
| **WeeboSIOperator** | validating and mutating admission webhooks: restrict which images may run, check which DevWorkspaceOperator config is in use, inject configuration into targeted pods | `crates/`, [hexagonal](./docs/architecture/hexagonal.md) |

## How work happens here

Features are designed before they are built. Every brick, every new rule, every contract change
gets an **RFC** in [`docs/rfc/`](./docs/rfc/readme.md) — these components rewrite and reject other
people's workloads, so the cost of thinking it through in a diff is far below the cost of
discovering the design in production.

- [`docs/rfc/readme.md`](./docs/rfc/readme.md) — the process: when a RFC is required, the
  statuses, and the index of what exists.
- [`docs/architecture/`](./docs/architecture/readme.md) — the conventions every brick follows,
  including [when hexagonal layering applies and when it is over-engineering](./docs/architecture/hexagonal.md).

Bricks that are pure transformations do **not** get ports and adapters. That is a decision each
RFC makes explicitly, against stated criteria.

## Getting started

```bash
task init              # mise install + cocogitto git hooks
task rfc:list          # what is designed, and where it stands
task rfc:new TITLE="restrict container images"
task rfc:check         # validate every RFC against the format
```

| Task | Does |
| --- | --- |
| `task lint` | `cargo fmt`, `clippy -D warnings`, `shellcheck`, `rfc:check` (also runs in the pre-commit hook) |
| `task recu` | regenerates what is derived from source — today the RFC index (also in the hook) |
| `task test` | the whole test suite |
| `task build` | release build of every brick |
| `task audit` | `cargo deny` for RUSTSEC advisories, `trivy fs` for the rest |
| `task supply-chain` | `postmortem` — dependency reputation and vulns, not just advisories |

The RFC index in `docs/rfc/readme.md` is generated, and both `recu` and `check` run on every
commit — so a RFC that drops a mandatory section, or an index that drifts from reality, does not
make it into a commit.

Run `task --list` for everything. Every gate also runs in CI — see
[`docs/ci.md`](./docs/ci.md) for what fires when and what it blocks.

## Conventions

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/), enforced by
  `cog verify` in the commit-msg hook. Implementation commits carry the RFC in the scope:
  `feat(rfc-0001): validate passwd fields`.
- The workspace lints are strict on purpose — `unsafe_code = "forbid"`, `panic = "deny"`,
  `unwrap_used = "deny"`. See [`docs/architecture/repo-layout.md`](./docs/architecture/repo-layout.md).

Bootstrapped from the [weebo-base](https://github.com/batleforc/weebo-base) template.
