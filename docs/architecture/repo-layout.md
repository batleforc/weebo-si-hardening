# Repository layout

Single Cargo workspace, two families of members.

```text
Cargo.toml              # [workspace] — shared deps, shared lints, shared edition
bins/                   # binaries that are not the operator
├── passwd-append/      # flat: one job, no ports, no adapters
├── preauth-proxy/      # hexagonal, its own chart
└── endpoint-gateway/   # hexagonal, its own chart; decisions come from crates/weebo-si-endpoint-auth
crates/                          # the operator: one crate per layer, two per feature
├── weebo-si-crd/                 # the three CRDs and every feature's config — kube-derive, schemars
├── weebo-si-chassis/             # Feature<S>, Registry<S>, admit(), ports, managed diff — no kube, no serde
├── weebo-si-<feature>/           # the decision, one per feature — depends on crd + chassis only:
│                                 #   dwoc-pin, network-profiles, policy-guard, image-policy,
│                                 #   kubearmor-policy, registry-config, endpoint-auth, identity
├── weebo-si-<feature>-adapters/  # what talks to the cluster for it (RFC 0012): stores, metrics,
│                                 #   admission routes, loops — every feature but dwoc-pin
├── weebo-si-runtime/             # shared adapters: the config and namespace caches, watch driving
├── weebo-si-webhook/             # shared admission: the DevWorkspace route, extract, render, metrics
├── weebo-si-controller/          # shared reconcile: WeeboSiConfig status, Events and retry
├── weebo-si-operator/            # the bin — sole composition root, sole binary
├── weebo-si-envtest-support/     # dev-only: a real ephemeral kube-apiserver, and the CRD fixtures
└── weebo-si-e2e/                 # test-only: the nightly kind + Eclipse Che suites
charts/                 # one Helm chart per deployable brick
├── weebo-si-operator/
├── endpoint-gateway/
└── preauth-proxy/
e2e/                    # fixtures for the nightly end-to-end suites
scripts/                # repo plumbing, POSIX sh (RFC validation and index generation, CRD regen, e2e rigs)
docs/                   # plain markdown: RFCs, architecture, runbooks
├── rfc/
├── architecture/
└── bricks/
site/                   # the documentation site (Fumadocs, @weebo/operator-docs): the generated
                        # CRD reference, form and IDE, published on GitHub Pages
```

How the operator's crates fit together at run time is
[`operator-internals.md`](./operator-internals.md).

`scripts/` holds repo tooling, not product code — it never ships in an image. POSIX `sh`, because
it runs in the pre-commit hook where "works on my shell" is not a guarantee we get.

`charts/<name>/` mirrors the brick's own name, not its `bins/`/`crates/` parent directory — a
chart is installed by name, and duplicating the parent would only be noise. A chart is the one
supported install path for its brick; `crates/weebo-si-operator/deploy/` keeps only the generated
`crd.yaml` (for installing the kinds without the operator), and `scripts/crd-regen.sh` regenerates
it and the chart's `crds/` copy from the same source so they cannot drift against each other. The
hand-written raw manifests that used to sit beside it were removed once they had drifted from the
chart far enough not to start.

## `bins/` or `crates/`?

The split is about *shape*, not about producing an executable — a hexagonal brick also ships a
binary.

- **`bins/`** — the brick is a single-purpose transformation with no policy in it. It reads
  input, produces output, exits. It has no reason to grow a port, and it can be read top to
  bottom in one sitting. `passwd-append` is the archetype.
- **`crates/`** — everything else: anything that talks to the Kubernetes API, anything that
  makes a decision someone might want to configure, anything that has to be tested without the
  system it drives. These follow [`hexagonal.md`](./hexagonal.md).

`preauth-proxy` and `endpoint-gateway` break the first rule and live in `bins/` anyway: each is a
standalone process with its own chart, outside the operator's composition root, and each keeps its
hexagonal layers as modules inside the one crate rather than as separate crates. What actually
separates the two directories today is "part of the operator's workspace of layered crates" versus
"a deployable of its own".

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
