# Hexagonal architecture

Ports & adapters, applied where it earns its keep and skipped where it does not.

## Why, in this project specifically

The interesting bricks here are policy engines wearing a Kubernetes costume. "Is this image
allowed?", "does this DevWorkspaceOperator config match what we mandate?", "what should this pod
look like after mutation?" — those are decisions we want to state as rules, test exhaustively
against a table of cases, and reason about without a cluster in the loop.

What makes that hard is that the decision arrives wrapped in an `AdmissionReview`, and the
answer leaves as a JSON Patch. If the rule and the wrapper live in the same function, every
test needs a cluster or a pile of fixture JSON, and every upstream API bump touches the policy.

Hexagonal is the fix: the rules sit in the middle and know nothing about admission; the
admission plumbing is an adapter plugged into the side.

## When to apply it

Apply it when **all three** hold:

1. There is a real decision — branching policy, configurable rules, something a user could get
   wrong in more than one way.
2. It touches at least one external system: the Kubernetes API, the filesystem of a container
   it does not own, the network.
3. We want that decision tested without the external system.

Skip it when the brick is a transformation with no policy: read input, write output, exit. Ports
around a 150-line binary are ceremony — three files of indirection to test a function you could
have called directly. `passwd-append` is on this side of the line and
[RFC 0001](../rfc/0001-passwd-append.md) says so explicitly.

The honest test: *if I extracted a port here, would the fake implementation be more code than
the real one?* If yes, do not extract it.

Outgrowing the simple form is expected and fine. Promoting a `bins/` member into a layered
`crates/` member is a refactor — no RFC needed.

## Layout

The tree below is the general pattern: one crate, three layers as modules. It is what a new
hexagonal brick should default to. `weebo-si-operator` itself no longer looks like this — RFC
0002's amendment split it into seven crates (one per layer or role: `weebo-si-crd`,
`weebo-si-chassis`, `weebo-si-dwoc-pin`, `weebo-si-runtime`, `weebo-si-webhook`,
`weebo-si-controller`, plus the `weebo-si-operator` bin) once its dependency rule needed to be
enforced by `cargo`, not by review — see that RFC's *Architecture* section for why and when that
move is worth making. A brick reaches for the crate-per-layer split when review-level enforcement
of the dependency rule has actually failed to hold, not by default.

```text
crates/weebo-si-operator/
├── Cargo.toml
└── src/
    ├── lib.rs           # re-exports; declares the three modules
    ├── main.rs          # composition root — the ONLY place that names concrete adapters
    ├── domain/          # the rules. Pure.
    │   ├── mod.rs
    │   ├── model/       # entities and value objects (ImageRef, PolicyDecision, ...)
    │   ├── error.rs     # domain errors — never `kube::Error`, never `std::io::Error`
    │   └── port/        # traits the domain owns and the outside implements
    ├── application/     # use cases: orchestrate domain rules over ports
    │   ├── mod.rs
    │   └── review_pod.rs
    └── adapters/
        ├── inbound/     # what drives the application: axum webhook server, CLI, reconcile loop
        └── outbound/    # what the application drives: kube client, config loader, metrics sink
```

## The dependency rule

```text
adapters ──▶ application ──▶ domain
                              (depends on nothing in this crate)
```

Arrows point inward only. Concretely:

- `domain` imports no `kube`, no `k8s-openapi`, no `axum`, no `tokio`, no `serde_json::Value`
  carrying an admission body. If a domain type needs to be serialized, that is the adapter's
  problem.
- `domain` does not do I/O. No `async` in domain code unless the *rule itself* is inherently
  asynchronous, which it never is.
- `application` may be `async` — it orchestrates ports, and ports do I/O.
- `adapters` know about `domain` and `application`; nothing knows about `adapters` except
  `main.rs`.

### Ports live in the domain, in domain vocabulary

A port is named for what the application needs, not for what happens to implement it today:

```rust
// domain/port/image_registry.rs — good: the domain's vocabulary
pub trait ImageRegistry {
    async fn resolve_digest(&self, image: &ImageRef) -> Result<Digest, DomainError>;
}

// bad: the adapter leaked into the port
pub trait CraneClient {
    async fn head_manifest(&self, r: &str) -> Result<oci::Manifest, reqwest::Error>;
}
```

The second one means swapping the implementation changes the domain. That is the coupling we
were buying the port to avoid.

### The composition root

`main.rs` — and only `main.rs` — constructs concrete adapters and injects them. Everything else
takes its dependencies as generics or trait objects. This is what makes the test story work:
tests construct the same use case with in-memory fakes and never touch a cluster.

## Enforcement

Today the dependency rule is a convention, checked in review. It is not compiler-enforced,
because the layers are modules inside one crate rather than three separate crates.

That is a deliberate trade: one crate is far less friction while a brick is young. If a brick's
domain starts drifting — adapter types creeping into rule signatures — the escape hatch is to
promote `domain/` into its own crate (`weebo-si-operator-domain`) so `cargo` refuses the
backwards edge. Do that when it becomes a real problem, not preemptively.

## Testing expectation

- `domain` — plain unit tests, table-driven, no `async`, no fixtures larger than a struct
  literal. This is where coverage should be near-total; it is cheap here and expensive anywhere
  else.
- `application` — use cases against fake ports. Asserts orchestration and error propagation.
- `adapters` — thin by construction, so tested thinly: one round-trip test per adapter proving
  the translation (`AdmissionReview` in → domain type → JSON Patch out) is faithful.
- End-to-end against a real API server is a separate, small, deliberately slow suite. It proves
  the wiring, not the rules.
