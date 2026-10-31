# Architecture

Conventions that hold across every brick in this repo. A RFC may deviate from them, but it has
to say so and say why — that is a design decision, not an implementation detail.

| Document | Scope |
| --- | --- |
| [`hexagonal.md`](./hexagonal.md) | When a brick uses ports & adapters, how it is laid out, and the dependency rule. |
| [`repo-layout.md`](./repo-layout.md) | Where code lives: `bins/` vs `crates/`, naming, the workspace. |
| [`operator-internals.md`](./operator-internals.md) | How `weebo-si-operator` works inside: the crates, the two roles, an admission request and a reconcile end to end, what adding a feature touches. |
