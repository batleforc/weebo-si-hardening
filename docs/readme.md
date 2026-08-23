# Documentation

Documentation for `weebo-si-hardening` is plain markdown, versioned next to the code.
No static site generator: a RFC has to be readable in a diff and in the forge UI.

## Map

| Path | What lives there |
| --- | --- |
| [`rfc/`](./rfc/readme.md) | The RFC process, the template, and every RFC. **Start here.** |
| [`architecture/`](./architecture/readme.md) | Cross-cutting conventions every brick follows (hexagonal layering, repo layout). |
| [`bricks/`](./bricks/readme.md) | Operator-facing docs for what has shipped: flags, config, exit codes, failure modes. |
| [`ci.md`](./ci.md) | Every CI gate, what it blocks, and how to run it locally. |

## Reading order for a newcomer

1. [`rfc/readme.md`](./rfc/readme.md) — how a feature gets from idea to merged code.
2. [`architecture/hexagonal.md`](./architecture/hexagonal.md) — how a non-trivial brick is laid out, and when that layout is *not* warranted.
3. The RFC index in [`rfc/readme.md`](./rfc/readme.md#index) — what exists and what is being built.
