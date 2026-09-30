# Documentation

Documentation for `weebo-si-hardening` is plain markdown, versioned next to the code.
No static site generator: a RFC has to be readable in a diff and in the forge UI. The one
exception is [`generator/`](./generator/readme.md), a single static page with no build step.

## Map

| Path | What lives there |
| --- | --- |
| [`rfc/`](./rfc/readme.md) | The RFC process, the template, and every RFC. **Start here.** |
| [`architecture/`](./architecture/readme.md) | Cross-cutting conventions every brick follows (hexagonal layering, repo layout). |
| [`bricks/`](./bricks/readme.md) | Operator-facing docs for what has shipped: flags, config, exit codes, failure modes. |
| [`weebosiconfig.md`](./weebosiconfig.md) | Every field of the `WeeboSiConfig` CRD: type, default, meaning, and what a wrong value does. |
| [`weebositeam.md`](./weebositeam.md) | Every field of the `WeeboSiTeam` CRD: a team's selector, priority, per-feature catalogues, groups and workspace template. |
| [`weebosiuser.md`](./weebosiuser.md) | Every field of the `WeeboSiUser` CRD: a person's identity, team, provisioning switches, and what their `status` means. |
| [`generator/`](./generator/readme.md) | A form per CRD that builds a valid object from the schema and prints the YAML — [published on GitHub Pages](https://batleforc.github.io/weebo-si-hardening/). |
| [`ci.md`](./ci.md) | Every CI gate, what it blocks, and how to run it locally. |

## Reading order for a newcomer

1. [`rfc/readme.md`](./rfc/readme.md) — how a feature gets from idea to merged code.
2. [`architecture/hexagonal.md`](./architecture/hexagonal.md) — how a non-trivial brick is laid out, and when that layout is *not* warranted.
3. The RFC index in [`rfc/readme.md`](./rfc/readme.md#index) — what exists and what is being built.
4. [`weebosiconfig.md`](./weebosiconfig.md) — the one object every feature is configured by, once
   you need to actually turn something on.
