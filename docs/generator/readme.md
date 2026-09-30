# Config generator

A form per CRD — [`WeeboSiConfig`](../weebosiconfig.md), [`WeeboSiTeam`](../weebositeam.md),
[`WeeboSiUser`](../weebosiuser.md) — that builds the object from the operator's own schema,
validates it as you type and prints the YAML to `kubectl apply`.

**Published at <https://batleforc.github.io/weebo-si-hardening/>** by the
[`pages`](../../.github/workflows/pages.yaml) workflow on every change to `main`. Link to one kind
with its name as the fragment: `…/weebo-si-hardening/#WeeboSiTeam`.

## What it does

- Renders every field of `spec`, plus `metadata.name`, `labels` and `annotations`, with its
  description, type and default. Optional blocks are left out until added; anything left unset keeps
  its schema default and is not written.
- Validates against the same schema the API server enforces — required fields, enums, patterns,
  lengths, bounds — and the one rule the schema cannot state: a `WeeboSiConfig` must be named
  `cluster`. Every error links to its field.
- **Import** takes an existing object and loads it into the form; fields the schema does not know
  are listed, because the API server prunes them.
- Keeps each kind's draft in the browser's `localStorage`. Nothing is sent anywhere.

The output quotes `'Off'` and the other YAML 1.1 booleans, so `kubectl` reads it as a string. When
hand-writing YAML, quote `"Off"` too.

It checks the schema, not the cluster: a catalogue key that does not exist, or a team another
object already claims, is only caught by the operator. Run
`kubectl apply --dry-run=server -f <file>` before applying.

## How it is built

| File | What it is |
| --- | --- |
| `index.html`, `style.css`, `generator.js` | The page. No build step and no framework; the one library, [js-yaml](https://github.com/nodeca/js-yaml), is loaded from jsDelivr pinned by version and subresource integrity, under a strict Content-Security-Policy. |
| `schemas.js` | **Generated** by `scripts/docs-schemas.sh` from `charts/weebo-si-operator/crds/`. Never edited by hand. |

```bash
task docs:schemas     # regenerate schemas.js after a CRD change (also part of `task recu`)
task docs:check       # fail if schemas.js is stale (part of `task lint`, and gated in CI)
task docs:generator   # serve it on http://127.0.0.1:8765 — opening index.html from disk works too
```

A CRD change reaches the page on its own: `task recu` regenerates `crd.yaml` and the chart's CRDs
from the Rust types, then `schemas.js` from those.
