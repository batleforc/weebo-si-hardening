# site

weebo-si-hardening's documentation site (RFC 0012): a Fumadocs site on
[`@weebo/operator-docs`](https://github.com/batleforc/weebo-operator-kit/tree/main/packages/operator-docs),
published to GitHub Pages by `.github/workflows/pages.yaml`.

It carries what is generated — the CRD reference, the CRD form and IDE,
from `charts/weebo-si-operator/crds/` — and short pages pointing at the
markdown in `../docs`, which stays the source for the RFCs, the runbooks and
the architecture.

```bash
task site:deps    # npm ci
task site:gen     # weebo-crd-docs: content/docs/crds/ and public/crd-schemas/
task site         # http://localhost:3000
task site:build   # lint, types, static export into out/
```

- `src/lib/shared.ts`: the site's name, pitch and repository.
- `crd-docs.config.mjs`: what the CRD pages say beyond the schema (order, guides, examples).
- `src/lib/crd-choices.ts`: the manifest builder's guided choices (none yet).
