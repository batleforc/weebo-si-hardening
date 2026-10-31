// Input of `weebo-crd-docs` (@weebo/operator-docs), run by `task docs:site:gen`
// (and `task recu`): what the CRD reference pages say beyond the CRDs
// themselves. The CRDs are the chart's copies, which `task recu` regenerates
// from crates/weebo-si-crd.
import { defineConfig } from "@weebo/operator-docs/crd-docs";

const repo = "https://github.com/batleforc/weebo-si-hardening/blob/main/docs";

export default defineConfig({
  crdDir: "../charts/weebo-si-operator/crds",
  // `WeeboSiConfig` → example named `my-config`. The operator only reads the one named
  // `cluster`: the overview page and the configuration reference say so.
  kindPrefix: "WeeboSi",
  // The order you create them in: the singleton, then teams, then people.
  order: ["WeeboSiConfig", "WeeboSiTeam", "WeeboSiUser"],
  guides: {
    WeeboSiConfig: ["The configuration reference", `${repo}/weebosiconfig.md`],
    WeeboSiTeam: ["Teams and users", `${repo}/bricks/teams-and-users.md`],
    WeeboSiUser: ["Teams and users", `${repo}/bricks/teams-and-users.md`],
  },
  // A minimal, realistic `spec` per kind, checked against the schema.
  examples: {
    WeeboSiConfig: {
      features: {
        dwocPin: {
          mode: "DryRun",
          catalog: [{ key: "baseline", name: "weebo-hardened-config", namespace: "eclipse-che" }],
          default: "baseline",
        },
      },
    },
    WeeboSiTeam: {
      namespaceSelector: { matchLabels: { "weebo.io/team": "team-1" } },
    },
    WeeboSiUser: {
      username: "alice",
    },
  },
});
