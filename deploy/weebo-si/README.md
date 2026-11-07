# `deploy/weebo-si/`

The reference hardening configuration for [weebo-si](https://github.com/batleforc/weebo-si)'s Eclipse
Che, for workspaces built on WeeboDevImage's `che-min-mise`. It is a worked example, applied one
stage at a time.

**Read [`docs/guides/weebo-si-standard.md`](../../docs/guides/weebo-si-standard.md) first.** It
walks these files in order, and says for each one what it refuses, what it allows and why.

```text
values/       chart values: weebo-si-operator, endpoint-gateway
dwoc/         DevWorkspaceOperatorConfigs: weebo-workspace (restricted), weebo-build (user namespace + seccomp)
templates/    what the features copy into workspace namespaces: network, kubearmor, registry, quotas
config/       the WeeboSiConfig singleton, every feature written out and Off (stage 0)
stages/       one merge patch per step of the guide; only `mode` changes
teams/        weebo, weebo-build
users/        one example member
examples/     a devfile and a namespace, annotated — read, not applied
```

On weebo-si itself, the singleton, the teams, the users and the templates are rendered by
`2.argo/helm/che/hardening` and self-healed by Argo CD. Write each stage into that chart's
`values.yaml`; do not `kubectl patch` the live object.

```bash
task deploy:check            # every stage resolved and validated as the controller does
task deploy:check:envtest    # every stage applied to a real apiserver, strict field validation
```
