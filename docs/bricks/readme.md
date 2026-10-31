# Bricks

Operator-facing documentation for what is built. Each page is the *how*; the matching RFC is the
*why*, and it stays the reference when the two disagree.

| Brick | Page | RFC | Layout |
| --- | --- | --- | --- |
| `passwd-append` | [`passwd-append.md`](./passwd-append.md) | [0001](../rfc/0001-passwd-append.md) | `bins/`, flat |
| `preauth-proxy` | [`preauth-proxy.md`](./preauth-proxy.md) | [0003](../rfc/0003-preauth-proxy.md) | `bins/`, hexagonal |
| `weebo-si-operator` | [`weebo-si-operator.md`](./weebo-si-operator.md) — install, CLI, rollout, `dwoc-pin` | [0002](../rfc/0002-weebo-si-operator.md) | `crates/`, hexagonal — see [`operator-internals.md`](../architecture/operator-internals.md) |
| ↳ `network-profiles`, `policy-guard` | [`network-profiles.md`](./network-profiles.md) | [0004](../rfc/0004-network-profiles.md), [0008](../rfc/0008-policy-guard-coverage.md) | `crates/weebo-si-{network-profiles,policy-guard}` and their `-adapters` |
| ↳ `image-policy` | [`image-policy.md`](./image-policy.md) | [0005](../rfc/0005-image-policy.md) | `crates/weebo-si-image-policy`, `crates/weebo-si-image-policy-adapters` |
| ↳ `kubearmor-policy` | [`kubearmor-policy.md`](./kubearmor-policy.md) | [0006](../rfc/0006-kubearmor-policy.md) | `crates/weebo-si-kubearmor-policy`, `crates/weebo-si-kubearmor-policy-adapters` |
| ↳ `registry-config` | [`registry-config.md`](./registry-config.md) | [0007](../rfc/0007-registry-config.md) | `crates/weebo-si-registry-config`, `crates/weebo-si-registry-config-adapters` |
| `endpoint-gateway` | [`endpoint-gateway.md`](./endpoint-gateway.md) | [0009](../rfc/0009-endpoint-auth.md) | `bins/` + `crates/weebo-si-endpoint-auth`, hexagonal |
| `WeeboSiTeam` / `WeeboSiUser` | [`teams-and-users.md`](./teams-and-users.md) | [0011](../rfc/0011-teams-and-users.md) | `crates/weebo-si-crd` + `crates/weebo-si-identity`, hexagonal |

A brick with no page here has not shipped yet. Check the
[RFC index](../rfc/readme.md#index) for what is designed and where it stands.
