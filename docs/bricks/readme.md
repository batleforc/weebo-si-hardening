# Bricks

Operator-facing documentation for what is built. Each page is the *how*; the matching RFC is the
*why*, and it stays the reference when the two disagree.

| Brick | Page | RFC | Layout |
| --- | --- | --- | --- |
| `passwd-append` | [`passwd-append.md`](./passwd-append.md) | [0001](../rfc/0001-passwd-append.md) | `bins/`, flat |
| `preauth-proxy` | [`preauth-proxy.md`](./preauth-proxy.md) | [0003](../rfc/0003-preauth-proxy.md) | `bins/`, hexagonal |
| `weebo-si-operator` | [`weebo-si-operator.md`](./weebo-si-operator.md) | [0002](../rfc/0002-weebo-si-operator.md) | `crates/`, hexagonal, 8 crates |

A brick with no page here has not shipped yet. Check the
[RFC index](../rfc/readme.md#index) for what is designed and where it stands.
