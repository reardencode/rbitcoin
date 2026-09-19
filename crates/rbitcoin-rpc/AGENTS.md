# rbitcoin-rpc

Core-class JSON-RPC subset. Not full Core parity. Depends on query, store,
net, and consensus. The HTTP server is `src/server.rs`; methods are
`src/methods.rs`.

## Read first

| Change | Read |
|--------|------|
| Method list, auth, permanent gaps | [`docs/rpc.md`](../../docs/rpc.md) |
| Intentional differences | [`COMPAT.md`](../../COMPAT.md) |
| What operators can pass | [`OPERATOR.md`](../../OPERATOR.md) |
| 0.8 mempool CORE_RPC over unix `rpc.sock` | [`docs/rpc.md`](../../docs/rpc.md), [`OPERATOR.md`](../../OPERATOR.md) |

## Rules here

- Document a new method in `docs/rpc.md` in the same change. Do not imply Core-complete RPC.
- Do not invent `rpcuser` / `rpcpassword` (already refused).
- Do not grow a `*_for_test` backdoor. Tests drive the shipped method.

## Verify

`cargo test -p rbitcoin-rpc --lib`

Core functional (labeled job only, not the default pin):
[`.agents/skills/core-functional/SKILL.md`](../../.agents/skills/core-functional/SKILL.md).
