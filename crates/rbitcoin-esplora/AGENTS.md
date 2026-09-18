# rbitcoin-esplora

Esplora-compatible REST and wallet-scoped WebSocket. Depends on query, store,
net, and mempool. Electrum is a sibling crate (`rbitcoin-electrum`); both
need `--sh-index`.

## Read first

| Change | Read |
|--------|------|
| Shipped HTTP / WS surface | [`COMPAT.md`](../../COMPAT.md) |
| Flags, listen, SH tradeoffs | [`OPERATOR.md`](../../OPERATOR.md) |
| 0.8 Core+electrs drop-in (`/internal/*`, unix) | [`docs/esplora-mempool-backend.md`](../../docs/esplora-mempool-backend.md) |
| JSON-RPC overlap (broadcast, cookie) | [`docs/rpc.md`](../../docs/rpc.md) |

## Where

- Router and listen: `src/server.rs`
- Handlers: `src/handlers.rs`
- Tx JSON: `src/tx_json.rs`
- WS: `src/ws.rs`

## Rules here

- Address-prefix and Liquid stay 404. Do not add `/api/v1/` catalogue routes.
- HTTP `sh_join` is not an unbounded process LRU (**X-M3**). Sticky joins stay Electrum TCP.
- Do not grow a `*_for_test` backdoor. Tests drive the shipped route.

## Verify

`cargo test -p rbitcoin-esplora --lib`
