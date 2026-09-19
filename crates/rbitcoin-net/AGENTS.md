# rbitcoin-net

P2P and IBD. Depends on query, store, consensus, and mempool.
`rbitcoin-node` owns the process; this crate owns the peer and confirm pipeline.

## Read first

| Change | Read |
|--------|------|
| Roles, body queue, publish order | [`docs/concurrency.md`](../../docs/concurrency.md) |
| Stage IO | [`docs/invariants.md`](../../docs/invariants.md) |
| Process RAM, caps, evict | [`docs/ibd-memory.md`](../../docs/ibd-memory.md) |
| IO machines | [`docs/io-modality.md`](../../docs/io-modality.md) |
| Published mempool snapshots (fees; 0.8 tx JSON) | [`docs/mempool-fee-estimation.md`](../../docs/mempool-fee-estimation.md), [`COMPAT.md`](../../COMPAT.md) |

## Where

- IBD: `src/ibd/` (`assign`, `body`, `path`, `perf_log`)
- Tip: `src/chain.rs`, `src/tip_accept.rs`
- Relay: `src/tx_relay.rs`, `src/peers.rs`

## Rules here

- IBD intake is body queue → lookup → load. No large process-resident body cache with FIFO, LRU, or sticky residency.
- A change on lookup, load, scripts, or write (or a sidecar the write thread joins) gets a named `ibd: perf` timer in the same commit. Inventory: `src/ibd/perf_log.rs`.

## Verify

`cargo test -p rbitcoin-net --lib`

Core functional (labeled job only): [`.agents/skills/core-functional/SKILL.md`](../../.agents/skills/core-functional/SKILL.md).
