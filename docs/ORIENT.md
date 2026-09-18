# Agent orientation

Read this before a broad search when the task area is unclear.
Facts stay in the owner files in [`README.md`](./README.md). This page only routes.

## Crate graph

`rbitcoin-primitives` and `rbitcoin-log` sit under the rest.
`rbitcoin-store` is the map-free relational archive (Class A append, Class B hash heads, Class C tip-mutable).
`rbitcoin-query` is the confirm and query layer over that store.
`rbitcoin-consensus` validates headers, blocks, and scripts.
`rbitcoin-mempool` is the live transaction graph.
`rbitcoin-net` is P2P and IBD (query, store, consensus, mempool).
`rbitcoin-rpc`, `rbitcoin-electrum`, and `rbitcoin-esplora` serve query and net.
`rbitcoin-node` composes those crates into one process.
`rbitcoin-cli` is the RPC client (primitives only).
`rbitcoin-test` and `rbitcoin-bench` are harnesses, not the product graph.

Before the first edit in a crate, read `crates/<name>/AGENTS.md` when that file exists.

## Read first

| Task | Read |
|------|------|
| Confirm stage IO, leftover union, pin identity, silent fallback | [`invariants.md`](./invariants.md) |
| Writer roles, publish order, body queue, pins | [`concurrency.md`](./concurrency.md) |
| On-disk bytes, schema bump / migrate / refuse | [`../SCHEMA.md`](../SCHEMA.md) |
| Process RAM, body-queue caps, production evict | [`ibd-memory.md`](./ibd-memory.md) |
| io_uring vs fd; do not flatten a purpose-built machine | [`io-modality.md`](./io-modality.md) |
| Which head file (tx / header / scripthash) | [`heads.md`](./heads.md) |
| Crash, tip-as-commit, kill-9 | [`crash-recovery.md`](./crash-recovery.md) |
| Tests, budgets, coverage, fixtures | [`../TESTING.md`](../TESTING.md) |
| Multi-step plan | [`how-we-plan.md`](./how-we-plan.md) |
| 0.8 Core+electrs drop-in | [`esplora-mempool-backend.md`](./esplora-mempool-backend.md) |
| JSON-RPC surface | [`rpc.md`](./rpc.md) |
| Open, push, or poll a PR | [`../.agents/skills/ship-pr/SKILL.md`](../.agents/skills/ship-pr/SKILL.md) |
| Minor, patch, or major release | [`../.agents/skills/release/SKILL.md`](../.agents/skills/release/SKILL.md) |
| Core functional harness | [`../.agents/skills/core-functional/SKILL.md`](../.agents/skills/core-functional/SKILL.md) |

## Ask first

Hard stops are the Store and IBD bullets in [`../AGENTS.md`](../AGENTS.md).
Also ask before expanding who is trusted beyond the boundary in
[`../SECURITY.md`](../SECURITY.md).
