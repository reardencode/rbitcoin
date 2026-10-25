# rbitcoin-store

Map-free relational archive: Class A append bodies, Class B mutable hash
heads, Class C tip-mutable confirmed state. Depends on `rbitcoin-primitives`
and `rbitcoin-log`. `rbitcoin-query` and everything above it call this crate.

## Read first

Open the row that matches the change. Leave the other owners closed.

| Change | Read |
|--------|------|
| Stage IO, leftover union, no silent fallback | [`docs/invariants.md`](../../docs/invariants.md) |
| Roles, publish order, locks, grow | [`docs/concurrency.md`](../../docs/concurrency.md) |
| Bytes, Class B geometry, schema bump | [`SCHEMA.md`](../../SCHEMA.md) |
| Which head file | [`docs/heads.md`](../../docs/heads.md) |
| fd vs io_uring | [`docs/io-modality.md`](../../docs/io-modality.md) |
| Tip-as-commit, kill-9 | [`docs/crash-recovery.md`](../../docs/crash-recovery.md) |

## Where

- Open and chain: `src/chain.rs`, `src/file.rs`
- IO: `src/io_backend.rs`, `src/io_session_pool.rs`
- Heads: `src/hashhead.rs`, `src/header_table.rs`, `src/scripthash.rs`
- Fixtures: `src/testutil.rs` (`TempDir`, `tiny_store`)
- Model-checked concurrency (loom / shuttle): `tests/model/main.rs`

## Verify

`cargo test -p rbitcoin-store --test suite`

`./scripts/model-check.sh loom` for changes to `src/array_table.rs` or `src/sync.rs`
