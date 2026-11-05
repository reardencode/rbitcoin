# `RBITCOIN_*` inventory and policy (Q-16)

Operator configuration is **CLI / conf first**. Process env is only for
bootstrap, a single IO field hatch, and an **unstable** debug set listed
below. Do not grow env surface without a damn-good reason.

## Survivors (production)

| Env | Why it stays |
|-----|----------------|
| **`RBITCOIN_LOG`** / **`RUST_LOG`** | Bootstrap logging before conf parse; CLI `--log-level` wins when set |
| **`RBITCOIN_IO`** | Field escape hatch: `uring` \| `pool` \| `iocp` \| `pread`. **Single** bulk switch. `pread` disables the completion session. Unknown tokens (including deleted `mmap`) fall through to the default |

`main` (`process_main`) reads `RBITCOIN_P2P_MAX_INBOUND`,
`RBITCOIN_BLOCK_QUEUE_BYTES`, `RBITCOIN_BLOCK_QUEUE_GB`,
`RBITCOIN_SH_FORCE_REBUILD`, `RBITCOIN_RPC_PACKAGE_DIALECT`,
`RBITCOIN_RPC_WAIT_TIP_IDLE`, and `RBITCOIN_TEST_DROP_STORE` once into
`NodeEnv` and passes that to `cli_main`. Nothing below the process shell
reads them. An empty value is the same as unset. A set value that does not
parse stops the start with exit 2 and `error: configuration error:
RBITCOIN_…`; it is never ignored. Flags take `1` or `true` (on) and `0` or
`false` (off).
`RBITCOIN_P2P_MAX_INBOUND` is an **input** only when CLI/conf omit
`--max-inbound` (`NodeConfig::absorb_inbound_env`).

## Unstable (honored, not advertised)

Rare operator/debug reads. Prefer changing defaults in code. Not required
for signet/mainnet sync. **Not** CLI.

| Env | Default | Role |
|-----|---------|------|
| `RBITCOIN_BLOCK_QUEUE_GB` | 1 | Densify assign-stop (GiB). `0` = unlimited. Never refuses enqueue for budget (undecodable wire is dropped) |
| `RBITCOIN_BLOCK_QUEUE_BYTES` | 1 GiB | Same stop in bytes (wins over `RBITCOIN_BLOCK_QUEUE_GB`). `0` = unlimited |
| `RBITCOIN_BULK_IO_WORKERS` | backend default | pread worker count when `RBITCOIN_IO=pread` |
| `RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS` | 25 | Wipe/empty-head MPHF range `2^bits` (26 wider; clamp 6..=26) |
| `RBITCOIN_TX_HEAD_REBUILD_WORKERS` | min(n-cpu, free-RAM/1 GiB) | Wipe/empty-head MPHF parallelism (`1` = serial). Unset = auto. **Not** the SH extract 1.5 GiB cap |
| `RBITCOIN_HEAD_SLOTS_HEADER` | scale default | Header hash-head initial slots (power of two) |
| `RBITCOIN_SH_FORCE_REBUILD` | off | Sticky SH rebuild (also in OPERATOR) |
| `RBITCOIN_SH_MERGE_WORKERS` | min(n-cpu, max(1, free-RAM/1.5 GiB)) | SH extract (collect, merge, BDZ, fuse, pass 2, pack). `1` = serial. Unset = auto (see [`ibd-memory.md`](./ibd-memory.md)) |
| `RBITCOIN_P2P_MAX_INBOUND` | 200 | Only if `--max-inbound` / conf omitted |
| `RBITCOIN_URING_DRAIN_HARD_SECS` | 120 | `drain_all` zero-CQE abort (Linux/pool/IOCP). Raise if completions are slow but still arriving |
| `RBITCOIN_RPC_WAIT_TIP_IDLE` | off | `getblockcount` / `getbestblockhash` / `wait_height` wait until the tip-accept lane is empty. Default (unset) waits only for the job that was running when the RPC arrived. The Core-functional bitcoind shim sets `1` so `sync_blocks` stays deterministic. **Not** a production operator knob |
| `RBITCOIN_RPC_PACKAGE_DIALECT` | off | `submitpackage` uses Core `IsChildWithParentsTree` (`-25 package topology disallowed`): the last tx spends every other member, and no parent spends another. Default (unset) still package-evaluates a child-with-parents remainder that failed min relay, the dynamic mempool floor, or missing inputs; a child that is not that shape stays `bad-txns-inputs-missingorspent`. A member whose own feerate exceeds `maxfeerate` is rejected either way and does not rescue the package. The Core-functional bitcoind shim sets `1`. **Not** a production operator knob |

## Hardcoded (no env)

| Former env | Production default |
|------------|--------------------|
| Confirm `loadq` / `scriptq` / `writeq` | 14 / 4 / 14 (`ready=` is not a cap) |
| `RBITCOIN_SH_UNIQUE_HINT` | ignored; cold open-address pre-size is gone |
| `RBITCOIN_CONFIRM_BATCH_INPUTS` | 8000 soft inputs/pack |
| Per-path IO (`RBITCOIN_PIN_IO`, `RBITCOIN_HEAD_RESOLVE_IO`, `RBITCOIN_SPEND_META`, `RBITCOIN_SPEND_ANN`, `RBITCOIN_CLASS_C_IO`) | Follow **`RBITCOIN_IO` only** (strings deleted) |
| `RBITCOIN_FD_APPEND` | Never read (deleted) |
| `RBITCOIN_BLOCK_QUEUE_MB` | Never read (deleted; use `RBITCOIN_BLOCK_QUEUE_BYTES` / `RBITCOIN_BLOCK_QUEUE_GB`) |

## Test-only (not operator)

| Env | Use |
|-----|-----|
| `RBITCOIN_TEST_DROP_STORE` | `1` or `true`: `--smoke` deletes the store before shutdown so the shutdown error path runs (`NodeEnv::test_drop_store`) |
| `RBITCOIN_CORE_DATA` | Directory of Core JSON corpora for consensus tests |

## Deleted / do not reintroduce

| Env | Note |
|-----|------|
| `RBITCOIN_DIAG_DATADIR` / `RBITCOIN_CAND_FK_FIXTURE` | Host-forensics tests deleted |
| `RBITCOIN_RESIDENCY_BYTES` / create pin FIFO | Feature removed |
| Per-path bulk IO matrix | Collapsed to `RBITCOIN_IO` |
| Confirm queue env overrides | Hardcoded depths |
| `RBITCOIN_IO_URING` | Deleted; use `RBITCOIN_IO=pread` |
| `RBITCOIN_TX_HEAD_ACCESS` | Deleted; tables are always fd pread/pwrite |
| `RBITCOIN_IO=mmap` | Deleted; unknown token falls through to default |
| `RBITCOIN_HEAD_SLOTS_TX` | Deleted; `tx.head` is segmented address head |
| `RBITCOIN_SH_MAX_DIRECT_MERGE` | Deleted; catalog k-way materialize removed (unsorted shards are the tip path) |
| `RBITCOIN_SH_MATERIALIZE` | Deleted; unsorted-shard collect/pack is the default (was env-select vs k-way) |
| `RBITCOIN_SH_RECOLLECT_WORKERS` | Deleted; collect and pack share `RBITCOIN_SH_MERGE_WORKERS` (1.5 GiB per worker) |
| `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` | Deleted; catalog recollect/spill is gone (unsorted shards) |
| `RBITCOIN_SH_TARGET_RUN_BYTES` | Deleted; catalog recollect/spill is gone |
| `RBITCOIN_SH_MERGE_FANIN` | Deleted; no fan-in reduce |
| `RBITCOIN_HEAD_SCALE` | Deleted (was test-only). Tiny vs Mainnet is store open layout (`StoreLayout::tiny` / `single`). Do not reintroduce |
| `RBITCOIN_TX_HEAD_BITS` | Deleted. New `tx.head` uses the scale width (tiny 16, otherwise 25). Do not reintroduce |
| `RBITCOIN_CLASS_C_INRAM_MAX_MB` | Deleted. `confirmed` and `header_txs_*` stay in RAM up to 256 MiB, then fd. `strong_tx` stays in RAM. Do not reintroduce |
| `RBITCOIN_TX_IDX_SOFT_SPAN` | Deleted; schema 22 loc has no Class A idx mmap span. Do not reintroduce |

## Related

- [`OPERATOR.md`](../OPERATOR.md) — CLI / conf
- [`docs/io-modality.md`](./io-modality.md) — bulk IO behavior
