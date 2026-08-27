# `RBITCOIN_*` inventory and policy (Q-16)

Operator configuration is **CLI / conf first**. Process env is only for
bootstrap, a single IO field hatch, and an **unstable** debug set listed
below. Do not grow env surface without a damn-good reason.

## Survivors (production)

| Env | Why it stays |
|-----|----------------|
| **`RBITCOIN_LOG`** / **`RUST_LOG`** | Bootstrap logging before conf parse; CLI `--log-level` wins when set |
| **`RBITCOIN_IO`** | Field escape hatch: `uring` \| `pool` \| `iocp` \| `pread`. **Single** bulk switch. `pread` disables the completion session. Unknown tokens (including deleted `mmap`) fall through to the default |

`RBITCOIN_P2P_MAX_INBOUND` is an **input** when CLI/conf omit `--maxinbound`
(`NodeConfig::absorb_inbound_env`). The node does not `set_var` it.

## Unstable (honored, not advertised)

Rare operator/debug reads. Prefer changing defaults in code. Not required
for signet/mainnet sync. **Not** CLI.

| Env | Default | Role |
|-----|---------|------|
| `RBITCOIN_BLOCK_QUEUE_GB` | 1 | Densify assign-stop (GiB). `0` = unlimited. Never refuses enqueue |
| `RBITCOIN_BLOCK_QUEUE_BYTES` | 1 GiB | Same stop in bytes (wins over GB). `0` = unlimited |
| `RBITCOIN_BULK_IO_WORKERS` | backend default | pread worker count when `RBITCOIN_IO=pread` |
| `RBITCOIN_CLASS_C_INRAM_MAX_MB` | 256 | L2 cap for `confirmed` / `header_txs_*`; over → fd L0. `strong_tx` always L2 |
| `RBITCOIN_TX_HEAD_BITS` | scale default | `tx.head` bits (dangerous on a live datadir) |
| `RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS` | 25 | Wipe/empty-head MPHF range `2^bits` (26 wider; clamp 6..=26) |
| `RBITCOIN_TX_HEAD_REBUILD_WORKERS` | min(n-cpu, free-RAM/750 MiB) | Wipe/empty-head MPHF parallelism (`1` = serial). Unset = auto. **Not** SH's 1.5 GiB cap |
| `RBITCOIN_TX_IDX_SOFT_SPAN` | 16 GiB | Per-stem idx soft rollover (do not set above 32 GiB hard span). Does **not** cut `tx.head`. |
| `RBITCOIN_HEAD_SLOTS_HEADER` | scale default | Header hash-head initial slots (power of two) |
| `RBITCOIN_SH_UNIQUE_HINT` | off | SH unique-hint probe |
| `RBITCOIN_SH_FORCE_REBUILD` | off | Sticky SH rebuild (also in OPERATOR) |
| `RBITCOIN_SH_RECOLLECT_WORKERS` | min(n-cpu, free-RAM/1.5 GiB) | SH recollect parallelism (`1` = serial). Unset = auto (see [`ibd-memory.md`](./ibd-memory.md)) |
| `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` | 128 MiB | Recollect per-worker spill (clamp 16–512 MiB); compact floor is 3/4 of this |
| `RBITCOIN_SH_MERGE_WORKERS` | min(n-cpu, free-RAM/1.5 GiB) | Recollect + shard k-way / ram-shard Class A scan (`1` = serial). Unset = auto (see [`ibd-memory.md`](./ibd-memory.md)) |
| `RBITCOIN_SH_MATERIALIZE` | k-way (unset) | Unset / other: catalog k-way. **`ram-shard`**: skip `scripthash.runs`; one Class A `txout` pass per unsealed prefix shard, sort that shard in RAM, pack+seal. Resume keeps sealed `head/NN`. |
| `RBITCOIN_P2P_MAX_INBOUND` | 125 | Only if `--maxinbound` / conf omitted |

## Hardcoded (no env)

| Former env | Production default |
|------------|--------------------|
| Confirm `loadq` / `scriptq` / `writeq` | 14 / 4 / 14 (`ready=` is not a cap) |
| `RBITCOIN_CONFIRM_BATCH_INPUTS` | 8000 soft inputs/pack |
| Per-path IO (`PIN_IO`, `HEAD_RESOLVE_IO`, `SPEND_META`, `SPEND_ANN`, `CLASS_C_IO`) | Follow **`RBITCOIN_IO` only** (strings deleted) |
| `RBITCOIN_FD_APPEND` | Never read (deleted) |
| `RBITCOIN_BLOCK_QUEUE_MB` | Never read (deleted; use `_BYTES` / `_GB`) |

## Test-only (not operator)

| Env | Use |
|-----|-----|
| `RBITCOIN_HEAD_SCALE` | Tiny heads under `cargo test` (honored if exported — do not set on operators) |
| `RBITCOIN_TEST_*` | Node/store test fixtures (`TEST_DROP_STORE`, `TEST_NO_SUCH_CAP`) |
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
| `RBITCOIN_SH_MAX_DIRECT_MERGE` | Deleted; catalog materialize is always k-way |
| `RBITCOIN_SH_TARGET_RUN_BYTES` | Deleted; recollect spill size is `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` |
| `RBITCOIN_SH_MERGE_FANIN` | Deleted; no fan-in reduce |

## Related

- [`OPERATOR.md`](../OPERATOR.md) — CLI / conf
- [`docs/io-modality.md`](./io-modality.md) — bulk IO behavior
