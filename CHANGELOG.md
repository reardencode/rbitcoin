# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the **0.x** experimental line (breaking on-disk and API changes are expected
before 1.0).

## [Unreleased]

### Fixed

- **Lookup nested io_uring on write-behind pending hits:** IBD
  `ibd-confirm-lookup` panicked (`nested thread-local io_uring`) when stamp
  resolved a parent still in the `tx.head` pending map — `record_range` opened a
  second TLS ring inside the plan machine. The window is long while drain
  **seals** a full segment. Pending hits now run **before** the plan
  `with_thread_local` (same serial `record_range` as before).

### Removed

- **Dead store APIs / duplicate benches:** refuse-only `TxTable::put` /
  `Store::put_tx` / `Query::put_tx`, `body_txid_at`, and
  `head_resize_in_progress`. Deleted `script_parallel{,_ab,_focus}` and
  `rayon_audit` (they duplicated `script_pool` / `script_hotpath`).

- **Zero meters:** `WRITE_STICKY` / `WRITE_DONTNEED`, `ASM_PREV_RES_*`,
  `pin_spent_ns` / `unpin_spent_parent_outs`, `archive_resolve_stats` alias,
  and mmap-half `sample_spend_*_ab_*` helpers.

- **Hash-only confirm:** `confirm_archived_*`, hash `confirm_load_phase` /
  `confirm_script_phase`, `wire_rebuild`, and `ChainHub::confirm_hash` /
  `confirm_run`. Confirm is wire-only (`confirm_wire_*`). Store fixtures
  `Query::connect_block` / `confirm_blocks_run` stay.

- **Archive queue budget:** uncharged `ArchiveQueueBudget` / `--archive-queue-mb` /
  `RBITCOIN_ARCHIVE_QUEUE_MB`. Densify is gated by body-queue soft depth only.

- **`rbitcoin-wire-cache`:** unused tip wire-format ring crate. Node no longer
  opens `{datadir}/wire`. Reconstruct + body queue + peer wire serve tip/reorg.
  On-disk `archive_epoch.wire_depth` bytes stay unread.

### Changed

- **Confirm write path:** Class C `strong_tx` flush already wrote only the dirty
  suffix — now pinned. Class A `txout`/`inwit`/`spent` bodies submit as one
  `pwrite_batch` wave. `tx.head` insert is write-behind (page-grouped drain
  overlaps structural/Class C); resolve hits a pending txid→fk map until drain.
  Crash-open backfills a lagging head from Class A.
- **`ibd: sizes` residual:** `fuse8=` / `open_keys=` / `class_c_l2=` enter
  accounted. Sealed fuse fingerprints (~9 bits/create) were the ~1.6 GiB gap
  at 1.42 B creates — see [`docs/ibd-memory.md`](docs/ibd-memory.md).
- **Agent delivery:** plans land on a worktree topic branch as many small
  commits and **one PR**. Full workspace test/coverage is GitHub Actions, not
  a local plan-end ritual; poll the PR to green. Musl install stays
  post-merge on `master`. See `AGENTS.md` and `docs/how-we-plan.md`.

- **Docs honesty:** root `/api.jsonl` is gitignored. SCHEMA `archive_epoch.wire_depth`
  is an unread leftover field (no tip wire ring). `page_rmw_pipelined` is
  documented as test-only.

- **Docs Q-14:** [`docs/heads.md`](docs/heads.md) is the head-module glossary.
  Pipeline details stay in `concurrency.md`; architecture / OPERATOR / AGENTS
  link instead of restating. SCHEMA tree uses `tx.head/` (not flat names).

### Fixed

- **Tests:** head and `tx.idx` share one thread-local soft-span override.
  `HeadScale::test_with` pins tiny/mainnet without process-global `set_var`.

### Removed

- **Dead DONTCACHE / IO aliases:** head/idx probe no longer threads an always-false
  DONTCACHE flag. `sealed_age_from_index` lives with winner-age stats.
  Dropped `get_outs_denserels_by_range_batch`, `spend_meta_backend_next`,
  `load_needs_resize`, `HeadRole::Tx` / `RBITCOIN_HEAD_SLOTS_TX`, and
  `RBITCOIN_IO_URING` (`RBITCOIN_IO=pread` is the only pread hatch).

### Added

- **CI musl artifacts:** after a green `ci` run on `master`/`main`, workflow
  `musl` builds `nix build .#rbitcoin-musl` and uploads
  `rbitcoin-node` / `rbitcoin-cli` + `SHA256SUMS` (90 days). Not a required
  PR check. Manual retry: Actions → musl → Run workflow.

### Fixed

- **Head resolve 2-wave:** wave 1 is open + sealed ages ≤3 again. The spend-only
  DONTCACHE change had made `head_or_idx_segment_index` always false, so hot
  probed every segment and cold was empty. Unconnected hot hits still run
  wave 2 so `TipThenAny` / `TipOnly` can take a connected sibling in age ≥4.

- **Tests:** scripts-phase steal-worker pin records the coordinator thread on
  the handle (not a process-global name). Archive plan/commit wall stats sample
  under an exclusive lock so parallel `sample_and_reset` cannot steal the
  window. Head soft-span override is thread-local so a sibling
  `test_set_soft_span_bytes(0)` cannot reset another test's 48-byte roll
  window (`tip_then_any_connected_in_cold_beats_unconnected_hot`).

### Changed

- **Lookup stamp:** consult live `PipelineParentStore` by prev_txid before
  `tx.head` (`pin_txid=` / `pin_txid%` / `pin_txid_ms` / `head_n` /
  `us/pin_txid` on `ibd: perf`). Remaining head `txout.idx` fills are
  page-grouped on the held resolve session. `pin_hit%` is adopt/plan
  reuse only (this-window range-fills stay `pin_new`).

- **Schema 16:** drop `tx_height.body` (~5 GiB). Create height is a resident
  fence from `confirmed[]` + `header_txs_*` (O(blocks), RAM bsearch). Reorg
  holes return unconnected. Schema 15 stores soft-open (unlink leftover file).
  Old binaries refuse 16 (they still write `tx_height`).

- **Script pool:** `try_for_each_parallel` steals on process-wide
  `rbtc-scripts-*` workers (no per-batch `thread::scope`). Confirm phases run
  on two `rbtc-script-coord-*` threads so a steal worker is not blocked inside
  the phase. Pool wait uses a condvar deque (not `recv` under mutex).

- **`--sptweaks` during IBD:** Direct confirm no longer write-throughs the
  thin BIP-352 index (it was 50–80% of fat-era write). After tip, SH
  materialize (if `--shindex`) then a sequential backfill to live tip;
  Tip write-through only when `height == next_height`. Restart resumes
  from `next_height`.

- **Schema 15 Class A split:** `txout.body` (outs) + `inwit.body` (ins+witness)
  + `spent.body` (9 B×n_out). Packed `tx.body` with creates is refused. Pin/SH
  read outs only; annotate RMW is `spent_off+9×vout`. Working-set census in
  [`SCHEMA.md`](./SCHEMA.md).
- **Schema 15 Class B SH:** geometric slabs + megakey pages; sealed
  sorted+idx main (**no** main fuse); global ingest OA; sealed ovf keeps
  fuse8. Tip lookup is overflow (ingest + ovf fuse) then main. Open
  rematerialized SHSR shards via an OA stub; sealed ovf files are not
  opened as OA. Unlink writes the home `locate_head` found. Cold bulk
  streams packed recs (no per-shard OA image). Page-era durable SH is
  refused. The OA global `scripthash.head.fuse8` builder is gone.
- **Electrum / RPC:** skip O(mempool) API walks; overlap Electrum dispatch;
  thin `--sptweaks` serve is idx→body uring, not a packed span.
- **Electrum `server.version`:** first element is `rbitcoin-electrs <ver>` so
  Cake Wallet’s `getNodeIsElectrs()` will probe `blockchain.tweaks.subscribe`.
- **CLI-first config:** `--maxinbound`/`--maxconnections`, `--archive-queue-mb`,
  `--conf`, Core-like aliases (`--assumevalid-height`, `--maxmempool`, `--chain`).
- **Tip-follow logging:** every accepted tip block logs Core-like `UpdateTip: …`.
- **Fee snapshot / mempool APIs:** published fee table and mining chunks so
  Electrum/Esplora estimates do not block accepts (R-01–R-04).
- **Quality gates:** `cargo deny` on PR (Q-20); coverage uses prebuilt
  `cargo-llvm-cov` (Q-22); `scripts/sbom.sh` emits CycloneDX from Cargo.lock.

### Fixed

- **Findings 012–021** (fuzzamoto differential): identity/BIP30 cluster,
  tapleaf, compact-block, reorg drain — all closed with named regressions.
- **Mainnet BIP30:** skip the two Core `IsBIP30Repeat` overwrites (91842 /
  91880 hashes). Those coinbases were overwritten while still unspent, not
  fully spent. IBD `bad-txns-BIP30` at logged `@91859` was the first height
  of a write batch that contained 91880.
- **Electrum tweaks subscribe:** stream remaining heights as notifications
  and finish with Cake’s `{"message":"done"}`. A one-shot 8-height result left
  the scan isolate idle after `[restore, remaining, false]`.
- **Electrum `get_balance`:** unconfirmed delta uses the mempool scripthash
  index instead of store-resolving every live chain input. Empty Cake keys were
  ~1.5 s each on a mainnet mempool.

### Added

- **IBD write meters:** `tweaks=` on `ibd: perf` / `perf_dbg` and `confirm write slow`
  (BIP-352 index wall after spend annotate). Makes the `--sptweaks` write-thread
  cost visible in the fat-era IBD hole.

- **`--sptweaks`:** optional thin BIP-352 index (`sp_tweaks.idx` / `.body`).
  Persist is `len:tweak` only (0 or 33-byte compressed `A_tweak`). Cake outs
  join `txout`. Confirm appends; reorg truncates; background backfill.
  Electrum still serves naive when the flag is off or a height is a hole.

## [0.1.0] — 2026-07-26

### Experimental first public packaging

Initial **0.x** packaging of an experimental Bitcoin full node in Rust:

- Multi-peer IBD and tip follow over **BIP324 v2-only** P2P
- Relational Class A/B/C archive (reconstruct historical blocks; tip wire ring + tip durability after catch-up; store later fully map-free — see `docs/io-modality.md`)
- **Pure-Rust** consensus/script path (secp256k1 via rust-bitcoin only; no libbitcoinconsensus dual-eval)
- Confirm pipeline (load / scripts / write), Direct index mode during IBD, native scripthash + in-process **Electrum** after tip
- Libre-class mempool admission with script checks on accept; BIP152 v2 compact blocks and BIP339 wtxid relay on tip sessions
- Operator docs for **signet lab first** and **experimental mainnet** (default milestone skips scripts ≤ 840000)

### Documentation

- Architecture overview for unique store / IO / consensus design (`docs/architecture.md`)
- Security policy (`SECURITY.md`), this changelog, dual MIT OR Apache-2.0 licenses

### Notes

- On-disk schema is **unstable until 1.0** (reindex on incompatible changes).
- Completing a full mainnet IBD on an operator host is **out of band** for this
  release packaging; experimental mainnet remains lab-only.
- Workspace package metadata does not claim a public `repository` URL until one
  is published.
