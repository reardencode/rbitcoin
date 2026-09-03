# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the **0.x** experimental line (breaking on-disk and API changes are expected
before 1.0).

## [Unreleased]

### Fixed

- **Leftover hop-dump is not cleared by the next head-resolve batch:**
  `clear_leftover_miss` wiped `diag=1` at the start of every TipOnly
  resolve. Parallel `cargo test` failed `leftover_miss_dumps_probe_diag`;
  the operator reject line could also lose the dump. Miss classification
  is still per-batch.

- **Mempool accept does not run on a tokio worker:** P2P `tx` and Esplora
  `POST /tx` used `accept_tx` on the session/axum thread, holding
  `inner` write across store UTXO lookups. All workers parked; timers and
  P2P died. Accept is `spawn_blocking` (`BlockingRegion`); prepare uses a
  graph **read** lock. The node runtime caps blocking threads at nCPU
  (min 4).

- **IBD tip is most-work, not max advertised height:** a higher-height
  less-work fork (or bogus `version.start_height`) is `register_explore`
  only and does not raise the work-path horizon. Empty `headers` at a
  drained most-work path is EOF even if `max_peer_height` is hundreds
  ahead — restart-at-tip no longer chases that height.

- **IBD empty-headers lag no longer reseeds a live work path:** `getheaders`
  empty while peers advertise ahead still re-asks, but
  `seed_work_path_from_store` (full header-graph walk) runs only when
  `ordered` is empty. Latter mainnet IBD was walking ~1M headers every ~2s
  (0.5–1.2s each) while already holding 12k–64k ordered hashes. The matching
  WARN is `trace` unless the path is empty.

### Changed

- **Tip connect runs on a dedicated `tip-accept` OS thread:** P2P reconstruct
  and RPC generate/submitblock no longer take `connect_lock` or run
  `confirm_wire_run_preverified` on a tokio worker. The peer awaits a oneshot;
  scripts still steal on `rbtc-scripts-*`. Not the IBD body-queue pipeline.

- **Electrum `blockchain.tweaks.subscribe`:** pre-taproot empty heights go out
  as **one notify** with ≤1024 keys (Cake last-key progress), not one line per
  height. Cake `historicalMode=false` (param `[2]`) **cut-through**: omit
  confirmed-spent P2TR outs (and txs with none left). Spentness is one
  `spent.idx` batch plus one spent-body walk per create, not a serial
  idx+body per eligible tx. `true` keeps spent outs
  for restore. Probe `[0,1,false]` is still `{"0": {}}`. `{"message":"done"}`
  ends a **chunk** (60s wall at a wave boundary, or the requested `count` if
  sooner) so Cake resubscribes; it is not “`count` through tip”.

### Added

- **Unsorted-shard SH materialize is the default:** tip finalize does one Class A
  `txout` pass into unsorted `scripthash.unsorted/NN` (nCPU collect, 1 MiB
  per-shard buffers, offset-ordered pwrite, 64 MiB fallocate extents), then
  unique-sorts each file **in place** and seals `head/NN` (~2 GiB per pack
  worker). Catalog k-way merge and Class A catalog recollect/spill are
  removed (`RBITCOIN_SH_RECOLLECT_WORKERS` / `RBITCOIN_SH_RECOLLECT_SPILL_BYTES`
  deleted). Leftover `scripthash.runs` are discarded at tip (never rematerialized).
  Collect workers are always nCPU. Class A collect body IO is libc `pread`
  (16 MiB spans), not TLS uring. SIGINT keeps sealed shards; missing `DONE`
  restarts collect.

- **Unsorted SH recs store the 16-byte head prefix:** each file rec is 24 B
  (`prefix16` + `create_fk`), matching the sealed head. `DONE` magic is
  `SHUNSRT3` and records the inclusive Class A create_fk scanned. Leftover
  `SHUNSRT2` / `SHUNSRT1` files restart collect. If Class A grows after `DONE`
  with no sealed shards, collect appends the tail into the unsorted files;
  if any `head/NN` is already sealed, pack finishes then Direct Class A tail
  backfill fills the gap (write-behind no-ops until Tip).

- **SH collect body IO is libc pread:** nCPU workers read coalesced 16 MiB
  `txout.body` spans with blocking `pread`. The TLS uring 5 s wait is a
  lost-CQE fence for 4 KiB lookup/g-page machines — not this path. Avoids
  `undrained pending=1` when n workers share the disk.

- **Peer full-node notes:** [`docs/peer-clients.md`](docs/peer-clients.md)
  compares Hornet Node and satd (tests and ideas to consider later, and
  explicit non-copies). Not a quality.md Open list.

- **Write `other=` classification:** `ibd: perf` names `pins=take+map`
  (plan Arc copies + create-pin FkMap) and `head_sub=` (tx.head drain
  submit). They join the write inventory so `other=` is the leftover
  residual. [`crates/rbitcoin-net/src/ibd/perf_log.rs`](crates/rbitcoin-net/src/ibd/perf_log.rs).

- **Structural lint / CRAP / Miri:** required `ast-grep` scan for discarded
  `tokio::spawn`, `mem::forget`/`Box::leak`, and dropped `thread::spawn`;
  `coverage.sh` prints a cargo-crap summary after the ≥90% LCOV gate (no
  CRAP-30 fail); nightly Miri on `rbitcoin-primitives` only. Further work
  is **Q-54–Q-56** in [`docs/quality.md`](docs/quality.md);
  how to run is [`TESTING.md`](TESTING.md).

- **Confirmed-tx chain view:** Electrum/Esplora responses for confirmed
  txs are built at one published tip and stamp that tip for the client
  (`X-Bitcoin-Chain-Tip` on Esplora; JSON-RPC `chain_tip` on Electrum).
  Same-height reorgs invalidate the SH join cache and change Electrum
  status (block hash in the preimage). Yuval raised the A-B-A hole;
  shape from [mempool#6584](https://github.com/mempool/mempool/issues/6584)
  and [electrum-protocol#2](https://github.com/spesmilo/electrum-protocol/pull/2).
  [`COMPAT.md`](COMPAT.md), [`docs/concurrency.md`](docs/concurrency.md).

- **As-of ancestor snapshot:** `?asof=<blockhash>` (Esplora) and a trailing
  Electrum `asof:<blockhash>` string on `get_balance` / `listunspent` /
  `get_history` / `transaction.get` / `transaction.get_merkle` return
  confirmed data as of a still-live best-chain block (scripthash reads
  are also capped at visible SH). Thanks again to Yuval — this is the
  buried-height half of binding confirmations to a chain. Stamp is the
  asof hash; unknown/disconnected → 404 / `asof not on chain`. The
  `asof:` prefix cannot be a later official hash/string arg. Clients
  negotiate protocol `1.4.2-asof` (`server.features.asof_protocol`);
  Electrum `protocol_max` stays dotted-int `1.4.2`.

- **Road to 1.0:** [`docs/road-to-1.0.md`](docs/road-to-1.0.md) owns 1.0
  product gates (claimed Core functional, Core-parity fuzz, selected
  crates.io libraries, SH/RSS, eclipse/DoS, fee validation, schema freeze).
  [`docs/quality.md`](docs/quality.md) stays the living Open backlog.

### Changed

- **Electrum thin tweaks serve:** indexed `blockchain.tweaks.subscribe`
  joins packed eligible create_fks with one `txid.body` range pread and
  a sequential idx walk, batches consecutive `sp_tweaks` heights (one
  idx + one body pread per segment), loads the JSON-RPC first height in
  the same Class A `txout` span as the first notifies, overlaps the next
  wave's load with the previous TCP flush, and skips zero-fill on the
  span pread. Default wave cap is **16384** eligible txs (128 heights
  unchanged). No `sp_tweaks` schema change.

- **Parallel `tx.head` wipe-rebuild:** ranges seal concurrently,
  min(CPUs, free RAM / **1 GiB**, range count). Distinct from SH
  materialize (1.5 GiB/worker). `RBITCOIN_TX_HEAD_REBUILD_WORKERS`
  overrides (`1` = serial).

- **`tx.head` seal uses less RAM:** uniqueness is an in-place sort (no
  per-key `HashMap<Vec>`), BDZ peel is XOR-degree with reused scratch
  (no CSR+edge list), fuse builds from the unique key vec, packed BDZ2
  streams `g[]` in 4 KiB pages. Wipe-rebuild default range is **2²⁵**
  keys (`RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS=26` still available). Same
  on-disk BDZ2. Live IBD roll-seal uses the same path.

- **`header.head` open-grow is sibling then rename:** undersized single-gen
  rewrite writes `header.head.grow`, fsyncs, then rename over the live file
  (`.mlt` kept). Crash during rewrite leaves the previous OA. A target-sized
  empty gen0 with a non-empty `header.body` / `.mlt` is Layout refuse
  (wipe `header.head`, `header.head.mlt`, `header.body`).
  [`SCHEMA.md`](SCHEMA.md), [`docs/concurrency.md`](docs/concurrency.md).

- **Tip-follow catch-up getdata matches serve cap:** connecting headers
  asked the whole path while a peer reconstructs at most 16 bodies.
  Extra hashes stayed in `requested` and were never re-asked
  (`sync_blocks` 60s overnight: `feature_minchainwork`,
  `rpc_createmultisig`, `feature_bip68_sequence`, …). First ask and
  drain continuation use `MAX_SERVE_BLOCKS`. Accepting a `CmpctBlock`
  (node-to-node `MSG_CMPCT_BLOCK` getdata) also drops the hash from
  `requested` so the next window can be asked. Writer saturating-subs
  `serve_inflight` so unpaired compact tip announce cannot wrap to
  `usize::MAX`. Announce does not occupy reconstruct slots (a burst of
  16 would skip later getdata). Coinbase-only compact fills from
  prefilled txs without a mempool.

- **Nightly Miri installs nightly:** `miri.yml` asked the CodeQL-pinned
  1.95.0 `dtolnay/rust-toolchain` snapshot for `components: miri` (that
  action has no `toolchain` input). First scheduled run died in 9s.
  Nightly + miri is a `rustup` step; product rustc stays 1.95.

- **IBD exits to tip follow at the peer horizon:** leftover off-path
  `getdata` is dropped so catch-up can complete; if peers then advertise
  a higher tip (`lag > 2`), `headers_done` unlatches and `getheaders`
  resumes. Near-tip (`lag ≤ 2`) still does not re-fan.

- **In-flight drop after last load batch of a wave:** lookup snapshots
  `drain_and_fence_hi` before TipOnly and passes it on the last load
  batch. After that batch's in-flight read, load drops map rows with
  pack height below the snapshot (equality keeps). Not Class C tip;
  `class_a_hi` is not a drop gate. Stamp walks the load-thread `InFlight`
  map then skeleton (IBD); leftover TipOnly for plan=None / S0.
  [`docs/invariants.md`](docs/invariants.md),
  [`docs/concurrency.md`](docs/concurrency.md).

- **In-flight is a load-thread map:** one `txid → fk` / `fk → CreatePin`
  HashMap with a height index (not `InFlightLog` layer snapshots). Insert
  after stamp so the current pack is invisible to that stamp. Disconnect
  `drop_from_height` on pack height.

- **Load-batch parent skeleton:** lookup TipOnly-fills `BatchParentIds`
  (fk + body/spent ranges + per-chunk need-vouts) onto each `LoadBatch`.
  Load binds same-batch → in-flight → skeleton → `Corrupt`. Published
  `live_union` / `PublishedIds` are gone. plan=None / S0 still leftover
  TipOnly. Lookup `wave=… spent=` is `tx_spent_range_batch` for those hits.

- **Confirm Class A kind per batch:** a load/write batch is all need-body
  (`plan=Some`) or all already-bodied (`plan=None`). Lookup splits loadq
  at `header_txs.has_body`; write drain stops on plan polarity. Mixed
  stamp is `Corrupt("invariant: confirm batch mixed archived")`. Write
  vs tip is all-old (`Ok([])`), all-new (fill zip), or
  `Corrupt("invariant: write batch spans tip")` — no prefix strip.
  [`docs/invariants.md`](docs/invariants.md),
  [`docs/concurrency.md`](docs/concurrency.md).

- **Pin `merge_outs` no-op Arc:** empty / already-covered `checked`+`live`
  keep the outs Arc (assemble sticky `ptr_eq`). RCU compose borrows `live`
  instead of cloning script bytes on every retry.

- **IBD Class A ins at write:** `confirm_wire_lookup_stamp` plans from
  wire (`archive_plan_batch_from_wire`) without `TxApply`. Packed ins stay
  empty; SpendEdges + CreatePin remain. Write encodes ins from `Arc<Block>`
  + those edges. CreatePin outs stay stamp-time for in-flight.

- **Retire `docs/algo-review.md`:** remaining worth-fixing items are
  **Q-57–Q-60** in [`docs/quality.md`](docs/quality.md) (store publish/flush,
  mempool persist/eviction, RPC/CLI honesty, P2P caps). Inventory, gotchas,
  and micro-opts are not a second backlog.

- **`load_thr stamp=` nest:** `ibd: perf` prints
  `stamp=Nms(pack=Xms head=Yms)`. `head=` is leftover TipOnly
  (`prep_head_fk_ns`). After a lookup wave publishes a parent, load
  stamp leftover for that parent is 0 — pack stays on load.

- **Held tx.head `.rel` pread:** after fail-closed `begin_batch` (`f07415b5`),
  a poisoned leftover ring made `pread_batch_on_ctx` return false and
  `read_rels_batch` opened a second TLS uring — nested panic on
  `ibd-confirm-lookup`. Held failure is now `Corrupt`; `pread_batch` only
  when `IoCtx` has no session.

- **Algo-review S-H1:** HashHead / ScriptHashHead no longer rewrite occupied
  tables while serving. Mainnet `header.head` creates at 2²² slots (~96 MiB
  sparse). Overflow rolls `header.head.gN`. Undersized single-gen files
  rewrite on open. Ingest SH seals at 0.80. `ShardedHashHead`,
  `HeadRole::ScriptHash`, and `rehash_gate` are deleted. Leftover 256-way
  `header.head/` is Layout refuse.
  ([#248](https://github.com/reardencode/rbitcoin/pull/248)).

- **Algo-review P7/P8/P10/P16:** leftover TipOnly fence snapshot is
  `Arc` (COW on extend). Densify assign resumes after the BQ-ready
  prefix. BIP324 v2 decode is command+payload (no sha256d checksum, no
  v1 reframe). Fence-tip BIP113 MTP is an 11-slot ring.
  ([#245](https://github.com/reardencode/rbitcoin/pull/245)).

- **Algo-review P1–P3:** BIP339 wtxid inv is a `TxGraph` map (no mempool
  scan under the lock). Best-chain cumulative work is a RAM prefix
  (~32 B × tip), not a genesis walk per unrequested body / `chainwork`.
  Mempool `worst_chunk` is an ordered cluster-rate index.
  ([#244](https://github.com/reardencode/rbitcoin/pull/244)).

- **BQ assign-stop 1 GiB:** `RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES` no longer
  refuse enqueue. Default 1 GiB densify assign-stop (`0` = unlimited): fill
  holes through the already-fetched height horizon; do not grow past it.
  [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Idx fill windows io_uring SQ:** unique `tx.idx` page preads harvest when
  the session is at in-flight cap (same shape as BDZ / bulk_io). SQ full is
  `BudgetFull`, not `corrupt record`. Lookup retries it at debug, not WARN.

- **RecentCreates layers:** write publishes one Arc layer per Class A batch
  (shared splice with live_union; no full-map clone). Drop when Class A has
  covered `lookup_started_hi` at publish. Stamp carries CreatePin so pin does
  not re-walk the ring. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Headers sync locator:** a full 2000-header reply continues `getheaders`
  from that last hash (not our tip locator). Periodic poll skips a peer
  whose best-known header is already on our chain behind tip, or a
  connecting fork that cannot beat us. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Tip-follow peer set:** disconnect sessions whose connecting header tip
  cannot beat us and is more than 288 blocks behind (BIP-110-class minority
  forks). Stale-tip extras no longer grow past `max_outbound`; at cap a
  random outbound is rotated for a new addrman addr. GetData reconstruct
  queues at most 16 full blocks per session; per-peer `pending_blocks`
  evicts at 128. [`docs/ibd-memory.md`](docs/ibd-memory.md).

- **Cargo.lock compatible bumps:** `bitcoin-consensus-encoding` 1.2.0,
  `cc` 1.4.4, `find-msvc-tools` 0.1.11, `futures-channel` 0.3.34,
  `http-body-util` 0.1.5, `log` 0.4.34, `rand` 0.8.8, `syn` 3.0.4,
  `zerocopy`/`zerocopy-derive` 0.8.56. Direct crates already at latest
  compatible; skipped `bitcoin_hashes` 1.x and `tokio-tungstenite` 0.30
  (axum 0.8 still on 0.29).

- **Two SH methods only:** a durable scripthash head stays Tip (short
  catch-up uses write-behind, leftover runs discarded). No head: Direct
  defers SH; post-IBD Class A recollect + FullCold/ColdResume. Removed the
  IBD memtable→runs worker and WarmOnly apply-onto-live-head (mainnet
  2026-08-25 `fk stream zero delta` on a 12-block catch-up).

- **Tip accept does not wait on scripthash:** Class C publishes `confirmed[]`
  then enqueues collected SH records onto a RAM head; `rbtc-sh-wb` seeds the
  durable index only after tip announce (`release_sh_writebehind`). Wallet SH
  reads join that RAM head at live tip so mempool can drop confirmed txs
  without a hole. Reorg reaccepts into the mempool overlay before dropping
  pending. Headers subscribe stays live tip. `tip: accept` now `sh_lag=`
  and `tweaks=`; worker logs `sh: apply h= wall= lag=`.

- **SH workers follow free RAM:** recollect and k-way materialize default to
  at most **one worker per 1.5 GiB** host free RAM (Linux `MemAvailable`,
  Darwin free+inactive pages, Windows `AvailPhys`; unknown OS → 1 worker).
  Unset env is auto; `RBITCOIN_SH_RECOLLECT_WORKERS` /
  `RBITCOIN_SH_MERGE_WORKERS` still override (`1` = serial). Start logs
  include `free_GiB=`.

### Removed

- **RecentCreates ring and `PipelineParentStore`:** write no longer clones
  a second identity+outs layer list; IBD never used the Weak pin registry.
  `ibd: sizes` `recent=` / `pstore=` stay 0. CreatePin outs live on
  in-flight keep-until and batch-local `BatchParents`.

- **Dead production APIs:** SH catalog materialize is always k-way (no
  fan-in reduce / CHECKPOINT / READY, no `RBITCOIN_SH_MERGE_FANIN` /
  `TARGET_RUN_BYTES` / `MAX_DIRECT_MERGE`). One catalog write policy (no
  L0 / paced IBD / DURABLE alias). Unused Store `*_at` body helpers,
  `header_head_occupied`, `header_body_contains`, `flush_index_tables`,
  `for_each_strong`, `BlockQueue::load_all`. `RBITCOIN_IO=mmap` is no
  longer a silent pread. No-op SH `stop_and_drain_spills` and unused
  `archive_plan_batch_from` / `archive_plan_batch_owned` wrappers.
  Unused `NodeClock::mock_value`, `ChainParams::min_difficulty_target`,
  `outbound_for_ibd`, `InvalidHashSet::{mark_path,is_invalid_fn}`,
  `MempoolHub::mining_frontier_snapshot`, `ConfirmParentCache::get_header_plan_arc`,
  `NodeConfig::with_datadir_cold`.

### Fixed

- **IBD catch-up complete ignores leftover explore/orphan getdata and
  competing `hash_height`:** exit uses connected-path remainder vs peer
  height (one-block version chatter). Empty path with a missing tip+1
  keeps `getheaders` instead of latching `headers_done` two blocks short
  of the horizon.

- **Esplora mempool-only tx JSON includes vin/vout/size/weight:** Class A
  miss uses the mempool wire body (`GET /tx`, `/txs`, `/txs/mempool`, WS
  address-transactions). No more txid+fee stub.

- **Mempool `relay_seq` / `accept_at` drop on unindex:** confirm, RBF, and
  eviction no longer leak per-admit INV maps for the process lifetime.

- **Electrum subscribe status row order matches `get_history`:** confirmed
  height-asc, then mempool tail (no `sort_by_key` on height). Extra
  confirming `blockhash` in the preimage is unchanged (A-B-A).

- **`testmempoolaccept` is dry-run:** `MempoolHub::test_accept` runs
  prepare + scripts + RBF/cluster checks without commit, announce, or
  conflict eviction.

- **RPC `getrpcinfo` active list is id-keyed:** concurrent `dispatch`
  no longer `pop()`s the wrong in-flight command.

- **Headers-sync stall timeout runs in production:** the 50 ms session
  tick calls `PeerHub::on_session_heartbeat` →
  `check_headers_sync_timeouts`.

- **Inbound VERSION/VERACK handshake has a 60 s bound:** timeout is
  `NetError::Timeout` and drops the `max_inbound` permit.

- **Script-pool wave `failed` is Acquire/Release:** a worker cannot enter
  a wave after the publisher observed `in_wave == 0` (ARM).

- **Signet matches Core BIP141 last-commitment + challenge flags:** last
  exact 38-byte `6a24aa21a9ed` output; verify with P2SH, WITNESS, DERSIG,
  NULLDUMMY (not CLEANSTACK / Base-only eval).

- **Assemble checks future-time and BIP34/66/65 nVersion on every block,**
  not only headers-first `validate_header` (pipelined / multi-block confirm).

- **Witness sigops only after segwit:** `GetTransactionSigOpCost` witness
  component is gated on `segwit_active_at` (pre-segwit P2WPKH-shaped prevouts
  no longer add 1).

- **P2SH sigops match Core GetSigOpCount(scriptSig):** opcode `> OP_16` yields 0.

- **Regtest subsidy halves every 150 blocks** (Core `nSubsidyHalvingInterval`).

- **Coinbase (and every tx) with empty vout is rejected:** Core
  `bad-txns-vout-empty`, including the coinbase.

- **Testnet 20-minute min-difficulty:** off-interval headers with
  `time > prev + 2×spacing` use powLimit bits; otherwise walk back to the last
  non-min-diff block (Core `GetNextWorkRequired`).

- **P2SH scriptSig matches Core EvalScript + IsPushOnly:** `OP_1NEGATE` is a
  valid push; scriptSig >10 000 bytes is rejected. Finding 006 520-byte pin kept.

- **BIP342 tapscript validation-weight budget:** script-path CHECKSIG /
  CHECKSIGADD with a non-empty signature subtracts 50 from
  `50 + witness_serialized_size`; remaining `< 0` fails (Core
  `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`).

- **Truncated PUSHDATA2/4 no longer counts leftover opcodes as sigops:**
  `script_sigop_count` stops when the length field or body overruns, matching
  Core `GetOp` / `GetSigOpCount` (`[0x4d, 0xac]` is 0, not 1).

- **SIGINT after `clean exit` no longer waits on peer header walks:** tip-follow
  sessions walked pending headers with a store lookup per step (`knows_header` /
  `header_height`), so a 2000-header stale-fork reply could peg the Tokio
  runtime for ~90s after shutdown logged (mainnet 2026-08-25, `disconnect stale
  fork tip announced=961638`). Walks are RAM-first (one store lookup at the
  join). Shutdown `request_disconnect`s live peers, aborts nested inbound/dial
  sessions, timeout-joins, and the process runtime uses `shutdown_timeout(2s)`.

- **io_uring drain fail-closed:** `drain_all` treats unmatched CQEs and CQ
  overflow as `Corrupt` (no longer ignored). `begin_batch` returns `Err` on a
  poisoned session or leftover that cannot drain. Held idx fill (`fill_idx_pages`)
  propagates that error instead of libc-falling back on a dirty TLS ring (that
  mixed `KIND_BULK_PREAD`/`KIND_IDX` into BDZ g-page harvest as
  `bdz g page bad slot` / leftover CQE). Invariant WARNs fire on every hit with
  `pending=` / `epoch=` / `thread=`. [`docs/concurrency.md`](docs/concurrency.md).

- **Tip `--sptweaks` write-through:** after backfill completes, every tip
  block indexed tweaks on the confirm wall. A pin miss on a *non-P2TR* tx
  failed the whole height into `tweaks_for_height` (Class A + secp). Ineligible
  txs now skip the prevout walk; spend lookup is a map. `tip: accept` shows
  `tweaks=`. Regression:
  `ineligible_external_spend_does_not_fail_the_height`.

- **Held io_uring leftover CQE vs BDZ g-pages:** lookup TipOnly resolve shares one TLS ring across OA probe, idx, sealed MPHF `g` pages, and rel preads. A swallowed `drain_all` left `KIND_BULK_PREAD` in `pending`; the next `stream_g_pages` harvested it as `bdz g page bad slot` and could park on unbounded `submit_and_wait`. `begin_batch` now drains leftover SQEs first; machines match `(kind, epoch, slot)`; undrained/unexpected/wait-timeout poison the session and drop the TLS ring. Caps `submit_and_wait_one` at 5 s.

- **Nightly fuzz vs musl cargo-fuzz:** `taiki-e/install-action`'s
  `cargo-fuzz` is a musl binary, so `cargo fuzz run` defaulted
  `--target x86_64-unknown-linux-musl` and ASan refused
  (`sanitizer is incompatible with statically linked libc`).
  `scripts/fuzz-run.sh` now passes rustc's host triple (gnu on the
  GHA runner).

- **Tapscript initial witness stack ([023](docs/external_findings/023-tapscript-initial-stack-limits.md)):**
  after the BIP342 OP_SUCCESS scan, tapscript now rejects an initial
  stack over 1000 items (`stack size`) and any initial element over 520
  bytes (`PUSH_SIZE`), matching Core `ExecuteWitnessScript`. OP_SUCCESS
  still overrides both. Regression:
  `script_path_rejects_initial_stack_over_max_size`.

## [0.5.1] — 2026-08-22

Workspace version **0.5.1**. Consensus + Electrum serve fixes on the 0.5 line.

### Fixed

- **Script stack size vs altstack ([022](docs/external_findings/022-stack-altstack-share-max-size.md)):**
  `push()` and `OP_TUCK` counted only the main stack against `MAX_STACK_SIZE`.
  Core shares 1000 across **stack + altstack** on every push (including
  `PushBytes`). Combined overflow now rejects (`stack size`). Regression:
  `stack_and_altstack_share_max_size_on_pushdata`.

- **Electrum silent-payment tweak serve:** indexed join is one sequential
  `txout` span per wave (not one body pread per eligible tx). Pre-taproot
  empty Cake maps flush in ≤1024-height waves. `server.ping` does not drop
  an in-flight wave.

### Changed

- **PR CI OS smoke:** `ci.yml` `windows` / `macos` jobs run native store
  platform tests (TableFile, SH free-RAM probe, pool/IOCP session, default
  `RBITCOIN_IO` kind) + `--smoke` on every PR and master push. Operator
  binaries are GitHub Releases only (`release.yml`). Snapshot workflows
  `musl.yml` / `windows.yml` / `macos.yml` and the `static-binaries` label
  are gone.

- **`getnetworkinfo.version`:** `rpc_client_version("0.5.1") == 501`.

- **Release script:** `./scripts/release.sh` on clean `master` checks
  Cargo/nix/CHANGELOG, creates annotated `vX.Y.Z`, and pushes **master
  + the tag** (`release.yml` builds the snapshots). `--dry-run` /
  `--no-push`.

## [0.5.0] — 2026-08-22

First **named published** 0.x line. **Not 1.0.** Schema 19 is still bumpable
(named refuse/wipe, no silent wipe). Default mainnet `--milestone 840000`
skips historical script/sig checks (`--milestone 0` is full scripts).
`--shindex` default off (required for Electrum/Esplora). BIP324 v2-only.
GitHub Release: Linux musl (operator) + Windows CRT-static PE + Darwin
aarch64 binaries + SHA256SUMS (ad-hoc signed, not notarized). In-tree `fuzz/` `block_wire`
nightly job (not a required PR check). P2P DoS is not Core-parity.

### Added

- **Fuzz (Q-30 min):** isolated `fuzz/` workspace, `block_wire` target on
  `check_block_wire` (consensus-encoded block → archive structure). Nightly
  `.github/workflows/fuzz.yml` (not a required PR check). Operator may need
  to push the workflow file.

- **Tag GitHub Release:** `.github/workflows/release.yml` on `v*.*.*` builds
  musl + Windows + Darwin snapshots and attaches them (Linux SBOM included).
  `workflow_dispatch` builds artifacts only. Operator may need to push the
  workflow file.

- **`rbitcoin-bench`:** optional Electrum/Esplora **client** benchmark (not
  default-members, not musl). Casa sequential median (`get_balance` /
  `get_history` / `listunspent`), Sparrow batched subscribe+history, fat-key
  `hot` suite. Embedded `--corpus` lists: `hot` (P2A + public high-tx
  addresses), `casa`/`sparrow` unique scripts sampled from 77 heights
  genesis→tip on a mainnet store (not one 200-block window).
  Stderr progress: 5% steps plus at most one line per 15s, with ETA.
  `--out FILE` writes a per-key CSV (heights, tx/utxo counts, warm
  latencies per query). `--suite clients` runs N concurrent small-wallet
  loads on one OS thread (`--clients`, default 8; corpus default
  `sparrow`; keys over `--max-txs`/`--max-utxos` dropped).
  `cargo run -p rbitcoin-bench --features cli --release`.

- **CI Windows / Darwin snapshots:** after a green `ci` run on
  `master`/`main` (and on `workflow_dispatch`, and on PRs labeled
  `static-binaries`), workflows `windows` and `macos` upload CRT-static
  PE and system-dylib Darwin `rbitcoin-node` / `rbitcoin-cli` +
  `SHA256SUMS` (90 days). Not required checks. `musl` uses the same
  label. Linux musl stays Nix; Darwin/Windows are native runners.

- **`generateblock submit=false`:** mine one block without connecting it
  and return `{hash,hex}` for `submitheader`. `output` accepts `raw()`
  descriptors.

- **`getblockstats`:** reconstruct the block and return Core fee / UTXO /
  weight fields (`hash_or_height`, `stats`). Genesis is excluded from
  actual UTXO counts; `OP_RETURN` is unspendable. Even `medianfee` is the
  integer mean of the two middle scores (Core `CalculateTruncatedMedian`).

- **`docs/errata.md`:** RAM leftover maps are one fk per txid. Pre-BIP30
  clobber is correct enough; post-BIP30 a disconnected sibling in those
  maps is an unlikely visibility hole, not the n−1 leftover miss.

- **`getmempoolcluster`:** cluster weight, tx count, and mining chunks
  (modified fees) from the live graph.
- **Test RPC proxy** (Core functional suite only): utility RPCs
  (`createrawtransaction`, `signrawtransactionwithkey`, `createmultisig`,
  `combinerawtransaction`, decode helpers) and an Esplora-backed wallet
  façade (`createwallet`, `importdescriptors`, `send`, `listunspent`, …)
  live in the bitcoind shim, not on `rbitcoin-node`.
- **Mempool verbose fees:** `getrawmempool` / `getmempoolentry` emit
  `fees.{base,modified,ancestor,descendant,chunk}` and `chunkweight`.
  `prioritisetransaction` deltas flow into modified/ancestor/descendant/chunk
  and into min-relay admission (free tx + delta can enter).

- **Core `-testactivationheight` overlay:** `name@height` (regtest) is parsed
  on `rbitcoin-node` and applied in `ChainParams` (`csv` / `segwit` / `bip34`
  / `dersig` / `cltv`). Script flags still follow the getters in a later
  confirm step. Shim forwards consensus/mempool/peer flags
  (`whitelist`, `blocksonly`, `minrelaytxfee`, `permitbaremultisig`,
  `limitcluster*`, `peertimeout`, `maxconnections`, `persistmempool`,
  `minimumchainwork`) instead of dropping them. `-minimumchainwork` keeps
  the node in IBD (no relay) until tip work meets the hex floor. There is
  no `-txindex` flag: Class A always looks up by txid. Core v31.1
  ancestor/descendant limit flags stay ignored (they are no-ops there).

- **Core functional coverage:** analog scenarios for `--milestone` skip-below /
  check-above, reconstruct after lost RAM head, and durable mempool reopen
  (`crates/rbitcoin-test/tests/core_analogs.rs`). Inventory `analog=` is
  required on `rpc-missing` as well as prune / LevelDB / UTXO-set skips.

- **MiniWallet + receive-block path:** `generatetodescriptor` (`raw(HEX)`),
  `scantxoutset` over Class A, `gettxout`, `getindexinfo` (Class A tx
  lookup), `getchaintips` (active tip), `waitforblock*`. Generate includes
  mempool txs then `remove_for_block`. `sendrawtransaction` maps accept
  rejects to Core `-26` strings. `submitblock` and P2P `block` share
  `ChainHub::accept_received_block` (hold never-confirmed side bodies,
  `accept_branch` on more work). Once-confirmed losers stay in Class A.
  Not a coins-DB / GBT product.

- **Core functional `run` set:** 14 unmodified scripts (first-green nine plus
  `rpc_getchaintips.py`, `rpc_invalidateblock.py`, `rpc_preciousblock.py`,
  `feature_csv_activation.py`, `feature_bip68_sequence.py`).
  `feature_nulldummy.py` is run (stateless raw-tx + ignored `-addresstype`).

- **`echo` + mixed `{args, argN}`:** Core testing RPC and AuthServiceProxy
  mixed named+positional. Inventory marks `rpc_named_arguments.py` `run`.

- **rbitcoin 199-block cache:** `create_cache.py` mines 199 via `generate`
  into `scripts/core-functional/cache/store`. `run.sh` preseeds empty Core
  `blocks/`+`chainstate/` and `--keepcache`; the shim copies our store into
  cache-shaped dests only.

- **`invalidateblock` / `reconsiderblock` / `preciousblock`:** disconnect
  via `ChainHub`; reconsider reconstructs from Class A; precious prefers
  an equal-work sibling (held or archive).

- **Debug.log mapper:** `scripts/core-functional/debuglog_map.toml` plus
  shim line pump. First extra Core script: `rpc_uptime.py` (setmocktime
  range + uptime ignores mock).

- **Regtest `setmocktime`:** `NodeClock` (AtomicI64; `0` = wall). Generate
  timestamps and future-header checks honor the mock. Not a process
  `time()` hook (log stamps stay wall).

- **Live `getpeerinfo` / `addnode` / `disconnectnode` / `addconnection`:**
  sessions register after BIP324 handshake. `addnode onetry` dials via the
  same outbound path as tip-follow. `subver` is the peer's version UA
  (our `-uacomment` is advertised on our `version`). `bytesrecv_per_msg.pong`
  is counted so Core `connect_nodes` can wait for handshake.

- **`syncwithvalidationinterfacequeue`:** no-op `null`. Core’s framework
  calls it from `sync_mempools`; we have no wallet/index callback queue.

- **First unmodified Core functional scripts:** inventory marks
  `feature_help.py` and `feature_uacomment.py` `run`.
  `scripts/core-functional/run.sh` invokes those two via Core’s
  `test_runner.py` (still never from default `cargo test`).

- **Regtest generate / submitblock (harness only):** `generatetoaddress`,
  `generateblock`, `generate`, and `submitblock` mine or accept through
  `ChainHub::accept_block` (same confirm path as P2P). Refused on mainnet /
  signet / testnet. Not a mining product (no GBT).

- **Core v31.1 submodule is the JSON source:** `third_party/bitcoin` is a
  shallow gitlink at `9be056a`. `cargo test` hard-links or copies
  `script_tests.json` / `tx_valid.json` / `tx_invalid.json` from
  `src/test/data` into `$CARGO_TARGET_DIR/core-data` every run (no in-tree
  copies). Missing pin: the fixture helper and `scripts/coverage.sh` run
  `./scripts/core-functional/init-submodule.sh` (sparse ~16 MiB).
  `sync-core-fixtures.sh --check` requires the three files in the submodule
  and none under `tests/fixtures/`.

- **Local extras after the v31.1 pin:** rust units for CHECKSIGVERIFY /
  CHECKMULTISIGVERIFY then `OP_1` (VERIFY must abort), empty-stack CLTV,
  and CLTV/CSV `0x80` (scriptnum −0) not taking the negative branch.

- **Core functional nightly job:** `.github/workflows/core-functional.yml`
  runs `scripts/core-functional/nightly.sh` on cron, `workflow_dispatch`,
  and PRs labeled `core-functional`. Unlabeled PRs keep cargo gates only.
  The job warns — does not fail — when a newer final Bitcoin Core release
  exists than `inventory.toml` `pin` (semver of published finals, not
  GitHub `/releases/latest`). Bump the submodule, fixtures, and inventory
  when it fires.

- **Core functional bitcoind shim:** `scripts/core-functional/bitcoind`
  starts `rbitcoin-node` from TestNode argv (`-datadir` → `DIR/regtest`
  so the cookie is `{datadir}/regtest/.cookie`). Clean chain:
  `getblockcount` is 0; RPC `stop` shuts down. Not the operator CLI.

- **Core functional runner:** `scripts/core-functional/run.sh` invokes Core
  `test_runner.py` only for inventory `run` names (`--v2transport`,
  `--exclude` every skip). A skip name fails `not in run set`. `--list` /
  `--dry-run` need no node. Default `cargo test` does not call it.

- **Core functional inventory (v31.1):** `scripts/core-functional/inventory.toml`
  classifies every Bitcoin Core `test/functional/*.py` (`run` / `skip` +
  reason; `analog` required for prune / LevelDB / UTXO-set skips).
  `python3 scripts/core-functional/check_inventory.py` fails on an unknown
  or incomplete row. See [`docs/core-functional.md`](docs/core-functional.md).
  No Core scripts run in default `cargo test` yet.

- **`--datadir-cold PATH`:** Class A `inwit.body` / `inwit.idx/` (cold; ~486 GiB
  on mainnet) live under `{PATH}/store` when set. `--datadir` still holds every
  other file (`txout`, `spent`, heads, mempool, peers, cookie). Omit the flag
  and both hot and cold files stay in `--datadir`. Conf: `datadir-cold=`.
  Existing split: move `inwit.body` + `inwit.idx/` yourself; the hot store
  records `inwit.reloc` so a later open without the flag refuses.

- **CI musl artifacts:** after a green `ci` run on `master`/`main`, workflow
  `musl` builds `nix build .#rbitcoin-musl` and uploads
  `rbitcoin-node` / `rbitcoin-cli` + `SHA256SUMS` (90 days). Not a required
  PR check. Manual retry: Actions → musl → Run workflow.

- **IBD write meters:** `tweaks=` on `ibd: perf` / `perf_dbg` and `confirm write slow`
  (BIP-352 index wall after spend annotate). Makes the `--sptweaks` write-thread
  cost visible in the fat-era IBD hole.

- **`--sptweaks`:** optional thin BIP-352 index (`sp_tweaks.idx` / `.body`).
  Persist is `len:tweak` only (0 or 33-byte compressed `A_tweak`). Cake outs
  join `txout`. Confirm appends; reorg truncates; background backfill.
  Electrum still serves naive when the flag is off or a height is a hole.


### Changed

- **0.5 operator voice:** README / SECURITY / experimental-mainnet treat
  **0.5.x** as the named published 0.x line (not 1.0, not a soak badge).
  Default milestone skip, `--shindex` off, and schema refuse/wipe stay
  unmissable. Workspace version **0.5.0**.

- **`getnetworkinfo.version`:** pin `rpc_client_version("0.5.0") == 500`
  (`major*10000+minor*100+patch`, same as `0.1.0` → `100`).

- **Core functional inventory:** skip reason `rpc-dialect` for COMPAT-done
  methods whose unmodified script still fails on type-check / field zoo.
  `rpc-missing` is only “method not implemented.” Analog required.

- **Schema upgrade one-pager:** [`OPERATOR.md`](OPERATOR.md#schema-upgrade)
  copy-paste for 17 populated `tx.head` / `scripthash*` (wipe those dirs, keep
  Class A), 18→19 `meta` rewrite, and kill-9 → crash-recovery. Byte layout
  stays [`SCHEMA.md`](SCHEMA.md).

- **RPC docs:** permanent gaps no longer call GBT a non-goal. Template RPC is
  the cluster-chunk selector (no stratum / testdummy); `generate*` stays
  regtest harness. Matches [`COMPAT.md`](COMPAT.md).

- **SH materialize resume:** [`OPERATOR.md`](OPERATOR.md) `--shindex` section
  documents abort/resume: keep `scripthash.runs`, sealed shards stay, restart
  packs unsealed shards only. Not a schema bump.

- **SH decode-into + drop ShEntry:** page/slab decode appends into a caller
  `Vec<Fk>`. Collect, tip pack, and `put_chain` work on `Fk`. Query history
  uses `create_fks`. `ShEntry` / `ScriptHashEntry` are gone. On-disk pack8 /
  slab / page bytes are unchanged.

- **SH pack write-behind:** sequential slabs append to a 16 MiB session
  `body_buf` (one `pwrite` per flush; HWM persist at shard seal). Slab and
  page encode write into a caller buffer; 1-FK keys stay head-only with no
  heap collect; megakey pages encode the delta stream once. `recs` hold
  `u64` pack8 through `MphfHead::write_pack8`. Stage timers
  (`merge`/`pack`/`mphf`/`body_flush`) are disjoint; pack-only
  `head_fill_ns` is 0. On-disk pack8 / slab / page bytes are unchanged.

- **SH recollect / tip materialize:** catalog spill writes outside `runs_io`,
  a bounded writer queue overlaps Class A scan with catalog fsync, pack
  reuses one FK scratch, and BDZ peel uses CSR adjacency (same `BdzMphf::build`
  for SH and `tx.head`). Stage timers (`merge`/`pack`/`mphf`/`body_flush`)
  are real. Catalog and SH head bytes are unchanged.
  `RBITCOIN_SH_RECOLLECT_SPILL_BYTES` overrides the 128 MiB default
  (16–512 MiB).

- **Quality reaudit (2026-08-21).** [`docs/quality.md`](docs/quality.md)
  refreshed against #177: schema **19**, Core functional **44/267**,
  confirm no-coord / park / head-drain and SH last-page extent called
  Completed. Open ranking unchanged (Q-30 fuzz still rank 1). Won't-fix
  adds headerless SH interiors, script coordinators, flattening uring
  machines, process pin FIFO, and `rbitcoin-bench` in required CI.

- **Quality cheap wins:** confirm queue owner docs match **14/4/14**.
  **Q-34** first hour is [`OPERATOR.md`](OPERATOR.md) (regtest mine →
  Electrum → Esplora). **Q-36** default INFO is `ibd: progress`;
  `ibd: perf` / `ibd: sizes` are DEBUG. **Q-50** closed (named `other=`
  residual). Inline tests moved out of `peer.rs` / `methods.rs` /
  `scripthash.rs`. Dead `ConfirmEvent::BodyMissing` removed.

- **tx.head drain thread:** confirm write-behind insert runs on a process-wide
  `ibd-confirm-head` OS thread overlapping structural + Class C, instead of a
  per-batch `thread::scope` spawn.

- **Script coordinators removed:** `ibd-confirm` publishes script waves itself
  (lock-free `next` / `in_wave` / `failed`), writes completed batches in
  height order, and feeds `scriptq` when steal is empty (up to 4 in-flight).
  A script reject finishes leftover inflight heights without write and keeps
  taking `scriptq` (cancel still stops); start-fail keeps the batch meta.
  `SCRIPT_NS` is publish → first complete (not write-queue pop). Steal
  workers unpark the publisher on wave complete; load unparks on `scriptq`
  send. No `rbtc-script-coord-*` threads.

- **Query-path `api:` / `sh_join` / tweaks timing are TRACE:** one line per
  Electrum/Esplora/RPC call (and per slow SH join) flooded DEBUG during
  wallet/bench load. `--api-log` JSONL is unchanged. Connect/disconnect
  stay INFO.

- **Serve lean (Electrum / Esplora / RPC):** block txids, merkle proofs, and
  `getblock` verbosity 1 read `txid.body` (no packed `txout`). Esplora `/txs`
  uses SH join fks. `/utxo` matches Electrum mempool listunspent. History
  `to_height` skips Class A expand for later creates. Parent prevouts are
  outs-only. Electrum scripthash subscribe restatuses on confirming tip
  when the block creates or spends that hash (posting-list probe).

- **Esplora `/utxo`:** status comes from the SH join height plus unique
  headers (`block_hash` / `block_time`). No per-coin `tx.head` or
  Class A `get`. Balance / `/address` stats skip `txid.body`; listunspent
  loads create identity for unspent creates only. `sh_join` debug adds
  `need=`.

- **Electrum fat-SH join:** `listunspent` identity is unspent-only. Tip
  subscribe no longer full-joins every subscribed hash on each block.
  Each TCP connection reuses the last scripthash outs+spent join until
  tip height changes (`get_balance` → `get_history` → `listunspent`).
  Packed `txout` expand is unchanged (no schema bump). Re-run Casa on
  the operator host; do not treat VM times as product numbers.

- **Esplora fat-SH join:** REST reuses one last-scripthash outs+spent join
  until tip height changes (`/scripthash` stats + mempool_stats, `/txs`
  pages, `/utxo`). WS `block-transactions` probes the posting list against
  the new block instead of a full history window.

- **Per-item `received getdata for: wtx` is TRACE:** one line per peer
  `MSG_WTX` getdata is too noisy at DEBUG. Counts stay on `tip: perf`.
  Core functional still sees the needle: the bitcoind shim maps
  `-loglevel=trace` (TestNode always passes it) to `--log-level trace`.

- **`tx.head` shards by create count:** live OA rolls at 80% of slots
  (~26.8 M at 25-bit); wipe-rebuild ranges are `2^bits` (default 2²⁶).
  Idx `RBITCOIN_TX_IDX_SOFT_SPAN` (16 GiB) no longer cuts head shards.
  `.rel` stays `n×4` 1-based relative to `first_fk` in `tx.head/meta`.

- **Sealed MPHF `g` is FdOnly:** `Store::open` no longer copies BDZ
  graphs into process heap (~4.92 B/key). Lookup streams unique 4 KiB
  `g` pages on the held uring session (`KIND_MPHF_G`), same shape as
  open `tx.head` OA page probes. Fuse8 fingerprints stay in RAM (~9
  bits/key). `ibd: sizes` adds `mphf_g=` (0 after open).

- **Tip-follow INV tick:** `queue_due_tx_invs` no longer `list_live()`
  (clone every mempool body + `compute_wtxid`) on the 50 ms session
  poll. Idle ticks return after a cheap due-check; flushes walk stored
  graph wtxids.

- **`--sptweaks` backfill:** one-core completion machine (`txout`, then
  `inwit`/parents only for P2TR) and batched height-blob + idx writes.
  Mainnet origin→tip on SSD is typically **about 1–2 hours** (was several
  hours at ~15–25 h/s serial `get_tx_full`). INFO every 10 s:
  `sptweaks: backfill next=… tip=… rate=…/s remain=…`.

- **`--sptweaks` backfill CPU:** `tweak_from_tx` runs on idle
  `rbtc-scripts-*` steal workers (`try_for_each_parallel_idle`). Block
  script waves and mempool `run_detached_join` still take the pool
  first. The uring load machine stays one-core.

- **`sp_tweaks` roll at u32 start:** a height blob may extend past 4 GiB
  as long as its idx **start** fits in `u32`. `put_blocks` rolls a new
  `NNNNNN` pair when the next start would overflow (including mid-batch)
  instead of `Corrupt("sp_tweaks body exceeds u32 off")`.

- **SH tip materialize is sliced k-way:** one worker per CPU core
  (clamped to shard count) k-way-merges one prefix shard's catalog
  slices with a loser tree of stable 256 KiB double-buffered cursors.
  Dir-variant `scripthash.body/NN` + `scripthash.ovf/body` (schema 17
  orientation, not a version bump): workers write the shard file
  directly; publisher only seals `scripthash.head/NN` in order so
  `scripthash.cold_progress` (`SHCOLDP1`) is still a prefix HWM.
  Legacy file `scripthash.body` stays one writer (`workers=1` for pack).
  No temp `pack*.body`. No extra 64-file catalog pass.
  `RBITCOIN_SH_MERGE_WORKERS=1` stays the serial oracle.
  Status is a 10 s observer of global pack/seal counters
  (`keys` / `creates` / unpublished `pending` / `shards` sealed /
  `rate`) rather than a per-worker session log.
  On the dir variant each pack worker seals its own `head/NN` (no
  ordered publisher). SIGINT keeps sealed holes; resume packs only
  unsealed shards. Shared file body stays prefix `SHCOLDP1`. Pack
  threads use default IO priority — tip materialize is the work.
  Pack streams `head/NN.part` (no in-RAM rec vec). Class A recollect
  walks `txout` fk-spans, not per-fk get. Seal progress uses observer
  atomics (not `entry_count()`). Sealed-main lookup is per-shard
  `RwLock` (not one process mutex). k-way merge submits 256 KiB ahead
  pages on the pack thread's TLS completion session (`io_uring` /
  process-shared `pool` / IOCP) and waits only if that page is still
  inflight at promote; `RBITCOIN_IO=pread` stays blocking.
  Bulk pack picks slab class from the ULEB payload size (not `n×8`
  geometric cap) and carves 4 KiB page-align gaps onto the relocating
  freelist so later slabs fill the hole.

- **Load stamp reuses lookup `TxPrecompute`:** `LoadBatch` carries the
  decode-time `pres` Arc; `confirm_wire_lookup_stamp` must not `from_tx`
  again (`stamp_sub struct_txid=` is 0 on IBD). BQ is not a decoded stash
  after `take_raw`.

- **Confirm queue caps:** `loadq=14` · `scriptq=4` · `writeq=14`
  (was loadq=8 · writeq=20).

- **Core functional Wave E / thin leftovers.** Official unmodified
  `p2p_getdata.py` is `run` (37→**38**). Invalid GETDATA inv type 0
  does not stall the session; a later MSG_BLOCK getdata of the tip
  is served. `p2p_invalid_block.py` stays skip at `--v1transport`
  magic-bytes mismatch (`:44`). `feature_chain_tiebreaks.py` stays
  skip at missing-parent B7 getdata (`:86`). `mempool_accept.py`
  stays skip at `testmempoolaccept` type-check dialect (`:98`)
  after `getmempoolinfo.permitbaremultisig` and `incrementalrelayfee`
  match Core. Q-41 is 38/267.

- **Lookup→load queue:** explicit `loadq=8` of load-sized batches.
  Lookup walks BQ in height order, dequeues raw on emit, and parks
  decoded `Block`+pres on the queue. Densify skips `H <= lookup_taken_hi`.
  RecentCreates horizon is EWMA(`lookup_taken_hi − tip`)+25% (floor 32,
  cap 32×144). `ibd: sizes` keeps `union=` / `h2h=` / `fence=` /
  `recent= live=/pub=/ov= fifo=` and adds loadq wire to `accounted`.
  `ready=` / `bq_dec=` are no longer queue tokens.

- **v2-only peer discovery (Q-49):** DNS queries `x809.<seed>`
  (`NETWORK|WITNESS|P2P_V2`) before the unfiltered name; learned
  `addr`/`addrv2` requires `P2P_V2`; dial ranking omits known-v1
  (`INCOMPATIBLE`) while any better candidate remains.

- **Core functional leftover-P2P follow-up.** Official unmodified
  `p2p_compactblocks_blocksonly.py` and `p2p_blocksonly.py` are `run`
  (35→**37**). `-blocksonly`
  does not select HB; it getdata's `MSG_WITNESS_BLOCK` while relay
  peers getdata `MSG_CMPCT_BLOCK` after `sendcmpct` v2. Handshake
  advertises BIP155 `sendaddrv2` before verack. Low-work header
  announces log Core `Ignoring low-work chain (height=N)` /
  `Synchronizing blockheaders, height: N` (pending-path height, not
  one-header-from-genesis); non-noban does not persist a low-work
  headers tree; noban stores headers-only. INV of a known fork header
  may getdata missing bodies on that path. `p2p_headers_sync_with_minchainwork.py`
  stays skip at the ~2032-block `generatetoaddress` 120s timeout
  (`:112`). `p2p_invalid_messages.py` stays skip at empty addrv2 Core
  logs (`:203`). `p2p_unrequested_blocks.py` stays skip at
  wait_for_disconnect on an immature-coinbase fork (`:275`). Known-header
  INV does not getdata (sendheaders `inv_node`). `-blocksonly` reports
  `localrelay=false`, disconnects P2P txs/tx-invs, and exposes
  `relaytxes`; RPC sendraw is still accepted and INVs inbound peers.
  `getpeerinfo.permissions` exposes whitelist `relay`. `testmempoolaccept`
  rolls back admits while relay is off so sendraw can note unbroadcast.
  Inbound + relay-on keeps the 30s INV/GetData gate on a brand-new sendraw
  after a mocktime jump (`mempool_reorg.py:122`). Q-41 is 37/267.

- **Lookup wave intake + write drain:** `wave_intake` classifies raw vs
  promoted heights with **no payload clone**; decode pulls `raw_payload`
  per height. Peer offer copies wire **before** the BQ lock.
  `lookup_thr wave=` nests `head=` (TipOnly `get_fk_by_txid_batch`);
  `lookup_sub head=` is that token, not load stamp. Collect sets use
  `TxidHasher`. Write merges at most **¼ of writeq** (5 of 20) so scripts
  keep empty slots; RecentCreates expire once per write. Pstore
  `size_snapshot` is insert/gc counters (no slot walk); pin names `thin=`.
  Restart leftover is still empty RAM identity (not a horizon miss).

- **Confirm pack / leftover / lookup meters:** load waits on `feed.cv` when
  tip+1 is ready but BQ resolve is incomplete (no retain+BQ spin). Write
  notes RecentCreates **per prepared height**; published identity layers
  stay while `tip − hi < 2×soft_win` after the span leaves the BQ.
  In-flight / pstore `size_snapshot` is O(1) occupancy (no per-pack pin
  script walk). Lookup wave names `decode=` / `precompute=` / `collect=`
  under `lookup_thr wave=`. BQ keeps a height→id map; load pack takes
  one feed collect, one `block_queue_pack_snapshot`, one inflight mark
  (stored hash vs feed; no happy-path `block.block_hash()`). Script
  steal is unchanged — decode stays on the lookup thread.

- **Docs remotes + lookup:** `origin` fetch is HTTPS, `pushurl` is SSH
  (`AGENTS.md`). `OPERATOR.md` lookup row includes the hard min 8000
  inputs. Living pointers use `block/mod.rs` / `structure_rule_tests.rs`.

- **Lookup wave min 8000 inputs:** do not publish a TipOnly layer under
  8000 Σ `tx.input` when more unresolved BQ heights can still join,
  including `ready=0` / load-frontier / unknown window. Last available
  thin wave still emits. Max remains 64000 inputs / 1080 blocks.

- **Core functional leftover-P2P.** Official unmodified
  `p2p_initial_headers_sync.py` and `p2p_compactblocks.py` are `run`
  (33→**35**). Initial `getheaders` goes to one `NODE_NETWORK` peer
  until the tip is within 24h; each new block INV may add one extra
  peer; headers-download timeout disconnects a stalling peer unless
  whitelist `noban`. BIP152: tip INV is `MSG_BLOCK`; `sendcmpct(1)`
  announces `cmpctblock`; getdata type 4; getblocktxn depth 10;
  compact getdata depth 5; OOB getblocktxn disconnects; HB max 3
  with 2 inbound + 1 outbound fill slots; cached-invalid child
  compact is `bad-prevblk`; a second failed `blocktxn` disconnects.
  v2 length-prefix reject logs `V2 transport error: packet too large`
  and disconnects; unknown short/long type logs and stays connected
  (`*other*` raw size). `getnettotals` counts raw TCP when a session
  has `WireBytes`. `p2p_invalid_messages.py` stays skip at inbound
  `sendaddrv2` (`:188`). Q-41 is 35/267.

- **Script steal claim + join:** `rbtc-scripts-*` claim a published
  wave snapshot (`ArcSwap`) instead of locking `WAVES` per job;
  steal is **32-wide chunks** (`in_wave` = in-flight chunks, AcqRel).
  After feed-ahead submits N+1, scripts join blocks instead of
  `recv_timeout(200µs)` for the rest of N. `script=` is still
  verify/`wait_done` wall, not the poller.

- **Confirm structure one-pass + lookup stash:** `TxPrecompute::from_tx`
  (txid + wtxid + weight + BIP143/BIP341 common SHA256 midstates) lives
  on Query. Lookup decodes each BQ height once, promotes to decoded-only
  (drops raw; `bytes()` keeps `max(payload, decoded)` charge; one mutex
  per wave), and load pack / structure reuse `Arc<Block>` + pres.
  Script jobs carry that pres (no job `from_tx` / `finish_spent`;
  WitnessV0 does not rehash per CHECKSIG). `SighashCache` is lazy
  (P2WPKH does not construct one). Stamp loads published/recent once
  per pack (`TxidHasher` on remaining txid maps); lookup keep uses a
  height `BTreeSet` (`range`, not `lo..=hi` / `list_meta`). Assemble
  confirmed-parent skips `validate_header` after the MTP walk; one
  `pending_spent` set; assemble clocks flush once per block.
  `ibd: sizes` adds `bq_dec=`. BIP143 P2WPKH/P2WSH / interpreter consume
  those midstates. `stamp_sub` adds `struct_txid=` / `struct_walk=`.
  rust-bitcoin remains the test oracle. Taproot still uses `SighashCache`.

- **Assemble meters and maps:** prevout path counts flush once per block
  (no per-input `Instant` / atomics). Same-block outs use `txid_index`
  (`TxidHasher`); pack `pending_creates` is `txid → fk`. `ibd: perf`
  assemble tokens stay; `us/in` is still `ASM_PREVOUT_NS / ASM_IN_N`.

- **Core functional field leftovers.** Official `rpc_net.py` stays
  skip: dual-connect `getconnectioncount` now counts inbound+outbound
  PeerHub sessions; `getpeerinfo` emits `last_block` /
  `last_transaction` / `minfeefilter`; `addnode` is `manual`; nodes
  send/record BIP133 `feefilter`; `getblockchaininfo` has tip `time`
  and `mediantime`. First remaining official fail is pre-version
  `getpeerinfo` (`rpc_net.py:138` — v1 magic / v2 `wait_for_new_peer`).
  Inventory still **33 run**. Q-41 table matches 33/267.

- **Store IoCtx:** head-resolve / identity / idx page fill share one
  `IoCtx` (`held` session or standalone). Crate-private
  `probe_candidates_batch_{open,sealed_hot,cold}_on_session` twins are
  one `probe_candidates_batch_wave`. Machines still hold TLS; nested
  `with_thread_local` still panics. Public `*_on_session` wrappers remain.

- **IBD write sample nest:** `IbdPerfSample.write` is a `WriteStageSample`
  of the eight inventory tokens (`class_a+ensure+struct+class_c+sh+spend+tweaks+tip_gc`).
  `write=` still equals `write_stage_ms`. INFO/DEBUG token strings unchanged.

- **Recent-create identity ring:** write publishes `txid → (create_fk,
  body_range)` after Class A + idx. Load stamp probes it after published
  live-union and before leftover TipOnly. Height-FIFO expire is
  `2 × soft_confirm_window` (floor 256). Identity only — no outs / not a
  process pin FIFO. `ibd: perf` adds `recent=` / `recent_ms=`; `ibd: sizes`
  adds `recent=Nh/Nk≈NMiB`.

- **Stamp identity union:** load/plan stamp no longer accepts a BQ-ahead
  hits map. Facts come from in-flight → published `live_union` →
  recent-creates → TipOnly.
  Deleted `BqParentHits` and `confirm_wire_lookup_stamp_with_hits`.
  Pin denserels read only `ParentPinStamp` (no `plan.external_parent_*`
  fallback). S0 plan and plan=None rehydrate share
  `stamp_external_parents` (query). `archive_plan_batch_from_store` no
  longer takes a parent-store argument — pstore is outs, not create_fk.

- **Core functional Wave D leftovers.** Official unmodified
  `interface_rpc.py` and `mempool_reorg.py` are now `run` (33 inventory
  run names). HTTP JSON-RPC 2.0 batch, notifications (204), and
  version/HTTP status dialect match Core v31.1. `getnettotals` sums live
  peer byte counters. Mempool GetData follows Core `info_for_relay`
  (entry sequence < last INV); reorg-reaccept uses sequence 0 so
  disconnected-block txs are servable without INV, and a later regular
  submit of the same wtxid is `notfound` until announced.

- **`ibd: perf` load/script tokens:** `load=` is pin+assemble only.
  `load_thr pack/stamp/pin/asm/prune` is the load OS thread (leftover
  TipOnly is `stamp=`; in-flight drop after scriptq is `prune=`). `script=`
  is verify ns (`jobs=`/`skip=`), not submit-to-join. `lookup_thr keep=`
  times live-union splice.

- **Store completion session:** `IoSession` backends — Linux `io_uring`
  (default), portable `RBITCOIN_IO=pool` (Darwin default), Windows IOCP.
  Spend-annotate, head-resolve, and bulk fill stay multi-stage machines.
  kqueue / POSIX AIO / `dispatch_io` are not file SQ/CQ rings.
  `RBITCOIN_IO=pread` still disables the session.

- **Confirm parent identity:** lookup prepends one `IdLayer` per resolve
  wave (`lo..=hi`) and `Arc`-bumps the chain head (`PublishedIds`). Get
  walks the chain (txid identity hasher; no union `reindex`). Drop is
  splice when no height in the span remains on the BQ. While `ready` is
  over half the 1-min BQ window, lookup holds short waves so it does not
  mint one layer per newly fetched block, unless the first unresolved
  height is in the load-facing half of that window (O(1) vs `path_lo`). Disconnect stores `None`
  immediately. `pin_txid=` counts published-union hits. IBD lookup
  TipOnly-resolves up to **64000** inputs (include-overshoot) or **1080**
  blocks per wave (8× load's 8000-input cap; ~1 week of 10-minute blocks).

- **Head resolve identity:** each probe wave fills `txid.body` in two shots
  (first four cands, then the rest if still unfinished). A connected win
  skips the tail. Sealed-hot probes only unfinished keys, same mask as cold.

- **Confirm pin outs:** `ArchiveWritePlan.external_parent_outs` and
  `ensure_external_parent_denserels_from_plan` are gone. IBD pin is
  `pin_for_wire_batch` (in-flight / same-batch / pstore adopt / cold
  range). Plan keeps ranges+txids until `freeze_after_pin`.

- **One SH durable dialect.** Incremental creates go to ingest OA (then
  sealed `SHSR` ovf). Live OA main / `ShOverflowStack` writes are gone.
  Leftover OA at `scripthash.head` or non-`SHSR` `ovf/NNNNNN` refuses
  open — wipe `store/scripthash*` and restart with `--shindex`.

- **`getblockchaininfo` disk / progress:** `size_on_disk` is a walk of
  store file lengths (plus cold inwit when split). `verificationprogress`
  is `blocks / headers` (1.0 when headers is 0), not a dummy 0.5 / 1.0.

- **No soak program.** Signet-first remains ordinary run advice. Q-35 is
  won't-fix. Docs no longer title a gated “soak” checklist.

- **SH on/off:** COMPAT and README point at the OPERATOR cost table.
  Disable-after-on leaves SH files on disk; tip follow stays up.

- **Electrum `electrs` UA + versions:** COMPAT documents why
  `server.version[0]` contains `electrs` (Cake `getNodeIsElectrs()`).
  README no longer hardcodes `0.1.0`; shipped strings stay
  `workspace.package.version`.

- **Quality:** **Q-47** closed (honest chaininfo). **Q-48** is BIP331 when
  rust-bitcoin grows the types — no private `rbtpkg` stand-in.

- **COMPAT GBT:** template RPCs (`getblocktemplate` / `getmininginfo` /
  `prioritisetransaction`) are shipped. COMPAT no longer lists GBT as
  never. Stratum / wallet keys stay non-goals.

- **Head resolve is three waves, no rank rounds.** Probe+identity is
  open, then sealed ages 1..=3, then sealed age ≥4. Each wave fills
  `txid.body` in two shots (first four cands, then the rest if still
  unfinished) and walks newest-first (fence-connected wins). Sealed-hot
  and cold probe only unfinished keys. Unconnected identity still
  continues to later waves. TipOnly still strips unconnected at the end.

- **Leftover probe dump.** A leftover miss (load leftover, not lookup /
  BQ-ahead TipOnly) logs hop + every cand (`txid.body` prefix, match,
  rel/abs fk) once. The reject line adds `diag=1`.

- **Quality reaudit (2026-08-17).** [`docs/quality.md`](docs/quality.md)
  Open list re-ranked. Q-37 (suite ≤3 min) closed on CI `test` ~85 s.
  Won't-fix: CODEOWNERS, crates.io publish, rustdoc site, structured
  logs, tier-C in default CI. New: honest chaininfo disk/progress
  (**Q-47**), BIP331 rust-bitcoin types (**Q-48**), v2 peer discovery
  (**Q-49**).

- **Withdrawn: open `tx.head` page seqlock (#82 / #84).** Leftover misses
  are old parent txids with a long hop of cands (`miss_on=body`, ~25–34).
  A torn old/new page still holds those occupants; seqlock cannot explain
  that miss. The 250 ms odd-page `Corrupt` aborted lookup waves and dumped
  more work onto leftover. Per-page `AtomicU32`s are gone; insert is again
  sole-writer page-coalesced `pwrite`.

- **Tests assert behavior, not the repo.** Default-suite tests no longer
  `include_str!` production sources or `CONTRIBUTING.md` to grep
  identifiers. Query open leftover-strong repair is pinned by
  `Query::open_or_create` reopen. CONTRIBUTING principle 8.

- **Documentation map.** [`docs/README.md`](docs/README.md) is the only
  index (one audience, one start file; one fact, one owner). Coverage
  policy lives in `TESTING.md`. Schema 17 freeze tables live in
  `SCHEMA.md`. Confirm start states live in `docs/invariants.md`.
  Most-work reorg rules live in `docs/architecture.md`. `AGENTS.md` is
  the slim harness contract. Removed `COVERAGE.md`,
  `docs/store-format.md`, `docs/startup-states.md`,
  `docs/design-ibd-most-work-reorg.md`, and `docs/future-features/`.

- **Source-code comments are a smell.** `CONTRIBUTING.md` now states that
  a comment restating *what* the next code does, *why* it exists, or a
  *weird* approach usually means names, signatures, or the library fit
  are unclear. Most `//` comments should not exist; remaining ones name
  an invariant, protocol, `SAFETY` requirement, or library quirk. First-party
  production sources were cleaned to that bar.

- **Core functional Wave D.** Future-tip load abort (Core 2h
  `MAX_FUTURE_BLOCK_TIME` vs `-mocktime`). `getblock(verbose=2)`
  `scriptPubKey.address`. `getrpcinfo.active_commands` + `logpath`.
  Official leftovers stay skip with first-failure analogs:
  `rpc_blockchain` missing `time` (`:157`), `rpc_generate` `combo()`
  (`:55`), `interface_rpc` JSON-RPC 2.0 batch (`:151`),
  `rpc_getblockfrompeer` method (`:69`), `mempool_reorg` unannounced
  getdata (`:94`), `rpc_net` dual connections (`:100`). Inventory still
  **31** `run`.

- **Core functional Wave C.** Official unmodified
  `p2p_sendheaders.py` and `p2p_compactblocks_hb.py` are now `run`
  (31 inventory run names). Header announce follows Core
  `pindexBestHeaderSent` (inv after a large reorg until the peer
  catches up; getblocks does not resume). Block bodies are requested
  from header announcements or getheaders replies, not from inv.
  Unrequested anti-dos:
  minwork header skip, weaker forks stay headers-only, missing parent
  header disconnects, 288-height window. `p2p_unrequested_blocks.py`
  / headers-sync / `p2p_invalid_messages.py` / `p2p_compactblocks.py`
  stay skip with first official-failure analogs. Compact **filters**
  stay skip.

- **Core functional Wave B.** Official unmodified
  `mempool_unbroadcast.py` is now `run` (29 inventory run names).
  Unbroadcast set persists across restart; `mockscheduler` re-INVs it.
  GBT/submitheader field zoo, `-blockversion` / `-blockmintxfee`, and
  GBT sigops shipped. `mining_basic.py` stays skip (first remaining
  official failure is `test_block_max_weight` empty mempool /
  reserved-weight). `rpc_net.py` / `rpc_getblockfrompeer.py` /
  `rpc_blockchain.py` stay skip with first-failure analogs.

- **Core functional Wave A.** Official unmodified
  `feature_dersig.py` / `feature_cltv.py` / `p2p_ping.py` /
  `feature_minchainwork.py` / `tool_rpcauth.py` are now `run` (28
  inventory run names). Compact block filters stay skip.

- **Core debug.log campaign (Step 21).** BIP34/66/65 outdated `nVersion`
  is `bad-version(0x…)`. Connect script fail logs
  `Block validation error: …` (`SIG_DER` / five CLTV parens).
  `testmempoolaccept` emits `reject-details`. Ping/pong logs Core
  `Short payload` / `Nonce mismatch` / `Nonce zero` / `ping timeout`
  and `getpeerinfo` RTT fields. Confirming an unbroadcast local tx
  logs Core's removal line. V2 unknown type and redundant version
  log the `p2p_invalid_messages` needles.

- **Height fence extend is fail-closed.** Missing or empty `header_txs` for
  the header is `Corrupt`, not `Ok` with a live `height_of` hole (TipOnly
  leftover miss that restart rebuild then heals). Confirm publishes the
  fence run **before** `confirmed[]` so a failed extend cannot leave tip
  ahead of `height_of`.

- **Invalidate evicts immature coinbase spends.** `QueryUtxoProvider`
  now ORs the input-null coinbase signal with first-in-block, so
  `evict_after_reorg` sees `ImmatureCoinbase` after `invalidateblock`
  drops tip below maturity. Creates whose Class A height is above tip
  are not chain coins, so children of a reorged spend leave too.
  Re-accepting a disconnected parent wires edges to children that were
  already live (`ancestorcount` 2).

- **`-minimumchainwork` is live on P2P.** Below the floor: stay in IBD
  (also if tip age > 24h), do not announce blocks, ignore inbound
  `getheaders`. Tip-follow still runs so later blocks can raise work.
  `getblockheader` / `getblockchaininfo` report real header `chainwork`
  (regtest 2 per block), not `""`. Download (getdata/accept) waits until
  the peer's best-known path meets the floor.

- **IBD leftover miss names the table:** stamp reject lines include
  `miss_on=head|body|idx|fence` and `miss_cands=` so a TipOnly miss is not
  read as a bare missing prevout (`body` is `txid.body` identity).

- **Load pin hygiene (scriptq feed).** Sparse need-vouts are binary-searched
  (sorted decode outs). Stamp maps move off the plan (`take_from_plan`)
  instead of cloning two ~100k U64Maps. Archive bind is one walk
  (in-flight → pin_txid → BQ → TipOnly). `pin_txid` is one Weak-map lock
  per pack (`bulk_lookup_txid`), not one mutex per remaining prev_txid.
  Load pin no longer `tx_spent_range_batch`s the parent set — write
  `ensure_spend_abs_layouts` is the sole `spent.idx` stamper. IBD
  `pread_skip` on write may drop; `scriptq` is the customer. Leftover
  TipOnly vs BQ leakage is still a host spike (no pending map, no
  soft-requeue).
- **io_uring harvest is fail-closed.** Unmatched/duplicate CQEs, leftover
  undrained SQEs, CQ overflow, and identity-without-idx-range are
  `Corrupt("invariant: io_uring …")` / `idx range missing after identity`,
  not a quiet TipOnly `MissingPrevout`. Distinct `user_data` kinds + epoch
  so a leftover probe slot cannot complete an identity pread. Spend
  annotate drains before slot buffers drop. Pwrite unfilled ops fail
  closed to libc retry. Uring resolve no longer swallows Corrupt into
  pread (ring-unavailable still falls back).

- **Mempool block connect evicts conflicts:** a confirmed block that
  spends a mempool tx's inputs (without including that tx) drops the
  conflict and its descendants. `wallet_txn_*` reorgs need this.
- **Mempool accessors:** `getmempoolancestors` / `getmempooldescendants` /
  `getmempoolfeeratediagram` / `submitpackage` / `gettxspendingprevout`.
  `-limitclustercount` / `-limitclustersize` overlay the live graph
  and survive `maybe_compact` rebuilds. Cluster overflow is
  `too-large-cluster`. `getmempoolinfo.optimal` is true (we linearize
  on insert). `sendrawtransaction` of a live mempool tx returns the
  txid (Core no-op), not `-26 txn-already-in-mempool`.
- **GBT proposal:** Core reject needles without writing UTXO / requiring
  PoW. `submitblock` maps `high-hash` / `prev-blk-not-found`.
- **BIP152 / inbound:** handshake `sendcmpct` is v2 low-bandwidth;
  HB (`send_compact: true`) is selected when we accept a tip from the
  peer (max 3). Announce compact with coinbase prefill. `getpeerinfo`
  reports `bip152_hb_to` / `bip152_hb_from`. Feeler outbounds send
  `relay=0` and close after version. Empty-locator `getheaders` is a
  single-hashstop request.

- **No leftover pending map.** Parent identity is in-flight until
  drain-fk **and** fence after pin + scripts handoff (n−1 outs).
  Prune-after-bind dropped those outs before pin (mainnet 187
  `load parent without body_range denserels`). Fence alone dropped
  layers during `tx.head` seal (269204 leftover 1121/1120).
  Disconnect drops in-flight layers at that height. Header-cache GC
  polls store tip every load pack. Store `PendingHeadInserts` is a
  write-local drain `Vec`. Not a leftover soft-requeue.

- **`tx.head` insert has no mmap-era CPU fence:** `insert_many` / page
  probe no longer `SeqCst`/`Acquire` fence. Tables are fd `pwrite`/`pread`;
  visibility is the syscall and `published_len` Release. VarTable seqlock
  and Class C `sync_data` are unchanged. Not a leftover-prevout fix.

- **Pending `tx.head` snap lives until insert and fence:** drain
  inserts head for probe; `forget_if_fenced` skips still-queued keys.
  Write forgets after `drain.join()` *and* `height_fence_extend` — not
  from Class C while insert is in flight. Fence-first (early IBD huge
  packs) dropped pending before `tx.head` published (`67438`
  leftover_n=11 hit=4). Drain-first hole was `327331` leftover_n−1.
  No leftover soft-requeue — union miss stays Corrupt.

- **IBD lookup wave select is one BQ lock:** unresolved heights come from
  `block_queue_unresolved_heights` (in-entry `resolve_complete`, capped).
  The old `list_meta` + per-height `is_resolve_complete` scan was O(n²)
  at a few thousand queued bodies (`lookup_thr other=` pegged at ~140k).

- **IBD connecting search only from a competing tip+1:** `consider` no
  longer walks `max_ordered`. A linear tip+1 (parent is the tip) is a
  download hole, not a fork. Most-work search still runs when tip+1's
  parent is some other known header.

- **IBD connecting search needs a connected LCA:** a capped ancestor walk
  from a far header-only horizon (early IBD, tip at a few thousand, headers
  at `max_ordered`) is not a disconnected fork. The old `!has_block(join)`
  shortcut treated that mid as a disconnected fork and getdata-stormed
  32 connecting hashes. Real forks still search when the join is on the
  best chain.

- **Tip-follow stale redial:** a persistent 60s interval plus the 5s
  `tip: perf` wake now run the extra-outbound check. The previous one-shot
  sleep in the same `select!` was reset by every perf/RPC tick, so a node
  that lost its last follow peer (mainnet 962723) never redialed.

- **Class A idx rolls:** each stem (`txout` / `inwit` / `spent`) rolls its
  own idx at the soft span. Inwit no longer forces hot idx splits.
- **`strong_tx`:** always L2 (1 bit/fk). `RBITCOIN_CLASS_C_INRAM_MAX_MB`
  still caps `confirmed` / `header_txs_*` only.
- **Schema 17 freeze note:** [`SCHEMA.md`](SCHEMA.md)
  (hot set, widths, kinds without wipe, what forces 18).

- **`getdeploymentinfo`:** buried `bip34` / `bip66` / `bip65` / `csv` /
  `segwit` / `taproot` from `ChainParams` (including the activation-height
  overlay). `active` is Core `DeploymentActiveAfter` (next block). No BIP9.

- **Confirm overlay:** `-testactivationheight` changes BIP68/CSV/CLTV/DERSIG
  and BIP147/WITNESS (with `segwit`) on the same `ChainParams` confirm uses.

- **Confirm reject log:** BIP113 uses the same `bad-txns-nonfinal` needle as
  BIP68. Script-flag rejects emit Core `block-script-verify-flag-failed (…)`
  on the receive path (P2P / `submitblock`).

- **`scantxoutset`:** `raw(script)` uses `--shindex` `scripthash_listunspent`
  when the index is on; otherwise Class A txout + spent. Never reconstructs
  every block.

- **Block selector:** `generate*` includes mempool txs via
  `TxGraph::select_block_txids` (best-chunk order, parent-before-child,
  block-weight cap). Same helper will feed `getblocktemplate`.
  Chunks are prefix-maximal feerate (cheap parent + hot children stay
  together; a cheap descendant does not dilute a hotter prefix).

- **`getblocktemplate` / `getmininginfo`:** template from the selector on
  every network. `rules` must include `segwit`. Proposal validates without
  connecting. No BIP9 testdummy version bit. `longpollid` waits for a new
  tip or a mempool/priority update (same production template).

- **`prioritisetransaction`:** additive i64 sat fee delta by txid (even if
  not in the mempool). Dummy must be 0. Selector / generate / GBT rank by
  modified fee; non-positive modified fee is not mined. Min-relay and RBF
  use the incoming modified fee. Mined txs drop the delta.
  `getprioritisedtransactions` reports the map.

- **`-persistmempool=0`:** start with an empty live set (do not reload the
  durable sidecar). The flag was already parsed; it now takes effect.

- **Mempool BIP68:** confirmed inputs use the parent create MTP (not 0).
  `getblockheader.mediantime` is real MTP.

- **`submitheader`:** same `ensure_header` path as P2P headers. Header-only
  children show up in `getchaintips` as `headers-only`. `getblockchaininfo.headers`
  is the best known header height. `invalidateblock` of an unknown hash is
  Core `-5 Block not found`; after invalidate the next most-work fork is
  applied. `preciousblock` breaks equal-work ties only (not less work).
  `generatetodescriptor` accepts `addr(ADDRESS)#checksum`.

- **`getchaintips`:** active tip plus losing `valid-fork` (archive after
  reorg) and held never-confirmed `valid-headers`. Hashes only — not a
  block index.

- **Mempool RPC graph fields:** `getmempoolentry` / verbose `getrawmempool`
  ancestor and descendant counts (and size/fee sums) come from the cluster
  graph, not stub `1`. `getmempoolinfo.unbroadcastcount` and per-entry
  `unbroadcast` track `sendrawtransaction` until a peer `getdata`s the tx.
- **`rbitcoin-cli`:** cookie / `--rpcuser` HTTP client for the documented
  JSON-RPC subset (plain HTTP, same as the node).
- **`--maxinbound`:** passed into `P2PNode` as a field. `RBITCOIN_P2P_MAX_INBOUND`
  is parse-time input only (no `set_var`).
- **`getnetworkinfo` / `getmempoolinfo`:** `version` is rbitcoin (`0.1.0` →
  `100`); `localservices` match advertised flags; `maxmempool` is the hub
  weight budget.

- **Schema 17 (durable) — wipe the datadir and redo IBD.** Opening a
  store that already has Class A creates (schema 15/16 16-byte meta /
  9-byte spent) or leftover `key_len=32` SH runs is refused. Empty
  Class A still soft-opens. This is meant to be the last full-datadir
  reindex for the Class A / B / C layout; later work (inwit Δfk, a new
  consensus script kind) would be schema 18 and should not require
  another wipe of `txout` / `spent` / heads. Layout in 17: SH runs
  unique `(scripthash, create_fk)` at `key_len=40`; megakey pages are
  uleb fk0+deltas; thin LAYOUT17 `txout` meta; script kinds 0–9; 8-byte
  spent slots; overflow is `spent.ovf`; reserved inwit bits 4–7 and
  spent flags other than `MULTI_SPENDER` are Corrupt. Leftover
  `archive_epoch`, `store/wire`, and single-file `sp_tweaks.idx` /
  `sp_tweaks.body` are unlinked on open. Tweaks (when `--sptweaks`) are
  segmented dirs: tip-only `off:u32` (no `header_fk`), original `0`/`33`
  body, new `NNNNNN` pair when the next body start would exceed `u32`.

- **IBD lookup is BQ-ahead TipOnly `head_fk`:** the lookup thread resolves
  external parents for at most **8** ready body-queue heights in one
  `get_fk_by_txid_batch` wave and attaches hits on the BQ record. Load claims
  only resolve-complete heights (soft **8000** inputs, typically 1–3 dense
  blocks — not a ~32-block pack) and stamps from those hits plus a leftover
  TipOnly `tx.head` for parents not in live caches (almost all open head; the
  rest ages ≤3 sealed). No `TipThenAny` last-chance on the confirm path.
  One-shot `accept_branch` / `confirm_wire_run` still stamp in-process with
  TipOnly. Progress/sizes print **`ready=`** (BQ resolve-complete count), not
  a fake `loadq=n/8`. Load leftover head is `leftover_n/hit/ms/pend/cdf`;
  lookup wave wall is `lookup_thr wave=`.

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
  post-merge on `master`. Leave `origin` on SSH (operator auth); the App
  fetch/push uses an explicit HTTPS URL. See `AGENTS.md` and
  `docs/how-we-plan.md`.

- **Docs honesty:** root `/api.jsonl` is gitignored. SCHEMA `archive_epoch.wire_depth`
  is an unread leftover field (no tip wire ring). `page_rmw_pipelined` is
  documented as test-only. io-modality no longer describes a map hatch;
  OPERATOR densify is body-queue soft depth (no archive-queue cap).
- **Table flush:** `TableFile::flush` always `sync_data` after a dirty persist.

- **Docs Q-14:** [`docs/heads.md`](docs/heads.md) is the head-module glossary.
  Pipeline details stay in `concurrency.md`; architecture / OPERATOR / AGENTS
  link instead of restating. SCHEMA tree uses `tx.head/` (not flat names).

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
- **CLI-first config:** `--maxinbound`/`--maxconnections`, `--conf`,
  Core-like aliases (`--assumevalid-height`, `--maxmempool`, `--chain`).
- **Tip-follow logging:** every accepted tip block logs Core-like `UpdateTip: …`.
- **Fee snapshot / mempool APIs:** published fee table and mining chunks so
  Electrum/Esplora estimates do not block accepts (R-01–R-04).
- **Quality gates:** `cargo deny` on PR (Q-20); coverage uses prebuilt
  `cargo-llvm-cov` (Q-22); `scripts/sbom.sh` emits CycloneDX from Cargo.lock.


### Fixed

- **Fuzz CI nightly:** `scripts/fuzz-run.sh` / `fuzz.yml` set
  `RUSTUP_TOOLCHAIN=nightly` so `rust-toolchain.toml` 1.95 cannot feed
  cargo-fuzz (`-Zsanitizer` is nightly-only).

- **SH materialize last page:** megakey chunking sizes the last extent page
  for the `ver=2` 24 B header (4072 B stream), not the `ver=1` 4088 B cap.
  A key whose delta stream sat in 4073..=4088 B overflowed
  `scripthash page pack: entries exceed page capacity` and aborted bulk
  materialize.

- **Script pool wake:** idle `rbtc-scripts-*` workers `park` with an epoch +
  `unpark` permit (wave publish / detached job). A worker that misses steal
  and parks after the wake still runs the work. Jobs mutex stays the
  detached-job queue only.

- **Script steal last-chunk:** `in_wave` increments before `next.fetch_add`,
  so `is_complete` cannot free wave ctx under a claimer about to `apply`.
  A lost claim decrements `in_wave` and re-checks completion.

- **Darwin / Windows smoke:** schema 17 dir-variant SH body is
  `scripthash.body/NN` + `scripthash.ovf/body`. Snapshot jobs now accept
  that layout (legacy file body still ok). Default `--datadir` is
  `Path::new(".").join("datadir")` so Windows does not mix `./datadir\store`.

- **Lookup wave at-least-unless-tip:** the 8000-input floor still
  holds a thin *far* layer while more BQ heights can join, but a
  single block at store tip+1 emits so load can take it.

- **IBD most-work rewind:** a heavier header branch (resume sibling
  fork, competing tip+1, or BadPrev) disconnects to the LCA and the
  normal confirm pipeline extends the winner. Gather-then-`accept_branch`
  could not converge: awaiting was overwritten, `HELD_CAP=32` evicted
  mids, and lookup stamped disconnected BQ heights (`…f972` @ 961635
  while tip stayed on the loser).

- **IBD BadPrev / fork child at tip+1:** work-path slots are first-wins
  and prev-anchored. After `take_raw`, Reject carries the wire so
  CompetingPath still classifies; `lookup_taken_hi` rewinds to tip;
  the losing slot identity is evicted (not `mark_missing` / re-get
  the same hash). Reorg apply clears the path suffix.

- **Tip-hole / densify / receive share one in-hand rule:** confirmed,
  matching BQ hash, or `H ≤ lookup_taken_hi`. Taken loadq heights are
  not fetch holes and do not re-getdata or `mark_pending`.

- **Lookup walk after loadq take:** `block_queue_unresolved_heights`
  starts after `lookup_taken_hi`. Taken BQ rows are not a fetch hole,
  so lookup can fill loadq ahead of tip. A missing height *above*
  that high-water still stops the walk.

- **Windows / Darwin store smoke `--release` compile:** `take_raw_clone_n`
  and the raw-clone meter are `cfg(any(test, debug_assertions))`. Native
  `cargo test --release -p rbitcoin-store --lib` (windows.yml / macos.yml)
  compiles the whole test crate; the meter stays off in production
  `--release` node builds.

- **Windows store create (os error 87):** table files open
  `FILE_FLAG_OVERLAPPED` for IOCP. `TableFile::create` / `open` / trailing
  header used std `Write`/`Read`/`Seek`, which call `WriteFile`/`ReadFile`
  with a NULL `OVERLAPPED` and fail with `ERROR_INVALID_PARAMETER` on the
  first file (`scripthash.body`). Header IO is positional `IoHandle`
  pread/pwrite; grow uses `SetFileInformationByHandle`. IOCP associate no
  longer treats every 87 as success (tracked same-port rebind only).
  `windows.yml` / `macos.yml` smoke `TableFile` create/open and
  `--smoke` until `store/scripthash.body` exists. Darwin zips are ad-hoc
  `codesign -s -` (not notarized).

- **Core functional proxy ports:** Esplora binds `rpcport+20000`, not
  `node_rpc+1`. Consecutive Core `-rpcport` values made the next node's
  internal RPC land on the previous node's Esplora (`HTTP 404` on
  `getblockcount` in multi-node tests).

- **`sp_tweaks` rolls a new 4 GiB body instead of dying at `u32` off:**
  mainnet backfill hit `store: corrupt record: sp_tweaks body exceeds u32
  off` once a single body crossed 4 GiB. Schema 17 keeps the original
  `0`/`33` records and stores only a per-segment `u32` start (no
  `header_fk`). The next put whose start would exceed `u32::MAX` opens
  `sp_tweaks.{idx,body}/NNNNNN`. Leftover single files are dropped;
  backfill regenerates.

- **SH bulk materialize heartbeats during a megakey:** status INFO only ran after
  `put_chain` (unique-key boundary). One scripthash can absorb tens of millions
  of creates with no key change — mainnet shard 1 went ~6.5 min silent
  (`keys≈36.6M→38.6M`, `creates≈92.7M→155.6M`) and looked stalled. The loop now
  samples the 10 s interval every 64 Ki recs of the same key and prints
  `pending≈` (in-progress chain) so `creates`/`pct` keep moving.

- **IBD tip no longer storms getheaders / re-admits:** already-known 1-header
  announces (inflight, BQ-pending, or height ≤ tip) stay off `ordered`. Empty
  `ordered` near the peer horizon marks `headers_done` instead of fanning
  getheaders to 4 peers every loop. That loop was ~1k INFO lines/s at mainnet
  tip and blocked catch-up complete → SH → tip follow. Mid-sync 292k re-admit
  of drained-but-still-needed headers is unchanged.

- **Disconnecting a confirmed block logs `DisconnectTip` at warn:**
  `Query::disconnect_tip` (every reorg / tip restore) emits
  `DisconnectTip: hash=… height=… tx=…` so leaving the best chain is
  never silent.

- **IBD searches connecting blocks for a heavier disconnected header chain:**
  if competing tip+1 does not meet the current tip, walk prev to the
  best-chain LCA and getdata the shortest prefix whose work beats the
  losing tip (then `accept_branch`). Do not wait for the dead fork to grow.
- **Leftover pending needs no fence; in-flight prune waits for fk span:**
  write-behind `pending_fk` is already a Class A identity — TipOnly leftover
  no longer requires `height_of`. In-flight drops a layer only when
  `covers_fk_span` of that pack's create fks (not fence max height).
  Mainnet **950545** `leftover_n=1752 hit=1751` after PR #37.

- **Class C open repair is a fence complement, not a full-bit walk:**
  `Query::open` revalidates the tip window first (last six heights now also
  require those `header_txs` runs to be all-strong), rebuilds the fence on
  shrink, then runs **one** `repair_class_c_above_tip`. Repair unstrongs holes
  between fence runs plus a short suffix (stop at a 64 KiB zero page) instead
  of `for_each_strong` + `height_of` on every set bit (~1.4 B visits × 2 on
  mainnet, ~1 minute pegged CPU even after a clean shutdown). Logs
  `class_c repair cleared= ranges= ms=` even when nothing is cleared.

- **In-flight prune is fence coverage, not confirmed tip HWM:** leftover
  TipOnly accepts a create iff `fence.height_of` is `Some`. `confirmed.set_many`
  publishes tip before `height_fence_extend`, and leftover held the fence lock
  across head IO — prune-on-tip dropped just-committed layers while TipOnly
  still saw the old fence. Open-head hits wiped; valid tip+1 blacklisted
  (mainnet **945952**, `leftover_n=3546 hit=2811`, age0=100, pend=0). Prune
  now uses `fence_tip_height`; leftover clones the fence before resolve.
  Occupied-HWM form of the same implication was **929462** / **931147** /
  **933474**.

- **In-flight prune is confirmed tip, not head occupied:** planned creates stay
  until `tip >= pack max_height`. Occupied/fence_max prune dropped tip-ahead
  parents after drain while leftover TipOnly still required `height_of` — valid
  tip+1 blacklisted (mainnet **929462**, **931147**, **933474**). Leftover
  remains connected-head only. Stamp reject logs `leftover_n/hit` for the fail
  pack.

- **Load leftover parents are TipOnly `tx.head`, not an invariant:** after the
  BQ wave, some externals remain (same-batch / in-flight / not yet in the
  wave hits). Treating those as `Corrupt("external parent missing BQ TipOnly
  hit")` rejected a valid mainnet block at 928640 and stalled IBD. Load now
  TipOnly-heads leftovers; a true miss is still unresolved (not TipThenAny).

- **Lookup nested io_uring on write-behind pending hits:** IBD
  `ibd-confirm-lookup` panicked (`nested thread-local io_uring`) when stamp
  resolved a parent still in the `tx.head` pending map — `record_range` opened a
  second TLS ring inside the plan machine. The window is long while drain
  **seals** a full segment. Pending hits now run **before** the plan
  `with_thread_local` (same serial `record_range` as before).

- **Tests:** head and `tx.idx` share one thread-local soft-span override.
  `HeadScale::test_with` pins tiny/mainnet without process-global `set_var`.

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


### Removed

- **Host forensics and cargo benches:** `examples/diag_*`, `dump_wit`,
  all `[[bench]]`, `rbitcoin-store-bench`, `freeze_benches`,
  `reader_contention`, `diag_tip961461`, and ignored page-group / SH-head
  wall microbenches. Default graph is product + suite
  (`scripts/check_default_targets.test.sh`). Host A/B is musl + `ibd: perf`.

- **Unused spend-annotate wrappers:** `Store::put_spend_batch_by_create` and
  `_ranged`. Confirm write is abs-meta only
  (`put_spend_batch_by_abs_meta_known`). `put_spend` / `put_spend_batch`
  (txid) stay for `connect_block` / archive commit.

- **`script_bench` facade:** detached script verify and fixture tests use
  `ScriptCheckJob` + `verify_scripts_pool` / `verify_job_all_inputs`.

- **`rbtpkg` P2P command.** Homegrown len-prefixed package inject is gone.
  Packages stay on RPC `submitpackage` and Esplora `POST /txs/package`.

- **`RWF_DONTCACHE`:** first-party flag, capability probe, and
  `dontcache_policy`. `spent.body` is its own file; evicting those pages
  does not protect `txout`. Uring machines stay.
- Unused Core-style `check_tx_standard` (admit is Libre only).
- Path-named IO backend aliases and always-true `class_a_append_uses_pwrite`.
- `crate_name()` / `smoke_crate_names` coverage theater.

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

- **FdOnly ceremony / leftover ghost surface:** `TableAccess` / ignored
  `RBITCOIN_TX_HEAD_ACCESS` / bench `--access`. `ibd_io_policy` (always-false
  defer). Always-empty `denserels_from_packed_records`, test-only packed
  spender-rel helpers, unused `head_insert_many_sole`, no-op
  `ConfirmParentCache::from_env`. Unprinted `connect_prevout_stats` and
  always-zero `HeadResizeSizeSnapshot` shadow fields. Printed `ibd: sizes` /
  `ASM_PREV_*` unchanged.

- **Hash-load confirm twin:** `Query::load_confirm_parents`, ConfirmParentCache
  scan watermark, and `BatchFullBodies`. Confirm load is wire-only
  (`pin_for_wire_batch` + `load_creates_once`). Reconstruct always reads
  Class A from the store. Header plans stay for MTP.

- **Dead wrappers after archive-ahead / hash-confirm:**
  `confirm_wire_lookup_and_ensure_denserels`, `ChainHub::confirm_wire_lookup_phase`
  / `_pipelined_cold` / `confirm_scripts` / `is_archived`,
  `prepare_block_for_archive_ibd`, header `put_raw`/`rewrite`, unread
  `archive_epoch` mutators, fused `get_fk_and_outs_by_txid_batch`, always-false
  `txid.body` DONTCACHE and confirm load-retry hook, no-op
  `warm_scripthash_create_index`, always-true `IndexMode::uses_durable_spends`.

- **Ghost meters those paths fed:** plan `sticky_ns` / `head_dens`, unused
  `last_stamp`, `lookup_thr resolve=` (always 0). `last_plan_batch`
  leftover_n/hit stays for stamp-reject. Live leftover `head_fk` /
  `pin_txid` / leftover CDF stay.

- **Public archive-without-confirm:** `Query::archive_block`,
  `accept_and_archive_block`, and `ChainHub::archive_block`. Confirm is sole
  Class A (`archive_plan_batch_*` + `archive_commit_plan`). Crash / `plan=None`
  tests use `commit_class_a_only`. `Query::connect_block` stays as the cheap
  store fixture. Plan stamp is TipOnly; store `TipThenAny` remains for RPC.

- **Dead DONTCACHE / IO aliases:** head/idx probe no longer threads an always-false
  DONTCACHE flag. `sealed_age_from_index` lives with winner-age stats.
  Dropped `get_outs_denserels_by_range_batch`, `spend_meta_backend_next`,
  `load_needs_resize`, `HeadRole::Tx` / `RBITCOIN_HEAD_SLOTS_TX`, and
  `RBITCOIN_IO_URING` (`RBITCOIN_IO=pread` is the only pread hatch).

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
