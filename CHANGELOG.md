# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for the **0.x** experimental line (breaking on-disk and API changes are expected
before 1.0).

## [Unreleased]

### Added

- **CI Windows / Darwin snapshots:** after a green `ci` run on
  `master`/`main` (and on `workflow_dispatch`, and on PRs labeled
  `static-binaries`), workflows `windows` and `macos` upload CRT-static
  PE and system-dylib Darwin `rbitcoin-node` / `rbitcoin-cli` +
  `SHA256SUMS` (90 days). Not required checks. `musl` uses the same
  label. Linux musl stays Nix; Darwin/Windows are native runners.

### Fixed

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

### Changed

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

### Added

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

### Removed

- **`rbtpkg` P2P command.** Homegrown len-prefixed package inject is gone.
  Packages stay on RPC `submitpackage` and Esplora `POST /txs/package`.

### Changed

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

### Removed

- **`RWF_DONTCACHE`:** first-party flag, capability probe, and
  `dontcache_policy`. `spent.body` is its own file; evicting those pages
  does not protect `txout`. Uring machines stay.
- Unused Core-style `check_tx_standard` (admit is Libre only).
- Path-named IO backend aliases and always-true `class_a_append_uses_pwrite`.
- `crate_name()` / `smoke_crate_names` coverage theater.

### Fixed

- **Core functional proxy ports:** Esplora binds `rpcport+20000`, not
  `node_rpc+1`. Consecutive Core `-rpcport` values made the next node's
  internal RPC land on the previous node's Esplora (`HTTP 404` on
  `getblockcount` in multi-node tests).

### Added

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

### Changed

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

### Fixed

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
- **CLI-first config:** `--maxinbound`/`--maxconnections`, `--conf`,
  Core-like aliases (`--assumevalid-height`, `--maxmempool`, `--chain`).
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
