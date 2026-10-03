# Crash recovery and reorg semantics (store)

Hard kills (`kill -9`) and tip disconnects are normal. **Corrupt Class A / Class C
payloads are not repaired in-process** — reindex / redo IBD. Derived `tx.head` in
the **current** layout that is unreadable (truncated sealed MPHF, empty/short
`meta`, other open errors) **rebuilds from Class A** when bodies exist. Leftover
**prior layouts** (fuse8 v1, flat `tx.head.meta`) still **refuse**.

## Tip as commit point

Best-chain views ignore uncommitted Class C state:

| Write order (confirm **write** thread) | Role |
|-------------------------------------------|------|
| 0. Structural spentness / maturity / subsidy | No durable tip write yet |
| 1. `strong_tx` (L2 RAM) | May lead tip after kill **before** barrier |
| 2. Thin scripthash **creates** (batched) | May lead tip after kill |
| 3. `confirmed[]` tip advance (L2 RAM) + height-fence extend | In-process commit |
| 3b. **`flush_class_c_tip`** (complete-or-fail L2 images) | **Durability barrier** |
| 4. Body-queue dequeue for those heights | Only after confirm-write returns Ok |
| 5. Spend annotations (Direct) | After tip. A missing slot is unspent until open replays from the marker |

`is_confirmed_strong(tx)` ⇔ strong ∧ height fence contains the fk. Queries that mean “on best chain” use this (or equivalent). Confirmed-tx **API** readers pin that tip (`Query::pin_chain_view` / `still_live`) and retry on disconnect rather than pausing the writer — [`concurrency.md`](./concurrency.md#confirmed-tx-readers-pin--retry-not-a-lock).

On open (in order):

1. Soft `store/tip_seal` (if present): clamp confirmed tip that advanced without a complete barrier seal.
2. **Tip-window revalidate** (Core `-checkblocks`, default 6, `0` = all): first drop any trailing null `confirmed[]` slots (HWM ahead of last real tip), then the last N confirmed heights — `prev_fk`/hash chain, `header_txs` range bounds, merkle root from `txid.body`, and those N runs all-strong. A missing `spend_durable` file is the whole chain (`n == 0`): nothing has been device-flushed, and a matching last 6 heights is not a proof. A present marker widens any other window to at least 6 and far enough to cover `(D, tip]`. `checkblocks=0` stays the whole chain. On failure: clear bad Class A association and/or shrink tip to last good height, rebuild the fence, flush confirmed.
3. One `repair_class_c_above_tip`: unstrong bits **not on the fence** via complement ranges (holes + suffix until a zero page). Does **not** walk every set bit. Logs `class_c repair cleared= ranges= ms=` even when zero.
4. Replay spend annotations for every height in `(A, tip]` (`spend_durable` annotated-through). A missing file has no device-flushed cursor, so `A = 0` and the chain is rewritten. `finish_post_commit_hashes` is idempotent. Then `sync_data` the replay inputs and publish `A` and durable-through `D` at the surviving tip. The replay logs height progress every 10 seconds.

In-process completion-session recover (IBD write/lookup/load/scripts and tip connect) consumes a 1000-height credit and requeues; it does **not** run `repair_class_c_above_tip` (lookup would race the write thread's strong-before-fence window). Abandoned leftover strong is the same as kill-9 and is repaired on the next open. Does **not** truncate Class A. Tip stays the commit point.

Open revalidation runs in `Query::open_or_create` **before** P2P can extend tip.

### L2 write-behind + body queue (phase 6)

- Compact Class C (`confirmed`, `header_txs_*`, `strong_tx`) mutate **RAM only** during the commit batch. The height fence is RAM-only (derived from those tables).
- **Connect** barrier order on disk (**tip last**): `strong_tx` → `header_txs` → **`confirmed[]` last**.
  - Mid-barrier kill after pre-tip tables: tip stays old; leftover strong not on the fence is repaired by `repair_class_c_above_tip`.
  - Never flush `confirmed` before strong on connect — tip with permanent unstrong txs (repair only clears leftover strong).
- **Disconnect** barrier order (**tip first** — opposite of connect):
  1. SH unlink only (do not unstrong yet).
  2. `confirmed` truncate + fence pop → `flush_confirmed_only` (durable tip shrink).
  3. Then `set_unstrong` → flush strong.
  - Mid-kill after tip shrink: leftover strong is **not on the new fence** → repairable.
  - Never unstrong while tip is still high — permanent unstrong-at-tip.
- Append-only tip extension writes **suffix only**. In-prefix full rewrites residual; tip-last connect + tip-first disconnect + BQ re-drive mitigate.
- Prefer **loss of uncommitted tip progress** over **tip-ahead-of-strong** or **tip-high-with-unstrong**.

## Class A (archive)

- Append-oriented; re-archive is **idempotent** when `header_txs` already present.
- **Never leads tip:** Class A is published only on the confirm-write path with tip advance in the same era (no dual-track archive-ahead).
- Kill mid-archive without a complete body association ⇒ not treated as archived; re-getdata.

## Spends (v5: annotation on create outputs)

- Sole spender: 8 B slot on **`spent.body`**. Multi: `MULTI_SPENDER` + `spent.ovf` list.
- Class A may write same-batch sole `spend_fk` into the spent stem (creates in that append wave). Historical parents stay zero until annotate **after tip**.
- Annotations may remain after disconnect / for non-strong spenders.
- Best-chain spentness: annotation + `is_confirmed_strong(spender)`. Same-batch pre-fill is not strong until this batch's Class C.
- Kill-safe for a stale annotation: non-strong fields do not false-positive if the filter is applied.
- A missing annotation is not kill-safe. Open replays `(A, tip]` from the block bodies, then advances `A` only after `sync_data`. `A` never exceeds tip. Disconnect below `A` lowers `A`.
- A confirm write that fails after its tip commit (live index seal, spend annotate) leaves its first height pending in process. The next confirm write replays `[pending, tip]` before structural, and returns the replay error without validating if that fails. The spend snapshot does not advance past the pending heights, a disconnect lowers it to the new tip, and a snapshot note is capped at the confirmed tip it reads in the same atomic update. The checkpoint also never publishes `A` at or above a pending height.
- No `point.head` (v4 open-hash multimap removed).
- Class A is **three stems** (`txout` / `seqsigwit` / `spent`); bare-meta puts are rejected. Packed `tx.body` with creates is refused on open.

## Thin scripthash (Electrum outpoint pointers)

- Schema 15: head holds ≤2 inline creates, a geometric **slab** (3–256 fks, ULEB128
  deltas), or a megakey **page chain** (≥257). Size-class freelist reuses freed slabs.
  Main heads are sealed MPHF+pack8 (no fuse); new keys go to global ingest OA.
- **No spend columns** — spentness from points + Class C at query time.
- Creates written on confirm (before tip advance).
- **Kill-safe without chain walks:** first confirm after open **sequentially scans**
  `scripthash.body` once into a process set of `create_tx_fk`s already present;
  re-confirm skips those txs. Hot path only appends + maintains heads in RAM.
- Creates for unstrong / above-tip txs are **invisible** via `is_confirmed_strong`.
- Disconnect tip: **unlink** creates for that block’s outputs (tombstone + rewire);
  process set updated so re-confirm can re-index.
- No tip-mode full rebuild; corrupt index ⇒ reindex (wipe store / redo IBD).

## Flush

Clean shutdown: `flush_for_shutdown` fsyncs tip/Class C (incl. L2 dirty images) then async Class A.
Steady path: payload pwrite + HWM publish; `sync_data` on flush barriers.
Kill mid-payload before HWM publish: readers never see past previous published length.

Connect barrier (`flush_class_c_tip`): headers (if dirty) → strong → height → header_txs → **confirmed last** → soft `tip_seal` (tmp + `sync_all` + rename + parent-directory `fsync`). The barrier does not `sync_data` Class A.
Disconnect: confirmed truncate + `flush_confirmed_only` (also refreshes `tip_seal`) before unstrong/height clear. If the new tip is below `spend_durable`, that marker is lowered to the tip.

Confirm stores a snapshot height after annotations are written and does not `sync_data` these stems. `rbtc-spend-sync` does, about every 10 minutes: `sync_data` on the replay stems and `spenders` (not a high-water rewrite, not `tx.head`), then if the confirmed tip is still at least that snapshot, publish `A = D` at the snapshot. Blocks written during the barrier are flushed along and are not claimed. A disconnect lowers the snapshot to the new tip, so a reconnect is not claimed until its own write finishes its annotate. A checkpoint that read a higher snapshot before the disconnect publishes it only if the tip is still at least that height when the barrier ends; a reconnect that reaches that height during the barrier and finishes its annotate is not fenced. One still pending caps `A` below its first height. A failed marker publish leaves the previous marker and does not start a new interval. Shutdown wakes the thread for one checkpoint, joins it, then runs `flush_for_shutdown`. The barrier is `File::sync_data` (Linux `fdatasync`, macOS `F_FULLFSYNC`, Windows `FlushFileBuffers`). It is not inside `flush_class_c_tip`, and it is not charged on the confirm thread's `ann_sync` timer. A cookie inside a data file, or a clean page cache, is not this cursor: writeback is not a device flush, and the kernel may reorder data ahead of a later header write.

| Write | Rebuild from durable tip + bodies? | Fsync |
|-------|--------------------------------------|-------|
| Class C barrier (`strong`, `header_txs`, `confirmed`, `tip_seal`) | No. This is the commit point. | Every barrier |
| Spend annotations (`spent.body`, `spenders`) | Yes, from the block body and parent outputs, when those bytes are durable | `rbtc-spend-sync` about every 10 minutes, then advance `A` to the pre-sync snapshot |
| Class A bodies replay and the tip window read (`txid.body`, `txout`, `seqsigwit`, `input`, `txstat`) | No. A torn page cannot be rebuilt | Same `sync_data`, which advances durable-through `D` to that snapshot. Open revalidates `(D, tip]` (at least the last 6) when the marker is present, and from genesis when it is missing |
| Scripthash heads, `tx.head` | Yes, from Class A | No barrier `fsync`. SH write-behind syncs the SH tables before it advances `scripthash.include_hwm` (a tip block, the end of a catch-up burst, or ≥1 s since the last advance); recovery replays the idempotent appends above that HWM. `sync=` on `tip: accept` |
| BIP-352 tweaks (`sp_tweaks.*`) | Yes, backfill from Class A | Each put syncs body, then idx. Open drops heights above the tip and fits the last record to its `n_tx` |
| Mempool sidecar | No. RAM is source of truth | Leave the 5 s path |

`tx.head` meta and the spend marker use the same parent-directory `fsync` as `tip_seal` after tmp+rename. Windows denies that directory handle; the file was already synced. A missing `spend_durable` revalidates and replays from genesis. `checkblocks=0` still walks from genesis when a marker is present.

## Mempool sidecar (`{datadir}/mempool/`)

Private, **not** Class A. RAM graph is source of truth; files may lag.

- **Order:** packed `tx.body` tail first, then LIVE slots, then meta. `persist_due` `pwrite`s only new LIVE slot records (not the full table). A crash after a grown body and before new slots loses admits; it does not claim LIVE ranges past durable body. Compact is tmp+rename of packed images (reclaim).
- **5 s admits:** `persist_due` (no fsync) from the tip-follow perf tick. Crash may lose ≤5 s of admits (relay re-fetch). Shutdown `flush` still generation-bumps and `sync_data`s.
- **DEAD:** already-durable slots are one-record `pwrite`. An admit that never hit disk stays RAM-only (crash loses it). Do not dump the full slot table on strip — that would write LIVE rows whose body is still in the unpersisted tail.
- **Leftover schema 1:** convert on open (recode LIVE payloads, tmp+rename like compact). Vin aux is empty; SH reindex batch-fills. Unknown schema still refuses — wipe `{datadir}/mempool/` (Class A kept). See [`OPERATOR.md`](../OPERATOR.md).

## Operator

- Direct IBD keeps segmented **`tx.head/`** (archive) and **spend annotations** (confirm) live; tip entry does **not** re-scan Class A to repair them. Corrupt head/spends ⇒ reindex (optional manual `backfill_tx_index` rebuilds segmented head mappings from Class A).
- **Segmented `tx.head`:** directory `tx.head/` with `meta` + open OA `NNNNNN`; sealed `NNNNNN.mphf` + `.fuse8`. Packed BDZ `g` is FdOnly (4 KiB page stream); MPHF output is `rel−1`. Flat `tx.head.meta` / `tx.head.NNNNNN` are **migrated into** `tx.head/` on open. Roll opens the next OA first; seal runs on a sidecar and publishes later. Seal/install of `meta` / `.mphf` is sibling tmp + `sync_all` then rename (empty truncate of the live name is not a seal). Publish persists sealed `meta` **before** unlinking the segment's OA; a leftover OA next to a sealed `.mphf` is discarded on open. Kill mid-seal leaves **at most one** unsealed non-tail OA: open collects fuse keys once from `txid.body` and seals it (does not retain `open_keys`). Two unsealed non-tails is **Corrupt**. Leftover fuse8 v1 and flat `tx.head.meta` **refuse** (`Query::open`); wipe `store/tx.head` (Class A kept) then restart. Unreadable **current** head (empty/truncated `meta`, truncated/missing sealed MPHF) with Class A: wipe+rebuild from `txid.body` (same cost as a clean wipe). Wipe or empty occupancy + Class A: open rebuilds **MPHF+fuse8 directly** from `txid.body` in parallel (default **2²⁵** keys/range; `RBITCOIN_TX_HEAD_REBUILD_WORKERS`); no historical OA. Legacy mono `tx.head` file / `.new` / `.resize` are not opened — reindex.
- Scripthash: Direct IBD **defers** SH (no memtable, no confirm enqueue). After the horizon, two Class A `txout` scans: each worker owns a contiguous create-fk span and unsized maps (1.5 GiB estimate cap; spill the largest shard map while over budget; one writer, 1-slot queue) into `scripthash.unsorted/keys/NN/` (`SHKSP01` files, first-fk delta singles; tmp+rename, not a kill-9 barrier — no `DONE.keys` still wipes unsorted); merge folds those spills into one map, one walk to `scripthash.head/NN` + `multi/NN.fuse8`, and unlinks `keys/NN/`; then fuse-hit `post` (`SHPST01` spills under `post/NN/`), pack folds those spills then 2+ bodies, unlink each shard's extract as it seals. A **durable head** on restart stays Tip: write-behind / `recover_sh_writebehind` fills any HWM lag; leftover `scripthash.runs` are discarded (not WarmOnly-merged).
  - **Full cold** when head empty. **`RBITCOIN_SH_FORCE_REBUILD=1`:** wipe head + full two-scan collect + pack. Empty collect after Class A creates remain is fatal.
  - **Cold resume:** the pack commit is `scripthash.head/NN.packed` (sibling of the MPHF base; holes stay). Open loads a shard's MPHF only when that mark exists. `MphfHead::exists` after pass-1 BDZ is **not** pack-done. A complete unmarked head (every shard has `.mphf`+`.val`, and `scripthash.unsorted` has no `DONE.keys` / `DONE.post` / `keys/` / `post/`) is soft-migrated: the marks are written, and a missing `include_hwm` is set from the create count. An extract still on disk never gets a mark, even if `include_hwm` already names the tip. No valid `DONE.keys` (including leftover `SHUNSRT3` / 24 B `NN`, or `keys/NN` / `post/NN` as a file) deletes unsorted and restarts pass 1. A spill whose first 8 B are not `SHKSP01` is Corrupt — wipe unsorted; do not parse or migrate. `DONE.keys` / `DONE.post` record the inclusive Class A `create_fk` scanned (`SHKEYS02` last_fk marker / `SHPOST02`). Missing current `keys/NN/` spills with unsealed shards finishes BDZ from those files. Head files present and no `DONE.post` restarts pass 2 from fk 1 (partial `post/` spills are deleted and recollected). Packing a shard soft-clears ingest keys that packed main now owns, so a tip append that landed on ingest while the shard was unsealed cannot hide that chain. A `post/NN` **file**, or a spill whose first 8 B are not `SHPST01`, is Corrupt (wipe unsorted). If Class A grew after `DONE.post` and **no** shards are packed, append postings. If any shard is already pack-marked, pack remaining unsealed `post/NN/`, then Class A tail-append onto the durable head (Direct write-behind no-ops). After all shards seal, the unsorted dir is removed.
  Empty head + leftover catalog: wipe leftover runs + SEAL, then Class A collect (not k-way from `scripthash.runs`). Durable head: leftover runs are discarded, `SEAL` kept; missing `include_hwm` bootstraps from SEAL. Inclusion HWM: `scripthash.include_hwm`. **Leftover live OA** at `scripthash.head` (or non-`SHSR` `ovf/NNNNNN`): refuse — wipe `store/scripthash*` and restart with `--shindex`.
  **SH head open:** sealed **main** shards load `.idx` only (one entry per 128
  records; no fuse). Sealed **ovf** loads `.idx` + BF8R. Occupancy scan is not
  used on those files. A schema-14 page-era durable index is **refused** (wipe
  `store/scripthash*` and rematerialize). Ingest OA still uses `{ingest}.occ`.
