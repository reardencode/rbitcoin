# Crash recovery and reorg semantics (store)

Hard kills (`kill -9`) and tip disconnects are normal. **Corrupt files are not repaired in-process** — reindex / redo IBD.

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
| 5. Spend annotations (Direct) | After tip; spentness filters use strong+fence |

`is_confirmed_strong(tx)` ⇔ strong ∧ height fence contains the fk. Queries that mean “on best chain” use this (or equivalent). Confirmed-tx **API** readers pin that tip (`Query::pin_chain_view` / `still_live`) and retry on disconnect rather than pausing the writer — [`concurrency.md`](./concurrency.md#confirmed-tx-readers-pin--retry-not-a-lock).

On open (in order):

1. Soft `store/tip_seal` (if present): clamp confirmed tip that advanced without a complete barrier seal.
2. **Tip-window revalidate** (Core `checkblocks=6`): first drop any trailing null `confirmed[]` slots (HWM ahead of last real tip), then the last six confirmed heights — `prev_fk`/hash chain, `header_txs` range bounds, merkle root from `txid.body`, and those six runs all-strong. On failure: clear bad Class A association and/or shrink tip to last good height, rebuild the fence, flush confirmed.
3. One `repair_class_c_above_tip`: unstrong bits **not on the fence** via complement ranges (holes + suffix until a zero page). Does **not** walk every set bit. Logs `class_c repair cleared= ranges= ms=` even when zero.

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
- Annotations may remain after disconnect / for non-strong spenders.
- Best-chain spentness: annotation + `is_confirmed_strong(spender)`.
- Kill-safe: stale/non-strong fields do not false-positive if filter is applied.
- No `point.head` (v4 open-hash multimap removed).
- Class A is **three stems** (`txout` / `inwit` / `spent`); bare-meta puts are rejected. Packed `tx.body` with creates is refused on open.

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

Connect barrier (`flush_class_c_tip`): headers (if dirty) → strong → height → header_txs → **confirmed last** → soft `tip_seal`.
Disconnect: confirmed truncate + `flush_confirmed_only` (also refreshes `tip_seal`) before unstrong/height clear.

## Operator

- Direct IBD keeps segmented **`tx.head/`** (archive) and **spend annotations** (confirm) live; tip entry does **not** re-scan Class A to repair them. Corrupt head/spends ⇒ reindex (optional manual `backfill_tx_index` rebuilds segmented head mappings from Class A).
- **Segmented `tx.head`:** directory `tx.head/` with `meta` + open OA `NNNNNN`; sealed `NNNNNN.mphf` + `.fuse8`. Packed BDZ `g` is FdOnly (4 KiB page stream); MPHF output is `rel−1`. Flat `tx.head.meta` / `tx.head.NNNNNN` are **migrated into** `tx.head/` on open. Roll opens the next OA first; seal runs on a sidecar and publishes later. Kill mid-seal leaves **at most one** unsealed non-tail OA: open rebuilds fuse keys from Class A and seals it. Two unsealed non-tails is **Corrupt**. Wipe or empty occupancy + Class A: open rebuilds **MPHF+fuse8 directly** from `txid.body` in parallel (default **2²⁵** keys/range; `RBITCOIN_TX_HEAD_REBUILD_WORKERS`); no historical OA. Legacy mono `tx.head` file / `.new` / `.resize` are not opened — reindex.
- Scripthash: Direct IBD **defers** SH (no memtable, no confirm enqueue). After the horizon, one Class A pass writes unsorted `scripthash.unsorted/NN`, then unique-sort + seal. A **durable head** on restart stays Tip: write-behind / `recover_sh_writebehind` fills any HWM lag; leftover `scripthash.runs` are discarded (not WarmOnly-merged).
  - **Full cold** when head empty. **`RBITCOIN_SH_FORCE_REBUILD=1`:** wipe head + full Class A collect + unsorted pack. Empty collect after Class A creates remain is fatal.
  - **Cold resume:** sealed `scripthash.head/NN` is the commit (holes stay). Incomplete collect (no `DONE`) restarts the Class A pass. `DONE` + sealed heads: pack only unsealed files (in-place unique-sort ~2 GiB/worker). After all shards seal, the unsorted dir is removed.
  Empty head + leftover catalog: wipe leftover runs + SEAL, then Class A collect (not k-way from `scripthash.runs`). Durable head: leftover runs are discarded, `SEAL` kept; missing `include_hwm` bootstraps from SEAL. Inclusion HWM: `scripthash.include_hwm`. **Leftover live OA** at `scripthash.head` (or non-`SHSR` `ovf/NNNNNN`): refuse — wipe `store/scripthash*` and restart with `--shindex`.
  **SH head open:** sealed **main** shards load `.idx` only (one entry per 128
  records; no fuse). Sealed **ovf** loads `.idx` + BF8R. Occupancy scan is not
  used on those files. A schema-14 page-era durable index is **refused** (wipe
  `store/scripthash*` and rematerialize). Ingest OA still uses `{ingest}.occ`.
