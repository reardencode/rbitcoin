# Concurrency model (store / IBD / tip follow)

Short map of who may write which tables. **Format is unstable until 1.0.**

## Roles during IBD

| Role | Threading | Store writes |
|------|-----------|--------------|
| Peer IO (N tasks) | tokio multi-thread | none; decoded blocks **offer body queue only**; note height/hash readiness on confirm feed |
| Confirm **lookup** | 1 OS thread | decode BQ raw + TipOnly `head_fk` + **`take_raw` onto loadq** (`Arc<Block>` + `TxPrecompute`). Does **not** plan_batch / structure |
| Confirm **load** | 1 OS thread | `confirm_wire_lookup_stamp` (structure with **loadq `pres`**, plan_batch, leftover TipOnly) + pin `txout` + assemble |
| Confirm **scripts** | 1 OS thread (`ibd-confirm`) publishes waves + `rbtc-scripts` steal (lock-free claim) | **none** — pure CPU |
| Confirm **write** | 1 OS thread (`ibd-confirm-write`) + 1 process-wide `ibd-confirm-head` | **sole Class A appender** (`txout`+`inwit`+`spent`) + structural + Class C + spend annotate on **`spent.body`** + tip GC; **`block_queue_dequeue_height`**. `tx.head` write-behind insert runs on **`ibd-confirm-head`** overlapping structural + Class C (not a per-batch spawn). Class A **never leads tip** (same commit era; no archive-ahead DONTNEED) |
| IBD main loop | 1 tokio task | none (orchestration only) |

**IoSession TLS:** one completion session per OS thread (`with_thread_local`). Nested calls panic. Harvest tracks pending `(kind, epoch, slot)`; unexpected CQE / undrained leftover / CQ overflow is `Corrupt`, not a TipOnly miss. Drain before SQE buffers drop (spend annotate / k-way merge `DrainOnDrop`). Backends: Linux `io_uring` (per thread), portable `pool` (Darwin default; **one process worker set**, per-session CQE queues), Windows IOCP. `RBITCOIN_IO=pread` disables the session. SH k-way merge submits 256 KiB ahead preads on that TLS session and waits only when promote needs a page that has not completed.

**Height-ordered unified pipeline (current):** peer → **body queue** (raw only) → **lookup** (in-order from `max(path_lo, lookup_taken_hi+1)`; decode + TipOnly `head_fk`; **dequeue** raw into `loadq=14`). Hole/densify/receive: in-hand = confirmed ∨ BQ hash ∨ `H ≤ lookup_taken_hi` → **load** (recv load-sized batch; stamp + pin + assemble) → scripts → write. Stage IO: [`invariants.md`](./invariants.md). **No** peer→confirm-feed wire retain. **No** hash-only / Class-A-only confirm (bq wire required). Load bind order is in-flight → published `live_union` chain → TipOnly (fence-connected). Lookup owns `live_union`; one `ArcSwap` of the layer-chain head per wave; get walks layers (no union rebuild); a layer stays while any height in its span is on the BQ **or** `tip − hi < recent_creates_horizon` (`2×soft_win`); disconnect stores None. Write drain inserts `tx.head` in parallel with Class C on the process-wide `ibd-confirm-head` thread. Drain complete is max inserted **fk** (not tip/fence — those advance during drain). Header-cache GC polls store tip every load pack. In-flight prune is **after pin + scripts handoff**: drain-fk **and** `covers_fk_span` (TipOnly home — `docs/invariants.md`). No leftover pending map. Bodies without a known height are marked missing and re-getdata after the height map is ready — there is **no** dual-track archive-job / ContigPark fallback. Load pack **waits** on `feed.cv` when tip+1 is in `ready` but the BQ is not resolve-complete (no retain/BQ spin). Pack takes the feed mutex to collect candidates and again to mark inflight; one BQ `pack_snapshot` in between.

**Load claim pack size:** soft **Σ `tx.input`** budget (hardcoded **8000**; include overshoot block) or hard **144** blocks. Dense mainnet blocks hit the input soft stop after **typically a few blocks** (often 1–3); early tiny blocks may pack many until the hard cap. Do **not** treat ~32 as pack size (that was 8000/250 mid-chain, not fat-era).

**IBD lookup resolve wave:** TipOnly `head_fk` over at most **1080** BQ-ready heights or soft **64000** inputs (include-overshoot; 256 k unique-key safety cap), then mark those complete for load to claim. Hard **min 8000** inputs per published layer when more unresolved heights can still join — including `ready=0` / load-frontier / unknown window. Last available thin wave still emits. One published identity layer per wave; get walks the chain (no union rebuild). When `ready >` half the 1-min BQ window, lookup waits for a full wave instead of minting a 1-block layer — unless the first unresolved height is within `path_lo + win/2` **and** the collect is already ≥8000 inputs (load is about to claim it; O(1) from the already-sorted unresolved list). `wave_intake` does **not** clone raw payloads for the 1080-cap list; decode clones `raw_payload(height)` only for heights this wave processes. `lookup_thr wave=(decode= precompute= collect= head=)`: `head=` is TipOnly `get_fk_by_txid_batch`, not load stamp.

**`ibd: perf`:** `load=` is pin+assemble only. Load OS-thread leftover TipOnly is `load_thr stamp=`; `stamp_sub struct_txid=` must be **0** on IBD (loadq `pres`). Non-zero means load dropped lookup hashes and `from_tx`'d again. Post-scriptq in-flight drop is `prune=` (layer retain + O(1) pstore counters; no slot walk). Lookup-wave `decode=` / `precompute=` / `collect=` / `head=` nest under `lookup_thr wave=`. Pin names `thin=` for the vout-map prefix. `script=` is per-batch wave wall on `ibd-confirm` (`jobs=`/`skip=`). Steal claim is an `ArcSwap` snapshot + `fetch_add(32)` (no `WAVES` mutex per job; `in_wave` counts in-flight chunks). The scripts thread publishes another `scriptq` batch when steal is empty (up to 4 in-flight, matching `scriptq`) and parks until a worker unparks it on wave complete (load also unparks on `scriptq` send). `script=` stamps when the wave first reports complete, not at write-queue pop. Write snapshot-drains the whole **writeq** (cap 14) so one `flush_class_c_tip` covers the queued run. `ready>0` + `scriptq=1` + high `stamp=` means leftover on load, not a hungry script pool. Do not retune steal or borrow `rbtc-scripts-*` for decode. Sptweak secp
may publish a **background** wave (`try_for_each_parallel_idle`) claimed
only when no foreground wave and no detached job are waiting. Process restart leftover is empty RAM identity (horizon does not survive).

**Tip follow / reorg:** peer wire via `ChainHub::accept_block` / `accept_branch` → `accept_and_connect_block` (same wire load path with cold denserels allowed on the one-shot call). Disconnect keeps Class A archive; re-extension always supplies **wire** from the peer, not hash-only load. **IBD most-work reorg** rewinds the tip to the LCA (`rewind_to_height`) from the **IBD orchestration task only** — never from confirm lookup/load/scripts/write threads — then the confirm pipeline connects the winner as a linear extension. `accept_branch` remains for tip-follow / held-body apply. Selector / rewind / invalid-heavy: [`architecture.md`](./architecture.md#most-work-chain-selection-ibd--tip-follow).

**Wire retained on the pipeline batch only:** lookup/load pull `bitcoin::Block` from the body queue; that wire rides through scripts; **no Class-A wire rebuild**. Script jobs carry lookup `TxPrecompute` (no job `from_tx`). Split Class A (`txout` / `inwit` / `spent`) is planned once and committed in the write stage.

**Body queue:** process-local **in-RAM** FIFO (id / height / hash / header_fk / raw charge) plus a first-wins **height → id** map. Height APIs (`is_resolve_complete`, `get_by_height`, `hash_at_height`, pack snapshot) do not walk `index.values()`. **Why RAM:** avoid **double disk write** of every block (queue then Class A); accept **redownload on restart** and peak RAM of soft depth. Peer copies wire **then** locks and enqueues **raw**; lookup **`take_raw`** (deletes the row) and puts `Arc<Block>` + `TxPrecompute` on **loadq** (`LoadBatch`). Load stamp consumes that `pres` — it does **not** read `block_queue_resolved`. **Never both** raw and decoded. **Primary capacity is soft densify assign** (no hysteresis): under ~100 MiB free densify ahead; over ~100 MiB only heights confirm will consume in the next ~1 min at tip rate. Soft assign keys off raw `bytes()`. Optional absolute byte ceiling via `RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES` (default unlimited). Height horizon (`CONTIG_DENSIFY_AHEAD`, 64 k past tip) caps densify/receive walk. **Offer** on peer Block → RAM; lookup takes; write **dequeue** is a no-op if the row is already gone. Restart starts empty (legacy `store/block_queue/` is best-effort removed).

**Pipeline pins:** plan `batch_pin` / `BatchParents` only (no process create FIFO). Stamp staging (`external_parent_ranges` / `external_parent_txids`) is **frozen/cleared after pin** (`ArchiveWritePlan::freeze_after_pin`) so write batch only concatenates commit halves. Outs live in `BatchParents` / pstore — not a third plan-local outs map. `SharedParentPin` publishes immutable outs/layout halves via `arc_swap::ArcSwap` (compose + RCU; no in-place mutation). `BatchParents` sticky-caches the last outs Arc for multi-input assemble. IBD `pin(... adopt= range_fill= contract= publish=)` names residual pin wall. ConfirmParentCache holds tip-ahead **Arc** header plans only (insert/replace/drop under tip GC). **RecentCreates** is write-published identity (`txid → fk+range`, `ArcSwap` snapshot) after Class A+idx, **one fifo row per prepared height**, **one snapshot publish per write batch**; load stamp reads a **dirty overlay** then the published Arc so unflushed notes still skip leftover TipOnly. Height-FIFO expire `2×soft_win` (floor 256). Published identity layers use the same horizon after their BQ span leaves. Not a pin/outs FIFO.

**tx.head (segmented):** see [`heads.md`](./heads.md). Lookup: live pin by
txid → hot (open + ages ≤3) → ID/idx → cold (ages ≥4) if needed.
The 2-wave split is sealed age, not an IO flag.

**Datadir secret (schema 12):** `store/store.secret` CSPRNG at create. XOR scripts/witness at rest; keyed TXID mix for heads.

## Roles after IBD / tip follow

| Role | Notes |
|------|--------|
| `peer_session` (split read/write) | Serve reconstruct + accept tip blocks via **`accept_and_connect_block`** → **`confirm_wire_run`** (same load→scripts→commit) |
| Electrum | Read-mostly; joins Class A + scripthash under `Query` |
| Epoch finalize | Single-threaded control path; flushes table maps / fd durability |

## Index modes (`IndexMode`)

| Mode | When | Spentness | Durable `tx.head` / spends | SH |
|------|------|-----------|----------------------------|-----|
| **Direct** | IBD (`enter_direct_index_mode`) | confirmed-strong annotations | commit-stage head insert; spend annotate in same stage | append-only target-sized runs + SEAL → bulk at tip |
| **Tip** | after IBD (`enter_tip_mode`) | confirmed-strong annotations | live heads + confirm spends | durable write-through after bulk |

Do not enter Tip until tip ≈ peer height. Tip entry bulk-materializes SH
(runs → optional fan-in reduce → sliced k-way per prefix shard, workers
capped at one per 1.5 GiB host free RAM, writing `scripthash.body/NN`
and sealing `scripthash.head/NN` themselves). Shared file `scripthash.body`
is one writer. Overflow body
is one writer (ingest / compact). It does **not** rebuild `tx.head` or
spend annotations.

## Locks (exceptions only)

**Default is lock-free** on table hot paths (see `AGENTS.md`):

| Mechanism | What it replaces |
|-----------|------------------|
| Capacity grow (`TableFile`) | No map epochs; fallocate/`set_len` only; readers use published HWM (Acquire) |
| Atomic `count` / HWM | Publish barrier (Acquire readers / Release appender) |
| Role exclusivity | One appender, one annotator — not a global store mutex |
| `tx.head` insert | **Sole writer**: page-coalesced `pwrite` + `published_len` Release (no CAS, no CPU fence). Role exclusivity — not multi-inserter safe |
| `tx.head` segment seal | Roll opens the next OA immediately; BDZ+fuse8 runs on a sidecar. Lookup probes every unsealed OA until publish. Write joins the sidecar only on the *next* roll, `flush`, or `Drop` (not on the rolling insert). |
| Process `rehash_gate` | Rare multi‑GiB open-hash rehash (host freeze prevention) |
| `ChainHub::confirmed` | `RwLock<HashSet>` for O(1) `has_block` (IBD assign path) |

There is **no** global “pause queries during confirm write.” Tip-as-commit +
`is_confirmed_strong` define query visibility ([`crash-recovery.md`](./crash-recovery.md)).

### Confirmed-tx readers: pin + retry (not a lock)

Wallet APIs (Electrum / Esplora) must not mix two chain prefixes in one
response, and they must tell the client **which tip hash** the body belongs
to. Yuval brought the A-B-A hole to our attention (same height, different
block, silent status). The shape we ship follows
[mempool/mempool#6584](https://github.com/mempool/mempool/issues/6584)
(HTTP tip-hash header on every response) and the Electrum 1.7
`chaintip` discussion in
[spesmilo/electrum-protocol#2](https://github.com/spesmilo/electrum-protocol/pull/2)
(added, then reverted in
[#17](https://github.com/spesmilo/electrum-protocol/pull/17) because ElectrumX
cannot pin bitcoind RPC — we can).

| Rule | Detail |
|------|--------|
| Pin | `Query::pin_chain_view` captures `{height, hash, header_fk}` of published tip |
| Buried / as-of | `pin_chain_view_at(hash)` for a still-live ancestor. As-of APIs stamp that hash. If it leaves the tip chain: 404 / `asof not on chain` — **do not** retry onto another block at the same height |
| Filter | SH join uses `is_confirmed_strong_at(fk, view.height)`; slot keys on **hash** |
| Live-check | `ChainView::still_live` ⇔ `confirmed[height] == header_fk` |
| Extension | Prefix pin stays live; creates above the pin are filtered |
| Disconnect / same-height replace | Live pin dies; `run_at_chain_view` retries (bound 8) then `StoreError::Stale` |
| Not OK | Pause queries during write, MVCC Class C, serving a disconnected hash |

API tokens: [`COMPAT.md`](../COMPAT.md) (Esplora headers, Electrum JSON-RPC extra members, status preimage).

## Practical rules

1. Do **not** spawn a second Class A writer while IBD confirm write is running.
2. Pipeline depth: lookup(N+1) ∥ load(N) ∥ scripts(N−1) ∥ write(N−2) via BQ `ready=` + bounded scriptq/writeq.
3. Scripts for batch N may run while load does N+1 and write does N−1. Scripts never touch disk.
4. **Load ahead of store tip:** lookup may stamp batch N+1 while write has not advanced tip.
   Lookup holds a **reserved create-fk HWM** and **in-flight create/out maps** from
   uncommitted plans (`WireLoadPipeline` / `archive_plan_batch_from`). First height
   of a batch is the **pipeline path_lo** (tip+1 or last-loaded+1), not only store tip.
   Write still applies batches in height order; on permanent reject, lookup clears
   reserved state and re-syncs from `txs.count()`.
5. On SIGINT, IBD cancels cooperatively — do not drop nested runtimes mid-await.

## Host freezes / IO storms

Single Class A writer is intentional. Multi‑GiB **FdOnly grow** is fallocate-only
(no remap), but **hash-head rehash** (header / scripthash shards when materializing)
can still stall the **host** (page cache / disk). Class C tip tables use L2
write-behind (`flush_class_c_tip` before BQ dequeue); large tables stay L0.
are small. See **[io-modality.md](./io-modality.md)** for operator IO levers.

### Confirm load read pipeline

Cold parent `txout.idx` / `txout.body` on the **load** thread uses
**FdOnly idx + bulk body** (`idx_body_pipeline` → `bulk_io` uring/pread). Batch
creates come from **wire**, not a second Class A full-decode pass.
