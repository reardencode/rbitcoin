# Concurrency model (store / IBD / tip follow)

Short map of who may write which tables. **Format is unstable until 1.0.**

## Roles during IBD

| Role | Threading | Store writes |
|------|-----------|--------------|
| Peer IO (N tasks) | tokio multi-thread | none; decoded blocks **offer body queue only**; note height/hash readiness on confirm feed |
| Confirm **lookup** | 1 OS thread | pack/hold from BQ stamped Σ inputs; emit: decode BQ raw + TipOnly `head_fk` + **`take_raw` onto loadq** (`Arc<Block>` + `TxPrecompute`). Does **not** plan_batch / structure |
| Confirm **load** | 1 OS thread | `confirm_wire_lookup_stamp` (structure with **loadq `pres`**, plan_batch, skeleton bind) + pin `txout` + assemble |
| Confirm **scripts** | 1 OS thread (`ibd-confirm`) publishes waves + `rbtc-scripts` steal (lock-free claim) | **none** — pure CPU |
| Confirm **write** | 1 OS thread (`ibd-confirm-write`) + 1 process-wide `ibd-confirm-head` | **sole Class A appender** (`txout`+`inwit`+`spent`; IBD encodes ins from `Arc<Block>` + SpendEdges) + structural + Class C + spend annotate on **`spent.body`** + tip GC; **`block_queue_dequeue_height`**. `tx.head` write-behind insert runs on **`ibd-confirm-head`** overlapping structural + Class C (not a per-batch spawn). Class A **never leads tip** (same commit era; no archive-ahead DONTNEED) |
| IBD main loop | 1 tokio task | none (orchestration only) |

**IoSession TLS:** one completion session per OS thread (`with_thread_local`). Harvest / poison / drain / do-not-flatten: [`io-modality.md`](./io-modality.md). `RBITCOIN_IO=pread` disables the session. SH k-way merge submits 256 KiB ahead preads on that TLS session and waits only when promote needs a page that has not completed.

**Height-ordered unified pipeline (current):** peer → **body queue** (raw only) → **lookup** (in-order from `max(path_lo, lookup_taken_hi+1)`; decode + TipOnly `head_fk`; **dequeue** raw into `loadq=14`). Hole/densify/receive: in-hand = confirmed ∨ BQ hash ∨ `H ≤ lookup_taken_hi` → **load** (recv load-sized batch; stamp + pin + assemble) → scripts → write. Stage IO: [`invariants.md`](./invariants.md). **No** peer→confirm-feed wire retain. **No** hash-only / Class-A-only confirm (bq wire required). Load bind order is same-batch → in-flight → load-batch skeleton → Corrupt (plan=None leftover TipOnly). Lookup does not own a published identity chain. Write drain inserts `tx.head` in parallel with Class C on the process-wide `ibd-confirm-head` thread. Drain complete is max inserted **fk** (not tip/fence — those advance during drain). Header-cache GC polls store tip every load pack. In-flight prune is **after the last load batch of a lookup wave finishes its in-flight read**, using the drain+fence height snapshotted before that wave's TipOnly (`docs/invariants.md`). No leftover pending map. Bodies without a known height are marked missing and re-getdata after the height map is ready — there is **no** dual-track archive-job / ContigPark fallback. Load pack **waits** on `feed.cv` when tip+1 is in `ready` but the BQ is not resolve-complete (no retain/BQ spin). Pack takes the feed mutex to collect candidates and again to mark inflight; one BQ `pack_snapshot` in between.

**Load claim pack size:** soft **Σ `tx.input`** budget (hardcoded **8000**; include overshoot block) or hard **144** blocks. Also stop a `LoadBatch` before the next height when `header_txs.has_body` differs from the part's first height (crash some→none). Lookup may still decode a mixed resolve wave; loadq chunks are one kind. Dense mainnet blocks hit the input soft stop after **typically a few blocks** (often 1–3); early tiny blocks may pack many until the hard cap. Do **not** treat ~32 as pack size (that was 8000/250 mid-chain, not fat-era).

**IBD lookup resolve wave:** TipOnly `head_fk` bounded by remaining loadq slots × load pack (safety cap **1080** heights / soft **64000** inputs; include-overshoot; 256 k unique-key safety cap). Decode parks as resolved BQ rows; `taken_hi` bumps **per load-batch send**. Unsent tail stays on the BQ (no re-decode). Hard **min 8000** inputs per wave when more unresolved heights can still join — including `ready=0` / load-frontier / unknown window. Last available thin wave still emits. Each load chunk carries a `BatchParentIds` skeleton (shared wave ids/spent + per-chunk need-vouts). Same-wave creates are omitted from TipOnly need. When `ready >` half the 1-min BQ window, lookup waits for a full wave instead of minting a 1-block layer — unless the first unresolved height is within `path_lo + win/2` **and** the collect is already ≥8000 inputs (load is about to claim it; O(1) from the already-sorted unresolved list). Pack/hold uses enqueue-stamped `n_inputs` (peer CompactSize walk). `wave_intake` does **not** clone raw payloads; decode clones `raw_payload(height)` only on emit. Hold is `decode=0` / `precompute=0`. `lookup_thr wave=(decode= precompute= collect= head= spent=)`: `precompute=` is `from_tx_connect` below milestone or `from_tx` when scripts run; `head=` is TipOnly `get_fk_by_txid_batch`, not load stamp; `spent=` is `tx_spent_range_batch` for hits.

**`ibd: perf`:** `load=` is pin+assemble only. Load OS-thread `stamp=` nests `pack=` (plan HashMap) vs `head=` (leftover TipOnly `prep_head_fk_ns`). IBD skeleton keeps `head=` ~0. `stamp_sub struct_txid=` must be **0** on IBD (loadq `pres`). Non-zero means load dropped lookup hashes and `from_tx`'d again. Post-stamp in-flight drop on the last load batch of a wave is `prune=` (height-index remove; IBD has no pstore Weak walk). Lookup-wave `decode=` / `precompute=` / `collect=` / `head=` / `spent=` nest under `lookup_thr wave=`. Pin names `thin=` for the vout-map prefix. `script=` is per-batch wave wall on `ibd-confirm` (`jobs=`/`skip=`). Steal claim is an `ArcSwap` snapshot + `fetch_add(32)` (no `WAVES` mutex per job; `in_wave` counts in-flight chunks). The scripts thread publishes another `scriptq` batch when steal is empty (up to 4 in-flight, matching `scriptq`) and parks until a worker unparks it on wave complete (load also unparks on `scriptq` send). `script=` stamps when the wave first reports complete, not at write-queue pop. Write snapshot-drains the whole **writeq** (cap 14) so one `flush_class_c_tip` covers the queued run. `append_contiguous` stops when `archive_plan` polarity differs (`Some` vs `None`); leftover is the next meta-batch. `ready>0` + `scriptq=1` + high `stamp=` `head=` means leftover on load, not a hungry script pool. High `stamp=` `pack=` with `head=0` is HashMap CPU on load (leave it there; lookup is already the wave). Do not retune steal or borrow `rbtc-scripts-*` for decode. Sptweak secp
may publish a **background** wave (`try_for_each_parallel_idle`) claimed
only when no foreground wave and no detached job are waiting. Process restart leftover is empty RAM identity (horizon does not survive).

**Tip follow / reorg:** peer reconstructs on the session task, then offers the body to the process-wide **`tip-accept`** OS thread (bounded queue 8, oneshot wait). That thread is the sole production owner of `connect_lock` / `accept_and_connect_block_preverified` / `confirm_wire_run_preverified` at tip (1-block, or one `accept_branch` run). Scripts still publish via `start_for_each_owned` → `rbtc-scripts-*` steal — same as IBD’s publisher, not a second interpreter. Disconnect keeps Class A archive; re-extension always supplies **wire** from the peer, not hash-only load. **IBD most-work reorg** rewinds the tip to the LCA (`rewind_to_height`) from the **IBD orchestration task only** — never from confirm lookup/load/scripts/write threads — then the confirm pipeline connects the winner as a linear extension. `accept_branch` remains for tip-follow / held-body apply (also on `tip-accept`). Selector / rewind / invalid-heavy: [`architecture.md`](./architecture.md#most-work-chain-selection-ibd--tip-follow).

**Wire retained on the pipeline batch only:** lookup/load pull `bitcoin::Block` from the body queue; that wire rides through scripts; **no Class-A wire rebuild**. Script jobs carry lookup `TxPrecompute` (no job `from_tx`). Split Class A (`txout` / `inwit` / `spent`) is planned once and committed in the write stage.

**Body queue:** process-local **in-RAM** FIFO (id / height / hash / header_fk / raw charge) plus a first-wins **height → id** map. Height APIs (`is_resolve_complete`, `get_by_height`, `hash_at_height`, pack snapshot) do not walk `index.values()`. Peer copies wire **then** locks and enqueues **raw**; lookup decodes and parks resolved, then **dequeues** on load-batch send into **loadq** (`LoadBatch`). Load stamp consumes that `pres` — it does **not** read `block_queue_resolved`. **Never both** raw and decoded. **Offer** on peer Block → RAM; lookup takes; write **dequeue** is a no-op if the row is already gone. Restart starts empty (legacy `store/block_queue/` is best-effort removed). Soft densify assign, never-refuse-enqueue, why RAM: [`ibd-memory.md`](./ibd-memory.md).

**Pipeline pins:** plan `batch_pin` / `BatchParents` only (no process create FIFO). Stamp staging (`external_parents`) is **frozen/cleared after pin** (`ArchiveWritePlan::freeze_after_pin`) so write batch concatenates `batch_pin` / `planned_fks` / SpendEdges (IBD packed ins are empty; write fills from wire). Outs live in `BatchParents` — not a third plan-local outs map. `SharedParentPin` vacant insert stores Frozen outs/layout halves; first real compose promotes that half to `ArcSwap` (RCU; no-op cover stays Frozen; no in-place mutation). `BatchParents` sticky-caches the last outs Arc for multi-input assemble. `get_parent_txout_parts` holds that Arc and yields `&[u8]`; IBD assemble below milestone counts sigops from the borrow (no `ScriptBuf::from_bytes`); scripts-on still clones into jobs. Pack `pending_spent` is `OutPointSet` (folds every hasher write — `TxidHasher` would drop the txid when vout arrives). IBD `pin(... range_fill= contract=)` names residual pin wall. ConfirmParentCache holds tip-ahead **Arc** header plans only (insert/replace/drop under tip GC). In-flight lifetime / prune: [`invariants.md`](./invariants.md). Not a coins cache / spend FIFO.

**tx.head (segmented):** see [`heads.md`](./heads.md). Lookup: live pin by
txid → hot (open + ages ≤3) → ID/idx → cold (ages ≥4) if needed.
The 2-wave split is sealed age, not an IO flag.

**Datadir secret (schema 12):** `store/store.secret` CSPRNG at create. XOR scripts/witness at rest; keyed TXID mix for heads.

## Roles after IBD / tip follow

| Role | Notes |
|------|--------|
| `peer_session` (split read/write) | Serve + reconstruct compact/body. Offers reconstructed blocks to **`tip-accept`** (does **not** take `connect_lock` or run confirm on the tokio worker). 50 ms tick calls `PeerHub::on_session_heartbeat` (headers-sync stall timeout). Inbound accept is `inbound_connect_and_handshake` (60 s VERSION/VERACK); timeout drops the `max_inbound` permit. |
| `tip-accept` | **One** process-wide OS thread. Queue depth 8. Sole production thread for `accept_block` / `accept_branch` / `accept_received_block` / `generate_to_script` / `connect_lock` at tip. Confirm is **`confirm_wire_run_preverified`** (lookup stamp, load pin/assemble, `confirm_scripts_phase` → `rbtc-scripts-*`, write + `ibd-confirm-head` drain). TLS uring is this thread’s `with_thread_local` session. SIGINT stays on tokio; the current job finishes, then the session sees shutdown. |
| `rbtc-sh-wb` | **One** Class B scripthash appender. Used for tip follow **and** short catch-up when a durable SH head already exists. Confirm enqueues RAM records; `connect_at` / `note_confirmed_tip` **release** after `tip_tx`. This thread `put_create_batch_append` only for released heights, then advances `sh_indexed_through`. Apply errors re-queue and halt. Post-IBD Class A collect uses pack sessions (not a second appender); it runs while still Direct so this thread no-ops. |
| Electrum / Esplora | Confirmed SH reads join durable index **plus a RAM SH head** (pending jobs keyed by scripthash) and pin that visible height (live tip while jobs sit, never above published tip). A tx is in mempool overlay **or** SH (pending/durable), not both and not neither. Reorg reaccepts then drops pending. Headers subscribe is live tip. |
| Epoch finalize | Single-threaded control path; flushes table maps / fd durability |

## Index modes (`IndexMode`)

| Mode | When | Spentness | Durable `tx.head` / spends | SH |
|------|------|-----------|----------------------------|-----|
| **Direct** | IBD (`enter_direct_index_mode`) | confirmed-strong annotations | commit-stage head insert; spend annotate in same stage | Class A collect → unsorted shards → seal at tip |
| **Tip** | after IBD (`enter_tip_mode`) | confirmed-strong annotations | live heads + confirm spends | write-behind after tip commit (may lag live tip by 1+ blocks) |

Do not enter Tip until IBD catch-up complete: no best-chain remainder
(ordered / `height_to_hash` above tip / BQ ready ahead / awaiting reorg /
on-path getdata) and path high water at or within 1 of max peer height
(one-block version chatter only when `headers_done`). Competing
`hash_height` and leftover explore getdata are not remainder. Tip entry
bulk-materializes SH (Class A collect → unsorted per-shard files →
in-place unique-sort + seal `scripthash.head/NN`; pack workers capped at
one per 2 GiB host free RAM). Shared file `scripthash.body`
is one writer. Overflow body
is one writer (ingest / compact). It does **not** rebuild `tx.head` or
spend annotations.

## Locks (exceptions only)

**Default is lock-free** on table hot paths:

| Mechanism | What it replaces |
|-----------|------------------|
| Capacity grow (`TableFile`) | No map epochs; fallocate/`set_len` only; readers use published HWM (Acquire) |
| Atomic `count` / HWM | Publish barrier (Acquire readers / Release appender) |
| Role exclusivity | One appender, one annotator — not a global store mutex |
| `tx.head` insert | **Sole writer**: page-coalesced `pwrite` + `published_len` Release (no CAS, no CPU fence). Role exclusivity — not multi-inserter safe |
| `tx.head` segment seal | Roll opens the next OA immediately; BDZ+fuse8 runs on a sidecar. Lookup probes every unsealed OA until publish. Write joins the sidecar only on the *next* roll, `flush`, or `Drop` (not on the rolling insert). |
| `header.head` overflow | Insert past 7/8 rolls `header.head.gN` (new empty file). Occupied rewrite is open-only: undersized single gen writes `header.head.grow` then rename. |
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
| Buried / as-of | `pin_chain_view_at(hash)` for a still-live ancestor. Esplora `?asof=`; Electrum trailing `asof:<hash>` after `server.version` dialect `1.4.2-asof`. Stamp is that hash. If it leaves the tip chain: 404 / `asof not on chain` — **do not** retry onto another block at the same height |
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
   The **load thread** holds a **reserved create-fk HWM** and the **in-flight map** from
   uncommitted plans (`WireLoadPipeline` / `archive_plan_batch_from_wire`). First height
   of a batch is the **pipeline path_lo** (tip+1 or last-loaded+1), not only store tip.
   Write still applies batches in height order; on permanent reject, lookup clears
   reserved state and re-syncs from `txs.count()`.
5. On SIGINT, IBD cancels cooperatively — do not drop nested runtimes mid-await.

## Host freezes / IO storms

Single Class A writer is intentional. Multi‑GiB **FdOnly grow** is fallocate-only
(no remap). Hash heads do not rewrite occupied tables while serving; a leftover
undersized `header.head` may be **rewritten via `header.head.grow` then rename** once on open. Class C tip tables use L2
write-behind (`flush_class_c_tip` before BQ dequeue); large tables stay L0.
See **[io-modality.md](./io-modality.md)** for operator IO levers.

### Confirm load read pipeline

Cold parent `txout.idx` / `txout.body` on the **load** thread uses
**FdOnly idx + bulk body** (`idx_body_pipeline` → `bulk_io` uring/pread). Batch
creates come from **wire**, not a second Class A full-decode pass.
