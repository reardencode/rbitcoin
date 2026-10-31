# Concurrency model (store / IBD / tip follow)

Short map of who may write which tables. **Format is unstable until 1.0.**

## Roles during IBD

| Role | Threading | Store writes |
|------|-----------|--------------|
| Peer IO (N tasks) | tokio multi-thread | none; decoded blocks **offer body queue only**; note height/hash readiness on confirm feed |
| Confirm **lookup** | 1 OS thread | pack/hold from BQ stamped Σ inputs; emit: decode BQ raw + TipOnly `head_fk` + **`take_raw` onto loadq** (`Arc<Block>` + `TxPrecompute`). Does **not** plan_batch / structure |
| Confirm **load** | 1 OS thread | `confirm_wire_lookup_stamp` (structure with **loadq `pres`**, plan_batch binds carried BQ keys, skeleton bind) + pin `txout` + assemble |
| Confirm **scripts** | 1 OS thread (`ibd-confirm`) publishes waves + `rbtc-scripts` steal (lock-free claim). The interpreter runs here, not on a peer IO task (`verify_tx_scripts_detached`) | **none** — pure CPU |
| Confirm **write** | 1 OS thread (`ibd-confirm-write`) + 1 process-wide `ibd-confirm-head` + one `rbtc-tip-flush` for the confirm engine (the Class C barrier) | **sole Class A appender** (`txout`+`seqsigwit`+`spent`; IBD encodes ins from `Arc<Block>` + SpendEdges) + structural + Class C (`ClassCWrite`, minted on this thread, not `Send`) + spend annotate on **`spent.body`** + tip GC; **`block_queue_dequeue_height`**. Archived-body clear is an item on this thread's channel: it joins the in-flight tip flush, then clears and flushes, before the next Class C store. The coordinator drops its state lock for that wait, then retakes the lock and marks the hash missing only when that hash still occupies the height. Header range puts on this path wait for that same join, including when a later phase rejects the batch. Class A body append still overlaps the flush. Class C still flushes once per confirm batch. `tx.head` write-behind insert runs on **`ibd-confirm-head`** (not a per-batch spawn). `--datadir-hdd` starts that insert after spend annotate; otherwise it overlaps structural and Class C. Class A **never leads tip** (same commit era on a clean run; no archive-ahead DONTNEED). A crash inside the era can leave it above the tip ([crash-recovery.md](./crash-recovery.md#class-a-archive)). When `index_live` is set, this thread appends that index after `confirmed[h]` is set (one put per confirm batch) and does not read Class A for it. Startup `prepare_live_indexes` seals a restart gap of at most one write drain (14 × 144 heights) before confirm; a larger gap is left for `rbtc-idx-wb` |
| IBD main loop | 1 tokio task | none (orchestration only; archived-body clear is sent to confirm-write, which stores it). Event drain + confirm-offer every turn; getdata assign ≤50 ms (immediate if inflight empty); main-loop `getheaders`/`locator_hashes` ≤500 ms (empty path immediate); peer stall/relative-slow and work-path hygiene ≤1 s. Full-batch header continuation stays on the Headers event. Tip hash is the snapshot confirm published with `confirmed[]` (`published_tip`); each admitted header's parent stays on the work state. Those two reads are not store IO. The write holds `tip_commit` from the tip-height check through `flush_class_c_tip`; in IBD, through starting it on `rbtc-tip-flush`, and the next `tip_commit` taker joins that flush first. IBD rewind tries that lock, and treats a flush still running as held, and retries on the next pass. |

**IoSession TLS:** one completion session per OS thread (`with_thread_local`). Harvest / poison / drain / do-not-flatten: [`io-modality.md`](./io-modality.md). `RBITCOIN_IO=pread` disables the session. SH k-way merge submits 256 KiB ahead preads on that TLS session and waits only when promote needs a page that has not completed.

**Height-ordered unified pipeline (current):** peer → **body queue** (raw only) → **lookup** (in-order from `max(path_lo, lookup_taken_hi+1)`; decode + TipOnly `head_fk`; **dequeue** raw into `loadq=14`). Hole/densify/receive: in-hand = confirmed ∨ BQ hash ∨ `H ≤ lookup_taken_hi` (Cancelled leaves taken_hi; every other post-lookup reject re-arms it at the confirmed tip; a load stamp, scripts, or write EngineFault re-offers the **full** batch including the first height after that re-arm and does not `request_single_block`; a load pin EngineFault retries one block at a time, as a cascade, since it can be a stale-fk plan race; a load reject bumps the feed epoch, so valid lower batches already in scripts or write are dropped and their bodies fetched again from peers — the price of a consistent restamp; epoch-stale loadq chunks re-offer on drop; BadPrev most-work rewind then sets the LCA) → **load** (recv load-sized batch; stamp binds carried BQ keys + BQ `header_fk` (skip header ensure/put when the store row matches) + pin + assemble) → scripts → write. Stage IO: [`invariants.md`](./invariants.md). **No** peer→confirm-feed wire retain. **No** hash-only / Class-A-only confirm (bq wire required). Load bind order is same-batch → in-flight → load-batch skeleton → Corrupt (plan=None leftover TipOnly). Lookup does not own a published identity chain. Class A sets loc once on the same `CreatePin` Arc load cloned into InFlight (`OnceLock`); later-wave stamp reads it (no disk loc-by-fk on that path). Header records are 88 B consensus fields. Block size and weight are stamped on `txstat`, not rewritten into `header.body`. Write drain inserts `tx.head` on the process-wide `ibd-confirm-head` thread, in parallel with Class C unless `--datadir-hdd` waits until after annotate. Drain complete is max inserted **fk** (not tip/fence — those advance during drain). Header-cache GC polls store tip every load pack. In-flight prune is **after the last load batch of a lookup wave finishes its in-flight read**, using the drain+fence height snapshotted before that wave's TipOnly (`docs/invariants.md`). No leftover pending map. Bodies without a known height are marked missing and re-getdata after the height map is ready — there is **no** dual-track archive-job / ContigPark fallback. Load pack **waits** on `feed.cv` when tip+1 is in `ready` but the BQ is not resolve-complete (no retain/BQ spin). Pack takes the feed mutex to collect candidates and again to mark inflight; one BQ `pack_snapshot` in between.

**Load claim pack size:** soft **Σ `tx.input`** budget (hardcoded **8000**; include overshoot block) or hard **144** blocks. Also stop a `LoadBatch` before the next height when `header_txs.has_body` differs from the part's first height (crash some→none). Lookup may still decode a mixed resolve wave; loadq chunks are one kind. Dense mainnet blocks hit the input soft stop after **typically a few blocks** (often 1–3); early tiny blocks may pack many until the hard cap. Do **not** treat ~32 as pack size (that was 8000/250 mid-chain, not fat-era).

**IBD lookup resolve wave:** TipOnly `head_fk` bounded by remaining loadq slots × load pack (safety cap **1080** heights / soft **64000** inputs; include-overshoot; 256 k unique-key safety cap). Decode parks as resolved BQ rows; `taken_hi` bumps **per load-batch send**. Unsent tail stays on the BQ (no re-decode). Hard **min 8000** inputs per wave when more unresolved heights can still join — including `ready=0` / load-frontier / unknown window. Last available thin wave still emits. Each load chunk carries a `BatchParentIds` skeleton (shared wave ids/spent + per-chunk need-vouts). Same-wave creates are omitted from TipOnly need. When `ready >` half the 1-min BQ window, lookup waits for a full wave instead of minting a 1-block layer — unless the first unresolved height is within `path_lo + win/2` **and** the collect is already ≥8000 inputs (load is about to claim it; O(1) from the already-sorted unresolved list). Pack/hold uses enqueue-stamped `n_inputs` (peer CompactSize walk). `wave_intake` does **not** clone raw payloads; decode clones `raw_payload(height)` only on emit. Hold is `decode=0` / `precompute=0`. `lookup_thr wave=(decode= precompute= collect= head= loc=)`: `precompute=` is `from_tx_wire` on payload slices (`sighash` midstates only when scripts run); `head=` is TipOnly `get_fk_by_txid_batch_cancellable` (one resolve; the confirm cancel is asked before each sealed segment and each identity shot), not load stamp; `loc=` is create.loc fill inside that TipOnly.

**`ibd: perf`:** one DEBUG line, `ibd: perf` plus a JSON object of `IbdPerfSample` (`ts` is unix milliseconds; zeros are included). A change on lookup, load, scripts, or write, or on a sidecar the write thread joins, adds a field on that struct in [`perf_log.rs`](../crates/rbitcoin-ibd/src/ibd/perf_log.rs) in the same commit. The field shows up because the struct serializes. JSON keys are the field names (`load_ms`, not a hand-written `load=` token). `load=` is pin+assemble only. Load OS-thread `stamp=` nests `pack=` (plan HashMap) vs `head=` (leftover TipOnly `prep_head_fk_ns`). IBD skeleton keeps `head=` ~0. `stamp_sub struct_txid=` must be **0** on IBD (loadq `pres`). Non-zero means load dropped lookup hashes and `from_tx`'d again. Post-stamp in-flight drop on the last load batch of a wave is `prune=` (height-index remove; IBD has no pstore Weak walk). A lone block's missing-parent check after a stamp miss (the wait for its parent to be the tip, the TipOnly read, and the unsynced-head scan) is `reject=`, not `prune=` ([089](./external_findings/089-missing-parent-verdict.md)). Lookup-wave `decode=` / `precompute=` / `collect=` / `head=` / `spent=` nest under `lookup_thr wave=`. Pin names `thin=` for the vout-map prefix. `script=` is per-batch verify wall on `ibd-confirm` (`jobs=`/`skip=`), the script-wave completion offset. `idx_asm=` is filter and tweak execution on the index wave (first index job through that wave's completion). It is not time queued behind scripts and it is not inside `script=`. `thr script work` is the stage wall: the later of those two completion offsets from batch start, not their sum. `idx_put=` is the write-thread index append and is inside `write=`. `tip_flush_wait=` is the commit waiting for the previous batch's `rbtc-tip-flush`; it is not inside `class_c_join=`. Steal claim is an `ArcSwap` snapshot + `fetch_add(32)` (no `WAVES` mutex per job; `in_wave` counts in-flight chunks). The scripts thread publishes another `scriptq` batch when both waves have nothing left to claim (up to 4 in-flight, matching `scriptq`) and parks until a worker unparks it on wave complete (load also unparks on `scriptq` send). `script=` stamps when script verify completes, not at write-queue pop. Write snapshot-drains the whole **writeq** (cap 14) so one `flush_class_c_tip` covers the queued run. `append_contiguous` stops when `archive_plan` polarity differs (`Some` vs `None`); leftover is the next meta-batch. `ready>0` + `scriptq=1` + high `stamp=` `head=` means leftover on load, not a hungry script pool. High `stamp=` `pack=` with `head=0` is HashMap CPU on load (leave it there; lookup is already the wave). Do not retune steal or borrow `rbtc-scripts-*` for decode. Process restart leftover is empty RAM identity (horizon does not survive).

**Tip follow / reorg:** peer reconstructs on the session task, then offers the body to the process-wide **`tip-accept`** OS thread (bounded queue 8, oneshot wait). That thread is the sole production owner of `connect_lock` / `accept_and_connect_block_preverified` / `confirm_wire_run_preverified` at tip (1-block, or one `accept_branch` run). Scripts still publish via `start_for_each_owned` → `rbtc-scripts-*` steal — same as IBD’s publisher, not a second interpreter. Disconnect keeps Class A archive; re-extension always supplies **wire** from the peer, not hash-only load. **IBD most-work reorg** rewinds the tip to the LCA (`rewind_to_height`) from the **IBD orchestration task only** — never from confirm lookup/load/scripts/write threads — then the confirm pipeline connects the winner as a linear extension. `accept_branch` remains for tip-follow / held-body apply (also on `tip-accept`). Selector / rewind / invalid-heavy: [`architecture.md`](./architecture.md#most-work-chain-selection-ibd--tip-follow).

**Wire retained on the pipeline batch only:** lookup/load pull `bitcoin::Block` from the body queue; that wire rides through scripts; **no Class-A wire rebuild**. Script jobs carry lookup `TxPrecompute` (no job `from_tx`). Split Class A (`txout` / `seqsigwit` / `spent`) is planned once and committed in the write stage.

**Body queue:** process-local **in-RAM** FIFO (id / height / hash / header_fk / raw charge) plus a first-wins **height → id** map (one row per height). `has_hash` is a hash→height map on that same mutex (no full-queue scan). Lookup's decoded stash is a **second** mutex: getdata enqueue and `has_hash` never take it, and row reads never take it. Height APIs (`is_resolve_complete`, `get_by_height`, `hash_at_height`, pack snapshot) do not walk `index.values()`. Peer copies wire **then** locks and enqueues **raw**; lookup decode borrows that queued `Arc` (it does not memcpy the frame) and parks resolved, then **dequeues** on load-batch send into **loadq** (`LoadBatch`). Load stamp consumes that `pres` — it does **not** read `block_queue_resolved`. **Never both** raw and decoded. **Offer** on peer Block → RAM (wire the input walk cannot decode is refused, never queued); lookup takes; write **dequeue** is a no-op if the row is already gone. A raw row that does not decode stops the lookup wave at that height; lookup dequeues it and emits a **SoftWire** reject so the hash is fetched again (never blacklisted). Restart starts empty (legacy `store/block_queue/` is best-effort removed). Soft densify assign, never-refuse-enqueue, why RAM: [`ibd-memory.md`](./ibd-memory.md).

**Pipeline pins:** plan `batch_pin` / `BatchParents` only (no process create FIFO). `freeze_after_pin` runs before pin and drops staging maps pin does not read (`external_parents`, `batch_creates`). Pin reads edges, `batch_pin`, `planned_fks`, and `per_header_ranges`. Write concatenates `batch_pin` / `planned_fks` / SpendEdges. Wire packed ins stay empty; write encodes seqsigwit from the wire transaction. A records row with empty ins is Corrupt. Outs live in `BatchParents` — not a third plan-local outs map. `SharedParentPin` vacant insert stores Frozen outs/layout halves; first real compose promotes that half to `ArcSwap` (RCU; no-op cover stays Frozen; no in-place mutation). `BatchParents` sticky-caches the last outs Arc for multi-input assemble. `get_parent_txout_parts` holds that Arc and yields `&[u8]`; IBD assemble below milestone counts sigops from the borrow (no `ScriptBuf::from_bytes`). Script jobs borrow script bytes (same-block from the wire block on the job, historical from the pin `Arc`) and do not clone `scriptPubKey`. Taproot sighash hashes those borrows inside `script=` and does not build `TxOut`. Pack `pending_spent` is `OutPointSet` (folds every hasher write — `TxidHasher` would drop the txid when vout arrives). IBD `pin(... range_fill= contract=)` names residual pin wall. ConfirmParentCache holds tip-ahead **Arc** header plans only (insert/replace/drop under tip GC). In-flight lifetime / prune: [`invariants.md`](./invariants.md). Not a coins cache / spend FIFO.

**tx.head (segmented):** see [`heads.md`](./heads.md). Lookup: live pin by
txid → hot (open + ages ≤3) → ID/idx → cold (ages ≥4) if needed.
The 2-wave split is sealed age, not an IO flag.

**Datadir secret (schema 12):** `store/store.secret` CSPRNG at create. XOR scripts/witness at rest; keyed TXID mix for heads.

## Roles after IBD / tip follow

Three thread kinds only. **Tokio workers must not wait on a `std` mutex/rwlock, store IO, or script verify** (`assert_not_reactor` / `BlockingRegion` on the blocking pool). Tokio names both workers and `spawn_blocking` threads `tokio-rt-worker`; blocking work enters `BlockingRegion`.

| Kind | Who | Notes |
|------|-----|--------|
| Reactor | `tokio-rt-worker` × nCPU | epoll, timers, framing. Node caps `spawn_blocking` at nCPU (min 4), not tokio’s 512. |
| Role | `tip-accept`, `ibd-header`, `ibd-confirm-*`, `rbtc-tip-flush`, `rbtc-sh-wb`, `rbtc-idx-wb` | Sole writer for a resource. Not a job pool. |
| Work pool | `rbtc-scripts-*` steal; tokio blocking pool | Independent jobs. Mempool script verify is awaited on the request task (`run_cpu`); prepare and commit run on `rbtc-off-pool`, not the blocking pool. Prepare takes one `--store-read-budget` permit and drops it before script verify. Electrum / Esplora / RPC / REST / BlindBit store joins still use the blocking pool, and they share that one budget. A waiter does not occupy a pool thread. `getblocktemplate` and Esplora `GET /block-template` sample the template tip on `rbtc-off-pool` before a store-read permit (Esplora also before its 15-second cache lock). Long-poll tip polls do the same and drop the permit before they sleep. Heavy v2 encode, compact short ids, and JSON of at least 4 KiB run on `rbtc-scripts-*`. |

| Role | Notes |
|------|--------|
| `peer_session` (split read/write) | Serve getdata. Full-block, compact, and `getblocktxn` reconstruct run on the blocking pool (block-decode permit). Inbound `cmpctblock` reconstruct uses that same permit. `headers` persist and `getheaders` / `getblocks` replies run on the blocking pool under the header-decode permit. The session applies notes, ban, and queued `getdata` after that join. Offers reconstructed blocks to **`tip-accept`** (does **not** take `connect_lock` or run confirm on the tokio worker). A reconstructed/received body whose header has valid PoW and **extends the current tip** is announced as `cmpctblock` to peers who sent `sendcmpct` announce=1 and already have the parent **before** connect (Core `NewPoWValidBlock`). That is not a connected tip. P2P `tx` is `accept_tx_from_async`: scripts are awaited on the session task, and prepare/commit run on `rbtc-off-pool`. INV / getdata / compact **first-pass** fill use mempool **`try_read` only** (busy write → skip that item; never park). A pending compact owns those clones; `blocktxn` apply does not `try_read` again. Handshake `FeeFilter` reads the **atomic** published fee floor (no `inner`). 50 ms tick: age-INV is a due-log cursor (newly due only); `clock_due` / unbroadcast may full-walk ≤1/30 s. `any_tx_inv_due` is min live `accept_at`, not a map walk. `PeerHub::on_session_heartbeat` (headers-sync stall timeout). While the writer is past the 4 MiB send budget, or a paused `getdata` tail waits for serve room, the reader reads no frame; the heartbeat still runs, so the ping timeout still fires. Inbound accept is `inbound_connect_and_handshake` (60 s VERSION/VERACK); timeout drops the `max_inbound` permit. |
| `tip-accept` | **One** process-wide OS thread. Queue depth 8. Sole production thread for `accept_block` / `accept_branch` / `accept_received_block` / `generate_to_script` / `connect_lock` at tip. HTTP `submitblock`, `generate*`, `invalidateblock`, `reconsiderblock`, `preciousblock`, and an SV2 solution await that thread. They do not occupy the work pool. A full queue waits on the request task. Mints `ClassCWrite` for that connect's Class C stores. Confirm is **`confirm_wire_run_preverified`** (lookup stamp, load pin/assemble, `confirm_scripts_phase` → `rbtc-scripts-*`, write + `ibd-confirm-head` drain). TLS uring is this thread’s `with_thread_local` session. SIGINT stays on tokio; the current job finishes, then the session sees shutdown. Dropping the session’s join future **detaches** (does not condvar-wait on the worker). |
| `ibd-header` | **One** thread for the catch-up. Persists header batches, loads the walk origin, and reseeds. Joined when IBD stops. |
| `rbtc-tip-flush` | **One** thread for the IBD confirm engine. Runs the Class C barrier. The next commit waits for the in-flight barrier. Joined when the engine stops. Tip mode flushes that barrier inline on `tip-accept`. |
| `rbtc-sh-wb` | **One** Class B scripthash appender. A durable `--sh-index` head starts it before catch-up. Direct catch-up starts it only after materialize enters Tip. Absent for the whole Direct catch-up, including a cancelled or failed materialize. Confirm enqueues RAM records; `connect_at` / `note_confirmed_tip` **release** after `tip_tx`. This thread `put_create_batch_append` only for released heights, then advances `sh_indexed_through`. Apply errors re-queue and halt. The Class A tail holds `sh.appender` and finishes inside tip entry before this thread starts. The same lock is the exclusion if a tail and the worker ever overlap. There is no process-local head map. |
| `rbtc-idx-wb` / `rbtc-idx-cpu` | **One** block index builder for BIP158 basic filters (`--block-filter-index`) and BIP-352 tweaks (`--sp-tweaks`), spawned at tip entry only when an enabled watermark is still behind the tip after startup repair. Live batches append on the confirm write thread; this reader does not walk a chain that was indexed as it connected. Waits on the same release gate as `rbtc-sh-wb` (`index_released_through`). The IO thread plans windows (≤64 heights / ≤50k creates) from the lower index watermark to the released tip and reads each with `read_index_window` on one completion session (locators, block spans, parent locators + P2TR-output `seqsigwit` + parent txids, parent records). One CPU worker, at most two windows behind, publishes one job per height to `rbtc-scripts-*` (filter GCS and tweak EC). That wave claims one height, so a short window still spreads across the pool. The CPU worker commits each index once per window under the index write-behind mutex, only if its watermark and every `confirmed[h]` are unchanged; `disconnect_tip_with` takes that mutex before truncating both. A failed commit (reorg) makes the IO thread re-plan from the watermarks. Apply errors halt the node. |
| Electrum / Esplora | Confirmed SH reads join durable index **plus a RAM SH head** (pending jobs keyed by scripthash) and pin that visible height (live tip while jobs sit, never above published tip). A tx is in mempool overlay **or** SH (pending/durable), not both and not neither. A disconnect to a fork point reaccepts, then drops pending. A branch reorg drops pending at its disconnect and reaccepts once the new branch is connected (Core order), so until then a disconnected tx is in neither. Its tip events wait for that reaccept, so a restatus on them sees the tx. A failed branch whose connected blocks come off sends one reorg event for the tip it leaves, so Electrum reads every status again. One whose first block fails sends none. Every Electrum scripthash status read (tip event, tick, pool admit) is dropped when it overlaps a `TemplateHold` (`pool_settle_gen`), and the next tick reads every sub again. Headers subscribe is live tip. |
| Epoch finalize | Single-threaded control path; flushes table maps / fd durability |

## Index modes (`IndexMode`)

| Mode | When | Spentness | Durable `tx.head` / spends | SH |
|------|------|-----------|----------------------------|-----|
| **Direct** | IBD (`enter_direct_index_mode`) | confirmed-strong annotations | commit-stage head insert; spend annotate in same stage | Class A collect → unsorted shards → seal at tip |
| **Tip** | after IBD (`enter_tip_mode`) | confirmed-strong annotations | live heads + confirm spends | write-behind after a pack-complete head (every `scripthash.head/NN.packed`; may lag live tip by 1+ blocks) |

Do not enter Tip until IBD catch-up complete: no best-chain remainder
(ordered / `height_to_hash` above tip / BQ ready ahead / awaiting reorg /
on-path getdata) and path high water at or within 1 of max peer height
(one-block version chatter only when `headers_done`), or a proven header
walk at the tip that no connected peer can extend. Competing
`hash_height` and leftover explore getdata are not remainder. Tip entry
bulk-materializes SH (two Class A `txout` scans → identity-map key spills
then fuse-hit postings → BDZ `scripthash.head/NN`; extract workers capped at
one per 1.5 GiB host free RAM). Shared file `scripthash.body`
is one writer. Overflow body
is one writer (ingest / compact). It does **not** rebuild `tx.head` or
spend annotations.

## Locks (exceptions only)

**Default is lock-free** on table hot paths:

| Mechanism | What it replaces |
|-----------|------------------|
| Capacity grow (`TableFile`) | Grow with fallocate/`set_len` and a published HWM. Do not introduce remap-epoch schemes (retired example: map epochs). Readers use the published HWM (Acquire) |
| Atomic `count` / HWM | Publish barrier (Acquire readers / Release appender) |
| Role exclusivity | One appender, one annotator — not a global store mutex |
| `tx.head` insert | **Sole writer**: page-coalesced `pwrite` (no CAS, no CPU fence). `published_len` Release orders the file length only, not the slot words. Lookups hop a read-only `MAP_SHARED` view of the slot file with atomic loads: the page cache makes a landed `pwrite` visible, and the Acquire load only stops the compiler from treating a word as frozen (it does not synchronize with the syscall). They never `pread` the open OA. Role exclusivity — not multi-inserter safe |
| `tx.head` segment seal | Roll opens the next OA immediately; BDZ+fuse8 runs on a sidecar. Lookup probes every unsealed OA until publish. Write joins the sidecar only on the *next* roll, `flush`, or `Drop` (not on the rolling insert). |
| `header.head` overflow | Insert past 7/8 rolls `header.head.gN` (new empty file). Occupied rewrite is open-only: undersized single gen writes `header.head.grow` then rename. |
| `ChainHub::confirmed` | `RwLock<HashSet>` for O(1) `has_block` (IBD assign path) |
| `ChainHub` header reporting | One short `RwLock` protects the cached maximum of proved stored prefixes and IBD's accepted checkpoints. Scrapes read no ancestry. Intake extends proved parents; invalidation/reconsideration stream the bounded stored frontier to the active chain (decreasing header fks, no depth cutoff), retaining the parent of the lowest invalid ancestor. All report/tip guards are dropped during IO. IBD queues proof checks on the existing header thread, outside the coordination lock. The cache keeps at most the 128 stored frontier candidates plus IBD checkpoint anchors, not a chain-scale reporting index. Unprovable look-ahead keeps only its proved prefix; ensuring a marked header refreshes its relationship to look-ahead even while intake is idle. A live walk can refresh its generation after revalidation. |
| `MempoolHub::inner` | One `RwLock<ActiveMempool>`. **Write** is graph mutation + durable slot append only (microseconds at ~12k live). No Query / script verify / compact reconstruct under write. The commit recheck of a confirmed coin runs before the write lock unless a confirm or disconnect holds the UTXO view. Prepare may hold a **read** across Query. Blocking `read`/`write` is `assert_not_reactor`. Session INV/getdata/compact use `try_read`; miss = skip that item (re-getdata / notfound / reconstruct without those txs). Compact fill siphashes live txid/wtxid and clones **matching** bodies only — never `list_live()`. Handshake `FeeFilter` reads the published fee-floor **atomic**, not `inner`. Age-INV log and min live `accept_at` are **not** `inner` (same class as `accept_at`). Accept caches `{tip_header_fk, height, mtp}` until the header fk changes. `get_coin` resolves the parent on the connected chain, decodes its packed outputs once, reads coinbase-ness from the Class C coinbase table (a failed read leaves the coin unavailable), and computes create MTP only for BIP68 **time** locks. `index_txid` hashes the admitted tx + prepare prevouts (no second Query). Do not CoW a 12k-txid presence set on every accept. A local submit is inserted into `local_origin` under the write that commits it, so a session that sees the tx live, in the relay maps, or on the announce channel already sees `skip_standing_inv`. Lock order: `inner` → `local_origin` / `sh_index` / `unbroadcast` / `relay_*`. |

There is **no** global “pause queries during confirm write.” Tip-as-commit +
`is_confirmed_strong` define query visibility ([`crash-recovery.md`](./crash-recovery.md)).

`--datadir-hdd` is the spindle exception. The write thread holds it across the Class A body pwrites and across the spend-annotate sweep, then starts the `tx.head` insert. Lookup and load call `spindle_wait` once before each bulk read (identity / `create.loc`, then pin / stamp). The flag off does not lock. The write thread never waits on this gate. Script threads, RPC, scripthash extract, and the index builder do not wait. Pending `tx.head` keys stay in RAM until the insert starts.

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
| Buried / as-of | `pin_chain_view_at(hash)` for a still-live ancestor. Esplora `?asof=`; Electrum trailing `asof:<hash>` on any protocol. Stamp is that hash. If it leaves the tip chain: 404 / `asof not on chain` — **do not** retry onto another block at the same height |
| Filter | SH join uses `is_confirmed_strong_at(fk, view.height)`; slot keys on **hash** |
| Live-check | `ChainView::still_live` ⇔ `confirmed[height] == header_fk` |
| Extension | Prefix pin stays live; creates above the pin are filtered |
| Disconnect / same-height replace | Live pin dies; `run_at_chain_view` retries (bound 8) then `StoreError::Stale` |
| Not OK | Pause queries during write, MVCC Class C, serving a disconnected hash |

API tokens: [`COMPAT.md`](../COMPAT.md) (Esplora headers, Electrum JSON-RPC extra members, status preimage).

## Wakeups and handoffs

What was checked against lock contention, wasted wakeups, and extra
handoffs. Each line is fixed or deferred. Tokio's eager driver handoff
stays off (`tokio_unstable` is not set). There is no second thread pool
and no environment knob for these choices.

**Fixed.** `wake_steal_workers` (`script_pool.rs`) unparks one parked
`rbtc-scripts-*` worker per unclaimed steal chunk and per detached job,
capped by how many workers are parked. A worker is on that idle list only
while it is not holding a job. The epoch check still runs after the debug
park delay, so a wave published after the steal check is not missed.
`steal_publish_wakes_idle_workers` is the pin. A claim increments
`in_wave`, then release-increments `next`. `is_complete` acquire-loads
`next` before it reads `in_wave`, so it does not drop the wave under a
claim that still applies.

**Fixed.** `serve_getdata_tail` used to call `ChainHub::knows_header` on
the session worker for every block `getdata`. An unknown hash took
`get_header_by_hash` there. `serve_getdata_full_block` already
reconstructs on the blocking pool and returns false when the header or
the body is missing, so the session check is gone.
`getdata_block_lookup_stays_off_the_reactor` is the pin.

**Fixed.** A compact tip announcement used to call `block_for_peer` on the
session inside `on_tip_event`, then build short ids there.
The body load stays on the blocking pool, under the block-decode permit.
Short ids run on `rbtc-scripts-*` once that body is in hand. A missing
body still falls through to a headers announcement. High-bandwidth relay
of a body already in hand persists that header and builds the prefill on
the blocking pool, then builds those short ids on `rbtc-scripts-*`, and
only when a high-bandwidth peer would be offered the block.
A failed high-bandwidth join is logged and skips that announcement.
A failed compact tip-announce join still ends that session.
An unsolicited compact block that does not
reconstruct yet persists that header path on the header-job pool.
`cmpct_tip_announce_shortids_run_off_the_reactor`,
`hb_relay_skips_the_build_when_no_peer_is_offered_it`, and
`hb_relay_offered_build_runs_off_the_reactor` are the pins.

**Fixed.** The IBD coordinator holds `shared` across the turn, the
redial apply, and the event drains. A peer split whose height has left
the download path is compared with the confirmed header only while that
lock is down. An unplanted header-walk candidate is checked for a
heavier fork the same way: the header walk runs with the lock down, and
only the commit takes `shared` again. That commit shares one rewind
exclusion with the header thread. It runs only when the tip is still the
block the prepare disconnected to, so a header-thread rewind that already
moved the tip is left in place. `tip_height`, `has_block`, and
`block_queue_*` under the lock are RAM. The header thread still reads
the store (`load_origin`, resume) with the lock dropped around that IO.
`coord_shared_lock_skips_header_and_store_io`,
`off_path_split_settles_outside_the_coord_lock`,
`unplanted_walk_reads_headers_outside_the_coord_lock`, and
`stale_heavier_rewind_does_not_commit_after_the_tip_moves` are the pins.

**Deferred.** Headers decode and classify are still two blocking joins.
`decode_framed_offload` drops its permit inside the decode job.
`on_headers` then takes the header-decode permit in `run_header_job`.
Fusing them would hold one permit across classify and tie the frame's
lifetime to `HeadersApply`. The session runs neither piece. One extra
join is not the stall.

**Deferred.** `queue_getheaders` still builds the locator on the caller
(`headers_sync_locator` / `locator_from_height`, about ten
`header_at_height` calls). Callers are the handshake, inv, and a missing
block parent. The headers-apply path already queues the locator
`classify_headers` built inside the header job (`queue_headers_locator`).
A second builder for that short walk is not the fix.

**Deferred.** These session checks are still one hash, not a batch:
`on_inv_block_needs_headers`, the `on_block` parent check, compact parent
checks, `header_announcement_connects`, and `stale_relay_allowed` after a
body was found. `is_connected` is the published height index and does not
read the header file. The per-item getdata loop was the batch, and that
moved.

**Fixed.** Block-sized pure CPU leaves the blocking pool for
`rbtc-scripts-*` through `run_cpu`. That is v2 encode when
`encode_is_cpu_heavy` (a short header batch and an inv list of 64 or fewer
stay on the caller), compact short ids after the body is in hand, and
Electrum or Esplora JSON of at least 4 KiB, including block templates.
Under 4 KiB, JSON stays on the
thread that did the store join. `run_cpu` parks the awaiting task. A guest
panic drops that reply and leaves the worker in the pool. A script worker
that calls store IO panics, including `pread_exact`, `pwrite_all`, and an
io_uring submit. A published steal chunk still runs before the
guest.
`run_cpu_uses_one_script_worker_after_the_wave`,
`run_cpu_panic_keeps_the_worker`, and `script_worker_cannot_pread` are the
pins.

Block-decode permits equal that pool. Header-decode permits are
`min(max(cores * 2, 8), pool)`, so a header storm cannot take block permits
or outnumber pool threads. Frames already requested still sit in the async
task until a permit is free; the getdata window, not the semaphore, bounds
that RAM. The reader does not await a decode permit before the next TCP read.
A heartbeat does not apply the ping timeout while a frame is still queued
for decode.

**Fixed.** Production mempool admit (HTTP `sendrawtransaction`,
`testmempoolaccept`, `submitpackage`, Electrum broadcast and package,
Esplora `POST /tx` and package, BlindBit `forward-tx`, and P2P `tx`)
awaits script verify off the blocking pool. Package accept, 1p1c,
`submitpackage`, and a multi-tx `testmempoolaccept` run that work on a task
the request cannot cancel, so a dropped caller still rolls back, trims, and
removes the test inserts. A single-tx admit still awaits on the request
task. BlindBit `forward-tx` already spawns its admit. A parked blocking pool
can still admit. Sync `accept_tx_from` remains for stack hubs and in-process
`dispatch()`. Orphan promotion after a commit still runs on the off-pool
thread that publishes the parent.

**Fixed.** RPC, REST, Electrum, Esplora, and BlindBit store reads share one
semaphore sized at listen. Omitted or `0` with `--datadir-hdd` is 1.
Otherwise it is one less than the core count, minimum 1. `--store-read-budget N`
(`N >= 1`) overrides that. The permit is acquired on the request task and
held until the read returns. P2P decode does not take it. Confirm's spindle
gate is unchanged, and these reads do not take that gate. An Electrum
read-only batch with a budget of 1 still completes, one read at a time.

**Fixed.** SV2 runs one template build at a time for the same previous-block
hash, coinbase size, coinbase sigops, and `template_updates`. A second
session with that key waits on its task and reuses the template. A different
coinbase budget or a bumped counter builds again. `None` (IBD, or the pool
not yet maintained) is not cached, so the next interval tries again.
Esplora's 15-second block-template cache is a separate path.
`MempoolHub::select_block_template` clones fee deltas, drops that lock, then
holds the mempool read lock for the whole selection. That lock is not held
across `.await`. The read spans selection.

**Deferred.** Block and header decode, compact reconstruct, header persist,
and full-block serve stay on Tokio's blocking pool (nCPU, minimum 4). The
cap stays there while block decode still occupies that pool. A private pool
would be a second pool. RPC can delay a reconstruct until one replacement
lane exists.

**Fixed.** Each failed async `try_send` on a full tip-accept queue
increments `FULL_QUEUE_SPINS`, then the sender parks on `Notify`. A yield
loop keeps moving that counter. `full_lane_parks_instead_of_spinning`
requires the count to settle in the single digits and stay there for
40ms. `notify_one` stores one permit when no waiter is registered, so
each sender that already saw a full queue tries again before it sleeps,
and a successful async enqueue wakes one more waiter.
`two_full_senders_both_enqueue` holds the lane inside a job with two
free slots and requires both senders to enqueue.

**Deferred.** Stack hubs that are not in an `Arc` still use the sync
wait. The node uses `ChainHub::into_arc`.

**Deferred.** `unpark_script_publisher` wakes every registered scripts
stage. A process has one (IBD or tip). That is not a pool-sized herd.
`Wave::notify_if_complete` is the caller.

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
write-behind (barrier `flush_class_c_tip`); large tables stay L0.
In-RAM gets of `confirmed`, `header_txs`, and `strong_tx` take no reader-writer
lock. `strong_tx` packs its bits into the same slot buffer and flush as those
arrays. Its length is the body in bytes and is not rounded up to a word.
The writer advances a sequence counter from even to odd with a
compare-exchange, so a second writer waits. The `ClassCWrite` token does
not do that exclusion. It then release-fences, stores the slots, and
advances the counter to even. The odd advance does not publish
those stores: a release on it would publish only the writes that came before
it, and a `SeqCst` increment does not either. A get loads the counter, loads
the slots, acquire-fences, and keeps the sample only when the counter is still
that even value. An acquire load of the counter does not by itself keep the
slot loads from moving after it. Gets are not `SeqCst`.
`header_txs` `get_range` uses one counter for the first and the count. A
column load acquires that store, then the same acquire fence checks the
counter again. A range put, a batch put, and `clear_body` store the first
column, then the count, while that counter is odd. If the count store
returns an error, the counter is even again and `get_range` can accept the
new first with the old count. Confirm joins the tip flush before those
stores, so a flush does not reject the count column on that path. The
error still leaves the pair torn. A flush excludes new stores, then reads the dirty range and
the live slots. A shrink writes that prefix when it still sits below the
new length, then shortens the file. A truncate that did not store into the
kept prefix only shortens. The odd bit and the flushing flag are `SeqCst` in both
directions. A `SeqCst` fence sits between the odd store and the flag load,
and between the flag store and the flusher's counter load. A relaxed odd bit
and a release store of the flag do not exclude each other, and a `SeqCst`
access is not that fence. The flag clears with `SeqCst` after the disk length
and the clean mark, which stay release stores. The flush does not bump the
counter, so a get during the flush does not retry because of the flush. Readers stay up
during IBD. Slot-table growth keeps the previous buffer until the table is dropped. `strong_tx` is one anonymous reservation of the 256 MiB cap: a grow commits the used prefix and does not keep a second image. A
get retries when the length it sampled does not fit the buffer it loaded. A
bulk bit scan rechecks the counter once at the end. A table past the RAM cap
is fd write-through. Its stores take the same sequence counter with no
flush flag, and a get retries a pread taken while a store ran, so a sample's
slot (or two adjacent slots) and length are one generation. An append pwrites the new
slots, then the file length, then `len`, so a get that sees the new length
has those bytes. A zero gap pwrites zeros across that new span before the
named slots. A get that sampled a length a truncate has since shortened
reads as an empty slot. A past-end pread is that empty slot only when the
reloaded length no longer covers the index.
See **[io-modality.md](./io-modality.md)** for operator IO levers.

### Confirm load read pipeline

Cold parent `create.loc` / `txout.body` on the **load** thread uses
**FdOnly loc + bulk body** (`idx_body_pipeline` → `bulk_io` uring/pread). Batch
creates come from **wire**, not a second Class A full-decode pass.
