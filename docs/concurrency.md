# Concurrency model (store / IBD / tip follow)

Short map of who may write which tables. **Format is unstable until 1.0.**

## Roles during IBD

| Role | Threading | Store writes |
|------|-----------|--------------|
| Peer IO (N tasks) | tokio multi-thread | none; decoded blocks **offer body queue only**; note height/hash readiness on confirm feed |
| Confirm **lookup** | 1 OS thread | load wire from **body queue**; structure + stamp create_fk (Class A planned only) |
| Confirm **load** | 1 OS thread | stamp from in-flight + published union + TipOnly `tx.head`; pin `txout` + assemble |
| Confirm **scripts** | 1 OS thread + 2 coordinators + `rbtc-scripts` steal | **none** — pure CPU |
| Confirm **write** | 1 OS thread | **sole Class A appender** (`txout`+`inwit`+`spent`) + structural + Class C + spend annotate on **`spent.body`** + tip GC; **`block_queue_dequeue_height`**. Class A **never leads tip** (same commit era; no archive-ahead DONTNEED) |
| IBD main loop | 1 tokio task | none (orchestration only) |

**IoSession TLS:** one completion session per OS thread (`with_thread_local`). Nested calls panic. Harvest tracks pending `(kind, epoch, slot)`; unexpected CQE / undrained leftover / CQ overflow is `Corrupt`, not a TipOnly miss. Drain before SQE buffers drop (spend annotate `DrainOnDrop`). Backends: Linux `io_uring`, portable `pool` (Darwin default), Windows IOCP. `RBITCOIN_IO=pread` disables the session.

**Height-ordered unified pipeline (current):** peer → **body queue** → **lookup** (BQ-ahead TipOnly `head_fk` wave; shipped, no fifth OS thread) → **load** (structure + stamp from in-flight + published union + TipOnly `tx.head` + pin `txout` + assemble) → scripts → single commit era. Stage IO: [`invariants.md`](./invariants.md). **No** peer→confirm-feed wire retain. **No** hash-only / Class-A-only confirm (bq wire required). Load bind order is in-flight → published `live_union` chain → TipOnly (fence-connected). Lookup owns `live_union`; one `ArcSwap` of the layer-chain head per wave; get walks layers (no union rebuild); a layer drops when no height in its span remains on the BQ; disconnect stores None. Write drain inserts `tx.head` in parallel with Class C. Drain complete is max inserted **fk** (not tip/fence — those advance during drain). Header-cache GC polls store tip every load pack. In-flight prune is **after pin + scripts handoff**: drain-fk **and** `covers_fk_span` (TipOnly home — `docs/invariants.md`). No leftover pending map. Bodies without a known height are marked missing and re-getdata after the height map is ready — there is **no** dual-track archive-job / ContigPark fallback.

**Load claim pack size:** soft **Σ `tx.input`** budget (hardcoded **8000**; include overshoot block) or hard **144** blocks. Dense mainnet blocks hit the input soft stop after **typically a few blocks** (often 1–3); early tiny blocks may pack many until the hard cap. Do **not** treat ~32 as pack size (that was 8000/250 mid-chain, not fat-era).

**IBD lookup resolve wave:** TipOnly `head_fk` over at most **1080** BQ-ready heights or soft **64000** inputs (include-overshoot; 256 k unique-key safety cap), then mark those complete for load to claim. One published identity layer per wave; get walks the chain (no union rebuild). When `ready >` half the 1-min BQ window, lookup waits for a full wave instead of minting a 1-block layer — unless the first unresolved height is within `path_lo + win/2` (load is about to claim it; O(1) from the already-sorted unresolved list).

**`ibd: perf`:** `load=` is pin+assemble only. Load OS-thread leftover TipOnly is `load_thr stamp=`; post-scriptq in-flight drop is `prune=`. `script=` is verify ns (`jobs=`/`skip=`), not feed-ahead join. `ready>0` + `scriptq=1` + high `stamp=` means leftover on load, not a hungry script pool.

**Tip follow / reorg:** peer wire via `ChainHub::accept_block` / `accept_branch` → `accept_and_connect_block` (same wire load path with cold denserels allowed on the one-shot call). Disconnect keeps Class A archive; re-extension always supplies **wire** from the peer, not hash-only load. **IBD most-work reorg** calls `accept_branch` from the **IBD orchestration task only** — never from confirm lookup/load/scripts/write threads. Selector / apply / invalid-heavy: [`architecture.md`](./architecture.md#most-work-chain-selection-ibd--tip-follow).

**Wire retained on the pipeline batch only:** lookup/load pull `bitcoin::Block` from the body queue; that wire rides through scripts; **no Class-A wire rebuild**. Script jobs carry lookup `TxPrecompute` (no job `from_tx`). Split Class A (`txout` / `inwit` / `spent`) is planned once and committed in the write stage.

**Body queue:** process-local **in-RAM** FIFO (id / height / hash / header_fk / raw-or-promoted charge). **Why RAM:** avoid **double disk write** of every block (queue then Class A); accept **redownload on restart** and peak RAM of soft depth. Peer enqueues **raw**; lookup **promotes** a wave to decoded-only (`Arc<Block>` + `TxPrecompute` on Query, same mutex as the queue — no ArcSwap). Load reads the Arc. **Never both** raw and decoded. **Primary capacity is soft densify assign** (no hysteresis): under ~100 MiB free densify ahead; over ~100 MiB only heights confirm will consume in the next ~1 min at tip rate. Soft assign keys off post-promote `bytes()` (decoded charge, not zero). Optional absolute byte ceiling via `RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES` (default unlimited). Height horizon (`CONTIG_DENSIFY_AHEAD`, 64 k past tip) caps densify/receive walk. **Offer** on peer Block → RAM; load **reads** by height; **dequeue** after confirm-commit. Restart starts empty (legacy `store/block_queue/` is best-effort removed).

**Pipeline pins:** plan `batch_pin` / `BatchParents` only (no process create FIFO). Stamp staging (`external_parent_ranges` / `external_parent_txids`) is **frozen/cleared after pin** (`ArchiveWritePlan::freeze_after_pin`) so write batch only concatenates commit halves. Outs live in `BatchParents` / pstore — not a third plan-local outs map. `SharedParentPin` publishes immutable outs/layout halves via `arc_swap::ArcSwap` (compose + RCU; no in-place mutation). `BatchParents` sticky-caches the last outs Arc for multi-input assemble. IBD `pin(... adopt= range_fill= contract= publish=)` names residual pin wall. ConfirmParentCache holds tip-ahead **Arc** header plans only (insert/replace/drop under tip GC). **RecentCreates** is write-published identity (`txid → fk+range`, `ArcSwap` snapshot) after Class A+idx; load stamp reads it before leftover TipOnly. Height-FIFO expire `2×soft_win` (floor 256). Not a pin/outs FIFO.

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
(runs → fan-in reduce → durable tables); it does **not** rebuild `tx.head` or spend annotations.

## Locks (exceptions only)

**Default is lock-free** on table hot paths (see `AGENTS.md`):

| Mechanism | What it replaces |
|-----------|------------------|
| Capacity grow (`TableFile`) | No map epochs; fallocate/`set_len` only; readers use published HWM (Acquire) |
| Atomic `count` / HWM | Publish barrier (Acquire readers / Release appender) |
| Role exclusivity | One appender, one annotator — not a global store mutex |
| `tx.head` insert | **Sole writer**: page-coalesced `pwrite` + `published_len` Release (no CAS, no CPU fence). Role exclusivity — not multi-inserter safe |
| `tx.head` segment seal | Synchronous on roll: build fuse8 + mark sealed + open new head (no shadow resize) |
| Process `rehash_gate` | Rare multi‑GiB open-hash rehash (host freeze prevention) |
| `ChainHub::confirmed` | `RwLock<HashSet>` for O(1) `has_block` (IBD assign path) |

There is **no** global “pause queries during confirm write.” Tip-as-commit +
`is_confirmed_strong` define query visibility ([`crash-recovery.md`](./crash-recovery.md)).

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
