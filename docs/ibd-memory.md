# IBD memory: intentional caches vs process leaks

This document is the developer/AI contract for **process-owned** memory on the
IBD path. It is **not** about kernel page cache under FdOnly store tables
(those count in RSS when faulted but are not Rust heap leaks). Sealed `.fuse8`
sidecars and SH BDZ3 occupancy prefixes are **read-only mmap** exceptions
([`io-modality.md`](./io-modality.md)); mapped RSS is `file=`. Heap meters
`fuse8=` and `mphf_occ=` are 0 / supers after open.

## Primary IBD wire path (current)

| Structure | Cap / bound | Production clear / evict |
|-----------|-------------|---------------------------|
| **In-RAM body queue** | Soft densify assign (no hysteresis): under ~100 MiB free densify ahead; over ~100 MiB only heights confirm will consume in the next ~1 min at tip rate; at the 1 GiB assign-stop (`RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES`, `0` = unlimited) no new getdata is issued. **Intake budget:** body-queue `bytes()` plus outstanding getdata hashes × the per-hash charge must fit in that same assign-stop before a **new** getdata hash is issued. The charge is 4 MiB until 8 requested bodies have been recorded, then the maximum wire length among the most recent 32, and never above 4 MiB. A hash already requested is never refused for budget (undecodable wire is still dropped; see below). A frame whose hash is not in inflight, or is already queued, is dropped before the payload copy. `bytes()` is **raw only** | Peer **BlockFramed** enqueues **raw** frame payload and stamps Σ `tx.input` via a CompactSize walk (no `Block` decode). Lookup packs/holds on that count; **dequeues** after load-batch send. Decoded `Arc<Block>` + `TxPrecompute` live on **loadq** (cap 14), then scriptq/writeq. **Have-body** (hole / densify / receive) is confirmed ∨ BQ hash ∨ `H ≤ lookup_taken_hi`. **Never both** raw and decoded. **RAM-only by design**. Restart empties BQ+loadq. Logs: `bq soft=n/win RAM=` (`bytes()`). `loadq=n/14`. |
| **Body densify height horizon** | `CONTIG_DENSIFY_AHEAD` (64 k past tip) | Safety max walk/receive; primary gate is soft assign (100 MiB free / 1 min confirm window). |
| **Confirm feed** | readiness (height/hash), no wire retain | Load pack / lookup-wave caps: [`concurrency.md`](./concurrency.md). Requeue / finish on outcome |

## Soft budgets (unified body-queue path)

Peers enqueue **raw** framed block payloads into the **in-RAM** body queue and
stamp Σ `tx.input` (`block_wire_input_count`; CompactSize walk, not a `Block`).
The walk refuses exactly the payloads `decode_block_precomputes` refuses. Offer
drops such a body before the copy, the sender is disconnected, and the hash
stays fetchable: a queued hash counts as in hand, so an undecodable row would
block the honest copy. Known gap: a tx with segwit flag 0 decodes in Core (an
empty vin, consensus-invalid) but not in rust-bitcoin, so such a block is
refetched instead of marked invalid.
Lookup packs and **holds** on that stamped count (no clone, no decode). The first
full decode is lookup emit: `decode_block_precomputes` (payload-slice wtxid;
stripped txid; `from_tx_wire` skips the second SHA engine when `wtxid==txid`;
sighash midstates only when scripts run) then **`take_raw`** (row gone),
`ResolvedWire` on loadq. Load stamp takes
that same `pres` Arc (no second `from_tx`; do not re-stash on the BQ).
Confirm commit is the sole Class A appender (**no** dual-track archive-job /
ContigPark pipeline).

**Why RAM (not disk):** writing peer wire to a durable queue and again into Class
A would **double disk write every block**. Process memory + redownload on restart
is the deliberate tradeoff. Accept stores raw wire only (block hash already known
from framing). After lookup processes a height we hold the decoded `Block` +
pres and **not** the raw bytes. Reorg gather that wants wire re-encodes.

| Structure | Cap / bound | Production clear / evict |
|-----------|-------------|---------------------------|
| **Load-batch parent skeleton** | Wave `txid → (fk, body_range)` + spent ranges on the `LoadBatch`; per-chunk need-vouts at split | Drop with the batch. Lookup TipOnly only. Not a process FIFO. |
| **Pipeline pins (no process FIFO)** | Plan `batch_pin` / `BatchParents` only | Drop with batch. Cold **outs** for ancient parents use `txout.body` into `BatchParents` (stamped range). Recent-window first spend uses stamp-carried in-flight CreatePin until load drops the pack below the wave's pre-TipOnly drain+fence snapshot. Class A `set_loc` on that Arc; later-wave stamp reads pin loc (same-wave creates omitted from the skeleton; write TLS loc covers those) |
| **In-flight CreatePin map** | identity + full create outs + loc `OnceLock` after Class A; one load-thread HashMap; lookup snapshots `drain_and_fence_hi` before TipOnly and passes it on the last load batch; load drops pack height below that after the in-flight read | Load notes after stamp; write sets loc on the same Arc; disconnect `drop_from` on pack height. Sizes: `iflight=`. Not a coins cache / spend FIFO |
| **Write loc packs** | Class A append `CreateLocPair`s on the **write thread** (TLS, no `Query` mutex); height-tagged like InFlight. `keep_until` = last height lookup has TipOnly'd at note (`lookup_started_hi`, ≥ pack height). Never bumped. No count cap | Write notes after append **and** `CreatePin::set_loc`. Prune when that last-started height has finished write (`written_hi ≥ keep_until`) and the pack is not the one just written (fill of that write already ran). Disconnect is polled on the write thread (`take_disconnect`) and `drop_from` on pack height (clamps remaining keep-until). Sizes: `wloc=` (atomics, like `iflight=`) |
| **ConfirmParentCache header plans** | tip-GC window | Always on — required for multi-block wire MTP |
| **Confirm plans / headers** | offer-ahead window | `ConfirmParentCache::advance_tip` from write `post_commit` |
| **SH catalog runs** | leftover `scripthash.runs` discarded at tip (unsorted collect does not write them) | write-behind / discard; not during Direct confirm |
| **SH unsorted collect / pack** | Two `txout` scans. All extract phases share `sh_extract_workers()` = min(CPUs, max(1, free RAM / 1.5 GiB)); `RBITCOIN_SH_MERGE_WORKERS` override. **Collect maps** use that same 1.5 GiB **per worker** as a cap (not a prefault): each worker owns a contiguous create-fk span and `n_shards` unsized identity maps (`HashMap<key16,u64>`, `0` = multi; 64 B/key estimate). After each 64 k-fk loc/body batch, spill the largest shard map while `sum(estimate) >= 1.5 GiB`. Status `scanned=` is finished fks (not max fk). Spills, including the end flush, go through one writer and a 1-slot queue so encode+tmp+rename is serial. Fuse8 mmap on pass 2 is process-wide, not subtracted from the cap. `keys/NN/` is a **directory** of `SHKSP01` spill files (`000000`, …; n_multi key16s already `0`, then first-fk-sorted uleb(delta)‖key16 singles; tmp+rename, no `sync_all`). Merge folds those spill files only into one identity map, one walk to `scripthash.head/NN` pack8 and `multi/NN.fuse8` (file, not kept resident for other shards), unlinks `keys/NN/`. The folded map is consumed into the pack8 records and dropped before fuse8 and BDZ. A previous `DONE` / 24 B `NN` layout, or `keys/NN` as a file, with no valid `DONE.keys` is deleted and pass 1 restarts. A spill whose magic is not `SHKSP01` is Corrupt. Pass 2 keeps fuse8 mmap only (no BDZ). Same static fk spans; fuse-hit creates append `fk` to per-worker `HashMap<key16, Vec<fk>>` (skip `vec.last() == fk`). Estimate `80 × n_keys + 8 × n_fks`; spill-largest while over 1.5 GiB. `post/NN/` is a **directory** of `SHPST01` spill files (`000000`, …; `u32 n_keys` then `key16 ‖ uleb(n) ‖ n × uleb(fk − prev)`; tmp+rename, no `sync_all`). A `post/NN` file, or a spill whose magic is not `SHPST01`, is Corrupt. **Pack fold** (named, after collect maps drop): one shard ~1.2 M multi keys × ~30 fks ≈ 0.3–0.5 GiB; 8 pack workers a few GiB. Fold spills into one map, then `MphfHead::open` + `slot_for_key16` + 2+ body + `rewrite_val_slots`; `len == 1` after fold is `fp_singles` (pass-1 `inline_one` stays). Unlink `post/NN/`. Packed 2-bit `g` ~8 MiB per pack worker + 16 MiB `body_buf`. Inner loc/body batch 65 536 fks inside each worker span (not a steal grain); body IO 16 MiB | Tip finalize. Extract under `scripthash.unsorted/{keys,multi,post}` |
| **`tx.head` wipe-rebuild workers** | min(CPUs, host free RAM / 1 GiB, range count); floor 1. Same free-RAM probe as SH. Matches BDZ peel+keys+g peak at default 2²⁵. **Not** the SH extract 1.5 GiB cap. Env `RBITCOIN_TX_HEAD_REBUILD_WORKERS` override (`1` = serial) | Empty/wipe `tx.head` rebuild from `txid.body`. Logs `workers=` `free_GiB=` |
| **Ordered work path** | `MAX_ORDERED_HEADERS` | `IbdWorkState::hygiene` |
| **Header-walk checkpoints** | One checkpoint per 2,000-header look-ahead reply. One peer, the lowest time to a first block byte among peers that have not failed the walk, serves both lanes. Block download uses the other peers. The walk asks from its tip while a connected peer is still ahead of it. That same peer refills from the queue tail, and below 16,384 headers the refill runs before another walk ask. Above the work floor a short reply that does not extend the candidate moves the reservation; a full 2,000-header window does not, so a lighter fork can still catch up. A block inv from another peer is one challenge, asked even when that peer's connect-time start height is below the walk: if the reply beats the candidate they become the header peer, and if it does not they leave the walk and the previous peer stays. One missed ask moves the reservation; a second miss disconnects. Less work does not disconnect. The first ask starts at the stored tip. A solicited continuation of that tip is a checkpoint, and so is a walk reply at any queue length once the walk is ahead of the stored path. A refill is stored only under 64,000 and only when it continues the stored top. Each checkpoint holds hash, height, work, that reply's last 80-byte header, up to 11 timestamps, and the difficulty period (one period-start header plus the last non-limit `nBits`) so a fork or rewind in the unstored gap can retarget. One competing chain is kept the same way until it loses or replaces the candidate. Mainnet stays under about 250 KB. No array of every header. Queue maps stay capped with the queue. Side headers below the work floor are one hash per peer. More than 4,000 disconnects that peer. Abandoned look-ahead tips are cleared at 1,024 and when a heavier chain is adopted. | Dropped with IBD state. `header.adopt` is the sidecar, not a resident copy. The file is deleted once the confirmed chain proves the anchor |

Tests that need a clean process must call these **same** entry points (or drop the
owning `Query` / pipeline), not a secret test-only free-all that masks production
leaks.

## Tip-follow / P2P serve (process heap)

Not page cache. Caps on **decoded `Block` objects and live outbound sessions**:

| Structure | Cap / bound | Production clear / evict |
|-----------|-------------|---------------------------|
| **Hopeless advertised tip** | Connecting headers with `header_branch_vs_tip` **Less** and announced height **+ 288 < our tip** | `request_disconnect` (no ban). `noban` keeps the session. |
| **`follow_live`** | ≤ `max_outbound` | Stale extra at cap **rotates** one random outbound full-relay (not `noban`) then dials a replacement. |
| **GetData serve inflight** | **16** full `Block`/`CmpctBlock` per session writer | Writer saturating-decrements after send so unpaired compact tip announce cannot wrap to `usize::MAX`. Announce is not counted on this cap (a burst would starve reconstruct). Extra inv hashes in the same inbound `getdata` past 16 are dropped (not a Core `ProcessGetData` leftover queue). |
| **Tip-follow catch-up getdata** | **16** (`MAX_SERVE_BLOCKS`) hashes per ask | `requested` tracks inflight; after those bodies connect, drain asks the next window. Asking the whole header path left hashes stuck while the peer served only 16. |
| **`from_this_peer`** / **`announced_wtx`** | **50_000** txids / wtxids per session | Insertion-order FIFO at cap (re-insert is a no-op; oldest dropped). ~32 B extra deque RAM per peer at full. |
| **`pending_blocks`** | **128** decoded bodies / session | Insert evicts the **oldest** hash (FIFO). Unsolicited BIP130 window still 16. |
| **Hub `BlockCache` bodies** | **16** decoded (`DEFAULT_BODY_DEPTH`) | Hashes kept for locators. Compact/`getblocktxn` serve is depth 5/10; IBD does not `push_best`. Reconstruct from store past the window. |
| **Hub `held_bodies`** | **320** count + **288** height window | Side-branch hold for most-work apply. After a successful tip connect, drop bodies whose connected height is more than **288** below tip (Core unrequested window). Do not hold `IgnoredWeaker` already that far behind. Consensus-invalid held tips are dropped and skipped by `try_apply_held`. Count cap evicts the oldest unasked hash at 320 (in-flight getdata hashes stay). |
| **Query `sh_heads`** | **65_536** process-local SH body heads | Evict arbitrary key at cap (`keys().next()`). Miss path `locate_head`s. Catch-up and tip SH apply share this map. |
| **getheaders continuation** | full 2000-header reply locates from last hash | Next batch after that hash, not a replay from our tip. |
| **headers poll** | skip if `best_known` cannot beat our tip | 120s `getheaders` only for peers that can still add work. |
| **Chainwork prefix** | `Vec<Work>` `prefix[h] = work through h` (~32 B × tip; ≈28–32 MiB at 900k) | Process cache. Extend/truncate to `query.tip_height()`. Not durable. Restart rebuilds on first `chain_work`. |
| **Block index windows** | ≤ 3 windows (one being read, ≤2 queued) of ≤64 heights / ≤50k creates: block outputs, input edges, P2TR-output witnesses, spent parents (tens of MiB each at mainnet sizes) | Only while `rbtc-idx-wb` builds a watermark that is behind the tip. A committed window is dropped. |
| **Confirm-batch index bytes** | One confirm batch of BIP158 filter bytes and BIP-352 tweak vecs while `index_live` is set | Drop with the batch at write. Not a cache. |
| **Fee history** | ≤1008 `(height, p10)` entries (~16 KiB) | Read from the chain per connected block; backfilled over the newest 1008 blocks when relay turns on (`txstat` + `spent` span reads, no bodies). Not a cache: every entry is a chain fact. |
| **Mempool fee snapshot** | Published Arc (chunks + live count/vsize/total_fee) | Dirty/singleflight ≤~1 s. Admit only marks dirty. `GET /mempool` Arc-loads; no graph walk, no body clones. |
| **Mempool tx-body snapshot** | Lazy; ≤ one extra live-pool of `Arc<Transaction>` + JSON `OnceLock` after first unix `/internal` mempool-tx page | Dirty/singleflight. Not FIFO/LRU. Operators who never hit unix `/internal` do not keep this. |

## Soft budgets: request-limited only (invariant)

**We never stop accepting block data a peer sends for a block we already
requested** just because body-queue soft depth (or any other soft meter)
is over target.

| Allowed | Forbidden |
|---------|-----------|
| Limit **densify getdata assign** when BQ payload is over ~100 MiB to heights confirm will consume in the next ~1 min at tip rate | Await a soft gate **before** the next TCP read on a peer |
| At the assign-stop, issue no new getdata. Between ~100 MiB and that stop, densify only the ~1 min confirm window | Drop a body we already **requested** solely for soft budget |
| Do not issue a new getdata hash when `bytes()` + (`inflight` + 1) × the per-hash charge would pass assign-stop. The charge is 4 MiB until 8 requested bodies are recorded, then the max of the most recent 32 wire lengths, capped at 4 MiB | Count outstanding getdata by scanning payloads |
| Drop an unsolicited or already-queued frame before copying it into the queue | Refuse `block_queue_offer` for a hash that is still in inflight |
| Free densify ahead while BQ payload is under ~100 MiB | Make healthy peers look stalled by parking the reader on soft backpressure |
| Overshoot soft limits while in-flight requests complete; accept those bodies via `block_queue_offer` | Bound process RAM by refusing peer bytes already requested |

**Why this is safe:** when soft assign restricts densify to the confirm-time
window, outstanding requests remain finite (per-peer in-flight window).
Enqueueing those bodies cannot create a truly unbounded leak; the backlog
drains as confirm dequeues. Bound queue size by **not requesting**, not by
**not reading**. A tight slow pack keeps half the per-peer count cap of
densify getdata (32 at the 64-block ceiling, and never past 16 MiB of
estimated block payload on that peer) and is allowed to finish them. While
`hole=` is open, assign issues **no new**
densify (existing in-flight requests may complete).

Do not add a second Class A path, or a large process-resident archive cache
(FIFO, LRU, or sticky residency), for unknown-height bodies.
Historical regression (example, do not reintroduce the names as a design):
bounded arch_job Full-drop and reader-side decode-permit wait before the next
frame made peers look dead while TCP buffers filled. Dual-track `ArchiveJob` +
ContigPark charge/release is **retired**.

## Process RSS vs true leak

| Observation | Interpretation |
|-------------|----------------|
| `bq RAM=` climbs while tip lags, falls as confirm dequeues | Working in-RAM queue (counts toward RSS/anon) |
| `conf_plans=` grows with tip-ahead headers | Intentional ConfirmParentCache Arc header plans (tip GC) |
| `conf … parents=` | Sum of `BatchParents` entries in scriptq + writeq (pipeline meter only; no writeq parent budget) |
| `sh_runs` grows during Direct IBD | On-disk runs; bulk materialize at tip |
| High `RssFile` with stable anon heap | File page cache (FdOnly tables + mapped `.fuse8` + mapped SH occ) — not a Rust leak |
| `fuse8=` | Heap-owned sealed fuse fingerprints; **0** after mmap open/seal. Idle fuse RSS is `file=` (kernel may drop pages; cheaper than swapping anon) |
| `mphf_g=` | Sealed BDZ `g` heap; **0** after FdOnly open (pages are `RssFile`) |
| `mphf_occ=` | Compact BDZ occupancy heap: superblock table after mmap; occ bits are `file=` |
| `class_c_l2=` ≈ creates/8 | Strong-tx bit image under the Class C in-RAM cap (process `Vec`; not mapped) |

Host check / in-process:

Every ~5s IBD emits **`ibd: sizes`** (INFO) with process RSS and occupancy of
known retain structures. Tip-follow emits **`tip: perf`** (DEBUG) with the same
`rss=` `anon=` `file=` `hwm=` split plus `cache=` `held=` `sh_heads=` `mp_live=`.
`anon=` growth is process heap; `file=` growth is mmap page cache.

Grep:

```bash
grep 'ibd: sizes' mainnet.log
grep 'tip: perf' mainnet.log
```

| Token group | What it meters |
|-------------|----------------|
| `rss=` `anon=` `file=` `hwm=` | `/proc` process RSS (anon vs mmap file pages) |
| `work` / `body` | IBD maps + body-presence sets |
| `bq soft=n/win RAM=` | In-RAM body-queue count vs 1-min confirm window at tip rate + heap MiB (**raw only**) |
| `conf_plans` / `plans=` / bq / conf pipe | Header plans + body-queue + confirm pipeline sizes (no process pin FIFO). Sizes does not print parent-cache `load thru=` / `bodies=` (those snapshot slots were always 0) |
| `conf loadq=` / `scriptq` / `writeq` | Real queue contents (loadq cap **14**) + pipeline-wide `parents=` + feed ready/inflight |
| `txhead` | Segmented `tx.head.*` (open head + sealed heads/fuses; logical sizes) |
| `sh` | SH catalog runs / tip heads |
| `heap … iflight= wloc= h2h= fence= fuse8= mphf_g= mphf_occ= class_c_l2= accounted= residual=` | Approx process **heap**: BQ + load-ahead CreatePins (`iflight=`) + write loc packs (`wloc=`) + `height_by_hash` + height fence (`Arc` snapshot for leftover TipOnly — not a 15 MiB memcpy/wave) + confirm wire + sealed fuse **heap** (`fuse8=`, 0 after mmap) + FdOnly BDZ `g` heap (`mphf_g=`, 0 after open) + compact occ supers (`mphf_occ=`) + Class C L2 images; residual = anon − accounted. Mapped `.fuse8` / occ are `file=` |

## Residual heap audit (872k / ~1.42 B creates)

`ibd: sizes` at `class_a≈1.416B` (mainnet.log, 2026-08-13) showed
`anon≈2.2 GiB` vs `accounted≈13 MiB` (`residual≈2.2 GiB`). That gap was a
**meter hole**, not an unbounded leak. The missing retain is almost all
intentional:

| Retain | Approx at 1.42 B creates | Notes |
|--------|-------------------------:|-------|
| **Sealed `tx.head` fuse8** | **0 heap**; ~1.5–1.6 GiB `file=` | Read-only mmap of every sealed `.fuse8` (~9 bits/key). Kernel may drop hot fuse under pressure; next `contains` faults the file. |
| **Sealed BDZ `g`** | **0 heap** | Header only; 4 KiB `g` pages via uring stream (`KIND_MPHF_G`). Hot pages are kernel `RssFile`. FdOnly because a mapped miss serializes one fault per lookup thread; the ring keeps 128 pages in flight. Do not mmap packed `g`. |
| **SH BDZ3 occupancy** | **supers heap** (`mphf_occ=`); ~150 MiB `file=` at ~1 B SH keys | Read-only map of the `NN.mphf` prefix through occ (not tags). Rank popcounts mapped bytes. |
| **Class C L2 `strong_tx`** | **~177 MiB** | 1 bit/create, under the 256 MiB in-RAM cap. Stays process `Vec`: `MAP_SHARED` would write before the tip barrier; `MAP_PRIVATE` COWs `set_bit` back into anon. |
| **Mempool schema 3** | Slot table ~6 MiB at 128k + body weight | InRam `slots`/`body` Vecs + `pwrite`. Live set is also the graph. Not mapped. |
| **`height_by_hash`** | **~60 MiB** | In-process confirmed hash→height map. Incremental on tip extend/shrink; full `0..=tip` walk on open / invalidate only. |
| **mimalloc arenas** | **anon − accounted** after IBD | Product bins are global mimalloc. IBD allocates/frees GiB-class transients; `free` is not `munmap`. After tip catch-up, `anon=` can stay fat while `accounted=` collapses. That is allocator residue, not a store leak. Fuse mmap does not mean RSS equals fuse. Do not `malloc_trim` a mimalloc process. Optional operator: `MIMALLOC_PURGE_DELAY=0`. The `mimalloc` crate does not expose `mi_collect` on `MiMalloc` (no in-process purge hook). |
| **Process baseline** | **~90 MiB** | Visible at genesis (`class_a=476`, `residual≈93`). Allocator arenas, rustc runtime, net. |

Meters `fuse8=` / `mphf_g=` / `mphf_occ=` / `class_c_l2=` enter `accounted`.
`fuse8=` / `mphf_g=` are **0** after open (mmap / FdOnly). `mphf_occ=` is
supers only (mapped occ is `file=`).
Mapped fuse / occ RSS is `file=`, not a fake leak.

Grep:

```bash
grep 'ibd: sizes' mainnet.log
grep 'tip: perf' mainnet.log
```

## Hard RAM (page-cache working set)

Process heap (BQ + L2 Class C + pins + mempool) is **a few GiB**. The
**hard** requirement is kernel page cache for the files each mode actually
touches. Census: [`SCHEMA.md`](../SCHEMA.md) (tip 962298, 1.42 B creates).

| Mode | Must stay hot | Approx | Cold (fault OK) |
|------|---------------|--------|-----------------|
| **Tip follow / Electrum serve** | Open `tx.head` + recent `txout`/`spent`/`txid` tails + SH main idx + mempool | **8–16 GiB** page cache + **~2–3 GiB** process | `seqsigwit` (except `getrawtransaction`), sealed `tx.head` older than fuse-skip, archive `txout` |
| **Comfortable serve** (busy wallets, Electrum tweaks, RPC reconstruct) | Above + more `txout` + SH body slabs + `txid.body` | **16–32 GiB** | `seqsigwit` except rawtx |
| **IBD pin+annotate (no thrash)** | **All** `txout` + **all** `spent` + `create.loc` (~3 GiB) + `txid.body` + `tx.head` | **~221 GiB** | **`seqsigwit` (~486 GiB)** — wire still holds witness |
| **IBD + reconstruct/getdata** | Previous + `seqsigwit` | **~710 GiB** (same order as old packed `tx.body`) | — |
| **SH tip materialize** | Two `txout` scans (16 MiB libc `pread` spans + 1 MiB write buffers); extract workers min(CPUs, free RAM / 1.5 GiB); ingest OA **~768 MiB** (2²⁵×24 B) | **~1.5 GiB** heap per extract worker (BDZ `g` + fuse + maps); pack ~8 MiB packed `g` + 16 MiB `body_buf` | No catalog k-way pages; no 64 × `.val` random-read set on the scan |

Packed schema 13/14 needed the whole **`tx.body` (~663 GiB)** hot for the same
pin/annotate work. Split Class A drops that to **~161 GiB** (`txout`+`spent`)
plus loc/identity. A **16 GiB** host can tip-follow (OPERATOR §16 GiB) but IBD
parent pin will be **disk-bound** on `txout`/`spent`.
