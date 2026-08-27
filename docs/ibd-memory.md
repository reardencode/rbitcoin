# IBD memory: intentional caches vs process leaks

This document is the developer/AI contract for **process-owned** memory on the
IBD path. It is **not** about kernel page cache under FdOnly store files
(those count in RSS when faulted but are not Rust heap leaks).

## Primary IBD wire path (current)

| Structure | Cap / bound | Production clear / evict |
|-----------|-------------|---------------------------|
| **In-RAM body queue** | Soft densify assign (no hysteresis): under ~100 MiB free densify ahead; over ~100 MiB only heights confirm will consume in the next ~1 min at tip rate; at/over 1 GiB assign-stop (`RBITCOIN_BLOCK_QUEUE_GB` / `_BYTES`, `0` = unlimited) fill holes through the already-fetched height horizon only (BQ max / lookup_taken) — do not grow past it. **Never** refuse enqueue. `bytes()` is **raw only** | Peer **BlockFramed** enqueues **raw** frame payload and stamps Σ `tx.input` via a CompactSize walk (no `Block` decode). Lookup packs/holds on that count; **dequeues** after load-batch send. Decoded `Arc<Block>` + `TxPrecompute` live on **loadq** (cap 14), then scriptq/writeq. **Have-body** (hole / densify / receive) is confirmed ∨ BQ hash ∨ `H ≤ lookup_taken_hi`. **Never both** raw and decoded. **RAM-only by design**. Restart empties BQ+loadq. Logs: `bq soft=n/win RAM=` `loadq=n/14`. |
| **Body densify height horizon** | `CONTIG_DENSIFY_AHEAD` (64 k past tip) | Safety max walk/receive; primary gate is soft assign (100 MiB free / 1 min confirm window). |
| **Confirm feed** | readiness (height/hash), no wire retain | **Load** packs tip-contiguous runs by decoding BQ wire one height at a time until soft **input** budget (hardcoded **8000**, overshoot block included) or hard **144** blocks. At dense mainnet heights **8000 inputs ≈ a few blocks** (often 1–3; early chain can pack many tiny blocks up to 144). Do not treat ~32 as pack size. IBD **lookup** TipOnly-resolves at most **64000** inputs or **1080** BQ-ready heights per wave. Hard **min 8000** inputs when more unresolved heights remain (`ready=0` included). Also holds a short wave while `ready` is over half the 1-min BQ window, unless the first unresolved height is in the load-facing half of that window **and** the collect is already ≥8000. Requeue / finish on outcome |

## Soft budgets (unified body-queue path)

Peers enqueue **raw** framed block payloads into the **in-RAM** body queue and
stamp Σ `tx.input` (`block_wire_input_count`; CompactSize walk, not a `Block`).
Lookup packs and **holds** on that stamped count (no clone, no decode). The first
full decode is lookup emit: `consensus_decode` + `TxPrecompute::from_tx_connect`
below milestone (txid/wtxid/sizes; no BIP143/341 midstates) or `from_tx` when
scripts will run, **`take_raw`** (row gone), `ResolvedWire` on loadq. Load stamp takes
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
| **Pipeline pins (no process FIFO)** | Plan `batch_pin` / `BatchParents` only | Drop with batch. Cold **outs** for ancient parents use `txout.body` into `BatchParents` (stamped range). Recent-window first spend uses stamp-carried in-flight CreatePin until load drops the pack below the wave's pre-TipOnly drain+fence snapshot |
| **In-flight CreatePin map** | identity + full create outs; one load-thread HashMap; lookup snapshots `drain_and_fence_hi` before TipOnly and passes it on the last load batch; load drops pack height below that after the in-flight read | Load notes after stamp; disconnect `drop_from` on pack height. Sizes: `iflight=`. Not a coins cache / spend FIFO |
| **ConfirmParentCache header plans** | tip-GC window | Always on — required for multi-block wire MTP |
| **Confirm plans / headers** | offer-ahead window | `ConfirmParentCache::advance_tip` from write `post_commit` |
| **SH catalog runs** | leftover `scripthash.runs` discarded at tip (unsorted collect does not write them) | write-behind / discard; not during Direct confirm |
| **SH unsorted collect / pack** | Collect: nCPU (no env / RAM cap; 1 MiB grow-on-demand write buffers; per-shard mutex so pwrite issues in offset order; 64 MiB fallocate on full flushes). Pack: min(CPUs, free RAM / 2 GiB); `RBITCOIN_SH_MERGE_WORKERS` override. One anonymous file image per pack worker (in-place unique-sort; MPHF has no HashSet). Class A collect spans 1 MiB | Tip finalize. Unsorted files under `scripthash.unsorted/` |
| **`tx.head` wipe-rebuild workers** | min(CPUs, host free RAM / 750 MiB, range count); floor 1. Same free-RAM probe as SH. **Not** the SH pack 2 GiB cap. Env `RBITCOIN_TX_HEAD_REBUILD_WORKERS` override (`1` = serial) | Empty/wipe `tx.head` rebuild from `txid.body`. Logs `workers=` `free_GiB=` |
| **Ordered work path** | `MAX_ORDERED_HEADERS` | `IbdWorkState::hygiene` |

Tests that need a clean process must call these **same** entry points (or drop the
owning `Query` / pipeline), not a secret test-only free-all that masks production
leaks.

## Tip-follow / P2P serve (process heap)

Not page cache. Caps on **decoded `Block` objects and live outbound sessions**:

| Structure | Cap / bound | Production clear / evict |
|-----------|-------------|---------------------------|
| **Hopeless advertised tip** | Connecting headers with `header_branch_vs_tip` **Less** and announced height **+ 288 < our tip** | `request_disconnect` (no ban). `noban` keeps the session. |
| **`follow_live`** | ≤ `max_outbound` | Stale extra at cap **rotates** one random outbound full-relay (not `noban`) then dials a replacement. |
| **GetData serve inflight** | **16** full `Block`/`CmpctBlock` per session writer | Writer saturating-decrements after send so unpaired compact tip announce cannot wrap to `usize::MAX`. Announce is not counted on this cap (a burst would starve reconstruct). Extra inv hashes not reconstructed. |
| **Tip-follow catch-up getdata** | **16** (`MAX_SERVE_BLOCKS`) hashes per ask | `requested` tracks inflight; after those bodies connect, drain asks the next window. Asking the whole header path left hashes stuck while the peer served only 16. |
| **`pending_blocks`** | **128** decoded bodies / session | Insert evicts one existing hash at cap. Unsolicited BIP130 window still 16. |
| **Hub `held_bodies`** | **320** | Existing; side-branch hold for most-work apply. |
| **getheaders continuation** | full 2000-header reply locates from last hash | Next batch after that hash, not a replay from our tip. |
| **headers poll** | skip if `best_known` cannot beat our tip | 120s `getheaders` only for peers that can still add work. |
| **Chainwork prefix** | `Vec<Work>` `prefix[h] = work through h` (~32 B × tip; ≈28–32 MiB at 900k) | Process cache. Extend/truncate to `query.tip_height()`. Not durable. Restart rebuilds on first `chain_work`. |

## Soft budgets: request-limited only (invariant)

**We never stop accepting block data a peer sends for a block we already
requested** just because body-queue soft depth (or any other soft meter)
is over target.

| Allowed | Forbidden |
|---------|-----------|
| Limit **densify getdata assign** when BQ payload is over ~100 MiB to heights confirm will consume in the next ~1 min at tip rate | Await a soft gate **before** the next TCP read on a peer |
| At/over 1 GiB assign-stop, densify **holes in the already-fetched height range only** (do not grow past BQ max / lookup_taken) | Drop a body we already received solely for soft budget |
| Free densify ahead while BQ payload is under ~100 MiB | Make healthy peers look stalled by parking the reader on soft backpressure |
| Overshoot soft limits while in-flight requests complete; accept all in-flight bodies via `block_queue_offer` (assign-stop is ignored on offer) | Bound process RAM by refusing peer bytes already on the wire |

**Why this is safe:** when soft assign restricts densify to the confirm-time
window, outstanding requests remain finite (per-peer in-flight window).
Enqueueing those bodies cannot create a truly unbounded leak; the backlog
drains as confirm dequeues. Bound queue size by **not requesting**, not by
**not reading**.

Historical regression (do not reintroduce): bounded arch_job Full-drop and
reader-side decode-permit wait before the next frame made peers look dead while
TCP buffers filled. Dual-track `ArchiveJob` + ContigPark charge/release is
**retired** — do not reintroduce a second Class A path for unknown-height bodies.

## Process RSS vs true leak

| Observation | Interpretation |
|-------------|----------------|
| `bq RAM=` climbs while tip lags, falls as confirm dequeues | Working in-RAM queue (counts toward RSS/anon) |
| `conf_plans=` grows with tip-ahead headers | Intentional ConfirmParentCache Arc header plans (tip GC) |
| `conf … parents=` | Sum of `BatchParents` entries in scriptq + writeq (pipeline meter only; no writeq parent budget) |
| `sh_runs` grows during Direct IBD | On-disk runs; bulk materialize at tip |
| High `RssFile` with stable anon heap | Mmap page cache — not a Rust leak |
| `fuse8=` ≈ 9 bits × sealed Class A | In-RAM sealed membership filters — intentional; not a leak |
| `mphf_g=` | Sealed BDZ `g` heap; **0** after FdOnly open (pages are `RssFile`) |
| `class_c_l2=` ≈ creates/8 | Strong-tx bit image under the Class C in-RAM cap |

Host check / in-process:

Every ~5s IBD emits **`ibd: sizes`** (INFO) with process RSS and occupancy of
known retain structures:

| Token group | What it meters |
|-------------|----------------|
| `rss=` `anon=` `file=` `hwm=` | `/proc` process RSS (anon vs mmap file pages) |
| `work` / `body` | IBD maps + body-presence sets |
| `bq soft=n/win RAM=` | In-RAM body-queue count vs 1-min confirm window at tip rate + heap MiB (**raw only**) |
| `conf_plans` / bq / conf pipe | Header plans + body-queue + confirm pipeline sizes (no process pin FIFO) |
| `conf loadq=` / `scriptq` / `writeq` | Real queue contents (loadq cap **14**) + pipeline-wide `parents=` + feed ready/inflight |
| `txhead` | Segmented `tx.head.*` (open head + sealed heads/fuses; logical sizes) |
| `sh` | SH catalog runs / tip heads |
| `heap … iflight= pstore= recent= h2h= fence= fuse8= mphf_g= open_keys= class_c_l2= accounted= residual=` | Approx process heap: BQ + load-ahead CreatePins (`iflight=`) + **pstore/recent meters stay 0** (no process pin store, no RecentCreates ring) + `height_by_hash` + height fence (`Arc` snapshot for leftover TipOnly — not a 15 MiB memcpy/wave) + confirm wire + **sealed `tx.head` fuse8 fingerprints** + FdOnly BDZ `g` heap (`mphf_g=`, 0 after open) + open-segment fuse-key Vec + Class C L2 images; residual = anon − accounted |

## Residual heap audit (872k / ~1.42 B creates)

`ibd: sizes` at `class_a≈1.416B` (mainnet.log, 2026-08-13) showed
`anon≈2.2 GiB` vs `accounted≈13 MiB` (`residual≈2.2 GiB`). That gap was a
**meter hole**, not an unbounded leak. The missing retain is almost all
intentional:

| Retain | Approx at 1.42 B creates | Notes |
|--------|-------------------------:|-------|
| **Sealed `tx.head` fuse8** | **~1.5–1.6 GiB** | `open_file` loads every sealed `.fuse8` fingerprint array into process RAM (~9 bits/key). |
| **Sealed BDZ `g`** | **0 heap** | Header only; 4 KiB `g` pages via uring stream (`KIND_MPHF_G`). Hot pages are kernel `RssFile`. |
| **Class C L2 `strong_tx`** | **~177 MiB** | 1 bit/create, under the 256 MiB in-RAM cap. |
| **Open-segment `open_keys`** | **~100–200 MiB** | `Vec<u64>` fuse keys for the unsealed tail. |
| **`height_by_hash`** | **~60 MiB** | Query comment; still unmetered. |
| **Process baseline** | **~90 MiB** | Visible at genesis (`class_a=476`, `residual≈93`). Allocator arenas, rustc runtime, net. |

Meters `fuse8=` / `mphf_g=` / `open_keys=` / `class_c_l2=` enter `accounted`.
`mphf_g=` is **0** after open (FdOnly). Fuse stays the intentional ~1.6 GiB
heap cost of segmented heads.

Grep:

```bash
grep 'ibd: sizes' mainnet.log
```

## Hard RAM (page-cache working set)

Process heap (BQ + L2 Class C + pins + mempool) is **a few GiB**. The
**hard** requirement is kernel page cache for the files each mode actually
touches. Census: [`SCHEMA.md`](../SCHEMA.md) (tip 962298, 1.42 B creates).

| Mode | Must stay hot | Approx | Cold (fault OK) |
|------|---------------|--------|-----------------|
| **Tip follow / Electrum serve** | Open `tx.head` + recent `txout`/`spent`/`txid` tails + SH main idx + mempool | **8–16 GiB** page cache + **~2–3 GiB** process | `inwit` (except `getrawtransaction`), sealed `tx.head` older than fuse-skip, archive `txout` |
| **Comfortable serve** (busy wallets, Electrum tweaks, RPC reconstruct) | Above + more `txout` + SH body slabs + `txid.body` | **16–32 GiB** | `inwit` except rawtx |
| **IBD pin+annotate (no thrash)** | **All** `txout` + **all** `spent` + three `*.idx` + `txid.body` + `tx.head` | **~227 GiB** | **`inwit` (~486 GiB)** — wire still holds witness |
| **IBD + reconstruct/getdata** | Previous + `inwit` | **~710 GiB** (same order as old packed `tx.body`) | — |
| **SH tip materialize** | Unsorted shards: nCPU Class A collect (1 MiB `txout` spans + 1 MiB write buffers); pack workers min(CPUs, free RAM / 2 GiB); ingest OA **~768 MiB** (2²⁵×24 B) | **~2 GiB** heap per pack worker | No catalog k-way pages |

Packed schema 13/14 needed the whole **`tx.body` (~663 GiB)** hot for the same
pin/annotate work. Split Class A drops that to **~161 GiB** (`txout`+`spent`)
plus idx/identity. A **16 GiB** host can tip-follow (OPERATOR §16 GiB) but IBD
parent pin will be **disk-bound** on `txout`/`spent`.
