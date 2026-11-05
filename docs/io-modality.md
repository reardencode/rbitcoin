# Store IO modality matrix

**Source of truth** for bulk `RBITCOIN_IO` vs table transport (fd + tiered RAM).
**Phase 6 complete:** workspace has **zero `memmap2` / `MmapMut`**.
[`TableFile`](../crates/rbitcoin-store/src/file.rs) stays **FdOnly**. The mmap
exceptions are **read-only**: sealed `.fuse8` fingerprint arrays
([`fuse8_filter.rs`](../crates/rbitcoin-store/src/fuse8_filter.rs)), SH
BDZ3 occupancy bitvectors (prefix of `NN.mphf` through occ, not tags), and the
open `tx.head` OA slot array, a live file its sole writer `pwrite`s (the page
cache keeps the view coherent). Unix
`mmap` `PROT_READ`/`MAP_SHARED`, Windows `MapViewOfFile` `PAGE_READONLY`. Packed
MPHF `g` stays FdOnly 4 KiB: a mapped miss is one synchronous fault on the lookup
thread, while `KIND_MPHF_G` keeps 128 pages in flight on the completion
session. `strong_tx` stays a process-resident bit image. Mempool stays
process `Vec`.

**Map vs FdOnly:** map when the bytes are immutable after write, touched as
a few random bytes per key, and must stay resident for the hot path (sealed
`.fuse8`: every unfinished key probes every sealed segment; SH BDZ3 `occ`:
1.23 bits/key, rank on every compact index). Keep FdOnly +
completion session when the file is larger than the residency budget or is
read as page batches (`txid.body` / `txout` / `spent` / `create.loc`, packed
BDZ `g`, SH tags/`.val`).

Related: [`env-knobs.md`](./env-knobs.md), [`concurrency.md`](./concurrency.md),
[`crash-recovery.md`](./crash-recovery.md), [`architecture.md`](./architecture.md).

---

## Two independent layers

| Layer | Controlled by | Values | Purpose |
|-------|---------------|--------|---------|
| **Bulk batch** | `RBITCOIN_IO` only | `uring` \| `pool` \| `iocp` \| `pread` | Multi-op **completion session** on file handles (`txout` pin/outs, `seqsigwit` reconstruct, spend meta/ann on `spent`, Class C bulk) |
| **Table transport** | [`TableFile`](../crates/rbitcoin-store/src/file.rs) | **FdOnly always** | All payload via pread/pwrite; fallocate grow; no process maps. Sealed `.fuse8` and SH BDZ3 occ are sidecar maps, not TableFile |

**`RBITCOIN_IO` selects the completion-session backend** (not per-path).
Unknown tokens (including deleted `mmap`) fall through to the platform default.

| Token | Backend |
|-------|---------|
| `uring` / `io_uring` | Linux `io_uring`. On Windows the token opens **IOCP** |
| `pool` | Worker-pool completion ring (opt-in on Darwin; Linux CI pin) |
| `iocp` | Windows IOCP (Windows **default**) |
| `pread` / `fd` / `libc` / `pwrite` | Disable session; libc positional IO (+ workers for reads) |

**Defaults:** Linux `io_uring` if the ring opens, else libc **pread** (session off). Darwin libc **pread** (session off).
Windows **IOCP**. Windows IoRing is not supported.

**Windows table handles** are `FILE_FLAG_OVERLAPPED` so IOCP can bind.
Create, open, header/trailer, and grow use positional `IoHandle`
pread/pwrite and `SetFileInformationByHandle(FileEndOfFileInfo)`. Do
**not** mix those handles with std `Read`/`Write`/`Seek` — `WriteFile`
with a NULL `OVERLAPPED` is os error 87 (`ERROR_INVALID_PARAMETER`).
Positional xfer sets the low bit of `OVERLAPPED.hEvent` so the packet is
**not** queued to the process IOCP (harvest `Box::from_raw`s only session
heap OVERLAPPEDs).

**kqueue is not a regular-file backend.** Darwin files report ready immediately;
`read` still blocks. POSIX AIO (`EVFILT_AIO`) and `dispatch_io` are also
thread pools (`kern.aiomax` default 16) — same class as `pool`, not an
SQ/CQ. The pool session is the honest Darwin completion ring, but each read
costs a shared-queue lock and two thread wakeups. In signet IBD that cost more
than the reads, warm or cold cache (about 20% slower end to end, four times the
system CPU), so Darwin defaults to libc pread and `RBITCOIN_IO=pool` opts in.
Pool **workers** are process-shared; each TLS session keeps its own CQE queue.

**TLS session:** one completion session per OS thread (`with_thread_local`).
Nested calls panic. Harvest tracks pending `(kind, epoch, slot)`. A CQE that
is unmatched, duplicate, from a prior epoch, leftover after `drain_all`, or
from CQ overflow is `Corrupt` — not a completion and not a TipOnly miss.
`begin_batch` treats leftover SQEs as fatal: a previous machine's buffers are
gone, so it aborts instead of draining them (probe / identity / BDZ g-pages /
rel preads share the ring). Every machine drains its own wave before returning,
or uses a `DrainOnDrop` declared **after** its buffers. `with_thread_local`
entry/exit/growth and session `Drop` follow the same rule: no boundary drain.
A caller-frame or backstop guard uses `abort_guard`, which never drains.
Held fill on that ring fails closed on a boundary error (no libc fallback on a
dirty ring). Head-resolve `create.loc` is **not**
on the probe ring: one FdOnly batch after identity (standalone bulk; live shorts
libc-complete; no probe recover credit). `range_batch_ctx` on a still-held
session keeps poison fail-closed and live-ring libc-complete. Undrained / unexpected /
wait-timeout **poisons** the session. A drain error with pending ids aborts (the
debug `with_drain_hard_cap` seam returns `Err`); with no pending it returns
`Err` and the TLS ring is dropped so the next wave opens a new one. `submit_and_wait_one` shares the drain budget (slow-log at
5 s, poison at the hard cap). Linux wait is Ready only when the CQ has a
visible event (`io_uring_enter` returns SQEs submitted, not CQE count); an
empty CQ is TimedOut. Live harvest loops wait, then retry; one empty harvest
is not batch death. `drain_all` on every TLS session (Linux, pool,
IOCP) waits while CQEs keep arriving; after 5 s it logs `store: io_uring
drain slow`. Zero completions for `RBITCOIN_URING_DRAIN_HARD_SECS` (default
120) abort **explicit** `drain_all` / `DrainOnDrop` (buffers still pinned).
Session `Drop` does not drain: pending ids there abort, because no buffer owner
is known. There is **no** runtime switch to `pread`. Per-op short/errno on a
live session still libc-completes that op; libc fail is `StoreError::io`. A live
unpoisoned session that fails the bulk batch after the wait budget (submit)
falls back per-op; leftover SQEs are fatal, not a recover credit. `RBITCOIN_IO=pread` is the only
whole-batch pread fallback (session unavailable also falls back; operator
restart after a drain abort).

IBD write / lookup / load / scripts and post-IBD tip connect: a session fault
after a successful drain recovers once per 1000-height window (credit CAS;
**no** in-process Class C repair — leftover strong is the open-repair case).
The next wave opens a new TLS ring. Load, scripts, and write then requeue the
faulted wave as an engine fault with no reject event: lookup re-arms at the
tip and the wave's bodies go back on the body queue. A second stall in that
window aborts and names `RBITCOIN_IO=pread`.

### Do not flatten custom machines

Machines (spend-annotate RMW, fused head-resolve, pipelined bulk fill) stay
**multi-stage**. Pool/IOCP are session backends — they do not flatten those
loops to one-shot `pread_batch`.

**Do not** replace a purpose-built / multi-stage **io_uring machine** with
batched `pread`/`pwrite` / one-shot `pread_batch`/`pwrite_batch` **without
explicit permission from the user**.

| OK | Not OK without permission |
|----|---------------------------|
| Fix bugs inside the existing machine | Delete/retire a custom machine and call bulk batch helpers |
| Thread new flags through the same SQE path | “Simplify” to serial pread + one big submit |
| Fall back to pread when uring is unavailable | Rewrite a machine away “because batch is enough” |

If a change seems to require collapsing a machine, **stop and ask**.

---

## RAM tiers (L0 / L1 / L2)

| Tier | Where hot bytes live | Sync |
|------|----------------------|------|
| **L0** | Kernel page cache via pread/pwrite; process holds staging only | Payload then HWM publish; `sync_data` on flush barriers |
| **L1** | 4 KiB head pages / 3–4 KiB SH chunks (working-set caches) | Write-back dirty page/chunk with one pwrite |
| **L2** | Compact Class C (`confirmed`, `header_txs_*`, `strong_tx`) full image in process | **Write-behind:** RAM mutate during commit; live slots on `flush_class_c_tip` ([when](./crash-recovery.md#flush)) |

**Never L2:** `txout` / `seqsigwit` / `spent`, full `tx.head` / `*.idx`.
A 256 MiB cap limits **`confirmed`** and **`header_txs_*`** to L2; over that
they stay fd. `strong_tx` stays L2 (1 bit/fk). Create height is a
RAM fence (~15 MiB at 1M blocks), not a file.

---

## Current matrix (`RBITCOIN_IO=uring`)

### Bulk batch (env)

| Path | Env | Syscalls |
|------|-----|----------|
| Pin outs / body pipeline | `RBITCOIN_IO` | uring/pread on **`txout.body` FD** (Full also zips `seqsigwit`). `group_body_peeks` also merges a hole of at most 64 KiB when the span stays at most 256 KiB. |
| Head-resolve identity | `RBITCOIN_IO` | uring/pread on **`txid.body`** (not a packed body prefix) |
| Spend-meta 8 B peeks | `RBITCOIN_IO` | uring/pread on **`spent.body` FD**. Page-grouped with the pin caps (`group_body_peeks`), pipelined at ring depth 128. A singleton stays an 8-byte pread. |
| Spend annotate | `RBITCOIN_IO` | 4 KiB page RMW on **`spent.body`** (uring or pwrite, depth 128, one in-flight RMW per page). The sweep sets `POSIX_FADV_RANDOM` and restores `POSIX_FADV_NORMAL` on exit. Unknown meta decides sole / multi / promote inside the same page groups. |
| Class C create-height | (RAM fence) | no IO |
| Class A body/idx **linear append** | always | **pwrite** (three stems + three idx). `--datadir-hdd` submits each body stem as its own `pwrite_batch`; otherwise the stems are one wave |
| SH unsorted collect (Class A) | libc `pread` | **Two** sequential coalesced **16 MiB** `txout.body` scans (`sh_extract_workers`): static create-fk spans (no steal); per-worker identity maps spill-largest as `SHKSP01` under `keys/NN/` (one spill writer, 1-slot queue; tmp+rename, no `sync_all`; first-fk delta singles); merge folds those files into one map, one walk to `scripthash.head/NN` + `multi/NN.fuse8`; leftover keys shapes refuse. Then fuse-hit `SHPST01` post spills under `post/NN/` (`80n+8f` estimate, same 1.5 GiB worker cap and 1-slot writer; tmp+rename, no `sync_all`). Not TLS uring: one large positional read per span, not a completion machine. Writes are libc `pwrite` / tmp+rename. Pass 2 does not Fd-index the main MPHF; pack folds one shard's spills then `slot_for_key16` once per unique multi key. Packed 2-bit `g` is ~8 MiB per pack worker, not a 12 GiB `.val` page-cache set. |
| SH Electrum/Esplora join | `RBITCOIN_IO` | Query-thread session: waved `idx_body_pipeline` on **`txout.body`**, optional page-grouped **`txid.body`** (history: creates+spenders; listunspent: unspent creates; balance/`/address` stats: none), `get_spender_meta_at_abs_batch` on **`spent.body`**. An unpaged join is one spend-slot batch (`join_spends_wave` on the whole create list). A height-ascending page flushes when the next create has no spend slots or those slots leave the peek group. A newest page shorter than its limit reads the spend slots of the creates it kept instead of walking every block. A `from_height` window reads `input.body` for those blocks and does not read spend slots for the older creates. Megakey **extent**: one span pread of `extent_n` pages, then linked 4 KiB tail. Schema-18 mode 10 leftovers **refuse** on open. Does **not** share a confirm TLS ring. |
| Block index build (filters + tweaks) | `RBITCOIN_IO` | `read_index_window`: one held TLS session per window, four stages (`create.loc` / `input.loc` / `seqsigwit.loc` windows → block `txout` / `input.body` / `txid.body` spans → parent `create.loc` + P2TR-output `seqsigwit.body` + parent `txid.body` → parent `txout`), offsets from RAM checkpoints so nothing nests. Parents read once per window. Short/errno on a live session libc-completes; no session → serial pread through the same stages. Writes are not on the ring: one filter put and one tweak put per window. |
| SP-tweak hole serve | `RBITCOIN_IO` | `tweaks_for_height` for heights the index has not sealed: idx ranges **before** TLS ring; uring/pread `txout.body`, then `seqsigwit` + parent `txout` for P2TR only. |

Default: Linux uring if the ring opens else libc pread; Darwin pread; Windows
IOCP. Ring depth **128** (merge may grow). `RBITCOIN_IO=pread` forces libc.

### Table transport (all fd)

| Object | Tier | Notes |
|--------|------|--------|
| **`txout.body`** | L0 | Hot outs (pin / SH / Electrum tweaks); pread/pwrite/uring |
| **`seqsigwit.body`** | L0 | Cold ins+witness; reconstruct / getdata only |
| **`spent.body`** | L0 | 8 B×n_out sole-spender; annotate RMW |
| **`create.loc` / `seqsigwit.loc`** | L0 | FdOnly 2 B/create (hot) / u16 (cold); leftover `spent.off` unlinked. `create.loc` leftover stamp: batched window preads, sum/read through max fk in-window, running-sum + SIMD deinterleave (no loc L2) |
| **`tx.head` segments** | L0 | Open OA: read-only `MAP_SHARED` view of the slot file (probe + insert hop, no syscall; slots carry a 7-bit fingerprint) + one 4 KiB page pwrite per dirty page. Sealed: mmap `.fuse8` (heap `fuse8=0`); packed BDZ `g` FdOnly 4 KiB page stream (`KIND_MPHF_G`); MPHF output is `rel−1` |
| Header hash head | L0+L1 | 128-slot (~3 KiB) chunk cache |
| Hash multi-list (`.mlt`) | L0 | Linear append |
| **`scripthash.head` / body** | L0+L1 / idx in process | Sealed MPHF main: mapped occ + BDZ `g` FdOnly + tag/val pread, **no fuse**. Ingest/OA: 4 KiB chunk cache. Sealed ovf L0 SHSR: idx + mapped `.fuse8`. L1 ovf: mapped fuse + mapped occ + FdOnly `g`. Body slabs L0 |
| **Spenders** | L0 | Linear append |
| `confirmed` / `header_txs_*` / `strong_tx` | **L2** | InRam write-behind; barrier = `Store::flush_class_c_tip` |
| Create-height fence | RAM | Built from confirmed + header_txs; no `tx_height.body` |
| Mempool (`{datadir}/mempool/*`) | L2 sidecar | Private; **not** Class A |

### Hybrid paths (easy to misread)

| Path | Table part | Fd/uring bulk part |
|------|------------|---------------------|
| Pin outs | FdOnly `create.loc` ranges (batched window preads; sum/read only through max fk in-window) | uring/pread `txout` bytes (starting OS page; full span if need is likely to spill) |
| Head resolve stream | Open OA probe through its read-only map (no syscall); sealed fuse + FdOnly BDZ `g` pages on the held session; **one** FdOnly loc batch after identity (standalone bulk, not on the probe ring) | uring/pread `txid.body` identity |
| IBD **getdata serve** reconstruct | FdOnly `create.loc` / `seqsigwit.loc` ranges for a contiguous `header_txs` run | libc span pread of `txout.body` + `seqsigwit.body` in parallel (not confirm `idx_body_pipeline`) |

---

## Head insert locality

Do not demap heads without an operator-host measurement (musl static).
A host A/B showed io_uring head inserts about 5× slower on head ms/blk than
a mapped insert. Prefer page-coalesced pread → mutate → pwrite over per-slot
uring. Segmented heads do not remove that page-locality constraint.

---

## Settled IO shape

Phase 6 is done: the workspace has zero `memmap2` / `MmapMut` (top of this
file). Multi-GiB random tables stay FdOnly. Small Class C and the mempool
stay explicit process buffers. A host A/B comes before a demap. Agent
correctness tests under `/tmp` are required; perf ship/fail is host-only.

---

## Host benchmarks (operator; musl static)

### Rules

- Run on a **real host** with a **local filesystem** datadir (not agent 9p workspace).
- Use the **portable static musl** binary — same as release (`docs/reproducible-builds.md`).
- **Do not** use `nix-shell --run 'cargo build -p rbitcoin-node --release'` for IBD
  benches (Nix-store glibc dynamic link).

### Build musl `rbitcoin-node`

```bash
# Repo root; Nix flakes enabled
nix build .#rbitcoin-musl --out-link result
mkdir -p target/release
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/
file target/release/rbitcoin-node   # must say "statically linked"
# or: ./scripts/repro-build.sh
```

### IBD / tip-rate window (primary live gate)

```bash
export RBITCOIN_IO=uring   # or pread for second arm
./target/release/rbitcoin-node --datadir /path/to/local/datadir …flags…

# Capture steady-state minutes:
grep 'ibd: perf {' host.log | sed 's/.*ibd: perf //' | jq -c '{ts, load_ms, rss_kb, rss_file_kb}'
```

**A/B:** same host, same network/milestone/height band when possible; baseline
SHA vs candidate SHA; compare tip rate, head ms/blk, RssFile. **Fail ship** on
5×-class head regression or agreed **>+20%** head ms/blk without tip-rate win.

There is no separate store microbench binary (`rbitcoin-store-bench` was
removed; default graph is product + suite). Head-insert A/B is the live
`ibd: perf` JSON window above.

`TableFile` has no maps (`memmap2` not in the workspace). There is no
`RBITCOIN_TX_HEAD_ACCESS` hatch. Tables are fd pread/pwrite + fallocate.
Sealed `.fuse8` sidecars and SH BDZ3 occupancy prefixes are the mmap
exceptions (read-only, not `MmapMut`). Packed `g` stays FdOnly. Class C is
L2 write-behind (`flush_class_c_tip`) — **not** mapped (`strong_tx` write-behind is tip-last).
Mempool schema 4 is InRam Vecs + `pwrite`.

Live head insert copies the page from the map → mutate → one pwrite per dirty
page (no pread, not per-slot uring); the map shows the new slots once the
pwrite lands. Head resolve hops the map for the open OA, then one loc batch
after identity (not on the probe ring). Node start logs `io=`,
not `tx_head_access=`.
