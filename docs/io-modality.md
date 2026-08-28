# Store IO modality matrix

**Source of truth** for bulk `RBITCOIN_IO` vs table transport (fd + tiered RAM).
**Phase 6 complete:** workspace has **zero `memmap2` / `MmapMut`** for store tables.

Related: [`OPERATOR.md`](../OPERATOR.md) (env knobs), [`concurrency.md`](./concurrency.md),
[`crash-recovery.md`](./crash-recovery.md), [`architecture.md`](./architecture.md).

---

## Two independent layers

| Layer | Controlled by | Values | Purpose |
|-------|---------------|--------|---------|
| **Bulk batch** | `RBITCOIN_IO` only | `uring` \| `pool` \| `iocp` \| `pread` | Multi-op **completion session** on file handles (`txout` pin/outs, `inwit` reconstruct, spend meta/ann on `spent`, Class C bulk) |
| **Table transport** | [`TableFile`](../crates/rbitcoin-store/src/file.rs) | **FdOnly always** | All payload via pread/pwrite; fallocate grow; no process maps |

**`RBITCOIN_IO` selects the completion-session backend** (not per-path).
Unknown tokens (including deleted `mmap`) fall through to the platform default.

| Token | Backend |
|-------|---------|
| `uring` / `io_uring` | Linux `io_uring`. On Windows the token opens **IOCP** |
| `pool` | Worker-pool completion ring (Darwin **default**; Linux CI pin) |
| `iocp` | Windows IOCP (Windows **default**) |
| `pread` / `fd` / `libc` / `pwrite` | Disable session; libc positional IO (+ workers for reads) |

**Defaults:** Linux `io_uring` if the ring opens, else pool. Darwin **pool**.
Windows **IOCP**. Windows IoRing is not supported.

**Windows table handles** are `FILE_FLAG_OVERLAPPED` so IOCP can bind.
Create, open, header/trailer, and grow use positional `IoHandle`
pread/pwrite and `SetFileInformationByHandle(FileEndOfFileInfo)`. Do
**not** mix those handles with std `Read`/`Write`/`Seek` — `WriteFile`
with a NULL `OVERLAPPED` is os error 87 (`ERROR_INVALID_PARAMETER`).

**kqueue is not a regular-file backend.** Darwin files report ready immediately;
`read` still blocks. POSIX AIO (`EVFILT_AIO`) and `dispatch_io` are also
thread pools (`kern.aiomax` default 16) — same class as `pool`, not an
SQ/CQ. The pool session is the honest Darwin completion ring. Pool
**workers** are process-shared; each TLS session keeps its own CQE queue.

Harvest invariants (TLS session): every SQE is tracked by packed
`(kind, epoch, slot)`. A CQE that is unmatched, duplicate, or from a
prior epoch is `Corrupt`, not a completion and not a TipOnly miss.
`drain_all` is `Result`; leftover pending is `Corrupt`. CQ overflow is
`Corrupt`. Per-op short/errno on a live session still libc-completes that
op; libc fail is `StoreError::io`. `RBITCOIN_IO=pread` is the only
whole-batch pread fallback (session unavailable also falls back).

Machines (spend-annotate RMW, fused head-resolve, pipelined bulk fill)
stay **multi-stage**. Pool/IOCP are session backends — they do
not flatten those loops to one-shot `pread_batch`.

---

## RAM tiers (L0 / L1 / L2)

| Tier | Where hot bytes live | Sync |
|------|----------------------|------|
| **L0** | Kernel page cache via pread/pwrite; process holds staging only | Payload then HWM publish; `sync_data` on flush barriers |
| **L1** | 4 KiB head pages / 3–4 KiB SH chunks (working-set caches) | Write-back dirty page/chunk with one pwrite |
| **L2** | Compact Class C (`confirmed`, `header_txs_*`, `strong_tx`) full `Vec` in process | **Write-behind:** RAM mutate during commit; complete-or-fail body image on `flush_class_c_tip` **before** body-queue dequeue |

**Never L2:** `txout` / `inwit` / `spent`, full `tx.head` / `*.idx`.
`RBITCOIN_CLASS_C_INRAM_MAX_MB` (default 256) caps **`confirmed`** and
**`header_txs_*` only**. `strong_tx` stays L2 (1 bit/fk). Create height is a
RAM fence (~15 MiB at 1M blocks), not a file.

---

## Current matrix (`RBITCOIN_IO=uring`)

### Bulk batch (env)

| Path | Env | Syscalls |
|------|-----|----------|
| Pin outs / body pipeline | `RBITCOIN_IO` | uring/pread on **`txout.body` FD** (Full also zips `inwit`) |
| Head-resolve identity | `RBITCOIN_IO` | uring/pread on **`txid.body`** (not a packed body prefix) |
| Spend-meta 8 B peeks | `RBITCOIN_IO` | uring/pread on **`spent.body` FD** |
| Spend pure-write annotate | `RBITCOIN_IO` | uring/pwrite or pwrite on **`spent.body` FD** |
| Class C create-height | (RAM fence) | no IO |
| Class A body/idx **linear append** | always | **pwrite** (three stems + three idx) |
| SH unsorted collect (Class A) | libc `pread` | Sequential coalesced **16 MiB** `txout.body` spans (nCPU workers). Not TLS uring: one large positional read per span, not a completion machine. Writes are libc `pwrite`. |
| SH Electrum/Esplora join | `RBITCOIN_IO` | Query-thread session: waved `idx_body_pipeline` on **`txout.body`**, optional page-grouped **`txid.body`** (history: creates+spenders; listunspent: unspent creates; balance/`/address` stats: none), `get_spender_meta_at_abs_batch` on **`spent.body`**. Megakey **extent**: one span pread of `extent_n` pages, then linked 4 KiB tail. Schema-18 mode 10 leftovers: linked 4 KiB walk. Does **not** share a confirm TLS ring. |
| SP-tweak backfill | `RBITCOIN_IO` | idx ranges **before** TLS ring; uring/pread `txout.body`, then `inwit` + parent `txout` for P2TR only. Writes are **not** the load ring: batched `sp_tweaks` body+idx pwrite (not per-tx CQEs). |

Default: Linux uring if the ring opens else pool; Darwin pool; Windows
IOCP. Ring depth **128** (merge may grow). `RBITCOIN_IO=pread` forces libc.

### Table transport (all fd)

| Object | Tier | Notes |
|--------|------|--------|
| **`txout.body`** | L0 | Hot outs (pin / SH / Electrum tweaks); pread/pwrite/uring |
| **`inwit.body`** | L0 | Cold ins+witness; reconstruct / getdata only |
| **`spent.body`** | L0 | 8 B×n_out sole-spender; annotate RMW |
| **`txout.idx` / `inwit.idx` / `spent.idx`** | L0 | Append pwrite; reads pread; **grow-tight** (~1 MiB) |
| **`tx.head` segments** | L0+L1 | Open OA: 4 KiB page-coalesced RMW. Sealed: RAM fuse8; packed BDZ `g` FdOnly 4 KiB page stream (`KIND_MPHF_G`); MPHF output is `rel−1` |
| Header hash head | L0+L1 | 128-slot (~3 KiB) chunk cache |
| Hash multi-list (`.mlt`) | L0 | Linear append |
| **`scripthash.head` / body** | L0+L1 / idx in process | Sealed MPHF main: BDZ `g` FdOnly + tag/val pread, **no fuse**. Ingest/OA: 4 KiB chunk cache. Sealed ovf L0 SHSR: idx+fuse8. L1 ovf: RAM fuse + FdOnly `g`. Body slabs L0 |
| **Spenders** | L0 | Linear append |
| `confirmed` / `header_txs_*` / `strong_tx` | **L2** | InRam write-behind; barrier = `Store::flush_class_c_tip` |
| Create-height fence | RAM | Built from confirmed + header_txs; no `tx_height.body` |
| Mempool (`{datadir}/mempool/*`) | L2 sidecar | Private; **not** Class A |

### Hybrid paths (easy to misread)

| Path | Table part | Fd/uring bulk part |
|------|------------|---------------------|
| Head resolve stream | FdOnly **page-batched** head probe + FdOnly idx | uring/pread body prefix |
| Pin outs | FdOnly `txout.idx` ranges | uring/pread `txout` bytes (4 KiB first page, extend if short) |

---

## Historical record: head insert uring ~5× slower

| Commit | Note |
|--------|------|
| `0ee28c0` / `77cb2ab` | io_uring bulk / page-grouped RMW for `tx.head` insert |
| **`259b766`** (2026-07-23) | **Reverted to mmap-only head insert.** Host A/B: **io_uring head inserts ~5× slower on head ms/blk** than mmap Release. Bulk uring kept for **reads** only |
| `788936e` | Page-coalesce insert still via **plain map** `write_at` |
| `bulk_io::page_rmw_pipelined` | **Test-only** (`#[cfg(test)]`) — not the head path |
| `3a0c220` | **Body** FdOnly success (different pattern: linear append + bulk batch read) |
| `f829090` / `11134cb` | Segmented idx/head landed **after** the 5× failure |

**Implication:** do not ship head demap without **operator host** A/B (musl
static). Prefer page-coalesced **pread→mutate→pwrite** over per-slot uring.
Segmented heads reduce grow/remap pain but do not free us from page locality.

---

## End goal (phased)

1. **FdOnly** for multi‑GiB random tables: `tx.idx` → `tx.head` / header head → SH head/body / spenders.
2. **InRam** (explicit process buffers) for small Class C / mempool — not leftover MapFull “because small.”
3. **Remove `memmap2`** from the workspace.
4. Update this doc after **each** phase with host A/B results.

Agent correctness tests under `/tmp` are required; **perf ship/fail is host-only**.

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
grep 'ibd: perf' host.log
grep 'ibd: perf_dbg' host.log    # head=, plan_batch, class_a head insert, pin
grep 'ibd: sizes' host.log       # rss= anon= file=
```

**A/B:** same host, same network/milestone/height band when possible; baseline
SHA vs candidate SHA; compare tip rate, head ms/blk, RssFile. **Fail ship** on
5×-class head regression or agreed **>+20%** head ms/blk without tip-rate win.

### Store microbench (phase 2 head insert A/B)

Binary: **`rbitcoin-store-bench`** (`crates/rbitcoin-store`).

```bash
# Dev / agent (glibc nix-shell) — correctness + rough order of magnitude only:
cargo build -p rbitcoin-store --release --bin rbitcoin-store-bench
./target/release/rbitcoin-store-bench --n 200000 --bits 18 --dir /var/tmp/head-ab

# Operator preferred: build via musl package (ships when -p rbitcoin-store is built):
nix build .#rbitcoin-musl --out-link result
# After install from result, or:
find result -name 'rbitcoin-store-bench' 2>/dev/null
# Run on local NVMe, not 9p:
./target/release/rbitcoin-store-bench --n 500000 --bits 20 --dir /var/tmp/head-ab
```

Maps are gone (`memmap2` not in the workspace). There is no `RBITCOIN_TX_HEAD_ACCESS`
hatch and no `--access` bench flag. Tables are fd pread/pwrite + fallocate.
Class C is L2 write-behind (`flush_class_c_tip` before BQ dequeue).

Live head insert is page-coalesced pread → mutate → pwrite (not per-slot uring).
Head resolve batches one pread per distinct probe page. Node start logs `io=`,
not `tx_head_access=`.
