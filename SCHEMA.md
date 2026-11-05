# On-disk schema (current)

**Version:** `SCHEMA_VERSION = 26` (`rbitcoin_primitives`).  
**Status:** 26 is `header.body` 88 B (consensus fields only). Occupied 24/25
rewrites each 96 B row down to 88 B (`header.body.grow` then rename), dropping
the trailing `size:u32` + `weight:u32`. Block size and weight are summed from
`txstat` for that header's create range. A 25 binary refuses 26 `meta`.
25 is `txstat.body` 8 B/create (canonical ULEB `fee_sat`/`base`/`wit_extra`; `n_in` is `input.loc`;
per-header remaining-byte overflow in `txstat.ovf` + `txstat.blk`). Occupied
24 rewrites `meta` and zero-extends `txstat.body` to `create.loc` count (**no**
`txout.body` rewrite; leftover LAYOUT17 still has uleb `input_count`). Unreleased
leftover `txfixed.body` is unlinked. A 24
binary refuses 25 `meta`. 24 is `header.body` 96 B (trailing `size:u32` + `weight:u32`). Occupied
23 leaves 88 B rows as they are. SH extent last-page reserved (offset 20) is create
count (`0` = unknown; readers walk, appender stamps on pack/append). 23 is `create.loc.ovf` 16 B (`fk:u64` + strides/`n_out`
u32) so a consensus-valid ~1 MiB txout (and `n_out > 65535`) stores. Occupied 22
Class A rewrites 12 B ovf rows and `meta`. 22 is `create.loc` + `seqsigwit.loc` (no
Class A `{txout,spent,seqsigwit}.idx`), LAYOUT17 without `output_count`, and spent
slots flags + u40 spend fk + u16 vin (still 8 bytes). `txout` amount is flags bits
4–7 = decimal exponent (0–9) + ULEB mantissa (`sats = mantissa × 10^e`). Encoding
is canonical compact: strip trailing tens up to `e=9` (`e<9` and mantissa
divisible by 10 is Corrupt; zero is `e=0`, mantissa 0). Meta older than 22
is one refuse, empty or occupied: `schema before 22 refuses this datadir;
wipe datadir and redo IBD`. That is the last time `tx.body`, `txout.body`,
or `inwit.body` / `seqsigwit.body` had to be deleted rather than rewritten.
`schema_file_openable` is 22 through 26. A 23 binary refuses 24 `meta`.

Operator copy-paste (which dirs to wipe; kill-9 is not a migrate):
[`docs/operator/storage.md`](./docs/operator/storage.md#schema-upgrade).

## Find it fast

| Question | Go to |
|----------|-------|
| Can this datadir open, migrate, or must it be refused? | [Changing durable bytes](#changing-durable-bytes), then [schema history](./SCHEMA_HISTORY.md) for earlier releases |
| What do I need to wipe or rebuild as an operator? | [Schema upgrade](./docs/operator/storage.md#schema-upgrade) |
| Which files make up a datadir? | [Datadir layout](#datadir-layout) |
| Where is a transaction, header, or scripthash lookup stored? | [Class A transactions](#class-a--transactions), [hash heads](#hash-heads-headerhead--generic), [Class B scripthash](#class-b--scripthash-electrum) |
| What is the current encoding or table geometry? | Pick the table in [Design at a glance](#design-at-a-glance), then follow its section below |
| Does this change require a schema bump? | [What forces a schema bump](#what-forces-a-schema-bump) |
| How large is the reference mainnet store? | [Mainnet census](#mainnet-census-this-trees-reference-datadir-2026-08-13) |

## Contents

- [Changing durable bytes](#changing-durable-bytes)
- [Schema 17 freeze](#schema-17-freeze)
- [Design at a glance](#design-at-a-glance)
- [Datadir layout](#datadir-layout)
- [Common file header](#common-file-header-16-bytes)
- [Identity](#identity)
- [Growable var records](#growable-var-records-body--loc)
- [Class A headers](#class-a--headers)
- [Class A transactions](#class-a--transactions)
- [Tx address head](#tx-address-head-segmented-txhead)
- [Hash heads](#hash-heads-headerhead--generic)
- [Class B scripthash](#class-b--scripthash-electrum)
- [Class C chain tip](#class-c--chain-tip)
- [Mainnet census](#mainnet-census-this-trees-reference-datadir-2026-08-13)
- [Query-layer notes](#query-layer-notes)
- [Related docs](#related-docs)

### Changing durable bytes

A populated datadir must not be silently wiped. Pick one, and write it here
plus [`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md) in the **same commit** as the
format code:

| Option | When |
|--------|------|
| **Soft migrate** | Payload-only: open legacy, `warn!`, rewrite on open or next seal — **not** “recreate whole table”. fuse8 v1 is **not** this (explicit refuse). |
| **`SCHEMA_VERSION` bump** | Class A / OA / body layout change, or anything that cannot soft-open prior files |
| **Explicit refuse** | Hard error with a one-line wipe/reindex message (which files) |

**Before 22:** `meta` below 22, empty or occupied, returns
`schema before 22 refuses this datadir; wipe datadir and redo IBD` before
any table parser runs. There is no per-version rewrite for 13–21. Layouts
from those versions are in [`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md); the
code that opened them is gone.
**Leftover index layouts a meta ≥ 22 datadir can still hit:** fuse8 **v1**,
flat `tx.head.meta`, flat `*.idx.meta`, a file (not a directory)
`scripthash.body`, and pack8 **Paged** (mode 10) **refuse**. Errors:

```text
index refuses fuse8 v1; wipe store/tx.head and store/scripthash* then restart (Class A kept; tx.head rebuilds, SH rematerializes with --sh-index)
index refuses flat tx.head.meta; wipe store/tx.head then restart (Class A kept; tx.head rebuilds)
index refuses flat *.idx.meta; place files under store/{stem}.idx/ (meta + NNNNNN segments) then restart (Class A kept)
index refuses Shared (file) scripthash.body; wipe store/scripthash* then restart (Class A kept; SH rematerializes with --sh-index)
index refuses pack8 Paged (mode 10) scripthash heads; wipe store/scripthash* then restart (Class A kept; SH rematerializes with --sh-index)
```  
Table file headers **22–26** remain `schema_file_openable`. A 22 binary refuses 23 `meta`.
**22→23 open:** occupied Class A rewrites `create.loc.ovf` 12 B rows (`fk:u64` + two u16) to 16 B (`fk:u64` + two u32) and `store/meta` to 23. Empty 22 rewrites `meta`. A 22 binary refuses 23 `meta`. Spent vin stays u16 (stripped input ≥ ~41 B ⇒ ≲24k vins in a 1 MB block; widening would bump the 8 B spent slot).
**23→24 open** (schema 24/25 binaries): rewrote `header.body` 88 B rows to 96 B. This binary does not expand. An 88 B body stays 88 B and `meta` rewrites to 26.
**24/25→26 open:** rewrite each 96 B `header.body` row to 88 B (drop trailing `size`/`weight`) via `header.body.grow` then rename; rewrite `meta` to 26. A body that is already 88 B is unchanged. A 25 binary refuses 26 `meta`. Crash with leftover `.grow` discards it and retries.
**24→25 open:** rewrite `meta` to 25; create or zero-extend `txstat.body` to `create.loc` count. Do **not** rewrite `txout.body`. Unlink leftover `txfixed.body`. A 24 binary refuses 25 `meta`.
**Endianness:** little-endian for all multi-byte integers.

Older versions and migration notes live in [`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md).

---

## Schema 17 freeze

Class A shape settled here at schema 17 and is still the live layout under
the `SCHEMA_VERSION` at the top of this file (26). Schemas 18–26 already
shipped. Meta 22–26 is what this binary opens (rules above). Earlier
layouts are history in
[`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md). A byte-incompatible change bumps
from that live constant
([Changing durable bytes](#changing-durable-bytes)). It does not target
schema 18.

### What 17 locks (on-disk)

| Object | Frozen choice |
|--------|----------------|
| Class A | Split `txout` / `seqsigwit` / `spent`; thin LAYOUT17 meta; kinds **0–9**; 8 B spent slots; `spent.ovf` |
| Identity | Dense `txid.body` (32 B/fk); segmented `tx.head` (25-bit + fuse8 v2) |
| Loc | `create.loc` (2 B/create + `create.off` + ovf) and cold `seqsigwit.loc`; leftover Class A `{txout,spent,seqsigwit}.idx/` unlinked on empty 21–24. Flat `*.idx.meta` **refused**. |
| Class B | SH runs `key_len=40` unique `(sh, create_fk)`; megakey pages ULEB deltas (`ver=1`); body **dir** (sharded). Leftover file body **refused**. Slab **class** is the byte allocation (32…2048); `used` is the fk count and may exceed the old geometric `slab_cap(class)` when the ULEB stream fits. Decode `used` fks from the payload. |
| Class C | `confirmed[]` + `header_txs_*`; no `tx_height.body`; `strong_tx` bitset |
| Tweaks | Segmented `sp_tweaks.idx/` + `sp_tweaks.body/` (`off:u32`, body `0`/`33`) |
| Secret | `store.secret` XOR of scripts/witness; `mix_txid` for **open** `tx.head` page-local probes (not shard-by-txid). Sealed MPHF/fuse use the same mixed u64. |

Empty / leftover prior files may be unlinked or `meta` rewritten on open as
already listed above. A packed `tx.body` with creates, leftover schema-16 SH
catalogs, or 16-layout Class A with creates is **refused**.

### Writer / RAM policy (same schema — not a bump)

| Policy | Choice |
|--------|--------|
| Loc | One loc pair per create; `seqsigwit` is the fat stem (cold) and does not force `txout` splits. `tx.head` rolls at OA 80% slots only. |
| `strong_tx` | Always L2. **`confirmed`** and **`header_txs_*`** stay in RAM up to 256 MiB, then fd. |
| `RWF_DONTCACHE` | **Not used.** Annotate pwrites hit `spent.body` only; evicting those pages does not protect `txout`, and the next block wants the same spent pages. |

### New script kinds without a wipe

Kind nibble **10–15** is **Corrupt** on this binary (no implicit width). A new
consensus script type does **not** force a wipe of the Class A shape settled
at 17:

| Path | On-disk | This binary | A later binary |
|------|---------|-------------|----------------|
| **RAW** | kind 0 + CompactSize + bytes | already decodes | same |
| **Kind nibble** | new kind + known width; bump `SCHEMA_VERSION` | refuses the new `meta` (or unknown kind) | reads these files; writes the new version |

Use RAW when the type is rare. Use a kind-nibble bump when the type is common
enough to pay a width table. That bump is not a silent in-place rewrite of
existing files. SeqSigWit `create_fk` Δfk (parked) is the same class: a
`SCHEMA_VERSION` bump or an seqsigwit-only rewrite, not a silent mutate of
existing rows.

### Field widths (10 years)

Assume ~400k–700k creates/day. Ten years ≈ +1.5e9…2.6e9 creates on top of
~1.4e9.

| Field | Width | Headroom |
|-------|-------|----------|
| `create_fk` / `header_fk` | u64 | 1e18-class; not a 10y issue |
| Spent spend fk | u40 | 2^40 ids ≈ 1.1e12 creates; census ~1.42e9 at h=962k. `fk ≥ 2^40` is Corrupt (no wrap) |
| Spent vin | u16 | Consensus max inputs at 400 kWU is ~2.4k. `vin ≥ 2^16` is Corrupt |
| Height / `confirmed[]` index | u32 | ~1e6 heights now; 10y adds ~0.5e6; year 2106 is **timestamp**, not height |
| Loc strides | u8 (create) / u16 (seqsigwit) | Overflow sidecar: `create.loc.ovf` **u32** strides + **u32** `n_out` (schema 23); `seqsigwit.loc.ovf` u32 strides. Sentinel when txout ≥ 2048 B aligned or `n_out ≥ 256`; seqsigwit ≥ 512 KiB |
| `tx.head` bits | 25-bit segments | Roll + seal; no mono-file widen |
| SH megakey page | 4 KiB delta stream | Page chain; not a single-integer cap |
| `sp_tweaks` off | u32 per segment | Already segmented |
| Script kind | 4 bits | 0–9 used; 10–15 reserved Corrupt; extension = RAW or a kind-nibble bump |

Practical risks are **loc overflow without ovf** (sentinel with missing
sidecar) and **Bitcoin timestamp 2106** (consensus, every node).

### What forces a schema bump

A **byte-incompatible** change to Class A / OA / body / idx / SH catalog
layout, or anything that cannot soft-open the live files. Bump from the
live `SCHEMA_VERSION`, not from 17.

| Change | Bump? | Notes |
|--------|-------|-------|
| New implicit-width script kind | Optional | RAW = no bump; nibble = next `SCHEMA_VERSION` (this binary refuses it) |
| SeqSigWit Δfk | Yes or seqsigwit-only rewrite | Parked; cold stem |
| Idx not stride-8 / not u32 | Yes | Would retire the 8-align pad |
| Packed Class A again / merge stems | Yes | Wipe |
| SH `key_len` ≠ 40 or raw-u64 pages | Yes | 17 already refuses leftovers |
| `txid.body` not dense 32 B/fk | Yes | Soft-open only if dual-read is explicit |
| Fuse8 envelope v3 | No | Soft-migrate like v1→v2 (log + rewrite; no wipe) |
| Independent rolls / L2 strong / no DONTCACHE | No | Writer/RAM only |

Parked size work that is **not** a live-layout tweak: seqsigwit Δfk; drop 8-align
pad on empty seqsigwit / zero-out spent (needs a different idx encoding);
`txid.body` compression. Do not chase `seqsigwit` size as an IBD **hot-set**
win — put it on a cold volume (`--datadir-cold`). Census:
[Mainnet census](#mainnet-census-this-trees-reference-datadir-2026-08-13).

Process: bump `SCHEMA_VERSION`, document this file + `SCHEMA_HISTORY.md` in
the same commit, refuse or soft-open with a one-line operator message. Do
not treat decode failure as “recreate the whole table” unless the OA layout
itself changed.

---

## Design at a glance

| Concern | Choice | Why |
|---------|--------|-----|
| Class A body | **Split** `txout` (thin meta + template outs) + `seqsigwit` + `spent` (8 B×n_out) | Pin/SH read outs only; annotate isolates scripts |
| Class A identity | Dense **`txid.body`** sidefile (32 B header + 32 B/txid by create_fk) | Fixed `fk → offset`; head-resolve multi-cand via sidefile, not body peeks |
| Non-coinbase prevout | On-disk **`create_fk:u64` + CompactSize vout** | Smaller than `prev_txid[32]`; archive stamps fk once; wire fills soft `prev_txid` from sidefile/create |
| Txid → create | Segmented keyless **`tx.head.*`** (25-bit OA open + MPHF/fuse sealed) | Open page from `mix_txid`; seal-time value-assigned MPHF + fuse8; **txid.body** verifies identity |
| Spentness | Annotation on **create output** (+ rare multi-list) | No multi-GiB `point.head` open-hash |
| Electrum index | Thin **create_tx_fk only** (inline ≤2 / geometric slabs / megakey pages) | Packed to ~run size; expand vouts/value/height at query via Class A + Class C |
| Best-chain commit | Advance **`confirmed[]` last** | Tip is the commit point; strong/height may lead tip after kill |

---

## Datadir layout

```text
<datadir>/
  store/
    meta                         # store magic + schema version
    header.body / header.head    # Class A headers + hash index (overflow: header.head.gN)
    header.adopt                     # IBD checkpoint list + milestone hash (not a header-chain copy)
    block.invalid                    # blocks that failed connect, kept across restart
    txout.body / create.loc / create.off / create.loc.ovf   # Class A outs (hot loc)
    seqsigwit.body / seqsigwit.loc / seqsigwit.off / seqsigwit.loc.ovf       # Class A inputs+witness (cold loc)
    seqsigwit.prune                  # optional: u32 LE pruneheight sidecar (`--prune-seqsigwit`; missing = off)
    seqsigwit.window/                # optional prune window: one {height}.bin per kept height
    seqsigwit.reloc                  # optional: append-only files live under --datadir-cold/store
    spent.body                                              # sole-spender 8 B × n_out; leftover spent.off unlinked
    tx.body / tx.idx.*                              # schema ≤14 packed (refused if non-empty)
    txid.body                                       # dense create_fk-ordered txids (schema 13+)
    txstat.body / txstat.ovf / txstat.blk            # 8 B/create ULEB econ + per-header tails (schema 25)
    input.loc / input.off / input.body               # spender → parent edges (8 B/input) + n_in (2 B/create)
    tx.head/                     # meta + open OA NNNNNN; sealed NNNNNN.mphf|.fuse8
    spent.ovf                    # multi-spender overflow (was spenders.body)
    confirmed.body               # Class C: height → header_fk
    strong_tx.body               # Class C: bitset, bit (tx_fk-1) = strong
    # tx_height.body retired in 16 (RAM fence from confirmed + header_txs)
    header_txs_first.body        # header_fk-1 → first_tx_fk
    header_txs_count.body        # header_fk-1 → tx count
    scripthash.body                  # 17 file variant: one shared TableFile
    scripthash.body/NN               # 17 dir variant: one TableFile per main shard
    scripthash.ovf/body              # dir variant: ingest + all sealed ovf
    scripthash.head/NN.mphf + NN.val + NN.packed # Class B MPHF main; `.packed` is the pack commit (pass-1 BDZ has no mark)
    scripthash.ovf/ingest                                # global OA ingest (key16+pack8, 2^25)
    scripthash.ovf/NNNNNN[.fuse8][.idx]                  # L0 SHSR pack8
    scripthash.ovf/NNNNNN.mphf|.val|.fuse8               # L1 promoted ovf (at most one)
    scripthash.runs              # leftover catalog (key_len=40); discarded at tip
    scripthash.unsorted/keys/NN/  # pass 1 dir of SHKSP01 spills (000000…); merge identity-map fold + one walk to head+multi fuse, unlinks; DONE.keys=SHKEYS02 last_fk marker
    scripthash.unsorted/multi/NN.fuse8  # throwaway fuse8 of 0xFFFF keys for pass 2
    scripthash.unsorted/post/NN/  # pass 2 dir of SHPST01 spills (000000…); pack folds to one map then slot_for_key16 + 2+ body; DONE.post=SHPOST02 last_fk; unlinked after pack
    # previous DONE / 24 B NN (SHUNSRT3) with no SHKEYS02 is wiped and pass 1 restarts; no SCHEMA_VERSION bump
    sp_tweaks.idx/  sp_tweaks.body/   # optional BIP-352 (schema 17 dirs; leftover files unlinked)
    blockfilter.idx/meta              # optional BIP158 basic (`--block-filter-index`): fmt:u32=1
    blockfilter.idx/NNNNNN            # 80 B slot per height from 0: off:u32 ‖ len:u32 ‖ header_fk:u64 ‖ filter_hash[32] ‖ filter_header[32]
    blockfilter.body/NNNNNN           # filter bytes (Core `BlockFilter` content), records back to back, no prefix; new NNNNNN pair when the next start passes u32. Commit: body sync, then idx sync, then publish. Open keeps the slot prefix whose records run back to back inside the body, cuts the body to its end, and drops slots whose header_fk is not confirmed[h]. Missing dirs: index off / not built

<datadir-cold>/                  # only when --datadir-cold is set
  store/
    seqsigwit.body / seqsigwit.loc / seqsigwit.off / seqsigwit.loc.ovf
    txstat.body / txstat.ovf / txstat.blk
    input.loc / input.off / input.body
    blockfilter.idx/  blockfilter.body/   # when --block-filter-index has created them
    sp_tweaks.idx/  sp_tweaks.body/       # when --sp-tweaks has created them
```

`--datadir` holds every file by default. `--datadir-cold PATH` places the
files the IBD pin path does not read under `PATH/store/` and writes
`seqsigwit.reloc` in the hot store: `seqsigwit.*`, `txstat.*`, `input.*`,
and, once those indexes exist, `blockfilter.*` and `sp_tweaks.*`. Pin / SH /
spend-annotate stay on the hot volume. `--prune-seqsigwit` is separate: it
drops historical `seqsigwit` below tip−288 and keeps that window on the hot
store. `txstat`, `input`, block filters, and tweaks are not pruned.

**Height → txs:** `confirmed[h]` → `header_fk` → contiguous Class A range  
`[header_txs_first[h−1], header_txs_first[h−1] + header_txs_count[h−1])`.

**Who writes what:** see [`docs/concurrency.md`](./docs/concurrency.md). IBD unified pipeline: confirm **commit** stage is the sole Class A appender (+ Class C / spends / tip); prep only plans Class A; peer IO does not write the store.

---

## Common file header (16 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `RBT1` |
| 4 | 2 | Schema version (u16) — live **26** (`SCHEMA_VERSION`). Occupied files keep the version they were written; **22–26** remain `schema_file_openable` |
| 6 | 2 | Table kind (u16) |
| 8 | 8 | Logical length (bytes), including this header |

### Table kinds

| Kind | Name |
|------|------|
| 1 | meta |
| 2 | header |
| 3 | txout (`txout.body`; was `tx` through schema 14) |
| 4 | input *(legacy kind id; no standalone tables)* |
| 5 | output *(legacy kind id; no standalone tables)* |
| 6 | point *(legacy kind id; no point.head)* |
| 7 | strong_tx |
| 8 | confirmed |
| 9 | array_link (idx files, dense arrays) |
| 10 | hash_head |
| 11 | scripthash |
| 13 | spender (`spent.ovf` multi-list) |
| 14 | txid_body (`txid.body`) |
| 15 | sp_tweaks (`sp_tweaks.body`; idx uses array_link) |
| 16 | seqsigwit (`seqsigwit.body`) |
| 17 | spent (`spent.body`) |
| 18 | delta loc (`create.loc` / `seqsigwit.loc` and `.ovf`) |
| 19 | txstat (`txstat.body`, 8 B/create) |
| 20 | txstat overflow (`txstat.ovf`) |
| 21 | txstat per-header locator (`txstat.blk`, 16 B/header) |
| 22 | inputs (`input.body`, 8 B/input) |
| 23 | inputs loc (`input.loc`, 2 B/create `n_in`) |
| 24 | blockfilter (`blockfilter.body`) |

---

## Identity

- **FK 0** = null / absent; otherwise **1-based** dense id into the table’s idx or bit/slot space.
- Lookups that use a **16 B key prefix** must **verify** full identity against Class A body when required.

---

## Growable var records (`*.body` + loc)

Used for Class A `txout` / `seqsigwit` / `spent` (and historically packed `tx.body`).

- **body:** append-oriented **unframed** payloads (no per-record length prefix).
- **loc:** schema 22 `create.loc` (txout + `n_out`) and `seqsigwit.loc` (cold);
  schema 23 ovf is 16 B u32 strides/`n_out`.
  Header hash lookup is a separate `HashHead`, not this loc.
- Record length = loc pair (txout/spent) or `seqsigwit.loc` (seqsigwit). Last record
  uses 8-aligned published body end.
- FK = 1-based create id.

---

## Class A — headers

### `header.body` record (fixed 88 bytes)

Consensus fields only. Schema 24/25 stored an extra `size:u32` + `weight:u32`;
open from those versions strips them. Block size and weight are not stored
here. A reader sums the header's `txstat` rows (`80 + compactsize(n) + Σ size`,
weight `4 * (80 + compactsize(n)) + Σ weight`).

| Field | Type |
|-------|------|
| prev_fk | u64 |
| version | i32 |
| timestamp | u32 |
| bits | u32 |
| nonce | u32 |
| merkle_root | [u8; 32] |
| hash | [u8; 32] |

### `header.head`

Open-address hash head (see [Hash heads](#hash-heads-headerhead--generic)): key = 16 B prefix of block hash → header fk. Multi-list for prefix collisions. Load ceiling **7/8**; overflow is a sibling generation, not an in-place rehash.

**Create:** single file. Mainnet **2²²** slots (~96 MiB sparse, ~3.67 M headers at 7/8). Tiny tests use 64 slots so generation roll is exercised.

**Overflow:** `header.head.g1`, `.g2`, … same slot count as create. Probe newest-first. No schema bump — same 24 B OA slot format.

**Open:** leftover `header.head/` directory (old 256-way shards) is **Layout refuse** (wipe `header.head` and `header.body`, reindex). A **single** file smaller than the create target is rewritten on open at the target slot count: write `header.head.grow`, fsync, rename over the live file (`.mlt` kept; no concurrent probes). Crash during rewrite leaves the previous undersized file. A target-sized gen0 with `occupied==0` and a non-empty `header.body` or `.mlt` is **Layout refuse** (wipe `header.head`, `header.head.mlt`, and `header.body`, reindex) — not a silent empty index.

### `header.adopt`

Sidecar for the IBD header walk. Not a schema bump and not a second copy of `header.body`. Missing is an empty walk. A file that does not parse does not skip scripts by height.

```text
0..8     magic b"rbtchdr1"
8..12    u32 LE checkpoint count
repeat   hash [u8; 32] ‖ height u32 LE ‖ work [u8; 32]
         ‖ header [u8; 80] (zeros if none)
         ‖ ntimes u8 ‖ 11 × time u32 LE
         ‖ period height u32 LE ‖ period-start header [u8; 80] (zeros if none)
         ‖ full-difficulty height u32 LE ‖ full-difficulty bits u32 LE (0 if none)
then     milestone hash [u8; 32] (zeros if none)
         base hash [u8; 32] ‖ base height u32 LE ‖ base work [u8; 32]
         tip header [u8; 80] (zeros if none)
         period height u32 LE ‖ period-start header [u8; 80] (zeros if none)
         full-difficulty height u32 LE ‖ full-difficulty bits u32 LE (0 if none)
         base period height u32 LE ‖ base period-start header [u8; 80] (zeros if none)
         base full-difficulty height u32 LE ‖ base full-difficulty bits u32 LE (0 if none)
```

Each checkpoint is 285 bytes. The tail is 364 bytes. Length is exact: `12 + count × 285 + 364`. An older or shorter file does not parse, and the script skip stays off.

Each checkpoint is the hash, height, and total work at the end of one look-ahead reply past the download queue, plus that reply's last header, up to 11 timestamps ending there, and the difficulty period after that header. `ntimes` is how many of those 11 slots are live, oldest first. The milestone hash is the header at the anchored milestone height when the walk passed it. The base is the stored header the checkpoints were built on. On restart, if that height already has a different hash, the file is ignored. A reorg below the base deletes the file. While `block.invalid` lists a block above the saved base, or one whose height is not found within 64 headers of the best chain, a saved candidate above the confirmed tip is not restored: it may build on that block, so the walk starts again from the tip. A listed block at or below the base is on no chain that walk can take. The per-checkpoint header, timestamps, and period-start header let the next look-ahead, a fork from that hash, or a rewind onto it check `nBits` and median time without a row in `header.body`. Full-difficulty height and bits are the last header in the period whose `nBits` are not the minimum-difficulty limit, so a restart can walk testnet difficulty back. The same pair is stored again for the base, for when every checkpoint has been rewound. The tail's period fields are the walk tip. Headers between the queue and that tip are not in this file.

### `block.invalid`

Sidecar of blocks that failed connect on a consensus rule, so a restart does not adopt a stored header chain through them again. Not a schema bump: missing is none. A file that does not parse is none and is replaced at the next mark. The whole file is written again (synced temp file, rename, directory sync) for each new failure and when `reconsiderblock` clears one. An IBD failure is written here before the retired walk goes to `header.adopt`. While a failure is not on disk, no walk is saved to `header.adopt` and an existing one is removed, and every later mark tries the write again. A restart while the write still fails has no record of that block and validates it again.

```text
0..8     magic b"rbtcinv1"
8..12    u32 LE count (at most 4096)
repeat   block hash [u8; 32]
```

Length is exact: `12 + count × 32`. Oldest first. Past 4096 the oldest hash gives way, so the newest failure survives restart. Mutated bodies, a header timestamp too far in the future, store and engine faults, and operator `invalidateblock` are not written. A descendant is invalid through its ancestor: the startup header scan and the IBD resume seed do not walk through a listed hash.

---

## Class A — transactions

### Dense identity sidefile (`txid.body`, schema 13+)

```text
offset 0..32    — 32-byte file header (standard 16-byte TableFile header + 16 pad)
offset 32+(fk-1)*32 — txid for create_fk = fk (1-based)
```

Append-published with Class A body/idx on the sole Class A write path. Count must match `txout` / `seqsigwit` / `spent` / `txid.body` / `txstat.body`. Head-resolve multi-cand identity peeks this file (fixed offset), **not** a body prefix.

### Confirm-time econ (`txstat.body`, schema 25)

```text
txstat.body  offset 0..32            — TableFile 16 + 16 pad
             offset 32+(fk-1)×8      — 8-byte cell
txstat.ovf   append-only             — remaining ULEB bytes when the stream exceeds 8 B
txstat.blk   offset 32+(header_fk-1)×16 — off:u64, len:u32, n_ovf:u32
```

Cell payload is three canonical ULEBs: `fee_sat`, `base` (non-witness
size), `wit_extra` (`total_size − base`). `n_in` is `input.loc` (u16). Readers
derive `size = base + wit_extra` and `weight = 4×base + wit_extra`. All-zero
cell = unstamped. A truncated ULEB or fewer than three fields means the rest
of the stream is in that header's overflow blob (`encoded[8..]` only). Missing
tail is `Corrupt("invariant: txstat overflow missing")`. Overlong ULEB is
Corrupt. Trailing non-zero after three fields is Corrupt. Class A append of
placeholders is all-zero and never overflows; only a confirm stamp can emit
tails. A cell written as four ULEBs starting with `n_in` (an unreleased
experiment) is not detected and is not rewritten; resync that datadir.
Blob entries are `u16 index_in_block` +
`u8 nrest` + rest, in block-index order. Empty header: `len=0`. Occupied 24 open
extends zeros to loc count (~11.3 GiB at the 2026-08-13 census if fully allocated).
Pin / SH / tweaks do **not** open these files. Unreleased leftover `txfixed.body`
is unlinked on open.

### Spender → parent edges (`input.body`, schema 25)

```text
input.off   ArrayLink: per 1024 creates, u64 file offset of the next window's first input
input.loc   2 B/create: n_in as u16 LE. 0 = unstamped
input.body  8 B × input, vin order
```

`n_in > u16::MAX` is Corrupt (no `input.loc.ovf`). A coinbase is `n_in == 1` and one null edge. Body record: parent `create_fk` as u40 LE (`0` = coinbase), then parent vout as u24 LE. `fk ≥ 2^40` or `vout ≥ 2^24` is Corrupt. A null parent with nonzero vout is Corrupt. The spending `vin` is the record index. Prefix-sum of `n_in` from the window checkpoint is the body offset (`8 × edges before this window`). Confirm appends these rows with Class A. Open with creates, no `input.loc`, and a `seqsigwit` count that matches `create.loc` walks `seqsigwit.body` with `decode_prevout_at` (prevout only) and writes the edges. A null parent in that payload is the coinbase edge (`vout` 0). `input` and `txstat` are not pruned.

### Split bodies (schema 15)

Each create_fk has three 8-aligned var records (loc maps; independent
stems; spent length is `8 × n_out` with `n_out ≥ 1`):

```text
txout.body  S:  thin LAYOUT17 meta | outputs (kind nibble + template payload)
seqsigwit.body Sw:  per-input flags|seq?|script_sig?|witness?
spent.body Ss:  8 B × n_out  (flags + u40 fk + u16 vin). Multi overflow → spent.ovf
```

New records set flag bit 4 (`PREV_ON_INPUTS`) and do not store parent `create_fk` or vout; that edge is `input.body`. A record without bit 4 is the legacy inline prevout (`NULL_PREV`, or `create_fk:u64` plus CompactSize vout). Open backfill of a missing `input.loc` still reads those legacy records. Empty seqsigwit: **8-byte zero pad** so loc strides stay strictly monotone.
Pin / SH / Electrum tweaks read **`txout` only**. Annotate RMW is on **`spent`** (`abs = Ss + 8×vout`).
Reconstruct zips `txout` + `seqsigwit`. First-wave Outs reads stay on the starting
OS page unless `4+(max_need+1)×38` (LAYOUT17 meta + kind + 5 B uleb amount + P2TR;
empty need: the loc span) is likely to spill; then the first wave is the full loc
span. Extend still covers a missed need.

Packed `tx.body` (schema 13–14: 32 B meta | inputs+witness | outputs) is **refused** if it contains creates.

### Packed body (schema 13–14, historic)

There is **no** leading magic byte and **no** leading txid (schema 11–12 stored txid at `[S, S+32)`). There are **no** standalone `input.body` / `output.body` tables.

**Alignment** (schema 13+): `S % 8 == 0` only. The pad exists so record starts
match **stride-8** (`IDX_STRIDE = 8`): loc stores body lengths as stride units.
The schema-11/12 page non-straddle rule for a leading 32-byte txid is **retired**
— identity is **`txid.body`**, not body bytes.

Decode walks meta + runs to a logical end; any remaining bytes in the loc span must be **all zeros**. Non-zero trailing garbage is corrupt.

**Body meta (schema 22 LAYOUT17, variable):** first byte bit 7 = `LAYOUT17`
(required). Bits 0–2 encode version 1/2/3 (else explicit i32 LE); bit 3 =
locktime 0 (else uleb locktime). Bit 4 (`N_IN_TXSTAT`) omits the following
uleb `input_count` (`n_in` is on `input.loc`; decode reports 0 until a
reader fills from that locator). Bits 5–6 reserved (nonzero → Corrupt).
New 25 writes omit the uleb (v2+locktime 0 is **1 B**). Leftover 24 rows
keep the uleb (typical v2+locktime 0 is **2 B**).
`CreateLocPair.n_out` (≥ 1) fills `TxRecord.output_count`. Schema-15 16-byte
prefixes (v1 starts `01 00 00 00`) are not accepted. Soft `TxRecord.txid` is
filled from the sidefile on get paths.

### Create / seqsigwit locators (`create.loc` / `seqsigwit.loc`)

```text
create.off              # ArrayLink: per 1024 creates, u64 txout_abs + u64 spent_abs
create.loc              # 2 B/create: (txout_strides:u8, n_out:u8)
create.loc.ovf          # sorted 16 B: fk:u64, strides:u32, n_out:u32
seqsigwit.loc / seqsigwit.off / seqsigwit.loc.ovf   # u16 strides; cold with seqsigwit.body
```

`n_out` is the true output count, always ≥ 1. Spent length is `8 × n_out`.
Loc byte **0** = overflow (`n_out ≥ 256` or txout aligned length ≥ 2048).
`create.loc.ovf` holds the true u32 strides and `n_out` (a ~1 MiB OP_RETURN is
~125k strides; min-size outputs in a 1 MB stripped tx can exceed 65535).
`seqsigwit.loc` **0** = overflow (`strides ≥ 65536`, i.e. ≥ 512 KiB). Missing ovf
when a sentinel is set is `Corrupt("invariant: create.loc overflow missing")`
(or seqsigwit). Checkpoints (~22 MiB) are RAM; do not L2 `create.loc`. Lookup `range_batch`
reads and prefix-sums only through the highest fk in each 1024-create window
(not the unused tail). Those window preads are **one** bulk batch (held
head-resolve session, else `pread_batch`). Every window uses a SIMD prefix
sum (`u8×8` SSE2 on x86_64, NEON on aarch64); overflow slots (u8 `0`) are then
corrected from `create.loc.ovf`.

One `create_loc_range_batch` yields both `(txout, spent)` and `n_out`. Lookup
stamps both ranges; load copies the stamp; write appends loc and keeps RAM
packs until write of the last height whose TipOnly had started at note
(`lookup_started_hi`; just-written abs; fill of that write runs first). Write
does not pread `create.loc`. Occupied 21 Class A
is refused. Occupied 22 rewrites `create.loc.ovf` 12 B → 16 B. Leftover
`{txout,spent,seqsigwit}.idx` and `spent.off` are unlinked on empty 21–24 open.

`spent_abs(off, vout) = off + 8×vout`.

### Input encoding (embedded)

| Field | Encoding |
|-------|----------|
| flags | u8 — `SEQ_FINAL`, `EMPTY_SCRIPT`, `EMPTY_WITNESS`, `NULL_PREV`; bits 4–7 reserved (Corrupt) |
| prev | coinbase (`NULL_PREV`): no payload; else **`create_fk:u64` LE** + CompactSize vout |
| sequence | omitted if `SEQ_FINAL`; else u32 LE |
| script_sig | omitted if empty; else CompactSize len + bytes |
| witness | omitted if empty; else CompactSize n + (len + bytes)×n |

Legacy `LOCAL_PREV` is **rejected** on decode.

**Soft `prev_txid`:** RAM-only for wire rebuild; filled from **`txid.body`**
(or the create’s known identity) when needed. Not stored in the input stream.

**Decision:** stamp `create_fk` at archive (batch map → sticky → `tx.head`) so confirm/cache can skip head probes on already-resolved edges.

### Output encoding (`txout.body`)

```text
flags:u8 (bits 0–3 SCRIPT_KIND, bits 4–7 amount exp 0–9; 10–15 Corrupt)
uleb128 mantissa
  sats = mantissa × 10^e
  canonical compact: largest e ≤ 9; e < 9 and mantissa divisible by 10 (except 0) is Corrupt
  zero amount is e=0, mantissa 0 (messy amounts stay e=0: no trailing factor of 10)
kind payload:
  0 RAW            CompactSize + bytes
  1 EMPTY          none
  2 OP_TRUE        none
  3–5 P2PKH/P2SH/P2WPKH   20 B hash
  6–7 P2WSH/P2TR          32 B
  8 OP_RETURN_PUSH CompactSize + data (canonical single push)
  9 P2A            none (`51 02 4e 73`)
  10–15            reserved — decode **Corrupt** (no implicit width)
```

**Amount nibble vs reserved flag bits.** `e` lives in flags so the first
amount byte *is* the ULEB. That keeps canonical mantissa `16..=127` at one
byte — 25 BTC, 12.5 BTC, 330 sat P2TR dust (`33×10`), 25-series fees/change.
Those are the live UTXO set, not 2010 coinbases (the whole 50/25/12.5
subsidy series is ~MB vs raw ULEB, ~420 KB vs a 1-flag prefix encoding).
Spare **bits** do not skip a later occupied-Class-A wipe; unused nibble
**values** `10–15` are the soft-extend hook (same pattern as kind `10–15`:
old writers never emit them; this binary Corrupt; a later version may bind
one code to “extension follows” and still read `e=0..=9` records).

| Rejected | Why not |
|---------|---------|
| Core `CompressAmount` packed into one integer | Can *grow* the following ULEB vs raw sats |
| 3-bit `e` (`0..=7`) + reserved bit 7 | 25/50 BTC become 2-byte mantissas; one boolean is already an unused nibble value |
| Cap `e` at 8, leave `9..=15` unused | Extra headroom we do not need; `e=9` is cheap (50 BTC is already `50×10^8`) and matches kind’s `0..=9` live |
| Use `e=0..=15` | 100 BTC is already `(9,10)` = 1 ULEB byte. A byte comes back only for round ≥10000 BTC (`(9,1000)` is 2 bytes). Occupying `10–15` spends the amount-nibble soft-extend hook for that |
| 1 flag bit `multi` + first amount byte `exp:4\|mant:4` + ULEB rest | Buys 3 flag bits. Pays +1 byte whenever leftover `m` is `16..=127` (see above). Continuation on the amount byte instead steals an `e` or `m` bit and cannot keep 4+4 |

Decode expands templates to wire scripts (P2TR is `5120||32`). XOR at rest
covers hash/data only. Spender flags live only on `spent`. A new consensus
script type does **not** wipe the Class A shape settled at 17: encode it as
kind 0 **RAW**, or introduce an implicit-width nibble as a
`SCHEMA_VERSION` bump (the new binary reads these files; this binary refuses
the new `meta` or an unknown kind). See [Schema 17 freeze](#schema-17-freeze).

### Sole-spender slot (`spent.body`)

8 B per vout at `Ss + 8×vout` (512 slots / 4 KiB page):

| Offset | Field |
|--------|-------|
| 0 | flags (`MULTI_SPENDER` bit 2; other bits reserved, Corrupt) |
| 1–7 | u56 LE = `(vin as u64) << 40 | (fk.0 & (2^40-1))`. `fk ≥ 2^40` or `vin ≥ 2^16` is Corrupt (no wrap). |

| `MULTI_SPENDER` | packed field |
|-----------------|--------------|
| 0 | 0 = unspent (`fk=0`, `vin=0`); else sole **spending_tx_fk** + spending **vin** |
| 1 | head fk into `spent.ovf` (`vin` in the sole slot is 0; vins live on ovf nodes) |

Best-chain spentness also requires `is_confirmed_strong(spender)` (annotations may outlive reorgs).

### Multi-spender overflow (`spent.ovf`)

Fixed 16 B records, append-only: packed `(fk:u40, vin:u16)` | `next:u64`.
Promote sole→multi copies the old `(fk,vin)` onto the first node.  
Only when an outpoint has **≥2** annotated spenders.

**Decision:** sole spends stay on the create output (no giant spend multimap head).

### Header ↔ tx range

- `header_txs_first[header_fk − 1]` = first_tx_fk (0 = no body)
- `header_txs_count[header_fk − 1]` = n  
Contiguous assignment required: block membership is an arithmetic range.

### Optional BIP-352 thin tweaks (`sp_tweaks.*`)

Schema **17** side product. Soft-open: missing dirs are empty (not `Corrupt`,
not a head recreate). Created when `--sp-tweaks` is on.

**Tip / strong height only** — no `header_fk` in the idx. A reorg truncates
above the new tip and those heights are written again. `put` requires
`confirmed[h]` to be the header being indexed.

```text
sp_tweaks.idx/meta       origin:u32 ‖ fmt:u32=3
sp_tweaks.idx/NNNNNN     slot[i] = off:u32     // start in that body file
sp_tweaks.body/NNNNNN    u8 len ‖ [u8; len]    // 0 = none; 33 + A_tweak
```

Body encoding is the original variable-width `0` / `33`. Each body file’s
published start offs stay in `u32`. When the next record’s **start** would
exceed `u32::MAX`, open a new `NNNNNN` pair (lookup is still this slot + next
slot in that file, or that file’s HWM). `n_tx` comes from
`header_txs_count[confirmed[h]]`.

Leftover **files** `store/sp_tweaks.idx` and `store/sp_tweaks.body` (schema 14
single-file, `header_fk` + absolute off) are unlinked on store open.
`--sp-tweaks` backfill regenerates. Not a Class A wipe.

Reorg: truncate slots above the new tip (same era as SH HWM).

Durability: each put writes and syncs the body, then writes and syncs the
idx, so an idx slot on disk never points at body bytes a power cut can lose.
Open (and first enable) repairs a crash tail: slots above the tip (a
disconnect whose truncate never ran) are dropped, then the last record is fit
to its `n_tx` — body bytes past it are cut, and a short record drops its slot.

---

## Tx address head (segmented `tx.head/`)

Keyless open-address tables: **txid → dense create_fk**, one **fixed-bits** head
per segment. There is **no** monolithic growing single `tx.head` file and **no**
bits-widen / shadow-resize path. Module map: [`docs/heads.md`](./docs/heads.md).

| Property | Current |
|----------|---------|
| Files | `tx.head/meta` (**v2**: per-segment `sealed` and `tagged` flags) + open `tx.head/NNNNNN`; sealed `NNNNNN.mphf` + `.fuse8` |
| Default | **BITS=25**, **4 B** entries → **128 MiB** per segment (`2^25` slots) |
| Bits | Tiny **16**, otherwise **25**. No process env. The entry is always 4 B; a footer that says 8 B **refuses** (`tx.head footer entry width`) |
| Entry | LE u32 word `rel \| fp << bits`. Low `bits`: **relative** create id, **0 = empty**, `fk = first_fk + rel − 1`. Spare high bits: fingerprint of the mixed key, `1..=2^(32−bits)−1`; **0 = untagged**, matches every key. No fingerprint at bits 32 |
| Meta v1 → v2 | A v1 meta **opens** (no refuse). Its unsealed OA slots carry fingerprint 0; open writes each slot's fingerprint from `txid.body` (one 4 B `pwrite` per row), flushes, then persists meta v2 with the segment `tagged`. A v1 binary refuses v2 meta (`tx.head.meta version`) and rebuilds `tx.head` from Class A |
| Capacity | Segment ends at **80% of head slots** (`max_keys`) → open next OA, seal previous on a sidecar. Class A loc/body size does **not** cut `tx.head`. |
| Seal filter | **Binary fuse8** (~9 bits/key, no false negatives, FP ≈ 0.39%) built **once on seal**; open segment has **no** filter |
| Fuse file | `BF8R` + **version** + body. **v2** = in-tree LE layout (current). **v1** = historical xorf+bincode — **refused** (wipe `store/tx.head` and `store/scripthash*`; Class A kept) |
| Probe | Open OA: page-local double-hash (1024 slots/page) through a read-only `MAP_SHARED` view of the slot file (no syscall); a slot whose fingerprint differs is skipped; `txid.body` verifies the rest. Sealed: RAM fuse skip, then unique 4 KiB packed BDZ `g` pages (not loaded into process heap); MPHF output is `rel−1` |
| Insert | First empty in-page (or same relative id idempotent); second same-txid goes **deeper** |
| Lookup | Pin by txid → **hot** (open + ages ≤3) → ID/idx → **cold** (ages ≥4) if needed; fuse-gate sealed; body-verify ([`docs/heads.md`](./docs/heads.md)) |
| Legacy | Monolithic `tx.head` / `tx.head.new` / `tx.head.resize` / `tx.head.overflow` **refused on open** — reindex |

**Publish order on seal:** flush the full OA → open the next head and persist
`tx.head.meta` (two unsealed) → sidecar writes fuse8 + value-assigned MPHF → mark the
previous segment sealed in meta → unlink the OA. Insert does not join the
sidecar. Lookup Open-wave probes every unsealed OA until publish.

**Probe note:** open OA candidates for a key share one page (single IO).
Keyless slots cannot Robin-Hood. Sealed: RAM fuse skip, then unique 4 KiB
BDZ `g` pages (`KIND_MPHF_G`). Kill mid-seal leaves at most
one unsealed non-tail OA; open rebuilds its fuse keys from Class A and
seals it. Two unsealed non-tails is **Corrupt**.

**Capacity @ 0.80 load (25-bit):** ≈ **26.8 M creates/segment**, ~29 MiB fuse8 when sealed (~6.1 B total sealed storage per create including head slots).

**Wipe / empty-head rebuild:** writes MPHF+fuse8 **directly** from `txid.body`
(no historical OA). Ranges seal in parallel: min(CPUs, free RAM / 1 GiB,
range count); `RBITCOIN_TX_HEAD_REBUILD_WORKERS` overrides (`1` = serial).
Default range **2²⁵ keys** (`RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS=25`); **26** is
wider. Remainder is sealed; an empty open tail is created. Live IBD rolls OA
at 80% slots (~26.8 M), so rebuild ranges match live seal size.

---

## Hash heads (`header.head`, generic)

Used where the key is a 32 B hash and the value is a single fk (or multi-list).
Not `tx.head` — see [`docs/heads.md`](./docs/heads.md).

- Slot = **16 B key prefix** + **8 B packed value** (24 B); power-of-two slots; linear probe.
- Packed value: sole fk (high bit clear), or `MULTI_BIT | list_fk` → sibling `.mlt` (`create_fk:u64 | next:u64`, newest first).
- Multi-list: 16 B prefix collisions and BIP30-style multiples.
- Identity: `get_all` candidates + **body verify**.
- Insert past **7/8** is full: `header.head` rolls a sibling generation at the same slot count. Occupied tables are never rewritten while serving. Undersized **single-gen** files are rewritten at the create target **on open** (`header.head.grow` then rename). Target-sized empty gen0 with a non-empty body/`.mlt` is Layout refuse. Leftover 256-way `header.head/` is **Layout refuse**.

**Not** used for `tx.head` (keyless address) or for scripthash **create lists** (slabs; megakey page chains).

---

## Class B — scripthash (Electrum)

Thin create index: **create_tx_fk only** (no vout in the index). Creates only
(outputs); spends join via Class A + spend annotations.

### Sorted create_fk invariant

For each key, durable create_tx_fks are **strictly increasing** by `create_tx_fk.0`
(within a slab, within each megakey page, and across pages).

**Insert / batch model (tip + warm residual):**

1. Read **max existing** FK (slab decode or **last page only** when paged; inline from head).
2. From the batch (sort+dedup by fk), **skip every `fk ≤ max`** (re-queue / HWM
   replay is safe — not a hard error).
3. Append remaining higher FKs: grow the slab class if needed, or fill last
   megakey page + new pages. **No full chain walk** on insert.

**Caller contract:** apply SH create batches for a key in **non-decreasing
block/batch time order**. Skipping lower fks assumes an earlier batch already
wrote them; inserting a later block before an earlier one can leave permanent holes.

Cold bulk: pick the **exact** geometric class from the run-group length (or emit
pages if `n ≥ 257`). One write per key. No half-empty 4 KiB.

### Head (schema 20)

- Key = first **16 B** of `SHA256(scriptPubKey)` (Electrum hash; wire APIs still use 32 B).
- **Main (sealed):** `scripthash.head/NN.mphf` (`BDZ3` 32 B header, packed 2-bit
  `g[m]`, occupancy bitvector `[m]`, then `n` mix64(key16) tags) + `NN.val`
  (`n × 8` pack8). Packed `g` is FdOnly 4 KiB pages; occupancy is a
  read-only map of the header+`g`+occ prefix (not tags; `HEADER+g` is not
  8-aligned, so rank popcounts bytes). MPHF maps into `[0, n)`; a miss fails the
  tag check (no main `.fuse8`). Record count is immutable after seal. Existing
  keys pwrite pack8 at `i×8`. New keys are **not** punched into main.
- pack8 (LE u64): bits 63–62 mode; `00` = 1-fk `create_fk`; `01` = slab
  `off:u40 \| used:u16 \| class:u6`; `10` = paged `last_page_off` (schema 18;
  first page lives in the LAST page header); `11` = **extent** `last_page_off`
  (schema 19). `SH_INLINE_CAP = 1`.
- Ingest OA, L0 `SHSR`, L1 ovf MPHF, and main MPHF all store **pack8**.
- Sharded **64-way** on mainnet (prefix of `scripthash[0]`). Cold load writes
  packed locators (no OA image). No `scripthash.head.oa_stub`.
- **Overflow:** one **global** ingest OA (`scripthash.ovf/ingest`, 256 slots tiny /
  **2²⁵ slots mainnet = 768 MiB** at 24 B). Load ≥ ~0.80 **seals** to L0
  `SHSR`+fuse (`scripthash.ovf/NNNNNN`, FORMAT_VER=2, rec = key16‖pack8).
  ≥8 L0 files **compact once** to L1 MPHF+val+fuse8. L1 is **never rewritten**.
  A later L0 stack of 8 **warns** (`wipe store/scripthash*` + rematerialize).
  Body offs are not copied. Do not fold ovf locators into `scripthash.body/NN`
  except via rematerialize.
- Lookup: **ingest OA → L0 SHSR newest→oldest (fuse) → L1 MPHF (fuse) →
  main MPHF+val (tags)**. A leftover live OA or schema-17 `SHSR` at
  `scripthash.head` (or non-`SHSR` six-digit `ovf/NNNNNN`) is **refused**.
  A key has **exactly one** home.

At ~2.5×10⁵ new unique scripts/day, first L1 is ~2.3 years after rematerialize
and the frozen-L1 warning is ~4.7 years. That is not a calendar guarantee.

| Mode | When | pack8 |
|------|------|-------|
| Empty | no creates | `0` |
| Inline | 1 create_tx_fk | mode `00`, fk |
| **Slab** | 2–256 fks | mode `01`, off/used/class |
| **Paged** | schema-18 megakey leftover | mode `10` — **refused** on open |
| **Extent** | ≥257 fks (new megakeys) | mode `11`, last page off |

Schema-13 slab packing (`w0` flagged, `w1` clear) still decodes as paged;
store open refuses a durable pre-15 SH index (no dual-read of 4 KiB pages as slabs).

### Body (schema 15 layout; 17 orientation)

Schema 17 had two **body orientations**. A **20** binary writes and opens only
the directory variant. A leftover file `scripthash.body` **refuses**.

| On disk | Meaning |
|---------|---------|
| file `scripthash.body` | **Shared (legacy):** **refused** — wipe `store/scripthash*` |
| dir `scripthash.body/NN` + file `scripthash.ovf/body` | **Sharded:** one TableFile per main shard + one ovf body |
| file **and** dir, or dir without `ovf/body` | **Refuse** `Layout` — wipe `store/scripthash*` and rematerialize |

New `Store::create` writes the dir variant. ColdProgress `SHCOLDP1`:
`next_shard` is the **lowest unsealed** main shard (holes after it
stay). The per-shard pack commit is `scripthash.head/NN.packed` next to
`.mphf`+`.val`. Pass-1 BDZ writes the MPHF and is not that mark. A complete
head with no extract in progress and no marks is soft-migrated on open
(marks written; missing `include_hwm` set from the create count). Overflow
compact still merges **heads only** — all ovf keys share
`scripthash.ovf/body`.

- Combined prefix: RBT1 at 0–15, SHAL v3 fields at 16–4095, **payload at 4096**.
  Small slabs pack from bump with **no** 4 KiB align. Megakey pages 4 KiB-align
  that alloc only.
- Geometric slabs class 0–7 (`16 B`–`2 KiB`; `slab_bytes(c) = 16 << c`). Payload:
  `used:u16` + ULEB128 `fk0` + ULEB128 deltas.
- Megakey **pages** (4 KiB): `ver=1` header is 8 B `ver:u8 | n_fks:u16 | LAST|page_index u40`
  then ULEB128 `fk0` + ULEB128 gaps. LAST=1 → index is **first** page; LAST=0 →
  **next**. `ver=2` last-in-extent / chain-last adds 16 B: `extent_base:u64` +
  `extent_n:u32` + reserved (stream starts at 24, max 4072 B). Last-page chunks
  use that cap; `ver=1` intermediates still fill 4088 B. Mode 11 pack8 stores **last**
  page off; that page holds `(extent_base, extent_n)`. Query span-reads `extent_n`
  pages then linked-walks a 4 KiB tail. Span pread is capped at 64 MiB; a larger
  or past-EOF `extent_n` falls back to the linked walk so disconnect/unlink can
  still rewrite the chain. Mode 10 pack8 is **refused** on open.
  `ver=0` with `n_fks>0` is a leftover raw-u64 page — rematerialize. Last-page
  append only. Megakeys never relocate.
- SH shard bodies and `scripthash.ovf/body` grow in **64 KiB** steps (`GrowPolicy::Align64k`).
  Class A stems keep 64–256 MiB slabs.
- Size-class freelist on SHAL. Grow relocates O(log n) times; megakeys never relocate.

### Query join

Heights, value, spentness, vouts: expand from Class A outputs (match full scripthash) + spend annotations + Class C.  
IBD may stage creates in **two Class A `txout` scans** under `scripthash.unsorted/`:
workers write `SHKSP01` spill files under `keys/NN/`
(n_multi key16s already `0`, then first-fk-sorted uleb(delta)‖key16 singles),
then one map-fold walk per shard into pack8 `scripthash.head/NN` and
`multi/NN.fuse8` (`DONE.keys` = `SHKEYS02` last_fk marker). A previous
`DONE` / 24 B `NN` layout with no valid `DONE.keys` is deleted and pass 1
restarts. A spill whose magic is not `SHKSP01` is Corrupt — wipe
`scripthash.unsorted` and rematerialize. Fuse-hit `SHPST01` post spills
under `post/NN/` (`DONE.post` = `SHPOST02` last_fk). A `post/NN` file, or a
spill whose magic is not `SHPST01`, is Corrupt. Pack folds those spills, then
rewrites 2+ into body and skips 1-fk fuse FPs. Leftover schema-16 `key_len=32`
catalogs are refused.

**Decision:** inline for 1-use scripts (`SH_INLINE_CAP = 1`, ~95 % of keys); geometric slabs for
typical multi-use; page chains only for megakeys. Query expand is waved
`idx_body_pipeline` (`txout` outs) + `txid.body` page-grouped identity +
`spent.body` 8 B batch peeks on the process `RBITCOIN_IO` session (not one
serial pread per create). Megakey **extent** (`pack8` mode 11): span-read
`extent_n` pages from `extent_base` on the last page (capped at 64 MiB; larger
falls back to linked walk), then linked-walk any 4 KiB tail. Mode 10 leftovers
are a linked walk (no `last = first + (n−1)×4096` guess). Cost for busy wallets
is still dominated by
Class A + spend joins, not SH pointer chasing.

---

## Class C — chain tip

### `confirmed.body`

Dense u64 array: index = height → header_fk. Length = tip_height + 1 when non-empty.

### `strong_tx.body`

Bitset: bit `(tx_fk − 1)` set ⇒ tx is strong on the best chain.

Always **L2** (full `Vec` in process), even when `confirmed` / `header_txs_*`
fall back to fd past 256 MiB. One bit per create; confirm/reorg/Electrum
must not pread the bitset.

### Create height (schema 16: RAM fence, no `tx_height.body`)

`tx_height.body` (4 B/tx) is **gone**. Create height is O(blocks): a resident
fence of `confirmed[h]` → `header_txs` `(first_fk, count)`. Point query is a
binary search over confirmed runs. Reorg holes (orphaned Class A fks between
two confirmed runs) return unconnected (`None`), not the neighbor height.

Schema 15 leftover `tx_height.body` is unlinked on open (logged).

### Commit order (confirm)

1. `strong_tx` (may lead tip after kill, before the barrier)
2. Height-fence extend (RAM), then **`confirmed[]` tip advance** ← **commit**
3. `flush_class_c_tip` (headers, then `strong_tx`, `header_txs`, `confirmed[]` last)
4. Scripthash write-behind enqueue (after tip). Direct IBD defers SH until tip entry

`is_confirmed_strong(tx)` ⇔ strong ∧ fence contains the fk (implies height ≤ tip
and membership in `confirmed[h]` header_txs).  
On open: after tip-window revalidate, one `repair_class_c_above_tip` unstrongs bits not on the fence (complement of fence runs — not a full-bit walk).

---

## Mainnet census (this tree’s reference datadir, 2026-08-13)

Tip **962,298**, **1,416,970,187** creates, mean packed **502.2 B/tx**,
~2.46 in / **2.70 out**. Exact HWM; outs ±2%; witness/in_base split ±10%.

| File | Packed 13/14 | Schema 15 |
|------|--------------|-----------|
| `tx.body` / `txout.body` | **662.73 GiB** | **~129 GiB** (schema 15; 17 thin meta + templates cut ~18–26 GiB) |
| `seqsigwit.body` | — | **~486 GiB** (ins + witness; cold) |
| `spent.body` | (9 B inside packed outs, ~32 GiB) | **~32 GiB** schema 15; **~21 GiB** after 8 B slots |
| `{stem}.idx` / loc | 5.28 GiB (`tx.idx`) | 5.28 GiB × **3** idx (schema 15–21); schema 22 is `create.loc` + `seqsigwit.loc` |
| `txid.body` / `tx.head` | 42.23 / 8.23 GiB | unchanged |

Hot pin+annotate working set: **txout + spent + create.loc + txid + tx.head**
(~129+21+3+42+8 ≈ **203 GiB**) vs packed **tx.body + idx + txid + head**
(~663+5+42+8 ≈ **718 GiB**). Reconstruct / `getrawtransaction` also needs
`seqsigwit` (~486 GiB), which pin/SH/tweaks do **not** open.

---

## Query-layer notes

- `spenders(outpoint)`: confirmed-strong only; `spenders_raw` for full annotation multimap.
- Electrum history / balance / listunspent: join thin SH rows → Class A → spends → Class C.
- Optional manual `backfill_tx_index` rebuilds segmented `tx.head` from Class A (direct MPHF; not part of tip entry). Empty occupancy uses the same path.

---

## Related docs

| Doc | Topic |
|-----|--------|
| [`docs/README.md`](docs/README.md) | Documentation map |
| [`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md) | Prior schema versions |
| [`docs/concurrency.md`](./docs/concurrency.md) | Writer ownership, IBD vs tip |
| [`docs/invariants.md`](docs/invariants.md) | Confirm stage IO / leftover union |
| [`docs/crash-recovery.md`](./docs/crash-recovery.md) | Kill safety, reorg, segmented head seal |
| [`OPERATOR.md`](./OPERATOR.md) | Datadir ops, env knobs |
