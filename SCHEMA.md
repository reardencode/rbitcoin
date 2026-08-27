# On-disk schema (current)

**Version:** `SCHEMA_VERSION = 20` (`rbitcoin_primitives`).  
**Status:** 20 replaces sealed `tx.head` MPHF+`.rel` with a value-assigned
packed BDZ (`BDZ2`; `index(key) = rel−1`) and sealed SH MPHF with compact
`BDZ3` (2-bit `g` + occupancy rank; mix64 tags + pack8 `.val` unchanged).
Fuse8 on `tx.head` stays 8-bit RAM. Occupied schema 18/19 `tx.head` or
`scripthash*` is **refused** (wipe those index dirs, keep Class A). Empty
18/19 indexes rewrite `meta` to 20; `tx.head` rebuilds from Class A; SH
rematerializes with `--shindex`. An 19 binary refuses 20 `meta`. A 17
datadir with populated `tx.head` or `scripthash*` is **refused**. Empty 17
indexes rewrite `meta` to 20.

Operator copy-paste (which dirs to wipe; kill-9 is not a migrate):
[`OPERATOR.md`](./OPERATOR.md#schema-upgrade).

**13/14→17 open:** Empty Class A (no creates) + empty/missing SH may silently
rewrite `meta` to 17. A packed `tx.body` **with creates**, or a durable page-era
(or schema-13 slab) SH index, is refused (wipe + IBD). Schema 15 Class A is
`txout` + `inwit` + `spent` (not a single packed `tx.body`).  
**15→17 open:** leftover `tx_height.body` is unlinked (RAM fence). Class A
with creates in the 16-byte-meta / 9-byte-spent layout is **refused**
(wipe datadir and redo IBD). Empty Class A may rewrite `meta`.  
**16→17 open:** Soft migrate when `scripthash.runs` is missing/empty or every
run has `key_len=40`. Leftover schema-16 catalogs (`key_len=32`) and leftover
raw-u64 megakey pages are **refused** (wipe `store/scripthash.runs` and
rematerialize). Sealed SH head/body kept only if pages are already delta
(`ver=1`). Class A with 16-layout creates is refused the same as 15→17.
Leftover single-file `sp_tweaks.idx` / `sp_tweaks.body` are unlinked
(schema 17 uses directories; `--sptweaks` backfill regenerates).  
**17→18/19 open:** If `tx.head` occupancy or any `scripthash*` data exists:
`schema 18 refuses schema-17 tx.head/scripthash; wipe store/tx.head and store/scripthash* then restart (Class A kept; indexes rebuild)`.
Empty 17 indexes rewrite `meta` to 20 **before** `TxTable::open` (so a following
head rebuild cannot trip the refuse).  
**18/19→20 open:** If `tx.head` occupancy or any `scripthash*` data exists:
`schema 20 refuses schema-18/19 tx.head/scripthash; wipe store/tx.head and store/scripthash* then restart (Class A kept; tx.head rebuilds, SH rematerializes with --shindex)`.
Empty 18/19 indexes rewrite `meta` to 20 **before** `ScriptHashTable::open` /
`TxTable::open`. `meta=20` is BDZ3 SH (no schema-20 SH was written as BDZ1).  
**18→19 open (19 binary):** Rewrite `meta` to 19 even with populated `tx.head` / `scripthash*`.
Mode 10 paged heads stay readable; new megakeys write mode 11.  
**Endianness:** little-endian for all multi-byte integers.

Older versions and migration notes live in [`SCHEMA_HISTORY.md`](./SCHEMA_HISTORY.md).

---

## Schema 17 freeze

### What 17 locks (on-disk)

| Object | Frozen choice |
|--------|----------------|
| Class A | Split `txout` / `inwit` / `spent`; thin LAYOUT17 meta; kinds **0–9**; 8 B spent slots; `spent.ovf` |
| Identity | Dense `txid.body` (32 B/fk); segmented `tx.head` (25-bit + fuse8 v2) |
| Idx | Per-stem `*.idx/` directories; **u32 stride-8**; hard span `2^32 × 8` ≈ 32 GiB; soft roll default 16 GiB |
| Class B | SH runs `key_len=40` unique `(sh, create_fk)`; megakey pages ULEB deltas (`ver=1`); body **file** or **dir** orientation (not a version bump). Slab **class** is the byte allocation (32…2048); `used` is the fk count and may exceed the old geometric `slab_cap(class)` when the ULEB stream fits. Decode `used` fks from the payload. |
| Class C | `confirmed[]` + `header_txs_*`; no `tx_height.body`; `strong_tx` bitset |
| Tweaks | Segmented `sp_tweaks.idx/` + `sp_tweaks.body/` (`off:u32`, body `0`/`33`) |
| Secret | `store.secret` XOR of scripts/witness; `mix_txid` for **open** `tx.head` page-local probes (not shard-by-txid). Sealed MPHF/fuse use the same mixed u64. |

Empty / leftover prior files may be unlinked or `meta` rewritten on open as
already listed above. A packed `tx.body` with creates, leftover schema-16 SH
catalogs, or 16-layout Class A with creates is **refused**.

### Writer / RAM policy (same schema — not a bump)

| Policy | Choice |
|--------|--------|
| Idx rolls | Each Class A stem rolls independently at **that** stem’s soft span. `inwit` is the fat stem and must not force `txout` / `spent` splits. |
| `strong_tx` | Always L2. `RBITCOIN_CLASS_C_INRAM_MAX_MB` (default 256) still caps **`confirmed`** and **`header_txs_*`** only. |
| `RWF_DONTCACHE` | **Not used.** Annotate pwrites hit `spent.body` only; evicting those pages does not protect `txout`, and the next block wants the same spent pages. |

### New script kinds without a wipe

Kind nibble **10–15** is **Corrupt** on this binary (no implicit width). A new
consensus script type does **not** force a 17 datadir wipe:

| Path | On-disk | Old 17 binary | New binary |
|------|---------|---------------|------------|
| **RAW** | kind 0 + CompactSize + bytes | already decodes | same |
| **Soft-18** | new kind nibble + known width; `SCHEMA_VERSION = 18` | **refuses** 18 `meta` (or unknown kind) | reads 17 files; writes 18 |

Use RAW when the type is rare. Use soft-18 when the type is common enough to
pay a width table. Soft-18 is **not** a silent in-place rewrite of 17 files.
Inwit `create_fk` Δfk (parked) is the same class: **18 or an inwit-only
rewrite**, not a silent 17 mutate.

### Field widths (10 years)

Assume ~400k–700k creates/day. Ten years ≈ +1.5e9…2.6e9 creates on top of
~1.4e9.

| Field | Width | Headroom |
|-------|-------|----------|
| `create_fk` / `header_fk` | u64 | 1e18-class; not a 10y issue |
| Spent `spender_field` | u56 | Same; 2^56 creates is not a Bitcoin problem |
| Height / `confirmed[]` index | u32 | ~1e6 heights now; 10y adds ~0.5e6; year 2106 is **timestamp**, not height |
| Idx relative | u32 × stride 8 | 32 GiB **per segment**. Soft 16 GiB rolls first. |
| `tx.head` bits | 25-bit segments | Roll + seal; no mono-file widen |
| SH megakey page | 4 KiB delta stream | Page chain; not a single-integer cap |
| `sp_tweaks` off | u32 per segment | Already segmented |
| Script kind | 4 bits | 0–9 used; 10–15 reserved Corrupt; extension = RAW or soft-18 |

Practical risks are **soft-span misuse** (one idx segment past 32 GiB) and
**Bitcoin timestamp 2106** (consensus, every node).

### What would force schema 18

A **byte-incompatible** change to Class A / OA / body / idx / SH catalog
layout, or anything that cannot soft-open 17 files.

| Change | 18? | Notes |
|--------|-----|-------|
| New implicit-width script kind | Optional | RAW = no bump; nibble = soft-18 (17 refuses 18) |
| Inwit Δfk | Yes or inwit-only rewrite | Parked; cold stem |
| Idx not stride-8 / not u32 | Yes | Would retire the 8-align pad |
| Packed Class A again / merge stems | Yes | Wipe |
| SH `key_len` ≠ 40 or raw-u64 pages | Yes | 17 already refuses leftovers |
| `txid.body` not dense 32 B/fk | Yes | Soft-open only if dual-read is explicit |
| Fuse8 envelope v3 | No | Soft-migrate like v1→v2 (log + rewrite; no wipe) |
| Independent rolls / L2 strong / no DONTCACHE | No | Writer/RAM only |

Parked size work that is **not** 17: inwit Δfk; drop 8-align pad on empty
inwit / zero-out spent (needs a different idx encoding); `txid.body`
compression. Do not chase `inwit` size as an IBD **hot-set** win — put it
on a cold volume (`--datadir-cold`). Census: [Mainnet census](#mainnet-census-this-trees-reference-datadir-2026-08-13).

Process: bump `SCHEMA_VERSION`, document this file + `SCHEMA_HISTORY.md` in
the same commit, refuse or soft-open with a one-line operator message. Do
not treat decode failure as “recreate the whole table” unless the OA layout
itself changed.

---

## Design at a glance

| Concern | Choice | Why |
|---------|--------|-----|
| Class A body | **Split** `txout` (thin meta + template outs) + `inwit` + `spent` (8 B×n_out) | Pin/SH read outs only; annotate isolates scripts |
| Class A identity | Dense **`txid.body`** sidefile (32 B header + 32 B/txid by create_fk) | Fixed `fk → offset`; head-resolve multi-cand without Prefix33 body peeks |
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
    txout.body / txout.idx/                         # Class A outs (hot)
    inwit.body / inwit.idx/                         # Class A inputs+witness (cold)
    inwit.reloc                  # optional: inwit lives under --datadir-cold/store
    spent.body / spent.idx/                         # sole-spender 8 B × n_out
    tx.body / tx.idx.*                              # schema ≤14 packed (refused if non-empty)
    txid.body                                       # dense create_fk-ordered txids (schema 13+)
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
    scripthash.head/NN.mphf + NN.val # Class B sealed MPHF main (8 B pack8; no fuse)
    scripthash.ovf/ingest                                # global OA ingest (key16+pack8, 2^25)
    scripthash.ovf/NNNNNN[.fuse8][.idx]                  # L0 SHSR pack8
    scripthash.ovf/NNNNNN.mphf|.val|.fuse8               # L1 promoted ovf (at most one)
    scripthash.runs              # leftover catalog (key_len=40); discarded at tip
    scripthash.unsorted/NN       # tip collect: raw 40 B recs, unsorted; DONE; unlinked after seal
    sp_tweaks.idx/  sp_tweaks.body/   # optional BIP-352 (schema 17 dirs; leftover files unlinked)

<datadir-cold>/                  # only when --datadir-cold is set
  store/
    inwit.body / inwit.idx/      # same files; not duplicated under <datadir>/store
```

`--datadir` holds both stems by default. `--datadir-cold PATH` places only
`inwit.body` + `inwit.idx/` under `PATH/store/` (and writes `inwit.reloc` in
the hot store). Pin / SH / spend-annotate stay on the hot volume.

**Height → txs:** `confirmed[h]` → `header_fk` → contiguous Class A range  
`[header_txs_first[h−1], header_txs_first[h−1] + header_txs_count[h−1])`.

**Who writes what:** see [`docs/concurrency.md`](./docs/concurrency.md). IBD unified pipeline: confirm **commit** stage is the sole Class A appender (+ Class C / spends / tip); prep only plans Class A; peer IO does not write the store.

---

## Common file header (16 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | Magic `RBT1` |
| 4 | 2 | Schema version (u16) — **17** |
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
| 16 | inwit (`inwit.body`) |
| 17 | spent (`spent.body`) |

---

## Identity

- **FK 0** = null / absent; otherwise **1-based** dense id into the table’s idx or bit/slot space.
- Lookups that use a **16 B key prefix** must **verify** full identity against Class A body when required.

---

## Growable var records (`*.body` + `*.idx`)

Used for Class A `txout` / `inwit` / `spent` (and historically packed `tx.body`).

- **body:** append-oriented **unframed** payloads (no per-record length prefix).
- **idx:** segmented **u32 stride-8** relatives (`{stem}.idx/`); see Class A index below.
  Header hash lookup is a separate `HashHead`, not this idx.
- Record length = `start(fk+1) − start(fk)` (last: published body end − start).
- FK = 1-based index into idx.

---

## Class A — headers

### `header.body` record (fixed 88 bytes)

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

---

## Class A — transactions

### Dense identity sidefile (`txid.body`, schema 13+)

```text
offset 0..32    — 32-byte file header (standard 16-byte TableFile header + 16 pad)
offset 32+(fk-1)*32 — txid for create_fk = fk (1-based)
```

Append-published with Class A body/idx on the sole Class A write path. Count must match `txout` / `inwit` / `spent` / `txid.body`. Head-resolve multi-cand identity peeks this file (fixed offset), **not** a body prefix.

### Split bodies (schema 15)

Each create_fk has three 8-aligned var records (per-stem idx maps; rolls
are independent when that stem’s next start would exceed the soft span):

```text
txout.body  S:  thin LAYOUT17 meta | outputs (kind nibble + template payload)
inwit.body Sw:  per-input flags|create_fk+vout|seq?|script_sig?|witness?
spent.body Ss:  8 B × out_count  (flags + u56 field). Multi overflow → spent.ovf
```

Empty inwit / zero-out spent: **8-byte zero pad** so idx starts stay strictly monotone.
Pin / SH / Electrum tweaks read **`txout` only**. Annotate RMW is on **`spent`** (`abs = Ss + 8×vout`).
Reconstruct zips `txout` + `inwit`. First-page Outs reads are 4 KiB; truncated outs extend
to the full idx span.

Packed `tx.body` (schema 13–14: 32 B meta | inputs+witness | outputs) is **refused** if it contains creates.

### Packed body (schema 13–14, historic)

There is **no** leading magic byte and **no** leading txid (schema 11–12 stored txid at `[S, S+32)`). There are **no** standalone `input.body` / `output.body` tables.

**Alignment** (schema 13+): `S % 8 == 0` only. The pad exists so record starts match **`tx.idx` u32 stride-8** (`IDX_STRIDE = 8`): idx stores body offsets as stride units from `body_base`. The schema-11/12 page non-straddle rule for a leading 32-byte txid is **retired** — identity is **`txid.body`**, not body bytes.

Decode walks meta + runs to a logical end; any remaining bytes in the idx span must be **all zeros**. Non-zero trailing garbage is corrupt.

**Body meta (schema 17, variable):** first byte bit 7 = `LAYOUT17` (required).
Bits 0–2 encode version 1/2/3 (else explicit i32 LE); bit 3 = locktime 0
(else uleb locktime); then uleb `input_count` and `output_count`. Typical
v2+locktime 0 is **3 B**. Schema-15 16-byte prefixes (v1 starts `01 00 00 00`)
are not accepted. `input_start_fk` / `output_start_fk` stay null in RAM.
Soft `TxRecord.txid` is filled from the sidefile on get paths.

### Segmented body index (`txout.idx.*` / `inwit.idx.*` / `spent.idx.*`)

```text
{txout,inwit,spent}.idx/meta     # per-stem segment map (first_fk / file_id)
{txout,inwit,spent}.idx/000000   # dense u32 LE stride units
…
```

Each segment covers a contiguous create_fk range with a fixed **8-aligned** `body_base`:

```text
abs_start = body_base + (u32_le[i] as u64) * 8
i = fk - first_fk
```

| Segment field | Meaning |
|---------------|---------|
| `first_fk` | 1-based inclusive start of the range |
| `count` | number of u32 slots in the segment file |
| `body_base` | absolute body base (8-aligned) for relatives |
| `file_id` | maps to `{stem}.idx/{file_id:06}` |

Hard span per segment: `2^32 × 8` ≈ 32 GiB. Soft rollover earlier (default 16 GiB; `RBITCOIN_TX_IDX_SOFT_SPAN`). **Each stem rolls independently** when that stem’s next start would exceed the soft span (`inwit` no longer forces `txout`/`spent` idx splits). Length: `start(fk+1) − start(fk)` (may cross segments); last record uses published body end. ~**4 B/tx** vs prior 8 B absolute u64 index (~50% smaller).

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
flags:u8 (bits 0–3 SCRIPT_KIND, bits 4–7 reserved 0)
uleb128 value
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

Decode expands templates to wire scripts (P2TR is `5120||32`). XOR at rest
covers hash/data only. Spender flags live only on `spent`. A new consensus
script type does **not** wipe a 17 datadir: encode it as kind 0 **RAW**, or
introduce an implicit-width nibble as **soft-18** (18 reads 17; this 17
binary refuses 18 / unknown kind). See [Schema 17 freeze](#schema-17-freeze).

### Sole-spender slot (`spent.body`)

8 B per vout at `Ss + 8×vout` (512 slots / 4 KiB page):

| Offset | Field |
|--------|-------|
| 0 | flags (`MULTI_SPENDER` bit 2; other bits reserved, Corrupt) |
| 1–7 | `spender_field` u56 LE (0 = unspent; else sole `spending_tx_fk` or multi-list head) |

| `MULTI_SPENDER` | `spender_field` |
|-----------------|-----------------|
| 0 | 0 = unspent; else sole **spending_tx_fk** |
| 1 | head fk into `spent.ovf` |

Best-chain spentness also requires `is_confirmed_strong(spender)` (annotations may outlive reorgs).

### Multi-spender overflow (`spent.ovf`)

Fixed 16 B records, append-only: `spending_tx_fk:u64 | next:u64`.  
Only when an outpoint has **≥2** annotated spenders.

**Decision:** sole spends stay on the create output (no giant spend multimap head).

### Header ↔ tx range

- `header_txs_first[header_fk − 1]` = first_tx_fk (0 = no body)
- `header_txs_count[header_fk − 1]` = n  
Contiguous assignment required: block membership is an arithmetic range.

### Optional BIP-352 thin tweaks (`sp_tweaks.*`)

Schema **17** side product. Soft-open: missing dirs are empty (not `Corrupt`,
not a head recreate). Created when `--sptweaks` is on.

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
`--sptweaks` backfill regenerates. Not a Class A wipe.

Reorg: truncate slots above the new tip (same era as SH HWM).

---

## Tx address head (segmented `tx.head/`)

Keyless open-address tables: **txid → dense create_fk**, one **fixed-bits** head
per segment. There is **no** monolithic growing single `tx.head` file and **no**
bits-widen / shadow-resize path. Module map: [`docs/heads.md`](./docs/heads.md).

| Property | Current |
|----------|---------|
| Files | `tx.head/meta` + open `tx.head/NNNNNN`; sealed `NNNNNN.mphf` + `.fuse8` |
| Default | **BITS=25**, **4 B relative** entries → **128 MiB** per segment (`2^25` slots) |
| Env | `RBITCOIN_TX_HEAD_BITS` in **8..=34** (tests/tiny only); product default **25** |
| Entry | LE **relative** create id; **0 = empty**; `fk = first_fk + rel − 1` |
| Capacity | Segment ends at **80% of head slots** (`max_keys`) → open next OA, seal previous on a sidecar. Idx 16 GiB soft-span does **not** cut `tx.head`. |
| Seal filter | **Binary fuse8** (~9 bits/key, no false negatives, FP ≈ 0.39%) built **once on seal**; open segment has **no** filter |
| Fuse file | `BF8R` + **version** + body. **v2** = in-tree LE layout (current). **v1** = historical xorf+bincode (open migrates to v2 from Class A; does **not** wipe head) |
| Probe | Open OA: page-local double-hash (1024 slots/page); one 4 KiB load. Sealed: RAM fuse skip, then unique 4 KiB packed BDZ `g` pages (not loaded into process heap); MPHF output is `rel−1` |
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
(no historical OA). Ranges seal in parallel: min(CPUs, free RAM / 750 MiB,
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
  (`n × 8` pack8). Packed `g` is FdOnly 4 KiB pages; occupancy is
  sequential-read into RAM on open. MPHF maps into `[0, n)`; a miss fails the
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
| **Paged** | schema-18 megakey leftover | mode `10`, last page off |
| **Extent** | ≥257 fks (new megakeys) | mode `11`, last page off |

Schema-13 slab packing (`w0` flagged, `w1` clear) still decodes as paged;
store open refuses a durable pre-15 SH index (no dual-read of 4 KiB pages as slabs).

### Body (schema 15 layout; 17 orientation)

Schema 17 has two **body orientations**. `SCHEMA_VERSION` stays 17. Open
detects files; it does **not** rewrite a file body into a directory.

| On disk | Meaning |
|---------|---------|
| file `scripthash.body` | **Shared:** one TableFile, one writer (legacy 17) |
| dir `scripthash.body/NN` + file `scripthash.ovf/body` | **Sharded:** one TableFile per main shard + one ovf body |
| file **and** dir, or dir without `ovf/body` | **Refuse** `Layout` — wipe `store/scripthash*` and rematerialize |

New `Store::create` writes the dir variant. An old 17 binary that
`TableFile::open("scripthash.body")` on a directory fails that open
(not a silent misread). ColdProgress `SHCOLDP1` bytes are unchanged:
`body_bump` is the shared HWM on the file variant. On the dir variant
`next_shard` is the **lowest unsealed** main shard (holes after it
stay); sealed `scripthash.head/NN.mphf`+`.val` is the per-shard commit. Overflow
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
  pages then linked-walks a 4 KiB tail. Mode 10 / `ver=1` is a linked walk only.
  `ver=0` with `n_fks>0` is a leftover raw-u64 page — rematerialize. Last-page
  append only. Megakeys never relocate.
- SH shard bodies and `scripthash.ovf/body` grow in **64 KiB** steps (`GrowPolicy::Align64k`).
  Class A stems keep 64–256 MiB slabs.
- Size-class freelist on SHAL. Grow relocates O(log n) times; megakeys never relocate.

### Query join

Heights, value, spentness, vouts: expand from Class A outputs (match full scripthash) + spend annotations + Class C.  
IBD may stage creates in **unsorted per-shard files** (40 B `{scripthash\|create_fk}`)
and unique-sort + pack durable SH at tip entry. Leftover schema-16 `key_len=32`
catalogs are refused.

**Decision:** inline for 1-use scripts (`SH_INLINE_CAP = 1`, ~95 % of keys); geometric slabs for
typical multi-use; page chains only for megakeys. Query expand is waved
`idx_body_pipeline` (`txout` outs) + `txid.body` page-grouped identity +
`spent.body` 8 B batch peeks on the process `RBITCOIN_IO` session (not one
serial pread per create). Megakey **extent** (`pack8` mode 11): span-read
`extent_n` pages from `extent_base` on the last page, then linked-walk any
4 KiB tail. Mode 10 leftovers are a linked walk (no `last = first + (n−1)×4096`
guess). Cost for busy wallets is still dominated by
Class A + spend joins, not SH pointer chasing.

---

## Class C — chain tip

### `confirmed.body`

Dense u64 array: index = height → header_fk. Length = tip_height + 1 when non-empty.

### `strong_tx.body`

Bitset: bit `(tx_fk − 1)` set ⇒ tx is strong on the best chain.

Always **L2** (full `Vec` in process), even when `RBITCOIN_CLASS_C_INRAM_MAX_MB`
demotes `confirmed` / `header_txs_*`. One bit per create; confirm/reorg/Electrum
must not pread the bitset.

### Create height (schema 16: RAM fence, no `tx_height.body`)

`tx_height.body` (4 B/tx) is **gone**. Create height is O(blocks): a resident
fence of `confirmed[h]` → `header_txs` `(first_fk, count)`. Point query is a
binary search over confirmed runs. Reorg holes (orphaned Class A fks between
two confirmed runs) return unconnected (`None`), not the neighbor height.

Schema 15 leftover `tx_height.body` is unlinked on open (logged).

### Commit order (confirm)

1. `strong_tx` (may lead tip after kill)
2. Thin scripthash creates (may lead tip)
3. **`confirmed[]` tip advance** ← **commit**, then fence extend

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
| `inwit.body` | — | **~486 GiB** (ins + witness; cold) |
| `spent.body` | (9 B inside packed outs, ~32 GiB) | **~32 GiB** schema 15; **~21 GiB** after 8 B slots |
| `{stem}.idx` | 5.28 GiB (`tx.idx`) | 5.28 GiB × **3** (grow-tight; do not 256 MiB-slab each) |
| `txid.body` / `tx.head` | 42.23 / 8.23 GiB | unchanged |

Hot pin+annotate working set: **txout + spent + three idx + txid + tx.head**
(~129+32+16+42+8 ≈ **227 GiB**) vs packed **tx.body + idx + txid + head**
(~663+5+42+8 ≈ **718 GiB**). Reconstruct / `getrawtransaction` also needs
`inwit` (~486 GiB), which pin/SH/tweaks do **not** open.

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
