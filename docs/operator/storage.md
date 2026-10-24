# Storage and indexes

## Bulk store IO backends

**Bulk batch** uses a **single** switch: `RBITCOIN_IO=uring|pool|iocp|pread` (default uring
when available). Table transport is always **fd pread/pwrite**. Compact Class C
is L2 write-behind; see [`docs/io-modality.md`](../io-modality.md). Per-path
env overrides are **removed**. If `uring` is selected but setup fails, demote to
**pread** / **pwrite**. If a live ring stops completing (`drain slow`, then abort),
restart with **`RBITCOIN_IO=pread`** — the process does not switch backends itself.

| Env | Values | Note |
|-----|--------|------|
| **`RBITCOIN_IO`** | `uring` \| `pool` \| `iocp` \| `pread` | Only bulk switch |

Inventory / survivors: [`docs/env-knobs.md`](../env-knobs.md).
Token meanings and ring depth: [`docs/io-modality.md`](../io-modality.md).
`RWF_DONTCACHE` is not used ([`SCHEMA.md`](../../SCHEMA.md) Schema 17 freeze).

## Defaults and memory budgets

| Knob | Default | Override |
|------|---------|----------|
| IBD concurrent getdata | **1024** | code `IbdConfig::window` |
| Blocks in transit / peer | **64** | `IbdConfig::per_peer` (16 MiB payload cap per peer) |
| Live IBD peers | **16** | `--max-outbound` |
| Inbound P2P sessions | **200** | `--max-inbound`. Peers that relay transactions hold at most half. At capacity, unprotected inbounds are evicted. Incomplete VERSION/VERACK is dropped after **60 s** (releases the slot). |
| Milestone (script skip) | mainnet anchor **840000**, testnet3 anchor **2500000**, signet **0**, regtest 0 | `--milestone` (`0` = full scripts; explicit height is height-only) |
| ConfirmParentCache header plans | always on | Tip-ahead header + tx_fks for multi-block MTP (no create pin FIFO) |
| Bulk store IO | **uring** (Linux) when available | `RBITCOIN_IO` only. Matrix: [`docs/io-modality.md`](../io-modality.md) |
| Archive Class A append | **pwrite** (always) | `txout` / `seqsigwit` / `spent` plus `create.loc` / `seqsigwit.loc` |
| `tx.head` (segmented) | fixed geometry | Default **25-bit**. Rebuild env: [`docs/env-knobs.md`](../env-knobs.md). Bytes: [`SCHEMA.md`](../../SCHEMA.md) / [`docs/heads.md`](../heads.md). Legacy mono-head datadirs require reindex |
| Confirm stages | **lookup · load · scripts · write** | Queues and pack/wave: [`docs/concurrency.md`](../concurrency.md). RAM: [`docs/ibd-memory.md`](../ibd-memory.md) |
| Confirm batch inputs | **8000** soft | Hardcoded. Live line: `h= n= in=` (**n** = blocks in pack, **in** = Σ inputs) |
| Mempool weight budget | **~300e6 WU** | `--mempool-size-mb N` (maps N×1e6 WU) |
| Inhibit auto-suspend | **off** | `--inhibit-suspend` (uses `systemd-inhibit` if available) |

### Suspend inhibit

Long IBD runs can be interrupted if the host auto-suspends. Pass
`--inhibit-suspend` to request a systemd **block** inhibit for `sleep` and
`idle` while the process runs (via `systemd-inhibit`). Default is off. If
`systemd-inhibit` is missing or logind rejects the request, the node logs a
warning and continues without inhibit.

**Peers file:** `{datadir}/peers` stores discovered addresses and **PeerFlags**
(connected / fast / slow / incompatible / last-fail) between runs. Loaded at
start (before seeds), updated after IBD and on shutdown. Seeds are merged in
without clearing known flags. New writes are `rbitcoin-peers-v2` (IPv4, IPv6,
and Tor v3 `.onion:port` tokens). `rbitcoin-peers-v1` IPv4/IPv6 files still
load.

**Index modes:** Direct vs Tip: [`docs/concurrency.md`](../concurrency.md).
IBD finishes Class A + `tx.head` + spend annotations **before** tip; tip entry
does not backfill them. Scripthash: durable head stays Tip write-behind;
no head means Direct defers SH until a Class A collect + unsorted pack at
horizon. Confirm does **not** enqueue SH during Direct.

SIGINT keeps every sealed SH head; resume packs only unsealed shards (holes
stay; missing `DONE` restarts collect). `RBITCOIN_SH_FORCE_REBUILD=1` wipes the
head and does a full Class A collect + unsorted pack — unset after success
([`docs/env-knobs.md`](../env-knobs.md)). Missing `include_hwm` bootstraps
from SEAL (never clamp SEAL→0). Clearing residual run files **preserves
`SEAL`**. **SIGINT** mid cold keeps finished prefix shards
(`scripthash.cold_progress`). Materialize status logs ~**every 10s**.

On enter Direct, leftover `ibd_utxo.map` / `point.runs` / `tx.runs` from old
Catchup datadirs are removed — prefer a **fresh datadir**. Layout, shard
counts, ingest OA, and refuse lines: [`SCHEMA.md`](../../SCHEMA.md) and
[Schema upgrade](#schema-upgrade). Working-set sizes: SCHEMA census and
[`docs/ibd-memory.md`](../ibd-memory.md).

## Schema upgrade

Live bytes: [`SCHEMA.md`](../../SCHEMA.md) (`SCHEMA_VERSION = 26`). This section is
the operator copy-paste only — do not treat it as a second layout map.

Open **never silently wipes** a populated store (policy:
[`SCHEMA.md`](../../SCHEMA.md#changing-durable-bytes)). An older `store/meta` either
rewrites `meta` (payload-only) or **refuses** with a one-line message that
names the dirs. Corrupt files are **not** repaired in-process.

| Incoming `meta` | What this binary does |
|-----------------|------------------------|
| **26** | Open. |
| **25** | If `header.body` is still 96 B, rewrite each row to 88 B (`header.body.grow`, then rename), dropping trailing size and weight. An 88 B body is left alone. Then rewrite `meta` to 26. |
| **24** | Same header shrink as 25. Zero-extend `txstat.body` to the `create.loc` count (no `txout.body` rewrite). Unlink leftover `txfixed.body`. Rewrite `meta` to 26. |
| **23** | Headers stay 88 B. Rewrite `meta` to 26. `txstat.body` is created and aligned to the loc count when it is missing or short. |
| **22**, occupied Class A | Rewrite `create.loc.ovf` 12 B→16 B. Headers stay 88 B. Then the same `meta` rewrite and `txstat` align as 23. |
| **22**, empty Class A | Rewrite `meta` to 26, then open. |
| **Below 22**, empty or occupied | **Refuse.** One line: `schema before 22 refuses this datadir; wipe datadir and redo IBD`. Wipe the datadir and redo IBD. No per-version rewrite. |

On every open of meta 22–25 the node also renames leftover `inwit.*` to `seqsigwit.*` and `inputs.*` to `input.*`. A missing `input.loc` with seqsigwit prevouts backfills parent edges. A crash during the 96 B→88 B rewrite leaves the old `meta`; the next open retries the shrink. Size and weight after that come from `txstat`.

A `txstat.body` cell written as four ULEBs starting with `n_in` (an unreleased 25 experiment) is not detected and is not rewritten. Resync that datadir. A **25 binary** refuses 26 `meta`. A **24 binary** refuses 25 `meta` (do not downgrade in place). A **23 binary** refuses 24+ `meta`. A **22 binary** refuses 23+ `meta`. A **21 binary** refuses 22+ `meta`. A **19 binary** refuses 20+ `meta`.

When meta is below 22, the log line is:

```text
schema before 22 refuses this datadir; wipe datadir and redo IBD
```

A meta **22 or newer** datadir can still refuse leftover **index** layouts (fuse8 v1,
flat `*.idx.meta`, Shared file `scripthash.body`, pack8 Paged mode 10). The
line is one of:

```text
index refuses fuse8 v1; wipe store/tx.head and store/scripthash* then restart (Class A kept; tx.head rebuilds, SH rematerializes with --sh-index)
index refuses flat tx.head.meta; wipe store/tx.head then restart (Class A kept; tx.head rebuilds)
index refuses flat *.idx.meta; place files under store/{stem}.idx/ (meta + NNNNNN segments) then restart (Class A kept)
index refuses Shared (file) scripthash.body; wipe store/scripthash* then restart (Class A kept; SH rematerializes with --sh-index)
index refuses pack8 Paged (mode 10) scripthash heads; wipe store/scripthash* then restart (Class A kept; SH rematerializes with --sh-index)
```

Copy-paste (node stopped with SIGTERM):

```bash
DATADIR=/path/to/datadir
# fuse8 v1 / Shared SH body / Paged SH heads (same dirs as schema-20 index refuse):
rm -rf "$DATADIR/store/tx.head" "$DATADIR/store/scripthash"*
# leftover Class A `*.idx` dirs (schema 22 uses create.loc / seqsigwit.loc):
#   rm -rf "$DATADIR/store/txout.idx" "$DATADIR/store/spent.idx" "$DATADIR/store/seqsigwit.idx"
```

Keep Class A (`txout` / `seqsigwit` / `spent` + `create.loc` / `seqsigwit.loc`, `txid.body`, headers) and
Class C. Restart the same binary: `tx.head` rebuilds from Class A; with
`--sh-index`, SH rematerializes. Do **not** `rm -rf store/`.

**Kill-9 / crash is not a schema upgrade.** Open follows
[`docs/crash-recovery.md`](../crash-recovery.md) (tip-as-commit, Class C
repair above tip). Prefer SIGTERM ([Resume / clean stop](#resume--clean-stop)).
A corrupt file still means wipe/reindex — not an in-process repair.

## Import a pre-built store (`--assumehot`)

A new node can start from another node's store instead of running IBD. You
trust whoever gave you the digest to name the right chain.

On the source, stop the node with SIGTERM, then print its digest:

```bash
rbitcoin-node --datadir /srv/rbtc-src --network signet --hot-digest
# signet 212345 000000…tiphash 3f9a…digest
```

The last field is the digest. It covers the confirmed chain and its spend
state, addressed by height. It does not depend on `store.secret`, the schema
the store started on, orphans, or reorg history, so two honest nodes on the
same tip print the same digest. Copy the source datadir to the new host, or
read it in place.

On the new node, start once with both flags and the usual ones:

```bash
rbitcoin-node --datadir /srv/rbtc --network signet \
  --assumehot-from /srv/rbtc-src --assumehot 3f9a…digest
```

Before it opens its own store, the node:

1. takes the source datadir's `.lock` (a running source node is refused);
2. refuses unless the destination `store/` is empty and has no
   `--datadir-cold`;
3. refuses a source that keeps files on a `--datadir-cold`
   (`seqsigwit.reloc`), is not on the current schema, did not stop cleanly
   (`tip_seal` or `spend_durable` missing or behind its tip), or is pruned;
4. walks the source by height into `store.import/` next to `store/`: each
   header is checked against its parent (proof of work, retarget, time),
   each body against its header and its height's soft forks (merkle root
   from recomputed txids, witness commitment, size, BIP34). Each block is
   then connected as IBD connects it: double spends, coinbase maturity,
   BIP30, BIP68 and subsidy plus fees are checked, and spends, fees and the
   indexes are recomputed. Scripts are not run, as with `--milestone` at the
   source's tip. A connect failure names the run of up to 64 heights it was
   checked in;
5. compares the new store's digest with `--assumehot`, records the
   import in `store.import/assumehot` (height, tip hash, digest), then
   renames `store.import/` to `store/`. On any refusal or mismatch it
   deletes `store.import/` and exits 1, leaving `store/` empty.

The import never writes to the source. It opens the source without the
start-up repairs a node runs: it doesn't recheck the tip window, repair indexes
or resize `header.head`. A source whose tip is past its `tip_seal` is
refused, not shrunk back; start it once as a node to repair it.

A later start that still passes the flags finds `store/assumehot`. If it
names the same digest, the node logs that the store is already imported and
opens it without touching the source, also after it has followed past the
imported tip, so the source can be deleted once the import is done. A
different digest is refused, and so is a non-empty `store/` that no import
wrote. The flags are CLI only, so a conf file never re-imports.

**Disk:** the destination gets a full rewritten copy, so it needs free space
about the size of the source `store/`. Neither side may be split with
`--datadir-cold`: the import reads and writes one `store/` each. The
destination's head scale comes from its own flags.

**What you skip:** the download and script checks below the imported tip,
as with `--milestone` at that height. Unlike Core's assumeutxo there is no
background validation from genesis. See [`COMPAT.md`](../../COMPAT.md).

## Scripthash index (`--sh-index`)

Class B **scripthash** reverse index is **optional** (default **off**), analogous
in *operator spirit* to Core’s heavy reverse indexes — **not** the same as
Core `-txindex` (we always keep Class A + `tx.head` for by-txid lookup).

| Mode | Behavior |
|------|----------|
| **off (default)** | No SH run enqueue during IBD; no tip bulk materialize. Tip follow + mempool relay + JSON-RPC work without SH. |
| **on** (`--sh-index` / `sh_index=1`) | Direct IBD defers SH. Tip entry runs two Class A scans, then pack and seal; write-behind follows. Address/scripthash Electrum/Esplora methods work after that seal. |

Electrum/Esplora **start without** `--sh-index`. Address/scripthash methods then fail closed (`scripthash index disabled`). Txid/outpoint/block/fees still work. Matrix: [`docs/lightning.md`](../../docs/lightning.md).

`--esplora-block-template` (conf `esplora_block_template=1`) enables
`GET /block-template` on the Esplora listen (same JSON as RPC
`getblocktemplate` template mode). Default **off** (404).

`--max-sh-creates N` (conf `max_sh_creates=`) defaults to **10000**. An unpaged
Electrum history or full stats join with more than N creates is refused
before Class A expand: Esplora **503** / Electrum JSON-RPC error
`scripthash join exceeds --max-sh-creates (<creates> creates, cap <N>)`. **0** is unlimited.
A history request that names a page (Esplora's 25, or any caller that sets a
limit) is still served: the join stops once that page is full.

`--heavy-sh-creates N` (conf `heavy_sh_creates=`, default **10000**, **0** off)
lets one unpaged join with more than N creates run at a time across the
node. One join near a raised cap of 100000 was measured at 2.1 GiB peak RSS,
so several at once can push a small box into swap. A waiting join holds a
blocking-pool thread; lighter joins and paged history do not wait.

Order-of-magnitude costs (mainnet-class SSD; not a warranty):

- **During IBD with sh_index=1:** modest extra work (run stream); after IBD, bulk materialize is typically **tens of minutes to a few hours**.
- **Enable after tip already synced:** full recollect/materialize from Class A — **often multi-hour**; tip follow continues; Electrum waits until SH ready.
- **Disable later:** tables are **left on disk** (no automatic purge). Re-enable may rematerialize.

Tip-follow readiness is **independent** of SH materialize (`tip_follow_ready` ≠ `sh_tip_ready`).

### Abort / resume (tip materialize)

Keep **`store/scripthash.unsorted/`** until every shard has
`scripthash.head/NN.packed`. That mark is the pack commit. Pass-1
`.mphf`+`.val` without it is not sealed. Resume rules:
[`docs/crash-recovery.md`](../crash-recovery.md) (scripthash cold resume).
Extra disk during build is **`SHKSP01` spills** plus **`SHPST01` post spills**.
Restart with the same `--datadir --sh-index`. Do not delete unsorted files
to start over unless you intend a full Class A collect
(`RBITCOIN_SH_FORCE_REBUILD`). A spill whose magic is not `SHKSP01` or
`SHPST01` is Corrupt — wipe `store/scripthash.unsorted` and rematerialize.

| Stop | What restart does |
|------|-------------------|
| No valid `DONE.keys` | Delete unsorted and restart pass 1. Seal rewrites the MPHF. |
| `DONE.keys`, no `DONE.post` | Keep pass-1 MPHF; discard partial `post/` spills; pass 2 from fk 1; pack. Electrum stays down. |
| `DONE.post`, some `.packed` | Pack only the unmarked shards. |
| All `.packed` | Tip write-behind. A second start does not collect. Electrum stays down until `include_hwm` covers the tip, then this process binds it. |
| Complete head, no marks, no extract | Soft-migrate: write `.packed`. Missing `include_hwm` is set from the create count. |
| Kill-9 mid pack | Unfinished shard is redone. Open follows [`docs/crash-recovery.md`](../crash-recovery.md). |
| Write-behind IO error (disk full) | The process exits non-zero after the shutdown flush. Restart the same datadir; write-behind continues. |
| Corrupt SH (leftover live OA, mixed body, refuse line) | Wipe `store/scripthash*` only, keep Class A, rematerialize with `--sh-index`. |

Electrum waits until SH is tip-ready. Do **not** `rm -rf store/` for an SH
abort. Force-rebuild sticky env (`RBITCOIN_SH_FORCE_REBUILD`) must never redo
multi-hour Class A work casually — [`docs/env-knobs.md`](../env-knobs.md).

## Silent payment tweaks (`--sp-tweaks`)

Optional **thin** BIP-352 index for Electrum `blockchain.tweaks.subscribe`
(Cake Wallet, [kiss-bdk](https://github.com/kkdao/kiss-bdk); client-side
scan). Default **off**. The method still exists when off (naive per-height
walk). Flag on = persist + serve-from-index. Stream shape and Sparrow/Frigate:
[`COMPAT.md`](../../COMPAT.md) (Electrum surface).

**Not built during Direct IBD** (the write thread stays Class A + annotate).
After catch-up, **SH materialize first** (if `--sh-index`), then a background
walker fills `origin..=live tip` from Class A. Tip write-through only when
`height == next_height`; if confirm is ahead, backfill owns the hole. Kill
is safe: `next_height` is the last complete put; restart in Tip (or after
the next Direct catch-up reaches tip) resumes the walker. Electrum during
the hole uses the naive path.

On disk (schema 17 dirs; leftover single files are unlinked on startup):

| File | Contents |
|------|----------|
| `store/sp_tweaks.idx/` | `meta` (`origin` + fmt 3) + `NNNNNN` tip-only `u32` start offs (no `header_fk`) |
| `store/sp_tweaks.body/` | Matching `NNNNNN` files: per tx `len=0` or `len=33` + compressed `A_tweak`. New pair when the next start would exceed 4 GiB. |

**Not stored:** txids, Taproot outs, values, parent scripts. Notify
`output_pubkeys` are joined from this block’s **`txout`** body (~12 ms
sequential on a 4k-tx 9p block; witness stays in `seqsigwit`). Indexed serve does
**not** parent-peek (~40–80 blk/s vs ~1.5–3 naive on that VM).

Serve-time **`--sp-tweaks-dust SATS`** (conf `sp_tweaks_dust=`) omits P2TR outs
with `value <= SATS` and drops txs that then have none. Default **1000**.
`0` serves every value. **`546` matches Cake electrs** `sp_min_dust`. This is
not Core dust: P2TR at 1 sat/vB is about **330** sats; 546 is the P2PKH
figure Cake’s server used. The index is unchanged — only the Electrum JSON.

IBD seals the index from the taproot origin (709632 on mainnet) when
`--sp-tweaks` is on from the start, on the confirm write thread, shared with
`--block-filter-index`. A restart gap of at most one write drain is sealed
at startup; a later enable still materializes after catch-up
(`rbtc-idx-wb`). Once the watermark covers the tip, new blocks are sealed on
the confirm write thread. That materialize is one IO thread reading windows of heights on one completion session
(`seqsigwit` and parent txids only for P2TR-output txs); one CPU thread
(`rbtc-idx-cpu`) publishes one job per height to `rbtc-scripts-*` (tweak EC,
and filter GCS when that index is on) and commits one batched height-blob +
idx write per window. A catch-up wave shares that pool with block scripts for
at most one window. Reorg truncates with tip. Kill-safe: `next_height` is the
last complete put. INFO every 10 s: `index: build next=… tip=… rate=…/s
remain=… read=…ms build=…ms commit=…ms`.

Cake Wallet’s scan isolate may still hardcode `electrs.cakewallet.com` even
after a successful probe — see `COMPAT.md`.
