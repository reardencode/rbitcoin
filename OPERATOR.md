# Operator guide — full participant node

## Status

BIP324 v2-only P2P, cluster mempool (Libre admission + **consensus script checks on accept**),
Electrum confirmed + unconfirmed (TLS via reverse proxy). **0.5 mainnet** is
early production / high-scrutiny — see
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md). Watch reorgs and disk
headroom before any serious use. Default mainnet **`--milestone 840000` skips script/sig checks** at/below
that height; use `--milestone 0` for full scripts.

Architecture: peer wire lands in an **in-RAM body queue**; confirm
(lookup → load → scripts → write) is the **sole Class A appender** and
advances Class C tip in the same era. Download defaults to **1024** concurrent
getdata (not a tip-distance cap), max **16** blocks in transit per peer.

## Build

Portable **static musl** binary (runs on ordinary Linux without Nix):

```bash
nix build .#rbitcoin-musl
mkdir -p target/release
install -m 755 result/bin/rbitcoin-node result/bin/rbitcoin-cli target/release/
./target/release/rbitcoin-node --help
```

Do not use `cargo build --release` under `nix-shell` for the operator binary —
that produces a Nix-glibc dynamic link that fails outside the store. Release on
Linux is always musl static. Compiling the tree as a contributor (rustup, no
Nix, macOS/Windows): [`CONTRIBUTING.md`](./CONTRIBUTING.md). See
[`docs/reproducible-builds.md`](./docs/reproducible-builds.md).

**GitHub Release** (`v*.*.*` tags) is the operator snapshot: Linux musl +
Windows CRT-static PE + Darwin aarch64 binaries + SHA256SUMS. Merge the version-bump PR into
`master` locally (merge commit), then:

```bash
./scripts/release.sh          # checks, tag vX.Y.Z, push master + tag
# ./scripts/release.sh --dry-run
```

Retry from Actions → **release** → Run workflow (artifacts only, no tag).
PR `ci` **windows** / **macos** jobs smoke store create/open + `--smoke`;
they do not upload binaries. Local Linux `target/release/` install is still
`nix build .#rbitcoin-musl` on a clean master tree. Windows IoRing is not
supported. Darwin/Windows are not Nix packages — see
[`docs/reproducible-builds.md`](docs/reproducible-builds.md).

**Darwin Gatekeeper:** the Darwin binaries are ad-hoc signed (`codesign -s -`), not
notarized. If Finder or a browser sets quarantine and the binary is killed
on launch:

```bash
xattr -d com.apple.quarantine rbitcoin-node rbitcoin-cli
```

**Windows store files** are opened `FILE_FLAG_OVERLAPPED` (IOCP). Header
create/open/grow use positional `ReadFile`/`WriteFile` +
`SetFileInformationByHandle`, not std `Read`/`Write`/`Seek`. Mixed
Default `--datadir` is cwd-relative `datadir` via `Path::new(".").join("datadir")`
(`./datadir` on Unix, `.\datadir` on Windows).

## First hour (regtest)

One loop: mine a block, one Electrum RPC, one Esplora GET. This is **regtest**,
not validated mainnet (default mainnet `--milestone` skips historical scripts).
Signet/mainnet: [`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

Electrum and Esplora **require `--shindex`**. JSON-RPC is only there so
`rbitcoin-cli` can mine.

```bash
./target/release/rbitcoin-node \
  --datadir /tmp/rb-hour \
  --network regtest \
  --no-seeds \
  --shindex \
  --rpc-listen 127.0.0.1:18443 \
  --electrum-listen 127.0.0.1:50001 \
  --esplora-listen 127.0.0.1:3000
```

In another terminal (cookie at `/tmp/rb-hour/.cookie`):

```bash
./target/release/rbitcoin-cli --datadir /tmp/rb-hour --rpcport 18443 \
  generatetodescriptor 1 'raw(51)'

python3 - <<'PY'
import json, socket
s = socket.create_connection(("127.0.0.1", 50001))
req = json.dumps({"id": 1, "method": "server.version", "params": ["rbitcoin-hour", "1.4"]}) + "\n"
s.sendall(req.encode())
print(s.recv(4096).decode())
PY

curl -s http://127.0.0.1:3000/blocks/tip/height
```

Expect: a generated block hash list, an Electrum `server.version` result, and
`1` from Esplora (tip height after the generate). More Electrum/Esplora surface:
sections below and [`COMPAT.md`](./COMPAT.md).

## CLI (operator-first)

Routine knobs are **CLI / conf**, not required env vars. Clean smoke:

```bash
./target/release/rbitcoin-node --smoke --datadir /tmp/rb-smoke --network regtest
```

| Flag | Core-ish alias | Default |
|------|----------------|---------|
| `--datadir PATH` | same | cwd `datadir` (`./datadir` Unix, `.\datadir` Windows) |
| `--datadir-cold PATH` | conf `datadir-cold=` | unset — Class A `inwit.body` / `inwit.idx/` under `{PATH}/store`; everything else stays in `--datadir` |
| `--network NET` | `--chain` | `mainnet` |
| `--signetchallenge HEX` | `--signet-challenge` | default global Signet challenge |
| `--signetblocktime SECONDS` | `--signet-block-time` | 600; requires a custom challenge |
| `--listen ADDR` | | bind later default port |
| `--connect ADDR` | (repeatable) | seeds |
| `--milestone HEIGHT` | `--assumevalid-height` | network default (mainnet 840000) |
| `--max-outbound N` | `--maxoutbound` | 16 live download peers |
| `--maxinbound N` | `--maxconnections` | 125 inbound sessions |
| `--mempool-size-mb N` | `--maxmempool` | ~300 MiB weight |
| `--conf FILE` | | none |
| `--log-level LEVEL` | | `info` |
| `--api-log PATH` | conf `api_log=` | off — JSONL of Electrum / Esplora / RPC calls |
| `--no-seeds` | `--noseeds` | seeds on |
| `--shindex` | conf `shindex=1` | **off** — Class B scripthash (required for Electrum/Esplora) |
| `--sptweaks` | conf `sptweaks=1` | **off** — thin BIP-352 tweak index (`sp_tweaks.*`) |
| `--electrum-listen ADDR` | | disabled (**requires** `--shindex`) |
| `--esplora-listen ADDR` | | disabled (Esplora REST; **requires** `--shindex`) |
| `--rpc-listen ADDR` | conf `rpc_listen` | disabled — Core-class JSON-RPC subset |
| `--rpcuser` / `--rpcpassword` | conf `rpcuser`/`rpcpassword` | unset — else cookie `{datadir}/.cookie` |
| `--inhibit-suspend` | | off |

Conf file: simple `key=value` lines (`#` comments). CLI overrides conf. Example:

```
network=signet
maxinbound=64
mempool_size_mb=100
```

`--datadir` holds the node root (`store/`, `mempool/`, `peers`, `.cookie`).
Omit `--datadir-cold` and cold files live there too. Set it to put the large
rarely-read Class A **inwit** stem (`inwit.body` + `inwit.idx/`, ~486 GiB + idx
on mainnet) on another volume. Pin / spend-annotate / Electrum / tweaks do not
read inwit; reconstruct / `getrawtransaction` / block serve do.

```
--datadir /mnt/nvme/rbtc --datadir-cold /mnt/hdd/rbtc-cold
# hot:  /mnt/nvme/rbtc/store/txout.body  (and the rest)
# cold: /mnt/hdd/rbtc-cold/store/inwit.body
#       /mnt/hdd/rbtc-cold/store/inwit.idx/
```

A hot-store sidecar `inwit.reloc` records the split. Opening without
`--datadir-cold` then refuses. Do not leave `inwit.*` in both places. Moving an
existing datadir is operator `mv` (or copy+remove cross-device):

```
mkdir -p /mnt/hdd/rbtc-cold/store
mv /mnt/nvme/rbtc/store/inwit.body /mnt/nvme/rbtc/store/inwit.idx /mnt/hdd/rbtc-cold/store/
```

**Advanced** IO/perf tunables may still use `RBITCOIN_*` (see below); they are
**not required** for normal signet/mainnet sync or tip follow.

## Logging

Operational logs go to **stderr** with UTC timestamps:

```
2026-07-15T03:04:26.725Z INFO  rbitcoin-node starting network=mainnet …
```

| Control | Values |
|---------|--------|
| `--log-level LEVEL` | `error` `warn` `info` `debug` `trace` `off` |
| `RBITCOIN_LOG` / `RUST_LOG` | advanced fallback if CLI omits `--log-level` |

Default: **info**. CLI wins over env.

### Tip-follow (every block)

After IBD, each accepted tip extension logs one **info** line (Core-like):

```
UpdateTip: new best=<hash> height=<n> version=<v> tx=<n> date=<unix> progress=tip
```

Emitted from the tip-follow / wire accept path (`ChainHub::connect_at`). IBD bulk
confirm does **not** spam this line per block — use the periodic IBD status below.

### Tip-follow status lines (after catch-up + tip SH ready)

| Line | Level | Use |
|------|-------|-----|
| `tip: perf` | DEBUG | Every ~5s: follow peers, blocks this window, mempool accept/reject + wall µs, inv/getdata/announce, Esplora/Electrum req counts + avg/max µs |
| `tip: accept` | INFO | Per accepted tip block: wall/load/script/class_a/class_c/SH breakdown (not emitted on reject) |
| `UpdateTip` | INFO | New best hash/height after connect |
| `node: tip=…` | DEBUG | Same height change plus `follow_live` (use `UpdateTip` at info) |
| `received getdata for: wtx` | TRACE | One line per peer `MSG_WTX` getdata (Core `p2p_blocksonly` needle; counts are on `tip: perf`) |
| `p2p: session … closed` | DEBUG | Clean session end. Unexpected end stays **WARN** `p2p: session … ended` |

Requires **tip mode** (`node: catch-up complete … tip tracking`). During IBD use `ibd: progress` at INFO; enable `ibd: perf` / `ibd: sizes` / `tip: perf` with `--log-level debug` (or conf / `RBITCOIN_LOG=debug`).

### IBD status lines (every ~5s)

| Line | Level | Use |
|------|-------|-----|
| `ibd: progress` | INFO | Tip rate, `loadq`/`scriptq`/`writeq`, `txs=` (Class A / `tx.idx` count), horizon, tip ETA, **`bq soft=n/win RAM=`** (in-RAM body queue; soft densify: under ~100 MiB free ahead, over that only ~1 min confirm window, at/over 1 GiB assign-stop fill holes in the fetched range only) |
| `ibd: perf` | DEBUG | Inflight + **`bq soft= RAM=`**; **`load=`** is pin+assemble only. **`load_thr pack/stamp/pin/asm/prune`** is the load OS thread. **`stamp=`** nests **`pack=`** (plan HashMap) vs **`head=`** (leftover TipOnly; IBD skeleton keeps this ~0). **`script=`** is verify ns (`jobs=` / `skip=`); recv/send are wait. **`pin_txid=`** is skeleton hits vs leftover `tx.head` |
| `ibd: sizes` | DEBUG | RSS + work path + **`bq soft=` / `RAM=`** + **conf_plans** + confirm pipe |
| `ibd: perf_dbg` | DEBUG | µs/blk load/write, pin/edge detail, **plan_batch** (`us/pin_txid` vs `probe/idx/body us/key`) + **class_a commit** |

Default INFO is `ibd: progress` only. `--log-level debug` adds perf / sizes / perf_dbg from the same sample. Ghost columns from deleted paths (wave-fill stubs, Direct SH head RMW) are omitted from both formatters. Pipeline roles: [`docs/concurrency.md`](docs/concurrency.md). Head files: [`docs/heads.md`](docs/heads.md).

`pin_txid%` is stamp `txid→create_fk` from the load-batch skeleton vs leftover `tx.head` (IBD skeleton path should stay at 100%). `pin_hit%` is load outs adopt/plan reuse — this-window range-fills are `pin_new` only.

**Tip hole / peer hygiene:** `hole=` on the progress line is the fetch gap from
tip+1 to the next in-hand body (confirmed, still on the BQ, or already taken
onto loadq). Tip-batch getdata races up to 4 peers
(preferring faster live rates) and re-races after ~6s without wire. WARN
`ibd: peer[…] stalled` is absolute zero block progress (~30s). WARN
`ibd: peer[…] relative-slow (bps= med= spread=…)` disconnects a clear
half-median outlier only after ~60s warm-up and only when the peer pack is not
tight (max/min bps &gt; 2×); good-but-slightly-slower peers are kept.

**Create pins:** pipeline-local only (`batch_pin` / `BatchParents`). No process pin FIFO. Header plans via ConfirmParentCache. Just-confirmed **identity + full create outs** stay on in-flight until a later lookup wave snapshots drain+fence past the pack height and load finishes that wave's last in-flight read. Not a coins cache.

**Archive `tx.head` split (perf_dbg):** `plan_batch … head_rd=` is parent
**read** resolve (`get_fk_by_txid_batch`, with `probe` / `idx` / `body` subtimers).
`class_a_commit … head=` is create **insert** (`head_insert_many`). Pipeline pins stay on the plan (`batch_pin`); no process denserels seed.

**Archive head resolve:** streaming — **FdOnly** page-coalesced head probe +
**FdOnly** `txout.idx` + **`txid.body`** identity via **io_uring or pread**
(deepest-cand-first).
**Class A `txout` / `inwit` / `spent` + their `*.idx`, `tx.head`, header head,
SH head/body, and spenders are fd pread/pwrite**.
Full modality matrix: [`docs/io-modality.md`](docs/io-modality.md).

## Bulk store IO backends

**Bulk batch** uses a **single** switch: `RBITCOIN_IO=uring|pread` (default uring
when available). Table transport is always **fd pread/pwrite**. Compact Class C
is L2 write-behind; see [`docs/io-modality.md`](docs/io-modality.md). Per-path
env overrides are **removed**. If `uring` is selected but setup fails, demote to
**pread** / **pwrite**.

| Env | Values | Note |
|-----|--------|------|
| **`RBITCOIN_IO`** | `uring` \| `pool` \| `iocp` \| `pread` | Only bulk switch |

Inventory / survivors: [`docs/env-knobs.md`](docs/env-knobs.md).

**RWF_DONTCACHE:** not used. `spent.body` is its own file; evicting those
pages after annotate does not protect `txout`. See
[`SCHEMA.md`](SCHEMA.md) (Schema 17 freeze).

- **uring** — Linux io_uring (ring depth **128**). On Windows this opens
  IOCP.
- **pool** — worker-pool completion session (Darwin default).
- **iocp** — Windows IOCP (Windows default).
- **pread** / **pwrite** — libc positional IO (session off).
- Class A **`txout` / `inwit` / `spent` + `*.idx` linear appends always pwrite**.

## Defaults and memory budgets

| Knob | Default | Override |
|------|---------|----------|
| IBD concurrent getdata | **1024** | code `IbdConfig::window` |
| Blocks in transit / peer | **16** | `IbdConfig::per_peer` |
| Live IBD peers | **16** | `--max-outbound` |
| Inbound P2P sessions | **125** | `--maxinbound` / `--maxconnections`. Incomplete VERSION/VERACK is dropped after **60 s** (releases the slot). |
| Milestone (skip scripts ≤ height) | mainnet **840000**, signet 2000000, … | `--milestone` / `--assumevalid-height` (`0` = full scripts) |
| ConfirmParentCache header plans | always on | Tip-ahead header + tx_fks for multi-block MTP (no create pin FIFO) |
| Bulk store IO | **uring** (Linux) when available | `RBITCOIN_IO` only; ring depth **128**. Segmented `tx.head` FdOnly; Class C L2 write-behind (`docs/io-modality.md`) |
| Archive Class A append | **pwrite** (always) | `txout` / `inwit` / `spent` + `*.idx` mega-appends use `write_at_pwrite` only |
| `tx.head` (segmented) | fixed geometry | Default **25-bit** heads. Open segment is 4 B OA; roll opens the next OA immediately and seals the previous (**value-assigned MPHF + fuse8**) on a sidecar. Wipe/empty rebuild writes MPHF directly in parallel (default **2²⁵** keys, min(CPUs, free RAM/750 MiB) workers; `RBITCOIN_TX_HEAD_REBUILD_SEAL_BITS=26` / `RBITCOIN_TX_HEAD_REBUILD_WORKERS` override). Legacy mono-head datadirs require reindex |
| Confirm stages | **lookup · load · scripts · write** | Real queues **loadq=14 · scriptq=4 · writeq=14**. Lookup takes BQ in height order (stops at a hole after `lookup_taken_hi`), parks resolved rows, and dequeues **per load-batch send** (8000 inputs / 144 blocks). IBD **lookup** TipOnly-resolves remaining-loadq × load pack (safety cap **64000** inputs / **1080** heights); hard **min 8000** when more unresolved heights remain. Wave table: [`docs/concurrency.md`](docs/concurrency.md). |
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
without clearing known flags.

**Index modes:** IBD defaults to **`IndexMode::Direct`**: archive batch-writes
split Class A (`txout` / `inwit` / `spent`) + durable **`tx.head`**; confirm
batch-writes **spend annotations** on **`spent.body`** after Class C. Those
indexes are **complete before tip** — catch-up must finish; tip entry does not
backfill them. Scripthash has **two** methods: a **durable head** stays
`IndexMode::Tip` (catch-up uses the same write-behind as tip follow;
leftover `scripthash.runs` are discarded). **No head:** Direct IBD defers SH;
after the horizon, Class A recollect spills catalog runs then **FullCold** /
**ColdResume**. Confirm does **not** enqueue SH during Direct. Tip SH
materialize **slices the catalog k-way by prefix shard** (workers = min(CPUs,
host free RAM / 1.5 GiB), 256 KiB pages). Workers write `scripthash.body/NN`
and seal `scripthash.head/NN` themselves. SIGINT keeps every sealed head;
resume packs only unsealed shards (holes stay). Legacy shared
`scripthash.body` stays one writer with prefix `scripthash.cold_progress`.
No temp `pack*.body`. Catalog records stay unique on `(scripthash, create_fk)`,
`key_len=40`. Sealed sorted+idx main shards (no main fuse). Schema-16
`key_len=32` leftover `scripthash.runs` are refused (wipe that dir and
rematerialize). Class A with creates in the pre-pack 16-byte meta /
9-byte spent layout is refused (wipe datadir and redo IBD). New keys after seal go
to one **global ingest OA** (mainnet 2²⁵ slots × 24 B ≈ 768 MiB). Materialize
k-ways catalog runs (recollect spills ~128 MiB). Materialize status logs
~**every 10s** from one observer (`keys`/`creates`/`pending` unpublished/
`shards` published/`rate`). Path selection logs `path=FullCold|ColdResume|Skip`.
**Full cold reinit only if the SH head is empty** (or force rebuild).
`RBITCOIN_SH_FORCE_REBUILD=1` wipes the head and does a full Class A collect +
FullCold — unset after success; see [`docs/env-knobs.md`](docs/env-knobs.md).
Unstable `RBITCOIN_SH_MATERIALIZE=unsorted-shards` skips catalog runs: one Class A
pass writes unsorted `scripthash.unsorted/NN` (nCPU, 1 MiB per-shard buffers,
offset-ordered pwrite), then each
pack worker unique-sorts one file **in place** (~2 GiB) and seals `head/NN`. Unset keeps k-way.
Incomplete catalog (high SEAL + tiny run mass) on an **empty** head triggers
full Class A recollect (SEAL=0). Missing `include_hwm` on a durable head
bootstraps from SEAL (never clamp SEAL→0). Clearing residual run files
**preserves `SEAL`**. **SIGINT** mid cold keeps finished prefix shards
(`scripthash.cold_progress`).
On enter Direct, leftover
`ibd_utxo.map` / `point.runs` / `tx.runs` from old Catchup datadirs are removed
— prefer a **fresh datadir**. Legacy **16-way** `scripthash.head/` with
**`scripthash.runs` still present** auto-migrates on open (old head renamed
`scripthash.head.legacy-*`, empty 64-way + tip rebuild from runs). No runs left
⇒ reindex.

**Schema 15 SH layout:** durable values are Empty / Inline / geometric **slab**
(3–256 fks) / megakey **pages** (≥257). Main shards are **sealed sorted+idx** (no fuse);
new keys land in **`scripthash.ovf/ingest`**. ≥8 sealed ovf files compact-merge.
**Open upgrade:** empty Class A + empty/missing SH may silently rewrite `meta`
13/14→15. A packed `tx.body` **with creates**, or a durable page-era (or
schema-13 slab) SH index, is **refused** — wipe `store/scripthash*` (and/or
Class A) and rematerialize / redo IBD; there is **no dual-read**.
After ingest load ≥ ~0.80, ingest seals to sorted ovf and rolls. Legacy
full-size `scripthash.ovf.head` is removed on open. Existing main keys update
`value16` in place.

New stores: **header.head** = **single** open-address file (~96 MiB sparse at
2²² slots; overflow `header.head.gN`). Leftover 256-way `header.head/` is
**refused** — wipe `store/header.head` and `store/header.body` and reindex.
**scripthash** **64** shards, **tx.head** = **segmented** fixed **25-bit**
heads (`tx.head/meta` + open `NNNNNN` OA, sealed `NNNNNN.mphf|.fuse8`).
Capacity ends at **80% of head slots** (~26.8 M creates at 25-bit): seal
builds a value-assigned MPHF + **binary fuse8**, unlinks OA, then opens a new
segment. Idx 16 GiB soft-span does not cut `tx.head`. Open segment has **no** filter (always probed); sealed segments are
fuse-gated then one packed MPHF probe (`rel−1`). Legacy monolithic `tx.head` / `.new` /
`.resize` / `.overflow` are **refused** — reindex. Schema 17 populated indexes
versus this binary: [Schema upgrade](#schema-upgrade). Create height is a RAM fence (no
`tx_height` file; schema 16).
Dense Class A fk + segmented **`txout.idx` / `inwit.idx` / `spent.idx`**.
Class A is **split** (outs / ins+wit / sole-spender). Spends are schema-v5
annotations on **`spent.body`** (no `point.head`). Inputs store **`create_fk` +
vout** (soft `prev_txid` in RAM only).

**Memory rule:** Direct IBD writes durable segmented `tx.head.*` live and spend
annotations on confirm. Pin/SH/tweaks read **`txout` only**; annotate dirties
**`spent`**. Parent resolve uses parent cache + `tx.head` (open + fuse-gated
sealed). SH create dedupe is an **O(1) height watermark**; durable SH tables
bulk-load at tip as sorted files (ingest OA is the only large SH heap). Densify
is gated by body-queue soft depth — do not raise that depth without watching
RSS vs page cache. Working-set sizes:
[`SCHEMA.md`](./SCHEMA.md) (mainnet census) and [`docs/ibd-memory.md`](docs/ibd-memory.md).

## Schema upgrade

Live bytes: [`SCHEMA.md`](./SCHEMA.md) (`SCHEMA_VERSION = 20`). This section is
the operator copy-paste only — do not treat it as a second layout map.

Open **never silently wipes** a populated store. An older `store/meta` either
rewrites `meta` (payload-only) or **refuses** with a one-line message that
names the dirs. Corrupt files are **not** repaired in-process.

| Incoming `meta` | What this binary does |
|-----------------|------------------------|
| **20** | Open (SH is compact `BDZ3`). |
| **19** or **18**, empty `tx.head` and no `scripthash*` data | Rewrite `meta` to 20, then open. |
| **19** or **18**, occupied `tx.head` or any `scripthash*` | **Refuse.** Wipe `store/tx.head` and `store/scripthash*`, keep Class A, restart. |
| **17**, empty `tx.head` and no `scripthash*` data | Rewrite `meta` to 20, then open. |
| **17**, populated `tx.head` or any `scripthash*` | **Refuse.** Wipe those index dirs, keep Class A, restart. |
| Older than 17 with creates / leftover catalogs | **Refuse.** The error names files; often a full datadir wipe + IBD. Details: SCHEMA.md **13/14→17**, **15→17**, **16→17**. |

A **19 binary** refuses 20 `meta` (do not downgrade in place).

When the 20 index refuse fires, the log line is:

```text
schema 20 refuses schema-18/19 tx.head/scripthash; wipe store/tx.head and store/scripthash* then restart (Class A kept; tx.head rebuilds, SH rematerializes with --shindex)
```

Copy-paste (node stopped with SIGTERM):

```bash
DATADIR=/path/to/datadir
rm -rf "$DATADIR/store/tx.head" "$DATADIR/store/scripthash"*
```

Keep Class A (`txout` / `inwit` / `spent` + idx, `txid.body`, headers) and
Class C. Restart the same binary: `tx.head` rebuilds from Class A; with
`--shindex`, SH rematerializes. Do **not** `rm -rf store/`.

When the 17-index refuse fires, the log line is:

```text
schema 18 refuses schema-17 tx.head/scripthash; wipe store/tx.head and store/scripthash* then restart (Class A kept; indexes rebuild)
```

Copy-paste (node stopped with SIGTERM):

```bash
DATADIR=/path/to/datadir
rm -rf "$DATADIR/store/tx.head" "$DATADIR/store/scripthash"*
```

Keep Class A (`txout` / `inwit` / `spent` + idx, `txid.body`, headers) and
Class C. Restart the same binary: `tx.head` rebuilds from Class A; with
`--shindex`, SH rematerializes from runs / Class A. Do **not** `rm -rf store/`.

**Kill-9 / crash is not a schema upgrade.** Open follows
[`docs/crash-recovery.md`](docs/crash-recovery.md) (tip-as-commit, Class C
repair above tip). Prefer SIGTERM ([Resume / clean stop](#resume--clean-stop)).
A corrupt file still means wipe/reindex — not an in-process repair.

## Libre-relay-class policy (mempool + Electrum broadcast)

| Rule | Value |
|------|--------|
| Min relay | **0.1 sat/vB** (100 sat/kvB) |
| Dust | **not enforced** |
| Script templates | allow if consensus-valid (within weight/CPU) |
| RBF | **full RBF** (no BIP125 signaling required) |
| Annex | empty OK; non-empty only if first data byte after `0x50` is `0x00` |
| Cluster caps | 64 txs / 101 kWU |
| Eviction | worst linearization **chunk** when over weight budget |
| Fee estimate | **10-minute inclusion** (cluster-chunk frontier + confirm-memory floor); see [`docs/mempool-fee-estimation.md`](docs/mempool-fee-estimation.md) |
| Compaction | DEAD slots reclaimed when wasteful (auto after confirm removes) |
| Slot table | **131 072** initial records (grows by doubling to 1 048 576); free-slot ensure **before** append |

Policy lives in `rbitcoin-consensus::policy` and is **never** applied on block connect.

**Empty-headers lag — two different causes:**

| Symptom | Cause | Fix |
|---------|--------|-----|
| `known≈982k` while peers ~961k, absurd resume walk | False `prev_fk` / duplicate header edges | Prefer a **fresh datadir**; header rows are hash-unique on write |
| `tip=H` but tip **hash** is a short orphan sibling; peers ahead | Stale confirmed tip; most-work **explore + reorg** | Restart; expect reorg once bodies densify |
| Stuck on tip+1: `prevout already spent` / many re-rejects of same block | Orphan Class C (second Class A+C copy at tip height) | Fixed on open: complement `repair_class_c_above_tip` + confirmed-strong **membership** |

**Every open:** the node (1) revalidates the last **six** confirmed heights
(header `prev_fk`/hash chain, Class A range bounds, merkle from `txid.body`,
those six runs all-strong) and may **shrink tip** or clear a bad body, then
(2) one Class C complement repair (unstrong leftover 1s in fence holes / a
short suffix — not a minute-long walk of every create). Look for
`rbitcoin: class_c repair cleared=…` and `rbitcoin: tip revalidate …` on
stderr. That is intentional Core-style `checkblocks=6` + crash/race healing —
not a full reindex. Widespread mid-chain header graph poison still means a
clean datadir.

**Mempool recovery:** `{datadir}/mempool/` is a private sidecar (not Class A). If it
is damaged or an old 4k-slot table was left wedged, stop the node and delete that
directory — the next start recreates it empty and redownloads unconfirmed txs.
Do **not** wipe `store/` for mempool slot/full errors.

## P2P transport

- **BIP324 v2 only** — plaintext v1 peers disconnect (`peer does not speak BIP324 v2`).
- **Discovery** queries Core DNS seeds for `NETWORK|WITNESS|P2P_V2`
  (`x809.<seed>` first; the bare seed name only if that returns nothing).
  Learned `addr` / `addrv2` is ingested only when the row advertises `P2P_V2`
  (plus `NETWORK` or `NETWORK_LIMITED`). Dial ranking omits known-v1
  (`INCOMPATIBLE`) addresses while any better candidate remains. Seed host
  list lives in `dns_seeds()` (`crates/rbitcoin-net/src/seeds.rs`).
- Tx inv/getdata/tx relay is **off during IBD**; enabled in tip mode after catch-up.
- **BIP152 compact blocks v2:** `sendcmpct` high-bandwidth; mempool short-id fill +
  `getblocktxn` / `blocktxn`; full witness getdata fallback. We also **serve** `getblocktxn`.
- **BIP339 wtxidrelay:** sent when peer version ≥70016; mutual negotiation uses `MSG_WTX`.
- Session **ban score** (threshold 100) disconnects peers that spam bad compact payloads.
- Package accept: `ActiveMempool::accept_package` via RPC `submitpackage` or
  Esplora `POST /txs/package`. No P2P package command (BIP331 is not in
  rust-bitcoin 0.32).

## Scripthash index (`--shindex`)

Class B **scripthash** reverse index is **optional** (default **off**), analogous
in *operator spirit* to Core’s heavy reverse indexes — **not** the same as
Core `-txindex` (we always keep Class A + `tx.head` for by-txid lookup).

| Mode | Behavior |
|------|----------|
| **off (default)** | No SH run enqueue during IBD; no tip bulk materialize. Tip follow + mempool relay + JSON-RPC work without SH. |
| **on** (`--shindex` / `shindex=1`) | Direct IBD SH runs + tip bulk materialize; Electrum/Esplora may start when SH is tip-ready. |

**Electrum or Esplora without `--shindex` fails at process start** (clear config error).

Order-of-magnitude costs (mainnet-class SSD; not a warranty):

- **During IBD with shindex=1:** modest extra work (run stream); after IBD, bulk materialize is typically **tens of minutes to a few hours**.
- **Enable after tip already synced:** full recollect/materialize from Class A — **often multi-hour**; tip follow continues; Electrum waits until SH ready.
- **Disable later:** tables are **left on disk** (no automatic purge). Re-enable may rematerialize.

Tip-follow readiness is **independent** of SH materialize (`tip_follow_ready` ≠ `sh_tip_ready`).

### Abort / resume (tip materialize)

Keep **`store/scripthash.runs`**. SIGINT / SIGTERM mid-cold keeps every
**sealed** `scripthash.head/NN` (`scripthash.cold_progress`); restart with the
same `--datadir --shindex` packs **unsealed** shards only (holes stay). Do not
delete runs to “start over” unless you intend a full Class A recollect.

| Stop | What restart does |
|------|-------------------|
| SIGTERM / SIGINT mid materialize | Resume. Lowest unsealed shard is `next_shard`. Catalog runs stay. |
| Kill-9 mid pack | Same idea; unfinished shard work is redone. Open follows [`docs/crash-recovery.md`](docs/crash-recovery.md) (scripthash Direct). |
| Empty SH head + usable catalog | FullCold from runs. |
| Durable SH head + leftover runs | **Warm-only.** Do not wipe. |
| Corrupt SH (leftover live OA, mixed body, refuse line) | Wipe `store/scripthash*` only, keep Class A, rematerialize with `--shindex`. |

Electrum waits until SH is tip-ready. Do **not** `rm -rf store/` for an SH
abort. Force-rebuild sticky env (`RBITCOIN_SH_FORCE_REBUILD`) must never redo
multi-hour Class A work casually — [`docs/env-knobs.md`](docs/env-knobs.md).

## Silent payment tweaks (`--sptweaks`)

Optional **thin** BIP-352 index for Electrum `blockchain.tweaks.subscribe`
(Cake Wallet, [kiss-bdk](https://github.com/kkdao/kiss-bdk); client-side
scan). Default **off**. The method still exists when off (naive per-height
walk). Flag on = persist + serve-from-index. Stream shape and Sparrow/Frigate:
[`COMPAT.md`](./COMPAT.md) (Electrum surface).

**Not built during Direct IBD** (the write thread stays Class A + annotate).
After catch-up, **SH materialize first** (if `--shindex`), then a background
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
sequential on a 4k-tx 9p block; witness stays in `inwit`). Indexed serve does
**not** parent-peek (~40–80 blk/s vs ~1.5–3 naive on that VM).

Tip follow writes 65 B-class records from already-pinned parents when the
cursor is caught up. Reorg truncates with tip. Post-IBD backfill is a
**one-core** completion machine: `txout` wave, then `inwit`/parent `txout`
only for P2TR creates, secp on **idle** `rbtc-scripts-*` workers (block
scripts and mempool accept still win), then **batched** height-blob
+ idx writes (one body pwrite + one idx pwrite per consecutive group — not
per tx). On local SSD, mainnet `origin` (Taproot, 709632) → tip is typically
**about 1–2 hours** (~200–250 h/s through 2022, then tens of h/s once
P2TR/ordinals density rises). The old serial `get_tx_full` path was
~15–25 h/s (**several hours**). 9p / spinning rust longer. Kill-safe:
`next_height` is the last complete put. INFO every 10 s:
`sptweaks: backfill next=… tip=… rate=…/s remain=…`.

Cake Wallet’s scan isolate may still hardcode `electrs.cakewallet.com` even
after a successful probe — see `COMPAT.md`.

## Electrum

Internet-facing Electrum is supported as a **wallet-client backend** (Electrum,
Sparrow, similar): bind plain TCP (public or loopback), terminate **TLS at a
reverse proxy**, and rely on the node’s **app DoS limits** always being on. A
loopback-only bind is convenient with a local proxy, but it is **not** the
security model by itself.

**Requires `--shindex`.** Without it the node refuses to start.

`server.version[0]` is `rbitcoin-electrs <ver>` so Cake Wallet
`getNodeIsElectrs()` will probe silent-payment tweaks. Other tweaks clients
do not need that substring. We are **not** electrs — see `COMPAT.md`.

**Not a graphical explorer.** We serve clients that already know their
scripthashes / txids; we do **not** aim to back block-explorer search UIs.

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --shindex \
  --sptweaks \
  --electrum-listen 127.0.0.1:50001 \
  --log-level info
```

TLS is **not** built into the node. Terminate TLS at nginx, Caddy, HAProxy, etc.,
and proxy plain TCP to `--electrum-listen` (e.g. `127.0.0.1:50001` behind the
proxy, or a public bind if the proxy sits elsewhere and you accept that risk).

| Feature | Behavior |
|---------|----------|
| Banner | states **libre-relay-class** |
| Transport | plain TCP only (external TLS termination) |
| `transaction.broadcast` | mempool accept → P2P inv announce |
| Unconfirmed history/balance/mempool | from cluster mempool |
| `transaction.get` | chain then mempool fallback |
| `relayfee` / `estimatefee` / histogram | from Libre min + live mempool |
| Silent Payments tweaks | `blockchain.tweaks.subscribe` — with `--sptweaks` index: multi-height load (default ≤128 heights / ≤8192 eligible txs per wave) then per-height notifies, **one TCP flush per wave**. Class A join is **one sequential `txout` span** from first..=last eligible fk in the wave (not one body pread per eligible tx; `inwit` stays out). Pre-taproot heights are empty maps in waves of ≤1024 (no store). Without index / hole: naive per height (Class A + parent outs). **Not** request/response: JSON-RPC result is the **first** height (1-height probe `[0,1,false]` → `{"0": {}}`); further heights are notifications, then `{"message":"done"}`. `count` is honored through tip. `server.features.genesis_hash` is the chain check. `server.version[0]` contains `electrs` (Cake probe). On 9p-class IO expect slower than local disk. |

### API request log

`--api-log PATH` (or conf `api_log=PATH`) appends **one JSON line per Electrum, Esplora, and RPC call**:

```
{"ts":"…Z","surface":"electrum","peer":"192.168.88.20:51122","method":"blockchain.tweaks.subscribe","params":"[850000,8,false]","wall_ms":2410,"ok":true,"err":null}
```

`tail -f` that file. The same line is also emitted at **TRACE** as `api: …`
(so `--log-level trace` shows methods in `mainnet.log`; DEBUG stays usable
during a wallet/bench query storm). Params are truncated (~384 bytes) so
broadcast hex does not fill the disk.

Use this to see whether a client is hitting tweaks vs only scripthash history, and which calls take seconds.
`wall_ms` is the full handler (including JSON). Scripthash history / balance /
UTXO / Esplora address stats share one waved Class A + spend join on the
process `RBITCOIN_IO` session. `--log-level trace` emits
`sh_join: creates=… outs=… need=… pages_us=… class_a_us=… spends_us=…` when
that join exceeds 10 ms (`need=` is `cs` / `c` / `-`: create and/or spender
`txid.body`). That split is not an `ibd: perf` line and is not extra JSONL
fields. Esplora `/address/{addr}/utxo` status (`block_hash` / `block_time`)
comes from join height plus unique headers — not a per-coin `tx.head` probe.
Confirmed `/txs` uses join `tx_fk` (no second `tx.head`). `getblock` verbosity 1
lists `txid.body`. Esplora `/utxo` applies the same mempool overlay as Electrum
`listunspent`. `listunspent` loads `txid.body` only for unspent creates.
`sh_join` with a history `to_height` skips Class A expand for creates at or
past that exclusive bound. Electrum subscribe tip restatus intersects the SH
posting list with the new block's tx fks and prevout `create_fk`s; a miss
does not expand packed `txout`. Full status still runs on a hit. Each Electrum
TCP connection keeps one last-scripthash join (outs + spentness) until tip
height changes, so Casa `get_balance` → `get_history` → `listunspent` on the
same socket pays Class A once. Not a process-global cache. Esplora REST keeps
one last-scripthash join on the listener (HTTP is not session-oriented) so
Casa `/scripthash` → `/txs` → `/utxo` and `/txs/chain` pages reuse packed
outs until tip height changes. Concurrent different keys may replace the
slot. Esplora WS `block-transactions` uses the same posting-list tip probe
as Electrum subscribe (miss skips Class A).

Re-measure fat keys on the operator host (`rbitcoin-bench --suite casa
--passes 1 --warmup 1`). Do not treat agent-VM times as product numbers.

### App DoS floor (always on)

Shared [`ServeLimits`](crates/rbitcoin-electrum) defaults (also the future Esplora
floor). Excess connections are **rejected immediately** (no hang); oversize lines
and idle clients fail closed.

| Limit | Default | Role |
|-------|---------|------|
| Max connections | 256 | Concurrent Electrum TCP clients |
| Max request line | 1 MiB | One JSON-RPC line including `\n` |
| Idle timeout | 120 s | No complete request → disconnect |
| Max scripthash subs / conn | 1000 | Notify fan-out cap |
| Max broadcast hex | ~8 MiB | `transaction.broadcast` hex length |

Edge rate-limits, auth, and TLS cipher policy stay on the proxy. See
[`SECURITY.md`](./SECURITY.md).

## Client benchmark (Electrum / Esplora)

Optional crate `rbitcoin-bench` talks to **any** Electrum TCP or Esplora HTTP
server (rbitcoin, Fulcrum, electrs, ElectrumX, Blockstream electrs, …). It is
**not** in `default-members` and **not** in the musl product package.

```bash
# embedded corpus matching --suite (no --targets needed)
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite casa
cargo run -p rbitcoin-bench --features cli --release -- \
  --esplora http://127.0.0.1:3000 --suite casa --corpus hot
# or your own list: one scripthash hex or address per line
printf '%s\n' bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq > /tmp/sh.txt
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --targets /tmp/sh.txt --suite casa
# per-key CSV (casa/hot): heights, tx/utxo counts, warm times for each query
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite casa --out /tmp/casa.csv
# many concurrent small wallets (one OS thread in the bench process)
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite clients --clients 32
```

| `--suite` | What it measures |
|-----------|------------------|
| `casa` | Lopp/Casa 2020–2022: sequential `get_balance`, `get_history`, `listunspent` per key on one TCP connection (the node reuses that connection's last SH join). Discard `--warmup` (default 1), keep `--passes` (default 9), report p50/p95 and history-size buckets. |
| `sparrow` | Sparrow 2022 wallet load (`subscribe` batches of `--batch`, default 50) then refresh (`get_history` batches). `--fetch-txs` also pulls `blockchain.transaction.get`. Electrum only. |
| `hot` | Fat-history keys (one-shot history + UTXO). Use for high-fanout scripts. |
| `clients` | N concurrent Electrum TCP or Esplora HTTP sessions (`--clients`, default 8) on **one OS thread**, each reloading a small wallet sliced from `--corpus` (default `sparrow`). Wallet sizes mix 8/16/32 keys unless `--wallet-keys N`. Keys that would push a wallet over `--max-txs` (1000) or `--max-utxos` (100) are dropped so megakeys do not dominate. Primary sample is `wallet_load` wall time under concurrency. |

| `--corpus` | Packed-in keys (default = `--suite`; `clients` uses `sparrow`) |
|------------|--------------------------------------|
| `hot` | Public fat keys: P2A `bc1pfeessrawgf` (portlandhodl electrs stress), genesis P2PKH, burns, high-tx exchange/mining addresses. |
| `casa` | ~4k unique output scripts from **77 heights spaced genesis→tip** (plus segwit / taproot / Casa-window pins) on a synced rbitcoin store, plus a few known mid-history addresses. Not Casa’s 103k dump from blocks 599900–600100 — that 200-block window makes height-list servers (electrs) look artificially fast because every key hits the same few blocks. |
| `sparrow` | 3000 keys, same spread-height source (Sparrow’s published run used a ~3000-address wallet). |

`--targets FILE` overrides the embedded list. Same corpus against two servers is
the comparison. First pass is usually cache-cold; Casa’s published numbers drop
that pass. Sequential by default (Casa did not test multi-thread load). `--suite clients`
is concurrent connections multiplexed on the bench’s current-thread runtime
(light next to a node on the same host; raise `--clients` to add sessions, not
threads). TLS is the reverse proxy’s job — point the client at plain
`127.0.0.1`.

Progress goes to **stderr** (stdout stays the p50/p95 table): about one line
per 5% plus at most one extra line every 15s, with elapsed and ETA. Sparrow
relabels load → refresh (→ txs if `--fetch-txs`).

`--out FILE` (casa/hot) writes one CSV row per key: `oldest_tx` / `newest_tx`
(confirmed history heights), `oldest_utxo` / `newest_utxo`, `txs`, `utxos`,
then `get_balance_us_1..N`, `get_history_us_1..N`, `listunspent_us_1..N` for
the counted warm passes (default N=9; warmup omitted). Blank height cells mean
no confirmed item. Esplora `oldest_tx`/`newest_tx` are from the returned
`/txs` page, while `txs` uses `chain_stats.tx_count` when present. For
`--suite clients`, `--out` is one row per connection:
`client,n_keys,txs,utxos,wallet_load_us_1..N`.

## Esplora REST

Blockstream-**compatible** **plain HTTP** API for **wallet clients and APIs**
(exact address/scripthash, tx/block by id, broadcast)—**not** a graphical
block-explorer backend. Same internet-facing model as Electrum: app DoS limits
always on; terminate TLS at a reverse proxy.

**Requires `--shindex`.** Without it the node refuses to start.

**Explicit non-goals:** explorer search/`address-prefix`, Liquid, mining
templates, mempool.space-style catalogue UI APIs.

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --shindex \
  --esplora-listen 127.0.0.1:3000 \
  --log-level info
```

Conf: `shindex=1` and `esplora_listen=127.0.0.1:3000`. Default is **disabled**.

## Core-class JSON-RPC

Optional HTTP JSON-RPC subset (default **off**). Auth: cookie file under
`{datadir}/.cookie` or `--rpcuser`/`--rpcpassword`. Does **not** require
`--shindex` (chain/mempool/rawtx by id only). See [`docs/rpc.md`](./docs/rpc.md)
and [`COMPAT.md`](./COMPAT.md).

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --rpc-listen 127.0.0.1:8332 \
  --log-level info
# same datadir cookie:
rbitcoin-cli --datadir ./datadir-mainnet getblockcount
```

| Feature | Behavior |
|---------|----------|
| Transport | plain HTTP (axum + tower body/concurrency/timeout from `ServeLimits`) |
| WebSocket | `/v1/ws` (+ `/ws`); **separate** WS connection cap (default 64) so upgrades do not starve REST |
| Tip / blocks | tip height/hash; `/blocks[/:start_height]` (10 summaries); `/block/:hash` JSON + **raw** + status |
| Tx | full JSON, hex, **raw**, status, Electrum merkle-proof, **BIP37 merkleblock-proof**, outspends |
| Address / scripthash | chain_stats, utxo, history pages (25 + `last_seen_txid`), `/txs/mempool`; complete after SH tip finalize |
| Mempool | `/mempool`, `/mempool/txids`, `/mempool/recent`, `/fee-estimates`; `POST /tx` and **`POST /txs/package`** when hub open |
| Without mempool | mempool routes empty/safe; POST broadcast → **503**; WS track still upgrades but mempool pushes need hub |
| Unknown / non-goal | **404** (explorer-only APIs e.g. address-prefix; Liquid; mining template) |

**Large responses:** `GET /block/:hash/raw` may be multi‑MB; concurrency/timeout from `ServeLimits` still apply.  
**Package broadcast:** body is a JSON array of tx hex (max 25); uses the same libre-relay mempool policy as single `POST /tx`.

DoS knobs share Electrum’s `ServeLimits` defaults (256 conns, 1 MiB body, 120 s timeout).
WebSocket extras (defaults): max 64 concurrent `/v1/ws` sockets, 64 KiB client frames,
64 tracked addresses and 64 tracked txids per connection. See [`COMPAT.md`](./COMPAT.md)
“Esplora WebSocket”.

### Reverse proxy (TLS + WebSocket upgrade)

Terminate TLS and forward REST **and** WebSocket to the same upstream. Example nginx:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:3000/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 3600s;
}
```

Clients then use `wss://host/api/v1/ws` (proxy strips `/api`). Caddy: `reverse_proxy`
with default HTTP/1.1 upgrade support to the same listen.

## Signet lab

```bash
mkdir -p ./datadir-signet
./target/release/rbitcoin-node \
  --datadir ./datadir-signet \
  --network signet \
  --listen 0.0.0.0:38333 \
  --max-outbound 16 \
  --log-level info
```

### Custom Signet

A custom Signet derives its P2P message magic from the challenge. Default
Signet seeds are not used, so provide at least one peer with `--connect`.
Use a dedicated datadir for each challenge.

```bash
mkdir -p ./datadir-custom-signet
./target/release/rbitcoin-node \
  --datadir ./datadir-custom-signet \
  --network signet \
  --signetchallenge 51 \
  --signetblocktime 60 \
  --connect 192.0.2.1:38333 \
  --listen 0.0.0.0:38333 \
  --milestone 0 \
  --log-level info
```

The equivalent conf-file keys are `signetchallenge` and `signetblocktime`.
Replace the illustrative `OP_TRUE` challenge and documentation-only peer with
the parameters supplied by the custom Signet operator.

### Resume / clean stop

Same `--datadir` resumes tip from the relational archive.

```bash
kill <pid>   # SIGTERM — flush store + mempool, exit 0
```

Prefer SIGTERM over `kill -9` (last uncommitted mempool batch may be lost on hard kill).

## Mainnet experimental

```bash
mkdir -p ./datadir-mainnet
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --listen 0.0.0.0:8333 \
  --max-outbound 16 \
  --mempool-size-mb 300 \
  --log-level info
```

Full script validation (slow, used for consensus parity labs):

```bash
  --milestone 0
```

### Before trusting mainnet

- [ ] Signet (or large range) to tip; restart resume
- [ ] Mainnet tip follow without corruption / OOM
- [ ] Post-milestone or `--milestone 0` script path exercised
- [ ] Disk headroom for full Class A archive
- [ ] Mempool file growth bounded under load (compaction + eviction)
- [ ] Electrum TCP wallet smoke (subscribe, broadcast, fees; TLS via proxy if needed)
- [ ] Peer diversity and reorg behavior under load

## 16 GiB RAM / sluggish disk (mainnet)

Full-validation IBD will be **disk-bound** and can freeze the UI if `datadir` shares
the desktop disk. Prefer a dedicated volume and modest memory knobs:

```bash
export RAYON_NUM_THREADS=4
# Prefer --milestone 840000 for catch-up, then reindex/full validate later if needed
nice -n 10 ionice -c 3 ./target/release/rbitcoin-node \
  --datadir /mnt/dedicated/datadir-mainnet \
  --network mainnet \
  --max-outbound 12 \
  --mempool-size-mb 200 \
  --log-level info
```

Hash-head in-place rehash is gone. An undersized leftover `header.head` may
be rewritten once at open via `header.head.grow` then rename
(`store: header.head open-grow`). An empty target-sized `header.head` with a
non-empty `header.body` is refused (wipe those files and reindex).

## Consensus notes (historical mainnet)

Full validation has fixed several pre-soft-fork script edges:

| Height / class | Issue |
|----------------|--------|
| High-S ECDSA | normalize before verify (never consensus-fail) |
| Hashtype 0 | raw byte, not `from_consensus` → ALL |
| Lax DER pre-BIP66 | always `from_der_lax`; BIP66 is encoding check |
| High-bit S, `from_der`≠lax | never prefer strict-first |
| CODESEPARATOR in scriptSig | full EvalScript(scriptSig) for bare |
| Pre-BIP16 P2SH shape | bare HASH160/EQUAL; Core BIP16Exception @ 170060 |

In-memory **confirm reject blacklist** clears only on process restart after a binary fix.
