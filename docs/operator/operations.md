# Node operations

## First hour (regtest)

One loop: mine a block, one Electrum RPC, one Esplora GET. This is **regtest**,
not validated mainnet (default mainnet `--milestone` skips historical scripts).
Signet/mainnet: [`docs/experimental-mainnet.md`](../../docs/experimental-mainnet.md).

Electrum and Esplora **start without `--sh-index`**. Address/scripthash
history needs it (fail closed otherwise). JSON-RPC is only there so
`rbitcoin-cli` can mine.

```bash
./target/release/rbitcoin-node \
  --datadir /tmp/rb-hour \
  --network regtest \
  --no-seeds \
  --sh-index \
  --rpc \
  --electrum-listen \
  --esplora-listen
```

In another terminal:

```bash
./target/release/rbitcoin-cli --datadir /tmp/rb-hour --network regtest \
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
sections below and [`COMPAT.md`](../../COMPAT.md).

## CLI (operator-first)

Routine knobs are **CLI / conf**, not required env vars. `rbitcoin-node` flags are
kebab-case (`--max-inbound`). Conf keys are snake_case (`max_inbound=`).
RPC auth is a unix socket (`--rpc`) or Bearer `{datadir}/rpc.token` (TCP).
There is no `--rpcuser` / `--rpcpassword`.
Core names (`-maxconnections`, `-whitelist`, `-blocksonly`,
`-minimumchainwork`, …) are translated by the functional `bitcoind` shim only
([`docs/core-functional.md`](docs/core-functional.md)).

Clean smoke:

```bash
./target/release/rbitcoin-node --smoke --datadir /tmp/rb-smoke --network regtest
```

| Flag | Conf | Default |
|------|------|---------|
| `--datadir PATH` | `datadir=` | cwd `datadir` (`./datadir` Unix, `.\datadir` Windows) |
| `--datadir-cold PATH` | `datadir_cold=` | unset — Class A `seqsigwit.body` / `seqsigwit.loc` under `{PATH}/store`; everything else stays in `--datadir` |
| `--network NET` | `network=` | `mainnet` |
| `--signet-challenge HEX` | `signet_challenge=` | default global Signet challenge |
| `--signet-block-time SECS` | `signet_block_time=` | 600; requires a custom challenge |
| `--listen ADDR` | `listen=` | bind later default port |
| `--no-listen` / `--listen=0` | `listen=0` / `no_listen=` | bind a loopback default; **off** = no clearnet P2P socket |
| `--listen-onion` | `listen_onion=` | **off** — loopback P2P + `ADD_ONION` (`{datadir}/onion/p2p.priv`); needs `--tor-control` and `--max-inbound` > 0 |
| `--no-discover` | `no_discover=` | discover **on**; flag off = no home-IP self-announce; P2P/wallet onions still listed |
| `--only-net NET` | `only_net=` | all nets; repeatable `ipv4` / `ipv6` / `onion` / `i2p` / `cjdns` |
| `--cjdns-reachable` | `cjdns_reachable=` | **off** — `fc00::/8` is unroutable until set; `--only-net=cjdns` requires it |
| `--connect ADDR` | `connect=` (repeatable) | seeds; `IP:port`, Tor v3 `.onion:port`, or `{52}.b32.i2p:port` |
| `--proxy HOST:PORT` | `proxy=` | unset — SOCKS5 for all P2P outbound |
| `--onion HOST:PORT` | `onion=` | unset — SOCKS5 for onion destinations |
| `--proxy-randomize[=0\|1]` | `proxy_randomize=` | **on** — fresh SOCKS username per peer (Tor circuit isolation) |
| `--tor-control [HOST:PORT]` | `tor_control=` | unset — no control connection; omit ADDR → `127.0.0.1:9051` |
| `--tor-control-cookie PATH` | `tor_control_cookie=` | `/run/tor/control.authcookie` when `--tor-control` is set and password is unset |
| `--tor-control-password PASS` | `tor_control_password=` | unset — cookie AUTH unless set |
| `--i2p-sam [HOST:PORT]` | `i2p_sam=` | unset — no SAM; omit ADDR → `127.0.0.1:7656` |
| `--i2p-accept-incoming` | `i2p_accept_incoming=` | **off** — persist `{datadir}/i2p/p2p.priv` and STREAM FORWARD to the P2P bind |
| `--milestone HEIGHT` | `milestone=` | mainnet anchor at 840000; signet 0; explicit height is height-only |
| `--max-outbound N` | `max_outbound=` | 16 live download peers |
| `--max-inbound N` | `max_inbound=` | 125 inbound sessions; **0** = no inbound slots (outbound-only) |
| `--mempool-size-mb N` | `mempool_size_mb=` | ~300 MiB weight |
| `--conf FILE` | | none |
| `--log-level LEVEL` | `log_level=` | `info` |
| `--api-log PATH` | `api_log=` | off — JSONL of Electrum / Esplora / RPC calls |
| `--asmap PATH` | `asmap=` | unset — try `{datadir}/ip_asn.dat` if present; else prefix groups |
| `--no-seeds` | `no_seeds=` | seeds on |
| `--sh-index` | `sh_index=` | **off** — Class B scripthash (address/history; Electrum/Esplora start without it) |
| `--block-filter-index` | `block_filter_index=` | **off** — BIP158 basic filters. Independent of `--sh-index`. IBD does not build them; they are sealed through the tip after catch-up (index materialize), then per block. `NODE_COMPACT_FILTERS` is advertised while the flag is on. `getblockfilter`, `/rest/blockfilter/`, and P2P serve heights the watermark covers; a stop past the watermark is silence |
| `--prune-seqsigwit` | `prune_seqsigwit=` | **off** — unpruned reads `seqsigwit.body`. On: refuse wire reconstruct below tip−288 **heights**, advertise `NETWORK_LIMITED`, and keep those heights as `store/seqsigwit.window/{height}.bin` plus a RAM cache |
| `--prune-seqsigwit-ram-threshold-bytes N` | `prune_seqsigwit_ram_threshold_bytes=` | `268435456` (256 MiB). `0` keeps nothing in RAM: every height, including tiny IBD blocks, is read from its file |
| `--max-sh-creates N` | `max_sh_creates=` | **10000** — unpaged SH join above N is refused (503 / JSON-RPC error). **0** is unlimited. A request that names a page still returns that page. |
| `--sp-tweaks` | `sp_tweaks=` | **off** — thin BIP-352 tweak index (`sp_tweaks.*`) |
| `--sp-tweaks-dust SATS` | `sp_tweaks_dust=` | **1000** — omit served P2TR outs with `value <= SATS` (`0` = serve all; **546** matches Cake electrs) |
| `--electrum-listen [ADDR]` | `electrum_listen=` | disabled; omit ADDR → `127.0.0.1:50001`. Address/scripthash methods need `--sh-index` |
| `--esplora-listen [ADDR\|PATH]` | `esplora_listen=` | disabled (Esplora REST); omit ADDR → `127.0.0.1:3000`; a filesystem path is unix HTTP (mode **0660**, dummy `Host: api` is fine). Address/scripthash methods need `--sh-index` |
| `--esplora-onion[=0\|1]` | `esplora_onion=` | **on** — `ADD_ONION` for Esplora when `--tor-control` is set |
| `--esplora-block-template` | `esplora_block_template=` | **off** — `GET /block-template` is 404; on = GBT JSON (same as RPC template mode) |
| `--rpc` | `rpc=` | **off** — unix JSON-RPC `{datadir}/rpc.sock` (mode 0600) |
| `--rpc-listen [ADDR]` | `rpc_listen=` | disabled — implies `--rpc`; omit ADDR → `127.0.0.1` and Core-matching RPC port |
| `--rpc-token-file PATH` | `rpc_token_file=` | `{datadir}/rpc.token` (CSPRNG hex; TCP Bearer) |
| `--rpc-work-queue N` | `rpc_work_queue=` | **16** in-flight HTTP RPC (Core `-rpcworkqueue`). One POST is one slot (array batches still run). Full permit is HTTP **503** `Work queue depth exceeded`. **0** is the default queue of 16. |
| `--min-relay-tx-fee BTC` | `min_relay_tx_fee=` | unset — Libre default 100 sat/kvB; `0` = no floor; garbage/negatives fail start |
| `--mempool-expiry HOURS` | `mempool_expiry=` | unset — hub default; min 1 |
| `--blocks-only` | `blocks_only=` | off |
| `--prefill-compact[=0\|1]` | `prefill_compact=` | **on** — extra BIP152 compact prefills (10 KiB cap); `=0` disables |
| `--persist-mempool[=0\|1]` | `persist_mempool=` | on |
| `--trusted` | `trusted=` | off — inbound is not evicted/banned |
| `--always-relay` | `always_relay=` | off — always announce inbound txs |
| `--relay` | `relay=` | off — permit tx relay to inbound while `--blocks-only` |
| `--net-permission SPEC` | `net_permission=` | empty — repeatable CIDR grant (`noban@1.2.3.4`, `noban@::1`, `noban@2001:db8::/32`, bare IP, …) |
| `--net-permission-bind SPEC` | `net_permission_bind=` | empty — repeatable bind grant (`noban@127.0.0.1:8333`) |
| `--net-permission-relay[=0\|1]` | `net_permission_relay=` | **on** — implicit relay on a bare CIDR grant |
| `--net-permission-force-relay[=0\|1]` | `net_permission_force_relay=` | **off** — implicit forcerelay on a bare CIDR grant |
| `--limit-cluster-count N` | `limit_cluster_count=` | unset — hub default |
| `--limit-cluster-size KVB` | `limit_cluster_size=` | unset — hub default |
| `--peer-timeout SECS` | `peer_timeout=` | unset — net default; `0` is InitError |
| `--external-ip IP` | `external_ip=` | empty — `getnetworkinfo.localaddresses` |
| `--seed-node HOST` | `seed_node=` | extra seeds (repeatable) |
| `--mock-time UNIX` | `mock_time=` | unset — wall clock; `0` allowed |
| `--max-tip-age SECS` | `max_tip_age=` | unset — hub relay-inhibited age (default 24h) |
| `--block-version N` | `block_version=` | unset — generate/template version overlay |
| `--block-min-tx-fee BTC` | `block_min_tx_fee=` | unset — template min tx fee; garbage/negatives fail start |
| `--bytes-per-sigop N` | `bytes_per_sigop=` | 20 — policy size is `max(weight, sigops*N)/4` for feerate; `0` disables |
| `--block-reserved-sigops N` | `block_reserved_sigops=` | 400 — sigop budget held for coinbase/template overhead; admission and template selection use the same strict limit; range 0–80000 |
| `--alert-notify CMD` | `alert_notify=` | unset — `%s` = warning; fires once |
| `--startup-notify CMD` | `startup_notify=` | unset |
| `--test-activation-height name@HEIGHT` | `test_activation_height=` | empty — buried deployment overlay |
| `--min-chain-work HEX` | `min_chain_work=` | unset — densify/relay work floor |
| `--check-blocks N` | `check_blocks=` | 6; `0` / negative = whole chain |
| `--ua-comment STR` | `ua_comment=` | empty — BIP14 subversion |
| `--max-run-secs N` | `max_run_secs=` | unset — process exit after N seconds |
| `--inhibit-suspend` | `inhibit_suspend=` | off |

Conf file: simple `key=value` lines (`#` comments). CLI overrides conf. Example:

```
network=signet
max_inbound=64
mempool_size_mb=100
```

### P2P via system Tor SOCKS

`--proxy 127.0.0.1:9050` sends every P2P outbound through SOCKS5 CONNECT
(system `tor`, not Arti). DNS seeds are not resolved locally on that path —
pass `--connect ADDR` (or reuse a `peers` file). `--proxy-randomize` (default
on) uses a fresh SOCKS username per peer so Tor isolates circuits.
`--proxy` or `--onion` also turns on **isolated local-tx broadcast**:
`sendrawtransaction`, Electrum `transaction.broadcast`, and Esplora
`POST /tx` (and packages) are not INV'd on standing peers. After mempool
accept the node opens a short-lived SOCKS circuit (fresh isolation
credentials), BIP324-handshakes one or two AddrMan peers (onion first),
sends `tx`, and disconnects. This is **not** Dandelion++. If that
one-shot fails, the tx stays in the mempool and is still not INV'd;
confirmation can still arrive in a block.
`--onion HOST:PORT` stores a separate SOCKS endpoint for onion destinations.
`--only-net onion` (repeatable with `ipv4`/`ipv6`/`i2p`/`cjdns`) filters dial and learn;
onion requires `--proxy` or `--onion`. `--connect foo.onion:8333` is a start
error when the v3 checksum is invalid. The peers file is `rbitcoin-peers-v2`
(v1 IPv4/IPv6 still loads).

`--listen=0` / `--no-listen` starts without a P2P TCP bind (no ISP port
forward). `--listen-onion` still binds **127.0.0.1** (ephemeral port) and
`ADD_ONION`s the network default P2P port (8333 / signet 38333 / …) to
that loopback (`{datadir}/onion/p2p.priv`, 0600). Needs `--tor-control`
and `--max-inbound` > 0. `--no-discover` still gossips that onion via
`addrv2` and lists it in `getnetworkinfo.localaddresses`; it does not
gossip `--external-ip`. `--max-inbound 0` refuses `--listen-onion`.
`--max-inbound 0` refuses inbound slots. `--no-discover` does not
self-announce even when `--external-ip` is set. A later onion inbound bind
does not require a public clearnet listen.

`--tor-control [HOST:PORT]` talks to **system tor** (SAFECOOKIE/COOKIE or password). Omit
ADDR for `127.0.0.1:9051`. Failed AUTH is a start error. Unset: no control
socket. With `--electrum-listen`, the node `ADD_ONION`s that TCP port to
`127.0.0.1:<bound>` and logs `….onion:port`. The private key is
`{datadir}/onion/electrum.priv` (0600). `server.features.hosts` is
`{ "<id>.onion": { "tcp_port": N } }` with no `ssl_port`. With
`--esplora-listen`, the same control port `ADD_ONION`s Esplora (`{datadir}/onion/esplora.priv`);
REST is on that TCP port (`http://….onion:<port>`). `--esplora-onion=0`
skips Esplora HS. `getnetworkinfo.localaddresses` lists those onion hostnames
even with `--no-discover`. Sparrow: `tcp://<id>.onion:50001` (plain TCP; no
in-binary TLS). JSON-RPC stays off the onion (`rpc.sock` / `--rpc-listen` only).
Cookie path differs by distro; pass `--tor-control-cookie` rather than globbing.

`--i2p-sam [HOST:PORT]` talks to **system i2pd** SAM v3 (not SOCKS, not Arti).
Omit ADDR for `127.0.0.1:7656`. Failed HELLO / `SESSION CREATE` is a start
error. Unset: I2P rows may still load from `peers` v2 but are not dialed.
`--only-net i2p` without `--i2p-sam` is a start error. `--i2p-accept-incoming`
creates a persistent local destination (`{datadir}/i2p/p2p.priv`, 0600) and
`STREAM FORWARD`s to the P2P bind. That destination is published as
`{52}.b32.i2p:0` (SAM 3.1 has no ports; Core refuses any other I2P port)
on `getnetworkinfo.localaddresses` and in addrv2, including with
`--no-discover`. With `--listen=0` that is a start error
unless `--listen-onion` provides a loopback accept. NixOS:
`services.rbitcoin.i2p.sam` / `i2p.acceptIncoming`; the unit `After`/`Wants`
`i2pd.service` when SAM is set. Do not start i2pd from this module.

`--cjdns-reachable` treats BIP155 `fc00::/8` as the kernel CJDNS overlay: dial
with ordinary TCP (OS routing), advertise a `--listen` on that IPv6, keep
tagged rows in `peers` v2. Off (default): do not dial CJDNS; do not treat
`fc00::/8` as advertisable. `--only-net=cjdns` without the flag is a start
error. `--listen [fc00:…]:port` binds that address when the OS has it; no
cjdns daemon in-process and no TUN in CI. NixOS: `cjdns.reachable`;
`After`/`Wants` `cjdns.service`. Do not start a cjdns router from this module.

`--datadir` holds the node root (`store/`, `mempool/`, `peers`, `rpc.token`, `rpc.sock`).
Omit `--datadir-cold` and cold files live there too. Set it to put the large
rarely-read Class A **seqsigwit** stem (`seqsigwit.body` + `seqsigwit.loc`, ~486 GiB + loc
on mainnet) on another volume. Pin / spend-annotate / Electrum / tweaks do not
read seqsigwit; reconstruct / `getrawtransaction` / block serve do.

```
--datadir /mnt/nvme/rbtc --datadir-cold /mnt/hdd/rbtc-cold
# hot:  /mnt/nvme/rbtc/store/txout.body  (and the rest)
# cold: /mnt/hdd/rbtc-cold/store/seqsigwit.body
#       /mnt/hdd/rbtc-cold/store/seqsigwit.loc
```

A hot-store sidecar `seqsigwit.reloc` records the split. Opening without
`--datadir-cold` then refuses. Do not leave `seqsigwit.*` in both places. Moving an
existing datadir is operator `mv` (or copy+remove cross-device):

```
mkdir -p /mnt/hdd/rbtc-cold/store
mv /mnt/nvme/rbtc/store/seqsigwit.body /mnt/nvme/rbtc/store/seqsigwit.loc /mnt/nvme/rbtc/store/seqsigwit.off /mnt/nvme/rbtc/store/seqsigwit.loc.ovf /mnt/hdd/rbtc-cold/store/
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

After IBD, each accepted tip extension logs one **info** line:

```
tip: best=<hash> height=<n> version=<v> tx=<n> date=<unix>
```

Emitted from the tip-follow / wire accept path (`ChainHub::connect_at`). IBD bulk
confirm does **not** spam this line per block — use the periodic IBD status below.
Core functional tests still grep `UpdateTip: …` via the debug.log map
([`docs/core-functional.md`](docs/core-functional.md)).

### Tip-follow status lines (after catch-up + tip SH ready)

| Line | Level | Use |
|------|-------|-----|
| `tip: perf` | DEBUG | Every ~5s: follow peers, blocks this window, mempool accept/reject + wall µs, inv/getdata/announce, Esplora/Electrum req counts + avg/max µs, historical block `serve n= bytes= tx= avg_us= max_us=` |
| `tip: accept` | INFO | Per accepted tip block: wall/load/script/class_a/class_c/SH plus lookup/struct/drain/mp_strip/other (not emitted on reject) |
| `tip: best=` | INFO | New best hash/height after connect |
| `cmpct reconstruct` | INFO | Per compact reconstruct: fill sources (`prefill`/`mempool`/`extra`/`orphan`) and `fetched=` `blocktxn` count/bytes. `fetched=0/0` means no getblocktxn round-trip. Getdata fallback: `getdata missing=` |
| `node: tip=…` | DEBUG | Same height change plus `follow_live` (use `tip: best=` at info) |
| `p2p: getdata wtx` | TRACE | One line per peer `MSG_WTX` getdata (counts are on `tip: perf`) |
| `p2p: received tx` | TRACE | One inbound tx |
| `p2p: headers sync` | INFO | Headers path that meets min-work (or a noban peer) |
| `p2p: ignore low-work headers` | INFO | Headers announcement below `--min-chain-work` |
| `p2p: header … missing pow proof` | INFO | Unrequested header without anti-DoS POW |
| `p2p: accept dropped … (prev not found)` | INFO | Unrequested block whose parent is unknown |
| `p2p: initial getheaders` | INFO | First getheaders after connect |
| `p2p: headers sync timeout` | INFO | Headers-sync peer stalled (`disconnect` or `keep`) |
| `p2p: session … closed` | DEBUG | Clean session end. Unexpected end stays **WARN** `p2p: session … ended` |

Requires **tip mode** (`node: catch-up complete … tip tracking`). During IBD use `ibd: progress` at INFO; enable `ibd: perf` / `ibd: sizes` / `tip: perf` with `--log-level debug` (or conf / `RBITCOIN_LOG=debug`).

### IBD status lines (every ~5s)

| Line | Level | Use |
|------|-------|-----|
| `ibd: progress` | INFO | Tip rate, `loadq`/`scriptq`/`writeq`, `txs=` (Class A / `tx.idx` count), horizon, tip ETA, **`bq soft=n/win RAM=`** (in-RAM body queue; soft densify: under ~100 MiB free ahead, over that only ~1 min confirm window, at/over 1 GiB assign-stop holes within that window and not past fetched_hi) |
| `ibd: perf` | DEBUG | Inflight + **`bq soft= RAM=`**; **`load=`** is pin+assemble only. **`load_thr pack/stamp/pin/asm/prune`** is the load OS thread. **`stamp=`** nests **`pack=`** (plan HashMap) vs **`head=`** (leftover TipOnly; IBD skeleton keeps this ~0). **`script=`** is verify ns (`jobs=` / `skip=`); recv/send are wait. **`pin_txid=`** is skeleton hits vs leftover `tx.head` |
| `ibd: sizes` | DEBUG | RSS + work path + **`bq soft=` / `RAM=`** + **conf_plans** + confirm pipe |
| `ibd: perf_dbg` | DEBUG | µs/blk load/write, pin detail, **plan_batch** (`us/pin_txid` vs `probe/idx/body us/key`) + **class_a commit** |

Default INFO is `ibd: progress` only. `--log-level debug` adds perf / sizes / perf_dbg from the same sample. Ghost columns from deleted paths (wave-fill stubs, Direct SH head RMW) are omitted from both formatters. Pipeline roles: [`docs/concurrency.md`](docs/concurrency.md). Head files: [`docs/heads.md`](docs/heads.md).

`pin_txid%` is stamp `txid→create_fk` from the load-batch skeleton vs leftover `tx.head` (IBD skeleton path should stay at 100%). `pin_hit%` is load outs adopt/plan reuse — this-window range-fills are `pin_new` only.

**Tip hole / peer hygiene:** `hole=` on the progress line is the fetch gap from
tip+1 to the next in-hand body (confirmed, still on the BQ, or already taken
onto loadq). Peer speed is one EWMA of all received bytes while that peer has
block getdata in flight. Tip+1 getdata races up to 4 peers ranked by expected
drain time (`(queue+1)/EWMA`), not by inflight count. Later contiguous holes
in that gap get one racer until tip+1 is in hand. A hole owner still serving
other getdata (densify FIFO) is dropped from that hash so a peer that can start
the hole can race; a hole owner with no qualifying rx is dropped when a sibling
is pulling; an aged solo owner is dropped when another peer exists. When
`hole=` is 0, at most one extra racer is added on the first later gap in the
32-window, and only if that owner is missing, aged ≥30s, or ≤ pack-median/4.
Densify default is 8 in-flight hashes per peer (none while a tip hole is open,
so getdata queues can drain for tip+1);
16 only for an EWMA outlier at ≥ 2× pack median. WARN
`ibd: peer[…] stalled` is 30s without qualifying rx (≥64 KiB stream or a
block / decode-fail / NotFound event) after work start. WARN
`ibd: peer[…] relative-slow` is a quarter-median outlier (cluster gate keeps a
uniformly slow pack). Slow or constrained uplinks: [Slow / constrained uplink
(IBD)](#slow--constrained-uplink-ibd).

**Create pins:** pipeline-local only (`batch_pin` / `BatchParents`). No process pin FIFO. Header plans via ConfirmParentCache. Just-confirmed **identity + full create outs** stay on in-flight until a later lookup wave snapshots drain+fence past the pack height and load finishes that wave's last in-flight read. Not a coins cache.

**Archive `tx.head` split (perf_dbg):** `plan_batch … head_rd=` is parent
**read** resolve (`get_fk_by_txid_batch`, with `probe` / `idx` / `body` subtimers).
`class_a_commit … head=` is create **insert** (`head_insert_many`). Pipeline pins stay on the plan (`batch_pin`); no process denserels seed.

**Archive head resolve:** streaming — **FdOnly** page-coalesced head probe +
**FdOnly** `create.loc` + **`txid.body`** identity via **io_uring or pread**
(deepest-cand-first).
**Class A `txout` / `seqsigwit` / `spent` + `create.loc` / `seqsigwit.loc`, `tx.head`, header head,
SH head/body, and spenders are fd pread/pwrite**.
Full modality matrix: [`docs/io-modality.md`](docs/io-modality.md).

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
| `tip=H` but tip **hash** is a short orphan sibling; peers ahead | Stale confirmed tip; most-work **explore + reorg** | Restart (invalid marks are process-local). v0.6.0: compact reconstruct could `accept` a merkle-mutated body and cache the header `BLOCK_FAILED`. Current builds merkle-check before `Ok` (`getdata`) and do not cache that hash invalid. After upgrade, reorg once bodies densify. |
| Stuck on tip+1: `prevout already spent` / many re-rejects of same block | Orphan Class C (second Class A+C copy at tip height) | Fixed on open: complement `repair_class_c_above_tip` + confirmed-strong **membership** |

**Every open:** the node (1) revalidates the last **N** confirmed heights
(`--check-blocks`, default **six**: header `prev_fk`/hash chain, Class A range
bounds, merkle from `txid.body`, those N runs all-strong; `0` walks from
genesis) and may **shrink tip** or clear a bad body, then
(2) one Class C complement repair (unstrong leftover 1s in fence holes / a
short suffix — not a minute-long walk of every create). Look for
`rbitcoin: class_c repair cleared=…` and `rbitcoin: tip revalidate …` on
stderr. That is intentional `--check-blocks` + crash/race healing —
not a full reindex. Widespread mid-chain header graph poison still means a
clean datadir.

**Mempool recovery:** `{datadir}/mempool/` is a private sidecar (not Class A),
schema **2**. Leftover schema **1** (pre-packed `fee‖weight‖bitcoin-serialize`)
converts to packed on the next open (Class A untouched). Wipe `{datadir}/mempool/`
only if the sidecar is damaged or an unknown schema/old 4k-slot table was left
wedged — the next start recreates it empty and redownloads unconfirmed txs.
Do **not** wipe `store/` for mempool slot/full/schema errors.

## P2P transport

- **BIP324 v2 only** — plaintext v1 peers disconnect (`peer does not speak BIP324 v2`).
- **IBD `getdata` serve** reconstructs witness blocks from contiguous Class A
  spans (`txout.body` + `seqsigwit.body`), off the session reactor. Serve volume
  is on DEBUG `tip: perf` (`serve n= bytes= tx= avg_us= max_us=`), not a
  per-block line. Host throughput probe:
  `python3 scripts/ibd-serve-bench.py 127.0.0.1:8333` (needs `cryptography`
  and a BIP324 client; see [`TESTING.md`](TESTING.md) § P2P serve bench).
- **Discovery** queries Core DNS seeds for `NETWORK|WITNESS|P2P_V2`
  (`x809.<seed>` first; the bare seed name only if that returns nothing).
  Learned `addr` / `addrv2` is ingested only when the row advertises `P2P_V2`
  (plus `NETWORK` or `NETWORK_LIMITED`). Dial ranking omits known-v1
  (`INCOMPATIBLE`) addresses while any better candidate remains. Seed host
  list lives in `dns_seeds()` (`crates/rbitcoin-net/src/seeds.rs`).
- **Outbound diversity:** live IBD and tip-follow peers prefer unused
  **netgroups**. With a Core `ip_asn.dat` (DecodeAsmap format) the group is
  **ASN**; without a file it is IPv4 `/16` or IPv6 `/32`. Place Core’s map at
  `{datadir}/ip_asn.dat` or pass `--asmap PATH` (relative paths are under
  datadir). A missing or invalid file logs a warning and falls back to prefix
  groups; the node still starts. `--connect` is operator-pinned and skips the
  filter. We do not ship a mainnet map. Core publishes maps from the same
  `ip_asn.dat` used by `bitcoind -asmap`.
- **Genesis `--connect` after a failed first catch-up.** If that attempt
  accepts no blocks and the tip is still height 0, the process enters
  tip-follow instead of staying in IBD. The peer that appears later is a
  follow session: `getheaders`, then at most 16 blocks in flight, confirmed
  on the tip index path. The stagnant-tip loop does not start the IBD
  scheduler again. A catch-up that finishes is unchanged, and a non-zero tip
  that has not finished catch-up stays in IBD. This is for a peer you expect
  to show up with a short chain. A fresh mainnet or signet datadir pointed at
  a full node stays on this slower path for the rest of the process whenever
  the first dial accepts nothing.
- Tx inv/getdata/tx relay is **off during IBD**; enabled in tip mode after catch-up.
- **BIP152 compact blocks v2:** `sendcmpct` high-bandwidth; mempool/orphan/`extra_compact` short-id fill +
  `getblocktxn` / `blocktxn`; full witness getdata fallback. We also **serve** `getblocktxn`.
  Outbound extra prefill (beyond coinbase) is **on** unless `--prefill-compact=0`.
  Generate / `submitblock` / full-block NewPoWValid pack txs that were not in the
  live mempool (`try_read` only; skip packing if the mempool lock is busy).
- **BIP339 wtxidrelay:** sent when peer version ≥70016; mutual negotiation uses `MSG_WTX`.
- Session **misbehavior score** (threshold 100) disconnects peers that spam bad compact payloads.
- Package accept: `ActiveMempool::accept_package` via RPC `submitpackage` or
  Esplora `POST /txs/package` (all-or-nothing; min-relay waiver is a
  child-with-parents ancestor tree). No P2P package command (BIP331 is not in
  rust-bitcoin 0.32).
