# Compatibility with Bitcoin Core

Pinned reference version: **Bitcoin Core v31.1** (same pin as
[`docs/core-functional.md`](./docs/core-functional.md) and nightly fuzz).
BIP324 v2 interop. Package wire tracks BIP331 when rust-bitcoin exposes the
messages (**Q-48** / RB-007).

**Experimental 0.x** — not a production Core or Fulcrum replacement. Design
contrasts: [`docs/architecture.md`](./docs/architecture.md). Lab mainnet:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

## Active product track

Full **P2P participant** (blocks + tip-mode tx relay) and **wallet-client
backends**: in-process **Electrum** (confirmed + unconfirmed, libre-relay-class
admission) and optional **Esplora-compatible REST** for the same role (history,
UTXO, broadcast, block/tx fetch by id). Optional **Core-class JSON-RPC subset**
(see [`docs/rpc.md`](./docs/rpc.md)) — not full Core wallet / mining parity.
**Scripthash index (`--shindex`) defaults off**; Electrum/Esplora require it.
On/off costs and start/IBD/tip behavior: [`OPERATOR.md`](./OPERATOR.md)
(Scripthash index). Disable later leaves SH files on disk; follow does not
wait on SH materialize.

### Query surface intent: wallet clients, plus 0.8 electrs drop-in

**Goal:** serve **wallet software** (Electrum, Sparrow, custom wallets, light
clients that already know their addresses/scripthashes or exact txids/block
ids).

**0.8:** drop-in **mempool/electrs or Blockstream electrs HTTP** so nginx
`/api/` can retire electrs. Core JSON-RPC for that stack is unix
`{datadir}/rpc.sock` (filesystem auth) plus a documented mempool `CORE_RPC`
socket patch — not cookie/Basic TCP. mempool.space **Node `/api/v1/`**
(MariaDB, cubes, mining, lightning) stays their process. Address-prefix
search is **not** in 0.8 (**404**). Surface table below.

**Non-goal (stays):** address-prefix autocomplete, Liquid/assets, in-binary
mempool.space catalogue UI (`/api/v1/`). Opt-in `GET /block-template`
is GBT (same JSON as RPC), not explorer search. Block/tx **by full id** and
address/**exact** scripthash history exist so wallets, APIs, and (after 0.8)
electrs-shaped explorers can verify and sync.

`--max-sh-creates N` (default **0** = unlimited) refuses Electrum/Esplora SH
joins with more than N creates: Esplora HTTP **503**, Electrum JSON-RPC error
`scripthash join exceeds --max-sh-creates`. Stats stay full when under the cap.

`GET …/txs/summary` is a **dialect** route (not Blockstream Esplora `API.md`).
Shape and owner row: [Esplora REST surface](#esplora-rest-surface).

**Product:** `/tx/:txid/outspend/:vout` and `/outspends` emit Blockstream
`vin` (spending input index) from the schema-22 spent slot. Mempool overlay
uses the hub tx’s input index. Unspent remains `{spent:false}` with no `vin`.
Full `/tx/:txid` JSON still has `vin[]`. Electrum has no outspend-vin surface.

## Intentional differences

| Area | This node | Bitcoin Core |
|------|-----------|--------------|
| Chainstore | Relational **map-free** archive (fd tables; see [`docs/io-modality.md`](./docs/io-modality.md)) | blocks/undo + LevelDB chainstate |
| Historical blocks | Reconstruct from archive; tip via body queue + peer wire | `blocks/` blk*.dat |
| Transport | **BIP324 v2 only** | v1 + v2 |
| Mempool structure | Cluster graph + chunks | Cluster mempool (same lineage) |
| Admission policy | **Libre-relay-class** (0.1 sat/vB, no dust, full RBF) | Standardness + policy knobs |
| Compact blocks | BIP152 **v2** receive + reconstruct + `getblocktxn` serve. Fill is live mempool + orphanage + `extra_compact` (cap 100). Outbound extra prefill is **on** unless `--prefill-compact=0` (10 KiB cap, extra-pool last; generate / submit / NewPoWValid pack txs not in the live mempool without delaying forward) | v1/v2 high-bandwidth + `extra_txn` cache (`-blockreconstructionextratxn`); Core #35558 prefill still unmerged |
| WTx inventory | BIP339 when peer also sends `wtxidrelay` | BIP339 |
| GetAddr | Core `MAX_ADDR_TO_SEND` / `MAX_PCT_ADDR_TO_SEND` (**1000** / **23%**), 24h per-bind cache. Named copies in `rbitcoin-net` — do not “improve” without a named reason to diverge. `MAX_ADDR_MAN` (8192) is **our** HashMap DoS cap and must stay above `1000/0.23` | Core new/tried buckets (~80k); same 1000 / 23% |
| Package submit | RPC `submitpackage` / Esplora `POST /txs/package` (no P2P package command) | BIP331 wire |
| Pruning / GUI | Not supported | Supported |
| Mining template RPC | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` (selector; no stratum) | GBT + stratum / pool stack |
| Wallets | Electrum clients (requires `--shindex`) | Descriptor + legacy |
| Scripthash index | Optional (`--shindex`, default **off**); bulk at tip when on | External ElectrumX / Fulcrum; Core `-txindex` is different (txid→block) |
| JSON-RPC | Documented **subset** ([`docs/rpc.md`](./docs/rpc.md)); cookie/user-pass; `rbitcoin-cli`. `--rpc-work-queue` is HTTP occupancy (503 when full); a JSON-RPC array is one POST | Full Core RPC; `-rpcworkqueue` is in-flight HTTP jobs (503) |
| GetData serve | Reconstruct/serve **16** (`MAX_SERVE_BLOCKS`) hashes per inbound message; leftover hashes in that `getdata` are dropped (RAM cap) | Core `ProcessGetData` can keep serving leftover hashes |
| Inbound eviction victim | After Core-shaped protect (netgroup / recent block / recent tx / min-ping), disconnect the **longest-connected** remaining inbound | Core `SelectNodeToEvict` youngest in the oldest netgroup |
| `--sptweaks-dust` | Serve-time floor default **1000** sat (omit P2TR outs `value <=` floor). **546** matches Cake electrs. Not Cake/Electrum protocol | n/a (Electrum tweaks are not Core) |
| IBD empty-headers EOF | Empty `headers` to **our locator** + idle path latches `headers_done` even if a peer advertises a taller less-work height / junk `version.start_height` | Core header sync follows most-work; advertised `start_height` is not a remaining header count |

Compact reconstruct fills short-ids from the live mempool graph, the
orphanage, and a small `extra_compact` ring (cap 100): RBF-replaced and
min-relay-rejected bodies, mempool removals (confirm/evict), inbound
`cmpctblock` prefills, and `blocktxn` bodies. Coinbase is skipped. That is
still not Core’s full `-blockreconstructionextratxn` cache of every recently
seen wire tx. Libre admission (0.1 sat/vB, no dust, full RBF) keeps more
bodies live than Core standardness, so a larger extra-txn ring would hit
less often than on Core — not never. Eviction still misses the short-id map
and costs a `getblocktxn` when the ring has already rolled off. Growing the
ring to Core’s extra-txn shape is worth later; not scheduled (no Open Q-id).

Inbound `tx` whose prevouts are spent or missing on a confirmed create is
`MissingPrevout`, not an orphan park. INV AlreadyHave is live mempool +
orphanage + a recent-confirmed txid/wtxid ring (filled at tip connect and IBD write) +
Class A `tx_fk_by_txid_tip`. Re-delivery of an already-parked orphan still
GETDATAs missing parents (TTL) but does not log a second `txrelay: park`.

Inbound `cmpctblock` may prefill any well-formed indexes (BIP152). We always
log reconstruct fill sources and `fetched=` `blocktxn` bytes, and outbound
`cmpct announce … prefill=N/bytes` when we send `cmpctblock` (tip announce or
`MSG_CMPCT_BLOCK` getdata). **Sending** extra prefills (beyond coinbase) is on
unless `--prefill-compact=0`. A pending compact owns the first-pass slot
bodies (mempool / extra / orphan hits). `blocktxn` overlays only the missing
indexes; apply does not re-walk a live short-id map.

## Core-class JSON-RPC (subset)

Per-method notes, auth, and the shindex matrix live in
**[`docs/rpc.md`](./docs/rpc.md)**. Group status (intentional scope):

| Method group | Status |
|--------------|--------|
| Control (`help`, `uptime`, `stop`, `getrpcinfo`, `echo`) | done (`syncwithvalidationinterfacequeue` omitted; functional proxy no-op for Core `sync_mempools`) |
| Blockchain (`getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`/`header`, `getdifficulty`, `getblockstats`) | done (archive reconstruct; disk/progress real) |
| Network (`getnetworkinfo`, `getconnectioncount`, `getpeerinfo`, `addnode`, `disconnectnode`, `addconnection`) | done (BIP324 v2-only; peer `timeoffset` / `synced_*` from session state) |
| Mempool / rawtx (`getmempool*`, `getrawtransaction`, `sendrawtransaction`, `testmempoolaccept`) | done (Libre; RPC `maxfeerate` / `maxburnamount` only) |
| Coin / MiniWallet (`gettxout`, `scantxoutset` `raw(HEX)`) | done (Class A unspent walk — not a coins-DB) |
| Index / tips (`getindexinfo`, `getchaintips`, `waitforblock*`) | done (`txindex` = Class A reconstruct) |
| Fee (`estimatesmartfee`) | done (**10-minute inclusion** — not Core historical) |
| Decode (`decoderawtransaction`, `decodescript`, `validateaddress`) | done (node subset; official Core dialect scripts stay `rpc-dialect`) |
| Regtest `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` / `submitblock` / `setmocktime` | harness (regtest only except `submitblock`) |
| `invalidateblock` / `reconsiderblock` / `preciousblock` | done |
| Mining template (`getblocktemplate`, `getmininginfo`, `prioritisetransaction`, `getmempoolcluster`) | done (no stratum / BIP9 testdummy / wallet keys) |
| Wallet RPC; `createrawtransaction` / `combinerawtransaction`; full `scantxoutset` / `gettxoutsetinfo` | **never** |

## Electrum surface

| Method | Status | Notes |
|--------|--------|-------|
| server.version / banner / features | done | Banner: libre-relay-class. `server.version[0]` is `rbitcoin-electrs <workspace.package.version>` — **not electrs**; see below. `server.version` negotiates: omitted → `1.6`; `"1.4"` → `1.4`; `["1.4","1.4.2"]` → `1.4.2`; `["1.4","1.6"]` → `1.6`; `"1.4.2-asof"` (or a range containing it) → as-of dialect. First call wins. `features.protocol_max` is `1.6`; `features.asof_protocol` is `1.4.2-asof`. `features.genesis_hash` is display-order hex (refuse a wrong-chain server before a tweaks scan). `features.tweaks` / `silent_payments` advertise the method; they are not a substitute for the stream. |
| blockchain.tweaks.subscribe | done | **Stream**, not a one-shot result: JSON-RPC `result` is the **first** height only; remaining heights are unsolicited notifications; `{"message":"done"}` ends the **chunk** (60s wall at a wave boundary, or the requested `count` if sooner) — Cake electrs clamps `count` to 1000 instead. Cake Wallet resubscribes from `syncHeight+1` ([cake_wallet#3574](https://github.com/cake-tech/cake_wallet/issues/3574) persist still lags one event). [kiss-bdk](https://github.com/kkdao/kiss-bdk) today treats `done` as the asked range finished ([kiss-bdk#10](https://github.com/kkdao/kiss-bdk/issues/10)). Each height carries tweak + txid + taproot `output_pubkeys` (client scans locally; no block fetch). Naive walk, or `--sptweaks` thin index (`len:tweak` only; one `txout` span per wave; the first height shares that span when indexed). Pre-taproot: **one** notify with ≤1024 empty height keys (Cake `fromJson` last key is progress); probe `[0,1,false]` stays `{"0": {}}`. Param `[2]` (Cake `historicalMode`): `false` **cut-through** (omit confirmed-spent P2TR outs / txs); `true` keeps spent outs. Serve-time `--sptweaks-dust` (default **1000**) omits P2TR outs with `value <=` the floor (`0` = all; **546** matches Cake electrs `sp_min_dust`). Sparrow Silent Payments uses Frigate `blockchain.silentpayments.subscribe` (server-side scan) — **not** this method. Cake isolate may still hardcode `electrs.cakewallet.com`. |
| headers / block headers | done | Tip push on subscribe |
| scripthash history / balance / listunspent | done | Unconf when mempool attached; `get_history` optional BCH-style `from_height` / exclusive `to_height` (`-1` = tip + mempool); 1-arg = full history; unconfirmed `get_history` rows include `fee` (same as `get_mempool`); `listunspent` mempool height is `0` or `-1` (unconfirmed parent); **subscribe status always full**; `blockchain.scripthash.unsubscribe` returns whether the connection was watching (frees the 1000-sub cap). `listunspent` loads `txid.body` only for unspent creates; one TCP connection reuses the last SH outs+spent join until SH-view **hash** changes. Confirmed methods stamp live tip: a RAM SH head (pending write-behind) joins with durable SH so mempool can drop confirmed txs without a hole. Durable Class B seed waits until after tip announce. `get_history` skips mempool rows already in the confirmed list. `server.features.chain_tip = true`. Trailing **`asof:<blockhash>`** after the official args (`server.features.asof` / `asof_protocol = 1.4.2-asof`): confirmed rows as of that still-live ancestor **at or behind visible SH** (durable + pending), **no** mempool; stamp is the asof block; unknown hash or ahead of visible SH → `asof not on chain`. Prefix keeps it off the future positional-string landmine. Requires negotiated `1.4.2-asof` (first `server.version` only). Electrum `protocol_max` is **1.6**. |
| scripthash.get_mempool / subscribe | done | Status on mempool announce **and** when SH applies a height that creates or spends the hash (posting-list probe; no Class A expand on a miss). Headers subscribe still live tip. Reorg (`TipNotify.reorg_from_height`) restatuses every watch even if the new block misses the script. Status preimage is `txid:height:blockhash:` for confirmed rows (mempool rows stay `txid:height:`). Row **order** is confirmed height-asc then mempool tail, same as `get_history`. `unsubscribe` is implemented. |
| transaction.get / get_merkle | done | get falls back to mempool unless `asof:`; confirmed responses stamp `chain_tip`. Verbose get is electrs-shaped: `time`/`blocktime`/`confirmations`/`blockhash` from the confirming header (mempool verbose is `confirmations: 0` with no block stamp), plus `vin`/`vout`/`size`/`version`/`locktime`/`hash` (wtxid) decoded from the hex already loaded. Trailing `asof:<blockhash>` (same dialect as scripthash): get returns the tx only if confirmed at or behind that ancestor (**no** mempool); get_merkle rejects a `height` above the asof pin (`asof not on chain`). `id_from_pos` is a txid string; third arg `merkle=true` returns `{tx_hash, merkle}` (same walk as `get_merkle`). |
| transaction.broadcast | done | Mempool accept + P2P inv. `broadcast_package` wraps `accept_package` (Electrum **1.6**; P2P BIP331 still Q-48). |
| relayfee / estimatefee / histogram / `mempool.get_info` | done | Libre min + live median. `mempool.get_info` is 1.6 (`minrelaytxfee` replaces `relayfee` for 1.6 clients; `relayfee` stays for 1.4). |
| outpoint.get_status / subscribe / unsubscribe | done | Electrum **1.7** methods; `protocol_max` stays **1.6** until `scriptpubkey.*`. Spent = confirmed-strong or mempool. |
| silentpayments.subscribe / unsubscribe | done | Frigate remote-scanner: session-only scan key; historical + tip notifies via tweak index / naive `tweaks_for_height`. Not Cake `tweaks.subscribe`. |
| TLS | external | terminate at reverse proxy; node is plain TCP. In-binary 50002 + onion is parked **Q-63**. |

### Protocol versions

`features.protocol_max` is **1.6** (plus dialect `1.4.2-asof`).
Electrum 4.8 wallets speak 1.4–1.6; ElectrumX advertises 1.7. `block.headers`
is concatenated `hex` for 1.4.x and a `headers` list for 1.6.
`scriptpubkey.*` still missing — do **not** advertise 1.7 yet.

P2P BIP331 package messages remain **Q-48**. Local Electrum
`broadcast_package` uses the same `accept_package` as RPC/Esplora.

### Why `server.version` says electrs

We are **not** electrs. Cake Wallet `getNodeIsElectrs()` lowercases
`version[0]` and requires the substring `electrs` before it will call
`blockchain.tweaks.subscribe`. The first element is therefore
`rbitcoin-electrs <ver>` (`ver` from `workspace.package.version`) so Cake
will probe tweaks. Other tweaks clients (kiss-bdk) do not need that
substring; they discover the chain via `server.features.genesis_hash`.
Cake isolate may still hardcode `electrs.cakewallet.com` after a passing
probe.

### Tweaks stream vs Sparrow / Frigate

`blockchain.tweaks.subscribe` is a **client-side** BIP-352 scan: the
server never sees a scan key. A client that treats the JSON-RPC call as
request/response reads one height and stops. Sparrow’s Silent Payments
path talks Frigate `blockchain.silentpayments.subscribe` (scan key on
the server, RAM-only for the session). That RPC is implemented on the
tweak index (or naive height walk). `tweaks.subscribe` remains the Cake
client-local scan.
| DoS floor | always on | max conn / line / idle / subs / broadcast hex (`ServeLimits`); public bind OK behind proxy |

### Chain view (confirmed-tx snapshot token)

Yuval pointed out that Electrum status and Esplora list envelopes are
**A-B-A**: a same-height reorg can leave `txid:height` (and a height-keyed
join cache) unchanged while merkle proofs and confirming block hashes
moved. We researched
[mempool/mempool#6584](https://github.com/mempool/mempool/issues/6584)
(tnull: stamp chain tip **hash** on every API response header so sequential
fetches detect tip movement, including A-B-A) and
[spesmilo/electrum-protocol#2](https://github.com/spesmilo/electrum-protocol/pull/2)
(1.7 `chaintip` on `scriptpubkey.*`, reverted in
[#17](https://github.com/spesmilo/electrum-protocol/pull/17) because ElectrumX
is bitcoind middleware and cannot pin). rbitcoin owns Query+store, so we pin
the published tip and retry if it disconnects
([`docs/concurrency.md`](docs/concurrency.md#confirmed-tx-readers-pin--retry-not-a-lock)).

| Surface | Token | Body |
|---------|--------|------|
| Esplora HTTP | `X-Bitcoin-Chain-Tip` + `X-Bitcoin-Chain-Tip-Height` | Unchanged JSON. Client: if two sequential fetches disagree on the hash, drop the batch and restart. |
| Electrum TCP | JSON-RPC extra members `chain_tip` / `chain_tip_height` next to `result` (ping/version omit). `server.features.chain_tip`. | `result` shape unchanged. Status preimage includes confirming `blockhash` so subscribe clients refetch on same-height replace. Notification `params` stay `[scripthash, status]`. |

We stamp **tip**, not only the last relevant history tx hash (empty history
and list envelopes still need a token).

**As-of (buried ancestor):** thanks again to Yuval — the same A-B-A /
bind-confirmations-to-a-chain work implies “wallet as of this block”
while that block is still on the best chain. Esplora `?asof=<hash>` and
Electrum trailing `asof:<hash>` (after official positional args) join
under `pin_chain_view_at`. Stamp is that hash. If the asof block leaves
the tip chain: **404** / `asof not on chain` (no retry onto another
block at the same height). We still do **not** serve a disconnected fork
hash.

Electrum clients that want as-of send `server.version(name, "1.4.2-asof")`
(or a `[min, max]` range containing that string). Standard Electrum
`"1.4"` / `["1.4", "1.4.2"]` stays on dotted-int 1.4.x; an `asof:` tag
without the dialect is an error. `server.features.protocol_max` remains
`"1.4.2"` so Electrum dotted-int parsers do not choke; discovery is
`asof` + `asof_protocol`.

## Esplora REST surface

Plain HTTP via `--esplora-listen` / conf `esplora_listen` (default **off**). TLS
via reverse proxy; app `ServeLimits` always on (same model as Electrum).

| Endpoint group | Status | Notes |
|----------------|--------|-------|
| Tip | done | `/blocks/tip/height`, `/blocks/tip/hash`. REST stamps `X-Bitcoin-Chain-Tip` / `X-Bitcoin-Chain-Tip-Height` (CORS-exposed): **live tip** for block/tx/header routes; **SH watermark** for `/address/` and `/scripthash/` so wallet JSON matches the SH join. Empty chain omits them (existing 503). If the pin dies mid-request: **503** `chain view moved`. |
| Blocks list | done | `/blocks`, `/blocks/:start_height` (10 summaries, newest-first) |
| Block | done | `/block/:hash` JSON, `/raw`, `/status`, `/header`, `/txids`, `/txid/:i`, `/txs[/:start]`. JSON `bits` is the compact-target **u32** (Esplora schema, not Core hex). `size` / `weight` are BIP144 total size and BIP141 weight (witness included). |
| Tx | done | `/tx/:txid` full JSON, `/hex`, `/raw`, `/status`, Electrum `/merkle-proof`, BIP37 `/merkleblock-proof`, `/outspend(s)` (`vin` from the spent slot; unspent omits it). Mempool-only txs (not in Class A) use the wire body from the mempool hub (`vin`/`vout`/`size`/`weight`/`fee`, `status.confirmed` false) including `GET /tx/:txid/status`. Live `/outspend(s)` overlay mempool spends of confirmed coins; `?asof=` omits mempool. `?asof=<hash>` on `/status` and `/outspend(s)`: confirmed/spent as of that ancestor; 404 if not on chain. |
| Address / scripthash | done | stats + `/utxo` + `/txs` + `/txs/mempool` + `/txs/chain[/:last_seen_txid]` + `/txs/summary[/:last_seen_txid]` (dialect; next row). `/utxo` matches Electrum listunspent (mempool funding + drop mempool-spent confirmed); `/txs` and `/txs/mempool` use full Esplora tx JSON for mempool-only rows (wire from the hub). `?after_txid=` on `/txs` and `/txs/summary` skips through that tx (mempool then chain); unknown or unparseable → **422** `after_txid not found`. Bounded HTTP `sh_join` (8 slots); concurrent different SHs re-join. Needs SH finalize. Stamp is visible SH (durable + pending write-behind), matching live tip while jobs sit in RAM. `?asof=<hash>` on `/`, `/utxo`, `/txs`, `/txs/chain`, `/txs/summary`: confirmed join at that ancestor **at or behind visible SH**, **no** mempool; headers are the asof hash; 404 if not on chain or ahead of visible SH. |
| `/txs/summary` | dialect | **Not** in Blockstream Esplora [`API.md`](https://github.com/Blockstream/esplora/blob/master/API.md). Compact `{txid, value, height, time}` like mempool.space `/address/:addr/txs/summary`. Confirmed only (25/page, newest first); path cursor `/:last_seen_txid` and mempool.space `?after_txid=` (unknown → **422**). `value` is net sats for that script in that tx (funded − spent). `time` is the confirming header timestamp (`0` if the header is missing). Mempool rows stay on `/txs` and `/txs/mempool`. Over `--max-sh-creates` → **503**. |
| Mempool / fees | done | `/mempool`, `/mempool/txids`, `/mempool/txids/page[/:last]`, `/mempool/recent` (accept-order ring), `/fee-estimates`, mempool.space `/fees/recommended` and `/v1/fees/recommended` (sat/vB tiers) |
| `POST /tx` | done | broadcast via mempool hub; **503** if hub absent |
| `POST /txs/package` | done | JSON array of hex txs → `accept_package`; **503** without hub; max 25 txs |
| electrs `/internal/*` | done | `POST /internal/txs` (400 on unparseable id; missing omitted); `POST /internal/mempool/txs` (mempool only); `GET /internal/mempool/txs[/all|/:last]` (txid-sort pages, default `max_txs=10000`; `/all` registered first); `GET /internal/block/:hash/txs` (full list; public `/txs` stays 25/page); `POST /internal/txs/outspends/by-txid` (same-length slots, unknown → `[]`); `POST /internal/txs/outspends/by-outpoint` (`txid:vout`; malformed → `{"spent":false}`). Snapshot JSON is published on the hub (no admit-path build). |
| Unix listen | done | `--esplora-listen` filesystem path (same router as TCP; mode **0660**) |
| Unknown path | 404 | plain body (including `/address-prefix`) |
| `GET /block-template` | opt-in | `--esplora-block-template` (default off → **404**). Same JSON as RPC `getblocktemplate` `{"rules":["segwit"]}` template mode. **503** without tip. `Cache-Control: no-store`. 15 s cache, invalidated on tip or mempool `template_updates`. No proposal/longpoll HTTP (parked **Q-64**). |
| **Non-goal / never** | — | Address-prefix search, Liquid/assets. mempool.space `/api/v1/` catalogue stays their Node. |

## Esplora WebSocket (wallet live subset)

Same listen as REST (`--esplora-listen`). Paths: **`/v1/ws`** (preferred) and
**`/ws`** alias. Plain WS in-process; terminate **WSS** at the reverse proxy
(often public URL `wss://host/api/ws` when nginx `/api/` → this listen).

**Product boundary:** wallet live updates only (tip, address watchlist, pending
txids, wallet-scoped RBF). mempool.space explorer live catalogue is **their**
`/api/v1/` WebSocket, not this listen. nginx `/api/` is our
Esplora; `/api/v1/` stays their backend. Message *names* follow mempool.space
where listed; **payloads use Esplora REST shapes** (`build_tx_json` /
`tx_status_json` / tip height+hash).

### Client → server (supported)

| Message | Behavior |
|---------|----------|
| `{ "action": "want", "data": ["blocks"] }` | Subscribe tip pushes; other `data` tokens **no-op** (no disconnect) |
| empty want / no `blocks` | Clear tip subscription |
| `{ "track-address": "<addr>" }` / `{ "track-addresses": [...] }` | Watchlist (network-checked); over-cap → `{ "error": "max_track_addresses exceeded" }` |
| `{ "stop-track-address": "…" }` / `stop-track-addresses` / empty track-address | Unsubscribe |
| `{ "track-tx": "<txid>" }` / `{ "track-txs": [...] }` | Pending set; over-cap → error |
| `{ "stop-track-tx": "…" }` / `stop-track-txs` | Unsubscribe |

No client API for global `track-mempool*`, `track-rbf`, or `want` stats/charts.

### Server → client (supported)

| Key | When |
|-----|------|
| `{ "block": { "height", "id", "timestamp" } }` | Tip advance after `want: blocks` |
| `{ "address-transactions": [ … ] }` | Mempool accept touching a tracked script (in/out when resolvable) |
| `{ "block-transactions": [ … ] }` | Tip height: txs in that block that create or spend a tracked script (posting-list probe; no Class A expand on a miss) |
| `{ "tx": { "txid", "status" } }` | Tracked txid status transition (mempool / confirmed) |
| `{ "replaced-transactions": [ { "txid", "replaced-by" } ] }` | Full-RBF replace **only if** old or new intersects this connection’s tracks |

Unknown client keys: ignored (or JSON error for bad JSON / oversize). Lagged
broadcast receivers drop (best-effort, like Electrum).

### Caps (`EsploraConfig`, defaults)

| Knob | Default |
|------|---------|
| max_ws_connections | 64 (separate from REST concurrency) |
| max_ws_message_bytes | 64 KiB |
| max_track_addresses | 64 / connection |
| max_track_txs | 64 / connection |

### Gap list (explorer-only — not supported)

| mempool.space-style feature | Status |
|-----------------------------|--------|
| `want`: `stats`, `mempool-blocks`, `live-2h-chart` | **No** |
| `track-mempool` / `track-mempool-txids` global firehose | **No** |
| `track-mempool-block` projected templates | **No** |
| Global `track-rbf` / `rbfLatest` trees | **No** (wallet-scoped replace only) |
| CPFP / `txPosition` / explorer fee-ladder fields | **No** |
| Durable resume / sequence cursors | **No** |

## BIP324 v2 short-ID surface (live paths)

Encode/decode uses Core’s `V2_MESSAGE_IDS` table (`crates/rbitcoin-net/src/v2.rs`).
**Live IBD + tip follow + tip tx relay** commands with short IDs:

| Short ID | Command | Role |
|----------|---------|------|
| 1 | addr | peers |
| 2 | block | IBD / tip body |
| 3 | blocktxn | compact fill |
| 4 | cmpctblock | tip HB |
| 5 | feefilter | tip policy |
| 9–15 | getblocks…mempool | headers/blocks/inv |
| 17–21 | notfound…tx | ping/pong/sendcmpct/tx |
| 28 | addrv2 | BIP155 |

Long-form (no short ID): `version`, `verack`, `wtxidrelay`, `sendheaders`,
`sendaddrv2`, and unknown/extension commands.

**Not implemented as product features** (short slots 22–27 compact filters, 29–36
placeholders, 37 `feature`): decode may reject unknown short IDs; peers that
only need the live set above interoperate. Full Core filter/light-client APIs
are deferred (**Q-65**). satd’s native BIP 157/158 index is noted in
[`docs/peer-clients.md`](./docs/peer-clients.md).

## Deferred surfaces

Core wallet RPC, fee-estimator research quality, BIP331 native wire enum,
durable orphans: **out of scope** for this plan. GBT **template RPC** is
shipped (see above); stratum / pool software is not.

**Permanent non-goals for Electrum/Esplora:** address-prefix autocomplete,
Liquid/assets, in-binary mempool.space `/api/v1/` (MariaDB cubes / mining /
lightning). **0.8** is electrs HTTP drop-in except prefix. Core RPC for that
stack is `rpc.sock` plus the mempool patch.
