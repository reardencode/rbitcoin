# Compatibility with Bitcoin Core

Pinned reference version: **target Core ≥27** for BIP324 v2 interop; package wire
tracks BIP331 when rust-bitcoin exposes the messages.

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

### Query surface intent: wallet clients, not graphical explorers

**Goal:** serve **wallet software** (Electrum, Sparrow, custom wallets, light
clients that already know their addresses/scripthashes or exact txids/block
ids).

**Non-goal:** power a **graphical block explorer** product (search boxes,
address-prefix autocomplete, “browse everything” UX, Liquid/mining template
surfaces). Those need reverse indexes and explorer-only APIs we deliberately
omit. Block/tx **by full id** and address/**exact** scripthash history exist so
wallets and APIs can verify and sync—not so we become mempool.space.

## Intentional differences

| Area | This node | Bitcoin Core |
|------|-----------|--------------|
| Chainstore | Relational **map-free** archive (fd tables; see [`docs/io-modality.md`](./docs/io-modality.md)) | blocks/undo + LevelDB chainstate |
| Historical blocks | Reconstruct from archive; tip via body queue + peer wire | `blocks/` blk*.dat |
| Transport | **BIP324 v2 only** | v1 + v2 |
| Mempool structure | Cluster graph + chunks | Cluster mempool (same lineage) |
| Admission policy | **Libre-relay-class** (0.1 sat/vB, no dust, full RBF) | Standardness + policy knobs |
| Compact blocks | BIP152 **v2** receive + reconstruct + `getblocktxn` serve | v1/v2 high-bandwidth |
| WTx inventory | BIP339 when peer also sends `wtxidrelay` | BIP339 |
| Package submit | RPC `submitpackage` / Esplora `POST /txs/package` (no P2P package command) | BIP331 wire |
| Pruning / GUI | Not supported | Supported |
| Mining template RPC | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` (selector; no stratum) | GBT + stratum / pool stack |
| Wallets | Electrum clients (requires `--shindex`) | Descriptor + legacy |
| Scripthash index | Optional (`--shindex`, default **off**); bulk at tip when on | External ElectrumX / Fulcrum; Core `-txindex` is different (txid→block) |
| JSON-RPC | Documented **subset** ([`docs/rpc.md`](./docs/rpc.md)); cookie/user-pass; `rbitcoin-cli` | Full Core RPC |

## Core-class JSON-RPC (subset)

| Method group | Status | Notes |
|--------------|--------|-------|
| Control (`help`, `uptime`, `stop`, `getrpcinfo`, `echo`, `syncwithvalidationinterfacequeue`) | done | Queue RPC is a no-op `null` |
| Blockchain (`getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`/`header`, `getdifficulty`, `getblockstats`) | done | Archive reconstruct. `getblock` verbosity **1** is `txid.body` identities (no packed reconstruct). v0/v2 share one prev_txid cache. `chainwork` is real. `size_on_disk` is a store file walk; `verificationprogress` is `blocks/headers` (see [`docs/rpc.md`](./docs/rpc.md)) |
| Network (`getnetworkinfo`, `getconnectioncount`, `getpeerinfo`, `addnode`, `disconnectnode`, `addconnection`) | done | BIP324 v2-only; live session table. `version` is rbitcoin, not Core 27.0; services match wire. Learned `addr`/`addrv2` must advertise `P2P_V2` |
| Mempool / rawtx (`getmempool*`, `getrawtransaction`, `sendrawtransaction`, `testmempoolaccept`) | done | Libre policy. `testmempoolaccept` is dry-run (no live-set mutation, does not park orphans). `maxmempool` is the hub weight budget |
| Coin / MiniWallet (`gettxout`, `scantxoutset` `raw(HEX)`) | done | Class A unspent walk — **not** a coins-DB / HD-range scan |
| Index / tips (`getindexinfo`, `getchaintips`, `waitforblock*`) | done | `txindex` means Class A reconstruct; `getchaintips` is the active tip |
| Fee (`estimatesmartfee`) | done | **10-minute inclusion** product — not Core historical |
| Decode (`decoderawtransaction`, `decodescript`, `validateaddress`) | done | |
| Regtest `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` / `submitblock` / `setmocktime` | harness | **Regtest only** (except `submitblock`). Same confirm/accept path as P2P. `setmocktime` is not a wall-clock hook. |
| `invalidateblock` / `reconsiderblock` / `preciousblock` | done | Disconnect/re-accept; precious = equal-work preference |
| Mining template (`getblocktemplate`, `getmininginfo`, `prioritisetransaction`, `getmempoolcluster` / feerate diagram) | done | Cluster-chunk selector. `rules` must include `segwit`. No stratum, no BIP9 testdummy, no wallet keys |
| Wallet RPC | **never** | No keystore |
| `createrawtransaction` / `combinerawtransaction` | **never** | External tools |
| Full `scantxoutset` / `gettxoutsetinfo` | **never** | No UTXO-set coins DB; `raw()` MiniWallet subset is the only scan |

Full method list, auth, and shindex matrix: **[`docs/rpc.md`](./docs/rpc.md)**.

## Electrum surface

| Method | Status | Notes |
|--------|--------|-------|
| server.version / banner / features | done | Banner: libre-relay-class. `server.version[0]` is `rbitcoin-electrs <workspace.package.version>` — **not electrs**; see below. `server.version` negotiates: omitted → `1.4.2`; `"1.4"` → `1.4`; `["1.4","1.4.2"]` → `1.4.2`; `"1.4.2-asof"` (or a range containing it) → as-of dialect. First call wins. `features.protocol_max` is `1.4.2`; `features.asof_protocol` is `1.4.2-asof`. `features.genesis_hash` is display-order hex (refuse a wrong-chain server before a tweaks scan). `features.tweaks` / `silent_payments` advertise the method; they are not a substitute for the stream. |
| blockchain.tweaks.subscribe | done | **Stream**, not a one-shot result: JSON-RPC `result` is the **first** height only; remaining heights are unsolicited notifications; `{"message":"done"}` ends the run. Each height carries tweak + txid + taproot `output_pubkeys` (client scans locally; no block fetch). Naive walk, or `--sptweaks` thin index (`len:tweak` only; one `txout` span per wave; the first height shares that span when indexed). Pre-taproot: empty maps in ≤1024-height writes. Clients: Cake Wallet, [kiss-bdk](https://github.com/kkdao/kiss-bdk). Sparrow Silent Payments uses Frigate `blockchain.silentpayments.subscribe` (server-side scan) — **not** this method. Cake isolate may still hardcode `electrs.cakewallet.com`. |
| headers / block headers | done | Tip push on subscribe |
| scripthash history / balance / listunspent | done | Unconf when mempool attached; `get_history` optional BCH-style `from_height` / exclusive `to_height` (`-1` = tip + mempool); 1-arg = full history; **subscribe status always full**; `listunspent` loads `txid.body` only for unspent creates; one TCP connection reuses the last SH outs+spent join until SH-view **hash** changes. Confirmed methods stamp live tip: a RAM SH head (pending write-behind) joins with durable SH so mempool can drop confirmed txs without a hole. Durable Class B seed waits until after tip announce. `get_history` skips mempool rows already in the confirmed list. `server.features.chain_tip = true`. Trailing **`asof:<blockhash>`** after the official args (`server.features.asof` / `asof_protocol = 1.4.2-asof`): confirmed rows as of that still-live ancestor **at or behind visible SH** (durable + pending), **no** mempool; stamp is the asof block; unknown hash or ahead of visible SH → `asof not on chain`. Prefix keeps it off the future positional-string landmine. Requires negotiated `1.4.2-asof` (first `server.version` only). Electrum `protocol_max` stays `1.4.2`. |
| scripthash.get_mempool / subscribe | done | Status on mempool announce **and** when SH applies a height that creates or spends the hash (posting-list probe; no Class A expand on a miss). Headers subscribe still live tip. Reorg (`TipNotify.reorg_from_height`) restatuses every watch even if the new block misses the script. Status preimage is `txid:height:blockhash:` for confirmed rows (mempool rows stay `txid:height:`). Row **order** is confirmed height-asc then mempool tail, same as `get_history`. |
| transaction.get / get_merkle | done | get falls back to mempool unless `asof:`; confirmed responses stamp `chain_tip`. Trailing `asof:<blockhash>` (same dialect as scripthash): get returns the tx only if confirmed at or behind that ancestor (**no** mempool); get_merkle rejects a `height` above the asof pin (`asof not on chain`). |
| transaction.broadcast | done | Mempool accept + P2P inv. `broadcast_package` is Electrum **1.6** — wait for P2P package relay, then bump (below). |
| relayfee / estimatefee / histogram | done | Libre min + live median |
| TLS | external | terminate at reverse proxy; node is plain TCP |

### Protocol versions

`features.protocol_max` is **1.4.2** on purpose (plus dialect `1.4.2-asof`).
Electrum 4.8 wallets speak 1.4–1.6; ElectrumX advertises 1.7. Do **not**
raise the number ahead of the methods.

**After P2P package relay** ([`docs/quality.md`](./docs/quality.md) **Q-48** /
BIP331), implement Electrum **1.6** (`blockchain.transaction.broadcast_package`,
`mempool.get_info`, `block.headers` as a list, `server.version` first) then
**1.7** (`scriptpubkey.*`, outpoint subscribe) and raise `protocol_max` in
the same work. Dual-serve `scripthash.*` until 1.7 clients exist. RPC
`submitpackage` / Esplora `POST /txs/package` already accept packages; the
Electrum bump waits on the P2P command so 1.6 is not a lie.

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
the server). We do **not** implement that RPC. Sparrow still uses this
node as a normal Electrum backend (scripthash / history / broadcast).
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
| Tx | done | `/tx/:txid` full JSON, `/hex`, `/raw`, `/status`, Electrum `/merkle-proof`, BIP37 `/merkleblock-proof`, `/outspend(s)`. Mempool-only txs (not in Class A) use the wire body from the mempool hub (`vin`/`vout`/`size`/`weight`/`fee`, `status.confirmed` false). `?asof=<hash>` on `/status` and `/outspend(s)`: confirmed/spent as of that ancestor; 404 if not on chain. |
| Address / scripthash | done | stats + `/utxo` + `/txs` + `/txs/mempool` + `/txs/chain[/:last_seen_txid]`; `/utxo` matches Electrum listunspent (mempool funding + drop mempool-spent confirmed); `/txs` and `/txs/mempool` use full Esplora tx JSON for mempool-only rows (wire from the hub). Last **one** SH join reused across sequential REST calls until SH-view **hash** changes; concurrent different SHs re-join. Needs SH finalize. Stamp is visible SH (durable + pending write-behind), matching live tip while jobs sit in RAM. `?asof=<hash>` on `/`, `/utxo`, `/txs`, `/txs/chain`: confirmed join at that ancestor **at or behind visible SH**, **no** mempool; headers are the asof hash; 404 if not on chain or ahead of visible SH. |
| Mempool / fees | done | `/mempool`, `/mempool/txids`, `/mempool/recent` (accept-order ring), `/fee-estimates` |
| `POST /tx` | done | broadcast via mempool hub; **503** if hub absent |
| `POST /txs/package` | done | JSON array of hex txs → `accept_package`; **503** without hub; max 25 txs |
| Unknown path | 404 | plain body |
| **Non-goal / never** | — | Graphical explorer features: `address-prefix` search, Liquid/assets, mining `block-template`, explorer UI-only APIs |

## Esplora WebSocket (wallet live subset)

Same listen as REST (`--esplora-listen`). Paths: **`/v1/ws`** (preferred) and
**`/ws`** alias. Plain WS in-process; terminate **WSS** at the reverse proxy
(often public URL `wss://host/api/v1/ws` if the proxy strips `/api`).

**Product boundary:** wallet live updates only (tip, address watchlist, pending
txids, wallet-scoped RBF). **Not** a mempool.space explorer live backend.
Message *names* follow mempool.space where listed; **payloads use Esplora REST
shapes** (`build_tx_json` / `tx_status_json` / tip height+hash).

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
are deferred. satd’s native BIP 157/158 index is noted (not scheduled) in
[`docs/peer-clients.md`](./docs/peer-clients.md).

## Deferred surfaces

Core wallet RPC, fee-estimator research quality, BIP331 native wire enum,
durable orphans: **out of scope** for this plan. GBT **template RPC** is
shipped (see above); stratum / pool software is not.

**Permanent non-goals for Electrum/Esplora:** graphical explorer backends
(address-prefix autocomplete, global search, explorer-only catalogue APIs).
