# Compatibility with Bitcoin Core

Pinned reference version: **Bitcoin Core v32.1** (same pin as
[`docs/core-functional.md`](./docs/core-functional.md) and nightly fuzz).
BIP324 v2 interop. Package wire tracks BIP331 when rust-bitcoin exposes the
messages (**Q-48** / RB-007).

**Experimental 0.x** — not a production Core or Fulcrum replacement. Design
contrasts: [`docs/architecture.md`](./docs/architecture.md). Lab mainnet:
[`docs/experimental-mainnet.md`](./docs/experimental-mainnet.md).

A Core, Electrum, or Esplora difference that looks like a bug is often
**intentional**. Read this file before changing shipped behavior. Name the
row you are changing; do not mix unrelated dialect work into the same step.

## Active product track

Full **P2P participant** (blocks + tip-mode tx relay) and **wallet-client
backends**: in-process **Electrum** (confirmed + unconfirmed, libre-relay-class
admission) and optional **Esplora-compatible REST** for the same role (history,
UTXO, broadcast, block/tx fetch by id). Optional **Core-class JSON-RPC subset**
(see [`docs/rpc.md`](./docs/rpc.md)) — not full Core wallet / mining parity.
**Scripthash index (`--sh-index`) defaults off**. Electrum/Esplora **start without it**; address/scripthash methods fail closed (`scripthash index disabled`). Txid/outpoint/block/broadcast/fees work. Which wallets use that surface: [`docs/wallets.md`](./docs/wallets.md). Lightning chain sources: [`docs/lightning.md`](./docs/lightning.md).
On/off costs and start/IBD/tip behavior: [`OPERATOR.md`](./OPERATOR.md)
(Scripthash index). Disable later leaves SH files on disk; follow does not
wait on SH materialize.

### Query surface intent: wallet clients, plus 0.8 electrs drop-in

**Goal:** serve **wallet software** (Electrum, Sparrow, custom wallets, light
clients that already know their addresses/scripthashes or exact txids/block
ids).

**0.8:** drop-in **mempool/electrs or Blockstream electrs HTTP** so nginx
`/api/` can retire electrs. Core JSON-RPC for that stack is TCP plus an
opt-in Core cookie (`--rpc-cookie-file`), which stock mempool `CORE_RPC`
uses unpatched; a unix-socket patch (filesystem auth) stays optional.
mempool.space **Node `/api/v1/`** (MariaDB, cubes, mining, lightning) stays
their process. Address-prefix
search is **not** in 0.8 (**404**). Surface table below.

**Non-goal (stays):** address-prefix autocomplete, Liquid/assets, in-binary
mempool.space catalogue UI (`/api/v1/`). Opt-in `GET /block-template`
is GBT (same JSON as RPC), not explorer search. Block/tx **by full id** and
address/**exact** scripthash history exist so wallets, APIs, and (after 0.8)
electrs-shaped explorers can verify and sync.

`--max-sh-creates N` (default **10000**; **0** = unlimited) refuses an unpaged Electrum/Esplora SH
joins with more than N creates: Esplora HTTP **503**, Electrum JSON-RPC error
`scripthash join exceeds --max-sh-creates`. Stats stay full when under the cap.
`--heavy-sh-creates N` (default **10000**; **0** = off) runs unpaged joins with
more than N creates one at a time across the node; lighter joins stay parallel.

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
| Admission policy | **Libre-relay-class** (0.1 sat/vB, no dust, full RBF). P2P admits any nVersion. RPC-submit (`sendrawtransaction` / `testmempoolaccept` / `submitpackage`) still rejects `"version"` outside 1/2. Feerate, RBF, min relay and `-blockmintxfee` use Core's sigop-adjusted size `max(weight, sigop_cost × 20)` (`--bytes-per-sigop`, `0` disables). Cluster and package count/size limits and the block weight budget count raw weight, unlike Core, so the adjustment never becomes a per-tx sigop cap. No 16,000 sigop-cost standardness cap; admission and template selection share a strict 80,000 minus `--block-reserved-sigops` budget (default reserve 400). P2P `accept_tx` has the minimum relay feerate and no absurd-fee or `-maxtxfee` cap; RPC submit keeps Core's default `maxfeerate` of 0.10 BTC/kvB (`0` unlimited). That split is intentional: the signer chose the fee. Mempool fee math checks `u64` overflow (`bad-txns-txouttotal-toolarge`), not `MAX_MONEY`. Block connect rejects an output or an output sum above `Amount::MAX_MONEY`. A mainnet input sum cannot exceed that cap, because those coins were rejected at connect | Standardness + policy knobs (nVersion 1/2, `MAX_STANDARD_TX_SIGOPS_COST` 16,000, `-bytespersigop`) |
| Compact blocks | BIP152 **v2** receive + reconstruct + `getblocktxn` serve. Fill is live mempool + orphanage + `extra_compact` (cap 100). Outbound extra prefill is **on** unless `--prefill-compact=0` (10 KiB cap, extra-pool last; generate / submit / NewPoWValid pack txs not in the live mempool without delaying forward) | v1/v2 high-bandwidth + `extra_txn` cache (`-blockreconstructionextratxn`); Core #35558 prefill still unmerged |
| WTx inventory | BIP339 when peer also sends `wtxidrelay` | BIP339 |
| GetAddr | Core `MAX_ADDR_TO_SEND` / `MAX_PCT_ADDR_TO_SEND` (**1000** / **23%**), 24h per-bind cache. Named copies in `rbitcoin-net` — do not “improve” without a named reason to diverge. `MAX_ADDR_MAN` (8192) is **our** HashMap DoS cap and must stay above `1000/0.23`. DNS and fixed inject, IBD and steady-state addr gossip, getaddr replies, and peers-file load ignore unroutable clearnet (loopback, private, `0.0.0.0/8`, CGNAT, link-local, documentation including `3fff::/20`, benchmarking (`198.18.0.0/15` and `2001:2::/48`), class E, and the matching IPv6 ranges). 6to4, well-known NAT64 `64:ff9b::/96`, local NAT64 `64:ff9b:1::/48`, IPv4-compatible `::/96`, and SIIT `::ffff:0:0:0/96` stay only when the embedded IPv4 is routable and the non-IPv4 bits are zero. Teredo `2001::/32` is dropped. Addr gossip also drops port 0 except I2P (advertised with port 0), Tor v2, and CJDNS addresses outside `fc00::/8`. Unknown BIP155 network ids are still relayed. `addpeeraddress` and `--connect` do not. Onion, I2P, and CJDNS are not IP bogons | Core new/tried buckets (~80k); same 1000 / 23% |
| Package submit | RPC `submitpackage` / Esplora `POST /txs/package` (no P2P package command) | BIP331 wire |
| Pruning / GUI | Unpruned: `seqsigwit.body`. `--prune-seqsigwit`: watermark + `NETWORK_LIMITED`, kept witness is 288 height files under `store/seqsigwit.window/` plus a RAM cap (`--prune-seqsigwit-ram-threshold-bytes`, `0` = files only). Not a rolling stem. Not Core `-prune` of headers/txout | Supported |
| Mining template RPC | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` (selector; no stratum) | GBT + stratum / pool stack |
| SV2 Template Distribution | In-process TDP v2 server over Noise NX (`--sv2-tp-listen`, default off): `NewTemplate` / `SetNewPrevHash` per tip, `NewTemplate` on a same-tip fee gain (`--sv2-tp-fee-delta`, `--sv2-tp-template-interval`, sv2-tp defaults), `RequestTransactionData`, `SubmitSolution` → block accept. No templates during IBD; every template on the tip kept, up to 64 per session. No plaintext, no pool / JD roles | No TDP in Core; sv2-apps `bitcoin-core-sv2` bridges Core's IPC mining interface to TDP |
| Wallets | Electrum clients (requires `--sh-index`) | Descriptor + legacy |
| Scripthash index | Optional (`--sh-index`, default **off**); bulk at tip when on | External ElectrumX / Fulcrum; Core `-txindex` is different (txid→block) |
| JSON-RPC | Documented **subset** ([`docs/rpc.md`](./docs/rpc.md)); Bearer token or opt-in Core cookie (`--rpc-cookie-file`), no `--rpcuser` / `--rpcpassword`; `rbitcoin-cli`. `--rpc-work-queue` defaults to **16** (HTTP occupancy, 503 when full; **0** is that default); a JSON-RPC array is one POST | Full Core RPC; `-rpcworkqueue` is in-flight HTTP jobs (503) |
| GetData serve | Every hash is served in order. While **16** (`MAX_SERVE_BLOCKS`) getdata bodies or 4 MiB sit in the peer's queue (RAM cap), the rest waits on the session and no new message is read; none is dropped. Pings and the ping timeout still run | Core `ProcessGetData` pauses on `fPauseSend` and serves the rest before the next message |
| Inbound eviction victim | After Core-shaped protect (netgroup / recent block / recent tx / min-ping / 8 longest-connected), disconnect the **newest** inbound in the largest remaining netgroup. A fully protected set rejects the new inbound | Core `SelectNodeToEvict` youngest in the oldest netgroup |
| Tx-relaying inbound share | Peers whose `version.relay` is set hold at most half of `--max-inbound` (fixed; no `-inboundrelaypercent`). The check runs once the handshake completes: past half, the new peer evicts another tx-relaying inbound under the same protection, or is closed after VERACK | Core #28463: `-inboundrelaypercent` (default 50). The check runs on VERSION, so a closed peer never gets VERACK |
| `--sp-tweaks-dust` | Serve-time floor default **1000** sat (omit P2TR outs `value <=` floor). **546** matches Cake electrs. Not Cake/Electrum protocol | n/a (Electrum tweaks are not Core) |
| IBD empty-headers EOF | Empty `headers` to **our locator** + idle path latches `headers_done` even if a peer advertises a taller less-work height / junk `version.start_height`. A proven header walk at the tip that every taller peer failed to extend also ends IBD | Core header sync follows most-work; advertised `start_height` is not a remaining header count |
| BIP94 | Not implemented. There is no testnet4 chain and no `-test=bip94`. A retarget multiplies the parent, and a difficulty-boundary timestamp only has to be after the median of ancestor timestamps. This does not fork mainnet, testnet3, signet, or default regtest | On testnet4, and on regtest only with `-test=bip94`, a retarget multiplies the first block of the period (that parent may be a min-difficulty exception) and a difficulty-boundary timestamp more than 600 seconds before its parent is `time-timewarp-attack` |
| Milestone script skip | A height-only `--milestone HEIGHT` skips scripts at and below that height with no anchor hash, including when the header lookup is empty. The default anchor skips once two height-to-hash lookups match: this block, and the anchor hash at the anchor height. It does not walk parents, does not read `min_work_be`, and does not require two weeks of burial. Prevouts, double spends, maturity, and fees still run. An output whose script starts with `OP_RETURN`, or is longer than 10,000 bytes, is still not a coin under the skip | Core runs scripts unless the assumevalid block is an ancestor, the best header is on that chain, chain work meets `nMinimumChainWork`, and the proof-equivalent time from the assumevalid block to the best header is more than two weeks |
| Invalid marks across restart | A block that failed connect on a consensus rule stays invalid across restart (`store/block.invalid`, the newest 4096). An operator `invalidateblock` does not: it lasts until the process exits | Both live in the block index (`BLOCK_FAILED_VALID`) and survive restart |
| `--trust-peer ADDR` | Default off. One peer (see [`docs/operator/operations.md`](./docs/operator/operations.md)). Checks still run; this is not a faster script skip. The waiver applies only to a block or transaction from that peer's current session. A warn-and-apply fault logs `trust-peer: applied block <hash> height <h>: <reason>` or `trust-peer: applied tx <txid>: <reason>` (the same reason text as today's reject). A script fault's applied line, and a lookup or load structural warn, are written only after that block connects. A header fault's applied line is written when that header check is kept. The fault is kept: script failure where scripts run; header median time, future time, and version; BIP34; signet solution, including a signet block that does not parse (`signet: no witness commitment` or a malformed solution; encoding a signet commitment stays a hard error); non-final locktime; sigop limit; subsidy mismatch; BIP68; immature coinbase; BIP30 overwrite (the new outputs are the ones a later spend resolves). Mempool script, immature, non-final, and BIP68 faults from that session stay through reorg eviction and a replacement that does not commit. Opening with the mode off removes those transactions. If a marked body or a descendant of it cannot be removed, open fails and the mark stays. The mark is loaded again only while the mode stays on. A block template skips a marked transaction, and a locally submitted block rechecks that transaction's script. A local non-final transaction is rejected. Two warnable faults in one block are two lines and one connect. The trusted session is not selected as a BIP152 high-bandwidth peer. A hostname used as `--trust-peer` or `--connect` keeps one current socket: a later resolution replaces it and disconnects the previous socket when no other current target still uses it. Proof-of-work (`high-hash`, `bad-diffbits`, a target above the pow limit) is not applied: the header is not stored and chain work does not move. A body that does not match its header (merkle root, witness commitment, witness nonce, or witness bytes before segwit) is not applied, stays refetchable, and is not marked permanently failed. Other hard rejects are unchanged: undecodable bytes; empty or mis-shaped block; duplicate txid; oversize weight; missing or already-spent prevout; duplicate input; same-block future spend; unspendable or genesis-coinbase spend; a value that does not fit a u64 fee. A missing confirmed mempool parent still leaves the pool. Local submit, `submitblock`, `getblocktemplate` proposals, SV2 block submission, `sendrawtransaction`, Electrum broadcast, and Esplora `POST /tx` stay strict and do not log a `trust-peer:` line. A wrong proposal prev stays `inconclusive-not-best-prevblk`. With `--proxy` or `--onion`, this node's own transactions are still announced on that one session. Isolated broadcast stays off, so no other peer is dialed and no other peer's transactions are waived. Standardness, dust, minimum relay fee, replace-by-fee, package limits, negative fee, and a missing parent stay policy rejects and are not `trust-peer:` lines. Flag off: those faults still reject, high-bandwidth selection is unchanged, and the log has no `trust-peer:` substring. `getnetworkinfo.warnings` and `getblockchaininfo.warnings` contain one string naming this peer while the mode is on, and omit that string when the mode is off. That string does not run `-alertnotify`. The template `warnings` key holds that string while the mode is on, and is absent when the array would be empty. The node will store and serve a chain it considers invalid | Core has no single-peer warn-and-apply mode |
| Equal-work fork choice | A connected tip is replaced only by strictly greater chain work, or by `preciousblock` at equal work. After `invalidateblock`, equal work prefers precious, then the earlier held tip. Header ranking before either chain is connected also stays with the chain already chosen when work is equal ([`docs/architecture.md`](./docs/architecture.md) layer 1, “equal work keeps the first seen”). A block that was stored earlier but was not yet connectable does not take the tip later | When work is equal, Core prefers the block seen first (`nSequenceId`). A block stored earlier but not yet connectable becomes the tip once it can be connected, even if a later equal-work block is already the tip. Neither rule makes a block valid on one side and invalid on the other |

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
| Blockchain (`getblockchaininfo`, `getblockcount`, `getbestblockhash`, `getblockhash`, `getblock`/`header`, `getdifficulty`, `getblockstats`) | done (`getblockstats` from `txstat` when stamped; size and count fields match Core, including `utxo_increase_actual`; omit coins-DB `utxo_size_*`) |
| Network (`getnetworkinfo`, `getconnectioncount`, `getpeerinfo`, `addnode`, `disconnectnode`, `addconnection`) | done (BIP324 v2-only; `getnetworkinfo.version` is the fixed Core 0.19 client integer `190000`, semver stays in `subversion`, `protocolversion` is `70016`; peer `version` / `conntime` / `lastsend` / `lastrecv` / `timeoffset` / `synced_*` from session state; hostname `addnode` / `--connect` resolve at dial and retry until live) |
| Mempool / rawtx (`getmempool*`, `getrawtransaction`, `sendrawtransaction`, `testmempoolaccept`) | done (Libre; RPC `maxfeerate` / `maxburnamount` / `"version"` only) |
| Coin / MiniWallet (`gettxout`) | done |
| Index / tips (`getindexinfo`, `getchaintips`, `waitforblock*`) | done (`txindex` = Class A reconstruct) |
| Fee (`estimatesmartfee`) | done (**10-minute inclusion** — not Core historical) |
| Decode (`decoderawtransaction`, `decodescript`, `validateaddress`) | done (node subset; official Core dialect scripts stay `rpc-dialect`) |
| Regtest `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` / `submitblock` / `setmocktime` | harness (`generate*` also on signet whose challenge is exactly `OP_TRUE`; `setmocktime` / `mockscheduler` stay regtest; `submitblock` is all networks) |
| `invalidateblock` / `reconsiderblock` / `preciousblock` | done |
| Mining template (`getblocktemplate`, `getmininginfo`, `prioritisetransaction`, `getmempoolcluster`) | done (no stratum / wallet keys; `getdeploymentinfo` does not list BIP9 `testdummy`) |
| Wallet RPC; `createrawtransaction` / `combinerawtransaction`; `gettxoutsetinfo`; `scantxoutset` | **never** (no UTXO set, no descriptor scan). The functional harness answers MiniWallet `raw()` `scantxoutset` from Esplora; it does not implement descriptors or `gettxoutsetinfo` |

## Electrum surface

| Method | Status | Notes |
|--------|--------|-------|
| server.version / banner / features | done | Banner: libre-relay-class. `server.version[0]` is `rbitcoin-electrs <workspace.package.version> electrumx` — **not electrs**; see below. `server.version` negotiates: omitted → `1.6`; `"1.4"` → `1.4`; `["1.4","1.4.2"]` → `1.4.2`; `["1.4","1.6"]` → `1.6`; `"1.4.2-asof"` (or a range containing it) → the legacy as-of dialect, which pins 1.4.x shapes; `asof:` does not need it. First call wins. `features.protocol_max` is `1.6`; `features.asof_protocol` names that legacy dialect. `features.genesis_hash` is display-order hex (refuse a wrong-chain server before a tweaks scan). `features.tweaks` / `silent_payments` advertise the method; they are not a substitute for the stream. |
| JSON-RPC batch | done | A line holding a JSON array is a JSON-RPC 2.0 batch: one array line back, same order, each slot `{id, result}` or `{id, error}`. Read-only items (scripthash `get_history` / `get_balance` / `listunspent` / `get_mempool`, `transaction.get` / `get_merkle` / `id_from_pos`, `block.header(s)`, `estimatefee`, `outpoint.get_status`, `mempool.get_fee_histogram` / `get_info`) run up to half the node's blocking pool at a time (at least 1; 2 on a 4-thread pool), and each reports only its own dispatch time; any other item waits for every earlier slot, then runs alone, so a `subscribe` is seen by the items after it. Slots are written in request order as soon as each is answered, and slot `i` is written before read `i + window` starts. A notification (no `id` member) is skipped: it is not run and gets no slot, and a batch of only notifications writes nothing. A non-object item gets a `-32600` `Invalid Request` slot. `[]` is one `-32600` `empty batch`; more than 345 items is one `-32600` `batch too large`. `blockchain.tweaks.subscribe` and `blockchain.silentpayments.subscribe` stream several lines, so inside a batch they get a `-32600` slot; send them alone. |
| blockchain.tweaks.subscribe | done | **Stream**, not a one-shot result: JSON-RPC `result` is the **first** height only; remaining heights are unsolicited notifications; `{"message":"done"}` ends the **chunk** (60s wall at a wave boundary, or the requested `count` if sooner) — Cake electrs clamps `count` to 1000 instead. Cake Wallet resubscribes from `syncHeight+1` ([cake_wallet#3574](https://github.com/cake-tech/cake_wallet/issues/3574) persist still lags one event). [kiss-bdk](https://github.com/kkdao/kiss-bdk) today treats `done` as the asked range finished ([kiss-bdk#10](https://github.com/kkdao/kiss-bdk/issues/10)). Each height carries tweak + txid + taproot `output_pubkeys` (client scans locally; no block fetch). Naive walk, or `--sp-tweaks` thin index (`len:tweak` only; one `txout` span per wave; the first height shares that span when indexed). Pre-taproot: **one** notify with ≤1024 empty height keys (Cake `fromJson` last key is progress); probe `[0,1,false]` stays `{"0": {}}`. Param `[2]` (Cake `historicalMode`): `false` **cut-through** (omit confirmed-spent P2TR outs / txs); `true` keeps spent outs. Serve-time `--sp-tweaks-dust` (default **1000**) omits P2TR outs with `value <=` the floor (`0` = all; **546** matches Cake electrs `sp_min_dust`). Sparrow Silent Payments uses Frigate `blockchain.silentpayments.subscribe` (server-side scan) — **not** this method. Cake isolate may still hardcode `electrs.cakewallet.com`. |
| headers / block headers | done | Tip push on subscribe |
| scripthash history / balance / listunspent | done | Unconf when mempool attached; `get_history` optional BCH-style `from_height` / exclusive `to_height` (`-1` = tip + mempool); 1-arg = full history; a `from_height` above 0 scans that block window and is served above `--max-sh-creates` (open history, and a window that starts at height 0, still refuse above the cap); unconfirmed `get_history` rows include `fee` (same as `get_mempool`); `listunspent` mempool height is `0` or `-1` (unconfirmed parent); **subscribe status always full**; `blockchain.scripthash.unsubscribe` returns whether the connection was watching (frees a slot under `--electrum-max-subs`, default 10000 per connection). `listunspent` loads `txid.body` only for unspent creates; one TCP connection reuses the last SH outs+spent join until SH-view **hash** changes. Confirmed methods stamp live tip: a RAM SH head (pending write-behind) joins with durable SH so mempool can drop confirmed txs without a hole. Durable Class B seed waits until after tip announce. `get_history` skips mempool rows already in the confirmed list. `server.features.chain_tip = true`. Trailing **`asof:<blockhash>`** after the official args, on any negotiated protocol (`server.features.asof`): confirmed rows as of that still-live ancestor **at or behind visible SH** (durable + pending), **no** mempool; stamp is the asof block; unknown hash or ahead of visible SH → `asof not on chain`. Prefix keeps it off the future positional-string landmine. Electrum `protocol_max` is **1.6**. |
| scripthash.get_mempool / subscribe | done | Status on mempool announce **and** when SH applies a height that creates or spends the hash (posting-list probe; no Class A expand on a miss). Headers subscribe still live tip. Reorg (`TipNotify.reorg_from_height`) restatuses every watch even if the new block misses the script. Status preimage is the protocol's `txid:height:` for every row: Electrum desktop recomputes it from `get_history` and drops the history on a mismatch. A same-height replace that keeps every `(txid, height)` keeps the status; the `chain_tip` stamp carries that A-B-A. Row **order** is confirmed height-asc then mempool tail, same as `get_history`. A script with no history has status `null` (subscribe reply and pushes), never `""`: wallets read any non-null status as a used address. `unsubscribe` is implemented. |
| transaction.get / get_merkle | done | get falls back to mempool unless `asof:`; confirmed responses stamp `chain_tip`. Verbose get is electrs-shaped: `time`/`blocktime`/`confirmations`/`blockhash` from the confirming header (mempool verbose is `confirmations: 0` with no block stamp), plus `vin`/`vout`/`size`/`version`/`locktime`/`hash` (wtxid) decoded from the hex already loaded. Trailing `asof:<blockhash>` (as for scripthash, on any protocol): get returns the tx only if confirmed at or behind that ancestor (**no** mempool); get_merkle rejects a `height` above the asof pin (`asof not on chain`). `id_from_pos` is a txid string; third arg `merkle=true` returns `{tx_hash, merkle}` (same walk as `get_merkle`). |
| transaction.broadcast | done | Mempool accept + P2P inv. `broadcast_package` wraps `accept_package` (Electrum **1.6**; P2P BIP331 still Q-48). |
| relayfee / estimatefee / histogram / `mempool.get_info` | done | `minrelaytxfee` is the configured minimum. `relayfee` and `mempoolminfee` are the enforced floor. `incrementalrelayfee` stays 100 sat/kvB. Estimates are the 10-minute flow/history product ([`docs/mempool-fee-estimation.md`](./docs/mempool-fee-estimation.md)), at least `mempoolminfee` like `estimatesmartfee`. `mempool.get_info` is 1.6 (`minrelaytxfee` replaces `relayfee` for 1.6 clients; `relayfee` stays for 1.4). |
| outpoint.get_status / subscribe / unsubscribe | done | Electrum **1.7** methods; `protocol_max` stays **1.6** until `scriptpubkey.*`. Spent = confirmed-strong or mempool. |
| silentpayments.subscribe / unsubscribe | done | Frigate remote-scanner: session-only scan key; historical + tip notifies via tweak index / naive `tweaks_for_height`. Not Cake `tweaks.subscribe`. |
| TLS | external | terminate at reverse proxy for **clearnet**; onion is plain TCP (`ADD_ONION` to loopback). In-binary 50002 + TLS is parked **Q-63**. |

### Protocol versions

`features.protocol_max` is **1.6** (plus the legacy as-of dialect `1.4.2-asof`).
Electrum 4.8 wallets speak 1.4–1.6; ElectrumX advertises 1.7. `block.headers`
is concatenated `hex` for 1.4.x and a `headers` list for 1.6.
`scriptpubkey.*` still missing — do **not** advertise 1.7 yet.

P2P BIP331 package messages remain **Q-48**. Local Electrum
`broadcast_package` uses the same `accept_package` as RPC/Esplora.

### Why `server.version` says electrs

We are **not** electrs. Cake Wallet `getNodeIsElectrs()` lowercases
`version[0]` and requires the substring `electrs` before it will call
`blockchain.tweaks.subscribe`. Sparrow sends JSON-RPC batches when the
lowercased `version[0]` contains `electrumx` (or starts with `electrs/` at
0.9.0 or later); otherwise it sends one request per line. BlueWallet stops
batching when `version[0]` starts with `electrs` (case-sensitive) unless
the first word is exactly `electrs` at 0.9.0 or later. The first element is
therefore `rbitcoin-electrs <ver> electrumx` (`ver` from
`workspace.package.version`): Cake will probe tweaks, Sparrow will batch,
and BlueWallet keeps batching. Other tweaks clients (kiss-bdk) do not need that
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
| Electrum TCP | JSON-RPC extra members `chain_tip` / `chain_tip_height` next to `result` (ping/version omit). `server.features.chain_tip`. | `result` shape unchanged. Status preimage stays the protocol's `txid:height:`; a same-height replace shows in `chain_tip`, not in the status. Notification `params` stay `[scripthash, status]`. |

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

Electrum clients that want as-of add a trailing `asof:<blockhash>`
argument to a method that takes it, on any negotiated protocol. A 1.6
connection keeps its 1.6 shapes. `server.version(name, "1.4.2-asof")` (or a
`[min, max]` range containing that string) is still accepted for clients
that negotiate it, and pins that connection to 1.4.x shapes.
`server.features.protocol_max` stays `"1.6"`. As-of discovery is
`server.features.asof`, not `protocol_max`; `asof_protocol` names the legacy
dialect and is not needed to send the token.

## Esplora REST surface

Request and response shapes: [`docs/esplora-openapi.yaml`](./docs/esplora-openapi.yaml) (OpenAPI 3.1).

Plain HTTP via `--esplora-listen` / conf `esplora_listen` (default **off**). TLS
via reverse proxy for **clearnet**; onion is plain TCP (`ADD_ONION` to loopback).
App `ServeLimits` always on (same model as Electrum).

| Endpoint group | Status | Notes |
|----------------|--------|-------|
| Tip | done | `/blocks/tip/height`, `/blocks/tip/hash`. REST stamps `X-Bitcoin-Chain-Tip` / `X-Bitcoin-Chain-Tip-Height` (CORS-exposed): **live tip** for block/tx/header routes; **SH watermark** for `/address/` and `/scripthash/` so wallet JSON matches the SH join. Empty chain omits them (existing 503). If the pin dies mid-request: **503** `chain view moved`. |
| Blocks list | done | `/blocks`, `/blocks/:start_height` (10 summaries, newest-first) |
| Block | done | `/block/:hash` JSON, `/raw`, `/status`, `/header`, `/txids`, `/txid/:i`, `/txs[/:start]`. JSON `bits` is the compact-target **u32** (Esplora schema, not Core hex). `size` / `weight` are BIP144 total size and BIP141 weight (witness included). |
| Tx | done | `/tx/:txid` full JSON, `/hex`, `/raw`, `/status`, Electrum `/merkle-proof`, BIP37 `/merkleblock-proof`, `/outspend(s)` (`vin` from the spent slot; unspent omits it). Below seqsigwit prune: JSON is 200 partial (`pruned: true`, vout+status, empty `vin`); stamped `txstat` fills `fee`/`size`/`weight`. Mempool-only txs (not in Class A) use the wire body from the mempool hub (`vin`/`vout`/`size`/`weight`/`fee`/`sigops`, `status.confirmed` false) including `GET /tx/:txid/status`. Live `/outspend(s)` overlay mempool spends of confirmed coins; `?asof=` omits mempool. `?asof=<hash>` on `/status` and `/outspend(s)`: confirmed/spent as of that ancestor; 404 if not on chain. `GET /tx/:txid?asof=` stays **404**. |
| Output by position | done | `GET /block-height/:height/tx/:index` is the same JSON as `GET /tx/:txid` for that confirmed tx, including a pruned partial and the genesis coinbase. A missing height or index is **404**. A non-integer segment is **400**. `GET /block-height/:height/tx/:index/out/:vout`, `GET /tx/:txid/out/:vout`, and `POST /block-heights/txs/outs` return one confirmed output: Esplora vout fields plus boolean `spent` and `status` of the creating transaction. `spent: true` is **200** and still includes the script and value (`gettxout` returns null once spent). A mempool spend stays `spent: false` with the script present. Genesis coinbase outputs, a mempool-only tx, a header with no body, and a missing vout are **404** on a GET and JSON `null` in a batch slot. The batch body is `[[height, index, vout], …]` (same length and order, duplicates kept). One bad element is **400** for the whole body. More than 300 is **422** `body too long`. An empty body is **200** `[]`. `?asof=<hash>` on all four pins one best-chain ancestor: tip headers and status name that pin, a height above it is **404** or batch `null`, a later spend stays `spent: false`, and a dead or disconnected hash is **404** `Not Found` for the whole GET or POST (no sibling at that height). `out` is this output. `outspend` is the spender. No `--sh-index`. |
| Address / scripthash | done | stats + `/utxo` + `/txs` + `/txs/mempool` + `/txs/chain[/:last_seen_txid]` + `/txs/summary[/:last_seen_txid]` (dialect; next row). `/utxo` matches Electrum listunspent (mempool funding + drop mempool-spent confirmed); `/txs` and `/txs/mempool` use full Esplora tx JSON for mempool-only rows (wire from the hub). `?after_txid=` on `/txs` and `/txs/summary` skips through that tx (mempool then chain); unknown or unparseable → **422** `after_txid not found`. A mempool-only cursor past the first 50 mempool rows returns the confirmed page. `POST /addresses/txs` and `POST /scripthashes/txs` (and `/txs/summary`) take a JSON array (max **300**; over → **422** `body too long`); unique scripts join once per request and merge newest-first into one page of 25 confirmed rows (mempool rows stay in front on `/txs`, 50 per script). A later page walks past each script's first 25. Unix/loopback `X-Rbitcoin-Client`: last-1 GET join + last-bulk POST (16 MiB packed/client), 30s idle, 256 clients, singleflight on the same `(client, sh)`. Public TCP ignores the header (stack-local join). Concurrent different GET scripts replace last-1. Unbounded process LRU stays **X-M3**. Needs SH finalize. Stamp is visible SH (durable + pending write-behind), matching live tip while jobs sit in RAM. `?asof=<hash>` on `/`, `/utxo`, `/txs`, `/txs/chain`, `/txs/summary`: confirmed join at that ancestor **at or behind visible SH**, **no** mempool; headers are the asof hash; 404 if not on chain or ahead of visible SH. |
| `/txs/summary` | dialect | **Not** in Blockstream Esplora [`API.md`](https://github.com/Blockstream/esplora/blob/master/API.md). Compact `{txid, value, height, time, tx_position}` like mempool.space `/address/:addr/txs/summary`. Confirmed only (25/page, newest first, including a multi-script post of that same merged page); path cursor `/:last_seen_txid` and mempool.space `?after_txid=` (unknown → **422**). `value` is net sats for that script in that tx (funded − spent). `time` is the confirming header timestamp (`0` if the header is missing). `tx_position` is that tx's index in the block. Mempool rows stay on `/txs` and `/txs/mempool`. A page is served above `--max-sh-creates`; unpaged stats and `/utxo` still **503**. |
| Mempool / fees | done | `/mempool`, `/mempool/txids`, `/mempool/txids/page[/:last]`, `/mempool/recent` (accept-order ring), `/fee-estimates` (sat/vB at the estimator's 1 sat/kvB resolution, each at least `mempoolminfee`; a target without an estimate is left out; when none has one, mainnet is **503** `fee estimates unavailable` and every other network is **200** `{}`). mempool.space `/api/v1/fees/recommended` is its backend's surface, not served here (**404**) |
| `POST /tx` | done | broadcast via mempool hub; **503** if hub absent. `GET /broadcast` is not served (**404**). |
| `POST /txs/test` | done | JSON array of hex (max 25) → `MempoolHub::test_accept` (no admit). `?maxfeerate=` is BTC/kvB like electrs (`0` unlimited; omitted → 0.1 BTC/kvB). |
| `POST /txs/package` | done | JSON array of hex txs → `accept_package`; **503** without hub; max 25 txs |
| electrs `/internal/*` | done | **Unix listen only.** TCP GET/POST `/internal/…` → **404** (same unknown-path fallback). `POST /internal/txs` (400 on unparseable id; missing omitted); `POST /internal/mempool/txs` (mempool only); `GET /internal/mempool/txs[/all or /:last]` (txid-sort pages, default `max_txs=10000`; `/all` registered first); `GET /internal/block/:hash/txs` (full list; public `/txs` stays 25/page); `POST /internal/txs/outspends/by-txid` (same-length slots, unknown → `[]`); `POST /internal/txs/outspends/by-outpoint` (`txid:vout`; malformed → `{"spent":false}`). Snapshot JSON is published on the hub (no admit-path build). `GET /mempool/txids/page` is public electrs (both listeners). |
| Unix listen | done | `--esplora-listen` filesystem path (mode **0660**). Public REST plus `/internal/*`. TCP `--esplora-listen host:port` never mounts `/internal`. |
| Unknown path | 404 | plain body (including `/address-prefix`) |
| `GET /block-template` | opt-in | `--esplora-block-template` (default off → **404**). Same JSON as RPC `getblocktemplate` `{"rules":["segwit"]}` template mode. **503** without tip. `Cache-Control: no-store`. 15 s cache, invalidated on tip or mempool `template_updates`. No proposal/longpoll HTTP (parked **Q-64**). |
| **Non-goal / never** | — | Address-prefix search, Liquid/assets. mempool.space `/api/v1/` catalogue stays their Node. |

### BlindBit oracle v1 (silent payments over HTTP)

With `--sp-tweaks`, the Esplora listener also serves the BlindBit oracle
v1 HTTP API under `/blindbit/v1/`. BlindBit v2 moved to gRPC. The v1 HTTP
clients are Dana's [`spdk`](https://github.com/cygnet3/spdk)
(`backends/blindbit-v1`), Bull Bitcoin mobile, and blindbitd. Point the client
at `http://host:port/blindbit/v1`. Without `--sp-tweaks` the prefix is **404**.
The served height is the lower of the tip and the tweak index's last height.
Until the index passes its origin there is no served height: `info` and
`block-height` are **503** `no height indexed`, and every height route is **404**.
`tweaks`, `tweak-index` and `utxos` start at Taproot activation (the tweak
index origin) and are **404** below it. `block-hash`, `filter/*` and `spent-index`
answer any height up to the served height; below the origin both filters and
the spent index are empty and read nothing, since no output there can be a
silent payment.

| Route | Notes |
|-------|-------|
| `GET /info` | `network` is the Core `-chain` name (`main`, `test`, `signet`, `regtest`); spdk rejects BlindBit's `testnet`. `height` is the served height (**503** while there is none, never `0`). All three tweak modes are `true`; `tweaks_only` is `false`. |
| `GET /block-height`, `GET /block-hash/:h` | `{"block_height"}`, `{"block_hash"}` (display hex). |
| `GET /tweaks/:h?dustLimit=` | Cut-through: tweaks of eligible txs with a P2TR output not yet spent. `dustLimit` keeps a tx whose largest remaining P2TR output is `>= dustLimit` (BlindBit's edge; **not** `--sp-tweaks-dust`). |
| `GET /tweak-index/:h?dustLimit=` | Every eligible tx; `dustLimit` over all its P2TR outputs. |
| `GET /utxos/:h` | Every P2TR output of every eligible tx, with `spent`. BlindBit drops spent rows over time; spent rows stay here. |
| `GET /filter/new-utxos/:h`, `GET /filter/spent/:h` | BIP158 GCS (P=19, M=784931, keyed by the block hash), `filter_type: 4`. New-utxos holds the x-only key of every P2TR output in the block. Spent holds the spent-index hashes. Built per request from the block's own txs: one `txout` span for the keys, and the input edges plus the txid sidefile for the spends. No parent tx and no witness is read, and nothing extra is stored. A key repeated in one block is written once (BlindBit writes it twice); membership is the same. |
| `GET /spent-index/:h` | First 8 bytes of `sha256(txid ‖ vout_le ‖ block_hash)` (internal byte order) for every non-coinbase input. BlindBit hashes only P2TR prevouts; the input edge does not carry the parent's script, so every spend is hashed here. spdk tests its own outpoints for membership, which a superset answers the same way. Always `{"block_hash","data"}`; BlindBit returns a bare `[]` when empty, which spdk cannot parse. |
| `POST /forward-tx` | `{"data":"<hex>"}` → mempool hub. The answer is the txid as a JSON string (spdk parses it; BlindBit sends an empty 200). Errors are `{"error"}` with **400**, or **503** without a hub. |

A bad height is **400** `could not parse block height`; a height above the
served height is **404** `height not indexed`. Store errors use the
listener's statuses (**404** not found or pruned, **503** rejected or stale)
with an `{"error"}` body. A reorg of that height between
the reads one answer is built from is **503** `chain view moved`; ask again.
Eligibility is BIP-352 as for `blockchain.tweaks.subscribe`.

All `/blindbit/v1/` routes share one limit of requests in flight: half the
node's blocking pool (`available_parallelism`, at least 4). It is taken
before a listener slot, so the ~200 asks spdk keeps open per scan queue there
without holding listener slots. A request keeps its permit until its read
returns, even after a timeout or a client disconnect.

## No Esplora WebSocket

Esplora and electrs have no WebSocket. mempool.space's `/api/v1/ws`
(`want`, `track-address`, `track-tx`, …) is its backend's surface, so
`/ws` and `/v1/ws` are **404** here. Wallets watching live use Electrum
subscriptions, or mempool's backend in front of this Esplora.

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
| 22–27 | getcfilters…cfcheckpt | BIP157 basic while `--block-filter-index` is on. A stop past the filter watermark is silence; an out-of-range request disconnects (Core) |
| 28 | addrv2 | BIP155 |

Long-form (no short ID): `version`, `verack`, `wtxidrelay`, `sendheaders`,
`sendaddrv2`, and unknown/extension commands.

**Not implemented as product features** (short slots 29–36 placeholders, 37
`feature`): decode may reject unknown short IDs. Slots 22–27 are live for
BIP158 basic filters while `--block-filter-index` is on
(`NODE_COMPACT_FILTERS` once filters first reach the tip, `getcfilters`, `getcfheaders`,
`getcfcheckpt`, `getblockfilter`). A request whose stop height is past the
filter watermark is silence, not an empty filter or a short batch. As in
Core's `PrepareBlockFilterRequest`, start past stop, 1000+ `getcfilters`,
or 2000+ `getcfheaders` heights disconnects the peer.

## Deferred surfaces

Core wallet RPC, fee-estimator research quality, BIP331 native wire enum,
durable orphans: **out of scope** for this plan. GBT **template RPC** is
shipped (see above); stratum / pool software is not.

**Permanent non-goals for Electrum/Esplora:** address-prefix autocomplete,
Liquid/assets, in-binary mempool.space `/api/v1/` (MariaDB cubes / mining /
lightning). **0.8** is electrs HTTP drop-in except prefix. Core RPC for that
stack is TCP plus an opt-in Core cookie (`--rpc-cookie-file`, stock mempool);
the unix-socket patch is optional.
