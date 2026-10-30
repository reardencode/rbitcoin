# Core-class JSON-RPC (rbitcoin)

`params` may be a JSON **array** (positional) or **object** (Core named
keys such as `blockhash`, `verbosity`, `txid`, `hexstring`). Missing
required keys are `-32602`; unknown named keys are `-8`.

rbitcoin serves a **documented subset** of Bitcoin Core JSON-RPC over plain HTTP.
A new method is documented in this file in the same change.
This is **not** full Core parity: no wallet, no `createrawtransaction` /
`signrawtransactionwithkey` / `createmultisig` / `sendtoaddress` (those
live only on the Core-functional test proxy, backed by Esplora).
`decoderawtransaction` / `decodescript` / `validateaddress` are a **node
subset** (table below). Official Core dialect scripts (`rpc_decodescript.py`,
`rpc_validateaddress.py`, `rpc_invalid_address_message.py`) stay inventory
`rpc-dialect`; the functional harness does not intercept those names.
`getblocktemplate` / `getmininginfo` are a miner-backend (no stratum). Address history is **Electrum / Esplora** with `--sh-index`.

## `getnetworkinfo.version`

`version` is the hardcoded integer **190000**, Bitcoin Core 0.19.0's
`CLIENT_VERSION` (`10000 * 19` in Core's 0.x packing). Typed RPC clients
compare this field when they choose a response shape. Below 190000,
`bitcoincore-rpc`'s `get_blockchain_info` requires the pre-0.19
`bip9_softforks` map and a `softforks` array, then returns
`UnexpectedStructure` on our object. At 190000 it deserializes the
modern object (`softforks` may be absent; `warnings` may be a string or
an array).

190000 is an RPC shape floor:

- `subversion` stays `/rbitcoin:<semver>/`, plus any `--ua-comment`.
  That string is the software version.
- `protocolversion` stays **70016**, the same integer on the P2P
  `VERSION` message. Peers negotiate with that, with service flags, and
  with the handshake messages. They do not read this field.
- The floor is not derived from the crate semver. Packing `0.7.99` with
  Core's post-22 formula yields 799, which sits under every client
  gate. Packing a later rbitcoin `19.0` or `22.0` the same way would
  collide with a real Core `CLIENT_VERSION`.

The floor stops at 0.19. A higher integer would tell those clients that
later Core RPC is present, including descriptor-wallet calls from 0.21
(`210000`). It would not change what peers accept.

## Operator knobs

| Knob | Default | Meaning |
|------|---------|---------|
| `--rpc` / conf `rpc=` | **off** | Unix JSON-RPC `{datadir}/rpc.sock` (mode 0600; filesystem auth) |
| `--rpc-socket PATH` / conf `rpc_socket=` | **off** | Bind the unix socket at PATH (mode **0660**, group may connect) instead of `{datadir}/rpc.sock`. Implies `--rpc`. For a client running as another user, such as mempool's Node. |
| `--rpc-listen [ADDR]` / conf `rpc_listen=` | **off** | TCP JSON-RPC; omit ADDR → `127.0.0.1` and Core-matching port (8332 / 18332 / 38332 / 18443). Implies `--rpc`. |
| `--rpc-token-file PATH` | `{datadir}/rpc.token` | CSPRNG hex token; TCP `Authorization: Bearer`. Created mode 0600. An existing file must be owner-only on Unix (group or world bits refuse startup). The node does not chmod it. Delete a wider file and start again: a new token is minted only when the file is gone. chmod 0600 keeps a secret that may already have been readable. Windows has no mode bits |
| `--rpc-cookie-file PATH` / conf `rpc_cookie_file=` | **off** | Existing Core-format `username:password` file (no trailing newline) accepted as TCP HTTP Basic in addition to Bearer; it is never created or logged |
| `--rpc-cookie-perms owner\|group\|all` / conf `rpc_cookie_perms=` | **owner** | Widest Unix mode the cookie file may have. `owner` is 0600. `group` is at most 0640 (group read; group write refuses startup). `all` is at most 0644. The node never chmods the file. Windows has no mode bits, so the flag is ignored there. NixOS `services.rbitcoin.rpc.cookiePerms` (default unset, so the unit argv omits the flag) |
| `--sh-index` | **off** | Class B scripthash for Electrum/Esplora address history. RPC by height/hash/txid does not need it |
| `--block-filter-index` | **off** | BIP158 basic. IBD seals them when the flag is on from the start. A later enable still materializes after catch-up. `NODE_COMPACT_FILTERS` is advertised once filters first reach the tip (`getnetworkinfo` lists `COMPACT_FILTERS`), then for the life of the process. `getblockfilter` serves a sealed height, one block whose parent filter is already sealed, and a stale branch back to that sealed fork point. An unsealed best-chain gap is refused. `/rest/blockfilter/` and P2P still serve only heights the watermark covers. Independent of `--sh-index` |
| `--rpc-work-queue N` | **16** | In-flight HTTP RPC (Core `-rpcworkqueue`). One POST is one slot (a JSON-RPC array is still one slot). Full permit is HTTP **503** `Work queue depth exceeded`. **0** is the default queue of 16. |
| `--rest` / conf `rest=` | **off** | Unauthenticated `/rest/` on the RPC listener. Own queue, same depth as `--rpc-work-queue`'s default. The body is read before that permit is taken. Without the flag those paths are 404. |

TLS is external (reverse proxy). Unix socket needs no HTTP header. TCP is
Bearer-authenticated (`{datadir}/rpc.token`) and, only when `--rpc-cookie-file`
is configured, also accepts Core cookie HTTP Basic. `GET /rest/…` is on the same
binds only when `--rest` is set. TCP `/rest/` skips Bearer, matching Core. Routes: `chaininfo.json`,
`blockhashbyheight/<height>.<bin|hex|json>`, `headers/<count>/<hash>.*`,
`block/<hash>.*`, `block/notxdetails/<hash>.*`, `tx/<txid>.*` (chain and
mempool), `mempool/info.json`, `mempool/contents.json`, `getutxos.json`
(confirmed spentness, plus the mempool overlay `gettxout` uses when the path
includes `checkmempool`), `deploymentinfo.json`, and
`blockfilter/basic/<hash>.*` when `--block-filter-index` is on and that height is sealed. A later height is “still in the process of being indexed”, not an empty filter.
No wallet routes. Broadcast and fees stay `POST /`.

TCP and Unix sockets share a 256-connection cap. Each HTTP header and request
body must finish within 30 seconds; waiting for the next keep-alive request
uses the same header deadline. Expiry closes the connection and releases its
slot. These read deadlines do not limit execution of a complete RPC request,
including long-poll calls. The deadlines are fixed, with no operator knob.

The Core-functional proxy still
speaks TestNode cookie + HTTP Basic on the public port and forwards Bearer
to the node. Mixed AuthServiceProxy `{args: […], maxfeerate: …}` is expanded
to a positional list in that proxy (`echo` mixed `{args, argN}` stays on the
node).

### curl example (unix socket, no HTTP auth)

```bash
# After node start with --rpc (binds {datadir}/rpc.sock, mode 0600)
curl --unix-socket datadir/rpc.sock --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' \
  -H 'content-type: application/json' http://rpc/
```

### curl example (TCP Bearer)

```bash
# After node start with --rpc-listen (default 127.0.0.1:8332 on mainnet)
TOKEN=$(cat datadir/rpc.token)
curl -H "Authorization: Bearer $TOKEN" --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' \
  -H 'content-type: application/json' http://127.0.0.1:8332/
```

### rbitcoin-cli

`--datadir` (default `./datadir`) prefers `{datadir}/rpc.sock`.
`--rpc-socket PATH` talks to a node started with `--rpc-socket PATH`. TCP uses
`--rpc-url host:port` (plain HTTP; no scheme). An IP is a strict address
(`10.0.0.1`, `[::1]`); leading zeros and hex forms are rejected. When the flag is omitted and no
socket is present, the client uses `127.0.0.1` and the network RPC port. Bearer
comes from `{datadir}/rpc.token` or `--rpc-token-file`. Prints the JSON-RPC
`result` (strings unquoted).

```bash
rbitcoin-cli --datadir datadir getblockcount
rbitcoin-cli --network regtest --rpc-url 127.0.0.1:18443 getblockchaininfo
```

## shindex matrix

| Capability | `shindex=0` (default) | `shindex=1` |
|------------|----------------------|-------------|
| IBD, tip follow, P2P, mempool relay | Yes | Yes |
| Node JSON-RPC (by height/hash/txid) | Yes | Yes |
| Electrum / Esplora listen | Start; address methods fail closed (`scripthash index disabled`) | Yes after SH tip-ready |
| SH run enqueue / tip bulk | **Skip** | On |

Tip-follow readiness is **independent** of scripthash materialize. Electrum/Esplora
still wait for durable SH when shindex is on.

## Supported methods (Tier 1)

| Method | Notes |
|--------|-------|
| `help` / `getrpcinfo` / `uptime` / `stop` | Control |
| `echo` / `echojson` | Testing RPC. `echojson` is the same method. Returns arguments as a positional array. AuthServiceProxy `{args: [...], argN: ...}` is peeled only here. Mixed `submitpackage`/`sendrawtransaction`/`testmempoolaccept` `{args, maxfeerate}` is expanded in the Core-functional proxy, not on the node. |
| `getblockchaininfo` / `getblockcount` / `getbestblockhash` / `getblockhash` | Chain tip. `getblockcount` / `getbestblockhash` wait for the in-flight tip-accept job (not the rest of a catch-up burst). `headers` is the best known local header height, including IBD's accepted header walk during fresh sync and resume, plus `submitheader` / P2P header tips. It may lead `blocks`; peer-advertised heights alone do not count. `chainwork` is summed header work (regtest 2 per block). `bits` and `target` are the tip compact target. `difficulty` prints with 16 significant digits. `size_on_disk` is a walk of `{datadir}/store` file lengths (plus `--datadir-cold` when split). `verificationprogress` is `blocks / headers` clamped to `[0, 1]` (`1.0` when `headers` is 0). `initialblockdownload` is the Core RPC name for **relay-inhibited**: `--min-chain-work` and `--max-tip-age` after densify/`enter_tip_mode`, not “still catching up”. `--prune-seqsigwit` sets `pruned: true` and `pruneheight` (omitted when off). |
| `getblockheader` / `getblock` (verbosity 0/1/2/3) | Archive reconstruct. `getblockheader` includes `chainwork`, `target`, and `nextblockhash` when the next active block exists. Genesis omits `previousblockhash`. A header that is stored but not on the active chain (reorg or `invalidateblock`) returns `confirmations: -1` and its own `previousblockhash`. `getblock` returns a Class A body for that hash the same way, or a held never-confirmed body. Verbosity 0/2 below `pruneheight` is `-8` `Block not available (pruned data)`; verbosity 1 (txids) stays. Every `getblock` verbosity >= 1 carries Core's `coinbase_tx` (`version`, `locktime`, `sequence`, `coinbase`, and `witness` when the coinbase has one). Below `pruneheight` verbosity 1 still answers (Core cannot) but omits `coinbase_tx`, because pruning drops the sequence, scriptSig, and witness it is made of. Verbosity >= 2 adds a BTC `fee` to each non-coinbase, and verbosity >= 3 adds `vin[].prevout` (the `getrawtransaction` verbosity 2 object). Both come from the stored body's prevout edges, Core's undo data, so a block disconnected by a reorg or `invalidateblock` keeps them. A parent created in that block or an earlier block of its stale branch takes its height from the branch, walked at most 10,000 blocks down to the active chain. A deeper branch is not placed: `getblock` verbosity >= 1 fails with `-1` `side header walk exceeded` before it reads undo, and `getrawtransaction` verbosity 2 with that `blockhash` fails with the `-32603` undo error. A held never-connected body has none, as Core. Stored edges or outputs that do not read fail the call with Core's `-32603` `Undo data expected but can't be read. This could be due to disk corruption or a conflict with a pruning event.`, as does `getrawtransaction` verbosity 2. `confirmations`, `nextblockhash`, and the active check come from one sample of the tip, `confirmed[height]`, and the slot above it, read after the body. The block is reported active only if that sample still holds it and the next block is its child; otherwise the answer is the disconnected-block object. A failed read of the tip or that slot is `-32603`, not a disconnected block. `previousblockhash` is the header's own parent. |
| `getblockstats` | All networks. Stamped `txstat` fee/size/weight/`n_in`. Size and count fields match Core for the keys we return: coinbase is left out of `ins`, fees, `total_size`, `total_weight`, and the segwit totals. `utxo_increase` is every output minus those inputs. `utxo_increase_actual` drops outputs that do not enter the UTXO set (height 0, the two mainnet BIP30-repeat coinbases, unspendable scripts). Omits coins-DB `utxo_size_inc` / `utxo_size_inc_actual` (selecting those names is invalid statistic `-8`). Unstamped leftover reconstructs then lazy-stamps. Reconstruct miss is `block body not in store`. Dummy `blk00000.dat` is shim-only so `rpc_getblockstats.py`'s rename-file needle stays Core-phrased. Pruned unstamped height is `-8` Core pruned text. |
| `getdifficulty` | From tip bits, 16 significant digits |
| `getnetworkinfo` / `getconnectioncount` / `getpeerinfo` | BIP324 v2-only; `getpeerinfo` is the live session table. `timeoffset` is VERSION clock minus connect time (`0` before handshake). `synced_headers` is the height of that peer's advertised best block when we know it, else `-1`. `synced_blocks` is that height when the hash is on our best chain, else `-1`. `getnetworkinfo.timeoffset` is the median of outbound handshake-complete offsets (`0` if none). `mapped_as` is present when `--asmap` / `{datadir}/ip_asn.dat` mapped the peer (Core field; omitted without a map or ASN 0). `version` is the fixed integer `190000` (Core 0.19 client version; see [getnetworkinfo.version](#getnetworkinfoversion)). `localservices` matches advertised `NETWORK\|WITNESS\|P2P_V2`, or `NETWORK_LIMITED\|WITNESS\|P2P_V2` under `--prune-seqsigwit`. `localaddresses` lists `--external-ip` (an IP or a v3 `.onion` host, `score` = Core `LOCAL_MANUAL`). An advertised onion does not mark onion reachable. `networks` has one row each for ipv4, ipv6, onion, i2p, and cjdns: `reachable` follows `--only-net`, a SOCKS proxy for onion, `--i2p-sam`, and `--cjdns-reachable`; `proxy` is `--proxy` for ipv4 and ipv6 and `--onion` (else `--proxy`) for onion. i2p shows the `--i2p-sam` address with `proxy_randomize_credentials` false, even when `--only-net` leaves it unreachable; cjdns dials direct, so it shows no proxy |
| `getnettotals` | All networks. Raw TCP `totalbytesrecv` / `totalbytessent` on live sessions. `uploadtarget` is a Core-shaped stub (`target` 0). |
| `ping` | All networks. Queues a ping on each live session (`null`). |
| `addpeeraddress` | Hidden Core name. Inserts `{address,port}` into addrman RAM (does not rewrite `peers` per call). |
| `getnodeaddresses` | Sample from addrman (`count=0` → all). Optional `network` filter. |
| `addnode` / `disconnectnode` / `addconnection` | All networks. Hostnames resolve at dial (network default P2P port if omitted). `addnode add` and `--connect` retry until a live session. `addnode onetry` dials once and errors if DNS fails. A blank `addnode` node is `-8` for every command. `disconnectnode` by `nodeid` or address. With `--trust-peer`, `addnode` / `addconnection` of any other address fails and names the trusted peer |
| `getmempoolinfo` / `getrawmempool` / `getmempoolentry` | MempoolHub. `getrawmempool` lists a maintained pool, including while peer relay is off, and lists under `-blocksonly`. An empty pool is listed before maintenance. A nonempty pool before maintenance returns `-10` because confirmed transactions may still be in it. `generate` on `-blocksonly` mines that pool; before maintenance it mines the coinbase only. `maxmempool` is the virtual-size byte cap (`--mempool-size-mb` weight budget / 4), the same unit as `bytes`. The `rbitcoin_mempool_max_weight` metric stays weight. `fullrbf` is `true` (Libre always replaces). `maxdatacarriersize` is JSON null (no datacarrier cap). `limitclustercount` / `limitclustersize` are the live cluster caps (count and vbytes). Fee amounts are 8-decimal BTC. `ancestorcount` / `descendantcount` (and size/fee sums) walk the cluster graph. `vsize_adjusted` and deprecated `vsize` are sigop-adjusted virtual sizes; `vsize_bip141` is `ceil(weight / 4)`. `ancestorsize`, `descendantsize` and `chunkweight` are sigop-adjusted (Core `GetAdjustedWeight`, `--bytes-per-sigop`); `weight` is raw. Verbose `fees.{base,modified,ancestor,descendant,chunk}` and `chunkweight` include `prioritisetransaction` deltas; top-level `ancestorfees` / `descendantfees` stay base satoshis. `unbroadcastcount` / `unbroadcast` track `sendrawtransaction` txs until a peer getdata's them. `orphanage.{size,bytes}` is the parked missing-parent side pool (vsize). `permitbaremultisig` is always `true` (Libre has no Core `IsStandard` bare-multisig gate; `--permitbaremultisig` is not a node flag). |
| `getorphantxs` | Hidden operator dump. Verbosity 0 txids, 1 details + `from` peer ids, 2 + hex. Details include `vsize_bip141` and its deprecated alias `vsize`; no adjusted size is available for orphans. Not listed by `help` / `getrpcinfo`. Counts-only `getmempoolinfo.orphanage` is not a substitute. |
| `getrawtransaction` | Class A + mempool. Optional `blockhash` returns the tx only when that block contains it: verbose results set `in_active_chain` (`true` on the active chain, `false` when the stored block still holds the tx). A different block, including a mempool tx that is not in it and a pruned block that does not contain it, is `-5` `No such transaction found in the provided block. Use gettransaction for wallet transactions.` An unknown block hash is `-5` `Block hash not found` and does not fall back to a txid hit. With no `blockhash`, `in_active_chain` is absent and mempool or confirmed lookup still succeeds. Verbose objects share `tx_to_json` with `decoderawtransaction` / `getblock` verbosity 2 (`scriptSig`, `scriptPubKey.type`, `scriptPubKey.desc`). A mempool verbose result adds `vsize_adjusted` from mempool policy; `vsize` stays BIP141. Confirmed and archive-only results omit `vsize_adjusted`. A verbose result for an active block carries `confirmations`, `blockhash`, `blocktime`, and `time`. The same call for an inactive block keeps `blockhash`, sets `confirmations` to `0`, and omits `time` and `blocktime`. Integer verbosity `2` on a confirmed non-coinbase adds a BTC `fee` and `vin[].prevout` (`generated`, `height`, `value`, `scriptPubKey` with `asm`, `hex`, `type`, and `desc`). Verbosity `1` / `true` omits `fee` and `prevout`. A coinbase at verbosity `2` omits `fee` and has no prevout on the coinbase input. A mempool tx at verbosity `2` omits both. With `blockhash` naming a disconnected block, a parent from that block's stale branch keeps its height. Stored prevouts that do not read are Core's `-32603` undo error. An unknown txid is `-5` `No such mempool or blockchain transaction. Use gettransaction for wallet transactions.` Below `pruneheight`: `-8` `Transaction not available (pruned data)` (not `-5`). The genesis coinbase txid is `-5` `The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved` (Core); REST `/rest/tx/` answers `404` `<txid> not found` for it, as Core (its txindex skips height 0). |
| `decoderawtransaction` | All networks. Decode hex. Optional `iswitness`: `false` refuses a BIP141 marker (`-22 TX decode failed`). Extra trailing bytes also `-22`. `scriptSig.asm` is rust-bitcoin, not Core `ScriptToAsmStr` sighash suffixes. Coinbase vin is Core-shaped `{coinbase, sequence}` (plus rbitcoin's `n`), with no `txid`/`vout`. |
| `decodescript` | All networks. `asm`, Core-style `type`, `hex`, `address` when `Address::from_script` succeeds, and `desc`. `desc` is Core's inference with no keystore: `pk`, `multi`, `rawtr`, `addr`, else `raw`, with the BIP380 checksum; `pkh` / `wpkh` / `sh` / `wsh` / `tr` never appear. No `p2sh` wrap, `segwit` wrap, or miniscript. |
| `validateaddress` | All networks. Valid: `isvalid`, `address`, `scriptPubKey`, `isscript`, `iswitness`, plus `witness_version` / `witness_program` when segwit except pay-to-anchor. P2TR and P2A set `isscript` true. Invalid (parse fail or wrong chain): `{isvalid: false}` only — no `error` / `error_locations`. |
| `sendrawtransaction` / `testmempoolaccept` | `sendrawtransaction` is live accept (RPC still admits under `-blocksonly`; serving-only refuse is IBD / tip-not-ready `relay disabled`). `testmempoolaccept` / `submitpackage` return `vsize_bip141` (raw `ceil(weight / 4)`) and `vsize_adjusted` (policy size); deprecated `vsize` retains the adjusted value. These size fields are omitted on rejected rows. `testmempoolaccept` is dry-run (`MempoolHub::test_accept`: prepare + scripts + RBF/cluster checks, no commit / announce / RBF eviction / orphan park). Invalid hex / decode is `-22 TX decode failed` (same as `decoderawtransaction`). Confirmed on the active chain is `txn-already-known` (tip + confirmed-strong); live mempool duplicate is `txn-already-in-mempool`; archive-only after invalidate is not already-known. RPC-submit only: `maxfeerate` is Core **BTC/kvB**, a number or string (default **0.10**; `0` unlimited; `>= 1` is `-8`). It and `maxburnamount` parse like Core `AmountFromValue`: exponent forms such as `1e-05` are read, and a bad or negative amount is `-3`. `sendrawtransaction` caps the base fee at that rate times BIP141 vsize, rounded up to a whole sat (Core `GetFee`); `testmempoolaccept` does the same over sigop-adjusted vsize. `submitpackage` compares each member's modified fee over its sigop-adjusted vsize with the rate, unrounded. `sendrawtransaction` also takes the pre-0.19 boolean `allowhighfees` in that slot (`true` unlimited, `false` the default); btcd `rpcclient` sends it because `/rbitcoin:` sorts below its `0.19.0` subversion check. sendraw over-cap is `-25` configured-max text; `testmempoolaccept` reject-reason stays `max-fee-exceeded`. `maxburnamount` default **0** (valued unspendable / OP_RETURN outs). nVersion outside 1/2 is `"version"`. P2P `accept_tx` does not apply these caps. Multi-tx `testmempoolaccept` is sequential: earlier `allowed: true` rows stay (no abort-class blanking). |
| `estimatesmartfee` | **10-minute inclusion frontier** — not Core historical multi-horizon. Core's result shape: `{feerate, blocks}`, or `{errors, blocks}` with no `feerate` when there is no estimate. Like Core, `feerate` is at least `mempoolminfee`. Optional `options.fee_rate_estimator` (`auto`, `block_policy`, `mempool_policy`) and `options.verbosity` are checked and do not change the feerate. See [`mempool-fee-estimation.md`](./mempool-fee-estimation.md). |
| `estimaterawfee` | Same 10-minute frontier product as `estimatesmartfee` (Core RPC name for harness scripts). Not Core historical `estimaterawfee` buckets. |
| `getnetworkhashps` | Core `GetNetworkHashPS`: `chainwork(end) − chainwork(start)` over `(maxTime − minTime)` in the lookup window. Default `nblocks` 120; `nblocks<=0` uses `height % difficulty_adjustment_interval + 1` (capped to height). `height<0` or past tip → tip. Genesis / zero dt → `0.0`. |
| `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` | **Regtest, and signet whose challenge is exactly `OP_TRUE`.** Mine through `ChainHub::accept_block` (same confirm as P2P). The `OP_TRUE` signet path uses signet bits and an empty BIP325 solution. First generated block includes `select_block_template`, then `remove_for_block`. `generatetodescriptor` accepts `raw(HEX)`, `addr(ADDRESS)`, or a bare address. |
| `getblocktemplate` / `getmininginfo` | All networks. A maintained pool is served, including while peer relay is off. An empty pool is served before maintenance. A nonempty pool before maintenance returns `-10`. `-blocksonly` returns a permanent error so a miner does not retry. Template from `select_block_template`; `-blockmintxfee` skips whole chunks under the floor (Core chunk feerate). `rules` must include `segwit`, and `signet` on signet. A rule that is not a string is `-3`. A proposal needs no rules; one without string `data` is `-3`. A mode other than `template` or `proposal` is `-8` `Invalid mode`. The template has Core's `rules` (`csv`, `!segwit` and `taproot` once segwit is active, `!signet`, `testdummy` once active), `vbavailable`, `vbrequired` `0`, `coinbaseaux` `{}`, and `signet_challenge` on signet. Before segwit it has the legacy sigop and size limits and no `weightlimit`. `default_witness_commitment` is always present, as in Core 32. `warnings` is the same string array as `getblockchaininfo` ([`COMPAT.md`](../COMPAT.md)). Proposal validates without connecting and returns Core reject needles (`bad-cb-missing`, `bad-cb-amount`, `bad-txns-premature-spend-of-coinbase`, `bad-txns-nonfinal` for BIP113 and BIP68, `bad-version`, `bad-diffbits`, `time-too-old`, …). `version` is `--block-version` when set, else Core `ComputeBlockVersion`: regtest follows the `testdummy` deployment (bit 28, 144-block periods, 108 signals to lock in, state cached per period-end hash), and other networks are `VERSIONBITS_TOP_BITS`. A locked-in `testdummy` sets bit 28 on an overridden version too. `longpollid` is Core's 64-hex tip followed by the mempool update counter, and waits until either changes. One whose first 64 characters are not a hash is `-8`. A non-string one waits on the current tip. Stop during the wait is `-9` `Shutting down`. On mainnet a template needs a peer (`-9`) and a node out of IBD (`-10`). A proposal of a connected block, or of one this process connected and then reorged off, is `duplicate`; of an invalid block `duplicate-invalid`; and of any other known header `duplicate-inconclusive`. The reorged-off mark is not kept across a restart. `getmininginfo.blockmintxfee` is 8-decimal BTC/kvB (`sat_btc_json`, same helper as mempool fees). `getmininginfo` reads the tip header once for `blocks`, `bestblockhash`, `bits`, and `target`. Its `next` has the template's bits for the next block. `next` and `networkhashps` are read by height at or below that tip, so a connect above it keeps the sample. A disconnect during the reads, or a failed read, starts the sample over with a short backoff, and 8 samples end in an error. `currentblockweight` and `currentblocktx` are the reserved 8000 plus the transactions of the last block a template, `generate`, or `generateblock` assembled, recorded per block (`generateblock` counts as empty, as in Core). The Stratum v2 template provider does not set them. |
| `prioritisetransaction` / `getprioritisedtransactions` | All networks. Local mining fee delta (sat). Dummy must be 0. Selector honors modified fee. The feerate announced to peers is base fee plus this delta. |
| `getmempoolcluster` | All networks. Cluster weight / chunks from the live graph (modified fees). Same prefix-maximal chunks as mining selection. `clusterweight` and `chunkweight` are sigop-adjusted (Core); the cluster size limit itself counts raw weight (`COMPAT.md`). |
| `getmempoolancestors` / `getmempooldescendants` | All networks. Exclusive walks of the live cluster graph. `verbose` reuses `getmempoolentry` fields. |
| `getmempoolfeeratediagram` | All networks. Mining chunks as `{weight, fee}` points (decreasing feerate). |
| `submitpackage` | All networks. `MempoolHub::submit_package_rpc` admits each tx with trim deferred, then package-evaluates a remainder of two or more that failed static min relay, the dynamic mempool min fee, or missing inputs. The package path is a child-with-parents tree; an in-mempool parent outside the remainder still supplies prevouts. When that remainder's combined fee meets static min relay, those members skip the dynamic floor. `fees.effective-feerate` / `effective-includes` for an individually admitted tx are that tx's modified fee and its own wtxid; for a package-eval tx they are the remainder's summed modified fees and vsizes, in package order. One unprotected trim runs after the package; a tx that was admitted and then dropped is `mempool full`. Package-admitted txs use the same relay-age clock as an individual admit. RPC `maxfeerate` / `maxburnamount` / `"version"` pre-checks. A member whose own feerate exceeds `maxfeerate`, including a parent that exists only in the package, is rejected (`max feerate exceeded`) and is not used to rescue the rest. An individual admit still lists the transactions it replaced. A 3-gen chain admits when fees/policy allow. A later member that failed missing-inputs and is not in a successful remainder stays `bad-txns-inputs-missingorspent`. `IsChildWithParents` `-25` applies only when `RBITCOIN_RPC_PACKAGE_DIALECT` is on ([`env-knobs.md`](./env-knobs.md)). `package_msg` / `tx-results` / `replaced-transactions`. Esplora `POST /txs/package` and Electrum `broadcast_package` still use atomic `accept_package` (all-or-nothing; child-fail rollback). |
| `gettxspendingprevout` | All networks. Live mempool spender of each `{txid,vout}`. |
| `submitblock` | All networks. Like Core, a coinbase with a witness commitment and no witness first gets the 32-byte zero reserved value once segwit is active. The parent's height comes from the connected chain, a header tip, or a walk of at most 10,000 stored headers. A parent past that walk is treated as before segwit, so the block is left as sent. Then the same `ChainHub::accept_received_block` as a P2P `block` message: tip-extend, or hold by hash + most-work `accept_branch`. A consensus reject is a BIP22 reason string. A local store fault, including one reading the parent or tip header or a spent output, is RPC error `-25` (Core `state.IsError()`). A cancelled connect is `inconclusive`. Neither caches the block as invalid. A `time-too-new` reject is not cached, as in Core (`BLOCK_TIME_FUTURE`): once the node clock is within two hours of the block time, the same block is checked again. A `time-too-old` reject is not cached either, so a second submit still answers `time-too-old`. A block that does not extend the tip uses that same clock, including under `setmocktime`, and the same BIP22 reason as a tip block (`time-too-new`, `time-too-old`, `bad-diffbits`). `bad-diffbits` is remembered. |
| `getblockfilter` | All networks. Requires `--block-filter-index`. `filtertype` `basic` only (anything else is `-5`). Returns `filter` and `header` hex. A sealed best-chain height uses the index. One block whose parent filter header is already sealed (genesis uses the zero prev-header) is built from the stored body. A stale branch is rebuilt back to that sealed fork point. An unsealed best-chain gap is “Filter not found. Block filters are still in the process of being indexed.” Unknown hash is `-5` “Block not found”. Flag off is “Index is not enabled”. REST `/rest/blockfilter/` stays watermark-only (“still in the process of being indexed” past the watermark). |
| `gettxout` | All networks. Connected Class A + mempool. `scriptPubKey` is the `getrawtransaction` object (`hex`, `asm`, Core `type`, `address` for a standard script, and `desc`). Default `include_mempool=true` returns `null` for a confirmed out spent by a live mempool tx. `include_mempool=false` still returns the confirmed coin. A leftover still live in the hub (IBD / `-blocksonly`) uses the connected path, not `confirmations: 0`. A disconnected archive row is `null` (not tip+1 confirmations). A vout at or past the output count is `null`. The genesis coinbase output is `null` (Core never adds it to the coins view). So is a confirmed unspendable output: a leading `OP_RETURN` (including the witness commitment) or a script over 10,000 bytes. A mempool output spent by another mempool tx is `null`; an unspent mempool output is listed. REST `getutxos` follows. |
| `getindexinfo` | All networks. Reports `txindex` synced at tip — we reconstruct by txid from Class A (no separate index flag). |
| `getchaintips` | All networks. Active + archive `valid-fork` + held `valid-headers` + header-only (`submitheader` / P2P headers). Invalid body after a known header marks that branch `invalid`. |
| `getdeploymentinfo` | All networks. Buried deployments from `ChainParams` including `--test-activation-height`. `active` follows Core `DeploymentActiveAfter` (true for the *next* block). No BIP9 / testdummy. |
| `submitheader` | All networks. Same `ChainHub::ensure_header` as P2P `headers`. Hex may be an 80-byte header or a full block. |
| `waitforblock` / `waitforblockheight` / `waitfornewblock` | All networks. Poll tip (milliseconds timeout). |
| `setmocktime` | **Regtest only.** `0` = wall clock. Generate timestamps and future-header checks use `NodeClock` (not a process `time()` hook). |
| `mockscheduler` | **Regtest / harness.** Advance the scheduler by `delta_seconds`; rebroadcast unbroadcast txs. |
| `invalidateblock` / `reconsiderblock` / `preciousblock` | All networks. Disconnect/re-accept via `ChainHub`; precious prefers equal-work siblings. |

## Permanent gaps (will not match Core)

| Method / area | Why |
|---------------|-----|
| Wallet RPC | No keystore |
| Stratum / pool | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` are a cluster-chunk **selector** ([`COMPAT.md`](../COMPAT.md)). No stratum, no wallet keys. `getdeploymentinfo` does not list `testdummy` |
| Core `generate*` as a mining product | **Regtest harness only.** `submitblock` is the same receive path as P2P |
| `combinerawtransaction` / `createrawtransaction` / `signrawtransactionwithkey` / `createmultisig` / `deriveaddresses` | Not implemented (harness proxy only) |
| Decode Core dialect | Node `decodescript` omits the `p2sh` / `segwit` wraps; `validateaddress` omits `error_locations`; `decoderawtransaction` asm is rust-bitcoin. Official scripts stay `rpc-dialect`. |
| `scantxoutset` / `gettxoutsetinfo` | No UTXO set and no descriptor scan. Not implemented. Address history is Electrum/Esplora. |
| Address history via Core method names | Use Electrum/Esplora with `--sh-index` |
| Exact Core JSON field-for-field | Best-effort |
| Multi-user `rpcauth` / method whitelist | Future |

## Auth (current / future)

| Now | Future (not v1) |
|-----|-----------------|
| `{datadir}/rpc.sock` (filesystem) | TLS in-process / mTLS |
| `{datadir}/rpc.token` Bearer on TCP | multi-user tokens |
| TCP HTTP Basic from `--rpc-cookie-file` (operator-written; the node never creates it). The functional harness still uses its own cookie on the test proxy | `rpcallowip` |

## Related

- [`COMPAT.md`](../COMPAT.md) — product surface
- [`OPERATOR.md`](../OPERATOR.md) — flags and shindex tradeoffs
- [`mempool-fee-estimation.md`](./mempool-fee-estimation.md) — fee product
- [`wallets.md`](./wallets.md) — which wallets use Electrum, Esplora, or this RPC
- [`lightning.md`](./lightning.md) — CLN, LDK, LND chain sources
