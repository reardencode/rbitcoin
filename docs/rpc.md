# Core-class JSON-RPC (rbitcoin)

`params` may be a JSON **array** (positional) or **object** (Core named
keys such as `blockhash`, `verbosity`, `txid`, `hexstring`). Missing
required keys are `-32602`; unknown named keys are `-8`.

rbitcoin serves a **documented subset** of Bitcoin Core JSON-RPC over plain HTTP.
This is **not** full Core parity: no wallet, no `createrawtransaction` /
`signrawtransactionwithkey` / `createmultisig` / `sendtoaddress` (those
live only on the Core-functional test proxy, backed by Esplora).
`decoderawtransaction` / `decodescript` / `validateaddress` are a **node
subset** (table below). Official Core dialect scripts (`rpc_decodescript.py`,
`rpc_validateaddress.py`, `rpc_invalid_address_message.py`) stay inventory
`rpc-dialect`; the functional harness does not intercept those names.
`getblocktemplate` / `getmininginfo` are a miner-backend (no stratum, no BIP9
testdummy). `scantxoutset` expands descriptors and looks them up on the
scripthash index. It requires `--sh-index` (`scripthash index disabled`
otherwise). Prefer **Electrum / Esplora** (with `--sh-index`) for address
history.

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
| `--rpc-token-file PATH` | `{datadir}/rpc.token` | CSPRNG hex token; TCP `Authorization: Bearer` |
| `--rpc-cookie-file PATH` / conf `rpc_cookie_file=` | **off** | Existing Core-format `username:password` file (no trailing newline) accepted as TCP HTTP Basic in addition to Bearer; it is never created or logged |
| `--sh-index` | **off** | Class B scripthash (Electrum/Esplora only; RPC by height/hash/txid does not need it) |
| `--block-filter-index` | **off** | BIP158 basic. IBD seals them when the flag is on from the start. A later enable still materializes after catch-up. `NODE_COMPACT_FILTERS` is advertised once filters first reach the tip (`getnetworkinfo` lists `COMPACT_FILTERS`), then for the life of the process. `getblockfilter` and `/rest/blockfilter/` serve heights the watermark already covers. Independent of `--sh-index` |
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
`--rpc-url` (default `http://127.0.0.1:<network port>`) and Bearer from
`{datadir}/rpc.token` or `--rpc-token-file`. Prints the JSON-RPC `result`
(strings unquoted).

```bash
rbitcoin-cli --datadir datadir getblockcount
rbitcoin-cli --network regtest --rpc-url http://127.0.0.1:18443 getblockchaininfo
```

## shindex matrix

| Capability | `shindex=0` (default) | `shindex=1` |
|------------|----------------------|-------------|
| IBD, tip follow, P2P, mempool relay | Yes | Yes |
| Node JSON-RPC (by height/hash/txid) | Yes | Yes |
| Electrum / Esplora listen | **Refuse start** | Yes after SH tip-ready |
| SH run enqueue / tip bulk | **Skip** | On |

Tip-follow readiness is **independent** of scripthash materialize. Electrum/Esplora
still wait for durable SH when shindex is on.

## Supported methods (Tier 1)

| Method | Notes |
|--------|-------|
| `help` / `getrpcinfo` / `uptime` / `stop` | Control |
| `echo` | Testing RPC. Returns arguments as a positional array. AuthServiceProxy `{args: [...], argN: ...}` is peeled only here. Mixed `submitpackage`/`sendrawtransaction`/`testmempoolaccept` `{args, maxfeerate}` is expanded in the Core-functional proxy, not on the node. |
| `getblockchaininfo` / `getblockcount` / `getbestblockhash` / `getblockhash` | Chain tip. `getblockcount` / `getbestblockhash` wait for the in-flight tip-accept job (not the rest of a catch-up burst). `headers` is the best known header height (`submitheader` / P2P headers may lead `blocks`). `chainwork` is summed header work (regtest 2 per block). `bits` and `target` are the tip compact target. `difficulty` prints with 16 significant digits. `size_on_disk` is a walk of `{datadir}/store` file lengths (plus `--datadir-cold` seqsigwit when split). `verificationprogress` is `blocks / headers` clamped to `[0, 1]` (`1.0` when `headers` is 0). `initialblockdownload` is the Core RPC name for **relay-inhibited**: `--min-chain-work` and `--max-tip-age` after densify/`enter_tip_mode`, not “still catching up”. `--prune-seqsigwit` sets `pruned: true` and `pruneheight` (omitted when off). |
| `getblockheader` / `getblock` (verbosity 0/1/2) | Archive reconstruct. `getblockheader` includes `chainwork`, `target`, and `nextblockhash` when the next active block exists. Genesis omits `previousblockhash`. A header that is stored but not on the active chain (reorg or `invalidateblock`) returns `confirmations: -1` and its own `previousblockhash`. `getblock` returns a Class A body for that hash the same way, or a held never-confirmed body. Verbosity 0/2 below `pruneheight` is `-8` `Block not available (pruned data)`; verbosity 1 (txids) stays. |
| `getblockstats` | All networks. Stamped `txstat` fee/size/weight/`n_in`. Size and count fields match Core for the keys we return: coinbase is left out of `ins`, fees, `total_size`, `total_weight`, and the segwit totals. `utxo_increase` is every output minus those inputs. `utxo_increase_actual` drops outputs that do not enter the UTXO set (height 0, the two mainnet BIP30-repeat coinbases, unspendable scripts). Omits coins-DB `utxo_size_inc` / `utxo_size_inc_actual` (selecting those names is invalid statistic `-8`). Unstamped leftover reconstructs then lazy-stamps. Reconstruct miss is `block body not in store`. Dummy `blk00000.dat` is shim-only so `rpc_getblockstats.py`'s rename-file needle stays Core-phrased. Pruned unstamped height is `-8` Core pruned text. |
| `getdifficulty` | From tip bits, 16 significant digits |
| `getnetworkinfo` / `getconnectioncount` / `getpeerinfo` | BIP324 v2-only; `getpeerinfo` is the live session table. `timeoffset` is VERSION clock minus connect time (`0` before handshake). `synced_headers` is the height of that peer's advertised best block when we know it, else `-1`. `synced_blocks` is that height when the hash is on our best chain, else `-1`. `getnetworkinfo.timeoffset` is the median of outbound handshake-complete offsets (`0` if none). `mapped_as` is present when `--asmap` / `{datadir}/ip_asn.dat` mapped the peer (Core field; omitted without a map or ASN 0). `version` is the fixed integer `190000` (Core 0.19 client version; see [getnetworkinfo.version](#getnetworkinfoversion)). `localservices` matches advertised `NETWORK\|WITNESS\|P2P_V2`, or `NETWORK_LIMITED\|WITNESS\|P2P_V2` under `--prune-seqsigwit`. `localaddresses` lists `--external-ip` (`score` = Core `LOCAL_MANUAL`) |
| `getnettotals` | All networks. Raw TCP `totalbytesrecv` / `totalbytessent` on live sessions. `uploadtarget` is a Core-shaped stub (`target` 0). |
| `ping` | All networks. Queues a ping on each live session (`null`). |
| `addpeeraddress` | Hidden Core name. Inserts `{address,port}` into addrman RAM (does not rewrite `peers` per call). |
| `getnodeaddresses` | Sample from addrman (`count=0` → all). Optional `network` filter. |
| `addnode` / `disconnectnode` / `addconnection` | All networks. Hostnames resolve at dial (network default P2P port if omitted). `addnode add` and `--connect` retry until a live session. `addnode onetry` dials once and errors if DNS fails. `disconnectnode` by `nodeid` or address |
| `getmempoolinfo` / `getrawmempool` / `getmempoolentry` | MempoolHub. `maxmempool` is the operator weight budget (`--mempool-size-mb`). `fullrbf` is `true` (Libre always replaces). `maxdatacarriersize` is JSON null (no datacarrier cap). `limitclustercount` / `limitclustersize` are the live cluster caps (count and vbytes). Fee amounts are 8-decimal BTC. `ancestorcount` / `descendantcount` (and size/fee sums) walk the cluster graph. `vsize`, `ancestorsize`, `descendantsize` and `chunkweight` are sigop-adjusted (Core `GetAdjustedWeight`, `--bytes-per-sigop`); `weight` is raw. Verbose `fees.{base,modified,ancestor,descendant,chunk}` and `chunkweight` include `prioritisetransaction` deltas; top-level `ancestorfees` / `descendantfees` stay base satoshis. `unbroadcastcount` / `unbroadcast` track `sendrawtransaction` txs until a peer getdata's them. `orphanage.{size,bytes}` is the parked missing-parent side pool (vsize). `permitbaremultisig` is always `true` (Libre has no Core `IsStandard` bare-multisig gate; `--permitbaremultisig` is not a node flag). |
| `getorphantxs` | Hidden operator dump. Verbosity 0 txids, 1 details + `from` peer ids, 2 + hex. Not listed by `help` / `getrpcinfo`. Counts-only `getmempoolinfo.orphanage` is not a substitute. |
| `getrawtransaction` | Class A + mempool. Optional Core `blockhash` arg is accepted and ignored. Verbose objects share `tx_to_json` with `decoderawtransaction` / `getblock` verbosity 2 (`scriptSig`, `scriptPubKey.type`). A confirmed verbose result also carries Core's `confirmations`, `blockhash`, `blocktime`, and `time`. Below `pruneheight`: `-8` `Transaction not available (pruned data)` (not `-5`). The genesis coinbase txid is `-5` `The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved` (Core); REST `/rest/tx/` answers `404` `<txid> not found` for it, as Core (its txindex skips height 0). |
| `decoderawtransaction` | All networks. Decode hex. Optional `iswitness`: `false` refuses a BIP141 marker (`-22 TX decode failed`). Extra trailing bytes also `-22`. `scriptSig.asm` is rust-bitcoin, not Core `ScriptToAsmStr` sighash suffixes. Coinbase vin is Core-shaped `{coinbase, sequence}` (plus rbitcoin's `n`), with no `txid`/`vout`. |
| `decodescript` | All networks. `asm`, Core-style `type`, `hex`, and `address` when `Address::from_script` succeeds. No `p2sh` wrap, `segwit` wrap, or `desc` / miniscript. |
| `validateaddress` | All networks. Valid: `isvalid`, `address`, `scriptPubKey`, `isscript`, `iswitness`, plus `witness_version` / `witness_program` when segwit except pay-to-anchor. P2TR and P2A set `isscript` true. Invalid (parse fail or wrong chain): `{isvalid: false}` only — no `error` / `error_locations`. |
| `sendrawtransaction` / `testmempoolaccept` | `sendrawtransaction` is live accept (RPC still admits under `-blocksonly`; serving-only refuse is IBD / tip-not-ready `relay disabled`). `testmempoolaccept` / `submitpackage` `vsize` is sigop-adjusted. `testmempoolaccept` is dry-run (`MempoolHub::test_accept`: prepare + scripts + RBF/cluster checks, no commit / announce / RBF eviction / orphan park). Invalid hex / decode is `-22 TX decode failed` (same as `decoderawtransaction`). Confirmed on the active chain is `txn-already-known` (tip + confirmed-strong); live mempool duplicate is `txn-already-in-mempool`; archive-only after invalidate is not already-known. RPC-submit only: `maxfeerate` is **sat/vB** (default **10000**; `0` unlimited; `>= 100000` is `-8`). sendraw over-cap is `-25` configured-max text; `testmempoolaccept` reject-reason stays `max-fee-exceeded`. `maxburnamount` default **0** (valued unspendable / OP_RETURN outs). nVersion outside 1/2 is `"version"`. P2P `accept_tx` does not apply these caps. Multi-tx `testmempoolaccept` is sequential: earlier `allowed: true` rows stay (no abort-class blanking). Core functional tests still speak BTC/kvB via `scripts/core-functional/rpc_proxy.py`. |
| `estimatesmartfee` | **10-minute inclusion frontier** — not Core historical multi-horizon. Core's result shape: `{feerate, blocks}`, or `{errors, blocks}` with no `feerate` when there is no estimate. Like Core, `feerate` is at least `mempoolminfee`. See [`mempool-fee-estimation.md`](./mempool-fee-estimation.md). |
| `estimaterawfee` | Same 10-minute frontier product as `estimatesmartfee` (Core RPC name for harness scripts). Not Core historical `estimaterawfee` buckets. |
| `getnetworkhashps` | Core `GetNetworkHashPS`: `chainwork(end) − chainwork(start)` over `(maxTime − minTime)` in the lookup window. Default `nblocks` 120; `nblocks<=0` uses `height % difficulty_adjustment_interval + 1` (capped to height). `height<0` or past tip → tip. Genesis / zero dt → `0.0`. |
| `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` | **Regtest only.** Mine through `ChainHub::accept_block` (same confirm as P2P). First generated block includes `select_block_template`, then `remove_for_block`. `generatetodescriptor` accepts `raw(HEX)`, `addr(ADDRESS)`, or a bare address. |
| `getblocktemplate` / `getmininginfo` | All networks. Template from `select_block_template`; `-blockmintxfee` skips whole chunks under the floor (Core chunk feerate). `rules` must include `segwit`. Proposal validates without connecting and returns Core reject needles (`bad-cb-missing`, `bad-diffbits`, `time-too-old`, …). Version is `VERSIONBITS_TOP_BITS` only (no testdummy). `longpollid` waits until the tip or mempool update counter changes. `getmininginfo.blockmintxfee` is 8-decimal BTC/kvB (`sat_btc_json`, same helper as mempool fees). |
| `prioritisetransaction` / `getprioritisedtransactions` | All networks. Local mining fee delta (sat). Dummy must be 0. Selector honors modified fee. |
| `getmempoolcluster` | All networks. Cluster weight / chunks from the live graph (modified fees). Same prefix-maximal chunks as mining selection. `clusterweight` and `chunkweight` are sigop-adjusted (Core); the cluster size limit itself counts raw weight (`COMPAT.md`). |
| `getmempoolancestors` / `getmempooldescendants` | All networks. Exclusive walks of the live cluster graph. `verbose` reuses `getmempoolentry` fields. |
| `getmempoolfeeratediagram` | All networks. Mining chunks as `{weight, fee}` points (decreasing feerate). |
| `submitpackage` | All networks. Sequential `MempoolHub::submit_package_rpc` (`accept_tx` per tx; keep successes). Remainders that failed `min relay fee` or missing inputs are then `accept_package` (CPFP waiver is a child-with-parents ancestor tree). RPC `maxfeerate` / `maxburnamount` / `"version"` pre-checks. A 3-gen chain admits when fees/policy allow. A later member that failed missing-inputs stays `bad-txns-inputs-missingorspent`. `IsChildWithParents` `-25` and in-package maxfeerate overlay apply only when `RBITCOIN_RPC_PACKAGE_DIALECT` is on ([`env-knobs.md`](./env-knobs.md)). `package_msg` / `tx-results` / `replaced-transactions`. Esplora `POST /txs/package` and Electrum `broadcast_package` still use atomic `accept_package` (all-or-nothing; child-fail rollback). |
| `gettxspendingprevout` | All networks. Live mempool spender of each `{txid,vout}`. |
| `submitblock` | All networks. Same `ChainHub::accept_received_block` as a P2P `block` message: tip-extend, or hold by hash + most-work `accept_branch`. |
| `scantxoutset` | All networks. Requires `--sh-index`. Expands output descriptors (`range` default 1000, Core's range errors) and looks each script up on the scripthash index. Refuses more than 10000 derived scripts. Does not store the descriptor. Never returns the genesis coinbase output (Core never adds it to the coins view). `txouts` is always `-1` (no coins DB; the count is not computed). |
| `getblockfilter` | All networks. Requires `--block-filter-index`. `filtertype` `basic` only. Returns `filter` and `header` hex for a sealed height. Flag off is “Index is not enabled”. Flag on and this height not sealed yet is “still in the process of being indexed”. |
| `gettxout` | All networks. Connected Class A + mempool. Default `include_mempool=true` returns `null` for a confirmed out spent by a live mempool tx. `include_mempool=false` still returns the confirmed coin. A leftover still live in the hub (IBD / `-blocksonly`) uses the connected path, not `confirmations: 0`. A disconnected archive row is `null` (not tip+1 confirmations). The genesis coinbase output is `null` (Core never adds it to the coins view); REST `getutxos` follows. |
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
| Stratum / pool / BIP9 testdummy | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` are a cluster-chunk **selector** ([`COMPAT.md`](../COMPAT.md)). No stratum, no testdummy, no wallet keys |
| Core `generate*` as a mining product | **Regtest harness only.** `submitblock` is the same receive path as P2P |
| `combinerawtransaction` / `createrawtransaction` / `signrawtransactionwithkey` / `createmultisig` / `deriveaddresses` | Not implemented (harness proxy only) |
| Decode Core dialect | Node `decodescript` omits wrap/`desc`; `validateaddress` omits `error_locations`; `decoderawtransaction` asm is rust-bitcoin. Official scripts stay `rpc-dialect`. |
| `gettxoutsetinfo` | No UTXO set. Not implemented. |
| Address history via Core method names | Use Electrum/Esplora with `--sh-index` |
| Exact Core JSON field-for-field | Best-effort |
| Multi-user `rpcauth` / method whitelist | Future |

## Auth (current / future)

| Now | Future (not v1) |
|-----|-----------------|
| `{datadir}/rpc.sock` (filesystem) | TLS in-process / mTLS |
| `{datadir}/rpc.token` Bearer on TCP | multi-user tokens |
| Harness `.cookie` + Basic on the test proxy only | `rpcallowip` |

## Related

- [`COMPAT.md`](../COMPAT.md) — product surface
- [`OPERATOR.md`](../OPERATOR.md) — flags and shindex tradeoffs
- [`mempool-fee-estimation.md`](./mempool-fee-estimation.md) — fee product
