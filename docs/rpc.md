# Core-class JSON-RPC (rbitcoin)

`params` may be a JSON **array** (positional) or **object** (Core named
keys such as `blockhash`, `verbosity`, `txid`, `hexstring`). Missing
required keys are `-32602`; unknown named keys are `-8`.

rbitcoin serves a **documented subset** of Bitcoin Core JSON-RPC over plain HTTP.
This is **not** full Core parity: no wallet, no `createrawtransaction` /
`signrawtransactionwithkey` / `createmultisig` / `sendtoaddress` (those
live only on the Core-functional test proxy, backed by Esplora). `getblocktemplate` / `getmininginfo` are a
miner-backend (no stratum, no BIP9 testdummy). `scantxoutset` supports `raw(script)` via the scripthash
index (when `--shindex`) or Class A txout + spent. Prefer **Electrum /
Esplora** (with `--shindex`) for address/script history.

## Operator knobs

| Knob | Default | Meaning |
|------|---------|---------|
| `--rpc-listen ADDR` / conf `rpc_listen` | **off** | Bind HTTP JSON-RPC |
| `--rpcuser` / `--rpcpassword` | unset | HTTP Basic credentials |
| Cookie | **on** when listen set and no user/pass | `{datadir}/.cookie` as `user:password` |
| `--shindex` | **off** | Class B scripthash (Electrum/Esplora only; RPC by height/hash/txid does not need it) |

TLS is external (reverse proxy). Non-loopback binds still use cookie or user/pass
(always authenticated).

### curl example (cookie)

```bash
# After node start with --rpc-listen 127.0.0.1:8332
USERPASS=$(cat datadir/.cookie)
curl --user "$USERPASS" --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}' \
  -H 'content-type: application/json' http://127.0.0.1:8332/
```

### curl example (user/pass)

```bash
rbitcoin-node --rpc-listen 127.0.0.1:8332 --rpcuser u --rpcpassword p ...
curl --user u:p --data-binary \
  '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  -H 'content-type: application/json' http://127.0.0.1:8332/
```

### rbitcoin-cli

Same datadir cookie, or `--rpcuser` / `--rpcpassword`. Default
`127.0.0.1:8332`. Prints the JSON-RPC `result` (strings unquoted).

```bash
rbitcoin-cli --datadir datadir getblockcount
rbitcoin-cli --rpcuser u --rpcpassword p --rpcport 8332 getblockchaininfo
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
| `echo` | Testing RPC. Returns arguments as a positional array. Mixed AuthServiceProxy `{args: [...], argN: ...}` is supported. |
| `syncwithvalidationinterfacequeue` | No-op `null` (no wallet/index callback queue) |
| `getblockchaininfo` / `getblockcount` / `getbestblockhash` / `getblockhash` | Chain tip. `headers` is the best known header height (`submitheader` / P2P headers may lead `blocks`). `chainwork` is summed header work (regtest 2 per block). `size_on_disk` is a walk of `{datadir}/store` file lengths (plus `--datadir-cold` inwit when split). `verificationprogress` is `blocks / headers` clamped to `[0, 1]` (`1.0` when `headers` is 0). |
| `getblockheader` / `getblock` (verbosity 0/1/2) | Archive reconstruct. `getblockheader` includes `chainwork`. |
| `getblockstats` | All networks. Reconstruct the block; Core named keys `hash_or_height` / `stats`. Fees from archive prevouts. Genesis excluded from actual UTXO counts. OP_RETURN unspendable. We do not have Core `blk*.dat`, so `rpc_getblockstats.py`'s rename-file needle stays skip. |
| `getdifficulty` | From tip bits |
| `getnetworkinfo` / `getconnectioncount` / `getpeerinfo` | BIP324 v2-only; `getpeerinfo` is the live session table. `version` is rbitcoin semver as a Core integer (`major*10000+minor*100+patch`: `0.1.0` → `100`, `0.5.0` → `500`, `0.5.1` → `501`), not a Core release. `localservices` matches advertised `NETWORK\|WITNESS\|P2P_V2`. `localaddresses` lists `-externalip` (`score` = Core `LOCAL_MANUAL`) |
| `addnode` / `disconnectnode` / `addconnection` | All networks. `addnode onetry` / `add` dial; `disconnectnode` by `nodeid` or address |
| `getmempoolinfo` / `getrawmempool` / `getmempoolentry` | MempoolHub. `maxmempool` is the operator weight budget (`--mempool-size-mb`). `ancestorcount` / `descendantcount` (and size/fee sums) walk the cluster graph. Verbose `fees.{base,modified,ancestor,descendant,chunk}` and `chunkweight` include `prioritisetransaction` deltas; top-level `ancestorfees` / `descendantfees` stay base satoshis. `unbroadcastcount` / `unbroadcast` track `sendrawtransaction` txs until a peer getdata's them. |
| `getrawtransaction` | Class A + mempool. Optional Core `blockhash` arg is accepted and ignored. |
| `sendrawtransaction` / `testmempoolaccept` | Relay must be enabled. `sendrawtransaction` is live accept. `testmempoolaccept` is dry-run (`MempoolHub::test_accept`: prepare + scripts + RBF/cluster checks, no commit / announce / RBF eviction / orphan park). |
| `estimatesmartfee` | **10-minute inclusion frontier** — not Core historical multi-horizon. See [`mempool-fee-estimation.md`](./mempool-fee-estimation.md). |
| `generatetoaddress` / `generatetodescriptor` / `generateblock` / `generate` | **Regtest only.** Mine through `ChainHub::accept_block` (same confirm as P2P). First generated block includes `select_block_txs`, then `remove_for_block`. `generatetodescriptor` accepts `raw(HEX)`, `addr(ADDRESS)`, or a bare address. |
| `getblocktemplate` / `getmininginfo` | All networks. Template from `select_block_txs`. `rules` must include `segwit`. Proposal validates without connecting and returns Core reject needles (`bad-cb-missing`, `bad-diffbits`, `time-too-old`, …). Version is `VERSIONBITS_TOP_BITS` only (no testdummy). `longpollid` waits until the tip or mempool update counter changes. |
| `prioritisetransaction` / `getprioritisedtransactions` | All networks. Local mining fee delta (sat). Dummy must be 0. Selector honors modified fee. |
| `getmempoolcluster` | All networks. Cluster weight / chunks from the live graph (modified fees). Same prefix-maximal chunks as mining selection. |
| `getmempoolancestors` / `getmempooldescendants` | All networks. Exclusive walks of the live cluster graph. `verbose` reuses `getmempoolentry` fields. |
| `getmempoolfeeratediagram` | All networks. Mining chunks as `{weight, fee}` points (decreasing feerate). |
| `submitpackage` | All networks. Sequential `accept_tx` (parent can stay if the child fails). No package-level feerate (a 0-fee CPFP parent is rejected on its own min-relay). `package_msg` / `tx-results` / `replaced-transactions`. |
| `gettxspendingprevout` | All networks. Live mempool spender of each `{txid,vout}`. |
| `submitblock` | All networks. Same `ChainHub::accept_received_block` as a P2P `block` message: tip-extend, or hold by hash + most-work `accept_branch`. |
| `scantxoutset` | All networks. `raw(HEX)` over Class A unspent outputs. MiniWallet on-ramp. Not Core coins-DB / HD-range scan. |
| `gettxout` | All networks. Class A + mempool. |
| `getindexinfo` | All networks. Reports `txindex` synced at tip — we reconstruct by txid from Class A (no separate index flag). |
| `getchaintips` | All networks. Active + archive `valid-fork` + held `valid-headers` + header-only (`submitheader` / P2P headers). Invalid body after a known header marks that branch `invalid`. |
| `getdeploymentinfo` | All networks. Buried deployments from `ChainParams` including `-testactivationheight`. `active` follows Core `DeploymentActiveAfter` (true for the *next* block). No BIP9 / testdummy. |
| `submitheader` | All networks. Same `ChainHub::ensure_header` as P2P `headers`. Hex may be an 80-byte header or a full block. |
| `waitforblock` / `waitforblockheight` / `waitfornewblock` | All networks. Poll tip (milliseconds timeout). |
| `setmocktime` | **Regtest only.** `0` = wall clock. Generate timestamps and future-header checks use `NodeClock` (not a process `time()` hook). |
| `invalidateblock` / `reconsiderblock` / `preciousblock` | All networks. Disconnect/re-accept via `ChainHub`; precious prefers equal-work siblings. |

## Permanent gaps (will not match Core)

| Method / area | Why |
|---------------|-----|
| Wallet RPC | No keystore |
| Stratum / pool / BIP9 testdummy | `getblocktemplate` / `getmininginfo` / `prioritisetransaction` are a cluster-chunk **selector** ([`COMPAT.md`](../COMPAT.md)). No stratum, no testdummy, no wallet keys |
| Core `generate*` as a mining product | **Regtest harness only.** `submitblock` is the same receive path as P2P |
| `combinerawtransaction` | Not implemented |
| Full `scantxoutset` / `gettxoutsetinfo` | No UTXO-set coins DB; denserels ≠ chainstate. `raw()` Class A walk is the MiniWallet subset only. |
| Address history via Core method names | Use Electrum/Esplora with `--shindex` |
| Exact Core JSON field-for-field | Best-effort |
| Multi-user `rpcauth` / method whitelist | Future |

## Auth (current / future)

| Now | Future (not v1) |
|-----|-----------------|
| Cookie under datadir | `rpcauth=` multi-user |
| `--rpcuser` / `--rpcpassword` | `rpcwhitelist` |
| Always Basic auth when listen set | `rpcallowip` / unix socket |

## Related

- [`COMPAT.md`](../COMPAT.md) — product surface
- [`OPERATOR.md`](../OPERATOR.md) — flags and shindex tradeoffs
- [`mempool-fee-estimation.md`](./mempool-fee-estimation.md) — fee product
