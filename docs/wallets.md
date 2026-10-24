# Wallets

Which open-source wallets can use this node, and the setting each one
expects. Lightning implementations are [`lightning.md`](./lightning.md).
Listener behavior, DoS limits, and the mempool.space nginx recipe stay in
[`operator/interfaces.md`](./operator/interfaces.md). Method lists stay in
[`COMPAT.md`](../COMPAT.md) and [`rpc.md`](./rpc.md).

Chains the node actually runs: `mainnet`, `testnet` (testnet3), `signet`,
`regtest`. There is no `--network testnet4`. A wallet left on testnet4
has nothing to connect to.

0.x. The Electrum and Esplora listeners are the wallet product. Core
wallet RPC (`importdescriptors`, `walletcreatefundedpsbt`,
`signrawtransactionwithwallet`, and the rest of the keystore) is a
permanent non-goal.

## Shared behavior

Address history needs `--sh-index`. Without it, Electrum scripthash
methods return `scripthash index disabled` and Esplora `/address` and
`/scripthash` return HTTP 503 with that phrase. Txid, block, header,
broadcast, and fee calls work with the index off. Lightning channel
watches use those, so they are documented in [`lightning.md`](./lightning.md).

Electrum is plain TCP (`--electrum-listen`). TLS terminates at a reverse
proxy ([`operator/interfaces.md`](./operator/interfaces.md)). With
`--tor-control`, the node publishes an onion for that port and advertises
`tcp_port` only (no `ssl_port`). Sparrow's onion URL is
`tcp://<id>.onion:<port>`.

Esplora is plain HTTP (`--esplora-listen`). There is no WebSocket. A
wallet that wants push notifications uses Electrum subscriptions. The
mempool.space UI's `/api/v1/ws` is mempool's own Node process, not this
listener.

One Electrum connection may hold `--electrum-max-subs` scripthash
subscriptions (default **10000**). That is the cap on one wallet's
receive and change addresses, including the gap limit.

Fee estimates (`estimatesmartfee`, Electrum `estimatefee`, Esplora
`/fee-estimates`) are a 10-minute inclusion price from the live mempool,
floored at the minimum relay fee. Minimum relay is 0.1 sat/vB. RBF is
always on. A fee slider will not match a Core or Fulcrum server. Detail:
[`mempool-fee-estimation.md`](./mempool-fee-estimation.md).

Released Electrum through 4.8 speaks protocol 1.4–1.6 and queries by
scripthash. This node advertises `protocol_max` **1.6**. Protocol 1.7
replaces `blockchain.scripthash.*` with `blockchain.scriptpubkey.*`.
Those methods are not implemented, so a 1.7-only client cannot sync.
`blockchain.outpoint.*` is already served and is not advertised as 1.7.

## TCP RPC cookie

Wasabi, LND's `bitcoind` backend, and a stratum pool that polls
`getblocktemplate` all expect Core's `rpcuser` / `rpcpassword`. This node
does not have those flags. TCP JSON-RPC accepts HTTP Basic from a cookie
file you write yourself, plus Bearer from `{datadir}/rpc.token`.

The file is one line, `username:password`, with **no trailing newline**.
The node refuses to start if the newline is there. Write it before each
start (`/run` is tmpfs):

```bash
sudo mkdir -p /run/rbitcoin
printf '__cookie__:%s' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" |
  sudo install -m 0640 -o "$(id -un)" -g "$(id -gn)" /dev/stdin /run/rbitcoin/rpc.cookie

./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --rpc-listen 127.0.0.1:8332 \
  --rpc-cookie-file /run/rbitcoin/rpc.cookie \
  --rpc-cookie-perms group
```

`--rpc-cookie-perms` defaults to `owner` (mode 0600). `group` is what makes
the 0640 file above acceptable, and it still refuses group write. `all` is
at most 0644. The check is Unix mode bits; Windows ignores the flag. The
node never chmods the file. NixOS: `services.rbitcoin.rpc.cookiePerms`.

The mempool.space group ownership and unix-socket variant are in
[`operator/interfaces.md`](./operator/interfaces.md#mempoolspace-core_rpc).
Unix `{datadir}/rpc.sock` (`--rpc`, mode 0600) needs no header.
`rbitcoin-cli` and the CLN wrapper use that socket.
[`lightning.md`](./lightning.md) has the LND `rpccookie` lines.

## Electrum and Esplora wallets

Start the listener the wallet speaks. Both need `--sh-index` for
balances and history.

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --sh-index \
  --electrum-listen 127.0.0.1:50001 \
  --esplora-listen 127.0.0.1:3000
```

| Wallet | Setting that works |
|--------|--------------------|
| Electrum desktop, including Electrum's Lightning | Server `127.0.0.1:50001:t` (the trailing `t` is plain TCP). Behind a TLS proxy, `host:443:s`. |
| Sparrow, private Electrum | Server type **Private Electrum**, TCP `127.0.0.1:50001`. Sparrow sees `electrumx` in `server.version[0]` and sends address lookups as JSON-RPC batches. Silent Payments uses Frigate `blockchain.silentpayments.subscribe`, which is implemented. Add `--sp-tweaks` so that scan is indexed. Sparrow's **Bitcoin Core** server type imports a descriptor wallet and does not apply. |
| Liana v7+ | Backend **Electrum server** at `127.0.0.1:50001`. The bitcoind backend wants Core's descriptor wallet (Core 24+, 26+ for Taproot) and does not apply. |
| Specter Desktop 2.0 | **External Electrum**. The Bitcoin Core connection needs `disablewallet=0` and wallet RPC, which this node does not serve. |
| Cake Wallet | Electrum server as above, plus `--sp-tweaks` and `--sp-tweaks-dust 546` (Cake's electrs dust floor; our default is 1000). `server.version[0]` is `rbitcoin-electrs <ver> electrumx` so Cake's electrs probe will call `blockchain.tweaks.subscribe`. A Cake build that still hardcodes `electrs.cakewallet.com` will not use the server you typed. |
| BlueWallet, Stack Wallet, Keeper, Nunchuk, BitBox App, Envoy / Passport, Caravan, MyCitadel, Blockstream Green personal server | The app's custom Electrum or Esplora field. Same listeners as the table above. |
| BDK wallets on Esplora (Alby Hub's chain source, and the same client shape Mutiny used) | `http://127.0.0.1:3000`, or TLS in front of that port. |

`--sp-tweaks` is refused together with `--prune-seqsigwit`. Cake and
Sparrow Silent Payments need the tweak index, so that prune stays off
for those wallets.

## Wasabi

Wasabi's full-node path is supported. It is a JSON-RPC client, not an
Electrum client. The jobs [Wasabi's full-node
doc](https://docs.wasabiwallet.io/using-wasabi/BitcoinFullNode.html)
assigns to a local node are the methods below, and each one is served:

| Wasabi uses the node for | Method | Flag |
|--------------------------|--------|------|
| BIP158 filters | `getblockfilter` `basic` | `--block-filter-index` |
| Block download | `getblock` | `--rpc-listen` |
| Fee estimates | `estimatesmartfee` | `--rpc-listen` |
| Broadcast | `sendrawtransaction` | `--rpc-listen` |

Two configuration facts are easy to read as "unsupported":

- Wasabi has no Electrum server field on this path. Pointing Sparrow at
  `--electrum-listen` does not configure Wasabi.
- The setting is `BitcoinRpcCredentialString`, a `username:password`
  sent as HTTP Basic. There is no `--rpcuser` / `--rpcpassword` to put
  in a `bitcoin.conf`. Paste the cookie file from [TCP RPC
  cookie](#tcp-rpc-cookie) into that string. The bytes must match,
  including the lack of a trailing newline.

```text
BitcoinRpcEndpoint: http://127.0.0.1:8332
BitcoinRpcCredentialString: <exact contents of /run/rbitcoin/rpc.cookie>
```

`estimatesmartfee` accepts Core's `estimate_mode` (`unset`,
`economical`, `conservative`) and returns the same 10-minute feerate
for all three. Wasabi's economical-versus-conservative choice does not
change the number.

If the endpoint or the credential is wrong, Wasabi keeps loading filters
from its own backend and shows the RPC status as disconnected. That
fallback is Wasabi's. The node is in use when the status bar says the
RPC is connected. Filters are absent until `--block-filter-index` has
sealed the heights Wasabi asks for. `getblockfilter` refuses a
best-chain block whose parent filter is not sealed yet. A stale branch
is rebuilt only back to a sealed fork point. REST
`/rest/blockfilter/` and P2P stay watermark-only.

## Core-wallet applications

These talk to Bitcoin Core's wallet RPC. Electrum or Esplora mode, where
the table above lists one, is the path that works. The Core mode does
not:

| Application | What it asks the node to do |
|-------------|----------------------------|
| Sparrow, server type Bitcoin Core | Create and scan a descriptor wallet on the node. |
| Specter Desktop, Bitcoin Core connection | The same, with `disablewallet=0`. |
| Liana bitcoind backend | Watch-only descriptor wallet. Core 24.0.1 minimum, 26.0 for Taproot. |
| Fully Noded | Remote control of a Core wallet. |
| JoinMarket and Jam | `listunspent`, wallet signing, `sendrawtransaction` through the Core wallet. |
| Electrum Personal Server | A watch-only Core wallet, then it serves Electrum. This node already is the Electrum server. EPS is not the way to attach Electrum. |

## BTCPay Server

NBXplorer scans blocks with `getblock` (verbosity 2) and
`getrawtransaction`, broadcasts with `sendrawtransaction`, and
authenticates with a cookie file. Those calls and the cookie exist.
Current NBXplorer also requires Bitcoin Core **24.0 or newer**.
`getnetworkinfo.version` defaults to **190000** so clients do not assume
a descriptor wallet ([`rpc.md`](./rpc.md#getnetworkinfoversion)). That
integer fails NBXplorer's version gate. `--rpc-client-version` can raise
the integer, and it still does not add wallet RPC. BTCPay works against
this node when NBXplorer accepts the `subversion` (`/rbitcoin:<semver>/`)
and keeps using the block and transaction calls.

## Compact-filter and SPV wallets

Wasabi's RPC filter path is above. These are different:

| Client | What it needs | On this node |
|--------|---------------|--------------|
| bitcoinj wallets (Schildbach Bitcoin Wallet, older Mycelium) | P2P v1 and BIP37 bloom filters (`filterload`) | P2P is BIP324 v2 only. `filterload` disconnects the peer. |
| LND Neutrino, Zeus embedded LND in Neutrino mode | BIP157 to a peer | Filters are served with `--block-filter-index`. Neutrino does not speak v2, so it cannot connect. Detail: [`lightning.md`](./lightning.md#neutrino). |

## Hardware-wallet apps

Sparrow, Electrum, Specter, Liana, BitBox App, and Envoy follow the
Electrum rows above. The signer never talks to the node.

Trezor Suite talks to Blockbook. Ledger Live talks to Ledger's backend.
Neither has an Electrum, Esplora, or Core-RPC-subset setting.

## Pools

SV2 Job Declarator clients and pools that speak Template Distribution
over Noise NX use `--sv2-tp-listen`. Setup is
[`operator/interfaces.md`](./operator/interfaces.md#stratum-v2-template-provider).

Stratum v1 pool software (public-pool, ckpool, Datum) that only polls
`getblocktemplate` and submits a block can use the template RPC. There
is no stratum server in the node. Authentication is the [cookie
file](#tcp-rpc-cookie), not `rpcuser` / `rpcpassword`.

## What is still missing for other wallets

| Gap | Who it blocks | What the change is |
|-----|---------------|--------------------|
| Electrum `scriptpubkey.*` (protocol 1.7) | A future Electrum that drops 1.4–1.6, and 1.7-only servers' clients | Hash the provided script and serve the existing scripthash index under the 1.7 response shapes. Then advertise 1.7. |
| TLS on port 50002 inside the node (**Q-63**) | Phone wallets whose only server field is SSL, when the operator will not run a proxy | A listener. The product today is the reverse proxy. |
| `getblockchaininfo.softforks` | A client that reads that object and stops | Copy the buried map `getdeploymentinfo` already returns. Current LND does not stop: a missing `softforks` map falls through to `getdeploymentinfo`, and `deployments.taproot` is present. See [`lightning.md`](./lightning.md#bitcoind-with-rpc-polling). |
| ZMQ | LND's default bitcoind mode, Eclair, Dojo / Ashigaru | A publisher. Out of scope. LND's `rpcpolling` path does not need it ([`lightning.md`](./lightning.md)). Eclair and Dojo also need Core wallet RPC. |
| Core wallet RPC | The Core-wallet table above, plus Eclair | Out of scope. |
| Blockbook WebSocket | Trezor Suite | A new API. |
| `--network testnet4` | Wallets whose chain selector is testnet4 | A network. Not implemented. |
| NBXplorer version gate | BTCPay | A client change. The block-scan methods are already served. |
