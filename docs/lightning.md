# Lightning backends

How Core Lightning, ldk-node, and LND use this node as the Bitcoin chain
source. On-chain wallets are [`wallets.md`](./wallets.md). This is not a
Core wallet. 0.x — do not put mainnet channel funds here until this file
says the contract is boring.

Operator flags: [`OPERATOR.md`](../OPERATOR.md). RPC JSON:
[`rpc.md`](./rpc.md). Electrum/Esplora surface: [`COMPAT.md`](../COMPAT.md).
Fee math: [`mempool-fee-estimation.md`](./mempool-fee-estimation.md).
Cookie file for TCP clients: [`wallets.md`](./wallets.md#tcp-rpc-cookie).

## Status

| Client | Path | Today |
|--------|------|--------|
| **CLN** stock `bcli` | `bitcoin-cli` → Core RPC | Methods exist on unix `{datadir}/rpc.sock`. Wrapper: [`scripts/lightning/bitcoin-cli`](../scripts/lightning/bitcoin-cli) (`-datadir=` → `--datadir`). Cookie/TCP `rpcauth` is not the product listen. |
| **CLN** `sauron` | Esplora HTTP | Channel watches use tip, tx, outspend, and broadcast. Point the plugin at `--esplora-listen`. No `--sh-index`. |
| **ldk-node Esplora** | `--esplora-listen` REST | Tip, `/tx/*` (raw/status/outspend/merkleblock-proof), `/fee-estimates`, `POST /tx` work **without** `--sh-index`. Address/scripthash: 503 `scripthash index disabled`. |
| **LDK gossip `UtxoLookup`** | `GET /block-height/{height}/tx/{index}/out/{vout}` | Served without `--sh-index`. Stock ldk-node, CLN, and LND do not call it. The application connector is [Gossip connector](#gossip-connector). |
| **ldk-node Electrum** | `--electrum-listen` TCP | Headers, `transaction.get` / broadcast, `estimatefee` work **without** `--sh-index`. `blockchain.scripthash.*`: JSON-RPC `scripthash index disabled`. TLS is reverse-proxy only (**Q-63**). |
| **ldk-node bitcoind REST** | `--rpc-listen --rest` `GET /rest/block/` | Block bytes, headers, and hash-by-height. TCP `/rest/` is unauthenticated and off unless `--rest` is set. The BDK wallet still needs Esplora or Electrum with `--sh-index`. |
| **LND** `bitcoind` + `rpcpolling` | TCP JSON-RPC, cookie file | Chain, tx, fee, and broadcast methods exist. ZMQ is not required on this path. Taproot detection falls through to `getdeploymentinfo`, which already lists buried taproot. See [LND](#lnd). |
| **LND** Neutrino | BIP157 to a v2 peer | `--block-filter-index` serves basic filters and advertises `NODE_COMPACT_FILTERS` once they first reach the tip. Neutrino does not speak BIP324. This node is v2-only, so Neutrino cannot connect. |
| **LND** default `bitcoind` | ZMQ `rawblock` + `rawtx` | ZMQ is not served. Use `bitcoind.rpcpolling=true` instead. |
| **Eclair** | Core wallet + ZMQ | Needs a wallet-enabled Core node (`getnewaddress` and the watch-only wallet) plus ZMQ. Both are absent here. |
| **Zeus** embedded LND, Lightning Terminal, Loop, Pool, Faraday, tapd | Whatever LND is using | Same as the LND row they configure. |
| **Phoenix, Breez** | Operator backends | The apps talk to their operators' Electrum and Lightning services. They have no home-node setting. |

`--sh-index` is **not** required to start Electrum/Esplora or for channel
watches (txid / outpoint). SH-only methods fail closed.

## `--sh-index` API matrix

`--sh-index` defaults **off**. Class B scripthash is for address/history
wallets (BDK, Electrum address lists), not for Lightning channel monitors.

| Surface | Works **without** `--sh-index` | Needs `--sh-index` (fail closed if off) |
|---------|--------------------------------|------------------------------------------|
| **RPC** | chain, `getblock` / `getrawtransaction`, `gettxout`, `sendrawtransaction`, fees, mempool | none for LN |
| **Electrum** | `server.*`, headers / `blockchain.block.header`, `transaction.get` / `get_merkle` / `broadcast`, `estimatefee` / `relayfee` / `mempool.get_info`, `outpoint.*` | `blockchain.scripthash.*`, `blockchain.tweaks.subscribe`, `blockchain.silentpayments.*`, scripthash `asof:` |
| **Esplora REST** | tip, `/block/*`, `/tx/*` (raw / status / outspend / merkle*), `/mempool`, `/fee-estimates`, `POST /tx`, `GET /block-height/{height}/tx/{index}`, `GET /block-height/{height}/tx/{index}/out/{vout}`, `GET /tx/{txid}/out/{vout}`, `POST /block-heights/txs/outs` | `/address/*`, `/scripthash/*`, `POST /addresses/*`, `POST /scripthashes/*` |

Fail closed (never empty history/utxo that looks like a new wallet):

- Electrum SH methods: JSON-RPC error, message **`scripthash index disabled`**.
- Esplora `/address` and `/scripthash`: HTTP **503** and that same phrase (not 404, not `[]`).

Tip stamp: tx / outpoint / block routes use **live tip**. The four position
routes above also accept `?asof=<blockhash>`; `X-Bitcoin-Chain-Tip` then
names that pin. Live gossip omits `asof`. A replay against a header passes
that header. Address / scripthash routes use the **SH watermark** when the
index is on ([`COMPAT.md`](../COMPAT.md)).

## CLN (`bcli` → `bitcoin-cli`)

CLN does not use a Core wallet. The default bitcoin plugin shells out to
`bitcoin-cli` for five JSON-RPC commands. Target operator line:

```text
lightningd --network=regtest \
  --bitcoin-cli=/path/to/scripts/lightning/bitcoin-cli \
  --bitcoin-datadir=/path/to/rbitcoin/datadir
```

Wrapper [`scripts/lightning/bitcoin-cli`](../scripts/lightning/bitcoin-cli) talks to `{datadir}/rpc.sock` only. No `.cookie`.

| Plugin | Node RPC | Spike |
|--------|----------|--------|
| `getchaininfo` | `getblockchaininfo` | `chain` is bip70 (`regtest` / `signet` / `main` / `test`). `blocks`, `headers`, `initialblockdownload` present. |
| `estimatefees` | `estimatesmartfee` 2 / 6 / 12 / 100 | Core JSON `{feerate: BTC/kvB, blocks}`, or `{errors: ["Insufficient data or no feerate found"], blocks}` with no `feerate`. Conf target 1–1008. Product is **10-minute inclusion**, not Core historical. `bcli` converts BTC/kvB → sat/kvB. |
| `getrawblockbyheight` | `getblockhash` + `getblock` verbosity **0** | Hex string; `false` is verbosity 0. Witness included on reconstruct. |
| `getutxout` | `gettxout` | Live coin: `value` BTC, `scriptPubKey.hex`. Spent / unknown / disconnected archive: JSON **`null`** (not RPC error). A closed channel's announcement cannot be re-checked for script and value on this path. CLN has no hook for the position route, which still returns those fields when `spent` is true. |
| `sendrawtransaction` | `sendrawtransaction` | `maxfeerate` is **sat/vB** (default 10000). CLN `allowhighfees` must pass **`0`**. |

`rbitcoin-cli` argv is `--datadir` / `--rpc-url host:port`, not Core
`-datadir=` / `-rpcport`. The value is an address, not a URL. That is why
the wrapper exists.

## LDK / ldk-node

ldk-node chain sources: Esplora, Electrum, bitcoind RPC/REST. Esplora and
Electrum are above. Bitcoind REST is `GET /rest/…` on `--rpc-listen` when
`--rest` is also set (same port as JSON-RPC). The BDK wallet on that REST source still needs an
address index, so point BDK at Esplora or Electrum with `--sh-index`.

### Esplora (`EsploraSyncClient` + BDK)

`--esplora-listen`. Channel sync (no SH):

| HTTP | Spike |
|------|--------|
| `/blocks/tip/hash`, `/blocks/tip/height` | done |
| `/tx/:txid/raw`, `/hex`, `/status` | done |
| `/tx/:txid/outspend/:n` | done (`spent`, optional `txid` / `vin` / `status`) |
| `/tx/:txid/merkleblock-proof` | done (BIP37 hex; verifies against header merkle root) |
| `/fee-estimates` | done (conf-target keys, sat/vB; **200** `{}` when none, except mainnet **503**) |
| `POST /tx` | done |

BDK on-chain wallet still needs `/address/*` and `/scripthash/*` → **`--sh-index`**.

### Electrum (`ElectrumSyncClient` + BDK)

`--electrum-listen` plain TCP. TLS at the reverse proxy.

| Method | Spike |
|--------|--------|
| `server.version` / `features` | done (`protocol_max` 1.6) |
| `blockchain.headers.subscribe`, `blockchain.block.header` | done |
| `blockchain.transaction.get`, `broadcast` | done |
| `blockchain.estimatefee` | done (10-minute product; `-1` if insufficient) |
| `blockchain.scripthash.*` | done **only with SH** |

## Gossip connector

Stock `EsploraSyncClient` does not implement this. An application that
verifies `channel_announcement` gossip copies the two functions below.
There is no `lightning` crate in this repo. Pass only
`channel_announcement.short_channel_id`. An alias short channel id is not
a bit pattern these functions can reject.

Check the chain hash first. A mismatch is `UnknownChain` and does not send HTTP.

`spent: true` still carries the script and value. The trait means the
funding output exists now, so the sample returns `UnknownTx`. A checker
that only wants the historical script can read the body.

A mempool spend stays `spent: false` here. The sample does not call
outspend. A caller who must refuse that spend also reads
`GET /tx/{txid}/outspend/{vout}`.

Live gossip omits `asof`. A replay against a header adds
`?asof=<blockhash>` to the same path. `funding_output_path` leaves that
query off.

```rust
/// BOLT 7 waits six confirmations. LDK `GossipVerifier` uses five
/// (`block_height + 5 > tip`).
const CONFIRMATIONS: u32 = 6;
const BATCH_LIMIT: usize = 300;

enum Lookup {
    TxOut { script_hex: String, value: u64 },
    UnknownTx,
    UnknownChain,
    Retry,
}

fn scid_parts(scid: u64) -> (u32, u32, u32) {
    (
        (scid >> 40) as u32,
        ((scid >> 16) & 0x00ff_ffff) as u32,
        (scid & 0xffff) as u32,
    )
}

fn funding_output_path(height: u32, index: u32, vout: u32) -> String {
    format!("/block-height/{height}/tx/{index}/out/{vout}")
}

/// One funding output. `status` is the HTTP status. `spent: true`, a 404,
/// and fewer than `CONFIRMATIONS` are `UnknownTx`. 5xx is `Retry`.
fn lookup_funding_utxo(
    status: u16,
    spent: Option<bool>,
    block_height: u32,
    tip_height: u32,
    script_hex: &str,
    value: u64,
) -> Lookup {
    if status >= 500 {
        return Lookup::Retry;
    }
    if status != 200 {
        return Lookup::UnknownTx;
    }
    // spent: true
    if spent != Some(false) {
        return Lookup::UnknownTx;
    }
    if tip_height.saturating_sub(block_height) < CONFIRMATIONS {
        return Lookup::UnknownTx;
    }
    Lookup::TxOut {
        script_hex: script_hex.to_string(),
        value,
    }
}

/// Graph sync. Each inner vec is one `POST /block-heights/txs/outs` body,
/// capped at `BATCH_LIMIT`. A null JSON slot is `UnknownTx` for that id.
/// HTTP 422 means the chunk was longer than 300. Zip each element with
/// `lookup_funding_utxo`.
fn lookup_funding_utxos(scids: &[u64]) -> Vec<Vec<(u32, u32, u32)>> {
    scids
        .chunks(BATCH_LIMIT)
        .map(|chunk| chunk.iter().copied().map(scid_parts).collect())
        .collect()
}
```

`funding_output_path` is the GET. `lookup_funding_utxo` decides the trait
result from the response. `lookup_funding_utxos` only builds the batch
bodies.

## LND

Two chain sources exist in current LND. One can use this node. One cannot.

### `bitcoind` with RPC polling

Set `bitcoind.rpcpolling=true`. LND then learns about blocks and
transactions by polling JSON-RPC. It does not open ZMQ. Authenticate with
`bitcoind.rpccookie` pointed at the file from
[`wallets.md`](./wallets.md#tcp-rpc-cookie). There is no `--rpcuser` /
`--rpcpassword`, and LND will not find ZMQ endpoints in a `bitcoin.conf`
because this node does not write one. Pass the cookie path and
`bitcoind.rpchost=127.0.0.1` explicitly.

```text
bitcoin.node=bitcoind
bitcoind.rpchost=127.0.0.1
bitcoind.rpccookie=/run/rbitcoin/rpc.cookie
bitcoind.rpcpolling=true
```

Start the node with `--rpc-listen` and `--rpc-cookie-file` on that path.
`--sh-index` is not involved. `getrawtransaction` answers from the archive
without a `txindex` flag.

What LND's startup check actually reads (current `chainreg/taproot_check.go`):

1. `getblockchaininfo`. This response has no `softforks` object.
2. Because that map is absent, LND does not treat the call as "no taproot".
   It calls `getdeploymentinfo`.
3. `deployments.taproot` is present (buried, same object as
   `getdeploymentinfo`). LND treats the key as support. It also accepts
   `script_flags` containing `TAPROOT`; we do not emit `script_flags`, and
   the deployments key is enough for this check.

`getnetworkinfo.version` defaults to `190000`. LND's health check uses
`uptime` when that integer is at least `150000`, which it is.
`--rpc-client-version` can raise the integer for a client that gates on
it. The flag does not add wallet RPC. See
[`rpc.md`](./rpc.md#getnetworkinfoversion).

`estimatesmartfee` accepts `estimate_mode` `economical` and `conservative`
and returns the same 10-minute feerate either way. `initialblockdownload`
means relay is inhibited (`--min-chain-work` / `--max-tip-age`), not
"headers are still downloading."

`gettxout` returns JSON null once the funding output is spent, so a closed
channel's announcement cannot be re-checked for script and value here
either. LND has no hook for the position route.

This path is read from LND's source and from this node's RPC. It has not
been run as a channel smoke.

### Neutrino

`--block-filter-index` is the server half: BIP158 basic filters, P2P
`getcfilters` / `getcfheaders` / `getcfcheckpt`, and `NODE_COMPACT_FILTERS`
once the filter watermark first reaches the tip. Peers that connected
before that advertisement do not learn the bit; a later connection does.

Neutrino's BIP324 handshake is still upstream work
([lightninglabs/neutrino#319](https://github.com/lightninglabs/neutrino/issues/319)).
Until that client speaks v2, it cannot peer with this node. Serving v1
P2P to make Neutrino connect is out of scope.

### Default ZMQ mode

`bitcoind.zmqpubrawblock` and `bitcoind.zmqpubrawtx` have nothing to
connect to. ZMQ is out of scope ([`wallets.md`](./wallets.md#what-is-still-missing-for-other-wallets)).
`rpcpolling` is the configuration that matches the RPC we already serve.

## Eclair

Current Eclair requires Bitcoin Core's wallet RPC and ZMQ
(`zmqpubhashblock`, `zmqpubrawtx`), plus `rpcuser` / `rpcpassword`. The
wallet calls and ZMQ are both absent. An Esplora or Electrum URL is not a
chain backend Eclair reads.

## Smoke stubs

[`scripts/lightning/run-cln.sh`](../scripts/lightning/run-cln.sh) and
[`run-ldk.sh`](../scripts/lightning/run-ldk.sh) exit 0 without funding a
channel or syncing a wallet. They skip when `lightningd` or `ldk-node` is
absent. A live smoke is a follow-up.

## Not this node

Core wallet RPC, ZMQ, in-binary Electrum TLS, and v1 P2P. BIP158 basic
filters are optional (`--block-filter-index`). Core REST block/header/tx
routes are on the RPC listener when `--rest` is set. TCP JSON-RPC accepts
a cookie file when `--rpc-cookie-file` is set; that is the LND and Wasabi
credential, not `rpcauth`.
