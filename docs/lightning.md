# Lightning backends (CLN and LDK)

How **Core Lightning** and **ldk-node** (LDK) use this node as the Bitcoin
chain source. Not a Core wallet. Not LND (ZMQ / Neutrino). 0.x — do not put
mainnet channel funds here until this file says the contract is boring.

Operator flags: [`OPERATOR.md`](../OPERATOR.md). RPC JSON:
[`rpc.md`](./rpc.md). Electrum/Esplora surface: [`COMPAT.md`](../COMPAT.md).
Fee math: [`mempool-fee-estimation.md`](./mempool-fee-estimation.md).

## Status (spike 2026-09-20)

| Client | Path | Today |
|--------|------|--------|
| **CLN** stock `bcli` | `bitcoin-cli` → Core RPC | Methods exist on unix `{datadir}/rpc.sock`. Wrapper: [`scripts/lightning/bitcoin-cli`](../scripts/lightning/bitcoin-cli) (`-datadir=` → `--datadir`). Cookie/TCP `rpcauth` is not the product listen. |
| **ldk-node Esplora** | `--esplora-listen` REST | Tip, `/tx/*` (raw/status/outspend/merkleblock-proof), `/fee-estimates`, `POST /tx` work **without** `--sh-index`. Address/scripthash: 503 `scripthash index disabled`. |
| **ldk-node Electrum** | `--electrum-listen` TCP | Headers, `transaction.get` / broadcast, `estimatefee` work **without** `--sh-index`. `blockchain.scripthash.*`: JSON-RPC `scripthash index disabled`. TLS is reverse-proxy only (**Q-63**). |
| **ldk-node bitcoind REST** | `--rpc-listen --rest` `GET /rest/block/` | Block bytes, headers, and hash-by-height. TCP `/rest/` is unauthenticated and off unless `--rest` is set. The BDK wallet still needs Esplora or Electrum with `--sh-index`. |
| **LND** | bitcoind + ZMQ or BIP157 | ZMQ stays out. Optional `--block-filter-index` serves BIP158 basic for sealed heights and advertises `NODE_COMPACT_FILTERS` once filters first reach the tip. |

`--sh-index` is **not** required to start Electrum/Esplora or for channel
watches (txid / outpoint). SH-only methods fail closed.

## `--sh-index` API matrix

`--sh-index` defaults **off**. Class B scripthash is for address/history
wallets (BDK, Electrum address lists), not for Lightning channel monitors.

| Surface | Works **without** `--sh-index` | Needs `--sh-index` (fail closed if off) |
|---------|--------------------------------|------------------------------------------|
| **RPC** | chain, `getblock` / `getrawtransaction`, `gettxout`, `sendrawtransaction`, fees, mempool | none for LN |
| **Electrum** | `server.*`, headers / `blockchain.block.header`, `transaction.get` / `get_merkle` / `broadcast`, `estimatefee` / `relayfee` / `mempool.get_info`, `outpoint.*` | `blockchain.scripthash.*`, `blockchain.tweaks.subscribe`, `blockchain.silentpayments.*`, scripthash `asof:` |
| **Esplora REST** | tip, `/block/*`, `/tx/*` (raw / status / outspend / merkle*), `/mempool`, `/fee-estimates`, `POST /tx` | `/address/*`, `/scripthash/*`, `POST /addresses/*`, `POST /scripthashes/*` |

Fail closed (never empty history/utxo that looks like a new wallet):

- Electrum SH methods: JSON-RPC error, message **`scripthash index disabled`**.
- Esplora `/address` and `/scripthash`: HTTP **503** and that same phrase (not 404, not `[]`).

Tip stamp: tx / outpoint / block routes use **live tip**. Address / scripthash
routes use the **SH watermark** when the index is on ([`COMPAT.md`](../COMPAT.md)).

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
| `getutxout` | `gettxout` | Live coin: `value` BTC, `scriptPubKey.hex`. Spent / unknown / disconnected archive: JSON **`null`** (not RPC error). |
| `sendrawtransaction` | `sendrawtransaction` | `maxfeerate` is **sat/vB** (default 10000). CLN `allowhighfees` must pass **`0`**. |

`rbitcoin-cli` argv is `--datadir` / `--rpc-url`, not Core `-datadir=` /
`-rpcport`. That is why the wrapper exists.

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
| `/fee-estimates` | done (conf-target keys, sat/vB) |
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

## Gaps this plan still implements

1. Optional `scripts/lightning/run-cln.sh` / `run-ldk.sh` if those binaries exist (skip 0 otherwise).
2. Remaining LDK dialect holes found by those smokes.

## Not this node

Core wallet RPC, ZMQ, LND’s ZMQ chain source, in-binary Electrum TLS,
cookie/`rpcauth` as the LN listen. BIP158 basic filters are optional
(`--block-filter-index`). Core REST block/header/tx routes are on the RPC
listener.
