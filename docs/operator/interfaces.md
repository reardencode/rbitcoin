# Client interfaces

## Electrum

Internet-facing Electrum is supported as a **wallet-client backend** (Electrum,
Sparrow, similar): bind plain TCP (public or loopback), terminate **TLS at a
reverse proxy**, and rely on the node’s **app DoS limits** always being on. A
loopback-only bind is convenient with a local proxy, but it is **not** the
security model by itself.

**`--sh-index` is required for scripthash/address history.** Without it those
methods return `scripthash index disabled`; the listener still binds.

`server.version[0]` is `rbitcoin-electrs <ver>` so Cake Wallet
`getNodeIsElectrs()` will probe silent-payment tweaks. Other tweaks clients
do not need that substring. We are **not** electrs — see `COMPAT.md`.

**Not a search-box explorer.** We serve clients that already know their
scripthashes / txids. Address-prefix autocomplete is out.
**0.8** electrs HTTP drop-in (mempool.space nginx `/api/`): [`COMPAT.md`](../../COMPAT.md).

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --sh-index \
  --sp-tweaks \
  --electrum-listen 127.0.0.1:50001 \
  --log-level info
```

TLS is **not** built into the node. Terminate TLS at nginx, Caddy, HAProxy, etc.,
and proxy plain TCP to `--electrum-listen` (e.g. `127.0.0.1:50001` behind the
proxy, or a public bind if the proxy sits elsewhere and you accept that risk).

| Feature | Behavior |
|---------|----------|
| Banner | states **libre-relay-class** |
| Transport | plain TCP only (external TLS termination) |
| `transaction.broadcast` | mempool accept → P2P inv announce |
| Unconfirmed history/balance/mempool | from cluster mempool |
| `transaction.get` | chain then mempool fallback |
| `relayfee` / `estimatefee` / histogram | from Libre min + live mempool |
| Silent Payments tweaks | `blockchain.tweaks.subscribe` — with `--sp-tweaks` index: multi-height load (default ≤128 heights / ≤16384 eligible txs per wave) then per-height notifies, **one TCP flush per wave**. Indexed JSON-RPC result shares the first wave's Class A `txout` span; remaining heights of that wave are notifies; further waves overlap the next load with the previous write. Class A join is **one sequential `txout` span** from first..=last eligible fk in the wave (not one body pread per eligible tx; `seqsigwit` stays out). Pre-taproot: **one** notify with ≤1024 empty height keys (no store; Cake last key = progress). Cake `historicalMode=false` (param `[2]`): omit confirmed-spent P2TR outs. `--sp-tweaks-dust` (default 1000; 546 = Cake electrs): omit P2TR outs with `value <=` the floor. Without index / hole: naive per height (Class A + parent outs). **Not** request/response: JSON-RPC result is the **first** height (1-height probe `[0,1,false]` → `{"0": {}}`); further heights are notifications, then `{"message":"done"}` at a **wave boundary after 60s wall** (or when `count`/tip finishes first). Cake resubscribes; kiss-bdk one-shot stops until it loops. `server.features.genesis_hash` is the chain check. `server.version[0]` contains `electrs` (Cake probe). On 9p-class IO expect slower than local disk. |

### API request log

`--api-log PATH` (or conf `api_log=PATH`) appends **one JSON line per Electrum, Esplora, and RPC call**:

```
{"ts":"…Z","surface":"electrum","peer":"192.168.88.20:51122","method":"blockchain.tweaks.subscribe","params":"[850000,8,false]","wall_ms":2410,"ok":true,"err":null}
```

`tail -f` that file. The same line is also emitted at **TRACE** as `api: …`
(so `--log-level trace` shows methods in `mainnet.log`; DEBUG stays usable
during a wallet/bench query storm). Params are truncated (~384 bytes) so
broadcast hex does not fill the disk.

Use this to see whether a client is hitting tweaks vs only scripthash history, and which calls take seconds.
`wall_ms` is the full handler (including JSON). Scripthash history / balance /
UTXO / Esplora address stats share one waved Class A + spend join on the
process `RBITCOIN_IO` session. `--log-level trace` emits
`sh_join: creates=… outs=… need=… pages_us=… class_a_us=… spends_us=…` when
that join exceeds 10 ms (`need=` is `cs` / `c` / `-`: create and/or spender
`txid.body`). That split is not an `ibd: perf` line and is not extra JSONL
fields. Esplora `/address/{addr}/utxo` status (`block_hash` / `block_time`)
comes from join height plus unique headers — not a per-coin `tx.head` probe.
Confirmed `/txs` uses join `tx_fk` (no second `tx.head`). `getblock` verbosity 1
lists `txid.body`. Esplora `/utxo` applies the same mempool overlay as Electrum
`listunspent`. `listunspent` loads `txid.body` only for unspent creates.
`sh_join` with a history `to_height` skips Class A expand for creates at or
past that exclusive bound. Electrum subscribe tip restatus intersects the SH
posting list with the new block's tx fks and prevout `create_fk`s; a miss
does not expand packed `txout`. Full status still runs on a hit. Each Electrum
TCP connection keeps one last-scripthash join (outs + spentness) until tip
height changes, so Casa `get_balance` → `get_history` → `listunspent` on the
same socket pays Class A once. Not a process-global cache. Esplora REST keys
reuse by nginx `$connection` via `X-Rbitcoin-Client` (**unix listen or TCP
loopback only**; public TCP ignores the header): **last-1 GET** so address-page
stats∥txs∥utxo and `after_txid` on the same script reuse one slot;
**last-bulk POST** (16 MiB packed/client) so wallet `POST /addresses/txs` then
the same POST with `after_txid` reuse. Idle **30s**; **256** clients (evict
idle-longest). Not an 8-script LRU and not a >5s process whale cache. Extra
operator RAM is the kernel page cache of Class A `txout` / SH heads. Public
explorer second-hit of a whale GET is nginx/CDN (`/api/address/` is cacheable).
`--max-sh-creates N` (`N>0` → Esplora **503** on an unpaged join) is the fuse; default **10000**. **0** is unlimited. A paged history request is still served.

Re-measure fat keys on the operator host (`rbitcoin-bench --suite casa
--passes 1 --warmup 1`). Do not treat agent-VM times as product numbers.

### App DoS floor (always on)

Shared [`ServeLimits`](crates/rbitcoin-electrum) defaults (also the future Esplora
floor). Excess connections are **rejected immediately** (no hang); oversize lines
and idle clients fail closed.

| Limit | Default | Role |
|-------|---------|------|
| Max connections | 256 | Concurrent Electrum TCP clients |
| Max request line | 1 MiB | One JSON-RPC line including `\n` |
| Idle timeout | 120 s | No complete request → disconnect |
| Max scripthash subs / conn | 10000 (`--electrum-max-subs`) | Notify fan-out cap. A wallet subscribes every address up to its gap limit; each sub is ~170 B (≈0.45 GB worst case at 256 connections) plus one posting check per block against that block's shared touch set; a reorg restatuses every sub |
| Max broadcast hex | ~8 MiB | `transaction.broadcast` hex length |

Edge rate-limits, auth, and TLS cipher policy stay on the proxy. See
[`SECURITY.md`](../../SECURITY.md).

## Client benchmark (Electrum / Esplora)

Optional crate `rbitcoin-bench` talks to **any** Electrum TCP or Esplora HTTP
server (rbitcoin, Fulcrum, electrs, ElectrumX, Blockstream electrs, …). It is
**not** in `default-members` and **not** in the musl product package.

```bash
# embedded corpus matching --suite (no --targets needed)
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite casa
cargo run -p rbitcoin-bench --features cli --release -- \
  --esplora http://127.0.0.1:3000 --suite casa --corpus hot
# or your own list: one scripthash hex or address per line
printf '%s\n' bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq > /tmp/sh.txt
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --targets /tmp/sh.txt --suite casa
# per-key CSV (casa/hot): heights, tx/utxo counts, warm times for each query
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite casa --out /tmp/casa.csv
# many concurrent small wallets (one OS thread in the bench process)
cargo run -p rbitcoin-bench --features cli --release -- \
  --electrum 127.0.0.1:50001 --suite clients --clients 32
```

| `--suite` | What it measures |
|-----------|------------------|
| `casa` | Lopp/Casa 2020–2022: sequential `get_balance`, `get_history`, `listunspent` per key on one TCP connection (the node reuses that connection's last SH join). Discard `--warmup` (default 1), keep `--passes` (default 9), report p50/p95 and history-size buckets. |
| `sparrow` | Sparrow 2022 wallet load (`subscribe` batches of `--batch`, default 50) then refresh (`get_history` batches). `--fetch-txs` also pulls `blockchain.transaction.get`. Electrum only. |
| `hot` | Fat-history keys (one-shot history + UTXO). Use for high-fanout scripts. |
| `clients` | N concurrent Electrum TCP or Esplora HTTP sessions (`--clients`, default 8) on **one OS thread**, each reloading a small wallet sliced from `--corpus` (default `sparrow`). Wallet sizes mix 8/16/32 keys unless `--wallet-keys N`. Keys that would push a wallet over `--max-txs` (1000) or `--max-utxos` (100) are dropped so megakeys do not dominate. Primary sample is `wallet_load` wall time under concurrency. |

| `--corpus` | Packed-in keys (default = `--suite`; `clients` uses `sparrow`) |
|------------|--------------------------------------|
| `hot` | Public fat keys: P2A `bc1pfeessrawgf` (portlandhodl electrs stress), genesis P2PKH, burns, high-tx exchange/mining addresses. |
| `casa` | ~4k unique output scripts from **77 heights spaced genesis→tip** (plus segwit / taproot / Casa-window pins) on a synced rbitcoin store, plus a few known mid-history addresses. Not Casa’s 103k dump from blocks 599900–600100 — that 200-block window makes height-list servers (electrs) look artificially fast because every key hits the same few blocks. |
| `sparrow` | 3000 keys, same spread-height source (Sparrow’s published run used a ~3000-address wallet). |

`--targets FILE` overrides the embedded list. Same corpus against two servers is
the comparison. First pass is usually cache-cold; Casa’s published numbers drop
that pass. Sequential by default (Casa did not test multi-thread load). `--suite clients`
is concurrent connections multiplexed on the bench’s current-thread runtime
(light next to a node on the same host; raise `--clients` to add sessions, not
threads). TLS is the reverse proxy’s job — point the client at plain
`127.0.0.1`.

Progress goes to **stderr** (stdout stays the p50/p95 table): about one line
per 5% plus at most one extra line every 15s, with elapsed and ETA. Sparrow
relabels load → refresh (→ txs if `--fetch-txs`).

`--out FILE` (casa/hot) writes one CSV row per key: `oldest_tx` / `newest_tx`
(confirmed history heights), `oldest_utxo` / `newest_utxo`, `txs`, `utxos`,
then `get_balance_us_1..N`, `get_history_us_1..N`, `listunspent_us_1..N` for
the counted warm passes (default N=9; warmup omitted). Blank height cells mean
no confirmed item. Esplora `oldest_tx`/`newest_tx` are from the returned
`/txs` page, while `txs` uses `chain_stats.tx_count` when present. For
`--suite clients`, `--out` is one row per connection:
`client,n_keys,txs,utxos,wallet_load_us_1..N`.

## Esplora REST

Blockstream-**compatible** **plain HTTP** API for **wallet clients** and
**mempool/electrs HTTP drop-in** (exact address/scripthash, tx/block by id,
broadcast). `/internal/*` is **unix listen only** (mempool Node
`ESPLORA.UNIX_SOCKET_PATH` → `--esplora-listen /path.sock`). nginx `/api/`
can retire electrs ([`COMPAT.md`](../../COMPAT.md)). Same internet-facing model as Electrum: app DoS
limits always on; terminate TLS at a reverse proxy.

**`--sh-index` is required for `/address` and `/scripthash` history.** Without
it those routes are 503 `scripthash index disabled`; the listener still binds.

**Still out:** explorer search/`address-prefix`, Liquid, in-binary
mempool.space `/api/v1/` catalogue. Opt-in `GET /block-template` is GBT
(`--esplora-block-template`), not a stratum/pool stack. Compact
`/address|scripthash/…/txs/summary` is a mempool.space-shaped dialect (not
Blockstream Esplora `API.md`); surface: [`COMPAT.md`](../../COMPAT.md).

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --sh-index \
  --esplora-listen 127.0.0.1:3000 \
  --rpc \
  --log-level info
```

Conf: `sh_index=1` and `esplora_listen=127.0.0.1:3000`. Default is **disabled**.
Leave `--max-sh-creates` at **10000** (or **0** for an unlimited unpaged join) for explorer backends. Paged history still stops at the page.

TCP Esplora does not keep a mempool of `Arc<Transaction>`. `GET /mempool` loads
the fee snapshot (count/vsize/total_fee + histogram). Unix `/internal` mempool-tx
pages lazy-build one published body snapshot (JSON `OnceLock` per live tx after
the first page; dirty/singleflight; not FIFO/LRU). RAM: [`docs/ibd-memory.md`](docs/ibd-memory.md).

| Feature | Behavior |
|---------|----------|
| Transport | plain HTTP (axum + tower body/concurrency/timeout from `ServeLimits`) |
| Tip / blocks | tip height/hash; `/blocks[/:start_height]` (10 summaries); `/block/:hash` JSON + **raw** + status |
| Tx | full JSON, hex, **raw**, status, Electrum merkle-proof, **BIP37 merkleblock-proof**, outspends |
| Address / scripthash | chain_stats, utxo, `/txs` + `/txs/chain` + `/txs/mempool`, compact `/txs/summary` (dialect; [`COMPAT.md`](../../COMPAT.md)); complete after SH tip finalize |
| Mempool | `/mempool`, `/mempool/txids`, `/mempool/recent`, `/fee-estimates`; `POST /tx` and **`POST /txs/package`** when hub open |
| Without mempool | mempool routes empty/safe; POST broadcast → **503** |
| Unknown / non-goal | **404** (address-prefix; Liquid; mempool.space `/ws` / `/v1/ws`). `GET /block-template` is 404 unless `--esplora-block-template`. `/internal/*` **unix listen only** (TCP 404): [`COMPAT.md`](../../COMPAT.md) |

**Large responses:** `GET /block/:hash/raw` may be multi‑MB; concurrency/timeout from `ServeLimits` still apply.
**Package broadcast:** body is a JSON array of tx hex (max 25); uses the same libre-relay mempool policy as single `POST /tx`.

DoS knobs share Electrum’s `ServeLimits` defaults (256 conns, 1 MiB body, 120 s timeout).

### mempool.space

Stock mempool Node + MariaDB + frontend. nginx **`/api/`** → this Esplora
(unix); **`/api/v1/`** → their process (`:8999`). Set `MEMPOOL.BACKEND=esplora`.
Point Node `ESPLORA.UNIX_SOCKET_PATH` at `--esplora-listen
/run/rbitcoin/esplora.sock` (mode **0660**; dummy `Host: api` is fine) so
`/internal/*` is available. Put the sock in `/run/rbitcoin` (**0750**,
rbitcoin user + `nginx` group) — nginx cannot traverse `{datadir}` when that
tree is `0700`. TCP `--esplora-listen host:port` is public REST only (no
`/internal`). Core RPC is TCP plus a Core cookie, which stock mempool
supports unpatched; see [mempool.space `CORE_RPC`](#mempoolspace-core_rpc).
Requires `--sh-index`. The default `--max-sh-creates` is 10000; set 0 for an
unlimited unpaged join.

```bash
sudo mkdir -p /run/rbitcoin
sudo chown "$(id -un)":nginx /run/rbitcoin
sudo chmod 0750 /run/rbitcoin

# Core-format cookie: no trailing newline, 0640, group mempool, written before
# every start (/run is tmpfs). The node's primary group may be shared (users).
printf '__cookie__:%s' "$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')" |
  sudo install -m 0640 -o "$(id -un)" -g mempool /dev/stdin /run/rbitcoin/rpc.cookie

./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --sh-index \
  --rpc-listen 127.0.0.1:8332 \
  --rpc-cookie-file /run/rbitcoin/rpc.cookie \
  --esplora-listen /run/rbitcoin/esplora.sock \
  --log-level info
```

mempool's Node user needs three memberships: `nginx` to traverse
`/run/rbitcoin` (**0750**), the node's group for the **0660** Esplora socket,
and `mempool` for the **0640** cookie. First start
must import `pools-v2.json` or every block is **Unknown**: `npm run start
--update-pools` (needs GitHub, or point `POOLS_JSON_URL` /
`POOLS_JSON_TREE_URL` at a local mirror). `SELECT COUNT(*) FROM pools` is
hundreds when that worked. Predicted blocks wait on Node’s first mempool
sync + rust-gbt; they are empty until `/internal/mempool/txs` has filled.

## Core-class JSON-RPC

Optional HTTP JSON-RPC subset (default **off**). `--rpc` binds
`{datadir}/rpc.sock` (mode **0600**, filesystem auth, no HTTP header).
`--rpc-socket PATH` binds that socket at PATH instead, mode **0660**, so a
client in rbitcoin's group can connect without traversing the `0700` datadir.
`--rpc-listen` adds TCP on `127.0.0.1:<network port>` when ADDR is omitted
(mainnet 8332, testnet 18332, signet 38332, regtest 18443). TCP auth is
`Authorization: Bearer` from `{datadir}/rpc.token` (0600), plus optional Core
cookie HTTP Basic from `--rpc-cookie-file PATH`. The same
listeners serve Core REST when `--rest` is set: `GET /rest/chaininfo.json`, block, headers, tx,
mempool, `getutxos`, `deploymentinfo`, and `blockfilter/basic` for heights
`--block-filter-index` has sealed. TCP `/rest/` is unauthenticated (Core).
`{datadir}/rpc.sock` stays mode 0600 with no HTTP header. See
[`docs/rpc.md`](../../docs/rpc.md) and [`COMPAT.md`](../../COMPAT.md).

```bash
./target/release/rbitcoin-node \
  --datadir ./datadir-mainnet \
  --network mainnet \
  --rpc \
  --log-level info
# local socket:
rbitcoin-cli --datadir ./datadir-mainnet getblockcount
```

### mempool.space `CORE_RPC`

Stock mempool reaches bitcoind over TCP with HTTP Basic. rbitcoin has no
`--rpcuser` / `--rpcpassword`; the only Basic credential it accepts is a
Core-format cookie named by `--rpc-cookie-file PATH`, and only on the TCP
listener. The node reads that file and never creates it, so write it before
each start (the [mempool.space](#mempoolspace) command above does). Keep it
readable only by the rbitcoin and mempool service identities.

1. Start the node with `--rpc-listen 127.0.0.1:<network RPC port>` and
   `--rpc-cookie-file /run/rbitcoin/rpc.cookie`.
2. Point mempool at the same file:

   ```json
   "CORE_RPC": {
     "HOST": "127.0.0.1",
     "PORT": 8332,
     "COOKIE": true,
     "COOKIE_PATH": "/run/rbitcoin/rpc.cookie"
   }
   ```

   `USERNAME` / `PASSWORD` are ignored while `COOKIE` is true. mempool
   re-reads the file after a 401, so a cookie rewritten on node restart is
   picked up.
3. Check it as a user that can read the cookie (the credential goes through
   stdin, not argv):

   ```bash
   printf 'user = "%s"\n' "$(cat /run/rbitcoin/rpc.cookie)" |
     curl -sK- --data-binary '{"id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:8332/
   ```

   returns the block count. The TCP listener, like Electrum and Esplora, binds
   only after initial catch-up, so during IBD this is connection refused and
   mempool retries. The cookie itself is checked at launch.

The file must be exactly `username:password` with **no trailing newline**, as
Core writes it. mempool sends the raw bytes as the credential, so a newline
would 401 forever while bitcoin-cli (which strips it) still works. rbitcoin
refuses to start on such a file. Write it with `printf`, not `echo`.

**Optional: unix socket instead of TCP.** Stock mempool cannot do this:
its unix config (`ESPLORA.UNIX_SOCKET_PATH`) is Esplora only, and Core RPC
goes through `backend/src/rpc-api/jsonrpc.ts`, which builds Node
`http.request` options from `CORE_RPC.HOST` / `PORT` with no socket support.
A patched mempool adds `CORE_RPC.SOCKET_PATH`, plumbs it through
`bitcoin-client.ts` into those request options as `socketPath`, and sets no
`auth` when it is used; see the `rbitcoin-compat` branch of
[reardencode/mempool](https://github.com/reardencode/mempool/tree/rbitcoin-compat).
Bind `--rpc-socket /run/rbitcoin/rpc.sock`
(mode **0660**, filesystem auth, mempool's user in rbitcoin's group); no
cookie or `Authorization` header is involved.

### Reverse proxy (TLS)

Terminate TLS at the proxy.
`/api/v1/` is mempool's Node (MariaDB catalogue), including its WebSocket
**`/api/v1/ws`**. `/api/` is rbitcoin Esplora (electrs HTTP, no WebSocket).
Register `/api/v1/` **first**. Deny
`/api/internal/` at nginx even when Esplora is a unix sock.

**Slash rules (these 404/502 if wrong):**

- Node `proxy_pass` has **no** trailing slash. Their routes are
  `/api/v1/mining/…` and `/api/v1/ws`. `http://127.0.0.1:8999/` strips the
  prefix and Express 404s (`Cannot GET /mining/pool/…`).
- Unix Esplora URI after the sock **is** `/`.
  `http://unix:/run/rbitcoin/esplora.sock:/` replaces `/api/` with `/` so
  Esplora sees `/blocks/tip/height`. A colon with nothing after it leaves
  `/api/…` on the request → Esplora **404**. Direct
  `curl --unix-socket … http://api/blocks/tip/height` can still be 200.

Local mempool.space (NixOS; browse `http://127.0.0.1:8080`). `virtualHosts."localhost"`
so `Host: localhost` matches. Frontend `proxyPass` uses `localhost:4200` (not
`127.0.0.1`) when `ng serve` bound `::1` only. Unix `proxy_pass` stays in
`extraConfig` so NixOS does not rewrite the sock URL.

```nix
services.nginx = {
  enable = true;
  recommendedProxySettings = true;
  virtualHosts."localhost" = {
    listen = [{ addr = "127.0.0.1"; port = 8080; }];
    extraConfig = ''
      proxy_http_version 1.1;
      proxy_read_timeout 3600s;
    '';
    locations."/api/v1/" = {
      proxyPass = "http://127.0.0.1:8999";
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
      '';
    };
    locations."^~ /api/internal/" = {
      extraConfig = "return 404;";
    };
    locations."/api/" = {
      extraConfig = ''
        proxy_pass http://unix:/run/rbitcoin/esplora.sock:/;
        proxy_set_header Host api;
        proxy_set_header X-Rbitcoin-Client $connection;
      '';
    };
    locations."/" = {
      proxyPass = "http://localhost:4200";
      extraConfig = ''
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
      '';
    };
  };
};
```

Equivalent nginx (public TLS or TCP Esplora on `:3000` — keep the same slashes):

```nginx
location /api/v1/ {
  proxy_pass http://127.0.0.1:8999;
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_read_timeout 3600s;
}
location ^~ /api/internal/ {
  return 404;
}
location /api/ {
  proxy_pass http://unix:/run/rbitcoin/esplora.sock:/;
  # TCP Esplora: proxy_pass http://127.0.0.1:3000/;
  proxy_http_version 1.1;
  proxy_set_header Host api;
  proxy_set_header X-Rbitcoin-Client $connection;
  proxy_read_timeout 3600s;
}
```

Probe (200 + a height, `X-Powered-By: rbitcoin-esplora/…`):

```bash
curl -sS -D- http://127.0.0.1:8080/api/blocks/tip/height | head
```

Caddy: `reverse_proxy` to the same
listen. `X-Rbitcoin-Client $connection` is how last-1 GET and last-bulk POST
joins stick to one nginx connection; omit it on a public TCP expose. HTTP/1.1
browsers open several `$connection` ids (each GET can miss last-1); terminate
**HTTP/2** on this location so one tab maps to one connection. Every Esplora
REST response includes
`X-Powered-By: rbitcoin-esplora/<version>-<hex>` (mempool failover regex).
