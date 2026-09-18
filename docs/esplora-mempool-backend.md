# 0.8: drop-in Core + electrs for mempool.space

**Status:** plan (not shipped). **Q-68.** Execute after **0.7.0**. Anatomy:
[`how-we-plan.md`](./how-we-plan.md). Shipped surface today:
[`COMPAT.md`](../COMPAT.md). Owner of this feature until step 12 flips
product docs.

**Story:** an operator running stock mempool/mempool Node+MariaDB+frontend
retires **bitcoind + mempool/electrs** (or Blockstream/electrs) and points
`CORE_RPC` + `ESPLORA` at **this** binary. nginx `/api/` is our Esplora;
`/api/v1/` stays their process.

## Goal

When this plan is **done**, product docs **drop** “not an explorer backend”
and **claim** drop-in replace of **Bitcoin Core + (mempool electrs or
Blockstream esplora electrs)**, except their optional `--address-search`
prefix index (we keep `GET /address-prefix` as **404**). Do **not** make
that claim until **step 12**.

Drop-in means their TypeScript `ElectrsApi` + `bitcoinCoreApi` need **no
patches**. It does **not** mean we ship MariaDB cubes, mining-pool
catalogue, lightning, FX, accelerator, or the SPA.

## Constraints

- No Class A / SH **on-disk** bump unless a step proves it; prefer RAM
  snapshots and HTTP batching.
- No store hot-path locks. Bulk mempool JSON rides a **published snapshot**,
  same rule as fee estimates ([`mempool-fee-estimation.md`](./mempool-fee-estimation.md)).
- Do not flatten io_uring machines ([`io-modality.md`](./io-modality.md)).
- Do not put mempool.space `/api/v1/` (cubes, RBF trees, 2h charts, pool
  hashrate, lightning) in this binary. That is their Node + MariaDB.
- Do not add ZMQ. Their backend polls (`POLL_RATE_MS`, default 2 s).
- Do not add `/address-prefix/:prefix` (404 stays).
- Do not add Liquid/assets routes (404 stays).
- Do not add `rpcuser` / `rpcpassword` flags (already refused). Cookie is
  the Core-client path.
- Esplora/Electrum still require `--sh-index`. Explorer operators leave
  `--max-sh-creates` at **0** (unlimited).
- Libre mempool policy stays. Their cubes are computed in **their** backend
  from our tx JSON; they will not match mempool.space.com’s Core-shaped pool.
- Wallet-scoped Esplora WS (`/v1/ws`) stays as today. The SPA’s live
  catalogue is `/api/v1/` on **their** port.

## Out of scope

| Item | Why |
|------|-----|
| Address-prefix index / `GET /address-prefix` | Optional electrs `--address-search`; SHA256 SH keys cannot range-scan; UI value is low |
| MariaDB mining/lightning/prices/accelerator | Their `/api/v1/` Node |
| `MEMPOOL.BACKEND=electrum` (Electrum TCP indexer mode) | Different client (`ElectrumApi`). This plan is `BACKEND=esplora` |
| Global `track-mempool*` / `want: mempool-blocks` on **our** WS | Their `/api/v1/` WS |
| Core-complete RPC, wallet RPC, prune, GUI, v1 P2P | Unchanged |
| Faithful `getnetworkhashps` / `estimatesmartfee` | Dummy / 10-minute product stay documented; mining pages that still call Core see dialect |
| Electrs RocksDB prefixes `t`/`O`/`X`/`M`/`a` | Reconstruct from Class A + SH; no second chainstore |
| `CORE_RPC.DEBUG_LOG_PATH` / second bitcoind | Leave unset; we do not emulate `debug.log` |
| `POST /addresses/txs/summary` multi-address | Not used by `ElectrsApi` |
| `GET /txs/outspends?txids=` (max 50 query-string) | `ElectrsApi.$getBatchedOutspends` **throws**; they use the POST `/internal/` twin |

## Target topology

```text
Browser ──nginx── /api/      → rbitcoin Esplora (TCP or unix)
              └── /api/v1/   → mempool backend :8999  (unchanged)
mempool backend
   CORE_RPC  → rbitcoin JSON-RPC (cookie/Basic, Core ports)
   ESPLORA   → rbitcoin Esplora  (REST_API_URL or UNIX_SOCKET_PATH)
   DATABASE  → MariaDB           (unchanged)
```

Their sample `mempool-config.json` has `MEMPOOL.BACKEND: "electrum"`.
Operators who want this drop-in set `"esplora"`. `bitcoinCoreApi` is
**always** constructed (`bitcoin-api-factory.ts`) even when Esplora is the
indexer: send/test/submit **throw** in `ElectrsApi` and go to Core RPC.
Stale-block 404 on `/block/…/txids` and `/internal/block/…/txs` also falls
back to Core `getblock`.

Blockstream/electrs (no `/internal/`) is a **subset** of mempool/electrs.
Finishing the mempool-fork routes also covers `BACKEND=esplora` against
stock Esplora `API.md`.

Pinned client (research 2026-09-18; re-read if their backend moves):

- [`mempool/backend/src/api/bitcoin/esplora-api.ts`](https://github.com/mempool/mempool/blob/master/backend/src/api/bitcoin/esplora-api.ts)
- [`mempool/backend/src/api/bitcoin/bitcoin-api.ts`](https://github.com/mempool/mempool/blob/master/backend/src/api/bitcoin/bitcoin-api.ts)
- [`mempool/backend/src/api/bitcoin/bitcoin-client.ts`](https://github.com/mempool/mempool/blob/master/backend/src/api/bitcoin/bitcoin-client.ts)
- [`mempool/electrs` `src/rest.rs`](https://github.com/mempool/electrs/blob/mempool/src/rest.rs) (`INTERNAL_PREFIX`, unix via `hyperlocal`)
- sample config: `ESPLORA.REQUEST_TIMEOUT` **10000** ms, `BATCH_QUERY_BASE_SIZE` **1000**, `CORE_RPC.COOKIE` + `COOKIE_PATH`

Unix HTTP: axios `socketPath` + dummy URL `http://api/…`. The listener
parses ordinary HTTP/1.1 on the socket (no special Host).

## Already shipped (do not rebuild)

**RPC** ([`rpc.md`](./rpc.md)): `getblockcount`, `getbestblockhash`,
`getblockhash`, `getblock` 0/1/2, `getblockheader`, `getrawtransaction`,
`getrawmempool` / verbose, `getmempoolentry`, `gettxout`,
`gettxspendingprevout`, `sendrawtransaction`, `testmempoolaccept`,
`submitpackage`, `getblocktemplate`, `getmininginfo`, `getblockchaininfo`,
`getmempoolinfo`. JSON-RPC **batches** already work. Held stale bodies
already emit `confirmations: -1` (their `stale` flag).

**Esplora:** tip height/hash, `/block-height/:h`, block JSON/raw/header/status
/txids/txid/i/txs[/:start], tx JSON/hex/raw/status/merkle-proof/outspend(s)
(with `vin` on spent), address + scripthash stats/utxo/txs/chain/mempool,
`/txs/summary` dialect, `/mempool` + `/txids` + `/recent`, fee estimates +
`/fees/recommended`, `POST /tx` and `POST /txs/package`. Tx JSON already has
prevouts, asm, script types, fee.

**Not drop-in today:** TCP RPC is **Bearer** `{datadir}/rpc.token` (their
client is cookie or `user:pass`); Esplora is TCP-only (they prefer a unix
socket); **no** `/internal/*` bulk routes; one process-wide HTTP `sh_join`
slot (**X-M3**).

## `ElectrsApi` coverage (what 0.8 must answer)

Methods that **throw** in `ElectrsApi` are Core-RPC’s job (already shipped,
except cookie). `$getAddressPrefix` stays unimplemented (404 / throw).
`$getBatchedOutspends` (non-internal) throws; they call the internal twin.

| Method | HTTP | Status |
|--------|------|--------|
| `$getRawMempool` | `GET /mempool/txids` | shipped |
| `$getRawTransaction` | `GET /tx/:id` | shipped |
| `$getTransactionHex` | `GET /tx/:id/hex` | shipped |
| `$getTransactionMerkleProof` | `GET /tx/:id/merkle-proof` | shipped |
| `$getBlockHeightTip` | `GET /blocks/tip/height` (JSON **number**) | shipped |
| `$getBlockHashTip` | `GET /blocks/tip/hash` | shipped |
| `$getTxIdsForBlock` | `GET /block/:h/txids`; 404 → Core stale fallback | shipped |
| `$getBlockHash` / `$getBlockHeader` / `$getBlock` / `$getRawBlock` | height / header / JSON / raw | shipped |
| `$getAddress` / `$getAddressUtxos` | `/address/…` | shipped |
| `$getOutspend` / `$getOutspends` | `/tx/…/outspend(s)` | shipped |
| `$getCoinbaseTx` | `/block/:h/txid/0` then `/tx/…` | shipped |
| `$getAddressTransactionSummary` | `/address/…/txs/summary` | shipped |
| `$getRawTransactions` | `POST /internal/txs` | **step 4** |
| `$getMempoolTransactions` | `POST /internal/mempool/txs` | **step 5** |
| `$getAllMempoolTransactions` | `GET /internal/mempool/txs[/:last]` | **step 6** |
| `$getTxsForBlock` | `GET /internal/block/:h/txs` | **step 8** |
| `$getBatchedOutspendsInternal` | `POST /internal/txs/outspends/by-txid` | **step 9** |
| `$getOutSpendsByOutpoint` | `POST /internal/txs/outspends/by-outpoint` | **step 9** |
| `$getAddressPrefix` | would be `/address-prefix/…` | **404** (permanent) |
| `$sendRawTransaction` / `$testMempoolAccept` / `$submitPackage` | throw → `bitcoinCoreApi` | RPC already |

`$getAddressTransactions` / `$getScriptHash*` throw in `ElectrsApi` and are
unused on this path (REST address/scripthash routes still exist for nginx
`/api/` browsers and wallets).

## Always-on Core RPC (`bitcoinCoreApi`)

Cookie/Basic (step 1) is the remaining glue. Methods their Core client
uses on the esplora path:

| RPC | Why |
|-----|-----|
| `sendrawtransaction` / `testmempoolaccept` / `submitpackage` | `ElectrsApi` throws |
| `getblock` verbosity 0/1/2 | stale-block fallback; raw; txid list |
| `getblockheader` (`verbose=false`) | header hex |
| `getblockcount` / `getbestblockhash` / `getblockhash` | tip / height |
| `getrawtransaction` verbose | Core-only paths / genesis coinbase special-case |
| `getrawmempool` / `getmempoolentry` | Core indexer mode; harmless if present |
| `gettxout` / `gettxspendingprevout` | Core outspend fallback |
| `getblocktemplate` / `getmininginfo` | optional; `RUST_GBT: true` computes templates in **their** Node from Esplora tx JSON |
| `getnetworkhashps` | dummy today (follow-up); mining pages that call it |

Operators set `CORE_RPC.COOKIE: true` and `COOKIE_PATH` to
`{datadir}/.cookie`. Do not invent `rpcuser`/`rpcpassword`.

## `/internal/` + glue (the fork delta)

Contracts match mempool/electrs `rest.rs` (not a paraphrase of the
TypeScript names only).

| Route | Caller | Contract |
|-------|--------|----------|
| `POST /internal/txs` | `$getRawTransactions` | JSON array of txid hex. **Any unparseable id → 400** text. Parse-ok missing ids **omitted** (output may be shorter). Empty `[]` → `[]`. |
| `POST /internal/mempool/txs` | `$getMempoolTransactions` | Same parse/400 rule; **mempool only** (confirmed/unknown omitted). |
| `GET /internal/mempool/txs` and `…/:lastSeenTxid` `?max_txs=` | `$getAllMempoolTransactions` | Paged live mempool as Esplora tx JSON. Default `max_txs=10000`. Cursor is **after** that txid in stable (txid-sort) order. Empty array ends. |
| `GET /internal/mempool/txs/all` | electrs extra (not `ElectrsApi`) | Full snapshot dump. Register **before** the `:lastSeenTxid` route so `all` is not a cursor. |
| `GET /internal/block/:hash/txs` | `$getTxsForBlock` | **All** txs (not 25-page `/block/.../txs`). Unknown hash **404**. Held/stale body: serve if we have it (`confirmations: -1` on RPC). |
| `POST /internal/txs/outspends/by-txid` | `$getBatchedOutspendsInternal` | Output **same length** as input. Unknown/unparseable tx → `[]` inner list (not omit). Spent objects match `GET /tx/:id/outspends` (include `vin`). |
| `POST /internal/txs/outspends/by-outpoint` | `$getOutSpendsByOutpoint` | `["txid:vout", …]` → `Outspend[]` same length. Malformed → `{"spent":false}`. |
| `GET /mempool/txids/page` and `…/page/:last` `?max_txs=` | large-pool sync | Txid-only pages; empty page ends. Existing `GET /mempool/txids` stays. |
| Esplora **unix socket** | `ESPLORA.UNIX_SOCKET_PATH` | Same router as TCP. |
| RPC **cookie + Basic** | `CORE_RPC.COOKIE` | `{datadir}/.cookie` `__cookie__:<hex>` (0600) + `Authorization: Basic`. Bearer `rpc.token` stays (same hex). |

Unknown `/internal/*` stays **404** (plain body), same as other non-goals.

Their client timeout is **10 s** (`ESPLORA.REQUEST_TIMEOUT`). Bulk handlers
must complete a default page / one full block under that, or the operator
raises the timeout. Snapshot **pre-serializes** JSON so a dump is a copy,
not `build_tx_json` under the request.

`ServeLimits.max_request_bytes` is 1 MiB: a 1000-txid POST (`BATCH_QUERY_BASE_SIZE`)
fits; do not silently 413 a legal electrs batch. Responses are **not**
1 MiB-capped (full-block JSON is multi‑MB).

## Acceptance (plan done)

1. A mempool/mempool checkout with `MEMPOOL.BACKEND=esplora` talks to this
   node for every method on `ElectrsApi` **except** `$getAddressPrefix` /
   `$sendRawTransaction` / `$testMempoolAccept` / `$submitPackage` (the last
   three **throw** in `ElectrsApi` and go to `bitcoinCoreApi`).
2. `bitcoinCoreApi` cookie HTTP Basic works against `--rpc-listen` without
   patching `bitcoin-client.ts`.
3. nginx can put `/api/` on our Esplora; `/address-prefix` is **404**.
4. Product docs (README, COMPAT, OPERATOR, SECURITY, architecture, crate
   rustdoc) **claim** Core+electrs drop-in and **do not** say “not a
   graphical explorer backend.” Address-prefix and Liquid stay explicit
   non-goals.
5. Default CI pins the new HTTP contracts on the existing
   `esplora_broadcast_visible_in_rpc_and_electrum` journey (extend, no twin).

## Test budget

Prefer unit tests in `rbitcoin-esplora` / `rbitcoin-rpc` next to the handler.
One catalog extension on `esplora_broadcast_visible_in_rpc_and_electrum` for
the unix/cookie + one bulk mempool + one full-block `/internal/block/.../txs`
path. No production-scale mempool fixture; synthetic N=2–8 txs. No agent-VM
mainnet. Core functional is not the Red test.

---

## Steps

### Step 1 — RPC cookie + HTTP Basic (Core client drop-in)

- **Contract:** `--rpc-listen` accepts Core-style `{datadir}/.cookie`
  (`__cookie__:<hex>`, 0600) and `Authorization: Basic` of that pair, and
  still accepts Bearer `rpc.token`. Token bytes match. Unix `rpc.sock`
  stays unauthenticated filesystem auth. 401 `WWW-Authenticate` lists
  **both** `Basic` and `Bearer`.
- **Red:** `cargo test -p rbitcoin-rpc --lib cookie` — write cookie, parse
  Basic, reject wrong user/pass; Bearer still works.
- **Green:** `crates/rbitcoin-rpc/src/auth.rs` + server header path. On
  `--rpc-listen`, write/sync `.cookie` beside `rpc.token` (same hex). Do not
  invent `rpcuser`/`rpcpassword` flags (already refused).
- **Refactor:** one `RpcAuth` matcher for Bearer and Basic; no duplicate
  token files with different secrets.
- **Verify:** `cargo test -p rbitcoin-rpc --lib auth`
- **Done when:** [ ] red [ ] green [ ] refactor [ ] `docs/rpc.md` Auth table
  lists cookie/Basic as TCP drop-in for Core clients

### Step 2 — Esplora unix-domain listen

- **Contract:** `--esplora-listen` / conf accepts a filesystem path
  (`/run/rbitcoin/esplora.sock` or `{datadir}/esplora.sock`). HTTP over that
  socket serves the same routes as TCP (dummy `Host: api` is fine). Mode
  0660/0666 is documented (nginx and their Node must connect). TCP form
  unchanged.
- **Red:** `cargo test -p rbitcoin-esplora --lib unix` — bind path, `GET
  /blocks/tip/height` via unix HTTP.
- **Green:** `EsploraConfig` listen enum (TCP \| unix). Node CLI parses
  path vs `host:port`.
- **Refactor:** one `run_esplora` bind helper; no second router.
- **Verify:** `cargo test -p rbitcoin-esplora --lib unix`
- **Done when:** [ ] red [ ] green [ ] refactor [ ] OPERATOR flag row

### Step 3 — Published mempool tx-JSON snapshot

- **Contract:** A hub-side snapshot (txid-sorted list + **pre-serialized**
  Esplora tx JSON, including prevouts) can be read **without** the admit
  write lock. Dirty on announce/remove/block; rebuild singleflight; readers
  see ≤ ~1 s staleness like fee estimates. Admit path does not
  `build_tx_json`. A 10 s client can copy a default page off the snapshot.
- **Red:** `cargo test -p rbitcoin-net --lib mempool_tx_snapshot` — two live
  txs, snapshot contains both fees/prevouts; accept while a reader holds the
  `Arc` does not deadlock.
- **Green:** next to fee snapshot on `MempoolHub`. Reuse `build_tx_json` /
  packed meta; do not clone the full graph into Esplora.
- **Refactor:** fee snapshot and tx snapshot share dirty/singleflight if
  that stays simpler than two flags.
- **Verify:** `cargo test -p rbitcoin-net --lib mempool_tx_snapshot`
- **Done when:** [ ] red [ ] green [ ] refactor [ ] no admit-path JSON build

### Step 4 — `POST /internal/txs`

- **Contract:** JSON array of txid hex → JSON array of Esplora tx objects
  (same shape as `GET /tx/:txid`). Unparseable id → **400**. Missing ids
  omitted. Empty array → `[]`. Oversize body hits `ServeLimits` (413).
- **Red:** `cargo test -p rbitcoin-esplora --lib internal_txs` — one
  confirmed + one mempool id; unknown id dropped; garbage id 400.
- **Green:** route on the existing Axum router; handlers call
  `build_tx_json` / mempool wire.
- **Refactor:** shared “txid → Option<Value>” helper for later bulk routes.
- **Verify:** `cargo test -p rbitcoin-esplora --lib internal_txs`
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 5 — `POST /internal/mempool/txs` (by id list)

- **Contract:** Same body/400 rule as step 4, but **only** live mempool
  txs. Confirmed or unknown ids omitted.
- **Red:** `cargo test -p rbitcoin-esplora --lib internal_mempool_txs_post`
- **Green:** filter through snapshot/live hub; do not reconstruct Class A.
- **Refactor:** share parser with step 4.
- **Verify:** that filter
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 6 — `GET /internal/mempool/txs` paged dump

- **Contract:** `GET /internal/mempool/txs` returns the first page of live
  mempool txs as Esplora JSON (default `max_txs=10000`, query override,
  cap at a named const). `GET /internal/mempool/txs/:lastSeenTxid` continues
  **after** that txid in **txid sort**. Empty array means done. Uses the
  step-3 snapshot. `GET /internal/mempool/txs/all` is registered first and
  returns the full snapshot array.
- **Red:** `cargo test -p rbitcoin-esplora --lib internal_mempool_txs_page`
  — three txs, `max_txs=2`, second page, third empty; `/all` length 3.
- **Green:** snapshot walk; no hub write lock.
- **Refactor:** same encoder as step 5.
- **Verify:** that filter
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 7 — `GET /mempool/txids/page/:last`

- **Contract:** txid-only pages, same cursor/`max_txs` rules as step 6.
  First page is `GET /mempool/txids/page` (no cursor). Existing
  `GET /mempool/txids` (full list) stays. Empty page ends.
- **Red:** `cargo test -p rbitcoin-esplora --lib mempool_txids_page`
- **Green:** snapshot txid list; cheap vs full JSON dump.
- **Refactor:** shared cursor helper with step 6.
- **Verify:** that filter
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 8 — `GET /internal/block/:hash/txs` (full block)

- **Contract:** all txs in the block as Esplora JSON (prevouts, fees),
  including coinbase `fee=0`. Unknown hash **404**. Stale/held block: serve
  if we have the body (`confirmations` false / not on tip), matching Core
  fallback in `$getTxsForBlock`. Public `/block/:hash/txs` stays 25/page.
- **Red:** `cargo test -p rbitcoin-esplora --lib internal_block_txs` —
  generate 3-tx block, internal list length 3; paged public route still 25
  semantics on a smaller block (full page).
- **Green:** reconstruct once, map `build_tx_json`; do not 25-loop internally.
- **Refactor:** share with public `/txs` page encoder.
- **Verify:** that filter
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 9 — bulk outspends

- **Contract:** `POST /internal/txs/outspends/by-txid` with a txid array
  returns `Outspend[][]` **same length as input** (unknown → `[]`). Objects
  match `GET /tx/:txid/outspends`, including `vin` when spent.
  `POST /internal/txs/outspends/by-outpoint` with `["txid:vout", …]`
  returns `Outspend[]` same length; malformed → `{"spent":false}`.
- **Red:** `cargo test -p rbitcoin-esplora --lib internal_outspends` — spend
  one output, bulk sees `spent` + `vin`; unknown tx keeps a slot.
- **Green:** existing outspend builder, batched.
- **Refactor:** no N HTTP internally.
- **Verify:** that filter
- **Done when:** [ ] red [ ] green [ ] refactor

### Step 10 — bounded HTTP SH join cache (revisit X-M3)

- **Contract:** concurrent Esplora requests for **two** different addresses
  both succeed without one clobbering the other’s join. Cache is **bounded**
  (named cap, e.g. 8 slots, evict arbitrary/oldest). Not an unbounded
  process LRU. Electrum TCP sticky join unchanged.
- **Red:** `cargo test -p rbitcoin-esplora --lib sh_join_slots` — two scripts,
  overlapping `/address/.../utxo` on one runtime.
- **Green:** `AppState.sh_join` becomes a small map; **X-M3** text in
  [`quality.md`](./quality.md) updates to “unbounded LRU still Won't-fix;
  bounded slots are 0.8.”
- **Refactor:** keep one join type; no Electrum path change.
- **Verify:** `cargo test -p rbitcoin-esplora --lib sh_join`
- **Done when:** [ ] red [ ] green [ ] refactor [ ] quality X-M3 sentence

### Step 11 — catalog journey pins + operator recipe

- **Contract:** `esplora_broadcast_visible_in_rpc_and_electrum` (or the same
  pad) hits cookie Basic `getblockcount`, unix or TCP `/internal/mempool/txs`,
  `/internal/block/:hash/txs` length, outspend bulk same-length slot, and
  `/address-prefix/bc1` **404**.
- **Red:** extend that test with those HTTP/RPC calls (fail until routes
  exist — if steps 1–9 already green, this step is the journey-only pin).
- **Green:** journey asserts only. Add `OPERATOR.md` recipe: example
  `mempool-config.json` with `MEMPOOL.BACKEND=esplora`, `CORE_RPC.COOKIE`
  + `COOKIE_PATH` `{datadir}/.cookie`, `ESPLORA.UNIX_SOCKET_PATH` or
  `REST_API_URL`, `--sh-index`, `--max-sh-creates` 0, `--rpc-listen`,
  `--esplora-listen`. nginx `/api/` → Esplora, `/api/v1/` → :8999.
- **Refactor:** none if helpers already exist.
- **Verify:** `cargo test -p rbitcoin-test esplora_broadcast`
- **Done when:** [ ] red [ ] green [ ] OPERATOR recipe [ ] TESTING.md catalog
  row updated

### Step 12 — product-doc flip (the claim)

- **Contract:** no remaining “not a graphical explorer backend / not
  mempool.space” as a **product non-goal**. Claim: drop-in for
  **Core + mempool/electrs or Blockstream electrs**, except optional
  address-prefix search. Liquid, MariaDB catalogue APIs, our WS firehose
  stay out. [`COMPAT.md`](../COMPAT.md) is the owner of the surface table.
- **Red:** none (docs). Agents must not ship this step before 1–11.
- **Green:** edit README, COMPAT, OPERATOR, SECURITY, architecture,
  `crates/rbitcoin-esplora/src/lib.rs` rustdoc, `crates/rbitcoin-electrum`
  rustdoc, quality Won't-fix line, this file **Status: shipped in 0.8**.
  CHANGELOG Unreleased **Changed** bullet. `/address-prefix` stays in the
  404 non-goal row. [`road-to-1.0.md`](./road-to-1.0.md) 0.8 checklist
  ticks the claim row.
- **Refactor:** one owner sentence per file; no second COMPAT copy here.
- **Verify:** grep the tree for `not a graphical` / `not a graphical
  block-explorer` / `Not a mempool.space` and only this plan’s history
  plus CHANGELOG may mention the old stance.
- **Done when:** [ ] grep clean except history [ ] COMPAT claim matches
  shipped routes [ ] `docs/README.md` still points here as owner

---

## Risks

| Risk | Mitigation |
|------|------------|
| Their `/internal/` path names move | Pin this doc’s table to `rest.rs`; step 11 404/200 against current `esplora-api.ts` |
| Bulk mempool dump CPU on a fat Libre pool | Step 3 pre-serialized snapshot; cap `max_txs`; operator `ServeLimits` / `ESPLORA.REQUEST_TIMEOUT` |
| 10 s client timeout vs full-block JSON | Step 8 reconstruct once; no 25-loop; operator can raise timeout |
| Fat confirmed addresses | Unlimited `--max-sh-creates`; step 10 concurrency; megakey join cost is already SH, not this plan |
| Cookie vs Bearer dual auth bugs | Step 1 tests; unix RPC stays no-header |
| Stale-block 404 vs Core fallback | Step 8 serve held bodies; unknown hashes 404 |
| `POST /internal/txs` 400-on-parse vs omit-missing | Tests pin electrs `rest.rs` (400 if any id fails to parse) |
| Claiming drop-in before routes exist | Step 12 last; 0.7 docs only **link** this plan |

## Follow-ups (not 0.8)

- Address-prefix index (Won't-fix unless a new product decision).
- Faithful `getnetworkhashps` (mining pages that still call Core).
- ZMQ `sequence` (poll is enough).
- In-binary `/api/v1/` cubes (their Node).
- Unbounded Esplora join LRU (**X-M3** remainder).
- `CORE_RPC.DEBUG_LOG_PATH` / `SECOND_CORE_RPC`.
- `MEMPOOL.BACKEND=electrum` (Electrum TCP) as a documented second recipe.
