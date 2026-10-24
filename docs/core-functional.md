# Bitcoin Core functional tests (rbitcoin)

Pin: **Bitcoin Core v31.1** (`9be056a8a72b624dae9623b2f7bded92c2a21c91`).

`scripts/core-functional/` holds the inventory, checkers, runner, and
the test-only bitcoind shim. Core’s Python tests and `src/test/data` live in the
**`third_party/bitcoin` submodule** (v31.1). We do **not** copy the 267
`*.py` files into this repo. Official `bitcoind` binaries for differential
fuzz are **not** built from the submodule (sparse `src/test/data` + `test`
only); `fetch-bitcoind.sh` downloads the `[release]` tarball into
`~/.cache/rbitcoin/core-bitcoind`.

Default `cargo test` never runs those Python tests. Consensus JSON corpora
are staged from the submodule each run (the helper runs `init-submodule.sh`
if the pin is missing; see
`crates/rbitcoin-consensus/tests/fixtures/README.md`).

```bash
./scripts/core-functional/init-submodule.sh
./scripts/core-functional/sync-core-fixtures.sh --check
python3 scripts/core-functional/check_inventory.py \
  --tests-dir third_party/bitcoin/test/functional
./scripts/core-functional/run.sh --list
```

## Runner

`scripts/core-functional/run.sh` is the only way we invoke Core’s
`test_runner.py`. It runs the inventory checker, then only inventory
`run` names, with `--v2transport`. A `skip` or unknown name fails with
`not in run set` / `unknown test` (we do not `--exclude` every skip —
Core exits if an exclude is not in the current test list).
`--list` prints `run` names (production P2P / mempool / buried-activation /
shipped RPC). `--dry-run` prints the command and writes `config.ini`
(wallet/zmq/ipc off) without starting a node. Default `cargo test`
never calls this.

`scripts/core-functional/bitcoind` is the TestNode binary: `-datadir=DIR`
→ `--datadir DIR/regtest` (`bitcoind.pid` under `DIR/regtest`),
`-rpcport`/`-port`/`bitcoin.conf` → `--rpc-listen` / `--listen` on
127.0.0.1, `--no-seeds`. It adds `--sh-index` only when the datadir parent
is `{script}_{n}` for a run test that reads address or scripthash history
(MiniWallet `scantxoutset`, or the wallet shim's send and balance calls).
Other nodes, including `p2p_compactblocks_hb.py`, start without that index,
so a fresh regtest does not pack an empty scripthash index before it can
relay. Esplora still listens; address routes fail closed until the flag is
on. The node writes `{datadir}/rpc.token` (Bearer);
the shim mirrors `__cookie__:<token>` to `{datadir}/.cookie` so Core
TestNode cookie + HTTP Basic still work on the **proxy** public port. The
proxy forwards `Authorization: Bearer` to the node (TCP is Bearer, plus
Basic only with `--rpc-cookie-file`).
Node stdio goes to `regtest/debug.log`; only
`Error:` lines (UA / init) are copied to the shim stderr so TestNode’s
clean-stop check matches Core. Unknown Core flags fail parse. The shim maps
Core names onto kebab `rbitcoin-node` flags (`-maxconnections` → `--max-inbound`
as `N−11`, `-whitelist` → `--net-permission`, `-whitebind` → `--net-permission-bind`,
`-whitelistrelay` → `--net-permission-relay`, `-checkblocks` → `--check-blocks`,
`-blocksonly` → `--blocks-only`,
`-minimumchainwork` → `--min-chain-work`, …). The operator CLI does not accept
those Core aliases. The shim sets `RBITCOIN_RPC_WAIT_TIP_IDLE=1` on the child so
`getblockcount` waits until the tip-accept lane is empty (`sync_blocks`).
Production (unset) waits only for the accept that was running when the RPC
arrived. The same child env sets `RBITCOIN_RPC_PACKAGE_DIALECT=1` so
`submitpackage` matches Core `IsChildWithParents` (`-25`). A member above
`maxfeerate` is rejected either way and does not rescue the package.
Production (unset) still package-evaluates a child-with-parents remainder
that failed min relay, the dynamic mempool floor, or missing inputs. The RPC
proxy rewrites multi-tx `testmempoolaccept` abort-class rows
(`missing-inputs` / `max-fee-exceeded` / `bip125-replacement-disallowed`) to
`{txid,wtxid}`; the node keeps earlier `allowed: true`.
`getmempoolinfo.maxmempool` is already the virtual-size byte cap. The shim's
4× `-maxmempool` map makes that number match Core. A `generateblock` spend of
an unspendable output still fails the script on the node; the proxy rewrites
that error to Core's `CheckTxInputs` missing-input sentence
(`feature_block.py`). The proxy answers MiniWallet `scantxoutset`
`raw(HEX)` from Esplora `/scripthash/:hash/utxo` (confirmed rows,
coinbase from `/tx/:txid`, genesis coinbase omitted). It does not expand
descriptors. `rpc_scantxoutset.py` and `rpc_signrawtransactionwithkey.py`
are inventory skips. The node implements neither `scantxoutset` nor
`gettxoutsetinfo`. `rpc_packages.py` `run` includes the package-dialect
shim (same honesty as `WAIT_TIP_IDLE`).

```bash
./scripts/core-functional/bitcoind.test.sh
# live cookie (mirrored from rpc.token) + getblockcount==0 (needs a built node):
cargo build -p rbitcoin-node
RBITCOIN_NODE=target/dev/debug/rbitcoin-node \
  python3 scripts/core-functional/smoke_rpc_up.py
```

```bash
./scripts/core-functional/run.sh --list
./scripts/core-functional/run.sh --dry-run
./scripts/core-functional/run.sh.test.sh
./scripts/core-functional/create_cache.test.sh
```

## Check the inventory

```bash
python3 scripts/core-functional/check_inventory.py
./scripts/core-functional/check_inventory_test.sh
```

`--tests-dir PATH` compares against a Core checkout’s `test/functional`.
Without it, the checker uses `scripts/core-functional/v31.1-tests.txt`
(the v31.1 filename list).

## Inventory schema

`scripts/core-functional/inventory.toml`:

Top-level `pin` / `core_commit` identify the Core tree. Optional `[release]`
pins official `bitcoind` tarball SHA256s for differential fuzz
(`scripts/core-functional/release_pin.py`, `fetch-bitcoind.sh`). The
inventory checker only reads `[[test]]` rows and ignores `[release]`.

| Field | Rule |
|-------|------|
| `name` | `*.py` basename, unique |
| `status` | `run` or `skip` |
| `reason` | required on `skip`; **forbidden** on `run`; never `unknown` |
| `analog` | required when `reason` is `no-prune`, `core-internal`, `no-utxo-set`, or `rpc-missing` (`none` if we will not re-home; otherwise a scenario name or follow-up) |
| `log_map` | optional; later `debuglog_map.toml` keys |

A file on disk (or in `v31.1-tests.txt`) that is missing from the inventory,
or an inventory row with no file, **fails the checker**.

`run` means an **unmodified** Core script is green against rbitcoin **and**
exercises node/P2P/RPC production (confirm, mempool, archive reconstruct,
listen, or a shipped RPC). Flip to `run` only in the PR that makes that
script pass. Wallet / `createrawtransaction` / `signrawtransactionwithkey` /
`createmultisig` on the proxy are MiniWallet-class **tooling**: allowed when
the asserts then hit `sendrawtransaction` / `generate*` / P2P. Do **not**
`run` a script whose asserts are only shim argv, dummy `blk*.dat`, fabricated
`Bound to` lines, vendored `rpcauth.py`, or Core decode/`validateaddress`
dialect the node does not ship. Named Core-functional shim dialect is allowed
when documented: child env (`RBITCOIN_RPC_WAIT_TIP_IDLE`,
`RBITCOIN_RPC_PACKAGE_DIALECT`) and proxy JSON (`maxfeerate` BTC/kvB,
abort-class `testmempoolaccept` blanking). Do not `run` a silent Core-clone
of production RPC.

First production-green pair (historical): `feature_uacomment.py`
(`getnetworkinfo.subversion` BIP14 parens) and `rpc_uptime.py` (`uptime` /
`setmocktime`).

## Skip reasons

| Code | Meaning |
|------|---------|
| `no-wallet` | wallet RPC / `wallet/` URL |
| `no-mining-product` | GBT / `prioritisetransaction` as Core mining |
| `no-prune` | prune / blk xor / `-blocksdir` |
| `no-utxo-set` | coins DB / assumeutxo |
| `no-zmq` / `no-ipc` / `no-qt` | those interfaces |
| `no-core-rest` | Unmodified `interface_rest.py` (`-rest` on the RPC port, MiniWallet, binary `getutxos`, `-blockfilterindex`). Node `/rest/` is a subset (`methods/rest.rs`, `--rest`), not Esplora, and this script stays `skip` until it is green |
| `no-tool` | bitcoin-wallet / bitcoin-tx / bitcoin-util / bitcoin-chainstate |
| `v1-only` | requires v1 or v2→v1 downgrade |
| `core-log` | `assert_debug_log` string not yet in the debug.log map |
| `core-internal` | LevelDB / LoadExternalBlockFile / USDT / rw_settings |
| `core-net-policy` | banlist format, tor, anchors.dat, asmap |
| `policy-libre` | assertion *is* Core standardness |
| `rpc-missing` | method/harness not implemented yet (shrinks; requires `analog` follow-up) |
| `rpc-dialect` | Method is **shipped** (COMPAT done) but the unmodified Core script still fails on type-check / field / error-text zoo (requires `analog`) |
| `core-cpp-unit` | Boost units — never in this runner |
| `prev-release` | previous-release binaries |
| `harness` | `test_runner.py`, `combine_logs.py`, framework self-tests |
| `unknown` | **illegal** |

## COMPAT-done vs inventory

`rpc-missing` is only for methods we do **not** claim. Surfaces COMPAT already
lists as done, but whose official script still fails on dialect, stay
`rpc-dialect` (not a silent “follow-up we claim”). Product-never stays
`no-wallet` / `no-prune` / `v1-only` / …

| Script | Skip | Why not `run` yet |
|--------|------|-------------------|
| `mempool_accept.py` | `rpc-dialect` | `testmempoolaccept` type-check (`-32602` vs Core `-3`) |
| `mining_basic.py` | `rpc-dialect` | GBT selector shipped; `-blockmaxweight` leftover |
| `rpc_blockchain.py` | `rpc-dialect` | `time`/`mediantime` shipped; prune / muhash later |
| `rpc_gettxspendingprevout.py` | `rpc-dialect` | method shipped; field/error zoo |
| `rpc_help.py` | `rpc-dialect` | `help` shipped; Core categories / converthelp |
| `rpc_rawtransaction.py` | `rpc-dialect` | Class A always indexes; remaining type-check needles |
| `rpc_decodescript.py` | `rpc-dialect` | node decode subset; no p2sh/segwit wrap, `desc`, Core asm |
| `rpc_validateaddress.py` | `rpc-dialect` | node happy-path subset (`isvalid` only) |
| `rpc_invalid_address_message.py` | `rpc-dialect` | same; no `error` / `error_locations` |
| `mempool_persist.py` | `rpc-dialect` | our `{datadir}/mempool/` analog; not Core `mempool.dat` |

`rpc_getblockfrompeer.py` stays `rpc-missing` (method not found).

Shim-only scripts that used to be `run` stay skip: `feature_help.py`
(`harness`), `tool_rpcauth.py` (`no-tool`), `feature_blocksdir.py`
(`no-prune`), `feature_dirsymlinks.py` stays skip (`core-internal`). Dummy `blk00000.dat`
still exists so `rpc_getblockstats.py`'s rename-file needle can run; the rest
of that script is `submitblock` + archive `getblockstats`. `feature_port.py`
is `run`: `-bind`/`-port` become `--listen` on those sockets.
`p2p_eviction.py` is skip (`core-net-policy`): the 21-peer set in that script is fully protected, including a share of the longest-connected peers, so the extra inbound is rejected. Core accepts it and evicts one slow peer.
`feature_filelock.py` is skip (`harness`): the node exclusive-locks `{datadir}`
(unit + shim InitError tests). Core `-wallet` SQLite flock and `-blocksdir`
`blocks/.lock` are not product. `rpc_orphans.py` is `run`: hidden
`getorphantxs` plus orphan announcers / `EraseForPeer`. `p2p_permissions.py`
is `run`: Core `NetPermissions` on `-whitelist`/`-whitebind`, per-peer
`getpeerinfo.permissions`, 0-value spendable `dust`, and forcerelay
recent-rejects.

## CI

[`.github/workflows/core-functional.yml`](../.github/workflows/core-functional.yml)
runs `scripts/core-functional/nightly.sh` on a nightly cron, on
`workflow_dispatch`, and on PRs labeled **`core-functional`**.
[`release-gate.yml`](../.github/workflows/release-gate.yml) also calls it on
**ship versions** and PRs labeled **`release`**. Unlabeled non-ship PRs keep the cargo
gates only. Do **not** make this job required on all PRs, or on PRs that
merely touch net or RPC (too slow). Default `cargo test` is the PR pin
([`TESTING.md`](../TESTING.md)). Label harness PRs and every version-bump
ship PR (see [`releases.md`](./releases.md)). The `release-extra` job in
`release-gate.yml` fails when a ship PR did not get a green
`core-functional`, `overlay-functional`, and `warnet-example`.
The `core-functional` job is **30 minutes** (80 `test_runner` jobs: 74
inventory `run`; Core expands transport twins and `wallet_txn_*` flags).

When that job is red, the inner loop is **local**, not another CI wait.
Build `rbitcoin-node`, run only the failing inventory names, and rebuild
after each product change until those scripts pass (leftover `test_runner_*`
dirs keep `regtest/debug.log`):

```bash
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"
cargo build -p rbitcoin-node
RBITCOIN_NODE="$CARGO_TARGET_DIR/debug/rbitcoin-node" \
  ./scripts/core-functional/run.sh feature_bip68_sequence.py
```

Do not push a compact/P2P guess and poll GitHub Actions to learn whether it
worked. In-tree Red stays a catalog journey or unit; this script is the
labeled-job oracle for the same contract.

The job sparse-inits the pin, checks the inventory, **warns** (does not
fail) if a newer Bitcoin Core *release* exists than `inventory.toml`
`pin`, then runs the inventory `run` set when a node binary can be
built (otherwise `--list` only). The warning compares **semver of
final releases**, not GitHub’s `/releases/latest` — Core still ships
older maintenance tags after a newer major. Bump `third_party/bitcoin`,
the JSON corpora, and the inventory when it fires.

```bash
python3 scripts/core-functional/check_core_release.py --latest v31.1
./scripts/core-functional/check_core_release.test.sh
# live list (network):
python3 scripts/core-functional/check_core_release.py
```

## Debug.log map

`debuglog_map.toml` + `map_debuglog.py`: the shim tails node stdio into
`regtest/debug.log` and appends mapped Core substrings (line-buffered).
**Operator stderr is rbitcoin dialect** (`tip: best=`, `p2p: headers sync`,
`p2p: getdata wtx`, store-tip-in-the-future abort). Do **not** emit Core
C++ function names (`UpdateTip`, `AcceptBlockHeader`, …) from the node;
add a `[[rule]]` (`match` regex → `emit` lines with `{1}` captures) so the
harness can still grep those needles. Flip the inventory row to `run` when
every `assert_debug_log` / InitError string the test can hit is mapped.
Unmapped stays `core-log`. There is no `--log-dialect` flag.

Startup refuse when the store tip is more than two hours ahead of the clock
is store language on stderr; the shim maps it to Core’s
`appears to be from the future` InitError paragraph (`rpc_blockchain`).

```bash
./scripts/core-functional/map_debuglog_test.sh
```

## Analog column

LevelDB / `blocks/blk*.dat` tests cannot pass unmodified. `analog` names
the rbitcoin scenario (or `none`) so we do not drop the behavior. See the
design plan for the first-pass mapping (`--datadir-cold`, reconstruct,
`--milestone`, durable mempool).

Named scenarios in `crates/rbitcoin-test/tests/core_analogs.rs`:

| Core skip | Analog |
|-----------|--------|
| `feature_assumevalid.py` | `analog_milestone_and_mempool_persist` (skip-below / check-above + missing prevout under high milestone) |
| `feature_reindex*.py` | `analog_reconstruct_after_lost_head` (wipe `tx.head/`, reopen) |
| `mempool_persist.py` | `analog_milestone_and_mempool_persist` (same pad) |

`rpc-missing` also requires `analog` (a follow-up row or `none`).

## 199-block cache

Tests with `setup_clean_chain=False` (including `rpc_named_arguments.py`)
assert height 199 then generate one more. Core’s cache is LevelDB + `blocks/`
and would wipe our store after remine.

`scripts/core-functional/create_cache.py` mines 199 via `generatetoaddress`
(Core `_initialize_chain` payees: PRIV_KEYS[0:3] + MiniWallet P2TR) into
`scripts/core-functional/cache/store` (gitignored). `run.sh` preseeds empty
`test/cache/node0/regtest/{blocks,chainstate}` and passes `--keepcache`. The
shim copies `RBITCOIN_CACHE/store` only when the dest has those two dirs and
no `store/` (clean-chain starts stay empty).

```bash
python3 scripts/core-functional/create_cache.py --ensure
./scripts/core-functional/create_cache.test.sh
```

## Warnet lab (all-rbitcoin tanks)

Not an operator musl Release. The compose example keeps image tag
`rbitcoin-warnet:local`. Kind and Helm use `rbitcoin-warnet:28.0.0`.
That tag is the chart's Core-version gate, not the rbitcoin version.
Warnet passes it to `semverCompare ">=0.17.0"` and, when the compare
succeeds, writes `[regtest]` before `rpcport`, `rpcpassword`, `rpcauth`,
and `addnode`. A prerelease does not count: Warnet main strips `-…` and
then compares, and `0.7.99` is below `0.17.0`, so the section is omitted
while `helm template` still exits 0. `local` is not a semantic version
(Warnet 1.1.20 compares the raw tag; current Warnet main normalizes a few
Core shapes and still rejects that fallback). A release tag `>= 0.17.0`
with no prerelease, such as `28.0.0`, emits the section on both.
Warnet stays Core Helm (`bitcoin.conf`, `rpcuser`/`rpcpassword`,
`addnode=tank-N`, `pidof bitcoind`). The node is not taught Core conf; the
Python shim translates `addnode=` to `--connect host:18444`, seeds
`{datadir}/rpc.token` from `rpcpassword`, and binds the test proxy on
`rpcbind=0.0.0.0`. Basic auth accepts the cookie, any username whose
password matches that token, and Core `rpcauth=` (HMAC-SHA256, salt as
the key). `rpcwhitelistdefault=0` limits only users named in
`rpcwhitelist=`, so fork-observer's published login can call
`getchaintips`, `getblockheader`, `getblockhash`, `getblock`, and
`getnetworkinfo`, and the tank `rpcuser` is not locked out. The image
sets `RBITCOIN_LOG_STDOUT=1` (node lines on container stdout and in
`debug.log`) and `RBITCOIN_LAB_HEAD_SCALE=tiny` when conf omits
`head_scale`. Conf `head_scale=mainnet` still selects mainnet heads.

Hostname `--connect` / `addnode add` resolve at each dial on a blocking
thread and retry every 2 seconds until a live session exists. `--connect`
does not turn DNS seeds back on. If the first catch-up accepts nothing and
the tip is still 0, the tank enters tip-follow (16 blocks in flight, no
return to the IBD window) so it can attach when the other tank appears.
That is the right shape for this one-block example, not for a genesis
mainnet sync. A non-zero tip that has not finished catch-up stays in IBD.
Relay stays off while tip work is below `--min-chain-work`. The operator
note is in [`OPERATOR.md`](../OPERATOR.md).

### CI example (label `warnet`)

Two tanks on one Docker network, not kind or Helm. Unlabeled non-ship PRs
do not run it. `workflow_dispatch`, label `release`, and ship versions also
run it; `release-extra` requires it on ship PRs.

```bash
cargo build -p rbitcoin-node
./scripts/core-functional/init-submodule.sh
./scripts/core-functional/warnet/example.sh
```

The example conf sets `head_scale=tiny`. The lab image does the same when
conf omits it, so a Helm tank does not fallocate mainnet heads. `example.sh`
copies a **bookworm-linked** `rbitcoin-node` into the image
(a nix devshell binary will not exec: its dynamic loader is not in Debian).
It starts `tank1` first (`addnode=tank0`), waits until that RPC is up at
height 0 with no peer, then starts `tank0`, mines one regtest block, and
waits until `tank1` matches that height with a live peer whose
`getpeerinfo` addr is the resolved address. CI builds the binary with
`rust:1.95.0-bookworm`.

`Dockerfile.test.sh` pins the image text and does not need Docker.

### Operator kind / miner_std

Needs Docker + kind on an operator host. Do not open mainnet. Wallet keys
are RAM-only.

```bash
docker build -t rbitcoin-warnet:28.0.0 \
  --build-arg NODE_BIN=target/dev/debug/rbitcoin-node \
  -f scripts/core-functional/warnet/Dockerfile .
kind load docker-image rbitcoin-warnet:28.0.0
python3 -m venv .venv && source .venv/bin/activate
pip install warnet
warnet setup
warnet new /tmp/rbtc-warnet
```

Three tanks, ring `addnode`, unique `rpcpassword`. Set
`image.repository` to `rbitcoin-warnet`, `image.tag` to `28.0.0`,
and `pullPolicy: Never`.
Pass when `miner_std.py --interval=10 --mature` leaves all three
`getblockcount` values equal and greater than 0. Fail classes: CrashLoop
`pidof`; 401 on RPC; height only on the miner (DNS or bind); ImagePullBackOff
without `kind load`.
