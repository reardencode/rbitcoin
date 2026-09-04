# Bitcoin Core functional tests (rbitcoin)

Pin: **Bitcoin Core v31.1** (`9be056a8a72b624dae9623b2f7bded92c2a21c91`).

`scripts/core-functional/` holds the inventory, checkers, runner, and
the test-only bitcoind shim. Core’s Python tests and `src/test/data` live in the
**`third_party/bitcoin` submodule** (v31.1). We do **not** copy the 267
`*.py` files into this repo.

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
`--list` prints `run` names (first-green CLI/UA/echo plus MiniWallet
mempool and inbound block-sync scripts). `--dry-run` prints the command and writes `config.ini`
(wallet/zmq/ipc off) without starting a node. Default `cargo test`
never calls this.

`scripts/core-functional/bitcoind` is the TestNode binary: `-datadir=DIR`
→ `--datadir DIR/regtest` (cookie + `bitcoind.pid` under `DIR/regtest`),
`-rpcport`/`-port`/`bitcoin.conf` → `--rpc-listen` / `--listen` on
127.0.0.1, `--no-seeds`. Node stdio goes to `regtest/debug.log`; only
`Error:` lines (UA / init) are copied to the shim stderr so TestNode’s
clean-stop check matches Core. Unknown Core flags fail parse. Operator
CLI is unchanged.

```bash
./scripts/core-functional/bitcoind.test.sh
# live cookie + getblockcount==0 (needs a built node):
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

`run` means an **unmodified** Core script is green against rbitcoin. Flip
to `run` only in the PR that makes that script pass. First green pair:
`feature_help.py` (shim `-h`/`-version`/`-fakearg`) and
`feature_uacomment.py` (`getnetworkinfo.subversion` BIP14 parens).

## Skip reasons

| Code | Meaning |
|------|---------|
| `no-wallet` | wallet RPC / `wallet/` URL |
| `no-mining-product` | GBT / `prioritisetransaction` as Core mining |
| `no-prune` | prune / blk xor / `-blocksdir` |
| `no-utxo-set` | coins DB / assumeutxo / scantxoutset |
| `no-zmq` / `no-ipc` / `no-qt` | those interfaces |
| `no-core-rest` | Core REST (`interface_rest.py`); we have Esplora instead |
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
| `rpc_estimatefee.py` | `rpc-dialect` | `estimatesmartfee` is 10-minute inclusion, not Core multi-horizon |
| `rpc_gettxspendingprevout.py` | `rpc-dialect` | method shipped; field/error zoo |
| `rpc_help.py` | `rpc-dialect` | `help` shipped; Core categories / converthelp |
| `rpc_invalid_address_message.py` | `rpc-dialect` | `validateaddress` shipped; Core error text |
| `rpc_packages.py` | `rpc-dialect` | `submitpackage` shipped; script field zoo |
| `rpc_rawtransaction.py` | `rpc-dialect` | Class A always indexes; remaining type-check needles |
| `rpc_validateaddress.py` | `rpc-dialect` | method shipped; Core error text |
| `mempool_persist.py` | `rpc-dialect` | our `{datadir}/mempool/` analog; not Core `mempool.dat` |

`rpc_getblockfrompeer.py` stays `rpc-missing` (method not found).

## CI

[`.github/workflows/core-functional.yml`](../.github/workflows/core-functional.yml)
runs `scripts/core-functional/nightly.sh` on a nightly cron, on
`workflow_dispatch`, and on PRs labeled **`core-functional`**. Unlabeled
PRs keep the cargo gates only. Label the PR when touching the harness
(see `AGENTS.md`).

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
Add a `[[rule]]` (`match` regex → `emit` lines with `{1}` captures) and
flip the inventory row to `run` when every `assert_debug_log` string the
test can hit is mapped or emitted natively. Unmapped stays `core-log`.

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
| `feature_reindex*.py` | `analog_reconstruct_after_lost_head` |
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
