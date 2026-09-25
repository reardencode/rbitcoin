# Testing guide

## Preference order (dev-cycle aware)

| Prefer | Avoid |
|--------|--------|
| **Journey scenarios**: one setup a peer, client, or operator could use, then a **sequence** of asserts on what they would observe | Many skinny scenarios that each remine maturity and re-open the store |
| The socket, RPC, HTTP route, operator config, or scripted peer | An in-process helper the product never calls, or a thread-local the client does not share |
| **Pure units** on pure helpers (scriptnum, bits, fuse8, open-hash) with **no store**, when a real session cannot reach them | Units that re-implement confirm and only paint lines a journey already hits |
| **One entry** per production path (the journey owns the asserts) | A `#[test]` that only calls other tests, or those tests kept as private bodies |
| Core JSON corpora for **script engine** breadth | A second parallel script suite |

**Fewer scenario functions / store opens, not less coverage** — put more asserts on one story.

### True journeys

A journey is one setup and one story. A peer, a client, or an operator does a sequence of things to that same node. Each beat asserts what they would observe: a response, a push, a reject, bytes on disk, a tip after reopen. The story should read like this node meeting the real network or a real client, and it should run as much of that path as the arc needs. One chain, one server, one session, the beats in order.

A `#[test]` whose body only calls other tests is not a journey. Each callee still opens its own store, hub, or socket. The suite gains one name and the same N boots. Delete the callees. The journey writes the asserts. Do not keep the old functions as private bodies the new test calls.

Small tests are the exception. Use one when a real session cannot reach the behavior without a setup no peer, client, or operator has: pure arithmetic, a codec with no socket, two networks that cannot be the same chain. Say why next to the test. A tall chain the rest of the story never builds is a named second chapter on a second setup. Two setups only when the objects cannot be the same.

Push the entry up. Prefer the surface a real session uses over an in-process dispatch the product never calls. In-process is for a fact that surface cannot show. Do not assert a thread-local, a counter on a worker the client does not share, or a helper's name. If the only proof lives there, it is not the contract yet.

A small unit is faster to land. It also freezes behavior a real node never exhibits, and later work has to preserve that accident. Assert what changes the result for a real user, peer, or operator. That includes rare real cases: a lagged subscriber, a pruned witness, a cap that returns an RPC error while ping still works. It does not include an internal shape no session can hit.

### Default CI is the pin

Default `cargo test` owns operator- and peer-visible contracts (JSON-RPC,
Electrum TCP, Esplora HTTP, BIP324 P2P). Bitcoin Core’s Python functional
suite is a **nightly / ship / `core-functional` label** oracle. It is **not**
a required PR check and **not** required on PRs that merely touch net or RPC
(too slow). Nightly Core is not a license to delete in-tree tests.
Unlabeled PRs stay cargo-only for overlays too: live Tor / i2pd / cjdns
meshes are the **`overlay-functional`** labeled / nightly / ship job
([`docs/overlay-functional.md`](docs/overlay-functional.md)), not default
`cargo test`.

When adding or folding a pin:

| Do | Do not |
|----|--------|
| Extend an existing [catalog](#scenario-catalog) journey (same `/tmp` pad, more asserts) | A new skinny scenario that remine-pads the same chain |
| Fold a twin unit once the journey hits the same shipped path | Twin unit + scenario for the same reject string |
| Keep a unit only while no real session can reach that path, then move the assert onto the journey | A new small test for a path a peer, client, or operator can already hit. Handshake **format** needles, `decode_rpc_subset`, and BIP324 encode vectors stay until a journey hits them |
| Live P2P/RPC on `cross_surface` / `integration_multinode` catalog tests | Grow `node_cli_and_surface_smoke` into a second live node |
| New P2P behavior on `p2p_timeout_*` / compact / feeler / inbound-full | Stuff more asserts onto `two_node` |

Coverage (LCOV `LH`/`LF` never below last green `master`) is a required PR
job. If deleting a guts test drops the ratio, the journey did not cover the
path — keep the guts or hit those lines from the journey first.

Keep until a **default** journey hits the same lines: store packed / v17 /
fuse / SH machines, unsorted pack/lag,
IBD wave fence / 8×8000, SH writebehind / uring CAS,
handshake format needles, `getaddr_cache_*`, sole-preferred stall KEEP, `stamp_reject_names_*`,
`multi_hop_bad_prev_*`, structure s1–s18, rate-limiter, netgroup, subsidy
table. Optional leftovers (more HTTP methods on `cross_surface`, a tiny
legacy-head `Store::open` fixture, testnet 20-minute min-diff header walk)
are not a backlog.

### Parallel cargo test (same binary)

`cargo test` / `cargo llvm-cov test` run **one process per test binary**.
Tests assert shipped behavior via session or table instance stats or on-disk
file state, not thread-local hot-path IO probes. Do not:

- Put HOLD / wait hooks in a shipped function other tests also call (`confirm_scripts_phase`).
- Assert process-global last-writer meters as the contract. Confirm / query / IBD window meters are instance-owned (`Query::confirm_stats`, take-and-reset). Pin two engines, not crate-root atomics. Store head-resolve window meters and `last_union_miss` / leftover probe diag remain process-global; use pin/layout, error strings, or a pure formatter.
- Thread-local `test_take_*` IO probes on store hot paths (example of the rule above; assert session/table instance stats or file state). Class A three-stem append is `UringSession` max-batch pwrite SQEs (`tls_take_max_batch_pwrite_n` after `with_thread_local`), not `test_take_pwrite_waves`.
- `std::env::set_var` without the crate lock (or pass the knob as an argument).
- Bind a fixed port (use `:0`) or share a `/tmp` path (use `rbitcoin_store::testutil::TempDir` / `tiny_store`, `rbitcoin_query::testutil::tiny_query`, net `tiny_regtest_hub`, or `rbitcoin_test::TestDatadir`).

Do **not** “fix” flakes with `RUST_TEST_THREADS=1`.

Shared Tiny on-disk fixtures live in `rbitcoin_store::testutil` (`TempDir`, `tiny_store`) and `rbitcoin_query::testutil::tiny_query` — unique path, Tiny heads, drop-cleans. Net tests that need a regtest `ChainHub` use `tiny_regtest_hub` / `tiny_regtest_hub_labeled` (Tiny query + shipped `ChainHub::new`), including IBD confirm-reject / path / progress / archive / dial / confirm tests. Do **not** roll your own `std::env::temp_dir()` + `create_dir_all` for a Tiny store/query. Node-level scenarios still use `rbitcoin-test` (`TestDatadir`, `mine`, `chain_fixture`). Class A TxApply fixtures call `rbitcoin_query::testutil::FixtureChain` (`connect_block` / `commit_class_a_only`), which converts once then uses shipped `archive_class_a_from_wire`. Do not put dummy-Block conversion on production `Query`.

### Third-party deps and compile cost (2026-08)

| Change | Why it helps the cycle |
|--------|------------------------|
| **mimalloc** only on product bins (`rbitcoin-node`, `rbitcoin-cli`) | Store **lib** tests no longer compile `libmimalloc-sys`/`cc`. Production still uses mimalloc on node/cli. |
| **rayon removed** from consensus | Parallel scripts use in-crate `script_pool` (`rbtc-scripts` steal). Drops rayon + crossbeam from the consensus graph. |
| **xorf + bincode + serde** removed from store | Sealed fuse8 is in-tree (`binary_fuse8` + hand LE layout **v2**). Drops a serde-heavy path from store rebuilds. |
| **fuse8 v1 on open** | Leftover v1 fuse **refuses**; wipe `store/tx.head` (Class A kept). Current writes are v2. |

`cargo check -p rbitcoin-store --tests` (and stacking `--tests` on query /
consensus / net) is a **fat** rustc unit — not the inner loop.
[`docs/how-we-plan.md`](docs/how-we-plan.md) (Keep the tree compiling).

Host forensics and `cargo bench` one-offs are **not** in the default compile
graph (`scripts/check_default_targets.test.sh`). Optional **client** comparison
is `rbitcoin-bench` (`cargo run -p rbitcoin-bench --features cli --release`);
not a musl product bin. Suites and packed `--corpus` lists:
[`OPERATOR.md`](./OPERATOR.md) (Client benchmark). IBD progress/rejects belong in node logs (`ibd: confirm reject`,
`ibd: archive reject`); host A/B is musl + `ibd: perf`.

## Running tests

Install rustc **1.95** and a first build: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
(Getting started). **Nix is not required.**

```bash
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/dev}"   # see Artifact silos
cargo test --workspace
./scripts/coverage.sh   # uses target/cov — does not thrash target/dev
```

Windows/macOS PR surface is `./scripts/ci-os-smoke.sh` (store IO/RAM/mmap
fuse, a few-block query confirm, `--smoke`), not this full suite —
see CONTRIBUTING (What works on each OS). No `libbitcoinconsensus` in the graph:
`cargo tree -i bitcoinconsensus` must fail to resolve.

### Artifact silos (do not mix)

Host **gnu** objects are not interchangeable with **musl** release or with
**llvm-cov**-instrumented objects (different triple / profile / RUSTFLAGS).

| Silo | Where | Used by |
|------|--------|---------|
| **Dev** | `target/dev` (`CARGO_TARGET_DIR`; `nix-shell` / `nix develop` set `$PWD/target/dev` when unset — rustup users should export it) | fmt, clippy, `cargo test`, ad-hoc `cargo build` |
| **Coverage** | `target/cov` (forced in `scripts/coverage.sh`) | `./scripts/coverage.sh` only |
| **Musl release** | Nix store via crane (`cargoArtifacts` + app) | `nix build .#rbitcoin-musl` — **not** `./target` |

Override dev dir only when intentional: `CARGO_TARGET_DIR=…` (Nix shell
reads it; rustup users export it). Override coverage dir:
`CARGO_TARGET_DIR_COV=… ./scripts/coverage.sh`.

Cargo incremental stays on in `target/dev`. Stale objects: `cargo clean -p
<crate>` or wipe the silo.

Humans and CI keep `$PWD/target/dev` (this table, CONTRIBUTING, `shell.nix` /
`flake.nix`). Constrained VMs may export a shared silo *before* `nix-shell`
(the hook only sets `$PWD/target/dev` when unset). `rearden-grok[bot]` on
the operator VM: [`rearden-vm-HOST.md`](rearden-vm-HOST.md). Other agents:
ignore that file.

**Default vs heavy tiers**

| Tier | Command | Contents |
|------|---------|----------|
| **Default** (CI / local full suite) | `cargo test --workspace` | Crate unit tests + scenarios + electrum + consensus_rules + live P2P (8-block `two_node`, restart reconstruct, dead-peer, hop serve, dual live seeders, post-IBD tip follow, getheaders gap fill, product `run_p2p --connect`) + hub reorgs. When agents run this suite: [`docs/how-we-plan.md`](docs/how-we-plan.md). Coverage stays a PR job. |

### Suite speed budgets (default tier)

**Target:** warm default suite wall **≤3 min** (stretch **&lt;2 min**) on a Linux host comparable to CI / agent VM with a warm `target/`.

**Baseline (agent VM, warm test profile, 2026-08-07):** full `cargo test --workspace` was **~1000 s (~17 min)** before store fan-in scale fixes. After parameterizing fan-in targets and shrinking SH head default benches (`6588b62` era): `rbitcoin-store --lib` serial **~26 s** (was **~498 s**); `sorted_run` module **~1 s** (was **~191 s**).

**CI-class (2026-08-17):** required GitHub Actions `test` job (`ubuntu-24.04`, `cargo test --workspace` + node/cli build) is **~85 s** (PR 85). That meets the ≤3 min budget and the **&lt;2 min** stretch on CI hardware. Do **not** re-run multi-minute full-suite timing loops as a planning spike; package walls below are still the local budget if a change feels slow.

| Package / binary (warm, order-of-magnitude) | Budget | Notes |
|---------------------------------------------|-------:|-------|
| `rbitcoin-store --lib` | **&lt;45 s** | Catalog-run fixtures stay tens of tiny files, not thousands |
| `rbitcoin-consensus --lib` | **&lt;30 s** | Prefer pure unit over full-store loops. Mainnet 866342 (~1.6 s) is the historical prevout pin — one zstd decode, overweight on a clone. |
| `rbitcoin-query --lib` | **&lt;20 s** | |
| `rbitcoin-test --test scenarios` | **&lt;15 s** | Prefer `pad_empty_from` / shared mature helpers |
| **Full** `cargo test --workspace` | **≤3 min** warm | Stretch **&lt;2 min** |

**New default-suite test rule:** if a new or expanded default test routinely takes **&gt;2 s wall** on a warm tree, the PR must **justify** it (what contract needs that cost, why a smaller N / unit cannot hit the branch). Prefer `#[ignore]` + reason string for true microbenches / host-only forensics.

**Do not pin production-scale constants in default unit fixtures** when a smaller N still exercises the code path:

| Anti-pattern | Prefer |
|--------------|--------|
| Thousands of SH catalog run files | Unsorted collect writes 64 prefix files; tests use tiny Class A |
| Multi‑GiB / mainnet head scale under `cargo test` | `testutil::tiny_store` / `tiny_query` / `tiny_regtest_hub` / `StoreLayout::tiny`; Mainnet only as a slot/shard/bit pin that does not create those files |
| Remining 100-block maturity pads with `confirm_wire_run` | `pad_empty_from` / `build_mature_regtest_with_spend` **once per binary journey** (not once per skinny test) |
| Wall-time multi-round microbenches in default suite | Deterministic structure / chunk-load asserts; demote wall arms to `#[ignore]` |

**P2P walls:** `two_node_header_and_block_sync`, `three_node_relay_path`, `ibd_two_peers`, `tip_follow_after_ibd`, `tip_follow_getheaders_catches_missed_blocks`, and `node_run_p2p_short` 60s wall (180s under `coverage.sh` / llvm-cov). `serve_after_restart_via_reconstruct` 90s wall (180s under llvm-cov). `p2p_compact_hb_getblocktxn_and_orphan` 30s wall (90s under llvm-cov). `p2p_timeout_getaddr_and_keepalive_ping`, `p2p_feeler_completes_and_closes`, and `p2p_inbound_full_rejects_extra` 20s wall. Live `P2PNode` tests in `integration_multinode` take a process mutex (shared `rbtc-scripts` pool / confirm OS threads); hub-only reorgs do not.

**Speed / reliability (default suite):** prefer `pad_empty_from` / `build_mature_regtest_with_spend` **once per journey** (tx_relay live hub, Electrum protocol, core_analogs assumevalid+mempool) over remine pads; SH run-builder sleeps are 1 ms under `cfg(test)` (40 ms in production). `pin_compose_multi_pack_timed` keeps functional + layout/covered short-circuit gates (multi-ms floor); sticky vs cold assemble is log-only (not a hard timing assert). Schema-13 wire rebuild must stamp create identity from `txid.body` — zero batch identity is treated as missing (regression covered by `reconstruct_and_connect_error_arms` + multi-vout confirm scenarios). Coverage vs speed: prefer **one** scenario at the real entry over N micro-opens that only paint lines; when adding coverage for reduce/materialize, use a **tiny** target, not production stream depth.

## Coverage

| Metric | Required |
|--------|----------|
| Line coverage | Production LCOV `LH`/`LF` from `./scripts/coverage.sh` **≥ 92%** (unrounded `LH*100 >= LF*92`). No never-falls ratchet — llvm-cov hit counts jitter tens of lines on the same tree. |
| Branch coverage | **≥ 90%** when measured on nightly with `--branch`; on stable, region-partial lines in the text report may remain — still close large gaps via scenarios |

Test modules (`*_tests.rs`, `/tests/`, `testutil.rs`, crate `rbitcoin-test`)
are omitted from `LH`/`LF`. `#[cfg(test)]` arms inside production files
still count. llvm-cov hit counts jitter tens of lines on the same tree;
the floor is the gate, not a never-falls ratchet vs master.

The README badge and rbitcoin.org figure are the last **green `master`**
`coverage` job (`badges` branch `coverage.json`, Shields endpoint). A red
PR does not publish. `coverage-history.jsonl` remains a log, not a gate.

`cargo llvm-cov`'s text “Missed Lines” column can count *partial regions within
a line* (for example match or-patterns) even when the line executed. The gate
uses LCOV line hit/total (`LH`/`LF`). HTML remains a diagnostic report under
`coverage/`.

```bash
nix-shell
./scripts/coverage.sh
```

Uses `cargo llvm-cov` with optional branch instrumentation. Local install if
missing: `cargo install cargo-llvm-cov --locked`. On Nix, prefer
`cargo-llvm-cov` from nixpkgs when available.

**CI:** the `coverage` job installs a **prebuilt** `cargo-llvm-cov@0.6.14` via
`taiki-e/install-action` pinned to a commit SHA (not a floating `v2` tag) —
it does **not** `cargo install` from crates.io on every PR. The job is
`timeout-minutes: 20` (step 15; `coverage.sh` GNU `timeout` 12m around
`llvm-cov test`, override `LLVM_COV_TEST_TIMEOUT`) so a hung instrumented
binary cannot sit until the runner 6h default. Do not pass `--report-time`
(stable rustc 1.95.0 rejects it).

**Target dir:** the script sets `CARGO_TARGET_DIR` to **`target/cov`** (override
with `CARGO_TARGET_DIR_COV`). Day-to-day `cargo test` / clippy use **`target/dev`**
from the nix shell so instrumented and uninstrumented artifacts never thrash
each other. Musl release stays on `nix build .#rbitcoin-musl` (crane), not host
`target/`. Default coverage is **incremental** (no `llvm-cov clean`); force a
cold instrumented rebuild with `COVERAGE_CLEAN=1 ./scripts/coverage.sh`.

### What is measured

All workspace members that contain production code:

- `rbitcoin-primitives`, `rbitcoin-store`, `rbitcoin-query`
- `rbitcoin-consensus`, `rbitcoin-mempool`, `rbitcoin-net`
- `rbitcoin-electrum`, `rbitcoin-esplora`, `rbitcoin-log`
- `rbitcoin-rpc`, `rbitcoin-cli`, `rbitcoin-node`

**Excluded by default:** third-party crates, `src/main.rs` trampolines, test
modules (`*_tests.rs`, `tests.rs`, crate `/tests/`, `testutil.rs`,
`tests_verify.rs`), crate `rbitcoin-test`, and `rbitcoin-bench` (optional
host client tool; not a coverage gate). Dependencies are not attributed
to us. `regtest_rpc.rs` / `regtest_pad.rs` stay in the denominator.

### Philosophy

1. Cover code with a [true journey](#true-journeys): one setup, one story,
   asserts on what a peer, client, or operator would observe.
2. Prefer extending that journey over a new small test. A caller of other
   tests is not a journey.
3. If a branch is unreachable from any real session, **delete it** or hit it
   through a **shipped** config / error / CLI path. Do not add a `pub` or
   `*_for_test` injector so a unit can see it
   ([`CONTRIBUTING.md`](./CONTRIBUTING.md) principle 11).
4. A small unit only when a real session cannot reach the behavior without
   absurd cost — say why in the test file. Drive the shipped function, not a
   `#[cfg(test)]` wrapper around it.

### Closing a red region

1. Open the HTML/LCOV report from `./scripts/coverage.sh`.
2. Identify high-miss production files (largest `LF − LH`).
3. Add or extend a **scenario** in `rbitcoin-test` or a unit test next to the
   shipped path that drives the real entry point.
4. Re-run `./scripts/coverage.sh` until the ratio is **≥ 92%**.

## Structural lints, CRAP, Miri, mutants

These do **not** measure operator RSS ([`docs/ibd-memory.md`](./docs/ibd-memory.md)
owns caps). They catch the *shapes* of unbounded heap / leaked tasks, untested
complexity, and UB in pure code. Landed: **Q-51–Q-53**. Named-cap ast-grep is
Won't-fix (**Q-54**). **Q-56** Completed: shipped scriptnum + pack-ints live in
primitives so Miri runs those functions. **Q-68** Completed: create.loc SIMD
deinterleave / inclusive `u8 << 3` live in primitives (scalar oracle; SIMD
matches scalar in default tests). Owner: [`docs/quality.md`](./docs/quality.md).

| Tool | How to run | CI |
|------|------------|----|
| **ast-grep** | `./scripts/ast-grep.sh` (needs `ast-grep` on `PATH`; `nix-shell` / `nix develop` provide it). Fixture self-test: `./scripts/ast-grep.test.sh` | Step in required job `qc` |
| **cargo-crap** | After LCOV, `./scripts/coverage.sh` calls `./scripts/coverage-crap.sh` (skip if `cargo-crap` missing). `--fail-above --threshold 30`; `.cargo-crap.toml` allowlists today's production CRAP>30 functions (remove a name when it scores ≤30). Dry-run: `CRAP_DRY_RUN=1 ./scripts/coverage-crap.sh`. Self-test: `./scripts/coverage-crap.test.sh` | Rides required `coverage`. No `--fail-regression` (llvm-cov coverage % jitters per function) |
| **coverage ignore / badge** | `./scripts/coverage.test.sh` (filename ignore, Tier A IBD not skipped, 92% floor, Shields JSON). Publish dry-run: `BADGE_DRY_RUN=1 ./scripts/publish-coverage-badge.sh` | `test` job self-test; `coverage` job writes `coverage/badge.json` and, on green `master`, pushes `badges/coverage.json` |
| **Miri** | `./scripts/miri.sh` → `cargo +nightly miri test -p rbitcoin-primitives`. Dry-run: `MIRI_DRY_RUN=1 ./scripts/miri.sh`. Self-test: `./scripts/miri.test.sh` | Nightly `miri.yml` (not required). Never `--workspace` |
| **cargo-mutants** | Nightly, not a PR check. `./scripts/mutants-nightly.sh` lists `--workspace` mutants, runs new diff lines first, then walks a cursor through the rest. `rbitcoin-bench` is excluded (`.cargo/mutants.toml` and `--exclude` on both invocations; CLI replaces the config glob). `#[mutants::skip]` on an expression is the won't-test list; those mutants are omitted, not `MISSED`. Each mutant uses `--test-workspace=true` so a higher journey counts, `--baseline=skip`, `-j 1`, 20 minute mutant timeout, 5 hour budget. Cursor artifact `mutants-cursor`. `MISSED` is uploaded and does not fail the run. Snapshot lists in [`docs/mutants/`](docs/mutants/) are host history, not the gate. | `mutants.yml` daily `47 7 * * *` (00:47 Pacific during PDT) and `workflow_dispatch`. Job timeout 330 minutes. |

Artifact silos above are unchanged: ast-grep / Miri dry-run / crap dry-run do
not write `target/`. `mutants.out/` is gitignored.

### Mature-chain fixtures

Electrum hub tests and `MempoolHub` accept harnesses use
`rbitcoin_consensus::pad_empty_from` for coinbase-maturity pads (not a local
`1..=103` POW remine loop).

Do **not** re-mine a 100-block maturity pad with per-height `confirm_wire_run`. Use:

```rust
use rbitcoin_test::{build_mature_regtest_with_spend, pad_empty_from};
// Full mature chain + one spend (accept path):
let chain = build_mature_regtest_with_spend(&query, &params);
// Or pad heights from_h..=last with accept_and_connect only:
let (tip, tip_time) = pad_empty_from(&query, &params, tip, tip_time, 2, maturity);
```

## Scenario catalog

Prefer **one high-level scenario** per behavior cluster. Delete lower-level tests when a newer scenario covers the same production paths.

| ID | Layer | Description |
|----|-------|-------------|
| `overlay_config` | Node CLI + net | In-process onion / I2P / cjdns matrix: `onlynet`, proxy, SAM, reachable, accept-incoming, and one parse or learn check per network. Live Tor, i2pd, and cjdns stay in overlay-functional. |
| `node_cli_and_surface_smoke` | Lifecycle/CLI | Networks, `run_node`, config errors, CLI flags (incl. `--conf`, `--peer-timeout=0` refuse / `=1` smoke, unknown conf key ignored, `min_relay_tx_fee=-1` and `network=nope` conf fail), dropped Core `--rpcuser`/`--rpcpassword`/`--rpcport`/`--rpcconnect`/`-rpcport` refuse, help/version. Signet: genesis header plus height-1 BIP325 connect |
| `three_stage_confirm_and_parent_pin_surface` | Consensus+query | Split load→scripts→write of pad+spend from genesis (header-plan BIP68 MTP); parent pin; load ready timeout/cancel; instance-owned `last_write` / `last_pin` / `take_window` meters; same-run create then spend; 546-shaped 2-vout merge + same-block chain + cross-batch head resolve |
| `mempool_under_pressure` | Mempool + RPC (crate) | One entry in `orphanage`, `accept`, `tx_relay`, and `methods_tests`: orphan reserve and expiry, sigops before script, rolling fee floor, cluster cap, parked min-relay orphan, and the package RPC rejects (unsorted, missing inputs, conflict, min-relay parent with maxfeerate child). |
| `block_cache_and_mempool_hub_surface` | Net | BlockCache locator/eviction + MempoolHub accept/remove/reorg on mature chain. `DEFAULT_BODY_DEPTH == 16` stays a unit. |
| `store_error_and_corrupt_paths` | Store | Error/corrupt surfaces |
| `store_table_header_and_idx_corrupt` | Store | Table header/head corrupt open |
| `pruned_seqsigwit_life` | Query + RPC (crate) | One `query_tests` entry for the prune watermark, RAM window, reopen, refuse-disable, reorg-through-pruneheight, and corrupt spill. One `methods_tests` entry for pruned `getblock` and `getblockstats` with and without txstat. |
| `chain_connect_reorg_and_growth` | Query | Synthetic growth + disconnect to genesis + reconnect suffix (header gen roll). Corrupt merkle in the last 6 confirmed heights: `Query::open` shrinks (`VERIFY_TIP_BLOCKS=6`) |
| `consensus_mature_chain_spend_reconstruct_and_scripthash` | Consensus+query | **One** mature mine: spend, local prev_fk, double-spend (accept, Class A then accept, and `confirm_wire_run`), reopen reconstruct (`witness_block_bytes` == serialize), SH history/balance. After disconnect, `resume_work_path_after_tip` still sees Class A bodies. Packed create_fk layout stays `input_encode_create_fk_not_prev_txid` |
| `confirm_load_ahead_of_write_does_not_badprev` | Consensus+query | Pipelined load 11..=20 while 1..=10 is still unwritten; then load 21..=32 after tip-GC (store MTP for confirmed parents) |
| `wire_prep_parent_layout_and_load_ahead` | Consensus+query | One mature pad: load-ahead fill of parent denserels after commit, already-archived plan=None spend annotate, cold Class A denserels for sequential spends of one create |
| `resume_tx_head_resolves_external_prev` | Query+consensus | Reopen `tx.head` create_fk spend; leftover TipOnly stamp matches the one connected fk; RAM leftover map clobber stays one slot |
| `buried_rules_and_a_lying_header_path` | Consensus (crate) | Signet BIP30 overwrite, mainnet BIP30 only when the BIP34 ancestor matches, and the anchored milestone, in `structure_rule_tests`. The heavier contiguous header-work path is the same name in `query_tests`. Store-less sigop and tx-count caps stay units. |
| `consensus_rules` (test binary) | Consensus | Focused reject paths for structure/header/connect rules we own — see [`docs/consensus-tests.md`](./docs/consensus-tests.md). Combined `header_and_spending_boundaries` includes H1/H2/H4/H5/H6, BIP68 height + time, and subsidy interval=2 overlay (50 BTC at interval−1, 25 BTC at interval, `subsidy+1` rejects). Same-block double spend, child-before-parent, `in < out`, and immature coinbase stay on that journey. Crate `accept_rejects_connect_spend_rules` is the LCOV pin (same-block coinbase spend, those connect rejects, 4-deep immature). Store-less `rejects_coinbase_excess_value_fast` stays with the subsidy table. H8 exact +2h stays `h8_timestamp_exactly_two_hours_accepts_plus_one_rejects`. Hornet-mapped subset: `./scripts/test-hornet-rules.sh` |
| `core_analogs::analog_milestone_and_mempool_persist` | Consensus | Milestone skip-below/check-above, missing prevout under high milestone, mempool persist (one pad). Restart leftover pool through catch-up then tip-mode relay-on: same-txid confirmed and input-conflict gone, child of a now-confirmed parent kept, DEAD marks durable without `flush`. Leftover `slots.tmp` after mid-compact: `MempoolHub` open finishes the rename and live count matches. Truncated body vs slots refuses (not empty pool) |
| `core_analogs::analog_reconstruct_after_lost_head` | Store+query | Wipe `tx.head/`, reopen, reconstruct height 1 and txid probe. Crash-open clamps unsealed `confirmed[]` (Electrum/RPC `chain_tip`). Leftover fuse8 v1 refuses at `Query::open` (Class A kept). Truncated MPHF and empty `tx.head/meta` rebuild from Class A |
| `unified_wire_pipeline_multi_block_to_tip` | Consensus+query | Class A archived ahead of tip then `confirm_wire_run` (no re-append + re-entry); empty run fails without advancing tip; then heights 2..=4 unified load/scripts/write |
| `direct_indexes_then_sh_bulk_at_tip` | Query | Direct IBD fills `tx.head`; SH bulk at tip; wipe SH shards, reopen, history still works. Keep unsorted pack/lag guts |
| `electrum_server_version_history_balance` | Electrum | One mature pad: version (`CARGO_PKG_VERSION`)/history/balance/headers, ping/features (`protocol_min` / `asof_protocol` / `server_version`)/tx/errors, confirmed history omits `fee`, scripthash subscribe notify, skip restatus when a new block misses the SH. TCP `get_history` `from_height` at create / exclusive `to_height` hides spend / `to_height=-1` open; subscribe status stays full; invalid `from_height` type. `get_merkle` wrong height for a known txid. Verbose `transaction.get` stamps `time`/`blocktime`/`confirmations`/`blockhash` and coinbase `vin`/`vout`. `id_from_pos` string vs `merkle=true` `{tx_hash, merkle}`; pos OOB errors. Line at `max_request_bytes` ignored; one past is JSON-RPC `-32600` `request line too long`. Electrum **1.6**: `mempool.get_info`, `blockchain.outpoint.*` (unsubscribe miss is `false`; tip notify while subscribed; missing vout errors), Frigate `silentpayments.subscribe` / unsubscribe / second unsubscribe / start past tip clamps / bad-params error, `block.headers` as a list, `broadcast_package` without a hub errors. Keep `read_line_capped` helper, dispatch height-window units, and crate TCP no-hub `estimatefee` `-1.0` / empty histogram / Cake `tweaks.subscribe [0,1,false]` |
| `electrum_scripthash_sub_cap_unsubscribe_frees_slot` | Electrum | Per-connection scripthash cap + unsubscribe frees a slot. Outpoint subscriptions use that same numeric cap on their own set (resubscribe does not consume another slot; a third distinct outpoint is `max 2` until unsubscribe). |
| `electrum_leftover_mempool_does_not_double_count` | Electrum | Relay-off leftover is confirmed, not a second mempool UTXO. With hub attached, `transaction.broadcast` of non-hex and consensus-invalid rejects (not hang / not admit). Same pad: confirmed `outpoint.get_status` (tip height, no `spending_txid`); `broadcast_package` invalid hex / reject / verbose success / non-verbose `"success"`; mempool-spent outpoint is `height=0` with `spending_txid`; mempool verbose `transaction.get` is `confirmations=0` with no `time`/`blocktime`/`blockhash` |
| `electrum_and_esplora_asof_hides_later_spend` | Electrum + Esplora | One pad: TCP `1.4.2-asof` plus HTTP `?asof=` hide a later spend; unknown asof errors; `GET /tx` `v0_p2wpkh` vout. SH-off tip+1: asof at visible SH watermark accepts, asof of the confirmed hash ahead of SH is `asof not on chain` / HTTP 404. Same-height A-B-A restatuses subscribe (confirming blockhash); `asof:` of the loser hash does not retry onto the sibling. Disconnect spend: history/utxo show the create again; live Esplora `/utxo` stamps the create hash (not the fork); loser `?asof=` 404 with no tip header. HTTP `503` `chain view moved` (no tip header) is `http_503_chain_view_moved_omits_tip_header` |
| `electrum_empty_chain_headers_subscribe_and_empty_scripthash` | Electrum | Empty store: `headers.subscribe` errors; scripthash history/balance/unspent/mempool empty |
| `electrum_tweaks_subscribe_streams_then_done` | Electrum | Cake `tweaks.subscribe`: one-height result, per-height notifies, `done`, and BIP352 hash-bind on a P2WPKH→P2TR spend. Keep zero-chunk / pre-taproot units |
| `electrum_max_connections_rejects_extra_client` | Electrum | TCP cap drops the extra client |
| `electrum_idle_timeout_disconnects_quiet_client` | Electrum | Idle timeout closes a quiet socket |
| `esplora_broadcast_visible_in_rpc_and_electrum` | Node + Electrum + Esplora + RPC | One `run_p2p` datadir: HTTP `sendrawtransaction` / `testmempoolaccept` (allowed, missing-or-spent, exact 100 sat/kvB min-relay accept + one-sat-under reject, RBF one-sat-short incremental reject + exact incremental accept); Esplora `POST /tx` parent and mempool child appear in `getrawmempool` and Electrum mempool/history (`fee` on unconfirmed, including child `height = -1`); Electrum `listunspent` of that child is `height=-1` and the parent UTXO drops; process `gettxout` / `getchaintips`; Esplora `POST /txs/package` 1p1c (including parent-alone below min-relay + paying child), 25-tx accept, 26-tx and over-weight `package too large`; serving-only `submitpackage` refuses (relay off); live `GET /mempool` / `/mempool/txids` / `/mempool/recent` / `/fee-estimates` (depths 1/5/144/504/1008 present and > 0; under-full near can be min-relay 0.1 sat/vB); process `getmempoolancestors` / descendants / cluster / `gettxspendingprevout` / feerate diagram / verbose `getrawmempool` on that 1p1c; `waitforblockheight` timeout=0 while behind returns the live tip; GBT stale `longpollid` is immediate; current id / `waitfornewblock` / `waitforblockheight` wake on the pad `generate`; `getblockhash` tip ok / tip+1 `-8`; unknown `getblock` `-5`; verbosity 0 hex and 2 vin/vout; `GET /blocks` 10 newest, `/blocks/0` and `/blocks/:tip` (start past tip clamps); `/block/:hash/txs/:start` last page shorter than 25, one-past last page `[]` (not 404), unknown hash 404; `/block/:hash/txids` + coinbase merkle-proof + unspent `outspend/0`; `/tx/:id/outspends`; `/block` JSON/raw/status/`txid/0` (OOB 404); `/tx/:id/raw` vs hex; merkleblock-proof; `/block-height` (missing 404); `/block/:hash/header` 160 hex; `/tx/:id/status` + full JSON (`unknown` OP_TRUE type, coinbase vin) and missing-tx 404s; OP_TRUE scripthash info/summary/utxo/`txs/chain` cursor and combined `/txs`. Keep crate no-hub mempool/fees/POST 503, reconstruct meters, header wire match, and `tx_status_json`; Esplora `/tx/:id/status` confirms the package parent on generate; `generate` includes those txs (parent before child) then leaves IBD (relay on); `scantxoutset` drops the spent coinbase and still sees a non-coinbase unspent; `submitpackage` maxfeerate reject, 1p1c success, already-in-mempool continue, below-min-relay parent + paying child success, 26-tx / over-weight `package too large`; immature coinbase sendraw rejects. Keep `accept.rs` reject units, package JSON errors, RPC dry-run orphan-count, leftover `gettxout` include_mempool / disconnected / leftover, `generate_selects_chained_mempool_parent_first`, `submitpackage_child_fail_keeps_parent`, maxburn `submitpackage`, and wait-on-stop units. Unix `--rpc-socket` (mode 0660, no datadir `rpc.sock`) `getblockcount` without Authorization; TCP `GET`/`POST /internal/mempool/txs`; `GET /internal/block/:hash/txs` full list vs public 25/page; `POST /internal/txs/outspends/by-txid` same-length unknown `[]` slot; `GET /address-prefix/bc1` **404**; unauthenticated Core REST on the RPC listener (`chaininfo`, block hash/headers/block/tx, mempool info/contents, `getutxos`, `deploymentinfo`, basic `blockfilter` bin/hex/json) and `getblockfilter` with `--block-filter-index` |
| `fee_history_backfills_from_the_chain_when_relay_starts` | Node + RPC | `run_p2p` over a datadir whose only fee-paying block predates startup; `generate` leaves IBD and turns relay on; `estimatesmartfee 144` answers that block's rate from the chain backfill, not from blocks mined after start |
| `two_node_header_and_block_sync` | P2P (**default**) | Seeder → peer genesis+1 IBD; peer `last_write` meter. Empty `headers` lag keep-sync is `apply_peer_event_body_and_control_surface`; drained-path EOF `headers_done` is `apply_peer_event_block_framed_bq_horizon_and_headers_done`. 8-block dual-seeder stays `ibd_two_peers` |
| `p2p_timeout_getaddr_and_keepalive_ping` | P2P (**default**) | One pad: v1-magic inbound drops at `peertimeout=1`, obsolete VERSION and pre-verack ping close the peer, full-relay GetAddr cache 1000, headers-sync stall replace, self-connect refuses, AddrFetch `getaddr`/`addrv2` (no `getheaders`), one keepalive ping/pong. Handshake **format** needles stay. Sole-preferred stall KEEP stays a PeerHub unit (`noban_headers_timeout_clears_awaiting_so_a_new_getheaders_can_send`: CIDR `noban@127.0.0.1` and hub `--trusted`). |
| `hostile_peer_session` | P2P (**default**, crate) | One lib entry in `peer::tests`, one in `chain::tests`, one in `assign::tests`. Header cap, send budget, one-shot `getaddr`, addr relay to one or two peers, zero-prev not held, witness padding and time-too-new not cached invalid, getdata stops at the byte budget. `tip_script_pres_skips_only_matching_wtxid` stays its own test (mempool graph, not the peer session). |
| `p2p_compact_hb_getblocktxn_and_orphan` | P2P (**default**) | One mature pad: HB coinbase `cmpctblock`, 2-tx compact → `getblocktxn` then same-peer compact retry while pending + `blocktxn` connect, unique short-id fill that fails header merkle → `getdata` (not `getblocktxn`, header not `BLOCK_FAILED`) then honest full `block` connects, orphan child GetData then parent accept (INV AlreadyHave), then live `getblocks` → `inv`, inbound `feefilter`, `filterload` disconnect. The pad seals filters through height 1, advertises `NODE_COMPACT_FILTERS` while the tip is ahead, stays silent for a stop at the tip, and answers `getcfilters` / `getcfheaders` / `getcfcheckpt` for the sealed height. Oversize locator and MemPool/`filteradd`/`filterclear` stay PeerHub units. Live mutated `block` disconnects in `on_block`. Inbound `getdata` of 20 witness blocks serves `MAX_SERVE_BLOCKS` (16); 17th is not queued (`getdata_skips_reconstruct_when_serve_inflight_at_cap`). Same-peer pending compact skip is `same_peer_pending_cmpct_does_not_getblocktxn_again`. Does **not** pin tokio-worker lock or park-not-reject logs |
| `p2p_feeler_completes_and_closes` | P2P (**default**) | Outbound feeler: VERSION then close (`feeler connection completed`). No live follow; dummy has no completed inbound. Same test: `run_feeler_timed` silence is `Timeout`. Inbound/outbound/plain silence stay `handshake_timeout_after_silence` |
| `p2p_inbound_full_rejects_extra` | P2P (**default**) | `max_inbound=1`: second follow is refused; first inbound stays. Same test: `select_inbound_eviction` 21-cand ranking (4 block + 5 slow + 4 tx + 8 ping → victim in slow). noban-alone stays a unit |
| `badprev_orphan_does_not_blacklist_then_reorg_reconstructs` | P2P/chain (default) | Orphan whose prev is not on the tip is held (not `BLOCK_FAILED`); winner branch reconstructs |
| `serve_after_restart_via_reconstruct` | P2P (**default**) | Cold serve via reconstruct. Restart RAM body queue is empty. Same-process `rehydrate_block_queue_residue` drops at/below tip, skips empty payloads, keeps above-tip wire, unknown height stays queued. `has_block` / known-archived keep and tip+1 gap `missing` stay `bq_rehydrate_residue_keep_drop_gap_and_unknown` |
| `ibd_skips_dead_peer` | P2P (**default**) | Live seeder + `127.0.0.1:1` |
| `reorg_to_longer_branch` | P2P/chain (default) | Most-work reorg (hub only — no IBD hang risk) |
| `reorg_same_height_then_multi_block_branch` | P2P/chain (default) | Mature pad + competing-spend reorg (third spend is prevout-spent, not `multi-spender`); same-height rival then multi-block reorg near tip; `getchaintips` `active` vs `valid-fork`; 16 vs 17 equal-work siblings park as `valid-headers` (product held cap 320 does not FIFO at 17); `precious_block` the loser; less work ignored; unknown hash `Block not found`. Held cap FIFO stays `hold_body_caps_fifo` |
| `three_node_relay_path` | P2P (**default**) | Leaf IBD-syncs from a mid node that already synced (hop serve) |
| `ibd_two_peers` | P2P (**default**) | Dual live seeders, 8-block IBD |
| `tip_follow_after_ibd` | P2P (**default**) | After IBD, follow + one new tip via inv/headers. With `--block-filter-index` on, IBD writes no basic filters; materialize seals through the tip, then the followed block seals one more |
| `tip_follow_getheaders_catches_missed_blocks` | P2P (**default**) | Blocks mined while disconnected fill via post-connect `getheaders` |
| `node_run_p2p_short` | Node (**default**) | Product `run_p2p` `--blocks-only` `--connect` to a live seeder (`--max-tip-age` so the 3-block pad is not stale IBD); process `getpeerinfo` / `getconnectioncount` / `getnetworkinfo` / `getnettotals` / `ping` while connected (v2 outbound-full-relay; handshake `startingheight` equals the seeder tip; `timeoffset` present; `synced_headers`/`synced_blocks` stay `-1` until the peer announces a header hash (empty getheaders at tip does not copy VERSION height); `servicesnames` present; `getnetworkinfo.timeoffset` present); after catch-up `localrelay` / mempool `relay_enabled` stay false and `sendrawtransaction` is not `relay disabled`; Electrum `broadcast` and Esplora `POST /tx` admit decode/consensus errors (not hub-missing / not `relay disabled`); `addconnection inbound` refuses; `disconnectnode` unknown `nodeid` / empty params error then a real addr clears `getpeerinfo`; `addnode onetry` reconnects as `manual`; seeder inbound `tx` then disconnects. Exit via `stop`. `max_run_secs=0` stays a node-crate unit. Mock-clock `timeoffset` median (odd N, even N upper-middle, inbound-only 0, peer clock behind), connecting dummy `-1`, header-only vs connected `synced_blocks`, query-without-chain, `pingwait` / `NETWORK_LIMITED` / `noban` stay RPC guts |

Removed (covered by the rows above): `confirm_cross_block_prevout_without_tx_head`,
`double_archive_keeps_tx_height_for_coinbase_maturity`, `mega_batch_duplicate_header_is_idempotent`,
`archive_local_prev_fk_and_reconstruct`, `ibd_to_tip_tracking_and_block_relay`,
`multinode_mesh_periodic`, `confirm_structural_rejects_already_spent_prevout`,
`unified_wire_pipeline_rejects_double_spend`, `confirm_run_sequential_and_failed_no_spend_poison`.

### Integration / multi-node

Default `cargo test` runs the live P2P catalog above (`two_node`, reconstruct,
dead-peer, hop serve, dual seeder, tip follow, getheaders gap, `run_p2p --connect`,
compact/feeler/inbound-full, hub reorg). Live `P2PNode` tests serialize in-process.
There is no ignored topology tier and no `scripts/integration.sh`.

New features: add a high-level scenario; remove obsolete lower-level tests in the same PR.

## Core differential

Nightly (not a required PR check) `fuzz.yml` runs **20** cargo-fuzz jobs.
`fuzz/` is not a default workspace member.
Treat crate-root `pub` that exists only so a fuzz target can call it as
the same smell as a test-only export: prefer `pub(crate)` plus an in-crate
harness, or the published `rbitcoin-node` / CLI binary, even if that costs
a little setup time, rather than growing helpers solely for fuzz. Allowlist
what must stay `pub` for a target; do not treat `fuzz/` as a second public
API.

| Target | What | Oracle |
|--------|------|--------|
| `block_wire` | `check_block_wire` (ASan, `block.dict`) | none |
| `v2_contents` | BIP324 `parse_v2_contents` + `try_decode` (ASan, `v2.dict`) | none |
| `addrv2_wire` | BIP155 `addrv2` payload parse (ASan, `addrv2.dict`) | none |
| `inv_getdata_wire` | `inv` / `getdata` payload parse (ASan, `inv.dict`) | none |
| `electrum_json` | Electrum JSON-RPC line parse (ASan, `electrum.dict`) | none |
| `asmap` | Core asmap bytecode `AsMap::from_bytes` then `interpret_ip16` on leftover 16 bytes (ASan, no Core). Junk must not panic or hang | none |
| `v2_session` | BIP324 handshake + structured ping/pong vs a live v31.1 `bitcoind` v2 peer (ASan). Matching `pong` is a comparison. Garbage slice remains for encoder ASan. | official **v31.1** `bitcoind` tarball (`scripts/core-functional/fetch-bitcoind.sh`), `-listen=1` |
| `cmpct_differential` | structured BIP152 recipe → `try_reconstruct` missing indexes vs Core `getblocktxn` (ASan). Fill-flag extras go to Core extra-txn first. Raw-wire arm is skip if decode fails. Full reconstruct (no `getblocktxn`) is a comparison. **Not** accept/reject; **not** two-node reorg. Duplicate-txid fill (018) may request extra indexes Core extra-txn already placed; Core's request must be a subset of ours | same tarball, `-listen=1` |
| `block_differential` | height-1 `ChainHub::accept_received_block` vs Core `submitblock`, **accept vs reject only** | same tarball |
| `block_spend_differential` | height-101 spend of a mature pad coinbase, same path and oracle | same tarball |
| `script_differential` | height-101 same-block spend whose **executed scriptPubKey** is fuzzer-owned, same path and oracle | same tarball |
| `block_fork_differential` | 2-block heavier fork off the pad (sibling of a pad+1 stem), same path and oracle | same tarball |
| `cmpct_reorg_differential` | same fork child, but hub delivers **child then parent** through `drain_pending` (014/020); Core `submitblock`s parent then child. Accept vs reject of C / final tip | same tarball |
| `block_reorg_n_differential` | `DIFF_REORG_N` heavier side vs 1-block stem; same rewind/restore as fork | same tarball |
| `block_csv_differential` | BIP68 relative lock (full `u32` nSequence + version + MTP `time_shift`) vs Core `submitblock` | same tarball |
| `mempool_differential` | `MempoolHub::test_accept` vs Core `testmempoolaccept`. **Consensus-class only** — Core standardness / fee / RBF / dust is skip (COMPAT) | same tarball, `-acceptnonstdtxn=1` |
| `script_verify_differential` | `verify_tx_scripts_detached` vs Core `testmempoolaccept` of the parent+spend package. Same policy skip | same tarball, `-acceptnonstdtxn=1` |
| `store_reorg` | Tiny-hub `{extend, sibling, rewind}` connect churn (ASan, no Core). Equal-work siblings park in `held_bodies`; sibling ops no-op once `held_body_count` hits 16 so `try_apply_held` stays inside `-timeout=30` on one persistent hub (reopening the store leaked ASan RSS to 2 GiB). Store `Corrupt` / probe-exhausted **panics** | none |
| `script_kernel_differential` | In-process `verify_tx_scripts_detached_forks` vs `bitcoinconsensus::verify_with_flags` (ASan, **fuzz workspace only**) | Core interpreter via `bitcoinconsensus` crate |
| `p2p_sequence_differential` | Up to 8 `{ping, headers, block}` steps vs live Core v2 + `compare_one` for block | same tarball, `-listen=1` |

```bash
./scripts/fuzz-run.sh                           # block_wire (ASan)
./scripts/fuzz-run.sh v2_contents               # BIP324 contents (ASan)
./scripts/fuzz-run.sh addrv2_wire               # BIP155 payload (ASan)
./scripts/fuzz-run.sh inv_getdata_wire          # inv/getdata payload (ASan)
./scripts/fuzz-run.sh electrum_json             # Electrum JSON line (ASan)
./scripts/fuzz-run.sh asmap                      # asmap bytecode + leftover IP (ASan)
./scripts/fuzz-run.sh v2_session                # live Core v2 peer, ping/pong compare, ASan
./scripts/fuzz-run.sh cmpct_differential        # compact missing indexes vs getblocktxn, ASan
./scripts/fuzz-run.sh block_differential        # fetch bitcoind, --sanitizer none
./scripts/fuzz-run.sh block_spend_differential  # 100-block pad, --sanitizer none, -timeout=180
./scripts/fuzz-run.sh script_differential       # mutate executed scriptPubKey, --sanitizer none
./scripts/fuzz-run.sh block_fork_differential   # pad+stem, 2-block fork, --sanitizer none
./scripts/fuzz-run.sh cmpct_reorg_differential  # child-first drain_pending vs Core
./scripts/fuzz-run.sh block_reorg_n_differential # N-block side vs 1-block stem
./scripts/fuzz-run.sh block_csv_differential    # BIP68 nSequence + version + MTP
./scripts/fuzz-run.sh mempool_differential      # test_accept vs testmempoolaccept
./scripts/fuzz-run.sh script_verify_differential # detached scripts vs testmempoolaccept package
./scripts/fuzz-run.sh store_reorg                # tiny hub connect/disconnect, ASan, no Core
./scripts/fuzz-run.sh script_kernel_differential # ours vs libbitcoinconsensus, ASan, no Core
./scripts/fuzz-run.sh p2p_sequence_differential  # ping/headers/block vs Core, --sanitizer none
```

`block_differential` prepares every candidate on **regtest genesis** (`prev`
fixed; coinbase/version stay fuzzer-owned). After a compared accept, rbitcoin
`rewind_to_height(0)` and Core `invalidateblock` until `getblockcount==0`.
`block_spend_differential` mines a **byte-identical** 100-block empty pad
(in-process, then `submitblock` each to Core — never Core `generate`), then
prepares candidates that spend the height-1 `OP_TRUE` coinbase. After a
compared accept, both sides rewind to height **100**. `script_differential`
uses the same pad; the fuzzer bytes are the scriptPubKey of an intra-block
output that a second tx spends (empty scriptSig), so the interpreter runs
them. Seed `OP_TRUE` (`0x51`) must accept. JSON corpora stay as static
vectors. `block_fork_differential`
mines the same pad plus one empty **stem** at height 101, then compares a
strictly heavier 2-block fork off height 100 (the first fork block is setup /
hold only — equal-work Core `null` is not a compared verdict). After a compared
accept, both sides rewind to the pad and restore the stem. Default-suite pins
use a 3-block pad + stem. The diff hub overlays `bip34@1` only —
global `ChainParams::regtest()` is unchanged. Harness/oracle failure exits
**2** (no libFuzzer crash file). Accept/reject disagreement **panics**
(reproducer). A red nightly is a **finding** (`docs/external_findings/`), not
a test to green by changing production in the harness PR.

`v2_session` completes VERSION/VERACK on the encrypted session
(`V2PlainSession`), then sends a first-byte-selected well-formed message
(`ping`/`pong`/`sendcmpct`/`verack`/`getheaders`) or a garbage slice.
A `ping` whose `pong` nonce matches counts as a comparison. Core TCP drop
on leftover garbage is not a consensus split.

`block_csv_differential` maps `[seq:u32 le][ver:u8][time_shift:u16 le]`
(short leftover zeros). Version 0 → tx v1 (CSV ignored); otherwise v2.
`time_shift` is added to the spend header time so MTP can satisfy or fail
`SEQUENCE_LOCKTIME_TYPE_FLAG`.

Skip-rate gate: after `Done N runs` with N≥1000, `comparisons/runs` must
be ≥ **0.01** for submitblock diffs. Skip-heavy jobs (`mempool_differential`,
`script_verify_differential`, `cmpct_differential`, `v2_session`) need
≥ **0.005**. Zero comparisons always fail. Unset `FUZZ_MAX_TOTAL_TIME` is
**600** (3600 when `date +%u` is Sunday).

`cmpct_differential` maps fuzzer bytes to a height-1 BIP152 recipe (extra
count, prefill mask, fill/duplicate/corrupt flags, nonce) then encodes a
well-formed `cmpctblock`. `data[0] % 8 == 7` is the raw-wire arm
(`prepare_cmpct_fuzz_hsi` restamp; malformed decode is skip). Each case
grinds a unique header (prev = genesis) so Core treats it as a new compact.
Spawn `setmocktime`s Core to regtest genesis time (`CanDirectFetch`).
P2P `bitcoind` also gets `-maxtipage=999999999` so Core v31's IBD latch
(`UpdateIBDStatus` on `LoadChainTip`, not `setmocktime`) leaves IBD at
genesis — otherwise P2P `tx` is dropped and fill extra-txn never matches.
Fill-flag extras are sent as `tx` first (Core extra-txn / orphan pool)
and included in our short-id map. Missing indexes must match Core
`getblocktxn`. Fully reconstructed (empty missing, Core sends no request)
is a comparison. After a compared case, Core `invalidateblock`s that
header. Seeds: 2-tx hole, coinbase-only, fill, duplicate short-id, raw
fixture. Disagreement panics. It does not compare accept/reject and does
not drive a two-node reorg.

`cmpct_reorg_differential` uses the same pad+stem and fork child as
`block_fork_differential`, but the hub never `accept_received_block`s B or C.
C then B enter `pending` and one `drain_pending` (child first); Core
`submitblock`s B then C. ours Accept iff hub tip is C. After a compared
verdict, both sides rewind to the pad and restore the stem. Not a live Core
HB `cmpctblock` announce.

`mempool_differential` and `script_verify_differential` use Core
`testmempoolaccept`. Libre vs Core **policy** is skip (COMPAT), including
`scriptpubkey` / `nonstandard` / non-mandatory script flags.
`mandatory-script-verify-flag-failed` is consensus and is compared.
RPC-only `bitcoind` is spawned with `-acceptnonstdtxn=1` (v31.1 regtest
requires standardness by default) so the OP_TRUE pad spend compares
consensus instead of bouncing at `IsStandardTx`.

## P2P serve bench (host only)

`scripts/ibd-serve-bench.py` is an IBD-shaped BIP324 client: `getheaders` then
windowed `getdata` `MSG_WITNESS_BLOCK` (16 inflight). It does **not** run in
CI and must not open a mainnet datadir in the agent VM.

```bash
python3 -m pip install --user cryptography
python3 scripts/ibd-serve-bench.py --network mainnet --bytes 512M 127.0.0.1:8333
```

Compare client `throughput` with node DEBUG `tip: perf` `serve bytes=` / `n=`
(window reconstruct+encode; `avg_us` / `max_us` are per-block walls).

Default `cargo test` does **not** download Core, bind RPC/P2P, or compile `fuzz/`.
The official tarball is glibc; GitHub Actions `ubuntu-latest` runs it. A NixOS
host cannot exec it without a foreign-glibc loader — that is CI-only, not a
default-suite concern.

Inventory for Bitcoin Core **v31.1** functional tests lives in
[`scripts/core-functional/`](scripts/core-functional/)
([`docs/core-functional.md`](docs/core-functional.md)).
`python3 scripts/core-functional/check_inventory.py` is the completeness
gate. `run.sh` may only invoke inventory `run` names (see
`./scripts/core-functional/run.sh --list`).
The nightly job (`.github/workflows/core-functional.yml` →
`scripts/core-functional/nightly.sh`) warns — it does not fail — when a
newer Bitcoin Core release exists than the inventory pin. Label
**`core-functional`** on harness PRs and on **ship** version-bump PRs
([`docs/releases.md`](docs/releases.md)). It is **not** a required PR check,
including on PRs that touch net or RPC (too slow). Label
**`nixos-module-runtime`** to run the NixOS module qemu test; every PR still
runs `nixos-module-eval`. Unlabeled PRs keep the default cargo jobs plus
eval. Default `cargo test` does **not** invoke Core’s Python
suite. A red labeled run is reproduced locally with
`./scripts/core-functional/run.sh <failing.py>` until that script passes
([`docs/core-functional.md`](docs/core-functional.md)); do not push-and-wait
on that job as the inner loop.
Label **`overlay-functional`** on harness PRs and on **ship** version-bump
PRs. It is **not** a required PR check. A red labeled run is reproduced
locally with `./scripts/overlay-functional/run.sh <filter>`
([`docs/overlay-functional.md`](docs/overlay-functional.md)).

```bash
python3 scripts/core-functional/check_inventory.py
./scripts/core-functional/check_inventory_test.sh
./scripts/core-functional/sync-core-fixtures.test.sh
./scripts/core-functional/run.sh.test.sh
./scripts/core-functional/run.sh --list
./scripts/core-functional/run.sh feature_uacomment.py rpc_uptime.py
./scripts/core-functional/bitcoind.test.sh
./scripts/core-functional/create_cache.test.sh
./scripts/core-functional/check_core_release.test.sh
# cargo test stages Core JSON from the submodule:
./scripts/core-functional/init-submodule.sh
./scripts/core-functional/sync-core-fixtures.sh --check
./scripts/overlay-functional/run.sh.test.sh
./scripts/overlay-functional/run.sh --list
```

## What a mutant kill looks like

Mutants are a nightly oracle, not a pull-request check. The command is
`./scripts/mutants-nightly.sh` ([`mutants.yml`](.github/workflows/mutants.yml)).
Do not treat a package-only `cargo mutants` run as the gate: a journey
outside the mutated crate must be able to catch the mutant.

A new production behavior still needs a test that fails when that behavior
is removed or inverted. Put that assert on a catalog journey, or on a
store-less unit when the journey cannot see it. `MISSED` in the nightly
artifact means no workspace test cared. Extend the journey. A same-crate
twin that only existed to satisfy a package-local mutant is a deletion
candidate once a workspace run shows the journey catching it.
