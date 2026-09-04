# Testing guide

## Preference order (dev-cycle aware)

| Prefer | Avoid |
|--------|--------|
| **Journey scenarios**: one `/tmp` store, one mature pad, then a **sequence** of asserts (spend, reject, reconstruct, scripthash, …) | Many skinny scenarios that each remine maturity and re-open the store |
| **Pure units** on pure helpers (scriptnum, bits, fuse8, open-hash) with **no store** | Units that re-implement confirm and only paint lines a journey already hits |
| **One entry** per production path (scenario **or** unit next to the shipped fn) | Twin unit + scenario for the same reject string |
| Core JSON corpora for **script engine** breadth | A second parallel script suite |

**Fewer scenario functions / store opens, not less coverage** — put more asserts on one carefully designed multi-stage journey.

### Parallel cargo test (same binary)

`cargo test` / `cargo llvm-cov test` run **one process per test binary**. Do not:

- Put HOLD / wait hooks in a shipped function other tests also call (`confirm_scripts_phase`).
- Assert process-global last-writer meters (`confirm_phase_stats`, `confirm_thr_stats::sample_and_reset`, `last_union_miss` / `last_plan_batch`) as the contract. Use pin/layout, error strings, or a pure formatter / local `AtomicU64`.
- `std::env::set_var` without the crate lock (or pass the knob as an argument).
- Bind a fixed port (use `:0`) or share a `/tmp` path (use `TestDatadir` / pid+nanos+seq).

Do **not** “fix” flakes with `RUST_TEST_THREADS=1`.

Shared helpers live in the `rbitcoin-test` crate (`mine`, `chain_fixture`).

### Third-party deps and compile cost (2026-08)

| Change | Why it helps the cycle |
|--------|------------------------|
| **mimalloc** only on product bins (`rbitcoin-node`, `rbitcoin-cli`) | Store **lib** tests no longer compile `libmimalloc-sys`/`cc`. Production still uses mimalloc on node/cli. |
| **rayon removed** from consensus | Parallel scripts use in-crate `script_pool` (`rbtc-scripts` steal). Drops rayon + crossbeam from the consensus graph. |
| **xorf + bincode + serde** removed from store | Sealed fuse8 is in-tree (`binary_fuse8` + hand LE layout **v2**). Drops a serde-heavy path from store rebuilds. |
| **fuse8 v1 → v2 on open** | Legacy fuse files soft-migrate (always-probe + rewrite from Class A); **do not** wipe `tx.head` for fuse payload-only changes. |

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

Windows/macOS PR surface is `./scripts/ci-os-smoke.sh`, not this full suite —
see CONTRIBUTING (What works on each OS). No `libbitcoinconsensus` in the graph:
`cargo tree -i bitcoinconsensus` must fail to resolve.

### Artifact silos (do not mix)

Host **gnu** objects are not interchangeable with **musl** release or with
**llvm-cov**-instrumented objects (different triple / profile / RUSTFLAGS).

| Silo | Where | Used by |
|------|--------|---------|
| **Dev** | `target/dev` (`CARGO_TARGET_DIR`; `nix-shell` / `nix develop` set it — rustup users should export it) | fmt, clippy, `cargo test`, ad-hoc `cargo build` |
| **Coverage** | `target/cov` (forced in `scripts/coverage.sh`) | `./scripts/coverage.sh` only |
| **Musl release** | Nix store via crane (`cargoArtifacts` + app) | `nix build .#rbitcoin-musl` — **not** `./target` |

Override dev dir only when intentional: `CARGO_TARGET_DIR=…` (Nix shell
reads it; rustup users export it). Override coverage dir:
`CARGO_TARGET_DIR_COV=… ./scripts/coverage.sh`.

**Default vs heavy tiers**

| Tier | Command | Contents |
|------|---------|----------|
| **Default** (CI / human local full suite) | `cargo test --workspace` | Crate unit tests + scenarios + electrum + consensus_rules + **8-block** `two_node` IBD + hub reorgs. Reconstruct / dead-peer are the **multinode** job. Agents use targeted `-p` tests locally; this suite runs on the PR. |
| **CI multinode job** | named filters + `--ignored` job-only cases | 8-block IBD, reconstruct, slim dead-peer |
| **Heavy multi-node / IBD** | `./scripts/integration.sh` or `-- --ignored` on `integration_multinode` / `ibd_smoke` | Multi-hop, tip-follow, 48-block dual seeder, mesh, `run_p2p` |

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
| **Full** `cargo test --workspace` | **≤3 min** warm | Stretch **&lt;2 min**; ignore-tier IBD stays out |

**New default-suite test rule:** if a new or expanded default test routinely takes **&gt;2 s wall** on a warm tree, the PR must **justify** it (what contract needs that cost, why a smaller N / unit cannot hit the branch). Prefer `#[ignore]` + reason string for true microbenches / host-only forensics.

**Do not pin production-scale constants in default unit fixtures** when a smaller N still exercises the code path:

| Anti-pattern | Prefer |
|--------------|--------|
| Thousands of SH catalog run files | Unsorted collect writes 64 prefix files; tests use tiny Class A |
| Multi‑GiB / mainnet head scale under `cargo test` | `RBITCOIN_HEAD_SCALE=tiny` / `cfg(test)` default; force mainnet only for explicit scale tests |
| Remining 100-block maturity pads with `confirm_wire_run` | `pad_empty_from` / `build_mature_regtest_with_spend` **once per binary journey** (not once per skinny test) |
| Wall-time multi-round microbenches in default suite | Deterministic structure / chunk-load asserts; demote wall arms to `#[ignore]` |

**Tier A timeouts:** `two_node_header_and_block_sync` 60s wall (default + job). Reconstruct / dead-peer are **multinode job only** (`#[ignore]`; job passes `--ignored`). `coverage.sh` also `--skip`s those names plus `two_node`. Heavier topology stays `#[ignore]` (`scripts/integration.sh`).

**Speed / reliability (default suite):** prefer `pad_empty_from` / `build_mature_regtest_with_spend` **once per journey** (tx_relay live hub, Electrum protocol, core_analogs assumevalid+mempool) over remine pads; SH run-builder sleeps are 1 ms under `cfg(test)` (40 ms in production). `pin_compose_multi_pack_timed` keeps functional + layout/covered short-circuit gates (multi-ms floor); sticky vs cold assemble is log-only (not a hard timing assert). Schema-13 wire rebuild must stamp create identity from `txid.body` — zero batch identity is treated as missing (regression covered by `reconstruct_and_connect_error_arms` + multi-vout confirm scenarios). Coverage vs speed: prefer **one** scenario at the real entry over N micro-opens that only paint lines; when adding coverage for reduce/materialize, use a **tiny** target, not production stream depth.

## Coverage

| Metric | Required |
|--------|----------|
| Line coverage | **≥ 90%** of first-party executable lines (LCOV `LH`/`LF` from `./scripts/coverage.sh`) |
| Branch coverage | **≥ 90%** when measured on nightly with `--branch`; on stable, region-partial lines in the text report may remain — still close large gaps via scenarios |

CI fails if measured line coverage is **below 90%**. New and existing first-party
code share this bar.

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
it does **not** `cargo install` from crates.io on every PR.

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
- `rbitcoin-bench` (lib only; bin is `--features cli`)

**Excluded by default:** third-party crates and `src/main.rs` trampolines.
Dependencies are not attributed to us.

### Philosophy

1. Cover code with **high-level functional/integration scenarios** (this file).
2. Prefer expanding the harness over adding private unit tests.
3. If a branch is unreachable, **delete it** or add a public fault injector /
   config path so a scenario can hit it.
4. True unit tests only when a branch cannot be reached through any higher API
   without absurd cost — document the reason in the test file.

### Closing a red region

1. Open the HTML/LCOV report from `./scripts/coverage.sh`.
2. Identify high-miss production files (largest `LF − LH`).
3. Add or extend a **scenario** in `rbitcoin-test` or a unit test next to the
   shipped path that drives the real entry point.
4. Re-run `./scripts/coverage.sh` until line coverage is **≥ 90%**.

## Structural lints, CRAP, Miri

These do **not** measure operator RSS ([`docs/ibd-memory.md`](./docs/ibd-memory.md)
owns caps). They catch the *shapes* of unbounded heap / leaked tasks, untested
complexity, and UB in pure code. Roadmap: [`docs/quality.md`](./docs/quality.md)
**Q-51–Q-56**.

| Tool | How to run | CI |
|------|------------|----|
| **ast-grep** | `./scripts/ast-grep.sh` (needs `ast-grep` on `PATH`; `nix-shell` / `nix develop` provide it). Fixture self-test: `./scripts/ast-grep.test.sh` | Required job `ast-grep` |
| **cargo-crap** | After LCOV, `./scripts/coverage.sh` calls `./scripts/coverage-crap.sh` (skip if `cargo-crap` missing). Dry-run: `CRAP_DRY_RUN=1 ./scripts/coverage-crap.sh`. Self-test: `./scripts/coverage-crap.test.sh` | Rides required `coverage`; report-only (no `--fail-above`) |
| **Miri** | `./scripts/miri.sh` → `cargo +nightly miri test -p rbitcoin-primitives`. Dry-run: `MIRI_DRY_RUN=1 ./scripts/miri.sh`. Self-test: `./scripts/miri.test.sh` | Nightly `miri.yml` (not required). Never `--workspace` |

Artifact silos above are unchanged: ast-grep / Miri dry-run / crap dry-run do
not write `target/`.

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
| `node_cli_and_surface_smoke` | Lifecycle/CLI | Networks, config errors, CLI flags (incl. log-level/mempool/electrum/inhibit), params, net surface |
| `three_stage_confirm_and_parent_pin_surface` | Consensus+query | Split load→scripts→write; parent pin; load ready timeout/cancel |
| `block_cache_and_mempool_hub_surface` | Net | BlockCache locator/eviction + MempoolHub accept/remove/reorg on mature chain |
| `store_error_and_corrupt_paths` | Store | Error/corrupt surfaces |
| `store_table_header_and_idx_corrupt` | Store | Table header/head corrupt open |
| `chain_connect_reorg_and_growth` | Query | Synthetic growth + disconnect (header gen roll) |
| `consensus_mature_chain_spend_and_reconstruct` | Consensus+query | **One** mature mine: spend, local prev_fk, double-spend, reopen reconstruct |
| `ibd_parallel_archive_idempotent_confirm_without_tx_head` | Query+consensus | Out-of-order archive, re-archive idempotent, head-off prevout+maturity |
| `resume_head_off_warms_cache_for_external_prev` | Query+consensus | Resume head-off: warm Class A cache fixes external-prev missing prevout |
| `consensus_rules` (test binary) | Consensus | Focused reject paths for structure/header/connect rules we own — see [`docs/consensus-tests.md`](./docs/consensus-tests.md). Hornet-mapped subset: `./scripts/test-hornet-rules.sh` |
| `core_analogs::analog_milestone_and_mempool_persist` | Consensus | Milestone skip-below/check-above, missing prevout under high milestone, mempool persist (one pad) |
| `scripthash_index_history_balance_and_reorg` | Query | Electrum index + reorg spend clear |
| `electrum_server_version_history_balance` | Electrum | One mature pad: version/history/balance/headers **and** ping/features/tx/errors |
| `two_node_header_and_block_sync` | P2P (**default + multinode CI**) | Seeder → peer 8-block IBD. **Not** re-run under `coverage.sh`. |
| `serve_after_restart_via_reconstruct` | P2P (**multinode job only**) | Cold serve via reconstruct |
| `ibd_skips_dead_peer` | P2P (**multinode job only**) | Live seeder + `127.0.0.1:1` |
| `reorg_to_longer_branch` | P2P/chain (default) | Most-work reorg (hub only — no IBD hang risk) |
| `three_node_relay_path` | P2P (**ignored**) | Hop serve — `scripts/integration.sh` |

| `ibd_two_peers` | P2P (**ignored**) | Dual-seeder 48-block IBD |
| `tip_follow_after_ibd` / `tip_follow_getheaders_*` / `ibd_to_tip_tracking_*` | P2P (**ignored**) | Tip follow / relay |
| `node_run_p2p_short` | Node (**ignored**) | Full `run_p2p` entry |
| `multinode_mesh_periodic` | P2P (**ignored**) | Larger mesh |

Removed (covered by the rows above): `confirm_cross_block_prevout_without_tx_head`,
`double_archive_keeps_tx_height_for_coinbase_maturity`, `mega_batch_duplicate_header_is_idempotent`,
`archive_local_prev_fk_and_reconstruct`.

### Integration / multi-node

Default `cargo test` runs `two_node_header_and_block_sync` (8-block). The required **multinode** job also runs reconstruct and slim dead-peer (`--ignored` filters in `ci.yml`).
Heavy topology (3-hop, 48-block, mesh, `run_p2p`) stays `#[ignore]` for `scripts/integration.sh`:

```bash
./scripts/integration.sh   # default multinode + --ignored
# or only heavy:
cargo test -p rbitcoin-test --test integration_multinode -- --ignored --nocapture
```

New features: add a high-level scenario; remove obsolete lower-level tests in the same PR.

## Core differential

Nightly (not a required PR check) `fuzz.yml` runs two cargo-fuzz targets:

| Target | What | Oracle |
|--------|------|--------|
| `block_wire` | `check_block_wire` (ASan) | none |
| `block_differential` | height-1 `ChainHub::accept_received_block` vs Core `submitblock`, **accept vs reject only** | official **v31.1** `bitcoind` tarball (`scripts/core-functional/fetch-bitcoind.sh`) |

```bash
./scripts/fuzz-run.sh                    # block_wire (ASan)
./scripts/fuzz-run.sh block_differential # fetch bitcoind, --sanitizer none
```

`block_differential` prepares every candidate on **regtest genesis** (`prev`
fixed; coinbase/version stay fuzzer-owned). After a compared accept, rbitcoin
`rewind_to_height(0)` and Core `invalidateblock` until `getblockcount==0`.
The diff hub overlays `bip34@1` only — global `ChainParams::regtest()` is
unchanged. Harness/oracle failure exits **2** (no libFuzzer crash file).
Accept/reject disagreement **panics** (reproducer). A red nightly is a
**finding** (`docs/external_findings/`), not a test to green by changing
production in the harness PR.

Default `cargo test` does **not** download Core, bind RPC, or compile `fuzz/`.
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
**`core-functional`** on harness PRs. Default `cargo test` does **not**
invoke Core’s Python suite.

```bash
python3 scripts/core-functional/check_inventory.py
./scripts/core-functional/check_inventory_test.sh
./scripts/core-functional/sync-core-fixtures.test.sh
./scripts/core-functional/run.sh.test.sh
./scripts/core-functional/run.sh --list
./scripts/core-functional/run.sh feature_help.py feature_uacomment.py
./scripts/core-functional/bitcoind.test.sh
./scripts/core-functional/create_cache.test.sh
./scripts/core-functional/check_core_release.test.sh
# cargo test stages Core JSON from the submodule:
./scripts/core-functional/init-submodule.sh
./scripts/core-functional/sync-core-fixtures.sh --check
```

## Fault injectors

Optional `integration-testing` cargo feature on crates that need crash points (e.g. mid-finalize). Off by default in release builds used for production packaging; **on** in CI test builds when needed for coverage.
