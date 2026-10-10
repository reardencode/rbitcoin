# Testing guide

## Preference order (dev-cycle aware)

| Prefer | Avoid |
|--------|--------|
| **Journey scenarios**: one setup a peer, client, or operator could use, then a **sequence** of asserts on what they would observe | Many skinny scenarios that each remine maturity and re-open the store |
| The socket, RPC, HTTP route, operator config, or scripted peer | An in-process helper the product never calls, or a thread-local the client does not share |
| A pure result only in the narrow case under [True journeys](#true-journeys) | A new pure unit a session or a reopened store can already show, or a unit whose job is a private branch |
| **One entry** per production path (the journey owns the asserts) | A `#[test]` that only calls other tests, or those tests kept as private bodies |
| Core JSON corpora for **script engine** breadth | A second parallel script suite |

**Fewer scenario functions, fewer store opens, and fewer pure results, not less coverage** — put more asserts on one story. The pure-result rule is [True journeys](#true-journeys).

### True journeys

A journey is one setup and one story. A peer, a client, or an operator does a sequence of things to that same node. Each beat asserts what they would observe: a response, a push, a reject, bytes on disk, a tip after reopen. The story should read like this node meeting the real network or a real client, and it should run as much of that path as the arc needs. One chain, one server, one session, the beats in order. That stays one `#[test]` when a later beat observes an earlier beat: a mined block, a spent coinbase, a grown chain, one mempool that is not reopened.

Distinct cases that only share a costly chain are separate `#[test]`s. Build that chain once in a `OnceLock`. Each test takes a private copy, or a fresh mempool on a query it does not modify. The fixture lives until the test binary exits. Deleting it while other tests run races the scheduler. Do not share a mutable hub, clock, or mempool across those tests.

A `#[test]` whose body only calls other tests is neither shape. If each callee still opens its own store, the suite gains one name and the same N boots. If the callees are independent, give each its own name on the shared fixture. Do not keep the old functions as private bodies the new test calls.

If no peer, client, or operator can cause the behavior, delete the behavior in the same change. A small test stays only when the function's return is the consensus or schema result and a session cannot reach it without an absurd chain: pure arithmetic, a codec with no socket, two networks that cannot be the same chain. Say which of those it is, next to the test. Store state is a surface: a tip after reopen, and bytes a later open reads back, are observed results, not pure ones. When a story shows a result a pure unit used to own, delete the pure unit in that commit. The set of pure results gets smaller over time. Do not add one because it is faster to land. A small unit is not a cheaper substitute for a journey the session can already run. A tall chain the rest of the story never builds is a named second chapter on a second setup. Two setups only when the objects cannot be the same.

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
| Delete a lower test only in a commit where a surface journey already hits those lines, so the 93% ratio holds. When no surface can hit the lines, delete the production branch and the test that only painted it in that same commit | A new small test for a path a peer, client, or operator can already hit, or a private-helper test written to turn coverage or CRAP green. Handshake **format** needles, `decode_rpc_subset`, and BIP324 encode vectors stay only until the live v2 journey observes those bytes |
| Live P2P/RPC on `cross_surface` / `integration_multinode` catalog tests | Grow `node_cli_and_surface_smoke` into a second live node |
| New P2P behavior on `p2p_timeout_*` / compact / feeler / inbound-full | Stuff more asserts onto `two_node` |

A coverage or CRAP miss is the catalog journey, or a deleted branch. The
floor and the CRAP gate are under [Coverage](#coverage). A missing promised
fact is `StoreError::Corrupt("invariant: …")`
([`docs/invariants.md`](docs/invariants.md)).

Internal witnesses still exist for store packed / v17 / fuse / scripthash
machines, unsorted pack/lag, the IBD wave fence / 8×8000, scripthash
write-behind / uring CAS, handshake format needles, `getaddr_cache_*`,
sole-preferred stall, `stamp_reject_names_*`, `multi_hop_bad_prev_*`,
the rate-limiter, netgroup, and the subsidy table. Which structure check
already runs on `submitblock` is
[`docs/consensus-tests.md`](docs/consensus-tests.md). Do not copy that
matrix here. The next change that touches one of these witnesses applies
the two rules above. It does not add another witness, and the list is not
a permanent exception.
Optional leftovers (more HTTP methods on `cross_surface`, a tiny
legacy-head `Store::open` fixture, testnet 20-minute min-diff header walk)
are not a backlog.

### Parallel cargo test (same binary)

`cargo test` / `cargo llvm-cov test` run **one process per test binary**.
Tests assert shipped behavior via session or table instance stats or on-disk
file state, not thread-local hot-path IO probes. Do not:

- Put HOLD / wait hooks in a shipped function other tests also call (`confirm_scripts_phase`).
- Assert process-global last-writer meters as the contract. Confirm / query / IBD window meters are instance-owned (`Query::confirm_stats`, take-and-reset). Pin two engines, not crate-root atomics. Store head-resolve window meters and `last_union_miss` / leftover probe diag remain process-global; use pin/layout, error strings, or a pure formatter.
- Thread-local `test_take_*` IO probes on store hot paths (example of the rule above; assert session/table instance stats or file state). Class A three-stem append is the bytes on disk after the append, not `test_take_pwrite_waves` or an SQE counter (`tls_take_max_batch_pwrite_n`).
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

Dev and test builds keep line tables on workspace crates and omit debug info
on dependencies (root `Cargo.toml` `[profile.dev]` / `[profile.test]`). Panic
backtraces still name the file and line. Release profiles are unchanged.

Humans, CI, and `rearden-grok[bot]` keep `$PWD/target/dev` (this table,
CONTRIBUTING, `shell.nix` / `flake.nix`). The nix hook sets that path when
`CARGO_TARGET_DIR` is unset. `rearden-grok[bot]` on the operator VM, one
worktree per session: [`rearden-vm-HOST.md`](rearden-vm-HOST.md). Other
agents: ignore that file.

**Default vs heavy tiers**

| Tier | Command | Contents |
|------|---------|----------|
| **Default** (CI / local full suite) | `cargo test --workspace` | Crate unit tests + scenarios + electrum + consensus_rules + live P2P (8-block `two_node`, restart reconstruct, dead-peer, hop serve, dual live seeders, post-IBD tip follow, getheaders gap fill, product `run_p2p --connect`) + hub reorgs. When agents run this suite: [`docs/how-we-plan.md`](docs/how-we-plan.md). Coverage stays a PR job. |

**tmpfs:** Linux CI (`test`, `coverage`, `mutants`) sets
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER` to
[`scripts/tmpfs-test-runner.sh`](scripts/tmpfs-test-runner.sh). Each test
binary gets a private `TMPDIR` under `/dev/shm`, removed when it exits.
Store fsyncs dominate suite wall on disk; tmpfs runs the same syscalls for
free (local workspace suite 141–299 s on disk, 79 s on tmpfs). With less than
`RBTC_TEST_TMPFS_MIN_MB` (2048) free, it keeps the caller's `TMPDIR`.
The same wrapper sets the child's address space to `RBTC_TEST_AS_MB`
(6144, 6 GiB) so a mutant that allocates without bound dies in the test
process. `RBTC_TEST_AS_MB=0` leaves the caller's limit. `windows` and
`macos` stay on real disk. Local opt-in: export the same variable with an
absolute path. Keep default-tier fixtures small: on tmpfs, test bytes are RAM.

### Suite speed budgets (default tier)

**Target:** warm default suite wall **≤3 min** (stretch **&lt;2 min**) on a Linux host comparable to CI / agent VM with a warm `target/`.

**Baseline (agent VM, warm test profile, 2026-08-07):** full `cargo test --workspace` was **~1000 s (~17 min)** before store fan-in scale fixes. After parameterizing fan-in targets and shrinking SH head default benches (`6588b62` era): `rbitcoin-store --lib` serial **~26 s** (was **~498 s**); `sorted_run` module **~1 s** (was **~191 s**).

**CI-class (2026-08-17):** required GitHub Actions `test` job (`ubuntu-latest`, `cargo test --workspace` + node/cli build) is **~85 s** (PR 85). That meets the ≤3 min budget and the **&lt;2 min** stretch on CI hardware. Do **not** re-run multi-minute full-suite timing loops as a planning spike; package walls below are still the local budget if a change feels slow.

**Agent VM (2026-10-03, warm test profile, tmpfs runner):** `cargo test --workspace` was **199.3 s** on `1d2f8896` and **117.2 s** / **118.5 s** after this cut, rebased onto current master. `end_of_ibd` went from **83.8 s** to **~23 s** (the work-fork journey was two 30 s stall waits, then **~5 s**). `cross_surface` went from **19.3 s** to **~9.5 s**. `integration_multinode` stayed **~32 s**.

| Package / binary (warm, order-of-magnitude) | Budget | Notes |
|---------------------------------------------|-------:|-------|
| `rbitcoin-store --lib` | **&lt;45 s** | Catalog-run fixtures stay tens of tiny files, not thousands |
| `rbitcoin-consensus --lib` | **&lt;30 s** | Pure-result rule: [True journeys](#true-journeys). Mainnet 866342 (~1.6 s) is the historical prevout pin — one zstd decode, overweight on a clone. |
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

**P2P walls:** `two_node_header_and_block_sync`, `three_node_relay_path`, `ibd_two_peers`, `tip_follow_after_ibd`, `tip_follow_getheaders_catches_missed_blocks`, and `node_run_p2p_short` 60s wall (180s under `coverage.sh` / llvm-cov). `serve_after_restart_via_reconstruct` and `end_of_ibd_follow` 90s wall (180s under llvm-cov). `end_of_ibd_sh_interrupt` 120s wall (240s under llvm-cov). `end_of_ibd_work_fork` 30s wall (90s under llvm-cov). A warm run is about 5s once an unknown-block getdata is answered `notfound`; the old 150s cap hid two 30s stall waits. The peer is not banned for that hash. `p2p_compact_hb_getblocktxn_and_orphan` 30s wall (90s under llvm-cov). `p2p_timeout_getaddr_and_keepalive_ping`, `p2p_feeler_completes_and_closes`, and `p2p_inbound_full_rejects_extra` 20s wall. Live `P2PNode` tests in one process may overlap. Each script stage registers its thread; hub-only reorgs do not run a `P2PNode`.

**Speed / reliability (default suite):** prefer `pad_empty_from` / `build_mature_regtest_with_spend` **once per journey** (tx_relay live hub, Electrum protocol, core_analogs assumevalid+mempool) over remine pads; SH run-builder sleeps are 1 ms under `cfg(test)` (40 ms in production). `pin_compose_multi_pack_timed` keeps functional + layout/covered short-circuit gates (multi-ms floor); sticky vs cold assemble is log-only (not a hard timing assert). Schema-13 wire rebuild must stamp create identity from `txid.body` — zero batch identity is treated as missing (regression covered by the spend reconstruct in `consensus_mature_chain_spend_reconstruct_and_scripthash` + multi-vout confirm scenarios). Coverage vs speed: prefer **one** scenario at the real entry over N micro-opens that only paint lines; when adding coverage for reduce/materialize, use a **tiny** target, not production stream depth.

### Test size contract

Size by resource (Small/Medium/Large) is defined in [`docs/test-size.md`](docs/test-size.md) — that file owns the contract by what the test does, not which helper it calls. `TESTING.md` owns current testing policy and budgets; [`docs/test-size.md`](docs/test-size.md) owns the Small/Medium/Large classification contract. Small = pure/in-process no sleep/fs/net, Medium = repository-local integration that touches filesystem (TempDir/TestDatadir with bounded teardown) or localhost `:0` only — examples: `tiny_store`/`tiny_query`/`TestDatadir`, Large = tests requiring external processes, external networks/overlays, or Core differential; normally outside fast default feedback (e.g. `core-functional`, `overlay-functional`).


## Coverage

| Metric | Required |
|--------|----------|
| Line coverage | Production LCOV `LH`/`LF` from `./scripts/coverage.sh` **≥ 93%** (unrounded `LH*100 >= LF*93`). No never-falls ratchet — llvm-cov hit counts jitter tens of lines on the same tree. |
| Branch coverage | **≥ 90%** when measured on nightly with `--branch`; on stable, region-partial lines in the text report may remain — still close large gaps via scenarios |

Test modules (`*_tests.rs`, `/tests/`, `testutil.rs`, crate `rbitcoin-test`)
are omitted from `LH`/`LF`. Those tests still run. A journey that executes
a production line already counts that line, so a second in-crate `#[test]`
is not required to make LCOV see it. `#[cfg(test)]` arms inside production
files still count. llvm-cov hit counts jitter tens of lines on the same
tree; the floor is the gate, not a never-falls ratchet vs master.

The README badge and rbitcoin.org figure are the last **green `master`**
`coverage` job (`badges` branch `coverage.json`, Shields endpoint). The
same file lists each production crate (`crates`: `name`, `lh`, `lf`,
`pct`). Those rows are the filtered LCOV grouped by `crates/<name>/`, and
they must sum to the badge `lh`/`lf`. A red PR does not publish.
`coverage-history.jsonl` remains a log of the workspace total, not a gate.

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
- `rbitcoin-rpc`, `rbitcoin-cli`, `rbitcoin-node`, `rbitcoin-sv2`

**Excluded by default:** third-party crates, `src/main.rs` trampolines, test
modules (`*_tests.rs`, `tests.rs`, crate `/tests/`, `testutil.rs`,
`tests_verify.rs`), crate `rbitcoin-test`, and `rbitcoin-bench` (optional
host client tool; not a coverage gate). The excluded tests still run.
Dependencies are not attributed to us. `regtest_rpc.rs` / `regtest_pad.rs`
stay in the denominator. A journey which executes a production line already
counts that line.

### Philosophy

1. Cover code with a [true journey](#true-journeys): one setup, one story,
   asserts on what a peer, client, or operator would observe.
2. Prefer extending that journey over a new small test. A caller of other
   tests is not a journey.
3. If a branch is unreachable from any real session, **delete it** or hit it
   through a **shipped** config / error / CLI path. Do not add a `pub` or
   `*_for_test` injector so a unit can see it
   ([`CONTRIBUTING.md`](./CONTRIBUTING.md) principle 11).
4. A small unit only for the narrow case in [True journeys](#true-journeys).
   Drive the shipped function, not a `#[cfg(test)]` wrapper around it.

### Closing a red region

1. Open the HTML/LCOV report from `./scripts/coverage.sh`.
2. For each missed region, decide which case it is.
3. A session can cause it: extend the [catalog](#scenario-catalog) journey
   that already has that peer, client, or datadir. Re-run until the lines
   are hit.
4. A session cannot cause it: delete the branch. Re-run. The ratio rises or
   holds because `LF` fell.
5. The narrow pure-result case in [True journeys](#true-journeys): one unit
   on that shipped function, reason in the test. A reopened store that can
   show the result is case 3.
6. Stop when the ratio is **≥ 93%**. Do not add a private-helper test to
   get there.

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
| **cargo-crap** | After LCOV, `./scripts/coverage.sh` calls `./scripts/coverage-crap.sh` (skip if `cargo-crap` missing). `--fail-above --threshold 30`; `.cargo-crap.toml` allowlists today's production CRAP>30 functions (remove a name when it scores ≤30). A new failure is answered by deleting branches until one path remains, or by extending the catalog journey that owns the feature so those branches run. Allowlist additions follow [`docs/code-shape.md`](docs/code-shape.md): do not split a Core-faithful opcode loop or an io_uring machine to beat a score. A test whose only effect is to change the CRAP input is not the fix. Dry-run: `CRAP_DRY_RUN=1 ./scripts/coverage-crap.sh`. Self-test: `./scripts/coverage-crap.test.sh` | Rides required `coverage`. No `--fail-regression` (llvm-cov coverage % jitters per function) |
| **coverage ignore / badge** | `./scripts/coverage.test.sh` (filename ignore, Tier A IBD not skipped, 93% floor, Shields JSON). Publish dry-run: `BADGE_DRY_RUN=1 ./scripts/publish-coverage-badge.sh` | `test` job self-test; `coverage` job writes `coverage/badge.json` and, on green `master`, pushes `badges/coverage.json` |
| **Miri** | `./scripts/miri.sh` → `cargo +nightly miri test -p rbitcoin-primitives`. Dry-run: `MIRI_DRY_RUN=1 ./scripts/miri.sh`. Self-test: `./scripts/miri.test.sh` | Nightly `miri.yml` (not required). Never `--workspace` |
| **cargo-mutants** | Nightly, not a PR check. `./scripts/mutants-nightly.sh` lists `--workspace` mutants, runs new diff lines first, then walks a cursor through the rest. `rbitcoin-bench` is excluded (`.cargo/mutants.toml` and `--exclude` on both invocations; CLI replaces the config glob). `#[mutants::skip]` on an expression is the won't-test list; those mutants are omitted, not `MISSED`. Each mutant uses `--test-workspace=true` so a higher journey counts, `--baseline=skip`, `-j 1`, test binaries on tmpfs (runner above; the mutants copy stays on disk), 20 minute mutant timeout, 8 hour budget across two jobs of 4 hours (a hosted job dies at 6). While both the new queue and the backlog have mutants, a job starts new batches only until half of its own budget has elapsed, then walks the backlog. Time the new queue does not use goes to the backlog. The second job resumes the cursor and does not open another new window after that half is used. An empty side does not block the other. Cursor and `MISSED` lines are pushed to the `mutants-state` branch; that branch wins over the `mutants-cursor` artifact, which is still uploaded and expires after 14 days. Resume continues at the saved backlog mutant name, or at the saved index modulo the current backlog length when that name is gone. A failed push fails the run. `MISSED` is uploaded and does not fail the run. Each invocation passes `--file` for one source file and at most `MUTANTS_BATCH` queued names from that file (default 200). cargo-mutants 27.1.0 emits `..` struct-field deletes without applying `--re`; one file keeps that repeat inside the file under test instead of retesting every such delete in the workspace on every batch. The miss list is `missed.txt` on the `mutants-state` branch. | `mutants.yml` daily `47 0 * * *` (17:47 Pacific during PDT) and `workflow_dispatch`. Each job timeout 270 minutes. |

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

A cell that names a crate-local test describes the witness that exists today. It is not an instruction to keep that witness. On the next change to that behavior, move any unique assert onto the surface journey and delete the lower test once `./scripts/coverage.sh` still passes. If the surface journey cannot reach the lines, delete the production branch in that change.

| ID | Layer | Description |
|----|-------|-------------|
| `overlay_config` | Node CLI + net | In-process onion / I2P / cjdns matrix: `onlynet`, proxy, SAM, reachable, accept-incoming, one parse or learn check per network, `--only-net` dial candidates, no cjdns dial until reachable, and one `peers` file round trip for all three. Live Tor, i2pd, and cjdns stay in overlay-functional. |
| `node_cli_and_surface_smoke` | Lifecycle/CLI | Networks, `run_node`, config errors, CLI flags (incl. `--conf`, `--peer-timeout=0` refuse / `=1` smoke, unknown conf key ignored, `min_relay_tx_fee=-1` and `network=nope` conf fail), dropped Core `--rpcuser`/`--rpcpassword`/`--rpcport`/`--rpcconnect`/`-rpcport` refuse, help/version (`rbitcoin-cli` help and version do not dial). Usage errors exit 2 before a datadir is touched: unknown flags, missing or bad values, and every concatenated, one-dash, or Core spelling of a native kebab flag. A missing conf, a bad line, a bad `log_level`, conf `rpcuser`/`rpcpassword`, and `max_outbound=0` exit 2 and open no store. Non-hex `--min-chain-work`, a signet challenge or block time off a custom signet, and `--sp-tweaks` with `--prune-seqsigwit` exit 1. One smoke takes the native flag set together; bare network conf lines parse and CLI `--datadir` wins over conf `datadir`; `--datadir-cold` puts seqsigwit, txstat, and input on the cold store; a custom signet smokes. Signet: genesis header plus height-1 BIP325 connect. The assembled `NodeConfig` values and help text no surface reports are the node-crate `operator_conf_and_argv` (`--bytes-per-sigop`, `--block-reserved-sigops`, conf `sp_tweaks` together with `prune_seqsigwit`, conf `sp_tweaks=1` at the default dust and `sp_tweaks_dust` of 546, 0, or a non-numeric value, and Electrum or Esplora with and without `--sh-index` plus `--sh-index` alone) |
| `three_stage_confirm_and_parent_pin_surface` | Consensus+query | Split load→scripts→write of pad+spend from genesis (header-plan BIP68 MTP); parent pin; load ready timeout/cancel; instance-owned `last_write` / `last_pin` / `take_window` meters (a second engine's window stays empty); txstat fee / size / weight from the load assemble, restamp and its refuses; same-run create then spend; 546-shaped 2-vout merge + same-block chain + cross-batch head resolve; an already-at-height retry finishes a spend annotate |
| `mempool_under_pressure` | Mempool + RPC (crate) | One entry in `orphanage`, `accept`, `tx_relay`, and `methods_tests`: orphan reserve and expiry, sigops before script, rolling fee floor, cluster cap, parked min-relay orphan, and the package RPC rejects (unsorted, missing inputs, conflict, min-relay parent with maxfeerate child). |
| `sigop_adjusted_size_budget_and_reopen` | Mempool (crate) | One empty `ActiveMempool`: sigop-adjusted vsize (boundary, min relay, full-pool floor, RBF, package and 1p1c), the raw-weight cluster limit, the shared block sigop budget, and sigop cost plus bytes-per-sigop and reserve overlays across reopen and compact. Each beat restores an empty pool. |
| `mempool_accept_life` | Mempool (crate) | One `ActiveMempool` against one chain view that blocks move. Orphan parks and re-announce, dry run not parked, parent promotes the child; missing vout, invalid parent, and block-spent coin reject without parking. Full RBF and no return, the staged commit failing closed on a conflict that landed after prepare, pure RBFR unpinning a child, replaced txs out of the cluster count; a ~30 kvB single tx under the vsize cap and the ten-way merge over it. Package order, CPFP, child fail restoring the RBF victim. A block evicts double-spent txs with descendants; a reorg readmits the parent and evicts the BIP68 and coinbase-maturity spends. Raised `-minrelaytxfee`: 1p1c needs a paying child, an unrelated tx does not ride the waiver, child fail takes a promoted spender down. Full pool: a protected lone worst chunk evicts nothing and leaves the floor, the next arrival evicts the CPFP pair together. |
| `rpc_regtest_from_genesis` | RPC (crate) | One regtest hub from genesis through the first submits. At genesis: `size_on_disk` is the store walk, IBD comes from the hub and not the stale atomic, buried deployments, `generateblock submit=false` connects nothing, and the priority, mocktime, mockscheduler, submitheader decode, and not-found refuses. The first block pays a p2wpkh address: display-order hashes and txids, raw `getblock` and header, a headers-only child at progress 0.5. Mocktime stamps `generate` and makes a far block `time-too-new`. Coinbase-only blocks: verbosity 1 without a seqsigwit zip, `getnetworkhashps` over chainwork, the empty template and proposal needles, a `time-too-old` header, an invalid parent body that marks its branch, and the structure rejects named on this hub in [`docs/consensus-tests.md`](docs/consensus-tests.md) (S1–S3, S6's RPC `bad-txnmrklroot`, S8's missing and mismatched witness commitment, S9–S11, S13, S17, S18), including S1–S3 on an equal-work sibling. A resubmit of a rejected sibling is `duplicate-invalid`; a valid sibling stays `inconclusive`. |
| `rpc_regtest_mature_chain_ops` | RPC (crate) | One regtest hub mined to height 130. The `nblocks=0` window, GBT fee and sigops (bare, P2SH, P2WSH), sigop-adjusted mempool vsize (`getmempoolentry`, package retry, `blockmintxfee`; weight and the Esplora/Electrum histogram stay raw) and a big-sigops cluster under the block budget, a non-DER spend with Core `reject-details`, deprioritise, `generateblock` reject shapes then parent-first mining, a premature coinbase, proposal spend/value/final needles against the chain, a repeated txid and a second coinbase, default and explicit `maxfeerate`, `testmempoolaccept` known vs mempool vs archived, invalidate and reconsider, and a parked sibling (held `getblock`, `preciousblock`). Last, a mainnet view of the same hub refuses the regtest-only methods and still takes `submitblock`. |
| `block_cache_and_mempool_hub_surface` | Net | BlockCache locator/eviction + MempoolHub accept/remove/reorg on mature chain. Eviction uses body depth 16. |
| `store_error_and_corrupt_paths` | Store | Error/corrupt surfaces |
| `store_table_header_and_idx_corrupt` | Store | Table header/head corrupt open |
| `pruned_seqsigwit_life` | Query + RPC (crate) | One `query_tests` entry for the prune watermark, RAM window, reopen, refuse-disable, reorg-through-pruneheight, and corrupt spill. One `methods_tests` entry for pruned `getblock` and `getblockstats` with and without txstat. |
| `chain_view_pin_asof_reorg` | Query (crate) | One `query_tests` pad: no view on an empty store, tip and buried pins across extension, as-of scripthash and outpoint answers around a spend, a same-height replace killing the tip pin and the join slot, a stale write-behind job not seeding the replaced branch, the pinned-run retry and its moved-view error, and disconnect to empty. Electrum and Esplora as-of are `electrum_and_esplora_asof_hides_later_spend` |
| `resume_most_work_header_path` | Query (crate) | One `query_tests` pad with a confirmed loser tip: a heavier header-only sibling beats the loser's body, `exclude` falls back, the ancestor walk takes the heaviest fork under the grandparent once the nearer sibling is excluded, a 12k-header band ahead of the tip does not overflow the stack, and a `prev_fk` cycle ends |
| `sp_tweaks_confirm_life` | Consensus (crate) | One `silent_payments` chain through the index builder: two P2WPKH→P2TR spends around a fat ineligible spend; the naive walk, the window reader (parent inside or outside), the engine on the rebuilt wire tx, and the served index agree; the thin serve spans the middle txout but not its seqsigwit; two heights sealed in one window; range limits, the hole, singles vs range, and cut-through down to an all-spent tx. BIP352 vectors are the `silent_payments` consensus results |
| `sh_history_caps` | Query (crate) | One `query_tests` scripthash with more creates than `--max-sh-creates`: the create count includes the pending write-behind; the full join and chain stats refuse; ascending, cursor, and newest-first (a spend of the oldest create) pages that close before the cap are still served; a separate unspent script confirms a full page past the cursor stops before loading later creates |
| `chain_connect_reorg_and_growth` | Query | Synthetic growth; height index full rebuild; disconnect logs `DisconnectTip` at warn and rewinds IBD marks and write locs; disconnect to empty (then refuses); same-height replace; reconnect and idempotent tip re-confirm. Corrupt merkle in the last 6 confirmed heights: `Query::open` shrinks (`VERIFY_TIP_BLOCKS=6`). A 257-create megakey block unlinks from SH and truncates tweaks on disconnect |
| `consensus_mature_chain_spend_reconstruct_and_scripthash` | Consensus+query | **One** mature mine: spend, local prev_fk, double-spend (accept, Class A then accept, and `confirm_wire_run`), reopen reconstruct (`witness_block_bytes` == serialize), SH history windows, newest-first page, net-value summary, chain stats, join slot (dropped on tip change), listunspent without spent-create identity, spend-index-off fallback, touched-at-height; merkle proof, archived span reconstruct (P2TR / P2A sibling), confirm-run refuses, clear archived body. After disconnect, a queued child of the abandoned spend is neither a TipOnly hit nor a leftover fill, `resume_work_path_after_tip` still sees Class A bodies, and reconnecting them extends the height index. Packed create_fk layout stays `input_encode_create_fk_not_prev_txid` |
| `confirm_load_ahead_of_write_does_not_badprev` | Consensus+query | Pipelined load 11..=20 while 1..=10 is still unwritten; then load 21..=32 after tip-GC (store MTP for confirmed parents) |
| `wire_prep_parent_layout_and_load_ahead` | Consensus+query | One mature pad: load-ahead fill of parent denserels after commit (plan stamps the head parent's fk, spend edges, same-batch overlay; write annotates the spent slot), already-archived plan=None spend annotate, cold Class A denserels for sequential spends of one create |
| `resume_tx_head_resolves_external_prev` | Query+consensus | Reopen `tx.head` create_fk spend: the parent TipOnly-heads through the leftover probe and through two BQ waves (skeleton needs no probe); once archived, lookup stamps plan=None with the block's create pairs and refuses a tampered tx list; leftover TipOnly stamp matches the one connected fk; RAM leftover map clobber stays one slot |
| `buried_rules_and_a_lying_header_path` | Consensus (crate) | Regtest and signet BIP30 overwrite, mainnet BIP30 only when the BIP34 ancestor matches, and the anchored milestone, in `structure_rule_tests`. The heavier contiguous header-work path is the same name in `query_tests`. A block over the sigop cap or the tx-count cap is rejected. |
| `consensus_rules` (test binary) | Consensus | Focused reject paths for structure/header/connect rules we own — see [`docs/consensus-tests.md`](./docs/consensus-tests.md). Combined `header_and_spending_boundaries` includes H1/H2/H4/H5/H6, BIP68 height + time, and subsidy interval=2 overlay (50 BTC at interval−1, 25 BTC at interval, `subsidy+1` rejects). Same-block double spend, same-block coinbase spend, child-before-parent, `in < out`, immature coinbase, and 4-deep immature are beats on `header_and_spending_boundaries`. Coinbase excess is the store-less subsidy-table result. H8 at exact +2h accepts, and one second later rejects. Hornet-mapped subset: `./scripts/test-hornet-rules.sh` |
| `core_analogs::analog_milestone_and_mempool_persist` | Consensus | Milestone skip-below/check-above, missing prevout under high milestone, mempool persist (one pad). Restart leftover pool through catch-up then tip-mode relay-on: same-txid confirmed and input-conflict gone, child of a now-confirmed parent kept, DEAD marks durable without `flush`. Leftover `slots.tmp` after mid-compact: `MempoolHub` open finishes the rename and live count matches. A body truncated back to the previous prefix under later slots keeps the in-range tx and drops the tail (`fee_history` stays in `mempool/`). New body with the previous slots reopens the previous live set. An in-range payload whose txid does not match the slot is moved under `mempool/torn-<unix>/` with `slots.tmp` and `tx.body.tmp`, and that open accepts a new tx. A file path instead of the mempool directory still fails the open. Fee survives flush and reopen |
| `core_analogs::analog_reconstruct_after_lost_head` | Store+query | Wipe `tx.head/`, reopen, reconstruct height 1 and txid probe. Crash-open clamps unsealed `confirmed[]` (Electrum/RPC `chain_tip`). Leftover fuse8 v1 refuses at `Query::open` (Class A kept). Truncated MPHF and empty `tx.head/meta` rebuild from Class A |
| `core_analogs::analog_block_filters_from_class_a` | Store+query | Coinbase-only, a spend, and a block with duplicate scripts, OP_RETURN, and a segwit output; `--prune-seqsigwit` passes them (reconstruct refuses). `rbtc-idx-wb` then materializes every height from Class A through `read_index_window`, stopped after its first commit and restarted: each mined block's stored filter equals rust-bitcoin `new_script_filter` and the header chain is unbroken. The completion-session window reader (`read_index_window`, windows of 37 heights across the prune line) builds the same filter at every height. A tip reorg while the index is off: reopening with it on drops the stale-branch slot (`header_fk` ≠ `confirmed[h]`) and the rebuilt filter matches the new block (`rpc_getblockfilter.py`, `feature_blockfilterindex_prune.py`) |
| `unified_wire_pipeline_multi_block_to_tip` | Consensus+query | Class A archived ahead of tip (tip stays, a second archive does not re-append, size/weight from txstat with a zero-row rebuild) then `confirm_wire_run` (no re-append + re-entry); empty run, empty or gapped load, and a body-less header all refuse without advancing tip; then heights 2..=4 unified load/scripts/write, and a BQ-queued coinbase-only block through the split stages |
| `direct_indexes_then_sh_bulk_at_tip` | Query | Direct IBD fills `tx.head` and collects no SH (no run worker, no write-behind); SH bulk at tip, idempotent on repeat and on Direct re-entry; Tip mode enqueues write-behind only with shindex on; a tip confirm leaves the SH watermark to the write-behind; `include_hwm` covers the tip without a SEAL file; wipe SH shards, reopen (leftover catch-up artifacts removed), history still works, including after an unsorted pack and a lagging include |
| `electrum_server_version_history_balance` | Electrum | One mature pad: version (`CARGO_PKG_VERSION`)/history/balance/headers, ping/features (`protocol_min` / `asof_protocol` / `server_version`)/tx/errors, confirmed history omits `fee`, scripthash subscribe notify, skip restatus when a new block misses the SH. TCP `get_history` `from_height` at create / exclusive `to_height` hides spend / `to_height=-1` open; subscribe status stays full; invalid `from_height` type. `get_merkle` wrong height for a known txid. Verbose `transaction.get` stamps `time`/`blocktime`/`confirmations`/`blockhash` and coinbase `vin`/`vout`. `id_from_pos` string vs `merkle=true` `{tx_hash, merkle}`; pos OOB errors. Line at `max_request_bytes` ignored; one past is JSON-RPC `-32600` `request line too long`. Electrum **1.6**: `mempool.get_info`, `blockchain.outpoint.*` (unsubscribe miss is `false`; tip notify while subscribed; missing vout errors), Frigate `silentpayments.subscribe` / unsubscribe / second unsubscribe / start past tip clamps / bad-params error, `block.headers` as a list, `broadcast_package` without a hub errors. With no hub, `estimatefee` is `-1.0`, the histogram is empty, and Cake `tweaks.subscribe [0,1,false]` answers |
| `electrum_scripthash_sub_cap_unsubscribe_frees_slot` | Electrum | Per-connection scripthash cap + unsubscribe frees a slot. Outpoint subscriptions use that same numeric cap on their own set (resubscribe does not consume another slot; a third distinct outpoint is `max 2` until unsubscribe). |
| `electrum_leftover_mempool_does_not_double_count` | Electrum | Relay-off leftover is confirmed, not a second mempool UTXO. With hub attached, `transaction.broadcast` of non-hex and consensus-invalid rejects (not hang / not admit). Same pad: confirmed `outpoint.get_status` (tip height, no `spending_txid`); `broadcast_package` invalid hex / reject / verbose success / non-verbose `"success"`; mempool-spent outpoint is `height=0` with `spending_txid`; mempool verbose `transaction.get` is `confirmations=0` with no `time`/`blocktime`/`blockhash` |
| `electrum_and_esplora_asof_hides_later_spend` | Electrum + Esplora | One pad: TCP `1.4.2-asof` plus HTTP `?asof=` hide a later spend; unknown asof errors; `GET /tx` `v0_p2wpkh` vout. SH-off tip+1: asof at visible SH watermark accepts, asof of the confirmed hash ahead of SH is `asof not on chain` / HTTP 404. Same-height A-B-A restatuses subscribe (confirming blockhash); `asof:` of the loser hash does not retry onto the sibling. Disconnect spend: history/utxo show the create again; live Esplora `/utxo` stamps the create hash (not the fork); loser `?asof=` 404 with no tip header. HTTP `503` `chain view moved` (no tip header) is `http_503_chain_view_moved_omits_tip_header` |
| `electrum_empty_chain_headers_subscribe_and_empty_scripthash` | Electrum | Empty store: `headers.subscribe` errors; scripthash history/balance/unspent/mempool empty |
| `electrum_tweaks_subscribe_streams_then_done` | Electrum | Cake `tweaks.subscribe`: one-height result, per-height notifies, `done`, and BIP352 hash-bind on a P2WPKH→P2TR spend. A zero-chunk subscribe returns wave 0 and then `done` while heights remain, and a resubscribe continues. Pre-taproot empty heights collapse into one notify |
| `electrum_max_connections_rejects_extra_client` | Electrum | TCP cap drops the extra client |
| `electrum_idle_timeout_disconnects_quiet_client` | Electrum | Idle timeout closes a quiet socket |
| `esplora_broadcast_visible_in_rpc_and_electrum` | Node + Electrum + Esplora + RPC | One `run_p2p` datadir: HTTP `sendrawtransaction` / `testmempoolaccept` (allowed, missing-or-spent, exact 100 sat/kvB min-relay accept + one-sat-under reject, RBF one-sat-short incremental reject + exact incremental accept); Esplora `POST /tx` parent and mempool child appear in `getrawmempool` and Electrum mempool/history (`fee` on unconfirmed, including child `height = -1`); Electrum `listunspent` of that child is `height=-1` and the parent UTXO drops; process `gettxout` / `getchaintips`; Esplora `POST /txs/package` 1p1c (including parent-alone below min-relay + paying child), 25-tx accept, 26-tx and over-weight `package too large`; serving-only `submitpackage` refuses (relay off); live `GET /mempool` / `/mempool/txids` / `/mempool/recent` / `/fee-estimates` answers 503 while flow is cold and the chain holds too little fee history (a thin live pool alone sets no rate); process `getmempoolancestors` / descendants / cluster / `gettxspendingprevout` / feerate diagram / verbose `getrawmempool` on that 1p1c; `waitforblockheight` timeout=0 while behind returns the live tip; GBT stale `longpollid` is immediate; current id / `waitfornewblock` / `waitforblockheight` wake on the pad `generate`; `getblockhash` tip ok / tip+1 `-8`; unknown `getblock` `-5`; verbosity 0 hex and 2 vin/vout; `GET /blocks` 10 newest, `/blocks/0` and `/blocks/:tip` (start past tip clamps); `/block/:hash/txs/:start` last page shorter than 25, one-past last page 404, unknown hash 404; `/block/:hash/txids` + coinbase merkle-proof + unspent `outspend/0`; `/tx/:id/outspends`; `/block` JSON/raw/status/`txid/0` (OOB 404); `/tx/:id/raw` vs hex; merkleblock-proof; `/block-height` (missing 404); `/block/:hash/header` 160 hex; `/tx/:id/status` + full JSON (`unknown` OP_TRUE type, coinbase vin) and missing-tx 404s; OP_TRUE scripthash info/summary/utxo/`txs/chain` cursor and combined `/txs`. No-hub: mempool and fee routes, and `POST /tx` 503. Header bytes match the wire header. `tx_status_json` matches the status route. Esplora `/tx/:id/status` confirms the package parent on generate; `generate` includes those txs (parent before child) then leaves IBD (relay on); `scantxoutset` drops the spent coinbase and still sees a non-coinbase unspent; `submitpackage` maxfeerate reject, 1p1c success, already-in-mempool continue, below-min-relay parent + paying child success, 26-tx / over-weight `package too large`; immature coinbase sendraw rejects. Package JSON errors. `testmempoolaccept` dry-run reports the orphan count. `gettxout` with `include_mempool`, on a disconnected tip, and on a leftover. `generate` selects the chained mempool parent first. A `submitpackage` child failure keeps the parent. Maxburn `submitpackage` rejects. Waiters return when the node stops. Unix `--rpc-socket` (mode 0660, no datadir `rpc.sock`) `getblockcount` without Authorization; TCP `GET`/`POST /internal/mempool/txs`; `GET /internal/block/:hash/txs` full list vs public 25/page; `POST /internal/txs/outspends/by-txid` same-length unknown `[]` slot; `GET /address-prefix/bc1` **404**; unauthenticated Core REST on the RPC listener (`chaininfo`, block hash/headers/block/tx, mempool info/contents, `getutxos`, `deploymentinfo`, basic `blockfilter` bin/hex/json) and `getblockfilter` with `--block-filter-index` |
| `fee_history_backfills_from_the_chain_when_relay_starts` | Node + RPC | `run_p2p` on a mature regtest datadir, started twice; `generate` leaves IBD and turns relay on; the preload writes the fee history file and the restart extends it; with flow cold and too little history, `estimatesmartfee` answers Core's insufficient-data shape. Rates from a ready history are the hub's `far_horizon_follows_block_history_not_pool_tail`; the success object is `smart_fee_json` |
| `node_listen_and_exit` | Node + Electrum + Esplora + RPC | One `run_p2p` datadir, restarted with its one `--connect` refusing (a pinned connect at genesis still enters tip mode): a taken `--health-listen` port stops the start before the store opens; a junk `peers` file and a missing `--asmap` start an empty book and exit, and the saved book records the refused connect; the next start loads that book and a valid `ip_asn.dat`, and Esplora, Electrum, and RPC answer at genesis until `stop`. On that start `/healthz` is 200 and `/progress` is 200 JSON while genesis `/readyz` is initial block download and `/metrics` reports the same; `generate` makes `/readyz` 200 and the scrape ready at height 1. An Electrum port and an RPC port another process holds warn, `/readyz` names both, and `/metrics` is absent without `--metrics`. Without `--connect` and with seeds on, regtest resolves none and the node exits short of tip mode; after a `--prune-seqsigwit` start, an unpruned start refuses. Live peers are `node_run_p2p_short`. The `/readyz` phase, lag, and tip-age table stays `readiness_reports_the_first_failing_gate`. A timed-out probe keeping its permit, the full-gate 503, and the routes answering again are `health_gate_caps` |
| `tor_control_onion_lifecycle` | Node + RPC | One `run_p2p` datadir against a fake Tor control port and SAM bridge (live Tor and i2pd are overlay-functional). A cookie from another Tor (SAFECOOKIE server hash mismatch), a 2-byte cookie, and a Tor that offers only plain COOKIE each refuse the start, and none sends `AUTHENTICATE`. Password auth with `--listen-onion`, `--i2p-accept-incoming`, Electrum, and Esplora: `ADD_ONION NEW` per service with the P2P virtual port on the loopback bind, each key saved `0600` under `onion/`, each SAM destination under `i2p/`, `STREAM FORWARD` to each port, and `getnetworkinfo.localaddresses` lists the three onions and the I2P address. A SAFECOOKIE restart reuses every saved key and destination |
| `enter_tip_mode_indexes` | Node + Electrum + RPC | One `run_p2p` datadir restarted with `--sh-index` off, on, off, on. Off with no index yet: RPC, tip follow, and Electrum listen, `blockchain.scripthash.get_history` fails closed, and `generateblock` mines three OP_TRUE coinbases. First start on: the index is collected from Class A before history answers, and the OP_TRUE history has three rows. Off again: Electrum still listens and the leftover watermark keeps those three history rows. On after a crash that left a collect run and a lagging include high-water mark: the durable index resumes under write-behind, so the run is discarded (not merged) and history answers, and the next block lands in history |
| `two_node_header_and_block_sync` | P2P (**default**) | Seeder → peer genesis+1 IBD; peer `last_write` meter. Empty `headers` lag keep-sync is `apply_peer_event_body_and_control_surface`; drained-path EOF `headers_done` is `apply_peer_event_block_framed_bq_horizon_and_headers_done`. 8-block dual-seeder stays `ibd_two_peers` |
| `p2p_timeout_getaddr_and_keepalive_ping` | P2P (**default**) | One pad: v1-magic inbound drops at `peertimeout=1`, obsolete VERSION and pre-verack ping close the peer, full-relay GetAddr cache 1000, headers-sync stall replace, self-connect refuses, a completed handshake outlives `peertimeout=1`, AddrFetch `getaddr`/`addrv2` (no `getheaders`) stays for one addr, times out at 300s, and completes on a longer list, one keepalive ping/pong. A sole preferred peer that stalls headers is kept, and a new `getheaders` can send (`noban@127.0.0.1`, hub `--trusted`). |
| `hostile_peer_session` | P2P (**default**, crate) | One lib entry in `peer::tests`, one in `chain::tests`, one in `assign::tests`. Header cap, send budget, one-shot `getaddr`, addr relay to one or two peers, zero-prev not held, witness padding and time-too-new not cached invalid. A getdata past the byte budget pauses and is served once the writer drains (`getdata_over_send_budget_waits_for_writer`). `tip_script_pres_skips_only_matching_wtxid` is the mempool-graph result, not this peer session. |
| `peer_blocksonly_and_orphan_tx` | P2P (**default**, crate) | One hub, relay off and then on. Blocks-only: a tx or wtx inv from an ordinary peer disconnects, a sendraw INVs once it is unbroadcast (never to block-relay) and serves, a `relay@` whitelisted peer's tx is kept and INV'd to the other inbound, and a type-0 getdata is ignored while the tip block still serves. A block confirms those txs and relay-on purges them. Then forced INVs skip block-relay, seen, feefilter, and isolated local-origin peers. Inbound waits 30s even for unbroadcast, never gets a tx older than its connection, and idle ticks do not clone or rescan. GetData serves only an announced or reorged-back tx, and a sendraw after a +300s jump neither INVs nor serves. An orphan parks on a tokio worker without a reject log and asks only the still-missing parent after NONPREF+TXID. |
| `stored_header_resends_walk_once` | IBD (crate) | One 240-header genesis chain. A re-sent stored run walks no ancestors, an unmapped stored run walks once, an unknown parent is not stored, a rejected tail keeps the stored prefix under a lowered walk cap, and a run past that cap walks once and is still accepted. |
| `two_peers_reserve_the_header_walk` | IBD (crate) | One hub. The lowest time-to-first-byte peer takes headers and the other takes blocks; a short miss moves the reservation without disconnecting; a heavier inv takes it and a lighter inv restores it; refill under the low-water mark stays on the reserved peer. A second chapter, because that lighter challenger is retired: a quiet header peer is skipped, asked again, then disconnected. A third, because that survivor already missed once: the only header peer is disconnected after two misses. |
| `a_seeded_header_walk_stores_drains_and_refills` | IBD (crate) | One walk from the stored tip. The first locator and the status line start there; the first batch is a checkpoint and the empty queue refills from that tip; with room in the queue the reserved peer keeps walking and a second peer is not asked; an empty queue still checkpoints; a refill stores without moving the walk; an empty queue refills from the confirmed tip; a full batch stays stored while a walk ask inside its window is not stirred. |
| `a_heavier_header_chain_keeps_its_context` | IBD (crate) | One hub: a challenger keeps median time while the tip is genesis (invalid at the median, valid one second later); that hub then confirms a stale ancestor, a heavier chain from below it replaces the candidate and drops its script skip, and a rewind uses the confirmed base work and height. Retarget is a second hub (period length is not regtest difficulty): a heavier fork across a gap retarget is adopted, rewind restores difficulty before the next retarget, and a challenger keeps its retarget snapshot. Those three checkpoint layouts cannot be one candidate. |
| `analog_selector_keeps_each_boundary_rate` | Mempool (crate) | One selector table: the exact band edge, absolute log distance, the requested quantile, and the two-hundredth nearest window each keep their own rate. |
| `fee_history_gaps_cache_and_reorg_share_one_history` | IBD (crate) | One history: heights without a hurdle are not observations, rates stay cached until a new height, only the newest hashes are kept, and a reorg drops those above. The RPC backfill stays `fee_history_backfills_from_the_chain_when_relay_starts`. |
| `peer_header_dos_and_self_announce` | P2P (**default**, crate) | One hub and one peer: verack order (wtxidrelay and sendaddrv2 stick, ping is logged, redundant verack is ignored, sendaddrv2 and oversized addrv2 after verack disconnect), unknown-parent block and compact, a full header batch continues from its last header, minchainwork stays silent until the floor, bad proof-of-work disconnects and time-too-new does not, empty-locator serves only a hash that has a body, an ancient weaker header disconnects unless noban. A noban or manual peer stays up on a bad block and gathers no score, and a manual peer that sends `sendaddrv2` after verack is still dropped. A version-3 header at CLTV activation logs `bad-version`, and a far stamp logs `time-too-new`. |
| `self_announce_clearnet_then_overlay` | P2P (**default**, crate) | One address book, no chain: externalip is daily, loopback and `--no-discover` suppress it, then onion and i2p replace that clearnet address on the same book. |
| `p2p_compact_hb_getblocktxn_and_orphan` | P2P (**default**) | One mature pad: HB coinbase `cmpctblock`, 2-tx compact → `getblocktxn` then same-peer compact retry while pending + `blocktxn` connect, unique short-id fill that fails header merkle → `getdata` (not `getblocktxn`, header not `BLOCK_FAILED`) then honest full `block` connects, orphan child GetData then parent accept (INV AlreadyHave), then live `getblocks` → `inv`, inbound `feefilter`, `filterload` disconnect. The pad seals filters through height 1, does not advertise `NODE_COMPACT_FILTERS` while the tip is ahead, stays silent for a stop at the tip, and answers `getcfilters` / `getcfheaders` / `getcfcheckpt` for the sealed height. An oversize locator is rejected. `mempool`, `filteradd`, and `filterclear` disconnect. Live mutated `block` disconnects in `on_block`. Inbound `getdata` of 20 witness blocks queues `MAX_SERVE_BLOCKS` (16), sends its `notfound`, and returns; the rest is served once the writer drains (`getdata_past_serve_cap_waits_for_writer`). The paused tail is served before the next `getdata`, and the session still pings and times out a peer that does not read (`paused_getdata_tail_is_served_before_the_next_getdata`, `paused_session_still_times_out_a_silent_peer`). A tip announce or `getblocktxn` block frees no serve slot (`uncounted_bodies_do_not_open_serve_slots`). Same-peer pending compact skip is `same_peer_pending_cmpct_does_not_getblocktxn_again`. Tokio-worker park and park-not-reject logs are `peer_blocksonly_and_orphan_tx` |
| `p2p_feeler_completes_and_closes` | P2P (**default**) | Outbound feeler: VERSION then close (`feeler connection completed`). No live follow; dummy has no completed inbound. Same test: `run_feeler_timed` silence is `Timeout`. Inbound/outbound/plain silence stay `handshake_timeout_after_silence` |
| `p2p_inbound_full_rejects_extra` | P2P (**default**) | `max_inbound=1`: second follow is refused; first inbound stays. Same test: `select_inbound_eviction` 21-cand ranking (4 block + 5 slow + 4 tx + 8 ping → victim in slow). A peer that is only noban is not the eviction victim |
| `badprev_orphan_does_not_blacklist_then_reorg_reconstructs` | P2P/chain (default) | Orphan whose prev is not on the tip is held (not `BLOCK_FAILED`); winner branch reconstructs. A mutated child of a held sibling is not `BLOCK_FAILED`, forgets the ask, and the honest body reorgs onto it |
| `serve_after_restart_via_reconstruct` | P2P (**default**) | Cold serve via reconstruct. Restart RAM body queue is empty. Same-process `rehydrate_block_queue_residue` drops at/below tip, skips empty payloads, keeps above-tip wire, unknown height stays queued. `has_block` / known-archived keep and tip+1 gap `missing` stay `bq_rehydrate_residue_keep_drop_gap_and_unknown` |
| `ibd_skips_dead_peer` | P2P (**default**) | Live seeder + `127.0.0.1:1` |
| `reorg_to_longer_branch` | P2P/chain (default) | Most-work reorg (hub only — no IBD hang risk). With the filter index on, the disconnect truncates basic filters and the branch's filters replace them. Then 20 side blocks received one at a time beat 19 tip-extends (`mempool_reorg.py`), the loser is a `valid-fork` that reconstructs from Class A (not held), an equal-work received branch waits for `preciousblock`, and invalidate / reconsider move between them without parking the old tip |
| `reorg_same_height_then_multi_block_branch` | P2P/chain (default) | Mature pad + competing-spend reorg (third spend is prevout-spent, not `multi-spender`); same-height rival then multi-block reorg near tip; `getchaintips` `active` vs `valid-fork`; 16 vs 17 equal-work siblings park as `valid-headers` (product held cap 320 does not FIFO at 17); `precious_block` the loser; less work ignored; unknown hash `Block not found` for precious and reconsider. Invalidating the tip with no precious preference picks the first-seen equal-work held sibling. With precious set, invalidate adopts that precious equal-work branch, and more total work still beats precious. Precious of an invalidated hash is a no-op that reconsider does not honor. A lone side block is `SideBlock`, a weaker branch is ignored, and an unknown parent errors on submit but is held from a peer. Held cap FIFO stays `hold_body_caps_fifo` |
| `three_node_relay_path` | P2P (**default**) | Leaf IBD-syncs from a mid node that already synced (hop serve) |
| `ibd_two_peers` | P2P (**default**) | Dual live seeders, 8-block IBD |
| `tip_follow_after_ibd` | P2P (**default**) | After IBD, follow + one new tip via inv/headers. With the filter index on, IBD confirm writes no basic filters; `rbtc-idx-wb` materializes them to the tip (its caught-up callback fires once, at the tip), then seals the followed block. With `--sp-tweaks` too: the builder brings both indexes to 5 and is stopped; a followed block with no builder running moves neither (no confirm path writes index data); a new builder seals 6, then follows 7 |
| `tip_follow_getheaders_catches_missed_blocks` | P2P (**default**) | Blocks mined while disconnected fill via post-connect `getheaders` |
| `end_of_ibd_follow` | P2P (**default**) | Miner plus `--sh-index` syncer. One mature regtest: coinbases pay script A, one spend pays script B. IBD reaches that tip, leaves IBD, and Electrum history matches. The next block tip-follows. Restart does not rewrite the scripthash pack mark; one more block arrives by write-behind. Cancelling IBD once the height is below the miner, then `run_p2p`, finishes the same tip and history. With the syncer caught up, dropping the miner leaves tip follow (not IBD). A partial datadir whose miner is down does not open Electrum and stays short of that tip; the same miner address coming back lets that datadir finish |
| `end_of_ibd_sh_interrupt` | P2P (**default**) | Same miner and scripts. The syncer first catches up with `--sh-index` off, then the datadir is frozen after pass 1 (`DONE.keys`, no `DONE.post`). Resume builds the index and Electrum's first answer is the full A/B history; restart does not rewrite the pack mark. A block mined after the freeze is in that history. A copy that already has the block, with `include_hwm` at the new tip and that create appended on the unsealed head, still serves the same history and does not open Electrum early |
| `end_of_ibd_work_fork` | P2P (**default**) | Two miners on a regtest with retargeting and min-difficulty. One chain retargets harder and stops shorter. The other forks after that retarget, resets to the pow limit, and grows taller with less work. The syncer IBD-adopts the heavier tip, keeps it across a reopen, and follows one more heavy block while the tall chain is still ahead |
| `node_run_p2p_short` | Node (**default**) | Product `run_p2p` `--blocks-only` `--connect` to a live seeder (`--max-tip-age` so the 3-block pad is not stale IBD); process `getpeerinfo` / `getconnectioncount` / `getnetworkinfo` / `getnettotals` / `ping` while connected (v2 `manual`, as Core reports `-connect`; handshake `startingheight` equals the seeder tip; `timeoffset` present; `synced_headers`/`synced_blocks` stay `-1` until the peer announces a header hash (empty getheaders at tip does not copy VERSION height); `servicesnames` present; `getnetworkinfo.timeoffset` present); after catch-up `localrelay` / mempool `relay_enabled` stay false and `sendrawtransaction` is not `relay disabled`; Electrum `broadcast` and Esplora `POST /tx` admit decode/consensus errors (not hub-missing / not `relay disabled`); `addconnection inbound` refuses; `disconnectnode` unknown `nodeid` / empty params error then a real addr drops that row from the next `getpeerinfo`, the seeder sees it go, and a second `disconnectnode` of that `nodeid` (or of an address never connected) is `-29`; the `--connect` peer is redialled as `manual` under a new id and the seeder sees the inbound; `addnode onetry` and `add` of that address succeed and open no second session; seeder inbound `tx` then ends that session. Exit via `stop`. `max_run_secs=0` is `node_listen_and_exit`. Mock-clock `timeoffset` is the median (odd N, even N upper-middle, inbound-only 0, peer clock behind). A connecting dummy reports `-1`. Header-only and connected peers report `synced_blocks` differently. A query without a chain errors. `pingwait`, `NETWORK_LIMITED`, and `noban` are on the peer row |

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

Nightly (not a required PR check) `fuzz.yml` runs **21** cargo-fuzz jobs.
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
| `cmpct_differential` | structured BIP152 recipe → `try_reconstruct` missing indexes vs Core `getblocktxn` (ASan). Fill-flag extras go to Core extra-txn first. Raw-wire arm is skip if decode fails. Full reconstruct (no `getblocktxn`) is a comparison, then `drain_pending_now` of a same-hash mutant and the honest body. Core is not invalidated first, and Core sees the honest body only. Hub accept with Core `submitblock` null or `duplicate` agrees. `duplicate-invalid` and `duplicate-inconclusive` are `reconsiderblock` then one more `submitblock`; a reason that remains is a reject. Both rejecting agrees. A tip that stays put is not treated as a Core accept. A disconnect-class error from the mutant drain is a disagreement. **Not** a second node process. Duplicate-txid fill (018) may request extra indexes Core extra-txn already placed; Core's request must be a subset of ours | same tarball, `-listen=1` |
| `block_differential` | height-1 `ChainHub::accept_received_block` vs Core `submitblock`, **accept vs reject only**. An input longer than 16 bytes whose tail control byte is `0xFE` submits a same-hash merkle mutant first. The honest block is replayed only when both sides rejected that mutant, so an accept or a split is not replaced by the honest result. Duplicating the last tx keeps the computed merkle root only for an odd count of at least 3; shorter and even counts fail `check_merkle_root` | same tarball |
| `block_spend_differential` | height-101 spend of a mature pad coinbase, same path and oracle, including the `0xFE` honest-twin replay. Weekdays are `--sanitizer none` and `-timeout=180`. Sunday (`FUZZ_WEEKDAY=7`) is `--sanitizer address` and `-timeout=90` so the maturity pad and Core spawn fit under ASan | same tarball |
| `script_differential` | height-101 same-block spend whose **executed scriptPubKey** is fuzzer-owned, same path and oracle, including the `0xFE` honest-twin replay | same tarball |
| `block_fork_differential` | 2-block heavier fork off the pad (sibling of a pad+1 stem), same path and oracle | same tarball |
| `cmpct_reorg_differential` | same fork child, but hub delivers **child then parent** through `drain_pending` (014/020); Core `submitblock`s parent then child. Accept vs reject of C / final tip | same tarball |
| `block_reorg_n_differential` | `DIFF_REORG_N` heavier side vs 1-block stem; same rewind/restore as fork | same tarball |
| `block_csv_differential` | BIP68 relative lock (full `u32` nSequence + version + MTP `time_shift`) vs Core `submitblock` | same tarball |
| `mempool_differential` | `MempoolHub::test_accept` vs Core `testmempoolaccept`. **Consensus-class only** — Core standardness / fee / RBF / dust is skip (COMPAT) | same tarball, `-acceptnonstdtxn=1` |
| `script_verify_differential` | `verify_tx_scripts_detached` vs Core `testmempoolaccept` of the parent+spend package. Same policy skip | same tarball, `-acceptnonstdtxn=1` |
| `store_reorg` | Tiny-hub `{extend, sibling, rewind}` connect churn (ASan, no Core). Sibling ops no-op once `held_body_count` hits 16 so one input cannot walk 320 bodies under the ASan timeout. Extend stops at height 32. After the op list the hub is dropped and the same datadir is reopened; the tip hash must match. The previous `Query` is dropped first, so this is not the two-live-`Query` RSS growth. A separate test rejects a second spend on a reopened hub. Store `Corrupt` / probe-exhausted **panics** | none, `-timeout=30` |
| `script_kernel_differential` | In-process script verify vs `bitcoinconsensus` (ASan, **fuzz workspace only**). Every executed input is `0xFE`, a Core flag word, a shape, and a payload. Shape 0 is opcode soup: tx version, sequence, locktime, amount, then length-prefixed scriptSig, scriptPubKey, and witness. Shapes 1–8 stay the fixed discriminators (empty-sig CHECKMULTISIG, non-canonical DER, typed P2PKH/P2WPKH, flag schedule, BIP16 exception, empty signet solution). Any other prefix skips. Aborting flag combinations are skips. Disagreement panics. The runner plants at most 32 shape-0 seeds from Core `script_tests.json` when that file is present, otherwise from `scripts/testdata/script-kernel-seed-rows.json` (`OP_TOALTSTACK`, `OP_TUCK`, and `CHECKMULTISIG` first). Our verifier has a 100ms thread-CPU budget (`SCRIPT_KERNEL_VERIFY_BUDGET`); a second sample must also exceed it. libFuzzer `-timeout=1` is the hang backstop | Core interpreter via `bitcoinconsensus` crate |
| `p2p_sequence_differential` | Up to 8 steps vs live Core v2. Bytes that do not start with `0xA5` stay `{ping, headers, block, skip}`. `0xA5` steps are `tag || u16le len || payload`: ping, headers, block, tx (consensus-class only, hub mempool attached), getheaders, cmpct, blocktxn, feefilter, and inv. Inv and feefilter payloads stay inside that `u16` length. A feefilter or inv is sent to the local `P2PNode`; a drop fails the input. It is not a Core comparison, because Core is whitelisted and the payload is re-encoded. An empty getheaders answer is not a comparison. A non-empty list of known hashes is. A dropped Core session is reconnected; a failed reconnect skips that step. A ping match, a consensus-class tx agree, a header-sequence agree, or a compact-index agree is a comparison | same tarball, `-listen=1` |
| `chain_review_differential` | Fresh `ChainHub` per shape: height-only milestone spend, genesis coinbase spend, unspendable BIP30 replay, same-batch immature coinbase, height-0 BIP68 lock, mutated-then-honest body, reorg respend. Injected or live `submitblock` reply. No skip. `"duplicate"` is an accept only when that block is active or `valid-fork`; the rule is `core_fate` in `fuzz/src/chain_review.rs`. Harness failure exits 2 | same tarball, `--sanitizer none`, `-testactivationheight=bip34@100000000` |

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
./scripts/fuzz-run.sh block_spend_differential  # 100-block pad; weekdays --sanitizer none -timeout=180; Sunday address -timeout=90
./scripts/fuzz-run.sh script_differential       # mutate executed scriptPubKey, --sanitizer none
./scripts/fuzz-run.sh block_fork_differential   # pad+stem, 2-block fork, --sanitizer none
./scripts/fuzz-run.sh cmpct_reorg_differential  # child-first drain_pending vs Core
./scripts/fuzz-run.sh block_reorg_n_differential # N-block side vs 1-block stem
./scripts/fuzz-run.sh block_csv_differential    # BIP68 nSequence + version + MTP
./scripts/fuzz-run.sh mempool_differential      # test_accept vs testmempoolaccept
./scripts/fuzz-run.sh script_verify_differential # detached scripts vs testmempoolaccept package
./scripts/fuzz-run.sh store_reorg                # tiny hub connect/disconnect, ASan, no Core
./scripts/fuzz-run.sh script_kernel_differential # ours vs libbitcoinconsensus, ASan, -timeout=1, 100ms verify budget
./scripts/fuzz-run.sh p2p_sequence_differential  # tagged steps vs Core, --sanitizer none
./scripts/fuzz-run.sh chain_review_differential  # hub review shapes vs submitblock, --sanitizer none
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

An external multi-message campaign stays on Fuzzamoto scenarios `ir` and
`compact_blocks`. This tree does not vendor that harness or run it in
GitHub Actions.

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
The stamp folds a mix of the input into genesis + 600 through genesis + 2
hours: this job's `setmocktime` is genesis, and a later header is
`time-too-new` on Core. The follow accept pins the hub clock to that same
mocktime. A split panic includes Core's `submitblock` reason.
Spawn `setmocktime`s Core to regtest genesis time (`CanDirectFetch`).
P2P `bitcoind` also gets `-maxtipage=999999999` so Core v31's IBD latch
(`UpdateIBDStatus` on `LoadChainTip`, not `setmocktime`) leaves IBD at
genesis — otherwise P2P `tx` is dropped and fill extra-txn never matches.
Fill-flag extras are sent as `tx` first (Core extra-txn / orphan pool)
and included in our short-id map. Missing indexes must match Core
`getblocktxn`. Fully reconstructed (empty missing, Core sends no request)
is a comparison: a same-hash mutant, then the honest body, scored against
`submitblock`. `duplicate` agrees. `duplicate-invalid` and
`duplicate-inconclusive` are `reconsiderblock` then one more `submitblock`,
because a compared accept `invalidateblock`s that header and Core keeps the
flag. A reason that remains is a disagreement. Seeds: 2-tx hole,
coinbase-only, fill, duplicate short-id, raw fixture. Disagreement panics.
It does not drive a two-node reorg.

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

Mutants are a nightly oracle, not a pull-request check, and not a local
command. Do not run `cargo mutants` on a developer machine. The nightly
script is `./scripts/mutants-nightly.sh`
([`mutants.yml`](.github/workflows/mutants.yml)). A local run copies a
workspace build and then reruns the suite once per mutant.

Check a kill by hand. Edit the expression to the missed operator, run the
catalog journey that should catch it, then restore the expression. The
journey fails while the mutant is applied and passes once the expression
is restored. That is the local proof. A package-only `cargo mutants` run
is not the gate: a journey outside the mutated crate must be able to catch
the mutant. The operator VM never runs it; that disk rule is
[`rearden-vm-HOST.md`](rearden-vm-HOST.md).

A new production behavior still needs a test that fails when that behavior
is removed or inverted. Put that assert on a catalog journey. A `MISSED`
mutant that changes a result a peer, client, or operator can observe is
killed by extending that journey. A `MISSED` mutant on an expression no
session can flip into a different client-visible result is a candidate to
delete the expression, not a candidate for a new unit. The nightly job
stays an oracle. It does not become a pull-request check. A same-crate
twin that only existed to satisfy a package-local mutant is a deletion
candidate once a workspace run shows the journey catching it.
