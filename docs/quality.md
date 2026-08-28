# Quality roadmap (living)

What is strong, what still blocks “industry-leading,” and what is already
closed. Replaces the 2026-08-06 point-in-time audit.

**Last reaudit:** 2026-08-21 (schema 18/19 + SH extent #177, confirm
no-coord / park / head-drain #173–#176, wallet-client join + bench
#162–#172, Core functional **44** `run`). Previous: 2026-08-18 (confirm
perf #117–#126, repo cruft #127, **Q-50**, leftover-P2P **37** `run`).

**Three lists only**

| Section | Purpose |
|---------|---------|
| **Open** | Single prioritized backlog — **rank 1 = next** |
| **Won't fix** | Explicitly retired. Do not reopen without a new product decision |
| **Completed** | Finished quality work — do not reopen without new evidence |

North star, baseline, and working rules are context, not a fourth backlog.
Update a row when work lands. Prefer that over a new dated audit PDF.

This is not a security audit. Numbers are order-of-magnitude.

**1.0 product gates** (what an operator can count on) live in
[`road-to-1.0.md`](./road-to-1.0.md). Do not copy that list here.

Former `algo-review.md` items that are still worth doing are **Q-57–Q-60**.
Inventory tables, gotchas, and micro-opts were not a second backlog — they
died with that file. Close a Q-id by moving it to Completed in the same PR.

Peer full-node notes (Hornet, satd) live in
[`peer-clients.md`](./peer-clients.md). Ranked later-consideration items
stay there; promote into Open only when scheduling a slice. **Q-30** already
covers the highest-leverage steal (in-tree differential fuzz).

---

## North star: industry-leading full node in Rust

rbitcoin’s thesis is already differentiated: **relational archive** (no UTXO
set), **pure-Rust scripts**, **in-process Electrum/Esplora for wallet backends**,
**Linux map-free IO + optional io_uring**, **reproducible static musl**.
Leadership is not “clone Core’s checklist”; it is **owning that thesis** at a
level peers cannot ignore.

### Pillars (priority)

| # | Pillar | Industry-leading looks like |
|---|--------|-----------------------------|
| 1 | **Correctness under adversarial load** | Consensus-aligned with Core where we claim parity; differential fuzz continuous; findings tracked to **fixed** + regression; no silent confirm/store fallbacks |
| 2 | **Operator trust** | Docs match shipped IO/store; milestone skip impossible to miss; CLI/conf primary; SECURITY contact; honest 0.x; dummy RPC numbers gone or labeled |
| 3 | **Build & release integrity** | Same toolchain in CI and Nix; byte-repro musl; SBOM/audit gates; no floating `stable` |
| 4 | **Contributor velocity** | God-files gone or split by stage; warm suite a few minutes; TDD practiced; first-hour tutorial |
| 5 | **Product surface honesty** | COMPAT accurate; Electrum/Esplora complete for *target* wallets, not explorer bloat |
| 6 | **Observability & ops** | Default INFO shippable; residual env in `docs/env-knobs.md`; signet-first then mainnet with monitoring |
| 7 | **Platform truth** | Linux-first operator binaries; store IO session exists for Darwin (`pool`) and Windows (IOCP). Packaging those OSes is still a later ask |

### Competitive bar

| Peer class | Beat them on | Do not waste effort matching |
|------------|--------------|------------------------------|
| **Bitcoin Core** | Archive model, Electrum-in-process, musl portable binary, pure-Rust script path | Every RPC, GUI, wallet, multi-OS desktop |
| **libbitcoin** | Modern Rust tooling, coverage gates, flake/repro, Electrum/Esplora | C++ cultural norms |
| **Fulcrum / Electrs** | Full validating node + index in one process | Being a pure indexer |
| **Other Rust nodes** | Store design, operator honesty, Linux IO, findings hygiene | Marketing or premature 1.0 |

### Non-goals that still look like “quality”

Not Open, not Completed — see **Won't fix** for retired Q-ids.

- Multi-OS operator binaries before Linux IBD/tip is boringly solid
- 100% line-coverage theater (gate is **≥90%** LCOV + property-focused tests)
- Rewriting secp256k1 / rust-bitcoin / tokio “to reduce deps”
- Flattening purpose-built io_uring machines to batched `pread` (see [`io-modality.md`](./io-modality.md))
- Core-compatible full RPC surface; graphical block-explorer APIs
- Growing leftover RAM maps to `Vec<Fk>` unless a mainnet miss is shown
  ([`errata.md`](./errata.md))
- Headerless SH extent interiors (uniform 4 KiB page records; ~0.2% density)
- Restoring `rbtc-script-coord-*` (ibd-confirm publishes waves)
- `rbitcoin-bench` in default-members / musl / required CI

---

## Open (priority order)

**One list.** Rank is overall operator + contributor leverage, not a category.
Tags are scan hints only.

**P0 trust/correctness (Q-01–Q-05) stays empty.** Do not reopen without new
evidence (failed Core corpus, new dual path, red required CI, MSRV drift).

| Rank | ID | Item | Tag | Done looks like |
|-----:|----|------|-----|-----------------|
| 1 | **Q-30** | Continuous differential fuzz | reliability | A nightly/weekly job that feeds BIP324 + header/block (and script) wire. Crashes → `docs/external_findings/` + named regression. **Today: `fuzz/` `block_wire` + nightly `fuzz.yml` (not a required PR check).** Grow corpus / more targets. Findings 001–021 came from an external fuzzamoto campaign — that is not a substitute for the in-tree job. |
| 2 | **Q-41** | Grow Core functional `run` set | test | Inventory `run` covers the wallet-client / P2P / mempool / buried-activation scripts we **claim**. **Today: 53 run / 214 skip (30 rpc-missing, 26 core-log).** COMPAT-done leftovers are `rpc-dialect` (not `rpc-missing`). Next `run` candidates: `mempool_accept` type-check, `mining_basic` weight, `rpc_getblockfrompeer`. Product-never skips stay skip. Unlabeled PRs stay cargo-only; nightly green |
| 3 | **Q-57** | Store publish / Class C flush / sidecar | store | `VarTable::published_meta` loads count/end `Acquire` (ARM cannot tear the pair). `ArrayTable` / `StrongTxTable` `flush_dirty` cannot lose a `set` in the write window (clear dirty then snapshot, or equivalent). fuse8 `decode_body` fails closed (`NeedsRewrite`) instead of indexing fingerprints OOB. Spender overflow walk bounded by `spenders.count()`. Sidecar meta / `.mphf` / SH `.idx` do not rename an unsynced empty file into place. `sorted_run` orphan GC cannot delete a live run (lock is a type, not a comment). |
| 4 | **Q-58** | Mempool persist order + eviction | mempool | `persist_all` writes body before claiming LIVE slots. Known-parent out-of-range vout hard-rejects (not orphan-forever). `worst_chunk` rate-tie does not strand descendants. `evict_to_budget` no-op iterations break (no spin). |
| 5 | **Q-59** | RPC / CLI honesty | ops | `submitblock` matches [`rpc.md`](./rpc.md) / COMPAT (all networks) or those docs say regtest-only. `gettxout include_mempool` hides mempool-spent confirmed outs. `sendrawtransaction` / `submitpackage` enforce or reject `maxfeerate` / `maxburnamount`. Conf `milestone=0` is not overwritten by the network default. `--minrelaytxfee` parse failure is an error (negatives rejected). `getmininginfo` `blockmintxfee` uses a feerate formatter. `getnetworkhashps` is not a dummy ~2 hashes/block (or is labeled). JSON-RPC batch is bounded under the work permit. |
| 6 | **Q-60** | P2P caps + compact reconstruction | p2p | Compact-block prefilled indexes are strictly increasing and in-bounds. AddrMan has tried/new caps. `cmpct_fills` / `requested_blocks` prune on abandon/timeout. `announced_wtx` rolls instead of clear-all INV burst. Pending/held eviction is FIFO (`held_seq`), not `HashMap::keys().next()`. Esplora WS mempool-announce store IO uses `spawn_blocking` like REST (**landed**). IBD `disconnect_to` skips cloning the losing branch when there is no mempool. |
| 7 | **Q-48** | BIP331 rust-bitcoin package types | interop | Native BIP331 `NetworkMessage` when rust-bitcoin exposes it (**RB-007**). Packages today are RPC `submitpackage` / Esplora `POST /txs/package` only — no private P2P command. Blocked upstream — ranked below unblocked ops work. **After this:** Electrum 1.6 then 1.7 (`protocol_max` bump in the same work) — [`COMPAT.md`](../COMPAT.md) § Protocol versions |
| 8 | **Q-31** | Hermetic tip fixtures | ops | Frozen signet/mainnet tip packs for offline consensus/Electrum regression (no live API). Unblocks Q-30 corpora |
| 9 | **R-10** | Residual god-files | code | Peel **only** when a higher row needs a seam. After extracting `peer_tests` / `methods_tests` / `scripthash_tests`: production `query/lib` **4.2k**, `electrum/server` **3.7k**, `scripthash` **3.4k**, `sorted_run` **3.4k**, `methods` **3.3k**, `chain` **3.3k**, `store` **3.2k**. Further production peels wait for a real seam. **Q-54** may need a seam if a cap rule cannot match a god-file. |
| 10 | **Q-54** | Grow ast-grep rules from `ibd-memory.md` | code | One rule per named cap that is easy to delete: `pending_blocks` 128, `held_bodies` 320, `MAX_SERVE_BLOCKS` 16, `follow_live` vs `max_outbound`. Each rule has `lint/ast-grep/fixtures/{good,bad}/`. Peel god-files (**R-10**) only if a rule needs a seam. |
| 11 | **Q-55** | CRAP `--fail-regression` | test | Commit `crap_baseline.json` (`--format json --sort file`) from a green coverage artifact. PRs fail if a function’s CRAP rises. Still no `--fail-above 30` while clippy allows `cognitive_complexity`. |
| 12 | **Q-56** | Miri islands beyond primitives | reliability | `cfg(miri)` tests for FFI-free helpers (scriptnum, pack_ud-style integers) that do not pull secp/store. Never workspace miri. |

### Still valid? (this reaudit)

2026-08-21 pass. Tree at #177. Verified: zero in-tree fuzz, inventory
**44** `run` / **223** `skip` / 267 total, `SCHEMA_VERSION = 19`, findings
001–022 all fixed, **0** `TODO`/`FIXME`, **2** `#[allow(` (clippy
`type_complexity` in consensus), `unsafe`
in store IO sessions + `script_pool` + confirm `head_drain`.

| ID | Verdict |
|----|---------|
| **Q-30** | Keep rank 1. Still the highest correctness hole; zero in-tree fuzz. External fuzzamoto is not a substitute job. |
| **Q-41** | Keep rank 2. 44 → **53** `run`. 214 skips; `rpc-missing` 30 + `core-log` 26 are the only growth matching claimed surface. |
| **Q-50** | **Closed.** Write/lookup/load inventory includes `drain_join` / `dequeue` / wave nested tokens; `other=` is the explicit residual (`format_info` pins). A fat `other=` on a later IBD is confirm-perf, not a missing-meter program. 2026-08-18 dark-time numbers retired. |
| **Q-36** | **Closed.** Default INFO is `ibd: progress`; `ibd: perf` / `ibd: sizes` / `perf_dbg` are DEBUG (`log_sample`). |
| **Q-48** | Keep, rank 7. Waits on rust-bitcoin (**RB-007**). |
| **Q-31** | Keep. Useful for Q-30; not blocking operators. |
| **Q-34** | **Closed.** `OPERATOR.md` § First hour (regtest); README points at that section. |
| **R-10** | Keep last among peels. Inline tests left `peer.rs` / `methods.rs` / `scripthash.rs`. Remaining giants are production-sized (`query/lib` **4.2k**). |
| **Q-57–Q-60** | **Added 2026-08-25** from retired `algo-review.md`. Not a reaudit of the rest of this table. |

Prior-reaudit closures (Q-37, Q-47, Q-49) and Won't-fix calls
(Q-24/25/32/33/35/38) stand — evidence unchanged. This pass adds
Won't-fix rows for headerless SH interiors, script coordinators,
and bench-in-CI (shipped shape, not a backlog).

### ID aliases (R-program ↔ catalog)

R-ids were the 2026-08-12 ranked slice. Canonical Open/Completed/Won't-fix
id is in **bold**. Do not start **R-11+** — new work is the next unused
**Q-id (Q-61+)**.

| R-id | Canonical | Where |
|------|-----------|-------|
| R-01–R-06 | **R-01–R-06** | Completed |
| R-07 | **Q-30** | Open rank 1 |
| R-08 | **Q-20** | Completed |
| R-09 | **Q-16** | Completed |
| R-10 | **R-10** | Open rank 9 |

Next unused Q-id is **Q-61**.

---

## Won't fix

Retired on purpose. Not a backlog. Not a failure.

| ID | Item | Why |
|----|------|-----|
| **Q-24** | CODEOWNERS / issue templates | No public collaboration process to own. Revisit only if external reviewers are invited |
| **Q-25** | crates.io package metadata | Distribution is `nix build .#rbitcoin-musl`. `repository` is already set |
| **Q-32** | Structured logging option | INFO/DEBUG text is the operator contract. JSON/kv is a second dialect |
| **Q-33** | Published rustdoc site | `cargo doc` locally. No docs.rs until crates.io (Q-25) |
| **Q-38** | Tier-C multinode in default CI | Wall/flake. `#[ignore]` + `scripts/integration.sh` is the product |
| **Q-35** | Mainnet soak program | Not a program. Run signet first, then mainnet with monitoring. No gated checklist or badge |
| **—** | Darwin notarization / Developer ID | Ad-hoc `codesign -s -` on the macos snapshot. Notarization is still not a product |
| **—** | Leftover maps as `txid → Vec<Fk>` | [`errata.md`](./errata.md): only if a mainnet miss is shown |
| **X-M3** | Esplora process-wide `sh_join` LRU / per-IP / large cache | HTTP is not a session. A tiny LRU still evicts wallets; per-IP is NAT/DoS; a large cache is RSS (join payload × addresses × clients). Sticky joins stay on Electrum TCP (one slot per connection). Esplora keeps one last SH for sequential REST. |
| **—** | Package-level feerate on `accept_package` / `submitpackage` | COMPAT: sequential `accept_tx`; a 0-fee CPFP parent is rejected on its own min-relay. Core `submitpackage` parity is not 1.0. |
| **—** | Esplora `/blocks` reconstruct + chained `scripthash_mempool_stats` | Explorer page cost / dialect. Persist size/weight is a schema ask; graphical explorer APIs are already Won't-fix. |
| **—** | Retired algo-review micro-opts | BDZ page fill, `HashHead::bulk_fill_empty` RAM, SH `insert_many` N², INV O(peers×mempool), Electrum per-row header read, mempool `find_free_slot` O(cap), `evict_nonfinal` O(n²), BQ `index.iter().find`, `BlockCache` prefix O(chain), GBT `depends` scan, log-macro eval when disabled, `api_log` mutex, bit-by-bit `count_ones`, `U64IdentityHasher` clustering, `last_push_data` PUSHDATA4, `--api-log` unbounded JSONL. Not a second backlog. Reopen a named Q-id only with a mainnet profile that names the cost. |
| **—** | Headerless SH extent interior pages | Extent is a span-read of the existing 4 KiB delta-page record. Interiors keep `ver`/`n_fks`/`next` so one decoder serves leftovers, tails, and last-page append. Full-page payload is ~0.2% and a schema bump |
| **—** | Restore `rbtc-script-coord-*` | `ibd-confirm` publishes waves, polls lock-free completion, feeds `scriptq` when steal is empty. Steal workers unpark the publisher. Do not add coordinator threads to keep the pool fed |
| **—** | Flatten purpose-built io_uring machines | [`io-modality.md`](./io-modality.md): fix the machine; do not replace it with batched `pread`/`pwrite` without an explicit ask |
| **—** | Process pin FIFO / CreateResidency / ContigPark / archive sticky | Pins are plan/batch only. IBD confirm is body-queue wire → lookup → load. [`concurrency.md`](./concurrency.md), [`invariants.md`](./invariants.md) |
| **—** | `rbitcoin-bench` default-member / musl / required CI | Optional crate, host A/B against a live store. Not a packaging or coverage gate |
| **—** | `cargo miri test --workspace` | io_uring, tokio, secp256k1-sys. Same class as Q-38 (too heavy / cannot go green). Primitives only (**Q-53**); extra islands are **Q-56**. |
| **—** | `cargo crap --fail-above --threshold 30` | At ≥90% line coverage CRAP **equals CC**. `handle_peer_frame` / confirm write / SH pack would force **R-10** peels. Use **Q-55** regression instead. |
| **—** | ast-grep as a second clippy for style | `cognitive_complexity` and friends are allowed on purpose. Structural rules catch RSS/task-leak *shapes*; they do not re-litigate clippy. |

---

## Completed

**One short list** of the latest quality program. Older closures (Q-01–Q-14,
findings 001–022, CI split, map-free README, …) live in
[`CHANGELOG.md`](../CHANGELOG.md). Do not reopen without new evidence.

| ID | Item | Resolution |
|----|------|------------|
| **Q-51** | ast-grep structural lints | `sgconfig.yml` + `lint/ast-grep/` first rules (`detached-tokio-spawn`, `mem-forget-or-leak`, `thread-spawn-dropped`) + `scripts/ast-grep.sh`. Required CI job `ast-grep` (fmt-class). Grow named-cap rules: **Q-54**. |
| **Q-52** | CRAP report on coverage LCOV | `scripts/coverage-crap.sh` after the ≥90% gate; `coverage/crap.json`. No `--fail-above 30`. Regression gate: **Q-55**. |
| **Q-53** | Miri on primitives | `scripts/miri.sh` → `cargo miri test -p rbitcoin-primitives`. Nightly `miri.yml` like `fuzz.yml` (not required). Islands: **Q-56**. |
| **—** | Schema 18/19 indexes | Sealed MPHF `g` is FdOnly (#161). SH extent pack8 mode 11; last-page stream **4072 B** for the `ver=2` header (#177). Class A / C stay 17 bytes. 17 populated `tx.head`/`scripthash*` still refused |
| **—** | Confirm scripts + write-behind | Park/unpark steal (#173). `ibd-confirm` publishes waves (no coordinators, #174). Process-wide `ibd-confirm-head` drain (#176). BIP141 nonce skipped pre-SegWit (#175) |
| **—** | Wallet-client SH join | Serve-lean `txid.body` identity (#168). Last-slot Electrum/Esplora join + tip probe (#170/#171). Optional `rbitcoin-bench` (#164–#172; not default-members) |
| **Q-50** | Perf meter residual coverage | Named write/lookup/load inventory + explicit `other=` (`drain_join` / `dequeue` / wave nested). Fat `other=` later is confirm-perf, not a meter program |
| **Q-36** | Perf log diet | Default INFO is `ibd: progress`. `ibd: perf` / `ibd: sizes` / `ibd: perf_dbg` at DEBUG (`log_sample`). `tip: perf` already DEBUG |
| **Q-34** | First-hour tutorial | [`OPERATOR.md`](../OPERATOR.md) § First hour (regtest): mine → Electrum `server.version` → Esplora tip height. README points there. No second docs map |
| **Q-49** | v2-only peer discovery | `x809.<seed>` first, then unfiltered; `addr`/`addrv2` requires `P2P_V2`; dial skips `INCOMPATIBLE` while any better addr remains. Owner: [`OPERATOR.md`](../OPERATOR.md) § P2P + `seeds.rs` |
| **Q-47** | Honest `getblockchaininfo` disk / progress | Store file walk + `blocks/headers` (not dummy 0 / 0.5) |
| **Q-37** | Warm default suite ≤3 min | Required CI `test` **~85 s** (2026-08-17, ubuntu-24.04). Stretch &lt;2 min met on CI-class. Recorded in TESTING.md |
| **—** | Docs map + one owner per fact | `docs/README.md`; folded store-format / startup-states / future-features / COVERAGE (`#81`) |
| **—** | Tests assert behavior, not repo text | No `include_str!` of production `.rs` / CONTRIBUTING (`#85`) |
| **—** | Core functional `run` set | **53** unmodified v31.1 scripts (was 44 at last reaudit, 9 at first green). Remaining growth is **Q-41** |
| **Q-15 / Q-42–Q-46** | CLI, inbound config, RPC honesty, Libre-only, IO aliases | 2026-08-16 cruft program |
| **R-01–R-06** | Mempool snapshot, `script_pool`, remine pads, TxGraph cache, llvm-cov pin, tip-follow store integrity | 2026-08-12. Wall leftover was **Q-37** (now closed) |
| **Q-16 / Q-20 / Q-23** | Residual env, `cargo deny` CI, optional musl artifact | `env-knobs.md`; required `deny`; musl zip is GitHub Release only |
| **—** | Darwin / Windows operator snapshots | GitHub Release (`release.yml`). PR `ci` `windows` / `macos` smoke store IO + `--smoke` |

---

## Working the list

| Do | Do not |
|----|--------|
| Close work by **moving the Open row into Completed** in the same edit as the landing change | Leave `Status: fixed` in Open, or start a second table |
| New item: next unused **Q-id (Q-61+)** inserted at an explicit rank | Fill historical gaps (Q-06–Q-09, Q-17–Q-19, Q-26–Q-29) or start **R-11+** |
| Retire a row to **Won't fix** when the product will not do it | Leave dead Open rows “for completeness” |
| God-file peels only when a higher Open row needs a seam (**R-10**) | Split `query/lib` / `interpreter.rs` / `scripthash.rs` as a standalone “modularity” project |
| Suite: no new remine-100 / default test **&gt;2 s** without justification ([TESTING.md](../TESTING.md)) | Time the full workspace as a planning spike |
| Differentials / crashes → `docs/external_findings/` + named regression | Soft dual paths on confirm identity / denserels / Class A load |

---

## Baseline snapshot

**Measured 2026-08-21** (`crates/**/*.rs` raw `wc -l`, inline test mods
included; tree at #177):

| Metric | Value |
|--------|-------|
| First-party Rust LOC | **~167k** (was ~150k on 2026-08-18; SH extents, confirm pipeline, wallet join, bench crate) |
| Workspace crates | **14** (`rbitcoin-cli` … `rbitcoin-test` + optional `rbitcoin-bench`; no wallet crate). `rbitcoin-bench` is not default-members and not musl |
| Largest production files (lines) | `query/lib` **4159**, `electrum/server` **3685**, `scripthash` **3446**, `sorted_run` **3366**, `rpc/methods` **3296**, `chain` **3251**, `store` **3242**, `ibd/perf_log` **2743**, `interpreter` **2628**, `peer` **2132** |
| Largest test files (lines) | `peer_tests` **3521**, `tx_table/tests` **3209**, `methods_tests` **2575**, `confirm_reject_tests` **2555**, `scenarios` **2267**, `scripthash_tests` **2111** |
| `#[test]` / `#[tokio::test]` | **~1.69k** |
| `TODO` / `FIXME` / `#[allow(` | **0** / **0** / **2** |
| Coverage gate | **≥90%** LCOV `LH`/`LF` (required CI) |
| Required CI | `fmt`, `deny`, `clippy`, `ast-grep`, `test`, `windows`, `macos`, `multinode`, `coverage` (+ CodeQL) |
| Extra CI | `release.yml` on `v*.*.*` / dispatch; `fuzz.yml` nightly; `miri.yml` nightly primitives; `core-functional.yml` nightly / labeled PR (not required) |
| rustc | **1.95** (`Cargo.toml` + `rust-toolchain.toml` + `dtolnay/rust-toolchain@1.95.0` + nixos-26.05 / shell) |
| Nix | **nixos-26.05** + crane **0.23.x** |
| Host cargo silos | `target/dev` (test) / `target/cov` (coverage) |
| Release | `nix build .#rbitcoin-musl` → static install |
| Core corpora | **No allowlist** |
| Findings 001–022 | All **fixed** |
| Core functional | **53** unmodified v31.1 scripts `run`; 214 skip (68 `no-wallet`, 30 `rpc-missing`, 26 `core-log`, …) |
| Residual `RBITCOIN_*` in crates | Honored set listed in `env-knobs.md` (**Q-16** closed) |
| On-disk | **Schema 19** (Class A/C still 17 bytes; 18 = MPHF indexes; 19 = SH extent last page). Populated 17 `tx.head`/`scripthash*` refused |
| Confirm queues | **loadq=14 · scriptq=4 · writeq=14** (hardcoded) |
| IBD confirm rate | Last instrumented fat-era number **6.4 blk/s** at #126 (2026-08-18). Not re-baselined after loadq/stamp/no-coord/head-drain. Residual meters are named (`other=`) — **Q-50** closed |
| Fuzz | **minimal** (`block_wire` nightly; breadth is Q-30) |

### Grade board (subjective; 2026-08-21)

| Dimension | Grade | Note |
|-----------|-------|------|
| Architecture clarity | Strong | Roles + HWM + single Class A appender; schema 19 in SCHEMA.md; scripts have no coordinator threads |
| Dependency hygiene | Strong | No `libbitcoinconsensus`; fuse8/script_pool in-tree; bench crate optional |
| Operator honesty | Strong | CLI primary; chaininfo disk/progress are real (Q-47); SH materialize keep-runs + last-page cap is pinned; README size matches SCHEMA census |
| Code modularity | Medium | Inline tests peeled from `peer` / `methods` / `scripthash`. Production leftover: `query/lib` **4.2k** (**R-10**) |
| Cross-platform | Medium (honest) | Completion session ports Darwin/Windows store IO. CI snapshots: musl + CRT-static Windows + system-dylib Darwin |
| Docs consistency | Strong | One map (`docs/README.md`); AGENTS slim; comments-as-smell + no repo-text tests |
| Contributor onboarding | Strong | how-we-plan + TDD + inventory; first hour is OPERATOR.md (Q-34) |
| CI fidelity | Strong | Split gates; `test` ~85 s; Core functional nightly extra |
| Dead / stub surface | Strong | Node RPC is a real subset; no dummy chaininfo numbers |
| Test reliability/speed | Strong | **Q-37** closed on CI-class; 2 s default-test rule remains |
| Tip-follow mempool APIs | Strong | **R-01–R-04**; persist sidecars exist (Core persist script still skip → Q-41); INV tick no longer clones the mempool |
| Wallet-client APIs | Strong | Last-slot SH join + serve-lean identity for Electrum/Esplora; Casa/Sparrow times stay host-only (`rbitcoin-bench`) |
| Adversarial / findings | Medium–Strong | **001–022** closed; **minimal fuzz** (`block_wire` nightly); breadth is **Q-30**. Core functional is the active surface program (**Q-41**) |
| Perf observability | Strong | Named residuals (`other=` / `drain_join=`) (**Q-50**). Default INFO is `ibd: progress` (**Q-36**) |

---

## What to protect

- Distinct product thesis (archive + pure Rust scripts + in-process wallet APIs).
- Small dependency graph; no `libbitcoinconsensus`.
- Operator honesty (experimental, milestone, Linux-first, honest MSRV).
- Written concurrency model (roles, HWM, one Class A appender; ibd-confirm
  publishes script waves — no coordinator threads).
- Portable static musl + crane + repro notes.
- Warnings-as-errors; Red → Green → Refactor (`docs/how-we-plan.md`).
- SCHEMA / SCHEMA_HISTORY / crash-recovery / COMPAT at 0.x.
- External findings hygiene + Core corpora without allowlist.
- Confirm dual-path kill + tier-A multinode in default/CI.
- Soft-migrate durable side formats; no silent wipes.
- Tests assert shipped behavior, not repo text.
- Schema 19 SH last-page stream cap (`ver=2` header 24 B / 4072 B stream);
  chunkers share `sh_page_chunk_ranges`.
- Sealed MPHF `g` stays FdOnly (fuse8 fingerprints in RAM).
- Schema 17 leftover regenerate for optional `sp_tweaks` files (not a Class A wipe).

---

## Consumers

| Audience | Read |
|----------|------|
| Next quality slice | **Open**, rank 1 (**Q-30** fuzz). Active program: **Q-41** (Core functional `run` set). Folded store/mempool/RPC/P2P leftovers: **Q-57–Q-60** |
| Peer full nodes | [`peer-clients.md`](./peer-clients.md) — Hornet / satd notes; not a fourth backlog |
| Release engineering | **Q-20**, **Q-21**, **Q-23** (completed) |
| Security / adversarial | Protect Q-01–Q-02; next **Q-30** |
| Docs / README | Map is done; first hour is OPERATOR.md (**Q-34** closed) |
| “Are we leading yet?” | North star + grade board |

---

*Living document. Prefer updating this file over dated audit copies.
Reaudit after a multi-commit quality program or when grade claims would rot.*
