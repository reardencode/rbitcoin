# Quality roadmap (living)

Ranked remaining work and invariants that must not slip. Closed work lives
in [`CHANGELOG.md`](../CHANGELOG.md). 1.0 product gates:
[`road-to-1.0.md`](./road-to-1.0.md). Peer-node notes:
[`peer-clients.md`](./peer-clients.md) (do not copy here).

**Last reaudit:** 2026-09-15. Schema **24**. Core functional **67** `run` /
**200** `skip`. Findings **001–023** fixed. Nightly fuzz **20** jobs.
Previous: 2026-09-13.

| Section | Purpose |
|---------|---------|
| **Open** | Single prioritized backlog — **rank 1 = next** |
| **Won't fix** | Retired. Do not reopen without a new product decision |
| **Protect** | Invariants. Not a backlog. Do not “improve” them away |

P0 trust/correctness (**Q-01–Q-05**) stays empty unless there is new
evidence (failed Core corpus, new dual path, red required CI, MSRV drift).

---

## Open (priority order)

| Rank | ID | Item | Done looks like |
|-----:|----|------|-----------------|
| 1 | **Q-41** | Grow Core functional `run` set | Inventory `run` covers claimed wallet-client / P2P / mempool / buried-activation. **67 run / 200 skip** (19 `rpc-missing`, 17 `core-log`, 68 `no-wallet`). COMPAT leftovers are `rpc-dialect`, not `rpc-missing`. `run` must hit node production (not only shim argv / dummy `blk*.dat` / Core decode dialect). Next `run`: recover to 71. `mempool_accept` stays skip (`policy-libre`). Unlabeled PRs stay cargo-only. Owner: [`core-functional.md`](./core-functional.md). |
| 2 | **Q-48** | BIP331 rust-bitcoin package types | Native BIP331 `NetworkMessage` when rust-bitcoin exposes it (**RB-007**). Local packages: RPC `submitpackage`, Esplora `POST /txs/package`, Electrum 1.6 `broadcast_package`. `protocol_max` is **1.6**; 1.7 `scriptpubkey.*` still missing. |
| 3 | **Q-31** | Hermetic tip fixtures | Frozen signet/mainnet tip packs for offline consensus/Electrum regression (no live API). Fuzz already merges tiny `signet_block_*.bin` / `mainnet_block_290329.bin`. Electrum hermetic packs still Open. |
| 4 | **R-10** | Residual god-files | Peel **only** when a higher row needs a seam. Do not split `interpreter.rs` opcode `match` or io_uring machines. Named extracts: **Q-61** Completed. |
| 5 | **Q-54** | ast-grep named-cap rules | One rule per easy-to-delete cap from [`ibd-memory.md`](./ibd-memory.md): `pending_blocks` 128, `held_bodies` 320, `MAX_SERVE_BLOCKS` 16, `follow_live` vs `max_outbound`. Each has `lint/ast-grep/fixtures/{good,bad}/`. Today **four** structural rules, **zero** cap rules. |
| 6 | **Q-55** | CRAP `--fail-regression` | Commit `crap_baseline.json` from a green coverage artifact; PRs fail if a function’s CRAP rises. Still no `--fail-above 30` (at ≥90% coverage CRAP equals CC and would force **R-10** peels). Clippy: [`code-shape.md`](./code-shape.md). |
| 7 | **Q-56** | Miri islands beyond primitives | `cfg(miri)` tests for FFI-free helpers (scriptnum, pack integers) that do not pull secp/store. Never workspace miri. Nightly `miri.yml` is still primitives-only (**Q-53**). |

R-ids were the 2026-08-12 slice. Canonical id is **bold**. Do not start
**R-11+**. Next unused Q-id is **Q-66**.

Close work by **moving the Open row into CHANGELOG** in the same edit as
the landing change (do not grow a Completed museum here). New item: insert
at an explicit rank with **Q-63+**.

---

## Won't fix

| ID | Item | Why |
|----|------|-----|
| **Q-24** | CODEOWNERS / issue templates | No public collaboration process |
| **Q-25** | crates.io package metadata | Distro is `nix build .#rbitcoin-musl` |
| **Q-32** | Structured logging option | INFO/DEBUG text is the operator contract |
| **Q-33** | Published rustdoc site | `cargo doc` locally; no docs.rs until crates.io |
| **Q-35** | Mainnet soak program | Signet first, then mainnet with monitoring. No badge |
| **—** | Darwin notarization | Ad-hoc `codesign -s -` only |
| **—** | Leftover maps as `txid → Vec<Fk>` | [`errata.md`](./errata.md): only if a mainnet miss is shown |
| **X-M3** | Esplora process-wide `sh_join` LRU | HTTP is not a session. Sticky joins stay Electrum TCP |
| **—** | Package-level feerate on `submitpackage` | Sequential `accept_tx`; Core parity is not 1.0 |
| **—** | Chained Esplora `scripthash_mempool_stats` | Dialect / page cost. Compact `/txs/summary` is COMPAT dialect. Graphical explorer APIs stay Won't-fix |
| **—** | Retired algo-review micro-opts | Reopen a named Q-id only with a mainnet profile that names the cost |
| **—** | Headerless SH extent interiors | Uniform 4 KiB page records; ~0.2% density; schema bump |
| **—** | Restore `rbtc-script-coord-*` | `ibd-confirm` publishes waves. No coordinator threads |
| **—** | Flatten purpose-built io_uring machines | [`io-modality.md`](./io-modality.md): fix the machine |
| **—** | Process pin FIFO / CreateResidency / ContigPark / archive sticky | Pins are plan/batch only. IBD is body-queue → lookup → load |
| **—** | `rbitcoin-bench` in default-members / musl / required CI | Optional host A/B. Not a packaging or coverage gate |
| **—** | `cargo miri test --workspace` | io_uring, tokio, secp256k1-sys. Primitives only |
| **—** | `cargo crap --fail-above --threshold 30` | CRAP equals CC at ≥90% lines. Use **Q-55** regression |
| **—** | ast-grep as a second clippy | Structural RSS/task-leak *shapes* only |

Coverage theater (chasing 100% lines), rewriting secp/rust-bitcoin/tokio
“to reduce deps”, Core-complete RPC, and explorer-search APIs are also
not Open.

### Parked (not now; promote to Open with a rank to revisit)

Wallet-backing extras from the 2026-09 node survey. Not Won't-fix forever —
just not the current product. COMPAT/OPERATOR stay the shipped contract.

| ID | Item | Why parked | Reopen when |
|----|------|------------|-------------|
| **Q-63** | Electrum TLS (50002) + Tor onion **in the binary** | Home Sparrow/phone off-LAN today uses nginx (`OPERATOR.md`). Node stays plain TCP. | Operators refuse a reverse proxy, or a first-class onion listener is the 1.0 install. |
| **Q-64** | GBT longpoll / `waitNext` (then Sv2 template provider) | Opt-in `getblocktemplate` + Esplora `/block-template` with 15 s cache is the mining extra. No stratum/pool. | DATUM / Bitaxe / mkpool users need push templates; IPC mining interface is the Core shape. |
| **Q-65** | BIP157/158 compact block filters (`peerblockfilters` / `getblockfilter`) | Electrum + Esplora (exact scripthash) is the wallet path. P2P filter short IDs stay decode-reject (`COMPAT.md`). | Neutrino / LDK-node on *this* node without handing every address to Electrum. |

---

## Protect

Do not “improve” these away. Design owners are linked; this is the
checklist.

- **Thesis:** relational archive, pure-Rust scripts, in-process
  Electrum/Esplora, Linux map-free IO + optional io_uring, reproducible
  musl. Not a Core clone. [`architecture.md`](./architecture.md).
- **No silent consensus/store fallback.** Missing promised fact →
  `StoreError::Corrupt("invariant: …")`. Confirm dual-path kill. TxApply →
  dummy `Block` is `rbitcoin_query::testutil` only. One Class A planner.
- **Concurrency / IBD:** no locks on the store hot path; one Class A
  appender; ibd-confirm publishes script waves (no coordinator). Pins are
  plan/batch only. [`concurrency.md`](./concurrency.md),
  [`invariants.md`](./invariants.md).
- **On-disk:** [`SCHEMA.md`](../SCHEMA.md) current bytes (today **24**).
  Soft-migrate durable side formats; bump or refuse; **no silent wipe**.
  Same commit as the format code.
- **io_uring:** do not flatten a purpose-built machine to batched
  `pread`/`pwrite` without an explicit ask. [`io-modality.md`](./io-modality.md).
- **SH create_count:** last-page reserved is stamped by the **appender**.
  Query/cap probes are read-only (walk when reserved is 0). Do not pwrite
  the last page from the join path.
- **Live `P2PNode` tests:** one topology at a time **per test process**
  (`live_p2p_lock`). Do not “fix” flakes with `RUST_TEST_THREADS=1`.
  [`TESTING.md`](../TESTING.md).
- **Default CI is the pin.** Unlabeled PRs: `cargo test`, not Core
  functional. Coverage: production LCOV **never-falls** vs the highest
  master snapshot at or before the PR merge-base (90% floor). Tests assert
  shipped behavior, not repo text.
- **Operator honesty:** experimental 0.x; milestone skip is loud; CLI/conf
  share `apply_kv`; dummy RPC numbers labeled or gone; COMPAT matches
  shipped surface (including Esplora `/txs/summary` as a dialect).
- **Build:** rustc **1.95.0** in CI and Nix; `cargo deny`; no floating
  `stable`. Musl operator binary is GitHub Release only.
- **Fuse8 / leftover:** sealed fuse8 fingerprints stay RAM; BDZ `g` is
  FdOnly. Optional `sp_tweaks` leftover regenerate is not a Class A wipe.
- **Meters:** instance `ConfirmStats` / session IO stats. No process-global
  confirm meters, no TLS `test_take_*` probes.
- **Crate graph:** unused `pub` is forbidden; fuzz lives in `fuzz/`.
  Clippy: no workspace `allow` list ([`code-shape.md`](./code-shape.md)).
- **Findings:** crashes → `docs/external_findings/` + named regression.
  Core JSON corpora without allowlist.

Suite budgets, coverage math, and default-vs-nightly Core:
[`TESTING.md`](../TESTING.md). Agent hard rules: [`AGENTS.md`](../AGENTS.md).

---

*Reaudit after a multi-commit quality program or when Open claims would
rot. Do not restore a LOC snapshot, grade board, or Completed museum.*
