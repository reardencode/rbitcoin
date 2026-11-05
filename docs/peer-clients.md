# Peer full nodes: Hornet and satd

Date: 2026-09-04. Research snapshot (Hornet `main` @ `151462fa`, satd `master`, public
docs). Analysis only at write time. Not re-read for the 2026-09-13 0.7 docs
pass — ranks 4–5 stay here, not quality.md Open.

**Owner of these notes:** this file. Ranked later-consideration items stay
here. Do **not** copy the tables into [`quality.md`](./quality.md) Open.
When an item becomes a real slice, give it the next unused Q-id in quality.md
and link back. Existing Open row **Q-41** is the remaining high-leverage test
program (**Q-30** Completed); this file is the source of the comparison, not a
second backlog.

Core / Fulcrum product contrasts stay in [`architecture.md`](./architecture.md).
This page is **other full-node implementations** we might steal tests,
designs, or serving ideas from — without becoming a UTXO node or a Core
`bitcoin.conf` clone.

Sources at write time:

| Project | Tree / docs |
|---------|-------------|
| **Hornet** | [tobysharp/hornet](https://github.com/tobysharp/hornet) `main` @ [`151462fa`](https://github.com/tobysharp/hornet/commit/151462fa5ceece39c159674886dcfa6cfe9b1234), [docs/overview.md](https://github.com/tobysharp/hornet/blob/main/docs/overview.md), [spec.html](https://hornetnode.org/spec.html), [`spec.h`](https://github.com/tobysharp/hornet/blob/main/src/hornetlib/consensus/rules/spec.h), arXiv [2509.15754](https://arxiv.org/abs/2509.15754) |
| **satd** | [epochbtc/satd](https://github.com/epochbtc/satd), [CORE_DIFFERENCES.md](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md), [E2E_TESTING.md](https://github.com/epochbtc/satd/blob/master/docs/E2E_TESTING.md), [`fuzz/fuzz_targets/block_differential.rs`](https://github.com/epochbtc/satd/blob/master/fuzz/fuzz_targets/block_differential.rs) |

---

## What each one is

| | **rbitcoin** | **Hornet** | **satd** |
|--|--|--|--|
| Thesis | Relational **archive** (no UTXO), pure-Rust scripts, in-process Electrum/Esplora, map-free Linux IO | **Spec-first** C++ consensus + custom UTXO LSM; IBD as a demo of the spec | **Core drop-in** (UTXO + `blocks/` + `bitcoin.conf`) with extra APIs in one process |
| Consensus | Independent Rust; Core JSON corpora + [`consensus-tests.md`](./consensus-tests.md); **no** `libbitcoinconsensus` | Named declarative rules in `spec.h` / DSL (published [spec.html](https://hornetnode.org/spec.html) H01–S09; unreleased `spec.h` merges S02 into S03); isolated from storage | Rust engine **plus** C++ `libbitcoinconsensus` shadow |
| Store | Class A/B/C tables, spent annotations ([`SCHEMA.md`](../SCHEMA.md)) | Age-stratified UTXO LSM, `ChainTree` + sidecars | RocksDB coins + Core-shaped flat files |
| IBD | Multi-peer, lookup→load→scripts→write ([`concurrency.md`](./concurrency.md)); default mainnet milestone anchored at block 966143 | Single-peer concurrent UTXO pipeline; claims ~15 min assumevalid on 32 cores | “Swarm” parallel download + speculative verify |
| Wallet APIs | Native Electrum + Esplora; SH optional and can **lag** tip ([`COMPAT.md`](../COMPAT.md)) | None yet | Native Electrum + Esplora + BIP 157; indexes **atomic** with `connect_block` |
| Maturity | Experimental 0.x; Core functional `run` set is **Q-41** | Spec + IBD node; mempool/multi-peer still future | Operator-facing 0.3–0.4, Docker signet demo |

Hornet IBD numbers are a UTXO + assumevalid + fat-core story. They are not a
template for our write/pin/`tx.head` path ([`ibd-memory.md`](./ibd-memory.md)).

satd’s compatibility story is the opposite of ours: they want an existing
`bitcoin.conf`. We want an honest subset ([`COMPAT.md`](../COMPAT.md)).

---

## Tests worth taking

### 1. satd `block_differential` vs a live `bitcoind` (highest leverage)

[`fuzz/fuzz_targets/block_differential.rs`](https://github.com/epochbtc/satd/blob/master/fuzz/fuzz_targets/block_differential.rs):
mutate a block, grind PoW onto a shared genesis tip, run **in-process**
accept, `submitblock` the same bytes to Core, compare **accept vs reject
only** (not first-fault strings). Harness failures exit 2 so Docker flakes
are not filed as consensus bugs.

In-tree **Q-30** slices against official **v32.1** `bitcoind` (SHA256-pinned
tarball, not Docker, not the sparse submodule):
`fuzz/fuzz_targets/block_differential.rs` (height-1),
`block_spend_differential.rs` (height-101 mature-pad spend), and
`block_fork_differential.rs` (2-block heavier fork / reorg dual-submit).
Verdict-only; harness `exit 2` vs finding `panic!`. BIP324 application
contents are ASan (`v2_contents`); a live Core v2 session (`v2_session`)
handshakes then writes fuzzed app contents (not a `submitblock` compare).
Compact reconstruct vs Core `getblocktxn` (`cmpct_differential`) is landed.
Script-mutating vs Core `submitblock` (`script_differential`) is landed
(fuzzer bytes run as scriptPubKey; JSON corpora stay static). Compact reorg
via child-first `drain_pending` vs Core (`cmpct_reorg_differential`) is
landed. N-block reorg (`block_reorg_n_differential`) and BIP68 CSV-age
(`block_csv_differential`) are in-tree; nightly jobs wait on `fuzz.yml`.
**Q-30** is Completed. Live Core HB `cmpctblock` announce is not a
leftover Open row. Fuzzamoto 001–023 stay as they were.

Their curated single-fault file (reason-string parity) is less useful; we
already pin reject *class* in [`consensus-tests.md`](./consensus-tests.md).

### 2. satd cross-surface E2E

One test: broadcast on Esplora, then the tx is visible on JSON-RPC **and**
Electrum (`test_e2e_cross_surface_esplora_broadcast_visible_in_rpc_and_electrum`).
Their E2E doc: one process, one store → a write on any surface must show on
every read surface. In-tree pin:
`rbitcoin-test` `--test suite cross_surface::`
`esplora_broadcast_visible_in_rpc_and_electrum` (Esplora `POST /tx` → RPC
`getrawmempool` + Electrum `get_mempool` / `get_history` on one `run_p2p`
datadir). Casa/Sparrow numbers stay host-only
([`OPERATOR.md`](../OPERATOR.md) Client benchmark).

### 3. Hornet block-validation rules ↔ our tests

[hornetnode.org/spec.html](https://hornetnode.org/spec.html) is the published
table (H01–H06, L01–L13, C01–C07, S01–S09). Hornet `main` `spec.h` @
`151462fa` is the same graph except **S02 `ValidateInputPrevoutsCreated` is
folded into S03** (`ValidateInputPrevoutsUnspent`: an input must reference a
prevout that exists and is still unspent). Wording nits only elsewhere (H02
“MUST achieve” vs “MUST NOT exceed”; H04 “strictly greater”; H05 `<= now+2h`).

This table is the Hornet checklist. The witness is the matrix ID in
[`consensus-tests.md`](./consensus-tests.md). Do not copy test names or
reject strings here. Do not import Hornet DSL. Selector:
`./scripts/test-hornet-rules.sh`.

| ID | Hornet rule (`spec.h` / spec.html) | Our pin |
|----|-------------------------------------|---------|
| **H01** | Parent hash is a valid header | **H1**, **H2** |
| **H02** | Header hash `<=` claimed target | **H7** |
| **H03** | `nBits` matches difficulty adjust | **H5**; testnet 20 min gap **H10** |
| **H04** | `time > MTP(11)` | **H3** |
| **H05** | `time <= now + 2h` | **H8** |
| **H06** | Version not retired by BIP34/66/65 | **H9** |
| **L01** | ≥1 transaction | **S1** |
| **L02** | Merkle root matches unique txid tree | **S6** |
| **L03** | Stripped size `<= 1_000_000` | **S14** |
| **L04** | First tx is the only coinbase | **S2**, **S3** |
| **L05** | Legacy sigop **count** `<= 20_000` | Hornet counts sigops. We charge cost. **S11** |
| **L06** | ≥1 input | **S15** |
| **L07** | ≥1 output | **S13** |
| **L08** | Tx stripped size `<= 1_000_000` | **S16** |
| **L09** | Output amounts non-negative | `Amount` is `u64`, so a negative output is unrepresentable. The sum cap is **S10** |
| **L10** | Output sum `<= 21e6` BTC | **S10** |
| **L11** | No duplicate outpoints in a tx | **S17** |
| **L12** | Coinbase scriptSig length `2..=100` | **S9** |
| **L13** | Non-coinbase inputs non-null | **S18** |
| **C01** | All txs final at height / locktime | **C36** |
| **C02** | Pre-SegWit block has no witness | **S8** |
| **C03** | Weight `<= 4_000_000` WU | **S4** |
| **C04** | BIP34 coinbase height push | **S7** |
| **C05** | Witness data ⇒ commitment | **S8** |
| **C06** | Commitment ⇒ 32-byte nonce | **S8** |
| **C07** | Commitment matches witness merkle + nonce | **S8** |
| **S01** | BIP30 unique unspent creates | **C37** |
| **S02** | Prevout exists *(merged into S03 in `spec.h`)* | **C38** |
| **S03** | Prevout still unspent | **C38** |
| **S04** | Sigop **cost** `<= 80_000` | Legacy count **S11**. P2SH and witness cost **S12** |
| **S05** | Coinbase `<=` subsidy + fees | **C22** |
| **S06** | Tx `out <= in` | **C40** |
| **S07** | Scripts succeed | **C15**, **C16** |
| **S08** | BIP68 relative finality | **C41** |
| **S09** | Coinbase maturity 100 | **C28** |

### 4. satd E2E flake-gate

`workflow_dispatch` that loops the suite 10–30 times, fail-fast, no
retry-mask. Same idea for Electrum/Esplora + `two_node` instead of treating
a one-off red as “CI flake.”

### 5. satd client canaries

They run real wallet clients in CI. Our Casa/Sparrow numbers live in
`rbitcoin-bench` and stay host-only. A **tiny** Sparrow-shaped Electrum
script in the Core functional harness or a labeled job is closer to **Q-41**
than a TUI.

---

## Designs / ideas worth taking

### From satd (operator and index serving), not the UTXO

| Idea | Why it fits | Why not blindly |
|------|-------------|-----------------|
| **Self-authenticating BIP352 tweak rows** (block hash in the row; stream/replay without trusting the server) | We already have `--sp-tweaks` and Electrum `tweaks.subscribe` ([`OPERATOR.md`](../OPERATOR.md)). Their row shape is a better serve contract than “trust the node.” | Do not make SH/tweaks wait on Class A if that fights write-behind. |
| **`/healthz` + `/readyz` + Prometheus** | Operators and k8s probe these. Logs are not a probe. | Unauthenticated loopback; do not grow a second metrics dialect. `GET /progress` is not one: it is the always-on human view of the long-stage counters that `/metrics` (opt-in) also exports ([`operations.md`](./operator/operations.md#progress)). |
| **Explicit reorg log** (`reorg.log` + `getreorghistory`) | Tip-follow already disconnects hopeless forks ([`ibd-memory.md`](./ibd-memory.md)); a durable ring is cheap evidence. | Webhooks / MCP / TUI are satd product, not ours. |
| **SIGHUP for hot mempool/relay knobs** | Useful once we have more policy flags. | We already log to stdout; do not cargo-cult Core `debug.log` reopen. satd’s split (`SIGHUP` config, `SIGUSR1` TLS) is the right shape **if** we add native TLS. |
| **Config: unknown keys fatal, unsupported-but-recognized warned** | Honest operator surface. We already lean this way. | Full Core `bitcoin.conf` drop-in is a satd goal, not ours. |
| **BIP 157/158** | [`COMPAT.md`](../COMPAT.md) slots 22–27 are explicit “not product.” Neutrino wallets are a later wallet-backend ask. | Do not start it until Electrum/Esplora claimed surface is boring. |

### From Hornet (clarity), not the UTXO engine

| Idea | Why it fits | Why not |
|------|-------------|---------|
| **Consensus as a pure function of (block, context) with no store types in the rule** | We already push that in `rbitcoin-consensus`. Hornet is stricter: no `CCoinsView` in the spec. Keep store out of structure/script rules. | Their UTXO LSM / out-of-order coins apply is the anti-thesis of Class A never leading tip ([`architecture.md`](./architecture.md)). |
| **`ChainTree` = main chain as a dense array, forks as a small forest** | Header-side locality; reorgs stay near the tip. | We already have header plans + most-work rewind from the IBD task only. Do not add a second header representation. |
| **Sidecars that reorg with the chain** | Mental model for “metadata that must move with tip.” | ConfirmParentCache / SH RAM head already play that role. |
| **io_uring + high QD for the hot index** | We already have purpose-built uring machines ([`io-modality.md`](./io-modality.md)). Their “batch + queue depth” is the same instinct as fill/idx. | Do not flatten our machines to `pread_batch` ([`io-modality.md`](./io-modality.md)). |

Hornet’s 10× Core IBD is **assumevalid + UTXO cache + 32 cores + single
peer**. Copying that would mean reintroducing a coins view.

---

## Explicitly do not copy

- **satd `libbitcoinconsensus` shadow.** [`architecture.md`](./architecture.md):
  pure-Rust scripts, no dual-eval. Shadow is how they sleep at night; we use
  Core JSON + functional + findings instead.
- **satd RocksDB coins + atomic address index.** SH lag is a product choice.
  Making SH wait on Class A would regress tip-accept.
- **Hornet UTXO LSM / speculative out-of-order apply.** Conflicts with
  “Class A never leads tip.”
- **satd MCP, TUI, policy DSL, prune, AssumeUTXO, ZMQ.** Non-goals or later
  ([`quality.md`](./quality.md) Won't fix / [`COMPAT.md`](../COMPAT.md)
  deferred). AssumeUTXO is meaningless without a UTXO set.
- **Hornet DSL as a second spec book.** [`consensus-tests.md`](./consensus-tests.md)
  is the owner.

---

## Ranked if we spend time later

Not scheduled. Implement a row only when the user names it. Do not treat
this as Open rank. Promote into [`quality.md`](./quality.md) only when
scheduling a slice.

| Rank | Item | Source | Lands in |
|-----:|------|--------|----------|
| 1 | Height-1 + spend-pad + 2-block fork vs v32.1 `bitcoind`; BIP324 `v2_contents` ASan + live Core `v2_session` + compact reconstruct vs `getblocktxn` + script-mutating vs Core + compact reorg via `drain_pending` (**landed**; **Q-30** Completed) | satd `block_differential` | **Q-30** / [`TESTING.md`](../TESTING.md) |
| 2 | One cross-surface scenario: Esplora `POST /tx` → Electrum history + RPC mempool (**landed**; `esplora_broadcast_visible_in_rpc_and_electrum`) | satd E2E | `rbitcoin-test` `--test suite cross_surface::` |
| — | ~~Hornet spec.html vs consensus-tests.md gap hunt~~ **done 2026-09-04** (table in this file; pins in `structure_rule_tests` / `header.rs` / `consensus_rules`) | Hornet | this file + [`consensus-tests.md`](./consensus-tests.md) |
| 4 | `/healthz` + `/readyz` on the node listen; Prometheus as a flag (**landed**; `--health-listen`, `--metrics`) | satd | node / [`operations.md`](./operator/operations.md#health-probes-and-metrics) |
| 5 | BIP352 serve: hash-bind tweak batches so a client can audit the stream | satd row idea on our tweaks path | Electrum tweaks / [`OPERATOR.md`](../OPERATOR.md) |

1, 2, and 4 landed. 5 is small product. None require becoming a UTXO node or a
Core conf clone.

---

*Living notes. Prefer updating this file when Hornet/satd trees move, or when
a ranked item is promoted to a Q-id.*
