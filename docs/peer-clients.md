# Peer full nodes: Hornet and satd

Date: 2026-09-04. Research snapshot (Hornet `main` @ `151462fa`, satd `master`, public
docs). Analysis only at write time.

**Owner of these notes:** this file. Ranked later-consideration items stay
here. Do **not** copy the tables into [`quality.md`](./quality.md) Open.
When an item becomes a real slice, give it the next unused Q-id in quality.md
and link back. Existing Open rows (**Q-30**, **Q-41**) already cover the
highest-leverage tests; this file is the source of the comparison, not a
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
| IBD | Multi-peer, lookup→load→scripts→write ([`concurrency.md`](./concurrency.md)); default `--milestone 840000` | Single-peer concurrent UTXO pipeline; claims ~15 min assumevalid on 32 cores | “Swarm” parallel download + speculative verify |
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

That is the missing piece of **Q-30** ([`quality.md`](./quality.md),
[`TESTING.md`](../TESTING.md) § Core differential). We already have Core
JSON corpora, `structure_rule_tests`, and an *external* fuzzamoto campaign
([`external_findings/`](./external_findings/), 001–022). In-tree fuzz is
still `block_wire` + nightly `fuzz.yml`. A nightly dual-submit job (Docker
`bitcoind`, verdict-only) would catch connect-path splits JSON fixtures
never hit.

Their curated single-fault file (reason-string parity) is less useful; we
already pin reject *class* in [`consensus-tests.md`](./consensus-tests.md).

### 2. satd cross-surface E2E

One test: broadcast on Esplora, then the tx is visible on JSON-RPC **and**
Electrum (`test_e2e_cross_surface_esplora_broadcast_visible_in_rpc_and_electrum`).
Their E2E doc: one process, one store → a write on any surface must show on
every read surface. We have Electrum and Esplora tests and `rbitcoin-bench`
Casa/Sparrow (host-only, [`OPERATOR.md`](../OPERATOR.md) Client benchmark).
We do **not** have one CI test that mines/broadcasts and asserts all three.
Cheap, and it hits SH lag / mempool overlay bugs we already care about
([`concurrency.md`](./concurrency.md) Electrum/Esplora roles).

### 3. Hornet block-validation rules ↔ our tests

[hornetnode.org/spec.html](https://hornetnode.org/spec.html) is the published
table (H01–H06, L01–L13, C01–C07, S01–S09). Hornet `main` `spec.h` @
`151462fa` is the same graph except **S02 `ValidateInputPrevoutsCreated` is
folded into S03** (`ValidateInputPrevoutsUnspent`: an input must reference a
prevout that exists and is still unspent). Wording nits only elsewhere (H02
“MUST achieve” vs “MUST NOT exceed”; H04 “strictly greater”; H05 `<= now+2h`).

This table is the Hornet checklist. Named rows for rules we own stay in
[`consensus-tests.md`](./consensus-tests.md). Do not import Hornet DSL.

Happy = accept at/under the limit. Boundary = exact limit accept + one-past
reject (or the Core-equivalent edge). Tests live in
`crates/rbitcoin-consensus/src/block/hornet_rule_tests.rs` unless noted.

| ID | Hornet rule (`spec.h` / spec.html) | Happy | Boundary / reject |
|----|-------------------------------------|-------|-------------------|
| **H01** | Parent hash is a valid header | `hornet_header_and_spending_boundaries` (`validate_header` height 1) | `h2_rejects_bad_prev_link` |
| **H02** | Header hash `<=` claimed target | same journey (regtest grind) | `h02_rejects_header_hash_above_target` (mainnet bits, nonce misses) |
| **H03** | `nBits` matches difficulty adjust | same journey | `h5_regtest_rejects_wrong_bits`; testnet 20 min min-diff: `testnet_min_difficulty_after_20_minute_gap` |
| **H04** | `time > MTP(11)` | journey: `mtp+1` accepts | journey + `h3_rejects_timestamp_not_after_mtp`: `time == mtp` rejects |
| **H05** | `time <= now + 2h` | `h05_timestamp_exactly_two_hours_accepts_plus_one_rejects` (`now+7200`) | same test (`now+7201`); `h8_rejects_timestamp_too_far_in_future` |
| **H06** | Version not retired by BIP34/66/65 | `h06_version_floors_at_bip34_66_65` (v2 @ BIP34, v3 @ BIP66, v4 @ BIP65 / regtest h=1) | same test (v1 @ BIP34, v2 @ BIP66, v3 @ BIP65 / regtest v3) |
| **L01** | ≥1 transaction | `l01_accepts_single_coinbase_rejects_empty` | same (`txdata` empty) |
| **L02** | Merkle root matches unique txid tree | `l02_accepts_matching_merkle_rejects_mismatch` | same; odd-leaf: `merkle_odd_leaf_duplication_is_unique_root` |
| **L03** | Stripped size `<= 1_000_000` | `l03_stripped_size_1_000_000_accepts_1_000_001_rejects` | same (`1_000_001`) |
| **L04** | First tx is the only coinbase | `l04_accepts_coinbase_first_only_rejects_later_or_missing` | same (non-coinbase first / second coinbase) |
| **L05** | Legacy sigop **count** `<= 20_000` | `l05_legacy_sigops_20_000_accepts_20_001_rejects` | same (`20_001`); `s11_rejects_excessive_legacy_sigops` |
| **L06** | ≥1 input | `l06_accepts_one_input_rejects_empty_vin` | same (empty `vin` on non-coinbase) |
| **L07** | ≥1 output | `l07_accepts_one_output_rejects_empty_vout` | same; `s13_rejects_coinbase_empty_vout`; `c1_non_coinbase_empty_outputs_rejected` |
| **L08** | Tx stripped size `<= 1_000_000` | `l08_tx_stripped_size_1_000_000_accepts_1_000_001_rejects` | same (`check_tx_local`) |
| **L09** | Output amounts non-negative | `l09_zero_output_is_non_negative` (`Amount::ZERO`) | rust-bitcoin `Amount` is `u64` — negative is unrepresentable |
| **L10** | Output sum `<= 21e6` BTC | `l10_max_money_accepts_max_plus_one_rejects` (exactly `MAX_MONEY`) | same (`MAX_MONEY+1` and two-output overflow); `s10_*` |
| **L11** | No duplicate outpoints in a tx | `l11_unique_inputs_accept_duplicate_reject` | same (two identical prevouts) |
| **L12** | Coinbase scriptSig length `2..=100` | `l12_coinbase_scriptsig_2_and_100_accept_1_and_101_reject` | same; `s9_rejects_bad_cb_length_*` |
| **L13** | Non-coinbase inputs non-null | `l13_non_coinbase_null_prevout_rejected_non_null_accepted` | same (null among two inputs) |
| **C01** | All txs final at height / locktime | journey: `locktime=100` at height 101; `finality_tests::final_when_locktime_zero` | journey: `locktime==height`; `height_locktime_not_final_until_height` (`lt < height`) |
| **C02** | Pre-SegWit block has no witness | `c02_pre_segwit_accepts_no_witness_rejects_witness` | same; `s8_mainnet_rejects_witness_before_segwit` |
| **C03** | Weight `<= 4_000_000` WU | `c03_weight_4_000_000_accepts_4_000_001_rejects` (no-witness 4 M and witness 4 M) | same (`4_000_001` via +1 witness byte); `s4_rejects_overweight_block` |
| **C04** | BIP34 coinbase height push | `c04_bip34_height_push_accepts_at_activation_rejects_missing` | same; `s7_*` activation / pre-activation |
| **C05** | Witness data ⇒ commitment | `c05_c06_c07_witness_commitment_nonce_merkle` (no witness, no commitment) | same (witness, no commitment); `s8_rejects_missing_witness_commitment` |
| **C06** | Commitment ⇒ 32-byte nonce | same test (exactly one 32-byte reserved) | same (empty nonce); `s8_rejects_empty_or_multi_item_coinbase_witness_reserved` |
| **C07** | Commitment matches witness merkle + nonce | same test (`apply_witness_commitment`) | same (wrong hash); `s8_rejects_wrong_witness_commitment` |
| **S01** | BIP30 unique unspent creates | every connecting block; exception table `is_bip30_repeat_matches_core` (91842 / 91880) | `bip30_rejects_unspent_connected_sibling` |
| **S02** | Prevout exists *(merged into S03 in `spec.h`)* | journey OP_TRUE spend of height-1 coinbase | journey: random txid → `MissingPrevout`; `c8_same_block_child_before_parent_rejected` |
| **S03** | Prevout still unspent | journey first spend | journey second spend of same outpoint; `c2_same_block_double_spend_rejected` |
| **S04** | Sigop **cost** `<= 80_000` | `s04_sigop_cost_80_000_accepts_80_004_rejects` (20 000×CHECKSIG) | same (`20_001` → cost 80 004); `sigop_cost_tests::*` (P2SH/witness) |
| **S05** | Coinbase `<=` subsidy + fees | journey exact 50 BTC empty pads; `s05_subsidy_exact_halving_boundaries` | journey `subsidy+1` sat; `c7_coinbase_excess_subsidy_rejected` |
| **S06** | Tx `out <= in` | journey `in==out` (zero fee) | journey `in+1`; `c6_value_in_less_than_out_rejected` |
| **S07** | Scripts succeed | journey anyone-can-spend `OP_TRUE`; Core `script_tests` / `tx_valid` | Core `tx_invalid` / `script_tests` reject rows |
| **S08** | BIP68 relative finality | journey `nSequence=10` at height 101; `bip68_height_relative_lock` | journey `nSequence=200` at 101; `finality_tests` 109/110 edge |
| **S09** | Coinbase maturity 100 | journey spend at height 101 (`created+100`) | journey spend at height 100; `c5_immature_coinbase_spend_rejected` |

Connect-path journey: `rbitcoin-test` `hornet_header_and_spending_boundaries`.

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
| **Self-authenticating BIP352 tweak rows** (block hash in the row; stream/replay without trusting the server) | We already have `--sptweaks` and Electrum `tweaks.subscribe` ([`OPERATOR.md`](../OPERATOR.md)). Their row shape is a better serve contract than “trust the node.” | Do not make SH/tweaks wait on Class A if that fights write-behind. |
| **`/healthz` + `/readyz` + Prometheus** | Operators and k8s probe these. Logs are not a probe. | Unauthenticated loopback; do not grow a second metrics dialect. |
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

Do not treat this as Open rank. Promote into [`quality.md`](./quality.md)
only when scheduling a slice.

| Rank | Item | Source | Lands in |
|-----:|------|--------|----------|
| 1 | In-tree **verdict-only** differential fuzz vs Docker `bitcoind` (harness-vs-finding exit codes) | satd `block_differential` | **Q-30** / [`TESTING.md`](../TESTING.md) |
| 2 | One cross-surface scenario: Esplora `POST /tx` → Electrum history + RPC mempool | satd E2E | scenarios / Electrum–Esplora tests |
| — | ~~Hornet spec.html vs consensus-tests.md gap hunt~~ **done 2026-09-04** (table in this file, pins in `hornet_rule_tests.rs`) | Hornet | this file + [`consensus-tests.md`](./consensus-tests.md) |
| 4 | `/healthz` (and maybe `/readyz`) on the node listen; Prometheus later as a flag | satd | node / [`OPERATOR.md`](../OPERATOR.md) |
| 5 | BIP352 serve: hash-bind tweak batches so a client can audit the stream | satd row idea on our tweaks path | Electrum tweaks / [`OPERATOR.md`](../OPERATOR.md) |

1–2 are remaining tests. 4–5 are small product. None require becoming a UTXO node or a
Core conf clone.

---

*Living notes. Prefer updating this file when Hornet/satd trees move, or when
a ranked item is promoted to a Q-id.*
