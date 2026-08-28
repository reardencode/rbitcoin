# Peer full nodes: Hornet and satd

Date: 2026-08-25. Research snapshot (Hornet `main`, satd `master`, public
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
| **Hornet** | [tobysharp/hornet](https://github.com/tobysharp/hornet), [docs/overview.md](https://github.com/tobysharp/hornet/blob/main/docs/overview.md), [spec.html](https://hornetnode.org/spec.html), arXiv [2509.15754](https://arxiv.org/abs/2509.15754) |
| **satd** | [epochbtc/satd](https://github.com/epochbtc/satd), [CORE_DIFFERENCES.md](https://github.com/epochbtc/satd/blob/master/CORE_DIFFERENCES.md), [E2E_TESTING.md](https://github.com/epochbtc/satd/blob/master/docs/E2E_TESTING.md), [`fuzz/fuzz_targets/block_differential.rs`](https://github.com/epochbtc/satd/blob/master/fuzz/fuzz_targets/block_differential.rs) |

---

## What each one is

| | **rbitcoin** | **Hornet** | **satd** |
|--|--|--|--|
| Thesis | Relational **archive** (no UTXO), pure-Rust scripts, in-process Electrum/Esplora, map-free Linux IO | **Spec-first** C++ consensus + custom UTXO LSM; IBD as a demo of the spec | **Core drop-in** (UTXO + `blocks/` + `bitcoin.conf`) with extra APIs in one process |
| Consensus | Independent Rust; Core JSON corpora + [`consensus-tests.md`](./consensus-tests.md); **no** `libbitcoinconsensus` | 34 named declarative rules in `spec.h` / DSL; isolated from storage | Rust engine **plus** C++ `libbitcoinconsensus` shadow |
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

### 3. Hornet’s published rule table as a checklist

[hornetnode.org/spec.html](https://hornetnode.org/spec.html) is 34
invariants (H01–H06, L01–L13, C01–C07, S01–S09). We already own a similar
matrix in [`consensus-tests.md`](./consensus-tests.md). Worth a one-pass
**gap hunt**, then add missing **named rows there** (not a second matrix
here). Candidates at write time:

| Hornet ID | Rule | Notes |
|-----------|------|--------|
| **L03** | 1 000 000-byte **stripped** size | Distinct from 4 M WU (our S4) |
| **C02** | Pre-SegWit block must not carry witness | |
| **C06 / C07** | Witness nonce + witness merkle | We have commitment tests; confirm nonce/merkle are named |
| **S04** | Total sigop **cost** 80 000 | They have `validate_sigop_costs_test.cpp` |
| **S01** | BIP30 exceptions as explicit table rows | Fuzzamoto BIP30 cluster is closed; the *table* is still useful |

Do not import Hornet DSL or their C++ `Rule{…}` array.

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
| 3 | Hornet spec.html vs [`consensus-tests.md`](./consensus-tests.md): add missing named rows | Hornet | `consensus-tests.md` |
| 4 | `/healthz` (and maybe `/readyz`) on the node listen; Prometheus later as a flag | satd | node / [`OPERATOR.md`](../OPERATOR.md) |
| 5 | BIP352 serve: hash-bind tweak batches so a client can audit the stream | satd row idea on our tweaks path | Electrum tweaks / [`OPERATOR.md`](../OPERATOR.md) |

1–3 are tests. 4–5 are small product. None require becoming a UTXO node or a
Core conf clone.

---

*Living notes. Prefer updating this file when Hornet/satd trees move, or when
a ranked item is promoted to a Q-id.*
