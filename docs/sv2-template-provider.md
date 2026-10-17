# SV2 template provider (TDP server)

Design record for **Q-64**. Plans A–C are in tree
([`quality.md`](./quality.md) keeps Q-64 off the open list). The steps
below are how they landed, not work left to start.
Cycle and step shape: [agent contract](./how-we-plan.md#agent-contract).

| Plan | Outcome | Ships flags |
|------|---------|-------------|
| **A** | Landed. GBT and `generate` build from `MempoolHub::select_block_template` | none |
| **B** | Landed. A Job Declarator Client mines a block through the node's TP | `--sv2-tp-listen`, `--sv2-tp-authority-sec` / `--sv2-tp-authority-sec-file`, `--sv2-tp-cert-validity`, `--sv2-tp-stale-grace` |
| **C** | Landed. Templates refresh on fee gain with the tip unchanged | `--sv2-tp-fee-delta`, `--sv2-tp-template-interval` |
| **D** | A Job Declarator Server validates custom jobs and submits their solutions through the TP ([`sv2-job-validation.md`](./sv2-job-validation.md)) | none (per-session `SetupConnection` flag) |

B was not split further: a listener that serves templates without
tip-change push or `SubmitSolution` makes miners work stale tips or lose
found blocks. The smallest safe operator surface is B whole. Live flags:
[`OPERATOR.md`](../OPERATOR.md) and [`COMPAT.md`](../COMPAT.md).

## Goal

Operator runs `rbitcoin-node --sv2-tp-listen 127.0.0.1:8442
--sv2-tp-authority-sec <key>`. A Stratum v2 Job Declarator Client or pool
connects over Noise_NX TCP, completes `SetupConnection(protocol=2)`, sends
`CoinbaseOutputConstraints`, and from then on is **pushed** `NewTemplate` /
`SetNewPrevHash` when the tip changes and when template fees rise by a
configured delta. `RequestTransactionData` returns the retained template's
transactions; `SubmitSolution` assembles the full block and submits it
through the normal accept path. TDP replaces `getblocktemplate` polling for
these clients (sv2-spec 07).

Reference state machine: sv2-apps `bitcoin-core-sv2` (Bitcoin Core IPC →
TDP). This TP is in-process: the template source is the node's own mempool
and tip, no IPC hop.

## Step 0 finding (spike, 2026-09-25): reuse stratum-core

Throwaway workspace member depending on the crates.io wire crates:
`noise_sv2` 2.0.0, `codec_sv2` 7.0.0 (`noise_sv2` feature), `framing_sv2`
8.0.0, `binary_sv2` 7.0.0, `template_distribution_sv2` 7.0.0,
`parsers_sv2` 0.6.0, `common_messages_sv2` 9.0.0.

- `cargo deny check`: advisories, bans, licenses, sources ok. No new
  license allow entry.
- No second `bitcoin`: the wire crates do not depend on it. New duplicate
  versions (warn only): `secp256k1` 0.28.2 + `secp256k1-sys` 0.9.2
  (`noise_sv2` only), `bitcoin_hashes` 0.13, `hex-conservative` 0.1,
  `cpufeatures`, `crypto-common`. Lock delta: 29 packages (AEAD stack:
  `chacha20poly1305`, `aes-gcm`, …, plus unused `mining_sv2` /
  `job_declaration_sv2` / `extensions_sv2` pulled by `parsers_sv2`).
- `x86_64-unknown-linux-musl` release link: static-pie; both libsecp
  builds coexist under distinct symbol prefixes (`rustsecp256k1_v0_9_2_*`,
  `rustsecp256k1_v0_10_0_*`).
- In-memory roundtrip: NX handshake with the authority keypair built from
  the **workspace** `secp256k1` 0.29 (`Responder::from_authority_kp` /
  `Initiator::from_raw_k` take raw bytes, so 0.28 types never leave
  `noise_sv2`), then `SetupConnection`, a 12-deep `NewTemplate`, and a
  3 MB `RequestTransactionData.Success` across Noise chunks, each decoded
  back field-equal.
- Published TDP field set matches this roadmap: `CoinbaseOutputConstraints
  {max_additional_size: u32, max_additional_sigops: u16}`, no
  `coinbase_witness` on `NewTemplate`.

Decision: **reuse**. Hand-rolling stays the fallback if a later bump fails
`cargo deny`. `parsers_sv2` is optional: B may decode with `binary_sv2::
from_bytes` on the known TDP / common message types and drop it (and the
three unused subprotocol crates) if it adds nothing.

## Constraints (all plans)

Operator-visible limits (session cap, setup and write deadlines, constraint
rebuild rate, retained templates, no client authentication, no templates
during IBD) live in
[`operator/interfaces.md`](./operator/interfaces.md#stratum-v2-template-provider).
Do not copy them here.

- New crate `crates/rbitcoin-sv2` (Plan B), service pattern of
  electrum/esplora: depends on `rbitcoin-net` (`ChainHub`, `MempoolHub`) /
  `rbitcoin-consensus` / `rbitcoin-store` (merkle); wired in `rbitcoin-node`
  `run.rs` behind flags. Nothing starts without `--sv2-tp-listen`.
- `binary_sv2` byte-buffer types and `noise_sv2`'s `secp256k1` 0.28 stay
  inside `rbitcoin-sv2`; consensus decode uses the workspace
  `rust-bitcoin`. No sv2 types in other crates' APIs.
- Reactor rule: template builds, solution assembly, and proposal
  validation run in a blocking region, never on tokio workers.
  `MempoolHub` accessors assert not-reactor. A proposal validation also
  runs off its session loop (D11): the session never waits on one.
- Named RAM trade (CONTRIBUTING 9): each session retains its templates
  (up to 64) holding the mempool's own `Arc<Transaction>` bodies, about
  24 KB of pointers per full template while the txs are still pooled.
  A body that leaves the pool stays alive while a template holds it: at
  most 64 × ~4 MB per session (~2 GB at the default cap of 8) if every
  template's txs were replaced, which costs replacement fees each time.
  Retention is required: the mempool may evict a tx
  before `RequestTransactionData` or `SubmitSolution` arrives. Stale grace
  (default 10 s) after a tip change, then drop (mirrors sv2-tp).
- Write deadline is per write call, not per frame, so a slow reader still
  receives a multi-MB `RequestTransactionData.Success`. The 30 s close is
  the operator page above.
- Client frame cap, per message type: a `ProposeTemplate` payload over
  `MAX_PROPOSE_TEMPLATE_PAYLOAD` (~6.5 MB: 8 fixed bytes, three `B064K`
  fields for the coinbase prefix, suffix, and excess data, 65535 wtxids,
  and a block's worth of `B016M` txs) closes the
  session; every other client payload closes past `MAX_CLIENT_PAYLOAD`
  (65557 bytes: `SubmitSolution`'s 20 fixed bytes plus a full `B064K`
  coinbase). codec_sv2 decrypts the header into a private buffer and reads
  a frame one chunk at a time, so the type is only known with the whole
  frame: the reader counts encrypted bytes per frame against the larger
  cap and closes before reading the chunk that would pass it, then applies
  the per-type cap once the frame is whole. Named RAM trade: one in-flight
  client frame of ≤ ~6.5 MB per session, ≤ ~52 MB at `MAX_SESSIONS`,
  instead of the ~16 MB the 24-bit length allows.
- Per-session budget: weight `MAX_BLOCK_WEIGHT − max(1168 +
  4·coinbase_output_max_additional_size, 2000)` WU (sv2-spec 07 §7.1);
  sigops start at `coinbase_output_max_additional_sigops` (Core
  `BlockAssembler` semantics: the client's value replaces the 400 default
  reserve). Each client sizes its own templates.
- Noise is the only mode (mandatory for remote TDP). No plaintext operator
  flag; tests drive the shipped Noise path.
- The only `SetupConnection` flag is `REQUIRES_JOB_VALIDATION` (bit 0,
  Plan D), echoed in `Success.flags`; any other set bit →
  `SetupConnection.Error` echoing the full set; `protocol != 2` or no
  version-2 overlap → Error and close.
- `template_id` strictly increasing per session.
- Coinbase split (sv2-spec 07 §7.2): `coinbase_prefix` is the BIP34 height
  push (≤ 8 bytes, start of scriptSig); `coinbase_tx_value_remaining` =
  subsidy + Σ fees; `coinbase_tx_outputs` is the raw concatenation (no
  CompactSize prefix) with the witness-commitment OP_RETURN **last**, from
  `rbitcoin_consensus::witness_commitment_script` (already the one owner,
  used by GBT) with a 32-byte zero reserved value. A `SubmitSolution`
  coinbase with an empty input witness and a witness-commitment output
  gets that reserved value filled in before assembly (the txid, and so
  the merkle root, does not cover it); a coinbase without a commitment
  or with a non-empty witness is submitted as sent.
- `SetNewPrevHash.target` == nBits target here (no weak blocks).
- No templates during IBD: the same refusal gate as `getblocktemplate`.
- `SubmitSolution` has no error message in TDP: undecodable or
  unknown-template solutions are logged and dropped; decodable ones that
  meet the target are always attempted through `ChainHub::accept_block` (the TP MUST try to
  broadcast work on its templates).
- `SubmitSolution.header_timestamp` window (sv2-spec 07 §7.7: ≥ the sent
  `SetNewPrevHash.header_timestamp` and ≤ that plus wall-clock elapsed) is
  logged, not enforced. A miner clock a few seconds fast still finds a
  consensus-valid block, and `accept_block` applies the consensus bounds
  (> MTP, < now + 2 h); dropping it would lose a real block.
- `SubmitSolution` PoW pre-check: the session folds the coinbase txid over
  the retained template's `merkle_path` (coinbase is leaf 0, always the
  left child), builds the header, and drops the solution unless it meets
  the template's `n_bits` target. Only then does it clone the template's
  txs and call `ChainHub::accept_block`, so a spam of cheap bad-nonce
  solutions never takes `connect_lock`, the compact-block prefill slot, or
  the mempool.
- OPERATOR / COMPAT / NixOS options land in the plan that ships the flag
  (same PR).

## Out of scope

Mining Protocol server (channels), Job Declaration **Server** (Plan D
serves its node backend — job validation and solution submission over
TDP — not the JDP role itself), SV1↔SV2 translator proxy, Job Declarator
Client, weak-block targets below nBits, extension negotiation, per-IP
metering/rate limits. None of these ship; nothing here precludes a later
JD-server plan.

Core's IPC mining interface (`waitNext`) is also out: TDP push covers
these clients, and polling clients already have GBT longpoll and the
Esplora `/block-template` 15 s cache. This replaces the old Q-64 backlog
row ("GBT longpoll / `waitNext`, then Sv2").

---

## Plan A — Caller-budgeted template selection

**Landed.** `getblocktemplate` and regtest `generate` call
`MempoolHub::select_block_template(budget)`. `template_budget(min)` is
this node's budget: template weight, the configured sigop reserve, and
the `-blockmintxfee` floor. The call returns each selected transaction
with its base fee and admission sigop cost from that same read.
GBT `transactions[].fee` / `sigops` and `coinbasevalue` come from it, so
a transaction removed after selection still reports the fee it was
selected with.

`TxGraph::select_block_template(budget, delta)` takes
`SelectBudget { max_weight_wu, reserved_sigops, min_sat_kvb }` and
returns `Vec<Selected { txid, fee_sat, sigop_cost }>` in mining order.
`fee_sat` is the base fee, not the `prioritisetransaction` delta.
`MempoolHub::select_block_template` applies the node's deltas under the
same lock and returns `Vec<(Arc<Transaction>, Selected)>`: the pool's own
bodies, not copies, so a template costs a pointer per tx and a body it
holds outlives eviction or replacement. A larger
`reserved_sigops` or a smaller `max_weight_wu` drops what no longer fits
and still takes a later chunk. A running sigop cost of exactly 80_000
fits; a chunk that would pass 80_000 is skipped.

No new flag.

`select_budgets_sigops_skip_and_continue` pins the budget, the base fee
under a delta, and the exact-80_000 edge. `sigop_adjusted_size_budget_and_reopen`
pins admission against the same cap. `hub_live_journey` reads fee and sigop
cost through the hub call (reserve 0 fits a 79,920-cost tx; a caller
reserving 400 does not). `rpc_regtest_mature_chain_ops` pins GBT `fee` beside
`sigops`.

---

## Plan B — Mine a block through the TP

**Goal:** the operator outcome in [Goal](#goal), minus fee-delta pushes.
Ships the listener, bootstrap, tip push, transaction data, and
`SubmitSolution`. Requires Plan A.

### B1 — Crate skeleton, Noise responder, SetupConnection

- **Contract:** a `noise_sv2` initiator completing the NX handshake against
  the listener and sending `SetupConnection{protocol=2, min_version=2,
  max_version=2, flags=0}` receives `SetupConnection.Success{used_version=2,
  flags=0}`. Nonzero flags → `SetupConnection.Error` echoing them.
  `protocol != 2` or no version-2 overlap → Error and the connection
  closes. With the session cap reached, the next connection is closed
  before the handshake and the existing sessions stay up.
- **Red:** `cargo test -p rbitcoin-sv2 setup_connection_` — loopback TCP,
  in-crate test initiator; success, bad-flags, bad-protocol, and
  (cap + 1)th-connection cases.
- **Green:** `crates/rbitcoin-sv2` (workspace member) with the wire crates
  pinned to the Step 0 set minus `parsers_sv2` (known TDP / common types
  decode with `binary_sv2::from_bytes`); authority-keypair config, listener task,
  per-connection session task driving the `codec_sv2` handshake then the
  common-message branch; session-cap semaphore on accept. Add the
  `rbitcoin-sv2` row to [`CRATES.md`](./CRATES.md) in this commit
  ([`README.md`](./README.md) rule: row with the new file).
- **Refactor:** session state as an enum (`AwaitingSetup`,
  `AwaitingConstraints`, later `Active`), not nested ifs. The Noise
  handshake is a typed prologue (`codec_sv2::Handshake` consumes its
  state), not a phase.
- **Verify:** `cargo test -p rbitcoin-sv2 setup_`

### B2 — Merkle path helper next to the root

- **Contract:** `merkle_branch(leaves, index)` returns the sibling hashes
  from `leaves[index]` to the root, deepest-first; folding them with the
  leaf reproduces `merkle_root_from_txids` for the same list. The coinbase
  path is `index = 0` (the leaf's own value feeds no entry, so the builder
  passes a placeholder). Edge cases: single tx (empty path), odd counts at
  every level.
- **Red:** `cargo test -p rbitcoin-store --lib merkle_path_` — small known
  vectors plus a fold at every index for 1..=9 leaves (pure arithmetic, no
  session reaches it before B3).
- **Green:** helper next to `merkle_root_from_txids`
  (`crates/rbitcoin-store/src/integrity.rs`). The root's owner is the store
  (consensus `merkle_root_bytes` only wraps it), and
  `rbitcoin-query` `merkle_proof` (Electrum `get_merkle`, Esplora
  `merkle-proof`) had its own inline branch loop; one owner for both.
- **Refactor:** root and branch share one level-pairing step;
  `Query::merkle_proof` calls `merkle_branch`.
- **Verify:** `cargo test -p rbitcoin-store --lib merkle_`, Electrum /
  Esplora merkle journeys

### B3 — Template builder, NewTemplate on constraints

- **Contract:** after setup, `CoinbaseOutputConstraints` makes the session
  build in a blocking region and send `NewTemplate{future_template: true}`
  with a strictly increasing `template_id`; a changed constraints message
  rebuilds with the new budget. A resend identical to the last budget,
  once a template on the current prev hash was sent, is a no-op: it
  does not take the mempool lock or send a template (tip events still
  rebuild; mempool gains on an unchanged tip are Plan C). A changed
  budget within 1 s of the session's last template is deferred to the end
  of that second and built once on the latest budget, so a client cycling
  budgets gets at most one constraints-triggered build per second. More
  than 8 budgets that each replace a still-queued one before it is built
  close the session: a real client changes its budget minutes apart, and
  the slot goes back to one. A client pacing one budget per cooldown is
  only made to wait. The build calls
  `MempoolHub::select_block_template` with the per-session budget
  ([Constraints](#constraints-all-plans)); `coinbase_prefix` is the BIP34
  height push; `value_remaining` = subsidy + Σ selected fees (from the
  selection, not a re-read); outputs = witness commitment last;
  `merkle_path` from B2's `merkle_branch` over the selection order.
- **Red:** `cargo test -p rbitcoin-sv2 template_` — loopback test client
  against a padded regtest `ChainHub` with an attached `MempoolHub`
  (Libre policy admits a high-sigop output script): weight bound at the
  reserved edge, sigops at a large `max_additional_sigops`, fee sum,
  prefix bytes, commitment, tx order via the merkle fold.
- **Green:** builder module in `rbitcoin-sv2`; subsidy from
  `rbitcoin-consensus`, version and min fee from `ChainHub`. The listener
  config carries the `ChainHub`. Sending in this step keeps the builder
  reachable from the shipped path (no test-only caller); tx retention
  lands with its first reader in B5.
- **Refactor:** none expected (commitment and selection already have one
  owner).
- **Verify:** `cargo test -p rbitcoin-sv2 template_`

### B4a — SetNewPrevHash + sync gate

- **Contract:** the first template on a prev hash is
  `NewTemplate{future_template: true}` followed by `SetNewPrevHash` with
  the same `template_id`, the tip as `prev_hash`, `header_timestamp` ≥
  MTP + 1, and the next nBits with its target. A later template on the
  same prev hash (changed constraints) is `future_template: false` with no
  `SetNewPrevHash`, and keeps that `SetNewPrevHash`'s nBits and target:
  §7.4 sends nBits once per prev hash, so a solution on any template on it
  is assembled with the bits the client hashed. On min-difficulty networks
  the build's bits follow the clock past prev + 2 × spacing; recomputing
  them would make every such solution `bad-diffbits`. While `ChainHub::in_ibd()` (relay-inhibited: stale tip
  or below min chain work), the session holds the constraints and builds
  when a tip event clears it. `getblocktemplate` has no sync gate in this
  node, so the TP gate is the relay gate; leaving IBD always comes with a
  new tip.
- **Red:** `cargo test -p rbitcoin-sv2 --lib` — the B3 template test gains
  the `SetNewPrevHash` pair and the `future_template: false` rebuilds;
  `sync_gate_` holds on a stale padded chain and serves after a fresh block
  is accepted through `ChainHub`.
- **Green:** tip read once per build (height, header, MTP, bits);
  per-session current prev hash; gate loop on `subscribe_tips()` in the
  session.
- **Refactor:** none expected.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`

### B4b — Node wiring + bootstrap journey

- **Contract:** with `--sv2-tp-listen` set, the node serves the listener
  (`--sv2-tp-authority-sec` required with it, `--sv2-tp-cert-validity`
  optional); a client completing setup and sending
  `CoinbaseOutputConstraints` receives the B4a pair against the node tip
  and mempool once the node leaves IBD.
- **Red:** `cargo test -p rbitcoin-test sv2_tp_bootstrap` — one regtest
  node on a padded (stale) chain: handshake → setup → constraints, no
  template while in IBD, `generateblock` clears the gate, then assert the
  pair against RPC (`getbestblockhash`, `getblocktemplate` bits) and a
  mempool tx sent over RPC; config parse units under `sv2_tp_`.
- **Green:** `run.rs` service start behind the three flags; handle shut
  down with the other services.
- **Refactor:** flag plumbing follows the `esplora_block_template` config
  pattern.
- **Verify:** `cargo test -p rbitcoin-test sv2_tp_bootstrap`,
  `cargo test -p rbitcoin-node sv2_tp_`

### B5 — RequestTransactionData

- **Contract:** a live `template_id` →
  `RequestTransactionData.Success{template_id, excess_data: "",
  transaction_list}` with the witness-serialized txs in template order.
  A session retains its templates (count bound in Plan C C1); an id it was
  sent but dropped →
  `RequestTransactionData.Error{error_code: "stale-template-id"}`, an id
  never sent → `"template-id-not-found"`.
- **Red:** extend the B4b journey: request the served template's data,
  assert count/order/bytes against the mempool txs; unknown-id and
  dropped-id errors.
- **Green:** per-session template map retaining the witness-serialized
  txs (the named RAM trade), and its read path.
- **Refactor:** none expected.
- **Verify:** same journey filter.

### B6 — Tip-change push + stale grace

- **Contract:** after the node accepts a new tip block, every active
  session receives `NewTemplate{future_template: true}` then
  `SetNewPrevHash` on the new `prev_hash`, `template_id` still increasing.
  During `--sv2-tp-stale-grace` the old template still answers
  `RequestTransactionData`; after the grace it answers
  `"stale-template-id"`. Future templates for the old prev hash retire the
  same way. `--sv2-tp-stale-grace` is at most 86400 s
  (`MAX_STALE_GRACE`) and `--sv2-tp-cert-validity` at most `u32::MAX` s
  (the Noise cert field); config parse and `run_sv2_tp` both refuse
  larger values. `ChainHub::connect_at` moves the store tip before it strips the
  block's txs from the mempool and sends the tip event, so a build in that
  window (constraints, or the previous event's rebuild on back-to-back
  blocks) can land on the new prev hash with confirmed txs. A failed
  reorg's rollback reconnects the same hash the same way. The session
  flags every build and each tip event clears the flag: an event for the
  current prev hash rebuilds iff a template was built since the last
  event, sent as `future_template: false` with no `SetNewPrevHash`. A
  repeat event with no build between is skipped.
  Future consideration: stripping the mempool before publishing the store
  tip, or publishing both atomically, would close the window for every
  template consumer, and `built_since_tip` could then go. GBT
  (`getblocktemplate`) and Esplora `GET /block-template` read the store tip
  and then select from the mempool with no tie to `connect_lock`, so a call
  in the window has the same stale selection. The change reorders the store
  publish against the mempool on the tip-accept hot path and needs `ibd:
  perf` timers. Admission is not serialized with connect: `accept_tx` takes
  neither `connect_lock` nor the tip-accept thread. It prepares against the
  store tip under the mempool read lock and commits under the write lock
  without re-reading the tip. A tx prepared against the old tip in the gap
  between strip and publish could then re-admit a confirmed tx unless
  admission is serialized with connect.
- **Red:** journey: generate a block via the harness RPC, assert the push
  pair arrives without client polling; stale-id behavior before and after
  the grace (the harness sets it small).
- **Green:** `ChainHub::subscribe_tips()` consumer; rebuild per session
  with its constraints; retire on the grace timer.
- **Refactor:** one "publish template" path shared by bootstrap and tip
  (Plan C adds the fee trigger to it). The session selects over client
  frames, tip events, and the grace deadline; frames come from a reader
  task because a Noise `recv` is not cancel-safe.
- **Verify:** journey filter; `cargo test -p rbitcoin-sv2 --lib` (the sync
  gate unit now clears on the tip event; the
  `tip_event_rebuilds_a_template_built_on_its_prev_hash` journey writes a
  two-block batch through `confirm_write`, so the rebuild for the first
  event already sits on the second block's hash; the
  `tip_event_rebuilds_a_template_built_before_it` unit pins the rollback
  reconnect, which no session hits deterministically)

### B7 — SubmitSolution → accept_block

- **Contract:** a client solving the served template sends
  `SubmitSolution{template_id, version, header_timestamp, header_nonce,
  coinbase_tx}` (full witness coinbase); the node assembles header (prev +
  recomputed merkle + message fields) + coinbase + retained txs and runs
  `ChainHub::accept_block`; the tip advances. Unknown/stale template or
  undecodable coinbase → log and drop. An out-of-window timestamp is
  logged and still submitted per [Constraints](#constraints-all-plans).
- **Red:** journey: grind a regtest nonce on the served template, submit,
  assert the new tip hash; a garbage-coinbase submission leaves tip and
  session healthy.
- **Green:** assembly + pre-checks in a blocking region; accept via
  ChainHub.
- **Refactor:** assembly folds the coinbase txid (leaf 0) over the
  retained template's `merkle_path` with the store's
  `merkle_root_from_branch` (the inverse of the B2 `merkle_branch`
  helper), so a bad-PoW solution is dropped before the full txid list is
  hashed; `accept_block` still checks the root.
- **Verify:** journey filter.

### B8a — Authority secret from a file

- **Contract:** `--sv2-tp-authority-sec-file PATH` (conf
  `sv2_tp_authority_sec_file`) reads the same secret from a file at
  parse time. A hex value in argv shows in `ps` and in a NixOS unit in the
  world-readable store; the file keeps it out of both. Errors name the knob
  and never echo the key.
- **Red:** node lib test: a key file sets the secret; a bad key and a
  missing file fail without echoing it.
- **Green:** the key shares the hex + `SecretKey` check with
  `sv2_tp_authority_sec`.
- **Verify:** `cargo test -p rbitcoin-node --lib sv2_tp`

### B8b — Operator surface

- **Contract:** [`OPERATOR.md`](../OPERATOR.md) documents
  `--sv2-tp-listen`, `--sv2-tp-authority-sec`,
  `--sv2-tp-authority-sec-file`, `--sv2-tp-cert-validity`,
  `--sv2-tp-stale-grace`. [`COMPAT.md`](../COMPAT.md) gains the SV2 TDP
  row (the "no stratum" row stays; that row is v1 stratum/pool).
  First-class `services.rbitcoin.sv2.tp.*` options in
  [`nix/modules/rbitcoin.nix`](../nix/modules/rbitcoin.nix) with argv
  asserts in `nixos-module-eval.nix`. The module takes only
  `authoritySecretFile` (a runtime path), never the hex.
- **Red:** eval assert for the flags; docs need no test.
- **Green:** options + docs.
- **Refactor:** `extraArgs` still appends last.
- **Verify:** `nix build .#checks.x86_64-linux.nixos-module-eval --no-link`

### B8c — Authority key in `key-utils` form

- **Contract:** the startup log prints the authority public key as SRI
  `key-utils` `Secp256k1PublicKey` (base58check of version `1u16` LE plus
  the x-only key), the form SRI clients take. Hex is not accepted there.
- **Red:** `listener_tests.rs` `authority_key_prints_in_key_utils_base58check`
  pins the key-utils 1.2.0 vector and connects with the decoded key.
- **Green:** `Sv2TpHandle::authority_key()`; `run.rs` logs it.

### B8d — Authority secret in `key-utils` form

- **Contract:** `--sv2-tp-authority-sec` and the file also take SRI
  `key-utils` `Secp256k1SecretKey` (base58check of the raw 32 bytes), so a
  key generated for an SRI deployment works as is. 64 hex still parses.
- **Red:** node lib `sv2_tp_authority_sec_takes_key_utils_base58check`: the
  key-utils vector secret, inline and from a file, yields the vector pubkey;
  a bad checksum names the knob without echoing the key.
- **Green:** `parse_authority_sec` falls back to base58check.

### B8e — Authority secret never prints

- **Contract:** `NodeConfig` `Debug` masks the authority secret, and a
  `sv2_tp_authority_sec_file` read error names the knob and the IO error
  without the path: an operator who passes the key to the file knob must
  not see it logged.
- **Red:** node lib `sv2_tp_authority_secret_never_prints`: the config
  `Debug` and the error for the hex key given as a path hold no key bytes.
- **Green:** `Sv2AuthoritySecret` newtype with a masking `Debug` (the
  `TorControlOpts` password precedent); the file error drops the path.

---

## Plan C — Fee-delta push

**Goal:** with the tip unchanged, connected clients get a fresh template
when fees rise enough to matter, throttled. Requires Plan B.

### C1 — Fee-delta push

- **Contract:** with the tip unchanged, a session sends
  `NewTemplate{future_template: false}` with **no** `SetNewPrevHash` when a
  rebuild's total fees are at least `--sv2-tp-fee-delta` sats above the
  last template it sent, and at least `--sv2-tp-template-interval` passed
  since its last push. Below the delta, inside the interval, or with
  `MempoolHub::template_updates` unchanged: nothing. Defaults follow
  stratum-mining `sv2-tp` (`src/sv2/template_provider.h`: `fee_delta{1000}`
  sat, `template_interval{5}` s; `-templateinterval` is at least 1 s), and
  the comparison is Core's waitNext (`node/block_template_manager.cpp`:
  `new_fees >= current_fees + fee_threshold`). Fees are base fees on both
  sides: Core sums `vTxFees`, which `node/miner.cpp` fills with
  `entry.GetFee()` (the modified fee only orders selection), and here
  `value_remaining` is subsidy plus `Selected.fee_sat`. A
  `prioritisetransaction` that reorders the selection without raising base
  fees by the delta does not push, as on Core.
- **Design:** `template_updates` is a plain counter, not a notifier (GBT
  longpoll polls it every 50 ms). The session `select!` gains one
  `sleep_until` arm beside `rebuild_at` / `retire_at`, armed one interval
  after each push and re-armed one interval after each check. When it
  fires the session rebuilds only if the counter moved since its last
  build and no constraints rebuild is queued (that rebuild publishes the
  latest mempool); a rebuild on a different prev hash is dropped (the tip
  event follows and publishes). The library refuses an interval under
  100 ms (`MIN_TEMPLATE_INTERVAL`) or over a day; the node flag takes whole
  seconds. The fee push goes through the B6 publish path, so
  it keeps the `SetNewPrevHash` nBits and target (`sent_bits`, B4a); bits
  are not recomputed. CPU trade: at most `MAX_SESSIONS` builds per interval
  under the mempool read lock. The interval is a check period: sv2-tp
  suppresses fee updates for `-templateinterval` after a push and then
  rechecks on Core's 1 s waitNext tick, so a gain can reach a client here
  up to one interval later than there; `--sv2-tp-template-interval 1`
  matches that latency at 1 build per second per session. A check whose
  build fails (a reorg pops the tip block by block with no event until the
  new branch connects) is skipped; the tip event publishes.
- **Retention:** fee pushes add one same-tip template per interval while a
  miner may still be on any job since `SetNewPrevHash` (SV1 translators
  update with `clean_jobs=false`). So every template on the current tip
  stays retained, as sv2-tp's `PruneBlockTemplateCache` keeps every
  current-prev template, up to `MAX_RETAINED` = 64 per session, oldest
  dropped first (replaced tips before the current one). Templates share the
  mempool's bodies (the `Arc` selection in Plan A), so the count is cheap.
  Templates on a replaced tip still retire after `--sv2-tp-stale-grace`.
- **Red:** `cargo test -p rbitcoin-sv2 fee_push` — a padded regtest
  session on a short interval: a tx above the delta is pushed after the
  interval with no `SetNewPrevHash`; one below it is not; a push never
  lands inside the interval; a budget queued by the constraints cooldown
  builds once; the first template on the tip still solves after more fee
  pushes than the old three-template ring; under steady admission
  consecutive pushes stay at least half an interval apart. The
  cross-surface `sv2_tp_bootstrap` journey gains one RPC-driven fee push.
- **Known mutant survivors** (nightly cargo-mutants, not PR checks):
  deleting the re-arm in `check_fees` (a session spins after a check that
  does not push) and dropping the unchanged-counter skip (one idle build
  per interval) change only CPU. The listener's `Sv2TpStats` (also
  `tip: perf` JSON `sv2_checks` / `sv2_builds` and `/metrics`) count checks and builds, and
  `idle_session_checks_each_interval_and_does_not_rebuild` pins both.
  Dropping the same-prev-hash guard in `check_fees` would send
  a fee rebuild from the store-publish-before-strip window as a new prev
  hash; a fee check cannot be steered into that window deterministically,
  so the guard is pinned by review, not a test.
- **Green:** per-session check deadline and last-seen counter; publish
  split into build and send.
- **Refactor:** none expected.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`,
  `cargo test -p rbitcoin-test --test cross_surface sv2`

### C2 — Operator surface

- **Contract:** `--sv2-tp-fee-delta SATS` (conf `sv2_tp_fee_delta`) and
  `--sv2-tp-template-interval SECS` (conf `sv2_tp_template_interval`, at
  least 1, at most 86400); `services.rbitcoin.sv2.tp.{feeDelta,
  templateInterval}` with argv asserts in `nix/tests/nixos-module-eval.nix`;
  `docs/operator/interfaces.md` documents both and the
  `RequestTransactionData` window.
- **Red / Green / Refactor / Verify:** as B8b, plus config parse units
  under `sv2_tp_`.

---

## Plan D — Custom job validation (TDP `ProposeTemplate`)

**Goal:** a Job Declarator Server in Full-Template mode checks a JDC's
`DeclareMiningJob` against this node over the TDP connection it already
holds, fetches the transactions the node lacks, and submits the found block
by `template_id`. Wire contract: [`sv2-job-validation.md`](./sv2-job-validation.md)
(proposed TDP messages 0x77–0x7b and `SetupConnection` flag bit 0, for
sv2-spec discussion #239, which supersedes #217). Requires Plan B and Plan C
(merged as #949 and #951: the shared `Arc<Transaction>` bodies and the
64-slot same-tip ring that retains validated jobs) and the proposal-check
stack on `ChainHub`, merged as #959, #961, #963, #967, #968, and #969. That
check is the job-validation hot path: a JDS asks once per JDC declaration,
dozens of times a minute per pool, so before this plan could ship it had
to become one decode per parent (#961, #968), bounded in memory (#968),
right about spent coins after a reorg (#968, #969), and complete (immature
coinbases and structure before spends in #963, script execution and the
fee-overflow checks in #967). The Core-IPC sibling implementation is
stratum-mining/sv2-tp PR #137. Ships no flag: a session opts in with
`REQUIRES_JOB_VALIDATION`.

### D1 — Block proposal check on `ChainHub`

- **Contract:** `ChainHub::check_block_proposal(&Block) -> Result<u64,
  String>` is Core `TestBlockValidity` for a GBT proposal or an SV2 job:
  prev must be the tip (`inconclusive-not-best-prevblk`), `bad-diffbits`,
  `time-too-old` / `time-too-new`, every spend against the block and the
  confirmed chain, then structure (merkle, weight, sigops, BIP34 height,
  witness commitment) and the coinbase priced at subsidy + fees
  (`bad-cb-amount`, after CheckBlock as in Core's ConnectBlock), then the
  scripts of every spend (#967). `Ok` is the fee total. No PoW, no UTXO
  write. Merged as #959; #963, #967, #968, and #969 extended it (see the
  Plan D intro).
- **Red:** `cargo test -p rbitcoin-net --lib check_block_proposal` — tip
  child passes, other parent rejects, `bad-cb-amount` after structure,
  `Ok(fees)`; `rbitcoin-rpc` `methods_tests` pins GBT proposal mode
  answering `bad-cb-amount`.
- **Green:** the check moves from the RPC crate onto the hub (a move:
  `check_block_proposal_with` keeps the explicit-inputs form for callers
  with a `Query` but no hub); the spend loop then returns Σ(inputs −
  outputs).
- **Verify:** both filters.

### D2 — Messages and the setup flag

- **Contract:** `messages.rs` carries `ProposeTemplate`,
  `.MissingTransactions` (the `ProvideMissingTransactions` pair since D12),
  `.Success`, `.Error` (0x77–0x7a) as binary_sv2
  structs, and `REQUIRES_JOB_VALIDATION`. Setup accepts bit 0 and echoes
  it; any other set bit is still `unsupported-feature-flags`.
- **Red:** `job_validation_messages_round_trip`;
  `setup_connection_success_errors_and_session_cap` gains the flag case.
- **Green:** the structs and the mask in `setup_error`.

### D3 — Client frame cap per message type

- **Contract:** the [Constraints](#constraints-all-plans) frame cap, per
  type. `ProposeTemplate` may carry a block's worth of transactions;
  every other client type still closes past 65557 bytes.
- **Red:** `oversized_client_frame_closes_the_session` — a 200 KiB
  `ProposeTemplate` keeps the session, a 200 KiB `SubmitSolution` and a
  `ProposeTemplate` over its cap close it.
- **Green:** `FrameCap { max_frame, payload: fn(u8) -> usize }`: read
  against the largest client message, apply the per-type cap once whole.
- **RAM trade:** one in-flight client frame of ≤ ~6.5 MB per session,
  ≤ ~52 MB at `MAX_SESSIONS`.

### D4 — ProposeTemplate happy path

- **Contract:** on a session that negotiated the flag, a
  `ProposeTemplate` whose `prev_hash` is the tip (field dropped in D9),
  whose `wtxid_list` is all in the mempool, and whose placeholder coinbase
  pays ≤ subsidy + fees
  is answered `Success{request_id, template_id, fees}` (D9 adds
  `prev_hash`): `template_id` is the next id in the session's counter. The
  job is retained exactly like a template, so
  `RequestTransactionData` returns the declared txs in block order and
  `SubmitSolution` finds it. Without the flag the message is ignored (the
  D3 journey already pins that).
- **Red:** `propose_template_prices_and_retains_the_declared_job` —
  two legacy spends with known fees in the mempool, a JDS-shaped coinbase
  (BIP34 push + 8 placeholder bytes, payout = subsidy + fees, witness
  commitment with a zero reserved value); `Success` with `fees` = 5 000
  and `template_id` = last `NewTemplate` id + 1; the retained txs read
  back. Red was a reply timeout (the message fell through to "ignoring").
- **Green:** `job::validate` under `spawn_blocking` + `BlockingRegion`:
  decode, resolve each wtxid with `MempoolHub::get_tx_by_wtxid`, header
  `{version, tip, merkle root over the coinbase txid + declared txids,
  time = max(now, MTP + 1), expected nBits, nonce 0}`,
  `check_block_proposal`, `Ok(fees)` → retained under `last_id + 1`,
  `Success`; a reject string → `Error{error_code}`. `Session` gains
  `job_validation` from the setup flags (its first read is the dispatch
  arm).
- **Refactor:** the tip read (height, prev hash, time, bits) moves out of
  `template::build` into `template::next_header` (a move; both paths call
  it). `Template` splits into the `NewTemplate` coinbase split over a
  `Job` — what a session retains under a template id (`merkle_path`,
  `prev_hash`, `header_timestamp`, `n_bits`, `target`, `txs`) — so a
  validated job carries no dead `NewTemplate` fields. The test client
  gains a typed `send`.
- **CPU trade:** one full proposal check per request on the blocking pool
  (every spend against the chain, structure, weight, sigops, coinbase
  value, scripts; no PoW). A JDS sends one per declaration; a flood
  costs blocking threads, not the reactor, and D3 bounds its RAM.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`.

### D5a — MissingTransactions round trip

- **Contract:** a wtxid neither the mempool nor `transaction_list`
  resolves → `MissingTransactions{request_id, unknown_tx_position_list}`
  (0-indexed positions in `wtxid_list`); the same job resent with those
  txs in `transaction_list` validates and the supplied txs are retained
  with it. The TP keeps no state across the round trip (reversed in D12:
  the TP holds the proposal and the txs arrive in their own message).
- **Red:** `propose_template_asks_for_and_accepts_missing_transactions`
  — one of two spends not in the mempool → `[1]`; resend with it
  supplied → `Success` with the full fee sum and both txs retained. Red
  was the session closing (D4's placeholder treated an unknown wtxid as
  an error).
- **Green:** resolution consults `transaction_list` first, keyed by
  sha256d of the bytes as sent (the wtxid of that serialization, so no
  decode before the slot is known), then the mempool; unknown positions
  are collected and answered.
- **Verify:** same filter.

### D5b — Untrusted-input rejections

- **Contract:** `Error.error_code` in this order, before any mempool
  lookup or transaction decode: `duplicate-wtxid` and `bad-missing-tx` (a
  supplied tx whose hash is not in `wtxid_list`) on arrival, with no chain
  read (D11 moved them ahead of the gate); then, on the blocking thread,
  `job-validation-unavailable` while `in_ibd()` (the template gate),
  `stale-prevhash` (dropped in D9), `bad-missing-tx` for a declared blob
  that does not decode, `bad-cb-decode` (this TP's code; the draft has none
  for an undecodable coinbase), then the proposal check's reject string
  (`bad-cb-amount` for an overpaying coinbase). Nothing is retained and no
  id is taken on an error.
- **Red:** `propose_template_rejects_untrusted_input_in_order` — seven
  sends on one session, then `RequestTransactionData(last + 1)` answers
  `template-id-not-found`. Red was `Success` for the first send.
- **Green:** the checks in `job::check`, ahead of resolution.
- **Verify:** same filter.

### D6 — SubmitSolution against a validated job

- **Contract:** after `Success`, a `SubmitSolution{template_id, version,
  ntime, nonce, coinbase_tx}` whose coinbase has the extranonce where the
  placeholder stood and whose header meets the target is assembled from
  the retained job, accepted through `ChainHub::accept_block`, and
  becomes the tip, exactly like a solution for a pushed template.
- **Red:** `submit_solution_for_a_validated_job_becomes_the_tip`. It
  passed with no production change (a validated job is retained as the
  same `Job` a built template is) and is kept as the pin; `first_template`
  takes the setup flags and connects through `connect_tp`.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib submit_solution`.

### D7 — Docs and tidy

- `messages` is crate-private (no other crate reads it yet; the
  `rbitcoin-test` journey that will needs the re-export then). The draft
  is copied unchanged as [`sv2-job-validation.md`](./sv2-job-validation.md)
  and owns the wire contract until it lands upstream. Operator lines in
  `docs/operator/interfaces.md`, the COMPAT row, and a `changelog.d`
  fragment.

### D8 — Rename to `ProposeTemplate`

- **Contract:** sv2-spec discussion #239 (plebhash, 2026-10-06) supersedes
  #217 and names the message `ProposeTemplate`; `.MissingTransactions`,
  `.Success`, `.Error` follow. Pure rename: structs, message-type consts,
  the frame cap, the session handler, journey names, log strings, this
  plan, the draft, the operator doc, the COMPAT row, the changelog
  fragment. No behaviour change.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`; `rg ValidateCustomJob`
  empty.

### D9 — The `DeclareMiningJob` subset; `Success` names the tip

- **Contract:** `ProposeTemplate` carries what a JDS has from
  `DeclareMiningJob` and nothing it would have to invent: `request_id`,
  `version`, `coinbase_tx_prefix`, `coinbase_tx_suffix`, `wtxid_list`,
  `excess_data` (opaque here), plus `transaction_list` (dropped in D12). No `prev_hash`:
  the TP validates on its current tip and `Success` carries that tip as
  `prev_hash` next to `template_id`. The TP builds the
  placeholder coinbase: `E = L − P` from the prefix (version, BIP144
  marker and flag when present, an input count that MUST be 1, the
  prevout, scriptSig length `L`, `P` bytes present; `2 ≤ L ≤ 100`,
  `P ≤ L`), coinbase = prefix ‖ zeros(E) ‖ suffix. A prefix that does not
  parse, or a result that does not decode, is `bad-cb-decode`.
  `stale-prevhash` is gone: a declaration from before the tip moved fails
  the proposal check on its own (`bad-cb-height` for its BIP34 push).
- **Red:** the four journeys send prefix/suffix and `expect_job_success`
  asserts `Success.prev_hash == tip`;
  `propose_template_rejects_untrusted_input_in_order` swaps the stale case
  for an old-height declaration (`bad-cb-height`) and adds a prefix with
  more scriptSig bytes than its length declares, a two-input prefix, and a
  truncated suffix (all `bad-cb-decode`); `job_validation_messages_round_trip`
  carries the new fields. Red was the compile error on the new fields.
- **Green:** `messages.rs` fields; `job::extranonce_len` (unit-tested for
  the legacy and segwit-marker prefix and each rejection) and the
  placeholder assembly ahead of the coinbase decode; the request
  `prev_hash` comparison dropped; `Success.prev_hash` from the retained
  job's header. `MAX_PROPOSE_TEMPLATE_PAYLOAD` re-priced for three
  `B064K` fields (~6.5 MB).
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`.

### D10 — Return `fees` in `Success`; retain jobs like templates

- **Contract:** `ProposeTemplate.Success` is `{request_id, template_id,
  prev_hash, fees}`; `fees` is the fee total of the declared transactions as
  `ChainHub::check_block_proposal` computed it. Only the validating node can
  derive it (sum of inputs minus sum of outputs per transaction needs the
  UTXO set) and it computes it anyway for `bad-cb-amount`; the Pool
  otherwise has only the coinbase's claimed value, which that check makes a
  lower bound. Bitcoin Core's IPC does not expose it today (`checkBlock`
  returns only reason, debug and result; a `TxCollection.makeTemplate`
  template throws on `getTxFees`); the gap is raised on bitcoin/bitcoin#35671
  rather than designed around. A validated job is retained exactly as a
  template is: the same
  `MAX_RETAINED` ring (oldest first) and the same stale grace after a tip
  change. A JDS multiplexes many JDCs over one connection, so "the latest
  validated job" is not a unit worth pinning; the 64-slot same-tip ring from
  C1 is the guarantee, and the draft (§4.3) now says so.
- **Red:** `job_validation_messages_round_trip` and `expect_job_success`
  with `fees`; Red was `E0560` on the struct literal.
- **Green:** the field, `Verdict::Valid { fees, job }` and the reply
  plumbing. `check_block_proposal` returns `Ok(fees)`: D1 cross-crate API
  that GBT proposal mode also reads.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`.

### D11 — Validation off the session loop

- **Contract:** a `ProposeTemplate` validation never delays the other
  frames or loop branches of its session. `SubmitSolution`,
  `RequestTransactionData`, tip pushes, fee checks, and retire timers run
  while a validation is in flight; `ProposeTemplate.Success` / `.Error` is
  sent when the validation completes, paired by `request_id`, and the job
  is retained when that reply is sent (so it takes the template id current
  then). Up to `MAX_INFLIGHT_VALIDATIONS` (4) validations run at once per
  session; further proposals wait in arrival order and are not refused.
  Session end aborts the in-flight set. Before D11 `on_frame` awaited the
  validation inline inside the session `select!`, so a JDS multiplexing
  many JDCs over one connection could have a found block's
  `SubmitSolution` sit behind another JDC's validation.
- **Red:** `propose_template_validation_does_not_delay_other_frames` —
  400 supplied spends of one confirmed fan-out make the validation the
  costly frame (about 85 ms on the parent-once proposal check) while every
  template stays coinbase-only. The proposal alone measures that wall. A
  `RequestTransactionData` for the empty template is sent right behind a
  second copy; its reply must arrive before that copy's `Success`, in under
  a quarter of the validation it overlapped: the request has no blocking
  work behind it, so a slower answer means the loop waited and the order
  was luck. A `SubmitSolution` behind a third copy is accepted while it
  validates and pushes the solved tip's `NewTemplate`; its accept ends in a
  tip write (an fsync), so the journey does not order it against that
  copy's reply, which is the straddle named under Risks: `Success` on the
  tip the validation started on, or the proposal check's reject once the
  tip moved first. The first shape (1200 inputs, the solution ordered
  before the reply) owed its margin to the per-input parent decode that
  #968 removed; on the merged check it failed 10 of 10 runs (`Success`
  before the solved tip's template, or `inconclusive-not-best-prevblk`
  when the tip moved first), which was Red for this shape. The original
  Red was `Success` as the first frame, the solution 527 ms behind a
  696 ms validation.
- **Green:** `on_frame` decodes the proposal and runs `job::precheck`
  (`duplicate-wtxid`, `bad-missing-tx`; no chain read) on arrival, replying
  at once on failure; otherwise the payload joins a FIFO and
  `start_validations` fills a `JoinSet` of `spawn_blocking` +
  `BlockingRegion` tasks up to the bound. A new `select!` arm takes each
  finished verdict and calls the one `reply_propose` path (retain on
  `Valid`, then the reply). `job::validate` stays complete on its own
  (the precheck runs again inside it).
- **CPU and RAM trade:** four full proposal checks at once per session,
  each on a blocking thread with up to a block of decoded txs; waiting
  proposals hold their payloads (≤ `MAX_PROPOSE_TEMPLATE_PAYLOAD` each),
  depth bounded by the client's burst (one job per JDC per tip change for a
  JDS), not by this TP: see Risks.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`; the journey 10 times in
  a loop.

### D12 — Missing transactions as a request/provide pair

- **Contract:** sv2-spec#239 (Sjors, 2026-10-08; agreed): the missing leg
  is proper messages reusing JDP 6.4.7 and 6.4.8 under TDP numbers.
  `ProposeTemplate` carries no `transaction_list`; the TP answers
  `ProvideMissingTransactions {request_id, unknown_tx_position_list}` (0x78)
  and the client returns `ProvideMissingTransactions.Success {request_id,
  transaction_list}` (0x7b). A JDS copies both payloads between the TP and
  its JDC, changing only the message type. The TP holds a proposal it asked
  about under its `request_id`: `job::Proposal` (wtxids and the coinbase
  split, no txs), at most `MAX_PENDING_PROPOSALS` (8) per session with the
  oldest dropped, for `provide_timeout` (`PROVIDE_TIMEOUT` 30 s, a
  `Sv2TpConfig` field like `setup_timeout`) checked in the retire arm. A
  provide for an id the session does not hold, already consumed, or
  expired is `ProposeTemplate.Error unknown-request-id`; a proposal under
  an id still queued, in flight, or held is `duplicate-request-id`; a
  provide that does not cover every requested position, supplies a tx the
  TP did not ask for, or one that does not decode, is `bad-missing-tx` and
  ends that exchange (the first two before any decode). These edge rules
  match sv2-tp #137. A validation still short of a tx asks again for every position
  the mempool lacks, the supplied ones included, since nothing is held
  across the round trip but the proposal. The block-sized client frame cap
  moves to `ProvideMissingTransactions.Success` (~4.2 MB);
  `ProposeTemplate` is wtxids plus coinbase (~2.3 MB).
- **Red:** `propose_template_asks_for_and_accepts_missing_transactions`
  rewritten around the round trip: `unknown-request-id` before, after, and
  past a 1 s `provide_timeout`; `duplicate-request-id` while held;
  `bad-missing-tx` for a tx not asked for, a provide short of a requested
  position (answered `ProvideMissingTransactions` again before), and a
  blob under the declared wtxid; nine holds dropping the first; only the
  completed jobs take ids. The D11 journey completes each copy through its
  provide and refuses a `ProposeTemplate` under the id in flight
  (`duplicate-request-id`; before, it was validated a second time);
  `oversized_client_frame_closes_the_session` gains a provide past the
  `ProposeTemplate` cap that keeps the session. Red was the compile
  failure against the one-message shape (no table, no 0x7b handler; the
  old session logged `ignoring message 0x7b`).
- **Green:** `job::Proposal` (owned decode, `precheck`, `accept_supplied`
  with the coverage count) and `job::validate(&Proposal, &Supplied)`;
  `Session.pending` as a `VecDeque<Pending>` with `hold` and expiry folded
  into the retire timer, `Session.open` for the ids queued or in flight;
  `Work { proposal, supplied }` through the FIFO and the `JoinSet`; the two
  payload caps in `transport.rs`.
- **RAM trade:** ≤ 8 × ~2.2 MiB held per session, no transactions; one
  in-flight client frame ≤ ~4.2 MB, ≤ ~34 MB at `MAX_SESSIONS`.
- **Verify:** `cargo test -p rbitcoin-sv2 --lib`.

### Test budget

Units: the messages round trip, `job::extranonce_len`, `rbitcoin-net`
`check_block_proposal_*`, `rbitcoin-rpc` GBT proposal `bad-cb-amount`.
Journeys in `rbitcoin-sv2`
`template_tests`: five, each one TP and one session on the shared regtest
pad; the D11 journey is the heaviest (a fan-out block, then three
validations of 400 supplied spends). No `rbitcoin-test` node journey yet
(follow-up with a JDS client).

### Risks / follow-ups

- No operator opt-out flag: any client that can reach the port may set
  the flag and cost one proposal check per request. Bind to loopback or
  firewall the port (the same advice as for templates).
- The waiting-proposal queue (D11) has no depth cap: a client that sends
  well-formed, expensive proposals faster than four blocking threads
  validate them grows it by one payload each (≤ ~6.5 MB). A refusal or a
  flood close would cut off a JDS at a tip change, when every JDC declares
  at once; the trust model above (who reaches the port) is the bound. A
  byte cap with an `Error` past it is the follow-up if that model changes.
- A job whose validation straddles a tip change ends one of two ways.
  Past the proposal check's tip read it is retained after the push for the
  new tip, so it misses that tip's stale grace and stays in the ring until
  pushed out; `Success.prev_hash` names the old tip, so the JDS discards
  it, and a solution on it is a side block, not the tip. Before that read
  the check rejects it (`inconclusive-not-best-prevblk`, or
  `bad-cb-height` when the header was read after the move). The D11
  journey accepts either.
- `SetupConnection.Success.flags` echoes the request flags verbatim.
- Retention is the template rule (D10): a validated job shares the
  session's `MAX_RETAINED` (64) ring with templates and the same stale
  grace. Past 64 same-tip pushes and validations the oldest goes; a
  `SubmitSolution` for it is dropped and JDC's own propagation (JDP 6.4.9)
  covers the block.
- A job is retained with the nBits its validation header used. On
  min-difficulty networks that can differ from the sent
  `SetNewPrevHash.n_bits` (the Plan B risk); mainnet and signet bits
  depend only on the prev hash.
- `ProvideMissingTransactions.Success` matching hashes the bytes as sent:
  a legacy tx relayed in segwit-marker form hashes differently from its
  wtxid and is `bad-missing-tx`. The draft requires the bytes exactly as
  JDC sent them, which is the serialization the wtxid was computed over.
- A held proposal dropped by the bound (D12) or the timeout surfaces only
  as `unknown-request-id` on its provide; the JDS proposes again. A JDS
  with more than eight JDCs short of transactions at one tip change loses
  the oldest round trips to that bound; raise `MAX_PENDING_PROPOSALS` if a
  pool reports it (each hold is wtxids and a coinbase, not a block).
- The message numbers 0x78 and 0x7b for the provide pair are this draft's
  proposal; #239 has assigned none yet.
- The IBD gate (`job-validation-unavailable`) and `bad-cb-decode` are
  this TP's choices within the draft's "recommended" list and should
  follow the upstream text once it settles.
- The extranonce-tail assumption (the suffix starts at `nSequence`) now
  lives in this TP's `extranonce_len`, not in the JDS. A JDC whose
  extranonce is not the scriptSig tail gets `bad-cb-decode` or a coinbase
  check failure here; the draft asks the Job Declaration Protocol to state
  the split (§6).
- No policy is applied (the draft forbids it); the Pool prices the
  declared coinbase from the coinbase itself.
- The JDS role itself, and a `rbitcoin-test` journey driving a JDS
  client, stay out.

## Test budget

Units in `rbitcoin-mempool` (budgeted selection), `rbitcoin-store`
(merkle path), and `rbitcoin-sv2` (builder, throttle, gate). **One**
regtest integration journey in `rbitcoin-test`, opened in B4b and extended
by B5–B7 and C1 — one node open, per [`TESTING.md`](../TESTING.md) budgets.
No live pool/JDC, no mainnet datadir, no plaintext mode.

## Risks / follow-ups

- stratum-core publishes the wire crates on crates.io while sv2-apps
  git-pins the meta-crate; crates.io versions may lag sv2-tp behavior. B1
  pins the Step 0 set. Interop against the sv2-apps integration-tests
  (their JDC against this TP) is a host follow-up, not default CI.
- A bump of the wire crates that fails `cargo deny` reopens the hand-roll
  fallback (name the dep that forced it).
- `secp256k1` 0.28 + `secp256k1-sys` 0.9 compile a second libsecp: compile
  time and binary size, not correctness (distinct symbol prefixes). Drops
  when `noise_sv2` moves to 0.29.
- Authority-cert rotation: certs are short-lived
  (`--sv2-tp-cert-validity`); rotation is restart-with-new-cert in
  OPERATOR. Hot rotation is a follow-up.
- Min-difficulty networks (testnet3, testnet4): a block's expected nBits
  depends on its own time (the pow limit past prev + 2 × spacing), but
  TDP sends nBits once per prev hash in `SetNewPrevHash` (sv2-spec 07
  §7.4) and `NewTemplate` carries none, by design: templates refresh
  often, the prev hash changes only on a block. So a TP client mines at
  the bits it was sent for that prev hash and never at the 20-minute pow
  limit, and a solution whose `ntime` rolls past prev + 2 × spacing is
  `bad-diffbits` unless the sent bits were already the limit. A re-push cannot fix it: a same-hash `SetNewPrevHash`
  is outside §7.4, and a `NewTemplate` has no field for the bits. Not
  planned; mainnet and signet bits depend only on the prev hash.
- Pre-existing, outside this plan: this binary has no testnet4 network.
  If one is added, consensus does not yet enforce the BIP94 timewarp floor.
  The first block of a retarget period may carry a timestamp more than 600 s
  before its parent. Core rejects that (`time-timewarp-attack`); the template
  timestamp floor must include the rule when consensus gains it. Mainnet,
  testnet3, signet, and regtest do not use that rule.
- After ship: JD-server mode, weak blocks, extension negotiation, per-IP
  connection limits → quality.md rows, not this roadmap.
