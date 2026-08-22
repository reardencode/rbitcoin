# Consensus-rule test matrix

Every consensus rule **we implement** (not delegated wholesale to rust-bitcoin) has an automated test that would fail if the check were removed or inverted.

**Out of scope:** full secp256k1 / script-interpreter opcode parity vs Core; rust-bitcoin PoW / `CompactTarget` retarget math; full mainnet retarget golden vectors.

## Running

```bash
nix-shell
cargo test -p rbitcoin-consensus --lib
cargo test -p rbitcoin-test --test consensus_rules
# Core JSON corpora (script_tests / tx_valid / tx_invalid / sighash / BIP341):
cargo test -p rbitcoin-consensus --lib core_script_tests_all_rows -- --nocapture
cargo test -p rbitcoin-consensus --lib core_tx_ -- --nocapture
cargo test -p rbitcoin-consensus --lib core_sighash -- --nocapture
cargo test -p rbitcoin-consensus --lib core_bip341 -- --nocapture
cargo test -p rbitcoin-consensus --lib block_866342 -- --nocapture
# broader integration still covers connect success paths:
cargo test -p rbitcoin-test --test scenarios consensus_
```

## Core consensus corpora (1:1 surface)

Staged each `cargo test` run from the Bitcoin Core **v31.1** submodule
`third_party/bitcoin/src/test/data/` (MIT). Offline after
`./scripts/core-functional/init-submodule.sh`. Bump the gitlink pin when
refreshing; do not check copies into `tests/fixtures/`.

| Fixture | Path | Harness | Success criterion |
|---------|------|---------|-------------------|
| `script_tests.json` | `third_party/bitcoin/src/test/data/` (staged to `$CARGO_TARGET_DIR/core-data/`) | `script::core_vectors::core_script_tests_all_rows` | **every** data row; `fail == 0` (no allowlist) |
| `tx_valid.json` | same | `script::core_tx_vectors::core_tx_valid_all_rows` | every data row accept |
| `tx_invalid.json` | same | `script::core_tx_vectors::core_tx_invalid_all_rows` | every data row reject |
| `sighash.json` | same | `script::core_sighash::core_sighash_all_rows` | every data row digest matches Core |
| `bip341_wallet_vectors.json` | same | `script::core_bip341::core_bip341_wallet_vectors_all_rows` | key-path fully-signed + per-input spends accept; unknown-leaf script-path accepts |
| mainnet 866342 + prevouts | `tests/fixtures/block_866342/` (Floresta zstd) | `block::block_866342::block_866342_structure_and_scripts` | structure at height + every non-coinbase `verify_job_all_inputs` |

### How the harness works

1. Stage JSON from the submodule (not network, not an in-tree copy).
2. Parse Core script language / hex txs.
3. Build Core-style **credit/spend** txs (script_tests) or deserialize fixture txs (tx_*).
4. Call shipped **`verify_job_all_inputs(ScriptCheckJob)`** (or bare EvalScript+P2SH path when `WITNESS` flag is off — Core treats v0 programs as bare without that flag).
5. Compare accept/reject to Core’s expected code. Named error codes only require **reject**, not exact code string.

### No allowlist

- Soft majority pass rates are **not** success criteria.
- There is **no** row skip inventory. A mismatch fails the test; fix the engine or
  the fixture interpretation before commit.
- **Status:** Core JSON corpora green on the shipped path
  (`script_tests` 1222/1222 on Core v31.1, `tx_valid` 121/121, `tx_invalid` 93/93,
  `sighash` 500/500, `bip341_wallet_vectors` 9/9).

### rust-bitcoin vs Core fixtures

| Topic | Doc |
|-------|-----|
| rust-bitcoin gaps we wrap | [`rust-bitcoin-limitations.md`](./rust-bitcoin-limitations.md) |
| External consensus findings | [`external_findings/`](./external_findings/) |

### Origin / update

See `crates/rbitcoin-consensus/tests/fixtures/README.md`.

## A. Block structure — `validate_block_structure_hashed`

| ID | Rule | Error signal | Test |
|----|------|--------------|------|
| S1 | Block has ≥1 tx | `BadBlock("no transactions")` | `structure_rule_tests::s1_rejects_empty_txdata` |
| S2 | First tx is coinbase | `BadBlock("first tx not coinbase")` | `structure_rule_tests::s2_rejects_non_coinbase_first` |
| S3 | No later coinbase | `BadBlock("coinbase not first")` | `structure_rule_tests::s3_rejects_second_coinbase` |
| S4 | Weight ≤ 4_000_000 WU | `BadBlock("…weight…")` | `structure_rule_tests::s4_rejects_overweight_block` |
| S5 | Unique txids | `BadBlock("duplicate txid")` | `structure_rule_tests::s5_rejects_duplicate_txid` |
| S6 | Merkle root matches txids | `BadBlock("merkle root mismatch")` | `structure_rule_tests::s6_rejects_merkle_root_mismatch` (+ `merkle_root_bytes_single_and_odd`) |
| S7 | BIP34 height in coinbase (h≥1) | `BadBlock("bip34…")` | `s7_rejects_bip34_missing_at_height_1`, `s7_bip34_not_required_at_height_0` |
| S8 | Witness commitment when any witness | missing / mismatch | `s8_rejects_missing_witness_commitment`, `s8_rejects_wrong_witness_commitment` |
| S9 | Coinbase scriptSig length 2..=100 | `bad-cb-length` | `s9_rejects_bad_cb_length_short`, `s9_rejects_bad_cb_length_long` |
| S10 | Output value / sum ≤ MAX_MONEY | `toolarge` | `s10_rejects_vout_toolarge` |
| S11 | Legacy sigops cost ≤ 80_000 | `bad-blk-sigops` | `s11_rejects_excessive_legacy_sigops` |
| S12 | Connect: P2SH + witness sigops (BIP16/BIP141) | `bad-blk-sigops` | `sigop_cost_tests::*` + connect path `tx_sigop_cost` |

Location: `crates/rbitcoin-consensus/src/block/structure_rule_tests.rs`.

## B. Header — `validate_header` / helpers

| ID | Rule | Error signal | Test |
|----|------|--------------|------|
| H1 | Genesis hash matches params | `BadHeader("genesis hash mismatch")` | `h1_rejects_wrong_genesis_hash` |
| H2 | `prev` links to height−1 | `BadPrev` | `h2_rejects_bad_prev_link` |
| H3 | `time > median_time_past` | `timestamp <= median-time-past` | `h3_rejects_timestamp_not_after_mtp` |
| H4 | Checkpoint hash at height | `checkpoint mismatch` | `h4_rejects_checkpoint_mismatch` |
| H5 | `bits == expected_next_bits` | `incorrect proof of work bits` | `h5_regtest_rejects_wrong_bits` (regtest: must equal prev) |
| H6 | Target ≤ `pow_limit` | `target above pow limit` | `h6_target_above_pow_limit_is_detectable` |
| H7 | PoW valid for claimed bits | `InvalidPow` | **rust-bitcoin** `validate_pow` — smoke via any successful `mine_regtest_block` accept |
| H8 | Time not > now + 2h | `timestamp too far in future` | `h8_rejects_timestamp_too_far_in_future` |

Location: `crates/rbitcoin-test/tests/consensus_rules.rs`.

## C. Connect — `connect_block_prevouts` / `validate_block_connect`

| ID | Rule | Error signal | Test |
|----|------|--------------|------|
| C1–C14 | (see prior matrix) | … | structure / locktime / script unit tests |
| C15 | Core `tx_valid` / `tx_invalid` | accept / reject at listed flags; valid still accepts with extra implemented flags off (FillFlags-implied bits skipped); invalid still rejects with extra **restriction** flags on (not P2SH/WITNESS/TAPROOT class changes) | `script::core_tx_vectors::*` |
| C16 | Core `script_tests.json` | accept / reject | `script::core_vectors::core_script_tests_all_rows` |
| C18 | Core `sighash.json` | 32-byte digest via `SighashCache::legacy_signature_hash` | `script::core_sighash::core_sighash_all_rows` |
| C19 | Core `bip341_wallet_vectors.json` | `verify_job_all_inputs` accept (taproot+witness) | `script::core_bip341::core_bip341_wallet_vectors_all_rows` |
| C20 | Mainnet 866342 + Floresta prevouts | structure + scripts; overweight 4_000_001 WU rejects | `block::block_866342::*` |
| C17 | Stack + altstack share `MAX_STACK_SIZE` | `stack size` | `stack_and_altstack_share_max_size_on_pushdata` ([022](./external_findings/022-stack-altstack-share-max-size.md)) |

## Adding a new rule

1. Add a row to the inventory above (or mark **rust-bitcoin** / **lib** if delegated).
2. Prefer a pure unit test in `rbitcoin-consensus` when no chain state is needed; otherwise `consensus_rules` or a focused scenario.
3. For Core corpora: every row must pass; never reintroduce allowlist/skip debt.
4. Assert on the **error signal** string/variant so removing the check fails the test.

Dependency gate: `cargo tree -i bitcoinconsensus` must not resolve.
