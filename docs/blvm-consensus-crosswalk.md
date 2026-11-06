# BLVM consensus register crosswalk

This file owns the map from the Bitcoin Commons **BLVM** consensus
register onto rbitcoin production code and tests. Our own rule ids
(S1, H1, C15, …) stay in [`consensus-tests.md`](./consensus-tests.md).
Do not copy those rows here.

Compared tree: rbitcoin `master` @ `4c0924f6a`.
Their register: [BTCDecoded/blvm-spec](https://github.com/BTCDecoded/blvm-spec)
`CONSENSUS_SPEC.md` @ `6b7ae49dc077cf174a2367b4d56eeeb31dcb8de5`
(2026-11-06). Version 1.0, status Draft. 163 numbered rules, each
claimed to have an Orange Paper section. The Orange Paper
(`PROTOCOL.md` in that repo) is the math those ids point at. This
page checks the numbered MUSTs against our connect path and against
Bitcoin Core v32.1 `GetBlockScriptFlags` / `ContextualCheckBlockHeader`,
not their Z3 proofs.

A row is a **match** when our reject matches the sentence and Core.
**Implied** means a stronger check we already run makes the sentence
true. **Absent** means we do not implement it. **Differs** means both
sides state a rule and the predicates are not the same. **Property**
is a theorem, not a block reject. **Policy** is mempool, which their
section 18 says is not block consensus.

## Where a chain would split

These are the register sentences that do not match what Core v32.1
enforces, and what we enforce.

1. **Witness flag is per block, not per transaction.** Their SC-017
   and Table 4 turn `SCRIPT_VERIFY_WITNESS` on only when that
   transaction has a non-empty witness or “is a SegWit transaction.”
   SEG-004 defines a SegWit transaction as one that **creates** a v0
   output. Core sets `P2SH | WITNESS | TAPROOT` on every transaction
   in the block (`validation.cpp` `GetBlockScriptFlags`), and replaces
   that set only for the two exception hashes. We do the same in
   `ScriptVerifyFlags::consensus_at`
   (`crates/rbitcoin-consensus/src/block/mod.rs`). A post-SegWit spend
   of a v0 program with an empty witness, and with no v0 output
   created, is anyone-can-spend if the flag stays off. It is invalid
   for Core and for us.

2. **`nBits` must equal the next-work result.** Core rejects
   `bad-diffbits` when `nBits != GetNextWorkRequired`. We reject
   `incorrect proof of work bits` in `check_header` and
   `validate_header_on_parent`
   (`crates/rbitcoin-consensus/src/header.rs`). Their HDR-007 checks
   proof of work against the **header’s own** bits, and says that
   copying the ancestor’s bits is not a substitute for that hash
   check. The register never says the header’s bits must equal
   `GetNextWorkRequired`. A header that meets an easier self-claimed
   target is invalid for us and Core. Their register does not say so.
   Test: `h7_rejects_header_hash_above_target` covers the hash check;
   `header_and_spending_boundaries` covers the bits mismatch.

3. **Chain work is the inverse of the target.** REORG-002 says
   cumulative work is the sum of `ExpandTarget(bits)`. Summing targets
   prefers easier blocks. Core `GetBlockProof` is the inverse.
   `chain_work_after` (`crates/rbitcoin-ibd/src/ibd/header_walk.rs`)
   adds `Header::work()`. Test: `chain_work_sums_distinct_header_bits`
   (`crates/rbitcoin-net/tests/chain.rs`).

4. **Compressed witness keys are policy.** Table 4 lists
   `SCRIPT_VERIFY_WITNESS_PUBKEYTYPE` as a consensus flag from taproot
   height, and only on a transaction that creates a P2TR output. Core
   does not set that flag in `GetBlockScriptFlags`. We leave
   `witness_pubkeytype` false on the consensus path. Test:
   `empty_sig_still_checks_pubkey_encoding` accepts an uncompressed
   witness key with the flag off and rejects it with the flag on.

5. **Version floor before BIP34.** HDR-001 rejects header version 0
   at every height. Core and
   `check_header_version_and_future_time` apply floors only after
   BIP34 (version ≥ 2), BIP66 (≥ 3), and BIP65 (≥ 4). Before height
   227,931 a version-0 header with valid work is legal for Core and
   for us. No mainnet header is version 0. Test of the floors we do
   enforce: `h9_version_floors_at_bip34_66_65`.

6. **Second coinbase.** BLK-002 requires the first transaction to be
   a coinbase and does not forbid another one.
   `reject_bad_block_tx_layout` returns `coinbase not first`. Test:
   `rpc_regtest_from_genesis` (consensus-tests S3).

7. **Testnet minimum difficulty.** After a 20-minute gap, testnet3
   may use the proof-of-work limit. The 163 rules do not say this.
   `next_work_bits` does. Test:
   `testnet_min_difficulty_after_20_minute_gap`.

8. **Regtest constants.** CONST-003 and CONST-008 state a 210,000-block
   halving and a retarget every 2,016 blocks, and no other network.
   Regtest halves every 150 blocks and does not retarget
   (`ChainParams::subsidy_halving_interval`,
   `no_pow_retargeting`). That matches Core. Test:
   `p1_block_subsidy_halvings`, `crates/rbitcoin-consensus/tests/params.rs`.

9. **Supply wording disagrees with itself.** SEC-004 says the supply
   converges to exactly 21 million BTC. ECO-007 says that from height
   `33 × 210_000` the integer sum is 2,099,999,997,690,000 satoshis.
   `block_subsidy` is the integer right shift (ECO-001), and it
   returns 0 once the shift count reaches 64. Nothing in the suite
   pins the 33-halving total.

## Not a live mainnet split

BIP54 (BLK-012, BLK-013, BLK-014, CB-007, SF-009, SF-010, SF-015) is
in their register and marked inactive on mainnet, testnet, and signet.
We do not implement the per-transaction 2,500-sigop cap, the consensus
ban on a non-coinbase whose stripped size is exactly 64 bytes, the
coinbase `nLockTime == height − 1` rule, or BIP54 version-bits
lock-in. The 600-second time-warp bound **is** implemented, under
Core’s BIP94 switch: `check_timewarp` runs when `enforce_bip94` is
set, which is testnet4 only. Mainnet leaves it off, as Core does.

CTV (SC-021, `OP_NOP4`) and CSFS (SC-020) are specified and disabled
on mainnet in their Table 1 (`u64::MAX`). We treat `OP_NOP4` as a
success NOP. `0xba` in tapscript is `OP_CHECKSIGADD`, not CSFS.
Regtest in their table activates both at height 0 when the feature is
compiled. A regtest node with those features on would disagree with us.

## Rules we enforce that the register does not number

| Rule | Production | Test |
|------|------------|------|
| Header `nBits` equals next work, including the factor-of-4 clamp and the pow-limit cap | `header::check_header`, `header::next_work_bits`, `header::retarget_bits` | `header_and_spending_boundaries`; `mainnet_retarget_32256_matches_core_compact`; `retarget_clamps_timespan_and_caps_at_pow_limit` |
| Testnet min-difficulty after 20 minutes | `header::next_work_bits` | `testnet_min_difficulty_after_20_minute_gap` |
| Regtest: no retarget, halving every 150 | `ChainParams::regtest`, `block_subsidy` | `params.rs` network asserts; `p1_block_subsidy_halvings` |
| Genesis hash | `check_header` → `check_genesis_hash` | `header_and_spending_boundaries`; `validate_header_genesis_and_bad_prev` |
| Only the first transaction is a coinbase | `reject_bad_block_tx_layout` | consensus-tests S3, `rpc_regtest_from_genesis` |
| Duplicate txids, even when they are not an adjacent merkle pair | `validate_block_structure_with_pres` | `s5_rejects_duplicate_txid` |
| Coinbase-less body that contains a 64-byte stripped tx is mutated (Core `IsBlockMutated`). The block is already invalid. This is not the BIP54 ban | `reject_bad_block_tx_layout` | `no_coinbase_with_a_64_byte_tx_is_mutated` |
| Genesis coinbase is not a coin | `facts::reject_genesis_coinbase_spend` | `header_and_spending_boundaries` |
| `OP_RETURN`, or a script longer than 10,000 bytes, is not a coin | `policy::is_unspendable`, `facts::reject_unspendable_prevout` | `spending_an_unspendable_output_is_missing_prevout` |
| Block and tx stripped size ≤ 1,000,000 (weight already implies this) | `validate_block_structure_with_pres`, `check_tx_shape` | `s14_stripped_size_1_000_000_accepts_1_000_001_rejects`; `s16_tx_stripped_size_1_000_000_accepts_1_000_001_rejects` |
| Script-flag exception hashes (BIP16 mainnet block, taproot block at height 692,261) | `ScriptVerifyFlags::consensus_at` | `script_flags_follow_core_exception_table`; `exception_hashes_change_which_scripts_run` |
| Milestone script skip is two header hashes on the path, not assumevalid chainwork | `milestone` gate, confirm | `anchored_milestone_skips_a_failing_p2pkh_script` |
| Testnet4 is its own network: BIP94 on, BIP34 hash null, so the BIP30 ancestry skip never applies | `ChainParams::testnet4` | `params.rs` |
| Signet challenge bytes are re-encoded like Core `CScript <<`, and the challenge runs without `CLEANSTACK` | `signet::check_signet_block_solution` | `signet_section_reencodes_pushes_like_core_cscript`; `signet_challenge_op_true_twice_is_not_cleanstack`; `signet_challenge_p2wpkh_empty_witness_rejected` |
| Mempool has no 65-byte non-witness floor (their MEM-003). Replacement does not require an RBF signal (their “standard” mode, not the conservative mode) | `mempool::accept::prepare_admit`, `rbf_pays_for_replacement` | `accept_life_journey`; `replacement_unconfirmed_inputs_follow_libre_rule` |

## Register map

Paths are under `crates/`. Tests are `#[test]` functions unless noted.
`core_script_tests_all_rows`, `core_tx_valid_all_rows`,
`core_tx_invalid_all_rows`, `core_sighash_all_rows`, and
`core_bip341_wallet_vectors_all_rows` are the Core v32.1 corpora
(consensus-tests C15–C19). “corpus” below means those harnesses.

### 1. Header

| ID | Their rule | Production | Test | Result | 
|----|------------|------------|------|---|
| HDR-001 | Version ≥ 1 always | Floors only after BIP34/66/65: `check_header_version_and_future_time` | `h9_version_floors_at_bip34_66_65` | differs |
| HDR-002 | BIP90 version floors | same function | `h9_version_floors_at_bip34_66_65` | match |
| HDR-003 | Timestamp ≠ 0 | `check_header`: time > median | `header_and_spending_boundaries` (time == mtp rejects) | implied |
| HDR-004 | Time ≤ network + 7,200s | `check_header_version_and_future_time` | `h8_rejects_timestamp_too_far_in_future`; `h8_timestamp_exactly_two_hours_accepts_plus_one_rejects` | match |
| HDR-005 | Time strictly after median | `check_header`, `median_time_past_times` | `header_and_spending_boundaries` | match |
| HDR-006 | Compact bits ≠ 0 | Bits must equal next work. A zero target is rejected by `ChainParams::apply_regtest_pow_bits` | `header_and_spending_boundaries`; `regtest_pow_bits_overlay_is_regtest_only_and_bounded` | implied |
| HDR-007 | Hash ≤ expanded **claimed** target | `pow_hash_meets_target`. We also require bits = next work (not in their sentence) | `h7_rejects_header_hash_above_target` | differs |
| HDR-008 | `prev` hash links | `check_header` | `header_and_spending_boundaries`; `validate_header_genesis_and_bad_prev` | match |

### 2. Block

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| BLK-001 | At least one tx | `reject_bad_block_tx_layout` | consensus-tests S1, `rpc_regtest_from_genesis` | match |
| BLK-002 | First tx is coinbase | `reject_bad_block_tx_layout` | S2, `no_coinbase_with_a_64_byte_tx_is_mutated` | match |
| BLK-003 | Every tx passes the local check | `check_tx_local` / `check_tx_shape` inside `validate_block_structure_with_pres` | S13, S15, S16, S17, S18 | match |
| BLK-004 | Inputs resolve against the set at this height | confirm spend walk, `facts::reject_prevout_spent` | `header_and_spending_boundaries` (C38) | match |
| BLK-005 | Scripts run, except assumevalid below a chainwork floor | Scripts run in `verify_job_all_inputs`. Skip is the milestone hash pair, not assumevalid chainwork | `anchored_milestone_skips_a_failing_p2pkh_script`; `block_866342_structure_scripts_and_overweight` | differs |
| BLK-006 | Coinbase value ≤ subsidy + fees | `block_subsidy` plus the connect value check | `rejects_coinbase_excess_value_fast`; `p1_block_subsidy_halvings` | match |
| BLK-007 | Weight ≤ 4,000,000 | `validate_block_structure_with_pres` | `s4_weight_4_000_000_accepts_4_000_001_rejects` | match |
| BLK-008 | Sigop cost ≤ 80,000 | same walk, `MAX_BLOCK_SIGOPS_COST` | `sigop_cost_tests`; S11/S12 in `rpc_regtest_from_genesis` | match |
| BLK-009 | Merkle root matches txids | `merkle_root_mutated` before other body rules | `s6_rejects_merkle_root_mismatch`; `body_rules_run_after_the_header_merkle_check` | match |
| BLK-010 | Reject adjacent duplicate hashes (CVE-2012-2459) | `rbitcoin-primitives` `merkle_root_mutated` | `merkle_mutation_flags_a_repeated_tail_at_any_level` | match |
| BLK-011 | SegWit commitment and weight when witness rules apply | witness-commitment scan in the structure walk | `s8_accepts_witness_commitment_with_reserved_value`; `s8_last_witness_commitment_output_wins`; `s8_rejects_nonce_lengths_beside_32` | match |
| BLK-012 | After BIP54, ≤ 2,500 sigops per non-coinbase tx | not implemented | — | absent |
| BLK-013 | After BIP54, stripped size exactly 64 is invalid for a non-coinbase | not implemented. The coinbase-less 64-byte case is the mutation flag above, and it is not this rule | — | absent |
| BLK-014 | After BIP54, time-warp bound on a retarget boundary | `check_timewarp`, only if `enforce_bip94` (testnet4). Not version-bits BIP54 | `timewarp_floor_is_600_seconds_before_the_parent_on_testnet4`; `bip94_proposal_rejects_a_timewarp` | differs |

### 3. Transaction

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| TX-001 | ≥ 1 input and ≥ 1 output | `check_tx_shape` | `s15_rejects_empty_vin`; S13 | match |
| TX-002 | Each output in `0 ..= MAX_MONEY` | `tx_value_out` | S10, `rpc_regtest_from_genesis` | match |
| TX-003 | Output sum ≤ MAX_MONEY | `tx_value_out` | S10 | match |
| TX-004 | No repeated outpoint inside one tx | `reject_duplicate_outpoints` | S17 | match |
| TX-005 | Non-coinbase prevouts are non-null | `reject_null_prevouts` | S18 | match |
| TX-006 | No separate cap on input or output count | No such cap. The bound is weight | S16 is the size bound, not a count cap | match |
| TX-007 | Stripped size × 4 ≤ 4,000,000 | `check_tx_shape` (`bad-txns-oversize` at 1,000,001) | `s16_tx_stripped_size_1_000_000_accepts_1_000_001_rejects` | match |
| TX-008 | Txid is double-SHA256 of the non-witness serialization | `TxPrecompute::from_tx` / `compute_txid` | corpus `core_sighash_all_rows`; structure tests that recompute txids | match |
| TX-009 | Input sum ≥ output sum | connect value check, `facts::fee_from_values` | `header_and_spending_boundaries` (C40) | match |
| TX-010 | Coinbase fee contribution is zero | coinbase is not summed as a spender | `rejects_coinbase_excess_value_fast` | match |
| TX-011 | Legacy sighash runs FindAndDelete | `interpreter` legacy scriptCode | `legacy_multisig_empty_sig_deletes_op_0_from_script_code`; `find_and_delete_pushdata_lengths` | match |
| TX-012 | Witness v0 and tapscript do not FindAndDelete | witness sighash paths | `core_sighash_all_rows`; `script_path_codeseparator_checksig_chain` | match |
| TX-013 | Legacy scriptCode strips `OP_CODESEPARATOR` at opcode positions | legacy sighash serializer | `core_sighash_all_rows` | match |
| TX-014 | After BIP66, sighash byte 0 is illegal; before it, 0 means `SIGHASH_ALL` | `parse_der_sig` with the DERSIG flag | `p2wpkh_der_follows_bip66_flag_and_push_size`; corpus | match |
| TX-015 | P2SH sighash uses the redeem script | `nested::verify_p2sh_legacy` | corpus; `p2sh_legacy_op_1negate_scriptsig_accepted` | match |
| TX-016 | BIP143 binds prevouts, sequences, amount, outputs, locktime | `crypto::bip143_p2wpkh_signature_hash` and the P2WSH path | `core_sighash_all_rows` | match |
| TX-017 | P2WPKH scriptCode is the 25-byte P2PKH expansion | `p2wpkh::verify` | `core_sighash_all_rows`; `p2wpkh_der_follows_bip66_flag_and_push_size` | match |
| TX-018 | P2WSH scriptCode is the witness script | `p2wsh` verify | corpus | match |

### 4. Coinbase

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| CB-001 | One null input, index `0xffffffff` | `Transaction::is_coinbase` | S2 | match |
| CB-002 | scriptSig length 2..=100 | structure walk `bad-cb-length` | `s9_coinbase_scriptsig_length_two_accepts_one_rejects` | match |
| CB-003 | BIP34: minimal height push | `check_bip34_coinbase` | `s7_rejects_bip34_missing_at_height_1`; `bip34_tests` | match |
| CB-004 | Before BIP34 the height push is not required | `bip34_active_at` guard | `s7_bip34_not_required_at_height_0` | match |
| CB-005 | Duplicate coinbase txid while an output is unspent, except the two mainnet hashes | `ChainParams::is_bip30_repeat`, confirm BIP30 | `is_bip30_repeat_matches_core`; `buried_rules_and_a_lying_header_path`; `bip30_duplicate_coinbase_in_one_batch` | match |
| CB-006 | Any other duplicate coinbase is rejected | same | `repeated_coinbase_chain_rejects_what_core_rejects` | match |
| CB-007 | After BIP54, coinbase locktime is height−1 and sequence is not final | not implemented | — | absent |
| CB-008 | Maturity 100 | connect maturity check | `coinbase_maturity_holds_inside_one_confirm_batch` | match |
| CB-009 | Witness commitment when a witness is present | structure walk | `s8_coinbase_witness_without_commitment_is_missing`; `s8_rejects_empty_or_multi_item_coinbase_witness_reserved` | match |
| CB-010 | Coinbase witness leaf is 32 zero bytes | commitment hash uses that leaf | `witness_commitment_script_honors_reserved`; `s8_accepts_witness_commitment_with_reserved_value` | match |

### 5. Script

The opcode machine is `rbitcoin-consensus/src/script/interpreter.rs`.
Resource limits and flag behavior are pinned by the Core corpora plus
the named tests.

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| SC-001 | Success is one true stack item | `eval_script` | `core_script_tests_all_rows` | match |
| SC-002 | Main stack + altstack ≤ 1,000 | `eval_script` | `stack_and_altstack_share_max_size_on_pushdata` | match |
| SC-003 | Base and witness v0: ≤ 10,000 bytes, ≤ 201 non-push ops | `eval_script` | corpus; `p2sh_legacy_scriptsig_over_10k_rejected` | match |
| SC-004 | Element ≤ 520 bytes | witness and eval push checks | `script_path_rejects_initial_element_over_520`; `p2pkh_signature_push_over_520_rejected_pre_bip66` | match |
| SC-005 | P2SH scriptSig is push-only | `nested` P2SH path | corpus | match |
| SC-006 | P2SH template is 23 bytes | `classify` | corpus | match |
| SC-007 | CHECKSIG costs 1; CHECKMULTISIG costs n or the legacy 20 | `script_sigops` | `sigop_cost_tests` | match |
| SC-008 | Coinbase contributes no P2SH sigops | sigop walk skips coinbase P2SH | `sigop_cost_tests` | match |
| SC-009 | Witness v0 sigops count; taproot key-path counts 0 | `count_witness_sigops` path in the block walk | `witness_empty_p2wsh_and_v1_program_cost_zero`; `witness_p2wpkh_counts_one` | match |
| SC-010 | Tapscript sigops count `0xac`, `0xad`, `0xba` at opcode positions | tapscript sigop counter | `sigop_cost_tests` | match |
| SC-011 | Null dummy after BIP147 | `null_dummy` flag from SegWit height | `witness_v0_nulldummy_follows_the_flag` | match |
| SC-012 | Strict DER after BIP66 | `check_signature_encoding` | `p2wpkh_der_follows_bip66_flag_and_push_size`; corpus | match |
| SC-013 | `OP_VER` fails only in an executed branch | interpreter conditional | corpus | match |
| SC-014 | Minimal IF | Consensus for tapscript. Witness v0 only if the policy flag is on. `consensus_at` leaves `minimal_if` false | `script_path` tapscript tests; corpus rows that set `MINIMALIF` | match |
| SC-015 | Flags are monotone in height, aside from the exception hashes | `ScriptVerifyFlags::consensus_at` | `script_flags_follow_core_exception_table` | match |
| SC-016 | Exception-hash blocks use the override set | `consensus_at` | `exception_hashes_change_which_scripts_run` | match |
| SC-017 | Witness flag is per transaction | Flag is per block. See the split list | `witness_program_rules_bind_below_segwit_height`; `script_flags_follow_core_exception_table` | differs |
| SC-018 | CLTV: same locktime type, and `tx.lockTime` ≥ stack value | interpreter BIP65 arm | corpus; `finality_tests` | match |
| SC-019 | Threshold 500,000,000 | `LOCKTIME_THRESHOLD` | `is_final_tx` via `header_and_spending_boundaries` (C36) | match |
| SC-020 | CSFS (BIP348) in tapscript | not implemented | — | absent |
| SC-021 | CTV (BIP119) template hash | `OP_NOP4` is a NOP | corpus NOP rows | absent |
| SC-022 | Empty `CScriptNum` is zero | `scriptnum` | `rbitcoin-primitives` `scriptnum` tests; corpus | match |
| SC-023 | P2SH runs the last push after the pattern matches | `nested::verify_p2sh_legacy` | `p2sh_script_pubkey_push_counts_against_max_stack_size` | match |
| SC-024 | Bare `OP_ELSE` fails; a second `OP_ELSE` flips again | interpreter | corpus | match |

### 6. UTXO

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| UTX-001 | A normal tx removes spent coins and adds outputs | confirm apply, in order | `header_and_spending_boundaries` | match |
| UTX-002 | Coinbase only adds | coinbase has no prevout lookup | same | match |
| UTX-003 | Apply-by-id matches apply | one apply path | spend tests do not fork a second applier | match |
| UTX-004 | Undo restores the previous set | disconnect in `rbitcoin-net` chain | `disconnect_to_without_mempool_skips_block_at_height`; `most_work_reorg_depth16_and_invalid_mid_branch_restores_tip` | match |
| UTX-005 | Sum of UTXO values equals issued supply | No stored UTXO sum. Per-block subsidy and fee checks are what we run | `rejects_coinbase_excess_value_fast` | implied |
| UTX-006 | Input sum ≥ output sum | same as TX-009 | C40 | match |
| UTX-007 | Spent prevout must exist | `MissingPrevout` | C38; `same_batch_spend_of_a_later_block_is_missing` | match |

### 7. Context

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| CTX-001 | Sequence bit 31 disables the relative lock | `sequence_locks_satisfied` | `bip68_disable_flag_and_time_type` | match |
| CTX-002 | Bit 22 selects time | same | `bip68_disable_flag_and_time_type` | match |
| CTX-003 | Value is the low 16 bits | same | `finality_tests` | match |
| CTX-004 | Enforced only when version as **unsigned** ≥ 2 and CSV is active | `bip68_active_for_tx` | `bip68_disabled_by_version_1`; `bip68_enforced_when_version_high_bit_set` | match |
| CTX-005 | Time lock is `value × 512` added to the coin’s median, minus 1 | `sequence_locks_satisfied` | `bip68_height_zero_time_lock_uses_the_median` | match |
| CTX-006 | Height lock is coin height + value − 1 | same | `bip68_height_relative_lock` | match |
| CTX-007 | Passes only when height and time are strictly greater | same (`>=` fails) | `finality_tests` boundary 109/110 | match |
| CTX-008 | Median is the upper middle of up to 11 timestamps | `median_time_past_times` | `median_time_past_tests` | match |
| CTX-009 | Mempool requires absolute and relative finality at the tip | `is_final_tx`; mempool admit calls it | `accept.rs` `bip68_time_lock_uses_coin_create_mtp` | policy |
| CTX-010 | Retarget span is 2,015 intervals, clamped to 1/4 .. 4× | `retarget_bits` | `retarget_clamps_timespan_and_caps_at_pow_limit` | match |
| CTX-011 | BIP94: first block of a period has time ≥ parent − 600 | `check_timewarp` when `enforce_bip94` | header BIP94 tests | match |
| CTX-012 | Money math uses checked add/sub | Output sums reject above `MAX_MONEY` before connect. Internal fee adds are not a separate checked-arithmetic proof | S10 | implied |
| CTX-013 | A relative lock whose prevout is missing fails before outputs are recorded | unresolved coin age fails closed | `bip68_unresolved_coin_age_fails_closed` | match |

### 8–9. Activation

Heights in `ChainParams` match their Table 1 for mainnet, testnet3,
regtest, and signet. Testnet4 is extra (taproot and the buried forks
at height 1, BIP94 on). Tests: `crates/rbitcoin-consensus/tests/params.rs`
(`signet_buried_deployments_match_core`, mainnet segwit 481,824,
taproot 709,632, testnet3 taproot 2,011,968).

| ID | Their rule | Disposition |
|----|------------|-------------|
| SF-001 | P2SH at 173,805 | match. `bip16_active_from_prev_mtp` |
| SF-002 | BIP34 at 227,931 | match |
| SF-003 | BIP66 at 363,725 | match |
| SF-004 | CLTV at 388,381 | match |
| SF-005 | CSV at 419,328 | match |
| SF-006 | SegWit at 481,824 | match. Null dummy shares this height |
| SF-007 | Taproot mainnet 709,632 | match. `taproot_height` |
| SF-008 | Taproot testnet 2,011,968, regtest 0, signet 1 | match. Testnet4 is 1, which their table does not list |
| SF-009 | BIP54 signals on bit 15, start time 0 | absent |
| SF-010 | Active at a configured BIP54 height | absent |
| SF-011 | DER is not required before BIP66 | match. Flag is height-gated |
| SF-012 | Before the BIP90 floors, version ≥ 1 passes | match. Version 0 before BIP34 is HDR-001, not this sentence |
| SF-013 | Null dummy is not required before SegWit | match |
| SF-014 | Rules stay on after their height | match, except the two exception hashes (SC-016) |
| SF-015 | BIP54 height comes from version-bits lock-in | absent |

Their Table 3 BIP30 exceptions and the skip until height 1,983,702
match `is_bip30_repeat` and `BIP34_IMPLIES_BIP30_LIMIT`. Test:
`is_bip30_repeat_matches_core`.

### 10. Constants

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| CONST-001 | Amounts are satoshis, 10^8 per BTC | integer satoshis throughout | subsidy and value tests | match |
| CONST-002 | Nothing above `MAX_MONEY` | `tx_value_out` | S10 | match |
| CONST-003 | Halving every 210,000 | 210,000 except regtest 150 | `p1_block_subsidy_halvings` | differs |
| CONST-004 | Weight ≤ 4,000,000 | `MAX_BLOCK_WEIGHT` | `s4_weight_4_000_000_accepts_4_000_001_rejects` | match |
| CONST-005 | Sigop cost ≤ 80,000 | `MAX_BLOCK_SIGOPS_COST` | `sigop_cost_tests` | match |
| CONST-006 | Maturity 100 | connect | `coinbase_maturity_holds_inside_one_confirm_batch` | match |
| CONST-007 | Script limits 10,000 / 1,000 / 201 / 520 | interpreter | SC-002..SC-004 tests | match |
| CONST-008 | Retarget every 2,016, spacing 600s | `difficulty_adjustment_interval`. Regtest does not retarget. Signet spacing can be overridden | `retarget_clamps_timespan_and_caps_at_pow_limit` | differs |

### 11. Economics

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| ECO-001 | Subsidy is `50 BTC >> floor(height / interval)`, and 0 at shift ≥ 64 | `block_subsidy` | `p1_block_subsidy_halvings` | match |
| ECO-002 | Total supply is the sum of subsidies | not computed as a chain total | — | property |
| ECO-003 | That sum stays ≤ MAX_MONEY | follows from ECO-001. Not a separate connect check | — | property |
| ECO-004 | The sum is monotone | follows from a non-negative subsidy | — | property |
| ECO-005 | Supply-limit predicate | no `validate_supply_limit` function | — | property |
| ECO-006 | Fees ≥ 0 | TX-009 | C40 | match |
| ECO-007 | Sum from height `33 × H` is 2,099,999,997,690,000 sats | the shift implements it. No test pins the total | — | property |

### 12. Proof of work

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| POW-001 | Compact bits > 0 to expand | rust-bitcoin `Target::from_compact`. A zero header target fails the next-work compare | HDR-006 | implied |
| POW-002 | Exponent in 3..=32; zero mantissa expands to 0 | `Target::from_compact` | no direct exponent-range test | implied |
| POW-003 | Next work is in `(0, MAX_TARGET]` | `retarget_bits` caps at `pow_limit` | `retarget_clamps_timespan_and_caps_at_pow_limit` | match |
| POW-004 | Compress and expand invert | rust-bitcoin compact target. We do not ship a separate inverse test | — | property |
| POW-005 | Proof-of-work check is deterministic | `pow_hash_meets_target` | `h7_rejects_header_hash_above_target` | property |

### 13. SegWit

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| SEG-001 | Weight = `3 × base + total` | structure weight | `s4_weight_4_000_000_accepts_4_000_001_rejects` | match |
| SEG-002 | `weight/4 ≤ vsize ≤ weight/4 + 1` | `policy::vbytes_ceil` is the ceil form. It is policy math, not a block reject | `saturated_weight_stays_a_huge_vsize` | policy |
| SEG-003 | v0 programs are 20 or 32 bytes | `verify_native_witness` | corpus; unknown lengths are anyone-can-spend or malleated, matching Core | match |
| SEG-004 | “A SegWit transaction must create a v0 output” | We do not require that. A transaction may spend a witness program and create none | corpus | differs |
| SEG-005 | Commitment is `SHA256d(witness root ‖ reserved)` | commitment check | `s8_accepts_witness_commitment_with_reserved_value` | match |
| SEG-006 | Nested P2WPKH/P2WSH uses BIP143 | `nested::try_p2sh_nested_segwit` | corpus | match |
| SEG-007 | Empty witness stack is empty | `witness.is_empty` | `s8_rejects_empty_or_multi_item_coinbase_witness_reserved` | match |
| SEG-008 | Version byte is `OP_0` or `OP_1`..`OP_16` | `classify::witness_program` | `unknown_witness_v16_accepts_without_discourage` | match |

### 14. Taproot

Production is `script/p2tr.rs` and the tapscript arm of
`interpreter.rs`.

| ID | Their rule | Test | Result |
|----|------------|------|---|
| TAP-001 | P2TR is `OP_1 PUSH32` | `core_bip341_wallet_vectors_all_rows`; `script_path_accepts_with_valid_bip341_tweak` | match |
| TAP-002 | scriptSig empty | corpus; malleation rejects | match |
| TAP-003 | Output key is the tweaked internal key | `script_path_rejects_wrong_output_key` | match |
| TAP-004 | Script path proves the leaf | `script_path_rejects_tampered_control_block`; `script_path_accepts_two_merkle_nodes` | match |
| TAP-005 | Key-path witness is 64 or 65 bytes, and 65 must not end in `0x00` | `key_path_accepts_valid_schnorr`; `key_path_rejects_65_byte_sighash_byte_zero` | match |
| TAP-006 | Annex (`0x50`) is stripped before sighash | `key_path_annex_must_enter_sighash`; `bip341_annex_detection_edges`; `script_path_accepts_leaf_0x50_with_annex_and_0xc2` | match |
| TAP-007 | Key-path sighash is `Tag("TapSighash")` | `key_path_accepts_valid_schnorr`; `core_bip341_wallet_vectors_all_rows` | match |
| TAP-008 | Script-path sighash binds leaf, codeseparator, key version | `script_path_codeseparator_checksig_chain`; `script_path_annex_checksig` | match |
| TAP-009 | CHECKMULTISIG disabled in tapscript | `checkmultisig_verify_fail_and_tapscript_disabled` | match |

### 15. Reorg and signet

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| REORG-001 | Reorg only to strictly more work | header walk adopts when `work > tip` | `most_work_reorg_depth16_and_invalid_mid_branch_restores_tip` | match |
| REORG-002 | Work is the sum of expanded targets | `Header::work()` (inverse of target) | `chain_work_sums_distinct_header_bits` | differs |
| REORG-003 | Undo inverts connect. A missing spent coin is an error | chain disconnect | `disconnect_fails_when_a_connected_height_has_no_block` | match |
| REORG-004 | Disconnect to the fork, then connect forward | most-work reorg | `most_work_reorg_depth16_and_invalid_mid_branch_restores_tip` | match |
| SIG-001 | Signet commitment must satisfy the challenge | `signet::check_signet_block_solution` | `signet_block_1_rejects_mutated_solution`; `signet_challenge_p2wpkh_empty_witness_rejected` | match |

### 16–17. Properties

| ID | Their rule | What we actually pin | |
|----|------------|----------------------|---|
| SEC-001 | Merkle root is deterministic | `merkle_root_mutated`. Test: primitives `merkle` suite | property |
| SEC-002 | Connect is deterministic | no purity proof. The connect tests are the pin | property |
| SEC-003 | Apply is side-effect-free | confirm writes are the effect, after validation | property |
| SEC-004 | Supply converges to exactly 21 million BTC | Contradicts ECO-007. The code follows the integer shift | differs |
| SEC-005 | Script time and space are O(ops) | tapscript sigop weight: `script_path_rejects_tapscript_validation_weight`. Base scripts hit the op and stack caps | match |
| ENG-001 | Serialize and parse invert | `check_block_wire`; bitcoin consensus encode. Not a proof | property |
| ENG-002 | Truncated wire is rejected | `check_block_wire` | match |
| ENG-003 | Locktime type boundary matches for CLTV and CSV | `LOCKTIME_THRESHOLD` shared | match |
| ENG-004 | Connect checks subsidy, fees, and the supply cap together | Subsidy and fees are checked. There is no whole-chain supply predicate | implied |

### 18. Mempool (not block consensus)

| ID | Their rule | Production | Test | Result |
|----|------------|------------|------|---|
| MEM-001 | No coinbase in the mempool | `prepare_admit` returns `AcceptError::Coinbase` | `accept_error_display_and_reject_paths` | match |
| MEM-002 | CheckTransaction and standardness | `check_tx_shape` then Libre policy (`policy.rs`). Dust is allowed. Standard weight cap is 400,000 | `accept_life_journey` | differs |
| MEM-003 | Non-witness size ≥ 65 | not enforced | — | absent |
| MEM-004 | RBF needs a conflict and a higher fee rate. Conservative mode also needs a sequence signal | `rbf_pays_for_replacement` has no signal requirement | `replacement_unconfirmed_inputs_follow_libre_rule` | differs |

## What this does not claim

Their spec-lock annotations and Z3 runs were not re-executed. A row
marked **match** means the reject we ship is the one Core ships for
that sentence. It does not mean the Orange Paper formula was checked
in a solver. Historical mainnet script acceptance is the Core v32.1
corpora plus block 866,342, as in
[`consensus-tests.md`](./consensus-tests.md).
