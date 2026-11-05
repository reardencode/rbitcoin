# rust-bitcoin limitations for a consensus node

Two jobs:

1. **Mitigations.** Stable `RB-*` rows for every place we wrap, cast around,
   reimplement, or refuse a rust-bitcoin (or secp-via-rust-bitcoin) API
   because Bitcoin Core consensus requires something else.
2. **Upstream queue.** The same facts, grouped by who would be hurt, so a
   later session can open rust-bitcoin issues or PRs without re-auditing.
   Filed: RB-004
   ([rust-secp256k1#1010](https://git.rust-bitcoin.org/rust-bitcoin/rust-secp256k1/issues/1010)),
   RB-014
   ([rust-bitcoin#7057](https://github.com/rust-bitcoin/rust-bitcoin/issues/7057)),
   RB-015
   ([rust-bitcoin#7020](https://github.com/rust-bitcoin/rust-bitcoin/issues/7020)),
   and RB-019
   ([rust-bitcoin#7019](https://github.com/rust-bitcoin/rust-bitcoin/issues/7019)).
   Checked `master` on 2026-10-17: RB-001, RB-002, RB-003, RB-020, and
   RB-021 are fixed there and still present in 0.32.102. Do not file them.
   RB-016 and RB-017 were reviewed the same day and left unfiled.
   The comparison for everything else is crate **0.32.102**
   as locked in this workspace, not rust-bitcoin `master` and not the open
   issue list. Re-check both before posting.

**Pinned crate:** `bitcoin` **0.32.102** (lock checksum `bb0ce8bd…`).
Update the pin note when the workspace bumps.

rust-bitcoin's own README says the crate must not be used as consensus code.
That does not retire the user-facing bugs below. It does mean the node-only
rows should be filed as a wrong helper, a missing helper, or a docs fix.
We are not asking upstream to absorb `rbitcoin-consensus::script`.

**Not this doc:** Core corpus harness rows in `core_vectors.rs` /
`core_tx_vectors.rs`. Every fixture row must pass (no allowlist). See
[`consensus-tests.md`](./consensus-tests.md). When a gap is "do not use this
rust-bitcoin helper," put it **here**. When our engine still disagrees with
Core, **fix the engine** before commit.

## Process

1. **New workaround → new `RB-*` row** in the same PR (or a docs commit right
   after), and a matching bullet in the queue section that fits.
2. Prefer **mitigated** + code pointer + unit test over a one-off comment.
3. Status: `open` | `mitigated` | `upstream` (upstream fixed; we still pin
   until our tests pass without the bypass).
4. Do not list every `use bitcoin::`. List a consensus-risk bypass, a
   non-obvious bypass, or a queue item we might send upstream.
5. When removing a mitigation, keep a regression test that would fail if the
   naive rust-bitcoin API were used again.
6. Do not file a row from [§ Checked, do not file](#checked-do-not-file).

## Inventory

| ID | Area | Symptom / risk | Our mitigation | Code pointer | Status | Notes |
|----|------|----------------|----------------|--------------|--------|-------|
| RB-001 | `transaction::Version` | Core `nVersion` is **unsigned**; rust-bitcoin `Version(i32)`. Signed `< 2` skips BIP68 at wire `0xFFFFFFFF` (`i32` −1). | `(tx.version.0 as u32) >= 2` via `bip68_active_for_tx`; CSV same cast | `crates/rbitcoin-consensus/src/block/mod.rs` (`bip68_active_for_tx`); `script/interpreter.rs` CSV | mitigated | Finding [003](./external_findings/003-bip68-version-signedness-consensus-split.md); unit `bip68_enforced_when_version_high_bit_set`. Fixed on `master` by [#4039](https://github.com/rust-bitcoin/rust-bitcoin/issues/4039) (`Version(u32)` / `to_u32`). Not filed. 0.32.102 is still `i32` |
| RB-002 | ECDSA sighash type | `EcdsaSighashType::from_consensus(0)` maps **0 → ALL(1)**; mainnet has hashtype **0**. | Parse raw type as `u32`; hash with raw byte; do not round-trip through `from_consensus` | `script/mod.rs` `crypto::parse_der_sig`; `crypto::bip143_signature_hash` writes `raw_ty` | mitigated | Mainnet e.g. block 110300 era. Fixed on `master`: `from_consensus` round-trips, including 0. Not filed. 0.32.102 still collapses |
| RB-003 | P2WPKH / P2WSH sighash helper | `p2wpkh_signature_hash` / `segwit_v0_encode_signing_data_to` hash `EcdsaSighashType::to_u32()`, so non-standard **0x65** (and raw 0) change the digest | Consensus path uses raw hashtype | `script/tests_verify.rs` `mainnet_508011_nested_p2wpkh_raw_sighash_0x65`; `crypto::bip143_*` | mitigated | Mainnet block 508011 nested P2SH-P2WPKH. Fixed on `master` once RB-002 round-trips: the helpers hash that `to_u32()`. Not filed. 0.32.102 still rewrites the type |
| RB-004 | DER parse (libsecp) | `from_der` can return **Ok with wrong (R,S)** on some pre-BIP66 encodings; Core uses **lax** then optional strict check | Always `from_der_lax`; when BIP66, strict encoding check **before** lax parse | `script/mod.rs` `crypto::parse_der_sig`, `is_valid_signature_encoding` | mitigated | e.g. mainnet block 140493-style encodings. Filed [rust-secp256k1#1010](https://git.rust-bitcoin.org/rust-bitcoin/rust-secp256k1/issues/1010) |
| RB-005 | Soft-fork heights | `Params::REGTEST` still has historical Core heights (BIP34 = 100_000_000, BIP65 = 1351, BIP66 = 1251). `Params` has no CSV, segwit, or taproot height | Own `ChainParams`: overwrite the three regtest fields; store the buried heights `Params` lacks | `params.rs` | mitigated | Finding [021](./external_findings/021-regtest-activation-heights.md). Current Core regtest is BIP34/65/66/CSV = 1, segwit = 0 |
| RB-006 | PoW formula | Compact target / retarget multiply-and-clamp lives in rust-bitcoin and matches Core | `CompactTarget::from_next_work_required` via `next_work_bits`. We do not reimplement that math | `header.rs`; [consensus-tests H7](./consensus-tests.md) | delegated | The *scheduler* around the formula is RB-018, not this row |
| RB-007 | BIP331 / package wire types | Package relay messages are not in the crate yet | No private stand-in. Track in COMPAT until upstream has types | `COMPAT.md` | open | Quality **Q-48** |
| RB-008 | Script engine | The only verifier is `consensus::verify_script`, and it is `libbitcoinconsensus` behind the `bitcoinconsensus` feature | In-tree pure-Rust `rbitcoin-consensus::script`. Workspace must not resolve `bitcoinconsensus` | `architecture.md` | mitigated (by design) | Core corpora all-rows-pass. Not an upstream request |
| RB-009 | txid / weight / BIP143 midstates | `compute_txid`, `compute_wtxid`, and `weight` each encode the transaction again. A `SighashCache` rewalks prevouts, sequences, and outputs | `TxPrecompute` one pass at lookup; load and script jobs reuse it. rust-bitcoin stays the unit oracle for the standard six ECDSA types | `query/tx_precompute.rs`; `script::crypto::bip143_*` | mitigated | Performance. SHA-NI is already in `bitcoin_hashes` 0.14; do not add `sha2` for that. `uses_segwit_serialization` is private, so the BIP144-vs-legacy choice is copied |
| RB-010 | Tapscript sighash cost | `taproot_signature_hash` hashes the annex on every call, and the caller rebuilds the tapleaf. A cache per input rehashes spent amounts and scriptPubKeys, and it wants owned `TxOut`s. Digests match ours | `crypto::tap_signature_hash` encodes the BIP341 message from borrowed prevout scripts (`leaf` absent is key path, ext flag 0; `Some` is script path). `TapscriptExecData` caches tapleaf, annex, and `SIGHASH_SINGLE` once per input. `TapSpentHashes` caches spent outputs once per tx | `script/mod.rs` `crypto::tap_signature_hash`; `script/p2tr.rs` `verify_key_path`, `verify_script_path` | mitigated | Performance. Oracle `tapscript_sighash_matches_rust_bitcoin_on_every_hash_type` compares script path and key path |
| RB-011 | Segwit flag 0 | Marker plus flag `0x00` is Core's 10-byte empty transaction (no inputs, no outputs). `Transaction::consensus_decode` returns `UnsupportedSegwitFlag(0)` | `decode_flag_zero_tx` accepts those 10 bytes, then consensus rejects the tx | `query/tx_precompute.rs` `decode_flag_zero_tx`; `store/block_wire.rs` | mitigated | The tx is invalid. The block must still decode so connect can reject it the way Core does |
| RB-012 | Merkle mutation | `merkle_tree::calculate_root` duplicates an odd tail and returns only the root. Core also returns the CVE-2012-2459 mutation bit | `merkle_root_mutated` sets the bit when a level pairs two equal hashes, before odd-padding | `store/integrity.rs`; consensus `merkle_root_bytes` | mitigated | `PartialMerkleTree` is the BIP37 merkleblock, not an Electrum sibling list. That branch is `merkle_branch` |
| RB-013 | BIP34 height parser | `Block::bip34_block_height` accepts only a minimal `PushBytes` and requires `version >= 2`. Core encodes height 0 as `OP_0` and heights 1..=16 as `OP_1`..=`OP_16` | `bip34_height_script` builds that byte string; connect checks the coinbase scriptSig prefix | `block/mod.rs` `check_bip34_coinbase` | mitigated | Mainnet BIP34 starts at height 227931 (a 3-byte push), so this shows up on regtest, signet, and any chain that activates below height 17 |
| RB-014 | Script integers | `read_scriptint` / `read_scriptint_non_minimal` reject a slice longer than 4 bytes. CLTV and CSV use a 5-byte `CScriptNum` | `scriptnum_decode_width(v, max_len, require_minimal)` | `rbitcoin-primitives/src/scriptnum.rs` | mitigated | Finding [004](./external_findings/004-csv-nop-and-scriptnum-width.md). The 4-byte readers are the right arithmetic helper. Filed [rust-bitcoin#7057](https://github.com/rust-bitcoin/rust-bitcoin/issues/7057). `master` `read_cltv_scriptint` already reads a minimal 5-byte number; the open issue is the non-minimal 5-byte operand |
| RB-015 | Sigop cost | `Transaction::total_sigop_cost` always adds P2SH and witness sigops. Its P2SH path counts a redeem script even when the scriptSig contains an opcode above `OP_16`. Core counts that input as 0, and gates the two classes on the script flags | `tx_sigop_cost` / `last_script_push` | `block/mod.rs`; `primitives/script_sigops.rs` | mitigated | Consensus-tests S11, S12. Filed [rust-bitcoin#7020](https://github.com/rust-bitcoin/rust-bitcoin/issues/7020) |
| RB-016 | Absolute lock in a block | `LockTime::is_satisfied_by` is `n <= height` / `n <= time`. That matches CLTV against `tx.nLockTime`. Core `IsFinalTx` is strict `<` against the block height or the cutoff time | `is_final_tx` | `block/mod.rs` | mitigated | Do not ask upstream to change `<=`. Reviewed 2026-10-17. Not filed |
| RB-017 | BIP68 sequence locks | `relative::LockTime::is_satisfied_by` is one input, `<=`, with no disable bit and no median-time past | `sequence_locks_satisfied` (Core `EvaluateSequenceLocks`) plus the unsigned version gate from RB-001 | `block/mod.rs` | mitigated | Reviewed 2026-10-17. Not filed. `master` has the per-input helper; it has no block-connect function |
| RB-018 | Difficulty scheduler | `from_next_work_required` is the 2016-block multiply-and-clamp only. It does not apply "retarget only on the boundary" or the testnet walk back across min-difficulty blocks | `next_work_bits` / `min_diff_bits` call the crate formula on a boundary and walk `bits_at` otherwise | `header.rs` | mitigated | Test `testnet_min_difficulty_after_20_minute_gap` |
| RB-019 | Taproot key-spend helper | `taproot_key_spend_signature_hash` hardcodes `annex = None`. A key-path spend with an annex is consensus-valid; that helper hashes the wrong message. `taproot_script_spend_signature_hash` also drops the annex and pins the codeseparator at `0xFFFFFFFF`. `TapSighashType::from_consensus_u8(0x00)` is `Default`, so a 65-byte signature ending in `0x00` must be rejected before the parser | Key path and script path call in-tree `tap_signature_hash` (annex included; `leaf` absent on key path). They do not call the two wrappers. An explicit `0x00` type byte is rejected. The `0x00 → Default` mapping itself is correct | `script/p2tr.rs` `verify_key_path`, `verify_script_path`; tapscript `checksig_schnorr` | mitigated | Finding [008](./external_findings/008-p2tr-keypath-sighash-zero.md). Mainnet annex key-path example: block 896078. Filed [rust-bitcoin#7019](https://github.com/rust-bitcoin/rust-bitcoin/issues/7019) |
| RB-020 | Witness decode allocation | `Witness::consensus_decode` allows a stack count up to `MAX_VEC_SIZE` (4_000_000), then allocates `count * 4 + 128` bytes before reading any element length. A short `tx`, `block`, `cmpctblock`, or `blocktxn` whose count is 4_000_000 zeros about 16 MB and then fails | Allocation-free pre-walk in `try_decode`. A count that cannot fit in the remaining bytes (an element is at least one byte) is `MessageTooLarge`, which the peer loop scores. Relay `tx`, `block`, `cmpctblock`, and `blocktxn` then walk inputs, outputs, and witnesses a second time inside `consensus_decode`. IBD block frames skip the pre-walk | `net/src/codec.rs` `walk_witness` | mitigated | `short_tx_witness_count_is_message_too_large` and the `block`, `cmpctblock`, and `blocktxn` siblings. A real witness payload still decodes. Fixed on `master` (`WitnessDecoder` grows from bytes received). Not filed. 0.32.102 still allocates up front |
| RB-021 | `merkleblock` bit vector | `PartialMerkleTree::consensus_decode` reads a flag-byte compact-size capped at 4_000_000, then allocates `vec![false; n * 8]` before reading those bytes. At the cap that is 32 MB of bools. This node never asks for or handles a merkle block | The command is `Unknown` before `consensus_decode`. An unrecognized command stays `Unknown` | `net/src/codec.rs` `decode_cmd_payload` | mitigated | `short_merkleblock_is_unknown_without_decoding`. Esplora still builds a `MerkleBlock` itself for `/tx/:txid/merkleblock-proof`. Fixed on `master` (`ByteVecDecoder` reserves as bytes arrive; the bit vector is built from bytes read). Not filed. 0.32.102 still allocates first |
| RB-022 | Taproot tweak scalar | `TapTweakHash::to_scalar` panics when the 32 bytes are at or above the curve order. Core's tweak-add returns 0 | `Scalar::from_be_bytes`; out of range is a commitment failure | `script/p2tr.rs` `output_key_matches_tweak` | mitigated | `script_path_tweak_at_or_above_curve_order_is_not_a_commitment`. 0.32.102 still `expect`s |

## Upstream queue

Suggested titles are drafts. Confirm the behavior on current upstream
`master`, then search the issue tracker, before opening anything.
A row marked **Filed** already has an issue. Do not open a second one.

### Bugs that can hit ordinary rust-bitcoin users

Callers who are not writing a full node. Wallets, tests, indexers, and
regtest harnesses included.

- **RB-003 + RB-002. Segwit sighash helpers hash the normalized type.**
  `EcdsaSighashType::from_consensus` maps `0` and any other non-standard
  value to `All` (or `AllPlusAnyoneCanPay` when bit `0x80` is set).
  `p2wpkh_signature_hash`, `p2wsh_signature_hash`, and
  `segwit_v0_encode_signing_data_to` then write `to_u32()` of that enum.
  A verifier of mainnet block 110300 (hashtype 0) or block 508011
  (hashtype `0x65`) gets a different digest from Core.
  `legacy_signature_hash` already documents and implements the raw `u32`.
  `from_consensus` already warns that it does not round-trip.
  **Ask:** give the segwit encoders the same raw-`u32` input
  `legacy_signature_hash` has, and hash those four bytes. Do not change
  `from_consensus` without a migration; callers rely on the lossy mapping
  for standardness. **Title:** "Segwit sighash helpers cannot verify a
  non-standard hashtype." **Fixed on `master` (2026-10-17). Do not file.**
  `from_consensus(n).to_u32()` is `n`, and the segwit helpers hash that
  value. 0.32.102 still maps a non-standard type to `All` before hashing.

- **RB-004. `Signature::from_der` is not a consensus parse.**
  On some pre-BIP66 encodings (high-bit S without a `0x00` pad; mainnet
  block 140493), libsecp `from_der` returns `Ok` with a different `(R, S)`
  from the OpenSSL-era pair that actually verifies. `from_der_lax`
  recovers that pair. BIP66 is a separate encoding check on the full push
  (DER plus hashtype), run *before* the lax parse.
  **Ask:** document this on the rust-bitcoin / `secp256k1` `from_der` path
  used for Bitcoin signatures. Do not change `from_der` to be lax; strict
  DER is what BIP66 requires, and the two steps are intentionally split.
  **Title:** "`from_der` can succeed with the wrong (R, S) on pre-BIP66
  signatures." **Filed:**
  [rust-secp256k1#1010](https://git.rust-bitcoin.org/rust-bitcoin/rust-secp256k1/issues/1010).

- **RB-005 (regtest numbers only). `Params::REGTEST` does not match Core.**
  0.32.102 still has BIP34 = 100_000_000, BIP65 = 1351, BIP66 = 1251, with
  comments that quote historical Core ("not activated", "rpc activation
  tests"). Current Core `CRegTestParams` sets BIP34, BIP65, BIP66, and CSV
  to 1 (overridable with `-testactivationheight`). Any regtest tool that
  trusts `Params` for "is DERSIG / CLTV / BIP34 active?" disagrees with
  bitcoind. Buried CSV / segwit / taproot heights are a separate, missing
  field (see the API section); this bullet is only the three fields that
  are present and wrong.
  **Ask:** set the three regtest heights to 1, and point the comments at
  current Core. **Title:** "Regtest Params still use pre-activation
  BIP34/65/66 heights."

- **RB-013. `bip34_block_height` rejects Core's small-height encoding.**
  Height 0 is the byte `OP_0`. Heights 1..=16 are `OP_1`..=`OP_16`. The
  parser only accepts `Instruction::PushBytes` via `read_scriptint`, so
  those blocks return `NotPresent`. It also refuses `version < 2` before
  looking at the script. Regtest and signet activate BIP34 at height 1,
  which is `OP_1`. Mainnet's first enforced height is 227931, a 3-byte
  push, so a mainnet-only caller does not see it.
  **Ask:** accept the `OP_0` / `OP_N` encodings Core's `CScript << n`
  emits. **Title:** "`bip34_block_height` rejects OP_0 and OP_1..OP_16."

- **RB-019 (annex half). Key-spend helper drops a consensus-valid annex.**
  `taproot_signature_hash` takes an annex and a codeseparator and is
  correct. `taproot_key_spend_signature_hash` always passes
  `annex = None`, so a key-path spend whose witness is `sig` plus an
  annex (mainnet block 896078) verifies against the wrong message.
  `taproot_script_spend_signature_hash` also passes `annex = None` and
  pins the codeseparator at `0xFFFFFFFF`, so a script-path spend with an
  annex or an executed `OP_CODESEPARATOR` disagrees with Core.
  The 65-byte `0x00` reject is our caller check, not a bad enum:
  `from_consensus_u8(0x00) → Default` is the right name for sighash type
  0. BIP341 forbids that byte only as an explicit 65th byte.
  **Ask:** document the key-spend helper as annex-free, or take an
  `Option<Annex>`. Same for the script-spend wrapper (annex and
  codeseparator). Do not change `from_consensus_u8(0)`. **Title:**
  "`taproot_key_spend_signature_hash` ignores the annex." **Filed:**
  [rust-bitcoin#7019](https://github.com/rust-bitcoin/rust-bitcoin/issues/7019).

- **RB-022. `TapTweakHash::to_scalar` panics above the curve order.**
  `Scalar::from_be_bytes(...).expect(...)` aborts when the hash is at or
  above the secp256k1 order. Core `CheckTapTweak` passes those bytes to
  `secp256k1_xonly_pubkey_tweak_add_check`, and
  `secp256k1_ec_pubkey_tweak_add_helper` returns 0 on overflow, so the
  script-path commitment fails. Reaching it from a real tweak hash takes
  about 2^128 attempts.
  **Ask:** return `Result` instead of panicking, matching
  `Scalar::from_be_bytes`. **Title:** "`TapTweakHash::to_scalar` panics
  when the tweak is out of range." Not filed.

- **RB-020. Witness decode allocates from the element count.**
  `Witness::consensus_decode` accepts a stack count up to `MAX_VEC_SIZE`
  (4_000_000), then allocates `count * 4 + 128` bytes before reading one
  element length. A transaction of a few dozen bytes whose count is
  4_000_000 zeros about 16 MB and then hits end of file. The same decoder
  runs for a prefilled compact-block transaction and for `blocktxn`.
  Relay `tx`, `block`, `cmpctblock`, and `blocktxn` pay that walk twice:
  once to reject a count that cannot fit, then again inside
  `consensus_decode` over inputs, outputs, and witnesses. IBD block
  frames skip the pre-walk.
  **Ask:** if `count` is greater than the bytes still available, return
  before allocating. Each element is at least one byte. **Title:**
  "`Witness::consensus_decode` allocates before checking the payload."
  **Fixed on `master` (2026-10-17). Do not file.** `WitnessDecoder`
  grows from the bytes that arrive and reserves the index table only
  after every element is read. 0.32.102 still allocates `count * 4 + 128`
  up front.

- **RB-021. Partial merkle tree allocates eight bools per flag byte.**
  `PartialMerkleTree::consensus_decode` reads a compact-size byte count
  capped at 4_000_000, then builds `vec![false; n * 8]` before reading
  the flag bytes. At the cap that is 32 MB. Callers who do not need
  BIP37 still pay it if they decode a `merkleblock`.
  **Ask:** size the bit vector from bytes actually read, or cap `n` by
  the remaining length. **Title:** "`PartialMerkleTree` allocates a bit
  per flag before reading it." **Fixed on `master` (2026-10-17). Do not
  file.** Flag bytes go through `ByteVecDecoder`, which reserves as those
  bytes arrive, and the bit vector is built from the bytes read.
  0.32.102 still builds `vec![false; n * 8]` first.

### Consensus gaps that hit a full node and not a wallet

A wallet that signs standard transactions, parses addresses, and checks
CLTV with `is_satisfied_by` does not hit these. A program that connects
untrusted blocks the way Core does will, if it uses the obvious helper.

- **RB-001. BIP68 compares `nVersion` as `uint32`.**
  Wire `0xFFFFFFFF` is `-1` as `Version(i32)`. A signed `< 2` skips
  relative locktime. Core enforces it. The `i32` newtype matches the
  4-byte serialization; the hazard is the comparison.
  **Ask:** a documented `as_u32()` (or equivalent) on `Version`, plus one
  sentence that BIP68 and CSV use the unsigned compare. Do not change the
  field to `u32`; negative versions exist on the wire.
  **Title:** "Version is i32; BIP68 needs an unsigned compare."
  **Fixed on `master` (2026-10-17). Do not file.** [#4039](https://github.com/rust-bitcoin/rust-bitcoin/issues/4039)
  stored `Version` as `u32` with `to_u32()`. Wire `0xFFFFFFFF` is a large
  version, so BIP68 still applies. 0.32.102 is still `Version(pub i32)`.

- **RB-011. Flag 0 does not decode.**
  Core `UnserializeTransaction` treats marker `0x00` plus flag `0x00` as a
  transaction with empty vin and empty vout. Those 10 bytes are also the
  legacy encoding, so the txid matches. rust-bitcoin returns
  `UnsupportedSegwitFlag(0)` from both the reader decoder and the
  pull-based decoder (`UnsupportedSegwitFlag` at the `SegwitFlag` state).
  Block parsers then fail the block before the consensus check that
  rejects an input-less transaction.
  **Ask:** decode flag 0 as that 10-byte transaction. Encoding can keep
  refusing to emit flag 0. **Title:** "Decode segwit flag 0 as Core's
  empty transaction."

- **RB-012. Merkle root without the mutation bit.**
  Duplicating the odd tail is correct and matches Core's root. Core's
  `ComputeMerkleRoot` also reports when a level paired two identical
  hashes. A shorter transaction list can carry the same root
  (CVE-2012-2459). A node that only compares `calculate_root` to the
  header accepts the mutated block. Computing a root for a block template
  the caller built is unaffected.
  **Ask:** `calculate_root` stays as it is; add a variant that returns
  `(root, mutated)`. **Title:** "Merkle helper has no CVE-2012-2459
  mutation flag."

- **RB-014. No 5-byte script number.**
  `read_scriptint` is the right 4-byte arithmetic reader, and it correctly
  errors past 4 bytes. CLTV and CSV allow 5 so a full `u32` locktime stays
  non-negative. An interpreter that uses `read_scriptint` for those
  opcodes rejects spends Core accepts.
  **Ask:** `read_scriptnum(bytes, max_len, require_minimal)` beside the
  existing 4-byte functions. Do not raise the cap on `read_scriptint`.
  **Title:** "Five-byte script numbers can only be read when they are
  minimal CLTV values." **Filed:**
  [rust-bitcoin#7057](https://github.com/rust-bitcoin/rust-bitcoin/issues/7057)
  (2026-10-17). `master` already has `read_cltv_scriptint` for a minimal
  5-byte number, including the CSV disable flag `2147483648`
  (`00 00 00 80 00`). The open issue is the non-minimal operand Core
  accepts with `MINIMALDATA` off: five zero bytes, `tx_valid.json`
  ("5 byte non-minimally-encoded arguments are valid"). Both public
  readers on 0.32.102 return `NumericOverflow` for that operand and for
  the minimal disable-flag operand.

- **RB-015. `total_sigop_cost` is not `GetSigOpCost`.**
  The public method always includes P2SH (scaled) and witness sigops.
  Consensus turns P2SH on with BIP16 and witness sigops on with the
  WITNESS flag. The mainnet BIP16 exception block clears the set. Inside
  the method, a scriptSig that is not push-only (any opcode above
  `OP_16`) still contributes the last push's sigops. Core contributes 0.
  `OP_1NEGATE` and `OP_1`..=`OP_16` leave `GetOp`'s data vector empty, so
  the redeem script is empty and the sigop count is 0.
  `last_pushdata` returning no bytes for those opcodes matches Core.
  A helper that skipped them and kept the previous push would drift.
  **Ask:** a cost function that takes the BIP16 and WITNESS booleans and
  uses Core's push-only rule. **Title:** "`total_sigop_cost` does not
  match Core's block sigop cost." **Filed:**
  [rust-bitcoin#7020](https://github.com/rust-bitcoin/rust-bitcoin/issues/7020).

- **RB-016. No `IsFinalTx`.**
  `is_satisfied_by` uses `<=` and its docs define CLTV satisfaction
  ("a transaction with nLockTime set to this height is valid"). That part
  is right: CLTV requires `script_num <= tx.nLockTime`. Core `IsFinalTx`
  is a different predicate: `nLockTime < block_height` (or `<` the cutoff
  time), unless every input sequence is final. A connect path that passes
  the block height to `is_satisfied_by` accepts a locktime equal to that
  height one block early. Wallet code that passes the current tip and
  means "mineable in the next block" is using the CLTV helper for a
  different question and can be correct by accident.
  **Ask:** add `Transaction::is_final_at(block_height, cutoff_time)` with
  the strict `<`. Leave `is_satisfied_by` alone.
  **Title:** "Add IsFinalTx; do not change LockTime::is_satisfied_by."
  **Not filed (2026-10-17).** Still absent on `master`. Separate from
  closed [#6373](https://github.com/rust-bitcoin/rust-bitcoin/issues/6373).

- **RB-017. No `EvaluateSequenceLocks`.**
  `relative::LockTime` cannot express the disable bit, the type bit, the
  512-second granularity against the *creating* block's median time, or
  the block-wide `min_height >= nHeight` failure. Combined with RB-001,
  version `0xFFFFFFFF` is the interesting case.
  **Ask:** a free function that takes the transaction, the previous
  heights, the previous median times, the block height, and the previous
  block's median time. **Title:** "Add EvaluateSequenceLocks."
  **Not filed (2026-10-17).** `master` can decode one sequence and answer
  the per-input "next block" question. It still has no block-connect
  function. The version half of this row is RB-001, already fixed on
  `master`.

- **RB-005 (absent fields) + RB-018. Deployment heights and the retarget
  scheduler.** `Params` stores BIP16 time and BIP34/65/66 heights. It does
  not store buried CSV, segwit, or taproot heights (Core mainnet
  419328 / 481824 / 709632; regtest CSV = 1 and segwit = 0). It also does
  not implement `GetNextWorkRequired`: retarget only when the height is a
  multiple of the interval, and on testnet walk backward across
  `powLimit` blocks until a non-limit `nBits` or a retarget boundary.
  `allow_min_difficulty_blocks` is only a flag. The multiply-and-clamp
  (RB-006) is already correct.
  **Ask:** optional height fields, and a `next_work_required` that takes
  the parent bits, the timestamps, and a bits-at-height callback.
  **Title:** "Params have no buried segwit/CSV/taproot heights, and no
  testnet difficulty walk."

### Performance only

Digests and counts match the crate. The in-tree code exists so IBD does
not hash the same transaction once per input and once per signature opcode.

- **RB-009. One-pass ids and midstates.**
  `SighashCache` already caches prevouts, sequences, and outputs *per
  cache*. A second cache, or `compute_txid` plus `weight` plus a cache,
  walks the transaction again. Block validation wants Core's
  `PrecomputedTransactionData`: those hashes, plus spent amounts and
  spent scriptPubKeys, filled once and shared by every input.
  **Ask:** a constructor that accepts those six hashes, or a way to clone
  the cache's midstate across inputs without rehashing. Making
  `uses_segwit_serialization` public is a small companion so callers can
  see the BIP144 choice without copying the predicate.
  **Title:** "Let SighashCache take precomputed BIP143/BIP341 midstates."

- **RB-010. Tapscript sighash is quadratic in the witness.**
  Each `taproot_signature_hash` call re-hashes the annex (prefixed with
  its compact size) and expects a freshly built `TapLeafHash`. Spent
  outputs are hashed again if the caller builds a new cache per input,
  and that cache wants owned `TxOut`s. Validation weight grows with the
  same witness bytes, so a tapscript full of `CHECKSIG` is quadratic.
  Key path and script path share one in-tree message (`leaf` absent is
  ext flag 0) over borrowed script bytes. The oracle locks byte-equality
  with `taproot_signature_hash` on every BIP341 hash type, for both
  paths, with and without an annex.
  **Ask:** accept an already-hashed annex and an already-hashed tapleaf,
  and document that one cache must be reused across inputs.
  **Title:** "taproot_signature_hash rehashes the annex on every opcode."

Neither item is a reason to reimplement `sha2`. `bitcoin_hashes` 0.14
already has SHA-NI.

### Missing API worth requesting

Not a wrong answer from an existing function. File only if we still want
the helper after the bugs above are in.

- **RB-007.** BIP331 package messages. No local wire types until the crate
  has them. **Title:** "BIP331 package relay types."
- **RB-008, explicitly not requested.** A pure-Rust script interpreter is
  our consensus engine. Upstream's position is that the crate is not a
  consensus library. The `bitcoinconsensus` feature is the supported
  escape hatch, and we refuse it so the node does not link
  `libbitcoinconsensus`.
- **`split_anyonecanpay_flag` is `pub(crate)`.** Only interesting if the
  segwit helpers stay enum-typed (RB-003). If they take a raw `u32`, we
  do not need the splitter.
- **BIP158 from a script iterator.** `BlockFilter::new_script_filter`
  needs a `Block` and an `OutPoint → Script` closure. `GcsFilterWriter`
  is the right encoder and we call it. A constructor from output-script
  and spent-script iterators would let an indexer build the same filter
  without a wire block. Low priority.

### Checked, do not file

- **`Target::difficulty_float` matches Core `GetDifficulty` for compact
  targets.** Both compute `(0xffff / mantissa) * 256^(29 - exponent)`.
  Their constant `TARGET_MAX_F64` is the expanded genesis target
  `0x1d00ffff`. A compact target's 24-bit mantissa is exact in `f64`.
  RPC difficulty calls this helper. It is not a workaround.
- **`TapSighashType::from_consensus_u8(0x00) → Default`.** Correct name
  for the type. The consensus reject is "65-byte signature whose last
  byte is `0x00`", which is the caller's length check (RB-019).
- **`LockTime::is_satisfied_by` uses `<=`.** That is CLTV, documented on
  the method. The node gap is the missing `IsFinalTx` (RB-016), not this
  operator.
- **`Block::witness_root`.** The witness merkle root of wtxids with a
  zero coinbase leaf. The BIP141 commitment is
  `sha256d(witness_root || coinbase_nonce)`. We hash that from
  precomputed wtxids so connect does not call `compute_wtxid` again.
  The root helper is the right primitive.
- **RB-006.** `CompactTarget::from_next_work_required` and
  `Target::is_met_by` stay upstream. We own only the scheduler (RB-018).
- **`SighashCache::legacy_signature_hash`.** Already hashes the raw
  `u32`. The interpreter and the P2PKH path call it.
- **`ControlBlock::verify_taproot_commitment`.** Script-path uses it for
  the merkle proof, the tweak, and `tweak_add_check`.
- **`GcsFilterWriter`.** BIP158 bit packing stays upstream. Our code only
  chooses the element set: non-`OP_RETURN` outputs, then spent
  scriptPubKeys. Tests require the bytes to equal `new_script_filter`.
- **High-S ECDSA.** libsecp rejects high S. Consensus does not (BIP146
  never activated). `verify_ecdsa` normalizes S before verify. That is a
  call we make, not a rust-bitcoin defect. Early mainnet P2PK spends
  (block 183) need it.
- **Local codecs.** `read_compact_size` / `write_compact_size` exist
  because store and mempool records are not rust-bitcoin values. The IBD
  input walk applies the same non-minimal refusal as `VarInt`
  (`NonMinimalVarInt`) without allocating a `Block`. That compact-size
  codec is not an upstream gap. Hex encode, decode, and display-order
  32-byte ids live in `rbitcoin-primitives`. The bodies and the errors
  are hex-conservative, the crate behind `bitcoin::hex`. `0x` / `0X` is
  stripped there. A 32-byte id whose hex is not 64 characters is that
  crate's length error, which does not look at the digits.
- **Non-canonical compact difficulty.** `difficulty_float` matches Core
  `GetDifficulty` when every mantissa bit lands inside the 256-bit target.
  The mantissa is at most `0x7fffff`. Size `3..=32` qualifies. Size `33`
  qualifies at a mantissa of at most `0xffff`, and size `34` at most
  `0xff`. A smaller size qualifies when the shifted-off low bits are
  clear. Network pow limits are in that set. A zero target makes
  `difficulty_float` `+inf` and the old loop a finite ratio: the sign
  bit, size `0`, and a size of `1` or `2` that shifts every remaining bit
  off (`0x0100ffff` was `2^224`). A partial drop stays finite and larger
  than the old loop (`0x0200ffff` leaves target `255`, at `257/256` of
  the old `2^216`). Size `33` or `34` past those mantissa limits drops
  high bits. Size `35` or more masks the shift with `0xff`. Size `35` is
  a shift of `0`, so the mantissa stays and the difficulty is huge where
  the old loop is small.
  `format_core_double` prints a non-finite result as `0`, which is what
  `getblock`, `getblockheader`, and `getblockchaininfo` return.
  `getmininginfo` puts the raw float in JSON, which is `null` when the
  value is non-finite. A connected tip cannot have a zero target.
- **RB-008 as an upstream port.** Do not send the interpreter.

## Related

- Core corpus policy (no allowlist): [`consensus-tests.md`](./consensus-tests.md)
- External differential findings (fixed **001–023**): [`external_findings/`](./external_findings/)
- Architecture script split: [`architecture.md`](./architecture.md)
