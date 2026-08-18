# rust-bitcoin limitations for a consensus node

Living list. Add a row when we wrap, cast around, reimplement, or refuse a
rust-bitcoin (or secp-via-rust-bitcoin) API because **Bitcoin Core consensus**
requires something else.

**Pinned crate:** `bitcoin` **0.32.x** (workspace `Cargo.toml` / lock; currently
`0.32.101` range). Update the pin note when the workspace bumps.

**Not this doc:** Core corpus harness rows in `core_vectors.rs` /
`core_tx_vectors.rs` — every fixture row must pass (no allowlist). See
[`consensus-tests.md`](./consensus-tests.md). When a gap is “do not use this
rust-bitcoin helper,” put it **here**; when the engine still disagrees with Core,
**fix the engine** before commit.

## Process

1. **New workaround → new row** in the same PR (or docs commit right after).
2. Prefer **mitigated** + code pointer + unit test over a one-off comment only.
3. Status: `open` | `mitigated` | `upstream` (upstream fixed; we still pin until
   our tests pass without the bypass).
4. Do not list every `use bitcoin::` — only consensus-risk or non-obvious bypasses.
5. When removing a mitigation, keep a regression test that would fail if the
   naive rust-bitcoin API were used again.

## Inventory

| ID | Area | Symptom / risk | Our mitigation | Code pointer | Status | Notes |
|----|------|----------------|----------------|--------------|--------|-------|
| RB-001 | `transaction::Version` | Core `nVersion` is **unsigned**; rust-bitcoin `Version(i32)`. Signed `< 2` skips BIP68 at wire `0xFFFFFFFF` (`i32` −1). | `(tx.version.0 as u32) >= 2` via `bip68_active_for_tx`; CSV same cast | `crates/rbitcoin-consensus/src/block.rs` (`bip68_active_for_tx`); `script/interpreter.rs` CSV | mitigated | Finding [003](./external_findings/003-bip68-version-signedness-consensus-split.md); unit `bip68_enforced_when_version_high_bit_set` |
| RB-002 | ECDSA sighash type | `EcdsaSighashType::from_consensus(0)` maps **0 → ALL(1)**; mainnet has hashtype **0**. | Parse raw type as `u32`; hash with raw byte; do not round-trip through `from_consensus` for legacy | `script/mod.rs` `crypto::parse_der_sig` | mitigated | Mainnet e.g. block 110300 era |
| RB-003 | P2WPKH sighash helper | `p2wpkh_signature_hash` uses `from_consensus(n).to_u32()`, breaks non-standard hashtype **0x65** | Consensus path uses raw hashtype (not naive helper) | `script/tests_verify.rs` `mainnet_508011_nested_p2wpkh_raw_sighash_0x65`; p2wpkh verify path | mitigated | Mainnet block 508011 nested P2SH-P2WPKH |
| RB-004 | DER parse (libsecp) | `from_der` can return **Ok with wrong (R,S)** on some pre-BIP66 encodings; Core uses **lax** then optional strict check | Always `from_der_lax`; when BIP66, strict encoding check **before** lax parse | `script/mod.rs` `crypto::parse_der_sig` | mitigated | e.g. mainnet block 140493-style encodings |
| RB-005 | Soft-fork heights | rust-bitcoin `Params` heights ≠ Inquisition/Core buried heights we need (e.g. REGTEST bip34 huge; CSV regtest) | Own `ChainParams` overlay (`csv_height`, `segwit_height`, `taproot_height`, …) | `params.rs` | mitigated | Local mining / script flags |
| RB-006 | PoW / retarget | Compact target / retarget math lives in rust-bitcoin | `expected_next_bits` / `validate_pow` via rust-bitcoin; H7 documented as delegated | `header.rs`; [consensus-tests H7](./consensus-tests.md) | mitigated | We do not reimplement PoW math |
| RB-007 | BIP331 / wire types | Some P2P message types not exposed yet | Track outside script; COMPAT / experimental docs | `COMPAT.md`, `experimental-mainnet.md` | open | Not an allowlist issue |
| RB-008 | Full script engine | rust-bitcoin is **not** a Core script consensus engine; we intentionally avoid `bitcoinconsensus` | In-tree pure-Rust `rbitcoin-consensus::script` | `architecture.md` | mitigated (by design) | Core corpora all-rows-pass |
| RB-009 | Structure / BIP143 midstates | `compute_txid`/`compute_wtxid`/`block.weight` plus `SighashCache` rewalk prevouts | `TxPrecompute` one-pass at lookup; load + script jobs reuse stash; rust-bitcoin is the unit oracle | `query/tx_precompute.rs`; `script::crypto::bip143_*` | mitigated | SHA-NI already in `bitcoin_hashes` 0.14; do not add `sha2` for that |

## Related

- Core corpus policy (no allowlist): [`consensus-tests.md`](./consensus-tests.md)
- External differential findings (fixed **001–021**): [`external_findings/`](./external_findings/)
- Architecture script split: [`architecture.md`](./architecture.md)
