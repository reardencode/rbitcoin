# External findings (fuzzamoto / differential / redteam)

Consensus, P2P, and mempool issues reported against rbitcoin (Bitcoin Core primary vs
rbitcoin reference, or redteam static analysis). Numbered reports live beside this index.

| ID | Severity | Topic | Status | Regression (shipped) |
|----|----------|--------|--------|----------------------|
| [001](./001-disconnect-on-invalid-block.md) | medium | Peer disconnect on invalid relayed block (BIP-152) | fixed | `rbitcoin-net` `peer::tests::cmpct_helpers_without_mempool_and_queue_out_closed` |
| [002](./002-store-corrupt-record-on-invalid-block.md) | low | Invalid block misclassified as store corrupt | fixed | `rbitcoin-consensus` `error::tests::archive_unresolved_parent_is_missing_prevout_not_corrupt` |
| [003](./003-bip68-version-signedness-consensus-split.md) | high | BIP68 skipped for version with bit 31 set | fixed | `block::tests::bip68_enforced_when_version_high_bit_set` |
| [004](./004-csv-nop-and-scriptnum-width.md) | high | CSV v1 no-op; CLTV/CSV 4-byte scriptnum | fixed | `script::interpreter::tests::csv_fails_when_tx_version_below_2` + Core script corpus |
| [005](./005-non-topological-block-accepted.md) | high | Non-topological same-block spends accepted | fixed | `rbitcoin-test` `consensus_rules::c8_same_block_child_before_parent_rejected` |
| [006](./006-p2sh-scriptsig-push-size.md) | medium | P2SH scriptSig pushes not limited to 520 bytes | fixed | `script::nested::tests::p2sh_scriptsig_push_over_520_rejected` |
| [007](./007-p2sh-nested-witness-exactness.md) | medium | P2SH nested-witness scriptSig exactness / program rules | fixed | `script::nested` nested-witness malleation tests |
| [008](./008-p2tr-keypath-sighash-zero.md) | medium | P2TR key-path 65-byte sig with sighash byte 0x00 | fixed | `script::p2tr::tests::key_path_rejects_65_byte_sighash_byte_zero` |
| [009](./009-witness-commitment-reserved.md) | medium | Witness commitment empty/multi-item coinbase witness | fixed | `block::tests::s8_rejects_empty_or_multi_item_coinbase_witness_reserved` |
| [010](./010-mempool-confirmed-spentness.md) | medium | Mempool no confirmed-chain spentness check | fixed | `rbitcoin-mempool` `accept::tests::reject_when_provider_has_no_unspent_coin` |
| [011](./011-mempool-structural-chain-context.md) | medium | Mempool no structural chain-context validation | fixed | `accept::tests::reject_non_final_locktime_height`, `reject_immature_coinbase` |
| [012](./012-p2sh-redeem-not-executed.md) | high | P2SH redeem skipped when BIP16 looks off | fixed | `bip16_from_prev_mtp_exception_and_time` |
| [013](./013-bip68-unresolved-age-fail-open.md) | high | BIP68 unresolved coin age fails open | fixed | `bip68_unresolved_coin_age_fails_closed` |
| [014](./014-stranded-on-peer-reorg.md) | high | Stranded when peer reorgs (sync) | fixed | `drain_requests_missing_parent_of_pending_branch` |
| [015](./015-spend-rejected-block-outputs.md) | high | Spend outputs of a rejected block | fixed | cluster 017/019 + structural fail-closed |
| [016](./016-unknown-taproot-leaf-rejected.md) | critical | Unknown tapleaf version rejected | fixed | `script_path_accepts_unknown_taproot_leaf_version` |
| [017](./017-duplicate-txid-unconnected-instance.md) | medium | Txid resolve hits unconnected instance | fixed | `resolve_txid_prefers_connected_over_newer_unconnected` |
| [018](./018-compact-block-duplicate-tx.md) | high | Compact block duplicates a tx | fixed | `repeated_short_id_is_requested_not_duplicated` |
| [019](./019-bip30-not-enforced.md) | critical | BIP30 not enforced | fixed | cluster 015/017 + BIP34-gated batch |
| [020](./020-pending-child-after-reorg.md) | high | Pending child not connected after reorg | fixed | `drain_connects_pending_child_of_new_tip_after_reorg` |
| [021](./021-regtest-activation-heights.md) | low | Regtest BIP65/66 heights stale | fixed | `params::tests::for_network_and_helpers` |
| [022](./022-stack-altstack-share-max-size.md) | high | `MAX_STACK_SIZE` ignored altstack on PushBytes / TUCK | fixed | `stack_and_altstack_share_max_size_on_pushdata` |
| [023](./023-tapscript-initial-stack-limits.md) | high | Tapscript initial witness stack skipped 1000/520 limits | fixed | `script_path_rejects_initial_stack_over_max_size` |

**012–021:** fuzzamoto differential report (`rbitcoin-report.tar.gz`, baseline
`8f3990f`). Report-local 001–010 are **renumbered** here. Identity/BIP30
(015/017/019) is one cluster (`TipOnly` confirm lookup + fail-closed height).

**Policy:** Core `script_tests` / `tx_valid` / `tx_invalid` corpora must pass **every**
data row with **no allowlist**. Do not commit if those tests fail. Findings stay
**fixed** with a named regression on the shipped path.

**006–009:** consensus accept-invalid (zip 2026-08-10) — **fixed** in-tree. **010–011:**
mempool remediation **fixed** (Coin spentness + structural tip checks + fee path).

Remediation (2026-08): 001–005 fixed in-tree; see each file **Status** and **Regression**.
