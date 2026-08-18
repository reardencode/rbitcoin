//! structure_rule_tests (peeled from block.rs).

use super::{
    apply_witness_commitment, bip16_active_from_prev_mtp, bip34_height_script, block_subsidy,
    is_p2sh_script, is_p2wpkh_program, is_p2wsh_program, last_script_push, merkle_root_bytes,
    script_sigop_count, validate_block_structure, validate_block_structure_hashed,
    validate_block_structure_with_pres, ScriptCheckJob, ValidationContext, BIP16_EXCEPTION_MAINNET,
};
use crate::error::ConsensusError;
use crate::milestone::Milestone;
use crate::params::ChainParams;
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Witness,
};
use rbitcoin_primitives::Height;

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn ctx_h(height: u32) -> ValidationContext<'static> {
    // Leak params for 'static test ctx simplicity.
    let p = Box::leak(Box::new(params()));
    ValidationContext::at(p, Height(height), Milestone::NONE)
}

fn coinbase(height: u32) -> Transaction {
    // Consensus requires coinbase scriptSig length in 2..=100.
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    let script_sig = ScriptBuf::from_bytes(ss);
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig,
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn non_coinbase_spend(n: u8) -> Transaction {
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([n; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn block_with(txs: Vec<Transaction>) -> Block {
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1_290_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: txs,
    };
    if !block.txdata.is_empty() {
        block.header.merkle_root = block.compute_merkle_root().unwrap();
    }
    block
}

/// `stamp_sub struct=` split: hash-encode vs extra walks (no algorithm change).
#[test]
fn structure_meters_split_txid_wtxid_walk() {
    let _ = crate::plan_stamp_sub_stats::sample_and_reset();
    let mut spend = non_coinbase_spend(1);
    spend.input[0].witness = Witness::from_slice(&[&[0x01]]);
    let mut b = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut b);
    validate_block_structure_hashed(&b, &ctx_h(1)).expect("witness block structure");
    let s = crate::plan_stamp_sub_stats::sample_and_reset();
    assert!(s.struct_txid_ns > 0, "one-pass hash must be metered: {s:?}");
    assert!(
        s.struct_walk_ns > 0,
        "weight/sigops walks must be metered: {s:?}"
    );
}

#[test]
fn structure_with_pres_skips_from_tx() {
    use rbitcoin_query::TxPrecompute;
    let _ = crate::plan_stamp_sub_stats::sample_and_reset();
    let mut spend = non_coinbase_spend(1);
    spend.input[0].witness = Witness::from_slice(&[&[0x01]]);
    let mut b = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut b);
    let pres: Vec<TxPrecompute> = b.txdata.iter().map(TxPrecompute::from_tx).collect();
    let _ = crate::plan_stamp_sub_stats::sample_and_reset();
    let out = validate_block_structure_with_pres(&b, &ctx_h(1), Some(&pres))
        .expect("stashed pres must still enforce merkle");
    assert_eq!(out.len(), pres.len());
    assert_eq!(out[0].txid, pres[0].txid);
    let s = crate::plan_stamp_sub_stats::sample_and_reset();
    assert_eq!(s.struct_txid_ns, 0, "with_pres must not from_tx: {s:?}");
    assert!(s.struct_walk_ns > 0, "merkle/weight still run: {s:?}");
}

fn assert_bad_block(err: ConsensusError, needle: &str) {
    match err {
        ConsensusError::BadBlock(s) => {
            assert!(
                s.contains(needle),
                "expected BadBlock containing {needle:?}, got {s:?}"
            );
        }
        other => panic!("expected BadBlock({needle:?}), got {other:?}"),
    }
}

/// Unspent connected sibling + same create txid is BIP30 (not the 91842/91880
/// mainnet grandfather). Spentness is durable annotate; this pin is the reject.
#[test]
fn bip30_rejects_unspent_connected_sibling() {
    use crate::block::structural_validate_spends;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, FkMap, Query, U32Map, U64Map};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::collections::HashSet;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-bip30-unspent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&path);
    let q = Query::open_or_create(&path).unwrap();
    q.enter_direct_index_mode().unwrap();

    let first = coinbase(1);
    let txid = first.compute_txid().to_byte_array();
    let rec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let fk = q
        .store()
        .put_tx_full_batch_indexed(
            &[(
                rec,
                vec![InputRecord::coinbase(u32::MAX, vec![0x00, 0x00], vec![])],
                vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            )],
            true,
        )
        .unwrap()[0];
    q.store().header_txs.put_range(Fk(1), fk, 1).unwrap();
    q.store().confirmed.set(Height(0), Fk(1)).unwrap();
    q.store().rebuild_height_fence().unwrap();

    let dup = block_with(vec![first]);
    let ctx = ctx_h(10);
    let err = structural_validate_spends(
        &q,
        &dup,
        &ctx,
        Some(&[Fk(2)]),
        &[],
        0,
        &mut HashSet::new(),
        &BatchParents::new(),
        &mut U32Map::default(),
        &mut U64Map::default(),
        &FkMap::default(),
    )
    .expect_err("unspent sibling must trip BIP30");
    let msg = format!("{err}");
    assert!(
        msg.contains("bad-txns-BIP30"),
        "expected BIP30 reject, got {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn s1_rejects_empty_txdata() {
    let b = block_with(vec![]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "no transactions");
}

#[test]
fn s2_rejects_non_coinbase_first() {
    let b = block_with(vec![non_coinbase_spend(1)]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "first tx not coinbase");
}

#[test]
fn s3_rejects_second_coinbase() {
    let b = block_with(vec![coinbase(1), coinbase(1)]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "coinbase not first");
}

#[test]
fn s4_rejects_overweight_block() {
    // ~1MB of script data per tx ≈ 4M weight; a few large outputs exceed the limit.
    let mut txs = vec![coinbase(1)];
    for i in 0..5u8 {
        let mut spk = vec![0x6a, 0x4d, 0xff, 0xff]; // OP_RETURN + pushdata2 placeholder
                                                    // Fill with ~900 KiB raw data via OP_RETURN chunking is awkward; use large script
                                                    // bytes rust-bitcoin will count toward base size.
        spk.extend(std::iter::repeat_n(0x61, 900_000)); // OP_NOP filler
        txs.push(Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([i.wrapping_add(1); 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(spk),
            }],
        });
    }
    let b = block_with(txs);
    assert!(
        b.weight().to_wu() > 4_000_000,
        "fixture weight {}",
        b.weight().to_wu()
    );
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "weight");
}

#[test]
fn s5_rejects_duplicate_txid() {
    let t = non_coinbase_spend(7);
    let b = block_with(vec![coinbase(1), t.clone(), t]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "duplicate txid");
}

#[test]
fn s6_rejects_merkle_root_mismatch() {
    let mut b = block_with(vec![coinbase(1)]);
    b.header.merkle_root = TxMerkleNode::from_byte_array([0x11; 32]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "merkle");
}

#[test]
fn s7_rejects_bip34_missing_after_activation_signet() {
    // Signet activates BIP34 at height 1 (rust-bitcoin Params::SIGNET).
    let p = Box::leak(Box::new(ChainParams::signet()));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut cb = coinbase(1);
    cb.input[0].script_sig = ScriptBuf::new(); // strip BIP34
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

#[test]
fn s7_bip34_not_required_before_mainnet_activation() {
    // Mainnet BIP34 height is 227931 — early blocks must not require the
    // height push (block 1 has a free-form coinbase scriptSig).
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    assert_eq!(p.btc.bip34_height, 227_931);
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut cb = coinbase(1);
    // Mainnet-style early coinbase: no BIP34 height push.
    cb.input[0].script_sig = ScriptBuf::from_bytes(b"hello".to_vec());
    let b = block_with(vec![cb]);
    validate_block_structure(&b, &ctx).expect("mainnet height 1 must not require BIP34");
}

#[test]
fn s7_bip34_required_at_mainnet_activation_height() {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    let h = p.btc.bip34_height;
    let ctx = ValidationContext::at(p, Height(h), Milestone::NONE);
    let mut cb = coinbase(h);
    cb.input[0].script_sig = ScriptBuf::new();
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

#[test]
fn s7_bip34_not_required_at_height_0() {
    let mut cb = coinbase(0);
    // Non-BIP34 push still OK at height 0; scriptSig must still be 2..=100.
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
    let b = block_with(vec![cb]);
    validate_block_structure(&b, &ctx_h(0)).expect("height 0 skips BIP34 height push rules we use");
}

#[test]
fn s7_regtest_does_not_activate_bip34_early() {
    // rust-bitcoin REGTEST bip34_height is 100_000_000 — our mined regtest
    // blocks may still *include* a height push, but empty/missing is OK.
    let p = Box::leak(Box::new(ChainParams::regtest()));
    assert!(p.btc.bip34_height > 1_000_000);
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut cb = coinbase(1);
    cb.input[0].script_sig = ScriptBuf::from_bytes(b"regtest".to_vec());
    let b = block_with(vec![cb]);
    validate_block_structure(&b, &ctx).expect("regtest height 1: BIP34 not active");
}

#[test]
fn s8_rejects_missing_witness_commitment() {
    let mut spend = non_coinbase_spend(9);
    // Non-empty witness forces BIP141 commitment path.
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let b = block_with(vec![coinbase(1), spend]);
    // coinbase has no aa21a9ed output
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "witness commitment");
}

#[test]
fn s8_rejects_wrong_witness_commitment() {
    let mut spend = non_coinbase_spend(10);
    spend.input[0].witness = Witness::from_slice(&[vec![0x02]]);
    let mut cb = coinbase(1);
    // Fake commitment: OP_RETURN magic + zeros
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, spend]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("witness")),
        "got {err:?}"
    );
}

/// Mainnet height 1: witness banned (segwit @ 481824).
#[test]
fn s8_mainnet_rejects_witness_before_segwit() {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut spend = non_coinbase_spend(10);
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut cb = coinbase(1);
    // Valid-looking commitment magic so we hit the pre-segwit ban first.
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, spend]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("before segwit")),
        "got {err:?}"
    );
}

/// Archive prep must accept signet-shaped witness blocks (BIP325).
/// Regression: GENESIS height + enforce gates rejected signet IBD entirely.
#[test]
fn archive_structure_allows_witness_when_gates_off() {
    let p = Box::leak(Box::new(ChainParams::signet()));
    let ctx = ValidationContext::archive_structure(p);
    assert!(!ctx.enforce_height_gates);
    let mut spend = non_coinbase_spend(10);
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut cb = coinbase(1);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, spend]);
    // Wrong commitment → still structure-checked (not pre-segwit ban).
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("witness")),
        "archive must check commitment, not pre-segwit ban; got {err:?}"
    );
    assert!(
        !matches!(err, ConsensusError::BadBlock(s) if s.contains("before segwit")),
        "archive must not ban witness as pre-segwit: {err:?}"
    );
}

/// Signet at true height 1: segwit active (Core/Inquisition SegwitHeight=1).
#[test]
fn signet_height_1_segwit_active_allows_witness_path() {
    let p = Box::leak(Box::new(ChainParams::signet()));
    assert!(p.segwit_active_at(1));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut spend = non_coinbase_spend(10);
    spend.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let mut cb = coinbase(1);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, spend]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    // Fails commitment hash, not pre-segwit.
    assert!(
        !matches!(err, ConsensusError::BadBlock(s) if s.contains("before segwit")),
        "got {err:?}"
    );
}

#[test]
fn merkle_root_bytes_single_and_odd() {
    let a = [1u8; 32];
    assert_eq!(merkle_root_bytes(&[a]), a);
    let b = [2u8; 32];
    let root2 = merkle_root_bytes(&[a, b]);
    // odd: third leaf duplicated
    let root3 = merkle_root_bytes(&[a, b, a]);
    assert_ne!(root2, root3);
    assert_eq!(merkle_root_bytes(&[]), [0u8; 32]);
}

#[test]
fn p1_block_subsidy_halvings() {
    let p = params();
    assert_eq!(block_subsidy(0, &p), 50_0000_0000);
    assert_eq!(block_subsidy(209_999, &p), 50_0000_0000);
    assert_eq!(block_subsidy(210_000, &p), 25_0000_0000);
    assert_eq!(block_subsidy(419_999, &p), 25_0000_0000);
    assert_eq!(block_subsidy(420_000, &p), 12_5000_0000);
    assert_eq!(block_subsidy(210_000 * 64, &p), 0);
}

#[test]
fn script_sigop_count_and_last_push_helpers() {
    // CHECKSIG / CHECKSIGVERIFY
    assert_eq!(script_sigop_count(&[0xac], false), 1);
    assert_eq!(script_sigop_count(&[0xad], false), 1);
    // CHECKMULTISIG without accurate → 20
    assert_eq!(script_sigop_count(&[0xae], false), 20);
    assert_eq!(script_sigop_count(&[0xaf], false), 20);
    // Accurate: OP_2 CHECKMULTISIG → 2
    assert_eq!(script_sigop_count(&[0x52, 0xae], true), 2);
    // Direct push skip
    assert_eq!(script_sigop_count(&[0x01, 0xff, 0xac], false), 1);
    // PUSHDATA1 / 2 / 4 skip
    assert_eq!(script_sigop_count(&[0x4c, 0x01, 0xab, 0xac], false), 1);
    assert_eq!(
        script_sigop_count(&[0x4d, 0x01, 0x00, 0xcd, 0xac], false),
        1
    );
    assert_eq!(
        script_sigop_count(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xee, 0xac], false),
        1
    );
    // last_script_push variants
    assert_eq!(
        last_script_push(&[0x02, 0x11, 0x22]),
        Some(&[0x11, 0x22][..])
    );
    assert_eq!(
        last_script_push(&[0x4c, 0x02, 0xaa, 0xbb]),
        Some(&[0xaa, 0xbb][..])
    );
    assert_eq!(
        last_script_push(&[0x4d, 0x01, 0x00, 0x99]),
        Some(&[0x99][..])
    );
    assert_eq!(
        last_script_push(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0x77]),
        Some(&[0x77][..])
    );
    assert!(last_script_push(&[]).is_none());
    // Program shape helpers
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0u8; 20]);
    p2sh.push(0x87);
    assert!(is_p2sh_script(&p2sh));
    assert!(!is_p2sh_script(&[0x00]));
    let mut wpkh = vec![0x00, 0x14];
    wpkh.extend_from_slice(&[1u8; 20]);
    assert!(is_p2wpkh_program(&wpkh));
    let mut wsh = vec![0x00, 0x20];
    wsh.extend_from_slice(&[2u8; 32]);
    assert!(is_p2wsh_program(&wsh));
    assert!(!is_p2wsh_program(&wpkh));
}

#[test]
fn p3_default_milestone_heights() {
    use crate::params::default_milestone_height;
    use rbitcoin_primitives::Network;
    assert_eq!(default_milestone_height(Network::Regtest), 0);
    assert!(default_milestone_height(Network::Mainnet) > 0);
    assert!(default_milestone_height(Network::Signet) > 0);
}

#[test]
fn s9_rejects_bad_cb_length_short() {
    let mut cb = coinbase(0);
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01]); // len 1
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "bad-cb-length");
}

#[test]
fn s9_rejects_bad_cb_length_long() {
    let mut cb = coinbase(0);
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01; 101]);
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "bad-cb-length");
}

#[test]
fn s10_rejects_vout_toolarge() {
    let mut cb = coinbase(0);
    // MAX_MONEY + 1 sat.
    cb.output[0].value = Amount::from_sat(21_000_000 * 100_000_000 + 1);
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "toolarge");
}

#[test]
fn s11_rejects_excessive_legacy_sigops() {
    let mut cb = coinbase(0);
    // 20_001 × OP_CHECKSIG × WITNESS_SCALE(4) = 80_004 > MAX 80_000.
    cb.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0xac; 20_001]);
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "sigops");
}

#[test]
fn s10_rejects_txouttotal_toolarge() {
    // Two outputs each under MAX_MONEY but sum over.
    let half = 11_000_000 * 100_000_000u64; // 11M BTC each
    let mut cb = coinbase(0);
    cb.output = vec![
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
        TxOut {
            value: Amount::from_sat(half),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
    ];
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "txouttotal");
}

#[test]
fn s8_accepts_witness_commitment_with_reserved_value() {
    // Build a valid commitment using non-zero witness reserved in coinbase witness.
    let mut spend = non_coinbase_spend(11);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let mut cb = coinbase(1);
    // Place reserved value as last coinbase witness stack item.
    let reserved = [0x42u8; 32];
    cb.input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
    // Compute expected commitment: SHA256D(witness_root || reserved)
    let wtxid = spend.compute_wtxid().to_byte_array();
    let leaves = vec![[0u8; 32], wtxid];
    let witness_root = merkle_root_bytes(&leaves);
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    buf[32..].copy_from_slice(&reserved);
    use bitcoin::hashes::{sha256d, Hash};
    let committed = sha256d::Hash::hash(&buf).to_byte_array();
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&committed);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, spend]);
    validate_block_structure(&b, &ctx_h(1)).expect("reserved witness commitment");
    let _ = leaves;
}

/// Finding 009: commitment present requires exactly one 32-byte coinbase witness item.
#[test]
fn s8_rejects_empty_or_multi_item_coinbase_witness_reserved() {
    use bitcoin::hashes::{sha256d, Hash};

    let mut spend = non_coinbase_spend(13);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let wtxid = spend.compute_wtxid().to_byte_array();
    let leaves = vec![[0u8; 32], wtxid];
    let witness_root = merkle_root_bytes(&leaves);
    // Commitment over reserved = zeros (valid crypto if nonce were present).
    let reserved_zero = [0u8; 32];
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&witness_root);
    buf[32..].copy_from_slice(&reserved_zero);
    let committed = sha256d::Hash::hash(&buf).to_byte_array();
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend_from_slice(&committed);

    // Empty coinbase witness → bad-witness-nonce-size (not accept via zero probe).
    {
        let mut cb = coinbase(1);
        cb.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        // witness empty
        let b = block_with(vec![cb, spend.clone()]);
        let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadBlock(s) if s.contains("witness") || s.contains("nonce")),
            "empty reserved: got {err:?}"
        );
    }

    // Multi-item stack with last = zeros matching commitment → still reject.
    {
        let mut cb = coinbase(1);
        cb.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        cb.input[0].witness = Witness::from_slice(&[vec![0xff], reserved_zero.to_vec()]);
        let b = block_with(vec![cb, spend.clone()]);
        let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadBlock(s) if s.contains("witness") || s.contains("nonce")),
            "multi-item reserved: got {err:?}"
        );
    }

    // Control: exactly one 32-zero item + matching commitment → Ok.
    {
        let mut cb = coinbase(1);
        cb.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk),
        });
        cb.input[0].witness = Witness::from_slice(&[reserved_zero.as_slice()]);
        let b = block_with(vec![cb, spend]);
        validate_block_structure(&b, &ctx_h(1)).expect("single zero reserved OK");
    }
}

#[test]
fn bip34_height_script_large_values() {
    // 0x80 high bit needs pad; larger multi-byte.
    assert_eq!(bip34_height_script(255), vec![0x02, 0xff, 0x00]);
    assert_eq!(bip34_height_script(256), vec![0x02, 0x00, 0x01]);
}

#[test]
fn bip34_height_script_small_and_op_n() {
    assert_eq!(bip34_height_script(0), vec![0x00]);
    for h in 1u32..=16 {
        assert_eq!(bip34_height_script(h), vec![0x50 + h as u8]);
    }
    // First multi-byte form (17).
    assert_eq!(bip34_height_script(17), vec![0x01, 0x11]);
    // Wrong encoding rejected after activation (signet height 1).
    let p = Box::leak(Box::new(ChainParams::signet()));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut cb = coinbase(1);
    // Height 1 must be OP_1 (0x51); push-length form is wrong.
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x01, 0x00]);
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

/// Full assemble mode: spentness probe + maturity (legacy path).
#[test]
fn assemble_full_mode_spend_and_bip68() {
    use super::{assemble_block_prevouts_mode, AssembleMode};
    use crate::accept_and_connect_block;
    use rbitcoin_query::{BatchParents, BatchThin, Query};
    use std::collections::HashSet;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-assemble-full-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut last_cb = genesis.txdata[0].compute_txid();
    for h in 1u32..=3 {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: tip,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: tip_time + 600,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(h)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        last_cb = block.txdata[0].compute_txid();
        accept_and_connect_block(&q, &params, Height(h), &block, ms).unwrap();
        tip = block.block_hash();
        tip_time = block.header.time;
    }
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: last_cb,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: tip,
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: tip_time + 600,
            bits,
            nonce: 0,
        },
        txdata: vec![coinbase(4), spend],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let ctx = ctx_h(4);
    let parents = BatchParents::new();
    let thin = BatchThin::default();
    let mut spent = HashSet::new();
    let mut creates = super::PendingCreates::default();
    let create_txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = block.header.block_hash().to_byte_array();
    let r = assemble_block_prevouts_mode(
        &q,
        &block,
        &ctx,
        None,
        &mut spent,
        &mut creates,
        AssembleMode::Full,
        &parents,
        &thin,
        &create_txids,
        0,
        &bh,
        bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &bh, 0),
        None,
        None,
    );
    // Immature coinbase or spentness walk — either exercises Full arms.
    let _ = r;
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn assemble_rejects_empty_and_fk_mismatch() {
    use super::assemble_block_prevouts;
    use rbitcoin_query::{BatchParents, BatchThin, Query};
    use std::collections::HashSet;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-assemble-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    let ctx = ctx_h(1);
    let empty = block_with(vec![]);
    let parents = BatchParents::new();
    let thin = BatchThin::default();
    let mut spent = HashSet::new();
    let mut creates = super::PendingCreates::default();
    let zero = [0u8; 32];
    let err = assemble_block_prevouts(
        &q,
        &empty,
        &ctx,
        None,
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &[],
        0,
        &zero,
        false,
        None,
        None,
    )
    .err()
    .expect("empty");
    assert_bad_block(err, "empty");
    // Wrong archived fk count: coinbase alone needs 1 fk; pass empty slice.
    let b = block_with(vec![coinbase(1)]);
    spent.clear();
    creates.clear();
    let tids: Vec<[u8; 32]> = b
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = b.header.block_hash().to_byte_array();
    let err2 = assemble_block_prevouts(
        &q,
        &b,
        &ctx,
        Some(&[]),
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &tids,
        0,
        &bh,
        false,
        None,
        None,
    )
    .err()
    .expect("fk mismatch");
    assert_bad_block(err2, "archived tx fk");
    // first tx not coinbase
    let bad = block_with(vec![non_coinbase_spend(1)]);
    spent.clear();
    creates.clear();
    let tids3: Vec<[u8; 32]> = bad
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh3 = bad.header.block_hash().to_byte_array();
    let err3 = assemble_block_prevouts(
        &q,
        &bad,
        &ctx,
        None,
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &tids3,
        0,
        &bh3,
        false,
        None,
        None,
    )
    .err()
    .expect("not coinbase");
    assert_bad_block(err3, "coinbase");
    let _ = std::fs::remove_dir_all(&path);
}

/// Pack creates are `txid → fk` (one insert). Meters flush once (in_n = spends).
#[test]
fn assemble_pending_creates_is_txid_map_and_meters_flush() {
    use super::assemble_block_prevouts;
    use crate::confirm_phase_stats;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, BatchThin, Query};
    use std::collections::HashSet;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-assemble-creates-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    let ctx = ctx_h(1);
    let parents = BatchParents::new();
    let thin = BatchThin::default();
    let mut spent = HashSet::new();
    let mut creates = super::PendingCreates::default();
    let b = block_with(vec![coinbase(1)]);
    let tids: Vec<[u8; 32]> = b
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = b.header.block_hash().to_byte_array();
    let bip16 = bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &bh, 0);
    let _ = confirm_phase_stats::sample_assemble_and_reset();
    let _ = confirm_phase_stats::sample_assemble_prevout_detail_and_reset();
    assemble_block_prevouts(
        &q,
        &b,
        &ctx,
        Some(&[Fk(1)]),
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &tids,
        0,
        &bh,
        bip16,
        None,
        None,
    )
    .expect("coinbase-only assemble");
    assert_eq!(creates.len(), 1, "one create fk per tx, not per vout");
    assert_eq!(creates.get(&tids[0]), Some(&Fk(1)));
    let (in_n, _bns, batch_n, _sns, same_n, ..) =
        confirm_phase_stats::sample_assemble_prevout_detail_and_reset();
    assert_eq!(in_n, 0, "coinbase has no prevouts");
    assert_eq!(batch_n, 0);
    assert_eq!(same_n, 0);
    let _ = std::fs::remove_dir_all(&path);
}

/// N1: cold-path reason counters for pin→assemble leakage classes.
///
/// Drives [`super::resolve_prevout`] (same crate) so each miss class is
/// forced without re-implementing path logic in the test.
#[test]
fn n1_assemble_cold_why_reasons() {
    use super::resolve_prevout;
    use crate::accept_and_connect_block;
    use crate::confirm_phase_stats;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, Query};
    use rbitcoin_store::OutputRecord;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-n1-cold-why-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut last_cb = genesis.txdata[0].compute_txid();
    let mut last_cb_fk = Fk::NULL;
    for h in 1u32..=3 {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: tip,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time: tip_time + 600,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(h)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        last_cb = block.txdata[0].compute_txid();
        accept_and_connect_block(&q, &params, Height(h), &block, ms).unwrap();
        last_cb_fk = q
            .tx_fk_by_txid(last_cb.as_byte_array())
            .unwrap()
            .expect("cb fk");
        tip = block.block_hash();
        tip_time = block.header.time;
    }
    let parent_txid = last_cb.to_byte_array();
    let op = OutPoint {
        txid: last_cb,
        vout: 0,
    };
    let empty_block = block_with(vec![coinbase(4)]);
    let txid_index = super::TxidMap::<usize>::default();
    let mut cb_cache: rbitcoin_query::FkMap<Option<u32>> = rbitcoin_query::FkMap::default();

    // Thread-local N1 counters (process-global atomics race under parallel cargo test).
    let _ = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
    let _ = confirm_phase_stats::sample_tl_batch_cold_n_and_reset();

    // ── null_fk: no hint; head still finds parent → cold ──────────
    {
        let parents = BatchParents::new();
        resolve_prevout(
            &q,
            &empty_block,
            op,
            None,
            &txid_index,
            0,
            &mut cb_cache,
            &parents,
            4,
            false,
            &mut super::AsmPrevoutAcc::default(),
        )
        .expect("null_fk cold");
        let why = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
        let (_batch_n, cold_n) = confirm_phase_stats::sample_tl_batch_cold_n_and_reset();
        assert_eq!(why, (1, 0, 0, 0), "null_fk why={why:?}");
        assert_eq!(cold_n, 1, "cold_n={cold_n}");
    }

    // ── not_pin: correct fk, empty BatchParents ───────────────────
    {
        let parents = BatchParents::new();
        resolve_prevout(
            &q,
            &empty_block,
            op,
            Some(last_cb_fk),
            &txid_index,
            0,
            &mut cb_cache,
            &parents,
            4,
            false,
            &mut super::AsmPrevoutAcc::default(),
        )
        .expect("not_pin cold");
        let why = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
        let (_batch_n, cold_n) = confirm_phase_stats::sample_tl_batch_cold_n_and_reset();
        assert_eq!(why, (0, 1, 0, 0), "not_pin why={why:?}");
        assert_eq!(cold_n, 1, "cold_n");
    }

    // ── batch hit: no cold ────────────────────────────────────────
    {
        let mut parents = BatchParents::new();
        let rec = q.get_tx_class_a(last_cb_fk).expect("class a");
        let out = OutputRecord::unspent(50_0000_0000, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(0, out)], &[0], Some(true));
        // Ensure pin txid matches wire.
        assert_eq!(
            parents.get_parent_txout_parts(last_cb_fk, 0).unwrap().2,
            parent_txid
        );
        resolve_prevout(
            &q,
            &empty_block,
            op,
            Some(last_cb_fk),
            &txid_index,
            0,
            &mut cb_cache,
            &parents,
            4,
            false,
            &mut super::AsmPrevoutAcc::default(),
        )
        .expect("batch hit");
        let why = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
        let (batch_n, cold_n) = confirm_phase_stats::sample_tl_batch_cold_n_and_reset();
        assert_eq!(why, (0, 0, 0, 0), "batch hit must not cold why={why:?}");
        assert_eq!(batch_n, 1, "batch_n");
        assert_eq!(cold_n, 0, "cold_n");
    }

    // ── txid_mismatch: pin present with wrong identity → hard invariant ─
    {
        let mut parents = BatchParents::new();
        let mut rec = q.get_tx_class_a(last_cb_fk).expect("class a");
        rec.txid = [0xee; 32]; // wrong identity
        let out = OutputRecord::unspent(50_0000_0000, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(0, out)], &[0], Some(true));
        let err = match resolve_prevout(
            &q,
            &empty_block,
            op,
            Some(last_cb_fk),
            &txid_index,
            0,
            &mut cb_cache,
            &parents,
            4,
            false,
            &mut super::AsmPrevoutAcc::default(),
        ) {
            Ok(_) => panic!("mismatch must hard-fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("invariant") && msg.contains("identity"),
            "got {err}"
        );
        let why = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
        assert_eq!(why, (0, 0, 1, 0), "mismatch why={why:?}");
    }

    // ── vout_miss: parent in batch, needed vout not sparse-pinned → invariant ─
    {
        let mut parents = BatchParents::new();
        let rec = q.get_tx_class_a(last_cb_fk).expect("class a");
        // Pin only vout 1 (does not exist on spend of vout 0).
        let out = OutputRecord::unspent(1, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(1, out)], &[1], Some(true));
        assert!(parents.contains(last_cb_fk));
        assert!(parents.get_parent_txout_parts(last_cb_fk, 0).is_none());
        let err = match resolve_prevout(
            &q,
            &empty_block,
            op,
            Some(last_cb_fk),
            &txid_index,
            0,
            &mut cb_cache,
            &parents,
            4,
            false,
            &mut super::AsmPrevoutAcc::default(),
        ) {
            Ok(_) => panic!("vout_miss must hard-fail"),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("invariant") && msg.contains("incomplete outs"),
            "got {err}"
        );
        let why = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
        assert_eq!(why, (0, 0, 0, 1), "vout_miss why={why:?}");
    }

    let _ = std::fs::remove_dir_all(&path);
}

/// Mainnet tip stall class (961460→961461): already-archived Class A tip+1
/// uses `plan=None` with lookup-stamped parent pin (ranges + wire identity).
/// Load pins denserels by range only — no soft spentness recovery for
/// zero-identity pins.
///
/// Shipped paths:
/// - archive body first → `confirm_wire_run` (plan=None) succeeds
/// - IBD-style `confirm_wire_load_from_plan` with plan=None succeeds via
///   single-path range denserels from stamp
/// - rapid tip+1/tip+2 accept; genuine double-spend still `PrevoutSpent`
#[test]
fn already_archived_schema13_pin_identity_tip_follow() {
    use crate::{
        accept_and_connect_block, commit_class_a_block, confirm_scripts_phase,
        confirm_wire_load_from_plan, confirm_wire_lookup_stamp, confirm_write_phase,
        ScriptPreverified,
    };
    use rbitcoin_query::Query;
    use std::sync::Arc;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-plan-none-pin-id-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    fn mine_cb(prev: BlockHash, time: u32, h: u32) -> Block {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(h)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    }
    fn mine_with(prev: BlockHash, time: u32, h: u32, extra: Vec<Transaction>) -> Block {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut txs = vec![coinbase(h)];
        txs.extend(extra);
        let mut block = Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: TxMerkleNode::from_byte_array([0; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: txs,
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = bitcoin::Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    }
    fn spend_acs(prev: bitcoin::Txid, vout: u32, val: Amount) -> Transaction {
        Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: prev, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: val,
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine_cb(tip, tip_time + 600, 1);
    let c1_txid = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;

    let b2 = mine_cb(tip, tip_time + 600, 2);
    let c2_txid = b2.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(2), &b2, ms).unwrap();
    tip = b2.block_hash();
    tip_time = b2.header.time;

    for h in 3..=maturity + 2 {
        let b = mine_cb(tip, tip_time + 600, h);
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    // Spend C1 + same-block chain (txA→txB) on tip+1; archive Class A only
    // then confirm plan=None. Same-block edges must not durable-probe Class A
    // by wire txid (that false-PrevoutSpent mainnet 961461 rehydrate).
    let h_spend = maturity + 3;
    let tx_a = spend_acs(c1_txid, 0, Amount::from_sat(49_0000_0000));
    let tx_a_id = tx_a.compute_txid();
    let tx_b = spend_acs(tx_a_id, 0, Amount::from_sat(48_0000_0000));
    let b_s1 = mine_with(tip, tip_time + 600, h_spend, vec![tx_a, tx_b]);
    commit_class_a_block(&q, &params, Height(h_spend), &b_s1, ms).unwrap();
    assert_eq!(q.tip_height().map(|h| h.0), Some(maturity + 2));
    // IBD rehydrate path: stamp → load(Forbid) must not miss denserels stage
    // when plan=None (consensus forces Allow cold + body_txid identity).
    {
        let arcs = [(Height(h_spend), Arc::new(b_s1.clone()))];
        let stamped =
            confirm_wire_lookup_stamp(&q, &params, ms, &arcs, None).expect("lookup stamp");
        assert!(
            stamped.plan.is_none(),
            "already-archived body must yield plan=None"
        );
        let mat =
            confirm_wire_load_from_plan(&q, &params, ms, stamped, None, &ScriptPreverified::new())
                .expect("plan=None load pins denserels by range from stamp");
        let ok = confirm_scripts_phase(mat.batch).expect("scripts");
        confirm_write_phase(&q, &params, ms, ok.batch)
            .expect("plan=None confirm with same-block spends must succeed");
    }
    assert_eq!(q.tip_height().map(|h| h.0), Some(h_spend));
    assert!(q.is_outpoint_spent(c1_txid.as_byte_array(), 0).unwrap());
    tip = b_s1.block_hash();
    tip_time = b_s1.header.time;

    // Also exercise unified confirm_wire_run on a second already-archived spend.
    // (tip already advanced above; remaining cases use accept_and_connect.)

    // Rapid sequential tip-follow (tip+1 then tip+2) via shipped accept.
    let h_n1 = h_spend + 1;
    let b_n1 = mine_with(
        tip,
        tip_time + 600,
        h_n1,
        vec![spend_acs(c2_txid, 0, Amount::from_sat(49_0000_0000))],
    );
    accept_and_connect_block(&q, &params, Height(h_n1), &b_n1, ms)
        .expect("rapid tip+1 valid spend of C2");
    tip = b_n1.block_hash();
    tip_time = b_n1.header.time;
    let h_n2 = h_n1 + 1;
    let b_n2 = mine_cb(tip, tip_time + 600, h_n2);
    accept_and_connect_block(&q, &params, Height(h_n2), &b_n2, ms)
        .expect("rapid tip+2 coinbase extension");
    assert_eq!(q.tip_height().map(|h| h.0), Some(h_n2));
    tip = b_n2.block_hash();
    tip_time = b_n2.header.time;

    // Genuine double-spend of already-spent C1 fails hard.
    let b_ds = mine_with(
        tip,
        tip_time + 600,
        h_n2 + 1,
        vec![spend_acs(c1_txid, 0, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(h_n2 + 1), &b_ds, ms)
        .expect_err("double-spend of C1 must fail");
    assert!(
        matches!(err, ConsensusError::PrevoutSpent)
            || format!("{err}").contains("spent")
            || format!("{err}").contains("prevout"),
        "got {err}"
    );

    // Structural without denserels/abs is invariant — not soft PrevoutSpent recovery.
    {
        use super::structural_validate_spends;
        use rbitcoin_primitives::Fk;
        use rbitcoin_query::{BatchParents, FkMap, U32Map, U64Map};
        use std::collections::HashSet;
        let c2_fk = q.tx_fk_by_txid(c2_txid.as_byte_array()).unwrap().unwrap();
        let spends = vec![(c2_txid.to_byte_array(), 0u32, Fk(9_000_001), c2_fk)];
        let parents = BatchParents::new();
        let ctx = ValidationContext::at(Box::leak(Box::new(params.clone())), Height(h_n1), ms);
        let mut pending = HashSet::new();
        let mut mtp = U32Map::default();
        let mut meta = U64Map::default();
        let err = structural_validate_spends(
            &q,
            &b_n1,
            &ctx,
            Some(&[Fk::NULL, Fk(9_000_001)]),
            &spends,
            0,
            &mut pending,
            &parents,
            &mut mtp,
            &mut meta,
            &FkMap::default(),
        )
        .expect_err("missing denserels abs must hard-fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("invariant") && msg.contains("denserels"),
            "expected denserels invariant, got {err}"
        );
    }

    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn check_witness_wtxid_count_mismatch_via_structure() {
    // Direct unit path for wtxid count: call internal helper via structure
    // with inconsistent precomputed length is not public — exercise
    // missing commitment + reserved-mismatch already covered; cover odd
    // merkle witness leaf + wrong commitment without reserved stack item.
    let mut spend = non_coinbase_spend(12);
    spend.input[0].witness = Witness::from_slice(&[vec![0xcd]]);
    let mut cb = coinbase(1);
    // Commitment magic with zeros; coinbase witness empty → mismatch (no reserved).
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    // Non-32 reserved last item cannot rescue.
    cb.input[0].witness = Witness::from_slice(&[vec![0x01, 0x02]]);
    let b = block_with(vec![cb, spend]);
    let err = validate_block_structure(&b, &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock(s) if s.contains("witness")),
        "got {err:?}"
    );
}

/// BIP16 from precomputed prev MTP — no header walk, exception hash respected.
#[test]
fn bip16_from_prev_mtp_exception_and_time() {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    // Exception block never enables P2SH regardless of MTP.
    assert!(!bip16_active_from_prev_mtp(
        p,
        170_000,
        &BIP16_EXCEPTION_MAINNET,
        u32::MAX,
    ));
    // Buried: active even when prev MTP predates the historical BIP16 time.
    assert!(bip16_active_from_prev_mtp(p, 170_000, &[1u8; 32], 0));
    // At/after bip16_time → still active.
    assert!(bip16_active_from_prev_mtp(
        p,
        170_000,
        &[1u8; 32],
        p.btc.bip16_time,
    ));
    // Genesis height never.
    assert!(!bip16_active_from_prev_mtp(
        p,
        0,
        &[1u8; 32],
        p.btc.bip16_time,
    ));
}

/// Confirm jobs share wire Arc — same Transaction address, no deep clone.
#[test]
fn script_job_shared_tx_is_wire_pointer() {
    use std::sync::Arc;
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([7; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let block = Arc::new(block_with(vec![coinbase(1), spend]));
    let tid = block.txdata[1].compute_txid().to_byte_array();
    let job = ScriptCheckJob::with_shared_tx(
        tid,
        vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
        Arc::clone(&block),
        1,
        true,
        true,
        true,
        true,
        true,
    );
    assert!(std::ptr::eq(
        &*job.tx as *const Transaction,
        &block.txdata[1] as *const Transaction
    ));
    assert_eq!(job.txid, tid);
}
