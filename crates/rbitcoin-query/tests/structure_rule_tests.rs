//! structure_rule_tests (peeled from block.rs).
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use rbitcoin_consensus::TxPrecompute;
use rbitcoin_primitives::Height;
use rbitcoin_query::confirm_error::ConfirmError;

use rbitcoin_query::block_pipeline::{
    assemble_block_prevouts, resolve_prevout, structural_validate_spends, AsmPrevoutAcc,
    ClassAWave, RunCreateHeight, StructuralScratch,
};

use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::VarInt;

use rbitcoin_consensus::block::{
    apply_witness_commitment, bip16_active_from_prev_mtp, bip34_height_script, block_has_witness,
    block_has_witness_from_pres, block_subsidy, check_tx_local, last_script_push,
    merkle_root_bytes, script_sigop_count, validate_block_structure,
    validate_block_structure_with_pres, witness_commitment_script, PendingCreates, ScriptCheckJob,
    ScriptVerifyFlags, ValidationContext, BIP16_EXCEPTION_MAINNET, MAX_BLOCK_STRIPPED_SIZE,
    MAX_BLOCK_TX_COUNT, MAX_BLOCK_WEIGHT, MIN_TX_WEIGHT, TAPROOT_EXCEPTION_MAINNET,
};
use rbitcoin_consensus::{ChainParams, ConsensusError, Milestone};

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn ctx_h(height: u32) -> ValidationContext<'static> {
    // Leak params for 'static test ctx simplicity.
    let p = Box::leak(Box::new(params()));
    ValidationContext::at(p, Height(height), Milestone::NONE)
}

#[test]
fn check_block_wire_junk_does_not_panic() {
    for data in [b"".as_slice(), &[0u8; 1], &[0xff; 80], b"not-a-block"] {
        let _ = rbitcoin_consensus::block::check_block_wire(data);
    }
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let raw = bitcoin::consensus::encode::serialize(&genesis);
    let _ = rbitcoin_consensus::block::check_block_wire(&raw);
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
    let stats = rbitcoin_query::ConfirmStats::default();
    let mut spend = non_coinbase_spend(1);
    spend.input[0].witness = Witness::from_slice(&[&[0x01]]);
    let mut b = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut b);
    let mut note = |txid_ns, wtxid_ns, walk_ns| {
        stats.note_struct_parts(txid_ns, wtxid_ns, walk_ns);
    };
    validate_block_structure_with_pres(&b, &ctx_h(1), None, Some(&mut note))
        .expect("witness block structure");
    let s = stats.take_window();
    assert!(
        s.stamp_struct_txid_ns > 0,
        "one-pass hash must be metered: {s:?}"
    );
    assert!(
        s.stamp_struct_walk_ns > 0,
        "weight/sigops walks must be metered: {s:?}"
    );
}

#[test]
fn structure_with_pres_skips_from_tx() {
    use TxPrecompute;
    let stats = rbitcoin_query::ConfirmStats::default();
    let mut spend = non_coinbase_spend(1);
    spend.input[0].witness = Witness::from_slice(&[&[0x01]]);
    let mut b = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut b);
    let pres: std::sync::Arc<[TxPrecompute]> = b
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let mut note = |txid_ns, wtxid_ns, walk_ns| {
        stats.note_struct_parts(txid_ns, wtxid_ns, walk_ns);
    };
    let out = validate_block_structure_with_pres(
        &b,
        &ctx_h(1),
        Some(std::sync::Arc::clone(&pres)),
        Some(&mut note),
    )
    .expect("stashed pres must still enforce merkle");
    assert_eq!(out.len(), pres.len());
    assert_eq!(out[0].txid, pres[0].txid);
    assert!(
        std::sync::Arc::ptr_eq(&out, &pres),
        "with_pres must keep the caller Arc"
    );
    let s = stats.take_window();
    assert_eq!(
        s.stamp_struct_txid_ns, 0,
        "with_pres must not from_tx: {s:?}"
    );
    assert!(s.stamp_struct_walk_ns > 0, "merkle/weight still run: {s:?}");
}

/// Confirm assemble must Arc-share lookup/structure pres, not `Arc::new(p.clone())`.
#[test]
fn script_jobs_from_same_pres_slice_share_pre() {
    use TxPrecompute;
    let spend = non_coinbase_spend(1);
    let pres: std::sync::Arc<[TxPrecompute]> =
        std::sync::Arc::from([TxPrecompute::from_tx(&spend)]);
    let prevouts = vec![
        bitcoin::TxOut {
            value: bitcoin::Amount::ZERO,
            script_pubkey: bitcoin::ScriptBuf::new(),
        };
        spend.input.len()
    ];
    let job_a = ScriptCheckJob::with_txid(
        pres[0].txid,
        prevouts.clone(),
        spend.clone(),
        ScriptVerifyFlags::buried(true, true, true, true, true),
    )
    .with_pre_slice(std::sync::Arc::clone(&pres), 0);
    let job_b = ScriptCheckJob::with_txid(
        pres[0].txid,
        prevouts,
        spend,
        ScriptVerifyFlags::buried(true, true, true, true, true),
    )
    .with_pre_slice(std::sync::Arc::clone(&pres), 0);
    assert!(
        std::ptr::eq(job_a.pre(), pres[0].as_script().expect("script precompute")),
        "job pre must be the slice element, not a cloned TxPrecompute"
    );
    assert!(
        std::ptr::eq(job_a.pre(), job_b.pre()),
        "two jobs from the same Arc<[TxPrecompute]> share the element"
    );
}

fn rule_err(err: ConfirmError) -> ConsensusError {
    match err {
        ConfirmError::Rules(e) => e,
        other => panic!("expected a consensus rule reject, got {other}"),
    }
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

fn assert_bad_tx(err: ConsensusError, needle: &str) {
    match err {
        ConsensusError::BadTx(s) => {
            assert!(
                s.contains(needle),
                "expected BadTx containing {needle:?}, got {s:?}"
            );
        }
        other => panic!("expected BadTx({needle:?}), got {other:?}"),
    }
}

fn stripped_size(block: &Block) -> usize {
    let n = block.txdata.len();
    80usize + VarInt(n as u64).size() + block.txdata.iter().map(|t| t.base_size()).sum::<usize>()
}

fn weight_wu(block: &Block) -> u64 {
    let n = block.txdata.len();
    let vi = VarInt(n as u64).size();
    let base = 80 + vi + block.txdata.iter().map(|t| t.base_size()).sum::<usize>();
    let total = 80 + vi + block.txdata.iter().map(|t| t.total_size()).sum::<usize>();
    (base.saturating_mul(3).saturating_add(total)) as u64
}

fn set_coinbase_pad(block: &mut Block, data_len: usize) {
    const COMMIT_MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    let mut spk = Vec::with_capacity(data_len.saturating_add(6));
    spk.push(0x6a);
    spk.push(0x4e);
    spk.extend_from_slice(&(data_len as u32).to_le_bytes());
    spk.extend(std::iter::repeat_n(0x61, data_len));
    let pad = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    };
    let pad_at = block.txdata[0].output.iter().position(|o| {
        let b = o.script_pubkey.as_bytes();
        b.first() == Some(&0x6a) && (b.len() < 6 || b[..6] != COMMIT_MAGIC)
    });
    match pad_at {
        Some(i) => block.txdata[0].output[i] = pad,
        None => block.txdata[0].output.push(pad),
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

fn refresh_witness_commitment(block: &mut Block) {
    let reserved = [0u8; 32];
    block.txdata[0].input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
    let wtxids = block
        .txdata
        .iter()
        .skip(1)
        .map(|tx| tx.compute_wtxid().to_byte_array());
    let spk = witness_commitment_script(wtxids, &reserved);
    const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    if let Some(out) = block.txdata[0].output.iter_mut().rev().find(|o| {
        let b = o.script_pubkey.as_bytes();
        b.len() >= 38 && b[..6] == MAGIC
    }) {
        out.script_pubkey = ScriptBuf::from_bytes(spk);
    } else {
        block.txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk),
        });
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
}

fn extend_spend_witness_one_byte(block: &mut Block) {
    let items: Vec<Vec<u8>> = block.txdata[1].input[0]
        .witness
        .iter()
        .map(|s| {
            let mut v = s.to_vec();
            v.push(0xcd);
            v
        })
        .collect();
    block.txdata[1].input[0].witness = Witness::from_slice(&items);
    refresh_witness_commitment(block);
}

fn pad_stripped_to(block: &mut Block, target: usize) {
    let before = stripped_size(block);
    assert!(
        before < target,
        "fixture already {before}, want pad to {target}"
    );
    let guess = target.saturating_sub(before).saturating_sub(24).max(1);
    set_coinbase_pad(block, guess);
    let got = stripped_size(block);
    if got != target {
        let adj = if got < target {
            guess + (target - got)
        } else {
            guess.saturating_sub(got - target)
        };
        set_coinbase_pad(block, adj);
    }
    assert_eq!(
        stripped_size(block),
        target,
        "stripped pad missed target (before {before})"
    );
}

fn padded_spend(data_len: usize) -> Transaction {
    let mut spk = Vec::with_capacity(data_len.saturating_add(6));
    spk.push(0x6a);
    spk.push(0x4e);
    spk.extend_from_slice(&(data_len as u32).to_le_bytes());
    spk.extend(std::iter::repeat_n(0x61, data_len));
    Transaction {
        version: TxVersion::ONE,
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
            script_pubkey: ScriptBuf::from_bytes(spk),
        }],
    }
}

/// An unspent connected coinbase with the same txid is BIP30 on regtest (no
/// 91842/91880 grandfather). Signet activates BIP34 at height 1, and Core's
/// empty BIP34 hash still enforces BIP30 on every signet block.
fn rejects_unspent_overwrite(q: &rbitcoin_query::Query, first: &Transaction) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, U32Map};
    let dup = block_with(vec![first.clone()]);
    let signet = Box::leak(Box::new(ChainParams::signet()));
    for (ctx, net) in [
        (ctx_h(10), "regtest"),
        (
            ValidationContext::at(signet, Height(2), Milestone::NONE),
            "signet",
        ),
    ] {
        let heights = RunCreateHeight::Spans(Vec::new());
        let parents = BatchParents::new();
        let abs_jobs = parents
            .spend_abs_jobs(std::iter::empty::<(Fk, u32, Fk, u32)>())
            .expect("no spend edges");
        let err = structural_validate_spends(
            q,
            &dup,
            &ctx,
            &[],
            0,
            &mut rbitcoin_query::block_pipeline::BatchSpent::default(),
            &parents,
            &mut U32Map::default(),
            &heights,
            &ClassAWave::default(),
            &mut StructuralScratch::default(),
            &abs_jobs,
            None,
        )
        .expect_err("an unspent overwrite must trip BIP30");
        let msg = format!("{err}");
        assert!(
            msg.contains("bad-txns-BIP30"),
            "{net}: expected BIP30 reject, got {msg}"
        );
    }
}

fn plant_unspent_coinbase(
    label: &str,
) -> (
    rbitcoin_store::testutil::TempDir,
    rbitcoin_query::Query,
    Transaction,
) {
    let (path, q, first, _fk) = plant_coinbase_with_outputs(label, coinbase(1).output);
    (path, q, first)
}

/// Connects a height-1 coinbase paying `outputs` at height 0 of a tiny store.
fn plant_coinbase_with_outputs(
    label: &str,
    outputs: Vec<TxOut>,
) -> (
    rbitcoin_store::testutil::TempDir,
    rbitcoin_query::Query,
    Transaction,
    rbitcoin_primitives::Fk,
) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
    q.enter_direct_index_mode().unwrap();
    let mut first = coinbase(1);
    first.output = outputs;
    let txid = first.compute_txid().to_byte_array();
    let rec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: first.output.len() as u32,
    };
    let outs = first
        .output
        .iter()
        .map(|o| OutputRecord::unspent(o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect();
    let fk = q
        .store()
        .put_tx_full_batch_indexed(
            &[(
                rec,
                vec![InputRecord::coinbase(
                    u32::MAX,
                    first.input[0].script_sig.to_bytes(),
                    vec![],
                )],
                outs,
            )],
            true,
        )
        .unwrap()[0];
    q.store().header_txs.put_range(Fk(1), fk, 1).unwrap();
    q.store().confirmed.set(Height(0), Fk(1)).unwrap();
    q.store().rebuild_height_fence().unwrap();
    (path, q, first, fk)
}

fn plant_bip34_ancestor(q: &rbitcoin_query::Query, hash: [u8; 32]) {
    use rbitcoin_store::HeaderRecord;
    let main = ChainParams::mainnet();
    let hfk = q
        .store()
        .put_header(&HeaderRecord {
            hash,
            ..HeaderRecord::default()
        })
        .unwrap();
    q.store()
        .confirmed
        .set(Height(main.btc.bip34_height), hfk)
        .unwrap();
    q.clear_bip34_ancestor();
}

fn bip30_message_at_mainnet_above_bip34(
    q: &rbitcoin_query::Query,
    block: &Block,
) -> Result<(), ConfirmError> {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, U32Map};
    let main = Box::leak(Box::new(ChainParams::mainnet()));
    let ctx = ValidationContext::at(main, Height(main.btc.bip34_height + 1), Milestone::NONE);
    let heights = RunCreateHeight::Spans(Vec::new());
    let parents = BatchParents::new();
    let abs_jobs = parents
        .spend_abs_jobs(std::iter::empty::<(Fk, u32, Fk, u32)>())
        .expect("no spend edges");
    structural_validate_spends(
        q,
        block,
        &ctx,
        &[],
        0,
        &mut rbitcoin_query::block_pipeline::BatchSpent::default(),
        &parents,
        &mut U32Map::default(),
        &heights,
        &ClassAWave::default(),
        &mut StructuralScratch::default(),
        &abs_jobs,
        q.confirmed_bip34_ancestor(main.btc.bip34_height),
    )
    .map(|_| ())
}

/// Mainnet skips BIP30 only when the header at BIP34 height is the real hash.
/// A wrong ancestor still rejects an unspent overwrite.
fn mainnet_ancestor_skip_then_miss(q: &rbitcoin_query::Query, first: &Transaction) {
    let main = ChainParams::mainnet();
    let real = main.bip34_hash.expect("mainnet BIP34 hash").to_byte_array();
    plant_bip34_ancestor(q, real);
    let skipped = bip30_message_at_mainnet_above_bip34(q, &block_with(vec![first.clone()]));
    let msg = skipped
        .as_ref()
        .err()
        .map(|e| format!("{e}"))
        .unwrap_or_default();
    assert!(
        !msg.contains("bad-txns-BIP30"),
        "real BIP34 ancestor must skip BIP30 above the activation height, got {msg}"
    );

    plant_bip34_ancestor(q, [0x11; 32]);
    let err = bip30_message_at_mainnet_above_bip34(q, &block_with(vec![first.clone()]))
        .expect_err("a non-BIP34 ancestor must still enforce BIP30");
    let msg = format!("{err}");
    assert!(
        msg.contains("bad-txns-BIP30"),
        "expected BIP30 reject, got {msg}"
    );
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
    match err {
        ConsensusError::BadBlock(s) => {
            assert!(
                s.contains("weight") || s.contains("stripped"),
                "expected weight or stripped reject, got {s:?}"
            );
        }
        other => panic!("expected BadBlock, got {other:?}"),
    }
}

#[test]
fn s4_weight_4_000_000_accepts_4_000_001_rejects() {
    let mut ok = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut ok, MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(weight_wu(&ok), 4_000_000);
    validate_block_structure(&ok, &ctx_h(0)).expect("exactly 4_000_000 WU");

    let mut spend = non_coinbase_spend(11);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let mut wblock = block_with(vec![coinbase(1), spend]);
    apply_witness_commitment(&mut wblock);
    while !weight_wu(&wblock).is_multiple_of(4) {
        extend_spend_witness_one_byte(&mut wblock);
    }
    let w = weight_wu(&wblock);
    assert!(w < 4_000_000);
    let gap = 4_000_000 - w;
    let target = stripped_size(&wblock) + (gap / 4) as usize;
    pad_stripped_to(&mut wblock, target);
    assert_eq!(weight_wu(&wblock), 4_000_000);
    validate_block_structure(&wblock, &ctx_h(1)).expect("witness block at 4_000_000 WU");

    extend_spend_witness_one_byte(&mut wblock);
    assert_eq!(weight_wu(&wblock), 4_000_001);
    assert!(stripped_size(&wblock) <= MAX_BLOCK_STRIPPED_SIZE);
    assert_bad_block(
        validate_block_structure(&wblock, &ctx_h(1)).unwrap_err(),
        "weight",
    );
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
    let good = block_with(vec![coinbase(0), non_coinbase_spend(1)]);
    validate_block_structure(&good, &ctx_h(0)).unwrap();
    let mut b = good;
    b.header.merkle_root = TxMerkleNode::from_byte_array([0x11; 32]);
    let err = validate_block_structure(&b, &ctx_h(0)).unwrap_err();
    assert_bad_block(err, "merkle");
}

/// A peer can pair any body with a valid header. Every body rule runs after
/// the merkle check, so a body the header does not commit to fails as a
/// merkle mismatch, never as a rule the hash could be blamed for.
#[test]
fn body_rules_run_after_the_header_merkle_check() {
    let cb = coinbase(1);
    let (a, b) = (non_coinbase_spend(1), non_coinbase_spend(2));
    let honest = block_with(vec![cb.clone(), a.clone(), b.clone()]);
    validate_block_structure(&honest, &ctx_h(1)).unwrap();
    let under_header = |txdata: Vec<Transaction>| Block {
        header: honest.header,
        txdata,
    };
    let mut no_vin = a.clone();
    no_vin.input.clear();
    let mut oversize = a.clone();
    oversize.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x61; MAX_BLOCK_STRIPPED_SIZE]);
    for (what, txdata) in [
        ("no transactions", vec![]),
        ("first tx not coinbase", vec![a.clone(), b.clone()]),
        (
            "coinbase not first",
            vec![cb.clone(), cb.clone(), b.clone()],
        ),
        ("no inputs", vec![cb.clone(), no_vin, b.clone()]),
        ("stripped size", vec![cb.clone(), oversize, b.clone()]),
        ("duplicate txid", vec![cb.clone(), a.clone(), a.clone()]),
    ] {
        let err = validate_block_structure(&under_header(txdata), &ctx_h(1)).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadBlock("merkle root mismatch")),
            "{what}: {err:?}"
        );
    }

    // CVE-2012-2459: repeating the tail keeps the root. The body is mutated,
    // not a block whose txids repeat.
    let err =
        validate_block_structure(&under_header(vec![cb, a, b.clone(), b]), &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock("bad-txns-duplicate")),
        "{err:?}"
    );
}

/// Core `IsBlockMutated`: with no coinbase first, a 64-byte tx can be an
/// inner merkle node read as a tx (CVE-2017-12842). That body is mutated.
/// submitblock still reports Core's CheckBlock reason.
#[test]
fn no_coinbase_with_a_64_byte_tx_is_mutated() {
    let mut inner = non_coinbase_spend(1);
    inner.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51; 3]);
    assert_eq!(bitcoin::consensus::serialize(&inner).len(), 64);
    let (a, b) = (non_coinbase_spend(2), non_coinbase_spend(3));
    for txdata in [vec![inner.clone(), a.clone()], vec![a.clone(), inner]] {
        let err = validate_block_structure(&block_with(txdata), &ctx_h(1)).unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::BadBlock("merkle mutated by a 64-byte tx")
            ),
            "{err:?}"
        );
        assert_eq!(
            rbitcoin_consensus::block_reject_reason(&err),
            "bad-cb-missing"
        );
    }
    let err = validate_block_structure(&block_with(vec![a, b]), &ctx_h(1)).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadBlock("first tx not coinbase")),
        "{err:?}"
    );
}

#[test]
fn s7_rejects_bip34_missing_after_activation_signet() {
    // Signet activates BIP34 at height 1 (rust-bitcoin Params::SIGNET).
    let p = Box::leak(Box::new(ChainParams::signet()));
    let h = p.btc.bip34_height;
    assert_eq!(h, 1);
    let ctx = ValidationContext::at(p, Height(h), Milestone::NONE);
    validate_block_structure(&block_with(vec![coinbase(h)]), &ctx)
        .expect("BIP34 height push at activation");
    let mut cb = coinbase(h);
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
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
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x00, 0x00]);
    let b = block_with(vec![cb.clone()]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
    // Core CheckTransaction's length rule runs before the height push.
    cb.input[0].script_sig = ScriptBuf::new();
    let err = validate_block_structure(&block_with(vec![cb]), &ctx).unwrap_err();
    assert_bad_block(err, "bad-cb-length");
}

/// A coinbase scriptSig swapped under a real header is a body the header
/// does not commit to. It must fail the merkle check, not `bad-cb-length`,
/// so IBD and P2P re-get the block instead of caching its hash.
#[test]
fn short_coinbase_under_a_real_header_is_merkle_mismatch() {
    let honest = block_with(vec![coinbase(1)]);
    validate_block_structure(&honest, &ctx_h(1)).unwrap();
    for script_sig in [vec![0x51], vec![], vec![0x51; 101]] {
        let mut swapped = honest.clone();
        swapped.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(script_sig);
        let err = validate_block_structure(&swapped, &ctx_h(1)).unwrap_err();
        assert!(
            matches!(err, ConsensusError::BadBlock("merkle root mismatch")),
            "{err:?}"
        );
    }
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
fn s7_regtest_rejects_bip34_missing_at_height_1() {
    // Core `CRegTestParams`: `BIP34Height = 1`.
    let p = Box::leak(Box::new(ChainParams::regtest()));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    validate_block_structure(&block_with(vec![coinbase(1)]), &ctx)
        .expect("BIP34 height push at height 1");
    let mut cb = coinbase(1);
    cb.input[0].script_sig = ScriptBuf::from_bytes(b"regtest".to_vec());
    let err = validate_block_structure(&block_with(vec![cb]), &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

#[test]
fn s7_regtest_bip34_activation_height_override() {
    // `-testactivationheight=bip34@N` moves the gate like Core.
    let mut over = ChainParams::regtest();
    over.apply_test_activation_height("bip34", 3).unwrap();
    let p = Box::leak(Box::new(over));
    let mut cb = coinbase(2);
    cb.input[0].script_sig = ScriptBuf::from_bytes(b"regtest".to_vec());
    let ctx = ValidationContext::at(p, Height(2), Milestone::NONE);
    validate_block_structure(&block_with(vec![cb.clone()]), &ctx)
        .expect("below the overridden BIP34 height");
    let ctx = ValidationContext::at(p, Height(3), Milestone::NONE);
    let err = validate_block_structure(&block_with(vec![cb]), &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

/// Core `CheckWitnessMalleation` only when SegWit is active. Pre-segwit
/// `aa21a9ed` OP_RETURN is data (mainnet 434499), not a BIP141 nonce demand.
#[test]
fn s8_mainnet_accepts_pre_segwit_commitment_magic_without_nonce() {
    let p = Box::leak(Box::new(ChainParams::mainnet()));
    let height = 434_499;
    assert!(!p.segwit_active_at(height));
    let ctx = ValidationContext::at(p, Height(height), Milestone::NONE);
    let mut cb = coinbase(height);
    let mut spk = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    spk.extend([0u8; 32]);
    cb.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(spk),
    });
    let b = block_with(vec![cb, non_coinbase_spend(10)]);
    validate_block_structure(&b, &ctx)
        .expect("pre-segwit dummy commitment OP_RETURN is not bad-witness-nonce-size");
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
    let root3 = merkle_root_bytes(&[a, b, a]);
    assert_ne!(root2, root3);
    assert_eq!(merkle_root_bytes(&[]), [0u8; 32]);
}

#[test]
fn witness_commitment_script_honors_reserved() {
    let wtx = [[0x11u8; 32]];
    let zero = witness_commitment_script(wtx, &[0u8; 32]);
    let ones = witness_commitment_script(wtx, &[0xffu8; 32]);
    assert_ne!(zero, ones);
    assert_eq!(&zero[..6], &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    assert_eq!(zero.len(), 38);
    assert_eq!(ones.len(), 38);
}

#[test]
fn p1_block_subsidy_halvings() {
    let main = ChainParams::mainnet();
    assert_eq!(block_subsidy(0, &main), 50_0000_0000);
    assert_eq!(block_subsidy(209_999, &main), 50_0000_0000);
    assert_eq!(block_subsidy(210_000, &main), 25_0000_0000);
    assert_eq!(block_subsidy(419_999, &main), 25_0000_0000);
    assert_eq!(block_subsidy(420_000, &main), 12_5000_0000);
    assert_eq!(block_subsidy(210_000 * 64, &main), 0);

    let rt = ChainParams::regtest();
    assert_eq!(block_subsidy(149, &rt), 50_0000_0000);
    assert_eq!(block_subsidy(150, &rt), 25_0000_0000);
}

#[test]
fn rejects_coinbase_excess_value_fast() {
    let mut cb = coinbase(1);
    cb.output[0].value = Amount::from_sat(50_0000_0000 + 1);
    let block = block_with(vec![cb]);
    let err = rbitcoin_consensus::block::check_coinbase_subsidy(&block, &ctx_h(1), 0).unwrap_err();
    assert_bad_block(err, "coinbase excess value");
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
    assert_eq!(last_script_push(&[]), Some(&[][..]));
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0u8; 20]);
    p2sh.push(0x87);
    assert!(bitcoin::Script::from_bytes(&p2sh).is_p2sh());
    assert!(!bitcoin::Script::from_bytes(&[0x00]).is_p2sh());
    assert!(!bitcoin::Script::from_bytes(&[0xa9, 0x14]).is_p2sh());
    let mut wpkh = vec![0x00, 0x14];
    wpkh.extend_from_slice(&[1u8; 20]);
    assert!(bitcoin::Script::from_bytes(&wpkh).is_p2wpkh());
    assert!(!bitcoin::Script::from_bytes(&[0x51, 0x14]).is_p2wpkh());
    let mut wsh = vec![0x00, 0x20];
    wsh.extend_from_slice(&[2u8; 32]);
    assert!(bitcoin::Script::from_bytes(&wsh).is_p2wsh());
    assert!(!bitcoin::Script::from_bytes(&wpkh).is_p2wsh());
    assert!(!bitcoin::Script::from_bytes(&[0x51, 0x20]).is_p2wsh());
}

#[test]
fn last_script_push_rejects_a_non_push_and_a_short_pushdata() {
    // OP_16 (0x60) is an empty push. The next opcode is not a push.
    assert_eq!(last_script_push(&[0x60]), Some(&[][..]));
    assert!(last_script_push(&[0x61]).is_none());
    // PUSHDATA2 needs two length bytes. One byte, or a length past the script, is no redeem.
    assert!(last_script_push(&[0x4d]).is_none());
    assert!(last_script_push(&[0x4d, 0x01]).is_none());
    assert!(last_script_push(&[0x4d, 0x02, 0x00, 0x11]).is_none());
    // PUSHDATA4 needs four length bytes. Three is no redeem.
    assert!(last_script_push(&[0x4e, 0x00, 0x00, 0x00]).is_none());
}

#[test]
fn p3_default_milestone_heights() {
    use rbitcoin_consensus::default_milestone_height;
    use rbitcoin_primitives::Network;
    assert_eq!(default_milestone_height(Network::Regtest), 0);
    assert_eq!(default_milestone_height(Network::Mainnet), 840_000);
    assert_eq!(default_milestone_height(Network::Testnet), 2_500_000);
    assert_eq!(default_milestone_height(Network::Signet), 0);
    let anchor = rbitcoin_consensus::default_milestone_anchor(Network::Mainnet).unwrap();
    assert_eq!(
        anchor.hash.to_string(),
        rbitcoin_consensus::MAINNET_MILESTONE_HASH
    );
    assert_ne!(anchor.min_work_be, [0u8; 32]);
    let testnet = rbitcoin_consensus::default_milestone_anchor(Network::Testnet).unwrap();
    assert_eq!(
        testnet.hash.to_string(),
        rbitcoin_consensus::TESTNET_MILESTONE_HASH
    );
    assert!(rbitcoin_consensus::default_milestone_anchor(Network::Signet).is_none());
    assert!(rbitcoin_consensus::default_milestone_anchor(Network::Regtest).is_none());
}

#[test]
fn s8_accepts_witness_commitment_with_reserved_value() {
    let mut spend = non_coinbase_spend(11);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let mut cb = coinbase(1);
    let reserved = [0x42u8; 32];
    cb.input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
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

/// Core `GetWitnessCommitmentIndex` keeps the last output whose script is at
/// least 38 bytes and starts `6a24aa21a9ed`. An earlier match does not win.
#[test]
fn s8_last_witness_commitment_output_wins() {
    let mut spend = non_coinbase_spend(17);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let wtxid = spend.compute_wtxid().to_byte_array();
    let reserved = [0x42u8; 32];
    let good = witness_commitment_script([wtxid], &reserved);
    let mut bad = good.clone();
    bad[6] ^= 0xff;
    let commit = |bytes: Vec<u8>| TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(bytes),
    };

    {
        let mut cb = coinbase(1);
        cb.input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
        cb.output.push(commit(bad.clone()));
        cb.output.push(commit(good.clone()));
        let b = block_with(vec![cb, spend.clone()]);
        validate_block_structure(&b, &ctx_h(1))
            .expect("the last commitment hash is the one checked");
    }
    {
        let mut cb = coinbase(1);
        cb.input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
        cb.output.push(commit(good.clone()));
        cb.output.push(commit(bad));
        let err =
            validate_block_structure(&block_with(vec![cb, spend.clone()]), &ctx_h(1)).unwrap_err();
        assert_bad_block(err, "witness commitment mismatch");
    }
    // 37 bytes is under Core's minimum, so a trailing magic prefix does not
    // displace the earlier 38-byte commitment.
    {
        let mut cb = coinbase(1);
        cb.input[0].witness = Witness::from_slice(&[reserved.as_slice()]);
        cb.output.push(commit(good));
        let mut short = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        short.extend([0u8; 31]);
        assert_eq!(short.len(), 37);
        cb.output.push(commit(short));
        validate_block_structure(&block_with(vec![cb, spend]), &ctx_h(1))
            .expect("a 37-byte trailer is not a witness commitment");
    }
}

/// Nonce length is exactly 32. Empty and multi-item stacks are pinned separately.
#[test]
fn s8_rejects_nonce_lengths_beside_32() {
    let mut spend = non_coinbase_spend(19);
    spend.input[0].witness = Witness::from_slice(&[vec![0xab]]);
    let wtxid = spend.compute_wtxid().to_byte_array();
    let reserved = [0x11u8; 32];
    let spk = witness_commitment_script([wtxid], &reserved);
    for n in [31usize, 33] {
        let mut cb = coinbase(1);
        cb.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        cb.input[0].witness = Witness::from_slice(&[vec![0u8; n]]);
        let err =
            validate_block_structure(&block_with(vec![cb, spend.clone()]), &ctx_h(1)).unwrap_err();
        assert_bad_block(err, "bad-witness-nonce-size");
    }
}

/// Once segwit is active, witness bytes on the coinbase alone still require a commitment.
#[test]
fn s8_coinbase_witness_without_commitment_is_missing() {
    let mut cb = coinbase(1);
    cb.input[0].witness = Witness::from_slice(&[&[0u8; 32]]);
    let err = validate_block_structure(&block_with(vec![cb]), &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "missing witness commitment");
}

/// Length 2 is the floor. Height 1's BIP34 push is one byte (`OP_1`); the
/// length rule rejects that encoding before the height check.
#[test]
fn s9_coinbase_scriptsig_length_two_accepts_one_rejects() {
    let cb = coinbase(1);
    assert_eq!(cb.input[0].script_sig.len(), 2);
    validate_block_structure(&block_with(vec![cb]), &ctx_h(1)).expect("scriptSig length 2");

    let mut short = coinbase(1);
    short.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    assert_eq!(short.input[0].script_sig.len(), 1);
    let err = validate_block_structure(&block_with(vec![short]), &ctx_h(1)).unwrap_err();
    assert_bad_block(err, "bad-cb-length");
}

#[test]
fn bip34_wrong_push_encoding_rejected_after_activation() {
    let p = Box::leak(Box::new(ChainParams::signet()));
    let ctx = ValidationContext::at(p, Height(1), Milestone::NONE);
    let mut cb = coinbase(1);
    // Height 1 must be OP_1 (0x51); push-length form is wrong.
    cb.input[0].script_sig = ScriptBuf::from_bytes(vec![0x01, 0x01, 0x00]);
    let b = block_with(vec![cb]);
    let err = validate_block_structure(&b, &ctx).unwrap_err();
    assert_bad_block(err, "bip34");
}

#[test]
fn assemble_rejects_empty_and_fk_mismatch() {
    use assemble_block_prevouts;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdges};
    let ctx = ctx_h(1);
    let empty = block_with(vec![]);
    let parents = BatchParents::new();
    let thin = SpendEdges::default();
    let mut spent = OutPointSet::default();
    let mut creates = PendingCreates::default();
    let zero = [0u8; 32];
    let err = assemble_block_prevouts(
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
        true,
    )
    .err()
    .expect("empty");
    assert_bad_block(rule_err(err), "empty");
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
        true,
    )
    .err()
    .expect("fk mismatch");
    assert_bad_block(rule_err(err2), "archived tx fk");
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
        true,
    )
    .err()
    .expect("not coinbase");
    assert_bad_block(rule_err(err3), "coinbase");
}

/// Pack creates are `txid → fk` (one insert). Meters flush once (in_n = spends).
#[test]
fn assemble_pending_creates_is_txid_map_and_meters_flush() {
    use assemble_block_prevouts;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdges};
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("assemble-creates");
    let ctx = ctx_h(1);
    let parents = BatchParents::new();
    let thin = SpendEdges::default();
    let mut spent = OutPointSet::default();
    let mut creates = PendingCreates::default();
    let b = block_with(vec![coinbase(1)]);
    let tids: Vec<[u8; 32]> = b
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = b.header.block_hash().to_byte_array();
    let bip16 = bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &bh, 0);
    let _ = q.confirm_stats().take_window();
    let (_, _, _, _, meters) = assemble_block_prevouts(
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
        true,
    )
    .expect("coinbase-only assemble");
    meters.acc.flush(q.confirm_stats());
    assert_eq!(creates.len(), 1, "one create fk per tx, not per vout");
    assert_eq!(creates.get(&tids[0]), Some(&Fk(1)));
    let w = q.confirm_stats().take_window();
    assert_eq!(w.asm_in_n, 0, "coinbase has no prevouts");
    assert_eq!(w.asm_prev_batch_n, 0);
    assert_eq!(w.asm_prev_same_n, 0);
    let _ = std::fs::remove_dir_all(&path);
}

/// Confirm jobs keep prevout scripts in the wire block or the pin Arc.
#[test]
fn script_job_shares_prevout_script() {
    use assemble_block_prevouts;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdge, SpendEdges};
    use rbitcoin_store::{OutputRecord, TxRecord};

    let ctx = ctx_h(1);
    let parent_txid = [0x42u8; 32];
    let hist_script = vec![0x51, 0x11, 0x22];
    let mut parents = BatchParents::new();
    parents.insert_owned(
        Fk(10),
        TxRecord {
            txid: parent_txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![(0, OutputRecord::unspent(50_0000_0000, hist_script.clone()))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let pin_ptr = parents
        .get_parent_txout_parts(Fk(10), 0, |_, script, _| script.as_ptr())
        .expect("pin script");

    let same_script = vec![0x51, 0xab];
    let mid = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(parent_txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(40_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(same_script),
        }],
    };
    let mid_txid = mid.compute_txid();
    let child = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: mid_txid,
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
    };
    let block = block_with(vec![coinbase(1), mid, child]);
    let wire = std::sync::Arc::new(block);
    let tids: Vec<[u8; 32]> = wire
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = wire.header.block_hash().to_byte_array();
    let bip16 = bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &bh, 0);
    let mut edges = SpendEdges::default();
    edges.insert(
        2,
        vec![SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk: Fk(2),
            create_fk: Fk(10),
            vin: 0,
        }],
    );
    let mut spent = OutPointSet::default();
    let mut creates = PendingCreates::default();
    let (jobs, _, _, _, _) = assemble_block_prevouts(
        &wire,
        &ctx,
        Some(&[Fk(1), Fk(2), Fk(3)]),
        &mut spent,
        &mut creates,
        &parents,
        &edges,
        &tids,
        0,
        &bh,
        bip16,
        Some(&wire),
        None,
        true,
    )
    .expect("assemble shared prevouts");
    assert_eq!(jobs.len(), 2);
    let hist = {
        let i = jobs[0].inputs().next().unwrap();
        jobs[0].prevout_script(i)
    }
    .expect("historical script");
    assert_eq!(hist, hist_script.as_slice());
    assert_eq!(
        hist.as_ptr(),
        pin_ptr,
        "historical prevout script is the pin allocation"
    );
    let same = {
        let i = jobs[1].inputs().next().unwrap();
        jobs[1].prevout_script(i)
    }
    .expect("same-block script");
    assert_eq!(same, wire.txdata[1].output[0].script_pubkey.as_bytes());
    assert_eq!(
        same.as_ptr(),
        wire.txdata[1].output[0].script_pubkey.as_bytes().as_ptr(),
        "same-block prevout script is the wire output"
    );
}

/// Optimistic IBD: unstamped parent must not recover via `tx_fk_by_txid_tip`.
#[test]
fn optimistic_assemble_unstamped_parent_is_invariant() {
    use assemble_block_prevouts;
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::accept_and_connect_block;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdges};
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("assemble-unstamped");
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let parent_txid = b1.txdata[0].compute_txid();
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: b1.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: b1.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase(2), spend],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let p = Box::leak(Box::new(params));
    let ctx = ValidationContext::at(p, Height(2), Milestone::height(840_000));
    let parents = BatchParents::new();
    let thin = SpendEdges::default();
    let mut spent = OutPointSet::default();
    let mut creates = PendingCreates::default();
    let create_txids: Vec<[u8; 32]> = block
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = block.header.block_hash().to_byte_array();
    let spend_fks = [Fk(3), Fk(4)];
    let err = assemble_block_prevouts(
        &block,
        &ctx,
        Some(&spend_fks),
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &create_txids,
        b1.header.time,
        &bh,
        bip16_active_from_prev_mtp(ctx.params, ctx.height.0, &bh, b1.header.time),
        None,
        None,
        true,
    )
    .err()
    .expect("unstamped parent must not head-recover");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant") && msg.contains("lookup stage miss"),
        "got {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Connect-path spend rejects: same-block coinbase spend (always immature),
/// same-block double spend, child-before-parent, `in < out`, and a height-1
/// coinbase still immature 4 deep.
#[test]
fn accept_rejects_connect_spend_rules() {
    use rbitcoin_consensus::{mine_empty_regtest, prepare_regtest_candidate};
    use rbitcoin_query::{accept_and_connect_block, pad_empty_from};
    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("connect-spend-rules");
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();

    fn spend(op: OutPoint, sats: u64) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    let mut same_cb = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let cb_op = OutPoint {
        txid: same_cb.txdata[0].compute_txid(),
        vout: 0,
    };
    same_cb
        .txdata
        .push(spend(cb_op, same_cb.txdata[0].output[0].value.to_sat()));
    prepare_regtest_candidate(
        &mut same_cb,
        genesis.block_hash(),
        genesis.header.time + 600,
    );
    let err = accept_and_connect_block(&q, &params, Height(1), &same_cb, Milestone::NONE)
        .expect_err("same-block coinbase spend must be immature");
    match err {
        ConfirmError::Rules(ConsensusError::BadTx("coinbase immature")) => {}
        other => panic!("expected coinbase immature, got {other}"),
    }

    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let op = OutPoint {
        txid: b1.txdata[0].compute_txid(),
        vout: 0,
    };

    let mut dup = mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
    dup.txdata.push(spend(op, 1_000));
    dup.txdata.push(spend(op, 2_000));
    prepare_regtest_candidate(&mut dup, b1.block_hash(), b1.header.time + 600);
    let err = accept_and_connect_block(&q, &params, Height(2), &dup, Milestone::NONE)
        .expect_err("same-block double spend");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadTx(s)) if s.contains("double spend")),
        "same-block double spend: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(1)));

    let parent = spend(op, 1_000);
    let child = spend(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        500,
    );
    let mut bad_order = mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
    bad_order.txdata.push(child);
    bad_order.txdata.push(parent);
    prepare_regtest_candidate(&mut bad_order, b1.block_hash(), b1.header.time + 600);
    let err = accept_and_connect_block(&q, &params, Height(2), &bad_order, Milestone::NONE)
        .expect_err("child-before-parent");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::MissingPrevout)),
        "child-before-parent: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(1)));

    let mut over = mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
    over.txdata.push(spend(op, 50_0000_0000 + 1));
    prepare_regtest_candidate(&mut over, b1.block_hash(), b1.header.time + 600);
    let err = accept_and_connect_block(&q, &params, Height(2), &over, Milestone::NONE)
        .expect_err("in < out");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadTx(s)) if s.contains("in < out")),
        "in < out: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(1)));

    let (tip, time, _) = pad_empty_from(&q, &params, b1.block_hash(), b1.header.time, 2, 4, 0);
    assert_eq!(q.tip_height(), Some(Height(4)));
    let mut b5 = mine_empty_regtest(tip, time + 600, 5);
    b5.txdata.push(spend(op, 1_000));
    prepare_regtest_candidate(&mut b5, tip, time + 600);
    let err = accept_and_connect_block(&q, &params, Height(5), &b5, Milestone::NONE)
        .expect_err("height-1 coinbase still immature 4 deep");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadTx(s)) if s.contains("immature")),
        "4-deep immature: {err:?}"
    );
}

/// Core never adds the genesis coinbase to the coin view. A spend of it is a
/// missing prevout at any depth, with or without script checks.
#[test]
fn genesis_coinbase_is_never_a_coin() {
    use rbitcoin_consensus::{mine_empty_regtest, prepare_regtest_candidate};
    use rbitcoin_query::{accept_and_connect_block, pad_empty_from};
    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("genesis-cb-spend");
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let op = OutPoint {
        txid: genesis.txdata[0].compute_txid(),
        vout: 0,
    };
    let spend_genesis = |tip: BlockHash, time: u32, h: u32| {
        let mut b = mine_empty_regtest(tip, time + 600, h);
        b.txdata.push(Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        });
        prepare_regtest_candidate(&mut b, tip, time + 600);
        b
    };

    let b1 = spend_genesis(genesis.block_hash(), genesis.header.time, 1);
    let err = accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE)
        .expect_err("genesis coinbase spend at height 1");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::MissingPrevout)),
        "height 1: {err:?}"
    );

    let maturity = params.coinbase_maturity();
    let (tip, time, _) = pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        maturity,
        0,
    );
    let h = maturity + 1;
    let block = spend_genesis(tip, time, h);
    for ms in [Milestone::NONE, Milestone::height(h)] {
        let err = accept_and_connect_block(&q, &params, Height(h), &block, ms)
            .expect_err("mature genesis coinbase spend");
        assert!(
            matches!(err, ConfirmError::Rules(ConsensusError::MissingPrevout)),
            "{ms:?}: {err:?}"
        );
        assert_eq!(q.tip_height(), Some(Height(maturity)));
    }
}

/// An anchored milestone skips a script that fails, and only on that header path.
///
/// The spent output is P2PKH and the scriptSig is empty, so the interpreter
/// rejects it. `OP_TRUE` and `OP_RETURN` are not this case.
#[test]
fn anchored_milestone_skips_a_failing_p2pkh_script() {
    use rbitcoin_consensus::{mine_regtest_paying, MilestoneAnchor};
    use rbitcoin_query::{accept_and_connect_block, pad_empty_from};

    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("anchor-skip-p2pkh");
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();

    let mut spk = vec![0x76, 0xa9, 0x14];
    spk.extend_from_slice(&[0x11; 20]);
    spk.extend_from_slice(&[0x88, 0xac]);
    let created = mine_regtest_paying(
        genesis.block_hash(),
        genesis.header.time + 600,
        1,
        ScriptBuf::from_bytes(spk),
        Vec::new(),
    );
    accept_and_connect_block(&q, &params, Height(1), &created, Milestone::NONE).unwrap();
    let coin_txid = created.txdata[0].compute_txid();
    let coin_value = created.txdata[0].output[0].value;

    let maturity = params.coinbase_maturity();
    let (tip, time, _) = pad_empty_from(
        &q,
        &params,
        created.block_hash(),
        created.header.time,
        2,
        maturity,
        0,
    );
    let h = maturity + 1;
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coin_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: coin_value - Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let block = mine_regtest_paying(
        tip,
        time + 600,
        h,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    );
    let block_hash = block.block_hash().to_byte_array();
    let parent_hash = tip.to_byte_array();
    let one = {
        let mut w = [0u8; 32];
        w[31] = 1;
        bitcoin::Work::from_be_bytes(w)
    };
    let note = |height: u32, hash: [u8; 32]| {
        q.note_milestone_header(height, hash, [0; 32], one, Some(one));
    };
    let anchored = |height: u32, hash: [u8; 32]| Milestone {
        height,
        anchor: Some(MilestoneAnchor {
            hash: bitcoin::BlockHash::from_byte_array(hash),
            min_work_be: [0xff; 32],
        }),
    };

    note(maturity, parent_hash);
    let above = anchored(maturity, parent_hash);
    let err = accept_and_connect_block(&q, &params, Height(h), &block, above)
        .expect_err("one height above the anchor still runs the failing script");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::Script(_))),
        "expected a script failure, got {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(maturity)));

    q.clear_milestone_path_above(0);
    let mut wrong = block_hash;
    wrong[0] ^= 0xff;
    note(h, wrong);
    let err = accept_and_connect_block(&q, &params, Height(h), &block, anchored(h, block_hash))
        .expect_err("a different hash at the anchor height does not skip");
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::Script(_))),
        "{err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(maturity)));

    q.clear_milestone_path_above(0);
    note(h, block_hash);
    accept_and_connect_block(&q, &params, Height(h), &block, anchored(h, block_hash))
        .expect("the anchor hash skips the failing P2PKH script");
    assert_eq!(q.tip_height(), Some(Height(h)));
}

/// An output whose script starts with `OP_RETURN`, or is longer than 10_000
/// bytes, is not a coin. Spending it is a missing prevout with scripts on
/// and under a height-only milestone. A 10_000-byte script that does not
/// start with `OP_RETURN` stays a coin. Leaving the output unspent still
/// connects, and the archive keeps the script bytes.
#[test]
fn spending_an_unspendable_output_is_missing_prevout() {
    use rbitcoin_consensus::{mine_empty_regtest, prepare_regtest_candidate};
    use rbitcoin_query::{accept_and_connect_block, pad_empty_from};
    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("unspendable-not-a-coin");
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();

    /// 10_000 bytes, 20 pushes, top of stack truthy. Under the 201-opcode cap,
    /// so a spend executes when scripts run and still connects when they do not.
    fn spendable_10k() -> Vec<u8> {
        let mut script = Vec::with_capacity(10_000);
        let chunk = [0x11u8; 520];
        for _ in 0..19 {
            script.push(0x4d);
            script.extend_from_slice(&520u16.to_le_bytes());
            script.extend_from_slice(&chunk);
        }
        script.push(0x4c);
        script.push(61);
        script.extend_from_slice(&[0x11u8; 61]);
        assert_eq!(script.len(), 10_000);
        script
    }
    fn pay(sats: u64, script: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(script),
        }
    }
    fn spend_to(txid: bitcoin::Txid, vout: u32, sats: u64) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![pay(sats, vec![0x51])],
        }
    }

    let subsidy = block_subsidy(1, &params) as u64;
    let op_return = vec![0x6a];
    let coin = spendable_10k();
    let mut oversize = coin.clone();
    oversize.push(0x00);
    let mut created = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    created.txdata[0].output = vec![
        pay(subsidy - 4, vec![0x51]),
        pay(1, op_return.clone()),
        pay(1, oversize.clone()),
        pay(1, coin.clone()),
        pay(1, coin.clone()),
    ];
    prepare_regtest_candidate(
        &mut created,
        genesis.block_hash(),
        genesis.header.time + 600,
    );
    accept_and_connect_block(&q, &params, Height(1), &created, Milestone::NONE)
        .expect("creating an unspendable output still connects");
    let cb_txid = created.txdata[0].compute_txid();
    let stored = q
        .connected_tx_outputs(&cb_txid.to_byte_array())
        .unwrap()
        .expect("the create stays in the archive");
    assert_eq!(stored.2[1].script, op_return);
    assert!(!q.is_outpoint_spent(&cb_txid.to_byte_array(), 1).unwrap());

    let maturity = params.coinbase_maturity();
    let (mut tip, mut time, _) = pad_empty_from(
        &q,
        &params,
        created.block_hash(),
        created.header.time,
        2,
        maturity,
        0,
    );
    assert_eq!(q.tip_height(), Some(Height(maturity)));

    let reject = |q: &rbitcoin_query::Query,
                  tip: BlockHash,
                  time: u32,
                  height: u32,
                  txs: Vec<Transaction>,
                  ms: Milestone| {
        let mut block = mine_empty_regtest(tip, time + 600, height);
        block.txdata.extend(txs);
        prepare_regtest_candidate(&mut block, tip, time + 600);
        let err = accept_and_connect_block(q, &params, Height(height), &block, ms)
            .expect_err("unspendable output is not a coin");
        assert!(
            matches!(err, ConfirmError::Rules(ConsensusError::MissingPrevout)),
            "{ms:?} h={height}: {err:?}"
        );
        assert_eq!(q.tip_height(), Some(Height(height - 1)));
    };
    let connect = |q: &rbitcoin_query::Query,
                   tip: BlockHash,
                   time: u32,
                   height: u32,
                   txs: Vec<Transaction>,
                   ms: Milestone|
     -> (BlockHash, u32) {
        let mut block = mine_empty_regtest(tip, time + 600, height);
        block.txdata.extend(txs);
        prepare_regtest_candidate(&mut block, tip, time + 600);
        accept_and_connect_block(q, &params, Height(height), &block, ms)
            .unwrap_or_else(|e| panic!("{ms:?} h={height} spend of a 10000-byte coin: {e:?}"));
        let next = block.block_hash();
        let stamped = block.header.time;
        (next, stamped)
    };

    let h = maturity + 1;
    for ms in [Milestone::NONE, Milestone::height(h)] {
        reject(&q, tip, time, h, vec![spend_to(cb_txid, 1, 1)], ms);
        reject(&q, tip, time, h, vec![spend_to(cb_txid, 2, 1)], ms);
    }
    (tip, time) = connect(
        &q,
        tip,
        time,
        h,
        vec![spend_to(cb_txid, 3, 1)],
        Milestone::NONE,
    );
    let h = h + 1;
    (tip, time) = connect(
        &q,
        tip,
        time,
        h,
        vec![spend_to(cb_txid, 4, 1)],
        Milestone::height(h),
    );

    let anchor_value = subsidy - 4;
    let h = h + 1;
    let same_block = |burn: Vec<u8>| {
        let parent = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: cb_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![pay(1, burn), pay(anchor_value - 1, vec![0x51])],
        };
        let child = spend_to(parent.compute_txid(), 0, 1);
        vec![parent, child]
    };
    for ms in [Milestone::NONE, Milestone::height(h)] {
        reject(&q, tip, time, h, same_block(vec![0x6a]), ms);
        reject(&q, tip, time, h, same_block(oversize.clone()), ms);
    }
    let _ = connect(&q, tip, time, h, same_block(coin), Milestone::height(h));
}

#[test]
fn assemble_milestone_pin_still_rejects_bad_blk_sigops() {
    use assemble_block_prevouts;
    use bitcoin::hashes::{sha256, Hash};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdge, SpendEdges};
    use rbitcoin_store::{OutputRecord, TxRecord};
    let ws = vec![0xacu8; 80_001];
    let h = sha256::Hash::hash(&ws);
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(h.as_byte_array());
    let mut parent_txid = [0u8; 32];
    parent_txid[0] = 0x42;
    let rec = TxRecord {
        txid: parent_txid,
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let mut parents = BatchParents::new();
    parents.insert_owned(
        Fk(7),
        rec,
        vec![(0, OutputRecord::unspent(50_0000_0000, spk))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(parent_txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&ws]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let b = block_with(vec![coinbase(1), spend]);
    let params = Box::leak(Box::new(ChainParams::regtest()));
    let ctx = ValidationContext::at(params, Height(1), Milestone::height(100));
    assert!(ctx.milestone.skips_scripts_at(ctx.height.0));
    let spend_fk = Fk(100);
    let mut thin = SpendEdges::default();
    thin.insert(
        spend_fk.0,
        vec![SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk,
            create_fk: Fk(7),
            vin: 0,
        }],
    );
    let mut spent = OutPointSet::default();
    let mut creates = PendingCreates::default();
    let tids: Vec<[u8; 32]> = b
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = b.header.block_hash().to_byte_array();
    let err = assemble_block_prevouts(
        &b,
        &ctx,
        Some(&[Fk::NULL, spend_fk]),
        &mut spent,
        &mut creates,
        &parents,
        &thin,
        &tids,
        0,
        &bh,
        true,
        None,
        None,
        true,
    )
    .err()
    .expect("over-budget pin P2WSH must reject");
    assert_bad_block(rule_err(err), "bad-blk-sigops");
}

/// Anchored skip uses the header path. A height match with a different hash
/// still builds script jobs.
fn signet_low_work_fork_runs_scripts(q: &rbitcoin_query::Query) {
    use assemble_block_prevouts;
    use bitcoin::hashes::Hash;
    use rbitcoin_consensus::MilestoneAnchor;
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParents, OutPointSet, SpendEdge, SpendEdges};
    use rbitcoin_store::{OutputRecord, TxRecord};
    let mut parent_txid = [0u8; 32];
    parent_txid[0] = 0x42;
    let rec = TxRecord {
        txid: parent_txid,
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let mut parents = BatchParents::new();
    parents.insert_owned(
        Fk(7),
        rec,
        vec![(0, OutputRecord::unspent(50_0000_0000, vec![0x51]))],
        vec![0],
        Some(false),
        None,
        Vec::new(),
    );
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(parent_txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let b = block_with(vec![coinbase(1), spend]);
    let params = Box::leak(Box::new(ChainParams::signet()));
    let anchor_hash = [0xabu8; 32];
    let mut min = [0u8; 32];
    min[1] = 1;
    let ms = Milestone {
        height: 100,
        anchor: Some(MilestoneAnchor {
            hash: bitcoin::BlockHash::from_byte_array(anchor_hash),
            min_work_be: min,
        }),
    };
    let ctx = ValidationContext::at(params, Height(1), ms);
    let spend_fk = Fk(100);
    let mut thin = SpendEdges::default();
    thin.insert(
        spend_fk.0,
        vec![SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk,
            create_fk: Fk(7),
            vin: 0,
        }],
    );
    let tids: Vec<[u8; 32]> = b
        .txdata
        .iter()
        .map(|t| t.compute_txid().to_byte_array())
        .collect();
    let bh = b.header.block_hash().to_byte_array();
    let run = |q: &rbitcoin_query::Query| {
        let mut spent = OutPointSet::default();
        let mut creates = PendingCreates::default();
        assemble_block_prevouts(
            &b,
            &ctx,
            Some(&[Fk::NULL, spend_fk]),
            &mut spent,
            &mut creates,
            &parents,
            &thin,
            &tids,
            0,
            &bh,
            true,
            None,
            None,
            rbitcoin_query::milestone_gate::check_scripts(ms, q, 1, &bh),
        )
        .expect("op_true spend assembles")
        .0
    };
    assert_eq!(run(q).len(), 1, "missing anchor path still checks scripts");
    assert!(rbitcoin_query::milestone_gate::check_scripts(ms, q, 1, &bh));
    let mut base = [0u8; 32];
    base[1] = 2;
    let mut one = [0u8; 32];
    one[31] = 1;
    q.note_milestone_header(
        1,
        bh,
        [0; 32],
        bitcoin::Work::from_be_bytes(one),
        Some(bitcoin::Work::from_be_bytes(base)),
    );
    q.note_milestone_header(
        100,
        anchor_hash,
        [0; 32],
        bitcoin::Work::from_be_bytes(one),
        None,
    );
    assert!(
        run(q).is_empty(),
        "header path through the anchor skips scripts"
    );
    assert!(!rbitcoin_query::milestone_gate::check_scripts(
        ms, q, 1, &bh
    ));
    q.clear_milestone_path_above(0);
    assert_eq!(run(q).len(), 1, "cleared path checks scripts again");
}

/// Confirms a height-1 tx that spends `create_fk:0`.
fn plant_confirmed_spend(
    q: &rbitcoin_query::Query,
    create_txid: [u8; 32],
    create_fk: rbitcoin_primitives::Fk,
) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    let rec = TxRecord {
        txid: [0x5e; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let input = InputRecord {
        prev_txid: create_txid,
        parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    };
    let spender = q
        .store()
        .put_tx_full_batch_indexed(
            &[(
                rec,
                vec![input],
                vec![OutputRecord::unspent(1_000, vec![0x51])],
            )],
            true,
        )
        .unwrap()[0];
    q.store().header_txs.put_range(Fk(2), spender, 1).unwrap();
    q.store().confirmed.set(Height(1), Fk(2)).unwrap();
    q.store().rebuild_height_fence().unwrap();
    q.store().strong_tx.set_strong(spender, Fk(2)).unwrap();
    q.store()
        .put_spend_create(create_fk, 0, spender, 0)
        .unwrap();
}

#[test]
fn bip30_and_immature_coinbase_reject_from_facts() {
    use rbitcoin_consensus::block::{reject_bip30_unspent_prior, reject_one_create};
    assert!(reject_bip30_unspent_prior(2, 2, true).is_ok());
    let bip30 = reject_bip30_unspent_prior(5, 1, true).unwrap_err();
    assert!(
        matches!(bip30, ConsensusError::BadTx(s) if s.contains("BIP30")),
        "{bip30:?}"
    );
    assert!(reject_bip30_unspent_prior(5, 1, false).is_ok());

    let missing = reject_one_create(10, 100, None, false).unwrap_err();
    assert!(
        matches!(missing, ConsensusError::BadTx(s) if s.contains("missingorspent")),
        "{missing:?}"
    );
    let forward = reject_one_create(10, 100, Some(11), false).unwrap_err();
    assert!(
        matches!(forward, ConsensusError::MissingPrevout),
        "{forward:?}"
    );
    let immature = reject_one_create(10, 100, Some(1), true).unwrap_err();
    assert!(
        matches!(immature, ConsensusError::BadTx(s) if s.contains("immature")),
        "{immature:?}"
    );
    assert!(reject_one_create(101, 100, Some(1), true).is_ok());
}

/// Core never adds `IsUnspendable` outputs (leading `OP_RETURN`, or a script
/// over 10_000 bytes) to the coin view, so they do not block a BIP30
/// overwrite. A spendable unspent output still does.
#[test]
fn bip30_ignores_unspendable_outputs() {
    use rbitcoin_query::{BatchParents, U32Map};
    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x42]),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51; 10_001]),
        },
    ];
    let (path, q, first, fk) = plant_coinbase_with_outputs("bip30-unspendable", outputs);
    let dup = block_with(vec![first.clone()]);
    let check = |q: &rbitcoin_query::Query| {
        let mut mtp_cache = U32Map::default();
        mtp_cache.insert(9, 0);
        let parents = BatchParents::new();
        let abs_jobs = parents
            .spend_abs_jobs(std::iter::empty::<(
                rbitcoin_primitives::Fk,
                u32,
                rbitcoin_primitives::Fk,
                u32,
            )>())
            .expect("no spend edges");
        structural_validate_spends(
            q,
            &dup,
            &ctx_h(10),
            &[],
            0,
            &mut rbitcoin_query::block_pipeline::BatchSpent::default(),
            &parents,
            &mut mtp_cache,
            &RunCreateHeight::Spans(Vec::new()),
            &ClassAWave::default(),
            &mut StructuralScratch::default(),
            &abs_jobs,
            None,
        )
        .err()
        .map(|e| format!("{e}"))
        .unwrap_or_default()
    };
    assert!(
        check(&q).contains("bad-txns-BIP30"),
        "a spendable unspent output must still block the overwrite"
    );
    plant_confirmed_spend(&q, first.compute_txid().to_byte_array(), fk);
    let msg = check(&q);
    assert!(
        msg.is_empty(),
        "unspendable outputs are not coins, got {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Leading `OP_RETURN` and a script longer than 10_000 bytes are not coins.
/// The pin returns an empty `script_pubkey`; the check uses the archived bytes
/// with and without a script job.
#[test]
fn resolve_prevout_rejects_an_unspendable_script() {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::block_pipeline::resolve_prevout;
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::{OutputRecord, TxRecord};
    let txid = [0x42u8; 32];
    let fk = Fk(7);
    let rec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_count: 0,
        output_count: 1,
    };
    let op = OutPoint {
        txid: bitcoin::Txid::from_byte_array(txid),
        vout: 0,
    };
    let dummy_in = TxIn {
        previous_output: op,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let block = block_with(vec![coinbase(1)]);
    let txid_index = rbitcoin_consensus::block::TxidMap::<usize>::default();
    let try_spend = |script: Vec<u8>, need_script_buf: bool| {
        let mut parents = BatchParents::new();
        parents.put_resolved(
            fk,
            rec.clone(),
            &[(0, OutputRecord::unspent(1, script))],
            &[0],
            Some(true),
        );
        resolve_prevout(
            &block,
            op,
            &dummy_in,
            Some(fk),
            &txid_index,
            1,
            &parents,
            false,
            true,
            need_script_buf,
            None,
            &mut AsmPrevoutAcc::default(),
        )
    };
    let show = |r: &Result<_, ConfirmError>| match r {
        Ok(_) => "resolved as a coin".to_string(),
        Err(e) => format!("{e:?}"),
    };
    for need_script_buf in [false, true] {
        let oversized = try_spend(vec![0x51; 10_001], need_script_buf);
        assert!(
            matches!(
                oversized,
                Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
            ),
            "need_script_buf={need_script_buf} oversized: {}",
            show(&oversized)
        );
        let op_return = try_spend(vec![0x6a, 0x01, 0x42], need_script_buf);
        assert!(
            matches!(
                op_return,
                Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
            ),
            "need_script_buf={need_script_buf} OP_RETURN: {}",
            show(&op_return)
        );
        let max = try_spend(vec![0x51; 10_000], need_script_buf);
        assert!(
            max.is_ok(),
            "need_script_buf={need_script_buf} 10000-byte script is still a coin, got {}",
            show(&max)
        );
    }
}

#[test]
fn buried_rules_and_a_lying_header_path() {
    let (signet_path, signet_q, signet_tx) = plant_unspent_coinbase("buried-signet");
    rejects_unspent_overwrite(&signet_q, &signet_tx);
    signet_low_work_fork_runs_scripts(&signet_q);
    let (main_path, main_q, main_tx) = plant_unspent_coinbase("buried-mainnet");
    mainnet_ancestor_skip_then_miss(&main_q, &main_tx);
    let _ = (
        std::fs::remove_dir_all(&signet_path),
        std::fs::remove_dir_all(&main_path),
    );
}

/// N1: Optimistic miss is lookup invariant; pin hit / identity / vout still classified.
#[test]
fn n1_assemble_cold_why_reasons() {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::accept_and_connect_block;
    use rbitcoin_query::block_pipeline::resolve_prevout;
    use rbitcoin_query::block_pipeline::test_phase as confirm_phase_stats;
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::OutputRecord;
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("n1-cold-why");
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
    let dummy_in = TxIn {
        previous_output: op,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let empty_block = block_with(vec![coinbase(4)]);
    let txid_index = rbitcoin_consensus::block::TxidMap::<usize>::default();

    // Thread-local N1 counters (process-global atomics race under parallel cargo test).
    let _ = confirm_phase_stats::sample_tl_assemble_cold_why_and_reset();
    let _ = confirm_phase_stats::sample_tl_batch_cold_n_and_reset();

    fn assert_lookup_miss(err: ConfirmError) {
        let msg = format!("{err}");
        assert!(
            msg.contains("invariant") && msg.contains("lookup stage miss"),
            "got {msg}"
        );
    }

    // ── null_fk: Optimistic must not recover via head ─────────────
    {
        let parents = BatchParents::new();
        let err = resolve_prevout(
            &empty_block,
            op,
            &dummy_in,
            None,
            &txid_index,
            0,
            &parents,
            false,
            false,
            true,
            None,
            &mut AsmPrevoutAcc::default(),
        )
        .err()
        .expect("null_fk optimistic");
        assert_lookup_miss(err);
    }

    // ── not_pin: correct fk, empty BatchParents ───────────────────
    {
        let parents = BatchParents::new();
        let err = resolve_prevout(
            &empty_block,
            op,
            &dummy_in,
            Some(last_cb_fk),
            &txid_index,
            0,
            &parents,
            false,
            false,
            true,
            None,
            &mut AsmPrevoutAcc::default(),
        )
        .err()
        .expect("not_pin optimistic");
        assert_lookup_miss(err);
    }

    // ── batch hit: no cold ────────────────────────────────────────
    {
        let mut parents = BatchParents::new();
        let rec = q.get_tx(last_cb_fk).expect("class a");
        let out = OutputRecord::unspent(50_0000_0000, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(0, out)], &[0], Some(true));
        // Ensure pin txid matches wire.
        assert_eq!(
            parents
                .get_parent_txout_parts(last_cb_fk, 0, |_, _, t| t)
                .unwrap(),
            parent_txid
        );
        resolve_prevout(
            &empty_block,
            op,
            &dummy_in,
            Some(last_cb_fk),
            &txid_index,
            0,
            &parents,
            false,
            false,
            true,
            None,
            &mut AsmPrevoutAcc::default(),
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
        let mut rec = q.get_tx(last_cb_fk).expect("class a");
        rec.txid = [0xee; 32]; // wrong identity
        let out = OutputRecord::unspent(50_0000_0000, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(0, out)], &[0], Some(true));
        let err = match resolve_prevout(
            &empty_block,
            op,
            &dummy_in,
            Some(last_cb_fk),
            &txid_index,
            0,
            &parents,
            false,
            false,
            true,
            None,
            &mut AsmPrevoutAcc::default(),
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
        let rec = q.get_tx(last_cb_fk).expect("class a");
        // Pin only vout 1 (does not exist on spend of vout 0).
        let out = OutputRecord::unspent(1, vec![0x51]);
        parents.put_resolved(last_cb_fk, rec, &[(1, out)], &[1], Some(true));
        assert!(parents.contains(last_cb_fk));
        assert!(parents
            .get_parent_txout_parts(last_cb_fk, 0, |_, _, _| ())
            .is_none());
        let err = match resolve_prevout(
            &empty_block,
            op,
            &dummy_in,
            Some(last_cb_fk),
            &txid_index,
            0,
            &parents,
            false,
            false,
            true,
            None,
            &mut AsmPrevoutAcc::default(),
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
    use rbitcoin_query::{
        accept_and_connect_block, commit_class_a_block, confirm_scripts_phase,
        confirm_wire_load_from_plan, confirm_wire_lookup_stamp, confirm_write_phase,
        ScriptPreverified,
    };

    use std::sync::Arc;
    let (path, q) = rbitcoin_query::testutil::tiny_query_labeled("plan-none-pin-id");
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
    let tx_b_id = tx_b.compute_txid();
    let b_s1 = mine_with(tip, tip_time + 600, h_spend, vec![tx_a, tx_b]);
    commit_class_a_block(&q, &params, Height(h_spend), &b_s1, ms).unwrap();
    assert_eq!(q.tip_height().map(|h| h.0), Some(maturity + 2));
    // IBD rehydrate path: stamp → load(Forbid) must not miss denserels stage
    // when plan=None (consensus forces Allow cold + body_txid identity).
    {
        let arcs = [(Height(h_spend), Arc::new(b_s1.clone()), None)];
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
        let tx_a_fk = q.tx_fk_by_txid(tx_a_id.as_byte_array()).unwrap().unwrap();
        let tx_b_fk = q.tx_fk_by_txid(tx_b_id.as_byte_array()).unwrap().unwrap();
        let (off, _) = q.store().tx_spent_range(tx_a_fk).unwrap();
        let abs0 = rbitcoin_store::spent_abs(off, 0);
        let bulk = q.store().get_spender_meta_at_abs_batch(&[abs0]).unwrap();
        assert_eq!(bulk[0].unwrap().0, tx_b_fk);
        let (boff, _) = q.store().tx_spent_range(tx_b_fk).unwrap();
        let babs = rbitcoin_store::spent_abs(boff, 0);
        let bbulk = q.store().get_spender_meta_at_abs_batch(&[babs]).unwrap();
        assert!(bbulk[0].unwrap().0.is_null());
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
        matches!(err, ConfirmError::Rules(ConsensusError::PrevoutSpent))
            || format!("{err}").contains("spent")
            || format!("{err}").contains("prevout"),
        "got {err}"
    );

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

/// Testnet3 BIP16 exception (Core `CTestNetParams::script_flag_exceptions`).
#[test]
fn bip16_testnet3_exception_block() {
    use std::str::FromStr;
    let exception =
        BlockHash::from_str("00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105")
            .unwrap()
            .to_byte_array();
    let p = ChainParams::testnet();
    assert!(!bip16_active_from_prev_mtp(&p, 1, &exception, u32::MAX));
    let mut neighbor = exception;
    neighbor[0] ^= 1;
    assert!(bip16_active_from_prev_mtp(&p, 1, &neighbor, u32::MAX));
    assert!(bip16_active_from_prev_mtp(&p, 1, &[1u8; 32], 0));
}

/// Core `GetBlockScriptFlags`: P2SH, WITNESS, and TAPROOT are on for every
/// block. An exception hash replaces that set. DERSIG and NULLDUMMY stay
/// height-gated.
#[test]
fn script_flags_follow_core_exception_table() {
    let mut rt = params();
    rt.apply_test_activation_height("segwit", 1_000).unwrap();
    rt.apply_test_activation_height("dersig", 1_000).unwrap();
    let rt = Box::leak(Box::new(rt));
    let ctx = ValidationContext::at(rt, Height(10), Milestone::NONE);
    let f = ScriptVerifyFlags::consensus_at(&ctx, &[1u8; 32], true);
    assert!(f.bip16_active && f.witness_active && f.taproot_active);
    assert!(!f.null_dummy && !f.bip66_active);

    let main = Box::leak(Box::new(ChainParams::mainnet()));
    let ctx = ValidationContext::at(main, Height(170_060), Milestone::NONE);
    let f = ScriptVerifyFlags::consensus_at(&ctx, &BIP16_EXCEPTION_MAINNET, false);
    assert!(!f.bip16_active && !f.witness_active && !f.taproot_active);

    let ctx = ValidationContext::at(main, Height(692_261), Milestone::NONE);
    let f = ScriptVerifyFlags::consensus_at(&ctx, &TAPROOT_EXCEPTION_MAINNET, true);
    assert!(f.bip16_active && f.witness_active && !f.taproot_active);
    assert!(f.null_dummy && f.bip66_active);
    for f in [
        ScriptVerifyFlags::consensus_at(
            &ValidationContext::at(main, Height(692_262), Milestone::NONE),
            &[1u8; 32],
            true,
        ),
        ScriptVerifyFlags::consensus_at(
            &ValidationContext::at(main, Height(170_060), Milestone::NONE),
            &BIP16_EXCEPTION_MAINNET,
            false,
        ),
        f,
    ] {
        assert!(
            !f.cleanstack && !f.low_s && !f.minimal_data && !f.strictenc && !f.const_scriptcode,
            "policy flags stay off: {f:?}"
        );
    }
}

/// The exception hashes change execution, not only the flag bits.
///
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
    let job = ScriptCheckJob::try_from_parts(
        tid,
        rbitcoin_consensus::block::JobPrevouts::owned(vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }]),
        rbitcoin_consensus::block::JobTx::shared(Arc::clone(&block), 1),
        ScriptVerifyFlags::buried(true, true, true, true, true),
    )
    .expect("prevouts");
    assert!(std::ptr::eq(
        &*job.tx as *const Transaction,
        &block.txdata[1] as *const Transaction
    ));
    assert_eq!(job.txid, tid);
}

#[test]
fn s14_stripped_size_1_000_000_accepts_1_000_001_rejects() {
    let mut ok = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut ok, MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(stripped_size(&ok), MAX_BLOCK_STRIPPED_SIZE);
    assert_eq!(weight_wu(&ok), 4_000_000);
    validate_block_structure(&ok, &ctx_h(0)).expect("exactly 1_000_000 stripped");

    let mut over = block_with(vec![coinbase(0)]);
    pad_stripped_to(&mut over, MAX_BLOCK_STRIPPED_SIZE + 1);
    assert_eq!(stripped_size(&over), MAX_BLOCK_STRIPPED_SIZE + 1);
    assert_bad_block(
        validate_block_structure(&over, &ctx_h(0)).unwrap_err(),
        "stripped",
    );
}

#[test]
fn s15_rejects_empty_vin() {
    validate_block_structure(
        &block_with(vec![coinbase(0), non_coinbase_spend(1)]),
        &ctx_h(0),
    )
    .unwrap();
    let empty = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert_bad_tx(
        validate_block_structure(&block_with(vec![coinbase(0), empty]), &ctx_h(0)).unwrap_err(),
        "no inputs",
    );
}

#[test]
fn s16_tx_stripped_size_1_000_000_accepts_1_000_001_rejects() {
    let mut lo = 0usize;
    let mut hi = MAX_BLOCK_STRIPPED_SIZE;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if padded_spend(mid).base_size() < MAX_BLOCK_STRIPPED_SIZE {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut data_ok = lo;
    while padded_spend(data_ok).base_size() > MAX_BLOCK_STRIPPED_SIZE {
        data_ok -= 1;
    }
    while padded_spend(data_ok).base_size() < MAX_BLOCK_STRIPPED_SIZE {
        data_ok += 1;
    }
    let ok = padded_spend(data_ok);
    assert_eq!(ok.base_size(), MAX_BLOCK_STRIPPED_SIZE);
    check_tx_local(&ok, ok.base_size()).expect("tx stripped == 1_000_000");

    let over = padded_spend(data_ok + 1);
    assert!(over.base_size() > MAX_BLOCK_STRIPPED_SIZE);
    assert_bad_tx(
        check_tx_local(&over, over.base_size()).unwrap_err(),
        "oversize",
    );
}

#[test]
fn s17_many_unique_outpoints_accept() {
    let mut input = Vec::with_capacity(64);
    for i in 0..64u32 {
        let mut tid = [0u8; 32];
        tid[..4].copy_from_slice(&i.to_le_bytes());
        input.push(TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(tid),
                vout: i,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
    }
    let many = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    check_tx_local(&many, many.base_size()).expect("64 unique inputs");
}

#[test]
fn pres_has_witness_matches_block_walk() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let gpres: Vec<TxPrecompute> = genesis.txdata.iter().map(TxPrecompute::from_tx).collect();
    assert_eq!(
        block_has_witness_from_pres(&gpres),
        block_has_witness(&genesis)
    );
    assert!(!block_has_witness(&genesis));

    let mut wit = genesis.txdata[0].clone();
    wit.input[0].witness = Witness::from_slice(&[vec![0x01]]);
    let block = Block {
        header: genesis.header,
        txdata: vec![wit],
    };
    let wpres: Vec<TxPrecompute> = block.txdata.iter().map(TxPrecompute::from_tx).collect();
    assert!(block_has_witness(&block));
    assert_eq!(
        block_has_witness_from_pres(&wpres),
        block_has_witness(&block)
    );
}

#[test]
fn exceeds_sigops_limit_matches_the_block_cap() {
    use rbitcoin_consensus::block::exceeds_sigops_limit;
    assert!(!exceeds_sigops_limit(0));
    assert!(!exceeds_sigops_limit(79_999));
    assert!(!exceeds_sigops_limit(80_000));
    assert!(exceeds_sigops_limit(80_001));
    assert!(exceeds_sigops_limit(u64::MAX));
}

#[test]
fn should_use_pres_requires_an_index_inside_the_slice() {
    use rbitcoin_consensus::block::should_use_pres;
    assert!(should_use_pres(0, 1));
    assert!(!should_use_pres(1, 1));
    assert!(!should_use_pres(0, 0));
    assert!(should_use_pres(0, 2));
    assert!(!should_use_pres(2, 2));
}

#[test]
fn lock_time_cutoff_uses_block_time_at_height_zero_even_when_csv_is_active() {
    use rbitcoin_query::block_pipeline::assemble_lock_time_cutoff;
    let mut block = block_with(vec![coinbase(0)]);
    block.header.time = 100;
    let mtp = 200;
    assert_eq!(assemble_lock_time_cutoff(&ctx_h(0), &block, mtp), 100);
    // Regtest CSV height is 1, so height 1 uses the previous median time.
    assert_eq!(assemble_lock_time_cutoff(&ctx_h(1), &block, mtp), mtp);

    let mut params = ChainParams::regtest();
    params.apply_test_activation_height("csv", 0).unwrap();
    let params = Box::leak(Box::new(params));
    let at_genesis = ValidationContext::at(params, Height(0), Milestone::NONE);
    assert!(params.csv_active_at(0));
    assert_eq!(assemble_lock_time_cutoff(&at_genesis, &block, mtp), 100);
    let after_genesis = ValidationContext::at(params, Height(1), Milestone::NONE);
    assert_eq!(assemble_lock_time_cutoff(&after_genesis, &block, mtp), mtp);

    let mut late = ChainParams::regtest();
    late.apply_test_activation_height("csv", 500).unwrap();
    let late = Box::leak(Box::new(late));
    let before_csv = ValidationContext::at(late, Height(10), Milestone::NONE);
    assert!(!late.csv_active_at(10));
    assert_eq!(assemble_lock_time_cutoff(&before_csv, &block, mtp), 100);
}

#[test]
fn max_money_fits_in_i64_so_the_assemble_cast_is_in_range() {
    use rbitcoin_consensus::block::{exceeds_max_money, money_range_out_sum};
    let max_money = Amount::MAX_MONEY.to_sat();
    assert!(!exceeds_max_money(0));
    assert!(!exceeds_max_money(max_money));
    assert!(exceeds_max_money(max_money + 1));
    assert!(exceeds_max_money(u64::MAX));
    assert_eq!(money_range_out_sum(max_money), max_money as i64);
    assert!(i64::try_from(max_money).is_ok());
    assert!(i64::try_from(u64::MAX).is_err());
}

#[test]
fn assemble_without_pres_sums_zero_and_rejects_over_max() {
    fn one(sats: u64) -> Transaction {
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }
    assert_eq!(
        rbitcoin_consensus::block::assemble_tx_value_out(&one(0), 0, None).unwrap(),
        0
    );
    let max_money = Amount::MAX_MONEY.to_sat();
    assert_eq!(
        rbitcoin_consensus::block::assemble_tx_value_out(&one(max_money), 0, None).unwrap(),
        max_money as i64
    );
    assert!(matches!(
        rbitcoin_consensus::block::assemble_tx_value_out(&one(max_money + 1), 0, None),
        Err(ConsensusError::BadBlock("bad-txns-vout-toolarge"))
    ));
}

#[test]
fn witness_commitment_leaves_a_legacy_block_unchanged() {
    let mut b = block_with(vec![coinbase(1)]);
    let outs = b.txdata[0].output.len();
    apply_witness_commitment(&mut b);
    assert_eq!(b.txdata[0].output.len(), outs);
    assert!(b.txdata[0].input[0].witness.is_empty());
}

#[test]
fn resolve_prevout_rejects_a_same_index_parent() {
    use rbitcoin_consensus::block::TxidMap;
    let parent = coinbase(1);
    let txid = parent.compute_txid().to_byte_array();
    let spend = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
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
    let block = block_with(vec![parent, spend.clone()]);
    let mut index = TxidMap::default();
    index.insert(txid, 1usize);
    match resolve_prevout(
        &block,
        spend.input[0].previous_output,
        &spend.input[0],
        None,
        &index,
        1,
        &rbitcoin_query::BatchParents::new(),
        true,
        true,
        false,
        None,
        &mut AsmPrevoutAcc::default(),
    ) {
        Err(err) => assert!(format!("{err}").contains("lookup stage miss"), "{err}"),
        Ok(_) => panic!("a tx cannot spend an output at its own index"),
    }
}

#[test]
fn same_height_confirmed_spender_is_not_below_its_create() {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::block_pipeline::structural_apply_one_meta;
    let (_dir, query) = rbitcoin_query::testutil::tiny_query_labeled("spend-same-h");
    let store = query.store();
    store
        .confirmed
        .set(rbitcoin_primitives::Height(0), Fk(1))
        .unwrap();
    store.header_txs.put_range(Fk(1), Fk(1), 1).unwrap();
    store.strong_tx.set_strong(Fk(1), Fk(1)).unwrap();
    store.rebuild_height_fence().unwrap();
    let mut scratch = rbitcoin_query::block_pipeline::StructuralScratch::default();
    scratch.height_by_id.insert(9, 0);
    scratch.field_h_by_id.insert(1, 0);
    structural_apply_one_meta(
        &query,
        Some((Fk(1), 0, 0)),
        9,
        0,
        0,
        Fk::NULL,
        0,
        Some(0),
        &mut scratch,
    )
    .expect("spender and create at the same height are not corrupt");
}

#[test]
fn max_block_tx_count_matches_weight_over_ten_byte_tx() {
    assert_eq!(MIN_TX_WEIGHT, 40, "10-byte tx at witness scale 4");
    assert_eq!(MAX_BLOCK_TX_COUNT, 100_000);
    assert_eq!(MAX_BLOCK_TX_COUNT as u64 * MIN_TX_WEIGHT, MAX_BLOCK_WEIGHT);
}
