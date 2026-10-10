//! Confirm_run unit tests (peeled from confirm_run.rs).

use super::{
    confirm_archive_kind, write_batch_vs_tip, write_height_needed, ConfirmArchiveKind,
    WriteBatchVsTip,
};
use rbitcoin_query::testutil::FixtureChain;

fn tmp_query() -> (rbitcoin_query::testutil::TempDir, rbitcoin_query::Query) {
    rbitcoin_query::testutil::tiny_query_labeled("write-idemp")
}

#[test]
fn tx_head_drain_thread_is_named_and_reused() {
    use super::{submit_head_drain, HEAD_DRAIN_THREAD_NAME};
    let (r1, id1, n1) = submit_head_drain(|| Ok(1)).join_named();
    let (r2, id2, n2) = submit_head_drain(|| Ok(2)).join_named();
    assert_eq!(r1.unwrap(), 1);
    assert_eq!(r2.unwrap(), 2);
    assert_eq!(n1, HEAD_DRAIN_THREAD_NAME);
    assert_eq!(n2, HEAD_DRAIN_THREAD_NAME);
    assert_eq!(id1, id2, "drain must keep one OS thread across batches");
}

#[test]
fn head_insert_join_restore_empty_ok() {
    use super::submit_head_insert;
    let (_d, q) = tmp_query();
    let (r, queued) = submit_head_insert(q.store(), Vec::new()).join_restore();
    assert_eq!(r.unwrap(), 0);
    assert!(queued.is_empty());
}

/// Batch append: contiguous heights merge; gap returns Err(other).
#[allow(clippy::cognitive_complexity)] // one fixture, many error arms
#[test]
fn script_ok_append_contiguous_and_gap() {
    use super::{Prepared, ScriptOkBatch};
    use bitcoin::CompactTarget;
    use rbitcoin_primitives::{Fk, Height};
    use std::sync::Arc;

    fn empty_prepared(h: u32, hash_byte: u8) -> Prepared {
        Prepared {
            height: Height(h),
            header_fk: Fk(h as u64),
            tx_fks: vec![],
            jobs: vec![],
            spends: vec![],
            fees: 0,
            check_scripts: false,
            time: 0,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            hash: [hash_byte; 32],
            prev_mtp: 0,
        }
    }
    fn batch_one(h: u32) -> ScriptOkBatch {
        ScriptOkBatch {
            prepared: vec![empty_prepared(h, h as u8)],
            wire_blocks: vec![Arc::new(crate::params::genesis_block(
                &crate::params::ChainParams::regtest(),
            ))],
            batch_parents: rbitcoin_query::BatchParents::new(),
            archive_plan: None,
            index_seal: super::index::IndexSeal::default(),
        }
    }
    let mut a = batch_one(10);
    let b = batch_one(11);
    assert!(a.append_contiguous(b).is_ok());
    assert_eq!(a.len(), 2);
    let gap = batch_one(13);
    let err = a.append_contiguous(gap).expect_err("gap");
    assert_eq!(err.len(), 1);
    assert_eq!(a.len(), 2);
    // Contiguous continue after gap reject.
    let c = batch_one(12);
    assert!(a.append_contiguous(c).is_ok());
    assert_eq!(a.len(), 3);

    // Empty other is no-op.
    assert!(a
        .append_contiguous(ScriptOkBatch {
            prepared: vec![],
            wire_blocks: vec![],
            batch_parents: rbitcoin_query::BatchParents::new(),
            archive_plan: None,
            index_seal: super::index::IndexSeal::default(),
        })
        .is_ok());
    assert_eq!(a.len(), 3);

    // Empty self absorbs other.
    let mut empty = ScriptOkBatch {
        prepared: vec![],
        wire_blocks: vec![],
        batch_parents: rbitcoin_query::BatchParents::new(),
        archive_plan: None,
        index_seal: super::index::IndexSeal::default(),
    };
    assert!(empty.append_contiguous(batch_one(50)).is_ok());
    assert_eq!(empty.len(), 1);
    assert_eq!(empty.heights_hashes()[0].0, 50);
    assert!(!empty.is_empty());
    assert!(empty.approx_wire_bytes() > 0);
    assert_eq!(empty.parent_count(), 0);

    // Wire/prepared length mismatch on contiguous height → Err(other).
    let mut good = batch_one(60);
    let mut bad = batch_one(61);
    bad.wire_blocks.clear();
    let err = good.append_contiguous(bad).expect_err("len mismatch");
    assert_eq!(err.len(), 1);

    // archive_plan merge: Some+Some concatenates; mixed polarity is leftover.
    let mut with_plan = batch_one(70);
    with_plan.archive_plan = Some(rbitcoin_query::ArchiveWritePlan::empty());
    let mut next = batch_one(71);
    next.archive_plan = Some(rbitcoin_query::ArchiveWritePlan::empty());
    assert!(with_plan.append_contiguous(next).is_ok());
    assert!(with_plan.archive_plan.is_some());
    let mut only_other = batch_one(72);
    only_other.archive_plan = None;
    let err = with_plan
        .append_contiguous(only_other)
        .expect_err("Some+None polarity");
    assert_eq!(err.len(), 1);
    assert_eq!(with_plan.len(), 2);
    assert!(with_plan.archive_plan.is_some());
    let mut no_plan = batch_one(80);
    let mut has = batch_one(81);
    has.archive_plan = Some(rbitcoin_query::ArchiveWritePlan::empty());
    let err = no_plan
        .append_contiguous(has)
        .expect_err("None+Some polarity");
    assert_eq!(err.len(), 1);
    assert_eq!(no_plan.len(), 1);
    assert!(no_plan.archive_plan.is_none());
    let n2 = batch_one(81);
    assert!(no_plan.append_contiguous(n2).is_ok());
    assert_eq!(no_plan.len(), 2);
    assert!(no_plan.archive_plan.is_none());
}

/// Write vs tip is all-old (no-op), all-new (proceed), or spans tip (Corrupt).
/// External three-stage path: rbitcoin-test three_stage_confirm_and_parent_pin_surface.
#[test]
fn three_stage_write_filter_and_scripts_surface() {
    let tip = Some(100u32);
    assert_eq!(
        write_batch_vs_tip(tip, [98u32, 99, 100, 101, 102]),
        WriteBatchVsTip::SpansTip
    );
    assert_eq!(
        write_batch_vs_tip(tip, [98u32, 99, 100]),
        WriteBatchVsTip::AllOld
    );
    assert_eq!(
        write_batch_vs_tip(tip, [101u32, 102]),
        WriteBatchVsTip::AllNew
    );
    assert_eq!(
        write_batch_vs_tip(tip, std::iter::empty()),
        WriteBatchVsTip::AllOld
    );
    assert!(!write_height_needed(tip, 100));
    assert!(!write_height_needed(Some(0), 0));
    assert!(write_height_needed(Some(0), 1));
    assert!(write_height_needed(None, 0));
    assert!(write_height_needed(None, 1));

    use super::{confirm_scripts_phase, LoadedBatch, ScriptPreverified};
    let batch = LoadedBatch {
        prepared: Vec::new(),
        wire_blocks: Vec::new(),
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: ScriptPreverified::new(),
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    };
    assert!(batch.is_empty());
    assert_eq!(batch.approx_wire_bytes(), 0);
    assert_eq!(batch.parent_count(), 0);
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut metered = LoadedBatch {
        prepared: Vec::new(),
        wire_blocks: vec![std::sync::Arc::new(genesis)],
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: ScriptPreverified::new(),
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    };
    assert!(metered.approx_wire_bytes() > 0);
    let mut txid = [0u8; 32];
    txid[0] = 1;
    metered.batch_parents.insert_owned(
        rbitcoin_primitives::Fk(1),
        rbitcoin_store::TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: rbitcoin_primitives::Fk::NULL,
            input_count: 0,
            output_start_fk: rbitcoin_primitives::Fk::NULL,
            output_count: 1,
        },
        vec![(0, rbitcoin_store::OutputRecord::unspent(1, vec![0x51]))],
        vec![0],
        Some(false),
        None,
        vec![],
    );
    assert_eq!(metered.parent_count(), 1);
    let script_ok = super::ScriptOkBatch {
        prepared: Vec::new(),
        wire_blocks: Vec::new(),
        batch_parents: metered.batch_parents,
        archive_plan: None,
        index_seal: super::index::IndexSeal::default(),
    };
    assert_eq!(script_ok.parent_count(), 1);
    let cur = std::thread::current();
    let name = cur.name().unwrap_or("").to_string();
    assert!(
        !name.starts_with("rbtc-scripts"),
        "confirm_scripts_phase must run on the caller, got {name}"
    );
    let ok = confirm_scripts_phase(batch).expect("empty scripts ok");
    assert!(ok.batch.prepared.is_empty());
    assert!(ok.batch.wire_blocks.is_empty());
}

#[test]
fn confirm_archive_kind_refuses_mixed() {
    assert_eq!(
        confirm_archive_kind(3, 0).unwrap(),
        ConfirmArchiveKind::AllHaveBody
    );
    assert_eq!(
        confirm_archive_kind(3, 3).unwrap(),
        ConfirmArchiveKind::AllNeedBody
    );
    assert_eq!(
        confirm_archive_kind(1, 0).unwrap(),
        ConfirmArchiveKind::AllHaveBody
    );
    assert_eq!(
        confirm_archive_kind(1, 1).unwrap(),
        ConfirmArchiveKind::AllNeedBody
    );
    let err = confirm_archive_kind(3, 2).unwrap_err();
    match err {
        crate::error::ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(m)) => {
            assert_eq!(m, "invariant: confirm batch mixed archived");
        }
        other => panic!("expected mixed archived, got {other:?}"),
    }
    assert!(confirm_archive_kind(2, 1).is_err());
    assert!(confirm_archive_kind(2, 3).is_err());
}

fn empty_loaded_batch() -> super::LoadedBatch {
    super::LoadedBatch {
        prepared: Vec::new(),
        wire_blocks: Vec::new(),
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: super::ScriptPreverified::new(),
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    }
}

fn linux_thread_comms() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    dir.filter_map(|e| {
        let p = e.ok()?.path().join("comm");
        std::fs::read_to_string(p).ok()
    })
    .map(|s| s.trim().to_string())
    .collect()
}

/// IBD `drive_script_waves_with` writes in input order and never starts
/// `rbtc-script-coord-*` threads.
#[test]
fn drive_script_waves_ordered_without_coordinator_threads() {
    use super::scripts::drive_script_waves_with;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, rx) = mpsc::sync_channel(4);
    let heights = Arc::new(Mutex::new(Vec::new()));
    let heights_w = Arc::clone(&heights);
    let stage = thread::Builder::new()
        .name("ibd-confirm".into())
        .spawn(move || {
            drive_script_waves_with(
                &rx,
                |_, _| {},
                |ok, meta| {
                    let cur = thread::current();
                    let name = cur.name().unwrap_or("").to_string();
                    assert!(
                        !name.starts_with("rbtc-scripts"),
                        "script publisher must not be a steal worker, got {name}"
                    );
                    heights_w.lock().unwrap().push(meta.first_h);
                    assert!(ok.batch.is_empty());
                    true
                },
                |_e, _meta, _dropped| false,
                || false,
            );
        })
        .expect("spawn publisher");
    for _ in 0..3 {
        tx.send((empty_loaded_batch(), 0)).expect("send");
    }
    drop(tx);
    crate::unpark_script_publisher();
    stage.join().expect("publisher");
    assert_eq!(heights.lock().unwrap().len(), 3);
    for comm in linux_thread_comms() {
        assert!(
            !comm.starts_with("rbtc-script-coord"),
            "coordinator thread still live: {comm}"
        );
    }
}

fn prepared_at(
    height: u32,
    hash: [u8; 32],
    jobs: Vec<crate::block::ScriptCheckJob>,
    check_scripts: bool,
) -> super::Prepared {
    use bitcoin::CompactTarget;
    use rbitcoin_primitives::{Fk, Height};
    super::Prepared {
        height: Height(height),
        header_fk: Fk(1),
        tx_fks: Vec::new(),
        jobs,
        spends: Vec::new(),
        fees: 0,
        check_scripts,
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        hash,
        prev_mtp: 0,
    }
}

fn loaded_at(
    height: u32,
    hash: [u8; 32],
    jobs: Vec<crate::block::ScriptCheckJob>,
    check_scripts: bool,
) -> super::LoadedBatch {
    super::LoadedBatch {
        prepared: vec![prepared_at(height, hash, jobs, check_scripts)],
        wire_blocks: Vec::new(),
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: super::ScriptPreverified::new(),
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    }
}

fn bad_p2pkh_job() -> crate::block::ScriptCheckJob {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let prevouts = vec![TxOut {
        value: Amount::from_sat(50_0000_0000),
        script_pubkey: ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
            0xac,
        ]),
    }];
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([9; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let tid = tx.compute_txid().to_byte_array();
    crate::block::ScriptCheckJob::with_txid(
        tid,
        prevouts,
        tx,
        crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
    )
}

/// One-job inline fail keeps the batch height/hash; a later batch still writes.
#[test]
fn drive_script_waves_start_fail_keeps_meta_and_continues() {
    use super::scripts::drive_script_waves_with;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, rx) = mpsc::sync_channel(4);
    let oks = Arc::new(Mutex::new(Vec::new()));
    let errs = Arc::new(Mutex::new(Vec::new()));
    let oks_w = Arc::clone(&oks);
    let errs_w = Arc::clone(&errs);
    let stage = thread::spawn(move || {
        drive_script_waves_with(
            &rx,
            |_, _| {},
            |ok, meta| {
                oks_w.lock().unwrap().push(meta.first_h);
                assert!(ok.batch.prepared.len() == 1);
                true
            },
            |e, meta, dropped| {
                assert!(dropped.is_empty());
                errs_w.lock().unwrap().push((
                    meta.first_h,
                    meta.heights_hashes.clone(),
                    format!("{e}"),
                ));
                true
            },
            || false,
        );
    });
    tx.send((loaded_at(10, [10u8; 32], vec![bad_p2pkh_job()], true), 0))
        .expect("send bad");
    tx.send((loaded_at(20, [20u8; 32], Vec::new(), true), 0))
        .expect("send ok");
    drop(tx);
    crate::unpark_script_publisher();
    stage.join().expect("publisher");
    let errs = errs.lock().unwrap();
    assert_eq!(errs.len(), 1, "one reject");
    assert_eq!(errs[0].0, 10);
    assert_eq!(errs[0].1, vec![(10, [10u8; 32])]);
    assert_ne!(errs[0].1[0].1, [0u8; 32]);
    let oks = oks.lock().unwrap();
    assert_eq!(&*oks, &[20], "later batch still written");
}

/// `should_stop` at loop top must not block on recv.
#[test]
fn drive_script_waves_should_stop_skips_recv() {
    use super::scripts::drive_script_waves_with;
    use std::sync::mpsc;
    let (_tx, rx) = mpsc::sync_channel::<(super::LoadedBatch, u64)>(1);
    drive_script_waves_with(&rx, |_, _| {}, |_, _| true, |_, _, _| true, || true);
}

/// Drained job vecs must drop capacity before write handoff.
#[test]
fn script_jobs_shrink_after_take() {
    use super::confirm_scripts_phase;
    let mut jobs = Vec::with_capacity(32);
    jobs.push(bad_p2pkh_job());
    assert!(jobs.capacity() >= 32);
    let batch = loaded_at(7, [7u8; 32], jobs, false);
    let ok = confirm_scripts_phase(batch).expect("skip scripts");
    assert_eq!(ok.batch.prepared[0].jobs.capacity(), 0);
}

/// Trailing null `confirmed[]` + reopen must still connect real tip+1
/// (`NotFound` was the inflated-HWM miss on a valid body).
#[test]
fn tip_plus_one_after_trailing_null_heal_is_not_notfound() {
    use crate::accept_and_connect_block;
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use crate::regtest_pad::{mine_empty_regtest, pad_empty_from};
    use rbitcoin_primitives::Height;
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (tip, tip_time, _) = pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        3,
        0,
    );
    drop(q);

    let conf = path.join("confirmed.body");
    let mut raw = std::fs::read(&conf).unwrap();
    assert!(raw.len() >= 16);
    let logical = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    let extra = [0u8; 20 * 8];
    let new_logical = logical + extra.len() as u64;
    if (raw.len() as u64) < new_logical {
        raw.resize(new_logical as usize, 0);
    }
    raw[8..16].copy_from_slice(&new_logical.to_le_bytes());
    std::fs::write(&conf, &raw).unwrap();

    let q = rbitcoin_query::Query::open_or_create_tiny(&path).unwrap();
    assert_eq!(q.tip_height().map(|h| h.0), Some(3));
    let nxt = mine_empty_regtest(tip, tip_time + 600, 4);
    let r = accept_and_connect_block(&q, &params, Height(4), &nxt, Milestone::NONE);
    match r {
        Ok(_) => {}
        Err(e) => {
            let s = e.to_string();
            assert!(
                !s.to_ascii_lowercase().contains("not found"),
                "valid tip+1 must not be Store NotFound: {e}"
            );
            panic!("tip+1 confirm failed: {e}");
        }
    }
    assert_eq!(q.tip_height().map(|h| h.0), Some(4));
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn expected_bits_extending_height0_and_no_retarget() {
    use super::expected_bits_extending;
    use crate::params::ChainParams;
    use bitcoin::CompactTarget;
    use rbitcoin_primitives::Height;
    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let gbits = expected_bits_extending(
        &q,
        &params,
        Height(0),
        CompactTarget::from_consensus(0),
        0,
        0,
    )
    .unwrap();
    assert_eq!(gbits, crate::params::genesis_block(&params).header.bits);
    // No-pow-retargeting: any height returns prev_bits.
    let prev = CompactTarget::from_consensus(0x207f_ffff);
    let b = expected_bits_extending(&q, &params, Height(2016), prev, 100, 0).unwrap();
    assert_eq!(b, prev);

    // ScriptOkBatch empty surfaces (mirror LoadedBatch).
    use super::{confirm_scripts_phase, LoadedBatch, ScriptPreverified};
    let loaded = LoadedBatch {
        prepared: Vec::new(),
        wire_blocks: Vec::new(),
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: ScriptPreverified::new(),
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    };
    let ok = confirm_scripts_phase(loaded).unwrap();
    assert!(ok.batch.is_empty());
    assert_eq!(ok.batch.len(), 0);
    assert!(ok.batch.heights_hashes().is_empty());
    assert_eq!(ok.batch.approx_wire_bytes(), 0);
    assert_eq!(ok.batch.parent_count(), 0);

    // check_bip34 wrong encoding
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{
        Amount, Block, BlockHash, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
        Witness,
    };
    let cb = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x99]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0; 32]),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![cb],
    };
    assert!(crate::block::check_bip34_coinbase(&block.txdata[0], 17).is_err());

    let _ = std::fs::remove_dir_all(&path);
}

/// Multi-block tip-ahead assemble (i>0) calls [`expected_bits_extending`] on a
/// retarget height. Period-start (`height − interval`) may still be **above**
/// confirmed tip while already present as a ConfirmParentCache header plan
/// (put when that height was looked up/loaded earlier).
///
/// Mainnet log 2026-08-07: batch @132992 n=92 includes retarget 133056;
/// first=131040; tip still ~129k → confirmed miss → "missing retarget first
/// header" even though the plan cache should hold 131040.
///
/// Ship path must resolve period-start via confirmed **or** header plan.
#[test]
fn expected_bits_extending_uses_header_plan_when_period_start_above_tip() {
    use super::expected_bits_extending;
    use crate::params::ChainParams;
    use bitcoin::CompactTarget;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_store::HeaderRecord;
    let (path, q) = tmp_query();
    let params = ChainParams::mainnet();
    let interval = params.difficulty_adjustment_interval();
    assert_eq!(interval, 2016, "mainnet difficulty interval");

    // Tip empty / genesis not required: period-start 2016 is above tip (None).
    assert!(
        q.header_at_height(Height(2016)).unwrap().is_none(),
        "period-start must not be on confirmed[]"
    );

    // Simulate earlier tip-ahead lookup/load that put the period-start plan.
    let mut hash_first = [0u8; 32];
    hash_first[0..4].copy_from_slice(&2016u32.to_le_bytes());
    hash_first[4] = 0xaa;
    let first_rec = HeaderRecord {
        prev_fk: Fk::NULL,
        version: 1,
        timestamp: 1_234_567,
        bits: 0x1d00ffff,
        nonce: 2016,
        merkle_root: hash_first,
        hash: hash_first,
        size: 0,
        weight: 0,
    };
    let first_fk = q.store().put_header(&first_rec).unwrap();
    q.confirm_parent_cache().put_header_plan(
        2016,
        first_fk,
        first_rec.clone(),
        Vec::new(),
        [0u8; 32],
    );
    assert!(
        q.confirm_parent_cache().get_header_plan(2016).is_some(),
        "plan cache holds period-start (as real put_header_plan during load does)"
    );

    // Mid-batch path: prev bits/time come from prior prepared block in RAM;
    // only period-start is resolved from store/plan.
    let prev_bits = CompactTarget::from_consensus(0x1d00ffff);
    let prev_time = first_rec.timestamp.saturating_add(2015 * 600);
    let retarget_h = Height(4032); // 2 * interval — needs first @ 2016
    assert_eq!(retarget_h.0 % interval, 0);

    let got = expected_bits_extending(&q, &params, retarget_h, prev_bits, prev_time, prev_time)
        .expect(
            "period-start on ConfirmParentCache must satisfy retarget bits \
             (tip-ahead multi-block); confirmed-only lookup is the mainnet bug",
        );
    // Sanity: result is a real CompactTarget (same construction as production).
    let timespan = prev_time.saturating_sub(first_rec.timestamp) as u64;
    let expect = CompactTarget::from_next_work_required(prev_bits, timespan, &params.btc);
    assert_eq!(got, expect);

    let _ = std::fs::remove_dir_all(&path);
}

/// Mempool-preverified txids skip script_wave verify (tip follow).
#[test]
fn script_wave_skips_preverified_txids() {
    use super::{confirm_scripts_phase, LoadedBatch, Prepared, ScriptPreverified};
    use crate::block::ScriptCheckJob;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::{Fk, Height};

    let prevouts = vec![TxOut {
        value: Amount::from_sat(50_0000_0000),
        // P2PKH-shaped (not anyone-can-spend) so job_needs_script_check is true
        // if we did not skip — invalid empty script_sig would fail without skip.
        script_pubkey: ScriptBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
            0xac,
        ]),
    }];
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([9; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let tid = tx.compute_txid().to_byte_array();
    let mut pre = ScriptPreverified::new();
    pre.insert(tid);

    let job = ScriptCheckJob::with_txid(
        tid,
        prevouts,
        tx,
        crate::block::ScriptVerifyFlags::buried(true, true, true, true, true),
    );
    let prepared = Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(1)],
        jobs: vec![job],
        spends: vec![],
        fees: 0,
        check_scripts: true,
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        hash: [1u8; 32],
        prev_mtp: 0,
    };
    let batch = LoadedBatch {
        prepared: vec![prepared],
        wire_blocks: vec![],
        batch_parents: rbitcoin_query::BatchParents::new(),
        script_preverified: pre,
        archive_plan: None,
        index_want: super::index::IndexWant::default(),
        stats: std::sync::Arc::new(rbitcoin_query::ConfirmStats::default()),
    };
    confirm_scripts_phase(batch).expect("preverified skip avoids bad script fail");
}

fn tiny_query() -> (rbitcoin_query::testutil::TempDir, rbitcoin_query::Query) {
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();
    (path, q)
}

fn fill_edges_from_packed(plan: &mut rbitcoin_query::ArchiveWritePlan) {
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::SpendEdge;
    if !plan.edges.is_empty() {
        return;
    }
    for ((_, ins), fk) in plan.packed.iter().zip(plan.planned_fks.iter()) {
        let Some(sid) = fk.get() else { continue };
        let mut edges = Vec::with_capacity(ins.len());
        for (vin, inp) in ins.iter().enumerate() {
            let vin = vin as u32;
            if inp.is_coinbase() || inp.prev_index == u32::MAX {
                edges.push(SpendEdge {
                    prev_txid: [0u8; 32],
                    vout: u32::MAX,
                    spend_fk: *fk,
                    create_fk: Fk::NULL,
                    vin,
                });
            } else {
                edges.push(SpendEdge {
                    prev_txid: inp.prev_txid,
                    vout: inp.prev_index,
                    spend_fk: *fk,
                    create_fk: inp.create_fk,
                    vin,
                });
            }
        }
        plan.edges.insert(sid, edges);
    }
}

fn rec_tx(b: u8, n_out: u32) -> rbitcoin_store::TxRecord {
    use rbitcoin_primitives::Fk;
    rbitcoin_store::TxRecord {
        txid: [b; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: n_out,
    }
}

/// One store: pin/ensure error strings + denserels/abs + freeze + same-batch.
#[test]
fn pin_and_ensure_journey() {
    use super::{
        ensure_spend_abs_layouts, pin_for_wire_batch, post_commit, ParentPinStamp, Prepared,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{ArchiveWritePlan, BatchParents};
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (path, q) = tiny_query();

    let missing_parent = Fk(999_999);
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0xAA, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        vec![InputRecord {
            prev_txid: [0xBB; 32],
            create_fk: missing_parent,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    plan.planned_fks = vec![Fk(1)];
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let err = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect_err("missing parent must hard-fail pin");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("wire pin") || msg.contains("lookup stage miss")),
        "unexpected err: {msg}"
    );

    let prepared_miss = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(10)],
        jobs: vec![],
        spends: vec![([9u8; 32], 0, Fk(10), Fk(999_999), 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [3u8; 32],
        prev_mtp: 0,
    }];
    let bp = BatchParents::new();
    q.store().reset_spent_range_batch();
    let err = ensure_spend_abs_layouts(&bp, &prepared_miss)
        .expect_err("ensure must hard-fail without denserels");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("ensure denserels") || msg.contains("abs incomplete")),
        "unexpected err: {msg}"
    );
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "ensure must not pread create.loc"
    );

    post_commit(&q, &crate::block::AnnotateSlots::default())
        .expect("empty annotate list does not consult BatchParents");

    let parent_tx = rec_tx(0x11, 1);
    let parent_outs = vec![OutputRecord::unspent(50, vec![0x51])];
    let parent_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let pfk = q
        .store()
        .put_tx_full_batch_indexed(
            &[(parent_tx.clone(), parent_ins, parent_outs.clone())],
            true,
        )
        .unwrap()[0];
    let range = q.store().tx_body_range(pfk).unwrap();
    let (spent_off, spent_len) = q.store().tx_spent_range(pfk).unwrap();
    let parent_id = pfk.get().unwrap();

    let spend_ins = vec![InputRecord {
        prev_txid: parent_tx.txid,
        create_fk: pfk,
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0x22, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins.clone(),
    )];
    plan.planned_fks = vec![Fk(2)];
    plan.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent::with_loc(parent_tx.txid, range, (spent_off, spent_len), 1),
    );
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect("pin via stamped range");
    assert!(parents.contains(pfk));
    assert!(parents.get_parent_out(pfk, 0).is_some());
    plan.freeze_after_pin();
    assert!(
        plan.external_parents.is_empty(),
        "post-pin plan must not carry stamp staging"
    );

    let mut plan2 = ArchiveWritePlan::empty();
    plan2.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0x22, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins.clone(),
    )];
    plan2.planned_fks = vec![Fk(2)];
    plan2.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent::with_body(parent_tx.txid, range),
    );
    let mut empty_stamp = ParentPinStamp::default();
    fill_edges_from_packed(&mut plan2);
    let err = pin_for_wire_batch(&q, Some(&plan2), &mut empty_stamp, &[], &[], None)
        .expect_err("plan maps must not backfill an empty stamp");
    assert!(err.to_string().contains("lookup stage miss"), "got: {err}");

    let mut bp = BatchParents::new();
    bp.insert_owned(
        pfk,
        parent_tx.clone(),
        vec![(0, parent_outs[0].clone())],
        vec![0],
        Some(true),
        None,
        Vec::new(),
    );
    assert!(!bp.has_abs_layout(pfk));
    let prepared = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(2)],
        jobs: vec![],
        spends: vec![([0x11u8; 32], 0, Fk(2), pfk, 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [4u8; 32],
        prev_mtp: 0,
    }];
    q.store().reset_spent_range_batch();
    let err = ensure_spend_abs_layouts(&bp, &prepared)
        .expect_err("pinned hole without lookup stamp is Corrupt");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("ensure denserels") || msg.contains("abs incomplete")),
        "unexpected err: {msg}"
    );
    let pinned_spent: Vec<u64> = q
        .store()
        .spent_range_batch_fks()
        .into_iter()
        .filter(|&id| id == parent_id)
        .collect();
    assert_eq!(
        pinned_spent.len(),
        0,
        "ensure must not pread create.loc: {pinned_spent:?}"
    );

    let cold_tx = rec_tx(0x33, 1);
    let cold_outs = vec![OutputRecord::unspent(50, vec![0x51])];
    let cold_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x02], vec![])];
    let cfk = q
        .store()
        .put_tx_full_batch_indexed(&[(cold_tx.clone(), cold_ins, cold_outs)], true)
        .unwrap()[0];
    let cid = cfk.get().unwrap();
    let prepared_cold = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(3)],
        jobs: vec![],
        spends: vec![([0x33u8; 32], 0, Fk(3), cfk, 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [5u8; 32],
        prev_mtp: 0,
    }];
    let bp_cold = BatchParents::new();
    q.store().reset_spent_range_batch();
    let err = ensure_spend_abs_layouts(&bp_cold, &prepared_cold)
        .expect_err("unpinned leftover without lookup stamp is Corrupt");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("ensure denserels") || msg.contains("abs incomplete")),
        "unexpected err: {msg}"
    );
    let cold_spent: Vec<u64> = q
        .store()
        .spent_range_batch_fks()
        .into_iter()
        .filter(|&id| id == cid)
        .collect();
    assert_eq!(
        cold_spent.len(),
        0,
        "ensure must not pread create.loc: {cold_spent:?}"
    );

    let mut plan3 = ArchiveWritePlan::empty();
    plan3.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0x22, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins,
    )];
    plan3.planned_fks = vec![Fk(2)];
    plan3.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent {
            txid: parent_tx.txid,
            body: Some(range),
            spent: Some((spent_off, spent_len)),
            n_out: Some(1),
            pin: None,
        },
    );
    let mut stamp3 = ParentPinStamp::take_from_plan(&mut plan3);
    fill_edges_from_packed(&mut plan3);
    let (parents3, _) = pin_for_wire_batch(&q, Some(&plan3), &mut stamp3, &[], &[], None).unwrap();
    assert!(
        parents3.has_abs_layout(pfk),
        "load pin copies lookup-stamped spent range (no write idx)"
    );
    assert_eq!(
        parents3.get_spender_abs(pfk, 0),
        Some(rbitcoin_store::spent_abs(spent_off, 0))
    );
    q.store().reset_spent_range_batch();
    ensure_spend_abs_layouts(&parents3, &prepared).expect("ensure already-abs skip");
    assert!(parents3.has_abs_layout(pfk));
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "already-abs ensure must not pread create.loc"
    );

    let mut plan4 = ArchiveWritePlan::empty();
    plan4.packed = vec![
        (
            rbitcoin_query::CreatePinInner::records(
                rec_tx(0x32, 1),
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        ),
        (
            rbitcoin_query::CreatePinInner::records(
                rec_tx(0x33, 1),
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            vec![InputRecord {
                prev_txid: [0x32; 32],
                create_fk: Fk(2),
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
        ),
    ];
    plan4.planned_fks = vec![Fk(2), Fk(3)];
    let mut stamp4 = ParentPinStamp::take_from_plan(&mut plan4);
    fill_edges_from_packed(&mut plan4);
    let (parents4, _) = pin_for_wire_batch(&q, Some(&plan4), &mut stamp4, &[], &[], None).unwrap();
    assert!(
        !parents4.contains(Fk(2)),
        "same-header create is wire-valued, not pinned"
    );

    let ghost = Fk(42);
    let mut bp_ghost = BatchParents::new();
    bp_ghost.insert_owned(
        ghost,
        rec_tx(0x42, 1),
        vec![(0, OutputRecord::unspent(1, vec![0x51]))],
        vec![0],
        Some(true),
        None,
        Vec::new(),
    );
    assert!(bp_ghost.contains(ghost));
    assert!(!bp_ghost.has_abs_layout(ghost));
    let prepared_ghost = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(4)],
        jobs: vec![],
        spends: vec![([0x42u8; 32], 0, Fk(4), ghost, 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [6u8; 32],
        prev_mtp: 0,
    }];
    q.store().reset_spent_range_batch();
    let err = ensure_spend_abs_layouts(&bp_ghost, &prepared_ghost)
        .expect_err("pin without spent.idx cannot invent abs");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("ensure denserels") || msg.contains("abs incomplete")),
        "unexpected err: {msg}"
    );
    let ghost_spent: Vec<u64> = q
        .store()
        .spent_range_batch_fks()
        .into_iter()
        .filter(|&id| id == 42)
        .collect();
    assert_eq!(
        ghost_spent.len(),
        0,
        "ensure must not pread create.loc: {ghost_spent:?}"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Same-batch child spend: abs from append RAM loc + packed pin, no create.loc pread.
#[test]
fn fill_same_batch_abs_from_append_loc_ram() {
    use super::{ensure_spend_abs_layouts, fill_planned_create_layout_after_commit, Prepared};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x32, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let child_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x33, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let parent_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let child_ins = vec![InputRecord {
        prev_txid: [0x32; 32],
        create_fk: Fk(1),
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    q.store().reset_spent_range_batch();
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[
                (std::sync::Arc::clone(&parent_pin), parent_ins),
                (std::sync::Arc::clone(&child_pin), child_ins),
            ],
            false,
            &[],
        )
        .unwrap();
    assert_eq!(fks[0], Fk(1));
    assert_eq!(loc.len(), 2);
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "append must not pread create.loc"
    );
    assert_eq!(loc[0].txout, q.store().tx_body_range(fks[0]).unwrap());
    assert_eq!(loc[0].spent, q.store().tx_spent_range(fks[0]).unwrap());
    assert_eq!(loc[0].n_out, 1);
    q.store().reset_spent_range_batch();

    let prepared = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: fks.clone(),
        jobs: vec![],
        spends: vec![([0x32u8; 32], 0, fks[1], fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [7u8; 32],
        prev_mtp: 0,
    }];
    let mut bp = BatchParents::new();
    fill_planned_create_layout_after_commit(
        &q,
        &mut bp,
        &fks,
        &loc,
        &[std::sync::Arc::clone(&parent_pin), child_pin],
        &prepared,
    )
    .expect("same-batch fill from append RAM");
    assert!(bp.has_abs_layout(fks[0]));
    assert_eq!(
        bp.get_spender_abs(fks[0], 0),
        Some(rbitcoin_store::spent_abs(loc[0].spent.0, 0))
    );
    q.store().reset_spent_range_batch();
    ensure_spend_abs_layouts(&bp, &prepared).expect("same-batch abs after RAM fill");
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "write fill/ensure must not pread create.loc"
    );

    q.set_lookup_started_hi(Some(4));
    q.note_write_create_loc(&fks, &loc, 1);
    let mut bp_later = BatchParents::new();
    bp_later.insert_create_pin(
        fks[0],
        std::sync::Arc::clone(&parent_pin),
        vec![0],
        None,
        None,
        Vec::new(),
    );
    assert!(!bp_later.has_abs_layout(fks[0]));
    let later = [Prepared {
        height: Height(2),
        header_fk: Fk(2),
        tx_fks: vec![Fk(3)],
        jobs: vec![],
        spends: vec![([0x32u8; 32], 0, Fk(3), fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [8u8; 32],
        prev_mtp: 0,
    }];
    q.store().reset_spent_range_batch();
    fill_planned_create_layout_after_commit(&q, &mut bp_later, &[], &[], &[], &later)
        .expect("just-written fill from write loc RAM");
    assert!(bp_later.has_abs_layout(fks[0]));
    assert_eq!(
        bp_later.get_spender_abs(fks[0], 0),
        Some(rbitcoin_store::spent_abs(loc[0].spent.0, 0))
    );
    q.prune_write_create_loc(3);
    assert!(
        q.write_create_loc(fks[0]).is_some(),
        "keep until write of last started (started_hi=4)"
    );
    q.prune_write_create_loc(4);
    assert!(
        q.write_create_loc(fks[0]).is_none(),
        "drop after the last-started-at-note height finished write"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Overlay slot already in Class A: structural must not meta-pread it.
#[test]
fn structural_same_batch_overlay_skips_meta_pread() {
    use crate::block::{structural_validate_spends, RunCreateHeight};
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{BatchParents, FkMap, OutPointSet};
    use rbitcoin_store::{InputRecord, OutputRecord};
    use std::sync::atomic::Ordering;

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x32, 2),
        vec![
            OutputRecord::unspent(7, vec![0x51]),
            OutputRecord::unspent(8, vec![0x52]),
        ],
    );
    let child_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x33, 1),
        vec![OutputRecord::unspent(5, vec![0x51])],
    );
    let parent_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let child_ins = vec![InputRecord {
        prev_txid: [0x32; 32],
        create_fk: Fk(1),
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let overlay = [vec![(0u32, Fk(2), 0)], vec![]];
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[
                (std::sync::Arc::clone(&parent_pin), parent_ins),
                (std::sync::Arc::clone(&child_pin), child_ins),
            ],
            false,
            &overlay,
        )
        .unwrap();
    assert_eq!(fks, vec![Fk(1), Fk(2)]);

    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x32; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, child],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();

    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        fks[0],
        std::sync::Arc::clone(&parent_pin),
        vec![0],
        Some(false),
        Some(loc[0].txout),
        Vec::new(),
    );
    bp.set_spent_range_only(fks[0], loc[0].spent);

    let spends = vec![([0x32u8; 32], 0u32, fks[1], fks[0], 0)];
    let mut map = FkMap::default();
    map.insert(fks[0], (1, false));
    map.insert(fks[1], (1, false));
    let run = RunCreateHeight::Map(map);
    let params = ChainParams::regtest();
    let ctx = crate::block::ValidationContext::at(&params, Height(1), Milestone::NONE);
    let mut pending = OutPointSet::default();
    let mut mtp = rbitcoin_query::U32Map::<u32>::default();
    mtp.insert(0, 1_300_000_000);
    let mut scratch = crate::block::StructuralScratch::default();
    let meta0 = q.confirm_stats().spend_meta_n.load(Ordering::Relaxed);
    let ovl0 = q
        .confirm_stats()
        .spend_overlay_skip_n
        .load(Ordering::Relaxed);
    structural_validate_spends(
        &q,
        &block,
        &ctx,
        Some(&fks),
        &spends,
        0,
        &mut pending,
        &bp,
        &mut mtp,
        &run,
        &crate::block::ClassAWave::new(fks.clone()),
        &mut scratch,
        None,
    )
    .expect("overlay spend is not durable-spent before tip");
    let meta_n = q
        .confirm_stats()
        .spend_meta_n
        .load(Ordering::Relaxed)
        .saturating_sub(meta0);
    let ovl_n = q
        .confirm_stats()
        .spend_overlay_skip_n
        .load(Ordering::Relaxed)
        .saturating_sub(ovl0);
    assert_eq!(meta_n, 0, "overlay abs must not structural-pread");
    assert_eq!(ovl_n, 1);
    assert!(
        scratch.slots.abs_edges.is_empty(),
        "Skip annotate job is a no-op write; omit it"
    );
    let (off, _) = q.store().tx_spent_range(fks[0]).unwrap();
    let abs0 = rbitcoin_store::spent_abs(off, 0);
    let abs1 = rbitcoin_store::spent_abs(off, 1);
    let bulk = q
        .store()
        .get_spender_meta_at_abs_batch(&[abs0, abs1])
        .unwrap();
    assert_eq!(bulk[0].unwrap().0, fks[1]);
    assert!(bulk[1].unwrap().0.is_null());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn structural_scratch_second_block_does_not_replay_first_slots() {
    use crate::block::{structural_validate_spends, RunCreateHeight, StructuralScratch};
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{BatchParents, OutPointSet};
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x41, 2),
        vec![
            OutputRecord::unspent(1, vec![0x51]),
            OutputRecord::unspent(1, vec![0x52]),
        ],
    );
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            )],
            false,
            &[],
        )
        .unwrap();
    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        fks[0],
        parent_pin,
        vec![0, 1],
        Some(false),
        Some(loc[0].txout),
        Vec::new(),
    );
    bp.set_spent_range_only(fks[0], loc[0].spent);
    q.store().header_txs.put_range(Fk(100), fks[0], 1).unwrap();
    q.store().confirmed.set(Height(0), Fk(100)).unwrap();
    q.store().rebuild_height_fence().unwrap();
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            coinbase,
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0x41; 32]),
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
            },
        ],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let params = ChainParams::regtest();
    let ctx = crate::block::ValidationContext::at(&params, Height(1), Milestone::NONE);
    let mut pending = OutPointSet::default();
    let mut mtp = rbitcoin_query::U32Map::<u32>::default();
    mtp.insert(0, 1_300_000_000);
    let mut scratch = StructuralScratch::default();
    let run = RunCreateHeight::Spans(Vec::new());
    for vout in [0u32, 1] {
        let spends = vec![([0x41u8; 32], vout, Fk(9), fks[0], 0)];
        structural_validate_spends(
            &q,
            &block,
            &ctx,
            None,
            &spends,
            0,
            &mut pending,
            &bp,
            &mut mtp,
            &run,
            &crate::block::ClassAWave::default(),
            &mut scratch,
            None,
        )
        .unwrap();
    }
    assert_eq!(scratch.slots.abs_edges.len(), 2);
    assert_eq!(scratch.slots.known.len(), 2);
    assert_ne!(scratch.slots.abs_edges[0].0, scratch.slots.abs_edges[1].0);
    let (off, _) = q.store().tx_spent_range(fks[0]).unwrap();
    assert_eq!(
        scratch.slots.abs_edges[0].0,
        rbitcoin_store::spent_abs(off, 0)
    );
    assert_eq!(
        scratch.slots.abs_edges[1].0,
        rbitcoin_store::spent_abs(off, 1)
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Spend index off must not write or count annotate slots structural already filled.
#[test]
fn post_commit_spend_index_off_leaves_slots_unwritten() {
    use super::post_commit;
    use crate::block::AnnotateSlots;
    use rbitcoin_primitives::Fk;
    use rbitcoin_store::OutputRecord;
    use std::sync::atomic::Ordering;

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x61, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let (fks, _loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![rbitcoin_store::InputRecord::coinbase(
                    u32::MAX,
                    vec![0x01],
                    vec![],
                )],
            )],
            false,
            &[],
        )
        .unwrap();
    let create_fk = fks[0];
    let (off, _) = q.store().tx_spent_range(create_fk).unwrap();
    let abs = rbitcoin_store::spent_abs(off, 0);
    q.set_spend_index(false);
    let mut slots = AnnotateSlots::default();
    slots.push((abs, create_fk, 0, Fk(9), 0), (Fk::NULL, 0, 0));
    let ann0 = q.confirm_stats().spend_ann_n.load(Ordering::Relaxed);
    post_commit(&q, &slots).expect("spend index off skips annotate");
    assert_eq!(q.confirm_stats().spend_ann_n.load(Ordering::Relaxed), ann0);
    let (_multi, field, _vin) = q.store().txs.get_output_spender_meta(create_fk, 0).unwrap();
    assert!(
        field.is_null(),
        "spend index off must not write spender meta"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Mainnet 496: lookup TipOnly already covers the child; note stamps
/// `keep_until = started_hi` and intervening writes must not drop loc.
#[test]
fn fill_just_written_survives_until_last_started_write() {
    use super::{ensure_spend_abs_layouts, fill_planned_create_layout_after_commit, Prepared};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::OutputRecord;

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x32, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    q.store().reset_spent_range_batch();
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![rbitcoin_store::InputRecord::coinbase(
                    u32::MAX,
                    vec![0x01],
                    vec![],
                )],
            )],
            false,
            &[],
        )
        .unwrap();
    q.set_lookup_started_hi(Some(496));
    q.note_write_create_loc(&fks, &loc, 360);
    q.prune_write_create_loc(432);
    assert!(
        q.write_create_loc(fks[0]).is_some(),
        "keep_until is 496 (last started); write 432 must not drop"
    );

    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        fks[0],
        std::sync::Arc::clone(&parent_pin),
        vec![0],
        None,
        None,
        Vec::new(),
    );
    let child = [Prepared {
        height: Height(496),
        header_fk: Fk(2),
        tx_fks: vec![Fk(3)],
        jobs: vec![],
        spends: vec![([0x32u8; 32], 0, Fk(3), fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [9u8; 32],
        prev_mtp: 0,
    }];
    q.store().reset_spent_range_batch();
    fill_planned_create_layout_after_commit(&q, &mut bp, &[], &[], &[], &child)
        .expect("child fill from write loc until last-started write");
    ensure_spend_abs_layouts(&bp, &child).expect("abs until last-started write");
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "write fill/ensure must not pread create.loc"
    );
    q.prune_write_create_loc(496);
    assert!(
        q.write_create_loc(fks[0]).is_none(),
        "drop when the last-started-at-note height finished write"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Mainnet 133433 unit: IBD stamp left spent unset (TipOnly miss, pin loc
/// unset). Write TLS fills abs. No `create.loc` pread.
#[test]
fn fill_stamp_spent_hole_from_write_tls() {
    use super::{ensure_spend_abs_layouts, fill_planned_create_layout_after_commit, Prepared};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{stamp_external_parents, BatchParentIds, BatchParents, InFlight};
    use rbitcoin_store::OutputRecord;
    use std::sync::atomic::Ordering;

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x32, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    q.store().reset_spent_range_batch();
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![rbitcoin_store::InputRecord::coinbase(
                    u32::MAX,
                    vec![0x01],
                    vec![],
                )],
            )],
            false,
            &[],
        )
        .unwrap();
    let mut inflight = InFlight::new();
    inflight.note_pins([(fks[0], &parent_pin)], Some(360));
    let _ = q.confirm_stats().fill_missing_n.swap(0, Ordering::Relaxed);
    let st = stamp_external_parents(
        q.store(),
        &[parent_pin.tx().txid],
        &inflight,
        Some(&BatchParentIds::default()),
        q.confirm_stats(),
    )
    .expect("inflight identity with empty skeleton");
    let id = fks[0].get().expect("fk");
    let ident = st.idents.get(&id).expect("ident");
    assert_eq!(ident.spent, None, "IBD stamp must not loc-by-fk");
    assert_eq!(q.confirm_stats().fill_missing_n.load(Ordering::Relaxed), 0);

    q.set_lookup_started_hi(Some(133_433));
    q.note_write_create_loc(&fks, &loc, 360);
    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        fks[0],
        std::sync::Arc::clone(&parent_pin),
        vec![0],
        None,
        None,
        Vec::new(),
    );
    let child = [Prepared {
        height: Height(133_433),
        header_fk: Fk(2),
        tx_fks: vec![Fk(3)],
        jobs: vec![],
        spends: vec![([0x32u8; 32], 0, Fk(3), fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [9u8; 32],
        prev_mtp: 0,
    }];
    q.store().reset_spent_range_batch();
    fill_planned_create_layout_after_commit(&q, &mut bp, &[], &[], &[], &child)
        .expect("child fill from write TLS after stamp spent hole");
    ensure_spend_abs_layouts(&bp, &child).expect("abs from write TLS");
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "write fill/ensure must not pread create.loc"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Write already finished: `CreatePin::set_loc` is the spent source after TLS
/// prune and disk loc truncate. Pin copies stamp range; ensure needs no TLS.
#[test]
fn pin_and_ensure_from_pin_loc_without_tls() {
    use super::{ensure_spend_abs_layouts, pin_for_wire_batch, ParentPinStamp, Prepared};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{stamp_external_parents, ArchiveWritePlan, InFlight};
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x41, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            )],
            false,
            &[],
        )
        .unwrap();
    parent_pin.set_loc(loc[0]);
    q.store().txs.create_loc_truncate_to_count(0).unwrap();
    q.set_lookup_started_hi(Some(1));
    q.note_write_create_loc(&fks, &loc, 1);
    q.prune_write_create_loc(2);
    assert!(q.write_create_loc(fks[0]).is_none(), "TLS pruned");

    let mut inflight = InFlight::new();
    inflight.note_pins([(fks[0], &parent_pin)], Some(1));
    let st = stamp_external_parents(
        q.store(),
        &[parent_pin.tx().txid],
        &inflight,
        Some(&rbitcoin_query::BatchParentIds::default()),
        q.confirm_stats(),
    )
    .expect("pin loc without disk");
    let id = fks[0].get().expect("fk");
    let ident = st.idents.get(&id).expect("ident");
    assert_eq!(ident.spent, Some(loc[0].spent));

    let spend_ins = vec![InputRecord {
        prev_txid: parent_pin.tx().txid,
        create_fk: fks[0],
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0x42, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(2)];
    plan.external_parents = st.idents;
    fill_edges_from_packed(&mut plan);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    q.store().reset_spent_range_batch();
    let (parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], Some(&inflight))
        .expect("pin from CreatePin outs + stamp loc");
    let child = [Prepared {
        height: Height(2),
        header_fk: Fk(2),
        tx_fks: vec![Fk(2)],
        jobs: vec![],
        spends: vec![(parent_pin.tx().txid, 0, Fk(2), fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [8u8; 32],
        prev_mtp: 0,
    }];
    ensure_spend_abs_layouts(&parents, &child).expect("abs from pin loc");
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "pin/ensure must not pread create.loc"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// IBD skeleton miss + creates-only InFlight (no pin): identity without range
/// is a lookup miss, not a load loc rescue.
#[test]
fn pin_creates_only_ibd_skeleton_miss_is_lookup_stage_miss() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, ParentIdent};
    use rbitcoin_store::{InputRecord, OutputRecord};

    let (path, q) = tiny_query();
    let parent_tx = rec_tx(0x51, 1);
    q.store()
        .put_tx_full_batch_indexed(
            &[(
                parent_tx.clone(),
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                vec![OutputRecord::unspent(1, vec![0x51])],
            )],
            true,
        )
        .unwrap();
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            rec_tx(0x52, 1),
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        vec![InputRecord {
            prev_txid: parent_tx.txid,
            create_fk: Fk(1),
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    plan.planned_fks = vec![Fk(2)];
    plan.external_parents
        .insert(1, ParentIdent::new(parent_tx.txid));
    fill_edges_from_packed(&mut plan);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    q.store().reset_spent_range_batch();
    let err = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect_err("creates-only without range is lookup miss");
    let msg = format!("{err}");
    assert!(msg.contains("lookup stage miss"), "unexpected err: {msg}");
    assert!(
        q.store().spent_range_batch_fks().is_empty(),
        "pin must not loc-by-fk to rescue a lookup miss"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Wire pin: in-flight outs shorter than need → cold miss → hard invariant.
#[test]
fn pin_for_wire_incomplete_outs_is_invariant_error() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::ArchiveWritePlan;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();

    let parent_id = 77u64;
    let parent_fk = Fk(parent_id);
    // Spend needs vout 0 from parent_id.
    let spend_tx = TxRecord {
        txid: [0xCCu8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let spend_ins = vec![InputRecord {
        prev_txid: [0xDDu8; 32],
        create_fk: parent_fk,
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let mut plan = ArchiveWritePlan {
        packed: vec![(
            rbitcoin_query::CreatePinInner::records(
                spend_tx,
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            spend_ins,
        )],
        planned_fks: vec![Fk(2)],
        per_header_ranges: vec![],
        per_header_sw: vec![],
        edges: Default::default(),
        batch_creates: vec![],
        external_parents: Default::default(),
        external_parent_vouts: Default::default(),
        batch_pin: vec![],
        index_tx: false,
        body_est: 0,
        tx_fees: Vec::new(),
        tx_sizes: Vec::new(),
    };
    // In-flight "parent" with **empty** outs → live.len() != need → cold path;
    // no Class A body either → end pin contract fails.
    let parent_tx = TxRecord {
        txid: [0xDDu8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 0,
    };
    let pin = rbitcoin_query::CreatePinInner::records(parent_tx, Vec::new());
    let mut inflight = rbitcoin_query::InFlight::new();
    inflight.note_pins([(Fk(parent_id), &pin)], None);

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let err = pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], Some(&inflight))
        .expect_err("incomplete outs must hard-fail pin");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("wire pin") || msg.contains("lookup stage miss")),
        "unexpected err: {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// After wire pin, freeze drops ranges+txids; BatchParents keep sparse outs.
#[test]
fn parent_pin_stamp_take_from_plan_moves_maps() {
    use super::ParentPinStamp;
    use rbitcoin_query::{ArchiveWritePlan, ParentIdent, U64Map};

    let mut idents = U64Map::default();
    idents.insert(
        7,
        ParentIdent {
            txid: [0xABu8; 32],
            body: Some((8, 16)),
            spent: Some((32, 8)),
            n_out: Some(1),
            pin: None,
        },
    );
    let mut plan = ArchiveWritePlan {
        packed: vec![],
        planned_fks: vec![],
        per_header_ranges: vec![],
        per_header_sw: vec![],
        edges: Default::default(),
        batch_creates: vec![],
        external_parents: idents,
        external_parent_vouts: Default::default(),
        batch_pin: vec![],
        index_tx: false,
        body_est: 0,
        tx_fees: Vec::new(),
        tx_sizes: Vec::new(),
    };
    let stamp = ParentPinStamp::take_from_plan(&mut plan);
    assert!(plan.external_parents.is_empty());
    assert_eq!(stamp.body_range(7), Some((8, 16)));
    assert_eq!(stamp.spent_range(7), Some((32, 8)));
    assert_eq!(stamp.create_txid(7), Some([0xABu8; 32]));
    assert!(
        stamp.resolved.is_empty(),
        "plan path pins from packed create_fk; SipHash invert is plan=None only"
    );
}

/// Pin moves stamp parent_vouts (no clone); stamp is empty after.
#[test]
fn pin_takes_stamp_parent_vouts() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::ArchiveWritePlan;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    let (path, q) = tmp_query();
    let parent_tx = TxRecord {
        txid: [0x11u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let parent = (
        parent_tx.clone(),
        vec![InputRecord::coinbase(u32::MAX, vec![0x11], vec![])],
        vec![OutputRecord::unspent(50, vec![0x51])],
    );
    let fks = q
        .store()
        .txs
        .put_full_batch_indexed(&[parent], true)
        .unwrap();
    let pfk = fks[0];
    let parent_id = pfk.get().unwrap();
    let range = q.store().txs.body_range(pfk).unwrap();
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            TxRecord {
                txid: [0x22u8; 32],
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        vec![InputRecord {
            prev_txid: parent_tx.txid,
            create_fk: pfk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    plan.planned_fks = vec![Fk(2)];
    let spent = q.store().tx_spent_range(pfk).unwrap();
    plan.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent::with_loc(parent_tx.txid, range, spent, 1),
    );
    plan.external_parent_vouts.insert(parent_id, vec![0]);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    assert_eq!(
        stamp.parent_vouts.get(&parent_id).map(|v| v.as_slice()),
        Some(&[0u32][..])
    );
    fill_edges_from_packed(&mut plan);
    let (parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect("pin via taken vouts");
    assert!(stamp.parent_vouts.is_empty(), "pin must take stamp vouts");
    assert!(parents.contains(pfk));
    assert!(parents.get_parent_out(pfk, 0).is_some());
    let _ = std::fs::remove_dir_all(&path);
}

/// Cross-height same-pack CreatePin must pin without cloning parent scripts.
#[test]
fn pin_for_wire_create_pin_shares_script_bytes() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, CreatePin};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Arc;

    let (path, q) = tmp_query();
    let script = vec![0x51u8; 4096];
    let parent_tx = TxRecord {
        txid: [0x41u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let pin: CreatePin = rbitcoin_query::CreatePinInner::records(
        parent_tx.clone(),
        vec![OutputRecord::unspent(50, script)],
    );
    let expect = pin.out_parts(0).expect("vout 0").1.as_ptr();
    let child_tx = TxRecord {
        txid: [0x42u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![
        (
            Arc::clone(&pin),
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        ),
        (
            rbitcoin_query::CreatePinInner::records(
                child_tx,
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            vec![InputRecord {
                prev_txid: parent_tx.txid,
                create_fk: Fk(1),
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
        ),
    ];
    plan.planned_fks = vec![Fk(1), Fk(2)];
    plan.batch_pin = vec![Arc::clone(&pin), Arc::clone(&plan.packed[1].0)];
    plan.per_header_ranges = vec![(Fk(10), Fk(1), 1), (Fk(11), Fk(2), 1)];
    plan.external_parent_vouts.insert(1, vec![0]);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, edges) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect("cross-height CreatePin pin");
    let child_edges = edges.get(&2).expect("child spend edges");
    assert_eq!(child_edges.len(), 1);
    assert_eq!(child_edges[0].create_fk, Fk(1));
    assert_eq!(child_edges[0].vout, 0);
    let got = parents
        .get_parent_txout_parts(Fk(1), 0, |v, sc, _| {
            assert_eq!(v, 50);
            sc.as_ptr()
        })
        .expect("pinned parent");
    assert_eq!(
        got, expect,
        "plan CreatePin pin must not clone OutputRecord scripts"
    );
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn write_encodes_seqsigwit_from_wire() {
    use super::{
        confirm_scripts_phase, confirm_wire_load_from_plan, confirm_wire_lookup_stamp,
        confirm_write_phase, ScriptPreverified,
    };
    use crate::accept_and_connect_block;
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use crate::regtest_pad::mine_empty_regtest;
    use rbitcoin_primitives::Height;
    use std::sync::Arc;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let items = [(Height(1), Arc::new(b1), None)];
    let mut stamped =
        confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &items, None).expect("stamp");
    {
        let plan = stamped.plan.as_mut().expect("plan");
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "stamp leaves packed ins empty"
        );
        for (_, ins) in plan.packed.iter_mut() {
            ins.clear();
        }
    }
    let script = items[0].1.txdata[0].input[0].script_sig.to_bytes();
    let mat = confirm_wire_load_from_plan(
        &q,
        &params,
        Milestone::NONE,
        stamped,
        None,
        &ScriptPreverified::new(),
    )
    .expect("load");
    let ok = confirm_scripts_phase(mat.batch).expect("scripts");
    confirm_write_phase(&q, &params, Milestone::NONE, ok.batch).expect("write encodes from wire");
    let (_tx, ins, _outs) = q.store().get_tx_full(rbitcoin_primitives::Fk(2)).unwrap();
    assert_eq!(ins[0].script_sig, script);
    let _ = std::fs::remove_dir_all(&path);
}

/// C1: pin reads plan.edges; packed ins may be empty.
#[test]
fn pin_plan_edges_without_packed_ins() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, CreatePin, SpendEdge};
    use rbitcoin_store::{OutputRecord, TxRecord};
    use std::sync::Arc;
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();

    let parent_tx = TxRecord {
        txid: [0x11u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let pin: CreatePin = rbitcoin_query::CreatePinInner::records(
        parent_tx.clone(),
        vec![OutputRecord::unspent(50, vec![0x51])],
    );
    let child_tx = TxRecord {
        txid: [0x42u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![
        (Arc::clone(&pin), vec![]),
        (
            rbitcoin_query::CreatePinInner::records(
                child_tx,
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            vec![],
        ),
    ];
    plan.planned_fks = vec![Fk(1), Fk(2)];
    plan.batch_pin = vec![Arc::clone(&pin), Arc::clone(&plan.packed[1].0)];
    plan.per_header_ranges = vec![(Fk(10), Fk(1), 1), (Fk(11), Fk(2), 1)];
    plan.external_parent_vouts.insert(1, vec![0]);
    plan.edges.insert(
        2,
        vec![SpendEdge {
            prev_txid: parent_tx.txid,
            vout: 0,
            spend_fk: Fk(2),
            create_fk: Fk(1),
            vin: 0,
        }],
    );
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, edges) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect("pin from plan.edges with empty packed ins");
    let child_edges = edges.get(&2).expect("child spend edges");
    assert_eq!(child_edges.len(), 1);
    assert_eq!(child_edges[0].create_fk, Fk(1));
    assert!(parents.get_parent_out(Fk(1), 0).is_some());
    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn pin_plan_empty_edges_is_invariant() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::ArchiveWritePlan;
    use rbitcoin_store::{OutputRecord, TxRecord};
    use std::sync::Arc;
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();
    let pin = rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid: [0x11u8; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![OutputRecord::unspent(50, vec![0x51])],
    );
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(Arc::clone(&pin), vec![])];
    plan.planned_fks = vec![Fk(1)];
    plan.batch_pin = vec![Arc::clone(&pin)];
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    let err = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
        .expect_err("empty edges with planned fks must not skip spends");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant") && msg.contains("spend edges empty"),
        "unexpected err: {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Need a high vout from a multi-out parent (need-vouts only, not full n_out).
#[test]
fn pin_sparse_need_high_vout_only() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, CreatePin};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Arc;

    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();

    let parent_tx = TxRecord {
        txid: [0x33u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 4,
    };
    let parent_outs = vec![
        OutputRecord::unspent(1, vec![0x00]),
        OutputRecord::unspent(2, vec![0x01]),
        OutputRecord::unspent(3, vec![0x02]),
        OutputRecord::unspent(4, vec![0xaa]),
    ];
    let parent_ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let pfk = q
        .store()
        .txs
        .put_full_batch_indexed(&[(parent_tx.clone(), parent_ins, parent_outs)], true)
        .unwrap()[0];
    let range = q.store().tx_body_range(pfk).unwrap();
    let parent_id = pfk.get().unwrap();

    let spend_tx = TxRecord {
        txid: [0x44u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let spend_ins = vec![InputRecord {
        prev_txid: parent_tx.txid,
        create_fk: pfk,
        prev_index: 3,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let spend_pin: CreatePin = rbitcoin_query::CreatePinInner::records(
        spend_tx,
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let mut plan = ArchiveWritePlan {
        packed: vec![(Arc::clone(&spend_pin), spend_ins)],
        planned_fks: vec![Fk(2)],
        per_header_ranges: vec![],
        per_header_sw: vec![],
        edges: Default::default(),
        batch_creates: vec![],
        external_parents: {
            let mut m = rbitcoin_query::U64Map::default();
            let spent = q.store().tx_spent_range(pfk).unwrap();
            m.insert(
                parent_id,
                rbitcoin_query::ParentIdent::with_loc(parent_tx.txid, range, spent, 4),
            );
            m
        },
        external_parent_vouts: Default::default(),
        batch_pin: vec![Arc::clone(&spend_pin)],
        index_tx: false,
        body_est: 0,
        tx_fees: Vec::new(),
        tx_sizes: Vec::new(),
    };
    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
        .expect("pin high vout");
    assert!(parents.get_parent_out(pfk, 3).is_some());
    assert_eq!(
        parents.get_parent_out(pfk, 3).unwrap().1.value,
        4,
        "need-vout 3 only"
    );
    assert!(
        parents.get_parent_out(pfk, 1).is_none(),
        "must not pin unneeded vouts"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Range-fill this window is `PIN_NEW`, not `PIN_CACHE_BODY` / `warm.already`.
#[test]
fn pin_range_fill_does_not_count_as_cache_hit() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::ArchiveWritePlan;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};

    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();

    let mk_parent = |tag: u8| {
        let mut tid = [0u8; 32];
        tid[0] = tag;
        tid[1] = 0xee;
        (
            TxRecord {
                txid: tid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            vec![InputRecord::coinbase(u32::MAX, vec![tag], vec![])],
            vec![OutputRecord::unspent(1000 + tag as i64, vec![0x51, tag])],
        )
    };
    let items = [mk_parent(1), mk_parent(2), mk_parent(3)];
    let fks = q.store().txs.put_full_batch_indexed(&items, true).unwrap();
    assert_eq!(fks.len(), 3);
    let mut ranges = Vec::new();
    for fk in &fks {
        ranges.push(q.store().tx_body_range(*fk).unwrap());
    }

    let spend_tx = TxRecord {
        txid: [0x5cu8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 3,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let spend_ins: Vec<InputRecord> = (0..3)
        .map(|i| InputRecord {
            prev_txid: items[i].0.txid,
            create_fk: fks[i],
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        })
        .collect();
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            spend_tx,
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    for i in 0..3 {
        if let Some(id) = fks[i].get() {
            plan.external_parents.insert(
                id,
                rbitcoin_query::ParentIdent::with_loc(
                    items[i].0.txid,
                    ranges[i],
                    q.store().tx_spent_range(fks[i]).unwrap(),
                    1,
                ),
            );
        }
    }

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (_parents, _) =
        pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None).expect("range-fill 3");
    let lp = q.confirm_stats().last_pin_phases();
    assert_eq!(lp.pin_new_n, 3);
    assert_eq!(
        lp.pin_plan_n, 0,
        "range-fills must not increment already / PIN_CACHE_BODY"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Stamp-carried CreatePin outs cover a later spend. That is `PIN_CACHE_BODY`
/// / `warm.already`, not `PIN_NEW` / range-fill.
#[test]
fn pin_stamp_outs_is_cache_not_new() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, CreatePin};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Arc;

    let (path, q) = tmp_query();

    let mut tid = [0u8; 32];
    tid[0] = 0x41;
    let parent_tx = TxRecord {
        txid: tid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let parent_out = OutputRecord::unspent(50, vec![0x51, 0xaa]);
    let pin: CreatePin =
        rbitcoin_query::CreatePinInner::records(parent_tx.clone(), vec![parent_out.clone()]);
    let pfk = Fk(7);

    let spend_tx = TxRecord {
        txid: [0x5cu8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let spend_ins = vec![InputRecord {
        prev_txid: tid,
        create_fk: pfk,
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            spend_tx,
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    plan.external_parents.insert(
        7,
        rbitcoin_query::ParentIdent {
            txid: tid,
            body: Some((99, 1)),
            spent: None,
            n_out: Some(1),
            pin: Some(Arc::clone(&pin)),
        },
    );

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    assert!(
        Arc::ptr_eq(parent_pin.create_pin(7).expect("stamp pin"), &pin),
        "pin must use stamp-carried CreatePin"
    );
    fill_edges_from_packed(&mut plan);
    let (_parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
        .expect("stamp-carried outs must cover");
    let lp = q.confirm_stats().last_pin_phases();
    assert_eq!(lp.pin_plan_n, 1);
    assert_eq!(
        lp.pin_new_n, 0,
        "stamp-carried outs must count as PIN_CACHE, not PIN_NEW"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Identity-only stamp (no outs) still cold-fills by stamped range.
#[test]
fn pin_recent_identity_without_outs_still_range_fills() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::ArchiveWritePlan;
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};

    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();

    let mut tid = [0u8; 32];
    tid[0] = 0x42;
    let parent = (
        TxRecord {
            txid: tid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x42], vec![])],
        vec![OutputRecord::unspent(50, vec![0x51, 0x42])],
    );
    let fks = q
        .store()
        .txs
        .put_full_batch_indexed(std::slice::from_ref(&parent), true)
        .unwrap();
    let range = q.store().tx_body_range(fks[0]).unwrap();

    let spend_tx = TxRecord {
        txid: [0x5du8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let spend_ins = vec![InputRecord {
        prev_txid: tid,
        create_fk: fks[0],
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        rbitcoin_query::CreatePinInner::records(
            spend_tx,
            vec![OutputRecord::unspent(1, vec![0x51])],
        ),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    if let Some(id) = fks[0].get() {
        plan.external_parents.insert(
            id,
            rbitcoin_query::ParentIdent::with_loc(
                tid,
                range,
                q.store().tx_spent_range(fks[0]).unwrap(),
                1,
            ),
        );
    }

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (_parents, _) = pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
        .expect("identity-only stamp still range-fills");
    let lp = q.confirm_stats().last_pin_phases();
    assert_eq!(lp.pin_new_n, 1);
    assert_eq!(
        lp.pin_plan_n, 0,
        "identity without outs must not count as PIN_CACHE"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Store start states: S0 new Class A and S1 already-archived both confirm
/// via shipped lookup→load (body denserels by range; no load head/idx).
#[test]
fn store_start_states_lookup_load_confirm() {
    use super::{
        confirm_scripts_phase, confirm_wire_load_from_plan, confirm_wire_lookup_stamp,
        confirm_write_phase, ScriptPreverified,
    };
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use crate::{accept_and_connect_block, prepare_block_for_archive};
    use bitcoin::block::{Header, Version};
    use bitcoin::blockdata::transaction::{
        OutPoint, Transaction, TxIn, TxOut, Version as TxVersion,
    };
    use bitcoin::hashes::Hash;
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::CompactTarget;
    use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Sequence, TxMerkleNode, Witness};
    use rbitcoin_primitives::Height;
    use std::sync::Arc;

    let (path, q) = tmp_query();
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    fn coinbase(height: u32) -> Transaction {
        let mut ss = crate::bip34_height_script(height);
        ss.push(bitcoin::opcodes::all::OP_CHECKSIG.to_u8());
        let script = ScriptBuf::from_bytes(ss);
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: script,
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }
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
    fn spend(prev: bitcoin::Txid, vout: u32, val: Amount) -> Transaction {
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
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 1 {
        let b = mine_cb(tip, tip_time + 600, h);
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    // S0: new Class A plan — stamp must fill parent body_range; load Forbid ok.
    let h_s0 = maturity + 2;
    let b_s0 = mine_with(
        tip,
        tip_time + 600,
        h_s0,
        vec![spend(c1, 0, Amount::from_sat(49_0000_0000))],
    );
    {
        let arcs = [(Height(h_s0), Arc::new(b_s0.clone()), None)];
        let stamped = confirm_wire_lookup_stamp(&q, &params, ms, &arcs, None).expect("S0 lookup");
        assert!(stamped.plan.is_some(), "S0 must plan Class A");
        let plan = stamped.plan.as_ref().expect("plan");
        assert!(
            plan.packed.iter().all(|(_, ins)| ins.is_empty()),
            "IBD stamp leaves packed ins empty; commit encodes from the wire tx"
        );
        assert!(
            !plan.edges.is_empty(),
            "IBD stamp must carry SpendEdges for pin/write encode"
        );
        assert!(
            stamped.parent_pin.idents.values().any(|p| p.body.is_some()),
            "S0 lookup must stamp external parent body ranges"
        );
        let mat =
            confirm_wire_load_from_plan(&q, &params, ms, stamped, None, &ScriptPreverified::new())
                .expect("S0 load denserels by range");
        let ok = confirm_scripts_phase(mat.batch).expect("S0 scripts");
        confirm_write_phase(&q, &params, ms, ok.batch).expect("S0 write");
    }
    assert_eq!(q.tip_height().map(|h| h.0), Some(h_s0));
    assert_eq!(
        q.class_a_hi(),
        Some(h_s0),
        "committed Class A must bump class_a_hi before Class C"
    );
    tip = b_s0.block_hash();
    tip_time = b_s0.header.time;

    // S1: already-archived (plan=None) — lookup stamps parent pin; load by range.
    let h_s1 = h_s0 + 1;
    let b_s1 = mine_cb(tip, tip_time + 600, h_s1);
    let (header_s1, txs_s1) = prepare_block_for_archive(&q, &params, &b_s1).unwrap();
    q.commit_class_a_only(&header_s1, &txs_s1).unwrap();
    assert_eq!(q.tip_height().map(|h| h.0), Some(h_s0));
    {
        let arcs = [(Height(h_s1), Arc::new(b_s1.clone()), None)];
        let stamped = confirm_wire_lookup_stamp(&q, &params, ms, &arcs, None).expect("S1 lookup");
        assert!(stamped.plan.is_none(), "S1 already-archived → plan=None");
        let mat =
            confirm_wire_load_from_plan(&q, &params, ms, stamped, None, &ScriptPreverified::new())
                .expect("S1 plan=None load");
        let ok = confirm_scripts_phase(mat.batch).expect("S1 scripts");
        confirm_write_phase(&q, &params, ms, ok.batch).expect("S1 write");
    }
    assert_eq!(q.tip_height().map(|h| h.0), Some(h_s1));
    assert_eq!(
        q.class_a_hi(),
        Some(h_s0),
        "idempotent Class A skip must not bump class_a_hi"
    );

    // One-shot mixed need-body + already-bodied must fail closed (split into two calls).
    let h_have = h_s1 + 1;
    let b_have = mine_cb(b_s1.block_hash(), b_s1.header.time + 600, h_have);
    let (header_have, txs_have) = prepare_block_for_archive(&q, &params, &b_have).unwrap();
    q.commit_class_a_only(&header_have, &txs_have).unwrap();
    let h_need = h_have + 1;
    let b_need = mine_cb(b_have.block_hash(), b_have.header.time + 600, h_need);
    let mixed_arcs = [
        (Height(h_have), Arc::new(b_have.clone()), None),
        (Height(h_need), Arc::new(b_need.clone()), None),
    ];
    match confirm_wire_lookup_stamp(&q, &params, ms, &mixed_arcs, None) {
        Err(crate::error::ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(m))) => {
            assert_eq!(m, "invariant: confirm batch mixed archived");
        }
        Ok(_) => panic!("mixed lookup stamp must fail closed"),
        Err(other) => panic!("expected mixed archived lookup, got {other:?}"),
    }
    let mixed_run = [(Height(h_have), b_have), (Height(h_need), b_need)];
    match super::confirm_wire_load_phase(&q, &params, ms, &mixed_run, &ScriptPreverified::new()) {
        Err(crate::error::ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(m))) => {
            assert_eq!(m, "invariant: confirm batch mixed archived");
        }
        Ok(_) => panic!("mixed one-shot load must fail closed"),
        Err(other) => panic!("expected mixed archived load, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&path);
}

#[test]
fn wire_lookup_empty_and_noncontiguous() {
    use super::confirm_wire_lookup_stamp;
    use crate::error::ConsensusError;
    use crate::milestone::Milestone;
    use crate::params::{genesis_block, ChainParams};
    use rbitcoin_primitives::Height;
    use std::sync::Arc;

    let (path, q) = tmp_query();
    let params = ChainParams::regtest();
    match confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &[], None) {
        Err(ConsensusError::BadBlock("empty confirm batch")) => {}
        Ok(_) => panic!("empty lookup must refuse"),
        Err(e) => panic!("empty lookup must refuse, got {e}"),
    }
    let g = genesis_block(&params);
    let a = (Height(0), Arc::new(g.clone()), None);
    let b = (Height(2), Arc::new(g), None);
    match confirm_wire_lookup_stamp(&q, &params, Milestone::NONE, &[a, b], None) {
        Err(ConsensusError::BadBlock("confirm run not contiguous")) => {}
        Ok(_) => panic!("gap lookup must refuse"),
        Err(e) => panic!("gap lookup must refuse, got {e}"),
    }
    let _ = std::fs::remove_dir_all(&path);
}

/// Load miss: spend edges without pin denserels must hard-fail (no cold tier).
/// Pin-covered parent without denserels/abs fails structural (no body-range cold).
#[test]
fn structural_pinned_without_abs_is_invariant_error() {
    use crate::block::{structural_validate_spends, RunCreateHeight};
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{BatchParents, OutPointSet};
    use rbitcoin_store::{OutputRecord, TxRecord};
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();

    // Minimal non-empty block (coinbase only) for structural entry.
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();

    // Parent pin present (outs) but denserels/body_range missing → abs None.
    let mut bp = BatchParents::new();
    let parent_fk = Fk(42);
    let tx = TxRecord {
        txid: [7u8; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let out = OutputRecord::unspent(1, vec![0x51]);
    bp.insert_owned(
        parent_fk,
        tx,
        vec![(0, out)],
        vec![0],
        Some(false),
        None,   // no body_range
        vec![], // no denserels
    );

    let spends = vec![([7u8; 32], 0u32, Fk(100), parent_fk, 0)];
    let ctx = crate::block::ValidationContext::at(&params, Height(1), Milestone::NONE);
    let mut pending = OutPointSet::default();
    let mut mtp = rbitcoin_query::U32Map::<u32>::default();
    let heights = RunCreateHeight::Spans(Vec::new());
    let err = structural_validate_spends(
        &q,
        &block,
        &ctx,
        None,
        &spends,
        0,
        &mut pending,
        &bp,
        &mut mtp,
        &heights,
        &crate::block::ClassAWave::default(),
        &mut crate::block::StructuralScratch::default(),
        None,
    )
    .expect_err("pinned without abs must be invariant");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant") && msg.contains("denserels"),
        "unexpected err: {msg}"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Direct write skips SH FkMap; Class A idx holds the body range.
#[test]
fn direct_write_skips_create_pin_map_idx_without_recent() {
    use crate::regtest_pad::mine_empty_regtest;
    use crate::{accept_and_connect_block, ChainParams, Milestone};
    use bitcoin::hashes::Hash;
    use rbitcoin_primitives::Height;
    let (path, q) = tmp_query();
    q.enter_direct_index_mode().unwrap();
    q.set_lookup_started_hi(Some(32));
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let tid = b1.txdata[0].compute_txid().to_byte_array();
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let fk = q
        .tx_fk_by_txid(&tid)
        .expect("txid lookup")
        .expect("height-1 create on idx");
    let idx = q.store().tx_body_range(fk).expect("idx after Class A");
    assert!(idx.1 > 0, "Class A body range must be on idx");
    let _ = std::fs::remove_dir_all(&path);
}

/// One-shot load and stamp+load_from_plan must produce the same batch.
#[test]
fn one_shot_load_matches_stamp_then_load_from_plan() {
    use super::{
        confirm_wire_load_from_plan, confirm_wire_load_phase, confirm_wire_lookup_stamp,
        ScriptPreverified,
    };
    use crate::regtest_pad::mine_empty_regtest;
    use crate::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use std::sync::Arc;

    fn open_q(_tag: &str) -> (rbitcoin_query::testutil::TempDir, rbitcoin_query::Query) {
        tmp_query()
    }

    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let b1 = mine_empty_regtest(genesis.block_hash(), genesis.header.time + 600, 1);
    let b2 = mine_empty_regtest(b1.block_hash(), b1.header.time + 600, 2);
    let run = [(Height(1), b1.clone()), (Height(2), b2.clone())];
    let none = ScriptPreverified::new();

    let (path_a, qa) = open_q("a");
    accept_and_connect_block(&qa, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let one_shot =
        confirm_wire_load_phase(&qa, &params, Milestone::NONE, &run, &none).expect("one-shot load");

    let (path_b, qb) = open_q("b");
    accept_and_connect_block(&qb, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let arcs: Vec<_> = run
        .iter()
        .map(|(h, b)| (*h, Arc::new(b.clone()), None))
        .collect();
    let stamped =
        confirm_wire_lookup_stamp(&qb, &params, Milestone::NONE, &arcs, None).expect("stamp");
    let from_plan =
        confirm_wire_load_from_plan(&qb, &params, Milestone::NONE, stamped, None, &none)
            .expect("load_from_plan");

    assert_eq!(
        one_shot.batch.heights_hashes(),
        from_plan.batch.heights_hashes()
    );
    assert_eq!(
        one_shot.batch.parent_count(),
        from_plan.batch.parent_count()
    );
    assert_eq!(one_shot.batch.len(), 2);
    assert!(one_shot.batch.approx_wire_bytes() > 0);
    assert!(
        qa.confirm_stats()
            .phase_prep_wire_arc_ns
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0,
        "cloning the wire batch records prep time"
    );
    for (a, b) in one_shot
        .batch
        .prepared
        .iter()
        .zip(from_plan.batch.prepared.iter())
    {
        assert_eq!(a.height, b.height);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.header_fk, b.header_fk);
        assert_eq!(a.tx_fks, b.tx_fks);
        assert_eq!(a.fees, b.fees);
        assert_eq!(a.spends, b.spends);
        assert_eq!(a.jobs.len(), b.jobs.len());
        for (ja, jb) in a.jobs.iter().zip(b.jobs.iter()) {
            assert_eq!(ja.txid, jb.txid);
            assert_eq!(ja.prevouts, jb.prevouts);
        }
    }
    let pa = one_shot.batch.archive_plan.as_ref().expect("plan A");
    let pb = from_plan.batch.archive_plan.as_ref().expect("plan B");
    assert_eq!(pa.planned_fks, pb.planned_fks);
    assert_eq!(pa.per_header_ranges, pb.per_header_ranges);
    assert_eq!(pa.edges.len(), pb.edges.len());
    assert_eq!(pa.packed.len(), pb.packed.len());
    assert_eq!(pa.index_tx, pb.index_tx);
    let _ = std::fs::remove_dir_all(&path_a);
    let _ = std::fs::remove_dir_all(&path_b);
}

/// Post-fill abs jobs come from one `spend_abs_jobs` walk. A vout outside the
/// spent range is the ensure `Corrupt` (before head insert). Duplicate abs
/// collapses to one job. A null create fk is skipped.
#[test]
fn collect_spend_abs_after_fill_is_one_walk() {
    use super::{collect_spend_abs_after_fill, Prepared};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::OutputRecord;

    let mut bp = BatchParents::new();
    bp.insert_owned(
        Fk(1),
        rec_tx(0x11, 2),
        vec![
            (0, OutputRecord::unspent(1, vec![0x51])),
            (1, OutputRecord::unspent(1, vec![0x51])),
        ],
        vec![0, 1],
        Some(false),
        None,
        Vec::new(),
    );
    // One spent slot: vout 0 is in range, vout 1 is not.
    bp.set_spent_range_only(Fk(1), (1000, OutputRecord::SPENT_SLOT_LEN as u64));

    let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    let prepared_ok = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(9)],
        jobs: vec![],
        spends: vec![
            ([0x11; 32], 0, Fk(9), Fk(1), 0),
            ([0x11; 32], 0, Fk(9), Fk(1), 1),
            ([0; 32], 0, Fk(9), Fk::NULL, 0),
        ],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits,
        hash: [1u8; 32],
        prev_mtp: 0,
    }];
    let jobs = collect_spend_abs_after_fill(&bp, &prepared_ok).expect("in-range vout 0");
    assert_eq!(
        jobs,
        vec![vec![(
            1u64,
            0u32,
            rbitcoin_store::spent_abs(1000, 0),
            Fk(9),
            0u32,
        )]]
    );

    let prepared_miss = [Prepared {
        height: Height(1),
        header_fk: Fk(1),
        tx_fks: vec![Fk(9)],
        jobs: vec![],
        spends: vec![([0x11; 32], 1, Fk(9), Fk(1), 0)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits,
        hash: [1u8; 32],
        prev_mtp: 0,
    }];
    let err =
        collect_spend_abs_after_fill(&bp, &prepared_miss).expect_err("vout past the spent range");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant: ensure denserels/abs incomplete for spend edge"),
        "got {msg}"
    );
}

/// A scratch reused for the next write batch must not keep the previous
/// batch's annotate slots or pack-local double-spend set.
#[test]
fn structural_run_clears_reused_scratch_between_batches() {
    use super::phases::{structural_run, StructuralReuse};
    use super::{collect_spend_abs_after_fill, Prepared};
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut,
        Witness,
    };
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::BatchParents;
    use rbitcoin_store::{InputRecord, OutputRecord};
    use std::sync::Arc;

    let (path, q) = tiny_query();
    let parent_pin = rbitcoin_query::CreatePinInner::records(
        rec_tx(0x41, 1),
        vec![OutputRecord::unspent(1, vec![0x51])],
    );
    let (fks, loc) = q
        .store()
        .put_tx_full_batch_from_pins(
            &[(
                std::sync::Arc::clone(&parent_pin),
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
            )],
            false,
            &[],
        )
        .unwrap();
    let mut bp = BatchParents::new();
    bp.insert_create_pin(
        fks[0],
        parent_pin,
        vec![0],
        Some(false),
        Some(loc[0].txout),
        Vec::new(),
    );
    bp.set_spent_range_only(fks[0], loc[0].spent);
    q.store().header_txs.put_range(Fk(100), fks[0], 1).unwrap();
    q.store().confirmed.set(Height(0), Fk(100)).unwrap();
    q.store().rebuild_height_fence().unwrap();

    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1_300_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            coinbase,
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: bitcoin::Txid::from_byte_array([0x41; 32]),
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
            },
        ],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let params = ChainParams::regtest();
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let prepared = [Prepared {
        height: Height(1),
        header_fk: Fk(100),
        tx_fks: vec![Fk(9)],
        jobs: vec![],
        spends: vec![([0x41; 32], 0, Fk(9), fks[0], 0)],
        fees: 0,
        check_scripts: false,
        time: 1_300_000_000,
        bits,
        hash: [2u8; 32],
        prev_mtp: 1_300_000_000,
    }];
    let jobs = collect_spend_abs_after_fill(&bp, &prepared).expect("parent abs");
    let wire = vec![Arc::new(block)];

    let mut reuse = StructuralReuse::default();
    reuse
        .scratch
        .slots
        .push((999, Fk(1), 0, Fk(8), 0), (Fk::NULL, 0, 0));
    reuse.pending.insert(([0x41; 32], 0u32));

    let run = |reuse: &mut StructuralReuse| {
        structural_run(
            &q,
            &params,
            Milestone::NONE,
            &prepared,
            &wire,
            &bp,
            &jobs,
            &crate::block::ClassAWave::default(),
            reuse,
        )
        .expect("reused scratch still connects")
    };
    let (_ph, slots) = run(&mut reuse);
    assert!(
        slots.abs_edges.iter().all(|e| e.0 != 999),
        "previous batch slot leaked: {:?}",
        slots.abs_edges
    );
    assert_eq!(slots.abs_edges.len(), 1);
    let (_ph, slots2) = run(&mut reuse);
    assert_eq!(slots2.abs_edges.len(), 1);
    assert_ne!(slots2.abs_edges[0].0, 999);
    let _ = std::fs::remove_dir_all(&path);
}
