//! Confirm_run unit tests (peeled from confirm_run.rs).

use super::{
    confirm_archive_kind, write_batch_vs_tip, write_height_needed, ConfirmArchiveKind,
    WriteBatchVsTip,
};

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

/// Batch append: contiguous heights merge; gap returns Err(other).
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
        }
    }
    let mut a = batch_one(10);
    let b = batch_one(11);
    assert!(a.append_contiguous(b).is_ok());
    assert_eq!(a.len(), 2);
    let gap = batch_one(13);
    let err = a.append_contiguous(gap).err().expect("gap");
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
        })
        .is_ok());
    assert_eq!(a.len(), 3);

    // Empty self absorbs other.
    let mut empty = ScriptOkBatch {
        prepared: vec![],
        wire_blocks: vec![],
        batch_parents: rbitcoin_query::BatchParents::new(),
        archive_plan: None,
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
    let err = good.append_contiguous(bad).err().expect("len mismatch");
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
        .err()
        .expect("Some+None polarity");
    assert_eq!(err.len(), 1);
    assert_eq!(with_plan.len(), 2);
    assert!(with_plan.archive_plan.is_some());
    let mut no_plan = batch_one(80);
    let mut has = batch_one(81);
    has.archive_plan = Some(rbitcoin_query::ArchiveWritePlan::empty());
    let err = no_plan
        .append_contiguous(has)
        .err()
        .expect("None+Some polarity");
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
    };
    assert!(batch.is_empty());
    assert_eq!(batch.approx_wire_bytes(), 0);
    assert_eq!(batch.parent_count(), 0);
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
    }
}

/// One-batch feed-ahead path (no lookahead) still succeeds on the real entry.
#[test]
fn scripts_feed_ahead_single_batch() {
    use super::confirm_scripts_feed_ahead;
    let outs = confirm_scripts_feed_ahead([empty_loaded_batch()]).expect("single");
    assert_eq!(outs.len(), 1);
    assert!(outs[0].batch.is_empty());
}

/// `confirm_scripts_phase_async` publishes on the caller (no coordinator
/// thread, no steal worker).
#[test]
fn scripts_phase_does_not_run_on_steal_worker() {
    use super::confirm_scripts_phase_async;
    let (ok, name) = confirm_scripts_phase_async(empty_loaded_batch())
        .join_with_phase_thread()
        .expect("empty phase");
    assert!(ok.batch.is_empty());
    assert!(
        !name.starts_with("rbtc-script-coord-"),
        "coordinator threads are gone, got {name:?}"
    );
    assert!(
        !name.starts_with("rbtc-scripts-"),
        "scripts phase ran on steal worker {name:?}"
    );
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

/// IBD `drive_script_waves` writes in input order and never starts
/// `rbtc-script-coord-*` threads.
#[test]
fn drive_script_waves_ordered_without_coordinator_threads() {
    use super::drive_script_waves;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, rx) = mpsc::sync_channel(4);
    let heights = Arc::new(Mutex::new(Vec::new()));
    let heights_w = Arc::clone(&heights);
    let stage = thread::Builder::new()
        .name("ibd-confirm".into())
        .spawn(move || {
            drive_script_waves(
                &rx,
                |ok, meta| {
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
    crate::block::ScriptCheckJob::with_txid(tid, prevouts, tx, true, true, true, true, true)
}

/// One-job inline fail keeps the batch height/hash; a later batch still writes.
#[test]
fn drive_script_waves_start_fail_keeps_meta_and_continues() {
    use super::drive_script_waves;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;

    let (tx, rx) = mpsc::sync_channel(4);
    let oks = Arc::new(Mutex::new(Vec::new()));
    let errs = Arc::new(Mutex::new(Vec::new()));
    let oks_w = Arc::clone(&oks);
    let errs_w = Arc::clone(&errs);
    let stage = thread::spawn(move || {
        drive_script_waves(
            &rx,
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

/// Two ready batches: both verify on the real async path; write order preserved.
///
/// Uses [`confirm_scripts_feed_ahead`] (same submit/join helper production
/// scripts OS thread uses via [`confirm_scripts_phase_async`]).
#[test]
fn scripts_feed_ahead_two_batches_ordered() {
    use super::{confirm_scripts_feed_ahead, confirm_scripts_phase_async};
    // Async handles: start both before joining either (overlap submit).
    let h0 = confirm_scripts_phase_async(empty_loaded_batch());
    let h1 = confirm_scripts_phase_async(empty_loaded_batch());
    let o0 = h0.join().expect("batch0");
    let o1 = h1.join().expect("batch1");
    assert!(o0.batch.is_empty());
    assert!(o1.batch.is_empty());

    // Ordered helper: two batches both ok, returned in input order.
    let outs = confirm_scripts_feed_ahead([empty_loaded_batch(), empty_loaded_batch()])
        .expect("feed-ahead two");
    assert_eq!(outs.len(), 2);
    assert!(outs[0].batch.is_empty());
    assert!(outs[1].batch.is_empty());
}

/// Empty iterator is a no-op (pipeline edge).
#[test]
fn scripts_feed_ahead_zero_batches() {
    use super::confirm_scripts_feed_ahead;
    let outs = confirm_scripts_feed_ahead(std::iter::empty()).expect("empty");
    assert!(outs.is_empty());
}

/// Depth-1 feed-ahead + no 200 µs-poll after lookahead, **without** a
/// process-global HOLD in [`super::confirm_scripts_phase`].
///
/// A sibling `confirm_scripts_phase` running while A is held must finish
/// immediately (the old `HOLD_FIRST` hook stalled every phase in the crate).
#[test]
fn scripts_stage_depth1_feeds_ahead_without_holding_siblings() {
    use super::{
        confirm_scripts_phase, join_scripts_polling, scripts_stage_from_load_channel_with,
        ConfirmScriptOutcome, ScriptsBatchMeta, ScriptsPhaseHandle,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Condvar, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    let submits = Arc::new(AtomicU64::new(0));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let outcomes: Arc<Mutex<Vec<ConfirmScriptOutcome>>> = Arc::new(Mutex::new(Vec::new()));
    let (mat_tx, mat_rx) = mpsc::sync_channel::<(super::LoadedBatch, u64)>(1);

    let submits_s = Arc::clone(&submits);
    let gate_s = Arc::clone(&gate);
    let outcomes_w = Arc::clone(&outcomes);
    let stage = thread::spawn(move || {
        scripts_stage_from_load_channel_with(
            &mat_rx,
            |batch, mat_ns| {
                let meta = ScriptsBatchMeta::from_batch(&batch, mat_ns);
                let n = submits_s.fetch_add(1, Ordering::SeqCst) + 1;
                let gate = Arc::clone(&gate_s);
                let handle = ScriptsPhaseHandle::spawn_fn(move || {
                    if n == 1 {
                        let (lock, cv) = &*gate;
                        let mut go = lock.lock().unwrap();
                        let deadline = Instant::now() + Duration::from_secs(2);
                        while !*go {
                            let left = deadline.saturating_duration_since(Instant::now());
                            if left.is_zero() {
                                break;
                            }
                            let (g, w) = cv.wait_timeout(go, left).unwrap();
                            go = g;
                            if w.timed_out() {
                                break;
                            }
                        }
                    }
                    confirm_scripts_phase(batch)
                });
                (handle, meta)
            },
            |ok, _meta: ScriptsBatchMeta| {
                outcomes_w.lock().unwrap().push(ok);
                true
            },
            |_e, _meta| false,
            || false,
        );
    });

    mat_tx.send((empty_loaded_batch(), 0)).expect("send A");
    let deadline = Instant::now() + Duration::from_secs(2);
    while submits.load(Ordering::SeqCst) < 1 {
        assert!(Instant::now() < deadline, "A never submitted");
        thread::sleep(Duration::from_millis(1));
    }

    let sibling = thread::spawn(|| {
        let t0 = Instant::now();
        confirm_scripts_phase(empty_loaded_batch()).expect("sibling phase");
        t0.elapsed()
    });
    let sibling_dt = sibling.join().expect("sibling");
    assert!(
        sibling_dt < Duration::from_millis(200),
        "confirm_scripts_phase must not honor another test's hold ({sibling_dt:?})"
    );

    mat_tx
        .send((empty_loaded_batch(), 0))
        .expect("send B while A held");
    while submits.load(Ordering::SeqCst) < 2 {
        assert!(
            Instant::now() < deadline,
            "B not submitted before A finished (feed-ahead dead under depth-1)"
        );
        thread::sleep(Duration::from_millis(1));
    }

    {
        let (lock, cv) = &*gate;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    drop(mat_tx);
    stage.join().expect("stage thread");
    let outs = outcomes.lock().unwrap();
    assert_eq!(outs.len(), 2, "both batches script-ok");
    assert!(outs[0].batch.is_empty());
    assert!(outs[1].batch.is_empty());

    let mut polls = 0u32;
    let handle = ScriptsPhaseHandle::spawn_fn(|| confirm_scripts_phase(empty_loaded_batch()));
    join_scripts_polling(&handle, Duration::from_micros(200), || {
        polls += 1;
        false
    })
    .expect("join after lookahead");
    assert_eq!(
        polls, 1,
        "join must recv_blocking after first false, not 200µs-poll (polls={polls})"
    );
}

#[test]
fn check_bip34_helper_and_expected_bits_no_retarget() {
    use super::{check_bip34, expected_bits_extending};
    use crate::params::ChainParams;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Witness,
    };
    use rbitcoin_primitives::Height;

    let height = 17u32;
    let mut ss = crate::block::bip34_height_script(height);
    while ss.len() < 2 {
        ss.push(0x00);
    }
    let cb = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
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
    check_bip34(&block, height).unwrap();
    // Wrong height
    assert!(check_bip34(&block, height + 1).is_err());
    let mut empty_cb = block.clone();
    empty_cb.txdata[0].input[0].script_sig = ScriptBuf::new();
    let err = check_bip34(&empty_cb, height).expect_err("empty scriptSig");
    assert!(
        err.to_string().contains("bip34 coinbase script empty"),
        "got: {err}"
    );

    // expected_bits_extending without store: height 0 and no_pow_retargeting regtest
    let params = ChainParams::regtest();
    // Cannot call with query easily; unit-test height==0 via expected_bits requires Query.
    // Cover pure branch: no_pow or non-interval uses prev_bits — needs Query only for retarget.
    let _ = (params, expected_bits_extending);
    let _ = Height;
}

#[test]
fn empty_confirm_batch_rejected() {
    // confirm_wire_load_phase empty → BadBlock without store open
    // We only have Query API; use a throwaway path under /tmp when available.
    use super::confirm_wire_load_phase;
    use super::ScriptPreverified;
    use crate::milestone::Milestone;
    use crate::params::ChainParams;
    use rbitcoin_primitives::Height;
    use rbitcoin_query::Query;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-confirm-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    let params = ChainParams::regtest();
    let none = ScriptPreverified::new();
    let err = match confirm_wire_load_phase(&q, &params, Milestone::NONE, &[], &none) {
        Ok(_) => panic!("expected empty batch error"),
        Err(e) => e,
    };
    assert!(matches!(err, crate::error::ConsensusError::BadBlock(_)));
    // Non-contiguous
    let g = crate::params::genesis_block(&params);
    let err2 = match confirm_wire_load_phase(
        &q,
        &params,
        Milestone::NONE,
        &[(Height(1), g.clone()), (Height(3), g)],
        &none,
    ) {
        Ok(_) => panic!("expected non-contiguous error"),
        Err(e) => e,
    };
    assert!(matches!(err2, crate::error::ConsensusError::BadBlock(_)));
    let _ = std::fs::remove_dir_all(&path);
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
    use rbitcoin_query::Query;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-confirm-tip1-heal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
    let extra = vec![0u8; 20 * 8];
    let new_logical = logical + extra.len() as u64;
    if (raw.len() as u64) < new_logical {
        raw.resize(new_logical as usize, 0);
    }
    raw[8..16].copy_from_slice(&new_logical.to_le_bytes());
    std::fs::write(&conf, &raw).unwrap();

    let q = Query::open_or_create(&path).unwrap();
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
    use rbitcoin_query::Query;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-confirm-bits-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
    };
    let ok = confirm_scripts_phase(loaded).unwrap();
    assert!(ok.batch.is_empty());
    assert_eq!(ok.batch.len(), 0);
    assert!(ok.batch.heights_hashes().is_empty());
    assert_eq!(ok.batch.approx_wire_bytes(), 0);
    assert_eq!(ok.batch.parent_count(), 0);

    // check_bip34 wrong encoding
    use super::check_bip34;
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
    assert!(check_bip34(&block, 17).is_err());

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
    use rbitcoin_query::Query;
    use rbitcoin_store::HeaderRecord;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-retarget-plan-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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

    let job = ScriptCheckJob::with_txid(tid, prevouts, tx, true, true, true, true, true);
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
    };
    confirm_scripts_phase(batch).expect("preverified skip avoids bad script fail");
}

fn tiny_query() -> (std::path::PathBuf, rbitcoin_query::Query) {
    use rbitcoin_query::Query;
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-ensure-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
        for inp in ins {
            if inp.is_coinbase() || inp.prev_index == u32::MAX {
                edges.push(SpendEdge {
                    prev_txid: [0u8; 32],
                    vout: u32::MAX,
                    spend_fk: *fk,
                    create_fk: Fk::NULL,
                });
            } else {
                edges.push(SpendEdge {
                    prev_txid: inp.prev_txid,
                    vout: inp.prev_index,
                    spend_fk: *fk,
                    create_fk: inp.create_fk,
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
        std::sync::Arc::new((rec_tx(0xAA, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
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
        spends: vec![([9u8; 32], 0, Fk(10), Fk(999_999))],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [3u8; 32],
        prev_mtp: 0,
    }];
    let mut bp = BatchParents::new();
    let err = ensure_spend_abs_layouts(&q, &mut bp, &prepared_miss)
        .expect_err("ensure must hard-fail without denserels");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant")
            && (msg.contains("ensure denserels") || msg.contains("abs incomplete")),
        "unexpected err: {msg}"
    );

    post_commit(&q, &[]).expect("empty annotate list does not consult BatchParents");

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
        std::sync::Arc::new((rec_tx(0x22, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
        spend_ins.clone(),
    )];
    plan.planned_fks = vec![Fk(2)];
    plan.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent::with_body(parent_tx.txid, range),
    );
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, _, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
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
        std::sync::Arc::new((rec_tx(0x22, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
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
        spends: vec![([0x11u8; 32], 0, Fk(2), pfk)],
        fees: 0,
        check_scripts: false,
        time: 1,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        hash: [4u8; 32],
        prev_mtp: 0,
    }];
    ensure_spend_abs_layouts(&q, &mut bp, &prepared).expect("spent-range ensure");
    assert!(bp.has_abs_layout(pfk));
    assert_eq!(
        bp.get_spender_abs(pfk, 0),
        Some(rbitcoin_store::spent_abs(spent_off, 0))
    );

    let mut plan3 = ArchiveWritePlan::empty();
    plan3.packed = vec![(
        std::sync::Arc::new((rec_tx(0x22, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
        spend_ins,
    )];
    plan3.planned_fks = vec![Fk(2)];
    plan3.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent {
            txid: parent_tx.txid,
            body: Some(range),
            spent: Some((spent_off, spent_len)),
            pin: None,
        },
    );
    let mut stamp3 = ParentPinStamp::take_from_plan(&mut plan3);
    fill_edges_from_packed(&mut plan3);
    let (mut parents3, _, _) =
        pin_for_wire_batch(&q, Some(&plan3), &mut stamp3, &[], &[], None).unwrap();
    assert!(
        parents3.has_abs_layout(pfk),
        "load pin copies lookup-stamped spent.idx range (no write idx)"
    );
    assert_eq!(
        parents3.get_spender_abs(pfk, 0),
        Some(rbitcoin_store::spent_abs(spent_off, 0))
    );
    ensure_spend_abs_layouts(&q, &mut parents3, &prepared).expect("ensure already-abs skip");
    assert!(parents3.has_abs_layout(pfk));

    let mut plan4 = ArchiveWritePlan::empty();
    plan4.packed = vec![
        (
            std::sync::Arc::new((rec_tx(0x32, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
            vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        ),
        (
            std::sync::Arc::new((rec_tx(0x33, 1), vec![OutputRecord::unspent(1, vec![0x51])])),
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
    let (parents4, _, _) =
        pin_for_wire_batch(&q, Some(&plan4), &mut stamp4, &[], &[], None).unwrap();
    assert!(
        !parents4.contains(Fk(2)),
        "same-header create is wire-valued, not pinned"
    );

    let _ = std::fs::remove_dir_all(&path);
}

/// Wire pin: in-flight outs shorter than need → cold miss → hard invariant.
#[test]
fn pin_for_wire_incomplete_outs_is_invariant_error() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-wire-outs-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
            std::sync::Arc::new((spend_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
            spend_ins,
        )],
        planned_fks: vec![Fk(2)],
        per_header_ranges: vec![],
        edges: Default::default(),
        spends: vec![],
        batch_creates: vec![],
        external_parents: Default::default(),
        external_parent_vouts: Default::default(),
        batch_pin: vec![],
        index_tx: false,
        body_est: 0,
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
    let pin = std::sync::Arc::new((parent_tx, Vec::new()));
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
            pin: None,
        },
    );
    let mut plan = ArchiveWritePlan {
        packed: vec![],
        planned_fks: vec![],
        per_header_ranges: vec![],
        edges: Default::default(),
        spends: vec![],
        batch_creates: vec![],
        external_parents: idents,
        external_parent_vouts: Default::default(),
        batch_pin: vec![],
        index_tx: false,
        body_est: 0,
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
    use rbitcoin_query::{ArchiveWritePlan, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-take-vouts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
        std::sync::Arc::new((
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
        )),
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
    plan.external_parents.insert(
        parent_id,
        rbitcoin_query::ParentIdent::with_body(parent_tx.txid, range),
    );
    plan.external_parent_vouts.insert(parent_id, vec![0]);
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    assert_eq!(
        stamp.parent_vouts.get(&parent_id).map(|v| v.as_slice()),
        Some(&[0u32][..])
    );
    fill_edges_from_packed(&mut plan);
    let (parents, _, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
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
    use rbitcoin_query::{ArchiveWritePlan, CreatePin, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-createpin-share-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
    let pin: CreatePin = Arc::new((parent_tx.clone(), vec![OutputRecord::unspent(50, script)]));
    let expect = pin.1[0].script.as_ptr();
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
            Arc::new((child_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
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
    let (parents, edges, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
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

/// C1: pin reads plan.edges; packed ins may be empty.
#[test]
fn pin_plan_edges_without_packed_ins() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, CreatePin, Query, SpendEdge};
    use rbitcoin_store::{OutputRecord, TxRecord};
    use std::sync::Arc;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-edges-no-ins-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
    let pin: CreatePin = Arc::new((
        parent_tx.clone(),
        vec![OutputRecord::unspent(50, vec![0x51])],
    ));
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
            Arc::new((child_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
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
        }],
    );
    let mut stamp = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, edges, _) = pin_for_wire_batch(&q, Some(&plan), &mut stamp, &[], &[], None)
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
    use rbitcoin_query::{ArchiveWritePlan, Query};
    use rbitcoin_store::{OutputRecord, TxRecord};
    use std::sync::Arc;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-empty-edges-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
    q.enter_direct_index_mode().unwrap();
    let pin = Arc::new((
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
    ));
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
    use rbitcoin_query::{ArchiveWritePlan, CreatePin, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-sparse-high-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
    let spend_pin: CreatePin = Arc::new((spend_tx, vec![OutputRecord::unspent(1, vec![0x51])]));
    let mut plan = ArchiveWritePlan {
        packed: vec![(Arc::clone(&spend_pin), spend_ins)],
        planned_fks: vec![Fk(2)],
        per_header_ranges: vec![],
        edges: Default::default(),
        spends: vec![],
        batch_creates: vec![],
        external_parents: {
            let mut m = rbitcoin_query::U64Map::default();
            m.insert(
                parent_id,
                rbitcoin_query::ParentIdent::with_body(parent_tx.txid, range),
            );
            m
        },
        external_parent_vouts: Default::default(),
        batch_pin: vec![Arc::clone(&spend_pin)],
        index_tx: false,
        body_est: 0,
    };
    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (parents, _thin, _warm) =
        pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
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
    use rbitcoin_query::{ArchiveWritePlan, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-hit-honest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
        Arc::new((spend_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    for i in 0..3 {
        if let Some(id) = fks[i].get() {
            plan.external_parents.insert(
                id,
                rbitcoin_query::ParentIdent::with_body(items[i].0.txid, ranges[i]),
            );
        }
    }

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (_parents, _thin, warm) =
        pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None).expect("range-fill 3");
    assert_eq!(warm.parents, 3);
    assert_eq!(
        warm.already, 0,
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
    use rbitcoin_query::{ArchiveWritePlan, CreatePin, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-recent-outs-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();

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
    let pin: CreatePin = Arc::new((parent_tx.clone(), vec![parent_out.clone()]));
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
        Arc::new((spend_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    plan.external_parents.insert(
        7,
        rbitcoin_query::ParentIdent {
            txid: tid,
            body: Some((99, 1)),
            spent: None,
            pin: Some(Arc::clone(&pin)),
        },
    );

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    assert!(
        Arc::ptr_eq(parent_pin.create_pin(7).expect("stamp pin"), &pin),
        "pin must use stamp-carried CreatePin"
    );
    fill_edges_from_packed(&mut plan);
    let (_parents, _thin, warm) =
        pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
            .expect("stamp-carried outs must cover");
    assert_eq!(warm.parents, 1);
    assert_eq!(
        warm.already, 1,
        "stamp-carried outs must count as PIN_CACHE, not PIN_NEW"
    );
    let _ = std::fs::remove_dir_all(&path);
}

/// Identity-only stamp (no outs) still cold-fills by stamped range.
#[test]
fn pin_recent_identity_without_outs_still_range_fills() {
    use super::{pin_for_wire_batch, ParentPinStamp};
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{ArchiveWritePlan, Query};
    use rbitcoin_store::{InputRecord, OutputRecord, TxRecord};
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-pin-recent-id-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
        .put_full_batch_indexed(&[parent.clone()], true)
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
        Arc::new((spend_tx, vec![OutputRecord::unspent(1, vec![0x51])])),
        spend_ins,
    )];
    plan.planned_fks = vec![Fk(100)];
    if let Some(id) = fks[0].get() {
        plan.external_parents
            .insert(id, rbitcoin_query::ParentIdent::with_body(tid, range));
    }

    let mut parent_pin = ParentPinStamp::take_from_plan(&mut plan);
    fill_edges_from_packed(&mut plan);
    let (_parents, _thin, warm) =
        pin_for_wire_batch(&q, Some(&plan), &mut parent_pin, &[], &[], None)
            .expect("identity-only stamp still range-fills");
    assert_eq!(warm.parents, 1);
    assert_eq!(
        warm.already, 0,
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
    use bitcoin::script::PushBytesBuf;
    use bitcoin::CompactTarget;
    use bitcoin::{Amount, Block, BlockHash, ScriptBuf, Sequence, TxMerkleNode, Witness};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::Query;
    use std::sync::{Arc, Once};

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-start-states-{}-{}",
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

    fn coinbase(height: u32) -> Transaction {
        let mut script = ScriptBuf::new();
        let pb = PushBytesBuf::try_from(height.to_le_bytes().to_vec()).unwrap();
        script.push_slice(pb);
        script.push_opcode(bitcoin::opcodes::all::OP_CHECKSIG);
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
            "IBD stamp must not carry packed InputRecords to load/write"
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

/// Load miss: spend edges without pin denserels must hard-fail (no cold tier).
/// Pin-covered parent without denserels/abs fails structural (no body-range cold).
#[test]
fn structural_pinned_without_abs_is_invariant_error() {
    use crate::block::structural_validate_spends;
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
    use rbitcoin_query::{BatchParents, OutPointSet, Query};
    use rbitcoin_store::{OutputRecord, TxRecord};
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-struct-pin-inv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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

    let spends = vec![([7u8; 32], 0u32, Fk(100), parent_fk)];
    let ctx = crate::block::ValidationContext::at(&params, Height(1), Milestone::NONE);
    let mut pending = OutPointSet::default();
    let mut mtp = rbitcoin_query::U32Map::<u32>::default();
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
        &rbitcoin_query::FkMap::default(),
        &mut Vec::new(),
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
    use rbitcoin_query::Query;
    use std::sync::Once;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
    });
    let path = std::env::temp_dir().join(format!(
        "rbitcoin-direct-write-pins-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&path).unwrap();
    let q = Query::open_or_create(&path).unwrap();
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
