use super::*;
use crate::testutil::FixtureChain;
use rbitcoin_store::{InputRecord, OutputRecord, TxRecord, TxStatRow};

#[test]
fn query_open_clears_strong_above_tip() {
    let (dir, q) = temp_query("open-repair-above-tip");
    let (mut h0, _) = coinbase_block(0, Fk::NULL, None);
    h0.hash = rbitcoin_store::block_header_hash(
        h0.version,
        &[0u8; 32],
        &h0.merkle_root,
        h0.timestamp,
        h0.bits,
        h0.nonce,
    );
    let hfk = q.put_header(&h0).unwrap();
    q.store().confirmed.set(Height(0), hfk).unwrap();
    q.store().rebuild_height_fence().unwrap();
    let leftover = Fk(99);
    q.store().strong_tx.set_strong(leftover, hfk).unwrap();
    q.store().flush_class_c_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert!(q.store().strong_tx.is_strong(leftover).unwrap());
    drop(q);

    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_eq!(
        q.tip_height(),
        Some(Height(0)),
        "repair must not shrink tip"
    );
    assert!(
        !q.store().strong_tx.is_strong(leftover).unwrap(),
        "open must clear leftover strong above the fence"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uring_recover_credit_gap() {
    assert!(uring_recover_credit(None, 0));
    assert!(!uring_recover_credit(Some(0), 0));
    assert!(!uring_recover_credit(Some(0), 144));
    assert!(!uring_recover_credit(Some(0), 999));
    assert!(uring_recover_credit(Some(0), 1000));
    assert!(uring_recover_credit(Some(100), 1100));
}

#[test]
fn uring_recover_credit_once_per_window_does_not_repair() {
    let (_d, q) = temp_query("uring-recover");
    let leftover = Fk(99);
    q.store().strong_tx.set_strong(leftover, Fk(1)).unwrap();
    q.store().flush_class_c_tip().unwrap();
    assert!(q.store().strong_tx.is_strong(leftover).unwrap());
    assert_eq!(q.uring_recover("test"), UringRecover::Recovered);
    assert!(
        q.store().strong_tx.is_strong(leftover).unwrap(),
        "in-process recover must not mutate Class C; leftover strong waits for open repair"
    );
    q.store().strong_tx.set_strong(leftover, Fk(1)).unwrap();
    q.store().flush_class_c_tip().unwrap();
    assert_eq!(q.uring_recover("again"), UringRecover::Exhausted);
}

#[test]
fn uring_recover_cas_second_claim_at_same_tip_is_exhausted() {
    let (_d, q) = temp_query("uring-recover-cas");
    assert_eq!(q.uring_recover("a"), UringRecover::Recovered);
    assert_eq!(q.uring_recover("b"), UringRecover::Exhausted);
}

#[test]
fn uring_recover_or_abort_takes_credit() {
    let (_d, q) = temp_query("uring-recover-or-abort");
    q.uring_recover_or_abort("test");
    assert_eq!(q.uring_recover("again"), UringRecover::Exhausted);
}

#[test]
fn held_pread_fault_string_exhausts_lookup_recover_at_same_tip() {
    use rbitcoin_store::StoreError;
    assert!(
        StoreError::Corrupt("invariant: io_uring held pread failed").is_uring_session_fault(),
        "if loc still emitted this, lookup would recover then abort"
    );
    let (_d, q) = temp_query("held-pread-lookup-abort");
    assert_eq!(
        q.uring_recover("ibd-confirm-lookup"),
        UringRecover::Recovered
    );
    assert_eq!(
        q.uring_recover("ibd-confirm-lookup"),
        UringRecover::Exhausted,
        "second fault in the same 1000-height window aborts IBD"
    );
}

fn temp_query(label: &str) -> (crate::testutil::TempDir, Query) {
    crate::testutil::tiny_query_labeled(label)
}

#[test]
fn lookup_started_hi_none_until_set() {
    let (dir, q) = temp_query("started-hi");
    assert!(q.lookup_started_hi().is_none());
    assert!(q.class_a_hi().is_none());
    q.set_lookup_started_hi(Some(4));
    q.set_class_a_hi(Some(2));
    assert_eq!(q.lookup_started_hi(), Some(4));
    assert_eq!(q.class_a_hi(), Some(2));
    q.set_lookup_started_hi(None);
    assert!(q.lookup_started_hi().is_none());
    q.note_lookup_tiponly_start(12);
    assert_eq!(q.lookup_started_hi(), Some(12));
    q.note_lookup_tiponly_start(7);
    assert_eq!(
        q.lookup_started_hi(),
        Some(12),
        "TipOnly start must never rewind"
    );
    q.note_lookup_tiponly_start(40);
    assert_eq!(q.lookup_started_hi(), Some(40));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn query_sh_heads_capped_after_append_miss_still_writes() {
    use rbitcoin_store::{script_hash, ScriptHashRecord, ShHeadValue, SH_HEADS_CAP};
    let (dir, q) = temp_query("sh-heads-cap");
    {
        let mut heads = q.sh.heads.lock().unwrap();
        for i in 0..SH_HEADS_CAP as u64 {
            let mut k = [0xEE; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            heads.insert(k, ShHeadValue::Empty);
        }
    }
    let sh = script_hash(&[0x51]);
    {
        let mut heads = q.sh.heads.lock().unwrap();
        let rec = ScriptHashRecord::from_fk(sh, Fk(1));
        q.store()
            .scripthash
            .put_create_batch_append(&[rec], &mut heads)
            .unwrap();
    }
    assert!(
        q.process_owned_size_snapshot().sh_heads <= SH_HEADS_CAP,
        "sh_heads={}",
        q.process_owned_size_snapshot().sh_heads
    );
    assert_eq!(q.store().scripthash.entries(&sh).unwrap().len(), 1);

    let evicted = {
        let heads = q.sh.heads.lock().unwrap();
        (0..SH_HEADS_CAP as u64).find_map(|i| {
            let mut k = [0xEE; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            (!heads.contains_key(&k)).then_some(k)
        })
    };
    if let Some(evicted) = evicted {
        let rec = ScriptHashRecord::from_fk(evicted, Fk(2));
        {
            let mut heads = q.sh.heads.lock().unwrap();
            q.store()
                .scripthash
                .put_create_batch_append(&[rec], &mut heads)
                .unwrap();
        }
        assert_eq!(q.store().scripthash.entries(&evicted).unwrap().len(), 1);
        assert!(q.process_owned_size_snapshot().sh_heads <= SH_HEADS_CAP);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Write-gate-safe: non-null `prev` requires `parent_hash` committed in header hash.
fn coinbase_block(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
    let version = 1;
    let timestamp = h + 1;
    let bits = 0x207fffff;
    let nonce = h;
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&h.to_le_bytes());
    merkle[4] = 0xab;
    let hash = match parent_hash {
        None => merkle,
        Some(ph) => {
            rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
        }
    };
    let header = HeaderRecord {
        prev_fk: prev,
        version,
        timestamp,
        bits,
        nonce,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    let mut txid = [0u8; 32];
    txid[0..4].copy_from_slice(&h.to_le_bytes());
    txid[31] = 0xcb;
    let ta = TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![h as u8],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    };
    (header, ta)
}

fn rehash_header(h: &mut HeaderRecord, parent_hash: &[u8; 32]) {
    h.hash = rbitcoin_store::block_header_hash(
        h.version,
        parent_hash,
        &h.merkle_root,
        h.timestamp,
        h.bits,
        h.nonce,
    );
}

fn replace_tip_same_height(
    q: &Query,
    height: u32,
    prev_fk: Fk,
    parent_hash: [u8; 32],
    nonce_delta: u32,
) -> (HeaderRecord, TxApply) {
    q.disconnect_tip().unwrap();
    let (mut h, t) = coinbase_block(height, prev_fk, Some(parent_hash));
    h.nonce = h.nonce.wrapping_add(nonce_delta);
    rehash_header(&mut h, &parent_hash);
    q.connect_block(Height(height), &h, std::slice::from_ref(&t))
        .unwrap();
    (h, t)
}

fn funded_op_true_coinbase(
    h: u32,
    prev: Fk,
    parent_hash: Option<[u8; 32]>,
) -> (HeaderRecord, TxApply) {
    let (hdr, mut ta) = coinbase_block(h, prev, parent_hash);
    ta.outputs = vec![OutputRecord::unspent(10_0000_0000, vec![0x51])];
    (hdr, ta)
}

fn spend_op_true(
    hfk0: Fk,
    hash0: [u8; 32],
    create_fk: Fk,
    create_txid: [u8; 32],
) -> (HeaderRecord, TxApply, [u8; 32]) {
    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    let hash1 = rbitcoin_store::block_header_hash(1, &hash0, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
        size: 0,
        weight: 0,
    };
    let spend = TxApply {
        tx: TxRecord {
            txid: spend_txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: create_txid,
            create_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
    };
    (h1, spend, spend_txid)
}

/// Slow-pin log is only emitted when load work_ms > 2s — keep the formatter unit.
#[test]
fn format_slow_pin_omits_retired_tokens() {
    assert_eq!(LastPinPhases::ms(2_000_000), 2);
    let zero = LastPinPhases {
        plan_pin_ns: 22,
        cold_ns: 33,
        contract_ns: 44,
        pin_plan_n: 100,
        pin_new_n: 9,
    };
    let slow = zero.format_slow_pin();
    assert!(!slow.contains("adopt="), "{slow}");
    assert!(!slow.contains("publish="), "{slow}");
    assert_eq!(slow, "pin(plan=0ms/n=100 cold=0ms/n=9 contract=0ms)");
    let stuffed = LastPinPhases {
        plan_pin_ns: 1_000_000,
        cold_ns: 2_000_000,
        contract_ns: 3_000_000,
        pin_plan_n: 7,
        pin_new_n: 8,
    };
    let stuffed_line = stuffed.format_slow_pin();
    assert!(!stuffed_line.contains("adopt="), "{stuffed_line}");
    assert!(!stuffed_line.contains("publish="), "{stuffed_line}");
    assert_eq!(stuffed_line, "pin(plan=1ms/n=7 cold=2ms/n=8 contract=3ms)");
}

fn prepared_at(q: &Query, height: Height, header_fk: Fk) -> ConfirmPrepared {
    ConfirmPrepared {
        height,
        header_fk,
        tx_fks: q
            .header_tx_fks(header_fk, None)
            .unwrap()
            .expect("archived body"),
    }
}

fn assert_height(q: &Query, hash: &[u8; 32], height: u32) {
    assert_eq!(
        q.height_of_hash(hash).unwrap(),
        Some(Height(height)),
        "hash at {height}"
    );
}

fn h2h_pad_0_4(q: &Query) -> Vec<[u8; 32]> {
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let mut hashes = vec![h0.hash];
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev0 = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev0, Some(hashes[0]));
    hashes.push(h1.hash);
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    let mut prev = q.tip_header_fk().unwrap().unwrap();
    let mut parent = hashes[1];
    let mut run = Vec::new();
    for h in 2u32..=4 {
        let (header, ta) = coinbase_block(h, prev, Some(parent));
        let fk = q
            .commit_class_a_only(&header, std::slice::from_ref(&ta))
            .unwrap();
        hashes.push(header.hash);
        run.push(prepared_at(q, Height(h), fk));
        prev = fk;
        parent = header.hash;
    }
    q.confirm_blocks_run(&run).unwrap();
    hashes
}

/// A concurrent disconnect can shrink `confirmed[]` between a reader's tip
/// snapshot and its height-index walk. No single session interleaves that,
/// so the stale-snapshot retry and the empty-chain arms stay a unit.
#[test]
fn height_of_hash_stale_snapshot_after_confirmed_shrink_is_none() {
    let (dir, q) = temp_query("h2h-stale");
    let hashes = h2h_pad_0_4(&q);
    q.invalidate_height_by_hash_index();
    q.store
        .confirmed
        .disconnect_tip(Height(4))
        .expect("shrink confirmed without map ensure");
    q.store.height_fence_pop_tip(Height(4));
    assert_eq!(q.tip_height(), Some(Height(3)));
    q.ensure_height_by_hash_index(Height(4))
        .expect("stale snapshot of old tip retries live tip");
    assert!(
        q.height_of_hash(&hashes[4]).unwrap().is_none(),
        "disconnected tip hash is not confirmed"
    );
    assert_height(&q, &hashes[3], 3);

    while let Some(h) = q.tip_height() {
        q.store.confirmed.disconnect_tip(h).unwrap();
        q.store.height_fence_pop_tip(h);
    }
    q.ensure_height_by_hash_index(Height(5))
        .expect("unpublished height with no tip clears the map");
    assert!(q.height_of_hash(&hashes[0]).unwrap().is_none());
    let empty_fill = q
        .ensure_height_by_hash_index(Height(0))
        .expect_err("empty confirmed[] is not a tip-0 map");
    assert!(
        empty_fill.to_string().contains("height_by_hash"),
        "{empty_fill}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sh_writebehind_does_not_seed_until_release() {
    let (dir, q) = temp_query("sh-no-seed-until-release");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    q.confirm_block(Height(0), &h0.hash).unwrap();

    assert_eq!(q.sh_indexed_through_height(), None);
    assert!(
        q.take_sh_job_for_apply().is_none(),
        "durable apply must not take an unreleased job"
    );
    let sh = script_hash(&[0x51]);
    assert_eq!(
        q.scripthash_history(&sh).unwrap().len(),
        1,
        "pending records must still be visible before release"
    );
    let written0 = q
        .confirm_stats()
        .sh_written_n
        .load(std::sync::atomic::Ordering::Relaxed);

    q.release_index_writebehind(Height(0));
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);
    let written1 = q
        .confirm_stats()
        .sh_written_n
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        written1 >= written0,
        "release+apply must be allowed to write durable SH"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Write-behind syncs the scripthash tables before `include_hwm` claims their
/// creates (a power cut must not leave the HWM ahead of body/head bytes):
/// once for a burst of queued catch-up jobs, once for a released tip job.
#[test]
fn sh_writebehind_syncs_tables_before_include_hwm() {
    let (dir, q) = temp_query("sh-sync-before-hwm");
    let mut prev = Fk::NULL;
    let mut parent = None;
    let mut connect = |h: u32| {
        let (header, ta) = coinbase_block(h, prev, parent);
        q.commit_class_a_only(&header, &[ta]).unwrap();
        prev = q.confirm_block(Height(h), &header.hash).unwrap();
        parent = Some(header.hash);
    };
    for h in 0..=2 {
        connect(h);
    }
    let _ = q.confirm_stats().take_window();
    q.apply_sh_pending().unwrap();
    let burst = q.confirm_stats().take_window();
    assert_eq!(q.sh_indexed_through_height(), Some(2));
    let hwm_burst = q.store().scripthash.include_hwm();
    assert!(hwm_burst > 0, "burst advanced the durable HWM");
    assert_eq!(burst.sh_sync_n, 1, "a queued burst syncs once");

    connect(3);
    q.release_index_writebehind(Height(3));
    q.apply_sh_pending().unwrap();
    let tip = q.confirm_stats().take_window();
    assert!(q.store().scripthash.include_hwm() > hwm_burst);
    assert_eq!(tip.sh_sync_n, 1, "a released tip job syncs before its HWM");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ram_sh_head_lookup_is_per_scripthash() {
    let (dir, q) = temp_query("ram-sh-head");
    let (h0, mut t0) = coinbase_block(0, Fk::NULL, None);
    t0.tx.output_count = 2;
    t0.outputs = vec![
        OutputRecord::unspent(25_0000_0000, vec![0x51]),
        OutputRecord::unspent(25_0000_0000, vec![0x52]),
    ];
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    q.confirm_block(Height(0), &h0.hash).unwrap();
    let sha = script_hash(&[0x51]);
    let shb = script_hash(&[0x52]);
    let fa = q.pending_sh_create_fks(&sha);
    let fb = q.pending_sh_create_fks(&shb);
    assert_eq!(fa.len(), 1, "script A must hit only its pending fks");
    assert_eq!(fb.len(), 1, "script B must hit only its pending fks");
    assert_eq!(fa, fb, "same create tx funds both scripts");
    assert!(q.pending_sh_create_fks(&[0u8; 32]).is_empty());
    q.apply_sh_pending().unwrap();
    assert!(
        q.pending_sh_create_fks(&sha).is_empty(),
        "apply must drop RAM-head keys"
    );
    assert_eq!(q.scripthash_history(&sha).unwrap().len(), 1);
    assert_eq!(q.scripthash_history(&shb).unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_sh_pending_writes_creates_and_advances_watermark() {
    let (dir, q) = temp_query("apply-sh-pending");
    assert!(q.index_mode().is_tip());

    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    q.confirm_block(Height(0), &h0.hash).unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert_eq!(q.sh_indexed_through_height(), None);

    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    let sh = script_hash(&[0x51]);
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].height, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `apply_sh_pending` must wait out an in-flight job (worker vs generate drain).
#[test]
fn apply_sh_pending_waits_for_in_flight_job() {
    use std::sync::Arc;
    let (dir, q) = temp_query("apply-sh-wait-inflight");
    let q = Arc::new(q);
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    q.confirm_block(Height(0), &h0.hash).unwrap();
    assert_eq!(q.sh_indexed_through_height(), None);
    q.release_index_writebehind(Height(0));

    let stolen = q.take_sh_job_for_apply().expect("enqueued genesis");
    let height = Height(0);
    let q_apply = Arc::clone(&q);
    let done = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        q_apply.apply_sh_job(stolen).unwrap();
        q_apply.finish_sh_job(height);
    });
    q.apply_sh_pending().unwrap();
    assert_eq!(
        q.sh_indexed_through_height(),
        Some(0),
        "drain must wait until the in-flight job is watermarked"
    );
    done.join().unwrap();
    let sh = script_hash(&[0x51]);
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn apply_sh_pending_two_drainers_cover_both_heights() {
    use std::sync::Arc;
    let (dir, q) = temp_query("apply-sh-two-drainers");
    let q = Arc::new(q);
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    q.confirm_block(Height(0), &h0.hash).unwrap();
    let prev = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev, Some(hash0));
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();

    let a = {
        let q = Arc::clone(&q);
        std::thread::spawn(move || q.apply_sh_pending())
    };
    let b = {
        let q = Arc::clone(&q);
        std::thread::spawn(move || q.apply_sh_pending())
    };
    a.join().unwrap().unwrap();
    b.join().unwrap().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    let sh = script_hash(&[0x51]);
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sh_writebehind_recover_requeues_unapplied_heights() {
    let (dir, q) = temp_query("sh-wb-recover");
    let (mut h0, t0) = coinbase_block(0, Fk::NULL, None);
    h0.merkle_root = t0.tx.txid;
    h0.hash = rbitcoin_store::block_header_hash(
        h0.version,
        &[0u8; 32],
        &h0.merkle_root,
        h0.timestamp,
        h0.bits,
        h0.nonce,
    );
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    q.finalize_sh_runs().unwrap();
    assert!(
        q.store().scripthash.has_durable_index(),
        "write-behind recover requires a pack-complete head"
    );
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (mut h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    h1.merkle_root = t1.tx.txid;
    rehash_header(&mut h1, &hash0);
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();
    q.store().flush_class_c_tip().unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    let sh = script_hash(&[0x51]);
    assert_eq!(
        q.scripthash_history(&sh).unwrap().len(),
        2,
        "requeued pending records must be visible before durable apply"
    );
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recover_sh_writebehind_fails_open_on_interior_missing_header_txs() {
    let (dir, q) = temp_query("sh-wb-recover-corrupt");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev0 = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev0, Some(hash0));
    let hash1 = h1.hash;
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    let hfk1 = q.confirm_block(Height(1), &hash1).unwrap();
    let (h2, t2) = coinbase_block(2, hfk1, Some(hash1));
    q.commit_class_a_only(&h2, &[t2]).unwrap();
    q.confirm_block(Height(2), &h2.hash).unwrap();
    assert!(q.store().header_txs.clear_body(hfk1).unwrap());
    let err = q.recover_sh_writebehind().expect_err("interior hole");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant:") || msg.contains("missing"),
        "expected invariant/missing body, got {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recover_sh_writebehind_skips_bodyless_structural_tip() {
    let (dir, q) = temp_query("sh-wb-recover-tip-nobody");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev0 = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev0, Some(hash0));
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    let hfk1 = q.confirm_block(Height(1), &h1.hash).unwrap();
    q.release_index_writebehind(Height(1));
    let _stolen = q.take_sh_job_for_apply().expect("height-1 job");
    q.finish_sh_job(Height(1));
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert!(q.store().header_txs.clear_body(hfk1).unwrap());
    q.recover_sh_writebehind()
        .expect("body-less structural tip must not fail open");
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    assert!(
        q.sh_pending_max_height().is_none() || q.sh_pending_max_height().unwrap() < 1,
        "body-less tip must not be re-queued"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn request_sh_writebehind_halt_sets_stop() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let stop = AtomicBool::new(false);
    crate::connect::request_sh_writebehind_halt(&stop, 7, &"apply failed");
    assert!(
        stop.load(Ordering::SeqCst),
        "apply error must request process stop so the node exits"
    );
}

/// Pending write-behind records join at live tip so a confirmed spend is
/// visible even though durable SH (and mempool) have already moved on.
#[test]
fn sh_pending_records_join_at_live_tip_before_apply() {
    let (dir, q) = temp_query("sh-pin-watermark");
    let (h0, ta0) = funded_op_true_coinbase(0, Fk::NULL, None);
    let create_txid = ta0.tx.txid;
    let hash0 = h0.hash;
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let sh = script_hash(&[0x51]);
    assert_eq!(q.scripthash_listunspent(&sh).unwrap().len(), 1);
    assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 10_0000_0000);

    let (h1, spend, spend_txid) = spend_op_true(hfk0, hash0, create_fk, create_txid);
    let hash1 = h1.hash;
    q.commit_class_a_only(&h1, &[spend]).unwrap();
    q.confirm_block(Height(1), &hash1).unwrap();

    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    assert!(q.is_outpoint_spent(&create_txid, 0).unwrap());

    let sh_view = q
        .pin_sh_chain_view()
        .unwrap()
        .expect("SH view follows pending");
    assert_eq!(sh_view.height, Height(1));
    assert_eq!(sh_view.hash, hash1);
    let live = q.pin_chain_view().unwrap().expect("live tip");
    assert_eq!(live.height, Height(1));

    assert!(
        q.scripthash_listunspent(&sh).unwrap().is_empty(),
        "pending join at live tip must show the spend (mempool already dropped it)"
    );
    assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 0);
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(hist.len(), 2);
    assert!(hist.iter().any(|i| i.txid == create_txid));
    assert!(hist.iter().any(|i| i.txid == spend_txid));

    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    let sh_view = q.pin_sh_chain_view().unwrap().expect("SH caught up");
    assert_eq!(sh_view.height, Height(1));
    assert_eq!(sh_view.hash, hash1);
    assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());
    assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 0);
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Worker / drain must not hide pending creates between pop and watermark.
///
/// Stealing the job (pop without apply) is the in-flight window today's
/// `rbtc-sh-wb` opens: generate's drain sees an empty queue while apply is
/// still running, MiniWallet scantxoutset pins the pre-tip watermark, and
/// a spent coin looks live while Class C already spent it (orphaned).
#[test]
fn sh_pending_join_holds_while_job_is_in_flight() {
    let (dir, q) = temp_query("sh-pending-inflight");
    let (h0, mut ta0) = coinbase_block(0, Fk::NULL, None);
    ta0.outputs = vec![OutputRecord::unspent(10_0000_0000, vec![0x51])];
    let create_txid = ta0.tx.txid;
    let hash0 = h0.hash;
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let sh = script_hash(&[0x51]);

    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x22;
    spend_txid[31] = 0xef;
    let hash1 = rbitcoin_store::block_header_hash(1, &hash0, &[0x22; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x22; 32],
        hash: hash1,
        size: 0,
        weight: 0,
    };
    q.commit_class_a_only(
        &h1,
        &[TxApply {
            tx: TxRecord {
                txid: spend_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
        }],
    )
    .unwrap();
    q.confirm_block(Height(1), &hash1).unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());
    q.release_index_writebehind(Height(1));

    // Same transition as rbtc-sh-wb / apply_sh_pending: queue → applying,
    // durable watermark not advanced yet.
    let stolen = q.take_sh_job_for_apply();
    assert!(stolen.is_some(), "confirm must enqueue the spend height");
    assert!(
        q.scripthash_listunspent(&sh).unwrap().is_empty(),
        "in-flight apply window must still join pending at live tip"
    );
    assert_eq!(
        q.pin_sh_chain_view().unwrap().map(|v| v.height),
        Some(Height(1)),
        "visible SH height must stay at tip while the job is in flight"
    );

    let job = stolen.expect("enqueued");
    q.apply_sh_job(job).unwrap();
    q.finish_sh_job(Height(1));
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

fn spend_apply(tag: u8, prev_txid: [u8; 32], keep_sat: i64) -> TxApply {
    let mut txid = [tag; 32];
    txid[31] = 0x5e;
    TxApply {
        tx: TxRecord {
            txid,
            version: 2,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid,
            create_fk: Fk::NULL,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(keep_sat, vec![0x51])],
    }
}

/// Fee history rows from `txstat` alone: stamped (fee, weight) per
/// non-coinbase tx, the block hash, and cell bytes including the coinbase.
#[test]
fn block_txstat_rows_have_fees_hash_and_cell_bytes() {
    let (dir, q) = temp_query("fee-rows");
    let (h0, cb0) = coinbase_block(0, Fk::NULL, None);
    let cb0_txid = cb0.tx.txid;
    let hfk0 = q.connect_block(Height(0), &h0, &[cb0]).unwrap();

    let (h1, cb1) = coinbase_block(1, hfk0, Some(h0.hash));
    let parent = spend_apply(0x11, cb0_txid, 50_0000_0000 - 10_000);
    let child = spend_apply(0x22, parent.tx.txid, 50_0000_0000 - 60_000);
    q.connect_block(Height(1), &h1, &[cb1, parent, child])
        .unwrap();

    let b1 = q.block_txstat_rows(Height(1)).unwrap().expect("stamped");
    assert_eq!(b1.hash, h1.hash);
    assert_eq!(b1.txstat_bytes, 3 * 8);
    let rows = b1.rows.expect("every row stamped");
    assert_eq!(
        rows.iter().map(|r| r.0).collect::<Vec<_>>(),
        vec![10_000, 50_000]
    );
    assert!(rows.iter().all(|r| r.1 > 0), "{rows:?}");
    let b0 = q
        .block_txstat_rows(Height(0))
        .unwrap()
        .expect("coinbase only");
    assert_eq!((b0.rows, b0.txstat_bytes), (Some(vec![]), 8));
    assert!(
        q.block_txstat_rows(Height(2)).unwrap().is_none(),
        "above the tip"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn buried_rules_and_a_lying_header_path() {
    let (dir, q) = temp_query("ms-work");
    assert!(q.milestone_best_work_be().is_none());
    let mut base_be = [0u8; 32];
    base_be[30] = 2;
    let mut one_be = [0u8; 32];
    one_be[31] = 4;
    let base = bitcoin::Work::from_be_bytes(base_be);
    let one = bitcoin::Work::from_be_bytes(one_be);
    let h1 = [0x11u8; 32];
    q.note_milestone_header(5, h1, [0; 32], one, Some(base));
    let at_five = (base + one).to_be_bytes();
    assert_eq!(q.milestone_best_work_be(), Some(at_five));

    let mut bigger_be = [0u8; 32];
    bigger_be[30] = 9;
    let bigger = bitcoin::Work::from_be_bytes(bigger_be);
    q.note_milestone_header(9, [0x66; 32], [0; 32], one, Some(bigger));
    let at_nine = (bigger + one).to_be_bytes();
    assert_eq!(
        q.milestone_best_work_be(),
        Some(at_nine),
        "a higher header replaces the running work total"
    );

    let mut tiny_be = [0u8; 32];
    tiny_be[31] = 1;
    q.note_milestone_header(
        1,
        [0x22; 32],
        [0; 32],
        bitcoin::Work::from_be_bytes(tiny_be),
        Some(base),
    );
    assert_eq!(
        q.milestone_best_work_be(),
        Some(at_nine),
        "a lower header must not replace a heavier path"
    );

    let h10 = [0x33u8; 32];
    q.note_milestone_header(10, h10, [0x66; 32], one, None);
    let at_ten = (bigger + one + one).to_be_bytes();
    assert_eq!(q.milestone_best_work_be(), Some(at_ten));
    q.note_milestone_header(11, [0x44; 32], [0x55; 32], one, None);
    assert_eq!(
        q.milestone_best_work_be(),
        Some(at_ten),
        "a header whose parent is not the path tip does not add work"
    );

    q.clear_milestone_path_above(10);
    assert_eq!(q.milestone_best_work_be(), Some(at_ten));
    assert_eq!(q.milestone_header_at(10), Some(h10));
    q.clear_milestone_path_above(12);
    assert_eq!(q.milestone_best_work_be(), Some(at_ten));
    q.clear_milestone_path_above(9);
    assert!(q.milestone_best_work_be().is_none());
    assert_eq!(q.milestone_header_at(9), Some([0x66; 32]));
    assert_eq!(q.milestone_header_at(10), None);
    let _ = dir;
}

#[test]
fn a_queued_body_off_the_header_path_is_not_the_milestone_chain() {
    let (dir, q) = temp_query("ms-queue-mix");
    let anchor = [0x11u8; 32];
    let block = [0x22u8; 32];
    let mut one_be = [0u8; 32];
    one_be[31] = 2;
    let one = bitcoin::Work::from_be_bytes(one_be);
    q.note_milestone_header(
        100,
        anchor,
        [0; 32],
        one,
        Some(bitcoin::Work::from_be_bytes([0; 32])),
    );
    let mut work = [0u8; 32];
    work[31] = 4;
    q.note_milestone_checkpoint_work(100, work);
    q.block_queue_enqueue(50, block, 0, &[0u8; 80]).unwrap();
    assert_eq!(
        q.milestone_header_at(100),
        Some(anchor),
        "the walk still has the milestone hash"
    );
    assert_eq!(
        q.milestone_header_at(50),
        None,
        "a queued body that was never on this header path is not an ancestor of the milestone"
    );
    q.note_milestone_header(50, block, [0; 32], one, None);
    assert_eq!(q.milestone_header_at(50), Some(block));
    let _ = dir;
}

#[allow(clippy::cognitive_complexity)] // one fixture, many helper arms
#[test]
fn index_mode_helpers_and_batch_helpers() {
    assert!(IndexMode::Direct.is_direct());
    assert!(!IndexMode::Direct.is_tip());
    assert!(IndexMode::Tip.is_tip());
    assert!(!IndexMode::Direct.enqueues_sh_writebehind(true));
    assert!(IndexMode::Tip.enqueues_sh_writebehind(true));
    assert!(!IndexMode::Tip.enqueues_sh_writebehind(false));

    let mut bp = BatchParents::new();
    assert!(bp.is_empty());
    bp.put_resolved(
        Fk(1),
        TxRecord {
            txid: [1; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        &[(0, OutputRecord::unspent(1, vec![0x51]))],
        &[0],
        Some(true),
    );
    assert!(!bp.is_empty());
    assert!(bp.pin_covered(Fk(1), &[]));
    assert!(bp.pin_covered(Fk(1), &[0]));
    assert!(!bp.pin_covered(Fk::NULL, &[0]));
    assert!(!bp.pin_covered(Fk(99), &[0]));
    assert!(bp.get_parent_outs_needed(Fk(1), &[0]).is_some());
    assert!(bp.get_parent_tx(Fk(1)).is_some());
    assert_eq!(bp.get_parent_coinbase(Fk(1)), Some(true));
    assert!(bp.get_body_range(Fk(1)).is_none());
    assert!(bp.get_spender_abs(Fk(1), 0).is_none());
    assert!(!bp.has_parent_out(Fk::NULL, 0));
    bp.insert_owned(
        Fk::NULL,
        bp.get_parent_tx(Fk(1)).unwrap(),
        vec![],
        vec![],
        None,
        None,
        vec![],
    );
    let rels = batch_parents::sparse_spender_rels(&[10, 20, 30], &[0, 2]);
    assert_eq!(rels, vec![(0, 10), (2, 30)]);
    // Partial covered outs path (not fully pin_covered but all live present).
    let mut bp2 = BatchParents::new();
    bp2.insert_owned(
        Fk(2),
        TxRecord {
            txid: [2; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 2,
        },
        vec![
            (0, OutputRecord::unspent(1, vec![0x51])),
            (1, OutputRecord::unspent(2, vec![0x51])),
        ],
        vec![], // empty checked → pin_covered false
        Some(false),
        Some((100, 50)),
        vec![(0, 1), (1, 10)],
    );
    assert!(!bp2.pin_covered(Fk(2), &[0, 1]));
    let got = bp2.get_parent_outs_needed(Fk(2), &[0, 1]).unwrap();
    assert!(!got.2);
    assert_eq!(got.1.len(), 2);
    bp2.set_spent_range_only(Fk(2), (100, 24));
    assert_eq!(bp2.get_spender_abs(Fk(2), 1), Some(108));
    assert!(bp2.get_parent_outs_needed(Fk(2), &[9]).is_none());
}
fn unstamp_txstat(q: &Query, fk: Fk) {
    q.store()
        .write_txstat_row(
            fk,
            &TxStatRow {
                fee_sat: 0,
                base: 0,
                wit_extra: 0,
            },
        )
        .unwrap();
}

#[test]
fn confirm_txstat_miss_is_corrupt() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header as BlockHeader, Version as BlockVersion};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = temp_query("txstat-miss-pinned");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let parent_txid = t0.tx.txid;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let parent_fk = q.block_tx_fks(Height(0)).unwrap()[0];

    let spend = Transaction {
        version: Version::ONE,
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
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = spend.compute_txid().to_byte_array();
    let block = std::sync::Arc::new(Block {
        header: BlockHeader {
            version: BlockVersion::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: 2,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![spend],
    });
    let txrec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let pin = CreatePinInner::wire(std::sync::Arc::clone(&block), 0, txrec);
    let child_fk = Fk(parent_fk.get().unwrap() + 1);
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        pin,
        vec![InputRecord {
            prev_txid: parent_txid,
            create_fk: parent_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    plan.planned_fks = vec![child_fk];
    plan.edges.insert(
        child_fk.get().unwrap(),
        vec![crate::SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk: child_fk,
            create_fk: parent_fk,
            vin: 0,
        }],
    );
    plan.body_est = 256;
    let err = q
        .archive_commit_plan_defer_head_parents(plan, Some(&BatchParents::new()))
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Corrupt("txstat parent not pinned")),
        "{err}"
    );
    assert!(q.store().get_tx_meta_and_outputs(parent_fk).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A plan whose fee rows do not line up with its packed txs, and an append
/// of a plan without fee rows, are plan shapes the load stage never emits.
/// The invariant and the append rule stay a unit.
#[test]
fn archive_plan_fee_rows_follow_packed_txs() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header as BlockHeader, Version as BlockVersion};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, q) = temp_query("txstat-fee-rows");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let parent_txid = t0.tx.txid;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let parent_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let spend = Transaction {
        version: Version::ONE,
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
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = spend.compute_txid().to_byte_array();
    let block = std::sync::Arc::new(Block {
        header: BlockHeader {
            version: BlockVersion::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: 2,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![spend],
    });
    let txrec = TxRecord {
        txid,
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    let mut bad = ArchiveWritePlan::empty();
    assert!(bad.is_empty());
    bad.packed = vec![(
        CreatePinInner::wire(std::sync::Arc::clone(&block), 0, txrec),
        vec![InputRecord {
            prev_txid: parent_txid,
            create_fk: parent_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    let child_fk = Fk(parent_fk.get().unwrap() + 1);
    bad.planned_fks = vec![child_fk];
    bad.edges.insert(
        child_fk.get().unwrap(),
        vec![crate::SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk: child_fk,
            create_fk: parent_fk,
            vin: 0,
        }],
    );
    bad.body_est = 256;
    bad.tx_fees = vec![1, 2];
    let err = q
        .archive_commit_plan_defer_head_parents(bad, Some(&BatchParents::new()))
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Corrupt("invariant: txstat fee length")),
        "{err}"
    );

    let aligned = |fee: u64| {
        let mut plan = ArchiveWritePlan::empty();
        plan.packed = vec![(
            CreatePinInner::records(
                TxRecord {
                    txid: [fee as u8; 32],
                    version: 1,
                    locktime: 0,
                    input_start_fk: Fk::NULL,
                    input_count: 0,
                    output_start_fk: Fk::NULL,
                    output_count: 1,
                },
                vec![OutputRecord::unspent(1, vec![0x51])],
            ),
            Vec::new(),
        )];
        plan.tx_fees = vec![fee];
        plan
    };
    let mut joined = aligned(7);
    joined.append(aligned(9));
    assert_eq!(joined.tx_fees, vec![7, 9]);
    let mut partial = aligned(7);
    let mut bare = aligned(9);
    bare.tx_fees.clear();
    partial.append(bare);
    assert!(partial.tx_fees.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn txstat_row_merges_overflow_via_header_blob() {
    let (dir, q) = temp_query("txstat-row-ovf");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hfk = q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let fk = q.block_tx_fks(Height(0)).unwrap()[0];
    assert!(q.store().txstat_row(fk).unwrap().is_some());
    let fat = TxStatRow {
        fee_sat: u64::from(u32::MAX),
        base: 4_000_000,
        wit_extra: 4_000_000,
    };
    q.store()
        .write_txstat_block(hfk, fk.get().unwrap(), &[fat])
        .unwrap();
    assert_eq!(q.store().txstat_row(fk).unwrap(), Some(fat));
    unstamp_txstat(&q, fk);
    assert_eq!(q.store().txstat_row(fk).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}
include!("query_prune_journey.rs");
include!("query_chain_view_journey.rs");
include!("query_resume_journey.rs");
include!("query_sh_caps_journey.rs");

/// W-SH.A: write-batch CreatePin supplies outs for SH collect without Class A
/// body re-read (missing store row still succeeds via pin).
#[test]
fn sh_collect_write_pin_skips_store() {
    let (dir, q) = temp_query("sh-collect-pin");

    let script = vec![0x51, 0xaa, 0xbb];
    let expected_sh = script_hash(&script);
    let fk = Fk(9_876_543);
    let pin = CreatePinInner::records(
        TxRecord {
            txid: [0xce; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        vec![OutputRecord::unspent(42, script)],
    );

    let mut recs = Vec::new();
    q.collect_scripthash_creates(fk, &mut recs, Some(&pin))
        .expect("pin path must not touch store");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].create_tx_fk, fk);
    assert_eq!(recs[0].scripthash, expected_sh);

    // Without pin and without store row → cold path errors (NotFound).
    let mut recs2 = Vec::new();
    assert!(
        q.collect_scripthash_creates(fk, &mut recs2, None).is_err(),
        "no pin + no store must not invent records"
    );
    assert!(recs2.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sh_collect_and_disconnect_skip_get_tx_full() {
    let (dir, q) = temp_query("sh-collect-outs-only");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let fks = q.block_tx_fks(Height(0)).unwrap();
    let mut recs = Vec::new();
    q.collect_scripthash_creates(fks[0], &mut recs, None)
        .expect("cold collect");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].create_tx_fk, fks[0]);
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), None, "disconnect removes the only block");

    let _ = std::fs::remove_dir_all(&dir);
}
