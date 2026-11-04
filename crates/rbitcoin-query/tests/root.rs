use bitcoin::hashes::Hash;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::archive::{ArchiveWritePlan, CreatePinInner};
use rbitcoin_query::batch_parents::BatchParents;
use rbitcoin_query::catchup::IndexMode;
use rbitcoin_query::chain_view::{ChainView, ChainViewKind};
use rbitcoin_query::confirm_stats::LastPinPhases;
use rbitcoin_query::connect::ConfirmPrepared;
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::Query;
use rbitcoin_query::*;
use rbitcoin_store::TxStatRow;
use rbitcoin_store::{script_hash, HeaderRecord, InputRecord, OutputRecord, StoreError, TxRecord};

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
    q.store()
        .confirmed
        .set(&rbitcoin_store::ClassCWrite::for_test(), Height(0), hfk)
        .unwrap();
    q.store().rebuild_height_fence().unwrap();
    let leftover = Fk(99);
    q.store()
        .strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), leftover, hfk)
        .unwrap();
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
    q.store()
        .strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), leftover, Fk(1))
        .unwrap();
    q.store().flush_class_c_tip().unwrap();
    assert!(q.store().strong_tx.is_strong(leftover).unwrap());
    assert_eq!(q.uring_recover("test"), UringRecover::Recovered);
    assert!(
        q.store().strong_tx.is_strong(leftover).unwrap(),
        "in-process recover must not mutate Class C; leftover strong waits for open repair"
    );
    q.store()
        .strong_tx
        .set_strong(&rbitcoin_store::ClassCWrite::for_test(), leftover, Fk(1))
        .unwrap();
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

#[test]
fn published_tip_is_in_the_height_index() {
    let (dir, q) = temp_query("pub-tip-index");
    q.store()
        .confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(0), 1)
        .unwrap();
    let hash = [0xab; 32];
    q.publish_confirmed_tip(0, hash);
    let before = rbitcoin_query::chain_view::header_lookup_count();
    assert_eq!(q.height_of_hash(&hash).unwrap(), Some(Height(0)));
    assert_eq!(
        rbitcoin_query::chain_view::header_lookup_count().saturating_sub(before),
        0,
        "a published tip is served from the height index"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extend_refuses_a_height_the_store_already_left() {
    let (dir, q) = temp_query("idx-left-height");
    q.store()
        .confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(0), 1)
        .unwrap();
    q.publish_confirmed_tip(0, [0x11; 32]);
    let stale = [0x22; 32];
    assert!(
        !q.extend_height_index(&[(stale, 1)], 1, Some(0), false),
        "a reader must not index a height the store has already left"
    );
    assert_eq!(q.height_of_hash(&stale).unwrap(), None);
    q.store()
        .confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(1), 2)
        .unwrap();
    assert!(q.extend_height_index(&[(stale, 1)], 1, Some(0), false));
    assert_eq!(q.height_of_hash(&stale).unwrap(), Some(Height(1)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn published_height_does_not_fill_a_lagging_index() {
    let (dir, q) = temp_query("pub-h-lag");
    let hashes = h2h_pad_0_4(&q);
    q.leave_height_index_gap_for_test(1);
    let before = rbitcoin_query::chain_view::header_lookup_count();
    assert_eq!(
        q.published_height_of_hash(&hashes[1]),
        Some(Height(1)),
        "a hash at or below the indexed tip is still that height"
    );
    assert_eq!(q.published_height_of_hash(&hashes[4]), None);
    assert_eq!(
        rbitcoin_query::chain_view::header_lookup_count().saturating_sub(before),
        0,
        "a lagging index is not filled from this lookup"
    );
    let _ = dir;
}

#[test]
fn height_index_catchup_does_not_hold_the_lock_across_header_reads() {
    let (dir, q) = temp_query("h2h-lock");
    let hashes = h2h_pad_0_4(&q);
    q.leave_height_index_gap_for_test(1);
    rbitcoin_query::chain_view::reset_index_io_under_lock();
    let before = rbitcoin_query::chain_view::header_lookup_count();
    q.ensure_height_by_hash_index(q.tip_height().unwrap())
        .unwrap();
    assert!(
        rbitcoin_query::chain_view::header_lookup_count() > before,
        "the gap is filled by reading the missing headers"
    );
    assert_eq!(
        rbitcoin_query::chain_view::index_io_under_lock(),
        0,
        "catch-up reads headers before taking height_by_hash"
    );
    assert_height(&q, &hashes[4], 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seed_published_tip_refuses_a_tip_with_no_header() {
    let (dir, q) = temp_query("seed-no-header");
    q.store()
        .confirmed
        .set_raw_for_test(&rbitcoin_store::ClassCWrite::for_test(), Height(0), 0)
        .unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    let err = q.seed_published_tip().unwrap_err();
    assert!(
        err.to_string().contains("confirmed tip has no header"),
        "{err}"
    );
    assert!(q.published_tip().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

fn temp_query(label: &str) -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled(label)
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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: create_txid,
            parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
    };
    (h1, spend, spend_txid)
}

/// A one-block catch-up still returns the spend. A clipped window above
/// eight weeks is refused before the block scan.
#[test]
fn history_window_wider_than_eight_weeks_is_refused() {
    let (dir, q) = temp_query("history-window-width");
    q.set_spend_index(true);
    let (h0, ta0) = funded_op_true_coinbase(0, Fk::NULL, None);
    let create_txid = ta0.tx.txid;
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let (h1, spend, spend_txid) = spend_op_true(hfk0, h0.hash, create_fk, create_txid);
    q.connect_block(Height(1), &h1, &[spend]).unwrap();
    let sh = rbitcoin_store::script_hash(&[0x51]);

    let narrow = rbitcoin_query::scripthash::HistoryFilter::height_window(1, Some(2));
    let rows = q.scripthash_history_filtered(&sh, &narrow).unwrap();
    assert_eq!(
        rows.rows.iter().map(|row| row.txid).collect::<Vec<_>>(),
        vec![spend_txid]
    );

    let mut wide_view = q.pin_sh_chain_view().unwrap().expect("sh view");
    wide_view.height = Height(1 + 8_064);
    let wide = rbitcoin_query::scripthash::HistoryFilter::height_window(1, None);
    let err = q
        .scripthash_history_filtered_in(&sh, &wide, &wide_view)
        .unwrap_err();
    assert!(
        matches!(err, StoreError::Rejected("history window too wide")),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A newest page whose creates sit more than eight weeks under the tip reads
/// spend slots. It does not walk `input.body` across the gap.
///
/// One chain fills the page, checks that dormant page, then spends the
/// create that falls below the page.
#[test]
fn newest_page_wide_gap_uses_spend_slots() {
    let sh = rbitcoin_store::script_hash(&[0x51]);
    let page = rbitcoin_query::HistoryFilter::esplora_chain_page(None);
    let (dir, q) = temp_query("newest-page-wide");
    q.set_spend_index(true);
    let mut prev = Fk::NULL;
    let mut parent = None;
    let mut txids = Vec::new();
    for h in 0..25u32 {
        let (header, ta) = coinbase_block(h, prev, parent);
        txids.push(ta.tx.txid);
        parent = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    let mut view = q.pin_sh_chain_view().unwrap().expect("sh view");
    view.height = Height(view.height.0.saturating_add(8_065));
    let rows = q
        .scripthash_history_summary_filtered_in(&sh, &page, &view)
        .expect("dormant page")
        .rows;
    let got: Vec<[u8; 32]> = rows.iter().map(|row| row.txid).collect();
    assert_eq!(got.len(), txids.len());
    for txid in &txids {
        assert!(got.contains(txid), "page drops a create inside the limit");
    }

    let (header, ta) = coinbase_block(25, prev, parent);
    txids.push(ta.tx.txid);
    parent = Some(header.hash);
    prev = q.connect_block(Height(25), &header, &[ta]).unwrap();
    let older = txids[0];
    let page_creates = txids[1..].to_vec();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let (header, mut spend) = coinbase_block(26, prev, parent);
    spend.tx.txid[30] = 0x5e;
    spend.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x00])];
    spend.inputs = vec![InputRecord {
        prev_txid: older,
        parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let spend_txid = spend.tx.txid;
    q.connect_block(Height(26), &header, &[spend]).unwrap();
    let mut view = q.pin_sh_chain_view().unwrap().expect("sh view");
    view.height = Height(view.height.0.saturating_add(8_065));
    let rows = q
        .scripthash_history_summary_filtered_in(&sh, &page, &view)
        .expect("page with an in-window spend")
        .rows;
    let got: Vec<[u8; 32]> = rows.iter().map(|row| row.txid).collect();
    assert!(
        got.contains(&spend_txid),
        "a spend of an older coin inside the page window must be on the page"
    );
    assert!(
        !got.contains(&older),
        "the older create itself is below the page"
    );
    assert_eq!(got.len(), 25, "the spend takes one slot on the page");
    for txid in &page_creates[1..] {
        assert!(
            got.contains(txid),
            "page drops a create newer than the spend's slot"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Disconnect of one block that holds a whole scripthash extent ends with an
/// empty head and no tip. The empty head is published only after the tip shrink.
#[test]
fn disconnect_one_block_megakey_clears_the_head() {
    let (dir, q) = temp_query("disconnect-megakey");
    let sh = rbitcoin_store::script_hash(&[0x51]);
    let (header, base) = coinbase_block(0, Fk::NULL, None);
    let mut txs = Vec::with_capacity(257);
    for i in 0..257u32 {
        let mut ta = base.clone();
        ta.tx.txid[0..4].copy_from_slice(&i.to_le_bytes());
        ta.inputs[0].script_sig = vec![(i & 0xff) as u8];
        txs.push(ta);
    }
    q.connect_block(Height(0), &header, &txs).unwrap();
    assert!(
        matches!(
            q.store().scripthash.head_value(&sh).unwrap().unwrap(),
            rbitcoin_store::ShHeadValue::Extent { .. }
        ),
        "257 creates of one script are a page chain"
    );
    assert_eq!(q.tip_height().map(|h| h.0), Some(0));
    q.disconnect_tip().unwrap();
    assert!(q.tip_height().is_none());
    let head = q.store().scripthash.head_value(&sh).unwrap();
    assert!(head
        .as_ref()
        .map(rbitcoin_store::ShHeadValue::is_empty)
        .unwrap_or(true));
    assert!(!q.store().scripthash.deferred_empty(&sh));
    let _ = std::fs::remove_dir_all(&dir);
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
        hash: q.get_header(header_fk).unwrap().hash,
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

/// Open rebuilds the confirmed hash map from height 0. The walk names its
/// window so a multi-minute restart is not a silent gap before spend replay.
#[test]
fn full_height_index_logs_the_walk() {
    let (dir, q) = temp_query("h2h-log");
    let hashes = h2h_pad_0_4(&q);
    q.invalidate_height_by_hash_index();
    rbitcoin_log::capture_logs(true);
    q.ensure_height_by_hash_index(q.tip_height().unwrap())
        .unwrap();
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let text = logs
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("query: height index 0..=4 (5 headers)"),
        "{text}"
    );
    assert!(
        text.contains("query: height index done headers=5"),
        "{text}"
    );
    assert_height(&q, &hashes[4], 4);
    let _ = std::fs::remove_dir_all(&dir);
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
        .disconnect_tip(&rbitcoin_store::ClassCWrite::for_test(), Height(4))
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
        q.store
            .confirmed
            .disconnect_tip(&rbitcoin_store::ClassCWrite::for_test(), h)
            .unwrap();
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
    assert!(q.index_mode().expect("index mode cell").is_tip());

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

/// A zero include mark proves nothing. Recovery re-queues from the start,
/// and applying that queue is what makes the index tip-ready. A mark written
/// with the head still names the height it covers.
#[test]
fn zero_include_mark_requeues_from_the_start() {
    let (dir, q) = temp_query("sh-zero-include");
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
    assert!(q.store().scripthash.has_durable_index());
    assert!(
        q.store().scripthash.include_hwm() > 0,
        "creating the head persists the include mark"
    );
    assert_eq!(
        q.recover_sh_indexed_through().unwrap(),
        Some(0),
        "a mark that covers the head is that height, not a rebuild"
    );

    std::fs::remove_file(dir.path().join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    assert_eq!(q.store().scripthash.include_hwm(), 0);
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (mut h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    h1.merkle_root = t1.tx.txid;
    rehash_header(&mut h1, &hash0);
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();
    q.store().flush_class_c_tip().unwrap();
    drop(q);

    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_ne!(
        q.sh_indexed_through_height(),
        Some(1),
        "a zero include mark must not report the tip as indexed"
    );
    assert!(
        !q.sh_is_tip_ready(),
        "wallet servers stay down while the gap is not durable"
    );
    let sh = script_hash(&[0x51]);
    assert_eq!(
        q.scripthash_history(&sh).unwrap().len(),
        2,
        "recovery re-queues from the start, so the unapplied height is visible"
    );
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    assert!(
        q.sh_is_tip_ready(),
        "applying the recovered queue makes the index tip-ready without another block"
    );
    assert!(q.store().scripthash.include_hwm() > 0);
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
    assert!(q
        .store()
        .header_txs
        .clear_body(&rbitcoin_store::ClassCWrite::for_test(), hfk1)
        .unwrap());
    let err = q.recover_sh_writebehind().expect_err("interior hole");
    let msg = format!("{err}");
    assert!(
        msg.contains("invariant:") || msg.contains("missing"),
        "expected invariant/missing body, got {msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clear_archived_body_waits_for_the_confirm_write_channel() {
    let (dir, q) = temp_query("clear-on-write-channel");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let hfk = q.tip_header_fk().unwrap().unwrap();
    assert!(q.store().header_txs.has_body(hfk).unwrap());
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    q.attach_confirm_write(tx);
    let cleared = std::thread::scope(|scope| {
        let worker = scope.spawn(|| q.clear_archived_body(&hash).unwrap());
        let msg = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("clear is a write-channel item");
        assert!(
            q.store().header_txs.has_body(hfk).unwrap(),
            "orchestration must not store Class C while the write thread has the channel"
        );
        let rbitcoin_query::ConfirmWriteMsg::ClearArchived { hash: got, reply } = msg else {
            panic!("clear must not arrive as a script batch");
        };
        assert_eq!(got, hash);
        let result = {
            let _commit = q.lock_tip_commit().unwrap();
            q.clear_archived_body_here(&got).unwrap()
        };
        reply.send(Ok(result)).unwrap();
        worker.join().unwrap()
    });
    assert!(cleared);
    assert!(!q.store().header_txs.has_body(hfk).unwrap());
    q.detach_confirm_write();
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
    assert!(q
        .store()
        .header_txs
        .clear_body(&rbitcoin_store::ClassCWrite::for_test(), hfk1)
        .unwrap());
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
    rbitcoin_query::connect::request_sh_writebehind_halt(&stop, 7, &"apply failed");
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
/// still running, a scripthash read pins the pre-tip watermark, and
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
                input_count: 1,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: create_txid,
                parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
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
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid,
            parent: rbitcoin_store::InputParent::Unstamped,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(keep_sat as u64, vec![0x51])],
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
            input_count: 1,
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
            input_count: 1,
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
        input_count: 1,
        output_count: 1,
    };
    let pin = CreatePinInner::wire(std::sync::Arc::clone(&block), 0, txrec);
    let child_fk = Fk(parent_fk.get().unwrap() + 1);
    let mut plan = ArchiveWritePlan::empty();
    plan.packed = vec![(
        pin,
        vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Prevout {
                create_fk: parent_fk,
                vout: 0,
            },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    plan.planned_fks = vec![child_fk];
    plan.edges.insert(
        child_fk.get().unwrap(),
        vec![rbitcoin_query::SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk: child_fk,
            create_fk: Fk(999_999),
            vin: 0,
        }],
    );
    plan.body_est = 256;
    let err = q.archive_commit_plan_defer_head_parents(plan).unwrap_err();
    assert!(
        matches!(err, StoreError::Corrupt("invariant: txstat fee length")),
        "empty fee rows are corrupt; commit does not walk prevouts: {err}"
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
        input_count: 1,
        output_count: 1,
    };
    let mut bad = ArchiveWritePlan::empty();
    assert!(bad.is_empty());
    bad.packed = vec![(
        CreatePinInner::wire(std::sync::Arc::clone(&block), 0, txrec),
        vec![InputRecord {
            prev_txid: parent_txid,
            parent: rbitcoin_store::InputParent::Prevout {
                create_fk: parent_fk,
                vout: 0,
            },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
    )];
    let child_fk = Fk(parent_fk.get().unwrap() + 1);
    bad.planned_fks = vec![child_fk];
    bad.edges.insert(
        child_fk.get().unwrap(),
        vec![rbitcoin_query::SpendEdge {
            prev_txid: parent_txid,
            vout: 0,
            spend_fk: child_fk,
            create_fk: parent_fk,
            vin: 0,
        }],
    );
    bad.body_est = 256;
    bad.tx_fees = vec![1, 2];
    let err = q.archive_commit_plan_defer_head_parents(bad).unwrap_err();
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
                    input_count: 0,
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
    assert_eq!(partial.tx_fees, vec![7]);
    assert_ne!(partial.tx_fees.len(), partial.packed.len());
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
            input_count: 1,
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
fn sh_collect_cold_then_disconnect_clears_tip() {
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

/// Core's coins view never holds an `OP_RETURN` output or a script over
/// 10,000 bytes. Balance, listunspent, and funded stats skip them. The
/// transaction that paid them stays in that script's history.
#[test]
fn sh_views_skip_unspendable_outputs() {
    let (dir, q) = temp_query("sh-unspendable");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    let hfk0 = q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let op_return = vec![0x6a, 0x01, 0x02];
    let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment.extend([0x5a; 32]);
    let oversize = vec![0x51; 10_001];
    let (h1, mut t1) = coinbase_block(1, hfk0, Some(hash0));
    t1.outputs = vec![
        OutputRecord::unspent(49_0000_0000, vec![0x51]),
        OutputRecord::unspent(1_0000, op_return.clone()),
        OutputRecord::unspent(0, commitment.clone()),
        OutputRecord::unspent(2_0000, oversize.clone()),
    ];
    t1.tx.output_count = 4;
    let txid1 = t1.tx.txid;
    q.connect_block(Height(1), &h1, &[t1]).unwrap();

    for script in [&op_return, &commitment, &oversize] {
        let sh = script_hash(script);
        assert!(q.scripthash_listunspent(&sh).unwrap().is_empty());
        assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 0);
        let stats = q.scripthash_chain_stats(&sh).unwrap();
        assert_eq!(stats.tx_count, 1, "the paying tx is still history");
        assert_eq!((stats.funded_txo_count, stats.funded_txo_sum), (0, 0));
        assert_eq!((stats.spent_txo_count, stats.spent_txo_sum), (0, 0));
        let hist: Vec<_> = q
            .scripthash_history(&sh)
            .unwrap()
            .iter()
            .map(|row| row.txid)
            .collect();
        assert_eq!(hist, vec![txid1]);
        let view = q.pin_sh_chain_view().unwrap().expect("SH view");
        for filter in [
            HistoryFilter::open(),
            HistoryFilter::esplora_chain_page(None),
        ] {
            let rows: Vec<_> = q
                .scripthash_history_summary_filtered_in(&sh, &filter, &view)
                .unwrap()
                .rows
                .iter()
                .map(|row| (row.txid, row.value))
                .collect();
            assert_eq!(rows, vec![(txid1, 0)], "summary value is funded coins");
        }
    }
    let sh = script_hash(&[0x51]);
    assert_eq!(q.scripthash_listunspent(&sh).unwrap().len(), 2);
    assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 99_0000_0000);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The genesis coinbase is not a coin and not an ordinary transaction.
/// Every scripthash view leaves it out, so Electrum never reports a
/// confirmed height-0 row (height 0 there means mempool). That holds while
/// its create is pending write-behind and after apply.
#[test]
fn sh_views_skip_the_genesis_coinbase() {
    let (dir, q) = temp_query("sh-genesis-coinbase");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let genesis_txid = t0.tx.txid;
    let hash0 = h0.hash;
    q.commit_class_a_only(&h0, &[t0]).unwrap();
    let hfk0 = q.confirm_block(Height(0), &hash0).unwrap();
    let (h1, t1) = coinbase_block(1, hfk0, Some(hash0));
    let txid1 = t1.tx.txid;
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();
    let sh = script_hash(&[0x51]);
    assert!(!q.pending_sh_create_fks(&sh).is_empty(), "creates pending");
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 2, "unset: listed");

    q.set_genesis_coinbase_txid(genesis_txid);
    let check = |state: &str| {
        let rows = |filter: &HistoryFilter| -> Vec<([u8; 32], i64)> {
            q.scripthash_history_filtered(&sh, filter)
                .unwrap()
                .rows
                .iter()
                .map(|row| (row.txid, row.height))
                .collect()
        };
        let want = vec![(txid1, 1)];
        assert_eq!(rows(&HistoryFilter::open()), want, "{state}");
        assert_eq!(
            rows(&HistoryFilter::esplora_chain_page(None)),
            want,
            "{state}"
        );
        assert_eq!(
            rows(&HistoryFilter::height_window(0, Some(2))),
            want,
            "{state}"
        );
        let utxos = q.scripthash_listunspent(&sh).unwrap();
        assert_eq!(utxos.len(), 1, "{state}");
        assert_eq!((utxos[0].tx_hash, utxos[0].height), (txid1, 1), "{state}");
        assert_eq!(q.scripthash_balance(&sh).unwrap().confirmed, 50_0000_0000);
        let stats = q.scripthash_chain_stats(&sh).unwrap();
        assert_eq!(
            (stats.tx_count, stats.funded_txo_count, stats.funded_txo_sum),
            (1, 1, 50_0000_0000),
            "{state}"
        );
    };
    check("pending");
    q.release_index_writebehind(Height(1));
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(1));
    assert!(q.pending_sh_create_fks(&sh).is_empty(), "creates durable");
    check("durable");
    let _ = std::fs::remove_dir_all(&dir);
}
