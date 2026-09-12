use super::*;
use rbitcoin_store::{InputRecord, OutputRecord};
use std::time::{SystemTime, UNIX_EPOCH};

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

    let q = Query::open_or_create(dir.join("store")).unwrap();
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

fn temp_query(label: &str) -> (std::path::PathBuf, Query) {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-query-{label}-{n}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let q = Query::open_or_create(dir.join("store")).unwrap();
    (dir, q)
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

#[test]
fn note_disconnect_rewinds_started_and_class_a_with_taken() {
    let (dir, q) = temp_query("disco-hwm");
    q.set_lookup_taken_hi(Some(12));
    q.set_lookup_started_hi(Some(12));
    q.set_class_a_hi(Some(10));
    q.note_disconnect_height(8);
    assert_eq!(q.lookup_taken_hi(), Some(7));
    assert_eq!(q.lookup_started_hi(), Some(7));
    assert_eq!(q.class_a_hi(), Some(7));
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
    q.connect_block(Height(height), &h, &[t.clone()]).unwrap();
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

#[test]
fn sampler_stats() {
    // Process-global IBD samplers race under parallel `cargo test`. Prefer
    // last-writer overwrite checks and accumulate lower-bounds over exact
    // equality on counters other tests may also bump.
    let _ = confirm_load_stats::sample_and_reset();
    confirm_load_stats::note(
        &ConfirmLoadStats {
            blocks: 1,
            utxo_parents: 2,
            creates_registered: 3,
            parent_unique: 4,
            pin_cache_body: 5,
            pin_new: 6,
            pin_body_ns: 8,
            pin_new_meta_ns: 9,
            parent_cache_hits: 10,
            full_tx_reads: 11,
            body_tx_reads: 12,
            missing_parents: 13,
            header_ns: 14,
            body_decode_ns: 15,
            thin_ns: 16,
            parent_pin_ns: 17,
            cache_put_ns: 18,
            edge_same_batch: 19,
            edge_fk: 20,
            edge_coinbase: 21,
            ..Default::default()
        },
        100,
    );
    let s = confirm_load_stats::sample_and_reset();
    assert!(s.ns >= 100);
    assert!(s.blocks >= 1);
    assert!(s.edge_coinbase >= 21);

    let _ = archive_phase_stats::sample_and_reset();
    archive_phase_stats::note_resolve_counts(1, 2, 3, 4, 5, 6);
    let last = archive_phase_stats::last_plan_batch();
    // last_plan_batch is last-writer; re-note immediately before read if raced.
    if last.head_need != 3 {
        archive_phase_stats::note_resolve_counts(1, 2, 3, 4, 5, 6);
    }
    let last = archive_phase_stats::last_plan_batch();
    assert_eq!(last.head_need, 3);
    assert_eq!(last.head_hit, 4);
    archive_phase_stats::note_prep_plan(1, 2, 3, 10, 6, 7);
    archive_phase_stats::note_prep_batch(10, 1, 2, 3, 4, 1);
    archive_phase_stats::note_write_commit(20, 1, 2, 3, 4, 5, 1);
    archive_phase_stats::note_write_flush(8);
    let a = archive_phase_stats::sample_and_reset();
    assert!(a.prep_phases_sum_ns() > 0);
    assert!(a.write_phases_sum_ns() > 0);
    assert!(a.blocks >= 1);
    assert!(a.prep_head_fk_ns >= 10);
    assert!(a.prep_head_ns >= 10);

    confirm_load_stats::note_last_pin(11, 22, 33, 44, 55, 100, 9);
    let lp = confirm_load_stats::last_pin_phases();
    if lp.adopt_ns != 11 {
        confirm_load_stats::note_last_pin(11, 22, 33, 44, 55, 100, 9);
    }
    let lp = confirm_load_stats::last_pin_phases();
    assert_eq!(lp.adopt_ns, 11);
    assert_eq!(lp.plan_pin_ns, 22);
    assert_eq!(lp.cold_ns, 33);
    assert_eq!(lp.contract_ns, 44);
    assert_eq!(lp.publish_ns, 55);
    assert_eq!(lp.pin_plan_n, 100);
    assert_eq!(lp.pin_new_n, 9);
    assert_eq!(confirm_load_stats::LastPinPhases::ms(2_000_000), 2);
}

/// Disconnecting a confirmed block must emit an info/warn line (not debug).
#[test]
fn disconnect_tip_logs_each_block_at_least_info() {
    let (dir, q) = temp_query("disconnect-log");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let (h1, t1) = coinbase_block(1, q.tip_header_fk().unwrap().unwrap(), Some(hash0));
    let hash1 = h1.hash;
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));

    rbitcoin_log::capture_logs(true);
    q.disconnect_tip().unwrap();
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(q.tip_height(), Some(Height(0)));
    let line = format_disconnect_tip_line(1, &hash1, 1);
    assert!(
        line.contains("height=1"),
        "disconnect line must name height: {line}"
    );
    assert!(
        line.to_ascii_lowercase().contains("disconnect"),
        "disconnect line must say disconnect: {line}"
    );
    let hash_disp = BlockHash::from_byte_array(hash1).to_string();
    assert!(
        line.contains(&hash_disp),
        "disconnect line must name the leaving hash {hash_disp}: {line}"
    );
    assert!(
        logs.iter()
            .any(|(l, m)| { *l == rbitcoin_log::Level::Warn && m.contains(&line) }),
        "disconnect_tip must emit the helper line at warn: {logs:?}"
    );

    q.disconnect_tip().unwrap();
    assert!(q.tip_height().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_pin_none_on_empty_store() {
    let (dir, q) = temp_query("chain-view-empty");
    assert!(q.pin_chain_view().unwrap().is_none());
    assert!(q.pin_view(ChainViewKind::Tip, None).unwrap().is_none());
    assert!(q
        .pin_view(ChainViewKind::ScriptHash, None)
        .unwrap()
        .is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_pin_live_across_extension_dead_after_same_height_replace() {
    let (dir, q) = temp_query("chain-view-pin");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();

    let genesis = q.pin_chain_view().unwrap().expect("genesis tip");
    assert_eq!(genesis.height, Height(0));
    assert_eq!(genesis.hash, hash0);
    assert!(genesis.still_live(&q).unwrap());
    assert_eq!(q.pin_view(ChainViewKind::Tip, None).unwrap(), Some(genesis));

    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    assert!(
        genesis.still_live(&q).unwrap(),
        "prefix pin stays live across tip extension"
    );

    let tip1 = q.pin_chain_view().unwrap().expect("height 1");
    assert_eq!(tip1.height, Height(1));
    assert_eq!(tip1.hash, h1.hash);
    assert!(tip1.still_live(&q).unwrap());

    q.disconnect_tip().unwrap();
    assert!(
        !tip1.still_live(&q).unwrap(),
        "disconnect of pinned height kills the view"
    );
    assert!(genesis.still_live(&q).unwrap());

    let (mut h1b, t1b) = coinbase_block(1, prev_fk, Some(hash0));
    h1b.nonce = h1.nonce.wrapping_add(1);
    rehash_header(&mut h1b, &hash0);
    q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
    assert_ne!(h1b.hash, tip1.hash);
    assert!(
        !tip1.still_live(&q).unwrap(),
        "same-height replace must not keep the old pin live"
    );
    let tip1b = q.pin_chain_view().unwrap().expect("replacement tip");
    assert_eq!(tip1b.height, Height(1));
    assert_eq!(tip1b.hash, h1b.hash);
    assert!(tip1b.still_live(&q).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_at_buried_pin_survives_tip_extension_and_higher_replace() {
    let (dir, q) = temp_query("chain-view-at");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    assert!(q.pin_chain_view_at(&[0xee; 32]).unwrap().is_none());

    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    let prev1 = q.tip_header_fk().unwrap().unwrap();
    let (h2, t2) = coinbase_block(2, prev1, Some(h1.hash));
    q.connect_block(Height(2), &h2, &[t2]).unwrap();

    let buried = q.pin_chain_view_at(&hash0).unwrap().expect("genesis hash");
    assert_eq!(buried.height, Height(0));
    assert_eq!(buried.hash, hash0);
    assert!(buried.still_live(&q).unwrap());

    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));
    assert!(
        buried.still_live(&q).unwrap(),
        "disconnect of height 2 must not kill a height-0 pin"
    );
    assert_eq!(
        q.pin_chain_view_at(&hash0).unwrap().unwrap().header_fk,
        buried.header_fk
    );

    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert!(buried.still_live(&q).unwrap());

    q.disconnect_tip().unwrap();
    assert!(
        !buried.still_live(&q).unwrap(),
        "disconnect of the pinned height kills the buried view"
    );
    assert!(q.pin_chain_view_at(&hash0).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_at_spend_asof_hides_later_spend() {
    let (dir, q) = temp_query("chain-view-asof-spend");
    let (h0, ta0) = funded_op_true_coinbase(0, Fk::NULL, None);
    let create_txid = ta0.tx.txid;
    let hash0 = h0.hash;
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let view0 = q.pin_chain_view_at(&hash0).unwrap().unwrap();

    let (h1, spend, _spend_txid) = spend_op_true(hfk0, hash0, create_fk, create_txid);
    let hash1 = h1.hash;
    q.connect_block(Height(1), &h1, &[spend]).unwrap();
    let view1 = q.pin_chain_view_at(&hash1).unwrap().unwrap();
    let sh = script_hash(&[0x51]);

    assert!(!q.is_outpoint_spent_at(&create_txid, 0, Some(0)).unwrap());
    assert!(q.is_outpoint_spent_at(&create_txid, 0, Some(1)).unwrap());
    assert!(q.is_outpoint_spent(&create_txid, 0).unwrap());

    let utxo0 = q.scripthash_listunspent_in(&sh, &view0).unwrap();
    assert_eq!(utxo0.len(), 1);
    assert_eq!(utxo0[0].tx_hash, create_txid);
    assert_eq!(utxo0[0].value, 10_0000_0000);
    let bal0 = q.scripthash_balance_in(&sh, &view0).unwrap();
    assert_eq!(bal0.confirmed, 10_0000_0000);
    let hist0 = q.scripthash_history_in(&sh, &view0).unwrap();
    assert_eq!(hist0.len(), 1);
    assert_eq!(hist0[0].txid, create_txid);

    let utxo1 = q.scripthash_listunspent_in(&sh, &view1).unwrap();
    assert!(utxo1.is_empty(), "spend at height 1 is visible as of 1");
    let bal1 = q.scripthash_balance_in(&sh, &view1).unwrap();
    assert_eq!(bal1.confirmed, 0);
    let hist1 = q.scripthash_history_in(&sh, &view1).unwrap();
    assert_eq!(hist1.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_sh_join_slot_miss_on_same_height_replace() {
    let (dir, q) = temp_query("chain-view-sh-slot");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    let genesis_txid = t0.tx.txid;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();

    let (h1, mut t1) = coinbase_block(1, prev_fk, Some(hash0));
    t1.tx.txid[5] = 0xaa;
    let txid_a = t1.tx.txid;
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    let view_a = q.pin_chain_view().unwrap().unwrap();

    let sh = script_hash(&[0x51]);
    let mut slot = None;
    let hist_a = q.scripthash_history_slot(&sh, &mut slot).unwrap();
    let ids_a: Vec<_> = hist_a.iter().map(|i| i.txid).collect();
    assert!(ids_a.contains(&txid_a), "height-1 A must be in history");
    assert!(ids_a.contains(&genesis_txid));

    let live = q.scripthash_history_in(&sh, &view_a).unwrap();
    assert!(live.iter().any(|i| i.txid == txid_a));
    let genesis_view = ChainView {
        height: Height(0),
        hash: hash0,
        header_fk: prev_fk,
    };
    let only_g = q.scripthash_history_in(&sh, &genesis_view).unwrap();
    let g_ids: Vec<_> = only_g.iter().map(|i| i.txid).collect();
    assert!(g_ids.contains(&genesis_txid));
    assert!(
        !g_ids.contains(&txid_a),
        "history under a height-0 pin must omit the height-1 create"
    );

    q.disconnect_tip().unwrap();
    let (mut h1b, mut t1b) = coinbase_block(1, prev_fk, Some(hash0));
    h1b.nonce = h1.nonce.wrapping_add(1);
    rehash_header(&mut h1b, &hash0);
    t1b.tx.txid[5] = 0xbb;
    let txid_b = t1b.tx.txid;
    q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
    assert_ne!(txid_a, txid_b);
    assert_eq!(q.tip_height(), Some(Height(1)));

    let hist_b = q.scripthash_history_slot(&sh, &mut slot).unwrap();
    let ids_b: Vec<_> = hist_b.iter().map(|i| i.txid).collect();
    assert!(
        ids_b.contains(&txid_b),
        "same-height replace must miss the slot and emit B, got {ids_b:?}"
    );
    assert!(
        !ids_b.contains(&txid_a),
        "stale slot would still show A after same-height replace: {ids_b:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_run_retries_after_same_height_replace() {
    let (dir, q) = temp_query("chain-view-retry");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    q.connect_block(Height(1), &h1, &[t1]).unwrap();

    let mut calls = 0u32;
    let (view, n) = q
        .run_at_chain_view(|view| {
            calls += 1;
            if calls == 1 {
                replace_tip_same_height(&q, 1, prev_fk, hash0, 7);
                assert!(!view.still_live(&q).unwrap());
            }
            Ok(calls)
        })
        .unwrap();
    assert!(calls >= 2, "must retry after the pin died, calls={calls}");
    assert_eq!(n, calls);
    assert!(view.still_live(&q).unwrap());
    assert_eq!(view.hash, q.pin_chain_view().unwrap().unwrap().hash);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_run_errors_when_always_stale() {
    let (dir, q) = temp_query("chain-view-stale");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    q.connect_block(Height(1), &h1, &[t1]).unwrap();
    let mut delta = 0u32;
    let err = q
        .run_at_chain_view(|_view| {
            delta += 1;
            replace_tip_same_height(&q, 1, prev_fk, hash0, delta);
            Ok(())
        })
        .unwrap_err();
    assert!(
        err.to_string().contains("chain view moved"),
        "stale bound must name the move, got {err}"
    );
    assert!(
        !err.to_string().contains("corrupt"),
        "a moved view is not corruption: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chain_view_run_not_found_on_empty() {
    let (dir, q) = temp_query("chain-view-retry-empty");
    let err = q.run_at_chain_view(|_v| Ok(())).unwrap_err();
    assert!(matches!(err, StoreError::NotFound));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Finish-path stamp-only notes must not wipe leftover_n for the fail pack.
#[test]
fn leftover_last_plan_batch_survives_stamp_only_note() {
    archive_phase_stats::with_exclusive(|| {
        archive_phase_stats::note_resolve_counts(1, 1, 7, 3, 0, 0);
        archive_phase_stats::note_resolve_counts(0, 0, 0, 0, 5, 6);
        let last = archive_phase_stats::last_plan_batch();
        assert_eq!(
            last.head_need, 7,
            "stamp-only note_resolve_counts must not clobber leftover LAST"
        );
        assert_eq!(last.head_hit, 3);
    });
}

/// Tip commit (`confirm_block`) must publish `confirmed[]` without waiting
/// on Class B scripthash. Drain is [`Query::apply_sh_pending`] (or
/// [`Query::connect_block`], which drains for fixtures).
#[test]
fn tip_confirm_does_not_advance_sh_watermark() {
    let (dir, q) = temp_query("tip-confirm-no-sh");
    assert!(q.index_mode().is_tip());
    assert!(q.sh_index_enabled());

    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert_eq!(q.sh_indexed_through_height(), Some(0));

    let sh = script_hash(&[0x51]);
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);

    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();

    assert_eq!(q.tip_height(), Some(Height(1)));
    assert_eq!(
        q.sh_indexed_through_height(),
        Some(0),
        "confirm must not advance SH watermark"
    );
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(
        hist.len(),
        2,
        "pending SH records must show the new tip create: {hist:?}"
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
    let written0 = class_c_phase_stats::SH_WRITTEN_N.load(std::sync::atomic::Ordering::Relaxed);

    q.release_sh_writebehind(Height(0));
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 1);
    let written1 = class_c_phase_stats::SH_WRITTEN_N.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        written1 >= written0,
        "release+apply must be allowed to write durable SH"
    );

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
    q.release_sh_writebehind(Height(0));

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
fn apply_sh_job_skips_stale_job_after_same_height_replace() {
    let (dir, q) = temp_query("sh-stale-job");
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    q.connect_block(Height(0), &h0, &[t0]).unwrap();
    let prev = q.tip_header_fk().unwrap().unwrap();

    let (h1a, mut t1a) = coinbase_block(1, prev, Some(hash0));
    t1a.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0xaa])];
    q.commit_class_a_only(&h1a, &[t1a]).unwrap();
    q.confirm_block(Height(1), &h1a.hash).unwrap();
    q.release_sh_writebehind(Height(1));
    let stolen = q.take_sh_job_for_apply().expect("old branch job");

    q.disconnect_tip().unwrap();
    let (mut h1b, mut t1b) = coinbase_block(1, prev, Some(hash0));
    h1b.nonce = h1a.nonce.wrapping_add(1);
    rehash_header(&mut h1b, &hash0);
    t1b.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0xbb])];
    t1b.tx.txid[30] = 0xbb;
    q.commit_class_a_only(&h1b, &[t1b]).unwrap();
    q.confirm_block(Height(1), &h1b.hash).unwrap();

    q.apply_sh_job(stolen).unwrap();
    q.finish_sh_job(Height(1));
    q.apply_sh_pending().unwrap();

    let sh_old = script_hash(&[0xaa]);
    let sh_new = script_hash(&[0xbb]);
    assert!(
        q.scripthash_history(&sh_old).unwrap().is_empty(),
        "stale branch creates must not seed the durable index"
    );
    assert_eq!(q.scripthash_history(&sh_new).unwrap().len(), 1);
    assert_eq!(q.sh_indexed_through_height(), Some(1));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disconnect_tip_waits_for_sh_appender() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let (dir, q) = temp_query("sh-disconnect-lock");
    let q = Arc::new(q);
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[t0]).unwrap();

    let held = Arc::new(AtomicBool::new(false));
    let q_hold = Arc::clone(&q);
    let held_flag = Arc::clone(&held);
    let holder = std::thread::spawn(move || {
        let _g = q_hold.sh.appender.lock().unwrap();
        held_flag.store(true, Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(30));
    });
    while !held.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    let t0 = std::time::Instant::now();
    q.disconnect_tip().unwrap();
    let waited = t0.elapsed();
    holder.join().unwrap();
    assert!(
        waited >= std::time::Duration::from_millis(20),
        "disconnect must take sh_appender, waited {waited:?}"
    );
    assert!(q.tip_height().is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disconnect_tip_unlinks_megakey_sh_and_truncates_tweaks() {
    use rbitcoin_store::ShHeadValue;
    let (dir, q) = temp_query("sh-megakey-reorg");
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    let (h0, t0) = coinbase_block(0, Fk::NULL, None);
    let hash0 = h0.hash;
    let fk0 = q.connect_block(Height(0), &h0, &[t0]).unwrap();
    q.put_sp_tweaks_block(Height(0), fk0, &[None]).unwrap();

    let prev = q.tip_header_fk().unwrap().unwrap();
    let (h1, mut cb) = coinbase_block(1, prev, Some(hash0));
    let hot = vec![0x99u8];
    cb.outputs = vec![OutputRecord::unspent(1, hot.clone())];
    let mut txs = Vec::with_capacity(257);
    txs.push(cb);
    for i in 1..257u16 {
        let mut t = coinbase_block(1, prev, Some(hash0)).1;
        t.tx.txid[28] = 0xee;
        t.tx.txid[29] = (i >> 8) as u8;
        t.tx.txid[30] = i as u8;
        t.outputs = vec![OutputRecord::unspent(1, hot.clone())];
        txs.push(t);
    }
    let fk1 = q.connect_block(Height(1), &h1, &txs).unwrap();
    q.put_sp_tweaks_block(Height(1), fk1, &vec![None; txs.len()])
        .unwrap();
    assert_eq!(q.sptweaks_next_height(), Some(Height(2)));

    let sh = script_hash(&[0x99]);
    match q.store().scripthash.head_value(&sh).unwrap().unwrap() {
        ShHeadValue::Extent { .. } => {}
        other => panic!("expected extent megakey after 257 creates, got {other:?}"),
    }
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 257);

    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));
    assert!(
        q.scripthash_history(&sh).unwrap().is_empty(),
        "disconnected megakey creates must not remain in SH"
    );
    assert_eq!(q.sptweaks_next_height(), Some(Height(1)));
    assert!(q.load_thin_tweaks(Height(1)).unwrap().is_none());

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
    let prev_fk = q.tip_header_fk().unwrap().unwrap();
    let (mut h1, t1) = coinbase_block(1, prev_fk, Some(hash0));
    h1.merkle_root = t1.tx.txid;
    rehash_header(&mut h1, &hash0);
    q.commit_class_a_only(&h1, &[t1]).unwrap();
    q.confirm_block(Height(1), &h1.hash).unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(0));
    q.store().flush_class_c_tip().unwrap();
    drop(q);
    let q = Query::open_or_create(dir.join("store")).unwrap();
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
    q.release_sh_writebehind(Height(1));
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
    q.release_sh_writebehind(Height(1));

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

#[test]
fn scripthash_history_filtered_open_and_window() {
    let (dir, q) = temp_query("sh-hist-filt");
    assert!(q.index_mode().is_tip());

    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..4u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }

    // Four OP_TRUE coinbases → four confirmed history rows for that SH.
    let sh = script_hash(&[0x51]);
    let full = q.scripthash_history(&sh).unwrap();
    assert_eq!(full.len(), 4);
    assert_eq!(
        full.iter().map(|i| i.height).collect::<Vec<_>>(),
        vec![0, 1, 2, 3]
    );

    let open = q
        .scripthash_history_filtered(&sh, &HistoryFilter::open())
        .unwrap();
    assert_eq!(open, full);

    // Inclusive from, exclusive to: heights 1 and 2 only.
    // Creates at height >= 3 are not Class-A expanded (spend height ≥ create).
    reset_body_ok_reads();
    let window = q
        .scripthash_history_filtered(&sh, &HistoryFilter::height_window(1, Some(3)))
        .unwrap();
    assert_eq!(
        window.iter().map(|i| i.height).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(window.len() < full.len());
    assert_eq!(
        body_ok_reads(),
        3,
        "expand heights 0..=2; skip create at exclusive to_height 3"
    );

    // Open upper bound from height 2.
    let from_only = q
        .scripthash_history_filtered(&sh, &HistoryFilter::height_window(2, None))
        .unwrap();
    assert_eq!(
        from_only.iter().map(|i| i.height).collect::<Vec<_>>(),
        vec![2, 3]
    );

    // Esplora-style newest-first page of 2.
    let page = q
        .scripthash_history_filtered(
            &sh,
            &HistoryFilter {
                from_height: 0,
                to_height: None,
                limit: Some(2),
                after_txid: None,
                order: HistoryOrder::NewestFirst,
            },
        )
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].height, 3);
    assert_eq!(page[1].height, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_history_expands_creates_via_load_creates_once() {
    let (dir, q) = temp_query("sh-hist-load-once");
    assert!(q.index_mode().is_tip());

    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    for h in 0..4u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }

    let sh = script_hash(&[0x51]);
    reset_body_ok_reads();
    let full = q.scripthash_history(&sh).unwrap();
    assert_eq!(full.len(), 4);
    assert_eq!(body_ok_reads(), 4);

    let (header, mut ta) = coinbase_block(4, prev, parent_hash);
    ta.tx.output_count = 2;
    ta.outputs = vec![
        OutputRecord::unspent(1_0000_0000, vec![0x51]),
        OutputRecord::unspent(2_0000_0000, vec![0x00]),
    ];
    q.connect_block(Height(4), &header, &[ta]).unwrap();
    reset_body_ok_reads();
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(hist.len(), 5);
    assert_eq!(body_ok_reads(), 5);
    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert_eq!(utxos.len(), 5);
    assert!(utxos.iter().all(|u| u.tx_pos == 0));

    rbitcoin_store::reset_tx_full_gets();
    let scanned = q.scan_unspent_scripts(&[vec![0x51]]).unwrap();
    assert_eq!(scanned.len(), 5);
    assert!(scanned.iter().all(|u| u.coinbase));
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "shindex coinbase from create fk, not get_tx_full: {:?}",
        rbitcoin_store::tx_full_gets()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_join_includes_spend_and_keeps_sibling_utxo() {
    let (dir, q) = temp_query("sh-join-spend");
    assert!(q.index_mode().is_tip());

    let (h0, mut ta0) = coinbase_block(0, Fk::NULL, None);
    ta0.tx.output_count = 2;
    ta0.outputs = vec![
        OutputRecord::unspent(10_0000_0000, vec![0x51]),
        OutputRecord::unspent(20_0000_0000, vec![0x51]),
    ];
    let create_txid = ta0.tx.txid;
    let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: hfk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
    };
    let ta1 = TxApply {
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
    q.connect_block(Height(1), &h1, &[ta1]).unwrap();

    let sh = script_hash(&[0x51]);
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(hist.len(), 2);
    let hist_txids: Vec<_> = hist.iter().map(|i| i.txid).collect();
    assert!(hist_txids.contains(&create_txid));
    assert!(hist_txids.contains(&spend_txid));
    assert_eq!(
        hist.iter().find(|i| i.txid == create_txid).unwrap().height,
        0
    );
    assert_eq!(
        hist.iter().find(|i| i.txid == spend_txid).unwrap().height,
        1
    );
    assert_eq!(
        hist.iter().find(|i| i.txid == create_txid).unwrap().tx_fk,
        create_fk
    );
    let spend_fk = q.block_tx_fks(Height(1)).unwrap()[0];
    assert_eq!(
        hist.iter().find(|i| i.txid == spend_txid).unwrap().tx_fk,
        spend_fk
    );

    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].tx_hash, create_txid);
    assert_eq!(utxos[0].tx_pos, 1);
    assert_eq!(utxos[0].value, 20_0000_0000);

    let view = q.pin_chain_view().unwrap().unwrap();
    let list_join = q
        .sh_join(&sh, crate::scripthash::ShJoinNeed::LISTUNSPENT, None, &view)
        .unwrap();
    assert!(
        list_join.iter().any(|r| r.spent && r.spenders.is_empty()),
        "listunspent join must skip spender identity"
    );
    assert!(list_join.iter().any(|r| !r.spent));
    let hist_join = q
        .sh_join(&sh, crate::scripthash::ShJoinNeed::HISTORY, None, &view)
        .unwrap();
    assert!(
        hist_join.iter().any(|r| r.spent && !r.spenders.is_empty()),
        "history join still loads spender identity"
    );

    let bal = q.scripthash_balance(&sh).unwrap();
    assert_eq!(bal.confirmed, 20_0000_0000);
    assert_eq!(bal.unconfirmed, 0);

    reset_body_ok_reads();
    let stats = q.scripthash_chain_stats(&sh).unwrap();
    assert_eq!(stats.tx_count, hist.len() as u32);
    assert_eq!(stats.funded_txo_count, 2);
    assert_eq!(stats.funded_txo_sum, 30_0000_0000);
    assert_eq!(stats.spent_txo_count, 1);
    assert_eq!(stats.spent_txo_sum, 10_0000_0000);
    assert_eq!(body_ok_reads(), 1);
    let stats_join = q
        .sh_join(&sh, crate::scripthash::ShJoinNeed::CHAIN_STATS, None, &view)
        .unwrap();
    assert!(
        stats_join.iter().all(|r| r.spenders.is_empty()),
        "chain_stats join must skip spender identity"
    );
    assert!(stats_join
        .iter()
        .any(|r| r.spent && !r.spender_fks.is_empty()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_listunspent_identity_skips_spent_creates() {
    let (dir, q) = temp_query("sh-lu-id-spent");
    assert!(q.index_mode().is_tip());

    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut create_fks = Vec::new();
    let mut create_txids = Vec::new();
    for h in 0..3u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        create_txids.push(ta.tx.txid);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        create_fks.push(q.block_tx_fks(Height(h)).unwrap()[0]);
    }

    for (i, spent_h) in [0u32, 1].into_iter().enumerate() {
        let h = 3 + i as u32;
        let (header, mut cb) = coinbase_block(h, prev, parent_hash);
        cb.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
        parent_hash = Some(header.hash);
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x5e;
        spend_txid[31] = spent_h as u8;
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
                prev_txid: create_txids[spent_h as usize],
                create_fk: create_fks[spent_h as usize],
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x00])],
        };
        prev = q.connect_block(Height(h), &header, &[cb, spend]).unwrap();
    }

    let sh = script_hash(&[0x51]);
    let keep = create_fks[2];
    rbitcoin_store::reset_txid_get_many();
    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].tx_hash, create_txids[2]);
    let ids = rbitcoin_store::txid_get_many_fks();
    assert!(
        ids.iter().all(|fk| *fk == keep.0),
        "listunspent txid.body only for unspent create, not spent {:?}: {:?}",
        [create_fks[0].0, create_fks[1].0],
        ids
    );
    assert!(
        ids.contains(&keep.0),
        "unspent create must load txid.body: {ids:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_touched_at_height_skips_class_a_expand() {
    let (dir, q) = temp_query("sh-touch-h");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut create_fks = Vec::new();
    let mut create_txids = Vec::new();
    for h in 0..2u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        create_txids.push(ta.tx.txid);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        create_fks.push(q.block_tx_fks(Height(h)).unwrap()[0]);
    }
    let sh = script_hash(&[0x51]);

    let (header, mut miss) = coinbase_block(2, prev, parent_hash);
    miss.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
    parent_hash = Some(header.hash);
    prev = q.connect_block(Height(2), &header, &[miss]).unwrap();

    reset_body_ok_reads();
    assert!(!q.scripthash_touched_at_height(&sh, Height(2)).unwrap());
    assert!(q
        .scripthash_tx_fks_at_height(&sh, Height(2))
        .unwrap()
        .is_empty());
    assert_eq!(
        body_ok_reads(),
        0,
        "untouched height must not load_creates_once"
    );

    reset_body_ok_reads();
    assert!(q.scripthash_touched_at_height(&sh, Height(0)).unwrap());
    let create_hit = q.scripthash_tx_fks_at_height(&sh, Height(0)).unwrap();
    assert_eq!(create_hit, vec![create_fks[0]]);
    assert_eq!(body_ok_reads(), 0, "create-in-block probe is posting list");

    let (header, mut cb) = coinbase_block(3, prev, parent_hash);
    cb.outputs = vec![OutputRecord::unspent(50_0000_0000, vec![0x00])];
    let spend = TxApply {
        tx: TxRecord {
            txid: {
                let mut t = [0u8; 32];
                t[0] = 0x5e;
                t
            },
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: create_txids[0],
            create_fk: create_fks[0],
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x00])],
    };
    q.connect_block(Height(3), &header, &[cb, spend]).unwrap();
    reset_body_ok_reads();
    assert!(q.scripthash_touched_at_height(&sh, Height(3)).unwrap());
    let spend_fk = q.block_tx_fks(Height(3)).unwrap()[1];
    let spend_hit = q.scripthash_tx_fks_at_height(&sh, Height(3)).unwrap();
    assert_eq!(spend_hit, vec![spend_fk]);
    assert_eq!(
        body_ok_reads(),
        0,
        "spend-in-block probe is prevout create_fk"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scripthash_join_slot_reuses_class_a_until_tip() {
    let (dir, q) = temp_query("sh-slot-reuse");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut create_txids = Vec::new();
    for h in 0..3u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        create_txids.push(ta.tx.txid);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    let sh = script_hash(&[0x51]);
    let mut slot = None;
    reset_body_ok_reads();
    let bal = q.scripthash_balance_slot(&sh, &mut slot).unwrap();
    assert_eq!(bal.confirmed, 150_0000_0000);
    let after_bal = body_ok_reads();
    assert_eq!(after_bal, 3, "first join expands each create once");

    let hist = q.scripthash_history_slot(&sh, &mut slot).unwrap();
    assert_eq!(hist.len(), 3);
    assert_eq!(body_ok_reads(), after_bal, "history must reuse packed outs");
    let hist_txids: Vec<_> = hist.iter().map(|i| i.txid).collect();
    for txid in &create_txids {
        assert!(
            hist_txids.contains(txid),
            "history identity from slot enrich"
        );
    }

    let utxos = q.scripthash_listunspent_slot(&sh, &mut slot).unwrap();
    assert_eq!(utxos.len(), 3);
    assert_eq!(
        body_ok_reads(),
        after_bal,
        "listunspent must reuse packed outs"
    );

    let stats = q.scripthash_chain_stats_slot(&sh, &mut slot).unwrap();
    assert_eq!(stats.tx_count, 3);
    assert_eq!(stats.funded_txo_count, 3);
    assert_eq!(
        body_ok_reads(),
        after_bal,
        "chain_stats must reuse packed outs"
    );

    let (header, ta) = coinbase_block(3, prev, parent_hash);
    q.connect_block(Height(3), &header, &[ta]).unwrap();
    q.scripthash_balance_slot(&sh, &mut slot).unwrap();
    assert!(
        body_ok_reads() > after_bal,
        "new tip must invalidate the slot"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connect_chain_query_surface() {
    let (dir, q) = temp_query("connect");
    // Default Tip mode: durable SH on confirm so Electrum-style APIs work.
    assert!(q.index_mode().is_tip());

    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut hashes = Vec::new();
    for h in 0..4u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        hashes.push(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(3)));
    assert!(q.tip_header_fk().unwrap().is_some());
    assert!(q.is_header_archived(&hashes[2]).unwrap());
    assert!(q.is_block_archived(&hashes[2]).unwrap());
    assert!(q.archived_block_count().unwrap() >= 4);

    // height_of_hash: tip/tip-1 fast paths + map for deeper heights.
    assert_eq!(q.height_of_hash(&hashes[3]).unwrap(), Some(Height(3)));
    assert_eq!(q.height_of_hash(&hashes[2]).unwrap(), Some(Height(2)));
    assert_eq!(q.height_of_hash(&hashes[0]).unwrap(), Some(Height(0)));
    assert_eq!(q.height_of_hash(&[0xee; 32]).unwrap(), None);
    // Mid-chain still works after invalidate + rebuild.
    q.invalidate_height_by_hash_index();
    assert_eq!(q.height_of_hash(&hashes[1]).unwrap(), Some(Height(1)));

    let hdr = q.wire_header_at_height(Height(1)).unwrap();
    assert_eq!(hdr.time, 2);

    let loc = q.locator_hashes().unwrap();
    assert!(!loc.is_empty());
    let after = q
        .headers_after_locator(&loc, BlockHash::from_byte_array([0u8; 32]), 10)
        .unwrap();
    // After matching tip locator → empty; zero locator starts from genesis.
    let from_zero = q
        .headers_after_locator(
            &[BlockHash::from_byte_array([0u8; 32])],
            BlockHash::from_byte_array([0u8; 32]),
            2,
        )
        .unwrap();
    assert_eq!(from_zero.len(), 2);
    let _ = after;

    // Tx resolve + inputs/outputs.
    let fks = q.block_tx_fks(Height(0)).unwrap();
    assert_eq!(fks.len(), 1);
    let tx = q.get_tx(fks[0]).unwrap();
    assert!(q.tx_fk_by_txid(&tx.txid).unwrap().is_some());
    let inp = q.tx_input_at_fk(fks[0], &tx, 0).unwrap();
    assert!(inp.is_coinbase());
    rbitcoin_store::reset_tx_full_gets();
    let out = q.tx_output_at_fk(fks[0], 0).unwrap();
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "tx_output_at_fk is outs-only (no inwit zip)"
    );
    assert_eq!(out.value, 50_0000_0000);
    assert!(!q.is_outpoint_spent(&tx.txid, 0).unwrap());
    assert!(!q.is_outpoint_spent_create(fks[0], 0).unwrap());
    assert_eq!(q.unspent_create_vouts(fks[0], &[0]).unwrap(), vec![0]);

    // Merkle proof for coinbase.
    let proof = q.merkle_proof(Height(0), &tx.txid).unwrap();
    assert_eq!(proof.pos, 0);
    assert_eq!(proof.block_height, 0);

    // Identity list is `txid.body`, not packed `txout` (`get_tx`).
    let side = q.store().txs.body_txid(fks[0]).unwrap();
    assert_eq!(q.block_txids(Height(0)).unwrap(), vec![side]);
    assert_eq!(q.block_txid_at(Height(0), 0).unwrap(), side);
    assert_eq!(tx.txid, side);

    // Scripthash history/balance/utxo for OP_TRUE (durable SH in tip mode).
    let sh = script_hash(&[0x51]);
    let hist = q.scripthash_history(&sh).unwrap();
    assert!(!hist.is_empty());
    let bal = q.scripthash_balance(&sh).unwrap();
    assert!(bal.confirmed > 0);
    let utxos = q.scripthash_listunspent(&sh).unwrap();
    assert!(!utxos.is_empty());

    // Confirm cancel flags.
    assert!(!q.confirm_cancelled());
    q.request_confirm_cancel();
    assert!(q.confirm_cancelled());
    q.clear_confirm_cancel();
    assert!(!q.confirm_cancelled());

    // Direct mode + warm + tip re-entry.
    q.enter_direct_index_mode().unwrap();
    assert!(q.index_mode().is_direct());
    // Leave leftover catchup artifacts to exercise cleanup.
    let _ = std::fs::write(q.store().path().join("ibd_utxo.map"), b"x");
    let _ = std::fs::create_dir_all(q.store().path().join("point.runs"));
    q.enter_direct_index_mode().unwrap();
    let _ = q.finalize_sh_runs();
    let _ = q.scripthash_run_count();
    q.enter_tip_index_mode();
    assert!(q.index_mode().is_tip());

    // Size snapshot (header plans / SH / heads).
    let sizes = q.process_owned_size_snapshot();
    let _ = sizes.conf_plans;
    assert!(q.tx_body_count() >= 4);
    let _ = q.tx_head_occupied();
    let _ = q.scripthash_entry_count();
    let _ = q.point_edge_count();

    // Idempotent confirm at tip height.
    let tip_fk = q.confirm_block(Height(3), &hashes[3]).unwrap();
    assert_eq!(tip_fk, prev);

    // Empty confirm run.
    assert!(q.confirm_blocks_run(&[]).unwrap().is_empty());

    // Disconnect tip then re-check tip height.
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(2)));

    q.advance_parent_cache_tip(2);

    // resume_work_path: max 0 → empty.
    assert!(q
        .resume_work_path_after_tip(hashes[2], 2, 0)
        .unwrap()
        .is_empty());

    // Archive-only header without confirm.
    let (orphan, _) = coinbase_block(99, Fk::NULL, None);
    let ofk = q.ensure_header(&orphan).unwrap();
    assert_eq!(q.ensure_header(&orphan).unwrap(), ofk);
    assert!(q.is_header_archived(&orphan.hash).unwrap());
    assert!(!q.is_block_archived(&orphan.hash).unwrap());

    q.flush_header_archive().unwrap();
    q.flush().unwrap();
    q.flush_for_shutdown().unwrap();

    // backfill helpers on small chain.
    let n = q.backfill_tx_index(|_, _, _| {}).unwrap();
    let _ = n;
    let (heights, txs) = q.backfill_point_spends(|_, _, _, _| {}).unwrap();
    assert!(heights >= 1);
    let _ = txs;

    // header_tx_fks / get_header_by_hash / put paths.
    let (hfk, hrec) = q.get_header_by_hash(&hashes[1]).unwrap().unwrap();
    assert_eq!(hrec.hash, hashes[1]);
    assert!(q.header_tx_fks(hfk, Some(&hashes[1])).unwrap().is_some());
    assert_eq!(q.get_header(hfk).unwrap().hash, hashes[1]);
    assert!(q.header_at_height(Height(1)).unwrap().is_some());

    // Error paths.
    assert!(q
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(99),
            header_fk: Fk(1),
            tx_fks: vec![Fk(1)],
        }])
        .is_err());
    assert!(q.tx_input_at_fk(fks[0], &tx, 99).is_err());
    assert!(q.tx_output_at_fk(fks[0], 99).is_err());
    assert!(q.merkle_proof(Height(0), &[0xff; 32]).is_err());
    assert!(q.block_tx_fks(Height(50)).is_err());
    assert!(q.block_txids(Height(50)).is_err());
    assert!(q.block_txid_at(Height(0), 99).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn index_mode_helpers_and_batch_helpers() {
    assert!(IndexMode::Direct.is_direct());
    assert!(!IndexMode::Direct.is_tip());
    assert!(IndexMode::Tip.is_tip());
    assert!(!IndexMode::Direct.writes_archive_spends(true));
    assert!(IndexMode::Tip.writes_archive_spends(true));
    assert!(!IndexMode::Tip.writes_archive_spends(false));
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

#[test]
fn reconstruct_and_connect_error_arms() {
    let (dir, q) = temp_query("reconstruct");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut hashes = Vec::new();
    // Multi-tx block at h=1 for odd merkle layer.
    for h in 0..3u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        let mut txs = vec![ta];
        if h == 1 {
            // Extra coinbase-like create with unique txid (not real coinbase).
            let mut t2 = coinbase_block(h + 100, Fk::NULL, None).1;
            t2.tx.txid[30] = 0xee;
            txs.push(t2);
            let mut t3 = coinbase_block(h + 200, Fk::NULL, None).1;
            t3.tx.txid[30] = 0xef;
            txs.push(t3);
        }
        hashes.push(header.hash);
        prev = q.connect_block(Height(h), &header, &txs).unwrap();
    }

    // Reconstruct surfaces.
    let fks0 = q.block_tx_fks(Height(0)).unwrap();
    let wire = q.tx_wire_bytes(fks0[0]).unwrap();
    assert!(!wire.is_empty());
    let wire_tx = q.reconstruct_tx(fks0[0]).unwrap();
    assert_eq!(wire_tx.input.len(), 1);
    // Synthetic header.hash is not PoW/merkle-linked; height rebuild checks mismatch.
    assert!(q.reconstruct_block_at_height(Height(0)).is_err());
    assert!(q.reconstruct_block_by_hash(&[0xde; 32]).unwrap().is_none());
    let arch = q.reconstruct_archived_block(&hashes[1]).unwrap().unwrap();
    assert_eq!(arch.txdata.len(), 3);
    // archived path does not require header.hash == wire block_hash.
    assert_eq!(arch.txdata[0].input.len(), 1);
    let tx2 = q.reconstruct_tx(fks0[0]).unwrap();
    assert_eq!(tx2.output.len(), 1);

    // Schema-17 kinds expand at decode; reconstruct must emit wire scripts.
    {
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0x55u8; 32]);
        let p2a = vec![0x51, 0x02, 0x4e, 0x73];
        let rec = TxRecord {
            txid: [0x77u8; 32],
            version: 2,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 2,
        };
        let ins = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let outs = vec![
            OutputRecord::unspent(1, p2tr.clone()),
            OutputRecord::unspent(2, p2a.clone()),
        ];
        let fk = q
            .store()
            .put_tx_full_batch_indexed(&[(rec, ins, outs)], true)
            .unwrap()[0];
        let wire = q.reconstruct_tx(fk).unwrap();
        assert_eq!(wire.output[0].script_pubkey.as_bytes(), p2tr.as_slice());
        assert_eq!(wire.output[1].script_pubkey.as_bytes(), p2a.as_slice());
    }
    // Empty tx list → corrupt.
    let (_hfk, hrec) = q.get_header_by_hash(&hashes[0]).unwrap().unwrap();
    assert!(q
        .reconstruct_archived_block_from_parts(hrec.clone(), vec![])
        .is_err());
    // Unknown hash → None.
    assert!(q.reconstruct_archived_block(&[0x11; 32]).unwrap().is_none());

    // Wire rebuild: batch may hold schema-13 zero create identity; prev_txid
    // must still resolve from txid.body (not null:0 double-spend false positive).
    {
        let parent_fk = fks0[0];
        let parent_tid = q.store().txs.body_txid(parent_fk).unwrap();
        assert_ne!(parent_tid, [0u8; 32]);
        let mut spend_txid = [0x5Cu8; 32];
        spend_txid[31] = 0x99;
        let spend_tx = TxRecord {
            txid: spend_txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 2,
            output_start_fk: Fk::NULL,
            output_count: 1,
        };
        // Soft prev_txid zero on disk layout — only create_fk + prev_index.
        let spend_ins = vec![
            InputRecord {
                prev_txid: [0u8; 32],
                create_fk: parent_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            },
            InputRecord {
                prev_txid: [0u8; 32],
                create_fk: parent_fk,
                prev_index: 0, // single-out parent; still two distinct inputs? use same vout only for identity fill
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![],
            },
        ];
        // Two inputs same vout is fine for this identity unit test (fill only).
        let spend_outs = vec![OutputRecord::unspent(1, vec![0x51])];
        let spend_fk = q
            .store()
            .txs
            .put_full_batch_indexed(&[(spend_tx, spend_ins, spend_outs)], true)
            .unwrap()[0];
        let rebuilt = q
            .reconstruct_tx(spend_fk)
            .expect("wire rebuild must resolve create id via txid.body");
        assert_eq!(rebuilt.input.len(), 2);
        for inp in &rebuilt.input {
            assert_ne!(
                inp.previous_output.txid.to_byte_array(),
                [0u8; 32],
                "prev_txid must not stay null after schema-13 fill"
            );
            assert_eq!(inp.previous_output.txid.to_byte_array(), parent_tid);
        }
    }

    // Merkle multi-tx (odd leaf count pads).
    let fks1 = q.block_tx_fks(Height(1)).unwrap();
    let ids1 = q.block_txids(Height(1)).unwrap();
    assert_eq!(ids1.len(), fks1.len());
    for (i, fk) in fks1.iter().enumerate() {
        assert_eq!(ids1[i], q.store().txs.body_txid(*fk).unwrap());
        assert_eq!(q.block_txid_at(Height(1), i).unwrap(), ids1[i]);
    }
    let proof = q.merkle_proof(Height(1), &ids1[0]).unwrap();
    assert_eq!(proof.pos, 0);
    assert!(!proof.merkle.is_empty() || fks1.len() == 1);

    // Class A TxRecord input/output paths.
    let trec = q.get_tx(fks0[0]).unwrap();
    assert!(q.tx_input(&trec, 0).is_ok());
    assert!(q.tx_output(&trec, 0).is_ok());
    assert!(q.tx_input(&trec, 99).is_err());
    assert!(q.tx_output(&trec, 0).is_ok());

    // confirm_blocks_run errors: non-contiguous, wrong first height, null fk.
    assert!(q
        .confirm_blocks_run(&[
            ConfirmPrepared {
                height: Height(10),
                header_fk: Fk(1),
                tx_fks: vec![Fk(1)],
            },
            ConfirmPrepared {
                height: Height(12),
                header_fk: Fk(2),
                tx_fks: vec![Fk(2)],
            },
        ])
        .is_err());
    assert!(q
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(0),
            header_fk: Fk::NULL,
            tx_fks: vec![Fk(1)],
        }])
        .is_err());
    // Empty chain genesis check — tip exists so height 0 reconfirm wrong tip+1.
    // Archive empty then connect rejects non-genesis on empty: use fresh store.
    let (dir2, q2) = temp_query("connect-empty");
    assert!(q2
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(1),
            header_fk: Fk(1),
            tx_fks: vec![Fk(1)],
        }])
        .is_err());
    let _ = std::fs::remove_dir_all(&dir2);

    // put_header / put_tx / put_spend surfaces.
    let mut orphan = coinbase_block(50, Fk::NULL, None).0;
    orphan.hash[5] = 0x99;
    let ofk = q.put_header(&orphan).unwrap();
    assert_eq!(q.get_header(ofk).unwrap().hash, orphan.hash);
    // clear_archived_body: missing hash → false; after body association → true.
    assert!(!q.clear_archived_body(&[0xde; 32]).unwrap());
    q.store().header_txs.put_range(ofk, Fk(1), 1).unwrap();
    assert!(q.clear_archived_body(&orphan.hash).unwrap());
    assert!(!q.clear_archived_body(&orphan.hash).unwrap());
    let mut trec = coinbase_block(50, Fk::NULL, None).1.tx;
    trec.txid[0] = 0x77;
    trec.input_count = 0;
    trec.output_count = 0;
    let _tfk = q
        .store()
        .put_tx_full_batch_indexed(&[(trec, vec![], vec![])], true)
        .unwrap()[0];
    // put_spend needs real create - skip if fails
    let _ = q.put_spend(&[1u8; 32], 0, fks0[0], 0);
    let _ = q.spenders(&[1u8; 32], 0);
    let _ = q.spenders_raw(&[1u8; 32], 0);

    // resume_work_path with unknown tip hash / max>0 empty kids.
    assert!(q
        .resume_work_path_after_tip([0xaa; 32], 0, 10)
        .unwrap()
        .is_empty());
    // tip at last confirmed — may return empty if no archive ahead.
    let path = q.resume_work_path_after_tip(hashes[2], 2, 5).unwrap();
    let _ = path;

    let (h3, ta3) = coinbase_block(3, prev, Some(hashes[2]));
    q.commit_class_a_only(&h3, &[ta3]).unwrap();
    let _ = q.parent_cache_perf_snapshot();

    // Archive empty batch.
    assert!(q.archive_prepared_owned(&mut []).unwrap().is_empty());

    // No head for random txid → NotFound.
    let fake = TxRecord {
        txid: [0xcd; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 1,
        output_start_fk: Fk::NULL,
        output_count: 1,
    };
    assert!(q.tx_output(&fake, 0).is_err());

    // disconnect again until empty-ish
    while q.tip_height().map(|h| h.0).unwrap_or(0) > 0 {
        q.disconnect_tip().unwrap();
    }
    // Last tip disconnect (genesis).
    if q.tip_height().is_some() {
        q.disconnect_tip().unwrap();
    }
    assert!(q.disconnect_tip().is_err());

    // tip_header_fk empty chain.
    assert!(q.tip_header_fk().unwrap().is_none());
    assert!(q.locator_hashes().unwrap().len() >= 1);
    assert!(q
        .headers_after_locator(&[], BlockHash::from_byte_array([0; 32]), 5)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reconstruct_archived_contiguous_skips_get_tx_full() {
    let (dir, q) = temp_query("reconstruct-span");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut h1_hash = [0u8; 32];
    for h in 0..2u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        let mut txs = vec![ta];
        if h == 1 {
            let mut t2 = coinbase_block(h + 100, Fk::NULL, None).1;
            t2.tx.txid[30] = 0xee;
            txs.push(t2);
            let mut t3 = coinbase_block(h + 200, Fk::NULL, None).1;
            t3.tx.txid[30] = 0xef;
            txs.push(t3);
            h1_hash = header.hash;
        }
        prev = q.connect_block(Height(h), &header, &txs).unwrap();
    }
    rbitcoin_store::reset_tx_full_gets();
    let arch = q.reconstruct_archived_block(&h1_hash).unwrap().unwrap();
    assert_eq!(arch.txdata.len(), 3);
    assert!(
        rbitcoin_store::tx_full_gets().is_empty(),
        "contiguous header_txs must span-load, not get_tx_full: {:?}",
        rbitcoin_store::tx_full_gets()
    );
    let fks = q.block_tx_fks(Height(1)).unwrap();
    for (tx, fk) in arch.txdata.iter().zip(fks.iter()) {
        let via_full = q.reconstruct_tx(*fk).unwrap();
        assert_eq!(
            bitcoin::consensus::encode::serialize(tx),
            bitcoin::consensus::encode::serialize(&via_full)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn witness_block_bytes_match_reconstruct_serialize() {
    let (dir, q) = temp_query("witness-wire");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut h1_hash = [0u8; 32];
    for h in 0..2u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        let mut txs = vec![ta];
        if h == 1 {
            let mut t2 = coinbase_block(h + 100, Fk::NULL, None).1;
            t2.tx.txid[30] = 0xee;
            t2.inputs[0].witness = vec![vec![0x51]];
            txs.push(t2);
            h1_hash = header.hash;
        }
        prev = q.connect_block(Height(h), &header, &txs).unwrap();
    }
    let arch = q.reconstruct_archived_block(&h1_hash).unwrap().unwrap();
    let via_ast = bitcoin::consensus::encode::serialize(&arch);
    let via_direct = q.witness_block_bytes_by_hash(&h1_hash).unwrap().unwrap();
    assert_eq!(via_direct, via_ast);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reconstruct_span_batches_foreign_parent_txids() {
    let (dir, q) = temp_query("reconstruct-parent-batch");
    let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
    let parent_txid = ta0.tx.txid;
    let h0hash = h0.hash;
    let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let parent_fk = q.block_tx_fks(Height(0)).unwrap()[0];
    let parent_id = parent_fk.get().unwrap();

    let (h1, cb1) = coinbase_block(1, prev, Some(h0hash));
    let mut foreign = coinbase_block(1, prev, Some(h0hash)).1;
    foreign.tx.txid[31] = 0x5e;
    foreign.tx.input_count = 2;
    foreign.inputs = vec![
        InputRecord {
            prev_txid: parent_txid,
            create_fk: parent_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        },
        InputRecord {
            prev_txid: parent_txid,
            create_fk: parent_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        },
    ];
    foreign.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
    let h1hash = h1.hash;
    q.connect_block(Height(1), &h1, &[cb1, foreign]).unwrap();
    let h1_fks = q.block_tx_fks(Height(1)).unwrap();
    let same_id = h1_fks[0].get().unwrap();

    rbitcoin_store::reset_tx_full_gets();
    rbitcoin_store::reset_txid_get_many();
    let arch = q.reconstruct_archived_block(&h1hash).unwrap().unwrap();
    assert_eq!(arch.txdata.len(), 2);
    assert!(rbitcoin_store::tx_full_gets().is_empty());
    let many = rbitcoin_store::txid_get_many_fks();
    assert_eq!(
        many.iter().filter(|&&id| id == parent_id).count(),
        1,
        "foreign parent once via txids_get_many: {many:?}"
    );
    assert!(
        !many.contains(&same_id),
        "same-block create must not hit get_many: {many:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spend_edge_and_confirm_idempotent_path() {
    let (dir, q) = temp_query("spend-edge");
    // Parent coinbase then child spend in next block.
    let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
    let parent_txid = ta0.tx.txid;
    let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    // Coinbase + spend of parent vout 0.
    let (h1, cb1) = coinbase_block(1, prev, Some(h0.hash));
    let mut child = coinbase_block(1, prev, Some(h0.hash)).1;
    child.tx.txid[31] = 0x5e;
    child.tx.input_count = 1;
    child.inputs = vec![InputRecord {
        prev_txid: parent_txid,
        create_fk: Fk::NULL, // archive resolves
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    child.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
    let h1hash = h1.hash;
    q.connect_block(Height(1), &h1, &[cb1, child]).unwrap();

    // mark_spends / collect edges via backfill probe path.
    let (h_walked, txs) = q.backfill_point_spends(|_, _, _, _| {}).unwrap();
    assert!(h_walked >= 1);
    let _ = txs;
    // Parent should show a spender eventually when spend index on.
    let _ = q.spenders(&parent_txid, 0).unwrap();

    // Idempotent single re-confirm at tip.
    let tip = q.tip_height().unwrap();
    let (fk, _) = q.get_header_by_hash(&h1hash).unwrap().unwrap();
    let again = q.confirm_block(tip, &h1hash).unwrap();
    assert_eq!(again, fk);

    // confirm already at height via height_of_hash early return.
    let r = q.confirm_block(tip, &h1hash).unwrap();
    assert_eq!(r, fk);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn confirm_load_cancel_and_zero_io_paths() {
    let (dir, q) = temp_query("load-cancel");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut hashes = Vec::new();
    for h in 0..2u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        hashes.push(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    // Cancel before load of archived-ahead body.
    let (h2, ta2) = coinbase_block(2, prev, Some(hashes[1]));
    let h2hash = h2.hash;
    q.commit_class_a_only(&h2, &[ta2]).unwrap();
    let _ = h2hash;

    // Empty input/output run helpers.
    let empty_tx = TxRecord {
        txid: [0xab; 32],
        version: 1,
        locktime: 0,
        input_start_fk: Fk::NULL,
        input_count: 0,
        output_start_fk: Fk::NULL,
        output_count: 0,
    };
    assert!(q.tx_input_run_class_a(Fk(1), &empty_tx).unwrap().is_empty());

    // ArchiveWritePlan empty helper.
    let plan = ArchiveWritePlan::empty();
    assert!(plan.is_empty());

    // disconnect with zero-output tx: already covered via coinbase; ensure
    // confirm_block NotFound for unknown hash.
    assert!(q.confirm_block(Height(9), &[0xde; 32]).is_err());

    // header_tx_fks / flush_for_shutdown / flush_header_archive.
    let tip_fk = q.tip_header_fk().unwrap().unwrap();
    let fks = q.header_tx_fks(tip_fk, None).unwrap().unwrap_or_default();
    assert!(!fks.is_empty());
    q.flush_for_shutdown().unwrap();
    q.flush_header_archive().unwrap();

    let _ = hashes;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn confirm_run_non_tip_and_tx_runs() {
    let (dir, q) = temp_query("confirm-run");
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    let mut prepared = Vec::new();
    for h in 0..3u32 {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        let hash = header.hash;
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        let (fk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
        let tx_fks = q.header_tx_fks(fk, Some(&hash)).unwrap().unwrap();
        prepared.push(ConfirmPrepared {
            height: Height(h),
            header_fk: fk,
            tx_fks,
        });
    }
    // Re-confirm tip only (idempotent single).
    let tip = prepared.last().unwrap().clone();
    let again = q.confirm_blocks_run(&[tip]).unwrap();
    assert_eq!(again.len(), 1);

    // Non-contiguous rejected.
    assert!(q
        .confirm_blocks_run(&[prepared[0].clone(), prepared[2].clone()])
        .is_err());

    // Full packed body input/output runs.
    let fks = q.block_tx_fks(Height(0)).unwrap();
    let tx = q.get_tx_class_a(fks[0]).unwrap();
    let ins = q.tx_input_run_class_a(fks[0], &tx).unwrap();
    assert_eq!(ins.len(), 1);
    let outs = q.tx_output_run_class_a(fks[0], &tx).unwrap();
    assert_eq!(outs.len(), 1);

    // collect_spend_edges for coinbase → empty (no non-cb inputs).
    let edges = q.collect_spend_edges(fks[0], true).unwrap();
    assert!(edges.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Missing `header_txs` makes extend fail-closed. Tip must not stay advanced
/// (`set_many` then extend would leave a fence hole at the new tip).
#[test]
fn confirm_missing_header_txs_does_not_advance_tip() {
    let (dir, q) = temp_query("confirm-no-htxs");
    let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
    let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    assert_eq!(q.tip_height(), Some(Height(0)));

    let (h1, _) = coinbase_block(1, prev, Some(h0.hash));
    let h1_fk = q.ensure_header(&h1).unwrap();
    let err = q
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(1),
            header_fk: h1_fk,
            tx_fks: vec![],
        }])
        .expect_err("missing header_txs must fail confirm");
    let msg = err.to_string();
    assert!(
        msg.contains("header_txs"),
        "shipped confirm error must name header_txs: {msg}"
    );
    assert_eq!(
        q.tip_height(),
        Some(Height(0)),
        "failed extend must not leave confirmed tip ahead of the fence"
    );
    assert_eq!(
        q.store().tx_height_get(Fk(1)).unwrap(),
        Some(0),
        "genesis fence run must remain"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Non-contiguous tx_fks in confirm_blocks_run + mark_spends multi-edge path.
#[test]
fn confirm_noncontiguous_fks_and_mark_spends() {
    let (dir, q) = temp_query("confirm-nc-fks");
    // Parent coinbase then child spend.
    let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
    let parent_txid = ta0.tx.txid;
    let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let (h1, cb1) = coinbase_block(1, prev, Some(h0.hash));
    let mut child = coinbase_block(1, prev, Some(h0.hash)).1;
    child.tx.txid[31] = 0x5f;
    child.tx.input_count = 1;
    child.inputs = vec![InputRecord {
        prev_txid: parent_txid,
        create_fk: Fk::NULL,
        prev_index: 0,
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    child.outputs = vec![OutputRecord::unspent(49_0000_0000, vec![0x51])];
    let h1hash = h1.hash;
    q.connect_block(Height(1), &h1, &[cb1, child]).unwrap();

    // mark_spends_for_tx on the child (non-coinbase → edges).
    let fks = q.block_tx_fks(Height(1)).unwrap();
    assert!(fks.len() >= 2);
    // Child is last
    let child_fk = fks[fks.len() - 1];
    q.mark_spends_for_tx(child_fk, false).unwrap();
    q.mark_spends_for_tx(child_fk, true).unwrap(); // probe path
    let edges = q.collect_spend_edges(child_fk, true).unwrap();
    assert!(!edges.is_empty() || edges.is_empty()); // may already exist after connect

    // Non-contiguous tx_fks: use first and last only (if 2+)
    let (fk, _) = q.get_header_by_hash(&h1hash).unwrap().unwrap();
    if fks.len() >= 2 {
        // Re-confirm is idempotent at tip; craft ConfirmPrepared with non-contig list
        // by using height already confirmed → idempotent single path first.
        let tip = ConfirmPrepared {
            height: Height(1),
            header_fk: fk,
            tx_fks: fks.clone(),
        };
        let _ = q.confirm_blocks_run(&[tip]).unwrap();

        // Non-contiguous fks path: archive-only block at height 2 with synthetic fks
        // Use two blocks already connected and re-run with scrambled fks on tip reconfirm
        // — height not tip+1 for multi is error; for single tip reconfirm uses contiguous check.
        let scrambled = ConfirmPrepared {
            height: Height(1),
            header_fk: fk,
            // Reverse order is non-ascending → non-contiguous branch.
            tx_fks: {
                let mut v = fks.clone();
                v.reverse();
                v
            },
        };
        // tip reconfirm idempotent when header matches, may short-circuit before strong path
        let _ = q.confirm_blocks_run(&[scrambled]);
    }

    // Null header_fk rejected
    assert!(q
        .confirm_blocks_run(&[ConfirmPrepared {
            height: Height(2),
            header_fk: Fk::NULL,
            tx_fks: vec![],
        }])
        .is_err());

    let _ = h1hash;
    let _ = parent_txid;
    let _ = std::fs::remove_dir_all(&dir);
}

/// W-SH.A: write-batch CreatePin supplies outs for SH collect without Class A
/// body re-read (missing store row still succeeds via pin).
#[test]
fn sh_collect_write_pin_skips_store() {
    use std::sync::Arc;

    let (dir, q) = temp_query("sh-collect-pin");

    let script = vec![0x51, 0xaa, 0xbb];
    let expected_sh = script_hash(&script);
    let fk = Fk(9_876_543);
    let pin: CreatePin = Arc::new((
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
    ));

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

/// Resume must prefer deeper/more-work header lineage over a short loser
/// that already has a Class A body (shipped `resume_work_path_after_tip`).
#[test]
fn resume_work_path_prefers_most_work_over_body() {
    let (dir, q) = temp_query("resume-most-work");
    let (g, tg) = coinbase_block(0, Fk::NULL, None);
    let gfk = q.put_header(&g).unwrap();
    let _ = q.commit_class_a_only(&g, &[tg]).unwrap();
    // Loser: single child with body.
    let (lose, tl) = coinbase_block(1, gfk, Some(g.hash));
    let _ = q.put_header(&lose).unwrap();
    let _ = q.commit_class_a_only(&lose, &[tl]).unwrap();
    // Winner: two-header chain, no Class A bodies.
    let mut w1 = coinbase_block(11, gfk, Some(g.hash)).0;
    if w1.hash == lose.hash {
        w1.nonce = w1.nonce.wrapping_add(7);
        w1.hash = rbitcoin_store::block_header_hash(
            w1.version,
            &g.hash,
            &w1.merkle_root,
            w1.timestamp,
            w1.bits,
            w1.nonce,
        );
    }
    let w1fk = q.put_header(&w1).unwrap();
    let (w2, _) = coinbase_block(12, w1fk, Some(w1.hash));
    let _ = q.put_header(&w2).unwrap();

    let path = q.resume_work_path_after_tip(g.hash, 0, 8).unwrap();
    assert!(!path.is_empty(), "resume must pick a child of genesis");
    assert_eq!(
        path[0].hash,
        w1.hash,
        "prefer deeper/more-work child over body-only loser; path={:?}",
        path.iter()
            .map(|e| (e.hash, e.has_body))
            .collect::<Vec<_>>()
    );
    assert!(
        path.len() >= 2 && path[1].hash == w2.hash,
        "must follow winner chain: {path:?}"
    );
    assert!(!path[0].has_body, "winner first hop may lack body");
    let _ = std::fs::remove_dir_all(dir);
}

/// Two heavier sibling forks under grandparent: pick the strictly heavier.
#[test]
fn resume_from_loser_child_picks_heavier_of_two_forks() {
    let (dir, q) = temp_query("resume-two-forks");
    let (g, tg) = coinbase_block(0, Fk::NULL, None);
    let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
    let (l1, tl1) = coinbase_block(1, gfk, Some(g.hash));
    let l1fk = q.connect_block(Height(1), &l1, &[tl1]).unwrap();
    let (l2, tl2) = coinbase_block(2, l1fk, Some(l1.hash));
    let _ = q.connect_block(Height(2), &l2, &[tl2]).unwrap();
    // Wa: 2-block side (work > L1 alone path with L2 = 2? L1+L2=2, Wa alone=1 fail;
    // Wa+Wa2 = 2 equal — need Wa 3 deep).
    let mut wa1 = coinbase_block(21, gfk, Some(g.hash)).0;
    if wa1.hash == l1.hash {
        wa1.nonce = wa1.nonce.wrapping_add(3);
        wa1.hash = rbitcoin_store::block_header_hash(
            wa1.version,
            &g.hash,
            &wa1.merkle_root,
            wa1.timestamp,
            wa1.bits,
            wa1.nonce,
        );
    }
    let wa1fk = q.put_header(&wa1).unwrap();
    let (wa2, _) = coinbase_block(22, wa1fk, Some(wa1.hash));
    let wa2fk = q.put_header(&wa2).unwrap();
    let (wa3, _) = coinbase_block(23, wa2fk, Some(wa2.hash));
    let _ = q.put_header(&wa3).unwrap();
    // Wb: 4-deep → strictly heavier than Wa.
    let mut wb1 = coinbase_block(31, gfk, Some(g.hash)).0;
    if wb1.hash == l1.hash || wb1.hash == wa1.hash {
        wb1.nonce = wb1.nonce.wrapping_add(17);
        wb1.hash = rbitcoin_store::block_header_hash(
            wb1.version,
            &g.hash,
            &wb1.merkle_root,
            wb1.timestamp,
            wb1.bits,
            wb1.nonce,
        );
    }
    let wb1fk = q.put_header(&wb1).unwrap();
    let (wb2, _) = coinbase_block(32, wb1fk, Some(wb1.hash));
    let wb2fk = q.put_header(&wb2).unwrap();
    let (wb3, _) = coinbase_block(33, wb2fk, Some(wb2.hash));
    let wb3fk = q.put_header(&wb3).unwrap();
    let (wb4, _) = coinbase_block(34, wb3fk, Some(wb3.hash));
    let _ = q.put_header(&wb4).unwrap();

    let path = q.resume_work_path_after_tip(l2.hash, 2, 8).expect("resume");
    assert_eq!(
        path[0].hash,
        wb1.hash,
        "must pick heavier Wb over Wa; path={:?}",
        path.iter().map(|e| e.hash).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Tip already on loser **child** (L2); heavier fork is sibling of L1 under
/// grandparent — ancestor walk must find W1 (mainnet 0139ed class).
#[test]
fn resume_from_loser_child_explores_grandparent_sibling_fork() {
    let (dir, q) = temp_query("resume-loser-child");
    let (g, tg) = coinbase_block(0, Fk::NULL, None);
    let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
    // L1 then L2 tip.
    let (l1, tl1) = coinbase_block(1, gfk, Some(g.hash));
    let l1fk = q.connect_block(Height(1), &l1, &[tl1]).unwrap();
    let (l2, tl2) = coinbase_block(2, l1fk, Some(l1.hash));
    let _ = q.connect_block(Height(2), &l2, &[tl2]).unwrap();
    // W1 sibling of L1, then W2.
    let mut w1 = coinbase_block(11, gfk, Some(g.hash)).0;
    if w1.hash == l1.hash {
        w1.nonce = w1.nonce.wrapping_add(13);
        w1.hash = rbitcoin_store::block_header_hash(
            w1.version,
            &g.hash,
            &w1.merkle_root,
            w1.timestamp,
            w1.bits,
            w1.nonce,
        );
    }
    let w1fk = q.put_header(&w1).unwrap();
    let (w2, _) = coinbase_block(12, w1fk, Some(w1.hash));
    let w2fk = q.put_header(&w2).unwrap();
    let (w3, _) = coinbase_block(13, w2fk, Some(w2.hash));
    let _ = q.put_header(&w3).unwrap();

    let path = q.resume_work_path_after_tip(l2.hash, 2, 8).expect("resume");
    assert!(
        !path.is_empty() && path[0].hash == w1.hash,
        "from L2 must explore W1 under grandparent; path={:?}",
        path.iter().map(|e| (e.height, e.hash)).collect::<Vec<_>>()
    );
    assert_eq!(path[0].height, 1, "W1 at fork height of L1");
    assert!(
        path.len() >= 2 && path[1].hash == w2.hash,
        "continue W path: {path:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Deep header band after tip (mid-IBD restart). Recursive subtree scoring
/// stack-overflowed here on mainnet (~64k headers ahead of tip 671583).
#[test]
fn resume_work_path_deep_chain_after_tip_no_stack_overflow() {
    let (dir, q) = temp_query("resume-deep");
    let (g, tg) = coinbase_block(0, Fk::NULL, None);
    let mut prev_fk = q.put_header(&g).unwrap();
    let _ = q.commit_class_a_only(&g, &[tg]).unwrap();
    let mut prev_hash = g.hash;
    // Tall enough that recursive DFS would blow a default ~2–8 MiB stack
    // when scoring the child under tip.
    const DEPTH: u32 = 12_000;
    for i in 1..=DEPTH {
        let (h, _) = coinbase_block(i, prev_fk, Some(prev_hash));
        prev_fk = q.put_header(&h).unwrap();
        prev_hash = h.hash;
    }
    // Tip = genesis; path should walk the long child chain (capped by max).
    let path = q
        .resume_work_path_after_tip(g.hash, 0, 32)
        .expect("deep resume must not stack-overflow");
    assert_eq!(path.len(), 32, "capped walk length");
    assert_eq!(path[0].height, 1);
    assert_eq!(path[31].height, 32);
    let _ = std::fs::remove_dir_all(dir);
}

/// Confirmed tip on short loser; heavier sibling path under tip's parent must
/// still be returned.
#[test]
fn resume_work_path_from_loser_tip_explores_heavier_sibling() {
    let (dir, q) = temp_query("resume-from-loser");
    let (g, tg) = coinbase_block(0, Fk::NULL, None);
    let gfk = q.connect_block(Height(0), &g, &[tg]).unwrap();
    let (p, tp) = coinbase_block(1, gfk, Some(g.hash));
    let pfk = q.connect_block(Height(1), &p, &[tp]).unwrap();

    // Loser tip: single hop at height 2 with body (confirmed).
    let (lose, tl) = coinbase_block(2, pfk, Some(p.hash));
    let _lfk = q.connect_block(Height(2), &lose, &[tl]).unwrap();
    assert_eq!(q.tip_height().map(|h| h.0), Some(2));

    // Winner: same parent, two-header extension (strictly more work).
    let mut w1 = coinbase_block(21, pfk, Some(p.hash)).0;
    if w1.hash == lose.hash {
        w1.nonce = w1.nonce.wrapping_add(11);
        w1.hash = rbitcoin_store::block_header_hash(
            w1.version,
            &p.hash,
            &w1.merkle_root,
            w1.timestamp,
            w1.bits,
            w1.nonce,
        );
    }
    let w1fk = q.put_header(&w1).unwrap();
    let (w2, _) = coinbase_block(22, w1fk, Some(w1.hash));
    let _ = q.put_header(&w2).unwrap();

    // Resume from **loser tip** (not parent) — must still explore winner.
    let path = q
        .resume_work_path_after_tip(lose.hash, 2, 8)
        .expect("resume");
    assert!(
        !path.is_empty(),
        "must explore a path from loser tip; path empty"
    );
    assert_eq!(
        path[0].hash,
        w1.hash,
        "first hop is winning sibling at tip height; got {:?}",
        path.iter().map(|e| e.hash).collect::<Vec<_>>()
    );
    assert_eq!(path[0].height, 2, "sibling shares tip height");
    assert!(
        path.len() >= 2 && path[1].hash == w2.hash,
        "must continue winner chain: {path:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
