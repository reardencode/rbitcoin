//! tests (peeled from ibd/confirm.rs).

use super::{
    format_conf_q, format_queue_depth, format_stamp_reject_missing_prevout,
    stamp_reject_operator_msg, write_drain_max_parts, write_queue_cap, ConfirmFeed,
    ConfirmQueueDepths, CONFIRM_RUN_MAX_BLOCKS,
};

#[test]
fn index_startup_gap_matches_one_write_drain() {
    assert_eq!(
        rbitcoin_consensus::INDEX_STARTUP_GAP_HEIGHTS as usize,
        write_drain_max_parts(write_queue_cap()) * CONFIRM_RUN_MAX_BLOCKS
    );
}
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use rbitcoin_primitives::Fk;
use rbitcoin_query::InFlight;
use rbitcoin_store::{OutputRecord, TxRecord};
use std::sync::Arc;

fn test_pin(id: u64) -> rbitcoin_query::CreatePin {
    let mut txid = [0u8; 32];
    txid[..8].copy_from_slice(&id.to_le_bytes());
    rbitcoin_query::CreatePinInner::records(
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 0,
            output_start_fk: Fk::NULL,
            output_count: 0,
        },
        vec![OutputRecord::unspent(1, vec![0x51])],
    )
}

/// Pack stays until a later wave snapshots drain+fence past its height (not pack height alone).
#[test]
fn prune_inflight_drops_below_wave_drain_fence_keeps_equal() {
    let mut log = InFlight::new();
    let pins: Vec<_> = (85u64..=100).map(|id| (Fk(id), test_pin(id))).collect();
    log.note_pins(pins.iter().map(|(f, p)| (*f, p)), Some(10));
    log.prune_below_height(Some(9));
    assert_eq!(log.entry_count(), 16, "noted 9: height 10 is not below");
    log.prune_below_height(Some(10));
    assert_eq!(
        log.entry_count(),
        16,
        "equality keeps (drop is strictly below)"
    );
    log.prune_below_height(Some(11));
    assert_eq!(log.pack_count(), 0);
}

#[test]
fn note_archived_creates_from_pairs_does_not_need_store() {
    use super::LoadAheadState;

    let (_dir, hub) = crate::chain::tiny_regtest_hub_labeled("note-archived-pairs");
    hub.ensure_genesis().unwrap();
    let mut st = LoadAheadState::new(&hub);
    let tid = [7u8; 32];
    let last = [3u8; 32];
    st.note_archived_creates(vec![(tid, Fk(9))], Some((4, last)));
    assert_eq!(st.in_flight.get_create_fk(&tid), Some(Fk(9)));
    assert_eq!(st.last_loaded, Some((4, last)));
    assert_eq!(st.next_tx_start, 10);

    let start = st.next_tx_start;
    st.note_archived_creates(Vec::new(), Some((5, [8u8; 32])));
    assert_eq!(
        st.in_flight.get_create_fk(&tid),
        Some(Fk(9)),
        "empty pairs must not invent or drop identity"
    );
    assert_eq!(st.next_tx_start, start);
    assert_eq!(
        st.last_loaded,
        Some((4, last)),
        "header_txs hole (no pairs) must not advance last_loaded"
    );
}

/// Drain can lead fence; tip prune must still keep the unconfirmed height.
#[test]
fn prune_inflight_keeps_unconfirmed_after_occupied_jumps() {
    let mut log = InFlight::new();
    let p = test_pin(42);
    log.note_pins([(Fk(42), &p)], Some(1));
    log.prune_below_height(Some(0));
    assert!(
        log.get_create_fk(&p.tx().txid).is_some(),
        "occupied/fence lag must not drop height > tip"
    );
}

fn bh(b: u8) -> BlockHash {
    BlockHash::from_byte_array([b; 32])
}

/// Contiguous feed claim from `expect`, optional skip of already-confirmed.
fn claim_feed_run(
    expect: u32,
    max: usize,
    claim_hi: u32,
    feed_has: impl Fn(u32) -> bool,
    already_confirmed: impl Fn(u32) -> bool,
) -> Vec<u32> {
    let mut run = Vec::with_capacity(max.min(32));
    let mut h = expect;
    while run.len() < max && h <= claim_hi {
        if !feed_has(h) {
            break;
        }
        if already_confirmed(h) {
            h = h.saturating_add(1);
            continue;
        }
        run.push(h);
        h = h.saturating_add(1);
    }
    run
}

/// Offline mirror of online pack: prefix length under soft inputs + hard blocks.
fn pack_confirm_run_len(
    input_counts: &[u32],
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> usize {
    if input_counts.is_empty() || hard_max_blocks == 0 {
        return 0;
    }
    let mut sum = 0u32;
    let mut n = 0usize;
    for &c in input_counts {
        sum = sum.saturating_add(c);
        n += 1;
        if super::pack_stop_after(sum, n, soft_max_inputs, hard_max_blocks) {
            break;
        }
    }
    n.max(1).min(input_counts.len())
}

#[test]
fn pack_confirm_run_len_policy() {
    use super::{CONFIRM_BATCH_INPUTS_DEFAULT, CONFIRM_RUN_MAX_BLOCKS};
    // Under budget: take all.
    assert_eq!(pack_confirm_run_len(&[10, 10, 10], 8000, 144), 3);
    // Soft overshoot: include crossing block then stop.
    // 7990 + 100 = 8090 > 8000 → n=2
    assert_eq!(pack_confirm_run_len(&[7990, 100, 50], 8000, 144), 2);
    // First block alone exceeds soft → n=1
    assert_eq!(pack_confirm_run_len(&[50_000, 10], 8000, 144), 1);
    // Block hard cap
    let ones = vec![1u32; 200];
    assert_eq!(
        pack_confirm_run_len(&ones, CONFIRM_BATCH_INPUTS_DEFAULT, CONFIRM_RUN_MAX_BLOCKS),
        CONFIRM_RUN_MAX_BLOCKS
    );
    assert_eq!(pack_confirm_run_len(&[], 8000, 144), 0);
    // Exactly at soft: sum==soft continues? policy is sum > soft stop after take.
    // 4000+4000=8000 not > 8000 → can take more if present
    assert_eq!(pack_confirm_run_len(&[4000, 4000, 1], 8000, 144), 3);
    // After third, sum=8001 > 8000 stops at 3
    assert_eq!(pack_confirm_run_len(&[4000, 4000, 1, 1], 8000, 144), 3);
}

#[test]
fn split_wave_into_load_batches_is_eight_by_8000() {
    use super::{
        split_wave_into_load_batches_kind, CONFIRM_BATCH_INPUTS_DEFAULT, CONFIRM_RUN_MAX_BLOCKS,
        LOAD_QUEUE_CAP_DEFAULT,
    };
    assert_eq!(LOAD_QUEUE_CAP_DEFAULT, 14);
    assert_eq!(super::confirm_queue_caps().load, LOAD_QUEUE_CAP_DEFAULT);
    assert_eq!(super::load_queue_cap(), LOAD_QUEUE_CAP_DEFAULT);
    assert!(super::LoadBatch {
        items: vec![],
        parent_ids: None,
        drop_inflight_below: None,
        epoch: 0,
        gen: 0,
    }
    .items
    .is_empty());
    // 8 × 8001 inputs (each block overshoots 8000) → 8 batches of one.
    let wave: Vec<u32> = vec![8001; 8];
    let parts = split_wave_into_load_batches_kind(
        &wave,
        &[],
        CONFIRM_BATCH_INPUTS_DEFAULT,
        CONFIRM_RUN_MAX_BLOCKS,
    );
    assert_eq!(parts, vec![1, 1, 1, 1, 1, 1, 1, 1]);
    // Exactly 8000 does not stop; two 8000-input blocks are one batch.
    assert_eq!(
        split_wave_into_load_batches_kind(&[8000, 8000], &[], 8000, 144),
        vec![2]
    );
    // Empty / single megablock.
    assert!(split_wave_into_load_batches_kind(&[], &[], 8000, 144).is_empty());
    assert_eq!(
        split_wave_into_load_batches_kind(&[50_000], &[], 8000, 144),
        vec![1]
    );
    // 144 thin blocks then 144 more → two hard-cap batches.
    let thin = vec![1u32; 288];
    assert_eq!(
        split_wave_into_load_batches_kind(&thin, &[], 8000, 144),
        vec![144, 144]
    );
}

#[test]
fn split_wave_into_load_batches_stops_at_has_body_change() {
    use super::split_wave_into_load_batches_kind;
    // Crash prefix already-bodied, suffix need-body: two batches.
    let counts = [1u32, 1, 1, 1, 1];
    let has_body = [true, true, false, false, false];
    assert_eq!(
        split_wave_into_load_batches_kind(&counts, &has_body, 8000, 144),
        vec![2, 3]
    );
    // Kind flip inside an 8000-input pack still splits (do not glue kinds).
    assert_eq!(
        split_wave_into_load_batches_kind(&[4000, 4000], &[true, false], 8000, 144),
        vec![1, 1]
    );
    // Homogeneous still packs on input cap only.
    assert_eq!(
        split_wave_into_load_batches_kind(&[8000, 8000], &[false, false], 8000, 144),
        vec![2]
    );
    assert!(split_wave_into_load_batches_kind(&[], &[], 8000, 144).is_empty());
    assert_eq!(
        split_wave_into_load_batches_kind(&[50_000], &[true], 8000, 144),
        vec![1]
    );
}

#[test]
fn last_sent_load_batch_carries_wave_drain_fence() {
    use super::{load_batches_from_wave, split_wave_into_load_batches_kind};
    use rbitcoin_query::{BatchParentIds, ResolvedWire, TxPrecompute};
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let pres: Arc<[TxPrecompute]> = genesis
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let mk = |h: u32| {
        (
            h,
            [h as u8; 32],
            ResolvedWire::new(Arc::new(genesis.clone()), Arc::clone(&pres)),
        )
    };
    let items: Vec<_> = (1..=5).map(mk).collect();
    let parts = split_wave_into_load_batches_kind(&[1, 1, 1, 1, 1], &[], 2, 2);
    assert_eq!(parts, vec![2, 2, 1]);
    let empty_ids = BatchParentIds::default();
    let batches = load_batches_from_wave(&items, &parts, 14, &empty_ids, Some(40));
    assert_eq!(batches.len(), 3);
    assert!(batches[0].drop_inflight_below.is_none());
    assert!(batches[1].drop_inflight_below.is_none());
    assert_eq!(batches[2].drop_inflight_below, Some(40));
    assert_eq!(batches[0].items.len(), 2);
    assert_eq!(batches[2].items.len(), 1);
    assert!(batches.iter().all(|b| b.parent_ids.is_some()));

    let truncated = load_batches_from_wave(&items, &parts, 2, &empty_ids, Some(7));
    assert_eq!(truncated.len(), 2, "remaining loadq slots cap sent batches");
    assert!(truncated[0].drop_inflight_below.is_none());
    assert_eq!(
        truncated[1].drop_inflight_below,
        Some(7),
        "last sent batch of a truncated wave still carries the snapshot"
    );

    let unmarked = load_batches_from_wave(&items, &parts, 14, &empty_ids, None);
    assert!(unmarked.last().unwrap().drop_inflight_below.is_none());
}

#[test]
fn marked_load_batch_drops_inflight_below_after_read() {
    let mut log = InFlight::new();
    let a = test_pin(10);
    let b = test_pin(50);
    log.note_pins([(Fk(10), &a)], Some(5));
    log.note_pins([(Fk(50), &b)], Some(20));
    log.prune_below_height(None);
    assert_eq!(log.pack_count(), 2, "unmarked batch does not drop");
    log.prune_below_height(Some(10));
    assert!(
        log.get_create_fk(&a.tx().txid).is_none(),
        "height 5 is below noted 10 after last-batch in-flight read"
    );
    assert!(
        log.get_create_fk(&b.tx().txid).is_some(),
        "height 20 stays until a later wave snapshots past it"
    );
}

#[test]
fn chunk_parent_ids_vouts_are_per_chunk() {
    use super::chunk_parent_ids;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use rbitcoin_primitives::Fk;
    use rbitcoin_query::{BatchParentIds, IdMap, ResolvedWire, TxPrecompute};
    use std::sync::Arc;

    let parent = {
        let mut t = [0u8; 32];
        t[0] = 0x42;
        t
    };
    let mut ids = IdMap::default();
    ids.insert(parent, (Fk(7), (100, 32)));
    let wave = BatchParentIds {
        ids: Arc::new(ids),
        spent: Arc::new(rbitcoin_query::U64Map::default()),
        n_out: Default::default(),
        need_vouts: rbitcoin_query::U64Map::default(),
    };
    let spend = Block {
        header: Header {
            version: Version::ONE,
            prev_blockhash: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
                .block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![
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
                    value: Amount::from_sat(1),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                }],
            },
            Transaction {
                version: TxVersion::ONE,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array(parent),
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
    let empty = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let pres_spend: Arc<[TxPrecompute]> = spend
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let pres_empty: Arc<[TxPrecompute]> = empty
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let mut wire0 = ResolvedWire::new(Arc::new(spend), pres_spend);
    wire0.spend_keys = Arc::from([(parent, 0)]);
    let mut wire1 = ResolvedWire::new(Arc::new(empty), pres_empty);
    wire1.spend_keys = Arc::from([(parent, 1)]);
    let chunk0 = [(1u32, [1u8; 32], wire0)];
    let chunk1 = [(2u32, [2u8; 32], wire1)];
    let a = chunk_parent_ids(&wave, &chunk0);
    let b = chunk_parent_ids(&wave, &chunk1);
    assert_eq!(a.need_vouts.get(&7).map(|v| v.as_slice()), Some(&[0][..]));
    assert_eq!(
        b.need_vouts.get(&7).map(|v| v.as_slice()),
        Some(&[1][..]),
        "chunk maps differ when carried vouts differ"
    );
    let ignored_wire = chunk_parent_ids(
        &wave,
        &[(3u32, [3u8; 32], {
            let mut w = chunk0[0].2.clone();
            w.spend_keys = Arc::from([]);
            w
        })],
    );
    assert!(
        !ignored_wire.need_vouts.contains_key(&7),
        "empty spend_keys must not walk ResolvedWire.block inputs"
    );
    assert!(
        Arc::ptr_eq(&a.ids, &b.ids),
        "chunks share the wave IdMap Arc"
    );
}

#[test]
fn load_recv_is_lookup_order() {
    use super::LoadBatch;
    use rbitcoin_query::{ResolvedWire, TxPrecompute};
    use std::sync::mpsc;
    use std::sync::Arc;
    let (tx, rx) = mpsc::sync_channel::<LoadBatch>(8);
    let mk = |h: u32| {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let pres: Arc<[TxPrecompute]> = genesis
            .txdata
            .iter()
            .map(TxPrecompute::from_tx)
            .collect::<Vec<_>>()
            .into();
        (h, [h as u8; 32], ResolvedWire::new(Arc::new(genesis), pres))
    };
    tx.send(LoadBatch {
        items: vec![mk(1), mk(2)],
        parent_ids: None,
        drop_inflight_below: None,
        epoch: 0,
        gen: 0,
    })
    .unwrap();
    tx.send(LoadBatch {
        items: vec![mk(3)],
        parent_ids: None,
        drop_inflight_below: Some(7),
        epoch: 0,
        gen: 0,
    })
    .unwrap();
    let a = rx.recv().unwrap();
    let b = rx.recv().unwrap();
    assert_eq!(a.items[0].0, 1);
    assert_eq!(a.items[1].0, 2);
    assert!(a.drop_inflight_below.is_none());
    assert_eq!(b.items[0].0, 3);
    assert_eq!(b.drop_inflight_below, Some(7));
}

#[test]
fn load_stamp_items_keep_pres() {
    use super::{load_stamp_items, LoadBatch};
    use rbitcoin_query::{ResolvedWire, TxPrecompute};
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let pres: Arc<[TxPrecompute]> = genesis
        .txdata
        .iter()
        .map(TxPrecompute::from_tx)
        .collect::<Vec<_>>()
        .into();
    let lb = LoadBatch {
        items: vec![(
            1,
            [1u8; 32],
            ResolvedWire::new(Arc::new(genesis), Arc::clone(&pres)),
        )],
        parent_ids: None,
        drop_inflight_below: None,
        epoch: 0,
        gen: 0,
    };
    let items = load_stamp_items(lb.items.into_iter().map(|(h, _, w)| (h, w.block, w.pres)));
    assert_eq!(items.len(), 1);
    let got = items[0].2.as_ref().expect("load must pass lookup pres");
    assert!(
        Arc::ptr_eq(got, &pres),
        "stamp input must keep the LoadBatch pres Arc"
    );
}

#[test]
fn lookup_blocks_when_loadq_full() {
    use super::{LoadBatch, LOAD_QUEUE_CAP_DEFAULT};
    use std::sync::mpsc;
    let (tx, rx) = mpsc::sync_channel::<LoadBatch>(LOAD_QUEUE_CAP_DEFAULT);
    for _ in 0..LOAD_QUEUE_CAP_DEFAULT {
        tx.send(LoadBatch {
            items: vec![],
            parent_ids: None,
            drop_inflight_below: None,
            epoch: 0,
            gen: 0,
        })
        .unwrap();
    }
    assert!(
        tx.try_send(LoadBatch {
            items: vec![],
            parent_ids: None,
            drop_inflight_below: None,
            epoch: 0,
            gen: 0,
        })
        .is_err(),
        "9th send must wait / fail while loadq is full"
    );
    let _ = rx.recv().unwrap();
    tx.send(LoadBatch {
        items: vec![],
        parent_ids: None,
        drop_inflight_below: None,
        epoch: 0,
        gen: 0,
    })
    .unwrap();
}

/// Parent entry meters accumulate and drain with send/recv (no budget gate).
#[test]
fn pipeline_parents_meter_prep_and_write() {
    let q = ConfirmQueueDepths::new();
    q.note_script_send(2, 1_000, 50);
    q.note_write_send(3, 2_000, 80);
    let c = q.content_snap();
    assert_eq!(c.script_parents, 50);
    assert_eq!(c.write_parents, 80);
    assert_eq!(c.parents_total(), 130);
    q.note_script_recv(2, 1_000, 50);
    q.note_write_recv(3, 2_000, 80);
    let c2 = q.content_snap();
    assert_eq!(c2.parents_total(), 0);
    // Over-recv saturates at 0.
    q.note_write_recv(1, 1, 99);
    assert_eq!(q.content_snap().write_parents, 0);
}

/// Contiguous claim + skip already-confirmed (pure claim helper).
#[test]
fn claim_feed_wave_and_skip_confirmed() {
    let run = claim_feed_run(101, 32, 200, |h| (101..101 + 40).contains(&h), |_| false);
    assert_eq!(run.len(), 32);
    assert_eq!(run[0], 101);
    assert_eq!(*run.last().unwrap(), 132);
    let run = claim_feed_run(
        10,
        32,
        200,
        |h| (10..=50).contains(&h),
        |h| h == 10 || h == 11,
    );
    assert_eq!(run.first().copied(), Some(12));
    assert_eq!(run.len(), 32);
}

/// Claim must not jump thousands past tip when near pipeline is full.
#[test]
fn claim_ahead_cap_blocks_far_skip() {
    let ahead = super::max_claim_ahead();
    assert!(ahead >= super::CONFIRM_RUN_MAX_BLOCKS as u32);
    assert!(
        ahead
            <= 64 * 3 * super::CONFIRM_RUN_MAX_BLOCKS as u32 + super::CONFIRM_RUN_MAX_BLOCKS as u32,
        "keep claim window within env clamp: {ahead}"
    );
    let path_lo = 87u32;
    let run = claim_feed_run(
        path_lo,
        super::CONFIRM_RUN_MAX_BLOCKS,
        path_lo + ahead,
        |h| h >= path_lo && h < path_lo + 1000,
        |_| false,
    );
    assert_eq!(run.len(), super::CONFIRM_RUN_MAX_BLOCKS);
    assert_eq!(run[0], path_lo);
    assert!(*run.last().unwrap() <= path_lo + ahead);
}

/// requeue_wire after empty load must clear inflight (Ok(None) leak regression).
#[test]
fn requeue_clears_inflight_so_tip_can_retry() {
    let feed = ConfirmFeed::new();
    feed.note(87, bh(1));
    feed.note(88, bh(2));
    {
        let mut g = feed.inner.lock().unwrap();
        g.ready.remove(&87);
        g.ready.remove(&88);
        g.inflight.insert(87);
        g.inflight.insert(88);
    }
    feed.requeue_wire(&[(87, bh(1), None), (88, bh(2), None)]);
    let g = feed.inner.lock().unwrap();
    assert!(!g.inflight.contains(&87));
    assert!(!g.inflight.contains(&88));
    assert!(g.ready.contains_key(&87));
    assert!(g.ready.contains_key(&88));
}

#[test]
fn queue_hwm_tracks_max_depth() {
    let q = ConfirmQueueDepths::new();
    q.note_script_send(32, 1, 0);
    q.note_script_send(32, 1, 0);
    assert_eq!(q.snap().1, 2);
    q.note_script_recv(32, 1, 0);
    assert_eq!(q.snap().1, 1);
    let (_lh, sh, wh) = q.sample_hwm_and_reset();
    assert_eq!(sh, 2, "hwm keeps max even after recv");
    assert_eq!(wh, 0);
    let (_, sh2, _) = q.sample_hwm_and_reset();
    assert_eq!(sh2, 0, "hwm resets each sample window");
}

#[test]
fn thr_stats_add_is_local() {
    use super::confirm_thr_stats;
    use std::time::Duration;
    let stats = rbitcoin_query::ConfirmStats::default();
    confirm_thr_stats::add_write_work(&stats, Duration::from_millis(5));
    confirm_thr_stats::add_write_work(&stats, Duration::from_millis(20));
    let w = stats.take_window();
    assert!(w.thr_write_work_ns >= 25_000_000);
    confirm_thr_stats::add_write_work(&stats, Duration::ZERO);
    assert_eq!(
        stats.take_window().thr_write_work_ns,
        0,
        "zero duration is a no-op"
    );
    assert_eq!(
        confirm_thr_stats::script_work_from_verify_ns(2_000),
        Duration::from_nanos(2_000)
    );
    assert_eq!(confirm_thr_stats::stage_wall_ns(100, 180), 180);
    assert_eq!(confirm_thr_stats::stage_wall_ns(180, 100), 180);
    assert_ne!(
        confirm_thr_stats::stage_wall_ns(100, 180),
        100u64.saturating_add(180),
        "stage wall is the later completion, not the sum"
    );
}

#[test]
fn stamp_reject_names_leftover_unresolved() {
    let msg =
        stamp_reject_operator_msg("missing prevout", &rbitcoin_query::ConfirmStats::default());
    assert!(msg.contains("missing prevout"), "{msg}");
    assert!(msg.contains("unresolved"), "{msg}");
    assert!(msg.contains("leftover_n="), "{msg}");
    assert!(msg.contains("leftover_hit="), "{msg}");
    assert!(
        !msg.contains("corrupt"),
        "must not look like store wipe: {msg}"
    );
    assert_eq!(
        stamp_reject_operator_msg(
            "unexpected previous header",
            &rbitcoin_query::ConfirmStats::default(),
        ),
        "unexpected previous header"
    );
}

/// 257581: leftover_n/hit is not enough — we need the missing prev_txid and
/// whether write-behind still holds it (TipOnly is durable head only).
#[test]
fn stamp_reject_names_union_miss_txid() {
    let mut raw = [0u8; 32];
    raw[0] = 0xab;
    raw[31] = 0xcd;
    let msg =
        format_stamp_reject_missing_prevout(1914, 1913, 1, Some(raw), true, Some("head"), 0, false);
    assert!(msg.contains("leftover_n=1914"), "{msg}");
    assert!(msg.contains("leftover_hit=1913"), "{msg}");
    assert!(msg.contains("miss_n=1"), "{msg}");
    assert!(msg.contains("miss_txid="), "{msg}");
    assert!(msg.contains("pending=1"), "{msg}");
    assert!(msg.contains("miss_on=head"), "{msg}");
    assert!(msg.contains("miss_cands=0"), "{msg}");
    let disp = bitcoin::Txid::from_byte_array(raw).to_string();
    assert!(
        msg.contains(&disp),
        "operator line must name display txid {disp}: {msg}"
    );
}

/// note / requeue / finish lifecycle (duplicate scripts bug + re-queue).
#[test]
fn feed_note_requeue_finish_surface() {
    let feed = ConfirmFeed::new();
    feed.note(100, bh(1));
    {
        let mut g = feed.inner.lock().unwrap();
        let (hash, wire) = g.ready.remove(&100).unwrap();
        g.inflight.insert(100);
        assert_eq!(hash, bh(1));
        assert!(wire.is_none());
    }
    // Main loop offer would re-note tip+1 every tick — must be ignored.
    feed.note(100, bh(1));
    {
        let g = feed.inner.lock().unwrap();
        assert!(
            g.ready.is_empty(),
            "inflight height must not re-enter ready"
        );
        assert!(g.inflight.contains(&100));
    }

    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(50);
        g.inflight.insert(51);
    }
    feed.requeue_wire(&[(50, bh(5), None), (51, bh(6), None)]);
    {
        let g = feed.inner.lock().unwrap();
        assert!(!g.inflight.contains(&50));
        assert_eq!(g.ready.get(&50).map(|(h, _)| *h), Some(bh(5)));
        assert_eq!(g.ready.get(&51).map(|(h, _)| *h), Some(bh(6)));
    }

    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(10);
        g.inflight.insert(11);
    }
    feed.finish([10, 11]);
    let g = feed.inner.lock().unwrap();
    assert!(!g.inflight.contains(&10));
    assert!(!g.inflight.contains(&11));
}

/// Log tokens + live caps (scriptq/writeq; ready= is not capped).
#[test]
fn queue_depth_log_and_caps_surface() {
    assert_eq!(format_queue_depth("write", 0, 2), "write<0/2");
    assert_eq!(format_queue_depth("script", 1, 2), "script=1/2");
    assert_eq!(format_queue_depth("write", 2, 2), "write=2/2");
    assert_eq!(
        format_conf_q(0, 0, 1, 8, 2, 2),
        "loadq<0/8 scriptq<0/2 writeq=1/2"
    );
    assert_eq!(
        format_conf_q(3, 1, 0, 8, 2, 2),
        "loadq=3/8 scriptq=1/2 writeq<0/2"
    );
    assert_eq!(
        format_conf_q(0, 0, 0, 8, 2, 2),
        "loadq<0/8 scriptq<0/2 writeq<0/2"
    );

    let caps = super::confirm_queue_caps();
    assert_eq!(caps.script, super::SCRIPT_QUEUE_CAP_DEFAULT);
    assert_eq!(caps.write, super::WRITE_QUEUE_CAP_DEFAULT);
    assert_eq!(super::script_queue_cap(), caps.script);
    assert_eq!(super::write_queue_cap(), caps.write);
    for c in [caps.script, caps.write] {
        assert!(c >= 1, "queue cap must be positive: {c}");
    }
    assert_eq!(
        format_conf_q(0, 0, 0, caps.load, caps.script, caps.write),
        format!(
            "loadq<0/{} scriptq<0/{} writeq<0/{}",
            caps.load, caps.script, caps.write
        )
    );
    assert_eq!(
        format_conf_q(
            caps.load,
            caps.script,
            caps.write,
            caps.load,
            caps.script,
            caps.write
        ),
        format!(
            "loadq={0}/{0} scriptq={1}/{1} writeq={2}/{2}",
            caps.load, caps.script, caps.write
        )
    );
}

#[test]
fn feed_stop_size_snap_and_empty_requeue() {
    let feed = ConfirmFeed::new();
    assert!(!feed.stopped());
    assert_eq!(feed.size_snap(), (0, 0));
    feed.note(1, bh(1));
    feed.note(2, bh(2));
    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(3);
    }
    assert_eq!(feed.size_snap(), (2, 1));
    feed.requeue_wire(&[]); // no-op empty
    assert_eq!(feed.size_snap(), (2, 1));
    feed.request_stop();
    assert!(feed.stopped());
}

#[test]
fn claim_feed_stops_at_gap() {
    let run = claim_feed_run(5, 10, 100, |h| h == 5 || h == 6 || h == 8, |_| false);
    // Contiguous only — gap at 7 stops.
    assert_eq!(run, vec![5, 6]);
    let empty = claim_feed_run(1, 8, 100, |_| false, |_| false);
    assert!(empty.is_empty());
}

#[test]
fn confirm_queue_depths_content_snap_and_notes() {
    use super::ConfirmQueueDepths;
    let q = ConfirmQueueDepths::new();
    assert_eq!(q.snap(), (0, 0, 0));
    let c0 = q.content_snap();
    assert_eq!(c0.script_batches, 0);
    assert_eq!(c0.write_batches, 0);
    assert_eq!(c0.feed_ready, 0);
    assert_eq!(c0.feed_inflight, 0);

    q.note_script_send(3, 1000, 2);
    q.note_write_send(2, 500, 7);
    let c1 = q.content_snap();
    assert_eq!(c1.script_batches, 1);
    assert_eq!(c1.script_blocks, 3);
    assert_eq!(c1.script_wire_bytes, 1000);
    assert_eq!(c1.script_parents, 2);
    assert_eq!(c1.write_batches, 1);
    assert_eq!(c1.write_blocks, 2);
    assert_eq!(c1.write_wire_bytes, 500);
    assert_eq!(c1.write_parents, 7);
    assert_eq!(c1.parents_total(), 9);
    assert_eq!(q.snap(), (0, 1, 1));

    q.note_script_recv(3, 1000, 2);
    q.note_write_recv(2, 500, 7);
    let c2 = q.content_snap();
    assert_eq!(c2.script_batches, 0);
    assert_eq!(c2.write_batches, 0);
    assert_eq!(c2.script_blocks, 0);
    assert_eq!(c2.write_blocks, 0);
    // saturating sub: over-recv is safe
    q.note_script_recv(99, 99, 99);
    assert_eq!(q.content_snap().script_blocks, 0);
}

#[test]
fn offer_confirm_ready_walks_height_map() {
    use super::super::body::BodyPresence;
    use super::offer_confirm_ready;

    use std::collections::HashMap;
    use std::sync::atomic::AtomicU32;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("offer");
    hub.ensure_genesis().unwrap();

    let feed = ConfirmFeed::new();
    let mut body = BodyPresence::new();
    let mut h2h = HashMap::new();
    // Tip is 0; expect tip+1 = 1. Zombie pending without BQ is not claim-ready.
    let h1 = bh(0x11);
    h2h.insert(1u32, h1);
    body.mark_pending(h1);
    let mut max_arch = 0u32;
    let shared = AtomicU32::new(0);
    let n = offer_confirm_ready(&feed, &h2h, &mut body, &hub, &mut max_arch, &shared);
    assert_eq!(n, 0, "pending without body queue must not note");
    assert_eq!(feed.size_snap().0, 0);

    // Rejected tip+1 stops and notes zero new.
    body.mark_rejected(h1);
    let n2 = offer_confirm_ready(&feed, &h2h, &mut body, &hub, &mut max_arch, &shared);
    assert_eq!(n2, 0);

    // Gap in height map stops.
    let h2h2 = HashMap::new();
    let n3 = offer_confirm_ready(&feed, &h2h2, &mut body, &hub, &mut max_arch, &shared);
    assert_eq!(n3, 0);

    // Already-confirmed tip heights are skipped (continue walking).
    // Archive+confirm height 1 so has_block is true; offer from tip=1 expects 2.
    let h2 = bh(0x22);
    // tip is still 0 (genesis only) — mark genesis-next already confirmed via
    // has_block is only true for store tip; exercise the continue arm by
    // re-running offer after feed has height 1 already noted (inflight path).
    feed.note(1, h1); // already ready — note is idempotent when not inflight
    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(1);
        g.ready.remove(&1);
    }
    // With tip+1 inflight, offer still notes if ready map empty for that height.
    let n4 = offer_confirm_ready(&feed, &h2h, &mut body, &hub, &mut max_arch, &shared);
    // rejected path already cleared h1 from ready; height 1 still rejected → 0.
    assert_eq!(n4, 0);

    // Class A alone is not claim-ready: height 1 archived without bq → offer 0.
    body = BodyPresence::new();
    let mut h2h3 = HashMap::new();
    h2h3.insert(1u32, h1);
    h2h3.insert(2u32, h2);
    body.mark_archived(h1);
    feed.finish([1]);
    max_arch = 0;
    let n5 = offer_confirm_ready(&feed, &h2h3, &mut body, &hub, &mut max_arch, &shared);
    assert_eq!(
        n5, 0,
        "Class A without body queue must not note confirm feed"
    );

    // Zombie pending without BQ is still not claim-ready.
    body.mark_pending(h1);
    let n6 = offer_confirm_ready(&feed, &h2h3, &mut body, &hub, &mut max_arch, &shared);
    assert_eq!(n6, 0, "pending alone must not note without body queue");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn claim_feed_skips_inflight_and_confirmed_in_helper() {
    // Pure claim helper: inflight-like skip is modeled by already_confirmed.
    // Heights 1..=10 present; skip 1,2,5 → claim 3,4,6,7,8,9,10 (7).
    let run = claim_feed_run(
        1,
        8,
        100,
        |h| (1..=10).contains(&h),
        |h| h == 1 || h == 2 || h == 5,
    );
    assert_eq!(run.first().copied(), Some(3));
    assert!(!run.contains(&5));
    assert_eq!(run, vec![3, 4, 6, 7, 8, 9, 10]);
    // Max 0 → empty.
    assert!(claim_feed_run(1, 0, 100, |_| true, |_| false).is_empty());
}

/// note_wire prefer path (instance-local; not process-global thr_stats).
#[test]
fn thr_stats_all_stages_and_note_wire_prefer() {
    // note_wire: prefer keeping wire when already noted without; ignore inflight.
    let feed = ConfirmFeed::new();
    feed.note(10, bh(1));
    {
        let g = feed.inner.lock().unwrap();
        assert!(g.ready.get(&10).unwrap().1.is_none());
    }
    // Re-note with wire upgrades the optional slot.
    let genesis = rbitcoin_consensus::genesis_block(&rbitcoin_consensus::ChainParams::regtest());
    feed.note_wire(10, bh(1), Some(genesis.clone()));
    {
        let g = feed.inner.lock().unwrap();
        assert!(g.ready.get(&10).unwrap().1.is_some());
    }
    // Second note_wire with wire does not replace existing wire.
    let kept_nonce = genesis.header.nonce;
    let mut other = genesis.clone();
    other.header.nonce = kept_nonce.wrapping_add(99);
    feed.note_wire(10, bh(1), Some(other));
    {
        let g = feed.inner.lock().unwrap();
        assert_eq!(
            g.ready.get(&10).unwrap().1.as_ref().unwrap().header.nonce,
            kept_nonce,
            "must keep first wire, not replace"
        );
    }
    // Inflight height ignores note_wire entirely.
    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(11);
    }
    feed.note_wire(11, bh(2), Some(genesis.clone()));
    {
        let g = feed.inner.lock().unwrap();
        assert!(!g.ready.contains_key(&11));
    }
    // requeue into existing ready without wire upgrades it.
    feed.requeue_wire(&[(10, bh(1), None)]);
    {
        let g = feed.inner.lock().unwrap();
        assert!(g.ready.get(&10).unwrap().1.is_some());
        assert!(!g.inflight.contains(&10));
    }
    // requeue into existing ready that already has no wire, supply wire.
    feed.note(12, bh(3));
    feed.requeue_wire(&[(12, bh(3), Some(genesis))]);
    {
        let g = feed.inner.lock().unwrap();
        assert!(g.ready.get(&12).unwrap().1.is_some());
    }
    feed.clear();
    {
        let g = feed.inner.lock().unwrap();
        assert!(g.ready.is_empty());
        assert!(g.inflight.is_empty());
    }

    // pack_stop_after edges.
    assert!(!super::pack_stop_after(0, 0, 8000, 144));
    assert!(super::pack_stop_after(0, 144, 8000, 144));
    assert!(super::pack_stop_after(8001, 1, 8000, 144));
    assert!(!super::pack_stop_after(8000, 1, 8000, 144));
    assert_eq!(
        super::confirm_batch_max_inputs(),
        super::CONFIRM_BATCH_INPUTS_DEFAULT
    );
    assert_eq!(super::write_drain_max_parts(20), 20);
    assert_eq!(super::write_drain_max_parts(4), 4);
    assert_eq!(super::write_drain_max_parts(3), 3);
    assert_eq!(super::write_drain_max_parts(0), 1);
}

/// A plan queued before rewind must be dropped so it cannot commit as fk mismatch.
#[test]
fn confirm_feed_clear_drops_queued_plans() {
    let feed = ConfirmFeed::new();
    feed.note(10, bh(1));
    feed.note(11, bh(2));
    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(12);
        assert_eq!(g.ready.len(), 2);
        assert_eq!(g.inflight.len(), 1);
    }
    feed.clear();
    let (ready, inflight) = feed.size_snap();
    assert_eq!(ready, 0, "rewind must drop ready confirm plans");
    assert_eq!(inflight, 0, "rewind must drop inflight confirm plans");
    assert_eq!(feed.epoch(), 1, "clear bumps the rewind epoch");
}

#[test]
fn isolate_if_batched_downgrades_multi_block_consensus_and_wire() {
    use super::ConfirmRejectClass;
    assert_eq!(
        ConfirmRejectClass::ConsensusInvalid.isolate_if_batched(1),
        ConfirmRejectClass::ConsensusInvalid
    );
    assert_eq!(
        ConfirmRejectClass::ConsensusInvalid.isolate_if_batched(8),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::SoftWire.isolate_if_batched(1),
        ConfirmRejectClass::SoftWire
    );
    assert_eq!(
        ConfirmRejectClass::SoftWire.isolate_if_batched(8),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::EngineFault.isolate_if_batched(8),
        ConfirmRejectClass::EngineFault
    );
}

#[test]
fn emit_confirm_reject_isolates_batched_consensus_and_requests_single() {
    use super::{emit_confirm_reject, ConfirmEvent, ConfirmFeed, ConfirmRejectClass};

    let feed = ConfirmFeed::new();
    let (tx, rx) = std::sync::mpsc::channel();
    let hash = BlockHash::from_byte_array([9u8; 32]);
    emit_confirm_reject(
        &tx,
        &feed,
        11,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "script failed".into(),
        8,
        None,
    )
    .unwrap();
    assert_eq!(
        feed.isolate_until(),
        18,
        "batched consensus must isolate through last height of the wave"
    );
    match rx.try_recv() {
        Ok(ConfirmEvent::Reject {
            height: 11,
            class: ConfirmRejectClass::Cascade,
            batch_len: 8,
            ..
        }) => {}
        _ => panic!("expected Cascade isolate"),
    }

    let feed_one = ConfirmFeed::new();
    let (tx, rx) = std::sync::mpsc::channel();
    emit_confirm_reject(
        &tx,
        &feed_one,
        12,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "script failed".into(),
        1,
        None,
    )
    .unwrap();
    assert_eq!(
        feed_one.isolate_until(),
        u32::MAX,
        "single-block consensus stays blacklistable"
    );
    match rx.try_recv() {
        Ok(ConfirmEvent::Reject {
            class: ConfirmRejectClass::ConsensusInvalid,
            batch_len: 1,
            ..
        }) => {}
        _ => panic!("expected ConsensusInvalid"),
    }

    let feed_fault = ConfirmFeed::new();
    let (tx, _rx) = std::sync::mpsc::channel();
    emit_confirm_reject(
        &tx,
        &feed_fault,
        13,
        hash,
        ConfirmRejectClass::EngineFault,
        "io_uring leftover cqe".into(),
        8,
        None,
    )
    .unwrap();
    assert_eq!(
        feed_fault.isolate_until(),
        u32::MAX,
        "engine fault is not a cascade isolate"
    );
}

#[test]
fn isolate_clears_only_after_original_batch_last_height() {
    use super::{emit_confirm_reject, ConfirmFeed, ConfirmRejectClass};

    let feed = ConfirmFeed::new();
    let (tx, _rx) = std::sync::mpsc::channel();
    let hash = BlockHash::from_byte_array([0x0a; 32]);
    emit_confirm_reject(
        &tx,
        &feed,
        100,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "script failed".into(),
        8,
        None,
    )
    .unwrap();
    assert_eq!(feed.isolate_until(), 107);
    feed.release_isolate_if_tip(100);
    assert_eq!(
        feed.isolate_until(),
        107,
        "first n=1 accept must not re-pack the rest of the failed wave"
    );
    feed.release_isolate_if_tip(106);
    assert_eq!(
        feed.isolate_until(),
        107,
        "tip still below last height of the wave"
    );
    feed.release_isolate_if_tip(107);
    assert_eq!(
        feed.isolate_until(),
        u32::MAX,
        "tip through the original batch last height clears isolate"
    );

    let feed_n1 = ConfirmFeed::new();
    emit_confirm_reject(
        &tx,
        &feed_n1,
        100,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "script failed".into(),
        8,
        None,
    )
    .unwrap();
    assert_eq!(feed_n1.isolate_until(), 107);
    emit_confirm_reject(
        &tx,
        &feed_n1,
        100,
        hash,
        ConfirmRejectClass::ConsensusInvalid,
        "script failed".into(),
        1,
        None,
    )
    .unwrap();
    assert_eq!(
        feed_n1.isolate_until(),
        107,
        "n=1 consensus reject must not clear isolate"
    );
    feed_n1.clear();
    assert_eq!(
        feed_n1.isolate_until(),
        u32::MAX,
        "rewind clear drops isolate"
    );
}

#[test]
fn plan_epoch_stale_after_clear() {
    let feed = ConfirmFeed::new();
    {
        let mut g = feed.inner.lock().unwrap();
        g.claimed_epoch.insert(1, feed.epoch());
    }
    assert!(!feed.plan_epoch_stale(1), "claimed at live epoch");
    feed.clear();
    assert!(
        feed.plan_epoch_stale(1),
        "in-channel plan claimed before rewind is stale"
    );
    assert!(!feed.plan_epoch_stale(99), "unknown height is not stale");
}

#[test]
fn write_session_fault_is_engine_fault() {
    use rbitcoin_consensus::ConsensusError;
    use rbitcoin_store::StoreError;

    let undrained = ConsensusError::Store(StoreError::Corrupt("invariant: io_uring undrained"));
    assert_eq!(
        super::ConfirmRejectClass::from_consensus(&undrained),
        super::ConfirmRejectClass::EngineFault
    );
    let leftover = ConsensusError::Store(StoreError::Corrupt("invariant: io_uring leftover cqe"));
    assert_eq!(
        super::ConfirmRejectClass::from_consensus(&leftover),
        super::ConfirmRejectClass::EngineFault
    );
    let io = ConsensusError::Store(StoreError::io("/tmp/x", std::io::Error::other("disk")));
    assert_eq!(
        super::ConfirmRejectClass::from_consensus(&io),
        super::ConfirmRejectClass::EngineFault
    );
}

#[test]
fn from_net_maps_wire_and_string_classes() {
    use super::ConfirmRejectClass;
    use crate::error::NetError;

    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::Cancelled),
        ConfirmRejectClass::Cancelled
    );
    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::Mutated("x".into())),
        ConfirmRejectClass::SoftWire
    );
    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::BadPrev),
        ConfirmRejectClass::SoftWire
    );
    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::ConnectFailed {
            hash: [0u8; 32],
            msg: "script verification failed".into(),
        }),
        ConfirmRejectClass::ConsensusInvalid
    );
    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::Consensus("fk mismatch".into())),
        ConfirmRejectClass::Cascade
    );
    assert_eq!(
        ConfirmRejectClass::from_net(&NetError::Timeout),
        ConfirmRejectClass::Cascade
    );
}

/// A scripts or write session fault takes recover credit, re-arms lookup
/// at the tip, and offers the wave back to the body queue: lookup took
/// those bodies, so a hash on feed.ready alone is never confirmed again.
#[test]
fn requeue_on_uring_recover_rearms_lookup_and_offers_the_wave_back() {
    use rbitcoin_consensus::mine_empty_regtest;
    use std::collections::HashSet;

    let (dir, hub) = crate::chain::tiny_regtest_hub_labeled("requeue-uring");
    hub.ensure_genesis().unwrap();
    let time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
        .header
        .time;
    let b1 = mine_empty_regtest(hub.tip_hash().unwrap(), time + 600, 1);
    let b2 = mine_empty_regtest(b1.block_hash(), time + 1200, 2);
    let wave = [(1, b1.block_hash(), &b1), (2, b2.block_hash(), &b2)];
    let feed = ConfirmFeed::new();
    {
        let mut g = feed.inner.lock().unwrap();
        g.inflight.insert(1);
        g.inflight.insert(2);
    }
    hub.query.set_lookup_taken_hi(Some(2));
    let gen = hub.query.lookup_taken_gen();
    super::requeue_on_uring_recover(&hub, &feed, "test", &wave);
    assert_ne!(hub.query.lookup_taken_gen(), gen, "load resets");
    assert_eq!(hub.query.lookup_taken_hi(), Some(0));
    assert!(!feed.single_block());
    assert_eq!(feed.size_snap(), (0, 0), "not feed.ready, not inflight");
    assert_eq!(
        hub.query
            .block_queue_unresolved_heights(1, &HashSet::new(), 4),
        vec![1, 2],
        "lookup takes the wave again"
    );
    assert_eq!(
        hub.query.uring_recover("again"),
        rbitcoin_query::UringRecover::Exhausted
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn lookup_fault_policy_io_halt() {
    use super::{LookupFaultAction, LookupFaultPolicy};
    use rbitcoin_consensus::ConsensusError;
    use rbitcoin_store::StoreError;

    let mut p = LookupFaultPolicy::default();
    let bp = ConsensusError::Store(StoreError::BudgetFull("io_uring SQ"));
    assert_eq!(p.on_err(&bp), LookupFaultAction::Ignore);
    let io = ConsensusError::Store(StoreError::io("/tmp/x", std::io::Error::other("disk")));
    for _ in 0..7 {
        assert_eq!(p.on_err(&io), LookupFaultAction::Warn);
    }
    assert_eq!(p.on_err(&io), LookupFaultAction::RejectEngineFault);
    p.on_success();
    assert_eq!(p.on_err(&io), LookupFaultAction::Warn);
}

#[test]
fn lookup_ready_hash_none_when_missing() {
    let feed = ConfirmFeed::new();
    assert!(super::lookup_ready_hash(&feed, 10).is_none());
    let h = bitcoin::BlockHash::from_byte_array([2u8; 32]);
    {
        let mut g = feed.inner.lock().unwrap();
        g.ready.insert(10, (h, None));
    }
    assert_eq!(super::lookup_ready_hash(&feed, 10), Some(h));
}

/// First `ConfirmEvent::Reject` within 15 s; other events are skipped.
fn next_reject(
    rx: &std::sync::mpsc::Receiver<super::ConfirmEvent>,
) -> (u32, BlockHash, super::ConfirmRejectClass) {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match rx.recv_timeout(Duration::from_millis(5)) {
            Ok(super::ConfirmEvent::Reject {
                height,
                hash,
                class,
                ..
            }) => return (height, hash, class),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {
                assert!(Instant::now() < deadline, "no confirm reject")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("confirm engine exited before a reject")
            }
        }
    }
}

/// One direct-index regtest chain through the confirm engine. Four spends of
/// a freshly written parent, each in a mainnet ordering of lookup and write,
/// must confirm (187, 905, 133433, and 496 under single-block isolate). Then,
/// at that tip, the fault paths: a stale write batch, a write fault after
/// Class C, a failed load wave, a stale load queue, and a load session fault.
#[test]
fn ibd_confirm_pin_fault() {
    use super::{
        finish_connected_write_after_session_fault, load_fail_rewind_wave,
        reoffer_blocks_to_body_queue, spawn_confirm_engine, write_batch_is_stale, ConfirmEvent,
        ConfirmRejectClass, LoadAheadState,
    };
    use crate::ibd::status::LoopStats;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use rbitcoin_consensus::{
        mine_empty_regtest, mine_regtest_paying, pad_empty_from, ChainParams,
    };
    use rbitcoin_primitives::Height;
    use rbitcoin_query::testutil::FixtureChain as _;
    use rbitcoin_query::{ArchiveWritePlan, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use std::sync::atomic::AtomicU32;
    use std::time::{Duration, Instant};

    let (dir, hub0) = crate::chain::tiny_regtest_hub_labeled("confirm-pin-fault");
    hub0.query.enter_direct_index_mode().unwrap();
    let params = ChainParams::regtest();
    let hub = Arc::new(hub0);
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().expect("genesis");
    let gen_time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
        .header
        .time;
    let maturity = params.coinbase_maturity();
    let (mut tip, mut tip_time, cbs) =
        pad_empty_from(&hub.query, &params, genesis, gen_time, 1, maturity + 4, 5);
    let spend = |prev: Txid, val: Amount| Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: val,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    // Parent spends a matured coinbase, `gap` empty blocks follow, and the
    // child spends the parent's spend.
    let mut story = |cb: Txid, gap: u32| {
        let mut h = hub.tip_height().unwrap() + 1;
        let parent = mine_regtest_paying(
            tip,
            tip_time + 600,
            h,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend(cb, Amount::from_sat(49_0000_0000))],
        );
        let mut blocks = vec![(h, parent.clone())];
        for _ in 0..gap {
            let (_, prev) = blocks.last().unwrap();
            let b = mine_empty_regtest(prev.block_hash(), prev.header.time + 600, h + 1);
            h += 1;
            blocks.push((h, b));
        }
        let (_, prev) = blocks.last().unwrap();
        let child = mine_regtest_paying(
            prev.block_hash(),
            prev.header.time + 600,
            h + 1,
            ScriptBuf::from_bytes(vec![0x51]),
            vec![spend(
                parent.txdata[1].compute_txid(),
                Amount::from_sat(48_0000_0000),
            )],
        );
        blocks.push((h + 1, child.clone()));
        tip = child.block_hash();
        tip_time = child.header.time;
        blocks
    };

    let feed = Arc::new(ConfirmFeed::new());
    let (ev_tx, ev_rx) = std::sync::mpsc::channel();
    let (engine, _queues) = spawn_confirm_engine(
        Arc::clone(&hub),
        Arc::clone(&feed),
        ev_tx,
        Arc::new(AtomicU32::new(0)),
        Arc::new(LoopStats::default()),
    );
    let wait = |what: &str, done: &dyn Fn() -> bool| {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !done() {
            match ev_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(ConfirmEvent::Reject { height, err, .. }) => {
                    panic!("confirm reject @{height}: {err}");
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => assert!(
                    Instant::now() < deadline,
                    "timeout waiting for {what} (tip {:?})",
                    hub.tip_height()
                ),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("confirm engine exited before {what}")
                }
            }
        }
    };
    let wait_tip = |want: u32| wait(&format!("tip={want}"), &|| hub.tip_height() == Some(want));
    let enqueue = |(h, b): &(u32, bitcoin::Block)| {
        hub.query
            .block_queue_enqueue(*h, b.block_hash().to_byte_array(), 1, &serialize(b))
            .unwrap();
        feed.note(*h, b.block_hash());
    };

    // 187: the parent's pack writes before the child is even offered.
    let blocks = story(cbs[0], 0);
    enqueue(&blocks[0]);
    wait_tip(blocks[0].0);
    enqueue(&blocks[1]);
    wait_tip(blocks[1].0);

    // 905: parent writes, an empty height writes (RAM loc prune), then a
    // later lookup wave spends the parent.
    let blocks = story(cbs[1], 1);
    for b in &blocks {
        enqueue(b);
        wait_tip(b.0);
    }

    // 133433: the child's lookup starts once the parent is taken, before
    // the parent is in the tx head.
    let blocks = story(cbs[2], 1);
    enqueue(&blocks[0]);
    wait(&format!("lookup_taken_hi>={}", blocks[0].0), &|| {
        hub.query.lookup_taken_hi() >= Some(blocks[0].0)
    });
    enqueue(&blocks[1]);
    enqueue(&blocks[2]);
    wait_tip(blocks[2].0);

    // 496: one lookup wave, one write per height under single-block
    // isolate. Loc must survive the intervening prunes.
    feed.request_single_block(u32::MAX - 1);
    let blocks = story(cbs[3], 2);
    for b in &blocks {
        enqueue(b);
    }
    wait_tip(blocks.last().unwrap().0);

    // A peer answers getdata with the real header and a body that does not
    // decode. Lookup drops the row and reports a soft wire reject, so the
    // hash stays fetchable. The honest body for the same hash then connects.
    let t = hub.tip_height().unwrap();
    let next = mine_empty_regtest(tip, tip_time + 600, t + 1);
    let mut junk = serialize(&next.header);
    junk.extend_from_slice(&[0x01, 0x01, 0x00]);
    hub.query
        .block_queue_enqueue(t + 1, next.block_hash().to_byte_array(), 1, &junk)
        .unwrap();
    feed.note(t + 1, next.block_hash());
    let reject = next_reject(&ev_rx);
    assert_eq!(
        (reject, hub.query.block_queue_has_height(t + 1)),
        (
            (t + 1, next.block_hash(), ConfirmRejectClass::SoftWire),
            false
        ),
        "the undecodable row leaves the body queue before the reject"
    );
    enqueue(&(t + 1, next.clone()));
    wait_tip(t + 1);
    tip = next.block_hash();
    tip_time = next.header.time;

    feed.request_stop();
    feed.notify();
    let _ = engine.join();

    // Only tip+1 is the live write batch.
    let t = hub.tip_height().unwrap();
    assert!(!write_batch_is_stale(&hub, t + 1), "tip+1 is live");
    assert!(write_batch_is_stale(&hub, t), "a confirmed height is stale");
    assert!(
        write_batch_is_stale(&hub, t + 2),
        "past tip+1 is not the live batch"
    );

    load_fail_rewind_requeues_the_wave(&hub, tip, tip_time);
    let tail = mine_empty_regtest(tip, tip_time + 600, t + 1);

    // A stale load queue only restores the body queue; lookup stays taken.
    hub.query.set_lookup_taken_hi(Some(t + 3));
    reoffer_blocks_to_body_queue(
        &hub,
        std::iter::once((t + 3, tail.block_hash(), &tail, None)),
    );
    assert_eq!(
        hub.query.block_queue_payload(t + 3).unwrap().as_deref(),
        Some(serialize(&tail).as_slice())
    );
    assert_eq!(hub.query.lookup_taken_hi(), Some(t + 3));
    hub.query.block_queue_dequeue_height(t + 3).unwrap();
    hub.query.set_lookup_taken_hi(None);

    // A load session fault rewinds as an engine fault. After lookup noted
    // speculative fks, the next fk is the one after the durable bodies.
    let mut st = LoadAheadState::new(&hub);
    let durable = hub.query.tx_body_count() + 1;
    let mut plan = ArchiveWritePlan::empty();
    plan.planned_fks = vec![Fk(durable + 10)];
    st.note_lookup_ok(&plan, t + 1, [1u8; 32]);
    let pin = test_pin(durable + 10);
    st.in_flight
        .note_pins(std::iter::once((plan.planned_fks[0], &pin)), Some(t + 1));
    assert!(st.next_tx_start > durable && st.in_flight.entry_count() > 0);
    load_fail_rewind_wave(
        &ConfirmFeed::new(),
        &hub,
        &mut st,
        t + 1,
        ConfirmRejectClass::EngineFault,
        &[],
    );
    assert_eq!(st.next_tx_start, durable);
    assert_eq!(st.in_flight.entry_count(), 0);

    // A write session fault after Class C connected tip+1 with the spend
    // index off: the write thread finishes the spend annotate in place,
    // then the body leaves the queue as on Ok.
    let (tip_fk, _) = hub
        .query
        .get_header_by_hash(&tip.to_byte_array())
        .unwrap()
        .unwrap();
    let cb_fk = hub.query.block_tx_fks(Height(5)).unwrap()[0];
    let cb_txid = cbs[4].to_byte_array();
    let hash1 = rbitcoin_store::block_header_hash(
        1,
        &tip.to_byte_array(),
        &[0x11; 32],
        tip_time + 600,
        0x207fffff,
        1,
    );
    let h1 = HeaderRecord {
        prev_fk: tip_fk,
        version: 1,
        timestamp: tip_time + 600,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: [0x11; 32],
        hash: hash1,
        size: 0,
        weight: 0,
    };
    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    let coinbase = TxApply {
        tx: TxRecord {
            txid: [0x22; 32],
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
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
            prev_txid: cb_txid,
            create_fk: cb_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x51])],
    };
    hub.query.set_spend_index(false);
    hub.query
        .connect_block(Height(t + 1), &h1, &[coinbase, ta1])
        .unwrap();
    let spend_fk = hub.query.block_tx_fks(Height(t + 1)).unwrap()[1];
    let (multi, field, _) = hub
        .query
        .store()
        .txs
        .get_output_spender_meta(cb_fk, 0)
        .unwrap();
    assert!(!multi && field.is_null());
    hub.query.set_spend_index(true);
    assert!(write_batch_is_stale(&hub, t + 1), "tip is already t+1");
    assert!(hub.is_connected(&BlockHash::from_byte_array(hash1)));
    let hfk1 = hub.query.get_header_by_hash(&hash1).unwrap().unwrap().0;
    hub.query
        .block_queue_offer(t + 1, hash1, hfk1.0, &[0u8; 81])
        .unwrap();
    finish_connected_write_after_session_fault(&hub.query, &[(t + 1, hash1)])
        .expect("in-place finish");
    let (multi, field, _) = hub
        .query
        .store()
        .txs
        .get_output_spender_meta(cb_fk, 0)
        .unwrap();
    assert!(!multi);
    assert_eq!(field, spend_fk);
    assert_eq!(hub.query.block_queue_dequeue_height(t + 1).unwrap(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A two-block load wave fails, named by tip+1: pins clear, the epoch drops
/// same-wave loads, lookup rewinds to the tip, the retry is one block at a
/// time, and both bodies go back on the body queue, not feed.ready. A
/// one-block verdict drops the block that failed; a one-block cascade or
/// engine fault goes back for a retry. An engine fault is not isolated.
fn load_fail_rewind_requeues_the_wave(hub: &crate::chain::ChainHub, tip: BlockHash, tip_time: u32) {
    use super::{load_fail_rewind_wave, ConfirmRejectClass, LoadAheadState};
    use bitcoin::consensus::encode::serialize;
    use rbitcoin_consensus::mine_empty_regtest;
    use rbitcoin_query::ArchiveWritePlan;
    use std::collections::HashSet;

    let t = hub.tip_height().unwrap();
    let fail_feed = ConfirmFeed::new();
    let mut st = LoadAheadState::new(hub);
    let body0 = hub.query.tx_body_count();
    let mut plan = ArchiveWritePlan::empty();
    plan.planned_fks = vec![Fk(body0 + 10)];
    st.note_lookup_ok(&plan, t + 1, [1u8; 32]);
    let pin = test_pin(body0 + 10);
    st.in_flight
        .note_pins(std::iter::once((plan.planned_fks[0], &pin)), Some(t + 1));
    assert!(st.in_flight.entry_count() > 0);
    {
        let mut g = fail_feed.inner.lock().unwrap();
        g.inflight.insert(t + 1);
        g.inflight.insert(t + 2);
    }
    let head = mine_empty_regtest(tip, tip_time + 600, t + 1);
    let tail = mine_empty_regtest(head.block_hash(), tip_time + 1200, t + 2);
    hub.query.set_lookup_taken_hi(Some(t + 2));
    load_fail_rewind_wave(
        &fail_feed,
        hub,
        &mut st,
        t + 1,
        ConfirmRejectClass::Cascade,
        &[
            (t + 1, head.block_hash(), &head, None),
            (t + 2, tail.block_hash(), &tail, None),
        ],
    );
    assert_eq!(st.in_flight.entry_count(), 0, "pin/stamp fail clears all");
    assert_eq!(fail_feed.epoch(), 1);
    assert_eq!(hub.query.lookup_taken_hi(), Some(t));
    assert_eq!(
        fail_feed.isolate_until(),
        t + 2,
        "retry one block at a time"
    );
    for (ht, b) in [(t + 1, &head), (t + 2, &tail)] {
        assert_eq!(
            hub.query.block_queue_payload(ht).unwrap().as_deref(),
            Some(serialize(b).as_slice())
        );
    }
    assert_eq!(
        hub.query
            .block_queue_unresolved_heights(t + 1, &HashSet::new(), 4),
        vec![t + 1, t + 2],
        "the wave is claimable again"
    );
    {
        let g = fail_feed.inner.lock().unwrap();
        assert!(!g.ready.contains_key(&(t + 1)) && !g.ready.contains_key(&(t + 2)));
    }
    hub.query.block_queue_dequeue_height(t + 1).unwrap();
    hub.query.block_queue_dequeue_height(t + 2).unwrap();

    for (class, kept) in [
        (ConfirmRejectClass::ConsensusInvalid, false),
        (ConfirmRejectClass::SoftWire, false),
        (ConfirmRejectClass::EngineFault, true),
        (ConfirmRejectClass::Cascade, true),
    ] {
        let solo = ConfirmFeed::new();
        load_fail_rewind_wave(
            &solo,
            hub,
            &mut st,
            t + 1,
            class,
            &[(t + 1, head.block_hash(), &head, None)],
        );
        assert!(!solo.single_block(), "{class:?}");
        assert_eq!(hub.query.block_queue_has_height(t + 1), kept, "{class:?}");
        if kept {
            hub.query.block_queue_dequeue_height(t + 1).unwrap();
        }
    }

    let fault = ConfirmFeed::new();
    hub.query.set_lookup_taken_hi(Some(t + 2));
    load_fail_rewind_wave(
        &fault,
        hub,
        &mut st,
        t + 1,
        ConfirmRejectClass::EngineFault,
        &[
            (t + 1, head.block_hash(), &head, None),
            (t + 2, tail.block_hash(), &tail, None),
        ],
    );
    assert_eq!(hub.query.lookup_taken_hi(), Some(t));
    assert!(!fault.single_block(), "an engine fault is not isolated");
    assert_eq!(
        hub.query
            .block_queue_unresolved_heights(t + 1, &HashSet::new(), 4),
        vec![t + 1, t + 2],
        "the faulted wave is claimable again"
    );
    hub.query.block_queue_dequeue_height(t + 1).unwrap();
    hub.query.block_queue_dequeue_height(t + 2).unwrap();
}

/// A write or scripts reject re-arms lookup at the tip. A retried batched
/// wave turns on isolation and goes back on the body queue; a one-block
/// consensus reject does not. An engine fault's wave goes back without
/// isolation. A torn store file faults lookup or load before write, so
/// this is a unit check.
#[test]
fn reject_rearms_lookup_and_requeues_a_retried_wave() {
    use super::{rearm_after_reject, ConfirmRejectClass};
    use rbitcoin_consensus::mine_empty_regtest;

    let (dir, hub0) = crate::chain::tiny_regtest_hub_labeled("rearm-reject");
    let hub = Arc::new(hub0);
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_hash().unwrap();
    let time = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
        .header
        .time;
    let b1 = mine_empty_regtest(tip, time + 600, 1);
    let b2 = mine_empty_regtest(b1.block_hash(), time + 1200, 2);
    let wave = [(1, b1.block_hash(), &b1), (2, b2.block_hash(), &b2)];

    let feed = ConfirmFeed::new();
    hub.query.set_lookup_taken_hi(Some(2));
    assert!(rearm_after_reject(
        &hub,
        &feed,
        ConfirmRejectClass::ConsensusInvalid,
        &wave[..1],
    ));
    assert_eq!(hub.query.lookup_taken_hi(), Some(0));
    assert!(
        !hub.query.block_queue_has_height(1),
        "invalid block dropped"
    );
    assert!(!feed.single_block());

    for class in [
        ConfirmRejectClass::Cascade,
        ConfirmRejectClass::ConsensusInvalid,
    ] {
        let feed = ConfirmFeed::new();
        hub.query.set_lookup_taken_hi(Some(2));
        let gen = hub.query.lookup_taken_gen();
        assert!(rearm_after_reject(&hub, &feed, class, &wave));
        assert_ne!(hub.query.lookup_taken_gen(), gen, "{class:?}: load resets");
        assert_eq!(hub.query.lookup_taken_hi(), Some(0), "{class:?}");
        assert_eq!(feed.isolate_until(), 2, "{class:?}: isolated");
        assert!(
            hub.query.block_queue_has_height(1) && hub.query.block_queue_has_height(2),
            "{class:?}: retried wave is back on the queue"
        );
        for ht in [1, 2] {
            hub.query.block_queue_dequeue_height(ht).unwrap();
        }
    }

    let feed = ConfirmFeed::new();
    hub.query.set_lookup_taken_hi(Some(2));
    let gen = hub.query.lookup_taken_gen();
    assert!(rearm_after_reject(
        &hub,
        &feed,
        ConfirmRejectClass::EngineFault,
        &wave
    ));
    assert_ne!(
        hub.query.lookup_taken_gen(),
        gen,
        "engine fault: load resets"
    );
    assert_eq!(hub.query.lookup_taken_hi(), Some(0), "engine fault");
    assert!(!feed.single_block(), "an engine fault is not isolated");
    assert!(
        hub.query.block_queue_has_height(1) && hub.query.block_queue_has_height(2),
        "engine fault: the wave is back on the queue"
    );
    let _ = std::fs::remove_dir_all(dir);
}
