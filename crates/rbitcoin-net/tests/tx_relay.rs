use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Wtxid};
use rbitcoin_mempool::{fee_at_target_sat_kvb, AcceptError, Coin, UtxoProvider};
use rbitcoin_net::fee_history::HistoricalFeeBlock;
use rbitcoin_net::fee_history_file;
use rbitcoin_net::tx_relay::parent_req::ParentNote;
use rbitcoin_net::tx_relay::*;
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::transaction::Version;
use bitcoin::{Sequence, TxIn, Witness};

use std::time::{SystemTime, UNIX_EPOCH};

fn tmp() -> std::path::PathBuf {
    // macOS clocks tick in µs: back-to-back calls can share `n`.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("rbitcoin-txrelay-{n}-{seq}"))
}

#[test]
fn fullness_decile_scales_by_ten() {
    assert_eq!(fullness_decile(0.0), 0);
    assert_eq!(fullness_decile(0.15), 1);
    assert_eq!(fullness_decile(0.99), 9);
    assert_eq!(fullness_decile(1.0), 10);
}

#[test]
fn fee_history_scan_is_exhausted_only_under_budget_at_genesis() {
    assert!(fee_history_scan_exhausted(50, 100, Some(0)));
    assert!(
        !fee_history_scan_exhausted(100, 100, Some(0)),
        "landing on the budget is not under it"
    );
    assert!(
        !fee_history_scan_exhausted(50, 100, Some(3)),
        "bytes still under the budget do not finish the scan above genesis"
    );
}

#[test]
fn package_full_slot_requires_both() {
    assert!(package_full_slot(true, true));
    assert!(!package_full_slot(true, false));
    assert!(!package_full_slot(false, true));
}

#[test]
fn fee_readiness_logs_once_per_code() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let mut history = std::collections::HashMap::new();
    history.insert(2u32, Some(1u64));
    history.insert(3u32, None);
    rbitcoin_log::capture_logs(true);
    hub.log_fee_readiness(3, &history);
    let first = rbitcoin_log::take_logs();
    hub.log_fee_readiness(3, &history);
    let second = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(
        hub.fee_readiness.load(Ordering::Relaxed),
        3 * (1u32 << 16) + 1
    );
    assert!(
        first.iter().any(|(_, line)| line.contains("fee estimates")),
        "a new decile logs, got {first:?}"
    );
    assert!(
        second
            .iter()
            .all(|(_, line)| !line.contains("fee estimates")),
        "the same code does not log again, got {second:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn fee_history_progress_is_due_at_ten_seconds() {
    assert!(!fee_progress_due(Duration::from_secs(9)));
    assert!(fee_progress_due(Duration::from_secs(10)));
    assert!(fee_progress_due(Duration::from_secs(11)));
    let stats = FeeHistoryBackfillStats::default();
    let started = Instant::now();
    let mut last = started;
    rbitcoin_log::capture_logs(true);
    MempoolHub::log_fee_history_progress(&stats, &mut last);
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert_eq!(last, started, "a sub-10s backfill does not move the window");
    assert!(
        lines
            .iter()
            .all(|(_, line)| !line.contains("fee history preload progress")),
        "a sub-10s backfill does not emit the progress line, got {lines:?}"
    );
}

#[test]
fn default_cluster_limits_are_the_mempool_caps() {
    assert_eq!(
        MempoolHub::default_cluster_limits(),
        (
            rbitcoin_mempool::MAX_CLUSTER_COUNT as u32,
            rbitcoin_mempool::MAX_CLUSTER_VSIZE,
        )
    );
}

/// `estimatesmartfee` / Electrum `blockchain.estimatefee` forward this rate.
/// Target 2 is the depth-2 curve point, not the 1-block horizon.
#[test]
fn confirm_target_two_is_the_two_block_rate() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    let mut snap = FeeSnapshot::empty(Instant::now());
    let rates: Vec<Option<u64>> = FEE_SNAPSHOT_DEPTHS
        .iter()
        .enumerate()
        .map(|(i, _)| Some(10_000 - i as u64 * 100))
        .collect();
    snap.depth_rates_sat_kvb = rates.clone();
    hub.fee_dirty.store(false, Ordering::Release);
    hub.fee_snapshot.store(Arc::new(snap));
    let one = hub.estimate_fee_btc_per_kb(1);
    let two = hub.estimate_fee_btc_per_kb(2);
    let expect =
        fee_at_target_sat_kvb(FEE_SNAPSHOT_DEPTHS, &rates, 2).unwrap() as f64 / 100_000_000.0;
    assert!((two - expect).abs() < 1e-12, "two={two} expect={expect}");
    assert!(
        (one - two).abs() > 1e-12,
        "target 2 must not collapse onto target 1 ({one})"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn recent_reject_at_the_cap_does_not_clear() {
    let dir = tmp();
    let mdir = tmp();
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let hub = MempoolHub::open(&mdir, std::sync::Arc::new(q)).unwrap();
    let first = bitcoin::Wtxid::from_byte_array({
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    });
    hub.note_recent_reject(first);
    // 2..4097 is 4095 ids and does not collide with `first` (byte 0 == 1).
    for i in 2..4_097u32 {
        let mut b = [0u8; 32];
        b[0..4].copy_from_slice(&i.to_le_bytes());
        hub.note_recent_reject(bitcoin::Wtxid::from_byte_array(b));
    }
    let extra = bitcoin::Wtxid::from_byte_array([0xff; 32]);
    hub.note_recent_reject(extra);
    assert!(hub.try_recent_reject(&first));
    assert!(!hub.try_recent_reject(&extra));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&mdir);
}

#[test]
fn expire_stale_drops_old_tx_without_a_new_accept() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    let tid = tx.compute_txid();
    hub.accept_tx(&tx).expect("admit");
    assert_eq!(hub.live_count(), 1);
    hub.set_expiry_hours(1);
    hub.note_mock_now(hub.relay_now_secs() + 3600 + 5);
    assert_eq!(hub.expire_stale(), 1);
    assert_eq!(hub.live_count(), 0);
    assert!(!hub.contains(&tid));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reopened pool keeps each entry's accept time: `getmempoolentry.time`
/// and `-mempoolexpiry` see the original accept, not 0 or the restart.
#[test]
fn reopen_keeps_accept_time_and_expiry() {
    let (_store, q, cbs) = pad_cbs(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    let t0 = 1_700_000_000;
    hub.note_mock_now(t0);
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    let tid = tx.compute_txid();
    hub.accept_tx(&tx).expect("admit");
    assert_eq!(hub.accept_time_txid(&tid), Some(t0));
    hub.flush().expect("shutdown flush");
    drop(hub);
    let hub2 = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    assert!(hub2.contains(&tid));
    assert_eq!(
        hub2.accept_time_txid(&tid),
        Some(t0),
        "accept time must survive a restart"
    );
    // Core gives a loaded tx a fresh entry sequence. A new peer starts at
    // last_inv_sequence 1, so it cannot getdata the tx before an INV.
    assert!(
        !hub2.is_relay_servable(&tx.compute_wtxid(), 1),
        "a restored tx is not servable to a fresh peer before an INV"
    );
    hub2.set_expiry_hours(1);
    hub2.note_mock_now(t0 + 3600 - 5);
    assert_eq!(hub2.expire_stale(), 0, "not yet an hour old");
    hub2.note_mock_now(t0 + 3600 + 5);
    assert_eq!(hub2.expire_stale(), 1, "a loaded entry must still expire");
    assert!(!hub2.contains(&tid));
    let _ = std::fs::remove_dir_all(&mp);
}

/// One scan visits 256 live txs. With more than that expired, the survivors
/// are the newest accepts, and the next call continues from there.
#[test]
fn expire_stale_drops_oldest_accepts_within_one_scan() {
    const N: u32 = 257;
    let (store_dir, q, cbs) = pad_cbs(N);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    let mut ids = Vec::with_capacity(N as usize);
    for (i, cb) in cbs.iter().enumerate() {
        hub.note_mock_now((i as u64) + 1);
        // Regtest halves every 150 blocks, so later coinbases are under 50 BTC.
        let mut tx = spend_true(*cb, 0, ScriptBuf::from_bytes(vec![0x51]));
        tx.output[0].value = Amount::from_sat(1_000_000);
        hub.accept_tx(&tx).expect("admit");
        ids.push(tx.compute_txid());
    }
    assert_eq!(hub.live_count(), N as usize);
    hub.set_expiry_hours(0);
    hub.note_mock_now(N as u64 + 1);
    let newest = *ids.last().unwrap();
    let updates = hub.template_updates();
    assert_eq!(hub.expire_stale(), 256);
    assert_eq!(
        hub.template_updates(),
        updates + 1,
        "dropping more than one expired root notes the template once"
    );
    assert_eq!(hub.live_count(), 1);
    assert!(hub.contains(&newest), "newest accept must survive the cap");
    for id in &ids[..ids.len() - 1] {
        assert!(
            !hub.contains(id),
            "older accept must leave in the first scan"
        );
    }
    assert_eq!(hub.expire_stale(), 1);
    assert_eq!(hub.live_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Ghosts left in accept-time order by an earlier eviction occupy the
/// 256-entry scan. Unindexing them lets the next scan expire a live tx
/// that is already past the horizon.
#[test]
fn expire_stale_reaches_a_live_tx_behind_evicted_ghosts() {
    const GHOSTS: usize = 256;
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.set_expiry_hours(1);
    hub.note_mock_now(10_000);
    let live = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    let live_id = live.compute_txid();
    hub.accept_tx(&live).expect("admit live");
    {
        let mut by_tx = hub.wtxid_by_txid.lock().unwrap();
        let mut ats = hub.accept_at.lock().unwrap();
        let mut order = hub.expiry_order.lock().unwrap();
        for i in 0..GHOSTS {
            let mut raw = [0u8; 32];
            raw[0..4].copy_from_slice(&(i as u32 + 1).to_le_bytes());
            let txid = Txid::from_byte_array(raw);
            raw[31] = 1;
            let wtxid = Wtxid::from_byte_array(raw);
            let at = (i as u64) + 1;
            by_tx.insert(txid, wtxid);
            ats.insert(wtxid, at);
            order.insert((at, wtxid), txid);
        }
    }
    hub.min_live_accept_at.store(1, Ordering::Relaxed);
    hub.note_mock_now(10_000 + 3600 + 5);
    assert!(
        hub.expire_stale() >= GHOSTS,
        "ghosts in front of the scan must leave the expiry index"
    );
    assert!(
        hub.contains(&live_id),
        "one scan still stops after 256 entries"
    );
    assert_eq!(hub.expire_stale(), 1);
    assert!(!hub.contains(&live_id));
    assert!(hub.wtxid_by_txid.lock().unwrap().get(&live_id).is_none());
    assert!(hub
        .expiry_order
        .lock()
        .unwrap()
        .values()
        .all(|id| *id != live_id));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn try_expire_stale_skips_when_the_order_lock_is_held() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(1);
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    let tid = tx.compute_txid();
    hub.accept_tx(&tx).expect("admit");
    hub.set_expiry_hours(0);
    hub.note_mock_now(hub.relay_now_secs() + 5);
    let held = hub.expiry_order.lock().unwrap();
    assert_eq!(hub.try_expire_stale(), 0);
    assert!(hub.contains(&tid));
    drop(held);
    assert_eq!(hub.expire_stale(), 1);
    assert!(!hub.contains(&tid));
    let _ = std::fs::remove_dir_all(&dir);
}

fn record_fee_sample(hub: &MempoolHub, height: u32, rate_sat_kvb: u64) {
    let block = HistoricalFeeBlock {
        p10_sat_kvb: Some(rate_sat_kvb),
        txstat_bytes: 8,
    };
    hub.block_p10_history
        .lock()
        .unwrap()
        .insert(height, block, None);
}

#[test]
fn tip_script_pres_skips_only_matching_wtxid() {
    use rbitcoin_mempool::TxEntry;
    let dir = tmp();
    let mdir = tmp();
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let hub = MempoolHub::open(&mdir, Arc::new(q)).unwrap();
    let mut good = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![0x01]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = good.compute_txid();
    hub.lock_write().graph.insert(
        TxEntry {
            txid,
            wtxid: good.compute_wtxid(),
            fee_sat: 1,
            weight: good.weight().to_wu(),
            sigop_cost: 0,
            slot: 0,
            parents: BTreeSet::new(),
            children: BTreeSet::new(),
        },
        &good,
    );
    let id = txid.to_byte_array();
    let (_, skip_good) = hub.tip_script_pres(std::slice::from_ref(&good));
    assert!(skip_good.contains(&id), "same witness is preverified");
    good.input[0].witness = Witness::from_slice(&[vec![0x02]]);
    assert_eq!(good.compute_txid(), txid);
    let (_, skip_bad) = hub.tip_script_pres(std::slice::from_ref(&good));
    assert!(
        !skip_bad.contains(&id),
        "different witness must not skip scripts"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&mdir);
}

/// Spend `prev` to one OP_TRUE output of `value`.
fn spend_vout(prev: OutPoint, value: u64) -> Transaction {
    let mut tx = spend_true(prev.txid, 0, ScriptBuf::from_bytes(vec![0x51]));
    tx.input[0].previous_output = prev;
    tx.output[0].value = Amount::from_sat(value);
    tx
}

fn spend_true(cb: Txid, fee: u64, spk: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - fee),
            script_pubkey: spk,
        }],
    }
}

#[test]
fn recent_confirmed_evicts_oldest_over_cap() {
    let mut r = RecentConfirmed::new();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let a = spend_true(Txid::from_byte_array([1u8; 32]), 1, spk.clone());
    let b = spend_true(Txid::from_byte_array([2u8; 32]), 1, spk);
    r.note_block_capped(std::slice::from_ref(&a), 1);
    r.note_block_capped(std::slice::from_ref(&b), 1);
    assert!(!r.contains_txid(&a.compute_txid()));
    assert!(!r.contains_wtxid(&a.compute_wtxid()));
    assert!(r.contains_txid(&b.compute_txid()));
    assert!(r.contains_wtxid(&b.compute_wtxid()));
}

#[test]
fn sh_index_insert_overwrite_and_remove_miss() {
    let mut idx = MempoolShIndex::new();
    let t = Txid::from_byte_array([1u8; 32]);
    let sh = [2u8; 32];
    idx.insert(t, vec![sh]);
    idx.insert(t, vec![sh]); // overwrite same mapping
    assert_eq!(idx.txs_for(&sh).count(), 1);
    idx.remove(&t);
    idx.remove(&t); // miss
    assert_eq!(idx.txs_for(&sh).count(), 0);
    assert!(idx.txs_for(&[3u8; 32]).next().is_none());
}

#[test]
fn reorg_reaccept_then_unindex_drops_relay() {
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = spend_true(cbs[0], 1_000, spk.clone());
    assert!(!hub.is_reorg_servable(&tx.compute_wtxid()));
    assert_eq!(hub.reorg_reaccept(std::slice::from_ref(&tx)), 1);
    let w = tx.compute_wtxid();
    assert!(hub.is_reorg_servable(&w));
    assert!(hub.get_tx_by_wtxid(&w).is_some());
    assert!(hub.remove_for_block(&[tx.compute_txid()]) >= 1);
    assert!(hub.get_tx_by_wtxid(&w).is_none());
    assert!(
        !hub.is_relay_servable(&w, u64::MAX),
        "unindex must drop relay maps with the live graph entry"
    );
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn unbroadcast_survives_reopen_and_logs_confirm_before_broadcast() {
    use rbitcoin_store::script_hash;
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = spend_true(cbs[1], 1_000, spk.clone());
    hub.accept_tx_from(&tx, TxOrigin::Local).expect("accept");
    let extra = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let (pres, skip) = hub.tip_script_pres(&[tx.clone(), extra]);
    let live_id = tx.compute_txid().to_byte_array();
    assert_eq!(skip.len(), 1);
    assert!(skip.contains(&live_id));
    assert!(
        pres[0].sha_prevouts().is_none(),
        "live graph tx must skip sighash midstates"
    );
    assert!(
        pres[1].sha_prevouts().is_some(),
        "non-live must fill midstates after connect ids"
    );
    let wire = spend_true(cbs[8], 1_000, spk.clone());
    hub.accept_tx(&wire).expect("peer tx");
    hub.note_unbroadcast(tx.compute_txid());
    assert_eq!(hub.unbroadcast_count(), 1);
    assert!(hub.is_local_origin(&tx.compute_txid()));
    assert!(!hub.is_local_origin(&wire.compute_txid()));
    assert!(
        !hub.skip_standing_inv(&tx.compute_txid()),
        "without --proxy/--onion, local-origin still uses standing INV"
    );
    hub.set_isolated_broadcast(true);
    assert!(hub.skip_standing_inv(&tx.compute_txid()));
    assert!(!hub.skip_standing_inv(&wire.compute_txid()));
    hub.flush().expect("shutdown flush");
    drop(hub);
    let hub2 = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    let reopen = hub2.sample_reset_perf();
    assert_eq!(
        reopen.get_coin, 0,
        "SH reindex must use stored vin aux, not get_txout"
    );
    assert!(
        !hub2.scripthash_mempool(&sh).is_empty(),
        "reopen SH index from stored hashes"
    );
    hub2.set_relay_enabled(true);
    assert_eq!(hub2.unbroadcast_count(), 1);
    let mut rx = hub2.subscribe_announces();
    hub2.rebroadcast_unbroadcast();
    let got = rx.try_recv().expect("mockscheduler rebroadcast");
    assert_eq!(got.txid, tx.compute_txid());
    rbitcoin_log::capture_logs(true);
    assert_eq!(hub2.remove_for_block(&[tx.compute_txid()]), 1);
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let needle = format!(
        "p2p: Removed {} from set of unbroadcast txns before confirmation that txn was sent out",
        tx.compute_txid()
    );
    assert!(logs.iter().any(|(_, m)| *m == needle), "{logs:?}");
    assert_eq!(hub2.unbroadcast_count(), 0);
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn scripthash_reopen_drops_parent_then_child() {
    use rbitcoin_store::script_hash;
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let mut rx = hub.subscribe_announces();
    let parent = spend_true(cbs[2], 1_000, spk.clone());
    hub.accept_tx(&parent).expect("accept");
    let ann = rx.try_recv().expect("announce");
    assert!(ann.scripthashes.contains(&sh));
    let child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9998_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    hub.accept_tx(&child).expect("child");
    assert!(hub.scripthash_mempool(&sh).len() >= 2);
    hub.flush().unwrap();
    drop(hub);
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    assert!(hub.scripthash_mempool(&sh).len() >= 2);
    assert!(hub.remove_for_block(&[parent.compute_txid()]) >= 1);
    assert!(!hub.scripthash_mempool(&sh).is_empty());
    assert!(hub.remove_for_block(&[child.compute_txid()]) >= 1);
    assert!(hub.scripthash_mempool(&sh).is_empty());
    let _ = std::fs::remove_dir_all(&mp);
}

#[allow(clippy::cognitive_complexity)] // one mempool session: later beats see earlier accepts
#[test]
fn live_pool_recent_accepts_and_1p1c_rollback() {
    use rbitcoin_store::script_hash;
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let mut ann_rx = hub.subscribe_announces();
    let provider = QueryUtxoProvider::new(q.as_ref());
    let op0 = OutPoint {
        txid: cbs[3],
        vout: 0,
    };
    assert!(provider.get_txout(&op0).is_some());
    let cheap = spend_true(cbs[9], 1, spk.clone());
    assert!(matches!(
        hub.accept_tx(&cheap),
        Err(AcceptError::Policy("min relay fee"))
    ));
    assert!(
        !hub.try_recent_reject(&cheap.compute_wtxid()),
        "min-relay is reconsiderable; must not skip a later ATMP"
    );
    let coinbase = Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: spk.clone(),
        }],
    };
    assert!(matches!(
        hub.accept_tx(&coinbase),
        Err(AcceptError::Coinbase)
    ));
    assert!(hub.try_recent_reject(&coinbase.compute_wtxid()));
    hub.note_recent_confirmed(&[]);
    assert!(
        !hub.try_recent_reject(&coinbase.compute_wtxid()),
        "tip connect must forget recent_rejects"
    );
    assert!(hub.recent_accepts().is_empty());
    let parent = spend_true(cbs[3], 1_000, spk.clone());
    let pr = hub.accept_tx(&parent).expect("accept parent");
    assert_eq!(pr.txid, parent.compute_txid());
    assert!(ann_rx.try_recv().is_ok());
    let recent = hub.recent_accepts();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].txid, parent.compute_txid());
    assert_eq!(recent[0].fee_sat, 1_000);
    let child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 2_000),
            script_pubkey: spk.clone(),
        }],
    };
    let second = spend_true(cbs[4], 5_000, ScriptBuf::from_bytes(vec![0x52]));
    let second_id = second.compute_txid();
    hub.accept_tx(&child).expect("child");
    let pkg = hub.accept_package(&[second]).expect("package");
    assert_eq!(pkg.len(), 1);
    assert_eq!(hub.live_count(), 3);
    let newest_first: Vec<Txid> = hub.recent_accepts().iter().map(|r| r.txid).collect();
    assert_eq!(
        newest_first,
        [second_id, child.compute_txid(), parent.compute_txid()]
    );
    assert!(hub.contains(&parent.compute_txid()));
    let wtxid = parent.compute_wtxid();
    assert!(hub.contains_wtxid(&wtxid));
    assert!(hub.get_tx_by_wtxid(&wtxid).is_some());
    assert!(!hub.fee_histogram().is_empty());
    let e1 = hub.estimate_fee_btc_per_kb(1);
    let e5 = hub.estimate_fee_btc_per_kb(5);
    let e144 = hub.estimate_fee_btc_per_kb(144);
    // Flow is cold on a fresh hub and the chain has no fee history:
    // a thin live pool alone does not set a guess.
    assert!(
        e1 < 0.0 && e5 < 0.0 && e144 < 0.0,
        "cold flow without history: e1={e1} e5={e5} e144={e144}"
    );
    let spent = hub.spent_outpoints();
    assert!(spent.contains(&op0));
    let rows = hub.scripthash_mempool(&sh);
    assert!(rows.len() >= 2);
    assert!(rows.iter().any(|r| r.height == -1));
    let delta = hub.scripthash_unconfirmed_delta(&sh).unwrap();
    assert_eq!(delta, 50_0000_0000 - 2_000 - 50_0000_0000 - 50_0000_0000);
    assert!(hub.is_relay_servable(&wtxid, hub.current_relay_seq()));
    assert!(hub.remove_for_block(&[parent.compute_txid()]) >= 1);
    hub.mark_fee_dirty();
    let e1b = hub.estimate_fee_btc_per_kb(1);
    let e144b = hub.estimate_fee_btc_per_kb(144);
    assert!(
        e1b < 0.0 && e144b < 0.0,
        "a confirm does not warm flow or add history: e1={e1b} e144={e144b}"
    );
    assert!(
        !hub.contains_wtxid(&wtxid),
        "wtxid index must drop with the live entry"
    );
    assert!(hub.get_tx_by_wtxid(&wtxid).is_none());
    assert!(
        !hub.is_relay_servable(&wtxid, u64::MAX),
        "unindex must drop relay maps with the live graph entry"
    );
    assert!(hub.list_live().len() < 3);

    hub.set_min_relay_sat_kvb(50_000);
    let lp = Transaction {
        output: vec![
            TxOut {
                value: Amount::from_sat(25_0000_0000),
                script_pubkey: spk.clone(),
            },
            TxOut {
                value: Amount::from_sat(25_0000_0000 - 200),
                script_pubkey: spk.clone(),
            },
        ],
        ..spend_true(cbs[9], 0, spk.clone())
    };
    let lpid = lp.compute_txid();
    assert!(matches!(
        hub.accept_tx(&lp),
        Err(AcceptError::Policy("min relay fee"))
    ));
    let one_sat = spend_vout(OutPoint::new(lpid, 0), 25_0000_0000 - 1);
    assert!(matches!(
        hub.accept_tx(&one_sat),
        Err(AcceptError::Orphaned { .. })
    ));
    assert_eq!(hub.orphan_count(), 1);
    let payer = spend_vout(OutPoint::new(lpid, 1), 1_000);
    hub.accept_tx_from(&payer, TxOrigin::Local)
        .expect("hub 1p1c must admit parent+child");
    assert!(hub.contains(&lpid));
    assert!(hub.contains(&payer.compute_txid()));
    assert!(hub.is_local_origin(&payer.compute_txid()));
    assert!(
        !hub.is_local_origin(&lpid),
        "the remembered parent came from the network, not this submit"
    );
    assert!(
        !hub.contains(&one_sat.compute_txid()),
        "1-sat sibling must not ride 1p1c promote at floor 0"
    );
    assert_eq!(hub.orphan_count(), 0);
    let sib = spend_vout(OutPoint::new(lpid, 0), 25_0000_0000 - 10_000);
    let (sib_id, sib_w) = (sib.compute_txid(), sib.compute_wtxid());
    hub.accept_tx(&sib).expect("paying sibling of live parent");
    assert!(hub.relay_seq_of(&sib_w).is_some());
    assert!(hub.accept_time_txid(&sib_id).is_some());
    let tmpl = hub.template_updates();
    hub.rollback_1p1c_parent(&lpid, &[]);
    assert!(!hub.contains(&lpid));
    assert!(!hub.contains(&sib_id));
    assert!(!hub.is_local_origin(&payer.compute_txid()));
    assert!(
        hub.relay_seq_of(&sib_w).is_none(),
        "published spender must leave wtxid/relay maps"
    );
    assert!(hub.accept_time_txid(&sib_id).is_none());
    assert!(
        hub.template_updates() > tmpl,
        "template must bump like remove_for_block_spent"
    );
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn accept_stage_meters_then_expiry_drops_stale_child() {
    use rbitcoin_store::script_hash;
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let _ = hub.sample_reset_perf();
    let mut fee_sum = 0i64;
    let mut spends = Vec::new();
    for (i, cbtxid) in cbs[5..8].iter().enumerate() {
        let fee = 1_000u64 + i as u64;
        fee_sum += fee as i64;
        let tx = spend_true(*cbtxid, fee, spk.clone());
        hub.accept_tx(&tx).expect("accept spend");
        spends.push(tx.compute_txid());
    }
    let n = 3u64;
    assert_eq!(hub.accept_totals(), (n, 0));
    let s = hub.sample_reset_perf();
    assert_eq!(s.accepts, n);
    assert_eq!(s.tip_mtp, 1, "same tip must compute MTP once");
    assert_eq!(
        s.expire_full_scans, 0,
        "young pool must not walk accept_at for expiry"
    );
    assert!(s.accept_us > 0);
    assert!(s.accept_lock_us > 0);
    assert!(s.accept_utxo_us > 0);
    assert!(s.accept_script_us > 0);
    assert!(s.accept_durable_us > 0);
    assert!(
        s.accept_lock_us >= s.accept_durable_us,
        "lock_us={} durable_us={}",
        s.accept_lock_us,
        s.accept_durable_us
    );
    assert!(
        s.accept_us >= s.accept_script_us,
        "wall={} script={}",
        s.accept_us,
        s.accept_script_us
    );
    let z = hub.sample_reset_perf();
    assert_eq!(z.accepts, 0);
    let unused = script_hash(&[0x00]);
    assert_eq!(hub.scripthash_unconfirmed_delta(&unused).unwrap(), 0);
    let s = hub.sample_reset_perf();
    assert_eq!(s.delta_prevouts, 0);
    assert_eq!(hub.scripthash_unconfirmed_delta(&sh).unwrap(), -fee_sum);

    // `mempool_expiry.py`: a new tx past -mempoolexpiry drops every
    // older tx with its child, and keeps prioritisetransaction.
    let child = spend_true(spends[0], 2_000, spk.clone());
    hub.accept_tx(&child).expect("child");
    hub.prioritise_tx(spends[0], 50_000);
    hub.set_expiry_hours(1);
    hub.note_mock_now(hub.relay_now_secs() + 3600 + 5);
    let trigger = spend_true(cbs[10], 3_000, spk.clone());
    hub.accept_tx(&trigger).expect("trigger expires stale");
    assert_eq!(hub.live_count(), 1);
    assert!(hub.contains(&trigger.compute_txid()));
    assert_eq!(hub.fee_delta(&spends[0]), 50_000);
    assert_eq!(hub.sample_reset_perf().expire_full_scans, 1);
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn missing_vin_aux_batches_class_a_on_open() {
    use rbitcoin_store::script_hash;
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let sh = script_hash(spk.as_bytes());
    let mp = tmp();
    let tx = spend_true(cbs[0], 1_000, spk.clone());
    let tid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    {
        let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
        store
            .append_live_tx(&tx, &tid, &wtxid, 1_000, 400, 0, 1_700_000_000, &[])
            .unwrap();
        store.flush().unwrap();
    }
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    let s = hub.sample_reset_perf();
    assert_eq!(
        s.get_coin, 0,
        "missing-aux fill must batch Class A, not get_txout"
    );
    assert!(
        !hub.scripthash_mempool(&sh).is_empty(),
        "batch-fill the vin that lacked aux"
    );
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn open_recomputes_unknown_sigops_and_drops_unresolvable() {
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    // Unknown sigop cost (schema-2 migrate): open recomputes it from
    // chain coins and drops the entry whose input is not a coin.
    let mp = tmp();
    // OP_CHECKSIG output: one legacy sigop, cost 4.
    let ok = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0xac]));
    let gone = spend_true(Txid::from_byte_array([0xee; 32]), 1_000, spk.clone());
    {
        let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
        for tx in [&ok, &gone] {
            let (tid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
            store
                .append_live_tx(tx, &tid, &wtxid, 1_000, 400, u64::MAX, 1_700_000_000, &[])
                .unwrap();
        }
        store.flush().unwrap();
    }
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    let picked: Vec<_> = hub
        .select_block_template(hub.template_budget(0))
        .into_iter()
        .map(|(_, s)| (s.txid, s.sigop_cost))
        .collect();
    assert_eq!(picked, vec![(ok.compute_txid(), 4)]);
    assert!(
        !hub.contains(&gone.compute_txid()),
        "unresolvable input evicted"
    );
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn sigop_adjusted_weight_feeds_cluster_and_confirm_memory() {
    let (_store, q, cbs) = pad_cbs(12);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    // Sigop-adjusted weight: max(400, 100 * 20) until bps is 0.
    let mp = tmp();
    let tx = spend_true(cbs[0], 1_000, spk.clone());
    let (tid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
    {
        let mut store = rbitcoin_mempool::Mempool::open_or_create(&mp).unwrap();
        store
            .append_live_tx(&tx, &tid, &wtxid, 1_000, 400, 100, 1_700_000_000, &[])
            .unwrap();
        store.flush().unwrap();
    }
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    assert_eq!(hub.get_live_adjusted_weight(&tid), Some(2_000));
    // Core `getmempoolcluster` `clusterweight` is sigop-adjusted.
    assert_eq!(hub.cluster_rpc(&tid).unwrap().0, 2_000);
    // Feefilter announce gate: Core `txinfo.vsize` is sigop-adjusted.
    assert_eq!(hub.try_get_live_meta(&tid), Some((1_000, 2_000)));
    hub.set_bytes_per_sigop(0);
    assert_eq!(hub.get_live_adjusted_weight(&tid), Some(400));
    assert_eq!(hub.cluster_rpc(&tid).unwrap().0, 400);
    assert_eq!(hub.get_live_adjusted_weight(&Txid::all_zeros()), None);
    hub.set_bytes_per_sigop(20);
    // Confirmed feerate memory: 1_000 sat on 500 adjusted vB (raw 100).
    hub.set_relay_enabled(true);
    assert_eq!(hub.remove_for_block(&[tid]), 1);
    assert_eq!(hub.confirm_memory_floor_sat_per_kvb(), Some(2_000));
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn over_standard_sigops_still_fit_a_block() {
    let (_store, q, cbs) = pad_cbs(12);
    // 4001 legacy CHECKSIG × 4 = 16004: over Core's standard cap, under
    // the block limit, so Libre policy admits it.
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[11],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 100_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0xac; 4_001]),
        }],
    };
    hub.accept_tx(&tx).expect("16004 sigop cost fits a block");
    let picked = hub.select_block_template(hub.template_budget(0));
    assert_eq!(picked.len(), 1);
    assert_eq!(*picked[0].0, tx);
    assert_eq!(
        (picked[0].1.fee_sat, picked[0].1.sigop_cost),
        (100_000, 16_004)
    );
    let _ = std::fs::remove_dir_all(&mp);
}

/// A Class C coinbase read that errors is not "not a coinbase". The
/// genesis coinbase is unspent; forcing that read to fail must make the
/// prevout unavailable. `Ok(false)` on height 0 is not a non-coinbase coin.
#[test]
fn coinbase_table_error_makes_the_prevout_unavailable() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_mempool::{ChainPrevout, UtxoProvider};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

    let dir = tmp();
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let op = OutPoint {
        txid: genesis.txdata[0].compute_txid(),
        vout: 0,
    };
    let provider = QueryUtxoProvider::new(&q);
    provider.coinbase_read.store(3, Ordering::Relaxed);
    assert!(
        matches!(provider.chain_prevout(&op), ChainPrevout::KnownUnavailable),
        "a failed Class C coinbase read must not admit the coin"
    );
    provider.coinbase_read.store(1, Ordering::Relaxed);
    assert!(
        matches!(provider.chain_prevout(&op), ChainPrevout::KnownUnavailable),
        "height 0 is the genesis coinbase; a false Class C flag does not admit a non-coinbase coin"
    );
    provider.coinbase_read.store(0, Ordering::Relaxed);
    match provider.chain_prevout(&op) {
        ChainPrevout::Unspent(coin) => assert!(coin.is_coinbase, "genesis is the coinbase"),
        ChainPrevout::KnownUnavailable => panic!("genesis coinbase is unspent"),
        ChainPrevout::Unknown => panic!("genesis coinbase is a known create"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Non-coinbase, no BIP68 time-lock: one packed body decode per coin
/// lookup and no create MTP. The parent has two outputs with distinct
/// values and the child spends vout 1, so the fee pins the vout index.
/// A spend of the tip coinbase is `ImmatureCoinbase`: coinbase-ness comes
/// from the Class C coinbase table, not the parent's inputs.
/// A satisfied time-lock spend must survive `evict_after_reorg`.
#[test]
fn get_coin_decodes_once_and_skips_mtp_without_time_lock() {
    let (store, owned_q, owned_cbs) = copy_maturity_pad(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;
    use rbitcoin_store::script_hash;

    let params = ChainParams::regtest();
    let tip_h = q.tip_height().expect("tip").0;
    let fk = q.tip_header_fk().unwrap().expect("tip header");
    let rec = q.get_header(fk).unwrap();
    let tip = bitcoin::BlockHash::from_byte_array(rec.hash);
    let next = tip_h + 1;
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mut confirmed = spend_true(cbs[0], 1_000, spk.clone());
    let total = confirmed.output[0].value.to_sat();
    confirmed.output = vec![
        TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: spk.clone(),
        },
        TxOut {
            value: Amount::from_sat(total - 5_000),
            script_pubkey: spk.clone(),
        },
    ];
    let b = rbitcoin_consensus::mine_regtest_paying(
        tip,
        rec.timestamp + 600,
        next,
        spk.clone(),
        vec![confirmed.clone()],
    );
    accept_and_connect_block(q, &params, Height(next), &b, Milestone::NONE).unwrap();
    q.apply_sh_pending().unwrap();
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let _ = hub.sample_reset_perf();
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: confirmed.compute_txid(),
                vout: 1,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(confirmed.output[1].value.to_sat() - 1_000),
            script_pubkey: spk.clone(),
        }],
    };
    let _ = q.store().txs.sample_reset_body_decodes();
    hub.accept_tx(&child).expect("non-coinbase chain spend");
    assert_eq!(
        hub.get_live_meta(&child.compute_txid()).map(|(fee, _)| fee),
        Some(1_000),
        "the coin is vout 1's value; vout 0 holds 5_000 sat"
    );
    let s = hub.sample_reset_perf();
    assert_eq!(
        s.get_coin, 2,
        "prepare and the pre-lock recheck each resolve the coin once (got {})",
        s.get_coin
    );
    assert_eq!(
        q.store().txs.sample_reset_body_decodes(),
        s.get_coin,
        "one packed body decode per get_coin; the fk resolve verifies txid.body only"
    );
    assert_eq!(
        s.get_coin_create_mtp, 0,
        "no BIP68 time-lock must not compute create MTP"
    );
    let immature = spend_true(b.txdata[0].compute_txid(), 1_000, spk.clone());
    let err = hub.accept_tx(&immature).unwrap_err();
    assert!(
        matches!(err, AcceptError::ImmatureCoinbase),
        "the tip coinbase is inside the maturity window, got {err}"
    );
    assert!(
        !hub.scripthash_mempool(&script_hash(spk.as_bytes()))
            .is_empty(),
        "output script must still hit SH overlay"
    );
    let err = hub.accept_tx(&confirmed).unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(_)),
        "confirmed body must not park as orphan, got {err}"
    );
    assert_eq!(hub.orphan_count(), 0);
    assert!(
        hub.try_contains(&confirmed.compute_txid()),
        "INV AlreadyHave for Class A txid"
    );
    assert!(
        !hub.try_contains_wtxid(&confirmed.compute_wtxid()),
        "wtxid AlreadyHave needs the recent-confirmed ring"
    );
    hub.note_recent_confirmed(std::slice::from_ref(&confirmed));
    assert!(hub.try_contains_wtxid(&confirmed.compute_wtxid()));
    assert!(
        hub.try_contains(&confirmed.compute_txid()),
        "recent-confirmed ring AlreadyHave for txid"
    );
    hub.note_recent_confirmed(std::slice::from_ref(&confirmed));
    hub.clear_recent_confirmed();
    assert!(
        !hub.try_contains_wtxid(&confirmed.compute_wtxid()),
        "reorg must drop wtxid AlreadyHave"
    );
    assert!(hub.try_contains(&confirmed.compute_txid()));
    let oob = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: confirmed.compute_txid(),
                vout: 99,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: spk.clone(),
        }],
    };
    let err = hub.accept_tx(&oob).unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(_)),
        "confirmed create missing vout must not park, got {err}"
    );
    assert_eq!(hub.orphan_count(), 0);

    hub.remove_for_block(&[child.compute_txid()]);
    q.disconnect_tip().unwrap();
    let ghost = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: confirmed.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(confirmed.output[0].value.to_sat() - 2_000),
            script_pubkey: spk.clone(),
        }],
    };
    let err = hub.accept_tx(&ghost).unwrap_err();
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "disconnected create (no height) must park, got {err}"
    );

    let _ = hub.sample_reset_perf();
    let timed = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[1],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus((1 << 22) | 1),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_0000),
            script_pubkey: spk,
        }],
    };
    hub.accept_tx(&timed).expect("bip68 time-lock spend");
    let s = hub.sample_reset_perf();
    assert!(
        s.get_coin_create_mtp >= 1,
        "BIP68 time-lock spend must compute create MTP"
    );
    hub.evict_after_reorg();
    assert!(
        hub.get_live_meta(&timed.compute_txid()).is_some(),
        "evict_after_reorg must not drop a still-valid BIP68 time lock"
    );
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// Disconnecting the parent's coin must not leave the child selectable.
/// The check runs after the parent is gone and before the function returns.
#[test]
fn reorg_evict_does_not_template_a_parentless_child() {
    let (store, q, cbs) = copy_maturity_pad(3);
    let mp = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[0], 1_000, spk.clone());
    let parent_id = parent.compute_txid();
    hub.accept_tx(&parent).expect("parent");
    let child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9998_0000),
            script_pubkey: spk,
        }],
    };
    let child_id = child.compute_txid();
    hub.accept_tx(&child).expect("child");
    while q.tip_height().map(|h| h.0).unwrap_or(0) > 0 {
        q.disconnect_tip().unwrap();
    }
    let mut saw_parentless = false;
    hub.evict_after_reorg_between(|hub| {
        let picked: Vec<_> = hub
            .select_block_template(hub.template_budget(0))
            .into_iter()
            .map(|(_, s)| s.txid)
            .collect();
        if !hub.contains(&parent_id) && picked.contains(&child_id) {
            saw_parentless = true;
        }
    });
    assert!(
        !saw_parentless,
        "template selected the child after its in-mempool parent was removed"
    );
    assert!(!hub.contains(&parent_id));
    assert!(!hub.contains(&child_id));
    assert!(!hub.sh_index.lock().unwrap().by_tx.contains_key(&parent_id));
    assert!(!hub.sh_index.lock().unwrap().by_tx.contains_key(&child_id));
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// A coin spent after prepare and before commit is not inserted.
#[test]
fn commit_refuses_a_coin_spent_during_script_check() {
    use std::sync::atomic::AtomicUsize;
    /// First `get_coin` returns the prepared coin. Later calls are spent.
    struct Flip {
        map: HashMap<OutPoint, Coin>,
        hits: AtomicUsize,
    }
    impl UtxoProvider for Flip {
        fn get_coin(&self, op: &OutPoint) -> Option<Coin> {
            let n = self.hits.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                self.map.get(op).cloned()
            } else {
                None
            }
        }
    }
    let (_store, q, _cbs) = pad_cbs(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, q).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0x11; 32]),
        vout: 0,
    };
    let coin = Coin {
        txout: TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk.clone(),
        },
        create_height: 1,
        create_mtp: 0,
        is_coinbase: false,
        create_fk: None,
    };
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: spk,
        }],
    };
    let utxo = Flip {
        map: HashMap::from([(op, coin)]),
        hits: AtomicUsize::new(0),
    };
    let err = hub
        .accept_with_utxo(&tx, &utxo, TxOrigin::Relay(None), false, &[])
        .unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(missing) if missing == op),
        "coin spent during the script check must conflict, got {err}"
    );
    let id = tx.compute_txid();
    assert!(!hub.contains(&id));
    assert!(!hub.sh_index.lock().unwrap().by_tx.contains_key(&id));
    let _ = std::fs::remove_dir_all(&mp);
}

/// Package member 0 can evict X and member 1 can then fail. X leaves the
/// relay maps with that rollback, and a prioritisation delta stays.
#[test]
fn package_rollback_unindexes_slot_eviction_and_keeps_delta() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10);
    let victim = spend_true(cbs[0], 1_000, spk.clone());
    let victim_id = victim.compute_txid();
    hub.prioritise_tx(victim_id, 11);
    hub.accept_tx(&victim).expect("victim");
    rbitcoin_mempool::testutil::pin_full_slot_table(&mut hub.lock_write().store);
    let parent = spend_true(cbs[1], 50_000, spk.clone());
    let parent_id = parent.compute_txid();
    let mut bad_child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: spk,
        }],
    };
    bad_child.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
    let err = hub
        .accept_package(&[parent, bad_child])
        .expect_err("annex child rolls the package back");
    assert!(matches!(err, AcceptError::Policy("libre annex")), "{err}");
    assert!(!hub.contains(&parent_id));
    assert!(!hub.contains(&victim_id));
    assert!(
        !hub.sh_index.lock().unwrap().by_tx.contains_key(&victim_id),
        "rolled-back member's eviction must leave sh_index"
    );
    assert!(!hub.wtxid_by_txid.lock().unwrap().contains_key(&victim_id));
    assert!(hub
        .expiry_order
        .lock()
        .unwrap()
        .values()
        .all(|id| *id != victim_id));
    assert_eq!(hub.fee_delta(&victim_id), 11);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A 1-parent-1-child admit that commits the parent, evicts for a slot,
/// then fails the child, drops the evicted tx's relay maps.
#[test]
fn onep_rollback_unindexes_slot_eviction() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10);
    let victim = spend_true(cbs[0], 1_000, spk.clone());
    let victim_id = victim.compute_txid();
    hub.accept_tx(&victim).expect("victim");
    rbitcoin_mempool::testutil::pin_full_slot_table(&mut hub.lock_write().store);
    let parent = spend_true(cbs[1], 50_000, ScriptBuf::from_bytes(vec![0x00]));
    let parent_id = parent.compute_txid();
    assert!(hub.try_note_extra_compact(&parent));
    let child = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: spk,
        }],
    };
    let _ = hub.accept_tx(&child);
    assert!(!hub.contains(&parent_id));
    assert!(!hub.contains(&victim_id));
    assert!(
        !hub.sh_index.lock().unwrap().by_tx.contains_key(&victim_id),
        "1p1c rollback must unindex the parent's eviction"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The orphan 1p1c path commits both members before the trim. When the
/// trim drops them, the conflict the parent replaced comes back.
#[test]
fn failed_1p1c_trim_restores_the_conflict() {
    let (_store, q, cbs) = pad_cbs(3);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let victim = spend_true(cbs[0], 1_000, spk.clone());
    let victim_id = victim.compute_txid();
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, q, victim.weight().to_wu() + 400).unwrap();
    hub.set_relay_enabled(true);
    hub.accept_tx(&victim).expect("victim");
    let parent = spend_true(cbs[0], 20_000, spk.clone());
    let parent_id = parent.compute_txid();
    assert!(hub.try_note_extra_compact(&parent));
    let mut child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        parent.output[0].value.to_sat() - 5_000,
    );
    child.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 4_000]);
    let err = hub.accept_tx(&child);
    assert!(
        err.is_err(),
        "an over-budget 1p1c must not stay, got {err:?}"
    );
    assert!(
        !hub.contains(&parent_id),
        "trimmed parent must be rolled back"
    );
    assert!(!hub.contains(&child.compute_txid()));
    assert!(
        hub.contains(&victim_id),
        "the conflict the parent replaced must be restored"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Eviction keeps a prioritisation delta. A later duplicate of the
/// survivor does not apply that eviction again. Mining drops the delta.
#[test]
fn eviction_keeps_priority_and_duplicate_does_not_replay_it() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let low = spend_true(cbs[0], 1_000, spk.clone());
    let high = spend_true(cbs[1], 50_000, spk);
    let budget = low.weight().to_wu();
    let hub = MempoolHub::open_with_weight(&dir, q, budget).unwrap();
    hub.set_relay_enabled(true);
    let low_id = low.compute_txid();
    let high_id = high.compute_txid();
    hub.prioritise_tx(low_id, 9);
    hub.prioritise_tx(high_id, 4);
    hub.accept_tx(&low).expect("low");
    hub.accept_tx(&high).expect("high evicts low");
    assert!(!hub.contains(&low_id));
    assert_eq!(hub.fee_delta(&low_id), 9);
    let updates = hub.template_updates();
    let err = hub.accept_tx(&high).expect_err("already in the pool");
    assert!(matches!(err, AcceptError::Duplicate(_)), "{err}");
    assert_eq!(hub.template_updates(), updates);
    assert_eq!(hub.fee_delta(&low_id), 9);
    assert!(hub.remove_for_block(&[high_id]) >= 1);
    assert_eq!(hub.fee_delta(&high_id), 0);
    assert_eq!(hub.fee_delta(&low_id), 9);
    assert_eq!(hub.remove_for_block(&[low_id]), 0);
    assert_eq!(
        hub.fee_delta(&low_id),
        0,
        "mining an evicted tx drops its prioritisation"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full slot table evicts a live tx to admit the next one, and that
/// tx leaves the relay maps with the graph.
#[test]
fn slot_evict_unindexes_evicted_relay_maps() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10);
    let first = spend_true(cbs[0], 2_000, spk.clone());
    let second = spend_true(cbs[1], 2_000, spk);
    let first_id = first.compute_txid();
    hub.accept_tx(&first).expect("first admit");
    rbitcoin_mempool::testutil::pin_full_slot_table(&mut hub.lock_write().store);
    hub.accept_tx(&second)
        .expect("second admit evicts for a slot");
    assert!(!hub.contains(&first_id));
    assert!(hub.contains(&second.compute_txid()));
    assert!(
        !hub.sh_index.lock().unwrap().by_tx.contains_key(&first_id),
        "slot eviction must drop sh_index"
    );
    assert!(!hub.wtxid_by_txid.lock().unwrap().contains_key(&first_id));
    assert!(hub
        .expiry_order
        .lock()
        .unwrap()
        .values()
        .all(|id| *id != first_id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A single-tx admit that trims for the weight budget must drop the
/// evicted tx from the relay maps, not only the graph.
#[test]
fn admission_trim_unindexes_evicted_relay_maps() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let low = spend_true(cbs[0], 1_000, spk.clone());
    let high = spend_true(cbs[1], 50_000, spk);
    let budget = low.weight().to_wu();
    let hub = MempoolHub::open_with_weight(&dir, q, budget).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10);
    let low_id = low.compute_txid();
    let high_id = high.compute_txid();
    hub.accept_tx(&low).expect("low feerate fits");
    hub.accept_tx(&high)
        .expect("higher feerate evicts the low one");
    assert!(
        !hub.contains(&low_id),
        "the low feerate tx leaves the graph"
    );
    assert!(hub.contains(&high_id));
    assert!(
        !hub.sh_index.lock().unwrap().by_tx.contains_key(&low_id),
        "fee eviction must leave sh_index"
    );
    assert!(!hub.wtxid_by_txid.lock().unwrap().contains_key(&low_id));
    assert!(hub
        .expiry_order
        .lock()
        .unwrap()
        .values()
        .all(|id| *id != low_id));
    assert!(hub.sh_index.lock().unwrap().by_tx.contains_key(&high_id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Confirm/RBF unindex must drop `relay_seq` / `accept_at` for the gone
/// wtxid and leave a still-live sibling indexed.
#[test]
fn unindex_drops_relay_seq_and_accept_at() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10);
    let gone = spend_true(cbs[0], 1_000, spk.clone());
    let stay = spend_true(cbs[1], 2_000, spk);
    hub.accept_tx(&gone).expect("accept gone");
    hub.accept_tx(&stay).expect("accept stay");
    let gone_w = gone.compute_wtxid();
    let stay_w = stay.compute_wtxid();
    assert!(hub.relay_seq_of(&gone_w).is_some());
    assert!(hub.relay_seq_of(&stay_w).is_some());
    assert!(hub.remove_for_block(&[gone.compute_txid()]) >= 1);
    assert!(hub.contains(&stay.compute_txid()));
    assert!(hub.relay_seq_of(&gone_w).is_none());
    assert!(hub.relay_seq_of(&stay_w).is_some());
    // A live tx stays indexed. A gone tx that is not parked drops its maps.
    // An orphan that is only parked keeps them.
    hub.unindex_if_absent(&stay);
    assert!(hub.relay_seq_of(&stay_w).is_some());
    let orphan = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x7eu8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(matches!(
        hub.accept_tx(&orphan),
        Err(AcceptError::Orphaned { .. })
    ));
    let orphan_w = orphan.compute_wtxid();
    hub.insert_relay_maps(
        orphan.compute_txid(),
        orphan_w,
        1,
        hub.relay_now_secs(),
        true,
    );
    assert!(hub.relay_seq_of(&orphan_w).is_some());
    hub.unindex_if_absent(&orphan);
    assert!(
        hub.relay_seq_of(&orphan_w).is_some(),
        "a parked orphan is still indexed"
    );
    let absent = spend_true(cbs[2], 3_000, ScriptBuf::from_bytes(vec![0x51]));
    let absent_w = absent.compute_wtxid();
    hub.insert_relay_maps(
        absent.compute_txid(),
        absent_w,
        1,
        hub.relay_now_secs(),
        true,
    );
    assert!(hub.relay_seq_of(&absent_w).is_some());
    hub.unindex_if_absent(&absent);
    assert!(
        hub.relay_seq_of(&absent_w).is_none(),
        "a tx in neither the graph nor the orphanage drops its relay maps"
    );
    hub.note_mock_now(40);
    assert!(!hub.tx_inv_due(&gone_w));
    assert!(hub.tx_inv_due(&stay_w));
    let _ = std::fs::remove_dir_all(&mp);
}

/// Without `setmocktime`, INV age must still elapse on wall clock
/// (`mempool_accept_wtxid` wait_for_broadcast; mock_now==0 must not freeze).
#[test]
fn tx_inv_due_uses_wall_clock_when_mocktime_unset() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    use bitcoin::script::ScriptBuf;

    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    assert_eq!(hub.mock_now.load(Ordering::Relaxed), 0);
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_tx(&tx).expect("accept");
    let w = tx.compute_wtxid();
    assert!(
        !hub.tx_inv_due(&w),
        "fresh accept must not be due before 30s"
    );
    {
        let mut ats = hub.accept_at.lock().unwrap();
        let mut order = hub.expiry_order.lock().unwrap();
        let at = ats.get_mut(&w).expect("accept_at");
        let old = *at;
        *at = at.saturating_sub(30);
        let tid = order.remove(&(old, w)).expect("expiry order");
        order.insert((*at, w), tid);
        hub.min_live_accept_at.store(*at, Ordering::Relaxed);
    }
    assert!(
        hub.tx_inv_due(&w),
        "30s wall age must due when mocktime is unset"
    );
    assert!(hub.any_tx_inv_due());
    let _ = std::fs::remove_dir_all(&mp);
}

/// A tx that is already confirmed-strong leaves the relay maps when purge
/// drops it. The graph filter is what decides, including a tx that is gone.
#[test]
fn purge_confirmed_drops_relay_maps() {
    use rbitcoin_consensus::{mine_regtest_paying, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

    let (store, q, cbs) = copy_maturity_pad(3);
    let params = ChainParams::regtest();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_tx(&tx).expect("admit");
    let w = tx.compute_wtxid();
    assert!(hub.relay_seq_of(&w).is_some());
    let tip_h = q.tip_height().unwrap().0;
    let fk = q.tip_header_fk().unwrap().unwrap();
    let rec = q.get_header(fk).unwrap();
    let prev = bitcoin::BlockHash::from_byte_array(rec.hash);
    let block = mine_regtest_paying(
        prev,
        rec.timestamp + 600,
        tip_h + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![tx.clone()],
    );
    accept_and_connect_block(&q, &params, Height(tip_h + 1), &block, Milestone::NONE)
        .expect("connect the mempool tx");
    assert!(hub.contains(&tx.compute_txid()));
    assert!(hub.purge_confirmed_on_chain() >= 1);
    assert!(!hub.contains(&tx.compute_txid()));
    assert!(
        hub.relay_seq_of(&w).is_none(),
        "purge drops relay maps for a tx the graph no longer holds"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store);
}

/// A confirm purge that faults after a chain-spent tx has already left the
/// graph still drops that tx's relay maps. Maintenance stays unpublished
/// so the next call can finish whatever is still live.
#[test]
fn purge_fault_unindexes_txs_that_already_left() {
    use rbitcoin_consensus::{mine_regtest_paying, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

    let (store, q, cbs) = copy_maturity_pad(3);
    let params = ChainParams::regtest();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    let confirmed = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    let conflict = spend_true(cbs[1], 2_000, ScriptBuf::from_bytes(vec![0x51]));
    let chain_spend = spend_true(cbs[1], 3_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_tx(&confirmed).expect("admit confirmed");
    hub.accept_tx(&conflict).expect("admit conflict");
    let confirmed_id = confirmed.compute_txid();
    let conflict_id = conflict.compute_txid();
    assert!(hub.relay_indexed(&confirmed_id));
    assert!(hub.relay_indexed(&conflict_id));
    let tip_h = q.tip_height().unwrap().0;
    let fk = q.tip_header_fk().unwrap().unwrap();
    let rec = q.get_header(fk).unwrap();
    let prev = bitcoin::BlockHash::from_byte_array(rec.hash);
    let block = mine_regtest_paying(
        prev,
        rec.timestamp + 600,
        tip_h + 1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![confirmed.clone(), chain_spend],
    );
    accept_and_connect_block(&q, &params, Height(tip_h + 1), &block, Milestone::NONE)
        .expect("connect");
    let body = {
        let mut g = hub.lock_write();
        g.bodies.remove(&confirmed_id).expect("confirmed body")
    };
    assert!(
        !hub.begin_pool_maintenance(),
        "a missing body is a store fault and must not publish maintenance"
    );
    assert!(!hub.pool_maintained());
    assert!(
        !hub.contains(&conflict_id),
        "the chain-spent tx already left the graph"
    );
    assert!(
        !hub.relay_indexed(&conflict_id),
        "a tx that left before the fault must leave the relay maps"
    );
    assert!(
        hub.contains(&confirmed_id),
        "the unlink that failed stays in the graph"
    );
    assert!(hub.relay_indexed(&confirmed_id));
    {
        let mut g = hub.lock_write();
        g.bodies.insert(confirmed_id, body);
    }
    assert!(
        hub.begin_pool_maintenance(),
        "the next call retries the tx that is still live"
    );
    assert!(hub.pool_maintained());
    assert!(!hub.contains(&confirmed_id));
    assert!(!hub.relay_indexed(&confirmed_id));
    assert!(!hub.relay_indexed(&conflict_id));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store);
}

/// The maintained flag is the Ready bit for listing and `generate`. It must
/// stay clear while `begin_pool_maintenance` is still waiting on the template
/// lock, which it holds across the purge.
#[test]
fn maintenance_flag_stays_clear_until_the_purge_lock() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let mp = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hold = mp.template_hold();
    let bg = Arc::clone(&mp);
    let started = std::thread::spawn(move || bg.begin_pool_maintenance());
    for _ in 0..40 {
        if started.is_finished() || mp.pool_maintained() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        !started.is_finished(),
        "begin returned while the template hold was still held"
    );
    assert!(
        !mp.pool_maintained(),
        "maintenance became visible before the purge could take the template lock"
    );
    drop(hold);
    started.join().expect("begin");
    assert!(mp.pool_maintained());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// A connect waiting on `template_prev` must see maintenance and the leaving
/// tip's fee sample. Both are stored before that lock is released.
fn on_maint_publish(mp: &MempoolHub) {
    assert!(
        mp.pool_maintained(),
        "maintenance flag was still clear inside the template lock"
    );
    let height = mp.query.tip_height().expect("tip").0;
    assert!(
        mp.block_p10_history.lock().unwrap().get(height).is_some(),
        "leaving tip was not in fee history inside the template lock"
    );
}

#[test]
fn maintenance_is_published_before_the_template_lock_releases() {
    let (store, q, _cbs) = copy_maturity_pad(3);
    let dir = tmp();
    let mp = MempoolHub::open(&dir, q).unwrap();
    MempoolHub::set_maint_publish_hook(on_maint_publish);
    assert!(mp.begin_pool_maintenance());
    assert!(mp.pool_maintained());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store);
}

/// Callers queue a feefilter only when the stored relay bit changes. A second
/// call, and a purge that does not publish, are not an edge.
#[test]
fn relay_edge_reports_a_change_only_when_the_bit_moves() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let mp = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    assert_eq!(mp.apply_relay_edge(true), Some(true));
    assert!(mp.relay_enabled());
    assert!(mp.pool_maintained());
    assert!(
        !mp.take_fee_backfill_due(),
        "the on edge consumes the preload bit"
    );
    assert_eq!(
        mp.apply_relay_edge(true),
        None,
        "a second on is not an edge"
    );
    assert_eq!(mp.apply_relay_edge(false), Some(false));
    assert!(!mp.relay_enabled());
    assert!(mp.pool_maintained(), "pausing relay keeps pool maintenance");
    assert_eq!(mp.apply_relay_edge(false), None);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Before maintenance begins, per-block remove is deferred. Enabling relay
/// starts maintenance and runs the purge.
#[test]
fn remove_for_block_skipped_until_relay_then_purge() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let mp = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    assert!(!mp.relay_enabled());
    assert!(!mp.pool_maintained());
    let dummy = Txid::from_byte_array([9u8; 32]);
    mp.prioritise_tx(dummy, 3);
    // Strip stays deferred until maintenance begins. The mined delta still drops.
    assert_eq!(mp.remove_for_block(&[dummy]), 0);
    assert_eq!(
        mp.fee_delta(&dummy),
        0,
        "a mined delta drops while relay is off"
    );
    // Enabling relay runs purge (empty → 0) and arms per-block strip.
    mp.set_relay_enabled(true);
    assert!(mp.relay_enabled());
    assert!(mp.pool_maintained());
    assert_eq!(mp.purge_confirmed_on_chain(), 0);
    // Still no-op for unknown txid, but path is live.
    assert_eq!(mp.remove_for_block(&[dummy]), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn hub_accept_remove_with_map_utxo_path() {
    // MempoolHub needs Query; use open empty store + MapUtxo via direct ActiveMempool
    // for isolation — hub Query path covered when store has txs.
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    assert!(!hub.relay_enabled());
    hub.set_relay_enabled(true);
    assert!(hub.relay_enabled());
    assert_eq!(hub.live_count(), 0);
    // Without chain UTXO, accept parks as orphan (soft path).
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub.test_accept(&tx).unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(_)),
        "dry-run missing parent: {err}"
    );
    assert_eq!(hub.orphan_count(), 0);
    let err = hub.accept_tx(&tx).unwrap_err();
    assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
    assert_eq!(hub.orphan_count(), 1);
    let err = hub.test_accept(&tx).unwrap_err();
    assert!(
        matches!(err, AcceptError::MissingPrevout(_)),
        "dry-run of parked orphan must stay MissingPrevout: {err}"
    );
    assert_eq!(hub.orphan_count(), 1);
    assert!(hub.fee_histogram().is_empty());
    assert!(hub.estimate_fee_btc_per_kb(2) < 0.0 || hub.estimate_fee_btc_per_kb(2) >= 0.0);
    assert!(MempoolHub::relay_fee_btc_per_kb() > 0.0);
    assert!(hub.scripthash_mempool(&[0u8; 32]).is_empty());
    assert_eq!(hub.scripthash_unconfirmed_delta(&[0u8; 32]).unwrap(), 0);
    assert!(hub.list_live().is_empty());
    assert!(!hub.contains_wtxid(&Wtxid::from_byte_array([0u8; 32])));
    assert!(hub
        .get_tx_by_wtxid(&Wtxid::from_byte_array([0u8; 32]))
        .is_none());
    assert_eq!(hub.remove_for_block(&[]), 0);
    assert_eq!(hub.reorg_reaccept(&[]), 0);
    hub.flush().unwrap();
    let _ = hub.compact();
    let _ = hub.generation();
    let _ = hub.subscribe_announces();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn accept_from_peer_erase_drops_orphan() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub
        .accept_tx_from(&tx, TxOrigin::Relay(Some(4)))
        .unwrap_err();
    assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
    assert_eq!(hub.orphan_snapshot()[0].announcers, vec![4]);
    hub.add_orphan_announcer(&tx.compute_txid(), 8);
    assert_eq!(hub.orphan_snapshot()[0].announcers, vec![4, 8]);
    hub.erase_orphans_for_peer(4);
    assert_eq!(hub.orphan_count(), 1);
    hub.erase_orphans_for_peer(8);
    assert_eq!(hub.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn compact_fill_uses_parked_orphan() {
    use bitcoin::bip152::ShortId;
    use bitcoin::hashes::Hash;
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(matches!(
        hub.accept_tx(&tx),
        Err(AcceptError::Orphaned { .. })
    ));
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let nonce = 1u64;
    let keys = ShortId::calculate_siphash_keys(&genesis.header, nonce);
    let sid = ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys);
    let got = hub
        .try_clone_matching_shortids(&genesis.header, nonce, 2, &[sid])
        .expect("read lock");
    let bodies = got.get(&sid).expect("orphan must fill compact short-id");
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0].compute_txid(), tx.compute_txid());
    let w = tx.compute_wtxid();
    let (_map, fill) = hub
        .try_cmpct_avail(&genesis.header, nonce, 2, &[sid], &[])
        .expect("avail");
    assert!(
        fill.orphan.contains(&w),
        "clone source is the reconstruct fill"
    );
    let (_empty, pref) = hub
        .try_cmpct_avail(&genesis.header, nonce, 2, &[], &[w])
        .expect("prefill classify");
    assert!(
        pref.orphan.contains(&w),
        "prefill wtxids classified in the same read as clone"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn try_note_extra_compact_fills_shortid() {
    use bitcoin::bip152::ShortId;
    use bitcoin::hashes::Hash;
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([8u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(hub.try_note_extra_compact(&tx));
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let nonce = 3u64;
    let keys = ShortId::calculate_siphash_keys(&genesis.header, nonce);
    let sid = ShortId::with_siphash_keys(&tx.compute_wtxid().to_raw_hash(), keys);
    let (_map, fill) = hub
        .try_cmpct_avail(&genesis.header, nonce, 2, &[sid], &[])
        .expect("avail");
    assert!(
        fill.extra.contains(&tx.compute_wtxid()),
        "compact-seen extra must fill short-ids"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn startup_recomputes_unknown_sigops_with_configured_reserve() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0xae]),
            };
            999
        ],
    };
    let (txid, wtxid) = (tx.compute_txid(), tx.compute_wtxid());
    let mempool_dir = tmp();
    {
        let mut store = rbitcoin_mempool::Mempool::open_or_create(&mempool_dir).unwrap();
        store
            .append_live_tx(
                &tx,
                &txid,
                &wtxid,
                4_999_999_001,
                tx.weight().to_wu(),
                u64::MAX,
                1_700_000_000,
                &[],
            )
            .unwrap();
        store.flush().unwrap();
    }
    let hub = MempoolHub::open_with_weight_persist_and_sigop_reserve(
        &mempool_dir,
        Arc::clone(q),
        rbitcoin_mempool::DEFAULT_MAX_MEMPOOL_WEIGHT,
        true,
        Some(0),
    )
    .unwrap();
    let budget = hub.template_budget(0);
    assert_eq!(budget.reserved_sigops, 0);
    let picked = hub.select_block_template(budget);
    assert_eq!(picked.len(), 1);
    assert_eq!(*picked[0].0, tx);
    assert_eq!(
        (picked[0].1.fee_sat, picked[0].1.sigop_cost),
        (4_999_999_001, 79_920)
    );
    // A caller reserving Core's 400 for its coinbase cannot fit it.
    let core_reserve = rbitcoin_mempool::SelectBudget {
        reserved_sigops: 400,
        ..budget
    };
    assert!(hub.select_block_template(core_reserve).is_empty());
    assert!(hub.contains(&txid));
    let _ = std::fs::remove_dir_all(&mempool_dir);
}

#[test]
fn take_due_parent_getdata_one_flush_covers_max_ancestor_package() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let mut missing = BTreeSet::new();
    for i in 0u8..24 {
        missing.insert(Txid::from_byte_array([i + 1; 32]));
    }
    let t0 = 1_000u64;
    hub.schedule_orphan_parents(&missing, 1, true, t0);
    let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
    let first = hub.take_due_parent_getdata(1, due);
    assert_eq!(
        first.len(),
        24,
        "24-orphan ancestor package must be one GetData"
    );
    assert!(hub.take_due_parent_getdata(1, due).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn take_due_parent_getdata_caps_per_flush() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let mut missing = BTreeSet::new();
    for i in 0u16..120 {
        let mut h = [0u8; 32];
        h[0] = (i >> 8) as u8;
        h[1] = i as u8;
        missing.insert(Txid::from_byte_array(h));
    }
    let t0 = 1_000u64;
    hub.schedule_orphan_parents(&missing, 1, true, t0);
    let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
    let first = hub.take_due_parent_getdata(1, due);
    assert_eq!(first.len(), MAX_PARENTS_PER_PARK);
    let rest = hub.take_due_parent_getdata(1, due);
    assert_eq!(rest.len(), 20);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

fn parent_hash(i: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..4].copy_from_slice(&i.to_le_bytes());
    h
}

#[test]
fn parent_req_stops_at_per_peer_cap() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let cap = parent_req::MAX_PARENT_ANN_PER_PEER;
    for i in 0..(cap as u32 + 10) {
        let accepted = hub.note_inv_tx_requested(7, parent_hash(i), false, 1_000, false);
        if i < cap as u32 {
            assert_eq!(
                accepted,
                ParentNote::RequestNow,
                "announcement {i} under the cap"
            );
        } else {
            assert_eq!(
                accepted,
                ParentNote::PeerCapped,
                "announcement {i} past this peer's cap"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn parent_req_stops_at_global_cap() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let per_peer = parent_req::MAX_PARENT_ANN_PER_PEER as u32;
    let global = parent_req::MAX_PARENT_ANN_GLOBAL as u32;
    let mut n = 0u32;
    let mut peer = 1u64;
    while n < global {
        assert_eq!(
            hub.note_inv_tx_requested(peer, parent_hash(n), false, 1_000, false),
            ParentNote::RequestNow
        );
        n += 1;
        if n.is_multiple_of(per_peer) {
            peer += 1;
        }
    }
    assert_eq!(
        hub.note_inv_tx_requested(peer, parent_hash(n), false, 1_000, false),
        ParentNote::GlobalFull,
        "a peer under its own cap is not misbehavior when the table is full"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn second_peer_take_due_does_not_drop_other_peers_keys() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hash = [0x91; 32];
    let txid = Txid::from_byte_array(hash);
    let wtxid = Wtxid::from_byte_array(hash);
    assert_eq!(
        hub.note_inv_tx_requested(1, hash, false, 1_000, false),
        ParentNote::RequestNow
    );
    hub.note_recent_reject(wtxid);
    assert_eq!(hub.announcer_peers_for(&txid, &wtxid), vec![1]);
    assert!(hub.take_due_parent_getdata(2, 2_000).is_empty());
    assert_eq!(
        hub.announcer_peers_for(&txid, &wtxid),
        vec![1],
        "peer 2's heartbeat must not walk peer 1's keys"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn disconnect_makes_the_waiting_wtxid_peer_due() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hash = [0xde; 32];
    let now = 1_000u64;
    assert_eq!(
        hub.note_inv_tx_requested(1, hash, true, now, true),
        ParentNote::RequestNow
    );
    assert_eq!(
        hub.note_inv_tx_requested(3, hash, true, now, true),
        ParentNote::Deferred
    );
    assert!(
        hub.take_due_parent_getdata(3, now).is_empty(),
        "the second announcer waits out the in-flight window"
    );
    hub.forget_parent_anns_for_peer(1);
    let due = hub.take_due_parent_getdata(3, now);
    assert_eq!(
        due.len(),
        1,
        "disconnect of the in-flight peer makes the waiter due immediately"
    );
    assert_eq!(due[0].hash, hash);
    assert!(due[0].wtxid);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn rejected_wtxid_is_not_requested() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let now = 1_000u64;
    let rejected = [0x11u8; 32];
    let fresh = [0x22u8; 32];
    assert_eq!(
        hub.note_inv_tx_requested(1, rejected, true, now, true),
        ParentNote::RequestNow
    );
    assert_eq!(
        hub.note_inv_tx_requested(3, rejected, true, now, true),
        ParentNote::Deferred
    );
    assert_eq!(
        hub.note_inv_tx_requested(1, fresh, true, now, true),
        ParentNote::RequestNow
    );
    assert_eq!(
        hub.note_inv_tx_requested(3, fresh, true, now, true),
        ParentNote::Deferred
    );
    hub.note_recent_reject(Wtxid::from_byte_array(rejected));
    hub.forget_parent_anns_for_peer(1);
    let due = hub.take_due_parent_getdata(3, now);
    assert!(
        due.iter().all(|d| d.hash != rejected),
        "a wtxid already in recent-reject is not fetched"
    );
    assert!(
        due.iter().any(|d| d.hash == fresh && d.wtxid),
        "a wtxid that is neither live nor rejected is still fetched"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn wtxid_followup_is_requested_as_wtx() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hash = [0xab; 32];
    assert_eq!(
        hub.note_inv_tx_requested(1, hash, false, 1_000, true),
        ParentNote::RequestNow
    );
    assert_eq!(
        hub.note_inv_tx_requested(3, hash, false, 1_000, true),
        ParentNote::Deferred,
        "the wtxid follow-up is its own row and is not a second getdata"
    );
    let missing = BTreeSet::from([Txid::from_byte_array(hash)]);
    hub.schedule_orphan_parents(&missing, 2, false, 1_000);
    let expired = 1_000 + GETDATA_TX_INTERVAL_SECS;
    assert!(hub.take_due_parent_getdata(1, expired).is_empty());
    let follow = hub.take_due_parent_getdata(3, expired);
    assert_eq!(follow.len(), 1);
    assert_eq!(follow[0].hash, hash);
    assert!(follow[0].wtxid, "wtxid follow-up must stay WTx");
    assert!(
        hub.take_due_parent_getdata(2, expired).is_empty(),
        "a txid parent waits while those bytes are in flight"
    );
    let parent = hub.take_due_parent_getdata(2, expired + GETDATA_TX_INTERVAL_SECS);
    assert_eq!(parent.len(), 1);
    assert_eq!(parent[0].hash, hash);
    assert!(
        !parent[0].wtxid,
        "a txid parent is not fetched as a wtxid because another peer announced these bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn same_peer_wtxid_inflight_expires_back_to_txid_parent() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hash = [0xbc; 32];
    let missing = BTreeSet::from([Txid::from_byte_array(hash)]);
    let t0 = 1_000u64;
    hub.schedule_orphan_parents(&missing, 2, false, t0);
    assert_eq!(
        hub.note_inv_tx_requested(2, hash, false, t0, true),
        ParentNote::RequestNow,
        "the same peer's wtxid inv is a second announcement"
    );
    let due = t0 + TXID_RELAY_DELAY_SECS;
    assert!(
        hub.take_due_parent_getdata(2, due).is_empty(),
        "the txid parent waits while this peer's wtxid request is in flight"
    );
    let expired = t0 + GETDATA_TX_INTERVAL_SECS;
    let parent = hub.take_due_parent_getdata(2, expired);
    assert_eq!(
        parent.len(),
        1,
        "the txid parent is requested once the wtxid window ends"
    );
    assert_eq!(parent[0].hash, hash);
    assert!(
        !parent[0].wtxid,
        "after the window the parent is requested as a txid"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn take_due_parent_getdata_waits_inbound_txid_delay() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let mut missing = BTreeSet::new();
    for i in 0u8..20 {
        missing.insert(Txid::from_byte_array([i + 1; 32]));
    }
    let t0 = 1_000u64;
    hub.schedule_orphan_parents(&missing, 1, true, t0);
    assert!(
        hub.take_due_parent_getdata(1, t0 + NONPREF_PEER_TX_DELAY_SECS)
            .is_empty(),
        "inbound must wait TXID_RELAY past NONPREF"
    );
    let due = t0 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
    let first = hub.take_due_parent_getdata(1, due);
    assert_eq!(first.len(), 20);
    assert!(
        hub.take_due_parent_getdata(1, due).is_empty(),
        "in-flight must not re-ask"
    );
    let expired = due + GETDATA_TX_INTERVAL_SECS;
    assert!(
        hub.take_due_parent_getdata(1, expired).is_empty(),
        "same peer is not retried after interval"
    );
    hub.schedule_orphan_parents(&missing, 2, true, expired);
    let other = hub.take_due_parent_getdata(
        2,
        expired + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS,
    );
    assert_eq!(other.len(), 20, "other peer after expiry");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn resolve_tx_request_lets_other_peer_fetch_after_reject() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    let hash = [0x44; 32];
    let txid = Txid::from_byte_array(hash);
    let wtxid = Wtxid::from_byte_array(hash);
    hub.note_inv_tx_requested(1, hash, true, 1_000, false);
    let missing = BTreeSet::from([txid]);
    hub.schedule_orphan_parents(&missing, 2, true, 1_000);
    let due = 1_000 + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS;
    assert!(
        hub.take_due_parent_getdata(2, due).is_empty(),
        "in-flight INV GETDATA must block other peer"
    );
    hub.resolve_tx_request(&txid, &wtxid, false);
    hub.schedule_orphan_parents(&missing, 2, true, due);
    let got =
        hub.take_due_parent_getdata(2, due + NONPREF_PEER_TX_DELAY_SECS + TXID_RELAY_DELAY_SECS);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].hash, txid.to_byte_array());
    assert!(!got[0].wtxid);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}
#[test]
fn open_with_weight_and_package_empty() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open_with_weight(&dir, Arc::new(q), 1_000_000).unwrap();
    hub.set_relay_enabled(true);
    assert!(matches!(
        hub.accept_package(&[]),
        Err(AcceptError::PackageEmpty)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn accept_package_does_not_park_orphan_member() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x44; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub.accept_package(&[tx]).unwrap_err();
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "package member missing parent: {err}"
    );
    assert_eq!(hub.orphan_count(), 0, "accept_package must not park");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// A child already in the orphan pool is still a package member.
/// `submitpackage` and Electrum use this hub path.
#[test]
fn hub_package_admits_its_parked_child() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(20_0000_0000),
                script_pubkey: spk.clone(),
            },
            TxOut {
                value: Amount::from_sat(20_0000_0000),
                script_pubkey: spk.clone(),
            },
        ],
    };
    let parent_id = parent.compute_txid();
    let child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        19_0000_0000,
    );
    let sibling = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 1,
        },
        19_0000_0000,
    );
    let child_id = child.compute_txid();
    let sibling_id = sibling.compute_txid();
    for tx in [&child, &sibling] {
        let err = hub.accept_tx(tx).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { .. }),
            "spend of the missing parent must park, got {err:?}"
        );
    }
    assert!(
        hub.add_orphan_announcer(&child_id, 4),
        "the parked child takes the peer"
    );
    let accepted = hub
        .accept_package(&[parent.clone(), child.clone()])
        .expect("hub package contains the parked child");
    assert_eq!(accepted.len(), 2);
    assert!(hub.try_contains(&parent_id));
    assert!(hub.try_contains(&child_id));
    assert!(
        !hub.lock_write().orphanage.has_announcer(4),
        "admitting the lifted child must drop its in-flight peer"
    );
    assert!(
        hub.try_contains(&sibling_id),
        "a parked sibling outside the package must still be admitted"
    );
    assert_eq!(hub.orphan_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[1], 10_000, spk);
    let parent_id = parent.compute_txid();
    let child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        49_0000_0000,
    );
    let child_id = child.compute_txid();
    let err = hub.accept_tx(&child).unwrap_err();
    assert!(matches!(err, AcceptError::Orphaned { .. }), "{err:?}");
    let bad = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        50_0000_0000,
    );
    let err = hub
        .accept_package(&[parent, child, bad])
        .expect_err("last member overspends the parent output");
    assert!(
        !matches!(err, AcceptError::Duplicate(id) if id == child_id),
        "a failed hub package must not report the parked child as a duplicate, got {err:?}"
    );
    assert!(
        !hub.contains(&parent_id),
        "a failed package must not leave the parent"
    );
    assert!(
        !hub.contains(&child_id),
        "a failed package must not leave the child in the mempool"
    );
    assert_eq!(
        hub.orphan_count(),
        1,
        "a failed package must put the parked child back, got {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A parent can land while its child is lifted. Putting the child back
/// under that parent leaves it parked with nobody left to wake it.
#[test]
fn failed_package_does_not_park_child_under_a_live_parent() {
    let (_store, q, cbs) = pad_cbs(3);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[0], 10_000, spk);
    let parent_id = parent.compute_txid();
    hub.accept_tx(&parent).expect("parent pays for itself");
    let child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        49_0000_0000,
    );
    let child_id = child.compute_txid();
    {
        let mut missing = BTreeSet::new();
        missing.insert(parent_id);
        let mut g = hub.lock_write();
        g.park_orphan_from(&child, missing, Some(4));
    }
    hub.add_orphan_announcer(&child_id, 8);
    let dummy = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x44; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub
        .accept_package(&[child.clone(), dummy])
        .expect_err("the second member has no parent");
    assert!(
        !matches!(err, AcceptError::Duplicate(id) if id == child_id),
        "the live parent must not make the lifted child a duplicate, got {err:?}"
    );
    assert!(
        hub.contains(&child_id),
        "a child whose parents are already in the mempool must be admitted, not parked, got {err:?}"
    );
    assert_eq!(hub.orphan_count(), 0);
    assert!(hub.contains(&parent_id));
    let _ = std::fs::remove_dir_all(&dir);

    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[1], 10_000, ScriptBuf::from_bytes(vec![0x51]));
    let parent_id = parent.compute_txid();
    hub.accept_tx(&parent).expect("parent");
    let absent = Txid::from_byte_array([0xab; 32]);
    let mut child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        49_0000_0000,
    );
    child.input.push(TxIn {
        previous_output: OutPoint {
            txid: absent,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    let child_id = child.compute_txid();
    {
        let mut missing = BTreeSet::new();
        missing.insert(parent_id);
        missing.insert(absent);
        let mut g = hub.lock_write();
        g.park_orphan_from(&child, missing, Some(4));
    }
    hub.add_orphan_announcer(&child_id, 8);
    let dummy = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x45; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub
        .accept_package(&[child, dummy])
        .expect_err("the child still misses a parent");
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "the child still misses a parent, got {err:?}"
    );
    assert!(!hub.contains(&child_id));
    let parked = hub.orphan_snapshot();
    assert_eq!(parked.len(), 1);
    assert_eq!(
        parked[0].announcers,
        vec![4, 8],
        "putting the child back must keep the peers who announced it"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A prioritised child is under the relay floor until its delta is applied.
/// A failed package must still admit it once its parent is in the mempool.
#[test]
fn failed_package_admits_prioritised_child() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = spend_true(cbs[2], 10_000, spk);
    let parent_id = parent.compute_txid();
    hub.accept_tx(&parent).expect("parent pays for itself");
    let parent_value = 50_0000_0000 - 10_000;
    let child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        parent_value - 1,
    );
    let child_id = child.compute_txid();
    let err = hub
        .accept_tx(&child)
        .expect_err("one sat is under the relay floor");
    assert!(
        matches!(err, AcceptError::Policy("min relay fee")),
        "raw fee must miss the floor before the delta, got {err:?}"
    );
    hub.prioritise_tx(child_id, 1_000_000);
    {
        let mut missing = BTreeSet::new();
        missing.insert(parent_id);
        let mut g = hub.lock_write();
        g.park_orphan_from(&child, missing, Some(4));
    }
    let dummy = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x46; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub
        .accept_package(&[child, dummy])
        .expect_err("the second member has no parent");
    assert!(
        hub.contains(&child_id),
        "a prioritised child must be admitted after the package fails, got {err:?}"
    );
    assert_eq!(hub.orphan_count(), 0);
    assert!(hub.contains(&parent_id));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Coinbases at heights `1..=n`, each with 100 confirmations.
///
/// `n == 3` and `n == 12` return the process pad. Callers that connect
/// or disconnect take [`copy_maturity_pad`] and leave this store in place.
fn pad_cbs(n: u32) -> (std::path::PathBuf, Arc<Query>, Vec<Txid>) {
    if n == 3 || n == 12 {
        let p = maturity_pad(n);
        return (p.dir.clone(), Arc::clone(&p.q), p.cbs.clone());
    }
    let p = build_maturity_pad(n);
    (p.dir, p.q, p.cbs)
}

struct MaturityPad {
    dir: std::path::PathBuf,
    q: Arc<Query>,
    cbs: Vec<Txid>,
}

fn maturity_pad(n: u32) -> &'static MaturityPad {
    use std::sync::OnceLock;
    static PAD3: OnceLock<MaturityPad> = OnceLock::new();
    static PAD12: OnceLock<MaturityPad> = OnceLock::new();
    match n {
        3 => PAD3.get_or_init(|| build_maturity_pad(3)),
        12 => PAD12.get_or_init(|| build_maturity_pad(12)),
        _ => panic!("maturity pad {n} is built per test"),
    }
}

fn build_maturity_pad(n: u32) -> MaturityPad {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;
    let dir = tmp();
    let q = Query::open_or_create_tiny(&dir).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let last = n + params.coinbase_maturity();
    let (_tip, _t, cbs) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        last,
        n,
    );
    assert_eq!(cbs.len(), n as usize);
    // Quiescent after init. Later tests only read this store.
    q.flush().expect("flush maturity pad");
    MaturityPad {
        dir,
        q: Arc::new(q),
        cbs,
    }
}

fn copy_maturity_pad(n: u32) -> (std::path::PathBuf, Arc<Query>, Vec<Txid>) {
    let src = maturity_pad(n);
    let dir = tmp();
    std::fs::create_dir_all(&dir).unwrap();
    copy_store_tree(&src.dir, &dir);
    let q = Query::open_or_create_tiny(&dir).expect("open maturity copy");
    (dir, Arc::new(q), src.cbs.clone())
}

fn copy_store_tree(src: &std::path::Path, dst: &std::path::Path) {
    rbitcoin_store::testutil::copy_store_tree(src, dst);
}

#[test]
fn submit_package_rpc_admits_cpfp_below_minrelay() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x51]));
    assert!(
        matches!(
            hub.accept_tx(&parent),
            Err(AcceptError::Policy("min relay fee"))
        ),
        "parent must fail min-relay alone"
    );
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1 - 50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x63]),
        }],
    };
    let unpaid = Transaction {
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x63]),
        }],
        ..child.clone()
    };
    let missed = hub.submit_package_rpc(&[parent.clone(), unpaid]);
    assert!(
        missed.iter().all(|r| r.fee_with.is_none()),
        "a remainder that does not land has no package feerate set, got {missed:?}"
    );
    assert!(!hub.try_contains(&parent.compute_txid()));
    let held = hub.submit_package_rpc_eval(&[parent.clone(), child.clone()], false);
    assert!(
        held[0].result.is_err(),
        "package_eval off must keep the individual min-relay failure"
    );
    assert!(
        held.iter().all(|r| r.fee_with.is_none()),
        "a disabled package eval has no effective-feerate set"
    );
    assert!(!hub.try_contains(&parent.compute_txid()));
    let rows = hub.submit_package_rpc(&[parent.clone(), child.clone()]);
    assert!(
        rows.iter().all(|r| r.result.is_ok()),
        "below-min-relay parent + paying child must admit, got {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|r| r.fee_with.as_ref().is_some_and(|ids| ids.len() == 2)),
        "package-eval remainder is the effective-feerate set, got {rows:?}"
    );
    assert!(hub.try_contains(&parent.compute_txid()));
    assert!(hub.try_contains(&child.compute_txid()));

    // Child also spends a parent already in the mempool. The package
    // remainder is only the under-fee parent plus the child.
    let sponsor = spend_true(cbs[1], 10_000, ScriptBuf::from_bytes(vec![0x51]));
    assert!(hub.accept_tx(&sponsor).is_ok());
    let poor = spend_true(cbs[2], 1, ScriptBuf::from_bytes(vec![0x51]));
    assert!(matches!(
        hub.accept_tx(&poor),
        Err(AcceptError::Policy("min relay fee"))
    ));
    let in_val = (50_0000_0000 - 10_000) + (50_0000_0000 - 1);
    let sponsored = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: poor.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: sponsor.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(in_val - 50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x63]),
        }],
    };
    let rows = hub.submit_package_rpc(&[poor.clone(), sponsored.clone()]);
    assert!(
        rows.iter().all(|r| r.result.is_ok()),
        "in-mempool sponsor must not hide the CPFP remainder, got {rows:?}"
    );
    assert!(hub.try_contains(&poor.compute_txid()));
    assert!(hub.try_contains(&sponsored.compute_txid()));
    // Package-eval members must join the same relay-age log as an
    // individual admit, or an inbound peer never INV them (`mempool_limit.py`).
    let at = hub
        .accept_time(&poor.compute_wtxid())
        .expect("package-admitted parent has an accept time");
    assert!(hub.accept_time(&sponsored.compute_wtxid()).is_some());
    assert!(!hub.tx_inv_due(&poor.compute_wtxid()));
    hub.note_mock_now(at.saturating_add(30));
    assert!(hub.tx_inv_due(&poor.compute_wtxid()));
    assert!(hub.tx_inv_due(&sponsored.compute_wtxid()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A commit that evicts and then returns `mempool full` has already raised
/// the rolling floor. The published atomic is what peers and Electrum read.
#[test]
fn failed_commit_publishes_raised_fee_floor() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    for package in [false, true] {
        let dir = tmp();
        let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), 50_000).unwrap();
        hub.set_relay_enabled(true);
        // 520-byte pushes stay within the script element cap. Nineteen of
        // them plus a small child exceed a 50_000 WU budget; the parent
        // script is still spendable with an empty signature.
        let mut fat = Vec::with_capacity(10_000);
        for _ in 0..19 {
            fat.push(0x4d);
            fat.extend_from_slice(&520u16.to_le_bytes());
            fat.extend(std::iter::repeat_n(0u8, 520));
            fat.push(0x75);
        }
        fat.push(0x51);
        let parent = spend_true(cbs[0], 100_000, ScriptBuf::from_bytes(fat));
        assert!(
            hub.accept_tx(&parent).is_ok(),
            "package={package}: parent must fit"
        );
        let advertised = hub.fee_floor_sat_kvb();
        let child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 100_000 - 200_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51; 9_000]),
            }],
        };
        let err = if package {
            hub.accept_package(std::slice::from_ref(&child)).map(|_| ())
        } else {
            hub.accept_tx(&child).map(|_| ())
        };
        assert!(
            matches!(err, Err(AcceptError::Policy("mempool full"))),
            "package={package}: child must be evicted with its parent, got {err:?}"
        );
        assert!(!hub.try_contains(&child.compute_txid()));
        assert!(
            !hub.try_contains(&parent.compute_txid()),
            "package={package}: parent chunk must have been evicted"
        );
        let enforced = hub.lock_read().mempool_min_fee_sat_kvb();
        assert!(
            enforced > advertised,
            "package={package}: eviction must raise the floor ({advertised} -> {enforced})"
        );
        assert_eq!(
            hub.fee_floor_sat_kvb(),
            enforced,
            "package={package}: failed commit must publish the raised floor, still {advertised}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A package whose child is evicted with the low-fee anchor must not drop
/// the conflict the replacement removed. The replacement does not spend
/// the anchor: that input is not a parent of the conflict.
#[test]
fn failed_replacement_keeps_the_conflict() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let mut fat = Vec::with_capacity(5_000);
    for _ in 0..9 {
        fat.push(0x4d);
        fat.extend_from_slice(&520u16.to_le_bytes());
        fat.extend(std::iter::repeat_n(0u8, 520));
        fat.push(0x75);
    }
    fat.push(0x51);
    let anchor = spend_true(cbs[0], 2_000, ScriptBuf::from_bytes(fat));
    let victim = spend_true(cbs[1], 3_000, ScriptBuf::from_bytes(vec![0x51]));
    let victim_id = victim.compute_txid();
    let anchor_wu = anchor.weight().to_wu();
    let budget = anchor_wu + victim.weight().to_wu() + 500;
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), budget).unwrap();
    hub.set_relay_enabled(true);
    assert!(hub.accept_tx(&anchor).is_ok(), "anchor fits");
    assert!(hub.accept_tx(&victim).is_ok(), "victim fits");
    let [replacement, child] = package_evicted_with_anchor(&anchor, cbs[1], 60_000, 50_000, budget);
    let replacement_id = replacement.compute_txid();
    let err = hub.accept_package(&[replacement, child]).map(|_| ());
    assert!(
        matches!(err, Err(AcceptError::Policy("mempool full"))),
        "replacement must not stay, got {err:?}"
    );
    assert!(!hub.contains(&replacement_id));
    assert!(
        hub.contains(&victim_id),
        "failed replacement must keep the conflict"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict restored after a failed replacement keeps its accept time
/// in RAM and on disk, so a restart moves neither `getmempoolentry.time`
/// nor its expiry.
#[test]
fn failed_replacement_restore_keeps_accept_time_across_restart() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let mut fat = Vec::with_capacity(5_000);
    for _ in 0..9 {
        fat.push(0x4d);
        fat.extend_from_slice(&520u16.to_le_bytes());
        fat.extend(std::iter::repeat_n(0u8, 520));
        fat.push(0x75);
    }
    fat.push(0x51);
    let anchor = spend_true(cbs[0], 2_000, ScriptBuf::from_bytes(fat));
    let victim = spend_true(cbs[1], 3_000, ScriptBuf::from_bytes(vec![0x51]));
    let victim_id = victim.compute_txid();
    let budget = anchor.weight().to_wu() + victim.weight().to_wu() + 500;
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), budget).unwrap();
    hub.set_relay_enabled(true);
    let t0 = 1_700_000_000u64;
    hub.note_mock_now(t0);
    hub.accept_tx(&anchor).expect("anchor fits");
    hub.accept_tx(&victim).expect("victim fits");
    hub.note_mock_now(t0 + 600);
    let [replacement, child] = package_evicted_with_anchor(&anchor, cbs[1], 60_000, 50_000, budget);
    let err = hub.accept_package(&[replacement, child]).map(|_| ());
    assert!(
        matches!(err, Err(AcceptError::Policy("mempool full"))),
        "got {err:?}"
    );
    assert!(hub.contains(&victim_id), "restored");
    assert_eq!(
        hub.accept_time_txid(&victim_id),
        Some(t0),
        "RAM keeps the original accept time"
    );
    hub.flush().expect("shutdown flush");
    drop(hub);
    let hub2 = MempoolHub::open_with_weight(&dir, Arc::clone(q), budget).unwrap();
    assert!(hub2.contains(&victim_id), "reloaded");
    assert_eq!(
        hub2.accept_time_txid(&victim_id),
        Some(t0),
        "disk keeps the original accept time"
    );
    hub2.set_expiry_hours(1);
    hub2.note_mock_now(t0 + 3600 + 5);
    assert!(
        hub2.expire_stale() >= 1,
        "expiry counts from the original accept"
    );
    assert!(!hub2.contains(&victim_id));
    drop(hub2);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict cheaper than the chunk the failed attempt evicted must stay,
/// and must not be recent-rejected.
#[test]
fn failed_replacement_keeps_below_floor_victim() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    // Cheap anchor so the package child is not its own protected chunk.
    let anchor_spk = cheap_anchor_script();
    let anchor_wu = spend_true(cbs[0], 0, anchor_spk.clone()).weight().to_wu();
    let victim_wu = spend_true(cbs[1], 0, spk.clone()).weight().to_wu();
    let budget = anchor_wu + victim_wu + 500;
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), budget).unwrap();
    hub.set_relay_enabled(true);
    let floor = hub.lock_read().mempool_min_fee_sat_kvb();
    let anchor = spend_true(cbs[0], fee_at_least(anchor_wu, floor), anchor_spk);
    let victim_fee = fee_at_least(victim_wu, floor);
    let victim = spend_true(cbs[1], victim_fee, spk.clone());
    let victim_id = victim.compute_txid();
    let victim_rate = rbitcoin_consensus::policy::fee_rate_sat_per_kvb(victim_fee, victim_wu);
    assert!(hub.accept_tx(&anchor).is_ok(), "anchor fits");
    assert!(
        hub.accept_tx(&victim).is_ok(),
        "victim at the pre-eviction floor fits, fee {victim_fee} floor {floor}"
    );
    let [replacement, child] = package_evicted_with_anchor(&anchor, cbs[1], 80_000, 50_000, budget);
    let replacement_id = replacement.compute_txid();
    let err = hub.accept_package(&[replacement, child]).map(|_| ());
    assert!(
        matches!(err, Err(AcceptError::Policy("mempool full"))),
        "replacement must not stay, got {err:?}"
    );
    let enforced = hub.lock_read().mempool_min_fee_sat_kvb();
    assert!(
        enforced > victim_rate,
        "eviction must price out the victim ({victim_rate} vs {enforced})"
    );
    assert!(!hub.contains(&replacement_id));
    assert!(hub.contains(&victim_id), "below-floor conflict must stay");
    assert!(
        !hub.try_recent_reject(&victim.compute_wtxid()),
        "restored conflict must not be recent-rejected"
    );
    assert_eq!(hub.orphan_count(), 0);
    assert!(
        hub.wtxid_by_txid.lock().unwrap().contains_key(&victim_id),
        "relay map must still name the conflict"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A conflict set that was only valid as CPFP (parent under min relay,
/// child paying) must come back ancestor-first, not as an orphan.
#[test]
fn failed_replacement_keeps_cpfp_conflict_set() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let anchor_spk = cheap_anchor_script();
    let anchor_wu = spend_true(cbs[0], 0, anchor_spk.clone()).weight().to_wu();
    let (parent, paying) = cpfp_child_sorts_first(cbs[1], &spk);
    assert!(
        paying.compute_txid() < parent.compute_txid(),
        "child txid must sort first so txid order is not ancestor order"
    );
    let parent_id = parent.compute_txid();
    let paying_id = paying.compute_txid();
    let budget = anchor_wu + parent.weight().to_wu() + paying.weight().to_wu() + 500;
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), budget).unwrap();
    hub.set_relay_enabled(true);
    let floor = hub.lock_read().mempool_min_fee_sat_kvb();
    let anchor = spend_true(cbs[0], fee_at_least(anchor_wu, floor), anchor_spk);
    assert!(hub.accept_tx(&anchor).is_ok(), "anchor fits");
    hub.accept_package(&[parent.clone(), paying.clone()])
        .expect("CPFP package admits a below-min-relay parent");
    assert!(hub.contains(&parent_id));
    assert!(hub.contains(&paying_id));
    let [replacement, child] = package_evicted_with_anchor(&anchor, cbs[1], 80_000, 50_000, budget);
    let replacement_id = replacement.compute_txid();
    let err = hub.accept_package(&[replacement, child]).map(|_| ());
    assert!(
        matches!(err, Err(AcceptError::Policy("mempool full"))),
        "replacement must not stay, got {err:?}"
    );
    assert!(!hub.contains(&replacement_id));
    assert!(hub.contains(&parent_id), "below-min-relay parent must stay");
    assert!(hub.contains(&paying_id), "paying child must stay");
    assert_eq!(
        hub.orphan_count(),
        0,
        "child must not be parked waiting on its parent"
    );
    assert!(!hub.try_recent_reject(&parent.compute_wtxid()));
    assert!(!hub.try_recent_reject(&paying.compute_wtxid()));
    let maps = hub.wtxid_by_txid.lock().unwrap();
    assert!(maps.contains_key(&parent_id));
    assert!(maps.contains_key(&paying_id));
    drop(maps);
    let _ = std::fs::remove_dir_all(&dir);
}

fn cheap_anchor_script() -> ScriptBuf {
    let mut fat = Vec::new();
    for _ in 0..6 {
        fat.push(0x4d);
        fat.extend_from_slice(&520u16.to_le_bytes());
        fat.extend(std::iter::repeat_n(0u8, 520));
        fat.push(0x75);
    }
    fat.push(0x51);
    ScriptBuf::from_bytes(fat)
}

fn fee_at_least(weight: u64, sat_kvb: u64) -> u64 {
    let vsize = weight.div_ceil(4);
    vsize.saturating_mul(sat_kvb).div_ceil(1000).max(1)
}

/// `[replacement, child]`. The replacement spends only the confirmed
/// conflict. The child also spends `anchor`, so evicting that anchor drops
/// the child once their weight exceeds `budget`.
fn package_evicted_with_anchor(
    anchor: &Transaction,
    conflict: Txid,
    repl_fee: u64,
    child_fee: u64,
    budget: u64,
) -> [Transaction; 2] {
    let replacement = spend_true(conflict, repl_fee, ScriptBuf::from_bytes(vec![0x51]));
    let held = anchor.weight().to_wu() + replacement.weight().to_wu();
    assert!(
        held <= budget,
        "replacement must fit beside the anchor ({held} > {budget})"
    );
    let input_value = replacement.output[0].value.to_sat() + anchor.output[0].value.to_sat();
    let child = heavier_than(
        OutPoint {
            txid: replacement.compute_txid(),
            vout: 0,
        },
        OutPoint {
            txid: anchor.compute_txid(),
            vout: 0,
        },
        input_value - child_fee,
        budget - held,
    );
    [replacement, child]
}

fn heavier_than(a: OutPoint, b: OutPoint, value: u64, min_wu: u64) -> Transaction {
    let mut n = 64usize;
    loop {
        let tx = two_in_one_out(a, b, value, ScriptBuf::from_bytes(vec![0x51; n]));
        if tx.weight().to_wu() > min_wu {
            return tx;
        }
        n += 32;
        assert!(n < 20_000, "replacement never exceeded the slack");
    }
}

fn two_in_one_out(a: OutPoint, b: OutPoint, value: u64, spk: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: a,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: b,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk,
        }],
    }
}

/// Parent fee is 1 sat. Child txid sorts before the parent.
fn cpfp_child_sorts_first(coin: Txid, spk: &ScriptBuf) -> (Transaction, Transaction) {
    for n in 0..10_000u32 {
        let mut parent = spend_true(coin, 1, spk.clone());
        parent.lock_time = LockTime::from_consensus(n);
        let child = spend_vout(
            OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            parent.output[0].value.to_sat() - 40_000,
        );
        if child.compute_txid() < parent.compute_txid() {
            return (parent, child);
        }
    }
    panic!("no locktime put the child txid first");
}

#[test]
fn submit_package_rpc_cpf_ps_parent_under_mempool_min_fee() {
    let (_store, owned_q, owned_cbs) = pad_cbs(4);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let dir = tmp();
    // One ~36kWU output fits; the second forces eviction and raises the floor.
    let hub = MempoolHub::open_with_weight(&dir, Arc::clone(q), 50_000).unwrap();
    hub.set_relay_enabled(true);
    let heavy = ScriptBuf::from_bytes(vec![0x51; 9_000]);
    let filler = spend_true(cbs[0], 100_000, heavy.clone());
    let bumper = spend_true(cbs[1], 200_000, heavy);
    assert!(
        hub.accept_tx(&filler).is_ok(),
        "filler must enter before the pool is over budget"
    );
    assert!(
        hub.accept_tx(&bumper).is_ok(),
        "higher-fee bumper must evict the filler"
    );
    assert!(
        !hub.try_contains(&filler.compute_txid()),
        "filler must have been evicted"
    );
    let floor = hub.mempool_min_fee_sat_kvb();
    assert!(
        floor > rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB,
        "eviction must raise the dynamic floor, got {floor}"
    );
    let parent = spend_true(cbs[2], 500, ScriptBuf::from_bytes(vec![0x51]));
    assert!(
        matches!(
            hub.accept_tx(&parent),
            Err(AcceptError::Policy("mempool min fee"))
        ),
        "parent clears static min relay and fails the dynamic floor, got {:?}",
        hub.accept_tx(&parent)
    );
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 500 - 50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x63]),
        }],
    };
    let rows = hub.submit_package_rpc(&[parent.clone(), child.clone()]);
    assert!(
        rows.iter().all(|r| r.result.is_ok()),
        "dynamic-floor parent + paying child must admit, got {rows:?}"
    );
    assert!(hub.try_contains(&parent.compute_txid()));
    assert!(hub.try_contains(&child.compute_txid()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A 1p1c admit inside the block-connect walk must also release orphans
/// that wait only on the packaged parent.
#[test]
fn package_inside_promote_admits_parent_orphans() {
    use rbitcoin_consensus::{mine_regtest_paying, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_query::accept_and_connect_block;

    let (store, q, cbs) = copy_maturity_pad(3);
    let params = ChainParams::regtest();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let half = (50_0000_0000 - 1) / 2;
    let low_parent = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(half),
                script_pubkey: spk.clone(),
            },
            TxOut {
                value: Amount::from_sat(50_0000_0000 - 1 - half),
                script_pubkey: spk.clone(),
            },
        ],
    };
    assert!(
        hub.try_note_extra_compact(&low_parent),
        "low parent is remembered for 1p1c and is not in the mempool"
    );
    assert!(!hub.try_contains(&low_parent.compute_txid()));
    let sibling = spend_vout(
        OutPoint {
            txid: low_parent.compute_txid(),
            vout: 1,
        },
        50_0000_0000 - 1 - half - 20_000,
    );
    let err = hub
        .accept_tx_from(&sibling, TxOrigin::Relay(Some(1)))
        .unwrap_err();
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "sibling waits on the low parent, got {err:?}"
    );
    let conf = spend_true(cbs[1], 10_000, spk.clone());
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: conf.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: low_parent.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 10_000 + half - 40_000),
            script_pubkey: spk.clone(),
        }],
    };
    let err = hub
        .accept_tx_from(&child, TxOrigin::Relay(Some(1)))
        .unwrap_err();
    assert!(
        matches!(err, AcceptError::Orphaned { .. }),
        "child waits on the confirmed parent and the low parent, got {err:?}"
    );
    let tip_h = q.tip_height().unwrap().0;
    let fk = q.tip_header_fk().unwrap().unwrap();
    let rec = q.get_header(fk).unwrap();
    let prev = bitcoin::BlockHash::from_byte_array(rec.hash);
    let block = mine_regtest_paying(
        prev,
        rec.timestamp + 600,
        tip_h + 1,
        spk,
        vec![conf.clone()],
    );
    accept_and_connect_block(&q, &params, Height(tip_h + 1), &block, Milestone::NONE)
        .expect("connect the chain parent");
    rbitcoin_net::tx_relay::reset_promote_depth();
    hub.remove_for_block(&[conf.compute_txid()]);
    assert!(
        hub.contains(&low_parent.compute_txid()),
        "1p1c inside the walk must admit the low parent"
    );
    assert!(hub.contains(&child.compute_txid()));
    assert!(
        hub.contains(&sibling.compute_txid()),
        "orphans of the packaged parent must be admitted in the same walk"
    );
    assert_eq!(hub.orphan_count(), 0);
    assert_eq!(rbitcoin_net::tx_relay::promote_depth_max(), 1);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store);
}

/// A parked chain admits when the root does, on one promote frame.
#[test]
fn parked_chain_promotes_in_one_frame() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mut value = 50_0000_0000 - 10_000;
    let root = spend_true(cbs[0], 10_000, spk.clone());
    let mut parent = root.compute_txid();
    let mut parked = Vec::new();
    for _ in 0..4 {
        value -= 1_000;
        let child = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: spk.clone(),
            }],
        };
        parent = child.compute_txid();
        parked.push(child);
    }
    for child in parked.iter().rev() {
        let err = hub.accept_tx(child).unwrap_err();
        assert!(
            matches!(err, AcceptError::Orphaned { .. }),
            "link must park, got {err:?}"
        );
    }
    assert_eq!(hub.orphan_count(), parked.len());
    rbitcoin_net::tx_relay::reset_promote_depth();
    hub.accept_tx(&root).expect("root admits the parked chain");
    assert_eq!(hub.orphan_count(), 0);
    assert!(hub.try_contains(&root.compute_txid()));
    for child in &parked {
        assert!(
            hub.try_contains(&child.compute_txid()),
            "descendant must be live"
        );
    }
    assert_eq!(
        rbitcoin_net::tx_relay::promote_depth_max(),
        1,
        "the hub walk must not take a frame per descendant"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mempool_under_pressure() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x51]));
    assert!(matches!(
        hub.accept_tx(&parent),
        Err(AcceptError::Policy("min relay fee"))
    ));
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1 - 50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub.accept_tx_from(&child, TxOrigin::Relay(Some(7)));
    assert!(
        matches!(err, Err(AcceptError::Orphaned { .. })),
        "P2P child of min-relay parent must orphan, got {err:?}"
    );
    assert!(!hub.contains(&child.compute_txid()));
    assert_eq!(hub.orphan_count(), 1);
    let parked = hub.orphan_count();

    let heavy = spend_true(cbs[0], 1, ScriptBuf::from_bytes(vec![0x6a; 110_000]));
    assert!(matches!(
        hub.accept_tx(&heavy),
        Err(AcceptError::Policy("tx weight"))
    ));
    assert_eq!(
        heavy.compute_txid().to_byte_array(),
        heavy.compute_wtxid().to_byte_array()
    );
    assert!(hub.try_recent_reject(&heavy.compute_wtxid()));
    let other = Txid::from_byte_array([0x33; 32]);
    let rejected_child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: heavy.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: other,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(40),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let child_err = hub.accept_tx(&rejected_child);
    assert!(
        matches!(child_err, Err(AcceptError::Orphaned { .. })),
        "missing inputs still orphaned, got {child_err:?}"
    );
    assert_eq!(
        hub.orphan_count(),
        parked,
        "known-invalid parent must not park child"
    );
    let grandchild = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: rejected_child.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(30),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let _ = hub.accept_tx(&grandchild);
    assert_eq!(
        hub.orphan_count(),
        parked,
        "child of rejected parent must poison descendants"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn accept_package_child_fail_restores_rbf_victims() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let low = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: spk.clone(),
        }],
    };
    let low_id = low.compute_txid();
    hub.accept_tx(&low).expect("low fee live");
    let high = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_0000_0000),
            script_pubkey: spk.clone(),
        }],
    };
    let high_id = high.compute_txid();
    let mut bad_child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: high_id,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: spk,
        }],
    };
    bad_child.input[0].witness = Witness::from_slice(&[vec![0x01], vec![0x50, 0x01]]);
    let err = hub
        .accept_package(&[high, bad_child])
        .expect_err("annex child must fail");
    assert!(
        matches!(err, AcceptError::Policy("libre annex")),
        "got {err}"
    );
    assert!(!hub.contains(&high_id));
    assert!(
        hub.contains(&low_id),
        "hub package rollback must restore the RBF victim"
    );
    let _ = std::fs::remove_dir_all(&mp);
}

#[test]
fn query_utxo_provider_miss_is_none() {
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let provider = QueryUtxoProvider::new(&q);
    let op = OutPoint {
        txid: Txid::from_byte_array([0xcd; 32]),
        vout: 0,
    };
    assert!(provider.get_txout(&op).is_none());
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn estimate_fee_percentiles_and_spent_outpoints_empty() {
    let dir = tmp();
    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&dir, Arc::new(q)).unwrap();
    assert!(hub.estimate_fee_btc_per_kb(1) < 0.0);
    assert!(hub.estimate_fee_btc_per_kb(5) < 0.0);
    assert!(hub.estimate_fee_btc_per_kb(100) < 0.0);
    assert!(hub.spent_outpoints().is_empty());
    assert!(!hub.contains(&Txid::from_byte_array([0u8; 32])));
    assert!(hub.get_tx(&Txid::from_byte_array([0u8; 32])).is_none());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Concurrent read APIs do not deadlock under RwLock (C2).
#[test]
fn concurrent_estimate_and_list_reads() {
    use std::thread;

    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let h = Arc::clone(&hub);
        handles.push(thread::spawn(move || {
            for _ in 0..32 {
                let _ = h.live_count();
                let _ = h.estimate_fee_btc_per_kb(2);
                let _ = h.fee_estimates_btc_per_kb();
                let _ = h.fee_histogram();
                let _ = h.list_live();
                let _ = h.contains_wtxid(&Wtxid::from_byte_array([0u8; 32]));
            }
        }));
    }
    for h in handles {
        h.join().expect("reader");
    }
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Fee snapshot covers Esplora depths; request path uses published table.
#[test]
fn fee_snapshot_bulk_and_estimate_share_table() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    // Empty pool: negative / unavailable for Electrum-style single target.
    assert!(hub.estimate_fee_btc_per_kb(2) < 0.0);
    assert!(hub.estimate_fee_btc_per_kb(12) < 0.0);
    assert!(hub.fee_estimates_btc_per_kb().is_empty());
    assert!(hub.fee_estimates_btc_per_kb().is_empty());
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn fee_history_preload_reuses_heights_it_already_holds() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::accept_and_connect_block;

    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        5,
        0,
    );
    let mp_dir = tmp();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();

    let first = hub.backfill_block_fee_history();
    assert_eq!(first.tip_height, Some(5));
    assert_eq!(first.heights_scanned, 6);
    assert_eq!(first.retained_heights, 0);
    assert_eq!(first.txstat_bytes, 6 * 8, "one coinbase cell per block");
    assert!(first.history_exhausted);

    let again = hub.backfill_block_fee_history();
    assert_eq!(again.heights_scanned, 6);
    assert_eq!(again.retained_heights, 6, "held heights are not reread");
    assert_eq!(again.txstat_bytes, first.txstat_bytes);
    assert_eq!(again.skipped_heights, first.skipped_heights);
    assert!(again.history_exhausted);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn fee_history_without_a_chain_is_exhausted_without_a_scan() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();

    let stats = hub.backfill_block_fee_history();

    assert_eq!(stats.tip_height, None);
    assert_eq!(stats.heights_scanned, 0);
    assert_eq!(stats.txstat_bytes, 0);
    assert!(stats.history_exhausted);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn fee_history_file_survives_a_restart_and_drops_heights_off_the_chain() {
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_query::accept_and_connect_block;

    let store_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (tip, tip_time, _) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        5,
        0,
    );
    let q = Arc::new(q);
    let mp_dir = tmp();

    let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    let first = hub.backfill_block_fee_history();
    assert_eq!((first.file_heights, first.retained_heights), (0, 0));
    assert_eq!(first.total_targets, 11);
    assert_eq!(first.ready_targets, 0);
    // a connect after the preload goes to the journal
    rbitcoin_query::pad_empty_from(&q, &params, tip, tip_time, 6, 6, 0);
    hub.note_block_fee_history(Height(6));
    let journaled = fee_history_file::load(&mp_dir).unwrap().unwrap();
    assert_eq!(
        journaled.journal.len(),
        1,
        "one connect stays in the journal until {COMPACT} connects",
        COMPACT = fee_history_file::COMPACT_EVERY
    );
    for _ in 1..fee_history_file::COMPACT_EVERY {
        hub.note_block_fee_history(Height(6));
    }
    let compacted = fee_history_file::load(&mp_dir).unwrap().unwrap();
    assert!(
        compacted.journal.is_empty(),
        "144 connects rewrite the snapshot and start an empty journal"
    );
    drop(hub);

    let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    let restart = hub.backfill_block_fee_history();
    assert_eq!(restart.file_heights, 7, "snapshot 0..=5 plus journal 6");
    assert_eq!(restart.retained_heights, 7, "no height read from the chain");
    assert_eq!(restart.txstat_bytes, 7 * 8);
    drop(hub);

    // A journal record for a block the chain does not have (a reorg while
    // down) is dropped with everything above the newest hash on the chain.
    let mut journal = std::fs::OpenOptions::new()
        .append(true)
        .open(mp_dir.join("fee_history.log"))
        .unwrap();
    let orphan = HistoricalFeeBlock {
        p10_sat_kvb: Some(5_000),
        txstat_bytes: 8,
    };
    fee_history_file::append(&mut journal, 7, &orphan, &[9u8; 32]).unwrap();
    drop(journal);
    let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    let reorged = hub.backfill_block_fee_history();
    assert_eq!(reorged.file_heights, 7);
    assert_eq!(hub.block_p10_history.lock().unwrap().get(7), None);
    drop(hub);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn far_horizon_follows_block_history_not_pool_tail() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    // Too few pairs for any target: no estimate rather than a guess.
    for height in 1..=100 {
        record_fee_sample(&hub, height, 2_000);
    }
    hub.mark_fee_dirty();
    assert!(
        hub.fee_estimates_btc_per_kb().is_empty(),
        "{:?}",
        hub.fee_estimates_btc_per_kb()
    );
    // 2000 pairs for 1008 blocks: 2000 + 144 lookback + 1008 - 1 hurdles.
    for height in 101..=3_200 {
        record_fee_sample(&hub, height, 2_000);
    }
    hub.mark_fee_dirty();
    let bulk = hub.fee_estimates_btc_per_kb();
    let sat = |pairs: &[(u32, f64)], d: u32| {
        pairs
            .iter()
            .find(|(k, _)| *k == d)
            .map(|(_, v)| (*v * 100_000.0).round())
            .unwrap()
    };
    let s1 = sat(&bulk, 1);
    let s144 = sat(&bulk, 144);
    let s504 = sat(&bulk, 504);
    let s1008 = sat(&bulk, 1008);
    assert!(s1 > 0.0, "1 must fall back to history, not empty-pool -1");
    assert!(s144 > 0.0, "144 must use history, not empty-pool -1");
    assert!(s504 > 0.0, "504 must use history, not empty-pool -1");
    assert!(s1008 > 0.0, "1008 must use history, not empty-pool -1");
    assert!(s144 <= s1 + 0.05, "monotone far={s144} near={s1}");
    assert!(s504 <= s144 + 0.05, "monotone 504={s504} 144={s144}");
    let keys: Vec<u32> = bulk.iter().map(|(d, _)| *d).collect();
    let esplora: Vec<u32> = (1..=25).chain([144, 504, 1008]).collect();
    assert_eq!(keys, esplora, "published targets: {keys:?}");
    let knot_sat = |depth: u32| {
        bulk.iter()
            .find(|(d, _)| *d == depth)
            .map(|(_, btc)| (btc * 100_000_000.0).round() as u64)
    };
    let rates: Vec<Option<u64>> = FEE_SNAPSHOT_DEPTHS.iter().copied().map(knot_sat).collect();
    assert!(
        rates.iter().all(Option::is_some),
        "history should define every computed depth via hold: {rates:?}"
    );
    for target in [12u32, 25, 100] {
        let expect =
            fee_at_target_sat_kvb(FEE_SNAPSHOT_DEPTHS, &rates, target).expect("off-knot target");
        let got = hub.estimate_fee_btc_per_kb(target);
        assert!(got >= 0.0, "target {target} insufficient");
        assert_eq!(
            (got * 100_000_000.0).round() as u64,
            expect,
            "target {target}"
        );
    }
    for i in 0..20u32 {
        record_fee_sample(&hub, 3_201 + i, 1_000 + u64::from(i) * 100);
    }
    hub.mark_fee_dirty();
    let bulk = hub.fee_estimates_btc_per_kb();
    let s1 = sat(&bulk, 1);
    let s6 = sat(&bulk, 6);
    let s144 = sat(&bulk, 144);
    assert!(s1 > 0.0 && s6 > 0.0 && s144 > 0.0);
    assert!(
        s1 >= s6 && s6 >= s144,
        "target rates monotone sat/vB n1={s1} n6={s6} n144={s144}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);

    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    for height in 1..=3_200 {
        record_fee_sample(&hub, height, 1);
    }
    hub.mark_fee_dirty();
    let bulk = hub.fee_estimates_btc_per_kb();
    let v144 = bulk
        .iter()
        .find(|(k, _)| *k == 144)
        .map(|(_, v)| *v)
        .unwrap();
    let min_btc = MempoolHub::relay_fee_btc_per_kb();
    assert!(
        v144 + 1e-12 >= min_btc,
        "hist below min-relay must clamp: {v144} min={min_btc}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Electrum `estimatefee` and Esplora `/fee-estimates` read these rates.
/// They quote at least the floor this pool admits at, as soon as it rises.
#[test]
fn fee_estimates_follow_the_admission_floor() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    for height in 1..=2_100 {
        record_fee_sample(&hub, height, 2_000);
    }
    hub.mark_fee_dirty();
    let sat = |btc: f64| (btc * 100_000_000.0).round() as u64;
    assert_eq!(sat(hub.estimate_fee_btc_per_kb(2)), 2_000);
    // A refresh already in flight leaves other requests on the old table.
    hub.fee_refreshing.store(true, Ordering::Release);
    hub.set_min_relay_sat_kvb(5_000);
    assert_eq!(hub.mempool_min_fee_sat_kvb(), 5_000);
    assert_eq!(sat(hub.estimate_fee_btc_per_kb(2)), 5_000);
    let bulk = hub.fee_estimates_btc_per_kb();
    assert_eq!(bulk.len(), 28, "{bulk:?}");
    assert!(bulk.iter().all(|&(_, btc)| sat(btc) == 5_000), "{bulk:?}");
    hub.fee_refreshing.store(false, Ordering::Release);
    hub.mark_fee_dirty();
    assert_eq!(sat(hub.estimate_fee_btc_per_kb(2)), 5_000);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// A package whose child fails after its parent replaced a conflict puts
/// that conflict back, and the pool is near full again. Estimates quote the
/// floor the restored pool enforces.
#[test]
fn fee_estimates_follow_the_floor_after_a_package_rollback() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open_with_weight(&dir, q, 420_000).unwrap();
    hub.set_relay_enabled(true);
    for height in 1..=2_100 {
        record_fee_sample(&hub, height, 150);
    }
    let victim = spend_true(cbs[0], 10_000, ScriptBuf::from_bytes(vec![0x51; 9_000]));
    hub.accept_tx(&victim).expect("victim");
    let near_full = hub.lock_read().mempool_min_fee_sat_kvb();
    assert!(near_full > 150, "near-full floor {near_full}");
    let replacement = spend_true(cbs[0], 20_000, ScriptBuf::from_bytes(vec![0x51]));
    let overspend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: replacement.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: replacement.output[0].value + Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    assert!(hub.accept_package(&[replacement, overspend]).is_err());
    assert!(hub.contains(&victim.compute_txid()), "rollback restores it");
    assert_eq!(hub.lock_read().mempool_min_fee_sat_kvb(), near_full);
    hub.mark_fee_dirty();
    let sat = |btc: f64| (btc * 100_000_000.0).round() as u64;
    assert_eq!(sat(hub.estimate_fee_btc_per_kb(2)), near_full);
    let bulk = hub.fee_estimates_btc_per_kb();
    assert!(
        !bulk.is_empty() && bulk.iter().all(|&(_, btc)| sat(btc) == near_full),
        "{bulk:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Arrivals priced above the flow ladder fill the next blocks at every
/// ladder rate, so flow has no price for the near targets. A pool thinner
/// than one block then quotes block history, or nothing, never min relay
/// and never the ladder top.
#[test]
fn arrivals_above_the_ladder_leave_near_targets_to_history() {
    let (_store, q, cbs) = pad_cbs(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.accept_tx(&spend_true(
        cbs[0],
        1_000,
        ScriptBuf::from_bytes(vec![0x51]),
    ))
    .expect("live stock");
    let vsize = rbitcoin_mempool::BLOCK_WEIGHT_WU / 4;
    for _ in 0..3 {
        hub.note_fee_flow_admit(rbitcoin_mempool::BLOCK_WEIGHT_WU, 2_000 * vsize);
    }
    for target in [1, 2] {
        let btc = hub.estimate_fee_btc_per_kb(target);
        assert!(btc < 0.0, "target {target} without history: {btc}");
    }
    for height in 1..=2_100 {
        record_fee_sample(&hub, height, 2_000);
    }
    hub.mark_fee_dirty();
    for target in [1, 2] {
        let sat = (hub.estimate_fee_btc_per_kb(target) * 100_000_000.0).round() as u64;
        assert_eq!(sat, 2_000, "target {target}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Fee-snapshot refresh publishes live count/vsize/total_fee (GET /mempool).
#[test]
fn fee_snapshot_live_totals_match_list_live_meta() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let mp_dir = tmp();
    let hub = MempoolHub::open(&mp_dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let a = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_tx(&a).expect("admit");
    let live = hub.list_live_meta();
    let expect_count = live.len();
    let expect_fee: u64 = live.iter().map(|(_, f, _)| *f).sum();
    let expect_vsize: u64 = live.iter().map(|(_, _, w)| w.saturating_add(3) / 4).sum();
    let (count, vsize, total_fee) = hub.mempool_live_totals();
    assert_eq!(count, expect_count);
    assert_eq!(vsize, expect_vsize);
    assert_eq!(total_fee, expect_fee);
    assert!(expect_count >= 1);
    assert!(expect_fee > 0);
    // Electrum histogram buckets are raw vsize, summing to GET /mempool vsize.
    let hist_vsize: u64 = hub.fee_histogram().iter().map(|(_, v)| v).sum();
    assert_eq!(hist_vsize, expect_vsize);
    // getmempoolinfo totals: a plain spend's adjusted vsize is its raw vsize.
    assert_eq!(
        hub.live_adjusted_totals(),
        (expect_count, expect_vsize, expect_fee)
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn accept_tx_async_runs_off_reactor() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let r = hub.accept_tx_from_async(tx, TxOrigin::Relay(None)).await;
    assert!(
        matches!(
            r,
            Err(AcceptError::Orphaned { .. }) | Err(AcceptError::MissingPrevout(_))
        ),
        "async accept off reactor: {r:?}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn try_contains_does_not_panic_on_tokio_worker() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let miss = Txid::from_byte_array([0u8; 32]);
    let join = tokio::spawn(async move {
        let name = std::thread::current().name().unwrap_or("").to_string();
        let hit = hub.try_contains(&miss);
        (name, hit)
    });
    let (name, hit) = join.await.expect("join worker");
    assert!(
        name.starts_with("tokio-rt-worker"),
        "spawned task must run on a tokio worker, got {name:?}"
    );
    assert!(!hit);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

fn parked_orphan_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

/// Handshake `unregister` runs on the reactor with an empty orphanage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erase_orphans_empty_does_not_panic_on_tokio_worker() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let join = tokio::spawn(async move {
        let name = std::thread::current().name().unwrap_or("").to_string();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hub.erase_orphans_for_peer(0);
        }));
        (name, panicked)
    });
    let (name, panicked) = join.await.expect("join worker");
    assert!(
        name.starts_with("tokio-rt-worker"),
        "spawned task must run on a tokio worker, got {name:?}"
    );
    assert!(
        panicked.is_ok(),
        "empty erase_orphans_for_peer must not take inner write on reactor: {panicked:?}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// INV of a parked orphan notes the announcer on the reactor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn add_orphan_announcer_does_not_panic_on_tokio_worker() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let tx = parked_orphan_tx();
    let err = hub
        .accept_tx_from(&tx, TxOrigin::Relay(Some(4)))
        .unwrap_err();
    assert!(matches!(err, AcceptError::Orphaned { .. }), "{err}");
    let txid = tx.compute_txid();
    let wtxid = tx.compute_wtxid();
    let join = tokio::spawn(async move {
        let name = std::thread::current().name().unwrap_or("").to_string();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(hub.add_orphan_announcer(&txid, 8));
            assert!(hub.add_orphan_announcer_wtxid(&wtxid, 9));
            hub.erase_orphans_for_peer(4);
            hub.erase_orphans_for_peer(8);
            hub.erase_orphans_for_peer(9);
        }));
        (name, panicked)
    });
    let (name, panicked) = join.await.expect("join worker");
    assert!(
        name.starts_with("tokio-rt-worker"),
        "spawned task must run on a tokio worker, got {name:?}"
    );
    assert!(
        panicked.is_ok(),
        "orphan announcer + EraseForPeer must not take blocking inner write on reactor: {panicked:?}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn min_relay_sat_kvb_does_not_panic_on_tokio_worker() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_min_relay_sat_kvb(250);
    let join = tokio::spawn(async move {
        let name = std::thread::current().name().unwrap_or("").to_string();
        let rate = hub.min_relay_sat_kvb();
        (name, rate)
    });
    let (name, rate) = join.await.expect("join worker");
    assert!(
        name.starts_with("tokio-rt-worker"),
        "spawned task must run on a tokio worker, got {name:?}"
    );
    assert_eq!(rate, 250);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebroadcast_unbroadcast_does_not_panic_on_tokio_worker() {
    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.note_unbroadcast(Txid::from_byte_array([1u8; 32]));
    let join = tokio::spawn(async move {
        let name = std::thread::current().name().unwrap_or("").to_string();
        hub.rebroadcast_unbroadcast();
        name
    });
    let name = join.await.expect("join worker");
    assert!(
        name.starts_with("tokio-rt-worker"),
        "spawned task must run on a tokio worker, got {name:?}"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// Prepare resolves coins off the write lock. A stable confirmed view
/// re-reads those coins before the commit takes the lock.
#[test]
fn accept_rechecks_confirmed_input_under_write() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    use rbitcoin_mempool::UtxoProvider;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    struct ProbeUtxo<'a> {
        hub: Arc<MempoolHub>,
        inner: QueryUtxoProvider<'a>,
        write_hits: Arc<AtomicU64>,
    }
    impl UtxoProvider for ProbeUtxo<'_> {
        fn note_spender(&self, tx: &Transaction) {
            self.inner.note_spender(tx);
        }
        fn utxo_view_stamp(&self) -> Option<u64> {
            self.inner.utxo_view_stamp()
        }
        fn get_coin(&self, op: &OutPoint) -> Option<rbitcoin_mempool::Coin> {
            let h = Arc::clone(&self.hub);
            let write_held = thread::spawn(move || h.inner.try_read().is_err())
                .join()
                .expect("probe");
            if write_held {
                self.write_hits.fetch_add(1, Ordering::Relaxed);
            }
            self.inner.get_coin(op)
        }
    }

    let mp_dir = tmp();
    let hub = MempoolHub::open(&mp_dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let hits = Arc::new(AtomicU64::new(0));
    let probe = ProbeUtxo {
        hub: Arc::clone(&hub),
        inner: QueryUtxoProvider::new(q.as_ref()),
        write_hits: Arc::clone(&hits),
    };
    let tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_with_utxo(&tx, &probe, TxOrigin::Relay(None), false, &[])
        .expect("accept");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "a stable UTXO view re-reads the confirmed input off the write lock"
    );
    hits.store(0, Ordering::Relaxed);
    let held = spend_true(cbs[1], 1_000, ScriptBuf::from_bytes(vec![0x52]));
    let _view = q.store().hold_utxo_view();
    hub.accept_with_utxo(&held, &probe, TxOrigin::Relay(None), false, &[])
        .expect("accept while the view is held");
    assert_eq!(
        hits.load(Ordering::Relaxed),
        1,
        "a held UTXO view re-reads the confirmed input under the write lock"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
}

#[test]
fn contains_wtxid_during_slow_utxo_prepare() {
    use rbitcoin_mempool::UtxoProvider;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Condvar;
    use std::thread;
    use std::time::{Duration, Instant};

    struct StallUtxo {
        entered: Arc<AtomicBool>,
        release: Arc<(Mutex<bool>, Condvar)>,
    }
    impl UtxoProvider for StallUtxo {
        fn get_coin(&self, _: &OutPoint) -> Option<rbitcoin_mempool::Coin> {
            self.entered.store(true, Ordering::Release);
            let (lock, cv) = &*self.release;
            let mut g = lock.lock().unwrap();
            while !*g {
                g = cv.wait(g).unwrap();
            }
            None
        }
    }

    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let hub = MempoolHub::open(&mp_dir, Arc::new(q)).unwrap();
    hub.set_relay_enabled(true);
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let stall = StallUtxo {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([7u8; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let h = Arc::clone(&hub);
    let join =
        thread::spawn(move || h.accept_with_utxo(&tx, &stall, TxOrigin::Relay(None), false, &[]));
    let start = Instant::now();
    while !entered.load(Ordering::Acquire) {
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "UTXO provider never entered"
        );
        thread::yield_now();
    }
    let miss = Wtxid::from_byte_array([0u8; 32]);
    let t_read = Instant::now();
    let _ = hub.contains_wtxid(&miss);
    assert!(
        t_read.elapsed() < Duration::from_millis(200),
        "contains_wtxid blocked on prepare UTXO ({:?})",
        t_read.elapsed()
    );
    {
        let (lock, cv) = &*release;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    let _ = join.join().expect("accept thread");
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

#[test]
fn mempool_tx_snapshot_two_live_and_accept_while_held() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    use std::thread;

    let mp_dir = tmp();
    let hub = MempoolHub::open(&mp_dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let a = spend_true(cbs[0], 1_000, spk.clone());
    let b = spend_true(cbs[1], 2_000, ScriptBuf::from_bytes(vec![0x52]));
    hub.accept_tx(&a).expect("a");
    hub.accept_tx(&b).expect("b");
    let snap = hub.mempool_tx_snapshot();
    assert_eq!(snap.entries().len(), 2);
    for e in snap.entries() {
        assert!(e.fee_sat > 0, "fee");
    }
    let aid = a.compute_txid();
    let bid = b.compute_txid();
    assert!(snap.get(&aid).is_some());
    assert!(snap.get(&bid).is_some());
    let _ = snap.get(&aid).unwrap().json.set("keep-a".into());
    let _ = snap.get(&bid).unwrap().json.set("keep-b".into());
    let c = spend_true(cbs[2], 3_000, ScriptBuf::from_bytes(vec![0x53]));
    let cid = c.compute_txid();
    let held = Arc::clone(&snap);
    let h2 = Arc::clone(&hub);
    let join = thread::spawn(move || h2.accept_tx(&c));
    join.join().expect("accept thread").expect("c");
    assert_eq!(held.entries().len(), 2, "held Arc is the old snapshot");
    let snap2 = hub.mempool_tx_snapshot();
    assert_eq!(snap2.entries().len(), 3);
    assert_eq!(
        snap2.get(&aid).unwrap().json.get().map(|s| s.as_ref()),
        Some("keep-a")
    );
    assert_eq!(
        snap2.get(&bid).unwrap().json.get().map(|s| s.as_ref()),
        Some("keep-b")
    );
    assert!(snap2.get(&cid).unwrap().json.get().is_none());
    let _ = std::fs::remove_dir_all(&mp_dir);
}

#[test]
fn mempool_tx_snapshot_refresh_reuses_tx_arc() {
    let (_store, owned_q, owned_cbs) = pad_cbs(3);
    let q = &owned_q;
    let cbs = owned_cbs.as_slice();
    let mp_dir = tmp();
    let hub = MempoolHub::open(&mp_dir, Arc::clone(q)).unwrap();
    hub.set_relay_enabled(true);
    let a = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    hub.accept_tx(&a).expect("a");
    let snap1 = hub.mempool_tx_snapshot();
    let aid = a.compute_txid();
    let e1 = snap1.get(&aid).expect("a in snap1");
    let _ = e1.json.set("keep-a".into());
    std::thread::sleep(Duration::from_millis(1100));
    let snap2 = hub.mempool_tx_snapshot();
    let e2 = snap2.get(&aid).expect("a in snap2");
    assert!(
        Arc::ptr_eq(&e1.tx, &e2.tx),
        "unchanged live set must reuse Transaction Arc"
    );
    assert_eq!(e2.json.get().map(|s| s.as_ref()), Some("keep-a"));
    let b = spend_true(cbs[1], 2_000, ScriptBuf::from_bytes(vec![0x52]));
    hub.accept_tx(&b).expect("b");
    let snap3 = hub.mempool_tx_snapshot();
    let bid = b.compute_txid();
    let e3a = snap3.get(&aid).expect("a still live");
    let e3b = snap3.get(&bid).expect("b in snap3");
    assert!(Arc::ptr_eq(&e2.tx, &e3a.tx), "A reused across new admit");
    assert!(!Arc::ptr_eq(&e3a.tx, &e3b.tx), "new admit gets its own Arc");
    assert!(e3b.json.get().is_none());
    let _ = std::fs::remove_dir_all(&mp_dir);
}

/// A non-final tx from the trusted session stays through hub reorg eviction.
/// A local submit of the same shape is rejected and stays out of the pool.
/// The coin is on the chain, so this is `evict_after_reorg`, not a private utxo map.
#[test]
fn trust_peer_reorg_evict_keeps_nonfinal() {
    let (store, q, cbs) = copy_maturity_pad(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    q.set_trust_peer(true);
    let session = 11u64;
    hub.set_trusted_session(Some(session));
    let tip = q.tip_height().unwrap().0;
    let mut tx = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    tx.lock_time = LockTime::from_height(tip + 10).unwrap();
    tx.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    hub.accept_tx_from(&tx, TxOrigin::Relay(Some(session)))
        .expect("non-final from the trusted session");
    let txid = tx.compute_txid();
    assert!(hub.try_contains(&txid));
    hub.evict_after_reorg();
    assert!(
        hub.try_contains(&txid),
        "reorg eviction must keep a session-warned non-final tx"
    );
    q.set_trust_peer(false);
    hub.evict_after_reorg();
    assert!(
        hub.try_contains(&txid),
        "the keep bit is on the tx, not the process flag"
    );

    let mut local = spend_true(cbs[1], 1_000, ScriptBuf::from_bytes(vec![0x52]));
    local.lock_time = LockTime::from_height(tip + 10).unwrap();
    local.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let err = hub.accept_tx(&local).unwrap_err();
    assert!(
        matches!(err, AcceptError::NotFinal | AcceptError::Policy(_)),
        "{err}"
    );
    let local_id = local.compute_txid();
    assert!(!hub.try_contains(&local_id));
    hub.evict_after_reorg();
    assert!(
        !hub.try_contains(&local_id),
        "a local non-final tx is not in the pool after the sweep"
    );
    assert!(hub.try_contains(&txid));
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// Flag-off `MempoolHub::open` drops a marked tx and its child. An open with
/// the flag still on keeps both, without a manual discard.
#[test]
fn review_trust_flag_off_open_drops_marked_tree() {
    let (store, q, cbs) = copy_maturity_pad(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    q.set_trust_peer(true);
    let session = 11u64;
    hub.set_trusted_session(Some(session));
    let tip = q.tip_height().unwrap().0;
    let mut parent = spend_true(cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
    parent.lock_time = LockTime::from_height(tip + 10).unwrap();
    parent.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    hub.accept_tx_from(&parent, TxOrigin::Relay(Some(session)))
        .expect("non-final from the trusted session");
    let parent_id = parent.compute_txid();
    let child = spend_vout(
        OutPoint {
            txid: parent_id,
            vout: 0,
        },
        parent.output[0].value.to_sat() - 1_000,
    );
    let child_id = child.compute_txid();
    hub.accept_tx(&child)
        .expect("clean child of a marked parent");
    assert!(hub.lock_read().trust_kept.contains(&parent_id));
    assert!(!hub.lock_read().trust_kept.contains(&child_id));
    hub.flush().unwrap();
    drop(hub);

    let kept = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    assert!(
        kept.try_contains(&parent_id),
        "flag-on open dropped the parent"
    );
    assert!(
        kept.try_contains(&child_id),
        "flag-on open dropped the child"
    );
    assert!(kept.lock_read().trust_kept.contains(&parent_id));
    drop(kept);

    q.set_trust_peer(false);
    let off = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    assert!(
        !off.try_contains(&parent_id),
        "flag-off open kept the marked parent"
    );
    assert!(!off.try_contains(&child_id), "flag-off open kept the child");
    assert!(!off.lock_read().trust_kept.contains(&parent_id));
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// A non-final or script-invalid orphan announced by the trusted session is
/// admitted when its parent arrives. Any other announcer is dropped.
#[test]
fn review_trust_orphan_keeps_session_waiver() {
    use bitcoin::WPubkeyHash;

    let (store, q, cbs) = copy_maturity_pad(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    q.set_trust_peer(true);
    let session = 7u64;
    hub.set_trusted_session(Some(session));
    let tip = q.tip_height().unwrap().0;
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let parent = spend_true(cbs[0], 1_000, spk.clone());
    let other_parent = spend_true(cbs[1], 1_000, spk.clone());
    let mut trusted = spend_vout(
        OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        },
        parent.output[0].value.to_sat() - 1_000,
    );
    trusted.lock_time = LockTime::from_height(tip + 10).unwrap();
    trusted.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let mut other = spend_vout(
        OutPoint {
            txid: other_parent.compute_txid(),
            vout: 0,
        },
        other_parent.output[0].value.to_sat() - 1_000,
    );
    other.lock_time = LockTime::from_height(tip + 10).unwrap();
    other.input[0].sequence = Sequence::from_consensus(0xfffffffe);
    let parked = hub
        .accept_tx_from(&trusted, TxOrigin::Relay(Some(session)))
        .unwrap_err();
    assert!(matches!(parked, AcceptError::Orphaned { .. }), "{parked}");
    let parked_other = hub
        .accept_tx_from(&other, TxOrigin::Relay(Some(99)))
        .unwrap_err();
    assert!(
        matches!(parked_other, AcceptError::Orphaned { .. }),
        "{parked_other}"
    );
    hub.accept_tx(&parent).expect("parent");
    hub.accept_tx(&other_parent).expect("other parent");
    let trusted_id = trusted.compute_txid();
    assert!(
        hub.try_contains(&trusted_id),
        "trusted non-final orphan dropped"
    );
    assert!(hub.lock_read().trust_kept.contains(&trusted_id));
    let other_id = other.compute_txid();
    assert!(!hub.try_contains(&other_id));
    assert!(!hub.lock_read().orphanage.contains(&other_id));

    let wpkh = WPubkeyHash::from_byte_array([0x46; 20]);
    let script_parent = spend_true(cbs[2], 1_000, ScriptBuf::new_p2wpkh(&wpkh));
    let bad = spend_vout(
        OutPoint {
            txid: script_parent.compute_txid(),
            vout: 0,
        },
        script_parent.output[0].value.to_sat() - 1_000,
    );
    let parked_bad = hub
        .accept_tx_from(&bad, TxOrigin::Relay(Some(session)))
        .unwrap_err();
    assert!(
        matches!(parked_bad, AcceptError::Orphaned { .. }),
        "{parked_bad}"
    );
    hub.accept_tx(&script_parent).expect("p2wpkh parent");
    let bad_id = bad.compute_txid();
    assert!(hub.try_contains(&bad_id), "trusted script orphan dropped");
    assert!(hub.lock_read().trust_kept.contains(&bad_id));
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// A script failure with no session is rejected even when the mode is on.
/// The same failure from the trusted session stays through reorg eviction.
#[test]
fn trust_peer_admit_from_peer_only() {
    use bitcoin::WPubkeyHash;

    let (store, q, cbs) = copy_maturity_pad(3);
    let mp = tmp();
    let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    q.set_trust_peer(true);
    let wpkh = WPubkeyHash::from_byte_array([0x44; 20]);
    let parent = spend_true(cbs[0], 1_000, ScriptBuf::new_p2wpkh(&wpkh));
    hub.accept_tx(&parent).expect("fund p2wpkh");
    let parent_value = parent.output[0].value.to_sat();
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(parent_value - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = hub.accept_tx(&child).unwrap_err();
    assert!(matches!(err, AcceptError::Script(_)), "{err}");
    assert!(!hub.try_contains(&child.compute_txid()));

    let session = 7u64;
    hub.set_trusted_session(Some(session));
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let got = hub
        .accept_tx_from(&child, TxOrigin::Relay(Some(session)))
        .expect("trusted session admits the script fault");
    assert_eq!(got.fee_sat, 1_000);
    let txid = child.compute_txid();
    assert!(hub.try_contains(&txid));
    let on = rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        on.contains(&format!("trust-peer: applied tx {txid}:")),
        "{on}"
    );
    hub.evict_after_reorg();
    assert!(
        hub.try_contains(&txid),
        "script admit stays through the sweep"
    );

    let parent2 = spend_true(cbs[1], 1_000, ScriptBuf::new_p2wpkh(&wpkh));
    hub.accept_tx(&parent2).expect("second fund");
    let other = Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent2.compute_txid(),
                vout: 0,
            },
            ..child.input[0].clone()
        }],
        ..child.clone()
    };
    let other_err = hub
        .accept_tx_from(&other, TxOrigin::Relay(Some(session + 1)))
        .unwrap_err();
    assert!(matches!(other_err, AcceptError::Script(_)), "{other_err}");
    assert!(!hub.try_contains(&other.compute_txid()));
    rbitcoin_log::capture_logs(false);
    let _ = std::fs::remove_dir_all(&mp);
    let _ = std::fs::remove_dir_all(&store);
}

/// Peer relay admit (`accept_with_utxo` → `admit_staged`) warns and stores
/// a consensus script failure. Flag off rejects with no `trust-peer:` line.
#[test]
fn trust_peer_admit_staged_script() {
    use bitcoin::WPubkeyHash;
    use rbitcoin_mempool::accept::MapUtxoProvider;

    let store_dir = tmp();
    let mp_dir = tmp();
    let q = Query::open_or_create_tiny(&store_dir).unwrap();
    let q = Arc::new(q);
    let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
    let wpkh = WPubkeyHash::from_byte_array([0x44; 20]);
    let op = OutPoint {
        txid: Txid::from_byte_array([0xab; 32]),
        vout: 0,
    };
    let mut map = HashMap::new();
    map.insert(
        op,
        Coin {
            txout: TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2wpkh(&wpkh),
            },
            create_height: 1,
            create_mtp: 0,
            is_coinbase: false,
            create_fk: None,
        },
    );
    let utxos = MapUtxoProvider { map };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    rbitcoin_log::capture_logs(false);
    rbitcoin_log::capture_logs(true);
    let off = hub
        .accept_with_utxo(&tx, &utxos, TxOrigin::Relay(None), false, &[])
        .unwrap_err();
    assert!(matches!(off, AcceptError::Script(_)), "{off}");
    let off_log = rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!off_log.contains("trust-peer:"), "{off_log}");
    assert!(!hub.try_contains(&tx.compute_txid()));

    q.set_trust_peer(true);
    let session = 4u64;
    hub.set_trusted_session(Some(session));
    rbitcoin_log::capture_logs(true);
    let got = hub
        .accept_with_utxo(&tx, &utxos, TxOrigin::Relay(Some(session)), false, &[])
        .expect("peer admit");
    assert_eq!(got.fee_sat, 1_000);
    let txid = tx.compute_txid();
    assert!(hub.try_contains(&txid));
    let on = rbitcoin_log::take_logs()
        .into_iter()
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        on.contains(&format!("trust-peer: applied tx {txid}:")),
        "{on}"
    );
    assert!(on.contains("script verification"), "{on}");
    rbitcoin_log::capture_logs(false);
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store_dir);
}

/// A script reject already in recent-reject is admitted again from the
/// trusted session. Another peer is still dropped. Dust stays out and
/// does not log `trust-peer:`.
#[test]
fn review_trust_recent_reject_does_not_drop_session_tx() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::WPubkeyHash;
    use rbitcoin_consensus::{ChainParams, Milestone};
    use rbitcoin_net::chain::ChainHub;
    use rbitcoin_net::peer::{on_tx, PeerFollowState};
    use rbitcoin_net::peers::{PeerConnType, PeerHub};
    use rbitcoin_net::NetAddr;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (store, q, cbs) = copy_maturity_pad(3);
    let q = match std::sync::Arc::try_unwrap(q) {
        Ok(q) => q,
        Err(_) => panic!("pad query is not shared"),
    };
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.finished_ibd.store(true, Ordering::Release);
    let mp_dir = tmp();
    let mp =
        std::sync::Arc::new(MempoolHub::open(&mp_dir, std::sync::Arc::clone(&hub.query)).unwrap());
    mp.set_relay_enabled(true);
    if hub.attach_mempool(std::sync::Arc::clone(&mp)).is_err() {
        panic!("mempool already attached");
    }
    hub.query.set_trust_peer(true);

    let wpkh = WPubkeyHash::from_byte_array([0x44; 20]);
    let parent = spend_true(cbs[0], 1_000, ScriptBuf::new_p2wpkh(&wpkh));
    mp.accept_tx(&parent).expect("fund p2wpkh");
    let parent_value = parent.output[0].value.to_sat();
    let child = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: parent.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[vec![0x01]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(parent_value - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let err = mp.accept_tx(&child).unwrap_err();
    assert!(matches!(err, AcceptError::Script(_)), "{err}");
    let txid = child.compute_txid();
    assert!(!mp.try_contains(&txid));
    assert!(
        mp.try_recent_reject(&child.compute_wtxid()),
        "local script reject must sit in recent-reject"
    );

    let trusted_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 18444);
    let other_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 18444);
    let peers = PeerHub::new();
    peers.set_trust_peer(Some(NetAddr::from_socket(trusted_addr)), None);
    let ver = |addr: SocketAddr| VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let other = peers.register(
        other_addr,
        other_addr,
        &ver(other_addr),
        false,
        PeerConnType::OutboundFullRelay,
    );
    let trusted = peers.register(
        trusted_addr,
        trusted_addr,
        &ver(trusted_addr),
        false,
        PeerConnType::OutboundFullRelay,
    );
    let (out_tx, _out_rx) = tokio::sync::mpsc::unbounded_channel();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let mut follow = PeerFollowState::new();
        on_tx(&hub, &out_tx, &mut follow, Some(&other), &child)
            .await
            .unwrap();
    });
    assert!(
        !mp.try_contains(&txid),
        "a non-trusted peer must not clear recent-reject"
    );

    rt.block_on(async {
        let mut follow = PeerFollowState::new();
        on_tx(&hub, &out_tx, &mut follow, Some(&trusted), &child)
            .await
            .unwrap();
    });
    assert!(mp.try_contains(&txid), "trusted session re-admits");

    // `on_tx` commits on the blocking pool, so this thread's log buffer
    // cannot see the applied line. The mempool test pins that log.
    let dust = spend_true(cbs[1], 50_0000_0000, ScriptBuf::from_bytes(vec![0x51]));
    rt.block_on(async {
        let mut follow = PeerFollowState::new();
        on_tx(&hub, &out_tx, &mut follow, Some(&trusted), &dust)
            .await
            .unwrap();
    });
    assert!(
        !mp.try_contains(&dust.compute_txid()),
        "a policy reject from the trusted session stays out"
    );
    let _ = std::fs::remove_dir_all(&mp_dir);
    let _ = std::fs::remove_dir_all(&store);
}
