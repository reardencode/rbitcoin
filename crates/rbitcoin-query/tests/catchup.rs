use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::catchup::*;
use rbitcoin_query::sh_builder::{load_seal, sh_force_rebuild, store_seal};
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::Query;
use rbitcoin_store::StoreError;
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
use std::sync::Mutex;

/// Serialize FORCE_REBUILD env mutations (parallel tests share process env).
static FORCE_ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_force_env() -> std::sync::MutexGuard<'static, ()> {
    FORCE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn coinbase_block(
    h: u32,
    prev: Fk,
    parent_hash: Option<[u8; 32]>,
) -> (HeaderRecord, rbitcoin_query::TxApply) {
    let version = 1;
    let timestamp = h + 1;
    let bits = 0x207fffff;
    let nonce = h;
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&h.to_le_bytes());
    merkle[4] = 0xcd;
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
    let ta = rbitcoin_query::TxApply {
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
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51, h as u8])],
    };
    (header, ta)
}

#[test]
fn unknown_index_mode_byte_is_corrupt() {
    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-mode-byte");
    for bad in [0u8, 3] {
        q.index_mode_cell
            .store(bad, std::sync::atomic::Ordering::SeqCst);
        match q.index_mode() {
            Err(StoreError::Corrupt(msg)) => {
                assert_eq!(msg, "index mode byte", "byte {bad}");
            }
            other => panic!("byte {bad} must be corrupt, got {other:?}"),
        }
    }
    q.index_mode_cell
        .store(IndexMode::Direct as u8, std::sync::atomic::Ordering::SeqCst);
    assert!(q.index_mode().expect("direct").is_direct());
    q.index_mode_cell
        .store(IndexMode::Tip as u8, std::sync::atomic::Ordering::SeqCst);
    assert!(q.index_mode().expect("tip").is_tip());
    assert!(!q.index_mode().expect("tip").is_direct());
}

fn seed_direct_chain(q: &Query, n: u32) {
    q.enter_direct_index_mode().unwrap();
    extend_direct_chain(q, n);
    assert_eq!(q.tip_height(), Some(Height(n - 1)));
    assert!(q.store.txs.count() >= u64::from(n));
}

fn extend_direct_chain(q: &Query, add: u32) {
    if add == 0 {
        return;
    }
    let start = q.tip_height().map(|h| h.0.saturating_add(1)).unwrap_or(0);
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    if start > 0 {
        let prev_h = Height(start - 1);
        prev = q.store.confirmed.get(prev_h).unwrap().unwrap();
        parent_hash = Some(q.get_header(prev).unwrap().hash);
    }
    for h in start..start + add {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
}

#[test]
fn finalize_sh_runs_durable_head_missing_hwm_keeps_seal() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-hwm");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 3);
    let n0 = q.finalize_sh_runs().unwrap();
    assert!(n0 >= 1 || q.store.scripthash.has_durable_index());
    assert!(q.store.scripthash.has_durable_index());
    let count_before = q.store.scripthash.entry_count();
    let sh0 = rbitcoin_store::script_hash(&[0x51, 0]);

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    let high_seal = 1_411_000_000u64;
    store_seal(&runs_dir, high_seal).unwrap();
    q.sh_run.refresh_seal();
    let _ = std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME));
    assert_eq!(q.store.scripthash.include_hwm(), 0);
    assert_eq!(q.sh_run.sealed_max_create_fk(), high_seal);

    let _ = q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.sh_run.sealed_max_create_fk(),
        high_seal,
        "SEAL must not be clamped to 0 when HWM was missing"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        high_seal,
        "include_hwm must bootstrap from SEAL"
    );
    assert!(
        !q.store.scripthash.entries(&sh0).unwrap().is_empty(),
        "durable head must remain"
    );
    assert!(q.store.scripthash.entry_count() >= count_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_runs_empty_head_leftover_seal_is_wiped() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-stale");
    q.enter_direct_index_mode().unwrap();
    assert!(!q.store.scripthash.has_durable_index());

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    let high_seal = 1_400_000_000u64;
    store_seal(&runs_dir, high_seal).unwrap();
    q.sh_run.refresh_seal();
    std::fs::write(runs_dir.join("000001.run"), b"leftover").unwrap();

    let _ = q.finalize_sh_runs().unwrap();
    assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
    assert_eq!(load_seal(&runs_dir), 0);
    assert_eq!(q.scripthash_run_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn force_rebuild_recollects_class_a_not_empty_materialize() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-force-recol");
    seed_direct_chain(&q, 6);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.store.scripthash.has_durable_index());

    std::env::set_var("RBITCOIN_SH_FORCE_REBUILD", "1");
    assert!(sh_force_rebuild());
    let result = q.finalize_sh_runs();
    std::env::remove_var("RBITCOIN_SH_FORCE_REBUILD");
    let n_mat = result.expect("finalize after FORCE must not fail empty");
    assert!(
        n_mat > 0,
        "materialize must load Class A creates, got {n_mat}"
    );
    assert!(
        q.store.scripthash.has_durable_index(),
        "head must not stay empty after FORCE collect+pack"
    );
    assert!(q.store.scripthash.entry_count() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsorted_shards_finalize_skips_catalog_runs() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-unsorted");
    seed_direct_chain(&q, 5);
    let n_mat = q.finalize_sh_runs().expect("unsorted-shards finalize");
    assert!(
        n_mat > 0 || q.store.scripthash.has_durable_index(),
        "unsorted-shards must settle SH"
    );
    assert!(q.store.scripthash.has_durable_index());
    assert_eq!(
        q.scripthash_run_count(),
        0,
        "unsorted-shards must not leave catalog runs"
    );
    assert!(
        !rbitcoin_store::unsorted_shard_dir(q.store.path()).exists()
            || std::fs::read_dir(rbitcoin_store::unsorted_shard_dir(q.store.path()))
                .map(|it| it.count() == 0)
                .unwrap_or(true),
        "unsorted dir must be cleared after seal"
    );
    let sh = rbitcoin_store::script_hash(&[0x51, 0]);
    assert!(
        !q.scripthash_history(&sh).unwrap().is_empty(),
        "Class A creates must be queryable"
    );
    assert!(q.sh_is_tip_ready() || q.store.scripthash.entry_count() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn durable_head_hwm_lag_discards_leftover_run() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-hwm-lag-skip");
    seed_direct_chain(&q, 6);
    let n0 = q.finalize_sh_runs().unwrap();
    assert!(n0 > 0 || q.store.scripthash.has_durable_index());
    assert!(q.store.scripthash.has_durable_index());
    let count_before = q.store.scripthash.entry_count();
    let tip_max = q.store.txs.count();
    assert!(tip_max >= 6);

    let lag = tip_max.saturating_sub(3).max(1);
    std::fs::write(
        dir.join(rbitcoin_store::INCLUDE_HWM_NAME),
        lag.to_le_bytes(),
    )
    .unwrap();
    assert!(
        q.store.scripthash.include_hwm() < tip_max,
        "planted HWM lag hwm={} tip_max={tip_max}",
        q.store.scripthash.include_hwm()
    );

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    std::fs::write(runs_dir.join("000050.run"), b"leftover").unwrap();
    assert!(q.sh_run.on_disk_run_count() > 0);
    assert!(!q.sh_is_tip_ready(), "strict HWM/run check is still false");
    assert!(
        q.sh_use_writebehind(),
        "durable head must choose write-behind even when HWM lags"
    );

    let n1 = q.finalize_sh_runs().unwrap();
    assert_eq!(n1, 0, "must not collect onto a live head");
    assert_eq!(
        q.store.scripthash.entry_count(),
        count_before,
        "leftover run must not be applied onto the live head"
    );
    assert_eq!(q.scripthash_run_count(), 0, "leftover runs discarded");
    assert!(
        q.store.scripthash.include_hwm() >= tip_max,
        "Direct finalize backfills Class A tail (hwm={} tip_max={tip_max}), not leftover fk=99",
        q.store.scripthash.include_hwm()
    );
    assert!(
        q.store.scripthash.include_hwm() < 99,
        "leftover run fk=99 must not become include_hwm"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_appends_unsorted_when_done_lags_before_any_shard() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-lag");
    seed_direct_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let done_last = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    extend_direct_chain(&q, 2);
    assert!(q.store.txs.count() > done_last);
    assert!(
        !q.store.scripthash.unsealed_main_shards().is_empty(),
        "RAM merge writes head files; pack seal is later"
    );
    let _ = q.finalize_sh_runs().unwrap();
    let sh_old = rbitcoin_store::script_hash(&[0x51, 0]);
    let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
    assert!(
        !q.scripthash_history(&sh_old).unwrap().is_empty(),
        "creates from the original collect must remain"
    );
    assert!(
        !q.scripthash_history(&sh_new).unwrap().is_empty(),
        "creates after DONE must be in unsorted catch-up before pack"
    );
    assert!(q.sh_is_tip_ready());
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_backfills_class_a_tail_when_shards_already_sealed() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-shard-lag");
    seed_direct_chain(&q, 3);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.store.scripthash.has_durable_index());
    assert!(q.sh_is_tip_ready());
    extend_direct_chain(&q, 2);
    assert!(
        !q.sh_is_tip_ready(),
        "new Class A after seal must lag honest include_hwm"
    );
    let _ = q.finalize_sh_runs().unwrap();
    let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
    assert!(
        !q.scripthash_history(&sh_new).unwrap().is_empty(),
        "Direct finalize must backfill Class A tail onto sealed shards"
    );
    assert!(q.sh_is_tip_ready());
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `submitblock` confirms while the tail backfill has already sampled
/// `txs.count()`. That create has to land in the inclusion watermark or
/// materialize refuses and Esplora never binds.
#[test]
fn backfill_includes_create_that_lands_after_count_sample() {
    let _g = lock_force_env();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-backfill-race");
    seed_direct_chain(&q, 3);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    extend_direct_chain(&q, 1);
    assert!(!q.sh_is_tip_ready());
    set_sh_backfill_after_sample_for_test(Some(extend_one_during_backfill));
    let result = q.backfill_sh_creates_from_class_a();
    set_sh_backfill_after_sample_for_test(None);
    result.expect("backfill");
    assert!(
        q.sh_is_tip_ready(),
        "a create confirmed after the count sample stays inside include_hwm"
    );
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

fn extend_one_during_backfill(q: &Query) {
    extend_direct_chain(q, 1);
}
