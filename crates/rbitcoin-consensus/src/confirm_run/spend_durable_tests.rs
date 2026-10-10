//! Spend annotations lost after the tip seal must not make that output spendable.

use std::io::{Seek, SeekFrom, Write};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Block, Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut,
    Txid, Witness,
};

use crate::block::bip34_height_script;
use crate::{accept_and_connect_block, ChainParams, ConsensusError, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_store::spent_abs;

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend_one(prev: Txid, val: Amount) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
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
    }
}

fn mine(prev: bitcoin::BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut txdata = vec![coinbase(height)];
    txdata.extend(extra);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time,
            bits,
            nonce: 0,
        },
        txdata,
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

#[test]
fn zeroed_spend_slot_after_tip_seal_rejects_respend() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-durable");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;

    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;

    for h in 2..=maturity + 2 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    let h_spend = maturity + 3;
    let tx = spend_one(c1, Amount::from_sat(49_0000_0000));
    let block = mine(tip, tip_time + 600, h_spend, vec![tx]);
    accept_and_connect_block(&q, &params, Height(h_spend), &block, ms).unwrap();
    assert!(q.is_outpoint_spent(c1.as_byte_array(), 0).unwrap());
    let create_fk = q.tx_fk_by_txid(c1.as_byte_array()).unwrap().unwrap();
    let (off, _) = q.store().tx_spent_range(create_fk).unwrap();
    let abs = spent_abs(off, 0);
    let store = q.store().path().to_path_buf();
    drop(q);

    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.join("spent.body"))
            .unwrap();
        f.seek(SeekFrom::Start(abs)).unwrap();
        f.write_all(&[0u8; 8]).unwrap();
    }
    let _ = std::fs::remove_file(store.join(rbitcoin_store::SPEND_DURABLE_NAME));

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let tip_h = q.tip_height().unwrap();
    let replayed = crate::replay_spend_annotations(&q).unwrap();
    assert_eq!(
        replayed, tip_h.0,
        "a missing marker replays every height above genesis"
    );
    let tip_hash = q.header_at_height(tip_h).unwrap().unwrap().1.hash;
    let respend = mine(
        bitcoin::BlockHash::from_byte_array(tip_hash),
        tip_time + 1_200,
        tip_h.0 + 1,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h.0 + 1), &respend, ms)
        .expect_err("a sealed spend must stay spent after its slot is zeroed");
    assert!(
        matches!(err, ConsensusError::PrevoutSpent),
        "reopen must reject the respend, got {err}"
    );
    let _ = dir;
}

/// A matching last-6 window does not prove spends below it. With no marker
/// those spends were never device-flushed.
#[test]
fn missing_marker_replays_a_spend_below_the_tip_window() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-window");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 2 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let h_spend = maturity + 3;
    let tx = spend_one(c1, Amount::from_sat(49_0000_0000));
    let block = mine(tip, tip_time + 600, h_spend, vec![tx]);
    accept_and_connect_block(&q, &params, Height(h_spend), &block, ms).unwrap();
    tip = block.block_hash();
    tip_time = block.header.time;
    for h in (h_spend + 1)..=(h_spend + rbitcoin_store::VERIFY_TIP_BLOCKS) {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let create_fk = q.tx_fk_by_txid(c1.as_byte_array()).unwrap().unwrap();
    let (off, _) = q.store().tx_spent_range(create_fk).unwrap();
    let abs = spent_abs(off, 0);
    let store = q.store().path().to_path_buf();
    drop(q);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.join("spent.body"))
            .unwrap();
        f.seek(SeekFrom::Start(abs)).unwrap();
        f.write_all(&[0u8; 8]).unwrap();
    }
    let _ = std::fs::remove_file(store.join(rbitcoin_store::SPEND_DURABLE_NAME));
    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let tip_h = q.tip_height().unwrap();
    let replayed = crate::replay_spend_annotations(&q).unwrap();
    assert!(
        replayed >= h_spend,
        "a missing marker must rewrite the spend below the tip window, replayed {replayed}"
    );
    let tip_hash = q.header_at_height(tip_h).unwrap().unwrap().1.hash;
    let respend = mine(
        bitcoin::BlockHash::from_byte_array(tip_hash),
        tip_time + 1_200,
        tip_h.0 + 1,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h.0 + 1), &respend, ms)
        .expect_err("a spend below the tip window must stay spent when the marker is missing");
    assert!(
        matches!(err, ConsensusError::PrevoutSpent),
        "reopen must reject the respend, got {err}"
    );
    let _ = dir;
}

/// No valid chain has a confirmed spender below its create's height. A
/// spend slot that names one is a store fault, not an unspent output.
#[test]
fn spender_below_its_create_height_is_corrupt() {
    use std::io::Read;

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-below-create");
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut cbs = Vec::new();
    for h in 1..=maturity + 2 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        cbs.push(b.txdata[0].compute_txid());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let early_spender = spend_one(cbs[0], Amount::from_sat(49_0000_0000));
    let later_create = spend_one(cbs[1], Amount::from_sat(49_0000_0000));
    let later_txid = later_create.compute_txid();
    for (h, tx) in [(maturity + 3, early_spender), (maturity + 4, later_create)] {
        let b = mine(tip, tip_time + 600, h, vec![tx]);
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let slot_abs = |txid: Txid| {
        let fk = q.tx_fk_by_txid(txid.as_byte_array()).unwrap().unwrap();
        spent_abs(q.store().tx_spent_range(fk).unwrap().0, 0)
    };
    let (from, to) = (slot_abs(cbs[0]), slot_abs(later_txid));
    let store = q.store().path().to_path_buf();
    drop(q);
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(store.join("spent.body"))
            .unwrap();
        let mut slot = [0u8; 8];
        f.seek(SeekFrom::Start(from)).unwrap();
        f.read_exact(&mut slot).unwrap();
        f.seek(SeekFrom::Start(to)).unwrap();
        f.write_all(&slot).unwrap();
    }

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    let tip_h = q.tip_height().unwrap();
    let spend = mine(
        tip,
        tip_time + 600,
        tip_h.0 + 1,
        vec![spend_one(later_txid, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h.0 + 1), &spend, ms)
        .expect_err("a slot naming a spender below the create must not read as unspent");
    assert!(
        matches!(
            &err,
            ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(m))
                if m.starts_with("invariant:")
        ),
        "got {err}"
    );
    assert_eq!(q.tip_height(), Some(tip_h));
    let _ = dir;
}

#[test]
fn confirms_past_eight_batches_wait_for_an_explicit_checkpoint() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-checkpoint");
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    for h in 1..=9 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    assert!(
        !q.store()
            .path()
            .join(rbitcoin_store::SPEND_DURABLE_NAME)
            .is_file(),
        "confirm must not publish the marker"
    );
    let h = q.store().spend_snapshot_height().unwrap();
    assert_eq!(h, 9);
    let b = mine(tip, tip_time + 600, 10, Vec::new());
    accept_and_connect_block(&q, &params, Height(10), &b, ms).unwrap();
    assert_eq!(q.store().spend_snapshot_height(), Some(10));
    q.store().checkpoint_spend_through(h).unwrap();
    let raw = std::fs::read(q.store().path().join(rbitcoin_store::SPEND_DURABLE_NAME)).unwrap();
    assert_eq!(u32::from_le_bytes(raw[8..12].try_into().unwrap()), h);
    assert_eq!(u32::from_le_bytes(raw[12..16].try_into().unwrap()), h);
    let _ = dir;
}

/// Y is archived in a rejected batch, so its spend of X's output is never
/// annotated and X's archive wave had no overlay for it. After X is
/// disconnected, the run `[X, Y]` has no archive plan. It must still write
/// the spend, or a later block can spend the same output again.
#[test]
fn rerun_without_archive_plan_annotates_a_spend_of_a_run_create() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-rerun");
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 1 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    let hx = maturity + 2;
    let t = spend_one(c1, Amount::from_sat(49_0000_0000));
    let tid = t.compute_txid();
    let x = mine(tip, tip_time + 600, hx, vec![t]);
    accept_and_connect_block(&q, &params, Height(hx), &x, ms).unwrap();

    let y = mine(
        x.block_hash(),
        x.header.time + 600,
        hx + 1,
        vec![spend_one(tid, Amount::from_sat(48_0000_0000))],
    );
    let z_bad = mine(
        y.block_hash(),
        y.header.time + 600,
        hx + 2,
        vec![spend_one(
            x.txdata[0].compute_txid(),
            Amount::from_sat(1_0000_0000),
        )],
    );
    let err = crate::confirm_wire_run(
        &q,
        &params,
        ms,
        &[(Height(hx + 1), y.clone()), (Height(hx + 2), z_bad)],
    )
    .expect_err("an immature coinbase spend must reject the batch");
    assert!(
        matches!(err, ConsensusError::BadTx("coinbase immature")),
        "{err}"
    );
    assert_eq!(q.tip_height(), Some(Height(hx)));
    assert!(
        q.tx_fk_by_txid(y.txdata[1].compute_txid().as_byte_array())
            .unwrap()
            .is_some(),
        "Class A commits Y before structural rejects the batch"
    );

    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(hx - 1)));
    crate::confirm_wire_run(
        &q,
        &params,
        ms,
        &[(Height(hx), x.clone()), (Height(hx + 1), y.clone())],
    )
    .unwrap();
    assert_eq!(q.tip_height(), Some(Height(hx + 1)));
    assert!(
        q.is_outpoint_spent(tid.as_byte_array(), 0).unwrap(),
        "Y's spend of X's output must be on disk"
    );

    let respend = mine(
        y.block_hash(),
        y.header.time + 600,
        hx + 2,
        vec![spend_one(tid, Amount::from_sat(46_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(hx + 2), &respend, ms)
        .expect_err("an output spent at the tip must not be spent again");
    assert!(matches!(err, ConsensusError::PrevoutSpent), "{err}");
    let _ = dir;
}

/// A stage after the tip commit fails, so Y is connected without its spend
/// annotation. The next block must not validate against that state.
///
/// Turning the filter index on after live append started leaves its
/// watermark at 0, so the live seal for Y fails after Class C.
#[test]
fn failed_post_tip_stage_does_not_let_the_next_block_respend() {
    let _gate = crate::script_pool::steal_test_gate();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-post-tip");
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 1 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    crate::prepare_live_indexes(&q).unwrap();
    assert!(q.index_live());
    q.set_block_filter_index(true).unwrap();
    assert_eq!(q.filter_index_next(), Some(0));

    let hy = maturity + 2;
    let y = mine(
        tip,
        tip_time + 600,
        hy,
        vec![spend_one(c1, Amount::from_sat(49_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(hy), &y, ms)
        .expect_err("the live seal finds a watermark that is not this batch");
    assert!(
        matches!(
            err,
            ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: live index commit"
            ))
        ),
        "{err}"
    );
    assert_eq!(q.tip_height(), Some(Height(hy)), "Class C committed Y");

    let respend = mine(
        y.block_hash(),
        y.header.time + 600,
        hy + 1,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(hy + 1), &respend, ms)
        .expect_err("an output Y spent must not be spent again");
    assert_eq!(q.tip_height(), Some(Height(hy)), "{err}");
    assert!(matches!(err, ConsensusError::PrevoutSpent), "{err}");
    assert!(q.is_outpoint_spent(c1.as_byte_array(), 0).unwrap());
    assert!(
        q.confirm_stats().take_window().spend_replay_ns > 0,
        "the replay is timed"
    );
    let _ = dir;
}

/// A reorg drops the tip below the spend snapshot, and the reconnect fails
/// after its tip commit. The checkpoint must not publish the old snapshot
/// over the reconnected height, or the next open does not replay its spends.
#[test]
fn checkpoint_after_reorg_does_not_skip_the_reconnected_spends() {
    let _gate = crate::script_pool::steal_test_gate();
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-reorg-snapshot");
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    for h in 2..=maturity + 1 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }

    let hy = maturity + 2;
    let x = mine(tip, tip_time + 600, hy, Vec::new());
    accept_and_connect_block(&q, &params, Height(hy), &x, ms).unwrap();
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(hy - 1)));

    q.set_sptweaks_enabled(true, Height(0)).unwrap();
    crate::prepare_live_indexes(&q).unwrap();
    q.set_block_filter_index(true).unwrap();
    let y = mine(
        tip,
        tip_time + 1_200,
        hy,
        vec![spend_one(c1, Amount::from_sat(49_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(hy), &y, ms)
        .expect_err("the live seal finds a watermark that is not this batch");
    assert!(
        matches!(
            err,
            ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: live index commit"
            ))
        ),
        "{err}"
    );
    assert_eq!(q.tip_height(), Some(Height(hy)), "Class C committed Y");

    let q = std::sync::Arc::new(q);
    rbitcoin_query::SpendSync::spawn(std::sync::Arc::clone(&q)).shutdown();
    let store = q.store().path().to_path_buf();
    drop(q);

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    crate::replay_spend_annotations(&q).unwrap();
    assert!(
        q.is_outpoint_spent(c1.as_byte_array(), 0).unwrap(),
        "open must replay Y's spend"
    );
    let respend = mine(
        y.block_hash(),
        y.header.time + 600,
        hy + 1,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(hy + 1), &respend, ms)
        .expect_err("an output Y spent must not be spent again");
    assert_eq!(q.tip_height(), Some(Height(hy)), "{err}");
    assert!(matches!(err, ConsensusError::PrevoutSpent), "{err}");
    let _ = dir;
}

fn marker_heights(store: &std::path::Path) -> Option<(u32, u32)> {
    let path = store.join(rbitcoin_store::SPEND_DURABLE_NAME);
    let buf = std::fs::read(&path).ok()?;
    if buf.len() != 16 {
        return None;
    }
    Some((
        u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        u32::from_le_bytes(buf[12..16].try_into().unwrap()),
    ))
}

fn connect_until(
    q: &rbitcoin_query::Query,
    params: &ChainParams,
    ms: Milestone,
    tip: &mut bitcoin::BlockHash,
    tip_time: &mut u32,
    end_height: u32,
) {
    let start = q.tip_height().map(|h| h.0).unwrap_or(0);
    for h in (start + 1)..=end_height {
        let b = mine(*tip, *tip_time + 600, h, Vec::new());
        accept_and_connect_block(q, params, Height(h), &b, ms).unwrap();
        *tip = b.block_hash();
        *tip_time = b.header.time;
    }
}

/// Shrink `input.loc` so `keep` creates remain. Simulates a power loss that
/// published the Class A tail without the input high-water mark.
fn shrink_input_loc_hwm(store: &std::path::Path, keep: u64) {
    let logical = 16u64 + keep * 2;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(store.join("input.loc"))
        .unwrap();
    f.seek(SeekFrom::Start(8)).unwrap();
    f.write_all(&logical.to_le_bytes()).unwrap();
}

fn input_body_off(q: &rbitcoin_query::Query, spend_fk: rbitcoin_primitives::Fk) -> u64 {
    let mut before = 0u64;
    for id in 1..spend_fk.0 {
        let (_, ins, _) = q.store().get_tx_full(rbitcoin_primitives::Fk(id)).unwrap();
        before += ins.len() as u64;
    }
    16 + before * 8
}

fn sealed_spend_chain() -> (
    rbitcoin_query::testutil::TempDir,
    rbitcoin_query::Query,
    ChainParams,
    Milestone,
    u32,
    Txid,
    Block,
    u32,
) {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spend-edge-loss");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let b1 = mine(tip, tip_time + 600, 1, Vec::new());
    let c1 = b1.txdata[0].compute_txid();
    accept_and_connect_block(&q, &params, Height(1), &b1, ms).unwrap();
    tip = b1.block_hash();
    tip_time = b1.header.time;
    connect_until(&q, &params, ms, &mut tip, &mut tip_time, maturity + 2);
    let h_spend = maturity + 3;
    let tx = spend_one(c1, Amount::from_sat(49_0000_0000));
    let block = mine(tip, tip_time + 600, h_spend, vec![tx]);
    accept_and_connect_block(&q, &params, Height(h_spend), &block, ms).unwrap();
    (dir, q, params, ms, h_spend, c1, block, tip_time)
}

#[test]
fn short_input_hwm_shrinks_below_the_edgeless_create() {
    let (dir, q, params, ms, h_spend, c1, block, tip_time) = sealed_spend_chain();
    assert_eq!(q.tip_height(), Some(Height(h_spend)));
    let keep = u64::from(h_spend);
    let store = q.store().path().to_path_buf();
    drop(q);
    shrink_input_loc_hwm(&store, keep);

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let tip_h = q.tip_height().expect("a prefix of the chain stays");
    assert!(
        tip_h.0 < h_spend,
        "open must drop the block whose creates lost their edges, tip {}",
        tip_h.0
    );
    crate::replay_spend_annotations(&q).unwrap();
    let marked = q.store().spend_annotated_through().unwrap();
    assert_ne!(
        marked,
        Some(h_spend),
        "the spend marker must not name the pre-loss tip"
    );
    if let Some((ann, durable)) = marker_heights(&store) {
        assert_ne!(ann, h_spend);
        assert_ne!(durable, h_spend);
    }
    let spend_txid = block.txdata[1].compute_txid();
    assert!(
        q.tx_fk_by_txid(spend_txid.as_byte_array())
            .unwrap()
            .is_none(),
        "the edgeless spend create is not left in the archive"
    );

    accept_and_connect_block(&q, &params, Height(tip_h.0 + 1), &block, ms).unwrap();
    let respend = mine(
        block.block_hash(),
        tip_time + 1_200,
        tip_h.0 + 2,
        vec![spend_one(c1, Amount::from_sat(48_0000_0000))],
    );
    let err = accept_and_connect_block(&q, &params, Height(tip_h.0 + 2), &respend, ms)
        .expect_err("reconnecting the spend keeps the output spent");
    assert!(
        matches!(err, ConsensusError::PrevoutSpent),
        "respend after reconnect: {err}"
    );
    let _ = dir;
}

#[test]
fn zeroed_input_body_shrinks_and_is_not_a_coinbase() {
    let (dir, q, _params, _ms, h_spend, c1, block, _tip_time) = sealed_spend_chain();
    let spend_txid = block.txdata[1].compute_txid();
    let spend_fk = q
        .tx_fk_by_txid(spend_txid.as_byte_array())
        .unwrap()
        .unwrap();
    let off = input_body_off(&q, spend_fk);
    let store = q.store().path().to_path_buf();
    drop(q);
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.join("input.body"))
            .unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&[0u8; 8]).unwrap();
    }

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    let tip_h = q.tip_height().unwrap();
    assert!(
        tip_h.0 < h_spend,
        "a coinbase-shaped edge on a non-coinbase shrinks the tip, got {}",
        tip_h.0
    );
    crate::replay_spend_annotations(&q).unwrap();
    assert_ne!(q.store().spend_annotated_through().unwrap(), Some(h_spend));
    assert!(
        !q.is_outpoint_spent(c1.as_byte_array(), 0).unwrap(),
        "the rolled-back spend must not leave the parent spent"
    );
    let _ = dir;
}

#[test]
fn replay_rejects_coinbase_edge_on_a_non_coinbase() {
    let (dir, q, _params, _ms, h_spend, _c1, block, _tip_time) = sealed_spend_chain();
    q.store().checkpoint_spend_through(h_spend - 1).unwrap();
    assert_eq!(
        q.store().spend_annotated_through().unwrap(),
        Some(h_spend - 1)
    );
    let spend_fk = q
        .tx_fk_by_txid(block.txdata[1].compute_txid().as_byte_array())
        .unwrap()
        .unwrap();
    let off = input_body_off(&q, spend_fk);
    let store = q.store().path().to_path_buf();
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.join("input.body"))
            .unwrap();
        f.seek(SeekFrom::Start(off)).unwrap();
        f.write_all(&[0u8; 8]).unwrap();
    }
    let err = crate::replay_spend_annotations(&q).expect_err("replay must fail closed");
    assert!(
        matches!(
            err,
            ConsensusError::Store(rbitcoin_store::StoreError::Corrupt(_))
        ),
        "{err}"
    );
    let (ann, durable) = marker_heights(&store).unwrap();
    assert_eq!(ann, h_spend - 1);
    assert_eq!(durable, h_spend - 1);
    let _ = dir;
}

fn chain_at_height(
    label: &str,
    height: u32,
) -> (rbitcoin_query::testutil::TempDir, rbitcoin_query::Query) {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    connect_until(&q, &params, ms, &mut tip, &mut tip_time, height);
    (dir, q)
}

#[test]
fn checkpoint_disconnect_before_gen_sample_does_not_publish() {
    let (dir, q) = chain_at_height("spend-gen-gap", 2);
    q.store().checkpoint_spend_through(1).unwrap();
    let parent = q.header_at_height(Height(1)).unwrap().unwrap().1;
    let replacement = mine(
        bitcoin::BlockHash::from_byte_array(parent.hash),
        parent.timestamp + 600,
        2,
        Vec::new(),
    );
    let q = std::sync::Arc::new(q);
    let on_disconnect = std::sync::Arc::clone(&q);
    let on_sync = std::sync::Arc::clone(&q);
    rbitcoin_store::testutil::checkpoint_observed_spend_gap(
        q.store(),
        move |_store| {
            on_disconnect.disconnect_tip().unwrap();
        },
        move |_store| {
            accept_and_connect_block(
                &on_sync,
                &ChainParams::regtest(),
                Height(2),
                &replacement,
                Milestone::NONE,
            )
            .unwrap();
        },
    )
    .unwrap();
    let (ann, durable) = marker_heights(q.store().path()).unwrap();
    assert_eq!(
        ann, 1,
        "a disconnect before the generation sample must not publish the replacement"
    );
    assert_eq!(durable, 1);
    let _ = dir;
}

#[test]
fn checkpoint_disconnect_inside_sync_does_not_publish() {
    let (dir, q) = chain_at_height("spend-gen-reorg", 2);
    q.store().checkpoint_spend_through(1).unwrap();
    let parent = q.header_at_height(Height(1)).unwrap().unwrap().1;
    let replacement = mine(
        bitcoin::BlockHash::from_byte_array(parent.hash),
        parent.timestamp + 600,
        2,
        Vec::new(),
    );
    let q = std::sync::Arc::new(q);
    let during = std::sync::Arc::clone(&q);
    rbitcoin_store::testutil::checkpoint_spend_through_between(q.store(), 2, move |_store| {
        during.disconnect_tip().unwrap();
        accept_and_connect_block(
            &during,
            &ChainParams::regtest(),
            Height(2),
            &replacement,
            Milestone::NONE,
        )
        .unwrap();
    })
    .unwrap();
    let (ann, durable) = marker_heights(q.store().path()).unwrap();
    assert_eq!(ann, 1, "a reorg inside the sync window must not publish 2");
    assert_eq!(durable, 1);
    assert_eq!(q.tip_height(), Some(Height(2)));
    let _ = dir;
}

#[test]
fn checkpoint_append_above_snapshot_still_publishes() {
    let (dir, q) = chain_at_height("spend-gen-append", 2);
    let tip = q.header_at_height(Height(2)).unwrap().unwrap().1.hash;
    let tip_time = q.header_at_height(Height(2)).unwrap().unwrap().1.timestamp;
    let next = mine(
        bitcoin::BlockHash::from_byte_array(tip),
        tip_time + 600,
        3,
        Vec::new(),
    );
    let q = std::sync::Arc::new(q);
    let during = std::sync::Arc::clone(&q);
    rbitcoin_store::testutil::checkpoint_spend_through_between(q.store(), 2, move |_store| {
        accept_and_connect_block(
            &during,
            &ChainParams::regtest(),
            Height(3),
            &next,
            Milestone::NONE,
        )
        .unwrap();
    })
    .unwrap();
    let (ann, durable) = marker_heights(q.store().path()).unwrap();
    assert_eq!(ann, 2);
    assert_eq!(durable, 2);
    assert_eq!(q.tip_height(), Some(Height(3)));
    let _ = dir;
}
