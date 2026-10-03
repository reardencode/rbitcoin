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

#[test]
fn replay_status_is_ten_seconds() {
    assert!(!super::write::replay_status_due(9_999));
    assert!(super::write::replay_status_due(10_000));
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
