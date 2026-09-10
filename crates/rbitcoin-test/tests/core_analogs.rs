//! Core functional analogs (inventory `analog=`).
//!
//! Unmodified Core scripts that touch LevelDB / `blocks/` / assumevalid logs
//! cannot `run`. These scenarios keep the behavior we still want:
//!
//! 1. `--milestone` skip-below / check-above + mempool persist + missing
//!    prevout still fails when scripts are skipped (`feature_assumevalid.py`,
//!    `mempool_persist.py`)
//! 2. Reconstruct height 1 after process restart / lost RAM head
//!    (`feature_reindex*.py`)

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use rbitcoin_consensus::{
    accept_and_connect_block, validate_block_connect, ChainParams, Milestone, ValidationContext,
};
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
use rbitcoin_test::{assert_reconstruct_eq, build_mature_regtest_with_spend, TestDatadir};
use std::sync::Arc;

/// One mature pad: mempool persist, then `--milestone` skip-below / check-above,
/// then missing prevout still fails under a high milestone (scripts skipped).
///
/// Core `feature_assumevalid.py` + `mempool_persist.py`.
#[test]
fn analog_milestone_and_mempool_persist() {
    let params = ChainParams::regtest();
    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    let chain = build_mature_regtest_with_spend(&q, &params);

    let spend_block = &chain.blocks[chain.spend_height as usize];
    let spend_txid = spend_block.txdata[1].compute_txid();
    let unconf = spend_anyone_can_spend(spend_txid, 0, Amount::from_sat(48_0000_0000));
    let want = unconf.compute_txid();

    let mp_dir = td.path().join("mempool");
    let q_arc = Arc::new(q);
    {
        let hub = MempoolHub::open_with_weight(&mp_dir, Arc::clone(&q_arc), 50_000_000).unwrap();
        hub.set_relay_enabled(true);
        let r = hub
            .accept_tx(&unconf)
            .expect("accept unconfirmed spend of confirmed anyone-can-spend");
        assert_eq!(r.txid, want);
        hub.flush().expect("SIGTERM-equivalent flush");
        assert!(hub.contains(&want));
    }
    let hub2 = MempoolHub::open_with_weight(&mp_dir, Arc::clone(&q_arc), 50_000_000).unwrap();
    assert!(
        hub2.contains(&want),
        "flushed mempool must still hold the tx after reopen"
    );
    assert_eq!(hub2.live_count(), 1);
    drop(hub2);

    let q = q_arc.as_ref();
    let mut bad = spend_anyone_can_spend(spend_txid, 0, Amount::from_sat(47_0000_0000));
    bad.input[0].script_sig = ScriptBuf::from_bytes(vec![0x6a]);

    let tip = chain.tip_hash();
    let tip_time = chain.blocks.last().unwrap().header.time;
    let h = chain.spend_height + 1;
    let bad_block = mine_regtest_block(tip, tip_time + 600, h, vec![bad]);

    let ms_skip = Milestone { height: h };
    let ms_check = Milestone { height: h - 1 };
    assert!(ms_skip.skips_scripts_at(h));
    assert!(!ms_check.skips_scripts_at(h));

    let err = accept_and_connect_block(q, &params, Height(h), &bad_block, ms_check)
        .expect_err("invalid script above milestone must fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("script") || msg.contains("opcode") || msg.contains("return"),
        "expected script failure above milestone, got: {err}"
    );
    assert_eq!(q.tip_height(), Some(Height(chain.spend_height)));

    accept_and_connect_block(q, &params, Height(h), &bad_block, ms_skip)
        .expect("invalid script below milestone must be skipped");
    assert_eq!(q.tip_height(), Some(Height(h)));

    let ms_hi = Milestone { height: 1_000_000 };
    let mut phantom = mine_regtest_block(
        bad_block.block_hash(),
        bad_block.header.time + 600,
        h + 1,
        vec![],
    );
    phantom.txdata.push(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0xcd; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    });
    phantom.header.merkle_root = phantom.compute_merkle_root().unwrap();
    let ctx = ValidationContext::at(&params, Height(h + 1), ms_hi);
    let err = validate_block_connect(q, &phantom, &ctx, None).expect_err("prevout must fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("prev")
            || msg.contains("not found")
            || msg.contains("missing")
            || msg.contains("input")
            || msg.contains("spend")
            || msg.contains("lookup stage miss")
            || msg.contains("invariant"),
        "expected prevout / lookup-miss failure under milestone, got: {err}"
    );
}

/// Archive reconstruct of height 1 after dropping RAM (reindex / lost-head analog).
#[test]
fn analog_reconstruct_after_lost_head() {
    let td = TestDatadir::new().unwrap();
    let params = ChainParams::regtest();
    let genesis = regtest_genesis();
    let store = td.store_path();
    let b1;
    {
        let q = Query::open_or_create_tiny(&store).unwrap();
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        b1 = mine_regtest_block(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        let b2 = mine_regtest_block(b1.block_hash(), b1.header.time + 600, 2, vec![]);
        accept_and_connect_block(&q, &params, Height(2), &b2, Milestone::NONE).unwrap();
        q.flush().unwrap();
        assert_eq!(q.tip_height(), Some(Height(2)));
        // Drop `q` — RAM cache / process head is gone; Class A archive stays.
    }

    let q2 = Query::open_or_create_tiny(&store).unwrap();
    assert_eq!(q2.tip_height(), Some(Height(2)));
    assert_reconstruct_eq(&q2, 1, &b1);
    let rec = q2
        .reconstruct_block_at_height(Height(1))
        .expect("reconstruct height 1 after lost RAM head");
    assert_eq!(rec.block_hash(), b1.block_hash());
}
