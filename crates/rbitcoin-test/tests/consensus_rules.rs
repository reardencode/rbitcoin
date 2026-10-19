//! Focused consensus-rule coverage (rules we implement outside rust-bitcoin).
//!
//! Matrix: see `docs/consensus-tests.md`.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, BlockHash, CompactTarget};
use rbitcoin_consensus::{genesis_block, ChainParams, ConsensusError, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_query::{
    accept_and_connect_block, confirm_wire_run, expected_next_bits, median_time_past,
    validate_header, ConfirmError, Query,
};
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
use rbitcoin_test::{pad_empty_from, TestDatadir};

fn regtest_q() -> (TestDatadir, Query, ChainParams) {
    let td = TestDatadir::new().unwrap();
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    let params = ChainParams::regtest();
    (td, q, params)
}

fn connect_genesis(q: &Query, params: &ChainParams) {
    let g = regtest_genesis();
    accept_and_connect_block(q, params, Height::GENESIS, &g, Milestone::NONE).unwrap();
}

/// Empty regtest through height 100, mined once. Snapshots at 11, 99, and 100
/// are the same headers; callers copy before they connect.
struct EmptyChainSnaps {
    _keep: TestDatadir,
    h11: std::path::PathBuf,
    h99: std::path::PathBuf,
    h100: std::path::PathBuf,
}

enum EmptySnap {
    H11,
    H99,
    H100,
}

fn empty_chain_snaps() -> &'static EmptyChainSnaps {
    use std::sync::OnceLock;
    static PAD: OnceLock<EmptyChainSnaps> = OnceLock::new();
    PAD.get_or_init(|| {
        let keep = TestDatadir::new().expect("empty chain pad");
        let live = keep.store_path();
        std::fs::create_dir_all(&live).unwrap();
        extend_empty_chain(&live, 11);
        let h11 = keep.path().join("h11");
        std::fs::create_dir_all(&h11).unwrap();
        copy_store_tree(&live, &h11);
        extend_empty_chain(&live, 99);
        let h99 = keep.path().join("h99");
        std::fs::create_dir_all(&h99).unwrap();
        copy_store_tree(&live, &h99);
        extend_empty_chain(&live, 100);
        EmptyChainSnaps {
            _keep: keep,
            h11,
            h99,
            h100: live,
        }
    })
}

fn extend_empty_chain(store: &std::path::Path, last: u32) {
    let q = Query::open_or_create_tiny(store).unwrap();
    let params = ChainParams::regtest();
    if q.tip_height().is_none() {
        connect_genesis(&q, &params);
        let g = regtest_genesis();
        let b1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    }
    let h = q.tip_height().unwrap().0;
    if h < last {
        let tip = q.reconstruct_block_at_height(Height(h)).unwrap();
        pad_empty_from(&q, &params, tip.block_hash(), tip.header.time, h + 1, last);
    }
    q.flush().expect("flush empty chain");
}

fn copy_store_tree(src: &std::path::Path, dst: &std::path::Path) {
    rbitcoin_store::testutil::copy_store_tree(src, dst);
}

fn open_empty_snap(which: EmptySnap) -> (TestDatadir, Query) {
    let pad = empty_chain_snaps();
    let src = match which {
        EmptySnap::H11 => &pad.h11,
        EmptySnap::H99 => &pad.h99,
        EmptySnap::H100 => &pad.h100,
    };
    let td = TestDatadir::new().unwrap();
    let dst = td.store_path();
    std::fs::create_dir_all(&dst).unwrap();
    copy_store_tree(src, &dst);
    let q = Query::open_or_create_tiny(&dst).unwrap();
    q.flush().expect("flush empty chain copy");
    (td, q)
}

#[test]
fn empty_through_100_copy_keeps_the_other_tip() {
    let (_da, qa) = open_empty_snap(EmptySnap::H100);
    let (_db, qb) = open_empty_snap(EmptySnap::H100);
    let (_d99, q99) = open_empty_snap(EmptySnap::H99);
    assert_eq!(qa.tip_height(), Some(Height(100)));
    assert_eq!(qb.tip_height(), Some(Height(100)));
    let tip_a = qa.reconstruct_block_at_height(Height(100)).unwrap();
    let tip_b = qb.reconstruct_block_at_height(Height(100)).unwrap();
    assert_eq!(tip_a.block_hash(), tip_b.block_hash());
    let cb_a = qa.reconstruct_block_at_height(Height(1)).unwrap();
    let cb_b = qb.reconstruct_block_at_height(Height(1)).unwrap();
    assert_eq!(cb_a.txdata[0].compute_txid(), cb_b.txdata[0].compute_txid());
    assert_eq!(q99.tip_height(), Some(Height(99)));
    assert_eq!(
        q99.reconstruct_block_at_height(Height(99))
            .unwrap()
            .block_hash(),
        qa.reconstruct_block_at_height(Height(99))
            .unwrap()
            .block_hash()
    );
    let next = mine_regtest_block(tip_a.block_hash(), tip_a.header.time + 600, 101, vec![]);
    accept_and_connect_block(
        &qa,
        &ChainParams::regtest(),
        Height(101),
        &next,
        Milestone::NONE,
    )
    .unwrap();
    assert_ne!(
        qa.reconstruct_block_at_height(Height(101))
            .unwrap()
            .block_hash(),
        tip_b.block_hash()
    );
    assert_eq!(qb.tip_height(), Some(Height(100)));
    assert_eq!(
        qb.reconstruct_block_at_height(Height(100))
            .unwrap()
            .block_hash(),
        tip_b.block_hash()
    );
    assert_eq!(q99.tip_height(), Some(Height(99)));
}

// ─── Header rules ───────────────────────────────────────────────────────────

fn pin_h6_pow_limit(q: &Query, params: &ChainParams, genesis: &bitcoin::Block) {
    let near = mine_regtest_block(genesis.block_hash(), genesis.header.time + 1, 1, vec![]);
    let mut tight = params.clone();
    tight.pow_limit = ChainParams::mainnet().pow_limit;
    let err = validate_header(q, &tight, Height(1), &near.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadHeader(s)) if s.contains("pow limit")),
        "h6: {err:?}"
    );
}

fn pin_bip68_time_lock(
    q: &Query,
    params: &ChainParams,
    child_txid: bitcoin::Txid,
    mut tip: BlockHash,
    mut time: u32,
) {
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::Sequence;

    let create_h = q.tip_height().expect("tip").0;
    let coin_mtp = median_time_past(q, Height(create_h.saturating_sub(1))).unwrap();
    let type_flag = 1u32 << 22;
    let n = 2u32;
    let min_time = i64::from(coin_mtp) + ((n as i64) << 9) - 1;

    let mut csv_time = spend_anyone_can_spend(child_txid, 0, Amount::from_sat(48_0000_0000));
    csv_time.version = TxVersion::TWO;
    csv_time.input[0].sequence = Sequence::from_consensus(type_flag | n);

    let early_h = create_h + 1;
    let prev_mtp = median_time_past(q, Height(create_h)).unwrap();
    assert!(
        min_time >= i64::from(prev_mtp),
        "fixture: n=2 still locked at {early_h} min_time={min_time} prev_mtp={prev_mtp}"
    );
    let early = mine_regtest_block(tip, time + 600, early_h, vec![csv_time.clone()]);
    let err = accept_and_connect_block(q, params, Height(early_h), &early, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("nonfinal")),
        "bip68 time just short: {err:?}"
    );

    let mut next_h = early_h;
    loop {
        let mtp = median_time_past(q, q.tip_height().unwrap()).unwrap();
        if i64::from(mtp) > min_time {
            break;
        }
        if next_h > create_h + 20 {
            panic!("mtp never exceeded bip68 min_time={min_time} mtp={mtp} h={next_h}");
        }
        (tip, time) = pad_empty_from(q, params, tip, time, next_h, next_h);
        next_h += 1;
    }
    let ok_h = q.tip_height().unwrap().0 + 1;
    let ok = mine_regtest_block(tip, time + 600, ok_h, vec![csv_time]);
    accept_and_connect_block(q, params, Height(ok_h), &ok, Milestone::NONE)
        .expect("bip68 time after MTP clears");
}

#[test]
fn h8_rejects_timestamp_too_far_in_future() {
    let (_td, q, params) = regtest_q();
    connect_genesis(&q, &params);
    let g = regtest_genesis();
    // Far beyond 2h network-adjusted (we use wall clock) allowance.
    let far = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1_700_000_000)
        .saturating_add(3 * 60 * 60);
    let mut bad = mine_regtest_block(g.block_hash(), far, 1, vec![]);
    let expected = expected_next_bits(&q, &params, Height(1), far).unwrap();
    bad.header.bits = expected;
    let target = bitcoin::Target::from_compact(expected);
    for nonce in 0..u32::MAX {
        bad.header.nonce = nonce;
        if bad.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let err = validate_header(&q, &params, Height(1), &bad.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadHeader(s)) if s.contains("future")),
        "{err:?}"
    );
}

fn grind_pow(block: &mut bitcoin::Block) {
    let target = bitcoin::Target::from_compact(block.header.bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            return;
        }
    }
    panic!("failed to grind regtest pow");
}

fn pin_subsidy_interval_two_overlay() {
    let (_td, q, mut params) = regtest_q();
    params.overlay_subsidy_halving_interval(2);
    let g = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &g, Milestone::NONE).unwrap();
    let h1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    accept_and_connect_block(&q, &params, Height(1), &h1, Milestone::NONE)
        .expect("interval-1 empty still 50 BTC");
    assert_eq!(q.tip_height(), Some(Height(1)));

    let old_floor = mine_regtest_block(h1.block_hash(), h1.header.time + 599, 2, vec![]);
    let err = accept_and_connect_block(&q, &params, Height(2), &old_floor, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadBlock(s))) if s.contains("coinbase excess")),
        "50 BTC at interval must exceed the new 25 BTC floor: {err:?}"
    );

    let mut excess = mine_regtest_block(h1.block_hash(), h1.header.time + 601, 2, vec![]);
    excess.txdata[0].output[0].value = Amount::from_sat(25_0000_0000 + 1);
    excess.header.merkle_root = excess.compute_merkle_root().unwrap();
    grind_pow(&mut excess);
    let err = accept_and_connect_block(&q, &params, Height(2), &excess, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadBlock(s))) if s.contains("coinbase excess")),
        "subsidy+1 at new floor: {err:?}"
    );

    let mut h2 = mine_regtest_block(h1.block_hash(), h1.header.time + 600, 2, vec![]);
    h2.txdata[0].output[0].value = Amount::from_sat(25_0000_0000);
    h2.header.merkle_root = h2.compute_merkle_root().unwrap();
    grind_pow(&mut h2);
    accept_and_connect_block(&q, &params, Height(2), &h2, Milestone::NONE)
        .expect("first halving empty is 25 BTC");
    assert_eq!(q.tip_height(), Some(Height(2)));
}

#[test]
fn h7_rejects_header_hash_above_target() {
    let (_td, q, params) = {
        let td = TestDatadir::new().unwrap();
        let q = Query::open_or_create_tiny(td.store_path()).unwrap();
        let params = ChainParams::mainnet();
        (td, q, params)
    };
    let g = genesis_block(&params);
    accept_and_connect_block(&q, &params, Height::GENESIS, &g, Milestone::NONE).unwrap();
    let mut h = g.header;
    h.prev_blockhash = g.block_hash();
    h.time = g.header.time + 600;
    h.version = bitcoin::block::Version::from_consensus(1);
    h.nonce = 0;
    let expected = expected_next_bits(&q, &params, Height(1), h.time).unwrap();
    h.bits = expected;
    if h.validate_pow(bitcoin::Target::from_compact(h.bits))
        .is_ok()
    {
        h.nonce = h.nonce.wrapping_add(1);
    }
    let err = validate_header(&q, &params, Height(1), &h).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::InvalidPow)),
        "expected InvalidPow, got {err:?}"
    );
}

/// Blocks `1..=spend_h` on regtest genesis; block `spend_h` spends block 1's coinbase.
fn run_spending_first_coinbase_at(spend_h: u32) -> Vec<(Height, bitcoin::Block)> {
    let g = regtest_genesis();
    let mut prev = g.block_hash();
    let mut time = g.header.time;
    let mut cb_txid = None;
    let mut run = Vec::with_capacity(spend_h as usize);
    for h in 1..=spend_h {
        time += 600;
        let txs = match cb_txid {
            Some(txid) if h == spend_h => {
                vec![spend_anyone_can_spend(
                    txid,
                    0,
                    Amount::from_sat(49_0000_0000),
                )]
            }
            _ => Vec::new(),
        };
        let b = mine_regtest_block(prev, time, h, txs);
        cb_txid.get_or_insert(b.txdata[0].compute_txid());
        prev = b.block_hash();
        run.push((Height(h), b));
    }
    run
}

#[test]
fn coinbase_maturity_holds_inside_one_confirm_batch() {
    let maturity = ChainParams::regtest().coinbase_maturity();
    for (spend_h, mature) in [(maturity, false), (maturity + 1, true)] {
        let (_td, q, params) = regtest_q();
        connect_genesis(&q, &params);
        let run = run_spending_first_coinbase_at(spend_h);
        let res = confirm_wire_run(&q, &params, Milestone::NONE, &run);
        if mature {
            res.expect("coinbase spent at created+100 in the same batch");
            assert_eq!(q.tip_height(), Some(Height(spend_h)));
        } else {
            assert!(
                matches!(res, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("immature")),
                "coinbase spent at created+99 in the same batch: {res:?}"
            );
            assert_eq!(q.tip_height(), Some(Height::GENESIS));
        }
    }
}

/// Core connects a run one block at a time, so a parent created in a later
/// block of the same confirm batch is a missing input
/// (`bad-txns-inputs-missingorspent`), not a batch pin hit.
#[test]
fn same_batch_spend_of_a_later_block_is_missing() {
    let (_td, q) = open_empty_snap(EmptySnap::H100);
    let params = ChainParams::regtest();
    assert_eq!(q.tip_height(), Some(Height(100)));
    let tip_blk = q.reconstruct_block_at_height(Height(100)).unwrap();
    let (tip, time) = (tip_blk.block_hash(), tip_blk.header.time);
    let b1 = q.reconstruct_block_at_height(Height(1)).unwrap();

    let parent = spend_anyone_can_spend(
        b1.txdata[0].compute_txid(),
        0,
        Amount::from_sat(49_0000_0000),
    );
    let parent_txid = parent.compute_txid();
    let child = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(48_0000_0000));

    let child_first = mine_regtest_block(tip, time + 600, 101, vec![child.clone()]);
    let parent_second = mine_regtest_block(
        child_first.block_hash(),
        time + 1200,
        102,
        vec![parent.clone()],
    );
    let err = confirm_wire_run(
        &q,
        &params,
        Milestone::NONE,
        &[
            (Height(101), child_first.clone()),
            (Height(102), parent_second),
        ],
    );
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
        ),
        "spend of an output created one block later in the batch: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    // Both bodies are archived now, and the parent is not connected.
    let err = confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(101), child_first)]);
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
        ),
        "the spending block retried alone: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let b101 = mine_regtest_block(tip, time + 600, 101, vec![parent]);
    let b102 = mine_regtest_block(b101.block_hash(), time + 1200, 102, vec![child]);
    let b102_hash = b102.block_hash();
    confirm_wire_run(
        &q,
        &params,
        Milestone::NONE,
        &[(Height(101), b101), (Height(102), b102)],
    )
    .expect("parent block before child block in one batch");
    assert_eq!(q.tip_height(), Some(Height(102)));

    let again = spend_anyone_can_spend(parent_txid, 0, Amount::from_sat(1));
    let b103 = mine_regtest_block(b102_hash, time + 1800, 103, vec![again]);
    let err = confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(103), b103)]);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::PrevoutSpent))),
        "second spend of the parent output: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(102)));
}

#[allow(clippy::cognitive_complexity)] // one fixture, many boundary arms
#[test]
// btc-lean: BLK-015 BLK-016 BLK-017 BLK-018 BLK-019 BLK-020 BLK-021 BLK-102 BLK-103 BLK-104 INV-027
// btc-lean: INV-028 INV-088 INV-089 INV-090 INV-091 INV-092 INV-093 INV-109 SWT-029 SWT-030 SWT-031
// btc-lean: SWT-032 SWT-033 SWT-034 SWT-035 TXV-020 TXV-021 TXV-070
fn header_and_spending_boundaries() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Sequence, Witness};

    let (_td, q, mut params) = regtest_q();
    params.apply_test_activation_height("segwit", 2).unwrap();
    let g = regtest_genesis();
    let mut bad_g = g.clone();
    bad_g.header.nonce = g.header.nonce.wrapping_add(1);
    let err = validate_header(&q, &params, Height::GENESIS, &bad_g.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadHeader(s)) if s.contains("genesis")),
        "h1: {err:?}"
    );
    accept_and_connect_block(&q, &params, Height::GENESIS, &g, Milestone::NONE).unwrap();

    let mut pre_segwit_spend = spend_anyone_can_spend(
        bitcoin::Txid::from_byte_array([0xa1; 32]),
        0,
        Amount::from_sat(1),
    );
    pre_segwit_spend.input[0].witness = Witness::from_slice(&[&[0x01]]);
    let pre_segwit = mine_regtest_block(
        g.block_hash(),
        g.header.time + 600,
        1,
        vec![pre_segwit_spend],
    );
    let err = accept_and_connect_block(&q, &params, Height(1), &pre_segwit, Milestone::NONE);
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::BadBlock(
                "unexpected witness before segwit"
            )))
        ),
        "pre-activation witness block must hit the SegWit gate: {err:?}"
    );

    let mut bad_prev = mine_regtest_block(g.block_hash(), g.header.time + 1, 1, vec![]);
    bad_prev.header.prev_blockhash = BlockHash::from_byte_array([0xee; 32]);
    grind_pow(&mut bad_prev);
    let err = validate_header(&q, &params, Height(1), &bad_prev.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadPrev)),
        "h2: {err:?}"
    );

    let mut bad_bits = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    bad_bits.header.bits = CompactTarget::from_consensus(0x207f_fffe);
    grind_pow(&mut bad_bits);
    let err = validate_header(&q, &params, Height(1), &bad_bits.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadHeader(s)) if s.contains("bits") || s.contains("proof")),
        "h5: {err:?}"
    );

    let b1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    pin_h6_pow_limit(&q, &params, &g);
    validate_header(&q, &params, Height(1), &b1.header).expect("valid parent, pow, bits");
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let cb_txid = b1.txdata[0].compute_txid();

    let (_d11, q11) = open_empty_snap(EmptySnap::H11);
    assert_eq!(q11.tip_height(), Some(Height(11)));
    let tip11 = q11.reconstruct_block_at_height(Height(11)).unwrap();
    assert_eq!(
        q11.reconstruct_block_at_height(Height(1)).unwrap().txdata[0].compute_txid(),
        cb_txid
    );
    let tip = tip11.block_hash();
    let mtp = median_time_past(&q11, Height(11)).unwrap();
    let mut eq = mine_regtest_block(tip, mtp, 12, vec![]);
    let expected = expected_next_bits(&q11, &params, Height(12), eq.header.time).unwrap();
    eq.header.bits = expected;
    grind_pow(&mut eq);
    let err = validate_header(&q11, &params, Height(12), &eq.header).unwrap_err();
    assert!(
        matches!(err, ConfirmError::Rules(ConsensusError::BadHeader(s)) if s.contains("median-time")),
        "time==mtp: {err:?}"
    );

    let mut after = mine_regtest_block(tip, mtp + 1, 12, vec![]);
    after.header.bits = expected_next_bits(&q11, &params, Height(12), after.header.time).unwrap();
    grind_pow(&mut after);
    validate_header(&q11, &params, Height(12), &after.header).expect("time==mtp+1");

    let (_d99, q99) = open_empty_snap(EmptySnap::H99);
    assert_eq!(q99.tip_height(), Some(Height(99)));
    let tip99 = q99.reconstruct_block_at_height(Height(99)).unwrap();
    let immature = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    let bad100 = mine_regtest_block(
        tip99.block_hash(),
        tip99.header.time + 600,
        100,
        vec![immature],
    );
    let err = accept_and_connect_block(&q99, &params, Height(100), &bad100, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("immature")),
        "immature at created+99: {err:?}"
    );
    assert_eq!(q99.tip_height(), Some(Height(99)));

    let (_d100, q) = open_empty_snap(EmptySnap::H100);
    assert_eq!(q.tip_height(), Some(Height(100)));
    let tip100 = q.reconstruct_block_at_height(Height(100)).unwrap();
    let tip = tip100.block_hash();
    let mut time = tip100.header.time;
    time += 600;

    for (prev_txid, case) in [
        ([0xabu8; 32], "unknown txid"),
        ([0u8; 32], "zero txid/vout 0"),
    ] {
        let missing = spend_anyone_can_spend(
            bitcoin::Txid::from_byte_array(prev_txid),
            0,
            Amount::from_sat(1),
        );
        let miss_block = mine_regtest_block(tip, time, 101, vec![missing]);
        let err = accept_and_connect_block(&q, &params, Height(101), &miss_block, Milestone::NONE);
        assert!(
            matches!(
                err,
                Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
            ),
            "{case} must reject as MissingPrevout: {err:?}"
        );
    }

    // Core CheckTxInputs: a confirmed txid with no output at `vout` is
    // bad-txns-inputs-missingorspent, not a store fault.
    let past_end = u32::try_from(b1.txdata[0].output.len()).unwrap();
    for vout in [past_end, past_end + 1, u32::MAX - 1] {
        let oob = spend_anyone_can_spend(cb_txid, vout, Amount::from_sat(1));
        let oob_block = mine_regtest_block(tip, time, 101, vec![oob]);
        let err = accept_and_connect_block(&q, &params, Height(101), &oob_block, Milestone::NONE);
        assert!(
            matches!(
                err,
                Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
            ),
            "confirmed txid vout {vout} past n_out must reject as MissingPrevout: {err:?}"
        );
        assert_eq!(q.tip_height(), Some(Height(100)));
    }

    // IBD batch: the parent is created one block earlier in the same confirm run.
    let parent = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    let oob_child = spend_anyone_can_spend(parent.compute_txid(), 1, Amount::from_sat(1));
    let b101 = mine_regtest_block(tip, time, 101, vec![parent]);
    let b102 = mine_regtest_block(b101.block_hash(), time + 600, 102, vec![oob_child]);
    let err = confirm_wire_run(
        &q,
        &params,
        Milestone::NONE,
        &[(Height(101), b101), (Height(102), b102)],
    );
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
        ),
        "same-batch parent vout past n_out must reject as MissingPrevout: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let mut nonfinal = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    nonfinal.lock_time = LockTime::from_height(101).unwrap();
    nonfinal.input[0].sequence = Sequence::ZERO;
    let nf_block = mine_regtest_block(tip, time, 101, vec![nonfinal]);
    let err = accept_and_connect_block(&q, &params, Height(101), &nf_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("nonfinal") || s.contains("not final")),
        "locktime==height: {err:?}"
    );

    let mut csv_early = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    csv_early.version = TxVersion::TWO;
    csv_early.input[0].sequence = Sequence::from_consensus(200);
    let csv_block = mine_regtest_block(tip, time, 101, vec![csv_early]);
    let err = accept_and_connect_block(&q, &params, Height(101), &csv_block, Milestone::NONE);
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::BadTx(
                "bad-txns-nonfinal"
            )))
        ),
        "relative lock 200 at height 101 must reject, got {err:?}"
    );

    let over = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(50_0000_0000 + 1));
    let over_block = mine_regtest_block(tip, time, 101, vec![over]);
    let err = accept_and_connect_block(&q, &params, Height(101), &over_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("in < out")),
        "in < out: {err:?}"
    );

    let mut excess = mine_regtest_block(tip, time, 101, vec![]);
    excess.txdata[0].output[0].value = Amount::from_sat(50_0000_0000 + 1);
    excess.header.merkle_root = excess.compute_merkle_root().unwrap();
    grind_pow(&mut excess);
    let err = accept_and_connect_block(&q, &params, Height(101), &excess, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadBlock(s))) if s.contains("coinbase excess")),
        "subsidy+1: {err:?}"
    );

    let s1 = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(25_0000_0000));
    let s2 = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(24_0000_0000));
    let dup = mine_regtest_block(tip, time, 101, vec![s1, s2]);
    let err = accept_and_connect_block(&q, &params, Height(101), &dup, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("double spend")),
        "same-block double spend: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let parent = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    let child = spend_anyone_can_spend(parent.compute_txid(), 0, Amount::from_sat(48_0000_0000));
    let bad_order = mine_regtest_block(tip, time, 101, vec![child, parent]);
    let err = accept_and_connect_block(&q, &params, Height(101), &bad_order, Milestone::NONE);
    assert!(
        matches!(
            err,
            Err(ConfirmError::Rules(ConsensusError::MissingPrevout))
        ),
        "child-before-parent must not become tip: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let mut empty_out = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(1));
    empty_out.output.clear();
    let empty_block = mine_regtest_block(tip, time, 101, vec![empty_out]);
    let err = accept_and_connect_block(&q, &params, Height(101), &empty_block, Milestone::NONE);
    assert!(
        // btc-lean: INV-002 TXV-002
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("no outputs")),
        "non-coinbase empty vout: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let mut parent = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(50_0000_0000));
    parent.version = TxVersion::TWO;
    parent.lock_time = LockTime::from_height(100).unwrap();
    parent.input[0].sequence = Sequence::from_consensus(10);
    let child = spend_anyone_can_spend(parent.compute_txid(), 0, Amount::from_sat(49_0000_0000));
    let child_txid = child.compute_txid();
    let good = mine_regtest_block(tip, time, 101, vec![parent, child]);
    accept_and_connect_block(&q, &params, Height(101), &good, Milestone::NONE).expect(
        "parent-before-child, exact subsidy, in==out, OP_TRUE, seq=10, mature, locktime 100",
    );
    assert_eq!(q.tip_height(), Some(Height(101)));

    let spent_again = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(1));
    let again = mine_regtest_block(good.block_hash(), time + 600, 102, vec![spent_again]);
    let err = accept_and_connect_block(&q, &params, Height(102), &again, Milestone::NONE);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::PrevoutSpent)))
            || matches!(
                err,
                Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("double spend") || s.contains("spent")
            ),
        "already spent: {err:?}"
    );
    pin_bip68_time_lock(&q, &params, child_txid, good.block_hash(), time);
    pin_subsidy_interval_two_overlay();
}

/// Below BIP34 two coinbases can share a txid. Core rejects the second while
/// the first is unspent, including when both blocks arrive in one run.
#[test]
fn bip30_duplicate_coinbase_in_one_batch() {
    let (_td, q, mut params) = regtest_q();
    params.apply_test_activation_height("bip34", 1_000).unwrap();
    connect_genesis(&q, &params);
    let g = regtest_genesis();
    let b1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    let mut b2 = mine_regtest_block(b1.block_hash(), b1.header.time + 600, 2, vec![]);
    b2.txdata[0] = b1.txdata[0].clone();
    b2.header.merkle_root = b2.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut b2.header);
    let bip30 = |r: &Result<_, ConfirmError>| matches!(r, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("BIP30"));

    let one_batch = confirm_wire_run(
        &q,
        &params,
        Milestone::NONE,
        &[(Height(1), b1.clone()), (Height(2), b2.clone())],
    );
    assert!(
        bip30(&one_batch),
        "duplicate coinbase one block later in the same batch: {one_batch:?}"
    );
    assert_eq!(q.tip_height(), Some(Height::GENESIS));

    confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(1), b1)]).unwrap();
    let next_batch = confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(2), b2)]);
    assert!(
        bip30(&next_batch),
        "duplicate coinbase in the next batch: {next_batch:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(1)));
}

/// Below BIP34 a coinbase can repeat once its first copy is spent. Core 31.1
/// accepts `repeated_coinbase_chain(203, 48 BTC, true)`: h1 creates X, h102
/// spends X:0, h103 creates X again, h203 spends the recreated X:0.
type Chain = Vec<(Height, bitcoin::Block)>;

fn repeated_coinbase_chain(
    second_spend_height: u32,
    second_spend_sat: u64,
    recreate: bool,
) -> Chain {
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let g = regtest_genesis();
    let mut run: Chain = Vec::new();
    let mut x: Option<bitcoin::Transaction> = None;
    for h in 1..=second_spend_height.max(103) {
        let (prev, time) = run
            .last()
            .map(|(_, b)| (b.block_hash(), b.header.time + 600))
            .unwrap_or((g.block_hash(), g.header.time + 600));
        let spend = |sat: u64| {
            let x = x.as_ref().expect("X before its spends");
            spend_anyone_can_spend(x.compute_txid(), 0, Amount::from_sat(sat))
        };
        let txs = match h {
            102 => vec![spend(49_0000_0000)],
            h if h == second_spend_height => vec![spend(second_spend_sat)],
            _ => vec![],
        };
        let mut b = rbitcoin_consensus::mine_regtest_paying(prev, time, h, op_true.clone(), txs);
        match (h, &x) {
            (1, _) => x = Some(b.txdata[0].clone()),
            (103, Some(first)) if recreate => {
                b.txdata[0] = first.clone();
                b.header.merkle_root = b.compute_merkle_root().unwrap();
                rbitcoin_consensus::grind_regtest_pow(&mut b.header);
            }
            _ => {}
        }
        run.push((Height(h), b));
    }
    run
}

const BATCH_CUTS: [&[usize]; 9] = [
    &[101, 102, 103, 149, 202],
    &[],
    &[101],
    &[102],
    &[54],
    &[102, 150],
    &[103],
    &[101, 103],
    &[54, 103],
];

/// Connect `chain` split into confirm batches at `cuts`; the first error ends it.
fn connect_in_batches(
    chain: &[(Height, bitcoin::Block)],
    cuts: &[usize],
) -> Result<Option<Height>, String> {
    connect_in_batches_bip34_at(chain, cuts, 1_000)
}

fn connect_in_batches_bip34_at(
    chain: &[(Height, bitcoin::Block)],
    cuts: &[usize],
    bip34_height: u32,
) -> Result<Option<Height>, String> {
    let (_td, q, mut params) = regtest_q();
    params
        .apply_test_activation_height("bip34", bip34_height)
        .unwrap();
    connect_genesis(&q, &params);
    let mut lo = 0usize;
    for hi in cuts
        .iter()
        .copied()
        .filter(|&c| c < chain.len())
        .chain([chain.len()])
    {
        confirm_wire_run(&q, &params, Milestone::NONE, &chain[lo..hi])
            .map_err(|e| format!("heights {}..={}: {e:?}", lo + 1, hi))?;
        lo = hi;
    }
    Ok(q.tip_height())
}

/// Height 1 (BIP34 still off) creates a coinbase whose scriptSig already pushes
/// 3. Height 2 is an ordinary BIP34 coinbase. Height 3 repeats the height-1
/// coinbase while its output is still unspent. Subsidy matches at 1 and 3.
/// Core accepts height 3 only when the header at BIP34 height is `bip34_hash`.
fn future_height_coinbase_over_unspent() -> Chain {
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let regtest = ChainParams::regtest();
    let value = rbitcoin_consensus::block::block_subsidy(1, &regtest);
    assert_eq!(
        value,
        rbitcoin_consensus::block::block_subsidy(3, &regtest),
        "heights 1 and 3 must pay the same subsidy"
    );
    let x =
        rbitcoin_consensus::regtest_coinbase(3, Amount::from_sat(value as u64), op_true.clone());
    let g = regtest_genesis();
    let mut run: Chain = Vec::new();
    for h in 1..=3 {
        let (prev, time) = run
            .last()
            .map(|(_, b)| (b.block_hash(), b.header.time + 600))
            .unwrap_or((g.block_hash(), g.header.time + 600));
        let mut b = rbitcoin_consensus::mine_regtest_paying(prev, time, h, op_true.clone(), vec![]);
        if h != 2 {
            b.txdata[0] = x.clone();
            b.header.merkle_root = b.compute_merkle_root().unwrap();
            rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        }
        run.push((Height(h), b));
    }
    run
}

/// `bip34_height` is 2. `one_write` connects 1..=3 in one `confirm_wire_run`.
fn connect_with_bip34_ancestor(
    chain: &Chain,
    bip34_hash: BlockHash,
    one_write: bool,
) -> Result<Option<Height>, String> {
    let (_td, q, mut params) = regtest_q();
    params.btc.bip34_height = 2;
    params.bip34_hash = Some(bip34_hash);
    connect_genesis(&q, &params);
    let connect = |slice: &[(Height, bitcoin::Block)]| {
        confirm_wire_run(&q, &params, Milestone::NONE, slice).map_err(|e| {
            format!(
                "{e:?}; tip {}",
                q.tip_height().map(|h| h.0).unwrap_or(u32::MAX)
            )
        })
    };
    if one_write {
        connect(chain)?;
    } else {
        for i in 0..chain.len() {
            connect(&chain[i..i + 1])?;
        }
    }
    Ok(q.tip_height())
}

/// The BIP34 block and the later overwrite share one write. The skip must see
/// this write's header at BIP34 height, which is not committed yet.
#[test]
fn bip34_ancestor_in_the_same_write_skips_bip30() {
    let chain = future_height_coinbase_over_unspent();
    let ancestor = chain[1].1.block_hash();
    assert_eq!(
        connect_with_bip34_ancestor(&chain, ancestor, true),
        Ok(Some(Height(3)))
    );
}

/// One block at a time commits the BIP34 header before the overwrite.
#[test]
fn bip34_ancestor_already_committed_skips_bip30() {
    let chain = future_height_coinbase_over_unspent();
    let ancestor = chain[1].1.block_hash();
    assert_eq!(
        connect_with_bip34_ancestor(&chain, ancestor, false),
        Ok(Some(Height(3)))
    );
}

/// A different hash at BIP34 height keeps BIP30 on, in one write and one
/// block at a time. A failed write commits nothing, so the one-write tip
/// stays genesis. The one-block path stops at 2.
#[test]
fn wrong_bip34_ancestor_keeps_bip30_on() {
    let chain = future_height_coinbase_over_unspent();
    let wrong = chain[0].1.block_hash();
    let one_write = connect_with_bip34_ancestor(&chain, wrong, true);
    assert!(
        matches!(&one_write, Err(e) if e.contains("BIP30") && e.contains("tip 0")),
        "one write: {one_write:?}"
    );
    let one_by_one = connect_with_bip34_ancestor(&chain, wrong, false);
    assert!(
        matches!(&one_by_one, Err(e) if e.contains("BIP30") && e.contains("tip 2")),
        "one block at a time: {one_by_one:?}"
    );
}

/// After the match is remembered, disconnecting the BIP34 block must not
/// keep skipping on the replacement chain.
#[test]
fn bip34_ancestor_reorg_drops_the_match() {
    let chain = future_height_coinbase_over_unspent();
    let ancestor = chain[1].1.block_hash();
    let (_td, q, mut params) = regtest_q();
    params.btc.bip34_height = 2;
    params.bip34_hash = Some(ancestor);
    connect_genesis(&q, &params);
    for i in 0..chain.len() {
        confirm_wire_run(&q, &params, Milestone::NONE, &chain[i..i + 1])
            .expect("one block at a time");
    }
    assert_eq!(q.tip_height(), Some(Height(3)));
    q.disconnect_tip().unwrap();
    q.disconnect_tip().unwrap();
    assert_eq!(q.tip_height(), Some(Height(1)));

    let b1 = &chain[0].1;
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let b2 = rbitcoin_consensus::mine_regtest_paying(
        b1.block_hash(),
        b1.header.time + 1_200,
        2,
        op_true.clone(),
        vec![],
    );
    assert_ne!(b2.block_hash(), ancestor);
    let mut b3 = rbitcoin_consensus::mine_regtest_paying(
        b2.block_hash(),
        b2.header.time + 600,
        3,
        op_true,
        vec![],
    );
    b3.txdata[0] = b1.txdata[0].clone();
    b3.header.merkle_root = b3.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut b3.header);
    confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(2), b2)]).unwrap();
    let err = confirm_wire_run(&q, &params, Milestone::NONE, &[(Height(3), b3)]);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("BIP30")),
        "replacement ancestor must keep BIP30 on: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(2)));
}

/// After BIP34 a coinbase can still repeat an older one whose scriptSig
/// already starts with the later height (Core's 490,897 / 1,983,702 case).
/// With BIP34 at 100, Core 31.1 accepts: h1 creates X with scriptSig
/// push(150), h149 spends X:0, h150 creates X again, h250 spends the new X:0.
fn bip34_era_repeat_chain(second_spend_sat: u64) -> Chain {
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let x = rbitcoin_consensus::regtest_coinbase(150, Amount::from_sat(25_0000_0000), op_true);
    let spend = |sat: u64| spend_anyone_can_spend(x.compute_txid(), 0, Amount::from_sat(sat));
    repeat_chain(250, &x, &[1, 150], |h| match h {
        149 => vec![spend(24_0000_0000)],
        250 => vec![spend(second_spend_sat)],
        _ => vec![],
    })
}

/// Chain to `tip` with coinbase `x` at each `x_at` height and `txs(h)` in block h.
fn repeat_chain(
    tip: u32,
    x: &bitcoin::Transaction,
    x_at: &[u32],
    txs: impl Fn(u32) -> Vec<bitcoin::Transaction>,
) -> Chain {
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    let g = regtest_genesis();
    let mut run: Chain = Vec::new();
    for h in 1..=tip {
        let (prev, time) = run
            .last()
            .map(|(_, b)| (b.block_hash(), b.header.time + 600))
            .unwrap_or((g.block_hash(), g.header.time + 600));
        let mut b = rbitcoin_consensus::mine_regtest_paying(prev, time, h, op_true.clone(), txs(h));
        if x_at.contains(&h) {
            b.txdata[0] = x.clone();
            b.header.merkle_root = b.compute_merkle_root().unwrap();
            rbitcoin_consensus::grind_regtest_pow(&mut b.header);
        }
        run.push((Height(h), b));
    }
    run
}

/// Pre-BIP34 (BIP34 at 1000) coinbase X paying 25 BTC, and `spend(prev, sat)`.
fn pre_bip34_x() -> bitcoin::Transaction {
    let op_true = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    rbitcoin_consensus::regtest_coinbase(1, Amount::from_sat(25_0000_0000), op_true)
}

fn spend_of(prev: &bitcoin::Transaction, sat: u64) -> bitcoin::Transaction {
    spend_anyone_can_spend(prev.compute_txid(), 0, Amount::from_sat(sat))
}

/// h102 creates P and spends P:0 in the same block; h103 spends P:0 again.
/// Core 31.1 rejects h103 (`bad-txns-inputs-missingorspent`), including when
/// IBD merges the two load batches into one write.
#[test]
fn respend_of_a_same_block_spend_rejects_in_any_split() {
    let x = pre_bip34_x();
    let p = spend_of(&x, 24_0000_0000);
    let chain = repeat_chain(103, &x, &[1], |h| match h {
        102 => vec![p.clone(), spend_of(&p, 23_0000_0000)],
        103 => vec![spend_of(&p, 22_0000_0000)],
        _ => vec![],
    });
    let spent = |got: &Result<Option<Height>, String>| matches!(got, Err(e) if ["PrevoutSpent", "double spend"].iter().any(|w| e.contains(w)));
    for cuts in [&[][..], &[102], &[54]] {
        let got = connect_in_batches(&chain, cuts);
        assert!(spent(&got), "cuts {cuts:?}: got {got:?}");
    }
    for cuts in [&[102][..], &[54, 102]] {
        let got = connect_merged(&chain, cuts, 1000);
        assert!(spent(&got), "merged, cuts {cuts:?}: got {got:?}");
    }
}

/// h102 spends X:0 by T and T:0 by U in the same block, h103 mines X again,
/// h204 repeats T, h205 spends the new T:0. Core 31.1 accepts to 205: the
/// first T was spent inside its own block.
#[test]
fn repeated_tx_spent_in_its_own_block_connects_in_any_split() {
    let x = pre_bip34_x();
    let t = spend_of(&x, 24_0000_0000);
    let chain = repeat_chain(205, &x, &[1, 103], |h| match h {
        102 => vec![t.clone(), spend_of(&t, 23_0000_0000)],
        204 => vec![t.clone()],
        205 => vec![spend_of(&t, 22_0000_0000)],
        _ => vec![],
    });
    for cuts in [&[][..], &[101], &[102], &[103], &[150], &[203]] {
        assert_eq!(
            connect_in_batches(&chain, cuts),
            Ok(Some(Height(205))),
            "cuts {cuts:?}"
        );
    }
    for cuts in [&[102][..], &[101, 103], &[150]] {
        assert_eq!(
            connect_merged(&chain, cuts, 1000),
            Ok(Some(Height(205))),
            "merged, cuts {cuts:?}"
        );
    }
}

/// X three times: h1, h103, h204, each copy spent before the next (h102,
/// h203) and the last at h304. Core 31.1 accepts to 304. With h1 connected
/// and the rest in one batch, the BIP30 check of h204 must count h102's spend
/// of the connected copy.
#[test]
fn third_copy_of_a_coinbase_connects_in_any_split() {
    let x = pre_bip34_x();
    let chain = repeat_chain(304, &x, &[1, 103, 204], |h| match h {
        102 => vec![spend_of(&x, 24_0000_0000)],
        203 => vec![spend_of(&x, 23_0000_0000)],
        304 => vec![spend_of(&x, 22_0000_0000)],
        _ => vec![],
    });
    for cuts in [&[][..], &[101], &[101, 204], &[102], &[203]] {
        assert_eq!(
            connect_in_batches(&chain, cuts),
            Ok(Some(Height(304))),
            "cuts {cuts:?}"
        );
    }
    for cuts in [&[101][..], &[150, 250]] {
        assert_eq!(
            connect_merged(&chain, cuts, 1000),
            Ok(Some(Height(304))),
            "merged, cuts {cuts:?}"
        );
    }
}

/// Same, but h204 mines X while h103's copy is still unspent. Core 31.1:
/// h204 `bad-txns-BIP30`. h102's spend of the connected copy does not count
/// as a spend of h103's copy.
#[test]
fn third_copy_over_an_unspent_copy_rejects_bip30_in_any_split() {
    let x = pre_bip34_x();
    let chain = repeat_chain(204, &x, &[1, 103, 204], |h| match h {
        102 => vec![spend_of(&x, 24_0000_0000)],
        _ => vec![],
    });
    for cuts in [&[][..], &[101], &[102], &[103]] {
        let got = connect_in_batches(&chain, cuts);
        assert!(
            matches!(&got, Err(e) if e.contains("BIP30")),
            "cuts {cuts:?}: got {got:?}"
        );
    }
    for cuts in [&[101][..], &[150]] {
        let got = connect_merged(&chain, cuts, 1000);
        assert!(
            matches!(&got, Err(e) if e.contains("BIP30")),
            "merged, cuts {cuts:?}: got {got:?}"
        );
    }
}

#[test]
fn bip34_era_repeat_connects_in_any_batch_split() {
    let chain = bip34_era_repeat_chain(23_0000_0000);
    for cuts in [
        &[][..],
        &[148],
        &[149],
        &[148, 150],
        &[100, 200],
        &[148, 149, 150, 249],
    ] {
        assert_eq!(
            connect_in_batches_bip34_at(&chain, cuts, 100),
            Ok(Some(Height(250))),
            "cuts {cuts:?}"
        );
    }
}

/// Core 31.1 rejects h250 with `bad-txns-BIP30` when it repeats h149's spend
/// byte for byte: h149's output is still unspent.
#[test]
fn bip34_era_repeated_spend_rejects_bip30_in_any_batch_split() {
    let chain = bip34_era_repeat_chain(24_0000_0000);
    for cuts in [&[][..], &[148], &[149], &[149, 150], &[100, 200]] {
        let got = connect_in_batches_bip34_at(&chain, cuts, 100);
        assert!(
            matches!(&got, Err(e) if e.contains("BIP30")),
            "cuts {cuts:?}: got {got:?}"
        );
    }
    for cuts in [&[149][..], &[100, 149, 200]] {
        let got = connect_merged(&chain, cuts, 100);
        assert!(
            matches!(&got, Err(e) if e.contains("BIP30")),
            "merged, cuts {cuts:?}: got {got:?}"
        );
    }
}

/// IBD's write path: load each slice ahead of the write (in-flight parents,
/// reserved fks), run scripts, merge the slices into one write batch, write once.
fn connect_merged(
    chain: &[(Height, bitcoin::Block)],
    load_cuts: &[usize],
    bip34_height: u32,
) -> Result<Option<Height>, String> {
    use rbitcoin_query::{
        confirm_scripts_phase, confirm_wire_load_phase_pipelined, confirm_write_phase, InFlight,
        ScriptPreverified, WireLoadPipeline,
    };
    let (_td, q, mut params) = regtest_q();
    params
        .apply_test_activation_height("bip34", bip34_height)
        .unwrap();
    connect_genesis(&q, &params);
    q.enter_direct_index_mode().unwrap();
    let none = ScriptPreverified::new();
    let mut inflight = InFlight::new();
    let mut next_tx_start = q.tx_body_count().saturating_add(1).max(1);
    let mut merged: Option<rbitcoin_query::ScriptOkBatch> = None;
    let mut lo = 0usize;
    for hi in load_cuts
        .iter()
        .copied()
        .filter(|&c| c < chain.len())
        .chain([chain.len()])
    {
        let slice = &chain[lo..hi];
        let pipe = WireLoadPipeline {
            path_lo: slice[0].0 .0,
            parent_hash: lo
                .checked_sub(1)
                .map(|i| chain[i].1.block_hash().to_byte_array()),
            next_tx_start,
            in_flight: &inflight,
            skeleton: None,
            carried_need: Vec::new(),
            carried_header_fks: Vec::new(),
            carried_header_hashes: Vec::new(),
        };
        let mat = confirm_wire_load_phase_pipelined(
            &q,
            &params,
            Milestone::NONE,
            slice,
            &none,
            Some(&pipe),
        )
        .map_err(|e| format!("load {}..={hi}: {e:?}", lo + 1))?;
        let plan = mat.batch.archive_plan.as_ref().expect("wire plan");
        inflight.note_pins(
            plan.planned_fks.iter().copied().zip(plan.batch_pin.iter()),
            Some(slice[slice.len() - 1].0 .0),
        );
        if let Some(last) = plan.planned_fks.last().and_then(|f| f.get()) {
            next_tx_start = last + 1;
        }
        let ok = confirm_scripts_phase(mat.batch)
            .map_err(|e| format!("scripts {}..={hi}: {e:?}", lo + 1))?;
        merged = Some(match merged.take() {
            None => ok.batch,
            Some(mut m) => {
                if m.append_contiguous(ok.batch).is_err() {
                    return Err(format!("merge at {}", lo + 1));
                }
                m
            }
        });
        lo = hi;
    }
    confirm_write_phase(&q, &params, Milestone::NONE, merged.expect("one slice"))
        .map_err(|e| format!("write: {e:?}"))?;
    Ok(q.tip_height())
}

#[test]
fn repeated_coinbase_connects_when_ibd_merges_load_batches() {
    let pre = repeated_coinbase_chain(203, 48_0000_0000, true);
    for cuts in [&[102][..], &[101, 103], &[54, 103, 150]] {
        assert_eq!(
            connect_merged(&pre, cuts, 1_000),
            Ok(Some(Height(203))),
            "pre-BIP34, load cuts {cuts:?}"
        );
    }
    let era = bip34_era_repeat_chain(23_0000_0000);
    for cuts in [&[149][..], &[100, 149, 200], &[148, 150]] {
        assert_eq!(
            connect_merged(&era, cuts, 100),
            Ok(Some(Height(250))),
            "BIP34 era, load cuts {cuts:?}"
        );
    }
}

/// The Core-valid chain above connects however IBD splits it into batches.
#[test]
fn repeated_coinbase_chain_connects_in_any_batch_split() {
    let chain = repeated_coinbase_chain(203, 48_0000_0000, true);
    for cuts in BATCH_CUTS {
        assert_eq!(
            connect_in_batches(&chain, cuts),
            Ok(Some(Height(203))),
            "cuts {cuts:?}"
        );
    }
}

/// What Core rejects around a repeated coinbase stays rejected in any split.
#[test]
fn repeated_coinbase_chain_rejects_what_core_rejects() {
    let cases: [(&str, Chain, &[&str]); 3] = [
        (
            "h203 repeats h102's spend while its output is unspent",
            repeated_coinbase_chain(203, 49_0000_0000, true),
            &["BIP30"],
        ),
        (
            "h203 spends X:0 again without a new X",
            repeated_coinbase_chain(203, 48_0000_0000, false),
            // Only spent errors: MissingPrevout would also match a spend bound
            // to a later copy, which is the bug this guards against.
            &["PrevoutSpent", "double spend"],
        ),
        (
            "h150 spends the new X before it matures",
            repeated_coinbase_chain(150, 48_0000_0000, true),
            &["immature"],
        ),
    ];
    for (what, chain, want) in &cases {
        for cuts in BATCH_CUTS {
            let got = connect_in_batches(chain, cuts);
            assert!(
                matches!(&got, Err(e) if want.iter().any(|w| e.contains(w))),
                "{what}, cuts {cuts:?}: got {got:?}, want one of {want:?}"
            );
        }
    }
}

/// A failed batch archives every body before Class C. Retrying the valid
/// prefix must bind through the archived stamp, not the fresh plan.
#[test]
fn repeated_coinbase_archived_retry_connects_the_valid_prefix() {
    let chain = repeated_coinbase_chain(150, 48_0000_0000, true);
    let (_td, q, mut params) = regtest_q();
    params.apply_test_activation_height("bip34", 1_000).unwrap();
    connect_genesis(&q, &params);
    let err = confirm_wire_run(&q, &params, Milestone::NONE, &chain);
    assert!(
        matches!(err, Err(ConfirmError::Rules(ConsensusError::BadTx(s))) if s.contains("immature")),
        "immature spend of the recreated coinbase: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height::GENESIS));
    confirm_wire_run(&q, &params, Milestone::NONE, &chain[..103])
        .expect("archived retry of h1..=h103");
    assert_eq!(q.tip_height(), Some(Height(103)));
}

// ─── Script flags (Core `GetBlockScriptFlags`) ──────────────────────────────

/// Core sets WITNESS on every block, not from the segwit height. Below the
/// overlaid segwit height a v0 program spend with an empty witness still
/// fails (native and P2SH-nested), and a native spend with a non-empty
/// scriptSig fails, where a bare-script read of the program would leave a
/// true stack.
#[test]
fn witness_program_rules_bind_below_segwit_height() {
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::ScriptBuf;

    let (_td, q, mut params) = regtest_q();
    params
        .apply_test_activation_height("segwit", 1_000)
        .unwrap();
    connect_genesis(&q, &params);
    let g = regtest_genesis();
    let b1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let cb_txid = b1.txdata[0].compute_txid();
    let (tip, time) = pad_empty_from(&q, &params, b1.block_hash(), b1.header.time, 2, 100);
    assert!(!params.segwit_active_at(101));

    let mut v0_program = vec![0x00, 0x14];
    v0_program.extend([0x11u8; 20]);
    let v0_program = ScriptBuf::from_bytes(v0_program);
    let p2sh_v0 = ScriptBuf::new_p2sh(&v0_program.script_hash());
    let redeem_push = PushBytesBuf::try_from(v0_program.to_bytes()).unwrap();

    for (spk, script_sig, case) in [
        (v0_program.clone(), ScriptBuf::new(), "native P2WPKH"),
        (
            v0_program.clone(),
            Builder::new().push_int(1).into_script(),
            "native P2WPKH with a scriptSig",
        ),
        (
            p2sh_v0,
            Builder::new().push_slice(&redeem_push).into_script(),
            "P2SH-P2WPKH",
        ),
    ] {
        let mut fund = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
        fund.output[0].script_pubkey = spk;
        let mut spend =
            spend_anyone_can_spend(fund.compute_txid(), 0, Amount::from_sat(48_0000_0000));
        spend.input[0].script_sig = script_sig;
        let block = mine_regtest_block(tip, time + 600, 101, vec![fund, spend]);
        let err = accept_and_connect_block(&q, &params, Height(101), &block, Milestone::NONE);
        assert!(
            matches!(err, Err(ConfirmError::Rules(ConsensusError::Script(_)))),
            "{case} below segwit height: {err:?}"
        );
        assert_eq!(q.tip_height(), Some(Height(100)));
    }
}
