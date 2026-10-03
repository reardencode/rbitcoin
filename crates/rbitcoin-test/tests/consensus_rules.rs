//! Focused consensus-rule coverage (rules we implement outside rust-bitcoin).
//!
//! Matrix: see `docs/consensus-tests.md`.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, BlockHash, CompactTarget};
use rbitcoin_consensus::{
    accept_and_connect_block, confirm_wire_run, expected_next_bits, genesis_block,
    median_time_past, validate_header, ChainParams, Checkpoint, ConsensusError, Milestone,
};
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
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

// ─── Header rules ───────────────────────────────────────────────────────────

fn pin_h4_checkpoint_and_h6_pow_limit(
    q: &Query,
    params: &ChainParams,
    genesis: &bitcoin::Block,
    b1: &bitcoin::Block,
) {
    let mut matched = params.clone();
    matched.checkpoints.push(Checkpoint {
        height: 1,
        hash: b1.block_hash(),
    });
    validate_header(q, &matched, Height(1), &b1.header).expect("h4 checkpoint match");

    let mut mismatch = params.clone();
    mismatch.checkpoints.push(Checkpoint {
        height: 1,
        hash: BlockHash::from_byte_array([0xcc; 32]),
    });
    let err = validate_header(q, &mismatch, Height(1), &b1.header).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("checkpoint")),
        "h4 mismatch: {err:?}"
    );

    let near = mine_regtest_block(genesis.block_hash(), genesis.header.time + 1, 1, vec![]);
    let mut tight = params.clone();
    tight.pow_limit = ChainParams::mainnet().pow_limit;
    let err = validate_header(q, &tight, Height(1), &near.header).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("pow limit")),
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
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("nonfinal")),
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
        matches!(err, ConsensusError::BadHeader(s) if s.contains("future")),
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
        matches!(err, Err(ConsensusError::BadBlock(s)) if s.contains("coinbase excess")),
        "50 BTC at interval must exceed the new 25 BTC floor: {err:?}"
    );

    let mut excess = mine_regtest_block(h1.block_hash(), h1.header.time + 601, 2, vec![]);
    excess.txdata[0].output[0].value = Amount::from_sat(25_0000_0000 + 1);
    excess.header.merkle_root = excess.compute_merkle_root().unwrap();
    grind_pow(&mut excess);
    let err = accept_and_connect_block(&q, &params, Height(2), &excess, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadBlock(s)) if s.contains("coinbase excess")),
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
        matches!(err, ConsensusError::InvalidPow),
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
                matches!(res, Err(ConsensusError::BadTx(s)) if s.contains("immature")),
                "coinbase spent at created+99 in the same batch: {res:?}"
            );
            assert_eq!(q.tip_height(), Some(Height::GENESIS));
        }
    }
}

#[allow(clippy::cognitive_complexity)] // one fixture, many boundary arms
#[test]
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
        matches!(err, ConsensusError::BadHeader(s) if s.contains("genesis")),
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
            Err(ConsensusError::BadBlock("unexpected witness before segwit"))
        ),
        "pre-activation witness block must hit the SegWit gate: {err:?}"
    );

    let mut bad_prev = mine_regtest_block(g.block_hash(), g.header.time + 1, 1, vec![]);
    bad_prev.header.prev_blockhash = BlockHash::from_byte_array([0xee; 32]);
    grind_pow(&mut bad_prev);
    let err = validate_header(&q, &params, Height(1), &bad_prev.header).unwrap_err();
    assert!(matches!(err, ConsensusError::BadPrev), "h2: {err:?}");

    let mut bad_bits = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    bad_bits.header.bits = CompactTarget::from_consensus(0x207f_fffe);
    grind_pow(&mut bad_bits);
    let err = validate_header(&q, &params, Height(1), &bad_bits.header).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("bits") || s.contains("proof")),
        "h5: {err:?}"
    );

    let b1 = mine_regtest_block(g.block_hash(), g.header.time + 600, 1, vec![]);
    pin_h4_checkpoint_and_h6_pow_limit(&q, &params, &g, &b1);
    validate_header(&q, &params, Height(1), &b1.header).expect("valid parent, pow, bits");
    accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
    let cb_txid = b1.txdata[0].compute_txid();

    let mut tip = b1.block_hash();
    let mut time = b1.header.time;
    (tip, time) = pad_empty_from(&q, &params, tip, time, 2, 11);

    let mtp = median_time_past(&q, Height(11)).unwrap();
    let mut eq = mine_regtest_block(tip, mtp, 12, vec![]);
    let expected = expected_next_bits(&q, &params, Height(12), eq.header.time).unwrap();
    eq.header.bits = expected;
    grind_pow(&mut eq);
    let err = validate_header(&q, &params, Height(12), &eq.header).unwrap_err();
    assert!(
        matches!(err, ConsensusError::BadHeader(s) if s.contains("median-time")),
        "time==mtp: {err:?}"
    );

    let mut after = mine_regtest_block(tip, mtp + 1, 12, vec![]);
    after.header.bits = expected_next_bits(&q, &params, Height(12), after.header.time).unwrap();
    grind_pow(&mut after);
    validate_header(&q, &params, Height(12), &after.header).expect("time==mtp+1");

    (tip, time) = pad_empty_from(&q, &params, tip, time, 12, 99);
    assert_eq!(q.tip_height(), Some(Height(99)));

    let immature = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    let bad100 = mine_regtest_block(tip, time + 600, 100, vec![immature]);
    let err = accept_and_connect_block(&q, &params, Height(100), &bad100, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("immature")),
        "immature at created+99: {err:?}"
    );

    (tip, time) = pad_empty_from(&q, &params, tip, time, 100, 100);
    assert_eq!(q.tip_height(), Some(Height(100)));
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
            matches!(err, Err(ConsensusError::MissingPrevout)),
            "{case} must reject as MissingPrevout: {err:?}"
        );
    }

    let mut nonfinal = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    nonfinal.lock_time = LockTime::from_height(101).unwrap();
    nonfinal.input[0].sequence = Sequence::ZERO;
    let nf_block = mine_regtest_block(tip, time, 101, vec![nonfinal]);
    let err = accept_and_connect_block(&q, &params, Height(101), &nf_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("nonfinal") || s.contains("not final")),
        "locktime==height: {err:?}"
    );

    let mut csv_early = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    csv_early.version = TxVersion::TWO;
    csv_early.input[0].sequence = Sequence::from_consensus(200);
    let csv_block = mine_regtest_block(tip, time, 101, vec![csv_early]);
    let err = accept_and_connect_block(&q, &params, Height(101), &csv_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx("bad-txns-nonfinal"))),
        "relative lock 200 at height 101 must reject, got {err:?}"
    );

    let over = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(50_0000_0000 + 1));
    let over_block = mine_regtest_block(tip, time, 101, vec![over]);
    let err = accept_and_connect_block(&q, &params, Height(101), &over_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("in < out")),
        "in < out: {err:?}"
    );

    let mut excess = mine_regtest_block(tip, time, 101, vec![]);
    excess.txdata[0].output[0].value = Amount::from_sat(50_0000_0000 + 1);
    excess.header.merkle_root = excess.compute_merkle_root().unwrap();
    grind_pow(&mut excess);
    let err = accept_and_connect_block(&q, &params, Height(101), &excess, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadBlock(s)) if s.contains("coinbase excess")),
        "subsidy+1: {err:?}"
    );

    let s1 = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(25_0000_0000));
    let s2 = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(24_0000_0000));
    let dup = mine_regtest_block(tip, time, 101, vec![s1, s2]);
    let err = accept_and_connect_block(&q, &params, Height(101), &dup, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("double spend")),
        "same-block double spend: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let parent = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(49_0000_0000));
    let child = spend_anyone_can_spend(parent.compute_txid(), 0, Amount::from_sat(48_0000_0000));
    let bad_order = mine_regtest_block(tip, time, 101, vec![child, parent]);
    let err = accept_and_connect_block(&q, &params, Height(101), &bad_order, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::MissingPrevout)),
        "child-before-parent must not become tip: {err:?}"
    );
    assert_eq!(q.tip_height(), Some(Height(100)));

    let mut empty_out = spend_anyone_can_spend(cb_txid, 0, Amount::from_sat(1));
    empty_out.output.clear();
    let empty_block = mine_regtest_block(tip, time, 101, vec![empty_out]);
    let err = accept_and_connect_block(&q, &params, Height(101), &empty_block, Milestone::NONE);
    assert!(
        matches!(err, Err(ConsensusError::BadTx(s)) if s.contains("no outputs")),
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
        matches!(err, Err(ConsensusError::PrevoutSpent))
            || matches!(
                err,
                Err(ConsensusError::BadTx(s)) if s.contains("double spend") || s.contains("spent")
            ),
        "already spent: {err:?}"
    );
    pin_bip68_time_lock(&q, &params, child_txid, good.block_hash(), time);
    pin_subsidy_interval_two_overlay();
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
            matches!(err, Err(ConsensusError::Script(_))),
            "{case} below segwit height: {err:?}"
        );
        assert_eq!(q.tip_height(), Some(Height(100)));
    }
}
