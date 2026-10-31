use crate::test_chain::{padded_chain_with, shared_regtest, TestChain};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use bitcoin::{CompactTarget, Target};
use rbitcoin_consensus::{
    bip34_height_script, block_subsidy, mine_empty_regtest, mine_regtest_paying,
    witness_commitment_script, ChainParams,
};
use rbitcoin_primitives::Height;
use rbitcoin_query::{confirm_scripts_phase, expected_next_bits, median_time_past};
use rbitcoin_store::merkle_root_from_txids;
use rbitcoin_sv2::testutil::TpClient;
use rbitcoin_sv2::{
    run_sv2_tp, Sv2TpConfig, CONSTRAINTS_COOLDOWN_TEST, FEE_DELTA, SETUP_TIMEOUT,
    TEMPLATE_INTERVAL, WRITE_TIMEOUT,
};
use std::sync::Arc;
use std::time::Duration;

use template_distribution_sv2::{
    NewTemplate, SetNewPrevHash, MESSAGE_TYPE_NEW_TEMPLATE, MESSAGE_TYPE_SET_NEW_PREV_HASH,
};

const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
const OP_TRUE: u8 = 0x51;
const OP_CHECKSIG: u8 = 0xac;

fn mock_live_tip(tc: &TestChain) {
    let tip_time = tc.chain.tip_header().expect("tip").time;
    tc.chain.clock.set_mock(i64::from(tip_time));
}

fn spend(coinbase: Txid, fee: u64, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - fee),
            script_pubkey,
        }],
    }
}

/// Coinbase is leaf 0, so every fold step hashes the running value on the left.
fn fold_coinbase_path(leaf: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    path.iter().fold(leaf, |acc, sibling| {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&acc);
        buf[32..].copy_from_slice(sibling);
        sha256d::Hash::hash(&buf).to_byte_array()
    })
}

async fn recv_in_time(c: &mut TpClient) -> rbitcoin_sv2::Frame {
    tokio::time::timeout(Duration::from_secs(10), c.recv())
        .await
        .expect("message in time")
        .expect("message")
}

async fn expect_template(
    c: &mut TpClient,
    tc: &TestChain,
    txs: &[&Transaction],
    future: bool,
) -> u64 {
    let f = recv_in_time(c).await;
    check_template(c, tc, f, txs, future).await
}

/// `future` templates must be followed by their `SetNewPrevHash` on the tip.
async fn check_template(
    c: &mut TpClient,
    tc: &TestChain,
    mut f: rbitcoin_sv2::Frame,
    txs: &[&Transaction],
    future: bool,
) -> u64 {
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    let next_h = tc.chain.query.tip_height().expect("tip").0 + 1;
    let fees: u64 = txs
        .iter()
        .map(|tx| 50_0000_0000 - tx.output[0].value.to_sat())
        .sum();

    assert_eq!(t.future_template, future);
    assert_eq!(
        t.version, 0x2000_0000,
        "testdummy is DEFINED below height 144"
    );
    assert_eq!(
        (
            t.coinbase_tx_version,
            t.coinbase_tx_input_sequence,
            t.coinbase_tx_locktime
        ),
        (2, u32::MAX, 0)
    );
    assert_eq!(t.coinbase_prefix.as_ref(), bip34_height_script(next_h));
    assert_eq!(
        t.coinbase_tx_value_remaining,
        block_subsidy(next_h, &tc.chain.params) as u64 + fees
    );
    let commitment = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(witness_commitment_script(
            txs.iter().map(|tx| tx.compute_wtxid().to_byte_array()),
            &[0u8; 32],
        )),
    };
    assert_eq!(t.coinbase_tx_outputs_count, 1);
    assert_eq!(t.coinbase_tx_outputs.as_ref(), serialize(&commitment));

    let path: Vec<[u8; 32]> = t
        .merkle_path
        .iter()
        .map(|h| h.as_ref().try_into().expect("32-byte hash"))
        .collect();
    let coinbase_leaf = [0x11; 32];
    let mut leaves = vec![coinbase_leaf];
    leaves.extend(txs.iter().map(|tx| tx.compute_txid().to_byte_array()));
    assert_eq!(
        fold_coinbase_path(coinbase_leaf, &path),
        merkle_root_from_txids(&leaves),
        "merkle path must fold to the root over the selection order"
    );
    if future {
        expect_prev_hash(c, tc, t.template_id, next_h).await;
    }
    t.template_id
}

async fn expect_prev_hash(c: &mut TpClient, tc: &TestChain, template_id: u64, next_h: u32) {
    let mut f = recv_in_time(c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_SET_NEW_PREV_HASH);
    let p: SetNewPrevHash = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    assert_eq!(p.template_id, template_id);
    let tip = tc.chain.tip_header().expect("tip header");
    assert_eq!(p.prev_hash.as_ref(), tip.block_hash().to_byte_array());
    let mtp = median_time_past(&tc.chain.query, Height(next_h - 1)).unwrap();
    assert!(p.header_timestamp > mtp, "header_timestamp above MTP");
    assert!(u64::from(p.header_timestamp) <= tc.chain.clock.now_secs());
    let bits = expected_next_bits(
        &tc.chain.query,
        &tc.chain.params,
        Height(next_h),
        p.header_timestamp,
    )
    .unwrap();
    assert_eq!(p.n_bits, bits.to_consensus());
    let target = Target::from_compact(CompactTarget::from_consensus(p.n_bits));
    assert_eq!(p.target.as_ref(), target.to_le_bytes());
}

#[tokio::test(flavor = "multi_thread")]
async fn template_budget_fees_coinbase_and_merkle_path() {
    let tc = shared_regtest(3);
    mock_live_tip(&tc);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 3_000, cheap.clone());
    let b = spend(tc.coinbases[1], 2_000, cheap);
    // 4000 legacy sigops × 4 = 16_000 cost; Libre admits the script.
    let heavy = spend(
        tc.coinbases[2],
        20_000,
        ScriptBuf::from_bytes(vec![OP_CHECKSIG; 4_000]),
    );
    for tx in [&a, &b, &heavy] {
        tc.mempool.accept_tx(tx).expect("mempool accept");
    }

    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    c.coinbase_output_constraints(0, 0).await.unwrap();
    let mut last = expect_template(&mut c, &tc, &[&a, &b, &heavy], true).await;

    // The client's sigops replace the reserve: 65_535 + 16_000 ≥ 80_000.
    c.coinbase_output_constraints(0, u16::MAX).await.unwrap();
    let id = expect_template(&mut c, &tc, &[&a, &b], false).await;
    assert!(id > last, "template_id must increase");
    last = id;

    // Reserved weight 1168 + 4·size leaves exactly a + b, then 4 WU less.
    let edge = MAX_BLOCK_WEIGHT - 1168 - a.weight().to_wu() - b.weight().to_wu();
    let size = u32::try_from(edge / 4).unwrap();
    c.coinbase_output_constraints(size, 0).await.unwrap();
    let id = expect_template(&mut c, &tc, &[&a, &b], false).await;
    assert!(id > last, "template_id must increase");
    last = id;
    c.coinbase_output_constraints(size + 1, 0).await.unwrap();
    let id = expect_template(&mut c, &tc, &[&a], false).await;
    assert!(id > last, "template_id must increase");

    tp.shutdown().await;
}

/// The pool is already maintained, then the tip leaves IBD with peer relay
/// still off. The session must publish on the template interval, not wait
/// for relay or another block.
#[tokio::test(flavor = "multi_thread")]
async fn holding_session_publishes_when_the_pool_is_maintained() {
    let tc = shared_regtest(0);
    assert!(tc.chain.in_ibd(), "stale pad starts in IBD");
    tc.mempool.set_relay_enabled(false);
    let interval = Duration::from_millis(100);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [9; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: Duration::from_secs(30),
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: interval,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let recv = c.recv();
    tokio::pin!(recv);
    let held = tokio::time::timeout(Duration::from_millis(150), &mut recv).await;
    assert!(
        held.is_err(),
        "no template while the pool is not maintained"
    );

    mock_live_tip(&tc);
    assert!(!tc.chain.in_ibd(), "mocked tip leaves IBD");
    assert!(tc.mempool.pool_maintained());
    assert!(!tc.mempool.relay_enabled());
    let frame = tokio::time::timeout(interval * 4, recv)
        .await
        .expect("template once the pool is maintained")
        .expect("sv2 message");
    assert_eq!(frame.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    tp.shutdown().await;
}

/// A later budget is published once [`CONSTRAINTS_COOLDOWN_TEST`] has elapsed.
/// The heavy output is counted out under `u16::MAX`.
#[tokio::test(flavor = "multi_thread")]
async fn constraints_cooldown_publishes_the_next_budget() {
    let tc = shared_regtest(1);
    mock_live_tip(&tc);
    let heavy = spend(
        tc.coinbases[0],
        20_000,
        ScriptBuf::from_bytes(vec![OP_CHECKSIG; 4_000]),
    );
    tc.mempool.accept_tx(&heavy).expect("mempool accept");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    let started = tokio::time::Instant::now();
    c.coinbase_output_constraints(0, 0).await.unwrap();
    expect_template(&mut c, &tc, &[&heavy], true).await;

    c.coinbase_output_constraints(0, u16::MAX).await.unwrap();
    let f = tokio::time::timeout(Duration::from_secs(3), c.recv())
        .await
        .expect("second budget after the cooldown")
        .expect("message");
    assert!(started.elapsed() >= CONSTRAINTS_COOLDOWN_TEST);
    check_template(&mut c, &tc, f, &[], false).await;

    tp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn template_resent_constraints_do_not_rebuild() {
    let tc = shared_regtest(1);
    mock_live_tip(&tc);
    // 16_000 sigop cost: excluded under a u16::MAX client reserve.
    let heavy = spend(
        tc.coinbases[0],
        20_000,
        ScriptBuf::from_bytes(vec![OP_CHECKSIG; 4_000]),
    );
    tc.mempool.accept_tx(&heavy).expect("mempool accept");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    c.coinbase_output_constraints(0, u16::MAX).await.unwrap();
    let first = expect_template(&mut c, &tc, &[], true).await;
    // Frames are handled in order: had the resend rebuilt, its heavy-less
    // template would be the next frame.
    c.coinbase_output_constraints(0, u16::MAX).await.unwrap();
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let id = expect_template(&mut c, &tc, &[&heavy], false).await;
    assert!(id > first, "template_id must increase");

    tp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn template_constraint_rebuilds_are_rate_limited() {
    let tc = shared_regtest(1);
    mock_live_tip(&tc);
    // 16_000 sigop cost: excluded under a u16::MAX client reserve.
    let heavy = spend(
        tc.coinbases[0],
        20_000,
        ScriptBuf::from_bytes(vec![OP_CHECKSIG; 4_000]),
    );
    tc.mempool.accept_tx(&heavy).expect("mempool accept");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    c.coinbase_output_constraints(0, u16::MAX).await.unwrap();
    let first = expect_template(&mut c, &tc, &[], true).await;
    // Alternating budgets: one deferred rebuild on the last budget, not one
    // template per message.
    for sigops in [0, u16::MAX, 0] {
        c.coinbase_output_constraints(0, sigops).await.unwrap();
    }
    let id = expect_template(&mut c, &tc, &[&heavy], false).await;
    assert!(id > first, "template_id must increase");
    let extra = tokio::time::timeout(Duration::from_millis(150), c.recv()).await;
    assert!(extra.is_err(), "one rebuild per cooldown");

    tp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_gate_holds_constraints_until_a_fresh_tip() {
    let tc = shared_regtest(1);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    // One recv future throughout: dropping it mid-frame breaks the Noise decoder.
    let first = {
        let recv = c.recv();
        tokio::pin!(recv);
        let held = tokio::time::timeout(Duration::from_millis(500), &mut recv).await;
        assert!(held.is_err(), "no template while the stale tip keeps IBD");

        let tip = tc.chain.tip_header().expect("tip header");
        let height = tc.chain.query.tip_height().unwrap().0 + 1;
        let now = tc.chain.clock.now_secs() as u32;
        let fresh = mine_empty_regtest(tip.block_hash(), now, height);
        tc.chain.accept_block(fresh).expect("accept fresh block");
        tokio::time::timeout(Duration::from_secs(10), recv)
            .await
            .expect("template after the fresh tip")
            .expect("message")
    };
    check_template(&mut c, &tc, first, &[], true).await;

    tp.shutdown().await;
}

/// A constraints flood while the node is in IBD must not close the session.
/// Nothing is queued to build, so the post-template 8-replacement close does
/// not apply. The tip that leaves IBD builds the last budget.
#[tokio::test(flavor = "multi_thread")]
async fn constraints_while_ibd_keep_the_last_budget() {
    let tc = shared_regtest(1);
    // 16_000 sigop cost: excluded under a u16::MAX client reserve.
    let heavy = spend(
        tc.coinbases[0],
        20_000,
        ScriptBuf::from_bytes(vec![OP_CHECKSIG; 4_000]),
    );
    tc.mempool.accept_tx(&heavy).expect("mempool accept");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    // Past the flood limit, including a repeat of the last budget. The
    // template after the tip must be the u16::MAX reserve (heavy excluded).
    c.coinbase_output_constraints(0, 0).await.unwrap();
    for sigops in [1u16, 2, 3, 4, 5, 6, 7, 8, 9, u16::MAX, u16::MAX] {
        c.coinbase_output_constraints(0, sigops)
            .await
            .expect("session stays up");
    }

    let first = {
        let recv = c.recv();
        tokio::pin!(recv);
        let held = tokio::time::timeout(Duration::from_millis(500), &mut recv).await;
        assert!(held.is_err(), "no template while the stale tip keeps IBD");

        let tip = tc.chain.tip_header().expect("tip header");
        let height = tc.chain.query.tip_height().unwrap().0 + 1;
        let now = tc.chain.clock.now_secs() as u32;
        let fresh = mine_empty_regtest(tip.block_hash(), now, height);
        tc.chain.accept_block(fresh).expect("accept fresh block");
        tokio::time::timeout(Duration::from_secs(10), recv)
            .await
            .expect("template after the fresh tip")
            .expect("message")
    };
    check_template(&mut c, &tc, first, &[], true).await;
    let extra = tokio::time::timeout(Duration::from_millis(500), c.recv()).await;
    assert!(extra.is_err(), "one template for the last budget");

    tp.shutdown().await;
}

/// A connected session's first template, with a coinbase paying the whole
/// value and an unground header over it.
struct FirstTemplate {
    tp: rbitcoin_sv2::Sv2TpHandle,
    c: TpClient,
    template_id: u64,
    version: u32,
    header: bitcoin::block::Header,
    coinbase: Vec<u8>,
}

async fn first_template(tc: &TestChain) -> FirstTemplate {
    first_template_every(tc, TEMPLATE_INTERVAL).await
}

/// [`first_template`] on a session that checks fees every `template_interval`.
async fn first_template_every(tc: &TestChain, template_interval: Duration) -> FirstTemplate {
    mock_live_tip(tc);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();

    let mut f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    let mut f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_SET_NEW_PREV_HASH);
    let p: SetNewPrevHash = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    let tip = tc.chain.tip_header().expect("tip").block_hash();

    let coinbase = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(t.coinbase_prefix.as_ref().to_vec()),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(t.coinbase_tx_value_remaining),
                script_pubkey: ScriptBuf::from_bytes(vec![OP_TRUE]),
            },
            bitcoin::consensus::deserialize(t.coinbase_tx_outputs.as_ref()).unwrap(),
        ],
    };
    let path: Vec<[u8; 32]> = t
        .merkle_path
        .iter()
        .map(|h| h.as_ref().try_into().expect("32-byte hash"))
        .collect();
    let root = fold_coinbase_path(coinbase.compute_txid().to_byte_array(), &path);
    let header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(t.version as i32),
        prev_blockhash: tip,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(root),
        time: p.header_timestamp,
        bits: CompactTarget::from_consensus(p.n_bits),
        nonce: 0,
    };
    FirstTemplate {
        tp,
        c,
        template_id: t.template_id,
        version: t.version,
        header,
        coinbase: serialize(&coinbase),
    }
}

/// A solution whose header misses the target is dropped before
/// `accept_block`: it never claims the compact-block prefill slot. A
/// solution that meets it still becomes the tip.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_checks_pow_before_accept() {
    let tc = shared_regtest(0);
    use template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS;

    tc.chain.set_prefill_compact(true);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    let tip = header.prev_blockhash;

    while header.validate_pow(header.target()).is_ok() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    c.request_transaction_data(template_id).await.unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS);
    assert_eq!(tc.chain.tip_header().unwrap().block_hash(), tip);
    assert_eq!(
        tc.chain.cmpct_prefill_indexes(&header.block_hash()),
        None,
        "a header that misses the target must not reach accept_block"
    );

    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    let solved = header.block_hash();
    assert_eq!(tc.chain.tip_header().unwrap().block_hash(), solved);
    assert_eq!(tc.chain.cmpct_prefill_indexes(&solved), Some(vec![0]));
    tc.chain.set_prefill_compact(false);

    tp.shutdown().await;
}

/// A client that leaves the coinbase witness empty still solves the block:
/// the TP fills the zero reserved value the witness commitment was built
/// with. The txid, and so the merkle root, does not cover the witness.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_without_coinbase_witness_is_accepted() {
    let tc = shared_regtest(0);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    let mut bare: Transaction = bitcoin::consensus::deserialize(&coinbase).unwrap();
    bare.input[0].witness = Witness::new();
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(
        template_id,
        version,
        header.time,
        header.nonce,
        &serialize(&bare),
    )
    .await
    .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );

    tp.shutdown().await;
}

/// A witness-less block may drop the commitment output. Its coinbase then
/// stays bare: a filled witness without a commitment is not valid (BIP141).
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_without_witness_commitment_is_accepted() {
    let tc = shared_regtest(0);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    let mut bare: Transaction = bitcoin::consensus::deserialize(&coinbase).unwrap();
    bare.input[0].witness = Witness::new();
    bare.output.truncate(1);
    // Empty mempool: the merkle path is empty and the root is the coinbase txid.
    header.merkle_root =
        bitcoin::TxMerkleNode::from_byte_array(bare.compute_txid().to_byte_array());
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(
        template_id,
        version,
        header.time,
        header.nonce,
        &serialize(&bare),
    )
    .await
    .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );

    tp.shutdown().await;
}

/// A miner whose clock runs a few seconds ahead of the TP rolls
/// `header_timestamp` past the wall time since `SetNewPrevHash`. The block is
/// still consensus-valid (above MTP, under now + 2h), so it becomes the tip.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_ahead_of_the_rolled_time_is_accepted() {
    let tc = shared_regtest(0);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    header.time += 5;
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );

    tp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn constraints_flood_closes_the_session() {
    let tc = shared_regtest(0);
    mock_live_tip(&tc);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    expect_template(&mut c, &tc, &[], true).await;

    // Well past the flood limit, all inside one cooldown: each budget
    // replaces the queued one before it is ever built.
    for i in 0..64u16 {
        if c.coinbase_output_constraints(0, i % 2).await.is_err() {
            break;
        }
    }
    let end = tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("closed before the deferred rebuild");
    assert!(end.is_err(), "flood must close the session, got a frame");

    let mut fresh = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("the slot is free again");
    fresh.setup_connection(2, 2, 2, 0).await.unwrap();
    fresh.recv().await.expect("setup reply");

    tp.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tip_event_rebuilds_a_template_built_on_its_prev_hash() {
    let tc = shared_regtest(1);
    mock_live_tip(&tc);
    let paid = spend(
        tc.coinbases[0],
        10_000,
        ScriptBuf::from_bytes(vec![OP_TRUE]),
    );
    tc.mempool.accept_tx(&paid).expect("mempool accept");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    expect_template(&mut c, &tc, &[&paid], true).await;

    // One write batch moves the store tip to y, then sends x's event, then
    // y's: the rebuild for x already sits on y's hash when y's event lands.
    let tip = tc.chain.tip_header().expect("tip").block_hash();
    let h = tc.chain.query.tip_height().expect("tip height").0;
    let script = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let now = tc.chain.tip_header().expect("tip").time;
    let x = mine_regtest_paying(tip, now + 1, h + 1, script, vec![paid.clone()]);
    let y = mine_empty_regtest(x.block_hash(), now + 2, h + 2);
    let loaded = tc
        .chain
        .confirm_wire_load_phase(&[(Height(h + 1), x), (Height(h + 2), y)])
        .expect("load")
        .expect("contiguous");
    let scripted = confirm_scripts_phase(loaded.batch).expect("scripts");
    tc.chain.confirm_write(scripted.batch).expect("write");

    let on_y = expect_template(&mut c, &tc, &[], true).await;
    let rebuilt = expect_template(&mut c, &tc, &[], false).await;
    assert!(rebuilt > on_y, "y's event must rebuild the template on y");

    tp.shutdown().await;
}

/// With no idle deadline, a client silent past the setup timeout after its
/// first `CoinbaseOutputConstraints` stays connected and gets the next tip.
#[tokio::test(flavor = "multi_thread")]
async fn silent_session_outlives_the_setup_timeout_and_gets_the_next_tip() {
    let tc = shared_regtest(1);
    mock_live_tip(&tc);
    let setup_timeout = Duration::from_millis(40);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let first = expect_template(&mut c, &tc, &[], true).await;

    tokio::time::sleep(setup_timeout * 4).await;

    let tip = tc.chain.tip_header().expect("tip").block_hash();
    let h = tc.chain.query.tip_height().expect("tip height").0;
    let now = tc.chain.tip_header().expect("tip").time;
    let next = mine_empty_regtest(tip, now + 1, h + 1);
    let loaded = tc
        .chain
        .confirm_wire_load_phase(&[(Height(h + 1), next)])
        .expect("load")
        .expect("contiguous");
    let scripted = confirm_scripts_phase(loaded.batch).expect("scripts");
    tc.chain.confirm_write(scripted.batch).expect("write");

    let after = expect_template(&mut c, &tc, &[], true).await;
    assert!(after > first, "the new tip must get a new template");

    tp.shutdown().await;
}

/// sv2-spec 07 §7.4: nBits comes with `SetNewPrevHash`, once per prev hash.
/// Past prev + 2 × spacing a min-difficulty network's expected bits follow
/// the header time to the pow limit; a rebuild on the same prev hash must
/// still assemble solutions with the bits the client was sent.
#[tokio::test(flavor = "multi_thread")]
async fn same_prev_hash_template_keeps_the_sent_bits() {
    // Regtest padding at 0x207fffff, under a pow limit above it: a header
    // past prev + 20 min expects the limit, an earlier one the padding bits.
    let mut params = ChainParams::regtest();
    params.pow_limit = Target::from_compact(CompactTarget::from_consensus(0x2100_ffff));
    let tc = padded_chain_with("sv2-sent-bits", 0, params);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;

    let spacing = tc.chain.params.btc.pow_target_spacing as u32;
    tc.chain
        .clock
        .set_mock(i64::from(tc.tip_time + 2 * spacing + 1));
    c.coinbase_output_constraints(0, 1).await.unwrap();
    let rebuilt = expect_template(&mut c, &tc, &[], false).await;
    assert!(rebuilt > template_id);

    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(rebuilt, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );

    tp.shutdown().await;
}

/// With the tip unchanged, a rebuild whose fees reach the last sent
/// template's plus the delta is pushed once the interval has passed, with no
/// `SetNewPrevHash`. The delta is against the last sent template, so gains
/// below it add up. A budget change queued by the constraints cooldown
/// builds once: the fee check leaves it to the deferred rebuild.
#[tokio::test(flavor = "multi_thread")]
async fn fee_push_after_the_interval_past_the_delta() {
    let tc = shared_regtest(3);
    mock_live_tip(&tc);
    let interval = Duration::from_millis(250);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: 1_000,
        template_interval: interval,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    // Before the first template is sent, so a lower bound on its send time.
    let asked = tokio::time::Instant::now();
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let first = expect_template(&mut c, &tc, &[], true).await;

    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 1_000, cheap.clone());
    tc.mempool.accept_tx(&a).expect("mempool accept");
    // `future: false` also asserts no SetNewPrevHash follows.
    let id = expect_template(&mut c, &tc, &[&a], false).await;
    assert!(
        asked.elapsed() >= interval,
        "no fee push inside the interval"
    );
    assert!(id > first, "template_id must increase");

    let b = spend(tc.coinbases[1], 600, cheap.clone());
    tc.mempool.accept_tx(&b).expect("mempool accept");
    let d = spend(tc.coinbases[2], 400, cheap.clone());
    // One recv future throughout: dropping it mid-frame breaks the Noise decoder.
    let pushed = {
        let recv = c.recv();
        tokio::pin!(recv);
        let below = tokio::time::timeout(3 * interval, &mut recv).await;
        assert!(
            below.is_err(),
            "600 sat over the last sent is below the delta"
        );
        // 600 + 400 since the last sent template reaches the delta.
        tc.mempool.accept_tx(&d).expect("mempool accept");
        tokio::time::timeout(Duration::from_secs(10), recv)
            .await
            .expect("fee push at the delta")
            .expect("message")
    };
    let next = check_template(&mut c, &tc, pushed, &[&a, &b, &d], false).await;
    assert!(next > id, "template_id must increase");

    // Inside the cooldown of that push: the new budget waits it out.
    // A fee check in between must not send it early and again at the end.
    let e = Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: a.compute_txid(),
                vout: 0,
            },
            ..a.input[0].clone()
        }],
        output: vec![TxOut {
            value: a.output[0].value - Amount::from_sat(1_000),
            script_pubkey: cheap,
        }],
        ..a.clone()
    };
    // Budget first: it queues the rebuild before `e` moves the counter.
    c.coinbase_output_constraints(0, 1).await.unwrap();
    tc.mempool.accept_tx(&e).expect("mempool accept");
    let mut f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    let next_h = tc.chain.query.tip_height().expect("tip").0 + 1;
    assert!(!t.future_template);
    assert!(t.template_id > next, "template_id must increase");
    assert_eq!(
        t.coinbase_tx_value_remaining,
        block_subsidy(next_h, &tc.chain.params) as u64 + 3_000
    );
    let extra = tokio::time::timeout(Duration::from_millis(200), c.recv()).await;
    assert!(extra.is_err(), "one template for the deferred budget");

    tp.shutdown().await;
}

/// Fee pushes add templates on the same tip, and a miner may still be on an
/// older job: every template since `SetNewPrevHash` stays solvable until
/// the tip moves (sv2-tp keeps the same set).
#[tokio::test(flavor = "multi_thread")]
async fn fee_pushes_keep_older_same_tip_templates_solvable() {
    let tc = shared_regtest(3);
    let interval = Duration::from_millis(250);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template_every(&tc, interval).await;

    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let mut txs = (0..3)
        .map(|i| spend(tc.coinbases[i], FEE_DELTA, cheap.clone()))
        .collect::<Vec<_>>();
    let child = Transaction {
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: txs[0].compute_txid(),
                vout: 0,
            },
            ..txs[0].input[0].clone()
        }],
        output: vec![TxOut {
            value: txs[0].output[0].value - Amount::from_sat(FEE_DELTA),
            script_pubkey: cheap,
        }],
        ..txs[0].clone()
    };
    txs.push(child);
    // More fee pushes than a three-template ring would keep.
    let mut last = template_id;
    for tx in &txs {
        tc.mempool.accept_tx(tx).expect("mempool accept");
        let mut f = recv_in_time(&mut c).await;
        assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
        let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
        assert!(!t.future_template && t.template_id > last, "fee push");
        last = t.template_id;
    }

    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash(),
        "the first template on the tip still solves"
    );

    tp.shutdown().await;
}

/// One paused interval after an admit produces one fee push. The next
/// admit waits for the next advance.
#[tokio::test]
async fn fee_pushes_stay_an_interval_apart_under_steady_admission() {
    let tc = shared_regtest(1);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let outs = 4u64;
    let each = (50_0000_0000 - 10_000) / outs;
    let mut fanout = spend(tc.coinbases[0], 10_000, cheap.clone());
    fanout.output = vec![
        TxOut {
            value: Amount::from_sat(each),
            script_pubkey: cheap.clone(),
        };
        outs as usize
    ];
    let tip = tc.chain.tip_header().expect("tip");
    let h = tc.chain.query.tip_height().expect("tip height").0;
    let block = mine_regtest_paying(
        tip.block_hash(),
        tip.time + 1,
        h + 1,
        cheap.clone(),
        vec![fanout.clone()],
    );
    tc.chain.accept_block(block).expect("accept fan-out");
    mock_live_tip(&tc);

    let interval = Duration::from_millis(250);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        idle_timeout: None,
        write_timeout: WRITE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: interval,
        constraints_cooldown: CONSTRAINTS_COOLDOWN_TEST,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    c.coinbase_output_constraints(0, 0).await.unwrap();
    expect_template(&mut c, &tc, &[], true).await;

    tokio::time::pause();
    for vout in 0..outs as u32 {
        let tx = Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: fanout.compute_txid(),
                    vout,
                },
                ..fanout.input[0].clone()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(each - FEE_DELTA),
                script_pubkey: cheap.clone(),
            }],
            ..fanout.clone()
        };
        tc.mempool.accept_tx(&tx).expect("mempool accept");
        let mut recv = std::pin::pin!(c.recv());
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::ZERO, &mut recv)
                .await
                .is_err(),
            "admit {vout} pushed before the interval"
        );
        // One millisecond past the deadline: an exact advance leaves the
        // timer due but not fired.
        tokio::time::advance(interval + Duration::from_millis(1)).await;
        let mut f = recv.await.expect("one advance produces one push");
        assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
        let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
        assert!(!t.future_template, "fee push");
    }
    tokio::time::resume();
    tp.shutdown().await;
}

/// An idle session checks once per paused interval and does not rebuild.
#[tokio::test]
async fn idle_session_checks_each_interval_and_does_not_rebuild() {
    let tc = shared_regtest(0);
    let interval = Duration::from_millis(250);
    let FirstTemplate { tp, c, .. } = first_template_every(&tc, interval).await;
    tokio::time::pause();
    let stats = tp.stats();
    assert_eq!(stats.builds.totals().0, 1, "the first template");
    let before = stats.fee_checks.totals().0;
    for i in 1..=4 {
        // One millisecond past the deadline: an exact advance leaves the
        // timer due but not fired.
        tokio::time::advance(interval + Duration::from_millis(1)).await;
        let want = before + u64::try_from(i).unwrap();
        for _ in 0..64 {
            if stats.fee_checks.totals().0 >= want {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(stats.fee_checks.totals().0, want, "one check per advance");
    }
    assert_eq!(stats.builds.totals().0, 1, "an idle mempool is not rebuilt");
    tokio::time::resume();
    drop(c);
    tp.shutdown().await;
}

#[test]
fn template_builds_on_the_stripped_tip() {
    let tc = crate::test_chain::padded_chain("sv2-stripped-tip", 0);
    let tip = tc.chain.query.tip_height().unwrap();
    assert!(tip.0 > 0);
    let (_, genesis) = tc
        .chain
        .query
        .header_at_height(rbitcoin_primitives::Height::GENESIS)
        .unwrap()
        .unwrap();
    tc.mempool.note_template_prev(genesis.hash);
    let built = rbitcoin_sv2::template::build(&tc.chain, 0, 0)
        .unwrap()
        .expect("template");
    assert_eq!(built.prev_hash, genesis.hash);
    let best = tc.chain.query.wire_header_at_height(tip).unwrap();
    assert_ne!(built.prev_hash, best.block_hash().to_byte_array());
}

/// Core `GetMinimumTime`: on a clock behind a period's first block, the
/// template for that period's last block is stamped at the first block's time.
#[test]
fn template_time_holds_the_last_of_period_floor() {
    let mut params = ChainParams::regtest();
    params.btc.pow_target_timespan = 16 * params.btc.pow_target_spacing;
    assert_eq!(params.difficulty_adjustment_interval(), 16);
    let tc = padded_chain_with("sv2-period-floor", 0, params);
    let genesis = tc.tip_time - 600 * 100;
    let first_time = genesis + 200_000;
    let mut prev = tc.chain.tip_header().expect("tip").block_hash();
    for h in 101..=126u32 {
        let time = if h == 112 {
            first_time
        } else {
            genesis + 600 * h
        };
        let block = mine_empty_regtest(prev, time, h);
        prev = block.block_hash();
        assert_eq!(
            tc.chain.accept_block(block).unwrap(),
            rbitcoin_net::AcceptOutcome::Accepted { height: h }
        );
    }
    tc.chain.clock.set_mock(i64::from(first_time - 7_200));
    let built = rbitcoin_sv2::template::build(&tc.chain, 0, 0)
        .unwrap()
        .expect("template");
    assert_eq!(built.prev_hash, prev.to_byte_array());
    assert_eq!(built.header_timestamp, first_time);
}

/// Under `regtest_pow_bits_overlay` the template carries the overlay target,
/// and a solution ground against it becomes the tip.
#[tokio::test(flavor = "multi_thread")]
async fn template_target_follows_the_regtest_pow_overlay() {
    const OVERLAY: u32 = 0x200f_ffff;
    let mut params = ChainParams::regtest();
    params.apply_regtest_pow_bits(OVERLAY).unwrap();
    let tc = padded_chain_with("sv2-pow-overlay", 0, params);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    assert_eq!(header.bits.to_consensus(), OVERLAY);

    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );
    assert_eq!(tc.chain.tip_header().unwrap().bits.to_consensus(), OVERLAY);

    tp.shutdown().await;
}

/// The template pinned the overlay bits for this prev hash. A timestamp past
/// the min-difficulty gap needs the pow-limit bits, and `nBits` is inside the
/// hash, so the solution is dropped before `accept_block`.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_past_the_min_diff_gap_is_dropped() {
    use template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS;

    const OVERLAY: u32 = 0x200f_ffff;
    let mut params = ChainParams::regtest();
    params.apply_regtest_pow_bits(OVERLAY).unwrap();
    let tc = padded_chain_with("sv2-pow-gap-drop", 0, params);
    tc.chain.set_prefill_compact(true);
    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc).await;
    assert_eq!(header.bits.to_consensus(), OVERLAY);
    let tip = header.prev_blockhash;
    let spacing = tc.chain.params.btc.pow_target_spacing as u32;
    header.time = header.time.saturating_add(spacing.saturating_mul(2) + 1);
    while header.validate_pow(header.target()).is_err() {
        header.nonce = header.nonce.wrapping_add(1);
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    c.request_transaction_data(template_id).await.unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS);
    assert_eq!(tc.chain.tip_header().unwrap().block_hash(), tip);
    assert_eq!(
        tc.chain.cmpct_prefill_indexes(&header.block_hash()),
        None,
        "a gap timestamp must not reach accept_block"
    );
    tc.chain.set_prefill_compact(false);

    tp.shutdown().await;
}
