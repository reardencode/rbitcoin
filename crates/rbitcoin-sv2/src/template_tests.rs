use crate::messages::{
    ProposeTemplate, ProposeTemplateError, ProposeTemplateSuccess, ProvideMissingTransactions,
    ProvideMissingTransactionsSuccess, MESSAGE_TYPE_PROPOSE_TEMPLATE,
    MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR, MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS,
    MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
    REQUIRES_JOB_VALIDATION,
};
use crate::session::MAX_PENDING_PROPOSALS;
use crate::test_chain::{padded_chain_with, shared_regtest, TestChain};
use crate::testutil::TpClient;
use crate::{
    run_sv2_tp, Sv2TpConfig, FEE_DELTA, PROVIDE_TIMEOUT, SETUP_TIMEOUT, TEMPLATE_INTERVAL,
    WRITE_TIMEOUT,
};
use binary_sv2::{Seq064K, B016M, B064K, U256};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use bitcoin::{CompactTarget, Target};
use rbitcoin_consensus::{
    bip34_height_script, block_subsidy, confirm_scripts_phase, expected_next_bits,
    median_time_past, mine_empty_regtest, mine_regtest_paying, witness_commitment_script,
    ChainParams,
};
use rbitcoin_primitives::Height;
use rbitcoin_store::merkle_root_from_txids;
use std::sync::Arc;
use std::time::Duration;
use template_distribution_sv2::{
    NewTemplate, RequestTransactionDataError, RequestTransactionDataSuccess, SetNewPrevHash,
    MESSAGE_TYPE_NEW_TEMPLATE, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
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

async fn recv_in_time(c: &mut TpClient) -> crate::Frame {
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
    mut f: crate::Frame,
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
    assert_eq!(t.version, tc.chain.gbt_block_version() as u32);
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
    let extra = tokio::time::timeout(Duration::from_millis(500), c.recv()).await;
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
    tp: crate::Sv2TpHandle,
    c: TpClient,
    template_id: u64,
    version: u32,
    header: bitcoin::block::Header,
    coinbase: Vec<u8>,
}

async fn first_template(tc: &TestChain, flags: u32) -> FirstTemplate {
    first_template_every(tc, flags, TEMPLATE_INTERVAL).await
}

/// [`first_template`] on a session that checks fees every `template_interval`.
async fn first_template_every(
    tc: &TestChain,
    flags: u32,
    template_interval: Duration,
) -> FirstTemplate {
    mock_live_tip(tc);
    let (tp, mut c) = connect_tp_with(tc, flags, template_interval, PROVIDE_TIMEOUT).await;
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
    } = first_template(&tc, 0).await;
    let tip = header.prev_blockhash;

    while header.validate_pow(header.target()).is_ok() {
        header.nonce += 1;
    }
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    // Frames are handled in order: this reply follows the submit.
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
    // The new tip's template follows the accept.
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
    } = first_template(&tc, 0).await;
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
    } = first_template(&tc, 0).await;
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
    } = first_template(&tc, 0).await;
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
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
    } = first_template(&tc, 0).await;

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
/// builds once: the fee check leaves it to the deferred rebuild. Wall is
/// about 3 s, most of it the fixed 1 s cooldown and the silence after it.
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: 1_000,
        template_interval: interval,
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

    // Inside the cooldown of that push: the new budget waits out the second.
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
    let extra = tokio::time::timeout(Duration::from_secs(1), c.recv()).await;
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
    } = first_template_every(&tc, 0, interval).await;

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

/// Fee pushes stay an interval apart while txs keep arriving: a tx admitted
/// during a build or send waits for the next check, not the moment after
/// the push. Steady admission makes that window likely on some push, not
/// certain. Cost: about 0.8 s over the shared pad copy. A smaller fan-out
/// runs out before four pushes, and a sparser stream rarely lands inside a
/// build; with this one, arming the check at the send was caught on every
/// run, with pushes 3-6 ms apart against the 125 ms floor.
#[tokio::test(flavor = "multi_thread")]
async fn fee_pushes_stay_an_interval_apart_under_steady_admission() {
    let tc = shared_regtest(1);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    // Confirmed fan-out: each streamed spend is its own cluster. Enough
    // outputs to outlast four pushes on a loaded runner.
    let outs = 1_000u64;
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
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: interval,
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

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let feeder = {
        let (mempool, stop, fanout) = (Arc::clone(&tc.mempool), Arc::clone(&stop), fanout);
        std::thread::spawn(move || {
            for vout in 0..outs as u32 {
                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
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
                mempool.accept_tx(&tx).expect("mempool accept");
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    let mut at = Vec::new();
    for _ in 0..4 {
        let mut f = recv_in_time(&mut c).await;
        at.push(tokio::time::Instant::now());
        assert_eq!(f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE);
        let t: NewTemplate = binary_sv2::from_bytes(&mut f.payload).expect("decode");
        assert!(!t.future_template, "fee push");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    feeder.join().expect("feeder");
    // Receive times jitter around the server's sends; half an interval
    // leaves room for that and still fails a push right after the last.
    for w in at.windows(2) {
        assert!(
            w[1] - w[0] >= interval / 2,
            "pushes {:?} apart, interval {interval:?}",
            w[1] - w[0]
        );
    }

    tp.shutdown().await;
}

/// An idle session checks once per interval and builds nothing: the
/// counter did not move. The listener's stats count both.
#[tokio::test(flavor = "multi_thread")]
async fn idle_session_checks_each_interval_and_does_not_rebuild() {
    let tc = shared_regtest(0);
    let interval = Duration::from_millis(250);
    let FirstTemplate { tp, c, .. } = first_template_every(&tc, 0, interval).await;
    let stats = tp.stats();
    assert_eq!(stats.builds.totals().0, 1, "the first template");
    tokio::time::sleep(4 * interval + interval / 2).await;
    let checks = stats.fee_checks.totals().0;
    assert!(
        (2..=8).contains(&checks),
        "about one check per interval, got {checks}"
    );
    assert_eq!(stats.builds.totals().0, 1, "an idle mempool is not rebuilt");
    drop(c);
    tp.shutdown().await;
}

/// A live TP on `tc` with one session past `SetupConnection(flags)`.
async fn connect_tp(tc: &TestChain, flags: u32) -> (crate::Sv2TpHandle, TpClient) {
    connect_tp_with(tc, flags, TEMPLATE_INTERVAL, PROVIDE_TIMEOUT).await
}

/// [`connect_tp`] on a TP that checks fees every `template_interval` and
/// holds a proposal waiting for its missing txs for `provide_timeout`.
async fn connect_tp_with(
    tc: &TestChain,
    flags: u32,
    template_interval: Duration,
    provide_timeout: Duration,
) -> (crate::Sv2TpHandle, TpClient) {
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout,
        fee_delta: FEE_DELTA,
        template_interval,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(2, 2, 2, flags).await.unwrap();
    c.recv().await.expect("setup reply");
    (tp, c)
}

const EXTRANONCE_LEN: usize = 8;

/// A JDS-shaped coinbase: BIP34 height then the extranonce, one payout, and
/// the witness commitment over `txs` with a zero reserved value in the
/// witness.
fn job_coinbase(height: u32, payout: u64, txs: &[&Transaction]) -> Transaction {
    let mut script_sig = bip34_height_script(height);
    script_sig.extend_from_slice(&[0u8; EXTRANONCE_LEN]);
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(payout),
                script_pubkey: ScriptBuf::from_bytes(vec![OP_TRUE]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(witness_commitment_script(
                    txs.iter().map(|tx| tx.compute_wtxid().to_byte_array()),
                    &[0u8; 32],
                )),
            },
        ],
    }
}

/// Where a segwit coinbase's scriptSig starts in its serialization: version,
/// BIP144 marker and flag, the one-input count, the null prevout, and the
/// one-byte scriptSig length.
const SCRIPT_SIG_AT: usize = 4 + 2 + 1 + 36 + 1;

/// One `ProposeTemplate` as owned fields, so a test can bend any of them.
struct Job {
    request_id: u32,
    version: u32,
    coinbase_prefix: Vec<u8>,
    coinbase_suffix: Vec<u8>,
    wtxids: Vec<[u8; 32]>,
}

impl Job {
    /// The `DeclareMiningJob` split a JDS relays: the prefix ends where the
    /// extranonce starts (the scriptSig tail), the suffix starts at nSequence.
    fn declare(
        tc: &TestChain,
        request_id: u32,
        coinbase: &Transaction,
        declared: &[&Transaction],
    ) -> Self {
        let raw = serialize(coinbase);
        let split = SCRIPT_SIG_AT + coinbase.input[0].script_sig.len() - EXTRANONCE_LEN;
        Job {
            request_id,
            version: tc.chain.gbt_block_version() as u32,
            coinbase_prefix: raw[..split].to_vec(),
            coinbase_suffix: raw[split + EXTRANONCE_LEN..].to_vec(),
            wtxids: declared
                .iter()
                .map(|tx| tx.compute_wtxid().to_byte_array())
                .collect(),
        }
    }

    async fn send(&self, c: &mut TpClient) {
        let msg = ProposeTemplate {
            request_id: self.request_id,
            version: self.version,
            coinbase_tx_prefix: B064K::try_from(&self.coinbase_prefix[..]).unwrap(),
            coinbase_tx_suffix: B064K::try_from(&self.coinbase_suffix[..]).unwrap(),
            wtxid_list: Seq064K::new(self.wtxids.iter().map(U256::from).collect()).unwrap(),
            excess_data: B064K::try_from(&[][..]).unwrap(),
        };
        c.send(MESSAGE_TYPE_PROPOSE_TEMPLATE, msg).await.unwrap();
    }
}

/// The TP asks for `positions` of `request_id`'s `wtxid_list`.
async fn expect_missing(c: &mut TpClient, request_id: u32, positions: &[u16]) {
    let mut f = recv_in_time(c).await;
    assert_eq!(
        f.msg_type, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS,
        "{:?}",
        f.payload
    );
    let m: ProvideMissingTransactions = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    assert_eq!(m.request_id, request_id);
    assert_eq!(m.unknown_tx_position_list.into_inner(), positions);
}

/// The JDS leg of the round trip: `txs` as the JDC serialized them, under
/// the `request_id` the TP asked with.
async fn provide(c: &mut TpClient, request_id: u32, txs: &[Vec<u8>]) {
    let msg = ProvideMissingTransactionsSuccess {
        request_id,
        transaction_list: Seq064K::new(
            txs.iter()
                .map(|t| B016M::try_from(&t[..]).unwrap())
                .collect(),
        )
        .unwrap(),
    };
    c.send(MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS, msg)
        .await
        .unwrap();
}

async fn expect_job_error(c: &mut TpClient, request_id: u32, code: &str) {
    let mut f = recv_in_time(c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR, "{code}");
    let e: ProposeTemplateError = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    assert_eq!(e.request_id, request_id);
    assert_eq!(e.error_code.as_utf8_or_hex(), code);
}

/// `Success` names the tip the job was validated on, next to the id it is
/// retained under and the fee total of the declared transactions.
async fn expect_job_success(
    c: &mut TpClient,
    tc: &TestChain,
    request_id: u32,
    template_id: u64,
    fees: u64,
) {
    let mut f = recv_in_time(c).await;
    assert_eq!(
        f.msg_type, MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS,
        "{:?}",
        f.payload
    );
    let ok: ProposeTemplateSuccess = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    let tip = tc.chain.tip_header().expect("tip").block_hash();
    assert_eq!(
        (ok.request_id, ok.template_id, ok.fees),
        (request_id, template_id, fees)
    );
    assert_eq!(ok.prev_hash.as_ref(), tip.as_byte_array(), "validated tip");
}

/// The retained job answers `RequestTransactionData` with the declared txs
/// in block order, exactly like a built template.
async fn expect_retained(c: &mut TpClient, template_id: u64, txs: &[&Transaction]) {
    c.request_transaction_data(template_id).await.unwrap();
    let mut f = recv_in_time(c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS);
    let d: RequestTransactionDataSuccess = binary_sv2::from_bytes(&mut f.payload).unwrap();
    assert_eq!(d.template_id, template_id);
    let got: Vec<Vec<u8>> = d
        .transaction_list
        .iter()
        .map(|t| t.as_ref().to_vec())
        .collect();
    let want: Vec<Vec<u8>> = txs.iter().map(serialize).collect();
    assert_eq!(got, want, "retained txs in declared order");
}

/// docs/sv2-job-validation.md §4.1–4.3: a job whose txs are all in the
/// mempool and whose coinbase pays subsidy + fees is answered `Success` with
/// the next template id, the declared fee sum, and the tip it was validated
/// on, and is retained like a template.
#[tokio::test(flavor = "multi_thread")]
async fn propose_template_prices_and_retains_the_declared_job() {
    let tc = shared_regtest(2);
    mock_live_tip(&tc);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 3_000, cheap.clone());
    let b = spend(tc.coinbases[1], 2_000, cheap);
    for tx in [&a, &b] {
        tc.mempool.accept_tx(tx).expect("mempool accept");
    }
    let (tp, mut c) = connect_tp(&tc, REQUIRES_JOB_VALIDATION).await;
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let last = expect_template(&mut c, &tc, &[&a, &b], true).await;

    let height = tc.chain.query.tip_height().unwrap().0 + 1;
    let subsidy = block_subsidy(height, &tc.chain.params) as u64;
    let coinbase = job_coinbase(height, subsidy + 5_000, &[&a, &b]);
    Job::declare(&tc, 9, &coinbase, &[&a, &b])
        .send(&mut c)
        .await;
    expect_job_success(&mut c, &tc, 9, last + 1, 5_000).await;
    expect_retained(&mut c, last + 1, &[&a, &b]).await;

    tp.shutdown().await;
}

/// §4.1–4.2: a wtxid the TP cannot resolve answers `ProvideMissingTransactions`
/// with its 0-indexed position and holds the proposal under its
/// `request_id`; the JDS's `ProvideMissingTransactions.Success` for that id
/// completes the validation with the supplied tx merged in, and the tx is
/// retained with the job. The hold is per request: a provide for an id the
/// TP never asked about, already consumed, or held past `provide_timeout`
/// is `unknown-request-id`; a second proposal under an id still waiting is
/// `duplicate-request-id`; a provide that does not cover every requested
/// position, supplies a tx the TP did not ask for, or one that does not
/// decode, is `bad-missing-tx` and ends that exchange. The
/// hold is bounded: past `MAX_PENDING_PROPOSALS` waiting proposals the
/// oldest is dropped and its provide is `unknown-request-id` too. No
/// rejected or dropped proposal takes a template id.
#[tokio::test(flavor = "multi_thread")]
async fn propose_template_asks_for_and_accepts_missing_transactions() {
    let tc = shared_regtest(2);
    mock_live_tip(&tc);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 3_000, cheap.clone());
    let b = spend(tc.coinbases[1], 2_000, cheap.clone());
    // Decodable and unknown to the mempool, like `b`; never validated.
    let sibling = spend(tc.coinbases[1], 2_500, cheap);
    tc.mempool.accept_tx(&a).expect("mempool accept");
    let provide_timeout = Duration::from_secs(1);
    let (tp, mut c) = connect_tp_with(
        &tc,
        REQUIRES_JOB_VALIDATION,
        TEMPLATE_INTERVAL,
        provide_timeout,
    )
    .await;
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let last = expect_template(&mut c, &tc, &[&a], true).await;

    let height = tc.chain.query.tip_height().unwrap().0 + 1;
    let subsidy = block_subsidy(height, &tc.chain.params) as u64;
    let coinbase = job_coinbase(height, subsidy + 5_000, &[&a, &b]);
    let raw_b = serialize(&b);

    provide(&mut c, 77, std::slice::from_ref(&raw_b)).await;
    expect_job_error(&mut c, 77, "unknown-request-id").await;

    let job = Job::declare(&tc, 4, &coinbase, &[&a, &b]);
    job.send(&mut c).await;
    expect_missing(&mut c, 4, &[1]).await;
    job.send(&mut c).await;
    expect_job_error(&mut c, 4, "duplicate-request-id").await;
    provide(&mut c, 4, std::slice::from_ref(&raw_b)).await;
    expect_job_success(&mut c, &tc, 4, last + 1, 5_000).await;
    expect_retained(&mut c, last + 1, &[&a, &b]).await;
    provide(&mut c, 4, std::slice::from_ref(&raw_b)).await;
    expect_job_error(&mut c, 4, "unknown-request-id").await;

    Job::declare(&tc, 5, &coinbase, &[&a, &b])
        .send(&mut c)
        .await;
    expect_missing(&mut c, 5, &[1]).await;
    provide(&mut c, 5, &[serialize(&a)]).await;
    expect_job_error(&mut c, 5, "bad-missing-tx").await;
    provide(&mut c, 5, std::slice::from_ref(&raw_b)).await;
    expect_job_error(&mut c, 5, "unknown-request-id").await;

    Job::declare(&tc, 6, &coinbase, &[&a, &b, &sibling])
        .send(&mut c)
        .await;
    expect_missing(&mut c, 6, &[1, 2]).await;
    provide(&mut c, 6, std::slice::from_ref(&raw_b)).await;
    expect_job_error(&mut c, 6, "bad-missing-tx").await;
    provide(&mut c, 6, &[raw_b.clone(), serialize(&sibling)]).await;
    expect_job_error(&mut c, 6, "unknown-request-id").await;

    let blob = vec![0xee; 40];
    let mut garbage = Job::declare(&tc, 8, &coinbase, &[]);
    garbage.wtxids = vec![sha256d::Hash::hash(&blob).to_byte_array()];
    garbage.send(&mut c).await;
    expect_missing(&mut c, 8, &[0]).await;
    provide(&mut c, 8, &[blob]).await;
    expect_job_error(&mut c, 8, "bad-missing-tx").await;

    for id in 10..10 + MAX_PENDING_PROPOSALS as u32 + 1 {
        Job::declare(&tc, id, &coinbase, &[&a, &b])
            .send(&mut c)
            .await;
        expect_missing(&mut c, id, &[1]).await;
    }
    provide(&mut c, 10, std::slice::from_ref(&raw_b)).await;
    expect_job_error(&mut c, 10, "unknown-request-id").await;
    provide(&mut c, 11, std::slice::from_ref(&raw_b)).await;
    expect_job_success(&mut c, &tc, 11, last + 2, 5_000).await;

    Job::declare(&tc, 7, &coinbase, &[&a, &b])
        .send(&mut c)
        .await;
    expect_missing(&mut c, 7, &[1]).await;
    tokio::time::sleep(provide_timeout + provide_timeout / 2).await;
    provide(&mut c, 7, &[raw_b]).await;
    expect_job_error(&mut c, 7, "unknown-request-id").await;

    c.request_transaction_data(last + 3).await.unwrap();
    let mut f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);
    let e: RequestTransactionDataError = binary_sv2::from_bytes(&mut f.payload).unwrap();
    assert_eq!(
        e.error_code.as_utf8_or_hex(),
        "template-id-not-found",
        "only the two completed jobs took ids"
    );

    tp.shutdown().await;
}

/// §4.1 and §4.4: everything in a job comes from a JDC. The checks run in
/// order before any mempool lookup or transaction decode: a repeated wtxid
/// is refused on arrival, even while the tip is stale (IBD) and every other
/// job is `job-validation-unavailable`; then a coinbase prefix that does
/// not parse or a coinbase that does not decode, then the proposal check's
/// own reject string: a declaration from before the tip moved fails its
/// BIP34 height, an overpaying coinbase its amount. Nothing is retained on
/// an error.
#[tokio::test(flavor = "multi_thread")]
async fn propose_template_rejects_untrusted_input_in_order() {
    let tc = shared_regtest(2);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 3_000, cheap.clone());
    let b = spend(tc.coinbases[1], 2_000, cheap);
    for tx in [&a, &b] {
        tc.mempool.accept_tx(tx).expect("mempool accept");
    }
    let (tp, mut c) = connect_tp(&tc, REQUIRES_JOB_VALIDATION).await;
    let height = tc.chain.query.tip_height().unwrap().0 + 1;
    let subsidy = block_subsidy(height, &tc.chain.params) as u64;
    let coinbase = job_coinbase(height, subsidy + 5_000, &[&a, &b]);

    // The padded tip is far in the past: the node is in IBD.
    Job::declare(&tc, 1, &coinbase, &[&a, &b])
        .send(&mut c)
        .await;
    expect_job_error(&mut c, 1, "job-validation-unavailable").await;
    Job::declare(&tc, 10, &coinbase, &[&a, &a])
        .send(&mut c)
        .await;
    expect_job_error(&mut c, 10, "duplicate-wtxid").await;
    mock_live_tip(&tc);
    c.coinbase_output_constraints(0, 0).await.unwrap();
    let last = expect_template(&mut c, &tc, &[&a, &b], true).await;

    Job::declare(&tc, 2, &coinbase, &[&a, &a])
        .send(&mut c)
        .await;
    expect_job_error(&mut c, 2, "duplicate-wtxid").await;

    // More scriptSig bytes than the length the prefix declares.
    let mut short_sig = Job::declare(&tc, 5, &coinbase, &[&a, &b]);
    short_sig.coinbase_prefix.extend_from_slice(&[0; 16]);
    short_sig.send(&mut c).await;
    expect_job_error(&mut c, 5, "bad-cb-decode").await;

    let mut two_inputs = Job::declare(&tc, 6, &coinbase, &[&a, &b]);
    two_inputs.coinbase_prefix[4 + 2] = 2;
    two_inputs.send(&mut c).await;
    expect_job_error(&mut c, 6, "bad-cb-decode").await;

    let mut bad_cb = Job::declare(&tc, 7, &coinbase, &[&a, &b]);
    bad_cb.coinbase_suffix.truncate(3);
    bad_cb.send(&mut c).await;
    expect_job_error(&mut c, 7, "bad-cb-decode").await;

    let old = job_coinbase(height - 1, subsidy + 5_000, &[&a, &b]);
    Job::declare(&tc, 8, &old, &[&a, &b]).send(&mut c).await;
    expect_job_error(&mut c, 8, "bad-cb-height").await;

    let fat = job_coinbase(height, subsidy + 5_001, &[&a, &b]);
    Job::declare(&tc, 9, &fat, &[&a, &b]).send(&mut c).await;
    expect_job_error(&mut c, 9, "bad-cb-amount").await;

    c.request_transaction_data(last + 1).await.unwrap();
    let mut f = recv_in_time(&mut c).await;
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);
    let e: RequestTransactionDataError = binary_sv2::from_bytes(&mut f.payload).unwrap();
    assert_eq!(
        e.error_code.as_utf8_or_hex(),
        "template-id-not-found",
        "a rejected job must not take a template id"
    );

    tp.shutdown().await;
}

/// §4.5: a `SubmitSolution` on a validated job's template id is assembled
/// from the retained job and the JDS's final coinbase (extranonce in place
/// of the placeholder) and accepted like one for a pushed template.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_for_a_validated_job_becomes_the_tip() {
    let tc = shared_regtest(2);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let a = spend(tc.coinbases[0], 3_000, cheap.clone());
    let b = spend(tc.coinbases[1], 2_000, cheap);
    for tx in [&a, &b] {
        tc.mempool.accept_tx(tx).expect("mempool accept");
    }
    let FirstTemplate {
        tp,
        mut c,
        template_id: last,
        version,
        header: sent,
        ..
    } = first_template(&tc, REQUIRES_JOB_VALIDATION).await;
    let height = tc.chain.query.tip_height().unwrap().0 + 1;
    let subsidy = block_subsidy(height, &tc.chain.params) as u64;
    let mut coinbase = job_coinbase(height, subsidy + 5_000, &[&a, &b]);
    Job::declare(&tc, 1, &coinbase, &[&a, &b])
        .send(&mut c)
        .await;
    expect_job_success(&mut c, &tc, 1, last + 1, 5_000).await;

    let mut script_sig = bip34_height_script(height);
    script_sig.extend_from_slice(&[0x42; EXTRANONCE_LEN]);
    coinbase.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
    let mut leaves = vec![coinbase.compute_txid().to_byte_array()];
    leaves.extend([&a, &b].iter().map(|tx| tx.compute_txid().to_byte_array()));
    let mut header = bitcoin::block::Header {
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(merkle_root_from_txids(&leaves)),
        ..sent
    };
    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    c.submit_solution(
        last + 1,
        version,
        header.time,
        header.nonce,
        &serialize(&coinbase),
    )
    .await
    .unwrap();
    let f = recv_in_time(&mut c).await;
    assert_eq!(
        f.msg_type, MESSAGE_TYPE_NEW_TEMPLATE,
        "the new tip's template"
    );
    assert_eq!(
        tc.chain.tip_header().unwrap().block_hash(),
        header.block_hash()
    );

    tp.shutdown().await;
}

/// A proposal's validation runs off the session loop. The proposal declares
/// a few hundred spends of one confirmed fan-out that the mempool lacks, so
/// each copy is asked for all of them and the costly frame (tens of
/// milliseconds) is the `ProvideMissingTransactions.Success` that completes
/// it, while every template stays coinbase-only; the first copy measures
/// that wall. A `RequestTransactionData` sent right behind the second copy's
/// provide is answered before that copy's `Success`, in a small fraction of
/// the validation it overlapped: the request has no blocking work behind
/// it, so a slower answer would mean the loop waited on the validation and
/// the order was luck; a `ProposeTemplate` under the id in flight is refused
/// `duplicate-request-id` on arrival the same way. A `SubmitSolution` sent
/// behind the third copy's
/// provide is accepted while that copy validates and pushes the solved
/// tip's `NewTemplate`. Its accept ends in a tip write, so it is not ordered
/// against the copy's reply, which is the straddle the plan names:
/// `Success` on the tip the validation started on, or the proposal check's
/// own reject once the tip moved first.
#[tokio::test(flavor = "multi_thread")]
async fn propose_template_validation_does_not_delay_other_frames() {
    let tc = shared_regtest(1);
    let cheap = ScriptBuf::from_bytes(vec![OP_TRUE]);
    let outs = 400u64;
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
    let fanout_txid = fanout.compute_txid();
    let spends: Vec<Transaction> = (0..outs as u32)
        .map(|vout| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: fanout_txid,
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(each - 1_000),
                script_pubkey: cheap.clone(),
            }],
        })
        .collect();
    let declared: Vec<&Transaction> = spends.iter().collect();

    let FirstTemplate {
        tp,
        mut c,
        template_id,
        version,
        mut header,
        coinbase,
    } = first_template(&tc, REQUIRES_JOB_VALIDATION).await;
    let height = tc.chain.query.tip_height().unwrap().0 + 1;
    let subsidy = block_subsidy(height, &tc.chain.params) as u64;
    let fees = outs * 1_000;
    let mut job = Job::declare(
        &tc,
        1,
        &job_coinbase(height, subsidy + fees, &declared),
        &declared,
    );
    // Provided, not pooled: the templates stay coinbase-only.
    let supplied: Vec<Vec<u8>> = spends.iter().map(serialize).collect();
    let all: Vec<u16> = (0..outs as u16).collect();

    job.send(&mut c).await;
    expect_missing(&mut c, 1, &all).await;
    let asked = tokio::time::Instant::now();
    provide(&mut c, 1, &supplied).await;
    expect_job_success(&mut c, &tc, 1, template_id + 1, fees).await;
    let alone = asked.elapsed();

    job.request_id = 2;
    job.send(&mut c).await;
    expect_missing(&mut c, 2, &all).await;
    let proposed = tokio::time::Instant::now();
    provide(&mut c, 2, &supplied).await;
    job.send(&mut c).await;
    c.request_transaction_data(template_id).await.unwrap();
    expect_job_error(&mut c, 2, "duplicate-request-id").await;
    let f = recv_in_time(&mut c).await;
    let requested = proposed.elapsed();
    assert_eq!(
        f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
        "the request's reply must precede the proposal's (validation alone {alone:?})"
    );
    expect_job_success(&mut c, &tc, 2, template_id + 2, fees).await;
    let replied = proposed.elapsed();
    assert!(
        requested * 4 < replied,
        "request answered in {requested:?} against a validation of {replied:?}"
    );

    while header.validate_pow(header.target()).is_err() {
        header.nonce += 1;
    }
    job.request_id = 3;
    job.send(&mut c).await;
    expect_missing(&mut c, 3, &all).await;
    provide(&mut c, 3, &supplied).await;
    c.submit_solution(template_id, version, header.time, header.nonce, &coinbase)
        .await
        .unwrap();
    let mut pushed = None;
    let mut verdict = None;
    for _ in 0..2 {
        let mut f = recv_in_time(&mut c).await;
        match f.msg_type {
            MESSAGE_TYPE_NEW_TEMPLATE => {
                assert_eq!(
                    tc.chain.tip_header().unwrap().block_hash(),
                    header.block_hash(),
                    "the solution became the tip before its template was pushed"
                );
                pushed = Some(check_template(&mut c, &tc, f, &[], true).await);
            }
            MESSAGE_TYPE_PROPOSE_TEMPLATE_SUCCESS => {
                let ok: ProposeTemplateSuccess =
                    binary_sv2::from_bytes(&mut f.payload).expect("decode");
                assert_eq!((ok.request_id, ok.fees), (3, fees));
                assert_eq!(
                    ok.prev_hash.as_ref(),
                    header.prev_blockhash.as_byte_array(),
                    "validated on the tip it started on"
                );
                verdict = Some(Some(ok.template_id));
            }
            MESSAGE_TYPE_PROPOSE_TEMPLATE_ERROR => {
                let e: ProposeTemplateError =
                    binary_sv2::from_bytes(&mut f.payload).expect("decode");
                assert_eq!(e.request_id, 3);
                assert!(
                    ["inconclusive-not-best-prevblk", "bad-cb-height"]
                        .contains(&e.error_code.as_utf8_or_hex().as_str()),
                    "a tip change mid-validation fails the proposal check: {}",
                    e.error_code.as_utf8_or_hex()
                );
                verdict = Some(None);
            }
            t => panic!("unexpected frame {t:#x}"),
        }
    }
    let pushed = pushed.expect("the solved tip's template");
    let mut ids = vec![pushed];
    ids.extend(verdict.expect("the proposal's reply"));
    ids.sort_unstable();
    let want: Vec<u64> = (template_id + 3..template_id + 3 + ids.len() as u64).collect();
    assert_eq!(ids, want, "ids follow the order the loop replied in");

    tp.shutdown().await;
}
