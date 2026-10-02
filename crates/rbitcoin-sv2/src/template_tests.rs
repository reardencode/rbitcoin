use crate::test_chain::{padded_chain, TestChain};
use crate::testutil::TpClient;
use crate::{run_sv2_tp, Sv2TpConfig, SETUP_TIMEOUT, WRITE_TIMEOUT};
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
};
use rbitcoin_primitives::Height;
use rbitcoin_store::merkle_root_from_txids;
use std::sync::Arc;
use std::time::Duration;
use template_distribution_sv2::{
    NewTemplate, SetNewPrevHash, MESSAGE_TYPE_NEW_TEMPLATE, MESSAGE_TYPE_SET_NEW_PREV_HASH,
};

const MAX_BLOCK_WEIGHT: u64 = 4_000_000;
const OP_TRUE: u8 = 0x51;
const OP_CHECKSIG: u8 = 0xac;

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
    let tc = padded_chain("sv2-template", 3);
    // Tip time as "now": the padded chain is out of IBD for this test.
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
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
    let tc = padded_chain("sv2-template-resent", 1);
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
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
    let tc = padded_chain("sv2-template-rate", 1);
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
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
    let tc = padded_chain("sv2-gate", 0);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
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

async fn first_template(tc: &TestChain) -> FirstTemplate {
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
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
    use template_distribution_sv2::MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS;

    let tc = padded_chain("sv2-pow-precheck", 0);
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

    tp.shutdown().await;
}

/// A client that leaves the coinbase witness empty still solves the block:
/// the TP fills the zero reserved value the witness commitment was built
/// with. The txid, and so the merkle root, does not cover the witness.
#[tokio::test(flavor = "multi_thread")]
async fn submit_solution_without_coinbase_witness_is_accepted() {
    let tc = padded_chain("sv2-no-cb-witness", 0);
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
    let tc = padded_chain("sv2-no-commitment", 0);
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
    let tc = padded_chain("sv2-fast-clock", 0);
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
    let tc = padded_chain("sv2-template-flood", 0);
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain: Arc::clone(&tc.chain),
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
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
    let tc = padded_chain("sv2-template-tip-race", 1);
    tc.chain.clock.set_mock(i64::from(tc.tip_time));
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
    let x = mine_regtest_paying(tip, tc.tip_time + 1, h + 1, script, vec![paid.clone()]);
    let y = mine_empty_regtest(x.block_hash(), tc.tip_time + 2, h + 2);
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
