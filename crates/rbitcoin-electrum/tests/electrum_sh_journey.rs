use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_electrum::server::*;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::TxApply;
use rbitcoin_query::{accept_and_connect_block, Query};
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

#[cfg(debug_assertions)]
use crate::server::electrum_tcp_batch;
use crate::server::electrum_tcp_rpc;

fn tmp_store() -> (rbitcoin_query::testutil::TempDir, Query) {
    rbitcoin_query::testutil::tiny_query_labeled("electrum-sh")
}

#[doc(hidden)]
pub fn op_true_apply(tag: u8) -> TxApply {
    let mut txid = [0u8; 32];
    txid[0] = tag;
    txid[31] = 0xcb;
    TxApply {
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
            script_sig: vec![tag],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    }
}

#[doc(hidden)]
pub fn connect_op_true(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) -> [u8; 32] {
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&height.to_le_bytes());
    merkle[5] = 0xec;
    let hash =
        rbitcoin_store::block_header_hash(1, &parent, &merkle, height + 1, 0x207fffff, height);
    let hdr = HeaderRecord {
        prev_fk: prev,
        version: 1,
        timestamp: height + 1,
        bits: 0x207fffff,
        nonce: height,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    q.connect_block(Height(height), &hdr, &[op_true_apply(height as u8)])
        .unwrap();
    hash
}

#[doc(hidden)]
pub fn class_a_op_true(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) -> [u8; 32] {
    let merkle = [0x11; 32];
    let hash =
        rbitcoin_store::block_header_hash(1, &parent, &merkle, height + 1, 0x207fffff, height);
    let hdr = HeaderRecord {
        prev_fk: prev,
        version: 1,
        timestamp: height + 1,
        bits: 0x207fffff,
        nonce: height,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    q.commit_class_a_only(&hdr, &[op_true_apply(height as u8)])
        .unwrap();
    q.confirm_block(Height(height), &hash).unwrap();
    hash
}

#[doc(hidden)]
pub fn view_hash(q: &Query) -> ([u8; 32], Height) {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let sh = electrum_scripthash_hex(&[0x51]);
    let (out, view) = electrum_at_chain_view(
        q,
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        |q, rpc_params, view, is_asof| {
            let mut pin_conn = ElectrumConn::new();
            dispatch_pinned(
                "blockchain.scripthash.get_balance",
                rpc_params,
                q,
                &cfg,
                &params,
                None,
                &mut pin_conn,
                view,
                is_asof,
            )
        },
    );
    assert!(out.is_ok(), "{out:?}");
    let v = view.unwrap();
    (v.hash, v.height)
}

#[doc(hidden)]
pub fn stamp_follows_pending(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) {
    let indexed = q.sh_indexed_through_height();
    let hash = class_a_op_true(q, height, prev, parent);
    assert_eq!(q.tip_height(), Some(Height(height)));
    assert_eq!(q.sh_indexed_through_height(), indexed);
    let (pending_hash, pending_h) = view_hash(q);
    assert_eq!(pending_hash, hash);
    assert_eq!(pending_h, Height(height));
    q.apply_sh_pending().unwrap();
    let (durable_hash, durable_h) = view_hash(q);
    assert_eq!(durable_hash, hash);
    assert_eq!(durable_h, Height(height));
}

#[doc(hidden)]
pub fn casa_cap_then_balance_history_unspent(q: &Query) {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let sh = electrum_scripthash_hex(&[0x51]);
    q.set_max_sh_creates(2);
    let mut capped = ElectrumConn::new();
    let err = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        q,
        &cfg,
        &params,
        None,
        &mut capped,
    )
    .unwrap_err();
    assert!(
        err.contains("scripthash join exceeds --max-sh-creates"),
        "{err}"
    );
    let ping = dispatch_with_join(
        "server.ping",
        &json!([]),
        q,
        &cfg,
        &params,
        None,
        &mut capped,
    )
    .unwrap();
    assert!(ping.is_null(), "{ping}");
    q.set_max_sh_creates(0);

    let mut conn = ElectrumConn::new();

    let bal = dispatch_with_join(
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert!(bal["confirmed"].as_i64().unwrap() > 0, "{bal}");

    let hist = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert!(!hist.as_array().unwrap().is_empty());

    let unspent = dispatch_with_join(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap();
    assert!(!unspent.as_array().unwrap().is_empty());
}

/// Unpaged joins above `--heavy-sh-creates` run one at a time across every
/// connection, from separate connections and from one batch, while lighter
/// joins overlap. The armed probe makes each join wait inside for a second
/// of its kind, so the peaks only stay at 1 because of the lock. A refused
/// join takes no turn, and a turn is given back after every join.
#[cfg(debug_assertions)]
pub async fn heavy_joins_take_turns(q: Arc<Query>) {
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.batch_window = 4;
    let (tip_tx, _) = broadcast::channel(4);
    let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, None)
        .await
        .expect("listen");
    let heavy = electrum_scripthash_hex(&[0x51]);
    let balance = |id: u32, sh: &str| json!({"jsonrpc":"2.0","id":id,"method":"blockchain.scripthash.get_balance","params":[sh]});
    q.set_heavy_sh_creates(1);
    q.set_max_sh_creates(2);
    let mut refused = TcpStream::connect(handle.local_addr).await.unwrap();
    let err = electrum_tcp_rpc(
        &mut refused,
        1,
        "blockchain.scripthash.get_balance",
        json!([heavy]),
    )
    .await;
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("--max-sh-creates"),
        "{err}"
    );
    q.set_max_sh_creates(0);
    q.sh_join_probe.arm();

    let mut a = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut b = TcpStream::connect(handle.local_addr).await.unwrap();
    let one = |sh: &str| {
        let mut line = serde_json::to_string(&balance(1, sh)).unwrap();
        line.push('\n');
        line
    };
    use tokio::io::AsyncWriteExt;
    a.write_all(one(&heavy).as_bytes()).await.unwrap();
    b.write_all(one(&heavy).as_bytes()).await.unwrap();
    let mut answers = Vec::new();
    for s in [&mut a, &mut b] {
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await.unwrap();
        answers.push(serde_json::from_str::<Value>(&line).unwrap());
    }
    assert_eq!(answers[0]["result"], answers[1]["result"], "{answers:?}");
    assert!(answers[0]["result"]["confirmed"].as_u64().unwrap() > 0);

    let light_a = format!("{:064x}", 0x11);
    let light_b = format!("{:064x}", 0x22);
    let mut c = TcpStream::connect(handle.local_addr).await.unwrap();
    let batch = electrum_tcp_batch(
        &mut c,
        &[
            balance(1, &heavy),
            balance(2, &heavy),
            balance(3, &light_a),
            balance(4, &light_b),
        ],
    )
    .await;
    let slots = batch.as_array().expect("array");
    assert_eq!(slots.len(), 4, "{batch}");
    assert_eq!(slots[0]["result"], answers[0]["result"], "{batch}");
    assert_eq!(slots[1]["result"], answers[0]["result"], "{batch}");
    assert_eq!(q.sh_join_probe.entered(), (2, 4), "two light, four heavy");
    assert_eq!(
        q.sh_join_probe.peaks(),
        (2, 1),
        "light joins overlap, heavy joins take turns"
    );

    let creates = q
        .scripthash_create_count(&rbitcoin_primitives::parse_display_hash32(&heavy).unwrap())
        .unwrap();
    q.set_heavy_sh_creates(creates);
    q.sh_join_probe.arm();
    let mut d = TcpStream::connect(handle.local_addr).await.unwrap();
    electrum_tcp_rpc(
        &mut d,
        1,
        "blockchain.scripthash.get_balance",
        json!([heavy]),
    )
    .await;
    assert_eq!(
        q.sh_join_probe.entered(),
        (1, 0),
        "a join at exactly --heavy-sh-creates is light"
    );
    q.set_heavy_sh_creates(rbitcoin_query::DEFAULT_HEAVY_SH_CREATES);
    handle.shutdown().await;
}

/// A batch read reports its own dispatch time, not the wait behind a slow
/// neighbour, and a read that never used the join cache leaves the one an
/// earlier `get_history` built. The probe holds a lone heavy join for
/// `SH_JOIN_PROBE_WAIT`, which makes the slow neighbour.
#[cfg(debug_assertions)]
pub async fn batch_reads_time_themselves_and_keep_the_join(q: Arc<Query>) {
    use rbitcoin_query::scripthash::SH_JOIN_PROBE_WAIT;
    let params = ChainParams::regtest();
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.batch_window = 2;
    let (tip_tx, _) = broadcast::channel(4);
    let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, None)
        .await
        .expect("listen");
    let sh = electrum_scripthash_hex(&[0x51]);
    let call = |id: u32, method: &str, params: Value| json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});

    q.set_heavy_sh_creates(1);
    q.sh_join_probe.arm();
    let mut a = TcpStream::connect(handle.local_addr).await.unwrap();
    batch_trace_arm();
    electrum_tcp_batch(
        &mut a,
        &[
            call(1, "blockchain.scripthash.get_balance", json!([sh])),
            call(2, "blockchain.block.header", json!([0])),
        ],
    )
    .await;
    let trace = batch_trace_snapshot();
    batch_trace_clear();
    let took = |i: usize| {
        trace
            .iter()
            .find_map(|s| match s {
                BatchStep::Timed(j, d) if *j == i => Some(*d),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no time for {i}: {trace:?}"))
    };
    assert!(took(0) >= SH_JOIN_PROBE_WAIT, "{trace:?}");
    assert!(
        took(1) < SH_JOIN_PROBE_WAIT / 2,
        "the header read reports its own time, not the join ahead of it: {trace:?}"
    );

    q.set_heavy_sh_creates(rbitcoin_query::DEFAULT_HEAVY_SH_CREATES);
    q.sh_join_probe.arm();
    let mut b = TcpStream::connect(handle.local_addr).await.unwrap();
    let missing = format!("{:064x}", 0x77);
    electrum_tcp_batch(
        &mut b,
        &[
            call(1, "blockchain.scripthash.get_history", json!([sh])),
            call(2, "blockchain.transaction.get", json!([missing])),
            call(3, "blockchain.block.header", json!([0])),
        ],
    )
    .await;
    let again = electrum_tcp_rpc(&mut b, 4, "blockchain.scripthash.get_history", json!([sh])).await;
    assert!(
        again["result"].as_array().is_some_and(|r| !r.is_empty()),
        "{again}"
    );
    assert_eq!(
        q.sh_join_probe.entered(),
        (1, 0),
        "the later get_history reuses the batch's join"
    );
    handle.shutdown().await;
}

#[doc(hidden)]
pub fn spend_coinbase(cbtxid: bitcoin::Txid, fee: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbtxid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - fee),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn tx_spending(txid: bitcoin::Txid, value: u64, script: &[u8]) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(script.to_vec()),
        }],
    }
}

#[doc(hidden)]
pub fn listunspent_skips_unused(q: &Arc<Query>, hub: &MempoolHub, spent_cb: &bitcoin::Txid) {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let unused = electrum_scripthash_hex(&[0x00]);
    let _ = hub.sample_reset_perf();
    let empty = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([unused]),
        q,
        &cfg,
        &params,
        Some(hub),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    assert!(empty.as_array().unwrap().is_empty());
    assert_eq!(
        hub.sample_reset_perf().spent_body_loads,
        0,
        "unused scripthash must not load mempool bodies"
    );
    let sh = electrum_scripthash_hex(&[0x51]);
    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &json!([sh]),
        q,
        &cfg,
        &params,
        Some(hub),
        &mut header_sub,
        &mut sh_subs,
    )
    .unwrap();
    let rows = unspent.as_array().unwrap();
    let spent = format!("{spent_cb}");
    assert!(
        rows.iter().all(|r| r["tx_hash"] != spent),
        "mempool-spent coinbase must drop: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r["height"] == 0),
        "mempool output must remain: {rows:?}"
    );
}

pub async fn read_push(stream: &mut TcpStream) -> Value {
    let mut reader = BufReader::new(&mut *stream);
    let mut resp = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut resp),
    )
    .await
    .unwrap()
    .unwrap();
    serde_json::from_str(&resp).unwrap()
}

pub async fn tip_push_two_clients_and_late(q: Arc<Query>, hub: Option<Arc<MempoolHub>>) {
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx.clone(), hub)
        .await
        .unwrap();
    let mut first = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut second = TcpStream::connect(handle.local_addr).await.unwrap();
    let sub = electrum_tcp_rpc(&mut first, 1, "blockchain.headers.subscribe", json!([])).await;
    assert!(sub.get("result").is_some(), "{sub}");
    let sub = electrum_tcp_rpc(&mut second, 1, "blockchain.headers.subscribe", json!([])).await;
    assert!(sub.get("result").is_some(), "{sub}");
    tip_tx
        .send(TipNotify {
            height: 3,
            header_hex: "aa".repeat(80),
            reorg_from_height: None,
        })
        .unwrap();
    for stream in [&mut first, &mut second] {
        let push = read_push(stream).await;
        assert_eq!(
            push["method"].as_str(),
            Some("blockchain.headers.subscribe")
        );
    }
    let mut late = TcpStream::connect(handle.local_addr).await.unwrap();
    let caught = electrum_tcp_rpc(&mut late, 1, "blockchain.headers.subscribe", json!([])).await;
    assert!(
        caught.get("result").is_some(),
        "a client that missed the push catches up on the next request: {caught}"
    );
    handle.shutdown().await;
}

#[doc(hidden)]
pub fn connect_script_block(
    q: &Query,
    height: u32,
    prev: Fk,
    parent: [u8; 32],
    extra: Vec<TxApply>,
) -> (Fk, [u8; 32], [u8; 32]) {
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&height.to_le_bytes());
    merkle[5] = 0xec;
    let hash =
        rbitcoin_store::block_header_hash(1, &parent, &merkle, height + 1, 0x207fffff, height);
    let hdr = HeaderRecord {
        prev_fk: prev,
        version: 1,
        timestamp: height + 1,
        bits: 0x207fffff,
        nonce: height,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    let cb = op_true_apply(height as u8);
    let cbtxid = cb.tx.txid;
    let mut txs = vec![cb];
    txs.extend(extra);
    let fk = q.connect_block(Height(height), &hdr, &txs).unwrap();
    (fk, hash, cbtxid)
}

/// Old creates, a tip create, and a tip spend of the oldest coin. A
/// `from_height` above 0 is that window and is served above the create cap.
/// Open history, and a window that still starts at height 0, stay capped.
#[test]
#[doc(hidden)]
pub fn from_height_window_is_served_above_the_create_cap() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let sh = electrum_scripthash_hex(&[0x51]);
    let mut prev = Fk::NULL;
    let mut parent = [0u8; 32];
    let mut oldest = [0u8; 32];
    for h in 0..5u32 {
        let (fk, hash, txid) = connect_script_block(&q, h, prev, parent, Vec::new());
        if h == 0 {
            oldest = txid;
        }
        prev = fk;
        parent = hash;
    }
    let (create_fk, _) = q.get_tx_by_txid(&oldest).unwrap().unwrap();
    let mut spend = op_true_apply(0xee);
    spend.inputs = vec![InputRecord {
        prev_txid: oldest,
        parent: rbitcoin_store::InputParent::Prevout { create_fk, vout: 0 },
        sequence: u32::MAX,
        script_sig: vec![],
        witness: vec![],
    }];
    let spend_txid = spend.tx.txid;
    let tip = 5u32;
    let (_fk, _hash, tip_cb) = connect_script_block(&q, tip, prev, parent, vec![spend]);

    q.set_max_sh_creates(2);
    let mut conn = ElectrumConn::new();
    let open = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap_err();
    assert!(
        open.contains("scripthash join exceeds --max-sh-creates"),
        "{open}"
    );
    let from_zero = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh, 0, tip + 1]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    )
    .unwrap_err();
    assert!(
        from_zero.contains("scripthash join exceeds --max-sh-creates"),
        "{from_zero}"
    );

    let window = dispatch_with_join(
        "blockchain.scripthash.get_history",
        &json!([sh, tip, tip + 1]),
        &q,
        &cfg,
        &params,
        None,
        &mut conn,
    );
    assert!(
        window.is_ok(),
        "a from_height window must not hit the create cap: {window:?}"
    );
    let rows = window.unwrap();
    let hashes: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["tx_hash"].as_str())
        .collect();
    let tip_hex = rbitcoin_primitives::display_hash_hex(tip_cb);
    let spend_hex = rbitcoin_primitives::display_hash_hex(spend_txid);
    let old_hex = rbitcoin_primitives::display_hash_hex(oldest);
    assert!(hashes.contains(&tip_hex.as_str()), "{hashes:?}");
    assert!(hashes.contains(&spend_hex.as_str()), "{hashes:?}");
    assert!(!hashes.contains(&old_hex.as_str()), "{hashes:?}");
    assert_eq!(hashes.len(), 2, "{hashes:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A later spend of a different output of a payment is not this script's
/// history. The output that does pay the script still is.
#[test]
#[doc(hidden)]
pub fn from_height_ignores_a_spend_of_another_output() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let sh = electrum_scripthash_hex(&[0x51]);
    let mut pay = op_true_apply(0xd0);
    pay.tx.output_count = 2;
    pay.tx.txid[31] = 0xce;
    pay.outputs = vec![
        OutputRecord::unspent(1, vec![0x51]),
        OutputRecord::unspent(1, vec![0x00]),
    ];
    let pay_txid = pay.tx.txid;
    let (mut prev, mut parent, _) = connect_script_block(&q, 0, Fk::NULL, [0u8; 32], vec![pay]);
    for h in 1..3u32 {
        let (fk, hash, _) = connect_script_block(&q, h, prev, parent, Vec::new());
        prev = fk;
        parent = hash;
    }
    let (create_fk, _) = q.get_tx_by_txid(&pay_txid).unwrap().unwrap();
    let spend_of = |tag: u8, vout: u32| {
        let mut spend = op_true_apply(tag);
        spend.tx.txid[31] = 0xce;
        spend.outputs = vec![OutputRecord::unspent(1, vec![0x00])];
        spend.inputs = vec![InputRecord {
            prev_txid: pay_txid,
            parent: rbitcoin_store::InputParent::Prevout { create_fk, vout },
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![],
        }];
        spend
    };
    let foreign = spend_of(0xe1, 1);
    let foreign_txid = foreign.tx.txid;
    let (prev, parent, _) = connect_script_block(&q, 3, prev, parent, vec![foreign]);
    let real = spend_of(0xe0, 0);
    let real_txid = real.tx.txid;
    let (_fk, _hash, tip_cb) = connect_script_block(&q, 4, prev, parent, vec![real]);

    let mut conn = ElectrumConn::new();
    let mut hashes_of = |from: u32, to: u32| {
        let rows = dispatch_with_join(
            "blockchain.scripthash.get_history",
            &json!([sh, from, to]),
            &q,
            &cfg,
            &params,
            None,
            &mut conn,
        )
        .unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["tx_hash"].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let foreign_hex = rbitcoin_primitives::display_hash_hex(foreign_txid);
    let real_hex = rbitcoin_primitives::display_hash_hex(real_txid);
    let tip_hex = rbitcoin_primitives::display_hash_hex(tip_cb);
    let other = hashes_of(3, 4);
    assert!(
        !other.iter().any(|h| h == &foreign_hex),
        "spend of the other output is not this script: {other:?}"
    );
    assert_eq!(other.len(), 1, "{other:?}");
    let mine = hashes_of(4, 5);
    assert!(mine.iter().any(|h| h == &real_hex), "{mine:?}");
    assert!(mine.iter().any(|h| h == &tip_hex), "{mine:?}");
    assert!(!mine.iter().any(|h| h == &foreign_hex), "{mine:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
pub async fn electrum_sh_join() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    const N_SPENDS: u32 = 4;
    let (tip, _tip_time, coinbase_txids) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        100 + N_SPENDS,
        N_SPENDS,
    );
    let mut parent = tip.to_byte_array();
    let mut prev = q.tip_header_fk().unwrap().unwrap();
    let base = q.tip_height().unwrap().0;
    for step in 1..3u32 {
        parent = connect_op_true(&q, base + step, prev, parent);
        prev = q.tip_header_fk().unwrap().unwrap();
    }
    stamp_follows_pending(&q, base + 3, prev, parent);
    casa_cap_then_balance_history_unspent(&q);

    let q = Arc::new(q);
    #[cfg(debug_assertions)]
    {
        heavy_joins_take_turns(Arc::clone(&q)).await;
        batch_reads_time_themselves_and_keep_the_join(Arc::clone(&q)).await;
    }
    let hub = MempoolHub::open(dir.join("mempool"), Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    for (i, cbtxid) in coinbase_txids.iter().enumerate() {
        hub.accept_tx(&spend_coinbase(*cbtxid, 1_000 + i as u64))
            .expect("accept spend");
    }
    listunspent_skips_unused(&q, &hub, &coinbase_txids[0]);
    tip_push_two_clients_and_late(Arc::clone(&q), Some(hub)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A spend stays unconfirmed for wallets until the visible scripthash height
/// covers its block. A spend whose block that view already covers stays out.
/// A payment to a different script stays in that script's unconfirmed answer,
/// and a spend of a covered parent that is still in the pool counts once.
#[test]
#[allow(clippy::cognitive_complexity)] // one chain, three wallet answers
fn unconfirmed_until_sh_visible() {
    const FEE_A: u64 = 1_000;
    const FEE_B: u64 = 2_000;
    const SUBSIDY: u64 = 50_0000_0000;

    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let maturity = params.coinbase_maturity();
    let (mut tip, mut tip_time, cbs) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        maturity + 1,
        3,
    );
    assert_eq!(q.tip_height(), Some(Height(maturity + 1)));
    assert_eq!(q.sh_visible_through_height(), Some(maturity + 1));
    assert!(q.enqueues_sh_writebehind());

    let q = Arc::new(q);
    let hub = MempoolHub::open(dir.join("mempool"), Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let spend_a = spend_coinbase(cbs[0], FEE_A);
    let spend_b = spend_coinbase(cbs[1], FEE_B);
    let id_a = spend_a.compute_txid().to_byte_array();
    let id_b = spend_b.compute_txid().to_byte_array();
    hub.accept_tx(&spend_a).expect("accept blink spend");
    hub.accept_tx(&spend_b).expect("accept covered spend");

    let sh = rbitcoin_store::script_hash(&[0x51]);
    let hex_a = rbitcoin_primitives::display_hash_hex(id_a);
    let hex_b = rbitcoin_primitives::display_hash_hex(id_b);
    let hist_n = |txid: [u8; 32]| {
        q.scripthash_history(&sh)
            .unwrap()
            .iter()
            .filter(|row| row.txid == txid)
            .count()
    };
    let wallet_for = |hub: &MempoolHub,
                      script: &[u8]|
     -> (i64, i64, Vec<String>, rbitcoin_electrum::MempoolShStats) {
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let hex = electrum_scripthash_hex(script);
        let script_sh = rbitcoin_store::script_hash(script);
        let bal = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([hex]),
            &q,
            &cfg,
            &params,
            Some(hub),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let rows = dispatch(
            "blockchain.scripthash.get_mempool",
            &json!([hex]),
            &q,
            &cfg,
            &params,
            Some(hub),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let ids = rows
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["tx_hash"].as_str().map(str::to_owned))
            .collect();
        let stats =
            rbitcoin_electrum::scripthash_mempool_stats_slot(&q, hub, &script_sh, &mut None)
                .unwrap();
        (
            bal["confirmed"].as_i64().unwrap(),
            bal["unconfirmed"].as_i64().unwrap(),
            ids,
            stats,
        )
    };
    let wallet = |hub: &MempoolHub| wallet_for(hub, &[0x51]);
    let connect_spend =
        |tip: bitcoin::BlockHash, tip_time: u32, height: u32, tx: Transaction, enqueue: bool| {
            if !enqueue {
                q.set_sh_index_enabled(false);
            }
            let block = rbitcoin_consensus::mine_regtest_paying(
                tip,
                tip_time + 600,
                height,
                ScriptBuf::from_bytes(vec![0x51]),
                vec![tx],
            );
            accept_and_connect_block(&q, &params, Height(height), &block, Milestone::NONE).unwrap();
            q.set_sh_index_enabled(true);
            block
        };

    assert_eq!(
        hub.scripthash_unconfirmed_delta(&sh).unwrap(),
        -((FEE_A + FEE_B) as i64),
        "both spends are still only in the mempool"
    );

    let height_b = maturity + 2;
    let block_b = connect_spend(tip, tip_time, height_b, spend_b, true);
    tip = block_b.block_hash();
    tip_time = block_b.header.time;
    assert_eq!(q.sh_visible_through_height(), Some(height_b));
    assert_eq!(hist_n(id_b), 1, "covered spend is confirmed history once");
    assert_eq!(hist_n(id_a), 0);
    assert!(
        hub.scripthash_mempool(&sh)
            .iter()
            .any(|row| row.txid == id_b),
        "covered spend stays in the pool when connect does not strip"
    );
    let (confirmed_b, unconfirmed, mempool_ids, stats) = wallet(&hub);
    assert_eq!(unconfirmed, -(FEE_A as i64), "{mempool_ids:?} {stats:?}");
    assert!(mempool_ids.iter().any(|id| id == &hex_a), "{mempool_ids:?}");
    assert!(
        !mempool_ids.iter().any(|id| id == &hex_b),
        "{mempool_ids:?}"
    );
    assert_eq!(stats.tx_count, 1);
    assert_eq!(stats.funded_txo_sum, (SUBSIDY - FEE_A) as i64);

    let height_a = maturity + 3;
    let block_a = connect_spend(tip, tip_time, height_a, spend_a, false);
    assert_eq!(q.tip_height(), Some(Height(height_a)));
    assert!(q.tx_fk_by_txid_tip(&id_a).unwrap().is_some());
    assert!(
        q.sh_visible_through_height().unwrap() < height_a,
        "address view has not reached the blink block"
    );
    assert!(
        hub.scripthash_mempool(&sh)
            .iter()
            .any(|row| row.txid == id_a),
        "blink spend stays in the pool"
    );
    assert_eq!(
        hist_n(id_a),
        0,
        "confirmed history cannot see the blink yet"
    );
    let unused = rbitcoin_store::script_hash(&[0x00]);
    hub.sample_reset_perf();
    assert_eq!(hub.scripthash_unconfirmed_delta(&unused).unwrap(), 0);
    assert_eq!(
        hub.sample_reset_perf().delta_prevouts,
        0,
        "an address with nothing pooled does no prevout lookups"
    );

    let (confirmed, unconfirmed, mempool_ids, stats) = wallet(&hub);
    assert_eq!(
        confirmed, confirmed_b,
        "confirmed balance must not include the blink spend yet"
    );
    assert_eq!(
        unconfirmed,
        -(FEE_A as i64),
        "unconfirmed balance must keep the spend until the address view covers its height"
    );
    assert!(
        mempool_ids.iter().any(|id| id == &hex_a),
        "get_mempool must keep the spend until the address view covers it: {mempool_ids:?}"
    );
    assert!(
        !mempool_ids.iter().any(|id| id == &hex_b),
        "a spend the address view already covers stays out of get_mempool"
    );
    assert_eq!(stats.tx_count, 1, "{stats:?}");
    assert_eq!(stats.funded_txo_sum, (SUBSIDY - FEE_A) as i64, "{stats:?}");

    let hash = block_a.block_hash().to_byte_array();
    let (header_fk, _) = q.get_header_by_hash(&hash).unwrap().unwrap();
    q.enqueue_sh_pending(
        &[rbitcoin_query::ConfirmPrepared {
            height: Height(height_a),
            header_fk,
            tx_fks: q.block_tx_fks(Height(height_a)).unwrap(),
            hash,
        }],
        None,
    )
    .unwrap();
    assert_eq!(q.sh_visible_through_height(), Some(height_a));
    let (confirmed, unconfirmed, mempool_ids, stats) = wallet(&hub);
    assert_eq!(unconfirmed, 0, "{mempool_ids:?}");
    assert!(
        !mempool_ids.iter().any(|id| id == &hex_a),
        "{mempool_ids:?}"
    );
    assert!(
        !mempool_ids.iter().any(|id| id == &hex_b),
        "{mempool_ids:?}"
    );
    assert_eq!(stats.tx_count, 0, "{stats:?}");
    assert_eq!(stats.funded_txo_sum, 0, "{stats:?}");
    assert_eq!(hist_n(id_a), 1, "confirmed history includes the spend once");
    assert_eq!(hist_n(id_b), 1);
    // The block also pays a new coinbase to this script. The spend's own net is the fee.
    assert_eq!(confirmed, confirmed_b + SUBSIDY as i64 - FEE_A as i64);

    // Payment to a script other than the spent coin. The self-spend fee net
    // above stays; this pins the receive side of an awaiting tx.
    const FEE_PAY: u64 = 3_000;
    let pay_script = [0x52u8];
    let pay_value = SUBSIDY - FEE_PAY;
    let pay = tx_spending(cbs[2], pay_value, &pay_script);
    let id_pay = pay.compute_txid().to_byte_array();
    let hex_pay = rbitcoin_primitives::display_hash_hex(id_pay);
    hub.accept_tx(&pay).expect("accept foreign-script payment");
    let height_pay = height_a + 1;
    let block_pay = connect_spend(
        block_a.block_hash(),
        block_a.header.time,
        height_pay,
        pay,
        false,
    );
    assert!(q.sh_visible_through_height().unwrap() < height_pay);
    let (confirmed_pay, unconfirmed_pay, ids_pay, stats_pay) = wallet_for(&hub, &pay_script);
    assert_eq!(
        confirmed_pay, 0,
        "the receive is not in the address view yet"
    );
    assert_eq!(
        unconfirmed_pay, pay_value as i64,
        "unconfirmed balance keeps the foreign-script output: {ids_pay:?} {stats_pay:?}"
    );
    assert_eq!(stats_pay.tx_count, 1, "{stats_pay:?}");
    assert_eq!(stats_pay.funded_txo_sum, pay_value as i64, "{stats_pay:?}");
    assert!(
        ids_pay.iter().any(|id| id == &hex_pay),
        "get_mempool keeps the foreign-script payment: {ids_pay:?}"
    );
    let (_, unconfirmed_spent, _, _) = wallet(&hub);
    assert_eq!(
        unconfirmed_spent, -(SUBSIDY as i64),
        "the spent coin leaves the unconfirmed answer and the self-spend fee net is already settled"
    );

    // Parent block is covered and the parent tx is still in the pool. The
    // child is on the tip ahead of the view, so the delta must net to the
    // child's fee instead of adding the child's output on top of the parent.
    const FEE_CHILD: u64 = 4_000;
    let child_value = SUBSIDY - FEE_B - FEE_CHILD;
    let child = tx_spending(bitcoin::Txid::from_byte_array(id_b), child_value, &[0x51]);
    let id_child = child.compute_txid().to_byte_array();
    let hex_child = rbitcoin_primitives::display_hash_hex(id_child);
    hub.accept_tx(&child)
        .expect("accept spend of a covered parent that is still in the pool");
    let height_child = height_pay + 1;
    let _block_child = connect_spend(
        block_pay.block_hash(),
        block_pay.header.time,
        height_child,
        child,
        false,
    );
    assert!(q.tx_fk_by_txid_tip(&id_child).unwrap().is_some());
    assert!(q.sh_visible_through_height().unwrap() < height_child);
    assert!(
        hub.scripthash_mempool(&sh)
            .iter()
            .any(|row| row.txid == id_b),
        "covered parent stays in the pool"
    );
    let (confirmed_child, unconfirmed_child, ids_child, stats_child) = wallet(&hub);
    assert_eq!(
        confirmed_child, confirmed,
        "the child block is not in the address view yet"
    );
    assert!(
        ids_child.iter().any(|id| id == &hex_child),
        "get_mempool keeps the child until the view covers it: {ids_child:?}"
    );
    assert!(
        !ids_child.iter().any(|id| id == &hex_b),
        "the covered parent stays out of get_mempool: {ids_child:?}"
    );
    assert_eq!(
        unconfirmed_child,
        -(SUBSIDY as i64) - FEE_CHILD as i64,
        "a covered parent still in the pool must not be counted twice: {ids_child:?} {stats_child:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A pooled `OP_RETURN` output is never a coin. listunspent, the
/// unconfirmed balance, and the mempool funded stats leave it out. The tx
/// still counts once in that script's mempool stats.
#[test]
fn pooled_unspendable_output_is_not_unspent() {
    const BURN: u64 = 10_000;
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let maturity = params.coinbase_maturity();
    let (_tip, _tip_time, cbs) = rbitcoin_query::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        maturity + 1,
        1,
    );
    let q = Arc::new(q);
    let hub = MempoolHub::open(dir.join("mempool"), Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let burn_script = vec![0x6a, 0x01, 0x02];
    let mut tx = spend_coinbase(cbs[0], 1_000 + BURN);
    tx.output.push(TxOut {
        value: Amount::from_sat(BURN),
        script_pubkey: ScriptBuf::from_bytes(burn_script.clone()),
    });
    hub.accept_tx(&tx).expect("accept burn");

    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let mut header_sub = false;
    let mut sh_subs = HashSet::new();
    let hex = electrum_scripthash_hex(&burn_script);
    let mut call = |method: &str| {
        dispatch(
            method,
            &json!([hex]),
            &q,
            &cfg,
            &params,
            Some(&hub),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap()
    };
    assert_eq!(call("blockchain.scripthash.listunspent"), json!([]));
    assert_eq!(
        call("blockchain.scripthash.get_balance"),
        json!({"confirmed": 0, "unconfirmed": 0})
    );
    assert_eq!(
        call("blockchain.scripthash.get_mempool")
            .as_array()
            .unwrap()
            .len(),
        1,
        "the burn tx stays in that script's mempool history"
    );
    let sh = rbitcoin_store::script_hash(&burn_script);
    let stats = rbitcoin_electrum::scripthash_mempool_stats_slot(&q, &hub, &sh, &mut None).unwrap();
    assert_eq!(stats.tx_count, 1);
    assert_eq!((stats.funded_txo_count, stats.funded_txo_sum), (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}
