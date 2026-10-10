use bitcoin::absolute::LockTime;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use rbitcoin_consensus::{accept_and_connect_block, Milestone};
use rbitcoin_query::TxApply;
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

fn op_true_apply(tag: u8) -> TxApply {
    let mut txid = [0u8; 32];
    txid[0] = tag;
    txid[31] = 0xcb;
    TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            create_fk: Fk::NULL,
            prev_index: u32::MAX,
            sequence: u32::MAX,
            script_sig: vec![tag],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    }
}

fn connect_op_true(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) -> [u8; 32] {
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&height.to_le_bytes());
    merkle[5] = 0xec;
    let hash = rbitcoin_store::block_header_hash(1, &parent, &merkle, height + 1, 0x207fffff, height);
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

fn class_a_op_true(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) -> [u8; 32] {
    let merkle = [0x11; 32];
    let hash = rbitcoin_store::block_header_hash(1, &parent, &merkle, height + 1, 0x207fffff, height);
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

fn view_hash(q: &Query) -> ([u8; 32], Height) {
    let params = ChainParams::regtest();
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let sh = electrum_scripthash_hex(&[0x51]);
    let (out, view) = electrum_at_chain_view(
        q,
        "blockchain.scripthash.get_balance",
        &json!([sh]),
        false,
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

fn stamp_follows_pending(q: &Query, height: u32, prev: Fk, parent: [u8; 32]) {
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

fn casa_reuses_then_cap(q: &Query) {
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
    assert!(err.contains("scripthash join exceeds --max-sh-creates"), "{err}");
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

fn spend_coinbase(cbtxid: bitcoin::Txid, fee: u64) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cbtxid, vout: 0 },
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

fn listunspent_skips_unused(q: &Arc<Query>, hub: &MempoolHub, spent_cb: &bitcoin::Txid) {
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

async fn read_push(stream: &mut TcpStream) -> Value {
    let mut reader = BufReader::new(&mut *stream);
    let mut resp = String::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), reader.read_line(&mut resp))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&resp).unwrap()
}

async fn tip_push_two_clients_and_late(q: Arc<Query>, hub: Option<Arc<MempoolHub>>) {
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx.clone(), hub).await.unwrap();
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
        assert_eq!(push["method"].as_str(), Some("blockchain.headers.subscribe"));
    }
    let mut late = TcpStream::connect(handle.local_addr).await.unwrap();
    let caught = electrum_tcp_rpc(&mut late, 1, "blockchain.headers.subscribe", json!([])).await;
    assert!(
        caught.get("result").is_some(),
        "a client that missed the push catches up on the next request: {caught}"
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn electrum_sh_join() {
    let (dir, q) = tmp_store();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    const N_SPENDS: u32 = 4;
    let (tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
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
    casa_reuses_then_cap(&q);

    let q = Arc::new(q);
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
