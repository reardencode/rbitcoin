//! Electrum protocol fixtures against a local server + mature regtest chain.

use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_electrum::{electrum_scripthash_hex, run_electrum, ElectrumConfig, TipNotify};
use rbitcoin_query::Query;
use rbitcoin_test::build_mature_regtest_with_spend;
use rbitcoin_test::TempDir;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

/// Bound every Electrum line read — unbounded `read_line` hangs the suite if the
/// server never answers (deadlock / dropped task).
async fn read_line_timeout(reader: &mut BufReader<&mut TcpStream>, buf: &mut String, label: &str) {
    buf.clear();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(buf))
        .await
        .unwrap_or_else(|_| panic!("electrum {label}: read_line timed out"))
        .unwrap_or_else(|e| panic!("electrum {label}: read_line io: {e}"));
}

async fn rpc(stream: &mut TcpStream, id: u64, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id": id, "method": method, "params": params});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut *stream);
    let mut resp_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp_line))
        .await
        .unwrap_or_else(|_| panic!("electrum rpc {method}: read_line timed out"))
        .unwrap_or_else(|e| panic!("electrum rpc {method}: io {e}"));
    serde_json::from_str(&resp_line).unwrap()
}

async fn read_notify(stream: &mut TcpStream, label: &str) -> Value {
    let mut reader = BufReader::new(&mut *stream);
    let mut resp_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp_line))
        .await
        .unwrap_or_else(|_| panic!("electrum {label}: read_line timed out"))
        .unwrap_or_else(|e| panic!("electrum {label}: io {e}"));
    serde_json::from_str(&resp_line).unwrap()
}

#[allow(clippy::cognitive_complexity)] // one TCP session, many protocol arms
#[tokio::test]
async fn electrum_server_version_history_balance() {
    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let chain = build_mature_regtest_with_spend(&q, &params);
    let _ = Milestone::NONE;

    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q.clone(), params.clone(), tip_tx.clone(), None)
        .await
        .expect("electrum listen");

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    // Need re-read pattern: after write we use BufReader which consumes stream.
    // Use split request/response carefully with single stream.
    {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"server.version","params":["test","1.4"]});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
    }
    let mut reader = BufReader::new(&mut stream);
    let mut resp_line = String::new();
    read_line_timeout(&mut reader, &mut resp_line, "server.version").await;
    let v: Value = serde_json::from_str(&resp_line).unwrap();
    assert!(v.get("result").is_some(), "{v}");
    let ver = v["result"].as_array().unwrap();
    assert_eq!(ver.len(), 2);
    assert_eq!(ver[1].as_str(), Some("1.4"));
    let server = ver[0].as_str().expect("server.version[0]");
    assert!(
        server.to_ascii_lowercase().contains("electrs"),
        "Cake skips tweaks unless version[0] contains electrs, got {server:?}"
    );
    assert!(
        server.to_ascii_lowercase().contains("rbitcoin"),
        "version[0] must still identify rbitcoin, got {server:?}"
    );

    // OP_TRUE scripthash
    let sh_hex = electrum_scripthash_hex(&[0x51]);
    let req = json!({
        "jsonrpc":"2.0","id":2,
        "method":"blockchain.scripthash.get_history",
        "params":[sh_hex]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    // reader holds &mut stream — drop reader first by re-getting stream from reader
    let stream = reader.into_inner();
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    read_line_timeout(&mut reader, &mut resp_line, "get_history").await;
    let v: Value = serde_json::from_str(&resp_line).unwrap();
    let hist = v["result"].as_array().expect("history array");
    assert!(!hist.is_empty());
    for row in hist {
        assert!(
            row.get("fee").is_none(),
            "confirmed history omits fee: {row}"
        );
    }

    let sh_hex = electrum_scripthash_hex(&[0x51]);
    let req = json!({
        "jsonrpc":"2.0","id":3,
        "method":"blockchain.scripthash.get_balance",
        "params":[sh_hex]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    let stream = reader.into_inner();
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    read_line_timeout(&mut reader, &mut resp_line, "get_balance").await;
    let v: Value = serde_json::from_str(&resp_line).unwrap();
    assert!(v["result"]["confirmed"].as_i64().unwrap_or(0) > 0);

    // Empty mempool
    let req = json!({
        "jsonrpc":"2.0","id":4,
        "method":"blockchain.scripthash.get_mempool",
        "params":[electrum_scripthash_hex(&[0x51])]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    let stream = reader.into_inner();
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    read_line_timeout(&mut reader, &mut resp_line, "get_mempool").await;
    let v: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(v["result"], json!([]));

    // Headers subscribe returns tip
    let req = json!({
        "jsonrpc":"2.0","id":5,
        "method":"blockchain.headers.subscribe",
        "params":[]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    let stream = reader.into_inner();
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(stream);
    read_line_timeout(&mut reader, &mut resp_line, "headers.subscribe").await;
    let v: Value = serde_json::from_str(&resp_line).unwrap();
    assert!(v["result"]["height"].as_u64().unwrap() > 0);
    assert!(v["result"]["hex"].as_str().unwrap().len() == 160); // 80-byte header hex

    // Tip push: server must forward TipNotify to subscribed clients.
    let tip_h = v["result"]["height"].as_u64().unwrap() as u32;
    let tip_hex = v["result"]["hex"].as_str().unwrap().to_string();
    tip_tx
        .send(rbitcoin_electrum::TipNotify {
            height: tip_h + 1,
            header_hex: tip_hex.clone(),
            reorg_from_height: None,
        })
        .expect("tip push");
    // Notification has no id — wait for one line.
    read_line_timeout(&mut reader, &mut resp_line, "tip notification").await;
    let push: Value = serde_json::from_str(&resp_line).unwrap();
    assert_eq!(
        push["method"].as_str(),
        Some("blockchain.headers.subscribe")
    );
    assert_eq!(
        push["params"][0]["height"].as_u64(),
        Some((tip_h + 1) as u64)
    );

    drop(reader);

    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    // Empty line is ignored (no response) — send ping after.
    stream.write_all(b"\n").await.unwrap();
    // Bad JSON is ignored.
    stream.write_all(b"{not json\n").await.unwrap();

    let v = rpc(&mut stream, 1, "server.ping", json!([])).await;
    assert!(v.get("result").is_some(), "{v}");
    assert!(v["result"].is_null());

    let v = rpc(&mut stream, 2, "server.banner", json!([])).await;
    assert!(v["result"].as_str().is_some());

    let v = rpc(&mut stream, 3, "server.donation_address", json!([])).await;
    assert!(v.get("result").is_some());

    let v = rpc(&mut stream, 4, "server.features", json!([])).await;
    assert!(v["result"]["genesis_hash"].as_str().is_some());
    assert_eq!(v["result"]["protocol_max"].as_str(), Some("1.4.2"));
    assert_eq!(v["result"]["silent_payments"], json!([0]));
    assert_eq!(v["result"]["tweaks"], json!(true));
    assert_eq!(v["result"]["asof"], json!(true));

    let v = rpc(&mut stream, 5, "server.peers.subscribe", json!([])).await;
    assert_eq!(v["result"], json!([]));

    let v = rpc(&mut stream, 6, "blockchain.block.header", json!([1])).await;
    assert_eq!(v["result"].as_str().unwrap().len(), 160);

    let v = rpc(&mut stream, 7, "blockchain.block.headers", json!([0, 5])).await;
    assert!(v["result"]["count"].as_u64().unwrap() >= 1);
    assert!(!v["result"]["hex"].as_str().unwrap().is_empty());

    let sh_hex = electrum_scripthash_hex(&[0x51]);
    let v = rpc(
        &mut stream,
        8,
        "blockchain.scripthash.listunspent",
        json!([sh_hex]),
    )
    .await;
    assert!(v["result"].as_array().is_some());

    let v = rpc(
        &mut stream,
        9,
        "blockchain.scripthash.subscribe",
        json!([sh_hex]),
    )
    .await;
    // status is hex string or null for empty
    assert!(v.get("result").is_some());

    let next_h = chain.tip_height() + 1;
    let last = chain.blocks.last().unwrap();
    let next = rbitcoin_test::mine::mine_regtest_block(
        last.block_hash(),
        last.header.time + 600,
        next_h,
        vec![],
    );
    rbitcoin_consensus::accept_and_connect_block(
        q.as_ref(),
        &params,
        rbitcoin_primitives::Height(next_h),
        &next,
        Milestone::NONE,
    )
    .unwrap();
    q.apply_sh_pending().unwrap();
    tip_tx
        .send(TipNotify {
            height: next_h,
            header_hex: bitcoin::consensus::encode::serialize_hex(&next.header),
            reorg_from_height: None,
        })
        .expect("scripthash tip push");
    let push = read_notify(&mut stream, "scripthash notification").await;
    assert_eq!(
        push["method"].as_str(),
        Some("blockchain.scripthash.subscribe")
    );

    // Coinbase of height 1 via id_from_pos.
    let v = rpc(
        &mut stream,
        10,
        "blockchain.transaction.id_from_pos",
        json!([1, 0]),
    )
    .await;
    let txid_hex = v["result"].as_str().expect("txid").to_string();
    assert_eq!(txid_hex.len(), 64);

    let v = rpc(
        &mut stream,
        11,
        "blockchain.transaction.get",
        json!([txid_hex]),
    )
    .await;
    assert!(v["result"].as_str().unwrap().len() > 20);

    let v = rpc(
        &mut stream,
        12,
        "blockchain.transaction.get",
        json!([txid_hex, true]),
    )
    .await;
    assert!(v["result"]["hex"].as_str().is_some());

    let v = rpc(
        &mut stream,
        13,
        "blockchain.transaction.get_merkle",
        json!([txid_hex, 1]),
    )
    .await;
    assert_eq!(v["result"]["block_height"].as_u64(), Some(1));
    assert!(v["result"]["merkle"].as_array().is_some());

    let v = rpc(&mut stream, 14, "blockchain.estimatefee", json!([2])).await;
    assert!(v["result"].as_f64().is_some() || v["result"].as_i64().is_some());

    let v = rpc(&mut stream, 15, "blockchain.relayfee", json!([])).await;
    assert!(v["result"].as_f64().is_some());

    let v = rpc(&mut stream, 16, "mempool.get_fee_histogram", json!([])).await;
    assert!(v["result"].as_array().is_some());

    // Missing tx.
    let v = rpc(
        &mut stream,
        17,
        "blockchain.transaction.get",
        json!(["00".repeat(32)]),
    )
    .await;
    assert!(v.get("error").is_some(), "{v}");

    // Unknown method.
    let v = rpc(&mut stream, 18, "no.such.method", json!([])).await;
    assert!(v.get("error").is_some());

    // Broadcast without mempool → error.
    let v = rpc(
        &mut stream,
        19,
        "blockchain.transaction.broadcast",
        json!(["00"]),
    )
    .await;
    assert!(v.get("error").is_some());

    // Bad params.
    let v = rpc(&mut stream, 20, "blockchain.block.header", json!(["x"])).await;
    assert!(v.get("error").is_some());

    handle.shutdown().await;
}

#[tokio::test]
async fn electrum_scripthash_sub_cap_unsubscribe_frees_slot() {
    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.max_scripthash_subs = 2;
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let h1 = "11".repeat(32);
    let h2 = "22".repeat(32);
    let h3 = "33".repeat(32);
    let v = rpc(
        &mut stream,
        1,
        "blockchain.scripthash.subscribe",
        json!([h1.clone()]),
    )
    .await;
    assert!(v.get("result").is_some(), "{v}");
    let v = rpc(
        &mut stream,
        2,
        "blockchain.scripthash.subscribe",
        json!([h2]),
    )
    .await;
    assert!(v.get("result").is_some(), "{v}");
    let v = rpc(
        &mut stream,
        3,
        "blockchain.scripthash.subscribe",
        json!([h3.clone()]),
    )
    .await;
    let msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("too many"), "{v}");
    let v = rpc(
        &mut stream,
        4,
        "blockchain.scripthash.unsubscribe",
        json!([h3.clone()]),
    )
    .await;
    assert_eq!(v["result"], json!(false), "never subscribed");
    let v = rpc(
        &mut stream,
        5,
        "blockchain.scripthash.unsubscribe",
        json!([h1]),
    )
    .await;
    assert_eq!(v["result"], json!(true));
    let v = rpc(
        &mut stream,
        6,
        "blockchain.scripthash.subscribe",
        json!([h3]),
    )
    .await;
    assert!(
        v.get("error").is_none(),
        "unsubscribe must free a cap slot: {v}"
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn electrum_leftover_mempool_does_not_double_count() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::Height;

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (tip, tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        101,
        1,
    );
    let q_arc = Arc::new(q);
    let mp = MempoolHub::open(dir.path().join("mempool"), Arc::clone(&q_arc)).unwrap();
    mp.set_relay_enabled(true);
    let spk = ScriptBuf::from_bytes(vec![0x52]);
    let value = 50_0000_0000 - 1_000;
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txids[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk.clone(),
        }],
    };
    mp.accept_tx(&parent).expect("accept");
    mp.set_relay_enabled(false);

    let blk = rbitcoin_consensus::mine_regtest_paying(
        tip,
        tip_time + 600,
        102,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![parent.clone()],
    );
    accept_and_connect_block(q_arc.as_ref(), &params, Height(102), &blk, Milestone::NONE).unwrap();
    q_arc.apply_sh_pending().unwrap();
    assert!(
        mp.contains(&parent.compute_txid()),
        "relay off must leave the confirmed tx in the hub"
    );

    let sh = electrum_scripthash_hex(spk.as_bytes());
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, Arc::clone(&q_arc), params, tip_tx, Some(mp))
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let want = rbitcoin_primitives::display_hash_hex(&parent.compute_txid().to_byte_array());
    let bal = rpc(
        &mut stream,
        1,
        "blockchain.scripthash.get_balance",
        json!([sh.clone()]),
    )
    .await;
    assert_eq!(bal["result"]["confirmed"], value, "{bal}");
    assert_eq!(
        bal["result"]["unconfirmed"], 0,
        "confirmed leftover must not add unconfirmed delta: {bal}"
    );
    let unspent = rpc(
        &mut stream,
        2,
        "blockchain.scripthash.listunspent",
        json!([sh.clone()]),
    )
    .await;
    let rows = unspent["result"].as_array().unwrap();
    let hits: Vec<_> = rows.iter().filter(|u| u["tx_hash"] == want).collect();
    assert_eq!(hits.len(), 1, "duplicate confirmed+mempool UTXO: {unspent}");
    assert!(hits[0]["height"].as_i64().unwrap() > 0, "{hits:?}");
    let mem = rpc(
        &mut stream,
        3,
        "blockchain.scripthash.get_mempool",
        json!([sh]),
    )
    .await;
    let mem_hits: Vec<_> = mem["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|u| u["tx_hash"] == want)
        .collect();
    assert!(
        mem_hits.is_empty(),
        "get_mempool must skip leftover already connected on the tip: {mem}"
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn electrum_max_connections_rejects_extra_client() {
    use tokio::io::AsyncReadExt;
    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.max_connections = 1;
    cfg.limits.idle_timeout = Duration::from_secs(30);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");
    let held = TcpStream::connect(handle.local_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut second = TcpStream::connect(handle.local_addr).await.unwrap();
    let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    let _ = second.write_all(line.as_bytes()).await;
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_millis(400), second.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) => {
            let s = std::str::from_utf8(&buf[..n]).unwrap_or("");
            assert!(
                !s.contains("\"result\""),
                "second client must not get RPC result at cap: {s}"
            );
        }
    }
    drop(held);
    handle.shutdown().await;
}

#[tokio::test]
async fn electrum_idle_timeout_disconnects_quiet_client() {
    use tokio::io::AsyncReadExt;
    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.idle_timeout = Duration::from_millis(80);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {}
        Ok(Ok(n)) => panic!("idle client must be closed, got {n} bytes"),
    }
    handle.shutdown().await;
}

/// Direct IBD leaves live `tx.head` + spend annotations; tip only bulk-loads SH.
/// `backfill_tx_index` stays available (idempotent rebuild / future rehash) but is
/// not required for tip entry.
#[test]
fn direct_indexes_then_sh_bulk_at_tip() {
    use bitcoin::hashes::Hash;
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis};

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();

    // Direct IBD: live heads + spend annotations on confirm.
    q.enter_direct_index_mode().unwrap();

    let g = regtest_genesis();
    accept_and_connect_block(&q, &params, Height::GENESIS, &g, Milestone::NONE).unwrap();
    let mut tip = g.block_hash();
    let mut time = g.header.time;
    for h in 1..=5u32 {
        time += 600;
        let b = mine_regtest_block(tip, time, h, vec![]);
        accept_and_connect_block(&q, &params, Height(h), &b, Milestone::NONE).unwrap();
        tip = b.block_hash();
    }
    assert_eq!(q.tip_height(), Some(Height(5)));
    assert!(q.tx_body_count() >= 6);
    // Direct writes tx.head on archive/connect path.
    assert!(q.tx_head_occupied() >= 6, "head filled under Direct");
    let b1 = q.reconstruct_block_at_height(Height(1)).unwrap();
    let cb_txid = b1.txdata[0].compute_txid().to_byte_array();
    assert!(
        q.get_tx_by_txid(&cb_txid).unwrap().is_some(),
        "txid resolves via live tx.head under Direct"
    );

    // Manual rebuild is idempotent when head is already dense (rehash tool).
    let inserted = q.backfill_tx_index(|_, _, _| {}).unwrap();
    assert_eq!(inserted, 0, "no missing head entries after Direct");

    // Direct IBD keeps SH in runs until tip bulk materialize.
    let n_sh = q.finalize_sh_runs().unwrap();
    assert!(n_sh > 0, "SH bulk materialize creates≈{n_sh}");
    q.enter_tip_index_mode();

    // OP_TRUE coinbase outputs from mine_regtest_block appear under that scripthash.
    let sh = {
        use rbitcoin_store::script_hash;
        script_hash(&[0x51])
    };
    let hist = q.scripthash_history(&sh).unwrap();
    assert!(
        !hist.is_empty(),
        "scripthash history non-empty after SH bulk"
    );
}
