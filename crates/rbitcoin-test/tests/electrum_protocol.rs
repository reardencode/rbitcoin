//! Electrum protocol fixtures against a local server + mature regtest chain.

use bitcoin::hashes::Hash;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_electrum::{electrum_scripthash_hex, run_electrum, ElectrumConfig, TipNotify};
use rbitcoin_query::Query;
use rbitcoin_test::build_mature_regtest_with_spend;
use rbitcoin_test::TempDir;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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

const SP_SCAN: &str = "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
const SP_SPEND: &str = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";

async fn pin_wallet_protocol_1_6(stream: &mut TcpStream) {
    let ver = rpc(stream, 40, "server.version", json!(["test", "1.6"])).await;
    assert_eq!(ver["result"][1].as_str(), Some("1.6"), "{ver}");
    let info = rpc(stream, 41, "mempool.get_info", json!([])).await;
    assert!(
        info["result"]["minrelaytxfee"].as_f64().unwrap() > 0.0,
        "{info}"
    );
    assert_eq!(info["result"]["unbroadcastcount"], 0);
    pin_outpoint_1_6(stream).await;
    pin_silentpayments_1_6(stream).await;
    let hdrs = rpc(stream, 48, "blockchain.block.headers", json!([0, 1])).await;
    assert!(
        hdrs["result"]["headers"].as_array().is_some(),
        "1.6 headers is a list: {hdrs}"
    );
}

async fn pin_outpoint_1_6(stream: &mut TcpStream) {
    let zero = format!("{:064}", 0);
    let st = rpc(
        stream,
        42,
        "blockchain.outpoint.get_status",
        json!([zero.clone(), 0]),
    )
    .await;
    assert_eq!(st["result"]["spent"], false, "{st}");
    let sub = rpc(
        stream,
        43,
        "blockchain.outpoint.subscribe",
        json!([zero.clone(), 0]),
    )
    .await;
    assert_eq!(sub["result"]["spent"], false, "{sub}");
    let un = rpc(
        stream,
        44,
        "blockchain.outpoint.unsubscribe",
        json!([zero.clone(), 0]),
    )
    .await;
    assert_eq!(un["result"], json!(true), "{un}");
    let un2 = rpc(
        stream,
        49,
        "blockchain.outpoint.unsubscribe",
        json!([zero, 0]),
    )
    .await;
    assert_eq!(un2["result"], json!(false), "second unsubscribe: {un2}");
    let sub_again = rpc(
        stream,
        51,
        "blockchain.outpoint.subscribe",
        json!([format!("{:064}", 0), 0]),
    )
    .await;
    assert_eq!(sub_again["result"]["spent"], false, "{sub_again}");
    let bad_op = rpc(
        stream,
        56,
        "blockchain.outpoint.get_status",
        json!([format!("{:064}", 0)]),
    )
    .await;
    assert!(
        bad_op.get("error").is_some(),
        "outpoint missing vout: {bad_op}"
    );
}

async fn pin_silentpayments_1_6(stream: &mut TcpStream) {
    let sp = rpc(
        stream,
        45,
        "blockchain.silentpayments.subscribe",
        json!([SP_SCAN, SP_SPEND, 0]),
    )
    .await;
    assert_eq!(sp["result"]["start_height"], 0, "{sp}");
    assert!(
        sp["result"]["address"].as_str().unwrap().contains("sp"),
        "{sp}"
    );
    let note = read_notify(stream, "silentpayments history").await;
    assert_eq!(
        note["method"].as_str(),
        Some("blockchain.silentpayments.subscribe"),
        "{note}"
    );
    assert!(note["params"]["history"].as_array().is_some(), "{note}");
    const OTHER_SCAN: &str = "1f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
    let mismatch = rpc(
        stream,
        56,
        "blockchain.silentpayments.unsubscribe",
        json!([OTHER_SCAN, SP_SPEND, 0]),
    )
    .await;
    assert!(
        mismatch["result"].as_str().unwrap().contains("sp"),
        "a different scan key must not clear the session: {mismatch}"
    );
    let unsp = rpc(
        stream,
        46,
        "blockchain.silentpayments.unsubscribe",
        json!([SP_SCAN, SP_SPEND, 0]),
    )
    .await;
    assert!(unsp["result"].as_str().unwrap().contains("sp"), "{unsp}");
    let unsp2 = rpc(
        stream,
        53,
        "blockchain.silentpayments.unsubscribe",
        json!([SP_SCAN, SP_SPEND, 0]),
    )
    .await;
    assert!(
        unsp2["result"].as_str().unwrap().contains("sp"),
        "second unsubscribe still returns address: {unsp2}"
    );
    let headers = rpc(
        stream,
        54,
        "blockchain.block.headers",
        json!([0, 1_000_000]),
    )
    .await;
    let tip_h = headers["result"]["count"].as_u64().expect("header count") - 1;
    let clamped = rpc(
        stream,
        55,
        "blockchain.silentpayments.subscribe",
        json!([SP_SCAN, SP_SPEND, 500_000]),
    )
    .await;
    assert_eq!(
        clamped["result"]["start_height"].as_u64(),
        Some(tip_h),
        "start past tip clamps: {clamped}"
    );
    let _ = read_notify(stream, "silentpayments clamp history").await;
    let bad = rpc(
        stream,
        47,
        "blockchain.silentpayments.subscribe",
        json!(["00", "02"]),
    )
    .await;
    assert!(bad.get("error").is_some(), "{bad}");
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

fn http_header_value(text: &str, name: &str) -> Option<String> {
    let want = name.to_ascii_lowercase();
    text.split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(&want))
        .map(|(_, v)| v.trim().to_string())
}

async fn http_get_raw(addr: SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).await.expect("esplora connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    (status, text, body)
}

async fn assert_esplora_asof_hides_later_spend(
    addr: SocketAddr,
    sh: &str,
    asof_create: &str,
    asof_spend: &str,
    create_hex: &str,
) {
    let (st, raw, body) =
        http_get_raw(addr, &format!("/scripthash/{sh}/utxo?asof={asof_create}")).await;
    assert_eq!(st, 200, "asof create utxo body={body}");
    let utxos: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(utxos.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip").as_deref(),
        Some(asof_create)
    );
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip-height").as_deref(),
        Some("102")
    );

    let (st, raw, body) =
        http_get_raw(addr, &format!("/scripthash/{sh}/utxo?asof={asof_spend}")).await;
    assert_eq!(st, 200, "asof spend utxo body={body}");
    let utxos: Value = serde_json::from_str(&body).unwrap();
    assert!(utxos.as_array().unwrap().is_empty(), "{body}");
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip").as_deref(),
        Some(asof_spend)
    );

    let (st, _, body) =
        http_get_raw(addr, &format!("/tx/{create_hex}/status?asof={asof_create}")).await;
    assert_eq!(st, 200, "status asof create={body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["confirmed"], true);

    let (st, _, _) = http_get_raw(
        addr,
        &format!("/scripthash/{sh}/utxo?asof={}", "ee".repeat(32)),
    )
    .await;
    assert_eq!(st, 404);

    let (st, raw, _) = http_get_raw(addr, &format!("/tx/{create_hex}?asof={asof_create}")).await;
    assert_eq!(st, 404, "asof is not documented on GET /tx/:txid");
    assert!(
        http_header_value(&raw, "x-bitcoin-chain-tip").is_none(),
        "rejected asof must not stamp a lying tip"
    );

    let (st, _, _) = http_get_raw(addr, &format!("/mempool?asof={asof_create}")).await;
    assert_eq!(st, 404, "asof is not documented on /mempool");

    let (st, _, body) = http_get_raw(addr, &format!("/tx/{create_hex}")).await;
    assert_eq!(st, 200, "GET /tx create={body}");
    let full: Value = serde_json::from_str(&body).unwrap();
    let v1 = &full["vout"][1];
    assert_eq!(v1["scriptpubkey_type"], "v0_p2wpkh", "{full}");
    assert_eq!(v1["value"], 50_000);
    assert!(v1.get("scriptpubkey_address").is_some(), "{v1}");
}

fn header_hex(block: &bitcoin::Block) -> String {
    bitcoin::consensus::encode::serialize_hex(&block.header)
}

async fn assert_esplora_asof_dead(addr: SocketAddr, path: &str) {
    let (st, raw, body) = http_get_raw(addr, path).await;
    assert_eq!(st, 404, "dead asof body={body}");
    assert!(
        http_header_value(&raw, "x-bitcoin-chain-tip").is_none(),
        "dead asof must not stamp a fork tip"
    );
}

async fn mempool_status_matches_history_row_order(
    stream: &mut TcpStream,
    q: &Query,
    hub: &rbitcoin_net::MempoolHub,
    chain: &rbitcoin_test::MatureRegtestChain,
) {
    use bitcoin::hashes::{sha256, Hash as _};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_primitives::Height;

    let coinbase = &chain.blocks[2].txdata[0];
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: spk,
        }],
    };
    hub.accept_tx(&tx).expect("mempool accept");
    let sh = electrum_scripthash_hex(&[0x51]);
    let hist = rpc(
        stream,
        30,
        "blockchain.scripthash.get_history",
        json!([sh.clone()]),
    )
    .await;
    let rows = hist["result"].as_array().expect("history");
    assert!(
        rows.iter().any(|r| r["height"].as_i64().unwrap() >= 1),
        "need a confirmed history row"
    );
    assert!(
        rows.last().unwrap()["height"].as_i64().unwrap() <= 0,
        "get_history must append the mempool row last: {hist}"
    );
    let mut preimage = String::new();
    let mut height_sorted = String::new();
    let mut ordered: Vec<(i64, String)> = Vec::new();
    for row in rows {
        let height = row["height"].as_i64().unwrap();
        let tx_hash = row["tx_hash"].as_str().unwrap();
        let piece = if height > 0 {
            let (_, rec) = q.header_at_height(Height(height as u32)).unwrap().unwrap();
            let block = rbitcoin_primitives::display_hash_hex(&rec.hash);
            format!("{tx_hash}:{height}:{block}:")
        } else {
            format!("{tx_hash}:{height}:")
        };
        preimage.push_str(&piece);
        ordered.push((height, piece));
    }
    ordered.sort_by_key(|(h, _)| *h);
    for (_, piece) in &ordered {
        height_sorted.push_str(piece);
    }
    let status_of =
        |s: &str| rbitcoin_primitives::hex_encode(sha256::Hash::hash(s.as_bytes()).to_byte_array());
    let expected = status_of(&preimage);
    assert_ne!(
        status_of(&height_sorted),
        expected,
        "height-sort must not match get_history order"
    );
    let sub = rpc(stream, 31, "blockchain.scripthash.subscribe", json!([sh])).await;
    assert_eq!(sub["result"].as_str(), Some(expected.as_str()), "{sub}");
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
    let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    cfg.limits.max_request_bytes = 2048;
    cfg.onion_tcp
        .set((
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion".into(),
            50001,
        ))
        .unwrap();
    let hub = rbitcoin_net::MempoolHub::open(dir.path().join("mempool"), q.clone()).expect("hub");
    hub.set_relay_enabled(true);
    let handle = run_electrum(
        cfg,
        q.clone(),
        params.clone(),
        tip_tx.clone(),
        Some(hub.clone()),
    )
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
    assert!(
        server.contains(env!("CARGO_PKG_VERSION")),
        "version[0] must track workspace.package.version, got {server:?}"
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
    assert_eq!(v["result"]["protocol_max"].as_str(), Some("1.6"));
    assert_eq!(v["result"]["silent_payments"], json!([0]));
    assert_eq!(v["result"]["tweaks"], json!(true));
    assert_eq!(v["result"]["asof"], json!(true));
    assert_eq!(v["result"]["chain_tip"], json!(true));
    assert_eq!(v["result"]["protocol_min"].as_str(), Some("1.4"));
    assert_eq!(v["result"]["asof_protocol"].as_str(), Some("1.4.2-asof"));
    assert_eq!(v["result"]["server_version"], ver[0]);
    assert_eq!(
        v["result"]["hosts"],
        json!({
            "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion": { "tcp_port": 50001 }
        })
    );
    assert!(v["result"]["hosts"]
        .as_object()
        .unwrap()
        .values()
        .all(|h| h.get("ssl_port").is_none()));

    let v = rpc(&mut stream, 5, "server.peers.subscribe", json!([])).await;
    assert_eq!(v["result"], json!([]));

    let v = rpc(&mut stream, 6, "blockchain.block.header", json!([1])).await;
    assert_eq!(v["result"].as_str().unwrap().len(), 160);

    let v = rpc(&mut stream, 7, "blockchain.block.headers", json!([0, 5])).await;
    assert!(v["result"]["count"].as_u64().unwrap() >= 1);
    assert!(!v["result"]["hex"].as_str().unwrap().is_empty());

    mempool_status_matches_history_row_order(&mut stream, &q, &hub, &chain).await;

    pin_wallet_protocol_1_6(&mut stream).await;

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
    {
        let mut reader = BufReader::new(&mut stream);
        let mut op_line = String::new();
        read_line_timeout(&mut reader, &mut op_line, "outpoint notification").await;
        let op_push: Value = serde_json::from_str(&op_line).unwrap();
        assert_eq!(
            op_push["method"].as_str(),
            Some("blockchain.outpoint.subscribe"),
            "{op_push}"
        );
        let mut sh_line = String::new();
        read_line_timeout(&mut reader, &mut sh_line, "scripthash notification").await;
        let push: Value = serde_json::from_str(&sh_line).unwrap();
        assert_eq!(
            push["method"].as_str(),
            Some("blockchain.scripthash.subscribe"),
            "{push}"
        );
    }
    let un_op = rpc(
        &mut stream,
        52,
        "blockchain.outpoint.unsubscribe",
        json!([format!("{:064}", 0), 0]),
    )
    .await;
    assert_eq!(un_op["result"], json!(true), "{un_op}");

    let miss_h = next_h + 1;
    let miss = rbitcoin_consensus::mine_regtest_paying(
        next.block_hash(),
        next.header.time + 600,
        miss_h,
        bitcoin::script::ScriptBuf::from_bytes(vec![0x00]),
        vec![],
    );
    rbitcoin_consensus::accept_and_connect_block(
        q.as_ref(),
        &params,
        rbitcoin_primitives::Height(miss_h),
        &miss,
        Milestone::NONE,
    )
    .unwrap();
    q.apply_sh_pending().unwrap();
    tip_tx
        .send(TipNotify {
            height: miss_h,
            header_hex: bitcoin::consensus::encode::serialize_hex(&miss.header),
            reorg_from_height: None,
        })
        .expect("unrelated tip push");
    let extra = tokio::time::timeout(Duration::from_millis(400), async {
        read_notify(&mut stream, "untouched scripthash").await
    })
    .await;
    assert!(extra.is_err(), "untouched tip must not restatus: {extra:?}");

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
        50,
        "blockchain.transaction.id_from_pos",
        json!([1, 0, false]),
    )
    .await;
    assert_eq!(v["result"].as_str(), Some(txid_hex.as_str()));
    let v = rpc(
        &mut stream,
        51,
        "blockchain.transaction.id_from_pos",
        json!([1, 0, true]),
    )
    .await;
    assert_eq!(v["result"]["tx_hash"].as_str(), Some(txid_hex.as_str()));
    assert!(v["result"]["merkle"].as_array().is_some(), "{v}");
    let v = rpc(
        &mut stream,
        52,
        "blockchain.transaction.id_from_pos",
        json!([1, 99]),
    )
    .await;
    assert!(v.get("error").is_some(), "pos OOB: {v}");

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
    assert!(v["result"]["vin"][0].get("coinbase").is_some());
    assert_eq!(v["result"]["vout"][0]["n"], 0);
    assert!(v["result"]["size"].as_u64().unwrap() > 0);
    let time = v["result"]["time"].as_u64().expect("verbose time");
    assert_eq!(v["result"]["blocktime"].as_u64(), Some(time));
    assert!(v["result"]["confirmations"].as_u64().unwrap() >= 1);
    assert_eq!(v["result"]["blockhash"].as_str().unwrap().len(), 64, "{v}");

    let v = rpc(
        &mut stream,
        13,
        "blockchain.transaction.get_merkle",
        json!([txid_hex, 1]),
    )
    .await;
    assert_eq!(v["result"]["block_height"].as_u64(), Some(1));
    assert!(v["result"]["merkle"].as_array().is_some());
    let v = rpc(
        &mut stream,
        27,
        "blockchain.transaction.get_merkle",
        json!([txid_hex, 2]),
    )
    .await;
    let merkle_msg = v["error"]["message"].as_str().unwrap_or("");
    assert!(
        merkle_msg.contains("not found"),
        "wrong height for known txid: {v}"
    );

    let create_hex =
        rbitcoin_primitives::display_hash_hex(&chain.matured_coinbase_txid.to_byte_array());
    let spend_hex = rbitcoin_primitives::display_hash_hex(
        &chain.blocks.last().unwrap().txdata[1]
            .compute_txid()
            .to_byte_array(),
    );
    let spend_h = chain.spend_height;
    let sh_hex = electrum_scripthash_hex(&[0x51]);
    let full = rpc(
        &mut stream,
        21,
        "blockchain.scripthash.get_history",
        json!([sh_hex]),
    )
    .await;
    let full_rows = full["result"].as_array().expect("full history");
    assert!(
        full_rows.iter().any(|r| r["tx_hash"] == create_hex),
        "full history missing create: {full}"
    );
    assert!(
        full_rows.iter().any(|r| r["tx_hash"] == spend_hex),
        "full history missing spend: {full}"
    );
    let from_create = rpc(
        &mut stream,
        22,
        "blockchain.scripthash.get_history",
        json!([sh_hex, 1]),
    )
    .await;
    assert!(
        from_create["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tx_hash"] == create_hex),
        "from_height at first create: {from_create}"
    );
    let before_spend = rpc(
        &mut stream,
        23,
        "blockchain.scripthash.get_history",
        json!([sh_hex, 1, spend_h]),
    )
    .await;
    let before_rows = before_spend["result"].as_array().unwrap();
    assert!(
        before_rows.iter().any(|r| r["tx_hash"] == create_hex),
        "exclusive to_height must keep create: {before_spend}"
    );
    assert!(
        before_rows.iter().all(|r| r["tx_hash"] != spend_hex),
        "exclusive to_height must hide spend: {before_spend}"
    );
    assert!(
        before_rows.len() < full_rows.len(),
        "window must be shorter than full history"
    );
    let open_to = rpc(
        &mut stream,
        24,
        "blockchain.scripthash.get_history",
        json!([sh_hex, 1, -1]),
    )
    .await;
    assert!(
        open_to["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["tx_hash"] == spend_hex),
        "to_height=-1 must include spend: {open_to}"
    );
    let status = rpc(
        &mut stream,
        25,
        "blockchain.scripthash.subscribe",
        json!([sh_hex]),
    )
    .await;
    let status_s = status["result"].as_str().expect("subscribe status");
    assert!(!status_s.is_empty(), "{status}");
    let bad_from = rpc(
        &mut stream,
        26,
        "blockchain.scripthash.get_history",
        json!([sh_hex, "x"]),
    )
    .await;
    let bad_msg = bad_from["error"]["message"].as_str().unwrap_or("");
    assert!(
        bad_msg.contains("expected number"),
        "invalid from_height: {bad_from}"
    );

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
    let v = rpc(
        &mut stream,
        21,
        "blockchain.transaction.broadcast_package",
        json!([["00"]]),
    )
    .await;
    assert!(v.get("error").is_some(), "{v}");

    // Bad params.
    let v = rpc(&mut stream, 20, "blockchain.block.header", json!(["x"])).await;
    assert!(v.get("error").is_some());

    let mut dos = TcpStream::connect(handle.local_addr).await.unwrap();
    let v = rpc(&mut dos, 1, "server.ping", json!([])).await;
    assert!(v.get("result").is_some(), "{v}");
    let mut at_cap = vec![b'A'; 2047];
    at_cap.push(b'\n');
    dos.write_all(&at_cap).await.unwrap();
    let v = rpc(&mut dos, 2, "server.ping", json!([])).await;
    assert!(
        v.get("result").is_some(),
        "line at max_request_bytes must not close: {v}"
    );
    let mut over = vec![b'A'; 2048];
    over.push(b'\n');
    dos.write_all(&over).await.unwrap();
    {
        let mut reader = BufReader::new(&mut dos);
        let mut resp = String::new();
        read_line_timeout(&mut reader, &mut resp, "request line too long").await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], json!(-32600), "{v}");
        assert_eq!(
            v["error"]["message"].as_str(),
            Some("request line too long"),
            "{v}"
        );
    }

    handle.shutdown().await;
}

/// `block_touch` must see a scripthash that a block only *spends*: OP_TRUE
/// coinbases (heights 1..=101) fund it, and block 102 pays its coinbase
/// elsewhere while spending one of those outputs. Removing the input
/// `create_fk`s from the touch set must fail this.
#[test]
fn block_touch_sees_spend_only_heights() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::accept_and_connect_block;
    use rbitcoin_primitives::Height;
    use rbitcoin_store::script_hash;

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
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase_txids[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
        }],
    };
    let blk = rbitcoin_consensus::mine_regtest_paying(
        tip,
        tip_time + 600,
        102,
        ScriptBuf::from_bytes(vec![0x53]),
        vec![spend],
    );
    accept_and_connect_block(&q, &params, Height(102), &blk, Milestone::NONE).unwrap();
    q.apply_sh_pending().unwrap();

    let spent_only = script_hash(&[0x51]);
    let touch = q.block_touch(Height(102)).unwrap();
    assert!(
        q.scripthash_touched_at_height(&spent_only, Height(102))
            .unwrap(),
        "fixture: OP_TRUE is spent (not paid) at 102"
    );
    assert!(
        q.scripthash_touched_by(&spent_only, &touch).unwrap(),
        "block_touch must include the spent outputs' create fks"
    );
    for (script, want) in [(vec![0x52], true), (vec![0x53], true), (vec![0x54], false)] {
        let sh = script_hash(&script);
        assert_eq!(
            q.scripthash_touched_by(&sh, &touch).unwrap(),
            want,
            "{script:?}"
        );
        assert_eq!(
            q.scripthash_touched_at_height(&sh, Height(102)).unwrap(),
            want,
            "{script:?}"
        );
    }
}

/// Every newline-delimited JSON message the server sends within `window`.
/// Reads raw bytes, so two pushes that arrive together are both counted.
async fn drain_lines(stream: &mut TcpStream, window: Duration) -> Vec<Value> {
    let mut raw = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = [0u8; 4096];
    while let Ok(Ok(n)) = tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
    }
    String::from_utf8(raw)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The mempool notify path probes the sub set with each accepted tx's
/// scripthashes. Funding the watched hash pushes its new status, and an RBF
/// replacement that stops paying it must push again via replaced_scripthashes
/// (the hash is no longer in the replacement's own scripthashes).
#[tokio::test]
async fn electrum_mempool_notify_follows_funding_and_rbf() {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::accept_and_connect_block;
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::Height;

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
        &q,
        &params,
        genesis.block_hash(),
        genesis.header.time,
        1,
        101,
        1,
    );
    let q = Arc::new(q);
    let mp = Arc::new(MempoolHub::open(dir.path().join("mempool"), Arc::clone(&q)).unwrap());
    mp.set_relay_enabled(true);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, Some(Arc::clone(&mp)))
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let watched = ScriptBuf::from_bytes(vec![0x52]);
    let sh = electrum_scripthash_hex(watched.as_bytes());
    let v = rpc(
        &mut stream,
        1,
        "blockchain.scripthash.subscribe",
        json!([sh.clone()]),
    )
    .await;
    // No history: status is null (protocol), not "". Sparrow reads any
    // non-null status as a used address and keeps deriving past its gap.
    assert_eq!(v["result"], Value::Null, "{v}");

    let spend = |outputs: Vec<TxOut>| Transaction {
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
        output: outputs,
    };
    let pays = |spk: &ScriptBuf, sat: u64| TxOut {
        value: Amount::from_sat(sat),
        script_pubkey: spk.clone(),
    };
    // Two outputs to the watched script; one status push for the hash.
    let first = spend(vec![
        pays(&watched, 20_0000_0000),
        pays(&watched, 29_9999_0000),
    ]);
    mp.accept_tx(&first).expect("accept first");
    let pushes = drain_lines(&mut stream, Duration::from_millis(800)).await;
    let for_sh: Vec<_> = pushes
        .iter()
        .filter(|m| m["method"] == "blockchain.scripthash.subscribe" && m["params"][0] == sh)
        .collect();
    assert_eq!(for_sh.len(), 1, "one push per accepted tx: {pushes:?}");
    let funded_status = for_sh[0]["params"][1].clone();
    assert!(funded_status.is_string(), "{pushes:?}");

    // RBF the spend to a different script: the watched hash is only in
    // replaced_scripthashes, and its status must be pushed again.
    let other = ScriptBuf::from_bytes(vec![0x53]);
    let replacement = spend(vec![pays(&other, 49_9990_0000)]);
    mp.accept_tx(&replacement).expect("accept replacement");
    let pushes = drain_lines(&mut stream, Duration::from_millis(800)).await;
    let for_sh: Vec<_> = pushes
        .iter()
        .filter(|m| m["method"] == "blockchain.scripthash.subscribe" && m["params"][0] == sh)
        .collect();
    assert_eq!(
        for_sh.len(),
        1,
        "RBF victim's hash is restatused: {pushes:?}"
    );
    assert_eq!(
        for_sh[0]["params"][1],
        Value::Null,
        "victim's history is empty again, so its status is null: {pushes:?}"
    );

    handle.shutdown().await;
}

/// Sparrow subscribes every receive and change address up to its gap limit on
/// one connection; the old 1,000 default refused `../0/332` of a real wallet.
/// The default must take a wallet well past that.
#[tokio::test]
async fn electrum_default_sub_cap_admits_a_large_wallet() {
    let dir = TempDir::new().unwrap();
    let q = Arc::new(Query::open_or_create_tiny(dir.path().join("store")).unwrap());
    let params = ChainParams::regtest();
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    assert_eq!(
        cfg.max_scripthash_subs,
        rbitcoin_electrum::DEFAULT_MAX_SCRIPTHASH_SUBS
    );
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
    for i in 0..1_200u64 {
        let mut sh = [0u8; 32];
        sh[..8].copy_from_slice(&(i + 1).to_le_bytes());
        let v = rpc(
            &mut stream,
            i + 1,
            "blockchain.scripthash.subscribe",
            json!([sh.iter().map(|b| format!("{b:02x}")).collect::<String>()]),
        )
        .await;
        assert!(v.get("result").is_some(), "sub #{} refused: {v}", i + 1);
    }
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
    // Outpoint subs are a second set with the same numeric cap.
    let op = |n: u8| "11".repeat(31) + &format!("{n:02x}");
    let a = rpc(
        &mut stream,
        7,
        "blockchain.outpoint.subscribe",
        json!([op(1), 0]),
    )
    .await;
    assert!(a.get("result").is_some(), "{a}");
    let b = rpc(
        &mut stream,
        8,
        "blockchain.outpoint.subscribe",
        json!([op(2), 0]),
    )
    .await;
    assert!(b.get("result").is_some(), "{b}");
    let again = rpc(
        &mut stream,
        9,
        "blockchain.outpoint.subscribe",
        json!([op(1), 0]),
    )
    .await;
    assert!(
        again.get("result").is_some(),
        "resubscribe stays under the cap: {again}"
    );
    let third = rpc(
        &mut stream,
        10,
        "blockchain.outpoint.subscribe",
        json!([op(3), 0]),
    )
    .await;
    let msg = third["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("max 2"), "{third}");
    let un = rpc(
        &mut stream,
        11,
        "blockchain.outpoint.unsubscribe",
        json!([op(1), 0]),
    )
    .await;
    assert_eq!(un["result"], json!(true), "{un}");
    let freed = rpc(
        &mut stream,
        12,
        "blockchain.outpoint.subscribe",
        json!([op(3), 0]),
    )
    .await;
    assert!(
        freed.get("error").is_none(),
        "unsubscribe must free an outpoint cap slot: {freed}"
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
    let handle = run_electrum(
        cfg,
        Arc::clone(&q_arc),
        params,
        tip_tx,
        Some(Arc::clone(&mp)),
    )
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

    let bad_hex = rpc(
        &mut stream,
        4,
        "blockchain.transaction.broadcast",
        json!(["zz"]),
    )
    .await;
    let hex_msg = bad_hex["error"]["message"].as_str().unwrap_or("");
    assert!(
        hex_msg.contains("hex") || hex_msg.contains("Invalid"),
        "non-hex broadcast with hub: {bad_hex}"
    );
    let miss = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let miss_hex = bitcoin::consensus::encode::serialize_hex(&miss);
    let bad_tx = rpc(
        &mut stream,
        5,
        "blockchain.transaction.broadcast",
        json!([miss_hex]),
    )
    .await;
    let tx_msg = bad_tx["error"]["message"].as_str().unwrap_or("");
    assert!(
        tx_msg.contains("broadcast reject"),
        "consensus-invalid broadcast with hub: {bad_tx}"
    );

    let cb1 = rbitcoin_primitives::display_hash_hex(&coinbase_txids[0].to_byte_array());
    let conf = rpc(
        &mut stream,
        8,
        "blockchain.outpoint.get_status",
        json!([cb1, 0]),
    )
    .await;
    assert_eq!(conf["result"]["spent"], true, "{conf}");
    assert_eq!(
        conf["result"]["height"].as_u64(),
        Some(102),
        "confirmed spend uses tip height: {conf}"
    );
    assert!(
        conf["result"].get("spending_txid").is_none(),
        "confirmed spend omits spending_txid: {conf}"
    );
    let pkg_hex_err = rpc(
        &mut stream,
        11,
        "blockchain.transaction.broadcast_package",
        json!([["zz"]]),
    )
    .await;
    assert!(
        pkg_hex_err.get("error").is_some(),
        "package invalid hex: {pkg_hex_err}"
    );
    let pkg_miss = rpc(
        &mut stream,
        9,
        "blockchain.transaction.broadcast_package",
        json!([[miss_hex.clone()]]),
    )
    .await;
    let pkg_miss_msg = pkg_miss["error"]["message"].as_str().unwrap_or("");
    assert!(
        pkg_miss_msg.contains("broadcast_package reject"),
        "invalid package with hub: {pkg_miss}"
    );

    mp.set_relay_enabled(true);
    let cb2 = q_arc.reconstruct_block_at_height(Height(2)).unwrap().txdata[0].compute_txid();
    let pkg = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb2, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let pkg_hex = bitcoin::consensus::encode::serialize_hex(&pkg);
    let packed = rpc(
        &mut stream,
        6,
        "blockchain.transaction.broadcast_package",
        json!([[pkg_hex], true]),
    )
    .await;
    assert_eq!(
        packed["result"]["package_msg"].as_str(),
        Some("success"),
        "{packed}"
    );
    let cb = rbitcoin_primitives::display_hash_hex(&cb2.to_byte_array());
    let spent = rpc(
        &mut stream,
        7,
        "blockchain.outpoint.get_status",
        json!([cb, 0]),
    )
    .await;
    assert_eq!(spent["result"]["spent"], true, "{spent}");
    assert_eq!(
        spent["result"]["height"].as_u64(),
        Some(0),
        "mempool spend height: {spent}"
    );
    assert!(
        spent["result"]["spending_txid"].as_str().is_some(),
        "mempool spend spending_txid: {spent}"
    );

    let cb3 = q_arc.reconstruct_block_at_height(Height(3)).unwrap().txdata[0].compute_txid();
    let pkg2 = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: cb3, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let pkg2_hex = bitcoin::consensus::encode::serialize_hex(&pkg2);
    let packed2 = rpc(
        &mut stream,
        10,
        "blockchain.transaction.broadcast_package",
        json!([[pkg2_hex]]),
    )
    .await;
    assert_eq!(
        packed2["result"].as_str(),
        Some("success"),
        "non-verbose package: {packed2}"
    );

    let pkg_txid = rbitcoin_primitives::display_hash_hex(&pkg.compute_txid().to_byte_array());
    let verbose = rpc(
        &mut stream,
        12,
        "blockchain.transaction.get",
        json!([pkg_txid, true]),
    )
    .await;
    let got = &verbose["result"];
    assert!(got.get("blockhash").is_none(), "mempool verbose: {verbose}");
    assert_eq!(got["confirmations"], 0, "{verbose}");
    assert!(got.get("time").is_none(), "{verbose}");
    assert!(got.get("blocktime").is_none(), "{verbose}");

    handle.shutdown().await;
}

#[allow(clippy::cognitive_complexity)] // one pad, Electrum TCP + Esplora HTTP asof
#[tokio::test]
async fn electrum_and_esplora_asof_hides_later_spend() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, Milestone};
    use rbitcoin_primitives::Height;

    const ASOF: &str = "1.4.2-asof";
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
    let create_spk = ScriptBuf::from_bytes(vec![0x52]);
    let p2wpkh_sats = 50_000u64;
    let value = 50_0000_0000 - 1_000 - p2wpkh_sats;
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&[0x11; 20]);
    let create = Transaction {
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
        output: vec![
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: create_spk.clone(),
            },
            TxOut {
                value: Amount::from_sat(p2wpkh_sats),
                script_pubkey: ScriptBuf::from_bytes(p2wpkh),
            },
        ],
    };
    let create_blk = rbitcoin_consensus::mine_regtest_paying(
        tip,
        tip_time + 600,
        102,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![create.clone()],
    );
    accept_and_connect_block(&q, &params, Height(102), &create_blk, Milestone::NONE).unwrap();

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: create.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x53]),
        }],
    };
    let spend_blk = rbitcoin_consensus::mine_regtest_paying(
        create_blk.block_hash(),
        create_blk.header.time + 600,
        103,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend.clone()],
    );
    accept_and_connect_block(&q, &params, Height(103), &spend_blk, Milestone::NONE).unwrap();
    q.apply_sh_pending().unwrap();
    let spend_blk_b = rbitcoin_consensus::mine_regtest_paying(
        create_blk.block_hash(),
        spend_blk.header.time.wrapping_add(1),
        103,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend.clone()],
    );
    assert_ne!(
        spend_blk.block_hash(),
        spend_blk_b.block_hash(),
        "same-height sibling must be a different blockhash"
    );

    let sh = electrum_scripthash_hex(create_spk.as_bytes());
    let asof_create =
        rbitcoin_primitives::display_hash_hex(&create_blk.block_hash().to_byte_array());
    let asof_spend = rbitcoin_primitives::display_hash_hex(&spend_blk.block_hash().to_byte_array());
    let tag_create = format!("asof:{asof_create}");
    let tag_spend = format!("asof:{asof_spend}");
    let create_hex = rbitcoin_primitives::display_hash_hex(&create.compute_txid().to_byte_array());
    let spend_hex = rbitcoin_primitives::display_hash_hex(&spend.compute_txid().to_byte_array());

    let q = Arc::new(q);
    let esplora_cfg = rbitcoin_esplora::EsploraConfig::with_network(
        "127.0.0.1:0".parse().unwrap(),
        bitcoin::Network::Regtest,
    );
    let esplora = rbitcoin_esplora::run_esplora(esplora_cfg, Arc::clone(&q), None)
        .await
        .expect("esplora listen");
    let (tip_tx, _) = broadcast::channel(8);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, Arc::clone(&q), params.clone(), tip_tx.clone(), None)
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let denied = rpc(
        &mut stream,
        1,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), tag_create.clone()]),
    )
    .await;
    let denied_msg = denied["error"]["message"].as_str().unwrap_or("");
    assert!(
        denied_msg.contains("1.4.2-asof"),
        "asof tag before handshake: {denied}"
    );

    let ver = rpc(&mut stream, 2, "server.version", json!(["test", ASOF])).await;
    assert_eq!(ver["result"][1], ASOF, "{ver}");
    let locked = rpc(&mut stream, 3, "server.version", json!(["test", "1.4"])).await;
    assert_eq!(locked["result"][1], ASOF, "{locked}");

    let bal0 = rpc(
        &mut stream,
        4,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), tag_create.clone()]),
    )
    .await;
    assert_eq!(bal0["result"]["confirmed"], value, "{bal0}");
    assert_eq!(bal0["result"]["unconfirmed"], 0, "{bal0}");

    let utxo0 = rpc(
        &mut stream,
        5,
        "blockchain.scripthash.listunspent",
        json!([sh.clone(), tag_create.clone()]),
    )
    .await;
    let utxo0_rows = utxo0["result"].as_array().unwrap();
    assert_eq!(utxo0_rows.len(), 1, "{utxo0}");
    assert_eq!(utxo0_rows[0]["tx_hash"], create_hex);

    let hist0 = rpc(
        &mut stream,
        6,
        "blockchain.scripthash.get_history",
        json!([sh.clone(), tag_create.clone()]),
    )
    .await;
    let hist0_rows = hist0["result"].as_array().unwrap();
    assert_eq!(hist0_rows.len(), 1, "{hist0}");
    assert_eq!(hist0_rows[0]["tx_hash"], create_hex);

    let bal1 = rpc(
        &mut stream,
        7,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), tag_spend.clone()]),
    )
    .await;
    assert_eq!(bal1["result"]["confirmed"], 0, "{bal1}");

    let utxo1 = rpc(
        &mut stream,
        8,
        "blockchain.scripthash.listunspent",
        json!([sh.clone(), tag_spend.clone()]),
    )
    .await;
    assert!(utxo1["result"].as_array().unwrap().is_empty(), "{utxo1}");

    let hist1 = rpc(
        &mut stream,
        9,
        "blockchain.scripthash.get_history",
        json!([sh.clone(), tag_spend.clone()]),
    )
    .await;
    let hist1_rows = hist1["result"].as_array().unwrap();
    assert_eq!(hist1_rows.len(), 2, "{hist1}");
    assert!(
        hist1_rows.iter().any(|r| r["tx_hash"] == spend_hex),
        "spend missing at asof spend: {hist1}"
    );

    let get_later = rpc(
        &mut stream,
        10,
        "blockchain.transaction.get",
        json!([spend_hex.clone(), tag_create.clone()]),
    )
    .await;
    let later_msg = get_later["error"]["message"].as_str().unwrap_or("");
    assert!(
        later_msg.contains("tx not found"),
        "asof create must hide later spend tx: {get_later}"
    );

    let merkle_later = rpc(
        &mut stream,
        11,
        "blockchain.transaction.get_merkle",
        json!([spend_hex, 103, tag_create]),
    )
    .await;
    let merkle_msg = merkle_later["error"]["message"].as_str().unwrap_or("");
    assert!(
        merkle_msg.contains("asof not on chain"),
        "merkle height above asof pin: {merkle_later}"
    );

    let unknown = rpc(
        &mut stream,
        12,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), format!("asof:{}", "ee".repeat(32))]),
    )
    .await;
    let unknown_msg = unknown["error"]["message"].as_str().unwrap_or("");
    assert!(
        unknown_msg.contains("asof not on chain"),
        "unknown asof: {unknown}"
    );

    assert_esplora_asof_hides_later_spend(
        esplora.local_addr,
        &sh,
        &asof_create,
        &asof_spend,
        &create_hex,
    )
    .await;

    q.set_sh_index_enabled(false);
    let lag_blk = rbitcoin_consensus::mine_empty_regtest(
        spend_blk.block_hash(),
        spend_blk.header.time + 600,
        104,
    );
    accept_and_connect_block(&q, &params, Height(104), &lag_blk, Milestone::NONE).unwrap();
    assert_eq!(q.tip_height(), Some(Height(104)));
    assert_eq!(
        q.sh_lag_heights(),
        1,
        "SH-off connect must leave visible SH behind tip"
    );
    let lag_hash = lag_blk.block_hash().to_byte_array();
    let spend_hash = spend_blk.block_hash().to_byte_array();
    assert!(
        q.pin_sh_chain_view_at(&spend_hash).unwrap().is_some(),
        "asof at visible SH watermark must pin"
    );
    assert!(
        q.pin_sh_chain_view_at(&lag_hash).unwrap().is_none(),
        "asof of a confirmed hash ahead of visible SH must not pin"
    );
    let asof_lag = rbitcoin_primitives::display_hash_hex(&lag_hash);
    let at_wm = rpc(
        &mut stream,
        13,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), tag_spend.clone()]),
    )
    .await;
    assert_eq!(at_wm["result"]["confirmed"], 0, "{at_wm}");
    let ahead = rpc(
        &mut stream,
        14,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), format!("asof:{asof_lag}")]),
    )
    .await;
    let ahead_msg = ahead["error"]["message"].as_str().unwrap_or("");
    assert!(
        ahead_msg.contains("asof not on chain"),
        "asof ahead of visible SH: {ahead}"
    );
    let (st, raw, body) = http_get_raw(
        esplora.local_addr,
        &format!("/scripthash/{sh}/utxo?asof={asof_spend}"),
    )
    .await;
    assert_eq!(st, 200, "asof at SH watermark utxo body={body}");
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip").as_deref(),
        Some(asof_spend.as_str())
    );
    assert_esplora_asof_dead(
        esplora.local_addr,
        &format!("/scripthash/{sh}/utxo?asof={asof_lag}"),
    )
    .await;

    q.disconnect_tip().unwrap();
    q.set_sh_index_enabled(true);
    assert_eq!(q.tip_height(), Some(Height(103)));

    let sub = rpc(
        &mut stream,
        15,
        "blockchain.scripthash.subscribe",
        json!([sh.clone()]),
    )
    .await;
    let status_a = sub["result"]
        .as_str()
        .expect("subscribe status")
        .to_string();
    assert_eq!(status_a.len(), 64, "{sub}");
    let live_hist = rpc(
        &mut stream,
        20,
        "blockchain.scripthash.get_history",
        json!([sh.clone()]),
    )
    .await;
    assert_eq!(
        live_hist["chain_tip"].as_str(),
        Some(asof_spend.as_str()),
        "history stamps the tip hash: {live_hist}"
    );

    q.disconnect_tip().unwrap();
    q.apply_sh_pending().unwrap();
    accept_and_connect_block(&q, &params, Height(103), &spend_blk_b, Milestone::NONE).unwrap();
    q.apply_sh_pending().unwrap();
    tip_tx
        .send(TipNotify {
            height: 103,
            header_hex: header_hex(&spend_blk_b),
            reorg_from_height: Some(103),
        })
        .expect("same-height replace notify");
    let push_b = read_notify(&mut stream, "same-height status B").await;
    assert_eq!(
        push_b["method"].as_str(),
        Some("blockchain.scripthash.subscribe")
    );
    let status_b = push_b["params"][1].as_str().expect("status B").to_string();
    assert_ne!(
        status_a, status_b,
        "same-height replace must change status via confirming blockhash"
    );
    let live_b = rpc(
        &mut stream,
        21,
        "blockchain.scripthash.get_history",
        json!([sh.clone()]),
    )
    .await;
    let tip_b = rbitcoin_primitives::display_hash_hex(&spend_blk_b.block_hash().to_byte_array());
    assert_eq!(
        live_b["chain_tip"].as_str(),
        Some(tip_b.as_str()),
        "replaced tip restamps history: {live_b}"
    );
    assert_ne!(asof_spend, tip_b);
    let asof_a = rpc(
        &mut stream,
        16,
        "blockchain.scripthash.get_history",
        json!([sh.clone(), tag_spend.clone()]),
    )
    .await;
    let asof_a_msg = asof_a["error"]["message"].as_str().unwrap_or("");
    assert!(
        asof_a_msg.contains("asof not on chain"),
        "asof of disconnected hash must not retry onto the sibling: {asof_a}"
    );
    assert_esplora_asof_dead(
        esplora.local_addr,
        &format!("/scripthash/{sh}/utxo?asof={asof_spend}"),
    )
    .await;
    assert_esplora_asof_dead(
        esplora.local_addr,
        &format!("/tx/{spend_hex}/status?asof={asof_spend}"),
    )
    .await;

    q.disconnect_tip().unwrap();
    q.apply_sh_pending().unwrap();
    accept_and_connect_block(&q, &params, Height(103), &spend_blk, Milestone::NONE).unwrap();
    q.apply_sh_pending().unwrap();
    tip_tx
        .send(TipNotify {
            height: 103,
            header_hex: header_hex(&spend_blk),
            reorg_from_height: Some(103),
        })
        .expect("A-B-A restore notify");
    let push_a2 = read_notify(&mut stream, "same-height status A again").await;
    assert_eq!(
        push_a2["params"][1].as_str(),
        Some(status_a.as_str()),
        "A-B-A must restore the original status string: {push_a2}"
    );

    q.disconnect_tip().unwrap();
    q.apply_sh_pending().unwrap();
    tip_tx
        .send(TipNotify {
            height: 102,
            header_hex: header_hex(&create_blk),
            reorg_from_height: Some(102),
        })
        .expect("disconnect spend notify");
    let push_u = read_notify(&mut stream, "unspend status").await;
    let status_u = push_u["params"][1].as_str().unwrap_or("");
    assert_ne!(
        status_u, status_a,
        "disconnecting the spend must restatus: {push_u}"
    );

    let hist_u = rpc(
        &mut stream,
        17,
        "blockchain.scripthash.get_history",
        json!([sh.clone()]),
    )
    .await;
    let hist_u_rows = hist_u["result"].as_array().unwrap();
    assert_eq!(hist_u_rows.len(), 1, "{hist_u}");
    assert_eq!(hist_u_rows[0]["tx_hash"], create_hex);
    let utxo_u = rpc(
        &mut stream,
        18,
        "blockchain.scripthash.listunspent",
        json!([sh.clone()]),
    )
    .await;
    let utxo_u_rows = utxo_u["result"].as_array().unwrap();
    assert_eq!(utxo_u_rows.len(), 1, "{utxo_u}");
    assert_eq!(utxo_u_rows[0]["tx_hash"], create_hex);
    let asof_dead = rpc(
        &mut stream,
        19,
        "blockchain.scripthash.get_balance",
        json!([sh.clone(), tag_spend]),
    )
    .await;
    let asof_dead_msg = asof_dead["error"]["message"].as_str().unwrap_or("");
    assert!(
        asof_dead_msg.contains("asof not on chain"),
        "asof of disconnected spend hash: {asof_dead}"
    );

    let (st, raw, body) = http_get_raw(esplora.local_addr, &format!("/scripthash/{sh}/utxo")).await;
    assert_eq!(st, 200, "live utxo after disconnect spend body={body}");
    let utxos: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(utxos.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(utxos[0]["txid"], create_hex);
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip").as_deref(),
        Some(asof_create.as_str()),
        "live stamp must be the create block, not the disconnected spend"
    );
    assert_eq!(
        http_header_value(&raw, "x-bitcoin-chain-tip-height").as_deref(),
        Some("102")
    );
    let (st, _, body) = http_get_raw(esplora.local_addr, &format!("/tx/{spend_hex}/status")).await;
    assert_eq!(st, 200, "spend status after disconnect={body}");
    let spend_st: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(spend_st["confirmed"], false, "{spend_st}");
    assert_esplora_asof_dead(
        esplora.local_addr,
        &format!("/scripthash/{sh}/utxo?asof={asof_spend}"),
    )
    .await;
    assert_esplora_asof_dead(
        esplora.local_addr,
        &format!("/tx/{spend_hex}/status?asof={asof_spend}"),
    )
    .await;

    handle.shutdown().await;
    esplora.shutdown().await;
}

#[tokio::test]
async fn electrum_empty_chain_headers_subscribe_and_empty_scripthash() {
    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let sub = rpc(&mut stream, 1, "blockchain.headers.subscribe", json!([])).await;
    let sub_msg = sub["error"]["message"].as_str().unwrap_or("");
    assert!(
        sub_msg.contains("no chain tip"),
        "empty chain headers.subscribe: {sub}"
    );

    let sh = electrum_scripthash_hex(&[0x51]);
    let hist = rpc(
        &mut stream,
        2,
        "blockchain.scripthash.get_history",
        json!([sh.clone()]),
    )
    .await;
    assert_eq!(hist["result"], json!([]), "{hist}");

    let bal = rpc(
        &mut stream,
        3,
        "blockchain.scripthash.get_balance",
        json!([sh.clone()]),
    )
    .await;
    assert_eq!(bal["result"]["confirmed"], 0, "{bal}");

    let unspent = rpc(
        &mut stream,
        4,
        "blockchain.scripthash.listunspent",
        json!([sh.clone()]),
    )
    .await;
    assert_eq!(unspent["result"], json!([]), "{unspent}");

    let mem = rpc(
        &mut stream,
        5,
        "blockchain.scripthash.get_mempool",
        json!([sh]),
    )
    .await;
    assert_eq!(mem["result"], json!([]), "{mem}");

    handle.shutdown().await;
}

/// Cake isolate: JSON-RPC result is the first height, then one notification
/// per following height, then `{"message":"done"}`. Height 2 hash-binds a
/// P2WPKH→P2TR spend to `tweak_from_tx`.
#[tokio::test]
async fn electrum_tweaks_subscribe_streams_then_done() {
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, tweak_from_tx, Milestone};
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::testutil::FixtureChain;
    use rbitcoin_query::TxApply;
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

    let dir = TempDir::new().unwrap();
    let q = Query::open_or_create_tiny(dir.path().join("store")).unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
    let (fk0, rec0) = q.header_at_height(Height::GENESIS).unwrap().unwrap();

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let ser = pk.serialize();
    let h160 = hash160::Hash::hash(&ser);
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(h160.as_ref());
    let (xonly, _) = pk.x_only_public_key();
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&xonly.serialize());

    let mut create_txid = [0u8; 32];
    create_txid[31] = 0xcb;
    let mut merkle1 = [0u8; 32];
    merkle1[0] = 1;
    merkle1[5] = 0xec;
    let hash1 = rbitcoin_store::block_header_hash(1, &rec0.hash, &merkle1, 2, 0x207fffff, 1);
    let h1 = HeaderRecord {
        prev_fk: fk0,
        version: 1,
        timestamp: 2,
        bits: 0x207fffff,
        nonce: 1,
        merkle_root: merkle1,
        hash: hash1,
        size: 0,
        weight: 0,
    };
    let ta1 = TxApply {
        tx: TxRecord {
            txid: create_txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
    };
    let fk1 = q.connect_block(Height(1), &h1, &[ta1]).unwrap();
    let create_fk = q.block_tx_fks(Height(1)).unwrap()[0];

    let mut spend_txid = [0u8; 32];
    spend_txid[0] = 0x11;
    spend_txid[31] = 0xcd;
    let merkle2 = [0x11; 32];
    let hash2 = rbitcoin_store::block_header_hash(1, &hash1, &merkle2, 3, 0x207fffff, 2);
    let h2 = HeaderRecord {
        prev_fk: fk1,
        version: 1,
        timestamp: 3,
        bits: 0x207fffff,
        nonce: 2,
        merkle_root: merkle2,
        hash: hash2,
        size: 0,
        weight: 0,
    };
    let ta2 = TxApply {
        tx: TxRecord {
            txid: spend_txid,
            version: 2,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: create_txid,
            create_fk,
            prev_index: 0,
            sequence: u32::MAX,
            script_sig: vec![],
            witness: vec![vec![0u8; 64], ser.to_vec()],
        }],
        outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
    };
    let fk2 = q.connect_block(Height(2), &h2, &[ta2]).unwrap();

    let mut merkle3 = [0u8; 32];
    merkle3[0] = 3;
    merkle3[5] = 0xec;
    let hash3 = rbitcoin_store::block_header_hash(1, &hash2, &merkle3, 4, 0x207fffff, 3);
    let mut dummy_txid = [0u8; 32];
    dummy_txid[0] = 3;
    dummy_txid[31] = 0xcb;
    let h3 = HeaderRecord {
        prev_fk: fk2,
        version: 1,
        timestamp: 4,
        bits: 0x207fffff,
        nonce: 3,
        merkle_root: merkle3,
        hash: hash3,
        size: 0,
        weight: 0,
    };
    let ta3 = TxApply {
        tx: TxRecord {
            txid: dummy_txid,
            version: 1,
            locktime: 0,
            input_start_fk: Fk::NULL,
            input_count: 1,
            output_start_fk: Fk::NULL,
            output_count: 1,
        },
        inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x03], vec![])],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
    };
    q.connect_block(Height(3), &h3, &[ta3]).unwrap();

    let engine_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(create_txid),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&[0u8; 64][..], &ser[..]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(p2tr.clone()),
        }],
    };
    let engine_prev = vec![TxOut {
        value: Amount::from_sat(50_0000_0000),
        script_pubkey: ScriptBuf::from_bytes(p2wpkh),
    }];
    let expect = tweak_from_tx(&engine_tx, &engine_prev).unwrap();
    let mut disp = spend_txid;
    disp.reverse();
    let spend_key = rbitcoin_primitives::hex_encode(disp);
    let tweak_hex = rbitcoin_primitives::hex_encode(expect.tweak);

    let q = Arc::new(q);
    let (tip_tx, _) = broadcast::channel(4);
    let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
    let handle = run_electrum(cfg, q, params, tip_tx, None)
        .await
        .expect("electrum listen");
    let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();

    let req = json!({
        "jsonrpc":"2.0","id":"scan",
        "method":"blockchain.tweaks.subscribe",
        "params":[1, 3, false]
    });
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut stream);
    let mut resp = String::new();

    read_line_timeout(&mut reader, &mut resp, "tweaks result").await;
    let result: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(result["id"], "scan");
    let map = result["result"].as_object().expect("result map");
    assert_eq!(
        map.len(),
        1,
        "JSON-RPC result must be one height, got {map:?}"
    );
    assert!(map.contains_key("1"), "{map:?}");
    assert_eq!(
        map["1"].as_object().map(|o| o.len()),
        Some(0),
        "height 1 is the P2WPKH create, not a tweak: {map:?}"
    );

    read_line_timeout(&mut reader, &mut resp, "tweaks 2").await;
    let n2: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(n2["method"], "blockchain.tweaks.subscribe");
    let p2 = n2["params"][0].as_object().expect("notify 2");
    assert_eq!(p2.len(), 1);
    let h2_txs = p2["2"].as_object().expect("height 2 txs");
    assert_eq!(h2_txs.len(), 1, "{h2_txs:?}");
    assert_eq!(h2_txs[&spend_key]["tweak"], json!(tweak_hex), "{h2_txs:?}");
    assert_eq!(
        h2_txs[&spend_key]["output_pubkeys"]["0"][0],
        json!(rbitcoin_primitives::hex_encode(xonly.serialize())),
        "{h2_txs:?}"
    );
    assert_eq!(
        h2_txs[&spend_key]["output_pubkeys"]["0"][1],
        json!(49_0000_0000_u64)
    );

    read_line_timeout(&mut reader, &mut resp, "tweaks 3").await;
    let n3: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(n3["method"], "blockchain.tweaks.subscribe");
    let p3 = n3["params"][0].as_object().expect("notify 3");
    assert_eq!(p3.len(), 1);
    assert!(p3.contains_key("3"), "{p3:?}");
    assert_eq!(
        p3["3"].as_object().map(|o| o.len()),
        Some(0),
        "height 3 has no P2TR spend: {p3:?}"
    );

    read_line_timeout(&mut reader, &mut resp, "tweaks done").await;
    let done: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(done["params"][0]["message"], "done");

    let past = json!({
        "jsonrpc":"2.0","id":"past",
        "method":"blockchain.tweaks.subscribe",
        "params":[99, 1, false]
    });
    let mut past_line = serde_json::to_string(&past).unwrap();
    past_line.push('\n');
    reader
        .get_mut()
        .write_all(past_line.as_bytes())
        .await
        .unwrap();
    read_line_timeout(&mut reader, &mut resp, "tweaks past result").await;
    let past_result: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(past_result["id"], "past");
    let past_map = past_result["result"].as_object().expect("past map");
    assert_eq!(
        past_map.len(),
        1,
        "start past tip is one empty height: {past_map:?}"
    );
    assert_eq!(
        past_map["99"].as_object().map(|o| o.len()),
        Some(0),
        "{past_map:?}"
    );
    read_line_timeout(&mut reader, &mut resp, "tweaks past done").await;
    let past_done: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(past_done["method"], "blockchain.tweaks.subscribe");
    assert_eq!(past_done["params"][0]["message"], "done");

    drop(reader);

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

/// Direct IBD collects no SH until the tip bulk materialize, and a repeat
/// finalize leaves the durable head alone.
fn pin_direct_collects_nothing_until_tip_materialize(q: &Query, sh: &[u8; 32]) {
    assert!(q.sh_index_enabled());
    assert!(!q.sh_run_enabled(), "Direct starts no SH run worker");
    assert!(!q.enqueues_sh_writebehind());
    q.enter_direct_index_mode().unwrap();
    assert_eq!(q.scripthash_run_count(), 0);
    assert!(!q.store().scripthash.has_durable_index());
    assert!(q.scripthash_history(sh).unwrap().is_empty());

    let n_sh = q.finalize_sh_runs().unwrap();
    assert!(n_sh > 0, "SH bulk materialize creates≈{n_sh}");
    assert_eq!(q.scripthash_run_count(), 0);
    let entries = q.scripthash_entry_count();
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.scripthash_entry_count(),
        entries,
        "a repeat finalize does not rewrite the durable head"
    );
    q.enter_tip_index_mode();
    assert!(q.sh_is_tip_ready());
    assert!(q.enqueues_sh_writebehind());
    q.set_sh_index_enabled(false);
    assert!(!q.enqueues_sh_writebehind());
    q.set_sh_index_enabled(true);
}

/// A tip confirm in Tip mode leaves SH to the write-behind, and the durable
/// head's `include_hwm` keeps the store tip-ready without a SEAL file.
fn pin_tip_follow_after_materialize(
    q: &Query,
    store: &std::path::Path,
    tip: bitcoin::BlockHash,
    time: u32,
) {
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_primitives::Height;
    use rbitcoin_test::mine::mine_regtest_block;

    let params = ChainParams::regtest();
    let sh = rbitcoin_store::script_hash(&[0x51]);
    let b6 = mine_regtest_block(tip, time + 600, 6, vec![]);
    accept_and_connect_block(q, &params, Height(6), &b6, Milestone::NONE).unwrap();
    assert_eq!(
        q.sh_indexed_through_height(),
        Some(5),
        "tip confirm leaves SH to the write-behind"
    );
    assert_eq!(
        q.scripthash_history(&sh).unwrap().len(),
        6,
        "pending SH shows the new tip create"
    );
    q.apply_sh_pending().unwrap();
    assert_eq!(q.sh_indexed_through_height(), Some(6));
    assert!(q.store().scripthash.include_hwm() >= q.tx_body_count());
    assert!(q.sh_is_tip_ready());

    let runs = store.join("scripthash.runs");
    let _ = std::fs::remove_dir_all(&runs);
    assert!(
        q.sh_is_tip_ready(),
        "include_hwm covers the tip without a SEAL file"
    );
    q.enter_direct_index_mode().unwrap();
    assert_eq!(q.finalize_sh_runs().unwrap(), 0);
    q.enter_tip_index_mode();
    assert_eq!(q.scripthash_history(&sh).unwrap().len(), 6);
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

    // OP_TRUE coinbase outputs from mine_regtest_block appear under that scripthash.
    let sh = {
        use rbitcoin_store::script_hash;
        script_hash(&[0x51])
    };
    pin_direct_collects_nothing_until_tip_materialize(&q, &sh);
    let hist = q.scripthash_history(&sh).unwrap();
    assert_eq!(
        hist.len(),
        5,
        "one OP_TRUE coinbase per height past genesis"
    );
    q.enter_direct_index_mode().unwrap();
    assert_eq!(
        q.finalize_sh_runs().unwrap(),
        0,
        "Direct re-entry keeps the SEAL the durable head covers"
    );
    q.enter_tip_index_mode();

    pin_tip_follow_after_materialize(&q, &dir.path().join("store"), tip, time);
    q.flush().unwrap();
    drop(q);

    let store = dir.path().join("store");
    for name in [
        "scripthash.body",
        "scripthash.head",
        "scripthash.runs",
        "scripthash.ovf",
        "scripthash.include_hwm",
        "scripthash.cold_progress",
    ] {
        let p = store.join(name);
        let _ = std::fs::remove_dir_all(&p);
        let _ = std::fs::remove_file(&p);
    }

    let q = Query::open_or_create_tiny(&store).unwrap();
    std::fs::write(store.join("ibd_utxo.map"), b"x").unwrap();
    std::fs::create_dir_all(store.join("point.runs")).unwrap();
    q.enter_direct_index_mode().unwrap();
    assert!(
        !store.join("ibd_utxo.map").exists() && !store.join("point.runs").exists(),
        "direct mode removes leftover catch-up artifacts"
    );
    let n_rebuild = q.finalize_sh_runs().unwrap();
    assert!(
        n_rebuild > 0 || !q.scripthash_history(&sh).unwrap().is_empty(),
        "wipe SH shards + reopen + finalize must restore history"
    );
    assert!(
        !q.scripthash_history(&sh).unwrap().is_empty(),
        "scripthash history must survive SH wipe + rematerialize"
    );
}
