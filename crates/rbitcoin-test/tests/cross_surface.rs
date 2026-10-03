//! One `run_p2p` process: Esplora broadcast is visible on RPC and Electrum.

use bitcoin::absolute::LockTime;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_consensus::{accept_and_connect_block, pad_empty_from, ChainParams, Milestone};
use rbitcoin_electrum::electrum_scripthash_hex;
use rbitcoin_node::{run_p2p, NodeConfig};
use rbitcoin_primitives::{Height, Network};
use rbitcoin_query::Query;
use rbitcoin_test::{build_mature_regtest_with_spend, TestDatadir};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// TCP RPC Bearer matching `{datadir}/rpc.token` written by the tests.
const RPC_BEARER: &str = "Bearer pass";

fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

async fn wait_listeners(addrs: &[SocketAddr]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut missing = None;
        for addr in addrs {
            if TcpStream::connect(addr).await.is_err() {
                missing = Some(*addr);
                break;
            }
        }
        if missing.is_none() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("listeners not up ({missing:?}): {addrs:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn http_exchange(addr: SocketAddr, req: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("http connect");
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
    (status, body)
}

async fn http_get_raw(addr: SocketAddr, path: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.expect("http connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let status = buf
        .split(|&b| b == b'\n')
        .next()
        .and_then(|l| std::str::from_utf8(l).ok())
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http headers");
    (status, buf[sep + 4..].to_vec())
}

async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    http_exchange(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
    .await
}

async fn http_post(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    http_exchange(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

async fn http_post_json(addr: SocketAddr, path: &str, body: &str) -> (u16, String) {
    http_exchange(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

#[cfg(unix)]
async fn wait_unix_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if tokio::net::UnixStream::connect(path).await.is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("unix socket not up: {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(unix)]
async fn jsonrpc_unix(path: &std::path::Path, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc":"1.0","id":"test","method":method,"params":params}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = tokio::net::UnixStream::connect(path)
        .await
        .unwrap_or_else(|e| panic!("unix rpc connect {}: {e}", path.display()));
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let json = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or(text.as_ref())
        .trim();
    serde_json::from_str(json).unwrap_or_else(|e| panic!("unix rpc {method} json: {e} body={text}"))
}

/// `--health-listen` answers `GET /healthz` in every phase; nothing else is a route.
async fn pin_healthz(health_addr: SocketAddr) {
    assert_eq!(http_get(health_addr, "/healthz").await, (200, "ok".into()));
    let (st, body) = http_post(health_addr, "/healthz", "").await;
    assert_eq!(st, 405, "POST /healthz: {body}");
    let (st, body) = http_get(health_addr, "/nope").await;
    assert_eq!(st, 404, "unknown health path: {body}");
}

/// `/readyz` once `run_p2p` is past bring-up (opening … indexing).
async fn readyz_after_startup(health_addr: SocketAddr) -> (u16, String) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (st, body) = http_get(health_addr, "/readyz").await;
        let starting = ["opening", "starting", "catch-up", "indexing"]
            .iter()
            .any(|p| body == format!("not ready: {p}"));
        if !starting || Instant::now() >= deadline {
            return (st, body);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// `/metrics` gauges a probe reads while the node is up: build, phase, ready,
/// initial block download, and block height.
async fn pin_health_scrape(health_addr: SocketAddr, ready: bool, blocks: f64) {
    let m = scrape_metrics(health_addr).await;
    let build = format!(
        "rbitcoin_build_info{{version=\"{}\",network=\"regtest\"}}",
        env!("CARGO_PKG_VERSION")
    );
    let flag = |on: bool| if on { 1.0 } else { 0.0 };
    assert_eq!(m.get(build.as_str()), Some(&1.0), "{m:?}");
    assert_eq!(
        m.get("rbitcoin_phase{phase=\"following\"}"),
        Some(&1.0),
        "{m:?}"
    );
    assert_eq!(m.get("rbitcoin_ready"), Some(&flag(ready)), "{m:?}");
    assert_eq!(
        m.get("rbitcoin_initial_block_download"),
        Some(&flag(!ready)),
        "{m:?}"
    );
    assert_eq!(m.get("rbitcoin_blocks"), Some(&blocks), "{m:?}");
}

/// `GET /metrics` in the Prometheus text format: one value per series.
async fn scrape_metrics(health_addr: SocketAddr) -> HashMap<String, f64> {
    let mut stream = TcpStream::connect(health_addr)
        .await
        .expect("metrics connect");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("http headers");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: text/plain; version=0.0.4; charset=utf-8"),
        "{head}"
    );
    body.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (series, v) = l.rsplit_once(' ').unwrap_or_else(|| panic!("sample: {l}"));
            let v = v.parse().unwrap_or_else(|_| panic!("sample value: {l}"));
            (series.to_string(), v)
        })
        .collect()
}

/// Every `/metrics` gauge that names an RPC field equals that field.
async fn pin_metrics_equal_rpc(
    health_addr: SocketAddr,
    rpc_addr: SocketAddr,
    ready: bool,
) -> HashMap<String, f64> {
    let chain = jsonrpc(rpc_addr, "getblockchaininfo", json!([])).await["result"].clone();
    let net = jsonrpc(rpc_addr, "getnetworkinfo", json!([])).await["result"].clone();
    let mempool = jsonrpc(rpc_addr, "getmempoolinfo", json!([])).await["result"].clone();
    let peers = jsonrpc(rpc_addr, "getpeerinfo", json!([])).await["result"].clone();
    let totals = jsonrpc(rpc_addr, "getnettotals", json!([])).await["result"].clone();
    let m = scrape_metrics(health_addr).await;
    let num = |v: &Value| v.as_f64().unwrap_or_else(|| panic!("number: {v}"));
    let flag = |b: bool| if b { 1.0 } else { 0.0 };
    let build = format!(
        "rbitcoin_build_info{{version=\"{}\",network=\"regtest\"}}",
        env!("CARGO_PKG_VERSION")
    );
    for (series, want) in [
        (build.as_str(), 1.0),
        ("rbitcoin_phase{phase=\"following\"}", 1.0),
        ("rbitcoin_phase{phase=\"opening\"}", 0.0),
        ("rbitcoin_ready", flag(ready)),
        ("rbitcoin_blocks", num(&chain["blocks"])),
        ("rbitcoin_headers", num(&chain["headers"])),
        ("rbitcoin_tip_time_seconds", num(&chain["time"])),
        (
            "rbitcoin_initial_block_download",
            flag(chain["initialblockdownload"] == true),
        ),
        (
            "rbitcoin_connections{direction=\"in\"}",
            num(&net["connections_in"]),
        ),
        (
            "rbitcoin_connections{direction=\"out\"}",
            num(&net["connections_out"]),
        ),
        ("rbitcoin_mempool_transactions", num(&mempool["size"])),
        ("rbitcoin_mempool_bytes", num(&mempool["bytes"])),
        (
            "rbitcoin_verification_progress",
            num(&chain["verificationprogress"]),
        ),
        ("rbitcoin_difficulty", num(&chain["difficulty"])),
        ("rbitcoin_peer_time_offset_seconds", num(&net["timeoffset"])),
        ("rbitcoin_mempool_max_weight", num(&mempool["maxmempool"])),
        (
            "rbitcoin_mempool_orphan_transactions",
            num(&mempool["orphanage"]["size"]),
        ),
        (
            "rbitcoin_mempool_unbroadcast_transactions",
            num(&mempool["unbroadcastcount"]),
        ),
    ] {
        assert_eq!(m.get(series), Some(&want), "{series}: {m:?}");
    }
    let min_fee_sat_kvb = (num(&mempool["mempoolminfee"]) * 100_000_000.0).round();
    assert_eq!(
        m["rbitcoin_mempool_min_fee_sat_per_vb"],
        min_fee_sat_kvb / 1000.0,
        "mempoolminfee: {mempool}"
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let tip_age = now - num(&chain["time"]);
    assert!(
        (m["rbitcoin_tip_age_seconds"] - tip_age).abs() < 30.0,
        "tip age {} vs {tip_age}",
        m["rbitcoin_tip_age_seconds"]
    );
    let peer_rows = peers.as_array().expect("getpeerinfo array");
    for network in ["ipv4", "ipv6", "onion", "i2p", "cjdns"] {
        let want = peer_rows.iter().filter(|p| p["network"] == network).count() as f64;
        let series = format!("rbitcoin_peers{{network=\"{network}\"}}");
        assert_eq!(m.get(&series), Some(&want), "{series}: {m:?}");
    }
    // Bytes can move between the RPC read and the scrape. Both are the same counters.
    let recv = num(&totals["totalbytesrecv"]);
    let sent = num(&totals["totalbytessent"]);
    assert!(
        (m["rbitcoin_network_receive_bytes_total"] - recv).abs() < 1_000_000.0,
        "recv {} vs {recv}",
        m["rbitcoin_network_receive_bytes_total"]
    );
    assert!(
        (m["rbitcoin_network_transmit_bytes_total"] - sent).abs() < 1_000_000.0,
        "sent {} vs {sent}",
        m["rbitcoin_network_transmit_bytes_total"]
    );
    assert!(m["rbitcoin_scripthash_lag_blocks"] <= 6.0, "{m:?}");
    let started = m["process_start_time_seconds"];
    assert!(started <= now && started > now - 600.0, "{m:?}");
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(m["process_resident_memory_bytes"] > 0.0, "{m:?}");
    m
}

async fn pin_address_prefix_404(esplora_addr: SocketAddr) {
    let (st, body) = http_get(esplora_addr, "/address-prefix/bc1").await;
    assert_eq!(st, 404, "address-prefix stays 404: {body}");
}

async fn pin_internal_mempool_txs(esplora_addr: SocketAddr) {
    let (st, body) = http_get(esplora_addr, "/internal/mempool/txs?max_txs=10000").await;
    assert_eq!(st, 404, "TCP GET /internal/mempool/txs: {body}");
    let payload = json!(["aa".repeat(32)]).to_string();
    let (st, body) = http_post_json(esplora_addr, "/internal/mempool/txs", &payload).await;
    assert_eq!(st, 404, "TCP POST /internal/mempool/txs: {body}");
}

async fn pin_internal_block_txs_and_outspends(esplora_addr: SocketAddr, block_hash: &str) {
    let (st, body) = http_get(esplora_addr, &format!("/internal/block/{block_hash}/txs")).await;
    assert_eq!(st, 404, "TCP GET /internal/block/…/txs: {body}");
    let (st, pub_body) = http_get(esplora_addr, &format!("/block/{block_hash}/txs")).await;
    assert_eq!(st, 200, "public /txs page: {pub_body}");
    let pub_arr: Vec<Value> = serde_json::from_str(&pub_body).unwrap();
    assert_eq!(pub_arr.len(), 25, "public /txs stays 25/page: {pub_body}");
    let (st, body) = http_post_json(
        esplora_addr,
        "/internal/txs/outspends/by-txid",
        &json!(["aa".repeat(32)]).to_string(),
    )
    .await;
    assert_eq!(st, 404, "TCP POST /internal/txs/outspends/by-txid: {body}");
}

async fn jsonrpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc":"1.0","id":"test","method":method,"params":params}).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {RPC_BEARER}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let (_st, text) = http_exchange(addr, &req).await;
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("rpc {method} json: {e} body={text}"))
}

/// A9: `waitforblockheight` timeout=0 while behind returns the live tip.
async fn pin_waitforblockheight_timeout_zero_behind(
    rpc_addr: SocketAddr,
    tip_height: u64,
    tip_hash: &str,
) {
    let t0 = Instant::now();
    let behind = jsonrpc(rpc_addr, "waitforblockheight", json!([tip_height + 50, 0])).await;
    assert!(
        t0.elapsed() < Duration::from_millis(1_000),
        "timeout=0 while behind must not hang: {:?}",
        t0.elapsed()
    );
    assert_eq!(behind["result"]["height"], tip_height, "{behind}");
    assert_eq!(behind["result"]["hash"], tip_hash, "{behind}");
}

/// B15: `getblockhash` tip ok / tip+1 `-8`; unknown `getblock` `-5`; verbosity 0 hex.
async fn pin_getblock_hash_oob_unknown_and_raw(
    rpc_addr: SocketAddr,
    tip_height: u64,
    tip_hash: &str,
) {
    let ok = jsonrpc(rpc_addr, "getblockhash", json!([tip_height])).await;
    assert_eq!(ok["result"], tip_hash, "{ok}");
    let oob = jsonrpc(rpc_addr, "getblockhash", json!([tip_height + 1])).await;
    assert_eq!(oob["error"]["code"], -8, "{oob}");
    assert_eq!(
        oob["error"]["message"], "Block height out of range",
        "{oob}"
    );
    let unknown = jsonrpc(rpc_addr, "getblock", json!(["00".repeat(32)])).await;
    assert_eq!(unknown["error"]["code"], -5, "{unknown}");
    assert_eq!(unknown["error"]["message"], "Block not found", "{unknown}");
    let v0 = jsonrpc(rpc_addr, "getblock", json!([tip_hash, 0])).await;
    let hex = v0["result"].as_str().expect("verbosity 0 hex");
    assert!(hex.len() > 160, "raw block hex: {v0}");
    assert!(
        hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "verbosity 0 must be hex: {v0}"
    );
}

struct TipWaiters {
    wait_new: tokio::task::JoinHandle<Value>,
    wait_height: tokio::task::JoinHandle<Value>,
    wait_gbt: tokio::task::JoinHandle<Value>,
    start_hash: String,
}

/// A9: spawn wait/GBT current-`longpollid` before generate. Stale id stays immediate.
async fn spawn_wait_and_gbt_longpoll(rpc_addr: SocketAddr, want_height: u64) -> TipWaiters {
    let start = jsonrpc(rpc_addr, "getbestblockhash", json!([])).await;
    let start_hash = start["result"].as_str().expect("tip hash").to_string();
    let gbt = jsonrpc(rpc_addr, "getblocktemplate", json!([{"rules": ["segwit"]}])).await;
    let lp = gbt["result"]["longpollid"]
        .as_str()
        .expect("longpollid")
        .to_string();
    let t0 = Instant::now();
    let stale = jsonrpc(
        rpc_addr,
        "getblocktemplate",
        json!([{"rules": ["segwit"], "longpollid": "not-this-id"}]),
    )
    .await;
    assert!(
        t0.elapsed() < Duration::from_millis(1_000),
        "stale longpollid must return immediately: {:?}",
        t0.elapsed()
    );
    assert_eq!(stale["result"]["longpollid"], lp, "{stale}");

    let wait_new =
        tokio::spawn(async move { jsonrpc(rpc_addr, "waitfornewblock", json!([15_000])).await });
    let wait_height = tokio::spawn(async move {
        jsonrpc(rpc_addr, "waitforblockheight", json!([want_height, 15_000])).await
    });
    let lp_owned = lp.clone();
    let wait_gbt = tokio::spawn(async move {
        jsonrpc(
            rpc_addr,
            "getblocktemplate",
            json!([{"rules": ["segwit"], "longpollid": lp_owned}]),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    TipWaiters {
        wait_new,
        wait_height,
        wait_gbt,
        start_hash,
    }
}

impl TipWaiters {
    async fn assert_woke_on_new_tip(self, new_hash: &str, new_height: u64) {
        assert_ne!(self.start_hash, new_hash);
        let waited = tokio::time::timeout(Duration::from_secs(10), self.wait_new)
            .await
            .expect("waitfornewblock timed out")
            .expect("waitfornewblock join");
        assert_eq!(waited["result"]["hash"], new_hash, "{waited}");
        assert_eq!(waited["result"]["height"], new_height, "{waited}");
        let h = tokio::time::timeout(Duration::from_secs(10), self.wait_height)
            .await
            .expect("waitforblockheight timed out")
            .expect("waitforblockheight join");
        assert_eq!(h["result"]["hash"], new_hash, "{h}");
        assert_eq!(h["result"]["height"], new_height, "{h}");
        let gbt = tokio::time::timeout(Duration::from_secs(10), self.wait_gbt)
            .await
            .expect("gbt longpoll timed out")
            .expect("gbt longpoll join");
        let lp = gbt["result"]["longpollid"].as_str().unwrap_or("");
        assert!(
            lp.starts_with(new_hash),
            "current longpollid must wake on generate: {gbt}"
        );
    }
}

async fn esplora_json_array(esplora_addr: SocketAddr, path: &str) -> (u16, String, Vec<Value>) {
    let (st, body) = http_get(esplora_addr, path).await;
    let list = serde_json::from_str(&body).unwrap_or_default();
    (st, body, list)
}

/// B12: `/blocks` 10 newest; `/blocks/:start` at 0 and at tip.
async fn pin_esplora_blocks_summaries(esplora_addr: SocketAddr, tip_height: u64, tip_hash: &str) {
    let (st, body, list) = esplora_json_array(esplora_addr, "/blocks").await;
    assert_eq!(st, 200, "GET /blocks: {body}");
    assert_eq!(list.len(), 10, "10 newest: {body}");
    assert_eq!(list[0]["height"], tip_height, "{body}");
    assert_eq!(list[9]["height"], tip_height - 9, "{body}");

    let (st, body, from_zero) = esplora_json_array(esplora_addr, "/blocks/0").await;
    assert_eq!(st, 200, "GET /blocks/0: {body}");
    assert_eq!(from_zero.len(), 1, "{body}");
    assert_eq!(from_zero[0]["height"], 0, "{body}");

    let (st, body, from_tip) =
        esplora_json_array(esplora_addr, &format!("/blocks/{tip_height}")).await;
    assert_eq!(st, 200, "GET /blocks/{{tip}}: {body}");
    assert_eq!(from_tip.len(), 10, "{body}");
    assert_eq!(from_tip[0]["height"], tip_height, "{body}");
    assert_eq!(from_tip[0]["id"], tip_hash, "{body}");

    let (st, body, past) =
        esplora_json_array(esplora_addr, &format!("/blocks/{}", tip_height + 1)).await;
    assert_eq!(st, 200, "GET /blocks/{{tip+1}} clamps: {body}");
    assert_eq!(past, from_tip, "start past tip clamps to tip: {body}");
}

/// B12: `/block/:hash/txs/:start` last page shorter than 25; unknown hash 404.
async fn pin_esplora_block_txs_pages(esplora_addr: SocketAddr, tip_hash: &str, n_tx: usize) {
    let (st, body, page0) =
        esplora_json_array(esplora_addr, &format!("/block/{tip_hash}/txs/0")).await;
    assert_eq!(st, 200, "GET /txs/0: {body}");
    assert_eq!(page0.len(), 25, "first page is 25: {body}");

    let (st, body, last) =
        esplora_json_array(esplora_addr, &format!("/block/{tip_hash}/txs/25")).await;
    assert_eq!(st, 200, "GET /txs/25: {body}");
    assert_eq!(
        last.len(),
        n_tx.saturating_sub(25),
        "last page shorter than 25: {body}"
    );
    assert!(last.len() < 25 && !last.is_empty(), "last page: {body}");

    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}/txs/1")).await;
    assert_eq!(st, 400, "start not multiple of 25: {body}");
    let (st, body) = http_get(esplora_addr, &format!("/block/{}/txs/0", "00".repeat(32))).await;
    assert_eq!(st, 404, "unknown block txs: {body}");

    let next = u32::try_from((n_tx / 25 + 1) * 25).expect("txs start");
    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}/txs/{next}")).await;
    assert_eq!(st, 404, "one-past last page: {body}");
    assert!(
        body.contains("start index out of range"),
        "one-past last page: {body}"
    );
}

/// Extra Esplora HTTP leftover: txids, merkle-proof, coinbase outspend.
async fn pin_esplora_block_txids_merkle_and_outspend(
    esplora_addr: SocketAddr,
    tip_hash: &str,
    cb_txid: &str,
    n_tx: usize,
) {
    let (st, body, ids) =
        esplora_json_array(esplora_addr, &format!("/block/{tip_hash}/txids")).await;
    assert_eq!(st, 200, "GET /txids: {body}");
    assert_eq!(ids.len(), n_tx, "{body}");
    assert_eq!(ids[0].as_str(), Some(cb_txid), "{body}");

    let (st, body) = http_get(esplora_addr, &format!("/tx/{cb_txid}/merkle-proof")).await;
    assert_eq!(st, 200, "GET merkle-proof: {body}");
    let mp: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(mp["block_height"], 107, "{body}");
    assert_eq!(mp["pos"], 0, "{body}");
    assert!(mp.get("merkle").is_some(), "{body}");

    let (st, body) = http_get(esplora_addr, &format!("/tx/{cb_txid}/outspend/0")).await;
    assert_eq!(st, 200, "GET outspend: {body}");
    let os: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(os["spent"], false, "{body}");

    let (st, body, oss) =
        esplora_json_array(esplora_addr, &format!("/tx/{cb_txid}/outspends")).await;
    assert_eq!(st, 200, "GET outspends: {body}");
    assert!(!oss.is_empty(), "{body}");
    assert_eq!(oss[0]["spent"], false, "{body}");
}

async fn pin_esplora_block_json_raw_status(
    esplora_addr: SocketAddr,
    tip_hash: &str,
    parent_hash: &str,
    tip_height: u64,
    n_tx: usize,
) {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::Block;

    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}")).await;
    assert_eq!(st, 200, "block json {body}");
    let bj: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(bj["height"], tip_height, "{body}");
    assert_eq!(bj["id"], tip_hash, "{body}");
    assert_eq!(bj["tx_count"], n_tx, "{body}");
    assert!(bj["size"].as_u64().unwrap() > 80, "{body}");
    assert!(bj["weight"].as_u64().unwrap() > 0, "{body}");
    assert!(bj.get("difficulty").is_some(), "{body}");
    assert!(bj.get("mediantime").is_some(), "{body}");
    assert!(bj["bits"].is_u64(), "Esplora bits is u32: {}", bj["bits"]);
    assert_eq!(bj["previousblockhash"], parent_hash, "{body}");

    let (st, raw) = http_get_raw(esplora_addr, &format!("/block/{tip_hash}/raw")).await;
    assert_eq!(st, 200, "raw status");
    let block: Block = deserialize(&raw).expect("decode raw block");
    assert_eq!(block.txdata.len(), n_tx);
    assert!(raw.len() > 80);

    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}/status")).await;
    assert_eq!(st, 200, "{body}");
    let stj: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stj["in_best_chain"], true, "{body}");
    assert_eq!(stj["height"], tip_height, "{body}");
    assert!(stj["next_best"].is_null(), "tip has no next: {body}");

    let (st, body) = http_get(esplora_addr, &format!("/block/{parent_hash}/status")).await;
    assert_eq!(st, 200, "{body}");
    let pst: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(pst["next_best"], tip_hash, "{body}");
}

async fn pin_esplora_txid_raw_hex_merkleblock(
    esplora_addr: SocketAddr,
    tip_hash: &str,
    cb_txid: &str,
) {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::MerkleBlock;

    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}/txid/0")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body.trim(), cb_txid, "{body}");
    let (st, _) = http_get(esplora_addr, &format!("/block/{tip_hash}/txid/999")).await;
    assert_eq!(st, 404);

    let (st, body, txs) = esplora_json_array(esplora_addr, &format!("/block/{tip_hash}/txs")).await;
    assert_eq!(st, 200, "/txs no start: {body}");
    assert!(!txs.is_empty(), "{body}");
    assert!(txs[0].get("txid").is_some(), "{body}");

    let (st, raw_tx) = http_get_raw(esplora_addr, &format!("/tx/{cb_txid}/raw")).await;
    assert_eq!(st, 200);
    let (st, hex_body) = http_get(esplora_addr, &format!("/tx/{cb_txid}/hex")).await;
    assert_eq!(st, 200, "{hex_body}");
    let hex_bytes = rbitcoin_primitives::hex_decode(hex_body.trim()).unwrap();
    assert_eq!(raw_tx, hex_bytes);

    let (st, body) = http_get(esplora_addr, &format!("/tx/{cb_txid}/merkleblock-proof")).await;
    assert_eq!(st, 200, "{body}");
    let mb_bytes = rbitcoin_primitives::hex_decode(body.trim()).unwrap();
    let mb: MerkleBlock = deserialize(&mb_bytes).expect("merkleblock");
    let mut matches = Vec::new();
    let mut indexes = Vec::new();
    mb.extract_matches(&mut matches, &mut indexes).unwrap();
    assert_eq!(indexes, vec![0]);
    assert_eq!(matches.len(), 1);
}

async fn pin_esplora_block_height_and_header(
    esplora_addr: SocketAddr,
    tip_hash: &str,
    tip_height: u64,
) {
    let (st, body) = http_get(esplora_addr, &format!("/block-height/{tip_height}")).await;
    assert_eq!(st, 200, "block-height: {body}");
    assert_eq!(body.trim(), tip_hash, "{body}");
    let (st, _) = http_get(esplora_addr, "/block-height/999").await;
    assert_eq!(st, 404);

    let (st, body) = http_get(esplora_addr, &format!("/block/{tip_hash}/header")).await;
    assert_eq!(st, 200, "header: {body}");
    assert_eq!(body.trim().len(), 160, "{body}");
    let miss = "ff".repeat(32);
    let (st, _) = http_get(esplora_addr, &format!("/block/{miss}/header")).await;
    assert_eq!(st, 404);
}

async fn pin_esplora_tx_status(
    esplora_addr: SocketAddr,
    tip_hash: &str,
    cb_txid: &str,
    tip_height: u64,
) {
    let (st, body) = http_get(esplora_addr, &format!("/tx/{cb_txid}/status")).await;
    assert_eq!(st, 200, "tx status: {body}");
    let stj: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(stj["confirmed"], true, "{body}");
    assert_eq!(stj["block_height"], tip_height, "{body}");
    assert_eq!(stj["block_hash"], tip_hash, "{body}");
    assert!(stj.get("block_time").is_some(), "{body}");

    let miss = "ff".repeat(32);
    let (st, _) = http_get(esplora_addr, &format!("/tx/{miss}/hex")).await;
    assert_eq!(st, 404);
    let (st, _) = http_get(esplora_addr, &format!("/tx/{miss}/status")).await;
    assert_eq!(st, 404);
    let (st, _) = http_get(esplora_addr, &format!("/tx/{miss}")).await;
    assert_eq!(st, 404);
}

async fn pin_esplora_tx_json_unknown_coinbase(esplora_addr: SocketAddr, cb_txid: &str) {
    let (st, body) = http_get(esplora_addr, &format!("/tx/{cb_txid}")).await;
    assert_eq!(st, 200, "tx json: {body}");
    let full: Value = serde_json::from_str(&body).unwrap();
    assert!(full.get("txid").is_some(), "{body}");
    assert!(full.get("vin").is_some(), "{body}");
    assert!(full.get("vout").is_some(), "{body}");
    assert!(full.get("status").is_some(), "{body}");
    assert_eq!(full["fee"], 0, "{body}");
    let v0 = &full["vout"][0];
    assert!(v0.get("scriptpubkey").is_some(), "{body}");
    assert!(v0.get("scriptpubkey_asm").is_some(), "{body}");
    assert_eq!(v0["scriptpubkey_type"], "unknown", "{body}");
    assert!(
        v0["scriptpubkey_asm"].as_str().unwrap().contains("OP_"),
        "{body}"
    );
    assert_eq!(full["vin"][0]["is_coinbase"], true, "{body}");
    assert!(full["vin"][0].get("scriptsig_asm").is_some(), "{body}");
    assert!(full.get("sigops").is_some(), "tx JSON sigops: {body}");
}

#[allow(clippy::cognitive_complexity)] // one SH surface pin table
async fn pin_esplora_scripthash_pages(esplora_addr: SocketAddr) {
    use rbitcoin_primitives::display_hash_hex;
    use rbitcoin_store::script_hash;

    let sh_hex = display_hash_hex(&script_hash(&[0x51]));
    let (st, body) = http_get(esplora_addr, &format!("/scripthash/{sh_hex}")).await;
    assert_eq!(st, 200, "{body}");
    let info: Value = serde_json::from_str(&body).unwrap();
    assert!(
        info["chain_stats"]["tx_count"].as_u64().unwrap() >= 1,
        "{body}"
    );
    assert!(
        info["chain_stats"]["funded_txo_count"].as_u64().unwrap() >= 1,
        "{body}"
    );

    let (st, body, sum) =
        esplora_json_array(esplora_addr, &format!("/scripthash/{sh_hex}/txs/summary")).await;
    assert_eq!(st, 200, "{body}");
    assert!(!sum.is_empty(), "{body}");
    assert!(sum[0].get("txid").is_some(), "{body}");
    assert!(sum[0].get("value").is_some(), "{body}");
    assert!(sum[0].get("height").is_some(), "{body}");
    assert!(sum[0].get("time").is_some(), "{body}");

    let (st, body, utxos) =
        esplora_json_array(esplora_addr, &format!("/scripthash/{sh_hex}/utxo")).await;
    assert_eq!(st, 200, "{body}");
    assert!(!utxos.is_empty(), "{body}");

    let (st, body, page1) =
        esplora_json_array(esplora_addr, &format!("/scripthash/{sh_hex}/txs/chain")).await;
    assert_eq!(st, 200, "{body}");
    assert!(!page1.is_empty(), "{body}");
    assert!(page1.len() <= 25, "{body}");
    let last = page1[0]["txid"]
        .as_str()
        .expect("chain page txid")
        .to_string();
    let (st, body, page2) = esplora_json_array(
        esplora_addr,
        &format!("/scripthash/{sh_hex}/txs/chain/{last}"),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert!(
        page2.iter().all(|row| row["txid"] != last),
        "cursor page must omit {last}: {body}"
    );

    let (st, body, combined) =
        esplora_json_array(esplora_addr, &format!("/scripthash/{sh_hex}/txs")).await;
    assert_eq!(st, 200, "{body}");
    assert!(!combined.is_empty(), "{body}");
    pin_esplora_after_txid_and_post_multi(esplora_addr, &sh_hex, &combined).await;
}

async fn pin_esplora_after_txid_and_post_multi(
    esplora_addr: SocketAddr,
    sh_hex: &str,
    combined: &[Value],
) {
    let newest = combined[0]["txid"]
        .as_str()
        .expect("combined txid")
        .to_string();
    let (st, body, after) = esplora_json_array(
        esplora_addr,
        &format!("/scripthash/{sh_hex}/txs?after_txid={newest}"),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert!(
        after.iter().all(|row| row["txid"] != newest),
        "after_txid must omit {newest}: {body}"
    );
    let payload = serde_json::to_string(&json!([sh_hex])).unwrap();
    let (st, body) = http_post_json(esplora_addr, "/scripthashes/txs", &payload).await;
    assert_eq!(st, 200, "POST /scripthashes/txs: {body}");
    let posted: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert!(!posted.is_empty(), "{body}");
}

fn encode_tx(tx: &Transaction) -> String {
    let mut raw = Vec::new();
    tx.consensus_encode(&mut raw).unwrap();
    rbitcoin_primitives::hex_encode(&raw)
}

fn acs_spend(prev: Txid, input_sat: u64, fee: u64, spk: ScriptBuf) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(input_sat - fee),
            script_pubkey: spk,
        }],
    }
}

fn tx_wu(tx: &Transaction) -> u64 {
    tx.weight().to_wu()
}

fn min_relay_fee_sat(weight: u64) -> u64 {
    let vsize = rbitcoin_consensus::policy::get_virtual_size(weight);
    vsize
        .saturating_mul(rbitcoin_consensus::policy::MIN_RELAY_FEE_RATE_SAT_PER_KVB)
        .saturating_add(999)
        / 1000
}

fn incremental_rbf_fee_sat(weight: u64) -> u64 {
    min_relay_fee_sat(weight)
}

fn op_return_output(data_len: usize) -> TxOut {
    let mut script = Vec::with_capacity(6 + data_len);
    script.push(0x6a);
    script.push(0x4e);
    script.extend_from_slice(&(data_len as u32).to_le_bytes());
    script.resize(script.len() + data_len, 0x61);
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn pad_tx_to_weight(mut tx: Transaction, want: u64) -> Transaction {
    let base = tx_wu(&tx);
    if base >= want {
        return tx;
    }
    let mut lo = 0usize;
    let mut hi = 80_000usize;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let mut probe = tx.clone();
        probe.output.push(op_return_output(mid));
        if tx_wu(&probe) < want {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    tx.output.push(op_return_output(lo));
    while lo > 0 && tx_wu(&tx) > want {
        lo -= 1;
        tx.output.pop();
        tx.output.push(op_return_output(lo));
    }
    tx
}

fn mempool_has(mem: &Value, txid: &str) -> bool {
    mem["result"]
        .as_array()
        .expect("getrawmempool array")
        .iter()
        .any(|v| v.as_str() == Some(txid))
}

fn pin_mined_parent_before_child(txs: &[Value], parent: &str, child: &str) {
    let ids: Vec<&str> = txs.iter().filter_map(|t| t["txid"].as_str()).collect();
    let p = ids
        .iter()
        .position(|t| *t == parent)
        .unwrap_or_else(|| panic!("mined block missing parent {parent}: {ids:?}"));
    let c = ids
        .iter()
        .position(|t| *t == child)
        .unwrap_or_else(|| panic!("mined block missing child {child}: {ids:?}"));
    assert!(
        p < c,
        "generate must select parent before child ({parent} @{p}, {child} @{c}): {ids:?}"
    );
}

fn rest_json(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

async fn pin_rest_chaininfo_and_blockhash(rpc_addr: SocketAddr, tip: &str, height: u64) {
    let (st, body) = http_get(rpc_addr, "/rest/chaininfo.json").await;
    assert_eq!(st, 200, "{body}");
    let info = rest_json(&body);
    assert_eq!(info["chain"], "regtest", "{info}");
    assert_eq!(info["blocks"], height, "{info}");

    let (st, body) = http_get(rpc_addr, &format!("/rest/blockhashbyheight/{height}.json")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(rest_json(&body)["blockhash"], tip, "{body}");
    let (st, hex) = http_get(rpc_addr, &format!("/rest/blockhashbyheight/{height}.hex")).await;
    assert_eq!((st, hex.as_str()), (200, tip), "{hex}");
    let (st, raw) = http_get_raw(rpc_addr, &format!("/rest/blockhashbyheight/{height}.bin")).await;
    assert_eq!(st, 200, "blockhash bin status");
    assert_eq!(raw.len(), 32, "blockhash bin");
    let (st, body) = http_get(rpc_addr, "/rest/blockhashbyheight/9999999.json").await;
    assert_eq!(st, 404, "{body}");
}

async fn pin_rest_headers(rpc_addr: SocketAddr) {
    let (st, body) = http_get(rpc_addr, "/rest/blockhashbyheight/0.json").await;
    assert_eq!(st, 200, "{body}");
    let genesis = rest_json(&body)["blockhash"]
        .as_str()
        .expect("genesis blockhash")
        .to_string();
    let (st, body) = http_get(rpc_addr, &format!("/rest/headers/3/{genesis}.json")).await;
    assert_eq!(st, 200, "{body}");
    let hdrs = rest_json(&body);
    let n = hdrs.as_array().map(|a| a.len()).unwrap_or(0);
    assert_eq!(n, 3, "{hdrs}");
    let (st, hex) = http_get(rpc_addr, &format!("/rest/headers/2/{genesis}.hex")).await;
    assert_eq!(st, 200, "{hex}");
    assert_eq!(hex.len(), 320, "two headers as hex");
    let (st, raw) = http_get_raw(rpc_addr, &format!("/rest/headers/2/{genesis}.bin")).await;
    assert_eq!((st, raw.len()), (200, 160), "two headers as bin");
}

async fn pin_rest_block_and_tx(rpc_addr: SocketAddr, tip: &str, txid: &str) {
    let (st, body) = http_get(rpc_addr, &format!("/rest/block/{tip}.json")).await;
    assert_eq!(st, 200, "{body}");
    let blk = rest_json(&body);
    assert_eq!(blk["hash"], tip, "{blk}");
    let ntx = blk["tx"].as_array().map(|a| a.len()).unwrap_or(0);
    assert!(ntx > 1, "{blk}");
    let (st, body) = http_get(rpc_addr, &format!("/rest/block/notxdetails/{tip}.json")).await;
    assert_eq!(st, 200, "{body}");
    let brief = rest_json(&body);
    assert!(brief["tx"][0].is_string(), "verbosity 1 txids: {brief}");
    let (st, hex) = http_get(rpc_addr, &format!("/rest/block/{tip}.hex")).await;
    assert_eq!(st, 200);
    assert!(hex.len() > 160, "block hex");
    let (st, raw) = http_get_raw(rpc_addr, &format!("/rest/block/{tip}.bin")).await;
    assert_eq!(st, 200);
    assert!(raw.len() > 80, "block bin");
    let (st, body) = http_get(
        rpc_addr,
        "/rest/block/0000000000000000000000000000000000000000000000000000000000000000.json",
    )
    .await;
    assert_eq!(st, 404, "{body}");

    let (st, body) = http_get(rpc_addr, &format!("/rest/tx/{txid}.json")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(rest_json(&body)["txid"], txid, "{body}");
    let (st, hex) = http_get(rpc_addr, &format!("/rest/tx/{txid}.hex")).await;
    assert_eq!(st, 200);
    assert!(!hex.is_empty(), "tx hex");
    let (st, raw) = http_get_raw(rpc_addr, &format!("/rest/tx/{txid}.bin")).await;
    assert_eq!(st, 200);
    assert!(!raw.is_empty(), "tx bin");
}

async fn pin_rest_mempool_and_utxos(rpc_addr: SocketAddr, height: u64, txid: &str) {
    let (st, body) = http_get(rpc_addr, "/rest/mempool/info.json").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        rest_json(&body)["size"],
        0,
        "generate emptied the pool: {body}"
    );
    let (st, body) = http_get(rpc_addr, "/rest/mempool/contents.json").await;
    assert_eq!(st, 200, "{body}");
    let n = rest_json(&body).as_object().map(|o| o.len()).unwrap_or(1);
    assert_eq!(n, 0, "{body}");
    let (st, body) = http_get(rpc_addr, "/rest/mempool/contents.json?verbose=false").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(rest_json(&body), json!([]), "{body}");
    let (st, body) = http_get(
        rpc_addr,
        "/rest/mempool/contents.json?verbose=false&mempool_sequence=true",
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let (st, body) = http_get(
        rpc_addr,
        "/rest/mempool/contents.json?verbose=true&mempool_sequence=true",
    )
    .await;
    assert_eq!(st, 400, "{body}");
    let (st, body) = http_get(rpc_addr, "/rest/mempool/nope.json").await;
    assert_eq!(st, 400, "{body}");

    let (st, body) = http_get(rpc_addr, &format!("/rest/getutxos/{txid}-0.json")).await;
    assert_eq!(st, 200, "{body}");
    let utxo = rest_json(&body);
    assert_eq!(utxo["chainHeight"], height, "{utxo}");
    assert_eq!(utxo["bitmap"], "1", "coinbase output is unspent: {utxo}");
    let (st, body) = http_get(
        rpc_addr,
        &format!("/rest/getutxos/checkmempool/{txid}-0.json"),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let (st, body) = http_get(rpc_addr, &format!("/rest/getutxos/{txid}-0.hex")).await;
    assert_eq!(st, 404, "{body}");
}

async fn pin_rest_deployment_and_filter(rpc_addr: SocketAddr, tip: &str) {
    let (st, body) = http_get(rpc_addr, "/rest/deploymentinfo.json").await;
    assert_eq!(st, 200, "{body}");
    assert!(rest_json(&body)["deployments"].is_object(), "{body}");
    let (st, body) = http_get(rpc_addr, &format!("/rest/deploymentinfo/{tip}.json")).await;
    assert_eq!(st, 200, "{body}");

    let filt = jsonrpc(rpc_addr, "getblockfilter", json!([tip])).await;
    let filter_hex = filt["result"]["filter"]
        .as_str()
        .unwrap_or_else(|| panic!("getblockfilter: {filt}"))
        .to_string();
    assert!(!filter_hex.is_empty(), "{filt}");
    // Filters reached the tip: new peers now hear NODE_COMPACT_FILTERS.
    let mut names = json!(null);
    for _ in 0..100 {
        names = jsonrpc(rpc_addr, "getnetworkinfo", json!([])).await["result"]
            ["localservicesnames"]
            .clone();
        if names
            .as_array()
            .is_some_and(|a| a.iter().any(|n| n == "COMPACT_FILTERS"))
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        names
            .as_array()
            .is_some_and(|a| a.iter().any(|n| n == "COMPACT_FILTERS")),
        "advertised once filters caught up: {names}"
    );
    let (st, body) = http_get(rpc_addr, &format!("/rest/blockfilter/basic/{tip}.json")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(rest_json(&body)["filter"], filter_hex, "{body}");
    let (st, hex) = http_get(rpc_addr, &format!("/rest/blockfilter/basic/{tip}.hex")).await;
    assert_eq!(st, 200);
    assert!(hex.starts_with("00"), "type byte 0: {hex}");
    let (st, raw) = http_get_raw(rpc_addr, &format!("/rest/blockfilter/basic/{tip}.bin")).await;
    assert_eq!(st, 200);
    assert_eq!(raw.first().copied(), Some(0), "filter bin type");
    let (st, body) = http_get(rpc_addr, &format!("/rest/blockfilter/unknown/{tip}.json")).await;
    assert_eq!(st, 400, "{body}");
}

async fn pin_scantxoutset_drops_spent_coinbase(rpc_addr: SocketAddr, spent_cb: &str) {
    let scan = jsonrpc(rpc_addr, "scantxoutset", json!(["start", ["raw(51)"]])).await;
    assert_eq!(scan["result"]["success"], true, "{scan}");
    let uns = scan["result"]["unspents"]
        .as_array()
        .expect("scantxoutset unspents");
    assert!(
        uns.iter().all(|u| u["txid"].as_str() != Some(spent_cb)),
        "spent coinbase must drop from scan: {scan}"
    );
    assert!(
        uns.iter().any(|u| u["coinbase"] == false),
        "scan must still see a non-coinbase unspent: {scan}"
    );
    let xpub = "pkh(tpubD6NzVbkrYhZ4XgiXtGrdW5XDAPFCL9h7we1vwNCpn8tGbBcgfVYjXyhWo4E1xkh56hjod1RhGjxbaTLV3X4FyWuejifB9jusQ46QzG87VKp/0/*)";
    let ranged = jsonrpc(
        rpc_addr,
        "scantxoutset",
        json!(["start", [{"desc": xpub, "range": 1}]]),
    )
    .await;
    assert_eq!(ranged["result"]["success"], true, "{ranged}");
    let hardened = "pkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/*h)";
    let hard = jsonrpc(
        rpc_addr,
        "scantxoutset",
        json!(["start", [{"desc": hardened, "range": 0}]]),
    )
    .await;
    assert_eq!(hard["result"]["success"], true, "{hard}");
}

async fn electrum_rpc(stream: &mut TcpStream, id: u64, method: &str, params: Value) -> Value {
    let req = json!({"jsonrpc":"2.0","id": id, "method": method, "params": params});
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    stream.write_all(line.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(&mut *stream);
    let mut resp_line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut resp_line))
        .await
        .unwrap_or_else(|_| panic!("electrum {method}: read_line timed out"))
        .unwrap_or_else(|e| panic!("electrum {method}: io {e}"));
    serde_json::from_str(&resp_line).unwrap()
}

/// True when `height` is a snapshot row, a snapshot hash, or a journal record.
///
/// Preload rewrites `fee_history` and truncates `fee_history.log` to its
/// header. A later connect appends one 52-byte record. When the previous run
/// already journaled a record of that size, the sum of the two files stays
/// put while the height moves.
fn fee_history_has_height(dir: &std::path::Path, height: u32) -> bool {
    fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        let end = at.checked_add(4)?;
        Some(u32::from_le_bytes(b.get(at..end)?.try_into().ok()?))
    }
    let snap = std::fs::read(dir.join("fee_history")).unwrap_or_default();
    if snap.len() >= 16 && &snap[..4] == b"RBFH" {
        if let (Some(count), Some(n_hashes)) = (u32_at(&snap, 8), u32_at(&snap, 12)) {
            let rows = (count as usize).min(snap.len().saturating_sub(16) / 16);
            let row_bytes = rows * 16;
            for i in 0..rows {
                if u32_at(&snap, 16 + i * 16) == Some(height) {
                    return true;
                }
            }
            let hash_base = 16 + row_bytes;
            let hashes = (n_hashes as usize).min(snap.len().saturating_sub(hash_base) / 36);
            for i in 0..hashes {
                if u32_at(&snap, hash_base + i * 36) == Some(height) {
                    return true;
                }
            }
        }
    }
    let journal = std::fs::read(dir.join("fee_history.log")).unwrap_or_default();
    if journal.len() >= 16 && &journal[..4] == b"RBFJ" {
        let mut at = 16;
        while at + 52 <= journal.len() {
            if u32_at(&journal, at) == Some(height) {
                return true;
            }
            at += 52;
        }
    }
    false
}

/// A node that leaves IBD with relay on preloads fee history from the chain
/// and keeps it in the mempool dir (snapshot plus per-connect journal), and a
/// restart preloads again on top of that file. With flow cold and too little history for any target,
/// `estimatesmartfee` says so rather than guessing from a thin pool. Rates
/// from a ready history are pinned on the hub
/// (`far_horizon_follows_block_history_not_pool_tail`): a ready 144-block
/// target needs ~2200 fee-paying blocks, ~40 s to build in a debug test.
#[tokio::test(flavor = "multi_thread")]
async fn fee_history_backfills_from_the_chain_when_relay_starts() {
    let td = TestDatadir::new().unwrap();
    let params = ChainParams::regtest();
    {
        let q = Query::open_or_create_tiny(td.store_path()).unwrap();
        build_mature_regtest_with_spend(&q, &params);
        q.flush().unwrap();
    }
    std::fs::write(td.path().join("rpc.token"), "pass").unwrap();
    let mempool_dir = td.path().join("mempool");
    for run in ["first start", "restart"] {
        let rpc_addr = ephemeral_addr();
        let mut cfg = NodeConfig::default()
            .with_datadir(td.path())
            .with_network(Network::Regtest)
            .with_tiny_heads()
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.rpc.listen = Some(rpc_addr);
        cfg.max_run_secs = Some(60);
        let node = tokio::spawn(run_p2p(cfg));
        wait_listeners(&[rpc_addr]).await;

        // A fresh tip leaves IBD and turns relay on (a restart is already
        // out of IBD). The new height is in the snapshot or the journal.
        let mined = jsonrpc(rpc_addr, "generate", json!([1])).await;
        assert!(mined["result"].is_array(), "{run}: {mined}");
        let count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
        let tip = u32::try_from(
            count["result"]
                .as_u64()
                .unwrap_or_else(|| panic!("{run}: {count}")),
        )
        .unwrap_or_else(|_| panic!("{run}: {count}"));
        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = loop {
            if fee_history_has_height(&mempool_dir, tip) || Instant::now() > deadline {
                break fee_history_has_height(&mempool_dir, tip);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(seen, "{run}: fee history missing height {tip}");

        let fee = jsonrpc(rpc_addr, "estimatesmartfee", json!([2])).await;
        assert!(fee["result"].get("feerate").is_none(), "{run}: {fee}");
        assert_eq!(
            fee["result"]["errors"][0], "Insufficient data or no feerate found",
            "{run}: {fee}"
        );
        assert_eq!(fee["result"]["blocks"], 2, "{run}: {fee}");

        let _ = jsonrpc(rpc_addr, "stop", json!([])).await;
        let stopped = tokio::time::timeout(Duration::from_secs(15), node).await;
        assert!(
            matches!(stopped, Ok(Ok(Ok(())))),
            "{run}: run_p2p did not stop cleanly"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn esplora_broadcast_visible_in_rpc_and_electrum() {
    let td = TestDatadir::new().unwrap();
    let params = ChainParams::regtest();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let (coinbase_txid, rpc_cb, pkg_cb, exact_cb, chain_cb, cpfp_cb, relay_cb, rpc_cpfp_cb) = {
        let q = Query::open_or_create_tiny(td.store_path()).unwrap();
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _time, cbs) = pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            106,
            8,
        );
        q.flush().unwrap();
        (
            cbs[0], cbs[1], cbs[2], cbs[3], cbs[4], cbs[5], cbs[6], cbs[7],
        )
    };

    let electrum_addr = ephemeral_addr();
    let esplora_addr = ephemeral_addr();
    let rpc_addr = ephemeral_addr();
    let health_addr = ephemeral_addr();

    let mut cfg = NodeConfig::default()
        .with_datadir(td.path())
        .with_network(Network::Regtest)
        .with_tiny_heads()
        .with_p2p_listen("127.0.0.1:0".parse().unwrap());
    cfg.listen.use_seeds = false;
    cfg.listen.connect.clear();
    cfg.shindex = true;
    cfg.block_filter_index = true;
    cfg.listen.electrum = Some(electrum_addr);
    cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora_addr));
    cfg.rpc.listen = Some(rpc_addr);
    cfg.listen.health = Some(health_addr);
    cfg.metrics = true;
    // mempool's CORE_RPC.SOCKET_PATH reaches the node from another user.
    let rpc_sock = td.path().join("run").join("rpc.sock");
    cfg.apply_kv("rpc_socket", rpc_sock.to_str().unwrap())
        .unwrap();
    std::fs::write(td.path().join("rpc.token"), "pass").unwrap();
    cfg.max_run_secs = Some(90);

    let node = tokio::spawn(run_p2p(cfg));
    wait_listeners(&[electrum_addr, esplora_addr, rpc_addr, health_addr]).await;
    pin_healthz(health_addr).await;
    pin_address_prefix_404(esplora_addr).await;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        wait_unix_socket(&rpc_sock).await;
        let mode = std::fs::metadata(&rpc_sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o660,
            "--rpc-socket is group-accessible, got {mode:o}"
        );
        assert!(!td.path().join("rpc.sock").exists(), "no datadir rpc.sock");
        let unix_count = jsonrpc_unix(&rpc_sock, "getblockcount", json!([])).await;
        assert_eq!(
            unix_count["result"], 106,
            "unix --rpc-socket getblockcount without Authorization: {unix_count}"
        );
    }

    let (st, height) = http_get(esplora_addr, "/blocks/tip/height").await;
    assert_eq!(st, 200, "esplora tip height: {height}");
    assert_eq!(height, "106");
    let count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
    assert_eq!(count["result"], 106, "{count}");
    let chain = jsonrpc(rpc_addr, "getblockchaininfo", json!([])).await;
    assert_eq!(chain["result"]["initialblockdownload"], true, "{chain}");
    assert_eq!(
        readyz_after_startup(health_addr).await,
        (503, "not ready: initial block download".into()),
        "/readyz agrees with RPC initialblockdownload"
    );
    let mpinfo = jsonrpc(rpc_addr, "getmempoolinfo", json!([])).await;
    assert_eq!(mpinfo["result"]["relay_enabled"], false, "{mpinfo}");
    let tips = jsonrpc(rpc_addr, "getchaintips", json!([])).await;
    assert_eq!(tips["result"][0]["height"], 106, "{tips}");
    assert_eq!(tips["result"][0]["status"], "active", "{tips}");
    let cb_hex = coinbase_txid.to_string();
    let utxo = jsonrpc(rpc_addr, "gettxout", json!([cb_hex.clone(), 0])).await;
    assert_eq!(utxo["result"]["coinbase"], true, "{utxo}");
    assert_eq!(utxo["result"]["confirmations"], 106, "{utxo}");

    let rpc_spk = ScriptBuf::from_bytes(vec![0x54]);
    let rpc_spend = acs_spend(rpc_cb, 50_0000_0000, 1_000, rpc_spk);
    let rpc_hex = encode_tx(&rpc_spend);
    let rpc_txid = rpc_spend.compute_txid().to_string();
    let rpc_wu = tx_wu(&rpc_spend);
    let exact_min = min_relay_fee_sat(rpc_wu);
    assert!(exact_min > 0, "acs_spend vsize must need a positive floor");
    let under_min = acs_spend(
        exact_cb,
        50_0000_0000,
        exact_min - 1,
        ScriptBuf::from_bytes(vec![0x4f]),
    );
    let tma = jsonrpc(
        rpc_addr,
        "testmempoolaccept",
        json!([[encode_tx(&under_min)]]),
    )
    .await;
    assert_eq!(tma["result"][0]["allowed"], false, "{tma}");
    assert_eq!(
        tma["result"][0]["reject-reason"], "min relay fee not met",
        "{tma}"
    );
    let at_min = acs_spend(
        exact_cb,
        50_0000_0000,
        exact_min,
        ScriptBuf::from_bytes(vec![0x4e]),
    );
    let at_min_hex = encode_tx(&at_min);
    let at_min_txid = at_min.compute_txid().to_string();
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[at_min_hex.clone()]])).await;
    assert_eq!(
        tma["result"][0]["allowed"], true,
        "exact 100 sat/kvB must meet min-relay: {tma}"
    );
    let sent_min = jsonrpc(rpc_addr, "sendrawtransaction", json!([at_min_hex])).await;
    assert_eq!(sent_min["result"], at_min_txid, "{sent_min}");
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[rpc_hex.clone()]])).await;
    assert_eq!(tma["result"][0]["allowed"], true, "{tma}");
    let sent = jsonrpc(rpc_addr, "sendrawtransaction", json!([rpc_hex])).await;
    assert_eq!(sent["result"], rpc_txid, "{sent}");
    let mem_utxo = jsonrpc(rpc_addr, "gettxout", json!([rpc_txid.clone(), 0])).await;
    assert_eq!(mem_utxo["result"]["confirmations"], 0, "{mem_utxo}");
    assert_eq!(mem_utxo["result"]["coinbase"], false, "{mem_utxo}");
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &rpc_txid),
        "getrawmempool missing sendraw {rpc_txid}: {mem}"
    );
    let miss = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x11; 32]),
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
    let mut miss_raw = Vec::new();
    miss.consensus_encode(&mut miss_raw).unwrap();
    let miss_hex = rbitcoin_primitives::hex_encode(&miss_raw);
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[miss_hex]])).await;
    assert_eq!(tma["result"][0]["allowed"], false, "{tma}");
    assert_eq!(tma["result"][0]["reject-reason"], "missing-inputs", "{tma}");

    let spk = ScriptBuf::from_bytes(vec![0x52]);
    let spend = acs_spend(coinbase_txid, 50_0000_0000, 1_000, spk.clone());
    let hex = encode_tx(&spend);
    let txid_hex = spend.compute_txid().to_string();

    let (st, body) = http_post(esplora_addr, "/tx", &hex).await;
    assert_eq!(st, 200, "POST /tx: {body}");
    assert_eq!(body, txid_hex);
    let (st, body) = http_get(esplora_addr, &format!("/broadcast?tx={hex}")).await;
    assert_eq!(st, 400, "GET /broadcast of live tx: {body}");
    assert!(body.contains("duplicate"), "{body}");
    let (st, body) = http_get(esplora_addr, &format!("/txs/outspends?txids={cb_hex}")).await;
    assert_eq!(st, 200, "GET /txs/outspends: {body}");
    let outspends: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(outspends[0][0]["spent"], true, "{body}");
    let hidden = jsonrpc(rpc_addr, "gettxout", json!([cb_hex.clone(), 0])).await;
    assert!(
        hidden["result"].is_null(),
        "default include_mempool hides mempool-spent coinbase: {hidden}"
    );
    let shown = jsonrpc(rpc_addr, "gettxout", json!([cb_hex, 0, false])).await;
    assert_eq!(shown["result"]["coinbase"], true, "{shown}");
    let dup = jsonrpc(rpc_addr, "sendrawtransaction", json!([hex.clone()])).await;
    assert_eq!(dup["result"], txid_hex, "sendraw of live mempool tx: {dup}");

    let (st, status) = http_get(esplora_addr, &format!("/tx/{txid_hex}/status")).await;
    assert_eq!(st, 200, "GET /tx status: {status}");
    let status_v: Value = serde_json::from_str(&status).unwrap();
    assert_eq!(status_v["confirmed"], false, "{status_v}");

    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &txid_hex),
        "getrawmempool missing {txid_hex}: {mem}"
    );
    assert!(
        mempool_has(&mem, &rpc_txid),
        "getrawmempool dropped sendraw {rpc_txid}: {mem}"
    );

    let sh = electrum_scripthash_hex(spk.as_bytes());
    let mut el = TcpStream::connect(electrum_addr).await.unwrap();
    let _ = electrum_rpc(&mut el, 1, "server.version", json!(["test", "1.4"])).await;
    let mempool = electrum_rpc(&mut el, 2, "blockchain.scripthash.get_mempool", json!([sh])).await;
    let mem_rows = mempool["result"].as_array().expect("get_mempool array");
    let mem_row = mem_rows
        .iter()
        .find(|r| r["tx_hash"] == txid_hex)
        .unwrap_or_else(|| panic!("get_mempool missing {txid_hex}: {mempool}"));
    let fee = mem_row["fee"].as_i64().expect("get_mempool fee");
    assert!(fee > 0, "get_mempool fee: {mem_row}");

    let hist = electrum_rpc(&mut el, 3, "blockchain.scripthash.get_history", json!([sh])).await;
    let hist_row = hist["result"]
        .as_array()
        .expect("get_history array")
        .iter()
        .find(|r| r["tx_hash"] == txid_hex)
        .unwrap_or_else(|| panic!("get_history missing {txid_hex}: {hist}"));
    assert_eq!(hist_row["fee"].as_i64(), Some(fee), "{hist_row}");
    for row in hist["result"].as_array().unwrap() {
        if row["tx_hash"] == txid_hex {
            assert!(row.get("fee").is_some(), "unconfirmed history fee: {row}");
        } else {
            assert!(
                row.get("fee").is_none(),
                "confirmed history omits fee: {row}"
            );
        }
    }

    let child_spk = ScriptBuf::from_bytes(vec![0x53]);
    let child = acs_spend(
        spend.compute_txid(),
        50_0000_0000 - 1_000,
        1_000,
        child_spk.clone(),
    );
    let child_hex = encode_tx(&child);
    let child_txid = child.compute_txid().to_string();
    let test_body = serde_json::to_string(&json!([child_hex.clone()])).unwrap();
    let (st, body) = http_post_json(esplora_addr, "/txs/test", &test_body).await;
    assert_eq!(st, 200, "POST /txs/test: {body}");
    let tested: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(tested[0]["allowed"], true, "{body}");
    let mem_before_child = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        !mempool_has(&mem_before_child, &child_txid),
        "test_accept must not admit: {mem_before_child}"
    );
    let (st, body) = http_post(esplora_addr, "/tx", &child_hex).await;
    assert_eq!(st, 200, "POST /tx child: {body}");
    assert_eq!(body, child_txid);

    let child_sh = electrum_scripthash_hex(child_spk.as_bytes());
    let child_hist = electrum_rpc(
        &mut el,
        4,
        "blockchain.scripthash.get_history",
        json!([child_sh.clone()]),
    )
    .await;
    let child_row = child_hist["result"]
        .as_array()
        .expect("child history array")
        .iter()
        .find(|r| r["tx_hash"] == child_txid)
        .unwrap_or_else(|| panic!("child history missing {child_txid}: {child_hist}"));
    assert_eq!(child_row["height"], -1, "{child_row}");
    let child_fee = child_row["fee"].as_i64().expect("mempool child fee");
    assert!(child_fee > 0, "mempool child fee: {child_row}");
    let child_utxo = electrum_rpc(
        &mut el,
        24,
        "blockchain.scripthash.listunspent",
        json!([child_sh.clone()]),
    )
    .await;
    let utxo_row = child_utxo["result"]
        .as_array()
        .expect("child listunspent array")
        .iter()
        .find(|r| r["tx_hash"] == child_txid)
        .unwrap_or_else(|| panic!("listunspent missing child {child_txid}: {child_utxo}"));
    assert_eq!(utxo_row["height"], -1, "{utxo_row}");
    let parent_utxo = electrum_rpc(
        &mut el,
        25,
        "blockchain.scripthash.listunspent",
        json!([sh]),
    )
    .await;
    assert!(
        parent_utxo["result"]
            .as_array()
            .expect("parent listunspent")
            .iter()
            .all(|r| r["tx_hash"] != txid_hex),
        "child spend must drop the parent UTXO: {parent_utxo}"
    );

    let child_mem = electrum_rpc(
        &mut el,
        5,
        "blockchain.scripthash.get_mempool",
        json!([child_sh]),
    )
    .await;
    let child_mem_row = child_mem["result"]
        .as_array()
        .expect("child mempool array")
        .iter()
        .find(|r| r["tx_hash"] == child_txid)
        .unwrap_or_else(|| panic!("get_mempool missing child {child_txid}: {child_mem}"));
    assert_eq!(
        child_mem_row["fee"].as_i64(),
        Some(child_fee),
        "{child_mem_row}"
    );

    let inc = incremental_rbf_fee_sat(rpc_wu);
    assert!(inc >= 1, "replacement must owe a positive incremental fee");
    let low = acs_spend(
        rpc_cb,
        50_0000_0000,
        1_000,
        ScriptBuf::from_bytes(vec![0x55]),
    );
    let low_hex = encode_tx(&low);
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[low_hex.clone()]])).await;
    assert_eq!(tma["result"][0]["allowed"], false, "{tma}");
    assert_eq!(
        tma["result"][0]["reject-reason"], "insufficient fee",
        "{tma}"
    );
    let short = acs_spend(
        rpc_cb,
        50_0000_0000,
        1_000 + inc - 1,
        ScriptBuf::from_bytes(vec![0x50]),
    );
    assert_eq!(tx_wu(&short), rpc_wu, "RBF pair must share vsize");
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[encode_tx(&short)]])).await;
    assert_eq!(tma["result"][0]["allowed"], false, "{tma}");
    assert_eq!(
        tma["result"][0]["reject-reason"], "insufficient fee",
        "one sat short of incremental relay: {tma}"
    );
    let rejected = jsonrpc(rpc_addr, "sendrawtransaction", json!([low_hex])).await;
    assert_eq!(rejected["error"]["code"], -26, "{rejected}");
    assert_eq!(
        rejected["error"]["message"], "insufficient fee",
        "{rejected}"
    );
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &rpc_txid),
        "too-low RBF must leave the original: {mem}"
    );

    let high = acs_spend(
        rpc_cb,
        50_0000_0000,
        1_000 + inc,
        ScriptBuf::from_bytes(vec![0x56]),
    );
    assert_eq!(tx_wu(&high), rpc_wu, "winning RBF must share vsize");
    let high_hex = encode_tx(&high);
    let high_txid = high.compute_txid().to_string();
    let tma = jsonrpc(rpc_addr, "testmempoolaccept", json!([[high_hex.clone()]])).await;
    assert_eq!(tma["result"][0]["allowed"], true, "{tma}");
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &rpc_txid),
        "testmempoolaccept must not RBF-evict: {mem}"
    );
    assert!(
        !mempool_has(&mem, &high_txid),
        "trial replacement must not remain: {mem}"
    );
    let replaced = jsonrpc(rpc_addr, "sendrawtransaction", json!([high_hex])).await;
    assert_eq!(replaced["result"], high_txid, "{replaced}");
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &high_txid),
        "replacement missing from mempool: {mem}"
    );
    assert!(
        !mempool_has(&mem, &rpc_txid),
        "replaced tx must leave mempool: {mem}"
    );

    let pkg_parent = acs_spend(
        pkg_cb,
        50_0000_0000,
        1_000,
        ScriptBuf::from_bytes(vec![0x57]),
    );
    let pkg_child = acs_spend(
        pkg_parent.compute_txid(),
        50_0000_0000 - 1_000,
        1_000,
        ScriptBuf::from_bytes(vec![0x58]),
    );
    let pkg_parent_txid = pkg_parent.compute_txid().to_string();
    let pkg_child_txid = pkg_child.compute_txid().to_string();
    let pkg_body = json!([encode_tx(&pkg_parent), encode_tx(&pkg_child)]).to_string();
    let (st, body) = http_post(esplora_addr, "/txs/package", &pkg_body).await;
    assert_eq!(st, 200, "POST /txs/package: {body}");
    let pkg_v: Value = serde_json::from_str(&body).unwrap_or_else(|e| {
        panic!("POST /txs/package json: {e} body={body}");
    });
    assert_eq!(
        pkg_v["txids"],
        json!([pkg_parent_txid.clone(), pkg_child_txid.clone()]),
        "{pkg_v}"
    );

    let submitted = jsonrpc(
        rpc_addr,
        "submitpackage",
        json!([[encode_tx(&pkg_parent), encode_tx(&pkg_child)]]),
    )
    .await;
    assert_eq!(submitted["error"]["code"], -1, "{submitted}");
    assert_eq!(
        submitted["error"]["message"], "mempool relay disabled (still in IBD or tip not ready)",
        "{submitted}"
    );

    let too_many = format!(
        "[{}]",
        (0..26).map(|_| "\"00\"").collect::<Vec<_>>().join(",")
    );
    let (st, body) = http_post(esplora_addr, "/txs/package", &too_many).await;
    assert_eq!(st, 400, "{body}");
    assert!(
        body.contains("package too large"),
        "26-tx HTTP package: {body}"
    );

    let mut chain_txs = Vec::with_capacity(25);
    let mut prev = chain_cb;
    let mut val = 50_0000_0000u64;
    for _ in 0..25u32 {
        let tx = acs_spend(prev, val, 1_000, ScriptBuf::from_bytes(vec![0x51]));
        prev = tx.compute_txid();
        val -= 1_000;
        chain_txs.push(tx);
    }
    let chain_hexes: Vec<String> = chain_txs.iter().map(encode_tx).collect();
    let chain_body = serde_json::to_string(&chain_hexes).unwrap();
    let (st, body) = http_post(esplora_addr, "/txs/package", &chain_body).await;
    assert_eq!(st, 200, "25-tx HTTP package: {body}");
    let chain_v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        chain_v["txids"].as_array().map(|a| a.len()),
        Some(25),
        "{chain_v}"
    );
    let chain_last = chain_txs[24].compute_txid().to_string();

    const MAX_PKG_WU: u64 = 404_000;
    let fat_a = pad_tx_to_weight(
        acs_spend(
            Txid::from_byte_array([0xfa; 32]),
            50_0000_0000,
            1_000_000,
            ScriptBuf::from_bytes(vec![0x60]),
        ),
        202_000,
    );
    let fat_b = pad_tx_to_weight(
        acs_spend(
            Txid::from_byte_array([0xfb; 32]),
            50_0000_0000,
            1_000_000,
            ScriptBuf::from_bytes(vec![0x61]),
        ),
        203_000,
    );
    let fat_wu = tx_wu(&fat_a) + tx_wu(&fat_b);
    assert!(
        fat_wu > MAX_PKG_WU,
        "padded package must exceed {MAX_PKG_WU}, got {fat_wu}"
    );
    assert!(tx_wu(&fat_a) <= 400_000 && tx_wu(&fat_b) <= 400_000);
    let fat_body = json!([encode_tx(&fat_a), encode_tx(&fat_b)]).to_string();
    let (st, body) = http_post(esplora_addr, "/txs/package", &fat_body).await;
    assert_eq!(st, 400, "{body}");
    assert!(
        body.contains("package too large"),
        "over-weight HTTP package: {body}"
    );

    let cheap_parent = acs_spend(cpfp_cb, 50_0000_0000, 1, ScriptBuf::from_bytes(vec![0x51]));
    let cheap_tma = jsonrpc(
        rpc_addr,
        "testmempoolaccept",
        json!([[encode_tx(&cheap_parent)]]),
    )
    .await;
    assert_eq!(cheap_tma["result"][0]["allowed"], false, "{cheap_tma}");
    assert_eq!(
        cheap_tma["result"][0]["reject-reason"], "min relay fee not met",
        "{cheap_tma}"
    );
    let cpfp_child = acs_spend(
        cheap_parent.compute_txid(),
        50_0000_0000 - 1,
        50_000,
        ScriptBuf::from_bytes(vec![0x63]),
    );
    let cpfp_body = json!([encode_tx(&cheap_parent), encode_tx(&cpfp_child)]).to_string();
    let (st, body) = http_post(esplora_addr, "/txs/package", &cpfp_body).await;
    assert_eq!(st, 200, "1p1c parent below min-relay HTTP package: {body}");
    let cpfp_v: Value = serde_json::from_str(&body).unwrap();
    let cpfp_parent_txid = cheap_parent.compute_txid().to_string();
    let cpfp_child_txid = cpfp_child.compute_txid().to_string();
    assert_eq!(
        cpfp_v["txids"],
        json!([cpfp_parent_txid.clone(), cpfp_child_txid.clone()]),
        "{cpfp_v}"
    );

    let entry = jsonrpc(rpc_addr, "getmempoolentry", json!([pkg_child_txid.clone()])).await;
    assert_eq!(entry["result"]["ancestorcount"], 2, "{entry}");
    assert_eq!(
        entry["result"]["depends"],
        json!([pkg_parent_txid.clone()]),
        "{entry}"
    );
    let ancs = jsonrpc(
        rpc_addr,
        "getmempoolancestors",
        json!([pkg_child_txid.clone()]),
    )
    .await;
    let anc_rows = ancs["result"].as_array().expect("ancestors array");
    assert!(
        anc_rows
            .iter()
            .any(|v| v.as_str() == Some(pkg_parent_txid.as_str())),
        "getmempoolancestors missing parent: {ancs}"
    );
    let desc = jsonrpc(
        rpc_addr,
        "getmempooldescendants",
        json!([pkg_parent_txid.clone()]),
    )
    .await;
    let desc_rows = desc["result"].as_array().expect("descendants array");
    assert!(
        desc_rows
            .iter()
            .any(|v| v.as_str() == Some(pkg_child_txid.as_str())),
        "getmempooldescendants missing child: {desc}"
    );
    let cluster = jsonrpc(
        rpc_addr,
        "getmempoolcluster",
        json!([pkg_child_txid.clone()]),
    )
    .await;
    assert_eq!(cluster["result"]["txcount"], 2, "{cluster}");
    let spend = jsonrpc(
        rpc_addr,
        "gettxspendingprevout",
        json!([[{"txid": pkg_cb.to_string(), "vout": 0}]]),
    )
    .await;
    assert_eq!(
        spend["result"][0]["spendingtxid"], pkg_parent_txid,
        "{spend}"
    );
    let diagram = jsonrpc(rpc_addr, "getmempoolfeeratediagram", json!([])).await;
    assert!(
        diagram["result"].as_array().is_some_and(|a| !a.is_empty()),
        "{diagram}"
    );
    let verbose = jsonrpc(rpc_addr, "getrawmempool", json!([true])).await;
    assert_eq!(
        verbose["result"][&pkg_child_txid]["ancestorcount"], 2,
        "{verbose}"
    );

    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    for tid in [
        &high_txid,
        &txid_hex,
        &child_txid,
        &pkg_parent_txid,
        &pkg_child_txid,
        &at_min_txid,
        &chain_last,
        &cpfp_parent_txid,
        &cpfp_child_txid,
    ] {
        assert!(mempool_has(&mem, tid), "getrawmempool missing {tid}: {mem}");
    }

    let (st, body) = http_get(esplora_addr, "/mempool").await;
    assert_eq!(st, 200, "GET /mempool: {body}");
    let mem_info: Value = serde_json::from_str(&body).unwrap();
    assert!(
        mem_info["count"].as_u64().unwrap_or(0) >= 30,
        "live mempool count: {mem_info}"
    );
    let (st, body) = http_get(esplora_addr, "/mempool/txids").await;
    assert_eq!(st, 200, "GET /mempool/txids: {body}");
    let txids_v: Value = serde_json::from_str(&body).unwrap();
    let txid_list = txids_v.as_array().expect("mempool/txids array");
    assert!(
        txid_list
            .iter()
            .any(|v| v.as_str() == Some(pkg_parent_txid.as_str())),
        "mempool/txids missing package parent: {body}"
    );
    pin_internal_mempool_txs(esplora_addr).await;
    let (st, body) = http_get(esplora_addr, "/mempool/recent").await;
    assert_eq!(st, 200, "GET /mempool/recent: {body}");
    let recent: Value = serde_json::from_str(&body).unwrap();
    let recent_rows = recent.as_array().expect("mempool/recent array");
    assert!(
        recent_rows.iter().any(|r| {
            r["txid"] == cpfp_child_txid
                || r["txid"] == cpfp_parent_txid
                || r["txid"] == pkg_child_txid
                || r["txid"] == pkg_parent_txid
        }),
        "mempool/recent missing package tx: {body}"
    );
    // Flow is cold and the chain holds too little fee history: the live
    // pool alone does not set a rate, so no target answers.
    let (st, body) = http_get(esplora_addr, "/fee-estimates").await;
    assert_eq!(st, 503, "GET /fee-estimates: {body}");

    let metrics_in_ibd = pin_metrics_equal_rpc(health_addr, rpc_addr, false).await;
    assert!(
        metrics_in_ibd["rbitcoin_mempool_transactions"] > 0.0,
        "{metrics_in_ibd:?}"
    );
    let tip_before = jsonrpc(rpc_addr, "getbestblockhash", json!([])).await;
    let tip_hash = tip_before["result"].as_str().expect("tip hash").to_string();
    pin_waitforblockheight_timeout_zero_behind(rpc_addr, 106, &tip_hash).await;
    pin_getblock_hash_oob_unknown_and_raw(rpc_addr, 106, &tip_hash).await;
    let waiters = spawn_wait_and_gbt_longpoll(rpc_addr, 107).await;

    let mined = jsonrpc(rpc_addr, "generate", json!([1])).await;
    assert_eq!(
        mined["result"].as_array().map(|a| a.len()),
        Some(1),
        "{mined}"
    );
    let count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
    assert_eq!(count["result"], 107, "{count}");
    let empty = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert_eq!(empty["result"], json!([]), "{empty}");
    let tip = jsonrpc(rpc_addr, "getbestblockhash", json!([])).await;
    let new_hash = tip["result"].as_str().expect("new tip");
    waiters.assert_woke_on_new_tip(new_hash, 107).await;
    let (st, body) = http_get(esplora_addr, &format!("/tx/{pkg_parent_txid}/status")).await;
    assert_eq!(st, 200, "tx status: {body}");
    let status: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        status["confirmed"], true,
        "{pkg_parent_txid} confirms on generate: {body}"
    );
    assert_eq!(status["block_height"], 107, "{body}");
    let blk = jsonrpc(rpc_addr, "getblock", json!([tip["result"].clone(), 2])).await;
    let txs = blk["result"]["tx"].as_array().expect("mined tx array");
    assert!(
        txs.len() >= 30,
        "coinbase + RBF + esplora + packages: {blk}"
    );
    pin_esplora_blocks_summaries(esplora_addr, 107, new_hash).await;
    pin_esplora_block_txs_pages(esplora_addr, new_hash, txs.len()).await;
    pin_internal_block_txs_and_outspends(esplora_addr, new_hash).await;
    // Core-shaped coinbase input: a `coinbase` hex script and no txid/vout,
    // which is what mempool's indexer requires.
    assert!(
        txs[0]["vin"][0].get("coinbase").is_some() && txs[0]["vin"][0].get("txid").is_none(),
        "verbosity 2 coinbase vin: {blk}"
    );
    assert!(
        txs[0]["vout"][0].get("value").is_some(),
        "verbosity 2 coinbase vout: {blk}"
    );
    assert!(
        txs.iter()
            .skip(1)
            .any(|t| t["vin"][0].get("txid").is_some()),
        "verbosity 2 spend vin: {blk}"
    );
    for tid in [
        &high_txid,
        &txid_hex,
        &child_txid,
        &pkg_parent_txid,
        &pkg_child_txid,
        &at_min_txid,
        &chain_last,
        &cpfp_parent_txid,
    ] {
        assert!(
            txs.iter().any(|t| t["txid"] == *tid),
            "generate must include {tid}: {blk}"
        );
    }
    pin_mined_parent_before_child(txs, &pkg_parent_txid, &pkg_child_txid);
    pin_scantxoutset_drops_spent_coinbase(rpc_addr, &cb_hex).await;
    let cb_txid = txs[0]["txid"].as_str().expect("coinbase txid").to_string();
    pin_rest_chaininfo_and_blockhash(rpc_addr, new_hash, 107).await;
    pin_rest_headers(rpc_addr).await;
    pin_rest_block_and_tx(rpc_addr, new_hash, &cb_txid).await;
    pin_rest_mempool_and_utxos(rpc_addr, 107, &cb_txid).await;
    pin_rest_deployment_and_filter(rpc_addr, new_hash).await;
    pin_esplora_block_txids_merkle_and_outspend(esplora_addr, new_hash, &cb_txid, txs.len()).await;
    let parent_hash = blk["result"]["previousblockhash"]
        .as_str()
        .expect("previousblockhash")
        .to_string();
    pin_esplora_block_json_raw_status(esplora_addr, new_hash, &parent_hash, 107, txs.len()).await;
    pin_esplora_txid_raw_hex_merkleblock(esplora_addr, new_hash, &cb_txid).await;
    pin_esplora_block_height_and_header(esplora_addr, new_hash, 107).await;
    pin_esplora_tx_status(esplora_addr, new_hash, &cb_txid, 107).await;
    pin_esplora_tx_json_unknown_coinbase(esplora_addr, &cb_txid).await;
    pin_esplora_scripthash_pages(esplora_addr).await;
    let cb_val = (txs[0]["vout"][0]["value"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    let immature = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(&cb_txid).expect("coinbase txid"),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(cb_val.saturating_sub(1_000)),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut imm_raw = Vec::new();
    immature.consensus_encode(&mut imm_raw).unwrap();
    let imm = jsonrpc(
        rpc_addr,
        "sendrawtransaction",
        json!([rbitcoin_primitives::hex_encode(&imm_raw)]),
    )
    .await;
    assert_eq!(imm["error"]["code"], -26, "{imm}");
    assert_eq!(
        imm["error"]["message"], "bad-txns-premature-spend-of-coinbase",
        "{imm}"
    );

    let relay_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let info = jsonrpc(rpc_addr, "getmempoolinfo", json!([])).await;
        if info["result"]["relay_enabled"] == true {
            break;
        }
        if Instant::now() >= relay_deadline {
            panic!("relay never enabled after generate: {info}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let chain = jsonrpc(rpc_addr, "getblockchaininfo", json!([])).await;
    assert_eq!(chain["result"]["initialblockdownload"], false, "{chain}");
    assert_eq!(
        chain["result"]["headers"], chain["result"]["blocks"],
        "{chain}"
    );
    assert_eq!(http_get(health_addr, "/readyz").await, (200, "ok".into()));
    let metrics_ready = pin_metrics_equal_rpc(health_addr, rpc_addr, true).await;
    for total in [
        "rbitcoin_esplora_requests_total",
        "rbitcoin_esplora_request_seconds_total",
        "rbitcoin_electrum_requests_total",
        "rbitcoin_electrum_request_seconds_total",
        "rbitcoin_block_serve_total",
        "rbitcoin_block_serve_bytes_total",
        "rbitcoin_mempool_accepts_total",
        "rbitcoin_mempool_rejects_total",
    ] {
        assert!(
            metrics_ready[total] >= metrics_in_ibd[total],
            "{total} counts up: {metrics_in_ibd:?} then {metrics_ready:?}"
        );
    }
    for total in [
        "rbitcoin_esplora_requests_total",
        "rbitcoin_electrum_requests_total",
        "rbitcoin_mempool_accepts_total",
    ] {
        assert!(metrics_in_ibd[total] >= 1.0, "{total}: {metrics_in_ibd:?}");
    }

    let relay_parent = acs_spend(
        relay_cb,
        50_0000_0000,
        1_000,
        ScriptBuf::from_bytes(vec![0x59]),
    );
    let relay_child = acs_spend(
        relay_parent.compute_txid(),
        50_0000_0000 - 1_000,
        1_000,
        ScriptBuf::from_bytes(vec![0x5a]),
    );
    let relay_parent_txid = relay_parent.compute_txid().to_string();
    let relay_child_txid = relay_child.compute_txid().to_string();
    let pkg_hexes = json!([encode_tx(&relay_parent), encode_tx(&relay_child)]);
    let capped = jsonrpc(rpc_addr, "submitpackage", json!([pkg_hexes.clone(), 1])).await;
    assert_eq!(
        capped["result"]["package_msg"], "transaction failed",
        "{capped}"
    );
    let cap_errs: Vec<&str> = capped["result"]["tx-results"]
        .as_object()
        .map(|m| m.values().filter_map(|v| v["error"].as_str()).collect())
        .unwrap_or_default();
    assert!(cap_errs.contains(&"max feerate exceeded"), "{capped}");

    let ok = jsonrpc(rpc_addr, "submitpackage", json!([pkg_hexes.clone()])).await;
    assert_eq!(ok["result"]["package_msg"], "success", "{ok}");
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &relay_parent_txid) && mempool_has(&mem, &relay_child_txid),
        "submitpackage success missing members: {mem}"
    );
    let again = jsonrpc(rpc_addr, "submitpackage", json!([pkg_hexes])).await;
    assert_eq!(again["result"]["package_msg"], "success", "{again}");
    let again_row = again["result"]["tx-results"]
        .as_object()
        .and_then(|m| m.values().next())
        .cloned()
        .unwrap_or(json!(null));
    assert!(
        again_row.get("error").is_none(),
        "already-in-mempool must not error: {again}"
    );

    let rpc_cpfp_parent = acs_spend(
        rpc_cpfp_cb,
        50_0000_0000,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
    );
    let rpc_cpfp_child = acs_spend(
        rpc_cpfp_parent.compute_txid(),
        50_0000_0000 - 1,
        50_000,
        ScriptBuf::from_bytes(vec![0x64]),
    );
    let rpc_cpfp = jsonrpc(
        rpc_addr,
        "submitpackage",
        json!([[encode_tx(&rpc_cpfp_parent), encode_tx(&rpc_cpfp_child)]]),
    )
    .await;
    assert_eq!(
        rpc_cpfp["result"]["package_msg"], "success",
        "RPC submitpackage CPFP: {rpc_cpfp}"
    );
    let mem = jsonrpc(rpc_addr, "getrawmempool", json!([])).await;
    assert!(
        mempool_has(&mem, &rpc_cpfp_parent.compute_txid().to_string())
            && mempool_has(&mem, &rpc_cpfp_child.compute_txid().to_string()),
        "submitpackage CPFP missing members: {mem}"
    );

    let n26 = jsonrpc(
        rpc_addr,
        "submitpackage",
        json!([(0..26).map(|_| json!("00")).collect::<Vec<Value>>()]),
    )
    .await;
    let n26_msg = n26["error"]["message"].as_str().unwrap_or("");
    assert!(
        n26_msg.contains("between 1 and 25"),
        "RPC 26-tx package: {n26}"
    );
    let fat = jsonrpc(
        rpc_addr,
        "submitpackage",
        json!([[encode_tx(&fat_a), encode_tx(&fat_b)]]),
    )
    .await;
    let fat_msg = fat["error"]["message"]
        .as_str()
        .or_else(|| fat["result"]["package_msg"].as_str())
        .unwrap_or("");
    let fat_err = fat["result"]["tx-results"]
        .as_object()
        .and_then(|m| m.values().find_map(|v| v["error"].as_str()))
        .unwrap_or("");
    assert!(
        fat_msg.contains("package too large") || fat_err.contains("package too large"),
        "RPC over-weight package: {fat}"
    );

    let _ = jsonrpc(rpc_addr, "stop", json!([])).await;
    let stopped = tokio::time::timeout(Duration::from_secs(15), node).await;
    match stopped {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => panic!("run_p2p error after stop: {e}"),
        Ok(Err(e)) => panic!("run_p2p join: {e}"),
        Err(_) => panic!("run_p2p did not exit after stop"),
    }
}

/// Nothing listens here. A pinned `--connect` at genesis still enters tip mode.
const DEAD_CONNECT: &str = "127.0.0.1:1";

/// `run_p2p` on regtest with an ephemeral P2P bind, no seeds, the one
/// `--connect` down, and `--max-run-secs 0`: exit once tip entry ends.
fn listen_and_exit_cfg(datadir: &std::path::Path) -> NodeConfig {
    let mut cfg = NodeConfig::default()
        .with_datadir(datadir)
        .with_network(Network::Regtest)
        .with_tiny_heads()
        .with_p2p_listen("127.0.0.1:0".parse().unwrap());
    cfg.listen.use_seeds = false;
    cfg.listen.connect = vec![DEAD_CONNECT.parse().unwrap()];
    cfg.max_run_secs = Some(0);
    cfg
}

async fn start_and_exit(cfg: NodeConfig) -> Result<(), rbitcoin_node::NodeError> {
    tokio::time::timeout(Duration::from_secs(30), run_p2p(cfg))
        .await
        .expect("run_p2p did not exit")
}

/// `run_p2p` off the runtime workers, as `cli_main` blocks on it: an empty
/// datadir connects genesis through tip-accept, which refuses a worker.
fn spawn_run_p2p(cfg: NodeConfig) -> tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>> {
    tokio::task::spawn_blocking(move || {
        let _block = rbitcoin_net::BlockingRegion::enter();
        tokio::runtime::Handle::current().block_on(run_p2p(cfg))
    })
}

async fn stop_run_p2p(
    rpc_addr: SocketAddr,
    node: tokio::task::JoinHandle<Result<(), rbitcoin_node::NodeError>>,
) {
    let _ = jsonrpc(rpc_addr, "stop", json!([])).await;
    match tokio::time::timeout(Duration::from_secs(15), node).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => panic!("run_p2p error after stop: {e}"),
        Ok(Err(e)) => panic!("run_p2p join: {e}"),
        Err(_) => panic!("run_p2p did not exit after stop"),
    }
}

/// One operator datadir restarted through the startup arms `run_p2p` owns
/// while its one `--connect` peer is down: a health port that does not bind,
/// a junk peer book, a missing then a valid asmap, the wallet servers and
/// health probes up until `stop`, listeners someone else holds, seeds with
/// no `--connect`, and a pruned datadir that refuses an unpruned start.
#[tokio::test(flavor = "multi_thread")]
async fn node_listen_and_exit() {
    let td = TestDatadir::new().unwrap();
    let dir = td.path();
    let peers = dir.join("peers");

    // Health binds before the store opens. A taken port stops the start
    // with nothing written under store/.
    let taken_health = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.listen.health = Some(taken_health.local_addr().unwrap());
    let err = start_and_exit(cfg)
        .await
        .expect_err("taken health port")
        .to_string();
    assert!(err.contains("health listen"), "{err}");
    assert!(
        !td.store_path().exists(),
        "store opened before the health bind"
    );
    drop(taken_health);

    // A copied-in datadir: the peer book is junk and the configured asmap is
    // not there. Catch-up gives up on the refused peer instead of hanging,
    // and the book on disk is a real book again.
    std::fs::write(&peers, b"not-a-valid-peers-blob\xff\x00").unwrap();
    let dead: SocketAddr = DEAD_CONNECT.parse().unwrap();
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.asmap = Some(dir.join("no-such-asmap"));
    let mempool = cfg.mempool_path();
    start_and_exit(cfg)
        .await
        .expect("a refused peer is not fatal");
    assert!(mempool.exists(), "run_p2p opens the mempool");
    let book = rbitcoin_net::AddrMan::load(&peers).expect("junk book replaced");
    assert!(
        book.flags(&dead).failed_last_connect(),
        "the refused --connect is in the saved book"
    );

    // The asmap is in place now, the saved book loads, and the wallet servers
    // answer until the operator stops the node.
    std::fs::write(dir.join("ip_asn.dat"), rbitcoin_net::TWO_PREFIX_ASMAP).unwrap();
    std::fs::write(dir.join("rpc.token"), "pass").unwrap();
    let (electrum_addr, esplora_addr, rpc_addr, health_addr) = (
        ephemeral_addr(),
        ephemeral_addr(),
        ephemeral_addr(),
        ephemeral_addr(),
    );
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.milestone_height = 100;
    cfg.shindex = true;
    cfg.listen.electrum = Some(electrum_addr);
    cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora_addr));
    cfg.rpc.listen = Some(rpc_addr);
    cfg.listen.health = Some(health_addr);
    cfg.metrics = true;
    cfg.max_run_secs = Some(60);
    let node = spawn_run_p2p(cfg);
    wait_listeners(&[electrum_addr, esplora_addr, rpc_addr, health_addr]).await;
    pin_healthz(health_addr).await;
    // Genesis is older than the default tip-age window, so the process is
    // live and following but not ready.
    assert_eq!(
        readyz_after_startup(health_addr).await,
        (503, "not ready: initial block download".into()),
        "genesis tip is older than --max-tip-age"
    );
    pin_health_scrape(health_addr, false, 0.0).await;
    let (st, height) = http_get(esplora_addr, "/blocks/tip/height").await;
    assert_eq!((st, height.as_str()), (200, "0"), "esplora on genesis");
    let mut el = TcpStream::connect(electrum_addr).await.unwrap();
    let tip = electrum_rpc(&mut el, 1, "blockchain.headers.subscribe", json!([])).await;
    assert_eq!(tip["result"]["height"], 0, "{tip}");
    let count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
    assert_eq!(count["result"], 0, "{count}");
    let mined = jsonrpc(rpc_addr, "generate", json!([1])).await;
    assert!(mined["result"].is_array(), "{mined}");
    let ready_deadline = Instant::now() + Duration::from_secs(20);
    let ready = loop {
        let got = http_get(health_addr, "/readyz").await;
        if got.0 == 200 || Instant::now() >= ready_deadline {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(ready, (200, "ok".into()), "a fresh tip is ready");
    pin_health_scrape(health_addr, true, 1.0).await;
    stop_run_p2p(rpc_addr, node).await;

    // Another process holds the Electrum and RPC ports. The binds warn, the
    // node still follows, and `/readyz` names both. `/metrics` is absent
    // without `--metrics`.
    let held_electrum = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let held_rpc = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let health_addr = ephemeral_addr();
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.shindex = true;
    cfg.listen.electrum = Some(held_electrum.local_addr().unwrap());
    cfg.rpc.listen = Some(held_rpc.local_addr().unwrap());
    cfg.listen.health = Some(health_addr);
    // Deadline starts at tip-follow entry, after `/readyz` has left bring-up.
    // Two seconds outlives that probe. The process then exits on the timer
    // because the held RPC port cannot take `stop`.
    cfg.max_run_secs = Some(2);
    let node = spawn_run_p2p(cfg);
    wait_listeners(&[health_addr]).await;
    assert_eq!(
        readyz_after_startup(health_addr).await,
        (503, "not ready: rpc, electrum not listening".into())
    );
    let (st, body) = http_get(health_addr, "/metrics").await;
    assert_eq!(st, 404, "/metrics without --metrics: {body}");
    let stopped = tokio::time::timeout(Duration::from_secs(30), node).await;
    assert!(matches!(stopped, Ok(Ok(Ok(())))), "{stopped:?}");
    drop((held_electrum, held_rpc));

    // Without `--connect` and with seeds on: regtest resolves none, the one
    // saved peer still refuses, and the node exits short of tip mode.
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.listen.connect.clear();
    cfg.listen.use_seeds = true;
    start_and_exit(cfg)
        .await
        .expect("no reachable peer is not fatal");

    // Once pruned, the datadir refuses a start without --prune-seqsigwit.
    let mut cfg = listen_and_exit_cfg(&dir);
    cfg.prune_seqsigwit = true;
    start_and_exit(cfg).await.expect("pruned start");
    let err = start_and_exit(listen_and_exit_cfg(&dir))
        .await
        .expect_err("unpruned start on a pruned datadir")
        .to_string();
    assert!(err.contains("--prune-seqsigwit"), "{err}");
}

/// Tor control port stand-in: PROTOCOLINFO advertises `methods`, SAFECOOKIE
/// answers from `cookie`, and ADD_ONION NEW mints `key{n}` for service `n`.
/// Every command line lands in `log`. Live Tor is overlay-functional.
struct FakeTor {
    addr: SocketAddr,
    methods: Arc<Mutex<&'static str>>,
    log: Arc<Mutex<Vec<String>>>,
    minted: Arc<Mutex<Vec<String>>>,
}

const TOR_COOKIE: [u8; 32] = [0x2a; 32];
const TOR_PASSWORD: &str = "s3cret";

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{hmac, sha256, HashEngine};
    let mut engine = hmac::HmacEngine::<sha256::Hash>::new(key);
    engine.input(data);
    hmac::Hmac::<sha256::Hash>::from_engine(engine).to_byte_array()
}

fn fake_onion_service_id(n: usize) -> String {
    let pk = [u8::try_from(n + 1).unwrap(); 32];
    let name = rbitcoin_net::NetAddr::Onion { pk, port: 0 }.to_string();
    name.trim_end_matches(".onion:0").to_string()
}

impl FakeTor {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tor = Self {
            addr: listener.local_addr().unwrap(),
            methods: Arc::new(Mutex::new("SAFECOOKIE")),
            log: Arc::default(),
            minted: Arc::default(),
        };
        let (methods, log, minted) = (
            Arc::clone(&tor.methods),
            Arc::clone(&tor.log),
            Arc::clone(&tor.minted),
        );
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                tokio::spawn(fake_tor_session(
                    s,
                    Arc::clone(&methods),
                    Arc::clone(&log),
                    Arc::clone(&minted),
                ));
            }
        });
        tor
    }

    fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

async fn fake_tor_session(
    s: TcpStream,
    methods: Arc<Mutex<&'static str>>,
    log: Arc<Mutex<Vec<String>>>,
    minted: Arc<Mutex<Vec<String>>>,
) {
    use bitcoin::hex::{DisplayHex, FromHex};
    let (r, mut w) = s.into_split();
    let mut lines = BufReader::new(r).lines();
    let mut client_hash: Option<[u8; 32]> = None;
    while let Ok(Some(line)) = lines.next_line().await {
        log.lock().unwrap().push(line.clone());
        let reply = if line == "PROTOCOLINFO 1" {
            let methods = *methods.lock().unwrap();
            format!("250-PROTOCOLINFO 1\r\n250-AUTH METHODS={methods}\r\n250 OK\r\n")
        } else if let Some(nonce) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
            let server_nonce = [0x5a; 32];
            let mut mat = TOR_COOKIE.to_vec();
            mat.extend(Vec::<u8>::from_hex(nonce).unwrap());
            mat.extend(server_nonce);
            client_hash = Some(hmac_sha256(
                b"Tor safe cookie authentication controller-to-server hash",
                &mat,
            ));
            let server_hash = hmac_sha256(
                b"Tor safe cookie authentication server-to-controller hash",
                &mat,
            );
            format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                server_hash.to_lower_hex_string(),
                server_nonce.to_lower_hex_string()
            )
        } else if let Some(auth) = line.strip_prefix("AUTHENTICATE ") {
            let ok = auth == format!("\"{TOR_PASSWORD}\"")
                || client_hash.is_some_and(|h| auth == h.to_lower_hex_string());
            if ok {
                "250 OK\r\n"
            } else {
                "515 Authentication failed\r\n"
            }
            .to_string()
        } else if line == "GETINFO version" {
            "250-version=0.4.8.10\r\n250 OK\r\n".to_string()
        } else if let Some(rest) = line.strip_prefix("ADD_ONION ") {
            let spec = rest.split_once(" Port=").map_or(rest, |(s, _)| s);
            let mut minted = minted.lock().unwrap();
            if spec == "NEW:ED25519-V3" {
                let n = minted.len();
                minted.push(format!("ED25519-V3:key{n}"));
                format!(
                    "250-ServiceID={}\r\n250-PrivateKey={}\r\n250 OK\r\n",
                    fake_onion_service_id(n),
                    minted[n]
                )
            } else if let Some(n) = minted.iter().position(|k| k == spec) {
                format!("250-ServiceID={}\r\n250 OK\r\n", fake_onion_service_id(n))
            } else {
                "512 Invalid onion key\r\n".to_string()
            }
        } else {
            "510 Unrecognized command\r\n".to_string()
        };
        if w.write_all(reply.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// I2P SAM stand-in: SESSION CREATE TRANSIENT hands out destination `n`, a
/// stored destination comes back as itself, and STREAM FORWARD is accepted.
struct FakeSam {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<String>>>,
}

/// A 387-byte public destination with no certificate, distinct per `n`:
/// I2P base64 of `fake_i2p_public(n)`.
fn fake_i2p_destination(n: usize) -> String {
    let first = char::from(b'B' + u8::try_from(n).unwrap());
    format!("{first}{}", "A".repeat(515))
}

fn fake_i2p_public(n: usize) -> Vec<u8> {
    let mut raw = vec![0u8; 387];
    raw[0] = (u8::try_from(n).unwrap() + 1) << 2;
    raw
}

impl FakeSam {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sam = Self {
            addr: listener.local_addr().unwrap(),
            log: Arc::default(),
        };
        let log = Arc::clone(&sam.log);
        let transient = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let (log, transient) = (Arc::clone(&log), Arc::clone(&transient));
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        log.lock().unwrap().push(line.clone());
                        let reply = if line.starts_with("HELLO VERSION") {
                            "HELLO REPLY RESULT=OK VERSION=3.1".to_string()
                        } else if line.starts_with("SESSION CREATE") {
                            let asked = line
                                .split_whitespace()
                                .find_map(|t| t.strip_prefix("DESTINATION="))
                                .unwrap_or("TRANSIENT");
                            let dest = if asked == "TRANSIENT" {
                                let n = transient.fetch_add(1, Ordering::SeqCst);
                                fake_i2p_destination(n)
                            } else {
                                asked.to_string()
                            };
                            format!("SESSION STATUS RESULT=OK DESTINATION={dest}")
                        } else if line.starts_with("STREAM FORWARD") {
                            "STREAM STATUS RESULT=OK".to_string()
                        } else {
                            "SESSION STATUS RESULT=I2P_ERROR".to_string()
                        };
                        if w.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        sam
    }

    fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

fn starts_with_any(lines: &[String], prefix: &str) -> Vec<String> {
    lines
        .iter()
        .filter(|l| l.starts_with(prefix))
        .cloned()
        .collect()
}

/// An operator publishes P2P, Electrum, and Esplora as onion and I2P
/// services through a local Tor control port and SAM bridge. A bad or short
/// cookie, or a Tor that does not offer SAFECOOKIE, stops the start before
/// any AUTHENTICATE; password auth mints and saves a key per service; a
/// SAFECOOKIE restart reuses every saved key and destination.
#[tokio::test(flavor = "multi_thread")]
async fn tor_control_onion_lifecycle() {
    let td = TestDatadir::new().unwrap();
    let dir = td.path();
    let tor = FakeTor::start().await;
    let sam = FakeSam::start().await;
    let cookie = dir.join("control.authcookie");
    let cookie_cfg = |cookie: &std::path::Path| {
        let mut cfg = listen_and_exit_cfg(&dir);
        cfg.tor.control = Some(tor.addr);
        cfg.tor.cookie = Some(cookie.to_path_buf());
        cfg
    };

    // A cookie from another Tor, a truncated cookie, and a Tor that only
    // offers plain COOKIE all refuse the start, and none sends AUTHENTICATE:
    // the node never hands the raw cookie to whatever owns the port.
    std::fs::write(&cookie, [0u8; 32]).unwrap();
    let err = start_and_exit(cookie_cfg(&cookie))
        .await
        .expect_err("wrong cookie")
        .to_string();
    assert!(err.contains("server hash mismatch"), "{err}");
    std::fs::write(&cookie, [0x2a; 2]).unwrap();
    let err = start_and_exit(cookie_cfg(&cookie))
        .await
        .expect_err("short cookie")
        .to_string();
    assert!(err.contains("32 bytes"), "{err}");
    std::fs::write(&cookie, TOR_COOKIE).unwrap();
    *tor.methods.lock().unwrap() = "COOKIE";
    let err = start_and_exit(cookie_cfg(&cookie))
        .await
        .expect_err("plain COOKIE only")
        .to_string();
    assert!(err.contains("SAFECOOKIE"), "{err}");
    let refused = tor.take_log();
    assert!(
        starts_with_any(&refused, "AUTHENTICATE ").is_empty(),
        "{refused:?}"
    );
    assert!(
        starts_with_any(&refused, "ADD_ONION ").is_empty(),
        "{refused:?}"
    );

    // Password auth. Each service gets a fresh onion key, saved 0600 under
    // the datadir, and an I2P destination; getnetworkinfo lists them all.
    *tor.methods.lock().unwrap() = "HASHEDPASSWORD";
    std::fs::write(dir.join("rpc.token"), "pass").unwrap();
    let (p2p, electrum, esplora, rpc) = (
        ephemeral_addr(),
        ephemeral_addr(),
        ephemeral_addr(),
        ephemeral_addr(),
    );
    let services_cfg = || {
        let mut cfg = listen_and_exit_cfg(&dir).with_p2p_listen(p2p);
        cfg.tor.control = Some(tor.addr);
        cfg.listen.listen_onion = true;
        cfg.listen.i2p_sam = Some(sam.addr);
        cfg.listen.i2p_accept_incoming = true;
        cfg.shindex = true;
        cfg.listen.electrum = Some(electrum);
        cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora));
        cfg
    };
    let mut cfg = services_cfg();
    cfg.tor.password = Some(TOR_PASSWORD.into());
    cfg.rpc.listen = Some(rpc);
    cfg.max_run_secs = Some(60);
    let node = spawn_run_p2p(cfg);
    wait_listeners(&[electrum, esplora, rpc]).await;
    let info = jsonrpc(rpc, "getnetworkinfo", json!([])).await;
    let local: Vec<(String, u64)> = info["result"]["localaddresses"]
        .as_array()
        .unwrap_or_else(|| panic!("{info}"))
        .iter()
        .map(|r| {
            (
                r["address"].as_str().unwrap().to_string(),
                r["port"].as_u64().unwrap(),
            )
        })
        .collect();
    let regtest_port = Network::Regtest.default_p2p_port();
    for (n, port) in [(0, regtest_port), (1, electrum.port()), (2, esplora.port())] {
        let host = format!("{}.onion", fake_onion_service_id(n));
        assert!(local.contains(&(host, u64::from(port))), "{local:?}");
    }
    let i2p_p2p = rbitcoin_net::NetAddr::I2p {
        dest: bitcoin::hashes::sha256::Hash::hash(&fake_i2p_public(0)).to_byte_array(),
        port: 0,
    }
    .host_str();
    assert!(local.iter().any(|(a, _)| *a == i2p_p2p), "{local:?}");
    stop_run_p2p(rpc, node).await;

    let first = tor.take_log();
    assert!(first.contains(&format!("AUTHENTICATE \"{TOR_PASSWORD}\"")));
    let onions = starts_with_any(&first, "ADD_ONION ");
    let targets = [
        format!("Port={regtest_port},127.0.0.1:{}", p2p.port()),
        format!("Port={0},127.0.0.1:{0}", electrum.port()),
        format!("Port={0},127.0.0.1:{0}", esplora.port()),
    ];
    assert_eq!(onions.len(), 3, "{onions:?}");
    for (line, target) in onions.iter().zip(&targets) {
        assert_eq!(*line, format!("ADD_ONION NEW:ED25519-V3 {target}"));
    }
    for (n, name) in ["p2p", "electrum", "esplora"].into_iter().enumerate() {
        let key = dir.join("onion").join(format!("{name}.priv"));
        assert_eq!(
            std::fs::read_to_string(&key).unwrap().trim(),
            format!("ED25519-V3:key{n}")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} onion key mode");
        }
        let dest = dir.join("i2p").join(format!("{name}.priv"));
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap().trim(),
            fake_i2p_destination(n)
        );
    }
    let forwards = starts_with_any(&sam.take_log(), "STREAM FORWARD");
    for port in [p2p.port(), electrum.port(), esplora.port()] {
        assert!(
            forwards
                .iter()
                .any(|f| f.contains(&format!("PORT={port} "))),
            "{forwards:?}"
        );
    }

    // SAFECOOKIE restart: the same three services under the saved keys, and
    // each SAM session under its saved destination.
    *tor.methods.lock().unwrap() = "SAFECOOKIE";
    let mut cfg = services_cfg();
    cfg.tor.cookie = Some(cookie.clone());
    start_and_exit(cfg).await.expect("SAFECOOKIE restart");
    let second = tor.take_log();
    assert_eq!(
        starts_with_any(&second, "AUTHCHALLENGE SAFECOOKIE ").len(),
        1,
        "{second:?}"
    );
    let onions = starts_with_any(&second, "ADD_ONION ");
    assert_eq!(onions.len(), 3, "{onions:?}");
    for (n, (line, target)) in onions.iter().zip(&targets).enumerate() {
        assert_eq!(*line, format!("ADD_ONION ED25519-V3:key{n} {target}"));
    }
    assert_eq!(tor.minted.lock().unwrap().len(), 3, "no key minted twice");
    let creates = starts_with_any(&sam.take_log(), "SESSION CREATE");
    assert_eq!(creates.len(), 3, "{creates:?}");
    for n in 0..3 {
        let dest = format!("DESTINATION={} ", fake_i2p_destination(n));
        assert!(creates.iter().any(|c| c.contains(&dest)), "{creates:?}");
    }
}

async fn history_closed(electrum_addr: SocketAddr, scripthash: &str) {
    let mut el = TcpStream::connect(electrum_addr)
        .await
        .expect("electrum listens");
    let hist = electrum_rpc(
        &mut el,
        1,
        "blockchain.scripthash.get_history",
        json!([scripthash]),
    )
    .await;
    let msg = hist["error"]["message"].as_str().unwrap_or("");
    assert!(msg.contains("scripthash index disabled"), "{hist}");
}

async fn history_len(electrum_addr: SocketAddr, scripthash: &str) -> usize {
    let mut el = TcpStream::connect(electrum_addr).await.unwrap();
    let hist = electrum_rpc(
        &mut el,
        1,
        "blockchain.scripthash.get_history",
        json!([scripthash]),
    )
    .await;
    hist["result"]
        .as_array()
        .unwrap_or_else(|| panic!("{hist}"))
        .len()
}

/// One datadir whose operator turns `--sh-index` on and off across
/// restarts. Blocks mined while it is off are collected from the archive
/// on the first start with it on; turning it off closes Electrum and keeps
/// the index; turning it back on after a crash that left a collect run and
/// a lagging high-water mark resumes the write-behind, discards the run,
/// and follows the next block.
#[tokio::test(flavor = "multi_thread")]
async fn enter_tip_mode_indexes() {
    let td = TestDatadir::new().unwrap();
    let dir = td.path();
    let store = td.store_path();
    std::fs::write(dir.join("rpc.token"), "pass").unwrap();
    let (electrum_addr, rpc_addr) = (ephemeral_addr(), ephemeral_addr());
    let start = |shindex: bool| {
        let mut cfg = NodeConfig::default()
            .with_datadir(&dir)
            .with_network(Network::Regtest)
            .with_tiny_heads()
            .with_p2p_listen("127.0.0.1:0".parse().unwrap());
        cfg.listen.use_seeds = false;
        cfg.listen.connect.clear();
        cfg.shindex = shindex;
        cfg.listen.electrum = Some(electrum_addr);
        cfg.rpc.listen = Some(rpc_addr);
        cfg.max_run_secs = Some(60);
        spawn_run_p2p(cfg)
    };
    let op_true = electrum_scripthash_hex(&[0x51]);

    // No scripthash index: tip follow, RPC, and Electrum listen.
    // Address methods fail closed.
    let node = start(false);
    wait_listeners(&[rpc_addr, electrum_addr]).await;
    for _ in 0..3 {
        let mined = jsonrpc(rpc_addr, "generateblock", json!(["raw(51)", []])).await;
        assert!(mined["result"]["hash"].is_string(), "{mined}");
    }
    history_closed(electrum_addr, &op_true).await;
    stop_run_p2p(rpc_addr, node).await;

    // First start with the index: the three coinbases are collected from the
    // archive before Electrum opens.
    let node = start(true);
    wait_listeners(&[electrum_addr, rpc_addr]).await;
    assert_eq!(history_len(electrum_addr, &op_true).await, 3);
    stop_run_p2p(rpc_addr, node).await;

    // Index off again: Electrum still listens. The watermark from the
    // previous run keeps history answering.
    let node = start(false);
    wait_listeners(&[rpc_addr, electrum_addr]).await;
    assert_eq!(history_len(electrum_addr, &op_true).await, 3);
    stop_run_p2p(rpc_addr, node).await;

    // A crash left a collect run behind and the write-behind mark short of
    // the tip. Turning the index off kept it, so it resumes under
    // write-behind: a recollect would merge the stale run, and instead the
    // run is discarded, Electrum opens, and the next block lands in history.
    let runs = store.join("scripthash.runs");
    std::fs::create_dir_all(&runs).unwrap();
    let stale_sh = [0xee; 32];
    let mut rec = [0u8; 40];
    rec[..32].copy_from_slice(&stale_sh);
    rec[32..].copy_from_slice(&99u64.to_le_bytes());
    rbitcoin_store::write_sorted_run(&rbitcoin_store::next_run_path(&runs, 50), 40, 40, &rec)
        .unwrap();
    let hwm_path = store.join(rbitcoin_store::INCLUDE_HWM_NAME);
    let hwm = u64::from_le_bytes(std::fs::read(&hwm_path).unwrap().try_into().unwrap());
    std::fs::write(&hwm_path, (hwm - 2).to_le_bytes()).unwrap();
    let node = start(true);
    wait_listeners(&[electrum_addr, rpc_addr]).await;
    assert_eq!(
        rbitcoin_store::list_runs(&runs).unwrap().len(),
        0,
        "leftover run discarded"
    );
    assert_eq!(
        history_len(
            electrum_addr,
            &bitcoin::hex::DisplayHex::to_lower_hex_string(&stale_sh[..])
        )
        .await,
        0
    );
    let mined = jsonrpc(rpc_addr, "generateblock", json!(["raw(51)", []])).await;
    assert!(mined["result"]["hash"].is_string(), "{mined}");
    let deadline = Instant::now() + Duration::from_secs(10);
    while history_len(electrum_addr, &op_true).await < 4 {
        assert!(
            Instant::now() < deadline,
            "write-behind did not reach the tip"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop_run_p2p(rpc_addr, node).await;
}
