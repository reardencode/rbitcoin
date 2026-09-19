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
use rbitcoin_test::TestDatadir;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::str::FromStr;
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

async fn pin_address_prefix_404(esplora_addr: SocketAddr) {
    let (st, body) = http_get(esplora_addr, "/address-prefix/bc1").await;
    assert_eq!(st, 404, "address-prefix stays 404: {body}");
}

async fn pin_internal_mempool_txs(esplora_addr: SocketAddr, live_txid: &str) {
    let (st, body) = http_get(esplora_addr, "/internal/mempool/txs?max_txs=10000").await;
    assert_eq!(st, 200, "GET /internal/mempool/txs: {body}");
    let arr: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert!(
        arr.iter().any(|t| t["txid"] == live_txid),
        "internal mempool dump missing {live_txid}: {body}"
    );
    let payload = json!([live_txid, "ff".repeat(32)]).to_string();
    let (st, body) = http_post_json(esplora_addr, "/internal/mempool/txs", &payload).await;
    assert_eq!(st, 200, "POST /internal/mempool/txs: {body}");
    let arr: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(arr.len(), 1, "unknown mempool id omitted: {body}");
    assert_eq!(arr[0]["txid"], live_txid, "{body}");
}

async fn pin_internal_block_txs_and_outspends(
    esplora_addr: SocketAddr,
    block_hash: &str,
    n_tx: usize,
    spent_txid: &str,
) {
    let (st, body) = http_get(esplora_addr, &format!("/internal/block/{block_hash}/txs")).await;
    assert_eq!(st, 200, "GET /internal/block/…/txs: {body}");
    let arr: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(
        arr.len(),
        n_tx,
        "internal block txs is the full list: {body}"
    );
    let (st, pub_body) = http_get(esplora_addr, &format!("/block/{block_hash}/txs")).await;
    assert_eq!(st, 200, "public /txs page: {pub_body}");
    let pub_arr: Vec<Value> = serde_json::from_str(&pub_body).unwrap();
    assert_eq!(pub_arr.len(), 25, "public /txs stays 25/page: {pub_body}");
    let unknown = "ff".repeat(32);
    let payload = json!([spent_txid, unknown]).to_string();
    let (st, body) =
        http_post_json(esplora_addr, "/internal/txs/outspends/by-txid", &payload).await;
    assert_eq!(st, 200, "POST outspends/by-txid: {body}");
    let arr: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(arr.len(), 2, "same-length outspend slots: {body}");
    assert_eq!(arr[0][0]["spent"], true, "{body}");
    assert!(arr[0][0].get("vin").is_some(), "{body}");
    assert_eq!(arr[1], json!([]), "unknown tx keeps [] slot: {body}");
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
    let (st, body, empty) =
        esplora_json_array(esplora_addr, &format!("/block/{tip_hash}/txs/{next}")).await;
    assert_eq!(st, 200, "one-past last page: {body}");
    assert!(empty.is_empty(), "Esplora empty page is [] not 404: {body}");
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

/// B13: one live `want: blocks` + `track-tx` on this `run_p2p` process.
async fn spawn_esplora_ws_want_blocks_and_track_tx(
    esplora_addr: SocketAddr,
    track_txid: String,
) -> tokio::task::JoinHandle<(bool, bool)> {
    tokio::spawn(async move {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        let url = format!("ws://{esplora_addr}/v1/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("esplora ws upgrade");
        tokio::time::sleep(Duration::from_millis(150)).await;
        ws.send(WsMsg::Text(r#"{"action":"want","data":["blocks"]}"#.into()))
            .await
            .unwrap();
        ws.send(WsMsg::Text(
            format!(r#"{{"track-tx":"{track_txid}"}}"#).into(),
        ))
        .await
        .unwrap();
        let mut saw = (false, false);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !(saw.0 && saw.1) {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(Some(Ok(WsMsg::Text(t)))) = tokio::time::timeout(left, ws.next()).await else {
                break;
            };
            let v: Value = serde_json::from_str(t.as_str()).unwrap_or(json!(null));
            saw.0 |= v["block"]["height"] == 107;
            saw.1 |= v["tx"]["txid"] == track_txid && v["tx"]["status"]["confirmed"] == true;
        }
        saw
    })
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

    let mut cfg = NodeConfig::default()
        .with_datadir(td.path())
        .with_network(Network::Regtest)
        .with_tiny_heads()
        .with_p2p_listen("127.0.0.1:0".parse().unwrap());
    cfg.listen.use_seeds = false;
    cfg.listen.connect.clear();
    cfg.shindex = true;
    cfg.listen.electrum = Some(electrum_addr);
    cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora_addr));
    cfg.rpc.listen = Some(rpc_addr);
    cfg.rpc.socket = true;
    std::fs::write(td.path().join("rpc.token"), "pass").unwrap();
    cfg.max_run_secs = Some(90);

    let node = tokio::spawn(run_p2p(cfg));
    wait_listeners(&[electrum_addr, esplora_addr, rpc_addr]).await;
    pin_address_prefix_404(esplora_addr).await;
    #[cfg(unix)]
    {
        let rpc_sock = td.path().join("rpc.sock");
        wait_unix_socket(&rpc_sock).await;
        let unix_count = jsonrpc_unix(&rpc_sock, "getblockcount", json!([])).await;
        assert_eq!(
            unix_count["result"], 106,
            "unix rpc.sock getblockcount without Authorization: {unix_count}"
        );
    }

    let (st, height) = http_get(esplora_addr, "/blocks/tip/height").await;
    assert_eq!(st, 200, "esplora tip height: {height}");
    assert_eq!(height, "106");
    let count = jsonrpc(rpc_addr, "getblockcount", json!([])).await;
    assert_eq!(count["result"], 106, "{count}");
    let chain = jsonrpc(rpc_addr, "getblockchaininfo", json!([])).await;
    assert_eq!(chain["result"]["initialblockdownload"], true, "{chain}");
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
    assert_eq!(
        tma["result"][0]["reject-reason"], "bad-txns-inputs-missingorspent",
        "{tma}"
    );

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
    pin_internal_mempool_txs(esplora_addr, &pkg_parent_txid).await;
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
    let (st, body) = http_get(esplora_addr, "/fee-estimates").await;
    assert_eq!(st, 200, "GET /fee-estimates: {body}");
    let fees: Value = serde_json::from_str(&body).unwrap();
    for key in ["1", "5", "144", "504", "1008"] {
        let v = fees[key].as_f64().unwrap_or(-1.0);
        assert!(v > 0.0, "{key} sat/vB: {fees}");
    }
    let near = fees["1"].as_f64().unwrap();
    let far = fees["144"].as_f64().unwrap();
    assert!(near > 0.0 && far > 0.0, "near={near} far={far}: {fees}");
    let (st, body) = http_get(esplora_addr, "/fees/recommended").await;
    assert_eq!(st, 200, "GET /fees/recommended: {body}");
    let rec: Value = serde_json::from_str(&body).unwrap();
    for key in [
        "fastestFee",
        "halfHourFee",
        "hourFee",
        "economyFee",
        "minimumFee",
    ] {
        let n = rec[key].as_u64().unwrap_or(0);
        assert!(n >= 1, "{key} sat/vB: {body}");
    }
    let (st, body) = http_get(esplora_addr, "/v1/fees/recommended").await;
    assert_eq!(st, 200, "GET /v1/fees/recommended: {body}");

    let tip_before = jsonrpc(rpc_addr, "getbestblockhash", json!([])).await;
    let tip_hash = tip_before["result"].as_str().expect("tip hash").to_string();
    pin_waitforblockheight_timeout_zero_behind(rpc_addr, 106, &tip_hash).await;
    pin_getblock_hash_oob_unknown_and_raw(rpc_addr, 106, &tip_hash).await;
    let waiters = spawn_wait_and_gbt_longpoll(rpc_addr, 107).await;
    let ws = spawn_esplora_ws_want_blocks_and_track_tx(esplora_addr, pkg_parent_txid.clone()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

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
    let (saw_block, saw_tx) = tokio::time::timeout(Duration::from_secs(10), ws)
        .await
        .expect("esplora ws timed out")
        .expect("esplora ws join");
    assert!(saw_block, "ws want:blocks must push the generate tip");
    assert!(
        saw_tx,
        "ws track-tx must confirm {pkg_parent_txid} on generate"
    );
    let blk = jsonrpc(rpc_addr, "getblock", json!([tip["result"].clone(), 2])).await;
    let txs = blk["result"]["tx"].as_array().expect("mined tx array");
    assert!(
        txs.len() >= 30,
        "coinbase + RBF + esplora + packages: {blk}"
    );
    pin_esplora_blocks_summaries(esplora_addr, 107, new_hash).await;
    pin_esplora_block_txs_pages(esplora_addr, new_hash, txs.len()).await;
    pin_internal_block_txs_and_outspends(esplora_addr, new_hash, txs.len(), &cb_hex).await;
    assert!(
        txs[0]["vin"][0].get("txid").is_some(),
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
    let cap_err = capped["result"]["tx-results"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(|v| v["error"].as_str())
        .unwrap_or("");
    assert_eq!(cap_err, "max-fee-exceeded", "{capped}");

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
        n26_msg.contains("package too large"),
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
