//! mempool/electrs `/internal/*` bulk REST and `/mempool/txids/page`.

use crate::handlers::{outspend_json, spawn_join};
use crate::server::{block_hash_hex, not_found, parse_hash32, pin_or_reject, store_err, AppState};
use crate::tx_json::{build_tx_json, build_tx_json_from_tx};
use axum::body::Bytes;
use axum::extract::{Path, Query as AxumQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use rbitcoin_net::{MempoolHub, MempoolTxSnapEntry};
use rbitcoin_query::ChainViewKind;
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_MAX_TXS: usize = 10_000;

#[derive(Deserialize)]
pub struct MaxTxs {
    max_txs: Option<usize>,
}

fn cap_max_txs(q: &MaxTxs) -> usize {
    q.max_txs.unwrap_or(DEFAULT_MAX_TXS).min(DEFAULT_MAX_TXS)
}

fn bad_request(msg: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}

fn parse_txid_array(body: &[u8]) -> Result<Vec<[u8; 32]>, Response> {
    let v: Value = serde_json::from_slice(body).map_err(|_| bad_request("invalid json"))?;
    let arr = v
        .as_array()
        .ok_or_else(|| bad_request("body must be a JSON array of txid hex"))?;
    let mut out = Vec::with_capacity(arr.len());
    for x in arr {
        let s = x
            .as_str()
            .ok_or_else(|| bad_request("txid must be a hex string"))?;
        let id = parse_hash32(s).map_err(|_| bad_request("unparseable txid"))?;
        out.push(id);
    }
    Ok(out)
}

fn entry_json(st: &AppState, mp: &MempoolHub, e: &MempoolTxSnapEntry) -> Value {
    let raw = e.json.get_or_init(|| {
        match build_tx_json_from_tx(
            &st.query,
            &e.tx,
            st.network,
            Some(e.fee_sat as i64),
            Some(mp),
        ) {
            Ok(v) => serde_json::to_string(&v)
                .unwrap_or_else(|_| "{}".into())
                .into(),
            Err(_) => "{}".into(),
        }
    });
    serde_json::from_str(raw).unwrap_or(json!({}))
}

fn confirmed_or_mempool_tx(st: &AppState, id: &[u8; 32]) -> Option<Value> {
    if let Ok(Some((fk, _))) = st.query.get_tx_by_txid(id) {
        return build_tx_json(&st.query, fk, st.network).ok();
    }
    mempool_tx_json(st, id)
}

fn mempool_tx_json(st: &AppState, id: &[u8; 32]) -> Option<Value> {
    let mp = st.mempool.as_ref()?;
    let tid = Txid::from_byte_array(*id);
    if let Some(e) = mp.mempool_tx_snapshot().get(&tid) {
        return Some(entry_json(st, mp, e));
    }
    let tx = mp.get_tx(&tid)?;
    let fee = mp.get_live_meta(&tid).map(|(f, _)| f as i64);
    build_tx_json_from_tx(&st.query, &tx, st.network, fee, Some(mp)).ok()
}

pub async fn post_internal_txs(State(st): State<AppState>, body: Bytes) -> Response {
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    spawn_join(move || {
        let ids = match parse_txid_array(&body) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(v) = confirmed_or_mempool_tx(&st, &id) {
                out.push(v);
            }
        }
        Json(out).into_response()
    })
    .await
}

pub async fn post_internal_mempool_txs(State(st): State<AppState>, body: Bytes) -> Response {
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    spawn_join(move || {
        let ids = match parse_txid_array(&body) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(v) = mempool_tx_json(&st, &id) {
                out.push(v);
            }
        }
        Json(out).into_response()
    })
    .await
}

fn mempool_tx_page(st: &AppState, last: Option<&Txid>, max: usize) -> Vec<Value> {
    let Some(mp) = st.mempool.as_ref() else {
        return Vec::new();
    };
    let snap = mp.mempool_tx_snapshot();
    snap.page(last, max)
        .iter()
        .map(|e| entry_json(st, mp, e))
        .collect()
}

pub async fn get_internal_mempool_txs(
    State(st): State<AppState>,
    AxumQuery(q): AxumQuery<MaxTxs>,
) -> Response {
    let max = cap_max_txs(&q);
    spawn_join(move || Json(mempool_tx_page(&st, None, max)).into_response()).await
}

pub async fn get_internal_mempool_txs_all(State(st): State<AppState>) -> Response {
    spawn_join(move || Json(mempool_tx_page(&st, None, usize::MAX)).into_response()).await
}

pub async fn get_internal_mempool_txs_cursor(
    State(st): State<AppState>,
    Path(last): Path<String>,
    AxumQuery(q): AxumQuery<MaxTxs>,
) -> Response {
    let Ok(id) = parse_hash32(&last) else {
        return bad_request("unparseable txid");
    };
    let last = Txid::from_byte_array(id);
    let max = cap_max_txs(&q);
    spawn_join(move || Json(mempool_tx_page(&st, Some(&last), max)).into_response()).await
}

fn mempool_txid_page(st: &AppState, last: Option<&Txid>, max: usize) -> Vec<String> {
    let Some(mp) = st.mempool.as_ref() else {
        return Vec::new();
    };
    mp.mempool_tx_snapshot()
        .page(last, max)
        .iter()
        .map(|e| block_hash_hex(&e.txid.to_byte_array()))
        .collect()
}

pub async fn get_mempool_txids_page(
    State(st): State<AppState>,
    AxumQuery(q): AxumQuery<MaxTxs>,
) -> Response {
    let max = cap_max_txs(&q);
    spawn_join(move || Json(mempool_txid_page(&st, None, max)).into_response()).await
}

pub async fn get_mempool_txids_page_cursor(
    State(st): State<AppState>,
    Path(last): Path<String>,
    AxumQuery(q): AxumQuery<MaxTxs>,
) -> Response {
    let Ok(id) = parse_hash32(&last) else {
        return bad_request("unparseable txid");
    };
    let last = Txid::from_byte_array(id);
    let max = cap_max_txs(&q);
    spawn_join(move || Json(mempool_txid_page(&st, Some(&last), max)).into_response()).await
}

pub async fn get_internal_block_txs(
    State(st): State<AppState>,
    Path(hash_hex): Path<String>,
) -> Response {
    spawn_join(move || {
        let Ok(hash) = parse_hash32(&hash_hex) else {
            return not_found();
        };
        let Some((header_fk, _)) = (match st.query.get_header_by_hash(&hash) {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }) else {
            return not_found();
        };
        let fks = match st.query.header_tx_fks(header_fk, Some(&hash)) {
            Ok(Some(fks)) => fks,
            Ok(None) => return not_found(),
            Err(e) => return store_err(e),
        };
        let mut out = Vec::with_capacity(fks.len());
        for fk in fks {
            match build_tx_json(&st.query, fk, st.network) {
                Ok(v) => out.push(v),
                Err(e) => return store_err(e),
            }
        }
        Json(out).into_response()
    })
    .await
}

pub async fn post_outspends_by_txid(State(st): State<AppState>, body: Bytes) -> Response {
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    spawn_join(move || {
        let ids = match parse_txid_array(&body) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, None) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mp = st.mempool.as_deref();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let nout = if let Ok(Some(fk)) = st.query.tx_fk_by_txid(&id) {
                match st.query.store().get_tx_meta_and_outputs(fk) {
                    Ok((meta, _)) => meta.output_count,
                    Err(e) => return store_err(e),
                }
            } else if let Some(mp) = mp {
                let tid = Txid::from_byte_array(id);
                mp.get_tx(&tid)
                    .map(|tx| tx.output.len() as u32)
                    .unwrap_or(0)
            } else {
                0
            };
            let mut slots = Vec::with_capacity(nout as usize);
            for vout in 0..nout {
                match outspend_json(&st.query, mp, &id, vout, view.as_ref()) {
                    Ok(v) => slots.push(v),
                    Err(e) => return store_err(e),
                }
            }
            out.push(Value::Array(slots));
        }
        Json(out).into_response()
    })
    .await
}

pub async fn post_outspends_by_outpoint(State(st): State<AppState>, body: Bytes) -> Response {
    if body.len() > st.max_body {
        return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response();
    }
    spawn_join(move || {
        let v: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return bad_request("invalid json"),
        };
        let Some(arr) = v.as_array() else {
            return bad_request("body must be a JSON array of txid:vout");
        };
        let view = match pin_or_reject(&st.query, ChainViewKind::Tip, None) {
            Ok(v) => v,
            Err(r) => return r,
        };
        let mp = st.mempool.as_deref();
        let mut out = Vec::with_capacity(arr.len());
        for x in arr {
            let Some(s) = x.as_str() else {
                out.push(json!({"spent": false}));
                continue;
            };
            let Some((tid_s, vout_s)) = s.rsplit_once(':') else {
                out.push(json!({"spent": false}));
                continue;
            };
            let Ok(txid) = parse_hash32(tid_s) else {
                out.push(json!({"spent": false}));
                continue;
            };
            let Ok(vout) = vout_s.parse::<u32>() else {
                out.push(json!({"spent": false}));
                continue;
            };
            match outspend_json(&st.query, mp, &txid, vout, view.as_ref()) {
                Ok(v) => out.push(v),
                Err(e) => return store_err(e),
            }
        }
        Json(out).into_response()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{run_esplora, EsploraConfig};
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use rbitcoin_consensus::{accept_and_connect_block, ChainParams, Milestone};
    use rbitcoin_net::MempoolHub;
    use rbitcoin_primitives::Height;
    use rbitcoin_query::Query;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn spend_true(cb: Txid, fee: u64, spk: ScriptBuf) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: cb, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - fee),
                script_pubkey: spk,
            }],
        }
    }

    async fn http_post(addr: std::net::SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
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

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
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
        (status, body)
    }

    struct Pad {
        dir: rbitcoin_query::testutil::TempDir,
        q: Arc<Query>,
        hub: Arc<MempoolHub>,
        cbs: Vec<Txid>,
        genesis: bitcoin::BlockHash,
    }

    fn pad_hub(label: &str, n_cb: u32) -> Pad {
        let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled(label);
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        let (_tip, _time, cbs) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            100 + n_cb,
            n_cb,
        );
        let q = Arc::new(q);
        let mp = dir.join("mp");
        std::fs::create_dir_all(&mp).unwrap();
        let hub = MempoolHub::open(&mp, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        Pad {
            dir,
            q,
            hub,
            cbs,
            genesis: genesis.block_hash(),
        }
    }

    #[tokio::test]
    async fn internal_txs() {
        let pad = pad_hub("internal-txs", 3);
        let a = spend_true(pad.cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        pad.hub.accept_tx(&a).unwrap();
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), Some(Arc::clone(&pad.hub)), None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let conf = pad.cbs[1].to_string();
        let mem = a.compute_txid().to_string();
        let unknown = "00".repeat(32);
        let body = serde_json::to_vec(&json!([conf, mem, unknown])).unwrap();
        let (st, resp) = http_post(addr, "/internal/txs", &body).await;
        assert_eq!(st, 200, "{resp}");
        let arr: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(arr.len(), 2, "{resp}");
        let (st, resp) = http_post(addr, "/internal/txs", br#"["zz"]"#).await;
        assert_eq!(st, 400, "{resp}");
        let (st, resp) = http_post(addr, "/internal/txs", b"[]").await;
        assert_eq!(st, 200, "{resp}");
        assert_eq!(resp, "[]");
        handle.shutdown().await;
        let _ = pad.dir;
    }

    #[tokio::test]
    async fn internal_mempool_txs_post() {
        let pad = pad_hub("internal-mp-post", 3);
        let a = spend_true(pad.cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        pad.hub.accept_tx(&a).unwrap();
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), Some(Arc::clone(&pad.hub)), None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let conf = pad.cbs[1].to_string();
        let mem = a.compute_txid().to_string();
        let body = serde_json::to_vec(&json!([conf, mem])).unwrap();
        let (st, resp) = http_post(addr, "/internal/mempool/txs", &body).await;
        assert_eq!(st, 200, "{resp}");
        let arr: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(arr.len(), 1, "confirmed omitted: {resp}");
        handle.shutdown().await;
        let _ = pad.dir;
    }

    #[tokio::test]
    async fn internal_mempool_txs_page() {
        let pad = pad_hub("internal-mp-page", 4);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        for i in 0..3 {
            let t = spend_true(pad.cbs[i], 1_000 + i as u64, spk.clone());
            pad.hub.accept_tx(&t).unwrap();
        }
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), Some(Arc::clone(&pad.hub)), None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let (st, all) = http_get(addr, "/internal/mempool/txs/all").await;
        assert_eq!(st, 200, "{all}");
        let all_arr: Vec<Value> = serde_json::from_str(&all).unwrap();
        assert_eq!(all_arr.len(), 3);
        let (st, p1) = http_get(addr, "/internal/mempool/txs?max_txs=2").await;
        assert_eq!(st, 200, "{p1}");
        let a1: Vec<Value> = serde_json::from_str(&p1).unwrap();
        assert_eq!(a1.len(), 2);
        let last = a1[1]["txid"].as_str().unwrap();
        let (st, p2) = http_get(addr, &format!("/internal/mempool/txs/{last}?max_txs=2")).await;
        assert_eq!(st, 200, "{p2}");
        let a2: Vec<Value> = serde_json::from_str(&p2).unwrap();
        assert_eq!(a2.len(), 1);
        let last2 = a2[0]["txid"].as_str().unwrap();
        let (st, p3) = http_get(addr, &format!("/internal/mempool/txs/{last2}?max_txs=2")).await;
        assert_eq!(st, 200, "{p3}");
        let a3: Vec<Value> = serde_json::from_str(&p3).unwrap();
        assert!(a3.is_empty(), "{p3}");
        handle.shutdown().await;
        let _ = pad.dir;
    }

    #[tokio::test]
    async fn mempool_txids_page() {
        let pad = pad_hub("internal-txids-page", 3);
        pad.hub
            .accept_tx(&spend_true(
                pad.cbs[0],
                1_000,
                ScriptBuf::from_bytes(vec![0x51]),
            ))
            .unwrap();
        pad.hub
            .accept_tx(&spend_true(
                pad.cbs[1],
                2_000,
                ScriptBuf::from_bytes(vec![0x52]),
            ))
            .unwrap();
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), Some(Arc::clone(&pad.hub)), None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let (st, p1) = http_get(addr, "/mempool/txids/page?max_txs=1").await;
        assert_eq!(st, 200, "{p1}");
        let a1: Vec<String> = serde_json::from_str(&p1).unwrap();
        assert_eq!(a1.len(), 1);
        let (st, p2) = http_get(addr, &format!("/mempool/txids/page/{}?max_txs=10", a1[0])).await;
        assert_eq!(st, 200, "{p2}");
        let a2: Vec<String> = serde_json::from_str(&p2).unwrap();
        assert_eq!(a2.len(), 1);
        handle.shutdown().await;
        let _ = pad.dir;
    }

    #[tokio::test]
    async fn internal_block_txs() {
        let pad = pad_hub("internal-block-txs", 1);
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), None, None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let g = pad.genesis.to_string();
        let (st, body) = http_get(addr, &format!("/internal/block/{g}/txs")).await;
        assert_eq!(st, 200, "{body}");
        let arr: Vec<Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(arr.len(), 1, "genesis coinbase");
        assert_eq!(arr[0]["vin"][0]["is_coinbase"], true);
        let (st, pubp) = http_get(addr, &format!("/block/{g}/txs")).await;
        assert_eq!(st, 200, "{pubp}");
        let pub_arr: Vec<Value> = serde_json::from_str(&pubp).unwrap();
        assert_eq!(pub_arr.len(), 1);
        let (st, miss) = http_get(addr, &format!("/internal/block/{}/txs", "11".repeat(32))).await;
        assert_eq!(st, 404, "{miss}");
        handle.shutdown().await;
        let _ = pad.dir;
    }

    #[tokio::test]
    async fn internal_outspends() {
        let pad = pad_hub("internal-outspends", 3);
        let a = spend_true(pad.cbs[0], 1_000, ScriptBuf::from_bytes(vec![0x51]));
        pad.hub.accept_tx(&a).unwrap();
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&pad.q), Some(Arc::clone(&pad.hub)), None)
            .await
            .unwrap();
        let addr = handle.local_addr;
        let spent = pad.cbs[0].to_string();
        let unknown = "ff".repeat(32);
        let body = serde_json::to_vec(&json!([spent, unknown])).unwrap();
        let (st, resp) = http_post(addr, "/internal/txs/outspends/by-txid", &body).await;
        assert_eq!(st, 200, "{resp}");
        let arr: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(arr.len(), 2, "same-length slots");
        assert_eq!(arr[0][0]["spent"], true);
        assert!(arr[0][0].get("vin").is_some(), "{resp}");
        assert_eq!(arr[1], json!([]));
        let op = format!("{}:0", spent);
        let body = serde_json::to_vec(&json!([op, "bad"])).unwrap();
        let (st, resp) = http_post(addr, "/internal/txs/outspends/by-outpoint", &body).await;
        assert_eq!(st, 200, "{resp}");
        let arr: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["spent"], true);
        assert_eq!(arr[1]["spent"], false);
        handle.shutdown().await;
        let _ = pad.dir;
    }
}
