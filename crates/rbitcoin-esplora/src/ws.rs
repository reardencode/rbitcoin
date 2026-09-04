//! Wallet-scoped WebSocket live updates (mempool.space-style message names).
//!
//! Payloads use Esplora REST shapes. Global mempool/RBF explorer feeds are out of scope.

use crate::handlers::resolve_address_sh;
use crate::server::AppState;
use crate::tx_json::{build_tx_json, build_tx_json_from_tx, tx_status_json};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Network, Transaction, Txid};
use futures_util::{SinkExt, StreamExt};
use rbitcoin_net::{MempoolAnnounce, MempoolHub, TipEvent};
use rbitcoin_primitives::{hex_encode, Height};
use rbitcoin_query::Query;
use rbitcoin_store::script_hash;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{broadcast, OwnedSemaphorePermit};

/// Parse one client JSON text frame (pure; unit-tested).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClientMsg {
    Want(Vec<String>),
    TrackAddress(String),
    TrackAddresses(Vec<String>),
    StopTrackAddress(Option<String>),
    StopTrackAddresses,
    TrackTx(String),
    TrackTxs(Vec<String>),
    StopTrackTx(Option<String>),
    StopTrackTxs,
    /// Recognized JSON object with no actionable keys (ignore).
    Noop,
}

pub(crate) fn parse_client_msg(text: &str) -> Result<ClientMsg, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid json: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "client message must be a JSON object".to_string())?;

    if let Some(action) = obj.get("action").and_then(|a| a.as_str()) {
        if action == "want" {
            let data = obj
                .get("data")
                .and_then(|d| d.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Ok(ClientMsg::Want(data));
        }
    }

    if let Some(v) = obj.get("track-address") {
        if v.is_null() || v.as_bool() == Some(false) {
            return Ok(ClientMsg::StopTrackAddresses);
        }
        if let Some(s) = v.as_str() {
            if s.is_empty() {
                return Ok(ClientMsg::StopTrackAddresses);
            }
            return Ok(ClientMsg::TrackAddress(s.to_string()));
        }
    }
    if let Some(v) = obj.get("track-addresses") {
        if v.is_null() || (v.as_array().is_some_and(|a| a.is_empty())) {
            return Ok(ClientMsg::StopTrackAddresses);
        }
        if let Some(arr) = v.as_array() {
            let addrs: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            return Ok(ClientMsg::TrackAddresses(addrs));
        }
    }
    if let Some(v) = obj.get("stop-track-address") {
        if v.as_bool() == Some(true) || v.is_null() {
            return Ok(ClientMsg::StopTrackAddresses);
        }
        if let Some(s) = v.as_str() {
            return Ok(ClientMsg::StopTrackAddress(Some(s.to_string())));
        }
    }
    if obj.get("stop-track-addresses").is_some() {
        return Ok(ClientMsg::StopTrackAddresses);
    }

    if let Some(v) = obj.get("track-tx") {
        if v.is_null() || v.as_bool() == Some(false) {
            return Ok(ClientMsg::StopTrackTxs);
        }
        if let Some(s) = v.as_str() {
            if s.is_empty() {
                return Ok(ClientMsg::StopTrackTxs);
            }
            return Ok(ClientMsg::TrackTx(s.to_string()));
        }
    }
    if let Some(v) = obj.get("track-txs") {
        if v.is_null() || (v.as_array().is_some_and(|a| a.is_empty())) {
            return Ok(ClientMsg::StopTrackTxs);
        }
        if let Some(arr) = v.as_array() {
            let ids: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            return Ok(ClientMsg::TrackTxs(ids));
        }
    }
    if let Some(v) = obj.get("stop-track-tx") {
        if v.as_bool() == Some(true) || v.is_null() {
            return Ok(ClientMsg::StopTrackTxs);
        }
        if let Some(s) = v.as_str() {
            return Ok(ClientMsg::StopTrackTx(Some(s.to_string())));
        }
    }
    if obj.get("stop-track-txs").is_some() {
        return Ok(ClientMsg::StopTrackTxs);
    }

    Ok(ClientMsg::Noop)
}

struct ConnState {
    want_blocks: bool,
    /// scripthash → display address (as client sent).
    addresses: HashMap<[u8; 32], String>,
    txids: HashSet<Txid>,
    /// Last pushed confirmed flag per tracked txid.
    last_confirmed: HashMap<Txid, bool>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            want_blocks: false,
            addresses: HashMap::new(),
            txids: HashSet::new(),
            last_confirmed: HashMap::new(),
        }
    }
}

fn parse_txid_hex(s: &str) -> Result<Txid, String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err("txid must be 64 hex chars".into());
    }
    let mut rev = [0u8; 32];
    // Esplora / display order is reversed internal byte order.
    let bytes = rbitcoin_primitives::hex_decode(s).map_err(|_| "invalid txid hex".to_string())?;
    if bytes.len() != 32 {
        return Err("txid must be 32 bytes".into());
    }
    for i in 0..32 {
        rev[i] = bytes[31 - i];
    }
    Ok(Txid::from_byte_array(rev))
}

fn txid_display_hex(txid: &Txid) -> String {
    let b = txid.to_byte_array();
    let mut rev = b;
    rev.reverse();
    hex_encode(rev)
}

fn scripts_touched(tx: &Transaction) -> HashSet<[u8; 32]> {
    let mut set = HashSet::new();
    for o in &tx.output {
        set.insert(script_hash(o.script_pubkey.as_bytes()));
    }
    // Input scriptPubKeys are not on the wire; caller may enrich via prevouts.
    let _ = &tx.input;
    set
}

/// Resolve input script hashes from chain/mempool when possible.
fn scripts_touched_full(
    query: &Query,
    mempool: Option<&rbitcoin_net::MempoolHub>,
    tx: &Transaction,
) -> HashSet<[u8; 32]> {
    let mut set = scripts_touched(tx);
    for inp in &tx.input {
        if inp.previous_output.is_null() {
            continue;
        }
        let prev_txid = inp.previous_output.txid;
        let vout = inp.previous_output.vout;
        if let Some(prev) = mempool.and_then(|m| m.get_tx(&prev_txid)) {
            if let Some(o) = prev.output.get(vout as usize) {
                set.insert(script_hash(o.script_pubkey.as_bytes()));
            }
            continue;
        }
        if let Ok(Some((fk, _))) = query.get_tx_by_txid(&prev_txid.to_byte_array()) {
            if let Ok((_, outs)) = query.store().get_tx_meta_and_outputs(fk) {
                if let Some(o) = outs.get(vout as usize) {
                    set.insert(script_hash(&o.script));
                }
            }
        }
    }
    set
}

fn tip_push_json(ev: &TipEvent) -> Value {
    let mut header_bytes = Vec::with_capacity(80);
    let _ = ev.header.consensus_encode(&mut header_bytes);
    let hash = ev.hash.to_byte_array();
    let mut rev = hash;
    rev.reverse();
    json!({
        "block": {
            "height": ev.height,
            "id": hex_encode(rev),
            "timestamp": ev.header.time,
        }
    })
}

async fn send_json(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    v: &Value,
) -> Result<(), ()> {
    let s = v.to_string();
    sink.send(Message::Text(s.into())).await.map_err(|_| ())
}

async fn send_error(
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    msg: &str,
) -> Result<(), ()> {
    send_json(sink, &json!({ "error": msg })).await
}

/// HTTP upgrade entry (own semaphore; not under REST concurrency layer).
pub async fn ws_upgrade(ws: WebSocketUpgrade, State(st): State<AppState>) -> Response {
    let Some(sem) = st.ws_sem.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "websocket disabled").into_response();
    };
    let permit = match sem.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "too many websocket connections",
            )
                .into_response();
        }
    };
    let max_msg = st.max_ws_message_bytes.max(1024);
    ws.max_message_size(max_msg)
        .max_frame_size(max_msg)
        .on_upgrade(move |socket| handle_socket(socket, st, permit))
        .into_response()
}

async fn handle_socket(socket: WebSocket, st: AppState, _permit: OwnedSemaphorePermit) {
    let (mut sink, mut stream) = socket.split();
    let mut conn = ConnState::new();
    let mut tip_rx = st.tip_tx.as_ref().map(|tx| tx.subscribe());
    let mut mempool_rx = st.mempool.as_ref().map(|m| m.subscribe_announces());

    loop {
        tokio::select! {
            biased;
            tip = async {
                match tip_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => {
                        std::future::pending::<()>().await;
                        None
                    }
                }
            } => {
                if let Some(msg) = tip {
                    match msg {
                        Ok(ev) => {
                            if conn.want_blocks {
                                if send_json(&mut sink, &tip_push_json(&ev)).await.is_err() {
                                    break;
                                }
                            }
                            if on_tip(&st, &mut conn, &ev, &mut sink).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            tip_rx = None;
                        }
                    }
                }
            }
            ann = async {
                match mempool_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => {
                        std::future::pending::<()>().await;
                        None
                    }
                }
            } => {
                if let Some(msg) = ann {
                    match msg {
                        Ok(a) => {
                            if on_mempool_announce(&st, &mut conn, &a, &mut sink).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => {
                            mempool_rx = None;
                        }
                    }
                }
            }
            frame = stream.next() => {
                match frame {
                    Some(Ok(Message::Text(text))) => {
                        if text.len() > st.max_ws_message_bytes {
                            let _ = send_error(&mut sink, "message too large").await;
                            break;
                        }
                        match parse_client_msg(text.as_str()) {
                            Ok(msg) => {
                                if handle_client_msg(&st, &mut conn, msg, &mut sink).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                if send_error(&mut sink, &e).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Ping(p))) => {
                        if sink.send(Message::Pong(p)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}

async fn handle_client_msg(
    st: &AppState,
    conn: &mut ConnState,
    msg: ClientMsg,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    match msg {
        ClientMsg::Want(data) => {
            // Only `blocks` is supported; other tokens no-op (wallet-not-explorer).
            conn.want_blocks = data.iter().any(|s| s == "blocks");
            Ok(())
        }
        ClientMsg::TrackAddress(addr) => add_addresses(st, conn, &[addr], sink).await,
        ClientMsg::TrackAddresses(addrs) => add_addresses(st, conn, &addrs, sink).await,
        ClientMsg::StopTrackAddress(Some(addr)) => {
            if let Ok(sh) = resolve_address_sh(&addr, st.network) {
                conn.addresses.remove(&sh);
            }
            Ok(())
        }
        ClientMsg::StopTrackAddress(None) | ClientMsg::StopTrackAddresses => {
            conn.addresses.clear();
            Ok(())
        }
        ClientMsg::TrackTx(id) => add_txids(conn, &[id], st.max_track_txs, sink).await,
        ClientMsg::TrackTxs(ids) => add_txids(conn, &ids, st.max_track_txs, sink).await,
        ClientMsg::StopTrackTx(Some(id)) => {
            if let Ok(t) = parse_txid_hex(&id) {
                conn.txids.remove(&t);
                conn.last_confirmed.remove(&t);
            }
            Ok(())
        }
        ClientMsg::StopTrackTx(None) | ClientMsg::StopTrackTxs => {
            conn.txids.clear();
            conn.last_confirmed.clear();
            Ok(())
        }
        ClientMsg::Noop => Ok(()),
    }
}

async fn add_addresses(
    st: &AppState,
    conn: &mut ConnState,
    addrs: &[String],
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    for addr in addrs {
        if conn.addresses.len() >= st.max_track_addresses {
            send_error(sink, "max_track_addresses exceeded").await?;
            return Ok(());
        }
        match resolve_address_sh(addr, st.network) {
            Ok(sh) => {
                conn.addresses.insert(sh, addr.clone());
            }
            Err(()) => {
                send_error(sink, &format!("invalid address: {addr}")).await?;
            }
        }
    }
    Ok(())
}

async fn add_txids(
    conn: &mut ConnState,
    ids: &[String],
    max: usize,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    for id in ids {
        if conn.txids.len() >= max {
            send_error(sink, "max_track_txs exceeded").await?;
            return Ok(());
        }
        match parse_txid_hex(id) {
            Ok(t) => {
                conn.txids.insert(t);
            }
            Err(e) => {
                send_error(sink, &e).await?;
            }
        }
    }
    Ok(())
}

struct MempoolAnnounceFrames {
    replaced: Option<Value>,
    address_txs: Option<Value>,
    tx_status: bool,
}

fn mempool_announce_frames(
    query: &Query,
    mempool: Option<&MempoolHub>,
    network: Network,
    watched: &HashMap<[u8; 32], String>,
    tracked: &HashSet<Txid>,
    ann: &MempoolAnnounce,
) -> MempoolAnnounceFrames {
    let mut replaced = None;
    if !ann.replaced.is_empty() {
        let addr_hit_old = !watched.is_empty()
            && ann
                .replaced_scripthashes
                .iter()
                .any(|sh| watched.contains_key(sh));
        let mut addr_hit_new = false;
        if !watched.is_empty() {
            if let Some(m) = mempool {
                if let Some(tx) = m.get_tx(&ann.txid) {
                    let shs = scripts_touched_full(query, Some(m), &tx);
                    addr_hit_new = shs.iter().any(|s| watched.contains_key(s));
                }
            }
        }
        let mut replaced_for_client = Vec::new();
        for old in &ann.replaced {
            if tracked.contains(old) || addr_hit_old || addr_hit_new {
                replaced_for_client.push(json!({
                    "txid": txid_display_hex(old),
                    "replaced-by": txid_display_hex(&ann.txid),
                }));
            }
        }
        if !replaced_for_client.is_empty() {
            replaced = Some(json!({ "replaced-transactions": replaced_for_client }));
        }
    }

    let Some(m) = mempool else {
        return MempoolAnnounceFrames {
            replaced,
            address_txs: None,
            tx_status: tracked.contains(&ann.txid),
        };
    };
    let Some(tx) = m.get_tx(&ann.txid) else {
        return MempoolAnnounceFrames {
            replaced,
            address_txs: None,
            tx_status: tracked.contains(&ann.txid),
        };
    };

    let mut address_txs = None;
    if !watched.is_empty() {
        let shs = scripts_touched_full(query, Some(m), &tx);
        if shs.iter().any(|s| watched.contains_key(s)) {
            let body = match query.get_tx_by_txid(&ann.txid.to_byte_array()) {
                Ok(Some((fk, _))) => build_tx_json(query, fk, network).unwrap_or_else(|_| {
                    build_tx_json_from_tx(query, &tx, network, None, Some(m))
                        .unwrap_or_else(|_| json!({ "txid": txid_display_hex(&ann.txid) }))
                }),
                _ => build_tx_json_from_tx(query, &tx, network, None, Some(m))
                    .unwrap_or_else(|_| json!({ "txid": txid_display_hex(&ann.txid) })),
            };
            address_txs = Some(json!({ "address-transactions": [body] }));
        }
    }

    MempoolAnnounceFrames {
        replaced,
        address_txs,
        tx_status: tracked.contains(&ann.txid),
    }
}

async fn on_mempool_announce(
    st: &AppState,
    conn: &mut ConnState,
    ann: &MempoolAnnounce,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    let query = Arc::clone(&st.query);
    let mempool = st.mempool.clone();
    let network = st.network;
    let watched = conn.addresses.clone();
    let tracked = conn.txids.clone();
    let txid = ann.txid;
    let ann = ann.clone();
    let frames = match tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::BlockingRegion::enter();
        mempool_announce_frames(
            query.as_ref(),
            mempool.as_deref(),
            network,
            &watched,
            &tracked,
            &ann,
        )
    })
    .await
    {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };

    if let Some(v) = frames.replaced {
        send_json(sink, &v).await?;
    }
    if let Some(v) = frames.address_txs {
        send_json(sink, &v).await?;
    }
    if frames.tx_status {
        push_tx_status(st, conn, &txid, sink).await?;
    }
    Ok(())
}

async fn push_tx_status(
    st: &AppState,
    conn: &mut ConnState,
    txid: &Txid,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    let status = tx_status_for(st, txid);
    let confirmed = status
        .get("confirmed")
        .and_then(|c| c.as_bool())
        .unwrap_or(false);
    let prev = conn.last_confirmed.get(txid).copied();
    if prev == Some(confirmed) {
        return Ok(());
    }
    conn.last_confirmed.insert(*txid, confirmed);
    send_json(
        sink,
        &json!({
            "tx": {
                "txid": txid_display_hex(txid),
                "status": status,
            }
        }),
    )
    .await
}

fn tx_status_for(st: &AppState, txid: &Txid) -> Value {
    let bytes = txid.to_byte_array();
    if let Ok(Some((fk, _))) = st.query.get_tx_by_txid(&bytes) {
        if let Ok(s) = tx_status_json(&st.query, fk) {
            return s;
        }
    }
    if st
        .mempool
        .as_ref()
        .map(|m| m.contains(txid))
        .unwrap_or(false)
    {
        return json!({ "confirmed": false });
    }
    json!({ "confirmed": false })
}

async fn on_tip(
    st: &AppState,
    conn: &mut ConnState,
    ev: &TipEvent,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    if !conn.addresses.is_empty() {
        let mut txs = Vec::new();
        for sh in conn.addresses.keys() {
            let Ok(fks) = st.query.scripthash_tx_fks_at_height(sh, Height(ev.height)) else {
                continue;
            };
            for fk in fks {
                if let Ok(v) = build_tx_json(&st.query, fk, st.network) {
                    txs.push(v);
                }
            }
        }
        if !txs.is_empty() {
            send_json(sink, &json!({ "block-transactions": txs })).await?;
        }
    }

    let tracked: Vec<Txid> = conn.txids.iter().copied().collect();
    for t in tracked {
        push_tx_status(st, conn, &t, sink).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_want_blocks_and_unknown_tokens() {
        let m = parse_client_msg(r#"{"action":"want","data":["blocks","stats"]}"#).unwrap();
        assert_eq!(m, ClientMsg::Want(vec!["blocks".into(), "stats".into()]));
    }

    #[test]
    fn parse_track_and_stop_address() {
        assert_eq!(
            parse_client_msg(r#"{"track-address":"bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8z5y2"}"#)
                .unwrap(),
            ClientMsg::TrackAddress("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8z5y2".into())
        );
        assert_eq!(
            parse_client_msg(r#"{"track-addresses":["a","b"]}"#).unwrap(),
            ClientMsg::TrackAddresses(vec!["a".into(), "b".into()])
        );
        assert_eq!(
            parse_client_msg(r#"{"stop-track-addresses":true}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
        assert_eq!(
            parse_client_msg(r#"{"track-address":""}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
    }

    #[test]
    fn parse_track_tx() {
        let id = "0".repeat(64);
        assert_eq!(
            parse_client_msg(&format!(r#"{{"track-tx":"{id}"}}"#)).unwrap(),
            ClientMsg::TrackTx(id.clone())
        );
        assert_eq!(
            parse_client_msg(&format!(r#"{{"track-txs":["{id}"]}}"#)).unwrap(),
            ClientMsg::TrackTxs(vec![id])
        );
        assert_eq!(
            parse_client_msg(r#"{"stop-track-txs":true}"#).unwrap(),
            ClientMsg::StopTrackTxs
        );
    }

    #[test]
    fn parse_noop_and_bad_json() {
        assert_eq!(parse_client_msg(r#"{"foo":1}"#).unwrap(), ClientMsg::Noop);
        assert!(parse_client_msg("not-json").is_err());
    }
}
