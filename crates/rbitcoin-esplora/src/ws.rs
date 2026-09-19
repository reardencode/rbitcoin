//! Wallet-scoped WebSocket live updates (mempool.space-style message names).
//!
//! Payloads use Esplora REST shapes. Global mempool/RBF explorer feeds are out of scope.

use crate::handlers::{fees_recommended_json, mempool_info_json, resolve_address_sh};
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
use rbitcoin_net::{MempoolAnnounce, MempoolHub, MempoolTxSnapshot, TipEvent};
use rbitcoin_primitives::{display_hash_hex, Height};
use rbitcoin_query::Query;
use rbitcoin_store::script_hash;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
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
    Ping,
    Init,
}

fn json_str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_want_action(obj: &serde_json::Map<String, Value>) -> Option<ClientMsg> {
    let action = obj.get("action").and_then(|a| a.as_str())?;
    match action {
        "want" => {
            let data = obj.get("data").map(json_str_list).unwrap_or_default();
            Some(ClientMsg::Want(data))
        }
        "ping" => Some(ClientMsg::Ping),
        "init" => Some(ClientMsg::Init),
        _ => None,
    }
}

fn parse_address_track(obj: &serde_json::Map<String, Value>) -> Option<ClientMsg> {
    if let Some(v) = obj.get("track-address") {
        if v.is_null() || v.as_bool() == Some(false) {
            return Some(ClientMsg::StopTrackAddresses);
        }
        if let Some(s) = v.as_str() {
            if s.is_empty() || s.eq_ignore_ascii_case("stop") {
                return Some(ClientMsg::StopTrackAddresses);
            }
            return Some(ClientMsg::TrackAddress(s.to_string()));
        }
    }
    if let Some(v) = obj.get("track-addresses") {
        if v.is_null() || (v.as_array().is_some_and(|a| a.is_empty())) {
            return Some(ClientMsg::StopTrackAddresses);
        }
        if let Some(arr) = v.as_array() {
            let addrs: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            return Some(ClientMsg::TrackAddresses(addrs));
        }
    }
    if let Some(v) = obj.get("stop-track-address") {
        if v.as_bool() == Some(true) || v.is_null() {
            return Some(ClientMsg::StopTrackAddresses);
        }
        if let Some(s) = v.as_str() {
            return Some(ClientMsg::StopTrackAddress(Some(s.to_string())));
        }
    }
    if obj.get("stop-track-addresses").is_some() {
        return Some(ClientMsg::StopTrackAddresses);
    }
    None
}

fn parse_tx_track(obj: &serde_json::Map<String, Value>) -> Option<ClientMsg> {
    if let Some(v) = obj.get("track-tx") {
        if v.is_null() || v.as_bool() == Some(false) {
            return Some(ClientMsg::StopTrackTxs);
        }
        if let Some(s) = v.as_str() {
            if s.is_empty() || s.eq_ignore_ascii_case("stop") {
                return Some(ClientMsg::StopTrackTxs);
            }
            return Some(ClientMsg::TrackTx(s.to_string()));
        }
    }
    if let Some(v) = obj.get("track-txs") {
        if v.is_null() || (v.as_array().is_some_and(|a| a.is_empty())) {
            return Some(ClientMsg::StopTrackTxs);
        }
        if let Some(arr) = v.as_array() {
            let ids: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect();
            return Some(ClientMsg::TrackTxs(ids));
        }
    }
    if let Some(v) = obj.get("stop-track-tx") {
        if v.as_bool() == Some(true) || v.is_null() {
            return Some(ClientMsg::StopTrackTxs);
        }
        if let Some(s) = v.as_str() {
            return Some(ClientMsg::StopTrackTx(Some(s.to_string())));
        }
    }
    if obj.get("stop-track-txs").is_some() {
        return Some(ClientMsg::StopTrackTxs);
    }
    None
}

pub(crate) fn parse_client_msg(text: &str) -> Result<ClientMsg, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid json: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "client message must be a JSON object".to_string())?;
    if let Some(m) = parse_want_action(obj) {
        return Ok(m);
    }
    if let Some(m) = parse_address_track(obj) {
        return Ok(m);
    }
    if let Some(m) = parse_tx_track(obj) {
        return Ok(m);
    }
    Ok(ClientMsg::Noop)
}

struct ConnState {
    want_blocks: bool,
    want_stats: bool,
    /// scripthash → display address (as client sent).
    addresses: HashMap<[u8; 32], String>,
    txids: HashSet<Txid>,
    /// Last pushed confirmed flag per tracked txid.
    last_confirmed: HashMap<Txid, bool>,
    last_stats_snap: Option<Arc<MempoolTxSnapshot>>,
    last_stats_push: Option<Instant>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            want_blocks: false,
            want_stats: false,
            addresses: HashMap::new(),
            txids: HashSet::new(),
            last_confirmed: HashMap::new(),
            last_stats_snap: None,
            last_stats_push: None,
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
    display_hash_hex(&txid.to_byte_array())
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
    json!({
        "block": {
            "height": ev.height,
            "id": display_hash_hex(&hash),
            "timestamp": ev.header.time,
        }
    })
}

fn init_tip_json(query: &Query) -> Option<Value> {
    let h = query.tip_height()?;
    let rec = query.header_at_height(h).ok()??.1;
    Some(json!({
        "block": {
            "height": h.0,
            "id": display_hash_hex(&rec.hash),
            "timestamp": rec.timestamp,
        }
    }))
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

/// Match fee-snapshot max age: re-push stats at most this often when the tx Arc is unchanged.
const STATS_PUSH_MIN_AGE: Duration = Duration::from_secs(1);

fn stats_frame(mp: Option<&MempoolHub>) -> Value {
    json!({
        "mempoolInfo": mempool_info_json(mp),
        "fees": fees_recommended_json(mp),
    })
}

async fn push_stats(
    st: &AppState,
    conn: &mut ConnState,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    force: bool,
) -> Result<(), ()> {
    if !conn.want_stats {
        return Ok(());
    }
    let mp = st.mempool.as_deref();
    let snap = mp.map(|m| m.mempool_tx_snapshot());
    if !force {
        let same_snap = match (&conn.last_stats_snap, &snap) {
            (Some(prev), Some(cur)) => Arc::ptr_eq(prev, cur),
            (None, None) => true,
            _ => false,
        };
        let fresh = conn
            .last_stats_push
            .is_some_and(|t| t.elapsed() < STATS_PUSH_MIN_AGE);
        if same_snap && fresh {
            return Ok(());
        }
    }
    send_json(sink, &stats_frame(mp)).await?;
    conn.last_stats_snap = snap;
    conn.last_stats_push = Some(Instant::now());
    Ok(())
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
                            if conn.want_blocks
                                && send_json(&mut sink, &tip_push_json(&ev)).await.is_err() {
                                    break;
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
                if handle_ws_frame(&st, &mut conn, frame, &mut sink).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn handle_ws_frame(
    st: &AppState,
    conn: &mut ConnState,
    frame: Option<Result<Message, axum::Error>>,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    match frame {
        Some(Ok(Message::Text(text))) => {
            if text.len() > st.max_ws_message_bytes {
                let _ = send_error(sink, "message too large").await;
                return Err(());
            }
            match parse_client_msg(text.as_str()) {
                Ok(msg) => handle_client_msg(st, conn, msg, sink).await,
                Err(e) => send_error(sink, &e).await,
            }
        }
        Some(Ok(Message::Ping(p))) => sink.send(Message::Pong(p)).await.map_err(|_| ()),
        Some(Ok(Message::Close(_))) | None => Err(()),
        Some(Ok(_)) => Ok(()),
        Some(Err(_)) => Err(()),
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
            conn.want_blocks = data.iter().any(|s| s == "blocks");
            conn.want_stats = data.iter().any(|s| s == "stats");
            if conn.want_stats {
                push_stats(st, conn, sink, true).await?;
            }
            Ok(())
        }
        ClientMsg::TrackAddress(addr) => add_addresses(st, conn, &[addr], false, sink).await,
        ClientMsg::TrackAddresses(addrs) => add_addresses(st, conn, &addrs, true, sink).await,
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
        ClientMsg::Ping => send_json(sink, &json!({ "pong": true })).await,
        ClientMsg::Init => match init_tip_json(&st.query) {
            Some(v) => send_json(sink, &v).await,
            None => Ok(()),
        },
    }
}

fn txs_touching_watched<'a, I>(
    query: &Query,
    mp: &MempoolHub,
    network: Network,
    watched: &HashMap<[u8; 32], String>,
    txs: I,
) -> HashMap<String, Vec<Value>>
where
    I: IntoIterator<Item = (Txid, &'a Transaction, Option<i64>)>,
{
    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    if watched.is_empty() {
        return out;
    }
    for (txid, tx, fee) in txs {
        let shs = scripts_touched_full(query, Some(mp), tx);
        let mut body: Option<Value> = None;
        for sh in shs {
            if let Some(addr) = watched.get(&sh) {
                let v = body
                    .get_or_insert_with(|| {
                        build_tx_json_from_tx(query, tx, network, fee, Some(mp))
                            .unwrap_or_else(|_| json!({ "txid": txid_display_hex(&txid) }))
                    })
                    .clone();
                out.entry(addr.clone()).or_default().push(v);
            }
        }
    }
    out
}

fn unique_tx_jsons(by_addr: &HashMap<String, Vec<Value>>) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut txs = Vec::new();
    for vs in by_addr.values() {
        for v in vs {
            let Some(id) = v.get("txid").and_then(|x| x.as_str()) else {
                continue;
            };
            if seen.insert(id.to_string()) {
                txs.push(v.clone());
            }
        }
    }
    txs
}

fn removed_tx_json(
    query: &Query,
    mempool: Option<&MempoolHub>,
    network: Network,
    old: &Txid,
) -> Value {
    if let Some(m) = mempool {
        if let Some(tx) = m.get_tx(old) {
            return build_tx_json_from_tx(query, &tx, network, None, Some(m))
                .unwrap_or_else(|_| json!({ "txid": txid_display_hex(old) }));
        }
        if let Some(e) = m.mempool_tx_snapshot().get(old) {
            return build_tx_json_from_tx(query, &e.tx, network, Some(e.fee_sat as i64), Some(m))
                .unwrap_or_else(|_| json!({ "txid": txid_display_hex(old) }));
        }
    }
    json!({ "txid": txid_display_hex(old) })
}

async fn add_addresses(
    st: &AppState,
    conn: &mut ConnState,
    addrs: &[String],
    keyed: bool,
    sink: &mut futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    let mut added: HashMap<[u8; 32], String> = HashMap::new();
    for addr in addrs {
        if conn.addresses.len() >= st.max_track_addresses {
            send_error(sink, "max_track_addresses exceeded").await?;
            return Ok(());
        }
        match resolve_address_sh(addr, st.network) {
            Ok(sh) => {
                conn.addresses.insert(sh, addr.clone());
                added.insert(sh, addr.clone());
            }
            Err(()) => {
                send_error(sink, &format!("invalid address: {addr}")).await?;
            }
        }
    }
    if added.is_empty() {
        return Ok(());
    }
    let Some(mp) = st.mempool.clone() else {
        return Ok(());
    };
    let query = Arc::clone(&st.query);
    let network = st.network;
    let by_addr = match tokio::task::spawn_blocking(move || {
        let _g = rbitcoin_net::BlockingRegion::enter();
        let snap = mp.mempool_tx_snapshot();
        txs_touching_watched(
            query.as_ref(),
            mp.as_ref(),
            network,
            &added,
            snap.entries()
                .iter()
                .map(|e| (e.txid, e.tx.as_ref(), Some(e.fee_sat as i64))),
        )
    })
    .await
    {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    if keyed {
        let mut obj = serde_json::Map::new();
        for addr in addrs {
            if let Some(txs) = by_addr.get(addr) {
                if !txs.is_empty() {
                    obj.insert(addr.clone(), json!(txs));
                }
            }
        }
        if !obj.is_empty() {
            send_json(sink, &json!({ "multi-address-transactions": obj })).await?;
        }
    } else {
        let txs = unique_tx_jsons(&by_addr);
        if !txs.is_empty() {
            send_json(sink, &json!({ "address-transactions": txs })).await?;
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
    address_removed: Option<Value>,
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
    let mut address_removed = None;
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
        if addr_hit_old {
            let removed: Vec<Value> = ann
                .replaced
                .iter()
                .map(|old| removed_tx_json(query, mempool, network, old))
                .collect();
            if !removed.is_empty() {
                address_removed = Some(json!({ "address-removed-transactions": removed }));
            }
        }
    }

    let Some(m) = mempool else {
        return MempoolAnnounceFrames {
            replaced,
            address_txs: None,
            address_removed,
            tx_status: tracked.contains(&ann.txid),
        };
    };
    let Some(tx) = m.get_tx(&ann.txid) else {
        return MempoolAnnounceFrames {
            replaced,
            address_txs: None,
            address_removed,
            tx_status: tracked.contains(&ann.txid),
        };
    };

    let mut address_txs = None;
    if !watched.is_empty() {
        let grouped = txs_touching_watched(
            query,
            m,
            network,
            watched,
            std::iter::once((ann.txid, &tx, None)),
        );
        let bodies = unique_tx_jsons(&grouped);
        if !bodies.is_empty() {
            address_txs = Some(json!({ "address-transactions": bodies }));
        }
    }

    MempoolAnnounceFrames {
        replaced,
        address_txs,
        address_removed,
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
    if let Some(v) = frames.address_removed {
        send_json(sink, &v).await?;
    }
    if let Some(v) = frames.address_txs {
        send_json(sink, &v).await?;
    }
    if frames.tx_status {
        push_tx_status(st, conn, &txid, sink).await?;
    }
    push_stats(st, conn, sink, false).await?;
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
    push_stats(st, conn, sink, false).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_display_hex_matches_primitives_owner() {
        let b = [0x7au8; 32];
        let txid = Txid::from_byte_array(b);
        assert_eq!(txid_display_hex(&txid), display_hash_hex(&b));
    }

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
        assert_eq!(
            parse_client_msg(r#"{"track-address":"stop"}"#).unwrap(),
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
        assert_eq!(
            parse_client_msg(r#"{"track-tx":"stop"}"#).unwrap(),
            ClientMsg::StopTrackTxs
        );
    }

    #[test]
    fn parse_noop_and_bad_json() {
        assert_eq!(parse_client_msg(r#"{"foo":1}"#).unwrap(), ClientMsg::Noop);
        assert!(parse_client_msg("not-json").is_err());
        assert!(parse_client_msg("[]").is_err());
        assert!(parse_client_msg("null").is_err());
        assert!(parse_client_msg("1").is_err());
        assert_eq!(
            parse_client_msg(r#"{"track-address":1}"#).unwrap(),
            ClientMsg::Noop
        );
        assert_eq!(
            parse_client_msg(r#"{"track-tx":false}"#).unwrap(),
            ClientMsg::StopTrackTxs
        );
        assert_eq!(
            parse_client_msg(r#"{"track-address":null}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
        assert_eq!(
            parse_client_msg(r#"{"stop-track-address":1}"#).unwrap(),
            ClientMsg::Noop
        );
        assert_eq!(
            parse_client_msg(r#"{"action":"want"}"#).unwrap(),
            ClientMsg::Want(vec![])
        );
        assert_eq!(
            parse_client_msg(r#"{"track-addresses":null}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
        assert_eq!(
            parse_client_msg(r#"{"track-addresses":[]}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
        assert_eq!(
            parse_client_msg(r#"{"stop-track-address":"bcrt1qtest"}"#).unwrap(),
            ClientMsg::StopTrackAddress(Some("bcrt1qtest".into()))
        );
        assert_eq!(
            parse_client_msg(r#"{"stop-track-address":true}"#).unwrap(),
            ClientMsg::StopTrackAddresses
        );
        let id = "ab".repeat(32);
        assert_eq!(
            parse_client_msg(&format!(r#"{{"stop-track-tx":"{id}"}}"#)).unwrap(),
            ClientMsg::StopTrackTx(Some(id))
        );
        assert_eq!(
            parse_client_msg(r#"{"track-tx":""}"#).unwrap(),
            ClientMsg::StopTrackTxs
        );
        assert_eq!(
            parse_client_msg(r#"{"track-txs":null}"#).unwrap(),
            ClientMsg::StopTrackTxs
        );
        assert_eq!(
            parse_client_msg(r#"{"action":"ping"}"#).unwrap(),
            ClientMsg::Ping
        );
        assert_eq!(
            parse_client_msg(r#"{"action":"init"}"#).unwrap(),
            ClientMsg::Init
        );
    }
}
