//! Esplora HTTP listener (axum + tower limits) and wallet WebSocket live path.

use crate::handlers;
use crate::tx_json::{build_tx_json, tx_status_json, tx_status_json_in};
use crate::ws;
use axum::extract::{Path, Query as AxumQuery, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use bitcoin::consensus::Encodable;
use bitcoin::Network;
use rbitcoin_electrum::ServeLimits;
use rbitcoin_net::{MempoolHub, TipEvent};
use rbitcoin_primitives::Height;
use rbitcoin_query::{ChainView, Query, ShJoinSlot};
use rbitcoin_store::StoreError;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinHandle;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Tip-follow 5s DEBUG `tip: perf`: REST request count this window.
static METER_REQ: AtomicU64 = AtomicU64::new(0);
/// Sum of REST handler walls (µs).
static METER_US: AtomicU64 = AtomicU64::new(0);
/// Max single REST request wall (µs).
static METER_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Sample-and-reset Esplora REST request meters: `(count, sum_us, max_us)`.
pub fn sample_reset_perf() -> (u64, u64, u64) {
    (
        METER_REQ.swap(0, Ordering::Relaxed),
        METER_US.swap(0, Ordering::Relaxed),
        METER_MAX_US.swap(0, Ordering::Relaxed),
    )
}

async fn meter_rest(req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let t0 = Instant::now();
    let resp = next.run(req).await;
    let elapsed = t0.elapsed();
    let us = elapsed.as_micros() as u64;
    METER_REQ.fetch_add(1, Ordering::Relaxed);
    METER_US.fetch_add(us, Ordering::Relaxed);
    let mut cur = METER_MAX_US.load(Ordering::Relaxed);
    while us > cur {
        match METER_MAX_US.compare_exchange_weak(cur, us, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(c) => cur = c,
        }
    }
    let status = resp.status();
    let err = if status.is_success() {
        None
    } else {
        Some(status.as_str().to_string())
    };
    rbitcoin_log::api_call(
        "esplora",
        "-",
        &format!("{method} {path}"),
        "",
        elapsed.as_millis() as u64,
        err.as_deref(),
    );
    resp
}

pub(crate) const HDR_CHAIN_TIP: &str = "x-bitcoin-chain-tip";
pub(crate) const HDR_CHAIN_TIP_HEIGHT: &str = "x-bitcoin-chain-tip-height";

fn stamp_chain_view_headers(resp: &mut Response, view: &ChainView) {
    let hash = block_hash_hex(&view.hash);
    let height = view.height.0.to_string();
    if let Ok(v) = HeaderValue::from_str(&hash) {
        resp.headers_mut().insert(HDR_CHAIN_TIP, v);
    }
    if let Ok(v) = HeaderValue::from_str(&height) {
        resp.headers_mut().insert(HDR_CHAIN_TIP_HEIGHT, v);
    }
    resp.headers_mut().insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("X-Bitcoin-Chain-Tip, X-Bitcoin-Chain-Tip-Height"),
    );
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct AsOfQuery {
    pub asof: Option<String>,
}

pub(crate) fn parse_asof_param(q: &AsOfQuery) -> Result<Option<[u8; 32]>, ()> {
    match q.asof.as_deref() {
        None => Ok(None),
        Some(s) => parse_hash32(s).map(Some),
    }
}

fn asof_hash_from_uri(uri: &axum::http::Uri) -> Result<Option<[u8; 32]>, ()> {
    let Some(query) = uri.query() else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("asof=") {
            if v.is_empty() {
                return Err(());
            }
            return parse_hash32(v).map(Some);
        }
    }
    Ok(None)
}

async fn stamp_chain_view_mw(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let asof = match asof_hash_from_uri(req.uri()) {
        Ok(v) => v,
        Err(()) => return not_found(),
    };
    let view = if let Some(hash) = asof {
        match st.query.pin_chain_view_at(&hash) {
            Ok(Some(v)) => Some(v),
            Ok(None) => return not_found(),
            Err(e) => return store_err(e),
        }
    } else {
        match st.query.pin_chain_view() {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    };
    let mut resp = next.run(req).await;
    let Some(view) = view else {
        return resp;
    };
    match view.still_live(&st.query) {
        Ok(true) => {
            stamp_chain_view_headers(&mut resp, &view);
            resp
        }
        Ok(false) if asof.is_some() => not_found(),
        Ok(false) => (StatusCode::SERVICE_UNAVAILABLE, "chain view moved").into_response(),
        Err(e) => store_err(e),
    }
}

/// Default concurrent upgraded WebSocket sockets (separate from REST concurrency).
pub const DEFAULT_MAX_WS_CONNECTIONS: usize = 64;
/// Default max inbound client WebSocket text frame size.
pub const DEFAULT_MAX_WS_MESSAGE_BYTES: usize = 64 * 1024;
/// Default max tracked addresses per WS connection (wallet watchlist).
pub const DEFAULT_MAX_TRACK_ADDRESSES: usize = 64;
/// Default max tracked txids per WS connection (pending set).
pub const DEFAULT_MAX_TRACK_TXS: usize = 64;

/// Esplora HTTP server config (listen + shared DoS floor + WS caps).
#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub listen: SocketAddr,
    /// Shared with Electrum ([`ServeLimits::for_public_proxy`] defaults).
    pub limits: ServeLimits,
    /// Address encoding network (mainnet/testnet/signet/regtest).
    pub network: Network,
    /// Max concurrent upgraded WebSocket connections (not REST concurrency).
    pub max_ws_connections: usize,
    /// Max inbound WS text frame bytes.
    pub max_ws_message_bytes: usize,
    /// Max tracked addresses per WS connection.
    pub max_track_addresses: usize,
    /// Max tracked txids per WS connection.
    pub max_track_txs: usize,
}

impl EsploraConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self::with_network(listen, Network::Bitcoin)
    }

    pub fn with_network(listen: SocketAddr, network: Network) -> Self {
        Self {
            listen,
            limits: ServeLimits::for_public_proxy(),
            network,
            max_ws_connections: DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_message_bytes: DEFAULT_MAX_WS_MESSAGE_BYTES,
            max_track_addresses: DEFAULT_MAX_TRACK_ADDRESSES,
            max_track_txs: DEFAULT_MAX_TRACK_TXS,
        }
    }
}

pub struct EsploraHandle {
    pub local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl EsploraHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = self.task.await;
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) query: Arc<Query>,
    pub(crate) network: Network,
    pub(crate) mempool: Option<Arc<MempoolHub>>,
    pub(crate) max_body: usize,
    /// Tip fan-out for `want: blocks` (each WS connection subscribes).
    pub(crate) tip_tx: Option<broadcast::Sender<TipEvent>>,
    pub(crate) ws_sem: Option<Arc<Semaphore>>,
    pub(crate) max_ws_message_bytes: usize,
    pub(crate) max_track_addresses: usize,
    pub(crate) max_track_txs: usize,
    /// Last scripthash join (tip-fenced). HTTP is not session-oriented; one
    /// slot still covers Casa `/scripthash` → `/txs` → `/utxo` and chain pages.
    pub(crate) sh_join: Arc<Mutex<Option<ShJoinSlot>>>,
}

impl AppState {
    pub(crate) fn with_sh_join<R>(&self, f: impl FnOnce(&mut Option<ShJoinSlot>) -> R) -> R {
        let mut slot = self
            .sh_join
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let r = f(&mut slot);
        *self.sh_join.lock().unwrap_or_else(|p| p.into_inner()) = slot;
        r
    }
}

/// Start Esplora **plain HTTP** (+ wallet WebSocket) on `config.listen`.
///
/// TLS is external (reverse proxy). App [`ServeLimits`] always apply to REST
/// (concurrency, body size, request timeout). WebSocket upgrades use a **separate**
/// semaphore so long-lived sockets do not starve HTTP concurrency.
///
/// Optional `mempool` enables fee estimates, mempool summary, `POST /tx`, and
/// live track pushes. Optional `tip_tx` enables `want: blocks` and confirm pushes
/// (clone of a broadcast sender; node bridges `ChainHub` tips into it).
pub async fn run_esplora(
    config: EsploraConfig,
    query: Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
    tip_tx: Option<broadcast::Sender<TipEvent>>,
) -> Result<EsploraHandle, std::io::Error> {
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_c = shutdown.clone();

    let max_conn = config.limits.max_connections.max(1);
    let max_body = config.limits.max_request_bytes.max(1);
    let idle = config.limits.idle_timeout;
    // Floor for request timeout: at least 1s so unit tests with short idle still work.
    let timeout = idle.max(Duration::from_secs(1));

    let ws_sem = Arc::new(Semaphore::new(config.max_ws_connections.max(1)));

    let state = AppState {
        query,
        network: config.network,
        mempool,
        max_body,
        tip_tx,
        ws_sem: Some(ws_sem),
        max_ws_message_bytes: config.max_ws_message_bytes.max(1024),
        max_track_addresses: config.max_track_addresses.max(1),
        max_track_txs: config.max_track_txs.max(1),
        sh_join: Arc::new(Mutex::new(None)),
    };

    // axum 0.8 path params use `{name}` (not `:name`).
    let rest = Router::new()
        .route("/blocks/tip/height", get(tip_height))
        .route("/blocks/tip/hash", get(tip_hash))
        .route("/blocks", get(handlers::blocks_tip))
        .route("/blocks/{start}", get(handlers::blocks_from_height))
        .route("/block-height/{height}", get(block_height))
        .route("/block/{hash}", get(handlers::block_json))
        .route("/block/{hash}/header", get(block_header))
        .route("/block/{hash}/status", get(handlers::block_status))
        .route("/block/{hash}/raw", get(handlers::block_raw))
        .route("/block/{hash}/txids", get(handlers::block_txids))
        .route("/block/{hash}/txid/{index}", get(handlers::block_txid_at))
        .route("/block/{hash}/txs", get(handlers::block_txs_0))
        .route("/block/{hash}/txs/{start}", get(handlers::block_txs_start))
        .route("/tx/{txid}", get(tx_full))
        .route("/tx/{txid}/hex", get(tx_hex))
        .route("/tx/{txid}/raw", get(handlers::tx_raw))
        .route("/tx/{txid}/status", get(tx_status))
        .route("/tx/{txid}/merkle-proof", get(handlers::tx_merkle_proof))
        .route(
            "/tx/{txid}/merkleblock-proof",
            get(handlers::tx_merkleblock_proof),
        )
        .route("/tx/{txid}/outspend/{vout}", get(handlers::tx_outspend))
        .route("/tx/{txid}/outspends", get(handlers::tx_outspends))
        .route("/tx", post(handlers::post_tx))
        .route("/txs/package", post(handlers::post_tx_package))
        .route("/address/{addr}", get(handlers::address_info))
        .route("/address/{addr}/utxo", get(handlers::address_utxo))
        .route("/address/{addr}/txs", get(handlers::address_txs))
        .route(
            "/address/{addr}/txs/mempool",
            get(handlers::address_txs_mempool),
        )
        .route(
            "/address/{addr}/txs/chain",
            get(handlers::address_txs_chain),
        )
        .route(
            "/address/{addr}/txs/chain/{last}",
            get(handlers::address_txs_chain_cursor),
        )
        .route("/scripthash/{hash}", get(handlers::scripthash_info))
        .route("/scripthash/{hash}/utxo", get(handlers::scripthash_utxo))
        .route("/scripthash/{hash}/txs", get(handlers::scripthash_txs))
        .route(
            "/scripthash/{hash}/txs/mempool",
            get(handlers::scripthash_txs_mempool),
        )
        .route(
            "/scripthash/{hash}/txs/chain",
            get(handlers::scripthash_txs_chain),
        )
        .route(
            "/scripthash/{hash}/txs/chain/{last}",
            get(handlers::scripthash_txs_chain_cursor),
        )
        .route("/mempool", get(handlers::mempool_info))
        .route("/mempool/txids", get(handlers::mempool_txids))
        .route("/mempool/recent", get(handlers::mempool_recent))
        .route("/fee-estimates", get(handlers::fee_estimates))
        .fallback(fallback_404)
        // Outer → inner: concurrency → body → timeout → meter → chain-view stamp.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            stamp_chain_view_mw,
        ))
        .layer(middleware::from_fn(meter_rest))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(RequestBodyLimitLayer::new(max_body))
        .layer(ConcurrencyLimitLayer::new(max_conn));

    // WS routes: separate from REST concurrency so upgrades do not hold HTTP permits.
    let ws_routes = Router::new()
        .route("/v1/ws", get(ws::ws_upgrade))
        .route("/ws", get(ws::ws_upgrade));

    let app = rest.merge(ws_routes).with_state(state);

    let task = tokio::spawn(async move {
        let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
            while !shutdown_c.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        if let Err(e) = serve.await {
            rbitcoin_log::warn!("esplora: serve ended: {e}");
        }
    });

    Ok(EsploraHandle {
        local_addr,
        shutdown,
        task,
    })
}

async fn tip_height(State(st): State<AppState>) -> Response {
    match st.query.tip_height() {
        Some(h) => (StatusCode::OK, format!("{}", h.0)).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "no chain tip").into_response(),
    }
}

async fn tip_hash(State(st): State<AppState>) -> Response {
    let Some(h) = st.query.tip_height() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no chain tip").into_response();
    };
    match st.query.header_at_height(h) {
        Ok(Some((_fk, rec))) => plain_ok(block_hash_hex(&rec.hash)),
        Ok(None) => (StatusCode::SERVICE_UNAVAILABLE, "no tip header").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// `GET /block-height/:height` → display-order block hash (plain text).
async fn block_height(State(st): State<AppState>, Path(height): Path<u32>) -> Response {
    match st.query.header_at_height(Height(height)) {
        Ok(Some((_fk, rec))) => plain_ok(block_hash_hex(&rec.hash)),
        Ok(None) => not_found(),
        Err(e) => store_err(e),
    }
}

/// `GET /block/:hash/header` → 80-byte header hex.
async fn block_header(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
    let Ok(hash) = parse_hash32(&hash_hex) else {
        return not_found();
    };
    // Prefer best-chain height path (fills prev correctly for wire header).
    match st.query.height_of_hash(&hash) {
        Ok(Some(h)) => match st.query.wire_header_at_height(h) {
            Ok(hdr) => match encode_header_hex(&hdr) {
                Ok(hex) => plain_ok(hex),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
            },
            Err(e) => store_err(e),
        },
        Ok(None) => not_found(),
        Err(e) => store_err(e),
    }
}

/// `GET /tx/:txid` → full Esplora transaction JSON (incl. asm/type/address).
async fn tx_full(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match build_tx_json(&st.query, fk, st.network) {
                Ok(v) => Json(v).into_response(),
                Err(e) => store_err(e),
            },
            Ok(None) => not_found(),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/hex` → raw consensus-encoded transaction hex.
async fn tx_hex(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match st.query.tx_wire_bytes(fk) {
                Ok(raw) => plain_ok(rbitcoin_primitives::hex_encode(raw)),
                Err(e) => store_err(e),
            },
            Ok(None) => not_found(),
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/status` → Esplora confirmation status JSON.
async fn tx_status(
    State(st): State<AppState>,
    Path(txid_hex): Path<String>,
    AxumQuery(asof): AxumQuery<AsOfQuery>,
) -> Response {
    let asof = match parse_asof_param(&asof) {
        Ok(v) => v,
        Err(()) => return not_found(),
    };
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.tx_fk_by_txid(&txid) {
            Ok(Some(fk)) => {
                let status = if let Some(hash) = asof {
                    match st.query.pin_chain_view_at(&hash) {
                        Ok(Some(view)) => tx_status_json_in(&st.query, fk, &view),
                        Ok(None) => return not_found(),
                        Err(e) => return store_err(e),
                    }
                } else {
                    tx_status_json(&st.query, fk)
                };
                match status {
                    Ok(v) => Json(v).into_response(),
                    Err(e) => store_err(e),
                }
            }
            Ok(None) => not_found(),
            Err(e) => store_err(e),
        }
    })
    .await
}

async fn fallback_404() -> Response {
    not_found()
}

pub(crate) fn plain_ok(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

pub(crate) fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

pub(crate) fn store_err(e: rbitcoin_query::QueryError) -> Response {
    match e {
        StoreError::NotFound => not_found(),
        StoreError::Stale(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()).into_response(),
    }
}

/// Esplora / Core display order (internal hash bytes reversed).
pub(crate) fn block_hash_hex(hash: &[u8; 32]) -> String {
    let mut rev = *hash;
    rev.reverse();
    rbitcoin_primitives::hex_encode(rev)
}

/// Parse 32-byte hash/txid hex (display order) → internal byte order.
pub(crate) fn parse_hash32(s: &str) -> Result<[u8; 32], ()> {
    let mut bytes = rbitcoin_primitives::hex_decode(s).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn encode_header_hex(hdr: &bitcoin::block::Header) -> Result<String, String> {
    let mut buf = Vec::with_capacity(80);
    hdr.consensus_encode(&mut buf)
        .map_err(|_| "header encode".to_string())?;
    Ok(rbitcoin_primitives::hex_encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{Query, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn temp_query(label: &str) -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-esplora-{label}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (dir, q)
    }

    fn coinbase(h: u32, prev: Fk, parent_hash: Option<[u8; 32]>) -> (HeaderRecord, TxApply) {
        let version = 1;
        let timestamp = h + 1;
        let bits = 0x207fffff;
        let nonce = h;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&h.to_le_bytes());
        merkle[5] = 0xab;
        let hash = match parent_hash {
            None => merkle,
            Some(ph) => {
                rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
            }
        };
        let header = HeaderRecord {
            prev_fk: prev,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
        };
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let ta = TxApply {
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
                script_sig: vec![h as u8],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
        };
        (header, ta)
    }

    fn header_value(text: &str, name: &str) -> Option<String> {
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

    async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
        let (status, _hdrs, body) = http_get_raw(addr, path).await;
        (status, body)
    }

    async fn http_get_raw(addr: SocketAddr, path: &str) -> (u16, String, String) {
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
        (status, text, body)
    }

    #[tokio::test]
    async fn tip_endpoints_and_unknown_404() {
        let (dir, q) = temp_query("tip");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut tip_hash = [0u8; 32];
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            tip_hash = header.hash;
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        assert_eq!(q.tip_height(), Some(Height(2)));

        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let addr = handle.local_addr;

        let (st, body) = http_get(addr, "/blocks/tip/height").await;
        assert_eq!(st, 200, "height body={body}");
        assert_eq!(body, "2");

        let (st, body) = http_get(addr, "/blocks/tip/hash").await;
        assert_eq!(st, 200, "hash body={body}");
        assert_eq!(body, block_hash_hex(&tip_hash));
        assert_eq!(body.len(), 64);

        let (st, body) = http_get(addr, "/no/such/path").await;
        assert_eq!(st, 404, "404 body={body}");
        assert!(body.to_ascii_lowercase().contains("not found") || body.contains("Not Found"));

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chain_view_tip_header_matches_hash_body() {
        let (dir, q) = temp_query("chain-view-hdr");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let addr = handle.local_addr;

        let (st, raw, body) = http_get_raw(addr, "/blocks/tip/hash").await;
        assert_eq!(st, 200, "hash body={body}");
        let tip = header_value(&raw, HDR_CHAIN_TIP).expect("X-Bitcoin-Chain-Tip");
        let height = header_value(&raw, HDR_CHAIN_TIP_HEIGHT).expect("height");
        assert_eq!(tip, body);
        assert_eq!(height, "0");
        let expose = header_value(&raw, "access-control-expose-headers").unwrap_or_default();
        assert!(
            expose.to_ascii_lowercase().contains("x-bitcoin-chain-tip"),
            "CORS must expose the tip header: {expose}"
        );

        let (st, raw, _) = http_get_raw(addr, "/blocks/tip/height").await;
        assert_eq!(st, 200);
        assert_eq!(
            header_value(&raw, HDR_CHAIN_TIP).as_deref(),
            Some(tip.as_str())
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chain_view_header_changes_after_same_height_replace() {
        let (dir, q) = temp_query("chain-view-reorg-hdr");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let (h1, t1) = coinbase(1, prev_fk, Some(hash0));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;
        let sh = rbitcoin_store::script_hash(&[0x51]);
        let sh_hex = block_hash_hex(&sh);

        let (st, raw_a, _) = http_get_raw(addr, &format!("/scripthash/{sh_hex}/utxo")).await;
        assert_eq!(st, 200, "utxo A");
        let tip_a = header_value(&raw_a, HDR_CHAIN_TIP).expect("tip A");
        assert_eq!(tip_a, block_hash_hex(&h1.hash));

        q.disconnect_tip().unwrap();
        let mut h1b = coinbase(1, prev_fk, Some(hash0)).0;
        h1b.nonce = h1.nonce.wrapping_add(1);
        h1b.hash = rbitcoin_store::block_header_hash(
            h1b.version,
            &hash0,
            &h1b.merkle_root,
            h1b.timestamp,
            h1b.bits,
            h1b.nonce,
        );
        let t1b = coinbase(1, prev_fk, Some(hash0)).1;
        q.connect_block(Height(1), &h1b, &[t1b]).unwrap();

        let (st, raw_b, _) = http_get_raw(addr, &format!("/scripthash/{sh_hex}/utxo")).await;
        assert_eq!(st, 200, "utxo B");
        let tip_b = header_value(&raw_b, HDR_CHAIN_TIP).expect("tip B");
        assert_eq!(tip_b, block_hash_hex(&h1b.hash));
        assert_ne!(tip_a, tip_b);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn asof_utxo_hides_later_spend() {
        use rbitcoin_primitives::Fk;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = temp_query("asof-utxo");
        let (h0, mut t0) = coinbase(0, Fk::NULL, None);
        t0.outputs = vec![OutputRecord::unspent(10_0000_0000, vec![0x51])];
        let create_txid = t0.tx.txid;
        let hash0 = h0.hash;
        let hfk0 = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let hash1 = rbitcoin_store::block_header_hash(1, &hash0, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        q.connect_block(
            Height(1),
            &h1,
            &[TxApply {
                tx: TxRecord {
                    txid: spend_txid,
                    version: 1,
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
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(9_0000_0000, vec![0x00])],
            }],
        )
        .unwrap();

        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;
        let sh = rbitcoin_store::script_hash(&[0x51]);
        let sh_hex = block_hash_hex(&sh);
        let asof0 = block_hash_hex(&hash0);
        let asof1 = block_hash_hex(&hash1);

        let (st, raw, body) =
            http_get_raw(addr, &format!("/scripthash/{sh_hex}/utxo?asof={asof0}")).await;
        assert_eq!(st, 200, "asof0 body={body}");
        let utxos: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(utxos.as_array().unwrap().len(), 1);
        assert_eq!(
            header_value(&raw, HDR_CHAIN_TIP).as_deref(),
            Some(asof0.as_str())
        );
        assert_eq!(
            header_value(&raw, HDR_CHAIN_TIP_HEIGHT).as_deref(),
            Some("0")
        );

        let (st, raw, body) =
            http_get_raw(addr, &format!("/scripthash/{sh_hex}/utxo?asof={asof1}")).await;
        assert_eq!(st, 200, "asof1 body={body}");
        let utxos: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(utxos.as_array().unwrap().is_empty());
        assert_eq!(
            header_value(&raw, HDR_CHAIN_TIP).as_deref(),
            Some(asof1.as_str())
        );

        let create_hex = block_hash_hex(&create_txid);
        let (st, _, body) =
            http_get_raw(addr, &format!("/tx/{create_hex}/status?asof={asof0}")).await;
        assert_eq!(st, 200, "status0={body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["confirmed"], true);

        let (st, _, _) = http_get_raw(
            addr,
            &format!("/scripthash/{sh_hex}/utxo?asof={}", "ee".repeat(32)),
        )
        .await;
        assert_eq!(st, 404);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_chain_tip_is_unavailable() {
        let (dir, q) = temp_query("empty");
        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let (st, raw, _) = http_get_raw(handle.local_addr, "/blocks/tip/height").await;
        assert_eq!(st, 503);
        assert!(
            header_value(&raw, HDR_CHAIN_TIP).is_none(),
            "empty chain must omit the tip header"
        );
        let (st, _) = http_get(handle.local_addr, "/blocks/tip/hash").await;
        assert_eq!(st, 503);
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_defaults_use_public_proxy_limits() {
        let cfg = EsploraConfig::new("0.0.0.0:3000".parse().unwrap());
        assert_eq!(cfg.limits, ServeLimits::for_public_proxy());
        assert_eq!(cfg.max_ws_connections, DEFAULT_MAX_WS_CONNECTIONS);
        assert_eq!(cfg.max_ws_message_bytes, DEFAULT_MAX_WS_MESSAGE_BYTES);
        assert_eq!(cfg.max_track_addresses, DEFAULT_MAX_TRACK_ADDRESSES);
        assert_eq!(cfg.max_track_txs, DEFAULT_MAX_TRACK_TXS);
    }

    /// Phase A: block-height, header, tx hex, tx status on one fixture store.
    #[tokio::test]
    async fn block_and_tx_read_path() {
        let (dir, q) = temp_query("block-tx");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        let mut coinbase_txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        assert_eq!(q.tip_height(), Some(Height(2)));

        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        // /block-height/1
        let (st, body) = http_get(addr, "/block-height/1").await;
        assert_eq!(st, 200, "block-height body={body}");
        assert_eq!(body, block_hash_hex(&hashes[1]));

        // missing height
        let (st, _) = http_get(addr, "/block-height/99").await;
        assert_eq!(st, 404);

        // /block/:hash/header — 80 bytes → 160 hex chars
        let hash_disp = block_hash_hex(&hashes[1]);
        let (st, body) = http_get(addr, &format!("/block/{hash_disp}/header")).await;
        assert_eq!(st, 200, "header body len={}", body.len());
        assert_eq!(body.len(), 160);
        // Matches Query wire encode.
        let wire = q.wire_header_at_height(Height(1)).unwrap();
        let expected = encode_header_hex(&wire).unwrap();
        assert_eq!(body, expected);

        // unknown hash
        let miss = "ff".repeat(32);
        let (st, _) = http_get(addr, &format!("/block/{miss}/header")).await;
        assert_eq!(st, 404);

        // /tx/:txid/hex
        let txid_disp = block_hash_hex(&coinbase_txids[0]); // same display reverse helper
        let (st, body) = http_get(addr, &format!("/tx/{txid_disp}/hex")).await;
        assert_eq!(st, 200, "tx hex body={body}");
        assert!(!body.is_empty());
        assert!(body.len() % 2 == 0);
        let (fk, _) = q.get_tx_by_txid(&coinbase_txids[0]).unwrap().unwrap();
        let raw = q.tx_wire_bytes(fk).unwrap();
        assert_eq!(body, rbitcoin_primitives::hex_encode(raw));

        // /tx/:txid/status
        let (st, body) = http_get(addr, &format!("/tx/{txid_disp}/status")).await;
        assert_eq!(st, 200, "status body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("status json");
        assert_eq!(v["confirmed"], true);
        assert_eq!(v["block_height"], 0);
        assert_eq!(v["block_hash"], block_hash_hex(&hashes[0]));
        assert!(v.get("block_time").is_some());

        // /tx/:txid full projection (asm/type keys present)
        let (st, body) = http_get(addr, &format!("/tx/{txid_disp}")).await;
        assert_eq!(st, 200, "tx full body={body}");
        let full: serde_json::Value = serde_json::from_str(&body).expect("tx json");
        assert!(full.get("txid").is_some());
        assert!(full.get("vin").is_some());
        assert!(full.get("vout").is_some());
        assert!(full.get("status").is_some());
        assert!(full.get("size").is_some());
        assert!(full.get("weight").is_some());
        assert_eq!(full["fee"], 0); // coinbase
        let v0 = &full["vout"][0];
        assert!(v0.get("scriptpubkey").is_some());
        assert!(v0.get("scriptpubkey_asm").is_some());
        assert!(v0.get("scriptpubkey_type").is_some());
        // OP_TRUE coinbase → unknown type, no address
        assert_eq!(v0["scriptpubkey_type"], "unknown");
        assert!(v0
            .get("scriptpubkey_asm")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("OP_"));
        let vin0 = &full["vin"][0];
        assert_eq!(vin0["is_coinbase"], true);
        assert!(vin0.get("scriptsig_asm").is_some());

        // missing tx
        let (st, _) = http_get(addr, &format!("/tx/{miss}/hex")).await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, &format!("/tx/{miss}/status")).await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, &format!("/tx/{miss}")).await;
        assert_eq!(st, 404);

        // status helper unit
        let st_json = tx_status_json(&q, fk).unwrap();
        assert_eq!(st_json["confirmed"], true);
        assert_eq!(st_json["block_height"], 0);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Steps 8–11: txids, merkle-proof, outspends, scripthash stats/utxo/pages, mempool empty.
    #[tokio::test]
    async fn remaining_routes_fixture() {
        use rbitcoin_store::script_hash;

        let (dir, q) = temp_query("remain");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        let mut coinbase_txids = Vec::new();
        for h in 0..4u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let hash0 = block_hash_hex(&hashes[0]);
        let (st, body) = http_get(addr, &format!("/block/{hash0}/txids")).await;
        assert_eq!(st, 200, "{body}");
        let ids: Vec<String> = serde_json::from_str(&body).unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], block_hash_hex(&coinbase_txids[0]));

        let (st, body) = http_get(addr, &format!("/block/{hash0}/txs")).await;
        assert_eq!(st, 200, "{body}");
        let txs: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(txs.len(), 1);
        assert!(txs[0].get("txid").is_some());

        // start not multiple of 25 → 400
        let (st, _) = http_get(addr, &format!("/block/{hash0}/txs/1")).await;
        assert_eq!(st, 400);

        let txid0 = block_hash_hex(&coinbase_txids[0]);
        let (st, body) = http_get(addr, &format!("/tx/{txid0}/merkle-proof")).await;
        assert_eq!(st, 200, "{body}");
        let mp: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(mp["block_height"], 0);
        assert_eq!(mp["pos"], 0);
        assert!(mp.get("merkle").is_some());

        let (st, body) = http_get(addr, &format!("/tx/{txid0}/outspend/0")).await;
        assert_eq!(st, 200, "{body}");
        let os: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(os["spent"], false);

        let (st, body) = http_get(addr, &format!("/tx/{txid0}/outspends")).await;
        assert_eq!(st, 200, "{body}");
        let oss: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(oss.len(), 1);

        // Scripthash for OP_TRUE
        let sh = script_hash(&[0x51]);
        let sh_hex = block_hash_hex(&sh);
        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}")).await;
        assert_eq!(st, 200, "{body}");
        let info: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(info["chain_stats"]["tx_count"].as_u64().unwrap() >= 4);
        assert!(info["chain_stats"]["funded_txo_count"].as_u64().unwrap() >= 4);

        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/utxo")).await;
        assert_eq!(st, 200, "{body}");
        let utxos: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert!(!utxos.is_empty());

        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/chain")).await;
        assert_eq!(st, 200, "{body}");
        let page1: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert!(page1.len() <= 25);
        assert!(!page1.is_empty());
        // Newest first: tip coinbase first.
        assert_eq!(page1[0]["status"]["block_height"], 3);

        // Cursor uses Class A / history txids (fixture synthetic ids), not recomputed wire txids.
        use rbitcoin_query::HistoryFilter;
        let full = q
            .scripthash_history_filtered(&sh, &HistoryFilter::esplora_chain_page(None))
            .unwrap();
        assert_eq!(full.len(), 4);
        let after = full[0].txid;
        let page2_items = q
            .scripthash_history_filtered(&sh, &HistoryFilter::esplora_chain_page(Some(after)))
            .unwrap();
        assert_eq!(page2_items.len(), 3);
        assert!(!page2_items.iter().any(|i| i.txid == after));
        let last = block_hash_hex(&after);
        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/chain/{last}")).await;
        assert_eq!(st, 200, "{body}");
        let page2: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(page2.len(), page2_items.len());

        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs")).await;
        assert_eq!(st, 200, "{body}");
        let combined: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert!(!combined.is_empty());

        // No mempool hub: empty-ish mempool, fee estimates still 200, POST 503.
        let (st, body) = http_get(addr, "/mempool").await;
        assert_eq!(st, 200, "{body}");
        let mem: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(mem["count"], 0);

        let (st, body) = http_get(addr, "/fee-estimates").await;
        assert_eq!(st, 200, "{body}");
        let fees: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(fees.get("1").is_some());

        // POST /tx without hub
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = "POST /tx HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab";
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("503") || text.contains("mempool"),
            "expected 503 without hub: {text}"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P0 gaps: block JSON/raw/status/txid-index/blocks list, tx raw, merkleblock, mempool lists.
    #[tokio::test]
    async fn block_raw_summary_status_and_mempool_routes() {
        use bitcoin::consensus::encode::deserialize;
        use bitcoin::hashes::Hash;
        use bitcoin::{Block, MerkleBlock};

        let (dir, q) = temp_query("p0-block");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        let mut coinbase_txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            hashes.push(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let _ = q.sample_reset_reconstruct_archived();
        let h1 = block_hash_hex(&hashes[1]);
        let (st, body) = http_get(addr, &format!("/block/{h1}")).await;
        assert_eq!(st, 200, "block json {body}");
        let bj: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(bj["height"], 1);
        assert_eq!(bj["id"], h1);
        assert_eq!(bj["tx_count"], 1);
        assert!(bj["size"].as_u64().unwrap() > 80);
        assert!(bj["weight"].as_u64().unwrap() > 0);
        assert!(bj.get("difficulty").is_some());
        assert!(bj.get("mediantime").is_some());
        assert_eq!(bj["previousblockhash"], block_hash_hex(&hashes[0]));
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/block JSON must not reconstruct wire"
        );

        // Raw block binary (HTTP body after headers — use binary-aware read).
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req =
            format!("GET /block/{h1}/raw HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let sep = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("http headers");
        let raw = &buf[sep + 4..];
        assert!(
            String::from_utf8_lossy(&buf[..sep]).contains("200"),
            "raw status"
        );
        let block: Block = deserialize(raw).expect("decode raw block");
        // Fixture headers use lab hashes; wire block still has 1 coinbase.
        assert_eq!(block.txdata.len(), 1);
        assert!(raw.len() > 80);
        assert!(
            q.sample_reset_reconstruct_archived() >= 1,
            "/block/:hash/raw must reconstruct wire"
        );

        let (st, body) = http_get(addr, &format!("/block/{h1}/status")).await;
        assert_eq!(st, 200, "{body}");
        let stj: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(stj["in_best_chain"], true);
        assert_eq!(stj["height"], 1);
        assert_eq!(stj["next_best"], block_hash_hex(&hashes[2]));

        let (st, body) = http_get(addr, &format!("/block/{h1}/txid/0")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, block_hash_hex(&coinbase_txids[1]));
        let (st, _) = http_get(addr, &format!("/block/{h1}/txid/9")).await;
        assert_eq!(st, 404);

        let (st, body) = http_get(addr, "/blocks").await;
        assert_eq!(st, 200, "{body}");
        let list: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["height"], 2);
        assert_eq!(list[2]["height"], 0);

        let (st, body) = http_get(addr, "/blocks/1").await;
        assert_eq!(st, 200, "{body}");
        let list1: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(list1[0]["height"], 1);
        assert_eq!(list1.len(), 2);
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/blocks must not reconstruct wire"
        );

        let txid0 = block_hash_hex(&coinbase_txids[0]);
        // Binary raw tx
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req =
            format!("GET /tx/{txid0}/raw HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let sep = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let raw_tx = &buf[sep + 4..];
        let (st, hex_body) = http_get(addr, &format!("/tx/{txid0}/hex")).await;
        assert_eq!(st, 200);
        let hex_bytes = rbitcoin_primitives::hex_decode(&hex_body).unwrap();
        assert_eq!(raw_tx, hex_bytes.as_slice());

        let _ = q.sample_reset_reconstruct_archived();
        let (st, body) = http_get(addr, &format!("/tx/{txid0}/merkleblock-proof")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "merkleblock-proof uses txid.body + header, not full reconstruct"
        );
        let mb_bytes = rbitcoin_primitives::hex_decode(&body).unwrap();
        let mb: MerkleBlock = deserialize(&mb_bytes).expect("merkleblock");
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        mb.extract_matches(&mut matches, &mut indexes).unwrap();
        assert_eq!(indexes, vec![0]); // coinbase at pos 0
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0],
            bitcoin::Txid::from_byte_array(coinbase_txids[0])
        );

        let (st, body) = http_get(addr, "/mempool/txids").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");
        let (st, body) = http_get(addr, "/mempool/recent").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");

        let sh = rbitcoin_store::script_hash(&[0x51]);
        let sh_hex = block_hash_hex(&sh);
        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/mempool")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "[]");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Packed SH `/txs` runs on `spawn_blocking` so tip height stays on the worker.
    #[tokio::test(flavor = "current_thread")]
    async fn tip_height_overlaps_scripthash_txs_on_one_worker() {
        use rbitcoin_store::script_hash;
        use std::time::Instant;

        let (dir, q) = temp_query("spawn-join");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..8u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;
        let sh_hex = block_hash_hex(&script_hash(&[0x51]));

        let t0 = Instant::now();
        let txs_path = format!("/scripthash/{sh_hex}/txs");
        let h_txs = tokio::spawn(async move { http_get(addr, &txs_path).await });
        let h_tip = tokio::spawn(async move { http_get(addr, "/blocks/tip/height").await });
        let (txs, tip) = tokio::join!(h_txs, h_tip);
        let (st_txs, _) = txs.unwrap();
        let (st_tip, body_tip) = tip.unwrap();
        assert_eq!(st_txs, 200);
        assert_eq!(st_tip, 200, "{body_tip}");
        assert_eq!(body_tip, "7");
        assert!(t0.elapsed().as_secs() < 2);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real WS upgrade against `run_esplora` + tip inject + REST coexistence.
    #[tokio::test]
    async fn ws_upgrade_want_blocks_and_rest_coexist() {
        use bitcoin::hashes::Hash;
        use futures_util::{SinkExt, StreamExt};
        use rbitcoin_net::TipEvent;
        use tokio::sync::broadcast;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (dir, q) = temp_query("ws-tip");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..2u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let (tip_tx, _) = broadcast::channel::<TipEvent>(16);
        let mut cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        cfg.max_ws_connections = 2;
        let handle = run_esplora(cfg, Arc::clone(&q), None, Some(tip_tx.clone()))
            .await
            .expect("listen");
        let addr = handle.local_addr;

        // REST works before and during WS.
        let (st, body) = http_get(addr, "/blocks/tip/height").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "1");

        let url = format!("ws://{addr}/v1/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("ws upgrade");
        // Handler task may lag the HTTP upgrade handshake.
        tokio::time::sleep(Duration::from_millis(150)).await;
        ws.send(WsMsg::Text(
            r#"{"action":"want","data":["blocks","stats"]}"#.into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Inject tip (header minimal).
        let tip_hash = q.header_at_height(Height(1)).unwrap().unwrap().1.hash;
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 1,
        };
        let n = tip_tx
            .send(TipEvent {
                height: 1,
                hash: bitcoin::BlockHash::from_byte_array(tip_hash),
                header,
                reorg_branch_len: 0,
            })
            .expect("tip send");
        assert!(n >= 1, "expected at least one tip subscriber, got {n}");

        let frame = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("timeout waiting tip push")
            .expect("ws closed")
            .expect("ws err");
        let text = match frame {
            WsMsg::Text(t) => t.as_str().to_owned(),
            other => panic!("expected text frame, got {other:?}"),
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["block"]["height"], 1);
        assert!(v["block"]["id"].as_str().unwrap().len() == 64);

        // REST still OK with WS open.
        let (st, body) = http_get(addr, "/blocks/tip/height").await;
        assert_eq!(st, 200, "{body}");

        // Cap: third connection rejected when max_ws=2 (we have 1 open; open second ok, third fails).
        let url2 = format!("ws://{addr}/ws");
        let (mut ws2, _) = tokio_tungstenite::connect_async(&url2)
            .await
            .expect("second ws");
        let third = tokio_tungstenite::connect_async(&url).await;
        assert!(
            third.is_err() || third.as_ref().ok().map(|(s, _)| s.get_ref()).is_none(),
            "third upgrade should fail or not stay open under max_ws=2"
        );
        // Prefer: connect fails or server closes immediately.
        if let Ok((mut ws3, _)) = third {
            // May get 503 via failed handshake; if upgraded, close.
            let _ = ws3.close(None).await;
        }

        let _ = ws2.close(None).await;
        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regtest P2WPKH address + scriptPubKey for wallet-style track-address tests.
    fn regtest_p2wpkh() -> (String, bitcoin::ScriptBuf) {
        use bitcoin::key::CompressedPublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::{Address, Network, PrivateKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[7u8; 32]).expect("sk");
        let pk = PrivateKey::new(sk, Network::Regtest);
        let cpk = CompressedPublicKey::from_private_key(&secp, &pk).expect("cpk");
        let addr = Address::p2wpkh(&cpk, Network::Regtest);
        let spk = addr.script_pubkey();
        (addr.to_string(), spk)
    }

    fn display_txid(txid: bitcoin::Txid) -> String {
        use bitcoin::hashes::Hash;
        let mut rev = txid.to_byte_array();
        rev.reverse();
        rbitcoin_primitives::hex_encode(rev)
    }

    async fn ws_recv_json(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        timeout_secs: u64,
    ) -> serde_json::Value {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as WsMsg;
        let frame = tokio::time::timeout(Duration::from_secs(timeout_secs), ws.next())
            .await
            .expect("timeout")
            .expect("closed")
            .expect("err");
        match frame {
            WsMsg::Text(t) => serde_json::from_str(t.as_str()).expect("json"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// Track real regtest address → mempool address-transactions + tip block-transactions.
    #[tokio::test]
    async fn ws_track_address_mempool_and_confirm() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use futures_util::SinkExt;
        use rbitcoin_net::{MempoolHub, TipEvent};
        use tokio::sync::broadcast;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (watch_addr, watch_spk) = regtest_p2wpkh();
        let (dir, q) = temp_query("ws-addr");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut coinbase_txids = Vec::new();
        for h in 0..101u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        // Confirm a pay-to-watch address at height 101 (SH index write on connect).
        let pay_bytes = {
            // Deterministic synthetic txid for Class A row (store uses raw bytes).
            let mut t = [0u8; 32];
            t[0] = 0xaa;
            t[31] = 0xbb;
            t
        };
        let mut pay_disp = pay_bytes;
        pay_disp.reverse();
        let pay_hex = rbitcoin_primitives::hex_encode(pay_disp);

        let ta_pay = TxApply {
            tx: TxRecord {
                txid: pay_bytes,
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: coinbase_txids[0],
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: 0xffff_fffd,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, watch_spk.to_bytes())],
        };
        let (cb_header, cb) = coinbase(101, prev, parent_hash);
        let _prev = q
            .connect_block(Height(101), &cb_header, &[cb, ta_pay])
            .expect("connect pay block");
        let tip_hash = cb_header.hash;

        let q = Arc::new(q);
        let mp_dir = dir.join("mp");
        std::fs::create_dir_all(&mp_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);

        let (tip_tx, _) = broadcast::channel::<TipEvent>(16);
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(
            cfg,
            Arc::clone(&q),
            Some(Arc::clone(&hub)),
            Some(tip_tx.clone()),
        )
        .await
        .expect("listen");
        let addr = handle.local_addr;

        let url = format!("ws://{addr}/v1/ws");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        ws.send(WsMsg::Text(
            (format!(r#"{{"track-address":"{watch_addr}"}}"#)).into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Mempool path: another mature coinbase → watch address.
        let op1 = OutPoint {
            txid: bitcoin::Txid::from_byte_array(coinbase_txids[1]),
            vout: 0,
        };
        let mem_pay = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op1,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: watch_spk.clone(),
            }],
        };
        let mem_hex = display_txid(mem_pay.compute_txid());
        hub.accept_tx(&mem_pay).expect("mempool accept to watch");

        let (st, body) = http_get(addr, &format!("/address/{watch_addr}/utxo")).await;
        assert_eq!(st, 200, "{body}");
        let utxos: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert!(
            utxos.iter().any(|u| u["status"]["confirmed"] == false),
            "mempool funding: {utxos:?}"
        );
        assert!(
            utxos.iter().any(|u| u["status"]["confirmed"] == true),
            "confirmed watch utxo: {utxos:?}"
        );
        let (st, body) = http_get(addr, &format!("/address/{watch_addr}")).await;
        assert_eq!(st, 200, "{body}");
        let info: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(info["mempool_stats"]["funded_txo_count"].as_u64().unwrap() >= 1);
        assert!(info["chain_stats"]["funded_txo_count"].as_u64().unwrap() >= 1);

        let true_sh = block_hash_hex(&rbitcoin_store::script_hash(&[0x51]));
        let (st, body) = http_get(addr, &format!("/scripthash/{true_sh}/utxo")).await;
        assert_eq!(st, 200, "{body}");
        let true_utxos: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        let spent = block_hash_hex(&coinbase_txids[1]);
        assert!(
            true_utxos.iter().all(|u| u["txid"] != spent),
            "mempool spend drops confirmed coin: {true_utxos:?}"
        );

        let mut saw_addr_mp = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(arr) = v.get("address-transactions").and_then(|a| a.as_array()) {
                assert!(!arr.is_empty());
                let txids: Vec<&str> = arr
                    .iter()
                    .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                    .collect();
                assert!(
                    txids.iter().any(|t| *t == mem_hex),
                    "address-transactions should include mempool pay {mem_hex}, got {txids:?}"
                );
                saw_addr_mp = true;
                break;
            }
        }
        assert!(saw_addr_mp, "expected address-transactions mempool push");

        // Confirm path: tip at height 101 should yield block-transactions for watch.
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(1),
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 102,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 101,
        };
        tip_tx
            .send(TipEvent {
                height: 101,
                hash: bitcoin::BlockHash::from_byte_array(tip_hash),
                header,
                reorg_branch_len: 0,
            })
            .expect("tip send");

        let mut saw_block_txs = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(arr) = v.get("block-transactions").and_then(|a| a.as_array()) {
                let txids: Vec<&str> = arr
                    .iter()
                    .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                    .collect();
                assert!(
                    txids.iter().any(|t| *t == pay_hex.as_str()),
                    "block-transactions should include confirmed pay {pay_hex}, got {txids:?}"
                );
                saw_block_txs = true;
                break;
            }
        }
        assert!(saw_block_txs, "expected block-transactions at tip 101");

        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// track-tx: unconfirmed on accept, then confirmed after connect + tip.
    #[tokio::test]
    async fn ws_track_tx_status_confirm_transition() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use futures_util::SinkExt;
        use rbitcoin_net::{MempoolHub, TipEvent};
        use tokio::sync::broadcast;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (dir, q) = temp_query("ws-tx-conf");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut coinbase_txids = Vec::new();
        for h in 0..101u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        let op0 = OutPoint {
            txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
            vout: 0,
        };
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let pending = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op0,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: spk.clone(),
            }],
        };
        let pending_id = pending.compute_txid();
        let pending_hex = display_txid(pending_id);
        let pending_bytes = pending_id.to_byte_array();

        let q = Arc::new(q);
        let mp_dir = dir.join("mp");
        std::fs::create_dir_all(&mp_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);

        let (tip_tx, _) = broadcast::channel::<TipEvent>(16);
        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(
            cfg,
            Arc::clone(&q),
            Some(Arc::clone(&hub)),
            Some(tip_tx.clone()),
        )
        .await
        .expect("listen");
        let addr = handle.local_addr;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/v1/ws"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        ws.send(WsMsg::Text(
            (format!(r#"{{"track-tx":"{pending_hex}"}}"#)).into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        hub.accept_tx(&pending).expect("accept");
        let mut saw_unconf = false;
        for _ in 0..10 {
            let v = ws_recv_json(&mut ws, 3).await;
            if v.get("tx").is_some() {
                assert_eq!(v["tx"]["txid"], pending_hex);
                assert_eq!(v["tx"]["status"]["confirmed"], false);
                saw_unconf = true;
                break;
            }
        }
        assert!(saw_unconf, "unconfirmed track-tx push");

        // Confirm the same txid via connect_block, then tip.
        let (tip_fk, tip_rec) = q.header_at_height(Height(100)).unwrap().unwrap();
        let (h_hdr, cb) = coinbase(101, tip_fk, Some(tip_rec.hash));
        let ta = TxApply {
            tx: TxRecord {
                txid: pending_bytes,
                version: 2,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord {
                prev_txid: coinbase_txids[0],
                create_fk: Fk::NULL,
                prev_index: 0,
                sequence: 0xffff_fffd,
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, vec![0x51])],
        };
        q.connect_block(Height(101), &h_hdr, &[cb, ta])
            .expect("confirm pending");
        tip_tx
            .send(TipEvent {
                height: 101,
                hash: bitcoin::BlockHash::from_byte_array(h_hdr.hash),
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::from_consensus(1),
                    prev_blockhash: bitcoin::BlockHash::from_byte_array([0u8; 32]),
                    merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                    time: 102,
                    bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                    nonce: 101,
                },
                reorg_branch_len: 0,
            })
            .unwrap();

        let mut saw_conf = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if v.get("tx").is_some() {
                assert_eq!(v["tx"]["txid"], pending_hex);
                if v["tx"]["status"]["confirmed"] == true {
                    saw_conf = true;
                    break;
                }
            }
        }
        assert!(saw_conf, "expected confirmed track-tx status after tip");

        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
        let _ = prev;
    }

    /// Caps: honest error frames for max_track_addresses and max_track_txs.
    #[tokio::test]
    async fn ws_track_caps_error_frames() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (dir, q) = temp_query("ws-caps");
        let q = Arc::new(q);
        let mut cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        cfg.max_track_addresses = 1;
        cfg.max_track_txs = 1;
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{}/v1/ws", handle.local_addr))
                .await
                .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        let (a1, _) = regtest_p2wpkh();
        // Second distinct address.
        let a2 = {
            use bitcoin::key::CompressedPublicKey;
            use bitcoin::secp256k1::{Secp256k1, SecretKey};
            use bitcoin::{Address, Network, PrivateKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
            let pk = PrivateKey::new(sk, Network::Regtest);
            let cpk = CompressedPublicKey::from_private_key(&secp, &pk).unwrap();
            Address::p2wpkh(&cpk, Network::Regtest).to_string()
        };

        ws.send(WsMsg::Text(
            (format!(r#"{{"track-address":"{a1}"}}"#)).into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        ws.send(WsMsg::Text(
            (format!(r#"{{"track-address":"{a2}"}}"#)).into(),
        ))
        .await
        .unwrap();
        let mut saw_addr_cap = false;
        for _ in 0..6 {
            let v = ws_recv_json(&mut ws, 2).await;
            if v.get("error")
                .and_then(|e| e.as_str())
                .is_some_and(|s| s.contains("max_track_addresses"))
            {
                saw_addr_cap = true;
                break;
            }
        }
        assert!(saw_addr_cap, "expected max_track_addresses error frame");

        let t1 = "11".repeat(32);
        let t2 = "22".repeat(32);
        ws.send(WsMsg::Text((format!(r#"{{"track-tx":"{t1}"}}"#)).into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        ws.send(WsMsg::Text((format!(r#"{{"track-tx":"{t2}"}}"#)).into()))
            .await
            .unwrap();
        let mut saw_tx_cap = false;
        for _ in 0..6 {
            let v = ws_recv_json(&mut ws, 2).await;
            if v.get("error")
                .and_then(|e| e.as_str())
                .is_some_and(|s| s.contains("max_track_txs"))
            {
                saw_tx_cap = true;
                break;
            }
        }
        assert!(saw_tx_cap, "expected max_track_txs error frame");

        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// RBF: track-tx replace + address-only replace (old pays watch, new does not).
    #[tokio::test]
    async fn ws_rbf_track_tx_and_address_only() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use futures_util::SinkExt;
        use rbitcoin_net::MempoolHub;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (watch_addr, watch_spk) = regtest_p2wpkh();
        let (dir, q) = temp_query("ws-rbf");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut coinbase_txids = Vec::new();
        for h in 0..101u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            coinbase_txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let mp_dir = dir.join("mp");
        std::fs::create_dir_all(&mp_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);

        let cfg =
            EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), bitcoin::Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)), None)
            .await
            .expect("listen");
        let (mut ws, _) =
            tokio_tungstenite::connect_async(format!("ws://{}/v1/ws", handle.local_addr))
                .await
                .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // --- track-tx RBF ---
        let op0 = OutPoint {
            txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
            vout: 0,
        };
        let low = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op0,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let low_hex = display_txid(low.compute_txid());
        ws.send(WsMsg::Text(
            (format!(r#"{{"track-tx":"{low_hex}"}}"#)).into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        hub.accept_tx(&low).unwrap();
        // drain unconf
        for _ in 0..5 {
            if let Ok(v) =
                tokio::time::timeout(Duration::from_millis(400), ws_recv_json(&mut ws, 1)).await
            {
                if v.get("tx").is_some() {
                    break;
                }
            } else {
                break;
            }
        }
        let high = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op0,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 10_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let high_hex = display_txid(high.compute_txid());
        hub.accept_tx(&high).unwrap();
        let mut saw = false;
        for _ in 0..10 {
            let v = ws_recv_json(&mut ws, 2).await;
            if let Some(arr) = v.get("replaced-transactions").and_then(|a| a.as_array()) {
                assert_eq!(arr[0]["txid"], low_hex);
                assert_eq!(arr[0]["replaced-by"], high_hex);
                saw = true;
                break;
            }
        }
        assert!(saw, "track-tx RBF replace frame");

        // --- address-only RBF: old pays watch, new pays OP_TRUE ---
        ws.send(WsMsg::Text(r#"{"stop-track-txs":true}"#.into()))
            .await
            .unwrap();
        ws.send(WsMsg::Text(
            (format!(r#"{{"track-address":"{watch_addr}"}}"#)).into(),
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;

        let op1 = OutPoint {
            txid: bitcoin::Txid::from_byte_array(coinbase_txids[1]),
            vout: 0,
        };
        let old_to_watch = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op1,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: watch_spk,
            }],
        };
        let old_hex = display_txid(old_to_watch.compute_txid());
        hub.accept_tx(&old_to_watch).unwrap();
        // drain address-transactions
        for _ in 0..8 {
            if let Ok(v) =
                tokio::time::timeout(Duration::from_millis(400), ws_recv_json(&mut ws, 1)).await
            {
                if v.get("address-transactions").is_some() {
                    break;
                }
            } else {
                break;
            }
        }
        let repl_away = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op1,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(48_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let repl_hex = display_txid(repl_away.compute_txid());
        hub.accept_tx(&repl_away).expect("rbf away from watch");

        let mut saw_addr_rbf = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 2).await;
            if let Some(arr) = v.get("replaced-transactions").and_then(|a| a.as_array()) {
                assert_eq!(arr[0]["txid"], old_hex);
                assert_eq!(arr[0]["replaced-by"], repl_hex);
                saw_addr_rbf = true;
                break;
            }
        }
        assert!(
            saw_addr_rbf,
            "address-only RBF: old paid watch, new does not"
        );

        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
