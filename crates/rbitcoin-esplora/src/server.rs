//! Esplora HTTP listener (axum + tower limits) and wallet WebSocket live path.

use crate::handlers;
use crate::tx_json::{build_tx_json, build_tx_json_from_tx, tx_status_json_in};
use crate::ws;
use axum::extract::{ConnectInfo, FromRequestParts, Path, Query as AxumQuery, Request, State};
use axum::http::request::Parts;
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
use rbitcoin_query::{ChainView, ChainViewKind, Query, ShJoinSlot};
use rbitcoin_store::StoreError;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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

/// Parsed `?asof=` (None if omitted). Invalid hex is 404.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AsOf(pub Option<[u8; 32]>);

impl FromRequestParts<AppState> for AsOf {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AxumQuery(q) = AxumQuery::<AsOfQuery>::from_request_parts(parts, state)
            .await
            .map_err(|_| not_found())?;
        parse_asof_param(&q).map(AsOf).map_err(|_| not_found())
    }
}

pub(crate) fn parse_asof_param(q: &AsOfQuery) -> Result<Option<[u8; 32]>, ()> {
    match q.asof.as_deref() {
        None => Ok(None),
        Some(s) => parse_hash32(s).map(Some),
    }
}

pub(crate) fn attach_chain_view(mut resp: Response, view: ChainView) -> Response {
    resp.extensions_mut().insert(view);
    resp
}

pub(crate) fn maybe_attach_view(resp: Response, view: Option<ChainView>) -> Response {
    match view {
        Some(v) => attach_chain_view(resp, v),
        None => resp,
    }
}

#[allow(clippy::result_large_err)] // public error enum
pub(crate) fn pin_or_reject(
    query: &Query,
    kind: ChainViewKind,
    asof: Option<[u8; 32]>,
) -> Result<Option<ChainView>, Response> {
    match query.pin_view(kind, asof.as_ref()) {
        Ok(None) if asof.is_some() => Err(not_found()),
        Ok(v) => Ok(v),
        Err(e) => Err(store_err(e)),
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

fn path_uses_sh_view(path: &str) -> bool {
    path.starts_with("/address/") || path.starts_with("/scripthash/")
}

/// COMPAT.md: `?asof=` only on tx status/outspend(s) and address/scripthash
/// `/`, `/utxo`, `/txs`, `/txs/chain` (not `/txs/mempool`).
fn path_accepts_asof(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["tx", _, "status"]
            | ["tx", _, "outspends"]
            | ["tx", _, "outspend", _]
            | ["address", _]
            | ["scripthash", _]
            | ["address", _, "utxo"]
            | ["scripthash", _, "utxo"]
            | ["address", _, "txs"]
            | ["scripthash", _, "txs"]
            | ["address", _, "txs", "chain"]
            | ["scripthash", _, "txs", "chain"]
            | ["address", _, "txs", "chain", _]
            | ["scripthash", _, "txs", "chain", _]
    )
}

fn path_never_pins(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["mempool"]
            | ["mempool", _]
            | ["fee-estimates"]
            | ["fees", "recommended"]
            | ["v1", "fees", "recommended"]
            | ["tx"]
            | ["txs", "package"]
            | ["address", _, "txs", "mempool"]
            | ["scripthash", _, "txs", "mempool"]
    )
}

fn powered_by_header() -> HeaderValue {
    static V: OnceLock<HeaderValue> = OnceLock::new();
    V.get_or_init(|| {
        let ver = env!("CARGO_PKG_VERSION");
        let mut hex = String::with_capacity(ver.len().saturating_mul(2));
        for b in ver.as_bytes() {
            hex.push_str(&format!("{b:02x}"));
        }
        HeaderValue::from_str(&format!("rbitcoin-esplora/{ver}-{hex}")).expect("ascii powered-by")
    })
    .clone()
}

async fn stamp_powered_by_mw(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("x-powered-by", powered_by_header());
    resp
}

async fn stamp_chain_view_mw(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let asof = match asof_hash_from_uri(req.uri()) {
        Ok(v) => v,
        Err(()) => return not_found(),
    };
    let path = req.uri().path().to_string();
    if asof.is_some() && !path_accepts_asof(&path) {
        return not_found();
    }
    let pre_view = if path_never_pins(&path) || asof.is_some() {
        None
    } else if path_uses_sh_view(&path) {
        match st.query.pin_sh_chain_view() {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    } else {
        match st.query.pin_chain_view() {
            Ok(v) => v,
            Err(e) => return store_err(e),
        }
    };
    let mut resp = next.run(req).await;
    let view = resp.extensions().get::<ChainView>().copied().or(pre_view);
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

/// Opt-in `GET /block-template` builder (node injects GBT; tests inject a stub).
#[derive(Clone)]
pub struct BlockTemplateFn(pub Arc<dyn Fn() -> Result<Value, String> + Send + Sync>);

impl std::fmt::Debug for BlockTemplateFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockTemplateFn")
    }
}

pub(crate) struct GbtCache {
    pub(crate) at: Instant,
    pub(crate) tip: [u8; 32],
    pub(crate) updates: u64,
    pub(crate) body: Value,
}

/// TCP `host:port` or a filesystem unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EsploraListen {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

impl EsploraListen {
    /// Empty value → `127.0.0.1:<default_port>`. A `host:port` is TCP. A path
    /// (`/…`, `./…`, or `*.sock`) is unix (not Windows).
    pub fn parse(val: &str, default_port: u16) -> Result<Self, String> {
        if val.is_empty() {
            return Ok(Self::Tcp(SocketAddr::from(([127, 0, 0, 1], default_port))));
        }
        if let Ok(addr) = val.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }
        let pathish = val.starts_with('/')
            || val.starts_with('.')
            || val.contains('/')
            || val.ends_with(".sock");
        if !pathish {
            return Err(format!(
                "esplora-listen: expected host:port or unix path, got {val}"
            ));
        }
        #[cfg(unix)]
        {
            Ok(Self::Unix(PathBuf::from(val)))
        }
        #[cfg(not(unix))]
        {
            Err(
                "esplora unix socket needs AF_UNIX; this Windows build has no tokio UnixListener"
                    .into(),
            )
        }
    }
}

/// Esplora HTTP server config (listen + shared DoS floor + WS caps).
#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub listen: EsploraListen,
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
    /// `None` → `GET /block-template` is 404 (default).
    pub block_template: Option<BlockTemplateFn>,
}

impl EsploraConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self::with_network(listen, Network::Bitcoin)
    }

    pub fn with_network(listen: SocketAddr, network: Network) -> Self {
        Self::with_listen(EsploraListen::Tcp(listen), network)
    }

    pub fn with_listen(listen: EsploraListen, network: Network) -> Self {
        Self {
            listen,
            limits: ServeLimits::for_public_proxy(),
            network,
            max_ws_connections: DEFAULT_MAX_WS_CONNECTIONS,
            max_ws_message_bytes: DEFAULT_MAX_WS_MESSAGE_BYTES,
            max_track_addresses: DEFAULT_MAX_TRACK_ADDRESSES,
            max_track_txs: DEFAULT_MAX_TRACK_TXS,
            block_template: None,
        }
    }
}

pub struct EsploraHandle {
    /// Bound TCP address. Unix listen leaves this as `127.0.0.1:0`.
    pub local_addr: SocketAddr,
    pub socket_path: Option<PathBuf>,
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
    /// Per-client last-1 GET + last-bulk POST joins (unix/loopback `X-Rbitcoin-Client`).
    pub(crate) sh_join: Arc<Mutex<JoinCache>>,
    /// Unix listen trusts `X-Rbitcoin-Client` without a TCP peer address.
    pub(crate) join_header_trusted: bool,
    pub(crate) block_template: Option<BlockTemplateFn>,
    pub(crate) gbt_cache: Arc<Mutex<Option<GbtCache>>>,
}

const JOIN_IDLE: Duration = Duration::from_secs(30);
const JOIN_MAX_CLIENTS: usize = 256;
const JOIN_BULK_CAP: usize = 16 * 1024 * 1024;

struct InflightJoin {
    /// `None` = still running. `Some(slot)` = finished (`slot` may be empty).
    done: Mutex<Option<Option<Arc<ShJoinSlot>>>>,
    cv: std::sync::Condvar,
}

impl InflightJoin {
    fn finish(&self, slot: Option<Arc<ShJoinSlot>>) {
        let mut d = self.done.lock().unwrap_or_else(|p| p.into_inner());
        if d.is_none() {
            *d = Some(slot);
            self.cv.notify_all();
        }
    }
}

/// Finishes the inflight slot (and drops the map entry) if the leader unwinds.
struct InflightGuard {
    cache: Arc<Mutex<JoinCache>>,
    id: String,
    sh: [u8; 32],
    inf: Arc<InflightJoin>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inf.finish(None);
        let mut g = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = g.clients.get_mut(&self.id) {
            if c.inflight
                .get(&self.sh)
                .is_some_and(|a| Arc::ptr_eq(a, &self.inf))
            {
                c.inflight.remove(&self.sh);
            }
        }
    }
}

struct ClientJoins {
    last_sh: Option<([u8; 32], Arc<ShJoinSlot>)>,
    last_bulk: HashMap<[u8; 32], Arc<ShJoinSlot>>,
    last_req: Instant,
    inflight: HashMap<[u8; 32], Arc<InflightJoin>>,
}

impl Default for ClientJoins {
    fn default() -> Self {
        Self {
            last_sh: None,
            last_bulk: HashMap::new(),
            last_req: Instant::now(),
            inflight: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub(crate) struct JoinCache {
    clients: HashMap<String, ClientJoins>,
}

impl JoinCache {
    #[cfg(test)]
    fn last_sh_key(&self, id: &str) -> Option<[u8; 32]> {
        self.clients
            .get(id)
            .and_then(|c| c.last_sh.as_ref().map(|(k, _)| *k))
    }

    #[cfg(test)]
    fn bulk_len(&self, id: &str) -> usize {
        self.clients.get(id).map(|c| c.last_bulk.len()).unwrap_or(0)
    }
}

fn sweep_clients(map: &mut HashMap<String, ClientJoins>, now: Instant) {
    map.retain(|_, c| now.saturating_duration_since(c.last_req) < JOIN_IDLE);
    while map.len() > JOIN_MAX_CLIENTS {
        let oldest = map
            .iter()
            .min_by_key(|(_, c)| c.last_req)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                map.remove(&k);
            }
            None => break,
        }
    }
}

fn cap_bulk(c: &mut ClientJoins) {
    let mut bytes: usize = c.last_bulk.values().map(|s| s.packed_bytes()).sum();
    while bytes > JOIN_BULK_CAP && !c.last_bulk.is_empty() {
        let victim = c
            .last_bulk
            .iter()
            .max_by_key(|(_, s)| s.packed_bytes())
            .map(|(k, s)| (*k, s.packed_bytes()));
        let Some((k, sz)) = victim else {
            break;
        };
        c.last_bulk.remove(&k);
        bytes = bytes.saturating_sub(sz);
    }
}

pub(crate) fn client_id_from(
    unix_or_trusted: bool,
    loopback: bool,
    header: Option<String>,
) -> Option<String> {
    if unix_or_trusted || loopback {
        header
    } else {
        None
    }
}

#[derive(Clone)]
pub(crate) struct JoinClient(pub Option<String>);

impl FromRequestParts<AppState> for JoinClient {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("x-rbitcoin-client")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let loopback = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|c| c.0.ip().is_loopback());
        Ok(JoinClient(client_id_from(
            state.join_header_trusted,
            loopback,
            header,
        )))
    }
}

impl AppState {
    pub(crate) fn with_sh_join<R>(
        &self,
        client: Option<&str>,
        sh: &[u8; 32],
        f: impl FnOnce(&mut Option<Arc<ShJoinSlot>>) -> R,
    ) -> R {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            let mut slot = None;
            return f(&mut slot);
        };
        let inflight = {
            let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            sweep_clients(&mut g.clients, Instant::now());
            let c = g.clients.entry(id.to_string()).or_default();
            c.last_req = Instant::now();
            if c.last_sh.as_ref().is_some_and(|(k, _)| k == sh) {
                let mut slot = c.last_sh.as_ref().map(|(_, s)| s.clone());
                drop(g);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        c.last_sh = Some((*sh, s));
                        c.last_req = Instant::now();
                    }
                }
                return r;
            }
            if let Some(inf) = c.inflight.get(sh).cloned() {
                Err(inf)
            } else {
                let inf = Arc::new(InflightJoin {
                    done: Mutex::new(None),
                    cv: std::sync::Condvar::new(),
                });
                c.inflight.insert(*sh, Arc::clone(&inf));
                Ok(inf)
            }
        };
        let inf = match inflight {
            Err(inf) => {
                let mut d = inf.done.lock().unwrap_or_else(|p| p.into_inner());
                while d.is_none() {
                    d = inf.cv.wait(d).unwrap_or_else(|p| p.into_inner());
                }
                let mut slot = (*d).clone().flatten();
                drop(d);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        c.last_sh = Some((*sh, s));
                        c.last_req = Instant::now();
                    }
                }
                return r;
            }
            Ok(inf) => inf,
        };
        let mut slot = {
            let g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            g.clients.get(id).and_then(|c| c.last_bulk.get(sh).cloned())
        };
        let _guard = InflightGuard {
            cache: Arc::clone(&self.sh_join),
            id: id.to_string(),
            sh: *sh,
            inf: Arc::clone(&inf),
        };
        let r = f(&mut slot);
        inf.finish(slot.clone());
        {
            let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(c) = g.clients.get_mut(id) {
                c.last_req = Instant::now();
                c.inflight.remove(sh);
                if let Some(s) = slot {
                    c.last_sh = Some((*sh, s));
                }
            }
        }
        r
    }

    pub(crate) fn seed_bulk(
        &self,
        client: Option<&str>,
        bag: &mut HashMap<[u8; 32], Arc<ShJoinSlot>>,
    ) {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            return;
        };
        let g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = g.clients.get(id) {
            for (k, v) in &c.last_bulk {
                bag.entry(*k).or_insert_with(|| v.clone());
            }
        }
    }

    pub(crate) fn promote_bulk(
        &self,
        client: Option<&str>,
        bag: HashMap<[u8; 32], Arc<ShJoinSlot>>,
    ) {
        let Some(id) = client.filter(|s| !s.is_empty()) else {
            return;
        };
        let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
        sweep_clients(&mut g.clients, Instant::now());
        let c = g.clients.entry(id.to_string()).or_default();
        c.last_req = Instant::now();
        c.last_bulk = bag;
        cap_bulk(c);
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
        sh_join: Arc::new(Mutex::new(JoinCache::default())),
        join_header_trusted: {
            #[cfg(unix)]
            {
                matches!(config.listen, EsploraListen::Unix(_))
            }
            #[cfg(not(unix))]
            {
                false
            }
        },
        block_template: config.block_template,
        gbt_cache: Arc::new(Mutex::new(None)),
    };

    // axum 0.8 path params use `{name}` (not `:name`).
    let rest = Router::new()
        .route("/block-template", get(handlers::block_template))
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
        .route("/broadcast", get(handlers::get_broadcast))
        .route("/txs/test", post(handlers::post_txs_test))
        .route("/txs/outspends", get(handlers::get_txs_outspends))
        .route("/txs/package", post(handlers::post_tx_package))
        .route("/addresses/txs", post(handlers::post_addresses_txs))
        .route(
            "/addresses/txs/summary",
            post(handlers::post_addresses_txs_summary),
        )
        .route("/scripthashes/txs", post(handlers::post_scripthashes_txs))
        .route(
            "/scripthashes/txs/summary",
            post(handlers::post_scripthashes_txs_summary),
        )
        .route("/address/{addr}", get(handlers::address_info))
        .route("/address/{addr}/utxo", get(handlers::address_utxo))
        .route("/address/{addr}/txs", get(handlers::address_txs))
        .route(
            "/address/{addr}/txs/summary",
            get(handlers::address_txs_summary),
        )
        .route(
            "/address/{addr}/txs/summary/{last}",
            get(handlers::address_txs_summary_cursor),
        )
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
            "/scripthash/{hash}/txs/summary",
            get(handlers::scripthash_txs_summary),
        )
        .route(
            "/scripthash/{hash}/txs/summary/{last}",
            get(handlers::scripthash_txs_summary_cursor),
        )
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
        .route(
            "/mempool/txids/page",
            get(crate::internal::get_mempool_txids_page),
        )
        .route(
            "/mempool/txids/page/{last}",
            get(crate::internal::get_mempool_txids_page_cursor),
        )
        .route("/mempool/txids", get(handlers::mempool_txids))
        .route("/mempool/recent", get(handlers::mempool_recent))
        .route("/fee-estimates", get(handlers::fee_estimates))
        .route("/fees/recommended", get(handlers::fees_recommended))
        .route("/v1/fees/recommended", get(handlers::fees_recommended))
        .route("/internal/txs", post(crate::internal::post_internal_txs))
        .route(
            "/internal/mempool/txs/all",
            get(crate::internal::get_internal_mempool_txs_all),
        )
        .route(
            "/internal/mempool/txs",
            get(crate::internal::get_internal_mempool_txs)
                .post(crate::internal::post_internal_mempool_txs),
        )
        .route(
            "/internal/mempool/txs/{last}",
            get(crate::internal::get_internal_mempool_txs_cursor),
        )
        .route(
            "/internal/block/{hash}/txs",
            get(crate::internal::get_internal_block_txs),
        )
        .route(
            "/internal/txs/outspends/by-txid",
            post(crate::internal::post_outspends_by_txid),
        )
        .route(
            "/internal/txs/outspends/by-outpoint",
            post(crate::internal::post_outspends_by_outpoint),
        )
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

    let app = rest
        .merge(ws_routes)
        .layer(middleware::from_fn(stamp_powered_by_mw))
        .with_state(state);

    match config.listen {
        EsploraListen::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let make = app.into_make_service_with_connect_info::<SocketAddr>();
                let serve = axum::serve(listener, make).with_graceful_shutdown(async move {
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
                socket_path: None,
                shutdown,
                task,
            })
        }
        #[cfg(unix)]
        EsploraListen::Unix(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
            }
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
                local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                socket_path: Some(path),
                shutdown,
                task,
            })
        }
    }
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
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => match build_tx_json_from_tx(
                    &st.query,
                    &tx,
                    st.network,
                    None,
                    st.mempool.as_deref(),
                ) {
                    Ok(v) => Json(v).into_response(),
                    Err(e) => store_err(e),
                },
                None => not_found(),
            },
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
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => {
                    let raw = bitcoin::consensus::serialize(&tx);
                    plain_ok(rbitcoin_primitives::hex_encode(raw))
                }
                None => not_found(),
            },
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/status` → Esplora confirmation status JSON.
async fn tx_status(
    State(st): State<AppState>,
    Path(txid_hex): Path<String>,
    AsOf(asof): AsOf,
) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.tx_fk_by_txid(&txid) {
            Ok(Some(fk)) => {
                let view = match pin_or_reject(&st.query, ChainViewKind::Tip, asof) {
                    Ok(v) => v,
                    Err(r) => return r,
                };
                let status = match &view {
                    Some(v) => tx_status_json_in(&st.query, fk, v),
                    None => Ok(json!({ "confirmed": false })),
                };
                match status {
                    Ok(v) => maybe_attach_view(Json(v).into_response(), view),
                    Err(e) => store_err(e),
                }
            }
            Ok(None) => {
                if asof.is_some() {
                    return not_found();
                }
                use bitcoin::hashes::Hash;
                let tid = bitcoin::Txid::from_byte_array(txid);
                if st.mempool.as_ref().is_some_and(|m| m.contains(&tid)) {
                    Json(json!({ "confirmed": false })).into_response()
                } else {
                    not_found()
                }
            }
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
        StoreError::Rejected(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()).into_response(),
    }
}

/// Esplora / Core display order (internal hash bytes reversed).
pub(crate) fn block_hash_hex(hash: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(hash)
}

/// Parse 32-byte hash/txid hex (display order) → internal byte order.
pub(crate) fn parse_hash32(s: &str) -> Result<[u8; 32], ()> {
    rbitcoin_primitives::parse_display_hash32(s).map_err(|_| ())
}

pub(crate) fn mempool_wire(st: &AppState, txid: &[u8; 32]) -> Option<bitcoin::Transaction> {
    use bitcoin::hashes::Hash;
    let tid = bitcoin::Txid::from_byte_array(*txid);
    st.mempool.as_ref().and_then(|m| m.get_tx(&tid))
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
    use crate::tx_json::tx_status_json;
    use rbitcoin_primitives::{Fk, Height};
    use rbitcoin_query::{Query, TxApply};
    use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use rbitcoin_query::testutil::FixtureChain;
    fn temp_query(label: &str) -> (rbitcoin_query::testutil::TempDir, Query) {
        rbitcoin_query::testutil::tiny_query_labeled(label)
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
            size: 0,
            weight: 0,
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

    async fn http_get_hdr(addr: SocketAddr, path: &str, client: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Rbitcoin-Client: {client}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        parse_http_response(&buf)
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

    async fn http_post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
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

    fn parse_http_response(buf: &[u8]) -> (u16, String) {
        let text = String::from_utf8_lossy(buf).into_owned();
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

    #[cfg(unix)]
    async fn http_get_unix(sock: &std::path::Path, path: &str) -> (u16, String) {
        use tokio::net::UnixStream;
        let mut stream = UnixStream::connect(sock).await.expect("unix connect");
        let req = format!("GET {path} HTTP/1.1\r\nHost: api\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        parse_http_response(&buf)
    }

    #[test]
    fn esplora_listen_parse_tcp_and_path() {
        assert!(matches!(
            EsploraListen::parse("127.0.0.1:3000", 3000).unwrap(),
            EsploraListen::Tcp(_)
        ));
        assert!(matches!(
            EsploraListen::parse("", 3000).unwrap(),
            EsploraListen::Tcp(a) if a.port() == 3000
        ));
        #[cfg(unix)]
        {
            assert!(matches!(
                EsploraListen::parse("/run/rbitcoin/esplora.sock", 3000).unwrap(),
                EsploraListen::Unix(_)
            ));
            assert!(matches!(
                EsploraListen::parse("./esplora.sock", 3000).unwrap(),
                EsploraListen::Unix(_)
            ));
        }
        assert!(EsploraListen::parse("not-an-addr", 3000).is_err());
    }

    #[test]
    fn client_id_ignored_on_public_tcp() {
        assert!(client_id_from(false, false, Some("x".into())).is_none());
        assert_eq!(
            client_id_from(false, true, Some("x".into())).as_deref(),
            Some("x")
        );
        assert_eq!(
            client_id_from(true, false, Some("x".into())).as_deref(),
            Some("x")
        );
        assert!(client_id_from(true, true, None).is_none());
    }

    #[test]
    fn join_idle_evicts_after_ttl() {
        let mut map = HashMap::new();
        let now = Instant::now();
        map.insert(
            "stale".into(),
            ClientJoins {
                last_req: now.checked_sub(JOIN_IDLE + Duration::from_secs(1)).unwrap(),
                ..ClientJoins::default()
            },
        );
        map.insert(
            "fresh".into(),
            ClientJoins {
                last_req: now,
                ..ClientJoins::default()
            },
        );
        sweep_clients(&mut map, now);
        assert!(!map.contains_key("stale"));
        assert!(map.contains_key("fresh"));
    }

    fn join_only_state(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>) -> AppState {
        AppState {
            query: q,
            network: Network::Regtest,
            mempool: None,
            max_body: 1 << 20,
            tip_tx: None,
            ws_sem: None,
            max_ws_message_bytes: 1024,
            max_track_addresses: 1,
            max_track_txs: 1,
            sh_join: cache,
            join_header_trusted: true,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        }
    }

    #[test]
    fn with_sh_join_empty_slot_unblocks_waiter() {
        let (_dir, q) = temp_query("join-empty-waiter");
        let st = Arc::new(join_only_state(
            Arc::new(q),
            Arc::new(Mutex::new(JoinCache::default())),
        ));
        let sh = [0x11u8; 32];
        let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_l = Arc::clone(&st);
        let leader = std::thread::spawn(move || {
            st_l.with_sh_join(Some("c1"), &sh, |slot| {
                *slot = None;
                let _ = leader_in.send(());
                let _ = release_rx.recv();
            });
        });
        leader_in_rx.recv().expect("leader entered f");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let st_w = Arc::clone(&st);
        let waiter = std::thread::spawn(move || {
            st_w.with_sh_join(Some("c1"), &sh, |slot| {
                let _ = done_tx.send(slot.is_none());
            });
        });
        std::thread::sleep(Duration::from_millis(50));
        let _ = release.send(());
        leader.join().expect("leader");
        let empty = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter unblocked after empty join");
        assert!(empty, "finished empty slot");
        waiter.join().expect("waiter");
    }

    #[test]
    fn with_sh_join_leader_panic_unblocks_waiter() {
        let (_dir, q) = temp_query("join-panic-waiter");
        let st = Arc::new(join_only_state(
            Arc::new(q),
            Arc::new(Mutex::new(JoinCache::default())),
        ));
        let sh = [0x22u8; 32];
        let (leader_in, leader_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_l = Arc::clone(&st);
        let leader = std::thread::spawn(move || {
            st_l.with_sh_join(Some("c1"), &sh, |_slot| {
                let _ = leader_in.send(());
                let _ = release_rx.recv();
                panic!("join leader unwind");
            });
        });
        leader_in_rx.recv().expect("leader entered f");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let st_w = Arc::clone(&st);
        let waiter = std::thread::spawn(move || {
            st_w.with_sh_join(Some("c1"), &sh, |_slot| {
                let _ = done_tx.send(());
            });
        });
        std::thread::sleep(Duration::from_millis(50));
        let _ = release.send(());
        let _ = leader.join();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter unblocked after leader panic");
        waiter.join().expect("waiter");
    }

    #[tokio::test]
    async fn with_sh_join_last1_clone_visible_to_overlapping_get() {
        use rbitcoin_store::script_hash;

        let (_a1, spk1) = regtest_p2wpkh();
        let (dir, q) = temp_query("join-last1-clone");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(Height(1), &h1, &[cb1, two_script_pay(0x11, spk1.clone())])
            .unwrap();
        let q = Arc::new(q);
        let sh1 = script_hash(spk1.as_bytes());
        let h1hex = block_hash_hex(&sh1);
        let cache = Arc::new(Mutex::new(JoinCache::default()));
        let app = app_with_join(Arc::clone(&q), Arc::clone(&cache), true);
        let (st, body) =
            oneshot_http(&app, get_with_client(&format!("/scripthash/{h1hex}"), "c1")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(cache.lock().unwrap().last_sh_key("c1"), Some(sh1));

        let st = Arc::new(join_only_state(Arc::clone(&q), Arc::clone(&cache)));
        let (holder_in, holder_in_rx) = std::sync::mpsc::channel::<()>();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let st_a = Arc::clone(&st);
        let holder = std::thread::spawn(move || {
            st_a.with_sh_join(Some("c1"), &sh1, |slot| {
                assert!(slot.is_some(), "holder must see warm last-1");
                let _ = holder_in.send(());
                let _ = release_rx.recv();
            });
        });
        holder_in_rx.recv().expect("holder entered f");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let st_b = Arc::clone(&st);
        let overlap = std::thread::spawn(move || {
            st_b.with_sh_join(Some("c1"), &sh1, |slot| {
                let _ = seen_tx.send(slot.is_some());
            });
        });
        let saw = seen_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("overlap entered f");
        assert!(
            saw,
            "overlapping same-sh GET must clone last-1, not take it"
        );
        let _ = release.send(());
        holder.join().expect("holder");
        overlap.join().expect("overlap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_listen_serves_tip_height() {
        let (dir, q) = temp_query("esplora-unix");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let q = Arc::new(q);
        let sock = dir.join("esplora.sock");
        let cfg = EsploraConfig::with_listen(EsploraListen::Unix(sock.clone()), Network::Regtest);
        let handle = run_esplora(cfg, q, None, None).await.expect("unix listen");
        assert!(sock.exists(), "socket file");
        let (st, body) = http_get_unix(&sock, "/blocks/tip/height").await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(body, "0");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn x_powered_by_on_tip_height() {
        let (dir, q) = temp_query("powered-by");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::new(q), None, None)
            .await
            .expect("listen");
        let (st, raw, body) = http_get_raw(handle.local_addr, "/blocks/tip/height").await;
        assert_eq!(st, 200, "{body}");
        let powered = header_value(&raw, "x-powered-by").expect("X-Powered-By");
        assert!(
            powered.starts_with("rbitcoin-esplora/"),
            "prefix: {powered}"
        );
        let hex_run = powered
            .bytes()
            .collect::<Vec<_>>()
            .windows(5)
            .any(|w| w.iter().all(|b| b.is_ascii_hexdigit()));
        assert!(hex_run, "need ≥5 hex for mempool failover: {powered}");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sh_join_slots_two_addresses_utxo() {
        let (a1, spk1) = regtest_p2wpkh();
        let (a2, spk2) = {
            use bitcoin::key::CompressedPublicKey;
            use bitcoin::secp256k1::{Secp256k1, SecretKey};
            use bitcoin::{Address, Network, PrivateKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
            let pk = PrivateKey::new(sk, Network::Regtest);
            let cpk = CompressedPublicKey::from_private_key(&secp, &pk).unwrap();
            let addr = Address::p2wpkh(&cpk, Network::Regtest);
            (addr.to_string(), addr.script_pubkey())
        };

        let (dir, q) = temp_query("sh-join-slots");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let pay = |tag: u8, spk: bitcoin::ScriptBuf| {
            let mut txid = [0u8; 32];
            txid[0] = tag;
            txid[31] = 0xaa;
            TxApply {
                tx: TxRecord {
                    txid,
                    version: 2,
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
                    script_sig: vec![],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(1_0000_0000, spk.to_bytes())],
            }
        };
        let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(Height(1), &h1, &[cb1, pay(0x11, spk1), pay(0x22, spk2)])
            .unwrap();

        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let addr = handle.local_addr;
        let p1 = format!("/address/{a1}/utxo");
        let p2 = format!("/address/{a2}/utxo");
        let ((st1, b1), (st2, b2)) =
            tokio::join!(http_get_hdr(addr, &p1, "a"), http_get_hdr(addr, &p2, "b"));
        assert_eq!(st1, 200, "{b1}");
        assert_eq!(st2, 200, "{b2}");
        let v1: Value = serde_json::from_str(&b1).unwrap();
        let v2: Value = serde_json::from_str(&b2).unwrap();
        assert_eq!(v1.as_array().map(|a| a.len()), Some(1), "{b1}");
        assert_eq!(v2.as_array().map(|a| a.len()), Some(1), "{b2}");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn two_script_pay(tag: u8, spk: bitcoin::ScriptBuf) -> TxApply {
        let mut txid = [0u8; 32];
        txid[0] = tag;
        txid[31] = 0xaa;
        TxApply {
            tx: TxRecord {
                txid,
                version: 2,
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
                script_sig: vec![],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1_0000_0000, spk.to_bytes())],
        }
    }

    fn app_with_join(q: Arc<Query>, cache: Arc<Mutex<JoinCache>>, trusted: bool) -> Router {
        let state = AppState {
            query: q,
            network: Network::Regtest,
            mempool: None,
            max_body: 1 << 20,
            tip_tx: None,
            ws_sem: None,
            max_ws_message_bytes: 1024,
            max_track_addresses: 1,
            max_track_txs: 1,
            sh_join: cache,
            join_header_trusted: trusted,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        };
        Router::new()
            .route("/scripthash/{hash}", get(handlers::scripthash_info))
            .route("/scripthash/{hash}/utxo", get(handlers::scripthash_utxo))
            .route("/scripthashes/txs", post(handlers::post_scripthashes_txs))
            .with_state(state)
    }

    async fn oneshot_http(
        app: &Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> (u16, String) {
        use tower::ServiceExt;
        let resp = app.clone().oneshot(req).await.expect("oneshot");
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    fn get_with_client(path: &str, client: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(path)
            .header("X-Rbitcoin-Client", client)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn http_sh_join_last1_last_bulk_and_header_trust() {
        use rbitcoin_store::script_hash;

        let (_a1, spk1) = regtest_p2wpkh();
        let (_a2, spk2) = {
            use bitcoin::key::CompressedPublicKey;
            use bitcoin::secp256k1::{Secp256k1, SecretKey};
            use bitcoin::{Address, PrivateKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
            let pk = PrivateKey::new(sk, Network::Regtest);
            let cpk = CompressedPublicKey::from_private_key(&secp, &pk).unwrap();
            let addr = Address::p2wpkh(&cpk, Network::Regtest);
            (addr.to_string(), addr.script_pubkey())
        };
        let (dir, q) = temp_query("sh-join-http");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(
            Height(1),
            &h1,
            &[
                cb1,
                two_script_pay(0x11, spk1.clone()),
                two_script_pay(0x22, spk2.clone()),
            ],
        )
        .unwrap();
        let q = Arc::new(q);
        let sh1 = script_hash(spk1.as_bytes());
        let sh2 = script_hash(spk2.as_bytes());
        let h1hex = block_hash_hex(&sh1);
        let h2hex = block_hash_hex(&sh2);
        let t2 = block_hash_hex(&[
            0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0xaa,
        ]);

        let cache = Arc::new(Mutex::new(JoinCache::default()));
        let app = app_with_join(Arc::clone(&q), Arc::clone(&cache), true);

        let (st, body) =
            oneshot_http(&app, get_with_client(&format!("/scripthash/{h1hex}"), "c1")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(cache.lock().unwrap().last_sh_key("c1"), Some(sh1));
        let (st, body) = oneshot_http(
            &app,
            get_with_client(&format!("/scripthash/{h1hex}/utxo"), "c1"),
        )
        .await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(cache.lock().unwrap().last_sh_key("c1"), Some(sh1));

        let (st, body) =
            oneshot_http(&app, get_with_client(&format!("/scripthash/{h2hex}"), "c1")).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(
            cache.lock().unwrap().last_sh_key("c1"),
            Some(sh2),
            "GET B replaces last-1"
        );

        let (st, body) =
            oneshot_http(&app, get_with_client(&format!("/scripthash/{h1hex}"), "c2")).await;
        assert_eq!(st, 200, "{body}");
        {
            let g = cache.lock().unwrap();
            assert_eq!(g.last_sh_key("c1"), Some(sh2));
            assert_eq!(g.last_sh_key("c2"), Some(sh1));
        }

        let body = serde_json::to_vec(&json!([&h1hex, &h2hex])).unwrap();
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/scripthashes/txs")
            .header("X-Rbitcoin-Client", "wallet")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .unwrap();
        let (st, resp) = oneshot_http(&app, req).await;
        assert_eq!(st, 200, "{resp}");
        assert_eq!(cache.lock().unwrap().bulk_len("wallet"), 2);
        {
            let st = join_only_state(Arc::clone(&q), Arc::clone(&cache));
            let mut bag = HashMap::new();
            st.seed_bulk(Some("wallet"), &mut bag);
            assert_eq!(bag.len(), 2);
            let g = cache.lock().unwrap();
            let c = g.clients.get("wallet").expect("wallet bulk");
            let packed: usize = c.last_bulk.values().map(|s| s.packed_bytes()).sum();
            assert!(packed <= JOIN_BULK_CAP, "last-bulk stays under 16 MiB");
            for (k, v) in &bag {
                let cached = c.last_bulk.get(k).expect("seeded key");
                assert!(
                    Arc::ptr_eq(cached, v),
                    "seed_bulk must Arc-clone last-bulk, not memcpy outs"
                );
            }
        }

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/scripthashes/txs?after_txid={t2}"))
            .header("X-Rbitcoin-Client", "wallet")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        let (st, resp) = oneshot_http(&app, req).await;
        assert_eq!(st, 200, "{resp}");
        assert_eq!(cache.lock().unwrap().bulk_len("wallet"), 2);

        let public = Arc::new(Mutex::new(JoinCache::default()));
        let pub_app = app_with_join(Arc::clone(&q), Arc::clone(&public), false);
        let (st, body) = oneshot_http(
            &pub_app,
            get_with_client(&format!("/scripthash/{h1hex}"), "ignored"),
        )
        .await;
        assert_eq!(st, 200, "{body}");
        assert!(
            public.lock().unwrap().last_sh_key("ignored").is_none(),
            "public TCP ignores X-Rbitcoin-Client"
        );

        let loopback = Arc::new(Mutex::new(JoinCache::default()));
        let lb_app = app_with_join(q, Arc::clone(&loopback), false);
        let mut req = get_with_client(&format!("/scripthash/{h1hex}"), "lb");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
        let (st, body) = oneshot_http(&lb_app, req).await;
        assert_eq!(st, 200, "{body}");
        assert_eq!(loopback.lock().unwrap().last_sh_key("lb"), Some(sh1));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn block_template_default_404() {
        let (dir, q) = temp_query("gbt-404");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let q = Arc::new(q);
        let cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let (st, body) = http_get(handle.local_addr, "/block-template").await;
        assert_eq!(st, 404, "{body}");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn block_template_enabled_no_tip_is_503() {
        let (dir, q) = temp_query("gbt-notip");
        let q = Arc::new(q);
        let mut cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.block_template = Some(BlockTemplateFn(Arc::new(|| Ok(json!({"height": 1})))));
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let (st, body) = http_get(handle.local_addr, "/block-template").await;
        assert_eq!(st, 503, "{body}");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn max_sh_creates_is_esplora_503() {
        let (dir, q) = temp_query("esplora-sh-cap");
        let mut prev = Fk::NULL;
        let mut parent = None;
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent);
            parent = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        q.set_max_sh_creates(2);
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let sh = block_hash_hex(&rbitcoin_store::script_hash(&[0x51]));
        let (st, body) = http_get(handle.local_addr, &format!("/scripthash/{sh}")).await;
        assert_eq!(st, 503, "{body}");
        assert!(
            body.contains("scripthash join exceeds --max-sh-creates"),
            "{body}"
        );
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn block_template_enabled_cache_and_503() {
        let (dir, q) = temp_query("gbt-on");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let q = Arc::new(q);
        let calls = Arc::new(AtomicU64::new(0));
        let c = Arc::clone(&calls);
        let mut cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        cfg.block_template = Some(BlockTemplateFn(Arc::new(move || {
            c.fetch_add(1, Ordering::Relaxed);
            Ok(json!({"height": 1, "rules": ["segwit"]}))
        })));
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;
        let (st, raw, body) = http_get_raw(addr, "/block-template").await;
        assert_eq!(st, 200, "{body}");
        assert!(
            raw.to_ascii_lowercase().contains("cache-control: no-store"),
            "{raw}"
        );
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["height"], 1);
        let (st, _) = http_get(addr, "/block-template").await;
        assert_eq!(st, 200);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "15s cache");
        let (h1, t1) = coinbase(1, prev, Some(h0.hash));
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let (st, _) = http_get(addr, "/block-template").await;
        assert_eq!(st, 200);
        assert_eq!(calls.load(Ordering::Relaxed), 2, "tip change invalidates");
        handle.shutdown().await;

        let calls2 = Arc::new(AtomicU64::new(0));
        let mut cfg = EsploraConfig::new("127.0.0.1:0".parse().unwrap());
        cfg.block_template = Some(BlockTemplateFn(Arc::new(|| Err("no hub".into()))));
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let (st, body) = http_get(handle.local_addr, "/block-template").await;
        assert_eq!(st, 503, "{body}");
        assert!(body.contains("no hub"), "{body}");
        let _ = calls2;
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

        let (st, body) = http_get(addr, "/no/such/path").await;
        assert_eq!(st, 404, "404 body={body}");
        assert!(body.to_ascii_lowercase().contains("not found") || body.contains("Not Found"));

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

        let (st, raw, body) = http_get_raw(addr, "/mempool").await;
        assert_eq!(
            st, 200,
            "mempool must not 503 on same-height replace: {body}"
        );
        assert!(
            header_value(&raw, HDR_CHAIN_TIP).is_none(),
            "mempool must not pin/stamp a chain view"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn http_503_chain_view_moved_omits_tip_header() {
        let (dir, q) = temp_query("http-503-moved");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let state = AppState {
            query: Arc::new(q),
            network: Network::Regtest,
            mempool: None,
            max_body: 1024,
            tip_tx: None,
            ws_sem: None,
            max_ws_message_bytes: 1024,
            max_track_addresses: 1,
            max_track_txs: 1,
            sh_join: Arc::new(Mutex::new(JoinCache::default())),
            join_header_trusted: false,
            block_template: None,
            gbt_cache: Arc::new(Mutex::new(None)),
        };
        async fn die_tip(State(st): State<AppState>) -> &'static str {
            st.query.disconnect_tip().unwrap();
            "ok"
        }
        let app = Router::new()
            .route("/blocks/tip/hash", get(die_tip))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                stamp_chain_view_mw,
            ))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (st, raw, body) = http_get_raw(addr, "/blocks/tip/hash").await;
        assert_eq!(st, 503, "body={body}");
        assert!(
            body.contains("chain view moved"),
            "503 body must name the move: {body}"
        );
        assert!(
            header_value(&raw, HDR_CHAIN_TIP).is_none(),
            "503 must not stamp a fork tip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::cognitive_complexity)] // one listener, path/asof/POST junk table
    #[tokio::test]
    async fn http_junk_paths_asof_and_post() {
        use rbitcoin_net::MempoolHub;

        let (dir, q) = temp_query("api-junk");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let q = Arc::new(q);
        let mp_dir = dir.join("mp");
        std::fs::create_dir_all(&mp_dir).unwrap();
        let hub = MempoolHub::open(&mp_dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), Some(hub), None)
            .await
            .expect("listen");
        let addr = handle.local_addr;
        let h0hex = block_hash_hex(&hash0);

        let (st, _) = http_get(addr, "/block/zz").await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, "/tx/aa").await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, "/scripthash/aa").await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, "/block-height/nope").await;
        assert_eq!(st, 400);
        let (st, _) = http_get(addr, "/address/not-an-address").await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, &format!("/tx/{h0hex}/outspend/nope")).await;
        assert_eq!(st, 400);
        let (st, _) = http_get(addr, "/blocks/nope").await;
        assert_eq!(st, 400);

        let (st, _) = http_get(addr, &format!("/tx/{h0hex}?asof={h0hex}")).await;
        assert_eq!(st, 404, "asof on full tx JSON is ungated");
        let (st, _) = http_get(addr, &format!("/mempool?asof={h0hex}")).await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, &format!("/tx/{h0hex}/status?asof=zz")).await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, &format!("/tx/{h0hex}/status?asof=")).await;
        assert_eq!(st, 404);
        let (st, _) = http_get(addr, "/tx/aa/status?asof=nothex").await;
        assert_eq!(st, 404);

        let (st, body) = http_post(addr, "/tx", b"zz").await;
        assert_eq!(st, 400, "{body}");
        assert!(body.contains("invalid hex"), "{body}");
        let (st, body) = http_post(addr, "/tx", b"").await;
        assert_eq!(st, 400, "{body}");
        let (st, body) = http_post(addr, "/txs/package", b"{}").await;
        assert_eq!(st, 400, "{body}");
        assert!(body.contains("JSON array"), "{body}");
        let (st, body) = http_post(addr, "/txs/package", b"not-json").await;
        assert_eq!(st, 400, "{body}");
        assert!(body.contains("invalid json"), "{body}");
        let (st, body) = http_post(addr, "/txs/package", b"[1]").await;
        assert_eq!(st, 400, "{body}");
        assert!(body.contains("hex string"), "{body}");

        let (st, _) = http_get(addr, "/tx").await;
        assert_eq!(st, 405);

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

    #[test]
    fn asof_query_is_gated_to_documented_routes() {
        assert!(path_accepts_asof("/tx/ab/status"));
        assert!(path_accepts_asof("/tx/ab/outspends"));
        assert!(path_accepts_asof("/tx/ab/outspend/0"));
        assert!(path_accepts_asof("/scripthash/ab/utxo"));
        assert!(path_accepts_asof("/address/bcrt1q/txs/chain/cd"));
        assert!(!path_accepts_asof("/tx/ab"));
        assert!(!path_accepts_asof("/mempool"));
        assert!(!path_accepts_asof("/scripthash/ab/txs/mempool"));
        assert!(path_never_pins("/mempool"));
        assert!(path_never_pins("/mempool/txids"));
        assert!(path_never_pins("/fee-estimates"));
        assert!(path_never_pins("/fees/recommended"));
        assert!(path_never_pins("/v1/fees/recommended"));
        assert!(path_never_pins("/tx"));
        assert!(!path_never_pins("/tx/ab"));
        assert!(parse_asof_param(&AsOfQuery { asof: None })
            .unwrap()
            .is_none());
        assert!(parse_asof_param(&AsOfQuery {
            asof: Some(String::new())
        })
        .is_err());
        assert!(parse_asof_param(&AsOfQuery {
            asof: Some("zz".into())
        })
        .is_err());
        assert!(parse_hash32("aa").is_err());
        assert!(parse_hash32("zz".repeat(32).as_str()).is_err());
    }

    /// No-hub Esplora: empty mempool, flat fee estimates, POST /tx is 503.
    /// Live `esplora_broadcast` always has a hub.
    #[tokio::test]
    async fn remaining_routes_fixture() {
        let (dir, q) = temp_query("remain");
        let (header, ta) = coinbase(0, Fk::NULL, None);
        q.connect_block(Height(0), &header, &[ta]).unwrap();
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), None, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let (st, body) = http_get(addr, "/mempool").await;
        assert_eq!(st, 200, "{body}");
        let mem: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(mem["count"], 0);

        let (st, body) = http_get(addr, "/fee-estimates").await;
        assert_eq!(st, 200, "{body}");
        let fees: serde_json::Value = serde_json::from_str(&body).unwrap();
        for t in [
            "1", "2", "3", "4", "5", "6", "10", "20", "144", "504", "1008",
        ] {
            assert_eq!(fees[t].as_f64(), Some(1.0), "{t}: {body}");
        }

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

    /// Reconstruct meters + no-hub empty mempool lists (HTTP JSON/raw/status ride
    /// `esplora_broadcast_visible_in_rpc_and_electrum`).
    #[allow(clippy::cognitive_complexity)] // meters + leftover header/height/status needles
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
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/block JSON uses stamped size/weight"
        );

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
        assert_eq!(block.txdata.len(), 1);
        assert!(
            q.sample_reset_reconstruct_archived() >= 1,
            "/block/:hash/raw must reconstruct wire"
        );

        let _ = q.sample_reset_reconstruct_archived();
        let (st, _) = http_get(addr, "/blocks").await;
        assert_eq!(st, 200);
        assert_eq!(
            q.sample_reset_reconstruct_archived(),
            0,
            "/blocks summaries use stamped size/weight"
        );

        let txid0 = block_hash_hex(&coinbase_txids[0]);
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
        assert_eq!(indexes, vec![0]);
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

        let (st, body) = http_get(addr, "/block-height/1").await;
        assert_eq!(st, 200, "block-height body={body}");
        assert_eq!(body, block_hash_hex(&hashes[1]));
        let (st, _) = http_get(addr, "/block-height/99").await;
        assert_eq!(st, 404);

        let hash_disp = block_hash_hex(&hashes[1]);
        let (st, body) = http_get(addr, &format!("/block/{hash_disp}/header")).await;
        assert_eq!(st, 200, "header body len={}", body.len());
        assert_eq!(body.len(), 160);
        let wire = q.wire_header_at_height(Height(1)).unwrap();
        let expected = encode_header_hex(&wire).unwrap();
        assert_eq!(body, expected);
        let miss = "ff".repeat(32);
        let (st, _) = http_get(addr, &format!("/block/{miss}/header")).await;
        assert_eq!(st, 404);

        let (fk, _) = q.get_tx_by_txid(&coinbase_txids[0]).unwrap().unwrap();
        let st_json = tx_status_json(&q, fk).unwrap();
        assert_eq!(st_json["confirmed"], true);
        assert_eq!(st_json["block_height"], 0);

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
        ws.send(WsMsg::Text(r#"{"action":"ping"}"#.into()))
            .await
            .unwrap();
        let ping = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("ping timeout")
            .expect("ws closed")
            .expect("ws err");
        let ping_text = match ping {
            WsMsg::Text(t) => t.as_str().to_owned(),
            other => panic!("expected pong text, got {other:?}"),
        };
        let ping_v: serde_json::Value = serde_json::from_str(&ping_text).unwrap();
        assert_eq!(ping_v["pong"], true, "{ping_text}");
        ws.send(WsMsg::Text(r#"{"action":"init"}"#.into()))
            .await
            .unwrap();
        let init = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("init timeout")
            .expect("ws closed")
            .expect("ws err");
        let init_text = match init {
            WsMsg::Text(t) => t.as_str().to_owned(),
            other => panic!("expected init text, got {other:?}"),
        };
        let init_v: serde_json::Value = serde_json::from_str(&init_text).unwrap();
        assert_eq!(init_v["block"]["height"], 1, "{init_text}");
        ws.send(WsMsg::Text(
            r#"{"action":"want","data":["blocks","stats"]}"#.into(),
        ))
        .await
        .unwrap();
        let stats = ws_recv_json(&mut ws, 3).await;
        assert!(stats.get("mempoolInfo").is_some(), "{stats}");
        assert!(stats.get("fees").is_some(), "{stats}");
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

        ws.send(WsMsg::Text(r#"{"foo":1}"#.into())).await.unwrap();
        ws.send(WsMsg::Text(r#"{"stop-track-addresses":true}"#.into()))
            .await
            .unwrap();
        ws.send(WsMsg::Text(r#"{"stop-track-txs":true}"#.into()))
            .await
            .unwrap();
        ws.send(WsMsg::Text(r#"{"track-address":"not-an-address"}"#.into()))
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("timeout waiting invalid-address error")
            .expect("ws closed")
            .expect("ws err");
        let err_text = match err {
            WsMsg::Text(t) => t.as_str().to_owned(),
            other => panic!("expected error text, got {other:?}"),
        };
        assert!(
            err_text.contains("invalid address"),
            "invalid address error: {err_text}"
        );
        let id = "ab".repeat(32);
        ws.send(WsMsg::Text(
            (format!(r#"{{"stop-track-tx":"{id}"}}"#)).into(),
        ))
        .await
        .unwrap();
        ws.send(WsMsg::Text(
            r#"{"stop-track-address":"bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz8z5y2"}"#.into(),
        ))
        .await
        .unwrap();
        ws.send(WsMsg::Text(format!(r#"{{"track-tx":"{id}"}}"#).into()))
            .await
            .unwrap();
        ws.send(WsMsg::Text(
            r#"{"track-addresses":["not-an-address"]}"#.into(),
        ))
        .await
        .unwrap();
        let err2 = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("timeout waiting track-addresses error")
            .expect("ws closed")
            .expect("ws err");
        let err2_text = match err2 {
            WsMsg::Text(t) => t.as_str().to_owned(),
            other => panic!("expected error text, got {other:?}"),
        };
        assert!(
            err2_text.contains("invalid address"),
            "track-addresses error: {err2_text}"
        );

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

    /// `want: stats` pushes GET /mempool + /fees/recommended shapes; admit bumps count.
    #[tokio::test]
    async fn ws_want_stats_mempoolinfo_and_fees() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use futures_util::SinkExt;
        use rbitcoin_net::MempoolHub;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (dir, q) = temp_query("ws-stats");
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

        ws.send(WsMsg::Text(r#"{"action":"want","data":["stats"]}"#.into()))
            .await
            .unwrap();

        let mut saw_zero = false;
        for _ in 0..8 {
            let v = ws_recv_json(&mut ws, 3).await;
            if v.get("mempoolInfo").is_some() && v.get("fees").is_some() {
                assert_eq!(v["mempoolInfo"]["count"], 0, "{v}");
                assert!(v["fees"].get("fastestFee").is_some(), "{v}");
                saw_zero = true;
                break;
            }
        }
        assert!(saw_zero, "expected mempoolInfo+fees on want stats");

        let pay = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        hub.accept_tx(&pay).expect("admit");

        let mut saw_bump = false;
        for _ in 0..8 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(info) = v.get("mempoolInfo") {
                assert!(
                    info["count"].as_u64().unwrap_or(0) >= 1,
                    "count should bump after admit, got {v}"
                );
                saw_bump = true;
                break;
            }
        }
        assert!(saw_bump, "expected mempoolInfo count bump after admit");

        let _ = ws.close(None).await;
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regtest P2WPKH address + scriptPubKey for wallet-style track-address tests.
    fn regtest_p2wpkh() -> (String, bitcoin::ScriptBuf) {
        regtest_p2wpkh_sk(7)
    }

    fn regtest_p2wpkh_sk(fill: u8) -> (String, bitcoin::ScriptBuf) {
        use bitcoin::key::CompressedPublicKey;
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::{Address, Network, PrivateKey};
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[fill; 32]).expect("sk");
        let pk = PrivateKey::new(sk, Network::Regtest);
        let cpk = CompressedPublicKey::from_private_key(&secp, &pk).expect("cpk");
        let addr = Address::p2wpkh(&cpk, Network::Regtest);
        let spk = addr.script_pubkey();
        (addr.to_string(), spk)
    }

    fn display_txid(txid: bitcoin::Txid) -> String {
        use bitcoin::hashes::Hash;
        rbitcoin_primitives::display_hash_hex(&txid.to_byte_array())
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
                    txids.contains(&pay_hex.as_str()),
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

    /// Subscribe snapshots live mempool txs; RBF emits address-removed; track-addresses is keyed.
    #[tokio::test]
    async fn ws_track_address_snapshot_removed_and_multi() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use futures_util::SinkExt;
        use rbitcoin_net::MempoolHub;
        use tokio_tungstenite::tungstenite::Message as WsMsg;

        let (addr_a, spk_a) = regtest_p2wpkh_sk(7);
        let (addr_b, spk_b) = regtest_p2wpkh_sk(8);
        let (dir, q) = temp_query("ws-snap");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut coinbase_txids = Vec::new();
        for h in 0..103u32 {
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

        let pay = |op: OutPoint, spk: bitcoin::ScriptBuf, value: u64| Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: op,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: spk,
            }],
        };

        let old = pay(
            OutPoint {
                txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
                vout: 0,
            },
            spk_a.clone(),
            49_0000_0000,
        );
        let old_hex = display_txid(old.compute_txid());
        hub.accept_tx(&old).expect("admit pay A");

        ws.send(WsMsg::Text(
            (format!(r#"{{"track-address":"{addr_a}"}}"#)).into(),
        ))
        .await
        .unwrap();

        let mut saw_snap = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(arr) = v.get("address-transactions").and_then(|a| a.as_array()) {
                let txids: Vec<&str> = arr
                    .iter()
                    .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                    .collect();
                assert!(
                    txids.iter().any(|t| *t == old_hex),
                    "subscribe snapshot should include live pay {old_hex}, got {txids:?}"
                );
                assert!(arr
                    .iter()
                    .any(|t| t.get("vin").and_then(|x| x.as_array()).is_some()));
                saw_snap = true;
                break;
            }
        }
        assert!(
            saw_snap,
            "expected address-transactions snapshot on subscribe"
        );

        let away = pay(
            OutPoint {
                txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
                vout: 0,
            },
            ScriptBuf::from_bytes(vec![0x51]),
            48_0000_0000,
        );
        hub.accept_tx(&away).expect("rbf away from A");

        let mut saw_removed = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(arr) = v
                .get("address-removed-transactions")
                .and_then(|a| a.as_array())
            {
                let txids: Vec<&str> = arr
                    .iter()
                    .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                    .collect();
                assert!(
                    txids.iter().any(|t| *t == old_hex),
                    "address-removed-transactions should include {old_hex}, got {txids:?}"
                );
                saw_removed = true;
                break;
            }
        }
        assert!(saw_removed, "expected address-removed-transactions on RBF");

        ws.send(WsMsg::Text(r#"{"stop-track-addresses":true}"#.into()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pay_a = pay(
            OutPoint {
                txid: bitcoin::Txid::from_byte_array(coinbase_txids[1]),
                vout: 0,
            },
            spk_a,
            49_0000_0000,
        );
        let pay_b = pay(
            OutPoint {
                txid: bitcoin::Txid::from_byte_array(coinbase_txids[2]),
                vout: 0,
            },
            spk_b,
            49_0000_0000,
        );
        let hex_a = display_txid(pay_a.compute_txid());
        let hex_b = display_txid(pay_b.compute_txid());
        hub.accept_tx(&pay_a).expect("admit A");
        hub.accept_tx(&pay_b).expect("admit B");

        ws.send(WsMsg::Text(
            (format!(r#"{{"track-addresses":["{addr_a}","{addr_b}"]}}"#)).into(),
        ))
        .await
        .unwrap();

        let mut saw_multi = false;
        for _ in 0..12 {
            let v = ws_recv_json(&mut ws, 3).await;
            if let Some(obj) = v
                .get("multi-address-transactions")
                .and_then(|o| o.as_object())
            {
                let ids_a: Vec<&str> = obj
                    .get(&addr_a)
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                            .collect()
                    })
                    .unwrap_or_default();
                let ids_b: Vec<&str> = obj
                    .get(&addr_b)
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.get("txid").and_then(|x| x.as_str()))
                            .collect()
                    })
                    .unwrap_or_default();
                assert!(
                    ids_a.iter().any(|t| *t == hex_a),
                    "multi {addr_a} should include {hex_a}, got {ids_a:?}"
                );
                assert!(
                    ids_b.iter().any(|t| *t == hex_b),
                    "multi {addr_b} should include {hex_b}, got {ids_b:?}"
                );
                saw_multi = true;
                break;
            }
        }
        assert!(
            saw_multi,
            "expected multi-address-transactions keyed by display address"
        );

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

    /// Mempool-only txs (not in Class A) must be full Esplora JSON, not a stub.
    #[tokio::test]
    async fn mempool_only_tx_json_has_vin_vout_size_weight() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use rbitcoin_net::MempoolHub;
        use rbitcoin_store::script_hash;

        let (dir, q) = temp_query("mp-tx-json");
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
        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(coinbase_txids[0]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        hub.accept_tx(&spend).expect("accept mempool spend");
        let txid_hex = display_txid(spend.compute_txid());
        let sh_hex = block_hash_hex(&script_hash(&[0x51]));

        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)), None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs/mempool")).await;
        assert_eq!(st, 200, "{body}");
        let arr: serde_json::Value = serde_json::from_str(&body).unwrap();
        let row = arr
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["txid"] == txid_hex);
        let row = row.expect("mempool list contains spend");
        assert!(row.get("vin").is_some(), "stub omitted vin: {row}");
        assert!(row.get("vout").is_some(), "stub omitted vout: {row}");
        assert!(row.get("size").is_some(), "stub omitted size: {row}");
        assert!(row.get("weight").is_some(), "stub omitted weight: {row}");
        assert_eq!(row["status"]["confirmed"], false);
        assert_eq!(row["fee"], 1_000);

        let (st, body) = http_get(addr, &format!("/scripthash/{sh_hex}/txs")).await;
        assert_eq!(st, 200, "{body}");
        let arr: serde_json::Value = serde_json::from_str(&body).unwrap();
        let row = arr
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["txid"] == txid_hex)
            .expect("combined /txs contains spend");
        assert!(row.get("vin").is_some(), "combined stub omitted vin: {row}");

        let (st, body) = http_get(addr, &format!("/tx/{txid_hex}")).await;
        assert_eq!(st, 200, "GET /tx mempool-only: {body}");
        let full: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(full.get("vin").is_some());
        assert!(full.get("vout").is_some());
        assert!(full.get("size").is_some());
        assert!(full.get("weight").is_some());
        assert_eq!(full["status"]["confirmed"], false);

        let (st, body) = http_get(addr, &format!("/tx/{txid_hex}/status")).await;
        assert_eq!(st, 200, "GET /tx status mempool-only: {body}");
        let status: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(status["confirmed"], false);

        let cb0 = block_hash_hex(&coinbase_txids[0]);
        let (st, body) = http_get(addr, &format!("/tx/{cb0}/outspend/0")).await;
        assert_eq!(st, 200, "mempool-spent confirmed coin: {body}");
        let os: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(os["spent"], true, "{os}");
        assert_eq!(os["txid"], txid_hex);
        assert_eq!(os["status"]["confirmed"], false);

        let (st, body) = http_get(addr, &format!("/tx/{txid_hex}/outspend/0")).await;
        assert_eq!(st, 200, "mempool-only create outspend: {body}");
        let os: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(os["spent"], false, "{os}");

        let hash0 = q.header_at_height(Height(0)).unwrap().unwrap().1.hash;
        let asof0 = block_hash_hex(&hash0);
        let (st, _, body) = http_get_raw(addr, &format!("/tx/{cb0}/outspend/0?asof={asof0}")).await;
        assert_eq!(st, 200, "asof outspend: {body}");
        let os: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(os["spent"], false, "asof omits mempool spend: {os}");

        let (st, hex_body) = http_get(addr, &format!("/tx/{txid_hex}/hex")).await;
        assert_eq!(st, 200, "{hex_body}");
        let (st, _) = http_get(addr, &format!("/tx/{txid_hex}/raw")).await;
        assert_eq!(st, 200);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn after_txid_skips_and_unknown_is_422() {
        use rbitcoin_store::script_hash;

        let (dir, q) = temp_query("after-txid");
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut txids = Vec::new();
        for h in 0..3u32 {
            let (header, ta) = coinbase(h, prev, parent_hash);
            parent_hash = Some(header.hash);
            txids.push(ta.tx.txid);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }
        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let addr = handle.local_addr;
        let sh = block_hash_hex(&script_hash(&[0x51]));
        let newest = block_hash_hex(&txids[2]);
        let mid = block_hash_hex(&txids[1]);
        let oldest = block_hash_hex(&txids[0]);

        let (st, body) = http_get(addr, &format!("/scripthash/{sh}/txs")).await;
        assert_eq!(st, 200, "{body}");
        let all: Vec<Value> = serde_json::from_str(&body).unwrap();
        let all_ids: Vec<&str> = all.iter().filter_map(|v| v["txid"].as_str()).collect();
        assert_eq!(
            all_ids,
            vec![newest.as_str(), mid.as_str(), oldest.as_str()]
        );

        let (st, body) = http_get(addr, &format!("/scripthash/{sh}/txs?after_txid={newest}")).await;
        assert_eq!(st, 200, "{body}");
        let page: Vec<Value> = serde_json::from_str(&body).unwrap();
        let page_ids: Vec<&str> = page.iter().filter_map(|v| v["txid"].as_str()).collect();
        assert_eq!(page_ids, vec![mid.as_str(), oldest.as_str()]);

        let (st, body) = http_get(
            addr,
            &format!("/scripthash/{sh}/txs/summary?after_txid={newest}"),
        )
        .await;
        assert_eq!(st, 200, "{body}");
        let sum: Vec<Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(sum[0]["txid"], mid);
        assert!(!sum.iter().any(|v| v["txid"] == newest));

        let unknown = "ff".repeat(32);
        let (st, body) =
            http_get(addr, &format!("/scripthash/{sh}/txs?after_txid={unknown}")).await;
        assert_eq!(st, 422, "{body}");
        assert!(body.contains("after_txid not found"), "{body}");
        let (st, body) = http_get(
            addr,
            &format!("/scripthash/{sh}/txs/summary?after_txid={unknown}"),
        )
        .await;
        assert_eq!(st, 422, "{body}");
        assert!(body.contains("after_txid not found"), "{body}");
        let (st, body) = http_get(addr, &format!("/scripthash/{sh}/txs?after_txid=zz")).await;
        assert_eq!(st, 422, "{body}");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn post_scripthashes_txs_merges_and_caps() {
        use rbitcoin_store::script_hash;

        let (a1, spk1) = regtest_p2wpkh();
        let (a2, spk2) = {
            use bitcoin::key::CompressedPublicKey;
            use bitcoin::secp256k1::{Secp256k1, SecretKey};
            use bitcoin::{Address, Network, PrivateKey};
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[9u8; 32]).unwrap();
            let pk = PrivateKey::new(sk, Network::Regtest);
            let cpk = CompressedPublicKey::from_private_key(&secp, &pk).unwrap();
            let addr = Address::p2wpkh(&cpk, Network::Regtest);
            (addr.to_string(), addr.script_pubkey())
        };

        let (dir, q) = temp_query("post-multi-txs");
        let (h0, t0) = coinbase(0, Fk::NULL, None);
        let prev = q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let pay = |tag: u8, spk: bitcoin::ScriptBuf| {
            let mut txid = [0u8; 32];
            txid[0] = tag;
            txid[31] = 0xaa;
            TxApply {
                tx: TxRecord {
                    txid,
                    version: 2,
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
                    script_sig: vec![],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(1_0000_0000, spk.to_bytes())],
            }
        };
        let (h1, cb1) = coinbase(1, prev, Some(h0.hash));
        let prev = q
            .connect_block(Height(1), &h1, &[cb1, pay(0x11, spk1.clone())])
            .unwrap();
        let (h2, cb2) = coinbase(2, prev, Some(h1.hash));
        q.connect_block(Height(2), &h2, &[cb2, pay(0x22, spk2.clone())])
            .unwrap();

        let q = Arc::new(q);
        let cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
        let handle = run_esplora(cfg, q, None, None).await.expect("listen");
        let addr = handle.local_addr;
        let sh1 = block_hash_hex(&script_hash(spk1.as_bytes()));
        let sh2 = block_hash_hex(&script_hash(spk2.as_bytes()));
        let t1 = block_hash_hex(&[
            0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0xaa,
        ]);
        let t2 = block_hash_hex(&[
            0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0xaa,
        ]);

        let body = serde_json::to_vec(&json!([&sh1, &sh2])).unwrap();
        let (st, resp) = http_post(addr, "/scripthashes/txs", &body).await;
        assert_eq!(st, 200, "{resp}");
        let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
        let ids: Vec<&str> = rows.iter().filter_map(|v| v["txid"].as_str()).collect();
        assert_eq!(ids, vec![t2.as_str(), t1.as_str()], "{resp}");

        let body = serde_json::to_vec(&json!([&a1, &a2])).unwrap();
        let (st, resp) = http_post(addr, "/addresses/txs", &body).await;
        assert_eq!(st, 200, "{resp}");
        let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(rows[0]["txid"], t2);

        let body = serde_json::to_vec(&json!([&sh1, &sh2])).unwrap();
        let (st, resp) = http_post(addr, "/scripthashes/txs/summary", &body).await;
        assert_eq!(st, 200, "{resp}");
        let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(rows[0]["txid"], t2);
        assert_eq!(rows[1]["txid"], t1);

        let (st, resp) =
            http_post(addr, &format!("/scripthashes/txs?after_txid={t2}"), &body).await;
        assert_eq!(st, 200, "{resp}");
        let rows: Vec<Value> = serde_json::from_str(&resp).unwrap();
        assert_eq!(rows[0]["txid"], t1);
        assert!(!rows.iter().any(|v| v["txid"] == t2));

        let unknown = "ff".repeat(32);
        let (st, resp) = http_post(
            addr,
            &format!("/scripthashes/txs?after_txid={unknown}"),
            &body,
        )
        .await;
        assert_eq!(st, 422, "{resp}");
        assert!(resp.contains("after_txid not found"), "{resp}");

        let too: Vec<String> = (0..301).map(|_| "aa".repeat(32)).collect();
        let body = serde_json::to_vec(&too).unwrap();
        let (st, resp) = http_post(addr, "/scripthashes/txs", &body).await;
        assert_eq!(st, 422, "{resp}");
        assert!(resp.contains("body too long"), "{resp}");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
