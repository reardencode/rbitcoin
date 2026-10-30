//! Esplora HTTP listener (axum + tower limits).

use crate::handlers;
use crate::tx_json::{build_tx_json, build_tx_json_from_tx, tx_status_json_in};
use axum::extract::{FromRequestParts, Path, Query as AxumQuery, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bitcoin::consensus::Encodable;
use bitcoin::Network;
use rbitcoin_electrum::ServeLimits;
use rbitcoin_net::MempoolHub;
use rbitcoin_net::RequestMeter;
use rbitcoin_primitives::Height;
use rbitcoin_query::{ChainView, ChainViewKind, Query, ShJoinSlot};
use rbitcoin_store::StoreError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Esplora REST requests: the `tip: perf` window and the `/metrics` totals.
#[doc(hidden)]
pub static METER: RequestMeter = RequestMeter::new();

/// Esplora REST request meters since the previous sample: `(count, sum_us, max_us)`.
/// Running totals are untouched ([`perf_totals`]).
pub fn sample_reset_perf() -> (u64, u64, u64) {
    METER.take_window()
}

/// Running Esplora REST totals for `/metrics`: `(requests, sum_us)`.
pub fn perf_totals() -> (u64, u64) {
    METER.totals()
}

pub async fn meter_rest(req: Request, next: Next) -> Response {
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
    METER.note(us);
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

pub const HDR_CHAIN_TIP: &str = "x-bitcoin-chain-tip";
pub const HDR_CHAIN_TIP_HEIGHT: &str = "x-bitcoin-chain-tip-height";

#[doc(hidden)]
pub fn stamp_chain_view_headers(resp: &mut Response, view: &ChainView) {
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
pub struct AsOfQuery {
    pub asof: Option<String>,
}

/// Parsed `?asof=` (None if omitted). Invalid hex is 404.
#[derive(Clone, Copy, Debug)]
pub struct AsOf(pub Option<[u8; 32]>);

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

#[allow(clippy::result_unit_err)] // a bad asof is (); the extractor maps it to not found
pub fn parse_asof_param(q: &AsOfQuery) -> Result<Option<[u8; 32]>, ()> {
    match q.asof.as_deref() {
        None => Ok(None),
        Some(s) => parse_hash32(s).map(Some),
    }
}

pub fn attach_chain_view(mut resp: Response, view: ChainView) -> Response {
    resp.extensions_mut().insert(view);
    resp
}

pub fn maybe_attach_view(resp: Response, view: Option<ChainView>) -> Response {
    match view {
        Some(v) => attach_chain_view(resp, v),
        None => resp,
    }
}

/// A JSON body whose encoded size is at least 4 KiB. The listener encodes it
/// on `rbtc-scripts-*` after the store join returns.
#[derive(Clone)]
struct HeavyJson(Arc<Value>);

/// Encode on this thread when the body is under 4 KiB. A heavier body waits
/// for [`ensure_json`] so a blocking-pool thread is not held across the encode.
///
/// Callers pass the same values `Json` used to take: a [`Value`], a list, or
/// a string.
#[doc(hidden)]
pub fn json_reply_here(v: impl Serialize) -> Response {
    let v = match serde_json::to_value(v) {
        Ok(v) => v,
        Err(_) => {
            return (
                [(header::CONTENT_TYPE, "application/json")],
                Vec::<u8>::from(&b"{}"[..]),
            )
                .into_response();
        }
    };
    json_reply_shared(Arc::new(v))
}

/// Light bodies encode here. A heavy body moves the `Arc` into the response
/// so [`ensure_json`] can hand it to `rbtc-scripts-*` without cloning.
#[doc(hidden)]
pub fn json_reply_shared(v: Arc<Value>) -> Response {
    if !rbitcoin_electrum::json_is_cpu_heavy(&v) {
        let bytes = serde_json::to_vec(v.as_ref()).unwrap_or_else(|_| b"{}".to_vec());
        return ([(header::CONTENT_TYPE, "application/json")], bytes).into_response();
    }
    let mut resp = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::empty())
        .expect("json response");
    resp.extensions_mut().insert(HeavyJson(v));
    resp
}

/// Finish a [`json_reply_here`] body. A light reply is unchanged.
#[doc(hidden)]
pub async fn ensure_json(resp: Response) -> Response {
    let (mut parts, body) = resp.into_parts();
    let Some(heavy) = parts.extensions.remove::<HeavyJson>() else {
        return Response::from_parts(parts, body);
    };
    let bytes = match rbitcoin_electrum::encode_json_body(heavy.0).await {
        Ok(bytes) => bytes,
        Err(()) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "json encode join failed").into_response();
        }
    };
    Response::from_parts(parts, axum::body::Body::from(bytes))
}

async fn finish_heavy_json(req: Request, next: Next) -> Response {
    ensure_json(next.run(req).await).await
}

#[allow(clippy::result_large_err)] // public error enum
pub fn pin_or_reject(
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

#[doc(hidden)]
#[allow(clippy::result_unit_err)] // a bad asof is (); the caller treats it as no view
pub fn asof_hash_from_uri(uri: &axum::http::Uri) -> Result<Option<[u8; 32]>, ()> {
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

#[doc(hidden)]
pub fn path_uses_sh_view(path: &str) -> bool {
    path.starts_with("/address/")
        || path.starts_with("/scripthash/")
        || path.starts_with("/addresses/")
        || path.starts_with("/scripthashes/")
}

/// COMPAT.md: `?asof=` on tx status/outspend(s), confirmed output and
/// tx-by-position reads, and address/scripthash `/`, `/utxo`, `/txs`,
/// `/txs/chain`, `/txs/summary` (not `/txs/mempool`, not `GET /tx/{txid}`).
#[doc(hidden)]
pub fn path_accepts_asof(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["tx", _, "status"]
            | ["tx", _, "outspends"]
            | ["tx", _, "outspend", _]
            | ["tx", _, "out", _]
            | ["block-height", _, "tx", _]
            | ["block-height", _, "tx", _, "out", _]
            | ["block-heights", "txs", "outs"]
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
            | ["address", _, "txs", "summary"]
            | ["scripthash", _, "txs", "summary"]
            | ["address", _, "txs", "summary", _]
            | ["scripthash", _, "txs", "summary", _]
    )
}

#[doc(hidden)]
pub fn path_never_pins(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    matches!(
        segs.as_slice(),
        ["mempool"]
            | ["mempool", _]
            | ["fee-estimates"]
            | ["tx"]
            | ["txs", "package"]
            | ["address", _, "txs", "mempool"]
            | ["scripthash", _, "txs", "mempool"]
    )
}

#[doc(hidden)]
pub fn powered_by_header() -> HeaderValue {
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

pub async fn stamp_powered_by_mw(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("x-powered-by", powered_by_header());
    resp
}

pub async fn stamp_chain_view_mw(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let asof = match asof_hash_from_uri(req.uri()) {
        Ok(v) => v,
        Err(()) => return not_found(),
    };
    let path = req.uri().path().to_string();
    if path_uses_sh_view(&path) && !st.query.sh_history_available() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            rbitcoin_query::SCRIPTHASH_INDEX_DISABLED,
        )
            .into_response();
    }
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

/// Opt-in `GET /block-template` builder (node injects GBT; tests inject a stub).
#[derive(Clone)]
pub struct BlockTemplateFn(pub Arc<dyn Fn() -> Result<Value, String> + Send + Sync>);

impl std::fmt::Debug for BlockTemplateFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockTemplateFn")
    }
}

pub struct GbtCache {
    pub at: Instant,
    pub tip: [u8; 32],
    pub updates: u64,
    pub body: Arc<Value>,
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

/// Esplora HTTP server config (listen + shared DoS floor).
#[derive(Clone, Debug)]
pub struct EsploraConfig {
    pub listen: EsploraListen,
    /// Shared with Electrum ([`ServeLimits::for_public_proxy`] defaults).
    pub limits: ServeLimits,
    /// Address encoding network (mainnet/testnet/signet/regtest).
    pub network: Network,
    /// `None` → `GET /block-template` is 404 (default).
    pub block_template: Option<BlockTemplateFn>,
    /// Requests in flight across `/blindbit/v1/` (>= 1), when mounted.
    pub blindbit_max_inflight: usize,
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
            block_template: None,
            blindbit_max_inflight: crate::blindbit::default_max_inflight(),
        }
    }
}

/// Stop bit for the HTTP serve task. `store(true)` wakes the accept loop.
pub struct EsploraStop {
    flag: AtomicBool,
    wake: Notify,
}

impl EsploraStop {
    pub fn new(initial: bool) -> Arc<Self> {
        Arc::new(Self {
            flag: AtomicBool::new(initial),
            wake: Notify::new(),
        })
    }

    pub fn load(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    pub fn store(&self, value: bool) {
        self.flag.store(value, Ordering::SeqCst);
        if value {
            self.wake.notify_waiters();
        }
    }

    fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }
}

/// Listener admission. `waiting` counts requests that found the limit full.
#[doc(hidden)]
pub struct AdmitGate {
    sem: Arc<Semaphore>,
    arrived: AtomicUsize,
    waiting: AtomicUsize,
    holding: AtomicUsize,
    wake: Notify,
}

impl AdmitGate {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(max.max(1))),
            arrived: AtomicUsize::new(0),
            waiting: AtomicUsize::new(0),
            holding: AtomicUsize::new(0),
            wake: Notify::new(),
        })
    }

    #[doc(hidden)]
    pub fn arrived(&self) -> usize {
        self.arrived.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn holding(&self) -> usize {
        self.holding.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }
}

async fn admit_connection(
    State(gate): State<Arc<AdmitGate>>,
    req: Request,
    next: Next,
) -> Response {
    gate.arrived.fetch_add(1, Ordering::SeqCst);
    gate.wake.notify_waiters();
    let permit = match gate.sem.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            gate.waiting.fetch_add(1, Ordering::SeqCst);
            gate.wake.notify_waiters();
            let Ok(permit) = gate.sem.clone().acquire_owned().await else {
                gate.waiting.fetch_sub(1, Ordering::SeqCst);
                gate.wake.notify_waiters();
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            };
            gate.waiting.fetch_sub(1, Ordering::SeqCst);
            gate.wake.notify_waiters();
            permit
        }
    };
    gate.holding.fetch_add(1, Ordering::SeqCst);
    gate.wake.notify_waiters();
    let _permit = permit;
    struct Hold(Arc<AdmitGate>);
    impl Drop for Hold {
        fn drop(&mut self) {
            self.0.holding.fetch_sub(1, Ordering::SeqCst);
            self.0.wake.notify_waiters();
        }
    }
    let _hold = Hold(Arc::clone(&gate));
    next.run(req).await
}

pub struct EsploraHandle {
    /// Bound TCP address. Unix listen leaves this as `127.0.0.1:0`.
    pub local_addr: SocketAddr,
    pub socket_path: Option<PathBuf>,
    pub shutdown: Arc<EsploraStop>,
    /// Listener slot gate. Tests wait on `waiting` instead of a settle sleep.
    #[doc(hidden)]
    pub admit: Arc<AdmitGate>,
    /// `/blindbit/v1/` permit gate, mounted only while tweaks are on.
    #[doc(hidden)]
    pub blindbit: Arc<crate::blindbit::BlindbitLimit>,
    pub task: JoinHandle<()>,
}

impl EsploraHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true);
        self.task.abort();
        let _ = self.task.await;
    }
}

#[derive(Clone)]
pub struct AppState {
    pub query: Arc<Query>,
    pub network: Network,
    pub mempool: Option<Arc<MempoolHub>>,
    pub max_body: usize,
    /// Per-client last-1 GET + last-bulk POST joins (unix or `join_header_trusted`).
    pub sh_join: Arc<Mutex<JoinCache>>,
    /// Unix listen trusts `X-Rbitcoin-Client` without a TCP peer address.
    pub join_header_trusted: bool,
    pub block_template: Option<BlockTemplateFn>,
    pub gbt_cache: Arc<Mutex<Option<GbtCache>>>,
}

#[doc(hidden)]
pub const JOIN_IDLE: Duration = Duration::from_secs(30);
#[doc(hidden)]
pub const JOIN_MAX_CLIENTS: usize = 256;
#[doc(hidden)]
pub const JOIN_BULK_CAP: usize = 16 * 1024 * 1024;

#[doc(hidden)]
pub struct InflightJoin {
    /// `None` = still running. `Some(slot)` = finished (`slot` may be empty).
    pub done: Mutex<Option<Option<Arc<ShJoinSlot>>>>,
    pub cv: std::sync::Condvar,
    /// Start order of the leader. Waiters publish this stamp.
    pub seq: u64,
    /// Set under `done` before a waiter sleeps. The wait, not the join result.
    queued: AtomicBool,
    queued_mu: Mutex<()>,
    queued_cv: std::sync::Condvar,
}

impl InflightJoin {
    /// `true` once a waiter has observed an unfinished leader and is in `cv.wait`.
    #[doc(hidden)]
    pub fn wait_queued(&self, timeout: std::time::Duration) -> bool {
        let g = self.queued_mu.lock().unwrap_or_else(|p| p.into_inner());
        let (_g, status) = self
            .queued_cv
            .wait_timeout_while(g, timeout, |_| !self.queued.load(Ordering::SeqCst))
            .unwrap_or_else(|p| p.into_inner());
        !status.timed_out()
    }

    #[doc(hidden)]
    pub fn finish(&self, slot: Option<Arc<ShJoinSlot>>) {
        let mut d = self.done.lock().unwrap_or_else(|p| p.into_inner());
        if d.is_none() {
            *d = Some(slot);
            self.cv.notify_all();
        }
    }
}

/// Finishes the inflight slot (and drops the map entry) if the leader unwinds.
#[doc(hidden)]
pub struct InflightGuard {
    pub cache: Arc<Mutex<JoinCache>>,
    pub id: String,
    pub sh: [u8; 32],
    pub inf: Arc<InflightJoin>,
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

/// Publish last-1 only when this join started at or after the one stored.
///
/// The leader stamps the counter before `f` runs. A waiter publishes that
/// same stamp, so waking after a newer script is not a newer start.
/// Matching on the scripthash alone would refuse a later sequential script.
#[doc(hidden)]
pub fn publish_last_sh(c: &mut ClientJoins, sh: &[u8; 32], slot: Arc<ShJoinSlot>, seq: u64) {
    let stored = c
        .last_sh
        .as_ref()
        .map(|(_, _, stored_seq)| *stored_seq)
        .unwrap_or(0);
    if seq >= stored {
        c.last_sh = Some((*sh, slot, seq));
    }
}

#[doc(hidden)]
pub fn take_join_seq(c: &mut ClientJoins) -> u64 {
    c.join_seq = c.join_seq.saturating_add(1);
    c.join_seq
}

#[doc(hidden)]
pub struct ClientJoins {
    pub last_sh: Option<([u8; 32], Arc<ShJoinSlot>, u64)>,
    pub join_seq: u64,
    pub last_bulk: HashMap<[u8; 32], Arc<ShJoinSlot>>,
    pub last_req: Instant,
    pub inflight: HashMap<[u8; 32], Arc<InflightJoin>>,
}

impl Default for ClientJoins {
    fn default() -> Self {
        Self {
            last_sh: None,
            join_seq: 0,
            last_bulk: HashMap::new(),
            last_req: Instant::now(),
            inflight: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub struct JoinCache {
    pub clients: HashMap<String, ClientJoins>,
}

impl JoinCache {
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn last_sh_key(&self, id: &str) -> Option<[u8; 32]> {
        self.clients
            .get(id)
            .and_then(|c| c.last_sh.as_ref().map(|(k, _, _)| *k))
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn bulk_len(&self, id: &str) -> usize {
        self.clients.get(id).map(|c| c.last_bulk.len()).unwrap_or(0)
    }
}

#[doc(hidden)]
pub fn sweep_clients(map: &mut HashMap<String, ClientJoins>, now: Instant) {
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

#[doc(hidden)]
pub fn cap_bulk(c: &mut ClientJoins) {
    let last_sh_bytes = c
        .last_sh
        .as_ref()
        .map(|(_, s, _)| s.packed_bytes())
        .unwrap_or(0);
    let mut bytes: usize =
        last_sh_bytes.saturating_add(c.last_bulk.values().map(|s| s.packed_bytes()).sum());
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

#[doc(hidden)]
pub fn retain_join_budget(c: &mut ClientJoins) {
    if c.last_sh
        .as_ref()
        .is_some_and(|(_, s, _)| s.packed_bytes() > JOIN_BULK_CAP)
    {
        c.last_sh = None;
    }
    cap_bulk(c);
}

#[doc(hidden)]
pub fn trusted_client_id(unix_or_trusted: bool, header: Option<String>) -> Option<String> {
    if unix_or_trusted {
        header
    } else {
        None
    }
}

#[derive(Clone)]
pub struct JoinClient(pub Option<String>);

impl FromRequestParts<AppState> for JoinClient {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let header = if state.join_header_trusted {
            parts
                .headers
                .get("x-rbitcoin-client")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        Ok(JoinClient(trusted_client_id(
            state.join_header_trusted,
            header,
        )))
    }
}

impl AppState {
    pub fn with_sh_join<R>(
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
            if c.last_sh.as_ref().is_some_and(|(k, _, _)| k == sh) {
                let seq = take_join_seq(c);
                let mut slot = c.last_sh.as_ref().map(|(_, s, _)| s.clone());
                drop(g);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        publish_last_sh(c, sh, s, seq);
                        c.last_req = Instant::now();
                        retain_join_budget(c);
                    }
                }
                return r;
            }
            if let Some(inf) = c.inflight.get(sh).cloned() {
                let seq = inf.seq;
                Err((inf, seq))
            } else {
                let seq = take_join_seq(c);
                let inf = Arc::new(InflightJoin {
                    done: Mutex::new(None),
                    cv: std::sync::Condvar::new(),
                    seq,
                    queued: AtomicBool::new(false),
                    queued_mu: Mutex::new(()),
                    queued_cv: std::sync::Condvar::new(),
                });
                c.inflight.insert(*sh, Arc::clone(&inf));
                Ok((inf, seq))
            }
        };
        let (inf, seq) = match inflight {
            Err((inf, seq)) => {
                let mut d = inf.done.lock().unwrap_or_else(|p| p.into_inner());
                while d.is_none() {
                    inf.queued.store(true, Ordering::SeqCst);
                    inf.queued_cv.notify_all();
                    d = inf.cv.wait(d).unwrap_or_else(|p| p.into_inner());
                }
                let mut slot = (*d).clone().flatten();
                drop(d);
                let r = f(&mut slot);
                if let Some(s) = slot {
                    let mut g = self.sh_join.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some(c) = g.clients.get_mut(id) {
                        publish_last_sh(c, sh, s, seq);
                        c.last_req = Instant::now();
                        retain_join_budget(c);
                    }
                }
                return r;
            }
            Ok((inf, seq)) => (inf, seq),
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
                    publish_last_sh(c, sh, s, seq);
                }
                retain_join_budget(c);
            }
        }
        r
    }

    pub fn seed_bulk(&self, client: Option<&str>, bag: &mut HashMap<[u8; 32], Arc<ShJoinSlot>>) {
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

    pub fn promote_bulk(&self, client: Option<&str>, bag: HashMap<[u8; 32], Arc<ShJoinSlot>>) {
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

/// electrs `/internal/*` bulk REST. Merged only on unix listen.
#[cfg(unix)]
#[doc(hidden)]
pub fn internal_routes() -> Router<AppState> {
    Router::new()
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
}

#[cfg(unix)]
#[doc(hidden)]
pub fn bind_unix_mode(
    path: &std::path::Path,
    mode: u32,
) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// Start Esplora **plain HTTP** on `config.listen`.
///
/// TLS is external (reverse proxy). App [`ServeLimits`] always apply
/// (concurrency, body size, request timeout).
///
/// Optional `mempool` enables fee estimates, mempool summary, and `POST /tx`.
pub async fn run_esplora(
    config: EsploraConfig,
    query: Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
) -> Result<EsploraHandle, std::io::Error> {
    let shutdown = EsploraStop::new(false);
    let shutdown_c = Arc::clone(&shutdown);

    let max_conn = config.limits.max_connections.max(1);
    let max_body = config.limits.max_request_bytes.max(1);
    let idle = config.limits.idle_timeout;
    // Floor for request timeout: at least 1s so unit tests with short idle still work.
    let timeout = idle.max(Duration::from_secs(1));

    let state = AppState {
        query,
        network: config.network,
        mempool,
        max_body,
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
        .route(
            "/block-height/{height}/tx/{index}",
            get(handlers::block_height_tx),
        )
        .route(
            "/block-height/{height}/tx/{index}/out/{vout}",
            get(handlers::block_height_tx_out),
        )
        .route("/tx/{txid}/out/{vout}", get(handlers::tx_out))
        .route(
            "/block-heights/txs/outs",
            post(handlers::post_block_height_outs),
        )
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
        .route("/fee-estimates", get(handlers::fee_estimates));
    #[cfg(unix)]
    let rest = if matches!(config.listen, EsploraListen::Unix(_)) {
        rest.merge(internal_routes())
    } else {
        rest
    };
    // Outer → inner: timeout → concurrency → body → meter → chain-view stamp
    // → heavy JSON encode. The timeout goes on last, outside the limit, so
    // the wait for a slot counts against it.
    let admit = AdmitGate::new(max_conn);
    let blindbit_limit = crate::blindbit::BlindbitLimit::new(config.blindbit_max_inflight.max(1));
    let listener_layers = |r: Router<AppState>| {
        r.layer(middleware::from_fn(finish_heavy_json))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                stamp_chain_view_mw,
            ))
            .layer(middleware::from_fn(meter_rest))
            .layer(RequestBodyLimitLayer::new(max_body))
            // One gate, cloned, shares its semaphore, so `max_conn` bounds the listener.
            .layer(middleware::from_fn_with_state(
                Arc::clone(&admit),
                admit_connection,
            ))
    };
    let request_timeout = || TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout);
    let rest = listener_layers(rest.fallback(fallback_404)).layer(request_timeout());
    // BlindBit takes its own permit before a listener slot, so a scan queued
    // on it holds no slot. One timeout covers both waits. Merged after the
    // listener layers, so they wrap these routes once.
    let rest = if state.query.sptweaks_enabled() {
        let blindbit = listener_layers(crate::blindbit::blindbit_routes())
            .layer(middleware::from_fn_with_state(
                Arc::clone(&blindbit_limit),
                crate::blindbit::blindbit_permit_mw,
            ))
            .layer(request_timeout());
        rest.merge(blindbit)
    } else {
        rest
    };

    let app = rest
        .layer(middleware::from_fn(stamp_powered_by_mw))
        .with_state(state);

    match config.listen {
        EsploraListen::Tcp(addr) => {
            let listener = TcpListener::bind(addr).await?;
            let local_addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let make = app.into_make_service_with_connect_info::<SocketAddr>();
                let serve = axum::serve(listener, make).with_graceful_shutdown(async move {
                    loop {
                        let wake = shutdown_c.notified();
                        if shutdown_c.load() {
                            break;
                        }
                        wake.await;
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
                admit: Arc::clone(&admit),
                blindbit: Arc::clone(&blindbit_limit),
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
            let listener = bind_unix_mode(&path, 0o660)?;
            let task = tokio::spawn(async move {
                let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                    loop {
                        let wake = shutdown_c.notified();
                        if shutdown_c.load() {
                            break;
                        }
                        wake.await;
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
                admit: Arc::clone(&admit),
                blindbit: Arc::clone(&blindbit_limit),
                task,
            })
        }
    }
}

pub async fn tip_height(State(st): State<AppState>) -> Response {
    match st.query.tip_height() {
        Some(h) => (StatusCode::OK, format!("{}", h.0)).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, "no chain tip").into_response(),
    }
}

pub async fn tip_hash(State(st): State<AppState>) -> Response {
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
pub async fn block_height(State(st): State<AppState>, Path(height): Path<u32>) -> Response {
    match st.query.header_at_height(Height(height)) {
        Ok(Some((_fk, rec))) => plain_ok(block_hash_hex(&rec.hash)),
        Ok(None) => not_found(),
        Err(e) => store_err(e),
    }
}

/// `GET /block/:hash/header` → 80-byte header hex.
pub async fn block_header(State(st): State<AppState>, Path(hash_hex): Path<String>) -> Response {
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
pub async fn tx_full(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match build_tx_json(&st.query, fk, st.network, None) {
                Ok(v) => json_reply_here(v),
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
                    Ok(v) => json_reply_here(v),
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
pub async fn tx_hex(State(st): State<AppState>, Path(txid_hex): Path<String>) -> Response {
    handlers::spawn_join(move || {
        let Ok(txid) = parse_hash32(&txid_hex) else {
            return not_found();
        };
        match st.query.get_tx_by_txid(&txid) {
            Ok(Some((fk, _))) => match st.query.tx_wire_bytes(fk) {
                Ok(raw) => plain_ok(rbitcoin_primitives::hex_encode(&(raw))),
                Err(e) => store_err(e),
            },
            Ok(None) => match mempool_wire(&st, &txid) {
                Some(tx) => {
                    let raw = bitcoin::consensus::serialize(&tx);
                    plain_ok(rbitcoin_primitives::hex_encode(&(raw)))
                }
                None => not_found(),
            },
            Err(e) => store_err(e),
        }
    })
    .await
}

/// `GET /tx/:txid/status` → Esplora confirmation status JSON.
pub async fn tx_status(
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
                    Ok(v) => maybe_attach_view(json_reply_here(v), view),
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
                    json_reply_here(json!({ "confirmed": false }))
                } else {
                    not_found()
                }
            }
            Err(e) => store_err(e),
        }
    })
    .await
}

pub async fn fallback_404() -> Response {
    not_found()
}

pub fn plain_ok(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

pub fn store_err(e: rbitcoin_query::QueryError) -> Response {
    match e {
        StoreError::NotFound => not_found(),
        StoreError::Pruned { .. } => (StatusCode::NOT_FOUND, "pruned").into_response(),
        StoreError::Stale(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        StoreError::Rejected(m) => (StatusCode::SERVICE_UNAVAILABLE, m).into_response(),
        e @ StoreError::ShCreatesCap { .. } => {
            (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response()
        }
        other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()).into_response(),
    }
}

/// Esplora / Core display order (internal hash bytes reversed).
pub fn block_hash_hex(hash: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(*hash)
}

/// Parse 32-byte hash/txid hex (display order) → internal byte order.
#[allow(clippy::result_unit_err)] // bad hex is (); callers map it to not found
pub fn parse_hash32(s: &str) -> Result<[u8; 32], ()> {
    rbitcoin_primitives::parse_display_hash32(s).map_err(|_| ())
}

pub fn mempool_wire(st: &AppState, txid: &[u8; 32]) -> Option<bitcoin::Transaction> {
    use bitcoin::hashes::Hash;
    let tid = bitcoin::Txid::from_byte_array(*txid);
    st.mempool.as_ref().and_then(|m| m.get_tx(&tid))
}

#[doc(hidden)]
pub fn encode_header_hex(hdr: &bitcoin::block::Header) -> Result<String, String> {
    let mut buf = Vec::with_capacity(80);
    hdr.consensus_encode(&mut buf)
        .map_err(|_| "header encode".to_string())?;
    Ok(rbitcoin_primitives::hex_encode(&(buf)))
}
