//! Line-delimited JSON-RPC Electrum server (TCP).
//!
//! Confirmed history from the store; unconfirmed + broadcast via optional
//! [`MempoolHub`] (plan P6, libre-relay-class).

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use rbitcoin_consensus::ChainParams;
use rbitcoin_net::{BlockingRegion, MempoolHub};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::{ChainView, ChainViewKind, HistoryFilter, Query, ShJoinSlot};
use rbitcoin_store::{script_hash, StoreError};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::JoinHandle;

const PROTOCOL_MIN: &str = "1.4";
const PROTOCOL_MAX: &str = "1.4.2";
// Dialect version: trailing `asof:<blockhash>`. Not a dotted-int; `protocol_max` stays 1.4.2.
const PROTOCOL_ASOF: &str = "1.4.2-asof";
/// First `server.version` element. Cake Wallet `getNodeIsElectrs()` requires
/// this string (lowercased) to contain `electrs` before it will probe
/// `blockchain.tweaks.subscribe [0, 1, false]`.
const SERVER_VERSION: &str = concat!("rbitcoin-electrs ", env!("CARGO_PKG_VERSION"));

/// One JSON-RPC request line. Junk is `None`; must not panic.
pub fn parse_electrum_request_line(line: &str) -> Option<Value> {
    serde_json::from_str(line).ok()
}

/// Tip-follow 5s DEBUG `tip: perf`: JSON-RPC request count this window.
static METER_REQ: AtomicU64 = AtomicU64::new(0);
/// Sum of dispatch walls (µs).
static METER_US: AtomicU64 = AtomicU64::new(0);
/// Max single dispatch wall (µs).
static METER_MAX_US: AtomicU64 = AtomicU64::new(0);

/// Sample-and-reset Electrum request meters: `(count, sum_us, max_us)`.
pub fn sample_reset_perf() -> (u64, u64, u64) {
    (
        METER_REQ.swap(0, Ordering::Relaxed),
        METER_US.swap(0, Ordering::Relaxed),
        METER_MAX_US.swap(0, Ordering::Relaxed),
    )
}

fn meter_dispatch_wall(us: u64) {
    METER_REQ.fetch_add(1, Ordering::Relaxed);
    METER_US.fetch_add(us, Ordering::Relaxed);
    let mut cur = METER_MAX_US.load(Ordering::Relaxed);
    while us > cur {
        match METER_MAX_US.compare_exchange_weak(cur, us, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(c) => cur = c,
        }
    }
}

/// Max simultaneous query-surface clients (Electrum / future Esplora).
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Max request payload bytes (Electrum: one JSON-RPC line incl. `\n`; Esplora: body).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1_048_576;
/// Alias for shared docs / Esplora body cap ([`DEFAULT_MAX_LINE_BYTES`]).
pub const DEFAULT_MAX_REQUEST_BYTES: usize = DEFAULT_MAX_LINE_BYTES;
/// Max scripthash subscriptions per Electrum connection (notify fan-out).
pub const DEFAULT_MAX_SCRIPTHASH_SUBS: usize = 1_000;
/// Idle read timeout — disconnect quiet clients (DoS of FD/tasks).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 120;
/// Max raw tx hex chars for `transaction.broadcast` (~4 MiB wire → 8 MiB hex).
pub const DEFAULT_MAX_BROADCAST_HEX: usize = 8_388_608;

/// Shared application DoS bounds for internet-facing query surfaces.
///
/// Defaults are sized for a **public bind behind a TLS reverse proxy** (or a
/// private LAN bind). The node always enforces these limits — binding only on
/// localhost is **not** required for safety. TLS, rate limiting at the edge,
/// and auth remain operator / proxy concerns.
///
/// Electrum uses this today; Esplora (HTTP) reuses the same type for connection
/// / body / idle caps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeLimits {
    /// Max concurrent clients (TCP accept or HTTP).
    pub max_connections: usize,
    /// Max request payload (Electrum line or HTTP body), bytes.
    pub max_request_bytes: usize,
    /// Disconnect if no complete request within this duration.
    pub idle_timeout: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self::for_public_proxy()
    }
}

impl ServeLimits {
    /// Defaults suitable when the listen address is reachable from untrusted
    /// clients **behind** TLS termination / a reverse proxy.
    pub fn for_public_proxy() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ElectrumConfig {
    pub listen: SocketAddr,
    pub banner: String,
    pub donation_address: String,
    /// Genesis hash (display order hex) for features.
    pub genesis_hash_hex: String,
    /// Shared connection / request / idle bounds (also used by future Esplora).
    pub limits: ServeLimits,
    /// Max `blockchain.scripthash.subscribe` entries per connection.
    pub max_scripthash_subs: usize,
    /// Max hex length accepted by `blockchain.transaction.broadcast`.
    pub max_broadcast_hex: usize,
    /// `blockchain.tweaks.subscribe` sends `done` at a wave boundary after
    /// this wall time so Cake resubscribes. [`Duration::ZERO`] seals after
    /// wave 0 (tests). Default [`crate::tweaks::SUBSCRIBE_CHUNK`].
    pub tweaks_chunk: Duration,
    /// Omit served P2TR outs with `value <=` this (sats). `0` serves all.
    /// Default [`crate::tweaks::DEFAULT_TWEAKS_MIN_DUST`].
    pub tweaks_min_dust: u64,
}

impl ElectrumConfig {
    pub fn for_params(listen: SocketAddr, params: &ChainParams) -> Self {
        let genesis = params.genesis_hash.to_byte_array();
        Self {
            listen,
            banner: "rbitcoin electrum — libre-relay-class (0.1 sat/vB, no dust ban, full RBF)"
                .into(),
            donation_address: String::new(),
            genesis_hash_hex: rbitcoin_primitives::display_hash_hex(&genesis),
            limits: ServeLimits::for_public_proxy(),
            max_scripthash_subs: DEFAULT_MAX_SCRIPTHASH_SUBS,
            max_broadcast_hex: DEFAULT_MAX_BROADCAST_HEX,
            tweaks_chunk: crate::tweaks::SUBSCRIBE_CHUNK,
            tweaks_min_dust: crate::tweaks::DEFAULT_TWEAKS_MIN_DUST,
        }
    }

    /// Max concurrent Electrum clients ([`ServeLimits::max_connections`]).
    pub fn max_connections(&self) -> usize {
        self.limits.max_connections
    }

    /// Max JSON-RPC request line bytes ([`ServeLimits::max_request_bytes`]).
    pub fn max_line_bytes(&self) -> usize {
        self.limits.max_request_bytes
    }

    /// Idle read timeout ([`ServeLimits::idle_timeout`]).
    pub fn idle_timeout(&self) -> Duration {
        self.limits.idle_timeout
    }
}

pub struct ElectrumHandle {
    pub local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
    clients: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ElectrumHandle {
    pub async fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for t in self.tasks.drain(..) {
            t.abort();
        }
        // Client tasks do not observe the accept-loop flag; abort so SIGINT
        // is not blocked behind a scripthash history / mempool restatus.
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        for t in clients.drain(..) {
            t.abort();
        }
    }
}

/// Tip notification for header subscriptions.
#[derive(Clone, Debug)]
pub struct TipNotify {
    pub height: u32,
    pub header_hex: String,
    /// Set when this tip replaced a previous prefix (reorg / same-height).
    /// Subscribe restatuses every watched scripthash, not only the new block.
    pub reorg_from_height: Option<u32>,
}

/// Start Electrum **plain TCP** listener.
///
/// `mempool` enables broadcast, unconfirmed history/balance, fee estimates, and
/// `transaction.get` fallback. Without it, confirmed-only behaviour remains.
///
/// TLS is intentionally not built in — terminate TLS at nginx/caddy/haproxy
/// (or similar) and proxy to this TCP port. Safe for internet-facing deployment
/// **only with app [`ServeLimits`] always on** plus edge TLS/limits; do not treat
/// “localhost-only bind” as the sole safety model.
///
/// **DoS limits:** [`ElectrumConfig::limits`] ([`ServeLimits`]) plus
/// scripthash-sub and broadcast-hex caps on [`ElectrumConfig`].
pub async fn run_electrum(
    config: ElectrumConfig,
    query: Arc<Query>,
    params: ChainParams,
    tip_tx: broadcast::Sender<TipNotify>,
    mempool: Option<Arc<MempoolHub>>,
) -> Result<ElectrumHandle, std::io::Error> {
    let listener = TcpListener::bind(config.listen).await?;
    let local_addr = listener.local_addr()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_c = shutdown.clone();
    let max_conn = config.max_connections().max(1);
    let conn_sem = Arc::new(Semaphore::new(max_conn));
    let config = Arc::new(config);
    let params = Arc::new(params);
    let clients: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let clients_c = clients.clone();

    let task = tokio::spawn(async move {
        loop {
            if shutdown_c.load(Ordering::SeqCst) {
                break;
            }
            let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
            match accept {
                Ok(Ok((stream, peer))) => {
                    let Ok(permit) = conn_sem.clone().try_acquire_owned() else {
                        rbitcoin_log::warn!(
                            "electrum: reject {peer} (at max_connections={max_conn})"
                        );
                        drop(stream);
                        continue;
                    };
                    rbitcoin_log::info!("electrum: connect {peer}");
                    let q = query.clone();
                    let cfg = config.clone();
                    let p = params.clone();
                    let tip_rx = tip_tx.subscribe();
                    let mp = mempool.clone();
                    let stop = shutdown_c.clone();
                    let h = tokio::spawn(async move {
                        let _connection_slot = permit;
                        let how = handle_client(stream, peer, q, cfg, p, tip_rx, mp, stop).await;
                        match how {
                            Ok(()) => rbitcoin_log::info!("electrum: disconnect {peer}"),
                            Err(e) => {
                                rbitcoin_log::info!("electrum: disconnect {peer} ({e})")
                            }
                        }
                    });
                    let mut g = clients_c.lock().unwrap_or_else(|e| e.into_inner());
                    g.retain(|t| !t.is_finished());
                    g.push(h);
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    });

    Ok(ElectrumHandle {
        local_addr,
        shutdown,
        tasks: vec![task],
        clients,
    })
}

/// Read one `\n`-terminated line with a hard byte cap (prevents OOM without newline).
pub async fn read_line_capped<R>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<String>, std::io::Error>
where
    R: AsyncBufReadExt + Unpin,
{
    let max_bytes = max_bytes.max(1);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                // EOF mid-line — treat as complete if under cap.
                if buf.len() > max_bytes {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "electrum request line too long",
                    ));
                }
                Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
            };
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len().saturating_add(take) > max_bytes {
                reader.consume(take);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "electrum request line too long",
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if buf.len().saturating_add(available.len()) > max_bytes {
            let n = available.len();
            reader.consume(n);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "electrum request line too long",
            ));
        }
        buf.extend_from_slice(available);
        let n = available.len();
        reader.consume(n);
    }
}

struct ElectrumConn {
    protocol: String,
    header_sub: bool,
    sh_subs: HashSet<[u8; 32]>,
    sh_join: Option<ShJoinSlot>,
}

impl ElectrumConn {
    fn new() -> Self {
        Self {
            protocol: String::new(),
            header_sub: false,
            sh_subs: HashSet::new(),
            sh_join: None,
        }
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[allow(clippy::cognitive_complexity)] // Electrum session dispatch
async fn handle_client<S>(
    stream: S,
    peer: SocketAddr,
    query: Arc<Query>,
    config: Arc<ElectrumConfig>,
    params: Arc<ChainParams>,
    mut tip_rx: broadcast::Receiver<TipNotify>,
    mempool: Option<Arc<MempoolHub>>,
    stop: Arc<AtomicBool>,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut conn = ElectrumConn::new();
    let mut last_sent_status: HashMap<[u8; 32], String> = HashMap::new();
    let notify = Arc::new(Notify::new());
    let mut mempool_rx = mempool.as_ref().map(|m| m.subscribe_announces());
    let idle = config.idle_timeout();
    let max_line = config.max_line_bytes();
    let mut sh_seen = query.sh_indexed_through_height();
    let mut sh_tick = tokio::time::interval(Duration::from_millis(50));
    sh_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        tokio::select! {
            biased;
            _ = async {
                while !stop.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } => break,
            tip = tip_rx.recv() => {
                match tip {
                    Ok(t) => {
                        if conn.header_sub {
                            let msg = json!({
                                "jsonrpc": "2.0",
                                "method": "blockchain.headers.subscribe",
                                "params": [{ "hex": t.header_hex, "height": t.height }]
                            });
                            write_line(&mut writer, &msg).await?;
                        }
                        if !conn.sh_subs.is_empty() {
                            let heights = if t.reorg_from_height.is_some() {
                                None
                            } else {
                                Some(vec![t.height])
                            };
                            emit_sh_notes(
                                &mut writer,
                                &query,
                                mempool.clone(),
                                &conn.sh_subs,
                                &mut last_sent_status,
                                heights,
                            )
                            .await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !conn.sh_subs.is_empty() {
                            emit_sh_notes(
                                &mut writer,
                                &query,
                                mempool.clone(),
                                &conn.sh_subs,
                                &mut last_sent_status,
                                None,
                            )
                            .await?;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = async {
                if conn.sh_subs.is_empty() {
                    std::future::pending::<()>().await;
                } else {
                    sh_tick.tick().await;
                }
            } => {
                let now = query.sh_indexed_through_height();
                let Some(scan) = tick_scan(sh_seen, now) else {
                    continue;
                };
                if conn.sh_subs.is_empty() {
                    sh_seen = now;
                    continue;
                }
                sh_seen = now;
                emit_sh_notes(
                    &mut writer,
                    &query,
                    mempool.clone(),
                    &conn.sh_subs,
                    &mut last_sent_status,
                    scan,
                )
                .await?;
            }
            ann = async {
                if let Some(rx) = mempool_rx.as_mut() {
                    Some(rx.recv().await)
                } else {
                    std::future::pending::<()>().await;
                    None
                }
            } => {
                // Only restatus hashes this tx (or its RBF victims) actually touch.
                // Re-walking every subscribe on every mempool accept pegs CPUs
                // (Cake: tens of gap-limit subs × full history + full-mempool scan).
                if let Some(Ok(ann)) = ann {
                    if let Some(mp) = &mempool {
                        for sh in conn.sh_subs.iter() {
                            let hit = ann.scripthashes.iter().any(|s| s == sh)
                                || ann.replaced_scripthashes.iter().any(|s| s == sh);
                            if !hit {
                                continue;
                            }
                            if let Ok(status) = scripthash_status_full(&query, mp, sh) {
                                let Some(status) = take_new_status(
                                    &mut last_sent_status,
                                    &conn.sh_subs,
                                    *sh,
                                    status,
                                ) else {
                                    continue;
                                };
                                let msg = json!({
                                    "jsonrpc": "2.0",
                                    "method": "blockchain.scripthash.subscribe",
                                    "params": [hash_hex_rev(sh), status]
                                });
                                let _ = write_line(&mut writer, &msg).await;
                            }
                        }
                    }
                }
            }
            line = tokio::time::timeout(idle, read_line_capped(&mut reader, max_line)) => {
                let line = match line {
                    Ok(Ok(Some(l))) => l,
                    Ok(Ok(None)) => {
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        if e.kind() == std::io::ErrorKind::InvalidData {
                            let resp = json!({
                                "jsonrpc":"2.0","id": null,
                                "error": {"code": -32600, "message": "request line too long"}
                            });
                            let _ = write_line(&mut writer, &resp).await;
                            return Err(e);
                        }
                        return Err(e);
                    }
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "idle timeout",
                        ));
                    }
                };
                if line.trim().is_empty() {
                    continue;
                }
                let req: Value = match parse_electrum_request_line(&line) {
                    Some(v) => v,
                    None => continue,
                };
                let id = req.get("id").cloned().unwrap_or(Value::Null);
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let params_v = req.get("params").cloned().unwrap_or(json!([]));
                if method == "blockchain.tweaks.subscribe" {
                    serve_tweaks_subscribe(
                        &mut reader,
                        &mut writer,
                        &query,
                        &params,
                        &peer,
                        id,
                        &params_v,
                        idle,
                        max_line,
                        config.tweaks_chunk,
                        config.tweaks_min_dust,
                    )
                    .await?;
                    continue;
                }
                let t0 = Instant::now();
                let mut stamped: Option<ChainView> = None;
                let result = if method_stays_on_worker(method) {
                    dispatch_with_join(
                        method,
                        &params_v,
                        &query,
                        &config,
                        &params,
                        mempool.as_deref(),
                        &mut conn,
                    )
                } else {
                    let q = Arc::clone(&query);
                    let cfg = Arc::clone(&config);
                    let p = Arc::clone(&params);
                    let mp = mempool.clone();
                    let method_owned = method.to_string();
                    let params_owned = params_v.clone();
                    let mut work = ElectrumConn {
                        protocol: conn.protocol.clone(),
                        header_sub: conn.header_sub,
                        sh_subs: conn.sh_subs.clone(),
                        sh_join: conn.sh_join.take(),
                    };
                    let stamp = method_stamps_chain_tip(&method_owned);
                    match tokio::task::spawn_blocking(move || {
                        let _g = BlockingRegion::enter();
                        let asof_ok = work.protocol.as_str() == PROTOCOL_ASOF;
                        let (r, view) = if stamp {
                            electrum_at_chain_view(
                                &q,
                                &method_owned,
                                &params_owned,
                                asof_ok,
                                |q, params, view, is_asof| {
                                    dispatch_pinned(
                                        &method_owned,
                                        params,
                                        q,
                                        &cfg,
                                        &p,
                                        mp.as_deref(),
                                        &mut work,
                                        view,
                                        is_asof,
                                    )
                                },
                            )
                        } else {
                            (
                                dispatch_pinned(
                                    &method_owned,
                                    &params_owned,
                                    &q,
                                    &cfg,
                                    &p,
                                    mp.as_deref(),
                                    &mut work,
                                    None,
                                    false,
                                ),
                                None,
                            )
                        };
                        (r, work, view)
                    })
                    .await
                    {
                        Ok((r, work, view)) => {
                            conn = work;
                            stamped = view;
                            r
                        }
                        Err(e) => {
                            return Err(std::io::Error::other(format!(
                                "electrum dispatch join: {e}"
                            )));
                        }
                    }
                };
                drop_unsubscribed_status(&mut last_sent_status, &conn.sh_subs);
                let wall_ms = t0.elapsed().as_millis() as u64;
                meter_dispatch_wall(t0.elapsed().as_micros() as u64);
                let params_s = serde_json::to_string(&params_v).unwrap_or_else(|_| "[]".into());
                let resp = match result {
                    Ok(v) => {
                        if method == "blockchain.scripthash.subscribe" {
                            if let (Ok(sh), Some(status)) =
                                (param_scripthash(&params_v, 0), v.as_str())
                            {
                                last_sent_status.insert(sh, status.to_string());
                            }
                        }
                        rbitcoin_log::api_call(
                            "electrum",
                            &peer.to_string(),
                            method,
                            &params_s,
                            wall_ms,
                            None,
                        );
                        rpc_result(&id, &v, stamped.as_ref())
                    }
                    Err(e) => {
                        rbitcoin_log::api_call(
                            "electrum",
                            &peer.to_string(),
                            method,
                            &params_s,
                            wall_ms,
                            Some(&e),
                        );
                        json!({"jsonrpc":"2.0","id": id, "error": {"code": 1, "message": e}})
                    }
                };
                write_line(&mut writer, &resp).await?;
                let _ = &notify;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Tweaks stream: JSON-RPC result = first height, then one notify per
/// following height, then `{"message":"done"}`. Honor `count` through tip.
/// Answer `server.ping` while computing.
async fn serve_tweaks_subscribe<R, W>(
    reader: &mut R,
    writer: &mut W,
    query: &Arc<Query>,
    chain: &Arc<ChainParams>,
    peer: &SocketAddr,
    id: Value,
    params_v: &Value,
    idle: Duration,
    max_line: usize,
    chunk: Duration,
    min_dust: u64,
) -> Result<(), std::io::Error>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWrite + Unpin,
{
    let req = match crate::tweaks::parse_req(params_v) {
        Ok(r) => r,
        Err(e) => {
            rbitcoin_log::api_call(
                "electrum",
                &peer.to_string(),
                "blockchain.tweaks.subscribe",
                &serde_json::to_string(params_v).unwrap_or_else(|_| "[]".into()),
                0,
                Some(&e),
            );
            write_line(
                writer,
                &json!({"jsonrpc":"2.0","id": id, "error": {"code": 1, "message": e}}),
            )
            .await?;
            return Ok(());
        }
    };
    let tip = query.tip_height().map(|h| h.0);
    let last = crate::tweaks::last_height(req.start, req.count, tip);
    let t0 = Instant::now();
    let Some(last) = last else {
        let first = match crate::tweaks::height_map_json(
            query,
            chain,
            req.start,
            !req.historical,
            min_dust,
        ) {
            Ok(v) => v,
            Err(e) => {
                rbitcoin_log::api_call(
                    "electrum",
                    &peer.to_string(),
                    "blockchain.tweaks.subscribe",
                    &serde_json::to_string(params_v).unwrap_or_else(|_| "[]".into()),
                    t0.elapsed().as_millis() as u64,
                    Some(&e),
                );
                write_line(
                    writer,
                    &json!({"jsonrpc":"2.0","id": id, "error": {"code": 1, "message": e}}),
                )
                .await?;
                return Ok(());
            }
        };
        let wall_ms = t0.elapsed().as_millis() as u64;
        meter_dispatch_wall(t0.elapsed().as_micros() as u64);
        rbitcoin_log::api_call(
            "electrum",
            &peer.to_string(),
            "blockchain.tweaks.subscribe",
            &serde_json::to_string(params_v).unwrap_or_else(|_| "[]".into()),
            wall_ms,
            None,
        );
        write_rpc_result(writer, &id, &first).await?;
        write_line(writer, &crate::tweaks::done_notify()).await?;
        return Ok(());
    };
    let limits = crate::tweaks::subscribe_serve_limits(req.historical);
    let wave_fut = {
        let q = Arc::clone(query);
        let c = Arc::clone(chain);
        let start_h = req.start;
        async move {
            tokio::task::spawn_blocking(move || {
                crate::tweaks::first_subscribe_wave(&q, &c, start_h, last, limits, min_dust)
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()))
        }
    };
    let wave = match wave_fut.await {
        Ok(v) => v,
        Err(e) => {
            rbitcoin_log::api_call(
                "electrum",
                &peer.to_string(),
                "blockchain.tweaks.subscribe",
                &serde_json::to_string(params_v).unwrap_or_else(|_| "[]".into()),
                t0.elapsed().as_millis() as u64,
                Some(&e),
            );
            write_line(
                writer,
                &json!({"jsonrpc":"2.0","id": id, "error": {"code": 1, "message": e}}),
            )
            .await?;
            return Ok(());
        }
    };
    let wall_ms = t0.elapsed().as_millis() as u64;
    meter_dispatch_wall(t0.elapsed().as_micros() as u64);
    rbitcoin_log::api_call(
        "electrum",
        &peer.to_string(),
        "blockchain.tweaks.subscribe",
        &serde_json::to_string(params_v).unwrap_or_else(|_| "[]".into()),
        wall_ms,
        None,
    );
    write_rpc_result(writer, &id, &wave.result_json).await?;
    write_raw_lines(writer, &wave.rest_notifies).await?;

    // Remaining heights after wave 0. Pre-taproot empty waves (no store), else
    // budgeted thin load then per-height notifies. Hole → one height.
    // `server.ping` must not drop the in-flight wave.
    // Cake electrs caps count at 1000 then done; we seal at a wave boundary
    // after `chunk` wall so Cake resubscribes. Wave 0 always completed above.
    let mut next = req.start.saturating_add(wave.consumed.max(1));
    let limits = crate::tweaks::subscribe_serve_limits(req.historical);
    let more = next <= last;
    if more && !crate::tweaks::seal_subscribe_chunk(t0.elapsed(), chunk, more) {
        let spawn_wave = |batch_start: u32| {
            let q = Arc::clone(query);
            let c = Arc::clone(chain);
            let lim = limits;
            let last_h = last;
            tokio::task::spawn_blocking(move || {
                crate::tweaks::remaining_notify_lines(&q, &c, batch_start, last_h, lim, min_dust)
            })
        };
        let mut batch_start = next;
        let mut handle = spawn_wave(batch_start);
        loop {
            let batch = loop {
                tokio::select! {
                    biased;
                    line = tokio::time::timeout(idle, read_line_capped(reader, max_line)) => {
                        match line {
                            Ok(Ok(Some(l))) => {
                                if !l.trim().is_empty() {
                                    if let Ok(req) = serde_json::from_str::<Value>(&l) {
                                        let ping_id = req.get("id").cloned().unwrap_or(Value::Null);
                                        if req.get("method").and_then(|m| m.as_str()) == Some("server.ping")
                                        {
                                            write_line(
                                                writer,
                                                &json!({"jsonrpc":"2.0","id": ping_id, "result": null}),
                                            )
                                            .await?;
                                        }
                                    }
                                }
                                continue;
                            }
                            Ok(Ok(None)) => return Ok(()),
                            Ok(Err(e)) => return Err(e),
                            Err(_) => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "idle timeout",
                                ));
                            }
                        }
                    }
                    map = &mut handle => {
                        break map.unwrap_or_else(|e| Err(e.to_string()));
                    }
                }
            };
            let batch = match batch {
                Ok(v) => v,
                Err(e) => {
                    rbitcoin_log::api_call(
                        "electrum",
                        &peer.to_string(),
                        "blockchain.tweaks.subscribe",
                        &format!("[{batch_start},batch]"),
                        0,
                        Some(&e),
                    );
                    break;
                }
            };
            let n = batch.consumed.max(1);
            next = batch_start.saturating_add(n);
            let more = next <= last;
            if more && !crate::tweaks::seal_subscribe_chunk(t0.elapsed(), chunk, more) {
                handle = spawn_wave(next);
            }
            write_raw_lines(writer, &batch.lines).await?;
            if !more || crate::tweaks::seal_subscribe_chunk(t0.elapsed(), chunk, more) {
                break;
            }
            batch_start = next;
        }
    }
    write_line(writer, &crate::tweaks::done_notify()).await?;
    Ok(())
}

async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Value,
) -> Result<(), std::io::Error> {
    let mut s = serde_json::to_string(msg).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

fn restatus_notes(
    query: &Query,
    mempool: Option<&MempoolHub>,
    subs: &[[u8; 32]],
    heights: Option<&[u32]>,
) -> Vec<([u8; 32], String)> {
    let mut out = Vec::new();
    for sh in subs {
        let hit = match heights {
            None => true,
            Some(hs) => hs.iter().any(|h| {
                query
                    .scripthash_touched_at_height(sh, Height(*h))
                    .ok()
                    .unwrap_or(false)
            }),
        };
        if !hit {
            continue;
        }
        let status = if let Some(mp) = mempool {
            scripthash_status_full(query, mp, sh).ok()
        } else {
            query
                .scripthash_history(sh)
                .ok()
                .and_then(|h| scripthash_status(Some(query), &h).ok())
        };
        if let Some(status) = status {
            out.push((*sh, status));
        }
    }
    out
}

const TICK_SCAN_MAX_GAP: u32 = 32;

fn tick_scan(seen: Option<u32>, now: Option<u32>) -> Option<Option<Vec<u32>>> {
    if seen == now {
        return None;
    }
    match (seen, now) {
        (Some(a), Some(b)) if b > a => {
            let gap = b.saturating_sub(a);
            if gap > TICK_SCAN_MAX_GAP {
                Some(None)
            } else {
                Some(Some((a.saturating_add(1)..=b).collect()))
            }
        }
        _ => Some(None),
    }
}

fn drop_unsubscribed_status(
    last_sent: &mut HashMap<[u8; 32], String>,
    sh_subs: &HashSet<[u8; 32]>,
) {
    last_sent.retain(|k, _| sh_subs.contains(k));
}

fn take_new_status(
    last_sent: &mut HashMap<[u8; 32], String>,
    sh_subs: &HashSet<[u8; 32]>,
    sh: [u8; 32],
    status: String,
) -> Option<String> {
    drop_unsubscribed_status(last_sent, sh_subs);
    if last_sent.get(&sh) == Some(&status) {
        return None;
    }
    last_sent.insert(sh, status.clone());
    Some(status)
}

async fn emit_sh_notes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    query: &Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
    sh_subs: &HashSet<[u8; 32]>,
    last_sent: &mut HashMap<[u8; 32], String>,
    heights: Option<Vec<u32>>,
) -> Result<(), std::io::Error> {
    let q = Arc::clone(query);
    let subs: Vec<[u8; 32]> = sh_subs.iter().copied().collect();
    let notes = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        restatus_notes(&q, mempool.as_deref(), &subs, heights.as_deref())
    })
    .await
    .unwrap_or_default();
    for (sh, status) in notes {
        let Some(status) = take_new_status(last_sent, sh_subs, sh, status) else {
            continue;
        };
        let msg = json!({
            "jsonrpc": "2.0",
            "method": "blockchain.scripthash.subscribe",
            "params": [hash_hex_rev(&sh), status]
        });
        write_line(writer, &msg).await?;
    }
    Ok(())
}

async fn write_raw_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &str,
) -> Result<(), std::io::Error> {
    writer.write_all(msg.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_raw_lines<W: AsyncWrite + Unpin>(
    writer: &mut W,
    lines: &[String],
) -> Result<(), std::io::Error> {
    if lines.is_empty() {
        return Ok(());
    }
    let mut n = 0usize;
    for l in lines {
        n = n.saturating_add(l.len()).saturating_add(1);
    }
    let mut buf = Vec::with_capacity(n);
    for l in lines {
        buf.extend_from_slice(l.as_bytes());
        buf.push(b'\n');
    }
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_rpc_result<W: AsyncWrite + Unpin>(
    writer: &mut W,
    id: &Value,
    result_json: &str,
) -> Result<(), std::io::Error> {
    let mut s = String::with_capacity(result_json.len() + 48);
    s.push_str("{\"jsonrpc\":\"2.0\",\"id\":");
    s.push_str(&serde_json::to_string(id).unwrap_or_else(|_| "null".into()));
    s.push_str(",\"result\":");
    s.push_str(result_json);
    s.push('}');
    write_raw_line(writer, &s).await
}

/// Instant methods that must stay on the connection task so a 1-worker runtime
/// can answer `server.ping` while another socket is in `spawn_blocking`.
fn method_stays_on_worker(method: &str) -> bool {
    matches!(
        method,
        "server.ping"
            | "server.version"
            | "server.banner"
            | "server.donation_address"
            | "server.features"
            | "server.peers.subscribe"
            | "blockchain.relayfee"
            | "blockchain.scripthash.unsubscribe"
    )
}

fn method_stamps_chain_tip(method: &str) -> bool {
    matches!(
        method,
        "blockchain.scripthash.get_history"
            | "blockchain.scripthash.get_balance"
            | "blockchain.scripthash.listunspent"
            | "blockchain.transaction.get"
            | "blockchain.transaction.get_merkle"
    )
}

fn rpc_result(id: &Value, result: &Value, view: Option<&ChainView>) -> Value {
    let mut obj = json!({"jsonrpc":"2.0","id": id, "result": result});
    if let Some(v) = view {
        obj["chain_tip"] = json!(hash_hex_rev(&v.hash));
        obj["chain_tip_height"] = json!(v.height.0);
    }
    obj
}

fn electrum_pin_kind(method: &str) -> ChainViewKind {
    if method.starts_with("blockchain.scripthash.") {
        ChainViewKind::ScriptHash
    } else {
        ChainViewKind::Tip
    }
}

fn electrum_at_chain_view<F>(
    query: &Query,
    method: &str,
    params: &Value,
    asof_ok: bool,
    mut f: F,
) -> (Result<Value, String>, Option<ChainView>)
where
    F: FnMut(&Query, &Value, Option<&ChainView>, bool) -> Result<Value, String>,
{
    let kind = electrum_pin_kind(method);
    match take_trailing_asof(method, params, asof_ok) {
        Ok((stripped, Some(hash))) => match query.pin_view(kind, Some(&hash)) {
            Ok(Some(view)) => {
                let out = f(query, &stripped, Some(&view), true);
                match view.still_live(query) {
                    Ok(true) => (out, Some(view)),
                    Ok(false) => (Err("asof not on chain".into()), None),
                    Err(e) => (Err(e.to_string()), None),
                }
            }
            Ok(None) => (Err("asof not on chain".into()), None),
            Err(e) => (Err(e.to_string()), None),
        },
        Ok((stripped, None)) => match query.run_at_view(kind, |view| {
            Ok::<_, rbitcoin_query::QueryError>(f(query, &stripped, Some(view), false))
        }) {
            Ok((view, inner)) => (inner, Some(view)),
            Err(StoreError::NotFound) => (f(query, &stripped, None, false), None),
            Err(StoreError::Stale(_)) => (Err("chain view moved".into()), None),
            Err(e) => (Err(e.to_string()), None),
        },
        Err(e) => (Err(e), None),
    }
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
#[cfg(test)]
fn dispatch(
    method: &str,
    params: &Value,
    query: &Query,
    config: &ElectrumConfig,
    chain: &ChainParams,
    mempool: Option<&MempoolHub>,
    header_sub: &mut bool,
    sh_subs: &mut HashSet<[u8; 32]>,
) -> Result<Value, String> {
    let mut conn = ElectrumConn {
        protocol: String::new(),
        header_sub: *header_sub,
        sh_subs: std::mem::take(sh_subs),
        sh_join: None,
    };
    let r = dispatch_with_join(method, params, query, config, chain, mempool, &mut conn);
    *header_sub = conn.header_sub;
    *sh_subs = conn.sh_subs;
    r
}

fn dispatch_with_join(
    method: &str,
    params: &Value,
    query: &Query,
    config: &ElectrumConfig,
    chain: &ChainParams,
    mempool: Option<&MempoolHub>,
    conn: &mut ElectrumConn,
) -> Result<Value, String> {
    if method == "server.version" {
        if conn.protocol.is_empty() {
            conn.protocol = negotiate_protocol(params)?;
        }
        return Ok(json!([SERVER_VERSION, conn.protocol.as_str()]));
    }
    dispatch_pinned(
        method, params, query, config, chain, mempool, conn, None, false,
    )
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn sh_at_view<T>(
    query: &Query,
    pinned: Option<&ChainView>,
    is_asof: bool,
    asof: Option<[u8; 32]>,
    sh_join: &mut Option<ShJoinSlot>,
    asof_fn: impl FnOnce(&Query, &ChainView) -> Result<T, String>,
    slot_fn: impl FnOnce(&Query, &mut Option<ShJoinSlot>, &ChainView) -> Result<T, String>,
    live_fn: impl FnOnce(&Query, &mut Option<ShJoinSlot>) -> Result<T, String>,
) -> Result<T, String> {
    if let Some(view) = pinned {
        if is_asof {
            return asof_fn(query, view);
        }
        return slot_fn(query, sh_join, view);
    }
    if let Some(hash) = asof {
        let view = query
            .pin_sh_chain_view_at(&hash)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "asof not on chain".to_string())?;
        return asof_fn(query, &view);
    }
    live_fn(query, sh_join)
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
fn dispatch_pinned(
    method: &str,
    params: &Value,
    query: &Query,
    config: &ElectrumConfig,
    chain: &ChainParams,
    mempool: Option<&MempoolHub>,
    conn: &mut ElectrumConn,
    pinned: Option<&ChainView>,
    is_asof: bool,
) -> Result<Value, String> {
    let protocol = conn.protocol.clone();
    let header_sub = &mut conn.header_sub;
    let sh_subs = &mut conn.sh_subs;
    let sh_join = &mut conn.sh_join;
    match method {
        "server.version" => Ok(json!([SERVER_VERSION, protocol])),
        "server.ping" => Ok(Value::Null),
        "server.banner" => Ok(json!(config.banner)),
        "server.donation_address" => Ok(json!(config.donation_address)),
        "server.features" => Ok(json!({
            "genesis_hash": config.genesis_hash_hex,
            "hosts": {},
            "protocol_max": PROTOCOL_MAX,
            "protocol_min": PROTOCOL_MIN,
            "server_version": SERVER_VERSION,
            "hash_function": "sha256",
            "pruning": null,
            // Cake gates SP on version[0] containing "electrs", then probes the
            // tweaks method — not features. Other clients (and future Cake) can
            // still see SP here without a dummy RPC. Cake electrs does not
            // implement server.features.
            "silent_payments": [0],
            "tweaks": true,
            "chain_tip": true,
            "asof": true,
            "asof_protocol": PROTOCOL_ASOF,
        })),
        "blockchain.headers.subscribe" => {
            *header_sub = true;
            tip_header_obj(query)
        }
        "blockchain.block.header" => {
            let height = param_u32(params, 0)?;
            let hdr = query
                .wire_header_at_height(Height(height))
                .map_err(|e| e.to_string())?;
            Ok(json!(header_hex(&hdr)))
        }
        "blockchain.block.headers" => {
            let start = param_u32(params, 0)?;
            let count = param_u32(params, 1)?.min(2016);
            let mut hexes = String::new();
            let mut n = 0u32;
            for h in start..start.saturating_add(count) {
                match query.wire_header_at_height(Height(h)) {
                    Ok(hdr) => {
                        hexes.push_str(&header_hex(&hdr));
                        n += 1;
                    }
                    Err(_) => break,
                }
            }
            Ok(json!({"count": n, "hex": hexes, "max": 2016}))
        }
        "blockchain.scripthash.get_history" => {
            let (params, asof) = if pinned.is_some() {
                (params.clone(), None)
            } else {
                take_trailing_asof(method, params, protocol == PROTOCOL_ASOF)?
            };
            let sh = param_scripthash(&params, 0)?;
            let (filter, mut include_mempool) = parse_get_history_window(&params)?;
            if is_asof || asof.is_some() {
                include_mempool = false;
            }
            let mut hist = sh_at_view(
                query,
                pinned,
                is_asof,
                asof,
                sh_join,
                |q, view| {
                    q.scripthash_history_filtered_in(&sh, &filter, view)
                        .map_err(|e| e.to_string())
                },
                |q, slot, view| {
                    q.scripthash_history_filtered_slot_in(&sh, &filter, slot, view)
                        .map_err(|e| e.to_string())
                },
                |q, slot| {
                    q.scripthash_history_filtered_slot(&sh, &filter, slot)
                        .map_err(|e| e.to_string())
                },
            )?;
            // Confirmed rows are height-asc from the filter. Mempool (if any) is
            // appended as a tail — Electrum Cash: only when to_height is -1/omitted.
            if include_mempool {
                if let Some(mp) = mempool {
                    append_mempool_history(&mut hist, mp, &sh);
                }
            }
            let arr: Vec<Value> = hist.iter().map(history_row_json).collect();
            Ok(Value::Array(arr))
        }
        "blockchain.scripthash.get_balance" => {
            let (params, asof) = if pinned.is_some() {
                (params.clone(), None)
            } else {
                take_trailing_asof(method, params, protocol == PROTOCOL_ASOF)?
            };
            let sh = param_scripthash(&params, 0)?;
            let mut b = sh_at_view(
                query,
                pinned,
                is_asof,
                asof,
                sh_join,
                |q, view| {
                    q.scripthash_balance_in(&sh, view)
                        .map_err(|e| e.to_string())
                },
                |q, slot, view| {
                    q.scripthash_balance_slot_in(&sh, slot, view)
                        .map_err(|e| e.to_string())
                },
                |q, slot| {
                    q.scripthash_balance_slot(&sh, slot)
                        .map_err(|e| e.to_string())
                },
            )?;
            if !is_asof && asof.is_none() {
                if let Some(mp) = mempool {
                    b.unconfirmed = mp.scripthash_unconfirmed_delta(&sh);
                }
            }
            Ok(json!({"confirmed": b.confirmed, "unconfirmed": b.unconfirmed}))
        }
        "blockchain.scripthash.listunspent" => {
            let (params, asof) = if pinned.is_some() {
                (params.clone(), None)
            } else {
                take_trailing_asof(method, params, protocol == PROTOCOL_ASOF)?
            };
            let sh = param_scripthash(&params, 0)?;
            let u = sh_at_view(
                query,
                pinned,
                is_asof,
                asof,
                sh_join,
                |q, view| {
                    q.scripthash_listunspent_in(&sh, view)
                        .map_err(|e| e.to_string())
                },
                |q, slot, view| {
                    crate::unspent::scripthash_utxos_with_mempool_slot_in(
                        q, mempool, &sh, slot, view,
                    )
                    .map_err(|e| e.to_string())
                },
                |q, slot| {
                    crate::unspent::scripthash_utxos_with_mempool_slot(q, mempool, &sh, slot)
                        .map_err(|e| e.to_string())
                },
            )?;
            let arr: Vec<Value> = u
                .iter()
                .map(|x| {
                    json!({
                        "tx_hash": txid_hex(&x.tx_hash),
                        "tx_pos": x.tx_pos,
                        "height": x.height,
                        "value": x.value,
                    })
                })
                .collect();
            Ok(Value::Array(arr))
        }
        "blockchain.scripthash.subscribe" => {
            let sh = param_scripthash(params, 0)?;
            if !sh_subs.contains(&sh) && sh_subs.len() >= config.max_scripthash_subs {
                return Err(format!(
                    "too many scripthash subscriptions (max {})",
                    config.max_scripthash_subs
                ));
            }
            sh_subs.insert(sh);
            let status = if let Some(mp) = mempool {
                scripthash_status_full_slot(query, mp, &sh, sh_join)?
            } else {
                let hist = query
                    .scripthash_history_slot(&sh, sh_join)
                    .map_err(|e| e.to_string())?;
                scripthash_status(Some(query), &hist)?
            };
            Ok(json!(status))
        }
        "blockchain.scripthash.unsubscribe" => {
            let sh = param_scripthash(params, 0)?;
            Ok(json!(sh_subs.remove(&sh)))
        }
        "blockchain.scripthash.get_mempool" => {
            let sh = param_scripthash(params, 0)?;
            let items = mempool
                .map(|m| m.scripthash_mempool(&sh))
                .unwrap_or_default();
            let arr: Vec<Value> = items
                .iter()
                .map(|i| {
                    json!({
                        "height": i.height,
                        "tx_hash": txid_hex(&i.txid),
                        "fee": i.fee,
                    })
                })
                .collect();
            Ok(Value::Array(arr))
        }
        "blockchain.transaction.get" => {
            let txid = param_txid(params, 0)?;
            let verbose = params
                .as_array()
                .and_then(|a| a.get(1))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if let Some((fk, _rec)) = query.get_tx_by_txid(&txid).map_err(|e| e.to_string())? {
                let confirmed_ok = if is_asof {
                    let view = pinned.ok_or_else(|| "asof not on chain".to_string())?;
                    query
                        .store()
                        .is_confirmed_strong_at(fk, Some(view.height.0))
                        .map_err(|e| e.to_string())?
                } else {
                    true
                };
                if confirmed_ok {
                    let raw = query.tx_wire_bytes(fk).map_err(|e| e.to_string())?;
                    if verbose {
                        return Ok(json!({
                            "hex": rbitcoin_primitives::hex_encode(&raw),
                            "txid": txid_hex(&txid)
                        }));
                    }
                    return Ok(json!(rbitcoin_primitives::hex_encode(&raw)));
                }
            }
            if !is_asof {
                if let Some(mp) = mempool {
                    use bitcoin::hashes::Hash;
                    let tid = bitcoin::Txid::from_byte_array(txid);
                    if let Some(tx) = mp.get_tx(&tid) {
                        let raw = bitcoin::consensus::serialize(&tx);
                        if verbose {
                            return Ok(json!({
                                "hex": rbitcoin_primitives::hex_encode(&raw),
                                "txid": txid_hex(&txid)
                            }));
                        }
                        return Ok(json!(rbitcoin_primitives::hex_encode(&raw)));
                    }
                }
            }
            Err("tx not found".into())
        }
        "blockchain.transaction.get_merkle" => {
            let txid = param_txid(params, 0)?;
            let height = param_u32(params, 1)?;
            if let Some(view) = pinned {
                if height > view.height.0 {
                    return Err("asof not on chain".into());
                }
            }
            let proof = query
                .merkle_proof(Height(height), &txid)
                .map_err(|e| e.to_string())?;
            let merkle: Vec<String> = proof.merkle.iter().map(hash_hex_rev).collect();
            Ok(json!({
                "block_height": proof.block_height,
                "merkle": merkle,
                "pos": proof.pos,
            }))
        }
        "blockchain.transaction.broadcast" => {
            let raw_hex = param_str(params, 0)?;
            if raw_hex.len() > config.max_broadcast_hex {
                return Err(format!(
                    "transaction hex too large (max {} chars)",
                    config.max_broadcast_hex
                ));
            }
            let raw = rbitcoin_primitives::hex_decode(raw_hex).map_err(|e| e.to_string())?;
            // Consensus max block weight is 4M; reject absurd raw sizes early.
            if raw.len() > 4_000_000 {
                return Err("transaction too large".into());
            }
            let tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&raw).map_err(|e| e.to_string())?;
            let mp = mempool.ok_or_else(|| "mempool not available".to_string())?;
            let r = mp
                .accept_tx(&tx)
                .map_err(|e| format!("broadcast reject: {e}"))?;
            let _ = chain.network;
            Ok(json!(format!("{}", r.txid)))
        }
        "blockchain.transaction.id_from_pos" => {
            let height = param_u32(params, 0)?;
            let tx_pos = param_u32(params, 1)? as usize;
            let txid = query.block_txid_at(Height(height), tx_pos).map_err(|e| {
                if matches!(e, StoreError::NotFound) {
                    "pos out of range".to_string()
                } else {
                    e.to_string()
                }
            })?;
            Ok(json!(txid_hex(&txid)))
        }
        "blockchain.estimatefee" => {
            let target = param_u32(params, 0).unwrap_or(2);
            let fee = mempool
                .map(|m| m.estimate_fee_btc_per_kb(target))
                .unwrap_or(-1.0);
            Ok(json!(fee))
        }
        "blockchain.relayfee" => {
            let fee = MempoolHub::relay_fee_btc_per_kb();
            Ok(json!(fee))
        }
        "mempool.get_fee_histogram" => {
            let hist = mempool.map(|m| m.fee_histogram()).unwrap_or_default();
            // Electrum: array of [feerate, cumulative_vsize] with cumulative sizes.
            let mut cum = 0u64;
            let mut arr = Vec::new();
            for (rate, vsize) in hist {
                cum = cum.saturating_add(vsize);
                arr.push(json!([rate, cum]));
            }
            Ok(Value::Array(arr))
        }
        "server.peers.subscribe" => Ok(json!([])),
        "blockchain.tweaks.subscribe" => {
            crate::tweaks::subscribe(query, params, chain, config.tweaks_min_dust)
        }
        other => Err(format!("unknown method: {other}")),
    }
}

fn tip_header_obj(query: &Query) -> Result<Value, String> {
    let tip = query
        .tip_height()
        .ok_or_else(|| "no chain tip".to_string())?;
    let hdr = query
        .wire_header_at_height(tip)
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "hex": header_hex(&hdr),
        "height": tip.0,
    }))
}

fn header_hex(hdr: &bitcoin::block::Header) -> String {
    let mut buf = Vec::new();
    hdr.consensus_encode(&mut buf).expect("header encode");
    rbitcoin_primitives::hex_encode(buf)
}

fn param_u32(params: &Value, idx: usize) -> Result<u32, String> {
    params
        .as_array()
        .and_then(|a| a.get(idx))
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u32)
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| format!("param {idx} expected number"))
}

fn param_i64(params: &Value, idx: usize) -> Result<i64, String> {
    params
        .as_array()
        .and_then(|a| a.get(idx))
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_u64().and_then(|n| i64::try_from(n).ok()))
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| format!("param {idx} expected integer"))
}

fn method_accepts_asof(method: &str) -> bool {
    matches!(
        method,
        "blockchain.scripthash.get_history"
            | "blockchain.scripthash.get_balance"
            | "blockchain.scripthash.listunspent"
            | "blockchain.transaction.get"
            | "blockchain.transaction.get_merkle"
    )
}

fn parse_blockhash32(s: &str) -> Option<[u8; 32]> {
    rbitcoin_primitives::parse_display_hash32(s).ok()
}

fn protocol_tuple(s: &str) -> Option<Vec<u32>> {
    if s.is_empty() {
        return None;
    }
    s.split('.').map(|p| p.parse().ok()).collect()
}

fn protocol_string(parts: &[u32]) -> String {
    parts
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn pick_dotted(cmin_s: &str, cmax_s: &str) -> Result<String, String> {
    let cmin =
        protocol_tuple(cmin_s).ok_or_else(|| format!("unsupported protocol version {cmin_s}"))?;
    let cmax =
        protocol_tuple(cmax_s).ok_or_else(|| format!("unsupported protocol version {cmax_s}"))?;
    let smin = protocol_tuple(PROTOCOL_MIN).expect("PROTOCOL_MIN");
    let smax = protocol_tuple(PROTOCOL_MAX).expect("PROTOCOL_MAX");
    let lo = if cmin < smin { smin } else { cmin };
    let hi = if cmax < smax { cmax } else { smax };
    if hi < lo {
        return Err("unsupported protocol version".into());
    }
    Ok(protocol_string(&hi))
}

fn negotiate_protocol(params: &Value) -> Result<String, String> {
    let pv = params
        .as_array()
        .and_then(|a| a.get(1))
        .unwrap_or(&Value::Null);
    if pv.is_null() {
        return Ok(PROTOCOL_MAX.to_string());
    }
    if let Some(s) = pv.as_str() {
        if s == PROTOCOL_ASOF {
            return Ok(PROTOCOL_ASOF.to_string());
        }
        return pick_dotted(s, s);
    }
    let Some(range) = pv.as_array() else {
        return Err("protocol_version expected string or [min, max]".into());
    };
    if range.len() != 2 {
        return Err("protocol_version range must be [min, max]".into());
    }
    let a = range[0]
        .as_str()
        .ok_or("protocol_version range expected strings")?;
    let b = range[1]
        .as_str()
        .ok_or("protocol_version range expected strings")?;
    if a == PROTOCOL_ASOF || b == PROTOCOL_ASOF {
        return Ok(PROTOCOL_ASOF.to_string());
    }
    pick_dotted(a, b)
}

fn take_trailing_asof(
    method: &str,
    params: &Value,
    asof_ok: bool,
) -> Result<(Value, Option<[u8; 32]>), String> {
    if !method_accepts_asof(method) {
        return Ok((params.clone(), None));
    }
    let Some(arr) = params.as_array() else {
        return Ok((params.clone(), None));
    };
    let Some(last) = arr.last().and_then(|v| v.as_str()) else {
        return Ok((params.clone(), None));
    };
    let Some(hex) = last.strip_prefix("asof:") else {
        return Ok((params.clone(), None));
    };
    if !asof_ok {
        return Err("asof requires protocol 1.4.2-asof".into());
    }
    let Some(hash) = parse_blockhash32(hex) else {
        return Err("asof must be asof:<32-byte hex>".into());
    };
    let mut rest = arr.clone();
    rest.pop();
    Ok((Value::Array(rest), Some(hash)))
}

/// Electrum Cash optional height window after scripthash for `get_history`.
///
/// Returns `(confirmed HistoryFilter, include_mempool)`.
/// - 1-arg / omitted heights: open confirmed window + mempool (BTC 1.4 / BCH defaults).
/// - `to_height == -1` (or only `from_height`): open upper bound + mempool.
/// - Finite exclusive `to_height`: confirmed `[from, to)` only — **no** mempool.
fn parse_get_history_window(params: &Value) -> Result<(HistoryFilter, bool), String> {
    let arr = params
        .as_array()
        .ok_or_else(|| "params expected array".to_string())?;
    let from = if arr.len() >= 2 {
        param_u32(params, 1)?
    } else {
        0
    };
    let (to_excl, include_mempool) = if arr.len() >= 3 {
        let to = param_i64(params, 2)?;
        if to == -1 {
            (None, true)
        } else if to < 0 {
            return Err("to_height must be -1 or non-negative".into());
        } else {
            // BCH: from_height <= to_height (treat -1 as infinity; already handled).
            if i64::from(from) > to {
                return Err("from_height must be <= to_height".into());
            }
            (Some(to), false)
        }
    } else {
        (None, true)
    };
    Ok((HistoryFilter::height_window(from, to_excl), include_mempool))
}

fn param_str(params: &Value, idx: usize) -> Result<&str, String> {
    params
        .as_array()
        .and_then(|a| a.get(idx))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("param {idx} expected string"))
}

fn param_scripthash(params: &Value, idx: usize) -> Result<[u8; 32], String> {
    let s = param_str(params, idx)?;
    rbitcoin_primitives::parse_display_hash32(s).map_err(|e| match e {
        rbitcoin_primitives::DisplayHashError::WrongLength { .. } => {
            "scripthash must be 32 bytes hex".into()
        }
        rbitcoin_primitives::DisplayHashError::Hex(h) => h.to_string(),
    })
}

fn param_txid(params: &Value, idx: usize) -> Result<[u8; 32], String> {
    let s = param_str(params, idx)?;
    rbitcoin_primitives::parse_display_hash32(s).map_err(|e| match e {
        rbitcoin_primitives::DisplayHashError::WrongLength { .. } => {
            "txid must be 32 bytes hex".into()
        }
        rbitcoin_primitives::DisplayHashError::Hex(h) => h.to_string(),
    })
}

fn txid_hex(txid: &[u8; 32]) -> String {
    hash_hex_rev(txid)
}

fn hash_hex_rev(h: &[u8; 32]) -> String {
    rbitcoin_primitives::display_hash_hex(h)
}

fn history_row_json(i: &rbitcoin_query::ScriptHashHistoryItem) -> Value {
    let mut row = json!({
        "height": i.height,
        "tx_hash": txid_hex(&i.txid),
    });
    if let Some(fee) = i.fee {
        row["fee"] = json!(fee);
    }
    row
}

fn append_mempool_history(
    hist: &mut Vec<rbitcoin_query::ScriptHashHistoryItem>,
    mp: &MempoolHub,
    sh: &[u8; 32],
) {
    for item in mp.scripthash_mempool(sh) {
        if hist.iter().any(|h| h.txid == item.txid) {
            continue;
        }
        hist.push(rbitcoin_query::ScriptHashHistoryItem {
            height: item.height,
            txid: item.txid,
            tx_fk: Fk::NULL,
            fee: Some(item.fee),
        });
    }
}

fn scripthash_status(
    query: Option<&Query>,
    hist: &[rbitcoin_query::ScriptHashHistoryItem],
) -> Result<String, String> {
    if hist.is_empty() {
        return Ok(String::new());
    }
    use bitcoin::hashes::{sha256, Hash as _};
    let mut s = String::new();
    for i in hist {
        if i.height > 0 {
            let q = query.ok_or_else(|| "status preimage needs a chain query".to_string())?;
            let (_, rec) = q
                .header_at_height(Height(i.height as u32))
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "header missing for confirmed history row".to_string())?;
            s.push_str(&format!(
                "{}:{}:{}:",
                txid_hex(&i.txid),
                i.height,
                hash_hex_rev(&rec.hash)
            ));
        } else {
            s.push_str(&format!("{}:{}:", txid_hex(&i.txid), i.height));
        }
    }
    let hash = sha256::Hash::hash(s.as_bytes());
    Ok(rbitcoin_primitives::hex_encode(hash.to_byte_array()))
}

fn scripthash_status_full(query: &Query, mp: &MempoolHub, sh: &[u8; 32]) -> Result<String, String> {
    let mut slot = None;
    scripthash_status_full_slot(query, mp, sh, &mut slot)
}

fn scripthash_status_full_slot(
    query: &Query,
    mp: &MempoolHub,
    sh: &[u8; 32],
    slot: &mut Option<ShJoinSlot>,
) -> Result<String, String> {
    let mut hist = query
        .scripthash_history_slot(sh, slot)
        .map_err(|e| e.to_string())?;
    append_mempool_history(&mut hist, mp, sh);
    scripthash_status(Some(query), &hist)
}

/// Helper to compute electrum scripthash hex (reversed) from script bytes.
pub fn electrum_scripthash_hex(script: &[u8]) -> String {
    let h = script_hash(script);
    hash_hex_rev(&h)
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
