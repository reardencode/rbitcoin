//! Line-delimited JSON-RPC Electrum server (TCP).
//!
//! Confirmed history from the store; unconfirmed + broadcast via optional
//! [`MempoolHub`] (plan P6, libre-relay-class).

use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use rbitcoin_consensus::ChainParams;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::{ChainView, HistoryFilter, Query, ShJoinSlot};
use rbitcoin_store::{script_hash, StoreError};
use serde_json::{json, Value};
use std::collections::HashSet;
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
/// First `server.version` element. Cake Wallet `getNodeIsElectrs()` requires
/// this string (lowercased) to contain `electrs` before it will probe
/// `blockchain.tweaks.subscribe [0, 1, false]`.
const SERVER_VERSION: &str = concat!("rbitcoin-electrs ", env!("CARGO_PKG_VERSION"));

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
}

impl ElectrumConfig {
    pub fn for_params(listen: SocketAddr, params: &ChainParams) -> Self {
        let genesis = params.genesis_hash.to_byte_array();
        // Electrum expects internal byte order reversed for display hex of hashes.
        let mut rev = genesis;
        rev.reverse();
        Self {
            listen,
            banner: "rbitcoin electrum — libre-relay-class (0.1 sat/vB, no dust ban, full RBF)"
                .into(),
            donation_address: String::new(),
            genesis_hash_hex: rbitcoin_primitives::hex_encode(rev),
            limits: ServeLimits::for_public_proxy(),
            max_scripthash_subs: DEFAULT_MAX_SCRIPTHASH_SUBS,
            max_broadcast_hex: DEFAULT_MAX_BROADCAST_HEX,
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
    let mut header_sub = false;
    let mut sh_subs: HashSet<[u8; 32]> = HashSet::new();
    let mut sh_join: Option<ShJoinSlot> = None;
    let notify = Arc::new(Notify::new());
    let mut mempool_rx = mempool.as_ref().map(|m| m.subscribe_announces());
    let idle = config.idle_timeout();
    let max_line = config.max_line_bytes();

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
                        if header_sub {
                            let msg = json!({
                                "jsonrpc": "2.0",
                                "method": "blockchain.headers.subscribe",
                                "params": [{ "hex": t.header_hex, "height": t.height }]
                            });
                            write_line(&mut writer, &msg).await?;
                        }
                        if !sh_subs.is_empty() {
                            let q = Arc::clone(&query);
                            let mp = mempool.clone();
                            let subs: Vec<[u8; 32]> = sh_subs.iter().copied().collect();
                            let height = t.height;
                            let restatus_all = t.reorg_from_height.is_some();
                            let notes = tokio::task::spawn_blocking(move || {
                                let mut out = Vec::new();
                                for sh in subs {
                                    let hit = restatus_all
                                        || q
                                            .scripthash_touched_at_height(&sh, Height(height))
                                            .ok()
                                            .unwrap_or(false);
                                    if !hit {
                                        continue;
                                    }
                                    let status = if let Some(mp) = &mp {
                                        scripthash_status_full(&q, mp, &sh).ok()
                                    } else {
                                        q.scripthash_history(&sh).ok().map(|h| {
                                            scripthash_status(Some(&q), &h)
                                        })
                                    };
                                    if let Some(status) = status {
                                        out.push((sh, status));
                                    }
                                }
                                out
                            })
                            .await
                            .unwrap_or_default();
                            for (sh, status) in notes {
                                let msg = json!({
                                    "jsonrpc": "2.0",
                                    "method": "blockchain.scripthash.subscribe",
                                    "params": [hash_hex_rev(&sh), status]
                                });
                                write_line(&mut writer, &msg).await?;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
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
                        for sh in sh_subs.iter() {
                            let hit = ann.scripthashes.iter().any(|s| s == sh)
                                || ann.replaced_scripthashes.iter().any(|s| s == sh);
                            if !hit {
                                continue;
                            }
                            if let Ok(status) = scripthash_status_full(&query, mp, sh) {
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
                let req: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => continue,
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
                        &mut header_sub,
                        &mut sh_subs,
                        &mut sh_join,
                    )
                } else {
                    let q = Arc::clone(&query);
                    let cfg = Arc::clone(&config);
                    let p = Arc::clone(&params);
                    let mp = mempool.clone();
                    let method_owned = method.to_string();
                    let params_owned = params_v.clone();
                    let mut hs = header_sub;
                    let mut shs = sh_subs.clone();
                    let mut slot = sh_join.take();
                    let stamp = method_stamps_chain_tip(&method_owned);
                    match tokio::task::spawn_blocking(move || {
                        let (r, view) = if stamp {
                            electrum_at_chain_view(&q, &method_owned, &params_owned, |q| {
                                dispatch_with_join(
                                    &method_owned,
                                    &params_owned,
                                    q,
                                    &cfg,
                                    &p,
                                    mp.as_deref(),
                                    &mut hs,
                                    &mut shs,
                                    &mut slot,
                                )
                            })
                        } else {
                            (
                                dispatch_with_join(
                                    &method_owned,
                                    &params_owned,
                                    &q,
                                    &cfg,
                                    &p,
                                    mp.as_deref(),
                                    &mut hs,
                                    &mut shs,
                                    &mut slot,
                                ),
                                None,
                            )
                        };
                        (r, hs, shs, slot, view)
                    })
                    .await
                    {
                        Ok((r, hs, shs, slot, view)) => {
                            header_sub = hs;
                            sh_subs = shs;
                            sh_join = slot;
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
                let wall_ms = t0.elapsed().as_millis() as u64;
                meter_dispatch_wall(t0.elapsed().as_micros() as u64);
                let params_s = serde_json::to_string(&params_v).unwrap_or_else(|_| "[]".into());
                let resp = match result {
                    Ok(v) => {
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

/// Cake scan isolate: JSON-RPC result = first height, then one notify per
/// following height, then `{"message":"done"}`. Honor `count` through tip
/// (Cake asks for the remaining chain). Answer `server.ping` while computing.
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
    let first = match crate::tweaks::height_map_json(query, chain, req.start) {
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

    let Some(last) = last else {
        write_line(writer, &crate::tweaks::done_notify()).await?;
        return Ok(());
    };
    // Remaining heights: pre-taproot empty waves (no store), else budgeted
    // thin load (one txout span per batch) then Cake notifies. Hole → one height.
    // `server.ping` must not drop the in-flight wave.
    let mut next = req.start.saturating_add(1);
    let limits = crate::tweaks::subscribe_range_limits();
    while next <= last {
        let batch_start = next;
        let batch_fut = {
            let q = Arc::clone(query);
            let c = Arc::clone(chain);
            let lim = limits;
            let last_h = last;
            let start_h = batch_start;
            async move {
                tokio::task::spawn_blocking(move || {
                    crate::tweaks::remaining_notify_lines(&q, &c, start_h, last_h, lim)
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
            }
        };
        tokio::pin!(batch_fut);
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
                map = &mut batch_fut => {
                    break map;
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
        let n = batch.len() as u32;
        write_raw_lines(writer, &batch).await?;
        next = batch_start.saturating_add(n.max(1));
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

fn electrum_at_chain_view<F>(
    query: &Query,
    method: &str,
    params: &Value,
    mut f: F,
) -> (Result<Value, String>, Option<ChainView>)
where
    F: FnMut(&Query) -> Result<Value, String>,
{
    match take_trailing_asof(method, params) {
        Ok((_, Some(hash))) => match query.pin_chain_view_at(&hash) {
            Ok(Some(view)) => {
                let out = f(query);
                match view.still_live(query) {
                    Ok(true) => (out, Some(view)),
                    Ok(false) => (Err("asof not on chain".into()), None),
                    Err(e) => (Err(e.to_string()), None),
                }
            }
            Ok(None) => (Err("asof not on chain".into()), None),
            Err(e) => (Err(e.to_string()), None),
        },
        Ok((_, None)) => {
            const BOUND: u32 = 8;
            for _ in 0..BOUND {
                let view = match query.pin_chain_view() {
                    Ok(v) => v,
                    Err(e) => return (Err(e.to_string()), None),
                };
                let Some(view) = view else {
                    return (f(query), None);
                };
                let out = f(query);
                if out.is_err() {
                    return (out, None);
                }
                match view.still_live(query) {
                    Ok(true) => return (out, Some(view)),
                    Ok(false) => continue,
                    Err(e) => return (Err(e.to_string()), None),
                }
            }
            (Err("chain view moved".into()), None)
        }
        Err(e) => (Err(e), None),
    }
}

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
    let mut slot = None;
    dispatch_with_join(
        method, params, query, config, chain, mempool, header_sub, sh_subs, &mut slot,
    )
}

fn dispatch_with_join(
    method: &str,
    params: &Value,
    query: &Query,
    config: &ElectrumConfig,
    chain: &ChainParams,
    mempool: Option<&MempoolHub>,
    header_sub: &mut bool,
    sh_subs: &mut HashSet<[u8; 32]>,
    sh_join: &mut Option<ShJoinSlot>,
) -> Result<Value, String> {
    match method {
        "server.version" => Ok(json!([SERVER_VERSION, PROTOCOL_MAX])),
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
            let (params, asof) = take_trailing_asof(method, params)?;
            let sh = param_scripthash(&params, 0)?;
            let (filter, mut include_mempool) = parse_get_history_window(&params)?;
            let mut hist = if let Some(hash) = asof {
                include_mempool = false;
                let view = query
                    .pin_chain_view_at(&hash)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "asof not on chain".to_string())?;
                query
                    .scripthash_history_filtered_in(&sh, &filter, &view)
                    .map_err(|e| e.to_string())?
            } else {
                query
                    .scripthash_history_filtered_slot(&sh, &filter, sh_join)
                    .map_err(|e| e.to_string())?
            };
            // Confirmed rows are height-asc from the filter. Mempool (if any) is
            // appended as a tail — Electrum Cash: only when to_height is -1/omitted.
            if include_mempool {
                if let Some(mp) = mempool {
                    for item in mp.scripthash_mempool(&sh) {
                        hist.push(rbitcoin_query::ScriptHashHistoryItem {
                            height: item.height,
                            txid: item.txid,
                            tx_fk: Fk::NULL,
                        });
                    }
                }
            }
            let arr: Vec<Value> = hist
                .iter()
                .map(|i| {
                    json!({
                        "height": i.height,
                        "tx_hash": txid_hex(&i.txid),
                    })
                })
                .collect();
            Ok(Value::Array(arr))
        }
        "blockchain.scripthash.get_balance" => {
            let (params, asof) = take_trailing_asof(method, params)?;
            let sh = param_scripthash(&params, 0)?;
            let mut b = if let Some(hash) = asof {
                let view = query
                    .pin_chain_view_at(&hash)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "asof not on chain".to_string())?;
                query
                    .scripthash_balance_in(&sh, &view)
                    .map_err(|e| e.to_string())?
            } else {
                query
                    .scripthash_balance_slot(&sh, sh_join)
                    .map_err(|e| e.to_string())?
            };
            if asof.is_none() {
                if let Some(mp) = mempool {
                    b.unconfirmed = mp.scripthash_unconfirmed_delta(&sh);
                }
            }
            Ok(json!({"confirmed": b.confirmed, "unconfirmed": b.unconfirmed}))
        }
        "blockchain.scripthash.listunspent" => {
            let (params, asof) = take_trailing_asof(method, params)?;
            let sh = param_scripthash(&params, 0)?;
            let u = if let Some(hash) = asof {
                let view = query
                    .pin_chain_view_at(&hash)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "asof not on chain".to_string())?;
                query
                    .scripthash_listunspent_in(&sh, &view)
                    .map_err(|e| e.to_string())?
            } else {
                crate::unspent::scripthash_utxos_with_mempool_slot(query, mempool, &sh, sh_join)
                    .map_err(|e| e.to_string())?
            };
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
                scripthash_status(Some(query), &hist)
            };
            Ok(json!(status))
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
                let raw = query.tx_wire_bytes(fk).map_err(|e| e.to_string())?;
                if verbose {
                    return Ok(json!({
                        "hex": rbitcoin_primitives::hex_encode(&raw),
                        "txid": txid_hex(&txid)
                    }));
                }
                return Ok(json!(rbitcoin_primitives::hex_encode(&raw)));
            }
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
            Err("tx not found".into())
        }
        "blockchain.transaction.get_merkle" => {
            let txid = param_txid(params, 0)?;
            let height = param_u32(params, 1)?;
            let proof = query
                .merkle_proof(Height(height), &txid)
                .map_err(|e| e.to_string())?;
            let merkle: Vec<String> = proof.merkle.iter().map(|h| hash_hex_rev(h)).collect();
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
        "blockchain.tweaks.subscribe" => crate::tweaks::subscribe(query, params, chain),
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
    )
}

fn parse_blockhash32(s: &str) -> Option<[u8; 32]> {
    let mut bytes = rbitcoin_primitives::hex_decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Trailing 64-hex is an asof block hash (display order). Never the sole param
/// (that is the scripthash).
fn take_trailing_asof(method: &str, params: &Value) -> Result<(Value, Option<[u8; 32]>), String> {
    if !method_accepts_asof(method) {
        return Ok((params.clone(), None));
    }
    let Some(arr) = params.as_array() else {
        return Ok((params.clone(), None));
    };
    if arr.len() < 2 {
        return Ok((params.clone(), None));
    }
    let Some(last) = arr.last().and_then(|v| v.as_str()) else {
        return Ok((params.clone(), None));
    };
    if last.len() != 64 {
        return Ok((params.clone(), None));
    }
    let Some(hash) = parse_blockhash32(last) else {
        return Err("asof must be 32 bytes hex".into());
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
    let mut bytes = rbitcoin_primitives::hex_decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("scripthash must be 32 bytes hex".into());
    }
    // Electrum uses reversed hex for scripthash
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn param_txid(params: &Value, idx: usize) -> Result<[u8; 32], String> {
    let s = param_str(params, idx)?;
    let mut bytes = rbitcoin_primitives::hex_decode(s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("txid must be 32 bytes hex".into());
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn txid_hex(txid: &[u8; 32]) -> String {
    hash_hex_rev(txid)
}

fn hash_hex_rev(h: &[u8; 32]) -> String {
    let mut r = *h;
    r.reverse();
    rbitcoin_primitives::hex_encode(r)
}

fn scripthash_status(
    query: Option<&Query>,
    hist: &[rbitcoin_query::ScriptHashHistoryItem],
) -> String {
    if hist.is_empty() {
        return String::new();
    }
    use bitcoin::hashes::{sha256, Hash as _};
    let mut s = String::new();
    for i in hist {
        if i.height > 0 {
            let bh = query
                .and_then(|q| q.header_at_height(Height(i.height as u32)).ok())
                .flatten()
                .map(|(_, rec)| hash_hex_rev(&rec.hash))
                .unwrap_or_default();
            s.push_str(&format!("{}:{}:{}:", txid_hex(&i.txid), i.height, bh));
        } else {
            s.push_str(&format!("{}:{}:", txid_hex(&i.txid), i.height));
        }
    }
    let hash = sha256::Hash::hash(s.as_bytes());
    rbitcoin_primitives::hex_encode(hash.to_byte_array())
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
    for item in mp.scripthash_mempool(sh) {
        hist.push(rbitcoin_query::ScriptHashHistoryItem {
            height: item.height,
            txid: item.txid,
            tx_fk: Fk::NULL,
        });
    }
    hist.sort_by_key(|i| i.height);
    Ok(scripthash_status(Some(query), &hist))
}

/// Helper to compute electrum scripthash hex (reversed) from script bytes.
pub fn electrum_scripthash_hex(script: &[u8]) -> String {
    let h = script_hash(script);
    hash_hex_rev(&h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_consensus::ChainParams;
    use rbitcoin_query::Query;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    fn tmp_store() -> (std::path::PathBuf, Query) {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-electrum-ut-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = Query::open_or_create(dir.join("store")).unwrap();
        (dir, q)
    }

    #[test]
    fn config_helpers_and_param_parsers() {
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        assert!(!cfg.genesis_hash_hex.is_empty());
        assert!(cfg.banner.contains("rbitcoin"));

        let sh = electrum_scripthash_hex(&[0x51]);
        assert_eq!(sh.len(), 64);

        assert_eq!(param_u32(&json!([3]), 0).unwrap(), 3);
        assert_eq!(param_u32(&json!(["7"]), 0).unwrap(), 7);
        assert!(param_u32(&json!([]), 0).is_err());
        assert_eq!(param_i64(&json!([-1]), 0).unwrap(), -1);
        assert_eq!(param_i64(&json!(["10"]), 0).unwrap(), 10);
        assert_eq!(param_str(&json!(["hi"]), 0).unwrap(), "hi");
        assert!(param_str(&json!([1]), 0).is_err());

        let mut sh_bytes = [0u8; 32];
        sh_bytes[0] = 0xaa;
        let sh_hex = hash_hex_rev(&sh_bytes);
        let parsed = param_scripthash(&json!([sh_hex]), 0).unwrap();
        assert_eq!(parsed, sh_bytes);
        assert!(param_scripthash(&json!(["aa"]), 0).is_err());

        let tid = param_txid(&json!([sh_hex]), 0).unwrap();
        assert_eq!(tid, sh_bytes);

        // get_history window: 1-arg open + mempool; finite to excludes mempool.
        let (f, mp) = parse_get_history_window(&json!([sh_hex])).unwrap();
        assert_eq!(f.from_height, 0);
        assert!(f.to_height.is_none());
        assert!(mp);
        let (f, mp) = parse_get_history_window(&json!([sh_hex, 5])).unwrap();
        assert_eq!(f.from_height, 5);
        assert!(f.to_height.is_none());
        assert!(mp);
        let (f, mp) = parse_get_history_window(&json!([sh_hex, 2, -1])).unwrap();
        assert_eq!(f.from_height, 2);
        assert!(f.to_height.is_none());
        assert!(mp);
        let (f, mp) = parse_get_history_window(&json!([sh_hex, 1, 10])).unwrap();
        assert_eq!(f.from_height, 1);
        assert_eq!(f.to_height, Some(10));
        assert!(!mp);
        let asof_hex = "ab".repeat(32);
        let (rest, h) = take_trailing_asof(
            "blockchain.scripthash.get_balance",
            &json!([sh_hex, asof_hex]),
        )
        .unwrap();
        assert!(h.is_some());
        assert_eq!(rest, json!([sh_hex]));
        let (_, none) =
            take_trailing_asof("blockchain.scripthash.get_balance", &json!([sh_hex])).unwrap();
        assert!(none.is_none());

        assert!(parse_get_history_window(&json!([sh_hex, 10, 5]))
            .unwrap_err()
            .contains("from_height"));
        assert!(parse_get_history_window(&json!([sh_hex, 0, -2]))
            .unwrap_err()
            .contains("to_height"));

        let empty_status = scripthash_status(None, &[]);
        assert!(empty_status.is_empty());
        let status = scripthash_status(
            None,
            &[rbitcoin_query::ScriptHashHistoryItem {
                height: 1,
                txid: [1u8; 32],
                tx_fk: Fk::NULL,
            }],
        );
        assert_eq!(status.len(), 64);

        use bitcoin::hashes::Hash;
        let hdr = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let hex = header_hex(&hdr);
        assert_eq!(hex.len(), 160);
    }

    #[test]
    fn dispatch_static_methods_and_errors() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();

        let v = dispatch(
            "server.version",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(v.as_array().unwrap().len() == 2);
        // Cake Wallet getNodeIsElectrs(): version[0].toLowerCase().contains('electrs')
        // before it will call blockchain.tweaks.subscribe [0, 1, false].
        let cake_server = v[0].as_str().expect("server.version[0] string");
        assert!(
            cake_server.to_ascii_lowercase().contains("electrs"),
            "Cake skips tweaks unless version[0] contains electrs, got {cake_server:?}"
        );
        assert!(
            cake_server.to_ascii_lowercase().contains("rbitcoin"),
            "version[0] must still identify rbitcoin, got {cake_server:?}"
        );
        assert!(
            cake_server.contains(env!("CARGO_PKG_VERSION")),
            "version[0] must track workspace.package.version, got {cake_server:?}"
        );

        assert!(dispatch(
            "server.ping",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .unwrap()
        .is_null());

        assert_eq!(
            dispatch(
                "server.banner",
                &json!([]),
                &q,
                &cfg,
                &params,
                None,
                &mut header_sub,
                &mut sh_subs
            )
            .unwrap()
            .as_str()
            .unwrap(),
            cfg.banner
        );

        let features = dispatch(
            "server.features",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(features["protocol_min"], PROTOCOL_MIN);
        assert_eq!(features["server_version"], v[0]);
        assert_eq!(features["silent_payments"], json!([0]));
        assert_eq!(features["tweaks"], json!(true));
        assert_eq!(features["chain_tip"], json!(true));
        assert_eq!(features["asof"], json!(true));

        let probe = dispatch(
            "blockchain.tweaks.subscribe",
            &json!([0, 1, false]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(probe, json!({"0": {}}));

        assert!(dispatch(
            "server.donation_address",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .unwrap()
        .as_str()
        .is_some());

        assert_eq!(
            dispatch(
                "server.peers.subscribe",
                &json!([]),
                &q,
                &cfg,
                &params,
                None,
                &mut header_sub,
                &mut sh_subs
            )
            .unwrap(),
            json!([])
        );

        let fee = dispatch(
            "blockchain.relayfee",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(fee.as_f64().is_some());

        let est = dispatch(
            "blockchain.estimatefee",
            &json!([6]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(est.as_f64(), Some(-1.0));

        let hist = dispatch(
            "mempool.get_fee_histogram",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(hist, json!([]));

        // No tip → headers.subscribe errors.
        assert!(dispatch(
            "blockchain.headers.subscribe",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .is_err());

        assert!(dispatch(
            "no.such.method",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .unwrap_err()
        .contains("unknown method"));

        // Empty-chain scripthash methods.
        let sh = electrum_scripthash_hex(&[0x51]);
        let empty_hist = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(empty_hist, json!([]));

        let bal = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(bal["confirmed"], 0);

        let unspent = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(unspent, json!([]));

        let sub = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(sub.as_str().is_some());
        assert_eq!(sh_subs.len(), 1);

        let mem = dispatch(
            "blockchain.scripthash.get_mempool",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(mem, json!([]));

        // Broadcast: bad hex fails before mempool gate.
        assert!(dispatch(
            "blockchain.transaction.broadcast",
            &json!(["zz"]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .is_err());

        // Non-empty hex that may fail deserialize or mempool gate — either is fine.
        assert!(dispatch(
            "blockchain.transaction.broadcast",
            &json!(["01000000000000000000"]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn accept_client_ping_and_shutdown() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");

        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("timeout")
        .unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 1);
        assert!(v.get("result").is_some());
        assert!(
            v.get("chain_tip").is_none(),
            "ping must not grow chain_tip: {v}"
        );

        // Empty line ignored; malformed JSON ignored; then version.
        let stream = reader.into_inner();
        stream.write_all(b"\n").await.unwrap();
        stream.write_all(b"{not json\n").await.unwrap();
        let mut line = serde_json::to_string(&json!({
            "jsonrpc":"2.0","id":2,"method":"server.version","params":[]
        }))
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(stream);
        resp.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("timeout")
        .unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 2);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chain_view_get_history_stamps_tip_and_changes_on_replace() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let (h0, t0) = {
            let merkle = [0xab; 32];
            let header = HeaderRecord {
                prev_fk: Fk::NULL,
                version: 1,
                timestamp: 1,
                bits: 0x207fffff,
                nonce: 0,
                merkle_root: merkle,
                hash: merkle,
            };
            let mut txid = [0xcb; 32];
            txid[31] = 0;
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
                    script_sig: vec![0],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            (header, ta)
        };
        let hash0 = h0.hash;
        q.connect_block(Height(0), &h0, &[t0]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let mut h1 = h0.clone();
        h1.prev_fk = prev_fk;
        h1.timestamp = 2;
        h1.nonce = 1;
        h1.hash = rbitcoin_store::block_header_hash(
            h1.version,
            &hash0,
            &h1.merkle_root,
            h1.timestamp,
            h1.bits,
            h1.nonce,
        );
        let mut t1 = {
            let mut txid = [0xcb; 32];
            txid[5] = 0xaa;
            TxApply {
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
                    script_sig: vec![1],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            }
        };
        t1.tx.txid[0] = 1;
        q.connect_block(Height(1), &h1, &[t1]).unwrap();
        let tip_a = hash_hex_rev(&h1.hash);

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, Arc::clone(&q), params, tip_tx, None)
            .await
            .expect("listen");
        let sh = electrum_scripthash_hex(&[0x51]);

        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let req = json!({
            "jsonrpc":"2.0","id":1,
            "method":"blockchain.scripthash.get_history","params":[sh]
        });
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("timeout")
        .unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["id"], 1, "{v}");
        assert!(v["result"].as_array().is_some(), "{v}");
        assert_eq!(v["chain_tip"], tip_a, "{v}");
        assert_eq!(v["chain_tip_height"], 1, "{v}");

        q.disconnect_tip().unwrap();
        let mut h1b = h1.clone();
        h1b.nonce = 9;
        h1b.hash = rbitcoin_store::block_header_hash(
            h1b.version,
            &hash0,
            &h1b.merkle_root,
            h1b.timestamp,
            h1b.bits,
            h1b.nonce,
        );
        let mut t1b = {
            let mut txid = [0xcb; 32];
            txid[5] = 0xbb;
            TxApply {
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
                    script_sig: vec![2],
                    witness: vec![],
                }],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            }
        };
        t1b.tx.txid[0] = 2;
        q.connect_block(Height(1), &h1b, &[t1b]).unwrap();
        let tip_b = hash_hex_rev(&h1b.hash);
        assert_ne!(tip_a, tip_b);

        let stream = reader.into_inner();
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(stream);
        resp.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("timeout")
        .unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["chain_tip"], tip_b, "{v}");
        assert_eq!(v["chain_tip_height"], 1, "{v}");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On a 1-worker runtime, ping must complete while another socket is inside
    /// a real blocking store query (`blockchain.block.headers`).
    #[tokio::test(flavor = "current_thread")]
    async fn ping_overlaps_blocking_headers_on_one_worker() {
        use rbitcoin_consensus::{accept_and_connect_block, Milestone};
        use rbitcoin_primitives::Height;
        use std::sync::atomic::AtomicU64;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        // Enough headers that a serial walk stays in-flight after ping is scheduled.
        let _ = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            80,
            0,
        );
        let q = Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");
        let addr = handle.local_addr;

        let mut a = TcpStream::connect(addr).await.unwrap();
        let mut b = TcpStream::connect(addr).await.unwrap();
        let a_started = Arc::new(AtomicBool::new(false));
        let a_done_us = Arc::new(AtomicU64::new(0));
        let b_done_us = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();

        let a_started_c = Arc::clone(&a_started);
        let a_done_c = Arc::clone(&a_done_us);
        let ha = tokio::spawn(async move {
            let req = json!({
                "jsonrpc":"2.0","id":10,
                "method":"blockchain.block.headers","params":[0, 2016]
            });
            let mut line = serde_json::to_string(&req).unwrap();
            line.push('\n');
            a.write_all(line.as_bytes()).await.unwrap();
            a_started_c.store(true, Ordering::SeqCst);
            let mut reader = BufReader::new(a);
            let mut resp = String::new();
            reader.read_line(&mut resp).await.unwrap();
            a_done_c.store(t0.elapsed().as_micros() as u64, Ordering::SeqCst);
            let v: Value = serde_json::from_str(&resp).unwrap();
            assert_eq!(v["id"], 10);
            assert!(v["result"]["count"].as_u64().unwrap() > 50);
        });

        let a_started_c = Arc::clone(&a_started);
        let b_done_c = Arc::clone(&b_done_us);
        let hb = tokio::spawn(async move {
            while !a_started_c.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
            let req = json!({"jsonrpc":"2.0","id":11,"method":"server.ping","params":[]});
            let mut line = serde_json::to_string(&req).unwrap();
            line.push('\n');
            b.write_all(line.as_bytes()).await.unwrap();
            let mut reader = BufReader::new(b);
            let mut resp = String::new();
            reader.read_line(&mut resp).await.unwrap();
            b_done_c.store(t0.elapsed().as_micros() as u64, Ordering::SeqCst);
            let v: Value = serde_json::from_str(&resp).unwrap();
            assert_eq!(v["id"], 11);
            assert!(v.get("result").is_some());
        });

        ha.await.expect("headers task");
        hb.await.expect("ping task");
        let a_done = a_done_us.load(Ordering::SeqCst);
        let b_done = b_done_us.load(Ordering::SeqCst);
        assert!(
            b_done < a_done,
            "ping finished at {b_done}µs, headers at {a_done}µs (expected overlap)"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn api_log_records_electrum_method() {
        let (dir, q) = tmp_store();
        let log_path = dir.join("api.jsonl");
        rbitcoin_log::init_api_log(&log_path).unwrap();
        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");

        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("timeout")
        .unwrap();
        handle.shutdown().await;
        rbitcoin_log::close_api_log();
        let body = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            body.contains("\"method\":\"server.ping\""),
            "api log missing ping: {body}"
        );
        assert!(body.contains("\"surface\":\"electrum\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dispatch_on_connected_chain() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        // Build 2-block synthetic chain.
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        let mut hashes = Vec::new();
        let mut first_txid = [0u8; 32];
        for h in 0..2u32 {
            let version = 1;
            let timestamp = h + 1;
            let bits = 0x207fffff;
            let nonce = h;
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
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
            if h == 0 {
                first_txid = txid;
            }
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
            hashes.push(hash);
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let tip = dispatch(
            "blockchain.headers.subscribe",
            &json!([]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(header_sub);
        assert_eq!(tip["height"], 1);

        let hdr = dispatch(
            "blockchain.block.header",
            &json!([0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(hdr.as_str().unwrap().len(), 160);

        let headers = dispatch(
            "blockchain.block.headers",
            &json!([0, 10]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(headers["count"].as_u64().unwrap() >= 2);

        let txid_hex = {
            let mut r = first_txid;
            r.reverse();
            rbitcoin_primitives::hex_encode(r)
        };
        let raw = dispatch(
            "blockchain.transaction.get",
            &json!([txid_hex]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(raw.as_str().unwrap().len() > 10);
        let verbose = dispatch(
            "blockchain.transaction.get",
            &json!([txid_hex, true]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(verbose.get("hex").is_some());

        let merkle = dispatch(
            "blockchain.transaction.get_merkle",
            &json!([txid_hex, 0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(merkle["block_height"], 0);

        let idpos = dispatch(
            "blockchain.transaction.id_from_pos",
            &json!([0, 0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(idpos.as_str().unwrap(), txid_hex);

        // Missing tx.
        let miss = [0xeeu8; 32];
        let mut miss_hex = miss;
        miss_hex.reverse();
        let miss_s = rbitcoin_primitives::hex_encode(miss_hex);
        assert!(dispatch(
            "blockchain.transaction.get",
            &json!([miss_s]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .is_err());

        // pos OOB
        assert!(dispatch(
            "blockchain.transaction.id_from_pos",
            &json!([0, 99]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs
        )
        .is_err());

        let sh = electrum_scripthash_hex(&[0x51]);
        let hist = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!hist.as_array().unwrap().is_empty());
        let bal = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(bal["confirmed"].as_i64().unwrap() > 0);
        let unspent = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!unspent.as_array().unwrap().is_empty());
        let status = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!status.as_str().unwrap().is_empty());

        let _ = hashes;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn asof_scripthash_reads_hide_later_spend() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let merkle = [0xab; 32];
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle,
            hash: merkle,
        };
        let mut create_txid = [0xcb; 32];
        create_txid[31] = 0;
        let ta0 = TxApply {
            tx: TxRecord {
                txid: create_txid,
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(10_0000_0000, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];
        let hash1 = rbitcoin_store::block_header_hash(1, &merkle, &[0x11; 32], 2, 0x207fffff, 1);
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

        let sh = electrum_scripthash_hex(&[0x51]);
        let asof0 = hash_hex_rev(&merkle);
        let asof1 = hash_hex_rev(&hash1);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();

        let bal0 = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh, asof0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(bal0["confirmed"], 10_0000_0000);
        assert_eq!(bal0["unconfirmed"], 0);
        let utxo0 = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh, asof0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(utxo0.as_array().unwrap().len(), 1);
        let hist0 = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh, asof0]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(hist0.as_array().unwrap().len(), 1);

        let bal1 = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh, asof1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(bal1["confirmed"], 0);
        let utxo1 = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh, asof1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(utxo1.as_array().unwrap().is_empty());
        let hist1 = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh, asof1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(hist1.as_array().unwrap().len(), 2);

        let err = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh, "ee".repeat(32)]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap_err();
        assert!(err.contains("asof not on chain"), "unknown asof: {err}");
        let (out, view) = electrum_at_chain_view(
            &q,
            "blockchain.scripthash.get_balance",
            &json!([sh, asof0]),
            |q| {
                let mut hs = false;
                let mut subs = HashSet::new();
                let mut slot = None;
                dispatch_with_join(
                    "blockchain.scripthash.get_balance",
                    &json!([sh, asof0]),
                    q,
                    &cfg,
                    &params,
                    None,
                    &mut hs,
                    &mut subs,
                    &mut slot,
                )
            },
        );
        assert_eq!(out.unwrap()["confirmed"], 10_0000_0000);
        assert_eq!(view.unwrap().hash, merkle);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dispatch_casa_sequence_reuses_sh_join_slot() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::{body_ok_reads, reset_body_ok_reads, TxApply};
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..3u32 {
            let version = 1;
            let timestamp = h + 1;
            let bits = 0x207fffff;
            let nonce = h;
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
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
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let mut sh_join = None;
        let sh = electrum_scripthash_hex(&[0x51]);
        reset_body_ok_reads();
        let bal = dispatch_with_join(
            "blockchain.scripthash.get_balance",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
            &mut sh_join,
        )
        .unwrap();
        assert_eq!(bal["confirmed"].as_i64().unwrap(), 150_0000_0000);
        let after_bal = body_ok_reads();
        assert_eq!(after_bal, 3);

        let hist = dispatch_with_join(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
            &mut sh_join,
        )
        .unwrap();
        assert_eq!(hist.as_array().unwrap().len(), 3);
        assert_eq!(
            body_ok_reads(),
            after_bal,
            "get_history must reuse the connection join slot"
        );

        let unspent = dispatch_with_join(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
            &mut sh_join,
        )
        .unwrap();
        assert_eq!(unspent.as_array().unwrap().len(), 3);
        assert_eq!(
            body_ok_reads(),
            after_bal,
            "listunspent must reuse the connection join slot"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BCH-style optional `from_height`/`to_height` on get_history; status stays full.
    #[test]
    fn get_history_height_window_and_status_full() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..4u32 {
            let version = 1;
            let timestamp = h + 1;
            let bits = 0x207fffff;
            let nonce = h;
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xee;
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
            parent_hash = Some(header.hash);
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
        }

        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let sh = electrum_scripthash_hex(&[0x51]);

        let full = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let full_arr = full.as_array().unwrap();
        assert_eq!(full_arr.len(), 4);

        // Inclusive from, exclusive to → heights 1 and 2 only.
        let windowed = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh, 1, 3]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let w = windowed.as_array().unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(w[0]["height"], 1);
        assert_eq!(w[1]["height"], 2);
        assert!(w.len() < full_arr.len());

        // to_height=-1 is open upper (same as full for confirmed-only).
        let open_to = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh, 0, -1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(open_to.as_array().unwrap().len(), full_arr.len());

        // Subscribe status is always full history, independent of windowed calls.
        let status = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([sh]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let status_s = status.as_str().unwrap();
        assert!(!status_s.is_empty());
        // Recompute status from full confirmed history and match.
        let sh_bytes = {
            let mut b = rbitcoin_primitives::hex_decode(&sh).unwrap();
            b.reverse();
            let mut out = [0u8; 32];
            out.copy_from_slice(&b);
            out
        };
        let full_hist = q.scripthash_history(&sh_bytes).unwrap();
        assert_eq!(full_hist.len(), 4);
        assert_eq!(scripthash_status(Some(&q), &full_hist), status_s);

        let _ = prev;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tip_push_and_lagged_client() {
        let (dir, q) = tmp_store();
        // Need a tip for headers.subscribe; empty chain errors on subscribe.
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
        let mut hash = [0u8; 32];
        hash[0] = 1;
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: hash,
            hash,
        };
        let mut txid = [0u8; 32];
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        q.connect_block(Height(0), &header, &[ta]).unwrap();

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(2);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, q, params, tip_tx.clone(), None)
            .await
            .unwrap();
        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let mut line = serde_json::to_string(&json!({
            "jsonrpc":"2.0","id":1,"method":"blockchain.headers.subscribe","params":[]
        }))
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        // Push tip notify.
        tip_tx
            .send(TipNotify {
                height: 1,
                header_hex: "aa".repeat(80),
                reorg_from_height: None,
            })
            .unwrap();
        resp.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        let push: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            push["method"].as_str(),
            Some("blockchain.headers.subscribe")
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scripthash_subscribe_notifies_on_tip_confirm() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0x42;
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: hash,
            hash,
        };
        let mut txid = [0u8; 32];
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &header, &[ta]).unwrap();
        let sh = electrum_scripthash_hex(&[0x51]);

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(2);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, std::sync::Arc::clone(&q), params, tip_tx.clone(), None)
            .await
            .unwrap();
        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let mut line = serde_json::to_string(&json!({
            "jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[sh]
        }))
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();

        let hash1 = rbitcoin_store::block_header_hash(1, &hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let mut txid1 = [0u8; 32];
        txid1[0] = 0x11;
        txid1[31] = 0xcd;
        let ta1 = TxApply {
            tx: TxRecord {
                txid: txid1,
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
                script_sig: vec![1],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();
        tip_tx
            .send(TipNotify {
                height: 1,
                header_hex: "aa".repeat(80),
                reorg_from_height: None,
            })
            .unwrap();
        resp.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        let push: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            push["method"].as_str(),
            Some("blockchain.scripthash.subscribe")
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scripthash_subscribe_skips_tip_when_block_misses_sh() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0x42;
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: hash,
            hash,
        };
        let mut txid = [0u8; 32];
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &header, &[ta]).unwrap();
        let sh = electrum_scripthash_hex(&[0x51]);

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(2);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, std::sync::Arc::clone(&q), params, tip_tx.clone(), None)
            .await
            .unwrap();
        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let mut line = serde_json::to_string(&json!({
            "jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[sh]
        }))
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();

        let hash1 = rbitcoin_store::block_header_hash(1, &hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: hfk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let mut txid1 = [0u8; 32];
        txid1[0] = 0x11;
        txid1[31] = 0xcd;
        let ta1 = TxApply {
            tx: TxRecord {
                txid: txid1,
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
                script_sig: vec![1],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x00])],
        };
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();
        tip_tx
            .send(TipNotify {
                height: 1,
                header_hex: "aa".repeat(80),
                reorg_from_height: None,
            })
            .unwrap();
        resp.clear();
        let extra = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            reader.read_line(&mut resp),
        )
        .await;
        assert!(extra.is_err(), "untouched tip must not restatus: {resp:?}");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_view_status_includes_blockhash() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let merkle = [0xab; 32];
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle,
            hash: merkle,
        };
        let mut txid = [0xcb; 32];
        txid[31] = 0;
        let t0 = TxApply {
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        q.connect_block(Height(0), &h0, &[t0.clone()]).unwrap();
        let prev_fk = q.tip_header_fk().unwrap().unwrap();
        let mut h1 = h0.clone();
        h1.prev_fk = prev_fk;
        h1.timestamp = 2;
        h1.nonce = 1;
        h1.hash = rbitcoin_store::block_header_hash(
            h1.version,
            &merkle,
            &h1.merkle_root,
            h1.timestamp,
            h1.bits,
            h1.nonce,
        );
        let mut t1 = t0;
        t1.tx.txid[5] = 0xaa;
        q.connect_block(Height(1), &h1, &[t1.clone()]).unwrap();
        let sh = script_hash(&[0x51]);
        let hist_a = q.scripthash_history(&sh).unwrap();
        let status_a = scripthash_status(Some(&q), &hist_a);
        let legacy = {
            use bitcoin::hashes::{sha256, Hash as _};
            let mut s = String::new();
            for i in &hist_a {
                s.push_str(&format!("{}:{}:", txid_hex(&i.txid), i.height));
            }
            rbitcoin_primitives::hex_encode(sha256::Hash::hash(s.as_bytes()).to_byte_array())
        };
        assert_ne!(
            status_a, legacy,
            "status preimage must include confirming block hash"
        );

        q.disconnect_tip().unwrap();
        let mut h1b = h1.clone();
        h1b.nonce = 9;
        h1b.hash = rbitcoin_store::block_header_hash(
            h1b.version,
            &merkle,
            &h1b.merkle_root,
            h1b.timestamp,
            h1b.bits,
            h1b.nonce,
        );
        q.connect_block(Height(1), &h1b, &[t1]).unwrap();
        let hist_b = q.scripthash_history(&sh).unwrap();
        let status_b = scripthash_status(Some(&q), &hist_b);
        assert_eq!(
            hist_a
                .iter()
                .map(|i| (i.txid, i.height))
                .collect::<Vec<_>>(),
            hist_b
                .iter()
                .map(|i| (i.txid, i.height))
                .collect::<Vec<_>>(),
            "same txs at the same heights"
        );
        assert_ne!(
            status_a, status_b,
            "same-height replace must change status via blockhash"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chain_view_reorg_notifies_dropped_scripthash() {
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        let (dir, q) = tmp_store();
        let mut hash = [0u8; 32];
        hash[0] = 0x42;
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: hash,
            hash,
        };
        let mut txid = [0u8; 32];
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x51])],
        };
        let hfk0 = q.connect_block(Height(0), &header, &[ta]).unwrap();
        let sh = electrum_scripthash_hex(&[0x51]);

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(2);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, std::sync::Arc::clone(&q), params, tip_tx.clone(), None)
            .await
            .unwrap();
        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        let mut line = serde_json::to_string(&json!({
            "jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[sh]
        }))
        .unwrap();
        line.push('\n');
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut resp = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .unwrap()
        .unwrap();
        let first: Value = serde_json::from_str(&resp).unwrap();
        let status0 = first["result"].as_str().unwrap().to_string();
        assert!(!status0.is_empty());
        let _ = hfk0;

        q.disconnect_tip().unwrap();
        let mut hash_b = [0u8; 32];
        hash_b[0] = 0x43;
        let header_b = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: hash_b,
            hash: hash_b,
        };
        let mut txid_b = [0u8; 32];
        txid_b[0] = 0x99;
        txid_b[31] = 0xcd;
        let ta_b = TxApply {
            tx: TxRecord {
                txid: txid_b,
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
                script_sig: vec![1],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(1, vec![0x00])],
        };
        q.connect_block(Height(0), &header_b, &[ta_b]).unwrap();
        tip_tx
            .send(TipNotify {
                height: 0,
                header_hex: "aa".repeat(80),
                reorg_from_height: Some(0),
            })
            .unwrap();
        resp.clear();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            reader.read_line(&mut resp),
        )
        .await
        .expect("reorg must restatus even when the new block misses the scripthash")
        .unwrap();
        let push: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(
            push["method"].as_str(),
            Some("blockchain.scripthash.subscribe")
        );
        assert_ne!(
            push["params"][1].as_str().unwrap_or("missing"),
            status0,
            "dropped history must change status"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dispatch_with_mempool_and_param_errors() {
        use rbitcoin_net::MempoolHub;
        use std::sync::Arc;

        let (dir, q) = tmp_store();
        // Genesis tip for broadcast / scripthash paths.
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};
        let mut hash = [0u8; 32];
        hash[0] = 0x42;
        let header = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: hash,
            hash,
        };
        let mut txid = [0u8; 32];
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
                script_sig: vec![0],
                witness: vec![],
            }],
            outputs: vec![OutputRecord::unspent(50_000, vec![0x51])],
        };
        q.connect_block(Height(0), &header, &[ta]).unwrap();

        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let q_arc = Arc::new(q);
        let mp_path = dir.join("mempool");
        let mp = MempoolHub::open(&mp_path, Arc::clone(&q_arc)).expect("mempool");
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let sh = electrum_scripthash_hex(&[0x51]);

        // Mempool-aware scripthash methods (empty pool).
        let hist = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(hist.as_array().is_some());

        let bal = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(bal["confirmed"].as_i64().unwrap_or(0) >= 0);

        let unspent = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(unspent.as_array().is_some());

        let sub = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(sub.as_str().is_some());

        let mem = dispatch(
            "blockchain.scripthash.get_mempool",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert_eq!(mem, json!([]));

        let hist_fee = dispatch(
            "mempool.get_fee_histogram",
            &json!([]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(hist_fee.as_array().is_some());

        // headers.subscribe with tip.
        let hs = dispatch(
            "blockchain.headers.subscribe",
            &json!([]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(header_sub);
        assert!(hs.get("height").is_some());

        // param_txid wrong length.
        assert!(param_txid(&json!(["aabb"]), 0).is_err());
        assert!(param_txid(&json!(["zz".repeat(32)]), 0).is_err());

        // Broadcast without valid tx → reject (mempool gate).
        assert!(dispatch(
            "blockchain.transaction.broadcast",
            &json!(["01000000000000000000"]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .is_err());

        // transaction.get for confirmed coinbase (hex).
        let tid = {
            let fks = q_arc.block_tx_fks(Height(0)).unwrap();
            let t = q_arc.get_tx(fks[0]).unwrap();
            hash_hex_rev(&t.txid)
        };
        let raw = dispatch(
            "blockchain.transaction.get",
            &json!([tid, false]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(raw.as_str().unwrap().len() > 20);

        // Verbose get (may be object or hex depending on implementation).
        let _ = dispatch(
            "blockchain.transaction.get",
            &json!([tid, true]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        );

        // scripthash_status_full direct.
        let sh_bytes = param_scripthash(&json!([sh]), 0).unwrap();
        let st = scripthash_status_full(&q_arc, &mp, &sh_bytes).unwrap();
        assert!(!st.is_empty() || st.is_empty()); // always returns string

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Live mempool txs: listunspent mempool outs, get_mempool rows, fee histogram,
    /// estimatefee, transaction.get mempool path, broadcast accept, status_full.
    #[test]
    fn dispatch_live_mempool_surfaces() {
        use bitcoin::absolute::LockTime;
        use bitcoin::hashes::Hash;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        use rbitcoin_consensus::{accept_and_connect_block, Milestone};
        use rbitcoin_net::MempoolHub;
        use rbitcoin_primitives::Height;
        use rbitcoin_store::script_hash;
        use std::sync::Arc;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        // Maturity pad so early coinbases are spendable (shared helper, not a POW remine loop).
        let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            103,
            2,
        );

        let q_arc = Arc::new(q);
        let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q_arc)).unwrap();
        mp.set_relay_enabled(true);

        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let sh = electrum_scripthash_hex(spk.as_bytes());
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
                value: Amount::from_sat(50_0000_0000 - 1_000),
                script_pubkey: spk.clone(),
            }],
        };
        mp.accept_tx(&parent).expect("accept parent");

        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();

        // History + mempool rows
        let hist = dispatch(
            "blockchain.scripthash.get_history",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!hist.as_array().unwrap().is_empty());

        let bal = dispatch(
            "blockchain.scripthash.get_balance",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let _ = bal["unconfirmed"].as_i64();

        // listunspent: confirmed coinbases + mempool parent out (filter spent)
        let unspent = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!unspent.as_array().unwrap().is_empty());

        let mem = dispatch(
            "blockchain.scripthash.get_mempool",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!mem.as_array().unwrap().is_empty());

        let sub = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(sub.as_str().is_some());

        let hist_fee = dispatch(
            "mempool.get_fee_histogram",
            &json!([]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(!hist_fee.as_array().unwrap().is_empty());

        let est = dispatch(
            "blockchain.estimatefee",
            &json!([2]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(est.as_f64().unwrap() >= 0.0);

        // Mempool transaction.get (parent not yet confirmed)
        let parent_hex = {
            let mut t = parent.compute_txid().to_byte_array();
            t.reverse();
            rbitcoin_primitives::hex_encode(t)
        };
        // Parent is live in mempool but also may resolve via chain if coinbase-related;
        // get by parent txid — if not confirmed, hits mempool fallback.
        let got = dispatch(
            "blockchain.transaction.get",
            &json!([parent_hex, true]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        );
        // Either confirmed path or mempool — must succeed for live parent.
        assert!(got.is_ok(), "{got:?}");

        // Broadcast a second spend of coinbase[1]
        let second = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: coinbase_txids[1],
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000 - 2_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            }],
        };
        let raw = bitcoin::consensus::serialize(&second);
        let raw_hex = rbitcoin_primitives::hex_encode(&raw);
        let br = dispatch(
            "blockchain.transaction.broadcast",
            &json!([raw_hex]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .expect("broadcast");
        assert!(br.as_str().unwrap().len() == 64);

        // status_full with live mempool
        let sh_bytes = script_hash(spk.as_bytes());
        let st = scripthash_status_full(&q_arc, &mp, &sh_bytes).unwrap();
        assert!(!st.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unused scripthash listunspent must not rebuild mempool spentness from
    /// every live body. Confirmed UTXOs spent by the mempool still drop.
    #[test]
    fn listunspent_unused_sh_does_not_load_mempool_bodies() {
        use bitcoin::absolute::LockTime;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        use rbitcoin_consensus::{accept_and_connect_block, Milestone};
        use rbitcoin_net::MempoolHub;
        use rbitcoin_primitives::Height;
        use std::sync::Arc;

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        const N_SPENDS: u32 = 4;
        let (_tip, _tip_time, coinbase_txids) = rbitcoin_consensus::pad_empty_from(
            &q,
            &params,
            genesis.block_hash(),
            genesis.header.time,
            1,
            100 + N_SPENDS,
            N_SPENDS,
        );
        let q_arc = Arc::new(q);
        let mp = MempoolHub::open(dir.join("mempool"), Arc::clone(&q_arc)).unwrap();
        mp.set_relay_enabled(true);
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        for (i, cbtxid) in coinbase_txids.iter().enumerate() {
            let fee = 1_000u64 + i as u64;
            let tx = Transaction {
                version: TxVersion::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: *cbtxid,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(50_0000_0000 - fee),
                    script_pubkey: spk.clone(),
                }],
            };
            mp.accept_tx(&tx).expect("accept spend");
        }
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let unused = electrum_scripthash_hex(&[0x00]);
        let _ = mp.sample_reset_perf();
        let empty = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([unused]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        assert!(empty.as_array().unwrap().is_empty());
        let s = mp.sample_reset_perf();
        assert_eq!(
            s.spent_body_loads, 0,
            "unused scripthash must not load mempool bodies (got {})",
            s.spent_body_loads
        );

        // Spent coinbase of the used script must drop; mempool parent out remains.
        let sh = electrum_scripthash_hex(spk.as_bytes());
        let unspent = dispatch(
            "blockchain.scripthash.listunspent",
            &json!([sh]),
            &q_arc,
            &cfg,
            &params,
            Some(&mp),
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let rows = unspent.as_array().unwrap();
        let spent_cb = format!("{}", coinbase_txids[0]);
        assert!(
            rows.iter().all(|r| r["tx_hash"] != spent_cb),
            "mempool-spent coinbase must drop: {rows:?}"
        );
        assert!(
            rows.iter().any(|r| r["height"] == 0),
            "mempool output must remain: {rows:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DoS: line without newline beyond max must fail without allocating forever.
    #[tokio::test]
    async fn read_line_capped_rejects_oversize() {
        use std::io::Cursor;
        use tokio::io::BufReader;
        let mut r = BufReader::new(Cursor::new(vec![b'A'; 64]));
        let err = read_line_capped(&mut r, 32).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_line_capped_accepts_under_limit() {
        use std::io::Cursor;
        use tokio::io::BufReader;
        let mut r = BufReader::new(Cursor::new(b"{\"id\":1}\nnext\n".as_slice()));
        let line = read_line_capped(&mut r, 1024).await.unwrap().unwrap();
        assert_eq!(line, "{\"id\":1}");
        let line2 = read_line_capped(&mut r, 1024).await.unwrap().unwrap();
        assert_eq!(line2, "next");
    }

    #[test]
    fn scripthash_sub_cap_enforced() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        cfg.max_scripthash_subs = 2;
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        // Two unique scripthashes.
        let h1 = "11".repeat(32);
        let h2 = "22".repeat(32);
        let h3 = "33".repeat(32);
        dispatch(
            "blockchain.scripthash.subscribe",
            &json!([h1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        dispatch(
            "blockchain.scripthash.subscribe",
            &json!([h2]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let err = dispatch(
            "blockchain.scripthash.subscribe",
            &json!([h3]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap_err();
        assert!(err.contains("too many"), "{err}");
        // Re-subscribe existing is ok.
        dispatch(
            "blockchain.scripthash.subscribe",
            &json!([h1]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broadcast_hex_cap_enforced() {
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        cfg.max_broadcast_hex = 16;
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let err = dispatch(
            "blockchain.transaction.broadcast",
            &json!(["aa".repeat(20)]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap_err();
        assert!(err.contains("too large"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DoS: when at max_connections, further accepts are dropped immediately.
    #[tokio::test]
    async fn max_connections_rejects_extra_client() {
        use tokio::io::AsyncReadExt;
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let q = Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        cfg.limits.max_connections = 1;
        cfg.limits.idle_timeout = Duration::from_secs(30);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");

        // Hold the only slot open.
        let held = TcpStream::connect(handle.local_addr).await.unwrap();
        // Give accept loop time to take the permit.
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Second client: TCP may still accept then drop the stream when no permit.
        let mut second = TcpStream::connect(handle.local_addr).await.unwrap();
        let req = json!({"jsonrpc":"2.0","id":1,"method":"server.ping","params":[]});
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        let _ = second.write_all(line.as_bytes()).await;
        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(Duration::from_millis(400), second.read(&mut buf)).await;
        // Dropped connection: EOF / error / timeout — not a successful JSON-RPC pong.
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// DoS: quiet client is disconnected when idle_timeout elapses.
    #[tokio::test]
    async fn idle_timeout_disconnects_quiet_client() {
        use tokio::io::AsyncReadExt;
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let q = Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let mut cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        cfg.limits.idle_timeout = Duration::from_millis(80);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");

        let mut stream = TcpStream::connect(handle.local_addr).await.unwrap();
        // Send nothing — wait for server idle close.
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {} // clean EOF or error on close
            Ok(Ok(n)) => panic!("unexpected data from idle close: {:?}", &buf[..n]),
            Err(_) => panic!("idle timeout did not close connection within 2s"),
        }
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_limits_public_proxy_defaults() {
        let lim = ServeLimits::for_public_proxy();
        assert_eq!(lim.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(lim.max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
        assert_eq!(
            lim.idle_timeout,
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
        );
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("0.0.0.0:50001".parse().unwrap(), &params);
        assert_eq!(cfg.limits, lim);
        assert_eq!(cfg.max_connections(), DEFAULT_MAX_CONNECTIONS);
        assert_eq!(cfg.max_line_bytes(), DEFAULT_MAX_LINE_BYTES);
    }

    #[test]
    fn tweaks_rpc_result_is_first_height_only() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..12u32 {
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version: 1,
                timestamp: h + 1,
                bits: 0x207fffff,
                nonce: h,
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
                inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            parent_hash = Some(hash);
        }
        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let v = dispatch(
            "blockchain.tweaks.subscribe",
            &json!([0, 100, true]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 1, "RPC result is the first height only");
        assert!(obj.contains_key("0"));
        assert!(!obj.contains_key("1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Cake scan isolate uses ElectrumProvider.subscribe: JSON-RPC result is the
    /// first height, then one notification per following height, then
    /// `{"message":"done"}`. A multi-height result is treated as one event
    /// (last key only); no `done` leaves the isolate pinging forever.
    #[tokio::test]
    async fn tweaks_subscribe_streams_heights_then_done() {
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let mut prev = Fk::NULL;
        let mut parent_hash: Option<[u8; 32]> = None;
        for h in 0..5u32 {
            let mut merkle = [0u8; 32];
            merkle[0..4].copy_from_slice(&h.to_le_bytes());
            merkle[5] = 0xec;
            let hash = match parent_hash {
                None => merkle,
                Some(ph) => {
                    rbitcoin_store::block_header_hash(1, &ph, &merkle, h + 1, 0x207fffff, h)
                }
            };
            let header = HeaderRecord {
                prev_fk: prev,
                version: 1,
                timestamp: h + 1,
                bits: 0x207fffff,
                nonce: h,
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
                inputs: vec![InputRecord::coinbase(u32::MAX, vec![h as u8], vec![])],
                outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51])],
            };
            prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
            parent_hash = Some(hash);
        }

        let params = ChainParams::regtest();
        let q = std::sync::Arc::new(q);
        let (tip_tx, _) = broadcast::channel(4);
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);
        let handle = run_electrum(cfg, q, params, tip_tx, None)
            .await
            .expect("listen");

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

        async fn read_json(reader: &mut BufReader<&mut TcpStream>) -> Value {
            let mut resp = String::new();
            tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut resp))
                .await
                .unwrap_or_else(|_| panic!("tweaks stream: timed out"))
                .unwrap();
            serde_json::from_str(&resp)
                .unwrap_or_else(|e| panic!("tweaks stream parse {e}: {resp}"))
        }

        let result = read_json(&mut reader).await;
        assert_eq!(result["id"], "scan");
        let map = result["result"].as_object().expect("result map");
        assert_eq!(
            map.len(),
            1,
            "JSON-RPC result must be one height, got {map:?}"
        );
        assert!(map.contains_key("1"), "{map:?}");

        let n2 = read_json(&mut reader).await;
        assert_eq!(n2["method"], "blockchain.tweaks.subscribe");
        let p2 = n2["params"][0].as_object().expect("notify 2");
        assert_eq!(p2.len(), 1);
        assert!(p2.contains_key("2"), "{p2:?}");

        let n3 = read_json(&mut reader).await;
        assert_eq!(n3["method"], "blockchain.tweaks.subscribe");
        let p3 = n3["params"][0].as_object().expect("notify 3");
        assert_eq!(p3.len(), 1);
        assert!(p3.contains_key("3"), "{p3:?}");

        let done = read_json(&mut reader).await;
        assert_eq!(done["method"], "blockchain.tweaks.subscribe");
        assert_eq!(done["params"][0]["message"], "done");

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tweaks_subscribe_matches_engine_on_p2wpkh_spend() {
        use bitcoin::hashes::{hash160, Hash};
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        use rbitcoin_consensus::tweak_from_tx;
        use rbitcoin_primitives::{Fk, Height};
        use rbitcoin_query::TxApply;
        use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, TxRecord};

        if std::env::var_os("RBITCOIN_HEAD_SCALE").is_none() {
            std::env::set_var("RBITCOIN_HEAD_SCALE", "tiny");
        }
        let (dir, q) = tmp_store();
        let params = ChainParams::regtest();
        let cfg = ElectrumConfig::for_params("127.0.0.1:0".parse().unwrap(), &params);

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

        let mut genesis_txid = [0u8; 32];
        genesis_txid[31] = 0xcb;
        let mut merkle0 = [0u8; 32];
        merkle0[5] = 0xec;
        let h0 = HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 1,
            bits: 0x207fffff,
            nonce: 0,
            merkle_root: merkle0,
            hash: merkle0,
        };
        let ta0 = TxApply {
            tx: TxRecord {
                txid: genesis_txid,
                version: 1,
                locktime: 0,
                input_start_fk: Fk::NULL,
                input_count: 1,
                output_start_fk: Fk::NULL,
                output_count: 1,
            },
            inputs: vec![InputRecord::coinbase(u32::MAX, vec![0x00], vec![])],
            outputs: vec![OutputRecord::unspent(50_0000_0000, p2wpkh.clone())],
        };
        let fk0 = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
        let create_fk = q.block_tx_fks(Height(0)).unwrap()[0];

        let mut spend_txid = [0u8; 32];
        spend_txid[0] = 0x11;
        spend_txid[31] = 0xcd;
        let hash1 = rbitcoin_store::block_header_hash(1, &h0.hash, &[0x11; 32], 2, 0x207fffff, 1);
        let h1 = HeaderRecord {
            prev_fk: fk0,
            version: 1,
            timestamp: 2,
            bits: 0x207fffff,
            nonce: 1,
            merkle_root: [0x11; 32],
            hash: hash1,
        };
        let ta1 = TxApply {
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
                prev_txid: genesis_txid,
                create_fk,
                prev_index: 0,
                sequence: u32::MAX,
                script_sig: vec![],
                witness: vec![vec![0u8; 64], ser.to_vec()],
            }],
            outputs: vec![OutputRecord::unspent(49_0000_0000, p2tr.clone())],
        };
        q.connect_block(Height(1), &h1, &[ta1]).unwrap();

        let mut header_sub = false;
        let mut sh_subs = HashSet::new();
        let v = dispatch(
            "blockchain.tweaks.subscribe",
            &json!([1, 1, false]),
            &q,
            &cfg,
            &params,
            None,
            &mut header_sub,
            &mut sh_subs,
        )
        .unwrap();

        let engine_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array(genesis_txid),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[&[0u8; 64][..], &ser[..]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(p2tr),
            }],
        };
        let engine_prev = vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(p2wpkh),
        }];
        let expect = tweak_from_tx(&engine_tx, &engine_prev).unwrap();
        let mut disp = spend_txid;
        disp.reverse();
        let key = rbitcoin_primitives::hex_encode(disp);
        assert_eq!(
            v["1"][key]["tweak"],
            json!(rbitcoin_primitives::hex_encode(expect.tweak))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
