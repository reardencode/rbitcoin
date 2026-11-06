//! Health listener (`--health-listen`): unauthenticated `GET /healthz` and
//! `GET /readyz` for process probes, `GET /progress` for the long stage
//! running now, and `GET /metrics` with `--metrics`.
//!
//! It binds at the top of [`crate::run_p2p`], before the store opens, so it
//! answers through a schema migration, catch-up, and index materialize. The
//! RPC, Electrum, and Esplora listeners bind only after those.

#[doc(hidden)]
pub mod metrics;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rbitcoin_log::{info, progress, warn};
use rbitcoin_net::{BlockingRegion, ChainHub, MempoolHub, PeerHub};
use rbitcoin_primitives::Network;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinHandle};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// `/readyz` checks running at once. Probers send one request per period;
/// past this a probe answers 503 at once instead of queueing.
#[doc(hidden)]
pub const READYZ_IN_FLIGHT: usize = 4;
/// Per-request wall. Probe timeouts are usually 1s.
#[doc(hidden)]
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Tip and scripthash index lag that `/readyz` still calls ready.
pub const READY_LAG_BLOCKS: u32 = 6;

/// Where [`crate::run_p2p`] is in bring-up. `/readyz` is 503 until `Following`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Store open: schema migration, backfill, spend replay.
    Opening,
    /// P2P, mempool, and proxy bring-up before catch-up.
    Starting,
    /// Initial block download.
    CatchUp,
    /// Tip-mode entry (scripthash materialize), follow peers, listeners.
    Indexing,
    /// Tip-follow loop.
    Following,
    /// Shutdown flush.
    Stopping,
}

impl Phase {
    #[doc(hidden)]
    pub const ALL: [Self; 6] = [
        Self::Opening,
        Self::Starting,
        Self::CatchUp,
        Self::Indexing,
        Self::Following,
        Self::Stopping,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Starting => "starting",
            Self::CatchUp => "catch-up",
            Self::Indexing => "indexing",
            Self::Following => "following",
            Self::Stopping => "stopping",
        }
    }

    #[doc(hidden)]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Opening,
            1 => Self::Starting,
            2 => Self::CatchUp,
            3 => Self::Indexing,
            4 => Self::Following,
            _ => Self::Stopping,
        }
    }
}

/// Bring-up state the health routes read. `run_p2p` writes the phase at each
/// transition; every read is an atomic load or a `OnceLock` get.
pub struct NodeStatus {
    pub phase: AtomicU8,
    pub network: Network,
    pub sh_index: bool,
    pub started: SystemTime,
    pub chain: OnceLock<Arc<ChainHub>>,
    pub peers: OnceLock<Arc<PeerHub>>,
    pub mempool: OnceLock<Arc<MempoolHub>>,
    pub sv2: OnceLock<Arc<rbitcoin_sv2::Sv2TpStats>>,
}

impl NodeStatus {
    pub fn new(network: Network, sh_index: bool) -> Arc<Self> {
        Arc::new(Self {
            phase: AtomicU8::new(Phase::Opening as u8),
            network,
            sh_index,
            started: SystemTime::now(),
            chain: OnceLock::new(),
            peers: OnceLock::new(),
            mempool: OnceLock::new(),
            sv2: OnceLock::new(),
        })
    }

    pub fn enter(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    pub fn attach_p2p(&self, chain: &Arc<ChainHub>, peers: &Arc<PeerHub>) {
        let _ = self.chain.set(Arc::clone(chain));
        let _ = self.peers.set(Arc::clone(peers));
    }

    pub fn attach_mempool(&self, mempool: &Arc<MempoolHub>) {
        let _ = self.mempool.set(Arc::clone(mempool));
    }

    pub fn attach_sv2(&self, stats: Arc<rbitcoin_sv2::Sv2TpStats>) {
        let _ = self.sv2.set(stats);
    }

    #[doc(hidden)]
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Chain reads may touch the store; call from the blocking pool.
    #[doc(hidden)]
    pub fn ready_snapshot(&self) -> ReadySnapshot {
        let phase = self.phase();
        let mut snap = ReadySnapshot {
            phase,
            in_ibd: false,
            blocks: 0,
            headers: 0,
            tip_age_secs: None,
            max_tip_age_secs: 0,
            sh_lag: None,
        };
        if phase != Phase::Following {
            return snap;
        }
        if let Some(chain) = self.chain.get() {
            snap.in_ibd = chain.in_ibd();
            snap.blocks = chain.query.tip_height().map_or(0, |h| h.0);
            snap.headers = chain.best_header_height();
            snap.tip_age_secs = chain
                .tip_header()
                .map(|h| chain.clock.now_secs().saturating_sub(u64::from(h.time)));
            snap.max_tip_age_secs = chain.max_tip_age_secs();
            snap.sh_lag = self.sh_index.then(|| chain.query.sh_lag_heights());
        }
        snap
    }
}

/// The inputs of one `/readyz` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ReadySnapshot {
    pub phase: Phase,
    /// Same value as RPC `getblockchaininfo.initialblockdownload`.
    pub in_ibd: bool,
    pub blocks: u32,
    pub headers: u32,
    /// Seconds since the tip block time; `None` with no tip. `in_ibd` latches
    /// off after the first exit — this one keeps reporting a stale tip.
    pub tip_age_secs: Option<u64>,
    pub max_tip_age_secs: u64,
    /// `None` without `--sh-index`.
    pub sh_lag: Option<u32>,
}

/// `Ok` when ready; otherwise the first failing gate, in check order.
#[doc(hidden)]
pub fn readiness(s: &ReadySnapshot) -> Result<(), String> {
    if s.phase != Phase::Following {
        return Err(s.phase.as_str().to_string());
    }
    if s.in_ibd {
        return Err("initial block download".into());
    }
    if let Some(age) = s.tip_age_secs {
        if age > s.max_tip_age_secs {
            return Err(format!("tip stale (last block {age}s ago)"));
        }
    }
    let behind = s.headers.saturating_sub(s.blocks);
    if behind > READY_LAG_BLOCKS {
        return Err(format!("tip {behind} blocks behind headers"));
    }
    match s.sh_lag {
        Some(lag) if lag > READY_LAG_BLOCKS => {
            Err(format!("scripthash index {lag} blocks behind tip"))
        }
        _ => Ok(()),
    }
}

/// Bound health listener. Dropping it stops serving.
pub struct HealthHandle {
    pub local_addr: SocketAddr,
    pub task: JoinHandle<()>,
}

impl Drop for HealthHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind `addr` and serve the health routes (and `/metrics` when `metrics`)
/// until the handle drops.
pub async fn run_health(
    addr: SocketAddr,
    status: Arc<NodeStatus>,
    metrics: bool,
) -> std::io::Result<HealthHandle> {
    let listener = rbitcoin_net::listen::bind_tcp(addr)?;
    let local_addr = listener.local_addr()?;
    if !local_addr.ip().is_loopback() {
        warn!(
            "health: {local_addr} is not loopback; /healthz, /readyz, {} are unauthenticated",
            if metrics {
                "/progress, and /metrics"
            } else {
                "and /progress"
            }
        );
    }
    let app = router(status, metrics);
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            warn!("health: serve ended: {e}");
        }
    });
    info!("health HTTP on {local_addr}");
    Ok(HealthHandle { local_addr, task })
}

/// Router state: the node's status and the gates on blocking work.
#[derive(Clone)]
#[doc(hidden)]
pub struct Health {
    pub status: Arc<NodeStatus>,
    pub readyz: Arc<Semaphore>,
    /// One render at a time, so a scrape never starts a second mempool fold
    /// while one is running.
    pub scrape: Arc<Semaphore>,
}

impl Health {
    #[doc(hidden)]
    pub fn new(status: Arc<NodeStatus>) -> Self {
        Self {
            status,
            readyz: Arc::new(Semaphore::new(READYZ_IN_FLIGHT)),
            scrape: Arc::new(Semaphore::new(1)),
        }
    }
}

#[doc(hidden)]
pub fn router(status: Arc<NodeStatus>, metrics: bool) -> Router {
    router_for(Health::new(status), metrics)
}

#[doc(hidden)]
pub fn router_for(health: Health, metrics: bool) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/progress", get(progress_json));
    let routes = if metrics {
        routes.route("/metrics", get(scrape))
    } else {
        routes
    };
    // Outer → inner: timeout → body (GET only, so none). The timeout covers
    // the whole request. The blocking work is capped by `gated`, not by a
    // concurrency layer: tower's queues without a bound, and axum builds one
    // per route.
    routes
        .layer(RequestBodyLimitLayer::new(0))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .with_state(health)
}

/// Run `f` on the blocking pool under a permit from `gate`, or `None` at
/// once when every permit is taken.
///
/// The permit moves into the task. A blocking task cannot be cancelled, so
/// a request that times out drops only its wait, and the gate stays closed
/// until `f` returns: timed-out requests cannot stack chain or mempool
/// readers behind the cap.
pub async fn gated<T: Send + 'static>(
    gate: &Arc<Semaphore>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<Result<T, JoinError>> {
    let permit = Arc::clone(gate).try_acquire_owned().ok()?;
    Some(
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _g = BlockingRegion::enter();
            f()
        })
        .await,
    )
}

pub async fn healthz() -> &'static str {
    "ok\n"
}

pub async fn scrape(State(health): State<Health>) -> Response {
    let status = Arc::clone(&health.status);
    match gated(&health.scrape, move || metrics::render(&status)).await {
        Some(Ok(body)) => ([(header::CONTENT_TYPE, metrics::CONTENT_TYPE)], body).into_response(),
        Some(Err(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("metrics: {e}\n")).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics: a scrape is already running\n",
        )
            .into_response(),
    }
}

pub async fn readyz(State(health): State<Health>) -> (StatusCode, String) {
    let status = Arc::clone(&health.status);
    match gated(&health.readyz, move || status.ready_snapshot()).await {
        Some(Ok(snap)) => match readiness(&snap) {
            Ok(()) => (StatusCode::OK, "ok\n".into()),
            Err(reason) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("not ready: {reason}\n"),
            ),
        },
        Some(Err(e)) => (StatusCode::SERVICE_UNAVAILABLE, format!("not ready: {e}\n")),
        None => (StatusCode::SERVICE_UNAVAILABLE, "not ready: busy\n".into()),
    }
}

/// `GET /progress`: the bring-up phase plus the long stage running now
/// (index build, rebuild, backfill), at any log level. Reads one lock and a
/// few atomics, so it needs no gate.
pub async fn progress_json(State(health): State<Health>) -> axum::Json<serde_json::Value> {
    let (running, finished) = progress::view();
    axum::Json(progress_body(
        health.status.phase(),
        running.as_ref(),
        finished.as_ref(),
    ))
}

#[doc(hidden)]
pub fn progress_body(
    phase: Phase,
    running: Option<&progress::Snapshot>,
    finished: Option<&progress::Snapshot>,
) -> serde_json::Value {
    let finished = finished.map(|f| {
        serde_json::json!({
            "stage": f.stage,
            "done": f.done,
            "total": f.total,
            "elapsed_secs": f.elapsed.as_secs(),
        })
    });
    let Some(p) = running else {
        return serde_json::json!({
            "phase": phase.as_str(),
            "stage": null,
            "finished": finished,
        });
    };
    serde_json::json!({
        "phase": phase.as_str(),
        "stage": p.stage,
        "done": p.done,
        "total": p.total,
        "percent": p.percent(),
        "elapsed_secs": p.elapsed.as_secs(),
        "eta_secs": p.eta().map(|d| d.as_secs()),
        "finished": finished,
    })
}
