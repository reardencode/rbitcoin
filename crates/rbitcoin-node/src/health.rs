//! Health listener (`--health-listen`): unauthenticated `GET /healthz` and
//! `GET /readyz` for process probes, `GET /progress` for the long stage
//! running now, and `GET /metrics` with `--metrics`.
//!
//! It binds at the top of [`crate::run_p2p`], before the store opens, so it
//! answers through a schema migration, catch-up, and index materialize. The
//! RPC, Electrum, and Esplora listeners bind only after those.

mod metrics;

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
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinHandle};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// `/readyz` checks running at once. Probers send one request per period;
/// past this a probe answers 503 at once instead of queueing.
const READYZ_IN_FLIGHT: usize = 4;
/// Per-request wall. Probe timeouts are usually 1s.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Tip and scripthash index lag that `/readyz` still calls ready.
pub(crate) const READY_LAG_BLOCKS: u32 = 6;

/// Where [`crate::run_p2p`] is in bring-up. `/readyz` is 503 until `Following`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
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
    const ALL: [Self; 6] = [
        Self::Opening,
        Self::Starting,
        Self::CatchUp,
        Self::Indexing,
        Self::Following,
        Self::Stopping,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Starting => "starting",
            Self::CatchUp => "catch-up",
            Self::Indexing => "indexing",
            Self::Following => "following",
            Self::Stopping => "stopping",
        }
    }

    fn from_u8(v: u8) -> Self {
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
pub(crate) struct NodeStatus {
    phase: AtomicU8,
    network: Network,
    sh_index: bool,
    started: SystemTime,
    chain: OnceLock<Arc<ChainHub>>,
    peers: OnceLock<Arc<PeerHub>>,
    mempool: OnceLock<Arc<MempoolHub>>,
    /// Configured listeners that failed to bind (RPC, Electrum, Esplora only warn).
    unbound: OnceLock<Vec<&'static str>>,
}

impl NodeStatus {
    pub(crate) fn new(network: Network, sh_index: bool) -> Arc<Self> {
        Arc::new(Self {
            phase: AtomicU8::new(Phase::Opening as u8),
            network,
            sh_index,
            started: SystemTime::now(),
            chain: OnceLock::new(),
            peers: OnceLock::new(),
            mempool: OnceLock::new(),
            unbound: OnceLock::new(),
        })
    }

    pub(crate) fn enter(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    pub(crate) fn attach_p2p(&self, chain: &Arc<ChainHub>, peers: &Arc<PeerHub>) {
        let _ = self.chain.set(Arc::clone(chain));
        let _ = self.peers.set(Arc::clone(peers));
    }

    pub(crate) fn attach_mempool(&self, mempool: &Arc<MempoolHub>) {
        let _ = self.mempool.set(Arc::clone(mempool));
    }

    /// Enter [`Phase::Following`] with the configured listeners that did not bind.
    pub(crate) fn follow(&self, unbound: Vec<&'static str>) {
        let _ = self.unbound.set(unbound);
        self.enter(Phase::Following);
    }

    fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Chain reads may touch the store; call from the blocking pool.
    fn ready_snapshot(&self) -> ReadySnapshot {
        let phase = self.phase();
        let mut snap = ReadySnapshot {
            phase,
            unbound: self.unbound.get().cloned().unwrap_or_default(),
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
struct ReadySnapshot {
    phase: Phase,
    unbound: Vec<&'static str>,
    /// Same value as RPC `getblockchaininfo.initialblockdownload`.
    in_ibd: bool,
    blocks: u32,
    headers: u32,
    /// Seconds since the tip block time; `None` with no tip. `in_ibd` latches
    /// off after the first exit — this one keeps reporting a stale tip.
    tip_age_secs: Option<u64>,
    max_tip_age_secs: u64,
    /// `None` without `--sh-index`.
    sh_lag: Option<u32>,
}

/// `Ok` when ready; otherwise the first failing gate, in check order.
fn readiness(s: &ReadySnapshot) -> Result<(), String> {
    if s.phase != Phase::Following {
        return Err(s.phase.as_str().to_string());
    }
    if !s.unbound.is_empty() {
        return Err(format!("{} not listening", s.unbound.join(", ")));
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
pub(crate) struct HealthHandle {
    task: JoinHandle<()>,
}

impl Drop for HealthHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind `addr` and serve the health routes (and `/metrics` when `metrics`)
/// until the handle drops.
pub(crate) async fn run_health(
    addr: SocketAddr,
    status: Arc<NodeStatus>,
    metrics: bool,
) -> std::io::Result<HealthHandle> {
    let listener = TcpListener::bind(addr).await?;
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
    Ok(HealthHandle { task })
}

/// Router state: the node's status and the gates on blocking work.
#[derive(Clone)]
struct Health {
    status: Arc<NodeStatus>,
    readyz: Arc<Semaphore>,
    /// One render at a time, so a scrape never starts a second mempool fold
    /// while one is running.
    scrape: Arc<Semaphore>,
}

impl Health {
    fn new(status: Arc<NodeStatus>) -> Self {
        Self {
            status,
            readyz: Arc::new(Semaphore::new(READYZ_IN_FLIGHT)),
            scrape: Arc::new(Semaphore::new(1)),
        }
    }
}

fn router(status: Arc<NodeStatus>, metrics: bool) -> Router {
    router_for(Health::new(status), metrics)
}

fn router_for(health: Health, metrics: bool) -> Router {
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
async fn gated<T: Send + 'static>(
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

async fn healthz() -> &'static str {
    "ok\n"
}

async fn scrape(State(health): State<Health>) -> Response {
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

async fn readyz(State(health): State<Health>) -> (StatusCode, String) {
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
async fn progress_json(State(health): State<Health>) -> axum::Json<serde_json::Value> {
    let (running, finished) = progress::view();
    axum::Json(progress_body(
        health.status.phase(),
        running.as_ref(),
        finished.as_ref(),
    ))
}

fn progress_body(
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

#[cfg(test)]
mod tests {
    use super::*;

    fn following() -> ReadySnapshot {
        ReadySnapshot {
            phase: Phase::Following,
            unbound: Vec::new(),
            in_ibd: false,
            blocks: 100,
            headers: 100,
            tip_age_secs: Some(0),
            max_tip_age_secs: 24 * 60 * 60,
            sh_lag: None,
        }
    }

    /// Phase, header-lag, scripthash-lag, and tip-age boundaries. One live
    /// node would need a header fork, a stalled index, and a tip older than
    /// `--max-tip-age` at once. `node_listen_and_exit` owns the HTTP answers
    /// a probe sees: live during initial block download, ready after a fresh
    /// block, and 503 when a listener did not bind.
    #[test]
    fn readiness_reports_the_first_failing_gate() {
        let mut cases = Vec::new();
        for phase in Phase::ALL {
            let want = match phase {
                Phase::Following => Ok(()),
                other => Err(other.as_str().to_string()),
            };
            cases.push((
                ReadySnapshot {
                    phase,
                    in_ibd: phase != Phase::Following,
                    ..following()
                },
                want,
            ));
        }
        let unbound = |names: &[&'static str]| ReadySnapshot {
            unbound: names.to_vec(),
            in_ibd: true,
            ..following()
        };
        cases.push((unbound(&["rpc"]), Err("rpc not listening".into())));
        cases.push((
            unbound(&["electrum", "esplora"]),
            Err("electrum, esplora not listening".into()),
        ));
        cases.push((
            ReadySnapshot {
                in_ibd: true,
                headers: 200,
                ..following()
            },
            Err("initial block download".into()),
        ));
        let behind = |n: u32, sh_lag: Option<u32>| ReadySnapshot {
            headers: 100 + n,
            sh_lag,
            ..following()
        };
        cases.push((behind(READY_LAG_BLOCKS, None), Ok(())));
        cases.push((
            behind(READY_LAG_BLOCKS + 1, Some(0)),
            Err(format!(
                "tip {} blocks behind headers",
                READY_LAG_BLOCKS + 1
            )),
        ));
        cases.push((behind(0, Some(READY_LAG_BLOCKS)), Ok(())));
        cases.push((
            behind(0, Some(READY_LAG_BLOCKS + 1)),
            Err(format!(
                "scripthash index {} blocks behind tip",
                READY_LAG_BLOCKS + 1
            )),
        ));
        cases.push((
            ReadySnapshot {
                headers: 90,
                ..following()
            },
            Ok(()),
        ));
        let stale = |age: u64| ReadySnapshot {
            tip_age_secs: Some(age),
            ..following()
        };
        cases.push((stale(24 * 60 * 60), Ok(())));
        cases.push((
            stale(24 * 60 * 60 + 1),
            Err("tip stale (last block 86401s ago)".into()),
        ));
        cases.push((
            ReadySnapshot {
                tip_age_secs: None,
                ..following()
            },
            Ok(()),
        ));
        for (snap, want) in cases {
            assert_eq!(readiness(&snap), want, "{snap:?}");
        }
    }

    /// One listener, one gate. A timed-out `/readyz` keeps its permit, so the
    /// next probe is 503 at once. After that work finishes, `/readyz` and
    /// `/metrics` answer from the node again.
    #[tokio::test(flavor = "multi_thread")]
    async fn health_gate_caps() {
        let health = Health::new(NodeStatus::new(Network::Regtest, false));
        let addr = serve(router_for(health.clone(), true)).await;
        let gate = Arc::clone(&health.readyz);

        let held = Arc::clone(&gate)
            .acquire_many_owned((READYZ_IN_FLIGHT - 1) as u32)
            .await
            .unwrap();
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let dropped = tokio::time::timeout(
            Duration::from_millis(100),
            gated(&gate, move || wait.recv().unwrap()),
        )
        .await;
        assert!(dropped.is_err(), "the request gave up while the work ran");
        assert_eq!(
            gate.available_permits(),
            0,
            "a timed-out request keeps its permit"
        );
        assert_eq!(
            get_soon(addr, "/readyz").await,
            "HTTP/1.1 503 Service Unavailable|not ready: busy\n"
        );

        let scrape_held = Arc::clone(&health.scrape).acquire_owned().await.unwrap();
        assert_eq!(
            get_soon(addr, "/metrics").await,
            "HTTP/1.1 503 Service Unavailable|metrics: a scrape is already running\n"
        );

        release.send(()).unwrap();
        drop(held);
        drop(scrape_held);
        tokio::time::timeout(Duration::from_secs(5), async {
            while gate.available_permits() < READYZ_IN_FLIGHT {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the permit returns when the work ends");
        assert_eq!(
            get_soon(addr, "/readyz").await,
            "HTTP/1.1 503 Service Unavailable|not ready: opening\n"
        );
        let scraped = get_soon(addr, "/metrics").await;
        assert!(
            scraped.starts_with("HTTP/1.1 200 OK|# HELP rbitcoin_build_info"),
            "{scraped}"
        );
    }

    #[test]
    fn progress_body_shapes() {
        assert_eq!(
            progress_body(Phase::Opening, None, None),
            serde_json::json!({ "phase": "opening", "stage": null, "finished": null })
        );
        let p = progress::Snapshot {
            stage: "scripthash keys collect",
            done: 1,
            total: 3,
            base: 0,
            elapsed: Duration::from_secs(60),
            started_at: std::time::SystemTime::UNIX_EPOCH,
        };
        assert_eq!(
            progress_body(Phase::Opening, Some(&p), None),
            serde_json::json!({
                "phase": "opening",
                "stage": "scripthash keys collect",
                "done": 1,
                "total": 3,
                "percent": 33.33,
                "elapsed_secs": 60,
                "eta_secs": 120,
                "finished": null,
            })
        );
        assert_eq!(
            progress_body(Phase::Following, None, Some(&p)),
            serde_json::json!({
                "phase": "following",
                "stage": null,
                "finished": {
                    "stage": "scripthash keys collect",
                    "done": 1,
                    "total": 3,
                    "elapsed_secs": 60,
                },
            })
        );
        let unknown = progress::Snapshot { total: 0, ..p };
        let body = progress_body(Phase::Indexing, Some(&unknown), None);
        assert_eq!(body["percent"], serde_json::Value::Null);
        assert_eq!(body["eta_secs"], serde_json::Value::Null);
    }

    /// A running stage shows on `/progress` and as `/metrics` gauges served by
    /// the health router. `/readyz` keeps its reason text as is.
    #[tokio::test(flavor = "multi_thread")]
    async fn running_stage_is_visible_on_every_route() {
        let addr = serve(router(NodeStatus::new(Network::Regtest, false), true)).await;
        // The registry is process-global and a store test in this binary may
        // start its own stage; retry a few times rather than flake.
        let mut last = String::new();
        for _ in 0..5 {
            let stage = progress::begin("health test stage", 8);
            stage.set_done(2);
            let p = get_soon(addr, "/progress").await;
            let r = get_soon(addr, "/readyz").await;
            let m = get_soon(addr, "/metrics").await;
            drop(stage);
            let ok = p.starts_with("HTTP/1.1 200 OK|")
                && p.contains(r#""stage":"health test stage""#)
                && p.contains(r#""done":2"#)
                && p.contains(r#""total":8"#)
                && p.contains(r#""percent":25.0"#)
                && r == "HTTP/1.1 503 Service Unavailable|not ready: opening\n"
                && m.contains("rbitcoin_progress_done{stage=\"health test stage\"} 2\n")
                && m.contains("rbitcoin_progress_target{stage=\"health test stage\"} 8\n");
            if ok {
                return;
            }
            last = format!("{p}\n---\n{r}\n---\n{m}");
        }
        panic!("stage not visible:\n{last}");
    }

    async fn serve(app: Router) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// [`get`], failing rather than hanging if the answer waits for a permit.
    async fn get_soon(addr: SocketAddr, path: &str) -> String {
        tokio::time::timeout(Duration::from_secs(2), get(addr, path))
            .await
            .expect("answered without queueing")
    }

    async fn get(addr: SocketAddr, path: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        let (head, body) = buf.split_once("\r\n\r\n").unwrap();
        format!("{}|{body}", head.lines().next().unwrap())
    }
}
