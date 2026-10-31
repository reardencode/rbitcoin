//! HTTP JSON-RPC server (axum) with Bearer or opted-in Core cookie auth on TCP.

use crate::auth::{
    parse_basic_auth, parse_bearer_auth, read_cookie_file, resolve_rpc_auth, RpcAuth, RpcCookie,
    RpcCookiePerms,
};
use crate::methods::{RpcContext, RpcRegtest};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequest, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;

/// Authenticated JSON-RPC body cap. Bitcoin Core `MAX_SIZE` (32 MiB).
pub const RPC_MAX_HTTP_BODY: usize = 32 * 1024 * 1024;
/// Unauthenticated REST body cap. REST does not use [`RPC_MAX_HTTP_BODY`].
pub const REST_MAX_HTTP_BODY: usize = 2 * 1024 * 1024;
/// Core `-rpcworkqueue`. Omitted or `0` is this finite queue.
pub const DEFAULT_RPC_WORK_QUEUE: usize = 16;
/// Accept cap, copied from the Electrum public listener. Not a knob.
#[doc(hidden)]
pub const RPC_MAX_CONNECTIONS: usize = 256;
const RPC_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
use rbitcoin_log::info;
#[cfg(unix)]
use rbitcoin_log::warn;
use rbitcoin_net::{BlockingRegion, MempoolHub};
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

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
use tokio::task::JoinHandle;

async fn serve_rpc<L>(mut listener: L, app: Router, sem: Arc<Semaphore>, shutdown: Arc<AtomicBool>)
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    let (shutdown_tx, _) = tokio::sync::watch::channel(());
    let mut shutdown_tick = tokio::time::interval(std::time::Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = shutdown_tick.tick() => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
            }
            (io, addr) = listener.accept() => {
                let Ok(permit) = sem.clone().try_acquire_owned() else {
                    info!("rpc: reject {addr:?} (at max connections={RPC_MAX_CONNECTIONS})");
                    continue;
                };
                let service = TowerToHyperService::new(app.clone());
                let mut shutdown_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    let _permit = permit;
                    let mut http = http1::Builder::new();
                    http.timer(TokioTimer::new()).header_read_timeout(RPC_READ_TIMEOUT);
                    let connection = http.serve_connection(TokioIo::new(io), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {}
                        _ = shutdown_rx.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
}

/// RPC listen configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// TCP bind. `None` = no TCP (unix socket only).
    pub listen: Option<SocketAddr>,
    /// Unix socket path. `None` = no socket.
    pub socket_path: Option<PathBuf>,
    /// Socket mode 0660 (the process group may connect) instead of owner-only 0600.
    pub socket_shared: bool,
    pub datadir: PathBuf,
    pub network: Network,
    /// Override token path (default `{datadir}/rpc.token`).
    pub token_path: Option<PathBuf>,
    /// Optional Core-format `username:password` file accepted as HTTP Basic on TCP.
    pub cookie_path: Option<PathBuf>,
    /// Widest mode `--rpc-cookie-perms` allows for [`Self::cookie_path`].
    pub cookie_perms: RpcCookiePerms,
    /// `getnetworkinfo.subversion`. Empty → `/rbitcoin:VERSION/`.
    pub subversion: Option<String>,
    /// HTTP occupancy cap. `None` and `0` are [`DEFAULT_RPC_WORK_QUEUE`].
    pub work_queue: Option<usize>,
    /// `GET`/`POST /rest/` on this listener. Off unless `--rest` / `rest=`.
    pub rest: bool,
    /// `--alert-notify` (`%s` = warning text).
    pub alert_notify: Option<String>,
    /// `-blocksonly`. Mining and raw-mempool listing stay off.
    pub blocksonly: bool,
    /// See [`crate::methods::RpcContext::package_dialect`].
    pub package_dialect: bool,
}

/// Live RPC server handle.
pub struct RpcHandle {
    pub local_addr: Option<SocketAddr>,
    pub socket_path: Option<PathBuf>,
    pub token_path: PathBuf,
    pub auth: RpcAuth,
    pub stop: Arc<AtomicBool>,
    pub connections: Arc<AtomicU64>,
    pub initial_block_download: Arc<AtomicBool>,
    /// Shared with [`RpcContext::active`] so tip-follow can drain in-flight
    /// handlers before tearing down the RPC server (`feature_shutdown.py`).
    pub active: Arc<std::sync::Mutex<crate::methods::RpcActive>>,
    pub shutdown: Arc<AtomicBool>,
    pub tasks: Vec<JoinHandle<()>>,
}

impl RpcHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for task in self.tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct AppState {
    pub ctx: Arc<RpcContext>,
    pub auth: RpcAuth,
    pub cookie: Option<RpcCookie>,
    pub work_queue: Arc<tokio::sync::Semaphore>,
    /// Separate from [`Self::work_queue`]. REST must not take an RPC slot.
    pub rest_queue: Arc<tokio::sync::Semaphore>,
    pub rest: bool,
    pub require_auth: bool,
}

/// Omitted and `0` are [`DEFAULT_RPC_WORK_QUEUE`]. A positive `N` is `N`.
#[doc(hidden)]
pub fn work_queue_permits(configured: Option<usize>) -> usize {
    match configured {
        Some(n) if n > 0 => n,
        _ => DEFAULT_RPC_WORK_QUEUE,
    }
}

/// Start JSON-RPC on TCP and/or a unix socket (plain HTTP; TLS via reverse proxy).
pub async fn run_rpc(
    config: RpcConfig,
    query: Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
    regtest: Option<Arc<dyn RpcRegtest>>,
    peers: Option<Arc<rbitcoin_net::PeerHub>>,
    chain: Option<Arc<rbitcoin_net::ChainHub>>,
    addrman: Option<Arc<std::sync::Mutex<rbitcoin_net::AddrMan>>>,
) -> Result<RpcHandle, String> {
    if config.listen.is_none() && config.socket_path.is_none() {
        return Err("rpc: need --rpc (socket) or --rpc-listen (TCP)".into());
    }
    if config.cookie_path.is_some() && config.listen.is_none() {
        return Err("rpc: --rpc-cookie-file applies to TCP only; add --rpc-listen".into());
    }
    let (auth, token_path) = resolve_rpc_auth(&config.datadir, config.token_path.as_deref())?;
    if auth.token.is_empty() {
        return Err("RPC token empty".into());
    }
    let cookie = config
        .cookie_path
        .as_deref()
        .map(|path| read_cookie_file(path, config.cookie_perms))
        .transpose()?;

    let stop = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(AtomicU64::new(0));
    let ibd = Arc::new(AtomicBool::new(false));
    let active = Arc::new(std::sync::Mutex::new(crate::methods::RpcActive::default()));
    let ctx = Arc::new(RpcContext {
        query,
        mempool,
        network: config.network,
        start: Instant::now(),
        stop: Arc::clone(&stop),
        connections: Arc::clone(&connections),
        initial_block_download: Arc::clone(&ibd),
        subversion: config.subversion.clone().unwrap_or_else(|| {
            rbitcoin_primitives::rbitcoin_subversion(env!("CARGO_PKG_VERSION"), &[] as &[&str])
                .unwrap_or_else(|_| format!("/rbitcoin:{}/", env!("CARGO_PKG_VERSION")))
        }),
        regtest,
        peers,
        chain,
        addrman,
        logpath: config.datadir.join("debug.log").display().to_string(),
        active: Arc::clone(&active),
        alert_notify: config.alert_notify.clone(),
        alert_fired: Arc::new(AtomicBool::new(false)),
        blocksonly: config.blocksonly,
        package_dialect: config.package_dialect,
    });

    let n = work_queue_permits(config.work_queue);
    let work_queue = Arc::new(tokio::sync::Semaphore::new(n));
    let rest_queue = Arc::new(tokio::sync::Semaphore::new(DEFAULT_RPC_WORK_QUEUE));
    let shutdown = Arc::new(AtomicBool::new(false));
    let accept_sem = Arc::new(Semaphore::new(RPC_MAX_CONNECTIONS));
    let mut tasks = Vec::new();
    let mut local_addr = None;

    // Before the TCP accept task: an error past that point would leave it
    // running with no handle to stop it.
    #[cfg(unix)]
    if let Some(parent) = config
        .socket_path
        .as_deref()
        .and_then(std::path::Path::parent)
    {
        std::fs::create_dir_all(parent).map_err(|e| format!("rpc socket parent: {e}"))?;
    }

    if let Some(addr) = config.listen {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("rpc bind {addr}: {e}"))?;
        let bound = listener
            .local_addr()
            .map_err(|e| format!("rpc local_addr: {e}"))?;
        local_addr = Some(bound);
        let state = AppState {
            ctx: Arc::clone(&ctx),
            auth: auth.clone(),
            cookie: cookie.clone(),
            work_queue: work_queue.clone(),
            rest_queue: rest_queue.clone(),
            rest: config.rest,
            require_auth: true,
        };
        let app = rpc_app(state);
        let shutdown_w = Arc::clone(&shutdown);
        let accept_sem = Arc::clone(&accept_sem);
        tasks.push(tokio::spawn(serve_rpc(
            listener, app, accept_sem, shutdown_w,
        )));
        info!(
            "rpc: HTTP JSON-RPC on {bound} (bearer token {})",
            token_path.display()
        );
    }

    #[cfg(unix)]
    let socket_path_out = if let Some(ref sock) = config.socket_path {
        let _ = std::fs::remove_file(sock);
        let mode = if config.socket_shared { 0o660 } else { 0o600 };
        // A too-long path (`SUN_LEN`) must not drop the TCP listener. Its
        // stop flag lives on the handle; returning Err here leaked the
        // accept task and left the node with no flag to poll.
        let listener = match bind_unix_mode(sock, mode) {
            Ok(listener) => listener,
            Err(e) if local_addr.is_some() => {
                warn!(
                    "rpc unix bind {}: {e} — TCP listener stays up",
                    sock.display()
                );
                return Ok(RpcHandle {
                    local_addr,
                    socket_path: None,
                    token_path,
                    auth,
                    stop,
                    connections,
                    initial_block_download: ibd,
                    active,
                    shutdown,
                    tasks,
                });
            }
            Err(e) => return Err(format!("rpc unix bind {}: {e}", sock.display())),
        };
        let state = AppState {
            ctx: Arc::clone(&ctx),
            auth: auth.clone(),
            cookie,
            work_queue,
            rest_queue,
            rest: config.rest,
            require_auth: false,
        };
        let app = rpc_app(state);
        let shutdown_w = Arc::clone(&shutdown);
        let accept_sem = Arc::clone(&accept_sem);
        tasks.push(tokio::spawn(serve_rpc(
            listener, app, accept_sem, shutdown_w,
        )));
        info!("rpc: unix JSON-RPC on {}", sock.display());
        Some(sock.clone())
    } else {
        None
    };
    #[cfg(not(unix))]
    let socket_path_out = {
        if config.socket_path.is_some() && config.listen.is_none() {
            return Err(
                "rpc unix socket needs AF_UNIX; this Windows build has no tokio UnixListener — use --rpc-listen"
                    .into(),
            );
        }
        if config.socket_path.is_some() {
            info!("rpc: unix socket skipped (no AF_UNIX listener in this build)");
        }
        None
    };
    let _ = ctx;

    Ok(RpcHandle {
        local_addr,
        socket_path: socket_path_out,
        token_path,
        auth,
        stop,
        connections,
        initial_block_download: ibd,
        active,
        shutdown,
        tasks,
    })
}

#[doc(hidden)]
pub fn rpc_app(state: AppState) -> Router {
    Router::new()
        .route(
            "/",
            post(rpc_post).layer(DefaultBodyLimit::max(RPC_MAX_HTTP_BODY)),
        )
        .route(
            "/rest/{*path}",
            get(rest_entry)
                .post(rest_entry)
                .layer(DefaultBodyLimit::max(REST_MAX_HTTP_BODY)),
        )
        .layer(from_fn_with_state(state.clone(), reject_unauthorized))
        .with_state(state)
}

pub async fn rest_entry(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    if !state.rest {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Body first, then the REST queue. A slow client must not hold an RPC slot,
    // and REST does not use the RPC work queue.
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let body = match read_http_body(req).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let _permit = match state.rest_queue.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Work queue depth exceeded\n",
            )
                .into_response();
        }
    };
    let ctx = Arc::clone(&state.ctx);
    let store_permit = state
        .ctx
        .query
        .api_read_budget()
        .acquire_owned()
        .await
        .expect("store budget");
    let reply = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        let _store = store_permit;
        crate::methods::dispatch_rest(&ctx, &path, &query, &body)
    })
    .await
    .unwrap_or_else(|_| crate::methods::RestReply {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        content_type: "text/plain",
        body: b"rest failed\n".to_vec(),
    });
    (
        reply.status,
        [(header::CONTENT_TYPE, reply.content_type)],
        reply.body,
    )
        .into_response()
}

pub async fn reject_unauthorized(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // Core REST is unauthenticated on TCP. POST / requires configured RPC auth.
    if req.uri().path().starts_with("/rest/") {
        return next.run(req).await;
    }
    if state.require_auth && !authorized(&state.auth, state.cookie.as_ref(), req.headers()) {
        // Challenge with the scheme a client can actually use here.
        let challenge = if state.cookie.is_some() {
            "Basic realm=\"jsonrpc\""
        } else {
            "Bearer realm=\"jsonrpc\""
        };
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, challenge)],
            "Unauthorized\n",
        )
            .into_response();
    }
    next.run(req).await
}

/// One HTTP call's long-poll, finished before that call runs.
#[doc(hidden)]
pub struct HttpWaitPrep {
    pub satisfied: bool,
    /// Tip at the end of a `waitfor*` call. Absent for a template long-poll.
    pub snap: Option<(String, u32)>,
}

impl HttpWaitPrep {
    fn skip() -> Self {
        Self {
            satisfied: false,
            snap: None,
        }
    }

    fn gbt() -> Self {
        Self {
            satisfied: true,
            snap: None,
        }
    }

    async fn tip(ctx: &Arc<crate::methods::RpcContext>) -> Self {
        let ctx = Arc::clone(ctx);
        let snap = tokio::task::spawn_blocking(move || crate::methods::tip_hash_height(&ctx).ok())
            .await
            .ok()
            .flatten();
        Self {
            satisfied: true,
            snap,
        }
    }
}

pub async fn satisfy_http_wait(
    ctx: &Arc<crate::methods::RpcContext>,
    parsed: &serde_json::Value,
) -> Vec<bool> {
    // Tests probe which calls waited. Production waits immediately before
    // each call so an earlier method is not stuck behind a later long-poll.
    if let Some(batch) = parsed.as_array() {
        let mut flags = Vec::with_capacity(batch.len());
        for item in batch {
            flags.push(satisfy_one_http_wait(ctx, item).await.satisfied);
        }
        return flags;
    }
    vec![satisfy_one_http_wait(ctx, parsed).await.satisfied]
}

async fn satisfy_one_http_wait(
    ctx: &Arc<crate::methods::RpcContext>,
    parsed: &serde_json::Value,
) -> HttpWaitPrep {
    use crate::methods::mine::{gbt_request, GbtRequest};
    use crate::methods::{tip_hash_height, wait_timeout_ms, RpcParams};
    let Some(method) = parsed.get("method").and_then(|m| m.as_str()) else {
        return HttpWaitPrep::skip();
    };
    if !matches!(
        method,
        "waitforblock" | "waitforblockheight" | "waitfornewblock" | "getblocktemplate"
    ) {
        return HttpWaitPrep::skip();
    }
    let params = match parsed.get("params") {
        Some(v) => RpcParams::from_json(v).unwrap_or_else(RpcParams::empty),
        _ => RpcParams::empty(),
    };
    let mut tips = ctx.chain.as_ref().map(|c| c.subscribe_tips());
    if method == "getblocktemplate" {
        let want = {
            let ctx = Arc::clone(ctx);
            let params = params.clone();
            tokio::task::spawn_blocking(move || match gbt_request(&ctx, &params) {
                Ok(GbtRequest::Template { longpoll, .. }) => longpoll,
                _ => None,
            })
            .await
            .ok()
            .flatten()
        };
        let Some(want) = want else {
            return HttpWaitPrep::skip();
        };
        rbitcoin_log::info!("ThreadRPCServer method=getblocktemplate");
        let _active = crate::methods::ActiveCall::enter(&ctx.active, method);
        let ctx = Arc::clone(ctx);
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(crate::methods::RPC_WAIT_TIMEOUT_MS);
        loop {
            if ctx.stop.load(Ordering::SeqCst) || tokio::time::Instant::now() >= deadline {
                return HttpWaitPrep::gbt();
            }
            let ready = {
                let ctx = Arc::clone(&ctx);
                let want = want.clone();
                tokio::task::spawn_blocking(move || {
                    ctx.stop.load(Ordering::SeqCst) || want.changed(&ctx)
                })
                .await
                .unwrap_or(true)
            };
            if ready || tokio::time::Instant::now() >= deadline {
                return HttpWaitPrep::gbt();
            }
            let slice = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(std::time::Duration::from_millis(50));
            tokio::select! {
                _ = tokio::time::sleep(slice) => {}
                _ = recv_tip(&mut tips) => {}
            }
        }
    }
    let timeout_ms = match method {
        "waitfornewblock" => wait_timeout_ms(&params, 0, "timeout"),
        _ => wait_timeout_ms(&params, 1, "timeout"),
    };
    let Ok(timeout_ms) = timeout_ms else {
        return HttpWaitPrep::skip();
    };
    let kind = match method {
        "waitforblock" => {
            let Ok(want) = params.req_str(0, "blockhash") else {
                return HttpWaitPrep::skip();
            };
            WaitKind::Block(want.to_string())
        }
        "waitforblockheight" => {
            let Ok(h) = params.req_u64(0, "height") else {
                return HttpWaitPrep::skip();
            };
            WaitKind::Height(h as u32)
        }
        "waitfornewblock" => {
            let ctx_b = Arc::clone(ctx);
            let start = tokio::task::spawn_blocking(move || tip_hash_height(&ctx_b).ok())
                .await
                .unwrap_or(None);
            let Some((hash, _)) = start else {
                return HttpWaitPrep::tip(ctx).await;
            };
            WaitKind::New(hash)
        }
        _ => return HttpWaitPrep::skip(),
    };
    let _active = crate::methods::ActiveCall::enter(&ctx.active, method);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let ctx = Arc::clone(ctx);
    loop {
        if ctx.stop.load(Ordering::SeqCst) || tokio::time::Instant::now() >= deadline {
            return HttpWaitPrep::tip(&ctx).await;
        }
        let ready = {
            let ctx = Arc::clone(&ctx);
            let kind = kind.clone();
            tokio::task::spawn_blocking(move || {
                let Ok((hash, height)) = tip_hash_height(&ctx) else {
                    return true;
                };
                match kind {
                    WaitKind::Block(want) => hash == want,
                    WaitKind::Height(want) => height >= want,
                    WaitKind::New(start) => hash != start,
                }
            })
            .await
            .unwrap_or(true)
        };
        if ready || tokio::time::Instant::now() >= deadline {
            return HttpWaitPrep::tip(&ctx).await;
        }
        let slice = deadline.saturating_duration_since(tokio::time::Instant::now());
        let slice = slice.min(std::time::Duration::from_millis(50));
        tokio::select! {
            _ = tokio::time::sleep(slice) => {}
            _ = recv_tip(&mut tips) => {}
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub enum WaitKind {
    Block(String),
    Height(u32),
    New(String),
}

pub async fn recv_tip(tips: &mut Option<tokio::sync::broadcast::Receiver<rbitcoin_net::TipEvent>>) {
    if let Some(rx) = tips.as_mut() {
        let _ = rx.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn read_http_body(req: Request) -> Result<Bytes, Response> {
    match tokio::time::timeout(RPC_READ_TIMEOUT, Bytes::from_request(req, &())).await {
        Ok(body) => body.map_err(IntoResponse::into_response),
        Err(_) => {
            Err((StatusCode::REQUEST_TIMEOUT, [(header::CONNECTION, "close")]).into_response())
        }
    }
}

pub async fn rpc_post(State(state): State<AppState>, req: Request) -> Response {
    let body = match read_http_body(req).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return parse_error_response();
        }
    };
    let ctx = Arc::clone(&state.ctx);
    let budget = state.ctx.query.api_read_budget();
    // A long-poll or a tip connect is ordered per call. The work-queue slot
    // and the disk permit are dropped while that call waits.
    if http_body_awaits_tip(&parsed) || http_body_has_longpoll(&parsed) {
        let out = rbitcoin_net::with_store_budget(
            budget,
            exec_http_rpc_async(ctx, parsed, &state.work_queue),
        )
        .await;
        return match out {
            Err(()) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Work queue depth exceeded\n",
            )
                .into_response(),
            Ok(HttpRpcOut::Json(status, body)) => json_rpc_response(status, body),
            Ok(HttpRpcOut::Empty(status)) => status.into_response(),
        };
    }
    let _permit = match state.work_queue.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Work queue depth exceeded\n",
            )
                .into_response();
        }
    };
    let store_permit = budget.acquire_owned().await.expect("store budget");
    let joined = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        let _store = store_permit;
        exec_http_rpc(&ctx, parsed, &[])
    })
    .await;
    match joined {
        Ok(HttpRpcOut::Json(status, body)) => json_rpc_response(status, body),
        Ok(HttpRpcOut::Empty(status)) => status.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("rpc join: {e}")).into_response(),
    }
}

#[doc(hidden)]
pub fn parse_error_response() -> Response {
    json_rpc_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        reply_v1(
            Some(serde_json::Value::Null),
            None,
            Some(serde_json::json!({ "code": -32700, "message": "Parse error" })),
        ),
    )
}

/// `serde_json` maps sort keys. The wire order is `jsonrpc`, `result`,
/// `error`, `id`, and the body ends with `\n`.
fn json_rpc_response(status: StatusCode, value: serde_json::Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        json_rpc_body(&value),
    )
        .into_response()
}

fn json_rpc_body(value: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_json_rpc_top(&mut out, value);
    out.push(b'\n');
    out
}

fn write_json_rpc_top(out: &mut Vec<u8>, value: &serde_json::Value) {
    if let Some(items) = value.as_array() {
        out.push(b'[');
        for (i, item) in items.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_json_rpc_envelope(out, item);
        }
        out.push(b']');
        return;
    }
    write_json_rpc_envelope(out, value);
}

fn write_json_rpc_envelope(out: &mut Vec<u8>, value: &serde_json::Value) {
    let Some(obj) = value.as_object() else {
        serde_json::to_writer(&mut *out, value).expect("json value");
        return;
    };
    out.push(b'{');
    let mut first = true;
    for key in ["jsonrpc", "result", "error", "id"] {
        if let Some(field) = obj.get(key) {
            write_json_key(out, &mut first, key, field);
        }
    }
    for (key, field) in obj {
        if matches!(key.as_str(), "jsonrpc" | "result" | "error" | "id") {
            continue;
        }
        write_json_key(out, &mut first, key, field);
    }
    out.push(b'}');
}

fn write_json_key(out: &mut Vec<u8>, first: &mut bool, key: &str, value: &serde_json::Value) {
    if !*first {
        out.push(b',');
    }
    *first = false;
    serde_json::to_writer(&mut *out, key).expect("json key");
    out.push(b':');
    serde_json::to_writer(&mut *out, value).expect("json value");
}

#[doc(hidden)]
pub enum HttpRpcOut {
    Json(StatusCode, serde_json::Value),
    Empty(StatusCode),
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum JsonRpcVer {
    V1,
    V2,
}

#[doc(hidden)]
pub fn parse_jsonrpc_ver(req: &serde_json::Value) -> Result<JsonRpcVer, (i64, &'static str)> {
    match req.get("jsonrpc") {
        None => Ok(JsonRpcVer::V1),
        Some(serde_json::Value::String(s)) if s == "1.0" || s == "1.1" => Ok(JsonRpcVer::V1),
        Some(serde_json::Value::String(s)) if s == "2.0" => Ok(JsonRpcVer::V2),
        Some(serde_json::Value::String(_)) => Err((-32600, "JSON-RPC version not supported")),
        Some(_) => Err((-32600, "jsonrpc field must be a string")),
    }
}

#[doc(hidden)]
pub fn reply_v1(
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    if let Some(id) = id {
        o.insert("id".into(), id);
    }
    o.insert("result".into(), result.unwrap_or(serde_json::Value::Null));
    o.insert("error".into(), error.unwrap_or(serde_json::Value::Null));
    serde_json::Value::Object(o)
}

#[doc(hidden)]
pub fn reply_v2(
    id: serde_json::Value,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("jsonrpc".into(), serde_json::json!("2.0"));
    o.insert("id".into(), id);
    if let Some(e) = error {
        o.insert("error".into(), e);
    } else {
        o.insert("result".into(), result.unwrap_or(serde_json::Value::Null));
    }
    serde_json::Value::Object(o)
}

#[doc(hidden)]
pub fn v1_http_status(error: &serde_json::Value) -> StatusCode {
    match error.get("code").and_then(|c| c.as_i64()) {
        Some(-32600) => StatusCode::BAD_REQUEST,
        Some(-32601) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn http_body_awaits_tip(parsed: &serde_json::Value) -> bool {
    let method_awaits = |req: &serde_json::Value| {
        req.get("method")
            .and_then(|m| m.as_str())
            .is_some_and(crate::methods::request_task_method)
    };
    if let Some(arr) = parsed.as_array() {
        arr.iter().any(method_awaits)
    } else {
        method_awaits(parsed)
    }
}

fn http_call_is_longpoll(req: &serde_json::Value) -> bool {
    matches!(
        req.get("method").and_then(|m| m.as_str()),
        Some("waitforblock" | "waitforblockheight" | "waitfornewblock" | "getblocktemplate")
    )
}

fn http_body_has_longpoll(parsed: &serde_json::Value) -> bool {
    if let Some(arr) = parsed.as_array() {
        arr.iter().any(http_call_is_longpoll)
    } else {
        http_call_is_longpoll(parsed)
    }
}

fn work_queue_exceeded_reply(req: &serde_json::Value) -> Option<serde_json::Value> {
    let ver = parse_jsonrpc_ver(req).unwrap_or(JsonRpcVer::V1);
    let has_id = req.as_object().is_some_and(|m| m.contains_key("id"));
    if ver == JsonRpcVer::V2 && !has_id {
        return None;
    }
    let err = serde_json::json!({
        "code": -32603,
        "message": "Work queue depth exceeded",
    });
    let id = req.get("id").cloned();
    Some(match ver {
        JsonRpcVer::V2 => reply_v2(id.unwrap_or(serde_json::Value::Null), None, Some(err)),
        JsonRpcVer::V1 => reply_v1(id, None, Some(err)),
    })
}

async fn prepare_ordered_call(
    ctx: &Arc<RpcContext>,
    req: &serde_json::Value,
    hold: &mut Option<tokio::sync::OwnedSemaphorePermit>,
    work_queue: &Arc<tokio::sync::Semaphore>,
) -> Result<HttpWaitPrep, ()> {
    let prep = if http_call_is_longpoll(req) {
        // A later wait must not keep the slot taken by an earlier call.
        drop(hold.take());
        satisfy_one_http_wait(ctx, req).await
    } else {
        HttpWaitPrep::skip()
    };
    if hold.is_none() {
        *hold = Some(Arc::clone(work_queue).try_acquire_owned().map_err(|_| ())?);
    }
    Ok(prep)
}

async fn exec_http_rpc_async(
    ctx: Arc<RpcContext>,
    parsed: serde_json::Value,
    work_queue: &Arc<tokio::sync::Semaphore>,
) -> Result<HttpRpcOut, ()> {
    if let Some(arr) = parsed.as_array() {
        let mut hold = None;
        let mut out = Vec::new();
        let mut ran = false;
        for (i, req) in arr.iter().enumerate() {
            let prep = match prepare_ordered_call(&ctx, req, &mut hold, work_queue).await {
                Ok(prep) => prep,
                Err(()) if !ran => return Err(()),
                Err(()) => {
                    for rest in &arr[i..] {
                        if let Some(body) = work_queue_exceeded_reply(rest) {
                            out.push(body);
                        }
                    }
                    if out.is_empty() {
                        return Ok(HttpRpcOut::Empty(StatusCode::NO_CONTENT));
                    }
                    return Ok(HttpRpcOut::Json(
                        StatusCode::OK,
                        serde_json::Value::Array(out),
                    ));
                }
            };
            match exec_one_async(&ctx, req, prep.satisfied, prep.snap).await {
                OneOut::Reply(body) => out.push(body),
                OneOut::Notification => {}
                OneOut::BadVersion { error } => {
                    out.push(reply_v1(
                        Some(req.get("id").cloned().unwrap_or(serde_json::Value::Null)),
                        None,
                        Some(error),
                    ));
                }
            }
            ran = true;
        }
        if out.is_empty() && !arr.is_empty() {
            return Ok(HttpRpcOut::Empty(StatusCode::NO_CONTENT));
        }
        return Ok(HttpRpcOut::Json(
            StatusCode::OK,
            serde_json::Value::Array(out),
        ));
    }
    if parsed.is_object() {
        let mut hold = None;
        let prep = prepare_ordered_call(&ctx, &parsed, &mut hold, work_queue).await?;
        return Ok(
            match exec_one_async(&ctx, &parsed, prep.satisfied, prep.snap).await {
                OneOut::Reply(body) => {
                    let ver = parse_jsonrpc_ver(&parsed).unwrap_or(JsonRpcVer::V1);
                    let status = if ver == JsonRpcVer::V2 {
                        StatusCode::OK
                    } else if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
                        v1_http_status(err)
                    } else {
                        StatusCode::OK
                    };
                    HttpRpcOut::Json(status, body)
                }
                OneOut::Notification => HttpRpcOut::Empty(StatusCode::NO_CONTENT),
                OneOut::BadVersion { error } => HttpRpcOut::Json(
                    StatusCode::BAD_REQUEST,
                    reply_v1(parsed.get("id").cloned(), None, Some(error)),
                ),
            },
        );
    }
    Ok(HttpRpcOut::Json(
        StatusCode::INTERNAL_SERVER_ERROR,
        reply_v1(
            Some(serde_json::Value::Null),
            None,
            Some(serde_json::json!({ "code": -32700, "message": "Parse error" })),
        ),
    ))
}

async fn exec_one_async(
    ctx: &Arc<RpcContext>,
    req: &serde_json::Value,
    waited: bool,
    snap: Option<(String, u32)>,
) -> OneOut {
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if !crate::methods::request_task_method(method) {
        let id = req.get("id").cloned();
        let req = req.clone();
        let ctx = Arc::clone(ctx);
        let store_permit = rbitcoin_net::acquire_armed_store_budget().await;
        return match tokio::task::spawn_blocking(move || {
            let _g = BlockingRegion::enter();
            let _store = store_permit;
            if waited {
                crate::methods::set_http_wait_satisfied(true);
                crate::methods::set_http_wait_snap(snap);
            }
            let out = exec_one(&ctx, &req);
            crate::methods::set_http_wait_satisfied(false);
            crate::methods::set_http_wait_snap(None);
            out
        })
        .await
        {
            Ok(out) => out,
            Err(e) => OneOut::Reply(reply_v1(
                id,
                None,
                Some(serde_json::json!({ "code": -1, "message": format!("rpc join: {e}") })),
            )),
        };
    }
    let ver = match parse_jsonrpc_ver(req) {
        Ok(v) => v,
        Err((code, msg)) => {
            return OneOut::BadVersion {
                error: serde_json::json!({ "code": code, "message": msg }),
            };
        }
    };
    let has_id = req.as_object().is_some_and(|m| m.contains_key("id"));
    let notification = ver == JsonRpcVer::V2 && !has_id;
    let id = if has_id {
        Some(req.get("id").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        None
    };
    let params = match req.get("params") {
        None | Some(serde_json::Value::Null) => crate::methods::RpcParams::empty(),
        Some(v) => match crate::methods::RpcParams::from_json(v) {
            Some(p) => p,
            None => {
                let err = serde_json::json!({
                    "code": -32602,
                    "message": "params must be array or object",
                });
                if notification {
                    return OneOut::Notification;
                }
                return OneOut::Reply(match ver {
                    JsonRpcVer::V2 => {
                        reply_v2(id.unwrap_or(serde_json::Value::Null), None, Some(err))
                    }
                    JsonRpcVer::V1 => reply_v1(id, None, Some(err)),
                });
            }
        },
    };
    let params_s = req
        .get("params")
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "[]".into()))
        .unwrap_or_else(|| "[]".into());
    let t0 = Instant::now();
    let dispatched = crate::methods::dispatch_tip_connect(ctx, method, params).await;
    let wall_ms = t0.elapsed().as_millis() as u64;
    let err_s = match &dispatched {
        Err(e) => e
            .get("message")
            .and_then(|m| m.as_str())
            .map(str::to_string),
        Ok(_) => None,
    };
    rbitcoin_log::api_call("rpc", "-", method, &params_s, wall_ms, err_s.as_deref());
    if notification {
        return OneOut::Notification;
    }
    let id_v1 = id.clone();
    let id_v2 = id.unwrap_or(serde_json::Value::Null);
    OneOut::Reply(match dispatched {
        Ok(result) => match ver {
            JsonRpcVer::V2 => reply_v2(id_v2, Some(result), None),
            JsonRpcVer::V1 => reply_v1(id_v1, Some(result), None),
        },
        Err(error) => match ver {
            JsonRpcVer::V2 => reply_v2(id_v2, None, Some(error)),
            JsonRpcVer::V1 => reply_v1(id_v1, None, Some(error)),
        },
    })
}

#[doc(hidden)]
pub fn exec_http_rpc(ctx: &RpcContext, parsed: serde_json::Value, waited: &[bool]) -> HttpRpcOut {
    if let Some(arr) = parsed.as_array() {
        let mut out = Vec::new();
        for (i, req) in arr.iter().enumerate() {
            let slot = waited.get(i).copied().unwrap_or(false);
            if slot {
                crate::methods::set_http_wait_satisfied(true);
            }
            let one = exec_one(ctx, req);
            if slot {
                crate::methods::set_http_wait_satisfied(false);
            }
            match one {
                OneOut::Reply(body) => out.push(body),
                OneOut::Notification => {}
                OneOut::BadVersion { error } => {
                    out.push(reply_v1(
                        Some(req.get("id").cloned().unwrap_or(serde_json::Value::Null)),
                        None,
                        Some(error),
                    ));
                }
            }
        }
        if out.is_empty() && !arr.is_empty() {
            return HttpRpcOut::Empty(StatusCode::NO_CONTENT);
        }
        return HttpRpcOut::Json(StatusCode::OK, serde_json::Value::Array(out));
    }
    if parsed.is_object() {
        let slot = waited.first().copied().unwrap_or(false);
        if slot {
            crate::methods::set_http_wait_satisfied(true);
        }
        let one = exec_one(ctx, &parsed);
        if slot {
            crate::methods::set_http_wait_satisfied(false);
        }
        return match one {
            OneOut::Reply(body) => {
                let ver = parse_jsonrpc_ver(&parsed).unwrap_or(JsonRpcVer::V1);
                let status = if ver == JsonRpcVer::V2 {
                    StatusCode::OK
                } else if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
                    v1_http_status(err)
                } else {
                    StatusCode::OK
                };
                HttpRpcOut::Json(status, body)
            }
            OneOut::Notification => HttpRpcOut::Empty(StatusCode::NO_CONTENT),
            OneOut::BadVersion { error } => HttpRpcOut::Json(
                StatusCode::BAD_REQUEST,
                reply_v1(parsed.get("id").cloned(), None, Some(error)),
            ),
        };
    }
    HttpRpcOut::Json(
        StatusCode::INTERNAL_SERVER_ERROR,
        reply_v1(
            Some(serde_json::Value::Null),
            None,
            Some(serde_json::json!({ "code": -32700, "message": "Parse error" })),
        ),
    )
}

#[doc(hidden)]
pub enum OneOut {
    Reply(serde_json::Value),
    Notification,
    BadVersion { error: serde_json::Value },
}

#[doc(hidden)]
pub fn exec_one(ctx: &RpcContext, req: &serde_json::Value) -> OneOut {
    let ver = match parse_jsonrpc_ver(req) {
        Ok(v) => v,
        Err((code, msg)) => {
            return OneOut::BadVersion {
                error: serde_json::json!({ "code": code, "message": msg }),
            };
        }
    };
    let has_id = req.as_object().is_some_and(|m| m.contains_key("id"));
    let notification = ver == JsonRpcVer::V2 && !has_id;
    let id = if has_id {
        Some(req.get("id").cloned().unwrap_or(serde_json::Value::Null))
    } else {
        None
    };
    let method = match req.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            let err = serde_json::json!({ "code": -32600, "message": "Missing method" });
            if notification {
                return OneOut::Notification;
            }
            return OneOut::Reply(match ver {
                JsonRpcVer::V2 => reply_v2(id.unwrap_or(serde_json::Value::Null), None, Some(err)),
                JsonRpcVer::V1 => reply_v1(id, None, Some(err)),
            });
        }
    };
    let params = match req.get("params") {
        None | Some(serde_json::Value::Null) => crate::methods::RpcParams::empty(),
        Some(v) => match crate::methods::RpcParams::from_json(v) {
            Some(p) => p,
            None => {
                let err = serde_json::json!({
                    "code": -32602,
                    "message": "params must be array or object",
                });
                if notification {
                    return OneOut::Notification;
                }
                return OneOut::Reply(match ver {
                    JsonRpcVer::V2 => {
                        reply_v2(id.unwrap_or(serde_json::Value::Null), None, Some(err))
                    }
                    JsonRpcVer::V1 => reply_v1(id, None, Some(err)),
                });
            }
        },
    };
    if method == "getblocktemplate" && !crate::methods::http_wait_satisfied() {
        rbitcoin_log::info!("ThreadRPCServer method=getblocktemplate");
    }
    let params_s = req
        .get("params")
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "[]".into()))
        .unwrap_or_else(|| "[]".into());
    let t0 = Instant::now();
    let dispatched = handle_request_dispatch(ctx, method, params);
    let wall_ms = t0.elapsed().as_millis() as u64;
    let err_s = match &dispatched {
        Err(e) => e
            .get("message")
            .and_then(|m| m.as_str())
            .map(|s| s.to_string()),
        Ok(_) => None,
    };
    rbitcoin_log::api_call("rpc", "-", method, &params_s, wall_ms, err_s.as_deref());
    if notification {
        return OneOut::Notification;
    }
    let id_v1 = id.clone();
    let id_v2 = id.clone().unwrap_or(serde_json::Value::Null);
    OneOut::Reply(match dispatched {
        Ok(result) => match ver {
            JsonRpcVer::V2 => reply_v2(id_v2.clone(), Some(result), None),
            JsonRpcVer::V1 => reply_v1(id_v1.clone(), Some(result), None),
        },
        Err(error) => match ver {
            JsonRpcVer::V2 => reply_v2(id_v2, None, Some(error)),
            JsonRpcVer::V1 => reply_v1(id_v1, None, Some(error)),
        },
    })
}

#[doc(hidden)]
pub fn handle_request_dispatch(
    ctx: &RpcContext,
    method: &str,
    params: crate::methods::RpcParams,
) -> Result<serde_json::Value, serde_json::Value> {
    crate::methods::dispatch(ctx, method, params)
}

#[doc(hidden)]
pub fn authorized(auth: &RpcAuth, cookie: Option<&RpcCookie>, headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    if let Some(token) = parse_bearer_auth(value) {
        return auth.matches_token(token);
    }
    let Some(cookie) = cookie else {
        return false;
    };
    parse_basic_auth(value).is_some_and(|credentials| cookie.matches_credentials(&credentials))
}
