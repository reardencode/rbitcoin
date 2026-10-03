//! HTTP JSON-RPC server (axum) with Bearer or opted-in Core cookie auth on TCP.

use crate::auth::{
    parse_basic_auth, parse_bearer_auth, read_cookie_file, resolve_rpc_auth, RpcAuth, RpcCookie,
};
use crate::methods::{RpcContext, RpcRegtest};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Axum's default request-body cap, named so auth and 413 share one limit.
pub const RPC_MAX_HTTP_BODY: usize = 2 * 1024 * 1024;
/// Core `-rpcworkqueue`. Omitted or `0` is this finite queue.
pub const DEFAULT_RPC_WORK_QUEUE: usize = 16;
/// Accept cap, copied from the Electrum public listener. Not a knob.
const RPC_MAX_CONNECTIONS: usize = 256;
use rbitcoin_log::info;
use rbitcoin_net::{BlockingRegion, MempoolHub};
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

#[cfg(unix)]
fn bind_unix_mode(path: &std::path::Path, mode: u32) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}
use tokio::task::JoinHandle;

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
    /// `getnetworkinfo.subversion`. Empty → `/rbitcoin:VERSION/`.
    pub subversion: Option<String>,
    /// HTTP occupancy cap. `None` and `0` are [`DEFAULT_RPC_WORK_QUEUE`].
    pub work_queue: Option<usize>,
    /// `GET`/`POST /rest/` on this listener. Off unless `--rest` / `rest=`.
    pub rest: bool,
    /// `--alert-notify` (`%s` = warning text).
    pub alert_notify: Option<String>,
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
    shutdown: Arc<AtomicBool>,
    tasks: Vec<JoinHandle<()>>,
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
struct AppState {
    ctx: Arc<RpcContext>,
    auth: RpcAuth,
    cookie: Option<RpcCookie>,
    work_queue: Arc<tokio::sync::Semaphore>,
    /// Separate from [`Self::work_queue`]. REST must not take an RPC slot.
    rest_queue: Arc<tokio::sync::Semaphore>,
    rest: bool,
    require_auth: bool,
}

/// Omitted and `0` are [`DEFAULT_RPC_WORK_QUEUE`]. A positive `N` is `N`.
fn work_queue_permits(configured: Option<usize>) -> usize {
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
        .map(read_cookie_file)
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
    });

    let n = work_queue_permits(config.work_queue);
    let work_queue = Arc::new(tokio::sync::Semaphore::new(n));
    let rest_queue = Arc::new(tokio::sync::Semaphore::new(DEFAULT_RPC_WORK_QUEUE));
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    let mut local_addr = None;

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
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    while !shutdown_w.load(Ordering::SeqCst) {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                })
                .await
                .ok();
        }));
        info!(
            "rpc: HTTP JSON-RPC on {bound} (bearer token {})",
            token_path.display()
        );
    }

    #[cfg(unix)]
    let socket_path_out = if let Some(ref sock) = config.socket_path {
        if let Some(parent) = sock.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("rpc socket parent: {e}"))?;
        }
        let _ = std::fs::remove_file(sock);
        let mode = if config.socket_shared { 0o660 } else { 0o600 };
        let listener = bind_unix_mode(sock, mode)
            .map_err(|e| format!("rpc unix bind {}: {e}", sock.display()))?;
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
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    while !shutdown_w.load(Ordering::SeqCst) {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                })
                .await
                .ok();
        }));
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

fn rpc_app(state: AppState) -> Router {
    Router::new()
        .route("/", post(rpc_post))
        .route("/rest/{*path}", get(rest_entry).post(rest_entry))
        .layer(DefaultBodyLimit::max(RPC_MAX_HTTP_BODY))
        .layer(from_fn_with_state(state.clone(), reject_unauthorized))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_millis(crate::methods::RPC_WAIT_TIMEOUT_MS),
        ))
        .layer(ConcurrencyLimitLayer::new(RPC_MAX_CONNECTIONS))
        .with_state(state)
}

async fn rest_entry(State(state): State<AppState>, req: axum::extract::Request) -> Response {
    if !state.rest {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Body first, then the REST queue. A slow client must not hold an RPC slot,
    // and REST does not use the RPC work queue.
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let body = axum::body::to_bytes(req.into_body(), RPC_MAX_HTTP_BODY)
        .await
        .unwrap_or_default();
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
    let reply = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
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

async fn reject_unauthorized(
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

async fn satisfy_http_wait(
    ctx: &Arc<crate::methods::RpcContext>,
    parsed: &serde_json::Value,
) -> bool {
    use crate::methods::{gbt_longpoll_id, tip_hash_height, wait_timeout_ms, RpcParams};
    let Some(method) = parsed.get("method").and_then(|m| m.as_str()) else {
        return false;
    };
    if !matches!(
        method,
        "waitforblock" | "waitforblockheight" | "waitfornewblock" | "getblocktemplate"
    ) {
        return false;
    }
    let params = match parsed.get("params") {
        Some(serde_json::Value::Array(a)) => RpcParams::positional(a.clone()),
        Some(serde_json::Value::Object(m)) => RpcParams::named(m.clone()),
        _ => RpcParams::empty(),
    };
    let mut tips = ctx.chain.as_ref().map(|c| c.subscribe_tips());
    if method == "getblocktemplate" {
        let Some(want) = params
            .get(0, "template_request")
            .and_then(serde_json::Value::as_object)
            .and_then(|o| o.get("longpollid"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            return false;
        };
        rbitcoin_log::info!("ThreadRPCServer method=getblocktemplate");
        let _active = crate::methods::ActiveCall::enter(&ctx.active, method);
        let ctx = Arc::clone(ctx);
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis(crate::methods::RPC_WAIT_TIMEOUT_MS);
        loop {
            if ctx.stop.load(Ordering::SeqCst) || tokio::time::Instant::now() >= deadline {
                return true;
            }
            let ready = {
                let ctx = Arc::clone(&ctx);
                let want = want.clone();
                tokio::task::spawn_blocking(move || {
                    ctx.stop.load(Ordering::SeqCst) || gbt_longpoll_id(&ctx) != want
                })
                .await
                .unwrap_or(true)
            };
            if ready || tokio::time::Instant::now() >= deadline {
                return true;
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
        return false;
    };
    let kind = match method {
        "waitforblock" => {
            let Ok(want) = params.req_str(0, "blockhash") else {
                return false;
            };
            WaitKind::Block(want.to_string())
        }
        "waitforblockheight" => {
            let Ok(h) = params.req_u64(0, "height") else {
                return false;
            };
            WaitKind::Height(h as u32)
        }
        "waitfornewblock" => {
            let ctx_b = Arc::clone(ctx);
            let start = tokio::task::spawn_blocking(move || tip_hash_height(&ctx_b).ok())
                .await
                .unwrap_or(None);
            let Some((hash, _)) = start else {
                return true;
            };
            WaitKind::New(hash)
        }
        _ => return false,
    };
    let _active = crate::methods::ActiveCall::enter(&ctx.active, method);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let ctx = Arc::clone(ctx);
    loop {
        if ctx.stop.load(Ordering::SeqCst) || tokio::time::Instant::now() >= deadline {
            return true;
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
            return true;
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
enum WaitKind {
    Block(String),
    Height(u32),
    New(String),
}

async fn recv_tip(tips: &mut Option<tokio::sync::broadcast::Receiver<rbitcoin_net::TipEvent>>) {
    if let Some(rx) = tips.as_mut() {
        let _ = rx.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn rpc_post(State(state): State<AppState>, body: Bytes) -> Response {
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return parse_error_response();
        }
    };
    let ctx = Arc::clone(&state.ctx);
    // The long-poll must not sit on the only work-queue slot.
    let waited = satisfy_http_wait(&ctx, &parsed).await;
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
    let joined = tokio::task::spawn_blocking(move || {
        let _g = BlockingRegion::enter();
        if waited {
            crate::methods::set_http_wait_satisfied(true);
        }
        let out = exec_http_rpc(&ctx, parsed);
        crate::methods::set_http_wait_satisfied(false);
        out
    })
    .await;
    match joined {
        Ok(HttpRpcOut::Json(status, body)) => (status, axum::Json(body)).into_response(),
        Ok(HttpRpcOut::Empty(status)) => status.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("rpc join: {e}")).into_response(),
    }
}

fn parse_error_response() -> Response {
    let err = serde_json::json!({
        "id": null,
        "result": null,
        "error": { "code": -32700, "message": "Parse error" },
    });
    (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(err)).into_response()
}

enum HttpRpcOut {
    Json(StatusCode, serde_json::Value),
    Empty(StatusCode),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonRpcVer {
    V1,
    V2,
}

fn parse_jsonrpc_ver(req: &serde_json::Value) -> Result<JsonRpcVer, (i64, &'static str)> {
    match req.get("jsonrpc") {
        None => Ok(JsonRpcVer::V1),
        Some(serde_json::Value::String(s)) if s == "1.0" || s == "1.1" => Ok(JsonRpcVer::V1),
        Some(serde_json::Value::String(s)) if s == "2.0" => Ok(JsonRpcVer::V2),
        Some(serde_json::Value::String(_)) => Err((-32600, "JSON-RPC version not supported")),
        Some(_) => Err((-32600, "jsonrpc field must be a string")),
    }
}

fn reply_v1(
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

fn reply_v2(
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

fn v1_http_status(error: &serde_json::Value) -> StatusCode {
    match error.get("code").and_then(|c| c.as_i64()) {
        Some(-32600) => StatusCode::BAD_REQUEST,
        Some(-32601) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn exec_http_rpc(ctx: &RpcContext, parsed: serde_json::Value) -> HttpRpcOut {
    if let Some(arr) = parsed.as_array() {
        let mut out = Vec::new();
        for req in arr {
            match exec_one(ctx, req) {
                OneOut::Reply(body) => out.push(body),
                OneOut::Notification => {}
                OneOut::BadVersion { error } => {
                    out.push(serde_json::json!({
                        "id": req.get("id").cloned().unwrap_or(serde_json::Value::Null),
                        "result": null,
                        "error": error,
                    }));
                }
            }
        }
        if out.is_empty() && !arr.is_empty() {
            return HttpRpcOut::Empty(StatusCode::NO_CONTENT);
        }
        return HttpRpcOut::Json(StatusCode::OK, serde_json::Value::Array(out));
    }
    if parsed.is_object() {
        return match exec_one(ctx, &parsed) {
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
                serde_json::json!({
                    "result": null,
                    "error": error,
                }),
            ),
        };
    }
    HttpRpcOut::Json(
        StatusCode::INTERNAL_SERVER_ERROR,
        serde_json::json!({
            "id": null,
            "result": null,
            "error": { "code": -32700, "message": "Parse error" },
        }),
    )
}

enum OneOut {
    Reply(serde_json::Value),
    Notification,
    BadVersion { error: serde_json::Value },
}

fn exec_one(ctx: &RpcContext, req: &serde_json::Value) -> OneOut {
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
        Some(serde_json::Value::Array(a)) => crate::methods::RpcParams::positional(a.clone()),
        Some(serde_json::Value::Object(m)) => crate::methods::RpcParams::named(m.clone()),
        Some(_) => {
            let err = serde_json::json!({
                "code": -32602,
                "message": "params must be array or object",
            });
            if notification {
                return OneOut::Notification;
            }
            return OneOut::Reply(match ver {
                JsonRpcVer::V2 => reply_v2(id.unwrap_or(serde_json::Value::Null), None, Some(err)),
                JsonRpcVer::V1 => reply_v1(id, None, Some(err)),
            });
        }
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

fn handle_request_dispatch(
    ctx: &RpcContext,
    method: &str,
    params: crate::methods::RpcParams,
) -> Result<serde_json::Value, serde_json::Value> {
    crate::methods::dispatch(ctx, method, params)
}

fn authorized(auth: &RpcAuth, cookie: Option<&RpcCookie>, headers: &HeaderMap) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::Network;

    #[test]
    fn work_queue_zero_and_omitted_are_the_default() {
        assert_eq!(work_queue_permits(None), DEFAULT_RPC_WORK_QUEUE);
        assert_eq!(work_queue_permits(Some(0)), DEFAULT_RPC_WORK_QUEUE);
        assert_eq!(work_queue_permits(Some(4)), 4);
    }

    fn auth_header(auth: &RpcAuth) -> String {
        format!("Bearer {}", auth.token)
    }

    fn tcp_addr(handle: &RpcHandle) -> SocketAddr {
        handle.local_addr.expect("tcp listen")
    }

    async fn post_rpc(
        addr: SocketAddr,
        auth: &RpcAuth,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "test",
            "method": method,
            "params": params,
        });
        let body_s = body.to_string();
        let auth_h = auth_header(auth);
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth_h}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_s}",
            body_s.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read: {e}"))?;
        let text = String::from_utf8_lossy(&buf);
        let body_start = text.find("\r\n\r\n").ok_or("no HTTP body")? + 4;
        let json_body = &text[body_start..];
        serde_json::from_str(json_body).map_err(|e| format!("json: {e} body={json_body}"))
    }

    #[tokio::test]
    async fn rpc_smoke_getblockcount_and_help() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-srv").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        mp.set_relay_enabled(true);
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: true,

            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let count = post_rpc(
            tcp_addr(&handle),
            &handle.auth,
            "getblockcount",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(count["error"].is_null(), "{count}");
        assert_eq!(count["result"], 0);

        let help = post_rpc(
            tcp_addr(&handle),
            &handle.auth,
            "help",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(help["error"].is_null(), "{help}");
        let s = help["result"].as_str().unwrap();
        assert!(s.contains("getblockchaininfo"));

        let mem = post_rpc(
            tcp_addr(&handle),
            &handle.auth,
            "getmempoolinfo",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(mem["error"].is_null(), "{mem}");
        assert_eq!(mem["result"]["size"], 0);

        let chain = post_rpc(
            tcp_addr(&handle),
            &handle.auth,
            "getblockchaininfo",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(chain["error"].is_null(), "{chain}");
        assert_eq!(chain["result"]["chain"], "regtest");

        // 401 without auth
        let mut stream = tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bad = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        stream.write_all(bad).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("401") || text.contains("Unauthorized"),
            "{text}"
        );

        let mut rest = tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap();
        let get = b"GET /rest/chaininfo.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        rest.write_all(get).await.unwrap();
        let mut rest_buf = Vec::new();
        rest.read_to_end(&mut rest_buf).await.unwrap();
        let rest_text = String::from_utf8_lossy(&rest_buf);
        assert!(
            rest_text.contains("200") && rest_text.contains("regtest"),
            "{rest_text}"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rest_is_404_without_the_flag() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-rest-off").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut rest = tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap();
        let get = b"GET /rest/chaininfo.json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        rest.write_all(get).await.unwrap();
        let mut buf = Vec::new();
        rest.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("404"), "REST is off unless --rest: {text}");
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn post_raw(
        addr: SocketAddr,
        auth: &RpcAuth,
        body: &[u8],
    ) -> (u16, Option<serde_json::Value>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let auth_h = auth_header(auth);
        let req = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth_h}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
        let json_body = text[body_start..].trim();
        let parsed = if json_body.is_empty() {
            None
        } else {
            Some(serde_json::from_str(json_body).unwrap_or(serde_json::json!(json_body)))
        };
        (status, parsed)
    }

    #[tokio::test]
    async fn jsonrpc_v2_batch_and_http_codes() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-v2").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        mp.set_relay_enabled(true);
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,

            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;

        let batch = serde_json::json!([
            {"jsonrpc":"2.0","id":1,"method":"getblockcount"},
            {"jsonrpc":"2.0","id":2,"method":"invalidmethod"},
            {"jsonrpc":"2.0","id":4,"pizza":"sausage"}
        ]);
        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            batch.to_string().as_bytes(),
        )
        .await;
        assert_eq!(st, 200, "{body:?}");
        let arr = body.unwrap();
        assert_eq!(arr[0]["jsonrpc"], "2.0");
        assert_eq!(arr[0]["result"], 0);
        assert!(arr[0].get("error").is_none());
        assert_eq!(arr[1]["error"]["code"], -32601);
        assert_eq!(arr[1]["error"]["message"], "Method not found");
        assert_eq!(arr[2]["error"]["message"], "Missing method");

        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":"2.0","method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 204, "{body:?}");
        assert!(body.is_none());

        let (st, body) = post_raw(tcp_addr(&handle), &handle.auth, b"").await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["message"], "Parse error");

        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":2,"method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 400);
        assert_eq!(
            body.unwrap()["error"]["message"],
            "jsonrpc field must be a string"
        );

        let (st, _) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":"1.1","id":1,"method":"invalidmethod"}"#,
        )
        .await;
        assert_eq!(st, 404);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unauthorized_large_content_length_is_401_before_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-auth-body").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let mut stream = tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap();
        let headers =
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 8000000\r\nConnection: close\r\n\r\n";
        stream.write_all(headers).await.unwrap();
        let mut buf = vec![0u8; 512];
        let n = timeout(Duration::from_millis(400), stream.read(&mut buf))
            .await
            .expect("401 before any body bytes")
            .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            text.contains("401") || text.contains("Unauthorized"),
            "{text}"
        );
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn oversized_bearer_body_is_413_and_small_body_still_runs() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-body-cap").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 200, "{body:?}");
        assert_eq!(body.unwrap()["result"], 0);

        let mut payload = br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#.to_vec();
        payload.resize(RPC_MAX_HTTP_BODY + 1, b' ');
        let mut stream = tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap();
        let headers = format!(
            "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            handle.auth.token,
            payload.len()
        );
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        let mut buf = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut buf))
            .await
            .expect("413 for a body over RPC_MAX_HTTP_BODY")
            .unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("413"), "{text}");
        assert!(
            !text.contains("\"result\""),
            "oversized getblockcount must not run: {text}"
        );
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rpc_max_http_body_is_two_mebibytes() {
        assert_eq!(RPC_MAX_HTTP_BODY, 2_097_152);
    }

    #[tokio::test]
    async fn waitforblock_positional_hash_returns_current_tip() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-wait-pos").expect("dir");
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        let hub = rbitcoin_net::ChainHub::new(
            q,
            rbitcoin_consensus::ChainParams::regtest(),
            rbitcoin_consensus::Milestone::NONE,
        );
        hub.ensure_genesis().unwrap();
        let query = Arc::clone(&hub.query);
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getbestblockhash"}"#,
        )
        .await;
        assert_eq!(st, 200, "{body:?}");
        let hash = body.unwrap()["result"].as_str().expect("hash").to_string();
        let req = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 2,
            "method": "waitforblock",
            "params": [hash]
        });
        let t0 = std::time::Instant::now();
        let (st, body) =
            post_raw(tcp_addr(&handle), &handle.auth, req.to_string().as_bytes()).await;
        assert_eq!(st, 200, "{body:?}");
        let body = body.expect("json");
        assert!(
            body.get("error").is_none() || body["error"].is_null(),
            "{body}"
        );
        assert_eq!(body["result"]["hash"], hash, "{body}");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(1),
            "positional waitforblock slept {:?}",
            t0.elapsed()
        );
        let named = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 3,
            "method": "waitfornewblock",
            "params": [0]
        });
        let t1 = std::time::Instant::now();
        let (st, body) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            post_raw(
                tcp_addr(&handle),
                &handle.auth,
                named.to_string().as_bytes(),
            ),
        )
        .await
        .expect("waitfornewblock timeout 0 must return");
        assert_eq!(st, 200, "{body:?}");
        let body = body.expect("json");
        assert_eq!(body["result"]["hash"], hash, "{body}");
        assert!(
            t1.elapsed() < std::time::Duration::from_secs(1),
            "waitfornewblock with timeout 0 slept {:?}",
            t1.elapsed()
        );
        let missing = "00".repeat(32);
        let short = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 4,
            "method": "waitforblock",
            "params": [missing, 50]
        });
        let t2 = std::time::Instant::now();
        let (st, body) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            post_raw(
                tcp_addr(&handle),
                &handle.auth,
                short.to_string().as_bytes(),
            ),
        )
        .await
        .expect("short waitforblock must hit its deadline");
        assert_eq!(st, 200, "{body:?}");
        assert!(
            t2.elapsed() < std::time::Duration::from_secs(1),
            "missing-hash waitforblock ignored the deadline: {:?}",
            t2.elapsed()
        );
        let gbt = serde_json::json!({
            "jsonrpc": "1.0",
            "id": 5,
            "method": "getblocktemplate",
            "params": [{"rules": ["segwit"], "longpollid": "00"}]
        });
        let t3 = std::time::Instant::now();
        let (st, body) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            post_raw(tcp_addr(&handle), &handle.auth, gbt.to_string().as_bytes()),
        )
        .await
        .expect("stale longpollid must not wait");
        assert_eq!(st, 200, "{body:?}");
        let body = body.expect("json");
        assert!(body["result"]["height"].is_number(), "{body}");
        assert!(
            t3.elapsed() < std::time::Duration::from_secs(1),
            "stale getblocktemplate longpoll slept {:?}",
            t3.elapsed()
        );
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn waitfor_does_not_hold_the_blocking_pool() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-wait-pool").expect("dir");
            let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
            let hub = rbitcoin_net::ChainHub::new(
                q,
                rbitcoin_consensus::ChainParams::regtest(),
                rbitcoin_consensus::Milestone::NONE,
            );
            hub.ensure_genesis().unwrap();
            let query = Arc::clone(&hub.query);
            let cfg = RpcConfig {
                listen: Some("127.0.0.1:0".parse().unwrap()),
                socket_path: None,
                socket_shared: false,
                datadir: dir.path().to_path_buf(),
                network: Network::Regtest,
                token_path: None,
                cookie_path: None,
                subversion: None,
                work_queue: None,
                rest: false,
                alert_notify: None,
            };
            let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            let addr = tcp_addr(&handle);
            let auth = handle.auth.clone();
            let waiter = tokio::spawn(async move {
                let body = serde_json::json!({
                    "jsonrpc": "1.0",
                    "id": "w",
                    "method": "waitforblock",
                    "params": {
                        "blockhash": "00".repeat(32),
                        "timeout": 2000
                    }
                })
                .to_string();
                let req = format!(
                    "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    auth.token,
                    body.len()
                );
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                stream.write_all(req.as_bytes()).await.unwrap();
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
            });
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            let t0 = std::time::Instant::now();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert!(
                t0.elapsed() < std::time::Duration::from_millis(400),
                "named waitforblock held the blocking pool for {:?}",
                t0.elapsed()
            );
            assert!(
                !waiter.is_finished(),
                "named waitforblock returned before the pool probe"
            );
            waiter.abort();
            handle.shutdown().await;
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[tokio::test]
    async fn long_poll_does_not_hold_the_work_queue() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-wait-queue").expect("dir");
        let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
        let hub = rbitcoin_net::ChainHub::new(
            q,
            rbitcoin_consensus::ChainParams::regtest(),
            rbitcoin_consensus::Milestone::NONE,
        );
        hub.ensure_genesis().unwrap();
        let query = Arc::clone(&hub.query);
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: Some(1),
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let addr = tcp_addr(&handle);
        let auth = handle.auth.clone();
        let waiter = tokio::spawn(async move {
            let body = serde_json::json!({
                "jsonrpc": "1.0",
                "id": "w",
                "method": "waitfornewblock",
                "params": [5_000]
            })
            .to_string();
            let _ = post_raw(addr, &auth, body.as_bytes()).await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let (st, body) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            post_raw(
                tcp_addr(&handle),
                &handle.auth,
                br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
            ),
        )
        .await
        .expect("getblockcount while a long-poll is in flight");
        assert_eq!(st, 200, "{body:?}");
        assert_eq!(body.expect("json")["result"], 0);
        assert!(
            !waiter.is_finished(),
            "waitfornewblock returned before the queue probe"
        );
        waiter.abort();
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rpc_work_queue_exceeded() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-wq").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: Some(1),
            rest: false,

            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 200, "{body:?}");
        assert_eq!(body.unwrap()["result"], 0);

        let batch = serde_json::json!([
            {"jsonrpc":"1.0","id":1,"method":"getblockcount"},
            {"jsonrpc":"1.0","id":2,"method":"getblockcount"}
        ]);
        let (st, body) = post_raw(
            tcp_addr(&handle),
            &handle.auth,
            batch.to_string().as_bytes(),
        )
        .await;
        assert_eq!(
            st, 200,
            "one POST is one occupancy even with 2 methods: {body:?}"
        );
        let arr = body
            .as_ref()
            .and_then(|v| v.as_array())
            .expect("batch json");
        assert_eq!(arr.len(), 2, "{body:?}");

        let mut hits = Vec::new();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let addr = tcp_addr(&handle);
            let auth = handle.auth.clone();
            set.spawn(async move {
                post_raw(
                    addr,
                    &auth,
                    br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
                )
                .await
            });
        }
        while let Some(r) = set.join_next().await {
            hits.push(r.unwrap().0);
        }
        assert!(
            hits.contains(&503),
            "full permit must HTTP 503, got {hits:?}"
        );
        assert!(
            hits.contains(&200),
            "some occupancy must still succeed, got {hits:?}"
        );
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[allow(clippy::cognitive_complexity)] // one listener, envelope junk table
    #[tokio::test]
    async fn jsonrpc_envelope_junk_and_auth() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-env").expect("temp dir");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        let cfg = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let addr = tcp_addr(&handle);
        let auth = &handle.auth;

        let (st, _) = http_verb(addr, "GET", "/", auth, b"").await;
        assert_eq!(st, 405);

        let (st, _) = http_verb(addr, "POST", "/not-rpc", auth, b"{}").await;
        assert_eq!(st, 404);

        let (st, body) = post_raw(addr, auth, b"null").await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["message"], "Parse error");

        let (st, body) = post_raw(addr, auth, b"42").await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["message"], "Parse error");

        let (st, body) = post_raw(addr, auth, b"   ").await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["code"], -32700);

        let (st, body) = post_raw(addr, auth, &[0xff, 0xfe, 0x00]).await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["code"], -32700);

        let (st, body) = post_raw(addr, auth, br#"[]"#).await;
        assert_eq!(st, 200);
        assert_eq!(body.unwrap(), serde_json::json!([]));

        let (st, body) = post_raw(
            addr,
            auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":5}"#,
        )
        .await;
        assert_eq!(st, 500);
        assert_eq!(
            body.unwrap()["error"]["message"],
            "params must be array or object"
        );

        let (st, body) = post_raw(
            addr,
            auth,
            br#"{"jsonrpc":"1.0","id":1,"method":7,"params":[]}"#,
        )
        .await;
        assert_eq!(st, 400);
        assert_eq!(body.unwrap()["error"]["message"], "Missing method");

        let (st, body) = post_raw(
            addr,
            auth,
            br#"{"jsonrpc":"2.0","id":[1,2],"method":"getblockcount","params":[]}"#,
        )
        .await;
        assert_eq!(st, 200);
        let v = body.unwrap();
        assert_eq!(v["id"], serde_json::json!([1, 2]));
        assert_eq!(v["result"], 0);

        let (st, body) = post_raw(
            addr,
            auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":{}}"#,
        )
        .await;
        assert_eq!(st, 200);
        assert_eq!(body.unwrap()["result"], 0);

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let bad = b"POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dGVzdHVzZXI6d3Jvbmc=\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        stream.write_all(bad).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("401") || text.contains("Unauthorized"),
            "{text}"
        );

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mal = b"POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic !!!\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
        stream.write_all(mal).await.unwrap();
        buf.clear();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("401") || text.contains("Unauthorized"),
            "{text}"
        );

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn http_verb(
        addr: SocketAddr,
        verb: &str,
        path: &str,
        auth: &RpcAuth,
        body: &[u8],
    ) -> (u16, Option<serde_json::Value>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let auth_h = auth_header(auth);
        let req = format!(
            "{verb} {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth_h}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
        let json_body = text[body_start..].trim();
        let parsed = if json_body.is_empty() {
            None
        } else {
            Some(serde_json::from_str(json_body).unwrap_or(serde_json::json!(json_body)))
        };
        (status, parsed)
    }

    async fn post_with_authorization(addr: SocketAddr, authorization: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let body = br#"{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn tcp_accepts_bearer_and_opted_in_core_cookie_basic() {
        use base64::Engine;

        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-token").expect("temp dir");
        std::fs::write(dir.path().join("rpc.token"), "pass").unwrap();
        let query = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let without_cookie = RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(
            without_cookie,
            Arc::clone(&query),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let addr = tcp_addr(&handle);
        let count = post_rpc(addr, &handle.auth, "getblockcount", serde_json::json!([]))
            .await
            .unwrap();
        assert_eq!(count["result"], 0, "{count}");
        let basic = base64::engine::general_purpose::STANDARD.encode("mempool:secret");
        let rejected = post_with_authorization(addr, &format!("Basic {basic}")).await;
        assert!(rejected.contains("401 Unauthorized"), "{rejected}");
        assert!(
            rejected
                .to_ascii_lowercase()
                .contains("www-authenticate: bearer"),
            "{rejected}"
        );
        handle.shutdown().await;

        let cookie_path = dir.path().join(".cookie");
        let with_cookie = || RpcConfig {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            socket_path: None,
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: Some(cookie_path.clone()),
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        // The cookie is TCP-only: a socket-only listener must not silently ignore it.
        std::fs::write(&cookie_path, "mempool:secret").unwrap();
        let socket_only = RpcConfig {
            listen: None,
            socket_path: Some(dir.path().join("cookie-socket-only.sock")),
            ..with_cookie()
        };
        let err = match run_rpc(
            socket_only,
            Arc::clone(&query),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        {
            Ok(_) => panic!("cookie without --rpc-listen must not start the listener"),
            Err(e) => e,
        };
        assert!(err.contains("TCP only"), "{err}");

        // mempool would send the newline as part of the password: refuse to start.
        std::fs::write(&cookie_path, "mempool:secret\n").unwrap();
        let err = match run_rpc(
            with_cookie(),
            Arc::clone(&query),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        {
            Ok(_) => panic!("cookie with a trailing newline must not start the listener"),
            Err(e) => e,
        };
        assert!(err.contains("line ending"), "{err}");

        std::fs::write(&cookie_path, "mempool:secret").unwrap();
        let handle = run_rpc(with_cookie(), query, None, None, None, None, None)
            .await
            .unwrap();
        let addr = tcp_addr(&handle);
        let accepted = post_with_authorization(addr, &format!("Basic {basic}")).await;
        assert!(accepted.contains("200 OK"), "{accepted}");
        assert!(accepted.contains("\"result\":0"), "{accepted}");
        let bad = base64::engine::general_purpose::STANDARD.encode("mempool:wrong");
        let rejected = post_with_authorization(addr, &format!("Basic {bad}")).await;
        assert!(rejected.contains("401 Unauthorized"), "{rejected}");
        assert!(
            rejected
                .to_ascii_lowercase()
                .contains("www-authenticate: basic"),
            "{rejected}"
        );
        // mempool drops its cached cookie only when a 401 body is not JSON
        // (rpc-api/jsonrpc.js), so a rotated cookie is re-read.
        let body = rejected.split_once("\r\n\r\n").map_or("", |(_, b)| b);
        assert!(!body.is_empty(), "{rejected}");
        assert!(
            serde_json::from_str::<serde_json::Value>(body).is_err(),
            "{rejected}"
        );
        let newline = base64::engine::general_purpose::STANDARD.encode("mempool:secret\n");
        let rejected = post_with_authorization(addr, &format!("Basic {newline}")).await;
        assert!(rejected.contains("401 Unauthorized"), "{rejected}");
        let malformed = post_with_authorization(addr, "Basic !!!").await;
        assert!(malformed.contains("401 Unauthorized"), "{malformed}");
        handle.shutdown().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_unix_socket_does_not_strip_dir_search() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicBool, Ordering};
        extern "C" {
            fn umask(mask: u32) -> u32;
        }
        let old = unsafe { umask(0o022) };
        let stop = Arc::new(AtomicBool::new(false));
        let bare = Arc::new(AtomicBool::new(false));
        let worker = {
            let stop = Arc::clone(&stop);
            let bare = Arc::clone(&bare);
            std::thread::spawn(move || {
                let mut n = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let path = std::env::temp_dir().join(format!(
                        "rbitcoin-umask-probe-{}-{}",
                        std::process::id(),
                        n
                    ));
                    n += 1;
                    if std::fs::create_dir(&path).is_err() {
                        continue;
                    }
                    let mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o111);
                    let _ = std::fs::remove_dir(&path);
                    if mode.is_ok_and(|m| m == 0) {
                        bare.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            })
        };
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-umask").expect("temp dir");
        for i in 0..200 {
            let sock = dir.path().join(format!("s{i}.sock"));
            let listener = super::bind_unix_mode(&sock, 0o600).expect("bind");
            let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "socket mode");
            drop(listener);
            let _ = std::fs::remove_file(&sock);
            if bare.load(Ordering::Relaxed) {
                break;
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = worker.join();
        unsafe { umask(old) };
        assert!(
            !bare.load(Ordering::Relaxed),
            "unix bind changed umask and a temp dir lost search permission"
        );
    }

    #[cfg(not(unix))]
    #[tokio::test]
    async fn unix_socket_without_tcp_refuses_without_af_unix() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-sock-win").expect("temp dir");
        let sock = dir.path().join("rpc.sock");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let cfg = RpcConfig {
            listen: None,
            socket_path: Some(sock),
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let err = run_rpc(cfg, q, None, None, None, None, None)
            .await
            .unwrap_err();
        assert!(
            err.contains("rpc-listen") || err.contains("AF_UNIX"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_needs_no_http_auth() {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-sock").expect("temp dir");
        let sock = dir.path().join("rpc.sock");
        let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
        let cfg = RpcConfig {
            listen: None,
            socket_path: Some(sock.clone()),
            socket_shared: false,
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
            token_path: None,
            cookie_path: None,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,
        };
        let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert!(sock.exists(), "socket file");
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "rpc.sock is created owner-only, got {mode:o}");
        }
        let body = br#"{"jsonrpc":"1.0","id":"1","method":"getblockcount","params":[]}"#;
        let req = format!(
            "POST / HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("\"result\":0") || text.contains("\"result\": 0"),
            "unix unauthenticated getblockcount: {text}"
        );
        handle.shutdown().await;
    }

    fn http_wait_ctx() -> (
        Arc<crate::methods::RpcContext>,
        rbitcoin_store::testutil::TempDir,
    ) {
        let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-http-wait").expect("temp dir");
        let hub = Arc::new(rbitcoin_net::ChainHub::new(
            Query::open_or_create_tiny(dir.join("store")).unwrap(),
            rbitcoin_consensus::ChainParams::regtest(),
            rbitcoin_consensus::Milestone::NONE,
        ));
        hub.ensure_genesis().unwrap();
        let ctx = Arc::new(crate::methods::RpcContext {
            query: Arc::clone(&hub.query),
            mempool: None,
            network: Network::Regtest,
            start: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            connections: Arc::new(AtomicU64::new(0)),
            initial_block_download: Arc::new(AtomicBool::new(false)),
            subversion: "/rbitcoin:test/".into(),
            regtest: None,
            peers: None,
            chain: Some(hub),
            addrman: None,
            logpath: String::new(),
            active: Arc::new(std::sync::Mutex::new(crate::methods::RpcActive::default())),
            alert_notify: None,
            alert_fired: Arc::new(AtomicBool::new(false)),
        });
        (ctx, dir)
    }

    /// `feature_shutdown.py`: a wait parked on the async side is still an
    /// active command.
    #[tokio::test]
    async fn http_wait_is_an_active_command_while_it_waits() {
        let (ctx, _dir) = http_wait_ctx();
        let body = serde_json::json!({ "method": "waitfornewblock", "params": [5_000] });
        let waiter = {
            let ctx = Arc::clone(&ctx);
            tokio::spawn(async move { satisfy_http_wait(&ctx, &body).await })
        };
        let t0 = Instant::now();
        loop {
            let names: Vec<String> = ctx
                .active
                .lock()
                .unwrap()
                .snapshot()
                .into_iter()
                .map(|(m, _)| m)
                .collect();
            if names.iter().any(|m| m == "waitfornewblock") {
                break;
            }
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(2),
                "waitfornewblock never showed as active: {names:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        ctx.stop.store(true, Ordering::SeqCst);
        assert!(waiter.await.unwrap());
        assert!(ctx.active.lock().unwrap().is_empty(), "the wait left");
    }

    /// `mining_getblocktemplate_longpoll.py` sees the request line while the
    /// longpoll waits, and only once.
    #[tokio::test]
    async fn http_longpoll_logs_the_request_once_before_it_waits() {
        let (ctx, _dir) = http_wait_ctx();
        let current = crate::methods::gbt_longpoll_id(&ctx);
        let req = serde_json::json!({
            "method": "getblocktemplate",
            "params": [{ "rules": ["segwit"], "longpollid": current }],
            "id": 1
        });
        rbitcoin_log::capture_logs(true);
        let waiter = {
            let ctx = Arc::clone(&ctx);
            let req = req.clone();
            tokio::spawn(async move { satisfy_http_wait(&ctx, &req).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!waiter.is_finished(), "the longpoll id has not changed");
        let mut lines = rbitcoin_log::take_logs();
        let needle = "ThreadRPCServer method=getblocktemplate";
        assert!(
            lines.iter().any(|(_, l)| l == needle),
            "logged before the wait ends: {lines:?}"
        );
        ctx.stop.store(true, Ordering::SeqCst);
        assert!(waiter.await.unwrap());
        crate::methods::set_http_wait_satisfied(true);
        let _ = exec_one(&ctx, &req);
        crate::methods::set_http_wait_satisfied(false);
        lines.extend(rbitcoin_log::take_logs());
        rbitcoin_log::capture_logs(false);
        let n = lines.iter().filter(|(_, l)| l == needle).count();
        assert_eq!(n, 1, "{lines:?}");
    }

    /// A plain `getblocktemplate` logs Core's request line once; other
    /// methods do not.
    #[test]
    fn exec_one_logs_the_getblocktemplate_request_line_only() {
        let (ctx, _dir) = http_wait_ctx();
        let needle = "ThreadRPCServer method=getblocktemplate";
        rbitcoin_log::capture_logs(true);
        let _ = exec_one(
            &ctx,
            &serde_json::json!({
                "method": "getblocktemplate",
                "params": [{ "rules": ["segwit"] }],
                "id": 1
            }),
        );
        let gbt = rbitcoin_log::take_logs();
        let _ = exec_one(
            &ctx,
            &serde_json::json!({ "method": "getblockcount", "params": [], "id": 2 }),
        );
        let other = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert_eq!(
            gbt.iter().filter(|(_, l)| l == needle).count(),
            1,
            "{gbt:?}"
        );
        assert!(other.iter().all(|(_, l)| l != needle), "{other:?}");
    }

    #[tokio::test]
    async fn http_wait_stop_returns_before_the_timeout() {
        let (ctx, _dir) = http_wait_ctx();
        ctx.stop.store(true, Ordering::SeqCst);
        let body = serde_json::json!({
            "method": "waitforblockheight",
            "params": [99, 2_000]
        });
        let t0 = Instant::now();
        assert!(satisfy_http_wait(&ctx, &body).await);
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(200),
            "stop is enough; the deadline is still ahead"
        );
    }

    #[tokio::test]
    async fn http_wait_met_height_does_not_sleep() {
        let (ctx, _dir) = http_wait_ctx();
        let body = serde_json::json!({
            "method": "waitforblockheight",
            "params": [0, 2_000]
        });
        let t0 = Instant::now();
        assert!(satisfy_http_wait(&ctx, &body).await);
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(200),
            "genesis height already meets 0"
        );
    }

    #[tokio::test]
    async fn http_wait_unmet_height_and_same_tip_use_the_timeout() {
        let (ctx, _dir) = http_wait_ctx();
        let height = serde_json::json!({
            "method": "waitforblockheight",
            "params": [1, 160]
        });
        let t0 = Instant::now();
        assert!(satisfy_http_wait(&ctx, &height).await);
        let dt = t0.elapsed();
        assert!(
            dt >= std::time::Duration::from_millis(100),
            "height 1 is still ahead of genesis, waited {dt:?}"
        );

        let fresh = serde_json::json!({
            "method": "waitfornewblock",
            "params": [160]
        });
        let t0 = Instant::now();
        assert!(satisfy_http_wait(&ctx, &fresh).await);
        let dt = t0.elapsed();
        assert!(
            dt >= std::time::Duration::from_millis(100),
            "the tip did not move, waited {dt:?}"
        );
    }
}
