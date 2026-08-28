//! HTTP JSON-RPC server (axum) with Basic auth.

use crate::auth::{parse_basic_auth, resolve_rpc_auth, RpcAuth};
use crate::methods::{RpcContext, RpcRegtest};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use rbitcoin_log::info;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// RPC listen configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    pub listen: SocketAddr,
    pub datadir: PathBuf,
    pub network: Network,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    /// Override cookie path (default `{datadir}/.cookie`).
    pub cookie_path: Option<PathBuf>,
    /// `getnetworkinfo.subversion`. Empty → `/rbitcoin:VERSION/`.
    pub subversion: Option<String>,
    /// Core `-rpcworkqueue`. `None` = unlimited (tests / default).
    pub work_queue: Option<usize>,
    /// Core `-permitbaremultisig` (default true).
    pub permit_bare_multisig: bool,
}

/// Live RPC server handle.
pub struct RpcHandle {
    pub local_addr: SocketAddr,
    pub cookie_path: Option<PathBuf>,
    pub auth: RpcAuth,
    pub stop: Arc<AtomicBool>,
    pub connections: Arc<AtomicU64>,
    pub initial_block_download: Arc<AtomicBool>,
    /// Shared with [`RpcContext::active`] so tip-follow can drain in-flight
    /// handlers before tearing down the RPC server (`feature_shutdown.py`).
    pub active: Arc<std::sync::Mutex<crate::methods::RpcActive>>,
    shutdown: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl RpcHandle {
    pub async fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = self.task.await;
    }
}

#[derive(Clone)]
struct AppState {
    ctx: Arc<RpcContext>,
    auth: RpcAuth,
    work_queue: Option<Arc<tokio::sync::Semaphore>>,
}

/// Start Core-class JSON-RPC on `config.listen` (plain HTTP; TLS via reverse proxy).
pub async fn run_rpc(
    config: RpcConfig,
    query: Arc<Query>,
    mempool: Option<Arc<MempoolHub>>,
    regtest: Option<Arc<dyn RpcRegtest>>,
    peers: Option<Arc<rbitcoin_net::PeerHub>>,
    chain: Option<Arc<rbitcoin_net::ChainHub>>,
    addrman: Option<Arc<std::sync::Mutex<rbitcoin_net::AddrMan>>>,
    peers_path: Option<std::path::PathBuf>,
) -> Result<RpcHandle, String> {
    let (auth, cookie_path) = resolve_rpc_auth(
        &config.datadir,
        config.rpc_user.as_deref(),
        config.rpc_password.as_deref(),
        config.cookie_path.as_deref(),
    )?;

    if auth.password.is_empty() {
        return Err("RPC auth password empty".into());
    }

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
        peers_path,
        logpath: config.datadir.join("debug.log").display().to_string(),
        active: Arc::clone(&active),
        permit_bare_multisig: config.permit_bare_multisig,
    });

    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("rpc bind {}: {e}", config.listen))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("rpc local_addr: {e}"))?;

    let work_queue = config
        .work_queue
        .filter(|n| *n > 0)
        .map(|n| Arc::new(tokio::sync::Semaphore::new(n)));
    let state = AppState {
        ctx,
        auth: auth.clone(),
        work_queue,
    };
    let app = Router::new().route("/", post(rpc_post)).with_state(state);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_w = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                while !shutdown_w.load(Ordering::SeqCst) {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await
            .ok();
    });

    if let Some(ref p) = cookie_path {
        info!(
            "rpc: HTTP JSON-RPC on {local_addr} (cookie auth {})",
            p.display()
        );
    } else {
        info!("rpc: HTTP JSON-RPC on {local_addr} (rpcuser/rpcpassword auth)");
    }

    Ok(RpcHandle {
        local_addr,
        cookie_path,
        auth,
        stop,
        connections,
        initial_block_download: ibd,
        active,
        shutdown,
        task,
    })
}

async fn rpc_post(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !authorized(&state.auth, &headers) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")],
            "Unauthorized\n",
        )
            .into_response();
    }
    let _permit = if let Some(sem) = state.work_queue.as_ref() {
        match sem.try_acquire() {
            Ok(p) => Some(p),
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Work queue depth exceeded\n",
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return parse_error_response();
        }
    };
    let ctx = Arc::clone(&state.ctx);
    let joined = tokio::task::spawn_blocking(move || exec_http_rpc(&ctx, parsed)).await;
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
    if method == "getblocktemplate" {
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

fn authorized(auth: &RpcAuth, headers: &HeaderMap) -> bool {
    let Some(val) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some((u, p)) = parse_basic_auth(val) else {
        return false;
    };
    auth.matches(&u, &p)
}

/// Build Basic auth header value for clients.
pub fn basic_auth_header(auth: &RpcAuth) -> String {
    use base64::Engine;
    let tok = base64::engine::general_purpose::STANDARD.encode(auth.cookie_line());
    format!("Basic {tok}")
}

/// Call a method against a live server (test helper / smoke).
pub async fn post_rpc(
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
    let auth_h = basic_auth_header(auth);
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

#[cfg(test)]
mod tests {
    use super::*;
    use rbitcoin_primitives::Network;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn rpc_smoke_getblockcount_and_help() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-srv-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        mp.set_relay_enabled(true);
        let cfg = RpcConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            datadir: dir.clone(),
            network: Network::Regtest,
            rpc_user: Some("testuser".into()),
            rpc_password: Some("testpass".into()),
            cookie_path: None,
            subversion: None,
            work_queue: None,
            permit_bare_multisig: true,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        let count = post_rpc(
            handle.local_addr,
            &handle.auth,
            "getblockcount",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(count["error"].is_null(), "{count}");
        assert_eq!(count["result"], 0);

        let help = post_rpc(
            handle.local_addr,
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
            handle.local_addr,
            &handle.auth,
            "getmempoolinfo",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(mem["error"].is_null(), "{mem}");
        assert_eq!(mem["result"]["size"], 0);

        let chain = post_rpc(
            handle.local_addr,
            &handle.auth,
            "getblockchaininfo",
            serde_json::json!([]),
        )
        .await
        .unwrap();
        assert!(chain["error"].is_null(), "{chain}");
        assert_eq!(chain["result"]["chain"], "regtest");

        // 401 without auth
        let mut stream = tokio::net::TcpStream::connect(handle.local_addr)
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

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn post_raw(
        addr: SocketAddr,
        auth: &RpcAuth,
        body: &[u8],
    ) -> (u16, Option<serde_json::Value>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let auth_h = basic_auth_header(auth);
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
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-v2-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        mp.set_relay_enabled(true);
        let cfg = RpcConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            datadir: dir.clone(),
            network: Network::Regtest,
            rpc_user: Some("testuser".into()),
            rpc_password: Some("testpass".into()),
            cookie_path: None,
            subversion: None,
            work_queue: None,
            permit_bare_multisig: true,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;

        let batch = serde_json::json!([
            {"jsonrpc":"2.0","id":1,"method":"getblockcount"},
            {"jsonrpc":"2.0","id":2,"method":"invalidmethod"},
            {"jsonrpc":"2.0","id":4,"pizza":"sausage"}
        ]);
        let (st, body) = post_raw(
            handle.local_addr,
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
            handle.local_addr,
            &handle.auth,
            br#"{"jsonrpc":"2.0","method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 204, "{body:?}");
        assert!(body.is_none());

        let (st, body) = post_raw(handle.local_addr, &handle.auth, b"").await;
        assert_eq!(st, 500);
        assert_eq!(body.unwrap()["error"]["message"], "Parse error");

        let (st, body) = post_raw(
            handle.local_addr,
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
            handle.local_addr,
            &handle.auth,
            br#"{"jsonrpc":"1.1","id":1,"method":"invalidmethod"}"#,
        )
        .await;
        assert_eq!(st, 404);

        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rpc_work_queue_exceeded() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rbitcoin-rpc-wq-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let q = Arc::new(Query::open_or_create(dir.join("store")).unwrap());
        let mp =
            MempoolHub::open_with_weight(dir.join("mempool"), Arc::clone(&q), 300_000_000).unwrap();
        let cfg = RpcConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            datadir: dir.clone(),
            network: Network::Regtest,
            rpc_user: Some("testuser".into()),
            rpc_password: Some("testpass".into()),
            cookie_path: None,
            subversion: None,
            work_queue: Some(1),
            permit_bare_multisig: true,
        };
        let handle = run_rpc(cfg, q, Some(mp), None, None, None, None, None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let (st, body) = post_raw(
            handle.local_addr,
            &handle.auth,
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
        )
        .await;
        assert_eq!(st, 200, "{body:?}");
        assert_eq!(body.unwrap()["result"], 0);
        handle.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
