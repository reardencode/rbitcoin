use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Network;
use rbitcoin_query::Query;
use rbitcoin_rpc::auth::{RpcAuth, RpcCookiePerms};
use rbitcoin_rpc::server::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

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
async fn long_socket_path_keeps_the_tcp_stop_flag() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-long-sock").expect("temp dir");
    let q = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
    let sock = dir.path().join(format!("{}.sock", "s".repeat(200)));
    let cfg = RpcConfig {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        socket_path: Some(sock),
        socket_shared: false,
        datadir: dir.path().to_path_buf(),
        network: Network::Regtest,
        token_path: None,
        cookie_path: None,
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None)
        .await
        .expect("tcp listener stays up when the unix path exceeds SUN_LEN");
    assert!(handle.socket_path.is_none());
    assert!(handle.local_addr.is_some());
    let stopped = post_rpc(
        tcp_addr(&handle),
        &handle.auth,
        "stop",
        serde_json::json!([]),
    )
    .await
    .unwrap();
    assert!(stopped["error"].is_null(), "{stopped}");
    assert!(handle.stop.load(Ordering::SeqCst));
    handle.shutdown().await;
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: true,

        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,

        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    let (st, body) = post_raw(tcp_addr(&handle), &handle.auth, req.to_string().as_bytes()).await;
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

/// A short deadline still returns the JSON-RPC tip, not an empty 408.
/// The two-minute numeric cap is `wait_timeout_ms_caps_at_two_minutes`.
#[tokio::test]
async fn long_poll_deadline_returns_the_tip() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-wait-cap").expect("dir");
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
        .await
        .unwrap();
    let missing = "00".repeat(32);
    // Long enough that a 50 ms sleep slice cannot return early, short
    // enough that the suite does not sleep the two-minute cap.
    let timeout_ms = 200u64;
    let req = serde_json::json!({
        "jsonrpc": "1.0",
        "id": 1,
        "method": "waitforblock",
        "params": [missing, timeout_ms]
    });
    let started = std::time::Instant::now();
    let (st, body) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        post_raw(tcp_addr(&handle), &handle.auth, req.to_string().as_bytes()),
    )
    .await
    .expect("deadline must return");
    let elapsed = started.elapsed();
    assert_eq!(st, 200, "{body:?}");
    let body = body.expect("json-rpc body");
    assert!(
        body.get("result").is_some_and(|r| !r.is_null()),
        "deadline returns the tip, got {body}"
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "waitforblock returned before its deadline: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "waitforblock slept past a short deadline: {elapsed:?}"
    );
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn extra_rpc_accept_is_dropped() {
    use tokio::io::AsyncReadExt;
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-accept-cap").expect("dir");
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let addr = tcp_addr(&handle);
    let mut held = Vec::with_capacity(RPC_MAX_CONNECTIONS);
    for _ in 0..RPC_MAX_CONNECTIONS {
        held.push(tokio::net::TcpStream::connect(addr).await.unwrap());
    }
    let mut extra = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), extra.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "an accept past the cap must be dropped, got {read:?}"
    );
    drop(held);
    drop(extra);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (st, body) = post_raw(
        addr,
        &handle.auth,
        br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
    )
    .await;
    assert_eq!(st, 200, "{body:?}");
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
            cookie_perms: RpcCookiePerms::Owner,
            subversion: None,
            work_queue: None,
            rest: false,
            alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: Some(1),
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: Some(1),
        rest: false,

        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `work_queue: Some(0)` is the default depth, so a live listener cannot
/// start with an empty queue. Call the handler with zero tickets.
#[tokio::test]
async fn empty_work_queue_is_http_503() {
    let (ctx, dir) = http_wait_ctx();
    let state = AppState {
        ctx,
        auth: RpcAuth::new("test-token"),
        cookie: None,
        work_queue: Arc::new(Semaphore::new(0)),
        rest_queue: Arc::new(Semaphore::new(1)),
        rest: false,
        require_auth: true,
    };
    let response = rpc_post(
        State(state),
        Bytes::from_static(br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 64)
        .await
        .expect("503 body");
    assert_eq!(&body[..], b"Work queue depth exceeded\n");
    let _ = std::fs::remove_dir_all(dir.path());
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.path().join("rpc.token"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let query = Arc::new(Query::open_or_create_tiny(dir.join("store")).unwrap());
    let without_cookie = RpcConfig {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        socket_path: None,
        socket_shared: false,
        datadir: dir.path().to_path_buf(),
        network: Network::Regtest,
        token_path: None,
        cookie_path: None,
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    // Mode is owner-only so the line-ending error is the one under test.
    std::fs::write(&cookie_path, "mempool:secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cookie_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
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
    // SAFETY: `umask` is process-global. This test restores `old` before return.
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
    let dir = rbitcoin_store::testutil::TempDir::for_socket().expect("temp dir");
    for i in 0..200 {
        let sock = dir.path().join(format!("s{i}.sock"));
        let listener = rbitcoin_rpc::server::bind_unix_mode(&sock, 0o600).expect("bind");
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
    // SAFETY: restores the umask saved at the start of this test.
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    let dir = rbitcoin_store::testutil::TempDir::for_socket().expect("temp dir");
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
        cookie_perms: RpcCookiePerms::Owner,
        subversion: None,
        work_queue: None,
        rest: false,
        alert_notify: None,

        client_version: 190_000,
        blocksonly: false,
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
    Arc<rbitcoin_rpc::methods::RpcContext>,
    rbitcoin_store::testutil::TempDir,
) {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-http-wait").expect("temp dir");
    let hub = Arc::new(rbitcoin_net::ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        rbitcoin_consensus::ChainParams::regtest(),
        rbitcoin_consensus::Milestone::NONE,
    ));
    hub.ensure_genesis().unwrap();
    let ctx = Arc::new(rbitcoin_rpc::methods::RpcContext {
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
        active: Arc::new(std::sync::Mutex::new(
            rbitcoin_rpc::methods::RpcActive::default(),
        )),
        alert_notify: None,
        alert_fired: Arc::new(AtomicBool::new(false)),

        client_version: 190_000,
        blocksonly: false,
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
    let current = rbitcoin_rpc::methods::gbt_longpoll_id(&ctx);
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
    rbitcoin_rpc::methods::set_http_wait_satisfied(true);
    let _ = exec_one(&ctx, &req);
    rbitcoin_rpc::methods::set_http_wait_satisfied(false);
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
