use axum::body::Body;
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

async fn read_keepalive_reply<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    let mut len = None;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut body = vec![0; len.expect("content-length")];
    reader.read_exact(&mut body).await.unwrap();
    let reply: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply["result"], 0, "{reply}");
    assert!(reply["error"].is_null(), "{reply}");
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

        blocksonly: false,
        package_dialect: false,
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
        .await
        .unwrap();

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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
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

async fn exchange_rpc(addr: SocketAddr, auth: &RpcAuth, body: &[u8]) -> (u16, String, Vec<u8>) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let auth_h = auth_header(auth);
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nAuthorization: {auth_h}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let status: u16 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut content_type = String::new();
    let mut len = None;
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await.unwrap();
        assert_ne!(n, 0, "response headers ended early");
        if line == "\r\n" {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-type:") {
            content_type = value.trim().to_string();
        }
        if let Some(value) = lower.strip_prefix("content-length:") {
            len = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut raw = vec![0; len.unwrap_or(0)];
    if !raw.is_empty() {
        reader.read_exact(&mut raw).await.unwrap();
    }
    (status, content_type, raw)
}

fn assert_json_line(raw: &[u8], expect: &str) {
    let text = std::str::from_utf8(raw).unwrap_or("not utf-8");
    assert_eq!(text, expect);
}

#[tokio::test]
async fn jsonrpc_http_body_matches_core_line() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-nl").expect("temp dir");
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
        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    let addr = tcp_addr(&handle);
    let auth = &handle.auth;

    let (st, ct, raw) = exchange_rpc(
        addr,
        auth,
        br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#,
    )
    .await;
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&raw));
    assert!(ct.starts_with("application/json"), "content-type {ct}");
    assert_json_line(&raw, "{\"result\":0,\"error\":null,\"id\":1}\n");

    let (st, _, raw) = exchange_rpc(
        addr,
        auth,
        br#"{"jsonrpc":"1.0","id":9,"method":"no-such-method","params":[]}"#,
    )
    .await;
    assert_eq!(st, 404);
    assert_json_line(
        &raw,
        "{\"result\":null,\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":9}\n",
    );

    let (st, _, raw) = exchange_rpc(addr, auth, b"").await;
    assert_eq!(st, 500);
    assert_json_line(
        &raw,
        "{\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n",
    );

    let (st, _, raw) = exchange_rpc(addr, auth, b"true").await;
    assert_eq!(st, 500);
    assert_json_line(
        &raw,
        "{\"result\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"},\"id\":null}\n",
    );

    let (st, _, raw) = exchange_rpc(
        addr,
        auth,
        br#"{"jsonrpc":2,"id":7,"method":"getblockcount"}"#,
    )
    .await;
    assert_eq!(st, 400);
    assert_json_line(
        &raw,
        "{\"result\":null,\"error\":{\"code\":-32600,\"message\":\"jsonrpc field must be a string\"},\"id\":7}\n",
    );

    let (st, _, raw) = exchange_rpc(
        addr,
        auth,
        br#"[{"jsonrpc":"2.0","id":1,"method":"getblockcount"},{"jsonrpc":"2.0","id":2,"method":"no-such-method"},{"jsonrpc":2,"id":4,"method":"getblockcount"}]"#,
    )
    .await;
    assert_eq!(st, 200);
    assert_json_line(
        &raw,
        "[{\"jsonrpc\":\"2.0\",\"result\":0,\"id\":1},{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"},\"id\":2},{\"result\":null,\"error\":{\"code\":-32600,\"message\":\"jsonrpc field must be a string\"},\"id\":4}]\n",
    );

    let (st, _, raw) = exchange_rpc(addr, auth, b"[]").await;
    assert_eq!(st, 200);
    assert_json_line(&raw, "[]\n");

    let (st, _, raw) =
        exchange_rpc(addr, auth, br#"{"jsonrpc":"2.0","method":"getblockcount"}"#).await;
    assert_eq!(st, 204);
    assert!(raw.is_empty(), "{}", String::from_utf8_lossy(&raw));

    handle.shutdown().await;
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
        .await
        .unwrap();

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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
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
fn rpc_body_caps_match_core_max_size_and_rest_two_mebibytes() {
    assert_eq!(RPC_MAX_HTTP_BODY, 32 * 1024 * 1024);
    assert_eq!(REST_MAX_HTTP_BODY, 2 * 1024 * 1024);
}

/// Witness v0 counts opcodes above `OP_16`. 201 `OP_DROP`s plus `OP_TRUE`
/// is the largest clean script, so each input's 520-byte stack is the
/// padding that pushes a block past 1 MiB without passing 4M weight.
fn witness_pad_script() -> bitcoin::ScriptBuf {
    let mut bytes = vec![0x75u8; 201];
    bytes.push(0x51);
    bitcoin::ScriptBuf::from_bytes(bytes)
}

fn over_one_mebibyte_block(hub: &rbitcoin_net::ChainHub) -> bitcoin::Block {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
        TxOut, Witness,
    };
    use rbitcoin_consensus::regtest_pad::{
        grind_regtest_pow, mine_regtest_paying, regtest_coinbase, REGTEST_POW_BITS,
    };

    let script = witness_pad_script();
    let spk = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::hash(script.as_bytes()));
    let subsidy =
        rbitcoin_consensus::block_subsidy(1, &rbitcoin_consensus::ChainParams::regtest()) as u64;
    let n = 11u64;
    let each = subsidy / n;
    let outputs: Vec<TxOut> = (0..n)
        .map(|i| {
            let value = if i + 1 == n {
                subsidy - each * (n - 1)
            } else {
                each
            };
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: spk.clone(),
            }
        })
        .collect();
    let mut coinbase = regtest_coinbase(1, Amount::from_sat(subsidy), spk);
    coinbase.output = outputs;
    let mut funding = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: hub.tip_hash().expect("genesis"),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: hub
                .tip_header()
                .expect("genesis header")
                .time
                .saturating_add(1),
            bits: CompactTarget::from_consensus(REGTEST_POW_BITS),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    funding.header.merkle_root = funding.compute_merkle_root().expect("funding merkle");
    grind_regtest_pow(&mut funding.header);
    let txid = funding.txdata[0].compute_txid();
    hub.accept_block(funding).expect("fund the padded spends");
    hub.generate_to_script(99, ScriptBuf::from_bytes(vec![0x51]), Vec::new())
        .expect("mature the coinbase");
    assert_eq!(
        hub.tip_height(),
        Some(100),
        "height-1 coinbase spends at 101"
    );

    let item = vec![0u8; 520];
    let mut stack: Vec<Vec<u8>> = (0..201).map(|_| item.clone()).collect();
    stack.push(script.into_bytes());
    let refs: Vec<&[u8]> = stack.iter().map(Vec::as_slice).collect();
    let witness = Witness::from_slice(&refs);
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: (0..n)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: vout as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: witness.clone(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(subsidy),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let block = mine_regtest_paying(
        hub.tip_hash().expect("mature tip"),
        hub.tip_header()
            .expect("mature header")
            .time
            .saturating_add(1),
        101,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    );
    let raw_len = bitcoin::consensus::encode::serialize(&block).len();
    assert!(
        raw_len > 1024 * 1024,
        "block must be over 1 MiB, got {raw_len}"
    );
    assert!(
        block.weight().to_wu() <= 4_000_000,
        "weight {}",
        block.weight()
    );
    block
}

fn http_status(text: &str) -> u16 {
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn http_json(text: &str) -> serde_json::Value {
    let body = text
        .find("\r\n\r\n")
        .map(|i| text[i + 4..].trim())
        .unwrap_or("");
    if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(body).unwrap_or(serde_json::Value::String(body.to_string()))
    }
}

async fn write_http<S>(stream: &mut S, head: &str, body: &[u8]) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(head.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        stream.read_to_end(&mut buf),
    )
    .await
    .expect("HTTP reply")
    .expect("read reply");
    String::from_utf8_lossy(&buf).into_owned()
}

async fn post_authed<S>(mut stream: S, bearer: &str, body: &[u8]) -> String
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let head = format!(
        "POST / HTTP/1.1\r\nHost: rpc\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    write_http(&mut stream, &head, body).await
}

/// `submitblock` and a proposal of one block past 1 MiB, on TCP and the unix
/// socket. A body past the cap, a bad credential, and REST stay rejected.
#[tokio::test]
async fn large_block_submit_and_proposal_clear_http_413() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-big-block").expect("temp dir");
    let hub = rbitcoin_net::ChainHub::new(
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        rbitcoin_consensus::ChainParams::regtest(),
        rbitcoin_consensus::Milestone::NONE,
    );
    hub.ensure_genesis().unwrap();
    let block = over_one_mebibyte_block(&hub);
    let want_hash = block.block_hash().to_string();
    let hex = rbitcoin_primitives::hex_encode(bitcoin::consensus::encode::serialize(&block));
    let submit = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "1.0",
        "id": 1,
        "method": "submitblock",
        "params": [hex],
    }))
    .unwrap();
    let proposal = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "1.0",
        "id": 1,
        "method": "getblocktemplate",
        "params": [{"mode": "proposal", "data": hex, "rules": ["segwit"]}],
    }))
    .unwrap();
    let two_mib = 2 * 1024 * 1024;
    let max_size = 32 * 1024 * 1024;
    assert!(
        submit.len() > two_mib && submit.len() <= max_size,
        "submit body {}",
        submit.len()
    );
    assert!(
        proposal.len() > two_mib && proposal.len() <= max_size,
        "proposal body {}",
        proposal.len()
    );

    let query = Arc::clone(&hub.query);
    let socket_path = cfg!(unix).then(|| dir.join("rpc.sock"));
    let cfg = RpcConfig {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        socket_path: socket_path.clone(),
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
        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
        .await
        .unwrap();
    let token = handle.auth.token.clone();

    let proposal_tcp = post_authed(
        tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap(),
        &token,
        &proposal,
    )
    .await;
    println!("PROPOSAL_TCP {proposal_tcp}");
    let proposal_json = http_json(&proposal_tcp);
    assert_eq!(
        http_status(&proposal_tcp),
        200,
        "proposal must not be HTTP 413: {proposal_json}"
    );
    assert!(
        proposal_json["result"].is_null() && proposal_json["error"].is_null(),
        "proposal {proposal_json}"
    );

    #[cfg(unix)]
    {
        let proposal_unix = post_authed(
            tokio::net::UnixStream::connect(socket_path.as_ref().unwrap())
                .await
                .unwrap(),
            &token,
            &proposal,
        )
        .await;
        println!("PROPOSAL_UNIX {proposal_unix}");
        let unix_json = http_json(&proposal_unix);
        assert_eq!(
            http_status(&proposal_unix),
            200,
            "unix proposal {unix_json}"
        );
        assert!(
            unix_json["result"].is_null() && unix_json["error"].is_null(),
            "unix proposal {unix_json}"
        );
    }

    let submit_tcp = post_authed(
        tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap(),
        &token,
        &submit,
    )
    .await;
    println!("SUBMIT {submit_tcp}");
    let submit_json = http_json(&submit_tcp);
    assert_eq!(
        http_status(&submit_tcp),
        200,
        "submitblock must not be HTTP 413: {submit_json}"
    );
    assert!(
        submit_json["result"].is_null() && submit_json["error"].is_null(),
        "submitblock {submit_json}"
    );
    let count = post_rpc(
        tcp_addr(&handle),
        &handle.auth,
        "getblockcount",
        serde_json::json!([]),
    )
    .await
    .unwrap();
    let best = post_rpc(
        tcp_addr(&handle),
        &handle.auth,
        "getbestblockhash",
        serde_json::json!([]),
    )
    .await
    .unwrap();
    println!("TIP count={count} best={best}");
    assert_eq!(count["result"], 101, "new tip {count}");
    assert_eq!(best["result"], want_hash, "new tip {best}");

    let mut over = br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#.to_vec();
    over.resize(RPC_MAX_HTTP_BODY + 1, b' ');
    let over_tcp = post_authed(
        tokio::net::TcpStream::connect(tcp_addr(&handle))
            .await
            .unwrap(),
        &token,
        &over,
    )
    .await;
    println!("OVER_CAP {over_tcp}");
    assert_eq!(http_status(&over_tcp), 413, "{over_tcp}");
    assert!(
        !over_tcp.contains("\"result\""),
        "a body over the cap must not run: {over_tcp}"
    );

    let wrong = status_before_body(
        tcp_addr(&handle),
        "POST / HTTP/1.1\r\nHost: rpc\r\nAuthorization: Bearer not-the-token\r\nContent-Length: 8000000\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("BAD_CREDENTIAL {wrong}");
    assert!(
        wrong.contains("401") || wrong.contains("Unauthorized"),
        "wrong credential must be 401 before the body: {wrong}"
    );
    let missing = status_before_body(
        tcp_addr(&handle),
        "POST / HTTP/1.1\r\nHost: rpc\r\nContent-Length: 8000000\r\nConnection: close\r\n\r\n",
    )
    .await;
    println!("MISSING_CREDENTIAL {missing}");
    assert!(
        missing.contains("401") || missing.contains("Unauthorized"),
        "missing credential must be 401 before the body: {missing}"
    );

    let rest_body = vec![b'{'; two_mib + 1];
    let mut rest = tokio::net::TcpStream::connect(tcp_addr(&handle))
        .await
        .unwrap();
    let rest_head = format!(
        "POST /rest/block/aa.json HTTP/1.1\r\nHost: rpc\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        rest_body.len()
    );
    let rest_text = write_http(&mut rest, &rest_head, &rest_body).await;
    println!("REST {rest_text}");
    assert_eq!(
        http_status(&rest_text),
        413,
        "REST must stay at 2 MiB: {rest_text}"
    );
    assert!(
        !rest_text.contains("\"result\""),
        "REST over the cap must not run: {rest_text}"
    );

    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

async fn status_before_body(addr: SocketAddr, head: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(std::time::Duration::from_millis(800), stream.read(&mut buf))
        .await
        .expect("401 before any body bytes")
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
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
    let hub = Arc::new(hub);
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::clone(&hub)), None)
        .await
        .unwrap();
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
        "params": [{"rules": ["segwit"], "longpollid": "0000000000000000000000000000000000000000000000000000000000000000"}]
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
    published_tip_wakes_waitfornewblock(&handle, &hub).await;
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
    let hub = Arc::new(hub);
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::clone(&hub)), None)
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
    let addr = tcp_addr(&handle);
    let auth = handle.auth.clone();
    let waiter = tokio::spawn(async move {
        post_rpc(
            addr,
            &auth,
            "waitforblock",
            serde_json::json!([missing, 60_000]),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let info = post_rpc(addr, &handle.auth, "getrpcinfo", serde_json::json!([]))
                .await
                .unwrap();
            if info["result"]["active_commands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cmd| cmd["method"] == "waitforblock")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("long-poll starts");
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    tokio::time::resume();
    tokio::task::yield_now().await;
    assert!(
        !waiter.is_finished(),
        "read timeout interrupted a complete RPC request"
    );
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(30)).await;
    tokio::time::resume();
    let reply = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("long-poll deadline returns")
        .unwrap()
        .unwrap();
    assert_eq!(reply["result"]["height"], 0, "{reply}");
    assert!(reply["error"].is_null(), "{reply}");
    published_tip_wakes_waitfornewblock(&handle, &hub).await;
    handle.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

async fn published_tip_wakes_waitfornewblock(handle: &RpcHandle, hub: &rbitcoin_net::ChainHub) {
    let addr = tcp_addr(handle);
    let auth = handle.auth.clone();
    let waiter = tokio::spawn(async move {
        post_rpc(addr, &auth, "waitfornewblock", serde_json::json!([5_000])).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let info = post_rpc(addr, &handle.auth, "getrpcinfo", serde_json::json!([]))
                .await
                .unwrap();
            if info["result"]["active_commands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cmd| cmd["method"] == "waitfornewblock")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("waitfornewblock parks before the tip");
    hub.generate_to_script(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), Vec::new())
        .expect("publish a tip");
    let body = tokio::time::timeout(std::time::Duration::from_millis(40), waiter)
        .await
        .expect("published tip wakes waitfornewblock within a few ms")
        .unwrap()
        .unwrap();
    assert!(body["result"]["height"].as_u64().unwrap() >= 1, "{body}");
}

#[tokio::test]
async fn stalled_rpc_connections_expire_and_free_capacity() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = rbitcoin_store::testutil::TempDir::labeled("rpc-accept-cap").expect("dir");
    let q = Query::open_or_create_tiny(dir.join("store")).unwrap();
    let hub = rbitcoin_net::ChainHub::new(
        q,
        rbitcoin_consensus::ChainParams::regtest(),
        rbitcoin_consensus::Milestone::NONE,
    );
    hub.ensure_genesis().unwrap();
    let query = Arc::clone(&hub.query);
    let socket_path = cfg!(unix).then(|| dir.join("rpc.sock"));
    let cfg = RpcConfig {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        socket_path: socket_path.clone(),
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
        .await
        .unwrap();
    let addr = tcp_addr(&handle);
    let request = br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#;
    let keepalive = format!(
        "POST / HTTP/1.1\r\nHost: rpc\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        auth_header(&handle.auth), request.len(), std::str::from_utf8(request).unwrap()
    );
    let mut held = Vec::with_capacity(RPC_MAX_CONNECTIONS);
    for i in 0..RPC_MAX_CONNECTIONS {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let prefix = match i % 4 {
            0 => String::new(),
            1 => "POST / HTTP/1.1\r\nHost:".into(),
            2 => format!(
                "POST / HTTP/1.1\r\nHost: rpc\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{",
                auth_header(&handle.auth)
            ),
            _ => "POST /rest/getutxos.json HTTP/1.1\r\nHost: rpc\r\nContent-Length: 100\r\n\r\n{".into(),
        };
        stream.write_all(prefix.as_bytes()).await.unwrap();
        if i == 0 {
            stream.write_all(keepalive.as_bytes()).await.unwrap();
            read_keepalive_reply(&mut stream).await;
        }
        held.push(stream);
    }
    let mut extra = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), extra.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "an accept past the cap must be dropped, got {read:?}"
    );
    drop(extra);
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::time::resume();
    for (i, stream) in held.iter_mut().enumerate() {
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .unwrap_or_else(|_| panic!("stalled connection {i} did not expire"))
            .expect("expired connection closes cleanly");
        if i % 4 >= 2 {
            assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 408"));
        }
    }
    let (st, body) = post_raw(
        addr,
        &handle.auth,
        br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#,
    )
    .await;
    assert_eq!(st, 200, "{body:?}");
    #[cfg(unix)]
    {
        let mut socket = tokio::net::UnixStream::connect(socket_path.unwrap())
            .await
            .unwrap();
        socket.write_all(format!(
            "POST / HTTP/1.1\r\nHost: rpc\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            request.len()
        ).as_bytes()).await.unwrap();
        socket.write_all(request).await.unwrap();
        read_keepalive_reply(&mut socket).await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::time::resume();
        let read = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buf))
            .await
            .expect("unix keep-alive expires")
            .unwrap();
        assert_eq!(read, 0);
    }
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

        blocksonly: false,
        package_dialect: false,
};
        let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
            .await
            .unwrap();
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, query, None, None, None, Some(Arc::new(hub)), None)
        .await
        .unwrap();
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
        post_raw(addr, &auth, body.as_bytes()).await
    });
    let mut idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled.write_all(format!(
        "POST / HTTP/1.1\r\nHost: rpc\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{",
        auth_header(&handle.auth)
    ).as_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let info = post_rpc(
                tcp_addr(&handle),
                &handle.auth,
                "getrpcinfo",
                serde_json::json!([]),
            )
            .await
            .unwrap();
            if info["result"]["active_commands"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cmd| cmd["method"] == "waitfornewblock")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("waitfornewblock parks");
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
    tokio::time::timeout(std::time::Duration::from_millis(500), handle.shutdown())
        .await
        .expect("closing the listener must not await the long-poll deadline");
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
    let mut buf = [0; 1];
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_millis(500), idle.read(&mut buf))
            .await
            .expect("idle connection closes during shutdown")
            .unwrap(),
        0
    );
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::time::resume();
    let (st, body) = tokio::time::timeout(std::time::Duration::from_secs(2), waiter)
        .await
        .expect("in-flight reply finishes after listener shutdown")
        .expect("client receives a complete HTTP response");
    assert_eq!(st, 200, "{body:?}");
    assert_eq!(body.expect("long-poll tip")["result"]["height"], 0);
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(25)).await;
    tokio::time::resume();
    let mut response = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stalled.read_to_string(&mut response),
    )
    .await
    .expect("stalled body still expires during shutdown")
    .unwrap();
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
        .await
        .unwrap();
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
        axum::extract::Request::new(Body::from(
            br#"{"jsonrpc":"1.0","id":1,"method":"getblockcount"}"#.as_slice(),
        )),
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, Some(mp), None, None, None, None)
        .await
        .unwrap();
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

        blocksonly: false,
        package_dialect: false,
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

        blocksonly: false,
        package_dialect: false,
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

        blocksonly: false,
        package_dialect: false,
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

        blocksonly: false,
        package_dialect: false,
    };
    let handle = run_rpc(cfg, q, None, None, None, None, None).await.unwrap();
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
        stop: rbitcoin_rpc::methods::StopFlag::new(false),
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

        blocksonly: false,
        package_dialect: false,
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
    let malformed = serde_json::json!({
        "method": "getblocktemplate",
        "params": [{ "rules": ["segwit"], "longpollid": "x" }],
        "id": 1
    });
    assert!(
        !satisfy_http_wait(&ctx, &malformed).await,
        "a longpollid Core cannot parse is the request's error, not a wait"
    );
    let current = format!(
        "{}0",
        rbitcoin_rpc::methods::tip_hash_height(&ctx).unwrap().0
    );
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
    let t0 = Instant::now();
    loop {
        let parked = ctx
            .active
            .lock()
            .unwrap()
            .snapshot()
            .iter()
            .any(|(method, _)| method == "getblocktemplate");
        if parked {
            break;
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "getblocktemplate longpoll never parked"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
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
