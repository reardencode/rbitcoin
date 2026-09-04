//! Live Core JSON-RPC + bitcoind spawn for `block_differential`.

use rbitcoin_net::{
    basic_auth_b64, build_jsonrpc_http_request, parse_submitblock_json, split_http_body,
    wait_for_file, BlockOracle, OracleReply,
};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct CoreRpc {
    host: String,
    auth_b64: String,
}

impl CoreRpc {
    pub fn call(&self, method: &str, params_json: &str) -> Result<String, String> {
        let req = build_jsonrpc_http_request(&self.host, &self.auth_b64, method, params_json);
        let mut stream = TcpStream::connect(&self.host).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        stream.write_all(&req).map_err(|e| e.to_string())?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Ok(body) = split_http_body(&buf) {
                        if http_body_complete(&buf, body) {
                            return Ok(String::from_utf8_lossy(body).into_owned());
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        let body = split_http_body(&buf).map_err(|_| "short http")?;
        Ok(String::from_utf8_lossy(body).into_owned())
    }
}

fn http_body_complete(raw: &[u8], body: &[u8]) -> bool {
    let head = std::str::from_utf8(&raw[..raw.len() - body.len()]).unwrap_or("");
    for line in head.split("\r\n") {
        let l = line.to_ascii_lowercase();
        if let Some(v) = l.strip_prefix("content-length:") {
            if let Ok(n) = v.trim().parse::<usize>() {
                return body.len() >= n;
            }
        }
    }
    !body.is_empty() && body.ends_with(b"}")
}

impl BlockOracle for CoreRpc {
    fn submitblock_hex(&self, hex: &str) -> OracleReply {
        let params = format!(r#"["{hex}"]"#);
        match self.call("submitblock", &params) {
            Ok(body) => match parse_submitblock_json(&body) {
                Ok(None) => OracleReply::NullAccept,
                Ok(Some(r)) => OracleReply::Reason(r),
                Err("rpc error") => OracleReply::RpcError,
                Err(_) => OracleReply::RpcError,
            },
            // TCP/read glitches are not a dead oracle; compare_one + liveness
            // decide whether to skip or fail closed after a streak.
            Err(_) => OracleReply::RpcError,
        }
    }

    fn liveness_ok(&self) -> bool {
        self.call("getblockcount", "[]").is_ok()
    }

    fn core_rewind_to_genesis(&self) -> Result<(), &'static str> {
        for _ in 0..32 {
            let body = self
                .call("getblockcount", "[]")
                .map_err(|_| "getblockcount")?;
            if json_result_u64(&body) == Some(0) {
                return Ok(());
            }
            let hash_body = self
                .call("getbestblockhash", "[]")
                .map_err(|_| "getbestblockhash")?;
            let Some(hash) = parse_submitblock_json(&hash_body).ok().flatten() else {
                return Err("best hash");
            };
            let params = format!(r#"["{hash}"]"#);
            let _ = self.call("invalidateblock", &params);
        }
        Err("core still above genesis")
    }
}

fn json_result_u64(body: &str) -> Option<u64> {
    let i = body.find("\"result\"")?;
    let rest = body[i + 8..].trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub struct CoreChild {
    pub rpc: CoreRpc,
    child: std::sync::Mutex<Child>,
}

impl Drop for CoreChild {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub fn spawn_bitcoind(bin: &Path, datadir: &Path) -> Result<CoreChild, String> {
    std::fs::create_dir_all(datadir).map_err(|e| e.to_string())?;
    let rpcport = free_port()?;
    let p2pport = rpcport.saturating_add(1);
    let cookie = datadir.join(".cookie");
    let child = Command::new(bin)
        .args([
            "-regtest",
            "-server",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-listenonion=0",
            "-printtoconsole=0",
            &format!("-datadir={}", datadir.display()),
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            &format!("-rpcport={rpcport}"),
            &format!("-port={p2pport}"),
            &format!("-rpccookiefile={}", cookie.display()),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn bitcoind: {e}"))?;
    wait_for_file(&cookie, Instant::now() + Duration::from_secs(90))
        .map_err(|_| "cookie file missing (datadir/.cookie)")?;
    let creds = std::fs::read_to_string(&cookie).map_err(|e| e.to_string())?;
    let (user, pass) = creds
        .trim()
        .split_once(':')
        .ok_or_else(|| "cookie not user:pass".to_string())?;
    let rpc = CoreRpc {
        host: format!("127.0.0.1:{rpcport}"),
        auth_b64: basic_auth_b64(user, pass),
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(body) = rpc.call("getblockcount", "[]") {
            if json_result_u64(&body) == Some(0) {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err("bitcoind RPC never reached getblockcount==0".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(CoreChild {
        rpc,
        child: std::sync::Mutex::new(child),
    })
}

fn free_port() -> Result<u16, String> {
    let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

pub fn tmp_dir(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
