//! Cookie / user-pass JSON-RPC client for the documented node subset.

use serde_json::Value;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn usage() -> String {
    format!(
        "rbitcoin-cli {} — usage: rbitcoin-cli [OPTIONS] <COMMAND> [PARAMS...]\n\
         \n\
         Options:\n\
           --datadir DIR         cookie at DIR/.cookie (same as rbitcoin-node --datadir)\n\
           --rpcconnect HOST     default 127.0.0.1\n\
           --rpcport PORT        default 8332\n\
           --rpcuser USER        with --rpcpassword (else cookie)\n\
           --rpcpassword PASS\n\
           -h, --help            this message\n\
           -V, --version\n\
         \n\
         Auth: --rpcuser/--rpcpassword, or the cookie written when the node\n\
         listens (`{{datadir}}/.cookie`). Plain HTTP, same as the node.",
        env!("CARGO_PKG_VERSION")
    )
}

struct CliConfig {
    datadir: Option<PathBuf>,
    rpcconnect: String,
    rpcport: u16,
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
    command: Option<String>,
    params: Vec<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            datadir: None,
            rpcconnect: "127.0.0.1".into(),
            rpcport: 8332,
            rpcuser: None,
            rpcpassword: None,
            command: None,
            params: Vec::new(),
        }
    }
}

enum Action {
    Help,
    Version,
    Call(CliConfig),
}

fn take_value(args: &[OsString], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_args(args: &[OsString]) -> Result<Action, String> {
    let mut cfg = CliConfig::default();
    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        match a.as_ref() {
            "--help" | "-h" => return Ok(Action::Help),
            "--version" | "-V" => return Ok(Action::Version),
            "--datadir" | "-datadir" => {
                cfg.datadir = Some(PathBuf::from(take_value(args, &mut i, "--datadir")?));
            }
            "--rpcconnect" | "-rpcconnect" => {
                cfg.rpcconnect = take_value(args, &mut i, "--rpcconnect")?;
            }
            "--rpcport" | "-rpcport" => {
                let v = take_value(args, &mut i, "--rpcport")?;
                cfg.rpcport = v.parse().map_err(|_| format!("invalid --rpcport {v}"))?;
            }
            "--rpcuser" | "-rpcuser" => {
                cfg.rpcuser = Some(take_value(args, &mut i, "--rpcuser")?);
            }
            "--rpcpassword" | "-rpcpassword" => {
                cfg.rpcpassword = Some(take_value(args, &mut i, "--rpcpassword")?);
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option {flag}"));
            }
            _ if cfg.command.is_none() => {
                cfg.command = Some(a.into_owned());
            }
            _ => cfg.params.push(a.into_owned()),
        }
        i += 1;
    }
    Ok(Action::Call(cfg))
}

fn resolve_auth(cfg: &CliConfig) -> Result<(String, String), String> {
    match (&cfg.rpcuser, &cfg.rpcpassword) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => Ok((u.clone(), p.clone())),
        (Some(_), None) | (None, Some(_)) => {
            Err("--rpcuser and --rpcpassword must both be set".into())
        }
        (Some(_), Some(_)) => Err("--rpcuser and --rpcpassword must be non-empty".into()),
        (None, None) => {
            let dir = cfg
                .datadir
                .as_ref()
                .ok_or("need --datadir (cookie) or --rpcuser/--rpcpassword")?;
            let path = dir.join(".cookie");
            let line = std::fs::read_to_string(&path)
                .map_err(|e| format!("read cookie {}: {e}", path.display()))?;
            let (u, p) = line
                .trim()
                .split_once(':')
                .ok_or("cookie file: expected user:password")?;
            if u.is_empty() || p.is_empty() {
                return Err("cookie file: expected user:password".into());
            }
            Ok((u.to_string(), p.to_string()))
        }
    }
}

fn param_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

/// POST one JSON-RPC method; returns the `result` value or an error message.
pub fn rpc_call(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    method: &str,
    params: &[Value],
) -> Result<Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "1.0",
        "id": "1",
        "method": method,
        "params": params,
    });
    let body = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
    use base64::Engine;
    let tok = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    let req = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Authorization: Basic {tok}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut stream =
        TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
    let mut wire = req.into_bytes();
    wire.extend_from_slice(&body);
    stream.write_all(&wire).map_err(|e| format!("write: {e}"))?;
    let (status, resp_body) = read_http(&mut stream)?;
    if status == 401 {
        return Err("RPC unauthorized (check cookie or --rpcuser/--rpcpassword)".into());
    }
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}: {resp_body}"));
    }
    let v: Value = serde_json::from_str(&resp_body).map_err(|e| format!("rpc json: {e}"))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("rpc error");
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        return Err(format!("RPC error {code}: {msg}"));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn read_http(stream: &mut TcpStream) -> Result<(u16, String), String> {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or("invalid HTTP response")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((status, body.to_string()))
}

fn format_result(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn dispatch_call(cfg: &CliConfig) -> Result<String, String> {
    let cmd = cfg.command.as_deref().ok_or_else(usage)?;
    if cmd == "help" {
        return Ok(usage());
    }
    let (user, pass) = resolve_auth(cfg)?;
    let params: Vec<Value> = cfg.params.iter().map(|p| param_value(p)).collect();
    let result = rpc_call(&cfg.rpcconnect, cfg.rpcport, &user, &pass, cmd, &params)?;
    Ok(format_result(&result))
}

/// Process entry used by `main` and high-level scenarios.
pub fn cli_main<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let action = match parse_args(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match action {
        Action::Help => {
            eprintln!("{}", usage());
            ExitCode::SUCCESS
        }
        Action::Version => {
            eprintln!("rbitcoin-cli {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Action::Call(cfg) => match dispatch_call(&cfg) {
            Ok(out) => {
                println!("{out}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn exit_ok(c: ExitCode) -> bool {
        format!("{c:?}") == format!("{:?}", ExitCode::SUCCESS)
    }

    fn tmp_datadir() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!("rbitcoin-cli-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Minimal JSON-RPC server: 401 without Basic; 200 + `result` when user:pass match.
    fn spawn_rpc_mock(user: &str, pass: &str, result_json: &str) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let expect = format!("{user}:{pass}");
        let result = result_json.to_string();
        let h = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut raw = Vec::new();
            let mut tmp = [0u8; 1024];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&tmp[..n]);
            }
            let req = String::from_utf8_lossy(&raw);
            let authorized = req.lines().any(|line| {
                let line = line.trim();
                let Some(rest) = line
                    .strip_prefix("Authorization: Basic ")
                    .or_else(|| line.strip_prefix("authorization: Basic "))
                else {
                    return false;
                };
                decode_basic(rest).as_deref() == Some(expect.as_str())
            });
            let body = if authorized {
                format!("{{\"jsonrpc\":\"1.0\",\"id\":\"1\",\"result\":{result},\"error\":null}}\n")
            } else {
                String::new()
            };
            if authorized {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(resp.as_bytes()).unwrap();
            } else {
                s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"jsonrpc\"\r\nContent-Length: 13\r\nConnection: close\r\n\r\nUnauthorized\n").unwrap();
            }
        });
        (port, h)
    }

    fn decode_basic(b64: &str) -> Option<String> {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .ok()?;
        String::from_utf8(raw).ok()
    }

    #[test]
    fn param_tokens_json_or_string() {
        assert_eq!(param_value("0"), serde_json::json!(0));
        assert_eq!(param_value("true"), serde_json::json!(true));
        assert_eq!(param_value("abc"), serde_json::json!("abc"));
    }

    #[test]
    fn help_and_version_do_not_dial() {
        assert!(exit_ok(cli_main(["rbitcoin-cli", "--help"])));
        assert!(exit_ok(cli_main(["rbitcoin-cli", "-V"])));
        assert!(exit_ok(cli_main(["rbitcoin-cli", "help"])));
    }

    #[test]
    fn getblockcount_cookie_against_mock() {
        let dir = tmp_datadir();
        std::fs::write(dir.join(".cookie"), "__cookie__:s3cret").unwrap();
        let (port, h) = spawn_rpc_mock("__cookie__", "s3cret", "0");
        let code = cli_main([
            "rbitcoin-cli",
            "--datadir",
            dir.to_str().unwrap(),
            "--rpcconnect",
            "127.0.0.1",
            "--rpcport",
            &port.to_string(),
            "getblockcount",
        ]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            exit_ok(code),
            "cookie getblockcount must succeed against a live RPC mock, got {code:?}"
        );
        let _ = h.join();
    }

    #[test]
    fn getblockcount_userpass_against_mock() {
        let (port, h) = spawn_rpc_mock("alice", "pw", "0");
        let code = cli_main([
            "rbitcoin-cli",
            "--rpcuser",
            "alice",
            "--rpcpassword",
            "pw",
            "--rpcport",
            &port.to_string(),
            "getblockcount",
        ]);
        assert!(
            exit_ok(code),
            "user/pass getblockcount must succeed against a live RPC mock, got {code:?}"
        );
        let _ = h.join();
    }

    #[test]
    fn missing_auth_is_unauthorized() {
        let (port, _h) = spawn_rpc_mock("alice", "pw", "0");
        let code = cli_main([
            "rbitcoin-cli",
            "--rpcport",
            &port.to_string(),
            "getblockcount",
        ]);
        assert!(!exit_ok(code));
    }
}
