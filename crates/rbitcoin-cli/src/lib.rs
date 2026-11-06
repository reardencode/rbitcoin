//! Datadir socket / bearer-token JSON-RPC client for the documented node subset.

#![forbid(unsafe_code)]

use rbitcoin_primitives::Network;
use serde_json::Value;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[doc(hidden)]
pub fn usage() -> String {
    format!(
        "rbitcoin-cli {} — usage: rbitcoin-cli [OPTIONS] <COMMAND> [PARAMS...]\n\
         \n\
         Options:\n\
           --datadir PATH         node datadir (default ./datadir); unix socket PATH/rpc.sock\n\
           --rpc-socket PATH      unix socket the node binds with --rpc-socket\n\
           --network NET          mainnet|testnet|testnet4|signet|regtest (default TCP port)\n\
           --rpc-url ADDR         plain HTTP host:port (else 127.0.0.1:<network port> if no socket)\n\
           --rpc-token-file PATH  Bearer token (default PATH/rpc.token from --datadir)\n\
           -h, --help             this message\n\
           -V, --version          print version\n\
         \n\
         Local: --datadir talks to {{datadir}}/rpc.sock (no token). TCP uses Bearer\n\
         from {{datadir}}/rpc.token. Plain HTTP, same as the node.",
        env!("CARGO_PKG_VERSION")
    )
}

#[doc(hidden)]
pub struct CliConfig {
    pub datadir: PathBuf,
    pub network: Network,
    pub rpc_url: Option<String>,
    pub socket: Option<PathBuf>,
    pub token_file: Option<PathBuf>,
    pub command: Option<String>,
    pub params: Vec<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            datadir: PathBuf::from(".").join("datadir"),
            network: Network::Mainnet,
            rpc_url: None,
            socket: None,
            token_file: None,
            command: None,
            params: Vec::new(),
        }
    }
}

#[doc(hidden)]
pub enum Action {
    Help,
    Version,
    Call(CliConfig),
}

#[doc(hidden)]
pub fn take_value(args: &[OsString], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .map(|s| s.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{flag} requires a value"))
}

#[doc(hidden)]
pub fn flag_name_and_eq(raw: &str) -> Option<(&str, Option<&str>)> {
    let rest = raw.strip_prefix("--")?;
    match rest.split_once('=') {
        Some((name, val)) => Some((name, Some(val))),
        None => Some((rest, None)),
    }
}

fn is_negative_number(a: &str) -> bool {
    a.as_bytes().get(1).is_some_and(|b| b.is_ascii_digit())
}

#[doc(hidden)]
pub fn parse_args(args: &[OsString]) -> Result<Action, String> {
    let mut cfg = CliConfig::default();
    let mut positional_only = false;
    let mut i = 1usize;
    while i < args.len() {
        let a = args[i].to_string_lossy();
        if !positional_only {
            if a == "--help" || a == "-h" {
                return Ok(Action::Help);
            }
            if a == "--version" || a == "-V" {
                return Ok(Action::Version);
            }
            if a == "--" {
                positional_only = true;
                i += 1;
                continue;
            }
            if a.starts_with('-') && !a.starts_with("--") && !is_negative_number(a.as_ref()) {
                return Err(format!("unknown argument `{a}`"));
            }
            if let Some((name, eq)) = flag_name_and_eq(a.as_ref()) {
                let val = match eq {
                    Some(v) => {
                        if v.is_empty() {
                            return Err(format!("--{name} requires a value"));
                        }
                        v.to_string()
                    }
                    None => take_value(args, &mut i, &format!("--{name}"))?,
                };
                match name {
                    "datadir" => cfg.datadir = PathBuf::from(val),
                    "network" => {
                        cfg.network =
                            Network::parse(&val).map_err(|e| format!("invalid --network: {e}"))?;
                    }
                    "rpc-url" => cfg.rpc_url = Some(val),
                    "rpc-socket" => cfg.socket = Some(PathBuf::from(val)),
                    "rpc-token-file" => cfg.token_file = Some(PathBuf::from(val)),
                    other => return Err(format!("unknown argument `--{other}`")),
                }
                i += 1;
                continue;
            }
        }
        if cfg.command.is_none() {
            cfg.command = Some(a.into_owned());
        } else {
            cfg.params.push(a.into_owned());
        }
        i += 1;
    }
    Ok(Action::Call(cfg))
}

#[doc(hidden)]
pub fn socket_path(cfg: &CliConfig) -> PathBuf {
    cfg.socket
        .clone()
        .unwrap_or_else(|| cfg.datadir.join("rpc.sock"))
}

#[doc(hidden)]
pub fn token_path(cfg: &CliConfig) -> PathBuf {
    cfg.token_file
        .clone()
        .unwrap_or_else(|| cfg.datadir.join("rpc.token"))
}

#[doc(hidden)]
pub fn parse_rpc_addr(addr: &str) -> Result<(String, u16), String> {
    let bad = || format!("--rpc-url takes host:port (plain HTTP, no scheme; got {addr})");
    if addr.contains("://") || addr.contains('/') || addr.contains('@') {
        return Err(bad());
    }
    let (raw_host, port_s) = addr.rsplit_once(':').ok_or_else(bad)?;
    let host = if let Some(inner) = raw_host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or_else(bad)?;
        if !inner.contains(':') {
            return Err(bad());
        }
        inner
    } else if raw_host.contains(':') {
        return Err(bad());
    } else {
        raw_host
    };
    if host.is_empty() || !acceptable_host(host) {
        return Err(bad());
    }
    let port: u16 = port_s
        .parse()
        .map_err(|_| format!("invalid --rpc-url port in {addr}"))?;
    Ok((host.to_string(), port))
}

/// A strict IP, a scoped IPv6 address, or a DNS name. inet_aton spellings
/// (`010.0.0.1`, `0x7f.0.0.1`) are rejected so libc does not retarget them.
fn acceptable_host(host: &str) -> bool {
    if let Some((addr, zone)) = host.split_once('%') {
        return addr.parse::<Ipv6Addr>().is_ok() && valid_zone(zone);
    }
    host.parse::<IpAddr>().is_ok() || !inet_aton_literal(host)
}

fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && !zone.contains('%')
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn inet_aton_literal(host: &str) -> bool {
    host.split('.').all(inet_aton_label)
}

fn inet_aton_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let Some(hex) = label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    else {
        return false;
    };
    !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let connect = match host.parse::<IpAddr>() {
        Ok(ip) => TcpStream::connect(SocketAddr::new(ip, port)),
        Err(_) => TcpStream::connect((host, port)),
    };
    connect.map_err(|e| format!("connect {host}:{port}: {e}"))
}

#[doc(hidden)]
pub fn http_host_value(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[doc(hidden)]
pub fn read_token(path: &Path) -> Result<String, String> {
    let line =
        std::fs::read_to_string(path).map_err(|e| format!("read token {}: {e}", path.display()))?;
    let t = line.trim();
    if t.is_empty() {
        return Err(format!("token file {}: empty", path.display()));
    }
    Ok(t.to_string())
}

#[doc(hidden)]
pub fn param_value(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

#[doc(hidden)]
pub fn rpc_http(
    mut stream: impl Read + Write,
    host: &str,
    port: u16,
    auth: Option<&str>,
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
    let auth_h = match auth {
        Some(t) => format!("Authorization: Bearer {t}\r\n"),
        None => String::new(),
    };
    let host_hdr = http_host_value(host, port);
    let req = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host_hdr}\r\n\
         {auth_h}\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut wire = req.into_bytes();
    wire.extend_from_slice(&body);
    stream.write_all(&wire).map_err(|e| format!("write: {e}"))?;
    let (status, resp_body) = read_http(&mut stream)?;
    if status == 401 {
        return Err("RPC unauthorized (check rpc.token or --rpc-token-file)".into());
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

#[doc(hidden)]
pub fn connect_unix(path: &Path) -> Result<socket2::Socket, String> {
    let sock = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(|e| format!("unix socket: {e}"))?;
    let addr = socket2::SockAddr::unix(path).map_err(|e| format!("unix addr: {e}"))?;
    sock.connect(&addr)
        .map_err(|e| format!("connect {}: {e}", path.display()))?;
    Ok(sock)
}

#[doc(hidden)]
pub fn read_http(stream: &mut impl Read) -> Result<(u16, String), String> {
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

#[doc(hidden)]
pub fn format_result(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[doc(hidden)]
pub fn dispatch_call(cfg: &CliConfig) -> Result<String, String> {
    let cmd = cfg.command.as_deref().ok_or_else(usage)?;
    if cmd == "help" {
        return Ok(usage());
    }
    let params: Vec<Value> = cfg.params.iter().map(|p| param_value(p)).collect();
    let sock = socket_path(cfg);
    let result = if cfg.rpc_url.is_none() && (cfg.socket.is_some() || sock.exists()) {
        let stream = connect_unix(&sock)?;
        rpc_http(stream, "localhost", 0, None, cmd, &params)?
    } else {
        let (host, port) = match cfg.rpc_url.as_deref() {
            Some(u) => parse_rpc_addr(u)?,
            None => ("127.0.0.1".into(), cfg.network.default_rpc_port()),
        };
        let stream = connect_tcp(&host, port)?;
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let token = read_token(&token_path(cfg))?;
        rpc_http(stream, &host, port, Some(&token), cmd, &params)?
    };
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
