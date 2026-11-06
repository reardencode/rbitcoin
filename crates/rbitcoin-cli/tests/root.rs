use rbitcoin_cli::*;
use rbitcoin_primitives::Network;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use std::net::TcpListener;

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

fn spawn_rpc_mock(token: &str, result_json: &str) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let expect = format!("Bearer {token}");
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
            line.trim()
                .strip_prefix("Authorization:")
                .map(|r| r.trim().eq_ignore_ascii_case(&expect))
                .unwrap_or(false)
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
            s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"jsonrpc\"\r\nContent-Length: 13\r\nConnection: close\r\n\r\nUnauthorized\n").unwrap();
        }
    });
    (port, h)
}

fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

#[test]
fn rpc_url_is_host_and_port() {
    assert_eq!(
        parse_rpc_addr("127.0.0.1:8332").unwrap(),
        ("127.0.0.1".into(), 8332)
    );
    assert_eq!(
        parse_rpc_addr("rpc.lan:18443").unwrap(),
        ("rpc.lan".into(), 18443)
    );
    assert_eq!(parse_rpc_addr("[::1]:8332").unwrap(), ("::1".into(), 8332));
    assert_eq!(
        parse_rpc_addr("[fe80::1%lo]:8332").unwrap(),
        ("fe80::1%lo".into(), 8332)
    );
    assert_eq!(
        parse_rpc_addr("dead.beef:8332").unwrap(),
        ("dead.beef".into(), 8332)
    );
    assert_eq!(
        parse_rpc_addr("0x10.lan:8332").unwrap(),
        ("0x10.lan".into(), 8332)
    );
    assert_eq!(http_host_value("127.0.0.1", 8332), "127.0.0.1:8332");
    assert_eq!(http_host_value("::1", 8332), "[::1]:8332");
    for bad in [
        "http://127.0.0.1:8332",
        "https://127.0.0.1:8332",
        "127.0.0.1:8332/",
        "user:pass@127.0.0.1:8332",
        "::1:8332",
        "127.0.0.1",
        "010.0.0.1:8332",
        "0x7f.0.0.1:8332",
        "0x7f000001:8332",
        "127.1:8332",
        "2130706433:8332",
        "[fe80::1%]:8332",
    ] {
        let err = parse_rpc_addr(bad).unwrap_err();
        assert!(err.contains("host:port"), "{bad} -> {err}");
    }
    let u = usage();
    assert!(u.contains("--rpc-url ADDR"), "{u}");
    assert!(!u.contains("http://"), "{u}");
}

#[test]
fn param_tokens_json_or_string() {
    assert_eq!(param_value("0"), serde_json::json!(0));
    assert_eq!(param_value("true"), serde_json::json!(true));
    assert_eq!(param_value("abc"), serde_json::json!("abc"));
}

#[test]
fn equals_form_datadir_is_accepted() {
    let dir = tmp_datadir();
    std::fs::write(dir.join("rpc.token"), "s3cret").unwrap();
    let (port, h) = spawn_rpc_mock("s3cret", "0");
    let flag = format!("--datadir={}", dir.display());
    let code = cli_main([
        "rbitcoin-cli",
        flag.as_str(),
        &format!("--rpc-url=127.0.0.1:{port}"),
        "getblockcount",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(exit_ok(code), "--foo=bar form must parse, got {code:?}");
    let _ = h.join();
}

#[test]
fn usage_describes_every_option() {
    let u = usage();
    for needle in [
        "--datadir PATH",
        "--network NET",
        "mainnet|testnet|testnet4|signet|regtest",
        "--rpc-url ADDR",
        "--rpc-token-file PATH",
        "-h, --help",
        "-V, --version",
    ] {
        assert!(u.contains(needle), "usage must list {needle}");
    }
    assert!(
        !u.contains("--rpcuser") && !u.contains("--rpcport") && !u.contains("--rpcconnect"),
        "dropped Core names must not be advertised: {u}"
    );
    assert!(
        u.contains("-V, --version") && u.contains("print version"),
        "version must have a description"
    );
}

#[test]
fn getblockcount_token_against_mock() {
    let dir = tmp_datadir();
    std::fs::write(dir.join("rpc.token"), "s3cret").unwrap();
    let (port, h) = spawn_rpc_mock("s3cret", "0");
    let code = cli_main([
        "rbitcoin-cli",
        "--datadir",
        dir.to_str().unwrap(),
        "--rpc-url",
        &format!("127.0.0.1:{port}"),
        "getblockcount",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        exit_ok(code),
        "token getblockcount must succeed against a live RPC mock, got {code:?}"
    );
    let _ = h.join();
}

#[test]
fn missing_auth_is_unauthorized() {
    let (port, _h) = spawn_rpc_mock("alice", "0");
    let dir = tmp_datadir();
    let code = cli_main([
        "rbitcoin-cli",
        "--datadir",
        dir.to_str().unwrap(),
        "--rpc-url",
        &format!("127.0.0.1:{port}"),
        "getblockcount",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!exit_ok(code));
}

#[test]
fn default_rpc_port_follows_network() {
    assert_eq!(Network::Mainnet.default_rpc_port(), 8332);
    assert_eq!(Network::Regtest.default_rpc_port(), 18443);
}

/// Answer one JSON-RPC request on `listener` with `"result": 7`.
#[cfg(unix)]
fn serve_one_rpc(listener: std::os::unix::net::UnixListener) -> thread::JoinHandle<()> {
    thread::spawn(move || {
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
        let body = "{\"jsonrpc\":\"1.0\",\"id\":\"1\",\"result\":7,\"error\":null}\n".to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(resp.as_bytes()).unwrap();
    })
}

#[cfg(unix)]
#[test]
fn unix_socket_needs_no_token() {
    use std::os::unix::net::UnixListener;
    let dir = tmp_datadir();
    let sock = dir.join("rpc.sock");
    let h = serve_one_rpc(UnixListener::bind(&sock).unwrap());
    let code = cli_main([
        "rbitcoin-cli",
        "--datadir",
        dir.to_str().unwrap(),
        "getblockcount",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        exit_ok(code),
        "unix getblockcount must succeed, got {code:?}"
    );
    let _ = h.join();
}

#[cfg(unix)]
#[test]
fn rpc_socket_reaches_a_socket_outside_the_datadir() {
    use std::os::unix::net::UnixListener;
    let dir = tmp_datadir();
    let sock = dir.join("rpc-elsewhere.sock");
    let h = serve_one_rpc(UnixListener::bind(&sock).unwrap());
    let code = cli_main([
        "rbitcoin-cli",
        "--datadir",
        dir.join("no-such-datadir").to_str().unwrap(),
        "--rpc-socket",
        sock.to_str().unwrap(),
        "getblockcount",
    ]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        exit_ok(code),
        "--rpc-socket getblockcount must succeed, got {code:?}"
    );
    let _ = h.join();
}

#[test]
fn parse_args_negative_numbers_are_params() {
    match parse_args(&os_args(&[
        "rbitcoin-cli",
        "getnetworkhashps",
        "-1",
        "-0.5",
    ])) {
        Ok(Action::Call(cfg)) => {
            assert_eq!(cfg.command.as_deref(), Some("getnetworkhashps"));
            assert_eq!(cfg.params, vec!["-1".to_string(), "-0.5".to_string()]);
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected Action::Call, got Help or Version"),
    }
}

#[test]
fn parse_args_dash_alpha_is_still_rejected() {
    for bad in ["-bogus", "-x"] {
        let err = match parse_args(&os_args(&["rbitcoin-cli", bad])) {
            Ok(_) => panic!("{bad} should have been rejected"),
            Err(e) => e,
        };
        assert!(err.contains("unknown argument"), "{bad} -> {err}");
    }
}

#[test]
fn parse_args_double_dash_ends_option_parsing() {
    match parse_args(&os_args(&["rbitcoin-cli", "getblockhash", "--", "-1"])) {
        Ok(Action::Call(cfg)) => {
            assert_eq!(cfg.command.as_deref(), Some("getblockhash"));
            assert_eq!(cfg.params, vec!["-1".to_string()]);
        }
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected Action::Call, got Help or Version"),
    }
}
