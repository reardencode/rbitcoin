use rbitcoin_net::error::NetError;
use rbitcoin_net::i2p_sam::*;
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::net::TcpStream;

#[tokio::test(flavor = "current_thread")]
async fn refused_local_sam_dial_is_not_a_dead_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let sam_addr = listener.local_addr().expect("addr");
    drop(listener);
    let dialer = I2pDialer {
        sam_addr,
        session_id: "refused".into(),
        destination: "dest".into(),
        forward_port: None,
        retry: SAM_RETRY_TEST,
    };
    let refused = dialer
        .stream_connect_once("abcdef.b32.i2p")
        .await
        .expect_err("closed SAM port");
    assert!(
        !session_dead(&refused),
        "a refused local SAM port must not rotate the installed session: {refused}"
    );
    assert!(
        matches!(refused, NetError::Encode(ref s) if s.starts_with("i2p sam dial:")),
        "the dial path must use sam_dial_error: {refused}"
    );
    let reply = NetError::Encode("i2p sam stream: STREAM STATUS RESULT=CANT_REACH_PEER".into());
    assert!(!session_dead(&reply));
    let invalid = NetError::Encode("i2p sam stream: SESSION STATUS RESULT=INVALID_ID".into());
    assert!(session_dead(&invalid));
}

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

const FAKE_DEST: &str = "fakeprivdest";
static INSTALL_GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "current_thread")]
async fn i2p_sam_hello_carries_its_newline() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::task::spawn_blocking(move || {
        let (mut sock, _) = listener.accept().unwrap();
        sock.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 128];
        let n = std::io::Read::read(&mut sock, &mut buf).unwrap();
        let got = &buf[..n];
        assert!(
            got.starts_with(b"HELLO VERSION") && got.contains(&b'\n'),
            "first SAM segment {got:?}"
        );
        std::io::Write::write_all(&mut sock, b"HELLO REPLY RESULT=OK VERSION=3.1\n").unwrap();
    });
    let mut s = TcpStream::connect(addr).await.unwrap();
    hello(&mut s).await.unwrap();
    server.await.unwrap();
}

async fn fake_sam(
    ok_hello: bool,
    dest_log: Arc<Mutex<Vec<String>>>,
) -> (SocketAddr, Arc<Mutex<HashSet<String>>>) {
    fake_sam_opts(
        ok_hello,
        dest_log,
        Arc::new(Mutex::new(0)),
        Arc::new(Mutex::new(0)),
        false,
        Arc::new(Mutex::new(0)),
    )
    .await
}

async fn fake_sam_opts(
    ok_hello: bool,
    dest_log: Arc<Mutex<Vec<String>>>,
    stream_drops: Arc<Mutex<usize>>,
    forward_drops: Arc<Mutex<usize>>,
    rst_unknown: bool,
    forward_rst: Arc<Mutex<usize>>,
) -> (SocketAddr, Arc<Mutex<HashSet<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let live = Arc::new(Mutex::new(HashSet::new()));
    let live_accept = Arc::clone(&live);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            let log = Arc::clone(&dest_log);
            let live = Arc::clone(&live_accept);
            let drops = Arc::clone(&stream_drops);
            let fwd_drops = Arc::clone(&forward_drops);
            let ok = ok_hello;
            let rst = rst_unknown;
            let fwd_rst = Arc::clone(&forward_rst);
            tokio::spawn(async move {
                let mut created_id: Option<String> = None;
                loop {
                    let line = match read_line(&mut s).await {
                        Ok(l) => l,
                        Err(_) => break,
                    };
                    let up = line.to_ascii_uppercase();
                    if up.starts_with("HELLO VERSION") {
                        if ok {
                            let _ = write_line(&mut s, "HELLO REPLY RESULT=OK VERSION=3.1").await;
                        } else {
                            let _ = write_line(&mut s, "HELLO REPLY RESULT=NOVERSION").await;
                            break;
                        }
                    } else if up.starts_with("SESSION CREATE") {
                        log.lock().unwrap().push(line.clone());
                        if let Some(id) = sam_kv(&line, "ID") {
                            live.lock().unwrap().insert(id.to_string());
                            created_id = Some(id.to_string());
                        }
                        let dest = sam_kv(&line, "DESTINATION").unwrap_or("TRANSIENT");
                        let reply_dest = if dest.eq_ignore_ascii_case("TRANSIENT") {
                            FAKE_DEST
                        } else {
                            dest
                        };
                        let _ = write_line(
                            &mut s,
                            &format!("SESSION STATUS RESULT=OK DESTINATION={reply_dest}"),
                        )
                        .await;
                    } else if up.starts_with("STREAM FORWARD") {
                        log.lock().unwrap().push(line.clone());
                        let drop_n = {
                            let mut n = fwd_drops.lock().unwrap();
                            if *n > 0 {
                                *n -= 1;
                                true
                            } else {
                                false
                            }
                        };
                        if drop_n {
                            break;
                        }
                        let reset = {
                            let mut n = fwd_rst.lock().unwrap();
                            if *n > 0 {
                                *n -= 1;
                                true
                            } else {
                                false
                            }
                        };
                        if reset {
                            rst_sam_socket(s);
                            return;
                        }
                        let _ = write_line(&mut s, "STREAM STATUS RESULT=OK").await;
                    } else if up.starts_with("STREAM CONNECT") {
                        log.lock().unwrap().push(line.clone());
                        let drop_n = {
                            let mut n = drops.lock().unwrap();
                            if *n > 0 {
                                *n -= 1;
                                true
                            } else {
                                false
                            }
                        };
                        if drop_n {
                            break;
                        }
                        let id = sam_kv(&line, "ID").unwrap_or("");
                        let known = live.lock().unwrap().contains(id);
                        if known {
                            let _ = write_line(&mut s, "STREAM STATUS RESULT=OK").await;
                        } else if rst {
                            // i2pd drops the SAM socket instead of INVALID_ID
                            // when the session is already gone.
                            #[cfg(unix)]
                            {
                                if let Ok(std) = s.into_std() {
                                    use std::os::fd::AsRawFd;
                                    let linger = libc::linger {
                                        l_onoff: 1,
                                        l_linger: 0,
                                    };
                                    // SAFETY: fd is the accepted SAM socket; SO_LINGER 0 resets it.
                                    unsafe {
                                        libc::setsockopt(
                                            std.as_raw_fd(),
                                            libc::SOL_SOCKET,
                                            libc::SO_LINGER,
                                            &linger as *const libc::linger as *const libc::c_void,
                                            std::mem::size_of::<libc::linger>() as libc::socklen_t,
                                        );
                                    }
                                }
                                return;
                            }
                            #[cfg(not(unix))]
                            {
                                let _ = rst;
                                let _ = write_line(&mut s, "STREAM STATUS RESULT=INVALID_ID").await;
                            }
                        } else {
                            let _ = write_line(&mut s, "STREAM STATUS RESULT=INVALID_ID").await;
                        }
                        break;
                    } else {
                        let _ = write_line(&mut s, "PING").await;
                    }
                }
                if let Some(id) = created_id {
                    live.lock().unwrap().remove(&id);
                }
            });
        }
    });
    (addr, live)
}

fn stream_lines(log: &Arc<Mutex<Vec<String>>>, prefix: &str) -> Vec<String> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|g| g.to_ascii_uppercase().starts_with(prefix))
        .cloned()
        .collect()
}

#[tokio::test]
async fn i2p_sam_stream_connect_retries_early_eof() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let drops = Arc::new(Mutex::new(2));
    let (addr, _live) = fake_sam_opts(
        true,
        Arc::clone(&log),
        drops,
        Arc::new(Mutex::new(0)),
        false,
        Arc::new(Mutex::new(0)),
    )
    .await;
    let sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    let dest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p";
    sam.stream_connect(dest).await.unwrap();
    let got = stream_lines(&log, "STREAM CONNECT");
    assert_eq!(got.len(), 3, "{got:?}");
}

#[tokio::test]
async fn i2p_sam_stream_forward_retries_early_eof() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let drops = Arc::new(Mutex::new(2));
    let (addr, _live) = fake_sam_opts(
        true,
        Arc::clone(&log),
        Arc::new(Mutex::new(0)),
        drops,
        false,
        Arc::new(Mutex::new(0)),
    )
    .await;
    let mut sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    sam.stream_forward(18444).await.unwrap();
    let got = stream_lines(&log, "STREAM FORWARD");
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(
        stream_lines(&log, "SESSION CREATE").len(),
        1,
        "early eof retries the forward on the same session"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn i2p_sam_forward_recreates_session_on_reset() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, _live) = fake_sam_opts(
        true,
        Arc::clone(&log),
        Arc::new(Mutex::new(0)),
        Arc::new(Mutex::new(0)),
        false,
        Arc::new(Mutex::new(1)),
    )
    .await;
    let mut sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    sam.stream_forward(18444).await.unwrap();
    let creates = stream_lines(&log, "SESSION CREATE");
    assert_eq!(creates.len(), 2, "{creates:?}");
    assert!(
        creates[1].contains(&format!("DESTINATION={FAKE_DEST}")),
        "{creates:?}"
    );
}

fn rst_sam_socket(s: TcpStream) {
    #[cfg(unix)]
    {
        if let Ok(std) = s.into_std() {
            use std::os::fd::AsRawFd;
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: fd is the accepted SAM socket; SO_LINGER 0 resets it.
            unsafe {
                libc::setsockopt(
                    std.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    &linger as *const libc::linger as *const libc::c_void,
                    std::mem::size_of::<libc::linger>() as libc::socklen_t,
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        drop(s);
    }
}

#[tokio::test]
async fn i2p_sam_stream_connect_fake() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, _live) = fake_sam(true, Arc::clone(&log)).await;
    let sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    let dest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p";
    sam.stream_connect(dest).await.unwrap();
    sam.stream_connect(dest).await.unwrap();
    let got = stream_lines(&log, "STREAM CONNECT");
    assert_eq!(got.len(), 2, "{got:?}");
    for g in &got {
        assert!(g.contains(dest), "{g}");
        assert!(g.contains("ID=rbtc"), "{g}");
        // i2pd drops the STREAM STATUS line when CONNECT sets SILENT=true,
        // so the dial never sees RESULT=OK. FORWARD is the command that
        // prefixes the peer destination; CONNECT must stay non-silent.
        assert!(!g.to_ascii_uppercase().contains("SILENT=TRUE"), "{g}");
    }

    let (bad, _live) = fake_sam(false, Arc::new(Mutex::new(Vec::new()))).await;
    let err = match I2pSam::connect(bad, SAM_RETRY_TEST).await {
        Err(e) => e,
        Ok(_) => panic!("bad HELLO must fail"),
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("hello") || msg.contains("NOVERSION") || msg.contains("sam"),
        "{msg}"
    );
}

#[tokio::test]
async fn dial_i2p_uses_sam() {
    let _gate = INSTALL_GATE.lock().await;
    clear_installed();
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, _live) = fake_sam(true, Arc::clone(&log)).await;
    let sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    let peer = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 8333,
    };
    sam.stream_connect(&peer.host_str()).await.unwrap();
    let got = stream_lines(&log, "STREAM CONNECT");
    assert!(got.iter().any(|g| g.contains(&peer.host_str())), "{got:?}");
    let err = match rbitcoin_net::socks::Dialer::Direct.connect_net(peer).await {
        Err(e) => e,
        Ok(_) => panic!("Direct must not dial I2P"),
    };
    let msg = format!("{err}");
    assert!(msg.contains("SAM") || msg.contains("i2p"), "{msg}");
}

#[tokio::test]
async fn i2p_accept_incoming_forwards_to_loopback() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, _live) = fake_sam(true, Arc::clone(&log)).await;
    let dir = std::env::temp_dir().join(format!(
        "rbtc-i2p-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let dest_path = dir.join("i2p").join("p2p.priv");
    let mut sam = I2pSam::connect_persistent(addr, &dest_path, SAM_RETRY_TEST)
        .await
        .unwrap();
    sam.stream_forward(18444).await.unwrap();
    let stored = std::fs::read_to_string(&dest_path).unwrap();
    assert_eq!(stored.trim(), FAKE_DEST);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dest_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let fw = stream_lines(&log, "STREAM FORWARD");
    assert_eq!(fw.len(), 1, "{fw:?}");
    assert!(fw[0].contains("PORT=18444"), "{}", fw[0]);
    assert!(fw[0].contains("ID=rbtc"), "{}", fw[0]);
    assert!(fw[0].contains("HOST=127.0.0.1"), "{}", fw[0]);
    assert!(fw[0].contains("SILENT=true"), "{}", fw[0]);
    let creates = stream_lines(&log, "SESSION CREATE");
    assert!(
        creates.iter().any(|c| {
            c.contains("DESTINATION=TRANSIENT")
                && c.contains("SIGNATURE_TYPE=7")
                && c.contains("i2cp.leaseSetEncType=6,4")
                && c.contains("inbound.length=1")
        }),
        "{creates:?}"
    );

    let mut sam2 = I2pSam::connect_persistent(addr, &dest_path, SAM_RETRY_TEST)
        .await
        .unwrap();
    sam2.stream_forward(18444).await.unwrap();
    let creates = stream_lines(&log, "SESSION CREATE");
    assert!(
        creates.iter().any(|c| {
            c.contains(&format!("DESTINATION={FAKE_DEST}"))
                && c.contains("i2cp.leaseSetEncType=6,4")
                && !c.contains("SIGNATURE_TYPE=")
        }),
        "{creates:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn i2p_sam_reconnects_after_invalid_id() {
    let _gate = INSTALL_GATE.lock().await;
    clear_installed();
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, live) = fake_sam(true, Arc::clone(&log)).await;
    let sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    rbitcoin_net::socks::install_i2p_dialer(sam.dialer());
    let peer = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 8333,
    };
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .unwrap();
    assert_eq!(stream_lines(&log, "SESSION CREATE").len(), 1);

    live.lock().unwrap().clear();
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .expect("SAM INVALID_ID must recreate the session and retry");
    let creates = stream_lines(&log, "SESSION CREATE");
    assert_eq!(creates.len(), 2, "{creates:?}");
    assert!(
        creates[1].contains(&format!("DESTINATION={FAKE_DEST}")),
        "{}",
        creates[1]
    );

    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .unwrap();
    assert_eq!(
        stream_lines(&log, "SESSION CREATE").len(),
        2,
        "published dialer must keep the new session id"
    );
    clear_installed();
}

#[cfg(unix)]
#[tokio::test]
async fn i2p_sam_recreates_session_when_router_resets_stream() {
    let _gate = INSTALL_GATE.lock().await;
    clear_installed();
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, live) = fake_sam_opts(
        true,
        Arc::clone(&log),
        Arc::new(Mutex::new(0)),
        Arc::new(Mutex::new(0)),
        true,
        Arc::new(Mutex::new(0)),
    )
    .await;
    let sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    rbitcoin_net::socks::install_i2p_dialer(sam.dialer());
    let peer = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 0,
    };
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .unwrap();
    assert_eq!(stream_lines(&log, "SESSION CREATE").len(), 1);

    live.lock().unwrap().clear();
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .expect("SAM reset must recreate the session and retry");
    let creates = stream_lines(&log, "SESSION CREATE");
    assert_eq!(creates.len(), 2, "{creates:?}");
    assert_eq!(
        stream_lines(&log, "STREAM CONNECT").len(),
        3,
        "a reset returns without another connect on the dead session"
    );
    clear_installed();
}

#[tokio::test]
async fn i2p_sam_recreate_restores_forward() {
    let _gate = INSTALL_GATE.lock().await;
    clear_installed();
    let log = Arc::new(Mutex::new(Vec::new()));
    let (addr, live) = fake_sam(true, Arc::clone(&log)).await;
    let mut sam = I2pSam::connect(addr, SAM_RETRY_TEST).await.unwrap();
    sam.stream_forward(18444).await.unwrap();
    rbitcoin_net::socks::install_i2p_dialer(sam.dialer());
    let peer = rbitcoin_net::NetAddr::I2p {
        dest: [0u8; 32],
        port: 0,
    };
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .unwrap();
    assert_eq!(stream_lines(&log, "STREAM FORWARD").len(), 1);
    live.lock().unwrap().clear();
    rbitcoin_net::socks::Dialer::Direct
        .connect_net(peer)
        .await
        .expect("INVALID_ID must recreate the session");
    let fw = stream_lines(&log, "STREAM FORWARD");
    assert_eq!(fw.len(), 2, "dropped session must FORWARD again: {fw:?}");
    assert!(fw[1].contains("PORT=18444"), "{}", fw[1]);
    assert!(fw[1].contains("SILENT=true"), "{}", fw[1]);
    clear_installed();
}

#[test]
fn i2p_addr_hashes_public_destination_only() {
    let mut ident = vec![7u8; 387];
    ident[384] = 0;
    ident[385] = 0;
    ident[386] = 0;
    let mut privd = ident.clone();
    privd.extend_from_slice(&[9u8; 80]);
    let a = i2p_addr_from_sam_b64(&i2p_b64_encode(&ident)).unwrap();
    let b = i2p_addr_from_sam_b64(&i2p_b64_encode(&privd)).unwrap();
    let want = rbitcoin_net::NetAddr::I2p {
        dest: [
            0x15, 0xe2, 0xe8, 0x24, 0x7c, 0x9d, 0xfa, 0x2e, 0xd0, 0xaa, 0x88, 0x04, 0xf8, 0x36,
            0xfc, 0x3a, 0x53, 0x23, 0x0d, 0x3c, 0xa5, 0x8e, 0x03, 0x4d, 0x05, 0x7f, 0xb0, 0xee,
            0x90, 0x7b, 0x3a, 0x57,
        ],
        port: 0,
    };
    assert_eq!(a, want);
    assert_eq!(b, want, "private key suffix must not change the b32");
    assert_eq!(
        a.to_string(),
        "cxroqjd4tx5c5ufkracpqnx4hjjsgdj4uwhagtifp6yo5ed3hjlq.b32.i2p:0"
    );

    let mut public = vec![9u8; 387];
    public[384] = 5;
    public[385] = 0;
    public[386] = 4;
    public.extend_from_slice(&[0x00, 0x07, 0x00, 0x04]);
    let mut full = public.clone();
    full.extend_from_slice(&[0xab; 64]);
    let ed = i2p_addr_from_sam_b64(&i2p_b64_encode(&public)).unwrap();
    let ed_priv = i2p_addr_from_sam_b64(&i2p_b64_encode(&full)).unwrap();
    assert_eq!(ed, ed_priv);
    assert_eq!(
        ed,
        rbitcoin_net::NetAddr::I2p {
            dest: [
                0x0f, 0x35, 0x9f, 0x01, 0x19, 0x78, 0x92, 0x09, 0x23, 0x60, 0xcb, 0x0d, 0x3e, 0xeb,
                0x27, 0xcf, 0x5f, 0xf7, 0xb7, 0x1f, 0x70, 0xef, 0xe7, 0xf7, 0x8d, 0x45, 0x03, 0x1e,
                0x1a, 0xe2, 0x11, 0x75,
            ],
            port: 0,
        }
    );
    assert!(i2p_addr_from_sam_b64("!!!").is_err());
    assert!(i2p_addr_from_sam_b64(&i2p_b64_encode(&[1, 2, 3])).is_err());
}

fn enc(msg: &str) -> NetError {
    NetError::Encode(msg.to_string())
}

#[test]
fn sam_errors_name_the_socket_and_the_reply_that_retry() {
    let io = NetError::Io(std::io::Error::other("sam io"));
    assert!(session_dead(&io));
    assert!(session_dead(&NetError::Disconnected));
    assert!(sam_retry(&io));
    assert!(sam_retry(&NetError::Disconnected));
    assert!(stream_retry(&io));
    assert!(stream_retry(&NetError::Disconnected));
    assert!(session_dead(&enc("STREAM CONNECT: refused")));
    assert!(!session_dead(&enc("i2p sam dial: connection refused")));
    for needle in [
        "connection reset",
        "connection closed",
        "i2p sam connect",
        "early eof",
        "unexpected eof",
        "broken pipe",
    ] {
        assert!(sam_retry(&enc(needle)), "{needle}");
    }
    assert!(!sam_retry(&enc("i2p sam stream: RESULT=I2P_ERROR")));
    for needle in [
        "unexpected eof",
        "broken pipe",
        "connection reset",
        "connection closed",
        "cant_reach",
        "early eof",
        "timeout",
    ] {
        assert!(stream_retry(&enc(needle)), "{needle}");
    }
    assert!(!stream_retry(&enc("i2p sam stream: RESULT=I2P_ERROR")));
}

#[test]
fn i2p_b64_round_trips_digits_dash_and_tilde() {
    for raw in [
        vec![0, 0, 52],
        vec![0, 0, 62],
        vec![0, 0, 63],
        vec![1, 2, 3, 4, 5],
    ] {
        let text = i2p_b64_encode(&raw);
        assert_eq!(decode_i2p_b64(&text).unwrap(), raw, "{text}");
        let plus = text.replace('-', "+");
        let slash = text.replace('~', "/");
        assert_eq!(decode_i2p_b64(&plus).unwrap(), raw, "{plus}");
        assert_eq!(decode_i2p_b64(&slash).unwrap(), raw, "{slash}");
    }
}

async fn sam_reply(lines: &'static [&'static str]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                for reply in lines {
                    if read_line(&mut sock).await.is_err() {
                        return;
                    }
                    if write_line(&mut sock, reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test(flavor = "current_thread")]
async fn hello_requires_the_reply_prefix_and_result_ok() {
    let ok = sam_reply(&["HELLO REPLY RESULT=OK VERSION=3.1"]).await;
    let mut sock = TcpStream::connect(ok).await.unwrap();
    hello(&mut sock).await.unwrap();

    let missing = sam_reply(&["HELLO REPLY RESULT=NOVERSION"]).await;
    let mut sock = TcpStream::connect(missing).await.unwrap();
    let err = hello(&mut sock).await.unwrap_err();
    assert!(err.to_string().contains("i2p sam hello"), "{err}");

    let bare = sam_reply(&["RESULT=OK"]).await;
    let mut sock = TcpStream::connect(bare).await.unwrap();
    let err = hello(&mut sock).await.unwrap_err();
    assert!(err.to_string().contains("i2p sam hello"), "{err}");
}

#[tokio::test(flavor = "current_thread")]
async fn read_line_stops_at_16kib() {
    async fn once(n: usize) -> Result<usize, NetError> {
        use tokio::io::AsyncWriteExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let body = vec![b'a'; n];
            sock.write_all(&body).await.unwrap();
            sock.write_all(b"\n").await.unwrap();
        });
        let mut sock = TcpStream::connect(addr).await.unwrap();
        let got = read_line(&mut sock).await.map(|s| s.len());
        let _ = server.await;
        got
    }
    assert_eq!(once(16 * 1024).await.unwrap(), 16 * 1024);
    assert!(once(16 * 1024 + 1).await.is_err());
    assert_eq!(once(16 + 1024 + 1).await.unwrap(), 16 + 1024 + 1);
}

#[tokio::test(flavor = "current_thread")]
async fn stream_status_error_is_not_retried() {
    let addr = sam_reply(&[
        "HELLO REPLY RESULT=OK VERSION=3.1",
        "STREAM STATUS RESULT=I2P_ERROR",
    ])
    .await;
    let dialer = I2pDialer {
        sam_addr: addr,
        session_id: "once".into(),
        destination: "dest".into(),
        forward_port: None,
        retry: SAM_RETRY_TEST,
    };
    let started = std::time::Instant::now();
    let err = dialer.stream_connect("peer.b32.i2p").await.unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a SAM status error is returned, not slept on"
    );
    assert!(err.to_string().contains("i2p sam stream"), "{err}");

    let forward_addr = sam_reply(&[
        "HELLO REPLY RESULT=OK VERSION=3.1",
        "STREAM STATUS RESULT=I2P_ERROR",
    ])
    .await;
    let (control, _held) = {
        let hold = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hold_addr = hold.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let _ = hold.accept().await;
        });
        let control = TcpStream::connect(hold_addr).await.unwrap();
        (control, accepted)
    };
    let mut sam = I2pSam {
        sam_addr: forward_addr,
        session_id: "fwd".into(),
        destination: "dest".into(),
        forward_port: None,
        retry: SAM_RETRY_TEST,
        _control: control,
        _forward: None,
    };
    let started = std::time::Instant::now();
    let err = sam.stream_forward(9).await.unwrap_err();
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "a forward status error is returned, not slept on"
    );
    assert!(err.to_string().contains("i2p sam forward"), "{err}");
}
